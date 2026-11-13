"""cli: signal handling, clean-up, core dumps, config errors, claim printing (spec 001 §3.7, §5)."""

import os
import contextlib
import io
import json
import signal
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import cli


HANDLED_SIGNALS = [signal.SIGTERM, signal.SIGINT] + ([signal.SIGHUP] if hasattr(signal, "SIGHUP") else [])
DEADLOCK_SECONDS = 3


class StubDialogs:
	def __init__(self, events):
		self.events = events
		self.shutdown_threads = []

	def shutdown(self):
		self.events.append("dialogs.shutdown")
		self.shutdown_threads.append(threading.current_thread())


class StubServer:
	"""Mimics BaseServer: shutdown() blocks until serve_forever() has returned.

	So shutdown() called on the serve_forever thread can never return by itself; it
	gives up after DEADLOCK_SECONDS and records the deadlock instead of hanging the run.
	"""

	def __init__(self, events, *, raise_signal=None, fail=None):
		self.events = events
		self.raise_signal = raise_signal
		self.fail = fail
		self._requested = threading.Event()
		self._returned = threading.Event()
		self.serve_thread = None
		self.shutdown_thread = None
		self.deadlocked = False
		self.closed = False

	def serve_forever(self):
		self.events.append("serve_forever")
		self.serve_thread = threading.current_thread()
		try:
			if self.fail is not None:
				raise self.fail
			if self.raise_signal is not None:
				signal.raise_signal(self.raise_signal)  # the handler runs on THIS thread
			if not self._requested.wait(DEADLOCK_SECONDS):
				self.events.append("serve_forever.never_stopped")
		finally:
			self._returned.set()

	def shutdown(self):
		self.events.append("server.shutdown")
		self.shutdown_thread = threading.current_thread()
		self._requested.set()
		if not self._returned.wait(DEADLOCK_SECONDS):
			self.deadlocked = True

	def server_close(self):
		self.events.append("server_close")
		self.closed = True


class StubService:
	def __init__(self, events, server):
		self.events = events
		self.dialogs = StubDialogs(events)
		self.server = server

	def make_server(self):
		self.events.append("make_server")
		return self.server


class SignalHandlersRestored(unittest.TestCase):
	def setUp(self):
		self._saved = {number: signal.getsignal(number) for number in HANDLED_SIGNALS}

	def tearDown(self):
		for number, handler in self._saved.items():
			signal.signal(number, handler)


class TestSignalShutdown(SignalHandlersRestored):
	def test_every_signal_stops_the_server_without_deadlock(self):
		for number in HANDLED_SIGNALS:
			with self.subTest(signal=number):
				events = []
				server = StubServer(events, raise_signal=number)
				service = StubService(events, server)
				cli._serve(service, server)
				if server.shutdown_thread is not None:
					server.shutdown_thread.join(DEADLOCK_SECONDS)
				self.assertFalse(server.deadlocked, "server.shutdown() ran on the serve_forever thread")
				self.assertNotIn("serve_forever.never_stopped", events)
				self.assertIsNotNone(server.shutdown_thread)
				self.assertIsNot(server.serve_thread, server.shutdown_thread)
				self.assertTrue(server.shutdown_thread.daemon)
				# The handler killed the dialog child first (no lock), the finally did it again.
				self.assertEqual(2, events.count("dialogs.shutdown"))
				self.assertIs(server.serve_thread, service.dialogs.shutdown_threads[0])
				self.assertTrue(server.closed)
				self.assertLess(events.index("dialogs.shutdown"), events.index("server_close"))

	def test_handlers_are_registered_for_the_spec_signals(self):
		events = []
		server = StubServer(events)
		cli._install_signal_handlers(StubService(events, server), server)
		handlers = {signal.getsignal(number) for number in HANDLED_SIGNALS}
		self.assertEqual(1, len(handlers))
		handler = handlers.pop()
		self.assertTrue(callable(handler))
		self.assertNotIn(handler, (signal.SIG_DFL, signal.SIG_IGN, signal.default_int_handler))

	def test_handler_only_kills_dialogs_and_delegates_shutdown(self):
		events = []
		server = StubServer(events)
		service = StubService(events, server)
		cli._install_signal_handlers(service, server)
		server._returned.set()  # as if serve_forever had already returned
		signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
		self.assertTrue(server._requested.wait(DEADLOCK_SECONDS))
		self.assertEqual(["dialogs.shutdown", "server.shutdown"], events)
		self.assertIsNot(threading.current_thread(), server.shutdown_thread)
		self.assertFalse(server.closed)  # closing belongs to the finally clause, not the handler


class TestServeCleanup(SignalHandlersRestored):
	def test_finally_closes_and_shuts_dialogs_when_serve_forever_raises(self):
		events = []
		server = StubServer(events, fail=RuntimeError("boom"))
		service = StubService(events, server)
		with self.assertRaises(RuntimeError):
			cli._serve(service, server)
		self.assertTrue(server.closed)
		self.assertEqual(["serve_forever", "server_close", "dialogs.shutdown"], events)

	@unittest.skipUnless(os.name != "nt", "POSIX-only: uses the resource module, POSIX paths or permission bits")
	def test_main_disables_core_dumps_before_serving(self):
		events = []
		server = StubServer(events)
		server._requested.set()  # serve_forever returns at once
		fake_service = types.ModuleType("erp_dsc_local.service")

		def make_service(config):
			events.append("SignerService")
			return StubService(events, server)

		fake_service.SignerService = make_service
		with tempfile.TemporaryDirectory() as directory:
			config = Path(directory) / "config.json"
			config.write_text("{}", encoding="utf-8")
			with mock.patch.dict(sys.modules, {"erp_dsc_local.service": fake_service}), mock.patch.object(
				sys, "argv", ["erp-dsc-local", "--config", str(config)]
			), mock.patch("resource.setrlimit", side_effect=lambda *a: events.append(("setrlimit", a))):
				cli.main()
		import resource

		self.assertEqual(("setrlimit", (resource.RLIMIT_CORE, (0, 0))), events[0])
		self.assertEqual(
			["SignerService", "make_server", "serve_forever", "server_close", "dialogs.shutdown"], events[1:]
		)


class FakeStore:
	def __init__(self, entries=()):
		self.entries = list(entries)

	def list_origins(self):
		return self.entries


def run_cli(argv, store=None):
	out, err = io.StringIO(), io.StringIO()
	code = None
	with mock.patch.object(sys, "argv", ["erp-dsc-local", *argv]), mock.patch.object(
		cli, "TrustStore", lambda: store or FakeStore()
	), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
		try:
			cli.main()
		except SystemExit as exc:
			code = exc.code
	return code, out.getvalue(), err.getvalue()


class TestConfigErrorsArePrinted(unittest.TestCase):
	def bad_config(self, directory):
		path = Path(directory) / "config.json"
		path.write_text(json.dumps({"development": {"allow_pin_in_request": False}}), encoding="utf-8")
		return path

	def test_list_origins_and_revoke_print_the_error(self):
		for argv in (["--list-origins"], ["--revoke", "https://a.example"]):
			with self.subTest(argv=argv):
				with tempfile.TemporaryDirectory() as directory:
					code, out, err = run_cli(["--config", str(self.bad_config(directory)), *argv])
				self.assertEqual(2, code)
				self.assertIn("error: development.allow_pin_in_request is no longer supported", err)
				self.assertNotIn("Paired on this computer", out)

	def test_missing_config_is_printed(self):
		code, _out, err = run_cli(["--config", "/nonexistent/erp-dsc/config.json", "--list-origins"])
		self.assertEqual(2, code)
		self.assertIn("Configuration file not found", err)

	def test_static_origins_helper(self):
		with tempfile.TemporaryDirectory() as directory:
			err = io.StringIO()
			with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
				cli._static_origins(self.bad_config(directory))
		self.assertEqual(2, ctx.exception.code)
		self.assertIn("allow_pin_in_request", err.getvalue())
		self.assertEqual(frozenset(), cli._static_origins(None))


class TestListOriginsPrinting(unittest.TestCase):
	def test_control_and_format_characters_are_stripped(self):
		hostile = "Evil\x1b[2J\x1b]0;owned\x07 Ltd‮​­\r\nnext \ud800"
		store = FakeStore([{"origin": "https://a.example", "approved_at": 0, "claimed_site_name": hostile}])
		code, out, _err = run_cli(["--list-origins"], store)
		self.assertEqual(0, code)
		line = [row for row in out.splitlines() if "https://a.example" in row]
		self.assertEqual(1, len(line), out)
		self.assertIn("Evil[2J]0;owned Ltdnext", line[0])
		for ch in ("\x1b", "\x07", "\r", "‮", "​", "­", " ", "\ud800"):
			self.assertNotIn(ch, out)

	def test_ordinary_claim_is_printed_verbatim(self):
		store = FakeStore([{"origin": "https://a.example", "approved_at": 0, "claimed_site_name": "Acme — Mumbai"}])
		_code, out, _err = run_cli(["--list-origins"], store)
		self.assertIn("[site describes itself as: Acme — Mumbai]", out)


class RevokableStore(FakeStore):
	def revoke(self, origin):
		return True

	def allow(self, origin):
		return origin


class TestEveryPrintedOriginIsSanitised(unittest.TestCase):
	HOSTILE = ("https://evil.example\x07", "https://a\u202eb.example")

	def assertClean(self, text):
		for ch in ("\x07", "\u202e"):
			self.assertNotIn(ch, text)

	def test_list_output_strips_stored_and_configured_origins(self):
		for origin in self.HOSTILE:
			with self.subTest(origin=origin):
				store = FakeStore([{"origin": origin, "approved_at": 0}])
				out = io.StringIO()
				with contextlib.redirect_stdout(out):
					cli._list_origins(store, frozenset({origin}))
				self.assertClean(out.getvalue())
				self.assertIn("evil.example" if "evil" in origin else "ab.example", out.getvalue())

	def test_revoke_and_allow_output_strip_the_origin(self):
		for origin in self.HOSTILE:
			with self.subTest(origin=origin), mock.patch.object(cli, "canonical_origin", lambda v: v):
				code, out, err = run_cli(["--revoke", origin], RevokableStore())
				self.assertEqual(0, code)
				self.assertClean(out + err)
				code, out, err = run_cli(["--allow", origin], RevokableStore())
				self.assertEqual(0, code)
				self.assertClean(out + err)
				code, out, err = run_cli(["--revoke", origin], FakeRefusingStore())
				self.assertEqual(1, code)
				self.assertClean(out + err)

	def test_revoke_of_configured_origin_error_is_clean(self):
		origin = self.HOSTILE[0]
		err = io.StringIO()
		with mock.patch.object(cli, "canonical_origin", lambda v: v), contextlib.redirect_stderr(err):
			self.assertEqual(2, cli._revoke(FakeStore(), origin, frozenset({origin})))
		self.assertClean(err.getvalue())
		self.assertIn("evil.example", err.getvalue())


class FakeRefusingStore(FakeStore):
	def revoke(self, origin):
		return False


class TestCoreDumpHelperIsShared(unittest.TestCase):
	def test_cli_reuses_the_dialog_child_helper(self):
		from erp_dsc_local import dialog_child

		self.assertIs(dialog_child._disable_core_dumps, cli._disable_core_dumps)



class TestRunAsModule(unittest.TestCase):
	"""``python -m erp_dsc_local`` must work: the Windows start command in the notes uses it."""

	def test_dash_m_package_runs_the_cli(self):
		import subprocess
		import sys

		root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		done = subprocess.run(
			[sys.executable, "-m", "erp_dsc_local", "--help"],
			cwd=root, capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONPATH": root},
		)
		self.assertEqual(0, done.returncode, done.stderr)
		self.assertIn("--doctor", done.stdout)

if __name__ == "__main__":
	unittest.main()


class TestVersionSingleSource(unittest.TestCase):
	def test_package_service_and_pyproject_agree(self):
		import re
		from pathlib import Path
		from erp_dsc_local import __version__, service
		self.assertEqual(__version__, service.VERSION)
		text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
		self.assertIn('attr = "erp_dsc_local.__version__"', text)
		self.assertIsNone(re.search(r'^version\s*=\s*"', text, re.M))
