"""The daemon's own log file (BRD F4, installer plan s5): size-capped, user-only, no secrets.

Checked here: the file and its folder are created user-only (0600 / 0700) whatever the
umask, a wider existing file is narrowed, a symlinked file or folder is refused; rotation
keeps 1 + BACKUP_COUNT files, each user-only; one record is one line (control characters
escaped) and carries no exception text, no traceback, no long hex, no base64 blob and no
URL path or query; the daemon logs startup, shutdown, signals, heartbeats and a request
that failed, and keeps serving after it; a full fake signing run with a sentinel PIN leaves
the sentinel in no log line and no file.
"""

import contextlib
import faulthandler
import io
import json
import logging
import os
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from erp_dsc_local import cli, logs
from test_cli import StubServer, StubService
from test_pin_leak_sweep import DIALOG_SENTINEL, MARK, ORIGIN, LeakSweepCase

POSIX = os.name != "nt"
SENTINEL = MARK + "-LOG-PIN-7731"


def _mode(path) -> int:
	return os.stat(path).st_mode & 0o777


def _text(path) -> str:
	return Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""


class LogDirCase(unittest.TestCase):
	def setUp(self):
		self.dir = Path(tempfile.mkdtemp(prefix="erp-dsc-logs-"))
		self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))
		self.config = self.dir / "config.json"
		self.config.write_text("{}", encoding="utf-8")

	def open_log(self, **kwargs):
		log = logs.DaemonLog(self.config, **kwargs).start()
		self.addCleanup(log.close)
		return log

	def log_text(self):
		return _text(logs.log_path(self.config))


class TestPaths(LogDirCase):
	def test_log_lives_in_the_config_folder(self):
		self.assertEqual(self.dir.resolve() / "logs" / "erp-dsc-local.log", logs.log_path(self.config).resolve())
		self.assertEqual(self.dir.resolve() / "logs", logs.log_dir(self.config).resolve())

	def test_default_is_the_state_folder(self):
		with mock.patch.dict(os.environ, {"HOME": str(self.dir)}):
			self.assertEqual(self.dir / ".erp-dsc-local" / "logs" / "erp-dsc-local.log", logs.log_path(None))
			self.assertEqual(self.dir / ".erp-dsc-local" / "config.json", logs.default_config_path())

	def test_size_and_count_limits(self):
		self.assertEqual(1024 * 1024, logs.MAX_BYTES)
		self.assertEqual(3, logs.BACKUP_COUNT)
		self.assertEqual(600, logs.HEARTBEAT_SECONDS)


@unittest.skipUnless(POSIX, "POSIX permission bits")
class TestPermissions(LogDirCase):
	def test_created_user_only_even_with_an_open_umask(self):
		previous = os.umask(0)
		try:
			log = self.open_log(heartbeat_seconds=None)
			log.event("hello")
		finally:
			os.umask(previous)
		self.assertEqual(0o600, _mode(logs.log_path(self.config)))
		self.assertEqual(0o700, _mode(logs.log_dir(self.config)))
		self.assertEqual(0o600, _mode(logs.crash_path(self.config)))

	def test_a_new_file_is_created_user_only_not_only_narrowed_afterwards(self):
		# No moment exists where a new log file is readable by others: the create mode is 0600.
		previous = os.umask(0)
		try:
			with mock.patch.object(os, "fchmod"):
				logs.open_private(self.dir / "fresh.log").close()
		finally:
			os.umask(previous)
		self.assertEqual(0o600, _mode(self.dir / "fresh.log"))

	def test_an_existing_wider_file_is_narrowed(self):
		path = logs.log_path(self.config)
		path.parent.mkdir(mode=0o755)
		path.write_text("old line\n", encoding="utf-8")
		os.chmod(path, 0o644)
		os.chmod(path.parent, 0o755)
		self.open_log(heartbeat_seconds=None)
		self.assertEqual(0o600, _mode(path))
		self.assertEqual(0o700, _mode(path.parent))
		self.assertIn("old line", self.log_text())

	def test_a_symlinked_log_file_is_refused_and_its_target_untouched(self):
		target = self.dir / "elsewhere.txt"
		target.write_text("", encoding="utf-8")
		path = logs.log_path(self.config)
		path.parent.mkdir(mode=0o700)
		path.symlink_to(target)
		with self.assertRaises(OSError):
			logs.DaemonLog(self.config, heartbeat_seconds=None).start()
		self.assertEqual("", target.read_text(encoding="utf-8"))

	def test_a_symlinked_log_folder_is_refused(self):
		elsewhere = self.dir / "elsewhere"
		elsewhere.mkdir()
		(self.dir / "logs").symlink_to(elsewhere, target_is_directory=True)
		with self.assertRaises(OSError):
			logs.DaemonLog(self.config, heartbeat_seconds=None).start()
		self.assertEqual([], list(elsewhere.iterdir()))

	def test_rotated_files_are_user_only_and_capped(self):
		previous = os.umask(0)
		try:
			log = self.open_log(max_bytes=2000, backup_count=3, heartbeat_seconds=None)
			for index in range(400):
				log.event("line %d %s", index, "x" * 40)
		finally:
			os.umask(previous)
		base = logs.log_path(self.config)
		rotated = [base] + [base.with_name(base.name + f".{n}") for n in (1, 2, 3)]
		for path in rotated:
			with self.subTest(path=path.name):
				self.assertTrue(path.is_file())
				self.assertEqual(0o600, _mode(path))
				self.assertLessEqual(path.stat().st_size, 2000)
		self.assertFalse(base.with_name(base.name + ".4").exists())


class TestLineSafety(unittest.TestCase):
	def format(self, message, *args, exc_info=None):
		record = logging.LogRecord("erp_dsc_local.events", logging.INFO, __file__, 1, message, args, exc_info)
		return logs.EventFormatter().format(record)

	def test_one_record_is_one_line(self):
		line = self.format("origin %s", "https://a.example.invalid\n2026-01-01T00:00:00Z INFO forged\r\x1b[2J")
		self.assertNotIn("\n", line)
		self.assertNotIn("\r", line)
		self.assertNotIn("\x1b", line)
		self.assertIn("\\x0a", line)

	def test_exception_text_and_traceback_are_never_written(self):
		try:
			raise RuntimeError("driver said " + SENTINEL)
		except RuntimeError:
			line = self.format("failed", exc_info=sys.exc_info())
		self.assertNotIn(SENTINEL, line)
		self.assertNotIn("Traceback", line)

	def test_long_hex_is_cut_to_its_first_eight(self):
		line = self.format("fingerprint %s", "ab12" * 16)
		self.assertIn("ab12ab12", line)
		self.assertNotIn("ab12ab12a", line)

	def test_base64_blob_is_removed(self):
		blob = "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3Jl"
		self.assertNotIn(blob[:40], self.format("der %s", blob))
		with_slashes = __import__("base64").b64encode(bytes(range(256)) * 2).decode("ascii")
		self.assertIn("/", with_slashes)
		self.assertNotIn(with_slashes[:40], self.format("der %s", with_slashes))

	def test_urls_keep_only_scheme_and_host(self):
		line = self.format("site %s", "https://user:secret@erp.example.invalid:8443/app?pin=" + SENTINEL + "#frag")
		self.assertIn("https://erp.example.invalid:8443", line)
		self.assertNotIn(SENTINEL, line)
		self.assertNotIn("secret", line)
		self.assertNotIn("/app", line)

	def test_paths_survive(self):
		path = "/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.dylib"
		self.assertIn(path, self.format("module %s", path))

	def test_line_is_capped(self):
		self.assertLessEqual(len(self.format("x" * 50000)), logs.MAX_LINE_CHARS + 80)

	def test_request_failure_names_only_route_and_class(self):
		records = []
		handler = logging.Handler()
		handler.emit = records.append
		logs.events.addHandler(handler)
		self.addCleanup(logs.events.removeHandler, handler)
		previous = logs.events.level
		logs.events.setLevel(logging.INFO)
		self.addCleanup(logs.events.setLevel, previous)
		for method, path in (("POST", "/v1/sign"), ("GET", "/v1/sign?pin=" + SENTINEL + "\nforged"), ("BREW", "/x")):
			try:
				raise ValueError("body " + SENTINEL)
			except ValueError:
				logs.log_request_failure(method, path)
		texts = [logs.EventFormatter().format(record) for record in records]
		self.assertEqual(3, len(texts))
		self.assertIn("POST /v1/sign (ValueError)", texts[0])
		self.assertIn("GET (other path) (ValueError)", texts[1])
		self.assertIn("(other method) (other path) (ValueError)", texts[2])
		for text in texts:
			self.assertNotIn(SENTINEL, text)
			self.assertNotIn("forged", text)


class TestDaemonEvents(LogDirCase):
	def test_heartbeat_is_written_and_stops_on_close(self):
		log = self.open_log(heartbeat_seconds=0.05)
		deadline = time.monotonic() + 5
		while "heartbeat" not in self.log_text() and time.monotonic() < deadline:
			time.sleep(0.02)
		self.assertIn("heartbeat: running for", self.log_text())
		thread = log._heartbeat
		log.close()
		self.assertFalse(thread.is_alive())

	def test_a_crashing_background_thread_is_logged_by_class_only(self):
		self.open_log(heartbeat_seconds=None)
		worker = threading.Thread(target=lambda: (_ for _ in ()).throw(RuntimeError(SENTINEL)), name="erp-dsc-test")
		worker.start()
		worker.join(5)
		text = self.log_text()
		self.assertIn("RuntimeError", text)
		self.assertNotIn(SENTINEL, text)

	def test_close_restores_hooks_level_and_handlers(self):
		hook, root_handlers = threading.excepthook, list(logging.getLogger(logs.LOGGER_NAME).handlers)
		was_enabled = faulthandler.is_enabled()
		log = self.open_log(heartbeat_seconds=None)
		self.assertTrue(faulthandler.is_enabled())
		self.assertIsNot(hook, threading.excepthook)
		log.close()
		self.assertIs(hook, threading.excepthook)
		self.assertEqual(root_handlers, logging.getLogger(logs.LOGGER_NAME).handlers)
		self.assertEqual(was_enabled, faulthandler.is_enabled())

	def test_faulthandler_writes_to_the_crash_file(self):
		calls = []
		with mock.patch.object(faulthandler, "enable", side_effect=lambda **kw: calls.append(kw)):
			log = self.open_log(heartbeat_seconds=None)
		self.assertEqual(1, len(calls))
		self.assertEqual(os.stat(logs.crash_path(self.config)).st_ino, os.fstat(calls[0]["file"].fileno()).st_ino)
		self.assertTrue(calls[0]["all_threads"])
		log.close()

	def test_an_unopenable_log_is_one_fixed_stderr_line_and_the_daemon_goes_on(self):
		err = io.StringIO()
		with contextlib.redirect_stderr(err), mock.patch.object(logs, "ensure_private_dir", side_effect=PermissionError(SENTINEL)):
			self.assertIsNone(logs.start_daemon_log(self.config))
		self.assertEqual(logs.LOG_UNAVAILABLE_LINE + "\n", err.getvalue())


class TestCliWiring(LogDirCase):
	def setUp(self):
		super().setUp()
		self._saved = {n: signal.getsignal(n) for n in (signal.SIGTERM, signal.SIGINT)}
		if hasattr(signal, "SIGHUP"):
			self._saved[signal.SIGHUP] = signal.getsignal(signal.SIGHUP)

	def tearDown(self):
		for number, handler in self._saved.items():
			signal.signal(number, handler)

	def test_main_logs_start_and_stop_and_closes_the_log(self):
		events = []
		server = StubServer(events)
		server._requested.set()
		fake = types.ModuleType("erp_dsc_local.service")
		fake.SignerService = lambda config: StubService(events, server)
		fake.VERSION = "9.9.9-test"
		with mock.patch.dict(sys.modules, {"erp_dsc_local.service": fake}), mock.patch.object(
			sys, "argv", ["erp-dsc-local", "--config", str(self.config)]
		), mock.patch("resource.setrlimit"):
			cli.main()
		text = self.log_text()
		self.assertIn("started: ERP DSC Signer 9.9.9-test on 127.0.0.1:17777", text)
		self.assertIn(" stopped", text)
		self.assertEqual([], [h for h in logging.getLogger(logs.LOGGER_NAME).handlers if isinstance(h, logs.PrivateRotatingFileHandler)])

	def test_port_in_use_is_one_line_not_a_traceback(self):
		events = []
		server = StubServer(events)
		service = StubService(events, server)

		def busy():
			raise OSError(48, "Address already in use " + SENTINEL)

		service.make_server = busy
		fake = types.ModuleType("erp_dsc_local.service")
		fake.SignerService = lambda config: service
		err = io.StringIO()
		with mock.patch.dict(sys.modules, {"erp_dsc_local.service": fake}), mock.patch.object(
			sys, "argv", ["erp-dsc-local", "--config", str(self.config)]
		), mock.patch("resource.setrlimit"), contextlib.redirect_stderr(err):
			with self.assertRaises(SystemExit) as raised:
				cli.main()
		self.assertEqual(1, raised.exception.code)
		self.assertEqual(1, len(err.getvalue().splitlines()), err.getvalue())
		self.assertIn("could not start on 127.0.0.1:17777 (OSError, errno 48)", err.getvalue())
		self.assertIn("could not start on 127.0.0.1:17777 (OSError, errno 48)", self.log_text())
		self.assertNotIn(SENTINEL, err.getvalue() + self.log_text())
		self.assertNotIn("Traceback", err.getvalue())

	def test_signal_receipt_is_logged(self):
		log = self.open_log(heartbeat_seconds=None)
		events = []
		server = StubServer(events)
		service = StubService(events, server)
		cli._install_signal_handlers(service, server)
		server._returned.set()
		signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
		self.assertTrue(server._requested.wait(3))
		server.shutdown_thread.join(3)
		self.assertIn("received SIGTERM, stopping", self.log_text())
		log.close()

	def test_show_log_path_prints_and_creates_nothing(self):
		out = io.StringIO()
		with mock.patch.object(sys, "argv", ["erp-dsc-local", "--show-log-path", "--config", str(self.config)]), contextlib.redirect_stdout(out):
			with self.assertRaises(SystemExit) as raised:
				cli.main()
		self.assertEqual(0, raised.exception.code)
		self.assertEqual(str(logs.log_path(self.config)) + "\n", out.getvalue())
		self.assertFalse(logs.log_dir(self.config).exists())


class TestSweepWithLogFile(LeakSweepCase):
	"""The leak sweep again, with the real log file open in the scanned config folder."""

	def setUp(self):
		super().setUp()
		self.log = logs.DaemonLog(self.config_dir / "config.json", heartbeat_seconds=0.05).start()
		self.addCleanup(self.log.close)
		self.log.event("test run started")

	def log_text(self):
		return _text(logs.log_path(self.config_dir / "config.json"))

	def test_full_signing_run_leaves_no_pin_in_the_log(self):
		self.use_child("success")
		self.assertEqual(200, self.sign()[0])
		self.token.mode = "driver_echo"
		self.assertEqual(500, self.sign()[0])
		handler = self.server.RequestHandlerClass
		with mock.patch.object(handler, "_respond", side_effect=RuntimeError("held " + DIALOG_SENTINEL)):
			with self.assertRaises(OSError):
				urllib.request.urlopen(urllib.request.Request(self.base + "/v1/health"), timeout=10).read()
		deadline = time.monotonic() + 5
		while "heartbeat" not in self.log_text() and time.monotonic() < deadline:
			time.sleep(0.02)
		text = self.log_text()
		# Not vacuous: the run wrote the lines this test is about...
		self.assertIn("request failed: POST /v1/sign (RuntimeError)", text)
		self.assertIn("request failed: GET /v1/health (RuntimeError)", text)
		self.assertIn("a request could not be handled and was dropped (RuntimeError)", text)
		self.assertIn("heartbeat", text)
		# ...and none of them, nor any file, holds the sentinel.
		self.assertNotIn(MARK, text)
		self.assertEqual([], self.files_with_sentinel())
		self.assertNotIn(DIALOG_SENTINEL, self.stderr.getvalue())

	def test_daemon_survives_a_failing_request_and_logs_it(self):
		with mock.patch.object(self.service, "list_certificates", side_effect=RuntimeError(SENTINEL)):
			_s, issued = self.request(self.base + "/v1/nonce", method="POST", body={"purpose": "certificates"})
			status, body = self.request(self.base + "/v1/certificates", method="POST", body={"nonce": issued["nonce"]})
		self.assertEqual(500, status, body)
		status, body = self.request(self.base + "/v1/health")
		self.assertEqual((200, True), (status, body["ok"]))
		self.assertIn("request failed: POST /v1/certificates (RuntimeError); the signer keeps running", self.log_text())
		self.assertNotIn(SENTINEL, self.log_text())

	def test_a_hostile_path_is_not_written(self):
		handler = self.server.RequestHandlerClass
		with mock.patch.object(handler, "_not_found", side_effect=RuntimeError("x")):
			self.request(self.base + "/v1/zz?pin=" + SENTINEL + "%0Aforged")
		text = self.log_text()
		self.assertIn("request failed: GET (other path) (RuntimeError)", text)
		self.assertNotIn(SENTINEL, text)
		self.assertNotIn("forged", text)


if __name__ == "__main__":
	unittest.main()
