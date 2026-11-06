"""DialogHost: spawn contract, supervision, classifier and lock (spec 001 §3.2, §4-§6, I5).

Children are the stub in tests/_stub_child.py (or a Popen stand-in where the OS cannot
be made to misbehave on demand); no display is needed.  The supervision constants are
patched small so deadline paths take about a second.
"""

import errno
import json
import logging
import os
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import types
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child, ui
from erp_dsc_local.errors import DialogFailed, DialogWedged


TESTS_DIR = Path(__file__).resolve().parent
LOCAL_SIGNER = TESTS_DIR.parent
STUB = TESTS_DIR / "_stub_child.py"
ORIGIN = "https://site.example"
SENTINEL = "S3NT1NEL-PIN-7731"
REAL_POPEN = subprocess.Popen


def request(*claims, kind="pin", origin=ORIGIN, warnings=(), final_try=False, timeout=0):
	return {
		"v": 1,
		"kind": kind,
		"origin": origin,
		"claims": list(claims),
		"warnings": list(warnings),
		"final_try": final_try,
		"timeout": timeout,
	}


def raw(obj) -> str:
	return json.dumps(obj, separators=(",", ":"))


def patch_timing(test, *, startup=5.0, grace=0.3, kill_delay=0.5):
	"""Small supervision constants; a request timeout of 0 then stays 0 after the clamp."""
	for target, name, value in (
		(ui, "STARTUP_ALLOWANCE_SECONDS", startup),
		(ui, "GRACE_SECONDS", grace),
		(ui, "KILL_DELAY_SECONDS", kill_delay),
		(dialog_child, "MIN_DIALOG_SECONDS", 0),
	):
		patcher = mock.patch.object(target, name, value)
		patcher.start()
		test.addCleanup(patcher.stop)


class PopenRecorder:
	"""Stands in for subprocess.Popen: records each call, then runs the real one."""

	def __init__(self, factory=None):
		self.calls = []
		self.procs = []
		self._factory = factory or REAL_POPEN

	def __call__(self, argv, **kwargs):
		self.calls.append((list(argv), dict(kwargs)))
		proc = self._factory(argv, **kwargs)
		self.procs.append(proc)
		return proc


def install_popen(test, factory=None) -> PopenRecorder:
	recorder = PopenRecorder(factory)
	patcher = mock.patch.object(subprocess, "Popen", recorder)
	patcher.start()
	test.addCleanup(patcher.stop)

	def reap():
		for proc in recorder.procs:
			if isinstance(proc, REAL_POPEN) and proc.poll() is None:
				proc.kill()
				proc.wait(5)

	test.addCleanup(reap)
	return recorder


def run_in_thread(fn):
	box = {}

	def target():
		try:
			box["result"] = fn()
		except BaseException as exc:  # noqa: BLE001 - handed back to the test
			box["error"] = exc

	thread = threading.Thread(target=target, daemon=True)
	thread.start()
	return thread, box


def wait_for(predicate, timeout=5.0):
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		if predicate():
			return True
		time.sleep(0.01)
	return predicate()


class HostCase(unittest.TestCase):
	def setUp(self):
		patch_timing(self)
		self.popen = install_popen(self)
		self.host = ui.DialogHost(child_script=STUB)

	def cause_of(self, req):
		with self.assertRaises(DialogFailed) as ctx:
			self.host.run_dialog(req)
		self.assertIsNone(ctx.exception.__context__)
		self.assertFalse(self.host.busy, "the lock must be free after an ordinary failure")
		return ctx.exception.cause

	def report(self, *claims, **fields) -> dict:
		directory = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, directory, True)
		path = os.path.join(directory, "r.json")
		self.host.run_dialog(request("MODE:report", path, *claims, **fields))
		with open(path, encoding="utf-8") as handle:
			return json.load(handle)


# --- spawn contract (§4) -------------------------------------------------------------
class TestSpawnContract(HostCase):
	def test_child_command_pure_shape(self):
		expected = [sys.executable, "-I", os.path.abspath(dialog_child.__file__)]
		with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawned")):
			self.assertEqual(expected, ui.child_command())
			self.assertEqual(expected, ui.child_command())  # pure: same answer every time
			self.assertEqual([sys.executable, "-I", str(STUB)], ui.child_command(STUB))
			relative = os.path.relpath(STUB)
			self.assertEqual(str(STUB), ui.child_command(relative)[2])
		self.assertTrue(os.path.isabs(expected[2]))
		self.assertTrue(os.path.isfile(expected[2]), "the child must be a real file")

	def test_spawned_argv_carries_no_caller_data(self):
		self.host.run_dialog(request("MODE:result:cancelled", SENTINEL, origin="https://" + SENTINEL.lower() + ".example"))
		argv, kwargs = self.popen.calls[0]
		self.assertEqual(ui.child_command(STUB), argv)
		self.assertNotIn(SENTINEL, " ".join(argv))
		self.assertNotIn(SENTINEL.lower(), json.dumps(kwargs["env"]))

	def test_default_host_spawns_the_real_dialog_child(self):
		refuse = PopenRecorder(factory=mock.Mock(side_effect=OSError("no spawn in tests")))
		with mock.patch.object(subprocess, "Popen", refuse):
			with self.assertRaises(DialogFailed) as ctx:
				ui.DialogHost().run_dialog(request("anything"))
		self.assertEqual("dialog_spawn_failed", ctx.exception.cause)
		self.assertEqual(ui.child_command(), refuse.calls[0][0])

	def test_popen_kwargs_stdin_is_a_pipe_never_devnull(self):
		self.host.run_dialog(request("MODE:result:cancelled"))
		_argv, kwargs = self.popen.calls[0]
		self.assertIs(subprocess.PIPE, kwargs["stdin"])
		self.assertIsNot(subprocess.DEVNULL, kwargs["stdin"])
		self.assertIs(subprocess.PIPE, kwargs["stdout"])
		self.assertIs(subprocess.DEVNULL, kwargs["stderr"])
		self.assertIs(True, kwargs["close_fds"])
		self.assertIs(False, kwargs.get("shell", False))
		self.assertEqual(tempfile.gettempdir(), kwargs["cwd"])
		self.assertNotIn("preexec_fn", kwargs)
		self.assertEqual(ui.child_env(), kwargs["env"])
		if os.name == "nt":
			self.assertTrue(kwargs["creationflags"] & 0x08000000)
		else:
			self.assertIs(True, kwargs["start_new_session"])
			self.assertNotIn("creationflags", kwargs)

	def test_env_allowlist(self):
		extra = {
			"ERP_DSC_SECRET": SENTINEL,
			"PYTHONPATH": "/evil",
			"PYTHONSTARTUP": "/evil.py",
			"TCL_LIBRARY": "/evil/tcl",
			"TK_LIBRARY": "/evil/tk",
			"TCLLIBPATH": "/evil",
			"DYLD_INSERT_LIBRARIES": "/evil.dylib",
			"LD_PRELOAD": "/evil.so",
			"LC_CTYPE": "UTF-8",
			"LANG": "en_IN.UTF-8",
			"DISPLAY": ":42",
		}
		forbidden = {k for k in extra if not k.startswith("LC_") and k not in ("LANG", "DISPLAY")}
		allowed = set(ui._ENV_NAMES) | (set(ui._ENV_NAMES_WINDOWS) if os.name == "nt" else set())
		with mock.patch.dict(os.environ, extra):
			got = self.report()
		_argv, kwargs = self.popen.calls[0]
		passed = kwargs["env"]
		self.assertEqual(set(), {k for k in passed if k not in allowed and not k.startswith("LC_")})
		self.assertEqual("UTF-8", passed["LC_CTYPE"])
		self.assertEqual(":42", passed["DISPLAY"])
		self.assertEqual("en_IN.UTF-8", passed["LANG"])
		# The child itself: nothing forbidden arrived (macOS adds __CF_USER_TEXT_ENCODING
		# to every process, so the child's env is checked for absence, not equality).
		self.assertEqual(set(), forbidden & set(got["env"]))
		self.assertNotIn(SENTINEL, json.dumps(got["env"]))
		self.assertEqual(":42", got["env"]["DISPLAY"])
		self.assertEqual(1, got["ignore_environment"])
		self.assertEqual(1, got["isolated"])
		self.assertEqual(os.path.realpath(tempfile.gettempdir()), os.path.realpath(got["cwd"]))
		self.assertTrue(got["stderr_is_devnull"])

	def test_child_env_names_per_platform(self):
		environ = {
			"PATH": "p",
			"HOME": "h",
			"TMPDIR": "t",
			"LANG": "l",
			"LC_ALL": "a",
			"WAYLAND_DISPLAY": "w",
			"XAUTHORITY": "x",
			"SYSTEMROOT": "s",
			"WINDIR": "w",
			"TEMP": "t",
			"TMP": "t",
			"USERPROFILE": "u",
			"TCL_LIBRARY": "bad",
			"OTHER": "bad",
		}
		with mock.patch.object(ui.os, "name", "posix"):
			posix = ui.child_env(environ)
		with mock.patch.object(ui.os, "name", "nt"):
			windows = ui.child_env(environ)
		self.assertEqual(
			{"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "WAYLAND_DISPLAY", "XAUTHORITY"}, set(posix)
		)
		self.assertEqual(set(posix) | {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE"}, set(windows))

	def test_request_is_newline_terminated_and_stdin_stays_open(self):
		req = request("MODE:report")
		got = self.report()
		line = got["request_line"]
		self.assertTrue(line.endswith("\n"))
		self.assertEqual(1, line.count("\n"), "exactly one newline, the terminator")
		self.assertEqual("open", got["stdin"], "stdin must stay open as the child's lifeline")
		received = json.loads(line)
		self.assertEqual(dialog_child.validate_request(dict(req, claims=received["claims"])), received)

	def test_request_without_newline_times_out(self):
		# The failure case the framing test guards: the stub's readline() never returns.
		patch_timing(self, startup=0.8, grace=0.2, kill_delay=0.3)
		real = dialog_child.encode_request
		with mock.patch.object(dialog_child, "encode_request", lambda r: real(r)[:-1]):
			self.assertEqual("dialog_timeout", self.cause_of(request("MODE:result:cancelled")))
		self.assertLess(self.popen.procs[0].returncode, 0, "killed and reaped at the deadline")

	def test_missing_script_is_spawn_failed_without_popen(self):
		host = ui.DialogHost(child_script=TESTS_DIR / "no_such_child.py")
		with self.assertRaises(DialogFailed) as ctx:
			host.run_dialog(request("MODE:result:cancelled"))
		self.assertEqual("dialog_spawn_failed", ctx.exception.cause)
		self.assertEqual([], self.popen.calls)
		self.assertFalse(host.busy)

	def test_popen_raising_is_spawn_failed(self):
		host = ui.DialogHost(child_script=STUB)
		with mock.patch.object(subprocess, "Popen", side_effect=OSError(errno.EAGAIN, "fork failed")):
			with self.assertRaises(DialogFailed) as ctx:
				host.run_dialog(request("MODE:result:cancelled"))
		self.assertEqual("dialog_spawn_failed", ctx.exception.cause)
		self.assertIsNone(ctx.exception.__context__)
		self.assertFalse(host.busy)

	def test_stub_mirrors_the_wire_reply_cap(self):
		self.assertEqual(dialog_child.MAX_REPLY_BYTES, runpy.run_path(str(STUB))["MAX_REPLY_BYTES"])

	def test_a_hostile_253_character_host_is_refused_before_any_spawn(self):
		# Its tail (the attacker's real domain) could not be shown in full: no dialog at all.
		host = ("erp.mycompany.com." * 15)[:249] + ".com"
		self.assertEqual(253, len(host))
		for kind in dialog_child.KINDS:
			with self.subTest(kind=kind):
				self.assertEqual("dialog_request_invalid", self.cause_of(request("MODE:result:cancelled", kind=kind, origin="https://" + host)))
		self.assertEqual([], self.popen.calls, "refused before spawn")
		at_limit = "https://" + "h" * (dialog_child.MAX_ORIGIN_CHARS - len("https://"))
		self.assertEqual("cancelled", self.host.run_dialog(request("MODE:result:cancelled", origin=at_limit))["result"])
		self.assertEqual(1, len(self.popen.calls), "a host at MAX_ORIGIN_CHARS is shown")


# --- classifier (§6), against a real child ----------------------------------------------
class TestValidReplies(HostCase):
	def test_valid_replies_are_returned(self):
		cases = [
			("pin", "MODE:ok_entered:" + SENTINEL, {"result": "entered", "value": SENTINEL}),
			("pin", "MODE:result:cancelled", {"result": "cancelled"}),
			("pin", "MODE:result:timeout", {"result": "timeout"}),
			("pin", "MODE:unavailable:tk_init_failed", {"result": "unavailable", "cause": "tk_init_failed"}),
			("pin", "MODE:unavailable:tk_import_failed", {"result": "unavailable", "cause": "tk_import_failed"}),
			("consent", "MODE:result:allow", {"result": "allow"}),
			("consent", "MODE:result:deny", {"result": "deny"}),
			("consent", "MODE:result:timeout", {"result": "timeout"}),
		]
		for kind, mode, expected in cases:
			with self.subTest(mode=mode, kind=kind):
				reply = self.host.run_dialog(request(mode, kind=kind))
				self.assertEqual(dict({"v": 1, "kind": kind}, **expected), reply)
				self.assertFalse(self.host.busy)
				self.assertEqual(0, self.popen.procs[-1].returncode)

	def test_reply_then_linger_is_accepted_after_grace_and_child_killed(self):
		patch_timing(self, startup=5.0, grace=0.3, kill_delay=0.5)
		start = time.monotonic()
		reply = self.host.run_dialog(request("MODE:reply_then_hang:" + SENTINEL))
		elapsed = time.monotonic() - start
		self.assertEqual(SENTINEL, reply["value"])
		self.assertLess(elapsed, 3.0, "the PIN must not be held until the deadline")
		self.assertLess(self.popen.procs[0].returncode, 0, "killed after the grace period")


class TestClassifierRows(HostCase):
	def assertCause(self, cause, *claims, kind="pin"):
		self.assertEqual(cause, self.cause_of(request(*claims, kind=kind)))

	def test_exit_codes(self):
		self.assertCause("dialog_process_crashed", "MODE:crash")
		self.assertCause("dialog_process_failed", "MODE:exit:3")
		self.assertCause("dialog_process_failed", "MODE:exit:70")
		self.assertCause("dialog_request_invalid", "MODE:exit:65")

	def test_valid_reply_with_nonzero_exit_is_ignored(self):
		self.assertCause("dialog_process_failed", "MODE:valid_then_exit:1", SENTINEL)
		self.assertCause("dialog_request_invalid", "MODE:valid_then_exit:65")

	def test_exit_zero_bad_output(self):
		self.assertCause("dialog_bad_reply", "MODE:empty")
		self.assertCause("dialog_bad_reply", "MODE:partial")
		self.assertCause("dialog_bad_reply", "MODE:badjson:x")
		self.assertCause("dialog_bad_reply", "MODE:extra_line:x")
		self.assertCause("dialog_bad_reply", "MODE:unavailable:bogus_cause")

	def test_schema_violations_are_bad_reply(self):
		pin = {"v": 1, "kind": "pin"}
		cases = {
			"missing result": raw(pin),
			"missing v": raw({"kind": "pin", "result": "cancelled"}),
			"extra key": raw(dict(pin, result="cancelled", note="x")),
			"v is 2": raw(dict(pin, v=2, result="cancelled")),
			"v is true": raw(dict(pin, v=True, result="cancelled")),
			"v is a string": raw(dict(pin, v="1", result="cancelled")),
			"v is a float": raw(dict(pin, v=1.0, result="cancelled")),
			"v is NaN": '{"v":NaN,"kind":"pin","result":"cancelled"}',
			"kind mismatch": raw({"v": 1, "kind": "consent", "result": "deny"}),
			"unknown result": raw(dict(pin, result="maybe")),
			"result of the other kind": raw(dict(pin, result="allow")),
			"stray value": raw(dict(pin, result="cancelled", value="1234")),
			"stray cause": raw(dict(pin, result="cancelled", cause="tk_init_failed")),
			"unknown cause": raw(dict(pin, result="unavailable", cause="dialog_timeout")),
			"unavailable without cause": raw(dict(pin, result="unavailable")),
			"entered empty value": raw(dict(pin, result="entered", value="")),
			"entered without value": raw(dict(pin, result="entered")),
			"entered non-string value": raw(dict(pin, result="entered", value=1234)),
			"duplicate key": '{"v":1,"kind":"pin","result":"entered","result":"cancelled"}',
			"top level list": raw([pin]),
			"top level string": raw("cancelled"),
		}
		for label, line in cases.items():
			with self.subTest(label):
				self.assertLessEqual(len(line), dialog_child.MAX_CLAIM_CHARS)
				self.assertCause("dialog_bad_reply", "MODE:raw", line)

	def test_deadline_kill_is_timeout_not_crashed(self):
		patch_timing(self, startup=0.8, grace=0.2, kill_delay=0.5)
		start = time.monotonic()
		self.assertCause("dialog_timeout", "MODE:hang")
		self.assertGreaterEqual(time.monotonic() - start, 1.0)
		self.assertLess(self.popen.procs[0].returncode, 0, "the child was killed and reaped")

	def test_deadline_escalates_to_kill_when_terminate_is_ignored(self):
		patch_timing(self, startup=0.8, grace=0.2, kill_delay=0.4)
		start = time.monotonic()
		self.assertCause("dialog_timeout", "MODE:ignore_term")
		self.assertGreaterEqual(time.monotonic() - start, 1.0 + 0.4)
		self.assertEqual(-signal.SIGKILL, self.popen.procs[0].returncode)

	def test_oversize_is_bad_reply_not_crashed_and_not_timeout(self):
		patch_timing(self, startup=5.0, grace=0.3, kill_delay=0.5)
		start = time.monotonic()
		self.assertCause("dialog_bad_reply", "MODE:oversize:" + SENTINEL)
		self.assertLess(time.monotonic() - start, 3.0, "killed on the extra byte, not at the deadline")
		self.assertLess(self.popen.procs[0].returncode, 0)
		self.assertCause("dialog_bad_reply", "MODE:oversize_line")

	def test_bad_line_then_linger_is_bad_reply_after_grace(self):
		patch_timing(self, startup=5.0, grace=0.3, kill_delay=0.5)
		start = time.monotonic()
		self.assertCause("dialog_bad_reply", "MODE:badjson_then_hang")
		self.assertLess(time.monotonic() - start, 3.0)


class _Proc:
	def __init__(self, returncode):
		self.returncode = returncode


def _load_line(child, line):
	"""Put `line` + newline into the child's reply buffer, as _read_reply would."""
	data = bytes(line) + b"\n"
	child.buffer[: len(data)] = data
	child.filled = len(data)
	child.line_end = len(data) - 1
	child.line_complete = True


class TestClassifierOrder(unittest.TestCase):
	"""§6 is ORDERED by recorded kill reason; checked directly on the classifier."""

	VALID = bytearray(b'{"v":1,"kind":"pin","result":"cancelled"}')

	def classify(self, *, reason=None, returncode=0, line=VALID, extra=False, shutting_down=False):
		host = ui.DialogHost(child_script=STUB)
		host._shutting_down = shutting_down
		child = ui._Child(_Proc(returncode), 0.0, None)
		child.reason = reason
		if line is not None:
			_load_line(child, line)
		child.extra = extra
		return host._classify(child, "pin")

	def test_order(self):
		ok = {"v": 1, "kind": "pin", "result": "cancelled"}
		rows = [
			(dict(reason="deadline", returncode=-9, shutting_down=True), "dialog_shutdown"),
			(dict(reason="shutdown", returncode=-15), "dialog_shutdown"),
			(dict(reason="deadline", returncode=-9), "dialog_timeout"),
			(dict(reason="deadline", returncode=0), "dialog_timeout"),
			(dict(reason="oversize", returncode=-9), "dialog_bad_reply"),
			(dict(reason="oversize", returncode=65), "dialog_bad_reply"),
			(dict(returncode=65), "dialog_request_invalid"),
			(dict(returncode=-9), "dialog_process_crashed"),
			(dict(returncode=1), "dialog_process_failed"),
			(dict(returncode=None), "dialog_process_failed"),
			(dict(returncode=0, line=None), "dialog_bad_reply"),
			(dict(returncode=0, extra=True), "dialog_bad_reply"),
			(dict(returncode=0), ok),
			(dict(reason="after_reply", returncode=-15), ok),
			(dict(reason="after_reply", returncode=-15, line=b"{"), "dialog_bad_reply"),
		]
		for fields, expected in rows:
			with self.subTest(**{k: v for k, v in fields.items() if k != "line"}):
				self.assertEqual(expected, self.classify(**fields))

	def test_line_is_parsed_in_place_and_wipe_zeroes_the_buffer(self):
		host = ui.DialogHost(child_script=STUB)
		child = ui._Child(_Proc(0), 0.0, None)
		_load_line(child, b'{"v":1,"kind":"pin","result":"entered","value":"' + SENTINEL.encode() + b'"}')
		self.assertEqual(len(child.buffer), dialog_child.MAX_REPLY_BYTES + 1, "preallocated to the cap + 1")
		self.assertEqual(SENTINEL, host._classify(child, "pin")["value"])
		child.wipe()
		self.assertEqual(bytes(len(child.buffer)), bytes(child.buffer))
		self.assertTrue(child.wiped)


# --- write errors (EPIPE / EINVAL) via a Popen stand-in -----------------------------------
class _FailingStdin:
	def __init__(self, error):
		self.error = error
		self.closed = False

	def write(self, _data):
		raise self.error

	def flush(self):
		pass

	def close(self):
		self.closed = True


class _ExitedProc:
	"""A child that already exited with `returncode` after writing `output`."""

	def __init__(self, error, output, returncode):
		read_end, write_end = os.pipe()
		os.write(write_end, output)
		os.close(write_end)
		self.stdout = os.fdopen(read_end, "rb", buffering=0)
		self.stdin = _FailingStdin(error)
		self.pid = 0
		self.returncode = None
		self._code = returncode

	def poll(self):
		self.returncode = self._code
		return self._code

	def wait(self, timeout=None):
		return self.poll()

	def terminate(self):
		pass

	def kill(self):
		pass


class TestWriteErrors(unittest.TestCase):
	VALID = b'{"v":1,"kind":"pin","result":"cancelled"}\n'

	def run_with(self, error, output, returncode):
		patch_timing(self)
		hook_calls = []
		patcher = mock.patch.object(threading, "excepthook", lambda args: hook_calls.append(args))
		patcher.start()
		self.addCleanup(patcher.stop)
		install_popen(self, lambda argv, **kw: _ExitedProc(error, output, returncode))
		host = ui.DialogHost(child_script=STUB)
		try:
			return host.run_dialog(request("x"))
		finally:
			self.assertEqual([], hook_calls, "a helper thread raised")
			self.assertFalse(host.busy)

	def test_broken_pipe_then_valid_reply(self):
		reply = self.run_with(BrokenPipeError(errno.EPIPE, "pipe"), self.VALID, 0)
		self.assertEqual("cancelled", reply["result"])

	def test_einval_then_valid_reply(self):
		reply = self.run_with(OSError(errno.EINVAL, "closed pipe"), self.VALID, 0)
		self.assertEqual("cancelled", reply["result"])

	def test_broken_pipe_without_reply_is_process_failed(self):
		with self.assertRaises(DialogFailed) as ctx:
			self.run_with(BrokenPipeError(errno.EPIPE, "pipe"), b"", 1)
		self.assertEqual("dialog_process_failed", ctx.exception.cause)

	def test_einval_without_reply_exit_zero_is_bad_reply(self):
		with self.assertRaises(DialogFailed) as ctx:
			self.run_with(OSError(errno.EINVAL, "closed pipe"), b"", 0)
		self.assertEqual("dialog_bad_reply", ctx.exception.cause)


# --- lifecycle (§5, I5) ------------------------------------------------------------------
class TestShutdown(HostCase):
	def start_hanging_dialog(self):
		thread, box = run_in_thread(lambda: self.host.run_dialog(request("MODE:hang", timeout=120)))
		self.assertTrue(wait_for(lambda: self.host._child is not None), "child never tracked")
		return thread, box

	def test_shutdown_kills_the_in_flight_child(self):
		thread, box = self.start_hanging_dialog()
		start = time.monotonic()
		self.host.shutdown()
		thread.join(5)
		self.assertFalse(thread.is_alive())
		self.assertLess(time.monotonic() - start, 2.0)
		self.assertIsInstance(box.get("error"), DialogFailed)
		self.assertEqual("dialog_shutdown", box["error"].cause)
		self.assertIsNotNone(self.popen.procs[0].returncode, "the child was reaped")
		self.assertFalse(self.host.busy)
		self.assertTrue(self.host.shutting_down)
		# Once shutting down, no further child is started.
		self.assertEqual("dialog_shutdown", self.cause_of(request("MODE:result:cancelled")))
		self.assertEqual(1, len(self.popen.calls))

	def test_kill_child_does_not_take_the_lock(self):
		thread, box = self.start_hanging_dialog()
		self.assertTrue(self.host.busy)
		self.host.kill_child()  # would deadlock or raise UiBusy if it took the lock
		thread.join(5)
		self.assertEqual("dialog_shutdown", box["error"].cause)

	@unittest.skipUnless(hasattr(signal, "SIGTERM") and os.name != "nt", "POSIX signals")
	def test_sigterm_handler_shutdown_does_not_deadlock(self):
		previous = signal.signal(signal.SIGTERM, lambda _signo, _frame: self.host.shutdown())
		self.addCleanup(signal.signal, signal.SIGTERM, previous)
		thread, box = self.start_hanging_dialog()
		os.kill(os.getpid(), signal.SIGTERM)  # the handler runs on this (main) thread
		thread.join(5)
		self.assertFalse(thread.is_alive(), "the dialog thread deadlocked")
		self.assertEqual("dialog_shutdown", box["error"].cause)

	def test_kill_reason_is_set_once_first_wins(self):
		child = ui._Child(_Proc(None), 0.0, None)
		for reason in ("deadline", "oversize", "shutdown"):
			child.record(reason)
		self.assertEqual("deadline", child.reason)

		# Live: the deadline is recorded, the child ignores SIGTERM, and a kill_child()
		# (no shutdown flag) arrives during the kill delay.  The first reason stands.
		patch_timing(self, startup=0.4, grace=0.1, kill_delay=0.8)
		thread, box = run_in_thread(lambda: self.host.run_dialog(request("MODE:ignore_term")))
		self.assertTrue(wait_for(lambda: self.host._child is not None and self.host._child.reason == "deadline"))
		self.host.kill_child()
		thread.join(5)
		self.assertEqual("dialog_timeout", box["error"].cause)

	def test_kill_child_with_nothing_running_is_a_no_op(self):
		self.host.kill_child()
		self.assertFalse(self.host.shutting_down)
		self.assertEqual("cancelled", self.host.run_dialog(request("MODE:result:cancelled"))["result"])


_HELPER_PARENT = """
import sys, threading, time
sys.path.insert(0, sys.argv[1])
from erp_dsc_local import ui
host = ui.DialogHost(child_script=sys.argv[2])
req = {"v": 1, "kind": "pin", "origin": "https://site.example", "claims": ["MODE:watch", sys.argv[3]],
       "warnings": [], "final_try": False, "timeout": 120}
threading.Thread(target=host.run_dialog, args=(req,), daemon=True).start()
time.sleep(60)
"""


@unittest.skipIf(os.name == "nt", "SIGKILL of a parent is POSIX-only here")
class TestChildDiesWithParent(unittest.TestCase):
	def test_child_exits_within_one_second_of_parent_sigkill(self):
		directory = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, directory, True)
		pidfile = os.path.join(directory, "pid")
		self.assertLessEqual(len(pidfile), dialog_child.MAX_CLAIM_CHARS)
		parent = subprocess.Popen(
			[sys.executable, "-c", _HELPER_PARENT, str(LOCAL_SIGNER), str(STUB), pidfile],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
		self.addCleanup(lambda: parent.poll() is None and (parent.kill(), parent.wait(5)))
		self.assertTrue(wait_for(lambda: os.path.exists(pidfile) and Path(pidfile).read_text(), 10))
		child_pid = int(Path(pidfile).read_text())
		self.addCleanup(self._kill_quietly, child_pid)
		self.assertTrue(self._alive(child_pid))

		parent.kill()  # SIGKILL: no cleanup code in the parent runs
		parent.wait(5)
		gone_by = time.monotonic() + 1.0
		while self._alive(child_pid) and time.monotonic() < gone_by:
			time.sleep(0.02)
		self.assertFalse(self._alive(child_pid), "the dialog child outlived its parent by > 1 s")

	@staticmethod
	def _alive(pid):
		try:
			os.kill(pid, 0)
		except ProcessLookupError:
			return False
		except PermissionError:
			return True
		return True

	@staticmethod
	def _kill_quietly(pid):
		try:
			os.kill(pid, signal.SIGKILL)
		except OSError:
			pass


class _StuckProc:
	"""A child that never exits and cannot be reaped."""

	def __init__(self):
		read_end, self._stdout_writer = os.pipe()
		self.stdout = os.fdopen(read_end, "rb", buffering=0)
		self._stdin_reader, write_end = os.pipe()
		self.stdin = os.fdopen(write_end, "wb", buffering=0)
		self.pid = 0
		self.returncode = None
		self.terminated = 0
		self.killed = 0

	def poll(self):
		return None

	def wait(self, timeout=None):
		raise subprocess.TimeoutExpired("stuck-child", timeout)

	def terminate(self):
		self.terminated += 1

	def kill(self):
		self.killed += 1

	def release(self):
		for fd in (self._stdout_writer, self._stdin_reader):
			try:
				os.close(fd)
			except OSError:
				pass


class TestWedged(unittest.TestCase):
	def test_unreapable_child_keeps_the_lock_and_later_calls_get_dialog_wedged(self):
		patch_timing(self, startup=0.2, grace=0.1, kill_delay=0.1)
		stuck = _StuckProc()
		self.addCleanup(stuck.release)
		recorder = install_popen(self, lambda argv, **kw: stuck)
		host = ui.DialogHost(child_script=STUB)

		with self.assertLogs("erp_dsc_local.ui", level="ERROR") as logs:
			with self.assertRaises(DialogWedged) as ctx:
				host.run_dialog(request("MODE:hang"))
		self.assertIsNone(ctx.exception.__context__)
		self.assertEqual([ui._WEDGED_LOG_LINE], [r.getMessage() for r in logs.records])
		self.assertGreaterEqual(stuck.terminated, 1)
		self.assertGreaterEqual(stuck.killed, 1)
		self.assertTrue(host.wedged)
		self.assertTrue(host.busy, "an un-reapable child must keep the lock")

		with self.assertRaises(DialogWedged):  # not UiBusy, and no second spawn
			host.run_dialog(request("MODE:result:cancelled"))
		with self.assertRaises(DialogWedged):
			host.run_exclusive(lambda: "anything")
		self.assertEqual(1, len(recorder.calls))
		self.assertEqual(503, DialogWedged().status)

		# Test hygiene: let the blocked reader see EOF, then close the pipe it held.
		stuck.release()
		host._child.reader.join(2)
		self.assertFalse(host._child.reader.is_alive())
		stuck.stdout.close()


# --- the lock -------------------------------------------------------------------------------
class TestLock(HostCase):
	def test_ui_busy_while_a_dialog_runs(self):
		thread, box = run_in_thread(lambda: self.host.run_dialog(request("MODE:hang", timeout=120)))
		self.assertTrue(wait_for(lambda: self.host._child is not None))
		self.assertTrue(self.host.busy)
		with self.assertRaises(ui.UiBusy):
			self.host.run_dialog(request("MODE:result:cancelled", kind="consent"))
		with self.assertRaises(ui.UiBusy):
			self.host.run_exclusive(lambda: "second")
		self.assertEqual(1, len(self.popen.calls), "a busy host must not spawn a second child")
		self.host.kill_child()
		thread.join(5)
		self.assertEqual("dialog_shutdown", box["error"].cause)
		self.assertFalse(self.host.busy)

	def test_run_exclusive_is_not_reentrant(self):
		with self.assertRaises(ui.UiBusy):
			self.host.run_exclusive(lambda: self.host.run_exclusive(lambda: "inner"))
		self.assertFalse(self.host.busy)

	def test_lock_is_free_after_every_failure_class(self):
		patch_timing(self, startup=0.5, grace=0.1, kill_delay=0.3)
		for mode in ("MODE:crash", "MODE:exit:3", "MODE:empty", "MODE:hang", "MODE:oversize:x"):
			with self.subTest(mode):
				self.cause_of(request(mode))  # asserts busy is False afterwards
		self.assertEqual("cancelled", self.host.run_dialog(request("MODE:result:cancelled"))["result"])
		self.assertIsNone(self.host._child, "the finished child is no longer tracked")


# --- I2: the PIN never reaches an exception or a log ---------------------------------------
class _Capture(logging.Handler):
	def __init__(self):
		super().__init__(level=logging.DEBUG)
		self.lines = []

	def emit(self, record):
		self.lines.append(self.format(record))


class TestPinNeverLeaks(HostCase):
	def setUp(self):
		super().setUp()
		patch_timing(self, startup=5.0, grace=0.2, kill_delay=0.3)
		self.capture = _Capture()
		root = logging.getLogger()
		previous = root.level
		root.addHandler(self.capture)
		root.setLevel(logging.DEBUG)
		self.addCleanup(root.setLevel, previous)
		self.addCleanup(root.removeHandler, self.capture)

	def assertClean(self, exc):
		chain = [exc, exc.__cause__, exc.__context__]
		text = "".join(traceback.format_exception(exc))
		for item in chain:
			if item is not None:
				text += str(item) + repr(item) + repr(item.args) + repr(getattr(item, "__dict__", {}))
		self.assertNotIn(SENTINEL, text)
		self.assertIsNone(exc.__context__)
		self.assertIsNone(exc.__cause__)

	def test_sentinel_never_in_an_exception_or_log(self):
		pin = {"v": 1, "kind": "pin"}
		failing = [
			("MODE:valid_then_exit:1", SENTINEL),
			("MODE:valid_then_exit:65", SENTINEL),
			("MODE:badjson:" + SENTINEL,),
			("MODE:extra_line:" + SENTINEL,),
			("MODE:oversize:" + SENTINEL,),
			("MODE:raw", raw(dict(pin, v=2, result="entered", value=SENTINEL))),
			("MODE:raw", raw(dict(pin, result="cancelled", value=SENTINEL))),
			("MODE:raw", raw(dict(pin, result="entered", value=SENTINEL, extra=1))),
			("MODE:raw", '{"v":1,"kind":"pin","result":"entered","value":"' + SENTINEL + '"'),
		]
		for claims in failing:
			with self.subTest(claims[0]):
				with self.assertRaises(DialogFailed) as ctx:
					self.host.run_dialog(request(*claims))
				self.assertClean(ctx.exception)

		# Success and post-reply kill: the PIN is returned, never logged.
		self.assertEqual(SENTINEL, self.host.run_dialog(request("MODE:ok_entered:" + SENTINEL))["value"])
		self.assertEqual(SENTINEL, self.host.run_dialog(request("MODE:reply_then_hang:" + SENTINEL))["value"])
		self.assertNotIn(SENTINEL, "\n".join(self.capture.lines))
		self.assertIsNone(self.host._child)

	def test_sentinel_never_in_a_timeout_or_shutdown_exception(self):
		patch_timing(self, startup=0.5, grace=0.1, kill_delay=0.3)
		with self.assertRaises(DialogFailed) as ctx:
			self.host.run_dialog(request("MODE:hang", SENTINEL))
		self.assertEqual("dialog_timeout", ctx.exception.cause)
		self.assertClean(ctx.exception)
		self.assertNotIn(SENTINEL, "\n".join(self.capture.lines))


if __name__ == "__main__":
	unittest.main()
