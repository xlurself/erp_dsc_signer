"""Owner of every desktop dialog: one dialog child process at a time (spec 001 §3.2, §4-§6).

Tk must run on the main thread of its process (on macOS `tk.Tk()` off the main thread
aborts the whole process), and the daemon serves HTTP on worker threads.  So the daemon
never touches Tk: each dialog is a short-lived child, `dialog_child.py`, that gets ONE
request line on stdin and answers with ONE reply line on stdout.

`DialogHost` is also the process-wide UI mutex.  `run_exclusive` is the ONE place the
lock is taken: non-blocking (a caller that finds a dialog already open gets `UiBusy`
at once; the UI mutex itself never queues anyone), not re-entrant, and held for the
whole call.  If a child cannot be reaped the lock is never released and every later
call gets `DialogWedged`.  This is NOT a promise that dialogs never queue: `/v1/sign`
takes the per-token lock (`service.TOKEN_LOCK_TIMEOUT_SECONDS`) BEFORE its PIN dialog
and holds it through the dialog, so a second sign request for the SAME token waits up
to that timeout (then `TokenBusy`) and, if the first finishes in time, shows its own
dialog right after the first one closes.

PIN discipline: the reply line is the only thing that can hold a PIN.  It is read
straight into ONE preallocated bytearray per child (`_Child.buffer`, no chunk copies,
no reallocation), the line is tracked by offsets into it (never copied), and
`_supervise` zeroes that buffer in a `finally` on every path -- valid reply, bad reply,
any early classifier return, a wedge or an exception.  The parsed PIN `str` is the
only intentional copy; the decoded reply text inside `_parse_reply` is a `str` that
cannot be zeroed and is dropped on return (spec I7).  Replies are parsed by a helper
that returns a sentinel instead of raising, every `DialogFailed` is raised outside any
`except` block (so no exception chains to one holding reply text), nothing from the
child is ever logged, and the child's stderr is discarded.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, TypeVar

from . import dialog_child
from .errors import DialogFailed, DialogWedged


T = TypeVar("T")

logger = logging.getLogger(__name__)

# --- Supervision constants (spec §2: defined here exactly once) ---------------------
# The wire constants (MAX_REPLY_BYTES, MIN/MAX_DIALOG_SECONDS, exit codes) live in
# dialog_child and are read from there at call time; they are never redefined here.
STARTUP_ALLOWANCE_SECONDS = 10
GRACE_SECONDS = 2
KILL_DELAY_SECONDS = 2

# How often the supervisor re-checks the child between wake-ups.  Internal only.
_POLL_SECONDS = 0.05

# Kill reasons.  Set once per child: the first one recorded wins.
_KILLED_SHUTDOWN = "shutdown"
_KILLED_DEADLINE = "deadline"
_KILLED_OVERSIZE = "oversize"
_KILLED_AFTER_REPLY = "after_reply"  # a complete reply line arrived, the child then lingered

# Environment allowlist (spec §4).  TCL_LIBRARY / TK_LIBRARY / TCLLIBPATH are NOT here.
_ENV_NAMES = ("PATH", "HOME", "TMPDIR", "LANG", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY")
_ENV_NAMES_WINDOWS = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE")
_ENV_PREFIXES = ("LC_",)

_WEDGED_LOG_LINE = "dialog child could not be stopped; dialogs are disabled until the signer restarts"

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_CREATE_NO_WINDOW = 0x08000000

_BAD_REPLY = object()


class UiBusy(Exception):
	"""Another dialog is already on screen."""


def child_command(script=None) -> list:
	"""Return the argv that starts the dialog child.  Pure: no I/O, no caller data.

	`[sys.executable, "-I", <absolute path of dialog_child.py>]`.  `script` replaces
	only the script path (tests point it at a stub child).
	"""
	if script is None:
		script = dialog_child.__file__
	return [sys.executable, "-I", os.path.abspath(os.fspath(script))]


def child_env(environ=None) -> dict:
	"""Return the child's environment: the allowlisted names only."""
	if environ is None:
		environ = os.environ
	names = _ENV_NAMES + (_ENV_NAMES_WINDOWS if os.name == "nt" else ())
	env = {name: environ[name] for name in names if name in environ}
	for name, value in environ.items():
		if name.startswith(_ENV_PREFIXES):
			env[name] = value
	return env


def _popen_kwargs() -> dict:
	kwargs = {
		# stdin is a PIPE, never DEVNULL: it is the child's lifeline, and Tk fails to
		# start with stdin on /dev/null in the venv Python.
		"stdin": subprocess.PIPE,
		"stdout": subprocess.PIPE,
		"stderr": subprocess.DEVNULL,
		"close_fds": True,
		"shell": False,
		"cwd": tempfile.gettempdir(),
		"env": child_env(),
		"bufsize": 0,
	}
	if os.name == "nt":
		kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
	else:
		kwargs["start_new_session"] = True
	return kwargs


def _assign_kill_on_close_job(proc):
	"""Windows only, best effort: tie the child to a KILL_ON_JOB_CLOSE Job Object.

	Returns a callable that closes the job handle, or None.  The handle is kept open
	while the child lives, so the OS kills the child if the daemon dies.  There is a
	short window between Popen and the assignment (spec §4); no Windows CI here.
	"""
	if os.name != "nt":
		return None
	try:
		import ctypes
		from ctypes import wintypes

		kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
		kernel32.CreateJobObjectW.restype = wintypes.HANDLE
		kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
		kernel32.SetInformationJobObject.restype = wintypes.BOOL
		kernel32.SetInformationJobObject.argtypes = (
			wintypes.HANDLE,
			ctypes.c_int,
			wintypes.LPVOID,
			wintypes.DWORD,
		)
		kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
		kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
		kernel32.CloseHandle.restype = wintypes.BOOL
		kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

		class _BasicLimits(ctypes.Structure):
			_fields_ = [
				("PerProcessUserTimeLimit", ctypes.c_int64),
				("PerJobUserTimeLimit", ctypes.c_int64),
				("LimitFlags", wintypes.DWORD),
				("MinimumWorkingSetSize", ctypes.c_size_t),
				("MaximumWorkingSetSize", ctypes.c_size_t),
				("ActiveProcessLimit", wintypes.DWORD),
				("Affinity", ctypes.c_size_t),
				("PriorityClass", wintypes.DWORD),
				("SchedulingClass", wintypes.DWORD),
			]

		class _IoCounters(ctypes.Structure):
			_fields_ = [
				(name, ctypes.c_uint64)
				for name in (
					"ReadOperationCount",
					"WriteOperationCount",
					"OtherOperationCount",
					"ReadTransferCount",
					"WriteTransferCount",
					"OtherTransferCount",
				)
			]

		class _ExtendedLimits(ctypes.Structure):
			_fields_ = [
				("BasicLimitInformation", _BasicLimits),
				("IoInfo", _IoCounters),
				("ProcessMemoryLimit", ctypes.c_size_t),
				("JobMemoryLimit", ctypes.c_size_t),
				("PeakProcessMemoryUsed", ctypes.c_size_t),
				("PeakJobMemoryUsed", ctypes.c_size_t),
			]

		job = kernel32.CreateJobObjectW(None, None)
		if not job:
			return None
		info = _ExtendedLimits()
		info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		assigned = kernel32.SetInformationJobObject(
			job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
		) and kernel32.AssignProcessToJobObject(job, int(proc._handle))
		if not assigned:
			kernel32.CloseHandle(job)
			return None
		return lambda: kernel32.CloseHandle(job)
	except Exception:
		return None


class _Child:
	"""The one tracked child.  Helper threads write it; the supervisor reads it."""

	__slots__ = (
		"proc",
		"started",
		"close_job",
		"wake",
		"_reason_lock",
		"reason",
		"buffer",
		"filled",
		"line_end",
		"line_complete",
		"extra",
		"wiped",
		"reader_done",
		"writer",
		"reader",
	)

	def __init__(self, proc, started: float, close_job):
		self.proc = proc
		self.started = started
		self.close_job = close_job
		self.wake = threading.Event()
		# Re-entrant: kill_child may run from a signal handler on any thread.
		self._reason_lock = threading.RLock()
		self.reason = None
		# The ONE buffer the reply is read into: the wire cap plus the byte that detects
		# an oversize reply.  Preallocated so it is never reallocated (a reallocation
		# would leave an unwiped copy behind).  The line is buffer[:line_end].
		self.buffer = bytearray(dialog_child.MAX_REPLY_BYTES + 1)
		self.filled = 0
		self.line_end = None
		self.line_complete = False
		self.extra = False
		self.wiped = False
		self.reader_done = False
		self.writer = None
		self.reader = None

	def record(self, reason: str) -> None:
		"""Record why the child is being killed.  Set-once: the first reason wins."""
		with self._reason_lock:
			if self.reason is None:
				self.reason = reason
		self.wake.set()

	def wipe(self) -> None:
		"""Zero the reply buffer.  Flag first: a reader still running wipes again on exit."""
		self.wiped = True
		_wipe(self.buffer)


def _wipe(buffer) -> None:
	"""Best effort: overwrite a bytearray in place.  A Python str cannot be zeroed (I7)."""
	if isinstance(buffer, bytearray):
		buffer[:] = bytes(len(buffer))


def _write_request(child: _Child, data: bytes) -> None:
	"""Helper thread: write the request line.  stdin stays OPEN afterwards (lifeline)."""
	try:
		stream = child.proc.stdin
		view = memoryview(data)
		while view:
			written = stream.write(view)  # unbuffered: may write part of the line
			if not written:
				break
			view = view[written:]
		stream.flush()
	except (OSError, ValueError):
		# BrokenPipeError (the child already exited) and OSError(EINVAL) (Windows
		# closed pipe) are expected.  Nothing is raised from a helper thread: the
		# classifier decides from the exit code and whatever reply arrived.
		pass


def _read_reply(child: _Child) -> None:
	"""Helper thread: read at most MAX_REPLY_BYTES + 1 bytes of stdout into child.buffer.

	`readinto` on the unbuffered pipe writes straight into the preallocated buffer, so
	no chunk object ever holds reply bytes.  The extra byte, or any byte after the
	first newline, records kill reason `oversize`.  Reading continues after the first
	line only to detect a second one.  The buffer is NOT wiped here (the supervisor
	still has to parse it) unless the supervisor already wiped it while this thread
	was blocked, in which case anything read since is wiped on the way out.
	"""
	buffer = child.buffer
	limit = len(buffer) - 1  # MAX_REPLY_BYTES; the last byte only detects oversize
	view = memoryview(buffer)
	try:
		stream = child.proc.stdout
		while child.filled < len(buffer):
			count = stream.readinto(view[child.filled :])
			if not count:
				break
			start = child.filled
			child.filled = start + count
			if child.line_end is None:
				newline = buffer.find(b"\n", start, child.filled)
				if newline >= 0:
					child.line_end = newline
					child.line_complete = True
					child.wake.set()
			if child.filled > limit or (child.line_end is not None and child.filled > child.line_end + 1):
				child.extra = True
				child.record(_KILLED_OVERSIZE)
				break
	except (OSError, ValueError):
		pass
	finally:
		child.reader_done = True
		if child.wiped:
			_wipe(buffer)
		child.wake.set()


def _start_thread(target, *args, name: str) -> threading.Thread:
	thread = threading.Thread(target=target, args=args, name=name, daemon=True)
	thread.start()
	return thread


def _kill_and_reap(proc) -> bool:
	"""terminate(); kill() after KILL_DELAY_SECONDS; wait(KILL_DELAY_SECONDS).  True if reaped."""
	for stop in (proc.terminate, proc.kill):
		try:
			stop()
		except OSError:
			pass
		try:
			proc.wait(timeout=KILL_DELAY_SECONDS)
			return True
		except subprocess.TimeoutExpired:
			pass
	return False


def _close_quietly(stream) -> None:
	try:
		if stream is not None:
			stream.close()
	except (OSError, ValueError):
		pass


class _Reject(Exception):
	"""Internal to _parse_reply; never escapes it and carries no text."""


def _unique_pairs(pairs):
	keys = [key for key, _value in pairs]
	if len(set(keys)) != len(keys):
		raise _Reject()
	return dict(pairs)


def _no_constant(_name):
	raise _Reject()


def _parse_reply(line, kind: str):
	"""Return the validated reply as a NEW dict, or _BAD_REPLY.  Never raises.

	`line` is any bytes-like object (the supervisor passes a memoryview of the reply
	buffer, so no bytes copy is made).  The caller raises outside any `except`, so no
	exception object (JSONDecodeError keeps the whole document in `.doc`) can end up
	chained to a DialogFailed.
	"""
	try:
		parsed = json.loads(
			str(line, "utf-8"),
			object_pairs_hook=_unique_pairs,
			parse_constant=_no_constant,
		)
	except Exception:
		parsed = _BAD_REPLY
	if type(parsed) is not dict:
		return _BAD_REPLY

	version = parsed.get("v")
	if type(version) is not int or version != dialog_child.PROTOCOL_VERSION:
		return _BAD_REPLY
	if type(parsed.get("kind")) is not str or parsed["kind"] != kind:
		return _BAD_REPLY
	result = parsed.get("result")
	if type(result) is not str or result not in dialog_child.RESULTS[kind]:
		return _BAD_REPLY

	expected = {"v", "kind", "result"}
	if result == "entered":
		expected.add("value")
	if result == "unavailable":
		expected.add("cause")
	if set(parsed) != expected:  # missing key, extra key, stray value, stray cause
		return _BAD_REPLY

	reply = {"v": dialog_child.PROTOCOL_VERSION, "kind": kind, "result": result}
	if result == "entered":
		value = parsed["value"]
		if type(value) is not str or not value:
			return _BAD_REPLY
		reply["value"] = value
	if result == "unavailable":
		cause = parsed["cause"]
		if type(cause) is not str or cause not in dialog_child.UNAVAILABLE_CAUSES:
			return _BAD_REPLY
		reply["cause"] = cause
	return reply


class DialogHost:
	"""Runs one dialog child at a time and classifies its outcome (spec §6)."""

	def __init__(self, child_script=None):
		self._child_script = child_script
		self._lock = threading.Lock()  # the UI mutex; taken ONLY in run_exclusive
		self._state = threading.RLock()  # guards _child; never held while waiting
		self._child = None
		self._wedged = False
		self._shutting_down = False

	# --- the one lock acquisition point -------------------------------------------
	def run_exclusive(self, fn: Callable[[], T]) -> T:
		"""Run `fn` holding the UI mutex for the whole call.

		Non-blocking and not re-entrant: raises UiBusy at once when the mutex is held
		(including by the calling thread).  Raises DialogWedged, checked FIRST, once a
		child could not be reaped.  Ordinary exceptions release the mutex; a wedged
		child keeps it, so one child at a time stays true.
		"""
		if self._wedged:
			raise DialogWedged()
		if not self._lock.acquire(blocking=False):
			if self._wedged:
				raise DialogWedged()
			raise UiBusy()
		try:
			return fn()
		finally:
			if not self._wedged:
				self._lock.release()

	def run_dialog(self, request: dict) -> dict:
		"""Show one dialog and return its validated reply dict, or raise DialogFailed(cause).

		The request is validated BEFORE any spawn; any failure (including a
		UnicodeEncodeError) is DialogFailed("dialog_request_invalid").  Also raises
		UiBusy or DialogWedged from run_exclusive.
		"""
		clean = data = None
		if type(request) is dict:
			try:
				clean = dialog_child.validate_request(request)
				data = dialog_child.encode_request(clean)
			except Exception:
				clean = data = None
		if data is None:
			raise DialogFailed("dialog_request_invalid")
		kind = clean["kind"]
		timeout = clean["timeout"]  # already clamped to [MIN, MAX]_DIALOG_SECONDS
		return self.run_exclusive(lambda: self._supervise(data, kind, timeout))

	# --- shutdown -------------------------------------------------------------------
	def shutdown(self) -> None:
		"""Refuse further dialogs and kill the one on screen, without taking the lock."""
		self._shutting_down = True
		self.kill_child()

	def kill_child(self) -> None:
		"""Kill the tracked child WITHOUT the UI mutex.  Safe from a signal handler.

		Records kill reason `shutdown` and sends terminate(); the supervising thread,
		which holds the mutex, then escalates, reaps and classifies (dialog_shutdown).
		"""
		with self._state:
			child = self._child
		if child is None:
			return
		child.record(_KILLED_SHUTDOWN)
		try:
			child.proc.terminate()
		except Exception:
			pass

	@property
	def busy(self) -> bool:
		locked = self._lock.acquire(blocking=False)
		if locked:
			self._lock.release()
		return not locked

	@property
	def wedged(self) -> bool:
		return self._wedged

	@property
	def shutting_down(self) -> bool:
		return self._shutting_down

	# --- supervision (always runs under the mutex, via run_exclusive) -----------------
	def _supervise(self, data: bytes, kind: str, timeout: int) -> dict:
		if self._shutting_down:
			raise DialogFailed("dialog_shutdown")
		child = self._spawn()
		if child is None:
			raise DialogFailed("dialog_shutdown" if self._shutting_down else "dialog_spawn_failed")
		# ONE monotonic deadline, measured from spawn (spec §2).
		deadline = child.started + STARTUP_ALLOWANCE_SECONDS + timeout + GRACE_SECONDS
		try:
			try:
				child.writer = _start_thread(_write_request, child, data, name="erp-dsc-dialog-write")
				child.reader = _start_thread(_read_reply, child, name="erp-dsc-dialog-read")
				self._watch(child, deadline)
			finally:
				self._stop(child)
			if self._wedged:
				raise DialogWedged()
			outcome = self._classify(child, kind)
		finally:
			# Every path, including each early classifier return and any exception:
			# the reply bytes do not outlive this call.
			child.wipe()
		if type(outcome) is str:
			raise DialogFailed(outcome)
		return outcome

	def _spawn(self):
		argv = child_command(self._child_script)
		if not os.path.isfile(argv[2]):  # must be a real file, not a zipimport member
			return None
		kwargs = _popen_kwargs()
		started = time.monotonic()
		try:
			proc = subprocess.Popen(argv, **kwargs)
		except Exception:
			proc = None
		if proc is None:
			return None
		child = _Child(proc, started, _assign_kill_on_close_job(proc))
		with self._state:
			self._child = child
		# shutdown() sets the flag before it looks for a child, so either it saw this
		# child or this check sees the flag.
		if self._shutting_down:
			child.record(_KILLED_SHUTDOWN)
		return child

	def _watch(self, child: _Child, deadline: float) -> None:
		"""Wait for an exit, a reply, a kill reason or the deadline."""
		proc = child.proc
		replied_at = None
		while child.reason is None:
			child.wake.clear()
			if child.line_complete and replied_at is None:
				replied_at = time.monotonic()
			if proc.poll() is not None and child.reader_done:
				return
			now = time.monotonic()
			if replied_at is not None:
				# A complete reply line is in: wait at most GRACE_SECONDS (never past the
				# deadline) for the child to exit, then kill it and keep the reply.
				if now >= min(replied_at + GRACE_SECONDS, deadline):
					if proc.poll() is None:
						child.record(_KILLED_AFTER_REPLY)
					return
			elif now >= deadline:
				if proc.poll() is None:
					child.record(_KILLED_DEADLINE)
				return
			child.wake.wait(_POLL_SECONDS)

	def _stop(self, child: _Child) -> None:
		"""Kill if alive, reap, close the pipes, untrack.  Wedge if it cannot be reaped."""
		proc = child.proc
		reaped = True
		if proc.poll() is None:
			if child.reason is None:
				child.record(_KILLED_DEADLINE)  # only reachable if _watch itself failed
			reaped = _kill_and_reap(proc)
		for thread, stream in ((child.writer, proc.stdin), (child.reader, proc.stdout)):
			if thread is not None:
				thread.join(KILL_DELAY_SECONDS)
			# Never close a pipe a helper thread may still be blocked on.
			if thread is None or not thread.is_alive():
				_close_quietly(stream)
		if not reaped:
			self._wedged = True
			logger.error(_WEDGED_LOG_LINE)
			return
		if child.close_job is not None:
			try:
				child.close_job()
			except Exception:
				pass
		with self._state:
			if self._child is child:
				self._child = None

	def _classify(self, child: _Child, kind: str):
		"""Spec §6 classifier, ORDERED, by recorded kill reason.  Returns a cause or a reply."""
		# 1. daemon shutting down
		if self._shutting_down or child.reason == _KILLED_SHUTDOWN:
			return "dialog_shutdown"
		# 2. killed at the deadline
		if child.reason == _KILLED_DEADLINE:
			return "dialog_timeout"
		# 2b. killed for an oversize reply or a second line
		if child.reason == _KILLED_OVERSIZE:
			return "dialog_bad_reply"
		# 3. Popen raised: handled in _supervise before a child exists.
		# 4. exit code -- skipped only when WE killed the child after its reply line.
		if child.reason != _KILLED_AFTER_REPLY:
			code = child.proc.returncode
			if type(code) is not int:
				return "dialog_process_failed"
			if code == dialog_child.EXIT_REQUEST_INVALID:
				return "dialog_request_invalid"
			if code < 0:
				return "dialog_process_crashed"
			if code > 0:
				return "dialog_process_failed"
		# 5. exit 0 (or killed after the reply): the reply must be exactly one valid line.
		#    Parsed in place from the buffer; the caller (_supervise) wipes it.
		if child.extra or not child.line_complete or child.line_end is None:
			return "dialog_bad_reply"
		reply = _parse_reply(memoryview(child.buffer)[: child.line_end], kind)
		if reply is _BAD_REPLY:
			return "dialog_bad_reply"
		# 6. valid reply: pin.py / pairing.py map it per the table.
		return reply
