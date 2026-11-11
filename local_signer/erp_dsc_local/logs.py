"""The signer's own log file: size-capped, readable only by the user, never a secret.

BRD F4 / installer plan s5.  ``<config folder>/logs/erp-dsc-local.log``, rotated at
``MAX_BYTES`` with ``BACKUP_COUNT`` older files, every file created 0600 in a 0700 folder
(Windows: the user's profile ACL, best effort).  A symlinked log file or log folder is
refused, so the log cannot be pointed at another file.

What the daemon writes: startup and shutdown, a signal it received, a request that failed
with an unexpected exception (method, a FIXED route name and the exception's CLASS name),
an exception in a background thread (class name), and a heartbeat every
``HEARTBEAT_SECONDS``.  What it never writes: request bodies, PINs, pairing tokens,
certificates, an exception's text or traceback in the helper's own records (the trust store's logger writes a short message with a path, never a secret), a request path that is not one of the
fixed routes, an origin's path or query.  As a second line of defence every record goes
through ``clean``: control characters are escaped (one record is one line, so a value
cannot forge a line), a hex run longer than 16 characters is cut to its first 8, a base64 or
token-looking run (64+ characters, 120+ with "/") is removed, and a URL keeps only scheme://host[:port].

``faulthandler`` writes a fatal crash (segfault in a vendor library, abort) to
``erp-dsc-local-crash.log`` next to the log: Python frames only (file, line, function),
never variable values.
"""

from __future__ import annotations

import faulthandler
import logging
import os
import re
import stat
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "erp_dsc_local"
EVENTS_LOGGER_NAME = "erp_dsc_local.events"
STATE_DIR = "~/.erp-dsc-local"  # trust.DEFAULT_STATE_DIR
CONFIG_FILE_NAME = "config.json"
LOG_DIR_NAME = "logs"
LOG_FILE_NAME = "erp-dsc-local.log"
CRASH_FILE_NAME = "erp-dsc-local-crash.log"
MAX_BYTES = 1024 * 1024
BACKUP_COUNT = 3
HEARTBEAT_SECONDS = 600
MAX_LINE_CHARS = 1000
LOG_UNAVAILABLE_LINE = "erp-dsc-local: the log file could not be opened; the signer runs without it."

ROUTES = frozenset({"/v1/health", "/v1/providers", "/v1/nonce", "/v1/certificates", "/v1/sign", "/v1/pair"})
METHODS = frozenset({"GET", "POST", "OPTIONS"})
_UNREADABLE = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})  # dialog_child.UNREADABLE_CATEGORIES
_URL = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{1,15})://([^\s/?#]+)[^\s]*")
_TOKEN_CHAR = r"A-Za-z0-9+/=_-"
_LONG_HEX = re.compile(rf"(?<![{_TOKEN_CHAR}])([0-9A-Fa-f]{{8}})[0-9A-Fa-f]{{9,}}(?![{_TOKEN_CHAR}])")
# URL-safe or slash-free base64 / tokens (64+), and standard base64 with "/" (120+, so a long
# path, which has "_", "-" or "." between its words, survives).
_BLOBS = (re.compile(r"[A-Za-z0-9+=_-]{64,}"), re.compile(r"[A-Za-z0-9+/=]{120,}"))
_CLASS_NAME = re.compile(r"[^A-Za-z0-9_.]")

# The daemon's own events.  The NullHandler keeps them off stderr when no log file is open
# (logging's last-resort handler would otherwise print them); other erp_dsc_local loggers
# keep their behaviour.
events = logging.getLogger(EVENTS_LOGGER_NAME)
events.addHandler(logging.NullHandler())


# --- where ------------------------------------------------------------------------------


def default_config_path() -> Path:
	return Path(STATE_DIR).expanduser() / CONFIG_FILE_NAME


def state_dir(config_path=None) -> Path:
	"""The folder of ``config_path`` (made absolute, links not resolved), else ~/.erp-dsc-local."""
	if not config_path:
		return Path(STATE_DIR).expanduser()
	return Path(os.path.abspath(os.path.expanduser(os.fspath(config_path)))).parent


def log_dir(config_path=None) -> Path:
	return state_dir(config_path) / LOG_DIR_NAME


def log_path(config_path=None) -> Path:
	return log_dir(config_path) / LOG_FILE_NAME


def crash_path(config_path=None) -> Path:
	return log_dir(config_path) / CRASH_FILE_NAME


# --- user-only files ----------------------------------------------------------------------


def ensure_private_dir(path) -> Path:
	"""Create ``path`` 0700 (or narrow it to 0700).  A symlink, a non-folder or, on POSIX, a
	folder owned by another user is refused with ``OSError``."""
	path = Path(path)
	try:
		path.mkdir(mode=0o700, parents=True, exist_ok=True)
	except FileExistsError:
		pass
	info = os.lstat(path)
	if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
		raise OSError(f"not a plain folder: {path}")
	if os.name != "nt":
		if info.st_uid != os.getuid():
			raise OSError(f"folder owned by another user: {path}")
		os.chmod(path, 0o700)
	return path


def open_private(path, *, binary=False):
	"""Open ``path`` for appending, created 0600 (an existing file is narrowed to 0600).

	``O_NOFOLLOW``: a symlink in place of the file is refused (``OSError``), never followed.
	"""
	flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
	flags |= getattr(os, "O_BINARY", 0) if binary else 0
	fd = os.open(os.fspath(path), flags, 0o600)
	try:
		info = os.fstat(fd)
		if not stat.S_ISREG(info.st_mode):
			raise OSError(f"not a regular file: {path}")
		if os.name != "nt":
			os.fchmod(fd, 0o600)
		if binary:
			return os.fdopen(fd, "ab", buffering=0)
		return os.fdopen(fd, "a", encoding="utf-8", errors="backslashreplace")
	except BaseException:
		os.close(fd)
		raise


class PrivateRotatingFileHandler(RotatingFileHandler):
	"""A RotatingFileHandler whose every file (the first and each one after a rollover) is
	opened by ``open_private``.  Rotation renames, so older files keep their 0600."""

	def _open(self):
		return open_private(self.baseFilename)


# --- one safe line per record --------------------------------------------------------------


def _escape(ch: str) -> str:
	code = ord(ch)
	return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def _origin_only(match) -> str:
	return f"{match.group(1)}://{match.group(2).rsplit('@', 1)[-1]}"


def clean(text) -> str:
	text = "".join(_escape(ch) if unicodedata.category(ch) in _UNREADABLE else ch for ch in str(text))
	text = _URL.sub(_origin_only, text)
	text = _LONG_HEX.sub(lambda m: m.group(1) + "...", text)
	for blob in _BLOBS:
		text = blob.sub("[removed]", text)
	if len(text) > MAX_LINE_CHARS:
		text = text[:MAX_LINE_CHARS] + " [cut]"
	return text


class EventFormatter(logging.Formatter):
	"""``<UTC time> [pid] LEVEL message``.  ``exc_info`` and ``stack_info`` are never rendered:
	an exception's text or a traceback's source lines can carry request data."""

	def format(self, record) -> str:
		try:
			message = record.getMessage()
		except Exception:
			message = "(a log record could not be formatted)"
		when = datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
		return f"{when} [{record.process}] {record.levelname} {clean(message)}"


def exception_name(exc_type) -> str:
	name = getattr(exc_type, "__qualname__", None) or getattr(exc_type, "__name__", None) or "unknown"
	return _CLASS_NAME.sub("", str(name))[:64] or "unknown"


def _route(path) -> str:
	return path if isinstance(path, str) and path in ROUTES else "(other path)"


def _method(method) -> str:
	return method if method in METHODS else "(other method)"


def log_request_failure(method=None, path=None) -> None:
	"""Called inside an ``except`` block of a request handler.  Never raises."""
	try:
		name = exception_name(sys.exc_info()[0])
		events.error("request failed: %s %s (%s); the signer keeps running", _method(method), _route(path), name)
	except Exception:
		pass


def log_handler_failure() -> None:
	"""Called from ``handle_error`` (an exception outside do_GET/do_POST).  Never raises."""
	try:
		events.error("a request could not be handled and was dropped (%s)", exception_name(sys.exc_info()[0]))
	except Exception:
		pass


# --- the daemon's log -----------------------------------------------------------------------


def _rotate_if_large(path, max_bytes) -> None:
	"""Keep one previous crash file (.1) and start a fresh one when the current file is over ``max_bytes``."""
	try:
		if os.lstat(path).st_size > max_bytes:
			os.replace(path, os.fspath(path) + ".1")
	except OSError:
		pass  # missing or unreadable: open_private decides what happens next


class DaemonLog:
	"""Open with ``start()``, always ``close()``: the handler, the logger level, the thread
	exception hook and faulthandler are restored, and the heartbeat thread stopped."""

	def __init__(self, config_path=None, *, max_bytes=MAX_BYTES, backup_count=BACKUP_COUNT, heartbeat_seconds=HEARTBEAT_SECONDS):
		self.config_path = config_path
		self.max_bytes = max_bytes
		self.backup_count = backup_count
		self.heartbeat_seconds = heartbeat_seconds
		self._handler = None
		self._crash = None
		self._heartbeat = None
		self._stop = threading.Event()
		self._saved = None

	def start(self) -> "DaemonLog":
		ensure_private_dir(log_dir(self.config_path))
		handler = PrivateRotatingFileHandler(
			log_path(self.config_path), maxBytes=self.max_bytes, backupCount=self.backup_count, encoding="utf-8"
		)
		_rotate_if_large(crash_path(self.config_path), self.max_bytes)  # faulthandler appends: cap it like the main log
		try:
			crash = open_private(crash_path(self.config_path), binary=True)
		except BaseException:
			handler.close()
			raise
		handler.setFormatter(EventFormatter())
		handler.setLevel(logging.INFO)
		root = logging.getLogger(LOGGER_NAME)
		self._saved = (root.level, threading.excepthook, faulthandler.is_enabled())
		root.addHandler(handler)
		if root.level == logging.NOTSET or root.level > logging.INFO:
			root.setLevel(logging.INFO)
		self._handler, self._crash = handler, crash
		threading.excepthook = _thread_exception
		faulthandler.enable(file=crash, all_threads=True)
		if self.heartbeat_seconds:
			self._heartbeat = threading.Thread(target=self._beat, name="erp-dsc-heartbeat", daemon=True)
			self._heartbeat.start()
		return self

	def event(self, message, *args) -> None:
		events.info(message, *args)

	def _beat(self) -> None:
		started = time.monotonic()
		while not self._stop.wait(self.heartbeat_seconds):
			events.info("heartbeat: running for %d s, %d threads", time.monotonic() - started, threading.active_count())

	def close(self) -> None:
		if self._handler is None:
			return
		self._stop.set()
		if self._heartbeat is not None:
			self._heartbeat.join(5)
		level, hook, was_enabled = self._saved
		threading.excepthook = hook
		faulthandler.disable()
		if was_enabled:
			faulthandler.enable()
		root = logging.getLogger(LOGGER_NAME)
		root.removeHandler(self._handler)
		root.setLevel(level)
		self._handler.close()
		self._crash.close()
		self._handler = self._crash = None


def _thread_exception(args) -> None:
	# Replaces threading's default hook, which prints the exception's text and traceback.
	try:
		thread = clean(getattr(args.thread, "name", "?"))[:40]
		events.error("a background thread (%s) stopped with an unexpected error (%s)", thread, exception_name(args.exc_type))
	except Exception:
		pass


def start_daemon_log(config_path=None, **kwargs):
	"""A started ``DaemonLog``, or None after ONE fixed stderr line: a log that cannot be
	opened must not stop the signer."""
	try:
		return DaemonLog(config_path, **kwargs).start()
	except Exception:
		try:
			sys.stderr.write(LOG_UNAVAILABLE_LINE + "\n")
			sys.stderr.flush()
		except Exception:
			pass
		return None
