"""PKCS#11 access.  This module is imported only on workstations with middleware.

PIN boundary (spec 001 §7): a PIN is sent in exactly ONE ``C_Login`` per entry, on the slot
the selected certificate came from, and only while that slot still reports the selected
token's serial.  From ``session.login`` through ``sign`` no driver text reaches an error,
and every error on that path is raised outside any ``except`` block, so neither
``__cause__`` nor ``__context__`` carries a driver exception.

Signing diagnostic: ``TOKEN_SIGNING_FAILED`` keeps its one fixed message and carries
``details = {"stage", "error", "ckr"}`` (``errors.TokenSigningFailed``): the step that
failed (``login``, ``find_key``, ``c_sign``, ``cms``, ``tsa``), the exception's CLASS
NAME if it is in ``SIGNING_ERROR_CLASSES`` (else "other") and, for a ``PyKCS11Error``, the
return-code name looked up in ``PyKCS11.CKR`` by its integer ``value`` (else None).  The
exception's text, args and traceback are never read, so a driver, endesive or a TSA that
echoes the PIN cannot put it there.  The same three fields go to stderr as one fixed line
(``SIGNING_FAILED_LOG``).

Digest (spec §7): ``_TokenHSM.sign`` signs with ``CKM_SHA256_RSA_PKCS`` only and refuses any
other digest endesive asks for (one taken from the PDF's own /Perms /DocMDP) before
``C_Login``, as ``TOKEN_SIGNING_FAILED`` stage ``c_sign``.

PIN lifetime (I7): ``_TokenHSM`` drops its reference to the PIN as soon as ``C_Login``
returns or raises, so the PIN is not held through signing or the timestamp request.
Residual: PyKCS11's ``Session.login`` copies the PIN into its own byte list for
``C_Login``; that copy is not ours to clear and cannot be wiped from Python.

Timestamp bound: the caller holds the token lock and the session stays logged in until
endesive returns, so the timestamp request is bounded by ``TSA_TIMEOUT_SECONDS``; a TSA
that times out or fails ends as ``TOKEN_SIGNING_FAILED`` after logout and close.

PIN-free reads in a child (2026-11-10: the WatchData library hung inside C_GetSlotList
after a token swap, the daemon thread never returned and /v1/health stopped answering):
``certificates()`` and ``token_state()`` never load the vendor library in this process.
``run_probe`` starts ``token_probe.py`` as ``[sys.executable, "-I", <file>]`` in its own
session, cwd "/", scrubbed env (``ui.child_env``), stderr discarded, the request on stdin
only; it reads at most ``token_probe.MAX_REPLY_BYTES`` + 1 bytes of stdout and, once the
reply is in or ``PROBE_TIMEOUT_SECONDS`` of wall clock has passed, SIGKILLs the child's
whole process group and reaps it.  A child that hangs, dies, or answers with anything
but ONE strictly valid line (duplicate keys, NaN, unknown fields, oversize: refused) is
``TokenDriverNotResponding``: ONE fixed message, raised outside any ``except``, with no
child output, driver text or path.  The child reports driver failures as PKCS#11
return-code numbers; this process names them from its own ``PyKCS11.CKR`` table.
The sign path (``_TokenHSM``) still uses the library in this process, loaded lazily by
``_library``; moving it is out of scope here.
"""

from __future__ import annotations

import base64
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

from . import token_probe
from .certificates import build_issuer_chain, parse_token_certificate, select_certificate
from .errors import (
	CKR_NAME,
	SIGNING_ERROR_CLASSES,
	SIGNING_STAGES,
	CertificatesHidden,
	LocalSignerError,
	PinIncorrect,
	PinLocked,
	TokenSigningFailed,
	TokenUnavailable,
)
from .ui import child_env

TOKEN_NOT_AVAILABLE = "The USB token is not available. Check that it is plugged in and try again."
DEPENDENCY_MISSING_MESSAGE = "Install PyKCS11 to use a USB DSC token."

# The PIN-free reads (see the module docstring).  Defined here and nowhere else.
PROBE_TIMEOUT_SECONDS = 15  # hard wall-clock limit for one child, spawn to reply
PROBE_KILL_WAIT_SECONDS = 2  # how long to wait for the killed child to be reaped
PROBE_SCRIPT = None  # the child script; None means token_probe.py (tests point it at a stub)
DRIVER_NOT_RESPONDING = "The token driver is not responding. Unplug and re-insert the token, then try again."
# The one stderr line per failed probe: op and reason from closed vocabularies only.
PROBE_FAILED_LOG = "erp-dsc-local: the token driver did not answer (op={op} reason={reason})"
UNNAMED_DRIVER_ERROR = "driver error"
NO_KEY_ID = "its certificates carry no CKA_ID"
UNREADABLE_CERTIFICATE = "a certificate on it cannot be read"

_REASON_SPAWN = "spawn"
_REASON_TIMEOUT = "timeout"
_REASON_OVERSIZE = "oversize"
_REASON_NO_REPLY = "no_reply"
_REASON_BAD_REPLY = "bad_reply"
_CREATE_NO_WINDOW = 0x08000000
_MAX_TEXT_CHARS = 4096
_RANGE = 2**64
_BAD_PROBE_REPLY = object()


class TokenDriverNotResponding(TokenUnavailable):
	"""The probe child hung, died or answered badly.  One fixed message, no details."""

	def __init__(self):
		super().__init__(DRIVER_NOT_RESPONDING)
SIGNING_FAILED = TokenSigningFailed.MESSAGE
# The one stderr line per TOKEN_SIGNING_FAILED: the three closed-vocabulary fields only.
SIGNING_FAILED_LOG = "erp-dsc-local: the USB token could not sign (stage={stage} error={error} ckr={ckr})"
KEY_NOT_AVAILABLE = "The selected signing key is no longer available on a connected token."

# The timestamp request endesive makes (``requests.post(url, ..., **timestamp_req_options)``
# in endesive 2.19.3 signer.timestamp) as a requests ``(connect, read)`` timeout.  Defined
# here and nowhere else.
TSA_CONNECT_TIMEOUT_SECONDS = 5
TSA_TIMEOUT_SECONDS = 15

_LOGIN_OK = "ok"
_LOGIN_PIN_INCORRECT = "pin_incorrect"
_LOGIN_PIN_LOCKED = "pin_locked"
_LOGIN_FAILED = "failed"

# C_Login results that mean a wrong PIN was presented (spec §7).  Middleware differs in
# which one it returns and any of them may burn a try on the token, so all three are
# counted by the limiter and reported as PinIncorrect.  No other result is counted.
_WRONG_PIN_RESULTS = ("CKR_PIN_INCORRECT", "CKR_PIN_INVALID", "CKR_PIN_LEN_RANGE")


def _token_field(info, name: str) -> str:
	"""The one normaliser for a CK_TOKEN_INFO text field (label, serialNumber)."""
	return str(getattr(info, name)).split("\\0")[0].strip()


def _only_holder(selected, readings):
	"""The info of ``selected.slot_id`` from ``readings`` (``(slot, info or None)`` pairs),
	only when it is the one and only slot whose normalised serial equals
	``selected.token_serial``; otherwise ``TokenUnavailable``.  Used by ``token_state``
	(child readings) and ``_chosen_slot_info`` (sign path, in-process readings)."""
	expected = selected.token_serial
	chosen = None
	holders = 0
	for slot, info in readings:
		if info is None or _token_field(info, "serialNumber") != expected:
			continue
		holders += 1
		if slot == selected.slot_id:
			chosen = info
	if chosen is None or holders != 1:
		raise TokenUnavailable(TOKEN_NOT_AVAILABLE) from None
	return chosen


# --- PIN-free reads in a child process ------------------------------------------------


def probe_command(script=None) -> list:
	"""``[sys.executable, "-I", <absolute path of token_probe.py>]``.  Pure: no caller data."""
	if script is None:
		script = token_probe.__file__
	return [sys.executable, "-I", os.path.abspath(os.fspath(script))]


def probe_popen_kwargs() -> dict:
	kwargs = {
		"stdin": subprocess.PIPE,
		"stdout": subprocess.PIPE,
		"stderr": subprocess.DEVNULL,
		"close_fds": True,
		"shell": False,
		"cwd": os.path.abspath(os.sep),
		"env": child_env(),
		"bufsize": 0,
	}
	if os.name == "nt":
		kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
	else:
		kwargs["start_new_session"] = True  # the child leads its own process group
	return kwargs


def run_probe(module_path: str, op: str, *, timeout=None, transport=None) -> dict:
	"""Run ``op`` in a probe child and return its validated reply.

	``module_path`` must be the path of a module the ProviderRegistry resolved.
	``transport(request, timeout) -> (reason, line)`` defaults to ``_spawn_probe``; tests
	replace it.  Every failure is ``TokenDriverNotResponding``, raised outside any
	``except``, after one ``PROBE_FAILED_LOG`` line.
	"""
	limit = PROBE_TIMEOUT_SECONDS if timeout is None else timeout
	alarm = max(1, min(token_probe.MAX_ALARM_SECONDS, math.ceil(limit) + PROBE_KILL_WAIT_SECONDS + 1))
	request = token_probe.encode_request(op, module_path, alarm=alarm)
	try:
		reason, line = (transport or _spawn_probe)(request, limit)
	except Exception:
		reason, line = _REASON_SPAWN, None
	reply = _BAD_PROBE_REPLY
	if reason is None:
		reply = _parse_probe_reply(line, op)
		if reply is _BAD_PROBE_REPLY:
			reason = _REASON_BAD_REPLY if line else _REASON_NO_REPLY
	if reply is _BAD_PROBE_REPLY:
		_log_probe_failure(op, reason)
		raise TokenDriverNotResponding() from None
	return reply


def _log_probe_failure(op: str, reason: str) -> None:
	try:
		sys.stderr.write(PROBE_FAILED_LOG.format(op=op, reason=reason) + "\n")
		sys.stderr.flush()
	except Exception:
		pass  # a closed stderr must not turn the failure into a different error


def _spawn_probe(request: bytes, timeout) -> tuple:
	"""Default transport: ``(None, reply bytes)`` once the child closed stdout in time,
	else ``(reason, None)``.  The child's process group is killed and the child reaped
	on EVERY path before this returns."""
	started = time.monotonic()
	try:
		proc = subprocess.Popen(probe_command(PROBE_SCRIPT), **probe_popen_kwargs())
	except (OSError, ValueError, subprocess.SubprocessError):
		return _REASON_SPAWN, None
	buffer = bytearray(token_probe.MAX_REPLY_BYTES + 1)  # the extra byte detects oversize
	filled = [0]
	threads = []
	try:
		threads.append(_start_thread(_write_probe_request, proc, request))
		reader = _start_thread(_read_probe_reply, proc, buffer, filled)
		threads.append(reader)
		reader.join(max(0.0, started + timeout - time.monotonic()))
		if reader.is_alive():
			return _REASON_TIMEOUT, None
		if filled[0] > token_probe.MAX_REPLY_BYTES:
			return _REASON_OVERSIZE, None
		return None, bytes(buffer[: filled[0]])
	finally:
		_stop_probe(proc)
		for thread in threads:
			thread.join(PROBE_KILL_WAIT_SECONDS)
		if not any(thread.is_alive() for thread in threads):
			# Closed only once no helper thread can still be blocked on them.
			_close_quietly(proc.stdin)
			_close_quietly(proc.stdout)


def _start_thread(target, *args) -> threading.Thread:
	thread = threading.Thread(target=target, args=args, name="erp-dsc-token-probe", daemon=True)
	thread.start()
	return thread


def _write_probe_request(proc, request: bytes) -> None:
	"""Helper thread: write the request, then close stdin (the child reads to EOF)."""
	try:
		view = memoryview(request)
		while view:
			written = proc.stdin.write(view)  # unbuffered: may write part of it
			if not written:
				break
			view = view[written:]
	except (OSError, ValueError):
		pass  # the child already exited: the reader and the reply decide
	finally:
		_close_quietly(proc.stdin)


def _read_probe_reply(proc, buffer: bytearray, filled: list) -> None:
	"""Helper thread: read stdout into ``buffer`` until EOF or until it is full."""
	view = memoryview(buffer)
	try:
		while filled[0] < len(buffer):
			count = proc.stdout.readinto(view[filled[0] :])
			if not count:
				break
			filled[0] += count
	except (OSError, ValueError):
		pass


def _stop_probe(proc) -> None:
	"""SIGKILL the child's whole process group, then reap the child.

	The group is signalled BEFORE the reap: until then the child's pid, which is also its
	group id (``start_new_session``), cannot be reused by another process."""
	if os.name != "nt":
		try:
			os.killpg(proc.pid, signal.SIGKILL)
		except OSError:
			pass  # gone already (macOS answers EPERM for a group of zombies)
	try:
		proc.kill()
	except OSError:
		pass
	try:
		proc.wait(timeout=PROBE_KILL_WAIT_SECONDS)
	except subprocess.TimeoutExpired:
		pass  # stuck in the kernel: Popen reaps it later; nothing here waits on it


def _close_quietly(stream) -> None:
	try:
		if stream is not None:
			stream.close()
	except (OSError, ValueError):
		pass


class _BadReply(Exception):
	"""Internal to ``_parse_probe_reply``; never escapes it and carries no text."""


def _unique_reply_pairs(pairs):
	keys = [key for key, _value in pairs]
	if len(set(keys)) != len(keys):
		raise _BadReply()
	return dict(pairs)


def _no_reply_constant(_name):
	raise _BadReply()


def _parse_probe_reply(line, op: str):
	"""The validated reply as a NEW dict (bytes decoded), or ``_BAD_PROBE_REPLY``.

	Never raises: the caller raises outside any ``except``, so no exception object (a
	``JSONDecodeError`` keeps the whole line in ``.doc``) can be chained to the error."""
	try:
		return _validated_reply(line, op)
	except Exception:
		return _BAD_PROBE_REPLY


def _validated_reply(line, op: str) -> dict:
	if (
		type(line) is not bytes
		or len(line) > token_probe.MAX_REPLY_BYTES
		or not line.isascii()
		or not line.endswith(b"\n")
		or line.count(b"\n") != 1
	):
		raise _BadReply()
	parsed = json.loads(str(line, "ascii"), object_pairs_hook=_unique_reply_pairs, parse_constant=_no_reply_constant)
	if type(parsed) is not dict or type(parsed.get("v")) is not int or parsed["v"] != token_probe.PROTOCOL_VERSION:
		raise _BadReply()
	if type(parsed.get("op")) is not str or parsed["op"] != op:
		raise _BadReply()
	result, keys = parsed.get("result"), set(parsed)
	if type(result) is not str:
		raise _BadReply()
	if result == "ok" and keys == {"v", "op", "result", "slots"} and type(parsed["slots"]) is list:
		entry = _certificate_entry if op == "certificates" else _state_entry
		return {"result": result, "slots": [entry(item) for item in parsed["slots"]]}
	if result == "slot_list_failed" and keys == {"v", "op", "result", "ckr"}:
		return {"result": result, "ckr": _optional_uint(parsed["ckr"])}
	if result in ("load_failed", "dependency_missing") and keys == {"v", "op", "result"}:
		return {"result": result}
	raise _BadReply()  # bad_request, failed, or anything else


def _uint(value) -> int:
	if type(value) is not int or not 0 <= value < _RANGE:
		raise _BadReply()
	return value


def _optional_uint(value):
	return None if value is None else _uint(value)


def _text(value) -> str:
	if type(value) is not str or len(value) > _MAX_TEXT_CHARS:
		raise _BadReply()
	return value


def _base64(value, *, empty_ok: bool) -> bytes:
	if type(value) is not str:
		raise _BadReply()
	data = base64.b64decode(value, validate=True)
	if not data and not empty_ok:
		raise _BadReply()
	return data


def _certificate_entry(entry) -> dict:
	if type(entry) is not dict:
		raise _BadReply()
	keys, slot = set(entry), _uint(entry.get("slot"))
	if keys == {"slot", "failed", "ckr"} and entry["failed"] is True:
		return {"slot": slot, "label": None, "serial": None, "objects": None, "failed": True, "ckr": _optional_uint(entry["ckr"])}
	if keys != {"slot", "label", "serial", "objects", "failed", "ckr"}:
		raise _BadReply()
	failed, objects, ckr = entry["failed"], entry["objects"], _optional_uint(entry["ckr"])
	if type(failed) is not bool or type(objects) is not list or (ckr is not None and not failed):
		raise _BadReply()
	return {
		"slot": slot,
		"label": _text(entry["label"]),
		"serial": _text(entry["serial"]),
		"objects": [_certificate_object(item) for item in objects],
		"failed": failed,
		"ckr": ckr,
	}


def _certificate_object(item):
	if item is None:
		return None
	if type(item) is not dict or set(item) != {"der", "key_id", "label"}:
		raise _BadReply()
	return {
		"der": _base64(item["der"], empty_ok=False),
		"key_id": _base64(item["key_id"], empty_ok=True),
		"label": _text(item["label"]),
	}


def _state_entry(entry) -> dict:
	if type(entry) is not dict:
		raise _BadReply()
	keys, slot = set(entry), _uint(entry.get("slot"))
	if keys == {"slot", "failed"} and entry["failed"] is True:
		return {"slot": slot, "failed": True, "serial": None, "flags": None}
	if keys != {"slot", "serial", "flags"}:
		raise _BadReply()
	return {"slot": slot, "failed": False, "serial": _text(entry["serial"]), "flags": _optional_uint(entry["flags"])}


def _signing_failed(stage, diagnosis=None) -> TokenSigningFailed:
	"""The ``TOKEN_SIGNING_FAILED`` to raise (outside any ``except``), logged once to stderr.

	``diagnosis`` is ``_diagnosis()``'s ``(error, ckr)``.  A value outside the closed
	vocabularies becomes "other" (stage, error) or None (ckr) here, never a ``ValueError``.
	"""
	error, ckr = diagnosis if diagnosis is not None else ("other", None)
	if type(stage) is not str or stage not in SIGNING_STAGES:
		stage = "other"
	if type(error) is not str or error not in SIGNING_ERROR_CLASSES:
		error = "other"
	if ckr is not None and (type(ckr) is not str or not CKR_NAME.fullmatch(ckr)):
		ckr = None
	failure = TokenSigningFailed(stage=stage, error=error, ckr=ckr)
	try:
		sys.stderr.write(SIGNING_FAILED_LOG.format(stage=stage, error=error, ckr=ckr or "none") + "\n")
		sys.stderr.flush()
	except Exception:
		pass  # a closed stderr must not turn the failure into a different error
	return failure


def _diagnosis(exc, pk) -> tuple[str, str | None]:
	"""``(error, ckr)`` for ``exc``, from closed vocabularies only.  Called inside the
	``except`` that caught ``exc``; reads its class name and, for a ``PyKCS11Error``, its
	integer ``value`` -- never its text, args or traceback.  Never raises."""
	try:
		name = type(exc).__name__
		error = name if type(name) is str and name in SIGNING_ERROR_CLASSES else "other"
		ckr = None
		error_type = getattr(pk, "PyKCS11Error", None)
		table = getattr(pk, "CKR", None)
		if isinstance(error_type, type) and isinstance(exc, error_type) and type(table) is dict:
			value = getattr(exc, "value", None)
			found = table.get(value) if type(value) is int else None
			ckr = found if type(found) is str and CKR_NAME.fullmatch(found) else None
	except Exception:
		return "other", None
	return error, ckr


def _is_timestamp_error(exc) -> bool:
	"""Is ``exc`` a requests exception, i.e. from the timestamp request?  With
	``signature_meta`` allowlisted (no ``ltv``), the TSA request is endesive's only network
	call.  Read from ``sys.modules``: a requests exception implies requests is loaded."""
	base = getattr(sys.modules.get("requests.exceptions"), "RequestException", None)
	try:
		return isinstance(base, type) and isinstance(exc, base)
	except Exception:
		return False


class TokenClient:
	# The vendor library in THIS process.  Loaded on first use by the sign path only
	# (``_library``); ``certificates`` and ``token_state`` never load it here.
	lib = None

	def __init__(self, module):
		try:
			import PyKCS11
		except ImportError as exc:
			raise LocalSignerError("DEPENDENCY_MISSING", DEPENDENCY_MISSING_MESSAGE, status=503) from exc
		self.pk = PyKCS11
		self.module = module

	def _probe(self, op):
		"""The PIN-free read ``op`` in a child, on the module the registry resolved."""
		return run_probe(self.module.path, op)

	def certificates(self):
		"""List certificates without a PIN, in a child process (``token_probe``).

		``CertificatesHidden`` only when a session opened and ``findObjects`` returned ``[]``
		without error and nothing else went wrong; every other zero-certificate outcome is
		``TokenUnavailable``.  A driver failure is named by its PKCS#11 return-code name
		only, never by its text; a child that hangs, dies or answers badly is
		``TokenDriverNotResponding``.
		"""
		reply = self._probe("certificates")
		result = reply["result"]
		if result == "dependency_missing":
			raise LocalSignerError("DEPENDENCY_MISSING", DEPENDENCY_MISSING_MESSAGE, status=503)
		if result == "load_failed":
			raise TokenUnavailable(f"Unable to load the selected token middleware ({self.module.label}).")
		if result == "slot_list_failed":
			raise TokenUnavailable(self._unreadable(self._driver_reason(reply["ckr"])))
		slots = reply["slots"]
		if not slots:
			raise TokenUnavailable()
		certificates = []
		opened_empty = False
		last_error = None
		for entry in slots:
			# One unreadable slot must not hide certificates on another.
			objects = entry["objects"]
			if objects is None:  # token info, session or findObjects failed
				last_error = self._driver_reason(entry["ckr"])
				continue
			if not objects and not entry["failed"]:
				opened_empty = True
				continue
			usable = 0
			unparsed = None
			try:
				for item in objects:
					if item is None:  # no DER or no CKA_ID
						continue
					certificates.append(
						parse_token_certificate(
							item["der"],
							item["key_id"],
							item["label"],
							entry["slot"],
							_normalised(entry["label"]),
							_normalised(entry["serial"]),
						)
					)
					usable += 1
			except Exception as exc:
				unparsed = _certificate_reason(exc)
			if unparsed is not None:
				last_error = unparsed
			elif entry["failed"]:  # an attribute read failed after the objects listed
				last_error = self._driver_reason(entry["ckr"])
			elif not usable:
				last_error = NO_KEY_ID
		if certificates:
			return certificates
		if opened_empty and last_error is None:
			raise CertificatesHidden()
		raise TokenUnavailable(self._unreadable(last_error))

	def select(self, selector):
		"""The ONE selection point: returns ``(selected, certificates)``."""
		certificates = self.certificates()
		return select_certificate(certificates, selector), certificates

	def token_state(self, selected):
		"""``(flags, serial)`` of the selected token, read without a PIN in a child process.

		Raises ``TokenUnavailable`` when the selected slot no longer holds, alone, the
		selected token's serial — so flags are never read from a different token — and
		``TokenDriverNotResponding`` when the child hangs, dies or answers badly.
		"""
		if not selected.token_serial:
			raise TokenUnavailable(TOKEN_NOT_AVAILABLE)
		reply = self._probe("token_state")
		readings = ()
		if reply["result"] == "ok":  # any other result: the token is not available
			readings = [
				(entry["slot"], None if entry["failed"] else SimpleNamespace(serialNumber=entry["serial"], flags=entry["flags"]))
				for entry in reply["slots"]
			]
		info = _only_holder(selected, readings)
		if info.flags is None:
			raise TokenUnavailable(TOKEN_NOT_AVAILABLE)
		return info.flags, _token_field(info, "serialNumber")

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		"""Sign with the already-selected certificate; no re-enumeration.

		``login_guard`` is a context manager supplied by the caller, who already holds the
		per-serial token lock. ``with login_guard as guard`` is entered immediately before the
		single ``C_Login`` (it re-checks the limiter and may raise). Inside it the slot's
		flags are re-read and passed to ``guard.check_flags(flags)``, which may raise; then
		no ``C_Login`` is made. ``guard.succeeded()`` is called as soon as ``C_Login``
		returns, ``guard.failed()`` only for a wrong-PIN result (``_WRONG_PIN_RESULTS``);
		for any other outcome neither is called.

		The timestamp request is bounded by ``TSA_TIMEOUT_SECONDS``.  Any exception from
		endesive that is not a ``LocalSignerError`` (a TSA timeout, a refused connection, a
		bad reply) becomes ``TOKEN_SIGNING_FAILED`` with fixed text, raised outside the
		``except``, with stage ``tsa`` if it is a requests exception or if ``timestamp_url``
		is set and a C_Sign had already returned, and ``cms`` otherwise (see the module
		docstring for ``details``); in every case the session is logged out and closed
		before this returns.
		"""
		adapter = _TokenHSM(self, selected, pin, login_guard)
		pin = None
		try:
			from endesive.pdf import cms

			diagnosis = None
			try:
				appended = cms.sign(
					pdf_bytes,
					metadata,
					None,
					None,
					build_issuer_chain(selected, certificates),
					"sha256",
					hsm=adapter,
					timestampurl=timestamp_url,
					timestamp_req_options={"timeout": (TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS)},
				)
			except LocalSignerError:
				raise
			except Exception as exc:
				# A TSA that answers but refuses is no requests exception: endesive raises a
				# plain ValueError (signer.py ~143/145), as asn1crypto does for a status-only
				# reply.  With a TSA, whatever fails after a C_Sign returned is stage "tsa".
				after_c_sign_with_tsa = timestamp_url is not None and adapter.c_sign_returned
				stage = "tsa" if after_c_sign_with_tsa or _is_timestamp_error(exc) else "cms"
				diagnosis = (stage, _diagnosis(exc, self.pk))
			if diagnosis is not None:
				raise _signing_failed(*diagnosis) from None
			return pdf_bytes + appended, selected.metadata
		finally:
			adapter.close()
			adapter.pin = None

	def _chosen_slot_info(self, selected):
		"""Freshly re-read every present slot (no PIN) and return the selected slot's info.

		Only when ``selected.slot_id`` is the one and only present slot whose normalised
		serial equals ``selected.token_serial``; otherwise ``TokenUnavailable``.  Sign path
		only (``_TokenHSM._login``), in this process.
		"""
		slots = self._present_slots() if selected.token_serial else None
		return _only_holder(selected, ((slot, self._token_info_or_none(slot)) for slot in slots or ()))

	def _library(self):
		"""The vendor library in THIS process, loaded once, on first use.  Reached only from
		the sign path's helpers below, each of which turns any failure into ``None``."""
		if self.lib is None:
			lib = self.pk.PyKCS11Lib()
			lib.load(self.module.path)
			self.lib = lib
		return self.lib

	def _present_slots(self):
		try:
			return list(self._library().getSlotList(tokenPresent=True))
		except Exception:
			return None

	def _token_info_or_none(self, slot):
		try:
			return self._library().getTokenInfo(slot)
		except Exception:
			return None

	def _open_session_or_none(self, slot):
		try:
			return self._library().openSession(slot, self.pk.CKF_SERIAL_SESSION)
		except Exception:
			return None

	def _driver_reason(self, code) -> str:
		"""The PKCS#11 name of return code ``code`` from THIS process's ``PyKCS11.CKR``
		table, else ``UNNAMED_DRIVER_ERROR``.  The child sends only the number."""
		table = getattr(self.pk, "CKR", None)
		name = table.get(code) if type(table) is dict and type(code) is int else None
		return name if type(name) is str and CKR_NAME.fullmatch(name) else UNNAMED_DRIVER_ERROR

	def _unreadable(self, reason: str) -> str:
		return (
			f"A USB token is connected, but the selected middleware ({self.module.label}) cannot read it "
			f"({reason}). The token probably needs its own vendor's driver, not this one. "
			"Install the driver for your token and try again."
		)


def _normalised(raw: str) -> str:
	"""``_token_field`` for a raw CK_TOKEN_INFO text the child sent."""
	return _token_field(SimpleNamespace(value=raw), "value")


def _certificate_reason(exc) -> str:
	"""Why a certificate the child read could not be parsed: our own fixed message for a
	``LocalSignerError``, else a fixed phrase (never text derived from the DER)."""
	message = getattr(exc, "message", None) if isinstance(exc, LocalSignerError) else None
	return message if type(message) is str else UNREADABLE_CERTIFICATE


def _attempt_login(session, pin, pk) -> tuple[str, tuple | None]:
	"""Call ``C_Login`` once and classify the outcome; never lets the driver error escape.

	Returns ``(outcome, diagnosis)``; ``diagnosis`` (``_diagnosis``) only for ``_LOGIN_FAILED``.
	"""
	try:
		session.login(pin)
	except Exception as exc:
		error_type = getattr(pk, "PyKCS11Error", None)
		code = getattr(exc, "value", None) if error_type is not None and isinstance(exc, error_type) else None
		if code is not None and any(code == getattr(pk, name, object()) for name in _WRONG_PIN_RESULTS):
			return _LOGIN_PIN_INCORRECT, None
		if code is not None and code == getattr(pk, "CKR_PIN_LOCKED", object()):
			return _LOGIN_PIN_LOCKED, None
		return _LOGIN_FAILED, _diagnosis(exc, pk)
	return _LOGIN_OK, None


class _TokenHSM:
	"""endesive HSM adapter.  Logs in lazily, once, on the selected token only."""

	def __init__(self, client, certificate, pin, login_guard):
		self.client, self.certificate_data, self.pin = client, certificate, pin
		self.login_guard = login_guard
		self.session = None
		self.logged_in = False
		self.login_attempted = False
		self.c_sign_returned = False  # set once a C_Sign has returned a signature

	def certificate(self):
		"""``(CKA_ID, DER)``.  endesive loads the HSM certificate with asn1crypto from bytes
		(``signer.cert2asn(cert, False)`` in 2.19.3); a cryptography object raises
		``TypeError`` there, which ended every real USB signing as TOKEN_SIGNING_FAILED.
		``othercerts`` (``build_issuer_chain``) stay cryptography certificates: endesive calls
		``public_bytes`` on each of them."""
		return self.certificate_data.key_id, self.certificate_data.der

	def sign(self, key_id, data, hash_algorithm):
		pk = self.client.pk
		# SHA-256 only (spec §7).  endesive does not keep the "sha256" sign_pdf passes: a PDF
		# whose catalog has /Perms /DocMDP /Reference[0] /DigestMethod makes it sign with THAT
		# digest (cms.py ~715-727), and PyKCS11 has CKM_MD5_RSA_PKCS and CKM_SHA1_RSA_PKCS.
		# Anything else is refused BEFORE C_Login, so no PIN is sent for it.  The mechanism is
		# never derived from the argument, and the argument never reaches a message or a log.
		mechanism = getattr(pk, "CKM_SHA256_RSA_PKCS", None)
		if type(hash_algorithm) is not str or hash_algorithm != "sha256" or type(mechanism) is not int:
			raise _signing_failed("c_sign") from None
		if not self.logged_in:
			if self.login_attempted:
				raise _signing_failed("login") from None
			self._login()
		key = self._signing_key(key_id)
		diagnosis = None
		try:
			signature = bytes(bytearray(self.session.sign(key, data, pk.Mechanism(mechanism, None))))
		except Exception as exc:
			diagnosis = _diagnosis(exc, pk)
		if diagnosis is not None:
			raise _signing_failed("c_sign", diagnosis) from None
		# From here endesive's only remaining network step is the timestamp request.
		self.c_sign_returned = True
		return signature

	def _login(self):
		self.login_attempted = True
		client = self.client
		with self.login_guard as guard:
			info = client._chosen_slot_info(self.certificate_data)
			guard.check_flags(info.flags)  # re-read immediately before C_Login; may refuse
			session = client._open_session_or_none(self.certificate_data.slot_id)
			if session is None:
				raise TokenUnavailable(TOKEN_NOT_AVAILABLE) from None
			self.session = session
			try:
				outcome, diagnosis = _attempt_login(session, self.pin, client.pk)
			finally:
				# One C_Login per entry: the PIN is never needed again, so it is not held
				# through signing or the timestamp request (I7).
				self.pin = None
			if outcome == _LOGIN_OK:
				guard.succeeded()
			elif outcome == _LOGIN_PIN_INCORRECT:
				guard.failed()
		if outcome == _LOGIN_OK:
			self.logged_in = True
			return
		if outcome == _LOGIN_PIN_INCORRECT:
			raise PinIncorrect() from None
		if outcome == _LOGIN_PIN_LOCKED:
			raise PinLocked() from None
		raise _signing_failed("login", diagnosis) from None

	def _signing_key(self, key_id):
		pk = self.client.pk
		diagnosis = None
		try:
			keys = self.session.findObjects([(pk.CKA_CLASS, pk.CKO_PRIVATE_KEY), (pk.CKA_ID, key_id)])
		except Exception as exc:
			diagnosis = _diagnosis(exc, pk)
		if diagnosis is not None:
			raise _signing_failed("find_key", diagnosis) from None
		if not keys:
			raise TokenUnavailable(KEY_NOT_AVAILABLE) from None
		return keys[0]

	def close(self):
		"""Log out and close the session.  Does NOT clear ``pin``: ``_login`` drops it once
		``C_Login`` returns, and ``sign_pdf``'s ``finally`` covers every path that never
		reached ``C_Login``."""
		session, self.session = self.session, None
		if session is None:
			return
		if self.logged_in:
			try:
				session.logout()
			except Exception:
				pass
		self.logged_in = False
		try:
			session.closeSession()
		except Exception:
			pass
