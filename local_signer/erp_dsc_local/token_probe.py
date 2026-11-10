"""Child process for the PIN-free PKCS#11 reads (``TokenClient.certificates`` / ``token_state``).

Why a child: on 2026-11-10 the WatchData library hung inside ``C_GetSlotList`` after a
token swap, the daemon thread never returned and ``/v1/health`` stopped answering.  So
the daemon never loads the vendor library for these reads.  ``token.run_probe`` starts
this file as ``[sys.executable, "-I", <this file>]`` with a scrubbed environment, sends
ONE request line on stdin and kills the child's whole process group once its hard
wall-clock limit (``token.PROBE_TIMEOUT_SECONDS``) has passed.

No PIN ever reaches this process; it never logs in.  The request carries only the op,
the module path the daemon's ProviderRegistry resolved (never a path from an HTTP
request) and the alarm below.  The reply is ONE line of JSON with public token data
only: slot ids, raw token label/serial, token flags, certificate DER, CKA_ID and
CKA_LABEL (bytes as base64), and PKCS#11 return codes as NUMBERS.  Exception text is
never read: the daemon names a return code from its own ``PyKCS11.CKR`` table.

Stdlib only at import time: under ``-I`` the package is not importable, so nothing here
imports a sibling module.  PyKCS11 is imported only inside the child, after the request
is valid.

Wire constants live here and nowhere else; ``token.py`` reads them from this module.
"""

from __future__ import annotations

import base64
import json
import os

PROTOCOL_VERSION = 1
OPS = ("certificates", "token_state")
MAX_REQUEST_BYTES = 8192
MAX_REPLY_BYTES = 256 * 1024
MAX_PATH_CHARS = 4096
# The child arms SIGALRM with the default action (terminate) as soon as it starts and
# again with the request's ``alarm``, so it dies on its own even if the daemon is gone
# and the vendor library is stuck in C code that no Python handler could interrupt.
MAX_ALARM_SECONDS = 120

_RANGE = 2**64
_REQUEST_KEYS = frozenset({"v", "op", "module_path", "alarm"})


class DependencyMissing(Exception):
	"""PyKCS11 is not importable in the child."""


class _Reject(Exception):
	pass


def _unique_pairs(pairs):
	keys = [key for key, _value in pairs]
	if len(set(keys)) != len(keys):
		raise _Reject()
	return dict(pairs)


def _no_constant(_name):
	raise _Reject()


def encode_request(op: str, module_path: str, alarm: int) -> bytes:
	"""The ONE request line (parent side)."""
	request = {"v": PROTOCOL_VERSION, "op": op, "module_path": module_path, "alarm": alarm}
	return json.dumps(request, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"


def parse_request(raw) -> dict | None:
	"""The validated request, or None.  Never raises."""
	try:
		if type(raw) is not bytes or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
			return None
		request = json.loads(str(raw, "utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_no_constant)
		if type(request) is not dict or set(request) != _REQUEST_KEYS:
			return None
		if type(request["v"]) is not int or request["v"] != PROTOCOL_VERSION:
			return None
		if type(request["op"]) is not str or request["op"] not in OPS:
			return None
		alarm = request["alarm"]
		if type(alarm) is not int or not 1 <= alarm <= MAX_ALARM_SECONDS:
			return None
		path = request["module_path"]
		# Absolute only: the child runs in "/", and a relative dlopen path would be
		# resolved against the working directory.
		if type(path) is not str or not 0 < len(path) <= MAX_PATH_CHARS or "\x00" in path or not os.path.isabs(path):
			return None
		return request
	except Exception:
		return None


def _ckr(exc, pk):
	"""The PKCS#11 return code of a PyKCS11Error as an int, else None.  Never the text."""
	try:
		error_type = getattr(pk, "PyKCS11Error", None)
		if isinstance(error_type, type) and isinstance(exc, error_type):
			value = getattr(exc, "value", None)
			if type(value) is int and 0 <= value < _RANGE:
				return value
	except Exception:
		pass
	return None


def _b64(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _certificate_slot(pk, lib, slot) -> dict:
	"""One slot, read the way ``certificates()`` always did: token info, a session,
	``findObjects`` for certificates, then ``CKA_VALUE``/``CKA_ID``/``CKA_LABEL`` per
	object.  Shape A ``{slot, failed: true, ckr}``: failed before objects were listed.
	Shape B ``{slot, label, serial, objects, failed, ckr}``: ``objects`` holds every
	object read before any failure, in order, ``null`` for one without DER or CKA_ID."""
	try:
		info = lib.getTokenInfo(slot)
		label = str(getattr(info, "label"))
		serial = str(getattr(info, "serialNumber"))
		session = lib.openSession(slot, pk.CKF_SERIAL_SESSION)
	except Exception as exc:
		return {"slot": slot, "failed": True, "ckr": _ckr(exc, pk)}
	objects = None
	failure = None
	try:
		handles = session.findObjects([(pk.CKA_CLASS, pk.CKO_CERTIFICATE)])
		objects = []
		for handle in handles or ():  # any falsy result is "listed nothing", as before
			der, key_id, value = session.getAttributeValue(handle, [pk.CKA_VALUE, pk.CKA_ID, pk.CKA_LABEL])
			if not der or key_id is None:
				objects.append(None)
				continue
			objects.append({"der": _b64(bytes(der)), "key_id": _b64(bytes(key_id)), "label": str(value)})
	except Exception as exc:
		failure = (_ckr(exc, pk),)
	finally:
		try:
			session.closeSession()
		except Exception:
			pass
	if objects is None:
		return {"slot": slot, "failed": True, "ckr": failure[0]}
	return {
		"slot": slot,
		"label": label,
		"serial": serial,
		"objects": objects,
		"failed": failure is not None,
		"ckr": failure[0] if failure is not None else None,
	}


def _state_slot(lib, slot) -> dict:
	"""``{slot, serial, flags}`` (flags null if not an int) or ``{slot, failed: true}``."""
	try:
		info = lib.getTokenInfo(slot)
		serial = str(getattr(info, "serialNumber"))
		flags = getattr(info, "flags", None)
	except Exception:
		return {"slot": slot, "failed": True}
	if type(flags) is not int or not 0 <= flags < _RANGE:
		flags = None
	return {"slot": slot, "serial": serial, "flags": flags}


def probe(op: str, pk, lib) -> dict:
	"""The reads for ``op`` over an already-loaded library.  May raise (``handle`` maps
	that to ``failed``)."""
	try:
		slots = list(lib.getSlotList(tokenPresent=True))
	except Exception as exc:
		return {"result": "slot_list_failed", "ckr": _ckr(exc, pk)}
	if any(type(slot) is not int or not 0 <= slot < _RANGE for slot in slots):
		return {"result": "failed"}
	if op == "certificates":
		return {"result": "ok", "slots": [_certificate_slot(pk, lib, slot) for slot in slots]}
	return {"result": "ok", "slots": [_state_slot(lib, slot) for slot in slots]}


def encode_reply(op, body: dict) -> bytes:
	"""The ONE reply line.  Never raises."""
	try:
		return json.dumps({"v": PROTOCOL_VERSION, "op": op, **body}, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"
	except Exception:
		return json.dumps({"v": PROTOCOL_VERSION, "op": op, "result": "failed"}).encode("ascii") + b"\n"


def _load(path: str):
	try:
		import PyKCS11
	except ImportError:
		raise DependencyMissing() from None
	lib = PyKCS11.PyKCS11Lib()
	lib.load(path)
	return PyKCS11, lib


def handle(raw, *, load=None, arm=None) -> bytes:
	"""Request bytes -> reply line.  ``load(path) -> (pk, lib)`` defaults to PyKCS11;
	``arm(seconds)`` re-arms the alarm once the request is valid.  Never raises."""
	request = parse_request(raw)
	if request is None:
		return encode_reply(None, {"result": "bad_request"})
	op = request["op"]
	try:
		if arm is not None:
			arm(request["alarm"])
		pk, lib = (load or _load)(request["module_path"])
	except DependencyMissing:
		return encode_reply(op, {"result": "dependency_missing"})
	except Exception:
		return encode_reply(op, {"result": "load_failed"})
	try:
		body = probe(op, pk, lib)
	except Exception:
		body = {"result": "failed"}
	return encode_reply(op, body)


def _arm(seconds: int) -> None:
	import signal

	if hasattr(signal, "alarm"):
		signal.signal(signal.SIGALRM, signal.SIG_DFL)
		signal.alarm(seconds)


def _read_request():
	chunks, size = [], 0
	while size <= MAX_REQUEST_BYTES:
		chunk = os.read(0, MAX_REQUEST_BYTES + 1 - size)
		if not chunk:
			break
		chunks.append(chunk)
		size += len(chunk)
	return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
	view = memoryview(data)
	while view:
		view = view[os.write(fd, view) :]


def main(load=None) -> None:
	"""Child entry: one request on stdin, one reply line, then ``os._exit``.

	fd 1 is moved to a private descriptor and replaced by /dev/null BEFORE the vendor
	library loads, so nothing a driver prints can corrupt the reply.  ``os._exit`` skips
	interpreter teardown, where PyKCS11 would call ``C_Finalize`` -- a vendor library
	that hangs there would otherwise keep the child alive after its reply.
	"""
	_arm(MAX_ALARM_SECONDS)
	try:
		reply_fd = os.dup(1)
		null = os.open(os.devnull, os.O_WRONLY)
		os.dup2(null, 1)
		os.close(null)
	except OSError:
		os._exit(2)
	try:
		line = handle(_read_request(), load=load, arm=_arm)
	except BaseException:
		line = encode_reply(None, {"result": "failed"})
	try:
		_write_all(reply_fd, line)
	except OSError:
		os._exit(3)
	os._exit(0)


if __name__ == "__main__":
	main()
