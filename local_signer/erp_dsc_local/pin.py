"""Ask for the USB token PIN in the signer's own dialog process (spec 001, §3.3 and §6).

The daemon never creates a window.  It builds a request with SEPARATE fields -- the
origin (the only text the requesting site cannot choose), the site's claims, and the
signer's own warnings -- and hands it to the shared DialogHost, which shows it from a
child process.  The document name arrives in the request body, so it is a site claim
like any other: the dialog labels it as such, and an over-long or unreadable one is
replaced by a visible placeholder (never silently truncated).

Only the `entered` reply carries the PIN, and it is returned directly.  Every failure is
raised outside the `except` that caught it, so no exception this module raises links
back (via __cause__ or __context__) to anything the dialog machinery saw.
"""

from __future__ import annotations

from . import dialog_child
from .errors import DialogBusy, DialogFailed, PinCancelled, PinPromptUnavailable
from .ui import UiBusy


def _build_request(origin, document_name, *, warnings=(), final_try=False) -> dict:
	"""The dialog request for one PIN prompt (spec §6 wire schema)."""
	return {
		"v": dialog_child.PROTOCOL_VERSION,
		"kind": "pin",
		"origin": origin,
		"claims": [document_name] if document_name else [],
		"warnings": list(warnings),
		"final_try": bool(final_try),
		"timeout": dialog_child.DEFAULT_DIALOG_SECONDS,
	}


def request_pin(origin, document_name, *, host, warnings=(), final_try=False) -> str:
	"""Show the PIN dialog through `host` and return the PIN the user typed.

	Raises PinCancelled, PinPromptUnavailable(cause), DialogBusy or DialogWedged
	(spec §6); the last propagates unchanged from the host.
	"""
	request = _build_request(origin, document_name, warnings=warnings, final_try=final_try)
	reply = cause = None
	busy = False
	try:
		reply = host.run_dialog(request)
	except DialogFailed as exc:
		cause = exc.cause
	except UiBusy:
		busy = True

	# Raised here, outside the handlers: __context__ stays empty.
	if busy:
		raise DialogBusy() from None
	if cause is not None:
		raise PinPromptUnavailable(cause) from None

	result = reply.get("result") if type(reply) is dict else None
	if result == "entered":
		value = reply.get("value")
		if type(value) is str and value:
			return value
		raise PinPromptUnavailable("dialog_bad_reply")
	if result == "cancelled":
		raise PinCancelled()
	if result == "timeout":
		raise PinPromptUnavailable("dialog_timeout")
	if result == "unavailable" and reply.get("cause") in dialog_child.UNAVAILABLE_CAUSES:
		raise PinPromptUnavailable(reply["cause"])
	# The host validates every reply, so this is unreachable with the real one: fail closed.
	raise PinPromptUnavailable("dialog_bad_reply")
