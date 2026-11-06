"""Structured errors that are safe to expose over the loopback API."""

from __future__ import annotations

import re


class LocalSignerError(Exception):
	def __init__(
		self,
		code: str,
		message: str,
		*,
		status: int = 400,
		details: dict | None = None,
	):
		super().__init__(message)
		self.code = code
		self.message = message
		self.status = status
		self.details = details or {}

	def as_dict(self) -> dict:
		payload = {"ok": False, "error": {"code": self.code, "message": self.message}}
		if self.details:
			payload["error"]["details"] = self.details
		return payload


class ConfigurationError(LocalSignerError):
	def __init__(self, message: str):
		super().__init__("CONFIGURATION_ERROR", message, status=500)


class MiddlewareUnavailable(LocalSignerError):
	def __init__(self, message: str):
		super().__init__("MIDDLEWARE_UNAVAILABLE", message, status=503)


class TokenUnavailable(LocalSignerError):
	def __init__(self, message: str = "No compatible USB DSC token is connected."):
		super().__init__("TOKEN_UNAVAILABLE", message, status=409)


class CertificatesHidden(LocalSignerError):
	"""A session opened and listed no objects: the token hides its certificates until login.

	Raised only for that clean empty result. Every other zero-certificate outcome is a
	``TokenUnavailable``. Carries no ``details``.
	"""

	def __init__(self):
		super().__init__(
			"TOKEN_CERTIFICATES_HIDDEN",
			"This token hides its certificates until login, which this version of the signer does not support.",
			status=409,
		)


# The closed vocabulary of reasons a desktop dialog produced no usable answer (spec §6).
# The cause is part of the sentence because the Desk shows only ``error.message``.
DIALOG_CAUSE_MESSAGES = {
	"tk_import_failed": "The signer cannot show a dialog because Tk is not available in its Python (tk_import_failed).",
	"tk_init_failed": "The signer could not open a window on this desktop (tk_init_failed). Run it in a logged-in desktop session.",
	"dialog_spawn_failed": "The signer could not start its dialog process (dialog_spawn_failed).",
	"dialog_process_crashed": "The signer's dialog process crashed (dialog_process_crashed).",
	"dialog_process_failed": "The signer's dialog process exited without an answer (dialog_process_failed).",
	"dialog_bad_reply": "The signer's dialog process returned an unexpected reply and was ignored (dialog_bad_reply).",
	"dialog_timeout": "No answer was given in time and the dialog was closed (dialog_timeout).",
	"dialog_shutdown": "The signer is shutting down (dialog_shutdown). Try again.",
	"dialog_request_invalid": "The signer refused to show a dialog for an invalid request (dialog_request_invalid).",
}
DIALOG_CAUSES = frozenset(DIALOG_CAUSE_MESSAGES)

PAIR_FROM_TERMINAL_HINT = " Or pair from a terminal: erp-dsc-local --allow <origin>"


def _dialog_cause(cause: object) -> str:
	if not isinstance(cause, str) or cause not in DIALOG_CAUSES:
		# The rejected value is deliberately not echoed: it may be text from the dialog child.
		raise ValueError("invalid dialog failure cause")
	return cause


class DialogFailed(Exception):
	"""The dialog child gave no usable answer. Internal: pin/pairing map it per spec §6."""

	def __init__(self, cause: str):
		self.cause = _dialog_cause(cause)
		super().__init__(self.cause)


class PinPromptUnavailable(LocalSignerError):
	def __init__(self, cause: str):
		cause = _dialog_cause(cause)
		super().__init__(
			"PIN_PROMPT_UNAVAILABLE",
			DIALOG_CAUSE_MESSAGES[cause],
			status=503,
			details={"cause": cause},
		)


class PinIncorrect(LocalSignerError):
	def __init__(self):
		super().__init__(
			"PIN_INCORRECT",
			"The PIN was incorrect. Check the remaining attempts before trying again.",
			status=401,
		)


class PinLocked(LocalSignerError):
	def __init__(self):
		super().__init__("PIN_LOCKED", "The token is locked. Unlock it with your DSC provider's tool.", status=423)


class PinRateLimited(LocalSignerError):
	def __init__(self):
		super().__init__(
			"PIN_RATE_LIMITED",
			"Too many incorrect PINs were entered for this token. Wait a few minutes.",
			status=429,
		)


# The closed vocabularies of a TOKEN_SIGNING_FAILED diagnostic (spec §7).  ``details``
# holds only these values, so no driver, endesive or TSA text (and so no PIN) reaches it.
SIGNING_STAGES = frozenset({"login", "find_key", "c_sign", "cms", "tsa", "other"})
SIGNING_ERROR_CLASSES = frozenset(
	{
		"TypeError",
		"AttributeError",
		"ImportError",
		"ModuleNotFoundError",
		"FileNotFoundError",
		"OSError",
		"ValueError",
		"KeyError",
		"ReadTimeout",
		"ConnectTimeout",
		"ConnectionError",
		"SSLError",
		"Timeout",
		"PyKCS11Error",
		"other",
	}
)
# A PKCS#11 return-code name as PyKCS11.CKR spells it (CKR_MECHANISM_INVALID, ...).
CKR_NAME = re.compile(r"CKR_[A-Z0-9_]{1,60}", re.ASCII)


def _vocabulary(value: object, vocabulary: frozenset, what: str) -> str:
	# Exact str first, so a str subclass cannot pass by overriding __eq__/__hash__.
	if type(value) is not str or value not in vocabulary:
		raise ValueError(f"invalid signing failure {what}")  # the value is never echoed
	return value


class TokenSigningFailed(LocalSignerError):
	"""``TOKEN_SIGNING_FAILED`` (502): one fixed message, which the Desk shows, and a
	diagnostic in ``details`` for the operator: ``stage`` (``SIGNING_STAGES``), ``error``
	(an exception class name in ``SIGNING_ERROR_CLASSES``) and ``ckr`` (a ``CKR_NAME`` or
	None).  Any other value raises ``ValueError``; ``token.py`` maps unknown values to
	"other" / None before it gets here.  No free text can be passed in.
	"""

	MESSAGE = "The USB token could not sign the document."

	def __init__(self, *, stage: str, error: str, ckr: str | None = None):
		stage = _vocabulary(stage, SIGNING_STAGES, "stage")
		error = _vocabulary(error, SIGNING_ERROR_CLASSES, "error")
		if ckr is not None and (type(ckr) is not str or not CKR_NAME.fullmatch(ckr)):
			raise ValueError("invalid signing failure ckr")
		super().__init__(
			"TOKEN_SIGNING_FAILED",
			self.MESSAGE,
			status=502,
			details={"stage": stage, "error": error, "ckr": ckr},
		)


class TokenBusy(LocalSignerError):
	"""``TOKEN_BUSY`` (429), with one of two fixed messages and no other text (spec §7).

	Default: the per-serial token lock was not free within ``TOKEN_LOCK_TIMEOUT_SECONDS``.
	``state_changed=True``: the token's flags, re-read immediately before ``C_Login``,
	show a state the dialog did not warn about, so the PIN was never sent to the token.
	"""

	IN_PROGRESS = "Another signing request for this token is still in progress. Try again in a moment."
	STATE_CHANGED = "The token's state changed while the PIN dialog was open, so the PIN was not sent to it. Try again."

	def __init__(self, *, state_changed: bool = False):
		super().__init__("TOKEN_BUSY", self.STATE_CHANGED if state_changed else self.IN_PROGRESS, status=429)


class DialogBusy(LocalSignerError):
	def __init__(self):
		super().__init__(
			"DIALOG_BUSY",
			"Another signer dialog is already waiting for an answer on this computer.",
			status=429,
		)


class DialogWedged(LocalSignerError):
	def __init__(self):
		super().__init__(
			"DIALOG_WEDGED",
			"The signer's dialog process could not be stopped. Restart the signer.",
			status=503,
		)


class PinCancelled(LocalSignerError):
	def __init__(self):
		super().__init__("PIN_CANCELLED", "Signing was cancelled in the local PIN dialog.", status=409)


class InvalidOrigin(LocalSignerError):
	def __init__(self):
		super().__init__("INVALID_ORIGIN", "The request Origin header is missing or malformed.", status=400)


class OriginNotPaired(LocalSignerError):
	"""The origin is well-formed but has not been paired with this workstation.

	Distinct from a hard denial: the browser client turns this into a "pair this
	workstation" prompt rather than "the signer is not running".
	"""

	def __init__(self):
		super().__init__(
			"ORIGIN_NOT_PAIRED",
			"This ERP site is not paired with the local signer on this computer.",
			status=403,
		)


class PairProofInvalid(LocalSignerError):
	def __init__(self, message: str = "The pairing proof could not be verified with the ERP site."):
		super().__init__("PAIR_PROOF_INVALID", message, status=403)


class PairDenied(LocalSignerError):
	def __init__(self):
		super().__init__("PAIR_DENIED", "Pairing was declined on this computer.", status=403)


class PairPromptUnavailable(LocalSignerError):
	def __init__(self, cause: str):
		cause = _dialog_cause(cause)
		super().__init__(
			"PAIR_PROMPT_UNAVAILABLE",
			DIALOG_CAUSE_MESSAGES[cause] + PAIR_FROM_TERMINAL_HINT,
			status=503,
			details={"cause": cause},
		)


class PairRateLimited(LocalSignerError):
	def __init__(self, message: str = "Too many pairing attempts. Try again later."):
		super().__init__("PAIR_RATE_LIMITED", message, status=429)
