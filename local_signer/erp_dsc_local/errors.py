"""Structured errors that are safe to expose over the loopback API."""

from __future__ import annotations


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


class PinRequired(LocalSignerError):
	def __init__(self):
		super().__init__(
			"PIN_REQUIRED",
			"The token hides certificates until login. Continue to signing to enter the PIN locally.",
			status=409,
			details={"pin_required": True},
		)


class PinPromptUnavailable(LocalSignerError):
	def __init__(self):
		super().__init__(
			"PIN_PROMPT_UNAVAILABLE",
			"The local PIN dialog is unavailable. Run the signer in an interactive desktop session with tkinter installed.",
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
	def __init__(self):
		super().__init__(
			"PAIR_PROMPT_UNAVAILABLE",
			"The pairing dialog is unavailable. Run the signer in an interactive desktop session, "
			"or pair from the command line with: erp-dsc-local --allow <origin>",
			status=503,
		)


class PairInProgress(LocalSignerError):
	def __init__(self):
		super().__init__(
			"PAIR_IN_PROGRESS",
			"Another pairing request is already waiting for an answer on this computer.",
			status=429,
		)


class PromptTimedOut(LocalSignerError):
	"""A desktop dialog outlived its hard timeout and is still on screen.

	Reported instead of a generic 500 so the caller can say something true, and so a
	wedged dialog is distinguishable from a crash.
	"""

	def __init__(self):
		super().__init__(
			"PROMPT_TIMED_OUT",
			"A dialog on this computer is still waiting for an answer. Finish or close it, then retry.",
			status=504,
		)


class PairRateLimited(LocalSignerError):
	def __init__(self, message: str = "Too many pairing attempts. Try again later."):
		super().__init__("PAIR_RATE_LIMITED", message, status=429)

