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

