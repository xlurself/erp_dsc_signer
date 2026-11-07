import json
import unittest

from erp_dsc_local import errors
from erp_dsc_local.errors import (
	DIALOG_CAUSE_MESSAGES,
	DIALOG_CAUSES,
	CertificatesHidden,
	DialogBusy,
	DialogFailed,
	DialogWedged,
	LocalSignerError,
	PairPromptUnavailable,
	PinIncorrect,
	PinLocked,
	PinPromptUnavailable,
	PinRateLimited,
	SIGNING_ERROR_CLASSES,
	SIGNING_STAGES,
	TokenBusy,
	TokenSigningFailed,
)
from erp_dsc_local.token import SIGNING_FAILED

# Spec 001 §6, copied by hand so a drift in errors.py fails here.
SPEC_MESSAGES = {
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
PAIR_SUFFIX = " Or pair from a terminal: erp-dsc-local --allow <origin>"
BAD_CAUSES = ["", "unknown", "TK_IMPORT_FAILED", "dialog_timeout ", None, 7, ("dialog_timeout",)]


# TOKEN_SIGNING_FAILED diagnostic (spec 001 §7), copied by hand.
SIGNING_MESSAGE = "The USB token could not sign the document."
SENTINEL = "PIN-SENTINEL-e7a1"
SPEC_STAGES = {"login", "find_key", "c_sign", "cms", "tsa", "other"}
SPEC_ERRORS = {
	"TypeError",
	"AttributeError",
	"ImportError",
	"ModuleNotFoundError",
	"FileNotFoundError",
	"OSError",
	"ValueError",
	"KeyError",
	"AssertionError",
	"IndexError",
	"ReadTimeout",
	"ConnectTimeout",
	"ConnectionError",
	"SSLError",
	"Timeout",
	"PyKCS11Error",
	"other",
}


def _liar(target, text=None):
	"""A str SUBCLASS that claims to equal, and hashes like, ``target``."""
	cls = type("_Liar", (str,), {"__eq__": lambda self, other: True, "__hash__": lambda self: hash(target)})
	return cls("Liar-" + SENTINEL if text is None else text)


class DialogCauseTests(unittest.TestCase):
	def test_vocabulary_is_exactly_the_nine_spec_causes(self):
		self.assertEqual(set(SPEC_MESSAGES), set(DIALOG_CAUSES))
		self.assertEqual(9, len(DIALOG_CAUSES))
		self.assertEqual(SPEC_MESSAGES, DIALOG_CAUSE_MESSAGES)

	def test_every_cause_message_names_its_cause(self):
		for cause, message in DIALOG_CAUSE_MESSAGES.items():
			self.assertIn(f"({cause})", message)

	def test_pin_prompt_unavailable_per_cause(self):
		for cause, message in SPEC_MESSAGES.items():
			error = PinPromptUnavailable(cause)
			self.assertEqual("PIN_PROMPT_UNAVAILABLE", error.code)
			self.assertEqual(503, error.status)
			self.assertEqual(message, error.message)
			self.assertEqual({"cause": cause}, error.details)
			self.assertEqual(
				{"ok": False, "error": {"code": "PIN_PROMPT_UNAVAILABLE", "message": message, "details": {"cause": cause}}},
				error.as_dict(),
			)

	def test_pair_prompt_unavailable_per_cause_appends_terminal_hint(self):
		for cause, message in SPEC_MESSAGES.items():
			error = PairPromptUnavailable(cause)
			self.assertEqual("PAIR_PROMPT_UNAVAILABLE", error.code)
			self.assertEqual(503, error.status)
			self.assertEqual(message + PAIR_SUFFIX, error.message)
			self.assertEqual({"cause": cause}, error.details)

	def test_unknown_cause_is_value_error_everywhere(self):
		for factory in (PinPromptUnavailable, PairPromptUnavailable, DialogFailed):
			for cause in BAD_CAUSES:
				with self.subTest(factory=factory.__name__, cause=cause):
					with self.assertRaises(ValueError) as ctx:
						factory(cause)
					if isinstance(cause, str) and cause:
						self.assertNotIn(cause, str(ctx.exception))

	def test_dialog_failed_is_a_plain_exception_carrying_the_cause(self):
		error = DialogFailed("dialog_bad_reply")
		self.assertIsInstance(error, Exception)
		self.assertNotIsInstance(error, LocalSignerError)
		self.assertEqual("dialog_bad_reply", error.cause)
		for cause in DIALOG_CAUSES:
			self.assertEqual(cause, DialogFailed(cause).cause)


class FixedErrorTests(unittest.TestCase):
	EXPECTED = [
		(DialogBusy, "DIALOG_BUSY", 429, "Another signer dialog is already waiting for an answer on this computer."),
		(DialogWedged, "DIALOG_WEDGED", 503, "The signer's dialog process could not be stopped. Restart the signer."),
		(
			CertificatesHidden,
			"TOKEN_CERTIFICATES_HIDDEN",
			409,
			"This token hides its certificates until login, which this version of the signer does not support.",
		),
		(PinIncorrect, "PIN_INCORRECT", 401, "The PIN was incorrect. Check the remaining attempts before trying again."),
		(PinLocked, "PIN_LOCKED", 423, "The token is locked. Unlock it with your DSC provider's tool."),
		(PinRateLimited, "PIN_RATE_LIMITED", 429, "Too many incorrect PINs were entered for this token. Wait a few minutes."),
		(TokenBusy, "TOKEN_BUSY", 429, "Another signing request for this token is still in progress. Try again in a moment."),
	]
	TOKEN_STATE_CHANGED = "The token's state changed while the PIN dialog was open, so the PIN was not sent to it. Try again."

	def test_codes_statuses_messages_and_no_details(self):
		for cls, code, status, message in self.EXPECTED:
			with self.subTest(cls=cls.__name__):
				error = cls()
				self.assertIsInstance(error, LocalSignerError)
				self.assertEqual(code, error.code)
				self.assertEqual(status, error.status)
				self.assertEqual(message, error.message)
				self.assertEqual(message, str(error))
				self.assertEqual({}, error.details)
				self.assertEqual({"ok": False, "error": {"code": code, "message": message}}, error.as_dict())

	def test_token_busy_has_exactly_two_fixed_messages(self):
		error = TokenBusy(state_changed=True)
		self.assertEqual(("TOKEN_BUSY", 429, self.TOKEN_STATE_CHANGED), (error.code, error.status, error.message))
		self.assertEqual({"ok": False, "error": {"code": "TOKEN_BUSY", "message": self.TOKEN_STATE_CHANGED}}, error.as_dict())
		self.assertEqual(TokenBusy().message, TokenBusy(state_changed=False).message)
		self.assertEqual((TokenBusy.IN_PROGRESS, TokenBusy.STATE_CHANGED), (TokenBusy().message, error.message))
		with self.assertRaises(TypeError):
			TokenBusy("any other text")  # no free-form message can be passed in

	def test_pin_required_is_gone(self):
		self.assertFalse(hasattr(errors, "PinRequired"))


class TestTokenSigningFailed(unittest.TestCase):
	def test_vocabularies_are_exactly_the_spec_lists(self):
		self.assertEqual(SPEC_STAGES, set(SIGNING_STAGES))
		self.assertEqual(SPEC_ERRORS, set(SIGNING_ERROR_CLASSES))

	def test_fixed_message_and_exactly_three_fields(self):
		self.assertEqual(SIGNING_MESSAGE, SIGNING_FAILED)
		for stage in SPEC_STAGES:
			for error in SPEC_ERRORS:
				for ckr in (None, "CKR_MECHANISM_INVALID", "CKR_VENDOR_DEFINED"):
					failure = TokenSigningFailed(stage=stage, error=error, ckr=ckr)
					self.assertEqual(("TOKEN_SIGNING_FAILED", 502, SIGNING_MESSAGE), (failure.code, failure.status, failure.message))
					self.assertEqual(SIGNING_MESSAGE, str(failure))
					details = {"stage": stage, "error": error, "ckr": ckr}
					self.assertEqual(details, failure.details)
					self.assertEqual(
						{"ok": False, "error": {"code": "TOKEN_SIGNING_FAILED", "message": SIGNING_MESSAGE, "details": details}},
						failure.as_dict(),
					)
		self.assertIn('"ckr": null', json.dumps(TokenSigningFailed(stage="cms", error="other").as_dict()))

	def test_a_value_outside_the_vocabularies_is_value_error_and_not_echoed(self):
		marker = "BAD-" + SENTINEL
		bad = (
			*[dict(stage=value, error="other") for value in ("bogus", marker, "Login", "login ", "", None, 5, _liar("login"))],
			*[dict(stage="cms", error=value) for value in ("RuntimeError", marker, "typeerror", "", None, TypeError, _liar("TypeError"))],
			*[
				dict(stage="cms", error="other", ckr=value)
				for value in ("MECHANISM_INVALID", "CKR_" + marker, "ckr_ok", "CKR_", "", 0x70, True, _liar("CKR_OK", "CKR_OK"))
			],
		)
		for kwargs in bad:
			with self.subTest(kwargs=kwargs):
				with self.assertRaises(ValueError) as ctx:
					TokenSigningFailed(**kwargs)
				self.assertNotIn(SENTINEL, str(ctx.exception))
				self.assertNotIn("bogus", str(ctx.exception))

	def test_no_free_form_text_can_be_passed_in(self):
		with self.assertRaises(TypeError):
			TokenSigningFailed("any text")
		self.assertTrue(issubclass(TokenSigningFailed, LocalSignerError))


if __name__ == "__main__":
	unittest.main()
