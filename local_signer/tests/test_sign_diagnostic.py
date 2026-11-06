"""TOKEN_SIGNING_FAILED carries a PIN-safe diagnostic (spec 001 §7).

The message stays the one fixed sentence the Desk shows.  ``details`` is
``{"stage", "error", "ckr"}``, each value from a closed vocabulary: the step that failed,
the exception CLASS NAME if allowlisted (else "other"), and the PKCS#11 return-code NAME
from ``PyKCS11.CKR`` (else null).  The exception's text, args and traceback are never read,
so a hostile driver, endesive or TSA cannot put the PIN there.  One fixed line with the
same three fields goes to stderr.
"""

import io
import json
import traceback
import unittest
from unittest import mock

import requests

import test_service_http as http_harness
import test_token_login as fakes
from test_token_login import PK, SENTINEL_PIN, FakeCms, FakeGuard, chain, install_fake_endesive, make_client, two_slot_lib

from erp_dsc_local import service as service_module
from erp_dsc_local import token as token_module
from erp_dsc_local.errors import PinIncorrect, TokenSigningFailed
from erp_dsc_local.token import SIGNING_FAILED_LOG

MESSAGE = "The USB token could not sign the document."



class PKC(PK):
	"""The PyKCS11 stand-in plus ``CKR``, which maps code -> name and name -> code as
	``PyKCS11.CKR`` does."""

	CKR_MECHANISM_INVALID = 0x70
	CKR = {}


for _name in dir(PKC):
	if _name.startswith("CKR_") and type(getattr(PKC, _name)) is int:
		PKC.CKR[getattr(PKC, _name)] = _name
		PKC.CKR[_name] = getattr(PKC, _name)


class _Liar(str):
	"""A str subclass that claims to equal (and hash like) an allowlisted name."""

	def __eq__(self, other):
		return True

	def __hash__(self):
		return hash("TypeError")


class _LyingName(type):
	__name__ = property(lambda cls: _Liar("Liar" + SENTINEL_PIN))


class LyingNameError(Exception, metaclass=_LyingName):
	pass


def hostile_class(base):
	"""A subclass of ``base`` whose class NAME carries the PIN."""
	return type("Hostile_" + SENTINEL_PIN.replace("-", "_") + "_" + base.__name__, (base,), {})


def renderings(error):
	texts = [str(error), repr(error), repr(error.args), repr(vars(error)), json.dumps(error.as_dict())]
	texts.append("".join(traceback.format_exception(type(error), error, error.__traceback__)))
	return texts


def setUpModule():
	if fakes.DER is None:  # test_token_login builds its certificate in its own setUpModule
		fakes.DER = fakes._make_der()


class SigningPathCase(unittest.TestCase):
	def setUp(self):
		self.cms = FakeCms()
		install_fake_endesive(self, self.cms)
		self.stderr = io.StringIO()
		patcher = mock.patch("sys.stderr", self.stderr)
		patcher.start()
		self.addCleanup(patcher.stop)

	def fail(self, *, attribute=None, factory=None, timestamp_error=None, pk=PKC):
		"""Sign once with the real TokenClient; return the error it raised."""
		lib = two_slot_lib()
		if attribute:
			setattr(lib, attribute, factory)
		client = make_client(lib)
		client.pk = pk
		selected, certificates = client.select(None)
		if timestamp_error is not None:

			def step(hsm):
				raise timestamp_error(lib.received_pin)

			self.cms.timestamp_step = step
		self.lib = lib
		try:
			client.sign_pdf(b"%PDF", selected, certificates, {"reason": "x"}, SENTINEL_PIN, None, login_guard=FakeGuard(lib.log))
		except BaseException as error:
			return error
		raise AssertionError("expected TOKEN_SIGNING_FAILED")

	def assert_failure(self, error, stage, name, ckr=None):
		self.assertIsInstance(error, TokenSigningFailed)
		self.assertEqual(("TOKEN_SIGNING_FAILED", 502, MESSAGE), (error.code, error.status, error.message))
		self.assertEqual({"stage": stage, "error": name, "ckr": ckr}, error.details)
		self.assertEqual([error], chain(error), "raised `from None`, outside any except block")
		self.assertIsNone(error.__cause__)
		self.assertIsNone(error.__context__)
		line = SIGNING_FAILED_LOG.format(stage=stage, error=name, ckr=ckr or "none") + "\n"
		self.assertEqual(line, self.stderr.getvalue(), "exactly one fixed line on stderr")
		self.stderr.seek(0)
		self.stderr.truncate()


class TestEachStage(SigningPathCase):
	def test_login(self):
		for code in ("CKR_GENERAL_ERROR", "CKR_TOKEN_NOT_PRESENT", "CKR_DEVICE_REMOVED", "CKR_USER_ALREADY_LOGGED_IN"):
			with self.subTest(code=code):
				factory = lambda pin, code=code: PKC.PyKCS11Error(getattr(PKC, code), f"driver says pin={pin}")
				self.assert_failure(self.fail(attribute="login_error", factory=factory), "login", "PyKCS11Error", code)
				self.assertEqual(1, len(self.lib.logins))
		self.assert_failure(self.fail(attribute="login_error", factory=lambda pin: TypeError(pin)), "login", "TypeError")

	def test_find_key(self):
		factory = lambda pin: PKC.PyKCS11Error(PKC.CKR_FUNCTION_FAILED, f"pin={pin}")
		self.assert_failure(self.fail(attribute="find_key_error", factory=factory), "find_key", "PyKCS11Error", "CKR_FUNCTION_FAILED")

	def test_c_sign(self):
		factory = lambda pin: PKC.PyKCS11Error(PKC.CKR_MECHANISM_INVALID, f"pin={pin}")
		self.assert_failure(self.fail(attribute="sign_error", factory=factory), "c_sign", "PyKCS11Error", "CKR_MECHANISM_INVALID")
		self.assertIn(("logout", 2), self.lib.log)
		self.assert_failure(self.fail(attribute="sign_error", factory=lambda pin: AttributeError(pin)), "c_sign", "AttributeError")

	def test_cms_by_class(self):
		for error_type in (TypeError, AttributeError, ImportError, ModuleNotFoundError, FileNotFoundError, OSError, ValueError, KeyError):
			with self.subTest(error=error_type.__name__):
				self.assert_failure(self.fail(timestamp_error=error_type), "cms", error_type.__name__)
				self.assertIn(("logout", 2), self.lib.log)

	def test_tsa_is_any_requests_exception(self):
		exceptions = requests.exceptions
		for error_type, name in (
			(exceptions.ReadTimeout, "ReadTimeout"),
			(exceptions.ConnectTimeout, "ConnectTimeout"),
			(exceptions.ConnectionError, "ConnectionError"),
			(exceptions.SSLError, "SSLError"),
			(exceptions.Timeout, "Timeout"),
			(exceptions.HTTPError, "other"),
			(exceptions.InvalidURL, "other"),
		):
			with self.subTest(error=error_type.__name__):
				self.assert_failure(self.fail(timestamp_error=error_type), "tsa", name)

	def test_a_class_outside_the_allowlist_is_other_at_every_stage(self):
		class Boom(Exception):
			pass

		for attribute in ("login_error", "find_key_error", "sign_error"):
			with self.subTest(attribute=attribute):
				stage = {"login_error": "login", "find_key_error": "find_key", "sign_error": "c_sign"}[attribute]
				self.assert_failure(self.fail(attribute=attribute, factory=lambda pin: Boom(pin)), stage, "other")
		self.assert_failure(self.fail(timestamp_error=Boom), "cms", "other")
		self.assert_failure(self.fail(timestamp_error=RuntimeError), "cms", "other")

	def test_ckr_is_looked_up_by_value_and_kept_only_if_it_is_a_ckr_name(self):
		class NoTable(PK):  # PyKCS11 without CKR
			pass

		class HostileTable(PKC):
			CKR = {PK.CKR_GENERAL_ERROR: SENTINEL_PIN, PK.CKR_FUNCTION_FAILED: "ckr_lower", 0x70: _Liar("CKR_OK")}

		general = lambda pin: PKC.PyKCS11Error(PK.CKR_GENERAL_ERROR, pin)
		for pk, factory in (
			(NoTable, general),
			(HostileTable, general),
			(HostileTable, lambda pin: PKC.PyKCS11Error(PK.CKR_FUNCTION_FAILED, pin)),
			(HostileTable, lambda pin: PKC.PyKCS11Error(0x70, pin)),
			(PKC, lambda pin: PKC.PyKCS11Error(0x7FFF0001, pin)),  # not in the table
			(PKC, lambda pin: PKC.PyKCS11Error("CKR_GENERAL_ERROR", pin)),  # value is not an int
			(PKC, lambda pin: PKC.PyKCS11Error(True, pin)),  # bool is not a return code
			(PKC, lambda pin: PKC.PyKCS11Error(None, pin)),
		):
			with self.subTest(pk=pk.__name__):
				self.assert_failure(self.fail(attribute="login_error", factory=factory, pk=pk), "login", "PyKCS11Error")

		class NotPyKCS11(Exception):
			value = PK.CKR_GENERAL_ERROR

		self.assert_failure(self.fail(attribute="login_error", factory=lambda pin: NotPyKCS11(pin)), "login", "other")

	def test_a_second_c_sign_after_a_failed_login_is_login_other(self):
		self.cms.retry_after_error = True
		factory = lambda pin: PKC.PyKCS11Error(PK.CKR_GENERAL_ERROR, pin)
		error = self.fail(attribute="login_error", factory=factory)
		self.assertEqual({"stage": "login", "error": "PyKCS11Error", "ckr": "CKR_GENERAL_ERROR"}, self.cms.first_error.details)
		self.assertEqual({"stage": "login", "error": "other", "ckr": None}, error.details)
		self.assertEqual(1, len(self.lib.logins))

	def test_a_wrong_pin_is_still_pin_incorrect_without_details(self):
		error = self.fail(attribute="login_error", factory=lambda pin: PKC.PyKCS11Error(PK.CKR_PIN_INCORRECT, pin))
		self.assertIsInstance(error, PinIncorrect)
		self.assertEqual({}, error.details)
		self.assertEqual("", self.stderr.getvalue())

	def test_an_unknown_stage_or_value_at_runtime_becomes_other(self):
		for stage, diagnosis in (("bogus", ("RuntimeError", "ckr_x")), (None, (5, 7)), ("cms", (_Liar("TypeError"), _Liar("CKR_OK")))):
			with self.subTest(stage=stage):
				error = token_module._signing_failed(stage, diagnosis)
				self.assertEqual({"stage": "other" if stage != "cms" else "cms", "error": "other", "ckr": None}, error.details)
				self.stderr.seek(0)
				self.stderr.truncate()


class TestTheDiagnosticNeverCarriesThePin(SigningPathCase):
	def assert_clean(self, error):
		for text in [*renderings(error), self.stderr.getvalue()]:
			self.assertNotIn(SENTINEL_PIN, text)
			self.assertNotIn("Hostile", text)
		for value in error.details.values():
			self.assertIn(type(value), (str, type(None)))

	def test_hostile_text_args_and_class_names(self):
		hostile_pkcs = hostile_class(PKC.PyKCS11Error)
		cases = [
			(dict(attribute="login_error", factory=lambda pin: hostile_pkcs(PK.CKR_GENERAL_ERROR, pin)), ("login", "other", "CKR_GENERAL_ERROR")),
			(dict(attribute="find_key_error", factory=lambda pin: hostile_class(KeyError)(pin)), ("find_key", "other", None)),
			(dict(attribute="sign_error", factory=lambda pin: LyingNameError(pin)), ("c_sign", "other", None)),
			(dict(timestamp_error=lambda pin: hostile_class(FileNotFoundError)(2, pin, "/srv/" + pin)), ("cms", "other", None)),
			(dict(timestamp_error=lambda pin: hostile_class(requests.exceptions.ReadTimeout)(pin)), ("tsa", "other", None)),
			(dict(timestamp_error=lambda pin: requests.exceptions.ReadTimeout(f"read timed out, pin={pin}")), ("tsa", "ReadTimeout", None)),
			(dict(timestamp_error=lambda pin: LyingNameError(pin)), ("cms", "other", None)),
		]
		for kwargs, expected in cases:
			with self.subTest(expected=expected):
				error = self.fail(**kwargs)
				self.assertEqual(SENTINEL_PIN, self.lib.received_pin, "the hostile driver did see the PIN")
				self.assertEqual(dict(zip(("stage", "error", "ckr"), expected)), error.details)
				self.assert_clean(error)
				self.assertEqual(1, len(self.stderr.getvalue().splitlines()))
				self.stderr.seek(0)
				self.stderr.truncate()


class TestTheHttpResponseCarriesTheDiagnostic(http_harness.SignTestCase):
	"""``/v1/sign`` with the real TokenClient: ``message`` fixed, ``details`` for the operator."""

	def setUp(self):
		super().setUp()
		install_fake_endesive(self, FakeCms())
		self.stderr = io.StringIO()
		patcher = mock.patch("sys.stderr", self.stderr)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.lib = two_slot_lib()
		self.lib.sign_error = lambda pin: hostile_class(PKC.PyKCS11Error)(PKC.CKR_MECHANISM_INVALID, f"pin={pin}")
		client = make_client(self.lib)
		client.pk = PKC
		patcher = mock.patch.object(service_module, "TokenClient", lambda module: client)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.service.pin_prompt = lambda origin, document_name, **kwargs: SENTINEL_PIN

	def test_response(self):
		status, _headers, body = self.sign_request("INV-1", certificate=None)
		self.assertEqual(502, status, body)
		details = {"stage": "c_sign", "error": "other", "ckr": "CKR_MECHANISM_INVALID"}
		self.assertEqual({"code": "TOKEN_SIGNING_FAILED", "message": MESSAGE, "details": details}, body["error"])
		self.assertNotIn(SENTINEL_PIN, json.dumps(body))
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		log = SIGNING_FAILED_LOG.format(stage="c_sign", error="other", ckr="CKR_MECHANISM_INVALID") + "\n"
		self.assertEqual(log, self.stderr.getvalue())


if __name__ == "__main__":
	unittest.main()
