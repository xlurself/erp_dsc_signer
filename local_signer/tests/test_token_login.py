"""Spec 001 §7 / I1: one C_Login per PIN entry, on the selected token only.

A fake PKCS#11 library records every call (and every handle passed to
getAttributeValue) so the tests can prove where the PIN went and what was read.
"""

import os
import ast
import inspect
import sys
import traceback
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import erp_dsc_local
from _probe_inproc import use_in_process_probe
from erp_dsc_local.errors import LocalSignerError, PinIncorrect, PinLocked, PinRateLimited, TokenBusy, TokenUnavailable
from erp_dsc_local.token import (
	KEY_NOT_AVAILABLE,
	SIGNING_FAILED,
	TOKEN_NOT_AVAILABLE,
	TSA_CONNECT_TIMEOUT_SECONDS,
	TSA_TIMEOUT_SECONDS,
	TokenClient,
	_TokenHSM,
	_token_field,
)

SENTINEL_PIN = "PIN-SENTINEL-8c41f2"
KEY_ID = b"\x01\x02\x03"


class PK:
	"""Stands in for the PyKCS11 module."""

	CKF_SERIAL_SESSION = 4
	CKA_CLASS = 0x000
	CKA_LABEL = 0x003
	CKA_VALUE = 0x011
	CKA_ID = 0x102
	CKA_PRIVATE_EXPONENT = 0x123
	CKO_CERTIFICATE = 1
	CKO_PRIVATE_KEY = 3
	CKR_GENERAL_ERROR = 0x05
	CKR_FUNCTION_FAILED = 0x06
	CKR_DEVICE_REMOVED = 0x32
	CKR_PIN_INCORRECT = 0xA0
	CKR_PIN_INVALID = 0xA1
	CKR_PIN_LEN_RANGE = 0xA2
	CKR_PIN_LOCKED = 0xA4
	CKR_SESSION_CLOSED = 0xB0
	CKR_SESSION_HANDLE_INVALID = 0xB3
	CKR_TOKEN_NOT_PRESENT = 0xE0
	CKR_USER_ALREADY_LOGGED_IN = 0x100
	CKF_USER_PIN_FINAL_TRY = 0x20000
	CKF_USER_PIN_LOCKED = 0x40000
	CKM_SHA256_RSA_PKCS = 0x40

	class PyKCS11Error(Exception):
		def __init__(self, value, text=""):
			super().__init__(value, text)
			self.value, self.text = value, text

		def __str__(self):
			return f"{self.value:#x} {self.text}"

	@staticmethod
	def Mechanism(mechanism, param):
		return ("mechanism", mechanism, param)


def _make_der():
	from cryptography import x509
	from cryptography.hazmat.primitives import hashes, serialization
	from cryptography.hazmat.primitives.asymmetric import rsa
	from cryptography.x509.oid import NameOID

	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "F1 Test Signer")])
	now = datetime.now(timezone.utc)
	certificate = (
		x509.CertificateBuilder()
		.subject_name(name)
		.issuer_name(name)
		.public_key(key.public_key())
		.serial_number(0xF1)
		.not_valid_before(now - timedelta(days=1))
		.not_valid_after(now + timedelta(days=30))
		.sign(key, hashes.SHA256())
	)
	return certificate.public_bytes(serialization.Encoding.DER)


DER = None


def setUpModule():
	global DER
	DER = _make_der()


class FakeSession:
	def __init__(self, lib, slot):
		self.lib, self.slot = lib, slot
		self.logged_in = False

	def findObjects(self, template):
		attrs = dict(template)
		self.lib.log.append(("findObjects", self.slot, attrs.get(PK.CKA_CLASS)))
		token = self.lib.tokens[self.slot]
		if attrs.get(PK.CKA_CLASS) == PK.CKO_CERTIFICATE:
			return [handle for handle, _ in token["certs"]]
		if attrs.get(PK.CKA_CLASS) == PK.CKO_PRIVATE_KEY:
			if self.lib.find_key_error:
				raise self.lib.find_key_error(self.lib.received_pin)
			wanted = bytes(attrs.get(PK.CKA_ID, b""))
			return [handle for handle, key_id in token["keys"] if key_id == wanted]
		return []

	def getAttributeValue(self, handle, attributes):
		self.lib.attribute_reads.append((handle, tuple(attributes)))
		for cert_handle, (der, key_id, label) in self.lib.tokens[self.slot]["certs"]:
			if cert_handle == handle:
				values = {PK.CKA_VALUE: der, PK.CKA_ID: key_id, PK.CKA_LABEL: label}
				return [values[attribute] for attribute in attributes]
		return [None for _ in attributes]

	def login(self, pin):
		self.lib.log.append(("login", self.slot))
		self.lib.logins.append((self.slot, pin))
		self.lib.received_pin = pin
		if self.lib.login_error:
			raise self.lib.login_error(pin)
		self.logged_in = True

	def sign(self, key, data, mechanism):
		self.lib.log.append(("sign", self.slot, key))
		self.lib.mechanisms.append(mechanism)
		if self.lib.sign_error:
			raise self.lib.sign_error(self.lib.received_pin)
		return list(b"SIG-" + bytes(data))

	def logout(self):
		self.lib.log.append(("logout", self.slot))

	def closeSession(self):
		self.lib.log.append(("closeSession", self.slot))


class FakeLib:
	"""slots: {slot_id: {"serial": raw, "label": raw, "flags": int, "certs": [...], "keys": [...]}}"""

	def __init__(self, tokens):
		self.tokens = tokens
		self.log, self.logins, self.attribute_reads, self.mechanisms = [], [], [], []
		self.private_handles = {handle for token in tokens.values() for handle, _ in token["keys"]}
		self.login_error = self.sign_error = self.find_key_error = None
		self.received_pin = None

	def getSlotList(self, tokenPresent=True):
		self.log.append(("getSlotList",))
		return sorted(self.tokens)

	def getTokenInfo(self, slot):
		self.log.append(("getTokenInfo", slot))
		token = self.tokens[slot]
		return SimpleNamespace(label=token["label"], serialNumber=token["serial"], flags=token.get("flags", 0))

	def openSession(self, slot, flags):
		self.log.append(("openSession", slot))
		return FakeSession(self, slot)


class FakeGuard:
	"""Records the guard protocol.  ``refuse`` fails __enter__; ``refuse_flags`` fails check_flags."""

	def __init__(self, log, refuse=None, refuse_flags=None):
		self.log, self.refuse, self.refuse_flags = log, refuse, refuse_flags

	def __enter__(self):
		self.log.append(("guard_enter",))
		if self.refuse:
			raise self.refuse
		return self

	def __exit__(self, *exc):
		self.log.append(("guard_exit",))
		return False

	def check_flags(self, flags):
		self.log.append(("check_flags", flags))
		if self.refuse_flags:
			raise self.refuse_flags

	def succeeded(self):
		self.log.append(("succeeded",))

	def failed(self):
		self.log.append(("failed",))


class FakeCms:
	def __init__(self):
		self.hsm = None
		self.timestamp_urls = []
		self.timestamp_options = []
		self.sign_rounds = 1
		self.pin_seen_by_hsm = None
		self.retry_after_error = False  # a caller that swallows hsm.sign's error and calls again
		self.first_error = None
		# Runs after hsm.sign, where endesive makes its timestamp request; may raise.
		self.timestamp_step = None
		# Runs before the first hsm.sign (endesive building the PDF); may raise.
		self.before_sign_step = None
		# What endesive passes to hsm.sign: the digest it took from the PDF (cms.py ~715-727).
		self.algorithm = "sha256"

	def sign(self, datau, udct, key, cert, othercerts, algomd, hsm=None, timestampurl=None, timestamp_req_options=None):
		self.hsm = hsm
		self.timestamp_urls.append(timestampurl)
		self.timestamp_options.append(timestamp_req_options)
		key_id, _certificate = hsm.certificate()
		signature = b""
		if self.before_sign_step is not None:
			self.before_sign_step(hsm)
		if self.retry_after_error:
			try:
				hsm.sign(key_id, b"attrs", self.algorithm)
			except LocalSignerError as error:
				self.first_error = error
		for _ in range(self.sign_rounds):
			signature = hsm.sign(key_id, b"attrs", self.algorithm)
		self.pin_seen_by_hsm = hsm.pin
		if self.timestamp_step is not None:
			self.timestamp_step(hsm)
		return b"|" + signature


class FakeTsaTimeout(Exception):
	"""Stands in for requests' ReadTimeout; its text names the TSA, like the real one."""

	def __init__(self):
		super().__init__("HTTPSConnectionPool(host='tsa.example', port=443): Read timed out. (read timeout=15)")


def raise_in_timestamp(error_type):
	def step(hsm):
		raise error_type()

	return step


def _token(serial, certs=(), keys=(), flags=0, label="Watchdata"):
	return {"serial": serial, "label": label, "flags": flags, "certs": list(certs), "keys": list(keys)}


def two_slot_lib(slot1_serial="SER-1", slot2_serial="SER-2   "):
	"""Slot 1: a token with no certificates.  Slot 2: the signing cert (handle 20) + key (handle 21)."""
	return FakeLib(
		{
			1: _token(slot1_serial),
			2: _token(slot2_serial, certs=[(20, (DER, KEY_ID, "sign"))], keys=[(21, KEY_ID)]),
		}
	)


def make_client(lib):
	"""A real TokenClient over ``lib``: the PIN-free reads run through the real probe
	protocol in-process (``_probe_inproc``); the sign path uses ``lib`` directly."""
	client = TokenClient.__new__(TokenClient)
	client.lib, client.pk = lib, PK
	client.module = SimpleNamespace(label="libwdpkcs.dylib", path=os.path.abspath("/Library/WD/libwdpkcs.dylib"))
	return use_in_process_probe(client)


def chain(error):
	seen = []
	while error is not None and error not in seen:
		seen.append(error)
		error = error.__cause__ or error.__context__
	return seen


def driver_error(code):
	"""A hostile driver that echoes the PIN in its error text."""
	return lambda pin: PK.PyKCS11Error(code, f"driver says pin={pin}")


def install_fake_endesive(test, cms):
	"""Put a fake ``endesive.pdf.cms`` in sys.modules for one test, restoring only those keys.

	Not ``mock.patch.dict(sys.modules)``: that restores the whole dict, dropping every module
	first imported during the test (PyKCS11, via ``service._pin_flags``), and re-importing
	that SWIG extension later crashes the interpreter.
	"""
	pdf_module = types.ModuleType("endesive.pdf")
	pdf_module.cms = cms
	endesive_module = types.ModuleType("endesive")
	endesive_module.pdf = pdf_module
	for name, module in (("endesive", endesive_module), ("endesive.pdf", pdf_module), ("endesive.pdf.cms", cms)):
		test.addCleanup(_restore_module, name, sys.modules.get(name, _MISSING))
		sys.modules[name] = module


_MISSING = object()


def _restore_module(name, previous):
	if previous is _MISSING:
		sys.modules.pop(name, None)
	else:
		sys.modules[name] = previous


PACKAGE_DIR = Path(erp_dsc_local.__file__).resolve().parent


def raised(call):
	"""Run ``call`` and return the exception it raised, traceback intact.

	``assertRaises`` clears the traceback's frames, so it cannot be used for a frame walk.
	"""
	try:
		call()
	except BaseException as error:
		return error
	raise AssertionError("expected an exception")


def assert_no_sentinel_in_frames(test, error, sentinel):
	"""No erp_dsc_local frame on ``error``'s traceback holds ``sentinel`` in a local, or in an
	attribute of a local, as the frame was left.  Returns ``(module, function)`` per frame.

	Test fakes hold the PIN by design, so only the signer's own frames are walked.
	"""
	frames = []
	tb = error.__traceback__
	while tb is not None:
		frames.append(tb.tb_frame)
		tb = tb.tb_next
	return _walk_signer_frames(test, frames, sentinel)


def assert_no_sentinel_in_stack(test, sentinel):
	"""The same walk over the LIVE call stack of the caller, e.g. from inside a fake TSA step.

	Returns ``(module, function)`` per erp_dsc_local frame, innermost first.
	"""
	frames = []
	frame = sys._getframe(1)
	while frame is not None:
		frames.append(frame)
		frame = frame.f_back
	return _walk_signer_frames(test, frames, sentinel)


def stack_walk_step(test, seen):
	"""A ``FakeCms.timestamp_step`` that records ``hsm.pin`` and walks the live stack.

	A failed walk is kept in ``seen["failure"]`` for the test body to report: raised here it
	would leave endesive as a non-LocalSignerError, which sign_pdf turns into
	TOKEN_SIGNING_FAILED, hiding the message.
	"""

	def step(hsm):
		seen["pin"] = hsm.pin
		try:
			seen["walked"] = assert_no_sentinel_in_stack(test, SENTINEL_PIN)
		except AssertionError as failure:
			seen["failure"] = str(failure)

	return step


def _walk_signer_frames(test, frames, sentinel):
	walked = []
	for frame in frames:
		path = Path(frame.f_code.co_filename).resolve()
		if path.parent != PACKAGE_DIR:
			continue
		walked.append((path.stem, frame.f_code.co_name))
		for name, value in dict(frame.f_locals).items():
			held = [(name, value)]
			try:
				held += [(f"{name}.{attr}", item) for attr, item in vars(value).items()]
			except TypeError:
				pass
			for label, item in held:
				if isinstance(item, str) and sentinel in item:
					test.fail(f"{path.stem}.{frame.f_code.co_name}: {label} still holds the PIN")
	return walked


class TokenLoginTests(unittest.TestCase):
	def setUp(self):
		self.cms = FakeCms()
		install_fake_endesive(self, self.cms)

	def _select(self, lib):
		client = make_client(lib)
		selected, certificates = client.select(None)
		lib.log.clear()
		return client, selected, certificates

	def _sign(self, client, selected, certificates, guard=None, pin=SENTINEL_PIN, timestamp_url=None):
		guard = guard or FakeGuard(client.lib.log)
		return client.sign_pdf(b"%PDF", selected, certificates, {"reason": "x"}, pin, timestamp_url, login_guard=guard)

	def _names(self, lib):
		return [entry[0] for entry in lib.log]

	# --- selection and token state -------------------------------------------------------

	def test_select_returns_the_selected_cert_and_the_list(self):
		client = make_client(two_slot_lib())
		selected, certificates = client.select(None)
		self.assertEqual([selected], certificates)
		self.assertEqual(2, selected.slot_id)
		self.assertEqual("SER-2", selected.token_serial)

	def test_token_field_is_the_one_normaliser(self):
		self.assertEqual("SER-2", _token_field(SimpleNamespace(serialNumber="SER-2   "), "serialNumber"))
		self.assertEqual("AB", _token_field(SimpleNamespace(label="AB\\0junk"), "label"))

	def test_token_state_reads_flags_and_normalised_serial_without_login(self):
		lib = two_slot_lib()
		lib.tokens[2]["flags"] = PK.CKF_USER_PIN_FINAL_TRY
		client, selected, _ = self._select(lib)
		self.assertEqual((PK.CKF_USER_PIN_FINAL_TRY, "SER-2"), client.token_state(selected))
		self.assertEqual([], lib.logins)

	def test_token_state_refuses_a_swapped_token(self):
		lib = two_slot_lib()
		client, selected, _ = self._select(lib)
		lib.tokens[2]["serial"] = "OTHER"
		with self.assertRaises(TokenUnavailable):
			client.token_state(selected)

	# --- one login, on the chosen token --------------------------------------------------

	def test_exactly_one_login_on_the_slot_with_the_matching_serial(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		signed, metadata = self._sign(client, selected, certificates)
		self.assertEqual([(2, SENTINEL_PIN)], lib.logins)
		self.assertTrue(signed.startswith(b"%PDF|SIG-"))
		self.assertEqual(selected.metadata, metadata)

	def test_key_on_second_slot_pin_never_offered_to_the_first(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates)
		self.assertNotIn(1, [slot for slot, _ in lib.logins])
		self.assertNotIn(("openSession", 1), lib.log)

	def test_second_hsm_sign_call_reuses_the_session_without_a_second_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self.cms.sign_rounds = 2
		self._sign(client, selected, certificates)
		self.assertEqual(1, len(lib.logins))
		self.assertEqual(2, self._names(lib).count("sign"))

	def test_sign_does_not_re_enumerate_certificates(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates)
		self.assertNotIn(("findObjects", 2, PK.CKO_CERTIFICATE), lib.log)
		self.assertNotIn(("findObjects", 1, PK.CKO_CERTIFICATE), lib.log)

	def test_timestamp_url_is_passed_through(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates, timestamp_url="https://tsa.example/")
		self.assertEqual(["https://tsa.example/"], self.cms.timestamp_urls)

	# --- the timestamp request -----------------------------------------------------------

	def test_the_timestamp_request_is_bounded(self):
		self.assertEqual((5, 15), (TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS))
		for timestamp_url in ("https://tsa.example/", None):
			with self.subTest(timestamp_url=timestamp_url):
				self.cms.timestamp_options.clear()
				lib = two_slot_lib()
				client, selected, certificates = self._select(lib)
				self._sign(client, selected, certificates, timestamp_url=timestamp_url)
				self.assertEqual([{"timeout": (TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS)}], self.cms.timestamp_options)

	def test_a_failed_timestamp_is_signing_failed_after_logout_and_close(self):
		# A TSA timeout, a refused connection, a bad reply: endesive signs before it
		# timestamps, so the token is logged in when any of these is raised.
		for error_type in (FakeTsaTimeout, ConnectionError, ValueError):
			with self.subTest(error=error_type.__name__):
				lib = two_slot_lib()
				self.cms.timestamp_step = raise_in_timestamp(error_type)
				client, selected, certificates = self._select(lib)
				error = raised(lambda: self._sign(client, selected, certificates, timestamp_url="https://tsa.example/"))
				self.assertIsInstance(error, LocalSignerError)
				self.assertEqual(("TOKEN_SIGNING_FAILED", 502, SIGNING_FAILED), (error.code, error.status, error.message))
				self.assertIsNone(error.__cause__)
				self.assertIsNone(error.__context__)
				names = self._names(lib)
				self.assertIn("succeeded", names)  # C_Login was OK: counts as a success
				self.assertLess(names.index("sign"), names.index("logout"))
				self.assertEqual([("logout", 2), ("closeSession", 2)], lib.log[-2:])
				self.assertIsNone(self.cms.hsm.session)
				self.assertIsNone(self.cms.hsm.pin)
				self.assertEqual([error], chain(error))
				rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
				self.assertNotIn("Read timed out", rendered)
				self.assertNotIn(error_type.__name__, rendered)

	def _assert_unavailable_without_login(self, lib, client, selected, certificates):
		with self.assertRaises(TokenUnavailable) as ctx:
			self._sign(client, selected, certificates)
		self.assertEqual(TOKEN_NOT_AVAILABLE, ctx.exception.message)
		self.assertEqual([], lib.logins)
		self.assertNotIn("succeeded", self._names(lib))
		self.assertNotIn("failed", self._names(lib))

	def test_serial_mismatch_means_no_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		lib.tokens[2]["serial"] = "SWAPPED"
		self._assert_unavailable_without_login(lib, client, selected, certificates)

	def test_duplicate_serial_means_no_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		lib.tokens[1]["serial"] = "SER-2"
		self._assert_unavailable_without_login(lib, client, selected, certificates)

	def test_empty_serial_means_no_login(self):
		lib = two_slot_lib(slot2_serial="   ")
		client, selected, certificates = self._select(lib)
		self.assertEqual("", selected.token_serial)
		self._assert_unavailable_without_login(lib, client, selected, certificates)

	def test_token_moved_to_another_slot_means_no_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		lib.tokens[3] = lib.tokens.pop(2)
		self._assert_unavailable_without_login(lib, client, selected, certificates)

	# --- the login guard -----------------------------------------------------------------

	def test_guard_entered_before_login_and_succeeded_right_after(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates)
		names = self._names(lib)
		self.assertLess(names.index("guard_enter"), names.index("login"))
		self.assertEqual("succeeded", names[names.index("login") + 1])
		self.assertNotIn("failed", names)

	def test_each_wrong_pin_result_is_pin_incorrect_and_guard_failed_right_after(self):
		# Middleware differs: a wrong PIN may come back as any of the three (spec §7).
		for code in (PK.CKR_PIN_INCORRECT, PK.CKR_PIN_INVALID, PK.CKR_PIN_LEN_RANGE):
			with self.subTest(code=hex(code)):
				lib = two_slot_lib()
				lib.login_error = driver_error(code)
				client, selected, certificates = self._select(lib)
				with self.assertRaises(PinIncorrect) as ctx:
					self._sign(client, selected, certificates)
				names = self._names(lib)
				self.assertEqual("failed", names[names.index("login") + 1])
				self.assertEqual(1, names.count("failed"))
				self.assertNotIn("succeeded", names)
				self.assertNotIn("sign", names)
				self.assertEqual(("PIN_INCORRECT", 401), (ctx.exception.code, ctx.exception.status))

	def test_locked_token_is_pin_locked_and_not_counted_as_a_failure(self):
		lib = two_slot_lib()
		lib.login_error = driver_error(PK.CKR_PIN_LOCKED)
		client, selected, certificates = self._select(lib)
		with self.assertRaises(PinLocked) as ctx:
			self._sign(client, selected, certificates)
		names = self._names(lib)
		self.assertNotIn("failed", names)
		self.assertNotIn("succeeded", names)
		self.assertEqual(("PIN_LOCKED", 423), (ctx.exception.code, ctx.exception.status))

	def test_other_login_errors_are_signing_failed_and_not_counted(self):
		other = (
			PK.CKR_GENERAL_ERROR,
			PK.CKR_TOKEN_NOT_PRESENT,
			PK.CKR_SESSION_CLOSED,
			PK.CKR_SESSION_HANDLE_INVALID,
			PK.CKR_USER_ALREADY_LOGGED_IN,
			PK.CKR_DEVICE_REMOVED,
		)
		for code in other:
			with self.subTest(code=hex(code)):
				lib = two_slot_lib()
				lib.login_error = driver_error(code)
				client, selected, certificates = self._select(lib)
				with self.assertRaises(LocalSignerError) as ctx:
					self._sign(client, selected, certificates)
				self.assertEqual(("TOKEN_SIGNING_FAILED", 502), (ctx.exception.code, ctx.exception.status))
				self.assertEqual(SIGNING_FAILED, ctx.exception.message)
				self.assertEqual(1, len(lib.logins))
				self.assertNotIn("failed", self._names(lib))
				self.assertNotIn("succeeded", self._names(lib))

	def test_guard_refusal_stops_before_any_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		with self.assertRaises(PinRateLimited):
			self._sign(client, selected, certificates, guard=FakeGuard(lib.log, refuse=PinRateLimited()))
		self.assertEqual([], lib.logins)

	def test_flags_are_re_read_under_the_guard_and_checked_before_login(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		lib.tokens[2]["flags"] = 0x1234  # changed after token_state: only a fresh read sees it
		self._sign(client, selected, certificates)
		enter, check, login = (lib.log.index(entry) for entry in (("guard_enter",), ("check_flags", 0x1234), ("login", 2)))
		self.assertLess(enter, check)
		self.assertLess(check, login)
		self.assertIn(("getTokenInfo", 2), lib.log[enter:check])  # the read is under the guard
		self.assertEqual(1, self._names(lib).count("check_flags"))

	def test_a_flag_refusal_under_the_guard_means_no_login(self):
		for refusal in (PinLocked(), TokenBusy(state_changed=True)):
			with self.subTest(refusal=refusal.code):
				lib = two_slot_lib()
				client, selected, certificates = self._select(lib)
				with self.assertRaises(type(refusal)) as ctx:
					self._sign(client, selected, certificates, guard=FakeGuard(lib.log, refuse_flags=refusal))
				self.assertIs(refusal, ctx.exception)
				self.assertEqual([], lib.logins)
				self.assertNotIn(("openSession", 2), lib.log)
				self.assertNotIn("succeeded", self._names(lib))
				self.assertNotIn("failed", self._names(lib))
				self.assertIn("guard_exit", self._names(lib))

	# --- after the login -----------------------------------------------------------------

	def test_key_gone_after_login_is_key_not_available(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		lib.tokens[2]["keys"] = []  # the certificate is still listed, its key is not
		with self.assertRaises(TokenUnavailable) as ctx:
			self._sign(client, selected, certificates)
		self.assertEqual(("TOKEN_UNAVAILABLE", KEY_NOT_AVAILABLE), (ctx.exception.code, ctx.exception.message))
		self.assertIsNone(ctx.exception.__cause__)
		self.assertIsNone(ctx.exception.__context__)
		self.assertEqual(1, len(lib.logins))
		self.assertIn("succeeded", self._names(lib))  # C_Login was OK: counts as a success
		self.assertNotIn("sign", self._names(lib))
		self.assertIn(("logout", 2), lib.log)

	def test_a_second_hsm_sign_after_a_failed_login_makes_no_second_login(self):
		for code, first in ((PK.CKR_PIN_INCORRECT, "PIN_INCORRECT"), (PK.CKR_GENERAL_ERROR, "TOKEN_SIGNING_FAILED")):
			with self.subTest(first=first):
				lib = two_slot_lib()
				lib.login_error = driver_error(code)
				self.cms.retry_after_error = True
				client, selected, certificates = self._select(lib)
				with self.assertRaises(LocalSignerError) as ctx:
					self._sign(client, selected, certificates)
				self.assertEqual(first, self.cms.first_error.code)
				self.assertEqual(("TOKEN_SIGNING_FAILED", SIGNING_FAILED), (ctx.exception.code, ctx.exception.message))
				self.assertEqual(1, len(lib.logins), "the PIN must reach C_Login once per entry")
				self.assertEqual(1, self._names(lib).count("guard_enter"))

	# --- nothing echoes the PIN ----------------------------------------------------------

	def test_sentinel_pin_never_in_any_error_on_the_pin_path(self):
		cases = [
			("login_error", PK.CKR_PIN_INCORRECT, "PIN_INCORRECT"),
			("login_error", PK.CKR_PIN_INVALID, "PIN_INCORRECT"),
			("login_error", PK.CKR_PIN_LEN_RANGE, "PIN_INCORRECT"),
			("login_error", PK.CKR_PIN_LOCKED, "PIN_LOCKED"),
			("login_error", PK.CKR_GENERAL_ERROR, "TOKEN_SIGNING_FAILED"),
			("find_key_error", PK.CKR_FUNCTION_FAILED, "TOKEN_SIGNING_FAILED"),
			("sign_error", PK.CKR_FUNCTION_FAILED, "TOKEN_SIGNING_FAILED"),
		]
		for attribute, code, expected_code in cases:
			with self.subTest(attribute=attribute, code=hex(code)):
				lib = two_slot_lib()
				setattr(lib, attribute, driver_error(code))
				client, selected, certificates = self._select(lib)
				with self.assertRaises(LocalSignerError) as ctx:
					self._sign(client, selected, certificates)
				error = ctx.exception
				self.assertEqual(expected_code, error.code)
				self.assertEqual(SENTINEL_PIN, lib.received_pin)  # the hostile driver did see it
				self.assertIsNone(error.__cause__)
				self.assertIsNone(error.__context__)
				if expected_code == "TOKEN_SIGNING_FAILED":
					self.assertEqual(SIGNING_FAILED, error.message)
				for link in chain(error):
					for text in (str(link), repr(link), repr(link.args), repr(vars(link))):
						self.assertNotIn(SENTINEL_PIN, text)
						self.assertNotIn("driver says", text)
				rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
				self.assertNotIn(SENTINEL_PIN, rendered)

	# --- the private key never leaves the token -------------------------------------------

	def test_no_private_key_attribute_reads(self):
		lib = two_slot_lib()
		client = make_client(lib)
		selected, certificates = client.select(None)
		client.token_state(selected)
		self._sign(client, selected, certificates)
		self.assertTrue(lib.attribute_reads, "the listing must have read certificate attributes")
		read_handles = {handle for handle, _ in lib.attribute_reads}
		self.assertFalse(read_handles & lib.private_handles)
		for handle, attributes in lib.attribute_reads:
			if handle in lib.private_handles:
				self.assertNotIn(PK.CKA_VALUE, attributes)
				self.assertNotIn(PK.CKA_PRIVATE_EXPONENT, attributes)
		self.assertIn(("sign", 2, 21), lib.log)

	# --- PIN references ------------------------------------------------------------------

	def test_pin_cleared_after_sign(self):
		lib = two_slot_lib()
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates)
		self.assertEqual([(2, SENTINEL_PIN)], lib.logins)  # the PIN did reach C_Login
		self.assertIsNone(self.cms.pin_seen_by_hsm, "the adapter must drop the PIN once C_Login returns")
		self.assertIsNone(self.cms.hsm.pin)
		self.assertIsNone(self.cms.hsm.session)
		self.assertIn(("logout", 2), lib.log)

	def test_no_signer_frame_holds_the_pin_during_the_timestamp_request(self):
		seen = {}
		lib = two_slot_lib()
		self.cms.timestamp_step = stack_walk_step(self, seen)
		client, selected, certificates = self._select(lib)
		self._sign(client, selected, certificates, timestamp_url="https://tsa.example/")
		self.assertNotIn("failure", seen)
		self.assertEqual([(2, SENTINEL_PIN)], lib.logins)
		self.assertIsNone(seen["pin"], "the adapter still holds the PIN during the TSA request")
		self.assertIn(("token", "sign_pdf"), seen["walked"])

	def test_the_pin_is_dropped_when_c_login_fails(self):
		lib = two_slot_lib()
		lib.login_error = driver_error(PK.CKR_GENERAL_ERROR)
		adapter = _TokenHSM(make_client(lib), make_client(lib).select(None)[0], SENTINEL_PIN, FakeGuard(lib.log))
		with self.assertRaises(LocalSignerError):
			adapter.sign(KEY_ID, b"attrs", "sha256")
		self.assertEqual(1, len(lib.logins))
		self.assertIsNone(adapter.pin, "the adapter itself, not only sign_pdf's finally, drops the PIN")

	def test_pin_cleared_after_a_failed_sign(self):
		lib = two_slot_lib()
		lib.login_error = driver_error(PK.CKR_PIN_INCORRECT)
		client, selected, certificates = self._select(lib)
		with self.assertRaises(PinIncorrect):
			self._sign(client, selected, certificates)
		self.assertIsNone(self.cms.hsm.pin)
		self.assertNotIn(("logout", 2), lib.log)
		self.assertIn(("closeSession", 2), lib.log)

	def test_no_signer_frame_holds_the_pin_when_sign_pdf_raises(self):
		cases = [
			("login_error", PK.CKR_PIN_INCORRECT, "PIN_INCORRECT"),
			("login_error", PK.CKR_GENERAL_ERROR, "TOKEN_SIGNING_FAILED"),
			("find_key_error", PK.CKR_FUNCTION_FAILED, "TOKEN_SIGNING_FAILED"),
			("sign_error", PK.CKR_FUNCTION_FAILED, "TOKEN_SIGNING_FAILED"),
		]
		for attribute, code, expected_code in cases:
			with self.subTest(attribute=attribute, code=hex(code)):
				lib = two_slot_lib()
				setattr(lib, attribute, driver_error(code))
				client, selected, certificates = self._select(lib)
				error = raised(lambda: self._sign(client, selected, certificates))
				self.assertEqual(expected_code, error.code)
				walked = assert_no_sentinel_in_frames(self, error, SENTINEL_PIN)
				self.assertIn(("token", "sign_pdf"), walked)  # the frame that received the PIN
				self.assertIn(("token", "sign"), walked)

	def test_close_does_not_clear_the_pin(self):
		adapter = _TokenHSM(make_client(two_slot_lib()), None, SENTINEL_PIN, FakeGuard([]))
		adapter.close()
		self.assertEqual(SENTINEL_PIN, adapter.pin)


class TestTimestampBoundConstants(unittest.TestCase):
	NAMES = ("TSA_CONNECT_TIMEOUT_SECONDS", "TSA_TIMEOUT_SECONDS")

	def test_each_is_assigned_exactly_once_in_the_package_in_token_py(self):
		found = []
		for path in sorted(PACKAGE_DIR.glob("*.py")):
			for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
				targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
				for target in targets:
					if isinstance(target, ast.Name) and target.id in self.NAMES:
						found.append((path.name, target.id))
		self.assertEqual(sorted(("token.py", name) for name in self.NAMES), sorted(found))


class TestInstalledEndesiveHonoursTheBound(unittest.TestCase):
	"""The option name and shape token.py passes reach ``requests.post`` in the installed
	endesive.  Skipped where endesive is not installed; fails if an upgrade drops either."""

	def setUp(self):
		try:
			import requests
			from endesive import signer
			from endesive.pdf import cms
		except ImportError:
			self.skipTest("endesive is not installed")
		if not hasattr(signer, "timestamp") or not hasattr(cms, "sign"):
			self.skipTest("endesive is the test fake")
		self.requests, self.signer, self.cms = requests, signer, cms

	def test_cms_sign_takes_timestamp_req_options(self):
		self.assertIn("timestamp_req_options", inspect.signature(self.cms.sign).parameters)

	def test_the_options_become_the_requests_timeout(self):
		options = {"timeout": (TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS)}
		with mock.patch.object(self.signer.requests, "post", side_effect=self.requests.exceptions.ReadTimeout()) as post:
			with self.assertRaises(self.requests.exceptions.ReadTimeout):
				self.signer.timestamp(b"signature", "sha256", "https://tsa.invalid/", None, options)
		self.assertEqual(1, post.call_count)
		self.assertEqual((TSA_CONNECT_TIMEOUT_SECONDS, TSA_TIMEOUT_SECONDS), post.call_args.kwargs["timeout"])


if __name__ == "__main__":
	unittest.main()
