import os
import unittest
from types import SimpleNamespace

from _probe_inproc import use_in_process_probe
from erp_dsc_local import token_probe
from erp_dsc_local.errors import CertificatesHidden, LocalSignerError, TokenUnavailable
from erp_dsc_local.token import TOKEN_NOT_AVAILABLE, TokenClient, TokenDriverNotResponding
from test_token_login import _make_der

MARKER = "DRIVER-TEXT-MARKER-5e1f"


class _PyKCS11Error(Exception):
	def __init__(self, value, text=""):
		super().__init__(value, text)
		self.value, self.text = value, text

	def __str__(self):
		return f"{self.value:#x} {self.text}"


PK = SimpleNamespace(
	CKF_SERIAL_SESSION=4,
	CKA_CLASS=0,
	CKA_LABEL=3,
	CKA_VALUE=0x11,
	CKA_ID=0x102,
	CKO_CERTIFICATE=1,
	PyKCS11Error=_PyKCS11Error,
	CKR={
		0x05: "CKR_GENERAL_ERROR",
		0x06: "CKR_FUNCTION_FAILED",
		0x30: "CKR_DEVICE_ERROR",
		0xE1: "CKR_TOKEN_NOT_RECOGNIZED",
		"CKR_GENERAL_ERROR": 0x05,
	},
)


def ckr(code, text=MARKER):
	"""A driver error as PyKCS11 raises it; its text carries MARKER."""
	return PK.PyKCS11Error(code, text)


class FakeSession:
	def __init__(self, objects=(), find_error=None, attributes=None):
		self.objects, self.find_error = list(objects), find_error
		self.attributes = attributes or {}

	def findObjects(self, template):
		if self.find_error:
			raise self.find_error
		return self.objects

	def getAttributeValue(self, handle, attributes):
		value = self.attributes[handle]
		if isinstance(value, BaseException):
			raise value
		return value

	def closeSession(self):
		pass


class FakeLib:
	def __init__(self, slots, token_info_error=None, session=None, open_error=None, slot_error=None):
		self.slots, self.token_info_error = slots, token_info_error
		self.session, self.open_error, self.slot_error = session, open_error, slot_error

	def getSlotList(self, tokenPresent=True):
		if self.slot_error:
			raise self.slot_error
		return self.slots

	def getTokenInfo(self, slot):
		if self.token_info_error:
			raise self.token_info_error
		return SimpleNamespace(label="T", serialNumber="1", flags=0)

	def openSession(self, slot, flags):
		if self.open_error:
			raise self.open_error
		if self.session is None:
			raise RuntimeError("CKR_USER_NOT_LOGGED_IN")
		return self.session


def make_client(lib):
	client = TokenClient.__new__(TokenClient)
	client.lib = lib
	client.module = SimpleNamespace(label="libcastle.dylib", path=os.path.abspath("/Library/Castle/libcastle.dylib"))
	client.pk = PK
	return use_in_process_probe(client)


def chain(error):
	seen = []
	while error is not None and error not in seen:
		seen.append(error)
		error = error.__cause__ or error.__context__
	return seen


class CertificateErrorTests(unittest.TestCase):
	def test_no_token_is_not_reported_as_hidden_certificates(self):
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([])).certificates()
		self.assertIn("No compatible USB DSC token", str(ctx.exception))

	def test_driver_that_cannot_read_token_is_named_and_not_hidden_certificates(self):
		lib = FakeLib([1], token_info_error=ckr(0x05))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).certificates()
		message = str(ctx.exception)
		self.assertIn("libcastle.dylib", message)
		self.assertIn("CKR_GENERAL_ERROR", message)

	def test_session_that_opens_and_lists_nothing_is_certificates_hidden(self):
		with self.assertRaises(CertificatesHidden) as ctx:
			make_client(FakeLib([1], session=FakeSession(objects=[]))).certificates()
		error = ctx.exception
		self.assertEqual("TOKEN_CERTIFICATES_HIDDEN", error.code)
		self.assertEqual(409, error.status)
		self.assertNotIn("details", error.as_dict()["error"])

	def test_session_open_failure_is_token_unavailable_not_certificates_hidden(self):
		lib = FakeLib([1], open_error=ckr(0xE1))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)
		self.assertEqual("TOKEN_UNAVAILABLE", ctx.exception.code)
		self.assertIn("CKR_TOKEN_NOT_RECOGNIZED", str(ctx.exception))
		self.assertIn("libcastle.dylib", str(ctx.exception))

	def test_find_objects_failure_is_token_unavailable_not_certificates_hidden(self):
		session = FakeSession(find_error=ckr(0x06))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([1], session=session)).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)
		self.assertIn("CKR_FUNCTION_FAILED", str(ctx.exception))

	def test_one_failing_slot_beside_an_empty_one_is_not_certificates_hidden(self):
		class MixedLib(FakeLib):
			def openSession(self, slot, flags):
				if slot == 1:
					raise ckr(0x30)
				return FakeSession(objects=[])

		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(MixedLib([1, 2])).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)


class DriverTextTests(unittest.TestCase):
	"""The child sends a return-code NUMBER, never exception text; the daemon names it."""

	def assert_no_driver_text(self, error):
		for link in chain(error):
			self.assertNotIn(MARKER, str(link))
			self.assertNotIn(MARKER, repr(link.args))
		self.assertNotIn(MARKER, str(error.as_dict()))

	def stages(self, make_error):
		session_attr_error = FakeSession(objects=[7], attributes={7: make_error()})
		return {
			"slot_list": FakeLib([1], slot_error=make_error()),
			"token_info": FakeLib([1], token_info_error=make_error()),
			"open_session": FakeLib([1], open_error=make_error()),
			"find_objects": FakeLib([1], session=FakeSession(find_error=make_error())),
			"attribute_read": FakeLib([1], session=session_attr_error),
		}

	def test_plain_exception_text_never_reaches_the_message(self):
		for stage, lib in self.stages(lambda: RuntimeError(MARKER)).items():
			with self.subTest(stage=stage):
				with self.assertRaises(TokenUnavailable) as ctx:
					make_client(lib).certificates()
				self.assert_no_driver_text(ctx.exception)
				self.assertIn("(driver error)", str(ctx.exception))

	def test_pykcs11_error_is_named_by_its_code_not_its_text(self):
		for stage, lib in self.stages(lambda: ckr(0x05)).items():
			with self.subTest(stage=stage):
				with self.assertRaises(TokenUnavailable) as ctx:
					make_client(lib).certificates()
				self.assert_no_driver_text(ctx.exception)
				self.assertIn("(CKR_GENERAL_ERROR)", str(ctx.exception))

	def test_unknown_return_code_is_not_named(self):
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([1], token_info_error=ckr(0x7777))).certificates()
		self.assertIn("(driver error)", str(ctx.exception))
		self.assertNotIn("7777", str(ctx.exception))

	def test_load_failure_is_fixed_text(self):
		def load(path):
			raise PK.PyKCS11Error(-1, f"{MARKER} {path}")

		client = make_client(FakeLib([1]))
		client._probe = _probe_with_load(client, load)
		with self.assertRaises(TokenUnavailable) as ctx:
			client.certificates()
		self.assertEqual("Unable to load the selected token middleware (libcastle.dylib).", ctx.exception.message)
		self.assert_no_driver_text(ctx.exception)
		self.assertNotIn("/Library/Castle", str(ctx.exception))

	def test_missing_pykcs11_in_the_child_is_dependency_missing(self):
		def load(path):
			raise token_probe.DependencyMissing()

		client = make_client(FakeLib([1]))
		client._probe = _probe_with_load(client, load)
		with self.assertRaises(LocalSignerError) as ctx:
			client.certificates()
		self.assertEqual(("DEPENDENCY_MISSING", 503), (ctx.exception.code, ctx.exception.status))


def _probe_with_load(client, load):
	from _probe_inproc import in_process_transport
	from erp_dsc_local import token

	return lambda op: token.run_probe(client.module.path, op, transport=in_process_transport(load))


class PartialSlotTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.der = _make_der()

	def test_certificate_read_before_a_failing_attribute_read_is_kept(self):
		session = FakeSession(
			objects=[7, 8],
			attributes={7: (self.der, b"\x01", "sign"), 8: ckr(0x05)},
		)
		certificates = make_client(FakeLib([1], session=session)).certificates()
		self.assertEqual([(1, b"\x01", "sign")], [(c.slot_id, c.key_id, c.label) for c in certificates])
		self.assertEqual(self.der, certificates[0].der)

	def test_objects_without_cka_id_are_token_unavailable_not_hidden(self):
		session = FakeSession(objects=[7], attributes={7: (self.der, None, "sign")})
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([1], session=session)).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)
		self.assertIn("its certificates carry no CKA_ID", str(ctx.exception))

	def test_unparseable_certificate_uses_fixed_text(self):
		session = FakeSession(objects=[7], attributes={7: (b"\x30\x03" + MARKER.encode(), b"\x01", "sign")})
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([1], session=session)).certificates()
		self.assertIn("The token returned an invalid X.509 certificate.", str(ctx.exception))
		self.assertNotIn(MARKER, str(ctx.exception))


class TokenStateTests(unittest.TestCase):
	def selected(self, slot=2, serial="SER"):
		return SimpleNamespace(slot_id=slot, token_serial=serial)

	def lib(self, tokens):
		class StateLib(FakeLib):
			def getTokenInfo(self, slot):
				value = tokens[slot]
				if isinstance(value, BaseException):
					raise value
				return value

		return StateLib(sorted(tokens))

	def test_flags_and_normalised_serial_of_the_only_holder(self):
		lib = self.lib({1: SimpleNamespace(serialNumber="OTHER", flags=1), 2: SimpleNamespace(serialNumber="SER   ", flags=0x20000)})
		self.assertEqual((0x20000, "SER"), make_client(lib).token_state(self.selected()))

	def test_same_serial_on_two_slots_is_refused(self):
		lib = self.lib({1: SimpleNamespace(serialNumber="SER", flags=0), 2: SimpleNamespace(serialNumber="SER", flags=0)})
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).token_state(self.selected())
		self.assertEqual(TOKEN_NOT_AVAILABLE, ctx.exception.message)

	def test_unreadable_flags_on_the_holder_are_refused(self):
		lib = self.lib({2: SimpleNamespace(serialNumber="SER", flags="not-an-int")})
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).token_state(self.selected())
		self.assertEqual(TOKEN_NOT_AVAILABLE, ctx.exception.message)

	def test_unreadable_other_slot_is_skipped(self):
		lib = self.lib({1: ckr(0x05), 2: SimpleNamespace(serialNumber="SER", flags=3)})
		self.assertEqual((3, "SER"), make_client(lib).token_state(self.selected()))

	def test_slot_list_failure_is_token_not_available(self):
		lib = FakeLib([2], slot_error=ckr(0x05))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).token_state(self.selected())
		self.assertEqual(TOKEN_NOT_AVAILABLE, ctx.exception.message)
		self.assertNotIsInstance(ctx.exception, TokenDriverNotResponding)

	def test_empty_selected_serial_is_refused_without_a_probe(self):
		client = make_client(FakeLib([2]))
		calls = []
		client._probe = lambda op: calls.append(op)
		with self.assertRaises(TokenUnavailable):
			client.token_state(self.selected(serial=""))
		self.assertEqual([], calls)


if __name__ == "__main__":
	unittest.main()
