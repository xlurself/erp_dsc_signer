import unittest
from types import SimpleNamespace

from erp_dsc_local.errors import CertificatesHidden, TokenUnavailable
from erp_dsc_local.token import TokenClient


class FakeSession:
	def __init__(self, objects=(), find_error=None):
		self.objects, self.find_error = list(objects), find_error

	def findObjects(self, template):
		if self.find_error:
			raise self.find_error
		return self.objects

	def closeSession(self):
		pass


class FakeLib:
	def __init__(self, slots, token_info_error=None, session=None, open_error=None):
		self.slots, self.token_info_error = slots, token_info_error
		self.session, self.open_error = session, open_error

	def getSlotList(self, tokenPresent=True):
		return self.slots

	def getTokenInfo(self, slot):
		if self.token_info_error:
			raise self.token_info_error
		return SimpleNamespace(label="T", serialNumber="1")

	def openSession(self, slot, flags):
		if self.open_error:
			raise self.open_error
		if self.session is None:
			raise RuntimeError("CKR_USER_NOT_LOGGED_IN")
		return self.session


def make_client(lib):
	client = TokenClient.__new__(TokenClient)
	client.lib = lib
	client.module = SimpleNamespace(label="libcastle.dylib")
	client.pk = SimpleNamespace(CKF_SERIAL_SESSION=4, CKA_CLASS=0, CKO_CERTIFICATE=1)
	return client


class CertificateErrorTests(unittest.TestCase):
	def test_no_token_is_not_reported_as_hidden_certificates(self):
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([])).certificates()
		self.assertIn("No compatible USB DSC token", str(ctx.exception))

	def test_driver_that_cannot_read_token_is_named_and_not_hidden_certificates(self):
		lib = FakeLib([1], token_info_error=RuntimeError("CKR_GENERAL_ERROR"))
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
		lib = FakeLib([1], open_error=RuntimeError("CKR_TOKEN_NOT_RECOGNIZED"))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(lib).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)
		self.assertEqual("TOKEN_UNAVAILABLE", ctx.exception.code)
		self.assertIn("CKR_TOKEN_NOT_RECOGNIZED", str(ctx.exception))
		self.assertIn("libcastle.dylib", str(ctx.exception))

	def test_find_objects_failure_is_token_unavailable_not_certificates_hidden(self):
		session = FakeSession(find_error=RuntimeError("CKR_FUNCTION_FAILED"))
		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(FakeLib([1], session=session)).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)
		self.assertIn("CKR_FUNCTION_FAILED", str(ctx.exception))

	def test_one_failing_slot_beside_an_empty_one_is_not_certificates_hidden(self):
		class MixedLib(FakeLib):
			def openSession(self, slot, flags):
				if slot == 1:
					raise RuntimeError("CKR_DEVICE_ERROR")
				return FakeSession(objects=[])

		with self.assertRaises(TokenUnavailable) as ctx:
			make_client(MixedLib([1, 2])).certificates()
		self.assertNotIsInstance(ctx.exception, CertificatesHidden)


if __name__ == "__main__":
	unittest.main()
