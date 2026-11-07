"""The token signs SHA-256 only, whatever digest endesive hands the adapter (spec 001 §7).

endesive 2.19.3 does not keep the "sha256" ``sign_pdf`` passes: when the PDF's catalog has
``/Perms /DocMDP /Reference [ << /DigestMethod /X >> ]`` it signs with THAT digest
(cms.py ~715-727), and ``_TokenHSM.sign`` used to build ``CKM_<X>_RSA_PKCS`` from it.  Real
PyKCS11 defines CKM_MD5_RSA_PKCS and CKM_SHA1_RSA_PKCS, so a paired site could make the
token sign with MD5 or SHA-1.  The fake ``PK`` defines only CKM_SHA256_RSA_PKCS, which hid
this; these tests use every CKM_* constant of the INSTALLED PyKCS11.  PyKCS11 is imported,
never loaded: no driver is touched.
"""

import io
import json
import unittest
from unittest import mock

import PyKCS11 as REAL_PYKCS11

import test_token_login as fakes
from test_endesive_integration import RealEndesiveCase, _minimal_pdf, _server_signature_meta
from test_token_login import PK, SENTINEL_PIN, FakeCms, FakeGuard, chain, install_fake_endesive, make_client, two_slot_lib

from erp_dsc_local.errors import TokenSigningFailed
from erp_dsc_local.token import SIGNING_FAILED_LOG


class RealMechanismsPK(PK):
	"""The PyKCS11 stand-in carrying every CKM_* constant of the installed PyKCS11."""


for _name in dir(REAL_PYKCS11):
	if _name.startswith("CKM_") and type(getattr(REAL_PYKCS11, _name)) is int:
		setattr(RealMechanismsPK, _name, getattr(REAL_PYKCS11, _name))

SHA256_MECHANISM = PK.Mechanism(REAL_PYKCS11.CKM_SHA256_RSA_PKCS, None)
C_SIGN_REFUSED = {"stage": "c_sign", "error": "other", "ckr": None}


class _LiarStr(str):
	def __eq__(self, other):
		return True

	def __hash__(self):
		return hash("sha256")


# Every digest name endesive could pass that is not exactly "sha256" (endesive lowercases
# the PDF's /DigestMethod, so a real PDF yields e.g. "md5"; the case variants come from
# no real path but must not be mapped either).
REFUSED_ALGORITHMS = (
	"md5",
	"sha1",
	"sha224",
	"sha384",
	"sha512",
	"MD5",
	"SHA1",
	"SHA256",
	"Sha256",
	" sha256",
	"sha256 ",
	"sha-256",
	"",
	None,
	b"sha256",
	256,
	_LiarStr("md5"),
)


def setUpModule():
	if fakes.DER is None:  # test_token_login builds its certificate in its own setUpModule
		fakes.DER = fakes._make_der()


class TestTheInstalledPyKCS11(unittest.TestCase):
	def test_it_defines_the_weak_mechanisms_the_old_lookup_reached(self):
		for name in ("CKM_MD5_RSA_PKCS", "CKM_SHA1_RSA_PKCS", "CKM_SHA512_RSA_PKCS", "CKM_SHA256_RSA_PKCS"):
			with self.subTest(name=name):
				self.assertIs(int, type(getattr(REAL_PYKCS11, name)))
				self.assertEqual(getattr(REAL_PYKCS11, name), getattr(RealMechanismsPK, name))


class TestTheAdapterSignsSha256Only(unittest.TestCase):
	def setUp(self):
		self.cms = FakeCms()
		install_fake_endesive(self, self.cms)
		self.stderr = io.StringIO()
		patcher = mock.patch("sys.stderr", self.stderr)
		patcher.start()
		self.addCleanup(patcher.stop)

	def sign(self, algorithm, pk=RealMechanismsPK):
		self.lib = two_slot_lib()
		client = make_client(self.lib)
		client.pk = pk
		selected, certificates = client.select(None)
		self.cms.algorithm = algorithm
		self.log_start = len(self.lib.log)
		return client.sign_pdf(b"%PDF", selected, certificates, {"reason": "x"}, SENTINEL_PIN, None, login_guard=FakeGuard(self.lib.log))

	def assert_refused_before_c_login(self, algorithm, pk=RealMechanismsPK):
		with self.assertRaises(TokenSigningFailed) as ctx:
			self.sign(algorithm, pk)
		error = ctx.exception
		self.assertEqual(C_SIGN_REFUSED, error.details)
		self.assertEqual([error], chain(error), "raised `from None`, outside any except block")
		self.assertEqual([], self.lib.logins, "no C_Login: the PIN is never sent")
		self.assertEqual([], self.lib.mechanisms, "no C_Sign")
		operations = [entry[0] for entry in self.lib.log[self.log_start :]]
		self.assertNotIn("guard_enter", operations)
		self.assertNotIn("sign", operations)
		self.assertIsNone(self.cms.hsm.pin, "the adapter dropped the PIN")
		log = SIGNING_FAILED_LOG.format(stage="c_sign", error="other", ckr="none") + "\n"
		self.assertEqual(log, self.stderr.getvalue())
		for text in (str(error), repr(error), json.dumps(error.as_dict()), self.stderr.getvalue()):
			self.assertNotIn(SENTINEL_PIN, text)
			if isinstance(algorithm, str) and algorithm.strip():
				self.assertNotIn(algorithm.strip(), text.replace("TOKEN_SIGNING_FAILED", ""), "the digest name is not echoed")
		self.stderr.seek(0)
		self.stderr.truncate()

	def test_any_digest_but_exactly_sha256_is_refused_before_c_login(self):
		for algorithm in REFUSED_ALGORITHMS:
			with self.subTest(algorithm=algorithm):
				self.assert_refused_before_c_login(algorithm)

	def test_sha256_logs_in_once_and_signs_with_ckm_sha256_rsa_pkcs(self):
		signed, _metadata = self.sign("sha256")
		self.assertEqual(b"%PDF|SIG-attrs", signed)
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		self.assertEqual([SHA256_MECHANISM], self.lib.mechanisms)

	def test_two_c_signs_reuse_the_one_login_and_both_use_sha256(self):
		self.cms.sign_rounds = 2
		self.sign("sha256")
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		self.assertEqual([SHA256_MECHANISM, SHA256_MECHANISM], self.lib.mechanisms)

	def test_a_module_without_ckm_sha256_rsa_pkcs_is_refused_before_c_login(self):
		class NoSha256(RealMechanismsPK):
			CKM_SHA256_RSA_PKCS = None

		self.assert_refused_before_c_login("sha256", pk=NoSha256)


def _pdf_naming_digest(method: bytes) -> bytes:
	return _minimal_pdf(
		b"<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP << /Reference [ << /DigestMethod /"
		+ method
		+ b" >> ] >> >> >>"
	)


class TestRealEndesiveWithAPdfThatNamesItsDigest(RealEndesiveCase):
	pk = RealMechanismsPK

	def test_a_weak_or_other_digest_method_is_refused_before_c_login(self):
		for method in (b"MD5", b"SHA1", b"SHA384", b"SHA512"):
			with self.subTest(method=method):
				self.lib.logins.clear()
				self.lib.mechanisms.clear()
				error = self._failure(_server_signature_meta(), pdf=_pdf_naming_digest(method))
				self.assertEqual(C_SIGN_REFUSED, error.details)
				self.assertEqual([], self.lib.logins, "no C_Login: the PIN is never sent")
				self.assertEqual([], self.lib.mechanisms, "no C_Sign")
				self.assertEqual([], self._operations())
				self.stderr.seek(0)
				self.stderr.truncate()

	def test_a_sha256_digest_method_still_signs_once_with_sha256(self):
		self._sign(_server_signature_meta(), pdf=_pdf_naming_digest(b"SHA256"))
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		self.assertEqual([SHA256_MECHANISM], self.lib.mechanisms)
		self.assertEqual(["login", "sign", "logout"], self._operations())

	def test_the_server_shaped_request_signs_with_sha256_and_verifies(self):
		signed, metadata = self._sign(_server_signature_meta())
		self._assert_verifies_on_server(signed, metadata)
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		self.assertEqual([SHA256_MECHANISM], self.lib.mechanisms)


if __name__ == "__main__":
	unittest.main()
