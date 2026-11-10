"""/v1/certificates across every installed PKCS#11 module, and only signing certificates.

The product is open: with provider "auto" the user never picks a driver.  The listing asks
EVERY available module (each through its own killable child, concurrently, under one cap),
skips a module with no token or a hung driver, tags each certificate with the module the
REGISTRY resolved, and offers only end-entity signing certificates.  Signing stays explicit:
``/v1/sign`` without a ``module_id`` still needs one when several modules match.

No real driver and no real token: the registry is built for a made-up system with made-up
module paths, and ``TokenClient`` is replaced by a fake.  Certificates are generated here
("Test Signer", "Test Company Pvt Ltd"), never personal data.
"""

from __future__ import annotations

import base64
import datetime
import functools
import hashlib
import threading
import time
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import test_service_http as http_tests
from erp_dsc_local import service as service_module
from erp_dsc_local.certificates import TokenCertificate, is_signing_certificate, parse_token_certificate
from erp_dsc_local.config import CustomModule, SignerConfig
from erp_dsc_local.errors import CertificatesHidden, LocalSignerError, MiddlewareUnavailable, TokenUnavailable
from erp_dsc_local.providers import ProviderRegistry
from erp_dsc_local.service import SignerService
from erp_dsc_local.token import TokenDriverNotResponding
from test_signature_meta import server_meta


WD = CustomModule("test-wd", "watchdata", "/opt/erp-dsc-test/libwatchdata-test.dylib", "Test WatchData module")
INNAIT = CustomModule("test-innait", "generic_pkcs11", "/opt/erp-dsc-test/libinnait-test.dylib", "Test InnaitKey module")
WD2 = CustomModule("test-wd-2", "watchdata", "/opt/erp-dsc-test/libwatchdata-2-test.dylib", "Second WatchData module")
MISSING = CustomModule("test-missing", "generic_pkcs11", "/opt/erp-dsc-test/not-installed.dylib", "Not installed")
NO_TOKEN = "No compatible USB DSC token is connected."
DRIVER_TEXT = "CKR_GENERAL_ERROR /opt/erp-dsc-test/libinnait-test.dylib vendor said: slot 0 fell over"
START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


@functools.lru_cache(maxsize=None)
def _key(name):
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn, org=None):
	attributes = [x509.NameAttribute(NameOID.COUNTRY_NAME, "IN")]
	if org is not None:
		attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
	attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
	return x509.Name(attributes)


def _usage(*, signing=True, non_repudiation=True, key_encipherment=False, cert_sign=False):
	return x509.KeyUsage(
		digital_signature=signing,
		content_commitment=non_repudiation,
		key_encipherment=key_encipherment,
		data_encipherment=False,
		key_agreement=False,
		key_cert_sign=cert_sign,
		crl_sign=cert_sign,
		encipher_only=False,
		decipher_only=False,
	)


@functools.lru_cache(maxsize=None)
def _der(cn, *, org="Test Company Pvt Ltd", issuer="Test Sub-CA", ca=None, usage="sign", self_issued=False):
	"""A generated certificate.  ``usage``: sign | nr | ds | encrypt | ca | none."""
	subject = _name(cn, org)
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(subject if self_issued else _name(issuer))
		.public_key(_key(cn).public_key())
		.serial_number(int(hashlib.sha256(cn.encode()).hexdigest()[:15], 16))
		.not_valid_before(START)
		.not_valid_after(START + datetime.timedelta(days=1400))
	)
	if ca is not None:
		builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
	keyusage = {
		"sign": _usage(),
		"nr": _usage(signing=False),
		"ds": _usage(non_repudiation=False),
		"encrypt": _usage(signing=False, non_repudiation=False, key_encipherment=True),
		"ca": _usage(signing=False, non_repudiation=False, cert_sign=True),
	}.get(usage)
	if keyusage is not None:
		builder = builder.add_extension(keyusage, critical=True)
	return builder.sign(_key("issuer"), hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _token_cert(der, *, token_label="Test Token", token_serial="TEST-TOKEN-0001", slot=1, metadata_extra=None):
	parsed = parse_token_certificate(der, b"\x01", "label", slot, token_label, token_serial)
	if metadata_extra:
		# What a driver-influenced value would look like if it ever reached metadata.
		parsed = TokenCertificate(
			parsed.der, parsed.key_id, parsed.label, parsed.slot_id, parsed.token_label, parsed.token_serial,
			{**parsed.metadata, **metadata_extra}, parsed.crypto_certificate,
		)
	return parsed


def _signing(cn="Test Signer", **kwargs):
	return _token_cert(_der(cn, ca=False), **kwargs)


def _real_token_five(token_label="Test Token", token_serial="TEST-TOKEN-0001"):
	"""The InnaitKey shape: signing leaf, encryption leaf, sub-CA, CA, root."""
	kwargs = {"token_label": token_label, "token_serial": token_serial}
	return [
		_token_cert(_der("Test Signer", ca=False, usage="sign"), **kwargs),
		_token_cert(_der("Test Signer Encryption", ca=False, usage="encrypt"), **kwargs),
		_token_cert(_der("Test Sub-CA", org="Test CA Pvt Ltd", issuer="Test CA", ca=True, usage="ca"), **kwargs),
		_token_cert(_der("Test CA", org="Test CA Pvt Ltd", issuer="Test Root", ca=True, usage="ca"), **kwargs),
		_token_cert(_der("Test Root", org="Test CA Pvt Ltd", ca=True, usage="ca", self_issued=True), **kwargs),
	]


class FakeClients:
	"""Replaces ``TokenClient``: behaviour per registry module id, every construction recorded."""

	def __init__(self, behaviours):
		self.behaviours = behaviours
		self.constructed = []
		self.release = threading.Event()  # set at cleanup so no hung fake outlives a test

	def __call__(self, module):
		self.constructed.append(module.id)
		return _FakeClient(self, module)


class _FakeClient:
	def __init__(self, owner, module):
		self.owner = owner
		self.module = module

	def certificates(self):
		behaviour = self.owner.behaviours[self.module.id]
		if behaviour == "hang":
			self.owner.release.wait(30)
			raise TokenDriverNotResponding()
		if isinstance(behaviour, BaseException):
			raise behaviour
		return list(behaviour)

	def select(self, selector):
		raise LocalSignerError("TEST_STOP", f"select reached on {self.module.id}")


class ListingTestCase(unittest.TestCase):
	modules = (WD, INNAIT)
	installed = frozenset({WD.path, INNAIT.path, WD2.path})

	def setUp(self):
		self.config = SignerConfig(custom_modules=self.modules)
		self.service = SignerService(self.config, trust_store=mock.Mock(), dialog_host=mock.Mock())
		self.service.providers = ProviderRegistry(self.config, system="ERPDSCTestOS", path_exists=self.installed.__contains__)

	def use(self, behaviours):
		fake = FakeClients(behaviours)
		patcher = mock.patch.object(service_module, "TokenClient", fake)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.addCleanup(fake.release.set)
		return fake

	def listing(self, provider="auto", module_id=None):
		return self.service.list_certificates(provider, module_id)


class TestAggregationAcrossModules(ListingTestCase):
	def test_two_modules_with_tokens_list_both_tagged_by_the_registry(self):
		self.use({
			WD.id: [_signing("Test Signer WD", token_label="WD Token", token_serial="WD-0001", metadata_extra={"module_id": "driver-said", "provider": "driver-said"})],
			INNAIT.id: [_signing("Test Signer Innait", token_label="Innait Token", token_serial="IN-0001")],
		})
		listed = self.listing()
		self.assertEqual(
			[("Test Signer WD", WD.id, "watchdata"), ("Test Signer Innait", INNAIT.id, "generic_pkcs11")],
			[(item["common_name"], item["module_id"], item["provider"]) for item in listed],
		)

	def test_hung_module_is_skipped_and_the_other_is_returned_within_the_cap(self):
		self.use({WD.id: "hang", INNAIT.id: [_signing("Test Signer Innait")]})
		with mock.patch.object(service_module, "CERTIFICATE_LISTING_SECONDS", 0.5):
			started = time.monotonic()
			listed = self.listing()
			elapsed = time.monotonic() - started
		self.assertLess(elapsed, 3.0)
		self.assertEqual([INNAIT.id], [item["module_id"] for item in listed])

	def test_modules_are_read_concurrently(self):
		slow = [_signing("Test Signer")]
		barrier = threading.Barrier(2, timeout=5)

		class Meeting(list):
			def __iter__(self):
				barrier.wait()  # both reads must be in flight at once, or this times out
				return super().__iter__()

		self.use({WD.id: Meeting(slow), INNAIT.id: Meeting([_signing("Test Signer 2", token_serial="IN-2")])})
		self.assertEqual(2, len(self.listing()))

	def test_no_module_has_a_token_gives_the_fixed_error_without_driver_text(self):
		self.use({WD.id: TokenUnavailable(DRIVER_TEXT), INNAIT.id: TokenDriverNotResponding()})
		with self.assertRaises(TokenUnavailable) as caught:
			self.listing()
		self.assertEqual("TOKEN_UNAVAILABLE", caught.exception.code)
		self.assertEqual(NO_TOKEN, caught.exception.message)
		self.assertEqual({"ok": False, "error": {"code": "TOKEN_UNAVAILABLE", "message": NO_TOKEN}}, caught.exception.as_dict())

	def test_unexpected_failure_in_one_module_is_skipped(self):
		self.use({WD.id: RuntimeError(DRIVER_TEXT), INNAIT.id: [_signing()]})
		self.assertEqual([INNAIT.id], [item["module_id"] for item in self.listing()])

	def test_hidden_certificates_on_one_and_no_token_on_the_other_is_hidden(self):
		self.use({WD.id: TokenUnavailable(DRIVER_TEXT), INNAIT.id: CertificatesHidden()})
		with self.assertRaises(CertificatesHidden):
			self.listing()

	def test_a_module_whose_certificates_are_all_filtered_answers_an_empty_list(self):
		self.use({WD.id: TokenUnavailable(), INNAIT.id: [_token_cert(_der("Test Signer Encryption", ca=False, usage="encrypt"))]})
		self.assertEqual([], self.listing())

	def test_same_certificate_through_two_modules_is_listed_once_from_the_first_module(self):
		same = _signing()
		self.use({WD.id: [same], INNAIT.id: [same]})
		self.assertEqual([WD.id], [item["module_id"] for item in self.listing()])

	def test_same_certificate_on_two_tokens_is_listed_twice(self):
		self.use({WD.id: [_signing(token_serial="WD-0001")], INNAIT.id: [_signing(token_serial="IN-0001")]})
		self.assertEqual(["WD-0001", "IN-0001"], [item["token_serial"] for item in self.listing()])

	def test_not_installed_module_is_never_asked(self):
		self.modules = (WD, MISSING, INNAIT)
		self.setUp()
		fake = self.use({WD.id: [_signing()], INNAIT.id: TokenUnavailable(), MISSING.id: AssertionError("asked")})
		self.listing()
		self.assertEqual({WD.id, INNAIT.id}, set(fake.constructed))


class TestExplicitSelectionUnchanged(ListingTestCase):
	modules = (WD, INNAIT, WD2)

	def test_explicit_module_id_lists_only_that_module_tagged(self):
		fake = self.use({WD.id: AssertionError("asked"), INNAIT.id: [_signing()], WD2.id: AssertionError("asked")})
		listed = self.listing("auto", INNAIT.id)
		self.assertEqual([INNAIT.id], fake.constructed)
		self.assertEqual([(INNAIT.id, "generic_pkcs11")], [(item["module_id"], item["provider"]) for item in listed])

	def test_single_module_errors_propagate_as_before(self):
		self.use({INNAIT.id: TokenUnavailable("Unable to load the selected token middleware (Test InnaitKey module).")})
		with self.assertRaises(TokenUnavailable) as caught:
			self.listing("generic_pkcs11", None)
		self.assertEqual("Unable to load the selected token middleware (Test InnaitKey module).", caught.exception.message)

	def test_provider_with_several_modules_aggregates_only_that_provider(self):
		fake = self.use({WD.id: [_signing("Test Signer A", token_serial="A")], WD2.id: [_signing("Test Signer B", token_serial="B")], INNAIT.id: AssertionError("asked")})
		listed = self.listing("watchdata", None)
		self.assertEqual({WD.id, WD2.id}, set(fake.constructed))
		self.assertEqual([WD.id, WD2.id], [item["module_id"] for item in listed])

	def test_module_id_from_the_request_is_an_id_never_a_path(self):
		fake = self.use({})
		for module_id in (INNAIT.path, "/usr/lib/opensc-pkcs11.so", "../libevil.so", "test-unknown"):
			with self.subTest(module_id=module_id), self.assertRaises(MiddlewareUnavailable):
				self.listing("auto", module_id)
		self.assertEqual([], fake.constructed)

	def test_module_id_of_another_provider_is_refused(self):
		self.use({})
		with self.assertRaises(MiddlewareUnavailable):
			self.listing("watchdata", INNAIT.id)


class TestOnlySigningCertificatesAreOffered(ListingTestCase):
	def test_the_five_object_token_offers_only_the_signing_leaf(self):
		self.use({WD.id: _real_token_five(), INNAIT.id: TokenUnavailable()})
		self.assertEqual(["Test Signer"], [item["common_name"] for item in self.listing()])

	def test_single_module_listing_is_filtered_too(self):
		self.use({INNAIT.id: _real_token_five()})
		self.assertEqual(["Test Signer"], [item["common_name"] for item in self.listing("auto", INNAIT.id)])

	def test_predicate(self):
		cases = {
			"digitalSignature + nonRepudiation leaf": (_der("Test Signer", ca=False), True),
			"nonRepudiation only": (_der("Test Signer NR", ca=False, usage="nr"), True),
			"digitalSignature only": (_der("Test Signer DS", ca=False, usage="ds"), True),
			"leaf without BasicConstraints": (_der("Test Signer No BC"), True),
			"keyEncipherment only": (_der("Test Signer Encryption", ca=False, usage="encrypt"), False),
			# R2 MEDIUM: absent KeyUsage = unrestricted, as on the server (was False before).
			"no KeyUsage at all": (_der("Test Signer No KU", ca=False, usage="none"), True),
			"no KeyUsage, no BasicConstraints": (_der("Test Signer Bare", usage="none"), True),
			"no KeyUsage but a CA": (_der("Test CA No KU", ca=True, usage="none"), False),
			"no KeyUsage but self-issued": (_der("Test Self No KU", ca=False, usage="none", self_issued=True), False),
			"CA with signing usage": (_der("Test Signing CA", ca=True, usage="sign"), False),
			"sub-CA": (_der("Test Sub-CA", issuer="Test CA", ca=True, usage="ca"), False),
			"self-issued root": (_der("Test Root", ca=True, usage="ca", self_issued=True), False),
			"self-issued leaf-looking": (_der("Test Self Signer", ca=False, self_issued=True), False),
		}
		for label, (der, expected) in cases.items():
			with self.subTest(label):
				self.assertIs(expected, is_signing_certificate(x509.load_der_x509_certificate(der)))

	def test_a_leaf_without_key_usage_is_offered_and_an_encryption_leaf_is_not(self):
		# R2 MEDIUM: the server accepts an absent KeyUsage, so the picker must not hide such a DSC.
		no_ku = _token_cert(_der("Test Signer No KU", ca=False, usage="none"))
		encryption = _token_cert(_der("Test Signer Encryption", ca=False, usage="encrypt"))
		self.use({WD.id: [encryption, no_ku], INNAIT.id: TokenUnavailable()})
		self.assertEqual(["Test Signer No KU"], [item["common_name"] for item in self.listing()])

	def test_flags_supplied_with_the_metadata_are_not_trusted(self):
		lying = _token_cert(_der("Test Sub-CA", issuer="Test CA", ca=True, usage="ca"), metadata_extra={"digital_signature": True})
		self.use({WD.id: [lying], INNAIT.id: TokenUnavailable()})
		self.assertEqual([], self.listing())


class TestSignStaysExplicit(ListingTestCase):
	def sign(self, module_id):
		return self.service.sign(
			http_tests.ERP, http_tests.PDF, server_meta(), document_name="SINV-TEST-0001",
			selector={"fingerprint_sha256": "ab" * 32}, provider="auto", module_id=module_id, timestamp_url=None,
		)

	def test_sign_without_module_id_and_two_modules_needs_a_module(self):
		fake = self.use({})
		with self.assertRaises(LocalSignerError) as caught:
			self.sign(None)
		self.assertEqual("MODULE_SELECTION_REQUIRED", caught.exception.code)
		self.assertEqual(409, caught.exception.status)
		self.assertEqual([], fake.constructed)

	def test_sign_with_module_id_uses_exactly_that_registry_module(self):
		fake = self.use({})
		with self.assertRaises(LocalSignerError) as caught:
			self.sign(INNAIT.id)
		self.assertEqual("TEST_STOP", caught.exception.code)
		self.assertEqual([INNAIT.id], fake.constructed)

	def test_sign_with_a_path_as_module_id_is_refused(self):
		fake = self.use({})
		with self.assertRaises(MiddlewareUnavailable):
			self.sign(INNAIT.path)
		self.assertEqual([], fake.constructed)


class TestCertificatesHttp(http_tests.ServiceTestCase):
	"""The HTTP response: the listing's schema plus exactly module_id and provider."""

	def setUp(self):
		super().setUp()
		config = SignerConfig(custom_modules=(WD, INNAIT))
		self.service.providers = ProviderRegistry(config, system="ERPDSCTestOS", path_exists={WD.path, INNAIT.path}.__contains__)
		self.fake = FakeClients({WD.id: _real_token_five(), INNAIT.id: TokenUnavailable(DRIVER_TEXT)})
		patcher = mock.patch.object(service_module, "TokenClient", self.fake)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.addCleanup(self.fake.release.set)
		self.trust.allow(http_tests.ERP)

	def certificates(self, **extra):
		_s, _h, issued = http_tests._request(self.base + "/v1/nonce", method="POST", origin=http_tests.ERP, body={"purpose": "certificates"})
		return http_tests._request(self.base + "/v1/certificates", method="POST", origin=http_tests.ERP, body={"nonce": issued["nonce"], **extra})

	def test_response_is_the_signing_leaf_with_module_and_provider(self):
		status, _headers, body = self.certificates()
		self.assertEqual(200, status)
		self.assertEqual({"ok", "certificates"}, set(body))
		[item] = body["certificates"]
		expected = _real_token_five()[0].metadata
		self.assertEqual({**expected, "module_id": WD.id, "provider": "watchdata"}, item)
		self.assertEqual(expected["fingerprint_sha256"], hashlib.sha256(base64.b64decode(item["der_base64"])).hexdigest())

	def test_no_token_anywhere_is_the_fixed_error(self):
		self.fake.behaviours[WD.id] = TokenDriverNotResponding()
		status, _headers, body = self.certificates()
		self.assertEqual(409, status)
		self.assertEqual({"ok": False, "error": {"code": "TOKEN_UNAVAILABLE", "message": NO_TOKEN}}, body)
		self.assertNotIn("CKR_", str(body))
		self.assertNotIn("/opt/", str(body))

	def test_a_nonce_is_still_required(self):
		status, _headers, body = http_tests._request(self.base + "/v1/certificates", method="POST", origin=http_tests.ERP, body={"nonce": "x" * 32})
		self.assertNotEqual(200, status)
		self.assertEqual([], self.fake.constructed)


if __name__ == "__main__":
	unittest.main()
