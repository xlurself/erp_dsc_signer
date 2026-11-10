"""F2: the certificate listing exposes the PUBLIC certificate so the ERP can authenticate it before the PIN."""

from __future__ import annotations

import base64
import datetime
import functools
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from erp_dsc_local.certificates import parse_token_certificate


@functools.lru_cache(maxsize=None)
def _leaf_der() -> bytes:
	"""A generated DSC-shaped leaf (CN "Test Signer", no personal data), issued by a generated CA."""
	ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	ca_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"), x509.NameAttribute(NameOID.COMMON_NAME, "Test Sub-CA")])
	subject = x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Personal"),
			x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer"),
		]
	)
	not_before = datetime.datetime(2026, 7, 20, tzinfo=datetime.timezone.utc)
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(ca_name)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(not_before)
		.not_valid_after(not_before + datetime.timedelta(days=730))
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.add_extension(
			x509.KeyUsage(
				digital_signature=True,
				content_commitment=True,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=False,
				crl_sign=False,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		)
		.add_extension(
			x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False
		)
		.add_extension(x509.SubjectAlternativeName([x509.RFC822Name("test.signer@example.invalid")]), critical=False)
		.sign(ca_key, hashes.SHA256())
	)
	return cert.public_bytes(serialization.Encoding.DER)


class TestCertificateDer(unittest.TestCase):
	def _parsed(self):
		return parse_token_certificate(_leaf_der(), b"\x01", "label", 1, "tok", "serial")

	def test_listing_carries_the_public_der_matching_the_fingerprint(self):
		meta = self._parsed().metadata
		der = base64.b64decode(meta["der_base64"], validate=True)
		self.assertEqual(_leaf_der(), der)
		self.assertEqual(meta["fingerprint_sha256"], hashlib.sha256(der).hexdigest())
		self.assertEqual(meta["common_name"], "Test Signer")

	def test_only_public_certificate_bytes_are_added(self):
		# The new key must not be able to carry anything but the certificate DER.
		meta = self._parsed().metadata
		self.assertEqual(set(meta) - {"der_base64"}, {
			"fingerprint_sha256", "serial_number", "serial_number_decimal", "subject", "issuer", "common_name",
			"valid_from", "valid_to", "currently_valid", "digital_signature", "key_type", "key_size", "label",
			"slot_id", "token_label", "token_serial", "organization",
		})


def _der_with_subject(attributes) -> bytes:
	key = _subject_key()
	subject = x509.Name([x509.NameAttribute(oid, value) for oid, value in attributes])
	not_before = datetime.datetime(2026, 7, 20, tzinfo=datetime.timezone.utc)
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Sub-CA")]))
		.public_key(key.public_key())
		.serial_number(7)
		.not_valid_before(not_before)
		.not_valid_after(not_before + datetime.timedelta(days=730))
		.sign(key, hashes.SHA256())
	)
	return cert.public_bytes(serialization.Encoding.DER)


@functools.lru_cache(maxsize=None)
def _subject_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestOrganizationMetadata(unittest.TestCase):
	"""``organization``: the subject O, read by the daemon from the parsed certificate."""

	def organization(self, attributes, label="label", token_label="tok"):
		der = _der_with_subject(attributes)
		return parse_token_certificate(der, b"\x01", label, 1, token_label, "serial").metadata["organization"]

	def test_company_certificate(self):
		attributes = [(NameOID.ORGANIZATION_NAME, "Test Company Pvt Ltd"), (NameOID.COMMON_NAME, "Test Signer")]
		self.assertEqual("Test Company Pvt Ltd", self.organization(attributes))

	def test_personal_certificate_keeps_the_word_personal(self):
		self.assertEqual("Personal", TestCertificateDer()._parsed().metadata["organization"])

	def test_absent_is_an_empty_string(self):
		self.assertEqual("", self.organization([(NameOID.COMMON_NAME, "Test Signer")]))

	def test_control_and_format_characters_are_removed(self):
		raw = "\x00Test\x07 Company‮ Pvt\nLtd​\x7f\x9b "
		self.assertEqual("Test Company Pvt Ltd", self.organization([(NameOID.ORGANIZATION_NAME, raw)]))

	def test_length_is_capped(self):
		value = self.organization([(NameOID.ORGANIZATION_NAME, "Test Company " * 60)])
		self.assertEqual(256, len(value))
		self.assertTrue(value.startswith("Test Company Test Company"))

	def test_first_organization_attribute_only(self):
		attributes = [(NameOID.ORGANIZATION_NAME, "Test Company Pvt Ltd"), (NameOID.ORGANIZATION_NAME, "Other Test Company")]
		self.assertEqual("Test Company Pvt Ltd", self.organization(attributes))

	def test_never_from_the_driver_supplied_labels(self):
		attributes = [(NameOID.COMMON_NAME, "Test Signer")]
		self.assertEqual("", self.organization(attributes, label="O=Driver Company", token_label="Driver Company"))


if __name__ == "__main__":
	unittest.main()
