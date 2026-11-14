"""``TokenClient.sign_pdf`` against the REAL endesive, with a software RSA key behind a fake
PKCS#11 library.

Every other token test replaces ``endesive.pdf.cms`` with a fake that never looks at what
``_TokenHSM.certificate()`` returns or at the ``othercerts`` it is given, so the forms the real
library accepts were never exercised: the first real USB signing failed inside ``cms.sign``
(``TypeError: byte_string must be a byte string``) because the HSM certificate was handed over
as a cryptography object.  These tests run the real certificate parsing, the real issuer-chain
builder, the real endesive and the real server-side verifier (``verify_usb_signed_pdf``).

No USB token, no PKCS#11 driver, no network: ``timestamp_url`` is ``None`` except in the
TSA-refusal test, which replaces ``requests.post`` and uses an ``.invalid`` host.
"""

import importlib
import importlib.util
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from asn1crypto import cms as asn1_cms
from asn1crypto import tsp as asn1_tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import os as _os
import sys as _sys

# Sibling test modules are imported by bare name; make that work when this module is
# loaded by its full name from the repository root as well as by discovery.
if _os.path.dirname(_os.path.abspath(__file__)) not in _sys.path:
	_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

import test_token_login as fakes
from test_token_login import PK, SENTINEL_PIN, FakeGuard, make_client

from erp_dsc_local.certificates import build_issuer_chain
from erp_dsc_local.errors import LocalSignerError, TokenSigningFailed
from erp_dsc_local.service import SIGNATURE_META_UNSUPPORTED, sanitise_signature_meta
from erp_dsc_local.token import _TokenHSM

# The server-side verifier the ERP runs on the returned PDF.  Loaded by path so the Frappe
# package ``erp_dsc_signer`` (and frappe) is not needed: the module imports only asn1crypto,
# cryptography and endesive.
USB_SIGNER_PATH = Path(__file__).resolve().parents[2] / "erp_dsc_signer" / "utils" / "usb_signer.py"

LEAF_KEY_ID = b"\x01\x02\x03"
LEAF_KEY_HANDLE = 21


def _load_usb_signer():
	spec = importlib.util.spec_from_file_location("erp_dsc_signer_usb_signer_under_test", USB_SIGNER_PATH)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def _name(common_name):
	return x509.Name(
		[
			x509.NameAttribute(NameOID.COMMON_NAME, common_name),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "F1 Integration Test"),
		]
	)


def _issue(subject, subject_key, issuer, issuer_key, serial, *, ca):
	now = datetime.now(timezone.utc)
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(subject_key.public_key())
		.serial_number(serial)
		.not_valid_before(now - timedelta(days=1))
		.not_valid_after(now + timedelta(days=30))
		.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
		.add_extension(
			x509.KeyUsage(
				digital_signature=not ca,
				content_commitment=not ca,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=ca,
				crl_sign=ca,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		)
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
		.add_extension(
			x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
		)
	)
	return builder.sign(issuer_key, hashes.SHA256())


def _make_chain():
	"""A root CA -> intermediate CA -> signer chain, like a CCA root, a licensed CA and a DSC."""
	keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
	root_key, intermediate_key, leaf_key = keys
	root_name, intermediate_name = _name("F1 Test Root CA"), _name("F1 Test Sub CA")
	root = _issue(root_name, root_key, root_name, root_key, 0x0A, ca=True)
	intermediate = _issue(intermediate_name, intermediate_key, root_name, root_key, 0x0B, ca=True)
	leaf = _issue(_name("F1 Test Signer"), leaf_key, intermediate_name, intermediate_key, 0xF1C3, ca=False)
	return leaf_key, leaf, intermediate, root


def _minimal_pdf(catalog: bytes = b"<< /Type /Catalog /Pages 2 0 R >>") -> bytes:
	"""A one-page PDF with a classic xref table (the shape wkhtmltopdf produces)."""
	content = b"BT /F1 18 Tf 72 760 Td (F1 integration invoice) Tj ET"
	objects = [
		catalog,
		b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
		b"/Resources << /Font << /F1 5 0 R >> >> >>",
		b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
		b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	]
	out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets = []
	for number, body in enumerate(objects, start=1):
		offsets.append(len(out))
		out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
	xref_offset = len(out)
	out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
	for offset in offsets:
		out += b"%010d 00000 n \n" % offset
	out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref_offset)
	return bytes(out)


def _server_signature_meta():
	"""The shape ``erp_dsc_signer.utils.pdf_signer._signature_metadata`` sends (after JSON)."""
	return {
		"aligned": 32768,
		"sigflags": 3,
		"sigflagsft": 132,
		"sigpage": 0,
		"sigbutton": True,
		"sigfield": "ERPNextSignature",
		"auto_sigfield": True,
		"sigandcertify": False,
		"signaturebox": [340, 45, 555, 130],
		"name": "USB DSC signer",
		"contact": "signer@example.invalid",
		"location": "",
		"signingdate": "D:20261106120000+05'30'",
		"reason": "Digitally signed invoice",
		"application": "ERPNext",
		"signature_appearance": {
			"display": "Digitally signed by USB DSC signer\nDate: 2026.11.06 12:00:00 +05'30'",
			"outline": [0, 0, 0],
			"border": 0,
		},
	}


class SoftwareKeySession(fakes.FakeSession):
	"""``C_Sign`` with ``CKM_SHA256_RSA_PKCS``, performed by a software key: SHA-256 of the
	data, then an RSA PKCS#1 v1.5 signature, returned as PyKCS11 returns it (a list of ints)."""

	def sign(self, key, data, mechanism):
		self.lib.log.append(("sign", self.slot, key))
		self.lib.mechanisms.append(mechanism)
		private_key = self.lib.private_keys[key]
		return list(private_key.sign(bytes(data), padding.PKCS1v15(), hashes.SHA256()))


class SoftwareKeyLib(fakes.FakeLib):
	def __init__(self, tokens, private_keys):
		super().__init__(tokens)
		self.private_keys = private_keys
		self.mechanisms = []

	def openSession(self, slot, flags):
		self.log.append(("openSession", slot))
		return SoftwareKeySession(self, slot)


def _der(certificate):
	return certificate.public_bytes(serialization.Encoding.DER)


class RealEndesiveCase(unittest.TestCase):
	"""The real endesive, a software key behind the fake PKCS#11 library.  No tests here."""

	pk = PK  # the PyKCS11 stand-in the client uses

	@classmethod
	def setUpClass(cls):
		cls.leaf_key, cls.leaf, cls.intermediate, cls.root = _make_chain()
		cls.pdf = _minimal_pdf()

	def setUp(self):
		# The fake cms other modules install is restored per test; this must be the real one.
		self.cms = importlib.import_module("endesive.pdf.cms")
		self.assertTrue(
			getattr(self.cms, "__file__", "").endswith(str(Path("endesive", "pdf", "cms.py"))),
			"endesive.pdf.cms is not the installed endesive",
		)
		self.usb_signer = _load_usb_signer()
		# The token carries the signer certificate and, as DSC tokens do, its CA certificates.
		# Deliberately not in chain order, so build_issuer_chain has to order them.
		self.lib = SoftwareKeyLib(
			{
				1: fakes._token("SER-INT-1"),
				2: fakes._token(
					"SER-INT-2",
					certs=[
						(24, (_der(self.root), b"\xca\x02", "root")),
						(20, (_der(self.leaf), LEAF_KEY_ID, "sign")),
						(22, (_der(self.intermediate), b"\xca\x01", "sub ca")),
					],
					keys=[(LEAF_KEY_HANDLE, LEAF_KEY_ID)],
				),
			},
			{LEAF_KEY_HANDLE: self.leaf_key},
		)
		self.client = make_client(self.lib)
		self.client.pk = self.pk
		self.selected, self.certificates = self.client.select(
			{"fingerprint_sha256": self.leaf.fingerprint(hashes.SHA256()).hex()}
		)
		self.stderr = io.StringIO()  # the one TOKEN_SIGNING_FAILED line
		patcher = mock.patch("sys.stderr", self.stderr)
		patcher.start()
		self.addCleanup(patcher.stop)

	def _sign(self, metadata, pdf=None, timestamp_url=None):
		self.sign_log_start = len(self.lib.log)  # enumeration in setUp opened and closed sessions
		return self.client.sign_pdf(
			self.pdf if pdf is None else pdf,
			self.selected,
			self.certificates,
			metadata,
			SENTINEL_PIN,
			timestamp_url,
			login_guard=FakeGuard(self.lib.log),
		)

	def _failure(self, metadata, pdf=None, timestamp_url=None):
		with self.assertRaises(TokenSigningFailed) as ctx:
			self._sign(metadata, pdf, timestamp_url)
		error = ctx.exception
		self.assertIsNone(error.__cause__)
		self.assertIsNone(error.__context__)
		self.assertNotIn(SENTINEL_PIN, json.dumps(error.as_dict()) + self.stderr.getvalue())
		return error

	def _operations(self):
		"""``login`` / ``sign`` / ``logout`` since ``_sign`` started, in order."""
		return [entry[0] for entry in self.lib.log[self.sign_log_start :] if entry[0] in ("login", "sign", "logout")]

	def _embedded_certificates(self, signed):
		(byte_range,) = self.usb_signer._find_byte_ranges(signed)
		_, first_length, second_offset, _ = byte_range
		content_info = asn1_cms.ContentInfo.load(bytes.fromhex(signed[first_length + 1 : second_offset - 1].decode("ascii")))
		return [choice.chosen.dump() for choice in content_info["content"]["certificates"]]

	def _assert_verifies_on_server(self, signed, metadata):
		self.assertTrue(signed.startswith(self.pdf))
		verified = self.usb_signer.verify_usb_signed_pdf(self.pdf, signed, metadata)
		self.assertEqual(verified["fingerprint_sha256"], self.leaf.fingerprint(hashes.SHA256()).hex())
		self.assertEqual(verified["serial_number_hex"], "F1C3")
		self.assertEqual(verified["subject"], self.leaf.subject.rfc4514_string())
		self.assertNotIn(SENTINEL_PIN.encode(), signed)


class RealEndesiveSigningTests(RealEndesiveCase):
	def test_hsm_certificate_is_der_bytes_that_asn1crypto_loads(self):
		"""endesive loads the HSM certificate with asn1crypto from bytes (DER or PEM)."""
		adapter = _TokenHSM(self.client, self.selected, None, FakeGuard(self.lib.log))
		key_id, certificate = adapter.certificate()
		self.assertEqual(key_id, LEAF_KEY_ID)
		self.assertIsInstance(certificate, bytes)
		self.assertEqual(certificate, _der(self.leaf))
		self.assertEqual(asn1_x509.Certificate.load(certificate).dump(), _der(self.leaf))

	def test_issuer_chain_is_leaf_to_root_cryptography_certificates(self):
		"""endesive turns each ``othercerts`` entry into asn1crypto via ``public_bytes``, so the
		chain stays as cryptography certificates (DER bytes would be rejected)."""
		chain = build_issuer_chain(self.selected, self.certificates)
		self.assertEqual([_der(item) for item in chain], [_der(self.intermediate), _der(self.root)])
		for item in chain:
			self.assertIsInstance(item, x509.Certificate)

	def test_sign_pdf_with_server_shaped_metadata_verifies_on_server(self):
		signed, metadata = self._sign(_server_signature_meta())
		self.assertEqual(metadata, self.selected.metadata)
		self._assert_verifies_on_server(signed, metadata)
		# The signer certificate and both token-resident CA certificates reach the CMS.
		self.assertCountEqual(
			self._embedded_certificates(signed), [_der(self.leaf), _der(self.intermediate), _der(self.root)]
		)
		self.assertEqual(self.lib.logins, [(2, SENTINEL_PIN)])
		self.assertEqual(self.lib.mechanisms, [PK.Mechanism(PK.CKM_SHA256_RSA_PKCS, None)])
		wanted = ("guard_enter", "check_flags", "login", "succeeded", "guard_exit", "sign", "logout", "closeSession")
		protocol = [entry for entry in self.lib.log[self.sign_log_start :] if entry[0] in wanted]
		self.assertEqual(
			protocol,
			[
				("guard_enter",),
				("check_flags", 0),
				("login", 2),
				("succeeded",),
				("guard_exit",),
				("sign", 2, LEAF_KEY_HANDLE),
				("logout", 2),
				("closeSession", 2),
			],
		)

	def test_server_shaped_meta_with_aligned_zero_is_login_sign_sign_and_verifies(self):
		"""``aligned`` 0: endesive signs once to size the contents and again for real; the
		adapter reuses its one ``C_Login`` for the second ``C_Sign``.  The allowlist pins
		``aligned`` to 32768, so this exercises the token layer directly."""
		signed, metadata = self._sign(dict(_server_signature_meta(), aligned=0))
		self._assert_verifies_on_server(signed, metadata)
		self.assertEqual(self.lib.logins, [(2, SENTINEL_PIN)])
		self.assertEqual(["login", "sign", "sign", "logout"], self._operations())
		self.assertEqual([PK.Mechanism(PK.CKM_SHA256_RSA_PKCS, None)] * 2, self.lib.mechanisms)

	def test_the_three_key_partial_meta_is_refused_by_the_allowlist(self):
		"""The partial meta the old unaligned test signed with no longer gets past the allowlist."""
		partial = {"sigflags": 3, "contact": "signer@example.invalid", "signingdate": "D:20261106120000+05'30'"}
		with self.assertRaises(LocalSignerError) as ctx:
			sanitise_signature_meta(partial)
		self.assertEqual(("INVALID_REQUEST", SIGNATURE_META_UNSUPPORTED), (ctx.exception.code, ctx.exception.message))
		self.assertEqual(_server_signature_meta(), sanitise_signature_meta(_server_signature_meta()))

	def test_a_sigpage_past_the_last_page_fails_in_cms_before_any_c_login(self):
		error = self._failure(dict(_server_signature_meta(), sigpage=1))  # a one-page PDF
		self.assertEqual({"stage": "cms", "error": "IndexError", "ckr": None}, error.details)
		self.assertEqual([], self.lib.logins)
		self.assertEqual([], self._operations())

	def test_an_aligned_too_small_for_the_signature_fails_in_cms_after_c_sign(self):
		error = self._failure(dict(_server_signature_meta(), aligned=16))
		self.assertEqual({"stage": "cms", "error": "AssertionError", "ckr": None}, error.details)
		self.assertEqual(["login", "sign", "logout"], self._operations())

	def test_a_tsa_that_answers_but_refuses_is_stage_tsa(self):
		"""requests does not raise on a 4xx/5xx and endesive raises a plain ValueError for a
		reply that is not a granted timestamp (signer.py ~145), and asn1crypto raises one for
		a status-only rejection, after the final C_Sign.  ``requests.post`` is replaced: no
		network."""
		# TimeStampResp { status PKIStatusInfo { status rejection(2) } }, no token: what a
		# refusing TSA sends.
		rejection = bytes.fromhex("30053003020102")
		with self.assertRaises(ValueError):
			asn1_tsp.TimeStampResp.load(rejection)["status"]
		replies = {
			"http-503": SimpleNamespace(status_code=503, headers={"Content-Type": "text/html"}, content=b"pin=" + SENTINEL_PIN.encode()),
			"rejection": SimpleNamespace(status_code=200, headers={"Content-Type": "application/timestamp-reply"}, content=rejection),
		}
		for label, reply in replies.items():
			with self.subTest(reply=label):
				posts = []

				def post(url, *args, reply=reply, **kwargs):
					posts.append((url, kwargs.get("timeout")))
					return reply

				with mock.patch("requests.post", post):
					error = self._failure(_server_signature_meta(), timestamp_url="https://tsa.invalid/")
				self.assertEqual({"stage": "tsa", "error": "ValueError", "ckr": None}, error.details)
				self.assertEqual([("https://tsa.invalid/", (5, 15))], posts)
				self.assertEqual(["login", "sign", "logout"], self._operations())


if __name__ == "__main__":
	unittest.main()
