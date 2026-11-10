"""F2 slice 2: the signing endpoints refuse any DSC that ca_trust cannot authenticate.

Contract: doc/spec/002-india-ca-verification.md s2 (API + order), s4 (record), s5 (messages, log line).
Owner rule: not authenticated by the CCA India chain => not signed, no override.

Pure unittest + unittest.mock: no site, no database, no network. The session cache is a dict-backed
fake so the real session code (prepare / peek / consume) runs.
"""

import base64
import contextlib
import datetime
import hashlib
import io
import json
import pickle
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from asn1crypto import cms as asn1_cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from endesive.pdf import cms as endesive_cms

from erp_dsc_signer.api import signing
from erp_dsc_signer.utils import ca_trust, pdf_signer, usb_signer
from erp_dsc_signer.utils.usb_signer import USBSignatureError

SENTINEL = "S3NT1NEL-PIN-9981"
USER = "signer@example.com"
FIXTURES = Path(__file__).parent / "fixtures"
LEAF_DER = (FIXTURES / "owner_leaf_signx_class3_individual.der").read_bytes()
LEAF_SHA = hashlib.sha256(LEAF_DER).hexdigest()
OTHER_DER = (FIXTURES / "signx_ca_2022.der").read_bytes()  # a different real certificate
OTHER_SHA = hashlib.sha256(OTHER_DER).hexdigest()
ORIGINAL_PDF = b"%PDF-1.7 prepared invoice"
NOW = datetime.datetime(2026, 11, 9, 10, 0, tzinfo=datetime.timezone.utc)
ROOT_SHA = "9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8"

# spec s4, written out here (not read from ca_trust) so drift in either place fails this suite.
SPEC_RECORD_KEYS = {"verified", "checked_at", "chain", "root_sha256", "revocation", "timestamp", "signing_time_basis"}
SPEC_CHAIN_KEYS = {"subject_cn", "sha256"}
SPEC_REVOCATION_KEYS = {"subject_cn", "method", "status", "responder_host", "produced_at"}


def _record(leaf_sha=LEAF_SHA):
	return {
		"verified": True,
		"checked_at": "2026-11-09T10:00:00+00:00",
		"chain": [
			{"subject_cn": "Owner", "sha256": leaf_sha},
			{"subject_cn": "SignX sub-CA for Class 3 Individual 2022", "sha256": "b" * 64},
			{"subject_cn": "SignX CA 2022", "sha256": "c" * 64},
			{"subject_cn": "CCA India 2022", "sha256": ROOT_SHA},
		],
		"root_sha256": ROOT_SHA,
		"revocation": [
			{
				"subject_cn": "Owner",
				"method": "ocsp",
				"status": "good",
				"responder_host": "ocsp.signxca.com",
				"produced_at": "2026-11-09T09:59:00+00:00",
			}
		],
		"timestamp": "none",
		"signing_time_basis": "server clock at verification",
	}


class _Thrown(Exception):
	"""Stands in for frappe.ValidationError raised by frappe.throw."""


def _throw(message, *args, **kwargs):
	raise _Thrown(message)


class _FakeCache:
	"""Mirrors frappe RedisWrapper: get/set/delete_value prefix the key via make_key and pickle the value;
	``set`` is the raw redis SET (already-made key, pickled value, ``ex`` and ``xx``)."""

	def __init__(self):
		self.store = {}
		self.expiry = {}
		self.reads = []

	@staticmethod
	def make_key(key):
		return f"site_db|{key}".encode()

	def get_value(self, key, expires=False):
		self.reads.append((key, expires))
		return self.store.get(self.make_key(key))

	def set_value(self, key, value, expires_in_sec=None):
		self.store[self.make_key(key)] = value
		self.expiry[self.make_key(key)] = expires_in_sec

	def delete_value(self, key):
		self.store.pop(self.make_key(key), None)

	def set(self, name, value, ex=None, xx=False):
		if xx and name not in self.store:
			return None
		self.store[name] = pickle.loads(value)
		self.expiry[name] = ex
		return True


class _Doc(dict):
	def __init__(self, **kw):
		super().__init__(**kw)
		self.name = "SINV-0001"
		self.doctype = "Sales Invoice"
		self.docstatus = 1


def _b64(data):
	return base64.b64encode(data).decode("ascii")


def _der(cert):
	return cert.public_bytes(serialization.Encoding.DER)


def _sha(cert):
	return hashlib.sha256(_der(cert)).hexdigest()


def _key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _issue(cn, key, issuer_name, issuer_key, serial, *, ca=False):
	"""A software-key test certificate (never a real DSC), valid around the real clock."""
	now = datetime.datetime.now(datetime.timezone.utc)
	subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer_name or subject)
		.public_key(key.public_key())
		.serial_number(serial)
		.not_valid_before(now - datetime.timedelta(days=1))
		.not_valid_after(now + datetime.timedelta(days=30))
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
	)
	return builder.sign(issuer_key, hashes.SHA256())


def _minimal_pdf():
	"""One-page PDF with a classic xref table (as in local_signer/tests/test_endesive_integration.py)."""
	content = b"BT /F1 18 Tf 72 760 Td (F2 binding invoice) Tj ET"
	objects = [
		b"<< /Type /Catalog /Pages 2 0 R >>",
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


_SIGNATURE_META = {
	"aligned": 32768,
	"sigflags": 3,
	"sigflagsft": 132,
	"sigpage": 0,
	"sigbutton": True,
	"sigfield": "ERPNextSignature",
	"auto_sigfield": True,
	"sigandcertify": False,
	"signaturebox": [340, 45, 555, 130],
	"name": "Test signer",
	"contact": "signer@example.invalid",
	"location": "",
	"signingdate": "D:20261109120000+05'30'",
	"reason": "Digitally signed invoice",
	"application": "ERPNext",
	"signature_appearance": {"display": "Digitally signed by Test signer", "outline": [0, 0, 0], "border": 0},
}


class _Base(unittest.TestCase):
	mock_ca_trust = True

	def setUp(self):
		self.cache = _FakeCache()
		self.doc = _Doc()
		self.events = []
		self.fr = self._patch(signing, "frappe")
		self.fr.cache.return_value = self.cache
		self.fr.session.user = USER
		self.fr.throw.side_effect = _throw
		self.fr.get_doc.return_value = self.doc
		self.fr.utils.cint.side_effect = lambda v: int(v or 0)
		self.fr.utils.now_datetime.return_value = datetime.datetime(2026, 11, 9, 15, 30)
		self.fr.db.set_value.side_effect = lambda *a, **k: self.events.append(("set_value", a, k))
		self.fr.log_error.side_effect = lambda *a, **k: self.events.append(("log_error", a, k))
		self.fr.db.commit.side_effect = lambda *a, **k: self.events.append(("commit", a, k))
		self._patch(signing, "_", side_effect=lambda s: s)
		self._patch(signing, "_utc_now", return_value=NOW)
		if self.mock_ca_trust:
			self.auth = self._patch(ca_trust, "authenticate_certificate", side_effect=self._authenticate)
		self.auth_results = []  # consumed in order; default: success
		self.settings = mock.MagicMock()
		self.settings.usb_session_expiry_minutes = 5
		self.settings.enable_timestamp = 0
		self.settings.get_password.return_value = "pfx-password"
		self._patch(signing, "get_signing_settings", return_value=self.settings)
		self.generate = self._patch(signing, "generate_invoice_pdf", return_value=ORIGINAL_PDF)
		self._patch(signing, "validate_prepared_pdf", return_value=None)
		self._patch(signing, "_signature_metadata", return_value={"name": "signer"})
		self.decode = self._patch(signing, "decode_signed_pdf_payload", return_value=ORIGINAL_PDF + b" signature")
		self.verify = self._patch(
			signing, "verify_usb_signed_pdf", return_value={"fingerprint_sha256": LEAF_SHA, "subject": "CN=Owner"}
		)
		self.attach = self._patch(signing, "attach_signed_invoice_pdf", side_effect=self._attach)
		self.sign_pdf = self._patch(signing, "sign_pdf_bytes", side_effect=self._sign_pdf)
		self.pfx_cert = mock.MagicMock()
		self.pfx_cert.public_bytes.return_value = LEAF_DER
		self.load_pfx = self._patch(signing, "load_pfx_credentials", return_value=(object(), self.pfx_cert, []))
		self.get_pfx = self._patch(signing, "get_pfx_bytes", return_value=b"pfx-bytes")

	def _patch(self, target, name, **kwargs):
		patcher = mock.patch.object(target, name, **kwargs)
		started = patcher.start()
		self.addCleanup(patcher.stop)
		return started

	def _authenticate(self, cert_der, **kwargs):
		self.events.append(("authenticate", cert_der, kwargs))
		outcome = self.auth_results.pop(0) if self.auth_results else _record(hashlib.sha256(cert_der).hexdigest())
		if isinstance(outcome, BaseException):
			raise outcome
		return outcome

	def _attach(self, doc, signed_pdf, replace, signed_by=None):
		self.events.append(("attach", doc.name, signed_pdf))
		return {"file_url": "/private/files/SINV-0001-signed.pdf", "file_name": "SINV-0001-signed.pdf"}

	def _sign_pdf(self, pdf_bytes, settings, credentials=None):
		self.events.append(("sign_pdf", pdf_bytes))
		return pdf_bytes + b" pfx signature"

	def key(self, prepared):
		return self.cache.make_key(signing._session_key(prepared["session_id"]))

	# ---- flow helpers

	def prepare(self):
		return signing.prepare_usb_signing("SINV-0001", provider="auto")

	def session(self, prepared):
		raw = self.cache.get_value(signing._session_key(prepared["session_id"]))
		return json.loads(raw) if raw else None

	def authenticate(self, prepared, der=LEAF_DER):
		return signing.authenticate_usb_certificate(prepared["session_id"], _b64(der))

	def complete(self, prepared, certificate_metadata=None):
		return signing.complete_usb_signing(
			prepared["session_id"], prepared["nonce"], "c2lnbmF0dXJl", certificate_metadata=certificate_metadata
		)

	def names(self):
		return [event[0] for event in self.events]

	def stored_records(self):
		return [
			json.loads(event[1][3])
			for event in self.events
			if event[0] == "set_value" and event[1][2] == "custom_signature_verification"
		]

	def sinks(self, *returned):
		return repr(
			[
				returned,
				self.fr.log_error.call_args_list,
				self.fr.throw.call_args_list,
				self.fr.db.set_value.call_args_list,
				self.fr.msgprint.call_args_list,
				self.fr.logger.mock_calls,
				self.cache.store,
			]
		)


class TestAuthenticateEndpoint(_Base):
	def test_uses_the_ca_trust_module_and_is_whitelisted(self):
		self.assertIs(signing.ca_trust, ca_trust)
		self.assertTrue(callable(signing.authenticate_usb_certificate))

	def test_success_marks_session_with_fingerprint_and_record(self):
		prepared = self.prepare()
		self.assertFalse(self.session(prepared).get("authenticated"))
		result = self.authenticate(prepared)
		session = self.session(prepared)
		self.assertIs(True, session["authenticated"])
		self.assertEqual(LEAF_SHA, session["certificate_sha256"])
		self.assertEqual(_record(), session["verification"])
		self.assertIs(True, result["verified"])
		self.assertEqual(LEAF_SHA, result["certificate_sha256"])
		# exactly one ca_trust call, on the decoded DER, at the server's UTC clock, no extra hosts/fetch.
		self.auth.assert_called_once()
		self.assertEqual(LEAF_DER, bytes(self.auth.call_args.args[0]))
		self.assertEqual({"now": NOW}, self.auth.call_args.kwargs)

	def test_signature_stamp_names_the_authenticated_certificate_holder(self):
		result = self.authenticate(self.prepare())
		signing._signature_metadata.assert_called_once()
		self.assertEqual("Vinay Saraf", signing._signature_metadata.call_args.args[2])
		self.assertEqual({"name": "signer"}, result["signature_meta"])

	def test_prepare_does_not_stamp_a_generic_signer_name(self):
		prepared = self.prepare()
		signing._signature_metadata.assert_not_called()
		self.assertNotIn("signature_meta", prepared["signing_request"])

	def test_session_is_marked_not_consumed(self):
		prepared = self.prepare()
		before = self.session(prepared)
		self.authenticate(prepared)
		after = self.session(prepared)
		self.assertIsNotNone(after)
		self.assertEqual(before["nonce"], after["nonce"])
		self.assertEqual(before["pdf_sha256"], after["pdf_sha256"])

	def test_marking_never_extends_the_session_lifetime(self):
		prepared = self.prepare()
		key = self.key(prepared)
		self.assertEqual(300, self.cache.expiry[key])
		with mock.patch.object(signing.time, "time", return_value=self.session(prepared)["expires_at"] - 42):
			self.authenticate(prepared)
		self.assertEqual(42, self.cache.expiry[key])

	def test_each_reason_code_throws_its_fixed_message_and_does_not_mark(self):
		self.assertEqual(8, len(ca_trust.REASON_CODES))
		self.assertIn("CERTIFICATE_PROFILE", ca_trust.REASON_CODES)
		for code in sorted(ca_trust.REASON_CODES):
			with self.subTest(code=code):
				self.fr.log_error.reset_mock()
				prepared = self.prepare()
				self.auth_results = [ca_trust.CertificateNotAuthenticated(code)]
				with self.assertRaises(_Thrown) as ctx:
					self.authenticate(prepared)
				self.assertEqual(ca_trust.MESSAGES[code], str(ctx.exception))
				self.assertNotIn("authenticated", self.session(prepared))
				self.fr.log_error.assert_called_once()
				logged = json.loads(self.fr.log_error.call_args.kwargs["message"])
				self.assertEqual({"reason_code": code, "certificate_sha256": LEAF_SHA}, logged)
				self.assertNotIn("\n", self.fr.log_error.call_args.kwargs["title"])

	def test_failure_log_is_committed_before_the_throw_rolls_back(self):
		# frappe/app.py rolls back a POST that raised, which would drop the Error Log row.
		prepared = self.prepare()
		self.auth_results = [ca_trust.CertificateNotAuthenticated("REVOKED")]
		with self.assertRaises(_Thrown):
			self.authenticate(prepared)
		names = self.names()
		self.assertLess(names.index("log_error"), names.index("commit"))
		self.assertNotIn("set_value", names)

	def test_unexpected_exception_fails_closed_with_a_generic_fixed_message(self):
		prepared = self.prepare()
		self.auth_results = [RuntimeError(f"pin={SENTINEL}")]
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(signing.CERTIFICATE_NOT_AUTHENTICATED_MESSAGE, str(ctx.exception))
		self.assertNotIn("authenticated", self.session(prepared))
		self.assertNotIn(SENTINEL, self.sinks())

	def test_record_that_is_not_verified_fails_closed(self):
		for bad in ({**_record(), "verified": False}, {**_record(), "verified": "yes"}, {"verified": True}, None):
			with self.subTest(bad=bad):
				prepared = self.prepare()
				self.auth_results = [bad]
				with self.assertRaises(_Thrown) as ctx:
					self.authenticate(prepared)
				self.assertEqual(signing.CERTIFICATE_NOT_AUTHENTICATED_MESSAGE, str(ctx.exception))
				self.assertNotIn("authenticated", self.session(prepared))

	def test_malformed_or_oversize_certificate_is_refused_before_ca_trust(self):
		oversize = _b64(b"\x30" * (ca_trust.MAX_CERT_BYTES + 1))
		bad_inputs = (None, "", 123, b"MIIB", "not base64!!", _b64(LEAF_DER)[:-1], "TUlJ\nQg==", oversize)
		for bad in bad_inputs:
			with self.subTest(bad=repr(bad)[:40]):
				prepared = self.prepare()
				with self.assertRaises(_Thrown):
					signing.authenticate_usb_certificate(prepared["session_id"], bad)
				self.assertNotIn("authenticated", self.session(prepared))
		self.auth.assert_not_called()

	def test_session_of_another_user_is_refused(self):
		prepared = self.prepare()
		self.fr.session.user = "intruder@example.com"
		with self.assertRaises(_Thrown):
			self.authenticate(prepared)
		self.auth.assert_not_called()
		self.assertNotIn("authenticated", self.session(prepared))

	def test_invoice_write_permission_is_checked(self):
		prepared = self.prepare()
		self.fr.has_permission.reset_mock()
		self.authenticate(prepared)
		self.fr.has_permission.assert_called_once_with("Sales Invoice", doc="SINV-0001", ptype="write", throw=True)

		prepared = self.prepare()
		self.auth.reset_mock()
		self.fr.has_permission.side_effect = _Thrown("no permission")
		with self.assertRaises(_Thrown):
			self.authenticate(prepared)
		self.auth.assert_not_called()
		self.assertNotIn("authenticated", self.session(prepared))

	def test_unknown_expired_or_invalid_sessions_are_refused(self):
		with self.assertRaises(_Thrown):
			signing.authenticate_usb_certificate("x" * 32, _b64(LEAF_DER))
		with self.assertRaises(_Thrown):
			signing.authenticate_usb_certificate("short", _b64(LEAF_DER))
		prepared = self.prepare()
		with mock.patch.object(signing.time, "time", return_value=self.session(prepared)["expires_at"] + 1):
			with self.assertRaises(_Thrown):
				self.authenticate(prepared)
		self.auth.assert_not_called()

	def test_an_authenticated_session_cannot_be_authenticated_again(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		with self.assertRaises(_Thrown):
			self.authenticate(prepared, der=OTHER_DER)
		self.assertEqual(1, self.auth.call_count)
		self.assertEqual(LEAF_SHA, self.session(prepared)["certificate_sha256"])

	# ---- finding 4: the write-back after the (slow, networked) check must not revive or overwrite

	def test_a_session_consumed_while_authenticating_is_not_revived(self):
		prepared = self.prepare()
		original = self.auth.side_effect

		def consumed_meanwhile(cert_der, **kwargs):
			self.cache.delete_value(signing._session_key(prepared["session_id"]))  # complete ran meanwhile
			return original(cert_der, **kwargs)

		self.auth.side_effect = consumed_meanwhile
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(signing.SESSION_UNAVAILABLE_MESSAGE, str(ctx.exception))
		self.assertNotIn(self.key(prepared), self.cache.store)  # not written back
		with self.assertRaises(_Thrown):
			self.complete(prepared)  # so the used nonce cannot complete a second time
		self.attach.assert_not_called()

	def test_a_session_consumed_between_the_reread_and_the_write_is_not_revived(self):
		# The re-read cannot close the last gap; the write itself must only overwrite an existing key (XX).
		prepared = self.prepare()
		key = signing._session_key(prepared["session_id"])
		reads = []
		plain_get = self.cache.get_value

		def get_then_consume_on_reread(name, expires=False):
			value = plain_get(name, expires=expires)
			reads.append(name)
			if name == key and len(reads) == 2:  # 1st: peek, 2nd: the re-read just before the write
				self.cache.delete_value(key)
			return value

		self.cache.get_value = get_then_consume_on_reread
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(signing.SESSION_UNAVAILABLE_MESSAGE, str(ctx.exception))
		self.assertNotIn(self.key(prepared), self.cache.store)

	def test_a_session_authenticated_meanwhile_is_not_overwritten(self):
		prepared = self.prepare()
		original = self.auth.side_effect

		def other_tab_won(cert_der, **kwargs):
			key = signing._session_key(prepared["session_id"])
			payload = json.loads(self.cache.get_value(key))
			payload.update(authenticated=True, certificate_sha256=OTHER_SHA, certificate_der_base64=_b64(OTHER_DER))
			self.cache.set_value(key, json.dumps(payload), expires_in_sec=100)
			return original(cert_der, **kwargs)

		self.auth.side_effect = other_tab_won
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(signing.ALREADY_AUTHENTICATED_MESSAGE, str(ctx.exception))
		self.assertEqual(OTHER_SHA, self.session(prepared)["certificate_sha256"])

	def test_session_reads_bypass_the_request_local_cache(self):
		# frappe's get_value without expires=True serves frappe.local.cache, which would hide a concurrent change.
		prepared = self.prepare()
		self.cache.reads.clear()
		self.authenticate(prepared)
		self.assertTrue(self.cache.reads)
		self.assertTrue(all(expires is True for _key, expires in self.cache.reads), self.cache.reads)

	# ---- finding 7: failed authentications are capped per session

	def test_failed_authentications_are_capped_per_session(self):
		self.assertEqual(5, signing.MAX_AUTHENTICATION_FAILURES)
		prepared = self.prepare()
		self.auth_results = [ca_trust.CertificateNotAuthenticated("REVOCATION_UNAVAILABLE") for _ in range(5)]
		for _ in range(5):
			with self.assertRaises(_Thrown) as ctx:
				self.authenticate(prepared)
			self.assertEqual(ca_trust.MESSAGES["REVOCATION_UNAVAILABLE"], str(ctx.exception))
		self.assertEqual(5, self.auth.call_count)
		self.assertEqual(5, self.session(prepared)["auth_failures"])
		logged = self.names().count("log_error")
		self.auth_results = []  # a 6th attempt would now succeed if it were allowed to run
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(signing.TOO_MANY_FAILURES_MESSAGE, str(ctx.exception))
		self.assertEqual(5, self.auth.call_count)  # no ca_trust call, so no network
		self.assertEqual(logged, self.names().count("log_error"))  # and no further Error Log row
		self.assertNotIn("authenticated", self.session(prepared))

	def test_failures_below_the_cap_do_not_block_a_later_success(self):
		prepared = self.prepare()
		self.auth_results = [ca_trust.CertificateNotAuthenticated("REVOCATION_UNAVAILABLE") for _ in range(4)]
		for _ in range(4):
			with self.assertRaises(_Thrown):
				self.authenticate(prepared)
		self.assertIs(True, self.authenticate(prepared)["verified"])
		self.assertIs(True, self.session(prepared)["authenticated"])

	def test_input_refused_before_ca_trust_is_not_counted(self):
		prepared = self.prepare()
		for _ in range(6):
			with self.assertRaises(_Thrown):
				signing.authenticate_usb_certificate(prepared["session_id"], "not base64!!")
		self.assertNotIn("auth_failures", self.session(prepared))
		self.assertIs(True, self.authenticate(prepared)["verified"])


class TestCompleteGate(_Base):
	def test_unauthenticated_session_is_refused_and_nothing_is_attached(self):
		prepared = self.prepare()
		with self.assertRaises(_Thrown) as ctx:
			self.complete(prepared)
		self.assertEqual(signing.SESSION_NOT_AUTHENTICATED_MESSAGE, str(ctx.exception))
		self.attach.assert_not_called()
		self.verify.assert_not_called()
		self.assertEqual([], self.stored_records())
		self.assertIsNone(self.session(prepared))  # still one-use

	def test_fingerprint_swap_between_authenticate_and_complete_is_refused(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		self.verify.return_value = {"fingerprint_sha256": OTHER_SHA, "subject": "CN=Someone else"}
		with self.assertRaises(_Thrown) as ctx:
			self.complete(prepared)
		self.assertEqual(signing.CERTIFICATE_MISMATCH_MESSAGE, str(ctx.exception))
		self.attach.assert_not_called()
		self.assertEqual(1, self.auth.call_count)  # no re-authentication of a swapped certificate
		self.assertEqual([], self.stored_records())

	def test_missing_signer_fingerprint_is_refused(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		self.verify.return_value = {"subject": "CN=Owner"}
		with self.assertRaises(_Thrown):
			self.complete(prepared)
		self.attach.assert_not_called()

	def test_complete_reauthenticates_then_attaches_then_stores_the_record(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		result = self.complete(prepared)
		self.assertEqual(2, self.auth.call_count)  # fresh revocation at completion
		self.assertEqual(LEAF_DER, bytes(self.auth.call_args.args[0]))
		names = self.names()
		self.assertEqual(["authenticate", "authenticate", "attach", "set_value"], names)
		set_call = self.fr.db.set_value.call_args
		self.assertEqual(("Sales Invoice", "SINV-0001", "custom_signature_verification"), set_call.args[:3])
		self.assertEqual({"update_modified": False}, set_call.kwargs)
		signed_sha = hashlib.sha256(ORIGINAL_PDF + b" signature").hexdigest()
		self.assertEqual([{**_record(), "signed_pdf_sha256": signed_sha}], self.stored_records())
		self.assertEqual(signed_sha, result["verification"]["signed_pdf_sha256"])
		self.assertIs(True, result["verification"]["verified"])
		self.assertEqual(LEAF_SHA, result["certificate"]["fingerprint_sha256"])

	def test_revoked_at_completion_attaches_nothing(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		self.auth_results = [ca_trust.CertificateNotAuthenticated("REVOKED")]
		with self.assertRaises(_Thrown) as ctx:
			self.complete(prepared)
		self.assertEqual(ca_trust.MESSAGES["REVOKED"], str(ctx.exception))
		self.assertEqual(2, self.auth.call_count)
		self.attach.assert_not_called()
		self.assertEqual([], self.stored_records())

	def test_session_certificate_that_does_not_match_its_fingerprint_is_refused(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		key = self.key(prepared)
		payload = json.loads(self.cache.store[key])
		payload["certificate_der_base64"] = _b64(OTHER_DER)
		self.cache.store[key] = json.dumps(payload)
		with self.assertRaises(_Thrown):
			self.complete(prepared)
		self.attach.assert_not_called()
		self.assertEqual(1, self.auth.call_count)

	def test_signature_verification_failure_still_attaches_nothing(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		self.verify.side_effect = USBSignatureError("The PDF digest or cryptographic signature is invalid.")
		with self.assertRaises(_Thrown):
			self.complete(prepared)
		self.attach.assert_not_called()
		self.assertEqual(1, self.auth.call_count)

	def test_certificate_metadata_json_string_is_still_parsed(self):
		# commit 0ae447a: frappe.call sends nested objects as JSON strings.
		prepared = self.prepare()
		self.authenticate(prepared)
		self.complete(prepared, certificate_metadata=json.dumps({"fingerprint_sha256": LEAF_SHA}))
		self.assertEqual({"fingerprint_sha256": LEAF_SHA}, self.verify.call_args.args[2])


class TestRealSignerBinding(_Base):
	"""finding 9: authenticate certificate A, then complete with a PDF really signed (endesive, software
	key) by certificate B. The REAL decode + verify_usb_signed_pdf run; only ca_trust is stubbed."""

	@classmethod
	def setUpClass(cls):
		ca_key, cls.signer_key = _key(), _key()
		ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "F2 Test Software CA")])
		cls.ca = _issue("F2 Test Software CA", ca_key, ca_name, ca_key, 0x0F20, ca=True)
		cls.signer_b = _issue("Certificate B", cls.signer_key, ca_name, ca_key, 0x0B0B)
		cls.pdf = _minimal_pdf()
		cls.signed = cls.pdf + endesive_cms.sign(cls.pdf, dict(_SIGNATURE_META), cls.signer_key, cls.signer_b, [cls.ca], "sha256")

	def setUp(self):
		super().setUp()
		self.generate.return_value = self.pdf
		self.decode.side_effect = usb_signer.decode_signed_pdf_payload
		self.verified = []

		def real_verify(*args):
			with contextlib.redirect_stdout(io.StringIO()):  # endesive prints its own chain diagnostics
				metadata = usb_signer.verify_usb_signed_pdf(*args)
			self.verified.append(metadata)
			return metadata

		self.verify.side_effect = real_verify

	def complete_signed(self, prepared):
		return signing.complete_usb_signing(prepared["session_id"], prepared["nonce"], _b64(self.signed))

	def test_authenticated_a_but_pdf_signed_by_b_is_refused_and_nothing_is_attached(self):
		prepared = self.prepare()
		self.authenticate(prepared, der=LEAF_DER)  # certificate A
		with self.assertRaises(_Thrown) as ctx:
			self.complete_signed(prepared)
		self.assertEqual(signing.CERTIFICATE_MISMATCH_MESSAGE, str(ctx.exception))
		self.assertEqual([_sha(self.signer_b)], [m["fingerprint_sha256"] for m in self.verified])  # real verifier ran
		self.attach.assert_not_called()
		self.assertEqual([], self.stored_records())
		self.assertEqual(1, self.auth.call_count)  # B is never authenticated as a substitute

	def test_control_authenticated_b_and_signed_by_b_is_attached(self):
		prepared = self.prepare()
		self.authenticate(prepared, der=_der(self.signer_b))
		result = self.complete_signed(prepared)
		self.attach.assert_called_once()
		self.assertEqual(self.signed, self.attach.call_args.args[1])
		(stored,) = self.stored_records()
		self.assertEqual(hashlib.sha256(self.signed).hexdigest(), stored["signed_pdf_sha256"])
		self.assertEqual(_sha(self.signer_b), result["certificate"]["fingerprint_sha256"])


def _cms_contents(sid_cert, certificates):
	"""A PDF-shaped buffer whose /Contents gap holds a CMS SignedData naming ``sid_cert`` by issuer+serial."""
	sid_tbs = asn1_x509.Certificate.load(_der(sid_cert))["tbs_certificate"]
	signer_info = asn1_cms.SignerInfo(
		{
			"version": "v1",
			"sid": asn1_cms.SignerIdentifier(
				name="issuer_and_serial_number",
				value=asn1_cms.IssuerAndSerialNumber(
					{"issuer": sid_tbs["issuer"], "serial_number": sid_tbs["serial_number"]}
				),
			),
			"digest_algorithm": {"algorithm": "sha256"},
			"signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
			"signature": b"\x00" * 8,
		}
	)
	signed_data = asn1_cms.SignedData(
		{
			"version": "v1",
			"digest_algorithms": [{"algorithm": "sha256"}],
			"encap_content_info": {"content_type": "data"},
			"certificates": [
				asn1_cms.CertificateChoices(name="certificate", value=asn1_x509.Certificate.load(_der(c)))
				for c in certificates
			],
			"signer_infos": [signer_info],
		}
	)
	content = asn1_cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
	buffer = b"<" + content.hex().encode("ascii") + b">"
	return buffer, (0, 0, len(buffer), 0)


class TestSignerCertificateSelection(unittest.TestCase):
	"""H1: the CMS signer is the ONE embedded certificate whose issuer AND serial both match the sid."""

	@classmethod
	def setUpClass(cls):
		key_a, key_b = _key(), _key()
		name_a = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer A")])
		name_b = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer B")])
		cls.signer = _issue("Real Signer", key_a, name_a, key_a, 0x5151)
		cls.same_serial_other_issuer = _issue("Decoy", key_b, name_b, key_b, 0x5151)
		cls.same_issuer_and_serial = _issue("Clone", key_b, name_a, key_b, 0x5151)

	def select(self, certificates):
		buffer, byte_range = _cms_contents(self.signer, certificates)
		return usb_signer._extract_signer_certificate(buffer, byte_range)[0]

	def test_serial_match_under_another_issuer_is_not_the_signer(self):
		chosen = self.select([self.same_serial_other_issuer, self.signer])
		self.assertEqual(_sha(self.signer), _sha(chosen))

	def test_only_a_serial_match_under_another_issuer_is_refused(self):
		with self.assertRaises(USBSignatureError):
			self.select([self.same_serial_other_issuer])

	def test_two_different_certificates_matching_issuer_and_serial_are_refused(self):
		with self.assertRaises(USBSignatureError):
			self.select([self.signer, self.same_issuer_and_serial])

	def test_the_same_certificate_embedded_twice_is_still_one_signer(self):
		self.assertEqual(_sha(self.signer), _sha(self.select([self.signer, self.signer])))


def _ski_cert(cn, key, serial, ski_digest):
	now = datetime.datetime.now(datetime.timezone.utc)
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
	return (
		x509.CertificateBuilder()
		.subject_name(name)
		.issuer_name(name)
		.public_key(key.public_key())
		.serial_number(serial)
		.not_valid_before(now - datetime.timedelta(days=1))
		.not_valid_after(now + datetime.timedelta(days=30))
		.add_extension(x509.SubjectKeyIdentifier(ski_digest), critical=False)
		.sign(key, hashes.SHA256())
	)


def _cms_contents_ski(ski_digest, certificates):
	"""Like _cms_contents, but the signer is named by subjectKeyIdentifier."""
	signer_info = asn1_cms.SignerInfo(
		{
			"version": "v3",
			"sid": asn1_cms.SignerIdentifier(name="subject_key_identifier", value=ski_digest),
			"digest_algorithm": {"algorithm": "sha256"},
			"signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
			"signature": b"\x00" * 8,
		}
	)
	signed_data = asn1_cms.SignedData(
		{
			"version": "v3",
			"digest_algorithms": [{"algorithm": "sha256"}],
			"encap_content_info": {"content_type": "data"},
			"certificates": [
				asn1_cms.CertificateChoices(name="certificate", value=asn1_x509.Certificate.load(_der(c)))
				for c in certificates
			],
			"signer_infos": [signer_info],
		}
	)
	content = asn1_cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
	buffer = b"<" + content.hex().encode("ascii") + b">"
	return buffer, (0, 0, len(buffer), 0)


class TestSignerCertificateSelectionBySki(unittest.TestCase):
	"""Cursor L2: a subjectKeyIdentifier sid must also name exactly ONE distinct embedded certificate."""

	SKI = b"\x11" * 20

	@classmethod
	def setUpClass(cls):
		key_a, key_b = _key(), _key()
		cls.real = _ski_cert("Real Signer", key_a, 0x01, cls.SKI)
		cls.decoy = _ski_cert("Decoy", key_b, 0x02, cls.SKI)

	def select(self, certificates):
		buffer, byte_range = _cms_contents_ski(self.SKI, certificates)
		return usb_signer._extract_signer_certificate(buffer, byte_range)[0]

	def test_one_match_is_the_signer(self):
		self.assertEqual(_sha(self.real), _sha(self.select([self.real])))

	def test_two_different_certificates_with_the_same_ski_are_refused(self):
		with self.assertRaises(USBSignatureError):
			self.select([self.decoy, self.real])

	def test_the_same_certificate_embedded_twice_is_still_one_signer(self):
		self.assertEqual(_sha(self.real), _sha(self.select([self.real, self.real])))


class TestPfxGate(_Base):
	def test_failing_pfx_certificate_is_never_used_to_sign(self):
		for code in ("NOT_CCA_TRUSTED", "REVOKED", "REVOCATION_UNAVAILABLE"):
			with self.subTest(code=code):
				self.events.clear()
				self.auth_results = [ca_trust.CertificateNotAuthenticated(code)]
				with self.assertRaises(_Thrown) as ctx:
					signing.sign_with_pfx("SINV-0001")
				self.assertEqual(ca_trust.MESSAGES[code], str(ctx.exception))
				self.assertNotIn("sign_pdf", self.names())
				self.assertNotIn("attach", self.names())
				self.assertEqual([], self.stored_records())
		self.sign_pdf.assert_not_called()
		self.generate.assert_not_called()

	def test_unexpected_failure_while_authenticating_pfx_fails_closed(self):
		self.auth_results = [ValueError(SENTINEL)]
		with self.assertRaises(_Thrown) as ctx:
			signing.sign_with_pfx("SINV-0001")
		self.assertEqual(signing.CERTIFICATE_NOT_AUTHENTICATED_MESSAGE, str(ctx.exception))
		self.sign_pdf.assert_not_called()
		self.assertNotIn(SENTINEL, self.sinks())

	def test_pfx_certificate_is_authenticated_before_signing_and_record_stored(self):
		result = signing.sign_with_pfx("SINV-0001")
		self.assertEqual(["authenticate", "sign_pdf", "attach", "set_value"], self.names())
		self.assertEqual(LEAF_DER, bytes(self.auth.call_args.args[0]))
		self.pfx_cert.public_bytes.assert_called_once()
		self.load_pfx.assert_called_once_with(b"pfx-bytes", "pfx-password")
		signed_sha = hashlib.sha256(ORIGINAL_PDF + b" pfx signature").hexdigest()
		self.assertEqual([{**_record(), "signed_pdf_sha256": signed_sha}], self.stored_records())
		self.assertIs(True, result["verification"]["verified"])

	def test_pfx_is_read_once_and_the_authenticated_credentials_are_the_ones_that_sign(self):
		# finding 5: no second read of the PFX file between the CCA gate and signing.
		signing.sign_with_pfx("SINV-0001")
		self.get_pfx.assert_called_once()
		self.load_pfx.assert_called_once()
		self.assertIs(self.load_pfx.return_value, self.sign_pdf.call_args.kwargs.get("credentials"))

	def test_sign_pdf_bytes_signs_with_the_given_credentials_without_reloading_the_pfx(self):
		key, cert = object(), mock.MagicMock()
		settings = mock.MagicMock()
		settings.get.side_effect = lambda name, default=None: {"signer_name": "Signer"}.get(name, default)
		with mock.patch.object(pdf_signer, "get_pfx_bytes", side_effect=AssertionError("PFX re-read")), mock.patch.object(
			pdf_signer, "load_pfx_credentials", side_effect=AssertionError("PFX re-loaded")
		), mock.patch.object(pdf_signer, "frappe") as pfr, mock.patch.object(
			pdf_signer, "_signature_metadata", return_value={"name": "Signer"}
		), mock.patch.object(pdf_signer.cms, "sign", return_value=b" sig") as cms_sign:
			pfr.utils.now_datetime.return_value = datetime.datetime(2026, 11, 9, 15, 30)
			pfr.utils.cint.side_effect = lambda v: int(v or 0)
			out = pdf_signer.sign_pdf_bytes(b"%PDF-1.7 x", settings, credentials=(key, cert, ["chain"]))
		self.assertEqual(b"%PDF-1.7 x sig", out)
		args = cms_sign.call_args.args
		self.assertIs(key, args[2])
		self.assertIs(cert, args[3])
		self.assertEqual(["chain"], args[4])
		settings.get_password.assert_not_called()


class TestRecordAndLeaks(_Base):
	def test_record_has_exactly_the_spec_allowlist(self):
		noisy = _record()
		noisy["debug"] = f"pin={SENTINEL}"
		noisy["chain"][0]["der"] = SENTINEL
		noisy["revocation"][0]["raw_response"] = SENTINEL
		prepared = self.prepare()
		self.auth_results = [noisy, noisy]
		self.authenticate(prepared)
		self.complete(prepared)
		(stored,) = self.stored_records()
		# finding 1: the stored record also binds the attached file (SHA-256 of the signed PDF).
		self.assertEqual(SPEC_RECORD_KEYS | {"signed_pdf_sha256"}, set(stored))
		self.assertEqual(SPEC_RECORD_KEYS | {"signed_pdf_sha256"}, set(signing.STORED_RECORD_KEYS))
		self.assertEqual(SPEC_RECORD_KEYS, set(ca_trust.RECORD_KEYS))
		self.assertEqual(hashlib.sha256(ORIGINAL_PDF + b" signature").hexdigest(), stored["signed_pdf_sha256"])
		for item in stored["chain"]:
			self.assertEqual(SPEC_CHAIN_KEYS, set(item))
		for item in stored["revocation"]:
			self.assertEqual(SPEC_REVOCATION_KEYS, set(item))
		self.assertEqual("none", stored["timestamp"])
		self.assertEqual("server clock at verification", stored["signing_time_basis"])
		self.assertNotIn(SENTINEL, self.sinks())
		self.assertNotIn("debug", json.dumps(self.session(prepared) or {}))

	def test_pin_sentinel_in_request_args_and_exceptions_never_reaches_any_sink(self):
		prepared = self.prepare()
		self.authenticate(prepared)
		result = self.complete(prepared, certificate_metadata=json.dumps({"pin": SENTINEL}))
		self.assertIn(SENTINEL, repr(self.verify.call_args))  # it really was in the request
		prepared = self.prepare()
		self.auth_results = [RuntimeError(f"PIN {SENTINEL} rejected")]
		with self.assertRaises(_Thrown):
			self.authenticate(prepared)
		self.auth_results = [KeyError(SENTINEL)]
		with self.assertRaises(_Thrown):
			signing.sign_with_pfx("SINV-0001")
		self.assertNotIn(SENTINEL, self.sinks(result))

	def test_negative_control_detects_a_leak(self):
		self.fr.log_error(title="x", message=SENTINEL)
		with self.assertRaises(AssertionError):
			self.assertNotIn(SENTINEL, self.sinks())


class TestRealCaTrustIntegration(_Base):
	"""The real ca_trust module behind the endpoint, with every outbound request refused (no network)."""

	mock_ca_trust = False

	def setUp(self):
		super().setUp()
		ca_trust.clear_cache()
		self.addCleanup(ca_trust.clear_cache)
		self.urls = []

		def refuse(url, **_kwargs):
			self.urls.append(url)
			raise ca_trust.FetchRefused("offline in tests")

		self._patch(ca_trust, "HttpTransport", return_value=refuse)

	def test_real_owner_leaf_cannot_be_authenticated_offline_so_session_is_not_marked(self):
		prepared = self.prepare()
		with self.assertRaises(_Thrown) as ctx:
			self.authenticate(prepared)
		self.assertEqual(ca_trust.MESSAGES["CA_FETCH_FAILED"], str(ctx.exception))
		self.assertNotIn("authenticated", self.session(prepared))
		self.assertTrue(self.urls)  # it tried the AIA address, through the injected transport only
		self.assertTrue(all(url.startswith(("http://", "https://")) for url in self.urls))
		with self.assertRaises(_Thrown):
			self.complete(prepared)
		self.attach.assert_not_called()


JS_PATH = Path(signing.__file__).parents[1] / "public" / "js" / "sales_invoice.js"


def _function_body(text, name):
	start = text.index(f"function {name}(")
	following = re.search(r"\n(?:async\s+)?function\s|\nclass\s", text[start + 1 :])
	return text[start : start + 1 + following.start()] if following else text[start:]


def _sign_request_body(text):
	body = _function_body(text, "sign_with_usb")
	start = body.index('"/v1/sign"')
	return body[start : body.index("});", start)]


class TestSalesInvoiceJsContract(unittest.TestCase):
	def setUp(self):
		self.text = JS_PATH.read_text(encoding="utf-8")

	def test_sign_request_body_carries_no_pin(self):
		self.assertIsNone(re.search(r"\bpin\b", _sign_request_body(self.text), re.I))

	def test_negative_control_pin_in_sign_body_is_detected(self):
		mutated = self.text.replace("nonce: sign_nonce.nonce,", "nonce: sign_nonce.nonce, pin: entered_pin,", 1)
		self.assertNotEqual(self.text, mutated)
		self.assertIsNotNone(re.search(r"\bpin\b", _sign_request_body(mutated), re.I))

	def test_authenticate_runs_after_certificate_selection_and_before_nonce_and_sign(self):
		body = _function_body(self.text, "sign_with_usb")
		select = body.index("select_local_certificate(")
		authenticate = body.index("erp_dsc_signer.api.signing.authenticate_usb_certificate")
		sign_nonce = body.index('"/v1/nonce"')
		sign = body.index('"/v1/sign"')
		self.assertLess(select, authenticate)
		self.assertLess(authenticate, sign_nonce)
		self.assertLess(sign_nonce, sign)
		call = body[authenticate : body.index("})", authenticate)]
		self.assertIn("certificate_der_base64", call)
		self.assertNotRegex(call, re.compile(r"\bpin\b", re.I))
		self.assertIn("Signed and verified (CCA India chain, revocation checked)", self.text)

	# ---- finding 6: the authenticated certificate must be the selected one, and errors must stop the flow

	def test_authenticated_fingerprint_must_equal_the_selected_one_before_any_nonce(self):
		body = _function_body(self.text, "sign_with_usb")
		match = _AUTH_CALL.search(body)
		self.assertIsNotNone(match, "authenticate result must be awaited into a const")
		result = match.group(1)
		segment = body[match.start() : body.index('"/v1/nonce"')]
		self.assertRegex(segment, re.escape(f"{result}.certificate_sha256 !== selected.fingerprint_sha256"))
		self.assertRegex(segment, re.escape(f"{result}.verified !== true"))
		self.assertIn("throw new Error(", segment[segment.index(f"{result}.certificate_sha256 !==") :])

	def test_authenticate_errors_are_never_swallowed(self):
		self.assertEqual([], _swallow_problems(self.text))

	def test_negative_controls_swallowed_authenticate_errors_are_detected(self):
		start = self.text.index(_AUTH_CALL.search(self.text).group(0))
		end = self.text.index("});", start) + 3
		call = self.text[start:end]
		mutants = {
			"try/catch around authenticate": self.text.replace(call, "try { " + call + " } catch (e) {}", 1),
			".catch on authenticate": self.text.replace(call, call[:-1] + ".catch(() => null);", 1),
			"not awaited": self.text.replace(call, call.replace("await ", "", 1), 1),
			"frappe_request resolves on error": self.text.replace("error: (r) => reject(", "error: (r) => resolve(", 1),
		}
		for label, mutant in mutants.items():
			with self.subTest(label):
				self.assertNotEqual(self.text, mutant)
				self.assertNotEqual([], _swallow_problems(mutant))

	# ---- finding 10: the Desk label

	def test_verified_wording_only_where_the_record_says_verified(self):
		strings = re.findall(r'__\("([^"]*)"', self.text)
		with_verified = sorted({s for s in strings if "erified" in s})
		self.assertEqual(
			["Signed and verified (CCA India chain, revocation checked)", "Verified (CCA India chain, revocation checked)"],
			with_verified,
		)
		self.assertEqual(1, self.text.count("Verified (CCA India chain, revocation checked)"))
		self.assertIn("Verified (CCA India chain", _function_body(self.text, "signature_status_label"))
		alert = self.text.index("Signed and verified (CCA India chain")
		self.assertIn(".verification.verified === true", self.text[alert - 250 : alert])
		refresh = self.text[: self.text.index("function choose_signing_method(")]
		self.assertIn("signature_status_label(frm.doc)", refresh)
		self.assertIn("frm.dashboard.add_indicator(frappe.utils.escape_html(", refresh)

	def test_signature_status_label_behaviour_in_node(self):
		node = shutil.which("node")
		if not node:
			self.skipTest("node is not installed")
		verified, valid = "Verified (CCA India chain, revocation checked)", "Signature valid"
		cases = [
			({"custom_digitally_signed": 1, "custom_signature_verification": '{"verified": true}'}, verified),
			({"custom_digitally_signed": 1, "custom_signature_verification": '{"verified": "true"}'}, valid),
			({"custom_digitally_signed": 1, "custom_signature_verification": '{"verified": 1}'}, valid),
			({"custom_digitally_signed": 1, "custom_signature_verification": '{"verified": false}'}, valid),
			({"custom_digitally_signed": 1, "custom_signature_verification": "not json"}, valid),
			({"custom_digitally_signed": 1, "custom_signature_verification": "null"}, valid),
			({"custom_digitally_signed": 1, "custom_signature_verification": "[true]"}, valid),
			({"custom_digitally_signed": 1}, valid),
			({"custom_digitally_signed": 0, "custom_signature_verification": ""}, None),
			({}, None),
		]
		script = (
			"const __ = (s) => s;\n"
			+ _function_body(self.text, "signature_status_label")
			+ f"\nconst docs = {json.dumps([doc for doc, _ in cases])};\n"
			+ "console.log(JSON.stringify(docs.map((d) => { const s = signature_status_label(d); return s ? s.label : null; })));"
		)
		completed = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
		self.assertEqual(0, completed.returncode, completed.stderr[-500:])
		self.assertEqual([expected for _, expected in cases], json.loads(completed.stdout))


_AUTH_CALL = re.compile(r'const (\w+) = await frappe_request\("erp_dsc_signer\.api\.signing\.authenticate_usb_certificate"')


def _swallow_problems(text):
	"""Ways an authenticate failure could be swallowed so the flow reaches /v1/nonce anyway."""
	problems = []
	body = re.sub(r"^\s*//.*$", "", _function_body(text, "sign_with_usb"), flags=re.M)  # code, not comments
	if not _AUTH_CALL.search(body):
		problems.append("authenticate result is not awaited")
	if len(re.findall(r"\btry\s*\{", body)) != 1:
		problems.append("a try block other than the outer one")
	if ".catch(" in body:
		problems.append("a promise .catch")
	first_catch = re.search(r"\bcatch\b", body)
	if first_catch is None or first_catch.start() < body.index("complete_usb_signing"):
		problems.append("a catch before completion")
	if "error: (r) => reject(" not in _function_body(text, "frappe_request"):
		problems.append("frappe_request does not reject on a server error")
	return problems


class TestSignatureVerificationField(unittest.TestCase):
	def test_fixture_field_is_read_only_long_text_after_the_signing_fields(self):
		fixture = Path(signing.__file__).parents[1] / "fixtures" / "custom_field.json"
		fields = {item["name"]: item for item in json.loads(fixture.read_text(encoding="utf-8"))}
		field = fields.get("Sales Invoice-custom_signature_verification")
		self.assertIsNotNone(field)
		self.assertEqual("Custom Field", field["doctype"])
		self.assertEqual("Sales Invoice", field["dt"])
		self.assertEqual("custom_signature_verification", field["fieldname"])
		self.assertEqual("Long Text", field["fieldtype"])
		self.assertEqual(1, field["read_only"])
		self.assertEqual(0, field.get("hidden", 0))
		self.assertEqual(1, field["no_copy"])
		# finding 1: with allow_on_submit, frappe.client.set_value could forge {"verified": true} on a
		# submitted invoice. Server writes use frappe.db.set_value, which this flag does not restrict.
		self.assertEqual(0, field.get("allow_on_submit", 0))
		self.assertEqual(1, field["print_hide"])  # never printed into a later re-signed PDF
		self.assertEqual("custom_signed_by", field["insert_after"])
		self.assertEqual(fields["Sales Invoice-custom_signed_by"]["module"], field["module"])


if __name__ == "__main__":
	unittest.main()
