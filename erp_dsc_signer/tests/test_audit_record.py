"""Audit-record tests: who/when/which invoice is recorded and never a PIN.

Pure unittest + unittest.mock; never touches a real site or database.
"""

import base64
import datetime
import hashlib
import unittest
from unittest import mock

from erp_dsc_signer.api import signing
from erp_dsc_signer.utils import pdf_signer
from erp_dsc_signer.utils.usb_signer import USBSignatureError

SENTINEL = "S3NT1NEL-PIN-9981"
MOMENT = datetime.datetime(2026, 1, 2, 3, 4, 5, 6)
CERT_DER = b"stand-in DER certificate"
CERT_SHA256 = hashlib.sha256(CERT_DER).hexdigest()
VERIFIED_RECORD = {
	"verified": True,
	"checked_at": "2026-01-02T03:04:05+00:00",
	"chain": [{"subject_cn": "Test Signer", "sha256": CERT_SHA256}],
	"root_sha256": "0" * 64,
	"revocation": [],
	"timestamp": "none",
	"signing_time_basis": "server clock at verification",
}


class _Doc(dict):
	"""Minimal stand-in for a Sales Invoice doc (get/name/doctype)."""

	def __init__(self, **kw):
		super().__init__(**kw)
		self.name = "SINV-0001"
		self.doctype = "Sales Invoice"


def _flatten(obj):
	return repr(obj)


class TestAuditRecord(unittest.TestCase):
	def _run(self, doc, signed_by="signer@example.com", leak=None):
		"""Run attach with everything mocked; return (result, captured calls)."""
		file_doc = mock.MagicMock()
		file_doc.file_url = "/private/files/SINV-0001-signed.pdf"
		file_doc.file_name = "SINV-0001-signed.pdf"
		with mock.patch.object(pdf_signer, "frappe") as fr, mock.patch.object(
			pdf_signer, "_"
		, side_effect=lambda s: s):
			fr.utils.now_datetime.return_value = MOMENT
			fr.utils.cint.side_effect = lambda v: int(v or 0)
			fr.session.user = "session@example.com"
			fr.get_doc.return_value = file_doc
			if leak:
				fr.db.set_value.side_effect = lambda *a, **k: fr.log_error(leak)
			result = pdf_signer.attach_signed_invoice_pdf(
				doc, b"%PDF-1.7 body", replace=0, signed_by=signed_by
			)
			return result, fr, file_doc

	def _all_calls_text(self, fr, file_doc):
		return _flatten(
			[
				fr.get_doc.call_args_list,
				fr.db.set_value.call_args_list,
				fr.log_error.call_args_list,
				fr.logger.mock_calls,
				fr.msgprint.call_args_list,
				fr.throw.call_args_list,
				fr.get_doc.return_value.mock_calls,
				file_doc.mock_calls,
			]
		)

	def test_records_signer_and_time(self):
		doc = _Doc()
		_, fr, _fd = self._run(doc)
		args = fr.db.set_value.call_args
		values = args.args[2]
		self.assertEqual("signer@example.com", values["custom_signed_by"])
		self.assertEqual(MOMENT, values["custom_signed_on"])
		self.assertEqual(1, values["custom_digitally_signed"])

	def test_falls_back_to_session_user(self):
		_, fr, _fd = self._run(_Doc(), signed_by=None)
		self.assertEqual("session@example.com", fr.db.set_value.call_args.args[2]["custom_signed_by"])


class TestCompleteUsbSigningAudit(unittest.TestCase):
	"""The real path: api.signing.complete_usb_signing receives certificate_metadata
	and form args from the browser. Everything below it is mocked; no site, no DB."""

	USER = "signer@example.com"

	def _drive(self, leak_into=None, verify_error=None, certificate_metadata=None):
		doc = _Doc()
		doc.docstatus = 1
		# F2: complete_usb_signing only accepts a session that authenticate_usb_certificate marked
		# (tests/test_signing_authenticate.py covers that gate); ca_trust is stubbed below.
		payload = {
			"invoice": doc.name,
			"replace": 0,
			"pdf_base64": "JVBERi0=",
			"authenticated": True,
			"certificate_sha256": CERT_SHA256,
			"certificate_der_base64": base64.b64encode(CERT_DER).decode("ascii"),
		}
		file_doc = mock.MagicMock()
		file_doc.file_url = "/private/files/SINV-0001-signed.pdf"
		file_doc.file_name = "SINV-0001-signed.pdf"
		metadata = {"subject": "CN=Test Signer", "serial": "01", "fingerprint_sha256": CERT_SHA256}
		with mock.patch.object(
			signing.ca_trust, "authenticate_certificate", return_value=VERIFIED_RECORD
		), mock.patch.object(signing, "frappe") as sfr, mock.patch.object(
			pdf_signer, "frappe"
		) as pfr, mock.patch.object(signing, "_consume_session", return_value=payload), mock.patch.object(
			signing, "_invoice_for_signing", return_value=doc
		), mock.patch.object(signing, "decode_signed_pdf_payload", return_value=b"%PDF-1.7 signed"), mock.patch.object(
			signing, "verify_usb_signed_pdf", side_effect=verify_error, return_value=metadata
		) as verify, mock.patch.object(signing, "_", side_effect=lambda s: s), mock.patch.object(
			pdf_signer, "_", side_effect=lambda s: s
		):
			sfr.session.user = self.USER
			sfr.throw.side_effect = RuntimeError("throw")
			pfr.session.user = self.USER
			pfr.utils.now_datetime.return_value = MOMENT
			pfr.utils.cint.side_effect = lambda v: int(v or 0)
			pfr.get_doc.return_value = file_doc
			if leak_into == "set_value":
				pfr.db.set_value.side_effect = lambda *a, **k: pfr.log_error(f"pin={SENTINEL}")
			try:
				result = signing.complete_usb_signing(
					"sess",
					"nonce",
					"b64",
					certificate_metadata=certificate_metadata
					if certificate_metadata is not None
					else {"pin": SENTINEL, "subject": "CN=Test Signer"},
				)
				error = None
			except RuntimeError as exc:
				result, error = None, exc
			return result, error, sfr, pfr, verify

	def _text(self, result, sfr, pfr):
		return repr(
			[
				result,
				sfr.log_error.call_args_list,
				pfr.log_error.call_args_list,
				pfr.db.set_value.call_args_list,
				pfr.get_doc.call_args_list,
				pfr.msgprint.call_args_list,
			]
		)

	def test_browser_sends_certificate_metadata_as_a_json_string(self):
		# frappe.call JSON-encodes nested objects, so the server receives a str, not a dict.
		import json

		_r, error, _sfr, _pfr, verify = self._drive(certificate_metadata=json.dumps({"subject": "CN=Test Signer"}))
		self.assertIsNone(error)
		self.assertEqual({"subject": "CN=Test Signer"}, verify.call_args.args[2])

	def test_garbage_certificate_metadata_is_rejected(self):
		for bad in ("not json", "[1, 2]", "12"):
			with self.subTest(bad=bad):
				_r, error, _sfr, _pfr, verify = self._drive(certificate_metadata=bad)
				self.assertIsNotNone(error)
				verify.assert_not_called()

	def test_records_user_time_and_invoice_name(self):
		result, error, _sfr, pfr, _v = self._drive()
		self.assertIsNone(error)
		args = pfr.db.set_value.call_args
		self.assertEqual("SINV-0001", args.args[1])
		self.assertEqual(self.USER, args.args[2]["custom_signed_by"])
		self.assertEqual(MOMENT, args.args[2]["custom_signed_on"])
		self.assertEqual("SINV-0001", pfr.get_doc.call_args.args[0]["attached_to_name"])
		self.assertEqual(
			{"subject": "CN=Test Signer", "serial": "01", "fingerprint_sha256": CERT_SHA256}, result["certificate"]
		)

	def test_pin_sentinel_in_request_args_never_reaches_any_sink(self):
		result, error, sfr, pfr, verify = self._drive()
		self.assertIsNone(error)
		# the sentinel really was handed to the verifier (so the test is not vacuous)...
		self.assertIn(SENTINEL, repr(verify.call_args))
		# ...and is not in the log, the stored values, the File dict or the return value.
		self.assertNotIn(SENTINEL, self._text(result, sfr, pfr))

	def test_negative_control_detects_a_leak(self):
		result, _error, sfr, pfr, _v = self._drive(leak_into="set_value")
		with self.assertRaises(AssertionError):
			self.assertNotIn(SENTINEL, self._text(result, sfr, pfr))

	def test_rejected_signature_logs_only_the_verifier_message(self):
		# verify_usb_signed_pdf never receives a PIN: its only inputs are the PDF bytes and
		# certificate_metadata (usb_signer.py verify_usb_signed_pdf signature), and every
		# USBSignatureError text it raises is a fixed string (usb_signer.py: all raises are fixed strings, no f-strings), so
		# log_error(message=str(exc)) in api/signing.py cannot carry one.
		result, error, sfr, pfr, _v = self._drive(verify_error=USBSignatureError("The PDF digest is invalid."))
		self.assertIsNotNone(error)
		self.assertIn("The PDF digest is invalid.", repr(sfr.log_error.call_args))
		self.assertNotIn(SENTINEL, self._text(result, sfr, pfr))
		pfr.db.set_value.assert_not_called()


if __name__ == "__main__":
	unittest.main()
