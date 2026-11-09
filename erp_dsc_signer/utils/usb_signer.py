# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone

from asn1crypto import cms as asn1_cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID
from endesive.pdf import verify as verify_pdf_signatures


MAX_PDF_BYTES = 50 * 1024 * 1024
MAX_INCREMENTAL_UPDATE_BYTES = 8 * 1024 * 1024
_BYTE_RANGE_RE = re.compile(
	r"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]".encode("ascii")
)


class USBSignatureError(ValueError):
	"""Raised when a workstation result cannot be accepted safely."""


def validate_prepared_pdf(pdf_bytes: bytes) -> None:
	if not isinstance(pdf_bytes, bytes) or b"%PDF-" not in pdf_bytes[:1024]:
		raise USBSignatureError("The generated document is not a valid PDF.")
	if len(pdf_bytes) > MAX_PDF_BYTES:
		raise USBSignatureError("The generated PDF is too large for workstation signing.")
	if _find_byte_ranges(pdf_bytes):
		raise USBSignatureError("The generated PDF unexpectedly already contains a signature.")


def decode_signed_pdf_payload(encoded_payload: str, original_pdf: bytes) -> bytes:
	"""Decode either a complete signed PDF or Endesive-style appended bytes."""
	if not isinstance(encoded_payload, str) or not encoded_payload:
		raise USBSignatureError("The workstation did not return a signed PDF.")

	payload = encoded_payload.strip()
	if payload.lower().startswith("data:"):
		header, separator, payload = payload.partition(",")
		if not separator or ";base64" not in header.lower():
			raise USBSignatureError("The signed PDF data URL is invalid.")

	max_encoded_size = ((len(original_pdf) + MAX_INCREMENTAL_UPDATE_BYTES + 2) // 3) * 4 + 16
	if len(payload) > max_encoded_size:
		raise USBSignatureError("The signed PDF response is too large.")
	try:
		decoded = base64.b64decode(payload, validate=True)
	except (ValueError, binascii.Error) as exc:
		raise USBSignatureError("The workstation returned invalid base64 PDF data.") from exc
	if not decoded:
		raise USBSignatureError("The workstation returned an empty signed PDF.")

	if decoded.startswith(original_pdf):
		full_pdf = decoded
	elif decoded.startswith(b"%PDF-"):
		# A different complete PDF must never replace the exact server rendering.
		raise USBSignatureError("The returned PDF does not match the prepared invoice.")
	else:
		full_pdf = original_pdf + decoded

	if not full_pdf.startswith(original_pdf):
		raise USBSignatureError("The returned PDF does not preserve the prepared invoice bytes.")
	if len(full_pdf) <= len(original_pdf):
		raise USBSignatureError("The returned PDF does not contain a new signature.")
	if len(full_pdf) - len(original_pdf) > MAX_INCREMENTAL_UPDATE_BYTES:
		raise USBSignatureError("The PDF signature update is unexpectedly large.")
	return full_pdf


def verify_usb_signed_pdf(
	original_pdf: bytes,
	signed_pdf: bytes,
	reported_metadata: dict | None = None,
) -> dict:
	"""Verify prefix binding, whole-file ByteRange, CMS signature, and signer cert."""
	validate_prepared_pdf(original_pdf)
	if not signed_pdf.startswith(original_pdf):
		raise USBSignatureError("The returned PDF does not preserve the prepared invoice bytes.")

	ranges = _find_byte_ranges(signed_pdf)
	if signed_pdf.count(b"/ByteRange") != len(ranges) or len(ranges) != 1:
		raise USBSignatureError("The signed PDF must contain exactly one well-formed PDF signature.")
	byte_range = ranges[0]
	_validate_whole_file_byte_range(signed_pdf, byte_range, len(original_pdf))

	try:
		verification_results = verify_pdf_signatures(signed_pdf)
	except Exception as exc:
		raise USBSignatureError("The embedded PDF signature could not be parsed.") from exc
	if len(verification_results) != 1:
		raise USBSignatureError("The embedded PDF signature could not be verified unambiguously.")
	hash_ok, signature_ok, chain_trusted = verification_results[0]
	if not hash_ok or not signature_ok:
		raise USBSignatureError("The PDF digest or cryptographic signature is invalid.")

	signer_certificate, digest_algorithm = _extract_signer_certificate(signed_pdf, byte_range)
	if digest_algorithm != "sha256":
		raise USBSignatureError("The DSC signer must use SHA-256.")
	_validate_certificate(signer_certificate)
	metadata = _certificate_metadata(signer_certificate, bool(chain_trusted))
	_validate_reported_metadata(metadata, reported_metadata or {})
	return metadata


def sha256_hex(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()


def _find_byte_ranges(pdf_bytes: bytes) -> list[tuple[int, int, int, int]]:
	return [tuple(int(value) for value in match.groups()) for match in _BYTE_RANGE_RE.finditer(pdf_bytes)]


def _validate_whole_file_byte_range(pdf_bytes, byte_range, original_length):
	first_offset, first_length, second_offset, second_length = byte_range
	if first_offset != 0:
		raise USBSignatureError("The PDF signature ByteRange must begin at byte zero.")
	if not 0 < first_length < second_offset <= len(pdf_bytes):
		raise USBSignatureError("The PDF signature ByteRange offsets are invalid.")
	if second_length < 0 or second_offset + second_length != len(pdf_bytes):
		raise USBSignatureError("The signature does not cover the complete returned PDF.")
	if first_length < original_length:
		raise USBSignatureError("The signature does not cover the complete prepared invoice.")
	if pdf_bytes[first_length : first_length + 1] != b"<":
		raise USBSignatureError("The PDF signature contents gap is malformed.")
	if pdf_bytes[second_offset - 1 : second_offset] != b">":
		raise USBSignatureError("The PDF signature contents gap is malformed.")


def _extract_signer_certificate(pdf_bytes, byte_range):
	_first_offset, first_length, second_offset, _second_length = byte_range
	hex_contents = pdf_bytes[first_length + 1 : second_offset - 1]
	try:
		cms_bytes = bytes.fromhex(hex_contents.decode("ascii"))
		content_info = asn1_cms.ContentInfo.load(cms_bytes)
	except Exception as exc:
		raise USBSignatureError("The embedded CMS signature is malformed.") from exc
	if content_info["content_type"].native != "signed_data":
		raise USBSignatureError("The PDF signature does not contain CMS SignedData.")

	signed_data = content_info["content"]
	signer_infos = signed_data["signer_infos"]
	if len(signer_infos) != 1:
		raise USBSignatureError("The PDF must contain exactly one CMS signer.")
	signer_info = signer_infos[0]
	digest_algorithm = signer_info["digest_algorithm"]["algorithm"].native
	sid = signer_info["sid"]

	certificates = []
	for certificate_choice in signed_data["certificates"]:
		if certificate_choice.name == "certificate":
			try:
				certificates.append(x509.load_der_x509_certificate(certificate_choice.chosen.dump()))
			except Exception:
				continue
	if not certificates:
		raise USBSignatureError("The CMS signature does not include the signer certificate.")

	signer_certificate = None
	if sid.name == "issuer_and_serial_number":
		# Issuer AND serial must both match, and match exactly ONE distinct certificate: a serial is unique
		# only per issuer, so a serial-only match could pick a decoy certificate embedded first.
		serial_number = sid.chosen["serial_number"].native
		issuer_der = sid.chosen["issuer"].dump()
		matches = {
			certificate.fingerprint(hashes.SHA256()): certificate
			for certificate in certificates
			if certificate.serial_number == serial_number and _issuer_der(certificate) == issuer_der
		}
		if len(matches) == 1:
			signer_certificate = next(iter(matches.values()))
	elif sid.name == "subject_key_identifier":
		key_identifier = sid.chosen.native
		for certificate in certificates:
			try:
				digest = certificate.extensions.get_extension_for_oid(
					ExtensionOID.SUBJECT_KEY_IDENTIFIER
				).value.digest
			except x509.ExtensionNotFound:
				continue
			if digest == key_identifier:
				signer_certificate = certificate
				break
	if signer_certificate is None:
		raise USBSignatureError("The CMS signer identifier does not match an embedded certificate.")
	return signer_certificate, digest_algorithm


def _issuer_der(certificate):
	"""The issuer Name exactly as encoded in the certificate (no re-encoding, no normalisation)."""
	try:
		return asn1_x509.Certificate.load(certificate.public_bytes(Encoding.DER))["tbs_certificate"]["issuer"].dump()
	except Exception:
		return None


def _validate_certificate(certificate):
	now = datetime.now(timezone.utc)
	not_before = getattr(certificate, "not_valid_before_utc", None)
	if not_before is None:
		not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
	not_after = getattr(certificate, "not_valid_after_utc", None)
	if not_after is None:
		not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
	if now < not_before:
		raise USBSignatureError("The DSC certificate is not valid yet.")
	if now > not_after:
		raise USBSignatureError("The DSC certificate has expired.")

	try:
		key_usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
	except x509.ExtensionNotFound:
		key_usage = None
	if key_usage and not (key_usage.digital_signature or key_usage.content_commitment):
		raise USBSignatureError("The DSC certificate is not permitted to create digital signatures.")


def _certificate_metadata(certificate, chain_trusted):
	not_before = getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before
	not_after = getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after
	return {
		"subject": certificate.subject.rfc4514_string(),
		"issuer": certificate.issuer.rfc4514_string(),
		"serial_number": str(certificate.serial_number),
		"serial_number_hex": format(certificate.serial_number, "X"),
		"fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
		"valid_from": not_before.isoformat(),
		"valid_until": not_after.isoformat(),
		# Trust-chain availability varies by OS/CCA root store; crypto validity is mandatory.
		"chain_trusted_by_server": chain_trusted,
	}


def _validate_reported_metadata(verified, reported):
	if not isinstance(reported, dict):
		raise USBSignatureError("Certificate metadata must be a JSON object.")
	reported_fingerprint = reported.get("fingerprint_sha256") or reported.get("fingerprint")
	if reported_fingerprint:
		normalized = re.sub(r"[^0-9a-fA-F]", "", str(reported_fingerprint)).lower()
		if len(normalized) != 64 or normalized != verified["fingerprint_sha256"]:
			raise USBSignatureError("The reported DSC certificate fingerprint does not match the PDF signer.")

	reported_serial = reported.get("serial_number") or reported.get("serial")
	if reported_serial is not None:
		value = str(reported_serial).strip().lower().replace(":", "")
		valid_values = {
			verified["serial_number"].lower(),
			verified["serial_number_hex"].lower(),
			"0x" + verified["serial_number_hex"].lower(),
		}
		if value not in valid_values:
			raise USBSignatureError("The reported DSC certificate serial number does not match the PDF signer.")
