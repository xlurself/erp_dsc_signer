"""X.509 metadata extraction and deterministic certificate selection."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone

from .errors import LocalSignerError

# Longest ``organization`` the listing reports; the rest is cut.
ORGANIZATION_MAX_CHARS = 256


@dataclass(frozen=True)
class TokenCertificate:
	der: bytes
	key_id: bytes
	label: str
	slot_id: int
	token_label: str
	token_serial: str
	metadata: dict
	crypto_certificate: object


def parse_token_certificate(
	der: bytes,
	key_id: bytes,
	label: str,
	slot_id: int,
	token_label: str,
	token_serial: str,
) -> TokenCertificate:
	try:
		from cryptography import x509
		from cryptography.hazmat.primitives.asymmetric import ec, rsa
	except ImportError as exc:
		raise LocalSignerError(
			"DEPENDENCY_MISSING",
			"The cryptography package is required to inspect DSC certificates.",
			status=503,
		) from exc

	try:
		certificate = x509.load_der_x509_certificate(der)
	except (TypeError, ValueError) as exc:
		raise LocalSignerError("INVALID_CERTIFICATE", "The token returned an invalid X.509 certificate.", status=502) from exc

	not_before = getattr(certificate, "not_valid_before_utc", None) or _as_utc(certificate.not_valid_before)
	not_after = getattr(certificate, "not_valid_after_utc", None) or _as_utc(certificate.not_valid_after)
	public_key = certificate.public_key()
	if isinstance(public_key, rsa.RSAPublicKey):
		key_type, key_size = "RSA", public_key.key_size
	elif isinstance(public_key, ec.EllipticCurvePublicKey):
		key_type, key_size = "EC", public_key.key_size
	else:
		key_type, key_size = type(public_key).__name__, getattr(public_key, "key_size", None)

	digital_signature = None
	try:
		digital_signature = certificate.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
	except x509.ExtensionNotFound:
		pass

	metadata = {
		"fingerprint_sha256": hashlib.sha256(der).hexdigest(),
		"serial_number": format(certificate.serial_number, "X"),
		"serial_number_decimal": str(certificate.serial_number),
		"subject": certificate.subject.rfc4514_string(),
		"issuer": certificate.issuer.rfc4514_string(),
		"common_name": _common_name(certificate.subject),
		# The subject O, from the parsed certificate (never a driver label): the Desk uses it
		# to say whose certificate this is.  Plain text, capped, "" when absent.
		"organization": _organization(certificate.subject),
		"valid_from": not_before.isoformat(),
		"valid_to": not_after.isoformat(),
		"currently_valid": not_before <= datetime.now(timezone.utc) <= not_after,
		"digital_signature": digital_signature,
		"key_type": key_type,
		"key_size": key_size,
		"label": label,
		"slot_id": slot_id,
		"token_label": token_label,
		"token_serial": token_serial,
		# PUBLIC certificate bytes only: the ERP authenticates them against the CCA India hierarchy
		# before the PIN is ever requested. Never key material.
		"der_base64": base64.b64encode(der).decode("ascii"),
	}
	return TokenCertificate(
		der, key_id, label, slot_id, token_label, token_serial, metadata, certificate
	)


def select_certificate(certificates: list[TokenCertificate], selector: object) -> TokenCertificate:
	if not certificates:
		raise LocalSignerError("CERTIFICATE_NOT_FOUND", "No X.509 certificate is available on the selected token.", status=409)
	if selector is None:
		usable = [item for item in certificates if item.metadata["key_type"] == "RSA"]
		if len(usable) == 1:
			return usable[0]
		raise LocalSignerError(
			"CERTIFICATE_SELECTION_REQUIRED",
			"Select a signing certificate by SHA-256 fingerprint or serial number.",
			status=409,
			details={"certificates": [item.metadata for item in certificates]},
		)
	if not isinstance(selector, dict):
		raise LocalSignerError("INVALID_CERTIFICATE_SELECTOR", "certificate must be a JSON object.")

	fingerprint = selector.get("fingerprint_sha256")
	serial = selector.get("serial_number")
	if not fingerprint and not serial:
		raise LocalSignerError(
			"INVALID_CERTIFICATE_SELECTOR",
			"Provide certificate.fingerprint_sha256 or certificate.serial_number.",
		)
	normalized_fp = _normalize_fingerprint(fingerprint) if fingerprint else None
	normalized_serial = _normalize_serial(serial) if serial else None
	for item in certificates:
		fp_matches = normalized_fp is None or item.metadata["fingerprint_sha256"] == normalized_fp
		serial_matches = normalized_serial is None or _normalize_serial(item.metadata["serial_number"]) == normalized_serial
		if fp_matches and serial_matches:
			if item.metadata["key_type"] != "RSA":
				raise LocalSignerError(
					"UNSUPPORTED_KEY_TYPE",
					"This release supports RSA DSC certificates. Select an RSA certificate.",
					status=409,
				)
			return item
	raise LocalSignerError(
		"CERTIFICATE_NOT_FOUND", "The requested certificate was not found on the selected token.", status=409
	)


def build_issuer_chain(selected: TokenCertificate, certificates: list[TokenCertificate]) -> list:
	"""Return token-resident issuer certificates in leaf-to-root order."""
	chain = []
	current = selected.crypto_certificate
	seen = {selected.metadata["fingerprint_sha256"]}
	while current.issuer != current.subject:
		issuer = next(
			(
				item
				for item in certificates
				if item.metadata["fingerprint_sha256"] not in seen
				and item.crypto_certificate.subject == current.issuer
			),
			None,
		)
		if issuer is None:
			break
		chain.append(issuer.crypto_certificate)
		seen.add(issuer.metadata["fingerprint_sha256"])
		current = issuer.crypto_certificate
	return chain


def _common_name(name) -> str:
	try:
		from cryptography.x509.oid import NameOID

		values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
		return values[0].value if values else ""
	except (ImportError, IndexError):
		return ""


def _organization(name) -> str:
	"""The first subject O as plain text: control characters become spaces, format
	characters (bidi overrides, zero-width) are dropped, whitespace is collapsed, and the
	result is capped at ``ORGANIZATION_MAX_CHARS``.  "" when there is no O."""
	from cryptography.x509.oid import NameOID

	values = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
	value = values[0].value if values else ""
	if not isinstance(value, str):
		return ""
	cleaned = "".join(
		" " if unicodedata.category(ch) == "Cc" else "" if unicodedata.category(ch) in ("Cf", "Cs", "Co", "Cn") else ch
		for ch in value
	)
	return re.sub(r"\s+", " ", cleaned).strip()[:ORGANIZATION_MAX_CHARS]


def is_signing_certificate(certificate) -> bool:
	"""True only for an end-entity certificate whose own KeyUsage, if any, allows signing.

	Read from the parsed certificate, never from a driver attribute or a metadata flag.
	Not a signing certificate: a CA (BasicConstraints cA true), a self-issued certificate
	(a root), and one whose KeyUsage is present without digitalSignature or nonRepudiation.
	No KeyUsage extension means unrestricted (RFC 5280 s4.2.1.3), the same rule the server
	applies (ca_trust._require_signing_usage, usb_signer._validate_certificate), so the
	picker never hides a certificate the server would accept.  A certificate whose
	extensions cannot be read is not one.
	"""
	try:
		from cryptography import x509

		if certificate.issuer == certificate.subject:
			return False
		extensions = certificate.extensions
		try:
			if extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
				return False
		except x509.ExtensionNotFound:
			pass
		try:
			usage = extensions.get_extension_for_class(x509.KeyUsage).value
		except x509.ExtensionNotFound:
			return True
		return bool(usage.digital_signature or usage.content_commitment)
	except Exception:
		return False


def _as_utc(value: datetime) -> datetime:
	return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _normalize_fingerprint(value: object) -> str:
	if not isinstance(value, str):
		raise LocalSignerError("INVALID_CERTIFICATE_SELECTOR", "Certificate fingerprint must be a string.")
	normalized = value.lower().replace(":", "").replace(" ", "")
	if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
		raise LocalSignerError("INVALID_CERTIFICATE_SELECTOR", "Certificate fingerprint must be SHA-256 hex.")
	return normalized


def _normalize_serial(value: object) -> str:
	if not isinstance(value, str):
		raise LocalSignerError("INVALID_CERTIFICATE_SELECTOR", "Certificate serial number must be a string.")
	normalized = value.upper().replace("0X", "").replace(":", "").replace(" ", "").lstrip("0") or "0"
	if any(char not in "0123456789ABCDEF" for char in normalized):
		raise LocalSignerError("INVALID_CERTIFICATE_SELECTOR", "Certificate serial number must be hexadecimal.")
	return normalized
