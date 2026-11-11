# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from __future__ import annotations

import base64
import binascii
import json
import pickle
import secrets
import time
from datetime import datetime, timezone

import frappe
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from frappe import _

from erp_dsc_signer.utils import ca_trust
from erp_dsc_signer.utils.pdf_signer import (
	PFX_METHOD,
	USB_METHOD,
	_cert_cn,
	_signature_metadata,
	stamp_holder_name as _stamp_holder_name,
	attach_signed_invoice_pdf,
	generate_invoice_pdf,
	get_pfx_bytes,
	get_signing_settings,
	load_pfx_credentials,
	sign_pdf_bytes,
	signing_now,
)
from erp_dsc_signer.utils.usb_signer import (
	USBSignatureError,
	decode_signed_pdf_payload,
	sha256_hex,
	validate_prepared_pdf,
	verify_usb_signed_pdf,
)


USB_PROVIDERS = (
	("auto", "Auto-detect"),
	("epass", "ePass"),
	("safenet", "SafeNet"),
	("proxkey", "ProxKey"),
	("watchdata", "WatchData"),
	("generic_pkcs11", "Generic PKCS#11"),
)
_SESSION_PREFIX = "erp_dsc_signer:usb_session:"
VERIFICATION_FIELD = "custom_signature_verification"
# Base64 of the largest DER ca_trust accepts; longer input is refused before decoding.
_MAX_CERT_BASE64_CHARS = 4 * -(-ca_trust.MAX_CERT_BYTES // 3)
_CHAIN_KEYS = ("subject_cn", "sha256")
_REVOCATION_KEYS = ("subject_cn", "method", "status", "responder_host", "produced_at")
# The stored record = the ca_trust record (spec s4) + the SHA-256 of the signed PDF it was attached with.
STORED_RECORD_KEYS = (*ca_trust.RECORD_KEYS, "signed_pdf_sha256")
# Each failed authentication can mean up to 3 AIA GETs plus OCSP/CRL requests and one committed Error Log.
MAX_AUTHENTICATION_FAILURES = 5

# Fixed texts only: no library or exception text ever reaches the user or the log (spec s2, s5).
CERTIFICATE_NOT_AUTHENTICATED_MESSAGE = (
	"The DSC certificate could not be authenticated with the CCA India certifying authority, so the "
	"document was not signed."
)
INVALID_CERTIFICATE_MESSAGE = "The workstation did not send a valid DSC certificate, so the document was not signed."
SESSION_NOT_AUTHENTICATED_MESSAGE = (
	"The DSC certificate was not authenticated for this signing session, so the document was not signed."
)
ALREADY_AUTHENTICATED_MESSAGE = (
	"The DSC certificate for this signing session was already authenticated. Start the signing again."
)
CERTIFICATE_MISMATCH_MESSAGE = (
	"The document was signed with a different certificate than the one that was authenticated, so it was "
	"not attached."
)
SESSION_UNAVAILABLE_MESSAGE = "The USB signing session is invalid, expired, or already used."
TOO_MANY_FAILURES_MESSAGE = (
	"The DSC certificate could not be authenticated after several attempts in this signing session, so the "
	"document was not signed. Start the signing again."
)


@frappe.whitelist()
def get_signing_options():
	"""Return only non-sensitive capabilities needed by the Sales Invoice form."""
	settings = get_signing_settings()
	methods = []
	if frappe.utils.cint(settings.enable_pfx_signing):
		methods.append({"id": PFX_METHOD, "label": _("PFX Certificate")})
	if frappe.utils.cint(settings.enable_usb_signing):
		methods.append({"id": USB_METHOD, "label": _("USB DSC Token")})
	return {
		"methods": methods,
		"default_method": settings.default_signing_method,
		"providers": [{"id": key, "label": _(label)} for key, label in USB_PROVIDERS],
		"local_signer_url": settings.usb_signer_url.rstrip("/"),
	}


@frappe.whitelist()
def sign_with_pfx(name, print_format=None, letterhead=None, replace=0):
	doc = _invoice_for_signing(name, replace)
	settings = get_signing_settings(PFX_METHOD)
	# Same gate as USB (spec s2): the PFX certificate is authenticated before anything is signed. The PFX
	# is read ONCE: the very credentials whose certificate passed the gate are the ones that sign.
	credentials = _pfx_credentials(settings)
	record = _authenticate_or_throw(credentials[1].public_bytes(Encoding.DER))
	pdf_bytes = generate_invoice_pdf(doc, print_format, letterhead)
	signed_pdf = sign_pdf_bytes(pdf_bytes, settings, credentials=credentials)
	result = attach_signed_invoice_pdf(doc, signed_pdf, replace)
	result["verification"] = _store_verification_record(doc.name, record, signed_pdf)
	return result


@frappe.whitelist()
def prepare_usb_signing(name, provider="auto", print_format=None, letterhead=None, replace=0):
	"""Render a bound PDF and create a short-lived, one-use signing session."""
	provider = _validate_provider(provider)
	doc = _invoice_for_signing(name, replace)
	settings = get_signing_settings(USB_METHOD)
	pdf_bytes = generate_invoice_pdf(doc, print_format, letterhead)
	try:
		validate_prepared_pdf(pdf_bytes)
	except USBSignatureError as exc:
		frappe.throw(_(str(exc)))

	session_id, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
	expires = frappe.utils.cint(settings.usb_session_expiry_minutes or 5) * 60
	payload = {
		"user": frappe.session.user,
		"invoice": doc.name,
		"provider": provider,
		"replace": frappe.utils.cint(replace),
		"pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
		"pdf_sha256": sha256_hex(pdf_bytes),
		"nonce": nonce,
		# authenticate_usb_certificate rewrites the session; it must keep this deadline, not extend it.
		"expires_at": int(time.time()) + expires,
	}
	frappe.cache().set_value(_session_key(session_id), json.dumps(payload), expires_in_sec=expires)
	return {
		"session_id": session_id,
		"nonce": nonce,
		"expires_in_seconds": expires,
		"pdf_base64": payload["pdf_base64"],
		"pdf_sha256": payload["pdf_sha256"],
		"signing_request": {
			"hash_algorithm": "sha256",
			"document_name": doc.name,
			"timestamp_url": settings.timestamp_url if frappe.utils.cint(settings.enable_timestamp) else None,
		},
	}


@frappe.whitelist()
def authenticate_usb_certificate(session_id, certificate_der_base64):
	"""Authenticate the selected token certificate against the CCA India chain BEFORE the PIN dialog.

	The session is marked, never consumed: complete_usb_signing consumes it and authenticates again.
	"""
	key, payload = _peek_session(session_id)
	_invoice_for_signing(payload["invoice"], payload["replace"])
	if payload.get("authenticated"):
		frappe.throw(_(ALREADY_AUTHENTICATED_MESSAGE))
	if _failure_count(payload) >= MAX_AUTHENTICATION_FAILURES:
		frappe.throw(_(TOO_MANY_FAILURES_MESSAGE))  # no ca_trust call: no network, no Error Log row
	der = _decode_certificate_der(certificate_der_base64)
	try:
		record = _authenticate_or_throw(der)
	except BaseException:
		_count_failed_authentication(key)
		raise
	# The check above may have taken up to 25 s: re-read NOW, so a session that was completed (consumed) or
	# authenticated meanwhile is neither revived nor overwritten (finding 4).
	fresh = _session_payload(_read_session(key))
	if fresh.get("authenticated"):
		frappe.throw(_(ALREADY_AUTHENTICATED_MESSAGE))
	fresh.update(
		authenticated=True,
		certificate_sha256=sha256_hex(der),
		certificate_der_base64=base64.b64encode(der).decode("ascii"),
		verification=record,
	)
	if not _rewrite_session(key, fresh, _session_seconds_left(fresh)):
		frappe.throw(_(SESSION_UNAVAILABLE_MESSAGE))
	return {
		"verified": True,
		"certificate_sha256": fresh["certificate_sha256"],
		"record": record,
		# The visible stamp names the holder of the authenticated certificate, never a generic label.
		"signature_meta": _stamp_metadata_for(der, fresh),
	}


def _stamp_metadata_for(der, payload):
	now = signing_now()
	holder = _stamp_holder_name(_cert_cn(x509.load_der_x509_certificate(der)))
	pdf_bytes = base64.b64decode(payload["pdf_base64"], validate=True)
	return _signature_metadata(pdf_bytes, get_signing_settings(USB_METHOD), holder, now, _format_tz_offset(now))


@frappe.whitelist()
def complete_usb_signing(session_id, nonce, signed_pdf_base64, certificate_metadata=None):
	"""Consume a prepared session, verify the returned CMS signature, re-authenticate, then attach it."""
	payload = _consume_session(session_id, nonce)
	if payload.get("authenticated") is not True or not payload.get("certificate_sha256"):
		frappe.throw(_(SESSION_NOT_AUTHENTICATED_MESSAGE))
	doc = _invoice_for_signing(payload["invoice"], payload["replace"])
	try:
		original_pdf = base64.b64decode(payload["pdf_base64"], validate=True)
		signed_pdf = decode_signed_pdf_payload(signed_pdf_base64, original_pdf)
		metadata = verify_usb_signed_pdf(original_pdf, signed_pdf, _certificate_metadata_arg(certificate_metadata))
	except USBSignatureError as exc:
		frappe.log_error(title="USB DSC signature rejected", message=str(exc))
		frappe.throw(_(str(exc)))
	signer_sha256 = str(metadata.get("fingerprint_sha256") or "")
	if signer_sha256 != payload["certificate_sha256"]:
		_log_refusal("CERTIFICATE_MISMATCH", signer_sha256)
		frappe.throw(_(CERTIFICATE_MISMATCH_MESSAGE))
	# Equal SHA-256 means the PDF signer IS the certificate authenticated earlier; authenticate it
	# again so revocation is fresh at attach time (spec s2, s8 TOCTOU).
	record = _authenticate_or_throw(_session_certificate_der(payload))
	result = attach_signed_invoice_pdf(doc, signed_pdf, payload["replace"], frappe.session.user)
	result["verification"] = _store_verification_record(doc.name, record, signed_pdf)
	result["certificate"] = metadata
	return result


def _certificate_metadata_arg(value):
	"""frappe.call JSON-encodes nested objects, so the browser's certificate details arrive as a str."""
	if value is None or value == "":
		return {}
	if isinstance(value, str):
		try:
			value = json.loads(value)
		except ValueError:
			raise USBSignatureError("Certificate metadata must be a JSON object.") from None
	if not isinstance(value, dict):
		raise USBSignatureError("Certificate metadata must be a JSON object.")
	return value


def _invoice_for_signing(name, replace):
	frappe.has_permission("Sales Invoice", doc=name, ptype="write", throw=True)
	doc = frappe.get_doc("Sales Invoice", name)
	if doc.docstatus != 1:
		frappe.throw(_("Sales Invoice must be submitted before digital signing."))
	if doc.get("custom_digitally_signed") and not frappe.utils.cint(replace):
		frappe.throw(_("This invoice is already digitally signed. Enable Replace to sign again."), title=_("Already Signed"))
	return doc


def _validate_provider(provider):
	if provider not in {item[0] for item in USB_PROVIDERS}:
		frappe.throw(_("Select a supported USB DSC token provider."))
	return provider


def _session_key(session_id):
	if not isinstance(session_id, str) or not 20 <= len(session_id) <= 128:
		frappe.throw(_("The USB signing session is invalid or has expired."))
	return _SESSION_PREFIX + session_id


def _consume_session(session_id, nonce):
	key = _session_key(session_id)
	# Deleting before verification makes every prepared document strictly one-use.
	raw = _read_session(key)
	frappe.cache().delete_value(key)
	payload = _session_payload(raw)
	if not secrets.compare_digest(str(payload.get("nonce", "")), str(nonce or "")):
		frappe.throw(_("The USB signing session does not belong to this user."))
	return payload


def _peek_session(session_id):
	"""Read a session WITHOUT consuming it; same user binding as _consume_session, plus its deadline."""
	key = _session_key(session_id)
	payload = _session_payload(_read_session(key))
	_session_seconds_left(payload)
	return key, payload


def _read_session(key):
	# expires=True: read Redis itself. Without it frappe serves (and fills) frappe.local.cache, so a change
	# made by another request during this one would be invisible. Sessions are always written with an
	# expiry, which frappe never caches locally, so no stale local copy exists either.
	return frappe.cache().get_value(key, expires=True)


def _rewrite_session(key, payload, seconds_left):
	"""Overwrite an EXISTING session only (redis SET ... XX): a session consumed meanwhile stays gone.

	Same encoding as RedisWrapper.set_value (key via make_key, value pickled by frappe's convention; this
	module only ever pickles its own JSON text and never unpickles anything itself).
	"""
	cache = frappe.cache()
	return bool(cache.set(cache.make_key(key), pickle.dumps(json.dumps(payload)), ex=seconds_left, xx=True))


def _failure_count(payload):
	try:
		return max(0, int(payload.get("auth_failures") or 0))
	except (TypeError, ValueError):
		return MAX_AUTHENTICATION_FAILURES  # a mangled counter fails closed


def _count_failed_authentication(key):
	"""Best effort: the refusal is already decided; a session that is gone has nothing left to count."""
	try:
		payload = json.loads(_read_session(key) or "null")
		if not isinstance(payload, dict) or payload.get("authenticated"):
			return
		seconds_left = int(payload.get("expires_at")) - int(time.time())
		if seconds_left > 0:
			payload["auth_failures"] = _failure_count(payload) + 1
			_rewrite_session(key, payload, seconds_left)
	except Exception:
		return


def _session_payload(raw):
	if not raw:
		frappe.throw(_(SESSION_UNAVAILABLE_MESSAGE))
	try:
		payload = json.loads(raw)
	except (TypeError, ValueError):
		frappe.throw(_("The USB signing session is invalid."))
	if not isinstance(payload, dict) or payload.get("user") != frappe.session.user:
		frappe.throw(_("The USB signing session does not belong to this user."))
	return payload


def _session_seconds_left(payload):
	try:
		left = int(payload.get("expires_at")) - int(time.time())
	except (TypeError, ValueError):
		left = 0
	if left <= 0:
		frappe.throw(_(SESSION_UNAVAILABLE_MESSAGE))
	return left


def _decode_certificate_der(value):
	"""Strict base64 of one DER certificate, capped at ca_trust's 20 KB certificate limit."""
	if not isinstance(value, str) or not value or len(value) > _MAX_CERT_BASE64_CHARS:
		frappe.throw(_(INVALID_CERTIFICATE_MESSAGE))
	try:
		der = base64.b64decode(value, validate=True)
	except (binascii.Error, ValueError):
		der = b""
	if not der or len(der) > ca_trust.MAX_CERT_BYTES:
		frappe.throw(_(INVALID_CERTIFICATE_MESSAGE))
	return der


def _session_certificate_der(payload):
	try:
		der = base64.b64decode(str(payload.get("certificate_der_base64") or ""), validate=True)
	except (binascii.Error, ValueError):
		der = b""
	if not der or sha256_hex(der) != payload["certificate_sha256"]:
		frappe.throw(_(SESSION_NOT_AUTHENTICATED_MESSAGE))
	return der


def _pfx_credentials(settings):
	"""(key, certificate, chain) of the configured PFX, loaded once and passed on to sign_pdf_bytes."""
	password = settings.get_password("pfx_password", raise_exception=False) or ""
	return load_pfx_credentials(get_pfx_bytes(settings), password)


def _utc_now():
	# Spec s3.2: the time used is the server clock at verification (no trusted timestamp).
	return datetime.now(timezone.utc)


def _authenticate_or_throw(der):
	"""Return the allowlisted record for ``der`` or refuse with a fixed message. Never warn-and-continue."""
	try:
		record = _verification_record(ca_trust.authenticate_certificate(der, now=_utc_now()))
	except ca_trust.CertificateNotAuthenticated as exc:
		code = exc.reason_code if exc.reason_code in ca_trust.MESSAGES else None
	except Exception:
		code = None  # fail closed; the exception text is deliberately dropped
	else:
		return record
	# Raised outside the except blocks so no library exception is kept as context.
	_log_refusal(code or "UNEXPECTED_ERROR", sha256_hex(der))
	message = ca_trust.MESSAGES[code] if code else CERTIFICATE_NOT_AUTHENTICATED_MESSAGE
	frappe.throw(_(message), title=_("DSC certificate not authenticated"))


def _verification_record(record):
	"""Copy exactly the spec s4 allowlist out of a ca_trust record; any other key is dropped."""
	if not isinstance(record, dict) or record.get("verified") is not True:
		raise ValueError("not a verified ca_trust record")
	clean = {key: _text(record[key]) for key in ca_trust.RECORD_KEYS}
	clean["verified"] = True
	clean["chain"] = [{key: _text(item[key]) for key in _CHAIN_KEYS} for item in record["chain"]]
	clean["revocation"] = [{key: _text(item.get(key)) for key in _REVOCATION_KEYS} for item in record["revocation"]]
	return clean


def _text(value):
	return None if value is None or isinstance(value, (list, dict)) else str(value)


def _log_refusal(reason_code, certificate_sha256):
	"""The only refusal log (spec s5): reason code + public certificate fingerprint, nothing else."""
	frappe.log_error(
		title="DSC certificate not authenticated",
		message=json.dumps({"reason_code": reason_code, "certificate_sha256": certificate_sha256}, sort_keys=True),
	)
	# frappe/app.py rolls back a POST that raised, which would drop this row. Every caller reaches here
	# before anything is written (no attach yet), so the commit keeps only the log row.
	frappe.db.commit()


def _store_verification_record(invoice_name, record, signed_pdf):
	"""Write the record bound to the attached file; returns exactly what was stored.

	Follows attach_signed_invoice_pdf in the same transaction. frappe.db.set_value is a direct UPDATE, so the
	field needs no allow_on_submit (which would let frappe.client.set_value forge it on a submitted invoice).
	"""
	stored = {key: record[key] for key in ca_trust.RECORD_KEYS}  # record is already _verification_record-clean
	stored["signed_pdf_sha256"] = sha256_hex(signed_pdf)
	frappe.db.set_value(
		"Sales Invoice",
		invoice_name,
		VERIFICATION_FIELD,
		json.dumps(stored, sort_keys=True),
		update_modified=False,
	)
	return stored


def _format_tz_offset(dt):
	offset = dt.utcoffset()
	seconds = int(offset.total_seconds()) if offset else 0
	sign, seconds = ("+", seconds) if seconds >= 0 else ("-", -seconds)
	return f"{sign}{seconds // 3600:02d}'{(seconds % 3600) // 60:02d}'"
