# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from __future__ import annotations

import base64
import json
import secrets

import frappe
from frappe import _

from erp_dsc_signer.utils.pdf_signer import (
	PFX_METHOD,
	USB_METHOD,
	_signature_metadata,
	attach_signed_invoice_pdf,
	generate_invoice_pdf,
	get_signing_settings,
	sign_pdf_bytes,
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
	pdf_bytes = generate_invoice_pdf(doc, print_format, letterhead)
	return attach_signed_invoice_pdf(doc, sign_pdf_bytes(pdf_bytes, settings), replace)


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

	now = frappe.utils.now_datetime().astimezone()
	meta = _signature_metadata(pdf_bytes, settings, _("USB DSC signer"), now, _format_tz_offset(now))
	session_id, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
	payload = {
		"user": frappe.session.user,
		"invoice": doc.name,
		"provider": provider,
		"replace": frappe.utils.cint(replace),
		"pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
		"pdf_sha256": sha256_hex(pdf_bytes),
		"nonce": nonce,
	}
	expires = frappe.utils.cint(settings.usb_session_expiry_minutes or 5) * 60
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
			"signature_meta": meta,
			"timestamp_url": settings.timestamp_url if frappe.utils.cint(settings.enable_timestamp) else None,
		},
	}


@frappe.whitelist()
def complete_usb_signing(session_id, nonce, signed_pdf_base64, certificate_metadata=None):
	"""Consume a prepared session, verify the returned CMS signature, then attach it."""
	payload = _consume_session(session_id, nonce)
	doc = _invoice_for_signing(payload["invoice"], payload["replace"])
	try:
		original_pdf = base64.b64decode(payload["pdf_base64"], validate=True)
		signed_pdf = decode_signed_pdf_payload(signed_pdf_base64, original_pdf)
		metadata = verify_usb_signed_pdf(original_pdf, signed_pdf, _certificate_metadata_arg(certificate_metadata))
	except USBSignatureError as exc:
		frappe.log_error(title="USB DSC signature rejected", message=str(exc))
		frappe.throw(_(str(exc)))
	result = attach_signed_invoice_pdf(doc, signed_pdf, payload["replace"], frappe.session.user)
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
	raw = frappe.cache().get_value(key)
	frappe.cache().delete_value(key)
	if not raw:
		frappe.throw(_("The USB signing session is invalid, expired, or already used."))
	try:
		payload = json.loads(raw)
	except (TypeError, ValueError):
		frappe.throw(_("The USB signing session is invalid."))
	if payload.get("user") != frappe.session.user or not secrets.compare_digest(str(payload.get("nonce", "")), str(nonce or "")):
		frappe.throw(_("The USB signing session does not belong to this user."))
	return payload


def _format_tz_offset(dt):
	offset = dt.utcoffset()
	seconds = int(offset.total_seconds()) if offset else 0
	sign, seconds = ("+", seconds) if seconds >= 0 else ("-", -seconds)
	return f"{sign}{seconds // 3600:02d}'{(seconds % 3600) // 60:02d}'"
