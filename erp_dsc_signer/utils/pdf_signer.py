# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from __future__ import annotations

import io
from datetime import datetime

import frappe
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive.pdf import cms
from frappe import _
from frappe.utils.file_manager import get_file_path
from PyPDF2 import PdfReader


PFX_METHOD = "pfx"
USB_METHOD = "usb"


def get_signing_settings(method: str | None = None):
	"""Return enabled settings, validating only the selected signing method."""
	settings = frappe.get_single("DSC Signing Settings")
	if not frappe.utils.cint(settings.get("enabled")):
		frappe.throw(_("Digital signing is disabled in DSC Signing Settings."))

	if method == PFX_METHOD:
		pfx_setting = settings.get("enable_pfx_signing")
		# Existing installations predate the method toggle and are PFX-enabled.
		if pfx_setting is not None and not frappe.utils.cint(pfx_setting):
			frappe.throw(_("PFX signing is disabled in DSC Signing Settings."))
		if not settings.get("pfx_file"):
			frappe.throw(_("Upload a PFX certificate in DSC Signing Settings."))
		if not _settings_pfx_is_valid(settings):
			frappe.throw(_("Validate the PFX certificate in DSC Signing Settings before signing."))

	if method == USB_METHOD and not frappe.utils.cint(settings.get("enable_usb_signing")):
		frappe.throw(_("USB DSC signing is disabled in DSC Signing Settings."))

	return settings


def _settings_pfx_is_valid(settings) -> bool:
	if settings.get("certificate_validation_status") == "Valid":
		return True
	password = settings.get_password("pfx_password", raise_exception=False) or ""
	return bool(check_pfx_certificate(settings.pfx_file, password).get("valid"))


def get_pfx_bytes(settings) -> bytes:
	return get_pfx_bytes_from_url(settings.pfx_file)


def get_pfx_bytes_from_url(pfx_file: str) -> bytes:
	file_path = get_file_path(pfx_file)
	if not file_path:
		frappe.throw(_("Unable to resolve PFX certificate file path."))
	with open(file_path, "rb") as handle:
		return handle.read()


def load_pfx_credentials(pfx_bytes: bytes, password: str | None):
	result = check_pfx_bytes(pfx_bytes, password)
	if not result["valid"]:
		frappe.throw(result["certificate_validation_message"])
	return result["key"], result["cert"], result["othercerts"]


def check_pfx_certificate(pfx_file: str, password: str | None = None) -> dict:
	try:
		pfx_bytes = get_pfx_bytes_from_url(pfx_file)
	except Exception:
		return _validation_result(False, "Invalid", _("Unable to resolve PFX certificate file path."))
	return check_pfx_bytes(pfx_bytes, password)


def check_pfx_bytes(pfx_bytes: bytes, password: str | None) -> dict:
	normalized_password = (password or "").strip()
	if normalized_password:
		try:
			return _build_valid_result(_load_pfx(pfx_bytes, normalized_password.encode("utf-8")))
		except (ValueError, TypeError):
			if _can_open_without_password(pfx_bytes):
				return _validation_result(
					False,
					"Invalid",
					_("This PFX file is not password-protected. Clear the PFX Password field, then validate again."),
				)
			return _validation_result(False, "Invalid", _("Invalid PFX password or corrupt certificate file."))

	for password_bytes in (b"", None):
		try:
			return _build_valid_result(_load_pfx(pfx_bytes, password_bytes), no_password=True)
		except (ValueError, TypeError):
			continue
	return _validation_result(False, "Invalid", _("Invalid PFX password or corrupt certificate file."))


def _load_pfx(pfx_bytes: bytes, password):
	key, cert, othercerts = pkcs12.load_key_and_certificates(
		pfx_bytes,
		password,
		backends.default_backend(),
	)
	if not key or not cert:
		raise ValueError("Missing private key or certificate")
	return key, cert, othercerts


def _can_open_without_password(pfx_bytes: bytes) -> bool:
	for password_bytes in (b"", None):
		try:
			key, cert, _othercerts = _load_pfx(pfx_bytes, password_bytes)
			return bool(key and cert)
		except (ValueError, TypeError):
			continue
	return False


def _build_valid_result(credentials, no_password=False):
	key, cert, othercerts = credentials
	not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
	valid_till = not_after.date().isoformat() if not_after else None
	message = (
		_("PFX certificate verified (no password required).")
		if no_password
		else _("PFX certificate and password verified successfully.")
	)
	return {
		"valid": True,
		"certificate_validation_status": "Valid",
		"certificate_validation_message": message,
		"certificate_subject": cert.subject.rfc4514_string(),
		"certificate_valid_till": valid_till,
		"key": key,
		"cert": cert,
		"othercerts": list(othercerts or []),
	}


def _validation_result(valid, status, message):
	return {
		"valid": valid,
		"certificate_validation_status": status,
		"certificate_validation_message": message,
		"certificate_subject": None,
		"certificate_valid_till": None,
		"key": None,
		"cert": None,
		"othercerts": [],
	}


def get_signature_page_index(pdf_bytes: bytes, page_option: str) -> int:
	if page_option == "First Page":
		return 0
	reader = PdfReader(io.BytesIO(pdf_bytes))
	page_count = len(reader.pages)
	if page_count <= 0:
		frappe.throw(_("Unable to read PDF pages for signing."))
	return page_count - 1


def get_signature_box(settings) -> tuple[int, int, int, int]:
	return (
		int(settings.get("signature_box_x1") or 340),
		int(settings.get("signature_box_y1") or 45),
		int(settings.get("signature_box_x2") or 555),
		int(settings.get("signature_box_y2") or 130),
	)


def sign_pdf_bytes(pdf_bytes: bytes, settings) -> bytes:
	pfx_bytes = get_pfx_bytes(settings)
	pfx_password = settings.get_password("pfx_password", raise_exception=False) or ""
	key, cert, othercerts = load_pfx_credentials(pfx_bytes, pfx_password)

	now = frappe.utils.now_datetime().astimezone()
	tz_offset = _format_tz_offset(now)
	signer_name = (settings.get("signer_name") or "").strip() or _cert_cn(cert)
	signature_meta = _signature_metadata(pdf_bytes, settings, signer_name, now, tz_offset)

	timestamp_url = None
	if frappe.utils.cint(settings.get("enable_timestamp")) and settings.get("timestamp_url"):
		timestamp_url = settings.timestamp_url.strip() or None

	try:
		# Endesive returns only the incremental update; retain the original bytes.
		appended = cms.sign(
			pdf_bytes,
			signature_meta,
			key,
			cert,
			othercerts,
			"sha256",
			timestampurl=timestamp_url,
		)
		return pdf_bytes + appended
	except Exception as exc:
		if timestamp_url:
			frappe.log_error(title="DSC Signing TSA Timestamp Failed", message=str(exc))
			frappe.msgprint(
				_("Could not reach the timestamp authority ({0}). Signing without a trusted timestamp.").format(
					timestamp_url
				),
				indicator="orange",
				alert=True,
			)
			try:
				appended = cms.sign(pdf_bytes, signature_meta, key, cert, othercerts, "sha256")
				return pdf_bytes + appended
			except Exception as retry_exc:
				frappe.log_error(title="DSC PDF Signing Failed (without TSA)", message=str(retry_exc))
				frappe.throw(_("PDF signing failed. Check the PFX certificate and password."))
		frappe.log_error(title="DSC PDF Signing Failed", message=str(exc))
		frappe.throw(_("PDF signing failed. Check the PFX certificate and password."))


def _signature_metadata(pdf_bytes, settings, signer_name, now, tz_offset):
	pretty_date = now.strftime("%Y.%m.%d %H:%M:%S ") + tz_offset
	appearance = {
		"display": f"Digitally signed by {signer_name}\nDate: {pretty_date}",
		"outline": [0, 0, 0],
		"border": 0,
	}
	if settings.get("signature_image"):
		try:
			image_path = get_file_path(settings.signature_image)
			if image_path:
				appearance["icon"] = image_path
		except Exception:
			pass

	return {
		"aligned": 32768,
		"sigflags": 3,
		"sigflagsft": 132,
		"sigpage": get_signature_page_index(pdf_bytes, settings.get("signature_page") or "Last Page"),
		"sigbutton": True,
		"sigfield": "ERPNextSignature",
		"auto_sigfield": True,
		"sigandcertify": False,
		"signaturebox": get_signature_box(settings),
		"name": signer_name,
		"contact": settings.get("contact_email") or frappe.session.user,
		"location": settings.get("certificate_location") or "",
		"signingdate": now.strftime("D:%Y%m%d%H%M%S") + tz_offset,
		"reason": settings.get("signing_reason") or "Digitally signed invoice",
		"application": "ERPNext",
		"signature_appearance": appearance,
	}


def generate_invoice_pdf(doc, print_format: str | None = None, letterhead: str | None = None) -> bytes:
	settings = frappe.get_single("DSC Signing Settings")
	print_format = print_format or settings.get("default_print_format")
	if not print_format:
		frappe.throw(_("Set a Default Print Format in DSC Signing Settings."))

	kwargs = {
		"doctype": doc.doctype,
		"name": doc.name,
		"print_format": print_format,
		"as_pdf": True,
	}
	letter_head_name = letterhead or settings.get("letter_head")
	if letter_head_name:
		kwargs["letterhead"] = letter_head_name
		kwargs["no_letterhead"] = 0
	return frappe.get_print(**kwargs)


def attach_signed_invoice_pdf(doc, signed_pdf: bytes, replace=0, signed_by=None) -> dict:
	"""Attach a signed PDF privately while retaining older files as audit evidence."""
	if not isinstance(signed_pdf, bytes) or not signed_pdf.startswith(b"%PDF-"):
		frappe.throw(_("The signed document is not a valid PDF."))
	if doc.get("custom_digitally_signed") and not frappe.utils.cint(replace):
		frappe.throw(
			_("This invoice is already digitally signed. Enable Replace to sign again."),
			title=_("Already Signed"),
		)

	signing_moment = frappe.utils.now_datetime()
	file_name = f"{doc.name}-signed-{signing_moment.strftime('%Y%m%d-%H%M%S-%f')}.pdf"
	if doc.get("custom_signed_invoice_pdf") and frappe.utils.cint(replace):
		_unlink_previous_signed_file(doc)

	file_doc = frappe.get_doc(
		{
			"doctype": "File",
			"file_name": file_name,
			"attached_to_doctype": doc.doctype,
			"attached_to_name": doc.name,
			"attached_to_field": "custom_signed_invoice_pdf",
			"is_private": 1,
			"content": signed_pdf,
		}
	)
	file_doc.save(ignore_permissions=True)
	frappe.db.set_value(
		"Sales Invoice",
		doc.name,
		{
			"custom_digitally_signed": 1,
			"custom_signed_invoice_pdf": file_doc.file_url,
			"custom_signed_on": signing_moment,
			"custom_signed_by": signed_by or frappe.session.user,
		},
		update_modified=False,
	)
	frappe.msgprint(_("Sales Invoice digitally signed and attached."), indicator="green", alert=True)
	return {"file_url": file_doc.file_url, "file_name": file_doc.file_name}


def _unlink_previous_signed_file(doc):
	old_url = doc.get("custom_signed_invoice_pdf")
	if not old_url:
		return
	old_name = frappe.db.get_value("File", {"file_url": old_url}, "name")
	if old_name:
		# Never delete the old File: detaching only the field preserves the audit trail.
		frappe.db.set_value("File", old_name, "attached_to_field", None)


def _format_tz_offset(dt) -> str:
	offset = dt.utcoffset()
	if offset is None:
		return "+00'00'"
	total = int(offset.total_seconds())
	sign = "+" if total >= 0 else "-"
	total = abs(total)
	return f"{sign}{total // 3600:02d}'{(total % 3600) // 60:02d}'"


def _cert_cn(cert) -> str:
	from cryptography.x509.oid import NameOID

	attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
	return attributes[0].value if attributes else cert.subject.rfc4514_string()
