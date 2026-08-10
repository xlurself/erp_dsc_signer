# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document

from erp_dsc_signer.utils.pdf_signer import check_pfx_certificate


ALLOWED_SIGNING_METHODS = {"pfx", "usb"}
LOCAL_SIGNER_HOSTS = {"127.0.0.1", "::1", "localhost"}


class DSCSigningSettings(Document):
	def validate(self):
		self._validate_pfx()

		if not frappe.utils.cint(self.enabled):
			return

		pfx_enabled = frappe.utils.cint(self.enable_pfx_signing)
		usb_enabled = frappe.utils.cint(self.enable_usb_signing)
		if not pfx_enabled and not usb_enabled:
			frappe.throw(_("Enable at least one signing method: PFX or USB DSC."))

		default_method = (self.default_signing_method or "").strip().lower()
		if default_method not in ALLOWED_SIGNING_METHODS:
			frappe.throw(_("Select a valid default signing method."))
		if default_method == "pfx" and not pfx_enabled:
			frappe.throw(_("Enable PFX Signing or select USB as the default method."))
		if default_method == "usb" and not usb_enabled:
			frappe.throw(_("Enable USB DSC Signing or select PFX as the default method."))

		if pfx_enabled:
			self._validate_pfx_configuration()
		if usb_enabled:
			self._validate_usb_configuration()

	def _validate_pfx(self):
		self._reset_validation_status()
		password = self.get_password("pfx_password", raise_exception=False) or ""

		if self.pfx_file:
			self._apply_validation_result(check_pfx_certificate(self.pfx_file, password))
		elif password:
			self.certificate_validation_message = _(
				"Upload the PFX file to validate the certificate."
			)

	def _validate_pfx_configuration(self):
		if not self.pfx_file:
			frappe.throw(_("PFX Certificate File is required when PFX signing is enabled."))
		if self.certificate_validation_status != "Valid":
			frappe.throw(
				_(self.certificate_validation_message or "PFX certificate validation failed."),
				title=_("Invalid Certificate"),
			)

	def _validate_usb_configuration(self):
		url = (self.usb_signer_url or "").strip().rstrip("/")
		parsed = urlparse(url)
		if parsed.scheme not in {"http", "https"} or parsed.hostname not in LOCAL_SIGNER_HOSTS:
			frappe.throw(
				_("Local DSC Signer URL must use HTTP(S) on localhost or 127.0.0.1.")
			)
		if parsed.username or parsed.password or parsed.query or parsed.fragment:
			frappe.throw(_("Local DSC Signer URL cannot contain credentials, a query, or a fragment."))
		if parsed.path not in {"", "/"}:
			frappe.throw(_("Local DSC Signer URL must not contain a path."))

		self.usb_signer_url = url
		expiry_minutes = frappe.utils.cint(self.usb_session_expiry_minutes or 5)
		if not 1 <= expiry_minutes <= 15:
			frappe.throw(_("USB signing session expiry must be between 1 and 15 minutes."))
		self.usb_session_expiry_minutes = expiry_minutes

	def _reset_validation_status(self):
		self.certificate_validation_status = "Not Validated"
		self.certificate_validation_message = None
		self.certificate_subject = None
		self.certificate_valid_till = None

	def _apply_validation_result(self, result):
		self.certificate_validation_status = result["certificate_validation_status"]
		self.certificate_validation_message = result["certificate_validation_message"]
		self.certificate_subject = result.get("certificate_subject")
		self.certificate_valid_till = result.get("certificate_valid_till")
