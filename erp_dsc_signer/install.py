# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

import frappe
from frappe import _


def before_install():
	"""Prevent two apps from owning the same Sales Invoice signing fields."""
	if "erp_pdf_signer" in frappe.get_installed_apps():
		frappe.throw(
			_(
				"ERP PDF Signer is installed on this site. Uninstall it before installing ERP DSC Signer "
				"because both apps manage the same Sales Invoice signing fields."
			)
		)
