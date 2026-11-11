"""Settings rules requested 2026-11-11 after the first Cloud test.

* The trusted timestamp is OFF on a new install (the helper reaches the TSA from the user's
  network; a blocked network failed every signing with stage=tsa).
* DSC Signing Settings cannot be saved until a Sales Invoice print format (the invoice template
  the signed PDF is made from) is chosen.
"""

import json
import unittest
from pathlib import Path
from unittest import mock

import frappe

from erp_dsc_signer.erp_dsc_signer.doctype.dsc_signing_settings import dsc_signing_settings as settings_module

DOCTYPE = Path(settings_module.__file__).with_name("dsc_signing_settings.json")


def _field(name):
	return next(item for item in json.loads(DOCTYPE.read_text(encoding="utf-8"))["fields"] if item["fieldname"] == name)


class FixtureTests(unittest.TestCase):
	def test_timestamp_is_off_by_default(self):
		self.assertIn(str(_field("enable_timestamp").get("default", "0")), ("0", ""))

	def test_the_invoice_template_is_a_required_field(self):
		self.assertEqual(1, _field("default_print_format").get("reqd"))


class PrintFormatCheckTests(unittest.TestCase):
	def run_check(self, value, row):
		with mock.patch.object(frappe, "throw", side_effect=frappe.ValidationError) as throw, mock.patch.object(
			frappe, "db", mock.Mock(get_value=mock.Mock(return_value=row)), create=True
		):
			try:
				settings_module.check_invoice_print_format(value)
			except frappe.ValidationError:
				return True, throw
			return False, throw

	def test_empty_is_refused(self):
		for value in (None, "", "  "):
			with self.subTest(value=value):
				self.assertTrue(self.run_check(value, None)[0])

	def test_unknown_other_doctype_or_disabled_is_refused(self):
		self.assertTrue(self.run_check("Nope", None)[0])
		self.assertTrue(self.run_check("PO", frappe._dict(doc_type="Purchase Order", disabled=0))[0])
		self.assertTrue(self.run_check("Old", frappe._dict(doc_type="Sales Invoice", disabled=1))[0])

	def test_an_enabled_sales_invoice_format_is_accepted(self):
		refused, _throw = self.run_check("Tax Invoice", frappe._dict(doc_type="Sales Invoice", disabled=0))
		self.assertFalse(refused)

	def test_validate_runs_the_check_even_when_signing_is_disabled(self):
		document = settings_module.DSCSigningSettings.__new__(settings_module.DSCSigningSettings)
		document.default_print_format = ""
		document.enabled = 0
		calls = []
		with mock.patch.object(settings_module, "check_invoice_print_format", side_effect=calls.append), mock.patch.object(
			settings_module.DSCSigningSettings, "_validate_pfx", return_value=None
		):
			document.validate()
		self.assertEqual([""], calls)
