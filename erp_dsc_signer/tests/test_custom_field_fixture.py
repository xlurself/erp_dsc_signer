import ast
import json
import unittest
from pathlib import Path

APP = Path(__file__).parents[1]


def _fixture_fields():
	return json.loads((APP / "fixtures" / "custom_field.json").read_text(encoding="utf-8"))


def _hooks_custom_field_filter():
	"""Names kept by the hooks.py ``fixtures`` filter for Custom Field (static parse; no site needed)."""
	tree = ast.parse((APP / "hooks.py").read_text(encoding="utf-8"))
	for node in tree.body:
		if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "fixtures" for t in node.targets):
			for entry in ast.literal_eval(node.value):
				if isinstance(entry, dict) and entry.get("dt") == "Custom Field":
					for field, operator, values in entry["filters"]:
						if field == "name" and operator == "in":
							return set(values)
	return set()


class TestSalesInvoiceCustomFields(unittest.TestCase):
	def test_signing_fields_are_never_copied(self):
		sales_invoice_fields = [item for item in _fixture_fields() if item["dt"] == "Sales Invoice"]
		self.assertEqual(6, len(sales_invoice_fields))
		self.assertEqual([], [item["fieldname"] for item in sales_invoice_fields if item.get("no_copy") != 1])

	def test_signature_verification_record_cannot_be_changed_after_submit(self):
		# finding 1: allow_on_submit would let frappe.client.set_value forge {"verified": true}.
		fields = {item["name"]: item for item in _fixture_fields()}
		field = fields["Sales Invoice-custom_signature_verification"]
		self.assertEqual(0, field.get("allow_on_submit", 0))
		self.assertEqual(1, field["read_only"])
		self.assertEqual(1, field["no_copy"])
		self.assertEqual(1, field["print_hide"])

	def test_hooks_fixture_filter_exports_every_fixture_field(self):
		# export-fixtures writes only the filtered names: a field missing here is dropped on the next export.
		names = {item["name"] for item in _fixture_fields() if item["doctype"] == "Custom Field"}
		self.assertIn("Sales Invoice-custom_signature_verification", names)
		self.assertEqual(set(), names - _hooks_custom_field_filter())
