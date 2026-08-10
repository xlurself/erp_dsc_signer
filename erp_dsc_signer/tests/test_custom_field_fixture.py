import json
import unittest
from pathlib import Path


class TestSalesInvoiceCustomFields(unittest.TestCase):
	def test_signing_fields_are_never_copied(self):
		fixture = Path(__file__).parents[1] / "fixtures" / "custom_field.json"
		fields = json.loads(fixture.read_text(encoding="utf-8"))
		sales_invoice_fields = [item for item in fields if item["dt"] == "Sales Invoice"]
		self.assertEqual(5, len(sales_invoice_fields))
		self.assertEqual([], [item["fieldname"] for item in sales_invoice_fields if item.get("no_copy") != 1])
