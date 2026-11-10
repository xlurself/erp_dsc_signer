"""Install metadata that Frappe Cloud and bench read. These tests need no site."""
import ast
import re
import unittest
from pathlib import Path

APP = Path(__file__).parents[1]
ROOT = APP.parent


def _hooks_value(name):
	tree = ast.parse((APP / "hooks.py").read_text(encoding="utf-8"))
	for node in tree.body:
		if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
			return ast.literal_eval(node.value)
	return None


def _pyproject():
	return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


class TestAppMetadata(unittest.TestCase):
	def test_erpnext_is_a_declared_requirement(self):
		# The custom fields attach to Sales Invoice, so ERPNext must be installed first.
		# Same form hrms and india_compliance use ("frappe/erpnext"); Frappe Cloud reads org/repo.
		self.assertIn("frappe/erpnext", _hooks_value("required_apps") or [])

	def test_supported_frappe_range_covers_14_15_and_16(self):
		match = re.search(r'frappe\s*=\s*"([^"]+)"', _pyproject().split("[tool.bench.frappe-dependencies]")[1])
		self.assertIsNotNone(match)
		spec = match.group(1)
		self.assertIn(">=14.0.0", spec)
		upper = re.search(r"<\s*(\d+)\.", spec)
		self.assertIsNotNone(upper)
		self.assertGreaterEqual(int(upper.group(1)), 17)  # v16 must be inside the range

	def test_cryptography_range_allows_the_version_each_frappe_pins(self):
		# Frappe 14/15 pin cryptography~=44.0.1, Frappe 16 pins ~=50.0.0: the app must allow both.
		match = re.search(r'"cryptography([^"]*)"', _pyproject())
		self.assertIsNotNone(match)
		spec = match.group(1)
		self.assertIn(">=42", spec)
		upper = re.search(r"<\s*(\d+)", spec)
		self.assertIsNotNone(upper, "cryptography needs an upper bound so a new major cannot break Frappe's pyOpenSSL")
		self.assertGreaterEqual(int(upper.group(1)), 51)


if __name__ == "__main__":
	unittest.main()
