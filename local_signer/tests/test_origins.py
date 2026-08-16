import unittest

from erp_dsc_local.origins import (
	canonical_origin,
	is_loopback_origin,
	is_transport_secure,
	try_canonical_origin,
)


class TestCanonicalOrigin(unittest.TestCase):
	def test_strips_default_ports(self):
		# The round-2 review finding: a stored "https://host:443" must match the
		# "https://host" a browser sends, or a paired site reads as unpaired.
		self.assertEqual("https://erp.example.com", canonical_origin("https://erp.example.com:443"))
		self.assertEqual("http://erp.example.com", canonical_origin("http://erp.example.com:80"))

	def test_keeps_non_default_ports(self):
		self.assertEqual("http://erp.internal:8000", canonical_origin("http://erp.internal:8000"))
		self.assertEqual("https://erp.example.com:8443", canonical_origin("https://erp.example.com:8443"))

	def test_lowercases_host_only(self):
		self.assertEqual("https://erp.example.com", canonical_origin("https://ERP.Example.COM"))

	def test_accepts_bare_trailing_slash(self):
		self.assertEqual("https://erp.example.com", canonical_origin("https://erp.example.com/"))

	def test_browser_and_stored_forms_agree(self):
		self.assertEqual(
			canonical_origin("https://NOISE.m.frappe.cloud:443/"),
			canonical_origin("https://noise.m.frappe.cloud"),
		)

	def test_ipv6_literal_keeps_brackets(self):
		self.assertEqual("http://[::1]:17777", canonical_origin("http://[::1]:17777"))
		self.assertEqual("http://[::1]", canonical_origin("http://[::1]:80"))

	def test_rejects_non_origins(self):
		for value in (
			"https://erp.example.com/app",       # path
			"https://erp.example.com?a=1",       # query
			"https://erp.example.com#f",         # fragment
			"https://user:pw@erp.example.com",   # credentials
			"ftp://erp.example.com",             # scheme
			"erp.example.com",                   # no scheme
			"https://",                          # no host
			"null",                              # opaque origin
			"",
			None,
			123,
		):
			with self.subTest(value=value):
				with self.assertRaises(ValueError):
					canonical_origin(value)

	def test_rejects_out_of_range_port(self):
		with self.assertRaises(ValueError):
			canonical_origin("https://erp.example.com:99999")

	def test_try_canonical_origin_returns_none(self):
		self.assertIsNone(try_canonical_origin("null"))
		self.assertEqual("https://a.example", try_canonical_origin("https://A.example:443"))


class TestTransportClassification(unittest.TestCase):
	def test_loopback_detection(self):
		self.assertTrue(is_loopback_origin("http://127.0.0.1:8000"))
		self.assertTrue(is_loopback_origin("http://localhost:8000"))
		self.assertTrue(is_loopback_origin("http://[::1]"))
		self.assertFalse(is_loopback_origin("http://erp.internal:8000"))

	def test_plain_http_off_loopback_is_not_secure(self):
		# Drives the "less safe" marking in the consent dialog.
		self.assertTrue(is_transport_secure("https://erp.example.com"))
		self.assertTrue(is_transport_secure("http://127.0.0.1:8000"))
		self.assertFalse(is_transport_secure("http://erp.internal:8000"))


if __name__ == "__main__":
	unittest.main()
