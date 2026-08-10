import tempfile
import unittest
from pathlib import Path

from erp_dsc_local.config import ConfigurationError, load_config
from erp_dsc_local.nonces import NonceStore


class TestConfig(unittest.TestCase):
	def test_rejects_non_loopback_host(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "config.json"
			path.write_text('{"host":"0.0.0.0","allowed_origins":["https://erp.example.com"]}', encoding="utf-8")
			with self.assertRaises(ConfigurationError):
				load_config(path)

	def test_requires_exact_origin(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "config.json"
			path.write_text('{"allowed_origins":["https://erp.example.com"]}', encoding="utf-8")
			config = load_config(path)
			self.assertEqual(frozenset({"https://erp.example.com"}), config.allowed_origins)


class TestNonceStore(unittest.TestCase):
	def test_nonce_is_one_use_and_origin_bound(self):
		store = NonceStore(60, 2)
		nonce, _ttl = store.issue("https://erp.example.com", "sign")
		store.consume(nonce, "https://erp.example.com", "sign")
		with self.assertRaises(Exception):
			store.consume(nonce, "https://erp.example.com", "sign")
