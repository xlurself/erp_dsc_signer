import json
import tempfile
import unittest
from pathlib import Path

from erp_dsc_local.config import ConfigurationError, SignerConfig, load_config
from erp_dsc_local.nonces import NonceStore


class TestConfig(unittest.TestCase):
	def test_shipped_example_loads_and_is_valid_on_every_os(self):
		# Windows test 2026-11-10: the example held "/absolute/path/..." which Windows rejects.
		example = Path(__file__).resolve().parents[1] / "config.example.json"
		load_config(example)
		from pathlib import PurePosixPath, PureWindowsPath
		for paths in json.loads(example.read_text(encoding="utf-8")).get("providers", {}).get("additional_paths", {}).values():
			for item in paths:
				self.assertTrue(PurePosixPath(item).is_absolute() and PureWindowsPath(item).is_absolute(), item)

	def test_bad_additional_path_names_the_entry(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "config.json"
			path.write_text('{"providers":{"additional_paths":{"generic_pkcs11":["relative/lib.dll"]}}}', encoding="utf-8")
			with self.assertRaises(ConfigurationError) as ctx:
				load_config(path)
		self.assertIn("providers.additional_paths.generic_pkcs11[0]", str(ctx.exception))

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

	def write(self, directory, document):
		path = Path(directory) / "config.json"
		path.write_text(json.dumps(document), encoding="utf-8")
		return path

	def test_dev_pin_key_rejected(self):
		# Spec 001: the key is refused at load whatever its value; a config written for a
		# signer that accepted a PIN in the HTTP body must not start silently.
		for value in (True, False, 1, 0, None, "yes"):
			with self.subTest(value=value):
				with tempfile.TemporaryDirectory() as directory:
					path = self.write(directory, {"development": {"allow_pin_in_request": value}})
					with self.assertRaises(ConfigurationError) as ctx:
						load_config(path)
					self.assertIn("development.allow_pin_in_request", ctx.exception.message)
					self.assertIn("no longer supported", ctx.exception.message)

	def test_development_section_without_the_key_still_loads(self):
		with tempfile.TemporaryDirectory() as directory:
			load_config(self.write(directory, {"development": {}}))
			load_config(self.write(directory, {}))

	def test_config_no_longer_has_a_body_pin_switch(self):
		with tempfile.TemporaryDirectory() as directory:
			config = load_config(self.write(directory, {}))
		self.assertFalse(hasattr(config, "allow_development_pin_in_request"))
		self.assertNotIn("allow_development_pin_in_request", SignerConfig.__dataclass_fields__)


class TestNonceStore(unittest.TestCase):
	def test_nonce_is_one_use_and_origin_bound(self):
		store = NonceStore(60, 2)
		nonce, _ttl = store.issue("https://erp.example.com", "sign")
		store.consume(nonce, "https://erp.example.com", "sign")
		with self.assertRaises(Exception):
			store.consume(nonce, "https://erp.example.com", "sign")
