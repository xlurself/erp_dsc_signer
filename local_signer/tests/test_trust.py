import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from erp_dsc_local.trust import STORE_VERSION, TrustStore


class _Clock:
	def __init__(self, now=1_000_000.0):
		self.now = now

	def __call__(self):
		return self.now


class TrustStoreTestCase(unittest.TestCase):
	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		self.path = Path(self._dir.name) / "nested" / "allowed_origins.json"
		self.clock = _Clock()

	def store(self, **kwargs):
		kwargs.setdefault("clock", self.clock)
		return TrustStore(self.path, **kwargs)


class TestAllowAndPersist(TrustStoreTestCase):
	def test_absent_file_is_empty_not_an_error(self):
		self.assertEqual([], self.store().list_origins())

	def test_allow_persists_across_instances(self):
		self.store().allow("https://noise.m.frappe.cloud")
		self.assertTrue(self.store().is_allowed("https://noise.m.frappe.cloud"))

	def test_allow_canonicalises_on_write_and_read(self):
		# Stored with an explicit default port and mixed case; the browser sends neither.
		self.store().allow("https://NOISE.m.frappe.cloud:443")
		reloaded = self.store()
		self.assertTrue(reloaded.is_allowed("https://noise.m.frappe.cloud"))
		self.assertEqual(["https://noise.m.frappe.cloud"], [e["origin"] for e in reloaded.list_origins()])

	def test_allow_is_idempotent(self):
		store = self.store()
		store.allow("https://a.example")
		store.allow("https://a.example")
		self.assertEqual(1, len(store.list_origins()))

	def test_rejects_invalid_origin(self):
		with self.assertRaises(ValueError):
			self.store().allow("not-an-origin")

	def test_enforces_max_origins(self):
		store = self.store(max_origins=2)
		store.allow("https://a.example")
		store.allow("https://b.example")
		with self.assertRaises(ValueError):
			store.allow("https://c.example")
		# Re-allowing an existing origin is still fine at the cap.
		store.allow("https://a.example")

	@unittest.skipIf(os.name == "nt", "POSIX mode bits; Windows reports 0o666 for any writable file")
	def test_file_is_private_and_atomic(self):
		self.store().allow("https://a.example")
		mode = stat.S_IMODE(os.stat(self.path).st_mode)
		self.assertEqual(0o600, mode)
		self.assertEqual(0o700, stat.S_IMODE(os.stat(self.path.parent).st_mode))
		# No temp files left behind by the atomic replace.
		self.assertEqual([], [p.name for p in self.path.parent.glob(".origins-*")])

	def test_claimed_fields_are_recorded_but_named_as_claims(self):
		self.store().allow("https://a.example", site_name="Acme", user="ceo@acme.test")
		entry = self.store().list_origins()[0]
		self.assertEqual("Acme", entry["claimed_site_name"])
		self.assertEqual("ceo@acme.test", entry["claimed_user"])
		self.assertNotIn("site_name", entry)
		self.assertNotIn("verified_user", entry)


class TestRevoke(TrustStoreTestCase):
	def test_revoke_removes_and_persists(self):
		store = self.store()
		store.allow("https://a.example")
		self.assertTrue(store.revoke("https://a.example:443"))
		self.assertFalse(self.store().is_allowed("https://a.example"))

	def test_revoke_unknown_origin_is_false(self):
		self.assertFalse(self.store().revoke("https://absent.example"))

	def test_revoke_invalid_origin_is_false_not_raise(self):
		self.assertFalse(self.store().revoke("garbage"))


class TestDenials(TrustStoreTestCase):
	def test_denial_persists_across_restart(self):
		# Round-1 finding: in-memory denials were wiped by restarting the signer.
		self.store().record_denial("https://evil.example")
		self.assertTrue(self.store().is_denied("https://evil.example"))

	def test_denial_expires(self):
		store = self.store(denial_ttl_seconds=100)
		store.record_denial("https://evil.example")
		self.assertTrue(store.is_denied("https://evil.example"))
		self.clock.now += 101
		self.assertFalse(store.is_denied("https://evil.example"))

	def test_allow_clears_denial(self):
		store = self.store()
		store.record_denial("https://a.example")
		store.allow("https://a.example")
		self.assertFalse(store.is_denied("https://a.example"))


class TestFailClosed(TrustStoreTestCase):
	def _write(self, text):
		self.path.parent.mkdir(parents=True, exist_ok=True)
		self.path.write_text(text, encoding="utf-8")

	def test_corrupt_json_is_empty_and_file_is_left_alone(self):
		self._write("{not json")
		self.assertEqual([], self.store().list_origins())
		self.assertEqual("{not json", self.path.read_text(encoding="utf-8"))

	def test_unknown_version_fails_closed(self):
		self._write(json.dumps({"version": STORE_VERSION + 99, "origins": [{"origin": "https://a.example"}]}))
		store = self.store()
		self.assertEqual([], store.list_origins())
		self.assertFalse(store.is_allowed("https://a.example"))

	def test_missing_version_fails_closed(self):
		self._write(json.dumps({"origins": [{"origin": "https://a.example"}]}))
		self.assertFalse(self.store().is_allowed("https://a.example"))

	def test_invalid_rows_dropped_valid_rows_kept(self):
		self._write(json.dumps({
			"version": STORE_VERSION,
			"origins": [
				{"origin": "https://good.example"},
				{"origin": "https://bad.example/path"},
				{"origin": None},
				"not-a-dict",
			],
		}))
		store = self.store()
		self.assertTrue(store.is_allowed("https://good.example"))
		self.assertEqual(1, len(store.list_origins()))

	def test_symlinked_store_is_refused(self):
		self.path.parent.mkdir(parents=True, exist_ok=True)
		target = self.path.parent / "real.json"
		target.write_text(json.dumps({"version": STORE_VERSION, "origins": [{"origin": "https://a.example"}]}), encoding="utf-8")
		try:
			os.symlink(target, self.path)
		except (OSError, NotImplementedError):
			self.skipTest("symlinks need Administrator or Developer Mode on Windows")
		self.assertFalse(self.store().is_allowed("https://a.example"))


if __name__ == "__main__":
	unittest.main()
