import io
import json
import unittest

from erp_dsc_local.errors import PairProofInvalid, PairRateLimited
from erp_dsc_local.pairing import (
	PairGuard,
	SiteClaims,
	build_consent_text,
	verify_pairing_proof,
)


class _Response(io.BytesIO):
	def __init__(self, payload, status=200):
		super().__init__(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
		self.status = status

	def __enter__(self):
		return self

	def __exit__(self, *exc):
		self.close()
		return False


class _Opener:
	"""Stands in for the HTTP opener; records what the callback actually sent."""

	def __init__(self, response=None, error=None):
		self._response = response
		self._error = error
		self.request = None

	def open(self, request, timeout=None):
		self.request = request
		if self._error:
			raise self._error
		return self._response


def _ok(origin, site_name="Acme Ltd", user="ceo@acme.test"):
	return _Response({"message": {"ok": True, "origin": origin, "site_name": site_name, "user": user}})


class TestVerifyPairingProof(unittest.TestCase):
	def test_returns_claims_on_matching_origin(self):
		opener = _Opener(_ok("https://noise.m.frappe.cloud"))
		claims = verify_pairing_proof("https://noise.m.frappe.cloud", "t" * 32, opener=opener)
		self.assertEqual("Acme Ltd", claims.site_name)
		self.assertEqual("ceo@acme.test", claims.user)

	def test_token_is_posted_in_the_body_never_the_query_string(self):
		opener = _Opener(_ok("https://a.example"))
		verify_pairing_proof("https://a.example", "s" * 32, opener=opener)
		self.assertEqual("POST", opener.request.get_method())
		self.assertNotIn("?", opener.request.full_url)
		self.assertNotIn("s" * 32, opener.request.full_url)
		self.assertIn(b"token=" + b"s" * 32, opener.request.data)

	def test_callback_targets_the_canonical_origin(self):
		opener = _Opener(_ok("https://a.example"))
		verify_pairing_proof("https://A.example:443", "t" * 32, opener=opener)
		self.assertTrue(
			opener.request.full_url.startswith(
				"https://a.example/api/method/erp_dsc_signer.api.pairing.verify_pairing_token"
			),
			opener.request.full_url,
		)

	def test_origin_mismatch_is_rejected(self):
		# A site that confirms a DIFFERENT origin than the browser used.
		opener = _Opener(_ok("https://other.example"))
		with self.assertRaises(PairProofInvalid):
			verify_pairing_proof("https://a.example", "t" * 32, opener=opener)

	def test_non_200_is_rejected(self):
		opener = _Opener(_Response({"message": {"ok": True, "origin": "https://a.example"}}, status=403))
		with self.assertRaises(PairProofInvalid):
			verify_pairing_proof("https://a.example", "t" * 32, opener=opener)

	def test_ok_false_is_rejected(self):
		opener = _Opener(_Response({"message": {"ok": False}}))
		with self.assertRaises(PairProofInvalid):
			verify_pairing_proof("https://a.example", "t" * 32, opener=opener)

	def test_garbage_body_is_rejected(self):
		opener = _Opener(_Response(b"<html>not json</html>"))
		with self.assertRaises(PairProofInvalid):
			verify_pairing_proof("https://a.example", "t" * 32, opener=opener)

	def test_unreachable_site_is_rejected_with_cli_hint(self):
		# Assert against the message itself. An earlier version of this test appended
		# the needle to the haystack, so it could not fail — worse than no test.
		opener = _Opener(error=OSError("connection refused"))
		with self.assertRaises(PairProofInvalid) as ctx:
			verify_pairing_proof("https://a.example", "t" * 32, opener=opener)
		message = ctx.exception.message
		self.assertIn("--allow", message)
		self.assertIn("could not be reached", message)

	def test_malformed_token_never_reaches_the_network(self):
		opener = _Opener(_ok("https://a.example"))
		for token in ("", "short", None, 12345, "x" * 900):
			with self.subTest(token=token):
				with self.assertRaises(PairProofInvalid):
					verify_pairing_proof("https://a.example", token, opener=opener)
		self.assertIsNone(opener.request)


class TestPairGuard(unittest.TestCase):
	def setUp(self):
		self.now = 1000.0
		self.guard = PairGuard(max_attempts_per_hour=3, cooldown_seconds=60, clock=lambda: self.now)

	def test_allows_up_to_the_hourly_cap(self):
		for _ in range(3):
			self.guard.check_and_record()
		with self.assertRaises(PairRateLimited):
			self.guard.check_and_record()

	def test_attempts_age_out_after_an_hour(self):
		for _ in range(3):
			self.guard.check_and_record()
		self.now += 3601
		self.guard.check_and_record()

	def test_denial_triggers_a_global_cooldown(self):
		# Round-1 finding: a per-origin cooldown is bypassed by rotating subdomains,
		# so the cooldown after a Deny must apply to every origin.
		self.guard.check_and_record()
		self.guard.record_denial()
		with self.assertRaises(PairRateLimited):
			self.guard.check_and_record()
		self.now += 61
		self.guard.check_and_record()


class TestConsentText(unittest.TestCase):
	def test_origin_is_present_verbatim(self):
		text = build_consent_text("https://noise.m.frappe.cloud", SiteClaims())
		self.assertIn("https://noise.m.frappe.cloud", text)

	def test_claims_are_labelled_as_unverified(self):
		# The round-2 finding: callback-supplied name/user must never read as verified.
		text = build_consent_text("https://a.example", SiteClaims(site_name="Acme", user="ceo@acme.test"))
		self.assertIn("not verified", text)
		self.assertNotIn("Verified", text)
		self.assertNotIn("VERIFIED", text)

	def test_plain_http_off_loopback_is_flagged(self):
		self.assertIn("unencrypted", build_consent_text("http://erp.internal:8000", SiteClaims()))
		self.assertNotIn("unencrypted", build_consent_text("https://a.example", SiteClaims()))
		self.assertNotIn("unencrypted", build_consent_text("http://127.0.0.1:8000", SiteClaims()))

	def test_states_the_pin_still_applies(self):
		text = build_consent_text("https://a.example", SiteClaims())
		self.assertIn("PIN", text)
		self.assertIn("sign documents", text)


if __name__ == "__main__":
	unittest.main()
