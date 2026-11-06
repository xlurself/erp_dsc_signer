import io
import json
import traceback
import unittest
from pathlib import Path

from erp_dsc_local import dialog_child, pairing, ui
from erp_dsc_local.errors import (
	DIALOG_CAUSES,
	PAIR_FROM_TERMINAL_HINT,
	DialogBusy,
	DialogFailed,
	DialogWedged,
	PairPromptUnavailable,
	PairProofInvalid,
	PairRateLimited,
)
from erp_dsc_local.pairing import (
	PairGuard,
	SiteClaims,
	consent_dialog,
	verify_pairing_proof,
)
from erp_dsc_local.ui import UiBusy


STUB = Path(__file__).resolve().parent / "_stub_child.py"
SENTINEL = "SITE-SENTINEL-4471"


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


class TestClaimsSanitisedAtSource(unittest.TestCase):
	"""verify_pairing_proof applies the dialog's claim rule; nothing raw gets past it."""

	def claims_for(self, site_name, user="ceo@acme.test"):
		opener = _Opener(_ok("https://a.example", site_name=site_name, user=user))
		return verify_pairing_proof("https://a.example", "t" * 32, opener=opener)

	def test_unreadable_characters_become_the_visible_placeholder(self):
		samples = {
			"newline": "Acme\nLtd",
			"escape sequence": "Acme\x1b[2J",
			"RLO U+202E": "Acme ‮etis",
			"ALM U+061C": "Acme؜",
			"soft hyphen U+00AD": "Ac­me",
			"lone surrogate": "Acme\ud800",
			"line separator U+2028": "Acme Ltd",
			"private use": "Acme",
		}
		for label, value in samples.items():
			with self.subTest(label):
				claims = self.claims_for(value, user=value)
				self.assertEqual(dialog_child.CLAIM_UNREADABLE, claims.site_name)
				self.assertEqual(dialog_child.CLAIM_UNREADABLE, claims.user)

	def test_over_long_claim_is_replaced_never_truncated(self):
		limit = dialog_child.MAX_CLAIM_CHARS
		claims = self.claims_for("A" * (limit + 1), user="u" * 500)
		self.assertEqual(dialog_child.CLAIM_TOO_LONG, claims.site_name)
		self.assertEqual(dialog_child.CLAIM_TOO_LONG, claims.user)
		exact = self.claims_for("A" * limit)
		self.assertEqual("A" * limit, exact.site_name)  # the boundary is kept whole

	def test_ordinary_text_is_kept_verbatim(self):
		claims = self.claims_for("Acme Ltd — Mumbai (हिंदी)", user="ceo@acme.test")
		self.assertEqual("Acme Ltd — Mumbai (हिंदी)", claims.site_name)
		self.assertEqual("ceo@acme.test", claims.user)

	def test_missing_claims_stay_empty(self):
		opener = _Opener(_Response({"message": {"ok": True, "origin": "https://a.example"}}))
		claims = verify_pairing_proof("https://a.example", "t" * 32, opener=opener)
		self.assertEqual(SiteClaims(), claims)

	def test_same_rule_as_the_dialog(self):
		corpus = ["", "Acme", "x\n", "‮", "­", "\ud800", "y" * 140, "y" * 141, "हि"]
		for value in corpus:
			with self.subTest(value=value):
				self.assertEqual(dialog_child._clean_claim(value), pairing.sanitise_claim(value))


def consent_reply(result, **fields):
	return {"v": 1, "kind": "consent", "result": result, **fields}


class FakeHost:
	def __init__(self, reply=None, error=None, *, error_context=None):
		self.reply = reply
		self.error = error
		self.error_context = error_context
		self.requests = []

	def run_dialog(self, request):
		self.requests.append(request)
		if self.error is not None:
			if self.error_context is not None:
				try:
					raise ValueError(self.error_context)
				except ValueError:
					raise self.error
			raise self.error
		return self.reply


def _chain(exc):
	seen, stack = [], [exc]
	while stack:
		current = stack.pop()
		if current is None or any(current is s for s in seen):
			continue
		seen.append(current)
		stack += [current.__cause__, current.__context__]
	return seen


class TestConsentRequest(unittest.TestCase):
	"""The consent text is now built by the child from separate fields."""

	def request_for(self, origin, claims=SiteClaims()):
		host = FakeHost(consent_reply("deny"))
		consent_dialog(origin, claims, host=host)
		self.assertEqual(1, len(host.requests))
		return host.requests[0]

	def test_origin_claims_and_warnings_are_separate_fields(self):
		request = self.request_for("https://noise.m.frappe.cloud", SiteClaims(site_name="Acme", user="ceo@acme.test"))
		self.assertEqual(
			{
				"v": 1,
				"kind": "consent",
				"origin": "https://noise.m.frappe.cloud",
				"claims": ["Acme", "ceo@acme.test"],
				"warnings": [],
				"final_try": False,
				"timeout": dialog_child.DEFAULT_DIALOG_SECONDS,
			},
			request,
		)
		for claim in request["claims"]:
			self.assertNotIn("noise.m.frappe.cloud", claim)
		self.assertEqual(request, dialog_child.validate_request(request))

	def test_claims_never_read_as_verified(self):
		# The round-2 finding: callback-supplied name/user must never read as verified.
		request = self.request_for("https://a.example", SiteClaims(site_name="Acme", user="ceo@acme.test"))
		text = json.dumps(request)
		self.assertNotIn("erified", text)
		# The child labels every claim; the label is not something the site can supply.
		self.assertTrue(dialog_child.CLAIM_PREFIX.startswith("as described by the site"))

	def test_absent_claims_send_no_lines(self):
		self.assertEqual([], self.request_for("https://a.example")["claims"])
		self.assertEqual(
			["u@x.test"], self.request_for("https://a.example", SiteClaims(user="u@x.test"))["claims"]
		)

	def test_user_claim_of_any_valid_length_is_sent_whole_and_validates(self):
		for length in (127, 128, 140):
			with self.subTest(length=length):
				user = "u" * length
				request = self.request_for("https://a.example", SiteClaims(user=user))
				self.assertEqual([user], request["claims"])
				self.assertNotEqual(dialog_child.CLAIM_TOO_LONG, request["claims"][0])
				self.assertEqual(request, dialog_child.validate_request(request))

	def test_plain_http_off_loopback_is_a_warning(self):
		self.assertEqual([pairing.HTTP_WARNING], self.request_for("http://erp.internal:8000")["warnings"])
		self.assertIn("unencrypted", pairing.HTTP_WARNING)
		self.assertEqual([], self.request_for("https://a.example")["warnings"])
		self.assertEqual([], self.request_for("http://127.0.0.1:8000")["warnings"])

	def test_the_dialog_states_the_pin_still_applies(self):
		footer = " ".join(dialog_child.CONSENT_FOOTER)
		self.assertIn("PIN", footer)
		self.assertIn("sign documents", footer)

	def test_host_is_required_and_old_names_are_gone(self):
		with self.assertRaises(TypeError):
			consent_dialog("https://a.example", SiteClaims())
		for name in ("build_consent_text", "DIALOG_TIMEOUT_SECONDS", "new_tk_root"):
			self.assertFalse(hasattr(pairing, name), name)


class TestConsentMapping(unittest.TestCase):
	def run_consent(self, host):
		return consent_dialog("https://a.example", SiteClaims(site_name="Acme"), host=host)

	def test_allow_is_true(self):
		self.assertIs(True, self.run_consent(FakeHost(consent_reply("allow"))))

	def test_deny_is_false(self):
		self.assertIs(False, self.run_consent(FakeHost(consent_reply("deny"))))

	def test_timeout_raises_and_is_not_a_denial(self):
		with self.assertRaises(PairPromptUnavailable) as ctx:
			self.run_consent(FakeHost(consent_reply("timeout")))
		self.assertEqual({"cause": "dialog_timeout"}, ctx.exception.details)
		self.assertTrue(ctx.exception.message.endswith(PAIR_FROM_TERMINAL_HINT))

	def test_unavailable_carries_the_child_cause(self):
		for cause in dialog_child.UNAVAILABLE_CAUSES:
			with self.subTest(cause=cause):
				with self.assertRaises(PairPromptUnavailable) as ctx:
					self.run_consent(FakeHost(consent_reply("unavailable", cause=cause)))
				self.assertEqual({"cause": cause}, ctx.exception.details)

	def test_dialog_failed_maps_every_cause_without_a_chain(self):
		for cause in sorted(DIALOG_CAUSES):
			with self.subTest(cause=cause):
				host = FakeHost(error=DialogFailed(cause), error_context=SENTINEL)
				with self.assertRaises(PairPromptUnavailable) as ctx:
					self.run_consent(host)
				exc = ctx.exception
				self.assertEqual({"cause": cause}, exc.details)
				self.assertIsNone(exc.__cause__)
				self.assertIsNone(exc.__context__)
				for item in _chain(exc):
					self.assertNotIn(SENTINEL, repr(item))
				self.assertNotIn(SENTINEL, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))

	def test_ui_busy_is_dialog_busy(self):
		with self.assertRaises(DialogBusy) as ctx:
			self.run_consent(FakeHost(error=UiBusy(), error_context=SENTINEL))
		self.assertIsNone(ctx.exception.__cause__)
		self.assertIsNone(ctx.exception.__context__)

	def test_dialog_wedged_propagates_unchanged(self):
		wedged = DialogWedged()
		with self.assertRaises(DialogWedged) as ctx:
			self.run_consent(FakeHost(error=wedged))
		self.assertIs(wedged, ctx.exception)

	def test_malformed_replies_never_allow_and_never_deny(self):
		for value in (None, "allow", True, consent_reply("entered", value="x"), consent_reply("unavailable", cause="nope")):
			with self.subTest(reply=value):
				with self.assertRaises(PairPromptUnavailable) as ctx:
					self.run_consent(FakeHost(value))
				self.assertEqual({"cause": "dialog_bad_reply"}, ctx.exception.details)


class TestConsentWithRealHost(unittest.TestCase):
	"""The same contract through the real DialogHost and the stub child process."""

	def setUp(self):
		self.host = ui.DialogHost(child_script=STUB)

	def run_mode(self, mode):
		return consent_dialog("https://a.example", SiteClaims(site_name=mode), host=self.host)

	def test_allow_and_deny(self):
		self.assertIs(True, self.run_mode("MODE:result:allow"))
		self.assertIs(False, self.run_mode("MODE:result:deny"))

	def test_timeout_raises(self):
		with self.assertRaises(PairPromptUnavailable) as ctx:
			self.run_mode("MODE:result:timeout")
		self.assertEqual({"cause": "dialog_timeout"}, ctx.exception.details)

	def test_crash_is_unavailable_not_deny(self):
		with self.assertRaises(PairPromptUnavailable) as ctx:
			self.run_mode("MODE:crash")
		self.assertEqual({"cause": "dialog_process_crashed"}, ctx.exception.details)


if __name__ == "__main__":
	unittest.main()
