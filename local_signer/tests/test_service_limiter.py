"""Per-token PIN limiter and the pre-dialog token checks on /v1/sign (spec 001 §2, §7).

The token is a scripted fake that logs in through the service's real `login_guard`, so
the limiter is exercised exactly as token.py drives it: `with login_guard as guard`
immediately before C_Login, `guard.check_flags(flags)` on the re-read flags,
`guard.succeeded()` on success, `guard.failed()` only for a wrong PIN.  Which PKCS#11
results count as a wrong PIN is tested against the real token.py in test_token_login.py
and test_token_race.py.  The clock is injected.
"""

import ast
import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.errors import LocalSignerError, PinCancelled, PinIncorrect, PinLocked, PinRateLimited, TokenBusy
from erp_dsc_local.pin import request_pin
from erp_dsc_local.service import (
	MAX_PIN_FAILURES,
	PIN_LOCKOUT_SECONDS,
	TOKEN_LOCK_TIMEOUT_SECONDS,
	PinLimiter,
	SignerService,
)
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost
from test_signature_meta import server_meta  # the full meta the ERP sends


PACKAGE = Path(service_module.__file__).resolve().parent
STUB = Path(__file__).resolve().parent / "_stub_child.py"
ORIGIN_A = "https://noise.m.frappe.cloud"
ORIGIN_B = "https://second-erp.example"
TOKEN_1 = "WD-TOKEN-0001"
TOKEN_2 = "WD-TOKEN-0002"
PDF = b"%PDF-1.4\n% erp-dsc-local test document\n"
CKF_USER_PIN_FINAL_TRY = 0x00020000
CKF_USER_PIN_LOCKED = 0x00040000
RATE_LIMITED = {
	"code": "PIN_RATE_LIMITED",
	"message": "Too many incorrect PINs were entered for this token. Wait a few minutes.",
}


def _request(url, *, method="GET", origin=None, body=None):
	data = json.dumps(body).encode() if body is not None else None
	req = urllib.request.Request(url, data=data, method=method)
	if origin:
		req.add_header("Origin", origin)
	if data is not None:
		req.add_header("Content-Type", "application/json")
	try:
		with urllib.request.urlopen(req, timeout=30) as response:
			return response.status, json.loads(response.read() or b"{}")
	except urllib.error.HTTPError as exc:
		raw = exc.read()
		exc.close()
		return exc.code, json.loads(raw or b"{}")


class FakeClock:
	def __init__(self, now=1000.0):
		self.now = now

	def __call__(self):
		return self.now


class _Certificate:
	slot_id = 1
	metadata = {"fingerprint_sha256": "ab" * 32}

	def __init__(self, serial):
		self.token_serial = serial


class ScriptedToken:
	"""TokenClient stand-in.  `outcomes` scripts each C_Login: ok | incorrect | locked | other."""

	def __init__(self):
		self.flags = 0
		self.serial = TOKEN_1
		self.outcomes = []
		self.entering = []  # every sign_pdf call, before the guard
		self.logins = []  # every C_Login, i.e. inside the guard
		self.holds = []  # per login: an Event to wait on inside the guard
		self.inside = threading.Event()
		self.state_error = None

	def __call__(self, module):
		return self

	def select(self, selector):
		certificate = _Certificate(self.serial)
		return certificate, [certificate]

	def token_state(self, selected):
		if self.state_error:
			raise self.state_error
		return self.flags, selected.token_serial

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		self.entering.append(selected.token_serial)
		with login_guard as guard:
			guard.check_flags(self.flags)  # token.py re-reads the flags here
			self.logins.append(selected.token_serial)
			hold = self.holds.pop(0) if self.holds else None
			if hold is not None:
				self.inside.set()
				hold.wait(10)
			outcome = self.outcomes.pop(0) if self.outcomes else "ok"
			if outcome == "ok":
				guard.succeeded()
			elif outcome == "incorrect":
				guard.failed()
		if outcome == "incorrect":
			raise PinIncorrect()
		if outcome == "locked":
			raise PinLocked()
		if outcome == "other":
			raise LocalSignerError("TOKEN_SIGNING_FAILED", "The USB token could not sign the document.", status=502)
		return pdf_bytes + b"%signed\n", dict(selected.metadata)


class LimiterCase(unittest.TestCase):
	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		config_path = Path(self._dir.name) / "config.json"
		config_path.write_text(json.dumps({"host": "127.0.0.1", "allowed_origins": []}), encoding="utf-8")
		self.config = load_config(config_path)
		self.trust = TrustStore(Path(self._dir.name) / "allowed_origins.json")
		self.trust.allow(ORIGIN_A)
		self.trust.allow(ORIGIN_B)
		self.clock = FakeClock()
		self.prompts = []
		self.prompt_result = "1111"
		self.host = DialogHost(child_script=STUB)
		self.addCleanup(self.host.shutdown)

		def prompt(origin, document_name, *, host, warnings=(), final_try=False):
			self.prompts.append({
				"origin": origin,
				"warnings": list(warnings),
				"final_try": final_try,
				"host": host,
				"token_locked": self.service.pin_limiter.token_lock(self.token.serial).locked(),
			})
			if isinstance(self.prompt_result, BaseException):
				raise self.prompt_result
			return self.prompt_result

		self.service = SignerService(
			self.config, trust_store=self.trust, dialog_host=self.host, pin_prompt=prompt, clock=self.clock
		)
		self.token = ScriptedToken()
		patcher = mock.patch.object(service_module, "TokenClient", self.token)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"
		self.server = self.service.make_server(("127.0.0.1", 0))
		self.addCleanup(self.server.server_close)
		threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
		self.addCleanup(self.server.shutdown)
		self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

	def sign(self, origin=ORIGIN_A, document_name="INV-1"):
		_s, issued = _request(self.base + "/v1/nonce", method="POST", origin=origin, body={"purpose": "sign"})
		return _request(
			self.base + "/v1/sign",
			method="POST",
			origin=origin,
			body={
				"nonce": issued["nonce"],
				"pdf_base64": base64.b64encode(PDF).decode("ascii"),
				"pdf_sha256": hashlib.sha256(PDF).hexdigest(),
				"signing_request": {"signature_meta": server_meta(), "document_name": document_name},
			},
		)

	def fail_login(self, origin=ORIGIN_A):
		self.token.outcomes.append("incorrect")
		status, body = self.sign(origin)
		self.assertEqual(401, status, body)
		self.assertEqual("PIN_INCORRECT", body["error"]["code"])

	def assert_refused_before_dialog(self, origin=ORIGIN_A):
		prompts, entering = len(self.prompts), len(self.token.entering)
		status, body = self.sign(origin)
		self.assertEqual(429, status, body)
		self.assertEqual(RATE_LIMITED, body["error"])
		self.assertEqual(prompts, len(self.prompts), "a rate-limited token must not reach the PIN dialog")
		self.assertEqual(entering, len(self.token.entering))

	def assert_allowed(self, origin=ORIGIN_A, document_name="INV-1"):
		status, body = self.sign(origin, document_name)
		self.assertEqual(200, status, body)


class TestConstants(unittest.TestCase):
	NAMES = ("MAX_PIN_FAILURES", "PIN_LOCKOUT_SECONDS", "TOKEN_LOCK_TIMEOUT_SECONDS")

	def test_values(self):
		self.assertEqual(3, MAX_PIN_FAILURES)
		self.assertEqual(900, PIN_LOCKOUT_SECONDS)
		self.assertEqual(20, TOKEN_LOCK_TIMEOUT_SECONDS)

	def test_each_is_assigned_exactly_once_in_the_package_in_service_py(self):
		found = []
		for path in sorted(PACKAGE.glob("*.py")):
			for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
				targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
				for target in targets:
					if isinstance(target, ast.Name) and target.id in self.NAMES:
						found.append((path.name, target.id))
		self.assertEqual(sorted(("service.py", name) for name in self.NAMES), sorted(found))

	def test_default_clock_is_monotonic(self):
		self.assertIs(time.monotonic, PinLimiter()._clock)


class TestLockout(LimiterCase):
	def test_three_failures_lock_the_token_for_900s_from_the_last_failure(self):
		for when in (1000.0, 1010.0, 1020.0):
			self.clock.now = when
			self.fail_login()
		self.assertEqual(3, len(self.token.logins))
		self.assert_refused_before_dialog()
		self.clock.now = 1020.0 + PIN_LOCKOUT_SECONDS - 1
		self.assert_refused_before_dialog()
		self.clock.now = 1020.0 + PIN_LOCKOUT_SECONDS
		self.assert_allowed()
		self.assertEqual(0, self.service.pin_limiter.failures(TOKEN_1))

	def test_two_failures_do_not_lock(self):
		self.fail_login()
		self.fail_login()
		self.assert_allowed()

	def test_a_later_failure_rearms_the_lockout(self):
		for _ in range(MAX_PIN_FAILURES):
			self.fail_login()
		self.clock.now += PIN_LOCKOUT_SECONDS
		self.fail_login()  # the lockout expired; this failure re-arms it at once
		self.assert_refused_before_dialog()
		self.clock.now += PIN_LOCKOUT_SECONDS - 1
		self.assert_refused_before_dialog()
		self.clock.now += 1
		self.assert_allowed()

	def test_success_clears_the_count(self):
		self.fail_login()
		self.fail_login()
		self.assert_allowed()
		self.fail_login()
		self.fail_login()
		self.assert_allowed()  # 2 consecutive since the success: still allowed

	def test_only_pin_incorrect_counts(self):
		for outcome, status in (("locked", 423), ("other", 502), ("locked", 423), ("other", 502)):
			self.token.outcomes.append(outcome)
			self.assertEqual(status, self.sign()[0])
		self.prompt_result = PinCancelled()
		for _ in range(MAX_PIN_FAILURES):
			self.assertEqual(409, self.sign()[0])
		self.prompt_result = "1111"
		self.assertEqual(0, self.service.pin_limiter.failures(TOKEN_1))
		self.assert_allowed()


class TestPerToken(LimiterCase):
	def test_two_origins_share_one_budget_per_token(self):
		self.fail_login(ORIGIN_A)
		self.fail_login(ORIGIN_B)
		self.fail_login(ORIGIN_A)
		self.assert_refused_before_dialog(ORIGIN_A)
		self.assert_refused_before_dialog(ORIGIN_B)

	def test_another_token_is_not_locked(self):
		for _ in range(MAX_PIN_FAILURES):
			self.fail_login()
		self.token.serial = TOKEN_2
		self.assert_allowed(ORIGIN_A)
		self.token.serial = TOKEN_1
		self.assert_refused_before_dialog(ORIGIN_A)


class TestTokenLock(LimiterCase):
	def test_a_second_request_waits_for_the_lock_and_is_refused_before_its_dialog(self):
		self.fail_login()
		self.fail_login()
		release_a = threading.Event()
		self.addCleanup(release_a.set)
		self.token.holds.append(release_a)
		self.token.outcomes.append("incorrect")  # A's login, the 3rd failure
		asked = []
		real_token_lock = self.service.pin_limiter.token_lock
		self.service.pin_limiter.token_lock = lambda serial: (asked.append(serial), real_token_lock(serial))[1]

		box = {}
		a = threading.Thread(target=lambda: box.setdefault("a", self.sign()), daemon=True)
		a.start()
		self.assertTrue(self.token.inside.wait(10), "request A never reached C_Login")
		b = threading.Thread(target=lambda: box.setdefault("b", self.sign(ORIGIN_B)), daemon=True)
		b.start()
		self.assertTrue(_wait_for(lambda: len(asked) == 2), "request B never asked for the token lock")
		time.sleep(0.1)
		# B waits for the lock A holds BEFORE reading flags: no dialog, so no PIN typed.
		self.assertEqual(3, len(self.prompts), "B must not be prompted while A holds the token")
		self.assertEqual(3, len(self.token.entering))
		release_a.set()
		a.join(10)
		b.join(10)

		self.assertEqual(401, box["a"][0])
		self.assertEqual("PIN_INCORRECT", box["a"][1]["error"]["code"])
		self.assertEqual(429, box["b"][0])
		self.assertEqual(RATE_LIMITED, box["b"][1]["error"])
		self.assertEqual(3, len(self.prompts), "B was refused before its dialog")
		self.assertEqual(3, len(self.token.logins))
		lock = real_token_lock(TOKEN_1)
		self.assertTrue(lock.acquire(blocking=False), "every request must release the token lock")
		lock.release()

	def test_the_lock_is_held_from_the_flags_read_to_the_end_of_sign_pdf(self):
		lock = self.service.pin_limiter.token_lock(TOKEN_1)
		seen = []
		for name in ("select", "token_state", "sign_pdf"):
			real = getattr(self.token, name)
			setattr(self.token, name, _spy(name, real, seen, lock.locked))
		self.assert_allowed()
		self.assertEqual([("select", False), ("token_state", True), ("sign_pdf", True)], seen)
		self.assertEqual([True], [p["token_locked"] for p in self.prompts])
		self.assertFalse(lock.locked())

	def test_every_exit_path_releases_the_lock(self):
		lock = self.service.pin_limiter.token_lock(TOKEN_1)
		cases = [
			("state_error", 409),  # TokenUnavailable from token_state
			("locked_flags", 423),  # PinLocked before the dialog
			("cancelled", 409),  # PinCancelled from the dialog
			("incorrect", 401),  # PinIncorrect from sign_pdf
			("rate_limited", 429),  # PinRateLimited before the dialog
		]
		for case, status in cases:
			with self.subTest(case=case):
				if case == "state_error":
					self.token.state_error = LocalSignerError("TOKEN_UNAVAILABLE", "x", status=409)
				elif case == "locked_flags":
					self.token.flags = CKF_USER_PIN_LOCKED
				elif case == "cancelled":
					self.prompt_result = PinCancelled()
				elif case == "incorrect":
					self.token.outcomes.append("incorrect")
				else:
					for _ in range(MAX_PIN_FAILURES):
						self.service.pin_limiter.record_failure(TOKEN_1)
				self.assertEqual(status, self.sign()[0])
				self.assertFalse(lock.locked(), f"{case} left the token lock held")
				self.token.state_error, self.token.flags, self.prompt_result = None, 0, "1111"

	def test_token_locks_are_one_per_serial(self):
		limiter = PinLimiter(FakeClock())
		self.assertIs(limiter.token_lock(TOKEN_1), limiter.token_lock(TOKEN_1))
		self.assertIsNot(limiter.token_lock(TOKEN_1), limiter.token_lock(TOKEN_2))

	def test_the_guard_re_checks_the_limiter_takes_no_lock_and_records_nothing(self):
		limiter = PinLimiter(FakeClock())
		for _ in range(MAX_PIN_FAILURES):
			limiter.record_failure(TOKEN_1)
		for shown in (False, True):
			with self.subTest(final_try_shown=shown):
				with self.assertRaises(PinRateLimited):
					with limiter.guard(TOKEN_1, final_try_shown=shown):
						self.fail("the guard body must not run")
				self.assertFalse(limiter.token_lock(TOKEN_1).locked())
				self.assertEqual(MAX_PIN_FAILURES, limiter.failures(TOKEN_1))
		with limiter.guard(TOKEN_2, final_try_shown=False):
			self.assertFalse(limiter.token_lock(TOKEN_2).locked(), "the caller holds the lock, not the guard")

	def test_check_flags_on_the_re_read_flags(self):
		limiter = PinLimiter(FakeClock())
		for flags, shown, expected in (
			(0, False, None),
			(0, True, None),
			(CKF_USER_PIN_FINAL_TRY, True, None),
			(CKF_USER_PIN_FINAL_TRY, False, TokenBusy.STATE_CHANGED),
			(CKF_USER_PIN_LOCKED, False, "PIN_LOCKED"),
			(CKF_USER_PIN_LOCKED, True, "PIN_LOCKED"),
			(CKF_USER_PIN_LOCKED | CKF_USER_PIN_FINAL_TRY, True, "PIN_LOCKED"),
		):
			with self.subTest(flags=hex(flags), shown=shown):
				guard = limiter.guard(TOKEN_1, final_try_shown=shown)
				if expected is None:
					self.assertIsNone(guard.check_flags(flags))
					continue
				with self.assertRaises(LocalSignerError) as ctx:
					guard.check_flags(flags)
				if expected == "PIN_LOCKED":
					self.assertIsInstance(ctx.exception, PinLocked)
				else:
					self.assertIsInstance(ctx.exception, TokenBusy)
					self.assertEqual(expected, ctx.exception.message)
		self.assertEqual(0, limiter.failures(TOKEN_1))


class TestTokenFlags(LimiterCase):
	def test_locked_token_is_refused_before_the_dialog(self):
		for flags in (CKF_USER_PIN_LOCKED, CKF_USER_PIN_LOCKED | CKF_USER_PIN_FINAL_TRY):
			with self.subTest(flags=hex(flags)):
				self.token.flags = flags
				status, body = self.sign()
				self.assertEqual(423, status)
				self.assertEqual(
					{"code": "PIN_LOCKED", "message": "The token is locked. Unlock it with your DSC provider's tool."},
					body["error"],
				)
		self.assertEqual([], self.prompts)
		self.assertEqual([], self.token.entering)

	def test_final_try_reaches_the_prompt_through_the_shared_host(self):
		self.token.flags = CKF_USER_PIN_FINAL_TRY
		self.assert_allowed()
		self.token.flags = 0
		self.assert_allowed()
		self.assertEqual([True, False], [p["final_try"] for p in self.prompts])
		# The child shows the final-try text itself (dialog_child.FINAL_TRY_TEXT).
		self.assertEqual([[], []], [p["warnings"] for p in self.prompts])
		self.assertTrue(all(p["host"] is self.host for p in self.prompts))

	def test_final_try_reaches_the_real_dialog_request(self):
		self.service.pin_prompt = request_pin
		requests = []
		real = self.host.run_dialog
		self.host.run_dialog = lambda request: (requests.append(dict(request)), real(request))[1]
		self.token.flags = CKF_USER_PIN_FINAL_TRY
		self.assert_allowed(document_name="MODE:ok_entered:2468")
		self.assertIs(True, requests[0]["final_try"])
		self.assertEqual([], requests[0]["warnings"])

	def test_flag_values_match_pykcs11_when_installed(self):
		try:
			import PyKCS11
		except ImportError:
			self.skipTest("PyKCS11 not installed")
		self.assertEqual(CKF_USER_PIN_FINAL_TRY, PyKCS11.CKF_USER_PIN_FINAL_TRY)
		self.assertEqual(CKF_USER_PIN_LOCKED, PyKCS11.CKF_USER_PIN_LOCKED)
		with mock.patch.dict("sys.modules", {"PyKCS11": None}):
			self.assertEqual((CKF_USER_PIN_LOCKED, CKF_USER_PIN_FINAL_TRY), service_module._pin_flags())


def _spy(name, real, seen, probe):
	def call(*args, **kwargs):
		seen.append((name, probe()))
		return real(*args, **kwargs)

	return call


def _wait_for(predicate, timeout=10.0):
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		if predicate():
			return True
		time.sleep(0.01)
	return predicate()


if __name__ == "__main__":
	unittest.main()
