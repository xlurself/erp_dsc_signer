"""Spec 001 §7: the per-serial token lock, and the flags re-read immediately before C_Login.

The real ``SignerService.sign`` drives a real ``TokenClient`` over the fake PKCS#11 library
from test_token_login, so the lock, the guard and token.py's re-read are production code;
only the token, the PIN dialog and endesive are fakes.

The scenario found by adversarial review: two concurrent requests on one token whose flags
are clear.  R2's dialog was shown, without the final-try warning, while R1's C_Login was
still in flight; R1's wrong PIN then moved the token to FINAL_TRY, and R2's wrong PIN
locked it.
"""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import test_token_login as fakes
from test_token_login import PK, SENTINEL_PIN, assert_no_sentinel_in_frames, make_client, raised, two_slot_lib

from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.errors import PinCancelled, PinIncorrect, PinLocked, PinRateLimited, TokenBusy
from erp_dsc_local.service import MAX_PIN_FAILURES, SignerService
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost
from test_signature_meta import server_meta  # the full meta the ERP sends

STUB = Path(__file__).resolve().parent / "_stub_child.py"
SERIAL = "SER-2"  # two_slot_lib's signing token, normalised
ORIGIN = "https://erp.example"
FINAL_TRY = PK.CKF_USER_PIN_FINAL_TRY
LOCKED = PK.CKF_USER_PIN_LOCKED
WAIT = 10.0


def setUpModule():
	fakes.setUpModule()


class ScriptedSession(fakes.FakeSession):
	def login(self, pin):
		self.lib.log.append(("login", self.slot))
		self.lib.logins.append((self.slot, pin))
		self.lib.received_pin = pin
		step = self.lib.steps.pop(0) if self.lib.steps else None
		if step is not None:
			step(self.lib.tokens[self.slot])  # may block, change the flags, or raise
		self.logged_in = True


class ScriptedLib(fakes.FakeLib):
	"""FakeLib whose each C_Login runs the next scripted step (none: login succeeds)."""

	def __init__(self, tokens):
		super().__init__(tokens)
		self.steps = []

	def openSession(self, slot, flags):
		self.log.append(("openSession", slot))
		return ScriptedSession(self, slot)


def wrong_pin(code=PK.CKR_PIN_INCORRECT, *, then_flags=None, entered=None, hold=None):
	def step(token):
		if entered is not None:
			entered.set()
		if hold is not None:
			hold.wait(WAIT)
		if then_flags is not None:
			token["flags"] = then_flags
		raise PK.PyKCS11Error(code)

	return step


def hang(entered, hold):
	def step(token):
		entered.set()
		hold.wait(WAIT)

	return step


class RecordingLock:
	"""One token's lock: a real Lock that records every acquire's timeout."""

	def __init__(self):
		self.lock = threading.Lock()
		self.timeouts = []
		self._calls = threading.Condition()

	def acquire(self, blocking=True, timeout=-1):
		with self._calls:
			self.timeouts.append(timeout)
			self._calls.notify_all()
		return self.lock.acquire(blocking, timeout)

	def release(self):
		self.lock.release()

	def locked(self):
		return self.lock.locked()

	def wait_for_acquires(self, count):
		with self._calls:
			return self._calls.wait_for(lambda: len(self.timeouts) >= count, WAIT)


class GatedLock(RecordingLock):
	"""A RecordingLock whose FIRST successful acquire waits on ``gate`` before returning, so
	a request can be held between taking the lock and opening its dialog."""

	def __init__(self):
		super().__init__()
		self.gate, self.holding = threading.Event(), threading.Event()
		self._gated = False

	def acquire(self, blocking=True, timeout=-1):
		got = super().acquire(blocking, timeout)
		if got and not self._gated:
			self._gated = True
			self.holding.set()
			self.gate.wait(WAIT)
		return got


class RaceCase(unittest.TestCase):
	LOCK = RecordingLock

	def setUp(self):
		self.cms = fakes.FakeCms()
		fakes.install_fake_endesive(self, self.cms)

		self.lib = ScriptedLib(two_slot_lib().tokens)
		client = mock.patch.object(service_module, "TokenClient", lambda module: make_client(self.lib))
		client.start()
		self.addCleanup(client.stop)

		directory = tempfile.TemporaryDirectory()
		self.addCleanup(directory.cleanup)
		config_path = Path(directory.name) / "config.json"
		config_path.write_text(json.dumps({"host": "127.0.0.1", "allowed_origins": []}), encoding="utf-8")
		host = DialogHost(child_script=STUB)
		self.addCleanup(host.shutdown)

		self.prompts = []
		self.answer = lambda final_try: SENTINEL_PIN

		def prompt(origin, document_name, *, host, warnings=(), final_try=False):
			self.prompts.append(final_try)
			return self.answer(final_try)

		self.trust = TrustStore(Path(directory.name) / "allowed_origins.json")
		self.trust.allow(ORIGIN)  # sign() re-checks the pairing once it holds the token lock
		self.service = SignerService(
			load_config(config_path),
			trust_store=self.trust,
			dialog_host=host,
			pin_prompt=prompt,
		)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"
		self.lock = self.LOCK()
		real_token_lock = self.service.pin_limiter.token_lock
		self.service.pin_limiter.token_lock = lambda serial: self.lock if serial == SERIAL else real_token_lock(serial)
		self.results = {}
		# Registered last, so it runs after each test's own release cleanups and before any
		# patch above is undone: no request thread may outlive its test.
		self.threads = []
		self.addCleanup(self._join_threads)

	def sign(self):
		return self.service.sign(
			ORIGIN, b"%PDF", server_meta(), document_name="INV-1", selector=None, provider="auto", module_id=None, timestamp_url=None
		)

	def start(self, name):
		def run():
			try:
				self.results[name] = ("ok", self.sign())
			except Exception as error:
				self.results[name] = (getattr(error, "code", type(error).__name__), error)

		thread = threading.Thread(target=run, daemon=True)
		self.threads.append(thread)
		thread.start()
		return thread

	def _join_threads(self):
		for thread in self.threads:
			thread.join(WAIT)
		self.assertFalse([thread for thread in self.threads if thread.is_alive()], "a request thread outlived its test")

	def code(self, name):
		return self.results[name][0]

	def short_lock_timeout(self, seconds):
		patcher = mock.patch.object(service_module, "TOKEN_LOCK_TIMEOUT_SECONDS", seconds)
		patcher.start()
		self.addCleanup(patcher.stop)


class TestTwoConcurrentWrongPins(RaceCase):
	def test_the_second_dialog_waits_for_the_first_login_and_warns_of_the_final_try(self):
		entered, hold = threading.Event(), threading.Event()
		self.addCleanup(hold.set)
		self.lib.steps = [
			wrong_pin(then_flags=FINAL_TRY, entered=entered, hold=hold),  # R1: slow token, wrong PIN
			wrong_pin(then_flags=LOCKED),  # only reached if R2 logs in: that would lock the token
		]

		def answer(final_try):
			if final_try:
				raise PinCancelled()  # the user who IS warned of the last attempt declines it
			return "WRONG-PIN"

		self.answer = answer
		r1 = self.start("R1")
		self.assertTrue(entered.wait(WAIT), "R1 never reached C_Login")
		r2 = self.start("R2")
		self.assertTrue(self.lock.wait_for_acquires(2), "R2 never asked for the token lock")
		self.assertEqual([False], self.prompts, "R2 must not read flags or show a dialog while R1 holds the token")
		hold.set()
		r1.join(WAIT)
		r2.join(WAIT)

		self.assertEqual("PIN_INCORRECT", self.code("R1"))
		self.assertEqual("PIN_CANCELLED", self.code("R2"))
		self.assertEqual([False, True], self.prompts, "R2's dialog must carry the final-try warning")
		self.assertEqual(1, len(self.lib.logins))
		self.assertEqual(FINAL_TRY, self.lib.tokens[2]["flags"], "the token must not be locked")
		self.assertFalse(self.lock.locked())


class TestLockTimeout(RaceCase):
	def test_the_service_waits_for_the_lock_with_the_constant_timeout(self):
		self.assertEqual(20, service_module.TOKEN_LOCK_TIMEOUT_SECONDS)
		self.sign()
		self.assertEqual([20], self.lock.timeouts)
		self.assertFalse(self.lock.locked())

	def test_a_busy_token_is_refused_with_no_dialog_and_no_login(self):
		self.short_lock_timeout(0.2)
		self.assertTrue(self.lock.lock.acquire(timeout=1))  # another request holds the token
		self.addCleanup(self.lock.lock.release)
		started = time.monotonic()
		thread = self.start("R")
		thread.join(5)
		elapsed = time.monotonic() - started
		self.assertFalse(thread.is_alive(), "the request waited past TOKEN_LOCK_TIMEOUT_SECONDS")

		code, error = self.results["R"]
		self.assertEqual("TOKEN_BUSY", code)
		self.assertEqual((429, TokenBusy.IN_PROGRESS), (error.status, error.message))
		self.assertEqual([0.2], self.lock.timeouts)
		self.assertGreaterEqual(elapsed, 0.15)
		self.assertEqual([], self.prompts)
		self.assertEqual([], self.lib.logins)
		self.assertEqual(1, self.lib.log.count(("getSlotList",)), "token_state must not run without the lock")

	def test_a_hung_login_parks_no_later_request_beyond_the_timeout(self):
		self.short_lock_timeout(0.3)
		entered, hold = threading.Event(), threading.Event()
		self.addCleanup(hold.set)
		self.lib.steps = [hang(entered, hold)]  # R1's C_Login does not return
		r1 = self.start("R1")
		self.assertTrue(entered.wait(WAIT), "R1 never reached C_Login")

		started = time.monotonic()
		later = [self.start(name) for name in ("R2", "R3")]
		for thread in later:
			thread.join(5)
		self.assertFalse(any(thread.is_alive() for thread in later), "a hung C_Login parked a later request")
		self.assertLess(time.monotonic() - started, 3.0)
		self.assertEqual(["TOKEN_BUSY", "TOKEN_BUSY"], [self.code("R2"), self.code("R3")])
		self.assertEqual([False], self.prompts, "a waiting request must hold no PIN: no dialog before the lock")
		self.assertEqual(1, len(self.lib.logins))

		hold.set()
		r1.join(WAIT)
		self.assertEqual("ok", self.code("R1"))
		self.assertFalse(self.lock.locked())
		self.sign()  # the lock is free again
		self.assertEqual(2, len(self.lib.logins))


class TestFlagsReReadBeforeLogin(RaceCase):
	"""Another application (a vendor tool, another process) can change the token while the
	dialog is open; only the re-read under the guard, just before C_Login, can see that."""

	def test_locked_while_the_dialog_was_open_is_pin_locked_with_no_login(self):
		def answer(final_try):
			self.lib.tokens[2]["flags"] = LOCKED
			return SENTINEL_PIN

		self.answer = answer
		error = raised(self.sign)
		self.assertIsInstance(error, PinLocked)
		self.assertEqual([], self.lib.logins)
		self.assertEqual(0, self.service.pin_limiter.failures(SERIAL))
		self.assertFalse(self.lock.locked())

	def test_final_try_appearing_behind_an_unwarned_dialog_is_token_busy_with_no_login(self):
		def answer(final_try):
			self.lib.tokens[2]["flags"] = FINAL_TRY
			return SENTINEL_PIN

		self.answer = answer
		error = raised(self.sign)
		self.assertIsInstance(error, TokenBusy)
		self.assertEqual(("TOKEN_BUSY", 429, TokenBusy.STATE_CHANGED), (error.code, error.status, error.message))
		self.assertEqual([False], self.prompts)
		self.assertEqual([], self.lib.logins)
		self.assertEqual(0, self.service.pin_limiter.failures(SERIAL))
		self.assertFalse(self.lock.locked())

		self.answer = lambda final_try: SENTINEL_PIN
		self.sign()  # the retry shows the warning and logs in
		self.assertEqual([False, True], self.prompts)
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)

	def test_a_final_try_the_dialog_warned_of_still_logs_in(self):
		self.lib.tokens[2]["flags"] = FINAL_TRY
		self.sign()
		self.assertEqual([True], self.prompts)
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)


class TestLimiterThroughTheRealToken(RaceCase):
	def test_every_wrong_pin_result_counts_towards_the_lockout(self):
		codes = (PK.CKR_PIN_INVALID, PK.CKR_PIN_LEN_RANGE, PK.CKR_PIN_INCORRECT)
		self.assertEqual(MAX_PIN_FAILURES, len(codes))
		for code in codes:
			self.lib.steps.append(wrong_pin(code))
			self.assertIsInstance(raised(self.sign), PinIncorrect)
		self.assertIsInstance(raised(self.sign), PinRateLimited)
		self.assertEqual(MAX_PIN_FAILURES, len(self.prompts), "the locked-out request got no dialog")
		self.assertEqual(MAX_PIN_FAILURES, len(self.lib.logins))

	def test_other_login_results_are_not_counted(self):
		for code in (PK.CKR_GENERAL_ERROR, PK.CKR_DEVICE_REMOVED, PK.CKR_USER_ALREADY_LOGGED_IN):
			self.lib.steps.append(wrong_pin(code))
			self.assertEqual("TOKEN_SIGNING_FAILED", raised(self.sign).code)
		self.assertEqual(0, self.service.pin_limiter.failures(SERIAL))
		self.sign()


class TestUnpairedWhileWaiting(RaceCase):
	def test_a_request_unpaired_while_it_waited_for_the_lock_gets_no_dialog(self):
		entered, hold = threading.Event(), threading.Event()
		self.addCleanup(hold.set)
		self.lib.steps = [hang(entered, hold)]  # R1 holds the token in C_Login
		r1 = self.start("R1")
		self.assertTrue(entered.wait(WAIT), "R1 never reached C_Login")
		r2 = self.start("R2")  # its nonce is already spent; it waits for R1
		self.assertTrue(self.lock.wait_for_acquires(2), "R2 never asked for the token lock")
		self.assertTrue(self.trust.revoke(ORIGIN))
		hold.set()
		r1.join(WAIT)
		r2.join(WAIT)

		self.assertEqual("ok", self.code("R1"))
		code, error = self.results["R2"]
		self.assertEqual("ORIGIN_NOT_PAIRED", code)
		self.assertEqual(403, error.status)
		self.assertEqual([False], self.prompts, "the unpaired request must not show a dialog")
		self.assertEqual(1, len(self.lib.logins))
		self.assertFalse(self.lock.locked())


class TestDialogOpenFailsFast(RaceCase):
	def test_a_request_during_another_requests_dialog_is_refused_at_once(self):
		in_dialog, close_dialog = threading.Event(), threading.Event()
		self.addCleanup(close_dialog.set)

		def answer(final_try):
			if len(self.prompts) == 1:  # R1's dialog stays open until the test closes it
				in_dialog.set()
				close_dialog.wait(WAIT)
			return SENTINEL_PIN

		self.answer = answer
		r1 = self.start("R1")
		self.assertTrue(in_dialog.wait(WAIT), "R1 never opened its dialog")
		started = time.monotonic()
		r2 = self.start("R2")
		r2.join(3)
		self.assertFalse(r2.is_alive(), "R2 queued behind R1's open dialog")
		self.assertLess(time.monotonic() - started, 2.0)
		code, error = self.results["R2"]
		self.assertEqual("TOKEN_BUSY", code)
		self.assertEqual((429, TokenBusy.IN_PROGRESS), (error.status, error.message))
		self.assertEqual([20], self.lock.timeouts, "R2 must not even wait for the lock")
		self.assertEqual([False], self.prompts)

		close_dialog.set()
		r1.join(WAIT)
		self.assertEqual("ok", self.code("R1"))
		self.sign()  # once the first request has finished, the next one proceeds
		self.assertEqual([False, False], self.prompts)
		self.assertEqual(2, len(self.lib.logins))
		self.assertFalse(self.lock.locked())


class TestWaitingThroughADialog(RaceCase):
	LOCK = GatedLock

	def test_a_request_waiting_when_a_dialog_opened_gets_no_second_dialog(self):
		self.addCleanup(self.lock.gate.set)
		r1 = self.start("R1")
		self.assertTrue(self.lock.holding.wait(WAIT), "R1 never took the token lock")
		r2 = self.start("R2")  # R1 holds the lock but has not opened its dialog yet
		self.assertTrue(self.lock.wait_for_acquires(2), "R2 never asked for the token lock")
		self.lock.gate.set()
		r1.join(WAIT)
		r2.join(WAIT)

		self.assertEqual("ok", self.code("R1"))
		code, error = self.results["R2"]
		self.assertEqual("TOKEN_BUSY", code)
		self.assertEqual(TokenBusy.IN_PROGRESS, error.message)
		self.assertEqual([False], self.prompts, "R2 must not pop a second dialog right after R1's")
		self.assertEqual(1, len(self.lib.logins))
		self.assertFalse(self.lock.locked())
		self.sign()  # a request that arrives afterwards proceeds
		self.assertEqual([False, False], self.prompts)


class TestTimestampFailureReleasesTheToken(RaceCase):
	def test_a_timed_out_tsa_logs_out_releases_the_lock_and_the_next_request_proceeds(self):
		self.cms.timestamp_step = fakes.raise_in_timestamp(fakes.FakeTsaTimeout)
		error = raised(self.sign)
		self.assertEqual(("TOKEN_SIGNING_FAILED", 502), (error.code, error.status))
		self.assertEqual([("logout", 2), ("closeSession", 2)], self.lib.log[-2:])
		self.assertFalse(self.lock.locked())

		self.cms.timestamp_step = None
		signed, _metadata = self.sign()  # not TOKEN_BUSY: the same token is usable at once
		self.assertTrue(signed.startswith(b"%PDF|SIG-"))
		self.assertEqual(2, len(self.lib.logins))
		self.assertEqual([20, 20], self.lock.timeouts)


class TestPinNotHeldDuringTheTimestamp(RaceCase):
	def test_no_signer_frame_holds_the_pin_while_the_tsa_is_asked(self):
		seen = {}
		self.cms.timestamp_step = fakes.stack_walk_step(self, seen)
		self.sign()
		self.assertNotIn("failure", seen)
		self.assertEqual([(2, SENTINEL_PIN)], self.lib.logins)
		self.assertIsNone(seen["pin"])
		self.assertIn(("service", "sign"), seen["walked"])  # the frame that called the dialog
		self.assertIn(("token", "sign_pdf"), seen["walked"])


class TestPinNotHeldInFrames(RaceCase):
	def test_no_signer_frame_holds_the_pin_when_sign_raises(self):
		for case in ("wrong_pin", "sign_error"):
			with self.subTest(case=case):
				self.lib.sign_error = None
				if case == "wrong_pin":
					self.lib.steps.append(wrong_pin())
				else:
					self.lib.sign_error = fakes.driver_error(PK.CKR_FUNCTION_FAILED)
				error = raised(self.sign)
				self.assertIn(error.code, ("PIN_INCORRECT", "TOKEN_SIGNING_FAILED"))
				walked = assert_no_sentinel_in_frames(self, error, SENTINEL_PIN)
				self.assertIn(("service", "sign"), walked)  # the frame that held the dialog's PIN
				self.assertIn(("token", "sign_pdf"), walked)
				self.assertFalse(self.lock.locked())


if __name__ == "__main__":
	unittest.main()
