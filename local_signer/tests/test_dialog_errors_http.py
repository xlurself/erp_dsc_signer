"""Spec 001 §6 error table, row by row, at the HTTP boundary.

Every case runs the REAL `pin.request_pin` / `pairing.consent_dialog` against a real
DialogHost.  The child is tests/_stub_child.py (mode in the first claim: the document
name on /v1/sign, the site name on /v1/pair) or, for replies the stub cannot shape
from one claim, a one-line child generated outside the repo that prints a fixed reply.
Each case asserts the EXACT `error.message` and `error.details.cause`.
"""

import base64
import errno
import hashlib
import json
import shutil
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child, ui
from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.pairing import PairGuard, SiteClaims, consent_dialog
from erp_dsc_local.pin import request_pin
from erp_dsc_local.service import SignerService
from erp_dsc_local.trust import TrustStore
from test_signature_meta import server_meta  # the full meta the ERP sends


STUB = Path(__file__).resolve().parent / "_stub_child.py"
REAL_POPEN = subprocess.Popen
SIGN_ORIGIN = "https://noise.m.frappe.cloud"
PAIR_ORIGIN = "https://pair.example"
PDF = b"%PDF-1.4\n% erp-dsc-local test document\n"
PIN = "246810"

# Spec §6 "Messages", copied literally so any drift in errors.py fails here.
MESSAGES = {
	"tk_import_failed": "The signer cannot show a dialog because Tk is not available in its Python (tk_import_failed).",
	"tk_init_failed": "The signer could not open a window on this desktop (tk_init_failed). Run it in a logged-in desktop session.",
	"dialog_spawn_failed": "The signer could not start its dialog process (dialog_spawn_failed).",
	"dialog_process_crashed": "The signer's dialog process crashed (dialog_process_crashed).",
	"dialog_process_failed": "The signer's dialog process exited without an answer (dialog_process_failed).",
	"dialog_bad_reply": "The signer's dialog process returned an unexpected reply and was ignored (dialog_bad_reply).",
	"dialog_timeout": "No answer was given in time and the dialog was closed (dialog_timeout).",
	"dialog_shutdown": "The signer is shutting down (dialog_shutdown). Try again.",
	"dialog_request_invalid": "The signer refused to show a dialog for an invalid request (dialog_request_invalid).",
}
PAIR_HINT = " Or pair from a terminal: erp-dsc-local --allow <origin>"
BUSY = ("DIALOG_BUSY", 429, "Another signer dialog is already waiting for an answer on this computer.")
WEDGED = ("DIALOG_WEDGED", 503, "The signer's dialog process could not be stopped. Restart the signer.")

# Stub modes with the same outcome on both paths.
COMMON_MODES = (
	("MODE:result:timeout", "dialog_timeout"),
	("MODE:unavailable:tk_import_failed", "tk_import_failed"),
	("MODE:unavailable:tk_init_failed", "tk_init_failed"),
	("MODE:crash", "dialog_process_crashed"),
	("MODE:exit:3", "dialog_process_failed"),
	("MODE:valid_then_exit:3", "dialog_process_failed"),  # a valid reply + exit>0 is ignored
	("MODE:exit:65", "dialog_request_invalid"),
	("MODE:empty", "dialog_bad_reply"),  # exit 0, nothing written
	("MODE:partial", "dialog_bad_reply"),  # no newline
	("MODE:badjson:1234", "dialog_bad_reply"),
	("MODE:extra_line:1234", "dialog_bad_reply"),
	("MODE:oversize:1234", "dialog_bad_reply"),
	("MODE:oversize_line", "dialog_bad_reply"),
	("MODE:result:bogus", "dialog_bad_reply"),  # unknown result
	("MODE:unavailable:bogus_cause", "dialog_bad_reply"),  # unknown cause
)
PIN_ONLY_MODES = (
	("MODE:result:allow", "dialog_bad_reply"),  # a consent result on a pin dialog
	("MODE:result:entered", "dialog_bad_reply"),  # entered without a value
)
CONSENT_ONLY_MODES = (
	("MODE:result:cancelled", "dialog_bad_reply"),  # a pin result on a consent dialog
	("MODE:ok_entered:1234", "dialog_bad_reply"),
)


def raw_replies(kind):
	"""Exit-0 replies the classifier must reject (spec §6 rule 5)."""
	ok = "cancelled" if kind == "pin" else "deny"
	other = "consent" if kind == "pin" else "pin"
	return {
		"missing_key": {"v": 1, "kind": kind},
		"v_not_1": {"v": 2, "kind": kind, "result": ok},
		"v_is_bool": {"v": True, "kind": kind, "result": ok},
		"kind_mismatch": {"v": 1, "kind": other, "result": ok},
		"extra_key": {"v": 1, "kind": kind, "result": ok, "x": 1},
		"stray_value": {"v": 1, "kind": kind, "result": ok, "value": "1234"},
		"stray_cause": {"v": 1, "kind": kind, "result": ok, "cause": "tk_init_failed"},
		"unavailable_without_cause": {"v": 1, "kind": kind, "result": "unavailable"},
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


def patch_timing(test, *, startup=0.6, grace=0.2, kill_delay=0.3):
	"""Short supervision: the dialog timeout clamps to 0, so a hang hits the deadline fast."""
	for target, name, value in (
		(ui, "STARTUP_ALLOWANCE_SECONDS", startup),
		(ui, "GRACE_SECONDS", grace),
		(ui, "KILL_DELAY_SECONDS", kill_delay),
		(dialog_child, "MIN_DIALOG_SECONDS", 0),
		(dialog_child, "MAX_DIALOG_SECONDS", 0),
	):
		patcher = mock.patch.object(target, name, value)
		patcher.start()
		test.addCleanup(patcher.stop)


class _Certificate:
	slot_id = 1
	token_serial = "WD-TOKEN-0001"
	metadata = {"fingerprint_sha256": "ab" * 32}


class FakeToken:
	def __init__(self):
		self.pins = []
		self.certificate = _Certificate()

	def __call__(self, module):
		return self

	def select(self, selector):
		return self.certificate, [self.certificate]

	def token_state(self, selected):
		return 0, selected.token_serial

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		self.pins.append(pin)
		with login_guard as guard:
			guard.succeeded()
		return pdf_bytes + b"%signed\n", dict(selected.metadata)


class RecordingPairGuard(PairGuard):
	def __init__(self):
		super().__init__(max_attempts_per_hour=10_000)
		self.denials = 0

	def record_denial(self):
		self.denials += 1
		super().record_denial()


class DialogHttpCase(unittest.TestCase):
	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		config_path = Path(self._dir.name) / "config.json"
		config_path.write_text(json.dumps({"host": "127.0.0.1", "allowed_origins": []}), encoding="utf-8")
		self.trust = TrustStore(Path(self._dir.name) / "allowed_origins.json")
		self.trust.allow(SIGN_ORIGIN)
		self.guard = RecordingPairGuard()
		self.site_name = "MODE:result:allow"
		self.host = ui.DialogHost(child_script=STUB)
		self.addCleanup(self.host.shutdown)
		self.service = SignerService(
			load_config(config_path),
			trust_store=self.trust,
			dialog_host=self.host,
			pair_guard=self.guard,
			consent=consent_dialog,
			pin_prompt=request_pin,
			verifier=lambda origin, token: SiteClaims(site_name=self.site_name, user="ceo@acme.test"),
		)
		self.token = FakeToken()
		patcher = mock.patch.object(service_module, "TokenClient", self.token)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"
		self.server = self.service.make_server(("127.0.0.1", 0))
		self.addCleanup(self.server.server_close)
		threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
		self.addCleanup(self.server.shutdown)
		self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

	# -- requests --------------------------------------------------------------------
	def sign(self, document_name):
		_s, issued = _request(self.base + "/v1/nonce", method="POST", origin=SIGN_ORIGIN, body={"purpose": "sign"})
		return _request(
			self.base + "/v1/sign",
			method="POST",
			origin=SIGN_ORIGIN,
			body={
				"nonce": issued["nonce"],
				"pdf_base64": base64.b64encode(PDF).decode("ascii"),
				"pdf_sha256": hashlib.sha256(PDF).hexdigest(),
				"signing_request": {"signature_meta": server_meta(), "document_name": document_name},
			},
		)

	def pair(self, site_name, origin=PAIR_ORIGIN):
		self.site_name = site_name
		return _request(self.base + "/v1/pair", method="POST", origin=origin, body={"pairing_token": "t" * 32})

	def use_child(self, script):
		self.host._child_script = script  # same host and lock; another child program

	def raw_child(self, payload: bytes) -> Path:
		"""A child that reads the request line, prints `payload` + newline and exits 0."""
		folder = Path(tempfile.mkdtemp(prefix="erp-dsc-raw-child-"))
		self.addCleanup(shutil.rmtree, folder, True)
		script = folder / "raw_child.py"
		script.write_text(
			textwrap.dedent(
				f"""
				import os, sys
				sys.stdin.buffer.readline()
				os.write(1, {payload + b"\n"!r})
				os._exit(0)
				"""
			),
			encoding="utf-8",
		)
		return script

	def run_then_shutdown(self, call):
		"""Start `call` (a request whose child hangs), then shut the host down under it."""
		box = {}
		thread = threading.Thread(target=lambda: box.setdefault("response", call()), daemon=True)
		thread.start()
		self.assertTrue(wait_for(lambda: self.host._child is not None), "the dialog child never started")
		self.host.shutdown()
		thread.join(15)
		return box["response"]

	# -- assertions ------------------------------------------------------------------
	def assert_pin_unavailable(self, response, cause):
		status, body = response
		self.assertEqual(503, status, body)
		self.assertEqual("PIN_PROMPT_UNAVAILABLE", body["error"]["code"])
		self.assertEqual(MESSAGES[cause], body["error"]["message"])
		self.assertEqual({"cause": cause}, body["error"]["details"])
		self.assertEqual([], self.token.pins)

	def assert_pair_unavailable(self, response, cause, origin=PAIR_ORIGIN):
		status, body = response
		self.assertEqual(503, status, body)
		self.assertEqual("PAIR_PROMPT_UNAVAILABLE", body["error"]["code"])
		self.assertEqual(MESSAGES[cause] + PAIR_HINT, body["error"]["message"])
		self.assertEqual({"cause": cause}, body["error"]["details"])
		self.assert_nothing_recorded(origin)

	def assert_nothing_recorded(self, origin=PAIR_ORIGIN):
		"""Never Deny, never consent: no denial, no cooldown, no trust write."""
		self.assertFalse(self.trust.is_denied(origin))
		self.assertFalse(self.trust.is_allowed(origin))
		self.assertEqual(0, self.guard.denials)

	def assert_error(self, response, expected):
		code, status, message = expected
		got_status, body = response
		self.assertEqual(status, got_status, body)
		self.assertEqual(code, body["error"]["code"])
		self.assertEqual(message, body["error"]["message"])
		self.assertNotIn("details", body["error"])


class TestPinPathTable(DialogHttpCase):
	def test_entered_signs_with_the_dialog_pin(self):
		status, body = self.sign(f"MODE:ok_entered:{PIN}")
		self.assertEqual(200, status, body)
		self.assertEqual([PIN], self.token.pins)

	def test_cancelled_is_pin_cancelled(self):
		status, body = self.sign("MODE:result:cancelled")
		self.assertEqual(409, status)
		self.assertEqual(
			{"code": "PIN_CANCELLED", "message": "Signing was cancelled in the local PIN dialog."}, body["error"]
		)
		self.assertEqual([], self.token.pins)

	def test_every_stub_outcome_maps_to_its_cause(self):
		for mode, cause in COMMON_MODES + PIN_ONLY_MODES:
			with self.subTest(mode=mode):
				self.assert_pin_unavailable(self.sign(mode), cause)

	def test_every_malformed_exit0_reply_is_bad_reply(self):
		for name, reply in raw_replies("pin").items():
			with self.subTest(reply=name):
				self.use_child(self.raw_child(json.dumps(reply).encode()))
				self.assert_pin_unavailable(self.sign("INV-1"), "dialog_bad_reply")

	def test_entered_with_empty_value_is_bad_reply(self):
		self.use_child(self.raw_child(b'{"v":1,"kind":"pin","result":"entered","value":""}'))
		self.assert_pin_unavailable(self.sign("INV-1"), "dialog_bad_reply")

	def test_deadline_kill_is_dialog_timeout(self):
		patch_timing(self)
		self.assert_pin_unavailable(self.sign("MODE:hang"), "dialog_timeout")

	def test_spawn_failure(self):
		with mock.patch.object(subprocess, "Popen", side_effect=OSError(errno.EAGAIN, "fork failed")):
			self.assert_pin_unavailable(self.sign(f"MODE:ok_entered:{PIN}"), "dialog_spawn_failed")

	def test_shutdown_mid_dialog(self):
		self.assert_pin_unavailable(self.run_then_shutdown(lambda: self.sign("MODE:hang")), "dialog_shutdown")
		# Rule 1 also refuses every later request.
		self.assert_pin_unavailable(self.sign(f"MODE:ok_entered:{PIN}"), "dialog_shutdown")

	def test_broken_pipe_on_flush_still_uses_the_valid_reply(self):
		with failing_stdin("flush"):
			status, body = self.sign(f"MODE:ok_entered:{PIN}")
		self.assertEqual(200, status, body)
		self.assertEqual([PIN], self.token.pins)

	def test_einval_on_write_classifies_from_the_exit(self):
		with failing_stdin("write"):
			self.assert_pin_unavailable(self.sign(f"MODE:ok_entered:{PIN}"), "dialog_process_failed")

	def test_busy(self):
		with HeldLock(self.host):
			self.assert_error(self.sign(f"MODE:ok_entered:{PIN}"), BUSY)
		self.assertEqual([], self.token.pins)

	def test_wedged(self):
		patch_timing(self)
		with unreapable():
			self.assert_error(self.sign("MODE:hang"), WEDGED)
		# Every later dialog request gets DialogWedged, never DialogBusy.
		self.assert_error(self.sign(f"MODE:ok_entered:{PIN}"), WEDGED)
		self.assert_error(self.pair("MODE:result:allow"), WEDGED)
		self.assertEqual([], self.token.pins)



class TestConsentPathTable(DialogHttpCase):
	def test_allow_pairs(self):
		status, body = self.pair("MODE:result:allow")
		self.assertEqual(200, status, body)
		self.assertTrue(self.trust.is_allowed(PAIR_ORIGIN))
		self.assertEqual(0, self.guard.denials)

	def test_deny_records_a_denial_and_the_cooldown(self):
		status, body = self.pair("MODE:result:deny")
		self.assertEqual(403, status)
		self.assertEqual({"code": "PAIR_DENIED", "message": "Pairing was declined on this computer."}, body["error"])
		self.assertTrue(self.trust.is_denied(PAIR_ORIGIN))
		self.assertFalse(self.trust.is_allowed(PAIR_ORIGIN))
		self.assertEqual(1, self.guard.denials)
		# The global cooldown now refuses another origin before any dialog.
		status, body = self.pair("MODE:result:allow", origin="https://other.example")
		self.assertEqual(429, status)
		self.assertEqual("PAIR_RATE_LIMITED", body["error"]["code"])
		self.assertFalse(self.trust.is_allowed("https://other.example"))

	def test_timeout_result_records_no_denial(self):
		self.assert_pair_unavailable(self.pair("MODE:result:timeout"), "dialog_timeout")
		# No cooldown was armed: another attempt reaches the dialog and pairs.
		status, body = self.pair("MODE:result:allow")
		self.assertEqual(200, status, body)

	def test_deadline_kill_records_no_denial(self):
		patch_timing(self)
		self.assert_pair_unavailable(self.pair("MODE:hang"), "dialog_timeout")

	def test_every_stub_outcome_maps_to_its_cause(self):
		for mode, cause in COMMON_MODES + CONSENT_ONLY_MODES:
			with self.subTest(mode=mode):
				self.assert_pair_unavailable(self.pair(mode), cause)

	def test_every_malformed_exit0_reply_is_bad_reply(self):
		for name, reply in raw_replies("consent").items():
			with self.subTest(reply=name):
				self.use_child(self.raw_child(json.dumps(reply).encode()))
				self.assert_pair_unavailable(self.pair("Acme Ltd"), "dialog_bad_reply")

	def test_spawn_failure(self):
		with mock.patch.object(subprocess, "Popen", side_effect=OSError(errno.EAGAIN, "fork failed")):
			self.assert_pair_unavailable(self.pair("MODE:result:allow"), "dialog_spawn_failed")

	def test_shutdown_mid_dialog(self):
		response = self.run_then_shutdown(lambda: self.pair("MODE:hang"))
		self.assert_pair_unavailable(response, "dialog_shutdown")

	def test_einval_on_write_classifies_from_the_exit(self):
		with failing_stdin("write"):
			self.assert_pair_unavailable(self.pair("MODE:result:allow"), "dialog_process_failed")

	def test_busy(self):
		with HeldLock(self.host):
			self.assert_error(self.pair("MODE:result:allow"), BUSY)
		self.assert_nothing_recorded()

	def test_wedged(self):
		patch_timing(self)
		with unreapable():
			self.assert_error(self.pair("MODE:hang"), WEDGED)
		self.assert_nothing_recorded()
		self.assert_error(self.pair("MODE:result:allow"), WEDGED)
		self.assert_nothing_recorded()


# --- helpers ------------------------------------------------------------------------
def wait_for(predicate, timeout=10.0):
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		if predicate():
			return True
		time.sleep(0.01)
	return predicate()


class HeldLock:
	"""Holds the real DialogHost's UI mutex from another thread, as an open dialog would."""

	def __init__(self, host):
		self.host = host
		self.entered = threading.Event()
		self.release = threading.Event()

	def __enter__(self):
		self.thread = threading.Thread(
			target=lambda: self.host.run_exclusive(lambda: (self.entered.set(), self.release.wait(30))),
			daemon=True,
		)
		self.thread.start()
		assert self.entered.wait(5)
		return self

	def __exit__(self, *_exc):
		self.release.set()
		self.thread.join(5)
		return False


class _FailingStdin:
	"""Wraps the child's stdin: `write` mode closes it and raises EINVAL (Windows closed
	pipe); `flush` mode delivers the line, then raises EPIPE."""

	def __init__(self, real, mode):
		self._real = real
		self._mode = mode

	def write(self, data):
		if self._mode == "write":
			self._real.close()
			raise OSError(errno.EINVAL, "Invalid argument")
		return self._real.write(data)

	def flush(self):
		if self._mode == "flush":
			raise BrokenPipeError(errno.EPIPE, "Broken pipe")
		self._real.flush()

	def __getattr__(self, name):
		return getattr(self._real, name)


class failing_stdin:
	def __init__(self, mode):
		self.mode = mode

	def __enter__(self):
		def popen(argv, **kwargs):
			proc = REAL_POPEN(argv, **kwargs)
			proc.stdin = _FailingStdin(proc.stdin, self.mode)
			return proc

		self.patcher = mock.patch.object(subprocess, "Popen", popen)
		self.patcher.start()
		return self

	def __exit__(self, *_exc):
		self.patcher.stop()
		return False


class unreapable:
	"""`_kill_and_reap` really kills and reaps (test hygiene) but reports failure."""

	def __enter__(self):
		def kill_and_report_failure(proc):
			proc.kill()
			proc.wait(5)
			return False

		self.patcher = mock.patch.object(ui, "_kill_and_reap", kill_and_report_failure)
		self.patcher.start()
		self.logs = mock.patch.object(ui.logger, "error")  # the one fixed wedge line
		self.logs.start()
		return self

	def __exit__(self, *_exc):
		self.patcher.stop()
		self.logs.stop()
		return False


if __name__ == "__main__":
	unittest.main()
