"""HTTP boundary of the loopback signer (spec 001 §1 rules, §3.5, §7, §8).

Tests that expect a dialog use the REAL `pin.request_pin` / `pairing.consent_dialog`
with a real DialogHost spawning tests/_stub_child.py (the mode rides in the first
claim: the document name for a PIN, the site name for consent).  Tests that expect NO
dialog keep the recording fakes and assert their call lists stay empty.  Servers come
from `SignerService.make_server(("127.0.0.1", 0))` -- never the production port.
"""

import base64
import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.errors import CertificatesHidden, PairProofInvalid, TokenUnavailable
from erp_dsc_local.pairing import PairGuard, SiteClaims, consent_dialog
from erp_dsc_local.pin import request_pin
from erp_dsc_local.service import SignerService
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost


STUB = Path(__file__).resolve().parent / "_stub_child.py"
ERP = "https://noise.m.frappe.cloud"
PDF = b"%PDF-1.4\n% erp-dsc-local test document\n"
TOKEN_SERIAL = "WD-TOKEN-0001"
DIALOG_PIN = "731904"
BODY_PIN = "000000-BODY"
UNSUPPORTED_META = "The signing request contains an unsupported field."
META_MARK = "META-HTTP-SENTINEL-7d2e"

BUSY_MESSAGE = "Another signer dialog is already waiting for an answer on this computer."
TK_INIT_MESSAGE = (
	"The signer could not open a window on this desktop (tk_init_failed). Run it in a logged-in desktop session."
	" Or pair from a terminal: erp-dsc-local --allow <origin>"
)


def _request(url, *, method="GET", origin=None, body=None, headers=None):
	data = json.dumps(body).encode() if body is not None else None
	req = urllib.request.Request(url, data=data, method=method)
	if origin:
		req.add_header("Origin", origin)
	if data is not None:
		req.add_header("Content-Type", "application/json")
	for key, value in (headers or {}).items():
		req.add_header(key, value)
	try:
		with urllib.request.urlopen(req, timeout=20) as response:
			raw = response.read()
			return response.status, dict(response.headers), (json.loads(raw) if raw else {})
	except urllib.error.HTTPError as exc:
		raw = exc.read()
		exc.close()
		return exc.code, dict(exc.headers), (json.loads(raw) if raw else {})


class _Certificate:
	slot_id = 1
	token_serial = TOKEN_SERIAL
	metadata = {"fingerprint_sha256": "ab" * 32, "token_serial": TOKEN_SERIAL}


class FakeToken:
	"""Stands in for TokenClient.  Records calls; logs in through the service's guard."""

	def __init__(self, events, *, flags=0, select_error=None, state_error=None):
		self.events = events
		self.flags = flags
		self.select_error = select_error
		self.state_error = state_error
		self.pins = []
		self.metadatas = []
		self.certificate = _Certificate()

	def __call__(self, module):  # used as the TokenClient class
		self.events.append("token_client")
		return self

	def select(self, selector):
		self.events.append("select")
		if self.select_error:
			raise self.select_error
		return self.certificate, [self.certificate]

	def token_state(self, selected):
		self.events.append("token_state")
		if self.state_error:
			raise self.state_error
		return self.flags, TOKEN_SERIAL

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		self.events.append("sign_pdf")
		self.pins.append(pin)
		self.metadatas.append(metadata)
		with login_guard as guard:
			guard.check_flags(self.flags)  # token.py re-reads the flags here
			guard.succeeded()
		return pdf_bytes + b"%signed\n", dict(selected.metadata)


class ServiceTestCase(unittest.TestCase):
	site_name = "MODE:result:allow"
	verifier_error = None

	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		config_path = Path(self._dir.name) / "config.json"
		config_path.write_text(
			json.dumps({
				"host": "127.0.0.1",
				"allowed_origins": [],            # fresh install: nothing pre-approved
				"timestamp": {"allowed_urls": ["https://timestamp.digicert.com"]},
			}),
			encoding="utf-8",
		)
		self.config = load_config(config_path)
		self.trust = TrustStore(Path(self._dir.name) / "allowed_origins.json")
		self.dialogs = DialogHost(child_script=STUB)
		self.addCleanup(self.dialogs.shutdown)
		self.events = []
		self.consent_calls = []
		self.pin_calls = []

		def fake_consent(origin, claims, *, host):
			self.consent_calls.append(origin)
			raise AssertionError("the consent dialog must not be reached")

		def fake_pin(origin, document_name, *, host, warnings=(), final_try=False):
			self.pin_calls.append(origin)
			raise AssertionError("the PIN dialog must not be reached")

		def verifier(origin, token):
			if self.verifier_error:
				raise self.verifier_error
			return SiteClaims(site_name=self.site_name, user="ceo@acme.test")

		self.service = SignerService(
			self.config,
			trust_store=self.trust,
			dialog_host=self.dialogs,
			pair_guard=PairGuard(max_attempts_per_hour=1000),
			consent=fake_consent,
			verifier=verifier,
			pin_prompt=fake_pin,
		)
		self.token = FakeToken(self.events)
		patcher = mock.patch.object(service_module, "TokenClient", self.token)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"

		self.server = self.service.make_server(("127.0.0.1", 0))
		self.addCleanup(self.server.server_close)
		threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
		self.addCleanup(self.server.shutdown)
		self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

	def use_real_dialogs(self):
		self.service.consent = consent_dialog
		self.service.pin_prompt = request_pin

	def pair_request(self, origin=ERP):
		return _request(self.base + "/v1/pair", method="POST", origin=origin, body={"pairing_token": "t" * 32})

	def sign_request(self, document_name, *, origin=ERP, **extra):
		_s, _h, issued = _request(self.base + "/v1/nonce", method="POST", origin=origin, body={"purpose": "sign"})
		body = {
			"nonce": issued["nonce"],
			"pdf_base64": base64.b64encode(PDF).decode("ascii"),
			"pdf_sha256": hashlib.sha256(PDF).hexdigest(),
			"signing_request": {"signature_meta": {"reason": "test"}, "document_name": document_name},
			"certificate": {"fingerprint_sha256": "ab" * 32},
		}
		body.update(extra)
		return _request(self.base + "/v1/sign", method="POST", origin=origin, body=body)


class TestPreflight(ServiceTestCase):
	def test_unpaired_preflight_on_bootstrap_paths_is_204_with_cors(self):
		# A 403 preflight fails regardless of headers, which is what made an unpaired
		# site look like an offline signer.
		for path in ("/v1/health", "/v1/pair"):
			with self.subTest(path=path):
				status, headers, _ = _request(
					self.base + path,
					method="OPTIONS",
					origin=ERP,
					headers={"Access-Control-Request-Method": "POST"},
				)
				self.assertEqual(204, status)
				self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
				self.assertEqual("true", headers.get("Access-Control-Allow-Private-Network"))

	def test_unpaired_preflight_on_protected_path_is_dark(self):
		status, headers, _ = _request(self.base + "/v1/sign", method="OPTIONS", origin=ERP)
		self.assertEqual(204, status)
		self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

	def test_malformed_origin_preflight_is_dark_and_does_not_500(self):
		status, headers, _ = _request(self.base + "/v1/health", method="OPTIONS", origin="null")
		self.assertEqual(204, status)
		self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

	def test_paired_origin_gets_cors_on_protected_preflight(self):
		self.trust.allow(ERP)
		status, headers, _ = _request(self.base + "/v1/sign", method="OPTIONS", origin=ERP)
		self.assertEqual(204, status)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))


class TestHealth(ServiceTestCase):
	def test_unpaired_health_is_readable_and_reports_not_paired(self):
		status, headers, body = _request(self.base + "/v1/health", origin=ERP)
		self.assertEqual(200, status)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
		self.assertFalse(body["paired"])

	def test_paired_health_reports_paired(self):
		self.trust.allow(ERP)
		_status, _headers, body = _request(self.base + "/v1/health", origin=ERP)
		self.assertTrue(body["paired"])

	def test_health_matches_across_default_port_forms(self):
		self.trust.allow("https://noise.m.frappe.cloud:443")
		_s, _h, body = _request(self.base + "/v1/health", origin="https://noise.m.frappe.cloud")
		self.assertTrue(body["paired"])


class TestProtectedRoutesStayDark(ServiceTestCase):
	def test_unpaired_origin_reaches_no_protected_route(self):
		for method, path, body in (
			("GET", "/v1/providers", None),
			("POST", "/v1/nonce", {"purpose": "sign"}),
			("POST", "/v1/certificates", {"nonce": "x"}),
			("POST", "/v1/sign", {"pdf_base64": ""}),
		):
			with self.subTest(path=path):
				status, headers, body_out = _request(self.base + path, method=method, origin=ERP, body=body)
				self.assertEqual(403, status)
				self.assertEqual("ORIGIN_NOT_PAIRED", body_out["error"]["code"])
				# Dark: the browser must not hand this body to the page.
				self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
		self.assertEqual([], self.pin_calls)
		self.assertEqual([], self.events)


class TestPairing(ServiceTestCase):
	def test_allow_persists_and_unlocks_protected_routes(self):
		self.use_real_dialogs()
		status, headers, body = self.pair_request()
		self.assertEqual(200, status)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
		self.assertTrue(body["paired"])
		self.assertEqual(self.site_name, body["claimed_site_name"])
		self.assertEqual("ceo@acme.test", body["claimed_user"])
		self.assertNotIn("site_name", body)  # never presented as verified identity
		self.assertTrue(self.trust.is_allowed(ERP))

		status, _headers, _body = _request(self.base + "/v1/nonce", method="POST", origin=ERP, body={"purpose": "sign"})
		self.assertEqual(200, status)

	def test_deny_records_a_persisted_denial_and_does_not_pair(self):
		self.use_real_dialogs()
		self.site_name = "MODE:result:deny"
		status, _headers, body = self.pair_request()
		self.assertEqual(403, status)
		self.assertEqual("PAIR_DENIED", body["error"]["code"])
		self.assertFalse(self.trust.is_allowed(ERP))
		self.assertTrue(self.trust.is_denied(ERP))

	def test_denied_origin_is_refused_without_reprompting(self):
		self.trust.record_denial(ERP)
		status, _headers, body = self.pair_request()
		self.assertEqual(403, status)
		self.assertEqual("PAIR_DENIED", body["error"]["code"])
		self.assertEqual([], self.consent_calls)

	def test_invalid_proof_never_opens_a_dialog(self):
		self.verifier_error = PairProofInvalid()
		status, headers, body = self.pair_request()
		self.assertEqual(403, status)
		self.assertEqual("PAIR_PROOF_INVALID", body["error"]["code"])
		self.assertEqual([], self.consent_calls)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))

	def test_malformed_origin_is_rejected_before_any_dialog(self):
		status, _headers, body = self.pair_request(origin="null")
		self.assertEqual(400, status)
		self.assertEqual("INVALID_ORIGIN", body["error"]["code"])
		self.assertEqual([], self.consent_calls)

	def test_already_paired_is_idempotent(self):
		self.trust.allow(ERP)
		status, _headers, body = _request(self.base + "/v1/pair", method="POST", origin=ERP, body={})
		self.assertEqual(200, status)
		self.assertTrue(body["paired"])
		self.assertEqual([], self.consent_calls)

	def test_concurrent_prompt_is_dialog_busy_429(self):
		# The REAL host's lock is held by another dialog; the stub would otherwise allow.
		self.use_real_dialogs()
		with _HeldDialogLock(self.dialogs):
			status, _headers, body = self.pair_request()
		self.assertEqual(429, status)
		self.assertEqual("DIALOG_BUSY", body["error"]["code"])
		self.assertEqual(BUSY_MESSAGE, body["error"]["message"])
		self.assertFalse(self.trust.is_allowed(ERP))
		self.assertFalse(self.trust.is_denied(ERP))
		# Once the other dialog is gone, the same request pairs.
		status, _headers, body = self.pair_request()
		self.assertEqual(200, status)

	def test_headless_fails_closed_with_a_cli_hint(self):
		self.use_real_dialogs()
		self.site_name = "MODE:unavailable:tk_init_failed"
		status, _headers, body = self.pair_request()
		self.assertEqual(503, status)
		self.assertEqual("PAIR_PROMPT_UNAVAILABLE", body["error"]["code"])
		self.assertEqual(TK_INIT_MESSAGE, body["error"]["message"])
		self.assertEqual({"cause": "tk_init_failed"}, body["error"]["details"])
		self.assertIn("--allow", body["error"]["message"])
		self.assertFalse(self.trust.is_allowed(ERP))
		self.assertFalse(self.trust.is_denied(ERP))

	def test_rate_limit_stops_repeated_attempts(self):
		self.use_real_dialogs()
		self.site_name = "MODE:result:deny"
		# First denial arms the global cooldown.
		self.pair_request()
		# A different origin must also be blocked: rotation was the bypass.
		self.service.consent = lambda origin, claims, *, host: self.consent_calls.append(origin)
		status, _headers, body = self.pair_request(origin="https://evil2.example")
		self.assertEqual(429, status)
		self.assertEqual("PAIR_RATE_LIMITED", body["error"]["code"])
		self.assertEqual([], self.consent_calls)


class _HeldDialogLock:
	"""Holds the real DialogHost's UI mutex from another thread, as an open dialog would."""

	def __init__(self, host):
		self.host = host
		self.entered = threading.Event()
		self.release = threading.Event()

	def __enter__(self):
		def hold():
			self.host.run_exclusive(lambda: (self.entered.set(), self.release.wait(30)))

		self.thread = threading.Thread(target=hold, daemon=True)
		self.thread.start()
		assert self.entered.wait(5)
		return self

	def __exit__(self, *_exc):
		self.release.set()
		self.thread.join(5)
		return False


class SignTestCase(ServiceTestCase):
	def setUp(self):
		super().setUp()
		self.trust.allow(ERP)


class TestSign(SignTestCase):
	def test_dialog_pin_signs_and_the_order_is_select_state_dialog_sign(self):
		self.use_real_dialogs()
		real = self.service.pin_prompt

		def prompt(*args, **kwargs):
			self.events.append("pin_prompt")
			return real(*args, **kwargs)

		self.service.pin_prompt = prompt
		status, headers, body = self.sign_request(f"MODE:ok_entered:{DIALOG_PIN}")
		self.assertEqual(200, status, body)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
		self.assertEqual(PDF + b"%signed\n", base64.b64decode(body["signed_pdf_base64"]))
		self.assertEqual(["token_client", "select", "token_state", "pin_prompt", "sign_pdf"], self.events)
		self.assertEqual([DIALOG_PIN], self.token.pins)

	def test_body_pin_not_used(self):
		self.use_real_dialogs()
		status, _headers, body = self.sign_request(f"MODE:ok_entered:{DIALOG_PIN}", pin=BODY_PIN)
		self.assertEqual(200, status, body)
		self.assertEqual([DIALOG_PIN], self.token.pins)

	def test_body_pin_never_skips_the_dialog(self):
		# With the dialog cancelled, a PIN in the body must not be used as a fallback.
		self.use_real_dialogs()
		status, _headers, body = self.sign_request("MODE:result:cancelled", pin=BODY_PIN)
		self.assertEqual(409, status)
		self.assertEqual("PIN_CANCELLED", body["error"]["code"])
		self.assertEqual([], self.token.pins)
		self.assertNotIn("sign_pdf", self.events)

	def test_unsupported_signature_meta_is_refused_before_any_token_or_dialog(self):
		cases = (
			{"signature_img": "/etc/hosts"},
			{"manual_fonts": {"F": "/etc/hosts"}},
			{"ltv": True},
			{"signature_appearance": {"background": "/etc/hosts"}},
			{"x_" + META_MARK: META_MARK},
			{"reason": META_MARK + "\x1b[2J"},
			{"aligned": True},
			{"sigpage": 10**30},
		)
		for meta in cases:
			with self.subTest(meta=meta):
				status, headers, body = self.sign_request(
					"INV-1", signing_request={"signature_meta": meta, "document_name": "INV-1"}
				)
				self.assertEqual(400, status)
				self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
				self.assertEqual({"code": "INVALID_REQUEST", "message": UNSUPPORTED_META}, body["error"])
				self.assertNotIn(META_MARK, json.dumps(body))
				self.assertNotIn("/etc/hosts", json.dumps(body))
		self.assertEqual([], self.events, "the token must not be touched")
		self.assertEqual([], self.pin_calls, "no PIN may be asked for")

	def test_the_server_icon_is_dropped_and_the_rest_reaches_sign_pdf(self):
		self.use_real_dialogs()
		appearance = {"display": "Digitally signed by USB DSC signer", "outline": [0, 0, 0], "border": 0}
		meta = {"reason": "Digitally signed invoice", "signature_appearance": dict(appearance, icon="/srv/sig.png")}
		status, _headers, body = self.sign_request(
			f"MODE:ok_entered:{DIALOG_PIN}", signing_request={"signature_meta": meta, "document_name": f"MODE:ok_entered:{DIALOG_PIN}"}
		)
		self.assertEqual(200, status, body)
		self.assertEqual([{"reason": "Digitally signed invoice", "signature_appearance": appearance}], self.token.metadatas)

	def test_concurrent_pin_prompt_is_dialog_busy_429(self):
		self.use_real_dialogs()
		with _HeldDialogLock(self.dialogs):
			status, _headers, body = self.sign_request(f"MODE:ok_entered:{DIALOG_PIN}")
		self.assertEqual(429, status)
		self.assertEqual("DIALOG_BUSY", body["error"]["code"])
		self.assertEqual(BUSY_MESSAGE, body["error"]["message"])
		self.assertEqual([], self.token.pins)
		status, _headers, body = self.sign_request(f"MODE:ok_entered:{DIALOG_PIN}")
		self.assertEqual(200, status, body)

	def test_hidden_certificates_stop_before_the_dialog(self):
		self.token.select_error = CertificatesHidden()
		status, _headers, body = self.sign_request("INV-1")
		self.assertEqual(409, status)
		self.assertEqual("TOKEN_CERTIFICATES_HIDDEN", body["error"]["code"])
		self.assertEqual(
			"This token hides its certificates until login, which this version of the signer does not support.",
			body["error"]["message"],
		)
		self.assertNotIn("details", body["error"])
		self.assertEqual([], self.pin_calls)
		self.assertNotIn("sign_pdf", self.events)

	def test_token_state_failure_stops_before_the_dialog(self):
		self.token.state_error = TokenUnavailable("The USB token is not available. Check that it is plugged in and try again.")
		status, _headers, body = self.sign_request("INV-1")
		self.assertEqual(409, status)
		self.assertEqual("TOKEN_UNAVAILABLE", body["error"]["code"])
		self.assertEqual([], self.pin_calls)

	def test_locked_token_stops_before_the_dialog(self):
		self.token.flags = 0x00040000  # CKF_USER_PIN_LOCKED
		status, _headers, body = self.sign_request("INV-1")
		self.assertEqual(423, status)
		self.assertEqual("PIN_LOCKED", body["error"]["code"])
		self.assertEqual([], self.pin_calls)
		self.assertNotIn("sign_pdf", self.events)

	def test_busy_token_is_token_busy_429_before_its_flags_or_any_dialog(self):
		lock = self.service.pin_limiter.token_lock(TOKEN_SERIAL)
		self.assertTrue(lock.acquire(timeout=1))  # another request is using this token
		try:
			with mock.patch.object(service_module, "TOKEN_LOCK_TIMEOUT_SECONDS", 0.2):
				status, headers, body = self.sign_request("INV-1")
		finally:
			lock.release()
		self.assertEqual(429, status)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
		self.assertEqual(
			{
				"code": "TOKEN_BUSY",
				"message": "Another signing request for this token is still in progress. Try again in a moment.",
			},
			body["error"],
		)
		self.assertEqual(["token_client", "select"], self.events)
		self.assertEqual([], self.pin_calls)
		self.assertEqual([], self.token.pins)

	def test_final_try_reaches_the_dialog_request(self):
		self.use_real_dialogs()
		self.token.flags = 0x00020000  # CKF_USER_PIN_FINAL_TRY
		requests = _spy_requests(self.dialogs)
		status, _headers, body = self.sign_request(f"MODE:ok_entered:{DIALOG_PIN}")
		self.assertEqual(200, status, body)
		self.assertEqual(1, len(requests))
		self.assertIs(True, requests[0]["final_try"])
		self.assertEqual("pin", requests[0]["kind"])
		self.assertEqual(ERP, requests[0]["origin"])
		self.assertEqual([f"MODE:ok_entered:{DIALOG_PIN}"], requests[0]["claims"])

	def test_request_validation_happens_before_any_token_or_dialog(self):
		cases = (
			({"pdf_base64": 5}, "INVALID_REQUEST"),
			({"pdf_base64": "!!"}, "INVALID_REQUEST"),
			({"pdf_sha256": "0" * 64}, "INVALID_PDF"),
			({"signing_request": {}}, "INVALID_REQUEST"),
			({"signing_request": {"signature_meta": {"signature_img": "/etc/hosts"}}}, "INVALID_REQUEST"),
			({"signing_request": {"signature_meta": {}, "timestamp_url": "https://tsa.evil.example"}}, "TSA_NOT_ALLOWED"),
		)
		for extra, code in cases:
			with self.subTest(code=code, extra=extra):
				status, _headers, body = self.sign_request("INV-1", **extra)
				self.assertIn(status, (400, 409))
				self.assertEqual(code, body["error"]["code"])
		self.assertEqual([], self.events)
		self.assertEqual([], self.pin_calls)


def _spy_requests(host):
	"""Record every request dict the real host is asked to show, then show it."""
	requests = []
	real = host.run_dialog

	def run_dialog(request):
		requests.append(json.loads(json.dumps(request)))
		return real(request)

	host.run_dialog = run_dialog
	return requests


class TestServerAndErrors(SignTestCase):
	def test_serve_forever_is_gone_and_make_server_defaults_to_the_config_address(self):
		self.assertFalse(hasattr(SignerService, "serve_forever"))
		with mock.patch.object(service_module._SignerHTTPServer, "__init__", return_value=None) as init:
			self.service.make_server()
		self.assertEqual((self.config.host, self.config.port), init.call_args.args[0])

	def test_unexpected_get_error_is_a_generic_500(self):
		self.service.providers.public_providers = mock.Mock(side_effect=RuntimeError("driver said: secret"))
		status, headers, body = _request(self.base + "/v1/providers", origin=ERP)
		self.assertEqual(500, status)
		self.assertEqual(
			{"ok": False, "error": {"code": "LOCAL_SIGNER_ERROR", "message": "The local signer could not process this request."}},
			body,
		)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))

	def test_unexpected_post_error_is_a_generic_500(self):
		def explode(*_args, **_kwargs):
			raise RuntimeError("driver said: secret")

		self.token.sign_pdf = explode
		self.service.pin_prompt = lambda *a, **k: DIALOG_PIN
		status, _headers, body = self.sign_request("INV-1")
		self.assertEqual(500, status)
		self.assertEqual("LOCAL_SIGNER_ERROR", body["error"]["code"])
		self.assertNotIn("secret", json.dumps(body))

	def test_handler_failure_logs_one_fixed_line_and_a_broken_pipe_logs_nothing(self):
		handler = self.server.RequestHandlerClass
		for error, expected in (
			(RuntimeError("boom: secret"), service_module.HANDLER_ERROR_LINE + "\n"),
			(BrokenPipeError(32, "Broken pipe"), ""),
			(ConnectionResetError(54, "reset"), ""),
		):
			with self.subTest(error=type(error).__name__):
				stderr = io.StringIO()
				with mock.patch.object(handler, "_respond", side_effect=error), mock.patch("sys.stderr", stderr):
					with self.assertRaises(OSError):  # no response: the connection just closes
						urllib.request.urlopen(urllib.request.Request(self.base + "/v1/health"), timeout=10).read()
					wait_for_handlers(self.server)
				self.assertEqual(expected, stderr.getvalue())


def wait_for_handlers(server, timeout=5.0):
	"""Join the server's request threads (ThreadingMixIn tracks them when block_on_close)."""
	for thread in list(getattr(server, "_threads", None) or ()):
		thread.join(timeout)


class TestStaticConfigOrigins(ServiceTestCase):
	def test_static_origin_is_trusted_without_pairing(self):
		config_path = Path(self._dir.name) / "static.json"
		config_path.write_text(
			json.dumps({"host": "127.0.0.1", "allowed_origins": ["https://fleet.example:443"]}),
			encoding="utf-8",
		)
		service = SignerService(
			load_config(config_path),
			trust_store=self.trust,
			dialog_host=self.dialogs,
			consent=lambda o, c, *, host: False,
			verifier=lambda o, t: SiteClaims(),
		)
		# Canonicalised on load, so the browser's port-less form still matches.
		self.assertTrue(service.is_paired("https://fleet.example"))


if __name__ == "__main__":
	unittest.main()
