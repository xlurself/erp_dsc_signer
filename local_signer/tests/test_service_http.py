import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from erp_dsc_local.config import load_config
from erp_dsc_local.errors import PairProofInvalid
from erp_dsc_local.pairing import SiteClaims
from erp_dsc_local.service import SignerService
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import UiBusy, UiUnavailable


ERP = "https://noise.m.frappe.cloud"


class _FakeDialogHost:
	"""Stands in for the Tk-owning worker. Never opens a window."""

	def __init__(self, *, raises=None):
		self.raises = raises
		self.calls = 0

	def run_exclusive(self, dialog):
		self.calls += 1
		if self.raises:
			raise self.raises
		return dialog()

	def shutdown(self):
		pass


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
		with urllib.request.urlopen(req, timeout=10) as response:
			raw = response.read()
			return response.status, dict(response.headers), (json.loads(raw) if raw else {})
	except urllib.error.HTTPError as exc:
		raw = exc.read()
		return exc.code, dict(exc.headers), (json.loads(raw) if raw else {})


class ServiceTestCase(unittest.TestCase):
	consent_result = True
	verifier_error = None

	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		config_path = Path(self._dir.name) / "config.json"
		config_path.write_text(
			json.dumps({
				"host": "127.0.0.1",
				"port": 17777,
				"allowed_origins": [],            # fresh install: nothing pre-approved
				"timestamp": {"allowed_urls": ["https://timestamp.digicert.com"]},
			}),
			encoding="utf-8",
		)
		self.config = load_config(config_path)
		self.trust = TrustStore(Path(self._dir.name) / "allowed_origins.json")
		self.dialogs = _FakeDialogHost()
		self.consent_calls = []

		def consent(origin, claims):
			self.consent_calls.append((origin, claims))
			return self.consent_result

		def verifier(origin, token):
			if self.verifier_error:
				raise self.verifier_error
			return SiteClaims(site_name="Acme Ltd", user="ceo@acme.test")

		self.service = SignerService(
			self.config,
			trust_store=self.trust,
			dialog_host=self.dialogs,
			consent=consent,
			verifier=verifier,
			pin_prompt=lambda origin, name: "1234",
		)
		self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.service.handler())
		self.addCleanup(self.server.server_close)
		threading.Thread(target=self.server.serve_forever, daemon=True).start()
		self.addCleanup(self.server.shutdown)
		self.base = f"http://127.0.0.1:{self.server.server_address[1]}"


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


class TestPairing(ServiceTestCase):
	def test_allow_persists_and_unlocks_protected_routes(self):
		status, headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(200, status)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))
		self.assertTrue(body["paired"])
		self.assertEqual("Acme Ltd", body["claimed_site_name"])
		self.assertNotIn("site_name", body)  # never presented as verified identity
		self.assertTrue(self.trust.is_allowed(ERP))

		status, _headers, _body = _request(self.base + "/v1/nonce", method="POST", origin=ERP, body={"purpose": "sign"})
		self.assertEqual(200, status)

	def test_deny_records_a_persisted_denial_and_does_not_pair(self):
		self.consent_result = False
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(403, status)
		self.assertEqual("PAIR_DENIED", body["error"]["code"])
		self.assertFalse(self.trust.is_allowed(ERP))
		self.assertTrue(self.trust.is_denied(ERP))

	def test_denied_origin_is_refused_without_reprompting(self):
		self.trust.record_denial(ERP)
		before = self.dialogs.calls
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(403, status)
		self.assertEqual("PAIR_DENIED", body["error"]["code"])
		self.assertEqual(before, self.dialogs.calls)

	def test_invalid_proof_never_opens_a_dialog(self):
		self.verifier_error = PairProofInvalid()
		status, headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(403, status)
		self.assertEqual("PAIR_PROOF_INVALID", body["error"]["code"])
		self.assertEqual(0, self.dialogs.calls)
		self.assertEqual(ERP, headers.get("Access-Control-Allow-Origin"))

	def test_malformed_origin_is_rejected_before_any_dialog(self):
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin="null", body={"pairing_token": "t" * 32}
		)
		self.assertEqual(400, status)
		self.assertEqual("INVALID_ORIGIN", body["error"]["code"])
		self.assertEqual(0, self.dialogs.calls)

	def test_already_paired_is_idempotent(self):
		self.trust.allow(ERP)
		status, _headers, body = _request(self.base + "/v1/pair", method="POST", origin=ERP, body={})
		self.assertEqual(200, status)
		self.assertTrue(body["paired"])
		self.assertEqual(0, self.dialogs.calls)

	def test_concurrent_prompt_is_429(self):
		self.service.dialogs = _FakeDialogHost(raises=UiBusy())
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(429, status)
		self.assertEqual("PAIR_IN_PROGRESS", body["error"]["code"])

	def test_headless_fails_closed_with_a_cli_hint(self):
		self.service.dialogs = _FakeDialogHost(raises=UiUnavailable())
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32}
		)
		self.assertEqual(503, status)
		self.assertEqual("PAIR_PROMPT_UNAVAILABLE", body["error"]["code"])
		self.assertIn("--allow", body["error"]["message"])
		self.assertFalse(self.trust.is_allowed(ERP))

	def test_rate_limit_stops_repeated_attempts(self):
		self.consent_result = False
		# First denial arms the global cooldown.
		_request(self.base + "/v1/pair", method="POST", origin=ERP, body={"pairing_token": "t" * 32})
		# A different origin must also be blocked: rotation was the bypass.
		status, _headers, body = _request(
			self.base + "/v1/pair", method="POST", origin="https://evil2.example", body={"pairing_token": "t" * 32}
		)
		self.assertEqual(429, status)
		self.assertEqual("PAIR_RATE_LIMITED", body["error"]["code"])


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
			consent=lambda o, c: False,
			verifier=lambda o, t: SiteClaims(),
		)
		# Canonicalised on load, so the browser's port-less form still matches.
		self.assertTrue(service.is_paired("https://fleet.example"))


if __name__ == "__main__":
	unittest.main()
