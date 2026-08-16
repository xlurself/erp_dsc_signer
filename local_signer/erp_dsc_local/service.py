"""Strict loopback HTTP API for the browser-side Sales Invoice workflow.

CORS policy
-----------
Only two paths are reachable by an origin this workstation has not paired with:
`/v1/health` and `/v1/pair`.  Those answer preflights with 204 and echo CORS headers,
because a browser can only read an error if the preflight itself succeeded -- a 403
fails the preflight no matter what headers it carries, which is why an unpaired site
used to surface as "the signer is not reachable".

Every other path stays dark to an unpaired origin: no CORS headers, so the browser
refuses to hand the page a body.  That keeps signing errors and provider inventories
unreadable to a site the user never approved.
"""

from __future__ import annotations

import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import (
	InvalidOrigin,
	LocalSignerError,
	OriginNotPaired,
	PairDenied,
	PairInProgress,
	PairPromptUnavailable,
	PromptTimedOut,
)
from .nonces import NonceStore
from .origins import try_canonical_origin
from .pairing import PairGuard, consent_dialog, verify_pairing_proof
from .pin import request_pin
from .providers import ProviderRegistry
from .token import TokenClient
from .trust import TrustStore
from .ui import DialogHost, UiBusy, UiTimedOut, UiUnavailable


VERSION = "0.2.0"

# The only paths an unpaired origin may talk to.
BOOTSTRAP_PATHS = frozenset({"/v1/health", "/v1/pair"})


class SignerService:
	def __init__(
		self,
		config,
		*,
		trust_store=None,
		dialog_host=None,
		pair_guard=None,
		consent=None,
		verifier=None,
		pin_prompt=None,
	):
		self.config = config
		self.nonces = NonceStore(config.nonce_ttl_seconds, config.max_nonce_count)
		self.providers = ProviderRegistry(config)
		self.trust = trust_store if trust_store is not None else TrustStore()
		self.dialogs = dialog_host if dialog_host is not None else DialogHost()
		self.pair_guard = pair_guard if pair_guard is not None else PairGuard()
		# Injected in tests so the suite never opens a real Tk window.
		self.consent = consent or consent_dialog
		self.verify_proof = verifier or verify_pairing_proof
		self.pin_prompt = pin_prompt or request_pin

	def is_paired(self, canonical_origin: str) -> bool:
		"""Static operator config union runtime consent."""
		return canonical_origin in self.config.allowed_origins or self.trust.is_allowed(canonical_origin)

	def pair(self, canonical_origin: str, pairing_token) -> dict:
		"""Verify the proof, ask the user, and persist on an explicit Allow."""
		if self.trust.is_denied(canonical_origin):
			raise PairDenied()
		# Rate limit before the callback so we cannot be used to generate traffic.
		self.pair_guard.check_and_record()
		claims = self.verify_proof(canonical_origin, pairing_token)

		try:
			allowed = self.dialogs.run_exclusive(lambda: self.consent(canonical_origin, claims))
		except UiBusy as exc:
			raise PairInProgress() from exc
		except UiTimedOut as exc:
			raise PromptTimedOut() from exc
		except UiUnavailable as exc:
			raise PairPromptUnavailable() from exc

		if not allowed:
			self.trust.record_denial(canonical_origin)
			self.pair_guard.record_denial()
			raise PairDenied()

		self.trust.allow(canonical_origin, site_name=claims.site_name, user=claims.user)
		return {
			"ok": True,
			"origin": canonical_origin,
			"paired": True,
			# Named as claims: these came from the site, not from a verified identity.
			"claimed_site_name": claims.site_name,
			"claimed_user": claims.user,
		}

	def ask_for_pin(self, canonical_origin: str, document_name) -> str:
		try:
			return self.dialogs.run_exclusive(
				lambda: self.pin_prompt(canonical_origin, document_name)
			)
		except UiBusy as exc:
			raise PairInProgress() from exc
		except UiTimedOut as exc:
			raise PromptTimedOut() from exc
		except UiUnavailable as exc:
			raise PairPromptUnavailable() from exc

	def handler(self):
		service = self

		class Handler(BaseHTTPRequestHandler):
			server_version = f"ERPDSCLocal/{VERSION}"

			# ------------------------------------------------------------ verbs

			def do_OPTIONS(self):
				# Never raises: a preflight that 500s is indistinguishable from an
				# offline signer, which is the failure this design exists to remove.
				try:
					canonical = try_canonical_origin(self.headers.get("Origin", ""))
					if canonical and (self.path in BOOTSTRAP_PATHS or service.is_paired(canonical)):
						self._respond(204, {}, canonical, preflight=True)
					else:
						self._respond(204, {}, None)
				except Exception:
					self._respond(204, {}, None)

			def do_GET(self):
				try:
					if self.path == "/v1/health":
						self._health()
					elif self.path == "/v1/providers":
						origin = self._paired_origin()
						self._respond(200, {"ok": True, "providers": service.providers.public_providers()}, origin)
					else:
						self._respond(404, self._not_found(), None)
				except LocalSignerError as exc:
					self._error(exc)

			def do_POST(self):
				try:
					if self.path == "/v1/pair":
						self._pair()
						return
					origin = self._paired_origin()
					body = self._json_body()
					if self.path == "/v1/nonce":
						nonce, ttl = service.nonces.issue(origin, body.get("purpose"))
						self._respond(200, {"ok": True, "nonce": nonce, "expires_in_seconds": ttl}, origin)
					elif self.path == "/v1/certificates":
						service.nonces.consume(body.get("nonce"), origin, "certificates")
						client = TokenClient(service.providers.resolve(body.get("provider", "auto"), body.get("module_id")))
						certificates = client.certificates()
						self._respond(200, {"ok": True, "certificates": [item.metadata for item in certificates]}, origin)
					elif self.path == "/v1/sign":
						service.nonces.consume(body.get("nonce"), origin, "sign")
						self._sign(origin, body)
					else:
						self._respond(404, self._not_found(), origin)
				except LocalSignerError as exc:
					self._error(exc)
				except Exception:
					self._error(LocalSignerError("LOCAL_SIGNER_ERROR", "The local signer could not process this request.", status=500))

			# --------------------------------------------------------- endpoints

			def _health(self):
				canonical = try_canonical_origin(self.headers.get("Origin", ""))
				if canonical is None:
					if not service.config.allow_originless_health:
						raise InvalidOrigin()
					self._respond(200, {"ok": True, "version": VERSION, "paired": False}, None)
					return
				# Readable by any well-formed origin: the client needs `paired` to tell
				# "not paired" apart from "not running".
				self._respond(
					200,
					{"ok": True, "version": VERSION, "paired": service.is_paired(canonical)},
					canonical,
				)

			def _pair(self):
				canonical = try_canonical_origin(self.headers.get("Origin", ""))
				if canonical is None:
					raise InvalidOrigin()
				body = self._json_body()
				if service.is_paired(canonical):
					self._respond(200, {"ok": True, "origin": canonical, "paired": True}, canonical)
					return
				self._respond(200, service.pair(canonical, body.get("pairing_token")), canonical)

			def _sign(self, origin, body):
				encoded = body.get("pdf_base64")
				if not isinstance(encoded, str):
					raise LocalSignerError("INVALID_REQUEST", "pdf_base64 is required.")
				try:
					pdf = base64.b64decode(encoded, validate=True)
				except Exception as exc:
					raise LocalSignerError("INVALID_REQUEST", "pdf_base64 is invalid.") from exc
				if not pdf.startswith(b"%PDF-") or len(pdf) > service.config.max_pdf_bytes:
					raise LocalSignerError("INVALID_PDF", "The requested PDF is invalid or exceeds the local size limit.")
				if body.get("pdf_sha256") != hashlib.sha256(pdf).hexdigest():
					raise LocalSignerError("INVALID_PDF", "The PDF digest does not match the signing request.")
				request = body.get("signing_request")
				if not isinstance(request, dict) or not isinstance(request.get("signature_meta"), dict):
					raise LocalSignerError("INVALID_REQUEST", "A signing_request with signature_meta is required.")
				timestamp_url = request.get("timestamp_url")
				if timestamp_url and timestamp_url not in service.config.allowed_timestamp_urls:
					raise LocalSignerError("TSA_NOT_ALLOWED", "The ERP timestamp URL is not allowed by this workstation configuration.", status=409)
				client = TokenClient(service.providers.resolve(body.get("provider", "auto"), body.get("module_id")))
				document_name = request.get("document_name")
				pin = (
					body.get("pin")
					if service.config.allow_development_pin_in_request
					else service.ask_for_pin(origin, document_name)
				)
				signed_pdf, certificate = client.sign_pdf(pdf, request["signature_meta"], body.get("certificate"), pin, timestamp_url)
				self._respond(200, {"ok": True, "signed_pdf_base64": base64.b64encode(signed_pdf).decode("ascii"), "certificate_metadata": certificate}, origin)

			# ----------------------------------------------------------- helpers

			def _paired_origin(self) -> str:
				"""Canonical origin for a protected route, or raise."""
				canonical = try_canonical_origin(self.headers.get("Origin", ""))
				if canonical is None:
					raise InvalidOrigin()
				if not service.is_paired(canonical):
					raise OriginNotPaired()
				return canonical

			def _not_found(self) -> dict:
				return {"ok": False, "error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}

			def _json_body(self):
				length = self.headers.get("Content-Length")
				try:
					length = int(length)
				except (TypeError, ValueError):
					raise LocalSignerError("INVALID_REQUEST", "Content-Length is required.")
				if not 0 < length <= service.config.max_request_bytes:
					raise LocalSignerError("REQUEST_TOO_LARGE", "Request exceeds the local signer size limit.", status=413)
				try:
					body = json.loads(self.rfile.read(length))
				except (UnicodeDecodeError, json.JSONDecodeError) as exc:
					raise LocalSignerError("INVALID_REQUEST", "Request body must be JSON.") from exc
				if not isinstance(body, dict):
					raise LocalSignerError("INVALID_REQUEST", "Request body must be a JSON object.")
				return body

			def _respond(self, status, payload, origin, *, preflight: bool = False):
				data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
				self.send_response(status)
				self.send_header("Content-Type", "application/json; charset=utf-8")
				self.send_header("Content-Length", str(len(data)))
				self.send_header("Cache-Control", "no-store")
				if origin:
					self.send_header("Access-Control-Allow-Origin", origin)
					self.send_header("Vary", "Origin")
					self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					self.send_header("Access-Control-Allow-Headers", "Content-Type")
					if preflight:
						# Chrome's Private Network Access gate for a public HTTPS page
						# reaching a loopback address.  Not required by today's Chrome
						# (measured), included so a future tightening cannot break it.
						self.send_header("Access-Control-Allow-Private-Network", "true")
						self.send_header("Access-Control-Max-Age", "600")
				self.end_headers()
				if status != 204:
					self.wfile.write(data)

			def _error(self, exc):
				canonical = try_canonical_origin(self.headers.get("Origin", ""))
				# Bootstrap errors must be readable, or the page cannot tell "not
				# paired" from "not running".  Everything else stays dark.
				readable = canonical and (self.path in BOOTSTRAP_PATHS or service.is_paired(canonical))
				self._respond(exc.status, exc.as_dict(), canonical if readable else None)

			def log_message(self, _format, *_args):
				return

		return Handler

	def serve_forever(self):
		server = ThreadingHTTPServer((self.config.host, self.config.port), self.handler())
		try:
			server.serve_forever()
		finally:
			server.server_close()
			self.dialogs.shutdown()
