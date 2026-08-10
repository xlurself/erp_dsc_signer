"""Strict loopback HTTP API for the browser-side Sales Invoice workflow."""

from __future__ import annotations

import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import LocalSignerError
from .nonces import NonceStore
from .pin import request_pin
from .providers import ProviderRegistry
from .token import TokenClient


class SignerService:
	def __init__(self, config):
		self.config = config
		self.nonces = NonceStore(config.nonce_ttl_seconds, config.max_nonce_count)
		self.providers = ProviderRegistry(config)

	def handler(self):
		service = self

		class Handler(BaseHTTPRequestHandler):
			server_version = "ERPDSCLocal/0.1"

			def do_OPTIONS(self):
				self._respond(204, {}, self._origin(required=True))

			def do_GET(self):
				try:
					if self.path == "/v1/health":
						origin = self._origin(required=not service.config.allow_originless_health)
						self._respond(200, {"ok": True, "version": "0.1.0"}, origin)
					elif self.path == "/v1/providers":
						origin = self._origin(required=True)
						self._respond(200, {"ok": True, "providers": service.providers.public_providers()}, origin)
					else:
						self._respond(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, None)
				except LocalSignerError as exc:
					self._error(exc)

			def do_POST(self):
				try:
					origin = self._origin(required=True)
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
						self._respond(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "Unknown endpoint."}}, origin)
				except LocalSignerError as exc:
					self._error(exc)
				except Exception:
					self._error(LocalSignerError("LOCAL_SIGNER_ERROR", "The local signer could not process this request.", status=500))

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
				document_name = str(request.get("document_name") or "ERPNext invoice")[:140]
				pin = body.get("pin") if service.config.allow_development_pin_in_request else request_pin(f"Approve signing {document_name} with your USB DSC token.")
				signed_pdf, certificate = client.sign_pdf(pdf, request["signature_meta"], body.get("certificate"), pin, timestamp_url)
				self._respond(200, {"ok": True, "signed_pdf_base64": base64.b64encode(signed_pdf).decode("ascii"), "certificate_metadata": certificate}, origin)

			def _origin(self, required):
				origin = self.headers.get("Origin", "")
				if not origin and not required:
					return None
				if origin not in service.config.allowed_origins:
					raise LocalSignerError("ORIGIN_DENIED", "This ERP origin is not allowed by the local signer.", status=403)
				return origin

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

			def _respond(self, status, payload, origin):
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
				self.end_headers()
				if status != 204:
					self.wfile.write(data)

			def _error(self, exc):
				origin = self.headers.get("Origin") if self.headers.get("Origin") in service.config.allowed_origins else None
				self._respond(exc.status, exc.as_dict(), origin)

			def log_message(self, _format, *_args):
				return

		return Handler

	def serve_forever(self):
		server = ThreadingHTTPServer((self.config.host, self.config.port), self.handler())
		try:
			server.serve_forever()
		finally:
			server.server_close()
