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

PIN policy (spec 001 §7)
------------------------
The USB token PIN is typed only into the signer's own dialog child.  A ``pin`` key in
the HTTP body is ignored, always.  Everything that can refuse a signing request without
a PIN (certificate selection, token flags, the per-token limiter) runs before the dialog
is shown.  The PIN is never bound to a name in ``SignerService.sign``: it goes from the
dialog straight into ``sign_pdf``, whose adapter drops it once ``C_Login`` returns.  From
the flags read to the logout, the request holds its token's lock, so no other request can
change that token's PIN state in between.  A request for a token whose PIN dialog is open
is refused at once (``TokenBusy``), so it never queues up a second dialog behind it.

Signature metadata
------------------
``signature_meta`` comes from the paired site and goes to endesive as its ``udct``.
endesive also honours keys that read workstation files or reach the network, so the
request is checked by ``sanitise_signature_meta`` FIRST, before the token is touched or a
PIN is asked for: exactly the keys the ERP server sends, all of them, each type- and
size-checked and the constant ones pinned to the value the server sends; a missing or
other key, a bad value or a ``signature_meta`` that is not an object is ``INVALID_REQUEST``
with one fixed message that never names the field.  ``signature_appearance.icon`` is
dropped: it is a path on the ERP server, so a signature image is not supported for USB
signing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import dialog_child
from .errors import (
	InvalidOrigin,
	LocalSignerError,
	OriginNotPaired,
	PairDenied,
	PinLocked,
	PinRateLimited,
	TokenBusy,
)
from .nonces import NonceStore
from .origins import try_canonical_origin
from .pairing import PairGuard, consent_dialog, verify_pairing_proof
from .pin import request_pin
from .providers import ProviderRegistry
from .token import TokenClient
from .trust import TrustStore
from .ui import DialogHost


VERSION = "0.2.0"

# The only paths an unpaired origin may talk to.
BOOTSTRAP_PATHS = frozenset({"/v1/health", "/v1/pair"})

# Per-token PIN limiter (spec §2, §7).  Defined here and nowhere else.
MAX_PIN_FAILURES = 3
PIN_LOCKOUT_SECONDS = 900
# How long a signing request waits for its token's lock before TokenBusy (spec §2, §7).
TOKEN_LOCK_TIMEOUT_SECONDS = 20

# PKCS#11 CK_TOKEN_INFO flag values, used when PyKCS11 cannot be imported.
_CKF_USER_PIN_FINAL_TRY = 0x00020000
_CKF_USER_PIN_LOCKED = 0x00040000

# The one line written to stderr when a request handler fails outside do_GET/do_POST.
# Fixed text: no traceback, no exception text, nothing from the request.
HANDLER_ERROR_LINE = "erp-dsc-local: a request could not be handled and was dropped."


def _internal_error() -> LocalSignerError:
	return LocalSignerError("LOCAL_SIGNER_ERROR", "The local signer could not process this request.", status=500)


def _pin_flags() -> tuple[int, int]:
	"""``(CKF_USER_PIN_LOCKED, CKF_USER_PIN_FINAL_TRY)`` from PyKCS11, else the PKCS#11 values."""
	try:
		import PyKCS11
	except Exception:
		return _CKF_USER_PIN_LOCKED, _CKF_USER_PIN_FINAL_TRY
	return (
		int(getattr(PyKCS11, "CKF_USER_PIN_LOCKED", _CKF_USER_PIN_LOCKED)),
		int(getattr(PyKCS11, "CKF_USER_PIN_FINAL_TRY", _CKF_USER_PIN_FINAL_TRY)),
	)


# --- signature_meta allowlist --------------------------------------------------------
# The ONE message for every refused signature_meta: it never names the key or the value.
SIGNATURE_META_UNSUPPORTED = "The signing request contains an unsupported field."
MAX_META_TEXT_CHARS = 200
MAX_APPEARANCE_DISPLAY_CHARS = 500
MAX_BOX_COORDINATE = 14400  # PDF user units: the largest page PDF allows (200 in)
# Where endesive 2.19.3 puts these values: /M (signingdate), /Name (name), /Contact,
# /Location, /Reason and the field's /T (sigfield) are PDF string objects, which PyPDF2
# escapes; ``application`` becomes a RAW PDF name (``NameObject("/" + application)``), so it
# is pinned to "ERPNext".  ``signature_appearance.display`` is the other RAW sink: PyPDF2_annotate (graphics.py ~264,
# ``'({}) Tj'.format(text)``) writes it into the content stream after only a UTF-16BE ->
# latin-1 conversion, so ``_display`` refuses any character that yields a delimiter byte.
# ``sigbutton`` is never read by endesive 2.19.3: allowed because the ERP sends it, inert.
_SIGNINGDATE = re.compile(r"D:[0-9]{14}(?:Z|[+-][0-9]{2}'[0-9]{2}')", re.ASCII)
# PDF literal-string delimiters: '(' ')' '\'.  A UTF-16BE code unit carrying one of these
# as either byte ends the string or escapes the byte after it.
_PDF_STRING_DELIMITER_BYTES = frozenset({0x28, 0x29, 0x5C})
# Server-local, so never usable here; dropped without failing the request.
DROPPED_APPEARANCE_FIELDS = frozenset({"icon"})
_INVALID = object()


def _text(limit: int):
	"""A str of at most ``limit`` characters with no character the claim rule calls
	unreadable (``dialog_child._clean_claim``: Cc/Cf/Cs/Co/Cn/Zl/Zp, Zs other than a
	space, invisible fillers; ZWNJ/ZWJ only next to a virama).  U+00A0 counts as a space,
	as it does there.  Nothing is altered: a value that fails is refused, never cleaned."""

	def check(value):
		if type(value) is not str or len(value) > limit:
			return _INVALID
		for index, ch in enumerate(value):
			if ch in (dialog_child.ZWNJ, dialog_child.ZWJ):
				if not dialog_child._joiner_allowed(value, index):
					return _INVALID
			elif ch != dialog_child.NO_BREAK_SPACE and dialog_child._unreadable_in_claim(ch):
				return _INVALID
		return value

	return check


def _integer(low: int, high: int):
	return lambda value: value if type(value) is int and low <= value <= high else _INVALID


def _boolean(value):
	return value if type(value) is bool else _INVALID


def _pattern(regex):
	return lambda value: value if type(value) is str and len(value) <= 64 and regex.fullmatch(value) else _INVALID


def _signature_box(value):
	if type(value) not in (list, tuple) or len(value) != 4:
		return _INVALID
	for item in value:
		if type(item) not in (int, float) or not math.isfinite(item) or abs(item) > MAX_BOX_COORDINATE:
			return _INVALID
	return list(value)


def _exactly(expected):
	"""Only ``expected`` itself, of exactly its type (so 1 is not True, nor 32768.0 32768)."""
	return lambda value: value if type(value) is type(expected) and value == expected else _INVALID


def _sigfield(value):
	"""A readable field name with no '.': a period makes it a hierarchical (child) field."""
	checked = _text(MAX_META_TEXT_CHARS)(value)
	return _INVALID if checked is _INVALID or "." in checked else checked


def _breaks_pdf_string(ch: str) -> bool:
	"""Would ``ch``, as UTF-16BE bytes written raw into a ``( ) Tj`` string, end or escape it?"""
	code = ord(ch)
	return code > 0xFFFF or (code >> 8) in _PDF_STRING_DELIMITER_BYTES or (code & 0xFF) in _PDF_STRING_DELIMITER_BYTES


def _display(value):
	if type(value) is not str or len(value) > MAX_APPEARANCE_DISPLAY_CHARS:
		return _INVALID
	if any(_breaks_pdf_string(ch) for ch in value):
		return _INVALID
	line_ok = _text(MAX_APPEARANCE_DISPLAY_CHARS)
	return value if all(line_ok(line) is not _INVALID for line in value.split("\n")) else _INVALID


def _outline(value):
	if type(value) not in (list, tuple) or len(value) != 3:
		return _INVALID
	if not all(type(item) is int and 0 <= item <= 255 for item in value):
		return _INVALID
	return list(value)


_APPEARANCE_CHECKS = {"display": _display, "outline": _outline, "border": _integer(0, 10)}


def _signature_appearance(value):
	if type(value) is not dict:
		return _INVALID
	return _checked_fields(value, _APPEARANCE_CHECKS, DROPPED_APPEARANCE_FIELDS)


# Exactly the keys erp_dsc_signer/utils/pdf_signer.py::_signature_metadata sends, every one
# of them required.  The values it always sends are pinned: ``sigandcertify`` True would
# turn the approval signature into a DocMDP certification, and ``aligned`` 32768 keeps
# endesive to one C_Sign.
_META_CHECKS = {
	"aligned": _exactly(32768),
	"sigflags": _exactly(3),
	"sigflagsft": _exactly(132),
	"sigpage": _integer(0, 99999),
	"sigbutton": _boolean,  # inert: endesive 2.19.3 never reads it
	"sigfield": _sigfield,
	"auto_sigfield": _exactly(True),
	"sigandcertify": _exactly(False),
	"signaturebox": _signature_box,
	"name": _text(MAX_META_TEXT_CHARS),
	"contact": _text(MAX_META_TEXT_CHARS),
	"location": _text(MAX_META_TEXT_CHARS),
	"signingdate": _pattern(_SIGNINGDATE),
	"reason": _text(MAX_META_TEXT_CHARS),
	"application": _exactly("ERPNext"),
	"signature_appearance": _signature_appearance,
}
SIGNATURE_META_FIELDS = frozenset(_META_CHECKS)
SIGNATURE_APPEARANCE_FIELDS = frozenset(_APPEARANCE_CHECKS)


def _checked_fields(value: dict, checks: dict, dropped=frozenset()):
	"""A NEW dict of the checked values, or ``_INVALID`` on any unknown key, bad value or
	missing key: the result holds every key of ``checks``, ``dropped`` keys left out."""
	clean = {}
	for key, item in value.items():
		if type(key) is not str:
			return _INVALID
		if key in dropped:
			continue
		check = checks.get(key)
		if check is None:
			return _INVALID
		checked = check(item)
		if checked is _INVALID:
			return _INVALID
		clean[key] = checked
	if set(clean) != set(checks):
		return _INVALID
	return clean


def sanitise_signature_meta(meta) -> dict:
	"""The ``udct`` endesive may see: a new dict holding exactly the allowlisted keys, checked.

	Every key the ERP sends must be present (``SIGNATURE_META_FIELDS``, and in
	``signature_appearance`` ``display``, ``outline`` and ``border``).  The values it always
	sends are pinned: ``aligned`` 32768, ``sigflags`` 3, ``sigflagsft`` 132,
	``sigandcertify`` False, ``auto_sigfield`` True, ``application`` "ERPNext".  Other
	integers are exact ``int`` (never ``bool``) within fixed bounds (``sigpage`` 0..99999);
	``sigbutton`` is an exact ``bool``; text is at most ``MAX_META_TEXT_CHARS`` and
	readable (``_text``); ``sigfield`` has no '.'; ``signingdate`` is a PDF date;
	``signaturebox`` four finite numbers; ``display`` (newlines allowed) has no character
	whose UTF-16BE bytes include '(' ')' '\\' and none above U+FFFF; ``outline`` three ints
	0..255; ``border`` 0..10.  ``signature_appearance.icon`` is dropped (see the module
	docstring).  Anything else raises ``INVALID_REQUEST`` with
	``SIGNATURE_META_UNSUPPORTED``, outside any ``except`` and naming nothing.
	"""
	clean = _checked_fields(meta, _META_CHECKS) if type(meta) is dict else _INVALID
	if clean is _INVALID:
		raise LocalSignerError("INVALID_REQUEST", SIGNATURE_META_UNSUPPORTED)
	return clean


class PinLimiter:
	"""In-memory, per-token count of consecutive incorrect PINs (spec §7).

	Keyed by the token's normalised serial, so every origin shares one budget per token.
	After ``MAX_PIN_FAILURES`` consecutive failures the token is refused until
	``PIN_LOCKOUT_SECONDS`` after the LAST failure; a further failure re-arms the
	lockout; a successful ``C_Login`` clears the count.  Lost on daemon restart (I7).

	It also owns the per-serial TOKEN lock that ``SignerService.sign`` holds from the flags
	read through the logout, and the per-serial record of that token's PIN dialog: whether
	one is open now, and how many have been opened.
	"""

	def __init__(self, clock=time.monotonic):
		self._clock = clock
		self._state = threading.Lock()  # guards the maps below; never held across a login or dialog
		self._failures: dict[str, tuple[int, float]] = {}
		self._token_locks: dict[str, threading.Lock] = {}
		self._open_dialogs: set[str] = set()
		self._dialogs_opened: dict[str, int] = {}

	def locked_out(self, serial: str) -> bool:
		with self._state:
			count, last = self._failures.get(serial, (0, 0.0))
			return count >= MAX_PIN_FAILURES and self._clock() - last < PIN_LOCKOUT_SECONDS

	def failures(self, serial: str) -> int:
		with self._state:
			return self._failures.get(serial, (0, 0.0))[0]

	def record_failure(self, serial: str) -> None:
		with self._state:
			count, _last = self._failures.get(serial, (0, 0.0))
			self._failures[serial] = (count + 1, self._clock())

	def record_success(self, serial: str) -> None:
		with self._state:
			self._failures.pop(serial, None)

	def token_lock(self, serial: str) -> threading.Lock:
		"""The one lock per token serial.  Taken only by ``SignerService.sign``, with a timeout."""
		with self._state:
			return self._token_locks.setdefault(serial, threading.Lock())

	def dialog_state(self, serial: str) -> tuple[bool, int]:
		"""``(a PIN dialog is open for this token now, PIN dialogs opened so far)``, read together."""
		with self._state:
			return serial in self._open_dialogs, self._dialogs_opened.get(serial, 0)

	@contextmanager
	def dialog_open(self, serial: str):
		"""Mark this token's PIN dialog as open for the ``with`` body (caller holds the token lock)."""
		with self._state:
			self._open_dialogs.add(serial)
			self._dialogs_opened[serial] = self._dialogs_opened.get(serial, 0) + 1
		try:
			yield
		finally:
			with self._state:
				self._open_dialogs.discard(serial)

	def guard(self, serial: str, *, final_try_shown: bool) -> "_LoginGuard":
		return _LoginGuard(self, serial, final_try_shown=final_try_shown)


class _LoginGuard:
	"""The ``login_guard`` handed to ``TokenClient.sign_pdf``.

	Used while the caller already holds the token lock for ``serial``; it takes no lock of
	its own.  ``__enter__`` re-checks the limiter immediately before ``C_Login``.
	``check_flags`` judges the flags token.py re-reads there: a locked token, or a
	FINAL_TRY the dialog did not warn about, is refused before the PIN reaches the token.
	"""

	def __init__(self, limiter: PinLimiter, serial: str, *, final_try_shown: bool):
		self._limiter = limiter
		self._serial = serial
		self.final_try_shown = bool(final_try_shown)

	def __enter__(self):
		if self._limiter.locked_out(self._serial):
			raise PinRateLimited()
		return self

	def __exit__(self, _type, _value, _traceback):
		return False

	def check_flags(self, flags: int) -> None:
		pin_locked, pin_final_try = _pin_flags()
		if flags & pin_locked:
			raise PinLocked()
		if flags & pin_final_try and not self.final_try_shown:
			raise TokenBusy(state_changed=True)

	def succeeded(self) -> None:
		self._limiter.record_success(self._serial)

	def failed(self) -> None:
		self._limiter.record_failure(self._serial)


class _SignerHTTPServer(ThreadingHTTPServer):
	daemon_threads = True

	def handle_error(self, request, client_address):
		# The default prints a traceback, whose frames and exception text can hold
		# request data.  One fixed line instead (spec §8).
		try:
			sys.stderr.write(HANDLER_ERROR_LINE + "\n")
			sys.stderr.flush()
		except Exception:
			pass


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
		clock=None,
	):
		self.config = config
		self.nonces = NonceStore(config.nonce_ttl_seconds, config.max_nonce_count)
		self.providers = ProviderRegistry(config)
		self.trust = trust_store if trust_store is not None else TrustStore()
		# The ONE shared dialog host: pin and consent dialogs take its lock, never ours.
		self.dialogs = dialog_host if dialog_host is not None else DialogHost()
		self.pair_guard = pair_guard if pair_guard is not None else PairGuard()
		self.consent = consent or consent_dialog
		self.verify_proof = verifier or verify_pairing_proof
		self.pin_prompt = pin_prompt or request_pin
		self.pin_limiter = PinLimiter(clock or time.monotonic)

	def is_paired(self, canonical_origin: str) -> bool:
		"""Static operator config union runtime consent."""
		return canonical_origin in self.config.allowed_origins or self.trust.is_allowed(canonical_origin)

	def pair(self, canonical_origin: str, pairing_token) -> dict:
		"""Verify the proof, ask the user, and persist on an explicit Allow.

		A denial (and the global cooldown) is recorded ONLY for an explicit Deny, i.e.
		``consent`` returning False.  A dialog that timed out, failed or was busy raises,
		and records nothing (spec §6).
		"""
		if self.trust.is_denied(canonical_origin):
			raise PairDenied()
		# Rate limit before the callback so we cannot be used to generate traffic.
		self.pair_guard.check_and_record()
		claims = self.verify_proof(canonical_origin, pairing_token)

		allowed = self.consent(canonical_origin, claims, host=self.dialogs)
		if allowed is not True:
			if allowed is False:
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

	def sign(self, origin: str, pdf: bytes, signature_meta: dict, *, document_name, selector, provider, module_id, timestamp_url):
		"""The ``/v1/sign`` order (spec §7): every refusal that needs no PIN comes first.

		``signature_meta`` is checked first of all (``sanitise_signature_meta``), before the
		provider is resolved or the token is read, and only the sanitised copy goes on.

		The token lock is taken BEFORE the flags are read and held through the dialog,
		login, signing, TSA and logout, so no other request on this daemon can move the
		token to FINAL_TRY or LOCKED between this request's checks and its ``C_Login``.
		A request that cannot get the lock in time is refused with no dialog and no login.

		While a request on this token is in its PIN dialog, a new request is refused at once
		(``TokenBusy``) instead of waiting.  A request that was already waiting when such a
		dialog opened is refused when it gets the lock, and so is one whose origin was
		unpaired while it waited (``OriginNotPaired``): neither shows a dialog.
		"""
		signature_meta = sanitise_signature_meta(signature_meta)
		client = TokenClient(self.providers.resolve(provider, module_id))
		selected, certificates = client.select(selector)  # CertificatesHidden propagates
		# token_state (below) refuses unless the slot still holds selected.token_serial, so
		# that one serial keys the lock, the dialog record and the limiter.
		serial = selected.token_serial
		lock = self.pin_limiter.token_lock(serial)
		dialog_is_open, dialogs_opened = self.pin_limiter.dialog_state(serial)
		if dialog_is_open:
			raise TokenBusy()
		if not lock.acquire(timeout=TOKEN_LOCK_TIMEOUT_SECONDS):
			raise TokenBusy()
		try:
			# The nonce is spent and the wait can be long: re-check the pairing now.
			if not self.is_paired(origin):
				raise OriginNotPaired()
			# The lock is not FIFO; a dialog shown while this request waited means another
			# request has just asked for this token's PIN, so do not ask again straight away.
			if self.pin_limiter.dialog_state(serial)[1] != dialogs_opened:
				raise TokenBusy()
			flags, serial = client.token_state(selected)
			pin_locked, pin_final_try = _pin_flags()
			if flags & pin_locked:
				raise PinLocked()
			if self.pin_limiter.locked_out(serial):
				raise PinRateLimited()
			# The child itself shows dialog_child.FINAL_TRY_TEXT and the tick-box for
			# final_try (spec §7), so it is not repeated in the signer's warnings.
			final_try = bool(flags & pin_final_try)
			# The PIN is passed straight from the dialog into sign_pdf and never bound to a
			# local here, so this frame holds no reference to it while signing and the TSA
			# request run (I7; a Python str cannot be zeroed).
			return client.sign_pdf(
				pdf,
				selected,
				certificates,
				signature_meta,
				self._ask_pin(serial, origin, document_name, final_try),
				timestamp_url,
				login_guard=self.pin_limiter.guard(serial, final_try_shown=final_try),
			)
		finally:
			lock.release()

	def _ask_pin(self, serial: str, origin: str, document_name, final_try: bool) -> str:
		"""Show the PIN dialog with this token's dialog marked open; returns the PIN."""
		with self.pin_limiter.dialog_open(serial):
			return self.pin_prompt(origin, document_name, host=self.dialogs, warnings=[], final_try=final_try)

	def make_server(self, address=None) -> ThreadingHTTPServer:
		"""The HTTP server for this service.  ``address=None`` means the configured host/port."""
		if address is None:
			address = (self.config.host, self.config.port)
		return _SignerHTTPServer(address, self.handler())

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
				except Exception:
					self._error(_internal_error())

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
					self._error(_internal_error())

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
				# body["pin"] is never read: the PIN comes only from the signer's dialog.
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
				if not isinstance(request, dict) or "signature_meta" not in request:
					raise LocalSignerError("INVALID_REQUEST", "A signing_request with signature_meta is required.")
				if type(request["signature_meta"]) is not dict:
					# The one message for every refused signature_meta (sanitise_signature_meta).
					raise LocalSignerError("INVALID_REQUEST", SIGNATURE_META_UNSUPPORTED)
				timestamp_url = request.get("timestamp_url")
				if timestamp_url and timestamp_url not in service.config.allowed_timestamp_urls:
					raise LocalSignerError("TSA_NOT_ALLOWED", "The ERP timestamp URL is not allowed by this workstation configuration.", status=409)
				signed_pdf, certificate = service.sign(
					origin,
					pdf,
					request["signature_meta"],
					document_name=request.get("document_name"),
					selector=body.get("certificate"),
					provider=body.get("provider", "auto"),
					module_id=body.get("module_id"),
					timestamp_url=timestamp_url,
				)
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
				try:
					canonical = try_canonical_origin(self.headers.get("Origin", ""))
					# Bootstrap errors must be readable, or the page cannot tell "not
					# paired" from "not running".  Everything else stays dark.
					readable = canonical and (self.path in BOOTSTRAP_PATHS or service.is_paired(canonical))
					self._respond(exc.status, exc.as_dict(), canonical if readable else None)
				except (BrokenPipeError, ConnectionResetError):
					# The client went away; there is nobody to tell.
					pass

			def log_message(self, _format, *_args):
				return

		return Handler
