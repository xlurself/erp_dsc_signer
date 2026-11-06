"""Pairing an ERP origin with this workstation.

What the callback does and does not prove
-----------------------------------------
`/v1/pair` asks the calling origin to confirm the pairing token it just handed us.
That is ANTI-SPOOF, not identity: it proves the caller really is the site the browser
loaded (a non-browser client cannot forge an Origin header and then satisfy a callback
to that origin), and it proves the token was minted by a logged-in session there.

It does NOT prove the site is trustworthy.  The callee is the caller -- any site can
serve an endpoint that echoes its own origin back.  So:

  * the only verified identity shown to the user is the ORIGIN HEADER;
  * the site name and user returned by the callback are CLAIMS by that site and are
    labelled as such in the dialog, never as "verified";
  * rate limiting, not the callback, is what protects the user from prompt spam.

The claims are sanitised where they enter (``verify_pairing_proof``) with the dialog's
own rule (``dialog_child.clean_claim``), so the trust store, the /v1/pair response and
the CLI never hold raw site text: an over-long claim becomes "(claim too long)"; a
NO-BREAK SPACE (U+00A0) counts as an ordinary space; one with any control, format,
surrogate, private-use, unassigned or line/paragraph-separator character, any space
separator other than U+0020, or an invisible filler (``dialog_child.INVISIBLE_FILLERS``)
becomes "(unreadable claim removed)" -- except a zero-width joiner/non-joiner next to a
virama, which Indic names need.  Runs of spaces are collapsed and the ends stripped;
a claim left empty is unreadable.  Nothing is silently truncated.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from threading import Lock

from . import dialog_child
from .errors import DialogBusy, DialogFailed, PairPromptUnavailable, PairProofInvalid, PairRateLimited
from .origins import canonical_origin, is_transport_secure
from .ui import UiBusy


VERIFY_PATH = "/api/method/erp_dsc_signer.api.pairing.verify_pairing_token"
CALLBACK_TIMEOUT_SECONDS = 5
CALLBACK_MAX_BYTES = 8 * 1024

MAX_ATTEMPTS_PER_HOUR = 10
GLOBAL_COOLDOWN_SECONDS = 60

HTTP_WARNING = "WARNING: this site uses an unencrypted (http) connection."


@dataclass(frozen=True)
class SiteClaims:
	"""Strings supplied by the site being paired. NOT verified identity.

	Built only by ``verify_pairing_proof``, which has already replaced any over-long or
	unreadable value with the dialog's visible placeholder.
	"""

	site_name: str = ""
	user: str = ""


def sanitise_claim(value: object) -> str:
	"""One site-supplied value, cleaned by the SAME rule the dialog applies (spec §6)."""
	return dialog_child.clean_claim(str(value or ""))


class PairGuard:
	"""Global pairing rate limits.

	Deliberately global rather than per-origin: a per-origin cooldown is trivially
	bypassed by rotating subdomains (evil1.example, evil2.example, ...), which was the
	round-1 review finding.
	"""

	def __init__(
		self,
		*,
		max_attempts_per_hour: int = MAX_ATTEMPTS_PER_HOUR,
		cooldown_seconds: int = GLOBAL_COOLDOWN_SECONDS,
		clock=time.monotonic,
	):
		self.max_attempts_per_hour = max_attempts_per_hour
		self.cooldown_seconds = cooldown_seconds
		self._clock = clock
		self._lock = Lock()
		self._attempts: list[float] = []
		self._cooldown_until = 0.0

	def check_and_record(self) -> None:
		"""Raise PairRateLimited unless another prompt is permitted right now."""
		with self._lock:
			now = self._clock()
			if now < self._cooldown_until:
				raise PairRateLimited(
					"Pairing was declined a moment ago. Wait a minute before trying again."
				)
			self._attempts = [t for t in self._attempts if now - t < 3600]
			if len(self._attempts) >= self.max_attempts_per_hour:
				raise PairRateLimited(
					"Too many pairing attempts on this computer in the last hour."
				)
			self._attempts.append(now)

	def record_denial(self) -> None:
		with self._lock:
			self._cooldown_until = self._clock() + self.cooldown_seconds


def _build_opener() -> urllib.request.OpenerDirector:
	"""An opener that follows no redirects and ignores environment proxies."""

	class _NoRedirect(urllib.request.HTTPRedirectHandler):
		def redirect_request(self, req, fp, code, msg, headers, newurl):
			return None

	context = ssl.create_default_context()  # verifies certificates and hostnames
	return urllib.request.build_opener(
		_NoRedirect,
		urllib.request.ProxyHandler({}),
		urllib.request.HTTPSHandler(context=context),
	)


def verify_pairing_proof(origin: str, token: str, *, opener=None) -> SiteClaims:
	"""Confirm `token` with `origin`, returning the site's (unverified) claims.

	The token travels in a POST body, never a query string, so it does not land in
	server access logs or referrers.
	"""
	canonical = canonical_origin(origin)
	if not isinstance(token, str) or not 16 <= len(token) <= 512:
		raise PairProofInvalid("The pairing token is missing or malformed.")

	opener = opener or _build_opener()
	body = urllib.parse.urlencode({"token": token}).encode("ascii")
	request = urllib.request.Request(
		canonical + VERIFY_PATH,
		data=body,
		headers={
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept": "application/json",
		},
		method="POST",
	)

	try:
		with opener.open(request, timeout=CALLBACK_TIMEOUT_SECONDS) as response:
			if response.status != 200:
				raise PairProofInvalid()
			payload = json.loads(response.read(CALLBACK_MAX_BYTES + 1).decode("utf-8", "replace"))
	except PairProofInvalid:
		raise
	except (urllib.error.URLError, urllib.error.HTTPError, OSError, ssl.SSLError) as exc:
		raise PairProofInvalid(
			"The ERP site could not be reached to confirm pairing. If this workstation has no "
			"route back to the site, pair from the command line instead: "
			"erp-dsc-local --allow <origin>"
		) from exc
	except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
		raise PairProofInvalid() from exc

	message = payload.get("message") if isinstance(payload, dict) else None
	if not isinstance(message, dict) or message.get("ok") is not True:
		raise PairProofInvalid()

	# The site must name itself, and it must name the SAME origin the browser used.
	# This is what makes a forged Origin header from a non-browser client fail.
	claimed_origin = message.get("origin")
	try:
		if canonical_origin(claimed_origin) != canonical:
			raise PairProofInvalid("The ERP site confirmed a different origin than the browser used.")
	except ValueError as exc:
		raise PairProofInvalid() from exc

	return SiteClaims(
		site_name=sanitise_claim(message.get("site_name")),
		user=sanitise_claim(message.get("user")),
	)


def build_consent_request(origin: str, claims: SiteClaims) -> dict:
	"""The dialog request for one pairing prompt (spec §6 wire schema).

	Origin, the site's claims (one per line) and the signer's own warnings travel as
	separate fields; the dialog child decides how they are laid out.
	"""
	site_claims = []
	if claims.site_name:
		site_claims.append(claims.site_name)
	if claims.user:
		# No prefix: the claim is already capped at MAX_CLAIM_CHARS and the dialog labels
		# every entry "as described by the site", so a prefix could only overflow it.
		site_claims.append(claims.user)
	return {
		"v": dialog_child.PROTOCOL_VERSION,
		"kind": "consent",
		"origin": origin,
		"claims": site_claims,
		"warnings": [] if is_transport_secure(origin) else [HTTP_WARNING],
		"final_try": False,
		"timeout": dialog_child.DEFAULT_DIALOG_SECONDS,
	}


def consent_dialog(origin: str, claims: SiteClaims, *, host) -> bool:
	"""Show the pairing prompt through `host`; True only on an explicit Allow.

	False means the user refused (Deny, Escape or closing the window) and the caller
	records the denial.  No answer is NOT a refusal: a timeout, a failed dialog and a
	busy host all raise (PairPromptUnavailable, DialogBusy, DialogWedged), so no denial
	or cooldown is recorded for them (spec §6).
	"""
	request = build_consent_request(origin, claims)
	reply = cause = None
	busy = False
	try:
		reply = host.run_dialog(request)
	except DialogFailed as exc:
		cause = exc.cause
	except UiBusy:
		busy = True

	# Raised here, outside the handlers: __context__ stays empty.
	if busy:
		raise DialogBusy() from None
	if cause is not None:
		raise PairPromptUnavailable(cause) from None

	result = reply.get("result") if type(reply) is dict else None
	if result == "allow":
		return True
	if result == "deny":
		return False
	if result == "timeout":
		raise PairPromptUnavailable("dialog_timeout")
	if result == "unavailable" and reply.get("cause") in dialog_child.UNAVAILABLE_CAUSES:
		raise PairPromptUnavailable(reply["cause"])
	# The host validates every reply, so this is unreachable with the real one: fail closed.
	raise PairPromptUnavailable("dialog_bad_reply")
