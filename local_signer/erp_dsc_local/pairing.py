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

from .errors import PairProofInvalid, PairRateLimited
from .origins import canonical_origin, is_transport_secure


VERIFY_PATH = "/api/method/erp_dsc_signer.api.pairing.verify_pairing_token"
CALLBACK_TIMEOUT_SECONDS = 5
CALLBACK_MAX_BYTES = 8 * 1024

MAX_ATTEMPTS_PER_HOUR = 10
GLOBAL_COOLDOWN_SECONDS = 60
DIALOG_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class SiteClaims:
	"""Strings supplied by the site being paired. NOT verified identity."""

	site_name: str = ""
	user: str = ""


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
		site_name=str(message.get("site_name") or "")[:120],
		user=str(message.get("user") or "")[:120],
	)


def build_consent_text(origin: str, claims: SiteClaims) -> str:
	"""The consent dialog body.

	Origin first and unadorned: it is the only thing here the site cannot choose.
	"""
	lines = [
		"Allow this website to use the digital signature token on this computer?",
		"",
		origin,
		"",
	]
	if not is_transport_secure(origin):
		lines += [
			"WARNING: this site uses an unencrypted (http) connection.",
			"",
		]
	if claims.site_name or claims.user:
		claimed = claims.site_name or "(unnamed)"
		if claims.user:
			claimed += f", signed in as {claims.user}"
		lines += [
			f"The site describes itself as: {claimed}",
			"That description comes from the site itself and is not verified.",
			"",
		]
	lines += [
		"If you allow it, this site can ask your USB token to sign documents.",
		"You will still enter your token PIN for every signature.",
		"",
		"Allow only if you just clicked Pair in your own ERP.",
	]
	return "\n".join(lines)


def consent_dialog(origin: str, claims: SiteClaims, *, timeout_seconds: int = DIALOG_TIMEOUT_SECONDS) -> bool:
	"""Show the consent prompt and return True only on an explicit Allow.

	Must run on the DialogHost worker thread.  Deny is the default: closing the
	window, pressing Escape, and the timeout all return False.
	"""
	import tkinter as tk

	from .ui import new_tk_root

	root = new_tk_root()
	answer = {"allow": False}
	try:
		window = tk.Toplevel(root)
		window.title("ERP DSC Signer - pairing request")
		window.attributes("-topmost", True)
		window.resizable(False, False)

		tk.Label(
			window,
			text=build_consent_text(origin, claims),
			justify="left",
			font=("TkFixedFont", 12),
			padx=18,
			pady=14,
			wraplength=560,
		).pack()

		buttons = tk.Frame(window)
		buttons.pack(pady=(0, 14))

		def close(allow: bool):
			answer["allow"] = allow
			window.destroy()

		deny = tk.Button(buttons, text="Deny", width=14, command=lambda: close(False))
		allow = tk.Button(buttons, text="Allow", width=14, command=lambda: close(True))
		deny.pack(side="left", padx=8)
		allow.pack(side="left", padx=8)

		deny.focus_set()
		window.bind("<Escape>", lambda _event: close(False))
		window.protocol("WM_DELETE_WINDOW", lambda: close(False))
		window.after(int(timeout_seconds * 1000), lambda: close(False))

		window.grab_set()
		root.wait_window(window)
	finally:
		try:
			root.destroy()
		except Exception:
			pass
	return bool(answer["allow"])
