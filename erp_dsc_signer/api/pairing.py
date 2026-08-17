# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

"""Pairing tokens that let a workstation confirm which ERP site is calling it.

The workstation signer receives a token from the browser and hands it back to this
site to be confirmed.  That proves the caller really is this site (a non-browser
client cannot forge an Origin header and then satisfy a callback to it) and that the
token came from a signed-in session here.

It does NOT vouch for this site being trustworthy -- any site can run this app and
confirm its own tokens.  The workstation shows the user the browser Origin and asks.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import frappe
from frappe import _


TOKEN_TTL_SECONDS = 120
CACHE_PREFIX = "erp_dsc_signer|pairing|"
DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_origin(scheme: str, host: str) -> str:
	"""Mirror of local_signer/erp_dsc_local/origins.py::canonical_origin.

	Duplicated rather than imported: the workstation package is not installed on the
	server.  The two must agree exactly -- lowercase host, default port stripped -- or
	a paired site reads as unpaired on the workstation.
	"""
	scheme = (scheme or "").lower()
	if scheme not in DEFAULT_PORTS:
		frappe.throw(_("Unsupported request scheme for pairing."))
	parsed = urlsplit(f"{scheme}://{host}")
	hostname = (parsed.hostname or "").lower()
	if not hostname:
		frappe.throw(_("Could not determine this site's address for pairing."))
	if ":" in hostname:  # IPv6 literal
		hostname = f"[{hostname}]"
	origin = f"{scheme}://{hostname}"
	try:
		port = parsed.port
	except ValueError:
		port = None
	if port is not None and port != DEFAULT_PORTS[scheme]:
		origin += f":{port}"
	return origin


def _request_origin() -> str:
	"""This site's origin, derived from the incoming request.

	Deliberately NOT frappe.utils.get_url() or site_config host_name: on Frappe Cloud
	and behind custom domains those routinely differ from the address the browser
	actually used, and binding the token to the wrong one reproduces exactly the
	"paired site looks unpaired" failure this feature exists to remove.

	Also deliberately NOT the request's Origin header, and NOT X-Forwarded-Host: both
	are client-supplied, and a caller must never be able to mint a token naming an
	origin of its choosing. The Host header is used instead because Frappe itself
	routes requests to a site with it (frappe/app.py: get_site_name(request.host)), so
	on any correctly-served deployment -- Frappe Cloud included -- it is already the
	address the browser used, and a wrong value would not have reached this site.

	X-Forwarded-Proto is still consulted for the SCHEME only: a TLS-terminating proxy
	leaves request.scheme as http, and it cannot be upgraded any other way. A forged
	value can only downgrade the origin to http, which the browser-side check against
	window.location.origin then rejects.
	"""
	request = getattr(frappe.local, "request", None)
	if request is None:
		frappe.throw(_("Pairing tokens can only be issued from a web request."))
	forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
	scheme = "https" if request.scheme == "https" or forwarded_proto == "https" else (forwarded_proto or request.scheme)
	return _canonical_origin(scheme, request.host)


@frappe.whitelist()
def issue_pairing_token() -> dict:
	"""Mint a single-use token for the signed-in user's workstation."""
	if frappe.session.user == "Guest":
		frappe.throw(_("Sign in before pairing a workstation."), frappe.PermissionError)

	origin = _request_origin()
	token = secrets.token_urlsafe(32)
	frappe.cache().set_value(
		CACHE_PREFIX + token,
		{"origin": origin, "user": frappe.session.user},
		expires_in_sec=TOKEN_TTL_SECONDS,
	)

	site_url_origin = ""
	try:
		parsed = urlsplit(frappe.utils.get_url())
		if parsed.scheme and parsed.netloc:
			site_url_origin = _canonical_origin(parsed.scheme, parsed.netloc)
	except Exception:
		pass

	return {
		"token": token,
		"origin": origin,
		"expires_in_seconds": TOKEN_TTL_SECONDS,
		# Surfaced so a mismatch with the browser's own origin is visible rather than
		# silent; the client compares `origin` with window.location.origin.
		"site_url_origin": site_url_origin,
	}


@frappe.whitelist(allow_guest=True)
def verify_pairing_token(token: str | None = None) -> dict:
	"""Confirm a token for the workstation signer. Single use.

	allow_guest because the caller is the local signer process, which has no Frappe
	session. The token itself is the only credential, and it is consumed here.
	"""
	# Consume before validating, so a wrong guess cannot be retried and a valid token
	# cannot be replayed even if the rest of this call fails.
	key = CACHE_PREFIX + (token or "")
	record = frappe.cache().get_value(key) if token else None
	if token:
		frappe.cache().delete_value(key)

	if not isinstance(record, dict) or not record.get("origin"):
		return {"ok": False}

	user = record.get("user") or ""
	full_name = ""
	try:
		full_name = frappe.db.get_value("User", user, "full_name") or ""
	except Exception:
		pass

	return {
		"ok": True,
		"origin": record["origin"],
		# Presented by the workstation as a claim by this site, never as verified
		# identity -- see the module docstring.
		"site_name": frappe.local.site,
		"user": full_name or user,
	}
