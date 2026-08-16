"""Canonical origin handling.

Single source of truth for every origin that is compared, persisted, or echoed in a
CORS header.  Without this, an origin stored as "https://Host:443" never matches the
"https://host" a browser actually sends, and a correctly paired site silently reads as
unpaired -- the same class of failure this feature exists to remove.
"""

from __future__ import annotations

from urllib.parse import urlsplit


DEFAULT_PORTS = {"http": 80, "https": 443}

# Hosts for which plain http is not treated as a downgrade in the consent dialog.
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def canonical_origin(value: object) -> str:
	"""Return the canonical form of an exact origin.

	Lowercases the host and strips the scheme's default port, so that every caller
	compares the same string.  Raises ValueError for anything that is not an exact
	origin (credentials, a path, a query, a fragment, an unknown scheme).
	"""
	if not isinstance(value, str):
		raise ValueError("Origin must be a string.")
	parsed = urlsplit(value.strip())
	if (
		parsed.scheme not in DEFAULT_PORTS
		or not parsed.hostname
		or parsed.username
		or parsed.password
		or parsed.path not in {"", "/"}
		or parsed.query
		or parsed.fragment
	):
		raise ValueError(f"Invalid origin: {value!r}")
	try:
		port = parsed.port
	except ValueError as exc:  # out-of-range port
		raise ValueError(f"Invalid origin: {value!r}") from exc

	host = parsed.hostname.lower()
	if ":" in host:  # IPv6 literal, which urlsplit returns without brackets
		host = f"[{host}]"
	origin = f"{parsed.scheme}://{host}"
	if port is not None and port != DEFAULT_PORTS[parsed.scheme]:
		origin += f":{port}"
	return origin


def try_canonical_origin(value: object) -> str | None:
	"""canonical_origin() that returns None instead of raising."""
	try:
		return canonical_origin(value)
	except ValueError:
		return None


def is_loopback_origin(origin: str) -> bool:
	host = urlsplit(origin).hostname or ""
	return host.lower() in LOOPBACK_HOSTS


def is_transport_secure(origin: str) -> bool:
	"""True when the origin is https, or http on loopback (safe for local dev)."""
	parsed = urlsplit(origin)
	return parsed.scheme == "https" or is_loopback_origin(origin)
