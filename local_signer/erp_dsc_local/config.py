"""Configuration loading and validation."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .errors import ConfigurationError


PROVIDER_IDS = ("epass", "safenet", "proxkey", "watchdata", "generic_pkcs11")


@dataclass(frozen=True)
class CustomModule:
	id: str
	provider: str
	path: str
	label: str = ""


@dataclass(frozen=True)
class SignerConfig:
	host: str = "127.0.0.1"
	port: int = 17777
	allowed_origins: frozenset[str] = frozenset()
	max_request_bytes: int = 20 * 1024 * 1024
	max_pdf_bytes: int = 14 * 1024 * 1024
	max_nonce_count: int = 512
	nonce_ttl_seconds: int = 180
	allow_originless_health: bool = True
	allow_development_pin_in_request: bool = False
	allowed_timestamp_urls: frozenset[str] = frozenset()
	retry_without_timestamp: bool = True
	custom_modules: tuple[CustomModule, ...] = field(default_factory=tuple)
	provider_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)


def load_config(path: str | Path) -> SignerConfig:
	config_path = Path(path).expanduser()
	try:
		raw = json.loads(config_path.read_text(encoding="utf-8"))
	except FileNotFoundError as exc:
		raise ConfigurationError(f"Configuration file not found: {config_path}") from exc
	except (OSError, json.JSONDecodeError) as exc:
		raise ConfigurationError("Unable to read a valid JSON configuration file.") from exc
	if not isinstance(raw, dict):
		raise ConfigurationError("The configuration root must be a JSON object.")

	host = _loopback_host(raw.get("host", "127.0.0.1"))
	port = _bounded_int(raw.get("port", 17777), "port", 1, 65535)
	origins_raw = raw.get("allowed_origins", [])
	if not isinstance(origins_raw, list):
		raise ConfigurationError("allowed_origins must be a list of exact ERP origins.")
	allowed_origins = frozenset(_validate_origin(value) for value in origins_raw)
	if not allowed_origins:
		raise ConfigurationError("At least one exact ERP origin is required in allowed_origins.")

	limits = _mapping(raw.get("limits", {}), "limits")
	max_request = _bounded_int(
		limits.get("max_request_bytes", 20 * 1024 * 1024), "limits.max_request_bytes", 1024, 100 * 1024 * 1024
	)
	max_pdf = _bounded_int(
		limits.get("max_pdf_bytes", 14 * 1024 * 1024), "limits.max_pdf_bytes", 1024, 75 * 1024 * 1024
	)
	if max_request < (max_pdf * 4 // 3) + 1024:
		raise ConfigurationError("max_request_bytes is too small for max_pdf_bytes after base64 encoding.")

	nonce = _mapping(raw.get("nonce", {}), "nonce")
	development = _mapping(raw.get("development", {}), "development")
	timestamp = _mapping(raw.get("timestamp", {}), "timestamp")
	tsa_values = timestamp.get("allowed_urls", [])
	if not isinstance(tsa_values, list):
		raise ConfigurationError("timestamp.allowed_urls must be a list.")
	allowed_tsa = frozenset(_validate_https_url(value) for value in tsa_values)

	providers = _mapping(raw.get("providers", {}), "providers")
	return SignerConfig(
		host=host,
		port=port,
		allowed_origins=allowed_origins,
		max_request_bytes=max_request,
		max_pdf_bytes=max_pdf,
		max_nonce_count=_bounded_int(nonce.get("max_count", 512), "nonce.max_count", 8, 4096),
		nonce_ttl_seconds=_bounded_int(nonce.get("ttl_seconds", 180), "nonce.ttl_seconds", 30, 600),
		allow_originless_health=bool(raw.get("allow_originless_health", True)),
		allow_development_pin_in_request=bool(development.get("allow_pin_in_request", False)),
		allowed_timestamp_urls=allowed_tsa,
		retry_without_timestamp=bool(timestamp.get("retry_without_timestamp", True)),
		custom_modules=_custom_modules(providers.get("custom_modules", [])),
		provider_paths=_provider_paths(providers.get("additional_paths", {})),
	)


def _mapping(value: object, name: str) -> dict:
	if not isinstance(value, dict):
		raise ConfigurationError(f"{name} must be a JSON object.")
	return value


def _loopback_host(value: object) -> str:
	if not isinstance(value, str):
		raise ConfigurationError("host must be a literal loopback IP address.")
	try:
		address = ipaddress.ip_address(value)
	except ValueError as exc:
		raise ConfigurationError("host must be 127.0.0.1 or ::1, not a hostname.") from exc
	if not address.is_loopback:
		raise ConfigurationError("The signer may bind only to a loopback address.")
	return value


def _validate_origin(value: object) -> str:
	if not isinstance(value, str):
		raise ConfigurationError("Every allowed origin must be a string.")
	parsed = urlsplit(value)
	if (
		parsed.scheme not in {"http", "https"}
		or not parsed.hostname
		or parsed.username
		or parsed.password
		or parsed.path not in {"", "/"}
		or parsed.query
		or parsed.fragment
	):
		raise ConfigurationError(f"Invalid ERP origin: {value!r}")
	canonical = f"{parsed.scheme}://{parsed.hostname.lower()}"
	if parsed.port is not None:
		canonical += f":{parsed.port}"
	return canonical


def _validate_https_url(value: object) -> str:
	if not isinstance(value, str):
		raise ConfigurationError("Every timestamp URL must be a string.")
	parsed = urlsplit(value)
	if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
		raise ConfigurationError(f"Timestamp URLs must be absolute HTTPS URLs: {value!r}")
	return value


def _bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
	if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
		raise ConfigurationError(f"{name} must be an integer from {minimum} to {maximum}.")
	return value


def _custom_modules(values: object) -> tuple[CustomModule, ...]:
	if not isinstance(values, list):
		raise ConfigurationError("providers.custom_modules must be a list.")
	result = []
	seen = set()
	for value in values:
		if not isinstance(value, dict):
			raise ConfigurationError("Each custom module must be a JSON object.")
		module_id = value.get("id")
		provider = value.get("provider", "generic_pkcs11")
		path = value.get("path")
		if not isinstance(module_id, str) or not module_id.replace("-", "").replace("_", "").isalnum():
			raise ConfigurationError("Custom module ids may contain only letters, numbers, '-' and '_'.")
		if module_id in seen:
			raise ConfigurationError(f"Duplicate custom module id: {module_id}")
		if provider not in PROVIDER_IDS:
			raise ConfigurationError(f"Unknown custom module provider: {provider}")
		if not isinstance(path, str) or not Path(path).expanduser().is_absolute():
			raise ConfigurationError(f"Custom module {module_id!r} needs an absolute path.")
		seen.add(module_id)
		result.append(CustomModule(module_id, provider, str(Path(path).expanduser()), str(value.get("label", ""))))
	return tuple(result)


def _provider_paths(value: object) -> dict[str, tuple[str, ...]]:
	if not isinstance(value, dict):
		raise ConfigurationError("providers.additional_paths must be a JSON object.")
	result = {}
	for provider, paths in value.items():
		if provider not in PROVIDER_IDS or not isinstance(paths, list):
			raise ConfigurationError("additional_paths keys must be known providers with list values.")
		normalized = []
		for path in paths:
			if not isinstance(path, str) or not Path(path).expanduser().is_absolute():
				raise ConfigurationError("Every additional PKCS#11 path must be absolute.")
			normalized.append(str(Path(path).expanduser()))
		result[provider] = tuple(normalized)
	return result
