"""erp-dsc-local --doctor: a plain-text support report with no PIN and no private data.

BRD F4 / installer plan s5.  The report shows what the owner would show support: system,
helper and Python versions, the config path and whether it loads, whether the port is free
or in use (and by this helper), HOW MANY sites are allowed (never which), where the log is,
every driver location the registry knows (found / missing) and, for each driver found, a
read-only token check.  The check is ``TokenClient.certificates()``: the vendor library runs
in the killable probe child (``token.run_probe``, ``PROBE_TIMEOUT_SECONDS``), never in this
process, and no PIN is involved.  Per certificate: common name, organisation, issuer CN,
valid-to date, whether it is a signing certificate, and the first 8 hex of its SHA-256
fingerprint.  Never printed: DER, serial numbers, a full fingerprint, the token's serial or
label, origins, pairing data.  Certificate text is printed without control or format
characters and capped.  The report is bounded (see the MAX_ constants) and always exits 0.
"""

from __future__ import annotations

import http.client
import json
import os
import platform
import sys
from pathlib import Path

from . import drivers
from .certificates import is_signing_certificate
from .cli import _printable
from .config import SignerConfig, load_config
from .errors import CertificatesHidden, ConfigurationError, LocalSignerError, MiddlewareUnavailable, TokenUnavailable
from .logs import default_config_path, exception_name, log_path
from .providers import PROVIDER_LABELS, ProviderRegistry
from .token import PROBE_TIMEOUT_SECONDS, TokenClient, TokenDriverNotResponding
from .trust import TrustStore

DEFAULT_CLIENT = TokenClient
MAX_TEXT_CHARS = 100
MAX_LISTED_MODULES = 30
MAX_CHECKED_MODULES = 6
MAX_CERTIFICATES_PER_MODULE = 6
HEALTH_TIMEOUT_SECONDS = 2
NOT_SHOWN = "  ... {count} more not shown"


def printable(value, limit=MAX_TEXT_CHARS) -> str:
	text = _printable(value if value is not None else "")
	return text if len(text) <= limit else text[: limit - 3] + "..."


def port_status(host: str, port: int) -> str:
	"""free / in use by this helper / in use by another program.  One loopback GET, no proxy."""
	connection = http.client.HTTPConnection(f"[{host}]" if ":" in host else host, port, timeout=HEALTH_TIMEOUT_SECONDS)
	try:
		try:
			connection.connect()
		except OSError:
			return "free (the helper is not running)"
		try:
			connection.request("GET", "/v1/health")
			payload = json.loads(connection.getresponse().read(4096))
		except Exception:
			payload = None
	finally:
		connection.close()
	if isinstance(payload, dict) and payload.get("ok") is True and isinstance(payload.get("version"), str):
		return f"in use by ERP DSC Signer {printable(payload['version'], 20)} (the helper is running)"
	return "in use by another program"


_PORT_STATUS = port_status


def _system_text(system=None) -> str:
	name = system or platform.system()
	if name == "Darwin":
		name = f"macOS {platform.mac_ver()[0] or platform.release()}"
	elif name == "Windows":
		name = f"Windows {platform.release()} ({platform.version()})"
	else:
		name = f"{name} {platform.release()}"
	return f"{name} ({platform.machine()})"


def _helper_version() -> str:
	try:
		from .service import VERSION
	except Exception:
		return "unknown"
	return VERSION


def _issuer_cn(certificate) -> str:
	try:
		from cryptography.x509.oid import NameOID

		values = certificate.crypto_certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
		return str(values[0].value) if values else ""
	except Exception:
		return ""


def _signing(certificate) -> str:
	try:
		return "yes" if is_signing_certificate(certificate.crypto_certificate) else "no"
	except Exception:
		return "unknown"


def _certificate_lines(certificate) -> list:
	meta = certificate.metadata
	return [
		f"    - {printable(meta.get('common_name')) or '(no name)'} | Organisation: {printable(meta.get('organization')) or '(none)'}"
		f" | Signing certificate: {_signing(certificate)}",
		f"      Issued by: {printable(_issuer_cn(certificate)) or '(unknown)'} | Valid to: {printable(str(meta.get('valid_to', ''))[:10], 10)}"
		f" | Fingerprint (first 8): {printable(str(meta.get('fingerprint_sha256', ''))[:8], 8)}",
	]


def _token_check(module, client_factory) -> list:
	head = f"  {PROVIDER_LABELS.get(module.provider, module.provider)}  {printable(module.path, 300)}: "
	try:
		certificates = list(client_factory(module).certificates())
	except TokenDriverNotResponding:  # a TokenUnavailable: checked first
		return [head + f"driver not responding (it was stopped after {PROBE_TIMEOUT_SECONDS} s)"]
	except CertificatesHidden:
		return [head + "token found, but no certificates are visible without a PIN"]
	except TokenUnavailable as exc:
		if exc.message == TokenUnavailable().message:
			return [head + "no token (plug the token in and run the check again)"]
		return [head + "the token cannot be read: " + printable(exc.message, 240)]
	except LocalSignerError as exc:
		if exc.code == "DEPENDENCY_MISSING":
			cause = exc.__cause__
			if isinstance(cause, ImportError) and not isinstance(cause, ModuleNotFoundError):
				# Installed, but it would not load (for example a wheel built for another Python).
				return [head + f"PyKCS11 is installed but failed to import ({exception_name(type(cause))}); reinstall it for this Python"]
			return [head + "PyKCS11 is not installed, so tokens cannot be read"]
		return [head + "the token cannot be read: " + printable(exc.message, 240)]
	except Exception as exc:
		return [head + f"check failed ({exception_name(type(exc))})"]
	count = len(certificates)
	lines = [head + f"{count} certificate{'s' if count != 1 else ''}"]
	for certificate in certificates[:MAX_CERTIFICATES_PER_MODULE]:
		lines += _certificate_lines(certificate)
	if count > MAX_CERTIFICATES_PER_MODULE:
		lines.append("  " + NOT_SHOWN.format(count=count - MAX_CERTIFICATES_PER_MODULE))
	return lines


def report_lines(config_path=None, *, system=None, client_factory=None, trust_store=None, port_status=None, path_exists=None) -> list:
	client_factory = client_factory or DEFAULT_CLIENT
	port_status = port_status or _PORT_STATUS
	config_file = Path(os.path.abspath(os.path.expanduser(os.fspath(config_path or default_config_path()))))
	lines = [
		"ERP DSC Signer support report",
		"No PIN, private key or pairing secret is part of this report. Certificate details are the public ones a signed PDF shows.",
		"",
		"Computer",
		f"  System: {printable(_system_text(system), 160)}",
		f"  Helper version: {printable(_helper_version(), 20)}",
		f"  Python: {platform.python_version()}",
		"",
		"Configuration",
	]
	try:
		config, state = load_config(config_file), "valid"
	except ConfigurationError as exc:
		config, state = SignerConfig(), f"cannot be used: {printable(exc.message, 200)}"
	lines.append(f"  Config file: {printable(str(config_file), 300)} ({state})")
	lines.append(f"  Listening address: {config.host}:{config.port}, {port_status(config.host, config.port)}")
	try:
		paired = str(len((trust_store if trust_store is not None else TrustStore()).list_origins()))
	except Exception:
		paired = "unknown"
	lines.append(f"  Allowed sites: {len(config.allowed_origins)} in config.json, {paired} paired on this computer")
	log_file = log_path(config_file)
	lines.append(f"  Log file: {printable(str(log_file), 300)} ({'exists' if log_file.is_file() else 'not created yet'})")
	lines.append("")

	registry = ProviderRegistry(config, system=system, path_exists=path_exists)
	listed = [module for group in registry.public_providers()[1:] for module in group["modules"]]
	listed.sort(key=lambda module: not module["available"])
	lines.append(f"Token driver locations the helper knows ({len(listed)})")
	for module in listed[:MAX_LISTED_MODULES]:
		state = "found  " if module["available"] else "missing"
		wrong = drivers.unusable_reason(module["path"]) if module["available"] else None
		lines.append(f"  {state}  {PROVIDER_LABELS[module['provider']]:<16} {printable(module['path'], 300)}" + (f"  ({wrong})" if wrong else ""))
	if len(listed) > MAX_LISTED_MODULES:
		lines.append(NOT_SHOWN.format(count=len(listed) - MAX_LISTED_MODULES))
	lines.append("")

	lines.append(f"Token check (read-only, no PIN; each driver runs in a separate process, stopped after {PROBE_TIMEOUT_SECONDS} s)")
	try:
		available = registry.candidates("auto", None)
	except MiddlewareUnavailable:
		available = []
	if not available:
		lines.append("  No token driver was found. Install the driver from the token's maker, or run erp-dsc-local --find-drivers.")
	for module in available[:MAX_CHECKED_MODULES]:
		wrong = drivers.unusable_reason(module.path)
		if wrong:
			lines.append(f"  {PROVIDER_LABELS.get(module.provider, module.provider)}  {printable(module.path, 300)}: skipped ({wrong})")
			continue
		lines += _token_check(module, client_factory)
	if len(available) > MAX_CHECKED_MODULES:
		lines.append(NOT_SHOWN.format(count=len(available) - MAX_CHECKED_MODULES) + " (drivers not checked)")
	lines.append("")
	lines.append("End of report.")
	return lines


def run(config_path=None, *, out=None, **kwargs) -> int:
	"""Print the report.  Always 0: a missing token or a bad config is something to report."""
	out = out or sys.stdout
	for line in report_lines(config_path, **kwargs):
		out.write(line + "\n")
	out.flush()
	return 0
