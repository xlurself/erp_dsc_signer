"""Known middleware locations and safe PKCS#11 module resolution."""

from __future__ import annotations

import hashlib
import platform
from dataclasses import dataclass
from pathlib import Path

from .config import PROVIDER_IDS, SignerConfig
from .errors import LocalSignerError, MiddlewareUnavailable


PROVIDER_LABELS = {
	"auto": "Auto-detect",
	"epass": "ePass",
	"safenet": "SafeNet",
	"proxkey": "ProxKey",
	"watchdata": "WatchData",
	"generic_pkcs11": "Generic PKCS#11",
}


# Middleware installers change paths between releases. These are discovery
# candidates only; a request can load only a path already present in this registry.
KNOWN_PATHS = {
	"Windows": {
		"epass": (
			r"C:\Windows\System32\eps2003csp11.dll",
			r"C:\Windows\System32\eps2003csp11v2.dll",
			r"C:\Windows\SysWOW64\eps2003csp11.dll",
			r"C:\Windows\SysWOW64\eps2003csp11v2.dll",
		),
		"safenet": (
			r"C:\Windows\System32\eTPKCS11.dll",
			r"C:\Windows\SysWOW64\eTPKCS11.dll",
		),
		"proxkey": (
			r"C:\Windows\System32\SignatureP11.dll",
			r"C:\Windows\SysWOW64\SignatureP11.dll",
			r"C:\Windows\System32\ProxKeyP11.dll",
		),
		"watchdata": (
			r"C:\Windows\System32\WDPKCS.dll",
			r"C:\Windows\SysWOW64\WDPKCS.dll",
			r"C:\Windows\System32\wdpkcs11.dll",
		),
		"generic_pkcs11": (),
	},
	"Darwin": {
		"epass": (
			"/usr/local/lib/libcastle.1.0.0.dylib",
			"/usr/local/lib/libcastle.dylib",
			"/usr/local/lib/libepsng_p11.dylib",
			"/Library/Frameworks/ePass2003.framework/Versions/Current/libcastle.dylib",
		),
		"safenet": (
			"/usr/local/lib/libeTPkcs11.dylib",
			"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
			"/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
		),
		"proxkey": (
			"/usr/local/lib/libSignatureP11.dylib",
			"/Library/ProxKey/lib/libSignatureP11.dylib",
		),
		"watchdata": (
			"/usr/local/lib/libwdpkcs.dylib",
			"/Library/WatchData/lib/libwdpkcs.dylib",
		),
		"generic_pkcs11": (
			"/Library/OpenSC/lib/opensc-pkcs11.so",
			"/usr/local/lib/opensc-pkcs11.so",
		),
	},
	"Linux": {
		"epass": ("/usr/lib/libcastle.so.1.0.0", "/usr/lib64/libcastle.so.1.0.0"),
		"safenet": ("/usr/lib/libeTPkcs11.so", "/usr/lib64/libeTPkcs11.so"),
		"proxkey": ("/usr/lib/libSignatureP11.so", "/usr/lib64/libSignatureP11.so"),
		"watchdata": ("/usr/lib/libwdpkcs.so", "/usr/lib64/libwdpkcs.so"),
		"generic_pkcs11": ("/usr/lib/opensc-pkcs11.so", "/usr/lib64/opensc-pkcs11.so"),
	},
}


@dataclass(frozen=True)
class ProviderModule:
	id: str
	provider: str
	label: str
	path: str
	available: bool
	configured: bool = False

	def public_dict(self) -> dict:
		return {
			"id": self.id,
			"provider": self.provider,
			"label": self.label,
			"path": self.path,
			"available": self.available,
			"configured": self.configured,
		}


class ProviderRegistry:
	def __init__(self, config: SignerConfig, *, system: str | None = None, path_exists=None):
		self.config = config
		self.system = system or platform.system()
		self._path_exists = path_exists or (lambda value: Path(value).is_file())
		self._modules = self._build_modules()

	def public_providers(self) -> list[dict]:
		providers = [{"id": "auto", "label": PROVIDER_LABELS["auto"], "modules": []}]
		for provider in PROVIDER_IDS:
			providers.append(
				{
					"id": provider,
					"label": PROVIDER_LABELS[provider],
					"modules": [item.public_dict() for item in self._modules if item.provider == provider],
				}
			)
		providers[0]["modules"] = [item.public_dict() for item in self._modules if item.available]
		return providers

	def candidates(self, provider: str, module_id: str | None) -> list[ProviderModule]:
		"""Every available module that ``provider`` / ``module_id`` names, in registry order.

		Never empty.  ``module_id`` is compared only with the registry's own ids, so a
		request can NAME a module but can never supply a library path.
		"""
		if provider not in PROVIDER_LABELS:
			raise LocalSignerError("UNKNOWN_PROVIDER", "Select a supported DSC token provider.")
		matches = [item for item in self._modules if item.available and provider in {"auto", item.provider}]
		if module_id:
			matches = [item for item in matches if item.id == module_id][:1]
			if not matches:
				raise MiddlewareUnavailable(
					"The selected PKCS#11 module is unavailable or does not belong to the selected provider."
				)
		if not matches:
			raise MiddlewareUnavailable(
				f"No installed {PROVIDER_LABELS[provider]} PKCS#11 middleware was found. Install the vendor driver or configure its absolute library path."
			)
		return matches

	def resolve(self, provider: str, module_id: str | None) -> ProviderModule:
		"""The ONE module to sign with: several candidates without a ``module_id`` is refused."""
		matches = self.candidates(provider, module_id)
		if not module_id and len(matches) > 1:
			raise LocalSignerError(
				"MODULE_SELECTION_REQUIRED",
				"More than one compatible middleware module is installed. Select a module explicitly.",
				status=409,
				details={"module_ids": [item.id for item in matches]},
			)
		return matches[0]

	def _build_modules(self) -> list[ProviderModule]:
		items = []
		seen_paths = set()
		for custom in self.config.custom_modules:
			path = str(Path(custom.path))
			if path in seen_paths:
				continue
			seen_paths.add(path)
			items.append(
				ProviderModule(
					custom.id,
					custom.provider,
					custom.label or f"Configured {PROVIDER_LABELS[custom.provider]} module",
					path,
					self._path_exists(path),
					True,
				)
			)

		known = KNOWN_PATHS.get(self.system, {})
		for provider in PROVIDER_IDS:
			configured_paths = self.config.provider_paths.get(provider, ())
			for path_value in tuple(configured_paths) + tuple(known.get(provider, ())):
				path = str(Path(path_value))
				if path in seen_paths:
					continue
				seen_paths.add(path)
				items.append(
					ProviderModule(
						_module_id(provider, path),
						provider,
						Path(path).name,
						path,
						self._path_exists(path),
						path_value in configured_paths,
					)
				)
		return items


def _module_id(provider: str, path: str) -> str:
	digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
	return f"{provider}-{digest}"
