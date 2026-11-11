"""Find token driver files, and add one to config.json, without loading it here (BRD F4).

``--find-drivers`` LISTS files whose name looks like a PKCS#11 library in a fixed, per-system
set of folders: shallow (a depth limit per folder), bounded (``MAX_ENTRIES`` directory
entries and ``MAX_SECONDS``), never descending into a symlinked folder and never reporting a
link whose target is outside the folder being searched.  Nothing is opened or loaded.

``--add-module`` writes ONE file into ``providers.custom_modules``.  The library is never
loaded in this process: the optional ``--verify`` asks the killable probe child
(``token.run_probe``), the same one the daemon uses.  The path must be absolute, plain (no
"..", no control character, not a link), a regular readable file with a library
extension, and on POSIX neither the file nor any folder above it may be writable by the
group or others (a sticky folder is allowed), and the file and those folders must belong to the
user or to root.  A path already configured or already a built-in location is a success that
changes nothing (exit 0), so an installer script can be run twice.  config.json is rewritten atomically (temp file in the same
folder, validated with ``load_config``, ``os.replace``) after its previous bytes are saved,
also atomically, as ``config.json.bak``; both are 0600.  A config.json that is a link or
does not load is never rewritten.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import ntpath
import os
import platform
import re
import struct
import sysconfig
import stat
import sys
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .cli import _printable
from .config import load_config
from .errors import ConfigurationError
from .logs import exception_name
from .providers import KNOWN_PATHS
from .token import PROBE_TIMEOUT_SECONDS, TokenDriverNotResponding, run_probe

NAME_NEEDLES = ("pkcs11", "castle", "wdpkcs", "etpkcs", "signature", "innait", "etoken")
LIBRARY_SUFFIXES = (".dylib", ".so", ".dll")
# "p11" only as a word part (SignatureP11, libdeep_p11), never inside msvcp110.
_P11_WORD = re.compile(r"(?:^|[^a-z0-9])p11(?:[^0-9]|$)")
# ...or a name that ENDS in p11 / csp11, with an optional version (ProxKeyP11, eps2003csp11v2); never msvcp110.
_P11_STEM = re.compile(r"p11(?:v\d+)?$")
# Look-alikes seen on a real Windows machine: .NET BouncyCastle, p11-kit, Java's j2pkcs11.
NOT_DRIVERS = ("bouncycastle", "p11-kit", "j2pkcs11", "minidriver", "interop", "innaitcsp")
_VERSIONED_SO = re.compile(r"\.so(?:\.[0-9]+)+$")
MAX_ENTRIES = 50_000
MAX_SECONDS = 10.0
MAX_CANDIDATES = 100
CUSTOM_PROVIDER = "generic_pkcs11"
BACKUP_SUFFIX = ".bak"


# --- find -----------------------------------------------------------------------------------


@dataclass
class ScanResult:
	candidates: list = field(default_factory=list)
	truncated: bool = False


def plausible_library_name(name: str) -> bool:
	lower = name.lower()
	return lower.endswith(LIBRARY_SUFFIXES) or bool(_VERSIONED_SO.search(lower))


def _looks_like_driver(name: str) -> bool:
	lower = name.lower()
	if not plausible_library_name(name) or any(word in lower for word in NOT_DRIVERS):
		return False
	stem = lower.rsplit(".", 1)[0]
	return any(needle in lower for needle in NAME_NEEDLES) or bool(_P11_WORD.search(lower)) or bool(_P11_STEM.search(stem))


def scan_roots(system=None, env=None) -> list:
	"""``[(folder, depth)]`` for ``system``: depth 0 means the folder's own files only."""
	system = system or platform.system()
	env = os.environ if env is None else env
	if system == "Windows":
		windows = env.get("SystemRoot") or "C:\\Windows"
		roots = [(ntpath.join(windows, "System32"), 0), (ntpath.join(windows, "SysWOW64"), 0)]
		for key, default in (
			("ProgramFiles", "C:\\Program Files"),
			("ProgramFiles(x86)", "C:\\Program Files (x86)"),
			("ProgramW6432", "C:\\Program Files"),
		):
			roots.append((env.get(key) or default, 3))
	elif system == "Darwin":
		roots = [("/usr/local/lib", 1), ("/opt", 4), ("/Library", 4)]
	else:
		roots = [("/usr/lib", 2), ("/usr/lib64", 2), ("/usr/local/lib", 1), ("/opt", 4)]
	seen, unique = set(), []
	for folder, depth in roots:
		key = folder.lower() if system == "Windows" else folder
		if key not in seen:
			seen.add(key)
			unique.append((folder, depth))
	return unique


def _inside(path: str, folder: str) -> bool:
	try:
		return os.path.commonpath([path, folder]) == folder
	except ValueError:  # different drives
		return False


def find_drivers(roots, *, max_entries=MAX_ENTRIES, max_seconds=MAX_SECONDS, max_candidates=MAX_CANDIDATES, clock=time.monotonic):
	result = ScanResult()
	deadline = clock() + max_seconds
	visited = 0
	for root, max_depth in roots:
		if not os.path.isdir(root):
			continue
		real_root = os.path.realpath(root)
		queue = deque([(root, 0)])
		while queue:
			folder, depth = queue.popleft()
			try:
				with os.scandir(folder) as listing:
					entries = []
					for entry in listing:  # lazily: never read more than the remaining budget
						entries.append(entry)
						if len(entries) > max_entries - visited or (len(entries) % 256 == 0 and clock() > deadline):
							break
					entries.sort(key=lambda entry: entry.name)
			except OSError:
				continue  # unreadable or vanished: skip it
			for entry in entries:
				visited += 1
				if visited > max_entries or clock() > deadline or len(result.candidates) >= max_candidates:
					result.truncated = True
					return result
				try:
					if entry.is_dir(follow_symlinks=False):
						if depth < max_depth:
							queue.append((entry.path, depth + 1))
					elif not _looks_like_driver(entry.name):
						continue
					elif entry.is_file(follow_symlinks=False):
						result.candidates.append(entry.path)
					elif entry.is_symlink():
						target = os.path.realpath(entry.path)
						if os.path.isfile(target) and _inside(target, real_root):
							result.candidates.append(entry.path)
				except OSError:
					continue
	return result


def _known_paths(config_path, system) -> set:
	"""Every path the helper would already offer: built-in locations plus config.json."""
	paths = [path for group in KNOWN_PATHS.get(system, {}).values() for path in group]
	try:
		config = load_config(config_path)
	except ConfigurationError:
		config = None
	if config is not None:
		paths += [module.path for module in config.custom_modules]
		paths += [path for group in config.provider_paths.values() for path in group]
	return {os.path.normcase(os.path.normpath(path)) for path in paths}


_PE_MACHINES = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64"}
_BITS = {"x64": "64-bit", "x86": "32-bit", "arm64": "ARM64"}


def driver_architecture(path: str) -> str | None:
	"""'x64', 'x86' or 'arm64' read from a Windows DLL's header; None for anything else.  Reads 4 KB, never loads it."""
	try:
		with open(path, "rb") as handle:
			head = handle.read(4096)
	except OSError:
		return None
	if head[:2] != b"MZ" or len(head) < 0x40:
		return None
	offset = int.from_bytes(head[0x3C:0x40], "little")
	if offset + 6 > len(head) or head[offset : offset + 4] != b"PE\0\0":
		return None
	return _PE_MACHINES.get(int.from_bytes(head[offset + 4 : offset + 6], "little"))


def python_architecture() -> str:
	build = sysconfig.get_platform().lower()  # the interpreter's build: an x64 Python on ARM64 Windows is "win-amd64"
	if "arm64" in build or "aarch64" in build:
		return "arm64"
	if "amd64" in build or "x86_64" in build:
		return "x64"
	if build == "win32":
		return "x86"
	if platform.machine().lower() in ("arm64", "aarch64"):
		return "arm64"
	return "x64" if struct.calcsize("P") == 8 else "x86"


def unusable_reason(path: str) -> str | None:
	"""Why this running Python cannot use the driver file (wrong bitness), or None when it can or we cannot tell."""
	driver, own = driver_architecture(path), python_architecture()
	if driver is None or driver == own:
		return None
	return f"{_BITS[driver]} driver; this Python is {_BITS[own]} and cannot use it"


def _shown(path: str) -> str:
	text = _printable(path)
	return text if text == path else text + "  (the name has hidden characters; shown without them)"


def find_drivers_command(config_path, *, system=None) -> int:
	system = system or platform.system()
	roots = scan_roots(system)
	known = _known_paths(config_path, system)
	print("Possible token driver files. Nothing was loaded: files are only listed.")
	print("Searched: " + ", ".join(f"{_printable(folder)} ({depth} level{'' if depth == 1 else 's'} down)" for folder, depth in roots))
	result = find_drivers(roots)
	for path in result.candidates:
		suffix = "  (already known to the helper)" if os.path.normcase(os.path.normpath(path)) in known else ""
		wrong = unusable_reason(path)
		if wrong:
			suffix += f"  ({wrong})"
		print(f"  {_shown(path)}{suffix}")
	if not result.candidates:
		print("  (none found in these folders)")
	if result.truncated:
		print(f"The search stopped at its limit ({MAX_ENTRIES} entries, {int(MAX_SECONDS)} s, {MAX_CANDIDATES} files); some folders were not searched.")
	print("To use a file the helper does not know yet:")
	print('  erp-dsc-local --add-module "<absolute path of the file>" --verify')
	return 0


# --- add ------------------------------------------------------------------------------------


class Refused(Exception):
	def __init__(self, message: str, code: int = 2):
		super().__init__(message)
		self.message = message
		self.code = code


def _has_control(text: str) -> bool:
	return _printable(text) != text


def check_module_path(value, *, system=None) -> str:
	"""The validated path, or ``Refused``.  Reads metadata only: never opens the file."""
	system = system or platform.system()
	if not isinstance(value, str) or not value:
		raise Refused("give the absolute path of the driver file.")
	if _has_control(value):
		raise Refused("the path contains a control character.")
	pathmod = ntpath if system == "Windows" else os.path
	if not pathmod.isabs(value) or (system == "Windows" and not ntpath.splitdrive(value)[0]):
		example = r"C:\Windows\System32\vendor-pkcs11.dll" if system == "Windows" else "/usr/local/lib/libvendor-pkcs11.dylib"
		raise Refused(f"give the absolute path of the driver file, for example {example}.")
	if ".." in re.split(r"[\\/]", value):
		raise Refused("the path must not contain '..'; give the plain path of the file.")
	try:
		info = os.lstat(value)
	except FileNotFoundError:
		raise Refused(f"{_printable(value)} does not exist.") from None
	except OSError:
		raise Refused(f"{_printable(value)} cannot be checked.") from None
	if stat.S_ISLNK(info.st_mode):
		raise Refused(
			f"{_printable(value)} is a link; add the file it points to instead: {_printable(os.path.realpath(value))}"
		)
	if not stat.S_ISREG(info.st_mode):
		raise Refused(f"{_printable(value)} is not a regular file.")
	if not plausible_library_name(os.path.basename(value)):
		raise Refused(f"{_printable(value)} is not a library file (.dylib, .so or .dll).")
	if system == "Windows":
		_check_windows_acl(value)
	else:
		_check_not_replaceable(value, info)
	if not os.access(value, os.R_OK):
		raise Refused(f"{_printable(value)} cannot be read.")
	return value


# Well-known SIDs of groups that must NOT be able to change the driver: Everyone, Authenticated Users, Users.
_UNTRUSTED_SIDS = ("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
# Access-mask bits: FILE_WRITE_DATA/ADD_FILE 0x2, FILE_APPEND_DATA/ADD_SUBDIRECTORY 0x4, FILE_WRITE_EA 0x10,
# FILE_DELETE_CHILD 0x40, FILE_WRITE_ATTRIBUTES 0x100, DELETE 0x10000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000.
_WRITE_RIGHTS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
# A folder further up only matters if it lets someone rename or delete the folder below it.
_REPLACE_RIGHTS = 0x40 | 0x10000 | 0x40000 | 0x80000


def windows_untrusted_rights(path: str) -> int:
	"""The access rights Everyone, Authenticated Users and Users have on ``path`` (a bit mask).  Windows only.

	Reads the real DACL with ``GetNamedSecurityInfoW`` and asks ``GetEffectiveRightsFromAclW`` per SID.
	Raises ``OSError`` when it cannot read: the caller then refuses (fail closed).
	"""
	import ctypes
	from ctypes import wintypes

	class Trustee(ctypes.Structure):
		_fields_ = [
			("pMultipleTrustee", ctypes.c_void_p),
			("MultipleTrusteeOperation", ctypes.c_int),
			("TrusteeForm", ctypes.c_int),
			("TrusteeType", ctypes.c_int),
			("ptstrName", ctypes.c_void_p),
		]

	advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
	kernel32.LocalFree.argtypes = [ctypes.c_void_p]
	kernel32.LocalFree.restype = ctypes.c_void_p
	advapi32.GetNamedSecurityInfoW.argtypes = [
		wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
		ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
	]
	advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
	advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
	advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
	advapi32.BuildTrusteeWithSidW.argtypes = [ctypes.POINTER(Trustee), ctypes.c_void_p]
	advapi32.BuildTrusteeWithSidW.restype = None
	advapi32.GetEffectiveRightsFromAclW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Trustee), ctypes.POINTER(wintypes.DWORD)]
	advapi32.GetEffectiveRightsFromAclW.restype = wintypes.DWORD

	dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
	# SE_FILE_OBJECT = 1, DACL_SECURITY_INFORMATION = 4
	status = advapi32.GetNamedSecurityInfoW(path, 1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
	if status:
		raise OSError(status, "the permissions of this file could not be read")
	try:
		combined = 0
		for text in _UNTRUSTED_SIDS:
			sid = ctypes.c_void_p()
			if not advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
				raise ctypes.WinError(ctypes.get_last_error())
			try:
				trustee = Trustee()
				advapi32.BuildTrusteeWithSidW(ctypes.byref(trustee), sid)
				mask = wintypes.DWORD()
				status = advapi32.GetEffectiveRightsFromAclW(dacl, ctypes.byref(trustee), ctypes.byref(mask))
				if status:
					raise OSError(status, "the permissions of this file could not be read")
				combined |= mask.value
			finally:
				kernel32.LocalFree(sid)
		return combined
	finally:
		kernel32.LocalFree(descriptor)


def _check_windows_acl(value: str, rights=None) -> None:
	"""Refuse a driver that Everyone / Authenticated Users / Users can change, or whose folder they can change.

	The helper loads this DLL in the process that holds the PIN.  The file and its own folder must deny
	write to those groups; every folder above must deny rename and delete.  Any failure to read a
	permission is a refusal.
	"""
	rights = rights or windows_untrusted_rights
	path = ntpath.normpath(value)
	level = 0
	while True:
		needed = _WRITE_RIGHTS if level < 2 else _REPLACE_RIGHTS
		try:
			granted = rights(path)
		except Exception:
			raise Refused("the permissions of this driver or its folder could not be checked; it was not added.") from None
		if granted & needed:
			raise Refused("other users can change this file or its folder; ask your administrator to fix its permissions.")
		parent = ntpath.dirname(path)
		if not parent or parent == path:
			return
		path, level = parent, level + 1


def _check_not_replaceable(value: str, info) -> None:
	"""The file and every folder above it: no group/other write (a sticky folder is fine), owned by root or the user.

	The helper later loads this library in the process that holds the PIN, so anyone who can swap it
	can read the PIN.
	"""
	me = os.getuid()
	if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
		raise Refused("other users can change this file or its folder; ask your administrator to fix its permissions.")
	if info.st_uid not in (0, me):
		raise Refused("the file is owned by another user; ask your administrator to install the driver properly.")
	folder = os.path.dirname(value)
	while True:
		meta = os.lstat(folder)
		sticky = bool(meta.st_mode & stat.S_ISVTX)
		if meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky:
			raise Refused("other users can change this file or its folder; ask your administrator to fix its permissions.")
		if meta.st_uid not in (0, me):
			raise Refused("a folder above the file is owned by another user; ask your administrator to install the driver properly.")
		parent = os.path.dirname(folder)
		if parent == folder:
			return
		folder = parent


def _module_id(path: str) -> str:
	slug = re.sub(r"[^A-Za-z0-9]+", "", Path(path).stem)[:24] or "module"
	return f"custom-{slug}-{hashlib.sha256(path.encode('utf-8')).hexdigest()[:8]}"


def _default_probe(path: str) -> dict:
	return run_probe(path, "certificates")


def _verify(path: str, probe) -> str:
	try:
		reply = (probe or _default_probe)(path)
	except TokenDriverNotResponding:
		raise Refused(f"the driver did not answer within {PROBE_TIMEOUT_SECONDS} s; nothing was added.", 1) from None
	except Exception as exc:
		raise Refused(f"the driver check failed ({exception_name(type(exc))}); nothing was added.", 1) from None
	result = reply.get("result")
	if result == "load_failed":
		raise Refused("the file could not be loaded as a token driver; nothing was added.", 1)
	if result == "dependency_missing":
		raise Refused("PyKCS11 is not installed for this helper, so the driver cannot be checked; nothing was added.", 1)
	if result == "slot_list_failed":
		return "The driver loaded, but it could not list token slots (try again with the token plugged in)."
	if result == "ok":
		slots = len(reply.get("slots") or ())
		return "The driver loaded; no token is connected right now." if not slots else f"The driver loaded; {slots} token slot(s) answered."
	raise Refused("the driver check gave no usable answer; nothing was added.", 1)


def _read_config(config: Path) -> tuple[bytes, dict]:
	try:
		info = os.lstat(config)
	except FileNotFoundError:
		raise Refused(f"the config file {_printable(str(config))} does not exist.") from None
	if stat.S_ISLNK(info.st_mode):
		raise Refused(f"the config file {_printable(str(config))} is a link; give the real file with --config.")
	if not stat.S_ISREG(info.st_mode):
		raise Refused(f"the config file {_printable(str(config))} is not a regular file.")
	original = config.read_bytes()
	try:
		raw = json.loads(original.decode("utf-8"))
		load_config(config)
	except (UnicodeDecodeError, ValueError, ConfigurationError) as exc:
		detail = exc.message if isinstance(exc, ConfigurationError) else "it is not valid JSON"
		raise Refused(f"the config file cannot be used: {detail}") from None
	if not isinstance(raw, dict):
		raise Refused("the config file cannot be used: its root is not a JSON object.")
	return original, raw


_ALREADY_KNOWN = "it is already known to the helper"
_ALREADY_PREFIXES = (_ALREADY_KNOWN, "it is already in config.json", "it is already listed in config.json")


def _duplicate(path: str, raw: dict, system: str) -> str | None:
	key = os.path.normcase(os.path.normpath(path))
	providers = raw.get("providers") or {}
	for module in providers.get("custom_modules") or ():
		if os.path.normcase(os.path.normpath(str(module.get("path", "")))) == key:
			return f"it is already in config.json as module {_printable(str(module.get('id')))}."
	for paths in (providers.get("additional_paths") or {}).values():
		if key in {os.path.normcase(os.path.normpath(str(item))) for item in paths}:
			return "it is already listed in config.json (providers.additional_paths)."
	for paths in KNOWN_PATHS.get(system, {}).values():
		if key in {os.path.normcase(os.path.normpath(item)) for item in paths}:
			return _ALREADY_KNOWN + " (a built-in location); nothing to add."
	return None


def _write_private(target: Path, data: bytes, *, validate=False) -> None:
	"""``data`` into ``target`` atomically: a 0600 temp file in the same folder, fsync, then (if
	``validate``) ``load_config`` on the temp file, then replace."""
	handle, temp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
	try:
		with os.fdopen(handle, "wb") as stream:
			stream.write(data)
			stream.flush()
			os.fsync(stream.fileno())
		if os.name != "nt":
			os.chmod(temp, 0o600)
		if validate:
			load_config(temp)
		os.replace(temp, target)
	except BaseException:
		with contextlib.suppress(OSError):
			os.unlink(temp)
		raise


def add_module(config_path, module_path, *, verify=False, probe=None, system=None) -> int:
	system = system or platform.system()
	config = Path(os.path.abspath(os.path.expanduser(os.fspath(config_path))))
	try:
		original, raw = _read_config(config)
		if isinstance(module_path, str) and module_path:
			early = _duplicate(module_path, raw, system)  # already configured or built in: nothing to write, so no strict check
			if early and early.startswith(_ALREADY_PREFIXES):
				print(f"{_printable(module_path)} was not added: {early}")
				return 0
		path = check_module_path(module_path, system=system)
		duplicate = _duplicate(path, raw, system)
		if duplicate:
			if duplicate.startswith(_ALREADY_PREFIXES):
				print(f"{_printable(path)} was not added: {duplicate}")
				return 0  # nothing to do is success: installer scripts must not fail on a built-in path
			raise Refused(f"{_printable(path)} was not added: {duplicate}")
		note = _verify(path, probe) if verify else None
		module_id = _module_id(path)
		providers = raw.setdefault("providers", {})
		modules = providers.setdefault("custom_modules", [])
		if any(item.get("id") == module_id for item in modules):
			raise Refused(f"a module with the id {module_id} is already configured.")
		modules.append(
			{"id": module_id, "provider": CUSTOM_PROVIDER, "path": path, "label": "Added: " + _printable(os.path.basename(path))[:80]}
		)
		updated = (json.dumps(raw, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
		backup = config.with_name(config.name + BACKUP_SUFFIX)
		try:
			_write_private(backup, original)
			_write_private(config, updated, validate=True)
		except (OSError, ConfigurationError) as exc:
			raise Refused(f"config.json could not be written ({exception_name(type(exc))}); it was left as it was.", 1) from None
	except Refused as refused:
		print(f"error: {refused.message}", file=sys.stderr)
		return refused.code
	if note:
		print(note)
	print(f"Added {_printable(path)} as module {module_id} in {_printable(str(config))}")
	print(f"The previous configuration is saved as {_printable(str(backup))}.")
	print("Restart ERP DSC Signer (or restart your computer) to use it.")
	return 0
