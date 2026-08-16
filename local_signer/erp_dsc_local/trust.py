"""Runtime origin trust store.

`config.json` stays operator-owned and immutable at runtime; consent granted at the
keyboard is persisted here instead.  Every origin is canonicalised on the way in and on
the way out, so a value written by one release still matches a browser header read by
the next.

Two processes touch this file: the running signer and the `erp-dsc-local --allow/--revoke`
CLI.  Neither can see the other's memory, so:

  * reads re-read the file whenever it has changed on disk, which is what makes a CLI
    revoke take effect against a running daemon instead of waiting for a restart;
  * writes take a cross-process lock and re-read before applying, so a daemon holding
    stale state cannot resurrect an origin the CLI just revoked.

Failure policy is closed: an unreadable, corrupt, or unknown-version file yields an
empty allow set and is left on disk untouched for an operator to inspect.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from threading import RLock

from .origins import canonical_origin, try_canonical_origin


logger = logging.getLogger(__name__)

STORE_VERSION = 1
DEFAULT_STATE_DIR = "~/.erp-dsc-local"
STORE_FILENAME = "allowed_origins.json"
TRUST_FILE_ENV = "ERP_DSC_LOCAL_TRUST_FILE"

MAX_ORIGINS = 32
DENIAL_TTL_SECONDS = 24 * 60 * 60


def default_store_path() -> Path:
	override = os.environ.get(TRUST_FILE_ENV)
	if override:
		return Path(override).expanduser()
	return Path(DEFAULT_STATE_DIR).expanduser() / STORE_FILENAME


@contextmanager
def _file_lock(path: Path):
	"""Best-effort cross-process exclusive lock on a sidecar file."""
	lock_path = path.with_name(path.name + ".lock")
	lock_path.parent.mkdir(parents=True, exist_ok=True)
	handle = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
	locked = False
	try:
		try:
			import fcntl

			fcntl.flock(handle, fcntl.LOCK_EX)
			locked = True
		except ImportError:
			try:
				import msvcrt

				msvcrt.locking(handle, msvcrt.LK_LOCK, 1)
				locked = True
			except Exception:
				# No advisory locking available.  Writes are still atomic; only the
				# read-modify-write window is unprotected.
				logger.warning("Advisory file locking unavailable; concurrent writes may race.")
		yield
	finally:
		if locked:
			try:
				import fcntl

				fcntl.flock(handle, fcntl.LOCK_UN)
			except ImportError:
				try:
					import msvcrt

					msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
				except Exception:
					pass
		os.close(handle)


class TrustStore:
	def __init__(
		self,
		path: Path | str | None = None,
		*,
		max_origins: int = MAX_ORIGINS,
		denial_ttl_seconds: int = DENIAL_TTL_SECONDS,
		clock=time.time,
	):
		self.path = Path(path).expanduser() if path else default_store_path()
		self.max_origins = max_origins
		self.denial_ttl_seconds = denial_ttl_seconds
		self._clock = clock
		self._lock = RLock()
		self._origins: dict[str, dict] = {}
		self._denials: dict[str, float] = {}
		self._fingerprint = None
		self._load()

	# ---------------------------------------------------------------- queries

	def is_allowed(self, origin: str) -> bool:
		canonical = try_canonical_origin(origin)
		if canonical is None:
			return False
		with self._lock:
			self._reload_if_changed()
			return canonical in self._origins

	def list_origins(self) -> list[dict]:
		with self._lock:
			self._reload_if_changed()
			return [dict(entry) for entry in self._origins.values()]

	def is_denied(self, origin: str) -> bool:
		canonical = try_canonical_origin(origin)
		if canonical is None:
			return False
		with self._lock:
			self._reload_if_changed()
			self._prune_denials()
			return canonical in self._denials

	# -------------------------------------------------------------- mutations

	def allow(self, origin: str, *, site_name: str | None = None, user: str | None = None) -> str:
		canonical = canonical_origin(origin)
		with self._lock, _file_lock(self.path):
			self._load(force=True)  # never write back over another process's changes
			if canonical not in self._origins and len(self._origins) >= self.max_origins:
				raise ValueError(
					f"The local signer already trusts {self.max_origins} origins. "
					"Revoke one before pairing another."
				)
			self._origins[canonical] = {
				"origin": canonical,
				"approved_at": int(self._clock()),
				# Recorded for support only.  These are supplied by the site being
				# paired and are NOT verified identity -- never present them as such.
				"claimed_site_name": site_name or "",
				"claimed_user": user or "",
			}
			self._denials.pop(canonical, None)
			self._save()
		return canonical

	def revoke(self, origin: str) -> bool:
		canonical = try_canonical_origin(origin)
		if canonical is None:
			return False
		with self._lock, _file_lock(self.path):
			self._load(force=True)
			if canonical not in self._origins:
				return False
			del self._origins[canonical]
			self._save()
		return True

	def record_denial(self, origin: str) -> None:
		canonical = try_canonical_origin(origin)
		if canonical is None:
			return
		with self._lock, _file_lock(self.path):
			self._load(force=True)
			self._denials[canonical] = self._clock() + self.denial_ttl_seconds
			self._prune_denials()
			self._save()

	# ------------------------------------------------------------- persistence

	def _prune_denials(self) -> None:
		now = self._clock()
		for origin, expires_at in list(self._denials.items()):
			if expires_at <= now:
				del self._denials[origin]

	def _fingerprint_now(self):
		"""Identity of the file as last written, for cheap change detection."""
		try:
			info = self.path.stat()
		except OSError:
			return None
		return (info.st_mtime_ns, info.st_size, info.st_ino)

	def _reload_if_changed(self) -> None:
		if self._fingerprint_now() != self._fingerprint:
			self._load(force=True)

	def _load(self, *, force: bool = False) -> None:
		if not force and self._fingerprint_now() == self._fingerprint:
			return
		self._origins = {}
		self._denials = {}
		self._fingerprint = self._fingerprint_now()

		path = self.path
		try:
			if path.is_symlink():
				logger.warning("Refusing to read trust store through a symlink: %s", path)
				return
			raw = json.loads(path.read_text(encoding="utf-8"))
		except FileNotFoundError:
			return
		except (OSError, json.JSONDecodeError) as exc:
			logger.warning("Trust store unreadable, treating as empty (left on disk): %s", exc)
			return

		if not isinstance(raw, dict) or raw.get("version") != STORE_VERSION:
			logger.warning(
				"Trust store version is missing or unsupported, treating as empty (left on disk): %s",
				path,
			)
			return

		now = self._clock()
		for entry in raw.get("origins") or []:
			if not isinstance(entry, dict):
				continue
			canonical = try_canonical_origin(entry.get("origin"))
			if canonical is None:
				logger.warning("Dropping invalid origin from trust store: %r", entry.get("origin"))
				continue
			if len(self._origins) >= self.max_origins:
				logger.warning("Trust store exceeds %s origins; ignoring the rest.", self.max_origins)
				break
			self._origins[canonical] = {
				"origin": canonical,
				"approved_at": entry.get("approved_at") or 0,
				"claimed_site_name": str(entry.get("claimed_site_name") or ""),
				"claimed_user": str(entry.get("claimed_user") or ""),
			}
		for entry in raw.get("denials") or []:
			if not isinstance(entry, dict):
				continue
			canonical = try_canonical_origin(entry.get("origin"))
			expires_at = entry.get("expires_at")
			if canonical is None or not isinstance(expires_at, (int, float)) or expires_at <= now:
				continue
			self._denials[canonical] = float(expires_at)

	def _save(self) -> None:
		payload = {
			"version": STORE_VERSION,
			"origins": list(self._origins.values()),
			"denials": [
				{"origin": origin, "expires_at": expires_at}
				for origin, expires_at in self._denials.items()
			],
		}
		directory = self.path.parent
		directory.mkdir(parents=True, exist_ok=True)
		try:
			os.chmod(directory, 0o700)
		except OSError:  # best effort; Windows and some mounts do not support it
			pass

		handle, temp_name = tempfile.mkstemp(dir=str(directory), prefix=".origins-", suffix=".tmp")
		try:
			with os.fdopen(handle, "w", encoding="utf-8") as stream:
				json.dump(payload, stream, indent=1)
				stream.flush()
				os.fsync(stream.fileno())
			try:
				os.chmod(temp_name, 0o600)
			except OSError:
				# POSIX-only.  On Windows the file inherits the ACL of the private
				# parent directory, which is the documented best effort.
				pass
			os.replace(temp_name, self.path)
		except BaseException:
			try:
				os.unlink(temp_name)
			except OSError:
				pass
			raise
		self._fingerprint = self._fingerprint_now()
