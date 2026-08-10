"""Short-lived, origin-bound, one-use nonces."""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock

from .errors import LocalSignerError


@dataclass(frozen=True)
class _Nonce:
	origin: str
	purpose: str
	expires_at: float


class NonceStore:
	def __init__(self, ttl_seconds: int, max_count: int, *, clock=time.monotonic):
		self.ttl_seconds = ttl_seconds
		self.max_count = max_count
		self._clock = clock
		self._items: OrderedDict[str, _Nonce] = OrderedDict()
		self._lock = Lock()

	def issue(self, origin: str, purpose: str) -> tuple[str, int]:
		if purpose not in {"certificates", "sign"}:
			raise LocalSignerError("INVALID_PURPOSE", "Nonce purpose must be 'certificates' or 'sign'.")
		with self._lock:
			now = self._clock()
			self._prune(now)
			while len(self._items) >= self.max_count:
				self._items.popitem(last=False)
			nonce = secrets.token_urlsafe(32)
			self._items[nonce] = _Nonce(origin, purpose, now + self.ttl_seconds)
		return nonce, self.ttl_seconds

	def consume(self, nonce: str | None, origin: str, purpose: str) -> None:
		# Pop before validation so even a failed protected request cannot be replayed.
		with self._lock:
			now = self._clock()
			self._prune(now)
			item = self._items.pop(nonce, None) if nonce else None
		if item is None or item.origin != origin or item.purpose != purpose or item.expires_at <= now:
			raise LocalSignerError(
				"INVALID_NONCE",
				"The request nonce is missing, expired, already used, or belongs to another operation.",
				status=409,
			)

	def _prune(self, now: float) -> None:
		for nonce, item in list(self._items.items()):
			if item.expires_at <= now:
				del self._items[nonce]
