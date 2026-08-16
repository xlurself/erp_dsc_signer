"""Single-threaded owner of every desktop dialog.

`ThreadingHTTPServer` dispatches each request on its own thread and Tk is not
thread-safe -- on macOS a Tk call from an arbitrary thread can hang or crash the
process.  Every dialog therefore runs on one dedicated worker thread and the calling
request thread blocks on the result.

The same single worker doubles as the process-wide UI mutex: a PIN prompt and a pairing
prompt can never be on screen at once, and a second concurrent request is rejected
rather than silently queued behind a dialog nobody is looking at.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar


T = TypeVar("T")

# Hard backstop only.  Each dialog is expected to enforce its own, shorter timeout;
# this exists so a wedged toolkit cannot pin a request thread forever.
HARD_TIMEOUT_SECONDS = 300


class UiBusy(Exception):
	"""A dialog is already on screen."""


class UiUnavailable(Exception):
	"""No interactive desktop is available (headless, no display, no tkinter)."""


class DialogHost:
	def __init__(self, *, hard_timeout: int = HARD_TIMEOUT_SECONDS):
		self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="erp-dsc-ui")
		self._busy = threading.Lock()
		self._hard_timeout = hard_timeout

	def run_exclusive(self, dialog: Callable[[], T]) -> T:
		"""Run `dialog` on the UI thread, refusing if one is already showing.

		Raises UiBusy immediately when another dialog holds the screen, so the caller
		can answer 429 instead of queueing behind an unanswered prompt.
		"""
		if not self._busy.acquire(blocking=False):
			raise UiBusy()
		try:
			return self._executor.submit(dialog).result(timeout=self._hard_timeout)
		finally:
			self._busy.release()

	@property
	def busy(self) -> bool:
		locked = self._busy.acquire(blocking=False)
		if locked:
			self._busy.release()
		return not locked

	def shutdown(self) -> None:
		self._executor.shutdown(wait=False)


def new_tk_root():
	"""Create a hidden, always-on-top Tk root, or raise UiUnavailable.

	Must only be called from the DialogHost worker thread.
	"""
	try:
		import tkinter as tk

		root = tk.Tk()
		root.withdraw()
		root.attributes("-topmost", True)
		return root
	except Exception as exc:  # ImportError, TclError (no display), ...
		raise UiUnavailable() from exc
