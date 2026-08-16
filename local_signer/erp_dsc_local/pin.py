"""Native, local-only PIN prompt.

The origin is shown first and unadorned because it is the only string in this dialog
the requesting site cannot choose.  The document name arrives in the request body, so
it is attacker-controlled: it is rendered as a clearly-labelled secondary line and
never as the headline the user is being asked to trust.
"""

from __future__ import annotations

from .errors import PinCancelled, PinPromptUnavailable
from .ui import UiUnavailable, new_tk_root


PIN_TIMEOUT_SECONDS = 120
MAX_DOCUMENT_NAME = 140


def build_pin_text(origin: str, document_name: str | None) -> str:
	lines = [
		"Sign with your USB DSC token?",
		"",
		"Requested by:",
		origin,
		"",
	]
	name = (document_name or "").strip()[:MAX_DOCUMENT_NAME]
	if name:
		lines += [
			f"Document (as described by the site): {name}",
			"",
		]
	lines.append("Enter your USB DSC token PIN to sign:")
	return "\n".join(lines)


def request_pin(origin: str, document_name: str | None = None, *, timeout_seconds: int = PIN_TIMEOUT_SECONDS) -> str:
	"""Prompt for the token PIN.  Must run on the DialogHost worker thread."""
	import tkinter as tk
	from tkinter import simpledialog

	try:
		root = new_tk_root()
	except UiUnavailable as exc:
		raise PinPromptUnavailable() from exc

	try:
		# Bound the wait so a prompt nobody answers cannot hold the UI thread forever.
		root.after(int(timeout_seconds * 1000), root.quit)
		pin = simpledialog.askstring(
			"ERP DSC Signer",
			build_pin_text(origin, document_name),
			show="*",
			parent=root,
		)
	except Exception as exc:
		raise PinPromptUnavailable() from exc
	finally:
		try:
			root.destroy()
		except Exception:
			pass

	if not pin:
		raise PinCancelled()
	return pin
