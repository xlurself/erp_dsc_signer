"""Native, local-only PIN prompt."""

from __future__ import annotations

from .errors import PinCancelled, PinPromptUnavailable


def request_pin(summary: str) -> str:
	try:
		import tkinter as tk
		from tkinter import simpledialog
		root = tk.Tk()
		root.withdraw()
		root.attributes("-topmost", True)
		pin = simpledialog.askstring("ERP DSC Signer", summary + "\n\nEnter USB DSC token PIN:", show="*", parent=root)
		root.destroy()
	except Exception as exc:
		raise PinPromptUnavailable() from exc
	if not pin:
		raise PinCancelled()
	return pin
