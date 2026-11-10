"""The signer's desktop dialog, run as its own short-lived child process.

The daemon starts this file as ``[sys.executable, "-I", <this file>]`` and hands it
ONE request line on stdin (spec 001 section 4/6).  The child shows one native Tk
window, writes ONE reply line on stdout and exits.  Tk therefore always runs on the
main thread of a process that owns nothing else, which is what macOS requires.

This module is a LEAF: at module level it holds stdlib imports, constants and
definitions only.  It never imports the rest of the package (``ui``, ``pin``,
``pairing``, ``service``, ``token``), it imports ``tkinter`` lazily inside functions,
and importing it reads no stdin and creates no window.  ``ui.py`` imports the
constants and ``validate_request`` from here so the parent and the child apply the
same rules.

Output discipline: nothing but the single reply line ever reaches stdout (fd 1 is
pointed at the null device for the lifetime of the dialog and the reply is written to
a private duplicate), no traceback is printed, and the PIN is never logged.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unicodedata


# --- Constants (spec section 2: defined here exactly once) -----------------------
MIN_DIALOG_SECONDS = 5
MAX_DIALOG_SECONDS = 300
DEFAULT_DIALOG_SECONDS = 120
INPUT_GUARD_SECONDS = 1.5
MAX_REQUEST_BYTES = 8192
MAX_REPLY_BYTES = 4096
# Short enough that the whole host fits on one line of any real screen at the smallest
# origin font: the TAIL of a long host is the part that names the attacker's domain.
MAX_ORIGIN_CHARS = 120
MAX_CLAIM_CHARS = 140

# --- Wire schema (spec section 6) -------------------------------------------------
PROTOCOL_VERSION = 1
KINDS = ("pin", "consent")
REQUEST_KEYS = frozenset({"v", "kind", "origin", "claims", "warnings", "final_try", "timeout"})
RESULTS = {
	"pin": ("entered", "cancelled", "timeout", "unavailable"),
	"consent": ("allow", "deny", "timeout", "unavailable"),
}
UNAVAILABLE_CAUSES = ("tk_import_failed", "tk_init_failed")

# Characters a person cannot see or that reorder/split what they see.
UNREADABLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# Claims only (spec section 6): characters that render as blank space in a category the
# rule above does not cover (Lo, So, Mn).  A run of them pushes the rest of a claim out
# of sight.  Every Zs other than U+0020 is refused too, by category.
INVISIBLE_FILLERS = frozenset(
	{
		"ㅤ",  # HANGUL FILLER (Lo)
		"ᅟ",  # HANGUL CHOSEONG FILLER (Lo)
		"ᅠ",  # HANGUL JUNGSEONG FILLER (Lo)
		"ﾠ",  # HALFWIDTH HANGUL FILLER (Lo)
		"⠀",  # BRAILLE PATTERN BLANK (So)
		"͏",  # COMBINING GRAPHEME JOINER (Mn)
		"᠎",  # MONGOLIAN VOWEL SEPARATOR (Cf today; Zs in old Unicode)
		"឴",  # KHMER VOWEL INHERENT AQ (Mn)
		"឵",  # KHMER VOWEL INHERENT AA (Mn)
		"\U00016fe4",  # KHITAN SMALL SCRIPT FILLER (Mn)
		"\U0001d159",  # MUSICAL SYMBOL NULL NOTEHEAD (So)
	}
)
# Claims only: a NO-BREAK SPACE is an ordinary space (company names carry it), so it is
# mapped to U+0020 before the rules above and before runs of spaces are collapsed.
NO_BREAK_SPACE = "\u00a0"
# Claims only: the Cf joiners Indic text needs.  Kept ONLY next to a virama (canonical
# combining class 9); anywhere else they are invisible and the claim is unreadable.
ZWNJ = "\u200c"
ZWJ = "\u200d"
VIRAMA_COMBINING_CLASS = 9
CLAIM_TOO_LONG = "(claim too long)"
CLAIM_UNREADABLE = "(unreadable claim removed)"

# --- Exit codes -------------------------------------------------------------------
# 65 is part of the parent's classifier (dialog_request_invalid).  Every other
# non-zero code classifies as dialog_process_failed; they are distinct only so a
# person reading a process table can tell them apart.
EXIT_REQUEST_INVALID = 65
EXIT_INTERNAL = 70
EXIT_PARENT_GONE = 75
EXIT_NOT_ISOLATED = 78

# --- Presentation -----------------------------------------------------------------
# Frappe v14 desk look (visual only: no behaviour depends on any value below).  The
# body text uses the first UI_FONT_FAMILIES entry Tk knows; Tk always knows Helvetica.
UI_FONT_FAMILIES = ("Inter", "Helvetica Neue", "Helvetica")
DIALOG_MIN_WIDTH = 460  # pixels; the window grows past it for a long host, never shrinks below
WINDOW_PADDING = 24
COLOR_BG = "#ffffff"
COLOR_TEXT = "#1f272e"
COLOR_MUTED = "#6c7680"
COLOR_BORDER = "#d1d8dd"
COLOR_FIELD_WAIT = "#f4f5f6"  # the PIN box before the accepted click
COLOR_FIELD_ACTIVE = "#ffffff"
COLOR_FOCUS_HALO = "#c8e2fb"  # around the active PIN box
COLOR_PRIMARY = "#2490ef"
COLOR_PRIMARY_PRESSED = "#1579d0"
COLOR_PRIMARY_DISABLED = "#a8d3fa"
COLOR_PRIMARY_DISABLED_TEXT = "#eef6fe"
COLOR_PRIMARY_TEXT = "#ffffff"
COLOR_SECONDARY = "#f4f5f6"
COLOR_SECONDARY_PRESSED = "#e2e6e9"
COLOR_BUTTON_FOCUS = "#1f272e"  # keyboard focus ring on a flat button
COLOR_WARNING = "#a40000"
PIN_ENTRY_WIDTH = 30  # characters
PIN_ENTRY_FONT_SIZE = 14
PIN_PLACEHOLDER = "Click here to start typing"  # its own Label drawn over the Entry, never inserted into it
# Only the signer's own text (heading, warnings, footer) is wrapped.  The origin's host
# line and every site claim are NEVER wrapped (spec section 9).
WRAP_PIXELS = DIALOG_MIN_WIDTH - 2 * WINDOW_PADDING
ORIGIN_FONT_FAMILY = "Courier"
ORIGIN_FONT_SIZES = (14, 13, 12, 11, 10, 9, 8)  # largest first; shrink only to fit the screen
ORIGIN_SCREEN_MARGIN = 80  # pixels left free beside the host line
CLAIM_FONT_FAMILY = "Helvetica"
CLAIM_FONT_SIZE = 12  # capped at the origin's size: site text is never larger than the origin
CLAIM_PREFIX = "as described by the site: "
FINAL_TRY_TEXT = "This is the LAST PIN attempt before the token locks."
FINAL_TRY_TICK = "I understand that a wrong PIN now locks the token."
PIN_TITLE = "ERP DSC Signer - PIN"
PIN_HEADING = "is asking to sign with your USB DSC token."
PIN_PROMPT = "Enter your USB DSC token PIN:"
PIN_HINT_WAIT = "Wait..."  # while the input guard is armed
PIN_HINT_BEFORE_CLICK = "Click inside this window first, then type your PIN."
PIN_HINT_CLICK_AGAIN = "Click inside this window again, then type your PIN."  # a click was ignored
PIN_HINT_AFTER_CLICK = "Type your PIN, then press OK."
CONSENT_TITLE = "ERP DSC Signer - pairing request"
CONSENT_HEADING = "wants to use the digital signature token on this computer."
CONSENT_FOOTER = (
	"If you allow it, this site can ask your USB token to sign documents. "
	"You will still enter your token PIN for every signature.",
	"Allow only if you just clicked Pair in your own ERP.",
)

# Consent events -> results.  Escape and window close are ALWAYS a Deny.
CONSENT_EVENTS = {
	"allow": "allow",
	"deny": "deny",
	"escape": "deny",
	"close": "deny",
	"timeout": "timeout",
}
CONSENT_BUTTON_EVENTS = frozenset({"allow", "deny"})


class InvalidRequest(ValueError):
	"""The dialog request failed validation.

	The message names the rule that failed and never contains request text.
	"""


# --- Validation (shared by parent and child) --------------------------------------
def _unreadable(text: str) -> bool:
	return any(unicodedata.category(ch) in UNREADABLE_CATEGORIES for ch in text)


def _reject_duplicate_keys(pairs):
	keys = [key for key, _value in pairs]
	if len(set(keys)) != len(keys):
		raise InvalidRequest("duplicate key")
	return dict(pairs)


def _reject_constant(_name):
	raise InvalidRequest("non-finite number")


def _parse_request_line(data: bytes) -> object:
	if len(data) > MAX_REQUEST_BYTES:
		raise InvalidRequest("request too large")
	if not data.endswith(b"\n"):
		raise InvalidRequest("request is not one newline-terminated line")
	body = data[:-1]
	if b"\n" in body or b"\r" in body:
		raise InvalidRequest("request is not one line")
	try:
		return json.loads(
			body.decode("utf-8"),
			object_pairs_hook=_reject_duplicate_keys,
			parse_constant=_reject_constant,
		)
	except InvalidRequest:
		raise
	except (ValueError, RecursionError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
		raise InvalidRequest("request is not valid JSON") from None


def _unreadable_in_claim(ch: str) -> bool:
	if ch == " ":
		return False
	category = unicodedata.category(ch)
	return category in UNREADABLE_CATEGORIES or category == "Zs" or ch in INVISIBLE_FILLERS


def _joiner_allowed(text: str, index: int) -> bool:
	"""Is the ZWNJ/ZWJ at text[index] part of Indic shaping?

	Either joiner right AFTER a virama (the Marathi eyelash ra is Devanagari RA, VIRAMA,
	ZWJ, YA; an explicit halant is KA, VIRAMA, ZWNJ, SSA), or a ZWJ right BEFORE one
	(Bengali ra + ya-phala is RA, ZWJ, VIRAMA, YA).
	"""
	if index > 0 and unicodedata.combining(text[index - 1]) == VIRAMA_COMBINING_CLASS:
		return True
	return (
		text[index] == ZWJ
		and index + 1 < len(text)
		and unicodedata.combining(text[index + 1]) == VIRAMA_COMBINING_CLASS
	)


def _clean_claim(claim: object) -> str:
	"""One site claim, as the dialog will show it (spec section 6).

	Over-long -> CLAIM_TOO_LONG.  U+00A0 NO-BREAK SPACE is first mapped to U+0020.
	Then any Cc/Cf/Cs/Co/Cn/Zl/Zp character, any Zs other than U+0020, or an
	INVISIBLE_FILLERS character -> CLAIM_UNREADABLE, except a ZWNJ/ZWJ next to a virama
	(_joiner_allowed).  Otherwise runs of U+0020 are collapsed to one and the ends are
	stripped; a non-empty claim that becomes empty is CLAIM_UNREADABLE.  Combining
	marks (Mn/Mc) are kept: Indian-script names need them.  Never truncated.
	Idempotent: a cleaned claim cleans to itself.
	"""
	if type(claim) is not str:
		raise InvalidRequest("claim is not a string")
	if len(claim) > MAX_CLAIM_CHARS:
		return CLAIM_TOO_LONG
	text = claim.replace(NO_BREAK_SPACE, " ")
	for index, ch in enumerate(text):
		if ch in (ZWNJ, ZWJ):
			if not _joiner_allowed(text, index):
				return CLAIM_UNREADABLE
		elif _unreadable_in_claim(ch):
			return CLAIM_UNREADABLE
	cleaned = " ".join(part for part in text.split(" ") if part)
	if claim and not cleaned:
		return CLAIM_UNREADABLE
	return cleaned


clean_claim = _clean_claim  # public name for pairing.py (one rule, one definition)


def _encode(request: dict) -> bytes:
	try:
		line = json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n"
	except (UnicodeEncodeError, ValueError):
		raise InvalidRequest("request cannot be encoded") from None
	if len(line) > MAX_REQUEST_BYTES:
		raise InvalidRequest("request too large")
	return line


def validate_request(request) -> dict:
	"""Validate a dialog request and return its normalised copy.

	Accepts the request dict (parent, before spawning) or the raw request line as
	bytes (child, after reading stdin).  Never alters the origin: an over-long or
	unreadable origin is refused.  Site claims go through _clean_claim: over-long or
	unreadable ones are replaced by a visible placeholder (never truncated) and runs of
	spaces are collapsed.  The timeout is clamped to
	[MIN_DIALOG_SECONDS, MAX_DIALOG_SECONDS].  Raises InvalidRequest (a ValueError).
	Pure: no I/O, the input is not modified.
	"""
	if isinstance(request, (bytes, bytearray)):
		request = _parse_request_line(bytes(request))
	if type(request) is not dict:
		raise InvalidRequest("request is not an object")
	if set(request) != REQUEST_KEYS:
		raise InvalidRequest("request keys do not match the schema")

	version = request["v"]
	if type(version) is not int or version != PROTOCOL_VERSION:
		raise InvalidRequest("unsupported version")

	kind = request["kind"]
	if type(kind) is not str or kind not in KINDS:
		raise InvalidRequest("unknown kind")

	origin = request["origin"]
	if type(origin) is not str or not origin:
		raise InvalidRequest("origin is not a non-empty string")
	if len(origin) > MAX_ORIGIN_CHARS:
		raise InvalidRequest("origin too long")
	if _unreadable(origin):
		raise InvalidRequest("origin contains unreadable characters")

	claims = request["claims"]
	if type(claims) is not list:
		raise InvalidRequest("claims is not a list")
	clean_claims = [_clean_claim(claim) for claim in claims]

	warnings = request["warnings"]
	if type(warnings) is not list:
		raise InvalidRequest("warnings is not a list")
	for warning in warnings:
		# Warnings are the signer's own text; anything unreadable here is a bug,
		# so it fails closed instead of being replaced.
		if type(warning) is not str or not warning or _unreadable(warning):
			raise InvalidRequest("warning is not readable text")

	final_try = request["final_try"]
	if type(final_try) is not bool:
		raise InvalidRequest("final_try is not a bool")

	timeout = request["timeout"]
	if type(timeout) is not int:
		raise InvalidRequest("timeout is not an int")
	timeout = max(MIN_DIALOG_SECONDS, min(MAX_DIALOG_SECONDS, timeout))

	clean = {
		"v": PROTOCOL_VERSION,
		"kind": kind,
		"origin": origin,
		"claims": clean_claims,
		"warnings": list(warnings),
		"final_try": final_try,
		"timeout": timeout,
	}
	_encode(clean)
	return clean


def encode_request(request) -> bytes:
	"""Validate `request` and return the exact bytes to write on the child's stdin."""
	return _encode(validate_request(request))


# --- Replies -----------------------------------------------------------------------
def make_reply(kind: str, result: str, *, value=None, cause=None) -> dict:
	"""Build a reply dict that satisfies the section 6 schema, or raise ValueError.

	Error messages never include `value`.
	"""
	if kind not in KINDS or result not in RESULTS[kind]:
		raise ValueError("reply result does not match the schema")
	reply = {"v": PROTOCOL_VERSION, "kind": kind, "result": result}
	if result == "entered":
		if type(value) is not str or not value:
			raise ValueError("an entered PIN needs a non-empty value")
		reply["value"] = value
	elif value is not None:
		raise ValueError("value is only allowed on an entered PIN")
	if result == "unavailable":
		if cause not in UNAVAILABLE_CAUSES:
			raise ValueError("unknown unavailable cause")
		reply["cause"] = cause
	elif cause is not None:
		raise ValueError("cause is only allowed on unavailable")
	return reply


def encode_reply(reply: dict) -> bytes:
	"""Serialise a reply as ONE line; refuse anything the parent would reject as oversize."""
	line = json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
	if len(line) > MAX_REPLY_BYTES:
		raise ValueError("reply too large")
	return line


# --- Decisions (pure) ----------------------------------------------------------------
def decide(event: str, *, guarded: bool = False):
	"""Map a consent-window event to a result.

	Returns None for a button event that arrives while the input guard is armed
	(the buttons are inert then).  Escape and close are a Deny even while guarded.
	An unknown event is a Deny: refusal is the fail-closed direction.
	"""
	if guarded and event in CONSENT_BUTTON_EVENTS:
		return None
	return CONSENT_EVENTS.get(event, "deny")


def pin_outcome(event: str, value=None) -> tuple:
	"""Map a PIN-window event to (result, value).  An empty PIN is a cancel."""
	if event == "ok":
		if type(value) is str and value:
			return "entered", value
		return "cancelled", None
	if event == "timeout":
		return "timeout", None
	return "cancelled", None


def consent_layout() -> dict:
	"""The consent window's behaviour as plain data, consumed by build_consent_window.

	Deny has the initial focus; Tab goes Deny then Allow; no button is the Tk
	default (so Return never answers); both buttons are inert for the input guard.
	"""
	return {
		"title": CONSENT_TITLE,
		"buttons": {"deny": "Deny", "allow": "Allow"},
		"tab_order": ("deny", "allow"),
		"initial_focus": "deny",
		"default": None,
		"input_guard_seconds": INPUT_GUARD_SECONDS,
	}


def origin_lines(origin: str) -> list:
	"""The origin's display lines: ``[scheme + "://", host[:port]]`` (spec section 9).

	The host, with any port, is ONE line that is never broken: breaking inside it
	lets an attacker subdomain such as ``erp.mycompany.com.evil.example`` show the
	victim's host alone on a line.  Never drops or alters a character:
	''.join(result) == origin.  An origin without "://" is one line.
	"""
	scheme, sep, host = origin.partition("://")
	if not sep or not host:
		return [origin]
	return [scheme + sep, host]


# --- Windows (Tk imported lazily; every string goes in as text=) ---------------------
def _is_window(widget, window) -> bool:
	return str(widget) == str(window)


def _when_shown(window, callback) -> None:
	"""Call `callback()` when `window` maps, and again on every later map.

	On macOS (Tk 9) the root window reports itself mapped as soon as Tk() returns and
	no <Map> event for it reaches a binding made afterwards, so an idle check covers
	a window that is already mapped when the event loop starts.
	"""

	def on_map(event) -> None:
		if _is_window(event.widget, window):
			callback()

	def if_already_mapped() -> None:
		if window.winfo_ismapped():
			callback()

	window.bind("<Map>", on_map)
	window.after_idle(if_already_mapped)


class _InputGuard:
	"""Input is ignored for `seconds` after the window maps and after focus RETURNS.

	Armed by arm() (called when the window is shown) and by a FocusIn -- on the
	toplevel or on any of its widgets -- that is a real return: focus had been inside
	the window, then a FocusOut left it (focus went to another application or
	nowhere), and now it comes back.  The window opens UNFOCUSED (click-first, no
	focus_force), so the FocusIn that the user's activating click produces is the
	window's FIRST focus, not a return: it does not re-arm, or that click would be
	ignored and the user would have to click again.  Moving focus between the
	window's own widgets does not re-arm either.  `on_change()` runs after every arm
	and release so the window can update its widgets.
	"""

	def __init__(self, tk, window, seconds: float, on_change):
		self._tk = tk
		self._window = window
		self._ms = int(seconds * 1000)
		self._on_change = on_change
		self._after = None
		self._was_inside = False  # focus has been inside the window at least once
		self._left = False  # ...and has left it since the last FocusIn
		self.armed = True
		self.stopped = False
		window.bind("<FocusIn>", self.on_focus_in)
		window.bind("<FocusOut>", lambda _event: window.after_idle(self.check_outside))

	def arm(self) -> None:
		if self.stopped:
			return
		self.armed = True
		if self._after is not None:
			self._window.after_cancel(self._after)
		self._after = self._window.after(self._ms, self._release)
		self._on_change()

	def _release(self) -> None:
		self._after = None
		if self.stopped:
			return
		self.armed = False
		self._on_change()

	def stop(self) -> None:
		self.stopped = True
		if self._after is not None:
			self._window.after_cancel(self._after)
			self._after = None

	def on_focus_in(self, _event) -> None:
		if self.stopped:
			return
		if self._left:
			self.arm()
		self._was_inside = True
		self._left = False

	def check_outside(self) -> None:
		"""Run when idle after a FocusOut: did focus leave the window (not just move)?"""
		if not self._was_inside:
			return
		try:
			focused = self._window.focus_get()
			outside = focused is None or not _is_window(focused.winfo_toplevel(), self._window)
		except (KeyError, self._tk.TclError):
			outside = True
		if outside:
			self._left = True


def _prepare_window(window, title: str) -> None:
	window.title(title)
	window.resizable(False, False)
	window.configure(bg=COLOR_BG)
	window.minsize(DIALOG_MIN_WIDTH, 1)
	window.attributes("-topmost", True)
	window.lift()
	# Deliberately no focus_force(): stealing focus while the user is typing in
	# another window would swallow keystrokes (spec section 9, click-first).


def _ui_family(window) -> str:
	"""The first UI_FONT_FAMILIES entry this Tk knows (Tk always maps the last, Helvetica)."""
	import tkinter.font as tkfont

	known = set(tkfont.families(window))
	for family in UI_FONT_FAMILIES:
		if family in known:
			return family
	return UI_FONT_FAMILIES[-1]


def _flat_button_class(tk):
	"""A flat, Frappe-coloured button drawn as a tk.Label (macOS Tk ignores tk.Button colours).

	It keeps the parts of the tk.Button contract the PIN window relies on:
	``invoke()`` runs the command only while the state is "normal", so a disabled
	button is inert to the mouse, to Space and to ``invoke()``; a mouse press that
	starts on the ENABLED button and is released inside it invokes it (as tk.Button
	does, a press that began while it was disabled never does); Space invokes it when
	it has keyboard focus (``takefocus``: Tab reaches it); Return does not.
	``set_state()`` changes the state and the colours together.  The 1-pixel outline
	(and the keyboard-focus ring) is ``outline``, a Frame around the Label: macOS Tk
	does not draw the highlight ring of a Label nested in a Frame.  Pack ``outline``.
	"""

	class FlatButton(tk.Label):
		def __init__(self, master, *, text, command, primary=False, font=None):
			self.outline = tk.Frame(master, padx=1, pady=1)
			super().__init__(self.outline, text=text, font=font, padx=20, pady=7, takefocus=1, cursor="hand2", highlightthickness=0)
			self.pack(fill="both", expand=True)
			self._on_activate = command
			self._primary = primary
			self._pressed = False
			self._focused = False
			self.set_state("normal")
			self.bind("<ButtonPress-1>", self._on_press)
			self.bind("<ButtonRelease-1>", self._on_release)
			self.bind("<KeyPress-space>", lambda _event: self.invoke())
			# Colour only; no "break", so the window's own FocusIn/FocusOut (the input
			# guard) still sees every event.
			self.bind("<FocusIn>", lambda _event: self._set_focused(True))
			self.bind("<FocusOut>", lambda _event: self._set_focused(False))

		def _enabled(self) -> bool:
			return str(self.cget("state")) != "disabled"

		def _set_focused(self, focused: bool) -> None:
			self._focused = focused
			self._paint()

		def _paint(self, background=None) -> None:
			if not self._primary:
				bg, fg, border = COLOR_SECONDARY, COLOR_TEXT, COLOR_BORDER
			elif self._enabled():
				bg, fg, border = COLOR_PRIMARY, COLOR_PRIMARY_TEXT, COLOR_PRIMARY
			else:
				bg, fg, border = COLOR_PRIMARY_DISABLED, COLOR_PRIMARY_DISABLED_TEXT, COLOR_PRIMARY_DISABLED
			self.configure(bg=background or bg, fg=fg, disabledforeground=fg, activebackground=bg, activeforeground=fg)
			self.outline.configure(bg=COLOR_BUTTON_FOCUS if self._focused else border)

		def set_state(self, state: str) -> None:
			self.configure(state=state)
			self._paint()

		def invoke(self):
			if not self._enabled():
				return None
			return self._on_activate()

		def _on_press(self, _event) -> None:
			self._pressed = self._enabled()
			if self._pressed:
				self._paint(COLOR_PRIMARY_PRESSED if self._primary else COLOR_SECONDARY_PRESSED)

		def _on_release(self, event) -> None:
			pressed, self._pressed = self._pressed, False
			if not pressed:
				return
			self._paint()
			if 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
				self.invoke()

	return FlatButton


def _origin_font(window, origin: str):
	"""The largest ORIGIN_FONT_SIZES font whose widest origin line fits on the screen.

	Fits means within ``winfo_screenwidth() - ORIGIN_SCREEN_MARGIN``.  Shrinking the
	font is the only adjustment: the host is never wrapped or elided.  Returns None
	when even the smallest size does not fit: the tail of the host -- the part that
	names the real domain -- would be off-screen, so the caller must refuse to show
	the dialog (fail closed).  A failure to measure is NOT swallowed: it ends the
	child (exit EXIT_INTERNAL), which the daemon reports as unavailable, never as an
	answer.
	"""
	import tkinter.font as tkfont

	lines = origin_lines(origin)
	room = window.winfo_screenwidth() - ORIGIN_SCREEN_MARGIN
	for size in ORIGIN_FONT_SIZES:
		font = tkfont.Font(root=window, family=ORIGIN_FONT_FAMILY, size=size, weight="bold")
		if max(font.measure(line) for line in lines) <= room:
			return (ORIGIN_FONT_FAMILY, size, "bold")
	return None


def _claim_font(origin_font: tuple) -> tuple:
	"""Site claims are never drawn larger than the origin."""
	return (CLAIM_FONT_FAMILY, min(CLAIM_FONT_SIZE, origin_font[1]))


def _add_text_block(tk, body, request: dict, heading: str, origin_font: tuple, extra_warnings=(), ui="Helvetica") -> None:
	"""Origin first in its own label, then the heading, warnings and site claims.

	The origin label and the claim labels have NO wraplength (Tk then never wraps).
	`origin_font` comes from _origin_font, so the host line fits on the screen.  Each
	claim is one line that starts with CLAIM_PREFIX, so site text can never begin a
	line of its own, and is drawn no larger than the origin (_claim_font).  `ui` is the
	font family of the signer's own text (_ui_family).
	"""
	tk.Label(
		body,
		text="\n".join(origin_lines(request["origin"])),
		justify="left",
		anchor="w",
		font=origin_font,
		fg=COLOR_TEXT,
		bg=COLOR_BG,
	).pack(anchor="w", fill="x")
	tk.Label(
		body, text=heading, justify="left", anchor="w", wraplength=WRAP_PIXELS, font=(ui, 13), fg=COLOR_TEXT, bg=COLOR_BG
	).pack(anchor="w", fill="x", pady=(4, 10))
	for warning in (*extra_warnings, *request["warnings"]):
		tk.Label(
			body,
			text=warning,
			justify="left",
			anchor="w",
			wraplength=WRAP_PIXELS,
			fg=COLOR_WARNING,
			bg=COLOR_BG,
			font=(ui, 13, "bold"),
		).pack(anchor="w", fill="x", pady=(0, 6))
	claim_font = _claim_font(origin_font)
	for claim in request["claims"]:
		tk.Label(
			body, text=CLAIM_PREFIX + claim, justify="left", anchor="w", font=claim_font, fg=COLOR_MUTED, bg=COLOR_BG
		).pack(anchor="w", fill="x")


def build_consent_window(layout: dict, request: dict, window, on_result) -> dict:
	"""Populate `window` (a Tk or Toplevel) as the consent dialog described by `layout`.

	`on_result(reply_dict)` is called exactly once.  Returns a handle with the
	buttons and the Escape/close handlers (used by tests).  If the host cannot fit on
	the screen (_origin_font is None) nothing is built: the answer is an immediate
	"deny" and no Allow button ever exists (``handle["refused"]`` is True).

	Input guard (_InputGuard): Allow and Deny are disabled for the layout's
	``input_guard_seconds`` after the window maps and after focus returns to it from
	outside; the first activation of the unfocused window does not re-arm it.
	Escape and close are a Deny at any time, including during the guard.
	"""
	import tkinter as tk

	origin_font = _origin_font(window, request["origin"])
	if origin_font is None:
		on_result(make_reply("consent", "deny"))
		return {"refused": True}

	state = {"timer": None, "done": False}
	ui = _ui_family(window)
	_prepare_window(window, layout["title"])

	body = tk.Frame(window, padx=WINDOW_PADDING, pady=WINDOW_PADDING, bg=COLOR_BG)
	body.pack(fill="both")
	_add_text_block(tk, body, request, CONSENT_HEADING, origin_font, ui=ui)
	for line in CONSENT_FOOTER:
		tk.Label(
			body, text=line, justify="left", anchor="w", wraplength=WRAP_PIXELS, font=(ui, 13), fg=COLOR_TEXT, bg=COLOR_BG
		).pack(anchor="w", fill="x", pady=(8, 0))

	def finish(result) -> None:
		if result is None or state["done"]:
			return
		state["done"] = True
		guard.stop()
		if state["timer"] is not None:
			window.after_cancel(state["timer"])
			state["timer"] = None
		on_result(make_reply("consent", result))

	def press(name: str) -> None:
		finish(decide(name, guarded=guard.armed))

	row = tk.Frame(window, bg=COLOR_BG)
	row.pack(pady=(0, WINDOW_PADDING))
	buttons = {}
	# Creation order is Tk's Tab order.  Native buttons (Space, focus, no default=
	# are Tk's own); only the colour around them follows the window.
	for name in layout["tab_order"]:
		button = tk.Button(
			row,
			text=layout["buttons"][name],
			width=14,
			state="disabled",
			command=lambda name=name: press(name),
			highlightbackground=COLOR_BG,
		)
		button.pack(side="left", padx=8)
		buttons[name] = button
	if layout["default"] is not None:
		buttons[layout["default"]].configure(default="active")
	buttons[layout["initial_focus"]].focus_set()

	def refresh() -> None:
		for button in buttons.values():
			button.configure(state="disabled" if guard.armed else "normal")

	guard = _InputGuard(tk, window, layout["input_guard_seconds"], refresh)

	def on_shown() -> None:
		if state["done"]:
			return
		guard.arm()
		if state["timer"] is None:
			state["timer"] = window.after(request["timeout"] * 1000, lambda: finish(decide("timeout")))

	def on_escape(_event=None) -> None:
		finish(decide("escape"))

	def on_close() -> None:
		finish(decide("close"))

	_when_shown(window, on_shown)
	window.bind("<Escape>", on_escape)
	window.protocol("WM_DELETE_WINDOW", on_close)
	return {
		"refused": False,
		"buttons": buttons,
		"escape": on_escape,
		"close": on_close,
		"guarded": lambda: guard.armed,
		"timer_started": lambda: state["timer"] is not None,
	}


def build_pin_window(request: dict, window, on_result) -> dict:
	"""Populate `window` as the PIN dialog.  `on_result(reply_dict)` is called once.

	The masked Entry stays DISABLED until the user clicks inside the window.  The
	input guard (INPUT_GUARD_SECONDS after the window maps and after focus returns
	from outside, see _InputGuard) ignores that click and Return/OK, so a click
	already in flight when the always-on-top window appears cannot enable the Entry
	and let keystrokes meant for another window be submitted as a PIN.  The click
	that first activates the (unfocused) window after the guard is NOT ignored.  The
	hint reads PIN_HINT_WAIT while the guard is armed and PIN_HINT_CLICK_AGAIN once
	it ends if a click was ignored.  With `final_try`, OK stays disabled until the
	tick-box is ticked.  Escape and close are always a cancel, including during the
	guard.  If the host cannot fit on the screen (_origin_font is None) nothing is
	built: the answer is an immediate "cancelled" and no OK button or Entry ever
	exists (``handle["refused"]`` is True).

	Look (visual only): the Entry sits in a bordered box (``handle["field"]``) whose
	border belongs to the frame, so it shows while the Entry is disabled (a disabled
	macOS Tk Entry draws none).  Until the accepted click the box is grey with
	PIN_PLACEHOLDER drawn over it as a separate Label (``handle["placeholder"]``),
	never inserted into the Entry; the accepted click turns it white with a blue ring.
	Cancel and OK are _flat_button_class buttons; OK looks disabled exactly while
	ok_allowed() is false.
	"""
	import tkinter as tk

	origin_font = _origin_font(window, request["origin"])
	if origin_font is None:
		on_result(make_reply("pin", "cancelled"))
		return {"refused": True}

	final_try = request["final_try"]
	state = {"clicked": False, "ignored": False, "timer": None, "done": False}
	ui = _ui_family(window)
	_prepare_window(window, PIN_TITLE)

	body = tk.Frame(window, padx=WINDOW_PADDING, pady=WINDOW_PADDING, bg=COLOR_BG)
	body.pack(fill="both")
	_add_text_block(tk, body, request, PIN_HEADING, origin_font, (FINAL_TRY_TEXT,) if final_try else (), ui)
	tk.Label(
		body, text=PIN_PROMPT, justify="left", anchor="w", font=(ui, 13, "bold"), fg=COLOR_TEXT, bg=COLOR_BG
	).pack(anchor="w", fill="x", pady=(16, 6))
	# halo (window-white; light blue once active) > field (the bordered box) > Entry.
	halo = tk.Frame(body, bg=COLOR_BG, padx=2, pady=2)
	halo.pack(anchor="w", fill="x")
	field = tk.Frame(
		halo, bg=COLOR_FIELD_WAIT, highlightthickness=1, highlightbackground=COLOR_BORDER, highlightcolor=COLOR_BORDER
	)
	field.pack(fill="x")
	entry = tk.Entry(
		field,
		show="*",
		width=PIN_ENTRY_WIDTH,
		state="disabled",
		exportselection=False,
		font=(ui, PIN_ENTRY_FONT_SIZE),
		relief="flat",
		borderwidth=0,
		highlightthickness=0,
		bg=COLOR_FIELD_WAIT,
		disabledbackground=COLOR_FIELD_WAIT,
		fg=COLOR_TEXT,
		insertbackground=COLOR_TEXT,
	)
	entry.pack(fill="x", padx=12, pady=9)
	placeholder = tk.Label(field, text=PIN_PLACEHOLDER, anchor="w", font=(ui, 13), fg=COLOR_MUTED, bg=COLOR_FIELD_WAIT)
	placeholder.place(in_=entry, x=0, rely=0.5, anchor="w")
	hint = tk.Label(
		body, text=PIN_HINT_WAIT, justify="left", anchor="w", wraplength=WRAP_PIXELS, font=(ui, 12), fg=COLOR_MUTED, bg=COLOR_BG
	)
	hint.pack(anchor="w", fill="x", pady=(6, 0))

	ticked = None
	tick = None
	if final_try:
		ticked = tk.BooleanVar(master=window, value=False)
		tick = tk.Checkbutton(
			body,
			text=FINAL_TRY_TICK,
			variable=ticked,
			anchor="w",
			justify="left",
			font=(ui, 13),
			fg=COLOR_TEXT,
			bg=COLOR_BG,
			activebackground=COLOR_BG,
			highlightthickness=0,
		)
		tick.pack(anchor="w", fill="x", pady=(10, 0))

	def show_active_box() -> None:
		placeholder.place_forget()
		halo.configure(bg=COLOR_FOCUS_HALO)
		field.configure(bg=COLOR_FIELD_ACTIVE, highlightbackground=COLOR_PRIMARY, highlightcolor=COLOR_PRIMARY)
		entry.configure(bg=COLOR_FIELD_ACTIVE)

	def ok_allowed() -> bool:
		return state["clicked"] and not guard.armed and (ticked is None or bool(ticked.get()))

	def finish(event: str, value=None) -> None:
		if state["done"]:
			return
		state["done"] = True
		guard.stop()
		if state["timer"] is not None:
			window.after_cancel(state["timer"])
			state["timer"] = None
		result, value = pin_outcome(event, value)
		on_result(make_reply("pin", result, value=value))

	def on_ok(_event=None) -> None:
		if state["done"] or not ok_allowed():
			return
		value = entry.get()
		entry.delete(0, "end")
		finish("ok", value)

	flat_button = _flat_button_class(tk)
	row = tk.Frame(window, bg=COLOR_BG)
	row.pack(fill="x", padx=WINDOW_PADDING, pady=(0, WINDOW_PADDING))
	# Creation order is Tk's Tab order (Cancel, then OK); packed right-aligned.
	cancel = flat_button(row, text="Cancel", command=lambda: finish("cancel"), font=(ui, 13))
	ok = flat_button(row, text="OK", command=on_ok, primary=True, font=(ui, 13, "bold"))
	ok.set_state("disabled")
	ok.outline.pack(side="right")
	cancel.outline.pack(side="right", padx=(0, 10))

	def hint_text() -> str:
		if guard.armed:
			return PIN_HINT_WAIT
		if state["clicked"]:
			return PIN_HINT_AFTER_CLICK
		return PIN_HINT_CLICK_AGAIN if state["ignored"] else PIN_HINT_BEFORE_CLICK

	def refresh() -> None:
		ok.set_state("normal" if ok_allowed() else "disabled")
		hint.configure(text=hint_text())

	if tick is not None:
		tick.configure(command=refresh)

	guard = _InputGuard(tk, window, INPUT_GUARD_SECONDS, refresh)

	def on_click(_event=None) -> None:
		if state["done"] or state["clicked"]:
			return
		if guard.armed:
			state["ignored"] = True
			return
		state["clicked"] = True
		entry.configure(state="normal")
		show_active_box()
		entry.focus_set()
		refresh()

	def on_shown() -> None:
		if state["done"]:
			return
		guard.arm()
		if state["timer"] is None:
			state["timer"] = window.after(request["timeout"] * 1000, lambda: finish("timeout"))

	def on_escape(_event=None) -> None:
		finish("escape")

	def on_close() -> None:
		finish("close")

	entry.bind("<Return>", on_ok)
	entry.bind("<KP_Enter>", on_ok)
	window.bind("<ButtonPress>", on_click)
	_when_shown(window, on_shown)
	window.bind("<Escape>", on_escape)
	window.protocol("WM_DELETE_WINDOW", on_close)
	return {
		"refused": False,
		"timer_started": lambda: state["timer"] is not None,
		"guarded": lambda: guard.armed,
		"hint": hint,
		"entry": entry,
		"field": field,
		"placeholder": placeholder,
		"ok": ok,
		"cancel": cancel,
		"tick": tick,
		"ticked": ticked,
		"click": on_click,
		"escape": on_escape,
		"close": on_close,
	}


# --- Process plumbing ----------------------------------------------------------------
class ReplyGate:
	"""Shared between the reply writer and the EOF watcher.

	Whoever takes the lock first wins: the writer marks the reply as written before
	writing it, and the watcher exits only if no reply has been started.
	"""

	__slots__ = ("lock", "written")

	def __init__(self):
		self.lock = threading.Lock()
		self.written = False


def watch_eof(stream=None, gate=None, *, exit_process=None, chunk: int = 4096):
	"""Start a daemon thread that discards `stream` until EOF, then exits the process.

	EOF on stdin means the parent died or gave up; the child must not outlive it.
	The exit is silent and is skipped when `gate` shows a reply is already being
	written.  Returns the started thread.
	"""
	if stream is None:
		stream = sys.stdin.buffer
	if exit_process is None:
		exit_process = os._exit

	def run() -> None:
		try:
			while stream.read(chunk):
				pass
		except (OSError, ValueError):
			pass
		if gate is None:
			exit_process(EXIT_PARENT_GONE)
			return
		with gate.lock:
			if not gate.written:
				exit_process(EXIT_PARENT_GONE)

	thread = threading.Thread(target=run, name="erp-dsc-dialog-eof", daemon=True)
	thread.start()
	return thread


def _disable_core_dumps() -> None:
	try:
		import resource
	except ImportError:  # Windows
		return
	try:
		resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
	except (ValueError, OSError):
		pass


def _private_stdout() -> int:
	"""Keep a private handle on stdout and point fd 1 at the null device.

	Anything else that writes to fd 1 (Tcl, Tk, a stray print) then cannot add a
	line to the reply channel.
	"""
	reply_fd = os.dup(1)
	null_fd = os.open(os.devnull, os.O_WRONLY)
	try:
		os.dup2(null_fd, 1)
	finally:
		os.close(null_fd)
	return reply_fd


def _write_all(fd: int, data: bytes) -> None:
	view = memoryview(data)
	while view:
		written = os.write(fd, view)
		view = view[written:]


def _show_dialog(request: dict) -> dict:
	kind = request["kind"]
	try:
		import tkinter
	except ImportError:
		return make_reply(kind, "unavailable", cause="tk_import_failed")
	try:
		root = tkinter.Tk()
	except tkinter.TclError:
		return make_reply(kind, "unavailable", cause="tk_init_failed")

	answer = []

	def on_result(reply: dict) -> None:
		if not answer:
			answer.append(reply)
			root.quit()

	try:
		if kind == "consent":
			build_consent_window(consent_layout(), request, root, on_result)
		else:
			build_pin_window(request, root, on_result)
		# A window that refused to show itself (host too wide) has already answered;
		# mainloop() would reset Tk's quit flag and wait for a window that never comes.
		if not answer:
			root.mainloop()
	finally:
		try:
			root.destroy()
		except Exception:
			pass
	if not answer:
		raise RuntimeError("the dialog closed without an answer")
	return answer[0]


def main() -> None:
	"""Child entry point.  Never returns: always ends in os._exit."""
	_disable_core_dumps()
	try:
		line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
		request = validate_request(line)
	except Exception:
		os._exit(EXIT_REQUEST_INVALID)
	try:
		reply_fd = _private_stdout()
		gate = ReplyGate()
		# Started only after the request line is consumed, so the two never compete
		# for stdin.
		watch_eof(sys.stdin.buffer, gate)
		reply = _show_dialog(request)
		data = encode_reply(reply)
		reply = None
		with gate.lock:
			gate.written = True
		_write_all(reply_fd, data)
		data = None
	except BaseException:
		# No traceback: it could carry dialog state, and stdout is the reply channel.
		os._exit(EXIT_INTERNAL)
	os._exit(0)


if __name__ == "__main__":
	if sys.flags.ignore_environment != 1:
		# Spawned without -I: PYTHON* variables could have changed what was imported.
		os._exit(EXIT_NOT_ISOLATED)
	main()
