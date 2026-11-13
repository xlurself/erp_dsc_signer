"""Tests for the dialog child process (spec 001 sections 2, 3.1, 6, 9, 10).

Most tests need no display: validation, replies and decisions are pure, and the
end-to-end tests run the REAL child (`runpy` as __main__, under -I) in a subprocess
with a fake `tkinter` module that mimics Tk's disabled-widget semantics.  Tests that
open real Tk windows run only with ERP_DSC_UI_TESTS=1.
"""

import ast
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child as dc


TESTS_DIR = Path(__file__).resolve().parent
LOCAL_SIGNER = TESTS_DIR.parent
CHILD = LOCAL_SIGNER / "erp_dsc_local" / "dialog_child.py"
UI_TESTS = os.environ.get("ERP_DSC_UI_TESTS") == "1"


def _stdin_is_pipe_or_tty() -> bool:
	"""In-process Tk() in the venv Python fails ("Cannot find a usable init.tcl") when
	stdin is /dev/null, so the in-process window tests need a pipe or a terminal."""
	try:
		return stat.S_ISFIFO(os.fstat(0).st_mode) or os.isatty(0)
	except OSError:
		return False


STDIN_SKIP = (
	"in-process Tk needs stdin to be a pipe or a terminal (with /dev/null Tk() fails: "
	"'Cannot find a usable init.tcl'); run as: echo | ERP_DSC_UI_TESTS=1 python -m unittest ..."
)
ORIGIN = "https://erp.example.com"
PIN_SENTINEL = "PIN-SENTINEL-4731"

# One or more sentinels per refused Unicode category; test_sentinel_table_covers_*
# proves each sentinel really is in the category it claims.
SENTINELS = {
	"newline": ("\n", "Cc"),
	"nul": ("\x00", "Cc"),
	"escape": ("\x1b", "Cc"),
	"c1_next_line": ("\x85", "Cc"),
	"rtl_override_U+202E": ("‮", "Cf"),
	"arabic_letter_mark_U+061C": ("؜", "Cf"),
	"soft_hyphen_U+00AD": ("­", "Cf"),
	"zero_width_space": ("​", "Cf"),
	"bom": ("﻿", "Cf"),
	"lone_surrogate": ("\ud800", "Cs"),
	"private_use": ("", "Co"),
	"noncharacter": ("￿", "Cn"),
	"line_separator": (" ", "Zl"),
	"paragraph_separator": (" ", "Zp"),
}


def make_request(**overrides):
	request = {
		"v": 1,
		"kind": "pin",
		"origin": ORIGIN,
		"claims": [],
		"warnings": [],
		"final_try": False,
		"timeout": dc.DEFAULT_DIALOG_SECONDS,
	}
	request.update(overrides)
	return request


# --------------------------------------------------------------------------------------
# Fake tkinter, installed in the CHILD subprocess by the end-to-end tests.
# --------------------------------------------------------------------------------------
FAKE_SCREEN_WIDTH = 1440


def fake_text_width(text, size):
	"""The fake `tkinter.font.Font.measure`: a monospaced font, 0.6 em per character."""
	return len(text) * size * 6 // 10


def install_fake_tkinter(script, mode="ok", trace_path=None, screen_width=FAKE_SCREEN_WIDTH):
	"""Register a fake `tkinter` (and `tkinter.font`) in sys.modules whose mainloop plays `script`.

	Like real Tk, a widget whose state is "disabled" ignores invoke() and insert().
	Fonts measure with fake_text_width and the screen is `screen_width` pixels wide.
	mode: "ok" | "missing" (import fails) | "init_fails" (Tk() raises TclError) |
	"noisy" (Tk() writes to fd 1 and to sys.stdout) | "premapped" (the root is
	already mapped when Tk() returns and sends no <Map>, as Tk 9 does on macOS).
	"""
	if mode == "missing":
		sys.modules["tkinter"] = None
		return

	def log(entry):
		if trace_path:
			with open(trace_path, "a", encoding="utf-8") as handle:
				handle.write(json.dumps(entry) + "\n")

	class TclError(Exception):
		pass

	class Event:
		def __init__(self, widget):
			self.widget = widget

	class Widget:
		counter = [0]

		def __init__(self, master=None, **kw):
			Widget.counter[0] += 1
			self._name = ".!w%d" % Widget.counter[0]
			self.app = master.app
			self.kw = dict(kw)
			self.bindings = {}
			self.value = ""
			self.placed = False
			self.app.widgets.append(self)

		def __str__(self):
			return self._name

		def pack(self, **kw):
			pass

		def place(self, **kw):
			self.placed = True

		def place_forget(self):
			self.placed = False

		def configure(self, **kw):
			self.kw.update(kw)

		config = configure

		def cget(self, key):
			return self.kw.get(key, "")

		def bind(self, sequence, func=None, add=None):
			self.bindings[sequence] = func

		def focus_set(self):
			self.app.focus_widget = self

		def winfo_toplevel(self):
			return self.app

		def disabled(self):
			return self.kw.get("state") == "disabled"

	class Frame(Widget):
		pass

	class Label(Widget):
		def __init__(self, master=None, **kw):
			super().__init__(master, **kw)
			if hasattr(self, "invoke"):
				# A button drawn as a Label (the PIN window's flat buttons) is a button.
				log({"button": kw.get("text")})
			else:
				log({"label": kw.get("text"), "wraplength": kw.get("wraplength", 0), "font": kw.get("font")})

		def configure(self, **kw):
			if "text" in kw and kw["text"] != self.kw.get("text"):
				log({"relabel": kw["text"]})
			super().configure(**kw)

		config = configure

	class Button(Widget):
		def __init__(self, master=None, **kw):
			super().__init__(master, **kw)
			log({"button": kw.get("text")})

		def invoke(self):
			if not self.disabled() and self.kw.get("command"):
				self.kw["command"]()

	class Checkbutton(Widget):
		def invoke(self):
			if self.disabled():
				return
			variable = self.kw["variable"]
			variable.set(not variable.get())
			if self.kw.get("command"):
				self.kw["command"]()

	class Entry(Widget):
		def get(self):
			return self.value

		def insert(self, index, text):
			if not self.disabled():
				self.value += text

		def delete(self, first, last=None):
			if not self.disabled():
				self.value = ""

	class BooleanVar:
		def __init__(self, master=None, value=False):
			self._value = bool(value)

		def get(self):
			return self._value

		def set(self, value):
			self._value = bool(value)

	class Tk(Widget):
		def __init__(self):
			if mode == "init_fails":
				raise TclError("no display name and no $DISPLAY environment variable")
			self.app = self
			self._name = "."
			self.kw = {}
			self.bindings = {}
			self.widgets = []
			self.protocols = {}
			self.afters = {}
			self.now = 0
			self.sequence = 0
			self.quitted = False
			self.focus_widget = None
			self.mapped = mode == "premapped"
			if mode == "noisy":
				os.write(1, b"tk noise on fd 1\n")
				print("python noise on sys.stdout")
				sys.stdout.flush()

		def title(self, text):
			log({"title": text})

		def resizable(self, *args):
			pass

		def minsize(self, *args):
			self.min_size = args

		def attributes(self, *args):
			pass

		def lift(self):
			pass

		def protocol(self, name, func):
			self.protocols[name] = func

		def after(self, ms, func):
			self.sequence += 1
			ident = "after#%d" % self.sequence
			self.afters[ident] = (self.now + ms, self.sequence, func)
			log({"after": ms})
			return ident

		def after_idle(self, func):
			return self.after(0, func)

		def after_cancel(self, ident):
			self.afters.pop(ident, None)

		def focus_get(self):
			return None

		def winfo_ismapped(self):
			return int(self.mapped)

		def winfo_screenwidth(self):
			return screen_width

		def quit(self):
			self.quitted = True

		def destroy(self):
			log({"destroyed": True})

		def advance(self, ms):
			target = self.now + ms
			while not self.quitted:
				due = sorted((when, seq, ident) for ident, (when, seq, _f) in self.afters.items() if when <= target)
				if not due:
					break
				when, _seq, ident = due[0]
				func = self.afters.pop(ident)[2]
				self.now = when
				func()
			self.now = max(self.now, target)

		def fire(self, sequence, widget=None):
			func = self.bindings.get(sequence)
			if func is not None:
				func(Event(widget or self))

		def find(self, cls, text=None):
			for widget in self.widgets:
				if type(widget) is cls and (text is None or widget.kw.get("text") == text):
					return widget
			raise AssertionError("fake tk: no %s %r" % (cls.__name__, text))

		def find_button(self, text):
			"""A native Button, or a button drawn as a Label (it has invoke()), by its text."""
			for widget in self.widgets:
				if (type(widget) is Button or (isinstance(widget, Label) and hasattr(widget, "invoke"))) and widget.kw.get("text") == text:
					return widget
			raise AssertionError("fake tk: no button %r" % (text,))

		def mainloop(self):
			for step in script:
				if self.quitted:
					return
				action, *args = step
				if action == "map":
					self.mapped = True
					self.fire("<Map>")
				elif action == "advance":
					self.advance(args[0])
				elif action == "button":
					self.find_button(args[0]).invoke()
				elif action == "tick":
					self.find(Checkbutton).invoke()
				elif action == "escape":
					self.fire("<Escape>")
				elif action == "close":
					self.protocols["WM_DELETE_WINDOW"]()
				elif action == "focus_in":
					self.fire("<FocusIn>")
				elif action == "focus_out":
					# focus_get() is None here: focus left for another application.
					self.fire("<FocusOut>")
				elif action == "focus_in_child":
					# FocusIn reported for one of the window's widgets, not the toplevel.
					self.fire("<FocusIn>", self.find({"Entry": Entry, "Button": Button}[args[0]]))
				elif action == "click":
					self.fire("<ButtonPress>")
				elif action == "type":
					self.find(Entry).insert("end", args[0])
				elif action == "return":
					entry = self.find(Entry)
					entry.bindings["<Return>"](Event(entry))
				elif action == "hang":
					threading.Event().wait()
				else:
					raise AssertionError("fake tk: unknown step %r" % (action,))

	class Font:
		def __init__(self, root=None, family=None, size=None, weight=None, **kw):
			self.size = size

		def measure(self, text):
			return fake_text_width(text, self.size)

	module = types.ModuleType("tkinter")
	for value in (TclError, Tk, Frame, Label, Button, Checkbutton, Entry, BooleanVar):
		setattr(module, value.__name__, value)
	font_module = types.ModuleType("tkinter.font")
	font_module.Font = Font
	# Tk always knows Helvetica, Courier and Times; Inter is not installed here.
	font_module.families = lambda root=None, displayof=None: ("Courier", "Helvetica", "Times")
	module.font = font_module
	sys.modules["tkinter"] = module
	sys.modules["tkinter.font"] = font_module


def install_boot_spy(trace_path):
	"""Record, in the CHILD, every setrlimit call and the moment stdin is first read.

	The stdin record carries the RLIMIT_CORE in force at that moment, so a test can
	prove core dumps were off BEFORE any request byte (or PIN) entered the process.
	"""
	import resource

	def log(entry):
		with open(trace_path, "a", encoding="utf-8") as handle:
			handle.write(json.dumps(entry) + "\n")

	real_setrlimit = resource.setrlimit

	def setrlimit(which, limits):
		log({"setrlimit": [which, list(limits)]})
		return real_setrlimit(which, limits)

	class SpyBuffer:
		def __init__(self, raw):
			self.raw = raw

		def readline(self, *args):
			log({"stdin_read": list(resource.getrlimit(resource.RLIMIT_CORE))})
			return self.raw.readline(*args)

		def read(self, *args):
			return self.raw.read(*args)

	resource.setrlimit = setrlimit
	sys.stdin = types.SimpleNamespace(buffer=SpyBuffer(sys.stdin.buffer))


BOOT = (
	"import sys\n"
	"sys.path[:0] = [{tests!r}, {local_signer!r}]\n"
	"import test_dialog_child as t\n"
	"t.install_fake_tkinter({script!r}, {mode!r}, {trace!r}, {screen!r})\n"
	"{spy}"
	"import runpy\n"
	"runpy.run_path({child!r}, run_name='__main__')\n"
)


class ChildRun:
	def __init__(self, returncode, stdout, stderr, trace, seconds_after_close=None):
		self.returncode = returncode
		self.stdout = stdout
		self.stderr = stderr
		self.trace = trace
		self.seconds_after_close = seconds_after_close

	def reply(self):
		assert self.stdout.endswith(b"\n") and self.stdout.count(b"\n") == 1, self.stdout
		return json.loads(self.stdout)

	def labels(self):
		return [entry["label"] for entry in self.trace if "label" in entry]

	def wraplengths(self):
		return {entry["label"]: entry["wraplength"] for entry in self.trace if "label" in entry}

	def afters(self):
		return [entry["after"] for entry in self.trace if "after" in entry]

	def fonts(self):
		return {entry["label"]: entry["font"] for entry in self.trace if "label" in entry}

	def buttons(self):
		return [entry["button"] for entry in self.trace if "button" in entry]

	def relabels(self):
		return [entry["relabel"] for entry in self.trace if "relabel" in entry]


def run_child(
	request=None,
	script=(),
	*,
	mode="ok",
	isolated=True,
	raw=None,
	keep_open=True,
	close_after=None,
	wait=20,
	spy=False,
	screen=FAKE_SCREEN_WIDTH,
):
	"""Run the real child as __main__ with a fake tkinter; behave like the parent.

	stdin stays open until the child exits (the lifeline), unless `keep_open` is
	False or `close_after` seconds elapse.  `screen` is the fake screen width.
	"""
	with tempfile.TemporaryDirectory() as tmp:
		trace_path = os.path.join(tmp, "trace.jsonl")
		code = BOOT.format(
			tests=str(TESTS_DIR),
			local_signer=str(LOCAL_SIGNER),
			script=list(script),
			mode=mode,
			trace=trace_path,
			screen=screen,
			child=str(CHILD),
			spy="t.install_boot_spy(%r)\n" % trace_path if spy else "",
		)
		argv = [sys.executable] + (["-I"] if isolated else []) + ["-c", code]
		with tempfile.TemporaryFile() as err:
			process = subprocess.Popen(
				argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, cwd=tmp
			)
			killer = threading.Timer(wait, process.kill)
			killer.start()
			seconds_after_close = None
			try:
				data = raw if raw is not None else dc.encode_request(request)
				try:
					process.stdin.write(data)
					process.stdin.flush()
				except BrokenPipeError:
					pass
				if not keep_open:
					process.stdin.close()
				if close_after is not None:
					time.sleep(close_after)
					closed_at = time.monotonic()
					process.stdin.close()
					process.wait()
					seconds_after_close = time.monotonic() - closed_at
				stdout = process.stdout.read()
				process.wait()
			finally:
				killer.cancel()
				for stream in (process.stdin, process.stdout):
					try:
						stream.close()
					except Exception:
						pass
			err.seek(0)
			stderr = err.read()
		trace = []
		if os.path.exists(trace_path):
			with open(trace_path, encoding="utf-8") as handle:
				trace = [json.loads(line) for line in handle]
	return ChildRun(process.returncode, stdout, stderr, trace, seconds_after_close)


# --------------------------------------------------------------------------------------
class TestConstants(unittest.TestCase):
	def test_spec_section_2_values(self):
		self.assertEqual(dc.MIN_DIALOG_SECONDS, 5)
		self.assertEqual(dc.MAX_DIALOG_SECONDS, 300)
		self.assertEqual(dc.DEFAULT_DIALOG_SECONDS, 120)
		self.assertEqual(dc.INPUT_GUARD_SECONDS, 1.5)
		self.assertEqual(dc.MAX_REQUEST_BYTES, 8192)
		self.assertEqual(dc.MAX_REPLY_BYTES, 4096)
		self.assertEqual(dc.MAX_ORIGIN_CHARS, 120)
		self.assertEqual(dc.MAX_CLAIM_CHARS, 140)
		self.assertEqual(dc.EXIT_REQUEST_INVALID, 65)


class TestValidateRequest(unittest.TestCase):
	def assertInvalid(self, request):
		with self.assertRaises(dc.InvalidRequest):
			dc.validate_request(request)

	def test_invalid_request_is_a_value_error(self):
		self.assertTrue(issubclass(dc.InvalidRequest, ValueError))

	def test_valid_requests_round_trip_through_the_wire_bytes(self):
		for kind in dc.KINDS:
			request = make_request(kind=kind, claims=["Site: Acme"], warnings=["A warning."], final_try=kind == "pin")
			clean = dc.validate_request(request)
			self.assertEqual(clean, request)
			line = dc.encode_request(request)
			self.assertEqual(line, json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n")
			self.assertEqual(line.count(b"\n"), 1)
			self.assertEqual(dc.validate_request(line), clean)

	def test_sentinel_table_covers_every_refused_category(self):
		for name, (char, category) in SENTINELS.items():
			self.assertEqual(unicodedata.category(char), category, name)
		self.assertEqual({category for _c, category in SENTINELS.values()}, set(dc.UNREADABLE_CATEGORIES))
		self.assertEqual(set(dc.UNREADABLE_CATEGORIES), {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

	def test_origin_with_any_unreadable_character_is_refused_not_altered(self):
		for name, (char, _category) in SENTINELS.items():
			with self.subTest(name):
				self.assertInvalid(make_request(origin="https://erp" + char + ".example.com"))

	def test_claim_with_any_unreadable_character_becomes_a_visible_placeholder(self):
		for name, (char, _category) in SENTINELS.items():
			with self.subTest(name):
				claim = "Acme" + char + "Corp"
				clean = dc.validate_request(make_request(claims=["fine", claim]))
				self.assertEqual(clean["claims"], ["fine", dc.CLAIM_UNREADABLE])
				line = dc.encode_request(make_request(claims=["fine", claim]))
				self.assertNotIn(b"Acme", line)

	# Invisible fillers the category rule alone lets through (review finding).
	SPEC_FILLERS = {
		"ㅤ": "Lo",
		"ᅟ": "Lo",
		"ᅠ": "Lo",
		"ﾠ": "Lo",
		"⠀": "So",
		"͏": "Mn",
		"᠎": None,  # Cf in current Unicode, Zs in older tables: refused either way
		"឴": "Mn",
		"឵": "Mn",
		"\N{KHITAN SMALL SCRIPT FILLER}": "Mn",
		"\N{MUSICAL SYMBOL NULL NOTEHEAD}": "So",
	}
	SPACES = [" ", " ", *[chr(cp) for cp in range(0x2000, 0x200B)], " ", " ", "　"]

	def assertUnreadableClaim(self, claim):
		self.assertEqual(dc.validate_request(make_request(claims=[claim]))["claims"], [dc.CLAIM_UNREADABLE])
		self.assertEqual(dc.clean_claim(claim), dc.CLAIM_UNREADABLE, "pairing.py's alias applies the same rule")

	def test_filler_set_is_exactly_the_spec_list(self):
		self.assertEqual(set(dc.INVISIBLE_FILLERS), set(self.SPEC_FILLERS))
		for char, category in self.SPEC_FILLERS.items():
			if category is not None:
				self.assertEqual(unicodedata.category(char), category, "U+%04X" % ord(char))
		self.assertIs(dc.clean_claim, dc._clean_claim)

	def test_invisible_fillers_make_a_claim_unreadable(self):
		for char in self.SPEC_FILLERS:
			with self.subTest("U+%04X" % ord(char)):
				# The review's exploit: a run of fillers pushes the real text out of sight.
				self.assertUnreadableClaim((char * 60 + "Verified ERP: erp.mycompany.com")[: dc.MAX_CLAIM_CHARS])
				self.assertUnreadableClaim("Acme" + char + "Corp")

	def test_every_space_separator_other_than_u0020_makes_a_claim_unreadable(self):
		every_zs = [chr(cp) for cp in range(sys.maxunicode + 1) if unicodedata.category(chr(cp)) == "Zs"]
		self.assertIn(" ", every_zs)
		# U+00A0 is the one exception: mapped to U+0020 (test_no_break_space_is_an_ordinary_space).
		for char in set(every_zs + self.SPACES) - {" ", "\N{NO-BREAK SPACE}"}:
			with self.subTest("U+%04X" % ord(char)):
				self.assertUnreadableClaim((char * 60 + "Verified ERP: erp.mycompany.com")[: dc.MAX_CLAIM_CHARS])
				self.assertUnreadableClaim("Acme" + char + "Ltd")

	def test_spaces_are_collapsed_and_stripped_and_an_all_space_claim_is_unreadable(self):
		cases = {
			"  Acme    Ltd  ": "Acme Ltd",
			"Acme Ltd": "Acme Ltd",
			" " * 60 + "Verified ERP: erp.mycompany.com": "Verified ERP: erp.mycompany.com",
			" ": dc.CLAIM_UNREADABLE,
			" " * dc.MAX_CLAIM_CHARS: dc.CLAIM_UNREADABLE,
			"": "",  # nothing was sent: stays empty (pairing keeps a missing claim empty)
		}
		for claim, expected in cases.items():
			with self.subTest(claim=claim[:20]):
				self.assertEqual(dc.validate_request(make_request(claims=[claim]))["claims"], [expected])
				self.assertEqual(dc.clean_claim(claim), expected)

	def test_combining_marks_stay_allowed(self):
		for claim in ("हिंदी", "தமிழ்நாடு", "ગુજરાત", "café", "Acme Ltd — Mumbai (हिंदी)"):
			with self.subTest(claim=claim):
				self.assertEqual(dc.validate_request(make_request(claims=[claim]))["claims"], [claim])

	def assertClaim(self, claim, expected):
		self.assertEqual(dc.validate_request(make_request(claims=[claim]))["claims"], [expected])
		self.assertEqual(dc.clean_claim(claim), expected, "pairing.py's alias applies the same rule")

	def test_no_break_space_is_an_ordinary_space(self):
		nbsp = "\N{NO-BREAK SPACE}"
		cases = {
			"Acme" + nbsp + "Pvt" + nbsp + "Ltd": "Acme Pvt Ltd",
			"Acme" + nbsp + " " + nbsp + "Ltd": "Acme Ltd",  # mapped BEFORE runs are collapsed
			nbsp + "Acme Ltd" + nbsp: "Acme Ltd",  # and before the ends are stripped
			nbsp * 3: dc.CLAIM_UNREADABLE,  # all space: unreadable, like "   "
			"\N{DEVANAGARI LETTER MA}\N{DEVANAGARI VOWEL SIGN AA}" + nbsp + "Ltd": "\N{DEVANAGARI LETTER MA}\N{DEVANAGARI VOWEL SIGN AA} Ltd",
		}
		for claim, expected in cases.items():
			with self.subTest(claim=claim.encode("unicode_escape")):
				self.assertClaim(claim, expected)
		# Only U+00A0: the narrow no-break space and the other Zs stay unreadable.
		self.assertClaim("Acme\N{NARROW NO-BREAK SPACE}Ltd", dc.CLAIM_UNREADABLE)

	ZWJ = "\N{ZERO WIDTH JOINER}"
	ZWNJ = "\N{ZERO WIDTH NON-JOINER}"
	# Real Indic spellings that need a joiner next to a virama (canonical combining class 9).
	INDIC_JOINER_SAMPLES = {
		# Marathi eyelash ra: RA, VIRAMA, ZWJ, YA (+ "le"), as in many Marathi names.
		"marathi": "\N{DEVANAGARI LETTER RA}\N{DEVANAGARI SIGN VIRAMA}\N{ZERO WIDTH JOINER}\N{DEVANAGARI LETTER YA}\N{DEVANAGARI VOWEL SIGN AA}\N{DEVANAGARI LETTER LA}\N{DEVANAGARI VOWEL SIGN E} Industries",
		# Bengali ra + ya-phala: RA, ZWJ, VIRAMA, YA (the joiner comes BEFORE the virama), "RAB".
		"bengali": "\N{BENGALI LETTER RA}\N{ZERO WIDTH JOINER}\N{BENGALI SIGN VIRAMA}\N{BENGALI LETTER YA}\N{BENGALI VOWEL SIGN AA}\N{BENGALI LETTER BA} Traders",
		# Devanagari half form (ZWJ) and explicit halant (ZWNJ) after KA + VIRAMA.
		"devanagari_zwj": "\N{DEVANAGARI LETTER KA}\N{DEVANAGARI SIGN VIRAMA}\N{ZERO WIDTH JOINER}\N{DEVANAGARI LETTER SSA}",
		"devanagari_zwnj": "\N{DEVANAGARI LETTER KA}\N{DEVANAGARI SIGN VIRAMA}\N{ZERO WIDTH NON-JOINER}\N{DEVANAGARI LETTER SSA}",
		# Tamil KA + VIRAMA + ZWNJ + SSA: stops the KSSA ligature.
		"tamil": "\N{TAMIL LETTER KA}\N{TAMIL SIGN VIRAMA}\N{ZERO WIDTH NON-JOINER}\N{TAMIL LETTER SSA} Exports",
		# A joiner may END a claim when a virama precedes it.
		"trailing": "Acme \N{DEVANAGARI LETTER NA}\N{DEVANAGARI SIGN VIRAMA}\N{ZERO WIDTH JOINER}",
	}

	def test_joiners_next_to_a_virama_are_kept(self):
		self.assertEqual(unicodedata.category(self.ZWJ), "Cf")
		self.assertEqual(unicodedata.category(self.ZWNJ), "Cf")
		for name, claim in self.INDIC_JOINER_SAMPLES.items():
			with self.subTest(name):
				self.assertTrue(self.ZWJ in claim or self.ZWNJ in claim)
				self.assertClaim(claim, claim)

	def test_joiners_anywhere_else_and_every_other_cf_stay_unreadable(self):
		ka_virama = "\N{DEVANAGARI LETTER KA}\N{DEVANAGARI SIGN VIRAMA}"
		cases = {
			"between latin letters": "Acme" + self.ZWJ + "Corp",
			"zwnj between latin letters": "Acme" + self.ZWNJ + "Corp",
			"first": self.ZWJ + "Acme",
			"last without a virama": "Acme" + self.ZWJ,
			"emoji sequence": "\N{MAN}" + self.ZWJ + "\N{WOMAN}",
			"two joiners after a virama": ka_virama + self.ZWJ + self.ZWJ + "\N{DEVANAGARI LETTER SSA}",
			"a run of joiners": ka_virama + self.ZWJ * 60 + "Verified ERP",
			"space between virama and joiner": ka_virama + " " + self.ZWJ + "x",
			"no-break space between virama and joiner": ka_virama + "\N{NO-BREAK SPACE}" + self.ZWJ + "x",
			"zwnj before a virama": "\N{BENGALI LETTER RA}" + self.ZWNJ + "\N{BENGALI SIGN VIRAMA}\N{BENGALI LETTER YA}",
			"other Cf after a virama": ka_virama + "\N{LEFT-TO-RIGHT MARK}",
			"rtl override after a virama": ka_virama + "\N{RIGHT-TO-LEFT OVERRIDE}x",
			"zero width space after a virama": ka_virama + "\N{ZERO WIDTH SPACE}x",
		}
		for name, claim in cases.items():
			with self.subTest(name):
				self.assertClaim(claim, dc.CLAIM_UNREADABLE)

	def test_clean_claim_is_idempotent(self):
		nbsp = "\N{NO-BREAK SPACE}"
		samples = [
			*self.INDIC_JOINER_SAMPLES.values(),
			"  Acme    Ltd  ",
			nbsp + "Acme" + nbsp + nbsp + "Ltd" + nbsp,
			"x" * dc.MAX_CLAIM_CHARS,
			"x" * (dc.MAX_CLAIM_CHARS + 1),
			"Acme" + self.ZWJ + "Corp",
			*("Acme" + char + "Corp" for char in self.SPEC_FILLERS),
			"",
			" ",
			dc.CLAIM_UNREADABLE,
			dc.CLAIM_TOO_LONG,
		]
		for claim in samples:
			with self.subTest(claim=claim.encode("unicode_escape")[:40]):
				once = dc.clean_claim(claim)
				self.assertEqual(dc.clean_claim(once), once)

	def test_warning_with_any_unreadable_character_is_refused(self):
		for name, (char, _category) in SENTINELS.items():
			with self.subTest(name):
				self.assertInvalid(make_request(warnings=["Careful" + char]))

	def test_origin_length_limit_is_refusal_never_truncation(self):
		at_limit = "https://" + "a" * (dc.MAX_ORIGIN_CHARS - len("https://"))
		self.assertEqual(dc.validate_request(make_request(origin=at_limit))["origin"], at_limit)
		self.assertInvalid(make_request(origin=at_limit + "b"))

	def test_a_hostile_253_character_host_is_refused(self):
		# A DNS name can be 253 characters; its tail names the real (attacker) domain.
		host = ("erp.mycompany.com." + "a" * 60 + ".") * 3
		host = (host + "x" * 253)[:249] + ".com"
		self.assertEqual(len(host), 253)
		for kind in dc.KINDS:
			with self.subTest(kind=kind):
				self.assertInvalid(make_request(kind=kind, origin="https://" + host))
				self.assertInvalid(dc.encode_request(make_request(kind=kind)).replace(ORIGIN.encode(), b"https://" + host.encode()))

	def test_claim_length_limit_is_a_placeholder_never_truncation(self):
		at_limit = "x" * dc.MAX_CLAIM_CHARS
		clean = dc.validate_request(make_request(claims=[at_limit, at_limit + "y"]))
		self.assertEqual(clean["claims"], [at_limit, dc.CLAIM_TOO_LONG])

	def test_wrong_types_are_refused(self):
		cases = {
			"v bool": {"v": True},
			"v float": {"v": 1.0},
			"v str": {"v": "1"},
			"v 2": {"v": 2},
			"kind upper": {"kind": "PIN"},
			"kind int": {"kind": 1},
			"origin none": {"origin": None},
			"origin bytes": {"origin": b"https://erp.example.com"},
			"origin empty": {"origin": ""},
			"claims str": {"claims": "x"},
			"claims tuple": {"claims": ("x",)},
			"claim int": {"claims": [1]},
			"claim none": {"claims": [None]},
			"warnings str": {"warnings": "x"},
			"warning none": {"warnings": [None]},
			"warning empty": {"warnings": [""]},
			"final_try int": {"final_try": 1},
			"final_try zero": {"final_try": 0},
			"final_try str": {"final_try": "true"},
			"final_try none": {"final_try": None},
			"timeout true": {"timeout": True},
			"timeout false": {"timeout": False},
			"timeout float": {"timeout": 60.0},
			"timeout str": {"timeout": "60"},
			"timeout none": {"timeout": None},
		}
		for name, override in cases.items():
			with self.subTest(name):
				self.assertInvalid(make_request(**override))

	def test_missing_or_extra_keys_are_refused(self):
		for key in dc.REQUEST_KEYS:
			request = make_request()
			del request[key]
			with self.subTest(missing=key):
				self.assertInvalid(request)
		self.assertInvalid(make_request(pin="1234"))
		self.assertInvalid(["not", "an", "object"])
		self.assertInvalid("a string")

	def test_timeout_is_clamped(self):
		for given, expected in ((-10, 5), (0, 5), (5, 5), (60, 60), (300, 300), (10_000, 300)):
			with self.subTest(given=given):
				self.assertEqual(dc.validate_request(make_request(timeout=given))["timeout"], expected)

	def test_oversize_request_is_refused(self):
		claims = ["c" * dc.MAX_CLAIM_CHARS] * 60  # > 8192 bytes once encoded
		self.assertInvalid(make_request(claims=claims))
		self.assertInvalid(b"{" + b" " * dc.MAX_REQUEST_BYTES + b"}\n")

	def test_request_at_the_byte_limit_is_accepted_and_one_over_is_refused(self):
		base = len(dc.encode_request(make_request(warnings=["w"])))
		padding = dc.MAX_REQUEST_BYTES - base
		fits = make_request(warnings=["w" + "x" * padding])
		self.assertEqual(len(dc.encode_request(fits)), dc.MAX_REQUEST_BYTES)
		self.assertInvalid(make_request(warnings=["w" + "x" * (padding + 1)]))

	def test_line_framing_and_json_shape_are_enforced_on_bytes(self):
		good = dc.encode_request(make_request())
		cases = {
			"no newline": good[:-1],
			"two lines": good + good,
			"raw newline inside": good[:1] + b"\n" + good[1:],
			"carriage return": good[:1] + b"\r" + good[1:],
			"not utf-8": b'{"v":1,"kind":"pin","origin":"\xff"}\n',
			"not json": b"hello\n",
			"nan": good.replace(b'"timeout": 120', b'"timeout": NaN'),
			"duplicate key": good[:-2] + b', "v": 1}\n',
			"top-level list": b"[1]\n",
			"deep nesting": b"[" * 4000 + b"]" * 4000 + b"\n",
			"escaped lone surrogate origin": good.replace(ORIGIN.encode(), b"https://erp\\ud800.example.com"),
		}
		for name, data in cases.items():
			with self.subTest(name):
				self.assertInvalid(data)

	def test_escaped_lone_surrogate_in_a_claim_is_replaced(self):
		line = dc.encode_request(make_request(claims=["SENTINEL"])).replace(b"SENTINEL", b"x\\ud800y")
		self.assertEqual(dc.validate_request(line)["claims"], [dc.CLAIM_UNREADABLE])

	def test_error_carries_no_request_text(self):
		secret = "SECRET-CLAIM-TEXT"
		try:
			dc.validate_request(make_request(origin="https://" + secret + "‮"))
		except dc.InvalidRequest as exc:
			self.assertNotIn(secret, str(exc))
			self.assertNotIn(secret, repr(exc.args))
		else:
			self.fail("not refused")
		try:
			dc.validate_request(b'{"v":1,"origin":"' + secret.encode() + b'"\n')
		except dc.InvalidRequest as exc:
			self.assertNotIn(secret, str(exc))
			self.assertIsNone(exc.__cause__)
			self.assertTrue(exc.__suppress_context__)
		else:
			self.fail("not refused")

	def test_input_is_not_modified(self):
		request = make_request(claims=["x" * 500, "ok‮"], timeout=1)
		snapshot = json.loads(json.dumps(request))
		dc.validate_request(request)
		self.assertEqual(request, snapshot)


class TestReplies(unittest.TestCase):
	def test_every_allowed_reply(self):
		self.assertEqual(
			dc.make_reply("pin", "entered", value="1234"),
			{"v": 1, "kind": "pin", "result": "entered", "value": "1234"},
		)
		for result in ("cancelled", "timeout"):
			self.assertEqual(dc.make_reply("pin", result), {"v": 1, "kind": "pin", "result": result})
		for result in ("allow", "deny", "timeout"):
			self.assertEqual(dc.make_reply("consent", result), {"v": 1, "kind": "consent", "result": result})
		for kind in dc.KINDS:
			for cause in ("tk_import_failed", "tk_init_failed"):
				self.assertEqual(
					dc.make_reply(kind, "unavailable", cause=cause),
					{"v": 1, "kind": kind, "result": "unavailable", "cause": cause},
				)

	def test_replies_outside_the_schema_are_refused(self):
		bad = [
			("pin", "entered", {}),
			("pin", "entered", {"value": ""}),
			("pin", "entered", {"value": 1234}),
			("pin", "cancelled", {"value": "1234"}),
			("pin", "allow", {}),
			("consent", "entered", {"value": "1234"}),
			("consent", "allow", {"cause": "tk_init_failed"}),
			("consent", "unavailable", {}),
			("consent", "unavailable", {"cause": "dialog_timeout"}),
			("other", "allow", {}),
		]
		for kind, result, extra in bad:
			with self.subTest(kind=kind, result=result, extra=extra):
				with self.assertRaises(ValueError) as caught:
					dc.make_reply(kind, result, **extra)
				self.assertNotIn("1234", str(caught.exception))

	def test_encoded_reply_is_one_line_and_bounded(self):
		line = dc.encode_reply(dc.make_reply("pin", "entered", value="12\n34"))
		self.assertEqual(line.count(b"\n"), 1)
		self.assertEqual(json.loads(line)["value"], "12\n34")
		with self.assertRaises(ValueError) as caught:
			dc.encode_reply(dc.make_reply("pin", "entered", value=PIN_SENTINEL * 400))
		self.assertNotIn(PIN_SENTINEL, str(caught.exception))


class TestDecisions(unittest.TestCase):
	def test_consent_events(self):
		self.assertEqual(dc.decide("allow"), "allow")
		self.assertEqual(dc.decide("deny"), "deny")
		self.assertEqual(dc.decide("escape"), "deny")
		self.assertEqual(dc.decide("close"), "deny")
		self.assertEqual(dc.decide("timeout"), "timeout")
		self.assertEqual(dc.decide("something-else"), "deny")

	def test_input_guard_makes_only_the_buttons_inert(self):
		self.assertIsNone(dc.decide("allow", guarded=True))
		self.assertIsNone(dc.decide("deny", guarded=True))
		self.assertEqual(dc.decide("escape", guarded=True), "deny")
		self.assertEqual(dc.decide("close", guarded=True), "deny")
		self.assertEqual(dc.decide("timeout", guarded=True), "timeout")

	def test_only_the_allow_event_allows(self):
		allowing = [event for event in ("allow", "deny", "escape", "close", "timeout", "", "space", "return") if dc.decide(event) == "allow"]
		self.assertEqual(allowing, ["allow"])

	def test_pin_outcomes(self):
		self.assertEqual(dc.pin_outcome("ok", "1234"), ("entered", "1234"))
		self.assertEqual(dc.pin_outcome("ok", ""), ("cancelled", None))
		self.assertEqual(dc.pin_outcome("ok", None), ("cancelled", None))
		for event in ("cancel", "escape", "close", "unknown"):
			self.assertEqual(dc.pin_outcome(event, "1234"), ("cancelled", None))
		self.assertEqual(dc.pin_outcome("timeout"), ("timeout", None))

	def test_consent_layout_is_pure_data(self):
		layout = dc.consent_layout()
		self.assertEqual(layout["initial_focus"], "deny")
		self.assertEqual(tuple(layout["tab_order"]), ("deny", "allow"))
		self.assertIsNone(layout["default"])
		self.assertEqual(layout["input_guard_seconds"], dc.INPUT_GUARD_SECONDS)
		self.assertEqual(layout["buttons"], {"deny": "Deny", "allow": "Allow"})
		json.dumps(layout)  # plain data, no widgets or callables
		layout["initial_focus"] = "allow"
		self.assertEqual(dc.consent_layout()["initial_focus"], "deny", "each call returns a fresh copy")

	def test_origin_lines_put_the_whole_host_on_one_unbroken_line(self):
		attack = "https://erp.mycompany.com.ap-south-1-secure-gateway.example"
		cases = {
			ORIGIN: ["https://", "erp.example.com"],
			attack: ["https://", "erp.mycompany.com.ap-south-1-secure-gateway.example"],
			"http://erp.mycompany.com:8443": ["http://", "erp.mycompany.com:8443"],
			"https://" + "x" * (dc.MAX_ORIGIN_CHARS - 8): ["https://", "x" * (dc.MAX_ORIGIN_CHARS - 8)],
			"https://" + ".".join("segment%d" % i for i in range(30)) + ".example.com": None,
			"null": ["null"],
		}
		for origin, expected in cases.items():
			with self.subTest(origin=origin[:40]):
				lines = dc.origin_lines(origin)
				self.assertEqual("".join(lines), origin, "never drops or alters a character")
				if expected is not None:
					self.assertEqual(lines, expected)
				host = origin.partition("://")[2] or origin
				self.assertEqual(lines[-1], host, "the host, with its port, is ONE line")
				for line in lines[1:]:
					self.assertFalse(
						line != host and host.startswith(line),
						"a line other than the scheme is a strict prefix of the host",
					)
		# The review's exact spoof: the victim's host must never stand alone on a line.
		self.assertNotIn("erp.mycompany.com.", dc.origin_lines(attack))
		self.assertNotIn("erp.mycompany.com", dc.origin_lines(attack))


class TestLeafModule(unittest.TestCase):
	FORBIDDEN = {"erp_dsc_local.ui", "erp_dsc_local.pin", "erp_dsc_local.pairing", "erp_dsc_local.service", "erp_dsc_local.token"}

	def run_python(self, code, *, isolated=True):
		argv = [sys.executable] + (["-I"] if isolated else []) + ["-c", code]
		process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tempfile.gettempdir())
		# stdin is kept open: an import that read stdin would block and be killed.
		killer = threading.Timer(20, process.kill)
		killer.start()
		try:
			out = process.stdout.read()
			err = process.stderr.read()
			process.wait()
		finally:
			killer.cancel()
			process.stdin.close()
			process.stdout.close()
			process.stderr.close()
		self.assertEqual(process.returncode, 0, err.decode(errors="replace"))
		return out.decode()

	def test_import_graph_has_no_tk_and_no_package_siblings(self):
		out = self.run_python(
			"import sys, json\n"
			"sys.path.insert(0, %r)\n"
			"before = set(sys.modules)\n"
			"import erp_dsc_local.dialog_child\n"
			"print(json.dumps(sorted(set(sys.modules) - before)))\n" % str(LOCAL_SIGNER)
		)
		new = set(json.loads(out))
		self.assertFalse({m for m in new if m.split(".")[0] in ("tkinter", "_tkinter")}, new)
		self.assertFalse(new & self.FORBIDDEN, new)
		self.assertEqual({m for m in new if m.startswith("erp_dsc_local")}, {"erp_dsc_local", "erp_dsc_local.dialog_child"})

	def test_loads_standalone_from_its_own_path(self):
		out = self.run_python(
			"import importlib.util, sys\n"
			"spec = importlib.util.spec_from_file_location('standalone_child', %r)\n"
			"module = importlib.util.module_from_spec(spec)\n"
			"spec.loader.exec_module(module)\n"
			"print(module.MAX_REQUEST_BYTES, 'tkinter' in sys.modules, any(k.startswith('erp_dsc_local') for k in sys.modules))\n"
			% str(CHILD)
		)
		self.assertEqual(out.split(), ["8192", "False", "False"])

	def test_module_level_is_constants_and_definitions_only(self):
		tree = ast.parse(CHILD.read_text(encoding="utf-8"))
		stdlib = {"json", "os", "sys", "threading", "unicodedata"}
		for node in tree.body:
			if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
				continue
			if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
				continue
			if isinstance(node, ast.ImportFrom):
				self.assertEqual(node.module, "__future__")
				continue
			if isinstance(node, ast.Import):
				self.assertLessEqual({alias.name for alias in node.names}, stdlib)
				continue
			if isinstance(node, (ast.Assign, ast.AnnAssign)):
				for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
					self.assertTrue(isinstance(call.func, ast.Name) and call.func.id == "frozenset", ast.dump(call))
				continue
			if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'":
				continue
			self.fail("unexpected module-level statement at line %d" % node.lineno)

	def test_tk_is_imported_only_inside_functions_and_never_eval(self):
		tree = ast.parse(CHILD.read_text(encoding="utf-8"))
		inside_functions = set()
		for func in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
			inside_functions.update(id(n) for n in ast.walk(func) if n is not func)
		tk_imports = [
			n for n in ast.walk(tree)
			if (isinstance(n, ast.Import) and any(a.name.split(".")[0] in ("tkinter", "_tkinter") for a in n.names))
			or (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in ("tkinter", "_tkinter"))
		]
		self.assertTrue(tk_imports)
		for node in tk_imports:
			self.assertIn(id(node), inside_functions, "tkinter imported at module level (line %d)" % node.lineno)
		for node in ast.walk(tree):
			if id(node) in inside_functions:
				continue
			if isinstance(node, (ast.Name, ast.Attribute)):
				name = node.id if isinstance(node, ast.Name) else node.attr
				self.assertNotIn(name, ("Tk", "Toplevel", "tkinter"), "line %d" % node.lineno)
		evals = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in ("eval", "call", "createcommand")]
		self.assertEqual(evals, [])


class TestWatchEof(unittest.TestCase):
	def start(self, gate):
		read_fd, write_fd = os.pipe()
		stream = os.fdopen(read_fd, "rb")
		self.addCleanup(stream.close)
		calls = []
		thread = dc.watch_eof(stream, gate, exit_process=calls.append)
		return thread, write_fd, calls

	def test_exits_on_eof_when_no_reply_was_written(self):
		thread, write_fd, calls = self.start(dc.ReplyGate())
		self.assertTrue(thread.daemon)
		os.write(write_fd, b"anything the parent sends is discarded\n" * 500)
		time.sleep(0.2)
		self.assertTrue(thread.is_alive(), "must keep running while stdin is open")
		self.assertEqual(calls, [])
		os.close(write_fd)
		thread.join(2)
		self.assertFalse(thread.is_alive())
		self.assertEqual(calls, [dc.EXIT_PARENT_GONE])

	def test_does_not_exit_once_the_reply_is_being_written(self):
		gate = dc.ReplyGate()
		gate.written = True
		thread, write_fd, calls = self.start(gate)
		os.close(write_fd)
		thread.join(2)
		self.assertFalse(thread.is_alive())
		self.assertEqual(calls, [])


class TestChildEndToEnd(unittest.TestCase):
	"""The real main() under -I, with a fake tkinter (no display needed)."""

	AFTER_GUARD = int(dc.INPUT_GUARD_SECONDS * 1000) + 1
	FOREVER = (dc.MAX_DIALOG_SECONDS + 10) * 1000

	def assertReply(self, run, expected):
		self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
		self.assertEqual(run.reply(), expected)
		self.assertEqual(run.stderr, b"", "nothing, and no traceback, on stderr")

	def consent(self, script, **request):
		return run_child(make_request(kind="consent", **request), script)

	def pin(self, script, **request):
		return run_child(make_request(kind="pin", **request), script)

	# consent ------------------------------------------------------------------------
	def test_consent_allow_after_the_guard(self):
		run = self.consent([("map",), ("advance", self.AFTER_GUARD), ("button", "Allow")])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "allow"})

	def test_consent_deny_button(self):
		run = self.consent([("map",), ("advance", self.AFTER_GUARD), ("button", "Deny")])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "deny"})

	def test_consent_escape_during_the_guard_is_deny(self):
		run = self.consent([("map",), ("escape",)])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "deny"})

	def test_consent_close_during_the_guard_is_deny(self):
		run = self.consent([("map",), ("close",)])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "deny"})

	def test_consent_buttons_are_inert_during_the_guard(self):
		run = self.consent([("map",), ("button", "Allow"), ("advance", self.AFTER_GUARD - 10), ("button", "Allow"), ("button", "Deny"), ("escape",)])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "deny"})

	def test_consent_first_activation_does_not_rearm_the_guard(self):
		# The window opens unfocused; the click that activates it (a toplevel FocusIn,
		# then the button press) counts once the guard after the map has run out.
		for activate in ([("focus_in",)], [("focus_in_child", "Button")]):
			with self.subTest(activate=activate):
				run = self.consent([("map",), ("advance", self.AFTER_GUARD), *activate, ("button", "Allow")])
				self.assertReply(run, {"v": 1, "kind": "consent", "result": "allow"})
		# Activation DURING the guard neither extends nor shortens it.
		early = self.consent([("map",), ("focus_in",), ("button", "Allow"), ("advance", self.AFTER_GUARD - 10), ("button", "Allow"), ("escape",)])
		self.assertReply(early, {"v": 1, "kind": "consent", "result": "deny"})
		after = self.consent([("map",), ("focus_in",), ("advance", self.AFTER_GUARD), ("button", "Allow")])
		self.assertReply(after, {"v": 1, "kind": "consent", "result": "allow"})

	def test_consent_focus_returning_from_outside_rearms_the_guard(self):
		settled = [("map",), ("advance", self.AFTER_GUARD), ("focus_in",), ("advance", self.AFTER_GUARD)]
		back = settled + [("focus_out",), ("advance", 0), ("focus_in",)]
		inert = self.consent(back + [("button", "Allow"), ("escape",)])
		self.assertReply(inert, {"v": 1, "kind": "consent", "result": "deny"})
		later = self.consent(back + [("advance", self.AFTER_GUARD), ("button", "Allow")])
		self.assertReply(later, {"v": 1, "kind": "consent", "result": "allow"})
		# A second FocusIn with no FocusOut in between is not a return.
		again = self.consent(settled + [("focus_in",), ("button", "Allow")])
		self.assertReply(again, {"v": 1, "kind": "consent", "result": "allow"})

	def test_consent_focus_returning_from_outside_to_a_button_rearms_the_guard(self):
		# FocusOut while focus_get() is None (another application), then FocusIn reported
		# for a button rather than the toplevel: still a return from outside.
		settled = [("map",), ("advance", self.AFTER_GUARD), ("focus_in",), ("advance", self.AFTER_GUARD)]
		back = settled + [("focus_out",), ("advance", 0), ("focus_in_child", "Button")]
		inert = self.consent(back + [("button", "Allow"), ("escape",)])
		self.assertReply(inert, {"v": 1, "kind": "consent", "result": "deny"})
		later = self.consent(back + [("advance", self.AFTER_GUARD), ("button", "Allow")])
		self.assertReply(later, {"v": 1, "kind": "consent", "result": "allow"})
		inside = self.consent(settled + [("focus_in_child", "Button"), ("button", "Allow")])
		self.assertReply(inside, {"v": 1, "kind": "consent", "result": "allow"})

	def test_consent_timeout(self):
		run = self.consent([("map",), ("advance", self.FOREVER)])
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "timeout"})

	def test_consent_window_text_order(self):
		run = self.consent(
			[("map",), ("escape",)],
			claims=["Acme ERP, signed in as a@b"],
			warnings=["WARNING: this site uses an unencrypted (http) connection."],
		)
		labels = run.labels()
		self.assertEqual(labels[0], "https://\nerp.example.com", "origin first, in its own label")
		self.assertIn("WARNING: this site uses an unencrypted (http) connection.", labels)
		self.assertIn("as described by the site: Acme ERP, signed in as a@b", labels)

	def test_host_line_and_claims_are_never_wrapped(self):
		attack = "https://erp.mycompany.com.ap-south-1-secure-gateway.example"
		long_claim = "Verified ERP " + "w" * (dc.MAX_CLAIM_CHARS - 13)
		for kind in dc.KINDS:
			with self.subTest(kind=kind):
				run = run_child(make_request(kind=kind, origin=attack, claims=[long_claim, "two"]), [("map",), ("escape",)])
				wraps = run.wraplengths()
				origin_label = "https://\nerp.mycompany.com.ap-south-1-secure-gateway.example"
				self.assertEqual(run.labels()[0], origin_label)
				self.assertEqual(wraps[origin_label], 0, "the host line is never wrapped")
				for claim in (long_claim, "two"):
					self.assertEqual(wraps[dc.CLAIM_PREFIX + claim], 0, "a claim is ONE unwrapped line")
				claim_labels = [label for label in run.labels() if long_claim in label or label.endswith("two")]
				for label in claim_labels:
					self.assertTrue(label.startswith(dc.CLAIM_PREFIX))
					self.assertNotIn("\n", label)
				self.assertEqual(len(claim_labels), 2)

	# origin font vs the screen (spec section 9: the host is never cut off) -------------
	MAX_ORIGIN = "https://" + "h" * (dc.MAX_ORIGIN_CHARS - len("https://"))
	MAX_ORIGIN_LABEL = "https://\n" + "h" * (dc.MAX_ORIGIN_CHARS - len("https://"))

	def expected_origin_size(self, origin, screen):
		room = screen - dc.ORIGIN_SCREEN_MARGIN
		for size in dc.ORIGIN_FONT_SIZES:
			if max(fake_text_width(line, size) for line in dc.origin_lines(origin)) <= room:
				return size
		return None

	def test_a_maximum_length_host_fits_at_full_size_on_an_ordinary_screen(self):
		self.assertEqual(self.expected_origin_size(self.MAX_ORIGIN, FAKE_SCREEN_WIDTH), dc.ORIGIN_FONT_SIZES[0])
		for kind in dc.KINDS:
			with self.subTest(kind=kind):
				run = run_child(make_request(kind=kind, origin=self.MAX_ORIGIN), [("map",), ("escape",)])
				self.assertEqual(run.labels()[0], self.MAX_ORIGIN_LABEL)
				self.assertEqual(run.fonts()[self.MAX_ORIGIN_LABEL], [dc.ORIGIN_FONT_FAMILY, dc.ORIGIN_FONT_SIZES[0], "bold"])

	def test_the_origin_font_shrinks_until_the_whole_host_fits_the_screen(self):
		screen = 1000
		size = self.expected_origin_size(self.MAX_ORIGIN, screen)
		self.assertIsNotNone(size)
		self.assertLess(size, dc.ORIGIN_FONT_SIZES[0], "this case needs a shrink, or it proves nothing")
		host = self.MAX_ORIGIN.partition("://")[2]
		self.assertGreater(fake_text_width(host, dc.ORIGIN_FONT_SIZES[0]), screen - dc.ORIGIN_SCREEN_MARGIN)
		for kind, script, expected in (
			("consent", [("map",), ("advance", self.AFTER_GUARD), ("button", "Allow")], {"v": 1, "kind": "consent", "result": "allow"}),
			("pin", [("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("return",)], {"v": 1, "kind": "pin", "result": "entered", "value": "1234"}),
		):
			with self.subTest(kind=kind):
				run = run_child(make_request(kind=kind, origin=self.MAX_ORIGIN), script, screen=screen)
				self.assertReply(run, expected)
				self.assertEqual(run.fonts()[self.MAX_ORIGIN_LABEL], [dc.ORIGIN_FONT_FAMILY, size, "bold"])

	def test_a_host_wider_than_the_screen_at_the_smallest_font_fails_closed(self):
		screen = 600
		self.assertIsNone(self.expected_origin_size(self.MAX_ORIGIN, screen))
		consent = run_child(
			make_request(kind="consent", origin=self.MAX_ORIGIN),
			[("map",), ("advance", self.AFTER_GUARD), ("button", "Allow")],
			screen=screen,
		)
		self.assertReply(consent, {"v": 1, "kind": "consent", "result": "deny"})
		pin = run_child(
			make_request(kind="pin", origin=self.MAX_ORIGIN),
			[("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", PIN_SENTINEL), ("return",)],
			screen=screen,
		)
		self.assertReply(pin, {"v": 1, "kind": "pin", "result": "cancelled"})
		for run in (consent, pin):
			self.assertEqual(run.buttons(), [], "no Allow / OK button is ever created")
			self.assertEqual(run.labels(), [], "nothing is drawn: the host would be cut off")
		self.assertNotIn(PIN_SENTINEL.encode(), pin.stdout)

	def test_claims_are_never_drawn_larger_than_the_origin(self):
		seen = set()
		for screen in (FAKE_SCREEN_WIDTH, 1000, 800, 700):
			with self.subTest(screen=screen):
				size = self.expected_origin_size(self.MAX_ORIGIN, screen)
				run = run_child(make_request(kind="consent", origin=self.MAX_ORIGIN, claims=["Acme Ltd"]), [("map",), ("escape",)], screen=screen)
				fonts = run.fonts()
				origin_size = fonts[self.MAX_ORIGIN_LABEL][1]
				self.assertEqual(origin_size, size)
				claim_font = fonts[dc.CLAIM_PREFIX + "Acme Ltd"]
				self.assertIsNotNone(claim_font, "a claim's font is explicit, so its size is known")
				self.assertLessEqual(claim_font[1], origin_size)
				seen.add(origin_size)
		self.assertGreater(len(seen), 2, "the screens must exercise several origin sizes")
		self.assertLess(min(seen), dc.CLAIM_FONT_SIZE, "some case must force the claim font below its own size")

	# pin ------------------------------------------------------------------------------
	def test_pin_entered_after_click(self):
		run = self.pin([("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", PIN_SENTINEL), ("button", "OK")])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "entered", "value": PIN_SENTINEL})
		self.assertEqual(run.stdout.count(PIN_SENTINEL.encode()), 1)
		self.assertNotIn(PIN_SENTINEL, json.dumps(run.trace))

	def test_pin_return_key_submits(self):
		run = self.pin([("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("return",)])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "entered", "value": "1234"})

	def test_pin_typed_before_the_click_is_not_captured(self):
		run = self.pin([("map",), ("advance", self.AFTER_GUARD), ("type", "1234"), ("button", "OK"), ("click",), ("button", "OK")])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_pin_empty_is_cancelled(self):
		run = self.pin([("map",), ("advance", self.AFTER_GUARD), ("click",), ("button", "OK")])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_pin_cancel_escape_and_close_are_cancelled(self):
		for script in (
			[("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("button", "Cancel")],
			[("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("escape",)],
			[("map",), ("escape",)],
			[("map",), ("close",)],
		):
			with self.subTest(script=script):
				self.assertReply(self.pin(script), {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_pin_timeout(self):
		run = self.pin([("map",), ("advance", self.FOREVER)])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "timeout"})

	# pin input guard (spec section 9) ---------------------------------------------------
	def test_pin_click_inside_the_guard_does_not_enable_the_entry(self):
		# A click already in flight when the window maps, then the user keeps typing.
		run = self.pin([("map",), ("click",), ("type", "1234"), ("return",), ("button", "OK"), ("advance", self.AFTER_GUARD), ("return",), ("escape",)])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "cancelled"})
		# Just before the guard ends the click is still ignored; a click after it counts.
		edge = self.pin([("map",), ("advance", self.AFTER_GUARD - 10), ("click",), ("type", "1"), ("advance", 20), ("click",), ("type", "2"), ("return",)])
		self.assertReply(edge, {"v": 1, "kind": "pin", "result": "entered", "value": "2"})

	def test_pin_first_click_after_the_guard_is_not_ignored(self):
		# The review's probe: the click that activates the unfocused window produces the
		# window's FIRST FocusIn; that is not a return, so the click itself counts.
		for activate in ([("focus_in",)], [("focus_in_child", "Entry")]):
			with self.subTest(activate=activate):
				run = self.pin([("map",), ("advance", self.AFTER_GUARD), *activate, ("click",), ("type", "1234"), ("return",)])
				self.assertReply(run, {"v": 1, "kind": "pin", "result": "entered", "value": "1234"})
		# Activated during the guard: that click is ignored, a click after the guard counts.
		early = self.pin(
			[("map",), ("focus_in",), ("click",), ("type", "1"), ("advance", self.AFTER_GUARD), ("return",), ("click",), ("type", "2"), ("return",)]
		)
		self.assertReply(early, {"v": 1, "kind": "pin", "result": "entered", "value": "2"})

	def test_pin_hint_says_wait_during_the_guard_and_click_again_after_an_ignored_click(self):
		# Created armed: "Wait..." until the guard after the map runs out.
		normal = self.pin([("map",), ("advance", self.AFTER_GUARD), ("click",), ("escape",)])
		self.assertIn(dc.PIN_HINT_WAIT, normal.labels())
		self.assertEqual(normal.relabels(), [dc.PIN_HINT_BEFORE_CLICK, dc.PIN_HINT_AFTER_CLICK])
		ignored = self.pin([("map",), ("click",), ("advance", self.AFTER_GUARD), ("escape",)])
		self.assertEqual(ignored.relabels(), [dc.PIN_HINT_CLICK_AGAIN])
		# A real return after the click re-arms the guard: "Wait..." again, then the prompt.
		rearmed = self.pin(
			[("map",), ("advance", self.AFTER_GUARD), ("focus_in",), ("click",), ("focus_out",), ("advance", 0), ("focus_in",), ("advance", self.AFTER_GUARD), ("escape",)]
		)
		self.assertEqual(
			rearmed.relabels(), [dc.PIN_HINT_BEFORE_CLICK, dc.PIN_HINT_AFTER_CLICK, dc.PIN_HINT_WAIT, dc.PIN_HINT_AFTER_CLICK]
		)

	def test_pin_return_inside_a_rearmed_guard_does_not_submit(self):
		enabled = [("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234")]
		# The window takes focus and the guard runs out; then focus leaves for another
		# application (FocusOut, focus_get() is None) and comes back, to the toplevel or
		# straight to the Entry.
		settled = [("focus_in",), ("advance", self.AFTER_GUARD), ("focus_out",), ("advance", 0)]
		for back in (settled + [("focus_in",)], settled + [("focus_in_child", "Entry")]):
			with self.subTest(back=back):
				inert = self.pin(enabled + back + [("return",), ("button", "OK"), ("escape",)])
				self.assertReply(inert, {"v": 1, "kind": "pin", "result": "cancelled"})
				later = self.pin(enabled + back + [("advance", self.AFTER_GUARD), ("return",)])
				self.assertReply(later, {"v": 1, "kind": "pin", "result": "entered", "value": "1234"})

	def test_pin_focus_moving_inside_the_window_does_not_rearm_the_guard(self):
		# Focus is already in the window and no FocusOut went outside: a FocusIn on a child
		# widget is internal movement.
		settled = [("map",), ("advance", self.AFTER_GUARD), ("focus_in",), ("advance", self.AFTER_GUARD)]
		run = self.pin(settled + [("click",), ("type", "1234"), ("focus_in_child", "Entry"), ("return",)])
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "entered", "value": "1234"})

	def test_pin_escape_and_close_cancel_during_the_guard(self):
		for step in (("escape",), ("close",)):
			with self.subTest(step=step):
				self.assertReply(self.pin([("map",), step]), {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_pin_final_try_requires_the_tick_box(self):
		run = self.pin(
			[("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("button", "OK"), ("return",), ("tick",), ("button", "OK")],
			final_try=True,
		)
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "entered", "value": "1234"})
		self.assertIn(dc.FINAL_TRY_TEXT, run.labels())
		untick = self.pin([("map",), ("advance", self.AFTER_GUARD), ("click",), ("type", "1234"), ("button", "OK"), ("escape",)], final_try=True)
		self.assertReply(untick, {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_pin_window_shows_claims_with_the_site_prefix_and_origin_first(self):
		run = self.pin([("map",), ("escape",)], claims=["Document: XL-SI-26-0000014"])
		labels = run.labels()
		self.assertEqual(labels[0], "https://\nerp.example.com")
		self.assertIn("as described by the site: Document: XL-SI-26-0000014", labels)
		self.assertNotIn(dc.FINAL_TRY_TEXT, labels)

	def test_child_timer_uses_the_clamped_timeout(self):
		low = self.pin([("map",), ("escape",)], timeout=1)
		self.assertIn(dc.MIN_DIALOG_SECONDS * 1000, low.afters())
		high = self.pin([("map",), ("escape",)], timeout=10_000)
		self.assertIn(dc.MAX_DIALOG_SECONDS * 1000, high.afters())

	# availability -------------------------------------------------------------------
	def test_tk_import_failure_is_unavailable(self):
		for kind in dc.KINDS:
			run = run_child(make_request(kind=kind), mode="missing")
			self.assertReply(run, {"v": 1, "kind": kind, "result": "unavailable", "cause": "tk_import_failed"})

	def test_tk_init_failure_is_unavailable(self):
		for kind in dc.KINDS:
			run = run_child(make_request(kind=kind), mode="init_fails")
			self.assertReply(run, {"v": 1, "kind": kind, "result": "unavailable", "cause": "tk_init_failed"})

	def test_stray_output_from_tk_never_reaches_the_reply_channel(self):
		run = run_child(make_request(kind="consent"), [("map",), ("escape",)], mode="noisy")
		self.assertReply(run, {"v": 1, "kind": "consent", "result": "deny"})
		self.assertNotIn(b"noise", run.stdout)

	# process contract -----------------------------------------------------------------
	def test_invalid_request_exits_65_with_no_output(self):
		cases = {
			"not json": {"raw": b"hello\n"},
			"unreadable origin": {"raw": json.dumps(make_request(origin="https://a‮.b")).encode() + b"\n"},
			"oversize": {"raw": b"x" * (dc.MAX_REQUEST_BYTES + 10) + b"\n"},
			"no newline then EOF": {"raw": dc.encode_request(make_request())[:-1], "keep_open": False},
			"empty stdin": {"raw": b"", "keep_open": False},
		}
		for name, kwargs in cases.items():
			with self.subTest(name):
				run = run_child(**kwargs)
				self.assertEqual(run.returncode, dc.EXIT_REQUEST_INVALID)
				self.assertEqual(run.stdout, b"")
				self.assertEqual(run.stderr, b"")

	def test_window_already_mapped_at_start_still_arms_the_guard_and_the_timer(self):
		# Tk 9 on macOS: the root is mapped when Tk() returns and no <Map> follows.
		for kind, expected in (("consent", "timeout"), ("pin", "timeout")):
			with self.subTest(kind=kind):
				run = run_child(make_request(kind=kind), [("advance", self.FOREVER)], mode="premapped")
				self.assertReply(run, {"v": 1, "kind": kind, "result": expected})
		inert = run_child(make_request(kind="consent"), [("advance", 0), ("button", "Allow"), ("escape",)], mode="premapped")
		self.assertReply(inert, {"v": 1, "kind": "consent", "result": "deny"})
		allowed = run_child(make_request(kind="consent"), [("advance", self.AFTER_GUARD), ("button", "Allow")], mode="premapped")
		self.assertReply(allowed, {"v": 1, "kind": "consent", "result": "allow"})

	def test_dialog_that_ends_without_an_answer_writes_nothing(self):
		run = self.consent([("map",)])
		self.assertEqual(run.returncode, dc.EXIT_INTERNAL)
		self.assertEqual(run.stdout, b"")
		self.assertEqual(run.stderr, b"")

	def test_child_exits_when_stdin_reaches_eof_mid_dialog(self):
		run = run_child(make_request(kind="pin"), [("map",), ("hang",)], close_after=0.5)
		self.assertEqual(run.returncode, dc.EXIT_PARENT_GONE)
		self.assertEqual(run.stdout, b"")
		self.assertLess(run.seconds_after_close, 1.0)

	@unittest.skipUnless(os.name != "nt", "POSIX-only: uses the resource module, POSIX paths or permission bits")
	def test_core_dumps_are_disabled_before_stdin_is_read(self):
		run = run_child(make_request(kind="pin"), [("map",), ("escape",)], spy=True)
		self.assertReply(run, {"v": 1, "kind": "pin", "result": "cancelled"})
		events = [entry for entry in run.trace if "setrlimit" in entry or "stdin_read" in entry]
		import resource

		self.assertEqual(events[0], {"setrlimit": [resource.RLIMIT_CORE, [0, 0]]}, "setrlimit comes first")
		reads = [index for index, entry in enumerate(events) if "stdin_read" in entry]
		self.assertEqual(len(reads), 1)
		self.assertGreater(reads[0], 0)
		self.assertEqual(events[reads[0]], {"stdin_read": [0, 0]}, "RLIMIT_CORE is (0, 0) when the request is read")

	def test_refuses_to_run_without_isolated_mode(self):
		run = run_child(make_request(), [("map",), ("escape",)], isolated=False)
		self.assertEqual(run.returncode, dc.EXIT_NOT_ISOLATED)
		self.assertEqual(run.stdout, b"")


class TestPinWindowLook(unittest.TestCase):
	"""The PIN window's look (visual-only redesign, 2026-11-10), on the fake tkinter in THIS process.

	The owner could not see where to type: a disabled macOS Tk Entry draws no border.
	These pin the contract that fixes it without touching behaviour: the Entry sits in a
	framed box that is visible in BOTH states, a placeholder is drawn BESIDE the Entry
	(never inserted into it), and OK looks disabled exactly while ok_allowed() is false.
	"""

	AFTER_GUARD = int(dc.INPUT_GUARD_SECONDS * 1000) + 1

	def build(self, **request):
		patcher = mock.patch.dict(sys.modules)
		patcher.start()
		self.addCleanup(patcher.stop)
		install_fake_tkinter([])
		import tkinter  # the fake

		self.tk = tkinter
		self.root = tkinter.Tk()
		self.results = []
		self.handle = dc.build_pin_window(dc.validate_request(make_request(kind="pin", **request)), self.root, self.results.append)
		self.assertFalse(self.handle["refused"])
		self.root.mapped = True
		self.root.fire("<Map>")
		return self.handle

	def advance(self, ms):
		self.root.advance(ms)

	def click(self):
		self.root.fire("<ButtonPress>")

	def assertWaitingLook(self, handle):
		field, entry, placeholder = handle["field"], handle["entry"], handle["placeholder"]
		self.assertGreaterEqual(field.cget("highlightthickness"), 1, "the box has a border")
		self.assertEqual(field.cget("highlightbackground"), dc.COLOR_BORDER)
		self.assertEqual(field.cget("bg"), dc.COLOR_FIELD_WAIT)
		self.assertNotEqual(dc.COLOR_FIELD_WAIT, dc.COLOR_BG, "the waiting box is filled, not window-coloured")
		self.assertEqual(entry.cget("state"), "disabled")
		self.assertEqual(entry.cget("disabledbackground"), dc.COLOR_FIELD_WAIT)
		self.assertTrue(placeholder.placed, "the placeholder is shown while waiting")
		self.assertEqual(placeholder.cget("text"), dc.PIN_PLACEHOLDER)
		self.assertEqual(placeholder.cget("fg"), dc.COLOR_MUTED)
		self.assertEqual(entry.get(), "", "the placeholder is never text inside the Entry")

	def test_window_is_white_and_wide(self):
		self.build()
		self.assertEqual(self.root.cget("bg"), dc.COLOR_BG)
		self.assertGreaterEqual(self.root.min_size[0], 460)

	def test_pin_box_is_visible_and_empty_while_waiting(self):
		handle = self.build()
		entry = handle["entry"]
		self.assertEqual(entry.cget("show"), "*")
		self.assertGreaterEqual(entry.cget("width"), 30)
		self.assertEqual(entry.cget("font")[1], 14)
		self.assertWaitingLook(handle)
		# A click inside the guard is ignored: still the waiting look, still empty.
		self.click()
		self.assertWaitingLook(handle)
		self.advance(self.AFTER_GUARD)
		self.assertWaitingLook(handle)

	def test_pin_box_turns_active_after_the_accepted_click(self):
		handle = self.build()
		self.advance(self.AFTER_GUARD)
		self.click()
		field, entry, placeholder = handle["field"], handle["entry"], handle["placeholder"]
		self.assertEqual(entry.cget("state"), "normal")
		self.assertEqual(entry.cget("bg"), dc.COLOR_FIELD_ACTIVE)
		self.assertEqual(field.cget("bg"), dc.COLOR_FIELD_ACTIVE)
		self.assertEqual(field.cget("highlightbackground"), dc.COLOR_PRIMARY, "Frappe-blue focus ring")
		self.assertGreaterEqual(field.cget("highlightthickness"), 1)
		self.assertFalse(placeholder.placed, "the placeholder goes once the box is active")
		self.assertEqual(entry.get(), "", "activation inserts nothing")

	def test_ok_looks_disabled_exactly_while_it_is_disabled(self):
		handle = self.build(final_try=True)
		ok, cancel = handle["ok"], handle["cancel"]
		self.assertEqual(ok.cget("text"), "OK")
		self.assertEqual(cancel.cget("text"), "Cancel")
		self.assertNotEqual(dc.COLOR_PRIMARY_DISABLED, dc.COLOR_PRIMARY)

		def assert_disabled_look(when):
			self.assertEqual(ok.cget("state"), "disabled", when)
			self.assertEqual(ok.cget("bg"), dc.COLOR_PRIMARY_DISABLED, when)

		assert_disabled_look("guard armed")
		self.advance(self.AFTER_GUARD)
		assert_disabled_look("guard over, no click yet")
		self.click()
		assert_disabled_look("clicked, final-try tick-box not ticked")
		handle["tick"].invoke()
		self.assertEqual(ok.cget("state"), "normal")
		self.assertEqual(ok.cget("bg"), dc.COLOR_PRIMARY)
		self.assertEqual(ok.cget("fg"), "#ffffff")
		self.assertEqual(cancel.cget("state"), "normal")
		self.assertEqual(cancel.cget("bg"), dc.COLOR_SECONDARY)
		# The outline is a Frame around the Label (macOS draws no ring on a nested Label).
		self.assertEqual(cancel.outline.cget("bg"), dc.COLOR_BORDER, "Cancel has a grey outline")
		self.assertEqual(cancel.outline.cget("padx"), 1)
		self.assertEqual(ok.outline.cget("bg"), dc.COLOR_PRIMARY)
		# Keyboard focus shows a ring; losing it restores the outline.  Both bindings
		# leave the event to the window (no "break"), so the input guard still sees it.
		self.assertIsNone(cancel.bindings["<FocusIn>"](None))
		self.assertEqual(cancel.outline.cget("bg"), dc.COLOR_BUTTON_FOCUS)
		self.assertIsNone(cancel.bindings["<FocusOut>"](None))
		self.assertEqual(cancel.outline.cget("bg"), dc.COLOR_BORDER)

	def test_flat_button_is_inert_while_disabled_and_space_activates_it(self):
		handle = self.build()
		flat = type(handle["ok"])
		pressed = []
		button = flat(self.root, text="X", command=lambda: pressed.append(1))
		self.assertEqual(int(button.cget("takefocus")), 1, "Tab reaches it")
		self.assertNotIn("<Return>", button.bindings, "Return never activates a button")
		space = button.bindings["<KeyPress-space>"]
		button.set_state("disabled")
		button.invoke()
		space(None)
		self.assertEqual(pressed, [], "a disabled button ignores invoke() and Space")
		button.set_state("normal")
		button.invoke()
		space(None)
		self.assertEqual(pressed, [1, 1])

	def test_cancel_and_ok_buttons_still_answer(self):
		handle = self.build()
		handle["ok"].invoke()
		self.assertEqual(self.results, [], "OK is inert before the click")
		self.advance(self.AFTER_GUARD)
		self.click()
		handle["entry"].insert("end", PIN_SENTINEL)
		handle["ok"].invoke()
		self.assertEqual(self.results, [{"v": 1, "kind": "pin", "result": "entered", "value": PIN_SENTINEL}])
		self.assertEqual(handle["entry"].get(), "", "the Entry is cleared once read")
		cancelled = self.build()
		cancelled["cancel"].invoke()
		self.assertEqual(self.results[-1], {"v": 1, "kind": "pin", "result": "cancelled"})

	def test_the_pin_is_held_by_the_entry_alone(self):
		handle = self.build()
		self.advance(self.AFTER_GUARD)
		self.click()
		handle["entry"].insert("end", PIN_SENTINEL)
		for widget in self.root.widgets:
			if widget is handle["entry"]:
				continue
			self.assertNotIn(PIN_SENTINEL, repr(widget.kw), widget)
			self.assertNotIn(PIN_SENTINEL, widget.value, widget)
		self.assertNotIn(PIN_SENTINEL, repr(handle["entry"].kw), "never an option such as text=")


@unittest.skipUnless(UI_TESTS, "real Tk windows: set ERP_DSC_UI_TESTS=1 on a desktop session")
class TestRealTkWindows(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		if not _stdin_is_pipe_or_tty():
			raise unittest.SkipTest(STDIN_SKIP)

	def setUp(self):
		import tkinter

		self.tkinter = tkinter
		self.root = tkinter.Tk()
		self.results = []
		self.handle = None
		self.addCleanup(self.tear_down_window)

	def tear_down_window(self):
		if self.handle is not None:
			self.handle["close"]()  # finishes the dialog, which cancels its timers
		self.root.destroy()

	def pump(self, seconds):
		end = time.monotonic() + seconds
		while time.monotonic() < end:
			self.root.update()
			time.sleep(0.02)

	def states(self):
		return {name: str(button.cget("state")) for name, button in self.handle["buttons"].items()}

	def consent(self, layout):
		self.handle = dc.build_consent_window(layout, make_request(kind="consent"), self.root, self.results.append)
		self.pump(0.3)

	def test_buttons_are_disabled_during_the_guard_while_escape_still_denies(self):
		self.consent(dc.consent_layout())
		self.assertEqual(self.states(), {"deny": "disabled", "allow": "disabled"})
		self.assertTrue(self.handle["guarded"]())
		self.assertTrue(self.root.bind("<Escape>"))
		self.handle["buttons"]["allow"].invoke()
		self.assertEqual(self.results, [])
		self.handle["escape"]()
		self.assertEqual(self.results, [{"v": 1, "kind": "consent", "result": "deny"}])

	def test_window_close_during_the_guard_is_deny(self):
		self.consent(dc.consent_layout())
		self.assertTrue(self.handle["guarded"]())
		self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))  # what the window manager runs
		self.assertEqual(self.results, [{"v": 1, "kind": "consent", "result": "deny"}])

	def test_default_layout_focuses_deny_with_no_default_button(self):
		self.consent(dc.consent_layout())
		self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
		buttons = self.handle["buttons"]
		self.assertEqual(self.states(), {"deny": "normal", "allow": "normal"})
		self.assertEqual(self.root.focus_lastfor(), buttons["deny"])
		self.assertEqual(buttons["deny"].tk_focusNext(), buttons["allow"])
		self.assertEqual(str(buttons["allow"].cget("default")), "disabled")
		self.assertEqual(str(buttons["deny"].cget("default")), "disabled")
		self.root.focus_lastfor().invoke()
		self.assertEqual(self.results, [{"v": 1, "kind": "consent", "result": "deny"}])

	def test_an_altered_layout_changes_the_window_and_the_result(self):
		layout = dc.consent_layout()
		layout.update(initial_focus="allow", default="allow", tab_order=("allow", "deny"), input_guard_seconds=0.1)
		self.consent(layout)
		self.pump(0.3)
		buttons = self.handle["buttons"]
		self.assertEqual(self.root.focus_lastfor(), buttons["allow"])
		self.assertEqual(buttons["allow"].tk_focusNext(), buttons["deny"])
		self.assertEqual(str(buttons["allow"].cget("default")), "active")
		self.root.focus_lastfor().invoke()
		self.assertEqual(self.results, [{"v": 1, "kind": "consent", "result": "allow"}])

	def leave_and_return(self):
		"""Focus goes to another application (focus_get() is None), then comes back."""
		self.root.event_generate("<FocusIn>")
		self.root.update()
		real_focus_get = self.root.focus_get
		self.root.focus_get = lambda: None
		try:
			self.root.event_generate("<FocusOut>")
			self.root.update()  # runs the idle check_outside
		finally:
			self.root.focus_get = real_focus_get
		self.root.event_generate("<FocusIn>")
		self.root.update()

	def test_first_focus_in_does_not_rearm_but_a_return_from_outside_does(self):
		layout = dc.consent_layout()
		layout["input_guard_seconds"] = 0.2
		self.consent(layout)
		self.pump(0.4)
		self.assertEqual(self.states(), {"deny": "normal", "allow": "normal"})
		self.root.event_generate("<FocusIn>")  # the activating click: the first focus
		self.root.update()
		self.assertEqual(self.states(), {"deny": "normal", "allow": "normal"})
		self.leave_and_return()
		self.assertEqual(self.states(), {"deny": "disabled", "allow": "disabled"})
		self.pump(0.4)
		self.assertEqual(self.states(), {"deny": "normal", "allow": "normal"})

	def test_pin_entry_ignores_typing_until_the_window_is_clicked(self):
		self.handle = dc.build_pin_window(make_request(kind="pin"), self.root, self.results.append)
		self.pump(0.3)
		entry = self.handle["entry"]
		self.assertEqual(str(entry.cget("state")), "disabled")
		self.assertEqual(str(entry.cget("show")), "*")
		entry.insert(0, "1234")  # what a keystroke's class binding does
		self.assertEqual(entry.get(), "")
		self.assertEqual(str(self.handle["ok"].cget("state")), "disabled")
		# A click inside the input guard is ignored: the Entry stays disabled.
		self.assertTrue(self.handle["guarded"]())
		self.root.event_generate("<ButtonPress-1>", x=5, y=5)
		self.root.update()
		self.assertEqual(str(entry.cget("state")), "disabled")
		self.pump(dc.INPUT_GUARD_SECONDS)
		self.assertFalse(self.handle["guarded"]())
		self.root.event_generate("<ButtonPress-1>", x=5, y=5)
		self.root.update()
		self.assertEqual(str(entry.cget("state")), "normal")
		entry.insert(0, "1234")
		self.assertEqual(entry.get(), "1234")
		self.handle["ok"].invoke()
		self.assertEqual(self.results, [{"v": 1, "kind": "pin", "result": "entered", "value": "1234"}])
		self.assertEqual(entry.get(), "", "the Entry is cleared once read")

	def test_pin_final_try_ok_needs_the_tick_box(self):
		self.handle = dc.build_pin_window(make_request(kind="pin", final_try=True), self.root, self.results.append)
		self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
		self.handle["click"]()
		self.assertEqual(str(self.handle["ok"].cget("state")), "disabled")
		self.handle["tick"].invoke()
		self.assertEqual(str(self.handle["ok"].cget("state")), "normal")

	def test_pin_focus_returning_from_outside_rearms_the_guard_for_return(self):
		self.handle = dc.build_pin_window(make_request(kind="pin"), self.root, self.results.append)
		self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
		self.handle["click"]()
		entry = self.handle["entry"]
		entry.insert(0, "1234")
		self.leave_and_return()
		self.assertTrue(self.handle["guarded"]())
		self.assertEqual(str(self.handle["hint"].cget("text")), dc.PIN_HINT_WAIT)
		self.assertEqual(str(self.handle["ok"].cget("state")), "disabled")
		entry.event_generate("<Return>")
		self.root.update()
		self.assertEqual(self.results, [], "Return inside the re-armed guard must not submit")
		self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
		self.assertEqual(str(self.handle["ok"].cget("state")), "normal")
		self.handle["ok"].invoke()
		self.assertEqual(self.results, [{"v": 1, "kind": "pin", "result": "entered", "value": "1234"}])

	def test_pin_box_is_drawn_around_the_entry_in_both_states(self):
		self.handle = dc.build_pin_window(make_request(kind="pin"), self.root, self.results.append)
		self.pump(0.3)
		field, entry = self.handle["field"], self.handle["entry"]
		self.assertIs(entry.master, field, "the box wraps the Entry itself")
		for when in ("waiting", "active"):
			with self.subTest(when=when):
				self.assertGreaterEqual(int(str(field.cget("highlightthickness"))), 1)
				self.assertGreater(field.winfo_height(), entry.winfo_height() + 2, "the border is drawn outside the Entry")
				self.assertGreaterEqual(field.winfo_width(), 400, "a wide, obvious box")
				self.assertEqual(entry.get(), "")
			if when == "waiting":
				self.assertEqual(str(entry.cget("state")), "disabled")
				self.assertTrue(self.handle["placeholder"].winfo_ismapped())
				self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
				self.handle["click"]()
				self.root.update()
		self.assertEqual(str(entry.cget("state")), "normal")
		self.assertFalse(self.handle["placeholder"].winfo_ismapped())
		self.assertEqual(str(field.cget("highlightbackground")), dc.COLOR_PRIMARY)

	def press_and_release(self, widget, x, y):
		widget.event_generate("<ButtonPress-1>", x=x, y=y)
		widget.event_generate("<ButtonRelease-1>", x=x, y=y)
		self.root.update()

	def test_pin_buttons_answer_a_mouse_release_inside_only_when_enabled(self):
		self.handle = dc.build_pin_window(make_request(kind="pin"), self.root, self.results.append)
		self.pump(0.3)
		ok, entry = self.handle["ok"], self.handle["entry"]
		self.press_and_release(ok, 5, 5)  # during the guard
		self.assertEqual(self.results, [])
		self.assertEqual(str(entry.cget("state")), "disabled")
		self.pump(dc.INPUT_GUARD_SECONDS + 0.3)
		# The accepted first click lands ON the disabled OK: it enables the Entry, and
		# its release must not submit (the press began while OK was disabled).
		self.press_and_release(ok, 5, 5)
		self.assertEqual(str(entry.cget("state")), "normal")
		self.assertEqual(self.results, [])
		entry.insert(0, "1234")
		self.press_and_release(ok, -20, -20)  # released outside the button
		self.assertEqual(self.results, [])
		self.press_and_release(ok, 5, 5)
		self.assertEqual(self.results, [{"v": 1, "kind": "pin", "result": "entered", "value": "1234"}])
		self.assertEqual(entry.get(), "")

	def test_long_host_is_one_unwrapped_line(self):
		attack = "https://erp.mycompany.com.ap-south-1-secure-gateway.example"
		self.handle = dc.build_pin_window(make_request(kind="pin", origin=attack, claims=["x" * dc.MAX_CLAIM_CHARS]), self.root, self.results.append)
		self.pump(0.3)
		labels = [w for w in self.root.winfo_children()[0].winfo_children() if w.winfo_class() == "Label"]
		origin_label = labels[0]
		self.assertEqual(origin_label.cget("text"), "https://\nerp.mycompany.com.ap-south-1-secure-gateway.example")
		self.assertEqual(int(str(origin_label.cget("wraplength"))), 0)
		import tkinter.font as tkfont

		font = tkfont.Font(root=self.root, font=origin_label.cget("font"))
		self.assertGreaterEqual(origin_label.winfo_reqwidth(), font.measure(attack.partition("://")[2]))
		claim_label = [w for w in labels if str(w.cget("text")).startswith(dc.CLAIM_PREFIX)][0]
		self.assertEqual(int(str(claim_label.cget("wraplength"))), 0)

	def test_the_timer_and_guard_start_once_the_real_window_is_shown(self):
		self.handle = dc.build_consent_window(dc.consent_layout(), make_request(kind="consent"), self.root, self.results.append)
		self.pump(0.3)
		self.assertTrue(self.handle["timer_started"]())
		self.assertTrue(self.handle["guarded"]())
		self.handle["close"]()
		self.handle = dc.build_pin_window(make_request(kind="pin"), self.root, self.results.append)
		self.pump(0.3)
		self.assertTrue(self.handle["timer_started"]())


@unittest.skipUnless(UI_TESTS, "real Tk windows: set ERP_DSC_UI_TESTS=1 on a desktop session")
class TestRealChildProcess(unittest.TestCase):
	"""The production argv shape, a real Tk window, nobody answering: the child's own timer ends it."""

	def run_real_child(self, kind):
		process = subprocess.Popen(
			[sys.executable, "-I", str(CHILD)],
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			close_fds=True,
			cwd=tempfile.gettempdir(),
		)
		killer = threading.Timer(30, process.kill)
		killer.start()
		started = time.monotonic()
		try:
			process.stdin.write(dc.encode_request(make_request(kind=kind, timeout=dc.MIN_DIALOG_SECONDS)))
			process.stdin.flush()
			out = process.stdout.read()
			process.wait()
		finally:
			killer.cancel()
			process.stdin.close()
			process.stdout.close()
		return process.returncode, out, time.monotonic() - started

	def test_consent_and_pin_time_out_on_their_own(self):
		for kind in dc.KINDS:
			with self.subTest(kind=kind):
				code, out, seconds = self.run_real_child(kind)
				self.assertEqual(code, 0)
				self.assertEqual(json.loads(out), {"v": 1, "kind": kind, "result": "timeout"})
				self.assertEqual(out.count(b"\n"), 1)
				self.assertLess(seconds, dc.MIN_DIALOG_SECONDS + 5)


if __name__ == "__main__":
	unittest.main()
