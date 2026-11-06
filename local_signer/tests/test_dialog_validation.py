"""Parent-side request validation before any spawn (spec 001 §6, §4).

An invalid request is DialogFailed("dialog_request_invalid") and no child is started.
Over-long or unreadable SITE claims are replaced by a visible placeholder (checked by
reading what a stub child actually received); the origin is never altered.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child, ui
from erp_dsc_local.errors import DialogFailed


TESTS_DIR = Path(__file__).resolve().parent
STUB = TESTS_DIR / "_stub_child.py"
ORIGIN = "https://site.example"


def request(**overrides):
	base = {
		"v": 1,
		"kind": "pin",
		"origin": ORIGIN,
		"claims": ["Sales Invoice XL-SI-26-0000014"],
		"warnings": [],
		"final_try": False,
		"timeout": 120,
	}
	base.update(overrides)
	return base


class TestInvalidRequestsNeverSpawn(unittest.TestCase):
	def setUp(self):
		self.popen = mock.Mock(side_effect=AssertionError("a child was spawned"))
		patcher = mock.patch.object(subprocess, "Popen", self.popen)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.host = ui.DialogHost(child_script=STUB)

	def assertInvalid(self, req):
		with self.assertRaises(DialogFailed) as ctx:
			self.host.run_dialog(req)
		self.assertEqual("dialog_request_invalid", ctx.exception.cause)
		self.assertIsNone(ctx.exception.__context__, "raised outside any except block")
		self.popen.assert_not_called()
		self.assertFalse(self.host.busy)

	def test_oversized_request(self):
		claims = ["c" * dialog_child.MAX_CLAIM_CHARS] * 60
		self.assertGreater(len(json.dumps(claims)), dialog_child.MAX_REQUEST_BYTES)
		self.assertInvalid(request(claims=claims))

	def test_request_exactly_at_the_limit_plus_one_byte(self):
		# Grow one claim until the encoded line (newline included) is one byte too long.
		claims = ["c" * dialog_child.MAX_CLAIM_CHARS] * 56
		line = dialog_child.encode_request(request(claims=claims))
		room = dialog_child.MAX_REQUEST_BYTES - len(line)
		self.assertGreaterEqual(room, 0)
		filler = "c" * (room - len(', ""') + 1)
		self.assertLessEqual(len(filler), dialog_child.MAX_CLAIM_CHARS)
		fits = dialog_child.encode_request(request(claims=claims + [filler[:-1]]))
		self.assertEqual(dialog_child.MAX_REQUEST_BYTES, len(fits), "the limit includes the newline")
		self.assertInvalid(request(claims=claims + [filler]))

	def test_overlong_origin_is_refused_not_truncated(self):
		origin = "https://" + "a" * (dialog_child.MAX_ORIGIN_CHARS - len("https://") + 1)
		self.assertEqual(dialog_child.MAX_ORIGIN_CHARS + 1, len(origin))
		self.assertInvalid(request(origin=origin))

	def test_unreadable_origin_is_refused(self):
		for char in ("\n", "‮", "؜", "­", " ", " ", "", "\ud800", "\x00"):
			with self.subTest(codepoint=hex(ord(char))):
				self.assertInvalid(request(origin="https://site" + char + ".example"))

	def test_lone_surrogate_is_refused(self):
		self.assertInvalid(request(origin="https://\ud800.example"))
		self.assertInvalid(request(warnings=["the signer's own text \ud800"]))

	def test_unencodable_request_is_refused_even_if_validation_passes(self):
		# Any encode failure (UnicodeEncodeError included) is dialog_request_invalid.
		with mock.patch.object(dialog_child, "encode_request", side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")):
			self.assertInvalid(request())

	def test_schema_violations(self):
		cases = {
			"v is 2": request(v=2),
			"v is true": request(v=True),
			"unknown kind": request(kind="other"),
			"empty origin": request(origin=""),
			"origin not a string": request(origin=None),
			"claims not a list": request(claims="claim"),
			"claim not a string": request(claims=[7]),
			"warnings not a list": request(warnings="w"),
			"empty warning": request(warnings=[""]),
			"final_try not a bool": request(final_try=1),
			"timeout is a bool": request(timeout=True),
			"timeout is a string": request(timeout="120"),
			"timeout is a float": request(timeout=120.0),
		}
		missing = request()
		del missing["final_try"]
		cases["missing key"] = missing
		cases["extra key"] = request(pin="1234")
		for label, req in cases.items():
			with self.subTest(label):
				self.assertInvalid(req)

	def test_not_a_dict(self):
		line = dialog_child.encode_request(request())
		for req in (line, line.decode(), [request()], None):
			with self.subTest(type=type(req).__name__):
				self.assertInvalid(req)


class TestClaimsReachTheChildAsVisiblePlaceholders(unittest.TestCase):
	def setUp(self):
		self.host = ui.DialogHost(child_script=STUB)
		self.directory = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.directory, True)

	def received(self, claims, **fields) -> dict:
		path = os.path.join(self.directory, "r.json")
		reply = self.host.run_dialog(request(claims=["MODE:report", path] + claims, **fields))
		self.assertEqual("cancelled", reply["result"])
		with open(path, encoding="utf-8") as handle:
			return json.loads(json.load(handle)["request_line"])

	def test_claims_are_replaced_never_truncated(self):
		too_long = "x" * (dialog_child.MAX_CLAIM_CHARS + 1)
		at_limit = "y" * dialog_child.MAX_CLAIM_CHARS
		unreadable = {
			"newline": "line one\nline two",
			"carriage return": "a\rb",
			"RLO U+202E": "invoice ‮gnp.exe",
			"ALM U+061C": "amount ؜100",
			"soft hyphen U+00AD": "soft­hyphen",
			"line separator U+2028": "a b",
			"private use U+E000": "ab",
			"lone surrogate": "a\ud800b",
			"NUL": "a\x00b",
			"escape": "\x1b[31mred",
		}
		claims = [too_long, at_limit, "Sales Invoice XL-SI-26-0000014"] + list(unreadable.values())
		got = self.received(claims)["claims"][2:]
		expected = [dialog_child.CLAIM_TOO_LONG, at_limit, "Sales Invoice XL-SI-26-0000014"]
		expected += [dialog_child.CLAIM_UNREADABLE] * len(unreadable)
		self.assertEqual(expected, got)
		for original, shown in zip(claims, got):
			if shown != original:
				self.assertFalse(original.startswith(shown), "a claim was silently truncated")
				self.assertIn(shown, (dialog_child.CLAIM_TOO_LONG, dialog_child.CLAIM_UNREADABLE))

	def test_origin_is_passed_unaltered(self):
		origin = "https://erp.example.co.in:8443"
		self.assertEqual(origin, self.received([], origin=origin)["origin"])

	def test_timeout_is_clamped_before_sending(self):
		self.assertEqual(dialog_child.MAX_DIALOG_SECONDS, self.received([], timeout=10_000)["timeout"])
		self.assertEqual(dialog_child.MIN_DIALOG_SECONDS, self.received([], timeout=-5)["timeout"])

	def test_deadline_uses_the_clamped_timeout(self):
		# STARTUP + clamped(0 -> MIN) + GRACE; with every term patched small the hang
		# is cut at ~0.5 s, proving an out-of-range timeout cannot stretch the deadline.
		patches = [
			mock.patch.object(ui, "STARTUP_ALLOWANCE_SECONDS", 0.3),
			mock.patch.object(ui, "GRACE_SECONDS", 0.1),
			mock.patch.object(ui, "KILL_DELAY_SECONDS", 0.3),
			mock.patch.object(dialog_child, "MIN_DIALOG_SECONDS", 0),
			mock.patch.object(dialog_child, "MAX_DIALOG_SECONDS", 0),
		]
		for patcher in patches:
			patcher.start()
			self.addCleanup(patcher.stop)
		with self.assertRaises(DialogFailed) as ctx:
			self.host.run_dialog(request(claims=["MODE:hang"], timeout=10_000))
		self.assertEqual("dialog_timeout", ctx.exception.cause)


if __name__ == "__main__":
	unittest.main()
