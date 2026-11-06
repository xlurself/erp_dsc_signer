"""pin.request_pin: the request it sends and every §6 mapping row (spec 001)."""

import traceback
import unittest
from pathlib import Path

from erp_dsc_local import dialog_child, pin, ui
from erp_dsc_local.errors import (
	DIALOG_CAUSES,
	DialogBusy,
	DialogFailed,
	DialogWedged,
	PinCancelled,
	PinPromptUnavailable,
)
from erp_dsc_local.ui import UiBusy


SENTINEL = "PIN-SENTINEL-7319"
ORIGIN = "https://erp.example.com"
STUB = Path(__file__).resolve().parent / "_stub_child.py"


class FakeHost:
	"""Stands in for DialogHost: records each request, then returns or raises."""

	def __init__(self, reply=None, error=None, *, error_context=None):
		self.reply = reply
		self.error = error
		self.error_context = error_context
		self.requests = []

	def run_dialog(self, request):
		self.requests.append(request)
		if self.error is not None:
			if self.error_context is not None:
				# The way a parser error holding the reply text would sit in the chain.
				try:
					raise ValueError(self.error_context)
				except ValueError:
					raise self.error
			raise self.error
		return self.reply


def reply(result, **fields):
	return {"v": 1, "kind": "pin", "result": result, **fields}


def chain(exc):
	"""The exception and everything reachable through __cause__ / __context__."""
	seen = []
	stack = [exc]
	while stack:
		current = stack.pop()
		if current is None or any(current is s for s in seen):
			continue
		seen.append(current)
		stack += [current.__cause__, current.__context__]
	return seen


def assert_no_sentinel(test, exc):
	for item in chain(exc):
		test.assertNotIn(SENTINEL, str(item))
		test.assertNotIn(SENTINEL, repr(item))
		test.assertNotIn(SENTINEL, repr(vars(item)))
	test.assertNotIn(SENTINEL, "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


class TestPinRequestShape(unittest.TestCase):
	def ask(self, *args, **kwargs):
		host = FakeHost(reply("entered", value=SENTINEL))
		pin.request_pin(*args, host=host, **kwargs)
		self.assertEqual(1, len(host.requests))
		return host.requests[0]

	def test_fields_are_separate(self):
		request = self.ask(ORIGIN, "XL-SI-26-0000014")
		self.assertEqual(
			{
				"v": 1,
				"kind": "pin",
				"origin": ORIGIN,
				"claims": ["XL-SI-26-0000014"],
				"warnings": [],
				"final_try": False,
				"timeout": dialog_child.DEFAULT_DIALOG_SECONDS,
			},
			request,
		)
		self.assertEqual(dialog_child.REQUEST_KEYS, set(request))
		# No merged text: the origin and the document name never share a string.
		for value in request.values():
			if isinstance(value, str) and value != ORIGIN:
				self.assertNotIn("XL-SI-26", value)
		self.assertNotIn(ORIGIN, request["claims"][0])

	def test_request_is_valid_for_the_real_host(self):
		request = self.ask(ORIGIN, "XL-SI-26-0000014", warnings=("Signer warning.",), final_try=True)
		self.assertEqual(request, dialog_child.validate_request(request))

	def test_empty_or_missing_document_name_sends_no_claim(self):
		for name in ("", None):
			with self.subTest(name=name):
				self.assertEqual([], self.ask(ORIGIN, name)["claims"])

	def test_warnings_and_final_try_are_passed_through(self):
		request = self.ask(ORIGIN, "INV-1", warnings=("first", "second"), final_try=True)
		self.assertEqual(["first", "second"], request["warnings"])
		self.assertIs(True, request["final_try"])
		self.assertIs(False, self.ask(ORIGIN, "INV-1")["final_try"])

	def test_long_document_name_is_not_truncated_and_is_replaced_visibly(self):
		name = "D" * (dialog_child.MAX_CLAIM_CHARS + 60)
		request = self.ask(ORIGIN, name)
		self.assertEqual([name], request["claims"])  # never a silent [:140]
		self.assertEqual([dialog_child.CLAIM_TOO_LONG], dialog_child.validate_request(request)["claims"])

	def test_host_is_required_and_old_names_are_gone(self):
		with self.assertRaises(TypeError):
			pin.request_pin(ORIGIN, "INV-1")
		for name in ("PIN_TIMEOUT_SECONDS", "MAX_DOCUMENT_NAME", "build_pin_text", "new_tk_root", "UiUnavailable"):
			self.assertFalse(hasattr(pin, name), name)


class TestPinMapping(unittest.TestCase):
	def run_pin(self, host):
		return pin.request_pin(ORIGIN, "INV-1", host=host)

	def test_entered_returns_the_value(self):
		self.assertEqual(SENTINEL, self.run_pin(FakeHost(reply("entered", value=SENTINEL))))

	def test_cancelled(self):
		with self.assertRaises(PinCancelled) as ctx:
			self.run_pin(FakeHost(reply("cancelled")))
		assert_no_sentinel(self, ctx.exception)

	def test_timeout_result_is_unavailable_dialog_timeout(self):
		with self.assertRaises(PinPromptUnavailable) as ctx:
			self.run_pin(FakeHost(reply("timeout")))
		self.assertEqual({"cause": "dialog_timeout"}, ctx.exception.details)

	def test_unavailable_carries_the_child_cause(self):
		for cause in dialog_child.UNAVAILABLE_CAUSES:
			with self.subTest(cause=cause):
				with self.assertRaises(PinPromptUnavailable) as ctx:
					self.run_pin(FakeHost(reply("unavailable", cause=cause)))
				self.assertEqual({"cause": cause}, ctx.exception.details)

	def test_dialog_failed_maps_every_cause_without_a_chain(self):
		self.assertEqual(9, len(DIALOG_CAUSES))
		for cause in sorted(DIALOG_CAUSES):
			with self.subTest(cause=cause):
				host = FakeHost(error=DialogFailed(cause), error_context='{"value":"%s"' % SENTINEL)
				with self.assertRaises(PinPromptUnavailable) as ctx:
					self.run_pin(host)
				exc = ctx.exception
				self.assertEqual({"cause": cause}, exc.details)
				self.assertIn(f"({cause})", exc.message)
				self.assertIsNone(exc.__cause__)
				self.assertIsNone(exc.__context__)
				assert_no_sentinel(self, exc)

	def test_ui_busy_is_dialog_busy(self):
		host = FakeHost(error=UiBusy(), error_context=SENTINEL)
		with self.assertRaises(DialogBusy) as ctx:
			self.run_pin(host)
		self.assertEqual(("DIALOG_BUSY", 429), (ctx.exception.code, ctx.exception.status))
		self.assertIsNone(ctx.exception.__cause__)
		self.assertIsNone(ctx.exception.__context__)
		assert_no_sentinel(self, ctx.exception)

	def test_dialog_wedged_propagates_unchanged(self):
		wedged = DialogWedged()
		with self.assertRaises(DialogWedged) as ctx:
			self.run_pin(FakeHost(error=wedged))
		self.assertIs(wedged, ctx.exception)

	def test_malformed_replies_fail_closed_without_the_value(self):
		bad = [
			None,
			"entered",
			reply("entered", value=""),
			reply("entered"),
			reply("allow"),
			reply("unavailable", cause="made_up"),
			{"result": "something", "value": SENTINEL},
		]
		for value in bad:
			with self.subTest(reply=value):
				with self.assertRaises(PinPromptUnavailable) as ctx:
					self.run_pin(FakeHost(value))
				self.assertEqual({"cause": "dialog_bad_reply"}, ctx.exception.details)
				assert_no_sentinel(self, ctx.exception)

	def test_cancelled_with_a_stray_value_never_returns_it(self):
		with self.assertRaises(PinCancelled) as ctx:
			self.run_pin(FakeHost(reply("cancelled", value=SENTINEL)))
		assert_no_sentinel(self, ctx.exception)


class TestPinWithRealHost(unittest.TestCase):
	"""The same contract through the real DialogHost and the stub child process."""

	def setUp(self):
		self.host = ui.DialogHost(child_script=STUB)

	def test_entered(self):
		self.assertEqual(SENTINEL, pin.request_pin(ORIGIN, "MODE:ok_entered:" + SENTINEL, host=self.host))

	def test_cancelled(self):
		with self.assertRaises(PinCancelled):
			pin.request_pin(ORIGIN, "MODE:result:cancelled", host=self.host)

	def test_bad_reply_holding_the_pin_never_leaks(self):
		with self.assertRaises(PinPromptUnavailable) as ctx:
			pin.request_pin(ORIGIN, "MODE:badjson:" + SENTINEL, host=self.host)
		self.assertEqual({"cause": "dialog_bad_reply"}, ctx.exception.details)
		assert_no_sentinel(self, ctx.exception)

	def test_exit_without_answer(self):
		with self.assertRaises(PinPromptUnavailable) as ctx:
			pin.request_pin(ORIGIN, "MODE:exit:3", host=self.host)
		self.assertEqual({"cause": "dialog_process_failed"}, ctx.exception.details)

	def test_invalid_request_is_refused_without_spawn(self):
		with self.assertRaises(PinPromptUnavailable) as ctx:
			pin.request_pin("https://evil.example‮", "INV-1", host=self.host)
		self.assertEqual({"cause": "dialog_request_invalid"}, ctx.exception.details)


if __name__ == "__main__":
	unittest.main()
