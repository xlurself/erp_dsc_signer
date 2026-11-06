"""PIN retention in the daemon's dialog plumbing (spec 001 §5, §6, I1, I2, I7).

(a) After EVERY classifier path -- success, linger-then-kill, cancel, deadline,
    shutdown (before and after a complete PIN line), oversize, a second line, bad
    JSON, a stray key, a valid PIN line followed by exit 3 or by a crash -- the reply
    buffer the daemon kept is zeroed, and the PIN bytes demonstrably reached it first
    (so the check is never vacuous).
(b) Every DialogFailed / PinPromptUnavailable raised on the PIN path is walked frame by
    frame (tests/_frames.py): no erp_dsc_local frame local, nor anything it references,
    still holds the PIN as str or bytes.
(c) After a SUCCESS (no exception to walk) the whole reachable heap is scanned
    (_frames.heap_hits): no str / bytes / bytearray / memoryview other than the returned
    PIN str and this module's constants holds the PIN -- a copy kept in a module global
    is found.
(d) The child's stdout is wrapped in _frames.ReadintoOnly for every test here, so the
    reader cannot copy the reply through read() chunks: it must readinto() the buffer.

The child is a stdlib-only script written to a temp dir with the PIN baked in, so the
PIN never travels in the request (a request holding it would itself be a frame hit).
"""

import os
import shutil
import tempfile
import textwrap
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child, pin, ui
from erp_dsc_local.errors import DialogFailed, PinCancelled, PinPromptUnavailable

try:
	from _frames import ReadintoOnly, assert_no_sentinel_in_frames, assert_no_sentinel_on_heap, heap_hits, raised, sentinel_hits
except ImportError:  # run as tests.test_pin_retention
	from tests._frames import (
		ReadintoOnly,
		assert_no_sentinel_in_frames,
		assert_no_sentinel_on_heap,
		heap_hits,
		raised,
		sentinel_hits,
	)


SENTINEL = "RETAIN-PIN-5150-SENTINEL"
SENTINEL_BYTES = SENTINEL.encode("utf-8")
ORIGIN = "https://retention.example"

CHILD_SCRIPT = textwrap.dedent(
	"""
	import json, os, signal, sys, time

	PIN = {pin!r}
	CAP = {cap!r}

	def write(data):
		view = memoryview(data)
		while view:
			view = view[os.write(1, view):]

	def hang():
		while True:
			time.sleep(1)

	raw = sys.stdin.buffer.readline()
	mode = json.loads(raw)["claims"][0]
	head = b'{{"v":1,"kind":"pin","result":"entered","value":"' + PIN.encode()
	line = head + b'"}}\\n'
	if mode == "entered":
		write(line)
	elif mode == "entered_then_hang":
		write(line)
		hang()
	elif mode == "entered_exit3":
		write(line)
		os._exit(3)
	elif mode == "entered_crash":
		write(line)
		os.kill(os.getpid(), signal.SIGKILL)
		hang()
	elif mode == "cancelled":
		write(b'{{"v":1,"kind":"pin","result":"cancelled"}}\\n')
	elif mode == "partial_hang":
		write(head)
		hang()
	elif mode == "oversize":
		write(head + b"x" * (CAP + 64))
		hang()
	elif mode == "extra_line":
		write(line + line)
	elif mode == "badjson":
		write(head + b'"\\n')
	elif mode == "stray_key":
		write(head + b'","cause":"tk_init_failed"}}\\n')
	else:
		os._exit(8)
	os._exit(0)
	"""
)

# mode -> (expected outcome, did the PIN bytes reach the buffer?)
FAILURES = {
	"entered_exit3": ("dialog_process_failed", True),
	"entered_crash": ("dialog_process_crashed", True),
	"partial_hang": ("dialog_timeout", True),
	"oversize": ("dialog_bad_reply", True),
	"extra_line": ("dialog_bad_reply", True),
	"badjson": ("dialog_bad_reply", True),
	"stray_key": ("dialog_bad_reply", True),
}


def request(mode):
	return {
		"v": 1,
		"kind": "pin",
		"origin": ORIGIN,
		"claims": [mode],
		"warnings": [],
		"final_try": False,
		"timeout": 0,
	}


def wait_for(predicate, timeout=5.0):
	end = time.monotonic() + timeout
	while time.monotonic() < end:
		if predicate():
			return True
		time.sleep(0.01)
	return predicate()


class RetentionCase(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.tmp = tempfile.mkdtemp(prefix="erp-dsc-retention-")
		cls.script = Path(cls.tmp) / "retention_child.py"
		cls.script.write_text(CHILD_SCRIPT.format(pin=SENTINEL, cap=dialog_child.MAX_REPLY_BYTES), encoding="utf-8")

	@classmethod
	def tearDownClass(cls):
		shutil.rmtree(cls.tmp, ignore_errors=True)

	def setUp(self):
		self.patch_timing(startup=0.8, grace=0.3, kill_delay=0.5)
		self.host = ui.DialogHost(child_script=self.script)
		self.children = []
		spawn = self.host._spawn

		def capture():
			child = spawn()
			if child is not None:
				# Before the reader thread starts (_supervise starts it after _spawn).
				child.proc.stdout = ReadintoOnly(child.proc.stdout)
				self.children.append(child)
			return child

		self.host._spawn = capture

	def patch_timing(self, *, startup, grace, kill_delay):
		for target, name, value in (
			(ui, "STARTUP_ALLOWANCE_SECONDS", startup),
			(ui, "GRACE_SECONDS", grace),
			(ui, "KILL_DELAY_SECONDS", kill_delay),
			(dialog_child, "MIN_DIALOG_SECONDS", 0),
			(dialog_child, "DEFAULT_DIALOG_SECONDS", 0),  # pin.request_pin's timeout
		):
			patcher = mock.patch.object(target, name, value)
			patcher.start()
			self.addCleanup(patcher.stop)

	def outcome(self, fn):
		try:
			return fn(), None
		except (DialogFailed, PinPromptUnavailable, PinCancelled) as exc:
			return None, exc

	def assertBufferWiped(self, child, *, reached):
		self.assertTrue(wait_for(lambda: child.reader_done), "the reader thread finished")
		self.assertTrue(child.wiped)
		if reached:
			self.assertGreaterEqual(child.filled, len(SENTINEL_BYTES), "the PIN bytes reached the buffer first")
		self.assertEqual(len(child.buffer), dialog_child.MAX_REPLY_BYTES + 1, "never reallocated")
		self.assertNotIn(SENTINEL_BYTES, child.buffer)
		self.assertEqual(bytes(len(child.buffer)), bytes(child.buffer), "every byte zeroed")
		self.assertEqual([], [name for name in ("line",) if hasattr(child, name)], "no line copy is kept")


class TestBuffersAreWipedOnEveryPath(RetentionCase):
	def test_success_returns_the_pin_and_wipes_the_buffer(self):
		for mode in ("entered", "entered_then_hang"):  # exit 0; reply then linger -> killed
			with self.subTest(mode=mode):
				reply = self.host.run_dialog(request(mode))
				self.assertEqual(SENTINEL, reply["value"], "the parsed str is the one intended copy")
				self.assertBufferWiped(self.children[-1], reached=True)
				assert_no_sentinel_on_heap(SENTINEL, exclude=(SENTINEL, SENTINEL_BYTES, reply["value"]))
				reply = None

	def test_cancel_wipes_the_buffer(self):
		self.assertEqual("cancelled", self.host.run_dialog(request("cancelled"))["result"])
		self.assertBufferWiped(self.children[-1], reached=False)

	def test_every_failure_path_wipes_the_buffer(self):
		for mode, (cause, reached) in FAILURES.items():
			with self.subTest(mode=mode):
				_reply, exc = self.outcome(lambda: self.host.run_dialog(request(mode)))
				self.assertIsInstance(exc, DialogFailed)
				self.assertEqual(cause, exc.cause)
				self.assertBufferWiped(self.children[-1], reached=reached)

	def shutdown_once(self, mode, ready):
		thread_box = {}

		def run():
			thread_box["outcome"] = self.outcome(lambda: self.host.run_dialog(request(mode)))

		thread = threading.Thread(target=run, daemon=True)
		thread.start()
		self.assertTrue(wait_for(lambda: self.children and ready(self.children[-1])))
		self.host.shutdown()
		thread.join(10)
		self.assertFalse(thread.is_alive())
		return thread_box["outcome"]

	def test_shutdown_wipes_the_buffer_with_a_partial_or_a_complete_pin_line(self):
		cases = {
			"partial_hang": lambda child: child.filled >= len(SENTINEL_BYTES),
			"entered_then_hang": lambda child: child.line_complete,  # inside the grace wait
		}
		for mode, ready in cases.items():
			with self.subTest(mode=mode):
				self.patch_timing(startup=5.0, grace=5.0, kill_delay=0.5)
				self.host = ui.DialogHost(child_script=self.script)
				spawn = self.host._spawn
				self.host._spawn = lambda spawn=spawn: self.children.append(spawn()) or self.children[-1]
				_reply, exc = self.shutdown_once(mode, ready)
				self.assertIsInstance(exc, DialogFailed)
				self.assertEqual("dialog_shutdown", exc.cause)
				self.assertBufferWiped(self.children[-1], reached=True)

	def test_wipe_runs_even_when_the_classifier_raises(self):
		with mock.patch.object(ui.DialogHost, "_classify", side_effect=RuntimeError("boom")):
			with self.assertRaises(RuntimeError):
				self.host.run_dialog(request("entered"))
		self.assertBufferWiped(self.children[-1], reached=True)

	def test_a_reader_still_running_after_the_wipe_wipes_again_on_exit(self):
		read_end, write_end = os.pipe()
		proc = types.SimpleNamespace(stdout=ReadintoOnly(os.fdopen(read_end, "rb", buffering=0)))
		self.addCleanup(proc.stdout.close)
		child = ui._Child(proc, 0.0, None)
		thread = threading.Thread(target=ui._read_reply, args=(child,), daemon=True)
		thread.start()
		child.wipe()  # the supervisor gave up on a reader that is still blocked
		os.write(write_end, b'{"value":"' + SENTINEL_BYTES)
		os.close(write_end)
		thread.join(5)
		self.assertFalse(thread.is_alive())
		self.assertBufferWiped(child, reached=True)


class TestNoFrameHoldsThePin(RetentionCase):
	def test_dialog_failed_frames(self):
		for mode, (cause, _reached) in FAILURES.items():
			with self.subTest(mode=mode):
				_reply, exc = self.outcome(lambda: self.host.run_dialog(request(mode)))
				self.assertIsInstance(exc, DialogFailed)
				self.assertEqual(cause, exc.cause)
				self.assertIsNotNone(exc.__traceback__)
				assert_no_sentinel_in_frames(exc, SENTINEL)

	def test_pin_prompt_unavailable_frames(self):
		for mode, (cause, _reached) in FAILURES.items():
			with self.subTest(mode=mode):
				_value, exc = self.outcome(lambda: pin.request_pin(ORIGIN, mode, host=self.host))
				self.assertIsInstance(exc, PinPromptUnavailable)
				self.assertEqual(cause, exc.details["cause"])
				assert_no_sentinel_in_frames(exc, SENTINEL)

	def test_shutdown_frames(self):
		self.patch_timing(startup=5.0, grace=5.0, kill_delay=0.5)
		box = {}

		def run():
			box["outcome"] = self.outcome(lambda: pin.request_pin(ORIGIN, "entered_then_hang", host=self.host))

		thread = threading.Thread(target=run, daemon=True)
		thread.start()
		self.assertTrue(wait_for(lambda: self.children and self.children[-1].line_complete))
		self.host.shutdown()
		thread.join(10)
		_value, exc = box["outcome"]
		self.assertIsInstance(exc, PinPromptUnavailable)
		self.assertEqual("dialog_shutdown", exc.details["cause"])
		assert_no_sentinel_in_frames(exc, SENTINEL)

	def test_success_leaves_no_reachable_copy_but_the_returned_str(self):
		value = pin.request_pin(ORIGIN, "entered", host=self.host)
		self.assertEqual(SENTINEL, value)
		self.assertBufferWiped(self.children[-1], reached=True)
		assert_no_sentinel_on_heap(SENTINEL, exclude=(SENTINEL, SENTINEL_BYTES, value))


class TestFrameHelperCanFail(unittest.TestCase):
	"""The helper must find what it is meant to find, or every test above is vacuous."""

	def raised_holding(self, value):
		def holder(secret):
			kept = secret  # noqa: F841 - the frame local under test
			raise DialogFailed("dialog_bad_reply")

		try:
			holder(value)
		except DialogFailed as exc:
			return exc
		raise AssertionError("not raised")

	def test_finds_str_bytes_bytearray_memoryview_and_nested_slots(self):
		slotted = ui._Child(types.SimpleNamespace(), 0.0, None)
		slotted.buffer[:4] = b"PIN:"
		slotted.buffer[4 : 4 + len(SENTINEL_BYTES)] = SENTINEL_BYTES
		samples = {
			"str": "x" + SENTINEL,
			"bytes": SENTINEL_BYTES,
			"bytearray": bytearray(SENTINEL_BYTES),
			"memoryview": memoryview(bytearray(SENTINEL_BYTES)),
			"dict value": {"value": SENTINEL},
			"slots": slotted,
		}
		for name, value in samples.items():
			with self.subTest(name):
				exc = self.raised_holding(value)
				hits = sentinel_hits(exc, SENTINEL, package_only=False)
				self.assertTrue(hits, name)
				self.assertNotIn(SENTINEL, " ".join(hits), "a hit report never repeats the value")
				with self.assertRaises(AssertionError):
					assert_no_sentinel_in_frames(exc, SENTINEL, package_only=False)

	def test_finds_a_closure_cell(self):
		secret = bytearray(SENTINEL_BYTES)
		exc = self.raised_holding(lambda: secret)
		self.assertTrue(sentinel_hits(exc, SENTINEL, package_only=False))

	def test_a_zeroed_buffer_passes(self):
		exc = self.raised_holding(bytearray(len(SENTINEL_BYTES)))
		assert_no_sentinel_in_frames(exc, SENTINEL, package_only=False)

	def test_package_only_skips_test_frames(self):
		exc = self.raised_holding(SENTINEL)
		assert_no_sentinel_in_frames(exc, SENTINEL)  # the holder frame is a test frame

	def test_finds_a_package_frame_local(self):
		# _supervise's `child` local, with the pre-fix behaviour: the classifier returned
		# early and nothing wiped the buffer.
		child = ui._Child(types.SimpleNamespace(), 0.0, None)
		child.buffer[: len(SENTINEL_BYTES)] = SENTINEL_BYTES
		host = ui.DialogHost(child_script="unused")
		host._spawn = lambda: child
		with mock.patch.object(ui, "_start_thread"), mock.patch.object(ui.DialogHost, "_watch"), mock.patch.object(
			ui.DialogHost, "_stop"
		), mock.patch.object(ui._Child, "wipe"), mock.patch.object(ui.DialogHost, "_classify", return_value="dialog_process_failed"):
			exc = raised(DialogFailed, host._supervise, b"", "pin", 0)
		hits = sentinel_hits(exc, SENTINEL)
		self.assertTrue(any("_supervise" in hit and "child" in hit for hit in hits), hits)
		with self.assertRaises(AssertionError):
			assert_no_sentinel_in_frames(exc, SENTINEL)

	def test_refuses_an_exception_whose_frames_were_stripped(self):
		with self.assertRaises(DialogFailed) as cm:
			raise DialogFailed("dialog_bad_reply")
		with self.assertRaises(ValueError):
			assert_no_sentinel_in_frames(cm.exception, SENTINEL)  # assertRaises removed the traceback
		exc = self.raised_holding(SENTINEL)
		import traceback

		traceback.clear_frames(exc.__traceback__)
		with self.assertRaises(ValueError):
			assert_no_sentinel_in_frames(exc, SENTINEL, package_only=False)


class TestHeapScanCanFail(unittest.TestCase):
	"""heap_hits / ReadintoOnly must catch what they are meant to, or (c) and (d) are vacuous."""

	CONSTANTS = (SENTINEL, SENTINEL_BYTES)

	def kept_in_a_module_global(self, value):
		"""heap_hits while `value` sits in a global of erp_dsc_local.ui (the M14 mutant), then after."""
		with mock.patch.object(ui, "_HEAP_PROBE", value, create=True):
			value = None
			during = heap_hits(SENTINEL, exclude=self.CONSTANTS)
		after = heap_hits(SENTINEL, exclude=self.CONSTANTS)
		return during, after

	def test_finds_every_kind_of_kept_copy_and_nothing_once_it_is_dropped(self):
		samples = {
			"bytes": lambda: b'{"value":"' + SENTINEL_BYTES + b'"}',
			"bytearray": lambda: bytearray(b"line:" + SENTINEL_BYTES),
			"memoryview": lambda: memoryview(bytearray(b"line:" + SENTINEL_BYTES)),
			"str": lambda: "line:" + SENTINEL,
			"bytes in a list": lambda: [b"line:" + SENTINEL_BYTES],
			"bytearray in a dict": lambda: {"line": bytearray(b"line:" + SENTINEL_BYTES)},
			"closure cell": lambda: (lambda kept: (lambda: kept))(b"line:" + SENTINEL_BYTES),
		}
		for name, make in samples.items():
			with self.subTest(name):
				during, after = self.kept_in_a_module_global(make())
				self.assertTrue(during, "the scan must find a kept " + name)
				self.assertNotIn(SENTINEL, " ".join(during), "a hit report never repeats the value")
				self.assertEqual([], after)
				with self.assertRaises(AssertionError):
					with mock.patch.object(ui, "_HEAP_PROBE", make(), create=True):
						assert_no_sentinel_on_heap(SENTINEL, exclude=self.CONSTANTS)

	def test_exclude_is_what_lets_the_test_constants_through(self):
		self.assertTrue(heap_hits(SENTINEL), "this module's own SENTINEL constants are found")
		self.assertEqual([], heap_hits(SENTINEL, exclude=self.CONSTANTS))

	def test_readinto_only_offers_no_copying_read(self):
		import io

		proxy = ReadintoOnly(io.BytesIO(b"line\n"))
		for name in ("read", "read1", "readline", "readlines", "readall", "fileno", "raw"):
			self.assertFalse(hasattr(proxy, name), name)
		buffer = bytearray(8)
		self.assertEqual(5, proxy.readinto(buffer))
		self.assertEqual(b"line\n", bytes(buffer[:5]))


if __name__ == "__main__":
	unittest.main()
