"""The PIN-free PKCS#11 reads run in a short-lived child with a hard wall-clock timeout.

2026-11-10: the WatchData library hung inside C_GetSlotList after a token swap; the daemon
thread waited forever and /v1/health stopped answering.  ``TokenClient.certificates()``
and ``token_state()`` now run that work in ``token_probe.py`` (a child process); the
daemon never loads the vendor library for them.  These tests spawn REAL children (stub
scripts, and the real ``token_probe.py``) and check: a hung child is killed with its
whole process group inside the limit and the caller gets ONE fixed message; nothing the
child prints or raises reaches that message; malformed, oversized or extra replies are
refused; the child runs isolated with its input on stdin only.
"""

import base64
import io
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from _probe_inproc import in_process_transport
from erp_dsc_local import service as service_module
from erp_dsc_local import token, token_probe
from erp_dsc_local.errors import CertificatesHidden, TokenUnavailable
from erp_dsc_local.token import DRIVER_NOT_RESPONDING, TokenClient, TokenDriverNotResponding

import test_service_http as http_tests

MARKER = "CHILD-TEXT-MARKER-93ad"
MODULE_PATH = "/Library/Vendor/libvendor.dylib"
PROBE_FILE = str(Path(token_probe.__file__).resolve())
POSIX = os.name != "nt"

try:
	import PyKCS11  # noqa: F401

	HAVE_PYKCS11 = True
except ImportError:
	HAVE_PYKCS11 = False

# Stand-in PKCS#11 pieces for stubs that run the REAL token_probe.main with a fake library.
FAKE_PK_SOURCE = """
class PK:
	CKF_SERIAL_SESSION = 4
	CKA_CLASS = 0
	CKA_LABEL = 3
	CKA_VALUE = 0x11
	CKA_ID = 0x102
	CKO_CERTIFICATE = 1

	class PyKCS11Error(Exception):
		def __init__(self, value, text=""):
			super().__init__(value, text)
			self.value = value
"""

LOAD_REAL_PROBE = """
import importlib.util
spec = importlib.util.spec_from_file_location("token_probe_under_test", {probe!r})
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
"""


def gone(pid, within=5.0):
	"""True once no process has ``pid`` (a zombie still counts as present)."""
	deadline = time.monotonic() + within
	while True:
		try:
			os.kill(pid, 0)
		except ProcessLookupError:
			return True
		except PermissionError:
			return True  # the pid now belongs to another user's process: ours is gone
		if time.monotonic() > deadline:
			return False
		time.sleep(0.05)


def chain(error):
	seen = []
	while error is not None and error not in seen:
		seen.append(error)
		error = error.__cause__ or error.__context__
	return seen


class StubCase(unittest.TestCase):
	def setUp(self):
		self._dir = tempfile.TemporaryDirectory()
		self.addCleanup(self._dir.cleanup)
		self.dir = Path(self._dir.name)
		self.stderr = io.StringIO()
		patcher = mock.patch.object(sys, "stderr", self.stderr)
		patcher.start()
		self.addCleanup(patcher.stop)

	def stub(self, body, **values):
		"""Write a stub child script and point ``token.PROBE_SCRIPT`` at it."""
		path = self.dir / f"stub_{len(list(self.dir.iterdir()))}.py"
		path.write_text(body.format(**values), encoding="utf-8")
		patcher = mock.patch.object(token, "PROBE_SCRIPT", str(path))
		patcher.start()
		self.addCleanup(patcher.stop)
		return path

	def kill_later(self, *pids):
		for pid in pids:
			self.addCleanup(_kill_quietly, pid)

	def assert_fixed_failure(self, error):
		self.assertIsInstance(error, TokenDriverNotResponding)
		self.assertIsInstance(error, TokenUnavailable)
		self.assertEqual("TOKEN_UNAVAILABLE", error.code)
		self.assertEqual(409, error.status)
		self.assertEqual(DRIVER_NOT_RESPONDING, error.message)
		self.assertEqual(DRIVER_NOT_RESPONDING, str(error))
		self.assertEqual({"ok": False, "error": {"code": "TOKEN_UNAVAILABLE", "message": DRIVER_NOT_RESPONDING}}, error.as_dict())
		self.assertIsNone(error.__cause__)
		self.assertIsNone(error.__context__)

	def probe_failure(self, op="certificates", timeout=5.0):
		with self.assertRaises(TokenDriverNotResponding) as ctx:
			token.run_probe(MODULE_PATH, op, timeout=timeout)
		return ctx.exception


def _kill_quietly(pid):
	try:
		os.kill(pid, signal.SIGKILL)
	except OSError:
		pass


def _kill_quietly_all(pids):
	for pid in pids:
		_kill_quietly(int(pid))


HUNG_STUB = """
import os, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
grandchild = subprocess.Popen(
	[sys.executable, "-I", "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"]
)
with open({pids!r} + ".tmp", "w") as handle:
	handle.write(f"{{os.getpid()}} {{grandchild.pid}}")
os.replace({pids!r} + ".tmp", {pids!r})
os.write(2, b"{marker} stderr")
while True:
	time.sleep(1)
"""


@unittest.skipUnless(POSIX, "process-group kill is POSIX")
class HungChildTests(StubCase):
	def test_hung_child_and_its_process_group_are_killed_within_the_limit(self):
		pids = self.dir / "pids"
		# Registered first: even if an assertion below fails, no stub process outlives the test.
		self.addCleanup(lambda: pids.exists() and _kill_quietly_all(pids.read_text().split()))
		self.stub(HUNG_STUB, pids=str(pids), marker=MARKER)
		limit = 1.5
		started = time.monotonic()
		error = self.probe_failure(timeout=limit)
		elapsed = time.monotonic() - started
		child, grandchild = (int(value) for value in pids.read_text().split())
		self.assert_fixed_failure(error)
		self.assertGreaterEqual(elapsed, limit - 0.05, "returned before the limit: not the timeout path")
		self.assertLess(elapsed, limit + token.PROBE_KILL_WAIT_SECONDS + 1.0)
		self.assertTrue(gone(child), "the child (which ignores SIGTERM) was left running or unreaped")
		self.assertTrue(gone(grandchild), "a process in the child's group survived")
		with self.assertRaises(ChildProcessError):
			os.waitpid(child, os.WNOHANG)  # already reaped: no zombie left behind
		self.assertNotIn(MARKER, self.stderr.getvalue())
		self.assertIn("reason=timeout", self.stderr.getvalue())

	def test_real_probe_child_over_a_hung_library_times_out(self):
		mark = self.dir / "in_getSlotList"
		body = FAKE_PK_SOURCE + LOAD_REAL_PROBE + """
import time
class HungLib:
	def getSlotList(self, tokenPresent=True):
		open({mark!r}, "w").close()
		while True:
			time.sleep(1)
probe.main(load=lambda path: (PK, HungLib()))
"""
		self.stub(body, probe=PROBE_FILE, mark=str(mark))
		for op in ("certificates", "token_state"):
			with self.subTest(op=op):
				mark.unlink(missing_ok=True)
				started = time.monotonic()
				error = self.probe_failure(op=op, timeout=1.5)
				self.assertLess(time.monotonic() - started, 1.5 + token.PROBE_KILL_WAIT_SECONDS + 1.0)
				self.assert_fixed_failure(error)
				self.assertTrue(mark.exists(), "the hang was not inside C_GetSlotList of the real child")

	def test_driver_output_on_stdout_cannot_corrupt_the_reply(self):
		body = FAKE_PK_SOURCE + LOAD_REAL_PROBE + """
import os
class ChattyLib:
	def getSlotList(self, tokenPresent=True):
		os.write(1, b"vendor debug: C_GetSlotList\\n")
		print("vendor debug via print", flush=True)
		return []
probe.main(load=lambda path: (PK, ChattyLib()))
"""
		self.stub(body, probe=PROBE_FILE)
		reply = token.run_probe(MODULE_PATH, "certificates", timeout=5.0)
		self.assertEqual({"result": "ok", "slots": []}, reply)

	def test_child_arms_its_own_alarm_so_it_dies_if_the_daemon_does(self):
		body = FAKE_PK_SOURCE + LOAD_REAL_PROBE + """
import time
class HungLib:
	def getSlotList(self, tokenPresent=True):
		while True:
			time.sleep(1)
probe.main(load=lambda path: (PK, HungLib()))
"""
		script = self.stub(body, probe=PROBE_FILE)
		proc = subprocess.Popen(
			token.probe_command(str(script)), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
		)
		self.kill_later(proc.pid)
		proc.stdin.write(token_probe.encode_request("certificates", MODULE_PATH, alarm=1))
		proc.stdin.close()
		try:
			code = proc.wait(timeout=5)
		finally:
			proc.stdout.close()
		self.assertEqual(-signal.SIGALRM, code)

class ChildOutputTests(StubCase):
	def test_stdout_stderr_and_exit_code_never_reach_the_message(self):
		self.stub(
			"""
import os, sys
sys.stdin.buffer.read()
os.write(2, b"{marker} on stderr")
os.write(1, b"{marker} not json\\n")
raise SystemExit("{marker} exception text")
""",
			marker=MARKER,
		)
		error = self.probe_failure()
		self.assert_fixed_failure(error)
		for link in chain(error):
			self.assertNotIn(MARKER, str(link))
			self.assertNotIn(MARKER, repr(link.args))
		self.assertNotIn(MARKER, self.stderr.getvalue())

	def test_well_formed_reply_with_an_extra_field_is_refused(self):
		reply = {"v": 1, "op": "certificates", "result": "ok", "slots": [], "note": MARKER}
		self.stub("import os, sys\nsys.stdin.buffer.read()\nos.write(1, {line!r})\n", line=json.dumps(reply).encode() + b"\n")
		error = self.probe_failure()
		self.assert_fixed_failure(error)
		self.assertNotIn(MARKER, str(error.as_dict()))

	def test_two_reply_lines_are_refused(self):
		line = json.dumps({"v": 1, "op": "certificates", "result": "ok", "slots": []}).encode() + b"\n"
		self.stub("import os, sys\nsys.stdin.buffer.read()\nos.write(1, {line!r})\n", line=line * 2)
		self.assert_fixed_failure(self.probe_failure())

	def test_child_that_exits_without_a_reply_is_refused(self):
		self.stub("import sys\nsys.stdin.buffer.read()\n")
		self.assert_fixed_failure(self.probe_failure())
		self.assertIn("reason=no_reply", self.stderr.getvalue())

	def test_child_that_cannot_start_is_refused(self):
		patcher = mock.patch.object(token, "probe_command", lambda script=None: [str(self.dir / "no-such-python")])
		patcher.start()
		self.addCleanup(patcher.stop)
		self.assert_fixed_failure(self.probe_failure())
		self.assertIn("reason=spawn", self.stderr.getvalue())

	def _failed_slots_reply(self, size):
		"""A VALID reply of exactly ``size`` bytes (newline included): every slot failed."""
		entry = {"slot": 0, "failed": True, "ckr": None}
		head = {"v": 1, "op": "certificates", "result": "ok", "slots": []}
		one = len(json.dumps(entry, separators=(",", ":"))) + 1
		count = (size - len(json.dumps(head, separators=(",", ":"))) - 1) // one
		head["slots"] = [entry] * count
		line = json.dumps(head, separators=(",", ":")).encode()
		pad = size - len(line) - 1
		self.assertGreaterEqual(pad, 0)
		return line + b" " * pad + b"\n"

	def test_reply_over_the_size_cap_is_refused_even_if_well_formed(self):
		line = self._failed_slots_reply(token_probe.MAX_REPLY_BYTES + 1)
		self.assertEqual(token_probe.MAX_REPLY_BYTES + 1, len(line))
		self.stub("import os, sys\nsys.stdin.buffer.read()\nview = memoryview({line!r})\nwhile view:\n\tview = view[os.write(1, view):]\n", line=line)
		self.assert_fixed_failure(self.probe_failure())
		self.assertIn("reason=oversize", self.stderr.getvalue())

	def test_reply_at_the_size_cap_is_accepted(self):
		line = self._failed_slots_reply(token_probe.MAX_REPLY_BYTES)
		self.stub("import os, sys\nsys.stdin.buffer.read()\nview = memoryview({line!r})\nwhile view:\n\tview = view[os.write(1, view):]\n", line=line)
		reply = token.run_probe(MODULE_PATH, "certificates", timeout=5.0)
		self.assertEqual("ok", reply["result"])

	def test_child_receives_the_request_on_stdin_only(self):
		capture = self.dir / "capture.json"
		self.stub(
			"""
import json, os, sys
request = sys.stdin.buffer.read()
with open({capture!r}, "w") as handle:
	json.dump({{"argv": sys.argv, "env": dict(os.environ), "cwd": os.getcwd(), "request": request.decode(), "flags": sys.flags.isolated}}, handle)
os.write(1, b'{{"v":1,"op":"certificates","result":"ok","slots":[]}}\\n')
""",
			capture=str(capture),
		)
		polluted = {"PYTHONPATH": "/evil", "DYLD_LIBRARY_PATH": "/evil", "LD_PRELOAD": "/evil.so", "SECRET_TOKEN": MARKER}
		with mock.patch.dict(os.environ, polluted):
			with self.assertRaises(TokenUnavailable):  # ok with no slots: no token connected
				client = TokenClient.__new__(TokenClient)
				client.module = SimpleNamespace(path=MODULE_PATH, label="libvendor.dylib")
				client.certificates()
		seen = json.loads(capture.read_text())
		self.assertEqual(1, seen["flags"])
		self.assertNotIn(MODULE_PATH, " ".join(seen["argv"]))
		for name in polluted:
			self.assertNotIn(name, seen["env"])
		self.assertNotIn(MARKER, json.dumps(seen["env"]))
		self.assertEqual(os.path.abspath(os.sep), seen["cwd"])
		request = json.loads(seen["request"])
		self.assertEqual({"v", "op", "module_path", "alarm"}, set(request))
		self.assertEqual((MODULE_PATH, "certificates"), (request["module_path"], request["op"]))
		self.assertEqual(math.ceil(token.PROBE_TIMEOUT_SECONDS) + token.PROBE_KILL_WAIT_SECONDS + 1, request["alarm"])


@unittest.skipUnless(HAVE_PYKCS11, "PyKCS11 is not installed")
class RealChildTests(StubCase):
	"""The REAL token_probe.py child with the REAL PyKCS11 (no stub, no fake library)."""

	def test_missing_library_is_unable_to_load_without_the_path(self):
		missing = str(self.dir / "no-such-pkcs11.dylib")
		with self.assertRaises(TokenUnavailable) as ctx:
			TokenClient(SimpleNamespace(path=missing, label="libmissing.dylib")).certificates()
		self.assertNotIsInstance(ctx.exception, TokenDriverNotResponding)
		self.assertEqual("Unable to load the selected token middleware (libmissing.dylib).", ctx.exception.message)
		self.assertNotIn(str(self.dir), str(ctx.exception.as_dict()))

	def test_missing_library_in_token_state_is_token_not_available(self):
		missing = str(self.dir / "no-such-pkcs11.dylib")
		client = TokenClient(SimpleNamespace(path=missing, label="libmissing.dylib"))
		with self.assertRaises(TokenUnavailable) as ctx:
			client.token_state(SimpleNamespace(slot_id=1, token_serial="SER"))
		self.assertEqual(token.TOKEN_NOT_AVAILABLE, ctx.exception.message)


class RequestTests(unittest.TestCase):
	def setUp(self):
		patcher = mock.patch.object(sys, "stderr", io.StringIO())
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_relative_or_odd_module_path_is_refused_before_any_load(self):
		loads = []

		def load(path):
			loads.append(path)
			raise AssertionError("must not load")

		for path in ("libvendor.dylib", "./libvendor.dylib", "", "/x\x00/lib.dylib", "/" + "a" * 5000):
			with self.subTest(path=path[:40]):
				raw = json.dumps({"v": 1, "op": "certificates", "module_path": path, "alarm": 5}).encode() + b"\n"
				reply = json.loads(token_probe.handle(raw, load=load))
				self.assertEqual("bad_request", reply["result"])
		self.assertEqual([], loads)

	def test_malformed_requests_are_refused_before_any_load(self):
		loads = []
		good = {"v": 1, "op": "certificates", "module_path": MODULE_PATH, "alarm": 5}
		bad = [
			b"not json\n",
			b'{"v":1,"v":1,"op":"certificates","module_path":"/x","alarm":5}\n',
			json.dumps({**good, "extra": 1}).encode() + b"\n",
			json.dumps({**good, "op": "sign"}).encode() + b"\n",
			json.dumps({**good, "alarm": 0}).encode() + b"\n",
			json.dumps({**good, "alarm": True}).encode() + b"\n",
			json.dumps({**good, "v": 2}).encode() + b"\n",
			json.dumps(good).encode(),  # no newline
			b"x" * (token_probe.MAX_REQUEST_BYTES + 1),
		]
		for raw in bad:
			with self.subTest(raw=raw[:60]):
				reply = json.loads(token_probe.handle(raw, load=lambda path: loads.append(path)))
				self.assertEqual("bad_request", reply["result"])
		self.assertEqual([], loads)

	def test_timeout_constant_is_the_default_limit(self):
		self.assertEqual(15, token.PROBE_TIMEOUT_SECONDS)
		seen = []

		def transport(request, timeout):
			seen.append(timeout)
			return "timeout", None

		with self.assertRaises(TokenDriverNotResponding):
			token.run_probe(MODULE_PATH, "certificates", transport=transport)
		self.assertEqual([15], seen)

	def test_module_path_comes_from_the_resolved_module_only(self):
		captured = []

		def transport(request, timeout):
			captured.append(json.loads(request))
			return "timeout", None

		client = TokenClient.__new__(TokenClient)
		client.module = SimpleNamespace(path=os.path.abspath("/opt/registry/libpkcs11.so"), label="libpkcs11.so")
		with mock.patch.object(token, "_spawn_probe", transport):
			with self.assertRaises(TokenDriverNotResponding):
				client.certificates()
		self.assertEqual("/opt/registry/libpkcs11.so", captured[0]["module_path"])


class NoVendorLibraryInDaemonTests(unittest.TestCase):
	"""``TokenClient(module)`` + ``certificates()`` + ``token_state()`` never load the
	vendor library in this process: PyKCS11Lib is not even constructed."""

	def test_reads_never_construct_pykcs11lib_in_the_daemon(self):
		constructed = []

		class Forbidden:
			def __init__(self):
				constructed.append(True)
				raise AssertionError("the daemon loaded the vendor library")

		fake = SimpleNamespace(PyKCS11Lib=Forbidden, PyKCS11Error=Exception, CKR={})
		child_pk = SimpleNamespace(CKF_SERIAL_SESSION=4, CKA_CLASS=0, CKO_CERTIFICATE=1, PyKCS11Error=Exception)

		class ChildLib:
			def getSlotList(self, tokenPresent=True):
				return [2]

			def getTokenInfo(self, slot):
				return SimpleNamespace(label="T", serialNumber="SER", flags=7)

			def openSession(self, slot, flags):
				return SimpleNamespace(findObjects=lambda template: [], closeSession=lambda: None)

		transport = in_process_transport(lambda path: (child_pk, ChildLib()))
		with mock.patch.dict(sys.modules, {"PyKCS11": fake}):
			with mock.patch.object(token, "_spawn_probe", transport):
				client = TokenClient(SimpleNamespace(path=MODULE_PATH, label="libvendor.dylib"))
				with self.assertRaises(CertificatesHidden):
					client.certificates()
				self.assertEqual((7, "SER"), client.token_state(SimpleNamespace(slot_id=2, token_serial="SER")))
		self.assertEqual([], constructed)
		self.assertIsNone(client.lib)


class ParseReplyTests(unittest.TestCase):
	def ok(self, slots, op="certificates"):
		return {"v": 1, "op": op, "result": "ok", "slots": slots}

	def parse(self, obj, op="certificates"):
		line = obj if isinstance(obj, bytes) else json.dumps(obj).encode() + b"\n"
		return token._parse_probe_reply(line, op)

	def assert_refused(self, obj, op="certificates"):
		self.assertIs(token._BAD_PROBE_REPLY, self.parse(obj, op))

	def test_valid_certificate_reply_is_decoded(self):
		der = base64.b64encode(b"\x30\x82").decode()
		slot = {"slot": 3, "label": "WD ", "serial": "S1", "objects": [None, {"der": der, "key_id": "", "label": "x"}], "failed": False, "ckr": None}
		parsed = self.parse(self.ok([slot, {"slot": 4, "failed": True, "ckr": 5}]))
		self.assertEqual(b"\x30\x82", parsed["slots"][0]["objects"][1]["der"])
		self.assertEqual(b"", parsed["slots"][0]["objects"][1]["key_id"])
		self.assertIsNone(parsed["slots"][1]["objects"])

	def test_structural_violations_are_refused(self):
		der = base64.b64encode(b"\x30").decode()
		good_slot = {"slot": 3, "label": "L", "serial": "S", "objects": [], "failed": False, "ckr": None}
		cases = {
			"duplicate key": b'{"v":1,"op":"certificates","result":"ok","slots":[],"slots":[]}\n',
			"NaN": b'{"v":1,"op":"certificates","result":"slot_list_failed","ckr":NaN}\n',
			"no newline": json.dumps(self.ok([])).encode(),
			"non-ascii": json.dumps(self.ok([{**good_slot, "label": "é"}]), ensure_ascii=False).encode() + b"\n",
			"bad utf-8": b'{"v":1,"op":"certificates","result":"ok","slots":[]}\xff\n',
			"not an object": b"[]\n",
			"wrong version": {**self.ok([]), "v": 2},
			"wrong op": self.ok([], op="token_state"),
			"child failed": {"v": 1, "op": "certificates", "result": "failed"},
			"bad request": {"v": 1, "op": None, "result": "bad_request"},
			"unknown result": {"v": 1, "op": "certificates", "result": "maybe"},
			"bool slot": self.ok([{**good_slot, "slot": True}]),
			"negative slot": self.ok([{**good_slot, "slot": -1}]),
			"huge slot": self.ok([{**good_slot, "slot": 2**64}]),
			"ckr without failure": self.ok([{**good_slot, "ckr": 5}]),
			"extra slot key": self.ok([{**good_slot, "pin": "1234"}]),
			"bad base64": self.ok([{**good_slot, "objects": [{"der": "%%%", "key_id": "", "label": "x"}]}]),
			"empty der": self.ok([{**good_slot, "objects": [{"der": "", "key_id": "", "label": "x"}]}]),
			"label not text": self.ok([{**good_slot, "objects": [{"der": der, "key_id": "", "label": 5}]}]),
			"long label": self.ok([{**good_slot, "label": "x" * 5000}]),
			"short entry not failed": self.ok([{"slot": 1, "failed": False, "ckr": None}]),
		}
		for name, obj in cases.items():
			with self.subTest(case=name):
				self.assert_refused(obj)

	def test_token_state_entries(self):
		parsed = self.parse(self.ok([{"slot": 1, "serial": "S", "flags": None}, {"slot": 2, "failed": True}], op="token_state"), op="token_state")
		self.assertEqual([1, 2], [entry["slot"] for entry in parsed["slots"]])
		for bad in ({"slot": 1, "serial": "S", "flags": -1}, {"slot": 1, "serial": "S"}, {"slot": 1, "failed": False}):
			with self.subTest(entry=bad):
				self.assert_refused(self.ok([bad], op="token_state"), op="token_state")


@unittest.skipUnless(HAVE_PYKCS11 and POSIX, "needs PyKCS11 for the real TokenClient")
class HealthWhileProbeHangsTests(http_tests.ServiceTestCase):
	"""The daemon keeps answering /v1/health while a /v1/certificates probe is hung."""

	def setUp(self):
		super().setUp()
		self._tmp = tempfile.TemporaryDirectory()
		self.addCleanup(self._tmp.cleanup)
		self.mark = Path(self._tmp.name) / "hung"
		script = Path(self._tmp.name) / "hung_probe.py"
		script.write_text(
			f"import sys, time\nsys.stdin.buffer.read()\nopen({str(self.mark)!r}, 'w').close()\nwhile True:\n\ttime.sleep(1)\n",
			encoding="utf-8",
		)
		for target, name, value in (
			(service_module, "TokenClient", TokenClient),
			(token, "PROBE_SCRIPT", str(script)),
			(token, "PROBE_TIMEOUT_SECONDS", 3),
			(sys, "stderr", io.StringIO()),
		):
			patcher = mock.patch.object(target, name, value)
			patcher.start()
			self.addCleanup(patcher.stop)
		module = SimpleNamespace(id="test-vendor", provider="generic_pkcs11", path=MODULE_PATH, label="libvendor.dylib")
		self.service.providers.resolve = lambda provider, module_id: module
		self.service.providers.candidates = lambda provider, module_id: [module]
		self.trust.allow(http_tests.ERP)

	def test_health_answers_while_certificates_is_hung_then_certificates_gets_the_fixed_error(self):
		_s, _h, issued = http_tests._request(self.base + "/v1/nonce", method="POST", origin=http_tests.ERP, body={"purpose": "certificates"})
		result = {}

		def certificates():
			result["response"] = http_tests._request(
				self.base + "/v1/certificates", method="POST", origin=http_tests.ERP, body={"nonce": issued["nonce"]}
			)

		worker = threading.Thread(target=certificates, daemon=True)
		worker.start()
		deadline = time.monotonic() + 5
		while not self.mark.exists() and time.monotonic() < deadline:
			time.sleep(0.02)
		self.assertTrue(self.mark.exists(), "the probe child never started")
		started = time.monotonic()
		status, _headers, body = http_tests._request(self.base + "/v1/health", origin=http_tests.ERP)
		self.assertLess(time.monotonic() - started, 1.0)
		self.assertEqual(200, status)
		self.assertTrue(worker.is_alive(), "health was not answered while the probe was hung")
		worker.join(10)
		self.assertFalse(worker.is_alive())
		status, _headers, body = result["response"]
		self.assertEqual(409, status)
		self.assertEqual({"code": "TOKEN_UNAVAILABLE", "message": DRIVER_NOT_RESPONDING}, body["error"])


if __name__ == "__main__":
	unittest.main()
