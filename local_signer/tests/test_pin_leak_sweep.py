"""Sentinel sweep (spec 001 I1, I2, §10): the PIN is never echoed, logged or written.

A dialog child generated OUTSIDE the scanned directories prints a reply carrying
DIALOG_SENTINEL (the PIN the user "typed"), and every /v1/sign body also carries
{"pin": BODY_SENTINEL}.  Across success, cancel, timeout, crash, oversize, bad-reply,
token-refusal and handler-failure paths, neither sentinel may appear in:
  * any HTTP response (status, headers, body, or the base64-decoded signed PDF),
  * daemon stderr/stdout (including the make_server handle_error path),
  * any log record (message and formatted exception),
  * str/repr/args/attrs/__cause__/__context__/format_exception of any exception the
    dialog path or the service raised,
  * any file under the test HOME, TMPDIR or config directory.
The token must receive the dialog's PIN and never the body's.
"""

import base64
import hashlib
import io
import json
import logging
import os
import shutil
import tempfile
import textwrap
import threading
import traceback
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from erp_dsc_local import dialog_child, ui
from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.errors import PinIncorrect
from erp_dsc_local.pin import request_pin
from erp_dsc_local.service import HANDLER_ERROR_LINE, SignerService
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost
import os as _os
import sys as _sys

# Sibling test modules are imported by bare name; make that work when this module is
# loaded by its full name from the repository root as well as by discovery.
if _os.path.dirname(_os.path.abspath(__file__)) not in _sys.path:
	_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from test_signature_meta import server_meta  # the full meta the ERP sends


STUB = Path(__file__).resolve().parent / "_stub_child.py"
MARK = "S3NT1NEL"
DIALOG_SENTINEL = MARK + "-DIALOG-PIN-9137"
BODY_SENTINEL = MARK + "-BODY-PIN-5521"
NEEDLES = (MARK.encode("utf-8"), MARK.encode("utf-16-le"))
ORIGIN = "https://noise.m.frappe.cloud"
PDF = b"%PDF-1.4\n% erp-dsc-local test document\n"


def _pin_line(**extra) -> bytes:
	return json.dumps({"v": 1, "kind": "pin", **extra}, separators=(",", ":")).encode()


PARTIAL = b'{"v":1,"kind":"pin","result":"entered","value":"' + DIALOG_SENTINEL.encode()

# name -> (bytes the child writes, what it does next, its exit code)
CHILDREN = {
	"success": (_pin_line(result="entered", value=DIALOG_SENTINEL) + b"\n", "exit", 0),
	"bad_reply": (_pin_line(result="entered", value=DIALOG_SENTINEL, x=1) + b"\n", "exit", 0),
	"stray_value": (_pin_line(result="cancelled", value=DIALOG_SENTINEL) + b"\n", "exit", 0),
	"valid_then_exit": (_pin_line(result="entered", value=DIALOG_SENTINEL) + b"\n", "exit", 3),
	"crash": (PARTIAL, "crash", 0),
	"timeout": (PARTIAL, "hang", 0),
	"oversize": (PARTIAL + b"x" * (dialog_child.MAX_REPLY_BYTES + 64), "hang", 0),
}
CHILD_TEMPLATE = """
import os, signal, sys, time
sys.stdin.buffer.readline()
view = memoryview({data!r})
while view:
    view = view[os.write(1, view):]
if {action!r} == "crash":
    os.kill(os.getpid(), signal.SIGKILL)
if {action!r} == "hang":
    while True:
        time.sleep(1)
os._exit({code!r})
"""


class _Certificate:
	slot_id = 1
	token_serial = "WD-TOKEN-0001"
	metadata = {"fingerprint_sha256": "ab" * 32}


class RecordingToken:
	"""TokenClient stand-in; `mode` is ok | incorrect | driver_echo."""

	def __init__(self):
		self.mode = "ok"
		self.pins = []

	def __call__(self, module):
		return self

	def select(self, selector):
		return _Certificate(), [_Certificate()]

	def token_state(self, selected):
		return 0, selected.token_serial

	def sign_pdf(self, pdf_bytes, selected, certificates, metadata, pin, timestamp_url=None, *, login_guard):
		self.pins.append(pin)
		with login_guard as guard:
			if self.mode == "incorrect":
				guard.failed()
			else:
				guard.succeeded()
		if self.mode == "incorrect":
			raise PinIncorrect()
		if self.mode == "driver_echo":
			# A misbehaving driver that puts the PIN in its error text.
			raise RuntimeError("driver error while using PIN " + pin)
		return pdf_bytes + b"%signed\n", dict(selected.metadata)


class _Records(logging.Handler):
	def __init__(self):
		super().__init__(level=logging.DEBUG)
		self.texts = []
		self.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))

	def emit(self, record):
		self.texts.append(self.format(record))


def exception_texts(exc):
	"""Every rendering of an exception and of everything chained to it."""
	texts, seen, stack = [], set(), [exc]
	while stack:
		item = stack.pop()
		if item is None or id(item) in seen:
			continue
		seen.add(id(item))
		texts += [str(item), repr(item), repr(item.args), repr(getattr(item, "__dict__", {}))]
		texts.append("".join(traceback.format_exception(item)))
		stack += [item.__cause__, item.__context__]
	return texts


class LeakSweepCase(unittest.TestCase):
	def setUp(self):
		# The generated children hold the sentinel; they live OUTSIDE the scanned dirs.
		self.scripts = Path(tempfile.mkdtemp(prefix="erp-dsc-sweep-children-"))
		self.addCleanup(shutil.rmtree, self.scripts, True)
		self.home = Path(tempfile.mkdtemp(prefix="erp-dsc-sweep-home-"))
		self.tmp = Path(tempfile.mkdtemp(prefix="erp-dsc-sweep-tmp-"))
		self.config_dir = Path(tempfile.mkdtemp(prefix="erp-dsc-sweep-config-"))
		for folder in (self.home, self.tmp, self.config_dir):
			self.addCleanup(shutil.rmtree, folder, True)
		for patcher in (
			mock.patch.dict(os.environ, {"HOME": str(self.home), "TMPDIR": str(self.tmp)}),
			mock.patch.object(tempfile, "tempdir", str(self.tmp)),  # the child's cwd
		):
			patcher.start()
			self.addCleanup(patcher.stop)

		self.stderr, self.stdout = io.StringIO(), io.StringIO()
		for patcher in (mock.patch("sys.stderr", self.stderr), mock.patch("sys.stdout", self.stdout)):
			patcher.start()
			self.addCleanup(patcher.stop)
		self.records = _Records()
		root = logging.getLogger()
		previous = root.level
		root.addHandler(self.records)
		root.setLevel(logging.DEBUG)
		self.addCleanup(root.setLevel, previous)
		self.addCleanup(root.removeHandler, self.records)

		config_path = self.config_dir / "config.json"
		config_path.write_text(json.dumps({"host": "127.0.0.1", "allowed_origins": []}), encoding="utf-8")
		self.trust = TrustStore(self.config_dir / "allowed_origins.json")
		self.trust.allow(ORIGIN)
		self.host = DialogHost(child_script=STUB)
		self.addCleanup(self.host.shutdown)
		self.service = SignerService(load_config(config_path), trust_store=self.trust, dialog_host=self.host)
		self.token = RecordingToken()
		patcher = mock.patch.object(service_module, "TokenClient", self.token)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"

		# Spies: every exception the dialog path or the service raises is kept.
		self.raised = []
		self.assertIs(request_pin, self.service.pin_prompt)
		self.service.pin_prompt = self._spy(request_pin)
		self.service.sign = self._spy(self.service.sign)

		self.server = self.service.make_server(("127.0.0.1", 0))
		self.addCleanup(self.server.server_close)
		threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
		self.addCleanup(self.server.shutdown)
		self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
		self.responses = []

	def _spy(self, fn):
		def spy(*args, **kwargs):
			try:
				return fn(*args, **kwargs)
			except BaseException as exc:
				self.raised.append(exc)
				raise

		return spy

	# -- driving ---------------------------------------------------------------------
	def use_child(self, name):
		data, action, code = CHILDREN[name]
		script = self.scripts / f"{name}.py"
		script.write_text(textwrap.dedent(CHILD_TEMPLATE.format(data=data, action=action, code=code)), encoding="utf-8")
		self.host._child_script = script

	def request(self, url, *, method="GET", body=None):
		data = json.dumps(body).encode() if body is not None else None
		req = urllib.request.Request(url, data=data, method=method)
		req.add_header("Origin", ORIGIN)
		if data is not None:
			req.add_header("Content-Type", "application/json")
		try:
			with urllib.request.urlopen(req, timeout=30) as response:
				status, headers, raw = response.status, dict(response.headers), response.read()
		except urllib.error.HTTPError as exc:
			status, headers, raw = exc.code, dict(exc.headers), exc.read()
			exc.close()
		self.responses.append(repr(status).encode() + repr(headers).encode() + raw)
		payload = json.loads(raw or b"{}")
		if isinstance(payload.get("signed_pdf_base64"), str):
			self.responses.append(base64.b64decode(payload["signed_pdf_base64"]))
		return status, payload

	def sign(self, document_name="INV-1"):
		_s, issued = self.request(self.base + "/v1/nonce", method="POST", body={"purpose": "sign"})
		return self.request(
			self.base + "/v1/sign",
			method="POST",
			body={
				"nonce": issued["nonce"],
				"pdf_base64": base64.b64encode(PDF).decode("ascii"),
				"pdf_sha256": hashlib.sha256(PDF).hexdigest(),
				"signing_request": {"signature_meta": server_meta(), "document_name": document_name},
				"pin": BODY_SENTINEL,
			},
		)

	def assert_cause(self, response, status, cause=None, code="PIN_PROMPT_UNAVAILABLE"):
		got_status, body = response
		self.assertEqual(status, got_status, body)
		self.assertEqual(code, body["error"]["code"])
		if cause is not None:
			self.assertEqual({"cause": cause}, body["error"]["details"])

	# -- the sweep -------------------------------------------------------------------
	def leaks(self, *, check_exceptions=True):
		found = []
		for index, raw in enumerate(self.responses):
			if any(needle in raw for needle in NEEDLES):
				found.append(f"response #{index}")
		for name, text in (("stderr", self.stderr.getvalue()), ("stdout", self.stdout.getvalue())):
			if MARK in text:
				found.append(name)
		found += [f"log: {text[:80]}" for text in self.records.texts if MARK in text]
		if check_exceptions:
			for exc in self.raised:
				if any(MARK in text for text in exception_texts(exc)):
					found.append(f"exception {type(exc).__name__}")
		found += [f"file {path}" for path in self.files_with_sentinel()]
		return found

	def files_with_sentinel(self):
		hits = []
		for root in (self.home, self.tmp, self.config_dir):
			for path in root.rglob("*"):
				if path.is_file() and not path.is_symlink():
					data = path.read_bytes()
					if any(needle in data for needle in NEEDLES):
						hits.append(path)
		return hits

	def assert_no_leak(self, **kwargs):
		self.assertEqual([], self.leaks(**kwargs))
		self.assertNotIn(BODY_SENTINEL, self.token.pins, "the body PIN reached the token")


class TestSweep(LeakSweepCase):
	def test_success(self):
		self.use_child("success")
		status, body = self.sign()
		self.assertEqual(200, status, body)
		self.assertEqual([DIALOG_SENTINEL], self.token.pins, "the token must receive the dialog's PIN")
		self.assert_no_leak()

	def test_cancel(self):
		self.assert_cause(self.sign("MODE:result:cancelled"), 409, code="PIN_CANCELLED")
		self.assertEqual([], self.token.pins)
		self.assert_no_leak()

	def test_timeout(self):
		for target, name, value in (
			(ui, "STARTUP_ALLOWANCE_SECONDS", 0.6),
			(ui, "GRACE_SECONDS", 0.2),
			(ui, "KILL_DELAY_SECONDS", 0.3),
			(dialog_child, "MIN_DIALOG_SECONDS", 0),
			(dialog_child, "MAX_DIALOG_SECONDS", 0),
		):
			patcher = mock.patch.object(target, name, value)
			patcher.start()
			self.addCleanup(patcher.stop)
		self.use_child("timeout")
		self.assert_cause(self.sign(), 503, "dialog_timeout")
		self.assert_no_leak()

	def test_crash(self):
		self.use_child("crash")
		self.assert_cause(self.sign(), 503, "dialog_process_failed" if os.name == "nt" else "dialog_process_crashed")
		self.assert_no_leak()

	def test_oversize(self):
		self.use_child("oversize")
		self.assert_cause(self.sign(), 503, "dialog_bad_reply")
		self.assert_no_leak()

	def test_bad_replies(self):
		for name, cause in (
			("bad_reply", "dialog_bad_reply"),
			("stray_value", "dialog_bad_reply"),
			("valid_then_exit", "dialog_process_failed"),
		):
			with self.subTest(child=name):
				self.use_child(name)
				self.assert_cause(self.sign(), 503, cause)
		self.assertEqual([], self.token.pins)
		self.assert_no_leak()

	def test_incorrect_pin_at_the_token(self):
		self.use_child("success")
		self.token.mode = "incorrect"
		self.assert_cause(self.sign(), 401, code="PIN_INCORRECT")
		self.assertEqual([DIALOG_SENTINEL], self.token.pins)
		self.assert_no_leak()

	def test_a_driver_that_echoes_the_pin_is_a_generic_500(self):
		self.use_child("success")
		self.token.mode = "driver_echo"
		status, body = self.sign()
		self.assertEqual(500, status)
		self.assertEqual(
			{"code": "LOCAL_SIGNER_ERROR", "message": "The local signer could not process this request."}, body["error"]
		)
		# The fake driver's own exception holds the PIN by construction; everything the
		# signer emits must not.
		self.assert_no_leak(check_exceptions=False)

	def test_forced_handler_exception_logs_one_fixed_line(self):
		handler = self.server.RequestHandlerClass
		boom = RuntimeError("handler failed while holding " + DIALOG_SENTINEL)
		with mock.patch.object(handler, "_respond", side_effect=boom):
			with self.assertRaises(OSError):
				urllib.request.urlopen(urllib.request.Request(self.base + "/v1/health"), timeout=10).read()
			for thread in list(getattr(self.server, "_threads", None) or ()):
				thread.join(5)
		self.assertEqual(HANDLER_ERROR_LINE + "\n", self.stderr.getvalue())
		self.assertNotIn("Traceback", self.stderr.getvalue())
		self.assert_no_leak()

	def test_no_file_contains_pin(self):
		self.use_child("success")
		self.assertEqual(200, self.sign()[0])
		for name in ("bad_reply", "crash", "oversize"):
			self.use_child(name)
			self.sign()
		self.assertEqual([], self.files_with_sentinel())
		# The scan is not vacuous: it covered the files this run wrote...
		self.assertTrue((self.config_dir / "allowed_origins.json").is_file())
		# ...and it finds a planted sentinel.
		planted = self.tmp / "nested" / "planted.txt"
		planted.parent.mkdir()
		planted.write_text("x" + DIALOG_SENTINEL, encoding="utf-8")
		self.assertEqual([planted], self.files_with_sentinel())
		planted.unlink()


class TestSigningFailureDiagnosticSweep(LeakSweepCase):
	"""TOKEN_SIGNING_FAILED ``details`` and its stderr line, with the REAL TokenClient over a
	driver, endesive and TSA whose errors carry the dialog's PIN in their text, args and
	class name: neither the response, the log line nor the raised error may carry it."""

	SIGNING_FAILED = "The USB token could not sign the document."

	def setUp(self):
		super().setUp()
		import test_token_login as fakes
		from test_sign_diagnostic import PKC

		if fakes.DER is None:
			fakes.DER = fakes._make_der()
		self.PKC = PKC
		self.cms = fakes.FakeCms()
		fakes.install_fake_endesive(self, self.cms)
		self.lib = fakes.two_slot_lib()
		client = fakes.make_client(self.lib)
		client.pk = PKC
		patcher = mock.patch.object(service_module, "TokenClient", lambda module: client)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.use_child("success")

	@staticmethod
	def hostile(base):
		return type("Driver" + MARK + base.__name__, (base,), {})

	def in_timestamp(self, factory):
		def step(hsm):
			raise factory(self.lib.received_pin)

		self.cms.timestamp_step = step

	def assert_diagnostic(self, stage, error, ckr=None):
		status, body = self.sign()
		self.assertEqual(502, status, body)
		details = {"stage": stage, "error": error, "ckr": ckr}
		self.assertEqual({"code": "TOKEN_SIGNING_FAILED", "message": self.SIGNING_FAILED, "details": details}, body["error"])
		self.assertEqual([(2, DIALOG_SENTINEL)], self.lib.logins, "the hostile driver did receive the PIN")
		self.assertEqual(1, self.stderr.getvalue().count("erp-dsc-local: the USB token could not sign"))
		self.assert_no_leak()

	def test_login(self):
		self.lib.login_error = lambda pin: self.hostile(self.PKC.PyKCS11Error)(self.PKC.CKR_GENERAL_ERROR, "pin=" + pin)
		self.assert_diagnostic("login", "other", "CKR_GENERAL_ERROR")

	def test_find_key(self):
		self.lib.find_key_error = lambda pin: self.hostile(KeyError)("pin=" + pin)
		self.assert_diagnostic("find_key", "other")

	def test_c_sign(self):
		self.lib.sign_error = lambda pin: self.PKC.PyKCS11Error(self.PKC.CKR_MECHANISM_INVALID, "pin=" + pin)
		self.assert_diagnostic("c_sign", "PyKCS11Error", "CKR_MECHANISM_INVALID")

	def test_cms(self):
		self.in_timestamp(lambda pin: FileNotFoundError(2, "pin=" + pin, "/srv/" + pin))
		self.assert_diagnostic("cms", "FileNotFoundError")

	def test_tsa(self):
		import requests

		self.in_timestamp(lambda pin: requests.exceptions.ReadTimeout("read timed out, pin=" + pin))
		self.assert_diagnostic("tsa", "ReadTimeout")

	def test_tsa_hostile_class_name(self):
		import requests

		self.in_timestamp(lambda pin: self.hostile(requests.exceptions.ConnectionError)("pin=" + pin))
		self.assert_diagnostic("tsa", "other")


if __name__ == "__main__":
	unittest.main()
