"""erp-dsc-local --doctor: a plain-text support report with no PIN and no private data.

The token check goes through ``TokenClient.certificates`` (the killable child), so a hung
driver ends as "driver not responding" within the probe limit.  The report names each
certificate by common name, organisation, issuer CN, valid-to date and whether it is a
signing certificate, with only the first 8 hex of its fingerprint: never DER, serial
numbers, the token's serial or label, the list of paired sites, or a full fingerprint.
Certificates are generated here ("Test Signer"), never personal data.
"""

import contextlib
import http.server
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import doctor, token
from erp_dsc_local.errors import CertificatesHidden, LocalSignerError, TokenUnavailable
from erp_dsc_local.token import TokenClient, TokenDriverNotResponding
import os as _os
import re
import sys as _sys

# Sibling test modules are imported by bare name; make that work when this module is
# loaded by its full name from the repository root as well as by discovery.
if _os.path.dirname(_os.path.abspath(__file__)) not in _sys.path:
	_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from test_certificate_listing import _der, _real_token_five, _token_cert

MARK = "D0CT0R-SENT1NEL"
CONFIG_ORIGIN = "https://config-" + MARK.lower() + ".example.invalid"
PAIRED_ORIGIN = "https://paired-" + MARK.lower() + ".example.invalid"
MODULE_A = _os.path.abspath("/opt/erp-dsc-test/libtest-a-pkcs11.dylib")
MODULE_B = _os.path.abspath("/opt/erp-dsc-test/libtest-b-pkcs11.dylib")
try:
	import PyKCS11  # noqa: F401

	HAVE_PYKCS11 = True
except ImportError:
	HAVE_PYKCS11 = False


class FakeStore:
	def __init__(self, origins=()):
		self.origins = list(origins)

	def list_origins(self):
		return [{"origin": origin, "approved_at": 0} for origin in self.origins]


class StrictClient:
	"""A TokenClient stand-in that fails the test on anything but ``certificates()``."""

	def __init__(self, behaviour, calls):
		self.behaviour = behaviour
		self.calls = calls

	def certificates(self):
		self.calls.append("certificates")
		if isinstance(self.behaviour, BaseException):
			raise self.behaviour
		return self.behaviour

	def __getattr__(self, name):
		raise AssertionError(f"the doctor used TokenClient.{name}; only certificates() is read-only")


class DoctorCase(unittest.TestCase):
	def setUp(self):
		self.dir = Path(tempfile.mkdtemp(prefix="erp-dsc-doctor-"))
		self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))
		self.config = self.dir / "config.json"
		self.write_config()
		self.calls = []

	def write_config(self, modules=((MODULE_A, "test-a"), (MODULE_B, "test-b")), **extra):
		raw = {
			"host": "127.0.0.1",
			"port": 17777,
			"allowed_origins": [CONFIG_ORIGIN],
			"providers": {"custom_modules": [{"id": mid, "path": path, "label": "Test " + mid} for path, mid in modules]},
		}
		raw.update(extra)
		self.config.write_text(json.dumps(raw), encoding="utf-8")

	def report(self, behaviours, *, existing=(MODULE_A, MODULE_B), port="free (test)"):
		def factory(module):
			return StrictClient(behaviours[module.path], self.calls)

		out = io.StringIO()
		code = doctor.run(
			self.config,
			out=out,
			system="Darwin",
			client_factory=factory,
			trust_store=FakeStore([PAIRED_ORIGIN]),
			port_status=lambda host, port: port,
			path_exists=lambda path: path in existing,
		)
		return code, out.getvalue()


class TestNoSecrets(DoctorCase):
	def test_certificate_details_without_serials_der_token_ids_or_sites(self):
		five = _real_token_five(token_label="LABEL-" + MARK, token_serial="SERIAL-" + MARK)
		code, text = self.report({MODULE_A: five, MODULE_B: TokenUnavailable()})
		self.assertEqual(0, code)
		leaf = five[0]
		forbidden = [
			MARK,
			MARK.lower(),
			leaf.metadata["fingerprint_sha256"][:9],
			leaf.metadata["serial_number"],
			leaf.metadata["serial_number_decimal"],
			leaf.metadata["der_base64"][:16],
		]
		for cert in five:
			forbidden += [cert.metadata["fingerprint_sha256"][:9], cert.metadata["serial_number"]]
		for needle in forbidden:
			with self.subTest(needle=needle):
				self.assertNotIn(needle, text)
		# Not vacuous: the public details ARE there.
		self.assertIn("Test Signer", text)
		self.assertIn("Organisation: Test Company Pvt Ltd", text)
		self.assertIn("Issued by: Test Sub-CA", text)
		self.assertIn("Valid to: " + leaf.metadata["valid_to"][:10], text)
		self.assertIn("Fingerprint (first 8): " + leaf.metadata["fingerprint_sha256"][:8], text)
		self.assertIn("Signing certificate: yes", text)
		self.assertIn("Signing certificate: no", text)  # the CA and encryption certificates
		self.assertIn("1 in config.json, 1 paired on this computer", text)
		self.assertEqual(["certificates", "certificates"], self.calls)

	def test_hostile_certificate_text_is_printed_plain(self):
		hostile = _token_cert(_der("Test\x1b[2J Signer‮", ca=False))
		_code, text = self.report({MODULE_A: [hostile], MODULE_B: TokenUnavailable()})
		self.assertNotIn("\x1b", text)
		self.assertNotIn("‮", text)
		self.assertIn("Test[2J Signer", text)


class TestOutcomes(DoctorCase):
	def test_no_token_is_a_report_not_a_failure(self):
		code, text = self.report({MODULE_A: TokenUnavailable(), MODULE_B: CertificatesHidden()})
		self.assertEqual(0, code)
		self.assertIn("no token", text)
		self.assertIn("no certificates are visible without a PIN", text)

	def test_driver_not_responding_and_unexpected_errors(self):
		code, text = self.report({MODULE_A: TokenDriverNotResponding(), MODULE_B: RuntimeError("driver text " + MARK)})
		self.assertEqual(0, code)
		self.assertIn("driver not responding", text)
		self.assertIn("check failed (RuntimeError)", text)
		self.assertNotIn(MARK, text)

	def test_missing_dependency(self):
		missing = LocalSignerError("DEPENDENCY_MISSING", "Install PyKCS11 to use a USB DSC token.", status=503)
		_code, text = self.report({MODULE_A: missing, MODULE_B: missing})
		self.assertIn("PyKCS11 is not installed", text)

	def test_an_installed_but_unloadable_pykcs11_is_named_not_called_missing(self):
		broken = LocalSignerError("DEPENDENCY_MISSING", "Install PyKCS11 to use a USB DSC token.", status=503)
		broken.__cause__ = ImportError("DLL load failed: secret-path-text " + MARK)
		_code, text = self.report({MODULE_A: broken, MODULE_B: broken})
		self.assertIn("PyKCS11 is installed but failed to import (ImportError)", text)
		self.assertNotIn("is not installed", text)
		self.assertNotIn(MARK, text)  # the import message is never printed, only its class

	def test_a_wrong_bitness_driver_is_tagged_and_never_probed(self):
		with mock.patch("erp_dsc_local.drivers.unusable_reason", side_effect=lambda p: "32-bit driver; this Python is 64-bit and cannot use it" if p == MODULE_B else None):
			code, text = self.report({MODULE_A: TokenUnavailable(), MODULE_B: AssertionError("probed a 32-bit driver")})
		self.assertEqual(0, code)
		self.assertIn("skipped (32-bit driver; this Python is 64-bit and cannot use it)", text)
		self.assertEqual(["certificates"], self.calls)

	def test_missing_modules_are_listed_but_never_asked(self):
		code, text = self.report({MODULE_A: TokenUnavailable()}, existing=(MODULE_A,))
		self.assertEqual(0, code)
		self.assertRegex(text, r"missing\s+Generic PKCS#11\s+" + re.escape(MODULE_B))
		self.assertRegex(text, r"found\s+Generic PKCS#11\s+" + re.escape(MODULE_A))
		self.assertEqual(["certificates"], self.calls)

	def test_bad_config_is_reported_and_the_rest_still_runs(self):
		self.config.write_text("{not json", encoding="utf-8")
		code, text = self.report({})
		self.assertEqual(0, code)
		self.assertIn("cannot be used: Unable to read a valid JSON configuration file.", text)
		self.assertIn("Helper version:", text)
		self.assertIn("/usr/local/lib/libwdpkcs.dylib", text.replace("\\", "/"))  # built-in locations still listed

	def test_output_is_plain_text_under_200_lines(self):
		modules = [(_os.path.abspath(f"/opt/erp-dsc-test/lib{n}-pkcs11.dylib"), f"test-{n}") for n in range(60)]
		self.write_config(modules=modules)
		many = _real_token_five() * 4
		code, text = self.report({path: many for path, _ in modules}, existing=[path for path, _ in modules])
		self.assertEqual(0, code)
		lines = text.splitlines()
		self.assertLess(len(lines), 200)
		self.assertIn("more not shown", text)
		with self.assertRaises(ValueError):
			json.loads(text)
		self.assertFalse([line for line in lines if line.lstrip().startswith(("{", "["))])

	def test_default_client_is_the_killable_token_client(self):
		self.assertIs(TokenClient, doctor.DEFAULT_CLIENT)


@unittest.skipUnless(HAVE_PYKCS11 and os.name != "nt", "needs PyKCS11 and POSIX process groups")
class TestHungDriver(DoctorCase):
	def test_a_hung_driver_is_killed_and_reported(self):
		script = self.dir / "hang_probe.py"
		script.write_text("import sys, time\nsys.stdin.buffer.read()\nwhile True:\n\ttime.sleep(1)\n", encoding="utf-8")
		self.write_config(modules=((MODULE_A, "test-a"),))
		out = io.StringIO()
		started = time.monotonic()
		with mock.patch.object(token, "PROBE_SCRIPT", str(script)), mock.patch.object(token, "PROBE_TIMEOUT_SECONDS", 1), contextlib.redirect_stderr(io.StringIO()):
			code = doctor.run(
				self.config,
				out=out,
				system="Darwin",
				trust_store=FakeStore(),
				port_status=lambda host, port: "free (test)",
				path_exists=lambda path: path == MODULE_A,
			)
		self.assertEqual(0, code)
		self.assertLess(time.monotonic() - started, 10)
		self.assertIn("driver not responding", out.getvalue())


class TestPortStatus(unittest.TestCase):
	def test_free_port(self):
		with socket.socket() as probe:
			probe.bind(("127.0.0.1", 0))
			port = probe.getsockname()[1]
		self.assertIn("free", doctor.port_status("127.0.0.1", port))

	def test_port_used_by_another_program(self):
		with socket.socket() as listener:
			listener.bind(("127.0.0.1", 0))
			listener.listen(1)
			port = listener.getsockname()[1]
			threading.Thread(target=lambda: listener.accept()[0].close(), daemon=True).start()
			self.assertIn("in use by another program", doctor.port_status("127.0.0.1", port))

	def test_port_used_by_the_signer(self):
		class Health(http.server.BaseHTTPRequestHandler):
			def do_GET(self):
				data = json.dumps({"ok": True, "version": "0.2.0", "paired": False}).encode()
				self.send_response(200)
				self.send_header("Content-Length", str(len(data)))
				self.end_headers()
				self.wfile.write(data)

			def log_message(self, *_args):
				return

		server = http.server.HTTPServer(("127.0.0.1", 0), Health)
		self.addCleanup(server.server_close)
		threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
		self.addCleanup(server.shutdown)
		self.assertIn("in use by ERP DSC Signer 0.2.0", doctor.port_status("127.0.0.1", server.server_address[1]))


class TestCliDoctor(DoctorCase):
	def test_cli_runs_the_doctor_and_exits_zero(self):
		out = io.StringIO()
		with mock.patch.object(sys, "argv", ["erp-dsc-local", "--doctor", "--config", str(self.config)]), mock.patch.object(
			doctor, "run", side_effect=lambda path, **kw: (out.write(f"ran {path}\n"), 0)[1]
		):
			with self.assertRaises(SystemExit) as raised:
				from erp_dsc_local import cli

				cli.main()
		self.assertEqual(0, raised.exception.code)
		self.assertEqual(f"ran {self.config}\n", out.getvalue())


if __name__ == "__main__":
	unittest.main()
