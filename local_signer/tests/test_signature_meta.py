"""``signature_meta`` allowlist: only what the ERP server sends reaches endesive (spec 001 §7).

endesive honours ``udct`` keys that read local files (``signature_img``, ``manual_fonts``,
``manual_images``, ``signature_appearance.icon``/``background``) or reach the network
(``ltv``: an OCSP request with no timeout).  A paired site could use them to embed any
workstation file in the PDF it gets back.  The server's ``icon`` is a path on the SERVER,
so passing it on also failed every real USB signing with FileNotFoundError.

``sanitise_signature_meta`` keeps exactly the keys ``erp_dsc_signer/utils/pdf_signer.py``
``_signature_metadata`` sends, each type- and size-checked, drops ``icon``, and refuses
anything else with one fixed message, before the token is touched or a PIN is asked for.
"""

import ast
import copy
import importlib
import json
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest import mock

import test_token_login as fakes
from test_token_login import SENTINEL_PIN, FakeCms, FakeGuard, install_fake_endesive, make_client, two_slot_lib

from erp_dsc_local import service as service_module
from erp_dsc_local.config import load_config
from erp_dsc_local.errors import LocalSignerError
from erp_dsc_local.service import SignerService
from erp_dsc_local.trust import TrustStore
from erp_dsc_local.ui import DialogHost

UNSUPPORTED = "The signing request contains an unsupported field."
MARK = "M3TA-SENTINEL-41d7"
ORIGIN = "https://noise.m.frappe.cloud"
STUB = Path(__file__).resolve().parent / "_stub_child.py"
SERVER_PDF_SIGNER = Path(__file__).resolve().parents[2] / "erp_dsc_signer" / "utils" / "pdf_signer.py"
SERVER_ICON = "/home/frappe/frappe-bench/sites/erp.example/private/files/signature.png"


def server_meta():
	"""What ``_signature_metadata`` sends (after JSON), without a signature image."""
	return {
		"aligned": 32768,
		"sigflags": 3,
		"sigflagsft": 132,
		"sigpage": 0,
		"sigbutton": True,
		"sigfield": "ERPNextSignature",
		"auto_sigfield": True,
		"sigandcertify": False,
		"signaturebox": [340, 45, 555, 130],
		"name": "USB DSC signer",
		"contact": "signer@example.invalid",
		"location": "",
		"signingdate": "D:20261106120000+05'30'",
		"reason": "Digitally signed invoice",
		"application": "ERPNext",
		"signature_appearance": {
			"display": "Digitally signed by USB DSC signer\nDate: 2026.11.06 12:00:00 +05'30'",
			"outline": [0, 0, 0],
			"border": 0,
		},
	}


def server_meta_with_icon(icon=SERVER_ICON):
	meta = server_meta()
	meta["signature_appearance"]["icon"] = icon
	return meta


def with_top(key, value):
	meta = server_meta()
	meta[key] = value
	return meta


def with_appearance(key, value):
	meta = server_meta()
	meta["signature_appearance"][key] = value
	return meta


# Keys endesive honours that the server never sends.  Each must be REFUSED.
HOSTILE_KEYS = [
	("signature_img", "/etc/hosts"),
	("background", "/etc/hosts"),
	("manual_images", {"I": "/etc/hosts"}),
	("manual_fonts", {"F": "/Library/Fonts/Arial.ttf"}),
	("signature_manual", [["text_box", "x", "default", 0, 0, 10, 10, 12, True, "left", "middle", 1.2]]),
	("ltv", True),
	("password", "secret"),
	("signature", "plain text"),
	("text", {"fontsize": 1000}),
	("signform", True),
	("attrs", False),
	("pss", True),
	("id", "x"),
	("newid", "x"),
	("signature_img_distort", True),
	("x_" + MARK, MARK),
]
HOSTILE_APPEARANCE = [
	("background", "/etc/hosts"),
	("background", [1, 0, 0]),
	("labels", True),
	("software", "x"),
	("icon_" + MARK, MARK),
]
# A wrong type or size for a KNOWN key.  Each must be REFUSED.
TYPE_CONFUSION = [
	*[("aligned", v) for v in (True, False, 10**30, -1, 65537, "32768", 32768.0, None, [32768], {"v": 1})],
	*[("sigflags", v) for v in (4, -1, True, "3", 3.0)],
	*[("sigflagsft", v) for v in (1024, -1, True, "132")],
	*[("sigpage", v) for v in (-1, 10**9, True, "0", 0.0, None)],
	*[(key, v) for key in ("sigbutton", "auto_sigfield", "sigandcertify") for v in (1, 0, "true", None)],
	*[
		("signaturebox", v)
		for v in (
			[1, 2, 3],
			[1, 2, 3, 4, 5],
			[1, 2, 3, "4"],
			[True, 0, 0, 0],
			{"x1": 1},
			"340,45,555,130",
			[float("nan"), 0, 0, 0],
			[float("inf"), 0, 0, 0],
			[14401, 0, 0, 0],
			[[1], 2, 3, 4],
			None,
		)
	],
	*[
		(key, v)
		for key in ("name", "contact", "location", "reason", "sigfield")
		for v in (
			"a" * 201,
			"\x1b[31m" + MARK,
			"a\u202eb",
			"line1\nline2",
			"a\u200bb",
			"a\x00b",
			"a\u2028b",
			"a\ue000b",
			"a\u3164b",
			"a\u200db",
			{"a": 1},
			["a"],
			5,
			None,
			b"bytes",
		)
	],
	*[
		("application", v)
		for v in ("ERPNext /Foo", "ERPNext>>", "ERP(Next)", "", "a" * 65, 5, None, "ERPNext\n")
	],
	*[
		("signingdate", v)
		for v in (
			"2026-11-06",
			"D:20261106120000",
			"D:20261106120000+05'30'\n",
			"D:\u0968\u0966\u0968\u0966\u0967\u0967\u0966\u0966\u0967\u0968\u0966\u0966\u0966\u0966+05'30'",
			"D:20261106120000+05'30'X",
			"D:20261106120000+0530",
			20261106,
			None,
		)
	],
	*[("signature_appearance", v) for v in ("x", [], None, 5)],
]
# A known key whose value is not the one the ERP always sends (pdf_signer._signature_metadata).
# ``sigandcertify`` True turns the approval signature into a DocMDP certification.
PINNED_CONFUSION = [
	*[("aligned", v) for v in (0, 1, 16, 4096, 32767, 32769, 65536)],
	*[("sigflags", v) for v in (0, 1, 2)],
	*[("sigflagsft", v) for v in (0, 1, 128, 133, 1023)],
	("sigandcertify", True),
	("auto_sigfield", False),
	*[("application", v) for v in ("ERPNext-v14.1_x", "erpnext", "ERPNEXT", "ERPNext2", "Frappe", "ERPNext.")],
	*[("sigfield", v) for v in ("a.b", ".", "ERPNextSignature.", ".ERPNextSignature", "ERPNext.Signature")],
]
# ``display`` is written RAW into the appearance content stream after a UTF-16BE -> latin-1
# conversion (PyPDF2_annotate graphics.py ``'({}) Tj'``): a character with a 0x28 '(',
# 0x29 ')' or 0x5C '\' byte, or above U+FFFF (a surrogate pair), can end the string and
# write operators.  U+2829 is '()' raw; U+7265 / U+546A are the operators 're' / 'Tj'.
DISPLAY_BREAKOUTS = [
	"(",
	")",
	"\\",
	"a) Tj ET 0 0 1 rg 0 0 500 500 re f BT (b",
	"back\\slash",
	"ok (balanced)",
	"\u2829",
	"\u2829\u7265\u546a",
	"x\u2900",
	"\u5c00",
	"\u0128",  # LATIN CAPITAL LETTER I WITH TILDE: 01 28
	"\u015c",  # LATIN CAPITAL LETTER S WITH CIRCUMFLEX: 01 5C
	"\u0929",  # DEVANAGARI LETTER NNNA: 09 29
	"Digitally signed by \u0935\u093f\u0928\u092f",  # DEVANAGARI NA is 09 28
	"\U0001f600",
	"\U00028029",
]
APPEARANCE_CONFUSION = [
	*[
		("display", v)
		for v in ("a" * 501, "a\rb", "a\x1bb", "a\u202eb", ["CN", "DN"], 5, None, {"a": 1}, *DISPLAY_BREAKOUTS)
	],
	*[("outline", v) for v in ([0, 0], [0, 0, 0, 0], [0, 0, 256], [0, 0, -1], [0, 0, True], [0.0, 0, 0], "black", None)],
	*[("border", v) for v in (11, -1, True, "0", 0.0, None)],
]
NOT_A_DICT = [None, [], "x", 5, [("reason", "x")]]


def without_top(key):
	meta = server_meta()
	del meta[key]
	return meta


def without_appearance(key):
	meta = server_meta()
	del meta["signature_appearance"][key]
	return meta


# The ERP always sends every key: an incomplete meta used to pass and then fail only after
# the PIN dialog, C_Login and C_Sign (a KeyError inside endesive), or sign something else.
INCOMPLETE = [
	("empty", {}),
	("reason-only", {"reason": "test"}),
	("appearance-only", {"signature_appearance": {}}),
	("signingdate-only", {"signingdate": "D:20261106120000Z"}),
	(
		"three-key-unaligned",
		{"sigflags": 3, "contact": "signer@example.invalid", "signingdate": "D:20261106120000+05'30'"},
	),
	("empty-appearance", with_top("signature_appearance", {})),
	("icon-only-appearance", with_top("signature_appearance", {"icon": SERVER_ICON})),
]


def hostile_metas():
	"""Every meta that must be refused, with a label for subTest."""
	cases = [(f"top:{key}", with_top(key, value)) for key, value in HOSTILE_KEYS]
	cases += [(f"appearance:{key}", with_appearance(key, value)) for key, value in HOSTILE_APPEARANCE]
	cases += [(f"type:{key}={value!r:.40}", with_top(key, value)) for key, value in TYPE_CONFUSION]
	cases += [(f"pinned:{key}={value!r:.40}", with_top(key, value)) for key, value in PINNED_CONFUSION]
	cases += [(f"appearance-type:{key}={value!r:.40}", with_appearance(key, value)) for key, value in APPEARANCE_CONFUSION]
	cases += [(f"meta:{value!r}", value) for value in NOT_A_DICT]
	cases += [(f"incomplete:{label}", meta) for label, meta in INCOMPLETE]
	cases += [(f"missing:{key}", without_top(key)) for key in sorted(server_meta())]
	cases += [(f"missing-appearance:{key}", without_appearance(key)) for key in sorted(server_meta()["signature_appearance"])]
	# icon is dropped only inside signature_appearance; at the top level it is unknown.
	cases.append(("top:icon", with_top("icon", "/etc/hosts")))
	return cases


def sanitise(meta):
	return service_module.sanitise_signature_meta(meta)


def renderings(error):
	texts = [str(error), repr(error), repr(error.args), repr(vars(error)), json.dumps(error.as_dict())]
	texts.append("".join(traceback.format_exception(type(error), error, error.__traceback__)))
	return texts


def setUpModule():
	if fakes.DER is None:  # test_token_login builds its certificate in its own setUpModule
		fakes.DER = fakes._make_der()


class TestServerShapeIsTheAllowlist(unittest.TestCase):
	"""The hand-copied server dict above IS what the ERP sends: a server change fails here."""

	def test_the_server_sends_exactly_these_keys(self):
		tree = ast.parse(SERVER_PDF_SIGNER.read_text(encoding="utf-8"))
		function = next(
			node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_signature_metadata"
		)
		returned = next(node.value for node in ast.walk(function) if isinstance(node, ast.Return))
		appearance = set()
		for node in ast.walk(function):
			if not isinstance(node, ast.Assign):
				continue
			for target in node.targets:
				if isinstance(target, ast.Name) and target.id == "appearance" and isinstance(node.value, ast.Dict):
					appearance |= {key.value for key in node.value.keys}
				if isinstance(target, ast.Subscript) and getattr(target.value, "id", None) == "appearance":
					appearance.add(target.slice.value)
		self.assertEqual(set(server_meta()), {key.value for key in returned.keys})
		self.assertEqual(set(server_meta_with_icon()["signature_appearance"]), appearance)
		# Every literal the server sends is the value pinned here (aligned, sigflags, ...).
		literals = {key.value: value.value for key, value in zip(returned.keys, returned.values) if isinstance(value, ast.Constant)}
		self.assertEqual(
			{"aligned", "sigflags", "sigflagsft", "sigbutton", "sigfield", "auto_sigfield", "sigandcertify", "application"},
			set(literals),
		)
		for key, value in literals.items():
			self.assertEqual((type(server_meta()[key]), server_meta()[key]), (type(value), value), key)


class TestSanitise(unittest.TestCase):
	def test_the_server_dict_passes_unchanged(self):
		self.assertEqual(server_meta(), sanitise(server_meta()))

	def test_icon_is_dropped_and_nothing_else_changes(self):
		for icon in (SERVER_ICON, "/etc/hosts", "", 5, {"a": 1}, None):
			with self.subTest(icon=icon):
				meta = server_meta_with_icon(icon)
				self.assertEqual(server_meta(), sanitise(meta))
				self.assertEqual(icon, meta["signature_appearance"]["icon"], "the caller's dict is not mutated")

	def test_the_result_is_a_new_dict_holding_only_allowlisted_keys(self):
		meta = server_meta_with_icon()
		clean = sanitise(meta)
		meta["signature_img"] = "/etc/hosts"
		meta["signature_appearance"]["background"] = "/etc/hosts"
		meta["signaturebox"].append(1)
		self.assertEqual(server_meta(), clean)

	def test_an_incomplete_meta_is_refused(self):
		for label, meta in INCOMPLETE:
			with self.subTest(case=label):
				with self.assertRaises(LocalSignerError) as ctx:
					sanitise(meta)
				self.assertEqual(("INVALID_REQUEST", UNSUPPORTED), (ctx.exception.code, ctx.exception.message))

	def test_every_key_the_server_sends_is_required(self):
		for key in server_meta():
			with self.subTest(key=key):
				with self.assertRaises(LocalSignerError):
					sanitise(without_top(key))
		for key in server_meta()["signature_appearance"]:
			with self.subTest(appearance=key):
				with self.assertRaises(LocalSignerError):
					sanitise(without_appearance(key))

	def test_the_values_the_server_always_sends_are_pinned(self):
		for key, value in PINNED_CONFUSION:
			with self.subTest(key=key, value=value):
				with self.assertRaises(LocalSignerError) as ctx:
					sanitise(with_top(key, value))
				self.assertEqual(("INVALID_REQUEST", UNSUPPORTED), (ctx.exception.code, ctx.exception.message))
		clean = sanitise(server_meta())
		self.assertEqual(
			(32768, 3, 132, False, True, "ERPNext"),
			tuple(clean[key] for key in ("aligned", "sigflags", "sigflagsft", "sigandcertify", "auto_sigfield", "application")),
		)
		for key in ("sigandcertify", "auto_sigfield"):
			self.assertIs(bool, type(clean[key]))
		# sigbutton is inert in endesive 2.19.3 (never read): either value passes.
		self.assertEqual(with_top("sigbutton", False), sanitise(with_top("sigbutton", False)))

	def test_a_display_that_could_end_the_pdf_string_is_refused(self):
		for display in DISPLAY_BREAKOUTS:
			with self.subTest(display=display):
				with self.assertRaises(LocalSignerError) as ctx:
					sanitise(with_appearance("display", display))
				self.assertEqual(("INVALID_REQUEST", UNSUPPORTED), (ctx.exception.code, ctx.exception.message))

	def test_the_byte_rule_refuses_exactly_the_delimiter_bytes_in_the_bmp(self):
		delimiters = {0x28, 0x29, 0x5C}
		for code in range(0x20, 0x10000):
			ch = chr(code)
			if service_module._text(1)(ch) is service_module._INVALID:
				continue  # refused by the claim rule already
			breaks = (code >> 8) in delimiters or (code & 0xFF) in delimiters
			accepted = service_module._display(ch) is not service_module._INVALID
			if accepted == breaks:
				self.fail(f"U+{code:04X}: accepted={accepted} but carries a delimiter byte={breaks}")

	def test_readable_values_at_the_limits_pass(self):
		eyelash_ra = "\u0930\u094d\u200d\u092f"  # RA VIRAMA ZWJ YA: a joiner Indian names need
		cases = [
			("name", "a" * 200),
			("location", "\u092e\u0941\u0902\u092c\u0908 " + eyelash_ra),
			("reason", "Signed\u00a0invoice"),
			("contact", ""),
			("sigpage", 0),
			("sigpage", 99999),
			("sigfield", "ERPNext_Signature-2"),
			("signaturebox", [340.5, -45, 14400, 130]),
			("signingdate", "D:20261106120000-03'30'"),
		]
		for key, value in cases:
			with self.subTest(key=key, value=value):
				self.assertEqual(with_top(key, value), sanitise(with_top(key, value)))
		displays = (
			"x" * 500,
			"a\nb\n\nc",
			"Digitally signed by Test Signer\nDate: 2026.11.06 12:00:00 +05'30'",
			"Digitally signed by TEST MIDDLE SIGNER\nDate: 2026.11.06 23:59:59 -03'30'",
			"Digitally signed by \u0935\u093f\u091c\u092f \u0936\u0930\u094d\u092e\u093e",  # vijay sharma
			"Digitally signed by J\u00f6rg M\u00fcller-\u00c5str\u00f6m [ACME] {x} <y> 50% #1",
		)
		appearance_cases = [("display", value) for value in displays]
		appearance_cases += [("outline", [255, 255, 255]), ("border", 10)]
		for key, value in appearance_cases:
			with self.subTest(key=key, value=value):
				self.assertEqual(with_appearance(key, value), sanitise(with_appearance(key, value)))

	def test_every_hostile_or_malformed_meta_is_refused_with_one_fixed_message(self):
		for label, meta in hostile_metas():
			with self.subTest(case=label):
				with self.assertRaises(LocalSignerError) as ctx:
					sanitise(meta)
				error = ctx.exception
				self.assertEqual(("INVALID_REQUEST", 400, UNSUPPORTED), (error.code, error.status, error.message))
				self.assertEqual({}, error.details)
				self.assertIsNone(error.__cause__)
				self.assertIsNone(error.__context__)

	def test_the_refusal_never_echoes_the_key_or_the_value(self):
		for label, meta in hostile_metas():
			if MARK not in repr(meta):
				continue
			with self.subTest(case=label):
				with self.assertRaises(LocalSignerError) as ctx:
					sanitise(meta)
				for text in renderings(ctx.exception):
					self.assertNotIn(MARK, text)


class _RecordingCms(FakeCms):
	"""The fake endesive, recording every ``udct`` it is handed."""

	def __init__(self):
		super().__init__()
		self.udcts = []

	def sign(self, datau, udct, *args, **kwargs):
		self.udcts.append(copy.deepcopy(udct))
		return super().sign(datau, udct, *args, **kwargs)


class TestServiceAppliesTheAllowlistFirst(unittest.TestCase):
	"""``SignerService.sign`` with the REAL TokenClient over a fake PKCS#11 library."""

	def setUp(self):
		self.cms = _RecordingCms()
		install_fake_endesive(self, self.cms)
		folder = tempfile.TemporaryDirectory()
		self.addCleanup(folder.cleanup)
		config_path = Path(folder.name) / "config.json"
		config_path.write_text(json.dumps({"host": "127.0.0.1", "allowed_origins": []}), encoding="utf-8")
		trust = TrustStore(Path(folder.name) / "allowed_origins.json")
		trust.allow(ORIGIN)
		host = DialogHost(child_script=STUB)
		self.addCleanup(host.shutdown)
		self.pin_calls = []

		def pin_prompt(origin, document_name, *, host, warnings=(), final_try=False):
			self.pin_calls.append(document_name)
			return SENTINEL_PIN

		self.service = SignerService(load_config(config_path), trust_store=trust, dialog_host=host, pin_prompt=pin_prompt)
		self.service.providers.resolve = lambda provider, module_id: "fake-module"
		self.lib = two_slot_lib()
		patcher = mock.patch.object(service_module, "TokenClient", lambda module: make_client(self.lib))
		patcher.start()
		self.addCleanup(patcher.stop)

	def sign(self, meta):
		return self.service.sign(
			ORIGIN, b"%PDF", meta, document_name="INV-1", selector=None, provider="auto", module_id=None, timestamp_url=None
		)

	def test_server_meta_with_icon_reaches_endesive_without_the_icon(self):
		signed, _metadata = self.sign(server_meta_with_icon())
		self.assertTrue(signed.startswith(b"%PDF"))
		self.assertEqual([server_meta()], self.cms.udcts)
		self.assertNotIn("icon", self.cms.udcts[0]["signature_appearance"])
		self.assertLessEqual(set(self.cms.udcts[0]), set(server_meta()))
		self.assertEqual(["INV-1"], self.pin_calls)

	def test_a_refused_meta_never_reaches_the_token_the_pin_dialog_or_endesive(self):
		for label, meta in hostile_metas():
			with self.subTest(case=label):
				with self.assertRaises(LocalSignerError) as ctx:
					self.sign(meta)
				self.assertEqual(("INVALID_REQUEST", UNSUPPORTED), (ctx.exception.code, ctx.exception.message))
				self.assertEqual([], self.pin_calls, "no PIN may be asked for")
				self.assertEqual([], self.cms.udcts, "nothing may reach cms.sign")
				self.assertEqual([], self.lib.log, "the token must not be touched")
				self.assertEqual([], self.lib.logins)


class TestRealEndesive(unittest.TestCase):
	"""The installed endesive: the server's ``icon`` really breaks USB signing, and a site-named
	local file really ends up in the signed PDF, unless the allowlist runs first."""

	@classmethod
	def setUpClass(cls):
		import test_endesive_integration as integ

		cls.integ = integ
		cls.leaf_key, cls.leaf, cls.intermediate, cls.root = integ._make_chain()
		cls.pdf = integ._minimal_pdf()

	def setUp(self):
		integ = self.integ
		cms = importlib.import_module("endesive.pdf.cms")
		if not getattr(cms, "__file__", "").endswith(str(Path("endesive", "pdf", "cms.py"))):
			self.skipTest("endesive is not installed")
		self.lib = integ.SoftwareKeyLib(
			{2: fakes._token("SER-META", certs=[(20, (integ._der(self.leaf), integ.LEAF_KEY_ID, "sign"))], keys=[(integ.LEAF_KEY_HANDLE, integ.LEAF_KEY_ID)])},
			{integ.LEAF_KEY_HANDLE: self.leaf_key},
		)
		self.client = make_client(self.lib)
		self.selected, self.certificates = self.client.select(None)

	def sign(self, meta):
		return self.client.sign_pdf(
			self.pdf, self.selected, self.certificates, meta, SENTINEL_PIN, None, login_guard=FakeGuard(self.lib.log)
		)

	def test_the_server_icon_path_fails_real_signing_and_the_allowlist_fixes_it(self):
		with mock.patch("sys.stderr"), self.assertRaises(LocalSignerError) as ctx:
			self.sign(server_meta_with_icon())  # the path exists only on the ERP server
		self.assertEqual("TOKEN_SIGNING_FAILED", ctx.exception.code)
		# The diagnostic names the cause the generic message hid from the operator.
		self.assertEqual({"stage": "cms", "error": "FileNotFoundError", "ckr": None}, ctx.exception.details)
		signed, metadata = self.sign(sanitise(server_meta_with_icon()))
		verified = self.integ._load_usb_signer().verify_usb_signed_pdf(self.pdf, signed, metadata)
		self.assertEqual(self.leaf.fingerprint(self.integ.hashes.SHA256()).hex(), verified["fingerprint_sha256"])

	def test_sigandcertify_true_certifies_the_document_and_is_refused(self):
		"""endesive turns ``sigandcertify`` True into a DocMDP certification (a catalog
		/Perms), and the server verifier accepts it as the approval signature it asked for."""
		certify = with_top("sigandcertify", True)
		signed, metadata = self.sign(certify)
		self.assertIn(b"/DocMDP", signed[len(self.pdf) :])
		self.integ._load_usb_signer().verify_usb_signed_pdf(self.pdf, signed, metadata)  # accepted
		with self.assertRaises(LocalSignerError) as ctx:
			sanitise(certify)
		self.assertEqual(("INVALID_REQUEST", UNSUPPORTED), (ctx.exception.code, ctx.exception.message))
		signed, _metadata = self.sign(sanitise(server_meta()))
		self.assertNotIn(b"/DocMDP", signed[len(self.pdf) :])

	def test_a_local_file_named_by_the_site_is_embedded_unless_dropped(self):
		from PIL import Image

		folder = tempfile.TemporaryDirectory()
		self.addCleanup(folder.cleanup)
		picture = Path(folder.name) / "workstation-private.png"
		Image.new("RGB", (37, 23), (200, 10, 10)).save(picture)
		signed, _metadata = self.sign(server_meta_with_icon(str(picture)))
		self.assertIn(b"/Width 37", signed[len(self.pdf) :], "endesive embeds the file the site named")
		signed, _metadata = self.sign(sanitise(server_meta_with_icon(str(picture))))
		self.assertNotIn(b"/Width 37", signed[len(self.pdf) :])


if __name__ == "__main__":
	unittest.main()
