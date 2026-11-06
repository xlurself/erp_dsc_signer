"""Static gates G1-G3 (spec 001 §10).  Each gate has a negative control proving it can fail.

G1  local_signer/erp_dsc_local/ (tests excluded): no tkinter/_tkinter import and no
    Tk(/Toplevel( call outside dialog_child.py.
G2  erp_dsc_signer/public/js/sales_invoice.js: the object literal sent to the local
    /v1/sign carries no PIN key.
G3  erp_dsc_signer/api and erp_dsc_signer/utils: no parameter, attribute, .get("pin"),
    ["pin"] or **kwargs path by which a USB PIN could reach the ERP.  `pfx_password`
    (the server-mode PFX secret, spec §11) is a different secret and is allowed.
"""

import ast
import re
import tempfile
import unittest
from pathlib import Path


LOCAL_SIGNER = Path(__file__).resolve().parent.parent
PACKAGE = LOCAL_SIGNER / "erp_dsc_local"
APP_ROOT = LOCAL_SIGNER.parent
SALES_INVOICE_JS = APP_ROOT / "erp_dsc_signer" / "public" / "js" / "sales_invoice.js"
ERP_DIRS = [APP_ROOT / "erp_dsc_signer" / "api", APP_ROOT / "erp_dsc_signer" / "utils"]

TK_MODULES = ("tkinter", "_tkinter")
TK_CONSTRUCTORS = ("Tk", "Toplevel")
TK_ALLOWED_FILE = "dialog_child.py"


# --- G1 ------------------------------------------------------------------------------
def _is_tk_module(name) -> bool:
	return isinstance(name, str) and name.split(".")[0] in TK_MODULES


def tk_offences(source: str, filename: str = "<src>") -> list:
	found = []
	for node in ast.walk(ast.parse(source, filename)):
		if isinstance(node, ast.Import):
			found += [f"import {a.name}" for a in node.names if _is_tk_module(a.name)]
		elif isinstance(node, ast.ImportFrom) and node.level == 0 and _is_tk_module(node.module):
			found.append(f"from {node.module} import")
		elif isinstance(node, ast.Call):
			func = node.func
			name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
			if name in TK_CONSTRUCTORS:
				found.append(f"{name}(")
			elif name in ("__import__", "import_module") and node.args:
				first = node.args[0]
				if isinstance(first, ast.Constant) and _is_tk_module(first.value):
					found.append(f"{name}({first.value!r})")
	return found


def g1_violations(package_dir: Path) -> dict:
	result = {}
	for path in sorted(package_dir.rglob("*.py")):
		if path.name == TK_ALLOWED_FILE:
			continue
		offences = tk_offences(path.read_text(encoding="utf-8"), str(path))
		if offences:
			result[path.name] = offences
	return result


class TestG1NoTkOutsideTheChild(unittest.TestCase):
	def test_package_has_no_tk_outside_dialog_child(self):
		self.assertTrue((PACKAGE / TK_ALLOWED_FILE).is_file())
		self.assertGreater(len(list(PACKAGE.glob("*.py"))), 5)  # the scan really saw the package
		self.assertEqual({}, g1_violations(PACKAGE))

	def test_dialog_child_is_where_tk_lives(self):
		# Not a requirement of G1 itself; proves the scanner recognises the real usage.
		self.assertTrue(tk_offences((PACKAGE / TK_ALLOWED_FILE).read_text(encoding="utf-8")))

	def test_negative_control_fake_offender_fails_the_gate(self):
		offenders = {
			"a.py": "import tkinter as tk\n",
			"b.py": "from tkinter import simpledialog\n",
			"c.py": "import _tkinter\n",
			"d.py": "def f(tk):\n\treturn tk.Toplevel(None)\n",
			"e.py": "def f(tk):\n\treturn tk.Tk()\n",
			"f.py": "import importlib\nimportlib.import_module('tkinter.ttk')\n",
			"g.py": "__import__('tkinter')\n",
			"h.py": "import tkinter.simpledialog\n",
		}
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			(root / TK_ALLOWED_FILE).write_text("import tkinter\ntkinter.Tk()\n", encoding="utf-8")
			(root / "clean.py").write_text("import json\nTK = 'tkinter'\n", encoding="utf-8")
			for name, source in offenders.items():
				(root / name).write_text(source, encoding="utf-8")
			found = g1_violations(root)
		self.assertEqual(set(offenders), set(found))


# --- G2 ------------------------------------------------------------------------------
_PUNCT = set("{}()[],:;=?!&|+-*%<>~^.")
_REGEX_AFTER = set("(,=:[!&|?{};+-*%<>~^")


def js_tokens(src: str) -> list:
	"""A small JS tokenizer: strings, template literals, comments and regex literals are
	consumed whole, so braces inside them never count.  Returns (kind, text) pairs."""
	tokens = []
	i, n = 0, len(src)

	def previous():
		return tokens[-1] if tokens else ("punct", ";")

	while i < n:
		c = src[i]
		if c.isspace():
			i += 1
		elif src.startswith("//", i):
			j = src.find("\n", i)
			i = n if j < 0 else j
		elif src.startswith("/*", i):
			j = src.find("*/", i + 2)
			i = n if j < 0 else j + 2
		elif c in "'\"":
			j = i + 1
			while j < n and src[j] != c:
				j += 2 if src[j] == "\\" else 1
			tokens.append(("str", src[i + 1 : j]))
			i = j + 1
		elif c == "`":
			j, depth = i + 1, 0
			while j < n:
				if src[j] == "\\":
					j += 2
					continue
				if depth == 0 and src[j] == "`":
					break
				if src.startswith("${", j):
					depth += 1
					j += 2
					continue
				if depth and src[j] == "{":
					depth += 1
				elif depth and src[j] == "}":
					depth -= 1
				elif depth and src[j] in "'\"":
					quote, j = src[j], j + 1
					while j < n and src[j] != quote:
						j += 2 if src[j] == "\\" else 1
				j += 1
			tokens.append(("template", src[i + 1 : j]))
			i = j + 1
		elif c == "/" and (previous()[1] in _REGEX_AFTER or previous()[1] in ("return", "typeof")):
			j, in_class = i + 1, False
			while j < n and (in_class or src[j] != "/"):
				if src[j] == "\\":
					j += 1
				elif src[j] == "[":
					in_class = True
				elif src[j] == "]":
					in_class = False
				j += 1
			j += 1
			while j < n and src[j].isalpha():
				j += 1
			tokens.append(("regex", src[i:j]))
			i = j
		elif src.startswith("...", i):
			tokens.append(("punct", "..."))
			i += 3
		elif c.isalnum() or c in "_$":
			j = i
			while j < n and (src[j].isalnum() or src[j] in "_$"):
				j += 1
			tokens.append(("name", src[i:j]))
			i = j
		else:
			tokens.append(("punct", c))
			i += 1
	return tokens


_OPEN, _CLOSE = "([{", ")]}"


def _balanced(tokens, start):
	"""Index just past the bracket group that opens at tokens[start]."""
	depth = 0
	for k in range(start, len(tokens)):
		kind, text = tokens[k]
		if kind == "punct" and text in _OPEN:
			depth += 1
		elif kind == "punct" and text in _CLOSE:
			depth -= 1
			if depth == 0:
				return k + 1
	raise ValueError("unbalanced brackets")


def _split_args(tokens):
	"""Top-level comma-separated groups of a token list (without the outer brackets)."""
	groups, current, depth = [], [], 0
	for token in tokens:
		kind, text = token
		if kind == "punct" and text in _OPEN:
			depth += 1
		elif kind == "punct" and text in _CLOSE:
			depth -= 1
		if depth == 0 and token == ("punct", ","):
			groups.append(current)
			current = []
		else:
			current.append(token)
	if current:
		groups.append(current)
	return groups


def object_keys(tokens) -> list:
	"""Every property key of the object literal `tokens` ({ ... }), nested ones included.
	A spread or computed key is reported as a key that cannot be proven safe."""
	if not tokens or tokens[0] != ("punct", "{"):
		return ["<not an object literal>"]
	keys = []
	for prop in _split_args(tokens[1:-1]):
		if not prop:
			continue
		head = prop[0]
		if head == ("punct", "..."):
			keys.append("<spread>")
			continue
		if head == ("punct", "["):
			keys.append("<computed>")
			continue
		keys.append(head[1])
		if len(prop) > 2 and prop[1] == ("punct", ":") and prop[2] == ("punct", "{"):
			keys += object_keys(prop[2 : _balanced(prop, 2)])
	return keys


def sign_bodies(src: str) -> list:
	"""The 4th argument of every local_request(..., "/v1/sign", ...) call, as tokens."""
	tokens = js_tokens(src)
	bodies = []
	for k in range(len(tokens) - 1):
		if tokens[k] == ("name", "local_request") and tokens[k + 1] == ("punct", "("):
			end = _balanced(tokens, k + 1)
			args = _split_args(tokens[k + 2 : end - 1])
			if len(args) > 1 and args[1] == [("str", "/v1/sign")]:
				bodies.append(args[3] if len(args) > 3 else [])
	return bodies


def _segments(name: str) -> list:
	spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
	return [part.lower() for part in re.split(r"[^A-Za-z0-9]+", spaced) if part]


def is_pin_name(name) -> bool:
	"""pin, user_pin, tokenPin, PIN... but not pinned, spinner, signing or pfx_password."""
	return isinstance(name, str) and "pin" in _segments(name)


def g2_violations(src: str) -> list:
	bodies = sign_bodies(src)
	if not bodies:
		return ["no local /v1/sign request found"]
	problems = []
	for body in bodies:
		keys = object_keys(body)
		problems += [key for key in keys if key.startswith("<") or is_pin_name(key)]
		if "nonce" not in keys:
			problems.append("<body not recognised: no nonce key>")
	return problems


class TestG2NoPinInTheSignBody(unittest.TestCase):
	def test_sales_invoice_sign_body_has_no_pin(self):
		source = SALES_INVOICE_JS.read_text(encoding="utf-8")
		self.assertEqual(1, len(sign_bodies(source)))
		self.assertEqual([], g2_violations(source))
		keys = object_keys(sign_bodies(source)[0])
		self.assertIn("pdf_base64", keys)  # the real literal was parsed, not something else

	def test_negative_controls(self):
		base = 'local_request(base_url, "/v1/sign", "POST", {nonce: n, %s});'
		cases = {
			"key": "pin: value",
			"quoted key": '"pin": value',
			"shorthand": "pin",
			"upper": "PIN: value",
			"variant": "user_pin: value",
			"camel": "tokenPin: value",
			"nested": "certificate: {id: 1, pin: value}",
			"spread": "...extra",
			"computed": '["p" + "in"]: value',
		}
		for label, fragment in cases.items():
			with self.subTest(label):
				self.assertNotEqual([], g2_violations(base % fragment))
		self.assertNotEqual([], g2_violations('local_request(base_url, "/v1/sign", "POST", body);'))
		self.assertNotEqual([], g2_violations('local_request(base_url, "/v1/nonce", "POST", {pin: 1});'))
		clean = base % "provider, signing_request: s, pinned_note: `a ${ {pin: 1}.x } b`, re: /}{pin/g"
		self.assertEqual([], g2_violations(clean))

	def test_pin_name_rule(self):
		for name in ("pin", "PIN", "user_pin", "usb_pin", "tokenPin", "pin_code"):
			self.assertTrue(is_pin_name(name), name)
		for name in ("pinned", "spinner", "signing", "pfx_password", "pinning", "opinion"):
			self.assertFalse(is_pin_name(name), name)


# --- G3 ------------------------------------------------------------------------------
_KEY_METHODS = ("get", "pop", "setdefault", "getlist")
_ATTR_FUNCTIONS = ("getattr", "hasattr", "setattr")


def pin_paths(source: str, filename: str = "<src>") -> list:
	found = []
	for node in ast.walk(ast.parse(source, filename)):
		where = f"{filename}:{getattr(node, 'lineno', '?')}"
		if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
			args = node.args
			for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
				if is_pin_name(arg.arg):
					found.append(f"{where} parameter {arg.arg}")
			if args.kwarg is not None:
				found.append(f"{where} **{args.kwarg.arg}")
		elif isinstance(node, ast.Attribute) and is_pin_name(node.attr):
			found.append(f"{where} attribute .{node.attr}")
		elif isinstance(node, ast.Subscript):
			key = node.slice
			if isinstance(key, ast.Constant) and is_pin_name(key.value):
				found.append(f"{where} [{key.value!r}]")
		elif isinstance(node, ast.Call):
			func, key = node.func, None
			if isinstance(func, ast.Attribute) and func.attr in _KEY_METHODS and node.args:
				key = node.args[0]  # d.get("pin"), form_dict.pop("pin"), ...
			elif isinstance(func, ast.Name) and func.id in _ATTR_FUNCTIONS and len(node.args) > 1:
				key = node.args[1]  # getattr(obj, "pin")
			if isinstance(key, ast.Constant) and is_pin_name(key.value):
				found.append(f"{where} call with key {key.value!r}")
	return found


def g3_violations(directories) -> list:
	found = []
	for directory in directories:
		for path in sorted(Path(directory).rglob("*.py")):
			found += pin_paths(path.read_text(encoding="utf-8"), str(path.relative_to(APP_ROOT)))
	return found


class TestG3NoPinPathIntoTheErp(unittest.TestCase):
	def test_api_and_utils_have_no_pin_path(self):
		for directory in ERP_DIRS:
			self.assertTrue(list(directory.glob("*.py")), directory)
		self.assertEqual([], g3_violations(ERP_DIRS))

	def test_negative_controls(self):
		offenders = {
			"parameter": "def sign(name, pin):\n\tpass\n",
			"keyword-only parameter": "def sign(name, *, user_pin=None):\n\tpass\n",
			"kwargs": "def sign(name, **kwargs):\n\tpass\n",
			"attribute": "def f():\n\treturn frappe.form_dict.pin\n",
			"get": "def f():\n\treturn frappe.form_dict.get('pin')\n",
			"subscript": "def f(d):\n\treturn d['PIN']\n",
			"pop": "def f(d):\n\treturn d.pop('token_pin', None)\n",
			"getattr": "def f(o):\n\treturn getattr(o, 'pin', None)\n",
			"lambda": "f = lambda pin: pin\n",
		}
		for label, source in offenders.items():
			with self.subTest(label):
				self.assertNotEqual([], pin_paths(source))
		allowed = (
			"def f(doc, pfx_password=None, signing_request=None):\n"
			"\tkwargs = {'a': 1}\n"
			"\tfrappe.get_print(**kwargs)\n"
			"\treturn doc.get('pinned') or settings.get_password('pfx_password')\n"
		)
		self.assertEqual([], pin_paths(allowed))

	def test_negative_control_on_disk(self):
		with tempfile.TemporaryDirectory() as directory:
			(Path(directory) / "api.py").write_text("def f(**kwargs):\n\treturn kwargs.get('pin')\n", encoding="utf-8")
			found = []
			for path in Path(directory).rglob("*.py"):
				found += pin_paths(path.read_text(encoding="utf-8"), path.name)
		self.assertEqual(2, len(found), found)


if __name__ == "__main__":
	unittest.main()
