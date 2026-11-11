"""Driver discovery: built-in locations, --find-drivers and --add-module (BRD F4 phase 1).

--find-drivers only LISTS files: shallow, bounded in entries and time, never descends into
a symlinked folder and never reports a link that leads out of the folder it scans.
--add-module never loads the library in this process (an optional --verify asks the
killable probe child); it refuses anything but an absolute, plain, regular, readable
library file that other users cannot replace, refuses duplicates, and rewrites
config.json atomically with a user-only config.json.bak.  Temp folders only: the owner's
real ~/.erp-dsc-local is never touched.
"""

import contextlib
import ctypes
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from erp_dsc_local import cli, drivers, providers
from erp_dsc_local.config import PROVIDER_IDS, load_config
from erp_dsc_local.providers import KNOWN_PATHS, ProviderRegistry
from erp_dsc_local.token import TokenDriverNotResponding

POSIX = os.name != "nt"
INNAIT_MAC = "/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.dylib"
EPASS_V2_MAC = "/usr/local/lib/libcastle_v2.1.0.0.dylib"
ORIGINAL_CONFIG = {"host": "127.0.0.1", "port": 17777, "allowed_origins": [], "providers": {"custom_modules": []}}


class TestKnownPaths(unittest.TestCase):
	def test_innaitkey_and_epass_v2_are_known_on_macos(self):
		self.assertIn(INNAIT_MAC, KNOWN_PATHS["Darwin"]["generic_pkcs11"])
		self.assertIn(EPASS_V2_MAC, KNOWN_PATHS["Darwin"]["epass"])

	def test_innaitkey_is_not_a_new_provider_id(self):
		# The ERP server accepts only its own fixed provider list (api/signing.py USB_PROVIDERS);
		# a new id would be refused there, so InnaitKey stays a generic PKCS#11 location.
		self.assertNotIn("innaitkey", PROVIDER_IDS)
		self.assertNotIn("innaitkey", providers.PROVIDER_LABELS)

	def test_the_registry_offers_innaitkey_through_auto(self):
		config = load_config(self.write_config())
		registry = ProviderRegistry(config, system="Darwin", path_exists=lambda path: path == INNAIT_MAC)
		listed = [module.path for module in registry.candidates("auto", None)]
		self.assertEqual([INNAIT_MAC], listed)
		self.assertEqual("generic_pkcs11", registry.resolve("auto", None).provider)

	def write_config(self):
		directory = tempfile.mkdtemp(prefix="erp-dsc-known-")
		self.addCleanup(shutil.rmtree, directory, True)
		path = Path(directory) / "config.json"
		path.write_text("{}", encoding="utf-8")
		return path


class TempTree(unittest.TestCase):
	def setUp(self):
		self.root = Path(tempfile.mkdtemp(prefix="erp-dsc-drivers-")).resolve()
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for path in self.root.rglob("*"):
			with contextlib.suppress(OSError):
				if path.is_dir() and not path.is_symlink():
					os.chmod(path, 0o700)
		shutil.rmtree(self.root, True)

	def file(self, relative, mode=0o644, data=b"\x00lib"):
		path = self.root / relative
		path.parent.mkdir(parents=True, exist_ok=True)
		path.write_bytes(data)
		os.chmod(path, mode)
		return path


class TestFindDrivers(TempTree):
	def build(self):
		scan = self.root / "scan"
		outside = self.root / "outside"
		self.file("scan/a/libvendor-pkcs11.dylib")
		self.file("scan/a/b/c/d/libdeep_p11.so")
		self.file("scan/a/b/c/d/e/libtoodeep_pkcs11.so")
		self.file("scan/readme-pkcs11.txt")
		self.file("scan/libunrelated.dylib")
		self.file("scan/libcastle.so.1.0.0")
		self.file("scan/WDPKCS.DLL")
		self.file("scan/libInnaITPKCS11Driver.dylib")
		self.file("outside/libescape_pkcs11.so")
		(scan / "linked-folder").symlink_to(outside, target_is_directory=True)
		(scan / "libescape-link-pkcs11.dylib").symlink_to(outside / "libescape_pkcs11.so")
		(scan / "libinside-link-pkcs11.dylib").symlink_to(scan / "a" / "libvendor-pkcs11.dylib")
		return scan

	def names(self, result):
		return sorted(Path(path).name for path in result.candidates)

	def test_matches_by_name_and_extension_within_depth(self):
		scan = self.build()
		result = drivers.find_drivers([(str(scan), 4)])
		self.assertEqual(
			sorted(
				[
					"libvendor-pkcs11.dylib",
					"libdeep_p11.so",
					"libcastle.so.1.0.0",
					"WDPKCS.DLL",
					"libInnaITPKCS11Driver.dylib",
					"libinside-link-pkcs11.dylib",
				]
			),
			self.names(result),
		)
		self.assertFalse(result.truncated)

	def test_never_follows_a_link_out_of_the_scanned_folder(self):
		scan = self.build()
		found = drivers.find_drivers([(str(scan), 6)]).candidates
		self.assertFalse([path for path in found if "escape" in path])
		self.assertFalse([path for path in found if "linked-folder" in path])

	def test_entry_and_time_bounds(self):
		scan = self.build()
		self.assertTrue(drivers.find_drivers([(str(scan), 4)], max_entries=3).truncated)
		ticks = iter(range(0, 1000, 50))
		self.assertTrue(drivers.find_drivers([(str(scan), 4)], max_seconds=10, clock=lambda: next(ticks)).truncated)

	@unittest.skipUnless(POSIX and os.geteuid() != 0, "needs POSIX permissions and a non-root user")
	def test_unreadable_folder_is_skipped(self):
		scan = self.build()
		os.chmod(scan / "a", 0)
		result = drivers.find_drivers([(str(scan), 4)])
		self.assertIn("WDPKCS.DLL", self.names(result))

	def test_missing_root_is_ignored(self):
		self.assertEqual([], drivers.find_drivers([(str(self.root / "nope"), 3)]).candidates)

	def test_per_system_folders(self):
		self.assertEqual([("/usr/local/lib", 1), ("/opt", 4), ("/Library", 4)], drivers.scan_roots("Darwin", {}))
		self.assertEqual(
			[
				("C:\\Windows\\System32", 0),
				("C:\\Windows\\SysWOW64", 0),
				("C:\\Program Files", 3),
				("C:\\Program Files (x86)", 3),
			],
			drivers.scan_roots("Windows", {}),
		)
		env = {"SystemRoot": "D:\\Win", "ProgramFiles": "D:\\Apps", "ProgramFiles(x86)": "D:\\Apps86", "ProgramW6432": "D:\\Apps"}
		self.assertEqual(
			[("D:\\Win\\System32", 0), ("D:\\Win\\SysWOW64", 0), ("D:\\Apps", 3), ("D:\\Apps86", 3)],
			drivers.scan_roots("Windows", env),
		)
		self.assertIn(("/usr/lib", 2), drivers.scan_roots("Linux", {}))

	def test_cli_prints_candidates_and_marks_known_ones(self):
		scan = self.build()
		known = str(scan / "WDPKCS.DLL")
		out = io.StringIO()
		with mock.patch.object(drivers, "scan_roots", return_value=[(str(scan), 4)]), mock.patch.object(
			drivers, "_known_paths", return_value={os.path.normcase(known)}
		), mock.patch.object(sys, "argv", ["erp-dsc-local", "--find-drivers"]), contextlib.redirect_stdout(out):
			with self.assertRaises(SystemExit) as raised:
				cli.main()
		self.assertEqual(0, raised.exception.code)
		text = out.getvalue()
		self.assertIn(known + "  (already known to the helper)", text)
		self.assertIn(str(scan / "a" / "libvendor-pkcs11.dylib"), text)
		self.assertIn("--add-module", text)
		self.assertIn("nothing was loaded", text.lower())


class AddModuleCase(TempTree):
	def setUp(self):
		super().setUp()
		self.config_dir = self.root / "state"
		self.config_dir.mkdir()
		self.config = self.config_dir / "config.json"
		self.original = (json.dumps(ORIGINAL_CONFIG, indent=2) + "\n").encode("utf-8")
		self.config.write_bytes(self.original)
		os.chmod(self.config, 0o644)
		self.lib_dir = self.root / "vendor"
		self.lib_dir.mkdir()
		os.chmod(self.lib_dir, 0o755)
		self.library = self.file("vendor/libTestVendorPKCS11.dylib", mode=0o755)
		# A library loaded in THIS process is the failure this command exists to avoid.
		targets = [(ctypes, "CDLL"), (ctypes.cdll, "LoadLibrary")]
		try:
			import PyKCS11

			targets.append((PyKCS11.PyKCS11Lib, "load"))
		except ImportError:
			pass
		for target, name in targets:
			patcher = mock.patch.object(target, name, side_effect=AssertionError("a library was loaded in-process"))
			patcher.start()
			self.addCleanup(patcher.stop)

	def add(self, path, *, verify=False, probe=None, system="Darwin"):
		out, err = io.StringIO(), io.StringIO()
		with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
			code = drivers.add_module(self.config, str(path), verify=verify, probe=probe, system=system)
		return code, out.getvalue(), err.getvalue()

	def assert_unchanged(self):
		self.assertEqual(self.original, self.config.read_bytes())
		self.assertFalse((self.config_dir / "config.json.bak").exists())
		self.assertEqual(["config.json"], sorted(p.name for p in self.config_dir.iterdir()))


class TestAddModuleAccepts(AddModuleCase):
	def test_writes_the_module_atomically_with_a_backup(self):
		code, out, _err = self.add(self.library)
		self.assertEqual(0, code, out)
		raw = json.loads(self.config.read_text(encoding="utf-8"))
		[entry] = raw["providers"]["custom_modules"]
		self.assertRegex(entry["id"], r"^custom-[A-Za-z0-9]+-[0-9a-f]{8}$")
		self.assertEqual(("generic_pkcs11", str(self.library)), (entry["provider"], entry["path"]))
		self.assertEqual(self.original, (self.config_dir / "config.json.bak").read_bytes())
		if POSIX:
			self.assertEqual(0o600, stat.S_IMODE(os.stat(self.config).st_mode))
			self.assertEqual(0o600, stat.S_IMODE(os.stat(self.config_dir / "config.json.bak").st_mode))
		self.assertEqual(["config.json", "config.json.bak"], sorted(p.name for p in self.config_dir.iterdir()))
		config = load_config(self.config)
		registry = ProviderRegistry(config, system="Darwin")
		self.assertIn(str(self.library), [m.path for m in registry.candidates("auto", None)])
		self.assertIn("Restart ERP DSC Signer", out)

	def test_id_is_plain_ascii_for_a_unicode_file_name(self):
		library = self.file("vendor/libé测试_pkcs11.dylib", mode=0o755)
		self.assertEqual(0, self.add(library)[0])
		[entry] = json.loads(self.config.read_text(encoding="utf-8"))["providers"]["custom_modules"]
		self.assertTrue(entry["id"].isascii())
		self.assertRegex(entry["id"], r"^custom-[A-Za-z0-9]+-[0-9a-f]{8}$")

	def test_versioned_so_and_dll_names_are_libraries(self):
		for name in ("libcastle.so.1.0.0", "WDPKCS.DLL", "opensc-pkcs11.so"):
			with self.subTest(name=name):
				self.assertTrue(drivers.plausible_library_name(name))
		for name in ("libfoo.dylib.txt", "pkcs11.py", "libfoo.so.x", "README"):
			with self.subTest(name=name):
				self.assertFalse(drivers.plausible_library_name(name))

	def test_verify_through_the_probe_child_then_add(self):
		seen = []
		code, out, _err = self.add(self.library, verify=True, probe=lambda path: seen.append(path) or {"result": "ok", "slots": []})
		self.assertEqual(0, code, out)
		self.assertEqual([str(self.library)], seen)
		self.assertIn("no token is connected", out)

	def test_default_verify_uses_the_killable_probe(self):
		with mock.patch.object(drivers, "run_probe", return_value={"result": "ok", "slots": [{}]}) as probe:
			code, out, _err = self.add(self.library, verify=True)
		self.assertEqual(0, code, out)
		probe.assert_called_once_with(str(self.library), "certificates")


class TestAddModuleRefuses(AddModuleCase):
	def assert_refused(self, path, fragment, **kwargs):
		code, out, err = self.add(path, **kwargs)
		self.assertNotEqual(0, code, out)
		self.assertIn(fragment, err)
		self.assert_unchanged()

	def test_relative_home_dotdot_and_control_characters(self):
		self.assert_refused("vendor/libTestVendorPKCS11.dylib", "absolute")
		self.assert_refused("~/libTestVendorPKCS11.dylib", "absolute")
		self.assert_refused(str(self.lib_dir / ".." / "vendor" / self.library.name), "'..'")
		self.assert_refused(str(self.library) + "\n", "control character")

	def test_missing_directory_and_wrong_extension(self):
		self.assert_refused(self.lib_dir / "libnothere.dylib", "does not exist")
		self.assert_refused(self.lib_dir, "not a regular file")
		self.assert_refused(self.file("vendor/libTestVendorPKCS11.txt"), "library file")

	def test_symlink_is_refused_with_the_real_path(self):
		link = self.lib_dir / "liblink.dylib"
		link.symlink_to(self.library)
		code, _out, err = self.add(link)
		self.assertNotEqual(0, code)
		self.assertIn("is a link", err)
		self.assertIn(str(self.library), err)
		self.assert_unchanged()

	@unittest.skipUnless(POSIX, "POSIX permission bits")
	def test_world_writable_file_or_folder(self):
		os.chmod(self.library, 0o777)
		self.assert_refused(self.library, "other users can change")
		os.chmod(self.library, 0o755)
		os.chmod(self.lib_dir, 0o777)
		self.assert_refused(self.library, "other users can change")

	@unittest.skipUnless(POSIX and os.geteuid() != 0, "needs a non-root user")
	def test_unreadable_file(self):
		os.chmod(self.library, 0o200)
		self.assert_refused(self.library, "cannot be read")

	@unittest.skipUnless(POSIX, "POSIX owners")
	def test_file_owned_by_another_user(self):
		with mock.patch.object(os, "getuid", return_value=os.getuid() + 4242):
			if os.stat(self.library).st_uid == 0:
				self.skipTest("running as root")
			self.assert_refused(self.library, "owned by another user")

	def test_duplicates(self):
		self.assertEqual(0, self.add(self.library)[0])
		self.original = self.config.read_bytes()
		backup = (self.config_dir / "config.json.bak").read_bytes()
		code, out, err = self.add(self.library)  # re-running an installer script must not fail
		self.assertEqual(0, code, err)
		self.assertIn("already", out)
		self.assertNotIn("Added", out)
		self.assertEqual(self.original, self.config.read_bytes())
		self.assertEqual(backup, (self.config_dir / "config.json.bak").read_bytes())

	def test_a_built_in_location_is_success_and_changes_nothing(self):
		# Windows test 2026-11-10: an installer script must not fail where the driver is a built-in path.
		with mock.patch.dict(KNOWN_PATHS, {"Darwin": {"generic_pkcs11": (str(self.library),)}}):
			code, out, err = self.add(self.library)
		self.assertEqual(0, code, err)
		self.assertIn("already known", out)
		self.assertNotIn("Added", out)
		self.assert_unchanged()

	def test_real_refusals_still_exit_2(self):
		code, _out, err = self.add("vendor/relative.dylib")
		self.assertEqual(2, code)
		self.assertIn("absolute", err)

	def test_bouncycastle_and_msvcp_are_not_drivers_but_epass_castle_is(self):
		for name in ("BouncyCastle.Crypto.dll", "msvcp110.dll", "msvcp110_win.dll", "libp11-kit-0.dll"):
			with self.subTest(name=name):
				self.assertFalse(drivers._looks_like_driver(name))
		for name in ("libcastle_v2.1.0.0.dylib", "libdeep_p11.so", "SignatureP11.dll", "opensc-pkcs11.so", "WDPKCS.DLL"):
			with self.subTest(name=name):
				self.assertTrue(drivers._looks_like_driver(name))

	def test_invalid_or_linked_config_is_never_rewritten(self):
		self.original = b"{not json"
		self.config.write_bytes(self.original)
		self.assert_refused(self.library, "config")
		self.config.unlink()
		real = self.root / "real-config.json"
		real.write_bytes(b"{}")
		self.config.symlink_to(real)
		code, _out, err = self.add(self.library)
		self.assertNotEqual(0, code)
		self.assertIn("link", err)
		self.assertEqual(b"{}", real.read_bytes())

	def test_verify_failures_write_nothing(self):
		def hung(_path):
			raise TokenDriverNotResponding()

		self.assert_refused(self.library, "could not be loaded", verify=True, probe=lambda path: {"result": "load_failed"})
		self.assert_refused(self.library, "did not answer", verify=True, probe=hung)
		self.assert_refused(self.library, "PyKCS11", verify=True, probe=lambda path: {"result": "dependency_missing"})

	def test_a_failed_replace_leaves_the_config_and_no_temp_file(self):
		real_replace = os.replace

		def failing(source, target):
			if Path(target) == self.config:
				raise OSError("disk full")
			return real_replace(source, target)

		with mock.patch.object(os, "replace", side_effect=failing):
			code, _out, _err = self.add(self.library)
		self.assertNotEqual(0, code)
		self.assertEqual(self.original, self.config.read_bytes())
		self.assertFalse([p.name for p in self.config_dir.iterdir() if p.name.endswith(".tmp")])


class TestCliAddModule(AddModuleCase):
	def test_cli_flags_reach_add_module(self):
		calls = []
		with mock.patch.object(drivers, "add_module", side_effect=lambda *a, **kw: calls.append((a, kw)) or 0), mock.patch.object(
			sys, "argv", ["erp-dsc-local", "--add-module", str(self.library), "--verify", "--config", str(self.config)]
		):
			with self.assertRaises(SystemExit) as raised:
				cli.main()
		self.assertEqual(0, raised.exception.code)
		self.assertEqual([((self.config, str(self.library)), {"verify": True})], [((Path(a[0]), a[1]), kw) for a, kw in calls])


if __name__ == "__main__":
	unittest.main()


def _pe(directory, name, machine, *, offset=0x80):
	path = Path(directory) / name
	head = bytearray(offset + 6)
	head[0:2] = b"MZ"
	head[0x3C:0x40] = offset.to_bytes(4, "little")
	head[offset : offset + 4] = b"PE\0\0"
	head[offset + 4 : offset + 6] = machine.to_bytes(2, "little")
	path.write_bytes(bytes(head))
	return str(path)


class TestDriverBitness(unittest.TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp(prefix="erp-dsc-pe-")
		self.addCleanup(shutil.rmtree, self.dir, True)

	def test_reads_the_machine_field(self):
		self.assertEqual("x64", drivers.driver_architecture(_pe(self.dir, "a.dll", 0x8664)))
		self.assertEqual("x86", drivers.driver_architecture(_pe(self.dir, "b.dll", 0x014C)))
		self.assertEqual("arm64", drivers.driver_architecture(_pe(self.dir, "c.dll", 0xAA64)))

	def test_not_a_windows_dll_is_unknown_not_unusable(self):
		other = Path(self.dir) / "libx.dylib"
		other.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(100))
		self.assertIsNone(drivers.driver_architecture(str(other)))
		self.assertIsNone(drivers.driver_architecture(str(Path(self.dir) / "missing.dll")))
		self.assertIsNone(drivers.unusable_reason(str(other)))

	def test_wrong_bitness_is_reported_with_plain_words(self):
		x86 = _pe(self.dir, "SignatureP11.dll", 0x014C)
		with mock.patch.object(drivers, "python_architecture", return_value="x64"):
			self.assertIn("32-bit driver; this Python is 64-bit and cannot use it", drivers.unusable_reason(x86))
			self.assertIsNone(drivers.unusable_reason(_pe(self.dir, "ok.dll", 0x8664)))
		with mock.patch.object(drivers, "python_architecture", return_value="x86"):
			self.assertIn("64-bit driver; this Python is 32-bit", drivers.unusable_reason(_pe(self.dir, "n.dll", 0x8664)))

	def test_find_drivers_tags_the_wrong_bitness(self):
		library = _pe(self.dir, "SignatureP11.dll", 0x014C)
		out = io.StringIO()
		with mock.patch.object(drivers, "python_architecture", return_value="x64"), mock.patch.object(
			drivers, "scan_roots", return_value=[(self.dir, 1)]
		), contextlib.redirect_stdout(out):
			drivers.find_drivers_command(Path(self.dir) / "config.json", system="Windows")
		self.assertRegex(out.getvalue(), r"SignatureP11\.dll.*32-bit driver; this Python is 64-bit")

	def test_look_alikes_seen_on_windows_are_not_drivers(self):
		for name in ("InnaITCSP.dll", "InnaITSmartCardMiniDriver.dll", "Pkcs11Interop.dll"):
			with self.subTest(name=name):
				self.assertFalse(drivers._looks_like_driver(name))
		self.assertTrue(drivers._looks_like_driver("HS2003-pkcs11.dll"))

	def test_relative_path_example_matches_the_system(self):
		with self.assertRaises(drivers.Refused) as win:
			drivers.check_module_path("vendor\\x.dll", system="Windows")
		self.assertIn("C:\\Windows", win.exception.message)
		with self.assertRaises(drivers.Refused) as mac:
			drivers.check_module_path("vendor/x.dylib", system="Darwin")
		self.assertIn("/usr/local/lib", mac.exception.message)


class TestReviewFindings(unittest.TestCase):
	"""Independent review 2026-11-11 of 61f087d..HEAD."""

	def test_every_built_in_driver_name_is_found_by_find_drivers(self):
		import ntpath

		names = set()
		for system, groups in KNOWN_PATHS.items():
			for paths in groups.values():
				names.update(ntpath.basename(p) if system == "Windows" else os.path.basename(p) for p in paths)
		missed = sorted(n for n in names if not drivers._looks_like_driver(n))
		self.assertEqual([], missed)
		self.assertFalse(drivers._looks_like_driver("msvcp110.dll"))

	def test_an_x64_python_on_arm64_windows_is_x64(self):
		with mock.patch("sysconfig.get_platform", return_value="win-amd64"), mock.patch("platform.machine", return_value="ARM64"):
			self.assertEqual("x64", drivers.python_architecture())
		with mock.patch("sysconfig.get_platform", return_value="win-arm64"):
			self.assertEqual("arm64", drivers.python_architecture())
		with mock.patch("sysconfig.get_platform", return_value="win32"):
			self.assertEqual("x86", drivers.python_architecture())

	def test_install_autostart_refuses_root(self):
		from erp_dsc_local import autostart

		ran = []
		err = io.StringIO()
		with contextlib.redirect_stderr(err):
			code = autostart.install("config.json", yes=True, system="Darwin", uid=0, runner=lambda *a, **k: ran.append(a))
		self.assertEqual(2, code)
		self.assertEqual([], ran)
		self.assertIn("not with sudo", err.getvalue())


@unittest.skipUnless(POSIX, "POSIX permission bits")
class TestDriverFolderPermissions(unittest.TestCase):
	def setUp(self):
		self.root = Path(tempfile.mkdtemp(prefix="erp-dsc-perm-"))
		self.addCleanup(shutil.rmtree, self.root, True)
		self.deep = self.root / "a" / "b"
		self.deep.mkdir(parents=True)
		self.library = self.deep / "libTestVendorPKCS11.dylib"
		self.library.write_bytes(b"x")
		os.chmod(self.library, 0o755)
		for folder in (self.root, self.root / "a", self.deep):
			os.chmod(folder, 0o755)

	def check(self):
		return drivers.check_module_path(str(self.library), system="Darwin")

	def test_a_private_tree_is_accepted(self):
		self.assertEqual(str(self.library), self.check())

	def test_group_write_on_the_file_is_refused(self):
		os.chmod(self.library, 0o775)
		with self.assertRaises(drivers.Refused):
			self.check()

	def test_group_write_on_the_folder_or_a_folder_above_is_refused(self):
		for folder in (self.deep, self.root / "a", self.root):
			with self.subTest(folder=str(folder)):
				os.chmod(folder, 0o775)
				with self.assertRaises(drivers.Refused):
					self.check()
				os.chmod(folder, 0o755)

	def test_a_folder_above_owned_by_another_user_is_refused(self):
		real = os.lstat
		other = os.getuid() + 4242

		def fake(path, *a, **k):
			info = real(path, *a, **k)
			if os.fspath(path) == str(self.root / "a"):
				fields = list(info)
				fields[4] = other
				return os.stat_result(fields)
			return info

		with mock.patch.object(os, "lstat", side_effect=fake), self.assertRaises(drivers.Refused) as ctx:
			self.check()
		self.assertIn("owned by another user", ctx.exception.message)


class TestPanelRound6(unittest.TestCase):
	def test_windows_driver_must_be_under_windows_or_program_files_and_not_a_network_path(self):
		env = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files", "ProgramFiles(x86)": r"C:\Program Files (x86)"}
		for good in (r"C:\Windows\System32\SignatureP11.dll", r"c:\windows\system32\x.dll", r"C:\Program Files\eMudhra\p11.dll"):
			with self.subTest(good=good):
				drivers._check_windows_location(good, env)
		for bad in (r"C:\Users\Public\p11.dll", r"D:\Windows\p11.dll", r"C:\Windows-evil\p11.dll", r"C:\Program Files-evil\p11.dll",
			r"C:\Windows\..\Users\x\p11.dll", r"\\server\share\p11.dll", r"\\?\UNC\server\share\p11.dll"):
			with self.subTest(bad=bad), self.assertRaises(drivers.Refused):
				drivers._check_windows_location(bad, env)

	def test_windows_path_through_a_link_or_junction_is_refused(self):
		drivers._check_windows_real_path(r"C:\Windows\System32\x.dll", resolve=lambda p: p)
		with self.assertRaises(drivers.Refused):
			drivers._check_windows_real_path(r"C:\Program Files\Vendor\x.dll", resolve=lambda p: r"C:\Users\Public\x.dll")

	def test_windows_acl_walk_checks_the_file_its_folder_and_every_folder_above(self):
		seen = []
		table = {}

		def aces(path):
			seen.append(path)
			return table.get(path, [("S-1-5-18", 0x1F01FF), ("S-1-5-32-544", 0x1F01FF), ("S-1-5-32-545", 0x1200A9)])

		driver = r"C:\Program Files\Vendor\bin\p11.dll"
		drivers._check_windows_acl(driver, aces)
		self.assertEqual(
			[driver, r"C:\Program Files\Vendor\bin", r"C:\Program Files\Vendor", r"C:\Program Files", "C:\\"], seen
		)
		for path, entry in (
			(driver, ("S-1-5-32-545", 0x2)),  # Users can write the file
			(r"C:\Program Files\Vendor\bin", ("S-1-5-11", 0x4)),  # Authenticated Users can add files to its folder
			(r"C:\Program Files\Vendor", ("S-1-5-32-545", 0x40)),  # delete children of a folder above
			(r"C:\Program Files", ("S-1-1-0", 0x10000)),  # Everyone can delete a folder above
			(driver, ("S-1-5-21-1-2-3-1001", 0x1F01FF)),  # a particular user account, not a named group (Codex round 9)
			(driver, ("S-1-5-21-1-2-3-513", 0x10000000)),  # a domain group with GENERIC_ALL
		):
			with self.subTest(path=path, entry=entry):
				table.clear()
				table[path] = [entry]
				with self.assertRaises(drivers.Refused):
					drivers._check_windows_acl(driver, aces)

	def test_windows_trusted_principals_may_write_and_read_only_entries_are_fine(self):
		trusted = [("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", 0x1F01FF), ("S-1-3-0", 0x1F01FF)]
		drivers._check_windows_acl(r"C:\Windows\System32\x.dll", lambda p: trusted + [("S-1-5-21-1-2-3-1001", 0x1200A9)])

	def test_windows_write_to_a_far_folder_is_not_a_replacement_risk_but_write_to_the_folder_is(self):
		# C:\ lets Authenticated Users create folders (0x4): that cannot replace a file two levels down.
		drivers._check_windows_acl(r"C:\Vendor\bin\p11.dll", lambda p: [("S-1-5-11", 0x4)] if p == "C:\\" else [])
		with self.assertRaises(drivers.Refused):
			drivers._check_windows_acl(r"C:\Windows\Temp\p11.dll", lambda p: [("S-1-5-32-545", 0x6)] if p == r"C:\Windows\Temp" else [])

	def test_windows_unreadable_permissions_refuse(self):
		def boom(path):
			raise OSError(5, "denied")

		with self.assertRaises(drivers.Refused) as ctx:
			drivers._check_windows_acl(r"C:\Windows\System32\x.dll", boom)
		self.assertIn("could not be checked", ctx.exception.message)

	def test_a_known_path_is_success_even_when_the_strict_check_would_refuse(self):
		root = Path(tempfile.mkdtemp(prefix="erp-dsc-known-"))
		self.addCleanup(shutil.rmtree, root, True)
		library = root / "libTestVendorPKCS11.dylib"
		library.write_bytes(b"x")
		os.chmod(library, 0o775)  # group-writable: the strict check refuses a NEW module here
		config = root / "config.json"
		config.write_text("{}", encoding="utf-8")
		out, err = io.StringIO(), io.StringIO()
		with mock.patch.dict(KNOWN_PATHS, {"Darwin": {"generic_pkcs11": (str(library),)}}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
			code = drivers.add_module(config, str(library), system="Darwin")
		self.assertEqual(0, code, err.getvalue())
		self.assertIn("already known", out.getvalue())
		self.assertEqual("{}", config.read_text(encoding="utf-8"))
		with contextlib.redirect_stderr(io.StringIO()):
			self.assertEqual(2, drivers.add_module(config, str(library), system="Darwin"))  # a new module is still refused

	def test_the_scan_stops_reading_a_huge_folder_at_the_bound(self):
		pulled = []

		class Entry:
			def __init__(self, n):
				self.name = f"f{n}.txt"

			def is_dir(self, **_):
				return False

			def is_file(self, **_):
				return False

			path = "x"

		def endless():
			for n in range(5000):
				pulled.append(n)
				yield Entry(n)

		class Listing:
			def __enter__(self):
				return endless()

			def __exit__(self, *_):
				return False

		with mock.patch.object(os, "scandir", return_value=Listing()), mock.patch.object(os.path, "isdir", return_value=True):
			result = drivers.find_drivers([("/x", 1)], max_entries=10)
		self.assertTrue(result.truncated)
		self.assertLessEqual(len(pulled), 12)
