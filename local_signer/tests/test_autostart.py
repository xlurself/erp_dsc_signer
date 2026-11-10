"""--install-autostart / --uninstall-autostart (BRD F4 phase 1): per user, no admin, explicit.

Every command and file is built by a pure function and asserted exactly here, including
paths with spaces, quotes and XML metacharacters.  Nothing is changed without --yes: the
default prints the plan and stops.  launchctl and schtasks are NEVER run by these tests:
every subprocess goes through an injected runner, and the default runner is checked to
pass an argument list with shell=False.  Temp HOME and temp config folders only.
"""

import contextlib
import io
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from erp_dsc_local import autostart, cli

POSIX = os.name != "nt"
LABEL = "com.xlurself.erp-dsc-local"
MAC_APP = "/Applications/ERP DSC Signer.app/Contents/MacOS/erp-dsc-local"
MAC_CONFIG = "/Users/Test Signer/.erp-dsc-local/config.json"
WIN_EXE = "C:\\Program Files\\ERP DSC Signer\\erp-dsc-local.exe"
WIN_CONFIG = "C:\\Users\\Test Signer\\.erp-dsc-local\\config.json"
TASK_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


class Runner:
	def __init__(self, results=None):
		self.calls = []
		self.results = results or {}

	def __call__(self, argv):
		self.calls.append(list(argv))
		code, stdout = self.results.get(argv[1] if len(argv) > 1 else "", (0, ""))
		return subprocess.CompletedProcess(argv, code, stdout, "")


class TestProgramArguments(unittest.TestCase):
	def test_frozen_helper_runs_itself(self):
		self.assertEqual([MAC_APP, "--config", MAC_CONFIG], autostart.program_arguments(MAC_CONFIG, executable=MAC_APP, frozen=True, system="Darwin"))

	def test_source_install_runs_the_interpreter_isolated(self):
		python = "/Users/Test Signer/.erp-dsc-local/venv/bin/python"
		self.assertEqual(
			[python, "-I", "-m", "erp_dsc_local.cli", "--config", MAC_CONFIG],
			autostart.program_arguments(MAC_CONFIG, executable=python, frozen=False, system="Darwin"),
		)

	def test_windows_source_install_prefers_the_windowless_interpreter(self):
		python = "C:\\Users\\Test Signer\\venv\\Scripts\\python.exe"
		pythonw = "C:\\Users\\Test Signer\\venv\\Scripts\\pythonw.exe"
		got = autostart.program_arguments(WIN_CONFIG, executable=python, frozen=False, system="Windows", path_exists=lambda p: p == pythonw)
		self.assertEqual([pythonw, "-I", "-m", "erp_dsc_local.cli", "--config", WIN_CONFIG], got)

	def test_refuses_a_relative_executable_or_config(self):
		for executable, config in (("python3", MAC_CONFIG), ("bin/erp-dsc-local", MAC_CONFIG), (MAC_APP, "config.json")):
			with self.subTest(executable=executable, config=config):
				with self.assertRaises(autostart.AutostartError):
					autostart.program_arguments(config, executable=executable, frozen=True, system="Darwin")
		with self.assertRaises(autostart.AutostartError):
			autostart.program_arguments("C:config.json", executable=WIN_EXE, frozen=True, system="Windows")

	def test_refuses_control_characters(self):
		for bad in (MAC_APP + "\n--evil", MAC_APP + "\x00"):
			with self.subTest(bad=bad), self.assertRaises(autostart.AutostartError):
				autostart.program_arguments(MAC_CONFIG, executable=bad, frozen=True, system="Darwin")


class TestLaunchAgent(unittest.TestCase):
	def test_plist_exactly(self):
		log_dir = "/Users/Test Signer/.erp-dsc-local/logs"
		data = autostart.build_launch_agent([MAC_APP, "--config", MAC_CONFIG], log_dir)
		self.assertEqual(
			{
				"Label": LABEL,
				"ProgramArguments": [MAC_APP, "--config", MAC_CONFIG],
				"RunAtLoad": True,
				"KeepAlive": True,
				"ThrottleInterval": 5,
				"ProcessType": "Interactive",
				"LimitLoadToSessionType": "Aqua",
				"Umask": 0o077,
				"StandardOutPath": log_dir + "/launchd-stdout.log",
				"StandardErrorPath": log_dir + "/launchd-stderr.log",
			},
			plistlib.loads(data),
		)
		text = data.decode("utf-8")
		self.assertIn(
			"<key>ProgramArguments</key>\n\t<array>\n"
			"\t\t<string>/Applications/ERP DSC Signer.app/Contents/MacOS/erp-dsc-local</string>\n"
			"\t\t<string>--config</string>\n"
			"\t\t<string>/Users/Test Signer/.erp-dsc-local/config.json</string>\n"
			"\t</array>",
			text,
		)
		for shell_marker in ("/bin/sh", "<string>-c</string>", "bash", "&&"):
			self.assertNotIn(shell_marker, text)

	def test_xml_metacharacters_and_quotes_are_escaped(self):
		config = '/Users/Test & <Signer> "Q\'s"/config.json'
		data = autostart.build_launch_agent([MAC_APP, "--config", config], "/tmp/l")
		self.assertIn("<string>/Users/Test &amp; &lt;Signer&gt; \"Q's\"/config.json</string>", data.decode("utf-8"))
		self.assertEqual(config, plistlib.loads(data)["ProgramArguments"][2])


class TestScheduledTask(unittest.TestCase):
	def parse(self, data):
		self.assertTrue(data.startswith(b"\xff\xfe"), "schtasks reads UTF-16 with a byte-order mark")
		return ET.fromstring(data.decode("utf-16"))

	def test_task_xml_exactly(self):
		user = "TESTPC\\Test Signer"
		data = autostart.build_task_xml(user, [WIN_EXE, "--config", WIN_CONFIG], "C:\\Users\\Test Signer\\.erp-dsc-local")
		root = self.parse(data)
		value = lambda path: root.find(path, TASK_NS).text  # noqa: E731
		self.assertEqual("erp-dsc-local", value("t:RegistrationInfo/t:Source"))
		self.assertEqual(user, value("t:Triggers/t:LogonTrigger/t:UserId"))
		self.assertEqual("true", value("t:Triggers/t:LogonTrigger/t:Enabled"))
		self.assertEqual(user, value("t:Principals/t:Principal/t:UserId"))
		self.assertEqual("InteractiveToken", value("t:Principals/t:Principal/t:LogonType"))
		self.assertEqual("LeastPrivilege", value("t:Principals/t:Principal/t:RunLevel"))
		self.assertEqual("IgnoreNew", value("t:Settings/t:MultipleInstancesPolicy"))
		self.assertEqual("PT0S", value("t:Settings/t:ExecutionTimeLimit"))
		self.assertEqual("false", value("t:Settings/t:DisallowStartIfOnBatteries"))
		self.assertEqual("false", value("t:Settings/t:StopIfGoingOnBatteries"))
		self.assertEqual("PT1M", value("t:Settings/t:RestartOnFailure/t:Interval"))
		self.assertEqual("999", value("t:Settings/t:RestartOnFailure/t:Count"))
		self.assertEqual(WIN_EXE, value("t:Actions/t:Exec/t:Command"))
		self.assertEqual('--config "C:\\Users\\Test Signer\\.erp-dsc-local\\config.json"', value("t:Actions/t:Exec/t:Arguments"))
		self.assertEqual("C:\\Users\\Test Signer\\.erp-dsc-local", value("t:Actions/t:Exec/t:WorkingDirectory"))
		self.assertEqual(1, len(root.findall("t:Actions/t:Exec", TASK_NS)))

	def test_arguments_quote_spaces_quotes_and_trailing_backslashes(self):
		data = autostart.build_task_xml("PC\\u", [WIN_EXE, "-I", "--config", 'C:\\A & B\\say "hi"\\'], "C:\\w")
		root = self.parse(data)
		self.assertEqual('-I --config "C:\\A & B\\say \\"hi\\"\\\\"', root.find("t:Actions/t:Exec/t:Arguments", TASK_NS).text)
		self.assertIn("C:\\A &amp; B", data.decode("utf-16"))


class AutostartCase(unittest.TestCase):
	def setUp(self):
		self.base = Path(tempfile.mkdtemp(prefix="erp-dsc-autostart-")).resolve()
		self.addCleanup(shutil.rmtree, self.base, True)
		self.home = self.base / "Test Signer home"
		self.home.mkdir()
		self.state = self.base / "state dir"
		self.state.mkdir()
		self.config = self.state / "config.json"
		self.config.write_text("{}", encoding="utf-8")
		self.runner = Runner({"bootout": (3, "")})
		self.plist = self.home / "Library" / "LaunchAgents" / f"{LABEL}.plist"

	def run_cmd(self, fn, **kwargs):
		out, err = io.StringIO(), io.StringIO()
		options = {"system": "Darwin", "runner": self.runner, "home": self.home, "uid": 501, "executable": MAC_APP, "frozen": True}
		options.update(kwargs)
		with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
			code = fn(self.config, **options)
		return code, out.getvalue(), err.getvalue()


class TestMacInstall(AutostartCase):
	def test_dry_run_by_default_changes_nothing(self):
		code, out, _err = self.run_cmd(autostart.install)
		self.assertEqual(0, code)
		self.assertEqual([], self.runner.calls)
		self.assertFalse((self.home / "Library").exists())
		self.assertFalse((self.state / "logs").exists())
		self.assertIn(str(self.plist), out)
		self.assertIn("/bin/launchctl bootstrap gui/501", out)
		self.assertIn("<string>" + MAC_APP + "</string>", out)
		self.assertIn("Dry run: nothing was changed", out)

	def test_yes_writes_the_plist_and_loads_it_as_the_user(self):
		code, out, err = self.run_cmd(autostart.install, yes=True)
		self.assertEqual(0, code, out + err)
		self.assertEqual(
			[
				["/bin/launchctl", "bootout", f"gui/501/{LABEL}"],
				["/bin/launchctl", "bootstrap", "gui/501", str(self.plist)],
			],
			self.runner.calls,
		)
		data = plistlib.loads(self.plist.read_bytes())
		self.assertEqual([MAC_APP, "--config", str(self.config)], data["ProgramArguments"])
		self.assertEqual(str(self.state / "logs" / "launchd-stderr.log"), data["StandardErrorPath"])
		if POSIX:
			self.assertEqual(0o600, stat.S_IMODE(os.stat(self.plist).st_mode))
			self.assertEqual(0o700, stat.S_IMODE(os.stat(self.state / "logs").st_mode))
			for name in ("launchd-stdout.log", "launchd-stderr.log"):
				self.assertEqual(0o600, stat.S_IMODE(os.stat(self.state / "logs" / name).st_mode))

	def test_installing_twice_is_the_same_state(self):
		self.run_cmd(autostart.install, yes=True)
		first = self.plist.read_bytes()
		self.runner.calls.clear()
		code, _out, _err = self.run_cmd(autostart.install, yes=True)
		self.assertEqual(0, code)
		self.assertEqual(first, self.plist.read_bytes())
		self.assertEqual(["bootout", "bootstrap"], [call[1] for call in self.runner.calls])
		self.assertEqual([f"{LABEL}.plist"], [p.name for p in self.plist.parent.iterdir()])

	def test_a_failed_bootstrap_is_reported(self):
		self.runner.results["bootstrap"] = (5, "")
		code, _out, err = self.run_cmd(autostart.install, yes=True)
		self.assertNotEqual(0, code)
		self.assertIn("launchctl bootstrap", err)

	def test_relative_executable_is_refused_before_anything(self):
		code, _out, err = self.run_cmd(autostart.install, yes=True, executable="erp-dsc-local")
		self.assertEqual(2, code)
		self.assertIn("absolute", err)
		self.assertEqual([], self.runner.calls)
		self.assertFalse((self.home / "Library").exists())

	def test_a_missing_or_broken_config_is_refused(self):
		self.config.write_text("{bad", encoding="utf-8")
		code, _out, err = self.run_cmd(autostart.install, yes=True)
		self.assertEqual(2, code)
		self.assertIn("config", err)
		self.assertEqual([], self.runner.calls)


class TestMacUninstall(AutostartCase):
	def test_dry_run_then_yes_removes_only_our_plist(self):
		self.run_cmd(autostart.install, yes=True)
		other = self.plist.parent / "com.example.other.plist"
		other.write_bytes(plistlib.dumps({"Label": "com.example.other"}))
		self.runner.calls.clear()
		code, out, _err = self.run_cmd(autostart.uninstall)
		self.assertEqual(0, code)
		self.assertEqual([], self.runner.calls)
		self.assertTrue(self.plist.exists())
		self.assertIn("Dry run: nothing was changed", out)
		code, _out, _err = self.run_cmd(autostart.uninstall, yes=True)
		self.assertEqual(0, code)
		self.assertEqual([["/bin/launchctl", "bootout", f"gui/501/{LABEL}"]], self.runner.calls)
		self.assertFalse(self.plist.exists())
		self.assertTrue(other.exists())
		self.assertTrue(self.config.exists())

	def test_a_plist_this_tool_did_not_write_is_left_alone(self):
		self.plist.parent.mkdir(parents=True)
		self.plist.write_bytes(plistlib.dumps({"Label": "com.example.impostor", "ProgramArguments": ["/bin/true"]}))
		code, _out, err = self.run_cmd(autostart.uninstall, yes=True)
		self.assertNotEqual(0, code)
		self.assertIn("not one this tool wrote", err)
		self.assertTrue(self.plist.exists())
		self.assertEqual([], self.runner.calls)

	def test_nothing_installed(self):
		code, out, _err = self.run_cmd(autostart.uninstall, yes=True)
		self.assertEqual(0, code)
		self.assertIn("does not exist", out)


class TestWindows(AutostartCase):
	def win(self, fn, **kwargs):
		options = {"system": "Windows", "executable": WIN_EXE, "frozen": True, "user_id": "TESTPC\\Test Signer", "home": None, "uid": None}
		options.update(kwargs)
		return self.run_cmd(fn, **options)

	def test_install_creates_the_task_from_an_xml_file_then_removes_the_file(self):
		seen = {}

		def runner(argv):
			seen["argv"] = list(argv)
			seen["xml"] = Path(argv[5]).read_bytes()
			return subprocess.CompletedProcess(argv, 0, "", "")

		code, out, err = self.win(autostart.install, yes=True, runner=runner)
		self.assertEqual(0, code, out + err)
		schtasks = seen["argv"][0]
		self.assertTrue(schtasks.lower().endswith("\\system32\\schtasks.exe"))
		self.assertEqual(["/Create", "/TN", "ERP DSC Signer", "/XML", seen["argv"][5], "/F"], seen["argv"][1:])
		self.assertEqual(Path(seen["argv"][5]).parent, self.state)
		root = ET.fromstring(seen["xml"].decode("utf-16"))
		self.assertEqual(WIN_EXE, root.find("t:Actions/t:Exec/t:Command", TASK_NS).text)
		self.assertFalse(Path(seen["argv"][5]).exists())

	def test_install_dry_run(self):
		code, out, _err = self.win(autostart.install)
		self.assertEqual(0, code)
		self.assertEqual([], self.runner.calls)
		self.assertIn('/Create /TN "ERP DSC Signer"', out)
		self.assertEqual(["config.json"], [p.name for p in self.state.iterdir()])

	def test_uninstall_deletes_only_a_task_this_tool_created(self):
		ours = autostart.build_task_xml("PC\\u", [WIN_EXE, "--config", WIN_CONFIG], "C:\\w").decode("utf-16")
		runner = Runner({"/Query": (0, ours)})
		code, _out, _err = self.win(autostart.uninstall, yes=True, runner=runner)
		self.assertEqual(0, code)
		self.assertEqual(["/Query", "/Delete"], [call[1] for call in runner.calls])
		self.assertEqual(["/Delete", "/TN", "ERP DSC Signer", "/F"], runner.calls[1][1:])
		foreign = ours.replace("<Source>erp-dsc-local</Source>", "<Source>someone-else</Source>")
		runner = Runner({"/Query": (0, foreign)})
		code, _out, err = self.win(autostart.uninstall, yes=True, runner=runner)
		self.assertNotEqual(0, code)
		self.assertIn("not one this tool created", err)
		self.assertEqual(["/Query"], [call[1] for call in runner.calls])


class TestOtherSystemsAndDefaults(AutostartCase):
	def test_linux_is_not_supported(self):
		code, out, err = self.run_cmd(autostart.install, yes=True, system="Linux")
		self.assertEqual(1, code)
		self.assertIn("not supported", out + err)
		self.assertEqual([], self.runner.calls)

	def test_default_runner_uses_an_argument_list_without_a_shell(self):
		with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
			autostart.run_command(["/bin/launchctl", "bootout", "gui/501/x"])
		args, kwargs = run.call_args
		self.assertEqual(["/bin/launchctl", "bootout", "gui/501/x"], args[0])
		self.assertIs(False, kwargs["shell"])
		self.assertIn("timeout", kwargs)

	def test_cli_passes_yes_and_defaults_to_dry_run(self):
		calls = []
		fake = lambda path, **kw: calls.append((Path(path), kw)) or 0  # noqa: E731
		for argv, expected in ((["--install-autostart"], False), (["--install-autostart", "--yes"], True)):
			with mock.patch.object(autostart, "install", side_effect=fake), mock.patch.object(
				sys, "argv", ["erp-dsc-local", *argv, "--config", str(self.config)]
			):
				with self.assertRaises(SystemExit) as raised:
					cli.main()
			self.assertEqual(0, raised.exception.code)
			self.assertEqual((self.config, {"yes": expected}), calls[-1])
		with mock.patch.object(autostart, "uninstall", side_effect=fake), mock.patch.object(
			sys, "argv", ["erp-dsc-local", "--uninstall-autostart", "--config", str(self.config)]
		):
			with self.assertRaises(SystemExit):
				cli.main()
		self.assertEqual((self.config, {"yes": False}), calls[-1])


if __name__ == "__main__":
	unittest.main()
