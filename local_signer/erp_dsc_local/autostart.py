"""Start the signer at login for THIS user, without administrator rights (BRD F4 phase 1).

Explicit commands only (the installer will call them later):

* macOS: ``~/Library/LaunchAgents/com.xlurself.erp-dsc-local.plist`` (RunAtLoad, KeepAlive,
  ThrottleInterval 5, Umask 077, stdout/stderr into the helper's log folder), loaded with
  ``launchctl bootstrap gui/<uid>``.  Re-installing first runs ``launchctl bootout`` for the
  same label, so running the command twice gives the same state.
* Windows: a per-user Scheduled Task "ERP DSC Signer" (logon trigger for this user,
  InteractiveToken, LeastPrivilege, restart on failure), created by ``schtasks /Create /XML``
  from a file written in the helper's own folder and removed afterwards.  NOT verified on a
  Windows machine yet.
* Anything else: not supported.

``ProgramArguments`` / the task's command line is the program running NOW (the packaged
helper, or this Python interpreter with ``-I -m erp_dsc_local.cli``) and the absolute
config path: always an argument list, never a shell string.  A relative path or one with a
control character is refused.  Every subprocess is an argument list with ``shell=False``,
by absolute path (``/bin/launchctl``, ``%SystemRoot%\\System32\\schtasks.exe``).

Nothing changes unless ``yes=True`` (``--yes``): otherwise the plan is printed and the
command stops.  Uninstall removes only what this tool created: on macOS the plist at our
label's path whose Label is ours, on Windows the task whose RegistrationInfo/Source is
``erp-dsc-local``.  It never touches the config, the pairing list or the logs.
"""

from __future__ import annotations

import contextlib
import ntpath
import os
import platform
import plistlib
import posixpath
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .cli import _printable
from .config import load_config
from .errors import ConfigurationError
from .logs import ensure_private_dir, log_dir, open_private

LABEL = "com.xlurself.erp-dsc-local"
TASK_NAME = "ERP DSC Signer"
TASK_SOURCE = "erp-dsc-local"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TASK_FILE_NAME = "erp-dsc-local-task.xml"
LAUNCHCTL = "/bin/launchctl"
STDOUT_NAME = "launchd-stdout.log"
STDERR_NAME = "launchd-stderr.log"
COMMAND_TIMEOUT_SECONDS = 30
_CREATE_NO_WINDOW = 0x08000000


class AutostartError(Exception):
	pass


# --- pure builders ------------------------------------------------------------------------


def _is_absolute(value: str, system: str) -> bool:
	if system != "Windows":
		return posixpath.isabs(value)
	if ntpath.isabs(value) and ntpath.splitdrive(value)[0]:
		return True  # C:\... or \\server\share\...
	# Planning a Windows task on a POSIX machine (the unit tests): the config file is a real
	# local path there.  On Windows itself os.name is "nt" and this is never reached.
	return os.name != "nt" and posixpath.isabs(value)


def _check_path(value, what: str, system: str) -> str:
	if not isinstance(value, str) or not value:
		raise AutostartError(f"the {what} path is missing.")
	if _printable(value) != value:
		raise AutostartError(f"the {what} path contains a control character.")
	if not _is_absolute(value, system):
		raise AutostartError(f"the {what} path must be absolute: {_printable(value)}")
	return value


def program_arguments(config_path, *, executable=None, frozen=None, system=None, path_exists=None) -> list:
	"""The argument list that starts the CURRENT program with ``--config <config_path>``."""
	system = system or platform.system()
	executable = sys.executable if executable is None else executable
	frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
	_check_path(executable, "program", system)
	config = _check_path(os.fspath(config_path), "config", system)
	if frozen:
		return [executable, "--config", config]
	if system == "Windows":
		folder, name = ntpath.split(executable)
		windowless = ntpath.join(folder, "pythonw.exe")
		if name.lower() == "python.exe" and (path_exists or os.path.isfile)(windowless):
			executable = windowless  # no console window at every logon
	return [executable, "-I", "-m", "erp_dsc_local.cli", "--config", config]


def build_launch_agent(arguments, log_folder) -> bytes:
	log_folder = os.fspath(log_folder)
	return plistlib.dumps(
		{
			"Label": LABEL,
			"ProgramArguments": list(arguments),
			"RunAtLoad": True,
			"KeepAlive": True,
			"ThrottleInterval": 5,
			"ProcessType": "Interactive",  # it shows the PIN and pairing dialogs
			"LimitLoadToSessionType": "Aqua",  # a desktop login only, never an SSH session
			"Umask": 0o077,  # every file the signer creates is user-only
			"StandardOutPath": posixpath.join(log_folder, STDOUT_NAME),
			"StandardErrorPath": posixpath.join(log_folder, STDERR_NAME),
		},
		fmt=plistlib.FMT_XML,
		sort_keys=True,
	)


def build_task_xml(user_id: str, arguments, working_dir: str) -> bytes:
	"""Task Scheduler 1.2 XML, UTF-16LE with a byte-order mark (what ``schtasks /XML`` reads)."""
	for value in (user_id, working_dir, *arguments):
		if not isinstance(value, str) or _printable(value) != value:
			raise AutostartError("a task value is missing or contains a control character.")

	def add(parent, tag, text=None):
		element = ET.SubElement(parent, tag)
		if text is not None:
			element.text = text
		return element

	task = ET.Element("Task", {"version": "1.2", "xmlns": TASK_NS})
	info = add(task, "RegistrationInfo")
	add(info, "Source", TASK_SOURCE)
	add(info, "Description", "Starts ERP DSC Signer when this user logs on and restarts it if it fails.")
	logon = add(add(task, "Triggers"), "LogonTrigger")
	add(logon, "Enabled", "true")
	add(logon, "UserId", user_id)
	principal = add(add(task, "Principals"), "Principal")
	principal.set("id", "Author")
	add(principal, "UserId", user_id)
	add(principal, "LogonType", "InteractiveToken")
	add(principal, "RunLevel", "LeastPrivilege")
	settings = add(task, "Settings")
	for tag, value in (
		("MultipleInstancesPolicy", "IgnoreNew"),
		("DisallowStartIfOnBatteries", "false"),
		("StopIfGoingOnBatteries", "false"),
		("AllowHardTerminate", "true"),
		("StartWhenAvailable", "true"),
		("RunOnlyIfNetworkAvailable", "false"),
		("AllowStartOnDemand", "true"),
		("Enabled", "true"),
		("Hidden", "false"),
		("RunOnlyIfIdle", "false"),
		("WakeToRun", "false"),
		("ExecutionTimeLimit", "PT0S"),
		("Priority", "7"),
	):
		add(settings, tag, value)
	idle = add(settings, "IdleSettings")
	add(idle, "StopOnIdleEnd", "false")
	add(idle, "RestartOnIdle", "false")
	restart = add(settings, "RestartOnFailure")
	add(restart, "Interval", "PT1M")  # the shortest Task Scheduler allows
	add(restart, "Count", "999")
	actions = add(task, "Actions")
	actions.set("Context", "Author")
	command = add(actions, "Exec")
	add(command, "Command", arguments[0])
	if len(arguments) > 1:
		add(command, "Arguments", subprocess.list2cmdline(list(arguments[1:])))
	add(command, "WorkingDirectory", working_dir)
	text = '<?xml version="1.0" encoding="UTF-16"?>\n' + ET.tostring(task, encoding="unicode")
	return b"\xff\xfe" + text.encode("utf-16-le")


def schtasks_path(env=None) -> str:
	env = os.environ if env is None else env
	return ntpath.join(env.get("SystemRoot") or "C:\\Windows", "System32", "schtasks.exe")


def current_windows_user() -> str:
	"""``DOMAIN\\user`` of this process (GetUserNameExW, NameSamCompatible)."""
	try:
		import ctypes
		from ctypes import wintypes

		secur32 = ctypes.WinDLL("secur32")
		size = wintypes.DWORD(0)
		secur32.GetUserNameExW(2, None, ctypes.byref(size))
		buffer = ctypes.create_unicode_buffer(size.value or 1)
		if secur32.GetUserNameExW(2, buffer, ctypes.byref(size)) and buffer.value:
			return buffer.value
	except Exception:
		pass
	domain, user = os.environ.get("USERDOMAIN"), os.environ.get("USERNAME")
	if user:
		return f"{domain}\\{user}" if domain else user
	raise AutostartError("the current Windows user could not be determined.")


# --- plans --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
	kind: str  # mkdir | private_dir | touch | write | remove | run | run_optional | check_task
	path: str = ""
	argv: tuple = ()
	content: bytes = b""
	always: bool = False  # also after an earlier step failed (clean-up)


def launch_agent_path(home) -> Path:
	return Path(home) / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _mac_install_steps(arguments, config: Path, home, uid) -> list:
	plist = launch_agent_path(home)
	logs = log_dir(config)
	return [
		Step("mkdir", str(plist.parent)),
		Step("private_dir", str(logs)),
		Step("touch", str(logs / STDOUT_NAME)),
		Step("touch", str(logs / STDERR_NAME)),
		Step("write", str(plist), content=build_launch_agent(arguments, logs)),
		Step("run_optional", argv=(LAUNCHCTL, "bootout", f"gui/{uid}/{LABEL}")),
		Step("run", argv=(LAUNCHCTL, "bootstrap", f"gui/{uid}", str(plist))),
	]


def _mac_uninstall_steps(home, uid) -> list:
	plist = launch_agent_path(home)
	steps = [Step("run_optional", argv=(LAUNCHCTL, "bootout", f"gui/{uid}/{LABEL}"))]
	if plist.exists() or plist.is_symlink():
		data = None
		with contextlib.suppress(Exception):
			if not plist.is_symlink():
				data = plistlib.loads(plist.read_bytes())
		if not isinstance(data, dict) or data.get("Label") != LABEL:
			raise AutostartError(f"{_printable(str(plist))} is not one this tool wrote; it was left alone.")
		steps.append(Step("remove", str(plist)))
	return steps


def _windows_install_steps(arguments, config: Path, user_id) -> list:
	task_file = str(config.parent / TASK_FILE_NAME)
	xml = build_task_xml(user_id, arguments, str(config.parent))
	return [
		Step("write", task_file, content=xml),
		Step("run", argv=(schtasks_path(), "/Create", "/TN", TASK_NAME, "/XML", task_file, "/F")),
		Step("remove", task_file, always=True),
	]


def _windows_uninstall_steps() -> list:
	return [
		Step("check_task", argv=(schtasks_path(), "/Query", "/TN", TASK_NAME, "/XML")),
		Step("run", argv=(schtasks_path(), "/Delete", "/TN", TASK_NAME, "/F")),
	]


def _command_line(argv, system) -> str:
	return subprocess.list2cmdline(list(argv)) if system == "Windows" else shlex.join(argv)


def describe(steps, system) -> list:
	lines = []
	for step in steps:
		shown = _printable(step.path)
		if step.kind == "mkdir":
			lines.append(f"- Create the folder {shown} if it does not exist")
		elif step.kind == "private_dir":
			lines.append(f"- Create the folder {shown} if it does not exist (only you can open it)")
		elif step.kind == "touch":
			lines.append(f"- Create the empty file {shown} if it does not exist (only you can read it)")
		elif step.kind == "write":
			lines.append(f"- Write {shown} (only you can read it), replacing it if it exists:")
			text = step.content[2:].decode("utf-16-le") if step.content.startswith(b"\xff\xfe") else step.content.decode("utf-8")
			lines += ["    " + _printable(line.replace("\t", "  ")) for line in text.splitlines()]
		elif step.kind == "remove":
			lines.append(f"- Delete {shown}")
		elif step.kind == "run_optional":
			lines.append(f"- Run: {_command_line(step.argv, system)}   (an error here only means it was not loaded)")
		elif step.kind == "check_task":
			lines.append(f"- Run: {_command_line(step.argv, system)}   (delete only if this tool created the task)")
		else:
			lines.append(f"- Run: {_command_line(step.argv, system)}")
	return lines


# --- doing it -------------------------------------------------------------------------------


def run_command(argv):
	"""The default runner: an argument list, no shell, no stdin, bounded in time."""
	kwargs = {
		"shell": False,
		"check": False,
		"capture_output": True,
		"stdin": subprocess.DEVNULL,
		"close_fds": True,
		"timeout": COMMAND_TIMEOUT_SECONDS,
	}
	if os.name == "nt":
		kwargs["creationflags"] = _CREATE_NO_WINDOW
	return subprocess.run(list(argv), **kwargs)


def _first_line(value) -> str:
	if isinstance(value, bytes):
		value = value.decode("utf-8", "replace")
	lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
	return _printable(lines[0])[:200] if lines else ""


def _ours(output) -> bool:
	marker = f"<Source>{TASK_SOURCE}</Source>"
	if isinstance(output, str):
		return marker in output
	output = output or b""
	return marker.encode("utf-8") in output or marker.encode("utf-16-le") in output


def _write_private_file(path: str, data: bytes) -> None:
	target = Path(path)
	handle, temp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
	try:
		with os.fdopen(handle, "wb") as stream:
			stream.write(data)
			stream.flush()
			os.fsync(stream.fileno())
		if os.name != "nt":
			os.chmod(temp, 0o600)
		os.replace(temp, target)
	except BaseException:
		with contextlib.suppress(OSError):
			os.unlink(temp)
		raise


def _execute(steps, runner, system) -> int:
	failed = 0
	for step in steps:
		if failed and not step.always:
			continue
		try:
			if step.kind == "mkdir":
				Path(step.path).mkdir(mode=0o700, parents=True, exist_ok=True)
			elif step.kind == "private_dir":
				ensure_private_dir(step.path)
			elif step.kind == "touch":
				open_private(step.path).close()
			elif step.kind == "write":
				_write_private_file(step.path, step.content)
			elif step.kind == "remove":
				with contextlib.suppress(FileNotFoundError):
					os.unlink(step.path)
			else:
				try:
					result = runner(list(step.argv))
					code, stdout, stderr = result.returncode, result.stdout, result.stderr
				except subprocess.TimeoutExpired:
					code, stdout, stderr = None, "", "it did not finish in time"
				if step.kind == "check_task":
					if code != 0:
						print(f'The scheduled task "{TASK_NAME}" does not exist; nothing to remove.')
						return 0
					if not _ours(stdout):
						print(f'error: the task "{TASK_NAME}" is not one this tool created; it was left alone.', file=sys.stderr)
						return 1
				elif step.kind == "run" and code != 0:
					detail = _first_line(stderr) or _first_line(stdout)
					print(f"error: {_command_line(step.argv[:2], system)} failed (exit {code}){': ' + detail if detail else ''}", file=sys.stderr)
					failed = 1
		except OSError as exc:
			print(f"error: could not {step.kind} {_printable(step.path)} ({type(exc).__name__})", file=sys.stderr)
			failed = 1
	return failed


def _prepare(config_path, system, executable, frozen, path_exists):
	config = Path(os.path.abspath(os.path.expanduser(os.fspath(config_path))))
	if not config.is_file():
		raise AutostartError(f"the config file {_printable(str(config))} does not exist; create it first.")
	try:
		load_config(config)
	except ConfigurationError as exc:
		raise AutostartError(f"the config file cannot be used: {exc.message}") from None
	arguments = program_arguments(config, executable=executable, frozen=frozen, system=system, path_exists=path_exists)
	return config, arguments


def _finish(steps, *, yes, runner, system, intro, done) -> int:
	print(intro)
	for line in describe(steps, system):
		print(line)
	if not yes:
		print("Dry run: nothing was changed. Run the same command again with --yes to make these changes.")
		return 0
	print("Making these changes now.")
	code = _execute(steps, runner or run_command, system)
	if code == 0:
		print(done)
	return code


def install(config_path, *, yes=False, system=None, runner=None, home=None, uid=None, executable=None, frozen=None, user_id=None, path_exists=None) -> int:
	system = system or platform.system()
	if system not in ("Darwin", "Windows"):
		print(f"Starting the signer at login is not supported on {system} by this tool.", file=sys.stderr)
		return 1
	try:
		config, arguments = _prepare(config_path, system, executable, frozen, path_exists)
		if system == "Darwin":
			steps = _mac_install_steps(arguments, config, home or Path.home(), os.getuid() if uid is None else uid)
		else:
			steps = _windows_install_steps(arguments, config, user_id or current_windows_user())
	except AutostartError as exc:
		print(f"error: {exc}", file=sys.stderr)
		return 2
	return _finish(
		steps,
		yes=yes,
		runner=runner,
		system=system,
		intro="To start ERP DSC Signer at every login for this user (no administrator rights), this command will:",
		done="Done. ERP DSC Signer now starts at every login and is started again if it stops. "
		"If you also start it by hand in a terminal, stop that copy: only one can use the port.",
	)


def uninstall(config_path=None, *, yes=False, system=None, runner=None, home=None, uid=None, **_ignored) -> int:
	system = system or platform.system()
	if system not in ("Darwin", "Windows"):
		print(f"Starting the signer at login is not supported on {system} by this tool.", file=sys.stderr)
		return 1
	try:
		if system == "Darwin":
			home = Path(home or Path.home())
			steps = _mac_uninstall_steps(home, os.getuid() if uid is None else uid)
			if len(steps) == 1:
				print(f"{_printable(str(launch_agent_path(home)))} does not exist.")
		else:
			steps = _windows_uninstall_steps()
	except AutostartError as exc:
		print(f"error: {exc}", file=sys.stderr)
		return 1
	return _finish(
		steps,
		yes=yes,
		runner=runner,
		system=system,
		intro="To stop starting ERP DSC Signer at login (your settings, paired sites and logs are kept), this command will:",
		done="Done. ERP DSC Signer no longer starts at login.",
	)
