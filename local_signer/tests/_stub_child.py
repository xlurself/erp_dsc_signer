"""Stand-in dialog child for the DialogHost tests.  Never imported by tests; spawned.

Launched as `[sys.executable, "-I", <this file>]` via `DialogHost(child_script=...)`.
It reads ONE request line with `readline()` (so it only proceeds if the parent sends a
newline-terminated line while keeping stdin open) and then behaves per the MODE in the
request's first claim: `MODE:<name>[:<arg>]`.  Extra arguments ride in claims[1].

Stdlib only: under -I the package is not importable.  The real `watch_eof` is loaded
from dialog_child.py with runpy where a mode needs it.
"""

import json
import os
import runpy
import select
import signal
import sys
import time
from pathlib import Path


DIALOG_CHILD = Path(__file__).resolve().parent.parent / "erp_dsc_local" / "dialog_child.py"
MAX_REPLY_BYTES = 4096  # mirrors dialog_child.MAX_REPLY_BYTES; a test asserts they match


def write(data: bytes) -> None:
	view = memoryview(data)
	while view:
		view = view[os.write(1, view) :]


def line(obj) -> bytes:
	return json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"


def hang() -> None:
	while True:
		time.sleep(1)


def _windows_stdin_state() -> str:
	# select() only works on sockets on Windows: read one byte on a helper thread instead.
	import threading

	got = []

	def read_one():
		got.append(os.read(0, 1))

	thread = threading.Thread(target=read_one, daemon=True)
	thread.start()
	thread.join(0.3)
	if not got:
		return "open"
	return "eof" if got[0] == b"" else "extra"


def stdin_state() -> str:
	if os.name == "nt":
		return _windows_stdin_state()
	readable, _w, _x = select.select([0], [], [], 0.3)
	if not readable:
		return "open"
	return "eof" if os.read(0, 1) == b"" else "extra"


def main() -> None:
	raw = sys.stdin.buffer.readline()
	if not raw.endswith(b"\n"):
		os._exit(9)
	request = json.loads(raw)
	kind = request["kind"]
	claims = request["claims"]
	_prefix, name, arg = (claims[0].split(":", 2) + ["", ""])[:3]
	extra = claims[1] if len(claims) > 1 else ""

	def reply(result, **fields):
		return line({"v": 1, "kind": kind, "result": result, **fields})

	if name == "ok_entered":
		write(reply("entered", value=arg))
	elif name == "result":
		write(reply(arg))
	elif name == "unavailable":
		write(reply("unavailable", cause=arg))
	elif name == "raw":
		write(extra.encode("utf-8") + b"\n")
	elif name == "crash":
		os.kill(os.getpid(), signal.SIGKILL)
		hang()
	elif name == "exit":
		os._exit(int(arg))
	elif name == "empty":
		pass
	elif name == "partial":
		write(reply("cancelled")[:-1])
	elif name == "badjson":
		write(b'{"v":1,"kind":"pin","result":"entered","value":"' + arg.encode() + b'"\n')
	elif name == "extra_line":
		write(reply("entered", value=arg) + reply("cancelled"))
	elif name == "oversize":
		head = b'{"v":1,"kind":"pin","result":"entered","value":"' + arg.encode()
		write(head + b"x" * (MAX_REPLY_BYTES + 64))
		hang()
	elif name == "oversize_line":
		# One line, newline included, of exactly MAX_REPLY_BYTES + 1 bytes.
		write(b"x" * MAX_REPLY_BYTES + b"\n")
		hang()
	elif name == "hang":
		hang()
	elif name == "ignore_term":
		signal.signal(signal.SIGTERM, signal.SIG_IGN)
		hang()
	elif name == "reply_then_hang":
		write(reply("entered", value=arg) if arg else reply("cancelled"))
		hang()
	elif name == "badjson_then_hang":
		write(b"not json\n")
		hang()
	elif name == "valid_then_exit":
		write(reply("entered", value=extra) if extra else reply("cancelled"))
		os._exit(int(arg))
	elif name == "report":
		report = {
			"argv": sys.argv,
			"executable": sys.executable,
			"cwd": os.getcwd(),
			"env": dict(os.environ),
			"ignore_environment": sys.flags.ignore_environment,
			"isolated": sys.flags.isolated,
			"request_line": raw.decode("utf-8"),
			"stdin": stdin_state(),
			"stderr_is_devnull": os.path.samestat(os.fstat(2), os.stat(os.devnull)),
		}
		Path(extra).write_text(json.dumps(report), encoding="utf-8")
		write(reply("cancelled" if kind == "pin" else "deny"))
	elif name == "watch":
		# The real EOF watcher: the child must exit when its parent dies.
		module = runpy.run_path(str(DIALOG_CHILD))
		module["watch_eof"](sys.stdin.buffer)
		Path(extra).write_text(str(os.getpid()), encoding="utf-8")
		hang()
	else:
		os._exit(8)
	os._exit(0)


if __name__ == "__main__":
	main()
