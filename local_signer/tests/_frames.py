"""Test helper: prove that no traceback frame still holds a sentinel PIN (spec I1/I2/I7).

    from _frames import assert_no_sentinel_in_frames, raised   # or: from tests._frames ...
    exc = raised(SomeError, code_under_test, *args)
    assert_no_sentinel_in_frames(exc, SENTINEL)

Do NOT pass ``assertRaises``' ``cm.exception``: unittest stores it with the traceback
removed and clears the frames, so there would be nothing to walk.  The helper refuses
an exception without a traceback, and a package frame whose locals were cleared,
instead of passing vacuously.

It walks the exception, its __cause__/__context__ chain, and every frame on each
traceback.  By default only frames whose code lives in the `erp_dsc_local` package are
checked (a test's own frames legitimately hold the sentinel it injected).  In each
checked frame every local is scanned -- and, `depth` levels down, what it references:
dict keys/values, list/tuple/set items, instance attributes (``__dict__`` and
``__slots__``), function closures, bound-method ``__self__`` and exception ``args`` --
for the sentinel as a ``str`` substring, or as its UTF-8 bytes inside ``bytes``,
``bytearray`` or ``memoryview``.  A zeroed bytearray therefore passes.

On a hit it raises AssertionError naming the frame and the path to the value
(``request_pin: local 'pin'`` / ``_supervise: local 'child'.buffer``); the message never
contains the value itself.  Stdlib only; reads nothing but the objects it is given.

Two more tools for the success path, where no exception exists to walk:
``heap_hits`` / ``assert_no_sentinel_on_heap`` scan everything the garbage collector
can reach (so a copy kept in a module global is found), and ``ReadintoOnly`` wraps a
child's stdout so the reply reader cannot copy the reply through read() chunks.
"""

from __future__ import annotations

import collections
import os
import types
from pathlib import Path

import erp_dsc_local

PACKAGE_DIR = str(Path(erp_dsc_local.__file__).resolve().parent)
DEFAULT_DEPTH = 4

_OPAQUE = (
	types.ModuleType,
	type,
	types.FrameType,
	types.TracebackType,
	types.CodeType,
	types.BuiltinFunctionType,
	int,
	float,
	complex,
	bool,
	type(None),
)


def raised(expected, fn, *args, **kwargs):
	"""Call fn(*args, **kwargs) and return the `expected` exception with its frames intact."""
	try:
		fn(*args, **kwargs)
	except expected as exc:
		return exc
	raise AssertionError("%s was not raised" % getattr(expected, "__name__", expected))


def _cleared(frame) -> bool:
	"""A frame whose arguments are gone was cleared (traceback.clear_frames / frame.clear())."""
	code = frame.f_code
	has_args = code.co_argcount or code.co_kwonlyargcount or code.co_flags & 0x0C  # *args / **kwargs
	return bool(has_args) and not frame.f_locals


def exception_chain(exc):
	"""`exc`, then every exception reachable through __cause__ / __context__."""
	seen = set()
	stack = [exc]
	while stack:
		current = stack.pop()
		if current is None or id(current) in seen:
			continue
		seen.add(id(current))
		yield current
		stack.extend((current.__cause__, current.__context__))


def traceback_frames(exc):
	tb = exc.__traceback__
	while tb is not None:
		yield tb.tb_frame
		tb = tb.tb_next


def in_package(frame, package_dir: str = PACKAGE_DIR) -> bool:
	try:
		path = str(Path(frame.f_code.co_filename).resolve())
	except (OSError, ValueError):
		return False
	return path.startswith(package_dir + os.sep)


def find_sentinel(value, sentinel: str, *, path: str = "value", depth: int = DEFAULT_DEPTH) -> list:
	"""Every path under `value` (up to `depth` references away) that holds `sentinel`."""
	hits = []
	_scan(value, sentinel, sentinel.encode("utf-8"), path, depth, set(), hits)
	return hits


def _scan(value, text, data, path, depth, seen, hits) -> None:
	if isinstance(value, str):
		if text in value:
			hits.append(path)
		return
	if isinstance(value, (bytes, bytearray)):
		if data in value:
			hits.append(path)
		return
	if isinstance(value, memoryview):
		try:
			content = value.tobytes()
		except ValueError:  # released
			return
		if data in content:
			hits.append(path)
		return
	if isinstance(value, _OPAQUE) or depth <= 0 or id(value) in seen:
		return
	seen.add(id(value))
	below = depth - 1

	def scan(child, child_path) -> None:
		_scan(child, text, data, child_path, below, seen, hits)

	if isinstance(value, dict):
		for key, item in list(value.items()):
			scan(key, "%s[key]" % path)
			scan(item, "%s[%r]" % (path, key if isinstance(key, (str, int)) else "?"))
		return
	if isinstance(value, (list, tuple, set, frozenset, collections.deque)):
		for index, item in enumerate(list(value)):
			scan(item, "%s[%d]" % (path, index))
		return
	if isinstance(value, types.FunctionType):
		for index, cell in enumerate(value.__closure__ or ()):
			try:
				contents = cell.cell_contents
			except ValueError:  # empty cell
				continue
			scan(contents, "%s.<closure %d>" % (path, index))
		return
	if isinstance(value, types.MethodType):
		scan(value.__self__, "%s.__self__" % path)
		return
	if isinstance(value, BaseException):
		scan(value.args, "%s.args" % path)
	attributes = getattr(value, "__dict__", None)
	if isinstance(attributes, dict):
		for name, item in list(attributes.items()):
			scan(item, "%s.%s" % (path, name))
	for klass in type(value).__mro__:
		slots = klass.__dict__.get("__slots__", ())
		if isinstance(slots, str):
			slots = (slots,)
		for name in slots:
			if name in ("__dict__", "__weakref__"):
				continue
			try:
				item = getattr(value, name)
			except AttributeError:
				continue
			scan(item, "%s.%s" % (path, name))


def sentinel_hits(exc, sentinel: str, *, package_only: bool = True, depth: int = DEFAULT_DEPTH) -> list:
	"""Every place in `exc`'s chain and traceback frames that still holds `sentinel`."""
	hits = []
	for index, current in enumerate(exception_chain(exc)):
		label = "exception %d (%s)" % (index, type(current).__name__)
		hits.extend(find_sentinel(current, sentinel, path=label, depth=depth))
		for frame in traceback_frames(current):
			if package_only and not in_package(frame):
				continue
			name = frame.f_code.co_name
			if _cleared(frame):
				raise ValueError("frame %s was cleared; capture the exception with _frames.raised()" % name)
			for local, value in dict(frame.f_locals).items():
				hits.extend(find_sentinel(value, sentinel, path="%s: local %r" % (name, local), depth=depth))
	return hits


def assert_no_sentinel_in_frames(exc, sentinel: str, *, package_only: bool = True, depth: int = DEFAULT_DEPTH) -> None:
	"""Raise AssertionError if any frame local (or the exception chain) holds `sentinel`."""
	if not isinstance(exc, BaseException):
		raise TypeError("assert_no_sentinel_in_frames needs an exception")
	if not sentinel:
		raise ValueError("an empty sentinel matches everything")
	if exc.__traceback__ is None:
		raise ValueError("the exception has no traceback (assertRaises strips it); use _frames.raised()")
	hits = sentinel_hits(exc, sentinel, package_only=package_only, depth=depth)
	if hits:
		raise AssertionError("the sentinel PIN is still referenced from: " + "; ".join(hits))


# --- heap scan: copies that no exception references ----------------------------------
_HEAP_TYPES = (str, bytes, bytearray, memoryview)


def _holds(value, text: str, data: bytes) -> bool:
	kind = type(value)
	if kind is str:
		return text in value
	if kind in (bytes, bytearray):
		return data in value
	if kind is memoryview:
		try:
			return data in value.tobytes()
		except (ValueError, TypeError):  # released, or not a byte format
			return False
	return False


def heap_hits(sentinel: str, *, exclude=()) -> list:
	"""Every str / bytes / bytearray / memoryview still reachable that holds `sentinel`.

	Runs gc.collect() first.  gc.get_objects() lists only CONTAINER objects, and
	str/bytes/bytearray are not containers, so the scan checks the REFERENTS of every
	tracked object (a module global, a class attribute, a list item, a dict value, a
	closure cell, an instance attribute) plus the locals of every frame on every
	thread's stack.  `exclude` holds the objects that legitimately keep the sentinel
	(the test's own constants, the returned PIN str); they are matched by identity.
	A copy that was already freed cannot be found: this proves "no reachable copy",
	not "no copy in memory" (spec I7).  The report names the holder, never the value.
	"""
	import gc
	import sys

	if not sentinel:
		raise ValueError("an empty sentinel matches everything")
	text, data = sentinel, sentinel.encode("utf-8")
	# The scan's own needles live in check()'s closure cells: never report them.
	skip = {id(value) for value in exclude} | {id(text), id(data)}
	gc.collect()
	hits = []
	found = set()

	def check(value, where) -> None:
		if type(value) in _HEAP_TYPES and id(value) not in skip and id(value) not in found and _holds(value, text, data):
			found.add(id(value))
			hits.append("%s held by %s" % (type(value).__name__, where))

	for holder in gc.get_objects():
		kind = type(holder)
		if kind is types.FrameType:
			continue  # frames are walked below, with their names
		for value in gc.get_referents(holder):
			check(value, "%s.%s" % (kind.__module__, kind.__qualname__))
	for top in sys._current_frames().values():
		frame = top
		while frame is not None:
			for local, value in dict(frame.f_locals).items():
				check(value, "frame %s: local %r" % (frame.f_code.co_name, local))
			frame = frame.f_back
	return hits


def assert_no_sentinel_on_heap(sentinel: str, *, exclude=()) -> None:
	"""Raise AssertionError if heap_hits() finds a reachable copy of `sentinel`."""
	hits = heap_hits(sentinel, exclude=exclude)
	if hits:
		raise AssertionError("a copy of the sentinel PIN is still reachable: " + "; ".join(hits))


class ReadintoOnly:
	"""A child's stdout as the reply reader may use it: readinto() and close(), nothing else.

	A reader that copied the reply through read()/read1()/readline() chunks, or went
	around the object through fileno(), raises AttributeError here and never sees the
	reply, so a test that needs the reply fails.
	"""

	__slots__ = ("_raw",)

	def __init__(self, raw):
		self._raw = raw

	def readinto(self, buffer):
		return self._raw.readinto(buffer)

	def close(self) -> None:
		self._raw.close()
