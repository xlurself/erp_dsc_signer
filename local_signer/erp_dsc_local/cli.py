from __future__ import annotations

import argparse
import platform
import signal
import sys
import threading
import unicodedata
from datetime import datetime, timezone

from . import logs
from .config import load_config
from .dialog_child import UNREADABLE_CATEGORIES, _disable_core_dumps
from .errors import ConfigurationError
from .logs import events, exception_name
from .origins import canonical_origin
from .trust import TrustStore


def _static_origins(config_path) -> frozenset[str]:
	"""Operator-owned origins, if a config was supplied.

	A config that cannot be loaded is reported and stops the command (exit 2): an
	empty result would silently hide the operator-owned origins it lists.
	"""
	if not config_path:
		return frozenset()
	try:
		return load_config(config_path).allowed_origins
	except ConfigurationError as exc:
		print(f"error: {exc.message}", file=sys.stderr)
		raise SystemExit(2) from None


def _printable(text) -> str:
	"""Site-supplied text with every control/format/unreadable character removed.

	Claims are sanitised when they enter (pairing.verify_pairing_proof), but a trust
	store written by an older signer, or edited by hand, may still hold raw text: an
	escape sequence printed here would be interpreted by the operator's terminal.
	"""
	return "".join(ch for ch in str(text) if unicodedata.category(ch) not in UNREADABLE_CATEGORIES)


def _stamp(value) -> str:
	try:
		return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
	except (TypeError, ValueError, OSError):
		return "unknown"


def _list_origins(store: TrustStore, static: frozenset[str]) -> int:
	if static:
		print("Configured in config.json (cannot be revoked from the command line):")
		for origin in sorted(static):
			print(f"  {_printable(origin)}")
	entries = sorted(store.list_origins(), key=lambda item: item["origin"])
	print("Paired on this computer:")
	if not entries:
		print("  (none yet)")
	for entry in entries:
		claimed = _printable(entry.get("claimed_site_name") or "")
		suffix = f"  [site describes itself as: {claimed}]" if claimed else ""
		print(f"  {_printable(entry['origin'])}  paired {_stamp(entry.get('approved_at'))}{suffix}")
	return 0


def _allow(store: TrustStore, value: str) -> int:
	try:
		origin = store.allow(canonical_origin(value))
	except ValueError as exc:
		print(f"error: {_printable(exc)}", file=sys.stderr)
		return 2
	print(f"Allowed {_printable(origin)}")
	return 0


def _revoke(store: TrustStore, value: str, static: frozenset[str]) -> int:
	try:
		origin = canonical_origin(value)
	except ValueError as exc:
		print(f"error: {_printable(exc)}", file=sys.stderr)
		return 2
	if origin in static:
		print(
			f"error: {_printable(origin)} is configured in config.json and is owned by whoever manages this\n"
			"       workstation. Remove it from allowed_origins there instead.",
			file=sys.stderr,
		)
		return 2
	if not store.revoke(origin):
		print(f"error: {_printable(origin)} is not paired on this computer.", file=sys.stderr)
		return 1
	print(f"Revoked {_printable(origin)}")
	return 0


def _parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Loopback USB DSC signer for ERPNext")
	parser.add_argument(
		"--config",
		help="Path to local signer JSON configuration (the support and setup commands default to "
		"~/.erp-dsc-local/config.json)",
	)
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--list-origins", action="store_true", help="Show trusted ERP origins and exit")
	group.add_argument("--allow", metavar="ORIGIN", help="Trust an ERP origin without a dialog (headless setup)")
	group.add_argument("--revoke", metavar="ORIGIN", help="Stop trusting an ERP origin paired on this computer")
	group.add_argument("--doctor", action="store_true", help="Print a support report (no PIN, no secrets) and exit")
	group.add_argument(
		"--find-drivers", action="store_true", help="List token driver files in the usual folders (nothing is loaded)"
	)
	group.add_argument("--add-module", metavar="PATH", help="Add a token driver file (absolute path) to config.json")
	group.add_argument("--show-log-path", action="store_true", help="Print where the signer writes its log and exit")
	group.add_argument(
		"--install-autostart",
		action="store_true",
		help="Start the signer at every login for this user (shows the changes; add --yes to make them)",
	)
	group.add_argument(
		"--uninstall-autostart",
		action="store_true",
		help="Remove the login entry this tool created (shows the changes; add --yes to make them)",
	)
	parser.add_argument("--verify", action="store_true", help="With --add-module: ask the driver first, in a separate process")
	parser.add_argument(
		"--yes", action="store_true", help="With --install-autostart / --uninstall-autostart: make the changes shown"
	)
	return parser


def _support_command(args) -> int | None:
	"""The support and setup commands: never open a window, never load PKCS#11 in this process."""
	config = args.config or logs.default_config_path()
	if args.show_log_path:
		print(logs.log_path(config))
		return 0
	if args.doctor:
		from . import doctor

		return doctor.run(config)
	if args.find_drivers or args.add_module:
		from . import drivers

		if args.find_drivers:
			return drivers.find_drivers_command(config)
		return drivers.add_module(config, args.add_module, verify=args.verify)
	if args.install_autostart or args.uninstall_autostart:
		from . import autostart

		command = autostart.install if args.install_autostart else autostart.uninstall
		return command(config, yes=args.yes)
	return None


def main():
	parser = _parser()
	args = parser.parse_args()
	if args.verify and not args.add_module:
		parser.error("--verify works only with --add-module")
	if args.yes and not (args.install_autostart or args.uninstall_autostart):
		parser.error("--yes works only with --install-autostart or --uninstall-autostart")
	code = _support_command(args)
	if code is not None:
		raise SystemExit(code)

	# Management commands never open a window and never load PKCS#11, so they work
	# over SSH and on a machine with no desktop session.
	if args.list_origins or args.allow or args.revoke:
		if args.allow:
			raise SystemExit(_allow(TrustStore(), args.allow))
		static = _static_origins(args.config)
		store = TrustStore()
		if args.list_origins:
			raise SystemExit(_list_origins(store, static))
		raise SystemExit(_revoke(store, args.revoke, static))

	if not args.config:
		parser.error("--config is required to run the signer")

	# Before anything that can hold a PIN exists in this process.
	_disable_core_dumps()

	try:
		config = load_config(args.config)
	except ConfigurationError as exc:
		parser.error(exc.message)
	log = logs.start_daemon_log(args.config)

	from .service import SignerService  # imported late: pulls in PKCS#11

	try:
		service = SignerService(config)
		server = service.make_server()
	except ConfigurationError as exc:
		_close_log(log)
		parser.error(exc.message)
	except OSError as exc:
		# Most often another program, or a second signer, already listens on the port.  One
		# line, no traceback: under launchd KeepAlive this repeats every few seconds, and the
		# stderr file there is not size-capped like the log.
		line = f"could not start on {config.host}:{config.port} ({exception_name(type(exc))}, errno {exc.errno})"
		events.error("%s", line)
		_close_log(log)
		print(f"erp-dsc-local: {line}. Is another copy already running?", file=sys.stderr)
		raise SystemExit(1) from None
	version = getattr(sys.modules.get(f"{__package__}.service"), "VERSION", "unknown")
	events.info(
		"started: ERP DSC Signer %s on %s:%s, Python %s, %s %s",
		version,
		config.host,
		config.port,
		platform.python_version(),
		platform.system(),
		platform.machine(),
	)
	_serve(service, server, log)


def _close_log(log) -> None:
	if log is not None:
		log.close()


def _signal_name(number) -> str:
	try:
		return signal.Signals(number).name
	except (ValueError, TypeError):
		return "signal"


def _install_signal_handlers(service, server) -> None:
	"""SIGTERM, SIGINT and (where it exists) SIGHUP stop the signer cleanly (spec §5).

	The handler runs on the thread inside serve_forever(), so it must not call
	server.shutdown() there: shutdown() waits for serve_forever() to return, which would
	deadlock.  It only refuses further dialogs, kills the one on screen without taking
	the UI lock, and asks a NEW daemon thread to stop the server.
	"""

	def stop(signum):
		# Logged here, on the new thread, not inside the signal handler.
		events.info("received %s, stopping", _signal_name(signum))
		server.shutdown()

	def handle(signum, _frame):
		service.dialogs.shutdown()
		threading.Thread(target=stop, args=(signum,), name="erp-dsc-shutdown", daemon=True).start()

	signals = [signal.SIGTERM, signal.SIGINT]
	if hasattr(signal, "SIGHUP"):
		signals.append(signal.SIGHUP)
	for number in signals:
		signal.signal(number, handle)


def _serve(service, server, log=None) -> None:
	"""Serve until a signal (or an error) stops the server, then always clean up."""
	_install_signal_handlers(service, server)
	try:
		server.serve_forever()
	except BaseException as exc:
		events.error("stopped by an unexpected error (%s)", exception_name(type(exc)))
		raise
	finally:
		server.server_close()
		service.dialogs.shutdown()
		events.info("stopped")
		_close_log(log)


if __name__ == "__main__":
	main()
