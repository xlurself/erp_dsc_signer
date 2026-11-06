from __future__ import annotations

import argparse
import signal
import sys
import threading
import unicodedata
from datetime import datetime, timezone

from .config import load_config
from .dialog_child import UNREADABLE_CATEGORIES, _disable_core_dumps
from .errors import ConfigurationError
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


def main():
	parser = argparse.ArgumentParser(description="Loopback USB DSC signer for ERPNext")
	parser.add_argument("--config", help="Path to local signer JSON configuration")
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--list-origins", action="store_true", help="Show trusted ERP origins and exit")
	group.add_argument("--allow", metavar="ORIGIN", help="Trust an ERP origin without a dialog (headless setup)")
	group.add_argument("--revoke", metavar="ORIGIN", help="Stop trusting an ERP origin paired on this computer")
	args = parser.parse_args()

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

	from .service import SignerService  # imported late: pulls in PKCS#11

	try:
		service = SignerService(load_config(args.config))
		server = service.make_server()
	except ConfigurationError as exc:
		parser.error(exc.message)
	_serve(service, server)


def _install_signal_handlers(service, server) -> None:
	"""SIGTERM, SIGINT and (where it exists) SIGHUP stop the signer cleanly (spec §5).

	The handler runs on the thread inside serve_forever(), so it must not call
	server.shutdown() there: shutdown() waits for serve_forever() to return, which would
	deadlock.  It only refuses further dialogs, kills the one on screen without taking
	the UI lock, and asks a NEW daemon thread to stop the server.
	"""

	def handle(_signum, _frame):
		service.dialogs.shutdown()
		threading.Thread(target=server.shutdown, name="erp-dsc-shutdown", daemon=True).start()

	signals = [signal.SIGTERM, signal.SIGINT]
	if hasattr(signal, "SIGHUP"):
		signals.append(signal.SIGHUP)
	for number in signals:
		signal.signal(number, handle)


def _serve(service, server) -> None:
	"""Serve until a signal (or an error) stops the server, then always clean up."""
	_install_signal_handlers(service, server)
	try:
		server.serve_forever()
	finally:
		server.server_close()
		service.dialogs.shutdown()


if __name__ == "__main__":
	main()
