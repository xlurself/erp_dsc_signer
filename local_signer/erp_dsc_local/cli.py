from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .config import load_config
from .errors import ConfigurationError
from .origins import canonical_origin
from .trust import TrustStore


def _static_origins(config_path) -> frozenset[str]:
	"""Operator-owned origins, if a config was supplied."""
	if not config_path:
		return frozenset()
	try:
		return load_config(config_path).allowed_origins
	except ConfigurationError:
		return frozenset()


def _stamp(value) -> str:
	try:
		return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
	except (TypeError, ValueError, OSError):
		return "unknown"


def _list_origins(store: TrustStore, static: frozenset[str]) -> int:
	if static:
		print("Configured in config.json (cannot be revoked from the command line):")
		for origin in sorted(static):
			print(f"  {origin}")
	entries = sorted(store.list_origins(), key=lambda item: item["origin"])
	print("Paired on this computer:")
	if not entries:
		print("  (none yet)")
	for entry in entries:
		claimed = entry.get("claimed_site_name") or ""
		suffix = f"  [site describes itself as: {claimed}]" if claimed else ""
		print(f"  {entry['origin']}  paired {_stamp(entry.get('approved_at'))}{suffix}")
	return 0


def _allow(store: TrustStore, value: str) -> int:
	try:
		origin = store.allow(canonical_origin(value))
	except ValueError as exc:
		print(f"error: {exc}", file=sys.stderr)
		return 2
	print(f"Allowed {origin}")
	return 0


def _revoke(store: TrustStore, value: str, static: frozenset[str]) -> int:
	try:
		origin = canonical_origin(value)
	except ValueError as exc:
		print(f"error: {exc}", file=sys.stderr)
		return 2
	if origin in static:
		print(
			f"error: {origin} is configured in config.json and is owned by whoever manages this\n"
			"       workstation. Remove it from allowed_origins there instead.",
			file=sys.stderr,
		)
		return 2
	if not store.revoke(origin):
		print(f"error: {origin} is not paired on this computer.", file=sys.stderr)
		return 1
	print(f"Revoked {origin}")
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
		store = TrustStore()
		static = _static_origins(args.config)
		if args.list_origins:
			raise SystemExit(_list_origins(store, static))
		if args.allow:
			raise SystemExit(_allow(store, args.allow))
		raise SystemExit(_revoke(store, args.revoke, static))

	if not args.config:
		parser.error("--config is required to run the signer")

	from .service import SignerService  # imported late: pulls in PKCS#11

	try:
		SignerService(load_config(args.config)).serve_forever()
	except ConfigurationError as exc:
		parser.error(exc.message)


if __name__ == "__main__":
	main()
