from __future__ import annotations

import argparse

from .config import load_config
from .errors import ConfigurationError
from .service import SignerService


def main():
	parser = argparse.ArgumentParser(description="Loopback USB DSC signer for ERPNext")
	parser.add_argument("--config", required=True, help="Path to local signer JSON configuration")
	args = parser.parse_args()
	try:
		SignerService(load_config(args.config)).serve_forever()
	except ConfigurationError as exc:
		parser.error(exc.message)


if __name__ == "__main__":
	main()
