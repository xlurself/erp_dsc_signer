"""python -m erp_dsc_local starts the signer, same as the erp-dsc-local command."""

import sys

from .cli import main

if __name__ == "__main__":
	sys.exit(main())
