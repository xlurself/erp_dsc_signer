"""F2: the certificate listing exposes the PUBLIC certificate so the ERP can authenticate it before the PIN."""

from __future__ import annotations

import base64
import hashlib
import pathlib
import unittest

from erp_dsc_local.certificates import parse_token_certificate

LEAF = pathlib.Path(__file__).resolve().parents[2] / "erp_dsc_signer" / "tests" / "fixtures" / "owner_leaf_signx_class3_individual.der"


class TestCertificateDer(unittest.TestCase):
	def _parsed(self):
		return parse_token_certificate(LEAF.read_bytes(), b"\x01", "label", 1, "tok", "serial")

	def test_listing_carries_the_public_der_matching_the_fingerprint(self):
		meta = self._parsed().metadata
		der = base64.b64decode(meta["der_base64"], validate=True)
		self.assertEqual(LEAF.read_bytes(), der)
		self.assertEqual(meta["fingerprint_sha256"], hashlib.sha256(der).hexdigest())

	def test_only_public_certificate_bytes_are_added(self):
		# The new key must not be able to carry anything but the certificate DER.
		meta = self._parsed().metadata
		self.assertEqual(set(meta) - {"der_base64"}, {
			"fingerprint_sha256", "serial_number", "serial_number_decimal", "subject", "issuer", "common_name",
			"valid_from", "valid_to", "currently_valid", "digital_signature", "key_type", "key_size", "label",
			"slot_id", "token_label", "token_serial",
		})


if __name__ == "__main__":
	unittest.main()
