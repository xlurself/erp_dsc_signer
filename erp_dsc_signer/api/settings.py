# Copyright (c) 2026, XLURSELF and contributors
# License: MIT

from __future__ import annotations

import frappe
from frappe import _

from erp_dsc_signer.utils.pdf_signer import check_pfx_certificate


@frappe.whitelist()
def validate_pfx_certificate(pfx_file=None, pfx_password=None):
	"""Validate a PFX file from DSC Signing Settings without persisting its password."""
	frappe.only_for(("System Manager", "Accounts Manager"))
	if not pfx_file:
		return _result(False, "Not Validated", _("Upload a PFX certificate file first."))
	if isinstance(pfx_password, str) and pfx_password and set(pfx_password) <= {"*"}:
		pfx_password = frappe.utils.password.get_decrypted_password(
			"DSC Signing Settings", "DSC Signing Settings", "pfx_password", raise_exception=False
		) or ""
	result = check_pfx_certificate(pfx_file, pfx_password)
	for internal_key in ("key", "cert", "othercerts"):
		result.pop(internal_key, None)
	return result


def _result(valid, status, message, subject=None, valid_till=None):
	return {
		"valid": valid,
		"certificate_validation_status": status,
		"certificate_validation_message": message,
		"certificate_subject": subject,
		"certificate_valid_till": valid_till,
	}


@frappe.whitelist()
def test_tsa_connectivity(timestamp_url=None):
	"""Send a minimal RFC 3161 request from the server and report its result."""
	frappe.only_for(("System Manager", "Accounts Manager"))
	url = (timestamp_url or frappe.get_single("DSC Signing Settings").timestamp_url or "").strip()
	if not url:
		return {"ok": False, "message": _("No TSA URL configured.")}

	import os
	import time
	import urllib.error
	import urllib.request

	from asn1crypto import algos, core, tsp
	from cryptography.hazmat.primitives import hashes

	digest = hashes.Hash(hashes.SHA256())
	digest.update(b"erp_dsc_signer-tsa-connectivity-probe")
	req = tsp.TimeStampReq({
		"version": 1,
		"message_imprint": tsp.MessageImprint({
			"hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
			"hashed_message": digest.finalize(),
		}),
		"nonce": core.Integer(int.from_bytes(os.urandom(8), "big")),
		"cert_req": True,
	})
	t0 = time.monotonic()
	try:
		request = urllib.request.Request(url, data=req.dump(), headers={
			"Content-Type": "application/timestamp-query", "User-Agent": "erp_dsc_signer/test_tsa",
		})
		with urllib.request.urlopen(request, timeout=15) as response:
			body, status, content_type = response.read(), response.status, response.headers.get("Content-Type", "")
	except urllib.error.HTTPError as exc:
		return {"ok": False, "url": url, "message": _("HTTP {0} from TSA: {1}").format(exc.code, exc.reason)}
	except urllib.error.URLError as exc:
		return {"ok": False, "url": url, "message": _("Could not reach TSA: {0}").format(exc.reason)}
	except Exception as exc:
		return {"ok": False, "url": url, "message": _("Unexpected TSA error: {0}").format(exc)}
	latency_ms = int((time.monotonic() - t0) * 1000)
	if "application/timestamp-reply" not in content_type.lower():
		return {"ok": False, "url": url, "http_status": status, "latency_ms": latency_ms,
			"message": _("TSA returned an unexpected Content-Type: {0}").format(content_type or "unknown")}
	return {"ok": True, "url": url, "http_status": status, "latency_ms": latency_ms,
		"response_bytes": len(body), "message": _("TSA reachable. HTTP {0}, {1} ms.").format(status, latency_ms)}
