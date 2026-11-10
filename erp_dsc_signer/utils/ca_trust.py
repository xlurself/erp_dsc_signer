"""Authenticate a DSC certificate against the pinned CCA India hierarchy (spec 002 s2, s3, s5).

Pure module: no frappe import, so it is unit-testable without a site. The only network access goes
through an injectable ``fetch`` callable; every URL is checked by :func:`url_allowed` before ``fetch`` is
called, and the default transport (:class:`HttpTransport`) also refuses non-public addresses and redirects.

Trust comes only from ``pinned_roots``. Certificates downloaded from AIA addresses are candidates, never
anchors: they count only when :func:`_validate_path` accepts the whole path from the leaf to a pinned root
(RFC 5280 basic path validation with a document-signing profile: no TLS rule such as a required SAN or
clientAuth purpose). Revocation is checked for every non-root certificate in that path, OCSP first and CRL
as fallback; a status that cannot be confirmed refuses (fail closed, never "assume good").

A failure raises :class:`CertificateNotAuthenticated` with a reason code from a closed set and a fixed
plain-language message. Library exception text never reaches the message, the attributes or the exception
chain. Only public data is handled here: the certificate, CA certificates and revocation data.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import io
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

from erp_dsc_signer.utils import pinned_roots

MESSAGES = {
	"NOT_CCA_TRUSTED": (
		"This certificate is not trusted by CCA India (it was not issued under the CCA India certifying "
		"authority hierarchy), so the document was not signed."
	),
	"CHAIN_INCOMPLETE": (
		"The chain from this certificate to the CCA India root could not be completed, so the document "
		"was not signed."
	),
	"EXPIRED_OR_NOT_YET_VALID": "This certificate is expired or not yet valid, so the document was not signed.",
	"KEY_USAGE": (
		"This certificate's key usage does not permit digital signatures (digitalSignature or non-repudiation), "
		"so the document was not signed."
	),
	"REVOKED": (
		"The certifying authority reports that this certificate has been revoked, so the document was not signed."
	),
	"REVOCATION_UNAVAILABLE": (
		"Could not confirm with the certifying authority that this certificate is not revoked, so the document "
		"was not signed. Check the internet connection and try again."
	),
	"CA_FETCH_FAILED": (
		"Could not download the issuing certifying authority's certificate, so the document was not signed. "
		"Check the internet connection and try again."
	),
	# The signer certificate itself is not an acceptable signing certificate (checked before any download).
	"CERTIFICATE_PROFILE": (
		"This certificate cannot be used to sign documents: it is a certifying-authority certificate, uses a weak "
		"algorithm or key, or carries a critical extension this verifier does not support, so the document was "
		"not signed. Please contact support."
	),
}
REASON_CODES = frozenset(MESSAGES)

# s3.5: exact host match. The integration layer may ADD hosts (``extra_hosts``) but never remove these.
DEFAULT_ALLOWED_HOSTS = frozenset({"signxca.com", "ocsp.signxca.com", "ocvs.gov.in", "cca.gov.in", "www.cca.gov.in"})
MAX_CERT_BYTES = 20 * 1024
MAX_OCSP_BYTES = 64 * 1024
MAX_CRL_BYTES = 8 * 1024 * 1024
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
TOTAL_BUDGET = 25.0
CLOCK_SKEW = timedelta(minutes=5)
MAX_INTERMEDIATES = 4
MAX_URLS_PER_KIND = 3
MAX_URL_LENGTH = 2048
_CACHE_LIMIT = 32

TIMESTAMP = "none"
SIGNING_TIME_BASIS = "server clock at verification"
RECORD_KEYS = ("verified", "checked_at", "chain", "root_sha256", "revocation", "timestamp", "signing_time_basis")

_monotonic = time.monotonic
# Intermediates that verified to a pinned root, keyed by SHA-256 (public data; saves AIA downloads only:
# a cached certificate is still re-validated by _validate_path on every call).
_INTERMEDIATE_CACHE: dict[str, x509.Certificate] = {}

_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)
_PEM_CRL = re.compile(rb"-----BEGIN X509 CRL-----(.+?)-----END X509 CRL-----", re.S)


class CertificateNotAuthenticated(Exception):
	"""The certificate was not authenticated. ``reason_code`` is in REASON_CODES; ``message`` is fixed text."""

	def __init__(self, reason_code: str):
		if reason_code not in MESSAGES:
			raise ValueError("unknown reason code")
		self.reason_code = reason_code
		self.message = MESSAGES[reason_code]
		super().__init__(reason_code, self.message)

	def __str__(self):
		return self.message


class FetchRefused(Exception):
	"""The default transport refused a URL, an address or a response."""


def clear_cache() -> None:
	_INTERMEDIATE_CACHE.clear()


def authenticate_certificate(cert_der, *, now, fetch=None, roots=None, extra_hosts=()) -> dict:
	"""Authenticate ``cert_der`` (the signer's DER certificate) at time ``now`` (timezone-aware).

	``fetch(url, *, data, content_type, max_bytes, timeout) -> bytes`` performs one request (POST when
	``data`` is given); it is called only for URLs that passed :func:`url_allowed`. Default: HttpTransport.
	``roots`` defaults to the pinned CCA India roots. ``extra_hosts`` adds DNS host names to the allowlist.
	Returns the verification record (keys RECORD_KEYS) or raises CertificateNotAuthenticated.
	"""
	if not isinstance(now, datetime) or now.utcoffset() is None:
		raise TypeError("now must be a timezone-aware datetime")
	now = now.astimezone(timezone.utc)
	allowed = _allowed_hosts(extra_hosts)
	anchors = tuple(pinned_roots.PINNED_ROOTS if roots is None else roots)
	if not anchors or not all(isinstance(root, x509.Certificate) for root in anchors):
		raise TypeError("roots must be a non-empty sequence of x509 certificates")
	net = _Network(fetch if fetch is not None else HttpTransport(), allowed)
	stage = ["NOT_CCA_TRUSTED"]
	try:
		return _authenticate(cert_der, now, anchors, net, stage)
	except CertificateNotAuthenticated as exc:
		code = exc.reason_code
	except Exception:
		code = stage[0]  # unexpected failure: refuse with the reason of the step that was running
	# Raised outside the except blocks so no library exception is kept as context or cause.
	raise CertificateNotAuthenticated(code) from None


def _authenticate(cert_der, now, anchors, net, stage):
	leaf = x509.load_der_x509_certificate(bytes(cert_der))
	# The signer certificate on its own, before any download.
	_require_valid_at(leaf, now)
	_require_signing_usage(leaf)
	_require_leaf_profile(leaf)
	stage[0] = "CHAIN_INCOMPLETE"
	intermediates, anchor = _build_path(leaf, anchors, net)
	chain = [leaf, *intermediates, anchor]
	stage[0] = "NOT_CCA_TRUSTED"
	_validate_path(chain, anchors, now)  # validity of every CA is checked first there (EXPIRED_OR_NOT_YET_VALID)
	_remember(chain[1:-1])
	stage[0] = "REVOCATION_UNAVAILABLE"
	revocation = [_revocation_status(chain[i], chain[i + 1], now, net) for i in range(len(chain) - 1)]
	return {
		"verified": True,
		"checked_at": now.isoformat(timespec="seconds"),
		"chain": [{"subject_cn": _common_name(cert), "sha256": _sha256(cert)} for cert in chain],
		"root_sha256": _sha256(chain[-1]),
		"revocation": revocation,
		"timestamp": TIMESTAMP,
		"signing_time_basis": SIGNING_TIME_BASIS,
	}


# ---------------------------------------------------------------- certificate checks


def _require_valid_at(cert, now):
	if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
		raise CertificateNotAuthenticated("EXPIRED_OR_NOT_YET_VALID")


def _require_signing_usage(leaf):
	# Existing rule (usb_signer._validate_certificate): keyUsage, when present, must allow signing.
	key_usage = _extension(leaf, x509.KeyUsage)
	if key_usage is not None and not (key_usage.digital_signature or key_usage.content_commitment):
		raise CertificateNotAuthenticated("KEY_USAGE")


def _require_leaf_profile(leaf):
	"""The signer certificate itself: an end entity, v3, strong key and signature, no critical extension we skip.

	A CMS/PDF signing certificate needs no SAN and no TLS clientAuth purpose, so neither is required, and the
	EKU is not a gate at all (absent, documentSigning, emailProtection, anyExtendedKeyUsage: all accepted):
	no CCA rule is known that would let an EKU refusal reject only certificates a real CCA CA never issues.
	"""
	if leaf.subject == leaf.issuer:
		raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")  # self-issued: its own root, never a CCA leaf
	constraints = _extension(leaf, x509.BasicConstraints)
	if (
		leaf.version != x509.Version.v3
		or (constraints is not None and constraints.ca)
		or not _extensions_understood(leaf, is_ca=False)
		or not _strong_key(leaf.public_key())
		or not _strong_signature(leaf)
	):
		raise CertificateNotAuthenticated("CERTIFICATE_PROFILE")


def _build_path(leaf, anchors, net):
	"""Collect candidate intermediates from the cache or AIA until a pinned root issued the last one."""
	path = []
	current = leaf
	seen = {_sha256(leaf)}
	while True:
		anchor = _issuing_anchor(current, anchors)
		if anchor is not None:
			return path, anchor
		if current.subject == current.issuer:
			raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")  # a self-issued root that is not pinned
		if len(path) >= MAX_INTERMEDIATES:
			raise CertificateNotAuthenticated("CHAIN_INCOMPLETE")
		issuer = _cached_issuer(current) or _fetch_issuer(current, net)
		fingerprint = _sha256(issuer)
		if fingerprint in seen:
			raise CertificateNotAuthenticated("CHAIN_INCOMPLETE")
		seen.add(fingerprint)
		path.append(issuer)
		current = issuer


def _issuing_anchor(cert, anchors):
	same_name = False
	for anchor in anchors:
		if anchor.subject != cert.issuer:
			continue
		same_name = True
		if _directly_issued(cert, anchor):
			return anchor
	if same_name:
		# The issuer name copies a pinned root but another key signed it: never follow it further.
		raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")
	return None


def _cached_issuer(cert):
	for candidate in list(_INTERMEDIATE_CACHE.values()):
		if candidate.subject == cert.issuer and _directly_issued(cert, candidate):
			return candidate
	return None


def _fetch_issuer(cert, net):
	urls = _aia_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)
	if not urls:
		raise CertificateNotAuthenticated("CHAIN_INCOMPLETE")
	mismatched = False
	for url in urls:
		body = net.get(url, max_bytes=MAX_CERT_BYTES)
		if body is None:
			continue
		candidate = _parse_fetched_certificate(body)
		if candidate is None:
			continue
		if _directly_issued(cert, candidate):
			return candidate
		mismatched = True
	raise CertificateNotAuthenticated("CHAIN_INCOMPLETE" if mismatched else "CA_FETCH_FAILED")


# ---------------------------------------------------------------- path validation (spec 002 s9 item 18)

# Extensions this validator understands. Any other extension marked critical refuses (RFC 5280 s4.2).
# certificatePolicies, inhibitAnyPolicy and policyConstraints' inhibitPolicyMapping only shape the RFC 5280
# policy tree, and that tree cannot change the verdict while no explicit policy is required; a
# requireExplicitPolicy anywhere in the path is therefore refused (_extensions_understood). nameConstraints is
# not implemented, so a CA that carries it is refused rather than having its constraints ignored.
_UNDERSTOOD_EXTENSIONS = frozenset(
	{
		ExtensionOID.BASIC_CONSTRAINTS,
		ExtensionOID.KEY_USAGE,
		ExtensionOID.EXTENDED_KEY_USAGE,
		ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
		ExtensionOID.CERTIFICATE_POLICIES,
		ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
		ExtensionOID.SUBJECT_KEY_IDENTIFIER,
		ExtensionOID.CRL_DISTRIBUTION_POINTS,
		ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
		ExtensionOID.POLICY_CONSTRAINTS,
		ExtensionOID.INHIBIT_ANY_POLICY,
	}
)
# Certificate signature hashes accepted on every link: SHA-2 and SHA-3 only (no MD2, MD5 or SHA-1).
_STRONG_HASHES = (
	hashes.SHA224,
	hashes.SHA256,
	hashes.SHA384,
	hashes.SHA512,
	hashes.SHA512_224,
	hashes.SHA512_256,
	hashes.SHA3_224,
	hashes.SHA3_256,
	hashes.SHA3_384,
	hashes.SHA3_512,
)
MIN_RSA_BITS = 2048
_STRONG_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)


def _validate_path(chain, anchors, now):
	"""Decide the path leaf -> intermediates -> pinned root; raise CertificateNotAuthenticated on any failure.

	RFC 5280 s6.1 basic path validation with a document-signing profile. It replaces cryptography's
	x509.verification client verifier, a TLS profile that demanded a SAN and clientAuth a CMS/PDF signing
	certificate does not need. Checks: the last certificate is a pinned root by DER; no repeated certificate
	and at most MAX_INTERMEDIATES intermediates; the leaf profile (KEY_USAGE, CERTIFICATE_PROFILE); every
	certificate valid at ``now``; every CA (the root included): cA, pathLenConstraint, keyCertSign when
	keyUsage is present, understood critical extensions, strong key; every link: issuer name encoded exactly
	as the issuer's subject, strong signature hash, and the issuer's key verifies the signature.
	"""
	if not 2 <= len(chain) <= MAX_INTERMEDIATES + 2:
		raise CertificateNotAuthenticated("CHAIN_INCOMPLETE")
	fingerprints = [_sha256(cert) for cert in chain]
	if len(set(fingerprints)) != len(fingerprints):
		raise CertificateNotAuthenticated("CHAIN_INCOMPLETE")  # a loop or a repeated certificate
	if fingerprints[-1] not in {_sha256(anchor) for anchor in anchors}:
		raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")  # the path must end at a pinned root, never a fetched one
	_require_signing_usage(chain[0])
	_require_leaf_profile(chain[0])
	for cert in chain:
		_require_valid_at(cert, now)
	for position in range(1, len(chain)):
		_require_issuing_ca(chain[position], position - 1)
		_require_link(chain[position - 1], chain[position])


def _require_issuing_ca(cert, intermediates_below):
	"""``cert`` issues certificates: cA, pathLen (CAs between it and the leaf), keyCertSign, extensions, key."""
	constraints = _extension(cert, x509.BasicConstraints)
	key_usage = _extension(cert, x509.KeyUsage)
	if (
		cert.version != x509.Version.v3
		or constraints is None
		or not constraints.ca
		or (constraints.path_length is not None and intermediates_below > constraints.path_length)
		or (key_usage is not None and not key_usage.key_cert_sign)
		or not _extensions_understood(cert, is_ca=True)
		or not _strong_key(cert.public_key())
	):
		raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")


def _require_link(cert, issuer):
	"""``issuer`` issued ``cert``: same encoded name, strong signature hash, and the signature verifies.

	Names are compared as their DER encoding, never as text: RFC 5280 s4.1.2.4 requires a CA to encode the
	issuer field exactly as its own subject, and cryptography's issuer check is DER-strict as well
	(x509.Name equality alone ignores the ASN.1 string type).
	"""
	if (
		cert.issuer.public_bytes() != issuer.subject.public_bytes()
		or not _strong_signature(cert)
		or not _directly_issued(cert, issuer)
	):
		raise CertificateNotAuthenticated("NOT_CCA_TRUSTED")


def _extensions_understood(cert, *, is_ca):
	for extension in cert.extensions:
		if extension.critical and extension.oid not in _UNDERSTOOD_EXTENSIONS:
			return False
	if is_ca and _extension(cert, x509.NameConstraints) is not None:
		return False  # not implemented: refused whether or not it is marked critical
	policy = _extension(cert, x509.PolicyConstraints)
	return policy is None or policy.require_explicit_policy is None


def _strong_key(public_key):
	if isinstance(public_key, rsa.RSAPublicKey):
		return public_key.key_size >= MIN_RSA_BITS
	if isinstance(public_key, ec.EllipticCurvePublicKey):
		return isinstance(public_key.curve, _STRONG_CURVES)
	return False  # DSA, Ed25519, Ed448 and anything else: not used by CCA India, refused


def _strong_signature(cert):
	try:
		algorithm = cert.signature_hash_algorithm
	except Exception:
		return False  # MD2 and other algorithms the library cannot even name
	return isinstance(algorithm, _STRONG_HASHES)


def _remember(certs):
	for cert in certs:
		fingerprint = _sha256(cert)
		_INTERMEDIATE_CACHE.pop(fingerprint, None)
		_INTERMEDIATE_CACHE[fingerprint] = cert
	while len(_INTERMEDIATE_CACHE) > _CACHE_LIMIT:
		_INTERMEDIATE_CACHE.pop(next(iter(_INTERMEDIATE_CACHE)))


# ---------------------------------------------------------------- revocation


def _revocation_status(cert, issuer, now, net):
	for check in (_check_ocsp, _check_crl):
		outcome = check(cert, issuer, now, net)
		if outcome is None:
			continue
		status, entry = outcome
		if status == "revoked":
			raise CertificateNotAuthenticated("REVOKED")
		if status == "good":
			return entry
	raise CertificateNotAuthenticated("REVOCATION_UNAVAILABLE")


def _check_ocsp(cert, issuer, now, net):
	"""("good", entry) | ("revoked", None) | None when no verified answer was obtained."""
	urls = _aia_urls(cert, AuthorityInformationAccessOID.OCSP)
	if not urls:
		return None
	try:
		request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
		body = request.public_bytes(serialization.Encoding.DER)
	except Exception:
		return None
	for url in urls:
		raw = net.get(url, max_bytes=MAX_OCSP_BYTES, data=body, content_type="application/ocsp-request")
		if raw is None:
			continue
		outcome = _evaluate_ocsp(raw, cert, issuer, now)
		if outcome is None:
			continue
		status, produced_at = outcome
		if status == "revoked":
			return "revoked", None
		return "good", _revocation_entry(cert, "ocsp", url, produced_at)
	return None


def _evaluate_ocsp(raw, cert, issuer, now):
	try:
		response = ocsp.load_der_ocsp_response(raw)
		if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
			return None
		signer = _ocsp_signer(response, issuer, now)
		if signer is None or not _signature_valid(
			signer.public_key(), response.signature, response.tbs_response_bytes, response.signature_hash_algorithm
		):
			return None
		single = _matching_single_response(response, cert, issuer)
		if single is None:
			return None
		if single.certificate_status == ocsp.OCSPCertStatus.REVOKED:
			return "revoked", None  # a verified revocation refuses even when the answer is not fresh
		if single.certificate_status != ocsp.OCSPCertStatus.GOOD:
			return None
		if not _fresh(single.this_update_utc, single.next_update_utc, now):
			return None
		return "good", response.produced_at_utc
	except Exception:
		return None


def _ocsp_signer(response, issuer, now):
	"""The issuer itself, or a responder certificate the issuer signed for id-kp-OCSPSigning."""
	if _is_responder(response, issuer):
		return issuer
	for candidate in response.certificates:
		if not _is_responder(response, candidate) or not _directly_issued(candidate, issuer):
			continue
		extended = _extension(candidate, x509.ExtendedKeyUsage)
		if extended is None or ExtendedKeyUsageOID.OCSP_SIGNING not in list(extended):
			continue
		key_usage = _extension(candidate, x509.KeyUsage)
		if key_usage is not None and not key_usage.digital_signature:
			continue
		if not (candidate.not_valid_before_utc <= now <= candidate.not_valid_after_utc):
			continue
		return candidate
	return None


def _is_responder(response, cert):
	if response.responder_name is not None:
		return response.responder_name == cert.subject
	key_hash = response.responder_key_hash
	return key_hash is not None and key_hash == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def _matching_single_response(response, cert, issuer):
	for single in response.responses:
		if single.serial_number != cert.serial_number:
			continue
		try:
			expected = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, single.hash_algorithm).build()
		except Exception:
			continue
		if single.issuer_name_hash == expected.issuer_name_hash and single.issuer_key_hash == expected.issuer_key_hash:
			return single
	return None


def _signature_valid(public_key, signature, data, hash_algorithm):
	try:
		if isinstance(public_key, rsa.RSAPublicKey):
			public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
		elif isinstance(public_key, ec.EllipticCurvePublicKey):
			public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
		elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
			public_key.verify(signature, data)
		else:
			return False
	except Exception:
		return False
	return True


def _check_crl(cert, issuer, now, net):
	"""("good", entry) | ("revoked", None) | None when no verified CRL was obtained."""
	for url in _crl_urls(cert):
		raw = net.get(url, max_bytes=MAX_CRL_BYTES)
		if raw is None:
			continue
		outcome = _evaluate_crl(raw, cert, issuer, now)
		if outcome is None:
			continue
		status, this_update = outcome
		if status == "revoked":
			return "revoked", None
		return "good", _revocation_entry(cert, "crl", url, this_update)
	return None


def _evaluate_crl(raw, cert, issuer, now):
	try:
		der = raw if raw[:1] == b"\x30" else _pem_or_base64(raw, _PEM_CRL)
		if der is None:
			return None
		crl = x509.load_der_x509_crl(der)
		if crl.issuer != issuer.subject:
			return None
		key_usage = _extension(issuer, x509.KeyUsage)
		if key_usage is not None and not key_usage.crl_sign:
			return None
		if not crl.is_signature_valid(issuer.public_key()) or not _crl_scope_ok(crl, cert):
			return None
		if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
			return "revoked", None
		if not _fresh(crl.last_update_utc, crl.next_update_utc, now):
			return None
		return "good", crl.last_update_utc
	except Exception:
		return None


def _crl_scope_ok(crl, cert):
	"""Only a complete, direct CRL can prove "not listed": no delta, indirect or partitioned CRLs."""
	for extension in crl.extensions:
		value = extension.value
		if isinstance(value, x509.DeltaCRLIndicator):
			return False
		if isinstance(value, x509.IssuingDistributionPoint):
			if value.indirect_crl or value.only_some_reasons or value.only_contains_attribute_certs:
				return False
			is_ca = _is_ca(cert)
			if (value.only_contains_user_certs and is_ca) or (value.only_contains_ca_certs and not is_ca):
				return False
		elif extension.critical and not isinstance(value, (x509.CRLNumber, x509.AuthorityKeyIdentifier)):
			return False
	return True


def _fresh(this_update, next_update, now):
	return (
		this_update is not None
		and next_update is not None
		and this_update - CLOCK_SKEW <= now <= next_update + CLOCK_SKEW
	)


def _revocation_entry(cert, method, url, produced_at):
	return {
		"subject_cn": _common_name(cert),
		"method": method,
		"status": "good",
		"responder_host": urlsplit(url).hostname or "",
		"produced_at": produced_at.astimezone(timezone.utc).isoformat() if produced_at else None,
	}


# ---------------------------------------------------------------- small helpers


def _extension(cert, extension_class):
	try:
		return cert.extensions.get_extension_for_class(extension_class).value
	except x509.ExtensionNotFound:
		return None


def _aia_urls(cert, method):
	aia = _extension(cert, x509.AuthorityInformationAccess)
	if aia is None:
		return []
	urls = [
		description.access_location.value
		for description in aia
		if description.access_method == method
		and isinstance(description.access_location, x509.UniformResourceIdentifier)
	]
	return urls[:MAX_URLS_PER_KIND]


def _crl_urls(cert):
	points = _extension(cert, x509.CRLDistributionPoints)
	if points is None:
		return []
	urls = []
	for point in points:
		if point.reasons is not None or point.crl_issuer is not None or not point.full_name:
			continue  # partitioned or indirect CRLs cannot prove "not revoked"
		urls.extend(name.value for name in point.full_name if isinstance(name, x509.UniformResourceIdentifier))
	return urls[:MAX_URLS_PER_KIND]


def _is_ca(cert):
	constraints = _extension(cert, x509.BasicConstraints)
	return bool(constraints and constraints.ca)


def _directly_issued(cert, issuer):
	try:
		cert.verify_directly_issued_by(issuer)
	except Exception:
		return False
	return True


def _parse_fetched_certificate(body):
	"""AIA answers may be DER, PEM or bare base64 text (SignX serves base64)."""
	der = body if body[:1] == b"\x30" else _pem_or_base64(body, _PEM_CERT)
	if der is None:
		return None
	try:
		return x509.load_der_x509_certificate(der)
	except Exception:
		return None


def _pem_or_base64(body, pem_pattern):
	text = body.strip()
	match = pem_pattern.fullmatch(text)
	if match:
		text = match.group(1)
	try:
		return base64.b64decode(b"".join(text.split()), validate=True)
	except (binascii.Error, ValueError):
		return None


def _sha256(cert):
	return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _common_name(cert):
	attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
	value = attributes[0].value if attributes else ""
	if isinstance(value, bytes):
		value = value.decode("utf-8", "replace")
	return str(value)[:256]


# ---------------------------------------------------------------- SSRF / DoS guard (s3.5)


def url_allowed(url, allowed_hosts) -> bool:
	"""http/https, exact allowlisted host, port 80/443, no userinfo, printable ASCII only."""
	if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH or not url.isascii():
		return False
	if any(ord(ch) <= 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in url):
		return False
	try:
		parts = urlsplit(url)
		port = parts.port
	except ValueError:
		return False
	if parts.scheme not in ("http", "https"):
		return False
	if "@" in parts.netloc or parts.username is not None or parts.password is not None:
		return False
	if port is not None and port not in (80, 443):
		return False
	host = parts.hostname
	return bool(host) and host in allowed_hosts


def _allowed_hosts(extra_hosts):
	hosts = set(DEFAULT_ALLOWED_HOSTS)
	for host in extra_hosts or ():
		name = host.strip().lower() if isinstance(host, str) else ""
		if not _HOSTNAME.match(name) or _is_ip_literal(name):
			raise ValueError("extra allowed hosts must be DNS host names")
		hosts.add(name)
	return frozenset(hosts)


def _is_ip_literal(name):
	try:
		ipaddress.ip_address(name)
	except ValueError:
		return False
	return True


def _is_public_ip(ip):
	if isinstance(ip, ipaddress.IPv6Address):
		if ip.ipv4_mapped is not None:
			ip = ip.ipv4_mapped
		elif ip.sixtofour is not None or ip.teredo is not None or ip.is_site_local:
			return False  # is_site_local: fec0::/10, which ipaddress does not count as private
	return ip.is_global and not (
		ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
	)


class _Network:
	"""Applies the URL policy, the size cap and the total time budget around the injected fetch."""

	def __init__(self, fetch, allowed_hosts):
		self._fetch = fetch
		self._allowed = allowed_hosts
		self._deadline = _monotonic() + TOTAL_BUDGET

	def get(self, url, *, max_bytes, data=None, content_type=None):
		"""The response body, or None when the URL is refused, the budget is spent or the fetch failed."""
		if not url_allowed(url, self._allowed):
			return None
		remaining = self._deadline - _monotonic()
		if remaining <= 0:
			return None
		try:
			body = self._fetch(url, data=data, content_type=content_type, max_bytes=max_bytes, timeout=remaining)
		except Exception:
			return None
		if not isinstance(body, (bytes, bytearray)) or len(body) > max_bytes:
			return None
		return bytes(body)


class HttpTransport:
	"""Default fetch: one request to a vetted public address. No redirects, bounded size and time.

	The resolved address is checked and then connected to directly, so DNS cannot be re-bound between the
	check and the connection. TLS here protects the transport only: nothing fetched is trusted because of
	TLS (certificates must chain to a pinned root, OCSP and CRL signatures are verified against the issuer).
	"""

	def __init__(self, *, resolver=None, connector=None, ssl_context=None):
		self._resolve = resolver or socket.getaddrinfo
		self._connect = connector or socket.create_connection
		self._ssl_context = ssl_context

	def __call__(self, url, *, data=None, content_type=None, max_bytes, timeout):
		deadline = _monotonic() + max(0.0, float(timeout))
		try:
			parts = urlsplit(url)
			port = parts.port
		except ValueError:
			raise FetchRefused("url") from None
		if parts.scheme not in ("http", "https") or "@" in parts.netloc or not parts.hostname:
			raise FetchRefused("url")
		default_port = 443 if parts.scheme == "https" else 80
		port = port or default_port
		if port not in (80, 443):
			raise FetchRefused("port")
		host = parts.hostname
		address = self._public_address(host, port)
		sock = self._connect((address, port), timeout=_bounded(CONNECT_TIMEOUT, deadline))
		conn = None
		try:
			sock.settimeout(_bounded(READ_TIMEOUT, deadline))  # bounds the TLS handshake as one operation
			if parts.scheme == "https":
				sock = self._context().wrap_socket(sock, server_hostname=host)
			conn = http.client.HTTPConnection(host, port)
			conn.sock = _DeadlineSocket(sock, deadline)
			target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
			conn.putrequest("POST" if data is not None else "GET", target, skip_host=True, skip_accept_encoding=True)
			conn.putheader("Host", host if port == default_port else f"{host}:{port}")
			conn.putheader("User-Agent", "erp-dsc-signer")
			conn.putheader("Accept", "*/*")
			conn.putheader("Accept-Encoding", "identity")
			conn.putheader("Connection", "close")
			if data is not None:
				conn.putheader("Content-Type", content_type or "application/octet-stream")
				conn.putheader("Content-Length", str(len(data)))
			conn.endheaders(message_body=data)
			return self._read(conn.getresponse(), max_bytes, deadline)
		finally:
			if conn is not None:
				conn.close()
			sock.close()

	def _public_address(self, host, port):
		try:
			infos = self._resolve(host, port, type=socket.SOCK_STREAM)
		except (OSError, UnicodeError):
			raise FetchRefused("resolve") from None
		chosen = None
		for info in infos or ():
			try:
				ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
			except ValueError:
				raise FetchRefused("address") from None
			if not _is_public_ip(ip):
				raise FetchRefused("address")  # any non-public answer refuses the whole host
			chosen = chosen or str(ip)
		if chosen is None:
			raise FetchRefused("resolve")
		return chosen

	def _context(self):
		if self._ssl_context is None:
			context = ssl.create_default_context()
			context.minimum_version = ssl.TLSVersion.TLSv1_2
			self._ssl_context = context
		return self._ssl_context

	@staticmethod
	def _read(response, max_bytes, deadline):
		if response.status != 200:
			raise FetchRefused("status")  # covers 3xx: redirects are never followed
		length = response.getheader("Content-Length")
		if length is not None and (not length.strip().isdigit() or int(length) > max_bytes):
			raise FetchRefused("size")
		chunks, total = [], 0
		while True:
			if _monotonic() > deadline:
				raise FetchRefused("time")
			chunk = response.read(min(65536, max_bytes + 1 - total))
			if not chunk:
				return b"".join(chunks)
			total += len(chunk)
			if total > max_bytes:
				raise FetchRefused("size")
			chunks.append(chunk)


class _DeadlineSocket:
	"""What http.client sees as its socket: EVERY send and recv (status line and headers included) is
	re-armed with min(READ_TIMEOUT, time left), and refused once the deadline has passed. A server that
	drips one byte just inside each timeout therefore cannot outlast the total budget."""

	def __init__(self, sock, deadline):
		self._sock = sock
		self._deadline = deadline
		self._readers = 0  # makefile() readers not yet closed
		self._closing = False

	def _arm(self):
		self._sock.settimeout(_bounded(READ_TIMEOUT, self._deadline))

	def sendall(self, data):
		self._arm()
		return self._sock.sendall(data)

	def recv_into(self, buffer):
		self._arm()
		return self._sock.recv_into(buffer)

	def makefile(self, mode="rb", buffering=None):
		if mode != "rb":
			raise ValueError("read-only binary socket file")
		self._readers += 1
		return io.BufferedReader(_DeadlineReader(self))

	def _reader_closed(self):
		self._readers -= 1
		if self._closing and self._readers <= 0:
			self._sock.close()

	def close(self):
		# Like socket.close(): while a makefile() reader is still open the real socket stays open, because
		# http.client closes the connection as soon as the headers of a "Connection: close" answer are read
		# and the body is read afterwards. HttpTransport.__call__ closes the real socket itself when done.
		self._closing = True
		if self._readers <= 0:
			self._sock.close()


class _DeadlineReader(io.RawIOBase):
	def __init__(self, sock):
		super().__init__()
		self._sock = sock

	def readable(self):
		return True

	def readinto(self, buffer):
		return self._sock.recv_into(buffer)

	def close(self):
		if not self.closed:
			super().close()
			self._sock._reader_closed()


def _bounded(limit, deadline):
	remaining = deadline - _monotonic()
	if remaining <= 0:
		raise FetchRefused("time")
	return min(limit, remaining)
