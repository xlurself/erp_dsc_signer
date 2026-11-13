"""F2 slice 1: authenticate a DSC against the pinned CCA India hierarchy (spec 002 s2, s3, s5, s6).

Pure unittest. No frappe, no site, and NO live network: every fetch goes to a FakeNet test double,
and the default HTTP transport is exercised only with a fake resolver and a fake socket.
A generated test PKI (pinned through the explicit ``roots=`` argument) covers every negative case.
A generated SignX-shaped chain whose leaf copies a real SignX Class 3 Individual DSC's profile
(tests/_test_pki.py, no personal data) runs end to end. The real CCA India 2022 root and the real,
public SignX intermediates (tests/fixtures/) run through the path validator (ca_trust._validate_path)
with only the leaf link stubbed: no real end-entity certificate is committed.
"""

import ast
import base64
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import traceback
import types
import threading
import time
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from erp_dsc_signer.tests import _test_pki
from erp_dsc_signer.utils import ca_trust, pinned_roots

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
DAY = datetime.timedelta(days=1)
MINUTE = datetime.timedelta(minutes=1)
SENTINEL = "S3NT1NEL-PIN-4417"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

CCA_ROOT_SHA256 = "9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8"
CCA_SPL_ROOT_SHA256 = "b724689b79b2ef9421ef8f5cc733eb093851b170ee715177005a09f226d8c91a"  # CCA India 2022 SPL
SIGNX_CA_SHA256 = "a8d6363afeb8fe0fc8b627022954d5681872ea4d998e59b3d8395abcc3953452"
SIGNX_SUB_SHA256 = "d29b3587cd540c45fdb29b416c73eec4c7311f721d037f16013a96ce55d4f824"

EXPECTED_REASONS = {
	"NOT_CCA_TRUSTED",
	"CHAIN_INCOMPLETE",
	"EXPIRED_OR_NOT_YET_VALID",
	"KEY_USAGE",
	"REVOKED",
	"REVOCATION_UNAVAILABLE",
	"CA_FETCH_FAILED",
	"CERTIFICATE_PROFILE",
}
EXPECTED_RECORD_KEYS = {
	"verified",
	"checked_at",
	"chain",
	"root_sha256",
	"revocation",
	"timestamp",
	"signing_time_basis",
}
SPEC_REVOCATION_UNAVAILABLE = (
	"Could not confirm with the certifying authority that this certificate is not revoked, so the document "
	"was not signed. Check the internet connection and try again."
)

CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
EMAIL = ExtendedKeyUsageOID.EMAIL_PROTECTION
OCSP_SIGNING = ExtendedKeyUsageOID.OCSP_SIGNING


# ---------------------------------------------------------------- test PKI helpers


def der(cert):
	return cert.public_bytes(serialization.Encoding.DER)


def sha(cert):
	return hashlib.sha256(der(cert)).hexdigest()


def _rsa_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_key():
	return ec.generate_private_key(ec.SECP256R1())


def _name(cn):
	return x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "XL Test PKI"),
			x509.NameAttribute(NameOID.COMMON_NAME, cn),
		]
	)


_KU = {
	"ca": dict(key_cert_sign=True, crl_sign=True),
	"leaf": dict(digital_signature=True, content_commitment=True),
	"nonrepudiation": dict(content_commitment=True),
	"encipher": dict(key_encipherment=True),
	"ocsp": dict(digital_signature=True),
}


def make_cert(
	cn,
	key,
	*,
	issuer=None,
	issuer_key=None,
	ca=False,
	pathlen=None,
	ku="leaf",
	eku=(CLIENT_AUTH, EMAIL),
	san=True,
	aia_ca=(),
	aia_ocsp=(),
	cdp=(),
	not_before=None,
	not_after=None,
	subject=None,
	serial=None,
):
	subject = subject or _name(cn)
	issuer_name = issuer.subject if issuer is not None else subject
	signing_key = issuer_key or key
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer_name)
		.public_key(key.public_key())
		.serial_number(serial or x509.random_serial_number())
		.not_valid_before(not_before or NOW - 30 * DAY)
		.not_valid_after(not_after or NOW + 365 * DAY)
		.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
	)
	if issuer is not None:
		builder = builder.add_extension(
			x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False
		)
	if ku is not None:
		flags = dict(
			digital_signature=False,
			content_commitment=False,
			key_encipherment=False,
			data_encipherment=False,
			key_agreement=False,
			key_cert_sign=False,
			crl_sign=False,
			encipher_only=False,
			decipher_only=False,
		)
		flags.update(_KU[ku])
		builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
	if eku:
		builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
	if san and not ca:
		builder = builder.add_extension(
			x509.SubjectAlternativeName([x509.RFC822Name("signer@example.com")]), critical=False
		)
	descriptions = [
		x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(u))
		for u in aia_ca
	] + [
		x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(u))
		for u in aia_ocsp
	]
	if descriptions:
		builder = builder.add_extension(x509.AuthorityInformationAccess(descriptions), critical=False)
	if cdp:
		builder = builder.add_extension(
			x509.CRLDistributionPoints(
				[
					x509.DistributionPoint(
						full_name=[x509.UniformResourceIdentifier(u)], relative_name=None, reasons=None, crl_issuer=None
					)
					for u in cdp
				]
			),
			critical=False,
		)
	return builder.sign(signing_key, hashes.SHA256())


class PKI:
	"""root -> CA (pathlen 1) -> sub-CA (pathlen 0) -> leaves, mirroring the observed SignX shape (spec s1)."""

	def __init__(self, slug, *, rsa_keys=True, root_subject=None):
		keygen = _rsa_key if rsa_keys else _ec_key
		self.u = {
			"root_cer": f"http://cca.gov.in/{slug}/root.cer",
			"ca_ocsp": f"http://ocvs.gov.in/{slug}",
			"ca_crl": f"http://cca.gov.in/{slug}/root.crl",
			"ca_cer": f"https://signxca.com/{slug}/ca.cer",
			"sub_ocsp": f"http://ocsp.signxca.com/{slug}-ca",
			"sub_crl": f"https://signxca.com/{slug}/ca.crl",
			"sub_cer": f"https://signxca.com/{slug}/sub.cer",
			"leaf_ocsp": f"http://ocsp.signxca.com/{slug}-sub",
			"leaf_crl": f"https://signxca.com/{slug}/sub.crl",
		}
		self.root_key, self.ca_key, self.sub_key = keygen(), keygen(), keygen()
		self.root = make_cert(f"{slug} Root", self.root_key, ca=True, ku="ca", eku=(), subject=root_subject)
		self.ca = self.make_ca(f"{slug} CA", self.ca_key, self.root, self.root_key, 1, "root_cer", "ca_ocsp", "ca_crl")
		self.sub = self.make_ca(f"{slug} Sub-CA", self.sub_key, self.ca, self.ca_key, 0, "ca_cer", "sub_ocsp", "sub_crl")

	def make_ca(self, cn, key, issuer, issuer_key, pathlen, cer, ocsp_url, crl, **kw):
		return make_cert(
			cn,
			key,
			issuer=issuer,
			issuer_key=issuer_key,
			ca=True,
			pathlen=pathlen,
			ku="ca",
			eku=(),
			aia_ca=[self.u[cer]],
			aia_ocsp=[self.u[ocsp_url]],
			cdp=[self.u[crl]],
			**kw,
		)

	def leaf(self, cn="Test Signer", **kw):
		kw.setdefault("issuer", self.sub)
		kw.setdefault("issuer_key", self.sub_key)
		kw.setdefault("aia_ca", [self.u["sub_cer"]])
		kw.setdefault("aia_ocsp", [self.u["leaf_ocsp"]])
		kw.setdefault("cdp", [self.u["leaf_crl"]])
		key = kw.pop("key", None) or _ec_key()
		return make_cert(cn, key, **kw)


def ocsp_bytes(
	cert,
	issuer,
	issuer_key,
	*,
	status="good",
	this_update=None,
	next_update="default",
	responder=None,
	responder_key=None,
	signer_key=None,
	certs=None,
	encoding=ocsp.OCSPResponderEncoding.HASH,
	algorithm=None,
):
	responder = responder or issuer
	responder_key = responder_key or issuer_key
	revoked = status == "revoked"
	builder = ocsp.OCSPResponseBuilder().add_response(
		cert=cert,
		issuer=issuer,
		algorithm=algorithm or hashes.SHA1(),
		cert_status={
			"good": ocsp.OCSPCertStatus.GOOD,
			"revoked": ocsp.OCSPCertStatus.REVOKED,
			"unknown": ocsp.OCSPCertStatus.UNKNOWN,
		}[status],
		this_update=this_update or NOW - 60 * MINUTE,
		next_update=(NOW + DAY) if next_update == "default" else next_update,
		revocation_time=NOW - DAY if revoked else None,
		revocation_reason=x509.ReasonFlags.key_compromise if revoked else None,
	)
	builder = builder.responder_id(encoding, responder)
	if certs is not None:
		if certs:  # certs=[] embeds no certificate
			builder = builder.certificates(certs)
	elif responder is not issuer:
		builder = builder.certificates([responder])
	return builder.sign(signer_key or responder_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def ocsp_unsuccessful():
	return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.INTERNAL_ERROR).public_bytes(
		serialization.Encoding.DER
	)


def crl_bytes(issuer, issuer_key, *, revoked=(), last_update=None, next_update=None, signer_key=None, issuer_name=None):
	builder = (
		x509.CertificateRevocationListBuilder()
		.issuer_name(issuer_name or issuer.subject)
		.last_update(last_update or NOW - 60 * MINUTE)
		.next_update(next_update or NOW + 7 * DAY)
	)
	for serial in revoked:
		builder = builder.add_revoked_certificate(
			x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW - 2 * DAY).build()
		)
	return builder.sign(signer_key or issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class FakeNet:
	"""Injected fetch: url -> bytes | Exception | callable(data). Records every call; never touches the network."""

	def __init__(self):
		self.routes = {}
		self.calls = []

	def __call__(self, url, *, data=None, content_type=None, max_bytes, timeout):
		self.calls.append(dict(url=url, data=data, content_type=content_type, max_bytes=max_bytes, timeout=timeout))
		route = self.routes.get(url)
		if route is None:
			raise OSError("no route")
		if isinstance(route, BaseException):
			raise route
		if callable(route):
			return route(data)
		return route

	def urls(self):
		return [c["url"] for c in self.calls]


def world(pki, leaf, *, with_ocsp=True, with_crl=True):
	net = FakeNet()
	u = pki.u
	net.routes[u["sub_cer"]] = base64.encodebytes(der(pki.sub))  # SignX serves AIA as base64 text
	net.routes[u["ca_cer"]] = der(pki.ca)
	net.routes[u["root_cer"]] = der(pki.root)
	if with_ocsp:
		net.routes[u["leaf_ocsp"]] = ocsp_bytes(leaf, pki.sub, pki.sub_key)
		net.routes[u["sub_ocsp"]] = ocsp_bytes(pki.sub, pki.ca, pki.ca_key)
		net.routes[u["ca_ocsp"]] = ocsp_bytes(pki.ca, pki.root, pki.root_key)
	if with_crl:
		net.routes[u["leaf_crl"]] = crl_bytes(pki.sub, pki.sub_key)
		net.routes[u["sub_crl"]] = crl_bytes(pki.ca, pki.ca_key)
		net.routes[u["ca_crl"]] = crl_bytes(pki.root, pki.root_key)
	return net


MAIN = None
ROGUE = None


def setUpModule():
	global MAIN, ROGUE
	MAIN = PKI("t")
	ROGUE = PKI("r", rsa_keys=False)


class _Base(unittest.TestCase):
	def setUp(self):
		ca_trust.clear_cache()

	def auth(self, leaf, net, pki=None, **kw):
		kw.setdefault("now", NOW)
		kw.setdefault("roots", [(pki or MAIN).root])
		return ca_trust.authenticate_certificate(der(leaf), fetch=net, **kw)

	def assertRefused(self, code, leaf, net, **kw):
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			self.auth(leaf, net, **kw)
		exc = cm.exception
		self.assertEqual(exc.reason_code, code)
		self.assertEqual(exc.message, ca_trust.MESSAGES[code])
		self.assertEqual(exc.args, (code, ca_trust.MESSAGES[code]))
		return exc

	def assertPasses(self, leaf, net, **kw):
		record = self.auth(leaf, net, **kw)
		self.assertIs(record["verified"], True)
		return record


# ---------------------------------------------------------------- chain / trust


class ChainTrustTest(_Base):
	def test_good_chain_passes_positive_control(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		record = self.assertPasses(leaf, net)
		self.assertEqual([c["sha256"] for c in record["chain"]], [sha(leaf), sha(MAIN.sub), sha(MAIN.ca), sha(MAIN.root)])
		self.assertEqual([c["subject_cn"] for c in record["chain"]], ["Test Signer", "t Sub-CA", "t CA", "t Root"])
		self.assertEqual(record["root_sha256"], sha(MAIN.root))
		self.assertEqual(record["checked_at"], "2026-11-09T12:00:00+00:00")
		# The pinned root is never downloaded; trust never comes from the network.
		self.assertNotIn(MAIN.u["root_cer"], net.urls())
		self.assertEqual(net.urls()[:2], [MAIN.u["sub_cer"], MAIN.u["ca_cer"]])

	def test_unpinned_root_refused(self):
		leaf = MAIN.leaf()
		self.assertRefused("NOT_CCA_TRUSTED", leaf, world(MAIN, leaf), roots=[ROGUE.root])
		self.assertEqual(ca_trust._INTERMEDIATE_CACHE, {})  # unverified downloads are never cached

	def test_foreign_hierarchy_refused_against_pinned_root(self):
		leaf = ROGUE.leaf()
		self.assertRefused("NOT_CCA_TRUSTED", leaf, world(ROGUE, leaf), roots=[MAIN.root])

	def test_self_signed_leaf_refused(self):
		key = _ec_key()
		leaf = make_cert("Self Signer", key)
		net = FakeNet()
		self.assertRefused("NOT_CCA_TRUSTED", leaf, net)
		self.assertEqual(net.calls, [])

	def test_fake_ca_with_copied_root_name_refused(self):
		# Attacker root copies the pinned root's subject name but has its own key.
		fake = PKI("f", rsa_keys=False, root_subject=MAIN.root.subject)
		self.assertEqual(fake.root.subject, MAIN.root.subject)
		leaf = fake.leaf()
		net = world(fake, leaf)
		self.assertRefused("NOT_CCA_TRUSTED", leaf, net, roots=[MAIN.root])
		# R2 iteration 4: a pinned-name match without the pinned key's signature is followed (it may sit below a
		# self-issued key-rollover certificate), so the fake root IS downloaded now; being self-signed and not
		# signed by a pinned key it ends the walk as NOT_CCA_TRUSTED, is never an anchor and is never cached.
		self.assertEqual(net.urls(), [fake.u["sub_cer"], fake.u["ca_cer"], fake.u["root_cer"]])
		self.assertEqual(ca_trust._INTERMEDIATE_CACHE, {})

	def test_chain_incomplete_without_aia(self):
		leaf = MAIN.leaf(aia_ca=())
		net = world(MAIN, leaf)
		self.assertRefused("CHAIN_INCOMPLETE", leaf, net)
		self.assertNotIn(MAIN.u["sub_cer"], net.urls())

	def test_fetched_intermediate_that_does_not_chain_is_rejected(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		net.routes[MAIN.u["sub_cer"]] = der(ROGUE.sub)  # a real CA cert, but not the leaf's issuer
		self.assertRefused("CHAIN_INCOMPLETE", leaf, net)
		self.assertEqual(len(ca_trust._INTERMEDIATE_CACHE), 0)

	def test_fetched_non_ca_intermediate_is_never_trusted_by_itself(self):
		# An end-entity cert issued under the pinned hierarchy "issues" the leaf: signatures chain,
		# but the library must refuse the path because the middle cert is not a CA.
		fake_mid_key = _ec_key()
		fake_mid = make_cert(
			"Not A CA",
			fake_mid_key,
			issuer=MAIN.sub,
			issuer_key=MAIN.sub_key,
			aia_ca=[MAIN.u["sub_cer"]],
			aia_ocsp=[MAIN.u["leaf_ocsp"]],
		)
		mid_url = "https://signxca.com/t/not-a-ca.cer"
		leaf = MAIN.leaf(issuer=fake_mid, issuer_key=fake_mid_key, aia_ca=[mid_url])
		net = world(MAIN, leaf)
		net.routes[mid_url] = der(fake_mid)
		self.assertRefused("NOT_CCA_TRUSTED", leaf, net)
		self.assertIn(mid_url, net.urls())
		self.assertEqual(ca_trust._INTERMEDIATE_CACHE, {})

	def test_ca_fetch_failures(self):
		leaf = MAIN.leaf()
		for label, body in (
			("network error", OSError("down")),
			("garbage", b"<html>not a certificate</html>"),
			("bad base64", b"MIIB!!!!"),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf)
				net.routes[MAIN.u["sub_cer"]] = body
				self.assertRefused("CA_FETCH_FAILED", leaf, net)

	def test_path_validator_gets_only_the_given_roots_and_ends_at_one(self):
		seen = []
		real_validate = ca_trust._validate_path

		def spy(chain, anchors, now):
			seen.append(([sha(c) for c in chain], [sha(c) for c in anchors]))
			return real_validate(chain, anchors, now)

		leaf = MAIN.leaf()
		with mock.patch.object(ca_trust, "_validate_path", side_effect=spy):
			self.assertPasses(leaf, world(MAIN, leaf))
		self.assertEqual(seen, [([sha(leaf), sha(MAIN.sub), sha(MAIN.ca), sha(MAIN.root)], [sha(MAIN.root)])])

	def test_default_roots_are_the_pinned_roots(self):
		# The anchors consulted while building the path are exactly the two pinned CCA India roots.
		# (The previous form spied on a library Store that a refused path never reached: vacuous.)
		seen = []
		real_anchor = ca_trust._issuing_anchor

		def spy(cert, anchors):
			seen.append([sha(c) for c in anchors])
			return real_anchor(cert, anchors)

		leaf = MAIN.leaf()
		with mock.patch.object(ca_trust, "_issuing_anchor", side_effect=spy):
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(der(leaf), now=NOW, fetch=world(MAIN, leaf))
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		self.assertTrue(seen)
		self.assertTrue(all(s == [CCA_ROOT_SHA256, CCA_SPL_ROOT_SHA256] for s in seen), seen)

	def test_verified_intermediates_are_cached(self):
		leaf = MAIN.leaf()
		self.assertPasses(leaf, world(MAIN, leaf))
		net = world(MAIN, leaf)
		del net.routes[MAIN.u["sub_cer"]], net.routes[MAIN.u["ca_cer"]]
		self.assertPasses(leaf, net)
		self.assertNotIn(MAIN.u["sub_cer"], net.urls())


class ValidityAndKeyUsageTest(_Base):
	def test_expired_leaf(self):
		leaf = MAIN.leaf(not_before=NOW - 400 * DAY, not_after=NOW - DAY)
		net = world(MAIN, leaf)
		self.assertRefused("EXPIRED_OR_NOT_YET_VALID", leaf, net)
		self.assertEqual(net.calls, [])  # a failing certificate never reaches the network

	def test_not_yet_valid_leaf(self):
		leaf = MAIN.leaf(not_before=NOW + DAY, not_after=NOW + 400 * DAY)
		self.assertRefused("EXPIRED_OR_NOT_YET_VALID", leaf, world(MAIN, leaf))

	def test_expired_intermediate(self):
		old_key = _rsa_key()
		old_sub = MAIN.make_ca(
			"t Old Sub-CA", old_key, MAIN.ca, MAIN.ca_key, 0, "ca_cer", "sub_ocsp", "sub_crl",
			not_before=NOW - 400 * DAY, not_after=NOW - DAY,
		)
		url = "https://signxca.com/t/old-sub.cer"
		leaf = MAIN.leaf(issuer=old_sub, issuer_key=old_key, aia_ca=[url], not_before=NOW - 500 * DAY)
		net = world(MAIN, leaf)
		net.routes[url] = der(old_sub)
		self.assertRefused("EXPIRED_OR_NOT_YET_VALID", leaf, net)

	def test_leaf_without_signing_key_usage_refused(self):
		leaf = MAIN.leaf(ku="encipher")
		net = world(MAIN, leaf)
		self.assertRefused("KEY_USAGE", leaf, net)
		self.assertEqual(net.calls, [])

	def test_key_usage_refusal_does_not_depend_on_san_or_eku(self):
		leaf = MAIN.leaf(ku="encipher", san=False, eku=(EMAIL,))
		net = world(MAIN, leaf)
		self.assertRefused("KEY_USAGE", leaf, net)
		self.assertEqual(net.calls, [])

	def test_no_tls_profile_rule_san_and_eku_are_not_gates(self):
		# R2 HIGH: a CMS/PDF signing DSC needs neither a SAN nor TLS clientAuth. Before the fix every case
		# below except "clientAuth only" was refused as CERTIFICATE_PROFILE before any download.
		for label, kw in (
			("no SAN", dict(san=False)),
			("EKU emailProtection only", dict(eku=(EMAIL,))),
			("EKU Microsoft documentSigning only", dict(eku=(_test_pki.MS_DOCUMENT_SIGNING,))),
			("EKU Adobe PDF signing only", dict(eku=(_test_pki.ADOBE_PDF_SIGNING,))),
			("EKU anyExtendedKeyUsage", dict(eku=(ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,))),
			("no EKU at all", dict(eku=())),
			("clientAuth only", dict(eku=(CLIENT_AUTH,))),
			("no SAN, no EKU, no keyUsage", dict(san=False, eku=(), ku=None)),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				leaf = MAIN.leaf(**kw)
				record = self.assertPasses(leaf, world(MAIN, leaf))
				self.assertEqual(record["chain"][0]["sha256"], sha(leaf))

	def test_key_usage_positive_controls(self):
		for label, kw in (
			("digitalSignature+nonRepudiation", dict(ku="leaf")),
			("nonRepudiation only", dict(ku="nonrepudiation")),
			("no keyUsage extension (existing rule)", dict(ku=None)),
		):
			with self.subTest(label):
				leaf = MAIN.leaf(**kw)
				self.assertPasses(leaf, world(MAIN, leaf))

	def test_naive_now_is_a_programming_error(self):
		leaf = MAIN.leaf()
		with self.assertRaises(TypeError):
			ca_trust.authenticate_certificate(der(leaf), now=NOW.replace(tzinfo=None), fetch=FakeNet(), roots=[MAIN.root])

	def test_unparseable_certificate_refused(self):
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust.authenticate_certificate(b"\x30\x03junk", now=NOW, fetch=FakeNet(), roots=[MAIN.root])
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")


# ---------------------------------------------------------------- revocation


class OCSPTest(_Base):
	def test_every_non_root_cert_is_checked_by_ocsp(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_crl=False)
		record = self.assertPasses(leaf, net)
		for url in (MAIN.u["leaf_ocsp"], MAIN.u["sub_ocsp"], MAIN.u["ca_ocsp"]):
			self.assertIn(url, net.urls())
		self.assertEqual([r["method"] for r in record["revocation"]], ["ocsp", "ocsp", "ocsp"])
		self.assertEqual([r["status"] for r in record["revocation"]], ["good", "good", "good"])
		self.assertEqual(
			[r["responder_host"] for r in record["revocation"]], ["ocsp.signxca.com", "ocsp.signxca.com", "ocvs.gov.in"]
		)
		self.assertEqual([r["subject_cn"] for r in record["revocation"]], ["Test Signer", "t Sub-CA", "t CA"])
		ocsp_call = next(c for c in net.calls if c["url"] == MAIN.u["leaf_ocsp"])
		self.assertEqual(ocsp_call["content_type"], "application/ocsp-request")
		request = ocsp.load_der_ocsp_request(ocsp_call["data"])
		self.assertEqual(request.serial_number, leaf.serial_number)

	def test_revoked_leaf_via_ocsp(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, status="revoked")
		self.assertRefused("REVOKED", leaf, net)
		self.assertNotIn(MAIN.u["leaf_crl"], net.urls())  # a revoked answer is final, no downgrade

	def test_stale_revoked_ocsp_is_still_final_even_when_the_crl_says_good(self):
		# Cursor L1: a correctly signed "revoked" answer refuses even when its nextUpdate is past.
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)  # the CRL (default) lists nothing: good
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(
			leaf, MAIN.sub, MAIN.sub_key, status="revoked", this_update=NOW - 3 * DAY, next_update=NOW - DAY
		)
		self.assertRefused("REVOKED", leaf, net)
		self.assertNotIn(MAIN.u["leaf_crl"], net.urls())

	def test_revoked_intermediate_via_ocsp(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		net.routes[MAIN.u["sub_ocsp"]] = ocsp_bytes(MAIN.sub, MAIN.ca, MAIN.ca_key, status="revoked")
		self.assertRefused("REVOKED", leaf, net)

	def test_ocsp_error_then_crl_good_passes(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_unsuccessful()
		record = self.assertPasses(leaf, net)
		self.assertEqual(record["revocation"][0]["method"], "crl")
		self.assertEqual(record["revocation"][0]["responder_host"], "signxca.com")
		self.assertEqual(record["revocation"][0]["produced_at"], (NOW - 60 * MINUTE).isoformat())

	def test_both_unavailable_refuses(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_ocsp=False, with_crl=False)
		exc = self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
		self.assertEqual(exc.message, SPEC_REVOCATION_UNAVAILABLE)

	def test_unknown_status_is_not_good(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, status="unknown")
		self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	def test_bad_ocsp_signature(self):
		leaf = MAIN.leaf()
		# Responder id names the real issuer, but the response is signed by an attacker key.
		attacker_key = _ec_key()
		impostor = make_cert("x", attacker_key, subject=MAIN.sub.subject, ca=True, ku="ca", eku=())
		forged = ocsp_bytes(
			leaf, MAIN.sub, MAIN.sub_key, responder=impostor, responder_key=attacker_key, certs=[],
			encoding=ocsp.OCSPResponderEncoding.NAME,
		)
		self.assertEqual(ocsp.load_der_ocsp_response(forged).responder_name, MAIN.sub.subject)
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = forged
		self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
		# Control: the same forged OCSP with a good CRL passes only through the CRL.
		ca_trust.clear_cache()
		net = world(MAIN, leaf)
		net.routes[MAIN.u["leaf_ocsp"]] = forged
		self.assertEqual(self.assertPasses(leaf, net)["revocation"][0]["method"], "crl")

	def test_stale_and_future_ocsp(self):
		leaf = MAIN.leaf()
		for label, kw in (
			("nextUpdate past skew", dict(this_update=NOW - 2 * DAY, next_update=NOW - 6 * MINUTE)),
			("thisUpdate in the future past skew", dict(this_update=NOW + 6 * MINUTE, next_update=NOW + DAY)),
			("no nextUpdate", dict(next_update=None)),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_crl=False)
				net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, **kw)
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	def test_ocsp_within_clock_skew_passes(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(
			leaf, MAIN.sub, MAIN.sub_key, this_update=NOW + 4 * MINUTE, next_update=NOW - 4 * MINUTE + DAY
		)
		self.assertPasses(leaf, net)
		ca_trust.clear_cache()
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(
			leaf, MAIN.sub, MAIN.sub_key, this_update=NOW - DAY, next_update=NOW - 4 * MINUTE
		)
		self.assertPasses(leaf, net)

	def test_ocsp_signed_by_non_delegated_cert(self):
		leaf = MAIN.leaf()
		no_eku_key = _ec_key()
		no_eku = make_cert("t Responder no EKU", no_eku_key, issuer=MAIN.sub, issuer_key=MAIN.sub_key, ku="ocsp", eku=(CLIENT_AUTH,), san=False)
		foreign_key = _ec_key()
		foreign = make_cert("t Responder foreign", foreign_key, issuer=ROGUE.sub, issuer_key=ROGUE.sub_key, ku="ocsp", eku=(OCSP_SIGNING,), san=False)
		for label, responder, key in (("no id-kp-OCSPSigning", no_eku, no_eku_key), ("not issued by issuer", foreign, foreign_key)):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_crl=False)
				net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, responder=responder, responder_key=key)
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	def test_ocsp_signed_by_delegated_responder_passes(self):
		leaf = MAIN.leaf()
		key = _ec_key()
		responder = make_cert("t OCSP Responder", key, issuer=MAIN.sub, issuer_key=MAIN.sub_key, ku="ocsp", eku=(OCSP_SIGNING,), san=False)
		for encoding in (ocsp.OCSPResponderEncoding.HASH, ocsp.OCSPResponderEncoding.NAME):
			with self.subTest(encoding.name):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_crl=False)
				net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(
					leaf, MAIN.sub, MAIN.sub_key, responder=responder, responder_key=key, encoding=encoding
				)
				self.assertPasses(leaf, net)

	def test_expired_delegated_responder_refused(self):
		leaf = MAIN.leaf()
		key = _ec_key()
		responder = make_cert(
			"t OCSP Responder old", key, issuer=MAIN.sub, issuer_key=MAIN.sub_key, ku="ocsp", eku=(OCSP_SIGNING,),
			san=False, not_before=NOW - 30 * DAY, not_after=NOW - DAY,
		)
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, responder=responder, responder_key=key)
		self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	def test_ocsp_good_answer_for_another_certificate_is_not_accepted(self):
		leaf = MAIN.leaf()
		other = MAIN.leaf("Someone Else")
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(other, MAIN.sub, MAIN.sub_key)
		self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	def test_ocsp_answer_must_match_issuer_hashes_not_only_the_serial(self):
		# A correctly signed answer about the leaf's SERIAL under another issuer proves nothing about the
		# leaf. Each case kills one mutation of _matching_single_response (serial-only, name-only, key-only).
		leaf = MAIN.leaf()
		other_key = _rsa_key()
		same_name_other_key = make_cert(
			"x", other_key, issuer=MAIN.ca, issuer_key=MAIN.ca_key, ca=True, ku="ca", eku=(), subject=MAIN.sub.subject
		)
		same_key_other_name = make_cert(
			"t Other Sub-CA", MAIN.sub_key, issuer=MAIN.ca, issuer_key=MAIN.ca_key, ca=True, ku="ca", eku=()
		)
		for label, wrong_issuer, wrong_key in (
			("other issuer", ROGUE.sub, ROGUE.sub_key),
			("same issuer name, other key", same_name_other_key, other_key),
			("same issuer key, other name", same_key_other_name, MAIN.sub_key),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				# The CertID name hash comes from the certificate's issuer field, the key hash from the issuer key.
				twin = make_cert("Serial Twin", _ec_key(), issuer=wrong_issuer, issuer_key=wrong_key, serial=leaf.serial_number)
				net = world(MAIN, leaf, with_crl=False)
				net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(
					twin, wrong_issuer, None, responder=MAIN.sub, responder_key=MAIN.sub_key, certs=[]
				)
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
				self.assertIn(MAIN.u["leaf_ocsp"], net.urls())

	def test_ocsp_cert_id_hash_algorithm_is_taken_from_the_answer(self):
		# control for the matcher above: a SHA-256 CertID for the right certificate is accepted.
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, algorithm=hashes.SHA256())
		record = self.assertPasses(leaf, net)
		self.assertEqual(record["revocation"][0]["method"], "ocsp")

	def test_second_ocsp_url_used_when_first_fails(self):
		second = "http://ocsp.signxca.com/t-sub-backup"
		leaf = MAIN.leaf(aia_ocsp=[MAIN.u["leaf_ocsp"], second])
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = RuntimeError("responder down")
		net.routes[second] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key)
		self.assertPasses(leaf, net)


class CRLTest(_Base):
	def test_revoked_via_crl(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_ocsp=False)
		net.routes[MAIN.u["leaf_crl"]] = crl_bytes(MAIN.sub, MAIN.sub_key, revoked=[12345, leaf.serial_number])
		self.assertRefused("REVOKED", leaf, net)

	def test_crl_good_passes_for_every_cert(self):
		leaf = MAIN.leaf()
		record = self.assertPasses(leaf, world(MAIN, leaf, with_ocsp=False))
		self.assertEqual([r["method"] for r in record["revocation"]], ["crl", "crl", "crl"])
		self.assertEqual([r["responder_host"] for r in record["revocation"]], ["signxca.com", "signxca.com", "cca.gov.in"])

	def test_unverifiable_crl_refused(self):
		leaf = MAIN.leaf()
		for label, body in (
			("wrong signer", crl_bytes(MAIN.sub, MAIN.sub_key, signer_key=_rsa_key())),
			("other issuer name", crl_bytes(MAIN.sub, MAIN.sub_key, issuer_name=_name("t Other"))),
			("stale", crl_bytes(MAIN.sub, MAIN.sub_key, last_update=NOW - 10 * DAY, next_update=NOW - 6 * MINUTE)),
			("future", crl_bytes(MAIN.sub, MAIN.sub_key, last_update=NOW + 6 * MINUTE, next_update=NOW + 7 * DAY)),
			("garbage", b"\x30\x82garbage"),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_ocsp=False)
				net.routes[MAIN.u["leaf_crl"]] = body
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)

	@staticmethod
	def _scoped_crl(issuer, issuer_key, extension, critical=True):
		builder = (
			x509.CertificateRevocationListBuilder()
			.issuer_name(issuer.subject)
			.last_update(NOW - 60 * MINUTE)
			.next_update(NOW + 7 * DAY)
			.add_extension(extension, critical=critical)
		)
		return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

	@staticmethod
	def _idp(url, **flags):
		values = dict(
			full_name=[x509.UniformResourceIdentifier(url)],
			relative_name=None,
			only_contains_user_certs=False,
			only_contains_ca_certs=False,
			only_some_reasons=None,
			indirect_crl=False,
			only_contains_attribute_certs=False,
		)
		values.update(flags)
		return x509.IssuingDistributionPoint(**values)

	def test_crl_outside_complete_direct_scope_cannot_prove_not_revoked(self):
		# Each CRL is correctly signed, fresh and does not list the certificate: only _crl_scope_ok refuses
		# it (forcing that function to True makes these cases pass, so the mutation is caught).
		leaf = MAIN.leaf()
		u = MAIN.u
		unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.7"), b"\x05\x00")
		cases = (
			("delta CRL", "leaf_crl", x509.DeltaCRLIndicator(7)),
			("indirect CRL", "leaf_crl", self._idp(u["leaf_crl"], indirect_crl=True)),
			("some reasons only", "leaf_crl", self._idp(u["leaf_crl"], only_some_reasons=frozenset({x509.ReasonFlags.key_compromise}))),
			("CA certs only, for a leaf", "leaf_crl", self._idp(u["leaf_crl"], only_contains_ca_certs=True)),
			("attribute certs only", "leaf_crl", self._idp(u["leaf_crl"], only_contains_attribute_certs=True)),
			("user certs only, for a CA", "sub_crl", self._idp(u["sub_crl"], only_contains_user_certs=True)),
			("unknown critical extension", "leaf_crl", unknown),
		)
		for label, route, extension in cases:
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_ocsp=False)
				issuer, issuer_key = (MAIN.sub, MAIN.sub_key) if route == "leaf_crl" else (MAIN.ca, MAIN.ca_key)
				net.routes[u[route]] = self._scoped_crl(issuer, issuer_key, extension)
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
				self.assertIn(u[route], net.urls())

	def test_crl_scope_positive_controls(self):
		leaf = MAIN.leaf()
		u = MAIN.u
		unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.7"), b"\x05\x00")
		for label, extension, critical in (
			("user certs only, for a leaf", self._idp(u["leaf_crl"], only_contains_user_certs=True), True),
			("plain IDP", self._idp(u["leaf_crl"]), True),
			("unknown NON-critical extension", unknown, False),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, with_ocsp=False)
				net.routes[u["leaf_crl"]] = self._scoped_crl(MAIN.sub, MAIN.sub_key, extension, critical=critical)
				self.assertPasses(leaf, net)


# ---------------------------------------------------------------- SSRF / DoS guard


HOSTILE_URLS = [
	"http://127.0.0.1/x",
	"http://localhost/x",
	"http://10.0.0.5/x",
	"http://192.168.1.1/x",
	"http://169.254.169.254/latest/meta-data/",
	"http://[::1]/x",
	"http://evil.example/x",
	"http://signxca.com.evil.example/x",
	"http://user:pw@signxca.com/x",
	"http://signxca.com@evil.example/x",
	"http://signxca.com:8080/x",
	"http://signxca.com:22/x",
	"ftp://signxca.com/x",
	"file:///etc/passwd",
	"gopher://ocsp.signxca.com/x",
]


class URLPolicyTest(_Base):
	def test_url_policy_table(self):
		allowed = ca_trust.DEFAULT_ALLOWED_HOSTS
		for url in HOSTILE_URLS + ["http://signxca.com/a b", "http://signxca.com./x", "", "http://signxca.com/\r\nX: y"]:
			with self.subTest(url=url):
				self.assertFalse(ca_trust.url_allowed(url, allowed))
		for url in (  # positive controls
			"http://ocsp.signxca.com/SignXClass3Individual",
			"https://signxca.com/repository/crl/SignXClass3Individual.crl",
			"http://ocvs.gov.in",
			"http://www.cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer",
			"http://cca.gov.in:80/rw/resources/CCAIndia2022Latest.crl",
			"https://signxca.com:443/x",
		):
			with self.subTest(url=url):
				self.assertTrue(ca_trust.url_allowed(url, allowed))

	def test_default_allowlist_is_exact(self):
		self.assertEqual(
			ca_trust.DEFAULT_ALLOWED_HOSTS,
			frozenset({"signxca.com", "ocsp.signxca.com", "ocvs.gov.in", "cca.gov.in", "www.cca.gov.in"}),
		)

	def test_hostile_aia_never_fetched(self):
		for url in HOSTILE_URLS:
			with self.subTest(url=url):
				ca_trust.clear_cache()
				leaf = MAIN.leaf(aia_ca=[url])
				net = world(MAIN, leaf)
				net.routes[url] = base64.encodebytes(der(MAIN.sub))
				self.assertRefused("CA_FETCH_FAILED", leaf, net)
				self.assertEqual(net.calls, [])

	def test_hostile_ocsp_and_crl_never_fetched(self):
		for url in HOSTILE_URLS:
			with self.subTest(url=url):
				ca_trust.clear_cache()
				leaf = MAIN.leaf(aia_ocsp=[url], cdp=[url])
				net = world(MAIN, leaf)
				net.routes[url] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key)
				self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
				self.assertNotIn(url, net.urls())

	def test_extra_hosts_extend_the_allowlist_only(self):
		host = "ocsp.example-ca.in"
		url = f"http://{host}/leaf"
		leaf = MAIN.leaf(aia_ocsp=[url])
		net = world(MAIN, leaf, with_crl=False)
		net.routes[url] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key)
		self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
		ca_trust.clear_cache()
		self.assertPasses(leaf, net, extra_hosts=[host])
		for bad in ("127.0.0.1", "10.0.0.1", "[::1]", "*.signxca.com", "a b", ""):
			with self.subTest(bad=bad):
				with self.assertRaises(ValueError):
					self.auth(leaf, net, extra_hosts=[bad])

	def test_size_caps_are_passed_and_enforced(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf)
		self.assertPasses(leaf, net)
		caps = {c["url"]: c["max_bytes"] for c in net.calls}
		self.assertEqual(caps[MAIN.u["sub_cer"]], 20 * 1024)
		self.assertEqual(caps[MAIN.u["leaf_ocsp"]], ca_trust.MAX_OCSP_BYTES)
		self.assertLessEqual(ca_trust.MAX_OCSP_BYTES, 64 * 1024)
		self.assertEqual(ca_trust.MAX_CERT_BYTES, 20 * 1024)
		self.assertEqual(ca_trust.MAX_CRL_BYTES, 8 * 1024 * 1024)

	def test_oversize_responses_refused_even_if_fetch_ignores_the_cap(self):
		# Each oversize body is otherwise acceptable (whitespace-padded base64; a valid OCSP response with
		# extra embedded certificates): the control raises the cap and the same body then passes.
		leaf = MAIN.leaf()
		big_cert = base64.encodebytes(der(MAIN.sub)) + b"\n" * (20 * 1024)
		big_ocsp = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key, certs=[MAIN.sub] * 80)
		big_crl = base64.encodebytes(crl_bytes(MAIN.sub, MAIN.sub_key)) + b"\n" * (8 * 1024 * 1024)
		self.assertGreater(len(big_ocsp), ca_trust.MAX_OCSP_BYTES)
		cases = (
			("aia", "CA_FETCH_FAILED", MAIN.u["sub_cer"], big_cert, {}, "MAX_CERT_BYTES"),
			("ocsp", "REVOCATION_UNAVAILABLE", MAIN.u["leaf_ocsp"], big_ocsp, dict(with_crl=False), "MAX_OCSP_BYTES"),
			("crl", "REVOCATION_UNAVAILABLE", MAIN.u["leaf_crl"], big_crl, dict(with_ocsp=False), "MAX_CRL_BYTES"),
		)
		for label, code, url, body, world_kw, cap in cases:
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf, **world_kw)
				net.routes[url] = body
				self.assertRefused(code, leaf, net)
				self.assertIn(url, net.urls())
				ca_trust.clear_cache()
				with mock.patch.object(ca_trust, cap, 64 * 1024 * 1024):
					self.assertPasses(leaf, net)  # control: only the cap refused it

	def test_total_budget_stops_further_fetches(self):
		leaf = MAIN.leaf()
		inner = world(MAIN, leaf)
		clock = [1000.0]

		def slow(url, **kw):
			result = inner(url, **kw)
			clock[0] += 9.0
			return result

		with mock.patch.object(ca_trust, "_monotonic", side_effect=lambda: clock[0]):
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(der(leaf), now=NOW, fetch=slow, roots=[MAIN.root])
		self.assertEqual(cm.exception.reason_code, "REVOCATION_UNAVAILABLE")
		self.assertEqual(len(inner.calls), 3)  # 2 AIA + 1 OCSP, then the 25 s budget is spent
		self.assertLessEqual(inner.calls[0]["timeout"], 25.0)
		self.assertLessEqual(inner.calls[2]["timeout"], 25.0 - 18.0)
		self.assertEqual(ca_trust.TOTAL_BUDGET, 25.0)


class HttpsTwinTest(_Base):
	"""CCA India publishes http:// CRL/CA-certificate addresses that no longer answer; https:// does."""

	CRL = "http://cca.gov.in/rw/resources/CCAIndia2022Latest.crl"

	def link(self):
		leaf = MAIN.leaf()
		return leaf, MAIN.sub

	def test_twin_is_built_only_for_http_get_urls_on_cca_hosts(self):
		for url, expected in (
			(self.CRL, "https://cca.gov.in/rw/resources/CCAIndia2022Latest.crl"),
			("http://www.cca.gov.in/a/b.cer?x=1", "https://www.cca.gov.in/a/b.cer?x=1"),
			("http://cca.gov.in:80/a.crl", "https://cca.gov.in/a.crl"),
			("https://cca.gov.in/a.crl", None),
			("http://signxca.com/a.crl", None),
			("http://ocvs.gov.in", None),
			("http://cca.gov.in:443/a.crl", None),
			("http://user@cca.gov.in/a.crl", None),
			("http://evil.example/cca.gov.in/a.crl", None),
		):
			with self.subTest(url):
				self.assertEqual(ca_trust._https_twin(url), expected)

	def test_twin_never_covers_extra_hosts(self):
		self.assertIsNone(ca_trust._https_twin("http://ca.example.org/a.crl"))

	def test_http_timeout_then_valid_https_crl_gives_good(self):
		https = self.CRL.replace("http://", "https://", 1)
		good = crl_bytes(MAIN.root, MAIN.root_key)

		def fetch(url, **kw):
			if url == https:
				return good
			raise TimeoutError()

		network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
		with mock.patch.object(ca_trust, "_crl_urls", return_value=[self.CRL]):
			outcome = ca_trust._check_crl(MAIN.sub, MAIN.root, NOW, network)
		self.assertIsNotNone(outcome)
		self.assertEqual(outcome[0], "good")
		self.assertEqual(outcome[1]["responder_host"], "cca.gov.in")

	def test_http_timeout_then_revoked_https_crl_is_revoked(self):
		https = self.CRL.replace("http://", "https://", 1)
		bad = crl_bytes(MAIN.root, MAIN.root_key, revoked=[MAIN.sub.serial_number])

		def fetch(url, **kw):
			if url == https:
				return bad
			raise TimeoutError()

		network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
		with mock.patch.object(ca_trust, "_crl_urls", return_value=[self.CRL]):
			self.assertEqual(ca_trust._check_crl(MAIN.sub, MAIN.root, NOW, network), ("revoked", None))

	def test_unverifiable_https_answer_is_still_refused(self):
		# A middlebox that answers the https twin with a CRL signed by the wrong key must not turn failure into success.
		cert = MAIN.sub
		network = ca_trust._Network(lambda url, **kw: crl_bytes(MAIN.root, MAIN.root_key, signer_key=_rsa_key()), ca_trust.DEFAULT_ALLOWED_HOSTS)
		with mock.patch.object(ca_trust, "_crl_urls", return_value=[self.CRL]):
			outcome = ca_trust._check_crl(cert, MAIN.root, NOW, network)
		self.assertIsNone(outcome)
		self.assertIn(("crl", "cca.gov.in", "unusable"), network.failures)

	def test_twin_is_attempted_after_http_failure_and_ocsp_is_not_upgraded(self):
		calls = []

		def fetch(url, **kw):
			calls.append((url, kw.get("data") is not None))
			raise TimeoutError()

		network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
		with mock.patch.object(ca_trust, "_crl_urls", return_value=[self.CRL]):
			self.assertIsNone(ca_trust._check_crl(MAIN.sub, MAIN.root, NOW, network))
		self.assertEqual([u for u, _ in calls], [self.CRL, self.CRL.replace("http://", "https://", 1)])
		self.assertEqual([f for _, _, f in network.failures], ["timeout", "timeout"])

	def test_ocsp_post_is_never_upgraded_even_on_a_cca_host(self):
		calls = []

		def fetch(url, **kw):
			calls.append((url, kw.get("data") is not None))
			raise TimeoutError()

		ocsp_url = "http://cca.gov.in/ocsp"
		network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
		with mock.patch.object(ca_trust, "_aia_urls", return_value=[ocsp_url]):
			self.assertIsNone(ca_trust._check_ocsp(MAIN.sub, MAIN.root, NOW, network))
		self.assertEqual(calls, [(ocsp_url, True)])  # one POST, no https twin

	def test_a_hostile_twin_target_is_never_fetched(self):
		called = []
		network = ca_trust._Network(lambda url, **kw: called.append(url), frozenset({"signxca.com"}))
		self.assertIsNone(network.get(self.CRL, max_bytes=10, source="crl"))
		self.assertEqual(called, [])
		self.assertEqual(network.failures, [("crl", "other", "refused")])

	def test_per_request_cap_and_failure_notes_are_bounded(self):
		seen = []
		clock = [1000.0]
		network = None

		def fetch(url, **kw):
			seen.append(kw["timeout"])
			raise ConnectionResetError()

		with mock.patch.object(ca_trust, "_monotonic", side_effect=lambda: clock[0]):
			network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
			for _ in range(20):
				network.get(self.CRL, max_bytes=10, source="crl")
		self.assertTrue(all(t <= ca_trust.PER_REQUEST_CAP for t in seen))
		self.assertEqual(len(network.failures), ca_trust.MAX_FAILURE_NOTES)
		self.assertEqual({f for _, _, f in network.failures}, {"reset"})

	def test_budget_never_resets_across_retries(self):
		clock = [1000.0]

		def fetch(url, **kw):
			clock[0] += kw["timeout"]
			raise TimeoutError()

		with mock.patch.object(ca_trust, "_monotonic", side_effect=lambda: clock[0]):
			network = ca_trust._Network(fetch, ca_trust.DEFAULT_ALLOWED_HOSTS)
			for _ in range(6):
				network.get(self.CRL, max_bytes=10, source="crl")
		self.assertLessEqual(clock[0] - 1000.0, ca_trust.TOTAL_BUDGET)
		self.assertIn("budget", [f for _, _, f in network.failures])

	def test_a_stalled_dns_lookup_is_stopped_at_its_slice(self):
		release = threading.Event()

		def resolver(*a, **kw):
			release.wait(5)
			return [(2, 1, 6, "", ("93.184.216.34", 80))]

		transport = ca_trust.HttpTransport(resolver=resolver, connector=lambda *a, **kw: self.fail("must not connect"))
		started = time.monotonic()
		with mock.patch.object(ca_trust, "RESOLVE_TIMEOUT", 0.2):
			with self.assertRaises(ca_trust.FetchRefused):
				transport("http://cca.gov.in/x", max_bytes=10, timeout=25)
		release.set()
		self.assertLess(time.monotonic() - started, 2.0)

	def test_stalled_lookups_cannot_accumulate_threads(self):
		release = threading.Event()
		started = []

		def resolver(*a, **kw):
			started.append(1)
			release.wait(5)
			return [(2, 1, 6, "", ("93.184.216.34", 80))]

		transport = ca_trust.HttpTransport(resolver=resolver, connector=lambda *a, **kw: self.fail("must not connect"))
		try:
			with mock.patch.object(ca_trust, "RESOLVE_TIMEOUT", 0.05):
				for _ in range(ca_trust.MAX_RESOLVER_THREADS + 6):
					with self.assertRaises(ca_trust.FetchRefused):
						transport("http://cca.gov.in/x", max_bytes=10, timeout=25)
			self.assertEqual(len(started), ca_trust.MAX_RESOLVER_THREADS)  # the rest were refused without a new thread
		finally:
			release.set()
			for _ in range(100):
				if ca_trust._RESOLVER_SLOTS.acquire(blocking=False):
					ca_trust._RESOLVER_SLOTS.release()
					if all(ca_trust._RESOLVER_SLOTS.acquire(blocking=False) for _ in range(ca_trust.MAX_RESOLVER_THREADS)):
						for _ in range(ca_trust.MAX_RESOLVER_THREADS):
							ca_trust._RESOLVER_SLOTS.release()
						break
				time.sleep(0.05)

	def test_refusal_carries_a_bounded_network_note_without_urls(self):
		leaf = MAIN.leaf()
		net = world(MAIN, leaf, with_ocsp=False)
		for url in [u for u in net.routes if not u.endswith(".cer")]:
			del net.routes[url]  # certificates still answer; every CRL is gone
		exc = self.assertRefused("REVOCATION_UNAVAILABLE", leaf, net)
		self.assertTrue(exc.detail)
		for source, host, failure in exc.detail:
			self.assertIn(source, {"aia", "ocsp", "crl"})
			self.assertTrue(host in ca_trust.DEFAULT_ALLOWED_HOSTS or host == "other")
			self.assertIn(failure, {"refused", "budget", "size", "timeout", "reset", "network", "error", "unusable"})


class _SegmentedSocket:
	"""A socket that, like a real one, delivers at most one TCP segment per recv and fails with EBADF when read after
	close(). Unlike _FakeSocket it models closing, which is what the "Connection: close" bug depended on."""

	def __init__(self, segments):
		self._segments = list(segments)
		self.closed = False
		self.sent = b""

	def settimeout(self, value):
		pass

	def sendall(self, data):
		if self.closed:
			raise OSError(9, "Bad file descriptor")
		self.sent += data

	def recv_into(self, buffer, nbytes=0):
		if self.closed:
			raise OSError(9, "Bad file descriptor")
		if not self._segments:
			return 0
		segment = self._segments[0]
		size = min(len(buffer), len(segment))
		buffer[:size] = segment[:size]
		if size == len(segment):
			self._segments.pop(0)
		else:
			self._segments[0] = segment[size:]
		return size

	def close(self):
		self.closed = True


class _FakeSocket:
	"""Serves ``response``. With a fake ``clock``, byte i arrives ``delay(i)`` s after the previous recv
	returned (one byte per recv when delayed); a recv whose timeout is shorter than that wait times out
	after the timeout, as a real socket does. ``makefile`` reads through the same recv_into."""

	def __init__(self, response, *, clock=None, delay=None):
		self._response = response
		self._pos = 0
		self._clock = clock
		self._delay = delay or (lambda index: 0.0)
		self._timeout = None
		self.sent = b""
		self.timeouts = []
		self.armed = []  # (clock, timeout) at every settimeout

	def sendall(self, data):
		self.sent += data

	def recv_into(self, buffer, nbytes=0):
		if self._pos >= len(self._response):
			return 0
		wait = self._delay(self._pos) if self._clock is not None else 0.0
		if wait > 0:
			if self._timeout is not None and self._timeout < wait:
				self._clock[0] += self._timeout
				raise socket.timeout("timed out")
			self._clock[0] += wait
			size = 1
		else:  # undelayed bytes come at once, but never past the next delayed byte
			size = 0
			limit = min(len(buffer), nbytes or len(buffer))
			while size < limit and self._pos + size < len(self._response):
				if self._clock is not None and self._delay(self._pos + size) > 0:
					break
				size += 1
		buffer[:size] = self._response[self._pos : self._pos + size]
		self._pos += size
		return size

	def makefile(self, mode, *args, **kwargs):
		sock = self

		class _Raw(io.RawIOBase):
			def readable(self):
				return True

			def readinto(self, b):
				return sock.recv_into(b)

		return io.BufferedReader(_Raw())

	def settimeout(self, value):
		self._timeout = value
		self.timeouts.append(value)
		self.armed.append((self._clock[0] if self._clock is not None else None, value))

	def close(self):
		pass


def _resolver(*ips):
	def resolve(host, port, *args, **kwargs):
		family = lambda ip: socket.AF_INET6 if ":" in ip else socket.AF_INET  # noqa: E731
		return [(family(ip), socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

	return resolve


class TransportTest(unittest.TestCase):
	"""Default transport, driven with a fake resolver and fake socket: no real network."""

	def transport(self, response, *ips):
		self.connects = []
		self.sock = _FakeSocket(response)

		def connector(address, timeout):
			self.connects.append((address, timeout))
			return self.sock

		return ca_trust.HttpTransport(resolver=_resolver(*(ips or ("93.184.216.34",))), connector=connector)

	def test_public_ip_200_returns_body_positive_control(self):
		body = b"\x30\x03\x02\x01\x00"
		t = self.transport(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + body)
		got = t("http://ocsp.signxca.com/x", data=b"REQ", content_type="application/ocsp-request", max_bytes=100, timeout=25)
		self.assertEqual(got, body)
		self.assertEqual(self.connects[0][0], ("93.184.216.34", 80))
		self.assertLessEqual(self.connects[0][1], ca_trust.CONNECT_TIMEOUT)
		self.assertTrue(self.sock.timeouts and max(self.sock.timeouts) <= ca_trust.READ_TIMEOUT)
		head, _, sent_body = self.sock.sent.partition(b"\r\n\r\n")
		self.assertEqual(sent_body, b"REQ")
		self.assertTrue(head.startswith(b"POST /x HTTP/1.1"))
		lowered = head.lower()
		for forbidden in (b"cookie", b"authorization", b"referer", b"x-frappe"):
			self.assertNotIn(forbidden, lowered)

	def test_slow_drip_cannot_outlast_the_budget(self):
		# Reviewer PoC: a server that sends one byte just inside each per-recv timeout kept a 1.0 s budget
		# busy for 4.9 s. Every recv (headers included) must be armed with the time left, not a fixed timeout.
		response = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n" + b"a" * 40
		header_length = response.index(b"\r\n\r\n") + 4
		for label, slow_from in (("status line and headers", 0), ("body", header_length)):
			with self.subTest(label):
				clock = [1000.0]
				sock = _FakeSocket(response, clock=clock, delay=lambda i, s=slow_from: 0.9 if i >= s else 0.0)
				t = ca_trust.HttpTransport(resolver=_resolver("93.184.216.34"), connector=lambda a, timeout: sock)
				with mock.patch.object(ca_trust, "_monotonic", side_effect=lambda: clock[0]):
					with self.assertRaises((ca_trust.FetchRefused, OSError)):
						t("http://signxca.com/x", max_bytes=100, timeout=1.0)
				self.assertLessEqual(clock[0] - 1000.0, 1.0 + 1e-6)
				deadline = 1001.0
				for at, value in sock.armed:
					self.assertLessEqual(value, deadline - at + 1e-6)

	def test_response_split_across_segments_is_read_after_connection_close_header(self):
		# Real servers answer "Connection: close" and send headers and body in separate TCP segments (and a CRL
		# in many). http.client closes the connection object as soon as the headers are read; the body must
		# still be readable. Found live 2026-11-10: every real CRL fetch and ~8% of OCSP fetches failed with
		# "[Errno 9] Bad file descriptor", so revocation was sporadically "unavailable".
		for label, body in (("small body in its own segment", b"x" * 1800), ("large CRL-size body", b"y" * 300000)):
			with self.subTest(label):
				head = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(body)
				segments = [head] + [body[i : i + 16384] for i in range(0, len(body), 16384)]
				sock = _SegmentedSocket(segments)
				t = ca_trust.HttpTransport(resolver=_resolver("93.184.216.34"), connector=lambda a, timeout: sock)
				self.assertEqual(t("http://signxca.com/x", max_bytes=400000, timeout=25), body)
				self.assertTrue(sock.closed)  # and the real socket IS closed when the transport is done

	def test_socket_is_closed_even_when_the_status_is_refused(self):
		sock = _SegmentedSocket([b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"])
		t = ca_trust.HttpTransport(resolver=_resolver("93.184.216.34"), connector=lambda a, timeout: sock)
		with self.assertRaises(ca_trust.FetchRefused):
			t("http://signxca.com/x", max_bytes=100, timeout=25)
		self.assertTrue(sock.closed)

	def test_fast_response_within_budget_still_passes_positive_control(self):
		clock = [1000.0]
		response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
		sock = _FakeSocket(response, clock=clock, delay=lambda i: 0.01)
		t = ca_trust.HttpTransport(resolver=_resolver("93.184.216.34"), connector=lambda a, timeout: sock)
		with mock.patch.object(ca_trust, "_monotonic", side_effect=lambda: clock[0]):
			self.assertEqual(t("http://signxca.com/x", max_bytes=100, timeout=25), b"abc")
		self.assertTrue(len(sock.armed) > 3)  # re-armed before every recv, not once

	def test_site_local_and_nat64_private_ipv6_are_not_public(self):
		for ip, public in (
			("fec0::1", False),  # site-local fec0::/10 (deprecated, still routable inside a site)
			("feff::1", False),
			("64:ff9b::7f00:1", False),  # NAT64 of 127.0.0.1
			("64:ff9b::a00:5", False),  # NAT64 of 10.0.0.5
			("64:ff9b:1::5db8:d822", False),  # local-use NAT64 prefix (RFC 8215)
			("64:ff9b::5db8:d822", False),  # every NAT64 form sits in reserved ::/8: refused (fail closed)
			("2606:4700:4700::1111", True),  # control
			("93.184.216.34", True),  # control
		):
			with self.subTest(ip=ip):
				self.assertIs(ca_trust._is_public_ip(ipaddress.ip_address(ip)), public)

	def test_non_public_resolution_refused_before_connect(self):
		for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.10", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "fec0::1", "64:ff9b::7f00:1"):
			with self.subTest(ip=ip):
				t = self.transport(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", ip)
				with self.assertRaises(ca_trust.FetchRefused):
					t("http://signxca.com/x", max_bytes=100, timeout=25)
				self.assertEqual(self.connects, [])

	def test_mixed_resolution_refused(self):
		t = self.transport(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "93.184.216.34", "127.0.0.1")
		with self.assertRaises(ca_trust.FetchRefused):
			t("http://signxca.com/x", max_bytes=100, timeout=25)
		self.assertEqual(self.connects, [])

	def test_redirect_never_followed(self):
		t = self.transport(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
		with self.assertRaises(ca_trust.FetchRefused):
			t("http://signxca.com/x", max_bytes=100, timeout=25)
		self.assertEqual(len(self.connects), 1)

	def test_oversize_refused(self):
		t = self.transport(b"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n" + b"a" * 101)
		with self.assertRaises(ca_trust.FetchRefused):
			t("http://signxca.com/x", max_bytes=100, timeout=25)
		t = self.transport(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"a" * 101)
		with self.assertRaises(ca_trust.FetchRefused):
			t("http://signxca.com/x", max_bytes=100, timeout=25)

	def test_bad_urls_refused_before_resolve(self):
		resolved = []

		def resolver(*args, **kwargs):
			resolved.append(args)
			return _resolver("93.184.216.34")(*args, **kwargs)

		t = ca_trust.HttpTransport(resolver=resolver, connector=lambda a, timeout: _FakeSocket(b""))
		for url in ("http://user:pw@signxca.com/x", "http://signxca.com:8080/x", "ftp://signxca.com/x", "file:///etc/passwd"):
			with self.subTest(url=url):
				with self.assertRaises(ca_trust.FetchRefused):
					t(url, max_bytes=100, timeout=25)
		self.assertEqual(resolved, [])

	def test_https_wraps_with_server_hostname(self):
		wrapped = []

		class Ctx:
			def wrap_socket(self, sock, server_hostname=None):
				wrapped.append(server_hostname)
				return sock

		sock = _FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		t = ca_trust.HttpTransport(
			resolver=_resolver("93.184.216.34"), connector=lambda a, timeout: sock, ssl_context=Ctx()
		)
		self.assertEqual(t("https://signxca.com/x", max_bytes=10, timeout=25), b"ok")
		self.assertEqual(wrapped, ["signxca.com"])


# ---------------------------------------------------------------- record, reasons, leakage


class RecordAndReasonTest(_Base):
	def test_reason_codes_are_a_closed_set(self):
		self.assertEqual(set(ca_trust.REASON_CODES), EXPECTED_REASONS)
		self.assertEqual(set(ca_trust.MESSAGES), EXPECTED_REASONS)
		self.assertEqual(ca_trust.MESSAGES["REVOCATION_UNAVAILABLE"], SPEC_REVOCATION_UNAVAILABLE)
		for code, message in ca_trust.MESSAGES.items():
			self.assertIn("not signed", message, code)
		# R2 HIGH: the profile refusal is about the signer certificate itself and no longer names any TLS field.
		profile = ca_trust.MESSAGES["CERTIFICATE_PROFILE"]
		self.assertIn("certifying-authority certificate, uses a weak algorithm or key, or carries a critical extension", profile)
		self.assertIn("Please contact support.", profile)
		for gone in ("subject alternative name", "client-authentication", "not trusted"):
			self.assertNotIn(gone, profile)
		self.assertIn("digital signatures", ca_trust.MESSAGES["KEY_USAGE"])
		with self.assertRaises(ValueError):
			ca_trust.CertificateNotAuthenticated("SOMETHING_ELSE")

	def test_record_has_exactly_the_allowlisted_keys(self):
		leaf = MAIN.leaf()
		record = self.assertPasses(leaf, world(MAIN, leaf))
		self.assertEqual(set(record), EXPECTED_RECORD_KEYS)
		self.assertEqual(set(ca_trust.RECORD_KEYS), EXPECTED_RECORD_KEYS)
		for entry in record["chain"]:
			self.assertEqual(set(entry), {"subject_cn", "sha256"})
		for entry in record["revocation"]:
			self.assertEqual(set(entry), {"subject_cn", "method", "status", "responder_host", "produced_at"})
		self.assertEqual(record["timestamp"], "none")
		self.assertEqual(record["signing_time_basis"], "server clock at verification")
		json.dumps(record)  # serialisable for the Long Text field

	def test_sentinel_from_failed_fetch_never_reaches_success_record(self):
		second = "http://ocsp.signxca.com/t-sub-backup"
		leaf = MAIN.leaf(aia_ocsp=[MAIN.u["leaf_ocsp"], second])
		net = world(MAIN, leaf, with_crl=False)
		net.routes[MAIN.u["leaf_ocsp"]] = RuntimeError(SENTINEL)
		net.routes[second] = ocsp_bytes(leaf, MAIN.sub, MAIN.sub_key)
		record = self.assertPasses(leaf, net)
		self.assertNotIn(SENTINEL, json.dumps(record))

	def _assert_no_leak(self, exc):
		text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
		for blob in (str(exc), repr(exc), repr(exc.args), repr(vars(exc)), text):
			self.assertNotIn(SENTINEL, blob)
		self.assertIsNone(exc.__cause__)
		self.assertTrue(exc.__suppress_context__)
		self.assertIn(exc.reason_code, EXPECTED_REASONS)

	def test_exception_text_never_leaks(self):
		leaf = MAIN.leaf()
		cases = [
			("aia fetch error", "CA_FETCH_FAILED", {MAIN.u["sub_cer"]: RuntimeError(SENTINEL)}, None),
			("aia garbage body", "CA_FETCH_FAILED", {MAIN.u["sub_cer"]: SENTINEL.encode()}, None),
			(
				"revocation errors",
				"REVOCATION_UNAVAILABLE",
				{MAIN.u["leaf_ocsp"]: ValueError(SENTINEL), MAIN.u["leaf_crl"]: ValueError(SENTINEL)},
				None,
			),
			(
				"path validator internal error",
				"NOT_CCA_TRUSTED",
				{},
				mock.patch.object(ca_trust, "_require_link", side_effect=ValueError(SENTINEL)),
			),
			(
				"unexpected internal error",
				"REVOCATION_UNAVAILABLE",
				{MAIN.u["leaf_ocsp"]: OSError("x")},
				mock.patch.object(ca_trust, "_check_crl", side_effect=KeyError(SENTINEL)),
			),
		]
		for label, code, routes, patcher in cases:
			with self.subTest(label):
				ca_trust.clear_cache()
				net = world(MAIN, leaf)
				net.routes.update(routes)
				if patcher is None:
					exc = self.assertRefused(code, leaf, net)
				else:
					with patcher:
						exc = self.assertRefused(code, leaf, net)
				self._assert_no_leak(exc)


# ---------------------------------------------------------------- gates


class GateTest(unittest.TestCase):
	def _imports(self, module):
		tree = ast.parse(open(module.__file__, encoding="utf-8").read())
		names = set()
		for node in ast.walk(tree):
			if isinstance(node, ast.Import):
				names.update(a.name for a in node.names)
			elif isinstance(node, ast.ImportFrom):
				names.add(node.module or "")
		return names

	def test_no_frappe_import(self):
		for module in (ca_trust, pinned_roots):
			with self.subTest(module.__name__):
				self.assertFalse([n for n in self._imports(module) if n.split(".")[0] == "frappe"])

	def test_no_os_or_certifi_trust_store_reference(self):
		for module in (ca_trust, pinned_roots):
			source = open(module.__file__, encoding="utf-8").read()
			for needle in ("certifi", "load_default_certs", "get_default_verify_paths", "set_default_verify_paths", "SSL_CERT_FILE", "truststore"):
				with self.subTest(module=module.__name__, needle=needle):
					self.assertIsNone(re.search(rf"\b{needle}\b", source))


# ---------------------------------------------------------------- pinned roots


class PinnedRootsTest(unittest.TestCase):
	def _source(self):
		with open(pinned_roots.__file__, encoding="utf-8") as fh:
			return fh.read()

	def _exec(self, source):
		namespace = {"__name__": "pinned_roots_probe", "__file__": pinned_roots.__file__}
		exec(compile(source, pinned_roots.__file__, "exec"), namespace)
		return namespace

	def test_pinned_roots_are_exactly_the_two_live_cca_india_roots(self):
		# cca.gov.in lists two roots that are valid today: CCA India 2022 and CCA India 2022 SPL (both to 2042).
		# The 2014 / 2015 SPL (expired 2024 / 2025) and older roots must NOT be pinned: they can validate nothing.
		self.assertEqual(pinned_roots.CCA_INDIA_2022_SHA256, CCA_ROOT_SHA256)
		self.assertEqual(pinned_roots.CCA_INDIA_2022_SPL_SHA256, CCA_SPL_ROOT_SHA256)
		self.assertEqual([sha(c) for c in pinned_roots.PINNED_ROOTS], [CCA_ROOT_SHA256, CCA_SPL_ROOT_SHA256])
		self.assertEqual(pinned_roots.PINNED_ROOT_SHA256, frozenset({CCA_ROOT_SHA256, CCA_SPL_ROOT_SHA256}))
		names = [r.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value for r in pinned_roots.PINNED_ROOTS]
		self.assertEqual(names, ["CCA India 2022", "CCA India 2022 SPL"])
		for root in pinned_roots.PINNED_ROOTS:
			self.assertEqual(root.subject, root.issuer)
			self.assertTrue(root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
			self.assertGreater(root.not_valid_after_utc.year, 2040)

	def test_untampered_source_imports_control(self):
		namespace = self._exec(self._source())
		self.assertEqual(namespace["PINNED_ROOT_SHA256"], frozenset({CCA_ROOT_SHA256, CCA_SPL_ROOT_SHA256}))

	def test_spl_root_tamper_fails_at_import(self):
		source = self._source()
		self.assertEqual(source.count(CCA_SPL_ROOT_SHA256), 1)
		for tampered in (source.replace(CCA_SPL_ROOT_SHA256, "0" * 64), source.replace("MIIFPDCC", "MIIFPDCD", 1)):
			self.assertNotEqual(tampered, source)
			with self.assertRaises(RuntimeError) as cm:
				self._exec(tampered)
			self.assertEqual(type(cm.exception).__name__, "PinnedRootError")
			self.assertIn("2022 SPL", str(cm.exception))

	def test_fingerprint_mismatch_fails_at_import(self):
		source = self._source()
		self.assertEqual(source.count(CCA_ROOT_SHA256), 1)
		for label, tampered in (
			("constant patched", source.replace(CCA_ROOT_SHA256, "0" * 64)),
			("embedded DER patched", source.replace("MII", "MIJ", 1)),
		):
			with self.subTest(label):
				self.assertNotEqual(tampered, source)
				with self.assertRaises(RuntimeError) as cm:
					self._exec(tampered)
				self.assertEqual(type(cm.exception).__name__, "PinnedRootError")


# ---------------------------------------------------------------- generated SignX-profile signer


def signer_world(chain, *, ocsp_status="good", with_ocsp=True, crl_revoked=None, leaf=None):
	"""FakeNet for the generated SignX-shaped chain: AIA served as SignX serves it, OCSP/CRL signed by the test keys.

	``leaf`` is a variant leaf issued by ``chain.sub`` (default ``chain.leaf``); its OCSP answer is for it.
	"""
	net = FakeNet()
	u = _test_pki.URLS
	net.routes[u["sub_cer"]] = base64.encodebytes(der(chain.sub))  # SignX serves AIA as base64 text
	net.routes[u["ca_cer"]] = der(chain.ca)
	net.routes[u["root_cer"]] = der(chain.root)
	if with_ocsp:
		net.routes[u["leaf_ocsp"]] = ocsp_bytes(leaf or chain.leaf, chain.sub, chain.sub_key, status=ocsp_status)
		net.routes[u["sub_ocsp"]] = ocsp_bytes(chain.sub, chain.ca, chain.ca_key)
		net.routes[u["ca_ocsp"]] = ocsp_bytes(chain.ca, chain.root, chain.root_key)
	if crl_revoked is not None:
		net.routes[u["leaf_crl"]] = crl_bytes(chain.sub, chain.sub_key, revoked=crl_revoked)
	return net


class SignerProfileChainTest(_Base):
	"""A generated leaf with a real SignX Class 3 Individual DSC's profile, end to end through the public API.

	Stands in for the owner's personal certificate, which is no longer committed. The generated root is pinned
	through ``roots=``; OCSP answers are genuine responses signed by the generated issuers (no stub).
	"""

	def setUp(self):
		super().setUp()
		self.chain = _test_pki.signer_chain()

	def test_generated_leaf_has_the_signx_class3_individual_profile(self):
		leaf = self.chain.leaf
		ext = leaf.extensions
		ku = ext.get_extension_for_class(x509.KeyUsage)
		self.assertTrue(ku.critical)
		self.assertTrue(ku.value.digital_signature and ku.value.content_commitment)
		self.assertFalse(ku.value.key_cert_sign or ku.value.key_encipherment)
		bc = ext.get_extension_for_class(x509.BasicConstraints)
		self.assertTrue(bc.critical)
		self.assertIs(bc.value.ca, False)
		self.assertEqual(list(ext.get_extension_for_class(x509.ExtendedKeyUsage).value), list(_test_pki.SIGNER_EKU))
		self.assertEqual(
			ext.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name),
			["test.signer@example.invalid"],
		)
		self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Test Signer")
		self.assertIsInstance(leaf.public_key(), rsa.RSAPublicKey)
		self.assertEqual(leaf.public_key().key_size, 2048)
		urls = (
			ca_trust._aia_urls(leaf, AuthorityInformationAccessOID.CA_ISSUERS)
			+ ca_trust._aia_urls(leaf, AuthorityInformationAccessOID.OCSP)
			+ ca_trust._crl_urls(leaf)
		)
		u = _test_pki.URLS
		self.assertEqual(urls, [u["sub_cer"], u["leaf_ocsp"], u["leaf_crl"]])
		self.assertTrue(all(ca_trust.url_allowed(url, ca_trust.DEFAULT_ALLOWED_HOSTS) for url in urls))

	def test_signer_profile_chain_passes_end_to_end(self):
		c = self.chain
		net = signer_world(c)
		record = self.assertPasses(c.leaf, net, roots=[c.root])
		self.assertEqual([e["sha256"] for e in record["chain"]], [sha(cert) for cert in c.path])
		self.assertEqual(record["chain"][0]["subject_cn"], "Test Signer")
		self.assertEqual(record["chain"][-1]["subject_cn"], "Test CCA Root")
		self.assertEqual(record["root_sha256"], sha(c.root))
		u = _test_pki.URLS
		# AIA walk leaf -> sub-CA -> CA, then one OCSP query per link in chain order (leaf, sub-CA, CA).
		self.assertEqual(net.urls(), [u["sub_cer"], u["ca_cer"], u["leaf_ocsp"], u["sub_ocsp"], u["ca_ocsp"]])
		self.assertEqual(
			[(r["method"], r["status"], r["responder_host"]) for r in record["revocation"]],
			[("ocsp", "good", "ocsp.signxca.com"), ("ocsp", "good", "ocsp.signxca.com"), ("ocsp", "good", "ocvs.gov.in")],
		)

	def test_signer_profile_negative_controls(self):
		c = self.chain
		u = _test_pki.URLS
		with self.subTest("expired the day after notAfter"):
			after = datetime.datetime(2028, 7, 21, tzinfo=UTC)
			self.assertRefused("EXPIRED_OR_NOT_YET_VALID", c.leaf, signer_world(c), roots=[c.root], now=after)
		with self.subTest("not yet valid the day before notBefore"):
			ca_trust.clear_cache()
			before = datetime.datetime(2026, 7, 19, tzinfo=UTC)
			self.assertRefused("EXPIRED_OR_NOT_YET_VALID", c.leaf, signer_world(c), roots=[c.root], now=before)
		with self.subTest("default pinned CCA India root: the generated root is not trusted"):
			ca_trust.clear_cache()
			net = signer_world(c)
			self.assertRefused("NOT_CCA_TRUSTED", c.leaf, net, roots=None)
			self.assertEqual(net.urls(), [u["sub_cer"], u["ca_cer"], u["root_cer"]])
		with self.subTest("another root pinned"):
			ca_trust.clear_cache()
			self.assertRefused("NOT_CCA_TRUSTED", c.leaf, signer_world(c), roots=[MAIN.root])
		with self.subTest("leaf revoked by OCSP"):
			ca_trust.clear_cache()
			self.assertRefused("REVOKED", c.leaf, signer_world(c, ocsp_status="revoked"), roots=[c.root])
		with self.subTest("leaf revoked by CRL, OCSP unreachable"):
			ca_trust.clear_cache()
			net = signer_world(c, with_ocsp=False, crl_revoked=[c.leaf.serial_number])
			self.assertRefused("REVOKED", c.leaf, net, roots=[c.root])
		with self.subTest("revocation unavailable"):
			ca_trust.clear_cache()
			net = signer_world(c, with_ocsp=False)
			self.assertRefused("REVOCATION_UNAVAILABLE", c.leaf, net, roots=[c.root])
			self.assertEqual(net.urls(), [u["sub_cer"], u["ca_cer"], u["leaf_ocsp"], u["leaf_crl"]])


# ---------------------------------------------------------------- path validator (R2 HIGH: replaces the TLS verifier)


class SigningPathValidatorTest(_Base):
	"""ca_trust._validate_path decides the path with a document-signing profile (spec 002 s9 item 18).

	Positive controls: SignX-shaped leaves without SAN / with any EKU / without keyUsage pass end to end.
	Negative controls: each check is exercised directly on an explicit chain (so a check cannot hide behind
	path building) and, for the main ones, end to end through the public API with AIA serving the bad CA.
	Every refusal is asserted with its reason code; the end-to-end ones also assert nothing was cached.
	"""

	def setUp(self):
		super().setUp()
		self.c = _test_pki.signer_chain()

	# -- builders: variants that reuse the chain's keys, so only the field under test differs

	def leaf(self, **kw):
		kw.setdefault("key", self.c.leaf_key)
		return _test_pki.make_signer_leaf(self.c.sub.subject, self.c.sub_key, **kw)[0]

	def sub_variant(self, **kw):
		"""The sub-CA again (same subject and key, so it issued every leaf above), with one field changed."""
		kw.setdefault("pathlen", 0)
		kw.setdefault("subject", self.c.sub.subject)
		kw.setdefault("locations", (_test_pki.URLS["ca_cer"], _test_pki.URLS["sub_ocsp"], _test_pki.URLS["sub_crl"]))
		issuer = kw.pop("issuer", self.c.ca)
		issuer_key = kw.pop("issuer_key", self.c.ca_key)
		return _test_pki.make_ca("unused", self.c.sub_key, issuer, issuer_key, **kw)

	def ca_variant(self, **kw):
		kw.setdefault("pathlen", 1)
		kw.setdefault("subject", self.c.ca.subject)
		return _test_pki.make_ca("unused", self.c.ca_key, self.c.root, self.c.root_key, **kw)

	def validate(self, chain, anchors=None, now=NOW):
		return ca_trust._validate_path(list(chain), tuple(anchors or [self.c.root]), now)

	def assertPathRefused(self, code, chain, **kw):
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			self.validate(chain, **kw)
		self.assertEqual(cm.exception.reason_code, code)

	def assertEndToEndRefused(self, code, leaf, net):
		self.assertRefused(code, leaf, net, roots=[self.c.root])
		self.assertEqual(ca_trust._INTERMEDIATE_CACHE, {})  # a refused path is never remembered

	def path(self, leaf=None, sub=None, ca=None):
		return [leaf or self.c.leaf, sub or self.c.sub, ca or self.c.ca, self.c.root]

	# -- positive controls

	def test_positive_control_todays_shape_and_minimal_shapes_validate(self):
		self.assertIsNone(self.validate(self.path()))
		for label, kw in (
			("no SAN", dict(san=False)),
			("EKU documentSigning only", dict(eku=(_test_pki.MS_DOCUMENT_SIGNING,))),
			("EKU Adobe PDF signing only", dict(eku=(_test_pki.ADOBE_PDF_SIGNING,))),
			("EKU emailProtection only", dict(eku=(EMAIL,))),
			("no EKU", dict(eku=None)),
			("no keyUsage (absent = unrestricted)", dict(key_usage=None)),
			("no basicConstraints", dict(basic_constraints=None)),
			("unknown NON-critical extension (ignored, RFC 5280 s4.2)", dict(extra_extensions=[(_test_pki.unknown_extension(), False)])),
		):
			with self.subTest(label):
				self.assertIsNone(self.validate(self.path(leaf=self.leaf(**kw))))

	def test_leaves_without_tls_fields_pass_end_to_end_with_revocation(self):
		u = _test_pki.URLS
		for label, kw in (
			("no SAN", dict(san=False)),
			("EKU documentSigning only", dict(eku=(_test_pki.MS_DOCUMENT_SIGNING,))),
			("EKU emailProtection only", dict(eku=(EMAIL,))),
			("no EKU", dict(eku=None)),
			("no keyUsage", dict(key_usage=None)),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				leaf = self.leaf(**kw)
				net = signer_world(self.c, leaf=leaf)
				record = self.assertPasses(leaf, net, roots=[self.c.root])
				self.assertEqual([e["sha256"] for e in record["chain"]], [sha(leaf), sha(self.c.sub), sha(self.c.ca), sha(self.c.root)])
				self.assertEqual(net.urls(), [u["sub_cer"], u["ca_cer"], u["leaf_ocsp"], u["sub_ocsp"], u["ca_ocsp"]])

	def test_ca_policy_extensions_that_cannot_change_the_verdict_are_accepted(self):
		with self.subTest("critical certificatePolicies"):
			sub = self.sub_variant(policies_critical=True)
			self.assertTrue(sub.extensions.get_extension_for_class(x509.CertificatePolicies).critical)
			self.assertIsNone(self.validate(self.path(sub=sub)))
		for label, extension in (
			("critical inhibitAnyPolicy", x509.InhibitAnyPolicy(0)),
			("critical policyConstraints inhibitPolicyMapping only", x509.PolicyConstraints(None, 0)),
		):
			with self.subTest(label):
				sub = self.sub_variant(extra_extensions=[(extension, True)])
				self.assertIsNone(self.validate(self.path(sub=sub)))

	def test_ca_without_key_usage_is_accepted_rfc5280_rule(self):
		# RFC 5280 s6.1.4(n): keyCertSign is checked only when keyUsage is present.
		self.assertIsNone(self.validate(self.path(sub=self.sub_variant(key_usage=None))))

	# -- leaf negative controls (refused before any download)

	def test_leaf_negative_controls_refused_before_any_fetch(self):
		weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
		cases = (
			("leaf cA=true", "CERTIFICATE_PROFILE", self.leaf(basic_constraints=(True, None))),
			("unknown critical extension", "CERTIFICATE_PROFILE", self.leaf(extra_extensions=[(_test_pki.unknown_extension(), True)])),
			(
				"critical nameConstraints in a leaf",
				"CERTIFICATE_PROFILE",
				self.leaf(extra_extensions=[(x509.NameConstraints([x509.RFC822Name("example.invalid")], None), True)]),
			),
			("requireExplicitPolicy", "CERTIFICATE_PROFILE", self.leaf(extra_extensions=[(x509.PolicyConstraints(0, None), True)])),
			("RSA-1024 leaf key", "CERTIFICATE_PROFILE", self.leaf(key=weak_rsa)),
			("EC P-192 leaf key", "CERTIFICATE_PROFILE", self.leaf(key=ec.generate_private_key(ec.SECP192R1()))),
			("Ed25519 leaf key", "CERTIFICATE_PROFILE", self.leaf(key=ed25519.Ed25519PrivateKey.generate())),
			("SHA-1 signed leaf", "CERTIFICATE_PROFILE", _test_pki.resign_with_weak_hash(self.c.leaf, self.c.sub_key, "sha1")),
			("MD5 signed leaf", "CERTIFICATE_PROFILE", _test_pki.resign_with_weak_hash(self.c.leaf, self.c.sub_key, "md5")),
			("keyEncipherment only", "KEY_USAGE", self.leaf(key_usage=("key_encipherment",))),
			("self-issued leaf", "NOT_CCA_TRUSTED", self.leaf(subject=self.c.sub.subject)),
		)
		for label, code, leaf in cases:
			with self.subTest(label):
				ca_trust.clear_cache()
				net = signer_world(self.c, leaf=leaf)
				self.assertEndToEndRefused(code, leaf, net)
				self.assertEqual(net.calls, [])
				self.assertPathRefused(code, self.path(leaf=leaf))

	def test_positive_control_strong_keys_and_hashes(self):
		self.assertIsNone(self.validate(self.path(leaf=self.leaf(key=ec.generate_private_key(ec.SECP256R1())))))
		self.assertIsNone(self.validate(self.path(leaf=self.leaf(key=ec.generate_private_key(ec.SECP384R1())))))
		for algorithm in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
			with self.subTest(algorithm.name):
				self.assertIsNone(self.validate(self.path(leaf=self.leaf(hash_algorithm=algorithm))))

	def test_algorithm_and_key_predicates(self):
		# The library also refuses SHA-1/MD5 link signatures, so these predicates are what proves our own rule.
		sha1 = _test_pki.resign_with_weak_hash(self.c.leaf, self.c.sub_key, "sha1")
		md5 = _test_pki.resign_with_weak_hash(self.c.leaf, self.c.sub_key, "md5")
		self.assertEqual(sha1.signature_hash_algorithm.name, "sha1")
		self.assertEqual(md5.signature_hash_algorithm.name, "md5")
		self.assertFalse(ca_trust._strong_signature(sha1))
		self.assertFalse(ca_trust._strong_signature(md5))
		self.assertTrue(ca_trust._strong_signature(self.c.leaf))
		self.assertFalse(ca_trust._strong_key(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()))
		self.assertFalse(ca_trust._strong_key(ec.generate_private_key(ec.SECP192R1()).public_key()))
		self.assertFalse(ca_trust._strong_key(ec.generate_private_key(ec.SECP256K1()).public_key()))
		self.assertTrue(ca_trust._strong_key(self.c.leaf_key.public_key()))
		self.assertTrue(ca_trust._strong_key(ec.generate_private_key(ec.SECP521R1()).public_key()))

	# -- CA negative controls

	def test_ca_negative_controls_on_an_explicit_chain(self):
		other_name = types.SimpleNamespace(subject=_test_pki._ca_name("Some Other CA", "Certifying Authority"))
		name_constraints = x509.NameConstraints([x509.RFC822Name("example.invalid")], None)
		cases = (
			("sub-CA without cA (end entity used as CA)", self.sub_variant(basic_constraints=(False, None))),
			("sub-CA without basicConstraints", self.sub_variant(basic_constraints=None)),
			("sub-CA keyUsage without keyCertSign", self.sub_variant(key_usage=("crl_sign", "digital_signature"))),
			("sub-CA signed by another key (tampered signature)", self.sub_variant(issuer_key=_test_pki.rsa_key())),
			("sub-CA issuer name differs from the CA's subject", self.sub_variant(issuer=other_name)),
			("sub-CA unknown critical extension", self.sub_variant(extra_extensions=[(_test_pki.unknown_extension(), True)])),
			("sub-CA critical nameConstraints (not implemented)", self.sub_variant(extra_extensions=[(name_constraints, True)])),
			("sub-CA non-critical nameConstraints (not ignored)", self.sub_variant(extra_extensions=[(name_constraints, False)])),
			("sub-CA requireExplicitPolicy (no policy tree)", self.sub_variant(extra_extensions=[(x509.PolicyConstraints(0, None), True)])),
			("sub-CA SHA-1 signature", _test_pki.resign_with_weak_hash(self.c.sub, self.c.ca_key, "sha1")),
			("sub-CA MD5 signature", _test_pki.resign_with_weak_hash(self.c.sub, self.c.ca_key, "md5")),
		)
		for label, sub in cases:
			with self.subTest(label):
				self.assertPathRefused("NOT_CCA_TRUSTED", self.path(sub=sub))
		with self.subTest("CA keyUsage without keyCertSign"):
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path(ca=self.ca_variant(key_usage=("crl_sign",))))
		with self.subTest("CA unknown critical extension"):
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path(ca=self.ca_variant(extra_extensions=[(_test_pki.unknown_extension(), True)])))

	def test_weak_ca_key_refused(self):
		weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
		weak_sub = _test_pki.make_ca("Weak Sub-CA", weak, self.c.ca, self.c.ca_key, pathlen=0, locations=(_test_pki.URLS["ca_cer"], _test_pki.URLS["sub_ocsp"], _test_pki.URLS["sub_crl"]))
		url = "https://signxca.com/test-pki/aia/WeakSub.cer"
		leaf = _test_pki.make_signer_leaf(weak_sub.subject, weak, key=self.c.leaf_key, ca_issuers=url)[0]
		self.assertPathRefused("NOT_CCA_TRUSTED", [leaf, weak_sub, self.c.ca, self.c.root])
		net = signer_world(self.c, leaf=leaf)
		net.routes[url] = der(weak_sub)
		self.assertEndToEndRefused("NOT_CCA_TRUSTED", leaf, net)
		self.assertIn(url, net.urls())

	def test_ca_negative_controls_end_to_end_through_aia(self):
		# The bad sub-CA is what the leaf's AIA address serves; it has the real sub-CA's key, so it did issue
		# the leaf and path building accepts it: only the validator stands between it and a signature.
		u = _test_pki.URLS
		for label, sub in (
			("sub-CA without cA", self.sub_variant(basic_constraints=(False, None))),
			("sub-CA keyUsage without keyCertSign", self.sub_variant(key_usage=("crl_sign",))),
			("sub-CA unknown critical extension", self.sub_variant(extra_extensions=[(_test_pki.unknown_extension(), True)])),
			("sub-CA critical nameConstraints", self.sub_variant(extra_extensions=[(x509.NameConstraints([x509.RFC822Name("example.invalid")], None), True)])),
		):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = signer_world(self.c)
				net.routes[u["sub_cer"]] = der(sub)
				self.assertEndToEndRefused("NOT_CCA_TRUSTED", self.c.leaf, net)
				self.assertEqual(net.urls(), [u["sub_cer"], u["ca_cer"]])  # refused before any revocation query
		with self.subTest("SHA-1 sub-CA: never accepted as the CA's child"):
			ca_trust.clear_cache()
			net = signer_world(self.c)
			net.routes[u["sub_cer"]] = der(_test_pki.resign_with_weak_hash(self.c.sub, self.c.ca_key, "sha1"))
			self.assertEndToEndRefused("CHAIN_INCOMPLETE", self.c.leaf, net)

	def test_path_length_constraints(self):
		key2 = _test_pki.rsa_key()
		sub2_url = "https://signxca.com/test-pki/aia/Sub2.cer"
		locations = (_test_pki.URLS["sub_cer"], _test_pki.URLS["sub_ocsp"], _test_pki.URLS["sub_crl"])
		sub2 = _test_pki.make_ca("Test Sub-sub-CA", key2, self.c.sub, self.c.sub_key, pathlen=None, locations=locations)
		leaf2 = _test_pki.make_signer_leaf(sub2.subject, key2, key=self.c.leaf_key, ca_issuers=sub2_url)[0]
		with self.subTest("sub-CA pathlen 0 with one CA below it"):
			self.assertPathRefused("NOT_CCA_TRUSTED", [leaf2, sub2, self.c.sub, self.c.ca, self.c.root])
		with self.subTest("same, end to end through AIA"):
			ca_trust.clear_cache()
			net = signer_world(self.c, leaf=leaf2)
			net.routes[sub2_url] = der(sub2)
			self.assertEndToEndRefused("NOT_CCA_TRUSTED", leaf2, net)
		ca_pl2 = self.ca_variant(pathlen=2)
		with self.subTest("positive control: sub-CA pathlen 1 under a CA with pathlen 2"):
			self.assertIsNone(self.validate([leaf2, sub2, self.sub_variant(pathlen=1, issuer=ca_pl2), ca_pl2, self.c.root]))
		with self.subTest("CA pathlen 1 with two CAs below it (sub-CA unconstrained)"):
			self.assertPathRefused("NOT_CCA_TRUSTED", [leaf2, sub2, self.sub_variant(pathlen=None), self.c.ca, self.c.root])
		with self.subTest("root pathlen 0 is respected too"):
			root_pl0 = _test_pki.make_ca("unused", self.c.root_key, None, None, pathlen=0, subject=self.c.root.subject, validity=_test_pki._VALIDITY["root"])
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path()[:-1] + [root_pl0], anchors=[root_pl0])

	def test_validity_of_every_ca_at_the_edges(self):
		# The leaf outlives the sub-CA on both sides, so only the sub-CA's own window decides at the edges.
		sub = self.c.sub
		not_after = sub.not_valid_after_utc
		not_before = sub.not_valid_before_utc
		leaf = self.leaf(not_before=not_before - DAY, not_after=not_after + DAY)
		self.assertIsNone(self.validate(self.path(leaf=leaf), now=not_after))  # inclusive, RFC 5280 s4.1.2.5
		self.assertIsNone(self.validate(self.path(leaf=leaf), now=not_before))
		second = datetime.timedelta(seconds=1)
		self.assertPathRefused("EXPIRED_OR_NOT_YET_VALID", self.path(leaf=leaf), now=not_after + second)
		self.assertPathRefused("EXPIRED_OR_NOT_YET_VALID", self.path(leaf=leaf), now=not_before - second)
		window = (NOW - 400 * DAY, NOW - DAY)
		for label, chain in (
			("expired sub-CA", self.path(sub=self.sub_variant(validity=window))),
			("expired CA", self.path(ca=self.ca_variant(validity=window))),
			("not-yet-valid sub-CA", self.path(sub=self.sub_variant(validity=(NOW + DAY, NOW + 400 * DAY)))),
		):
			with self.subTest(label):
				self.assertPathRefused("EXPIRED_OR_NOT_YET_VALID", chain)

	def test_root_must_be_a_pinned_root_by_der(self):
		with self.subTest("another hierarchy's root"):
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path()[:-1] + [ROGUE.root])
		with self.subTest("same name and key as the pinned root, different DER (re-issued, not pinned)"):
			reissued = _test_pki.make_ca("unused", self.c.root_key, None, None, subject=self.c.root.subject, validity=_test_pki._VALIDITY["root"])
			self.assertNotEqual(sha(reissued), sha(self.c.root))
			self.assertTrue(ca_trust._directly_issued(self.c.ca, reissued))
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path()[:-1] + [reissued])
		with self.subTest("pinned root presented as the signer certificate"):
			net = FakeNet()
			# Its keyUsage (keyCertSign, cRLSign) is checked first; it would also fail as self-issued and as cA.
			self.assertRefused("KEY_USAGE", self.c.root, net, roots=[self.c.root])
			self.assertEqual(net.calls, [])
			self.assertPathRefused("CHAIN_INCOMPLETE", [self.c.root, self.c.root])

	def test_loops_duplicates_and_depth(self):
		with self.subTest("a certificate repeated in the path"):
			self.assertPathRefused("CHAIN_INCOMPLETE", [self.c.leaf, self.c.sub, self.c.sub, self.c.ca, self.c.root])
		with self.subTest("leaf only, no anchor"):
			self.assertPathRefused("CHAIN_INCOMPLETE", [self.c.leaf])
		with self.subTest("deeper than MAX_INTERMEDIATES (all distinct, so only the depth cap refuses it first)"):
			middle = [self.sub_variant(pathlen=None) for _ in range(ca_trust.MAX_INTERMEDIATES + 1)]
			self.assertEqual(len({sha(c) for c in middle}), ca_trust.MAX_INTERMEDIATES + 1)
			self.assertPathRefused("CHAIN_INCOMPLETE", [self.c.leaf, *middle, self.c.root])
		with self.subTest("cross-signed loop through AIA stops"):
			key_a, key_b = _ec_key(), _ec_key()
			name_a, name_b = _name("Loop CA A"), _name("Loop CA B")
			url_a, url_b = "https://signxca.com/loop/a.cer", "https://signxca.com/loop/b.cer"
			ca_a = make_cert("Loop CA A", key_a, issuer=types.SimpleNamespace(subject=name_b), issuer_key=key_b, ca=True, ku="ca", eku=(), aia_ca=[url_b])
			ca_b = make_cert("Loop CA B", key_b, issuer=types.SimpleNamespace(subject=name_a), issuer_key=key_a, ca=True, ku="ca", eku=(), aia_ca=[url_a])
			leaf = make_cert("Loop Signer", _ec_key(), issuer=ca_a, issuer_key=key_a, aia_ca=[url_a])
			net = FakeNet()
			net.routes[url_a], net.routes[url_b] = der(ca_a), der(ca_b)
			self.assertRefused("CHAIN_INCOMPLETE", leaf, net)
			self.assertEqual(net.urls(), [url_a, url_b, url_a])

	def test_deep_aia_chain_stops_at_max_intermediates(self):
		keys = [_ec_key() for _ in range(ca_trust.MAX_INTERMEDIATES + 1)]
		urls = [f"https://signxca.com/deep/{i}.cer" for i in range(len(keys))]
		net = FakeNet()
		issuer, issuer_key, issuer_url = self.c.sub, self.c.sub_key, _test_pki.URLS["sub_cer"]
		for index in reversed(range(len(keys))):  # deep[0] is issued by deep[1] ... deep[last] by the sub-CA
			cert = make_cert(f"Deep CA {index}", keys[index], issuer=issuer, issuer_key=issuer_key, ca=True, ku="ca", eku=(), aia_ca=[issuer_url])
			net.routes[urls[index]] = der(cert)
			issuer, issuer_key, issuer_url = cert, keys[index], urls[index]
		leaf = make_cert("Deep Signer", _ec_key(), issuer=issuer, issuer_key=issuer_key, aia_ca=[issuer_url])
		self.assertRefused("CHAIN_INCOMPLETE", leaf, net, roots=[self.c.root])
		self.assertEqual(net.urls(), urls[: ca_trust.MAX_INTERMEDIATES])

	def test_malformed_certificates_fail_closed(self):
		def resign(tbs, key):
			from cryptography.hazmat.primitives.asymmetric import padding

			identifier = _test_pki._tlv(0x30, _test_pki._tlv(0x06, bytes.fromhex("2a864886f70d01010b")) + b"\x05\x00")
			signature = key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
			return x509.load_der_x509_certificate(_test_pki._tlv(0x30, tbs + identifier + _test_pki._tlv(0x03, b"\x00" + signature)))

		with self.subTest("duplicate extension (two SKIs) in the leaf: refused before any fetch"):
			ski = self.c.leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
			carrier = x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.99"), ski.public_bytes())
			tbs = self.leaf(extra_extensions=[(carrier, False)]).tbs_certificate_bytes
			self.assertEqual(tbs.count(bytes.fromhex("0603551d63")), 1)
			duplicate = resign(tbs.replace(bytes.fromhex("0603551d63"), bytes.fromhex("0603551d0e")), self.c.sub_key)
			net = FakeNet()
			self.assertRefused("NOT_CCA_TRUSTED", duplicate, net, roots=[self.c.root])
			self.assertEqual(net.calls, [])
		with self.subTest("TBS says sha1WithRSA, outer says sha256WithRSA"):
			tbs = self.c.leaf.tbs_certificate_bytes.replace(bytes.fromhex("2a864886f70d01010b"), bytes.fromhex("2a864886f70d010105"))
			mixed = resign(tbs, self.c.sub_key)
			self.assertEqual(mixed.signature_hash_algorithm.name, "sha256")
			self.assertPathRefused("NOT_CCA_TRUSTED", self.path(leaf=mixed))
		with self.subTest("version 1 leaf or CA (no extensions to constrain it)"):

			class _Version1:
				version = x509.Version.v1

				def __init__(self, cert):
					self._cert = cert

				def __getattr__(self, name):
					return getattr(self._cert, name)

			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._require_leaf_profile(_Version1(self.c.leaf))
			self.assertEqual(cm.exception.reason_code, "CERTIFICATE_PROFILE")
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._require_issuing_ca(_Version1(self.c.sub), 0)
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
			ca_trust._require_leaf_profile(self.c.leaf)  # positive controls: the same certificates as v3
			ca_trust._require_issuing_ca(self.c.sub, 0)

	def test_issuer_name_must_be_encoded_exactly_as_the_issuers_subject(self):
		# Compared as DER (RFC 5280 s4.1.2.4), never as text: the same attributes reordered, the same text in
		# another ASN.1 string type (x509.Name equality says "equal" there) and a case change all refuse. Each is
		# refused by our own name check alone too (signature check stubbed to "valid").
		attributes = list(self.c.sub.subject)
		reordered = x509.Name(list(reversed(attributes)))
		self.assertEqual(sorted(reordered.rfc4514_string().split(",")), sorted(self.c.sub.subject.rfc4514_string().split(",")))
		retyped = x509.Name(
			[x509.NameAttribute(a.oid, a.value, x509.name._ASN1Type.PrintableString) if a.oid != NameOID.COUNTRY_NAME else a for a in attributes]
		)
		self.assertEqual(retyped, self.c.sub.subject)  # x509.Name equality ignores the string type ...
		self.assertNotEqual(retyped.public_bytes(), self.c.sub.subject.public_bytes())  # ... the encoding does not
		recased = x509.Name([x509.NameAttribute(a.oid, a.value.upper()) if a.oid == NameOID.COMMON_NAME else a for a in attributes])
		for label, name in (("reordered", reordered), ("string type changed", retyped), ("case changed", recased)):
			leaf = _test_pki.make_signer_leaf(name, self.c.sub_key, key=self.c.leaf_key)[0]
			with self.subTest(label):
				self.assertPathRefused("NOT_CCA_TRUSTED", self.path(leaf=leaf))
			with self.subTest(label + ", signature check stubbed"), mock.patch.object(ca_trust, "_directly_issued", return_value=True):
				self.assertPathRefused("NOT_CCA_TRUSTED", self.path(leaf=leaf))
		with self.subTest("positive control: identical encoding, signature check stubbed"), mock.patch.object(
			ca_trust, "_directly_issued", return_value=True
		):
			self.assertIsNone(self.validate(self.path()))


# ---------------------------------------------------------------- CA key rollover (R2 iteration 4)

RO = {  # rollover test addresses, all on allowlisted hosts
	"root_cer": "http://www.cca.gov.in/test-pki/rollover/Root.cer",
	"x_cer": "https://signxca.com/test-pki/rollover/X.cer",
	"x_ocsp": "http://ocvs.gov.in/test-pki/rollover/X",
	"x_crl": "http://cca.gov.in/test-pki/rollover/X.crl",
	"s_cer": "https://signxca.com/test-pki/rollover/S.cer",
	"s_ocsp": "http://ocsp.signxca.com/test-pki/rollover/S",
	"s_crl": "https://signxca.com/test-pki/rollover/S.crl",
	"t_cer": "https://signxca.com/test-pki/rollover/T.cer",
	"t_ocsp": "http://ocsp.signxca.com/test-pki/rollover/T",
	"t_crl": "https://signxca.com/test-pki/rollover/T.crl",
	"leaf_ocsp": "http://ocsp.signxca.com/test-pki/rollover/leaf",
	"leaf_crl": "https://signxca.com/test-pki/rollover/leaf.crl",
}


class KeyRolloverTest(_Base):
	"""Self-issued intermediates (RFC 5280 s6.1): a CA's new-key certificate signed by its old key, same name.

	Root-level rollover: pinned root (old key) -> X (root's name, NEW key, signed by the old key) -> sub-CA S
	(issuer = root's name, signed by the NEW key) -> leaf. The leaf's AIA serves S, S's AIA serves X; X is
	directly signed by the pinned root. Sub-CA-level rollover: leaf -> S1 (sub-CA's name, new key, signed by the
	sub-CA's old key) -> sub-CA -> CA -> root. Self-issued intermediates do not count against pathLenConstraint
	(RFC 5280 s4.2.1.9, s6.1.4(l)) but do count against MAX_INTERMEDIATES (a hard bound).
	"""

	@classmethod
	def setUpClass(cls):
		cls.new_key = _test_pki.rsa_key()  # the root's (or sub-CA's) NEW key
		cls.t_key = _test_pki.rsa_key()

	def setUp(self):
		super().setUp()
		self.c = _test_pki.signer_chain()

	def root(self, pathlen=None):
		if pathlen is None:
			return self.c.root
		return _test_pki.make_ca(
			"unused", self.c.root_key, None, None, pathlen=pathlen, subject=self.c.root.subject, validity=_test_pki._VALIDITY["root"]
		)

	def rollover(self, *, root_pathlen=None, x_pathlen=None, s_pathlen=0, with_t=False, x_signer_key=None, **x_kw):
		"""(chain, keys): leaf -> [T ->] S -> X (self-issued) -> root; keys[i] signs what chain[i] issues."""
		c = self.c
		root = self.root(root_pathlen)
		x = _test_pki.make_ca(
			"unused", self.new_key, root, x_signer_key or c.root_key, pathlen=x_pathlen, subject=root.subject,
			validity=_test_pki._VALIDITY["ca"], locations=(RO["root_cer"], RO["x_ocsp"], RO["x_crl"]), **x_kw,
		)
		s = _test_pki.make_ca("Rollover Sub-CA", c.sub_key, x, self.new_key, pathlen=s_pathlen, locations=(RO["x_cer"], RO["s_ocsp"], RO["s_crl"]))
		chain, keys = [s, x, root], [c.sub_key, self.new_key, c.root_key]
		if with_t:
			t = _test_pki.make_ca("Rollover Sub-sub-CA", self.t_key, s, c.sub_key, pathlen=0, locations=(RO["s_cer"], RO["t_ocsp"], RO["t_crl"]))
			chain, keys = [t, *chain], [self.t_key, *keys]
		issuer_url = RO["t_cer"] if with_t else RO["s_cer"]
		leaf = _test_pki.make_signer_leaf(
			chain[0].subject, keys[0], key=c.leaf_key, ca_issuers=issuer_url, ocsp_url=RO["leaf_ocsp"], crl_url=RO["leaf_crl"]
		)[0]
		return [leaf, *chain], [c.leaf_key, *keys]

	def sub_rollover(self, *, with_t=False):
		"""leaf -> [T ->] S1 (self-issued: the sub-CA's name, new key, signed by the sub-CA's key) -> sub -> CA -> root."""
		c = self.c
		s1 = _test_pki.make_ca(
			"unused", self.new_key, c.sub, c.sub_key, pathlen=None, subject=c.sub.subject, locations=(_test_pki.URLS["sub_cer"], RO["s_ocsp"], RO["s_crl"])
		)
		chain, keys = [s1, c.sub, c.ca, c.root], [self.new_key, c.sub_key, c.ca_key, c.root_key]
		issuer_url = RO["s_cer"]
		if with_t:
			t = _test_pki.make_ca("Rollover Sub-sub-CA", self.t_key, s1, self.new_key, pathlen=0, locations=(RO["s_cer"], RO["t_ocsp"], RO["t_crl"]))
			chain, keys, issuer_url = [t, *chain], [self.t_key, *keys], RO["t_cer"]
		leaf = _test_pki.make_signer_leaf(
			chain[0].subject, keys[0], key=c.leaf_key, ca_issuers=issuer_url, ocsp_url=RO["leaf_ocsp"], crl_url=RO["leaf_crl"]
		)[0]
		return [leaf, *chain], [c.leaf_key, *keys]

	@staticmethod
	def world(chain, keys, *, with_ocsp=True, with_crl=True):
		"""AIA serves every issuer at the child's caIssuers URL; genuine OCSP and CRL answers for every non-root link."""
		net = FakeNet()
		for index in range(len(chain) - 1):
			child, issuer, issuer_key = chain[index], chain[index + 1], keys[index + 1]
			for url in ca_trust._aia_urls(child, AuthorityInformationAccessOID.CA_ISSUERS):
				net.routes[url] = base64.encodebytes(der(issuer))
			if with_ocsp:
				for url in ca_trust._aia_urls(child, AuthorityInformationAccessOID.OCSP):
					net.routes[url] = ocsp_bytes(child, issuer, issuer_key)
			if with_crl:
				for url in ca_trust._crl_urls(child):
					net.routes[url] = crl_bytes(issuer, issuer_key)
		return net

	def assertChainPasses(self, chain, keys, **kw):
		net = self.world(chain, keys, **kw)
		record = self.assertPasses(chain[0], net, roots=[chain[-1]])
		self.assertEqual([e["sha256"] for e in record["chain"]], [sha(cert) for cert in chain])
		self.assertEqual(len(record["revocation"]), len(chain) - 1)
		for url in (RO["root_cer"], _test_pki.URLS["root_cer"]):
			self.assertNotIn(url, net.urls())  # the pinned root is never downloaded
		return record, net

	def assertChainRefused(self, code, chain, keys, roots=None):
		net = self.world(chain, keys)
		self.assertRefused(code, chain[0], net, roots=roots or [chain[-1]])
		self.assertEqual(ca_trust._INTERMEDIATE_CACHE, {})
		return net

	# -- positive controls

	def test_root_key_rollover_passes_end_to_end_with_ocsp_and_with_crl(self):
		chain, keys = self.rollover()
		leaf, s, x, root = chain
		self.assertEqual(x.subject, x.issuer)  # self-issued ...
		self.assertFalse(ca_trust._directly_issued(x, x))  # ... but not self-signed: the OLD key signed the NEW key
		self.assertFalse(ca_trust._directly_issued(s, root))  # the pinned key did not sign the sub-CA
		record, net = self.assertChainPasses(chain, keys)
		self.assertEqual(net.urls(), [RO["s_cer"], RO["x_cer"], RO["leaf_ocsp"], RO["s_ocsp"], RO["x_ocsp"]])
		self.assertEqual([r["method"] for r in record["revocation"]], ["ocsp"] * 3)
		with self.subTest("CRL only"):
			ca_trust.clear_cache()
			record, net = self.assertChainPasses(chain, keys, with_ocsp=False)
			self.assertEqual([r["method"] for r in record["revocation"]], ["crl"] * 3)
		with self.subTest("verified rollover certificate is cached and reused"):
			net = self.world(chain, keys)
			self.assertPasses(leaf, net, roots=[root])
			self.assertNotIn(RO["x_cer"], net.urls())

	def test_sub_ca_key_rollover_passes_end_to_end(self):
		chain, keys = self.sub_rollover()
		self.assertEqual(chain[1].subject, chain[1].issuer)
		# the sub-CA's pathLenConstraint is 0 and S1 is below it: accepted only because S1 is self-issued
		self.assertEqual(chain[2].extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
		self.assertChainPasses(chain, keys)

	# -- pathLenConstraint: self-issued intermediates are not counted (both sides of each boundary)

	def test_path_length_boundaries_with_a_self_issued_intermediate(self):
		with self.subTest("root pathLen 1: S counted, X (self-issued) not -> accepted at the limit"):
			self.assertChainPasses(*self.rollover(root_pathlen=1))
		with self.subTest("root pathLen 0: S is one real intermediate too many -> refused"):
			ca_trust.clear_cache()
			self.assertChainRefused("NOT_CCA_TRUSTED", *self.rollover(root_pathlen=0))
		with self.subTest("root pathLen 1 with T below S: two real intermediates -> refused"):
			ca_trust.clear_cache()
			self.assertChainRefused("NOT_CCA_TRUSTED", *self.rollover(root_pathlen=1, s_pathlen=None, with_t=True))
		with self.subTest("root pathLen 2 with T below S -> accepted at the limit"):
			ca_trust.clear_cache()
			self.assertChainPasses(*self.rollover(root_pathlen=2, s_pathlen=None, with_t=True))
		with self.subTest("X pathLen 0: S below it -> refused"):
			ca_trust.clear_cache()
			self.assertChainRefused("NOT_CCA_TRUSTED", *self.rollover(x_pathlen=0))
		with self.subTest("X pathLen 1: S below it -> accepted"):
			ca_trust.clear_cache()
			self.assertChainPasses(*self.rollover(x_pathlen=1))
		with self.subTest("sub-CA pathLen 0 with self-issued S1 and a real T below -> refused"):
			ca_trust.clear_cache()
			self.assertChainRefused("NOT_CCA_TRUSTED", *self.sub_rollover(with_t=True))

	def test_path_length_counts_follow_rfc5280(self):
		chain, _ = self.rollover(root_pathlen=1)  # leaf, S, X, root
		self.assertEqual([ca_trust._self_issued(cert) for cert in chain], [False, False, True, True])
		self.assertEqual(ca_trust._real_intermediates_below(chain), [0, 1, 1])  # for S, X, root
		self.assertIsNone(ca_trust._validate_path(chain, (chain[-1],), NOW))
		chain, _ = self.sub_rollover(with_t=True)  # leaf, T, S1, sub (pathLen 0), CA (pathLen 1), root
		self.assertEqual([ca_trust._self_issued(cert) for cert in chain], [False, False, True, False, False, True])
		self.assertEqual(ca_trust._real_intermediates_below(chain), [0, 1, 1, 2, 3])
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._validate_path(chain, (chain[-1],), NOW)
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		chain, _ = self.sub_rollover()  # leaf, S1, sub (pathLen 0), CA (pathLen 1), root
		self.assertEqual(ca_trust._real_intermediates_below(chain), [0, 0, 1, 2])
		self.assertIsNone(ca_trust._validate_path(chain, (chain[-1],), NOW))

	# -- negative controls

	def test_self_issued_intermediate_signed_by_an_unrelated_key_is_refused(self):
		chain, keys = self.rollover(x_signer_key=_test_pki.rsa_key())
		self.assertFalse(ca_trust._directly_issued(chain[2], chain[3]))
		net = self.assertChainRefused("CHAIN_INCOMPLETE", chain, keys)  # X's AIA serves the root, which did not sign X
		self.assertEqual(net.urls(), [RO["s_cer"], RO["x_cer"], RO["root_cer"], RO["root_cer"].replace("http://", "https://", 1)])  # the CCA https twin follows an unusable http answer
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:  # the builder alone refuses the link
			ca_trust._build_path(chain[0], (chain[-1],), ca_trust._Network(self.world(chain, keys), ca_trust.DEFAULT_ALLOWED_HOSTS))
		self.assertEqual(cm.exception.reason_code, "CHAIN_INCOMPLETE")
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._validate_path(chain, (chain[-1],), NOW)
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")

	def test_self_signed_rogue_with_the_pinned_name_never_becomes_an_anchor(self):
		rogue_key = _test_pki.rsa_key()
		rogue = _test_pki.make_ca("unused", rogue_key, None, None, subject=self.c.root.subject, validity=_test_pki._VALIDITY["root"])
		self.assertEqual(rogue.subject, self.c.root.subject)
		self.assertTrue(ca_trust._directly_issued(rogue, rogue))
		s = _test_pki.make_ca("Rogue Sub-CA", self.c.sub_key, rogue, rogue_key, pathlen=0, locations=(RO["x_cer"], RO["s_ocsp"], RO["s_crl"]))
		leaf = _test_pki.make_signer_leaf(s.subject, self.c.sub_key, key=self.c.leaf_key, ca_issuers=RO["s_cer"], ocsp_url=RO["leaf_ocsp"])[0]
		chain, keys = [leaf, s, rogue], [self.c.leaf_key, self.c.sub_key, rogue_key]
		net = self.assertChainRefused("NOT_CCA_TRUSTED", chain, keys, roots=[self.c.root])
		self.assertEqual(net.urls(), [RO["s_cer"], RO["x_cer"]])  # fetched, refused, no revocation query
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._build_path(leaf, (self.c.root,), ca_trust._Network(self.world(chain, keys), ca_trust.DEFAULT_ALLOWED_HOSTS))
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._validate_path(chain, (self.c.root,), NOW)
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")

	def test_self_issued_leaf_is_still_refused(self):
		leaf = _test_pki.make_signer_leaf(self.c.root.subject, self.new_key, key=self.c.leaf_key, subject=self.c.root.subject, ca_issuers=RO["x_cer"])[0]
		self.assertEqual(leaf.subject, leaf.issuer)
		net = FakeNet()
		self.assertRefused("NOT_CCA_TRUSTED", leaf, net, roots=[self.c.root])
		self.assertEqual(net.calls, [])

	def test_self_issued_intermediate_must_be_a_ca_that_signs_certificates(self):
		for label, kw in (("keyUsage without keyCertSign", dict(key_usage=("crl_sign",))), ("cA=false", dict(basic_constraints=(False, None)))):
			with self.subTest(label):
				ca_trust.clear_cache()
				net = self.assertChainRefused("NOT_CCA_TRUSTED", *self.rollover(**kw))
				self.assertEqual(net.urls(), [RO["s_cer"], RO["x_cer"]])

	def test_self_signed_certificate_is_never_an_intermediate_link(self):
		# A re-issued copy of the pinned root (same name, same key, other DER) placed between the CA and the root:
		# every signature in the chain verifies, yet a self-signed certificate is a root, not a link.
		c = self.c
		reissued = _test_pki.make_ca("unused", c.root_key, None, None, subject=c.root.subject, validity=_test_pki._VALIDITY["root"])
		self.assertTrue(ca_trust._directly_issued(reissued, c.root) and ca_trust._directly_issued(c.ca, reissued))
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._validate_path([c.leaf, c.sub, c.ca, reissued, c.root], (c.root,), NOW)
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		self.assertIsNone(ca_trust._validate_path([c.leaf, c.sub, c.ca, c.root], (c.root,), NOW))  # positive control

	def stuffed(self, count):
		"""(chain, keys, x_urls): root -> X1..Xcount (all self-issued, each signed by the previous key) -> S -> leaf."""
		c = self.c
		issuer, issuer_key, issuer_url = c.root, c.root_key, RO["root_cer"]
		xs, keys, urls = [], [], []
		for index in range(1, count + 1):
			key, url = _ec_key(), f"https://signxca.com/test-pki/rollover/X{index}.cer"
			locations = (issuer_url, f"http://ocvs.gov.in/test-pki/rollover/X{index}", f"http://cca.gov.in/test-pki/rollover/X{index}.crl")
			xs.append(_test_pki.make_ca("unused", key, issuer, issuer_key, subject=c.root.subject, locations=locations))
			keys.append(key)
			urls.append(url)
			issuer, issuer_key, issuer_url = xs[-1], key, url
		s = _test_pki.make_ca("Stuffed Sub-CA", c.sub_key, issuer, issuer_key, pathlen=0, locations=(issuer_url, RO["s_ocsp"], RO["s_crl"]))
		leaf = _test_pki.make_signer_leaf(s.subject, c.sub_key, key=c.leaf_key, ca_issuers=RO["s_cer"], ocsp_url=RO["leaf_ocsp"], crl_url=RO["leaf_crl"])[0]
		return [leaf, s, *reversed(xs), c.root], [c.leaf_key, c.sub_key, *reversed(keys), c.root_key], urls

	def test_rollover_stuffing_is_bounded_by_the_depth_cap(self):
		with self.subTest("positive control: 3 self-issued + S = MAX_INTERMEDIATES intermediates passes end to end"):
			chain, keys, _ = self.stuffed(ca_trust.MAX_INTERMEDIATES - 1)
			self.assertChainPasses(chain, keys)
		for count in (ca_trust.MAX_INTERMEDIATES, ca_trust.MAX_INTERMEDIATES + 1):
			with self.subTest(f"{count} self-issued + S: over the cap even though pathLen ignores self-issued"):
				ca_trust.clear_cache()
				chain, keys, urls = self.stuffed(count)
				net = self.world(chain, keys)
				self.assertRefused("CHAIN_INCOMPLETE", chain[0], net, roots=[chain[-1]])
				# exactly MAX_INTERMEDIATES downloads, then the walk stops (a hard bound on fetches too)
				self.assertEqual(net.urls(), [RO["s_cer"], *list(reversed(urls))[: ca_trust.MAX_INTERMEDIATES - 1]])
				with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
					ca_trust._validate_path(chain, (chain[-1],), NOW)
				self.assertEqual(cm.exception.reason_code, "CHAIN_INCOMPLETE")

	def test_two_self_issued_certificates_signing_each_other_stop(self):
		c = self.c
		key_a, key_b = _ec_key(), _ec_key()
		url_a, url_b = "https://signxca.com/test-pki/rollover/A.cer", "https://signxca.com/test-pki/rollover/B.cer"
		name = types.SimpleNamespace(subject=c.root.subject)
		a = _test_pki.make_ca("unused", key_a, name, key_b, subject=c.root.subject, locations=(url_b, RO["x_ocsp"], RO["x_crl"]))
		b = _test_pki.make_ca("unused", key_b, name, key_a, subject=c.root.subject, locations=(url_a, RO["x_ocsp"], RO["x_crl"]))
		s = _test_pki.make_ca("Loop Sub-CA", c.sub_key, name, key_a, pathlen=0, locations=(url_a, RO["s_ocsp"], RO["s_crl"]))
		leaf = _test_pki.make_signer_leaf(s.subject, c.sub_key, key=c.leaf_key, ca_issuers=RO["s_cer"])[0]
		net = FakeNet()
		net.routes.update({RO["s_cer"]: der(s), url_a: der(a), url_b: der(b)})
		self.assertRefused("CHAIN_INCOMPLETE", leaf, net, roots=[c.root])
		self.assertEqual(net.urls(), [RO["s_cer"], url_a, url_b, url_a])

	def test_issuer_name_encoding_tricks_on_the_rollover_link(self):
		# X claims the pinned name as issuer, re-encoded as PrintableString, and IS signed by the pinned key:
		# x509.Name equality would match, the DER does not, so X is neither anchored nor self-issued.
		c = self.c
		retyped = x509.Name(
			[x509.NameAttribute(a.oid, a.value, x509.name._ASN1Type.PrintableString) if a.oid != NameOID.COUNTRY_NAME else a for a in c.root.subject]
		)
		self.assertEqual(retyped, c.root.subject)
		self.assertNotEqual(retyped.public_bytes(), c.root.subject.public_bytes())
		x = _test_pki.make_ca(
			"unused", self.new_key, types.SimpleNamespace(subject=retyped), c.root_key, subject=c.root.subject,
			validity=_test_pki._VALIDITY["ca"], locations=(RO["root_cer"], RO["x_ocsp"], RO["x_crl"]),
		)
		self.assertFalse(ca_trust._self_issued(x))
		chain, keys = self.rollover()
		chain[2] = x
		net = self.assertChainRefused("CHAIN_INCOMPLETE", chain, keys)
		self.assertEqual(net.urls(), [RO["s_cer"], RO["x_cer"], RO["root_cer"], RO["root_cer"].replace("http://", "https://", 1)])  # the CCA https twin follows an unusable http answer
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust._validate_path(chain, (c.root,), NOW)
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")


# ---------------------------------------------------------------- real CCA India chain (public certificates only)


def _fixture(name):
	with open(os.path.join(FIXTURES, name), "rb") as fh:
		return fh.read()


class RealCCAChainTest(_Base):
	"""The real pinned CCA India 2022 root and the real SignX intermediates (public, institutional certificates).

	No real end-entity certificate is committed, and none can be generated under the real SignX sub-CA. The path
	validator (ca_trust._validate_path) runs over the real sub-CA -> real CA -> pinned root with a generated leaf
	whose single link to the real sub-CA is stubbed; every other check (CA flags, pathlen, keyCertSign, critical
	extensions, algorithms, key sizes, validity, the real signatures, the pinned root) runs on the real
	certificates. Also proven: AIA path building from the real sub-CA up to the pinned root, the real AIA/OCSP/CRL
	URLs against the default allowlist, and that a leaf or sub-CA forged under a real SignX name is refused
	through the public API with the default (pinned) roots.
	"""

	LEAF_AIA = "https://signxca.com/repository/aia/SignXClass3Individual.cer"
	LEAF_OCSP = "http://ocsp.signxca.com/SignXClass3Individual"
	LEAF_CRL = "https://signxca.com/repository/crl/SignXClass3Individual.crl"
	SUB_AIA = "https://signxca.com/repository/aia/SignXRootCA2022.cer"
	SUB_OCSP = "http://ocsp.signxca.com/SignXRootCA2022"
	SUB_CRL = "https://signxca.com/repository/crl/SignXRootCA2022.crl"
	ROOT_AIA = "http://www.cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer"
	CA_OCSP = "http://ocvs.gov.in"
	CA_CRL = "http://cca.gov.in/rw/resources/CCAIndia2022Latest.crl"

	def setUp(self):
		super().setUp()
		self.sub_der = _fixture("signx_sub_ca_class3_individual_2022.der")
		self.ca_der = _fixture("signx_ca_2022.der")
		self.assertEqual(hashlib.sha256(self.sub_der).hexdigest(), SIGNX_SUB_SHA256)
		self.assertEqual(hashlib.sha256(self.ca_der).hexdigest(), SIGNX_CA_SHA256)
		self.sub = x509.load_der_x509_certificate(self.sub_der)
		self.ca = x509.load_der_x509_certificate(self.ca_der)
		self.root = pinned_roots.PINNED_ROOTS[0]

	def net(self):
		net = FakeNet()
		net.routes[self.LEAF_AIA] = base64.encodebytes(self.sub_der)  # SignX serves AIA as base64 text
		net.routes[self.SUB_AIA] = self.ca_der
		return net

	@staticmethod
	def network(net):
		return ca_trust._Network(net, ca_trust.DEFAULT_ALLOWED_HOSTS)

	def test_real_signx_intermediates_chain_to_the_pinned_cca_india_root(self):
		net = self.net()
		path, anchor = ca_trust._build_path(self.sub, tuple(pinned_roots.PINNED_ROOTS), self.network(net))
		self.assertEqual([sha(cert) for cert in path], [SIGNX_CA_SHA256])
		self.assertEqual(sha(anchor), CCA_ROOT_SHA256)
		self.assertEqual(ca_trust._common_name(anchor), "CCA India 2022")
		self.assertEqual(net.urls(), [self.SUB_AIA])
		# each real link is signed by its real issuer's key, and by nothing else
		self.assertTrue(ca_trust._directly_issued(self.sub, self.ca))
		self.assertTrue(ca_trust._directly_issued(self.ca, self.root))
		self.assertFalse(ca_trust._directly_issued(self.sub, self.root))
		self.assertFalse(ca_trust._directly_issued(self.ca, self.sub))
		for cert in (self.sub, self.ca, self.root):
			ca_trust._require_valid_at(cert, NOW)
		# the real AIA bodies parse in the encodings the real servers use
		self.assertEqual(sha(ca_trust._parse_fetched_certificate(base64.encodebytes(self.sub_der))), SIGNX_SUB_SHA256)
		self.assertEqual(sha(ca_trust._parse_fetched_certificate(self.ca_der)), SIGNX_CA_SHA256)

	def test_real_intermediates_revocation_endpoints_are_allowlisted_and_queried_in_order(self):
		urls = [
			url
			for cert in (self.sub, self.ca)
			for url in (
				ca_trust._aia_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)
				+ ca_trust._aia_urls(cert, AuthorityInformationAccessOID.OCSP)
				+ ca_trust._crl_urls(cert)
			)
		]
		self.assertEqual(urls, [self.SUB_AIA, self.SUB_OCSP, self.SUB_CRL, self.ROOT_AIA, self.CA_OCSP, self.CA_CRL])
		self.assertTrue(all(ca_trust.url_allowed(url, ca_trust.DEFAULT_ALLOWED_HOSTS) for url in urls))
		# Nothing answers (no real responder key is available): the real OCSP then CRL endpoints of each real link
		# are queried through the URL policy, and the link is refused as unconfirmed.
		links = (
			(self.sub, self.ca, [self.SUB_OCSP, self.SUB_CRL]),
			(self.ca, self.root, [self.CA_OCSP, self.CA_CRL, self.CA_CRL.replace("http://", "https://", 1)]),
		)
		for cert, issuer, expected in links:
			with self.subTest(sha(cert)):
				net = FakeNet()
				with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
					ca_trust._revocation_status(cert, issuer, NOW, self.network(net))
				self.assertEqual(cm.exception.reason_code, "REVOCATION_UNAVAILABLE")
				self.assertEqual(net.urls(), expected)
				self.assertEqual(net.calls[0]["content_type"], "application/ocsp-request")

	def test_real_chain_negative_controls(self):
		with self.subTest("real sub-CA expired / not yet valid"):
			for when in (datetime.datetime(2032, 8, 27, tzinfo=UTC), datetime.datetime(2022, 8, 29, tzinfo=UTC)):
				with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
					ca_trust._require_valid_at(self.sub, when)
				self.assertEqual(cm.exception.reason_code, "EXPIRED_OR_NOT_YET_VALID")
		with self.subTest("another root pinned: the real CCA root fetched over AIA is self-issued but not pinned"):
			net = self.net()
			net.routes[self.ROOT_AIA] = der(self.root)
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._build_path(self.sub, (MAIN.root,), self.network(net))
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
			self.assertEqual(net.urls(), [self.SUB_AIA, self.ROOT_AIA])

	def _stub_leaf_link(self, *stubbed):
		"""Patch _directly_issued so ONLY the given (child, issuer) pairs are taken as signed; all others are real."""
		real = ca_trust._directly_issued
		checked = []
		pairs = {(sha(child), sha(issuer)) for child, issuer in stubbed}

		def directly_issued(cert, issuer):
			if (sha(cert), sha(issuer)) in pairs:
				return True
			checked.append((sha(cert), sha(issuer)))
			return real(cert, issuer)

		return mock.patch.object(ca_trust, "_directly_issued", side_effect=directly_issued), checked

	def test_real_signx_chain_passes_the_path_validator_with_only_the_leaf_link_stubbed(self):
		leaf, _ = _test_pki.make_signer_leaf(self.sub.subject, _test_pki.rsa_key(), san=False, eku=None)
		chain = [leaf, self.sub, self.ca, self.root]
		patcher, checked = self._stub_leaf_link((leaf, self.sub))
		with patcher:
			self.assertIsNone(ca_trust._validate_path(chain, tuple(pinned_roots.PINNED_ROOTS), NOW))
		# both real links were verified by the real signature check, not by the stub
		self.assertEqual(checked, [(SIGNX_SUB_SHA256, SIGNX_CA_SHA256), (SIGNX_CA_SHA256, CCA_ROOT_SHA256)])
		with self.subTest("without the stub the generated leaf is refused: the real sub-CA did not sign it"):
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._validate_path(chain, tuple(pinned_roots.PINNED_ROOTS), NOW)
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		with self.subTest("the SPL root is pinned but did not issue the real SignX CA"):
			with patcher, self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._validate_path(chain[:-1] + [pinned_roots.PINNED_ROOTS[1]], tuple(pinned_roots.PINNED_ROOTS), NOW)
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		with self.subTest("the real sub-CA's pathlen 0 refuses one more CA below it"):
			key = _test_pki.rsa_key()
			extra = _test_pki.make_ca("Generated Sub-sub-CA", key, self.sub, _test_pki.rsa_key())
			leaf2, _ = _test_pki.make_signer_leaf(extra.subject, key)
			patcher2, _ = self._stub_leaf_link((extra, self.sub))
			with patcher2, self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._validate_path([leaf2, extra, self.sub, self.ca, self.root], tuple(pinned_roots.PINNED_ROOTS), NOW)
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		with self.subTest("the real sub-CA after its notAfter (the leaf outlives it)"):
			long_leaf, _ = _test_pki.make_signer_leaf(
				self.sub.subject, _test_pki.rsa_key(), not_after=datetime.datetime(2034, 1, 1, tzinfo=UTC)
			)
			long_patcher, _ = self._stub_leaf_link((long_leaf, self.sub))
			with long_patcher, self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust._validate_path(
					[long_leaf, self.sub, self.ca, self.root], tuple(pinned_roots.PINNED_ROOTS), datetime.datetime(2032, 8, 26, 9, tzinfo=UTC)
				)
			self.assertEqual(cm.exception.reason_code, "EXPIRED_OR_NOT_YET_VALID")

	def test_real_certificates_meet_the_ca_profile_on_their_own(self):
		# Each real CA passes the CA checks with the number of CAs it really has below it in a SignX path.
		for cert, below in ((self.sub, 0), (self.ca, 1), (self.root, 2), (pinned_roots.PINNED_ROOTS[1], 2)):
			with self.subTest(ca_trust._common_name(cert)):
				ca_trust._require_issuing_ca(cert, below)
		with self.assertRaises(ca_trust.CertificateNotAuthenticated):
			ca_trust._require_issuing_ca(self.sub, 1)  # pathlen 0
		ca_trust._require_link(self.sub, self.ca)
		ca_trust._require_link(self.ca, self.root)
		with self.assertRaises(ca_trust.CertificateNotAuthenticated):
			ca_trust._require_link(self.ca, pinned_roots.PINNED_ROOTS[1])

	def test_leaf_claiming_the_real_signx_sub_ca_is_refused_with_the_pinned_roots(self):
		leaf, _ = _test_pki.make_signer_leaf(
			self.sub.subject, _test_pki.rsa_key(), ca_issuers=self.LEAF_AIA, ocsp_url=self.LEAF_OCSP, crl_url=self.LEAF_CRL
		)
		net = self.net()
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust.authenticate_certificate(der(leaf), now=NOW, fetch=net)  # default = pinned CCA root
		# CHAIN_INCOMPLETE: the real base64 AIA answer parsed, but the real sub-CA did not sign this leaf
		# (an unparseable answer would be CA_FETCH_FAILED).
		self.assertEqual(cm.exception.reason_code, "CHAIN_INCOMPLETE")
		self.assertEqual(net.urls(), [self.LEAF_AIA])

	def test_sub_ca_forged_under_the_real_signx_ca_name_is_refused_with_the_pinned_roots(self):
		forged_key = _test_pki.rsa_key()
		forged_sub = make_cert(
			"forged",
			forged_key,
			subject=self.sub.subject,
			issuer=self.ca,
			issuer_key=_test_pki.rsa_key(),
			ca=True,
			pathlen=0,
			ku="ca",
			eku=(),
			aia_ca=[self.SUB_AIA],
		)
		forged_url = "https://signxca.com/test-pki/forged/sub.cer"
		leaf, _ = _test_pki.make_signer_leaf(forged_sub.subject, forged_key, ca_issuers=forged_url)
		net = self.net()
		net.routes[forged_url] = der(forged_sub)
		with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
			ca_trust.authenticate_certificate(der(leaf), now=NOW, fetch=net)
		self.assertEqual(cm.exception.reason_code, "CHAIN_INCOMPLETE")  # the real SignX CA did not sign it
		self.assertEqual(net.urls(), [forged_url, self.SUB_AIA])


if __name__ == "__main__":
	unittest.main()
