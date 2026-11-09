"""F2 slice 1: authenticate a DSC against the pinned CCA India hierarchy (spec 002 s2, s3, s5, s6).

Pure unittest. No frappe, no site, and NO live network: every fetch goes to a FakeNet test double,
and the default HTTP transport is exercised only with a fake resolver and a fake socket.
A generated test PKI (pinned through the explicit ``roots=`` argument) covers every negative case;
one test uses the real CCA India 2022 root, the real SignX intermediates and the owner's real leaf
(public certificates in tests/fixtures/) with OCSP stubbed.
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
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import VerificationError

from erp_dsc_signer.utils import ca_trust, pinned_roots

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
DAY = datetime.timedelta(days=1)
MINUTE = datetime.timedelta(minutes=1)
SENTINEL = "S3NT1NEL-PIN-4417"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

CCA_ROOT_SHA256 = "9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8"
SIGNX_CA_SHA256 = "a8d6363afeb8fe0fc8b627022954d5681872ea4d998e59b3d8395abcc3953452"
SIGNX_SUB_SHA256 = "d29b3587cd540c45fdb29b416c73eec4c7311f721d037f16013a96ce55d4f824"
OWNER_LEAF_SHA256 = "96cd11ced957520f876a4552cb739d22e5a01de4bd6949065834ae8bca17b76c"

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
		self.assertNotIn(fake.u["root_cer"], net.urls())

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

	def test_store_holds_only_the_given_roots(self):
		seen = []
		real_store = ca_trust.Store

		def spy(certs):
			seen.append(list(certs))
			return real_store(certs)

		leaf = MAIN.leaf()
		with mock.patch.object(ca_trust, "Store", side_effect=spy):
			self.assertPasses(leaf, world(MAIN, leaf))
		self.assertEqual(len(seen), 1)
		self.assertEqual([sha(c) for c in seen[0]], [sha(MAIN.root)])

	def test_default_roots_are_the_pinned_roots(self):
		seen = []
		real_store = ca_trust.Store

		def spy(certs):
			seen.append([sha(c) for c in certs])
			return real_store(certs)

		leaf = MAIN.leaf()
		with mock.patch.object(ca_trust, "Store", side_effect=spy):
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(der(leaf), now=NOW, fetch=world(MAIN, leaf))
		self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		self.assertTrue(all(s == [CCA_ROOT_SHA256] for s in seen))

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

	def test_leaf_eku_without_client_auth_is_a_profile_refusal_before_any_fetch(self):
		# cryptography 44's client verifier needs clientAuth when an EKU is present: that is a verifier
		# requirement, not a usage or trust problem, so it gets its own honest reason (finding 2).
		leaf = MAIN.leaf(eku=(EMAIL,))
		net = world(MAIN, leaf)
		self.assertRefused("CERTIFICATE_PROFILE", leaf, net)
		self.assertEqual(net.calls, [])

	def test_leaf_without_san_is_a_profile_refusal_not_untrusted(self):
		leaf = MAIN.leaf(san=False)
		net = world(MAIN, leaf)
		self.assertRefused("CERTIFICATE_PROFILE", leaf, net)
		self.assertEqual(net.calls, [])

	def test_real_key_usage_problem_is_still_key_usage_even_with_a_profile_gap(self):
		leaf = MAIN.leaf(ku="encipher", san=False, eku=(EMAIL,))
		net = world(MAIN, leaf)
		self.assertRefused("KEY_USAGE", leaf, net)
		self.assertEqual(net.calls, [])

	def test_profile_positive_controls(self):
		for label, kw in (("no EKU at all", dict(eku=())), ("clientAuth only", dict(eku=(CLIENT_AUTH,)))):
			with self.subTest(label):
				ca_trust.clear_cache()
				leaf = MAIN.leaf(**kw)
				self.assertPasses(leaf, world(MAIN, leaf))

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
		# finding 2: the profile refusal says plainly that the certificate was NOT found untrusted.
		profile = ca_trust.MESSAGES["CERTIFICATE_PROFILE"]
		self.assertIn("subject alternative name and a client-authentication purpose", profile)
		self.assertIn("It was not rejected as untrusted; please contact support.", profile)
		self.assertNotIn("not trusted", profile)
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

		class _Verifier:
			def verify(self, *args):
				raise VerificationError(SENTINEL)

		class _Builder:
			def __getattr__(self, name):
				return lambda *a, **k: _Verifier() if name == "build_client_verifier" else self

		cases = [
			("aia fetch error", "CA_FETCH_FAILED", {MAIN.u["sub_cer"]: RuntimeError(SENTINEL)}, None),
			("aia garbage body", "CA_FETCH_FAILED", {MAIN.u["sub_cer"]: SENTINEL.encode()}, None),
			(
				"revocation errors",
				"REVOCATION_UNAVAILABLE",
				{MAIN.u["leaf_ocsp"]: ValueError(SENTINEL), MAIN.u["leaf_crl"]: ValueError(SENTINEL)},
				None,
			),
			("library verification error", "NOT_CCA_TRUSTED", {}, mock.patch.object(ca_trust, "PolicyBuilder", _Builder)),
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

	def test_pinned_root_is_cca_india_2022(self):
		self.assertEqual(pinned_roots.CCA_INDIA_2022_SHA256, CCA_ROOT_SHA256)
		self.assertEqual([sha(c) for c in pinned_roots.PINNED_ROOTS], [CCA_ROOT_SHA256])
		self.assertEqual(pinned_roots.PINNED_ROOT_SHA256, frozenset({CCA_ROOT_SHA256}))
		root = pinned_roots.PINNED_ROOTS[0]
		self.assertEqual(root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "CCA India 2022")
		self.assertEqual(root.subject, root.issuer)

	def test_untampered_source_imports_control(self):
		namespace = self._exec(self._source())
		self.assertEqual(namespace["PINNED_ROOT_SHA256"], frozenset({CCA_ROOT_SHA256}))

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


# ---------------------------------------------------------------- real CCA India chain


def _fixture(name):
	with open(os.path.join(FIXTURES, name), "rb") as fh:
		return fh.read()


def _ocsp_url(cert):
	aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
	return next(d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP)


class RealCCAChainTest(_Base):
	LEAF_AIA = "https://signxca.com/repository/aia/SignXClass3Individual.cer"
	SUB_AIA = "https://signxca.com/repository/aia/SignXRootCA2022.cer"
	ROOT_AIA = "http://www.cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer"

	def setUp(self):
		super().setUp()
		self.leaf_der = _fixture("owner_leaf_signx_class3_individual.der")
		self.sub_der = _fixture("signx_sub_ca_class3_individual_2022.der")
		self.ca_der = _fixture("signx_ca_2022.der")
		self.assertEqual(hashlib.sha256(self.leaf_der).hexdigest(), OWNER_LEAF_SHA256)
		self.assertEqual(hashlib.sha256(self.sub_der).hexdigest(), SIGNX_SUB_SHA256)
		self.assertEqual(hashlib.sha256(self.ca_der).hexdigest(), SIGNX_CA_SHA256)

	def net(self):
		net = FakeNet()
		net.routes[self.LEAF_AIA] = base64.encodebytes(self.sub_der)
		net.routes[self.SUB_AIA] = self.ca_der
		return net

	def stub_ocsp(self, result="good"):
		calls = []

		def fake(cert, issuer, now, net):
			calls.append((sha(cert), sha(issuer)))
			if result != "good":
				return None
			return "good", ca_trust._revocation_entry(cert, "ocsp", _ocsp_url(cert), now)

		return calls, mock.patch.object(ca_trust, "_check_ocsp", side_effect=fake)

	def test_real_cca_india_chain_passes_with_stubbed_ocsp(self):
		calls, patcher = self.stub_ocsp()
		net = self.net()
		with patcher:
			record = ca_trust.authenticate_certificate(self.leaf_der, now=NOW, fetch=net)  # default = pinned CCA root
		self.assertIs(record["verified"], True)
		self.assertEqual(
			[c["sha256"] for c in record["chain"]], [OWNER_LEAF_SHA256, SIGNX_SUB_SHA256, SIGNX_CA_SHA256, CCA_ROOT_SHA256]
		)
		self.assertEqual(record["root_sha256"], CCA_ROOT_SHA256)
		self.assertEqual(record["chain"][-1]["subject_cn"], "CCA India 2022")
		self.assertEqual(
			calls,
			[(OWNER_LEAF_SHA256, SIGNX_SUB_SHA256), (SIGNX_SUB_SHA256, SIGNX_CA_SHA256), (SIGNX_CA_SHA256, CCA_ROOT_SHA256)],
		)
		self.assertEqual(net.urls(), [self.LEAF_AIA, self.SUB_AIA])
		self.assertEqual(
			[r["responder_host"] for r in record["revocation"]], ["ocsp.signxca.com", "ocsp.signxca.com", "ocvs.gov.in"]
		)

	def test_real_chain_negative_controls(self):
		calls, patcher = self.stub_ocsp()
		with patcher:
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(
					self.leaf_der, now=datetime.datetime(2028, 7, 21, tzinfo=UTC), fetch=self.net()
				)
			self.assertEqual(cm.exception.reason_code, "EXPIRED_OR_NOT_YET_VALID")
			ca_trust.clear_cache()
			net = self.net()
			net.routes[self.ROOT_AIA] = der(pinned_roots.PINNED_ROOTS[0])
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(self.leaf_der, now=NOW, fetch=net, roots=[MAIN.root])
			self.assertEqual(cm.exception.reason_code, "NOT_CCA_TRUSTED")
		ca_trust.clear_cache()
		calls, patcher = self.stub_ocsp(result="unavailable")
		with patcher:
			with self.assertRaises(ca_trust.CertificateNotAuthenticated) as cm:
				ca_trust.authenticate_certificate(self.leaf_der, now=NOW, fetch=self.net())
		self.assertEqual(cm.exception.reason_code, "REVOCATION_UNAVAILABLE")


if __name__ == "__main__":
	unittest.main()
