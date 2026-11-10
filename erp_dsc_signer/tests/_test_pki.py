"""A generated stand-in for a SignX "Class 3 Individual" DSC and its chain, built at test time.

Nothing here is a real certificate and nothing is written to disk, so no personal data is committed.
The leaf copies the extension profile of a genuine SignX Class 3 Individual DSC: RSA 2048, critical
basicConstraints cA=false, critical keyUsage digitalSignature + nonRepudiation, EKU clientAuth +
emailProtection + Adobe PDF signing + Microsoft document signing + smart-card logon, an rfc822Name SAN,
the CCA India certificate policies, AKI/SKI, and AIA caIssuers / OCSP / CRL URLs on the SignX hosts that
ca_trust.DEFAULT_ALLOWED_HOSTS allows (the caIssuers answer is served as base64 text, as SignX does).

The hierarchy mirrors SignX: root -> CA (pathlen 1) -> sub-CA (pathlen 0) -> leaf. The root is NOT the
pinned CCA India root, so callers pin it explicitly: authenticate_certificate(..., roots=[chain.root]).
Validity dates are fixed (not relative to the wall clock) so expiry tests are deterministic.
"""

import dataclasses
import datetime
import functools
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID, ObjectIdentifier

UTC = datetime.timezone.utc

SIGNER_CN = "Test Signer"
SIGNER_EMAIL = "test.signer@example.invalid"

# Same validity windows as the observed SignX chain: leaf valid 2026-07-20 .. 2028-07-20.
LEAF_NOT_BEFORE = datetime.datetime(2026, 7, 20, 7, 14, 38, tzinfo=UTC)
LEAF_NOT_AFTER = datetime.datetime(2028, 7, 20, 7, 14, 38, tzinfo=UTC)
_VALIDITY = {
	"root": (datetime.datetime(2022, 1, 1, tzinfo=UTC), datetime.datetime(2042, 1, 1, tzinfo=UTC)),
	"ca": (datetime.datetime(2022, 8, 26, 9, 32, 30, tzinfo=UTC), datetime.datetime(2032, 8, 26, 9, 32, 30, tzinfo=UTC)),
	"sub": (datetime.datetime(2022, 8, 30, 5, 7, 8, tzinfo=UTC), datetime.datetime(2032, 8, 26, 8, 32, 30, tzinfo=UTC)),
}

URLS = {
	"root_cer": "http://www.cca.gov.in/test-pki/TestRoot.cer",
	"ca_ocsp": "http://ocvs.gov.in/test-pki",
	"ca_crl": "http://cca.gov.in/test-pki/TestRoot.crl",
	"ca_cer": "https://signxca.com/test-pki/aia/TestCA.cer",
	"sub_ocsp": "http://ocsp.signxca.com/test-pki/TestCA",
	"sub_crl": "https://signxca.com/test-pki/crl/TestCA.crl",
	"sub_cer": "https://signxca.com/test-pki/aia/TestSubCA.cer",
	"leaf_ocsp": "http://ocsp.signxca.com/test-pki/TestSubCA",
	"leaf_crl": "https://signxca.com/test-pki/crl/TestSubCA.crl",
}

ADOBE_PDF_SIGNING = ObjectIdentifier("1.2.840.113583.1.1.5")
MS_DOCUMENT_SIGNING = ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")
MS_SMARTCARD_LOGON = ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
SIGNER_EKU = (
	ExtendedKeyUsageOID.CLIENT_AUTH,
	ExtendedKeyUsageOID.EMAIL_PROTECTION,
	ADOBE_PDF_SIGNING,
	MS_DOCUMENT_SIGNING,
	MS_SMARTCARD_LOGON,
)
# CCA India certificate policy OIDs (public, from the Interoperability Guidelines), not personal data.
CCA_CLASS3_POLICIES = ("2.16.356.100.2.3", "2.16.356.100.2.2")
CCA_CA_POLICY = ("2.16.356.100.2",)


def der(cert):
	return cert.public_bytes(serialization.Encoding.DER)


def sha256(cert):
	return hashlib.sha256(der(cert)).hexdigest()


def rsa_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ca_name(cn, ou):
	return x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "XL Test PKI"),
			x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
			x509.NameAttribute(NameOID.COMMON_NAME, cn),
		]
	)


def signer_name(cn=SIGNER_CN):
	"""The attribute shape of a SignX individual subject, with synthetic values only (no telephone)."""
	return x509.Name(
		[
			x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Personal"),
			x509.NameAttribute(NameOID.PSEUDONYM, "test-pseudonym-0001"),
			x509.NameAttribute(NameOID.POSTAL_CODE, "000000"),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
			x509.NameAttribute(NameOID.SERIAL_NUMBER, "0" * 64),
			x509.NameAttribute(NameOID.COMMON_NAME, cn),
		]
	)


def _key_usage(**flags):
	base = dict(
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
	base.update(flags)
	return x509.KeyUsage(**base)


def _policies(oids):
	return x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(o), None) for o in oids])


def _locations(ca_issuers, ocsp_url, crl_url):
	aia = x509.AuthorityInformationAccess(
		[
			x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(ca_issuers)),
			x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)),
		]
	)
	cdp = x509.CRLDistributionPoints(
		[x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]
	)
	return aia, cdp


def _builder(subject, issuer_name, public_key, not_before, not_after, serial):
	return (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer_name)
		.public_key(public_key)
		.serial_number(serial or x509.random_serial_number())
		.not_valid_before(not_before)
		.not_valid_after(not_after)
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
	)


def make_signer_leaf(
	issuer_name,
	issuer_key,
	*,
	key=None,
	cn=SIGNER_CN,
	ca_issuers=URLS["sub_cer"],
	ocsp_url=URLS["leaf_ocsp"],
	crl_url=URLS["leaf_crl"],
	not_before=LEAF_NOT_BEFORE,
	not_after=LEAF_NOT_AFTER,
	serial=None,
):
	"""A leaf with the SignX Class 3 Individual profile, issued under ``issuer_name`` and signed by ``issuer_key``."""
	key = key or rsa_key()
	aia, cdp = _locations(ca_issuers, ocsp_url, crl_url)
	builder = (
		_builder(signer_name(cn), issuer_name, key.public_key(), not_before, not_after, serial)
		.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
		.add_extension(aia, critical=False)
		.add_extension(cdp, critical=False)
		.add_extension(_policies(CCA_CLASS3_POLICIES), critical=False)
		.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
		.add_extension(x509.ExtendedKeyUsage(list(SIGNER_EKU)), critical=False)
		.add_extension(x509.SubjectAlternativeName([x509.RFC822Name(SIGNER_EMAIL)]), critical=False)
		.add_extension(_key_usage(digital_signature=True, content_commitment=True), critical=True)
	)
	return builder.sign(issuer_key, hashes.SHA256()), key


def _make_ca(cn, ou, key, issuer, issuer_key, pathlen, validity, locations):
	subject = _ca_name(cn, ou)
	builder = _builder(subject, issuer.subject if issuer is not None else subject, key.public_key(), *validity, None)
	if issuer is not None:
		aia, cdp = _locations(*locations)
		builder = (
			builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
			.add_extension(aia, critical=False)
			.add_extension(cdp, critical=False)
			.add_extension(_policies(CCA_CA_POLICY), critical=False)
		)
	builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True).add_extension(
		_key_usage(key_cert_sign=True, crl_sign=True), critical=True
	)
	return builder.sign(issuer_key or key, hashes.SHA256())


@dataclasses.dataclass(frozen=True)
class SignerChain:
	root: x509.Certificate
	root_key: object
	ca: x509.Certificate
	ca_key: object
	sub: x509.Certificate
	sub_key: object
	leaf: x509.Certificate
	leaf_key: object

	@property
	def leaf_der(self):
		return der(self.leaf)

	@property
	def path(self):
		"""leaf -> sub-CA -> CA -> root, the order ca_trust reports in record["chain"]."""
		return (self.leaf, self.sub, self.ca, self.root)


@functools.lru_cache(maxsize=None)
def signer_chain():
	"""One generated SignX-shaped chain per test process (RSA key generation is the slow part)."""
	root_key, ca_key, sub_key = rsa_key(), rsa_key(), rsa_key()
	root = _make_ca("Test CCA Root", "Test Root", root_key, None, None, None, _VALIDITY["root"], None)
	ca = _make_ca(
		"Test SignX CA",
		"Certifying Authority",
		ca_key,
		root,
		root_key,
		1,
		_VALIDITY["ca"],
		(URLS["root_cer"], URLS["ca_ocsp"], URLS["ca_crl"]),
	)
	sub = _make_ca(
		"Test SignX sub-CA for Class 3 Individual",
		"Sub-CA",
		sub_key,
		ca,
		ca_key,
		0,
		_VALIDITY["sub"],
		(URLS["ca_cer"], URLS["sub_ocsp"], URLS["sub_crl"]),
	)
	leaf, leaf_key = make_signer_leaf(sub.subject, sub_key)
	return SignerChain(root, root_key, ca, ca_key, sub, sub_key, leaf, leaf_key)
