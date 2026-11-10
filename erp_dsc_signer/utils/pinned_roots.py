"""Pinned trust anchors for DSC authentication (spec 002 s3.1).

The ONLY roots the app trusts for a Digital Signature Certificate. Operating-system, browser and
bundled third-party CA stores are never used. Each root is embedded as DER and checked against its SHA-256 fingerprint
when this module is imported: a mismatch raises ``PinnedRootError`` and the module (and everything that
imports it) fails to load, so a corrupted or swapped anchor can never be used silently.

Adding a root needs a reviewed code change: embed the DER, add its fingerprint constant taken from the
issuing authority's published value, and add it to ``_ROOTS``.

CCA India 2022 — Controller of Certifying Authorities, India (root of the India PKI).
Source: http://www.cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer (cca.gov.in), the caIssuers
address in SignX CA 2022. Fingerprint checked against cca.gov.in on 2026-11-09.

CCA India 2022 SPL — second live root published on cca.gov.in (valid 2022-09-20 to 2042-09-20).
Source: https://cca.gov.in/cca/sites/default/files/files/CCAIndia2022SPL.cer (page https://cca.gov.in/root_certificate.html,
fetched 2026-11-10). Checked: self-issued, CA=true with keyCertSign, self-signature verifies. cca.gov.in does not print
a fingerprint on that page (it offers out-of-band verification by email) and no second source quoting it was found,
so the fingerprint is the SHA-256 of the file as served over https on that date.

Roots NOT pinned on purpose (2026-11-10): CCA India 2014 (expired 2024-03-05), CCA India 2015 SPL (expired 2025-01-29),
CCA India 2011 / 2007 / 2000-era roots (expired). An expired root validates no certificate at signing time, so pinning
it adds attack surface and no accepted DSC. Re-check cca.gov.in/root_certificate.html when a new root is announced.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography import x509

CCA_INDIA_2022_SHA256 = "9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8"

_CCA_INDIA_2022_DER_B64 = """
MIIFNDCCAxygAwIBAgIQdiQz69smdlqFYM0KqC/hFzANBgkqhkiG9w0BAQsFADA6MQswCQYDVQQG
EwJJTjESMBAGA1UEChMJSW5kaWEgUEtJMRcwFQYDVQQDEw5DQ0EgSW5kaWEgMjAyMjAeFw0yMjAy
MDIxMjA0MzdaFw00MjAyMDIxMjA0MzdaMDoxCzAJBgNVBAYTAklOMRIwEAYDVQQKEwlJbmRpYSBQ
S0kxFzAVBgNVBAMTDkNDQSBJbmRpYSAyMDIyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAv3EBudWC8HY0oSwtJZCqpjQTGpEewl3EdDqUORV0qoFp78mdR/vuATXI83G7nF9RLvmNjgQg
Kr/bMx6gPO4Y57bMjAsgwEzleFclZka/sqc68iN5rS3huhrCX6MEINLyDOQ71MRA7GJCaNL6E3j1
438eTu011mlikeZYBdkhvfpAVjCw90w8wcWDmqx66Y561T/RiXyz2uEhBBZAD43gV58eXStOeOTw
AzEZYMrmp232GfmQKabYRfdIRus1avyuGea2nICEsRHE8M2tdzwpGP7oIy2qHBFJJ+3AwmwQA4Dj
mDkJtCD+58awohQavRNhqjsGD+ZifG3VR4i6WrKv8OWqZzcZj3g3Elr5+fRMlz1GSqkWPBw1Ev8K
WTHazSUKF7OMxm3XzyXxQnw7fZF9GOVtx3adpfRPqYGgtbOP34EVkz4wsHvNMrvUrYcKymdOrnkT
jlX26fIHUJpKGYkLk9q0jhMNKs4Rn8lj4pJ7YF33/ND4bjpV0ex1EAQz0iZvT37OnxNiuAZ/+4Dj
f075UuNX2ecWnadOrN1r8NAParZIwUoSUnWhU8TqAWWRqzFURHUZuOMQcA0geg4c9zqtBoUPgtQk
sbIAEsEXmDuRpwSIFjEkK11f5Eemfmfdg37KyIjQ67TRTmBA+kT9Q5JIm/e7m1ILg/HKckgLUOCn
AMsCAwEAAaM2MDQwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQITjtINlziX30wDgYDVR0PAQH/
BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4ICAQCdbE8d1c1DysKtrtYlApYIXTlY3N2XHNQ6gKoaVWsK
a1TJ/ovrT+FV3bmQLet3aSoEG6pTe/vLZSg8WiF7cn7WuF4XlQS3yA2Uu8/cg/S4owqhQJp6K/Xg
6UoSBad9Kog1H8deOfV8Nmb8a89zB4Yf8/AepId+Lr/3I6O7iub+PUT2QBXnksa+cf0yf+49GhyM
CILZvctNSQd4Vxr9EgRvBARTrAgNQ9sEOJ6myOz4iTFR7T2pIFP8Cp15e8jEVI1q4IuHu3XlwJNk
9f5k3gbwrzoy9P5rP8voQU3u9wh62JZa9U63b+u/Ur1tsKb5Lx0YUedtHvpIiIRurEPxumW0twjr
x8TrAcXRrViSL7dsXAoYC0dXo154EE8jBAzgIIur7tJizxgXDEn4i2pu8Yd615YML9ii5BooEJ2j
6fQ0nzyPRmx1Egw2Fjlgzzceai4TUOcaCKab86yyu5MZIp+BiPR840nw5MggbRgYH2nFRBA70toV
m4VFlbZs3reGmaICm4ST6R395OxYS1iYBm5kXm9tLb4pkIhUxrkgyuiwE+DsWceBjHAYaXnCgUGK
tiG9tfBMUw3fChoPb9L1yKdNof3zXDdTloMqEpO4BFrmjco8kt1v0LUQPhNZmQP4nqd4Hqx2384n
PmWDXbQ+eePyxRteYGY0hJeDLVpyeYG8VQ==
"""


class PinnedRootError(RuntimeError):
	"""An embedded trust anchor does not match its pinned fingerprint."""


def _load(name: str, der_b64: str, expected_sha256: str) -> x509.Certificate:
	der = base64.b64decode("".join(der_b64.split()), validate=True)
	if hashlib.sha256(der).hexdigest() != expected_sha256:
		raise PinnedRootError(f"Pinned root {name} does not match its SHA-256 fingerprint.")
	certificate = x509.load_der_x509_certificate(der)
	if certificate.subject != certificate.issuer:
		raise PinnedRootError(f"Pinned root {name} is not self-issued.")
	return certificate


CCA_INDIA_2022_SPL_SHA256 = "b724689b79b2ef9421ef8f5cc733eb093851b170ee715177005a09f226d8c91a"

_CCA_INDIA_2022_SPL_DER_B64 = """
MIIFPDCCAySgAwIBAgIQYoKBxu6+xz94CH5f9Y9J9DANBgkqhkiG9w0BAQsFADA+MQswCQYDVQQG
EwJJTjESMBAGA1UEChMJSW5kaWEgUEtJMRswGQYDVQQDExJDQ0EgSW5kaWEgMjAyMiBTUEwwHhcN
MjIwOTIwMDkxODE5WhcNNDIwOTIwMDkxODE5WjA+MQswCQYDVQQGEwJJTjESMBAGA1UEChMJSW5k
aWEgUEtJMRswGQYDVQQDExJDQ0EgSW5kaWEgMjAyMiBTUEwwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDMA++VJxEXN+coznBAEf0dz+8DBj9SpEQGoehjxoDnD+WYEBAXnap2lh5yE7/w
lpHUQ7hJ54JsqLBZQGkM0pk35bkvvcf2wAGSdK0KRilNeFDmVdduqAUJUlmNeL0ufIufsSBEusOW
KK6VvQHxiZ0qoyoeqV+CpnDm8I2IE0WBSbaotXtGWSyBLNDCEH3lRA9GQDOZ5Utc8soR2YVwbQSi
cGoyAC1PiPah7LY6nZCbBjc63r22dE+Cm1TGeqEb0ZUdhHl051WqEGXXmtQNfytdNP+VdKU1nrYE
cQ5BeGMaWA5bHkO2ERldI5F55pX06hUxwjL39H6JVX5/0I+bBiPsZiCpea2gKozNBg+MBWLqyBUz
FRVhLfdCPB6tm9EKHgrlP6rsWrjgZ5FcREmerCYs7HIYeemiI0UO4X8rqpobT3rL7mWALB2plyFa
BdiUWW1r87eZQDEeYWavOhNITYNc31FG3Kn8DANF3IhNeYmUDzG7/M1XyGycqBmXG7tVVXezO1Gb
gfM0SYlkVFRDOD6u9Tf0lR1MfjrJpMB+JdIJlimMM5G6LGia7+3Nlll8SJ0DhW49FdKlLB92iXuO
ok4iwPzyFKg8Eax/9iN9TxMadYxbpKkePL9DpL/ymRvpGDkPaurqUP77smtB8Jlf7bx8SB9DWVjV
qsgvemN+DZfNawIDAQABozYwNDAPBgNVHRMBAf8EBTADAQH/MBEGA1UdDgQKBAhIEoydvDOh6jAO
BgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBADYv91JbnwU+Ih5gNzZSJY0yJkYk4tbB
BsCZDivmZknCTbM8B9j/hEZcfXZCTbP6GCGkrxVx8aDl7E1s5DGmdO7x5R+dxrLD2B4+ORhDetlM
Yd22mopVnzqY5UdaQ8u16JNEp/m75UqT5NvcgtE+/s1Hr+3lhWKKvN7u9PxDSIoMT/I0/sje9fWw
jeX29nzqHTw7hYTLCIeQv8c9+wGBFAAFArUq0MaI6jxIav10DKeHptycUHwMNyzP9hh7G4nHo+lE
IT0/jWIrjv53+aVFLdAvBKQ2jyAKd/OhuQFCue3zMVMoTQ7Zl9HZk72CkBecaZhHnEzqjpOzueCw
eK0h27IvwED7scudpOPnY7ml6fEFdpHXZXcVz8TZbqirkHTLepfAOUBcyuadAKkOR+m5uU1UKkES
exaY2yVEdWcVAeCM6p6FXlFeRMEebMbppkPeSFUPMRA9mhsUTOk5sbnGN2TVkSfUpcUMoQgz2bSq
vGyR7sAZ9Un457swjwEEEnzijdMvd9YDj1wRq+tsq38zq5IaE50VMMXeBoVz2/2Bn8Mrp8kN7XIk
rCui8wjclnG9BB1SbwjXPhE+7zE6GKh+oIRZua2RkamTpjwe+2oSihGVFeD7pSMh/Pgyxg1lxSVD
KvbBdxNrBpot2OQN35+DkAU2exJMtUYAvzdPVx9d2elo
"""

_ROOTS = (
	("CCA India 2022", _CCA_INDIA_2022_DER_B64, CCA_INDIA_2022_SHA256),
	("CCA India 2022 SPL", _CCA_INDIA_2022_SPL_DER_B64, CCA_INDIA_2022_SPL_SHA256),
)

PINNED_ROOTS: tuple[x509.Certificate, ...] = tuple(_load(*entry) for entry in _ROOTS)
PINNED_ROOT_SHA256: frozenset[str] = frozenset(expected for _name, _b64, expected in _ROOTS)
