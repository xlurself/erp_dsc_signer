---
id: F2
title: Authenticate the DSC against the Indian CCA hierarchy before signing (fail closed)
priority: P0
status: planned
covers: [F2]
spec: doc/spec/002-india-ca-verification.md
---

## Summary
Today the ERP accepts any validly formed signature. It records whether the certificate chain is trusted but never
enforces it, never checks revocation, and judges the certificate against today's date. This feature makes the
"signed" result mean what an Indian user expects: the DSC belongs to a certificate issued under the Controller of
Certifying Authorities (CCA) India hierarchy and is not revoked. Rule from the owner: if the DSC cannot be
authenticated through the Indian certifying authority, the document is NOT signed. There is no override.

Scope boundary: the PIN, key and dialog behaviour of F1 are unchanged. No new secret is stored, logged or sent.
This feature is technical verification aligned to the IT Act rules and CCA guidelines; whether it satisfies a
specific legal requirement is for the owner's advisor or the CA to confirm.

## Acceptance criteria
- Trust anchors are pinned in the app by SHA-256 fingerprint, taken from cca.gov.in (CCA India 2022 root). The
  operating-system and web trust stores are not used. Adding another root needs a reviewed code change.
- The certificate chain must run from the signer's certificate, through its issuing CA, to a pinned root. A chain
  that ends anywhere else is refused.
- Revocation is checked online with the issuing CA's OCSP (CRL as fallback). A revoked certificate, or a
  revocation status that cannot be obtained, refuses the signing.
- The certificate must be valid at the signing time and permitted to sign (existing key-usage check kept).
- The check runs BEFORE the PIN dialog opens, so a failing certificate never reaches the token, and again when the
  signed PDF returns. Either failure attaches nothing to the invoice.
- Failure gives the user a clear reason in plain language (not trusted by CCA India / revoked / status could not be
  confirmed). No generic message. No override and no "warn and continue" mode.
- The verification record kept on the invoice: issuer, root fingerprint, revocation result with time and responder,
  and the statement "no trusted timestamp". It never contains a PIN or key material.
- The screen says "verified" only when all checks above passed. Until then the wording is "signature valid".
- No timestamp is required. When no trusted timestamp is used, the signing time is the signer computer's clock and
  the record says so.

## Out of scope (deferred, owner-decided 2026-11-08)
CCA-licensed timestamp, certificate policy/class check, long-term validation data embedding, CRL caching.
Open items for the owner's advisor or SignX: personal vs organisational Class 3 certificate for company invoices;
whether the IT (End Entity) Rules bind a private application.

## Done when
- A test proves a chain ending at an unpinned root is refused and nothing is attached.
- A test proves a revoked certificate is refused, and that an unreachable revocation service refuses too.
- A test proves the check runs before the PIN dialog and the token is never asked to sign for a failing certificate.
- A test proves the returned PDF is re-verified and refused when the certificate fails at completion.
- A test proves the verification record contains the stated fields and no PIN or key material.
- A test with the real CCA India 2022 root and a real-shaped chain proves a good certificate passes.
- Manual boot-and-click: signing XL-SI-26-0000014 with the Watchdata token passes, and signing with a certificate
  outside the CCA hierarchy is refused with a clear reason.
