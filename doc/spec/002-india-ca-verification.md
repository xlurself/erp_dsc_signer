# Spec 002 — Authenticate the DSC against the CCA India hierarchy (fail closed)

BRD: doc/brd/002-india-ca-verification.md (owner-approved 2026-11-09). Rev 2 (as built, before panel; section 9 lists every change from rev 1). Rev 3 (2026-11-10): s9 item 18, own path validator instead of the TLS verifier.
Owner rules: not authenticated by the Indian CA chain => do NOT sign, no override (decision 2026-11-09).
Scope: certificate authentication only. PIN/key/dialog handling (F1) is unchanged. No secret is involved at any step:
only the PUBLIC certificate, public CA certificates and public revocation data are handled.

## 1. Observed chain (SignX, from the owner's real DSC, checked 2026-11-09)
leaf (Class 3 Individual, policy OIDs 2.16.356.100.2.3 / .2.2) -> SignX sub-CA for Class 3 Individual 2022
(pathlen 0, valid to 2032-08-26) -> SignX CA 2022 (pathlen 1, valid to 2032-08-26) -> CCA India 2022 (root,
SHA-256 9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8, matches cca.gov.in).
The signed PDF carries ONLY the leaf; intermediates are NOT embedded. Public addresses (all answered 200):
leaf OCSP http://ocsp.signxca.com/SignXClass3Individual; CRL https://signxca.com/repository/crl/SignXClass3Individual.crl
(1.37 MB: OCSP first, CRL fallback); sub-CA AIA https://signxca.com/repository/aia/SignXClass3Individual.cer;
SignX CA 2022 (OCSP http://ocvs.gov.in, AIA http://www.cca.gov.in/.../CCAIndia2022.cer). AIA files may be base64 text.

## 2. Module and API
New leaf module `erp_dsc_signer/utils/ca_trust.py` (no frappe import, unit-testable):
`authenticate_certificate(cert_der, *, now, fetch=<injectable>) -> AuthResult` (record dict) or raises
`CertificateNotAuthenticated(reason_code, message)`. `reason_code` is a closed set:
`NOT_CCA_TRUSTED`, `CHAIN_INCOMPLETE`, `EXPIRED_OR_NOT_YET_VALID`, `KEY_USAGE`, `REVOKED`,
`REVOCATION_UNAVAILABLE`, `CA_FETCH_FAILED`. No exception text from libraries reaches the user.

Whitelisted `api.signing.authenticate_usb_certificate(session_id, certificate_der_base64)`: same permission/session
checks as the other signing endpoints (session user+invoice+provider bound). On success it marks the session
`authenticated` with the certificate fingerprint. `complete_usb_signing` refuses any session not marked, and
refuses when the returned signature's certificate fingerprint differs from the authenticated one, then
authenticates AGAIN (fresh revocation) before attaching. PFX mode calls the same function on the PFX certificate
before signing (same gate; fail closed).
JS order: prepare -> select certificate -> **authenticate (new)** -> nonce -> PIN dialog/sign -> complete. A failure
at authenticate shows the reason and stops BEFORE the PIN dialog; the token is never asked to sign.

## 3. Checks (all must pass, any failure refuses)
1. Chain: build leaf -> ... -> pinned root using cryptography's `x509.verification` with a Store containing ONLY
   the pinned roots (`pinned_roots.py`: the CCA India 2022 DER embedded, verified at import against its fingerprint
   constant; code fails to import on mismatch). OS/certifi stores are never used. Intermediates come from AIA (3).
   CA flag, pathlen, key-usage keyCertSign and signature at every link are enforced by the library.
   **Superseded (rev 3, s9 item 18):** the library verifier is no longer used; `ca_trust._validate_path` enforces these.
2. Validity: now within notBefore/notAfter for every cert in the chain; leaf keyUsage digitalSignature or
   contentCommitment (existing rule kept). Time = server clock at verification (no trusted timestamp in this
   release; the record states "signing time is the server clock at verification").
3. Intermediate fetch (AIA): URL must come from the cert's AIA caIssuers AND its host must be in the allowlist
   below; result must parse as DER or base64-DER, be <= 20 KB, and is accepted ONLY if the chain verifies to the
   pinned root (a fetched cert is never trusted by itself). Cached in process memory by SHA-256 (public data).
4. Revocation, every non-root certificate in the path (leaf, sub-CA, SignX CA): OCSP request to the OCSP URL in
   that cert's AIA (allowlisted host), no nonce requirement, response must be `successful`, signed by the issuer
   or a delegated responder certified by the issuer with id-kp-OCSPSigning, thisUpdate <= now <= nextUpdate
   (5 min skew), status `good`. `revoked` => REVOKED. Unknown/error/timeout/bad signature/stale => CRL fallback
   (DP URL allowlisted host; CRL signature verified against the issuer; thisUpdate/nextUpdate valid; serial not
   listed; size cap 8 MB). If neither yields a verified `good`/not-listed answer => REVOCATION_UNAVAILABLE.
5. SSRF/DoS guard: allowed hosts default `signxca.com`, `ocsp.signxca.com`, `ocvs.gov.in`, `cca.gov.in`,
   `www.cca.gov.in` (exact match, scheme http/https, port 80/443, no userinfo, no redirects, resolved IP must be
   public: refuse loopback/private/link-local). Connect 5 s / read 10 s, total budget 25 s per authentication.
   Allowlist lives in code; a site setting may ADD hosts only for System Manager and is logged. Requests carry only
   the OCSP request (issuer hashes + serial) — no document, user, site name or PIN.

## 4. Record on the invoice
New read-only Long Text custom field `custom_signature_verification` (fixture; `bench migrate`), JSON with a
strict allowlist: `verified` (bool), `checked_at`, `chain` (subject CN + SHA-256 per cert), `root_sha256`,
`revocation` (per cert: method ocsp|crl, status, responder host, produced_at), `timestamp` = "none",
`signing_time_basis` = "server clock at verification". Never any PIN/key/exception text. The Desk label shows
"Verified (CCA India chain, revocation checked)" only when `verified` is true; otherwise "Signature valid".

## 5. Errors and messages
Plain wording per `reason_code` (e.g. REVOCATION_UNAVAILABLE: "Could not confirm with the certifying authority
that this certificate is not revoked, so the document was not signed. Check the internet connection and try
again."). Log line: reason_code + fingerprint only.

## 6. Tests (written first; each must be able to fail)
Real-shaped fixtures: a generated test PKI (test root pinned via an injectable roots argument; generated at test time, no personal
certificate is stored) plus tests with the real CCA India 2022 root and the real two SignX intermediates (public
institutional certificates). No end-to-end test over a real end-entity certificate exists (2026-11-10). Cases: unpinned root refused; chain incomplete; expired; wrong key usage; revoked (OCSP and
CRL); OCSP error + CRL good passes; both unavailable refuses; bad OCSP signature; stale OCSP; OCSP signed by
non-delegated cert; hostile AIA/OCSP host (loopback, private IP, non-allowlisted, redirect) never fetched;
oversize responses; fetched intermediate that does not chain is rejected; session not authenticated => complete
refuses; fingerprint swap between authenticate and complete refused; token never asked to sign when authenticate
fails (JS-level contract via signer test double); record has exactly the allowlisted keys and a sentinel PIN
never appears; PFX path gated. Gates: no module other than `ca_trust` makes outbound HTTP for trust data; no
OS trust store reference.

## 7. Residual limits (stated, not hidden)
No trusted timestamp: signing time is not third-party proven (deferred). Revocation freshness is "at signing".
Server must reach SignX/CCA hosts. Legal sufficiency is for the owner's advisor/CA to confirm. Personal vs
organisational Class 3 question is open with SignX/advisor.

## 8. Adversarial self-review (before the panel)
Attacks considered: fake CA with a copied name (pinned by key/fingerprint chain, not names); SSRF through AIA/OCSP
URLs (allowlist + IP check + no redirects); OCSP replay (nextUpdate enforced); downgrade to CRL on attacker-forced
OCSP failure (CRL still verified, never "assume good"); intermediate substitution (fetched certs must chain);
TOCTOU between authenticate and sign (re-authenticate on complete + fingerprint binding); log/PIN leakage
(public data only, closed reason set); unbounded downloads (caps/timeouts). Open point for the panel: use the
Python `x509.verification` API (needs cryptography >= 42; confirm bench env version) vs a hand-rolled walk.

## 9. Rev 2 — as built (changes from rev 1)
1. **Certificate bytes reach the browser.** `/v1/certificates` metadata now includes `der_base64` (PUBLIC certificate
   DER only; local_signer/erp_dsc_local/certificates.py). Only paired origins can call that endpoint. The browser sends
   it to `authenticate_usb_certificate` and sends only the fingerprint to `/v1/sign`. The daemon signs with the
   certificate whose fingerprint the browser names; complete refuses if the PDF's signer fingerprint differs from the
   authenticated one. Test: local_signer/tests/test_certificate_der.py.
2. **No extra-hosts site setting** in this release. `extra_hosts` exists in `ca_trust` but api/signing.py never passes it.
   Allowlist = code only.
3. **TLS wording (replaces the s6 gate "no OS trust store").** No TRUST DECISION uses the OS or certifi store: chain trust
   comes only from the pinned root. HTTPS transport to SignX/CCA hosts uses the platform TLS bundle for the connection
   only; every CA/OCSP/CRL answer is verified cryptographically regardless of transport.
4. **Library limits (cryptography 44):** the leaf must carry a SAN, and clientAuth if it has an EKU (the owner's does).
   A CCA DSC without them is refused (new 8th closed reason code `CERTIFICATE_PROFILE`, detected before chain building, honest message "not rejected as untrusted"): fail closed, relaxable by a library upgrade. `KEY_USAGE` now means a real digitalSignature/non-repudiation problem only.
   **Superseded (rev 3, item 18):** no SAN or clientAuth is required any more; `CERTIFICATE_PROFILE` now means the leaf itself is unacceptable.
5. **Revocation details:** a correctly signed OCSP `revoked` refuses even if stale; OCSP without `nextUpdate` counts as
   stale and falls to the CRL; RSA-PSS-signed OCSP, delta/indirect/partitioned CRLs and PKCS#7 AIA files are not
   supported (fall back / refuse). OCSP size cap 64 KB; DNS lookup has no timeout of its own (the 25 s budget applies).
6. **Signing time basis:** "server clock at verification" (spec value; the BRD's "signer computer's clock" is superseded
   for the record wording).
7. **Session:** authenticate does not consume the session; marks it (authenticated, sha256, DER, record); a second
   authenticate of the same session is refused; the original expiry is kept. Complete: unmarked => refuse; PDF verified;
   fingerprint equals authenticated; DER hash re-checked; authenticate AGAIN (fresh revocation); attach; write record.
8. **Record write:** `custom_signature_verification` (Long Text, read-only, no_copy, print_hide, **allow_on_submit=0** so a client `set_value` on a submitted invoice cannot forge it) is written
   by a separate `frappe.db.set_value` in api/signing.py right after `attach_signed_invoice_pdf` (pdf_signer.py unchanged),
   same transaction. Keys = spec s4 allowlist plus `signed_pdf_sha256` (SHA-256 of the attached PDF), nested keys allowlisted too.
9. **Refusal logging** records reason_code + certificate fingerprint only and commits the Error Log row (Frappe rolls back a
   raised POST otherwise).
10. **PFX mode** authenticates the PFX certificate before generating/signing (fail closed). Any PFX not issued under CCA
    India (e.g. self-signed test) is refused; PFX signing now needs the server to reach the CCA/SignX hosts. The PFX is loaded ONCE and the same credentials sign (no re-read).
11. **Deployment:** the workstation daemon must be restarted (new certificate listing field) and the site migrated
    (new custom field); until then every USB signing is refused with the "session not authenticated" message.
12. **Live proof (2026-11-09):** the owner's real certificate authenticated against the live SignX and CCA servers: chain to
    CCA India 2022 (9a3fd317...), OCSP `good` for all three certificates (ocsp.signxca.com x2, ocvs.gov.in).
13. **Adversarial review (2026-11-09) and fixes:** no path found that attaches a non-CCA, revoked or unverifiable
    certificate. Fixed before the panel: forgeable record (allow_on_submit=0, PDF hash in record, fixtures filter);
    CERTIFICATE_PROFILE code; deadline re-armed on every send/recv (incl. headers); late authenticate cannot revive a used
    session (re-read + Redis SET XX); max 5 failed authentications per session; PFX loaded once; browser compares the
    returned certificate fingerprint before the nonce; issuer AND serial must match exactly one certificate in
    usb_signer; site-local IPv6 (fec0::/10) refused; Desk label "Verified" only when record.verified is true.
14. **Stated residuals:** OCSP `thisUpdate` has no maximum age (a "good" answer can be replayed until its nextUpdate);
    CRL issuing-distribution-point is not matched to the certificate's CDP; two concurrent authenticates of one session
    can both pass the re-read (later wins; complete still binds to the PDF signer); complete's read-then-delete of the
    session is two steps (existing); the failure counter is per session and can lose a count under concurrency; DNS lookup
    has no timeout of its own; PFX signing needs the server to reach the CCA/SignX hosts.
15. **Existing fields (not changed here):** the five `custom_signed_*` custom fields still have allow_on_submit=1, so a user
    with Sales Invoice write permission can set them via the client API (the Desk then shows "Signature valid", never
    "Verified"). They are shared with erp_pdf_signer; owner decision pending.
    **Closed 2026-11-10:** all six signing fields now have allow_on_submit=0 (owner decision); the server writes them with
    frappe.db.set_value, so signing does not depend on them being editable.
16. **Pinned roots (2026-11-10, owner: "add all CCA roots"):** two roots are pinned, the two that cca.gov.in lists as valid
    today: CCA India 2022 and CCA India 2022 SPL (both to 2042). CCA India 2014 (expired 2024-03-05), 2015 SPL (expired
    2025-01-29), 2011, 2007 and older are deliberately NOT pinned: an expired root validates no certificate at signing time,
    so pinning it would add attack surface and accept nothing. The SPL fingerprint is the SHA-256 of the file served over
    https by cca.gov.in; the site prints no fingerprint and no second source quoting it was found (CCA offers out-of-band
    verification by email: open item for the owner).
17. **Transport bug found by a real certificate (2026-11-10):** `_DeadlineSocket.close()` closed the real socket while
    http.client was still going to read the body of a "Connection: close" answer. Every real CRL fetch (315 KB) and about
    8% of OCSP fetches failed with "Bad file descriptor", which surfaced as sporadic REVOCATION_UNAVAILABLE refusals (seen
    2026-11-09 and 2026-11-10); the CRL fallback had never worked against a live server. Fixed: close is deferred while a
    reader is open, tests model close and segmented delivery. After the fix: 40/40 live authentications, and a live
    CRL-only run, passed.
18. **Path validator replaces the TLS verifier (rev 3, 2026-11-10, panel round F2-INDIA-CA-VERIFY-R2).** cryptography's
    `x509.verification` client verifier is a TLS profile: it refused a leaf without a SAN, or with an EKU lacking clientAuth,
    which a CMS/PDF signing DSC does not need (owner rule: any valid CCA-hierarchy DSC, any brand). It is no longer used.
    `ca_trust._validate_path` (RFC 5280 s6.1 basic path validation, document-signing profile) decides the path that
    `_build_path` assembled (leaf -> AIA intermediates -> pinned root). All checks fail closed:
    - path ends at a pinned root, matched by DER SHA-256 (never a root from AIA); 2..`MAX_INTERMEDIATES`+2 certificates,
      no certificate repeated (else `CHAIN_INCOMPLETE`);
    - leaf, before any download: valid at `now`; keyUsage absent = unrestricted, present must have digitalSignature or
      nonRepudiation (`KEY_USAGE`); not self-issued (`NOT_CCA_TRUSTED`); v3, basicConstraints absent or cA=false, strong key
      and signature, no unhandled critical extension (`CERTIFICATE_PROFILE`). **No SAN and no EKU gate**: absent,
      documentSigning, Adobe, emailProtection, anyExtendedKeyUsage all pass (no CCA rule lets an EKU refusal reject only
      certificates a real CCA CA never issues);
    - every certificate valid at `now`, inclusive at both edges (`EXPIRED_OR_NOT_YET_VALID`);
    - every CA, the pinned root included: v3, basicConstraints cA=true, pathLenConstraint >= number of CAs below it
      (self-issued ones counted too, stricter than RFC: **superseded by item 19**), keyCertSign when keyUsage is present (RFC 5280 s6.1.4(n)), strong
      key, no unhandled critical extension, no nameConstraints (not implemented: refused even when non-critical)
      (`NOT_CCA_TRUSTED`);
    - every link: issuer name DER-equal to the issuer's subject (RFC 5280 s4.1.2.4; x509.Name equality would ignore the
      string type), signature hash SHA-2/SHA-3 only (no MD2/MD5/SHA-1), signature verified with the issuer's key
      (`NOT_CCA_TRUSTED`);
    - strong key: RSA >= 2048 or EC P-256/P-384/P-521; DSA/Ed25519/Ed448/other curves refused;
    - critical extensions handled: basicConstraints, keyUsage, EKU, SAN, certificatePolicies, AKI, SKI, CRL DP, AIA,
      policyConstraints, inhibitAnyPolicy. No policy tree is built: certificatePolicies, inhibitAnyPolicy and
      inhibitPolicyMapping cannot change the verdict while no explicit policy is required, so any requireExplicitPolicy
      in the path is refused. The old library refused critical certificatePolicies/policyConstraints/inhibitAnyPolicy
      (probed on cryptography 44), so nothing it accepted is refused now except as listed here.
    Reason codes: the closed set is unchanged (8); the `CERTIFICATE_PROFILE` message now names the leaf problems. Revocation
    (OCSP then CRL, every non-root certificate), SSRF guard and budgets are unchanged. The daemon's certificate filter
    (`local_signer/erp_dsc_local/certificates.py::is_signing_certificate`) now treats an absent keyUsage as unrestricted,
    like the server, so the picker no longer hides such a DSC. Tests: `test_ca_trust.SigningPathValidatorTest`, the real
    SignX/CCA certificates through `_validate_path` with only the leaf link stubbed (`RealCCAChainTest`), 21 ca_trust
    mutants + 2 daemon mutants all killed. Live (2026-11-10, real HttpTransport): the organisation and the personal
    SignX DSC each verified 5/5 (2 AIA + 3 OCSP calls per run). Residuals: nameConstraints and requireExplicitPolicy are
    refused, not implemented; non-critical policyMappings is ignored (RFC 6.1.4(a) anyPolicy check not done; it cannot
    widen trust, which comes only from the pinned roots and the verified links); names that RFC 5280 s7.1 would match
    after normalisation but that are encoded differently are refused.
19. **CA key rollover: self-issued intermediates (rev 3.1, 2026-11-10, panel round R2 iteration 4, release 54e6157).**
    Found by the panel: a valid chain through a CA's key-rollover certificate (RFC 5280 s6.1 "self-issued": same subject
    and issuer name, NEW key, signed by the OLD key) was refused as NOT_CCA_TRUSTED, because `_issuing_anchor` treated a
    pinned-name match without the pinned key's signature as terminal, `_build_path` rejected every self-issued
    certificate, and pathLen counted self-issued intermediates. Rule now (`ca_trust.py`):
    - **Trust is only a pinned key's direct signature.** `_issuing_anchor` returns a pinned root only when that root's key
      signed the certificate (names DER-equal); a name match alone decides nothing and the walk follows the AIA. The
      anchor is always one of the pinned objects, and `_validate_path` still requires the last certificate to BE a
      pinned DER.
    - **Self-issued vs self-signed.** A self-issued certificate signed by another key (a rollover) is an ordinary
      intermediate: it must be signed by the next certificate up and pass every CA check (cA, keyCertSign, extensions,
      key, validity). A self-signed certificate (verifies with its own key) that no pinned key signed ends the walk as
      NOT_CCA_TRUSTED and is never an anchor or a link; the validator also refuses a self-signed certificate in any
      intermediate position. "Self-issued" compares the DER names, like every name in the path. A self-issued LEAF is
      still refused (NOT_CCA_TRUSTED, before any download).
    - **pathLenConstraint** counts only non-self-issued intermediates between the CA and the leaf (RFC 5280 s4.2.1.9,
      the count s6.1.4(l)/(m) enforce; `_real_intermediates_below`). The pinned root's own pathLen is still applied
      (stricter than RFC, which does not process the anchor's).
    - **Hard bounds unchanged:** at most `MAX_INTERMEDIATES` (4) intermediates, self-issued ones included, in both the
      builder (so at most 4 certificate downloads) and the validator; no certificate twice (a loop of two self-issued
      certificates signing each other ends as CHAIN_INCOMPLETE).
    - Contract change: a certificate issued under a pinned root's name but by another key used to stop at once; now its AIA
      is followed (bounded as above) and the outcome is CHAIN_INCOMPLETE / CA_FETCH_FAILED, or NOT_CCA_TRUSTED when the
      walk reaches a self-signed certificate (e.g. a rogue root copying the pinned name, which is now downloaded, refused
      and never cached). Reason codes unchanged (8).
    Tests: `test_ca_trust.KeyRolloverTest`: root-level and sub-CA-level rollover end to end (OCSP, and CRL only); pathLen
    boundaries on both sides (root pathLen 1 accepted / 0 refused, one real intermediate too many refused, X pathLen 0/1,
    sub-CA pathLen 0 with a self-issued certificate below accepted and with a real one refused); refusals for a self-issued
    certificate signed by an unrelated key, a self-signed rogue with the pinned name, a self-issued leaf, a self-issued
    CA without keyCertSign or with cA=false, a self-signed intermediate, rollover stuffing beyond the cap (exactly 4
    downloads), a two-certificate loop, and an issuer name re-encoded as PrintableString. Mutation: 12 new mutants plus
    the earlier 25, all killed. Live (2026-11-10): the organisation and personal SignX DSCs re-verified (real chain, direct
    signature to the pinned root). Residual: an AIA candidate is chosen by signature; when one AIA address serves
    several certificates (PKCS#7 bundles) none is used (unchanged: PKCS#7 AIA files are not supported).
