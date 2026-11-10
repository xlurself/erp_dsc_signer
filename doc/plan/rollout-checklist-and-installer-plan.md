# Rollout checklist and installer plan (cloud site + USB tokens on user laptops)

Status: proposal, 2026-11-10. Nothing here is built. Facts marked (proven) were run on the local macOS bench; everything else is unproven.

## 1. What runs where

| Part | Where | Notes |
|---|---|---|
| Frappe app (PDF render, CCA India authentication, verification, attach, record) | Cloud site | Server needs outbound http/https to signxca.com, ocsp.signxca.com, ocvs.gov.in, cca.gov.in |
| Signer daemon `erp-dsc-local` | Each user's laptop | 127.0.0.1 only; PIN dialog; PKCS#11 |
| Token driver (maker's PKCS#11 library) | Each user's laptop | Not bundled: vendor licence; installed from the CA/vendor |
| Token + PIN | User | PIN typed only into the daemon's own dialog |

## 2. End-to-end checklist (run before any client demo)

Each row needs a recorded PASS/FAIL with date and tester. PINs are never recorded.

### A. Cloud site
- [ ] A1 App installed on the cloud site; `bench migrate` ran; custom field `custom_signature_verification` exists, read-only.
- [ ] A2 `DSC Signing Settings` set (USB method; timestamp off until a TSA is chosen).
- [ ] A3 Cloud server can reach the 5 CCA/SignX hosts: run `authenticate_certificate` on the cloud with the public leaf fixture, expect `verified`.
- [ ] A4 Site origin (https) added to the laptop daemon's allowed origins (via pairing dialog).
- [ ] A5 Existing `custom_signed_*` fields `allow_on_submit` decision (open owner item).

### B. Laptop (repeat on: clean Windows 11, clean Windows 10, one macOS)
- [ ] B1 Install daemon with the installer (section 3); it starts at login; health answers on 127.0.0.1:17777.
- [ ] B2 Install token driver from vendor; add path to config if it is not a known path.
- [ ] B3 Browsers: Chrome, Edge, Firefox, Safari. Cloud https page calling `http://127.0.0.1:17777` works (mixed content / local network permission prompts). Record each.
- [ ] B4 Pairing: approve the site's origin once; revoke with `--revoke`; confirm refused afterwards.
- [ ] B5 Token read: public certificate listed without PIN.

### C. Signing, per token brand (WatchData/ProxKey, InnaitKey, ePass, SafeNet)
- [ ] C1 Certificate chain authenticates (note which CCA root: 2022 only is pinned today).
- [ ] C2 Authentication happens BEFORE the PIN dialog; failure shows a refusal and no PIN dialog.
- [ ] C3 Wrong PIN, final-try warning, cancel, timeout: each ends cleanly, no signed file.
- [ ] C4 Signed PDF: Adobe Reader shows signature valid, signer = certificate holder, stamp "Digitally signed by <holder>" (stamp fix 2026-11-10, retest pending).
- [ ] C5 Invoice shows "Verified (CCA India chain, revocation checked)"; record JSON has no PIN/key.
- [ ] C6 Revoked/expired/non-CCA certificate refused with nothing attached (unit tests exist; hardware run needs a non-CCA token).
- [ ] C7 Token swap while daemon running: next sign works without restarting the daemon (found 2026-11-10: the WatchData vendor library hung after a token swap and wedged the daemon until the vendor helper apps were restarted. The daemon needs a bounded call + clear message).
- [ ] C8 Revocation server briefly unreachable: user sees the retry message (seen 2026-11-09 22:23; retry worked).

### D. Security checks
- [ ] D1 PIN not in any log, Error Log, cache, process list, or crash report (the PIN-secrecy tests plus one manual grep after a real sign).
- [ ] D2 Independent security review and legal view on personal vs organisational Class 3 certificate for company invoices.
- [ ] D3 OM panel approval of the release commit.

## 3. Installer plan

Goal: a user installs once, with no Python knowledge and (where possible) no admin rights.

1. **Package the daemon as a single app.** Build with PyInstaller (includes Python, tkinter, PyKCS11, cryptography). One build per OS: Windows x64, macOS arm64/x64. Risk: tkinter dialogs and the child-process dialog model must be re-tested inside the frozen build (the macOS child-process rule from F1 still applies).
2. **Windows:** Inno Setup/MSI, per-user install under `%LOCALAPPDATA%`, auto-start via Startup shortcut/Task Scheduler at login, uninstall entry. Sign with an Authenticode certificate or SmartScreen will warn.
3. **macOS:** `.pkg` or app bundle, LaunchAgent for auto-start, signed with an Apple Developer ID and notarised, else Gatekeeper blocks it.
4. **Config:** ship `config.json` with the production site origin (not the dev `om-erp-v14.local`) and the token provider search paths; keep the Python `allowed_origins` pairing approval as the real trust gate (user still approves in a dialog).
5. **Token drivers:** do not bundle. The installer's last page lists supported drivers and links; a "Check token" button runs the read-certificates test and reports the library path found or missing.
6. **Updates:** version check against a signed manifest, user-approved update; never silent code download without signature check.
7. **Diagnostics:** `erp-dsc-local --doctor` prints (no PIN, no secrets): OS, daemon version, ports, config origins, driver paths found, token present, public certificate subject/issuer/expiry, and whether the CA root is pinned.
8. **Hardening found in testing (build before rollout):** bound every PKCS#11 call with a timeout so a hung vendor library cannot wedge the daemon (item C7); add providers for InnaitKey and the ePass v2.1 library name (`libcastle_v2.1.0.0.dylib`) to the known paths.

Rough order: 8 and 7 first (small, testable on this Mac), then 1-4 per OS, then 5-6.

## 4. Open decisions for the owner
1. Which CCA roots to pin besides CCA India 2022 (each is a fingerprint taken from cca.gov.in).
2. Windows first or macOS first for the pilot; which token brands are in the pilot.
3. Who buys the code-signing certificates (Windows Authenticode, Apple Developer ID).
4. PFX/server-side signing: keep out of the client demo, or decide where its password lives.
