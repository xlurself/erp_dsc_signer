# Installer plan: ERP DSC Signer (the program on each user's computer)

Status: proposal, 2026-11-10. Nothing here is built except what is marked "exists today". Estimates are rough working
days for one developer, not promises.

## 1. Why a program is needed at all
A web page cannot talk to a USB token or its driver: browsers block it. Every web system that signs with a USB DSC needs a
small helper on the user's computer. Ours is `erp-dsc-local` (folder `local_signer/`). The token vendor's own tool
(WatchData, InnaitKey, ePass, SafeNet ...) stays: it provides the driver. Our helper is the bridge between the page and
that driver, and it enforces our rules (pairing, CCA authentication before the PIN, PIN never leaves the computer).
One helper serves every brand through the standard PKCS#11 interface, so each user installs: **their vendor driver +
our one helper**.

## 2. What the user should experience
1. Download one file for their system (Windows or Mac) and double-click it. No Python, no commands, no admin rights
   where the OS allows it.
2. The helper starts by itself now, at every login, and restarts itself if it stops (today it does not: it stopped on the
   owner's Mac on 2026-11-10 with an empty log).
3. A small status icon (menu bar / system tray) shows: running, which sites are paired, which token is detected, "Open
   logs", "Restart", "Quit".
4. First Sign on a site: a plain-English pairing dialog (exists today). Then the certificate picker and the PIN dialog
   (exist today).
5. If something is wrong, the page says what to do in plain words (for example "Open ERP DSC Signer from your menu bar,
   or restart your computer").

## 3. What the installer does (both systems)
- Installs a self-contained helper (no separate Python): built with PyInstaller (or equivalent). Risk: the Tk dialogs,
  the child-process PIN dialog and PyKCS11 must be re-tested inside the packaged build.
- Per-user install, no administrator needed (an optional all-users package for IT-managed fleets).
- Registers auto-start and auto-restart: macOS LaunchAgent (KeepAlive); Windows per-user Startup entry or Scheduled Task
  "at log on", restart on failure.
- Writes a default `config.json` (loopback only, port 17777, no pre-approved sites; production site addresses can be
  pre-approved for managed fleets). Pairing is still approved by the user in a dialog.
- Finds the token driver: looks in the known locations (37 paths in `providers.py` today, including WatchData and
  ePass; add InnaitKey `/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.dylib` and ePass
  `libcastle_v2.1.0.0.dylib` found on 2026-11-10; Windows locations for InnaitKey still to be found on a real Windows
  machine). If none is found, a "Find my token driver" step lets the user pick the file; it is saved as a custom module.
- Does NOT bundle vendor drivers (their licences) and never stores or logs the PIN.
- Uninstall removes the helper, the auto-start entry and (optionally) the pairing list. It leaves the vendor driver alone.

## 4. Per system
**macOS:** `.pkg` (or signed app) for Apple Silicon and Intel; signed with an Apple Developer ID and notarised, else
Gatekeeper blocks it. Some token drivers are Intel-only and need Rosetta (already noted in the README). LaunchAgent for
auto-start. Menu-bar icon.
**Windows 10/11:** `.exe`/MSI installer (for example Inno Setup or WiX); signed with a code-signing certificate, else
SmartScreen warns (an EV certificate avoids the reputation wait). Startup entry or Scheduled Task. System-tray icon.
Known Windows driver paths are in the code for WatchData, ePass, SafeNet and ProxKey but none has been run on Windows.
Windows alternative to evaluate later: read certificates from the Windows certificate store (many tokens register
there), which avoids driver-path hunting but is a separate signing path.

## 5. Diagnostics and updates
- `erp-dsc-local --doctor` (to build): prints OS, helper version, port in use, config, which driver files were found,
  token present, the public certificate's name/issuer/expiry, and whether its CA root is pinned. No PIN, no secrets.
  A "Check my token" button in the tray icon runs it. (Token reads already run in a killable child process with a 15 s
  limit, so a hung vendor driver can no longer freeze the helper: exists today.)
- Logs: a size-capped log file in the user's folder with a "Copy support info" button; never contains the PIN.
- Updates: the helper checks a signed manifest; the user approves the update. No silent download without a signature check.
- Port busy: if 17777 is taken, say so and name the program using it.

## 6. Security requirements the installer must keep
Loopback only; no PIN or key material on disk, in logs, in the config, in argv or in the environment; config and pairing
files readable only by the user; code-signed installer and updates; only paired sites can use the token; the helper
never runs with more rights than the user.

## 7. Phases and rough effort
| Phase | Work | Rough effort |
|---|---|---|
| 0 | Done: killable token reads, open-token listing, plain-English picker, revocation fix | done |
| 1 | `--doctor`, friendlier errors, log file, InnaitKey/ePass driver paths, auto-restart wrapper | 2-3 days |
| 2 | macOS package: packaged build, LaunchAgent, menu-bar icon, signing and notarisation | 3-4 days (+ certificate lead time) |
| 3 | Windows package: packaged build, startup entry, tray icon, signing, driver paths on real tokens | 4-6 days (+ a Windows machine or VM + certificate lead time) |
| 4 | Signed-update check, uninstall, all-users/IT package, one-page admin guide | 3-4 days |
Total about 3 to 4 working weeks for both systems, mostly spent testing on real machines and tokens.

## 8. Acceptance tests (each recorded PASS/FAIL, no PIN in the record)
Clean Windows 10, Windows 11, Apple Silicon and Intel Mac; each token brand in the pilot; Chrome, Edge, Firefox, Safari;
install, reboot, sign without touching anything; kill the helper and see it return; token unplug and swap; sleep and wake;
upgrade over an older version; uninstall leaves nothing running; pairing refused and revoked; a non-CCA certificate refused.

## 9. Owner decisions (2026-11-10)
1. Order: **Windows first, then Mac.** Phase 3 (Windows) therefore moves ahead of Phase 2 (macOS).
2. Code-signing certificates: not needed to build or to run an internal pilot, but needed before real customers. Without them
   Windows SmartScreen shows "unknown publisher" (user must click More info, then Run anyway), some company antivirus or IT
   policies block the installer, and macOS Gatekeeper blocks an unsigned, un-notarised app. Decision: skip for the internal
   pilot, buy before customer rollout. Buy: an Apple Developer ID (annual) and a Windows code-signing certificate (annual).
3. Pilot token: **WatchData** (on Windows). The helper is designed for any token with a PKCS#11 driver, but each brand is
   treated as working only after a real signing run: WatchData and InnaitKey are proven on macOS; nothing is proven on Windows yet.
4. Updates: the user approves each update.
5. A status icon is in the first release.
6. Publish on the company website first; GitHub Releases afterwards. (GitHub allows files up to 2 GB, so a packaged helper
   of tens of MB would fit; to be confirmed once built.)

Revised order: Phase 1, then Phase 3 (Windows), then Phase 2 (macOS), then Phase 4.
