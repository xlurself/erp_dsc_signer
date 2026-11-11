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
- `erp-dsc-local --doctor` (built in Phase 1, see 7a): prints OS, helper version, port in use, config, which driver files were found,
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

## 7a. Phase 1 as built (2026-11-10, committed in a415024)
What exists now in `local_signer/` (all commands are explicit; nothing runs by itself yet):
- `erp-dsc-local --doctor [--config PATH]`: plain-text support report (`doctor.py`). System, helper and Python version, config
  path and whether it loads, port free / in use / in use by this helper, how many sites are allowed (never which), log path,
  every driver location the registry knows (found / missing) and, for each found driver, a token check through the killable
  probe child (15 s limit): no token / driver not responding / N certificates with common name, organisation, issuer, valid-to,
  signing yes/no and the first 8 hex of the fingerprint. Never DER, serial numbers, token serial or label, PIN. Exit 0.
- `erp-dsc-local --find-drivers`: lists PKCS#11-looking library files in fixed folders per system (macOS `/usr/local/lib`,
  `/opt`, `/Library`; Windows `System32`, `SysWOW64`, `Program Files*`), shallow, bounded (50 000 entries, 10 s), no symlinked
  folders, nothing loaded (`drivers.py`).
- `erp-dsc-local --add-module PATH [--verify]`: validates the file (absolute, plain, regular, library extension, readable, not
  replaceable by the group or others, nor any folder above it, owned by root or the user) and adds it to `providers.custom_modules`, atomically, with `config.json.bak`; `--verify` asks the
  probe child first. Never loads the library in the helper's own process.
- Driver paths: InnaitKey `/opt/Precision_Biometric/InnaITDSC/libraries/libInnaITPKCS11Driver.dylib` (as Generic PKCS#11: the
  ERP server accepts only its fixed provider list) and ePass `/usr/local/lib/libcastle_v2.1.0.0.dylib`.
- Log file `<config folder>/logs/erp-dsc-local.log` (1 MB x 3 rotated, 0600 in a 0700 folder; `logs.py`): startup, shutdown,
  signals, a failed request (route and exception class only), background-thread errors, a heartbeat every 10 minutes;
  `faulthandler` writes fatal crashes to `erp-dsc-local-crash.log`. `erp-dsc-local --show-log-path` prints where it is.
- `erp-dsc-local --install-autostart` / `--uninstall-autostart` (`autostart.py`): prints exactly what it will change and stops
  unless `--yes` is given. macOS: `~/Library/LaunchAgents/com.xlurself.erp-dsc-local.plist` (RunAtLoad, KeepAlive,
  ThrottleInterval 5, Umask 077) loaded with `launchctl bootstrap gui/<uid>`. Windows: per-user Scheduled Task "ERP DSC Signer"
  at logon, LeastPrivilege, restart on failure, created with `schtasks /Create /XML`. Linux: not supported. Uninstall removes
  only the entry this tool wrote.
- The Sales Invoice page now says in plain words what to do when the helper is not running, when this computer declined the
  site, and when the site is not yet allowed.

NOT done in Phase 1: a packaged build (PyInstaller), the tray / menu-bar icon, code signing and notarisation, signed updates,
and any run on Windows. The Windows code (task XML, driver folders, `schtasks` calls) is unit-tested with mocks on macOS
only; nothing is proven on Windows. Task Scheduler's shortest restart interval is 1 minute (not "within seconds"), and whether
it restarts a task whose program exits on its own must be checked on Windows (a small supervisor may be needed). The auto-start
commands were exercised only through mocks and a dry run, never for real on a workstation.

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

## 10. Windows pilot results (2026-11-10 and 11, Windows 11, Python 3.14 64-bit, WatchData ProxKey, Frappe Cloud site)
Rounds 1 to 3 (commits a415024, b28d300, 5beb2da): install, `--find-drivers`, `--doctor` (certificate read from the x64
`System32\SignatureP11.dll` with no PIN), `--add-module`, `--install-autostart` dry run, health, Ctrl+C clean stop: PASS after the
fixes recorded in those commits (valid example config, one version number, built-in `--add-module` exits 0, look-alike
files filtered, 32-bit drivers tagged, packaging with a `logs` folder).
First real signing on Windows against a Frappe Cloud site: the PDF was produced and its signature verifies (digest and RSA
signature checked independently). Two defects were found and fixed: the timestamp request failed on a network that blocks the
timestamp server (now off by default), and the signing time was the site clock labelled with the server zone (Adobe: "signed in
future"). NOT yet tested on Windows: `--install-autostart --yes`, log off and on, the PIN window focus, pairing from a second
browser, Windows 10, 32-bit Python, an InnaIT token. The Mac signing with the InnaitKey organisation DSC on the same site
produced a valid file; Adobe's refusal to open it is unexplained (exact message requested).
Review fixes (2026-11-11, panel round 6): the LaunchAgent no longer writes stdout/stderr to files (/dev/null; the capped daemon
log is the record, `--doctor` shows config problems); the crash log is rotated at start when over the size cap (only its last 1 MB is kept as .1); on Windows
`--add-module` first requires the driver to be under Windows or Program Files (never a network path, never through a link or
junction), then reads the real permissions (GetNamedSecurityInfoW + GetEffectiveRightsFromAclW through ctypes) and refuses a
driver that Everyone, Authenticated Users or Users can write, or whose folder they can write, or whose parent folders they can
rename or delete; a permission it cannot read is a refusal (unit-tested with injected rights; the real Windows API call is
verified on a Windows machine, see section 10); `--install-autostart --yes` /
`--uninstall-autostart --yes` refuse root (macOS) and an elevated prompt (Windows); `--find-drivers` reads a folder lazily
within its bounds; adding an already known or configured driver is exit 0 before the strict file check.
Remaining residuals: a failing auto-start can still restart every few seconds (only the capped log records it; Task Scheduler
restart behaviour on Windows is untested); signing/probe failure lines go to stderr only (lost under pythonw on Windows);
the daemon itself does not skip 32-bit drivers (the doctor and `--find-drivers` do); log/config files on Windows rely on the
user-profile default permissions (no explicit ACL code).
