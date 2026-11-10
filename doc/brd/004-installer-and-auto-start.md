---
id: F4
title: Installable signer helper for Windows and Mac: starts by itself, finds the token driver, plain-English status
priority: P1
status: planned
covers: [F4]
spec: doc/plan/installer-plan.md
---

## Summary
Signing with a USB DSC needs a helper program (erp-dsc-local) on each user's computer. Today it is set up by hand and does
not start by itself: on 2026-11-10 it stopped silently and users saw "The local ERP DSC Signer is not running". This feature
makes the helper install like an ordinary app, start at login, restart if it stops, find the token's own driver, and show
its status. Owner decisions (2026-11-10): Windows first, then Mac; pilot token WatchData; user-approved updates; a status icon
in the first release; website distribution first.

Scope boundary: every security rule of F1 and F2 is unchanged (PIN never stored, logged or sent; loopback only; pairing
approval; CCA authentication before the PIN). The installer adds no new place where a secret can live.

## Acceptance criteria
- One download per system installs the helper without Python knowledge and, where the system allows it, without
  administrator rights. Uninstall removes the helper and its auto-start entry.
- The helper starts at login and is restarted automatically within seconds if it exits. A user who has enabled USB signing
  never has to start it by hand.
- The helper finds the token driver in the usual places and can be pointed at one by the user once; it never bundles vendor
  drivers.
- A status icon (menu bar or tray) shows running, paired sites and token detected, with Restart, Open logs and Check my
  token. Check my token reports names and certificate details only, never the PIN.
- When the helper is not reachable, the page tells the user in plain words what to do next.
- Updates are checked against a signed manifest and installed only after the user approves.
- Files the helper writes (configuration, pairing list, logs) are readable only by the user and never contain a PIN.

## Out of scope
Bundling vendor drivers; reading certificates from the Windows certificate store (to evaluate later); signing certificates for
the installer are bought separately before customer rollout; macOS package after the Windows one.

## Done when
- Tests prove: the packaged helper refuses a non-loopback bind; the config and pairing files are created with user-only
  permissions; no log line, file or process argument contains a sentinel PIN during a full signing run; the doctor report
  contains no secret.
- On a clean Windows 10/11 machine with a WatchData token: install, reboot, sign an invoice without starting anything by hand;
  kill the helper and it returns; unplug and replug the token and signing still works.
- Uninstall leaves no running process and no auto-start entry.
- Manual boot-and-click by the owner on Windows with the WatchData token, recorded as PASS or FAIL without the PIN.
