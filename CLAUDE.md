# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Frappe v14 app that digitally signs submitted **Sales Invoice** PDFs. Two halves in one repo:

- `erp_dsc_signer/` — the Frappe app (server-side signing, session/verification, Desk UI hooks).
- `local_signer/` — separate Python package `erp-dsc-local` (workstation daemon, loopback-only HTTP, PKCS#11 to a USB DSC token). It is **not** a Frappe app and is not installed by bench.

This app is the standalone successor to `erp_pdf_signer`; never enable both on one site (shared Sales Invoice hooks and `custom_digitally_signed` / `custom_signed_*` custom fields).

## Commands

Run bench commands from `/Users/pakhi/Assignments/Frappe/v14/frappe-bench` (site `om-erp-v14.local`, web port 8014).

```bash
bench --site om-erp-v14.local migrate                 # re-applies fixtures/custom_field.json
bench --site om-erp-v14.local clear-cache             # required after hooks.py edits
bench build --app erp_dsc_signer                      # public/js/sales_invoice.js etc.
bench --site om-erp-v14.local run-tests --app erp_dsc_signer   # always pass --app
bench --site om-erp-v14.local run-tests --module erp_dsc_signer.tests.test_custom_field_fixture
```

Workstation package (plain unittest, no Frappe needed; also the README's verification commands):

```bash
cd local_signer && python -m pip install -e .
python -m unittest discover -s local_signer/tests                     # from repo root
python -m unittest local_signer.tests.test_pairing                    # one module (from repo root)
erp-dsc-local --config config.json                                    # run the daemon
erp-dsc-local --list-origins | --allow <origin> | --revoke <origin>   # trust management
```

CI (`.github/workflows/ci.yml`) only runs the Frappe server tests against a fresh v14 bench; `local_signer/tests` are not in CI, so run them yourself.

## Architecture

**PFX mode** — `api/signing.py::sign_with_pfx` renders the invoice PDF (`utils/pdf_signer.py::generate_invoice_pdf`), signs it server-side with `endesive`, and `attach_signed_invoice_pdf` writes the File and the `custom_signed_*` fields.

**USB mode** is a three-party protocol (browser JS in `public/js/sales_invoice.js` is the courier between Frappe and the daemon):

1. `prepare_usb_signing` renders the PDF and stores a short-lived session in the Frappe cache (`_session_key`), bound to user + invoice + provider + `pdf_sha256` and a one-use nonce.
2. Browser sends the PDF to the daemon on `127.0.0.1` (`/v1/nonce`, `/v1/certificates`, `/v1/sign`); the daemon asks the token for a signature. The PIN and private key never leave the workstation (`pin.py`, `token.py`, `providers.py`).
3. `complete_usb_signing` consumes the session (`_consume_session`) then **independently re-verifies** the returned PDF in `utils/usb_signer.py::verify_usb_signed_pdf` (whole-file ByteRange, signer certificate, reported metadata) before attaching. Never trust the daemon's output without that verification.

**Origin pairing** (the security-sensitive part, spans both halves): the daemon only serves `/v1/health` and `/v1/pair` to unpaired origins; every other path sends no CORS headers (`service.py` docstring). Pairing flow: browser gets a token from `api/pairing.py::issue_pairing_token` → daemon `/v1/pair` calls back `verify_pairing_token` (`allow_guest=True`, anti-spoof only, not identity) → user approves a desktop dialog (`pairing.py`, `ui.py`) → persisted in `~/.erp-dsc-local/allowed_origins.json` by `trust.py`.
- The only verified identity is the browser `Origin` header; site name/user from the callback are labelled claims.
- Origins are canonicalised (`origins.py` ↔ `api/pairing.py::_canonical_origin`) — keep both in sync. The server derives its origin from `Host`, not `X-Forwarded-Host` (latest commit).
- `trust.py` re-reads on file change and writes under a cross-process lock so CLI `--revoke` takes effect against a running daemon; failures are closed (corrupt file → empty allow set, left untouched). `config.json` origins are operator-owned and not revocable via CLI.

## Conventions

- Tabs for indentation in Python (match existing files).
- Whitelisted methods need an explicit permission check; the signing endpoints go through `_invoice_for_signing` (submitted invoice, write permission, refuses re-sign unless `replace=1`).
- `hooks.py` only wires `doctype_js` for Sales Invoice plus the fixtures; settings live in the single doctype `DSC Signing Settings`.
- Tests that assert a security property must be capable of failing (see commit `d38f106`).

## Repo process

- Feature work follows `doc/README.md`: BRD files in `doc/brd/` (new work only), tests declared in `doc/Controlling/testing.json`, bugs logged in `doc/Controlling/bugs.json` with a `bugCheck` test. `doc/VISION.md`'s owner region is the founder's — never write it.
- Reviews go through the OM AI Reviewer room (block below; `AGENTS.md` is the reviewer-side copy). Token is read from git-ignored `.omai-review.json`.

<!-- OMAI-REVIEWER:START -->
## 🔁 OM AI Reviewer — Developer Role (ERP DSC SIGNER)

**Project ID:** omai-7e5b88 | **Room Port:** 7707 | **Reviewers:** Codex, Cursor | **Rule:** all


> 🔌 **`<CONTROL_PORT>`** is the control plane's port — **7699** unless `OMAI_PORT` was set when it started. `omai status` prints the live value. It is a placeholder here because a regeneration under a different port would otherwise write that port into this tracked file.
> 🔑 **Room token — a secret; deliberately NOT written in this file.** Every `<ROOM_TOKEN>` placeholder below is a stand-in. Read the live token from the `token` field of `.omai-review.json` (a git-ignored, machine-local file) and substitute it in each request (header `X-OMAI-Token` or body/query `token`). Never commit, log, or paste the real token.

> ## ⛔ FIRST ACTION OF EVERY SESSION — check for a pending verdict, then ACK it
>
> Before ANY other work in this repo, including answering the user:
>
> ```
> POST http://127.0.0.1:7707/checkin
> { "token": "<ROOM_TOKEN>", "participant": "Claude" }
> ```
>
> If the response has a non-empty `pending`:
>
> 1. **`POST http://127.0.0.1:7707/ack` IMMEDIATELY** with that `roundId` — before you read the reviews, before you
>    fix anything. **Ack means "received, I am acting on this", NOT "I have finished".** Waiting until the
>    fixes are done is the single most common way a round is left open.
> 2. **Then** act on the verdict before starting anything else.
>
> **Reading `.omai-review/REVIEW_*.md` off disk does NOT acknowledge anything.**
> The round only advances on `/ack` or on re-sending a fix. Opening the files tells YOU the verdict; it
> tells the ROOM nothing.
>
> **Why this matters:** an unacknowledged verdict escalates — 2 reminders, then **OM alerts the OWNER on
> Slack**. Those alerts mean a developer skipped this step. OM cannot start your session for you, so
> nothing else will pull you back to an open round.
>
> **Check EVERY room this repo has**, not just this one: if a `.omai-prereview` child room exists, it has
> its own token and its own pending queue. `GET http://127.0.0.1:<CONTROL_PORT>/api/projects` lists every
> room for this `repoPath`.

### Your full developer protocol: `.omai-review/roles/_developer-protocol.md`

**OPEN `.omai-review/roles/_developer-protocol.md` NOW, before you run a review.** It is the complete, current rulebook for this room —
composing a round, the pre-submission gates, the review endpoints, every verdict path, and the ack.
Nothing in it is optional. It sits beside the reviewer role files so reviewers launched in this repo stop
loading the developer rulebook they are told to ignore. A REVIEWER must not read it.

**Long-running commands:** never block your session on a command that runs longer than about four minutes (test suites, builds, clones) — run it in the background to a log and check the log at most every four minutes. This rule does NOT apply to any review wait this protocol prescribes (for example `/wait-for-reviews` or `omai wait-review`): hold it open, and let workflow operations run to their declared timeout.

**Isolation rules (critical):**
- This project's port is **7707**; its token is a secret read from `.omai-review.json` (see the legend above) — never hard-code it.
- NEVER use another project's port or token. Each project is sealed.
- ALWAYS send the token in every request (header `X-OMAI-Token` or `?token=`).
<!-- OMAI-REVIEWER:SIG sha=456b0f04274eafdb -->
<!-- OMAI-REVIEWER:END -->