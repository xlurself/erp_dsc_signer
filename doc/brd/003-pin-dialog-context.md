---
id: F3
title: PIN dialog shows what is being signed, by whom, and whether the certificate was verified
priority: P1
status: planned
covers: [F3]
spec: doc/spec/001-secure-pin-entry.md
---

## Summary
The PIN dialog already looks like the Frappe desk (visual-only change, 2026-11-10) and shows the site origin and one
"as described by the site" line. The user still cannot see, at the moment of typing the PIN, WHICH certificate will
sign and whether the app has already verified it. This feature adds three read-only lines so the user can check
before typing. Owner approved the three lines on 2026-11-10.

Scope boundary: every F1 security rule is unchanged (PIN only in the masked box, never logged or stored; click
guard; origin first and never shortened; Escape/close = cancel). No new field accepts input.

## Acceptance criteria
- The dialog shows, below the origin and above the PIN box: **Document** (the invoice name), **Certificate** (holder
  name and valid-to date), **Verified** ("CCA India chain, not revoked" only when the server authenticated this exact
  certificate; otherwise the line is not shown).
- **Certificate** holder and validity are read by the signer itself from the token's public certificate, never taken
  from the site's request. **Document** and **Verified** come from the site and are labelled as the site's claim,
  like the existing "as described by the site" line.
- All new text passes the same cleaning as the existing claims: control and direction-changing characters removed,
  length capped, one line each. Text that cannot be cleaned is dropped, never shown raw.
- The origin line stays the first and largest text. A long value can never push the origin or the PIN box off the
  screen; if the dialog cannot fit, it refuses as it does today.
- The layout stays readable in the Frappe style on macOS and Windows.

## Out of scope
Showing the full certificate chain, the amount or customer of the invoice, a show-PIN toggle, any editable field.

## Done when
- Tests prove each new line appears with the right source (token for the certificate, site claim for the rest) and is
  cleaned (control/bidi/over-length input is dropped or capped).
- A test proves a site that sends a false certificate name cannot change the Certificate line.
- Existing guard, secrecy and origin-first tests pass unchanged.
- A screenshot of the real dialog on macOS shows the three lines and an obvious PIN box.
- Manual boot-and-click: sign XL-SI-26-0000014 with the Watchdata token; the lines match the real certificate.
