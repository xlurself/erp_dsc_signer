# PIN dialog redesign (proposal, needs BRD amendment before any code)

Status: proposal 2026-11-10. The PIN dialog is security-critical (BRD 001, panel-approved). This changes what it shows, so it needs an owner-approved BRD amendment and a panel round. No code has been changed.

## Problems with today's dialog (`dialog_child.py::build_pin_window`)
- Plain default Tk look: bold origin line, claim lines, a bare password box, a grey hint line, two plain buttons.
- The user cannot see WHICH certificate/holder and WHICH document they are about to sign.
- The box is disabled until a click, with hint text that changes ("wait", "click again"). It reads as broken.
- No remaining-attempts display except the final-try warning.

## Proposed layout (same guards, same fields, better hierarchy)

```
+--------------------------------------------------+
|  [lock]  Sign with your USB DSC token            |
|                                                  |
|  Requested by    http://om-erp-v14.local:8014    |   (origin: large, never elided, unchanged rule)
|  Document        XL-SI-26-0000013                |   (NEW, from the verified signing request)
|  Certificate     Vinay Saraf  (valid to 2027-..) |   (NEW, from the authenticated certificate)
|  Authenticated   CCA India chain, not revoked    |   (NEW, only shown if the server verified it)
|                                                  |
|  Token PIN                                       |
|  [ ************                    ]             |   (wider box, 14 pt, focus ring)
|  3 attempts left before the token locks          |   (NEW when the token reports it)
|                                                  |
|            [ Cancel ]      [ Sign document ]     |   (primary button emphasised, Enter = Sign)
|  Click the box to begin typing.                  |   (one stable hint; guard timing unchanged)
+--------------------------------------------------+
```

## Must not change (security invariants from BRD 001)
- PIN only on stdin/child process; never logged; the entry is cleared after use.
- Click-to-enable guard (`_InputGuard`) and the ignore-first-click rule stay exactly as they are.
- Origin shown in the largest font, never wrapped or elided; claims drawn no larger than the origin.
- No "show PIN" toggle. No copy/paste of the PIN out of the box.
- Escape / close = cancel; final-try tick-box stays.

## New text is data from outside the dialog, so it is untrusted
Document name and certificate holder come from the paired site's request. They must pass the same cleaning as `_clean_claim` (no control/bidi characters, length caps) and be labelled as claims (like the existing claim lines), except the certificate holder, which should come from the daemon's own read of the token, not from the site.

## Work if approved
1. BRD amendment (BRD 001 or new F3) for the new fields, owner approves on the dashboard.
2. Spec update, tests first: layout structure tests, claim-cleaning tests for the new fields, guard tests unchanged and still passing.
3. Implement in `dialog_child.py` only (plus `validate_request` for the new fields).
4. Real check on macOS and Windows (Tk looks different per OS) and the OM panel.
