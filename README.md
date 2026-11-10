# ERP DSC Signer

Digital signing for submitted ERPNext Sales Invoice PDFs using either a server-side PFX certificate or a DSC USB token attached to the user's Windows or macOS workstation.

## Signing modes

- **PFX Certificate:** Frappe loads a private PFX file and signs on the server.
- **USB DSC Token:** Frappe prepares the exact PDF, the workstation signer asks the token for a signature through its PKCS#11 middleware, and Frappe verifies the result before attaching it.

The USB private key and PIN never leave the token or workstation. Prepared signing sessions are short-lived, one-use, and bound to the user, invoice, provider, and PDF digest.

## Installation

```bash
cd frappe-bench
bench get-app erp_dsc_signer <repository-url>
bench --site <site> install-app erp_dsc_signer
bench build --app erp_dsc_signer
bench --site <site> migrate
```

Configure **DSC Signing Settings**, enable one or both methods, validate the PFX when applicable, and set the print format, signature appearance, and timestamp authority.

This app is the standalone successor to `erp_pdf_signer`. Do not enable both apps on the same site: both integrate with Sales Invoice and reuse the existing signature custom fields for migration compatibility. Existing signed-file links and audit history remain usable.

### Frappe Cloud (Frappe v14, v15, v16)

1. In your Frappe Cloud dashboard open the bench group, choose **Apps → Add App → Add from GitHub**, select this repository and the `main` branch, and deploy. The app declares ERPNext as a required app and supports Frappe 14, 15 and 16.
2. Install **ERP DSC Signer** on the site (**Site → Apps → Install App**). Installing creates the read-only signing fields on Sales Invoice.
3. Open **DSC Signing Settings**, enable the USB method, and keep the workstation signer address `http://127.0.0.1:17777`.
4. The server must be able to reach the certifying authority for the revocation check (`signxca.com`, `ocsp.signxca.com`, `ocvs.gov.in`, `cca.gov.in`). Frappe Cloud allows outbound web access by default.
5. On each user's computer install the workstation signer (see below) and the USB token's own driver, then pair the site once from the Sign dialog.

USB signing never sends the PIN or the private key to the server. Only the certifying authority (CCA India) hierarchy is trusted: a certificate that cannot be authenticated through it is refused and nothing is signed.

## Workstation signer

The companion package is in `local_signer/`. Install it on each workstation that uses a USB token:

```bash
cd local_signer
python -m pip install -e .
cp config.example.json config.json
erp-dsc-local --config config.json
```

The service binds only to loopback. Supported provider profiles include ePass, SafeNet, ProxKey, WatchData, and a configured generic PKCS#11 module. The token vendor's current middleware is still required, and Apple Silicon needs a compatible native or Rosetta driver.

### Pairing a site

`allowed_origins` can be left empty. The first time you sign from a given ERP site, the
signer asks on the desktop whether to allow it and remembers the answer in
`~/.erp-dsc-local/allowed_origins.json`. Nothing needs to be edited by hand, which
matters when the same build is installed on workstations nobody can pre-configure.

The dialog shows the site's address exactly as the browser sent it. Allow it only when
it matches the address in your browser's own address bar.

Manage trusted sites without a desktop session — useful over SSH, and the fallback when
the workstation has no route back to the site:

```bash
erp-dsc-local --list-origins
erp-dsc-local --allow https://erp.example.com
erp-dsc-local --revoke https://erp.example.com
```

Origins listed in `config.json` are owned by whoever manages the workstation: they need
no pairing and `--revoke` will not remove them. Use that to pre-approve a fleet.

### Support and setup commands

None of these opens a window or asks for a PIN, and none loads a token driver in the helper's
own process. Without `--config` they use `~/.erp-dsc-local/config.json`.

```bash
erp-dsc-local --doctor                          # support report: versions, port, drivers, certificates (no secrets)
erp-dsc-local --find-drivers                    # list token driver files in the usual folders (nothing is loaded)
erp-dsc-local --add-module /absolute/path/libvendor-pkcs11.dylib --verify   # add a driver to config.json
erp-dsc-local --show-log-path                   # where the log file is (logs/erp-dsc-local.log next to config.json)
erp-dsc-local --install-autostart [--yes]       # start at every login (macOS LaunchAgent, Windows Scheduled Task)
erp-dsc-local --uninstall-autostart [--yes]     # remove that login entry again
```

`--install-autostart` and `--uninstall-autostart` only print what they would change unless
`--yes` is given. `--add-module` keeps the previous file as `config.json.bak`. Restart the
signer after adding a driver.

For administrators: when the page says "The ERP DSC Signer program is not running on this
computer", run `erp-dsc-local --doctor` on that computer. It shows whether the helper is
running, whether its port is taken by another program, and which token drivers and
certificates it can see.

## Verification

```bash
python -m unittest discover -s erp_dsc_signer/tests
python -m unittest discover -s local_signer/tests
bench build --app erp_dsc_signer
```

Hardware acceptance testing must cover each supported token/driver/OS combination. Confirm the PDF in Adobe Reader, certificate chain and validity, TSA timestamp, re-sign history, and duplicated-invoice behavior.

## License

MIT
