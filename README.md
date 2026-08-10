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

## Workstation signer

The companion package is in `local_signer/`. Install it on each workstation that uses a USB token:

```bash
cd local_signer
python -m pip install -e .
cp config.example.json config.json
erp-dsc-local --config config.json
```

Set the exact ERP origin in `allowed_origins`. The service binds only to loopback. Supported provider profiles include ePass, SafeNet, ProxKey, WatchData, and a configured generic PKCS#11 module. The token vendor's current middleware is still required, and Apple Silicon needs a compatible native or Rosetta driver.

## Verification

```bash
python -m unittest discover -s erp_dsc_signer/tests
python -m unittest discover -s local_signer/tests
bench build --app erp_dsc_signer
```

Hardware acceptance testing must cover each supported token/driver/OS combination. Confirm the PDF in Adobe Reader, certificate chain and validity, TSA timestamp, re-sign history, and duplicated-invoice behavior.

## License

MIT
