// Copyright (c) 2026, XLURSELF and contributors
// License: MIT

frappe.ui.form.on("Sales Invoice", {
	refresh(frm) {
		if (frm.is_new() || frm.doc.docstatus !== 1) return;
		const status = signature_status_label(frm.doc);
		if (status) frm.dashboard.add_indicator(frappe.utils.escape_html(status.label), status.color);
		const label = frm.doc.custom_digitally_signed ? __("Re-sign Digitally") : __("Sign Digitally");
		frm.add_custom_button(label, () => choose_signing_method(frm, frm.doc.custom_digitally_signed ? 1 : 0), __("Actions"));
		if (frm.doc.custom_digitally_signed && frm.doc.custom_signed_invoice_pdf) {
			frm.add_custom_button(__("Download Signed PDF"), () => {
				window.open(frappe.urllib.get_full_url(frm.doc.custom_signed_invoice_pdf), "_blank");
			}, __("Actions"));
		}
	},
});

// "Verified" only when the server-written record says verified === true (a boolean, not "true" or 1).
function signature_status_label(doc) {
	let record = null;
	try {
		record = JSON.parse(doc.custom_signature_verification || "null");
	} catch (_error) {
		record = null;
	}
	if (record && typeof record === "object" && record.verified === true) {
		return {label: __("Verified (CCA India chain, revocation checked)"), color: "green"};
	}
	if (doc.custom_digitally_signed) return {label: __("Signature valid"), color: "blue"};
	return null;
}

function choose_signing_method(frm, replace) {
	frappe.call({
		method: "erp_dsc_signer.api.signing.get_signing_options",
		freeze: true,
		callback(r) {
			const options = r.message || {};
			if (!options.methods || !options.methods.length) {
				frappe.msgprint(__("No signing method is enabled in DSC Signing Settings."));
				return;
			}
			const dialog = new frappe.ui.Dialog({
				title: __("Digitally Sign Sales Invoice"),
				fields: [
					{fieldname: "method", label: __("Signing Method"), fieldtype: "Select", options: options.methods.map((item) => item.id).join("\n"), default: options.default_method},
					{fieldname: "provider", label: __("USB Token Provider"), fieldtype: "Select", options: options.providers.map((item) => item.id).join("\n"), default: "auto", depends_on: "eval:doc.method === 'usb'"},
					{fieldname: "help", fieldtype: "HTML", options: `<p class="text-muted">${__("For USB signing, connect the token and start the local ERP DSC Signer. The first time you sign from this site, it will ask you on the desktop to allow it. Its PIN dialog only ever appears on this computer.")}</p>`},
				],
				primary_action_label: __("Continue"),
				primary_action(values) {
					dialog.hide();
					if (values.method === "usb") sign_with_usb(frm, replace, values.provider, options.local_signer_url);
					else sign_with_pfx(frm, replace);
				},
			});
			dialog.show();
		},
	});
}

function sign_with_pfx(frm, replace) {
	frappe.call({
		method: "erp_dsc_signer.api.signing.sign_with_pfx",
		args: {name: frm.doc.name, replace},
		freeze: true,
		freeze_message: __("Digitally signing invoice with PFX..."),
		callback: () => frm.reload_doc(),
	});
}

async function sign_with_usb(frm, replace, provider, base_url) {
	try {
		// Pair before anything server-side happens, so a workstation that is not yet
		// trusted never leaves a half-built signing session behind.
		await ensure_paired(base_url);
		const prepared = await frappe_request("erp_dsc_signer.api.signing.prepare_usb_signing", {name: frm.doc.name, replace, provider});
		const selected = await select_local_certificate(base_url, provider);
		const certificate = {fingerprint_sha256: selected.fingerprint_sha256};
		// F2: authenticate the certificate against the CCA India hierarchy BEFORE any PIN is requested.
		// A refusal rejects frappe_request and lands in the outer catch: nothing below runs.
		const authenticated = await frappe_request("erp_dsc_signer.api.signing.authenticate_usb_certificate", {
			session_id: prepared.session_id,
			certificate_der_base64: selected.der_base64,
		});
		// The server must have authenticated THE certificate the token will sign with; otherwise stop
		// before the token is ever asked for a nonce, a PIN or a signature.
		if (!authenticated || authenticated.verified !== true || authenticated.certificate_sha256 !== selected.fingerprint_sha256) {
			throw new Error(__("The authenticated certificate is not the selected DSC certificate, so the document was not signed."));
		}
		const sign_nonce = await local_request(base_url, "/v1/nonce", "POST", {purpose: "sign"});
		frappe.dom.freeze(__("Click the signer window, then type your PIN"));
		const signed = await local_request(base_url, "/v1/sign", "POST", {
			nonce: sign_nonce.nonce,
			provider,
			certificate,
			pdf_base64: prepared.pdf_base64,
			pdf_sha256: prepared.pdf_sha256,
			signing_request: prepared.signing_request,
		});
		const completed = await frappe_request("erp_dsc_signer.api.signing.complete_usb_signing", {
			session_id: prepared.session_id,
			nonce: prepared.nonce,
			signed_pdf_base64: signed.signed_pdf_base64,
			certificate_metadata: signed.certificate_metadata,
		});
		// Only the server's record may say "verified" (CCA India chain, revocation checked).
		if (completed && completed.verification && completed.verification.verified === true) {
			frappe.show_alert({message: __("Signed and verified (CCA India chain, revocation checked)"), indicator: "green"});
		}
		frm.reload_doc();
	} catch (error) {
		frappe.msgprint({title: __("USB DSC Signing"), indicator: "red", message: frappe.utils.escape_html(error.message || __("Signing could not be completed."))});
	} finally {
		frappe.dom.unfreeze();
	}
}

async function select_local_certificate(base_url, provider) {
	const nonce = await local_request(base_url, "/v1/nonce", "POST", {purpose: "certificates"});
	const result = await local_request(base_url, "/v1/certificates", "POST", {nonce: nonce.nonce, provider});
	const certificates = result.certificates || [];
	if (!certificates.length) throw new Error(__("No signing certificate is available on the connected token."));
	if (certificates.length === 1) return {fingerprint_sha256: certificates[0].fingerprint_sha256, der_base64: certificates[0].der_base64};
	return new Promise((resolve, reject) => {
		const dialog = new frappe.ui.Dialog({
			title: __("Select DSC Certificate"),
			fields: [{fieldname: "fingerprint", label: __("Certificate"), fieldtype: "Select", options: certificates.map((cert) => `${cert.fingerprint_sha256}\t${cert.common_name || cert.subject}`).join("\n")}],
			primary_action_label: __("Use Certificate"),
			primary_action(values) { dialog.hide(); const fingerprint = values.fingerprint.split("\t")[0]; const chosen = certificates.find((cert) => cert.fingerprint_sha256 === fingerprint); resolve({fingerprint_sha256: fingerprint, der_base64: chosen && chosen.der_base64}); },
		});
		dialog.$wrapper.on("hidden.bs.modal", () => reject(new Error(__("Certificate selection was cancelled."))));
		dialog.show();
	});
}

async function frappe_request(method, args) {
	return new Promise((resolve, reject) => frappe.call({method, args, callback: (r) => resolve(r.message), error: (r) => reject(new Error(r._server_messages ? JSON.parse(r._server_messages)[0] : __("ERPNext rejected the request.")))}));
}

class LocalSignerError extends Error {
	constructor(message, code) {
		super(message);
		this.code = code;
	}
}

async function local_request(base_url, path, method, body) {
	const options = {method};
	if (body !== undefined) {
		options.body = JSON.stringify(body);
		// Set only when a body exists. A Content-Type on a GET makes it a non-simple
		// request, forcing a CORS preflight that an unpaired origin cannot complete —
		// which is how "not paired" used to masquerade as "not reachable".
		options.headers = {"Content-Type": "application/json"};
	}
	let response;
	try {
		response = await fetch(`${base_url.replace(/\/$/, "")}${path}`, options);
	} catch (_error) {
		// A rejected fetch means no HTTP response at all: nothing is listening.
		throw new LocalSignerError(
			__("The local ERP DSC Signer is not running on this computer. Start it and try again."),
			"SIGNER_OFFLINE"
		);
	}
	const payload = await response.json().catch(() => ({}));
	if (!response.ok || !payload.ok) {
		const error = (payload && payload.error) || {};
		throw new LocalSignerError(error.message || __("The local signer rejected the request."), error.code);
	}
	return payload;
}

function confirm_pairing() {
	return new Promise((resolve) => {
		frappe.confirm(
			__("This computer has not been paired with this ERP site yet.") +
				`<br><br><b>${frappe.utils.escape_html(window.location.origin)}</b><br><br>` +
				__("A dialog will appear on your desktop asking you to allow it. Check that the address shown there matches the one above before you allow it."),
			() => resolve(true),
			() => resolve(false)
		);
	});
}

async function ensure_paired(base_url) {
	const health = await local_request(base_url, "/v1/health", "GET");
	if (health.paired) return;

	if (!(await confirm_pairing())) {
		throw new LocalSignerError(__("Pairing was cancelled."), "PAIR_CANCELLED");
	}

	const issued = await frappe_request("erp_dsc_signer.api.pairing.issue_pairing_token", {});
	// The token is bound to the origin this site derived from the request. If that is
	// not the address in the browser, pairing the workstation would trust the wrong
	// name — stop rather than silently pair something the user cannot verify.
	if (!issued || issued.origin !== window.location.origin) {
		throw new LocalSignerError(
			__("This site reported its address as {0} but your browser is on {1}. Pairing was stopped.", [
				(issued && issued.origin) || "?",
				window.location.origin,
			]),
			"ORIGIN_MISMATCH"
		);
	}
	await local_request(base_url, "/v1/pair", "POST", {pairing_token: issued.token});
}
