// Copyright (c) 2026, XLURSELF and contributors
// License: MIT

frappe.ui.form.on("Sales Invoice", {
	refresh(frm) {
		if (frm.is_new() || frm.doc.docstatus !== 1) return;
		const label = frm.doc.custom_digitally_signed ? __("Re-sign Digitally") : __("Sign Digitally");
		frm.add_custom_button(label, () => choose_signing_method(frm, frm.doc.custom_digitally_signed ? 1 : 0), __("Actions"));
		if (frm.doc.custom_digitally_signed && frm.doc.custom_signed_invoice_pdf) {
			frm.add_custom_button(__("Download Signed PDF"), () => {
				window.open(frappe.urllib.get_full_url(frm.doc.custom_signed_invoice_pdf), "_blank");
			}, __("Actions"));
		}
	},
});

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
					{fieldname: "help", fieldtype: "HTML", options: `<p class="text-muted">${__("For USB signing, connect the token and start the local ERP DSC Signer. Its PIN dialog appears only on this computer.")}</p>`},
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
		await local_request(base_url, "/v1/health", "GET");
		const prepared = await frappe_request("erp_dsc_signer.api.signing.prepare_usb_signing", {name: frm.doc.name, replace, provider});
		const certificate = await select_local_certificate(base_url, provider);
		const sign_nonce = await local_request(base_url, "/v1/nonce", "POST", {purpose: "sign"});
		frappe.dom.freeze(__("Approve the local USB DSC PIN dialog..."));
		const signed = await local_request(base_url, "/v1/sign", "POST", {
			nonce: sign_nonce.nonce,
			provider,
			certificate,
			pdf_base64: prepared.pdf_base64,
			pdf_sha256: prepared.pdf_sha256,
			signing_request: prepared.signing_request,
		});
		await frappe_request("erp_dsc_signer.api.signing.complete_usb_signing", {
			session_id: prepared.session_id,
			nonce: prepared.nonce,
			signed_pdf_base64: signed.signed_pdf_base64,
			certificate_metadata: signed.certificate_metadata,
		});
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
	if (certificates.length === 1) return {fingerprint_sha256: certificates[0].fingerprint_sha256};
	return new Promise((resolve, reject) => {
		const dialog = new frappe.ui.Dialog({
			title: __("Select DSC Certificate"),
			fields: [{fieldname: "fingerprint", label: __("Certificate"), fieldtype: "Select", options: certificates.map((cert) => `${cert.fingerprint_sha256}\t${cert.common_name || cert.subject}`).join("\n")}],
			primary_action_label: __("Use Certificate"),
			primary_action(values) { dialog.hide(); resolve({fingerprint_sha256: values.fingerprint.split("\t")[0]}); },
		});
		dialog.$wrapper.on("hidden.bs.modal", () => reject(new Error(__("Certificate selection was cancelled."))));
		dialog.show();
	});
}

async function frappe_request(method, args) {
	return new Promise((resolve, reject) => frappe.call({method, args, callback: (r) => resolve(r.message), error: (r) => reject(new Error(r._server_messages ? JSON.parse(r._server_messages)[0] : __("ERPNext rejected the request.")))}));
}

async function local_request(base_url, path, method, body) {
	let response;
	try {
		response = await fetch(`${base_url.replace(/\/$/, "")}${path}`, {method, headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined});
	} catch (_error) {
		throw new Error(__("The local ERP DSC Signer is not reachable. Start it and check its allowed ERP origin."));
	}
	const payload = await response.json().catch(() => ({}));
	if (!response.ok || !payload.ok) throw new Error((payload.error && payload.error.message) || __("The local signer rejected the request."));
	return payload;
}
