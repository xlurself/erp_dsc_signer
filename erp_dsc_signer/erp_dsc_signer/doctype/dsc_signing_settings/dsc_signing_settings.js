// Copyright (c) 2026, XLURSELF and contributors
// License: MIT

frappe.ui.form.on("DSC Signing Settings", {
	onload(frm) {
		frm.trigger("set_validation_indicator");
	},

	refresh(frm) {
		frm.set_intro(
			__(
				"PFX signing runs on the Frappe server. USB DSC signing requires the local signer app and the token vendor's middleware on each user's computer. Token PINs never pass through ERPNext."
			)
		);
		frm.trigger("set_validation_indicator");
	},

	pfx_file(frm) {
		frm.trigger("reset_validation_fields");
	},

	pfx_password(frm) {
		frm.trigger("reset_validation_fields");
	},

	validate_now(frm) {
		if (!frm.doc.pfx_file) {
			frappe.show_alert({
				message: __("Upload a PFX certificate file first."),
				indicator: "orange",
			});
			return;
		}

		frappe.call({
			method: "erp_dsc_signer.api.settings.validate_pfx_certificate",
			args: {
				pfx_file: frm.doc.pfx_file,
				pfx_password: frm.doc.pfx_password || "",
			},
			freeze: true,
			freeze_message: __("Validating PFX certificate..."),
			callback(r) {
				const result = r.message || {};
				frm.set_value(
					"certificate_validation_status",
					result.certificate_validation_status || "Invalid"
				);
				frm.set_value(
					"certificate_validation_message",
					result.certificate_validation_message || ""
				);
				frm.set_value("certificate_subject", result.certificate_subject || "");
				frm.set_value("certificate_valid_till", result.certificate_valid_till || "");
				frm.trigger("set_validation_indicator");

				frappe.show_alert({
					message: result.certificate_validation_message || __("Validation completed."),
					indicator: result.valid ? "green" : "red",
				});
			},
		});
	},

	test_tsa(frm) {
		if (!frm.doc.timestamp_url) {
			frappe.show_alert({ message: __("Set a TSA URL first."), indicator: "orange" });
			return;
		}

		frappe.call({
			method: "erp_dsc_signer.api.settings.test_tsa_connectivity",
			args: { timestamp_url: frm.doc.timestamp_url },
			freeze: true,
			freeze_message: __("Probing TSA..."),
			callback(r) {
				const result = r.message || {};
				if (!result.ok) {
					frappe.msgprint({
						title: __("TSA Unreachable"),
						indicator: "red",
						message: frappe.utils.escape_html(
							result.message || __("The timestamp authority could not be reached.")
						),
					});
					return;
				}

				frappe.msgprint({
					title: __("TSA Connectivity"),
					indicator: "green",
					message: __("TSA reachable. HTTP {0}, {1} ms.", [
						result.http_status,
						result.latency_ms,
					]),
				});
			},
		});
	},

	reset_validation_fields(frm) {
		frm.set_value("certificate_validation_status", "Not Validated");
		frm.set_value("certificate_validation_message", "");
		frm.set_value("certificate_subject", "");
		frm.set_value("certificate_valid_till", "");
		frm.trigger("set_validation_indicator");
	},

	set_validation_indicator(frm) {
		const status = frm.doc.certificate_validation_status;
		const indicator = status === "Valid" ? "green" : status === "Invalid" ? "red" : "blue";

		frm.dashboard.clear_headline();
		if (frm.doc.enable_pfx_signing && status) {
			frm.dashboard.set_headline(
				`<span class="indicator ${indicator}">${frappe.utils.escape_html(status)}</span>`,
				indicator
			);
		}
	},
});
