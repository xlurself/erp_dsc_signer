app_name = "erp_dsc_signer"
app_title = "ERP DSC Signer"
app_publisher = "XLURSELF"
app_description = "Digital signing for ERPNext documents using PFX certificates or USB DSC tokens"
app_email = "info@xlurself.com"
app_license = "MIT"

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/erp_dsc_signer/css/erp_dsc_signer.css"
# app_include_js = "/assets/erp_dsc_signer/js/erp_dsc_signer.js"

# include js, css files in header of web template
# web_include_css = "/assets/erp_dsc_signer/css/erp_dsc_signer.css"
# web_include_js = "/assets/erp_dsc_signer/js/erp_dsc_signer.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "erp_dsc_signer/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
doctype_js = {
	"Sales Invoice": "public/js/sales_invoice.js",
}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "erp_dsc_signer.utils.jinja_methods",
# 	"filters": "erp_dsc_signer.utils.jinja_filters"
# }

# Installation
# ------------

before_install = "erp_dsc_signer.install.before_install"

# Uninstallation
# ------------

# before_uninstall = "erp_dsc_signer.uninstall.before_uninstall"
# after_uninstall = "erp_dsc_signer.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "erp_dsc_signer.utils.before_app_install"
# after_app_install = "erp_dsc_signer.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "erp_dsc_signer.utils.before_app_uninstall"
# after_app_uninstall = "erp_dsc_signer.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "erp_dsc_signer.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"erp_dsc_signer.tasks.all"
# 	],
# 	"daily": [
# 		"erp_dsc_signer.tasks.daily"
# 	],
# 	"hourly": [
# 		"erp_dsc_signer.tasks.hourly"
# 	],
# 	"weekly": [
# 		"erp_dsc_signer.tasks.weekly"
# 	],
# 	"monthly": [
# 		"erp_dsc_signer.tasks.monthly"
# 	],
# }

# Testing
# -------

# before_tests = "erp_dsc_signer.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "erp_dsc_signer.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "erp_dsc_signer.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["erp_dsc_signer.utils.before_request"]
# after_request = ["erp_dsc_signer.utils.after_request"]

# Job Events
# ----------
# before_job = ["erp_dsc_signer.utils.before_job"]
# after_job = ["erp_dsc_signer.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"erp_dsc_signer.auth.validate"
# ]

# Sales Invoice signing status fields. Keep the names compatible with the
# original ERP PDF Signer app so existing sites can migrate without data loss.
fixtures = [
	{
		"dt": "Custom Field",
		"filters": [
			[
				"name",
				"in",
				[
					"Sales Invoice-custom_digital_signature_section",
					"Sales Invoice-custom_digitally_signed",
					"Sales Invoice-custom_signed_invoice_pdf",
					"Sales Invoice-custom_signed_on",
					"Sales Invoice-custom_signed_by",
				],
			]
		],
	}
]
