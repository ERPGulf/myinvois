# from frappe import _
app_name = "myinvois_erpgulf"
app_title = "Myinvois Erpgulf"
app_publisher = "ERPGulf"
app_description = "MyInvoice - E-Invoice for Malaysia"
app_email = "support@erpgulf.com"
app_license = "mit"


from . import __version__ as app_version
add_to_apps_screen = [
    {
        "name": app_name,
        "logo": "/assets/myinvois_erpgulf/images/ERPGulf.png",
        "title": app_title,
        "route": "/desk/malaysia-compliance",
        # "has_permission": "zatca_erpgulf.check_app_permission",
    }
]
# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "myinvois_erpgulf",
# 		"logo": "/assets/myinvois_erpgulf/logo.png",
# 		"title": "Myinvois Erpgulf",
# 		"route": "/myinvois_erpgulf",
# 		"has_permission": "myinvois_erpgulf.api.permission.has_app_permission"
# 	}
# ]



doctype_js = {
    # "LHDN Setting": "myinvois_erpgulf/public/js/LHDN_setting.js",
    "Company": "public/js/company.js",
    "Customer": "public/js/customer.js",
    "Purchase Invoice": "public/js/puchase.js",
    "Sales Invoice": "public/js/sales.js",
}

doctype_list_js = {
    "Sales Invoice": "public/js/sales_invoice.js",
}


doc_events = {
    "Sales Invoice": {
        "before_submit": "myinvois_erpgulf.myinvois_erpgulf.original.validate_before_submit",
        "on_submit": "myinvois_erpgulf.myinvois_erpgulf.original.submit_document_wrapper",
        "on_cancel": "myinvois_erpgulf.myinvois_erpgulf.cancel_doc.cancel_document_wrapper",
        "after_submit": "myinvois_erpgulf.myinvois_erpgulf.createxml.after_submit",
    },
    "Purchase Invoice": {
        "before_submit": "myinvois_erpgulf.myinvois_erpgulf.submit_purchase.validate_before_submit",
        "on_submit": "myinvois_erpgulf.myinvois_erpgulf.submit_purchase.submit_document_wrapper",
        "on_cancel": "myinvois_erpgulf.myinvois_erpgulf.cancel_doc.cancel_document_wrapper",
        "after_submit": "myinvois_erpgulf.myinvois_erpgulf.purchase_invoice.after_submit",
    },
}

# Fixtures
fixtures = [
    {"dt": "Workspace", "filters": {"module": "Myinvois Erpgulf"}},
    {"dt": "Custom Field", "filters": [["module", "=", "Myinvois Erpgulf"]]},
    {"dt": "Print Format", "filters": [["module", "=", "Myinvois Erpgulf"]]},
    {"dt": "Property Setter", "filters": [["module", "=", "Myinvois Erpgulf"]]},
    {"dt": "Desktop Icon", "filters": [["label", "=", "Malaysia Compliance"]]},
]
# fixtures = [
#     {
#         "dt": "Desktop Icon",
#         "filters": [
#             ["label", "=", "Malaysia Compliance"]
#         ]
#     }
# ]