"""LHDN Document Cancellation Module"""

import json
import requests
import frappe
from frappe import _
import datetime
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token

def get_api_url(company_abbr, base_url):
    """There are many api susing in malaysia which can be defined by a field in settings"""
    try:
        company_doc = frappe.get_doc("Company", {"abbr": company_abbr})
        if company_doc.custom_integration_type == "Sandbox":
            url = company_doc.custom_sandbox_url + base_url
        else:
            url = company_doc.custom_production_url + base_url

        return url

    except (ValueError, TypeError, KeyError) as e:
        frappe.throw(_(("get api url" f"error: {str(e)}")))
        return None

@frappe.whitelist(allow_guest=True)
def cancel_document_wrapper(doc, method):
    """Wrapper function to handle document cancellation via LHDN."""

    if not doc.custom_submit_response:

        return

    try:
        response_data = json.loads(doc.custom_submit_response)
    except json.JSONDecodeError:
        frappe.throw(_("Invalid JSON format in custom_submit_response."))

    submission_uid = response_data.get("submissionUid")

    # ✅ Extract uuid from acceptedDocuments[0]
    accepted_docs = response_data.get("acceptedDocuments", [])
    if accepted_docs and "uuid" in accepted_docs[0]:
        uuid = accepted_docs[0]["uuid"]
    else:
        frappe.msgprint(
            _("As per LHDN Regulation,UUID not found in accepted documents.")
        )
        return
    if not submission_uid or not uuid:
        frappe.throw(
            _("Missing submission UID or UUID. Cannot proceed with cancellation.")
        )
    submission_time_str = (
        doc.custom_submission_time
    )  # Assuming this stores the timestamp like '2025-05-10T08:00:00Z'
    if not submission_time_str:
        frappe.throw(
            _("Submission time not found. Cannot validate cancellation window.")
        )

    # Parse submission time to datetime object
    submission_time = datetime.datetime.strptime(
        submission_time_str, "%Y-%m-%dT%H:%M:%SZ"
    )
    submission_time = submission_time.replace(tzinfo=datetime.timezone.utc)

    # Get current UTC time
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # Check if within 72 hours
    time_diff = current_time - submission_time
    if time_diff.total_seconds() > 72 * 3600:
        frappe.throw(
            _(
                "As per LHDN Regulation,Cancellation not allowed after 72 hours of submission."
            )
        )

    company_name = doc.company
    settings = frappe.get_doc("Company", company_name)
    company_abbr = settings.abbr
    company_doc = frappe.get_doc("Company", {"abbr": company_abbr})

    token = company_doc.custom_bearer_token

    # url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/documents/state/{uuid}/state"
    url = get_api_url(company_doc.abbr, f"/api/v1.0/documents/state/{uuid}/state")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    payload = {
        "status": "cancelled",
        "reason": "Cancelled from ERP system by user",
    }

    try:
        # First attempt
        response = requests.put(url, headers=headers, json=payload, timeout=10)

        # Retry if token expired or internal server error
        if response.status_code in [401, 500]:
            get_access_token(company_doc.name)
            settings.reload()
            token = company_doc.custom_bearer_token
            headers["Authorization"] = f"Bearer {token}"

            response = requests.put(url, headers=headers, json=payload, timeout=10)

        # Final response handling
        if response.status_code == 200:
            frappe.msgprint(_("LHDN document cancelled successfully."))
            frappe.msgprint(_(response.text))
            doc.custom_lhdn_status = "Cancelled"
            doc.db_update()
            if doc.doctype == 'Sales Invoice':
                remove_consolidated_invoice_ref(doc,method)
        else:
            frappe.throw(_("LHDN cancellation failed: {0}").format(response.text))

    except Exception as e:

        frappe.throw(_("Error cancelling document from LHDN: {0}").format(str(e)))


def remove_consolidated_invoice_ref(doc,method):
    if doc.custom_is_consolidated_invoice:
        for i in doc.items:
            frappe.db.set_value('Sales Invoice',i.custom_consolidated_invoice_refrence_copy,'custom_consolidate_invoice_number','')
            frappe.db.commit()