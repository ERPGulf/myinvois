"""this module for getting teh status through button"""

import frappe
import requests
import json
from frappe import _
from myinvois_erpgulf.myinvois_erpgulf.original import get_api_url
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token


@frappe.whitelist(allow_guest=True)
def status_submit(doc):
    """Fetch submission status and update in Sales or Purchase Invoice."""

    try:
        # Parse string input to dict
        if isinstance(doc, str):
            doc = frappe.parse_json(doc)

        # Get settings and token
        settings = frappe.get_doc("LHDN Malaysia Setting")
        token = settings.bearer_token

        # Get submission UID
        response_data = json.loads(doc.get("custom_submit_response", "{}"))
        submission_uid = response_data.get("submissionUid")
        if not submission_uid:
            frappe.throw("Submission UID is missing from the document.")

        # Prepare request
        url = get_api_url(base_url=f"api/v1.0/documentsubmissions/{submission_uid}")
        headers = {"Authorization": f"Bearer {token}"}

        # First attempt
        response = requests.get(url, headers=headers, timeout=30)

        # Retry on auth/server error
        if response.status_code in [401, 500]:
            get_access_token()  # Refresh token
            settings.reload()
            token = settings.bearer_token
            headers["Authorization"] = f"Bearer {token}"
            response = requests.get(url, headers=headers, timeout=30)

        # Success response
        if response.status_code == 200:
            frappe.msgprint(f"Response body: {response.text}")
            response_data = response.json()

            document_summary = response_data.get("documentSummary", [])
            if document_summary:
                status = document_summary[0].get("status", "Unknown")

                # Try Sales Invoice first
                if doc.get("doctype") == "Sales Invoice":
                    invoice = frappe.get_doc("Sales Invoice", doc.get("name"))
                else:
                    # If not found, try Purchase Invoice
                    invoice = frappe.get_doc("Purchase Invoice", doc.get("name"))

                invoice.custom_lhdn_status = status
                invoice.save(ignore_permissions=True)
                frappe.msgprint(_("LHDN submission status updated: ") + status)

            frappe.db.commit()
            return response_data

        # Handle non-success response
        else:
            frappe.throw(
                f"Failed to retrieve status. HTTP {response.status_code}: {response.text}"
            )

    except requests.RequestException as e:
        frappe.throw(_(f"Request failed: {str(e)}"))
    except (ValueError, KeyError, frappe.ValidationError) as e:
        frappe.log_error(title="LHDN Status Error", message=str(e))
        frappe.throw(
            _("Failed to update LHDN submission status. Check logs for details.")
        )
