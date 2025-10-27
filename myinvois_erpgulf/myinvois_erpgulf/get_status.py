"""this module contains the function to get the status of LHDN submission"""

import json
import frappe
import requests
import os
from frappe import _
from myinvois_erpgulf.myinvois_erpgulf.original import get_api_url
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token
from myinvois_erpgulf.myinvois_erpgulf.createxml import generate_qr_code, attach_qr_code_to_sales_invoice

@frappe.whitelist(allow_guest=True)
def status_submit(doc):
    """
    Fetch submission status from LHDN API and update the corresponding Sales or Purchase Invoice.
    """
    try:
        # If doc is a JSON string (from client side), parse it to dict
        if isinstance(doc, str):

            doc = json.loads(doc)

        company_name = doc.get("company")
        if not company_name:
            frappe.throw(_("Company name not provided in document."))

        company_doc = frappe.get_doc("Company", company_name)
        token = company_doc.custom_bearer_token
        if not token:
            frappe.throw(_("Bearer token not found in company document."))

        # Extract submissionUid from stored API response JSON string
        submission_response_str = doc.get("custom_submit_response", "{}")
        response_data = json.loads(submission_response_str)
        submission_uid = response_data.get("submissionUid")

        if not submission_uid:
            invoice_doctype = doc.get("doctype")
            if invoice_doctype not in ["Sales Invoice", "Purchase Invoice"]:
                frappe.throw(
                    _("Document type must be Sales Invoice or Purchase Invoice.")
                )

            invoice = frappe.get_doc(invoice_doctype, doc.get("name"))
            invoice.custom_lhdn_status = "Failed"
            invoice.save(ignore_permissions=True)
            frappe.db.commit()
            frappe.throw(
                _(
                    "As per LHDN Regulation,Submission UID is missing from the document's custom_submit_response."
                )
            )

        company_abbr = company_doc.abbr
        url = get_api_url(
            company_abbr, base_url=f"/api/v1.0/documentsubmissions/{submission_uid}"
        )
        headers = {"Authorization": f"Bearer {token}"}

        # Make API request to get status
        response = requests.get(url, headers=headers, timeout=30)

        # Retry once on auth or server error
        if response.status_code in [401, 500]:
            get_access_token(company_doc.name)  # Refresh token
            company_doc.reload()
            token = company_doc.custom_bearer_token
            headers["Authorization"] = f"Bearer {token}"
            response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            response_data = response.json()

            document_summary = response_data.get("documentSummary", [])
            if document_summary:
                status = document_summary[0].get("status", "Unknown")

                # Determine the invoice doctype to update
                invoice_doctype = doc.get("doctype")
                if invoice_doctype not in ["Sales Invoice", "Purchase Invoice"]:
                    frappe.throw(
                        _("Document type must be Sales Invoice or Purchase Invoice.")
                    )

                invoice = frappe.get_doc(invoice_doctype, doc.get("name"))
                invoice.custom_lhdn_status = status
                invoice.save(ignore_permissions=True)
                frappe.db.commit()
                # frappe.msgprint(response.text)  # Log the full response for debugging
                frappe.msgprint(_("LHDN submission status updated: {0}").format(status))
                if status.strip().lower() == "valid":
                    # Check for existing QR attachment
                    qr_filename_prefix = f"startQR_{invoice.name}.png"
                    existing_attachments = frappe.get_all(
                        "File",
                        filters={
                            "attached_to_doctype": invoice_doctype,
                            "attached_to_name": invoice.name,
                            "file_name": ["like", qr_filename_prefix],
                        },
                        fields=["file_name", "file_url"],
                    )

                    if not existing_attachments:
                        try:
                            qr_image_path = generate_qr_code(invoice, status)
                            if not qr_image_path or not os.path.exists(qr_image_path):
                                frappe.log_error(
                                    message=f"QR code path invalid: {qr_image_path}",
                                    title="QR Generation Error",
                                )
                            else:
                                attach_qr_code_to_sales_invoice(invoice, qr_image_path)
                                frappe.msgprint(_("QR code generated and attached successfully."))
                        except Exception:
                            frappe.log_error(
                                message=frappe.get_traceback(),
                                title="Error Generating/Attaching QR Code",
                            )
                else:
                    frappe.msgprint(_("No document summary found in response."))

            return response_data
        else:
            frappe.throw(
                _("Failed to retrieve status. HTTP {0}: {1}").format(
                    response.status_code, response.text
                )
            )

    except requests.RequestException as e:
        frappe.throw(_("Request failed: {0}").format(str(e)))
    except (ValueError, KeyError, frappe.ValidationError) as e:

        frappe.log_error(title="LHDN Status Error", message=str(e))
        frappe.throw(
            _("Failed to update LHDN submission status. Check logs for details.")
        )
