import json
import requests
import frappe
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token


@frappe.whitelist(allow_guest=True)
def cancel_document_wrapper(doc, method):
    """Wrapper function to handle document cancellation."""
    # If not submitted to LHDN, allow normal cancel
    if not doc.custom_submit_response:
        return  # nothing to do extra, just cancel locally

    try:
        response_data = json.loads(doc.custom_submit_response)
    except json.JSONDecodeError:
        frappe.throw(_("Invalid LHDN submission response format."))

    submission_uid = response_data.get("submissionUid")
    uuid = response_data.get("uuid")

    if not submission_uid or not uuid:
        return  # No valid submission data, cancel normally

    settings = frappe.get_doc("LHDN Malaysia Setting")
    token = settings.bearer_token
    
    try:
        url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/documents/state/{uuid}/state"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",  # Use the token retrieved from settings
        }
        payload = {
            "status": "cancelled",
            "reason": "Cancelled from ERP system by user",
        }

        response = requests.put(url, headers=headers, json=,timeout=10)

        # Check if the response status code is 401 or 500, then refresh token and retry
        if response.status_code in [401, 500]:
            get_access_token()  # Refresh the token and save it in settings
            settings.reload()  # Reload settings to get the new token
            token = settings.bearer_token  # Fetch updated token
            headers["Authorization"] = f"Bearer {token}"  # Update headers with new token

            # Retry the cancellation API with the new token
            response = requests.put(url, headers=headers, json=payload,timeout=10)

        if response.status_code == 200:
            frappe.msgprint(response.text)  # Display the actual response text
        else:
            frappe.throw(_("LHDN cancellation failed: {0}").format(response.text))

    except Exception as e:
        frappe.throw(_("Error cancelling document from LHDN: {0}").format(str(e)))
