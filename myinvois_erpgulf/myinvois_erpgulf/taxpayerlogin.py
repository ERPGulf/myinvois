"""This module contains the function to get the access token from LHDN API"""

import frappe
import requests
from frappe import _


def get_api_url(company_abbr, base_url):
    """Constructs the API URL based on the company abbreviation and base URL."""
    try:
        company_doc = frappe.get_doc("Company", {"abbr": company_abbr})
        if company_doc.custom_integration_type == "Sandbox":
            url = company_doc.custom_sandbox_url + base_url
        else:
            url = company_doc.custom_production_url + base_url
        return url
    except Exception as e:
        frappe.throw(_(f"Error getting API URL: {str(e)}"))
        return None


@frappe.whitelist(allow_guest=False)
def get_access_token(doc: str):
    """Fetches the access token from the LHDN API for the specified company."""
    # Determine company name
    if isinstance(doc, str):
        company_name = doc
    elif isinstance(doc, dict):
        company_name = doc.get("name") or doc.get("company")  # Try both
        if not company_name:
            frappe.throw(_("Company name not provided in doc"))
    else:
        frappe.throw(_("Invalid argument type for doc"))

    # Load company doc
    try:
        company_doc = frappe.get_doc("Company", company_name)
    except frappe.DoesNotExistError:
        frappe.throw(_(f"Company '{company_name}' not found"))

    company_abbr = company_doc.abbr
    url = get_api_url(company_abbr, base_url="/connect/token")

    client_id = company_doc.custom_client_id
    client_secret = company_doc.custom_client_secret
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "InvoicingAPI",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        response.raise_for_status()
        token_response = response.json()
        access_token = token_response.get("access_token")

        if access_token:
            company_doc.custom_bearer_token = access_token
            company_doc.save()
            company_doc.save(ignore_permissions=True)
        else:
            frappe.throw(
                _("Failed to fetch access token. Response: {0}").format(token_response)
            )
        company_doc.save()
        company_doc.save(ignore_permissions=True)
        return token_response

    except requests.exceptions.RequestException as e:
        frappe.throw(_(f"Error fetching token: {e}"))
