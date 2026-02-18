"""this module provides functions to search for TIN company or customer details."""

import requests
import frappe
from frappe import _
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token
from urllib.parse import quote


def get_api_url(company_abbr, endpoint_path=""):
    """Construct the full base URL plus endpoint path."""
    try:
        company_doc = frappe.get_doc("Company", {"abbr": company_abbr})
        if company_doc.custom_integration_type == "Sandbox":
            base = company_doc.custom_sandbox_url.rstrip("/")
        else:
            base = company_doc.custom_production_url.rstrip("/")
        return f"{base}/{endpoint_path.lstrip('/')}" if endpoint_path else base
    except Exception as e:
        frappe.throw(_(f"Error getting API URL: {str(e)}"))
        return None


@frappe.whitelist(allow_guest=False)
def search_company_tin(company_name):
    """Search for TIN using company name, ID type, and ID value."""
    company = frappe.get_doc("Company", company_name)
    company_abbr = company.abbr

    id_type = (
        company.custom_company_registrationicpassport_type
        or company.custom_company_registration_for_self_einvoicing
    )
    id_value = company.custom_company__registrationicpassport_number
    taxpayer_name = company.custom_taxpayer_name

    # Determine API endpoint and construct query URL
    if id_type and id_value:
        endpoint = f"api/v1.0/taxpayer/search/tin?idType={quote(id_type)}&idValue={quote(id_value)}"
    elif taxpayer_name:
        endpoint = f"api/v1.0/taxpayer/search/tin?taxpayerName={quote(taxpayer_name)}"
    else:
        frappe.throw(
            _(
                "As per LHDN Regulations,Either ID Type and Value or Taxpayer Name must be present in the Company document."
            )
        )

    query_url = get_api_url(company_abbr, endpoint)

    # Get bearer token
    token = company.custom_bearer_token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # Make API request
    response = requests.get(query_url, headers=headers, timeout=10)

    # Handle token expiration or server error
    if response.status_code in [401, 500]:
        get_access_token(company.name)
        company.reload()
        token = company.custom_bearer_token
        headers["Authorization"] = f"Bearer {token}"
        response = requests.get(query_url, headers=headers, timeout=10)

    frappe.msgprint(_(f"Response body: {response.text}"))

    if response.status_code != 200:
        frappe.throw(_("API request failed: {0}").format(response.text))

    try:
        data = response.json()
    except ValueError:
        frappe.throw(_("Failed to parse API response."))

    # Extract TIN
    tin = data.get("tin") or data.get("data", {}).get("tin")
    if not tin:
        frappe.throw(_("TIN not found in API response."))

    # Save TIN to Company doc
    company.custom_company_tin_number = tin
    company.save()

    return data


from urllib.parse import quote


@frappe.whitelist(allow_guest=False)
def search_sales_tin(sales_invoice_doc):
    """Search for TIN using Sales Invoice's customer details (ID type/value or name)."""

    # Load full Sales Invoice doc
    if isinstance(sales_invoice_doc, dict):
        sales_invoice_doc = frappe.get_doc(
            "Sales Invoice", sales_invoice_doc.get("name")
        )
    elif isinstance(sales_invoice_doc, str):
        sales_invoice_doc = frappe.get_doc("Sales Invoice", sales_invoice_doc)

    id_type = sales_invoice_doc.get("custom_customer__registrationicpassport_type")
    id_value = sales_invoice_doc.get("custom_customer_registrationicpassport_number")
    taxpayer_name = sales_invoice_doc.get("custom_customer_taxpayer_name")
    company_name = sales_invoice_doc.company

    if not company_name:
        frappe.throw(_("Company must be specified in the Sales Invoice."))

    # Fetch Company doc and abbreviation
    company_doc = frappe.get_doc("Company", company_name)
    company_abbr = company_doc.abbr

    # Construct API endpoint
    if id_type and id_value:
        endpoint = f"api/v1.0/taxpayer/search/tin?idType={quote(id_type)}&idValue={quote(id_value)}"
    elif taxpayer_name:
        endpoint = f"api/v1.0/taxpayer/search/tin?taxpayerName={quote(taxpayer_name)}"
    else:
        frappe.throw(
            _(
                "As per LHDN Regulation,Either ID Type and Value or Taxpayer Name must be present in the Sales Invoice."
            )
        )

    query_url = get_api_url(company_abbr, endpoint)

    # Get bearer token
    token = company_doc.get("custom_bearer_token")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # First request
    response = requests.get(query_url, headers=headers, timeout=10)

    # Handle token expiration or server error
    if response.status_code in [401, 500]:
        get_access_token(company_doc.name)  # Correctly pass company_doc here
        company_doc.reload()
        token = company_doc.get("custom_bearer_token")
        headers["Authorization"] = f"Bearer {token}"
        response = requests.get(query_url, headers=headers, timeout=10)

    frappe.msgprint(_(f"Response body: {response.text}"))

    if response.status_code != 200:
        frappe.throw(
            _(
                "API request failed ,As per LHDN,either type or value or taxpayer data is wrong: {0}"
            ).format(response.text)
        )

    try:
        data = response.json()
    except ValueError:
        frappe.throw(_("Failed to parse API response."))

    tin = data.get("tin") or data.get("data", {}).get("tin")
    if not tin:
        frappe.throw(_("TIN not found in API response."))

    # Save TIN to Sales Invoice
    sales_invoice_doc.db_set("custom_customer_tin_number", tin)

    return {
        "taxpayerTIN": tin,
        "message": _("TIN fetched successfully."),
        "data": data,
    }


import frappe
import requests
from urllib.parse import quote


@frappe.whitelist(allow_guest=False)
def search_purchase_tin(sales_invoice_doc):
    """
    Search for TIN using Purchase Invoice's customer details (ID type/value or name).
    """
    # Load full Purchase Invoice doc
    try:
        if isinstance(sales_invoice_doc, dict):
            sales_invoice_doc = frappe.get_doc(
                "Purchase Invoice", sales_invoice_doc.get("name")
            )
        elif isinstance(sales_invoice_doc, str):
            sales_invoice_doc = frappe.get_doc("Purchase Invoice", sales_invoice_doc)
        else:
            frappe.throw(_("Invalid argument for sales_invoice_doc"))
    except Exception as e:
        # frappe.log_error(f"Failed to load Purchase Invoice: {e}", "search_purchase_tin")
        frappe.throw(_(f"Failed to load Purchase Invoice: {e}"))

    # Fix potential typo in field names here:
    id_type = sales_invoice_doc.get("custom_customer__registrationicpassport_type")
    id_value = sales_invoice_doc.get("custom_customer_registrationicpassport_number")
    taxpayer_name = sales_invoice_doc.get("custom_supplier_taxpayer_name")
    company_name = sales_invoice_doc.company
    if not company_name:
        frappe.throw(_("Company must be specified in the Purchase Invoice."))

    # Fetch Company doc and abbreviation
    try:
        company_doc = frappe.get_doc("Company", company_name)
        company_abbr = company_doc.abbr
    except Exception as e:
        frappe.throw(_(f"Failed to load Company doc: {e}"))
    # Construct API endpoint URL
    if id_type and id_value:
        endpoint = f"api/v1.0/taxpayer/search/tin?idType={quote(id_type)}&idValue={quote(id_value)}"
    elif taxpayer_name:
        endpoint = f"api/v1.0/taxpayer/search/tin?taxpayerName={quote(taxpayer_name)}"
    else:
        frappe.throw(
            _(
                "As per LHDN Regulation,Either ID Type and Value or Taxpayer Name must be present in the Purchase Invoice."
            )
        )

    query_url = get_api_url(
        company_abbr, endpoint
    )  # You must define get_api_url elsewhere
    # Get bearer token from company
    token = company_doc.get("custom_bearer_token")
    if not token:
        frappe.throw(_("Bearer token not found in Company record."))

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    try:
        response = requests.get(query_url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        frappe.log_error(f"API request exception: {e}", "search_purchase_tin")
        frappe.throw(_("API request failed: {0}").format(e))

    # Handle token expiration or server error (try refresh once)
    if response.status_code in [401, 500]:
        try:
            get_access_token(
                company_doc.name
            )  # You must define get_access_token elsewhere
            company_doc.reload()
            token = company_doc.get("custom_bearer_token")
            headers["Authorization"] = f"Bearer {token}"
            response = requests.get(query_url, headers=headers, timeout=10)
        except Exception as e:
            frappe.log_error(
                f"Token refresh or retry failed: {e}", "search_purchase_tin"
            )
            frappe.throw(_("API request failed after token refresh: {0}").format(e))

    frappe.log_error(f"API Response Text: {response.text}")

    if response.status_code != 200:
        msg = (
            response.text
            if response.text
            else f"Status code: {response.status_code} As per LHDN,either type or value or taxpayer data is wrong"
        )
        frappe.log_error(f"API request failed: {msg}", "search_purchase_tin")
        frappe.throw(_("API request failed: {0}").format(msg))

    try:
        data = response.json()
    except ValueError:
        frappe.throw(_("Failed to parse API response as JSON."))

    tin = data.get("tin") or data.get("data", {}).get("tin")
    if not tin:
        frappe.throw(_("TIN not found in API response."))

    # Save TIN to Purchase Invoice doc
    sales_invoice_doc.db_set("custom_customer_tin_number", tin)

    return {
        "taxpayerTIN": tin,
        "message": _("TIN fetched successfully."),
        "data": data,
    }
