import requests
import frappe
from frappe import _
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token
import requests
import frappe
from frappe import _


@frappe.whitelist()
def search_company_tin(company_name):
    # Fetch company doc
    company = frappe.get_doc("Company", company_name)

    id_type = company.custom_company_registrationicpassport_type
    id_value = company.custom_company__registrationicpassport_number
    taxpayer_name = company.custom_taxpayer_name

    # Determine which API to call based on available data
    if id_type and id_value:
        query_url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/taxpayer/search/tin?idType={id_type}&idValue={id_value}"
    elif taxpayer_name:
        query_url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/taxpayer/search/tin?taxpayerName={taxpayer_name}"
    else:
        frappe.throw(
            _(
                "Either ID Type and Value or Taxpayer Name must be present in the Company document."
            )
        )

    # Get bearer token from settings
    settings = frappe.get_doc("LHDN Malaysia Setting")
    token = settings.bearer_token

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    response = requests.get(
        query_url,
        headers=headers,
        timeout=10,
    )

    if response.status_code in [401, 500]:
        get_access_token()  # Refresh token and save in settings
        settings.reload()
        token = settings.bearer_token
        headers["Authorization"] = f"Bearer {token}"
        response = requests.get(
            query_url,
            headers=headers,
            timeout=10,
        )

    frappe.msgprint(f"Response body: {response.text}")

    if response.status_code != 200:
        frappe.throw(_("API request failed {0}").format(response.text))

    try:
        data = response.json()
    except ValueError:
        frappe.throw(_("Failed to parse API response."))

    # Check if TIN exists in response
    tin = data.get("tin")
    if not tin:
        frappe.throw(_("TIN not found in API response."))

    # Save TIN to Company doc field
    company.custom_company_tin_number = tin
    company.save()

    return data


@frappe.whitelist()
def search_customer_tin(customer_name):
    """Search for TIN using customer name, ID type, and ID value."""
    # Fetch Customer doc (you were using "customer" which is incorrect, must use customer_name)

    customer = frappe.get_doc("Customer", customer_name)

    id_type = customer.get("custom_customer__registrationicpassport_type")
    id_value = customer.get("custom_customer_registrationicpassport_number")
    taxpayer_name = customer.get("custom_customer_taxpayer_name")

    # Construct API URL
    if id_type and id_value:
        query_url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/taxpayer/search/tin?idType={id_type}&idValue={id_value}"
    elif taxpayer_name:
        query_url = f"https://preprod-api.myinvois.hasil.gov.my/api/v1.0/taxpayer/search/tin?taxpayerName={frappe.utils.quote(taxpayer_name)}"
    else:
        frappe.throw(
            _(
                "Either ID Type and Value or Taxpayer Name must be present in the Customer document."
            )
        )

    # Get bearer token from custom settings
    settings = frappe.get_doc("LHDN Malaysia Setting")
    token = settings.get("bearer_token")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    response = requests.get(query_url, headers=headers, timeout=10)

    # Handle token expiration or server error
    if response.status_code in [401, 500]:

        get_access_token()
        settings.reload()
        token = settings.get("bearer_token")
        headers["Authorization"] = f"Bearer {token}"
        response = requests.get(query_url, headers=headers, timeout=10)

    frappe.msgprint(f"Response body: {response.text}")

    if response.status_code != 200:
        frappe.throw(_("API request failed: {0}").format(response.text))

    try:
        data = response.json()
    except ValueError:
        frappe.throw(_("Failed to parse API response."))

    # Extract TIN (depends on response structure)
    tin = data.get("tin") or data.get("data", {}).get("tin")
    if not tin:
        frappe.throw(_("TIN not found in API response."))

    # Save TIN to custom field
    customer.custom_customer_tin_number = tin
    customer.save(ignore_permissions=True)

    return data
