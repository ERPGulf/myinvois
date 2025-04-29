"""This module contains the function to get the access token from LHDN API"""

import frappe
import requests
from frappe import _


def get_api_url(base_url):
    """There are many api susing in zatca which can be defined by a feild in settings"""
    try:
        settings = frappe.get_doc("LHDN Malaysia Setting")
        if settings.integration_type == "Sandbox":
            url = settings.custom_sandbox_url + base_url
        else:
            url = settings.custom_production_url + base_url

        return url

    except (ValueError, TypeError, KeyError) as e:
        frappe.throw(_(("get api url" f"error: {str(e)}")))
        return None


@frappe.whitelist(allow_guest=True)  # Make sure this method is whitelisted
def get_access_token():
    """Get access token from LHDN API"""
    # Debug to ensure function is triggered
    # frappe.msgprint("Python function triggered successfully!")
    url = get_api_url(base_url="connect/token")
    # url = "https://preprod-api.myinvois.hasil.gov.my/connect/token"
    settings = frappe.get_doc("LHDN Malaysia Setting")
    client_id = settings.client_id
    client_secret = settings.client_secret
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
        # frappe.msgprint(f"Access token response: {response.text}")
        token_response = response.json()
        access_token = token_response.get("access_token")

        if access_token:
            settings.bearer_token = access_token
            settings.save()

        else:
            frappe.throw(
                _("An error occurred while fetching the token", response.json())
            )
        return response.json()
    except requests.exceptions.RequestException as e:
        frappe.throw(_(f"An error occurred while fetching the token: {e}"))
