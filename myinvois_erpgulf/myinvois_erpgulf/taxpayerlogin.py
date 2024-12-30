import frappe
import requests

@frappe.whitelist(allow_guest=True)# Make sure this method is whitelisted
def get_access_token():
    # Debug to ensure function is triggered
    # frappe.msgprint("Python function triggered successfully!")  
    url = "https://preprod-api.myinvois.hasil.gov.my/connect/token"
    settings = frappe.get_doc('LHDN Malaysia Setting')
    client_id = settings.client_id
    client_secret = settings.client_secret
    payload = f'client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials&scope=InvoicingAPI'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        # frappe.msgprint(f"Access token response: {response.text}")
        token_response = response.json()
        access_token = token_response.get("access_token")
        
        if access_token:
            settings.bearer_token = access_token
            settings.save()
        return response.json()
    except requests.exceptions.RequestException as e:
        frappe.throw(f"An error occurred while fetching the token: {e}")

