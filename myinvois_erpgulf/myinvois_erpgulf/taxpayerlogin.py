import requests

def get_access_token(client_id, client_secret, url="https://preprod-api.myinvois.hasil.gov.my/connect/token"):
    payload = f'client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials&scope=InvoicingAPI'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()  # Return the response as a JSON object
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

# Example usage
client_id = "d708f413-2d93-4309-88db-a0f70259a290"
client_secret = "97069288-86de-4e73-b029-3c9547fec236"

token_response = get_access_token(client_id, client_secret)
print(token_response)
