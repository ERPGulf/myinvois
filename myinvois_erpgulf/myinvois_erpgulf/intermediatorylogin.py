import requests

url = "https://preprod-api.myinvois.hasil.gov.my/connect/token"

payload = 'client_id=d708f413-2d93-4309-88db-a0f70259a290&client_secret=97069288-86de-4e73-b029-3c9547fec236&grant_type=client_credentials&scope=InvoicingAPI'
headers = {
  'onbehalfof': '100015840',
  'Content-Type': 'application/x-www-form-urlencoded'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
