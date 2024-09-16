import requests

url = "https://preprod-api.myinvois.hasil.gov.my/api/v1.0/documenttypes"

payload = {}
headers = {
  'Authorization': 'Bearer '
}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
