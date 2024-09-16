import hashlib
import base64
import json
import requests

# Load the XML file
with open('/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml', 'rb') as f:
    xml_data = f.read()

# Generate the SHA-256 hash of the XML document in hex encoding
sha256_hash = hashlib.sha256(xml_data).hexdigest()
print(sha256_hash)
# Encode the XML document in Base64
encoded_xml = base64.b64encode(xml_data).decode('utf-8')
print(encoded_xml)
# Prepare the JSON payload
json_payload = {
    "documents": [
        {
            "format": "XML",
            "documentHash": sha256_hash,
            "codeNumber": "INV12345",
            "document": encoded_xml
        }
    ]
}

# Set up the request headers with Authorization token
headers = {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk2RjNBNjU2OEFEQzY0MzZDNjVBNDg1MUQ5REM0NTlFQTlCM0I1NTRSUzI1NiIsIng1dCI6Imx2T21Wb3JjWkRiR1draFIyZHhGbnFtenRWUSIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL3ByZXByb2QtaWRlbnRpdHkubXlpbnZvaXMuaGFzaWwuZ292Lm15IiwibmJmIjoxNzI2NDg3NTE1LCJpYXQiOjE3MjY0ODc1MTUsImV4cCI6MTcyNjQ5MTExNSwiYXVkIjpbIkludm9pY2luZ0FQSSIsImh0dHBzOi8vcHJlcHJvZC1pZGVudGl0eS5teWludm9pcy5oYXNpbC5nb3YubXkvcmVzb3VyY2VzIl0sInNjb3BlIjpbIkludm9pY2luZ0FQSSJdLCJjbGllbnRfaWQiOiJkNzA4ZjQxMy0yZDkzLTQzMDktODhkYi1hMGY3MDI1OWEyOTAiLCJJc1RheFJlcHJlcyI6IjEiLCJJc0ludGVybWVkaWFyeSI6IjAiLCJJbnRlcm1lZElkIjoiMCIsIkludGVybWVkVElOIjoiIiwiSW50ZXJtZWRFbmZvcmNlZCI6IjIiLCJuYW1lIjoiQzg4ODI4MTA5MDpkNzA4ZjQxMy0yZDkzLTQzMDktODhkYi1hMGY3MDI1OWEyOTAiLCJTU0lkIjoiNmViMmQzNjMtMGZiNS04NGU1LWFmNGMtNGM1OTE5YTc4ZTBiIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiTWlyY29zb2Z0IER5bmFtaWNzIE5hdmlzaW9uIiwiVGF4SWQiOiIyMTU4IiwiVGF4VGluIjoiQzg4ODI4MTA5MCIsIlByb2ZJZCI6IjI3MDYiLCJJc1RheEFkbWluIjoiMCIsIklzU3lzdGVtIjoiMSJ9.aRbmbTF95Y57K-pn29HA2SaiZpccAbx4PiFxvncl8IRBGgKFOWqbTZYm5aPl6kWNwP5emQUF61XfsD1wxglHEqMQZiWKaUnhHr5jme-JRHyX0cH8AQOiq59dZdXUEPb1FmFavbMGf-s2Qui6NsFu84e3NtxnuMvf0uP-RyI7DPSpbpvA6Mv0TeDHXMVOUa4D6uWTtJ3ovzTTy7LA2vo6nW2_ITXhGB0kh24hxdQpYbMbVn02xrQiyFmlxDB9MIUXH-PGO8NGNhDCNRpiIZByrKAC3fPhPoJrGRNcN0Kj6Iu48UgZ9SIpSaHUBsmfzJdLy3ZFn9nl-94zGtJD4jzVvw',
    'Content-Type': 'application/json'
}

# Send the POST request
response = requests.post(
    'https://preprod-api.myinvois.hasil.gov.my/api/v1.0/documentsubmissions',
    headers=headers,
    json=json_payload
)


print("Response status code:", response.status_code)
print("Response body:", response.text)
