import hashlib
import base64
import json
import requests

# Load the XML file
with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml', 'rb') as f:
    xml_data = f.read()

sha256_hash = hashlib.sha256(xml_data).hexdigest()
print(sha256_hash)
encoded_xml = base64.b64encode(xml_data).decode('utf-8')
print(encoded_xml)
json_payload = {
    "documents": [
        {
            "format": "XML",
            "documentHash": sha256_hash,
            "codeNumber": "INV 6",
            "document": encoded_xml
        }
    ]
}

# # Set up the request headers with Authorization token
headers = {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk2RjNBNjU2OEFEQzY0MzZDNjVBNDg1MUQ5REM0NTlFQTlCM0I1NTRSUzI1NiIsIng1dCI6Imx2T21Wb3JjWkRiR1draFIyZHhGbnFtenRWUSIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL3ByZXByb2QtaWRlbnRpdHkubXlpbnZvaXMuaGFzaWwuZ292Lm15IiwibmJmIjoxNzI3MjQ3MjQzLCJpYXQiOjE3MjcyNDcyNDMsImV4cCI6MTcyNzI1MDg0MywiYXVkIjpbIkludm9pY2luZ0FQSSIsImh0dHBzOi8vcHJlcHJvZC1pZGVudGl0eS5teWludm9pcy5oYXNpbC5nb3YubXkvcmVzb3VyY2VzIl0sInNjb3BlIjpbIkludm9pY2luZ0FQSSJdLCJjbGllbnRfaWQiOiJkNzA4ZjQxMy0yZDkzLTQzMDktODhkYi1hMGY3MDI1OWEyOTAiLCJJc1RheFJlcHJlcyI6IjEiLCJJc0ludGVybWVkaWFyeSI6IjAiLCJJbnRlcm1lZElkIjoiMCIsIkludGVybWVkVElOIjoiIiwiSW50ZXJtZWRFbmZvcmNlZCI6IjIiLCJuYW1lIjoiQzg4ODI4MTA5MDpkNzA4ZjQxMy0yZDkzLTQzMDktODhkYi1hMGY3MDI1OWEyOTAiLCJTU0lkIjoiYmVkZDk0NDctZTA0MS00MmVhLWM3NWUtZGNjZGQ0ZmEzODE1IiwicHJlZmVycmVkX3VzZXJuYW1lIjoiTWlyY29zb2Z0IER5bmFtaWNzIE5hdmlzaW9uIiwiVGF4SWQiOiIyMTU4IiwiVGF4VGluIjoiQzg4ODI4MTA5MCIsIlByb2ZJZCI6IjI3MDYiLCJJc1RheEFkbWluIjoiMCIsIklzU3lzdGVtIjoiMSJ9.GkOm9nVhZPn650o9NDlSI2q0HUIB76Rwrc9abJ9cB9fVWj1OYFqkDiHnd4Ej6FmxC8vdlZwIzjvN8W3iSX_hwsQV5P1x0KfiHkntxUdZnkdkMWtK49l1iIse8s1pQcdoe8y-ICROhCWd7QCgBaGes3DQSSfMks59yqOOrR6PEScO1LjwL2hvxbHcRhT3TaryqP-cU-r6pj8L3OxDiBr6wBzv1iUUC-A6B-Gs1_ym5lbUU-NP_LGpN6nL3_AO_rX-2V_oZalMajM9Xh5ahrtP4zeWI8OANlROLFfmGD5Fo42cMIN3anfQUNJ2syVYeywnAw2HJyGga08NoVtMKktgNg',
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
