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
    'Authorization': 'Bearer ',
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
