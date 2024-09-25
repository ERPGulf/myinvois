# import lxml.etree as ET
# import xmlsec
# from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
# from cryptography.hazmat.backends import default_backend

# # Load the XML
# xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/newtest.xml"
# tree = ET.parse(xml_file_path)
# root = tree.getroot()

# # Namespace mappings (adjust these based on your actual namespaces in the XML)
# nsmap = {
#     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#     'ds': 'http://www.w3.org/2000/09/xmldsig#'
# }

# # Create the signature template
# sign_node = xmlsec.template.create(
#     root,
#     xmlsec.Transform.EXCL_C14N,
#     xmlsec.Transform.RSA_SHA256,
#     ns='ds'
# )

# # Add key info and signature properties
# key_info = xmlsec.template.ensure_key_info(sign_node)
# xmlsec.template.add_x509_data(key_info)

# # Insert signature node into the XML
# ext_content = root.find('.//ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent', namespaces=nsmap)
# ext_content.append(sign_node)

# # Load the PFX file
# with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX", "rb") as f:
#     pfx_data = f.read()

# # Load the PFX (certificate and key)
# pfx = pkcs12.load_key_and_certificates(pfx_data, b'Ci8)RmsE', backend=default_backend())

# # Initialize signer context
# signer = xmlsec.SignatureContext()

# # Set the key from the PFX file
# key = xmlsec.Key.from_memory(
#     pfx[0].private_bytes(
#         encoding=Encoding.PEM,
#         format=PrivateFormat.PKCS8,
#         encryption_algorithm=NoEncryption()
#     ),
#     xmlsec.KeyFormat.PEM,
#     None
# )
# signer.key = key

# # Add X509 certificate to the signature key info
# x509_data = xmlsec.template.add_x509_data(key_info)
# x509_data_node = x509_data.find(".//ds:X509Certificate", namespaces=nsmap)
# x509_data_node.text = pfx[1].public_bytes(Encoding.PEM).decode("utf-8")

# # Sign the document
# signer.sign(sign_node)

# # Save the signed XML to a file
# signed_xml_file = "signed_invoice.xml"
# tree.write(signed_xml_file, pretty_print=True, xml_declaration=True, encoding="UTF-8")

# print(f"Signed XML saved to {signed_xml_file}")

# # ---------------------------------------
# # Verify the signed XML
# # ---------------------------------------

# # Load the signed XML
# signed_tree = ET.parse(signed_xml_file)
# signed_root = signed_tree.getroot()

# # Load the signature node
# signature_node = signed_root.find('.//ds:Signature', namespaces=nsmap)

# # Initialize verify context
# verifier = xmlsec.SignatureContext()

# # Set the certificate for verification (from the PFX)
# verifier.key = xmlsec.Key.from_memory(
#     pfx[1].public_bytes(Encoding.PEM),
#     xmlsec.KeyFormat.PEM,
#     None
# )

# # Verify the signature
# try:
#     verifier.verify(signature_node)
#     print("Signature verification succeeded.")
# except xmlsec.VerificationError as e:
#     print("Signature verification failed:", e)

import hashlib
import base64
from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import datetime

class SignatureData:
    def __init__(self):
        self.signature_value = None
        self.props_digest = None
        self.doc_digest = None
        self.cert_digest = None
        self.signing_time = None
        self.x509_certificate = None
        self.x509_issuer_name = None
        self.x509_serial_number = None
        self.x509_subject_name = None

class UBLSignatureXML:
    def __init__(self, xml_path, cert_path, cert_password):
        self.xml_path = xml_path
        self.cert_path = cert_path
        self.cert_password = cert_password
        self.cert = None
        self.private_key = None
        self.sign_data = SignatureData()

    def load_cert(self):
        print("Loading certificate from:", self.cert_path)
        with open(self.cert_path, 'rb') as cert_file:
            pfx_data = cert_file.read()
            private_key, cert, _ = pkcs12.load_key_and_certificates(
                pfx_data,
                self.cert_password.encode(),
                default_backend()
            )
            self.cert = cert
            self.private_key = private_key

    def get_cert_details(self):
        self.sign_data.x509_certificate = base64.b64encode(
            self.cert.public_bytes(serialization.Encoding.DER)
        ).decode('utf-8')

        # Calculate the certificate hash (SHA-256) and base64 encode it
        der_cert = self.cert.public_bytes(serialization.Encoding.DER)
        cert_hash = hashlib.sha256(der_cert).digest()
        self.sign_data.cert_digest = base64.b64encode(cert_hash).decode('utf-8')

        # Ensure correct issuer and serial number
        self.sign_data.x509_issuer_name = self.cert.issuer.rfc4514_string()
        self.sign_data.x509_serial_number = str(self.cert.serial_number)
        self.sign_data.x509_subject_name = self.cert.subject.rfc4514_string()
        self.sign_data.signing_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        print("Certificate subject name:", self.sign_data.x509_subject_name)
        print("Certificate issuer name:", self.sign_data.x509_issuer_name)
        print("Certificate serial number:", self.sign_data.x509_serial_number)
        print("Certificate digest (hash):", self.sign_data.cert_digest)
        print("Signing time:", self.sign_data.signing_time)

    def sha256_hash(self, data):
        print("Generating SHA-256 hash for data...")
        return hashlib.sha256(data).digest()

    def canonicalize_xml(self, xml_tree):
        return etree.tostring(xml_tree, method='c14n', exclusive=True)

    def sign_document(self):
        try:
            # Load and parse XML
            parser = etree.XMLParser(remove_blank_text=True)
            doc = etree.parse(self.xml_path, parser)
            print("XML loaded successfully.")

            # Canonicalize the document (C14N)
            canonical_xml = self.canonicalize_xml(doc)
            doc_hash = self.sha256_hash(canonical_xml)
            self.sign_data.doc_digest = base64.b64encode(doc_hash).decode()
            print(base64.b64encode(doc_hash).decode())
            # Sign the document using RSA private key from the certificate
            signature = self.private_key.sign(
                doc_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.sign_data.signature_value = base64.b64encode(signature).decode('utf-8')
            print("Document signed successfully. Signature value:", self.sign_data.signature_value)

            # Get certificate details
            self.get_cert_details()

            # Hash the signed properties
            signed_props_element = doc.find(".//xades:SignedProperties", namespaces={
                'xades': 'http://uri.etsi.org/01903/v1.3.2#'
            })
            if signed_props_element is not None:
                canonical_signed_props = self.canonicalize_xml(signed_props_element)
                signed_props_hash = self.sha256_hash(canonical_signed_props)
                self.sign_data.props_digest = base64.b64encode(signed_props_hash).decode('utf-8')
                print("Signed Properties Hash (Base64):", self.sign_data.props_digest)
            else:
                print("SignedProperties element not found in the XML.")

            # Modify and insert the signature
            self.modify_and_insert_signature(doc)

            # Save the final signed XML document
            with open("/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb") as signed_file:
                signed_file.write(etree.tostring(doc, pretty_print=True))
            print("Final signed XML saved successfully.")

        except Exception as e:
            print(f"Error during document signing: {str(e)}")

    def modify_and_insert_signature(self, doc):
        try:
            print("Modifying XML with signature details...")

            namespaces = {
                'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
                'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
                'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
                'xades': 'http://uri.etsi.org/01903/v1.3.2#',
                'ds': 'http://www.w3.org/2000/09/xmldsig#'
            }

            # Modify XML with signature value, certificate, signed properties digest, and document digest
            signature_value_element = doc.find(".//ds:SignatureValue", namespaces)
            if signature_value_element is not None:
                signature_value_element.text = self.sign_data.signature_value

            cert_element = doc.find(".//ds:X509Certificate", namespaces)
            if cert_element is not None:
                cert_element.text = self.sign_data.x509_certificate

            # Set Issuer Name and Serial Number
            issuer_element = doc.find(".//ds:X509IssuerName", namespaces)
            if issuer_element is not None:
                issuer_element.text = self.sign_data.x509_issuer_name

            serial_element = doc.find(".//ds:X509SerialNumber", namespaces)
            if serial_element is not None:
                serial_element.text = self.sign_data.x509_serial_number

            # Add digest values for SignedProperties and Document
            props_digest_element = doc.find(".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue", namespaces)
            if props_digest_element is not None:
                props_digest_element.text = self.sign_data.props_digest

            doc_digest_element = doc.find(".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue", namespaces)
            if doc_digest_element is not None:
                doc_digest_element.text = self.sign_data.doc_digest

            print("Signature, certificate, and digest values inserted successfully.")

        except Exception as e:
            print("Error during XML modification: " + str(e))


if __name__ == "__main__":
    xml_signer = UBLSignatureXML(
        xml_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml", 
        cert_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX", 
        cert_password="Ci8)RmsE"
    )
    xml_signer.load_cert()
    xml_signer.sign_document()



import hashlib
import base64

def compute_certificate_hash_base64(certificate_data):
    # Encode certificate data to bytes
    certificate_data_bytes = certificate_data.encode('utf-8')
    
    # Compute the SHA-256 hash (in bytes, not hex)
    sha256_hash = hashlib.sha256(certificate_data_bytes).digest()
    
    # Encode the binary hash in base64
    base64_encoded_hash = base64.b64encode(sha256_hash).decode('utf-8')
    
    return base64_encoded_hash

# Example usage
certificate_data = "MIIFdjCCA16gAwIBAgIDBWvEMA0GCSqGSIb3DQEBCwUAMHUxCzAJBgNVBAYTAk1ZMQ4wDAYDVQQKEwVMSEROTTE2MDQGA1UECxMtVGVybXMgb2YgdXNlIGF0IGh0dHA6Ly93d3cucG9zZGlnaWNlcnQuY29tLm15MR4wHAYDVQQDExVUcmlhbCBMSEROTSBTdWIgQ0EgVjEwHhcNMjQwNjI4MjMxNTAxWhcNMjQwOTI2MjMxNTAxWjCBizELMAkGA1UEBhMCTVkxFjAUBgNVBAoTDVRIQyBTRE4uIEJIRC4xEzARBgNVBGETCkM4ODgyODEwOTAxFjAUBgNVBAMTDVRIQyBTRE4uIEJIRC4xFTATBgNVBAUTDDE5NzgwMTAwMDA3NDEgMB4GCSqGSIb3DQEJARYRbGMudGFuQHRoYy5jb20ubXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoxfC5OkAAwKYECZZfa6oSlpCnglh1kINlg3i1ai1CqZfBG71QJYQ6Tf2X8UPXLcWBr3SbrBArD+a15ydEOnwP9b7XnT/yyJSugMULY81szRnsPp85VUBJ8zcQimq1L+Hir+s9hFxLZHL2MMQQ2/mL2+M5EaspYtX7OhspMYlmqZOxp/MnKESZyZiv90gLkPUg2BUAwh+igtpjCBKFvFpKpgSbraasne8Zsbmse4Sq8i0bj1fLhNMkU57X6Ybgn/VZHcvzSmUymSHmmkK+FaN5IGOiEdU3lQ1alesktsbNaGcfWKy5f2Iig9gxsSb0r326VFutr855Kd+xDXv2AaUjAgMBAAGjgfcwgfQwHwYDVR0lBBgwFgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwEQYDVR0OBAoECEFpaJN3wvTBMFMGA1UdIARMMEowSAYJKwYBBAGDikUBMDswOQYIKwYBBQUHAgEWLWh0dHBzOi8vd3d3LnBvc2RpZ2ljZXJ0LmNvbS5teS9yZXBvc2l0b3J5L2NwczATBgNVHSMEDDAKgAhNf9lrtsUI0DAOBgNVHQ8BAf8EBAMCBkAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL3RyaWFsY3JsLnBvc2RpZ2ljZXJ0LmNvbS5teS9UcmlhbExIRE5NVjEuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQCnOiF+oMJVGWXlZ3nvol17rdeMGVVeOiWa6oV1lR14I4qwqgSUB82GzsAoPvbyshUeov1lxBkvM9TUeC7atROEgbQNOMUXS/bVeTOLrFZ9l8hZQhGDGBJa2NiURsvLfdT7MAIQMO74C2Bc06u6Uhcrcpbz2wWSbthwRgJ/xHlIhqULGN9a2mAv/lcQDD88ujOBSALOB8aE6V/cmhfmNoLdgDtoHVclwxstLEgFI+UyTU0UU3LOL4lTL04/hA9fFIhN/aZAlSvNTkzcCSIlMzVsVYHDsuelY8aHJ61v4GrV4yRVwWLXwYzAyZJ9zP8C0VoTakUMgBZt+59Dis2xpHGHnJNGkKhHyAFRrMi4Lny6wSJys7SkhsbnEt94PvBvhv0jTx7VVjvpZF5G69iyPq366FXPsKdFGXg3slr0ecnFy839zSquxzGHGpPUj+Oq8dHzdf4kBngyO+yyg42JLNAGmq3cCVqytJCuYvs7q1m9IHliiZRlRtOW5SufdGM9NBCO/dtRdz3HjlJ4DsMnUPPZLNRC7DM84XCT9hyP6cnaQhYL2L9myPTTJ4C2Nxu/P/XUWPUP7vmBEWI5vANAfSwiUwVdwD8RFd+y+VWc3rpp1o16cWR9kpt6FHA0qvcQedoJTx+bxcp3jpr6A9wjAi8OggRTRp3QNwGe2ygV4gndaQ=="
hash_result = compute_certificate_hash_base64(certificate_data)
print(hash_result)


# import base64
# import hashlib
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.serialization import pkcs12
# from cryptography.hazmat.backends import default_backend

# def load_pfx_and_sign(pfx_path, pfx_password, data_to_sign):
#     # Load the PFX file
#     with open(pfx_path, 'rb') as pfx_file:
#         pfx_data = pfx_file.read()
    
#     # Extract the private key, certificate, and additional certificates from the PFX
#     private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
#         pfx_data, pfx_password.encode('utf-8') if pfx_password else None, backend=default_backend()
#     )

#     # Ensure we have the private key
#     if private_key is None:
#         raise ValueError("Private key not found in the PFX file.")

#     # Compute the hash of the data you want to sign (assuming it's in hexadecimal)
#     hash_bytes = bytes.fromhex(data_to_sign)

#     # Sign the hash using the private key with RSA PKCS1v15 padding and SHA-256
#     signature = private_key.sign(
#         hash_bytes,
#         padding.PKCS1v15(),
#         hashes.SHA256()
#     )

#     # Encode the signature in base64
#     encoded_signature = base64.b64encode(signature).decode('utf-8')

#     return encoded_signature

# # Example usage
# pfx_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX"
# pfx_password = "Ci8)RmsE"
# data_to_sign = "3bafe22054b54e758b4c37271255c874fd740bee5baf82a570a23601e2f68ddd"  # Ensure this is in hexadecimal string format
# signature = load_pfx_and_sign(pfx_path, pfx_password, data_to_sign)
# print("Signature:", signature)



# import base64
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

# def format_certificate_and_extract_info(certificate_content):
#     # Properly format the certificate by adding the BEGIN and END tags and wrapping at 64 characters
#     formatted_certificate = "-----BEGIN CERTIFICATE-----\n"
#     formatted_certificate += "\n".join(certificate_content[i:i+64] for i in range(0, len(certificate_content), 64))
#     formatted_certificate += "\n-----END CERTIFICATE-----\n"

#     # Load the certificate using cryptography
#     certificate_bytes = formatted_certificate.encode('utf-8')
#     cert = x509.load_pem_x509_certificate(certificate_bytes, default_backend())

#     # Extract the issuer name and serial number
#     formatted_issuer_name = cert.issuer.rfc4514_string()
#     issuer_name = ", ".join([x.strip() for x in formatted_issuer_name.split(',')])
#     serial_number = cert.serial_number

#     return issuer_name, serial_number

# # Example certificate content (base64-encoded certificate without BEGIN/END lines)
# certificate_content = """MIIFdjCCA16gAwIBAgIDBWvEMA0GCSqGSIb3DQEBCwUAMHUxCzAJBgNVBAYTAk1ZMQ4wDAYDVQQKEwVMSEROTTE2MDQGA1UECxMtVGVybXMgb2YgdXNlIGF0IGh0dHA6Ly93d3cucG9zZGlnaWNlcnQuY29tLm15MR4wHAYDVQQDExVUcmlhbCBMSEROTSBTdWIgQ0EgVjEwHhcNMjQwNjI4MjMxNTAxWhcNMjQwOTI2MjMxNTAxWjCBizELMAkGA1UEBhMCTVkxFjAUBgNVBAoTDVRIQyBTRE4uIEJIRC4xEzARBgNVBGETCkM4ODgyODEwOTAxFjAUBgNVBAMTDVRIQyBTRE4uIEJIRC4xFTATBgNVBAUTDDE5NzgwMTAwMDA3NDEgMB4GCSqGSIb3DQEJARYRbGMudGFuQHRoYy5jb20ubXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoxfC5OkAAwKYECZZfa6oSlpCnglh1kINlg3i1ai1CqZfBG71QJYQ6Tf2X8UPXLcWBr3SbrBArD+a15ydEOnwP9b7XnT/yyJSugMULY81szRnsPp85VUBJ8zcQimq1L+Hir+s9hFxLZHL2MMQQ2/mL2+M5EaspYtX7OhspMYlmqZOxp/MnKESZyZiv90gLkPUg2BUAwh+igtpjCBKFvFpKpgSbraasne8Zsbmse4Sq8i0bj1fLhNMkU57X6Ybgn/VZHcvzSmUymSHmmkK+FaN5IGOiEdU3lQ1alesktsbNaGcfWKy5f2Iig9gxsSb0r326VFutr855Kd+xDXv2AaUjAgMBAAGjgfcwgfQwHwYDVR0lBBgwFgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwEQYDVR0OBAoECEFpaJN3wvTBMFMGA1UdIARMMEowSAYJKwYBBAGDikUBMDswOQYIKwYBBQUHAgEWLWh0dHBzOi8vd3d3LnBvc2RpZ2ljZXJ0LmNvbS5teS9yZXBvc2l0b3J5L2NwczATBgNVHSMEDDAKgAhNf9lrtsUI0DAOBgNVHQ8BAf8EBAMCBkAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL3RyaWFsY3JsLnBvc2RpZ2ljZXJ0LmNvbS5teS9UcmlhbExIRE5NVjEuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQCnOiF+oMJVGWXlZ3nvol17rdeMGVVeOiWa6oV1lR14I4qwqgSUB82GzsAoPvbyshUeov1lxBkvM9TUeC7atROEgbQNOMUXS/bVeTOLrFZ9l8hZQhGDGBJa2NiURsvLfdT7MAIQMO74C2Bc06u6Uhcrcpbz2wWSbthwRgJ/xHlIhqULGN9a2mAv/lcQDD88ujOBSALOB8aE6V/cmhfmNoLdgDtoHVclwxstLEgFI+UyTU0UU3LOL4lTL04/hA9fFIhN/aZAlSvNTkzcCSIlMzVsVYHDsuelY8aHJ61v4GrV4yRVwWLXwYzAyZJ9zP8C0VoTakUMgBZt+59Dis2xpHGHnJNGkKhHyAFRrMi4Lny6wSJys7SkhsbnEt94PvBvhv0jTx7VVjvpZF5G69iyPq366FXPsKdFGXg3slr0ecnFy839zSquxzGHGpPUj+Oq8dHzdf4kBngyO+yyg42JLNAGmq3cCVqytJCuYvs7q1m9IHliiZRlRtOW5SufdGM9NBCO/dtRdz3HjlJ4DsMnUPPZLNRC7DM84XCT9hyP6cnaQhYL2L9myPTTJ4C2Nxu/P/XUWPUP7vmBEWI5vANAfSwiUwVdwD8RFd+y+VWc3rpp1o16cWR9kpt6FHA0qvcQedoJTx+bxcp3jpr6A9wjAi8OggRTRp3QNwGe2ygV4gndaQ=="""

# # Extract issuer name and serial number
# issuer_name, serial_number = format_certificate_and_extract_info(certificate_content)
# print("Issuer Name:", issuer_name)
# print("Serial Number:", serial_number)



import os
import hashlib
import base64
from lxml import etree
import xmlsec
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Initialize xmlsec library
xmlsec.init()

# File paths
xml_file = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
output_file = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/final_can.xml"
certificate_file = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem"  # Path to your certificate file

# Canonicalize the XML (C14N 1.1 without comments)
def canonicalize_xml(input_xml_path, output_xml_path):
    try:
        # Parse the XML file
        with open(input_xml_path, 'rb') as f:
            root = etree.parse(f)

        # Canonicalize the XML (C14N 1.1 without comments)
        canonical_xml = etree.tostring(root, method="c14n", exclusive=False, with_comments=False)

        # Write the canonicalized XML to the output file
        with open(output_xml_path, 'wb') as f_out:
            f_out.write(canonical_xml)

        print(f"Canonicalized XML written to {output_xml_path}")
    
    except Exception as e:
        print(f"Error during canonicalization: {e}")

# Function to read file content
def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content
    except IOError as e:
        print(f"Error reading file: {e}")
        return None

# Function to calculate SHA-256 and encode in Base64
def calculate_sha256_base64(input_data):
    try:
        # Calculate the SHA-256 hash
        sha256_hash = hashlib.sha256(input_data).digest()
        print("val is",sha256_hash )
        # Encode the hash in Base64
        base64_hash = base64.b64encode(sha256_hash).decode('utf-8')
        
        return base64_hash
    except Exception as e:
        raise RuntimeError(f"Error during hash calculation: {e}")

# Function to calculate the SHA-256 hash of a certificate
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Function to calculate the SHA-256 hash of a certificate
def calculate_certificate_hash_base64(cert_path):
    try:
        # Read the certificate file
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()

        # Load the certificate using cryptography library
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Get the encoded form of the certificate (DER format)
        cert_encoded = cert.public_bytes(serialization.Encoding.DER)

        # Calculate the SHA-256 hash of the certificate
        cert_hash_base64 = calculate_sha256_base64(cert_encoded)
        
        return cert_hash_base64
    except Exception as e:
        raise RuntimeError(f"Error calculating certificate hash: {e}")


# Main execution
if __name__ == "__main__":
    # Canonicalize the XML
    canonicalize_xml(xml_file, output_file)

    # Read the canonicalized XML file
    file_content = read_file(output_file)

    # Check if the content is not None
    if file_content:
        # Calculate the Base64 encoded SHA-256 hash of the XML content
        hash_base64 = calculate_sha256_base64(file_content.encode('utf-8'))
        print(f"SHA-256 Hash of Canonicalized XML in Base64: {hash_base64}")
    else:
        print("Failed to read the canonicalized XML file.")

    # # Calculate the SHA-256 hash of the certificate in Base64
    cert_hash_base64 = calculate_certificate_hash_base64(certificate_file)
    print(f"SHA-256 Certificate Hash in Base64: {cert_hash_base64}")



    