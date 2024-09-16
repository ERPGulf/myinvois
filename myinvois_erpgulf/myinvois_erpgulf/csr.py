# from cryptography import x509
# from cryptography.x509.oid import NameOID, ObjectIdentifier
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# # Generate a private key
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

# # Define the distinguished name fields based on the provided information
# subject = x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, u"Contoso Malaysia Sdn Bhd"),  # CN
#     x509.NameAttribute(NameOID.COUNTRY_NAME, u"MY"),  # C
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Contoso Malaysia Sdn Bhd"),  # O
#     x509.NameAttribute(NameOID.SERIAL_NUMBER, u"2020051234562475382886904809774818644480820936050208702411"),  # Serial Number (BRN)
#     x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"noemail@contoso.com"),  # E (Email)
#     # x509.NameAttribute(ObjectIdentifier("2.5.4.97"), u"C20830570210"),  # Organization identifier (TIN)
#     # Optional Organizational Unit (OU)
#     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Contoso Malaysia Sdn Bhd"),  # OU
# ])

# # Create a CSR with the specified subject
# csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

# # Write the CSR to a file
# with open("csr.pem", "wb") as f:
#     f.write(csr.public_bytes(Encoding.PEM))

# # Optionally, write the private key to a file
# with open("private_key.pem", "wb") as f:
#     f.write(private_key.private_bytes(
#         encoding=Encoding.PEM,
#         format=PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=NoEncryption()  # Or use BestAvailableEncryption(b"your_password")
#     ))

# print("CSR and Private Key have been generated and saved.")

from lxml import etree
import hashlib
import base64 
import lxml.etree as MyTree
# import frappe
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
# import frappe
from cryptography.hazmat.primitives.asymmetric import ec

from lxml import etree
from datetime import datetime


import lxml.etree as ET
import hashlib
import base64
import io

# Function to remove unnecessary elements
def remove_elements(xml_root):
    namespaces = {
        'ext': "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        'cac': "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
    }
    # Remove UBLExtensions
    ubl_extensions = xml_root.xpath('//ext:UBLExtensions', namespaces=namespaces)
    for elem in ubl_extensions:
        elem.getparent().remove(elem)
    
    # Remove Signature
    signatures = xml_root.xpath('//cac:Signature', namespaces=namespaces)
    for elem in signatures:
        elem.getparent().remove(elem)

# Function to canonicalize XML using C14N11
def canonicalize_xml(xml_tree):
    output_buffer = io.BytesIO()
    xml_tree.write_c14n(output_buffer, exclusive=False, with_comments=False)
    return output_buffer.getvalue()

# Function to hash using SHA-256 and encode to base64
def hash_and_encode(canonicalized_xml):
    sha256_hash = hashlib.sha256(canonicalized_xml).digest()
    return base64.b64encode(sha256_hash).decode()

# Load and process the XML from file
def process_xml(file_path):
    # Parse XML from file
    with open(file_path, 'r', encoding='utf-8') as file:
        xml_content = file.read()

    parser = ET.XMLParser(remove_blank_text=True, encoding='UTF-8')
    xml_tree = ET.ElementTree(ET.fromstring(xml_content, parser))
    xml_root = xml_tree.getroot()

    # Remove not required elements (UBLExtensions, Signature)
    remove_elements(xml_root)

    # Canonicalize the XML document
    canonicalized_xml = canonicalize_xml(xml_tree)

    # Print the canonicalized XML (before hashing)
    print("Canonicalized XML:")
    print(canonicalized_xml.decode('utf-8'))  # Decode from bytes to string for readability

    # Hash and encode the canonicalized document
    doc_digest = hash_and_encode(canonicalized_xml)

    return doc_digest

# Use file path for XML content



def signature(hash_base64):
        
        private_key_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem'

        with open(private_key_file_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  
                backend=default_backend()
            )

        hash_bytes = base64.b64decode(hash_base64)
        signature = private_key.sign(
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        signature_base64 = base64.b64encode(signature)

        print("Signature:", signature_base64.decode())
        
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
import base64

# Function to hash the certificate and encode it in Base64
def hash_certificate(cert_path):
    try:
        # Load the certificate from the PEM file
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        # Parse the certificate using cryptography's x509 library
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Get the DER encoded form of the certificate
        der_cert = cert.public_bytes(encoding=x509.Encoding.DER)

        # Compute the SHA-256 hash of the DER-encoded certificate
        sha256_hash = hashlib.sha256(der_cert).digest()

        # Encode the hash using Base64
        cert_hash_base64 = base64.b64encode(sha256_hash).decode()

        print("Certificate Hash (Base64):", cert_hash_base64)
        return cert_hash_base64

    except ValueError as e:
        print(f"Error processing the PEM file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
hash1 = process_xml(xml_file_path)
print("Document Digest (Base64):", hash1)
# tag_removed_xml=removeTags()
# canonicalized_xml=canonicalize_xml (tag_removed_xml)
# hash1,hash_base64=getInvoiceHash(canonicalized_xml)
digital_signature = signature(hash1)

# Usage:
certificate_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem'
certificate_hash_base64 = hash_certificate(certificate_file_path)
# signxml_modify()
# hashed_properties_base64 = process_properties_tag()
# result = populate_signed_properties(digital_signature,  hashed_properties_base64, hash1)
# print(result)
# if hashed_properties_base64:
#     print(f"Base64-encoded hashed properties tag: {hashed_properties_base64}")


# import base64

# # Path to your XML file
# xml_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml'

# # Read the XML file and base64 encode it
# with open(xml_file_path, 'rb') as file:
#     encoded_string = base64.b64encode(file.read()).decode('utf-8')

# # Print or use the base64 encoded XML string
# print(encoded_string)
