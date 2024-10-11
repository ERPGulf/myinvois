# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import pkcs12
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
# from lxml import etree
# import hashlib
# import base64
# from lxml import etree
# import hashlib
# import base64
# import datetime
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.x509 import load_pem_x509_certificate
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, BestAvailableEncryption, PrivateFormat
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes, serialization
# import datetime

# def process_xml(file_path):
#     parser = etree.XMLParser(encoding='UTF-8')
#     tree = etree.parse(file_path, parser)
#     root = tree.getroot()

#     nsmap = {
#         'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
#         'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
#         'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
#     }

#     ubl_extensions = root.xpath('.//*[local-name()="UBLExtensions"]', namespaces=nsmap)
#     for ext in ubl_extensions:
#         ext.getparent().remove(ext)
#     signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
#     for sig in signatures:
#         sig.getparent().remove(sig)
#     processed_xml = etree.tostring(root, pretty_print=True, encoding='UTF-8').decode('UTF-8')
#     print(processed_xml)

#     with open('processed_output.xml', 'wb') as f:
#         tree.write(f, encoding='UTF-8', xml_declaration=False)
#     return processed_xml

# def canonicalize_and_hash_xml(xml):
#     parser = etree.XMLParser(remove_blank_text=True)
#     tree = etree.parse(xml, parser)
#     canonicalized_xml = etree.tostring(tree, method="c14n")
#     sha256_hash = hashlib.sha256(canonicalized_xml).digest()  
#     return sha256_hash

# def load_pfx_certificate(pfx_path, pfx_password):
#     with open(pfx_path, 'rb') as f:
#         pfx_data = f.read()

#     # Load the private key and certificate
#     private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
#         pfx_data,
#         pfx_password.encode('utf-8'),
#         backend=default_backend()
#     )
    
#     if isinstance(private_key, rsa.RSAPrivateKey):
#         print("This is an RSA private key.")
#     else:
#         print("This is not an RSA private key.")

#     certificate_base64 = base64.b64encode(
#             certificate.public_bytes(serialization.Encoding.DER)
#         ).decode('utf-8')
    
#     return private_key, certificate, certificate_base64





# def bytes_to_base64_string(value: bytes) -> str:   
#    return base64.b64encode(value).decode('ASCII')

# def sign_data(processed_xml):
#     # print(single_line_xml1)
#     hashdata = processed_xml.encode() 
#     f = open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/output.pem", "r")
#     cert_pem=f.read()
#     if hashdata is None:
#         raise ValueError("hashdata cannot be None")
#     if cert_pem is None:
#         raise ValueError("cert_pem cannot be None")
#     cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
#     print(cert.issuer)
#     private_key = serialization.load_pem_private_key(
#         cert_pem.encode(),
#         password='EO1TM1NA'.encode(),
#     )
    
#     if private_key is None or not isinstance(private_key, rsa.RSAPrivateKey):
#         raise ValueError("The certificate does not contain an RSA private key.")
    
#     try:
#         signed_data = private_key.sign(
#             hashdata,
#             padding.PKCS1v15(),
#             hashes.SHA256()        
#         )
#         base64_bytes = base64.b64encode(signed_data)
#         base64_string = base64_bytes.decode("ascii")
#         print(f"Encoded string: {base64_string}")
#     except InvalidSignature as ex:
#         raise Exception("An error occurred while signing the data.") from ex
#     return base64_string


# def encode_to_base64(data):
#     return base64.b64encode(data).decode('utf-8')

# def get_cert_details(cert):
#     try:
#         x509_certificate = base64.b64encode(
#             cert.public_bytes(serialization.Encoding.DER)
#         ).decode('utf-8')
#         # print(x509_certificate)
#         der_cert = cert.public_bytes(serialization.Encoding.DER)
#         cert_hash = hashlib.sha256(der_cert).digest()
#         cert_digest = base64.b64encode(cert_hash).decode('utf-8')
#         x509_issuer_name ="CN=LHDNM Sub CA G3, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
#         x509_serial_number = cert.serial_number
#         x509_subject_name = cert.subject.rfc4514_string()
#         # print(x509_issuer_name)
#         # print(x509_serial_number)
#         signing_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
#         # print(signing_time)
#         return x509_issuer_name, x509_serial_number, cert_digest, signing_time
#     except Exception as e:
#         print(f"Error loading certificate details: {str(e)}")
#         return None

# def signxml_modify(encoded_certificate_hash, issuer_name, serial_number, signing_time):
#     try:
#         original_invoice_xml = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml")
#         root = original_invoice_xml.getroot()

#         namespaces = {
#             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#             'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#             'ds': 'http://www.w3.org/2000/09/xmldsig#'
#         }

#         xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                     "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                     "xades:SignedProperties/xades:SignedSignatureProperties/"
#                     "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
#         xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                           "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                           "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
#         xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                             "xades:SignedProperties/xades:SignedSignatureProperties/"
#                             "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
#         xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                            "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                            "xades:SignedProperties/xades:SignedSignatureProperties/"
#                            "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")

#         element_dv = root.find(xpath_dv, namespaces)
#         element_st = root.find(xpath_signTime, namespaces)
#         element_in = root.find(xpath_issuerName, namespaces)
#         element_sn = root.find(xpath_serialNum, namespaces)

#         element_dv.text = encoded_certificate_hash
#         element_st.text = signing_time
#         element_in.text = issuer_name
#         element_sn.text = str(serial_number)

#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml", 'wb') as file:
#             original_invoice_xml.write(file, encoding='utf-8',  xml_declaration=False)

#         return namespaces

#     except Exception as e:
#         print("Error in signing XML: " + str(e))



# def populate_signed_properties(digital_signature, certificate_base64, signed_properties_hash, invoice_hash):
#     try:
#         tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
#         root = tree.getroot()

#         namespaces = {
#             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#             'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#             'ds': 'http://www.w3.org/2000/09/xmldsig#',
#             'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
#             'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2'
#         }

#         xpath_signature_value = ".//ds:SignatureValue"
#         xpath_x509_certificate = ".//ds:X509Certificate"
#         xpath_signed_props_digest = ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
#         xpath_doc_signed_digest = ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"

#         signature_value_element = root.find(xpath_signature_value, namespaces)
#         if signature_value_element is not None:
#             signature_value_element.text = digital_signature

#         x509_certificate_element = root.find(xpath_x509_certificate, namespaces)
#         if x509_certificate_element is not None:
#             x509_certificate_element.text = certificate_base64

#         signed_props_digest_element = root.find(xpath_signed_props_digest, namespaces)
#         if signed_props_digest_element is not None:
#             signed_props_digest_element.text = signed_properties_hash

#         doc_signed_digest_element = root.find(xpath_doc_signed_digest, namespaces)
#         if doc_signed_digest_element is not None:
#             doc_signed_digest_element.text = invoice_hash

#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml", 'wb') as file:
#             tree.write(file, encoding='utf-8',  xml_declaration=False)

#         return "Successfully populated the signed properties."

#     except Exception as e:
#         print("Error in populating signed properties: " + str(e))

# # Example usage
# xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml'
# processed_xml=process_xml(xml_file)
# xml = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/processed_output.xml'
# pfx_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/THC SDN. BHD.p12'
# pfx_password = 'EO1TM1NA'

# hashed_doc = canonicalize_and_hash_xml(xml)
# print(hashed_doc)
# doc_digest = encode_to_base64(hashed_doc)

# print(doc_digest)
# private_key, certificate, certificate_base64 = load_pfx_certificate(pfx_path, pfx_password)

# # signature_value = sign_with_private_key(private_key, hashed_doc)

# signature=sign_data(processed_xml);

# # sig_base64 = encode_to_base64(signature_value)

# # print(sig_base64)
# x509_issuer_name, x509_serial_number, cert_digest, signing_time = get_cert_details(certificate)
# signxml_modify(cert_digest, x509_issuer_name, x509_serial_number, signing_time)
# print(cert_digest)
# xml_file_after_step_6 = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml"

# # Assign your dynamic values
# signing_time = signing_time
# certificate_hash =cert_digest# Example cert digest value
# issuer_name =x509_issuer_name
# serial_number = x509_serial_number

# single_line_xml = f'''<xades:SignedProperties Id="id-xades-signed-props" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:SignedSignatureProperties><xades:SigningTime>{signing_time}</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:DigestMethod><ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{certificate_hash}</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{issuer_name}</ds:X509IssuerName><ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{serial_number}</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>'''

# prop_cert_hash = hashlib.sha256(single_line_xml.encode('utf-8')).digest()

# # Convert the hash to Base64
# prop_cert_base64 = base64.b64encode(prop_cert_hash).decode('utf-8')

# # Output the Base64 encoded hash
# print(f"SHA-256 Hash in Base64 (propCert): {prop_cert_base64}")

# print(single_line_xml)
# populate_signed_properties(signature, certificate_base64,prop_cert_base64, doc_digest)





# import base64
# import hashlib
# import datetime
# from lxml import etree
# from cryptography.hazmat.primitives.serialization import (
#     pkcs12,
#     load_pem_public_key,
#     load_pem_private_key,
# )
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import serialization


# class SignatureData:
#     def __init__(self):
#         self.signature_value = None
#         self.props_digest = None
#         self.doc_digest = None
#         self.cert_digest = None
#         self.signing_time = None
#         self.x509_certificate = None
#         self.x509_issuer_name = None
#         self.x509_serial_number = None
#         self.x509_subject_name = None


# class UBLSignatureXML:
#     def __init__(
#         self, xml_path, cert_path, cert_password, public_key_path, private_key_path
#     ):
#         self.xml_path = xml_path
#         self.cert_path = cert_path
#         self.cert_password = cert_password
#         self.public_key_path = public_key_path
#         self.private_key_path = private_key_path
#         self.cert = None
#         self.private_key = None
#         self.public_key = None
#         self.sign_data = SignatureData()

#     def load_cert(self):
#         print("Loading certificate from:", self.cert_path)
#         with open(self.cert_path, "rb") as cert_file:
#             pfx_data = cert_file.read()
#             _, cert, _ = pkcs12.load_key_and_certificates(
#                 pfx_data, self.cert_password.encode(), default_backend()
#             )
#             self.cert = cert
#             print("Certificate loaded successfully.")

#     def load_private_key(self):
#         print("Loading private key from PEM file:", self.private_key_path)
#         with open(self.private_key_path, "rb") as key_file:
#             self.private_key = load_pem_private_key(
#                 key_file.read(),
#                 password=None,  # If there's a password, provide it here
#                 backend=default_backend(),
#             )
#         print("Private key loaded successfully.")

#     def load_public_key(self):
#         print("Loading public key from PEM file:", self.public_key_path)
#         with open(self.public_key_path, "rb") as pub_file:
#             self.public_key = load_pem_public_key(
#                 pub_file.read(), backend=default_backend()
#             )
#         print("Public key loaded successfully.")

#     def get_cert_details(self):
#         try:
#             # Encode the certificate to DER format and then base64 encode it
#             self.sign_data.x509_certificate = base64.b64encode(
#                 self.cert.public_bytes(serialization.Encoding.DER)
#             ).decode("utf-8")

#             # Calculate and store the certificate's digest (SHA-256)
#             der_cert = self.cert.public_bytes(serialization.Encoding.DER)
#             cert_hash = hashlib.sha256(der_cert).digest()
#             self.sign_data.cert_digest = base64.b64encode(cert_hash).decode("utf-8")

#             # Use rfc4514_string() to ensure proper formatting for issuer and subject names
#             self.sign_data.x509_issuer_name = self.cert.issuer.rfc4514_string()
#             self.sign_data.x509_serial_number = self.cert.serial_number
#             self.sign_data.x509_subject_name = self.cert.subject.rfc4514_string()
#             self.sign_data.signing_time = datetime.datetime.utcnow().strftime(
#                 "%Y-%m-%dT%H:%M:%SZ"
#             )

#             # Debugging: Print certificate and other details
#             print("Certificate (Base64):", self.sign_data.x509_certificate)
#             print("Certificate subject name:", self.sign_data.x509_subject_name)
#             print(
#                 "Certificate issuer name:", self.sign_data.x509_issuer_name
#             )  # Extracted dynamically
#             print("Certificate serial number:", self.sign_data.x509_serial_number)
#             print("Certificate digest (hash):", self.sign_data.cert_digest)
#             print("Signing time:", self.sign_data.signing_time)

#         except Exception as e:
#             print(f"Error loading certificate details: {str(e)}")

#     def sha256_hash(self, data):
#         print("Generating SHA-256 hash for data...")
#         return hashlib.sha256(data).digest()

#     def canonicalize_xml(self, xml_tree):
#         return etree.tostring(xml_tree, method="c14n", exclusive=True)

#     def get_signed_properties_hash(self, doc):
#         signed_props_element = doc.find(
#             ".//xades:SignedProperties",
#             namespaces={"xades": "http://uri.etsi.org/01903/v1.3.2#"},
#         )

#         if signed_props_element is not None:
#             canonical_signed_props = self.canonicalize_xml(signed_props_element)
#             signed_properties_hash = self.sha256_hash(canonical_signed_props)
#             return base64.b64encode(signed_properties_hash).decode("utf-8")
#         else:
#             print("SignedProperties element not found.")
#             return None

#     def process_xml(self, file_path):
#         parser = etree.XMLParser(encoding="UTF-8")
#         tree = etree.parse(file_path, parser)
#         root = tree.getroot()

#         nsmap = {
#             "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
#             "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
#             "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
#         }

#         ubl_extensions = root.xpath(
#             './/*[local-name()="UBLExtensions"]', namespaces=nsmap
#         )
#         for ext in ubl_extensions:
#             ext.getparent().remove(ext)

#         signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
#         for sig in signatures:
#             sig.getparent().remove(sig)

#         with open("processed_output.xml", "wb") as f:
#             tree.write(f, encoding="UTF-8", xml_declaration=False)

#         print("XML processed successfully.")

#     def canonicalize_and_hash_xml(self, xml):
#         parser = etree.XMLParser(remove_blank_text=True)
#         tree = etree.parse(xml, parser)

#         canonicalized_xml = etree.tostring(tree, method="c14n")
#         print("Canonicalized XML:", canonicalized_xml)

#         sha256_hash = hashlib.sha256(canonicalized_xml).digest()

#         return sha256_hash

#     def sign_document(self):
#         try:
#             self.load_cert()
#             self.load_private_key()

#             self.process_xml(self.xml_path)
#             canonical_xml_hash = self.canonicalize_and_hash_xml("processed_output.xml")

#             self.sign_data.doc_digest = base64.b64encode(canonical_xml_hash).decode(
#                 "utf-8"
#             )
#             print("Document digest (Base64):", self.sign_data.doc_digest)

#             signature = self.private_key.sign(
#                 canonical_xml_hash, padding.PKCS1v15(), hashes.SHA256()
#             )
#             self.sign_data.signature_value = base64.b64encode(signature).decode("utf-8")
#             print(
#                 "Document signed successfully. Signature value:",
#                 self.sign_data.signature_value,
#             )

#             self.get_cert_details()

#             self.sign_data.props_digest = self.get_signed_properties_hash(
#                 etree.parse("processed_output.xml")
#             )

#             self.modify_and_insert_signature(
#                 etree.parse("processed_output.xml"),
#                 self.sign_data.props_digest,
#                 self.sign_data.doc_digest,
#             )

#             with open(
#                 "/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb"
#             ) as signed_file:
#                 signed_file.write(
#                     etree.tostring(
#                         etree.parse("processed_output.xml"), pretty_print=True
#                     )
#                 )
#             print("Final signed XML saved successfully.")

#             self.verify_signature(canonical_xml_hash, signature)

#         except Exception as e:
#             print(f"Error during document signing: {str(e)}")

#     def verify_signature(self, doc_hash, signature):
#         try:
#             self.load_public_key()
#             print("Verifying signature...")
#             self.public_key.verify(
#                 signature, doc_hash, padding.PKCS1v15(), hashes.SHA256()
#             )
#             print("Signature verified successfully.")
#         except Exception as e:
#             print(f"Signature verification failed: {str(e)}")

#     def modify_and_insert_signature(self, doc, signed_properties_hash, doc_hash):
#         try:
#             print("Modifying XML with signature details...")

#             namespaces = {
#                 "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
#                 "sig": "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2",
#                 "sac": "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2",
#                 "xades": "http://uri.etsi.org/01903/v1.3.2#",
#                 "ds": "http://www.w3.org/2000/09/xmldsig#",
#             }

#             xpath_signature_value = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:SignatureValue"
#             )
#             xpath_x509_certificate = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
#             )
#             xpath_signed_props_digest = (
#                 ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
#             )
#             xpath_doc_signed_digest = (
#                 ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
#             )

#             signature_value_element = doc.find(xpath_signature_value, namespaces)
#             x509_certificate_element = doc.find(xpath_x509_certificate, namespaces)
#             signed_props_digest_element = doc.find(
#                 xpath_signed_props_digest, namespaces
#             )
#             doc_signed_digest_element = doc.find(xpath_doc_signed_digest, namespaces)

#             if signature_value_element is None or x509_certificate_element is None:
#                 signature_info_path = "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation"
#                 signature_info_element = doc.find(signature_info_path, namespaces)
#                 if signature_info_element is None:
#                     ubl_extensions = doc.find("ext:UBLExtensions", namespaces)
#                     if ubl_extensions is None:
#                         ubl_extensions = etree.SubElement(
#                             doc.getroot(),
#                             "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtensions",
#                         )

#                     ubl_extension = etree.SubElement(
#                         ubl_extensions,
#                         "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension",
#                     )
#                     extension_content = etree.SubElement(
#                         ubl_extension,
#                         "{urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2}ExtensionContent",
#                     )
#                     signature_info_element = etree.SubElement(
#                         extension_content,
#                         "{urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2}SignatureInformation",
#                     )

#                 ds_signature = etree.SubElement(
#                     signature_info_element,
#                     "{http://www.w3.org/2000/09/xmldsig#}Signature",
#                 )
#                 signature_value_element = etree.SubElement(
#                     ds_signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue"
#                 )
#                 ds_key_info = etree.SubElement(
#                     ds_signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
#                 )
#                 ds_x509_data = etree.SubElement(
#                     ds_key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data"
#                 )
#                 x509_certificate_element = etree.SubElement(
#                     ds_x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
#                 )

#             signature_value_element.text = self.sign_data.signature_value
#             x509_certificate_element.text = self.sign_data.x509_certificate

#             if signed_props_digest_element is not None:
#                 signed_props_digest_element.text = signed_properties_hash

#             if doc_signed_digest_element is not None:
#                 doc_signed_digest_element.text = doc_hash

#             xpath_dv = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                 "xades:SignedProperties/xades:SignedSignatureProperties/"
#                 "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue"
#             )
#             xpath_signTime = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                 "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime"
#             )
#             xpath_issuerName = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                 "xades:SignedProperties/xades:SignedSignatureProperties/"
#                 "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName"
#             )
#             xpath_serialNum = (
#                 "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                 "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                 "xades:SignedProperties/xades:SignedSignatureProperties/"
#                 "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber"
#             )

#             element_dv = doc.find(xpath_dv, namespaces)
#             element_st = doc.find(xpath_signTime, namespaces)
#             element_in = doc.find(xpath_issuerName, namespaces)
#             element_sn = doc.find(xpath_serialNum, namespaces)

#             if element_dv is not None:
#                 element_dv.text = self.sign_data.cert_digest
#             if element_st is not None:
#                 element_st.text = self.sign_data.signing_time
#             if element_in is not None:
#                 element_in.text = self.sign_data.x509_issuer_name
#             if element_sn is not None:
#                 element_sn.text = str(self.sign_data.x509_serial_number)

#             print("Signature, certificate, and digest values inserted successfully.")

#         except Exception as e:
#             print("Error during XML modification: " + str(e))


# if __name__ == "__main__":
#     xml_signer = UBLSignatureXML(
#         xml_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml",
#         cert_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX",
#         cert_password="Ci8)RmsE",
#         public_key_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/publickey.pem",
#         private_key_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem",
#     )
#     # xml_signer.sign_document()

# import hashlib
# import base64
# from lxml import etree

# # XML content with namespaces
# xml_content = '''
# <xades:SignedProperties Id="id-xades-signed-props" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
#   <xades:SignedSignatureProperties>
#     <xades:SigningTime>2024-07-16T03:36:15Z</xades:SigningTime>
#     <xades:SigningCertificate>
#       <xades:Cert>
#         <xades:CertDigest>
#           <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
#           <ds:DigestValue>SLFswNMf8a6muzczA+EO356bvJNDkr9LhT25+pqacdE=</ds:DigestValue>
#         </xades:CertDigest>
#         <xades:IssuerSerial>
#           <ds:X509IssuerName>CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY</ds:X509IssuerName>
#           <ds:X509SerialNumber>352825</ds:X509SerialNumber>
#         </xades:IssuerSerial>
#       </xades:Cert>
#     </xades:SigningCertificate>
#   </xades:SignedSignatureProperties>
# </xades:SignedProperties>
# '''

# # Parse the XML string
# parser = etree.XMLParser(remove_blank_text=True)
# tree = etree.fromstring(xml_content, parser)

# # Define the namespaces
# namespaces = {
#     'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#     # 'ds': 'http://www.w3.org/2000/09/xmldsig#'
# }

# # Extract the <xades:SignedProperties> block using XPath
# signed_props = tree.xpath('/xades:SignedProperties', namespaces=namespaces)

# if signed_props:
#     # Convert the SignedProperties block to a string (canonicalized/minified XML)
#     signed_props_str = etree.tostring(signed_props[0], method='c14n').decode('utf-8')
#     print("Canonicalized SignedProperties:\n",signed_props_str)

#     # Compute the SHA-256 hash of the SignedProperties block
#     sha256_hash = hashlib.sha256(signed_props_str.encode('utf-8')).digest()

#     # Convert the hash to Base64
#     signed_props_digest = base64.b64encode(sha256_hash).decode('utf-8')

#     # Output the result
#     print("SignedProperties Digest:", signed_props_digest)
# else:
#     print("SignedProperties block not found.")
