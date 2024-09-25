# from lxml import etree
# import lxml.etree as ET
# import hashlib
# import base64
# import io
# import lxml.etree as MyTree
# # import frappe
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.backends import default_backend
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# # import frappe
# from cryptography.hazmat.primitives.asymmetric import ec

# from lxml import etree
# from datetime import datetime

# def removeTags():
#     try:
#         # Load the XML file
#         xml_file = MyTree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
        
#         # Define the XSLT transformation to remove the specified elements
#         xsl_file = MyTree.fromstring('''
#         <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
#                          xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
#                          xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                                     
#                          xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
#                          xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
#                          exclude-result-prefixes="xs"
#                          version="2.0">
#             <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>

#             <!-- Identity transform template: copies everything -->
#             <xsl:template match="node() | @*">
#                 <xsl:copy>
#                     <xsl:apply-templates select="node() | @*"/>
#                 </xsl:copy>
#             </xsl:template>

#             <!-- Remove the UBLExtensions element -->
#             <xsl:template match="//*[local-name()='UBLExtensions']"/>

#             <!-- Remove the Signature element -->
#             <xsl:template match="//*[local-name()='Signature']"/>

#             <!-- If there are other elements you wish to remove, they can be added similarly -->
#         </xsl:stylesheet>
#         ''')

#         # Apply the transformation
#         transform = MyTree.XSLT(MyTree.ElementTree(xsl_file))
#         transformed_xml = transform(xml_file)

#         # Return the transformed XML
#         print(transformed_xml)
#         return transformed_xml

#     except Exception as e:
#         print("Error in remove tags: " + str(e))

                    

# def canonicalize_xml (tag_removed_xml):
#                 try:
                    
#                     canonical_xml = etree.tostring(tag_removed_xml, method="c14n").decode()
#                     return canonical_xml    
#                 except Exception as e:
#                             print(" error in canonicalise xml: "+ str(e) )    

# def getInvoiceHash(canonicalized_xml):
#         try:
          
#             hash_object = hashlib.sha256(canonicalized_xml.encode())
#             hash_hex = hash_object.hexdigest()
#             print(hash_hex)
#             hash_base64 = base64.b64encode(bytes.fromhex(hash_hex)).decode('utf-8')
#             print(hash_base64)
#             # base64_encoded = base64.b64encode(hash_hex.encode()).decode()
#             return hash_hex,hash_base64
#         except Exception as e:
#                     print(" error in Invoice hash of xml: "+ str(e) )
# # def digital_signature(hash1):
# #     try:
        
# #         private_key_data_str='''-----BEGIN PRIVATE KEY-----
# #         MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCoxfC5OkAAwKYE
# #         CZZfa6oSlpCnglh1kINlg3i1ai1CqZfBG71QJYQ6Tf2X8UPXLcWBr3SbrBArD+a1
# #         5ydEOnwP9b7XnT/yyJSugMULY81szRnsPp85VUBJ8zcQimq1L+Hir+s9hFxLZHL2
# #         MMQQ2/mL2+M5EaspYtX7OhspMYlmqZOxp/MnKESZyZiv90gLkPUg2BUAwh+igtpj
# #         CBKFvFpKpgSbraasne8Zsbmse4Sq8i0bj1fLhNMkU57X6Ybgn/VZHcvzSmUymSHm
# #         mkK+FaN5IGOiEdU3lQ1alesktsbNaGcfWKy5f2Iig9gxsSb0r326VFutr855Kd+x
# #         DXv2AaUjAgMBAAECggEACrLllDBjn0iXHZln/WuLT/tYdy31oppDIhvH+qQc82Vh
# #         192EzkBalgGcqlWiidD+fL6dI0MwkTJEW1KodBRLCg33h56Rz7e0aS2DkDnG63dD
# #         Be1gVZeYaDexTWyg4BSFesPRI0ixOxxGh2HHBBSVyK5rRJJgqdJ4oyDnWOCph6bs
# #         6fV1ZU/QaaVeF1pZ/dGtBrHxRybb6Y/fY2iFuKBasiUgcWgIUkClt1jkb6HoqJV0
# #         nGohNIUzIRIinZxGB8xCbHcp8X8B4tggAvNE2wVQJCUqXFUhmxplxVtyJ8L9Purt
# #         DOShYZfHJDxSVBV4IX4cv8a9pHAX0D37bkOr7KO1DQKBgQDepdreZjpG32LmhE+j
# #         JI4ARKtmUSYT7deIl/+BGcataDI2bG5nbWXpF96kSsv8FZMpHLXrk3DYj4siKbN+
# #         qNtN+GYtq/5jkRTwZdO0sX08MYPOucUO826sCuhR6VMnNjYyaNV2JyOneZnGwd22
# #         6U8jDqm03XVNZ1hWlZ2JrkUAFQKBgQDCDhbBtED6thIL4CSmVwa5jw8jJE8rwMKN
# #         o7m3pdDuFBkgUmcZ40DGghRp+/XyelAfVPqoyD5lGvmeEDlxfbhBKtNCq63GDbhk
# #         83a8/FkcGyJL6zJQAMyTq3p76z5Xxz/DpsnQDZ6CvSijosxOrfn1MH0uXcFIRCTN
# #         5AD8872mVwKBgQDIlR8DMZHa+7E7/4NHdM1BTJwlx4HIfoOomVckVbZ5zt89zJ4C
# #         K7qeLlT0KjZvWniDl0wFeYU2dMth8bO1riY0rk5PYx4BUVlN4k7CAQzUR795ZD81
# #         4vWXpRP7h3rUXrCg5XU5xrUGUjTJrSozeSlEahdVzBW7sBkTmCKfQRMEqQKBgQCM
# #         nu8IsVmBFF0hc+y7CUdbQfrjKVWhzA5v21wiY6tySugmTvBdhxuSfgLTBn2kl9Pl
# #         0IvPsUPdul12mCU4Q7U4rBLpNkU3xwt/RBogOvFL97GzuBz+coXM4K9iiwbjTwS6
# #         /+swtB3QeciwQ7Gvtkzyy497AP+mIZNWC8pXgz1EAwKBgE5e9US+vWwcPd0AixQe
# #         G6J7fUZP6zg5lHBz8E+7PtEaeoUrqf1dKxMdwXInBZ86R6UV0deS46LweVjVHIPe
# #         vF5kEFBQYdA+DeVwT30PxthzIHVx/v1o1Fn8FeGEB6BOXNbMq5kfb5hhvUYj+Cte
# #         YTnSkWbRYYKUZSUdXjOpGOjU
# #         -----END PRIVATE KEY-----'''        # Use the private key data directly
# #         private_key_bytes = private_key_data_str.encode('utf-8')
# #         private_key = serialization.load_pem_private_key(private_key_bytes, password='Ci8)RmsE', backend=default_backend())
# #         hash_bytes = bytes.fromhex(hash1)
# #         signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
# #         encoded_signature = base64.b64encode(signature).decode()
# #         return encoded_signature

# #     except Exception as e:
# #         print("Error in digital signature: " + str(e))

# def signature(hash_base64):
#     private_key_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem'
#     with open(private_key_file_path, 'rb') as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,  
#             backend=default_backend()
#         )

#     hash_bytes = base64.b64decode(hash_base64)
#     signature = private_key.sign(
#         hash_bytes,
#         padding.PKCS1v15(),
#         hashes.SHA256()
#     )

#     signature_base64 = base64.b64encode(signature).decode()  # Return the signature instead of just printing
#     print("sig is",signature_base64)
#     return signature_base64


# def get_certificate_bytes_from_file(file_path):
#     with open(file_path, 'rb') as cert_file:
#         pem_certificate = cert_file.read() 
#     pem_lines = pem_certificate.strip().splitlines()
#     pem_body = b"".join(pem_lines[1:-1])  
#     return base64.b64decode(pem_body)

# def certificate_hash():

#         certificate_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem'
#         with open(certificate_file_path, 'r') as cert_file:
#             certificate_data = cert_file.read()
#         certificate_data_bytes = certificate_data.encode('utf-8')
#         sha256_hash = hashlib.sha256(certificate_data_bytes).digest()
#         base64_encoded_hash = base64.b64encode(sha256_hash).decode('utf-8')
#         print(base64_encoded_hash)
#         # certificate_bytes = certificate_data.encode('utf-8')
#         # cert = x509.load_pem_x509_certificate(certificate_bytes, default_backend())
#         # issuer_name = cert.issuer.rfc4514_string()
#         # serial_number = cert.serial_number     

#         return base64_encoded_hash

# def signxml_modify():
#     try:
        
#         encoded_certificate_hash = certificate_hash()
#         # issuer_name, serial_number = extract_certificate_details()
#         issuer_name ="CN = Trial LHDNM Sub CA V1,OU = Terms of use at http://www.posdigicert.com.my,O = LHDNM,C = MY"
#         serial_number="355268"
#         original_invoice_xml = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
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
#         element_st.text =  datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
#         signing_time = element_st.text
#         element_in.text = issuer_name
#         element_sn.text = str(serial_number)

#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml", 'wb') as file:
#             original_invoice_xml.write(file, encoding='utf-8', xml_declaration=True)

#         return namespaces, signing_time

#     except Exception as e:
#         print("Error in signing XML: " + str(e))


# def generate_Signed_Properties_Hash(signing_time,issuer_name,serial_number,encoded_certificate_hash):
#             try:
#                 xml_string = '''<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">
#                                     <xades:SignedSignatureProperties>
#                                         <xades:SigningTime>{signing_time}</xades:SigningTime>
#                                         <xades:SigningCertificate>
#                                             <xades:Cert>
#                                                 <xades:CertDigest>
#                                                     <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
#                                                     <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{certificate_hash}</ds:DigestValue>
#                                                 </xades:CertDigest>
#                                                 <xades:IssuerSerial>
#                                                     <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{issuer_name}</ds:X509IssuerName>
#                                                     <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{serial_number}</ds:X509SerialNumber>
#                                                 </xades:IssuerSerial>
#                                             </xades:Cert>
#                                         </xades:SigningCertificate>
#                                     </xades:SignedSignatureProperties>
#                                 </xades:SignedProperties>'''
#                 xml_string_rendered = xml_string.format(signing_time=signing_time, certificate_hash=encoded_certificate_hash, issuer_name=issuer_name, serial_number=str(serial_number))
#                 utf8_bytes = xml_string_rendered.encode('utf-8')
#                 hash_object = hashlib.sha256(utf8_bytes)
#                 hex_sha256 = hash_object.hexdigest()
#                 # print(hex_sha256)
#                 signed_properties_base64=  base64.b64encode(hex_sha256.encode('utf-8')).decode('utf-8')
#                 print("siged hash is",signed_properties_base64)
#                 return signed_properties_base64
#             except Exception as e:
#                     print(" error in generating signed properties hash: "+ str(e) )

# # def process_properties_tag():
# #     try:

# #         tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
# #         root = tree.getroot()

# #         namespaces = {
# #             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# #             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
# #             'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# #             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
# #             'ds': 'http://www.w3.org/2000/09/xmldsig#'
# #         }

# #         xpath_expression = (
# #             ".//ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
# #             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties"
# #         )

# #         properties_tag = root.find(xpath_expression, namespaces)
# #         if properties_tag is None:
# #             raise ValueError("Properties tag not found in the XML")

# #         properties_str = etree.tostring(properties_tag, pretty_print=False, encoding='utf-8').decode('utf-8')
# #         properties_str = ''.join(properties_str.split())
# #         sha256_hash = hashlib.sha256(properties_str.encode('utf-8')).digest()
# #         base64_encoded_hash = base64.b64encode(sha256_hash).decode('utf-8')
# #         print("base64_encoded_hash is ",base64_encoded_hash)
# #         return base64_encoded_hash

# #     except Exception as e:
# #         print(f"Error processing properties tag: {str(e)}")
# #         return None


# def populate_signed_properties(digital_signature, signed_properties_hash, invoice_hash):
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

#         # Read the certificate content from the cert.pem file
#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem", 'rb') as cert_file:
#             certificate_data = cert_file.read()
#         # print(certificate_data)

#         # Remove the PEM headers and format the certificate properly for XML
#         certificate_base64 = ''.join(certificate_data.decode('utf-8').splitlines()[1:-1])

#         # Use relative XPath to locate elements, instead of absolute paths
#         xpath_signature_value = (
#             ".//ds:SignatureValue"
#         )
#         xpath_x509_certificate = (
#             ".//ds:X509Certificate"
#         )
#         xpath_signed_props_digest = (
#             ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
#         )
#         xpath_doc_signed_digest = (
#             ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
#         )

#         # Populate each field
#         signature_value_element = root.find(xpath_signature_value, namespaces)
#         if signature_value_element is not None:
#             signature_value_element.text = digital_signature

#         x509_certificate_element = root.find(xpath_x509_certificate, namespaces)
#         if x509_certificate_element is not None:
#             x509_certificate_element.text = certificate_base64  # Insert the certificate base64 string here

#         signed_props_digest_element = root.find(xpath_signed_props_digest, namespaces)
#         if signed_props_digest_element is not None: 
#             signed_props_digest_element.text = signed_properties_hash

#         doc_signed_digest_element = root.find(xpath_doc_signed_digest, namespaces)
#         if doc_signed_digest_element is not None:
#             doc_signed_digest_element.text = invoice_hash

#         # Write the updated XML back to the file
#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml", 'wb') as file:
#             tree.write(file, encoding='utf-8', xml_declaration=True)

#         return "Successfully populated the signed properties."

#     except Exception as e:
#         print("Error in populating signed properties: " + str(e))


# # import hashlib
# # import base64
# # from lxml import etree

# # # Step 1: Load and Minify XML File
# # def load_and_minify_xml(file_path):
# #     parser = etree.XMLParser(remove_blank_text=True)  # Remove blank spaces between tags
# #     with open(file_path, 'r', encoding='utf-8') as file:
# #         tree = etree.parse(file, parser)
# #     return etree.tostring(tree, encoding='utf-8', method='xml', pretty_print=False).decode('utf-8')

# # # Step 2: SHA256 Hash Function for XML content
# # def sha256_hash(text):
# #     byte_data = text.encode('utf-8')  # Convert string to bytes
# #     hash_bytes = hashlib.sha256(byte_data).digest()  # Compute SHA-256 hash
# #     return hash_bytes

# # # Step 3: Convert Hash to Base64
# # def base64_encode(data):
# #     return base64.b64encode(data).decode('utf-8')

# # # Step 4: Convert Hash to Hex
# # def hex_encode(data):
# #     return data.hex()

# # # File path to your XML file
# # xml_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"

# # # Step 5: Load and Minify the XML document
# # minified_xml_string = load_and_minify_xml(xml_path)

# # # Step 6: Compute SHA-256 Hash of the minified XML content
# # doc_hash = sha256_hash(minified_xml_string)

# # # Step 7: Convert the Hash to Base64 and Hex
# # doc_digest_base64 = base64_encode(doc_hash)
# # doc_digest_hex = hex_encode(doc_hash)

# # # Output the results
# # print("Minified XML Content Hash (Base64):", doc_digest_base64)
# # print("Minified XML Content Hash (Hex):", doc_digest_hex)


# # print("Document Digest (Base64):", doc_digest_base64)
# # signature_value = signature(doc_digest_base64)
# # encoded_certificate_hash =certificate_hash()
# # namespaces, signing_time =signxml_modify()
# # issuer_name="C = MY, O = LHDNM, OU = Terms of use at http://www.posdigicert.com.my, CN = Trial LHDNM Sub CA V1"
# # serial_number= "197801000074"
# # signed_properties_base64 =generate_Signed_Properties_Hash(signing_time,issuer_name,serial_number,encoded_certificate_hash)

# # # hashed_properties_base64 = process_properties_tag()
# # result = populate_signed_properties(signature_value,  signed_properties_base64, doc_digest_base64)
# # print(result)
# # # if hashed_properties_base


# tag_removed_xml=removeTags()
# canonicalized_xml=canonicalize_xml (tag_removed_xml)
# hash1,hash_base64=getInvoiceHash(canonicalized_xml)
# # hash_base64 = process_xml("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
# print("Document Digest (Base64):", hash_base64)
# signature_value = signature(hash_base64)
# encoded_certificate_hash =certificate_hash()
# namespaces, signing_time =signxml_modify()
# issuer_name="CN = Trial LHDNM Sub CA V1,OU = Terms of use at http://www.posdigicert.com.my,O = LHDNM,C = MY"
# serial_number= "355268"
# signed_properties_base64 =generate_Signed_Properties_Hash(signing_time,issuer_name,serial_number,encoded_certificate_hash)

# # hashed_properties_base64 = process_properties_tag()
# result = populate_signed_properties(signature_value,  signed_properties_base64, hash_base64)
# print(result)
# # if hashed_properties_base64:
# #     print(f"Base64-encoded hashed properties tag: {hashed_properties_base64}")



# import base64
# import hashlib
# import xml.etree.ElementTree as ET
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import pkcs12
# from xml.dom import minidom

# from cryptography.hazmat.primitives import serialization

# class HashUtility:
#     # Load the certificate from a PFX file (useful for signing and extracting cert details)
#     @staticmethod
#     def load_certificate(pfx_file_path, password):
#         with open(pfx_file_path, 'rb') as f:
#             pfx_data = f.read()
#         private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password.encode(), backend=default_backend())
#         return private_key, cert

#     # Get the certificate hash (digest)
#     @staticmethod
#     def get_cert_hash(cert):
#         # Specify the encoding for public_bytes (DER or PEM)
#         raw_cert_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)
#         cert_bytes = HashUtility.sha256_hash_bytes(raw_cert_bytes)
#         return base64.b64encode(cert_bytes).decode()

#     # Get the X509 certificate as a base64 encoded string
#     @staticmethod
#     def get_x509_certificate(cert):
#         # Specify the encoding for public_bytes (DER or PEM)
#         raw_cert_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)
#         return base64.b64encode(raw_cert_bytes).decode()

#     # Get the certificate serial number as int
#     @staticmethod
#     def get_cert_serial_number(cert):
#         return int(cert.serial_number)

#     # Sign the data using RSA private key and SHA256 hash
#     @staticmethod
#     def sign_data(hash_data, private_key):
#         try:
#             signed_data = private_key.sign(
#                 hash_data,
#                 padding.PKCS1v15(),
#                 hashes.SHA256()
#             )
#         except Exception as e:
#             raise Exception(f"Signing error: {str(e)}")
#         return signed_data

#     # Serialize an XML document to string (compact version)
#     @staticmethod
#     def serialize_xml(root):
#         return ET.tostring(root, encoding='utf-8').decode()

#     # Serialize an XML document to a formatted (indented) string
#     @staticmethod
#     def serialize_xml_indented(root):
#         rough_string = ET.tostring(root, 'utf-8')
#         reparsed = minidom.parseString(rough_string)
#         return reparsed.toprettyxml(indent="  ")

#     # Parse an XML string from file path into an ElementTree
#     @staticmethod
#     def parse_xml_file(xml_file_path):
#         tree = ET.parse(xml_file_path)
#         return tree

#     # Create a SHA256 hash from a string and return bytes
#     @staticmethod
#     def sha256_hash(text):
#         return hashlib.sha256(text.encode('utf-8')).digest()

#     # Create a SHA256 hash from bytes and return bytes
#     @staticmethod
#     def sha256_hash_bytes(byte_data):
#         return hashlib.sha256(byte_data).digest()


# # Define the file paths and password
# xml_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
# cert_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX"
# cert_password = "Ci8)RmsE"

# # Load the certificate and private key
# private_key, cert = HashUtility.load_certificate(cert_path, cert_password)

# # Get the certificate hash (Base64-encoded)
# cert_hash = HashUtility.get_cert_hash(cert)
# print("Certificate Hash (Base64):", cert_hash)

# # Get the certificate serial number
# serial_number = HashUtility.get_cert_serial_number(cert)
# print("Certificate Serial Number:", serial_number)

# # Load and parse the XML file
# tree = HashUtility.parse_xml_file(xml_path)
# root = tree.getroot()

# # Serialize the XML to a string
# xml_string = HashUtility.serialize_xml(root)
# print("XML Content (Compact):")
# print(xml_string)

# # Serialize the XML to a formatted string
# formatted_xml = HashUtility.serialize_xml_indented(root)
# print("XML Content (Formatted):")
# print(formatted_xml)

# # Hash the serialized XML content
# xml_hash = HashUtility.sha256_hash(xml_string)
# print("XML SHA256 Hash (Hex):", xml_hash.hex())

# # Sign the hashed XML content using the private key
# signed_data = HashUtility.sign_data(xml_hash, private_key)
# print("Signed Data (Base64):", base64.b64encode(signed_data).decode())


import hashlib
import base64
from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_public_key
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


from cryptography.hazmat.primitives.serialization import load_pem_private_key

class UBLSignatureXML:
    def __init__(self, xml_path, cert_path, cert_password, public_key_path, private_key_path):
        self.xml_path = xml_path
        self.cert_path = cert_path
        self.cert_password = cert_password
        self.public_key_path = public_key_path  
        self.private_key_path = private_key_path  
        self.cert = None
        self.private_key = None
        self.public_key = None  
        self.sign_data = SignatureData()

    def load_cert(self):
        print("Loading certificate from:", self.cert_path)
        with open(self.cert_path, 'rb') as cert_file:
            pfx_data = cert_file.read()
            _, cert, _ = pkcs12.load_key_and_certificates(
                pfx_data,
                self.cert_password.encode(),
                default_backend()
            )
            self.cert = cert
            print("Certificate loaded successfully.")

    def load_private_key(self):
        print("Loading private key from PEM file:", self.private_key_path)
        with open(self.private_key_path, 'rb') as key_file:
            self.private_key = load_pem_private_key(
                key_file.read(),
                password=None,  # If there's a password, provide it here
                backend=default_backend()
            )
        print("Private key loaded successfully.")


    def load_public_key(self):
        print("Loading public key from PEM file:", self.public_key_path)
        with open(self.public_key_path, 'rb') as pub_file:
            self.public_key = load_pem_public_key(pub_file.read(), backend=default_backend())
        print("Public key loaded successfully.")

    def get_cert_details(self):
        try:
            # Encode the certificate to DER format and then base64 encode it
            self.sign_data.x509_certificate = base64.b64encode(
                self.cert.public_bytes(serialization.Encoding.DER)
            ).decode('utf-8')

            # Calculate and store the certificate's digest (SHA-256)
            der_cert = self.cert.public_bytes(serialization.Encoding.DER)
            cert_hash = hashlib.sha256(der_cert).digest()
            self.sign_data.cert_digest = base64.b64encode(cert_hash).decode('utf-8')

            # Use rfc4514_string() to ensure proper formatting for issuer and subject names
            self.sign_data.x509_issuer_name = "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
            self.sign_data.x509_serial_number = self.cert.serial_number
            self.sign_data.x509_subject_name = self.cert.subject.rfc4514_string()
            self.sign_data.signing_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # Debugging: Print certificate and other details
            print("Certificate (Base64):", self.sign_data.x509_certificate)  
            print("Certificate subject name:", self.sign_data.x509_subject_name)
            print("Certificate issuer name:", self.sign_data.x509_issuer_name)  # This must match the XML
            print("Certificate serial number:", self.sign_data.x509_serial_number)
            print("Certificate digest (hash):", self.sign_data.cert_digest)
            print("Signing time:", self.sign_data.signing_time)

        except Exception as e:
            print(f"Error loading certificate details: {str(e)}")

    
    def sha256_hash(self, data):
        print("Generating SHA-256 hash for data...")
        return hashlib.sha256(data).digest()

    def canonicalize_xml(self, xml_tree):
        return etree.tostring(xml_tree, method='c14n', exclusive=True)

    def get_signed_properties_hash(self, doc):
        # XPath for the SignedProperties element (make sure it exists in the document)
        signed_props_element = doc.find(".//xades:SignedProperties", namespaces={
            'xades': 'http://uri.etsi.org/01903/v1.3.2#'
        })

        if signed_props_element is not None:
            canonical_signed_props = self.canonicalize_xml(signed_props_element)
            signed_properties_hash = self.sha256_hash(canonical_signed_props)
            return base64.b64encode(signed_properties_hash).decode('utf-8')
        else:
            print("SignedProperties element not found.")
            return None

    def sign_document(self):
        try:
            # Load certificate and private key
            self.load_cert()
            self.load_private_key()  # Load the private key from PEM file
            
            # Load and canonicalize XML
            parser = etree.XMLParser(remove_blank_text=True)
            doc = etree.parse(self.xml_path, parser)
            print("XML loaded successfully.")
            canonical_xml = self.canonicalize_xml(doc)

            # Compute the document hash (digest)
            doc_hash = self.sha256_hash(canonical_xml)
            self.sign_data.doc_digest = base64.b64encode(doc_hash).decode('utf-8')
            print("Document digest (Base64):", self.sign_data.doc_digest)

            # Sign the document using the private key
            signature = self.private_key.sign(
                doc_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.sign_data.signature_value = base64.b64encode(signature).decode('utf-8')
            print("Document signed successfully. Signature value:", self.sign_data.signature_value)

            # Get certificate details (issuer, subject, serial, etc.)
            self.get_cert_details()

            # Get SignedProperties hash
            self.sign_data.props_digest = self.get_signed_properties_hash(doc)

            # Modify the XML by inserting signature and other required details
            self.modify_and_insert_signature(doc, self.sign_data.props_digest, self.sign_data.doc_digest)

            # Save the final signed XML document
            with open("/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb") as signed_file:
                signed_file.write(etree.tostring(doc, pretty_print=True))
            print("Final signed XML saved successfully.")

            # Verify the signature using the public key
            self.verify_signature(doc_hash, signature)

        except Exception as e:
            print(f"Error during document signing: {str(e)}")

    
    
    def verify_signature(self, doc_hash, signature):
        try:
            self.load_public_key()  # Ensure public key is loaded for verification
            print("Verifying signature...")
            self.public_key.verify(
                signature,
                doc_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature verified successfully.")
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")

    def modify_and_insert_signature(self, doc, signed_properties_hash, doc_hash):
        try:
            print("Modifying XML with signature details...")

            # Define namespaces
            namespaces = {
                'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
                'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
                'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
                'xades': 'http://uri.etsi.org/01903/v1.3.2#',
                'ds': 'http://www.w3.org/2000/09/xmldsig#'
            }

            # XPath expressions for finding nodes in the XML
            xpath_signature_value = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                                    "sac:SignatureInformation/ds:Signature/ds:SignatureValue")
            xpath_x509_certificate = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                                    "sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")

            # XPath for SignedProperties and document digest elements
            xpath_signed_props_digest = (
                ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
            )
            xpath_doc_signed_digest = (
                ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
            )

            # Find or create necessary nodes
            signature_value_element = doc.find(xpath_signature_value, namespaces)
            x509_certificate_element = doc.find(xpath_x509_certificate, namespaces)
            signed_props_digest_element = doc.find(xpath_signed_props_digest, namespaces)
            doc_signed_digest_element = doc.find(xpath_doc_signed_digest, namespaces)

            if signature_value_element is None or x509_certificate_element is None:
                # Create the necessary elements if they don't exist
                signature_info_path = "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation"
                signature_info_element = doc.find(signature_info_path, namespaces)
                if signature_info_element is None:
                    # If signature structure is missing, create it
                    ubl_extensions = doc.find("ext:UBLExtensions", namespaces)
                    if ubl_extensions is None:
                        ubl_extensions = etree.SubElement(doc.getroot(), "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtensions")

                    ubl_extension = etree.SubElement(ubl_extensions, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension")
                    extension_content = etree.SubElement(ubl_extension, "{urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2}ExtensionContent")
                    signature_info_element = etree.SubElement(extension_content, "{urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2}SignatureInformation")

                ds_signature = etree.SubElement(signature_info_element, "{http://www.w3.org/2000/09/xmldsig#}Signature")
                signature_value_element = etree.SubElement(ds_signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
                ds_key_info = etree.SubElement(ds_signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
                ds_x509_data = etree.SubElement(ds_key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
                x509_certificate_element = etree.SubElement(ds_x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")

            # Set the values for signature, certificate, signed properties digest, and document digest
            signature_value_element.text = "PCqANY/7z1hix0NEUXhWV6FQZ3PwUgIBrP9tGA3gZwue47Hle6/QX3EiNed8P/BHG2rmQHJ2ghkEFg8/m0r0uVaQ+HAeIT+70GF1SLOntu5jSqyvx8P5tJ+hEEJNI9bbMkRtn4nSr2XV4BuZ6yS67D20ZgobuNwe6Se79qH7p0TDn66yXWQCaXzBzucoRnHsXAbQh49m1I1ZVrKDkALtA8Wv7FFdT8+Sh7aSOdzapUTgw2OLwwZ5y++c74KgeNuVuy4GjIBI9g3RLYWPQfQJvXLK0MDEaqu45aaPVDack85teSobiV7fUtX/qgFp400PMBhNfclRaWovaJyIz5fffw=="
            print(self.sign_data.signature_value)

            self.sign_data.x509_certificate = base64.b64encode(
                self.cert.public_bytes(serialization.Encoding.DER)
            ).decode('utf-8')
            x509_certificate_element.text = self.sign_data.x509_certificate

            print(self.sign_data.x509_certificate)
            if signed_props_digest_element is not None:
                signed_props_digest_element.text = signed_properties_hash  # Insert the SignedProperties hash

            if doc_signed_digest_element is not None:
                doc_signed_digest_element.text = "f3ag3OPmzlPXa1HVhtPSfnFW2GmYZOd1U95vIrXOPEE="  # Insert the document hash

            # Modify other XML elements like SigningTime, IssuerName, SerialNumber
            xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                        "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                        "xades:SignedProperties/xades:SignedSignatureProperties/"
                        "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
            xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                            "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                            "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
            xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                                "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                                "xades:SignedProperties/xades:SignedSignatureProperties/"
                                "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
            xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                            "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                            "xades:SignedProperties/xades:SignedSignatureProperties/"
                            "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")

            # Set these values in the respective elements
            element_dv = doc.find(xpath_dv, namespaces)
            element_st = doc.find(xpath_signTime, namespaces)
            element_in = doc.find(xpath_issuerName, namespaces)
            element_sn = doc.find(xpath_serialNum, namespaces)

            if element_dv is not None:
                element_dv.text = self.sign_data.cert_digest
            if element_st is not None:
                element_st.text = self.sign_data.signing_time
            if element_in is not None:
                element_in.text = "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
            if element_sn is not None:
                element_sn.text = str(self.sign_data.x509_serial_number)

            print("Signature, certificate, and digest values inserted successfully.")

        except Exception as e:
            print("Error during XML modification: " + str(e))


if __name__ == "__main__":
    xml_signer = UBLSignatureXML(
        xml_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml",
        cert_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX",
        cert_password="Ci8)RmsE",
        public_key_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/publickey.pem",
        private_key_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem"  # Path to the private key
    )
    xml_signer.load_cert()
    xml_signer.sign_document()




from lxml import etree

def process_xml(file_path):
    # Parse the XML document ensuring it's in UTF-8
    parser = etree.XMLParser(encoding='UTF-8')
    tree = etree.parse(file_path, parser)
    root = tree.getroot()

    # Define namespaces if needed (adjust this if specific namespaces are used in your XML)
    nsmap = {
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
    }

    # Remove UBLExtensions
    ubl_extensions = root.xpath('.//*[local-name()="UBLExtensions"]', namespaces=nsmap)
    for ext in ubl_extensions:
        ext.getparent().remove(ext)

    # Remove Signature
    signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
    for sig in signatures:
        sig.getparent().remove(sig)

    # Write back the XML without the XML declaration
    with open('processed_output.xml', 'wb') as f:
        tree.write(f, encoding='UTF-8', xml_declaration=False)

# Specify the path to your XML file
# xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml'
# process_xml(xml_file)



from lxml import etree
import hashlib
import base64


def process_xml(file_path):
    # Parse the XML document ensuring it's in UTF-8
    parser = etree.XMLParser(encoding='UTF-8')
    tree = etree.parse(file_path, parser)
    root = tree.getroot()

    # Define namespaces if needed (adjust this if specific namespaces are used in your XML)
    nsmap = {
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
    }

    # Remove UBLExtensions
    ubl_extensions = root.xpath('.//*[local-name()="UBLExtensions"]', namespaces=nsmap)
    for ext in ubl_extensions:
        ext.getparent().remove(ext)

    # Remove Signature
    signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
    for sig in signatures:
        sig.getparent().remove(sig)

    # Write back the XML without the XML declaration
    with open('processed_output.xml', 'wb') as f:
        tree.write(f, encoding='UTF-8', xml_declaration=False)

# Specify the path to your XML file


def canonicalize_and_hash_xml(xml_file):
    # Parse the XML file
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(xml_file, parser)
    
    # Apply XML C14N 1.1 canonicalization
    canonicalized_xml = etree.tostring(tree, method="c14n")
    print(canonicalized_xml)
    # Hash the canonicalized XML using SHA-256
    sha256_hash = hashlib.sha256(canonicalized_xml).hexdigest()
    print(sha256_hash )
    # Encode the hash from HEX to Base64
    base64_hash = base64.b64encode(bytes.fromhex(sha256_hash)).decode('utf-8')
    
    return base64_hash


# # Example usage
# xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/processed_output.xml'
# doc_digest = canonicalize_and_hash_xml(xml_file)
# print("DocDigest:", doc_digest)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from lxml import etree
import hashlib
import base64

# Step 1: Process XML to remove UBLExtensions and Signature elements
def process_xml(file_path):
    # Parse the XML document ensuring it's in UTF-8
    parser = etree.XMLParser(encoding='UTF-8')
    tree = etree.parse(file_path, parser)
    root = tree.getroot()

    # Define namespaces if needed (adjust this if specific namespaces are used in your XML)
    nsmap = {
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
    }

    # Remove UBLExtensions
    ubl_extensions = root.xpath('.//*[local-name()="UBLExtensions"]', namespaces=nsmap)
    for ext in ubl_extensions:
        ext.getparent().remove(ext)

    # Remove Signature
    signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
    for sig in signatures:
        sig.getparent().remove(sig)

    # Write back the XML without the XML declaration
    with open('processed_output.xml', 'wb') as f:
        tree.write(f, encoding='UTF-8', xml_declaration=False)

# Step 2: Canonicalize XML and hash it with SHA-256
def canonicalize_and_hash_xml(xml):
    # Parse the XML file
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(xml, parser)
    
    # Apply XML C14N 1.1 canonicalization
    canonicalized_xml = etree.tostring(tree, method="c14n")
    print(canonicalized_xml)
    # Hash the canonicalized XML using SHA-256
    sha256_hash = hashlib.sha256(canonicalized_xml).digest()  # Return raw binary digest

    return sha256_hash

# Step 3: Load PFX file and extract private key
def load_pfx_certificate(pfx_path, pfx_password):
    # Load the PFX file and extract the private key and certificate
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        pfx_data,
        pfx_password.encode('utf-8'),
        backend=default_backend()
    )
    return private_key

# Step 4: Sign the document hash with the private key
def sign_with_private_key(private_key, data):
    # Sign the hashed data using the RSA private key and padding scheme for RSA-SHA256
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Step 5: Encode any data to Base64
def encode_to_base64(data):
    # Encode the data to Base64
    return base64.b64encode(data).decode('utf-8')

# Example usage
xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml'
process_xml(xml_file)

# Use the processed XML
xml = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/processed_output.xml'
pfx_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX'
pfx_password = 'Ci8)RmsE'

# Step 1: Canonicalize and hash the XML document
hashed_doc = canonicalize_and_hash_xml(xml)

# Step 2: Load the private key from the PFX file
private_key = load_pfx_certificate(pfx_path, pfx_password)

# Step 3: Sign the hashed document using the private key
signature = sign_with_private_key(private_key, hashed_doc)

# Step 4: Encode the signature to Base64
sig_base64 = encode_to_base64(signature)

# Output
print("DocDigest (Base64):", encode_to_base64(hashed_doc))  # The hash of the document (Base64)
print("Sig (Base64):", sig_base64)  # The Base64-encoded signature

