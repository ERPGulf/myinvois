# # from lxml import etree
# # import lxml.etree as ET
# # import hashlib
# # import base64
# # import io
# # import lxml.etree as MyTree
# # # import frappe
# # from cryptography.hazmat.primitives import serialization, hashes
# # from cryptography.hazmat.primitives.asymmetric import rsa, padding
# # from cryptography.hazmat.backends import default_backend
# # from cryptography import x509
# # from cryptography.hazmat.backends import default_backend
# # # import frappe
# # from cryptography.hazmat.primitives.asymmetric import ec

# # from lxml import etree
# # from datetime import datetime


# # # def remove_elements(xml_root):
# # #     namespaces = {
# # #         'ext': "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
# # #         'cac': "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
# # #     }
# # #     # Remove UBLExtensions
# # #     ubl_extensions = xml_root.xpath('//ext:UBLExtensions', namespaces=namespaces)
# # #     for elem in ubl_extensions:
# # #         elem.getparent().remove(elem)
    
# # #     # Remove Signature
# # #     signatures = xml_root.xpath('//cac:Signature', namespaces=namespaces)
# # #     for elem in signatures:
# # #         elem.getparent().remove(elem)

# # # # Function to canonicalize XML using C14N11
# # # def canonicalize_xml(xml_tree):
# # #     output_buffer = io.BytesIO()
# # #     xml_tree.write_c14n(output_buffer, exclusive=False, with_comments=False)
# # #     return output_buffer.getvalue()

# # # # Function to hash using SHA-256 and encode to base64
# # # def hash_and_encode(canonicalized_xml):
# # #     sha256_hash = hashlib.sha256(canonicalized_xml).digest()
# # #     return base64.b64encode(sha256_hash).decode()

# # # # Load and process the XML from file
# # # def process_xml(file_path):
# # #     # Parse XML from file
# # #     with open(file_path, 'r', encoding='utf-8') as file:
# # #         xml_content = file.read()

# # #     parser = ET.XMLParser(remove_blank_text=True, encoding='UTF-8')
# # #     xml_tree = ET.ElementTree(ET.fromstring(xml_content, parser))
# # #     xml_root = xml_tree.getroot()

# # #     # Remove not required elements (UBLExtensions, Signature)
# # #     remove_elements(xml_root)
# # #     canonicalized_xml = canonicalize_xml(xml_tree)

# # #     # Print the canonicalized XML (before hashing)
# # #     print("Canonicalized XML:")
# # #     print(canonicalized_xml.decode('utf-8'))  # Decode from bytes to string for readability

# # #     # Hash and encode the canonicalized document
# # #     doc_digest = hash_and_encode(canonicalized_xml)

# # #     return doc_digest

def removeTags():
    try:
        # Load the XML file
        xml_file = MyTree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
        
        # Define the XSLT transformation to remove the specified elements
        xsl_file = MyTree.fromstring('''
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                         xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
                         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                                     
                         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
                         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
                         exclude-result-prefixes="xs"
                         version="2.0">
            <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>

            <!-- Identity transform template: copies everything -->
            <xsl:template match="node() | @*">
                <xsl:copy>
                    <xsl:apply-templates select="node() | @*"/>
                </xsl:copy>
            </xsl:template>

            <!-- Remove the UBLExtensions element -->
            <xsl:template match="//*[local-name()='UBLExtensions']"/>

            <!-- Remove the Signature element -->
            <xsl:template match="//*[local-name()='Signature']"/>

            <!-- If there are other elements you wish to remove, they can be added similarly -->
        </xsl:stylesheet>
        ''')

        # Apply the transformation
        transform = MyTree.XSLT(MyTree.ElementTree(xsl_file))
        transformed_xml = transform(xml_file)

        # Return the transformed XML
        print(transformed_xml)
        return transformed_xml

    except Exception as e:
        print("Error in remove tags: " + str(e))

                    

def canonicalize_xml (tag_removed_xml):
                try:
                    
                    canonical_xml = etree.tostring(tag_removed_xml, method="c14n").decode()
                    return canonical_xml    
                except Exception as e:
                            print(" error in canonicalise xml: "+ str(e) )    

def getInvoiceHash(canonicalized_xml):
        try:
          
            hash_object = hashlib.sha256(canonicalized_xml.encode())
            hash_hex = hash_object.hexdigest()
            print(hash_hex)
            hash_base64 = base64.b64encode(bytes.fromhex(hash_hex)).decode('utf-8')
            print(hash_base64)
            # base64_encoded = base64.b64encode(hash_hex.encode()).decode()
            return hash_hex,hash_base64
        except Exception as e:
                    print(" error in Invoice hash of xml: "+ str(e) )

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

    signature_base64 = base64.b64encode(signature).decode()  # Return the signature instead of just printing
    print("sig is",signature_base64)
    return signature_base64


def get_certificate_bytes_from_file(file_path):
    with open(file_path, 'rb') as cert_file:
        pem_certificate = cert_file.read() 
    pem_lines = pem_certificate.strip().splitlines()
    pem_body = b"".join(pem_lines[1:-1])  
    return base64.b64decode(pem_body)

def certificate_hash():
    certificate_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem'

    certificate_bytes = get_certificate_bytes_from_file(certificate_file_path)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate_bytes)
    certificate_hash = digest.finalize()
    certificate_hash_base64 = base64.b64encode(certificate_hash)
    print("Base64-encoded certificate hash:", certificate_hash_base64.decode())
    return certificate_hash_base64.decode()


def signxml_modify():
    try:
        
        encoded_certificate_hash = certificate_hash()
        # issuer_name, serial_number = extract_certificate_details()
        issuer_name ="C = MY, O = LHDNM, OU = Terms of use at http://www.posdigicert.com.my, CN = Trial LHDNM Sub CA V1"
        serial_number="197801000074"
        original_invoice_xml = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
        root = original_invoice_xml.getroot()

        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }

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

        
        element_dv = root.find(xpath_dv, namespaces)
        element_st = root.find(xpath_signTime, namespaces)
        element_in = root.find(xpath_issuerName, namespaces)
        element_sn = root.find(xpath_serialNum, namespaces)

        
        element_dv.text = encoded_certificate_hash
        element_st.text =  datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        signing_time = element_st.text
        element_in.text = issuer_name
        element_sn.text = str(serial_number)

        with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml", 'wb') as file:
            original_invoice_xml.write(file, encoding='utf-8', xml_declaration=True)

        return namespaces, signing_time

    except Exception as e:
        print("Error in signing XML: " + str(e))




def process_properties_tag():
    try:

        tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
        root = tree.getroot()

        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }

        xpath_expression = (
            ".//ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
            "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties"
        )

        properties_tag = root.find(xpath_expression, namespaces)
        if properties_tag is None:
            raise ValueError("Properties tag not found in the XML")

        properties_str = etree.tostring(properties_tag, pretty_print=False, encoding='utf-8').decode('utf-8')
        properties_str = ''.join(properties_str.split())
        sha256_hash = hashlib.sha256(properties_str.encode('utf-8')).digest()
        base64_encoded_hash = base64.b64encode(sha256_hash).decode('utf-8')
        print("base64_encoded_hash is ",base64_encoded_hash)
        return base64_encoded_hash

    except Exception as e:
        print(f"Error processing properties tag: {str(e)}")
        return None


def populate_signed_properties(digital_signature, signed_properties_hash, invoice_hash):
    try:
        # Load the XML document
        tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
        root = tree.getroot()

        # Define namespaces for XPath
        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
            'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2'
        }

        # Read the certificate content from the cert.pem file
        with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem", 'rb') as cert_file:
            certificate_data = cert_file.read()
        # print(certificate_data)

        # Remove the PEM headers and format the certificate properly for XML
        certificate_base64 = ''.join(certificate_data.decode('utf-8').splitlines()[1:-1])

        # Use relative XPath to locate elements, instead of absolute paths
        xpath_signature_value = (
            ".//ds:SignatureValue"
        )
        xpath_x509_certificate = (
            ".//ds:X509Certificate"
        )
        xpath_signed_props_digest = (
            ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
        )
        xpath_doc_signed_digest = (
            ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
        )

        # Populate each field
        signature_value_element = root.find(xpath_signature_value, namespaces)
        if signature_value_element is not None:
            signature_value_element.text = digital_signature

        x509_certificate_element = root.find(xpath_x509_certificate, namespaces)
        if x509_certificate_element is not None:
            x509_certificate_element.text = certificate_base64  # Insert the certificate base64 string here

        signed_props_digest_element = root.find(xpath_signed_props_digest, namespaces)
        if signed_props_digest_element is not None: 
            signed_props_digest_element.text = signed_properties_hash

        doc_signed_digest_element = root.find(xpath_doc_signed_digest, namespaces)
        if doc_signed_digest_element is not None:
            doc_signed_digest_element.text = invoice_hash

        # Write the updated XML back to the file
        with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml", 'wb') as file:
            tree.write(file, encoding='utf-8', xml_declaration=True)

        return "Successfully populated the signed properties."

    except Exception as e:
        print("Error in populating signed properties: " + str(e))



# tag_removed_xml=removeTags()
# canonicalized_xml=canonicalize_xml (tag_removed_xml)
# hash1,hash_base64=getInvoiceHash(canonicalized_xml)
# # hash_base64 = process_xml("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml")
# print("Document Digest (Base64):", hash_base64)
# digital_signature = signature(hash_base64)
# certificate_hash()
# signxml_modify()
# hashed_properties_base64 = process_properties_tag()
# result = populate_signed_properties(digital_signature,  hashed_properties_base64, hash_base64)
# print(result)
# # if hashed_properties_base64:
# #     print(f"Base64-encoded hashed properties tag: {hashed_properties_base64}")


# # import base64


# # xml_file_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml'
# # with open(xml_file_path, 'rb') as file:
# #     encoded_string = base64.b64encode(file.read()).decode('utf-8')

# # print(encoded_string)
# # # from lxml import etree
# # # import hashlib
# # # import base64 
# # # import lxml.etree as MyTree
# # # from datetime import datetime
# # # import xml.etree.ElementTree as ET
# # # # import frappe
# # # # import pyqrcode
# # # # frappe.init(site="prod.erpgulf.com")
# # # # frappe.connect()
# # # import binascii
# # # from cryptography import x509
# # # from cryptography.hazmat._oid import NameOID
# # # from cryptography.hazmat.backends import default_backend
# # # from cryptography.hazmat.bindings._rust import ObjectIdentifier
# # # from cryptography.hazmat.primitives import serialization, hashes
# # # from cryptography.hazmat.primitives.asymmetric import ec
# # # import json
# # # # import requests
# # # from cryptography.hazmat.primitives import serialization
# # # # import asn1
# # # def removeTags(finalzatcaxml):
# # #     try:
# # #         # Read the XML file
# # #         with open(finalzatcaxml, 'r', encoding='utf-8') as xml_file:
# # #             xml_content = xml_file.read()

# # #         # Parse the XML string
# # #         xml_tree = MyTree.fromstring(xml_content)

# # #         # XSLT for transforming the XML
# # #         xsl_content = '''<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
# # #                               xmlns:xs="http://www.w3.org/2001/XMLSchema"
# # #                               xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
# # #                               xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
# # #                               xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
# # #                               xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
# # #                               exclude-result-prefixes="xs"
# # #                               version="2.0">
# # #                               <xsl:output omit-xml-declaration="yes" encoding="utf-8" indent="no"/>
# # #                               <xsl:template match="node() | @*">
# # #                                   <xsl:copy>
# # #                                       <xsl:apply-templates select="node() | @*"/>
# # #                                   </xsl:copy>
# # #                               </xsl:template>
# # #                               <xsl:template match="//*[local-name()='Invoice']//*[local-name()='UBLExtensions']"></xsl:template>
# # #                               <xsl:template match="//*[local-name()='AdditionalDocumentReference'][cbc:ID[normalize-space(text()) = 'QR']]"></xsl:template>
# # #                               <xsl:template match="//*[local-name()='Invoice']/*[local-name()='Signature']"></xsl:template>
# # #                           </xsl:stylesheet>'''

# # #         xsl_tree = MyTree.fromstring(xsl_content)

# # #         # Perform the transformation
# # #         transform = MyTree.XSLT(xsl_tree)
# # #         transformed_xml = transform(xml_tree)

# # #         return transformed_xml  # Return as XML tree object, not as string

# # #     except Exception as e:
# # #         print("Error in remove tags: " + str(e))

# # # # Path to your XML file
# # # finalzatcaxml = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
# # # tag_removed_xml = removeTags(finalzatcaxml)


# # # def canonicalize_xml(tag_removed_xml):
# # #     try:
# # #         # Canonicalize the XML tree
# # #         canonical_xml = etree.tostring(tag_removed_xml, method="c14n").decode()
# # #         return canonical_xml    
# # #     except Exception as e:
# # #         print("Error in canonicalize xml: " + str(e))


# # # canonicalized_xml = canonicalize_xml(tag_removed_xml)

# # # print(canonicalized_xml)


# # # def getInvoiceHash(canonicalized_xml):
# # #         try:
# # #             #Code corrected by Farook K - ERPGulf
# # #             hash_object = hashlib.sha256(canonicalized_xml.encode())
# # #             hash_hex = hash_object.hexdigest()
# # #             # print(hash_hex)
# # #             hash_base64 = base64.b64encode(bytes.fromhex(hash_hex)).decode('utf-8')
# # #             print(hash_base64)
# # #             # base64_encoded = base64.b64encode(hash_hex.encode()).decode()
# # #             return hash_hex,hash_base64
# # #         except Exception as e:
# # #                     print(" error in Invoice hash of xml: "+ str(e) )

# # # hash1, encoded_hash = getInvoiceHash(canonicalized_xml)

# # # # def digital_signature(hash1):
# # # #     try:
# # # #         private_key_data_str="MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCoxfC5OkAAwKYECZZfa6oSlpCnglh1kINlg3i1ai1CqZfBG71QJYQ6Tf2X8UPXLcWBr3SbrBArD+a15ydEOnwP9b7XnT/yyJSugMULY81szRnsPp85VUBJ8zcQimq1L+Hir+s9hFxLZHL2MMQQ2/mL2+M5EaspYtX7OhspMYlmqZOxp/MnKESZyZiv90gLkPUg2BUAwh+igtpjCBKFvFpKpgSbraasne8Zsbmse4Sq8i0bj1fLhNMkU57X6Ybgn/VZHcvzSmUymSHmmkK+FaN5IGOiEdU3lQ1alesktsbNaGcfWKy5f2Iig9gxsSb0r326VFutr855Kd+xDXv2AaUjAgMBAAECggEACrLllDBjn0iXHZln/WuLT/tYdy31oppDIhvH+qQc82Vh192EzkBalgGcqlWiidD+fL6dI0MwkTJEW1KodBRLCg33h56Rz7e0aS2DkDnG63dDBe1gVZeYaDexTWyg4BSFesPRI0ixOxxGh2HHBBSVyK5rRJJgqdJ4oyDnWOCph6bs6fV1ZU/QaaVeF1pZ/dGtBrHxRybb6Y/fY2iFuKBasiUgcWgIUkClt1jkb6HoqJV0nGohNIUzIRIinZxGB8xCbHcp8X8B4tggAvNE2wVQJCUqXFUhmxplxVtyJ8L9PurtDOShYZfHJDxSVBV4IX4cv8a9pHAX0D37bkOr7KO1DQKBgQDepdreZjpG32LmhE+jJI4ARKtmUSYT7deIl/+BGcataDI2bG5nbWXpF96kSsv8FZMpHLXrk3DYj4siKbN+qNtN+GYtq/5jkRTwZdO0sX08MYPOucUO826sCuhR6VMnNjYyaNV2JyOneZnGwd226U8jDqm03XVNZ1hWlZ2JrkUAFQKBgQDCDhbBtED6thIL4CSmVwa5jw8jJE8rwMKNo7m3pdDuFBkgUmcZ40DGghRp+/XyelAfVPqoyD5lGvmeEDlxfbhBKtNCq63GDbhk83a8/FkcGyJL6zJQAMyTq3p76z5Xxz/DpsnQDZ6CvSijosxOrfn1MH0uXcFIRCTN5AD8872mVwKBgQDIlR8DMZHa+7E7/4NHdM1BTJwlx4HIfoOomVckVbZ5zt89zJ4CK7qeLlT0KjZvWniDl0wFeYU2dMth8bO1riY0rk5PYx4BUVlN4k7CAQzUR795ZD814vWXpRP7h3rUXrCg5XU5xrUGUjTJrSozeSlEahdVzBW7sBkTmCKfQRMEqQKBgQCMnu8IsVmBFF0hc+y7CUdbQfrjKVWhzA5v21wiY6tySugmTvBdhxuSfgLTBn2kl9Pl0IvPsUPdul12mCU4Q7U4rBLpNkU3xwt/RBogOvFL97GzuBz+coXM4K9iiwbjTwS6/+swtB3QeciwQ7Gvtkzyy497AP+mIZNWC8pXgz1EAwKBgE5e9US+vWwcPd0AixQeG6J7fUZP6zg5lHBz8E+7PtEaeoUrqf1dKxMdwXInBZ86R6UV0deS46LweVjVHIPevF5kEFBQYdA+DeVwT30PxthzIHVx/v1o1Fn8FeGEB6BOXNbMq5kfb5hhvUYj+CteYTnSkWbRYYKUZSUdXjOpGOjU"
# # # #         private_key_bytes = private_key_data_str.encode('utf-8')
# # # #         private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
# # # #         hash_bytes = bytes.fromhex(hash1)
# # # #         signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
# # # #         encoded_signature = base64.b64encode(signature).decode()

# # # #         return encoded_signature

# # # #     except Exception as e:
# # # #         print("Error in digital signature: " + str(e))


# # # # encoded_signature = digital_signature(hash1)


# # # import base64
# # # import lxml.etree as ET
# # # from cryptography.hazmat.primitives.serialization import pkcs12
# # # from cryptography.hazmat.backends import default_backend
# # # from cryptography.hazmat.primitives import hashes
# # # from cryptography.hazmat.primitives.asymmetric import padding

# # # # Load the PFX file and extract the private key and certificate
# # # with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
# # #     pfx_data = pfx_file.read()

# # # password = b'Ci8)RmsE'  # Your PFX password

# # # # Load the PFX file and extract the key and certificate
# # # private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
# # #     pfx_data,
# # #     password,
# # #     backend=default_backend()
# # # )

# # # # Load the XML file
# # # xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
# # # tree = ET.parse(xml_file_path)
# # # root = tree.getroot()

# # # # Extract namespaces from the root element
# # # namespaces = root.nsmap
# # # print(f"Namespaces: {namespaces}")

# # # # Adjust the XPath expression to match the UBL schema (signing target path)
# # # signature_target_path = '/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures'
# # # signature_target = root.xpath(signature_target_path, namespaces={
# # #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# # #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2'
# # # })

# # # # Ensure you find the correct target node
# # # if len(signature_target) == 0:
# # #     raise Exception(f"Signature target node not found. Please check the XPath or namespace definitions.")

# # # # Canonicalize the target XML content (remove unnecessary spaces, sort attributes, etc.)
# # # canonical_data = ET.tostring(signature_target[0], method="c14n", exclusive=True)

# # # # Hash the canonicalized data using SHA-256
# # # digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
# # # digest.update(canonical_data)
# # # invoice_hash = digest.finalize()

# # # # Sign the hashed data using the private key and RSA-SHA256
# # # signature = private_key.sign(
# # #     invoice_hash,
# # #     padding.PKCS1v15(),
# # #     hashes.SHA256()
# # # )

# # # # Base64 encode the signature
# # # encoded_signature = base64.b64encode(signature).decode()

# # # # Now, let's locate where to inject the signature in the XML according to the UBL schema
# # # sig_path = '/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue'
# # # sig_node = root.xpath(sig_path, namespaces={
# # #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# # #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
# # #     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# # #     'ds': 'http://www.w3.org/2000/09/xmldsig#'
# # # })

# # # # Check if the signature node is found
# # # if len(sig_node) == 0:
# # #     raise Exception(f"Signature node not found. Please check the XPath or namespace definitions.")

# # # # Create a new SignatureValue element and set its text content to the Base64-encoded signature
# # # sig_node[0].text = encoded_signature

# # # # Save the signed XML document
# # # signed_xml_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/signed_invoice.xml"
# # # tree.write(signed_xml_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")

# # # print(f"Signed XML saved at {signed_xml_path}")



# from lxml import etree
# from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
# from cryptography.hazmat.primitives.asymmetric import rsa
# import xmlsec

# # # # Load and parse the XML document
# # # xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/TEST.xml'
# # # parser = etree.XMLParser(remove_blank_text=True)
# # # doc = etree.parse(xml_file, parser)

# # # # Define the namespaces used in the XML
# # # namespaces = {
# # #     'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
# # #     'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
# # #     'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
# # #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# # #     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# # #     'sbc': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2',
# # #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2'
# # # }

# # # # Load the PFX certificate and private key
# # # with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
# # #     pfx_data = pfx_file.read()

# # # password = b'Ci8)RmsE'  # PFX password
# # # private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password)

# # # # Find the Invoice node using the default namespace
# # # invoice_node = doc.xpath('//urn:Invoice', namespaces={'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'})
# # # if not invoice_node:
# # #     raise ValueError("Invoice node not found. Check XML structure and namespaces.")
# # # else:
# # #     invoice_node = invoice_node[0]  # Extract the first node found

# # # # Find the signature location node using the xpath() method and passing namespaces
# # # signature_location_node = invoice_node.xpath(
# # #     ".//sig:UBLDocumentSignatures", namespaces=namespaces
# # # )
# # # if not signature_location_node:
# # #     raise ValueError("Signature location node not found. Check XML structure and namespaces.")
# # # else:
# # #     signature_location_node = signature_location_node[0]

# # # # Set up xmlsec for signature generation
# # # sign_ctx = xmlsec.SignatureContext()
# # # sign_ctx.key = xmlsec.Key.from_memory(
# # #     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
# # #     format=xmlsec.KeyFormat.DER
# # # )

# # # # Set up signature template
# # # signature_node = xmlsec.template.create(
# # #     doc,
# # #     xmlsec.Transform.EXCL_C14N,
# # #     xmlsec.Transform.RSA_SHA256,
# # #     ns='ds'
# # # )

# # # # Insert the signature template into the appropriate location in the XML document
# # # signature_location_node.append(signature_node)

# # # # Add a reference to the SignedProperties
# # # ref = xmlsec.template.add_reference(
# # #     signature_node,
# # #     xmlsec.Transform.SHA256,
# # #     uri=''
# # # )

# # # # Add transforms to the reference
# # # xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # # # Add KeyInfo and X509Data nodes to include the certificate in the signature
# # # key_info = xmlsec.template.ensure_key_info(signature_node)
# # # xmlsec.template.add_x509_data(key_info)

# # # # Sign the XML document
# # # sign_ctx.sign(signature_node)

# # # # Save the signed XML document
# # # signed_xml = etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8")
# # # with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml", "wb") as f:
# # #     f.write(signed_xml)

# # # print("XML has been signed successfully and saved to /opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")

# # # # Now verify the signature
# # # verify_ctx = xmlsec.SignatureContext()
# # # key_manager = xmlsec.KeysManager()
# # # key = xmlsec.Key.from_file("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem", xmlsec.KeyFormat.PEM, None)
# # # key_manager.add_key(key)
# # # verify_ctx.key = key

# # # # Load the signed XML file
# # # doc = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")
# # # signature_node = xmlsec.tree.find_node(doc, xmlsec.Node.SIGNATURE)

# # # # Verify the signature
# # # try:
# # #     verify_ctx.verify(signature_node)
# # #     print("Signature is valid!")
# # # except Exception as e:
# # #     print(f"Verification failed: {str(e)}")



# # from lxml import etree
# # from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
# # import xmlsec

# # # Load and parse the XML document
# # xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/TEST.xml'
# # parser = etree.XMLParser(remove_blank_text=True)
# # doc = etree.parse(xml_file, parser)

# # # Define the namespaces used in the XML
# # namespaces = {
# #     'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
# #     'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
# #     'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
# #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# #     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# #     'sbc': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2',
# #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2'
# # }

# # # Load the PFX certificate and private key
# # with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
# #     pfx_data = pfx_file.read()

# # password = b'Ci8)RmsE'  # PFX password
# # private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password)

# # # Find the Invoice node using the default namespace
# # invoice_node = doc.xpath('//urn:Invoice', namespaces={'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'})
# # if not invoice_node:
# #     raise ValueError("Invoice node not found. Check XML structure and namespaces.")
# # else:
# #     invoice_node = invoice_node[0]  # Extract the first node found

# # # Find the signature location node using the xpath() method and passing namespaces
# # signature_location_node = invoice_node.xpath(
# #     ".//sig:UBLDocumentSignatures", namespaces=namespaces
# # )
# # if not signature_location_node:
# #     raise ValueError("Signature location node not found. Check XML structure and namespaces.")
# # else:
# #     signature_location_node = signature_location_node[0]

# # # Set up xmlsec for signature generation
# # sign_ctx = xmlsec.SignatureContext()
# # sign_ctx.key = xmlsec.Key.from_memory(
# #     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
# #     format=xmlsec.KeyFormat.DER
# # )

# # # Set up signature template
# # signature_node = xmlsec.template.create(
# #     doc,
# #     xmlsec.Transform.EXCL_C14N,
# #     xmlsec.Transform.RSA_SHA256,
# #     ns='ds'
# # )

# # # Insert the signature template into the appropriate location in the XML document
# # signature_location_node.append(signature_node)

# # # Add a reference to the SignedProperties
# # ref = xmlsec.template.add_reference(
# #     signature_node,
# #     xmlsec.Transform.SHA256,
# #     uri=''
# # )

# # # Add transforms to the reference
# # xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # # Add KeyInfo and X509Data nodes to include the certificate in the signature
# # key_info = xmlsec.template.ensure_key_info(signature_node)
# # xmlsec.template.add_x509_data(key_info)

# # # Sign the XML document
# # sign_ctx.sign(signature_node)

# # # Save the signed XML document
# # signed_xml = etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8")
# # with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml", "wb") as f:
# #     f.write(signed_xml)

# # print("XML has been signed successfully and saved to /opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")

# # # Now verify the signature
# # verify_ctx = xmlsec.SignatureContext()
# # verify_ctx.key = sign_ctx.key  # Use the same private key for verification

# # # Load the signed XML file
# # doc = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")
# # signature_node = xmlsec.tree.find_node(doc, xmlsec.Node.SIGNATURE)

# # # Debugging: Print signed XML for verification
# # print("Signed XML Content:")
# # print(etree.tostring(doc, pretty_print=True).decode('utf-8'))

# # # Verify the signature
# # try:
# #     verify_ctx.verify(signature_node)
# #     print("Signature is valid!")
# # except Exception as e:
# #     print(f"Verification failed: {str(e)}")


# import xmlsec
# from lxml import etree
# from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
# from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# # Load your XML document from file
# xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
# with open(xml_file_path, 'rb') as f:
#     doc = etree.parse(f)

# # Load your PFX certificate and private key
# with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
#     pfx_data = pfx_file.read()

# password = b'Ci8)RmsE'  # PFX password
# private_key, cert, additional_certs = load_key_and_certificates(pfx_data, password)

# # Set up xmlsec for signature generation
# sign_ctx = xmlsec.SignatureContext()

# # Load your private key in DER format
# sign_ctx.key = xmlsec.Key.from_memory(
#     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
#     format=xmlsec.KeyFormat.DER
# )
# print("the key is",sign_ctx.key )
# # Ensure signature node exists or create a new one
# signature_location_node = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
# if signature_location_node is None:
#     # Create signature node at the correct location
#     signature_location_node = doc.getroot()

# # Set up the signature template
# signature_node = xmlsec.template.create(
#     doc,
#     xmlsec.Transform.EXCL_C14N,
#     xmlsec.Transform.RSA_SHA256,
#     ns="ds"
# )

# # Append the signature template to the appropriate location in the XML document
# signature_location_node.append(signature_node)

# # Add a reference to the SignedProperties
# ref = xmlsec.template.add_reference(
#     signature_node,
#     xmlsec.Transform.SHA256,
#     uri=""
# )

# # Add transforms to the reference
# xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # Add KeyInfo and X509Data nodes to include the certificate in the signature
# key_info = xmlsec.template.ensure_key_info(signature_node)
# xmlsec.template.add_x509_data(key_info)

# # Sign the XML document
# try:
#     sign_ctx.sign(signature_node)
#     print("XML signed successfully.")
# except Exception as e:
#     print(f"Error during signing: {e}")

# # Extract the signature value after signing
# signature_value_node = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
# if signature_value_node is not None:
#     signature_value = signature_value_node.text
#     print("Signature Value:", signature_value)
# else:
#     print("Signature Value node not found.")

# # Save the signed XML back to the file
# signed_xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/signed_finalzatca.xml"
# with open(signed_xml_file_path, 'wb') as f:
#     f.write(etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8"))

# print(f"Signed XML saved to {signed_xml_file_path}")





from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
import xmlsec

# # # Load and parse the XML document
# # xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/TEST.xml'
# # parser = etree.XMLParser(remove_blank_text=True)
# # doc = etree.parse(xml_file, parser)

# # # Define the namespaces used in the XML
# # namespaces = {
# #     'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
# #     'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
# #     'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
# #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# #     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# #     'sbc': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2',
# #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2'
# # }

# # # Load the PFX certificate and private key
# # with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
# #     pfx_data = pfx_file.read()

# # password = b'Ci8)RmsE'  # PFX password
# # private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password)

# # # Find the Invoice node using the default namespace
# # invoice_node = doc.xpath('//urn:Invoice', namespaces={'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'})
# # if not invoice_node:
# #     raise ValueError("Invoice node not found. Check XML structure and namespaces.")
# # else:
# #     invoice_node = invoice_node[0]  # Extract the first node found

# # # Find the signature location node using the xpath() method and passing namespaces
# # signature_location_node = invoice_node.xpath(
# #     ".//sig:UBLDocumentSignatures", namespaces=namespaces
# # )
# # if not signature_location_node:
# #     raise ValueError("Signature location node not found. Check XML structure and namespaces.")
# # else:
# #     signature_location_node = signature_location_node[0]

# # # Set up xmlsec for signature generation
# # sign_ctx = xmlsec.SignatureContext()
# # sign_ctx.key = xmlsec.Key.from_memory(
# #     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
# #     format=xmlsec.KeyFormat.DER
# # )

# # # Set up signature template
# # signature_node = xmlsec.template.create(
# #     doc,
# #     xmlsec.Transform.EXCL_C14N,
# #     xmlsec.Transform.RSA_SHA256,
# #     ns='ds'
# # )

# # # Insert the signature template into the appropriate location in the XML document
# # signature_location_node.append(signature_node)

# # # Add a reference to the SignedProperties
# # ref = xmlsec.template.add_reference(
# #     signature_node,
# #     xmlsec.Transform.SHA256,
# #     uri=''
# # )

# # # Add transforms to the reference
# # xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # # Add KeyInfo and X509Data nodes to include the certificate in the signature
# # key_info = xmlsec.template.ensure_key_info(signature_node)
# # xmlsec.template.add_x509_data(key_info)

# # # Sign the XML document
# # sign_ctx.sign(signature_node)

# # # Save the signed XML document
# # signed_xml = etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8")
# # with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml", "wb") as f:
# #     f.write(signed_xml)

# # print("XML has been signed successfully and saved to /opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")

# # # Now verify the signature
# # verify_ctx = xmlsec.SignatureContext()
# # key_manager = xmlsec.KeysManager()
# # key = xmlsec.Key.from_file("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/cert.pem", xmlsec.KeyFormat.PEM, None)
# # key_manager.add_key(key)
# # verify_ctx.key = key

# # # Load the signed XML file
# # doc = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")
# # signature_node = xmlsec.tree.find_node(doc, xmlsec.Node.SIGNATURE)

# # # Verify the signature
# # try:
# #     verify_ctx.verify(signature_node)
# #     print("Signature is valid!")
# # except Exception as e:
# #     print(f"Verification failed: {str(e)}")



# # from lxml import etree
# # from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
# # import xmlsec

# # # Load and parse the XML document
# # xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/TEST.xml'
# # parser = etree.XMLParser(remove_blank_text=True)
# # doc = etree.parse(xml_file, parser)

# # # Define the namespaces used in the XML
# # namespaces = {
# #     'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
# #     'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
# #     'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
# #     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
# #     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
# #     'sbc': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2',
# #     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2'
# # }

# # # Load the PFX certificate and private key
# # with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
# #     pfx_data = pfx_file.read()

# # password = b'Ci8)RmsE'  # PFX password
# # private_key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password)

# # # Find the Invoice node using the default namespace
# # invoice_node = doc.xpath('//urn:Invoice', namespaces={'urn': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2'})
# # if not invoice_node:
# #     raise ValueError("Invoice node not found. Check XML structure and namespaces.")
# # else:
# #     invoice_node = invoice_node[0]  # Extract the first node found

# # # Find the signature location node using the xpath() method and passing namespaces
# # signature_location_node = invoice_node.xpath(
# #     ".//sig:UBLDocumentSignatures", namespaces=namespaces
# # )
# # if not signature_location_node:
# #     raise ValueError("Signature location node not found. Check XML structure and namespaces.")
# # else:
# #     signature_location_node = signature_location_node[0]

# # # Set up xmlsec for signature generation
# # sign_ctx = xmlsec.SignatureContext()
# # sign_ctx.key = xmlsec.Key.from_memory(
# #     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
# #     format=xmlsec.KeyFormat.DER
# # )

# # # Set up signature template
# # signature_node = xmlsec.template.create(
# #     doc,
# #     xmlsec.Transform.EXCL_C14N,
# #     xmlsec.Transform.RSA_SHA256,
# #     ns='ds'
# # )

# # # Insert the signature template into the appropriate location in the XML document
# # signature_location_node.append(signature_node)

# # # Add a reference to the SignedProperties
# # ref = xmlsec.template.add_reference(
# #     signature_node,
# #     xmlsec.Transform.SHA256,
# #     uri=''
# # )

# # # Add transforms to the reference
# # xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # # Add KeyInfo and X509Data nodes to include the certificate in the signature
# # key_info = xmlsec.template.ensure_key_info(signature_node)
# # xmlsec.template.add_x509_data(key_info)

# # # Sign the XML document
# # sign_ctx.sign(signature_node)

# # # Save the signed XML document
# # signed_xml = etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8")
# # with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml", "wb") as f:
# #     f.write(signed_xml)

# # print("XML has been signed successfully and saved to /opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")

# # # Now verify the signature
# # verify_ctx = xmlsec.SignatureContext()
# # verify_ctx.key = sign_ctx.key  # Use the same private key for verification

# # # Load the signed XML file
# # doc = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/signedXml.xml")
# # signature_node = xmlsec.tree.find_node(doc, xmlsec.Node.SIGNATURE)

# # # Debugging: Print signed XML for verification
# # print("Signed XML Content:")
# # print(etree.tostring(doc, pretty_print=True).decode('utf-8'))

# # # Verify the signature
# # try:
# #     verify_ctx.verify(signature_node)
# #     print("Signature is valid!")
# # except Exception as e:
# #     print(f"Verification failed: {str(e)}")


# import xmlsec
# from lxml import etree
# from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
# from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# # Load your XML document from file
# xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml"
# with open(xml_file_path, 'rb') as f:
#     doc = etree.parse(f)

# # Load your PFX certificate and private key
# with open('/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/public/EINVCERT.PFX', 'rb') as pfx_file:
#     pfx_data = pfx_file.read()

# password = b'Ci8)RmsE'  # PFX password
# private_key, cert, additional_certs = load_key_and_certificates(pfx_data, password)

# # Set up xmlsec for signature generation
# sign_ctx = xmlsec.SignatureContext()

# # Load your private key in DER format
# sign_ctx.key = xmlsec.Key.from_memory(
#     private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
#     format=xmlsec.KeyFormat.DER
# )
# print("the key is",sign_ctx.key )
# # Ensure signature node exists or create a new one
# signature_location_node = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
# if signature_location_node is None:
#     # Create signature node at the correct location
#     signature_location_node = doc.getroot()

# # Set up the signature template
# signature_node = xmlsec.template.create(
#     doc,
#     xmlsec.Transform.EXCL_C14N,
#     xmlsec.Transform.RSA_SHA256,
#     ns="ds"
# )

# # Append the signature template to the appropriate location in the XML document
# signature_location_node.append(signature_node)

# # Add a reference to the SignedProperties
# ref = xmlsec.template.add_reference(
#     signature_node,
#     xmlsec.Transform.SHA256,
#     uri=""
# )

# # Add transforms to the reference
# xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

# # Add KeyInfo and X509Data nodes to include the certificate in the signature
# key_info = xmlsec.template.ensure_key_info(signature_node)
# xmlsec.template.add_x509_data(key_info)

# # Sign the XML document
# try:
#     sign_ctx.sign(signature_node)
#     print("XML signed successfully.")
# except Exception as e:
#     print(f"Error during signing: {e}")

# # Extract the signature value after signing
# signature_value_node = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
# if signature_value_node is not None:
#     signature_value = signature_value_node.text
#     print("Signature Value:", signature_value)
# else:
#     print("Signature Value node not found.")

# # Save the signed XML back to the file
# signed_xml_file_path = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/signed_finalzatca.xml"
# with open(signed_xml_file_path, 'wb') as f:
#     f.write(etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding="UTF-8"))

# print(f"Signed XML saved to {signed_xml_file_path}")




# from lxml import etree
# import hashlib
# import base64
# from datetime import datetime

# # Paths to be updated in the XML for signing properties
# xpath_signed_props = "/Invoice/ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties"
# xpath_cert_digest = ".//{http://www.w3.org/2000/09/xmldsig#}DigestValue"
# xpath_signing_time = ".//{http://uri.etsi.org/01903/v1.3.2#}SigningTime"
# xpath_issuer_name = ".//{http://www.w3.org/2000/09/xmldsig#}X509IssuerName"
# xpath_serial_number = ".//{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber"

# # Example certificate values to populate
# issuer_name = "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
# serial_number = "352825"
# certificate_hash = "SLFswNMf8a6muzczA+EO356bvJNDkr9LhT25+pqacdE="

# # The XML content (replace with actual content from the document)
# xml_content = '''<xades:SignedProperties Id="id-xades-signed-props" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
#   <xades:SignedSignatureProperties>
#     <xades:SigningTime>2024-07-06T15:06:45Z</xades:SigningTime>
#     <xades:SigningCertificate>
#       <xades:Cert>
#         <xades:CertDigest>
#           <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:DigestMethod>
#           <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">SLFswNMf8a6muzczA+EO356bvJNDkr9LhT25+pqacdE=</ds:DigestValue>
#         </xades:CertDigest>
#         <xades:IssuerSerial>
#           <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY</ds:X509IssuerName>
#           <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">352825</ds:X509SerialNumber>
#         </xades:IssuerSerial>
#       </xades:Cert>
#     </xades:SigningCertificate>
#   </xades:SignedSignatureProperties>
# </xades:SignedProperties>'''

# # Parse the XML
# root = etree.fromstring(xml_content)

# # Define namespaces for XPath queries
# namespaces = {
#     'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#     'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#     'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#     'ds': 'http://www.w3.org/2000/09/xmldsig#',
#     'xades': 'http://uri.etsi.org/01903/v1.3.2#'
# }

# # Fill in the necessary properties
# root.find(xpath_cert_digest).text = certificate_hash
# root.find(xpath_signing_time).text = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
# root.find(xpath_issuer_name).text = issuer_name
# root.find(xpath_serial_number).text = serial_number

# # Canonicalize the SignedProperties element using XPath with namespaces
# signed_props_element = root.xpath(xpath_signed_props, namespaces=namespaces)[0]
# canonical_xml = etree.tostring(signed_props_element, method="c14n", exclusive=True, with_comments=False)

# # Compute the SHA-256 hash of the canonicalized XML
# sha256_hash = hashlib.sha256(canonical_xml).digest()

# # Base64 encode the hash
# props_digest = base64.b64encode(sha256_hash).decode()

# # Output the canonicalized SignedProperties XML and the computed PropsDigest
# print("Canonicalized SignedProperties XML:", canonical_xml.decode())
# print("PropsDigest (Base64 Encoded):", props_digest)

# Insert the PropsDigest into your signed document as required



# import hashlib
# import base64
# import json
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.serialization import load_pem_private_key
# from cryptography.hazmat.backends import default_backend
# from cryptography.x509 import load_pem_x509_certificate

# # Function to hash certificate data (SHA-256) and return Base64-encoded result
# def get_cert_hash(cert_bytes):
#     sha256 = hashlib.sha256()
#     sha256.update(cert_bytes)
#     return base64.b64encode(sha256.digest()).decode()

# # Function to get certificate in Base64 encoding (like GetX509Certificate in C#)
# def get_x509_certificate(cert_bytes):
#     return base64.b64encode(cert_bytes).decode()

# # Function to get certificate serial number
# def get_cert_serial_number(cert):
#     return cert.serial_number

# # Function to hash a string using SHA-256
# def hash_string(text, salt=""):
#     sha256 = hashlib.sha256()
#     sha256.update((text + salt).encode('utf-8'))
#     return sha256.hexdigest()

# # Function to convert a string to Base64 encoding
# def string_to_base64(string_data):
#     return base64.b64encode(string_data.encode('utf-8')).decode()

# # Function to serialize an object to JSON string with specific settings
# def serialize_json(doc, indented=False):
#     settings = {
#         "indent": 4 if indented else None,
#         "separators": (',', ': ') if not indented else None
#     }
#     return json.dumps(doc, default=str, **settings)

# # Function to hash a string (or XML text) using SHA-256
# def sha256_hash(text):
#     return hashlib.sha256(text.encode('utf-8')).digest()

# # Function to hash byte data using SHA-256
# def sha256_hash_bytes(byte_data):
#     return hashlib.sha256(byte_data).digest()

# # Function to sign the data (digest) with the private key
# def sign_data(private_key_pem, data):
#     with open(private_key_pem, 'rb') as key_file:
#         private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    
#     signature = private_key.sign(
#         data,
#         padding.PKCS1v15(),  # Using PKCS1 padding as in C# example
#         hashes.SHA256()
#     )
#     return signature

# # Example usage of the functions:
# # Assuming you have the certificate and private key files in PEM format

# cert_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/certificate.pem'
# private_key_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem'

# # Load certificate
# with open(cert_path, 'rb') as cert_file:
#     cert_data = cert_file.read()

# # Load and parse certificate for serial number and hash
# cert = load_pem_x509_certificate(cert_data, default_backend())

# # Get certificate hash and serial number
# cert_hash = get_cert_hash(cert_data)
# cert_serial_number = get_cert_serial_number(cert)

# print("Certificate Hash (Base64):", cert_hash)
# print("Certificate Serial Number:", cert_serial_number)

# # Hash and sign a piece of data
# data_to_sign = sha256_hash("Your data to sign here")

# # Sign the data with private key
# signature = sign_data(private_key_path, data_to_sign)

# print("Signature (Base64):", base64.b64encode(signature).decode())




# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import pkcs12
# from cryptography.hazmat.primitives import serialization
# from lxml import etree
# import hashlib
# import base64
# import datetime
# from lxml import etree
# import hashlib
# import base64


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

#     with open('processed_output.xml', 'wb') as f:
#         tree.write(f, encoding='UTF-8', xml_declaration=False)

# def canonicalize_and_hash_xml(xml):
#     parser = etree.XMLParser(remove_blank_text=True)
#     tree = etree.parse(xml, parser)
#     canonicalized_xml = etree.tostring(tree, method="c14n")
#     # print(canonicalized_xml)
#     sha256_hash = hashlib.sha256(canonicalized_xml).digest()  
#     return sha256_hash


# def load_pfx_certificate(pfx_path, pfx_password):
#     with open(pfx_path, 'rb') as f:
#         pfx_data = f.read()
    
#     private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
#         pfx_data,
#         pfx_password.encode('utf-8'),
#         backend=default_backend()
#     )
#     certificate_base64 = base64.b64encode(
#             certificate.public_bytes(serialization.Encoding.DER)
#         ).decode('utf-8')
#     # print(certificate_base64)
#     return private_key,certificate,certificate_base64


# def sign_with_private_key(private_key, data):
#     signature = private_key.sign(
#         data,
#         padding.PKCS1v15(),
#         hashes.SHA256()
#     )
#     return signature


# def encode_to_base64(data):
#     return base64.b64encode(data).decode('utf-8')

# def get_cert_details(cert):
#     try:
#         x509_certificate = base64.b64encode(
#             cert.public_bytes(serialization.Encoding.DER)
#         ).decode('utf-8')

#         der_cert = cert.public_bytes(serialization.Encoding.DER)
#         cert_hash = hashlib.sha256(der_cert).digest()
#         cert_digest = base64.b64encode(cert_hash).decode('utf-8')
#         x509_issuer_name = "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
#         x509_serial_number = cert.serial_number
#         x509_subject_name = cert.subject.rfc4514_string()
#         signing_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

#         # print("Certificate (Base64):", x509_certificate)  
#         # print("Certificate subject name:", x509_subject_name)
#         # print("Certificate issuer name:", x509_issuer_name)  # This must match the XML
#         # print("Certificate serial number:", x509_serial_number)
#         # print("Certificate digest (hash):", cert_digest)
#         # print("Signing time:", signing_time)

#         return x509_issuer_name ,x509_serial_number,cert_digest,signing_time
#     except Exception as e:
#         print(f"Error loading certificate details: {str(e)}")
#         return None


# def signxml_modify(encoded_certificate_hash,issuer_name,serial_number,signing_time):
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
#                         "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                         "xades:SignedProperties/xades:SignedSignatureProperties/"
#                         "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
#         xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                         "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                         "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
#         xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                             "xades:SignedProperties/xades:SignedSignatureProperties/"
#                             "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
#         xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                             "xades:SignedProperties/xades:SignedSignatureProperties/"
#                             "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")

        
#         element_dv = root.find(xpath_dv, namespaces)
#         element_st = root.find(xpath_signTime, namespaces)
#         element_in = root.find(xpath_issuerName, namespaces)
#         element_sn = root.find(xpath_serialNum, namespaces)

        
#         element_dv.text = encoded_certificate_hash
#         element_st.text = signing_time
#         signing_time = element_st.text
#         element_in.text = issuer_name
#         element_sn.text = str(serial_number)

#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml", 'wb') as file:
#             original_invoice_xml.write(file, encoding='utf-8', xml_declaration=True)

#         return namespaces

#     except Exception as e:
#         print("Error in signing XML: " + str(e))


# def extract_signed_properties(xml_file):
#     try:
#         namespaces = {
#             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#             'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#             'ds': 'http://www.w3.org/2000/09/xmldsig#'
#         }

#         tree = etree.parse(xml_file)
#         root = tree.getroot()
#         xpath_signed_props = (
#             "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#             "xades:SignedProperties[@Id='id-xades-signed-props']"
#         )
#         signed_properties_element = root.find(xpath_signed_props, namespaces)

#         if signed_properties_element is not None:
#             signed_properties_xml = etree.tostring(signed_properties_element, method="c14n", pretty_print=False)
#             return signed_properties_xml
#         else:
#             print("SignedProperties element not found.")
#             return None
#     except Exception as e:
#         print(f"Error extracting SignedProperties: {str(e)}")
#         return None


# def hash_signed_properties(signed_properties_xml):
#     try:
#         sha256_hash = hashlib.sha256(signed_properties_xml).digest()
#         return sha256_hash
#     except Exception as e:
#         print(f"Error hashing SignedProperties: {str(e)}")
#         return None

# def encode_to_base64(data):
#     try:
        
#         return base64.b64encode(data).decode('utf-8')
#     except Exception as e:
#         print(f"Error encoding to Base64: {str(e)}")
#         return None

# def generate_props_digest(xml_file):

#     signed_properties_xml = extract_signed_properties(xml_file)

#     if signed_properties_xml is not None:
       
#         hashed_props = hash_signed_properties(signed_properties_xml)

#         if hashed_props is not None:
#             props_digest = encode_to_base64(hashed_props)
#             return props_digest
#         else:
#             print("Failed to hash SignedProperties.")
#             return None
#     else:
#         print("Failed to extract SignedProperties.")
#         return None


        
# def populate_signed_properties(digital_signature,certificate_base64, signed_properties_hash, invoice_hash):
#     try:
#         # Load the XML document
#         tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
#         root = tree.getroot()

#         # Define namespaces for XPath
#         namespaces = {
#             'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#             'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#             'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#             'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#             'ds': 'http://www.w3.org/2000/09/xmldsig#',
#             'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
#             'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2'
#         }

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
#         with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml", 'wb') as file:
#             tree.write(file, encoding='utf-8', xml_declaration=True)

#         return "Successfully populated the signed properties."

#     except Exception as e:
#         print("Error in populating signed properties: " + str(e))

# # Example usage
# xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml'
# process_xml(xml_file)
# xml = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/processed_output.xml'
# pfx_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX'
# pfx_password = 'Ci8)RmsE'
# hashed_doc = canonicalize_and_hash_xml(xml)
# private_key,certificate ,certificate_base64= load_pfx_certificate(pfx_path, pfx_password)
# signature_value= sign_with_private_key(private_key, hashed_doc)
# sig_base64 = encode_to_base64(signature_value)
# doc_digest=encode_to_base64(hashed_doc)
# print("DocDigest (Base64):", encode_to_base64(hashed_doc))  # The hash of the document (Base64)
# print("Sig (Base64):", sig_base64)  # The Base64-encoded signature
# x509_issuer_name ,x509_serial_number,cert_digest,signing_time=get_cert_details(certificate)
# signxml_modify(cert_digest,x509_issuer_name ,x509_serial_number,signing_time)
# # Example usage:
# xml_file = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml"
# props_digest = generate_props_digest(xml_file)
# if props_digest:
#     print("PropsDigest (Base64):", props_digest)

# populate_signed_properties(sig_base64,certificate_base64,props_digest,doc_digest)




from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from lxml import etree
import hashlib
import base64
import datetime

def process_xml(file_path):
    parser = etree.XMLParser(encoding='UTF-8')
    tree = etree.parse(file_path, parser)
    root = tree.getroot()

    nsmap = {
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
    }

    ubl_extensions = root.xpath('.//*[local-name()="UBLExtensions"]', namespaces=nsmap)
    for ext in ubl_extensions:
        ext.getparent().remove(ext)
    signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
    for sig in signatures:
        sig.getparent().remove(sig)

    with open('processed_output.xml', 'wb') as f:
        tree.write(f, encoding='UTF-8', xml_declaration=False)

def canonicalize_and_hash_xml(xml):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(xml, parser)
    canonicalized_xml = etree.tostring(tree, method="c14n")
    sha256_hash = hashlib.sha256(canonicalized_xml).digest()  
    return sha256_hash

def load_pfx_certificate(pfx_path, pfx_password):
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()

    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        pfx_data,
        pfx_password.encode('utf-8'),
        backend=default_backend()
    )
    certificate_base64 = base64.b64encode(
            certificate.public_bytes(serialization.Encoding.DER)
        ).decode('utf-8')
    return private_key, certificate, certificate_base64

def sign_with_private_key(private_key, data):
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def encode_to_base64(data):
    return base64.b64encode(data).decode('utf-8')

def get_cert_details(cert):
    try:
        x509_certificate = base64.b64encode(
            cert.public_bytes(serialization.Encoding.DER)
        ).decode('utf-8')

        der_cert = cert.public_bytes(serialization.Encoding.DER)
        cert_hash = hashlib.sha256(der_cert).digest()
        cert_digest = base64.b64encode(cert_hash).decode('utf-8')
        x509_issuer_name = "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY"
        x509_serial_number = cert.serial_number
        x509_subject_name = cert.subject.rfc4514_string()
        signing_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        print(signing_time)
        return x509_issuer_name, x509_serial_number, cert_digest, signing_time
    except Exception as e:
        print(f"Error loading certificate details: {str(e)}")
        return None

def signxml_modify(encoded_certificate_hash, issuer_name, serial_number, signing_time):
    try:
        original_invoice_xml = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml")
        root = original_invoice_xml.getroot()

        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }

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

        element_dv = root.find(xpath_dv, namespaces)
        element_st = root.find(xpath_signTime, namespaces)
        element_in = root.find(xpath_issuerName, namespaces)
        element_sn = root.find(xpath_serialNum, namespaces)

        element_dv.text = encoded_certificate_hash
        element_st.text = signing_time
        element_in.text = issuer_name
        element_sn.text = str(serial_number)

        with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml", 'wb') as file:
            original_invoice_xml.write(file, encoding='utf-8', xml_declaration=True)

        return namespaces

    except Exception as e:
        print("Error in signing XML: " + str(e))

def extract_and_canonicalize_signed_properties(xml_file):
    try:
        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }

        tree = etree.parse(xml_file)
        root = tree.getroot()
        xpath_signed_props = (
            "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
            "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
            "xades:SignedProperties[@Id='id-xades-signed-props']"
        )
        signed_properties_element = root.find(xpath_signed_props, namespaces)

        if signed_properties_element is not None:
            signed_properties_xml = etree.tostring(signed_properties_element, method="c14n", pretty_print=False)
            return signed_properties_xml
        else:
            print("SignedProperties element not found.")
            return None
    except Exception as e:
        print(f"Error extracting SignedProperties: {str(e)}")
        return None

def hash_signed_properties(signed_properties_xml):
    try:
        sha256_hash = hashlib.sha256(signed_properties_xml).digest()
        return sha256_hash
    except Exception as e:
        print(f"Error hashing SignedProperties: {str(e)}")
        return None

def generate_props_digest(xml_file):
    signed_properties_xml = extract_and_canonicalize_signed_properties(xml_file)

    if signed_properties_xml is not None:
        hashed_props = hash_signed_properties(signed_properties_xml)

        if hashed_props is not None:
            props_digest = encode_to_base64(hashed_props)
            return props_digest
        else:
            print("Failed to hash SignedProperties.")
            return None
    else:
        print("Failed to extract SignedProperties.")
        return None

def populate_signed_properties(digital_signature, certificate_base64, signed_properties_hash, invoice_hash):
    try:
        tree = etree.parse("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml")
        root = tree.getroot()

        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
            'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
            'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2'
        }

        xpath_signature_value = ".//ds:SignatureValue"
        xpath_x509_certificate = ".//ds:X509Certificate"
        xpath_signed_props_digest = ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
        xpath_doc_signed_digest = ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"

        signature_value_element = root.find(xpath_signature_value, namespaces)
        if signature_value_element is not None:
            signature_value_element.text = digital_signature

        x509_certificate_element = root.find(xpath_x509_certificate, namespaces)
        if x509_certificate_element is not None:
            x509_certificate_element.text = certificate_base64

        signed_props_digest_element = root.find(xpath_signed_props_digest, namespaces)
        if signed_props_digest_element is not None:
            signed_props_digest_element.text = signed_properties_hash

        doc_signed_digest_element = root.find(xpath_doc_signed_digest, namespaces)
        if doc_signed_digest_element is not None:
            doc_signed_digest_element.text = invoice_hash

        with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml.xml", 'wb') as file:
            tree.write(file, encoding='utf-8', xml_declaration=True)

        return "Successfully populated the signed properties."

    except Exception as e:
        print("Error in populating signed properties: " + str(e))

# Example usage
xml_file = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/final_signed_xml1111.xml'
process_xml(xml_file)
xml = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/processed_output.xml'
pfx_path = '/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX'
pfx_password = 'Ci8)RmsE'

hashed_doc = canonicalize_and_hash_xml(xml)
private_key, certificate, certificate_base64 = load_pfx_certificate(pfx_path, pfx_password)
signature_value = sign_with_private_key(private_key, hashed_doc)
sig_base64 = encode_to_base64(signature_value)
doc_digest = encode_to_base64(hashed_doc)
print(doc_digest)
print(sig_base64)
x509_issuer_name, x509_serial_number, cert_digest, signing_time = get_cert_details(certificate)
signxml_modify(cert_digest, x509_issuer_name, x509_serial_number, signing_time)

xml_file_after_step_6 = "/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/after_step_6.xml"
props_digest = generate_props_digest(xml_file_after_step_6)
if props_digest:
    print("PropsDigest (Base64):", props_digest)

populate_signed_properties(sig_base64, certificate_base64, props_digest, doc_digest)
