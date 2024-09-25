# import hashlib
# import base64
# from lxml import etree
# import xmlsec
# from cryptography.hazmat.primitives.serialization import pkcs12
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# import datetime
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
#     def __init__(self, xml_path, cert_path, cert_password):
#         self.xml_path = xml_path
#         self.cert_path = cert_path
#         self.cert_password = cert_password
#         self.cert = None
#         self.private_key = None
#         self.sign_data = SignatureData()

#     def load_cert(self):
#         print("Loading certificate from:", self.cert_path)

#         with open(self.cert_path, 'rb') as cert_file:
#             pfx_data = cert_file.read()
#             private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
#                 pfx_data,
#                 self.cert_password.encode(),
#                 default_backend()
#             )
#             self.cert = cert
#             self.private_key = private_key


#     def get_cert_details(self):

#         self.sign_data.x509_certificate = base64.b64encode(
#             self.cert.public_bytes(serialization.Encoding.DER)
#         ).decode('utf-8')
#         der_cert = self.cert.public_bytes(serialization.Encoding.DER)
#         cert_hash = hashlib.sha256(der_cert).digest()
#         self.sign_data.cert_digest = base64.b64encode(cert_hash).decode('utf-8')

#         self.sign_data.x509_issuer_name = self.cert.issuer.rfc4514_string()
#         self.sign_data.x509_serial_number = self.cert.serial_number
#         self.sign_data.x509_subject_name = self.cert.subject.rfc4514_string()
#         self.sign_data.signing_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

#         print("Certificate subject name:", self.sign_data.x509_subject_name)
#         print("Certificate issuer name:", self.sign_data.x509_issuer_name)
#         print("Certificate serial number:", self.sign_data.x509_serial_number)
#         print("Certificate digest (hash):", self.sign_data.cert_digest)
#         print("Signing time:", self.sign_data.signing_time)


#     def sha256_hash(self, data):
#         print("Generating SHA-256 hash for data...")
#         return hashlib.sha256(data).digest()

#     def canonicalize_xml(self, xml_tree):
#         return etree.tostring(xml_tree, method='c14n', exclusive=True)


#     # def sign_document(self):
#     #     try:

#     #         parser = etree.XMLParser(remove_blank_text=True)
#     #         doc = etree.parse(self.xml_path, parser)
#     #         print("XML loaded successfully.")
#     #         canonical_xml = self.canonicalize_xml(doc)
#     #         doc_hash = self.sha256_hash(canonical_xml)
#     #         sha256_hash = hashlib.sha256(canonical_xml).hexdigest()
#     #         print(sha256_hash)
#     #         self.sign_data.doc_digest = base64.b64encode(doc_hash).decode()
#     #         print("doc hash",self.sign_data.doc_digest)
#     #         # Sign the document using RSA private key from the certificate
#     #         signature = self.private_key.sign(
#     #             doc_hash,
#     #             padding.PKCS1v15(),
#     #             hashes.SHA256()
#     #         )
#     #         self.sign_data.signature_value = base64.b64encode(signature).decode('utf-8')
#     #         print("Document signed successfully. Signature value:", self.sign_data.signature_value)

#     #         self.get_cert_details()


#     #         signed_props_element = doc.find(".//xades:SignedProperties", namespaces={
#     #             'xades': 'http://uri.etsi.org/01903/v1.3.2#'
#     #         })
#     #         if signed_props_element is not None:
#     #             canonical_signed_props = self.canonicalize_xml(signed_props_element)
#     #             signed_props_hash = self.sha256_hash(canonical_signed_props)
#     #             self.sign_data.props_digest = base64.b64encode(signed_props_hash).decode('utf-8')

#     #             # Print the signed properties hash
#     #             print("Signed Properties Hash (Base64):", self.sign_data.props_digest)
#     #         else:
#     #             print("SignedProperties element not found in the XML.")

#     #         # Modify the XML by inserting signature and other required details
#     #         self.modify_and_insert_signature(doc, self.sign_data.props_digest, self.sign_data.doc_digest)

#     #         # Save the final signed XML document
#     #         with open("/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb") as signed_file:
#     #             signed_file.write(etree.tostring(doc, pretty_print=True))
#     #         print("Final signed XML saved successfully.")

#     #     except Exception as e:
#     #         print(f"Error during document signing: {str(e)}")
#     def sign_document(self):
#         try:
#             # Load and canonicalize XML
#             parser = etree.XMLParser(remove_blank_text=True)
#             doc = etree.parse(self.xml_path, parser)
#             print("XML loaded successfully.")
#             canonical_xml = self.canonicalize_xml(doc)

#             # Compute the document hash (digest)
#             doc_hash = self.sha256_hash(canonical_xml)
#             self.sign_data['doc_digest'] = base64.b64encode(doc_hash).decode('utf-8')
#             print("Document digest (Base64):", self.sign_data['doc_digest'])

#             # Sign the document using RSA private key
#             signature = self.private_key.sign(
#                 doc_hash,
#                 padding.PKCS1v15(),
#                 hashes.SHA256()
#             )
#             self.sign_data['signature_value'] = base64.b64encode(signature).decode('utf-8')
#             print("Document signed successfully. Signature value:", self.sign_data['signature_value'])

#             # Get SignedProperties (if exists) and hash it
#             signed_props_element = doc.find(".//xades:SignedProperties", namespaces={
#                 'xades': 'http://uri.etsi.org/01903/v1.3.2#'
#             })
#             if signed_props_element is not None:
#                 canonical_signed_props = self.canonicalize_xml(signed_props_element)
#                 signed_props_hash = self.sha256_hash(canonical_signed_props)
#                 self.sign_data['props_digest'] = base64.b64encode(signed_props_hash).decode('utf-8')
#                 print("Signed Properties Hash (Base64):", self.sign_data['props_digest'])
#             else:
#                 print("SignedProperties element not found in the XML.")

#             # Modify the XML by inserting signature and other required details
#             self.modify_and_insert_signature(doc, self.sign_data['props_digest'], self.sign_data['doc_digest'])

#             # Save the final signed XML document
#             with open("/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb") as signed_file:
#                 signed_file.write(etree.tostring(doc, pretty_print=True))
#             print("Final signed XML saved successfully.")

#             # Verify the signature using the public key
#             self.verify_signature(doc_hash, signature)

#         except Exception as e:
#             print(f"Error during document signing: {str(e)}")


#     def modify_and_insert_signature(self, doc, signed_properties_hash, doc_hash):
#         try:
#             print("Modifying XML with signature details...")

#             # Define namespaces
#             namespaces = {
#                 'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
#                 'sig': 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
#                 'sac': 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
#                 'xades': 'http://uri.etsi.org/01903/v1.3.2#',
#                 'ds': 'http://www.w3.org/2000/09/xmldsig#'
#             }

#             # XPath expressions for finding nodes in the XML
#             xpath_signature_value = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                                     "sac:SignatureInformation/ds:Signature/ds:SignatureValue")
#             xpath_x509_certificate = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                                     "sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")

#             # XPath for SignedProperties and document digest elements
#             xpath_signed_props_digest = (
#                 ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
#             )
#             xpath_doc_signed_digest = (
#                 ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
#             )

#             # Find or create necessary nodes
#             signature_value_element = doc.find(xpath_signature_value, namespaces)
#             x509_certificate_element = doc.find(xpath_x509_certificate, namespaces)
#             signed_props_digest_element = doc.find(xpath_signed_props_digest, namespaces)
#             doc_signed_digest_element = doc.find(xpath_doc_signed_digest, namespaces)

#             if signature_value_element is None or x509_certificate_element is None:
#                 # Create the necessary elements if they don't exist
#                 signature_info_path = "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation"
#                 signature_info_element = doc.find(signature_info_path, namespaces)
#                 if signature_info_element is None:
#                     # If signature structure is missing, create it
#                     ubl_extensions = doc.find("ext:UBLExtensions", namespaces)
#                     if ubl_extensions is None:
#                         ubl_extensions = etree.SubElement(doc.getroot(), "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtensions")

#                     ubl_extension = etree.SubElement(ubl_extensions, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension")
#                     extension_content = etree.SubElement(ubl_extension, "{urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2}ExtensionContent")
#                     signature_info_element = etree.SubElement(extension_content, "{urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2}SignatureInformation")

#                 ds_signature = etree.SubElement(signature_info_element, "{http://www.w3.org/2000/09/xmldsig#}Signature")
#                 signature_value_element = etree.SubElement(ds_signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
#                 ds_key_info = etree.SubElement(ds_signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
#                 ds_x509_data = etree.SubElement(ds_key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
#                 x509_certificate_element = etree.SubElement(ds_x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")

#             # Set the values for signature, certificate, signed properties digest, and document digest
#             signature_value_element.text = self.sign_data.signature_value
#             x509_certificate_element.text = self.sign_data.x509_certificate

#             if signed_props_digest_element is not None:
#                 signed_props_digest_element.text = signed_properties_hash  # Insert the SignedProperties hash

#             if doc_signed_digest_element is not None:
#                 doc_signed_digest_element.text = doc_hash  # Insert the document hash

#             # Modify other XML elements like SigningTime, IssuerName, SerialNumber
#             xpath_dv = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                         "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                         "xades:SignedProperties/xades:SignedSignatureProperties/"
#                         "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue")
#             xpath_signTime = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                             "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime")
#             xpath_issuerName = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                                 "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                                 "xades:SignedProperties/xades:SignedSignatureProperties/"
#                                 "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName")
#             xpath_serialNum = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
#                             "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
#                             "xades:SignedProperties/xades:SignedSignatureProperties/"
#                             "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber")

#             # Set these values in the respective elements
#             element_dv = doc.find(xpath_dv, namespaces)
#             element_st = doc.find(xpath_signTime, namespaces)
#             element_in = doc.find(xpath_issuerName, namespaces)
#             element_sn = doc.find(xpath_serialNum, namespaces)
#             print(self.sign_data.cert_digest)
#             if element_dv is not None:
#                 element_dv.text = self.sign_data.cert_digest
#             if element_st is not None:
#                 element_st.text = self.sign_data.signing_time
#             if element_in is not None:
#                 element_in.text = self.sign_data.x509_issuer_name
#                 # element_in.text = "C = MY, O = LHDNM, OU = Terms of use at http://www.posdigicert.com.my, CN = Trial LHDNM Sub CA V1"
#             if element_sn is not None:
#                 element_sn.text = str(self.sign_data.x509_serial_number)
#                 # element_sn.text = "197801000074"

#             print("Signature, certificate, and digest values inserted successfully.")

#         except Exception as e:
#             print("Error during XML modification: " + str(e))


# if __name__ == "__main__":
#     xml_signer = UBLSignatureXML(xml_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml", cert_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX", cert_password="Ci8)RmsE")
#     xml_signer.load_cert()
#     xml_signer.sign_document()


import base64
import hashlib
import datetime
from lxml import etree
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    load_pem_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


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
    def __init__(
        self, xml_path, cert_path, cert_password, public_key_path, private_key_path
    ):
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
        with open(self.cert_path, "rb") as cert_file:
            pfx_data = cert_file.read()
            _, cert, _ = pkcs12.load_key_and_certificates(
                pfx_data, self.cert_password.encode(), default_backend()
            )
            self.cert = cert
            print("Certificate loaded successfully.")

    def load_private_key(self):
        print("Loading private key from PEM file:", self.private_key_path)
        with open(self.private_key_path, "rb") as key_file:
            self.private_key = load_pem_private_key(
                key_file.read(),
                password=None,  # If there's a password, provide it here
                backend=default_backend(),
            )
        print("Private key loaded successfully.")

    def load_public_key(self):
        print("Loading public key from PEM file:", self.public_key_path)
        with open(self.public_key_path, "rb") as pub_file:
            self.public_key = load_pem_public_key(
                pub_file.read(), backend=default_backend()
            )
        print("Public key loaded successfully.")

    def get_cert_details(self):
        try:
            # Encode the certificate to DER format and then base64 encode it
            self.sign_data.x509_certificate = base64.b64encode(
                self.cert.public_bytes(serialization.Encoding.DER)
            ).decode("utf-8")

            # Calculate and store the certificate's digest (SHA-256)
            der_cert = self.cert.public_bytes(serialization.Encoding.DER)
            cert_hash = hashlib.sha256(der_cert).digest()
            self.sign_data.cert_digest = base64.b64encode(cert_hash).decode("utf-8")

            # Use rfc4514_string() to ensure proper formatting for issuer and subject names
            self.sign_data.x509_issuer_name = self.cert.issuer.rfc4514_string()
            self.sign_data.x509_serial_number = self.cert.serial_number
            self.sign_data.x509_subject_name = self.cert.subject.rfc4514_string()
            self.sign_data.signing_time = datetime.datetime.utcnow().strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

            # Debugging: Print certificate and other details
            print("Certificate (Base64):", self.sign_data.x509_certificate)
            print("Certificate subject name:", self.sign_data.x509_subject_name)
            print(
                "Certificate issuer name:", self.sign_data.x509_issuer_name
            )  # Extracted dynamically
            print("Certificate serial number:", self.sign_data.x509_serial_number)
            print("Certificate digest (hash):", self.sign_data.cert_digest)
            print("Signing time:", self.sign_data.signing_time)

        except Exception as e:
            print(f"Error loading certificate details: {str(e)}")

    def sha256_hash(self, data):
        print("Generating SHA-256 hash for data...")
        return hashlib.sha256(data).digest()

    def canonicalize_xml(self, xml_tree):
        return etree.tostring(xml_tree, method="c14n", exclusive=True)

    def get_signed_properties_hash(self, doc):
        signed_props_element = doc.find(
            ".//xades:SignedProperties",
            namespaces={"xades": "http://uri.etsi.org/01903/v1.3.2#"},
        )

        if signed_props_element is not None:
            canonical_signed_props = self.canonicalize_xml(signed_props_element)
            signed_properties_hash = self.sha256_hash(canonical_signed_props)
            return base64.b64encode(signed_properties_hash).decode("utf-8")
        else:
            print("SignedProperties element not found.")
            return None

    def process_xml(self, file_path):
        parser = etree.XMLParser(encoding="UTF-8")
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        nsmap = {
            "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
            "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
            "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        }

        ubl_extensions = root.xpath(
            './/*[local-name()="UBLExtensions"]', namespaces=nsmap
        )
        for ext in ubl_extensions:
            ext.getparent().remove(ext)

        signatures = root.xpath('.//*[local-name()="Signature"]', namespaces=nsmap)
        for sig in signatures:
            sig.getparent().remove(sig)

        with open("processed_output.xml", "wb") as f:
            tree.write(f, encoding="UTF-8", xml_declaration=False)

        print("XML processed successfully.")

    def canonicalize_and_hash_xml(self, xml):
        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.parse(xml, parser)

        canonicalized_xml = etree.tostring(tree, method="c14n")
        print("Canonicalized XML:", canonicalized_xml)

        sha256_hash = hashlib.sha256(canonicalized_xml).digest()

        return sha256_hash

    def sign_document(self):
        try:
            self.load_cert()
            self.load_private_key()

            self.process_xml(self.xml_path)
            canonical_xml_hash = self.canonicalize_and_hash_xml("processed_output.xml")

            self.sign_data.doc_digest = base64.b64encode(canonical_xml_hash).decode(
                "utf-8"
            )
            print("Document digest (Base64):", self.sign_data.doc_digest)

            signature = self.private_key.sign(
                canonical_xml_hash, padding.PKCS1v15(), hashes.SHA256()
            )
            self.sign_data.signature_value = base64.b64encode(signature).decode("utf-8")
            print(
                "Document signed successfully. Signature value:",
                self.sign_data.signature_value,
            )

            self.get_cert_details()

            self.sign_data.props_digest = self.get_signed_properties_hash(
                etree.parse("processed_output.xml")
            )

            self.modify_and_insert_signature(
                etree.parse("processed_output.xml"),
                self.sign_data.props_digest,
                self.sign_data.doc_digest,
            )

            with open(
                "/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb"
            ) as signed_file:
                signed_file.write(
                    etree.tostring(
                        etree.parse("processed_output.xml"), pretty_print=True
                    )
                )
            print("Final signed XML saved successfully.")

            self.verify_signature(canonical_xml_hash, signature)

        except Exception as e:
            print(f"Error during document signing: {str(e)}")

    def verify_signature(self, doc_hash, signature):
        try:
            self.load_public_key()
            print("Verifying signature...")
            self.public_key.verify(
                signature, doc_hash, padding.PKCS1v15(), hashes.SHA256()
            )
            print("Signature verified successfully.")
        except Exception as e:
            print(f"Signature verification failed: {str(e)}")

    def modify_and_insert_signature(self, doc, signed_properties_hash, doc_hash):
        try:
            print("Modifying XML with signature details...")

            namespaces = {
                "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
                "sig": "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2",
                "sac": "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2",
                "xades": "http://uri.etsi.org/01903/v1.3.2#",
                "ds": "http://www.w3.org/2000/09/xmldsig#",
            }

            xpath_signature_value = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:SignatureValue"
            )
            xpath_x509_certificate = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
            )
            xpath_signed_props_digest = (
                ".//ds:Reference[@URI='#id-xades-signed-props']/ds:DigestValue"
            )
            xpath_doc_signed_digest = (
                ".//ds:Reference[@Id='id-doc-signed-data']/ds:DigestValue"
            )

            signature_value_element = doc.find(xpath_signature_value, namespaces)
            x509_certificate_element = doc.find(xpath_x509_certificate, namespaces)
            signed_props_digest_element = doc.find(
                xpath_signed_props_digest, namespaces
            )
            doc_signed_digest_element = doc.find(xpath_doc_signed_digest, namespaces)

            if signature_value_element is None or x509_certificate_element is None:
                signature_info_path = "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation"
                signature_info_element = doc.find(signature_info_path, namespaces)
                if signature_info_element is None:
                    ubl_extensions = doc.find("ext:UBLExtensions", namespaces)
                    if ubl_extensions is None:
                        ubl_extensions = etree.SubElement(
                            doc.getroot(),
                            "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtensions",
                        )

                    ubl_extension = etree.SubElement(
                        ubl_extensions,
                        "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension",
                    )
                    extension_content = etree.SubElement(
                        ubl_extension,
                        "{urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2}ExtensionContent",
                    )
                    signature_info_element = etree.SubElement(
                        extension_content,
                        "{urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2}SignatureInformation",
                    )

                ds_signature = etree.SubElement(
                    signature_info_element,
                    "{http://www.w3.org/2000/09/xmldsig#}Signature",
                )
                signature_value_element = etree.SubElement(
                    ds_signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue"
                )
                ds_key_info = etree.SubElement(
                    ds_signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
                )
                ds_x509_data = etree.SubElement(
                    ds_key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data"
                )
                x509_certificate_element = etree.SubElement(
                    ds_x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
                )

            signature_value_element.text = self.sign_data.signature_value
            x509_certificate_element.text = self.sign_data.x509_certificate

            if signed_props_digest_element is not None:
                signed_props_digest_element.text = signed_properties_hash

            if doc_signed_digest_element is not None:
                doc_signed_digest_element.text = doc_hash

            xpath_dv = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                "xades:SignedProperties/xades:SignedSignatureProperties/"
                "xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue"
            )
            xpath_signTime = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                "xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningTime"
            )
            xpath_issuerName = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                "xades:SignedProperties/xades:SignedSignatureProperties/"
                "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509IssuerName"
            )
            xpath_serialNum = (
                "ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/"
                "sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/"
                "xades:SignedProperties/xades:SignedSignatureProperties/"
                "xades:SigningCertificate/xades:Cert/xades:IssuerSerial/ds:X509SerialNumber"
            )

            element_dv = doc.find(xpath_dv, namespaces)
            element_st = doc.find(xpath_signTime, namespaces)
            element_in = doc.find(xpath_issuerName, namespaces)
            element_sn = doc.find(xpath_serialNum, namespaces)

            if element_dv is not None:
                element_dv.text = self.sign_data.cert_digest
            if element_st is not None:
                element_st.text = self.sign_data.signing_time
            if element_in is not None:
                element_in.text = self.sign_data.x509_issuer_name
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
        private_key_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/privatekey.pem",
    )
    # xml_signer.sign_document()

from lxml import etree

# Define namespaces
namespaces = {
    'xades': 'http://uri.etsi.org/01903/v1.3.2#',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

# Parse the XML document (replace with your actual XML string or file path)
xml_content = '''<?xml version='1.0' encoding='UTF-8'?>
<Invoice xmlns=śśśś"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
      <ext:ExtensionContent>
        <sig:UBLDocumentSignatures xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2" xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2" xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2">
          <sac:SignatureInformation>
            <cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID>
            <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference Id="id-doc-signed-data" URI="">
                  <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                      <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                    </ds:Transform>
                    <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                      <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                    </ds:Transform>
                    <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                  </ds:Transforms>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>fmHu036oMcy1doxlQBZcRGdcEL48CLZUvRHRNRi0oU0=</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#id-xades-signed-props" Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" >
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>jR7jWKLe+sHyzhBMjtICuSxzDzdLNJB1JtTfI1hFfRA=</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>dvMBrosxV+R3jBB8fS7IJE6SdqW0p8+Bl4hHyO9VU4CiL5py5IAAvfw3tArndLN2lhvsVe89ZmUa7N8liW+quiv/ku1HJbtgvir5LTrCMzIj8JqUgs/Eh6KqC80v4eeKOzfy30KWzAAZdnf9rkBQy5XiQbylD5AviRq0oSo3WX+6rjssKlCJ9jQ3yzxmH+ayqSE9nHkP9q0CVxh2qJa0d1k3kcCTsPOIwhdCvr75b4jLchIl7Fk2Zi3RkMxoQ0E+kZbW7XMySF23PL1fg/Pd9J8RSeHvNARE10YzEdYUPbw9PotHLu47AiFGmIyfdaZM9Ld+wEv+9F/RWPY1fRX94g==</ds:SignatureValue>
              <ds:KeyInfo>
                <ds:X509Data>
                  <ds:X509Certificate>MIIFdjCCA16gAwIBAgIDBWvEMA0GCSqGSIb3DQEBCwUAMHUxCzAJBgNVBAYTAk1ZMQ4wDAYDVQQKEwVMSEROTTE2MDQGA1UECxMtVGVybXMgb2YgdXNlIGF0IGh0dHA6Ly93d3cucG9zZGlnaWNlcnQuY29tLm15MR4wHAYDVQQDExVUcmlhbCBMSEROTSBTdWIgQ0EgVjEwHhcNMjQwNjI4MjMxNTAxWhcNMjQwOTI2MjMxNTAxWjCBizELMAkGA1UEBhMCTVkxFjAUBgNVBAoTDVRIQyBTRE4uIEJIRC4xEzARBgNVBGETCkM4ODgyODEwOTAxFjAUBgNVBAMTDVRIQyBTRE4uIEJIRC4xFTATBgNVBAUTDDE5NzgwMTAwMDA3NDEgMB4GCSqGSIb3DQEJARYRbGMudGFuQHRoYy5jb20ubXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoxfC5OkAAwKYECZZfa6oSlpCnglh1kINlg3i1ai1CqZfBG71QJYQ6Tf2X8UPXLcWBr3SbrBArD+a15ydEOnwP9b7XnT/yyJSugMULY81szRnsPp85VUBJ8zcQimq1L+Hir+s9hFxLZHL2MMQQ2/mL2+M5EaspYtX7OhspMYlmqZOxp/MnKESZyZiv90gLkPUg2BUAwh+igtpjCBKFvFpKpgSbraasne8Zsbmse4Sq8i0bj1fLhNMkU57X6Ybgn/VZHcvzSmUymSHmmkK+FaN5IGOiEdU3lQ1alesktsbNaGcfWKy5f2Iig9gxsSb0r326VFutr855Kd+xDXv2AaUjAgMBAAGjgfcwgfQwHwYDVR0lBBgwFgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwEQYDVR0OBAoECEFpaJN3wvTBMFMGA1UdIARMMEowSAYJKwYBBAGDikUBMDswOQYIKwYBBQUHAgEWLWh0dHBzOi8vd3d3LnBvc2RpZ2ljZXJ0LmNvbS5teS9yZXBvc2l0b3J5L2NwczATBgNVHSMEDDAKgAhNf9lrtsUI0DAOBgNVHQ8BAf8EBAMCBkAwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL3RyaWFsY3JsLnBvc2RpZ2ljZXJ0LmNvbS5teS9UcmlhbExIRE5NVjEuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQCnOiF+oMJVGWXlZ3nvol17rdeMGVVeOiWa6oV1lR14I4qwqgSUB82GzsAoPvbyshUeov1lxBkvM9TUeC7atROEgbQNOMUXS/bVeTOLrFZ9l8hZQhGDGBJa2NiURsvLfdT7MAIQMO74C2Bc06u6Uhcrcpbz2wWSbthwRgJ/xHlIhqULGN9a2mAv/lcQDD88ujOBSALOB8aE6V/cmhfmNoLdgDtoHVclwxstLEgFI+UyTU0UU3LOL4lTL04/hA9fFIhN/aZAlSvNTkzcCSIlMzVsVYHDsuelY8aHJ61v4GrV4yRVwWLXwYzAyZJ9zP8C0VoTakUMgBZt+59Dis2xpHGHnJNGkKhHyAFRrMi4Lny6wSJys7SkhsbnEt94PvBvhv0jTx7VVjvpZF5G69iyPq366FXPsKdFGXg3slr0ecnFy839zSquxzGHGpPUj+Oq8dHzdf4kBngyO+yyg42JLNAGmq3cCVqytJCuYvs7q1m9IHliiZRlRtOW5SufdGM9NBCO/dtRdz3HjlJ4DsMnUPPZLNRC7DM84XCT9hyP6cnaQhYL2L9myPTTJ4C2Nxu/P/XUWPUP7vmBEWI5vANAfSwiUwVdwD8RFd+y+VWc3rpp1o16cWR9kpt6FHA0qvcQedoJTx+bxcp3jpr6A9wjAi8OggRTRp3QNwGe2ygV4gndaQ==</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
              <ds:Object>
                <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature">
                  <xades:SignedProperties Id="id-xades-signed-props">
                    <xades:SignedSignatureProperties>
                      <xades:SigningTime>2024-09-25T06:51:37Z</xades:SigningTime>
                      <xades:SigningCertificate>
                        <xades:Cert>
                          <xades:CertDigest>
                            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                            <ds:DigestValue>mbtCC0dy0b+ih7VUz/8XMIgSPnNxTZ9KdLGfF5U5iW4=</ds:DigestValue>
                          </xades:CertDigest>
                          <xades:IssuerSerial>
                            <ds:X509IssuerName>CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY</ds:X509IssuerName>
                            <ds:X509SerialNumber>355268</ds:X509SerialNumber>
                          </xades:IssuerSerial>
                        </xades:Cert>
                      </xades:SigningCertificate>
                    </xades:SignedSignatureProperties>
                  </xades:SignedProperties>
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
          </sac:SignatureInformation>
        </sig:UBLDocumentSignatures>
      </ext:ExtensionContent>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <cbc:ID>IV0000010134444</cbc:ID>
  <cbc:IssueDate>2024-09-23</cbc:IssueDate>
  <cbc:IssueTime>03:36:00Z</cbc:IssueTime>
  <cbc:InvoiceTypeCode listVersionID="1.1">01</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>MYR</cbc:DocumentCurrencyCode>
  <cac:BillingReference>
    <cac:AdditionalDocumentReference>
      <cbc:ID>IV0000010134444</cbc:ID>
    </cac:AdditionalDocumentReference>
  </cac:BillingReference>
  <cac:Signature>
    <cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID>
    <cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod>
  </cac:Signature>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cbc:IndustryClassificationCode name="Other information technology service activities n.e.c.">62099</cbc:IndustryClassificationCode>
      <cac:PartyIdentification>
        <cbc:ID schemeID="TIN">C888281090</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyIdentification>
        <cbc:ID schemeID="BRN">197801000074</cbc:ID>
      </cac:PartyIdentification>
      <cac:PostalAddress>
        <cbc:CityName>Cheras</cbc:CityName>
        <cbc:PostalZone>56000</cbc:PostalZone>
        <cbc:CountrySubentityCode>14</cbc:CountrySubentityCode>
        <cac:AddressLine>
          <cbc:Line>B-3, 13, Jalan 2/142a, </cbc:Line>
        </cac:AddressLine>
        <cac:AddressLine>
          <cbc:Line>Cheras, 56000 Cheras</cbc:Line>
        </cac:AddressLine>
        <cac:AddressLine>
          <cbc:Line>Wilayah Persekutuan Kuala Lumpur</cbc:Line>
        </cac:AddressLine>
        <cac:Country>
          <cbc:IdentificationCode listAgencyID="6" listID="ISO3166-1">MYS</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>M POS SYSTEMS SERVICES</cbc:RegistrationName>
      </cac:PartyLegalEntity>
      <cac:Contact>
        <cbc:Telephone>019-626 3923</cbc:Telephone>
        <cbc:ElectronicMail>Info@m-pos.com.my</cbc:ElectronicMail>
      </cac:Contact>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="TIN">C20086138070</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyIdentification>
        <cbc:ID schemeID="BRN">200701008200</cbc:ID>
      </cac:PartyIdentification>
      <cac:PostalAddress>
        <cbc:CityName>Cheras</cbc:CityName>
        <cbc:PostalZone>56000</cbc:PostalZone>
        <cbc:CountrySubentityCode>14</cbc:CountrySubentityCode>
        <cac:AddressLine>
          <cbc:Line>B-3, 13, Jalan 2/142a, </cbc:Line>
        </cac:AddressLine>
        <cac:AddressLine>
          <cbc:Line>Cheras, 56000 Cheras</cbc:Line>
        </cac:AddressLine>
        <cac:AddressLine>
          <cbc:Line>Cheras, 56000 Cheras</cbc:Line>
        </cac:AddressLine>
        <cac:Country>
          <cbc:IdentificationCode listAgencyID="6" listID="ISO3166-1">MYS</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>M POS SYSTEMS SERVICES</cbc:RegistrationName>
      </cac:PartyLegalEntity>
      <cac:Contact>
        <cbc:Telephone>019-626 3923</cbc:Telephone>
        <cbc:ElectronicMail>Info@m-pos.com.my</cbc:ElectronicMail>
      </cac:Contact>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="MYR">3.5</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="MYR">3.5</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="MYR">3.5</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>01</cbc:ID>
        <cbc:Percent>10</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID schemeAgencyID="6" schemeID="UN/ECE 5153">OTH</cbc:ID>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="MYR">35</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="MYR">35</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="MYR">38.5</cbc:TaxInclusiveAmount>
    <cbc:AllowanceTotalAmount currencyID="MYR">5</cbc:AllowanceTotalAmount>
    <cbc:PayableAmount currencyID="MYR">38.5</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="H87">2</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="MYR">35</cbc:LineExtensionAmount>
    <cac:AllowanceCharge>
      <cbc:ChargeIndicator>false</cbc:ChargeIndicator>
      <cbc:AllowanceChargeReason>Item Discount</cbc:AllowanceChargeReason>
      <cbc:MultiplierFactorNumeric>1</cbc:MultiplierFactorNumeric>
      <cbc:Amount currencyID="MYR">5</cbc:Amount>
    </cac:AllowanceCharge>
    <cac:TaxTotal>
      <cbc:TaxAmount currencyID="MYR">3.5</cbc:TaxAmount>
      <cac:TaxSubtotal>
        <cbc:TaxableAmount currencyID="MYR">35</cbc:TaxableAmount>
        <cbc:TaxAmount currencyID="MYR">3.5</cbc:TaxAmount>
        <cac:TaxCategory>
          <cbc:ID>01</cbc:ID>
          <cbc:Percent>10</cbc:Percent>
          <cac:TaxScheme>
            <cbc:ID schemeAgencyID="6" schemeID="UN/ECE 5153">OTH</cbc:ID>
          </cac:TaxScheme>
        </cac:TaxCategory>
      </cac:TaxSubtotal>
    </cac:TaxTotal>
    <cac:Item>
      <cbc:Description>Computer Monitor 24 inch</cbc:Description>
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="CLASS">003</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="MYR">20</cbc:PriceAmount>
    </cac:Price>
    <cac:ItemPriceExtension>
      <cbc:Amount currencyID="MYR">40</cbc:Amount>
    </cac:ItemPriceExtension>
  </cac:InvoiceLine>
</Invoice>'''

# Parse the XML content
root = etree.fromstring(xml_content)

# Try to locate the SignedProperties element using XPath
signed_properties = root.xpath('//xades:SignedProperties', namespaces=namespaces)

if signed_properties:
    print("SignedProperties found!")
    # You can now work with the signed_properties node
else:
    print("SignedProperties node not found.")
śś