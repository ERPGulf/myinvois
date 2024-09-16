import hashlib
import base64
from lxml import etree
import xmlsec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
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
    def __init__(self, xml_path, cert_path, cert_password):
        self.xml_path = xml_path
        self.cert_path = cert_path
        self.cert_password = cert_password
        self.cert = None
        self.private_key = None
        self.sign_data = SignatureData()

    def load_cert(self):
        print("Loading certificate from:", self.cert_path)
        # Load the PKCS12 (PFX) certificate using cryptography
        with open(self.cert_path, 'rb') as cert_file:
            pfx_data = cert_file.read()
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data,
                self.cert_password.encode(),
                default_backend()
            )
            self.cert = cert
            self.private_key = private_key



    def get_cert_details(self):
        # Use PEM encoding for the certificate
        self.sign_data.x509_certificate = base64.b64encode(
            self.cert.public_bytes(serialization.Encoding.DER)  # Using DER format for binary encoding
        ).decode('utf-8')

        # Calculate the certificate hash (SHA-256) and base64 encode it
        der_cert = self.cert.public_bytes(serialization.Encoding.DER)
        cert_hash = hashlib.sha256(der_cert).digest()
        self.sign_data.cert_digest = base64.b64encode(cert_hash).decode('utf-8')

        self.sign_data.x509_issuer_name = self.cert.issuer.rfc4514_string()
        self.sign_data.x509_serial_number = self.cert.serial_number
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
            print("doc hash",self.sign_data.doc_digest)
            # Sign the document using RSA private key from the certificate
            signature = self.private_key.sign(
                doc_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.sign_data.signature_value = base64.b64encode(signature).decode('utf-8')
            print("Document signed successfully. Signature value:", self.sign_data.signature_value)

            # Get the certificate details for XML inclusion
            self.get_cert_details()

            # Hash the signed properties (for example, this could be an element like <xades:SignedProperties>)
            signed_props_element = doc.find(".//xades:SignedProperties", namespaces={
                'xades': 'http://uri.etsi.org/01903/v1.3.2#'
            })
            if signed_props_element is not None:
                canonical_signed_props = self.canonicalize_xml(signed_props_element)
                signed_props_hash = self.sha256_hash(canonical_signed_props)
                self.sign_data.props_digest = base64.b64encode(signed_props_hash).decode('utf-8')

                # Print the signed properties hash
                print("Signed Properties Hash (Base64):", self.sign_data.props_digest)
            else:
                print("SignedProperties element not found in the XML.")

            # Modify the XML by inserting signature and other required details
            self.modify_and_insert_signature(doc, self.sign_data.props_digest, self.sign_data.doc_digest)

            # Save the final signed XML document
            with open("/opt/malaysia/frappe-bench/sites/signed_finalzatca.xml", "wb") as signed_file:
                signed_file.write(etree.tostring(doc, pretty_print=True))
            print("Final signed XML saved successfully.")

        except Exception as e:
            print(f"Error during document signing: {str(e)}")



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
            signature_value_element.text = self.sign_data.signature_value
            x509_certificate_element.text = self.sign_data.x509_certificate

            if signed_props_digest_element is not None:
                signed_props_digest_element.text = signed_properties_hash  # Insert the SignedProperties hash

            if doc_signed_digest_element is not None:
                doc_signed_digest_element.text = doc_hash  # Insert the document hash

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
                element_in.text = self.sign_data.x509_issuer_name
            if element_sn is not None:
                element_sn.text = str(self.sign_data.x509_serial_number)

            print("Signature, certificate, and digest values inserted successfully.")

        except Exception as e:
            print("Error during XML modification: " + str(e))


if __name__ == "__main__":
    xml_signer = UBLSignatureXML(xml_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml", cert_path="/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/myinvois_erpgulf/myinvois_erpgulf/EINVCERT.PFX", cert_password="Ci8)RmsE")
    xml_signer.load_cert()
    xml_signer.sign_document()



