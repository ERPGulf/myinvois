from lxml import etree
import hashlib
import base64
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, BestAvailableEncryption, PrivateFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from myinvois_erpgulf.myinvois_erpgulf.createxml import create_invoice_with_extensions,salesinvoice_data,company_data,customer_data,tax_total,legal_monetary_total,xml_structuring,invoice_line_item,item_data_with_template,tax_total_with_template
import frappe       
import requests

def xml_hash():
    try:
        with open(frappe.local.site + "/private/files/create.xml", "rb") as file:
            xml_content = file.read()
        root = etree.fromstring(xml_content)
        line_xml = etree.tostring(root, pretty_print=False, encoding='UTF-8')
        sha256_hash = hashlib.sha256(line_xml).digest()  
        doc_hash = base64.b64encode(sha256_hash).decode('utf-8')
        return line_xml,doc_hash
    except Exception as e:
            frappe.throw(f"Error in xml hash: {str(e)}")


def certificate_data():
    try:

        settings = frappe.get_doc('LHDN Malaysia Setting')
        attached_file = settings.certificate_file

        if not attached_file:
            frappe.throw("No PFX file attached in the settings.")
        file_doc = frappe.get_doc("File", {"file_url": attached_file})
        pfx_path = file_doc.get_full_path()
        
        pfx_password = settings.pfx_cert_password
        pem_output_path = frappe.local.site + "/private/files/certificate.pem"
        pem_encryption_password = pfx_password.encode()   
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data, pfx_password.encode(), backend=default_backend()
        )

        with open(pem_output_path, "wb") as pem_file:
            if private_key:
                pem_file.write(private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,  
                    encryption_algorithm=BestAvailableEncryption(pem_encryption_password) 
                ))

            if certificate:
                certificate_base64 = base64.b64encode(certificate.public_bytes(Encoding.DER)).decode("utf-8")
                pem_file.write(certificate.public_bytes(Encoding.PEM))
                x509_issuer_name = formatted_issuer_name = certificate.issuer.rfc4514_string()
                formatted_issuer_name =x509_issuer_name.replace(",", ", ")
                x509_serial_number = certificate.serial_number
                cert_digest = base64.b64encode(certificate.fingerprint(hashes.SHA256())).decode("utf-8")
                signing_time =  datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            if additional_certificates:
                for cert in additional_certificates:
                    pem_file.write(cert.public_bytes(Encoding.PEM))
            return  certificate_base64,formatted_issuer_name,  x509_serial_number ,cert_digest ,signing_time
        

    except Exception as e:
        frappe.throw(f"Error loading certificate details: {str(e)}")



def bytes_to_base64_string(value: bytes) -> str:   
   return base64.b64encode(value).decode('ASCII')

def sign_data(line_xml):
    try:
        # print(single_line_ xml1)
        hashdata = line_xml.decode().encode() 
        f = open(frappe.local.site + "/private/files/certificate.pem", "r")
        cert_pem=f.read()
        if hashdata is None:
            raise ValueError("hashdata cannot be None")
        if cert_pem is None:
            raise ValueError("cert_pem cannot be None")
        cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        # print(cert.issuer)
        settings = frappe.get_doc('LHDN Malaysia Setting')
        pass_file=settings.pfx_cert_password
        private_key = serialization.load_pem_private_key(
            cert_pem.encode(),
            password=pass_file.encode(),
        )
        
        if private_key is None or not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("The certificate does not contain an RSA private key.")
        
        try:
            signed_data = private_key.sign(
                hashdata,
                padding.PKCS1v15(),
                hashes.SHA256()        
            )
            base64_bytes = base64.b64encode(signed_data)
            base64_string = base64_bytes.decode("ascii")
            # print(f"Encoded string: {base64_string}")
        except InvalidSignature as ex:
            raise Exception("An error occurred while signing the data.") from ex
        return base64_string
    except Exception as e:
        frappe.throw(f"Error in sign data: {str(e)}")



def signed_properties_hash(signing_time,cert_digest,formatted_issuer_name,x509_serial_number):
        try:

            single_line_xml = f'''<xades:SignedProperties Id="id-xades-signed-props" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"><xades:SignedSignatureProperties><xades:SigningTime>{signing_time}</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:DigestMethod><ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{cert_digest}</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{formatted_issuer_name}</ds:X509IssuerName><ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{x509_serial_number}</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>'''
            prop_cert_hash = hashlib.sha256(single_line_xml.encode('utf-8')).digest()
            prop_cert_base64 = base64.b64encode(prop_cert_hash).decode('utf-8')
            # print(f"SHA-256 Hash in Base64 (propCert): {prop_cert_base64}")
            return prop_cert_base64
        except Exception as e:
            frappe.throw(f"Error signed properties hash: {str(e)}")


def ubl_extension_string(doc_hash,prop_cert_base64,signature,certificate_base64,signing_time,cert_digest,formatted_issuer_name,x509_serial_number,line_xml):
        try:
                inv_xml_string = f"""<ext:UBLExtensions>
                        <ext:UBLExtension>
                            <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
                            <ext:ExtensionContent>
                                <sig:UBLDocumentSignatures xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2"
                                     xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2"
                                     xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2">
                                    <sac:SignatureInformation>
                                        <cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID>
                                        <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>
                                        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature">
                                            <ds:SignedInfo>
                                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>
                                                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>
                                                <ds:Reference Id="id-doc-signed-data" URI="">
                                                    <ds:Transforms>
                                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                                            <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                                                        </ds:Transform>
                                                        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                                            <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                                                        </ds:Transform>
                                                        <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:Transform>
                                                    </ds:Transforms>
                                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                                                    <ds:DigestValue>{doc_hash}</ds:DigestValue>
                                                </ds:Reference>
                                                <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#id-xades-signed-props">
                                                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                                                    <ds:DigestValue>{prop_cert_base64}</ds:DigestValue>
                                                </ds:Reference>
                                            </ds:SignedInfo>
                                            <ds:SignatureValue>{signature}</ds:SignatureValue>
                                            <ds:KeyInfo>
                                                <ds:X509Data>
                                                    <ds:X509Certificate>{certificate_base64}</ds:X509Certificate>
                                                </ds:X509Data>
                                            </ds:KeyInfo>
                                            <ds:Object>
                                                <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature">
                                                    <xades:SignedProperties Id="id-xades-signed-props">
                                                        <xades:SignedSignatureProperties>
                                                            <xades:SigningTime>{signing_time}</xades:SigningTime>
                                                            <xades:SigningCertificate>
                                                                <xades:Cert>
                                                                    <xades:CertDigest>
                                                                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                                                                        <ds:DigestValue>{cert_digest}</ds:DigestValue>
                                                                    </xades:CertDigest>
                                                                    <xades:IssuerSerial>
                                                                        <ds:X509IssuerName>{formatted_issuer_name}</ds:X509IssuerName>
                                                                        <ds:X509SerialNumber>{x509_serial_number}</ds:X509SerialNumber>
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
                    </ext:UBLExtensions>"""
                inv_xml_string_single_line = inv_xml_string.replace("\n", "").replace("  ", "").replace("> <", "><")
                string=line_xml.decode()
                if isinstance(string, str) and isinstance(inv_xml_string_single_line, str):
                
                    insert_position = string.find(">") + 1
                    result = string[:insert_position] + inv_xml_string_single_line + string[insert_position:]

                
                signature_string = """<cac:Signature><cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID><cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod></cac:Signature>"""
                insert_position = result.find("<cac:AccountingSupplierParty>")
                if insert_position != -1:  
                    
                    result_final = result[:insert_position] + signature_string + result[insert_position:]
                    # print(result_final)

                    output_path = frappe.local.site + "/private/files/output.xml"
                    with open(output_path, "w") as file:
                        file.write(result_final)
                    
                    
                    # frappe.throw("The modified XML has been saved to 'signedxml_for_submit.xml'.")
                else:
                    frappe.throw("The element <cac:AccountingSupplierParty> was not found in the XML string.")
        except Exception as e:
            frappe.throw(f"Error ubl extension string: {str(e)}")


def submission_url():
                
            try:

                settings = frappe.get_doc('LHDN Malaysia Setting')
                token = settings.bearer_token
                with open(frappe.local.site + "/private/files/output.xml", 'rb') as f:
                    xml_data = f.read()

                sha256_hash = hashlib.sha256(xml_data).hexdigest()
                # print(sha256_hash)
                encoded_xml = base64.b64encode(xml_data).decode('utf-8')
                # print(encoded_xml)
                json_payload = {
                    "documents": [
                        {
                            "format": "XML",
                            "documentHash": sha256_hash,
                            "codeNumber": "INV 15",
                            "document": encoded_xml
                        }
                    ]
                }

                headers = {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                }

                # Send the POST request
                response = requests.post(
                    'https://preprod-api.myinvois.hasil.gov.my/api/v1.0/documentsubmissions',
                    headers=headers,
                    json=json_payload
                )
                # print("Response status code:", response.status_code)
                frappe.msgprint(f"Response body: {response.text}")

            except Exception as e:
                frappe.z(f"Error in submission url: {str(e)}")
            


@frappe.whitelist(allow_guest=True)
def submit_document(invoice_number, any_item_has_tax_template=False):
    try:
        sales_invoice_doc = frappe.get_doc('Sales Invoice', invoice_number)

        # Check if any item has a tax template but not all items have one
        if any(item.item_tax_template for item in sales_invoice_doc.items) and not all(item.item_tax_template for item in sales_invoice_doc.items):
            frappe.throw("If any one item has an Item Tax Template, all items must have an Item Tax Template.")
        else:
            # Set to True if all items have a tax template
            any_item_has_tax_template = all(item.item_tax_template for item in sales_invoice_doc.items)

        invoice = create_invoice_with_extensions()
        salesinvoice_data(invoice, sales_invoice_doc)
        
        company_data(invoice, sales_invoice_doc)
        customer_data(invoice, sales_invoice_doc)
        
        # Call appropriate tax total function
        if not any_item_has_tax_template:
            tax_total(invoice, sales_invoice_doc)
        else:
            tax_total_with_template(invoice, sales_invoice_doc)
        
        legal_monetary_total(invoice, sales_invoice_doc)

        # Call appropriate item data function
        if not any_item_has_tax_template:
            invoice_line_item(invoice, sales_invoice_doc)
        else:
            item_data_with_template(invoice, sales_invoice_doc)
        
        xml_output = xml_structuring(invoice, sales_invoice_doc)
        line_xml, doc_hash = xml_hash()
        
        certificate_base64, formatted_issuer_name, x509_serial_number, cert_digest, signing_time = certificate_data()
        
        signature = sign_data(line_xml)
        prop_cert_base64 = signed_properties_hash(signing_time, cert_digest, formatted_issuer_name, x509_serial_number)
        
        ubl_extension_string(doc_hash, prop_cert_base64, signature, certificate_base64, signing_time, cert_digest, formatted_issuer_name, x509_serial_number, line_xml)
        
        submission_url()

    except Exception as e:
        frappe.throw(f"Error in submit document: {str(e)}")
