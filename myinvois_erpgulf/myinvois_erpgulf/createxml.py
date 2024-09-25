import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom


def create_invoice_with_extensions():
 
            try: 
                invoice = ET.Element("Invoice", xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" )
                invoice.set("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
                invoice.set("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
                invoice.set("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")   
                ubl_extensions = ET.SubElement(invoice, "ext:UBLExtensions")
                ubl_extension = ET.SubElement(ubl_extensions, "ext:UBLExtension")
                extension_uri = ET.SubElement(ubl_extension, "ext:ExtensionURI")
                extension_uri.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
                extension_content = ET.SubElement(ubl_extension, "ext:ExtensionContent")
                UBL_Document_Signatures = ET.SubElement(extension_content , "sig:UBLDocumentSignatures"    )
                UBL_Document_Signatures.set("xmlns:sig" , "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2")
                UBL_Document_Signatures.set("xmlns:sac" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2")
                UBL_Document_Signatures.set("xmlns:sbc" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2")
                Signature_Information = ET.SubElement(UBL_Document_Signatures , "sac:SignatureInformation"  )
                id = ET.SubElement(Signature_Information , "cbc:ID"  )
                id.text = "urn:oasis:names:specification:ubl:signature:1"
                Referenced_SignatureID = ET.SubElement(Signature_Information , "sbc:ReferencedSignatureID"  )
                Referenced_SignatureID.text = "urn:oasis:names:specification:ubl:signature:Invoice"
                Signature = ET.SubElement(Signature_Information , "ds:Signature"  )
                Signature.set("xmlns:ds" , "http://www.w3.org/2000/09/xmldsig#" )
                Signature.set("Id" , "signature" )
                
                Signed_Info = ET.SubElement(Signature , "ds:SignedInfo"  )
                Canonicalization_Method = ET.SubElement(Signed_Info , "ds:CanonicalizationMethod"  )
                Canonicalization_Method.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11")
                Signature_Method = ET.SubElement(Signed_Info , "ds:SignatureMethod"  )
                Signature_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                Reference = ET.SubElement(Signed_Info , "ds:Reference"  )
                Reference.set("Id"  , "id-doc-signed-data")
                Reference.set("URI"  , "")
                Transforms = ET.SubElement(Reference , "ds:Transforms" )
                Transform = ET.SubElement(Transforms , "ds:Transform" )
                Transform.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath = ET.SubElement(Transform , "ds:XPath" )
                XPath.text = "not(//ancestor-or-self::ext:UBLExtensions)"
                Transform2 = ET.SubElement(Transforms , "ds:Transform" )
                Transform2.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath2 = ET.SubElement(Transform2 , "ds:XPath" )
                XPath2.text = "not(//ancestor-or-self::cac:Signature)"
                # Transform3 = ET.SubElement(Transforms , "ds:Transform" )
                # Transform3.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                # XPath3 = ET.SubElement(Transform3 , "ds:XPath" )
                # XPath3.text = "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])"
                Transform3 = ET.SubElement(Transforms , "ds:Transform" )
                Transform3.set("Algorithm" , "ttp://www.w3.org/2006/12/xml-c14n11")
                Diges_Method = ET.SubElement(Reference , "ds:DigestMethod" )
                Diges_Method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
                Diges_value = ET.SubElement(Reference , "ds:DigestValue" )
                Diges_value.text = "RvCSpMYz8009KbJ3ku72oaCFWpzEfQNcpc+5bulh3Jk="
                Reference2 = ET.SubElement(Signed_Info , "ds:Reference"  )
                
                Reference2.set("Type" , "http://www.w3.org/2000/09/xmldsig#SignatureProperties")
                Reference2.set("URI" , "#id-xades-signed-props")

                Digest_Method1 = ET.SubElement(Reference2 , "ds:DigestMethod"  )
                Digest_Method1.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_value1 = ET.SubElement(Reference2 , "ds:DigestValue"  )
                Digest_value1.text="OGU1M2Q3NGFkOTdkYTRiNDVhOGZmYmU2ZjE0YzI3ZDhhNjlmM2EzZmQ4MTU5NTBhZjBjNDU2MWZlNjU3MWU0ZQ=="
                Signature_Value = ET.SubElement(Signature , "ds:SignatureValue"  )
                Signature_Value.text = "MEYCIQDYsDnviJYPgYjyCIYAyzETeYthIoJaQhChblP4eAAPPAIhAJl6zfHgiKmWTtsfUz8YBZ8QkQ9rBL4Uy7mK0cxvWooH"
                KeyInfo = ET.SubElement(Signature , "ds:KeyInfo"  )
                X509Data = ET.SubElement(KeyInfo , "ds:X509Data"  )
                X509Certificate = ET.SubElement(X509Data , "ds:X509Certificate"  )
                X509Certificate.text = "MIIEQzCCAyugAwIBAgIhAOkUChItLeodmoK/A7B0XLcSUCvT4jgrSeYBOeZ1G8VPMA0GCSqGSIb3DQEBBQUAMIG9MQswCQYDVQQGEwJLTDEhMB8GA1UECgwYQ29udG9zbyBNYWxheXNpYSBTZG4gQmhkMSEwHwYDVQQLDBhDb250b3NvIE1hbGF5c2lhIFNkbiBCaGQxITAfBgNVBAMMGENvbnRvc28gTWFsYXlzaWEgU2RuIEJoZDEiMCAGCSqGSIb3DQEJARYTbm9lbWFpbEBjb250b3NvLmNvbTEhMB8GA1UEAwwYQ29udG9zbyBNYWxheXNpYSBTZG4gQmhkMB4XDTI0MDQwMzA5NTM1MFoXDTI3MDQwNDA5NTM1MFowgZoxCzAJBgNVBAYTAktMMSEwHwYDVQQKDBhDb250b3NvIE1hbGF5c2lhIFNkbiBCaGQxITAfBgNVBAsMGENvbnRvc28gTWFsYXlzaWEgU2RuIEJoZDEhMB8GA1UEAwwYQ29udG9zbyBNYWxheXNpYSBTZG4gQmhkMSIwIAYJKoZIhvcNAQkBFhNub2VtYWlsQGNvbnRvc28uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8yRxOigcbDzObxhNmVklzyJOItz4eSZHUv+JEy7nTosOg/wcFcDgrJDw6LZ/Mr6aW98VJ930hlSw52fOPiMnXTyJLF6ZjISPsTjlrn9eKnbWt6DWqFIDWDIaXVhAcfFRkKftSFgSIEO9NIb+kmV6K/LotWEiLglz6KZE3EopSF+pXa1LmwC8v0UhK8V8LcxqIe3dBq/jzyaWsLx5D4zdQqBSFEXrfp0A+N/93uAtQa35Fj3ypEpSzF/EQ6bDO/GwBKQm3lCny6AJB/I/kCbC/X+oMxkTOo9zW5hcdRiqmAa4iIrhORIOTlj5qfnngjulTnSMdK5kXSLJxC6SDlKtVwIDAQABo08wTTAdBgNVHQ4EFgQU2pvYc/z5Prqp8Dt8PM1C/df1ysQwHwYDVR0jBBgwFoAU2pvYc/z5Prqp8Dt8PM1C/df1ysQwCwYDVR0RBAQwAoIAMA0GCSqGSIb3DQEBBQUAA4IBAQBHzVHoQk+cAwunDlmrBjWYxfzmF3Adab81HKug+riDGiSG3bNntAwRVkDC4onG680Ucsuhxeyj18gkAtR/5ZWu3RDZwcYoBMuQzUSS9U5bwg5VqCqxEfTQCSERjuCa8lt99EcgY06e8a8WEwcY19LKVVwtrTJnlHvXhmcheumX3pfjPb5u0c0WKnbkj5mow75TuEmc0k1qow6Z6H5O6cPhX+eyNQSFZ3QnC0W2oIZTi96TVT4JH8LOPurZ5AdG9maQNIypaZ0gYPtAJISP+nxPOHmloicecdLLaMG/cvDf2+/bJR2P98dTuTZqgKrvWHkiMOma62MVx5dbcmbxgxU6"
                Object = ET.SubElement(Signature , "ds:Object"  )
                QualifyingProperties = ET.SubElement(Object , "xades:QualifyingProperties"  )
                
                QualifyingProperties.set("xmlns:xades" , "http://uri.etsi.org/01903/v1.3.2#")
                QualifyingProperties.set("Target" , "signature")
                SignedProperties = ET.SubElement(QualifyingProperties , "xades:SignedProperties"  )
                SignedProperties.set("Id" , "id-xades-signed-props")
                SignedSignatureProperties = ET.SubElement(SignedProperties , "xades:SignedSignatureProperties"  )
                SigningTime = ET.SubElement(SignedSignatureProperties , "xades:SigningTime"  )
                SigningTime.text = "2024-04-01T00:41:21Z"
                SigningCertificate = ET.SubElement(SignedSignatureProperties , "xades:SigningCertificate"  )
                Cert = ET.SubElement(SigningCertificate , "xades:Cert"  )
                CertDigest = ET.SubElement(Cert , "xades:CertDigest"  )
                Digest_Method2 = ET.SubElement(CertDigest , "ds:DigestMethod"  )
                Digest_Value2 = ET.SubElement(CertDigest , "ds:DigestValue"  )
                Digest_Method2.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_Value2.text = "YTJkM2"
                IssuerSerial = ET.SubElement(Cert , "xades:IssuerSerial"  )
                X509IssuerName = ET.SubElement(IssuerSerial , "ds:X509IssuerName"  )
                X509SerialNumber = ET.SubElement(IssuerSerial , "ds:X509SerialNumber"  )
                X509IssuerName.text = "89"
                X509SerialNumber.text = "32"
                return invoice
            except Exception as e:
                    print("error in xml tags formation:  "+ str(e) )
from datetime import datetime, timezone



def salesinvoice_data(invoice):
            try:
                cbc_ProfileID = ET.SubElement(invoice, "cbc:ProfileID")
                cbc_ProfileID.text = "reporting:1.0"
                cbc_ID = ET.SubElement(invoice, "cbc:ID")
                cbc_ID.text = "INV12345"
                # Get current time in UTC
                current_datetime_utc = datetime.now(timezone.utc)

                # Format date as 'YYYY-MM-DD' and time as 'HH:MM:SSZ'
                formatted_date = current_datetime_utc.strftime('%Y-%m-%d')
                formatted_time = current_datetime_utc.strftime('%H:%M:%SZ')

                # Print formatted date and time
                # print(f"Date: {formatted_date}")
                # print(f"Time: {formatted_time}")
                cbc_IssueDate = ET.SubElement(invoice, "cbc:IssueDate")
                cbc_IssueDate.text = formatted_date
                cbc_IssueTime = ET.SubElement(invoice, "cbc:IssueTime")
                cbc_IssueTime.text =formatted_time 
                return invoice 
            except Exception as e:
                print("error occured in salesinvoice data"+ str(e) )

def invoice_Typecode_and_currency(invoice):
            try:                             
                cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")     
                cbc_InvoiceTypeCode.set("listVersionID", "1.1") # Simplified
                cbc_InvoiceTypeCode.text = "01"
                cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
                cbc_DocumentCurrencyCode.text = "MYR"
                return invoice
            except Exception as e:
                    print("error occured in simplified invoice typecode"+ str(e) )

def invoice_period(invoice):
    try:
        cac_InvoicePeriod = ET.SubElement(invoice, "cac:InvoicePeriod")
        
        cbc_StartDate = ET.SubElement(cac_InvoicePeriod, "cbc:StartDate")
        current_datetime_utc = datetime.now(timezone.utc)

                # Format date as 'YYYY-MM-DD' and time as 'HH:MM:SSZ'
        formatted_date = current_datetime_utc.strftime('%Y-%m-%d')
        cbc_StartDate.text = formatted_date
        
        cbc_EndDate = ET.SubElement(cac_InvoicePeriod, "cbc:EndDate")
        cbc_EndDate.text = "2024-10-16"
        
        cbc_Description = ET.SubElement(cac_InvoicePeriod, "cbc:Description")
        cbc_Description.text = "Monthly"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating invoice period: " + str(e))



def create_billing_and_additional_references(invoice):
    try:
       
        cac_BillingReference_1 = ET.SubElement(invoice, "cac:BillingReference")
        cac_InvoiceDocumentReference = ET.SubElement(cac_BillingReference_1, "cac:InvoiceDocumentReference")
        
        cbc_ID = ET.SubElement(cac_InvoiceDocumentReference, "cbc:ID")
        cbc_ID.text = "INV54321"
        
        cbc_UUID = ET.SubElement(cac_InvoiceDocumentReference, "cbc:UUID")
        cbc_UUID.text = "F9D425P6DS7D8IU"
        
        
        cac_BillingReference_2 = ET.SubElement(invoice, "cac:BillingReference")
        cac_AdditionalDocumentReference_1 = ET.SubElement(cac_BillingReference_2, "cac:AdditionalDocumentReference")
        
        cbc_ID = ET.SubElement(cac_AdditionalDocumentReference_1, "cbc:ID")
        cbc_ID.text = "L1"
        
        
        cac_AdditionalDocumentReference_2 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
        cbc_ID = ET.SubElement(cac_AdditionalDocumentReference_2, "cbc:ID")
        cbc_ID.text = "L1"
        
        cbc_DocumentType = ET.SubElement(cac_AdditionalDocumentReference_2, "cbc:DocumentType")
        cbc_DocumentType.text = "CustomsImportForm"
        

        cac_AdditionalDocumentReference_3 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
        cbc_ID = ET.SubElement(cac_AdditionalDocumentReference_3, "cbc:ID")
        cbc_ID.text = "FTA"
        
        cbc_DocumentType = ET.SubElement(cac_AdditionalDocumentReference_3, "cbc:DocumentType")
        cbc_DocumentType.text = "FreeTradeAgreement"
        
        cbc_DocumentDescription = ET.SubElement(cac_AdditionalDocumentReference_3, "cbc:DocumentDescription")
        cbc_DocumentDescription.text = "Sample Description"
        
       
        cac_AdditionalDocumentReference_4 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
        cbc_ID = ET.SubElement(cac_AdditionalDocumentReference_4, "cbc:ID")
        cbc_ID.text = "L1"
        
        cbc_DocumentType = ET.SubElement(cac_AdditionalDocumentReference_4, "cbc:DocumentType")
        cbc_DocumentType.text = "K2"
        

        cac_AdditionalDocumentReference_5 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
        cbc_ID = ET.SubElement(cac_AdditionalDocumentReference_5, "cbc:ID")
        cbc_ID.text = "L1"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating billing and additional document references: " + str(e))


def create_signature(invoice):
    try:
        cac_Signature = ET.SubElement(invoice, "cac:Signature")
        
        cbc_ID = ET.SubElement(cac_Signature, "cbc:ID")
        cbc_ID.text = "urn:oasis:names:specification:ubl:signature:Invoice"
        
        cbc_SignatureMethod = ET.SubElement(cac_Signature, "cbc:SignatureMethod")
        cbc_SignatureMethod.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating signature: " + str(e))

def company_data(invoice):
    try:
        
        cac_AccountingSupplierParty = ET.SubElement(invoice, "cac:AccountingSupplierParty")
        cbc_AdditionalAccountID = ET.SubElement(cac_AccountingSupplierParty, "cbc:AdditionalAccountID")
        cbc_AdditionalAccountID.set("schemeAgencyName", "CertEX")
        
        
        cac_Party = ET.SubElement(cac_AccountingSupplierParty, "cac:Party")
        cbc_IndustryClassificationCode = ET.SubElement(cac_Party, "cbc:IndustryClassificationCode")
        cbc_IndustryClassificationCode.set("name", "Wholesale of computer hardware, software and peripherals")
        cbc_IndustryClassificationCode.text = "46510"
        
        cac_PartyIdentification_1 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        cbc_ID_1 = ET.SubElement(cac_PartyIdentification_1, "cbc:ID")
        cbc_ID_1.set("schemeID", "TIN")
        cbc_ID_1.text = "C888281090"
        
        cac_PartyIdentification_2 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        cbc_ID_2 = ET.SubElement(cac_PartyIdentification_2, "cbc:ID")
        cbc_ID_2.set("schemeID", "BRN")
        cbc_ID_2.text = "202201020832"
        
        cac_PostalAddress = ET.SubElement(cac_Party, "cac:PostalAddress")
        cbc_CityName = ET.SubElement(cac_PostalAddress, "cbc:CityName")
        cbc_CityName.text = "Cyberjaya"
        
        cbc_PostalZone = ET.SubElement(cac_PostalAddress, "cbc:PostalZone")
        cbc_PostalZone.text = "63000"
        
        cbc_CountrySubentityCode = ET.SubElement(cac_PostalAddress, "cbc:CountrySubentityCode")
        cbc_CountrySubentityCode.text = "14"
        
        
        cac_AddressLine_1 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_1 = ET.SubElement(cac_AddressLine_1, "cbc:Line")
        cbc_Line_1.text = "Persiaran Rimba Permai"
        
        cac_AddressLine_2 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_2 = ET.SubElement(cac_AddressLine_2, "cbc:Line")
        cbc_Line_2.text = "Cyber 8"
        
        cac_AddressLine_3 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_3 = ET.SubElement(cac_AddressLine_3, "cbc:Line")
        cbc_Line_3.text = "63000 Cyberjaya"
        
        cac_Country = ET.SubElement(cac_PostalAddress, "cac:Country")
        cbc_IdentificationCode = ET.SubElement(cac_Country, "cbc:IdentificationCode")
        cbc_IdentificationCode.set("listID", "ISO3166-1")
        cbc_IdentificationCode.set("listAgencyID", "6")
        cbc_IdentificationCode.text = "MYS"
        
        cac_PartyLegalEntity = ET.SubElement(cac_Party, "cac:PartyLegalEntity")
        cbc_RegistrationName = ET.SubElement(cac_PartyLegalEntity, "cbc:RegistrationName")
        cbc_RegistrationName.text = "AMS Setia Jaya Sdn. Bhd."
        
        
        cac_Contact = ET.SubElement(cac_Party, "cac:Contact")
        cbc_Telephone = ET.SubElement(cac_Contact, "cbc:Telephone")
        cbc_Telephone.text = "+969876543210"
        
        cbc_ElectronicMail = ET.SubElement(cac_Contact, "cbc:ElectronicMail")
        cbc_ElectronicMail.text = "xyz@test.com"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating accounting supplier party: " + str(e))

def customer_data(invoice):
    try:
        
        cac_AccountingCustomerParty = ET.SubElement(invoice, "cac:AccountingCustomerParty")
        cac_Party = ET.SubElement(cac_AccountingCustomerParty, "cac:Party")
        
        cac_PartyIdentification_1 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        cbc_ID_1 = ET.SubElement(cac_PartyIdentification_1, "cbc:ID")
        cbc_ID_1.set("schemeID", "TIN")
        cbc_ID_1.text = "C29967772090"
        
        cac_PartyIdentification_2 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        cbc_ID_2 = ET.SubElement(cac_PartyIdentification_2, "cbc:ID")
        cbc_ID_2.set("schemeID", "BRN")
        cbc_ID_2.text = "197801000074"
        
        
        cac_PostalAddress = ET.SubElement(cac_Party, "cac:PostalAddress")
        cbc_CityName = ET.SubElement(cac_PostalAddress, "cbc:CityName")
        cbc_CityName.text = "Kuala Lumpur"
        
        cbc_PostalZone = ET.SubElement(cac_PostalAddress, "cbc:PostalZone")
        cbc_PostalZone.text = "50200"
        
        cbc_CountrySubentityCode = ET.SubElement(cac_PostalAddress, "cbc:CountrySubentityCode")
        cbc_CountrySubentityCode.text = "14"
        
    
        cac_AddressLine_1 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_1 = ET.SubElement(cac_AddressLine_1, "cbc:Line")
        cbc_Line_1.text = "Lot 5 08"
        
        cac_AddressLine_2 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_2 = ET.SubElement(cac_AddressLine_2, "cbc:Line")
        cbc_Line_2.text = "5th Floor"
        
        cac_AddressLine_3 = ET.SubElement(cac_PostalAddress, "cac:AddressLine")
        cbc_Line_3 = ET.SubElement(cac_AddressLine_3, "cbc:Line")
        cbc_Line_3.text = "Wisma Cosway Jalan Raja Chulan"
        
        cac_Country = ET.SubElement(cac_PostalAddress, "cac:Country")
        cbc_IdentificationCode = ET.SubElement(cac_Country, "cbc:IdentificationCode")
        cbc_IdentificationCode.set("listID", "ISO3166-1")
        cbc_IdentificationCode.set("listAgencyID", "6")
        cbc_IdentificationCode.text = "MYS"
        
       
        cac_PartyLegalEntity = ET.SubElement(cac_Party, "cac:PartyLegalEntity")
        cbc_RegistrationName = ET.SubElement(cac_PartyLegalEntity, "cbc:RegistrationName")
        cbc_RegistrationName.text = "Chuan Sin Sdn. Bhd."
        
       
        cac_Contact = ET.SubElement(cac_Party, "cac:Contact")
        cbc_Telephone = ET.SubElement(cac_Contact, "cbc:Telephone")
        cbc_Telephone.text = "+969876543210"
        
        cbc_ElectronicMail = ET.SubElement(cac_Contact, "cbc:ElectronicMail")
        cbc_ElectronicMail.text = "xyz@test.com"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating accounting customer party: " + str(e))

def payment_information(invoice):
    try:
        
        cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
        
        cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
        cbc_PaymentMeansCode.text = "01"
        
        cac_PayeeFinancialAccount = ET.SubElement(cac_PaymentMeans, "cac:PayeeFinancialAccount")
        cbc_ID = ET.SubElement(cac_PayeeFinancialAccount, "cbc:ID")
        cbc_ID.text = "L1"
        
        cac_PaymentTerms = ET.SubElement(invoice, "cac:PaymentTerms")
        
        cbc_Note = ET.SubElement(cac_PaymentTerms, "cbc:Note")
        cbc_Note.text = "Cash"
        
        cac_PrepaidPayment = ET.SubElement(invoice, "cac:PrepaidPayment")
        
        cbc_ID = ET.SubElement(cac_PrepaidPayment, "cbc:ID")
        cbc_ID.text = "L1"
        
        cbc_PaidAmount = ET.SubElement(cac_PrepaidPayment, "cbc:PaidAmount")
        cbc_PaidAmount.set("currencyID", "MYR")
        cbc_PaidAmount.text = "1.0"
        
        cbc_PaidDate = ET.SubElement(cac_PrepaidPayment, "cbc:PaidDate")
        cbc_PaidDate.text = "2000-01-01"
        
        cbc_PaidTime = ET.SubElement(cac_PrepaidPayment, "cbc:PaidTime")
        cbc_PaidTime.text = "12:00:00"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating payment information: " + str(e))

def allowance_charge(invoice):
    try:
    
        cac_AllowanceCharge_1 = ET.SubElement(invoice, "cac:AllowanceCharge")
        
        cbc_ChargeIndicator_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:ChargeIndicator")
        cbc_ChargeIndicator_1.text = "false"
        
        cbc_AllowanceChargeReason_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:AllowanceChargeReason")
        cbc_AllowanceChargeReason_1.text = "Sample Description"
        
        cbc_Amount_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:Amount")
        cbc_Amount_1.set("currencyID", "MYR")
        cbc_Amount_1.text = "100"
        
        cac_AllowanceCharge_2 = ET.SubElement(invoice, "cac:AllowanceCharge")
        
        cbc_ChargeIndicator_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:ChargeIndicator")
        cbc_ChargeIndicator_2.text = "true"
        
        cbc_AllowanceChargeReason_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:AllowanceChargeReason")
        cbc_AllowanceChargeReason_2.text = "Sample Description"
        
        cbc_Amount_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:Amount")
        cbc_Amount_2.set("currencyID", "MYR")
        cbc_Amount_2.text = "100"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating allowance charge: " + str(e))


def tax_and_monetary_totals(invoice):
    try:

        cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
        
        cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
        cbc_TaxAmount.set("currencyID", "MYR")
        cbc_TaxAmount.text = "60.00"
        
        cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
        
        cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount")
        cbc_TaxableAmount.set("currencyID", "MYR")
        cbc_TaxableAmount.text = "60.00"
        
        cbc_TaxAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount")
        cbc_TaxAmount.set("currencyID", "MYR")
        cbc_TaxAmount.text = "1000.00"
        
       
        cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
        
        cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
        cbc_ID.text = "01"
        
        
        cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
        
        cbc_TaxScheme_ID = ET.SubElement(cac_TaxScheme, "cbc:ID")
        cbc_TaxScheme_ID.set("schemeID", "UN/ECE 5153")
        cbc_TaxScheme_ID.set("schemeAgencyID", "6")
        cbc_TaxScheme_ID.text = "OTH"
        
        cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
        
        cbc_LineExtensionAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:LineExtensionAmount")
        cbc_LineExtensionAmount.set("currencyID", "MYR")
        cbc_LineExtensionAmount.text = "1436.5"
        
        cbc_TaxExclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount")
        cbc_TaxExclusiveAmount.set("currencyID", "MYR")
        cbc_TaxExclusiveAmount.text = "1436.5"
        
        cbc_TaxInclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount")
        cbc_TaxInclusiveAmount.set("currencyID", "MYR")
        cbc_TaxInclusiveAmount.text = "1436.5"
        
        cbc_AllowanceTotalAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount")
        cbc_AllowanceTotalAmount.set("currencyID", "MYR")
        cbc_AllowanceTotalAmount.text = "1436.5"
        
        cbc_ChargeTotalAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:ChargeTotalAmount")
        cbc_ChargeTotalAmount.set("currencyID", "MYR")
        cbc_ChargeTotalAmount.text = "1436.5"
        
        cbc_PayableRoundingAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableRoundingAmount")
        cbc_PayableRoundingAmount.set("currencyID", "MYR")
        cbc_PayableRoundingAmount.text = "0.30"
        
        cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")
        cbc_PayableAmount.set("currencyID", "MYR")
        cbc_PayableAmount.text = "1436.5"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating tax and monetary totals: " + str(e))



def invoice_line_and_item_data(invoice):
    try:
    
        cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
        
        cbc_ID = ET.SubElement(cac_InvoiceLine, "cbc:ID")
        cbc_ID.text = "1234"
        
        cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity")
        cbc_InvoicedQuantity.set("unitCode", "C62")
        cbc_InvoicedQuantity.text = "1"
        
        cbc_LineExtensionAmount = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount")
        cbc_LineExtensionAmount.set("currencyID", "MYR")
        cbc_LineExtensionAmount.text = "1436.5"
        
        
        cac_AllowanceCharge_1 = ET.SubElement(cac_InvoiceLine, "cac:AllowanceCharge")
        cbc_ChargeIndicator_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:ChargeIndicator")
        cbc_ChargeIndicator_1.text = "false"
        cbc_AllowanceChargeReason_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:AllowanceChargeReason")
        cbc_AllowanceChargeReason_1.text = "Sample Description"
        cbc_MultiplierFactorNumeric_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:MultiplierFactorNumeric")
        cbc_MultiplierFactorNumeric_1.text = "0.15"
        cbc_Amount_1 = ET.SubElement(cac_AllowanceCharge_1, "cbc:Amount")
        cbc_Amount_1.set("currencyID", "MYR")
        cbc_Amount_1.text = "100"
        
        
        cac_AllowanceCharge_2 = ET.SubElement(cac_InvoiceLine, "cac:AllowanceCharge")
        cbc_ChargeIndicator_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:ChargeIndicator")
        cbc_ChargeIndicator_2.text = "true"
        cbc_AllowanceChargeReason_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:AllowanceChargeReason")
        cbc_AllowanceChargeReason_2.text = "Sample Description"
        cbc_MultiplierFactorNumeric_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:MultiplierFactorNumeric")
        cbc_MultiplierFactorNumeric_2.text = "0.10"
        cbc_Amount_2 = ET.SubElement(cac_AllowanceCharge_2, "cbc:Amount")
        cbc_Amount_2.set("currencyID", "MYR")
        cbc_Amount_2.text = "100"
        
        
        cac_TaxTotal = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
        cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
        cbc_TaxAmount.set("currencyID", "MYR")
        cbc_TaxAmount.text = "60.00"
        
        
        cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
        cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount")
        cbc_TaxableAmount.set("currencyID", "MYR")
        cbc_TaxableAmount.text = "1000.00"
        cbc_TaxAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount")
        cbc_TaxAmount.set("currencyID", "MYR")
        cbc_TaxAmount.text = "60.00"
        
       
        cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
        cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
        cbc_ID.text = "01"
        cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
        cbc_Percent.text = "6.00"
        
        
        cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
        cbc_TaxScheme_ID = ET.SubElement(cac_TaxScheme, "cbc:ID")
        cbc_TaxScheme_ID.set("schemeID", "UN/ECE 5153")
        cbc_TaxScheme_ID.set("schemeAgencyID", "6")
        cbc_TaxScheme_ID.text = "OTH"
        
        
        cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
        cbc_Description = ET.SubElement(cac_Item, "cbc:Description")
        cbc_Description.text = "Laptop Peripherals"
        
      
        cac_OriginCountry = ET.SubElement(cac_Item, "cac:OriginCountry")
        cbc_IdentificationCode = ET.SubElement(cac_OriginCountry, "cbc:IdentificationCode")
        cbc_IdentificationCode.text = "MYS"
        
        
        for code, listID in [("038", "PTC"), ("023", "CLASS"), ("011", "CLASS")]:
            cac_CommodityClassification = ET.SubElement(cac_Item, "cac:CommodityClassification")
            cbc_ItemClassificationCode = ET.SubElement(cac_CommodityClassification, "cbc:ItemClassificationCode")
            cbc_ItemClassificationCode.set("listID", listID)
            cbc_ItemClassificationCode.text = code
        
       
        cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
        cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount")
        cbc_PriceAmount.set("currencyID", "MYR")
        cbc_PriceAmount.text = "17"
        
        
        cac_ItemPriceExtension = ET.SubElement(cac_InvoiceLine, "cac:ItemPriceExtension")
        cbc_Amount = ET.SubElement(cac_ItemPriceExtension, "cbc:Amount")
        cbc_Amount.set("currencyID", "MYR")
        cbc_Amount.text = "100"
        
        return invoice
    except Exception as e:
        print("Error occurred in creating invoice line: " + str(e))

def xml_structuring(invoice):
            try:
                xml_declaration = "<?xml version='1.0' encoding='UTF-8'?>\n"
                tree = ET.ElementTree(invoice)
                with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/invoice_with_extensions.xml", 'wb') as file:
                    tree.write(file, encoding='utf-8', xml_declaration=True)
                with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/invoice_with_extensions.xml", 'r') as file:
                    xml_string = file.read()
                xml_dom = minidom.parseString(xml_string)
                pretty_xml_string = xml_dom.toprettyxml(indent="  ")   # created xml into formatted xml form 
                with open("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/finalzatcaxml.xml", 'w') as file:
                    file.write(pretty_xml_string)
                          # Attach the getting xml for each invoice
                
            except Exception as e:
                    print("error in structuring" + str(e))

invoice= create_invoice_with_extensions()
salesinvoice_data(invoice)
invoice_Typecode_and_currency(invoice)
invoice_period(invoice)
create_billing_and_additional_references(invoice)
create_signature(invoice)
company_data(invoice)
customer_data(invoice)
payment_information(invoice)
allowance_charge(invoice)
tax_and_monetary_totals(invoice)
invoice_line_and_item_data(invoice)
xml_structuring(invoice)



# tree = ET.ElementTree(invoice)
# ET.indent(tree, space="  ", level=0)
# tree.write("/opt/malaysia/frappe-bench/apps/myinvois_erpgulf/invoice_with_extensions.xml", encoding="utf-8", xml_declaration=True)
# xml_str = ET.tostring(invoice, encoding="utf-8", method="xml").decode("utf-8")

# print(xml_str)
  