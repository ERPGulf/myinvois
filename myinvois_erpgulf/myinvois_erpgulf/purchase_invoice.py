"""this file is used to generate the xml file for the invoice"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import json
import re
import frappe
import pyqrcode


def get_icv_code(invoice_number):
    """Extracts the numeric part from the invoice number to generate the ICV code"""
    try:
        icv_code = re.sub(
            r"\D", "", invoice_number
        )  # taking the number part only from doc name
        return icv_code
    except TypeError as e:
        frappe.throw("Type error in getting ICV number: " + str(e))
        return None
    except re.error as e:
        frappe.throw("Regex error in getting ICV number: " + str(e))
        return None


def create_invoice_with_extensions():
    """Creates an Invoice element with the necessary extensions"""

    try:
        invoice = ET.Element(
            "Invoice",
            {
                "xmlns": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                "xmlns:cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "xmlns:cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "xmlns:ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
            },
        )
        return invoice
    except (ET.ParseError, TypeError, ValueError) as e:
        frappe.msgprint(f"Error creating invoice extensions: {str(e)}")
        return ET.Element("Error")


def create_element(parent, tag, text=None, attributes=None):
    """Creates an element with the given tag and text, and appends it to the parent element"""
    element = ET.SubElement(parent, tag, attributes or {})
    if text:
        element.text = text
    return element


def get_current_utc_datetime():
    """Returns the current date and time in UTC"""
    current_datetime_utc = datetime.now(timezone.utc)
    formatted_date = current_datetime_utc.strftime("%Y-%m-%d")
    formatted_time = current_datetime_utc.strftime("%H:%M:%SZ")
    return formatted_date, formatted_time


def add_billing_reference(invoice, invoice_number, sales_invoice_doc):
    """Adds BillingReference with InvoiceDocumentReference to the invoice"""
    try:
        billing_reference = create_element(invoice, "cac:BillingReference")
        invoice_document_reference = create_element(
            billing_reference, "cac:InvoiceDocumentReference"
        )
        if sales_invoice_doc.custom_invoicetype_code in [
            "12 : Self-billed Credit Note",
            "13 : Self-billed Debit Note",
            "14 : Self-billed Refund Note",
        ]:
            invoice_id = sales_invoice_doc.return_against
        else:

            invoice_id = get_icv_code(invoice_number)

        create_element(invoice_document_reference, "cbc:ID", invoice_id)
        if sales_invoice_doc.custom_invoicetype_code in [
            "12 : Self-billed Credit Note",
            "13 : Self-billed Debit Note",
            "14 : Self-billed Refund Note",
        ]:
            doc_id = sales_invoice_doc.return_against
            if not doc_id:
                frappe.throw("No document found in return_against.")

            # Fetch the full document using Frappe's API
            doc = frappe.get_doc("Purchase Invoice", doc_id)

            # Check if `custom_submit_response` exists and is valid
            if hasattr(doc, "custom_submit_response") and doc.custom_submit_response:
                try:
                    # Parse the JSON data
                    custom_submit_response = json.loads(doc.custom_submit_response)

                    # Extract the `uuid` from `acceptedDocuments`
                    accepted_documents = custom_submit_response.get(
                        "acceptedDocuments", []
                    )
                    if accepted_documents:
                        uuid = accepted_documents[0].get("uuid")
                        create_element(invoice_document_reference, "cbc:UUID", uuid)
                    else:
                        frappe.throw(
                            "No accepted documents found in custom_submit_response."
                        )
                except json.JSONDecodeError:
                    frappe.throw("Invalid JSON format in custom_submit_response.")
            else:
                frappe.throw("custom_submit_response is missing or empty.")
    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.msgprint(f"Error in add billing reference: {str(e)}")
        return None

        # Use the `uuid` to create the element


def add_additional_document_reference(invoice, document_references):
    """
    Adds multiple AdditionalDocumentReference elements to the given invoice.
    """
    try:
        for ref in document_references:
            additional_doc_reference = create_element(
                invoice, "cac:AdditionalDocumentReference"
            )
            create_element(additional_doc_reference, "cbc:ID", ref.get("ID", ""))
            if "DocumentType" in ref:
                create_element(
                    additional_doc_reference, "cbc:DocumentType", ref["DocumentType"]
                )
            if "DocumentDescription" in ref:
                create_element(
                    additional_doc_reference,
                    "cbc:DocumentDescription",
                    ref["DocumentDescription"],
                )
    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.msgprint(f"Error add aditional daata: {str(e)}")
        return None


def add_signature(invoice):
    """Adds Signature to the invoice"""
    try:
        signature = create_element(invoice, "cac:Signature")
        create_element(
            signature, "cbc:ID", "urn:oasis:names:specification:ubl:signature:Invoice"
        )
        create_element(
            signature,
            "cbc:SignatureMethod",
            "urn:oasis:names:specification:ubl:dsig:enveloped:xades",
        )
    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.msgprint(f"Error signature data: {str(e)}")
        return None


def salesinvoice_data(invoice, sales_invoice_doc):
    """Adds the Purchase Invoice data to the invoice"""
    try:
        create_element(invoice, "cbc:ID", str(sales_invoice_doc.name))

        formatted_date, formatted_time = get_current_utc_datetime()
        create_element(invoice, "cbc:IssueDate", formatted_date)
        create_element(invoice, "cbc:IssueTime", formatted_time)
        if not sales_invoice_doc.custom_invoicetype_code:
            frappe.throw("Custom Invoice Type Code is missing! ")

        if sales_invoice_doc.is_return == 1:
            # Check if the field is already set to "02 : Credit Note"
            if sales_invoice_doc.custom_invoicetype_code not in [
                "02 : Credit Note",
                "04 :  Refund Note",
            ]:
                frappe.throw(
                    "Choose the invoice type code as '02 : Credit Note' and"
                    " '04 :  Refund Note'"
                )
        if sales_invoice_doc.is_debit_note == 1:
            # Check if the field is already set to "03 : Debit Note"
            if sales_invoice_doc.custom_invoicetype_code != "03 :  Debit Note":
                frappe.throw("Choose the invoice type code as '03 : Debit Note'")
        raw_invoice_type_code = sales_invoice_doc.custom_invoicetype_code

        invoice_type_code = raw_invoice_type_code.split(":")[0].strip()
        settings = frappe.get_doc("LHDN Malaysia Setting")
        if settings.certificate_file and settings.version == "1.1":
            create_element(
                invoice,
                "cbc:InvoiceTypeCode",
                invoice_type_code,
                {"listVersionID": "1.1"},
            )
        else:
            create_element(
                invoice,
                "cbc:InvoiceTypeCode",
                invoice_type_code,
                {"listVersionID": "1.0"},
            )

        create_element(
            invoice, "cbc:DocumentCurrencyCode", "MYR"
        )  # or sales_invoice_doc.currency
        create_element(invoice, "cbc:TaxCurrencyCode", "MYR")

        inv_period = create_element(invoice, "cac:InvoicePeriod")
        create_element(inv_period, "cbc:StartDate", str(sales_invoice_doc.posting_date))
        create_element(inv_period, "cbc:EndDate", str(sales_invoice_doc.due_date))
        create_element(inv_period, "cbc:Description", "Monthly")
        # if sales_invoice_doc.custom_invoicetype_code != "02 : Credit Note":
        invoice_number = sales_invoice_doc.name
        add_billing_reference(invoice, invoice_number, sales_invoice_doc)
        # add_signature(invoice)
        return invoice

    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.msgprint(f"Error Purchase Invoice data: {str(e)}")
        return None


def company_data(invoice, sales_invoice_doc):
    """Adds the Company data to the invoice"""
    try:
        company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
        account_supplier_party = ET.SubElement(invoice, "cac:AccountingSupplierParty")
        party_ = ET.SubElement(account_supplier_party, "cac:Party")

        # Extract MSIC code and name
        msic_code_full = (
            company_doc.custom_msic_code_
        )  # e.g., "01111: Growing of maize"
        if ":" in msic_code_full:
            msic_code_code, msic_code_name = [
                s.strip() for s in msic_code_full.split(":", 1)
            ]
        else:
            msic_code_code, msic_code_name = msic_code_full.strip(), ""

        # Create the cbc:IndustryClassificationCode element
        cbc_indclacode = ET.SubElement(
            party_, "cbc:IndustryClassificationCode", name=msic_code_name
        )
        cbc_indclacode.text = msic_code_code

        # Company Identifications
        identifiers = [
            ("TIN", company_doc.custom_company_tin_number),
            (
                company_doc.custom_company_registrationicpassport_type,
                company_doc.custom_company__registrationicpassport_number,
            ),
            ("SST", getattr(company_doc, "custom_sst_number", "NA") or "NA"),
            ("TTX", getattr(company_doc, "custom_tourism_tax_number", "NA") or "NA"),
        ]

        for scheme_id, value in identifiers:
            party_id = ET.SubElement(party_, "cac:PartyIdentification")
            id_element = ET.SubElement(party_id, "cbc:ID", schemeID=scheme_id)
            id_element.text = str(value) if value else "NA"

        # Retrieve the first valid company address
        address_list = frappe.get_list(
            "Address",
            filters={"is_your_company_address": "1"},
            fields=[
                "address_line1",
                "address_line2",
                "city",
                "pincode",
                "state",
                "custom_state_code",
                "phone",
                "email_id",
            ],
            order_by="creation asc",  # Ensures a consistent selection
        )

        if not address_list:
            frappe.throw(
                "Invoice requires a proper address. Please add your company address in the Address field."
            )

        address = address_list[0]  # Select the first address only

        # Create PostalAddress Element
        post_add = ET.SubElement(party_, "cac:PostalAddress")
        ET.SubElement(post_add, "cbc:CityName").text = address.city
        ET.SubElement(post_add, "cbc:PostalZone").text = address.pincode
        ET.SubElement(post_add, "cbc:CountrySubentityCode").text = (
            address.custom_state_code
        ).split(":")[0]

        # Address lines
        if address.address_line1:
            add_line1 = ET.SubElement(post_add, "cac:AddressLine")
            ET.SubElement(add_line1, "cbc:Line").text = address.address_line1

        if address.address_line2:
            add_line2 = ET.SubElement(post_add, "cac:AddressLine")
            ET.SubElement(add_line2, "cbc:Line").text = address.address_line2

        # Combined city and postal code
        combined_city_pincode = f"{address.city}, {address.pincode}"
        add_line3 = ET.SubElement(post_add, "cac:AddressLine")
        ET.SubElement(add_line3, "cbc:Line").text = combined_city_pincode

        # Country
        cntry = ET.SubElement(post_add, "cac:Country")
        idntfn_cod = ET.SubElement(
            cntry,
            "cbc:IdentificationCode",
            listAgencyID="6",
            listID="ISO3166-1",
        )
        idntfn_cod.text = "MYS"

        # PartyLegalEntity
        party_legal_entity = ET.SubElement(party_, "cac:PartyLegalEntity")
        ET.SubElement(party_legal_entity, "cbc:RegistrationName").text = (
            sales_invoice_doc.company
        )

        # Contact Information
        cont_ct = ET.SubElement(party_, "cac:Contact")
        if address.get("phone"):
            ET.SubElement(cont_ct, "cbc:Telephone").text = address.phone
        if address.get("email_id"):
            ET.SubElement(cont_ct, "cbc:ElectronicMail").text = address.email_id

        return invoice

    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.throw(f"Error in company data generation: {str(e)}")
        return None


# def company_data(invoice, sales_invoice_doc):
#     """Adds the Company data to the invoice"""
#     try:

#         company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
#         account_supplier_party = ET.SubElement(invoice, "cac:AccountingSupplierParty")
#         party_ = ET.SubElement(account_supplier_party, "cac:Party")
#         # additional_account_id = ET.SubElement(party_, "cbc:AdditionalAccountID", schemeAgencyName="CertEX")
#         # additional_account_id.text = "CPT-CCN-W-211111-KL-000002"
#         msic_code_full = (
#             company_doc.custom_msic_code_
#         )  # e.g., "01111: Growing of maize"
#         if ":" in msic_code_full:
#             msic_code_code = msic_code_full.split(":")[
#                 0
#             ].strip()  # Extract the part before the colon (code)
#             msic_code_name = msic_code_full.split(":")[
#                 1
#             ].strip()  # Extract the part after the colon (name)
#         else:
#             msic_code_code = (
#                 msic_code_full.strip()
#             )  # Use the full value if no colon is present
#             msic_code_name = ""  # No name available

#         # Create the cbc:IndustryClassificationCode element with the name attribute and code text
#         cbc_indclacode = ET.SubElement(
#             party_, "cbc:IndustryClassificationCode", name=msic_code_name
#         )
#         cbc_indclacode.text = msic_code_code

#         # cbc_indclacode = ET.SubElement(party_, "cbc:IndustryClassificationCode", name=str(company_doc.custom_business_activities))
#         # cbc_indclacode.text = company_doc.custom_msic_code_            #"62099"
#         party_identification_1 = ET.SubElement(party_, "cac:PartyIdentification")
#         id_val_1 = ET.SubElement(party_identification_1, "cbc:ID", schemeID="TIN")
#         id_val_1.text = str(company_doc.custom_company_tin_number)

#         partyid_2 = ET.SubElement(party_, "cac:PartyIdentification")
#         value_id = ET.SubElement(
#             partyid_2,
#             "cbc:ID",
#             schemeID=str(company_doc.custom_company_registrationicpassport_type),
#         )
#         value_id.text = str(company_doc.custom_company__registrationicpassport_number)

#         partyid_3 = ET.SubElement(party_, "cac:PartyIdentification")
#         value_id3 = ET.SubElement(partyid_3, "cbc:ID", schemeID="SST")
#         company_doc.custom_sst_number = (
#             getattr(company_doc, "custom_sst_number", "NA") or "NA"
#         )

#         value_id3.text = (
#             str(company_doc.custom_sst_number)
#             if str(company_doc.custom_sst_number)
#             else "NA"
#         )

#         partyid_4 = ET.SubElement(party_, "cac:PartyIdentification")
#         value_id4 = ET.SubElement(partyid_4, "cbc:ID", schemeID="TTX")
#         value_id4.text = (
#             str(company_doc.custom_tourism_tax_number)
#             if str(company_doc.custom_tourism_tax_number)
#             else "NA"
#         )

#         address_list = frappe.get_list(
#             "Address",
#             filters={"is_your_company_address": "1"},
#             fields=[
#                 "address_line1",
#                 "address_line2",
#                 "city",
#                 "pincode",
#                 "state",
#                 "custom_state_code",
#                 "phone",
#                 "email_id",
#             ],
#         )

#         if len(address_list) == 0:
#             frappe.throw(
#                 "Invoice requires a proper address. Please add your company address in the Address field."
#             )

#         for address in address_list:

#             post_add = ET.SubElement(party_, "cac:PostalAddress")
#             city_name = ET.SubElement(post_add, "cbc:CityName")
#             city_name.text = address.city

#             postal_zone = ET.SubElement(post_add, "cbc:PostalZone")
#             postal_zone.text = address.pincode

#             cntry_subentity_cod = ET.SubElement(post_add, "cbc:CountrySubentityCode")
#             statecode = (address.custom_state_code).split(":")[0]
#             cntry_subentity_cod.text = statecode

#             if address.address_line1:
#                 add_line1 = ET.SubElement(post_add, "cac:AddressLine")
#                 line_val = ET.SubElement(add_line1, "cbc:Line")
#                 line_val.text = address.address_line1

#             if address.address_line2:
#                 add_line2 = ET.SubElement(post_add, "cac:AddressLine")
#                 line2_val = ET.SubElement(add_line2, "cbc:Line")
#                 line2_val.text = address.address_line2

#             combined_city_pincode = f"{address.city}, {address.pincode}"
#             add_line3 = ET.SubElement(post_add, "cac:AddressLine")
#             line_3_val = ET.SubElement(add_line3, "cbc:Line")
#             line_3_val.text = combined_city_pincode

#             cntry = ET.SubElement(post_add, "cac:Country")
#             idntfn_cod = ET.SubElement(
#                 cntry,
#                 "cbc:IdentificationCode",
#                 listAgencyID="6",
#                 listID="ISO3166-1",
#             )
#             idntfn_cod.text = "MYS"

#         party_legal_entity = ET.SubElement(party_, "cac:PartyLegalEntity")
#         reg_name = ET.SubElement(party_legal_entity, "cbc:RegistrationName")
#         reg_name.text = sales_invoice_doc.company

#         cont_ct = ET.SubElement(party_, "cac:Contact")

#         if address.get("phone"):
#             tele = ET.SubElement(cont_ct, "cbc:Telephone")
#             tele.text = address.phone

#         if address.get("email_id"):
#             mail = ET.SubElement(cont_ct, "cbc:ElectronicMail")
#             mail.text = address.email_id

#         return invoice

#     except (
#         frappe.DoesNotExistError,
#         frappe.ValidationError,
#         AttributeError,
#         KeyError,
#     ) as e:
#         frappe.throw(f"Error in company data generation: {str(e)}")
#         return None


def customer_data(invoice, sales_invoice_doc):
    """Adds the Customer data to the invoice"""
    try:

        customer_doc = frappe.get_doc("Supplier", sales_invoice_doc.supplier)
        accounting_customer_party = ET.SubElement(
            invoice, "cac:AccountingCustomerParty"
        )
        cac_Party = ET.SubElement(accounting_customer_party, "cac:Party")

        party_id_1 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        prty_id = ET.SubElement(party_id_1, "cbc:ID", schemeID="TIN")
        prty_id.text = str(customer_doc.custom_customer_tin_number)

        party_identifn_2 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        id_party2 = ET.SubElement(
            party_identifn_2,
            "cbc:ID",
            schemeID=str(customer_doc.custom_customer__registrationicpassport_type),
        )
        id_party2.text = str(
            customer_doc.custom_customer_registrationicpassport_number
        )  # Buyer’s Registration / Identification Number / Passport Number

        partyid_3 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        value_id3 = ET.SubElement(partyid_3, "cbc:ID", schemeID="SST")
        customer_doc.custom_sst_number = (
            getattr(customer_doc, "custom_sst_number", "NA") or "NA"
        )

        value_id3.text = (
            str(customer_doc.custom_sst_number)
            if str(customer_doc.custom_sst_number)
            else "NA"
        )

        partyid_4 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        value_id4 = ET.SubElement(partyid_4, "cbc:ID", schemeID="TTX")
        value_id4.text = (
            str(customer_doc.custom_tourism_tax_number)
            if str(customer_doc.custom_tourism_tax_number)
            else "NA"
        )

        if int(frappe.__version__.split(".")[0]) == 13:
            address = frappe.get_doc("Address", sales_invoice_doc.customer_address)
        else:
            address = frappe.get_doc("Address", customer_doc.customer_primary_address)
        posta_address = ET.SubElement(cac_Party, "cac:PostalAddress")
        name_city = ET.SubElement(posta_address, "cbc:CityName")
        name_city.text = address.city
        post_zone = ET.SubElement(posta_address, "cbc:PostalZone")
        post_zone.text = address.pincode
        cntry_sub_cod = ET.SubElement(posta_address, "cbc:CountrySubentityCode")
        statecode = (address.custom_state_code).split(":")[0]
        cntry_sub_cod.text = statecode

        add_cust_line1 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line1 = ET.SubElement(add_cust_line1, "cbc:Line")
        add_line1.text = address.address_line1

        add_cust_line2 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line2 = ET.SubElement(add_cust_line2, "cbc:Line")
        add_line2.text = address.address_line2

        combined_city_pincode = f"{address.city}, {address.pincode}"
        add_cust_line3 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line3 = ET.SubElement(add_cust_line3, "cbc:Line")
        add_line3.text = combined_city_pincode

        cnty_customer = ET.SubElement(posta_address, "cac:Country")
        idntfn_code_val = ET.SubElement(
            cnty_customer,
            "cbc:IdentificationCode",
            listAgencyID="6",
            listID="ISO3166-1",
        )
        idntfn_code_val.text = "MYS"

        party_legalEntity = ET.SubElement(cac_Party, "cac:PartyLegalEntity")
        reg_name_val = ET.SubElement(party_legalEntity, "cbc:RegistrationName")
        reg_name_val.text = sales_invoice_doc.customer

        cont_customer = ET.SubElement(cac_Party, "cac:Contact")
        tele_party = ET.SubElement(cont_customer, "cbc:Telephone")
        tele_party.text = str(address.phone)

        mail_party = ET.SubElement(cont_customer, "cbc:ElectronicMail")
        mail_party.text = str(address.email_id)
        return invoice
    except Exception as e:
        frappe.throw(f"Error customer data: {str(e)}")
        return None


def delivery_data(invoice, sales_invoice_doc):
    "" "Adds the Delivery data to the invoice" ""
    try:
        customer_doc = frappe.get_doc("Supplier", sales_invoice_doc.supplier)

        delivery = ET.SubElement(invoice, "cac:Delivery")
        delivery_party = ET.SubElement(delivery, "cac:DeliveryParty")

        party_id_tin = ET.SubElement(delivery_party, "cac:PartyIdentification")
        tin_id = ET.SubElement(party_id_tin, "cbc:ID", schemeID="TIN")
        tin_id.text = str(customer_doc.custom_customer_tin_number)

        party_id_brn = ET.SubElement(delivery_party, "cac:PartyIdentification")
        brn_id = ET.SubElement(
            party_id_brn,
            "cbc:ID",
            schemeID=str(customer_doc.custom_customer__registrationicpassport_type),
        )
        brn_id.text = str(customer_doc.custom_customer_registrationicpassport_number)

        if int(frappe.__version__.split(".")[0]) == 13:
            address = frappe.get_doc("Address", sales_invoice_doc.customer_address)
        else:
            address = frappe.get_doc("Address", customer_doc.customer_primary_address)

        postal_address = ET.SubElement(delivery_party, "cac:PostalAddress")
        city_name = ET.SubElement(postal_address, "cbc:CityName")
        city_name.text = address.city

        postal_zone = ET.SubElement(postal_address, "cbc:PostalZone")

        postal_zone.text = str(address.custom_state_code).split(":", 1)[1].strip()

        country_subentity_code = ET.SubElement(
            postal_address, "cbc:CountrySubentityCode"
        )
        statecode = (address.custom_state_code).split(":")[0]
        country_subentity_code.text = statecode

        address_line1 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        address_line1.text = address.address_line1

        address_line2 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        address_line2.text = address.address_line2

        combined_city_pincode = f"{address.city}, {address.pincode}"
        address_line3 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        address_line3.text = combined_city_pincode

        country = ET.SubElement(postal_address, "cac:Country")
        country_id_code = ET.SubElement(
            country,
            "cbc:IdentificationCode",
            listAgencyID="6",
            listID="ISO3166-1",
        )
        country_id_code.text = "MYS"

        party_legal_entity = ET.SubElement(delivery_party, "cac:PartyLegalEntity")
        registration_name = ET.SubElement(party_legal_entity, "cbc:RegistrationName")
        registration_name.text = sales_invoice_doc.customer
        return invoice
    except Exception as e:
        frappe.throw(f"Error in customer_data: {str(e)}")
        return None


def payment_data(invoice, sales_invoice_doc):
    """Adds PaymentMeans, PaymentTerms, and PrepaidPayment to the invoice based on the payment mode"""
    try:
        payment_mode_code_map = {
            "Cash": "01",
            "Cheque": "02",
            "Bank Transfer": "03",
            "Credit Card": "04",
            "Debit Card": "05",
            "E-wallet": "06",
        }

        payment_mode = sales_invoice_doc.custom_payment_mode
        payment_means_code = payment_mode_code_map.get(payment_mode, "01")

        payment_means = ET.SubElement(invoice, "cac:PaymentMeans")
        payment_means_code_element = ET.SubElement(
            payment_means, "cbc:PaymentMeansCode"
        )
        payment_means_code_element.text = payment_means_code

        payee_financial_account = ET.SubElement(
            payment_means, "cac:PayeeFinancialAccount"
        )
        payee_id = ET.SubElement(payee_financial_account, "cbc:ID")
        payee_id.text = "1234567890"

        payment_terms = ET.SubElement(invoice, "cac:PaymentTerms")
        payment_note = ET.SubElement(payment_terms, "cbc:Note")
        payment_note.text = f"Payment method is {payment_mode}"

        # prepaid_payment = ET.SubElement(invoice, "cac:PrepaidPayment")
        # prepaid_id = ET.SubElement(prepaid_payment, "cbc:ID")
        # prepaid_id.text = "E12345678912"

        # paid_amount = ET.SubElement(prepaid_payment, "cbc:PaidAmount", currencyID="MYR")
        # paid_amount.text = "1.00"

        # paid_date = ET.SubElement(prepaid_payment, "cbc:PaidDate")
        # paid_date.text = "2024-07-23"

        # paid_time = ET.SubElement(prepaid_payment, "cbc:PaidTime")
        # paid_time.text = "00:30:00Z"
        return invoice
    except Exception as e:
        frappe.throw(f"Error adding payment data: {str(e)}")
        return None


def allowance_charge_data(invoice, sales_invoice_doc):
    """Adds AllowanceCharge elements to the invoice"""
    try:
        for single_item in sales_invoice_doc.items:
            discount_amount = abs(single_item.get("discount_amount", 0.0))
            if discount_amount > 0:
                allowance_charge_1 = ET.SubElement(invoice, "cac:AllowanceCharge")
                charge_indicator_1 = ET.SubElement(
                    allowance_charge_1, "cbc:ChargeIndicator"
                )
                charge_indicator_1.text = "false"

                allowance_charge_reason_1 = ET.SubElement(
                    allowance_charge_1, "cbc:AllowanceChargeReason"
                )
                allowance_charge_reason_1.text = "Promotional Discount"

                amount_1 = ET.SubElement(
                    allowance_charge_1, "cbc:Amount", currencyID="MYR"
                )
                amount_1.text = str(discount_amount)

                # Second AllowanceCharge with ChargeIndicator = true only use when there shipping like charge
                # allowance_charge_2 = ET.SubElement(invoice, "cac:AllowanceCharge")
                # charge_indicator_2 = ET.SubElement(allowance_charge_2, "cbc:ChargeIndicator")
                # charge_indicator_2.text = "true"

                # allowance_charge_reason_2 = ET.SubElement(allowance_charge_2, "cbc:AllowanceChargeReason")
                # allowance_charge_reason_2.text = "Service charge"

                # amount_2 = ET.SubElement(allowance_charge_2, "cbc:Amount", currencyID="MYR")
                # amount_2.text = "100"
            return invoice
    except Exception as e:
        frappe.throw(f"Error adding allowance charge data: {str(e)}")
        return None


def tax_total(invoice, sales_invoice_doc):
    """Adds TaxTotal, TaxSubtotal, TaxCategory, and TaxScheme elements to the invoice"""
    try:
        taxable_amount = sales_invoice_doc.base_total - sales_invoice_doc.get(
            "base_discount_amount", 0.0
        )
        cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
        taxamnt = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
        tax_amount_without_retention = (
            taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100
        )
        taxamnt.text = f"{abs(round(tax_amount_without_retention, 2)):.2f}"

        cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
        taxable_amnt = ET.SubElement(
            cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR"
        )
        taxable_amnt.text = str(abs(round(taxable_amount, 2)))
        TaxAmnt = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR")
        TaxAmnt.text = str(
            abs(round(taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100, 2))
        )

        cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
        raw_item_id_code = sales_invoice_doc.custom_zatca_tax_category
        cat_id_val = ET.SubElement(cac_TaxCategory, "cbc:ID")
        # cat_id_val.text = str(sales_invoice_doc.custom_zatca_tax_category)
        cat_id_val.text = raw_item_id_code.split(":")[0].strip()
        # <cbc:Percent>0.00</cbc:Percent><cbc:TaxExemptionReason>NA</cbc:TaxExemptionReason>
        prct = ET.SubElement(cac_TaxCategory, "cbc:Percent")
        prct.text = str(sales_invoice_doc.taxes[0].rate)
        exemption = ET.SubElement(cac_TaxCategory, "cbc:TaxExemptionReason")
        if (sales_invoice_doc.custom_zatca_tax_category) == "E":
            exemption.text = sales_invoice_doc.custom_exemption_code
        else:
            exemption.text = "NA"

        cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
        taxscheme_id = ET.SubElement(
            cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153"
        )
        taxscheme_id.text = "OTH"
        return invoice
    except Exception as e:
        frappe.throw(f"Error tax total: {str(e)}")
        return None


def tax_total_with_template(invoice, sales_invoice_doc):
    """Adds TaxTotal, TaxSubtotal, TaxCategory, and TaxScheme elements to the invoice"""
    try:
        tax_category_totals = {}

        for item in sales_invoice_doc.items:
            item_tax_template = frappe.get_doc(
                "Item Tax Template", item.item_tax_template
            )
            zatca_tax_category = item_tax_template.custom_zatca_tax_category

            if zatca_tax_category not in tax_category_totals:
                tax_category_totals[zatca_tax_category] = {
                    "taxable_amount": 0,
                    "tax_amount": 0,
                    "tax_rate": (
                        item_tax_template.taxes[0].tax_rate
                        if item_tax_template.taxes
                        else 0
                    ),
                    "exemption_reason_code": item_tax_template.custom_exemption_reason_code,
                }

            if sales_invoice_doc.currency == "SAR":
                tax_category_totals[zatca_tax_category]["taxable_amount"] += abs(
                    item.base_amount
                )
            else:
                tax_category_totals[zatca_tax_category]["taxable_amount"] += abs(
                    item.amount
                )

        first_tax_category = next(iter(tax_category_totals))
        base_discount_amount = sales_invoice_doc.get("discount_amount", 0.0)
        tax_category_totals[first_tax_category][
            "taxable_amount"
        ] -= base_discount_amount

        for zatca_tax_category in tax_category_totals:
            taxable_amount = tax_category_totals[zatca_tax_category]["taxable_amount"]
            tax_rate = tax_category_totals[zatca_tax_category]["tax_rate"]
            tax_category_totals[zatca_tax_category]["tax_amount"] = abs(
                round(taxable_amount * tax_rate / 100, 2)
            )

        total_tax = sum(totals["tax_amount"] for totals in tax_category_totals.values())
        tax_amount_without_retention_sar = round(abs(total_tax), 2)

        cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
        cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
        cbc_TaxAmount.text = str(tax_amount_without_retention_sar)

        for zatca_tax_category, totals in tax_category_totals.items():
            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            cbc_TaxableAmount = ET.SubElement(
                cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR"
            )
            cbc_TaxableAmount.text = str(round(totals["taxable_amount"], 2))

            cbc_TaxAmount = ET.SubElement(
                cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR"
            )
            cbc_TaxAmount.text = str(round(totals["tax_amount"], 2))

            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cbc_ID.text = zatca_tax_category

            cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            cbc_Percent.text = f"{totals['tax_rate']:.2f}"

            cbc_TaxExemptionReason = ET.SubElement(
                cac_TaxCategory, "cbc:TaxExemptionReason"
            )
            if zatca_tax_category == "E":
                cbc_TaxExemptionReason.text = (
                    item_tax_template.custom_exemption_reason_code
                )
            else:
                cbc_TaxExemptionReason.text = "NA"

            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            cbc_TaxScheme_ID = ET.SubElement(
                cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153"
            )
            cbc_TaxScheme_ID.text = "OTH"
        return invoice
    except Exception as e:
        frappe.throw(f"Error in tax total calculation: {str(e)}")
        return None


def legal_monetary_total(invoice, sales_invoice_doc):
    """Adds LegalMonetaryTotal elements to the invoice"""
    try:

        taxable_amount_1 = sales_invoice_doc.total - sales_invoice_doc.get(
            "discount_amount", 0.0
        )
        tax_amount_without_retention = (
            taxable_amount_1 * (sales_invoice_doc.taxes[0].rate) / 100
        )
        legal_monetary_total = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
        line_ext_amnt = ET.SubElement(
            legal_monetary_total, "cbc:LineExtensionAmount", currencyID="MYR"
        )
        line_ext_amnt.text = str(abs(sales_invoice_doc.total))
        tax_exc_ = ET.SubElement(
            legal_monetary_total, "cbc:TaxExclusiveAmount", currencyID="MYR"
        )
        tax_exc_.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
        )
        tax_inc = ET.SubElement(
            legal_monetary_total, "cbc:TaxInclusiveAmount", currencyID="MYR"
        )
        tax_inc.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
            + abs(round(tax_amount_without_retention, 2))
        )
        allw_tot = ET.SubElement(
            legal_monetary_total, "cbc:AllowanceTotalAmount", currencyID="MYR"
        )
        allw_tot.text = str(abs(sales_invoice_doc.get("discount_amount", 0.0)))
        # <cbc:ChargeTotalAmount currencyID="MYR">1436.50</cbc:ChargeTotalAmount>
        payable_ = ET.SubElement(
            legal_monetary_total, "cbc:PayableAmount", currencyID="MYR"
        )
        payable_.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
            + abs(round(tax_amount_without_retention, 2))
        )
        return invoice
    except Exception as e:
        frappe.throw(f"Error legal monetary: {str(e)}")
        return None


def get_Tax_for_Item(full_string, item):
    """Get tax amount and tax percentage for the given item"""
    try:
        data = json.loads(full_string)
        tax_percentage = data.get(item, [0, 0])[0]
        tax_amount = data.get(item, [0, 0])[1]
        return tax_amount, tax_percentage
    except Exception as e:
        frappe.throw("error occured in tax for item" + str(e))


def invoice_line_item(invoice, sales_invoice_doc):
    """Adds InvoiceLine elements to the invoice"""
    try:
        # frappe.msgprint("Entering invoice_line_item function")
        for single_item in sales_invoice_doc.items:
            # frappe.msgprint(f"Processing item: {single_item.item_code}")

            invoice_line = ET.SubElement(invoice, "cac:InvoiceLine")
            # frappe.msgprint(f"Created InvoiceLine element: {invoice_line}")

            item_id = ET.SubElement(invoice_line, "cbc:ID")
            item_id.text = str(single_item.idx)
            # frappe.msgprint(f"Set item ID: {item_id.text}")

            item_qty = ET.SubElement(
                invoice_line,
                "cbc:InvoicedQuantity",
                unitCode="H87",
            )
            item_qty.text = str(abs(single_item.qty))
            # frappe.msgprint(f"Set item quantity: {item_qty.text}")

            item_line_exte_amnt = ET.SubElement(
                invoice_line, "cbc:LineExtensionAmount", currencyID="MYR"
            )
            item_line_exte_amnt.text = str(abs(single_item.amount))
            # frappe.msgprint(f"Set LineExtensionAmount: {item_line_exte_amnt.text}")

            discount_amount = abs(single_item.get("discount_amount", 0.0))
            # frappe.msgprint(f"Discount amount: {discount_amount}")

            if discount_amount > 0:
                # frappe.msgprint("Adding discount elements")
                allw_chrge = ET.SubElement(invoice_line, "cac:AllowanceCharge")
                chrg_indic = ET.SubElement(allw_chrge, "cbc:ChargeIndicator")
                chrg_indic.text = "false"
                allwa_chrge_reson = ET.SubElement(
                    allw_chrge, "cbc:AllowanceChargeReason"
                )
                allwa_chrge_reson.text = "Item Discount"
                multi_fac = ET.SubElement(allw_chrge, "cbc:MultiplierFactorNumeric")
                multi_fac.text = "1"
                amnt = ET.SubElement(allw_chrge, "cbc:Amount", currencyID="MYR")
                amnt.text = str(discount_amount)
                # frappe.msgprint(
                #     f"Added discount elements for item: {single_item.item_code}"
                # # )

            tax_total_item = ET.SubElement(invoice_line, "cac:TaxTotal")
            tax_amount_item = ET.SubElement(
                tax_total_item, "cbc:TaxAmount", currencyID="MYR"
            )
            tax_amount_item.text = str(
                abs(
                    round(
                        (sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2
                    )
                )
            )
            # frappe.msgprint(f"Set tax amount: {tax_amount_item.text}")

            tax_subtot_item = ET.SubElement(tax_total_item, "cac:TaxSubtotal")
            taxable_amnt_item = ET.SubElement(
                tax_subtot_item, "cbc:TaxableAmount", currencyID="MYR"
            )
            taxable_amnt_item.text = str(abs(single_item.amount - discount_amount))
            tax_amnt = ET.SubElement(tax_subtot_item, "cbc:TaxAmount", currencyID="MYR")
            tax_amnt.text = str(
                abs(
                    round(
                        (sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2
                    )
                )
            )
            # frappe.msgprint(
            # f"Set tax subtotal: TaxableAmount={taxable_amnt_item.text}, TaxAmount={tax_amnt.text}"
            # )

            tax_cate_item = ET.SubElement(tax_subtot_item, "cac:TaxCategory")
            cat_item_id = ET.SubElement(tax_cate_item, "cbc:ID")
            raw_invoice_type_code = sales_invoice_doc.custom_zatca_tax_category

            cat_item_id.text = raw_invoice_type_code.split(":")[0].strip()
            # cat_item_id.text = str(sales_invoice_doc.custom_zatca_tax_category)
            item_prct = ET.SubElement(tax_cate_item, "cbc:Percent")
            item_prct.text = str(sales_invoice_doc.taxes[0].rate)
            # frappe.msgprint(
            #     f"Set tax category: ID={cat_item_id.text}, Percent={item_prct.text}"
            # # )

            tax_scheme_item = ET.SubElement(tax_cate_item, "cac:TaxScheme")
            tax_id_scheme_item = ET.SubElement(
                tax_scheme_item, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153"
            )
            tax_id_scheme_item.text = "OTH"

            item_data = ET.SubElement(invoice_line, "cac:Item")
            descp_item = ET.SubElement(item_data, "cbc:Description")
            descp_item.text = str(single_item.description)
            # frappe.msgprint(f"Set item description: {descp_item.text}")

            comm_class_cod = ET.SubElement(item_data, "cac:CommodityClassification")
            item_class_cod = ET.SubElement(
                comm_class_cod, "cbc:ItemClassificationCode", listID="CLASS"
            )
            item_doc = frappe.get_doc("Item", single_item.item_code)
            classification_code = str(item_doc.custom_item_classification_code).split(
                ":"
            )[0]
            item_class_cod.text = classification_code
            # frappe.msgprint(f"Set classification code: {item_class_cod.text}")

            price_item = ET.SubElement(invoice_line, "cac:Price")
            pri_amnt_item = ET.SubElement(
                price_item, "cbc:PriceAmount", currencyID="MYR"
            )
            pri_amnt_item.text = str(
                abs(single_item.base_price_list_rate) - discount_amount
            )
            # frappe.msgprint(f"Set price amount: {pri_amnt_item.text}")

            item_pri_ext = ET.SubElement(invoice_line, "cac:ItemPriceExtension")
            item_val_amnt = ET.SubElement(item_pri_ext, "cbc:Amount", currencyID="MYR")
            item_val_amnt.text = str(abs(single_item.base_amount))
            # frappe.msgprint(f"Set item price extension: {item_val_amnt.text}")

        # frappe.msgprint("Completed processing all items")
        return invoice
    except Exception as e:
        frappe.throw(f"Error in invoice_line_item: {str(e)}")


def item_data_with_template(invoice, sales_invoice_doc):
    """Adds InvoiceLine elements to the invoice"""

    try:
        for single_item in sales_invoice_doc.items:
            item_tax_template = frappe.get_doc(
                "Item Tax Template", single_item.item_tax_template
            )
            item_tax_percentage = (
                item_tax_template.taxes[0].tax_rate if item_tax_template.taxes else 0
            )
            cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
            cbc_ID = ET.SubElement(cac_InvoiceLine, "cbc:ID")
            cbc_ID.text = str(single_item.idx)
            cbc_InvoicedQuantity = ET.SubElement(
                cac_InvoiceLine, "cbc:InvoicedQuantity", unitCode="H87"
            )
            cbc_InvoicedQuantity.text = str(abs(single_item.qty))
            cbc_LineExtensionAmount = ET.SubElement(
                cac_InvoiceLine, "cbc:LineExtensionAmount", currencyID="MYR"
            )
            cbc_LineExtensionAmount.text = str(abs(single_item.amount))

            discount_amount = abs(single_item.get("discount_amount", 0.0))
            if discount_amount > 0:
                cac_AllowanceCharge = ET.SubElement(
                    cac_InvoiceLine, "cac:AllowanceCharge"
                )
                cbc_ChargeIndicator = ET.SubElement(
                    cac_AllowanceCharge, "cbc:ChargeIndicator"
                )
                cbc_ChargeIndicator.text = "false"
                cbc_AllowanceChargeReason = ET.SubElement(
                    cac_AllowanceCharge, "cbc:AllowanceChargeReason"
                )
                cbc_AllowanceChargeReason.text = "Item Discount"
                cbc_MultiplierFactorNumeric = ET.SubElement(
                    cac_AllowanceCharge, "cbc:MultiplierFactorNumeric"
                )
                cbc_MultiplierFactorNumeric.text = "1"
                cbc_Amount = ET.SubElement(
                    cac_AllowanceCharge, "cbc:Amount", currencyID="MYR"
                )
                cbc_Amount.text = str(discount_amount)

            cac_TaxTotal = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
            cbc_TaxAmount = ET.SubElement(
                cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR"
            )
            cbc_TaxAmount.text = str(
                abs(round(item_tax_percentage * single_item.amount / 100, 2))
            )

            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            cbc_TaxableAmount = ET.SubElement(
                cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR"
            )
            cbc_TaxableAmount.text = str(abs(single_item.amount - discount_amount))
            cbc_TaxAmount = ET.SubElement(
                cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR"
            )
            cbc_TaxAmount.text = str(
                abs(round(item_tax_percentage * single_item.amount / 100, 2))
            )

            zatca_tax_category = item_tax_template.custom_zatca_tax_category
            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cbc_ID.text = str(zatca_tax_category)
            cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            cbc_Percent.text = f"{float(item_tax_percentage):.2f}"
            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            cbc_TaxScheme_ID = ET.SubElement(
                cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153"
            )
            cbc_TaxScheme_ID.text = "OTH"

            cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
            cbc_Description = ET.SubElement(cac_Item, "cbc:Description")
            cbc_Description.text = str(single_item.description)

            cac_CommodityClassification = ET.SubElement(
                cac_Item, "cac:CommodityClassification"
            )
            cbc_ItemClassificationCode = ET.SubElement(
                cac_CommodityClassification,
                "cbc:ItemClassificationCode",
                listID="CLASS",
            )
            # cbc_ItemClassificationCode.text =str(single_item.custom_item_classification_code)
            item_doc = frappe.get_doc(
                "Item", single_item.item_code
            )  # Example for Frappe framework
            classification_code = str(item_doc.custom_item_classification_code).split(
                ":"
            )[0]
            cbc_ItemClassificationCode.text = classification_code

            cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
            cbc_PriceAmount = ET.SubElement(
                cac_Price, "cbc:PriceAmount", currencyID="MYR"
            )
            cbc_PriceAmount.text = str(
                abs(single_item.base_price_list_rate) - discount_amount
            )

            cac_ItemPriceExtension = ET.SubElement(
                cac_InvoiceLine, "cac:ItemPriceExtension"
            )
            cbc_Amount = ET.SubElement(
                cac_ItemPriceExtension, "cbc:Amount", currencyID="MYR"
            )
            cbc_Amount.text = str(abs(single_item.base_amount))
        return invoice
    except Exception as e:
        frappe.throw(f"Error in invoice_line item template: {str(e)}")
        return None


def xml_structuring(invoice, sales_invoice_doc):
    """status_submit_success_log"""
    try:
        raw_xml = ET.tostring(invoice, encoding="utf-8", method="xml").decode("utf-8")
        with open(frappe.local.site + "/private/files/beforesubmit1.xml", "w") as file:
            file.write(raw_xml)

        fileXx = frappe.get_doc(
            {
                "doctype": "File",
                "file_type": "xml",
                "file_name": "E-invoice-" + sales_invoice_doc.name + ".xml",
                "attached_to_doctype": sales_invoice_doc.doctype,
                "attached_to_name": sales_invoice_doc.name,
                "content": raw_xml,
                "is_private": 1,
            }
        )
        fileXx.save()

        return raw_xml
    except Exception as e:
        frappe.throw(f"Error in xml structuring: {str(e)}")


def generate_qr_code(sales_invoice_doc, status):
    """Generate QR code for the given Purchase Invoice"""
    # Extract required fields
    customer_doc = frappe.get_doc("Customer", sales_invoice_doc.customer)
    company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
    verification_url = (
        "https://verify.hasil.gov.my/einvoice?ref=" + sales_invoice_doc.name
    )
    # qr_data = {
    #     "uin": sales_invoice_doc.name,  # Invoice number
    #     "seller_tin": company_doc.custom_company_tin_number,
    #     "buyer_tin": customer_doc.custom_customer_tin_number,
    #     "date": sales_invoice_doc.posting_date.strftime("%Y-%m-%d"),
    #     "total_amount": f"{sales_invoice_doc.base_grand_total:.2f}",
    #     "tax_amount": f"{sales_invoice_doc.total_taxes_and_charges:.2f}",
    #     "status": status,  # Example status, modify as needed
    #     "verification_url": verification_url,
    # }
    posting_date = sales_invoice_doc.posting_date
    if isinstance(posting_date, str):
        posting_date = datetime.strptime(posting_date, "%Y-%m-%d").date()

    qr_data = {
        "uin": sales_invoice_doc.name,
        "seller_tin": company_doc.custom_company_tin_number,
        "buyer_tin": customer_doc.custom_customer_tin_number,
        "date": posting_date.strftime("%Y-%m-%d"),
        "total_amount": f"{sales_invoice_doc.base_grand_total:.2f}",
        "tax_amount": f"{sales_invoice_doc.total_taxes_and_charges:.2f}",
        "status": status,
        "verification_url": verification_url,
    }
    # frappe.throw(f"QR Code generated and saved at {qr_data}")
    # Serialize to JSON
    qr_code_payload = json.dumps(qr_data)
    # Generate QR code
    qr = pyqrcode.create(qr_code_payload)

    # Save QR code image
    qr_image_path = frappe.utils.get_site_path(
        "public", "files", f"{sales_invoice_doc.name}_qr.png"
    )
    qr.png(qr_image_path, scale=6)  # Adjust scale as needed

    return qr_image_path


def attach_qr_code_to_sales_invoice(sales_invoice_doc, qr_image_path):
    """Attach the QR code image to the Purchase Invoice"""
    # Read the file content
    with open(qr_image_path, "rb") as qr_file:
        qr_content = qr_file.read()

    # Create a File document and attach it to the Purchase Invoice
    qr_file_doc = frappe.get_doc(
        {
            "doctype": "File",
            "file_name": f"QR_{sales_invoice_doc.name}.png",
            "attached_to_doctype": sales_invoice_doc.doctype,
            "attached_to_name": sales_invoice_doc.name,
            "content": qr_content,
            "is_private": 1,
        }
    )
    qr_file_doc.save(ignore_permissions=True)


# print(f"QR Code generated and saved at {qr_image_path}")
