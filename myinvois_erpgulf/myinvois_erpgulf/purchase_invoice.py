"""this file is used to generate the xml file for the invoice"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import json
import re
import frappe
import pyqrcode
from frappe import _
import os
import requests
from myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin import get_access_token
DESCRIPTION = "cbc:Description"
POSTAL_ADDRESS = "cac:PostalAddress"
CITY_NAME = "cbc:CityName"
POSTAL_ZONE = "cbc:PostalZone"
COUNTRY_SUBENTITY = "cbc:CountrySubentityCode"
ADDRESS_LINE ="cac:AddressLine"
LINE = "cbc:Line"
COUNTRY = "cac:Country"
IDENTIFICATION_CODE = "cbc:IdentificationCode"
LEGAL_ENTITY = "cac:PartyLegalEntity"
REG_NAME = "cbc:RegistrationName"
DYANAMIC_LINK = "Dynamic Link"
CBC_ID = "cbc:ID"
PARTY_IDENTIFICATION="cac:PartyIdentification"
LINE_EXTENSION="cbc:LineExtensionAmount"
TAX_CATE ="cac:TaxCategory"
PERCENT = "cbc:Percent"
TAX_SCHEME= "cac:TaxScheme"
UN_ECE="UN/ECE 5153"
TAXABLE_AMOUNT="cbc:TaxableAmount"
TAX_SUBTOT="cac:TaxSubtotal"
ALLOWANCE_CHARGE = "cac:AllowanceCharge"
CHARGE_IND = "cbc:ChargeIndicator"
CHARGE_REASON="cbc:AllowanceChargeReason"
AMOUNT ="cbc:Amount"
TAX_TOTAL = "cac:TaxTotal"
TAX_AMOUNT = "cbc:TaxAmount"
SELF_CREDIT= "12 : Self-billed Credit Note"
SELF_DEBIT= "13 : Self-billed Debit Note"
SELF_REFUND = "14 : Self-billed Refund Note"


def get_icv_code(invoice_number):
    """Extracts the numeric part from the invoice number to generate the ICV code"""
    try:
        icv_code = re.sub(
            r"\D", "", invoice_number
        )  # taking the number part only from doc name
        return icv_code
    except TypeError as e:
        frappe.throw(_("Type error in getting ICV number: " + str(e)))
        return None
    except re.error as e:
        frappe.throw(_("Regex error in getting ICV number: " + str(e)))
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
        frappe.throw(_(f"Error creating invoice extensions: {str(e)}"))
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


def handle_self_billed_reference(invoice_document_reference, sales_invoice_doc):
    """Handles the special case for self-billed credit/debit/refund """
    if sales_invoice_doc.custom_invoicetype_code in [
        SELF_CREDIT,
        SELF_DEBIT,
        SELF_REFUND,
    ]:
        doc_id = sales_invoice_doc.return_against
        if not doc_id:
            frappe.throw(_("No document found in return_against."))
        doc = frappe.get_doc("Purchase Invoice", doc_id)
        if hasattr(doc, "custom_submit_response") and doc.custom_submit_response:
            try:
                custom_submit_response = json.loads(doc.custom_submit_response)
                accepted_documents = custom_submit_response.get(
                    "acceptedDocuments", []
                )
                if accepted_documents:
                    uuid = accepted_documents[0].get("uuid")
                    create_element(invoice_document_reference, "cbc:UUID", uuid)
                else:
                    frappe.throw(
                        _(
                            "As per LHDN Regulation,no accepted documents found in custom_submit_response."
                        )
                    )
            except Exception as e:
                frappe.throw(
                    _("Error parsing custom_submit_response: {0}").format(str(e))
                )
def add_billing_reference(invoice, invoice_number, sales_invoice_doc):
    """Adds BillingReference with InvoiceDocumentReference to the invoice"""
    try:
        billing_reference = create_element(invoice, "cac:BillingReference")
        invoice_document_reference = create_element(
            billing_reference, "cac:InvoiceDocumentReference"
        )
        if sales_invoice_doc.custom_invoicetype_code in [
            SELF_CREDIT,
            SELF_DEBIT,
            SELF_REFUND,
        ]:
            invoice_id = sales_invoice_doc.return_against
        else:
            invoice_id = get_icv_code(invoice_number)
        create_element(invoice_document_reference, CBC_ID, invoice_id)

        # 🔹 extracted block (no internal change)
        handle_self_billed_reference(invoice_document_reference, sales_invoice_doc)

    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.throw(_(f"Error in add billing reference: {str(e)}"))
        return None

def add_additional_document_reference(invoice, document_references):
    """
    Adds multiple AdditionalDocumentReference elements to the given invoice.
    """
    try:
        for ref in document_references:
            additional_doc_reference = create_element(
                invoice, "cac:AdditionalDocumentReference"
            )
            create_element(additional_doc_reference, CBC_ID, ref.get("ID", ""))
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
        frappe.throw(_(f"Error add aditional daata: {str(e)}"))
        return None


def add_signature(invoice):
    """Adds Signature to the invoice"""
    try:
        signature = create_element(invoice, "cac:Signature")
        create_element(
            signature, CBC_ID, "urn:oasis:names:specification:ubl:signature:Invoice"
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
        frappe.throw(_(f"Error signature data: {str(e)}"))
        return None


def salesinvoice_data(invoice, sales_invoice_doc, company_abbr):
    """Adds the Purchase Invoice data to the invoice"""
    try:
        create_element(invoice, CBC_ID, str(sales_invoice_doc.name))

        formatted_date, formatted_time = get_current_utc_datetime()
        create_element(invoice, "cbc:IssueDate", formatted_date)
        create_element(invoice, "cbc:IssueTime", formatted_time)
        if not sales_invoice_doc.custom_invoicetype_code:
            frappe.throw(_("As per LHDN Regulation,Custom Invoice Type Code is missing!"))
        if (
            sales_invoice_doc.custom_is_return_refund == 1
            and sales_invoice_doc.is_return == 1
        ):
            # Check if the field is already set to "03 : Debit Note"
            if (
                sales_invoice_doc.custom_invoicetype_code
                != SELF_REFUND
            ):
                frappe.throw(_(
                    "As per LHDN Regulation, the invoice type code as '14 : Self-billed Refund Note'"
                ))
        if (
            sales_invoice_doc.is_return == 1
            and sales_invoice_doc.custom_is_return_refund == 0
        ):
            # Check if the field is already set to "02 : Credit Note"
            if sales_invoice_doc.custom_invoicetype_code not in [
                SELF_CREDIT,
                SELF_DEBIT,
            ]:
                frappe.throw(_(
                    "As per LHDN Regulation,Choose the invoice type code as Self-billed Credit Note or Self-billed Debit Note"
                ))

        raw_invoice_type_code = sales_invoice_doc.custom_invoicetype_code

        invoice_type_code = raw_invoice_type_code.split(":")[0].strip()
        company_doc = frappe.get_doc("Company", {"abbr": company_abbr})
        if company_doc.custom_certificate_file and company_doc.custom_version == "1.1":
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
        # try:
        #     supplier_doc = frappe.get_doc("Supplier", sales_invoice_doc.supplier)
        #     if int(frappe.__version__.split(".")[0]) == 13:
        #         address = frappe.get_doc("Address", sales_invoice_doc.primary_address)
        #     else:
        #         address = frappe.get_doc(
        #             "Address", supplier_doc.supplier_primary_address
        #         )

        #     if address.country != "Malaysia":
        #         create_element(invoice, "SubType", "Foreign")
        # except Exception as e:
        #     frappe.throw(_("Error determining supplier country for SubType: ") + str(e))
        create_element(
            invoice, "cbc:DocumentCurrencyCode", sales_invoice_doc.currency
        )  # or sales_invoice_doc.currency
        create_element(invoice, "cbc:TaxCurrencyCode", sales_invoice_doc.currency)

        inv_period = create_element(invoice, "cac:InvoicePeriod")
        create_element(inv_period, "cbc:StartDate", str(sales_invoice_doc.posting_date))
        create_element(inv_period, "cbc:EndDate", str(sales_invoice_doc.due_date))
        create_element(inv_period, DESCRIPTION, "Monthly")
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
        frappe.throw(_(f"Error Purchase Invoice data: {str(e)}"))
        return None


def set_msic_code(party_, company_doc):
    """Adds the MSIC code to the party element"""
    msic_code_full = company_doc.custom_msic_code_
    if ":" in msic_code_full:
        msic_code_code, msic_code_name = [
            s.strip() for s in msic_code_full.split(":", 1)
        ]
    else:
        msic_code_code, msic_code_name = msic_code_full.strip(), ""

    cbc_indclacode = ET.SubElement(
        party_, "cbc:IndustryClassificationCode", name=msic_code_name
    )
    cbc_indclacode.text = msic_code_code


def set_identifiers(party_, company_doc):
    """Adds the various identifiers (TIN, Registration/IC/Passport, SST, TTX) to the party element"""
    identifiers = [
        ("TIN", company_doc.custom_customer_tin_number),
        (
            company_doc.custom_customer__registrationicpassport_type,
            company_doc.custom_customer_registrationicpassport_number,
        ),
        ("SST", getattr(company_doc, "custom_sst_number", "NA") or "NA"),
        ("TTX", getattr(company_doc, "custom_tourism_tax_number", "NA") or "NA"),
    ]

    for scheme_id, value in identifiers:
        party_id = ET.SubElement(party_, PARTY_IDENTIFICATION)
        id_element = ET.SubElement(party_id, CBC_ID, schemeID=scheme_id)
        id_element.text = str(value) if value else "NA"


def set_address(party_, sales_invoice_doc, company_doc):
    """Adds the address information to the party element and returns the address document"""
    if int(frappe.__version__.split(".")[0]) == 13:
        address = frappe.get_doc("Address", sales_invoice_doc.primary_address)
    else:
        address = frappe.get_doc(
            "Address", company_doc.supplier_primary_address
        )

    post_add = ET.SubElement(party_, POSTAL_ADDRESS)
    ET.SubElement(post_add, CITY_NAME).text = address.city
    ET.SubElement(post_add, POSTAL_ZONE).text = address.pincode

    statecode_raw = address.custom_state_code or ""
    statecode = statecode_raw.split(":")[0].strip() if statecode_raw else "17"
    if not statecode:
        statecode = "17"
    ET.SubElement(post_add, COUNTRY_SUBENTITY).text = statecode

    add_line1 = ET.SubElement(post_add, ADDRESS_LINE)
    ET.SubElement(add_line1, LINE).text = address.address_line1

    add_line2 = ET.SubElement(post_add, ADDRESS_LINE)
    ET.SubElement(add_line2, LINE).text = address.address_line2

    combined_city_pincode = f"{address.city}, {address.pincode}"
    add_line3 = ET.SubElement(post_add, ADDRESS_LINE)
    ET.SubElement(add_line3, LINE).text = combined_city_pincode

    cntry = ET.SubElement(post_add, COUNTRY)
    idntfn_cod = ET.SubElement(
        cntry,
        IDENTIFICATION_CODE,
        listAgencyID="6",
        listID="ISO3166-1",
    )

    idntfn_cod.text = "MYS" if address.country == "Malaysia" else address.country

    return address


def set_contact(party_, address):
    """Adds contact information to the party element"""
    cont_ct = ET.SubElement(party_, "cac:Contact")

    phone = address.get("phone")
    ET.SubElement(cont_ct, "cbc:Telephone").text = (
        phone if not is_na(phone) else "60100000000"
    )

    email = address.get("email_id")

    if is_na(email) or not is_valid_email(email):
        email = "noemail@noemail.com"

    ET.SubElement(cont_ct, "cbc:ElectronicMail").text = email


def company_data(invoice, sales_invoice_doc):
    """Adds the Company data to the invoice"""
    try:
        company_doc = frappe.get_doc("Supplier", sales_invoice_doc.supplier)
        account_supplier_party = ET.SubElement(invoice, "cac:AccountingSupplierParty")
        party_ = ET.SubElement(account_supplier_party, "cac:Party")

        set_msic_code(party_, company_doc)
        set_identifiers(party_, company_doc)

        address = set_address(party_, sales_invoice_doc, company_doc)

        party_legal_entity = ET.SubElement(party_, LEGAL_ENTITY)
        ET.SubElement(party_legal_entity, REG_NAME).text = (
            sales_invoice_doc.supplier
        )

        set_contact(party_, address)

        return invoice

    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.throw(_(f"Error in supplier data generation: {str(e)}"))
        return None


def is_na(value):
    """is na"""
    return value is None or str(value).strip().lower() in ["n/a", "na", ""]


def is_valid_email(email):
    """valid email"""
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None


def customer_data(invoice, sales_invoice_doc):
    """Adds the Customer data to the invoice"""
    try:

        customer_doc = frappe.get_doc("Company", sales_invoice_doc.company)
        accounting_customer_party = ET.SubElement(
            invoice, "cac:AccountingCustomerParty"
        )
        cac_party = ET.SubElement(accounting_customer_party, "cac:Party")

        party_id_1 = ET.SubElement(cac_party,PARTY_IDENTIFICATION)
        prty_id = ET.SubElement(party_id_1, CBC_ID, schemeID="TIN")
        prty_id.text = str(customer_doc.custom_company_tin_number)

        party_identifn_2 = ET.SubElement(cac_party, PARTY_IDENTIFICATION)
        id_party2 = ET.SubElement(
            party_identifn_2,
            CBC_ID,
            schemeID=str(customer_doc.custom_company_registration_for_self_einvoicing),
        )
        id_party2.text = str(
            customer_doc.custom_company__registrationicpassport_number
        )  # Buyer’s Registration / Identification Number / Passport Number

        partyid_3 = ET.SubElement(cac_party, PARTY_IDENTIFICATION)
        value_id3 = ET.SubElement(partyid_3, CBC_ID, schemeID="SST")
        customer_doc.custom_sst_number = (
            getattr(customer_doc, "custom_sst_number", "NA") or "NA"
        )

        value_id3.text = (
            str(customer_doc.custom_sst_number)
            if str(customer_doc.custom_sst_number)
            else "NA"
        )

        partyid_4 = ET.SubElement(cac_party, PARTY_IDENTIFICATION)
        value_id4 = ET.SubElement(partyid_4,CBC_ID, schemeID="TTX")
        value_id4.text = (
            str(customer_doc.custom_tourism_tax_number)
            if str(customer_doc.custom_tourism_tax_number)
            else "NA"
        )
        address_list = frappe.get_list(
		"Address",
		filters=[
			[DYANAMIC_LINK, "link_doctype", "=", "Company"],
			[DYANAMIC_LINK, "link_name", "=", sales_invoice_doc.company],
			[DYANAMIC_LINK, "parenttype", "=", "Address"],
		],
		fields=["*"],
		order_by="`tabAddress`.creation asc",
        )

        if not address_list:
            frappe.throw(
                _(
                    "Invoice requires a proper address. Please add your company address in the Address field."
                )
            )

        address = address_list[0]
        posta_address = ET.SubElement(cac_party, POSTAL_ADDRESS)
        name_city = ET.SubElement(posta_address, CITY_NAME)
        name_city.text = address.city
        post_zone = ET.SubElement(posta_address, POSTAL_ZONE)
        post_zone.text = address.pincode
        cntry_sub_cod = ET.SubElement(posta_address, COUNTRY_SUBENTITY)
        statecode = (
            address.custom_state_code.split(":")[0]
            if address.custom_state_code
            else "17"
        )
        cntry_sub_cod.text = statecode

        add_cust_line1 = ET.SubElement(posta_address, ADDRESS_LINE)
        add_line1 = ET.SubElement(add_cust_line1, LINE)
        add_line1.text = address.address_line1

        add_cust_line2 = ET.SubElement(posta_address, ADDRESS_LINE)
        add_line2 = ET.SubElement(add_cust_line2, LINE)
        add_line2.text = address.address_line2

        combined_city_pincode = f"{address.city}, {address.pincode}"
        add_cust_line3 = ET.SubElement(posta_address, ADDRESS_LINE)
        add_line3 = ET.SubElement(add_cust_line3, LINE)
        add_line3.text = combined_city_pincode

        cnty_customer = ET.SubElement(posta_address, COUNTRY)
        idntfn_code_val = ET.SubElement(
            cnty_customer,
            IDENTIFICATION_CODE,
            listAgencyID="6",
            listID="ISO3166-1",
        )
        idntfn_code_val.text = "MYS"

        party_legalentity = ET.SubElement(cac_party, LEGAL_ENTITY)
        reg_name_val = ET.SubElement(party_legalentity,REG_NAME)
        reg_name_val.text = sales_invoice_doc.company

        cont_customer = ET.SubElement(cac_party, "cac:Contact")
        tele_party = ET.SubElement(cont_customer, "cbc:Telephone")
        tele_party.text = str(address.phone)

        mail_party = ET.SubElement(cont_customer, "cbc:ElectronicMail")
        mail_party.text = str(address.email_id)
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error customer data: {str(e)}"))
        return None


def delivery_data(invoice, sales_invoice_doc):
    """Adds the Delivery data to the invoice"""
    try:
        customer_doc = frappe.get_doc("Company", sales_invoice_doc.company)

        delivery = ET.SubElement(invoice, "cac:Delivery")
        delivery_party = ET.SubElement(delivery, "cac:DeliveryParty")

        party_id_tin = ET.SubElement(delivery_party, PARTY_IDENTIFICATION)
        tin_id = ET.SubElement(party_id_tin, CBC_ID, schemeID="TIN")
        tin_id.text = str(customer_doc.custom_company_tin_number)

        party_id_brn = ET.SubElement(delivery_party, PARTY_IDENTIFICATION)
        brn_id = ET.SubElement(
            party_id_brn,
            CBC_ID,
            schemeID=str(customer_doc.custom_company_registration_for_self_einvoicing),
        )
        brn_id.text = str(customer_doc.custom_company__registrationicpassport_number)

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
                _(
                    "Invoice requires a proper address. Please add your company address in the Address field."
                )
            )

        address = address_list[0]

        postal_address = ET.SubElement(delivery_party, POSTAL_ADDRESS)
        city_name = ET.SubElement(postal_address, CITY_NAME)
        city_name.text = address.city

        postal_zone = ET.SubElement(postal_address, POSTAL_ZONE)

        postal_zone.text = address.pincode
        # str(address.custom_state_code).split(":", 1)[1].strip()

        country_subentity_code = ET.SubElement(
            postal_address, COUNTRY_SUBENTITY
        )
        # (address.custom_state_code).split(":")[0]
        statecode = (
            address.custom_state_code.split(":")[0]
            if address.custom_state_code
            else "17"
        )
        country_subentity_code.text = statecode

        address_line1 = ET.SubElement(
            ET.SubElement(postal_address,ADDRESS_LINE), LINE
        )
        address_line1.text = address.address_line1

        address_line2 = ET.SubElement(
            ET.SubElement(postal_address, ADDRESS_LINE), LINE
        )
        address_line2.text = address.address_line2

        combined_city_pincode = f"{address.city}, {address.pincode}"
        address_line3 = ET.SubElement(
            ET.SubElement(postal_address, ADDRESS_LINE), LINE
        )
        address_line3.text = combined_city_pincode

        country = ET.SubElement(postal_address, COUNTRY)
        country_id_code = ET.SubElement(
            country,
            IDENTIFICATION_CODE,
            listAgencyID="6",
            listID="ISO3166-1",
        )
        country_id_code.text = "MYS"

        party_legal_entity = ET.SubElement(delivery_party, LEGAL_ENTITY)
        registration_name = ET.SubElement(party_legal_entity, REG_NAME)
        registration_name.text = sales_invoice_doc.company
        return invoice
    except Exception as e:
        frappe.throw(
            _(f"Error in customer means company details in purchase invoice: {str(e)}")
        )
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
        payee_id = ET.SubElement(payee_financial_account, CBC_ID)
        payee_id.text = "1234567890"

        payment_terms = ET.SubElement(invoice, "cac:PaymentTerms")
        payment_note = ET.SubElement(payment_terms, "cbc:Note")
        payment_note.text = f"Payment method is {payment_mode}"

        
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error adding payment data: {str(e)}"))
        return None


def allowance_charge_data(invoice, sales_invoice_doc):
    """Adds AllowanceCharge elements to the invoice"""
    try:
        for single_item in sales_invoice_doc.items:
            discount_amount = abs(single_item.get("discount_amount", 0.0))
            if discount_amount > 0:
                allowance_charge_1 = ET.SubElement(invoice, ALLOWANCE_CHARGE)
                charge_indicator_1 = ET.SubElement(
                    allowance_charge_1, CHARGE_IND
                )
                charge_indicator_1.text = "false"

                allowance_charge_reason_1 = ET.SubElement(
                    allowance_charge_1, CHARGE_REASON
                )
                allowance_charge_reason_1.text = "Promotional Discount"

                amount_1 = ET.SubElement(
                    allowance_charge_1, AMOUNT, currencyID=sales_invoice_doc.currency
                )
                amount_1.text = str(discount_amount)

        if sales_invoice_doc.currency and sales_invoice_doc.currency != "MYR":
            tax_exchange_rate = ET.SubElement(invoice, "cac:TaxExchangeRate")

            # Source currency is the document currency (e.g., USD)
            ET.SubElement(tax_exchange_rate, "cbc:SourceCurrencyCode").text = sales_invoice_doc.currency

            # Target currency is always MYR
            ET.SubElement(tax_exchange_rate, "cbc:TargetCurrencyCode").text = "MYR"

            # Use exchange rate from document or default value (e.g., 4.72)
            ET.SubElement(tax_exchange_rate, "cbc:CalculationRate").text = str(
                sales_invoice_doc.conversion_rate or 4.72
            )

        return invoice
    except Exception as e:
        frappe.throw(_(f"Error adding allowance charge data: {str(e)}"))
        return None


def tax_total(invoice, sales_invoice_doc):
    """Adds TaxTotal, TaxSubtotal, TaxCategory, and TaxScheme elements to the invoice"""
    try:
        taxable_amount = sales_invoice_doc.base_total - sales_invoice_doc.get(
            "base_discount_amount", 0.0
        )
        cac_taxtotal = ET.SubElement(invoice, TAX_TOTAL)
        taxamnt = ET.SubElement(cac_taxtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency)
        tax_amount_without_retention = (
            taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100
        )
        taxamnt.text = f"{abs(round(tax_amount_without_retention, 2)):.2f}"

        cac_taxsubtotal = ET.SubElement(cac_taxtotal, TAX_SUBTOT)
        taxable_amnt = ET.SubElement(
            cac_taxsubtotal, TAXABLE_AMOUNT, currencyID=sales_invoice_doc.currency
        )
        taxable_amnt.text = str(abs(round(taxable_amount, 2)))
        taxamnt = ET.SubElement(cac_taxsubtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency)
        taxamnt.text = str(
            abs(round(taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100, 2))
        )

        cac_taxcategory = ET.SubElement(cac_taxsubtotal, TAX_CATE)
        raw_item_id_code = sales_invoice_doc.custom_malaysia_tax_category
        cat_id_val = ET.SubElement(cac_taxcategory, CBC_ID)
        cat_id_val.text = raw_item_id_code.split(":")[0].strip()
        prct = ET.SubElement(cac_taxcategory, PERCENT)
        prct.text = str(sales_invoice_doc.taxes[0].rate)
        exemption = ET.SubElement(cac_taxcategory, "cbc:TaxExemptionReason")
        if (sales_invoice_doc.custom_malaysia_tax_category) == "E":
            exemption.text = sales_invoice_doc.custom_exemption_code
        else:
            exemption.text = "NA"

        cac_taxscheme = ET.SubElement(cac_taxcategory, TAX_SCHEME)
        taxscheme_id = ET.SubElement(
            cac_taxscheme, CBC_ID, schemeAgencyID="6", schemeID=UN_ECE
        )
        taxscheme_id.text = "OTH"
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error tax total: {str(e)}"))
        return None


def tax_total_with_template(invoice, sales_invoice_doc):
    """Adds TaxTotal, TaxSubtotal, TaxCategory, and TaxScheme elements to the invoice"""
    try:
        tax_category_totals = {}

        for item in sales_invoice_doc.items:
            item_tax_template = frappe.get_doc(
                "Item Tax Template", item.item_tax_template
            )
            malaysia_tax_category = item_tax_template.custom_malaysia_tax_category

            if malaysia_tax_category not in tax_category_totals:
                tax_category_totals[malaysia_tax_category] = {
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
                tax_category_totals[malaysia_tax_category]["taxable_amount"] += abs(
                    item.base_amount
                )
            else:
                tax_category_totals[malaysia_tax_category]["taxable_amount"] += abs(
                    item.amount
                )

        first_tax_category = next(iter(tax_category_totals))
        base_discount_amount = sales_invoice_doc.get("discount_amount", 0.0)
        tax_category_totals[first_tax_category][
            "taxable_amount"
        ] -= base_discount_amount

        for malaysia_tax_category in tax_category_totals:
            taxable_amount = tax_category_totals[malaysia_tax_category]["taxable_amount"]
            tax_rate = tax_category_totals[malaysia_tax_category]["tax_rate"]
            tax_category_totals[malaysia_tax_category]["tax_amount"] = abs(
                round(taxable_amount * tax_rate / 100, 2)
            )

        total_tax = sum(totals["tax_amount"] for totals in tax_category_totals.values())
        tax_amount_without_retention_sar = round(abs(total_tax), 2)

        cac_taxtotal = ET.SubElement(invoice, TAX_TOTAL)
        cbc_taxamount = ET.SubElement(cac_taxtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency)
        cbc_taxamount.text = str(tax_amount_without_retention_sar)

        for malaysia_tax_category, totals in tax_category_totals.items():
            cac_taxsubtotal = ET.SubElement(cac_taxtotal, TAX_SUBTOT)
            cbc_taxableamount = ET.SubElement(
                cac_taxsubtotal, TAXABLE_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_taxableamount.text = str(round(totals["taxable_amount"], 2))

            cbc_taxamount = ET.SubElement(
                cac_taxsubtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_taxamount.text = str(round(totals["tax_amount"], 2))

            cac_taxcategory = ET.SubElement(cac_taxsubtotal,TAX_CATE)
            cbc_id = ET.SubElement(cac_taxcategory, CBC_ID)
            cbc_id.text = malaysia_tax_category

            cbc_percent = ET.SubElement(cac_taxcategory, PERCENT)
            cbc_percent.text = f"{totals['tax_rate']:.2f}"

            cbc_taxexemptionreason = ET.SubElement(
                cac_taxcategory, "cbc:TaxExemptionReason"
            )
            if malaysia_tax_category == "E":
                cbc_taxexemptionreason.text = (
                    item_tax_template.custom_exemption_reason_code
                )
            else:
                cbc_taxexemptionreason.text = "NA"

            cac_taxscheme = ET.SubElement(cac_TaxCategory, TAX_SCHEME)
            cbc_taxscheme_id = ET.SubElement(
                cac_taxscheme, CBC_ID, schemeAgencyID="6", schemeID=UN_ECE
            )
            cbc_taxscheme_id.text = "OTH"
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error in tax total calculation: {str(e)}"))
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
            legal_monetary_total, LINE_EXTENSION, currencyID=sales_invoice_doc.currency
        )
        line_ext_amnt.text = str(abs(sales_invoice_doc.total))
        tax_exc_ = ET.SubElement(
            legal_monetary_total, "cbc:TaxExclusiveAmount", currencyID=sales_invoice_doc.currency
        )
        tax_exc_.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
        )
        tax_inc = ET.SubElement(
            legal_monetary_total, "cbc:TaxInclusiveAmount", currencyID=sales_invoice_doc.currency
        )
        tax_inc.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
            + abs(round(tax_amount_without_retention, 2))
        )
        allw_tot = ET.SubElement(
            legal_monetary_total, "cbc:AllowanceTotalAmount", currencyID=sales_invoice_doc.currency
        )
        allw_tot.text = str(abs(sales_invoice_doc.get("discount_amount", 0.0)))
        # <cbc:ChargeTotalAmount currencyID="MYR">1436.50</cbc:ChargeTotalAmount>
        payable_ = ET.SubElement(
            legal_monetary_total, "cbc:PayableAmount", currencyID=sales_invoice_doc.currency
        )
        payable_.text = str(
            abs(sales_invoice_doc.total - sales_invoice_doc.get("discount_amount", 0.0))
            + abs(round(tax_amount_without_retention, 2))
        )
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error legal monetary: {str(e)}"))
        return None


def get_tax_for_item(full_string, item):
    """Get tax amount and tax percentage for the given item"""
    try:
        data = json.loads(full_string)
        tax_percentage = data.get(item, [0, 0])[0]
        tax_amount = data.get(item, [0, 0])[1]
        return tax_amount, tax_percentage
    except Exception as e:
        frappe.throw(_("error occured in tax for item" + str(e)))


def invoice_line_item(invoice, sales_invoice_doc):
    """Adds InvoiceLine elements to the invoice"""
    try:
        for single_item in sales_invoice_doc.items:
            invoice_line = ET.SubElement(invoice, "cac:InvoiceLine")
            item_id = ET.SubElement(invoice_line, CBC_ID)
            item_id.text = str(single_item.idx)

            item_qty = ET.SubElement(
                invoice_line,
                "cbc:InvoicedQuantity",
                unitCode="H87",
            )
            item_qty.text = str(abs(single_item.qty))
            item_line_exte_amnt = ET.SubElement(
                invoice_line, LINE_EXTENSION, currencyID=sales_invoice_doc.currency
            )
            item_line_exte_amnt.text = str(abs(single_item.amount))
            discount_amount = abs(single_item.get("discount_amount", 0.0))
            if discount_amount > 0:
                allw_chrge = ET.SubElement(invoice_line, ALLOWANCE_CHARGE)
                chrg_indic = ET.SubElement(allw_chrge, CHARGE_IND)
                chrg_indic.text = "false"
                allwa_chrge_reson = ET.SubElement(
                    allw_chrge, CHARGE_REASON
                )
                allwa_chrge_reson.text = "Item Discount"
                multi_fac = ET.SubElement(allw_chrge, "cbc:MultiplierFactorNumeric")
                multi_fac.text = "1"
                amnt = ET.SubElement(allw_chrge, AMOUNT, currencyID=sales_invoice_doc.currency)
                amnt.text = str(discount_amount)
            tax_total_item = ET.SubElement(invoice_line,TAX_TOTAL)
            tax_amount_item = ET.SubElement(
                tax_total_item, TAX_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            tax_amount_item.text = str(
                abs(
                    round(
                        (sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2
                    )
                )
            )
            tax_subtot_item = ET.SubElement(tax_total_item, TAX_SUBTOT)
            taxable_amnt_item = ET.SubElement(
                tax_subtot_item, TAXABLE_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            taxable_amnt_item.text = str(abs(single_item.amount - discount_amount))
            tax_amnt = ET.SubElement(tax_subtot_item, TAX_AMOUNT, currencyID=sales_invoice_doc.currency)
            tax_amnt.text = str(
                abs(
                    round(
                        (sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2
                    )
                )
            )
            tax_cate_item = ET.SubElement(tax_subtot_item, TAX_CATE)
            cat_item_id = ET.SubElement(tax_cate_item,CBC_ID)
            raw_invoice_type_code = sales_invoice_doc.custom_malaysia_tax_category

            cat_item_id.text = raw_invoice_type_code.split(":")[0].strip()
            item_prct = ET.SubElement(tax_cate_item, PERCENT)
            item_prct.text = str(sales_invoice_doc.taxes[0].rate)
            tax_scheme_item = ET.SubElement(tax_cate_item, TAX_SCHEME)
            tax_id_scheme_item = ET.SubElement(
                tax_scheme_item, CBC_ID, schemeAgencyID="6", schemeID=UN_ECE
            )
            tax_id_scheme_item.text = "OTH"

            item_data = ET.SubElement(invoice_line, "cac:Item")
            descp_item = ET.SubElement(item_data, DESCRIPTION)
            desc = ""
            if single_item.description and single_item.item_name:
                desc = f"{single_item.description} - {single_item.item_name}"
            elif single_item.description:
                desc = str(single_item.description)
            elif single_item.item_name:
                desc = str(single_item.item_name)

            descp_item.text = desc
            comm_class_cod = ET.SubElement(item_data, "cac:CommodityClassification")
            item_class_cod = ET.SubElement(
                comm_class_cod, "cbc:ItemClassificationCode", listID="CLASS"
            )
            classification_code = str(
                single_item.custom_item_classification_codes
            ).split(":")[0]
            item_class_cod.text = classification_code
            price_item = ET.SubElement(invoice_line, "cac:Price")
            pri_amnt_item = ET.SubElement(
                price_item, "cbc:PriceAmount", currencyID=sales_invoice_doc.currency
            )
            pri_amnt_item.text = str(
                abs(single_item.base_price_list_rate) - discount_amount
            )
            item_pri_ext = ET.SubElement(invoice_line, "cac:ItemPriceExtension")
            item_val_amnt = ET.SubElement(item_pri_ext, AMOUNT, currencyID=sales_invoice_doc.currency)
            item_val_amnt.text = str(abs(single_item.base_amount))
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error in invoice_line_item: {str(e)}"))


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
            cac_invoiceline = ET.SubElement(invoice, "cac:InvoiceLine")
            cbc_id = ET.SubElement(cac_invoiceline, CBC_ID)
            cbc_id.text = str(single_item.idx)
            cbc_invoicedquantity = ET.SubElement(
                cac_invoiceline, "cbc:InvoicedQuantity", unitCode="H87"
            )
            cbc_invoicedquantity.text = str(abs(single_item.qty))
            cbc_lineextensionamount = ET.SubElement(
                cac_invoiceline,LINE_EXTENSION, currencyID=sales_invoice_doc.currency
            )
            cbc_lineextensionamount.text = str(abs(single_item.amount))

            discount_amount = abs(single_item.get("discount_amount", 0.0))
            if discount_amount > 0:
                cac_allowancecharge = ET.SubElement(
                    cac_invoiceline, ALLOWANCE_CHARGE
                )
                cbc_chargeindicator = ET.SubElement(
                    cac_allowancecharge, CHARGE_IND
                )
                cbc_chargeindicator.text = "false"
                cbc_allowancechargereason = ET.SubElement(
                    cac_allowancecharge, CHARGE_REASON
                )
                cbc_allowancechargereason.text = "Item Discount"
                cbc_multiplierfactornumeric = ET.SubElement(
                    cac_allowancecharge, "cbc:MultiplierFactorNumeric"
                )
                cbc_multiplierfactornumeric.text = "1"
                cbc_amount = ET.SubElement(
                    cac_allowancecharge, AMOUNT, currencyID=sales_invoice_doc.currency
                )
                cbc_amount.text = str(discount_amount)

            cac_taxtotal = ET.SubElement(cac_invoiceline, TAX_TOTAL)
            cbc_taxamount = ET.SubElement(
                cac_taxtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_taxamount.text = str(
                abs(round(item_tax_percentage * single_item.amount / 100, 2))
            )

            cac_taxsubtotal = ET.SubElement(cac_TaxTotal, TAX_SUBTOT)
            cbc_taxableamount = ET.SubElement(
                cac_taxsubtotal, TAXABLE_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_taxableamount.text = str(abs(single_item.amount - discount_amount))
            cbc_taxamount = ET.SubElement(
                cac_TaxSubtotal, TAX_AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_taxamount.text = str(
                abs(round(item_tax_percentage * single_item.amount / 100, 2))
            )

            malaysia_tax_category = item_tax_template.custom_malaysia_tax_category
            cac_taxcategory = ET.SubElement(cac_TaxSubtotal, TAX_CATE)
            cbc_id = ET.SubElement(cac_TaxCategory, CBC_ID)
            cbc_id.text = str(malaysia_tax_category)
            cbc_percent = ET.SubElement(cac_taxcategory, PERCENT)
            cbc_percent.text = f"{float(item_tax_percentage):.2f}"
            cac_taxscheme = ET.SubElement(cac_taxcategory, TAX_SCHEME)
            cbc_taxscheme_id = ET.SubElement(
                cac_taxscheme,CBC_ID, schemeAgencyID="6", schemeID=UN_ECE
            )
            cbc_taxscheme_id.text = "OTH"

            cac_item = ET.SubElement(cac_invoiceline, "cac:Item")
            cbc_description = ET.SubElement(cac_item, DESCRIPTION)
            
            if single_item.description and single_item.item_name:
                cbc_description.text = (
                    f"{single_item.description} - {single_item.item_name}"
                )
            elif single_item.description:
                cbc_description.text = str(single_item.description)
            elif single_item.item_name:
                cbc_description.text = str(single_item.item_name)
            cac_commodityclassification = ET.SubElement(
                cac_item, "cac:CommodityClassification"
            )
            cbc_itemclassificationcode = ET.SubElement(
                cac_commodityclassification,
                "cbc:ItemClassificationCode",
                listID="CLASS",
            )
            
            classification_code = str(
                single_item.custom_item_classification_codes
            ).split(":")[0]
            cbc_itemclassificationcode.text = classification_code

            cac_price = ET.SubElement(cac_invoiceline, "cac:Price")
            cbc_priceamount = ET.SubElement(
                cac_price, "cbc:PriceAmount", currencyID=sales_invoice_doc.currency
            )
            cbc_priceamount.text = str(abs(single_item.base_rate) - discount_amount)

            cac_itempriceextension = ET.SubElement(
                cac_invoiceline, "cac:ItemPriceExtension"
            )
            cbc_amount = ET.SubElement(
                cac_itempriceextension, AMOUNT, currencyID=sales_invoice_doc.currency
            )
            cbc_amount.text = str(abs(single_item.base_amount))
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error in invoice_line item template: {str(e)}"))
        return None


def xml_structuring(invoice):
    """xml structuring of purchase invoice"""
    try:
        raw_xml = ET.tostring(invoice, encoding="utf-8", method="xml").decode("utf-8")
        # nosemgrep: frappe-semgrep-rules.rules.security.frappe-security-file-traversal
        with open(frappe.local.site + "/private/files/beforesubmit1.xml", "w") as file:
            file.write(raw_xml)

       

        return raw_xml
    except Exception as e:
        frappe.throw(_(f"Error in xml structuring: {str(e)}"))


def get_api_url(company_abbr, base_url=""):
    """Return full API URL based on integration type and base URL"""
    try:
        company_doc = frappe.get_doc("Company", {"abbr": company_abbr})

        if company_doc.custom_integration_type == "Sandbox":
            base = company_doc.custom_sandbox_url or ""
        else:
            base = company_doc.custom_production_url or ""

        # Clean up slashes to avoid issues
        return (base.rstrip("/") + "/" + base_url.lstrip("/")).rstrip("/")

    except Exception as e:
        frappe.throw(_(f"Error generating API URL: {e}"))

def fetch_long_id(longid_api, headers):
    """Fetch longId from API with error handling and logging"""
    def get_long_id():
        try:
            res = requests.get(longid_api, headers=headers, timeout=30)
            if res.status_code != 200:
                frappe.log_error(
                    f"Status {res.status_code} for longId API",
                    "LHDN longId Fetch Error",
                )
                return None
            res_data = res.json()
            frappe.log_error(json.dumps(res_data, indent=2), "LHDN longId Response")
            if res_data.get("documentSummary"):
                return res_data["documentSummary"][0].get("longId")
        except Exception as e:
            frappe.log_error(str(e), "QR Code Generation: longId request failed")
        return None

    return get_long_id()

def create_qr_image(sales_invoice_doc, verification_url):
    """Generate QR code image from verification URL and return file path"""
    try:
        qr_code_payload = json.dumps(verification_url)
        qr = pyqrcode.create(qr_code_payload)
        qr_image_path = frappe.utils.get_site_path(
            "public", "files", f"{sales_invoice_doc.name}_qr.png"
        )
        qr.png(qr_image_path, scale=6)
        return qr_image_path
    except Exception as e:
        frappe.log_error(str(e), "QR Code Generation Failed")
        return None

def generate_qr_code(sales_invoice_doc):
    """Generate QR code for the given Sales Invoice that links to verification URL"""
    
    company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
    company_abbr = company_doc.abbr
    submit_response = json.loads(sales_invoice_doc.custom_submit_response or "{}")
    token = company_doc.get("custom_bearer_token")

    if not token:
        frappe.throw(_("Bearer token not found in Company document."))

    submission_uid = submit_response.get("submissionUid")

    if not submission_uid:
        sales_invoice_doc.custom_lhdn_status = "Failed"
        sales_invoice_doc.save(ignore_permissions=True)
        frappe.db.commit()  # nosemgrep: frappe-semgrep-rules.rules.frappe-manual-commit
        frappe.throw(_("Getting error from LHDN, please check 'Submit Response' field"))

    uuid = None

    if submit_response.get("acceptedDocuments"):
        uuid = submit_response["acceptedDocuments"][0].get("uuid")

    if not uuid:
        frappe.throw(_("UUID not found in acceptedDocuments from LHDN response."))

    longid_api = get_api_url(
        company_abbr, f"/api/v1.0/documentsubmissions/{submission_uid}"
    )
    headers = {"Authorization": f"Bearer {token}"}

    # 🔹 extracted API call
    long_id = fetch_long_id(longid_api, headers)

    if not long_id:
        get_access_token(company_doc.name)
        company_doc.reload()
        token = company_doc.custom_bearer_token
        headers["Authorization"] = f"Bearer {token}"
        long_id = fetch_long_id(longid_api, headers)

    if not long_id:
        frappe.log_error(
            "longId not found from LHDN — skipping QR generation",
            "QR Generation Skipped",
        )
        return None

    if company_doc.custom_integration_type == "Sandbox":
        verification_url = (
            f"https://preprod.myinvois.hasil.gov.my/{uuid}/share/{long_id}"
        )
    else:
        verification_url = f"https://myinvois.hasil.gov.my/{uuid}/share/{long_id}"

    # 🔹 extracted QR creation
    return create_qr_image(sales_invoice_doc, verification_url)

def attach_qr_code_to_sales_invoice(sales_invoice_doc, qr_image_path):
    """Attach the QR code image to the Sales Invoice"""

    if not qr_image_path or not os.path.exists(qr_image_path):
        frappe.throw(_(f"QR file not found at path: {qr_image_path}"))
    with open(qr_image_path, "rb") as qr_file:  # nosemgrep: frappe-semgrep-rules.rules.security.frappe-security-file-traversal
        qr_content = qr_file.read()
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
    sales_invoice_doc.db_set("custom_einvoice_qr", qr_file_doc.file_url)
    sales_invoice_doc.notify_update()



def delayed_qr_generation(sales_invoice_name):
    """Background job: generate and attach QR after delay."""
    try:
        frappe.log_error(
            f"Started delayed QR for: {sales_invoice_name}", "QR Job Triggered"
        )

        sales_invoice_doc = frappe.get_doc("Purchase Invoice", sales_invoice_name)

        qr_image_path = generate_qr_code(sales_invoice_doc)
        if qr_image_path:
            attach_qr_code_to_sales_invoice(sales_invoice_doc, qr_image_path)
        else:
            frappe.log_error(
                "QR path None", f"QR not generated for {sales_invoice_name}"
            )
    except Exception as e:
        frappe.log_error(str(e), "Delayed QR generation failed")


def after_submit(sales_invoice_doc, _method=None):
    """Run QR generation after submit if no QR already attached."""
    try:
        existing_qr = frappe.get_all(
            "File",
            filters={
                "attached_to_doctype": sales_invoice_doc.doctype,
                "attached_to_name": sales_invoice_doc.name,
                "file_name": ["like", f"QR_{sales_invoice_doc.name}.png"],
            },
        )
        if not existing_qr:
            frappe.log_error(
                f"Enqueueing QR for {sales_invoice_doc.name}", "QR After Submit"
            )
            frappe.enqueue(
                "myinvois_erpgulf.myinvois_erpgulf.purchase_invoice.delayed_qr_generation",
                queue="long",
                timeout=300,
                now=False,
                sales_invoice_name=sales_invoice_doc.name,
            )
    except Exception as e:
        frappe.log_error(str(e), "QR After Submit Hook Error")
