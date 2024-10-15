import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timezone
import frappe
import json


def create_invoice_with_extensions():
                
            try:
                invoice = ET.Element("Invoice", {
                    "xmlns": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
                    "xmlns:cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                    "xmlns:cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                    "xmlns:ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
                })
                return invoice
            except Exception as e:
                frappe.msgprint(f"Errorcreate invoice extensions: {str(e)}")


def create_element(parent, tag, text=None, attributes=None):
    element = ET.SubElement(parent, tag, attributes or {})
    if text:
        element.text = text
    return element

def get_current_utc_datetime():
    current_datetime_utc = datetime.now(timezone.utc)
    formatted_date = current_datetime_utc.strftime('%Y-%m-%d')
    formatted_time = current_datetime_utc.strftime('%H:%M:%SZ')
    return formatted_date, formatted_time

def salesinvoice_data(invoice, sales_invoice_doc):
    try:
        create_element(invoice, "cbc:ID", str(sales_invoice_doc.name))

        formatted_date, formatted_time = get_current_utc_datetime()
        create_element(invoice, "cbc:IssueDate", formatted_date)
        create_element(invoice, "cbc:IssueTime", formatted_time)

        invoice_type_code = "01" if sales_invoice_doc.is_return == 0 else "02"
        create_element(invoice, "cbc:InvoiceTypeCode", invoice_type_code, {"listVersionID": "1.0"})

        create_element(invoice, "cbc:DocumentCurrencyCode", "MYR")  # or sales_invoice_doc.currency
        create_element(invoice, "cbc:TaxCurrencyCode", "MYR")

        invoice_Period = create_element(invoice, "cac:InvoicePeriod")
        create_element(invoice_Period, "cbc:StartDate", str(sales_invoice_doc.posting_date))
        create_element(invoice_Period, "cbc:EndDate", str(sales_invoice_doc.due_date))
        create_element(invoice_Period, "cbc:Description", "Monthly")

    except Exception as e:
        frappe.msgprint(f"Error sales invoice data: {str(e)}")

def company_data(invoice, sales_invoice_doc):
    try:

        settings = frappe.get_doc('LHDN Malaysia Setting')
        account_supplier_party = ET.SubElement(invoice, "cac:AccountingSupplierParty")
        party_ = ET.SubElement(account_supplier_party, "cac:Party")
        cbc_IndClaCode = ET.SubElement(party_, "cbc:IndustryClassificationCode", name="Other information technology service activities n.e.c.")
        cbc_IndClaCode.text = "62099" 
        party_identification_1 = ET.SubElement(party_, "cac:PartyIdentification")
        id_val_1 = ET.SubElement(party_identification_1, "cbc:ID", schemeID="TIN")
        id_val_1.text = str(settings.company_tin_number)

        partyid_2 = ET.SubElement(party_, "cac:PartyIdentification")
        value_id = ET.SubElement(partyid_2, "cbc:ID", schemeID=str(settings.company_id_type))
        value_id.text = str(settings.company_id_value)
        
        address_list = frappe.get_list(
            "Address", 
            filters={"is_your_company_address": "1"}, 
            fields=["address_line1", "address_line2", "city", "pincode", "state", "phone", "email_id"]
        )

        if len(address_list) == 0:
            frappe.throw("Invoice requires a proper address. Please add your company address in the Address field.")

        for address in address_list:
    
            post_add = ET.SubElement(party_, "cac:PostalAddress")
            city_name = ET.SubElement(post_add, "cbc:CityName")
            city_name.text = address.city

            postal_zone = ET.SubElement(post_add, "cbc:PostalZone")
            postal_zone.text = address.pincode

            cntry_subentity_cod = ET.SubElement(post_add, "cbc:CountrySubentityCode")
            cntry_subentity_cod.text = address.state

           
            if address.address_line1:
                add_line1 = ET.SubElement(post_add, "cac:AddressLine")
                line_val = ET.SubElement(add_line1, "cbc:Line")
                line_val.text = address.address_line1

            if address.address_line2:
                add_line2 = ET.SubElement(post_add, "cac:AddressLine")
                line2_val = ET.SubElement(add_line2, "cbc:Line")
                line2_val.text = address.address_line2

            combined_city_pincode = f"{address.city}, {address.pincode}"
            add_line3 = ET.SubElement(post_add, "cac:AddressLine")
            line_3_val = ET.SubElement(add_line3, "cbc:Line")
            line_3_val.text = combined_city_pincode


            cntry = ET.SubElement(post_add, "cac:Country")
            idntfn_cod = ET.SubElement(cntry, "cbc:IdentificationCode", listAgencyID="6", listID="ISO3166-1")
            idntfn_cod.text = "MYS"

        party_legal_entity = ET.SubElement(party_, "cac:PartyLegalEntity")
        reg_name = ET.SubElement(party_legal_entity, "cbc:RegistrationName")
        reg_name.text = sales_invoice_doc.company

        cac_Contact = ET.SubElement(party_, "cac:Contact")

        if address.get("phone"):
            tele = ET.SubElement(cac_Contact, "cbc:Telephone")
            tele.text = address.phone

        if address.get("email_id"):
            mail = ET.SubElement(cac_Contact, "cbc:ElectronicMail")
            mail.text = address.email_id

    except Exception as e:
        frappe.throw(f"Error in company data generation: {str(e)}")


# Create billing reference
# def create_billing_reference(invoice):
#             try:


#                 cac_BillingReference = ET.SubElement(invoice, "cac:BillingReference")
#                 cac_AdditionalDocumentReference = ET.SubElement(cac_BillingReference, "cac:AdditionalDocumentReference")
#                 cbc_ID = ET.SubElement(cac_AdditionalDocumentReference, "cbc:ID")
#                 cbc_ID.text = "IV0000010178689"

#             except Exception as e:
#                 frappe.msgprint(f"Error create billing: {str(e)}")




def customer_data(invoice,sales_invoice_doc):
            try:
                    settings = frappe.get_doc('LHDN Malaysia Setting')
                    customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                    accounting_customer_party = ET.SubElement(invoice, "cac:AccountingCustomerParty")
                    cac_Party = ET.SubElement(accounting_customer_party, "cac:Party")

                    party_id_1 = ET.SubElement(cac_Party, "cac:PartyIdentification")
                    prty_id = ET.SubElement(party_id_1, "cbc:ID", schemeID="TIN")
                    prty_id.text = settings.customer_tin_number

                    party_Identifn_2 = ET.SubElement(cac_Party, "cac:PartyIdentification")
                    id_party2 = ET.SubElement(party_Identifn_2, "cbc:ID", schemeID=settings.customer_id_type)
                    id_party2.text = settings.customer_id_value


                    if int(frappe.__version__.split('.')[0]) == 13:
                        address = frappe.get_doc("Address", sales_invoice_doc.customer_address)    
                    else:
                        address = frappe.get_doc("Address", customer_doc.customer_primary_address)
                    posta_address = ET.SubElement(cac_Party, "cac:PostalAddress")
                    name_city = ET.SubElement(posta_address, "cbc:CityName")
                    name_city.text = address.city
                    post_zone = ET.SubElement(posta_address, "cbc:PostalZone")
                    post_zone.text = address.pincode 
                    cntry_sub_cod = ET.SubElement(posta_address, "cbc:CountrySubentityCode")
                    cntry_sub_cod.text = address.state

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

                    cac_Country = ET.SubElement(posta_address, "cac:Country")
                    idntfn_code_val= ET.SubElement(cac_Country, "cbc:IdentificationCode", listAgencyID="6", listID="ISO3166-1")
                    idntfn_code_val.text = "MYS"

                    party_legalEntity = ET.SubElement(cac_Party, "cac:PartyLegalEntity")
                    reg_name_val = ET.SubElement(party_legalEntity, "cbc:RegistrationName")
                    reg_name_val.text = sales_invoice_doc.customer
                    
                    cac_Contact = ET.SubElement(cac_Party, "cac:Contact")
                    tele_party = ET.SubElement(cac_Contact, "cbc:Telephone")
                    tele_party.text = str(address.phone)
                    
                    mail_party = ET.SubElement(cac_Contact, "cbc:ElectronicMail")
                    mail_party.text = str(address.email_id)

                
            except Exception as e:
                frappe.throw(f"Error customer data: {str(e)}")



def tax_total(invoice,sales_invoice_doc):
        try:
            taxable_amount = sales_invoice_doc.base_total - sales_invoice_doc.get('base_discount_amount', 0.0)
            cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
            taxamnt = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
            tax_amount_without_retention =  taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100
            taxamnt.text=f"{abs(round(tax_amount_without_retention, 2)):.2f}"
           

            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            taxable_amnt = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR")
            taxable_amnt.text = str(abs(round(taxable_amount, 2)))
            TaxAmnt = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR")
            TaxAmnt.text =str(abs(round(taxable_amount * float(sales_invoice_doc.taxes[0].rate) / 100, 2)))

            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cat_id_val = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cat_id_val.text = str(sales_invoice_doc.custom_zatca_tax_category)
            prct = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            prct.text =str(sales_invoice_doc.taxes[0].rate)
            exemption = ET.SubElement(cac_TaxCategory, "cbc:TaxExemptionReason")
            if (sales_invoice_doc.custom_zatca_tax_category) == "E":
                exemption.text = sales_invoice_doc.custom_exemption_code
            else:
                exemption.text = "NA"

            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            taxscheme_id = ET.SubElement(cac_TaxScheme, "cbc:ID",  schemeAgencyID="6",schemeID="UN/ECE 5153")
            taxscheme_id.text = "OTH"
        except Exception as e:
                frappe.throw(f"Error tax total: {str(e)}")
     
def tax_total_with_template(invoice, sales_invoice_doc):
    try:
        tax_category_totals = {}

        for item in sales_invoice_doc.items:
            item_tax_template = frappe.get_doc('Item Tax Template', item.item_tax_template)
            zatca_tax_category = item_tax_template.custom_zatca_tax_category

            if zatca_tax_category not in tax_category_totals:
                tax_category_totals[zatca_tax_category] = {
                    "taxable_amount": 0,
                    "tax_amount": 0,
                    "tax_rate": item_tax_template.taxes[0].tax_rate if item_tax_template.taxes else 0,
                    "exemption_reason_code": item_tax_template.custom_exemption_reason_code
                }

            if sales_invoice_doc.currency == "SAR":
                tax_category_totals[zatca_tax_category]["taxable_amount"] += abs(item.base_amount)
            else:
                tax_category_totals[zatca_tax_category]["taxable_amount"] += abs(item.amount)

   
        first_tax_category = next(iter(tax_category_totals))
        base_discount_amount = sales_invoice_doc.get('discount_amount', 0.0)
        tax_category_totals[first_tax_category]["taxable_amount"] -= base_discount_amount

       
        for zatca_tax_category in tax_category_totals:
            taxable_amount = tax_category_totals[zatca_tax_category]["taxable_amount"]
            tax_rate = tax_category_totals[zatca_tax_category]["tax_rate"]
            tax_category_totals[zatca_tax_category]["tax_amount"] = abs(
                round(taxable_amount * tax_rate / 100, 2)
            )

    
        total_tax = sum(
            totals["tax_amount"] for totals in tax_category_totals.values()
        )
        tax_amount_without_retention_sar = round(abs(total_tax), 2)

        cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
        cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
        cbc_TaxAmount.text = str(tax_amount_without_retention_sar)

    
        for zatca_tax_category, totals in tax_category_totals.items():
            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR")
            cbc_TaxableAmount.text = str(round(totals["taxable_amount"], 2))

            cbc_TaxAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR")
            cbc_TaxAmount.text = str(round(totals["tax_amount"], 2))

            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cbc_ID.text = zatca_tax_category

            cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            cbc_Percent.text = f"{totals['tax_rate']:.2f}"

            cbc_TaxExemptionReason = ET.SubElement(cac_TaxCategory, "cbc:TaxExemptionReason")
            if zatca_tax_category == "E":
                cbc_TaxExemptionReason.text = item_tax_template.custom_exemption_reason_code
            else:
                cbc_TaxExemptionReason.text = "NA"

            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            cbc_TaxScheme_ID = ET.SubElement(cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153")
            cbc_TaxScheme_ID.text = "OTH"

    except Exception as e:
        frappe.throw(f"Error in tax total calculation: {str(e)}")


def legal_monetary_total(invoice,sales_invoice_doc):
        try:

            taxable_amount_1 = sales_invoice_doc.total - sales_invoice_doc.get('discount_amount', 0.0)
            tax_amount_without_retention = taxable_amount_1 * (sales_invoice_doc.taxes[0].rate) / 100
            legal_monetary_total = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
            line_ext_amnt = ET.SubElement(legal_monetary_total, "cbc:LineExtensionAmount", currencyID="MYR")
            line_ext_amnt.text =str(abs(sales_invoice_doc.total))
            tax_exc_ = ET.SubElement(legal_monetary_total, "cbc:TaxExclusiveAmount", currencyID="MYR")
            tax_exc_.text = str(abs(sales_invoice_doc.total - sales_invoice_doc.get('discount_amount', 0.0)))
            tax_inc = ET.SubElement(legal_monetary_total, "cbc:TaxInclusiveAmount", currencyID="MYR")
            tax_inc.text = str(abs(sales_invoice_doc.total - sales_invoice_doc.get('discount_amount', 0.0)) + abs(round(tax_amount_without_retention, 2)))
            allw_tot = ET.SubElement(legal_monetary_total, "cbc:AllowanceTotalAmount", currencyID="MYR")
            allw_tot.text =  str(abs(sales_invoice_doc.get('discount_amount', 0.0)))
            payable_ = ET.SubElement(legal_monetary_total, "cbc:PayableAmount", currencyID="MYR")
            payable_.text =  str(abs(sales_invoice_doc.total - sales_invoice_doc.get('discount_amount', 0.0)) + abs(round(tax_amount_without_retention, 2)))

        except Exception as e:
                frappe.throw(f"Error legal monetary: {str(e)}")

def get_Tax_for_Item(full_string,item):
                    try:                                          
                        data = json.loads(full_string)
                        tax_percentage=data.get(item,[0,0])[0]
                        tax_amount = data.get(item, [0, 0])[1]
                        return tax_amount,tax_percentage
                    except Exception as e:
                            frappe.throw("error occured in tax for item"+ str(e) )

def invoice_line_item(invoice, sales_invoice_doc):
    try:
        for single_item in sales_invoice_doc.items:
            cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
            cbc_ID = ET.SubElement(cac_InvoiceLine, "cbc:ID")
            cbc_ID.text = str(single_item.idx)
            cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity", unitCode="H87")
            cbc_InvoicedQuantity.text = str(abs(single_item.qty))
            cbc_LineExtensionAmount = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount", currencyID="MYR")
            cbc_LineExtensionAmount.text = str(abs(single_item.amount))

            discount_amount = abs(single_item.get('discount_amount', 0.0))
            if discount_amount > 0:
                cac_AllowanceCharge = ET.SubElement(cac_InvoiceLine, "cac:AllowanceCharge")
                cbc_ChargeIndicator = ET.SubElement(cac_AllowanceCharge, "cbc:ChargeIndicator")
                cbc_ChargeIndicator.text = "false"
                cbc_AllowanceChargeReason = ET.SubElement(cac_AllowanceCharge, "cbc:AllowanceChargeReason")
                cbc_AllowanceChargeReason.text = "Item Discount"
                cbc_MultiplierFactorNumeric = ET.SubElement(cac_AllowanceCharge, "cbc:MultiplierFactorNumeric")
                cbc_MultiplierFactorNumeric.text = "1"
                cbc_Amount = ET.SubElement(cac_AllowanceCharge, "cbc:Amount", currencyID="MYR")
                cbc_Amount.text = str(discount_amount)

           
            cac_TaxTotal = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
            cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
            cbc_TaxAmount.text = str(abs(round((sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2)))

            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR")
            cbc_TaxableAmount.text = str(abs(single_item.amount - discount_amount))
            cbc_TaxAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR")
            cbc_TaxAmount.text = str(abs(round((sales_invoice_doc.taxes[0].rate) * single_item.amount / 100, 2)))

            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cbc_ID.text = str(sales_invoice_doc.custom_zatca_tax_category)
            cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            cbc_Percent.text = str(sales_invoice_doc.taxes[0].rate)
            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            cbc_TaxScheme_ID = ET.SubElement(cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153")
            cbc_TaxScheme_ID.text = "OTH"

            
            cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
            cbc_Description = ET.SubElement(cac_Item, "cbc:Description")
            cbc_Description.text = str(single_item.description)

            cac_CommodityClassification = ET.SubElement(cac_Item, "cac:CommodityClassification")
            cbc_ItemClassificationCode = ET.SubElement(cac_CommodityClassification, "cbc:ItemClassificationCode", listID="CLASS")
            cbc_ItemClassificationCode.text =str(sales_invoice_doc.custom_item_classification_code_)

           
            cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
            cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount", currencyID="MYR")
            cbc_PriceAmount.text = str(abs(single_item.base_price_list_rate) - discount_amount)

            
            cac_ItemPriceExtension = ET.SubElement(cac_InvoiceLine, "cac:ItemPriceExtension")
            cbc_Amount = ET.SubElement(cac_ItemPriceExtension, "cbc:Amount", currencyID="MYR")
            cbc_Amount.text = str(abs(single_item.base_amount))

    except Exception as e:
        frappe.throw(f"Error in invoice_line: {str(e)}")

def item_data_with_template(invoice,sales_invoice_doc):
       
    try:
        for single_item in sales_invoice_doc.items:
            item_tax_template = frappe.get_doc('Item Tax Template', single_item.item_tax_template)
            item_tax_percentage = item_tax_template.taxes[0].tax_rate if item_tax_template.taxes else 0
            cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
            cbc_ID = ET.SubElement(cac_InvoiceLine, "cbc:ID")
            cbc_ID.text = str(single_item.idx)
            cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity", unitCode="H87")
            cbc_InvoicedQuantity.text = str(abs(single_item.qty))
            cbc_LineExtensionAmount = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount", currencyID="MYR")
            cbc_LineExtensionAmount.text = str(abs(single_item.amount))

            discount_amount = abs(single_item.get('discount_amount', 0.0))
            if discount_amount > 0:
                cac_AllowanceCharge = ET.SubElement(cac_InvoiceLine, "cac:AllowanceCharge")
                cbc_ChargeIndicator = ET.SubElement(cac_AllowanceCharge, "cbc:ChargeIndicator")
                cbc_ChargeIndicator.text = "false"
                cbc_AllowanceChargeReason = ET.SubElement(cac_AllowanceCharge, "cbc:AllowanceChargeReason")
                cbc_AllowanceChargeReason.text = "Item Discount"
                cbc_MultiplierFactorNumeric = ET.SubElement(cac_AllowanceCharge, "cbc:MultiplierFactorNumeric")
                cbc_MultiplierFactorNumeric.text = "1"
                cbc_Amount = ET.SubElement(cac_AllowanceCharge, "cbc:Amount", currencyID="MYR")
                cbc_Amount.text = str(discount_amount)

            
            cac_TaxTotal = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
            cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount", currencyID="MYR")
            cbc_TaxAmount.text =  str(abs(round(item_tax_percentage * single_item.amount / 100, 2)))

            cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
            cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount", currencyID="MYR")
            cbc_TaxableAmount.text = str(abs(single_item.amount - discount_amount))
            cbc_TaxAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount", currencyID="MYR")
            cbc_TaxAmount.text =  str(abs(round(item_tax_percentage * single_item.amount / 100, 2)))

            zatca_tax_category = item_tax_template.custom_zatca_tax_category
            cac_TaxCategory = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
            cbc_ID = ET.SubElement(cac_TaxCategory, "cbc:ID")
            cbc_ID.text = str(zatca_tax_category)
            cbc_Percent = ET.SubElement(cac_TaxCategory, "cbc:Percent")
            cbc_Percent.text = f"{float(item_tax_percentage):.2f}"
            cac_TaxScheme = ET.SubElement(cac_TaxCategory, "cac:TaxScheme")
            cbc_TaxScheme_ID = ET.SubElement(cac_TaxScheme, "cbc:ID", schemeAgencyID="6", schemeID="UN/ECE 5153")
            cbc_TaxScheme_ID.text = "OTH"

            cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
            cbc_Description = ET.SubElement(cac_Item, "cbc:Description")
            cbc_Description.text = str(single_item.description)

            cac_CommodityClassification = ET.SubElement(cac_Item, "cac:CommodityClassification")
            cbc_ItemClassificationCode = ET.SubElement(cac_CommodityClassification, "cbc:ItemClassificationCode", listID="CLASS")
            cbc_ItemClassificationCode.text =str(sales_invoice_doc.custom_item_classification_code_)

            cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
            cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount", currencyID="MYR")
            cbc_PriceAmount.text = str(abs(single_item.base_price_list_rate) - discount_amount)

            cac_ItemPriceExtension = ET.SubElement(cac_InvoiceLine, "cac:ItemPriceExtension")
            cbc_Amount = ET.SubElement(cac_ItemPriceExtension, "cbc:Amount", currencyID="MYR")
            cbc_Amount.text = str(abs(single_item.base_amount))

    except Exception as e:
        frappe.throw(f"Error in invoice_line: {str(e)}")




def xml_structuring(invoice,sales_invoice_doc):
  
    raw_xml = ET.tostring(invoice, encoding='utf-8', method='xml').decode('utf-8')
    with open(frappe.local.site + "/private/files/create.xml", 'w') as file:
        file.write(raw_xml)
    try:
                    fileXx = frappe.get_doc(
                        {   "doctype": "File",        
                            "file_type": "xml",  
                            "file_name":  "E-invoice-" + sales_invoice_doc.name + ".xml",
                            "attached_to_doctype":sales_invoice_doc.doctype,
                            "attached_to_name":sales_invoice_doc.name, 
                            "content": raw_xml,
                            "is_private": 1,})
                    fileXx.save()


    except Exception as e:
                    frappe.throw(frappe.get_traceback())
    return raw_xml



