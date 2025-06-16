"""THIS MODULE IS FOR MERGE AND CONSOLIDATE INVOICES"""

import xml.etree.ElementTree as ET
import frappe
from frappe import _
import datetime


NOT_APPLICABLE = "NA"


def customer_data_consolidate(invoice, sales_invoice_doc):
    """Adds the Customer data to the invoice"""
    try:

        customer_doc = frappe.get_doc("Customer", sales_invoice_doc.customer)
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
            schemeID="BRN",
        )
        id_party2.text = NOT_APPLICABLE

        partyid_3 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        value_id3 = ET.SubElement(partyid_3, "cbc:ID", schemeID="SST")
        customer_doc.custom_sst_number = NOT_APPLICABLE

        value_id3.text = NOT_APPLICABLE

        partyid_4 = ET.SubElement(cac_Party, "cac:PartyIdentification")
        value_id4 = ET.SubElement(partyid_4, "cbc:ID", schemeID="TTX")
        value_id4.text = NOT_APPLICABLE
        posta_address = ET.SubElement(cac_Party, "cac:PostalAddress")
        name_city = ET.SubElement(posta_address, "cbc:CityName")
        # name_city.text = NOT_APPLICABLE
        post_zone = ET.SubElement(posta_address, "cbc:PostalZone")
        # post_zone.text = NOT_APPLICABLE
        cntry_sub_cod = ET.SubElement(posta_address, "cbc:CountrySubentityCode")
        # statecode = (address.custom_state_code).split(":")[0]
        # cntry_sub_cod.text = NOT_APPLICABLE
        add_cust_line1 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line1 = ET.SubElement(add_cust_line1, "cbc:Line")
        add_line1.text = NOT_APPLICABLE

        add_cust_line2 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line2 = ET.SubElement(add_cust_line2, "cbc:Line")
        # add_line2.text = NOT_APPLICABLE

        # combined_city_pincode = f"{address.city}, {address.pincode}"
        add_cust_line3 = ET.SubElement(posta_address, "cac:AddressLine")
        add_line3 = ET.SubElement(add_cust_line3, "cbc:Line")
        # add_line3.text = NOT_APPLICABLE

        cnty_customer = ET.SubElement(posta_address, "cac:Country")
        idntfn_code_val = ET.SubElement(
            cnty_customer,
            "cbc:IdentificationCode",
            listAgencyID="6",
            listID="ISO3166-1",
        )
        idntfn_code_val.text = "MYS"

        party_legalentity = ET.SubElement(cac_Party, "cac:PartyLegalEntity")
        reg_name_val = ET.SubElement(party_legalentity, "cbc:RegistrationName")
        reg_name_val.text = "Consolidated Buyers"  # sales_invoice_doc.customer

        cont_customer = ET.SubElement(cac_Party, "cac:Contact")
        tele_party = ET.SubElement(cont_customer, "cbc:Telephone")
        tele_party.text = "NA"
        mail_party = ET.SubElement(cont_customer, "cbc:ElectronicMail")
        mail_party.text = "NA"
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error customer data: {str(e)}"))
        return None


def delivery_data_consolidate(invoice, sales_invoice_doc):
    "" "Adds the Delivery data to the invoice" ""
    try:
        customer_doc = frappe.get_doc("Customer", sales_invoice_doc.customer)

        delivery = ET.SubElement(invoice, "cac:Delivery")
        delivery_party = ET.SubElement(delivery, "cac:DeliveryParty")

        party_id_tin = ET.SubElement(delivery_party, "cac:PartyIdentification")
        tin_id = ET.SubElement(party_id_tin, "cbc:ID", schemeID="TIN")
        tin_id.text = str(customer_doc.custom_customer_tin_number)

        party_id_brn = ET.SubElement(delivery_party, "cac:PartyIdentification")
        brn_id = ET.SubElement(
            party_id_brn,
            "cbc:ID",
            schemeID="BRN",
        )
        brn_id.text = NOT_APPLICABLE

        postal_address = ET.SubElement(delivery_party, "cac:PostalAddress")
        city_name = ET.SubElement(postal_address, "cbc:CityName")
        # city_name.text = NOT_APPLICABLE

        postal_zone = ET.SubElement(postal_address, "cbc:PostalZone")

        # postal_zone.text = NOT_APPLICABLE

        country_subentity_code = ET.SubElement(
            postal_address, "cbc:CountrySubentityCode"
        )
        # statecode = NOT_APPLICABLE
        # country_subentity_code.text = statecode

        address_line1 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        address_line1.text = NOT_APPLICABLE

        address_line2 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        # address_line2.text =

        address_line3 = ET.SubElement(
            ET.SubElement(postal_address, "cac:AddressLine"), "cbc:Line"
        )
        # address_line3.text = NOT_APPLICABLE

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
        registration_name.text = "Consolidated Buyers"  # sales_invoice_doc.customer
        return invoice
    except Exception as e:
        frappe.throw(_(f"Error in customer_data: {str(e)}"))
        return None


# @frappe.whitelist(allow_guest=True)
# def merge_sales_invoices(invoice_numbers):
#     """
#     Merge multiple Sales Invoices into a single consolidated invoice.
#     The merged invoice will be assigned to customer 'General Public'.

#     Args:
#         invoice_numbers (list): List of Sales Invoice names to be merged.

#     Returns:
#         str: Name of the newly created merged Sales Invoice.
#     """
#     if isinstance(invoice_numbers, str):
#         invoice_numbers = frappe.parse_json(invoice_numbers)

#     if not invoice_numbers or len(invoice_numbers) < 2:
#         frappe.throw(_("Please select at least two Sales Invoices to merge."))

#     # Fetch all Sales Invoices
#     sales_invoices = frappe.get_all(
#         "Sales Invoice",
#         filters={"name": ["in", invoice_numbers]},
#         fields=[
#             "name",
#             "customer",
#             "company",
#             "currency",
#             "conversion_rate",
#             "posting_date",
#             "due_date",
#             "customer_name",
#             "customer_group",
#             "territory",
#             "is_pos",
#             "debit_to",
#             "docstatus",
#         ],
#     )

#     if not sales_invoices:
#         frappe.throw(_("No valid Sales Invoices found."))

#     base_invoice = sales_invoices[0]

#     # Create new Sales Invoice
#     new_invoice = frappe.get_doc(
#         {
#             "doctype": "Sales Invoice",
#             "customer": "General Public",
#             "customer_name": "General Public",
#             "company": base_invoice["company"],
#             "currency": base_invoice["currency"],
#             "conversion_rate": base_invoice["conversion_rate"],
#             "posting_date": min([inv["posting_date"] for inv in sales_invoices]),
#             "due_date": max([inv["due_date"] for inv in sales_invoices]),
#             "customer_group": base_invoice["customer_group"],
#             "territory": base_invoice["territory"],
#             "is_pos": base_invoice["is_pos"],
#             "debit_to": base_invoice["debit_to"],
#             "is_return": 0,
#             "custom_is_submit_to_lhdn": 1,
#             "items": [],
#             "taxes": [],
#             "remarks": f"Merged from invoices: {', '.join(invoice_numbers)}",
#             "custom_submission_time": datetime.datetime.now(
#                 datetime.timezone.utc
#             ).strftime("%Y-%m-%dT%H:%M:%SZ"),
#         }
#     )

#     # Consolidate items
#     item_dict = {}
#     for inv in sales_invoices:
#         invoice_items = frappe.get_all(
#             "Sales Invoice Item",
#             filters={"parent": inv["name"]},
#             fields=[
#                 "item_code",
#                 "item_name",
#                 "description",
#                 "qty",
#                 "rate",
#                 "amount",
#                 "income_account",
#                 "cost_center",
#                 "custom_item_classification_codes",  # include field
#             ],
#         )
#         for item in invoice_items:
#             item_key = (item["item_code"], item["rate"])
#             if item_key in item_dict:
#                 item_dict[item_key]["qty"] += item["qty"]
#                 item_dict[item_key]["amount"] += item["amount"]
#             else:
#                 new_item = item.copy()
#                 new_item["custom_item_classification_codes"] = (
#                     "004:Consolidated e-Invoice"
#                 )
#                 item_dict[item_key] = new_item

#     for item in item_dict.values():
#         new_invoice.append("items", item)

#     # Consolidate taxes
#     tax_dict = {}
#     for inv in sales_invoices:
#         invoice_taxes = frappe.get_all(
#             "Sales Taxes and Charges",
#             filters={"parent": inv["name"]},
#             fields=["charge_type", "account_head", "description", "rate", "tax_amount"],
#         )
#         for tax in invoice_taxes:
#             tax_key = (tax["account_head"], tax["charge_type"])
#             if tax_key in tax_dict:
#                 tax_dict[tax_key]["tax_amount"] += tax["tax_amount"]
#             else:
#                 tax_dict[tax_key] = tax.copy()

#     for tax in tax_dict.values():
#         new_invoice.append("taxes", tax)

#     # Ensure all item_classification_code fields are set properly
#     for row in new_invoice.items:
#         row.custom_item_classification_codes = "004:Consolidated e-Invoice"

#     # Save and submit new invoice
#     new_invoice.insert()
#     new_invoice.submit()

#     # Cancel or delete original invoices
#     for inv in sales_invoices:
#         doc = frappe.get_doc("Sales Invoice", inv["name"])
#         doc.custom_consolidate_invoice_number = new_invoice.name
#         doc.save(ignore_permissions=True)
#     #     if doc.docstatus == 1:
#     #         doc.cancel()
#     #     elif doc.docstatus == 0:
#     #         doc.delete()

#     return new_invoice.name


@frappe.whitelist(allow_guest=True)
def merge_sales_invoices(invoice_numbers):
    """
    Merge multiple Sales Invoices into a single consolidated invoice.
    Excludes items where amount > 10,000.
    Creates separate invoices for such items, preserving original customer and tax details.
    """
    if isinstance(invoice_numbers, str):
        invoice_numbers = frappe.parse_json(invoice_numbers)

    if not invoice_numbers or len(invoice_numbers) < 2:
        frappe.throw(_("Please select at least two Sales Invoices to merge."))

    sales_invoices = frappe.get_all(
        "Sales Invoice",
        filters={"name": ["in", invoice_numbers]},
        fields=[
            "name",
            "customer",
            "company",
            "currency",
            "conversion_rate",
            "posting_date",
            "due_date",
            "customer_name",
            "customer_group",
            "territory",
            "is_pos",
            "debit_to",
            "docstatus",
        ],
    )

    if not sales_invoices:
        frappe.throw(_("No valid Sales Invoices found."))

    sales_invoices = frappe.get_all(
        "Sales Invoice",
        filters={
            "name": ["in", invoice_numbers],
            "custom_consolidate_invoice_number": ["is", "not set"],
        },
        fields=[
            "name",
            "customer",
            "company",
            "currency",
            "conversion_rate",
            "posting_date",
            "due_date",
            "customer_name",
            "customer_group",
            "territory",
            "is_pos",
            "debit_to",
            "docstatus",
        ],
    )

    already_merged = [
        name
        for name in invoice_numbers
        if name not in [inv["name"] for inv in sales_invoices]
    ]

    if already_merged:
        frappe.throw(
            _(
                "The following invoices are already consolidated and cannot be merged again:"
            )
            + "<br>"
            + "<br>".join(already_merged)
        )
    base_invoice = sales_invoices[0]

    new_invoice = frappe.get_doc(
        {
            "doctype": "Sales Invoice",
            "customer": "General Public",
            "customer_name": "General Public",
            "company": base_invoice["company"],
            "currency": base_invoice["currency"],
            "conversion_rate": base_invoice["conversion_rate"],
            "posting_date": min([inv["posting_date"] for inv in sales_invoices]),
            "due_date": max([inv["due_date"] for inv in sales_invoices]),
            "customer_group": base_invoice["customer_group"],
            "territory": base_invoice["territory"],
            "is_pos": base_invoice["is_pos"],
            "debit_to": base_invoice["debit_to"],
            "is_return": 0,
            "custom_is_submit_to_lhdn": 1,
            "items": [],
            "taxes": [],
            "remarks": f"Merged from invoices: {', '.join(invoice_numbers)}",
            "custom_submission_time": datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    item_dict = {}
    excluded_items_map = []

    for inv in sales_invoices:
        invoice_items = frappe.get_all(
            "Sales Invoice Item",
            filters={"parent": inv["name"]},
            fields=[
                "item_code",
                "item_name",
                "description",
                "qty",
                "rate",
                "amount",
                "income_account",
                "cost_center",
                "custom_item_classification_codes",
            ],
        )
        for item in invoice_items:
            if item["amount"] > 10000:
                excluded_items_map.append({"invoice": inv, "item": item})
                continue

            item_key = (item["item_code"], item["rate"])
            if item_key in item_dict:
                item_dict[item_key]["qty"] += item["qty"]
                item_dict[item_key]["amount"] += item["amount"]
            else:
                new_item = item.copy()
                new_item["custom_item_classification_codes"] = (
                    "004:Consolidated e-Invoice"
                )
                item_dict[item_key] = new_item

    if not item_dict:
        frappe.throw(
            _(
                "All items were excluded because their amount exceeded 10,000. Consolidated invoice not created."
            )
        )

    for item in item_dict.values():
        new_invoice.append("items", item)

    # Consolidate taxes from original invoices
    tax_dict = {}
    for inv in sales_invoices:
        invoice_taxes = frappe.get_all(
            "Sales Taxes and Charges",
            filters={"parent": inv["name"]},
            fields=["charge_type", "account_head", "description", "rate", "tax_amount"],
        )
        for tax in invoice_taxes:
            tax_key = (tax["account_head"], tax["charge_type"])
            if tax_key in tax_dict:
                tax_dict[tax_key]["tax_amount"] += tax["tax_amount"]
            else:
                tax_dict[tax_key] = tax.copy()

    for tax in tax_dict.values():
        new_invoice.append("taxes", tax)

    # Set item classification codes
    for row in new_invoice.items:
        row.custom_item_classification_codes = "004:Consolidated e-Invoice"

    new_invoice.insert()

    new_invoice.submit()

    # Update original invoices
    for inv in sales_invoices:
        doc = frappe.get_doc("Sales Invoice", inv["name"])
        doc.custom_consolidate_invoice_number = new_invoice.name
        doc.save(ignore_permissions=True)

    # Create separate invoices for excluded items
    excluded_items_messages = []
    for entry in excluded_items_map:
        inv = entry["invoice"]
        item = entry["item"]

        original_taxes = frappe.get_all(
            "Sales Taxes and Charges",
            filters={"parent": inv["name"]},
            fields=["charge_type", "account_head", "description", "rate", "tax_amount"],
        )

        new_single_invoice = frappe.get_doc(
            {
                "doctype": "Sales Invoice",
                "customer": inv["customer"],
                "customer_name": inv["customer_name"],
                "company": inv["company"],
                "currency": inv["currency"],
                "conversion_rate": inv["conversion_rate"],
                "posting_date": inv["posting_date"],
                "due_date": inv["due_date"],
                "customer_group": inv["customer_group"],
                "territory": inv["territory"],
                "is_pos": inv["is_pos"],
                "debit_to": inv["debit_to"],
                "is_return": 0,
                "custom_is_submit_to_lhdn": 1,
                "items": [
                    {
                        "item_code": item["item_code"],
                        "item_name": item["item_name"],
                        "description": item["description"],
                        "qty": item["qty"],
                        "rate": item["rate"],
                        "amount": item["amount"],
                        "income_account": item["income_account"],
                        "cost_center": item["cost_center"],
                        "custom_item_classification_codes": item.get(
                            "custom_item_classification_codes", ""
                        ),
                    }
                ],
                "remarks": f"Auto-created from item exceeding 10,000 in invoice {inv['name']}",
                "custom_submission_time": datetime.datetime.now(
                    datetime.timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )

        for tax in original_taxes:
            new_single_invoice.append(
                "taxes",
                {
                    "charge_type": tax["charge_type"],
                    "account_head": tax["account_head"],
                    "description": tax["description"],
                    "rate": tax["rate"],
                    "tax_amount": tax["tax_amount"],
                },
            )

        new_single_invoice.insert()
        new_single_invoice.submit()

        excluded_items_messages.append(
            f"{item['item_code']} (Amount: {item['amount']}) from Invoice: {inv['name']} "
            f"moved to new invoice: {new_single_invoice.name}"
        )

    # Show message with excluded items
    if excluded_items_messages:
        frappe.msgprint(
            _(
                "The following items were excluded from the consolidated invoice because their amount exceeded 10,000. "
                "Individual invoices were created:"
            )
            + "<br>"
            + "<br>".join(excluded_items_messages),
            title=_("Excluded Items"),
            indicator="orange",
        )

    return new_invoice.name
