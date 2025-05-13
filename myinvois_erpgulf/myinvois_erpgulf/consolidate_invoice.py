"""THIS MODULE IS FOR MERGE AND CONSOLIDATE INVOICES"""

import xml.etree.ElementTree as ET
import frappe
from frappe import _
import datetime


NOT_APPLICABLE = "NA"


def company_data_consolidate(invoice, sales_invoice_doc):
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
                _(
                    "Invoice requires a proper address. Please add your company address in the Address field."
                )
            )

        address = address_list[0]  # Select the first address only

        # Create PostalAddress Element
        post_add = ET.SubElement(party_, "cac:PostalAddress")
        ET.SubElement(post_add, "cbc:CityName").text = NOT_APPLICABLE
        ET.SubElement(post_add, "cbc:PostalZone").text = NOT_APPLICABLE
        ET.SubElement(post_add, "cbc:CountrySubentityCode").text = (
            address.custom_state_code
        ).split(":")[0]

        # Address lines
        if address.address_line1:
            add_line1 = ET.SubElement(post_add, "cac:AddressLine")
            ET.SubElement(add_line1, "cbc:Line").text = NOT_APPLICABLE

        if address.address_line2:
            add_line2 = ET.SubElement(post_add, "cac:AddressLine")
            ET.SubElement(add_line2, "cbc:Line").text = NOT_APPLICABLE

        # Combined city and postal code
        combined_city_pincode = f"{address.city}, {address.pincode}"
        add_line3 = ET.SubElement(post_add, "cac:AddressLine")
        ET.SubElement(add_line3, "cbc:Line").text = NOT_APPLICABLE

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

        phone = address.get("phone")
        ET.SubElement(cont_ct, "cbc:Telephone").text = NOT_APPLICABLE

        email = address.get("email_id")

        ET.SubElement(cont_ct, "cbc:ElectronicMail").text = NOT_APPLICABLE

        return invoice

    except (
        frappe.DoesNotExistError,
        frappe.ValidationError,
        AttributeError,
        KeyError,
    ) as e:
        frappe.throw(_(f"Error in company data generation: {str(e)}"))
        return None


# @frappe.whitelist()
# def merge_sales_invoices(invoice_numbers):
#     """
#     Merge multiple Sales Invoices into a single consolidated invoice.

#     Args:
#         invoice_numbers (list): List of Sales Invoice names to be merged.

#     Returns:
#         str: Name of the newly created merged Sales Invoice.
#     """
#     if isinstance(invoice_numbers, str):
#         invoice_numbers = frappe.parse_json(invoice_numbers)

#     if not invoice_numbers or len(invoice_numbers) < 2:
#         frappe.throw("Please select at least two Sales Invoices to merge.")

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
#         frappe.throw("No valid Sales Invoices found.")

#     # Ensure all invoices belong to the same customer
#     customer_set = {inv["customer"] for inv in sales_invoices}
#     if len(customer_set) > 1:
#         frappe.throw("Cannot merge invoices from different customers.")

#     # Use the first invoice as a base
#     base_invoice = sales_invoices[0]

#     # Create a new Sales Invoice
#     new_invoice = frappe.get_doc(
#         {
#             "doctype": "Sales Invoice",
#             "customer": "General Public",
#             "company": base_invoice["company"],
#             "currency": base_invoice["currency"],
#             "conversion_rate": base_invoice["conversion_rate"],
#             "posting_date": min([inv["posting_date"] for inv in sales_invoices]),
#             "due_date": max([inv["due_date"] for inv in sales_invoices]),
#             "customer_name": base_invoice["customer_name"],
#             "customer_group": base_invoice["customer_group"],
#             "territory": base_invoice["territory"],
#             "is_pos": base_invoice["is_pos"],
#             "debit_to": base_invoice["debit_to"],
#             "is_return": 0,
#             "items": [],
#             "taxes": [],
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
#             ],
#         )
#         for item in invoice_items:
#             item_key = (
#                 item["item_code"],
#                 item["rate"],
#             )  # Merge same items with the same rate
#             if item_key in item_dict:
#                 item_dict[item_key]["qty"] += item["qty"]
#                 item_dict[item_key]["amount"] += item["amount"]
#             else:
#                 item_dict[item_key] = item.copy()

#     # Append merged items
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

#     # Append merged taxes
#     for tax in tax_dict.values():
#         new_invoice.append("taxes", tax)

#     # Save and Submit the new invoice
#     new_invoice.insert()
#     new_invoice.submit()

#     # Cancel or Delete original invoices
#     for inv in sales_invoices:
#         doc = frappe.get_doc("Sales Invoice", inv["name"])
#         if doc.docstatus == 1:
#             doc.cancel()  # Cancel if submitted
#         elif doc.docstatus == 0:
#             doc.delete()  # Delete if in draft

#     return new_invoice.name

import datetime
import frappe
from frappe import _


def get_company_account(account, target_company):
    """
    Ensure the account belongs to the target company.
    If not, find an account with the same account name under the target company.
    """
    account_doc = frappe.get_doc("Account", account)
    if account_doc.company == target_company:
        return account

    account_name = account_doc.account_name
    matching_accounts = frappe.get_all(
        "Account",
        filters={"account_name": account_name, "company": target_company},
        limit=1,
    )
    if matching_accounts:
        return matching_accounts[0].name

    frappe.throw(
        _(f"No matching account found for '{account}' in company '{target_company}'")
    )


def get_company_cost_center(cost_center, target_company):
    """
    Ensure the cost center belongs to the target company.
    If not, find a cost center with the same name under the target company.
    """
    cost_center_doc = frappe.get_doc("Cost Center", cost_center)
    if cost_center_doc.company == target_company:
        return cost_center

    cost_center_name = cost_center_doc.cost_center_name
    matching_centers = frappe.get_all(
        "Cost Center",
        filters={"cost_center_name": cost_center_name, "company": target_company},
        limit=1,
    )
    if matching_centers:
        return matching_centers[0].name

    frappe.throw(
        _(
            f"No matching cost center found for '{cost_center}' in company '{target_company}'"
        )
    )


@frappe.whitelist()
def merge_sales_invoices(invoice_numbers):
    """
    Merge multiple Sales Invoices into a single consolidated invoice.
    The merged invoice will be assigned to company 'General Public' but keep the customer of the original invoices.

    Args:
        invoice_numbers (list): List of Sales Invoice names to be merged.

    Returns:
        str: Name of the newly created merged Sales Invoice.
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
            "customer_name",
            "company",
            "currency",
            "conversion_rate",
            "posting_date",
            "due_date",
            "customer_group",
            "territory",
            "is_pos",
            "debit_to",
            "docstatus",
        ],
    )

    if not sales_invoices:
        frappe.throw(_("No valid Sales Invoices found."))

    # Ensure all invoices are for the same customer
    customer_set = {inv["customer"] for inv in sales_invoices}
    if len(customer_set) != 1:
        frappe.throw(_("Cannot merge invoices with different customers."))

    target_company = "General Public"
    base_invoice = sales_invoices[0]

    new_invoice = frappe.get_doc(
        {
            "doctype": "Sales Invoice",
            "customer": base_invoice["customer"],
            "customer_name": base_invoice["customer_name"],
            "company": target_company,
            "currency": base_invoice["currency"],
            "conversion_rate": base_invoice["conversion_rate"],
            "posting_date": min([inv["posting_date"] for inv in sales_invoices]),
            "due_date": max([inv["due_date"] for inv in sales_invoices]),
            "customer_group": base_invoice["customer_group"],
            "territory": base_invoice["territory"],
            "is_pos": base_invoice["is_pos"],
            "debit_to": get_company_account(base_invoice["debit_to"], target_company),
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

    # Consolidate items
    item_dict = {}
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
            ],
        )
        for item in invoice_items:
            item_key = (item["item_code"], item["rate"])
            item["income_account"] = get_company_account(
                item["income_account"], target_company
            )
            item["cost_center"] = get_company_cost_center(
                item["cost_center"], target_company
            )

            if item_key in item_dict:
                item_dict[item_key]["qty"] += item["qty"]
                item_dict[item_key]["amount"] += item["amount"]
            else:
                item_dict[item_key] = item.copy()

    for item in item_dict.values():
        new_invoice.append("items", item)

    # Consolidate taxes
    tax_dict = {}
    for inv in sales_invoices:
        invoice_taxes = frappe.get_all(
            "Sales Taxes and Charges",
            filters={"parent": inv["name"]},
            fields=["charge_type", "account_head", "description", "rate", "tax_amount"],
        )
        for tax in invoice_taxes:
            tax_key = (tax["account_head"], tax["charge_type"])
            tax["account_head"] = get_company_account(
                tax["account_head"], target_company
            )

            if tax_key in tax_dict:
                tax_dict[tax_key]["tax_amount"] += tax["tax_amount"]
            else:
                tax_dict[tax_key] = tax.copy()

    for tax in tax_dict.values():
        new_invoice.append("taxes", tax)

    new_invoice.insert()
    new_invoice.submit()

    # Cancel or Delete original invoices
    for inv in sales_invoices:
        doc = frappe.get_doc("Sales Invoice", inv["name"])
        if doc.docstatus == 1:
            doc.cancel()
        elif doc.docstatus == 0:
            doc.delete()

    return new_invoice.name


# @frappe.whitelist()
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

#     # Use the first invoice as a base for shared values
#     base_invoice = sales_invoices[0]

#     # Create a new Sales Invoice with customer 'General Public'
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
#             ],
#         )
#         for item in invoice_items:
#             item_key = (
#                 item["item_code"],
#                 item["rate"],
#             )  # Merge same items with the same rate
#             if item_key in item_dict:
#                 item_dict[item_key]["qty"] += item["qty"]
#                 item_dict[item_key]["amount"] += item["amount"]
#             else:
#                 item_dict[item_key] = item.copy()

#     # Append merged items
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

#     # Append merged taxes
#     for tax in tax_dict.values():
#         new_invoice.append("taxes", tax)

#     # Save and Submit the new invoice
#     new_invoice.insert()
#     new_invoice.submit()

#     # Cancel or Delete original invoices
#     for inv in sales_invoices:
#         doc = frappe.get_doc("Sales Invoice", inv["name"])
#         if doc.docstatus == 1:
#             doc.cancel()  # Cancel if submitted
#         elif doc.docstatus == 0:
#             doc.delete()  # Delete if in draft

#     return new_invoice.name
