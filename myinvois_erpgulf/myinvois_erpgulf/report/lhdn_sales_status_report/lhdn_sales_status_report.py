# Copyright (c) 2025, ERPGulf and contributors
# For license information, please see license.txt

# import frappe

import frappe
from frappe import _

def execute(filters=None):
    if not filters:
        filters = {}

    columns = get_columns()
    data = get_data_and_chart(filters)

    # Returning columns, data, message, chart (None for now)
    return columns, data, None, None


def get_columns():
    return [
        {
            'fieldname': 'name',
            'label': _('Inv. Number'),
            'fieldtype': 'Link',
            'options': 'Sales Invoice',
            'width': 200
        },
        {
            'fieldname': 'posting_date',
            'label': _('Date'),
            'fieldtype': 'Date',
            'width': 140
        },
        {
            'fieldname': 'customer_name',
            'label': _('Customer'),
            'fieldtype': 'Data',
            'width': 200
        },
        {
            'fieldname': 'grand_total',
            'label': _('Total'),
            'fieldtype': 'Currency',
            'width': 160
        },
        {
            'fieldname': 'custom_lhdn_status',
            'label': _('Status'),
            'fieldtype': 'Data',
            'width': 160
        }
    ]

def get_data_and_chart(filters):
    dt_from = filters.get("dt_from")
    dt_to = filters.get("dt_to")
    status = filters.get("status")

    # Build safe SQL conditions
    conditions = []
    params = {}

    if dt_from and dt_to:
        conditions.append("posting_date BETWEEN %(dt_from)s AND %(dt_to)s")
        params["dt_from"] = dt_from
        params["dt_to"] = dt_to

    # Default WHERE 1=1 if no conditions
    where_clause = " AND ".join(conditions) if conditions else "1=1"

    query = """
        SELECT
            name,
            customer_name,
            posting_date,
            grand_total,
            custom_lhdn_status,
            docstatus
        FROM `tabSales Invoice`
        WHERE {where_clause}
    """.format(where_clause=where_clause)

    invoices = frappe.db.sql(query, params, as_dict=True)

    # Status filter
    if status == "Not Submitted":
        filtered = [
            inv for inv in invoices
            if inv.get("docstatus") == 0 or not inv.get("custom_lhdn_status")
        ]
    elif status:
        filtered = [
            inv for inv in invoices
            if inv.get("custom_lhdn_status") == status
        ]
    else:
        filtered = invoices

    return filtered