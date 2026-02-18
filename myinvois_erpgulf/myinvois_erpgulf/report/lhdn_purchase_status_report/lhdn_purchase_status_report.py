import frappe
from frappe import _

def execute(filters=None):
    if not filters:
        filters = {}

    columns = get_columns()
    data = get_data_and_chart(filters)

    # Return columns, data, message, chart
    return columns, data, None, None


def get_columns():
    return [
        {
            'fieldname': 'name',
            'label': _('Inv. Number'),
            'fieldtype': 'Link',
            'options': 'Purchase Invoice',
            'width': 200
        },
        {
            'fieldname': 'posting_date',
            'label': _('Date'),
            'fieldtype': 'Date',
            'width': 140
        },
        {
            'fieldname': 'supplier_name',
            'label': _('Supplier'),
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
    dt_from = filters.get('dt_from')
    dt_to = filters.get('dt_to')
    status = filters.get('status')

    # Base condition for date range
    base_conditions = "1=1"
    if dt_from and dt_to:
        base_conditions += f" AND posting_date BETWEEN '{dt_from}' AND '{dt_to}'"

    # Query Purchase Invoices
    query = f"""
        SELECT 
            name, 
            supplier_name, 
            posting_date, 
            grand_total, 
            custom_lhdn_status, 
            docstatus
        FROM `tabPurchase Invoice`
        WHERE {base_conditions} 
    """

    invoices = frappe.db.sql(query, as_dict=True)

    # Filter by status
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
