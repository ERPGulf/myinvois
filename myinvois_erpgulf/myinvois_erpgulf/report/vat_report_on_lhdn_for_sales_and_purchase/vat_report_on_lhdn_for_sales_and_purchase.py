import frappe

# -----------------------------
# Tax categories
# -----------------------------
TAX_CATEGORIES = {
    "01": "Sales Tax",
    "02": "Service Tax",
    "03": "Tourism Tax",
    "04": "High-Value Goods Tax",
    "05": "Sales Tax on Low Value Goods",
    "06": "Not Applicable",
    "E": "Tax Exemption (where applicable)"
}

# -----------------------------
# Process Sales Invoices with filters
# -----------------------------
def process_sales_invoices(filters=None):
    totals = {k: {"amount": 0, "adjustment": 0, "vat": 0} for k in TAX_CATEGORIES.keys()}

    filters = filters or {}
    base_filters = {"docstatus": 1}
    if filters.get("company"):
        base_filters["company"] = filters["company"]
    if filters.get("from_date") and filters.get("to_date"):
        base_filters["posting_date"] = ["between", [filters["from_date"], filters["to_date"]]]
    elif filters.get("from_date"):
        base_filters["posting_date"] = [">=", filters["from_date"]]
    elif filters.get("to_date"):
        base_filters["posting_date"] = ["<=", filters["to_date"]]

    invoices = frappe.get_all(
        "Sales Invoice",
        filters=base_filters,
        fields=["name", "grand_total", "is_return", "total_taxes_and_charges", "custom_zatca_tax_category"]
    )

    for inv in invoices:
        doc = frappe.get_doc("Sales Invoice", inv.name)
        key_amount = "adjustment" if doc.is_return else "amount"

        # --- Check items first ---
        item_has_template = False
        for item in doc.items:
            template_id = getattr(item, "item_tax_template", None)
            if template_id:
                item_has_template = True
                template = frappe.get_doc("Item Tax Template", template_id)
                code = template.custom_zatca_tax_category
                if code not in TAX_CATEGORIES:
                    continue
                amount = item.amount or 0
                tax_rate = template.taxes[0].tax_rate if template.taxes else 0
                vat = round((item.net_amount or amount) * (tax_rate / 100), 2)
                totals[code][key_amount] += amount
                totals[code]["vat"] += vat

        # --- Fallback to invoice-level category ---
        if not item_has_template:
            raw_code = getattr(doc, "custom_zatca_tax_category", None)
            if not raw_code:
                raw_code = "E"
            code = raw_code.split(" : ")[0] if " : " in raw_code else raw_code
            if code in TAX_CATEGORIES:
                totals[code][key_amount] += doc.grand_total or 0
                totals[code]["vat"] += doc.total_taxes_and_charges or 0

    return totals

# -----------------------------
# Process Purchase Invoices with filters
# -----------------------------
def process_purchase_invoices(filters=None):
    totals = {k: {"amount": 0, "adjustment": 0, "vat": 0} for k in TAX_CATEGORIES.keys()}

    filters = filters or {}
    base_filters = {"docstatus": 1}
    if filters.get("company"):
        base_filters["company"] = filters["company"]
    if filters.get("from_date") and filters.get("to_date"):
        base_filters["posting_date"] = ["between", [filters["from_date"], filters["to_date"]]]
    elif filters.get("from_date"):
        base_filters["posting_date"] = [">=", filters["from_date"]]
    elif filters.get("to_date"):
        base_filters["posting_date"] = ["<=", filters["to_date"]]

    invoices = frappe.get_all(
        "Purchase Invoice",
        filters=base_filters,
        fields=["name", "grand_total", "is_return", "total_taxes_and_charges", "custom_zatca_tax_category"]
    )

    for inv in invoices:
        doc = frappe.get_doc("Purchase Invoice", inv.name)
        key_amount = "adjustment" if doc.is_return else "amount"

        # --- Check items first ---
        item_has_template = False
        for item in doc.items:
            template_id = getattr(item, "item_tax_template", None)
            if template_id:
                item_has_template = True
                template = frappe.get_doc("Item Tax Template", template_id)
                code = template.custom_zatca_tax_category
                if code not in TAX_CATEGORIES:
                    continue
                amount = item.amount or 0
                tax_rate = template.taxes[0].tax_rate if template.taxes else 0
                vat = round((item.net_amount or amount) * (tax_rate / 100), 2)
                totals[code][key_amount] += amount
                totals[code]["vat"] += vat

        # --- Fallback to invoice-level category ---
        if not item_has_template:
            raw_code = getattr(doc, "custom_zatca_tax_category", None)
            if not raw_code:
                raw_code = "E"
            code = raw_code.split(" : ")[0] if " : " in raw_code else raw_code
            if code in TAX_CATEGORIES:
                totals[code][key_amount] += doc.grand_total or 0
                totals[code]["vat"] += doc.total_taxes_and_charges or 0

    return totals

# -----------------------------
# Execute function with filters
# -----------------------------
def execute(filters=None):
    columns = [
        {"label": "Category", "fieldname": "category", "fieldtype": "Data", "width": 380},
        {"label": "Amount (SAR)", "fieldname": "amount", "fieldtype": "Currency", "width": 180},
        {"label": "Adjustment (SAR)", "fieldname": "adjustment", "fieldtype": "Currency", "width": 180},
        {"label": "VAT Amount (SAR)", "fieldname": "vat", "fieldtype": "Currency", "width": 180},
    ]
    data = []

    # SALES VAT
    data.append({"category": "<b>Sales VAT</b>", "amount": None, "adjustment": None, "vat": None})
    sales_totals = process_sales_invoices(filters)
    for code, label in TAX_CATEGORIES.items():
        vals = sales_totals[code]
        data.append({
            "category": label,
            "amount": vals["amount"],
            "adjustment": vals["adjustment"],
            "vat": vals["vat"]
        })
    total_sales = {
        "amount": sum(vals["amount"] for vals in sales_totals.values()),
        "adjustment": sum(vals["adjustment"] for vals in sales_totals.values()),
        "vat": sum(vals["vat"] for vals in sales_totals.values())
    }
    data.append({
        "category": "<b>Total Sales</b>",
        "amount": total_sales["amount"],
        "adjustment": total_sales["adjustment"],
        "vat": total_sales["vat"]
    })

    data.append({"category": None, "amount": None, "adjustment": None, "vat": None})

    # PURCHASE VAT
    data.append({"category": "<b>Purchase VAT</b>", "amount": None, "adjustment": None, "vat": None})
    purchase_totals = process_purchase_invoices(filters)
    for code, label in TAX_CATEGORIES.items():
        vals = purchase_totals[code]
        data.append({
            "category": label,
            "amount": vals["amount"],
            "adjustment": vals["adjustment"],
            "vat": vals["vat"]
        })
    total_purchase = {
        "amount": sum(vals["amount"] for vals in purchase_totals.values()),
        "adjustment": sum(vals["adjustment"] for vals in purchase_totals.values()),
        "vat": sum(vals["vat"] for vals in purchase_totals.values())
    }
    data.append({
        "category": "<b>Total Purchase</b>",
        "amount": total_purchase["amount"],
        "adjustment": total_purchase["adjustment"],
        "vat": total_purchase["vat"]
    })

    return columns, data
