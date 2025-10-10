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
    "E" : "Tax Exemption (where applicable)"
   
}

# -----------------------------
# Process Sales Invoices with filters using SQL
# -----------------------------
def process_sales_invoices(filters=None):
    totals = {k: {"amount": 0, "adjustment": 0, "vat": 0} for k in TAX_CATEGORIES.keys()}
    filters = filters or {}
    values = []

    # --- Items-level totals ---
    query_items = """
        SELECT si.name AS invoice, sit.custom_zatca_tax_category AS code,
               sii.amount, sii.net_amount,
               IFNULL(st.tax_rate, 0) AS tax_rate,
               si.is_return
        FROM `tabSales Invoice Item` sii
        LEFT JOIN `tabItem Tax Template` sit ON sii.item_tax_template = sit.name
        LEFT JOIN `tabItem Tax Template Detail` st ON st.parent = sit.name
        LEFT JOIN `tabSales Invoice` si ON si.name = sii.parent
        WHERE si.docstatus = 1 AND sii.item_tax_template IS NOT NULL
    """

    if filters.get("company"):
        query_items += " AND si.company = %s"
        values.append(filters["company"])
    if filters.get("from_date") and filters.get("to_date"):
        query_items += " AND si.posting_date BETWEEN %s AND %s"
        values.extend([filters["from_date"], filters["to_date"]])
    elif filters.get("from_date"):
        query_items += " AND si.posting_date >= %s"
        values.append(filters["from_date"])
    elif filters.get("to_date"):
        query_items += " AND si.posting_date <= %s"
        values.append(filters["to_date"])

    items = frappe.db.sql(query_items, values, as_dict=True)

    for row in items:
        key_amount = "adjustment" if row.is_return else "amount"
        code = row.code or "E"
        if code not in TAX_CATEGORIES:
            code = "E"
        amount = row.amount or 0
        vat = round((row.net_amount or amount) * (row.tax_rate / 100), 2)
        totals[code][key_amount] += amount
        totals[code]["vat"] += vat

    # --- Invoice-level fallback (no item tax template) ---
    query_invoice = """
        SELECT si.name, si.grand_total, si.total_taxes_and_charges,
               si.custom_zatca_tax_category, si.is_return
        FROM `tabSales Invoice` si
        WHERE si.docstatus = 1
    """

    values = []
    if filters.get("company"):
        query_invoice += " AND si.company = %s"
        values.append(filters["company"])
    if filters.get("from_date") and filters.get("to_date"):
        query_invoice += " AND si.posting_date BETWEEN %s AND %s"
        values.extend([filters["from_date"], filters["to_date"]])
    elif filters.get("from_date"):
        query_invoice += " AND si.posting_date >= %s"
        values.append(filters["from_date"])
    elif filters.get("to_date"):
        query_invoice += " AND si.posting_date <= %s"
        values.append(filters["to_date"])

    invoices = frappe.db.sql(query_invoice, values, as_dict=True)

    for doc in invoices:
        # Check if this invoice has items with templates already counted
        item_check = frappe.db.exists(
            "Sales Invoice Item",
            {"parent": doc.name, "item_tax_template": ["is", "set"]}
        )
        if item_check:
            continue  # Already included in item-level totals

        key_amount = "adjustment" if doc.is_return else "amount"
        raw_code = doc.custom_zatca_tax_category or "E"
        code = raw_code.split(" : ")[0] if " : " in raw_code else raw_code
        if code not in TAX_CATEGORIES:
            code = "E"
        totals[code][key_amount] += doc.grand_total or 0
        totals[code]["vat"] += doc.total_taxes_and_charges or 0

    return totals

# -----------------------------
# Process Purchase Invoices with filters using SQL
# -----------------------------
def process_purchase_invoices(filters=None):
    totals = {k: {"amount": 0, "adjustment": 0, "vat": 0} for k in TAX_CATEGORIES.keys()}
    filters = filters or {}
    values = []

    # --- Items-level totals ---
    query_items = """
        SELECT pi.name AS invoice, pit.custom_zatca_tax_category AS code,
               pii.amount, pii.net_amount,
               IFNULL(pt.tax_rate, 0) AS tax_rate,
               pi.is_return
        FROM `tabPurchase Invoice Item` pii
        LEFT JOIN `tabItem Tax Template` pit ON pii.item_tax_template = pit.name
        LEFT JOIN `tabItem Tax Template Detail` pt ON pt.parent = pit.name
        LEFT JOIN `tabPurchase Invoice` pi ON pi.name = pii.parent
        WHERE pi.docstatus = 1 AND pii.item_tax_template IS NOT NULL
    """

    if filters.get("company"):
        query_items += " AND pi.company = %s"
        values.append(filters["company"])
    if filters.get("from_date") and filters.get("to_date"):
        query_items += " AND pi.posting_date BETWEEN %s AND %s"
        values.extend([filters["from_date"], filters["to_date"]])
    elif filters.get("from_date"):
        query_items += " AND pi.posting_date >= %s"
        values.append(filters["from_date"])
    elif filters.get("to_date"):
        query_items += " AND pi.posting_date <= %s"
        values.append(filters["to_date"])

    items = frappe.db.sql(query_items, values, as_dict=True)

    for row in items:
        key_amount = "adjustment" if row.is_return else "amount"
        code = row.code or "E"
        if code not in TAX_CATEGORIES:
            code = "E"
        amount = row.amount or 0
        vat = round((row.net_amount or amount) * (row.tax_rate / 100), 2)
        totals[code][key_amount] += amount
        totals[code]["vat"] += vat

    # --- Invoice-level fallback ---
    query_invoice = """
        SELECT pi.name, pi.grand_total, pi.total_taxes_and_charges,
               pi.custom_zatca_tax_category, pi.is_return
        FROM `tabPurchase Invoice` pi
        WHERE pi.docstatus = 1
    """
    values = []
    if filters.get("company"):
        query_invoice += " AND pi.company = %s"
        values.append(filters["company"])
    if filters.get("from_date") and filters.get("to_date"):
        query_invoice += " AND pi.posting_date BETWEEN %s AND %s"
        values.extend([filters["from_date"], filters["to_date"]])
    elif filters.get("from_date"):
        query_invoice += " AND pi.posting_date >= %s"
        values.append(filters["from_date"])
    elif filters.get("to_date"):
        query_invoice += " AND pi.posting_date <= %s"
        values.append(filters["to_date"])

    invoices = frappe.db.sql(query_invoice, values, as_dict=True)

    for doc in invoices:
        item_check = frappe.db.exists(
            "Purchase Invoice Item",
            {"parent": doc.name, "item_tax_template": ["is", "set"]}
        )
        if item_check:
            continue  # Already included
        key_amount = "adjustment" if doc.is_return else "amount"
        raw_code = doc.custom_zatca_tax_category or "E"
        code = raw_code.split(" : ")[0] if " : " in raw_code else raw_code
        if code not in TAX_CATEGORIES:
            code = "E"
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

    # --- SALES VAT ---
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

    # --- PURCHASE VAT ---
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
