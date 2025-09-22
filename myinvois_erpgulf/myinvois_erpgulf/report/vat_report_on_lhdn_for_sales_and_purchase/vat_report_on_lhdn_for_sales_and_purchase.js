// Copyright (c) 2025, ERPGulf and contributors
// For license information, please see license.txt

frappe.query_reports["VAT Report on LHDN for Sales and Purchase"] = {
    "filters": [
        {
            "fieldname": "company",
            "label": "Company",
            "fieldtype": "Link",
            "options": "Company"
        },
        {
            "fieldname": "from_date",
            "label": "From Date",
            "fieldtype": "Date"
        },
        {
            "fieldname": "to_date",
            "label": "To Date",
            "fieldtype": "Date"
        }
    ],

    "formatter": function(value, row, column, data, default_formatter) {
        if (data && data.category) {
            // Bold headings and total rows
            if (["Sales VAT", "Purchase VAT"].includes(data.category) ||
                data.category.startsWith("Total")) {
                return `<strong>${value}</strong>`;
            }
        }
        return default_formatter(value, row, column, data);
    }
};
