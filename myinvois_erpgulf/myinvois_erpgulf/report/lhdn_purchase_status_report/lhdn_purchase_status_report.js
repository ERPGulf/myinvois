// Copyright (c) 2025, ERPGulf and contributors
// For license information, please see license.txt


frappe.query_reports["LHDN Purchase Status Report"] = {
	"filters": [
		{
			fieldname: "company",
			label: __("Company"),
			fieldtype: "Link",
			options: "Company",
			default: frappe.defaults.get_user_default("Company"),
			reqd: 1,
		},	
		{
			fieldname: "dt_from",
			label: __("From"),
			fieldtype: "Date",
			default: frappe.datetime.add_months(frappe.datetime.get_today(), -30),
		},
		

		{
			"fieldname": "dt_to",
			"label": __("To"),
			"fieldtype": "Date",
		    default: frappe.datetime.get_today(),
	
		
		},		
		{
			fieldname: "status",
			label: __("Status"),
			"fieldtype": "Select",
            "options": "\Valid\nInvalid\nSubmitted\nCancelled\nFailed\nNot Submitted", 
            "default": "Valid",
			

		},		
	]
};