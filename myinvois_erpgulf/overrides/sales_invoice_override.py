import frappe
from erpnext.accounts.doctype.sales_invoice.sales_invoice import SalesInvoice as OriginalSalesInvoice

class CustomSalesInvoice(OriginalSalesInvoice):
    def on_submit(self):
        if hasattr(self, "custom_is_consolidated_invoice") and self.get("custom_is_consolidated_invoice") == 1:
            # frappe.msgprint("Skipping submission logic for consolidated invoice.")
            return

        super().on_submit()

