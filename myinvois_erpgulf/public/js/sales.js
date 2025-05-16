
frappe.ui.form.on('Sales Invoice', {
    refresh: function(frm) {
        frm.add_custom_button(__('Submit Invoice to LHDN'), function() {
            frappe.call({
                method: "myinvois_erpgulf.myinvois_erpgulf.original.submit_document",
                args: {
                    "invoice_number": frm.doc.name
                },
                callback: function(response) {
                    if (response.message) {
                        frm.refresh_fields();
                        frm.reload_doc(); 
                        frappe.msgprint(__("Invoices xml imported successfully!"));
                    }
                }
            });
        });
    }
});
