function extend_listview_event(doctype, event, callback) {
    if (!frappe.listview_settings[doctype]) {
        frappe.listview_settings[doctype] = {};
    }

    const old_event = frappe.listview_settings[doctype][event];
    frappe.listview_settings[doctype][event] = function (listview) {
        if (old_event) {
            old_event(listview); // Call the original event
        }
        callback(listview); // Call your custom callback
    };
}

// Extend the "onload" event for Sales Invoice
extend_listview_event("Sales Invoice", "onload", function (listview) {
    // Add the "Merge and Consolidate Invoices" action to the menu
    listview.page.add_action_item(__("Merge and Consolidate Invoices"), () => {
        const selected = listview.get_checked_items();
        if (selected.length < 2) {
            frappe.msgprint(__('Please select at least two Sales Invoices to merge.'));
            return;
        }

        // Confirmation dialog before merging
        frappe.confirm(
            `Are you sure you want to merge ${selected.length} invoices into a single one?`,
            () => {
                // If user confirms, proceed with merging
                frappe.call({
                    method: "myinvois_erpgulf.myinvois_erpgulf.consolidate_invoice.merge_sales_invoices",
                    args: {
                        invoice_numbers: selected.map(invoice => invoice.name)
                    },
                    callback: function (response) {
                        if (response.message) {
                            frappe.msgprint(__('Invoices successfully merged into one consolidated invoice: ') + response.message);
                            listview.refresh();
                            listview.check_all(false);
                        } else {
                            frappe.msgprint(__('Failed to merge invoices. Please check logs for details.'));
                        }
                    }
                });
            },
            () => {
                // If user cancels, do nothing
                frappe.msgprint(__('Invoice merge operation cancelled.'));
            }
        );
    });

    console.log('Custom "Merge and Consolidate Invoices" action added to Sales Invoice list view.');
});


frappe.ui.form.on('Sales Invoice', { 
    refresh: function(frm) {
        // Add the custom button
        frm.add_custom_button(__('Get Status of SubmittedDoc'), function() {
            // Call the backend method to get the status
            frappe.call({
                method: "myinvois_erpgulf.myinvois_erpgulf.get_status.status_submit",
                args: {
                    "doc": frm.doc  // Pass the current document
                },
                callback: function(response) {
                    if (response.message) {
                        frappe.msgprint(__("Status updated successfully! Check the logs for details."));
                        frm.reload_doc();  // Reload the form to reflect any changes
                    }
                }
            });
        });
    }
});