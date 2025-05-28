frappe.ui.form.on('Sales Invoice', {
    refresh: function(frm) {
        // Only proceed if docstatus is 1 (Submitted)
        if (frm.doc.docstatus !== 1) return;

        let response = frm.doc.custom_submit_response;
        let should_show_button = false;

        if (!response) {
            // Field is blank
            should_show_button = true;
        } else {
            try {
                let parsed = JSON.parse(response);

                // Show button if no submissionUid or acceptedDocuments is empty
                if (
                    !parsed.submissionUid ||
                    !Array.isArray(parsed.acceptedDocuments) ||
                    parsed.acceptedDocuments.length === 0
                ) {
                    should_show_button = true;
                }
            } catch (e) {
                // Invalid JSON, show button
                should_show_button = true;
            }
        }

        if (should_show_button) {
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
                            frappe.msgprint(__("Invoice XML submitted successfully!"));
                        }
                    }
                });
            });
        }
    }
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
        },

    custom_check_customer_tin: function(frm) {
        frappe.call({
            method: "myinvois_erpgulf.myinvois_erpgulf.search_taxpayer.search_sales_tin", 
            args: {
                sales_invoice_doc: frm.doc.name 
            },
            callback: function(r) {
                if (!r.exc) {
                    if (r.message?.taxpayerTIN) {
                        frappe.msgprint(__('TIN Fetched Successfully: ') + r.message.taxpayerTIN);
                    } else {
                        frappe.msgprint(__('TIN lookup completed, but TIN was not found.'));
                    }
                    frm.reload_doc();  // Refresh the document to reflect any updates
                } else {
                    frappe.msgprint(__('Something went wrong while fetching TIN.'));
                }
            }
        });
    }
});