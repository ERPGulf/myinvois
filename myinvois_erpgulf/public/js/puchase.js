frappe.ui.form.on('Purchase Invoice', {
    refresh: function(frm) {
        // Add the "Get Status" button regardless of docstatus
        frm.add_custom_button(__('Get Status of SubmittedDoc'), function() {
            frappe.call({
                method: "myinvois_erpgulf.myinvois_erpgulf.get_status.status_submit",
                args: {
                    "doc": frm.doc
                },
                callback: function(response) {
                    if (response.message) {
                        frappe.msgprint(__("Status updated successfully! Check the logs for details."));
                        frm.reload_doc();
                    }
                }
            });
        });

        // Only add "Submit Invoice" button if docstatus is 1 (Submitted)
        if (frm.doc.docstatus !== 1) return;

        let response = frm.doc.custom_submit_response;
        let should_show_button = false;

        if (!response) {
            should_show_button = true;
        } else {
            try {
                let parsed = JSON.parse(response);
                if (
                    !parsed.submissionUid ||
                    !Array.isArray(parsed.acceptedDocuments) ||
                    parsed.acceptedDocuments.length === 0
                ) {
                    should_show_button = true;
                }
            } catch (e) {
                should_show_button = true;
            }
        }

        if (should_show_button) {
            frm.add_custom_button(__('Submit Invoice to LHDN'), function() {
                frappe.call({
                    method: "myinvois_erpgulf.myinvois_erpgulf.submit_purchase.submit_document",
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




frappe.ui.form.on('Purchase Invoice', {
    refresh: function(frm) {
        // Optional: call on refresh or via button
    },

    custom_check_supplier_tin: function(frm) {
        frappe.call({
            method: "myinvois_erpgulf.myinvois_erpgulf.search_taxpayer.search_purchase_tin",
            args: {
                sales_invoice_doc: frm.doc.name
            },
            callback: function(r) {
                if (!r.exc) {
                    if (r.message?.taxpayerTIN) {
                        frappe.msgprint(__('TIN Fetched Successfully: ') + r.message.taxpayerTIN);
                        frm.reload_doc();
                    } else {
                        frappe.msgprint(__('TIN lookup completed, but TIN was not found.'));
                    }
                } else {
                    frappe.msgprint(__('Something went wrong while fetching TIN.'));
                }
            },
            error: function(err) {
                frappe.msgprint(__('API call failed: ') + JSON.stringify(err));
            }
        });
    }
});
