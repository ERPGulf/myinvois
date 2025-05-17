frappe.ui.form.on('Sales Invoice', {
    refresh: function(frm) {
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
