// This script is used to add a custom button to the LHDN Success Log form.
frappe.ui.form.on('LHDN Success Log', {
    refresh: function(frm) {
        // Add the custom button
        frm.add_custom_button(__('Get Status of SubmittedDoc'), function() {
            // Call the backend method to get the status
            frappe.call({
                method: "myinvois_erpgulf.myinvois_erpgulf.original.status_submit_success_log",
                args: {
                    "doc": frm.doc,
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
