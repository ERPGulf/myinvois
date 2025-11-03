// frappe.ui.form.on('Sales Invoice', {
//     refresh: function(frm) {
//         // Only proceed if docstatus is 1 (Submitted)
//         if (frm.doc.docstatus !== 1) return;

//         let response = frm.doc.custom_submit_response;
//         let should_show_button = false;

//         if (!response) {
//             // Field is blank
//             should_show_button = true;
//         } else {
//             try {
//                 let parsed = JSON.parse(response);

//                 // Show button if no submissionUid or acceptedDocuments is empty
//                 if (
//                     !parsed.submissionUid ||
//                     !Array.isArray(parsed.acceptedDocuments) ||
//                     parsed.acceptedDocuments.length === 0
//                 ) {
//                     should_show_button = true;
//                 }
//             } catch (e) {
//                 // Invalid JSON, show button
//                 should_show_button = true;
//             }
//         }

//         if (should_show_button) {
//             frm.add_custom_button(__('Submit Invoice to LHDN'), function() {
//                 frappe.call({
//                     method: "myinvois_erpgulf.myinvois_erpgulf.original.submit_document",
//                     args: {
//                         "invoice_number": frm.doc.name
//                     },
//                     callback: function(response) {
//                         if (response.message) {
//                             frm.refresh_fields();
//                             frm.reload_doc();
//                             frappe.msgprint(__("Invoice XML submitted successfully!"));
//                         }
//                     }
//                 });
//             });
//         }
//     }
// });

frappe.ui.form.on('Sales Invoice', {
    after_save(frm) {
        if (frm.doc.docstatus == 1) {
            frm.reload_doc();
        }
    },
    refresh: function(frm) {
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
            frm.add_custom_button(__('Submit Invoice to LHDN'), function () {
                // Show loading overlay
                show_loading_overlay();

                frappe.call({
                    method: "myinvois_erpgulf.myinvois_erpgulf.original.submit_document",
                    args: {
                        "invoice_number": frm.doc.name
                    },
                    callback: function (response) {
                        // Hide loading overlay
                        hide_loading_overlay();

                        if (response.message) {
                            frm.reload_doc();
                            frappe.msgprint(__("Invoice XML submitted successfully!"));
                        }
                    },
                    error: function () {
                        hide_loading_overlay();
                        frappe.msgprint(__('Something went wrong during submission.'));
                    }
                });
            });
        }
    }
});

// Reusable helpers
function show_loading_overlay() {
    if (!$('#custom-loading-overlay').length) {
        $('body').append(`
            <div id="custom-loading-overlay" style="
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(255, 255, 255, 0.7);
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <img src="/assets/myinvois_erpgulf/js/loading01.gif" alt="Loading..." style="width: 100px;" />
            </div>
        `);
    }
}

function hide_loading_overlay() {
    $('#custom-loading-overlay').remove();
}

frappe.ui.form.on('Sales Invoice', { 
    refresh: function(frm) {
        if(frm.is_new()){
             set_invoice_type_code(frm);
        }
       
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
    },
     is_return: function(frm) {
        set_invoice_type_code(frm);
    },
    is_debit_note: function(frm) {
        set_invoice_type_code(frm);
    },
});

frappe.realtime.on('show_lhdn_loader', () => {
    show_loading_overlay();
});

frappe.realtime.on('hide_lhdn_loader', () => {
    hide_loading_overlay();
});

function show_loading_overlay() {
    if (!$('#custom-loading-overlay').length) {
        $('body').append(`
            <div id="custom-loading-overlay" style="
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(255, 255, 255, 0.7);
                z-index: 10000;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <img src="/assets/myinvois_erpgulf/js/loading01.gif" style="width: 100px;" />
            </div>
        `);
    }
}

function hide_loading_overlay() {
    $('#custom-loading-overlay').remove();
}

function set_invoice_type_code(frm) {
    if (frm.doc.is_return) {
        frm.set_value('custom_invoicetype_code', '02 : Credit Note');
    } else if (frm.doc.is_debit_note){
        frm.set_value('custom_invoicetype_code', '03 :  Debit Note');
    } else {
        frm.set_value('custom_invoicetype_code', '01 :  Invoice');
    }
}