// frappe.ui.form.on('Purchase Invoice', {
//     refresh: function(frm) {
//         // Add the "Get Status" button regardless of docstatus
//         frm.add_custom_button(__('Get Status of SubmittedDoc'), function() {
//             frappe.call({
//                 method: "myinvois_erpgulf.myinvois_erpgulf.get_status.status_submit",
//                 args: {
//                     "doc": frm.doc
//                 },
//                 callback: function(response) {
//                     if (response.message) {
//                         frappe.msgprint(__("Status updated successfully! Check the logs for details."));
//                         frm.reload_doc();
//                     }
//                 }
//             });
//         });

//         // Only add "Submit Invoice" button if docstatus is 1 (Submitted)
//         if (frm.doc.docstatus !== 1) return;

//         let response = frm.doc.custom_submit_response;
//         let should_show_button = false;

//         if (!response) {
//             should_show_button = true;
//         } else {
//             try {
//                 let parsed = JSON.parse(response);
//                 if (
//                     !parsed.submissionUid ||
//                     !Array.isArray(parsed.acceptedDocuments) ||
//                     parsed.acceptedDocuments.length === 0
//                 ) {
//                     should_show_button = true;
//                 }
//             } catch (e) {
//                 should_show_button = true;
//             }
//         }

//         if (should_show_button) {
//             frm.add_custom_button(__('Submit Invoice to LHDN'), function() {
//                 frappe.call({
//                     method: "myinvois_erpgulf.myinvois_erpgulf.submit_purchase.submit_document",
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


frappe.ui.form.on('Purchase Invoice', {
    refresh: function(frm) {
        // Always show "Get Status" button
        frm.add_custom_button(__('Get Status of SubmittedDoc'), function () {
            frappe.call({
                method: "myinvois_erpgulf.myinvois_erpgulf.get_status.status_submit",
                args: {
                    "doc": frm.doc
                },
                callback: function (response) {
                    if (response.message) {
                        frappe.msgprint(__("Status updated successfully! Check the logs for details."));
                        frm.reload_doc();
                    }
                }
            });
        });

        // Only proceed with Submit button if docstatus is 1
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
                // 🔄 Show loading GIF
                show_loading_overlay();

                frappe.call({
                    method: "myinvois_erpgulf.myinvois_erpgulf.submit_purchase.submit_document",
                    args: {
                        "invoice_number": frm.doc.name
                    },
                    callback: function (response) {
                        // ✅ Hide loading GIF
                        hide_loading_overlay();

                        if (response.message) {
                            frm.refresh_fields();
                            frm.reload_doc();
                            frappe.msgprint(__("Invoice XML submitted successfully!"));
                        }
                    },
                    error: function () {
                        hide_loading_overlay();
                        frappe.msgprint(__('Error occurred while submitting the invoice.'));
                    }
                });
            });
        }
    }
});

// 🔧 Utility: Show loading overlay
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

// 🔧 Utility: Hide loading overlay
function hide_loading_overlay() {
    $('#custom-loading-overlay').remove();
}


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
