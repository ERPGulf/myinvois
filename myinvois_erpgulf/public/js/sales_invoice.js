// function extend_listview_event(doctype, event, callback) {
//     if (!frappe.listview_settings[doctype]) {
//         frappe.listview_settings[doctype] = {};
//     }

//     const old_event = frappe.listview_settings[doctype][event];
//     frappe.listview_settings[doctype][event] = function (listview) {
//         if (old_event) {
//             old_event(listview); // Call the original event
//         }
//         callback(listview); // Call your custom callback
//     };
// }

// // Extend the "onload" event for Sales Invoice
// extend_listview_event("Sales Invoice", "onload", function (listview) {
//     // Add the "Merge and Consolidate Invoices" action to the menu
//     listview.page.add_action_item(__("Merge and Consolidate Invoices"), () => {
//         const selected = listview.get_checked_items();
//         if (selected.length < 2) {
//             frappe.msgprint(__('Please select at least two Sales Invoices to merge.'));
//             return;
//         }

//         // Confirmation dialog before merging
//         frappe.confirm(
//             `Are you sure you want to merge ${selected.length} invoices into a single one?`,
//             () => {
//                 // If user confirms, proceed with merging
//                 frappe.call({
//                     method: "myinvois_erpgulf.myinvois_erpgulf.consolidate_invoice.merge_sales_invoices",
//                     args: {
//                         invoice_numbers: selected.map(invoice => invoice.name)
//                     },
//                     callback: function (response) {
//                         if (response.message) {
//                             frappe.msgprint(__('Invoices successfully merged into one consolidated invoice: ') + response.message);
//                             listview.refresh();
//                             listview.check_all(false);
//                         } else {
//                             frappe.msgprint(__('Failed to merge invoices. Please check logs for details.'));
//                         }
//                     }
//                 });
//             },
//             () => {
//                 // If user cancels, do nothing
//                 frappe.msgprint(__('Invoice merge operation cancelled.'));
//             }
//         );
//     });

//     console.log('Custom "Merge and Consolidate Invoices" action added to Sales Invoice list view.');
// });


// frappe.listview_settings['Sales Invoice'] = frappe.listview_settings['Sales Invoice'] || {};

// frappe.listview_settings['Sales Invoice'].get_indicator = function (doc) {
//     if (doc.status === "Consolidated") {
//         return [__("Consolidated"), "red", "status,=,Consolidated"];
//     }
//     return [__(doc.status), frappe.utils.guess_colour(doc.status), `status,=,${doc.status}`];
// };

// Helper to show loading overlay
function show_loading_overlay() {
    if (!$('#custom-loading-overlay').length) {
        $('body').append(`
            <div id="custom-loading-overlay" style="
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(255, 255, 255, 0.8);
                z-index: 9999;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <img src="/assets/myinvois_erpgulf/js/loading01.gif" alt="Loading..." style="width: 100px; height: 100px;" />
            </div>
        `);
    }
}

// Helper to hide loading overlay
function hide_loading_overlay() {
    $('#custom-loading-overlay').remove();
}

// Function to extend ListView events
function extend_listview_event(doctype, event, callback) {
    if (!frappe.listview_settings[doctype]) {
        frappe.listview_settings[doctype] = {};
    }

    const old_event = frappe.listview_settings[doctype][event];
    frappe.listview_settings[doctype][event] = function (listview) {
        if (old_event) {
            old_event(listview);
        }
        callback(listview);
    };
}

// Extend "onload" event for Sales Invoice
extend_listview_event("Sales Invoice", "onload", function (listview) {
    listview.page.add_action_item(__("Merge and Consolidate Invoices"), () => {
        const selected = listview.get_checked_items();
        if (selected.length < 2) {
            frappe.msgprint(__('Please select at least two Sales Invoices to merge.'));
            return;
        }

        frappe.confirm(
            `Are you sure you want to merge ${selected.length} invoices into a single one?`,
            () => {
                // Show loading GIF
                show_loading_overlay();

                frappe.call({
                    method: "myinvois_erpgulf.myinvois_erpgulf.consolidate_invoice.merge_sales_invoices",
                    args: {
                        invoice_numbers: selected.map(invoice => invoice.name)
                    },
                    callback: function (response) {
                        // Hide loading GIF
                        hide_loading_overlay();

                        if (response.message) {
                            frappe.msgprint(_('Invoices successfully merged into one consolidated invoice:') + ' ' + response.message);
                            listview.refresh();
                            listview.check_all(false);
                        } else {
                            frappe.msgprint(__('Failed to merge invoices. Please check logs for details.'));
                        }
                    },
                    error: function () {
                        hide_loading_overlay();
                        frappe.msgprint(__('An error occurred during invoice merge.'));
                    }
                });
            },
            () => {
                frappe.msgprint(__('Invoice merge operation cancelled.'));
            }
        );
    });

    console.log('Custom "Merge and Consolidate Invoices" action added to Sales Invoice list view.');
});


