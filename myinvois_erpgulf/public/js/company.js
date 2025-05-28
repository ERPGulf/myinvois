// // frappe.ui.form.on('Company', {
// //     refresh: function (frm) {
// //         console.log("Custom script loaded successfully.");
// //     },
// //     custom_company_registrationicpassport_type: function (frm) {
// //         console.log("Triggered dropdown change:", frm.doc.custom_company_registrationicpassport_type);
// //         if (frm.doc.custom_company_registrationicpassport_type === 'BRN') {
// //             frm.set_df_property(
// //                 'custom_company__registrationicpassport_number', 
// //                 'label', 
// //                 'Business Registration Number'
// //             );
// //         } else if (frm.doc.custom_company_registrationicpassport_type === 'MyKad') {
// //             frm.set_df_property(
// //                 'custom_company__registrationicpassport_number', 
// //                 'label', 
// //                 'MyKad Number'
// //             );
// //         } else if (frm.doc.custom_company_registrationicpassport_type === 'MyKas') {
// //             frm.set_df_property(
// //                 'custom_company__registrationicpassport_number', 
// //                 'label', 
// //                 'MyKas Number'
// //             );
// //         } else if (frm.doc.custom_company_registrationicpassport_type === 'My Tentera') {
// //             frm.set_df_property(
// //                 'custom_company__registrationicpassport_number', 
// //                 'label', 
// //                 'My Tentera Number'
// //             );
// //         } else {
// //             frm.set_df_property(
// //                 'custom_company__registrationicpassport_number', 
// //                 'label', 
// //                 'Company Registration/IC/Passport Number'
// //             );
// //         }

// //         frm.refresh_field('custom_company__registrationicpassport_number');
// //     }
// // });
// frappe.ui.form.on('Company', {
//     custom_company_registrationicpassport_type: function (frm) {
//         const type = (frm.doc.custom_company_registrationicpassport_type || '').trim().toLowerCase();
//         console.log("Normalized dropdown value:", type);

//         if (type === 'brn') {
//             frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'Business Registration Number');
//         } else if (type === 'mykad') {
//             frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'MyKad Number');
//         } else if (type === 'mykas') {
//             frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'MyKas Number');
//         } else if (type === 'my tentera') {
//             frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'My Tentera Number');
//         } else {
//             frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'Company Registration/IC/Passport Number');
//         }

//         frm.refresh_field('custom_company__registrationicpassport_number');
//     }
// });




frappe.ui.form.on('Company', {
    // Triggered when dropdown value changes
    custom_company_registrationicpassport_type: function(frm) {
        const type = (frm.doc.custom_company_registrationicpassport_type || '').trim().toLowerCase();
        console.log("Normalized dropdown value:", type);

        if (type === 'brn') {
            frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'Business Registration Number');
        } else if (type === 'mykad') {
            frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'MyKad Number');
        } else if (type === 'mykas') {
            frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'MyKas Number');
        } else if (type === 'my tentera') {
            frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'My Tentera Number');
        } else {
            frm.set_df_property('custom_company__registrationicpassport_number', 'label', 'Company Registration/IC/Passport Number');
        }

        frm.refresh_field('custom_company__registrationicpassport_number');
    },

    // Your custom method triggered somewhere else — 
    // you can call this from a custom button or another event
    custom_search_company_tin: function(frm) {
        frappe.call({
            method: "myinvois_erpgulf.myinvois_erpgulf.search_taxpayer.search_company_tin",
            args: {
                company_name: frm.doc.name
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

frappe.ui.form.on("Company", {
    refresh: function(frm) {
        // Optional actions on refresh
    },
    custom_taxpayer_login: function(frm) {
        frappe.call({
            method: "myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin.get_access_token",
            args: {
                doc: frm.doc.name  // Send just the company name string
            },
            callback: function(r) {
                if (!r.exc) {
                    frappe.msgprint("Access token fetched successfully!");
                    frm.reload_doc();  // Reload to show updated token
                } else {
                    frappe.msgprint("Failed to fetch access token.");
                }
            },
            error: function(err) {
                frappe.msgprint("Error: " + err.message);
            }
        });
    }
});
