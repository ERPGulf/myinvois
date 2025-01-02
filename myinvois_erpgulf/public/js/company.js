// frappe.ui.form.on('Company', {
//     refresh: function (frm) {
//         console.log("Custom script loaded successfully.");
//     },
//     custom_company_registrationicpassport_type: function (frm) {
//         console.log("Triggered dropdown change:", frm.doc.custom_company_registrationicpassport_type);
//         if (frm.doc.custom_company_registrationicpassport_type === 'BRN') {
//             frm.set_df_property(
//                 'custom_company__registrationicpassport_number', 
//                 'label', 
//                 'Business Registration Number'
//             );
//         } else if (frm.doc.custom_company_registrationicpassport_type === 'MyKad') {
//             frm.set_df_property(
//                 'custom_company__registrationicpassport_number', 
//                 'label', 
//                 'MyKad Number'
//             );
//         } else if (frm.doc.custom_company_registrationicpassport_type === 'MyKas') {
//             frm.set_df_property(
//                 'custom_company__registrationicpassport_number', 
//                 'label', 
//                 'MyKas Number'
//             );
//         } else if (frm.doc.custom_company_registrationicpassport_type === 'My Tentera') {
//             frm.set_df_property(
//                 'custom_company__registrationicpassport_number', 
//                 'label', 
//                 'My Tentera Number'
//             );
//         } else {
//             frm.set_df_property(
//                 'custom_company__registrationicpassport_number', 
//                 'label', 
//                 'Company Registration/IC/Passport Number'
//             );
//         }

//         frm.refresh_field('custom_company__registrationicpassport_number');
//     }
// });
frappe.ui.form.on('Company', {
    custom_company_registrationicpassport_type: function (frm) {
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
    }
});
