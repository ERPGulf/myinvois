// Copyright (c) 2024, ERPGulf and contributors
// For license information, please see license.txt

// frappe.ui.form.on("LHDN Malaysia Setting", {
// 	refresh(frm) {

// 	},
// });
frappe.ui.form.on("LHDN Malaysia Setting", {
    refresh: function(frm) {
    },
    taxpayer_login: function(frm) {
        frappe.call({
            method: "myinvois_erpgulf.myinvois_erpgulf.taxpayerlogin.get_access_token",
            callback: function(r) {
                if (!r.exc) {
                    frm.save();
                }
            }
        });
    }
});
