frappe.ui.form.on('Sales Invoice', {
    refresh(frm) {
        frm.refresh_field('custom_submit_response');
        frm.refresh_field('custom_lhdn_status');
    }
});
