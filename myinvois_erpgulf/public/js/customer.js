frappe.ui.form.on('Customer', {
    custom_customer__registrationicpassport_type: function (frm) {
        // Normalize the value from the select field
        const type = (frm.doc.custom_customer__registrationicpassport_type || '').trim().toLowerCase();
        console.log("Normalized dropdown value:", type);

        // Check and update the label based on the selected type
        if (type === 'brn') {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'Business Registration Number');
        } else if (type === 'mykad') {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'MyKad Number');
        } else if (type === 'mykas') {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'MyKas Number');
        } else if (type === 'my tentera') {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'My Tentera Number');
        } else if (type === 'passport') {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'Passport Number');
        } else {
            frm.set_df_property('custom_customer_registrationicpassport_number', 'label', 'Customer Registration/IC/Passport Number');
        }

        // Refresh the field to reflect changes
        frm.refresh_field('custom_customer_registrationicpassport_number');
    },
      // you can call this from a custom button or another event
     
    });

