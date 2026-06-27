frappe.ui.form.on("Sales Invoice", {
    refresh(frm) {

        frm.set_df_property("custom_lhdn_status_notification", "options", " ");

        try {

            let badgeHtml = "";

            const lhdnStatus = (frm.doc.custom_lhdn_status || "").trim();
            const isConsolidated = cint(frm.doc.custom_is_consolidated_invoice);

            // 🟣 Consolidated (Highest Priority)
            if (isConsolidated === 1) {


                badgeHtml = `
                    <div class="lhdn-badge-container">
                        <img src="/assets/myinvois_erpgulf/js/badges/lhdn-consolidated.png"
                             alt="Consolidated"
                             class="lhdn-badge"
                             width="120"
                             height="120"
                             style="margin-top:-5px;margin-left:215px;">
                    </div>`;
            }

            // 🟢 Valid
            else if (lhdnStatus === "Valid") {


                badgeHtml = `
                    <div class="lhdn-badge-container">
                        <img src="/assets/myinvois_erpgulf/js/badges/lhdn-valid.png"
                             alt="Valid"
                             class="lhdn-badge"
                             width="120"
                             height="120"
                             style="margin-top:-5px;margin-left:215px;">
                    </div>`;
            }

            // 🟠 Invalid
            else if (lhdnStatus === "Invalid") {


                badgeHtml = `
                    <div class="lhdn-badge-container">
                        <img src="/assets/myinvois_erpgulf/js/badges/lhdn-invalid.png"
                             alt="Invalid"
                             class="lhdn-badge"
                             width="120"
                             height="120"
                             style="margin-top:-5px;margin-left:215px;">
                    </div>`;
            }

            // 🔴 Cancelled
            else if (lhdnStatus === "Cancelled") {


                badgeHtml = `
                    <div class="lhdn-badge-container">
                        <img src="/assets/myinvois_erpgulf/js/badges/lhdn-cancelled.png"
                             alt="Cancelled"
                             class="lhdn-badge"
                             width="120"
                             height="120"
                             style="margin-top:-5px;margin-left:215px;">
                    </div>`;
            }

            // Set badge
            if (badgeHtml) {
                frm.set_df_property(
                    "custom_lhdn_status_notification",
                    "options",
                    badgeHtml
                );
            } else {
                // console.log("No matching status.");
                frm.set_df_property(
                    "custom_lhdn_status_notification",
                    "options",
                    ""
                );
            }

        } catch (e) {
            console.error(e);
            frm.set_df_property(
                "custom_lhdn_status_notification",
                "options",
                ""
            );
        }

        frm.refresh_field("custom_lhdn_status_notification");
    }
});