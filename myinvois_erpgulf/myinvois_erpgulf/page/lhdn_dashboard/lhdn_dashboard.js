frappe.pages['lhdn-dashboard'].on_page_load = function (wrapper) {
    const page = frappe.ui.make_app_page({
        parent: wrapper,
        title: 'LHDN Dashboard',
        single_column: true
    });
    new LhdnDashboard(page);
    //     $(page.wrapper).find('.page-body').css({
    //     'max-width': '100%',
    //     'padding-left': '0',
    //     'padding-right': '0'
    // });
};

class LhdnDashboard {
    constructor(page) {
        this.page = page;
        this.make_form();
        this.render_cards();
        this.render_charts();
        this.render_list();
        this.render_purchase_invoice_list();
    }

    make_form() {
        this.form = new frappe.ui.FieldGroup({
            fields: [
                { fieldtype: "HTML", fieldname: "summary_cards" },
                { label: __("Charts"), fieldname: "lhdn_charts", fieldtype: "HTML" },
                { label: __("Current Month LHDN Status"), fieldname: "current_month_lhdn_chart", fieldtype: "HTML" },
                { label: __("Sales Invoice List"), fieldtype: "HTML", fieldname: "lhdn_list" },
                { label: __("Purchase Invoice List"), fieldtype: "HTML", fieldname: "purchase_invoice_list" }
            ],
            body: this.page.body,
        });
        this.form.make();
    }

render_cards() {
    const statuses = ['Valid', 'Invalid', 'Submitted', 'Cancelled', 'Failed', 'Not Submitted'];

    const getCounts = (doctype, filters) => frappe.call({
        method: "frappe.client.get_count",
        args: { doctype, filters }
    });

    const getNotSubmittedCounts = (doctype) => {
        const draftCountPromise = frappe.call({
            method: "frappe.client.get_count",
            args: { doctype, filters: { docstatus: 0 } }
        });
        const blankStatusCountPromise = frappe.call({
            method: "frappe.client.get_count",
            args: {
                doctype,
                filters: [
                    // ["docstatus", "=", 1],
                    ["custom_lhdn_status", "in", ["", null]]
                ]
            }
        });

        return Promise.all([draftCountPromise, blankStatusCountPromise]).then(([draftCountRes, blankStatusCountRes]) => {
            const draftCount = draftCountRes.message || 0;
            const blankStatusCount = blankStatusCountRes.message || 0;
            return draftCount + blankStatusCount;
        });
    };

    const promises = statuses.map(status => {
        if (status === 'Not Submitted') {
            return Promise.all([
                getNotSubmittedCounts("Sales Invoice"),
                getNotSubmittedCounts("Purchase Invoice")
            ]).then(([salesCount, purchaseCount]) => ({
                status,
                sales_count: salesCount,
                purchase_count: purchaseCount
            }));
        } else {
            const filters = { custom_lhdn_status: status };
            return Promise.all([
                getCounts("Sales Invoice", filters),
                getCounts("Purchase Invoice", filters)
            ]).then(([salesCount, purchaseCount]) => ({
                status,
                sales_count: salesCount.message || 0,
                purchase_count: purchaseCount.message || 0
            }));
        }
    });

    Promise.all(promises).then(results => {
        let cardHtml = '';

        for (let i = 0; i < results.length; i += 3) {
            // cardHtml += `<div class="status-row" style="display: flex; gap: 30px; margin-bottom: 30px;">`;
            cardHtml += `<div class="status-row" style="display:flex; flex-wrap:wrap; gap:30px; margin-bottom:30px;">`;

            for (let j = i; j < i + 3 && j < results.length; j++) {
                const res = results[j];
                cardHtml += `
                    <div style="flex: 1;">
                        <h4 style="margin-bottom: 10px;">${res.status}</h4>
                        <div style="display: flex; gap: 12px;">
                            ${this.create_card(res.status, res.sales_count, j, "Sales Invoice")}
                            ${this.create_card(res.status, res.purchase_count, j, "Purchase Invoice")}
                        </div>
                    </div>
                `;
            }

            cardHtml += `</div>`;
        }

        this.form.get_field("summary_cards").html(cardHtml);
    });
}


    create_card(title, count, index, doctype) {
        const colors = [
            '#ff6384', '#36a2eb', '#ffce56',
            '#4bc0c0', '#9966ff', '#999999'
        ];

        const reportName = doctype === "Sales Invoice"
            ? "LHDN Sales Status Report"
            : "LHDN Purchase Status Report";

        return `
            <a href="/app/query-report/${encodeURIComponent(reportName)}?&status=${encodeURIComponent(title)}" style="color: inherit;">
                <div 
                    style="flex: 0 0 22%; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; 
                    padding: 16px; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    cursor: pointer; transition: transform 0.2s ease;"
                    onmouseover="this.style.transform='scale(1.02)'"
                    onmouseout="this.style.transform='scale(1)'"
                >
                    <h5 style="font-weight: 600; margin-bottom: 8px;">${doctype}</h5>
                    <div style="font-size: 16px; color: #495057;">${title}</div>
                    <div style="font-size: 28px; font-weight: bold; color: ${colors[index % colors.length]};">${count}</div>
                </div>
            </a>
        `;
    }

    render_charts() {
        const charts_container = `
            <div style="display: flex; justify-content: space-between; box-sizing: border-box;">
                <div style="width: 49%; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
                    <canvas id="currentMonthChart" style="flex: 1; height: 250px;"></canvas>
                </div>
                <div style="width: 49%; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
                    <canvas id="monthlyChart" style="flex: 1; height: 250px;"></canvas>
                </div>
            </div>`;

        this.form.get_field("lhdn_charts").html(charts_container);

        if (typeof Chart === 'undefined') {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
            script.onload = () => {
                this.fetch_monthly_status("monthlyChart", "Monthly LHDN Status", "bar");
                this.fetch_current_month_status("currentMonthChart", "Current Month LHDN Status", "pie");
            };
            document.head.appendChild(script);
        } else {
            this.fetch_monthly_status("monthlyChart", "Monthly LHDN Status", "bar");
            this.fetch_current_month_status("currentMonthChart", "Current Month LHDN Status", "pie");
        }
    }

    fetch_monthly_status(chartId, label, chartType = 'bar') {
        const monthlyStatusCount = {};
        const currentYear = new Date().getFullYear();

        Promise.all([
            frappe.call({
                method: "frappe.client.get_list",
                args: { doctype: "Sales Invoice", fields: ["posting_date", "custom_lhdn_status"], filters: { docstatus: 1 }, limit_page_length: 5000 }
            }),
            frappe.call({
                method: "frappe.client.get_list",
                args: { doctype: "Purchase Invoice", fields: ["posting_date", "custom_lhdn_status"], filters: { docstatus: 1 }, limit_page_length: 5000 }
            })
        ]).then(([salesRes, purchaseRes]) => {
            const data = [...(salesRes.message || []), ...(purchaseRes.message || [])];

            data.forEach(invoice => {
                const date = new Date(invoice.posting_date);
                const year = date.getFullYear();
                const month = date.getMonth();
                let status = invoice.custom_lhdn_status;

                if (year === currentYear) {
                    if (!status || !status.trim()) {
                        status = "Not Submitted";
                    }
                    if (!monthlyStatusCount[status]) monthlyStatusCount[status] = Array(12).fill(0);
                    monthlyStatusCount[status][month]++;
                }
            });

            this.render_chart(chartId, monthlyStatusCount, label, chartType);
        });
    }

    fetch_current_month_status(chartId, label, chartType = 'pie') {
        const currentMonth = new Date().getMonth();
        const statusCount = {};

        Promise.all([
            frappe.call({
                method: "frappe.client.get_list",
                args: { doctype: "Sales Invoice", fields: ["posting_date", "custom_lhdn_status"], filters: { docstatus: 1 }, limit_page_length: 5000 }
            }),
            frappe.call({
                method: "frappe.client.get_list",
                args: { doctype: "Purchase Invoice", fields: ["posting_date", "custom_lhdn_status"], filters: { docstatus: 1 }, limit_page_length: 5000 }
            })
        ]).then(([salesRes, purchaseRes]) => {
            const data = [...(salesRes.message || []), ...(purchaseRes.message || [])];

            data.forEach(invoice => {
                const month = new Date(invoice.posting_date).getMonth();
                let status = invoice.custom_lhdn_status;

                if (month === currentMonth) {
                    if (!status || !status.trim()) {
                        status = "Not Submitted";
                    }
                    statusCount[status] = (statusCount[status] || 0) + 1;
                }
            });

            this.render_chart(chartId, statusCount, label, chartType);
        });
    }

    render_chart(chartId, data, label, chartType) {
        const ctx = document.getElementById(chartId).getContext('2d');
        const labels = chartType === 'bar'
            ? ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            : Object.keys(data);

        const colors = [
            'rgba(255, 99, 132, 0.6)',   // Valid
            'rgba(54, 162, 235, 0.6)',   // Invalid
            'rgba(255, 206, 86, 0.6)',   // Submitted
            'rgba(75, 192, 192, 0.6)',   // Cancelled
            'rgba(153, 102, 255, 0.6)',  // Failed
            'rgba(153, 153, 153, 0.6)'   // Not Submitted
        ];

        const borderColors = colors.map(c => c.replace('0.6', '1'));

        const datasets = Object.keys(data).map((status, i) => ({
            label: status,
            data: chartType === 'bar' ? data[status] : [data[status]],
            backgroundColor: colors[i % colors.length],
            borderColor: borderColors[i % borderColors.length],
            borderWidth: 1,
        }));

        new Chart(ctx, {
            type: chartType,
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: chartType === 'bar' ? {
                    x: { stacked: true },
                    y: { stacked: true }
                } : {},
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: label }
                }
            }
        });
    }

    render_list() {
        frappe.call({
            method: "frappe.client.get_list",
            args: {
                doctype: "Sales Invoice",
                fields: ["name", "customer", "posting_date", "custom_lhdn_status", "grand_total"],
                limit_page_length: 50,
                order_by: "posting_date desc"
            },
            callback: (r) => {
                if (r.message) {
                    let rows = r.message.map(row =>
                        `<tr>
                            <td>${row.name}</td>
                            <td>${row.customer}</td>
                            <td>${row.posting_date}</td>
                            <td>${row.custom_lhdn_status && row.custom_lhdn_status.trim() ? row.custom_lhdn_status : 'Not Submitted'}</td>
                            <td>${row.grand_total}</td>
                        </tr>`
                    ).join("");

                    const table_html = `
                        <table class="table table-bordered table-striped">
                            <thead>
                                <tr>
                                    <th>Invoice</th>
                                    <th>Customer</th>
                                    <th>Posting Date</th>
                                    <th>LHDN Status</th>
                                    <th>Grand Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rows}
                            </tbody>
                        </table>`;

                    this.form.get_field("lhdn_list").html(table_html);
                }
            }
        });
    }

    render_purchase_invoice_list() {
        frappe.call({
            method: "frappe.client.get_list",
            args: {
                doctype: "Purchase Invoice",
                fields: ["name", "supplier", "posting_date", "custom_lhdn_status", "grand_total"],
                limit_page_length: 50,
                order_by: "posting_date desc"
            },
            callback: (r) => {
                if (r.message) {
                    let rows = r.message.map(row =>
                        `<tr>
                            <td>${row.name}</td>
                            <td>${row.supplier}</td>
                            <td>${row.posting_date}</td>
                            <td>${row.custom_lhdn_status && row.custom_lhdn_status.trim() ? row.custom_lhdn_status : 'Not Submitted'}</td>
                            <td>${row.grand_total}</td>
                        </tr>`
                    ).join("");

                    const table_html = `
                        <table class="table table-bordered table-striped">
                            <thead>
                                <tr>
                                    <th>Invoice</th>
                                    <th>Supplier</th>
                                    <th>Posting Date</th>
                                    <th>LHDN Status</th>
                                    <th>Grand Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${rows}
                            </tbody>
                        </table>`;

                    this.form.get_field("purchase_invoice_list").html(table_html);
                }
            }
        });
    }
}
