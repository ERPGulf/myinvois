frappe.pages['lhdn-dashboard'].on_page_load = function (wrapper) {
    const page = frappe.ui.make_app_page({
        parent: wrapper,
        title: 'LHDN Dashboard',
        single_column: true
    });
    new LhdnDashboard(page);
};

class LhdnDashboard {
    constructor(page) {
        this.page = page;
        this.make_form();
        this.render_cards();
        this.render_charts();
        this.render_list();
    }

    make_form() {
        this.form = new frappe.ui.FieldGroup({
            fields: [
                { fieldtype: "HTML", fieldname: "summary_cards" },
                { label: __("Charts"), fieldname: "lhdn_charts", fieldtype: "HTML" },
                { label: __("Current Month LHDN Status"), fieldname: "current_month_lhdn_chart", fieldtype: "HTML" },
                { label: __("LHDN List"), fieldtype: "HTML", fieldname: "lhdn_list" }
            ],
            body: this.page.body,
        });
        this.form.make();
    }

    render_cards() {
        const statuses = ['Valid', 'Invalid', 'Submitted', 'Cancelled', 'Failed', 'Not Submitted'];
        const statusPromises = statuses.map(status => {
            return frappe.call({
                method: "frappe.client.get_count",
                args: {
                    doctype: "Sales Invoice",
                    filters: { custom_lhdn_status: status }
                }
            });
        });

        Promise.all(statusPromises).then((responses) => {
            let cardHtml = `<div class="card-container" style="display: flex; gap: 10px; justify-content: space-between; flex-wrap: nowrap; overflow-x: auto; margin-top: 20px; margin-bottom: 20px;">`;


            responses.forEach((response, index) => {
                const count = response.message || 0;
                cardHtml += this.create_card(statuses[index], count, index);
            });

            cardHtml += '</div>';
            this.form.get_field("summary_cards").html(cardHtml);
        });
    }

    create_card(title, count, index) {
        const colors = [
            '#ff6384', // Valid
            '#36a2eb', // Invalid
            '#ffce56', // Submitted
            '#4bc0c0', // Cancelled
            '#9966ff', // Failed
            '#999999'  // Not Submitted
        ];
        return `
            <div style="flex: 0 0 16%; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); min-width: 150px;">
                <h4 style="font-weight: bold; color: #495057;">${title}</h4>
                <div class="count" style="font-size: 32px; font-weight: bold; color: ${colors[index % colors.length]}; margin-top: 10px;">${count}</div>
            </div>
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

        frappe.call({
            method: "frappe.client.get_list",
            args: {
                doctype: "Sales Invoice",
                fields: ["posting_date", "custom_lhdn_status"],
                filters: { docstatus: 1 },
                limit_page_length: 5000
            },
            callback: (response) => {
                if (response.message) {
                    response.message.forEach((invoice) => {
                        const date = new Date(invoice.posting_date);
                        const year = date.getFullYear();
                        const month = date.getMonth();
                        const status = invoice.custom_lhdn_status;

                        if (year === currentYear) {
                            if (!monthlyStatusCount[status]) monthlyStatusCount[status] = Array(12).fill(0);
                            monthlyStatusCount[status][month]++;
                        }
                    });
                    this.render_chart(chartId, monthlyStatusCount, label, chartType);
                }
            }
        });
    }

    fetch_current_month_status(chartId, label, chartType = 'pie') {
        const currentMonth = new Date().getMonth();
        const statusCount = {};

        frappe.call({
            method: "frappe.client.get_list",
            args: {
                doctype: "Sales Invoice",
                fields: ["posting_date", "custom_lhdn_status"],
                filters: { docstatus: 1 },
                limit_page_length: 5000
            },
            callback: (response) => {
                if (response.message) {
                    response.message.forEach((invoice) => {
                        const month = new Date(invoice.posting_date).getMonth();
                        const status = invoice.custom_lhdn_status;

                        if (month === currentMonth) {
                            statusCount[status] = (statusCount[status] || 0) + 1;
                        }
                    });
                    this.render_chart(chartId, statusCount, label, chartType);
                }
            }
        });
    }

    render_chart(chartId, data, label, chartType) {
        const ctx = document.getElementById(chartId).getContext('2d');
        const labels = chartType === 'bar' ?
            ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] :
            Object.keys(data);

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
                            <td>${row.custom_lhdn_status || ''}</td>
                            <td>${row.grand_total.toFixed(2)}</td>
                        </tr>`
                    ).join('');

                    const tableHtml = `
                        <table class="table table-bordered table-striped" style="width: 100%; margin-top: 20px;">
                            <thead>
                                <tr>
                                    <th>Invoice</th>
                                    <th>Customer</th>
                                    <th>Date</th>
                                    <th>LHDN Status</th>
                                    <th>Total</th>
                                </tr>
                            </thead>
                            <tbody>${rows}</tbody>
                        </table>`;

                    this.form.get_field("lhdn_list").html(tableHtml);
                }
            }
        });
    }
}
