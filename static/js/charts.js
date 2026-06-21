function renderCharts(scanData) {
    if (typeof Chart === 'undefined') return;

    const labels = scanData.map(s => {
        const d = new Date(s.scan_date || s.date);
        return isNaN(d.getTime()) ? (s.scan_date || s.date || '').slice(0, 10) : d.toLocaleDateString();
    });

    const barCtx = document.getElementById('barChart');
    if (barCtx) {
        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: labels.length ? labels : ['No Data'],
                datasets: [
                    {
                        label: 'Critical',
                        data: scanData.map(s => s.total_critical || s.critical || 0),
                        backgroundColor: 'rgba(239, 68, 68, 0.8)',
                        borderColor: '#ef4444',
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                    {
                        label: 'High',
                        data: scanData.map(s => s.total_high || s.high || 0),
                        backgroundColor: 'rgba(249, 115, 22, 0.8)',
                        borderColor: '#f97316',
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                    {
                        label: 'Medium',
                        data: scanData.map(s => s.total_medium || s.medium || 0),
                        backgroundColor: 'rgba(234, 179, 8, 0.8)',
                        borderColor: '#eab308',
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                    {
                        label: 'Low',
                        data: scanData.map(s => s.total_low || s.low || 0),
                        backgroundColor: 'rgba(107, 114, 128, 0.8)',
                        borderColor: '#6b7280',
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8899bb', padding: 16, usePointStyle: true, pointStyle: 'circle' },
                    },
                    tooltip: {
                        backgroundColor: '#1a2233',
                        titleColor: '#e8edf5',
                        bodyColor: '#8899bb',
                        borderColor: '#2a3a5a',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: {
                            footer: function(items) {
                                const idx = items[0].dataIndex;
                                const s = scanData[idx];
                                if (!s) return '';
                                const total = (s.total_critical || s.critical || 0)
                                    + (s.total_high || s.high || 0)
                                    + (s.total_medium || s.medium || 0)
                                    + (s.total_low || s.low || 0);
                                return 'Total: ' + total;
                            },
                        },
                    },
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: 'rgba(42, 58, 90, 0.3)', drawBorder: false },
                        ticks: { color: '#8899bb' },
                        title: { display: true, text: 'Scan Date', color: '#8899bb' },
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: 'rgba(42, 58, 90, 0.3)', drawBorder: false },
                        ticks: { color: '#8899bb', precision: 0 },
                        title: { display: true, text: 'Vulnerability Count', color: '#8899bb' },
                    },
                },
            },
        });
    }

    const pieCtx = document.getElementById('pieChart');
    if (pieCtx) {
        const totals = scanData.reduce(
            (acc, s) => {
                acc.critical += s.total_critical || s.critical || 0;
                acc.high += s.total_high || s.high || 0;
                acc.medium += s.total_medium || s.medium || 0;
                acc.low += s.total_low || s.low || 0;
                return acc;
            },
            { critical: 0, high: 0, medium: 0, low: 0 },
        );

        const hasData = totals.critical + totals.high + totals.medium + totals.low > 0;

        new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: hasData
                    ? ['Critical', 'High', 'Medium', 'Low']
                    : ['No Vulnerabilities'],
                datasets: [
                    {
                        data: hasData
                            ? [totals.critical, totals.high, totals.medium, totals.low]
                            : [1],
                        backgroundColor: hasData
                            ? ['rgba(239, 68, 68, 0.8)', 'rgba(249, 115, 22, 0.8)', 'rgba(234, 179, 8, 0.8)', 'rgba(107, 114, 128, 0.8)']
                            : ['rgba(16, 185, 129, 0.3)'],
                        borderWidth: 2,
                        borderColor: '#111827',
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8899bb', padding: 16, usePointStyle: true, pointStyle: 'circle' },
                    },
                    tooltip: {
                        backgroundColor: '#1a2233',
                        titleColor: '#e8edf5',
                        bodyColor: '#8899bb',
                        borderColor: '#2a3a5a',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: {
                            label: function(item) {
                                if (!hasData) return 'Target is secure — no vulnerabilities';
                                const total = totals.critical + totals.high + totals.medium + totals.low;
                                const val = item.parsed;
                                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                                return item.label + ': ' + val + ' (' + pct + '%)';
                            },
                        },
                    },
                },
            },
        });
    }
}

async function pollScanStatus(scanId, onComplete) {
    const interval = setInterval(async () => {
        try {
            const resp = await fetch('/api/scan-status/' + scanId);
            const data = await resp.json();
            if (data.error) {
                clearInterval(interval);
                onComplete(null);
                return;
            }
            if (data.status === 'Done' || data.status === 'Stopped' || data.status === 'Failed' || data.status === 'Error') {
                clearInterval(interval);
                onComplete(data);
            }
        } catch (e) {
            clearInterval(interval);
            onComplete(null);
        }
    }, 3000);
}
