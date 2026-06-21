#!/usr/bin/env python3
"""Generate comprehensive PDF documentation for VulnScanner (with code)."""

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

OUTPUT = "/home/kali/demo/vuln-scanner/VulnScanner_Full_Documentation.pdf"

doc = SimpleDocTemplate(
    OUTPUT, pagesize=letter,
    leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    topMargin=0.75 * inch, bottomMargin=0.75 * inch,
)

styles = getSampleStyleSheet()

def make_style(name, **kw):
    if name in styles:
        return ParagraphStyle(name + "_doc", **kw)
    s = ParagraphStyle(name, **kw)
    styles.add(s)
    return s

cover_title = make_style("CT", fontName="Helvetica-Bold", fontSize=28,
    alignment=TA_CENTER, spaceAfter=6, textColor=colors.HexColor("#00d4ff"))
cover_sub = make_style("CS", fontName="Helvetica", fontSize=14,
    alignment=TA_CENTER, spaceAfter=4, textColor=colors.HexColor("#c8d6e5"))
sec_h1 = make_style("SH1", fontName="Helvetica-Bold", fontSize=18,
    spaceBefore=20, spaceAfter=10, textColor=colors.HexColor("#0dcaf0"))
sec_h2 = make_style("SH2", fontName="Helvetica-Bold", fontSize=14,
    spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#5a9fd4"))
sec_h3 = make_style("SH3", fontName="Helvetica-Bold", fontSize=11,
    spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#c8d6e5"))
body_j = make_style("BJ", fontName="Helvetica", fontSize=10,
    leading=14, alignment=TA_JUSTIFY, spaceAfter=6)
code_block = make_style("CB", fontName="Courier", fontSize=8,
    leading=11, leftIndent=16, spaceAfter=4,
    backColor=colors.HexColor("#1a2a3a"),
    textColor=colors.HexColor("#e8c87a"),
    borderWidth=1, borderColor=colors.HexColor("#2a3a4a"),
    borderPadding=6)
bullet_style = make_style("BL", fontName="Helvetica", fontSize=10,
    leading=14, leftIndent=24, bulletIndent=12, spaceAfter=3)

def make_table(headers, rows, col_widths=None):
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#2a3a4a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    t.setStyle(TableStyle(style_cmds))
    return t

def code(text):
    return Paragraph(text.replace("\n", "<br/>"), code_block)

def bullet(text):
    return Paragraph(f"&bull; {text}", bullet_style)

elements = []

# ── COVER PAGE ──
elements.append(Spacer(1, 2.5 * inch))
elements.append(Paragraph("VulnScanner", cover_title))
elements.append(Paragraph("Advanced Web Vulnerability Scanner", cover_sub))
elements.append(Spacer(1, 0.3 * inch))
elements.append(Paragraph("Documentation v1.0", ParagraphStyle(
    "CS2", parent=cover_sub, fontSize=11, textColor=colors.HexColor("#6c8aa0"),
)))
elements.append(Spacer(1, 0.15 * inch))
elements.append(Paragraph("June 2026", ParagraphStyle(
    "CS3", parent=cover_sub, fontSize=10, textColor=colors.HexColor("#4a6a7a"),
)))
elements.append(PageBreak())

# ── TABLE OF CONTENTS ──
elements.append(Paragraph("Table of Contents", sec_h1))
toc_items = [
    "1. Project Overview",
    "2. Architecture",
    "3. Project Structure",
    "4. Prerequisites & Installation",
    "5. Configuration",
    "6. Running the Application",
    "7. Scanning Targets",
    "8. Dashboard Features",
    "9. API Endpoints",
    "10. Automated Scheduling",
    "11. Email Alerts",
    "12. Exporting Reports (PDF/CSV)",
    "13. CI/CD Pipeline",
    "14. Database Schema",
    "15. Legal Scanning Targets",
    "16. Troubleshooting",
]
for item in toc_items:
    elements.append(Paragraph(item, ParagraphStyle(
        "TOC", fontName="Helvetica", fontSize=11, leading=18,
        leftIndent=16, textColor=colors.HexColor("#c8d6e5"),
    )))
elements.append(PageBreak())

# ── 1. PROJECT OVERVIEW ──
elements.append(Paragraph("1. Project Overview", sec_h1))
elements.append(Paragraph(
    "VulnScanner is a full-stack vulnerability management system that integrates "
    "with <b>OpenVAS / Greenbone Community Edition</b> as the scanning engine, "
    "uses <b>Python Flask</b> for the web dashboard, and <b>SQLite</b> as the local database. "
    "It provides automated vulnerability scanning, severity-based dashboards with charts, "
    "PDF/CSV report generation, SMTP email alerts for critical findings, and "
    "a built-in scheduler for recurring scans.",
    body_j,
))
elements.append(Paragraph(
    "The project includes a built-in <b>demo mode</b> that simulates realistic vulnerabilities "
    "(real CVEs with descriptions and remediation steps) without requiring an OpenVAS installation. "
    "This makes it ideal for training, demonstrations, and testing.",
    body_j,
))
elements.append(bullet("<b>OpenVAS/GVM Integration</b> &mdash; Native scan automation via <i>python-gvm</i>"))
elements.append(bullet("<b>Flask Dashboard</b> &mdash; KPI cards, stacked bar charts, pie charts, CVE tables, scan history"))
elements.append(bullet("<b>PDF &amp; CSV Export</b> &mdash; Professional vulnerability reports for compliance and sharing"))
elements.append(bullet("<b>SMTP Email Alerts</b> &mdash; Instant notifications for Critical/High severity findings"))
elements.append(bullet("<b>Automated Scheduling</b> &mdash; Daily or weekly recurring scans"))
elements.append(bullet("<b>Demo Mode</b> &mdash; 18 realistic CVEs auto-injected when GVM is unavailable"))
elements.append(bullet("<b>CI/CD Integration</b> &mdash; GitHub Actions workflow for automated scanning"))

# ── 2. ARCHITECTURE ──
elements.append(Paragraph("2. Architecture", sec_h1))
elements.append(Paragraph(
    "VulnScanner follows a modular architecture with clearly separated components:",
    body_j,
))
arch_table = make_table(
    ["Component", "File", "Responsibility"],
    [
        ["Web Server", "app.py", "Flask routes, dashboard rendering, API endpoints"],
        ["Scanner Engine", "scanner.py", "GVM/OpenVAS scan orchestration & demo fallback"],
        ["Database Layer", "database.py", "SQLite CRUD for targets, scans, vulnerabilities"],
        ["Alert System", "alerts.py", "SMTP-based email notifications for critical CVEs"],
        ["Scheduler", "scheduler.py", "Thread-based daily/weekly scan scheduling"],
        ["Templates", "templates/*.html", "Jinja2 HTML views (dashboard, history, CVE detail)"],
        ["Static Assets", "static/", "CSS styling and Chart.js rendering"],
        ["Report Export", "app.py (routes)", "PDF (ReportLab) and CSV generation"],
    ],
    col_widths=[1.3 * inch, 1.5 * inch, 4.2 * inch],
)
elements.append(arch_table)
elements.append(Spacer(1, 0.1 * inch))
elements.append(Paragraph(
    "The application flow: User triggers a scan (via UI or API) &rarr; scanner.py connects to "
    "GVM Unix socket (or falls back to demo mode) &rarr; results are stored in SQLite &rarr; "
    "dashboard reads from DB and displays charts &rarr; alerts are sent for Critical/High findings.",
    body_j,
))

# ── 3. PROJECT STRUCTURE ──
elements.append(Paragraph("3. Project Structure", sec_h1))
tree = """vuln-scanner/
  app.py                 # Flask web application
  scanner.py             # Scan engine (GVM + demo fallback)
  database.py            # SQLite ORM layer
  alerts.py              # SMTP email alerts
  scheduler.py           # Recurring scan scheduler
  run.sh                 # Convenience launcher script
  requirements.txt       # Python dependencies
  vulndb.sqlite          # SQLite database file
  README.md              # Quick-start guide
  .github/workflows/
    scan.yml             # GitHub Actions CI/CD pipeline
  templates/
    dashboard.html       # Main dashboard view
    scan_history.html    # Scan history table
    cve_detail.html      # CVE breakdown view
  static/
    css/style.css        # Dark-themed UI styles
    js/charts.js         # Chart.js bar & pie charts
  reports/               # (optional) exported reports
  venv/                  # Python virtual environment"""
elements.append(Preformatted(tree, code_block))

# ── 4. PREREQUISITES & INSTALLATION ──
elements.append(PageBreak())
elements.append(Paragraph("4. Prerequisites &amp; Installation", sec_h1))
elements.append(Paragraph("4.1 System Requirements", sec_h2))
elements.append(bullet("Python 3.10+"))
elements.append(bullet("pip (Python package manager)"))
elements.append(bullet("(Optional) OpenVAS / Greenbone Community Edition for real scanning"))
elements.append(bullet("(Optional) SMTP server for email alerts"))

elements.append(Paragraph("4.2 One-Time Setup", sec_h2))
elements.append(Paragraph("Step 1 &mdash; Clone the repository:", body_j))
elements.append(code("git clone <your-repo-url>\ncd vuln-scanner"))
elements.append(Paragraph("Step 2 &mdash; Create and activate a virtual environment:", body_j))
elements.append(code("python3 -m venv venv\nsource venv/bin/activate  # Linux/Mac\n# venv\\Scripts\\activate  # Windows"))
elements.append(Paragraph("Step 3 &mdash; Install dependencies:", body_j))
elements.append(code("pip install -r requirements.txt"))

elements.append(Paragraph("Dependencies (from requirements.txt):", body_j))
dep_table = make_table(
    ["Package", "Version", "Purpose"],
    [
        ["flask", "3.1.0", "Web framework for the dashboard"],
        ["python-gvm", ">=24.11.0", "OpenVAS/GVM protocol bindings"],
        ["reportlab", ">=4.0", "PDF report generation"],
        ["schedule", ">=1.2", "Recurring job scheduling"],
        ["gvm-tools", ">=24.11.0", "GVM CLI utilities"],
    ],
    col_widths=[1.5 * inch, 1.2 * inch, 4.3 * inch],
)
elements.append(dep_table)

elements.append(Paragraph("4.3 (Optional) Install OpenVAS / Greenbone", sec_h2))
elements.append(Paragraph(
    "If you want real vulnerability scanning instead of demo mode, install OpenVAS:",
    body_j,
))
elements.append(code(
    "sudo add-apt-repository ppa:mrazavi/gvm\n"
    "sudo apt update\n"
    "sudo apt install -y gvm gvm-tools\n"
    "sudo gvm-setup\n"
    "sudo gvm-fix-permissions\n"
    "sudo gvm-check-setup  # verify installation"
))

# ── 5. CONFIGURATION ──
elements.append(Paragraph("5. Configuration", sec_h1))
elements.append(Paragraph("All configuration is via environment variables. None are required for demo mode.", body_j))
cfg_table = make_table(
    ["Variable", "Default", "Description"],
    [
        ["PORT", "5000", "Flask server port"],
        ["FLASK_DEBUG", "true", "Enable debug mode"],
        ["GVM_USER", "admin", "GVM/OpenVAS username"],
        ["GVM_PASS", "admin", "GVM/OpenVAS password"],
        ["SMTP_SERVER", "sandbox.smtp.mailtrap.io", "SMTP server for alerts"],
        ["SMTP_PORT", "587", "SMTP server port"],
        ["SMTP_USER", "", "SMTP authentication username"],
        ["SMTP_PASS", "", "SMTP authentication password"],
        ["SMTP_FROM", "scanner@vulnscanner.local", "Sender email address"],
        ["ALERT_EMAIL", "admin@example.com", "Recipient for alerts"],
        ["ALERT_ENABLED", "false", "Enable email alerts (true/false)"],
    ],
    col_widths=[1.6 * inch, 1.6 * inch, 3.8 * inch],
)
elements.append(cfg_table)
elements.append(Spacer(1, 0.1 * inch))
elements.append(Paragraph("Example configuration for Mailtrap (testing):", body_j))
elements.append(code(
    "export SMTP_SERVER=sandbox.smtp.mailtrap.io\n"
    "export SMTP_PORT=587\n"
    "export SMTP_USER=your_mailtrap_user\n"
    "export SMTP_PASS=your_mailtrap_pass\n"
    "export ALERT_EMAIL=admin@example.com\n"
    "export ALERT_ENABLED=true"
))

# ── 6. RUNNING THE APPLICATION ──
elements.append(PageBreak())
elements.append(Paragraph("6. Running the Application", sec_h1))
elements.append(Paragraph("6.1 Start the Dashboard", sec_h2))
elements.append(Paragraph("Using the convenience script (recommended):", body_j))
elements.append(code("bash run.sh app"))
elements.append(Paragraph("Or directly:", body_j))
elements.append(code("source venv/bin/activate\npython app.py"))
elements.append(Paragraph("Open <b>http://localhost:5000</b> in your browser.", body_j))

elements.append(Paragraph("6.2 Run a One-Time Scan", sec_h2))
elements.append(code("bash run.sh scan"))
elements.append(Paragraph("This scans the default targets. Results appear in the dashboard after refresh.", body_j))

elements.append(Paragraph("6.3 Start the Scheduler", sec_h2))
elements.append(code("bash run.sh scheduler"))
elements.append(Paragraph("Runs a scan immediately and then every 24 hours. Keeps running until CTRL+C.", body_j))

elements.append(Paragraph("6.4 Run in Background (Linux)", sec_h2))
elements.append(code("nohup venv/bin/python app.py > flask.log 2>&1 &\necho $! > flask.pid  # save PID for later"))

# ── 7. SCANNING TARGETS ──
elements.append(Paragraph("7. Scanning Targets", sec_h1))
elements.append(Paragraph("7.1 Default Targets", sec_h2))
elements.append(Paragraph(
    "Two default targets are hardcoded in scanner.py (line 242-244). "
    "These are publicly authorized test sites:",
    body_j,
))
target_table = make_table(
    ["Name", "URL", "Description"],
    [
        ["Acunetix TestPHP", "http://testphp.vulnweb.com", "Publicly authorized test site"],
        ["Nmap ScanMe", "http://scanme.nmap.org", "Authorized by nmap.org for testing"],
    ],
    col_widths=[1.5 * inch, 2.5 * inch, 3.0 * inch],
)
elements.append(target_table)

elements.append(Paragraph("7.2 Scanning via Dashboard", sec_h2))
elements.append(Paragraph(
    "On the dashboard, use the <b>Manual Scan</b> form: enter a target URL and name, "
    "then click <b>Scan Now</b>. The page refreshes automatically when the scan completes.",
    body_j,
))
elements.append(Paragraph("7.3 Scanning via API", sec_h2))
elements.append(code(
    'curl -X POST http://localhost:5000/api/scan \\\n'
    '  -H "Content-Type: application/json" \\\n'
    '  -d \'{"host":"http://example.com","name":"My Scan"}\''
))

# ── 8. DASHBOARD FEATURES ──
elements.append(Paragraph("8. Dashboard Features", sec_h1))
elements.append(Paragraph("8.1 KPI Cards", sec_h2))
elements.append(Paragraph(
    "Four severity cards at the top display the total count of <b>Critical</b> (red), "
    "<b>High</b> (orange), <b>Medium</b> (blue), and <b>Low</b> (gray) vulnerabilities "
    "aggregated across all scans.",
    body_j,
))
elements.append(Paragraph("8.2 Charts", sec_h2))
elements.append(bullet("<b>Bar Chart</b> &mdash; Stacked bar chart showing vulnerability counts per scan date"))
elements.append(bullet("<b>Pie Chart</b> &mdash; Severity distribution across all scans with percentage tooltips"))
elements.append(Paragraph("8.3 Recent Vulnerabilities Table", sec_h2))
elements.append(Paragraph(
    "Lists the most recent 50 vulnerabilities with CVE ID, name, severity badge, CVSS score, and status. "
    "Export buttons for CSV and PDF are provided.",
    body_j,
))
elements.append(Paragraph("8.4 Alert Log", sec_h2))
elements.append(Paragraph(
    "Displays the last 10 email alerts sent, showing timestamp, CVE ID, and recipient.",
    body_j,
))
elements.append(Paragraph("8.5 Scan History Page", sec_h2))
elements.append(Paragraph(
    "Lists all scans with target info, date, status badge, severity counts, and action buttons "
    "to view CVEs, or export individual scan reports in CSV or PDF format.",
    body_j,
))
elements.append(Paragraph("8.6 CVE Detail Page", sec_h2))
elements.append(Paragraph(
    "Full breakdown of all vulnerabilities with CVE ID, name, severity, CVSS score, "
    "description, remediation solution, and status.",
    body_j,
))

# ── 9. API ENDPOINTS ──
elements.append(PageBreak())
elements.append(Paragraph("9. API Endpoints", sec_h1))
api_table = make_table(
    ["Method", "Route", "Description"],
    [
        ["GET", "/", "Dashboard (HTML)"],
        ["GET", "/scan-history", "Scan history table (HTML)"],
        ["GET", "/cve-detail", "CVE breakdown (HTML)"],
        ["POST", "/api/scan", "Trigger a scan (JSON)"],
        ["GET", "/api/stats", "JSON stats for charts"],
        ["GET", "/export/pdf?scan_id=ID", "Download PDF report"],
        ["GET", "/export/csv?scan_id=ID", "Download CSV report"],
        ["GET", "/health", "Health check endpoint"],
    ],
    col_widths=[0.8 * inch, 2.2 * inch, 4.0 * inch],
)
elements.append(api_table)
elements.append(Paragraph("/api/scan &mdash; Request Body Example:", sec_h3))
elements.append(code('{\n  "host": "http://testphp.vulnweb.com",\n  "name": "Manual Scan"\n}'))
elements.append(Paragraph("/api/scan &mdash; Response Example:", sec_h3))
elements.append(code('{\n  "status": "ok",\n  "scan_id": 5\n}'))
elements.append(Paragraph("/api/stats &mdash; Response Example:", sec_h3))
elements.append(code(
    '{\n'
    '  "counts": {"critical": 3, "high": 5, "medium": 4, "low": 2},\n'
    '  "scans": [\n'
    '    {"id": 1, "target": "Acunetix TestPHP", "date": "2026-06-10 04:30:00",\n'
    '     "critical": 2, "high": 3, "medium": 2, "low": 1}\n'
    '  ]\n'
    '}'
))

# ── 10. AUTOMATED SCHEDULING ──
elements.append(Paragraph("10. Automated Scheduling", sec_h1))
elements.append(Paragraph(
    "The scheduler (scheduler.py) uses the <i>schedule</i> library to run scans at configurable intervals. "
    "It runs a scan immediately on start, then repeats daily or weekly.",
    body_j,
))
elements.append(Paragraph("Usage:", sec_h2))
elements.append(code(
    "# Via run.sh (default: daily):\n"
    "bash run.sh scheduler\n\n"
    "# Direct Python (custom interval):\n"
    'python -c "from scheduler import start_scheduler_thread; start_scheduler_thread(interval_days=1); import time; time.sleep(99999)"'
))

# ── 11. EMAIL ALERTS ──
elements.append(Paragraph("11. Email Alerts", sec_h1))
elements.append(Paragraph(
    "The alert system (alerts.py) sends SMTP email notifications for <b>Critical</b> and <b>High</b> "
    "severity vulnerabilities after each scan. Alerts are configured via environment variables.",
    body_j,
))
elements.append(Paragraph("Alert email template:", sec_h2))
elements.append(code(
    "Subject: [VulnScanner] Critical: CVE-2024-21626 on Acunetix TestPHP\n\n"
    "Vulnerability Detected\n"
    "======================\n"
    "Target:     Acunetix TestPHP\n"
    "CVE ID:     CVE-2024-21626\n"
    "Name:       runc container breakout\n"
    "Severity:   Critical\n"
    "CVSS Score: 9.8\n"
    "Scan ID:    5\n\n"
    "Please investigate immediately."
))
elements.append(Paragraph(
    "When <b>ALERT_ENABLED=false</b> (default), alerts are logged but not sent. "
    "Set it to <b>true</b> with valid SMTP credentials to enable delivery.",
    body_j,
))

# ── 12. EXPORTING REPORTS ──
elements.append(Paragraph("12. Exporting Reports (PDF / CSV)", sec_h1))
elements.append(Paragraph("12.1 PDF Export", sec_h2))
elements.append(Paragraph("Uses <b>ReportLab</b> to generate a professionally formatted PDF with:", body_j))
elements.append(bullet("Title page with generation timestamp"))
elements.append(bullet("Target metadata (name, host, scan date, status)"))
elements.append(bullet("Severity summary table (Critical/High/Medium/Low/Total)"))
elements.append(bullet("Vulnerability details table (CVE, name, severity, CVSS, status)"))
elements.append(Paragraph("Get link: <b>/export/pdf</b> (all data) or <b>/export/pdf?scan_id=ID</b> (specific scan)", body_j))
elements.append(Paragraph("12.2 CSV Export", sec_h2))
elements.append(Paragraph(
    "Generates a structured CSV with the same data sections as the PDF, suitable for spreadsheet "
    "import or further analysis.",
    body_j,
))
elements.append(Paragraph("Get link: <b>/export/csv</b> or <b>/export/csv?scan_id=ID</b>", body_j))

# ── 13. CI/CD PIPELINE ──
elements.append(PageBreak())
elements.append(Paragraph("13. CI/CD Pipeline", sec_h1))
elements.append(Paragraph(
    "A GitHub Actions workflow (<i>.github/workflows/scan.yml</i>) runs automated scans:",
    body_j,
))
ci_table = make_table(
    ["Trigger", "Schedule"],
    [
        ["Push to main branch", "On every push"],
        ["Weekly scan", "Monday 06:00 UTC"],
        ["Manual trigger", "Via GitHub Actions UI (workflow_dispatch)"],
    ],
    col_widths=[2.5 * inch, 4.5 * inch],
)
elements.append(ci_table)
elements.append(Spacer(1, 0.1 * inch))
elements.append(Paragraph("The pipeline:", body_j))
elements.append(bullet("Checks out the repository"))
elements.append(bullet("Sets up Python 3.10"))
elements.append(bullet("Installs system dependencies (libxml2, libssh, etc.)"))
elements.append(bullet("Installs Python packages from requirements.txt"))
elements.append(bullet("Runs <i>python scanner.py</i>"))
elements.append(bullet("Uploads the SQLite database as an artifact (retained 30 days)"))
elements.append(bullet("Sends notification on failure"))

# ── 14. DATABASE SCHEMA ──
elements.append(Paragraph("14. Database Schema", sec_h1))
elements.append(Paragraph("SQLite database stored at <i>vulndb.sqlite</i>. Four tables:", body_j))
elements.append(Paragraph("Table: targets", sec_h2))
elements.append(code(
    "id          INTEGER PRIMARY KEY AUTOINCREMENT\n"
    "name        TEXT NOT NULL\n"
    "host        TEXT NOT NULL\n"
    "created_at  DATETIME DEFAULT CURRENT_TIMESTAMP"
))
elements.append(Paragraph("Table: scans", sec_h2))
elements.append(code(
    "id              INTEGER PRIMARY KEY AUTOINCREMENT\n"
    "target_id       INTEGER NOT NULL REFERENCES targets(id)\n"
    "scan_date       DATETIME DEFAULT CURRENT_TIMESTAMP\n"
    "status          TEXT DEFAULT 'pending'\n"
    "total_critical  INTEGER DEFAULT 0\n"
    "total_high      INTEGER DEFAULT 0\n"
    "total_medium    INTEGER DEFAULT 0\n"
    "total_low       INTEGER DEFAULT 0"
))
elements.append(Paragraph("Table: vulnerabilities", sec_h2))
elements.append(code(
    "id          INTEGER PRIMARY KEY AUTOINCREMENT\n"
    "scan_id     INTEGER NOT NULL REFERENCES scans(id)\n"
    "cve_id      TEXT DEFAULT ''\n"
    "name        TEXT DEFAULT ''\n"
    "severity    TEXT DEFAULT ''\n"
    "cvss_score  REAL DEFAULT 0.0\n"
    "description TEXT DEFAULT ''\n"
    "solution    TEXT DEFAULT ''\n"
    "status      TEXT DEFAULT 'Open'"
))
elements.append(Paragraph("Table: alert_log", sec_h2))
elements.append(code(
    "id              INTEGER PRIMARY KEY AUTOINCREMENT\n"
    "scan_id         INTEGER REFERENCES scans(id)\n"
    "vulnerability_id INTEGER REFERENCES vulnerabilities(id)\n"
    "recipient       TEXT\n"
    "subject         TEXT\n"
    "sent_at         DATETIME DEFAULT CURRENT_TIMESTAMP"
))

# ── 15. LEGAL SCANNING TARGETS ──
elements.append(PageBreak())
elements.append(Paragraph("15. Legal Scanning Targets", sec_h1))
elements.append(Paragraph(
    "These targets explicitly authorize security testing. Always verify authorization "
    "before scanning any system.",
    body_j,
))
legal_table = make_table(
    ["Target", "URL", "Notes"],
    [
        ["OWASP Juice Shop", "https://juice-shop.herokuapp.com", "Modern OWASP training app"],
        ["OWASP Bricks", "http://sechow.com/bricks/", "PHP vulnerable web app"],
        ["Acunetix TestPHP", "http://testphp.vulnweb.com", "Publicly authorized test site"],
        ["Nmap ScanMe", "http://scanme.nmap.org", "Authorized by nmap.org"],
        ["WebGoat", "https://webgoat.herokuapp.com", "OWASP deliberately insecure app"],
        ["DVWA", "Run locally via Docker", "Damn Vulnerable Web App"],
        ["HackTheBox", "https://hackthebox.com", "CTF & pentesting labs (VPN req.)"],
        ["PentesterLab", "https://pentesterlab.com", "Hands-on security exercises"],
    ],
    col_widths=[1.5 * inch, 2.5 * inch, 3.0 * inch],
)
elements.append(legal_table)
elements.append(Spacer(1, 0.15 * inch))
elements.append(Paragraph("Scanning Juice Shop via API:", body_j))
elements.append(code(
    'curl -X POST http://localhost:5000/api/scan \\\n'
    '  -H "Content-Type: application/json" \\\n'
    '  -d \'{"host":"https://juice-shop.herokuapp.com","name":"Juice Shop"}\''
))
elements.append(Paragraph("Run Juice Shop locally with Docker:", body_j))
elements.append(code(
    "docker pull bkimminich/juice-shop\n"
    "docker run -d -p 3000:3000 bkimminich/juice-shop"
))

# ── 16. TROUBLESHOOTING ──
elements.append(Paragraph("16. Troubleshooting", sec_h1))
trouble_table = make_table(
    ["Issue", "Cause", "Solution"],
    [
        ["ModuleNotFoundError", "Dependencies not installed", "Run: pip install -r requirements.txt"],
        ["Port 5000 in use", "Another process on port 5000", "Set PORT env var: export PORT=5001"],
        ["Scan returns error", "GVM socket not found", "Demo mode auto-fallback; check logs"],
        ["Alerts not sending", "ALERT_ENABLED=false or bad SMTP", "Set ALERT_ENABLED=true; check credentials"],
        ["PDF export fails", "ReportLab missing font", "Install: pip install reportlab"],
        ["Blank dashboard", "No scans have run", "Trigger a scan via UI or POST /api/scan"],
        ["SQLite locked", "Concurrent writes", "WAL mode enabled by default; retry"],
        ["Charts not rendering", "No scan data", "Run a scan to populate the database"],
    ],
    col_widths=[1.5 * inch, 2.2 * inch, 3.3 * inch],
)
elements.append(trouble_table)

doc.build(elements)
print(f"[+] PDF generated: {OUTPUT}")
