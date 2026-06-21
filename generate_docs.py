#!/usr/bin/env python3
"""Generate plain-English PDF documentation for VulnScanner (no code)."""

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT

OUTPUT = "/home/kali/demo/vuln-scanner/VulnScanner_Documentation.pdf"

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

cover_title = make_style("CT", fontName="Helvetica-Bold", fontSize=26,
    alignment=TA_CENTER, spaceAfter=6, textColor=colors.HexColor("#00d4ff"))
cover_sub = make_style("CS", fontName="Helvetica", fontSize=13,
    alignment=TA_CENTER, spaceAfter=4, textColor=colors.HexColor("#c8d6e5"))
sec_h1 = make_style("SH1", fontName="Helvetica-Bold", fontSize=17,
    spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#0dcaf0"))
sec_h2 = make_style("SH2", fontName="Helvetica-Bold", fontSize=13,
    spaceBefore=12, spaceAfter=5, textColor=colors.HexColor("#5a9fd4"))
body = make_style("BJ", fontName="Helvetica", fontSize=10,
    leading=15, alignment=TA_JUSTIFY, spaceAfter=8)
body_indent = make_style("BI", fontName="Helvetica", fontSize=10,
    leading=15, alignment=TA_JUSTIFY, leftIndent=20, spaceAfter=6)
toc_style = make_style("TOC", fontName="Helvetica", fontSize=11,
    leading=20, leftIndent=16, textColor=colors.HexColor("#c8d6e5"))

elements = []

# ── COVER PAGE ──
elements.append(Spacer(1, 2.5 * inch))
elements.append(Paragraph("VulnScanner", cover_title))
elements.append(Paragraph("Advanced Web Vulnerability Scanner", cover_sub))
elements.append(Spacer(1, 0.3 * inch))
elements.append(Paragraph("Complete Project Documentation", ParagraphStyle(
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
    "2. Architecture of the Application",
    "3. Project Structure",
    "4. Prerequisites and Installation",
    "5. Configuration Settings",
    "6. How to Run the Application",
    "7. Scanning Targets",
    "8. Dashboard and Its Features",
    "9. API Endpoints",
    "10. Automated Scheduling",
    "11. Email Alert System",
    "12. Exporting Reports",
    "13. CI/CD Pipeline",
    "14. Database Structure",
    "15. Legal Targets for Practice",
    "16. Troubleshooting Common Issues",
]
for item in toc_items:
    elements.append(Paragraph(item, toc_style))
elements.append(PageBreak())

# ── 1. PROJECT OVERVIEW ──
elements.append(Paragraph("1. Project Overview", sec_h1))
elements.append(Paragraph(
    "VulnScanner is a complete vulnerability management system designed to help security professionals "
    "and organizations identify, track, and manage security weaknesses in their web applications. "
    "Think of it as a centralized command center that performs automated security scans, "
    "presents the results through an easy-to-understand web dashboard, generates professional reports, "
    "and sends email alerts when serious vulnerabilities are discovered.",
    body,
))
elements.append(Paragraph(
    "The project integrates with OpenVAS, which is a well-known open-source vulnerability scanning "
    "engine. However, the application also includes a built-in demonstration mode that works even "
    "without OpenVAS installed. This demo mode simulates realistic vulnerabilities using real-world "
    "CVEs, making the project immediately usable for learning, demonstrations, and testing purposes.",
    body,
))
elements.append(Paragraph(
    "The main objectives of this project are to automate the process of scanning web applications "
    "for vulnerabilities, organize the findings by severity level, provide visual insights through "
    "charts and graphs, enable report generation in PDF and CSV formats, notify administrators about "
    "critical issues via email, and allow scans to run automatically on a schedule. It is built using "
    "Python with the Flask web framework for the dashboard, SQLite for data storage, and ReportLab "
    "for PDF generation.",
    body,
))
elements.append(Paragraph(
    "The application is particularly useful for small to medium-sized security teams, bug bounty "
    "hunters, penetration testers, and anyone learning about web application security. It eliminates "
    "the need to manually run scans and compile reports, saving time and ensuring consistency in "
    "the vulnerability management process.",
    body,
))

# ── 2. ARCHITECTURE ──
elements.append(Paragraph("2. Architecture of the Application", sec_h1))
elements.append(Paragraph(
    "VulnScanner follows a modular architecture where each component has a specific responsibility. "
    "The entire application is written in Python and organized into several files that work together "
    "seamlessly. At the heart of the system is the Flask web server, which serves as the dashboard "
    "that users interact with through their web browser. This web server handles all the pages, "
    "API requests, and report generation.",
    body,
))
elements.append(Paragraph(
    "The scanning engine is the component that performs the actual vulnerability assessment. When a "
    "scan is triggered, it attempts to connect to the OpenVAS service running on the same machine. "
    "If OpenVAS is not available, which is the common case for demo and learning environments, the "
    "system automatically switches to demonstration mode. In this mode, it randomly selects realistic "
    "vulnerabilities from a built-in library of eighteen real CVEs and presents them as scan results. "
    "This ensures the application is always functional regardless of whether a full scanning engine "
    "is installed.",
    body,
))
elements.append(Paragraph(
    "The database layer stores all information using SQLite, which is a lightweight file-based database. "
    "It keeps track of targets that have been scanned, the history of all scans performed, details of "
    "every vulnerability discovered, and logs of email alerts that were sent. The alert system handles "
    "sending email notifications when critical or high-severity vulnerabilities are found. The scheduler "
    "component allows scans to run automatically on a daily or weekly basis without any manual intervention. "
    "All of these components communicate through the database, which acts as the central data repository.",
    body,
))
elements.append(Paragraph(
    "The user interface consists of HTML templates rendered by the Flask server, with a dark-themed "
    "design that is both professional and easy on the eyes. Charts are drawn using the Chart.js "
    "JavaScript library directly in the browser, providing interactive visual representations of "
    "the vulnerability data. The entire application can run on a single machine and requires no "
    "external services other than an optional SMTP server for email alerts.",
    body,
))

# ── 3. PROJECT STRUCTURE ──
elements.append(Paragraph("3. Project Structure", sec_h1))
elements.append(Paragraph(
    "The project is organized into a clear directory structure. The main application file is called "
    "app.py and it contains all the web routes, dashboard logic, and report generation code. The "
    "scanning engine is in scanner.py, which handles both the OpenVAS integration and the demo mode "
    "fallback. Database operations are in database.py, which defines how targets, scans, vulnerabilities, "
    "and alerts are stored and retrieved from the SQLite database.",
    body,
))
elements.append(Paragraph(
    "The alert system lives in alerts.py and manages all email notification functionality. The scheduler "
    "is in scheduler.py and handles automated recurring scans. There is also a convenience script called "
    "run.sh that simplifies launching the application. The HTML templates are stored in a templates "
    "folder, containing three pages: the main dashboard, the scan history page, and the CVE detail page. "
    "Static assets like CSS stylesheets and JavaScript files are kept in a static folder. A requirements.txt "
    "file lists all Python dependencies needed to run the project. The SQLite database file is created "
    "automatically when the application starts.",
    body,
))
elements.append(Paragraph(
    "There is also a GitHub Actions workflow file for continuous integration and deployment, and a "
    "README.md file that provides quick-start instructions. This structure follows standard Python web "
    "application conventions, making it easy for developers familiar with Flask to understand and "
    "contribute to the project.",
    body,
))

# ── 4. PREREQUISITES & INSTALLATION ──
elements.append(PageBreak())
elements.append(Paragraph("4. Prerequisites and Installation", sec_h1))
elements.append(Paragraph(
    "Before using VulnScanner, you need to have Python version 3.10 or newer installed on your system. "
    "You will also need pip, which is the Python package manager that comes bundled with Python. "
    "No other software is strictly required because the application works in demo mode by default. "
    "However, if you want to perform real vulnerability scans using the OpenVAS engine, you would need "
    "to install OpenVAS separately on a Linux system. Additionally, if you wish to receive email alerts, "
    "you will need access to an SMTP server such as Gmail, Mailtrap, or any other email service.",
    body,
))
elements.append(Paragraph(
    "The installation process is straightforward. First, you obtain the project code by cloning the "
    "repository from GitHub. Then you navigate into the project directory and create a Python virtual "
    "environment, which is a best practice that keeps the project dependencies isolated from other "
    "Python projects on your system. Once the virtual environment is activated, you install all "
    "required Python packages using the requirements.txt file. This single command installs Flask "
    "for the web framework, python-gvm and gvm-tools for OpenVAS integration, reportlab for PDF "
    "generation, and the schedule library for automated task scheduling.",
    body,
))

# ── 5. CONFIGURATION ──
elements.append(Paragraph("5. Configuration Settings", sec_h1))
elements.append(Paragraph(
    "VulnScanner is configured entirely through environment variables, which means you do not need to "
    "edit any configuration files. This approach follows the twelve-factor app methodology and makes "
    "the application easy to deploy in different environments. None of these settings are mandatory "
    "because the application ships with sensible defaults that work out of the box for demo mode.",
    body,
))
elements.append(Paragraph(
    "You can change the port the Flask server runs on by setting the PORT variable, which defaults to "
    "5000. The debug mode can be toggled with FLASK_DEBUG. For OpenVAS integration, you can set "
    "GVM_USER and GVM_PASS, which both default to admin. The email alert system requires several "
    "settings: SMTP_SERVER and SMTP_PORT for the mail server address, SMTP_USER and SMTP_PASS for "
    "authentication credentials, SMTP_FROM for the sender address, and ALERT_EMAIL for the recipient. "
    "The ALERT_ENABLED variable must be set to true for emails to actually be sent. "
    "When alerts are disabled, the system still logs what it would have sent, allowing you to verify "
    "the configuration before enabling live email delivery.",
    body,
))

# ── 6. RUNNING THE APPLICATION ──
elements.append(PageBreak())
elements.append(Paragraph("6. How to Run the Application", sec_h1))
elements.append(Paragraph(
    "There are several ways to run VulnScanner depending on what you want to accomplish. The most "
    "common way is to start the web dashboard. You can do this using the provided run.sh script by "
    "typing bash run.sh app in the terminal. Alternatively, you can activate the virtual environment "
    "and run python app.py directly. Both methods start the Flask development server, which listens "
    "on all network interfaces on port 5000. You then open a web browser and navigate to "
    "http://localhost:5000 to access the dashboard.",
    body,
))
elements.append(Paragraph(
    "To run a vulnerability scan without starting the dashboard, you can use the command "
    "bash run.sh scan. This triggers the scanner to scan the two default targets and stores the "
    "results in the database. You can then start the dashboard afterward to view the results. "
    "For automated recurring scans, the command bash run.sh scheduler starts a process that runs "
    "a scan immediately and then repeats every twenty-four hours automatically.",
    body,
))
elements.append(Paragraph(
    "If you prefer to run the dashboard in the background so it keeps running even after you close "
    "the terminal, you can use the nohup command followed by the Python command, redirecting the "
    "output to a log file. This is useful for long-term deployment on servers where you want the "
    "application to keep running continuously.",
    body,
))

# ── 7. SCANNING TARGETS ──
elements.append(Paragraph("7. Scanning Targets", sec_h1))
elements.append(Paragraph(
    "VulnScanner comes with two default targets that are pre-configured for scanning. The first is "
    "Acunetix TestPHP, which is a publicly authorized test website hosted at testphp.vulnweb.com. "
    "The second is Nmap ScanMe, which is a test service provided by the makers of Nmap at "
    "scanme.nmap.org. Both of these explicitly authorize security testing, so you can scan them "
    "without any legal concerns. When you run a scan using the run.sh scan command or trigger "
    "one from the dashboard, these two targets are scanned automatically.",
    body,
))
elements.append(Paragraph(
    "You are not limited to these two targets. The dashboard includes a manual scan form where you "
    "can enter any URL you wish to scan. You simply type the target host address, give the scan a "
    "descriptive name, and click the Scan Now button. The application also provides an API endpoint "
    "that accepts scan requests in JSON format. This allows you to integrate scanning into other "
    "tools or scripts. You can send a POST request to the API with the host URL and scan name, "
    "and the system will run the scan and return the scan identifier.",
    body,
))

# ── 8. DASHBOARD FEATURES ──
elements.append(Paragraph("8. Dashboard and Its Features", sec_h1))
elements.append(Paragraph(
    "The dashboard is the main user interface of VulnScanner and it is designed to give you a "
    "comprehensive overview of your vulnerability landscape at a glance. When you open the dashboard, "
    "the first thing you see is a manual scan form where you can quickly launch a new scan against "
    "any target. Below the form, four large cards display the total counts of vulnerabilities "
    "categorized by severity. Critical vulnerabilities are shown in red, High in orange, Medium "
    "in blue, and Low in gray. These numbers are updated automatically as new scans are performed.",
    body,
))
elements.append(Paragraph(
    "The dashboard also features two interactive charts. A stacked bar chart shows the distribution "
    "of vulnerabilities across different scans over time. Each bar is color-coded by severity, making "
    "it easy to see trends and compare scan results. A pie chart displays the overall severity "
    "distribution across all scans combined, showing the percentage of each severity category. "
    "These charts are rendered using Chart.js and update dynamically as new data comes in.",
    body,
))
elements.append(Paragraph(
    "Below the charts, a table lists the most recent vulnerabilities with details such as the CVE "
    "identifier, vulnerability name, severity badge, CVSS score, and current status. The table is "
    "accompanied by export buttons that allow you to download the data as a CSV file or a PDF report. "
    "On the right side, an alert log shows the history of email notifications that have been sent "
    "for critical and high-severity findings.",
    body,
))
elements.append(Paragraph(
    "The dashboard also provides navigation to two additional pages. The Scan History page displays "
    "a complete log of all scans performed, showing each scan's target, date, status, and severity "
    "counts. From this page, you can view the CVE details for any specific scan or export individual "
    "scan reports. The CVE Detail page provides a full breakdown of all discovered vulnerabilities, "
    "including descriptions and recommended remediation steps. This is particularly useful for "
    "security teams who need to understand the nature of each vulnerability and how to fix it.",
    body,
))

# ── 9. API ENDPOINTS ──
elements.append(PageBreak())
elements.append(Paragraph("9. API Endpoints", sec_h1))
elements.append(Paragraph(
    "VulnScanner exposes several API endpoints that allow other applications and scripts to interact "
    "with the system programmatically. The main API endpoint is for triggering scans. This endpoint "
    "accepts POST requests with a JSON body containing the target host URL and an optional scan name. "
    "When called, it runs the scan and returns a JSON response indicating whether the scan was "
    "successful along with the scan identifier that can be used to reference the scan later.",
    body,
))
elements.append(Paragraph(
    "There is a statistics endpoint that returns JSON data about all scans and vulnerability counts, "
    "which is what the dashboard charts use to render their visualizations. This endpoint can be "
    "consumed by external monitoring tools or custom dashboards. The report export endpoints generate "
    "PDF and CSV files that can be downloaded. When called without any parameters, they export data "
    "from all scans. When a scan identifier is provided, they export data for that specific scan only. "
    "A health check endpoint is also available for monitoring whether the application is running "
    "properly, which is useful for deployment in containerized environments.",
    body,
))

# ── 10. AUTOMATED SCHEDULING ──
elements.append(Paragraph("10. Automated Scheduling", sec_h1))
elements.append(Paragraph(
    "One of the key features of VulnScanner is its ability to run scans automatically on a recurring "
    "schedule. This is particularly important for organizations that need to continuously monitor "
    "their web applications for new vulnerabilities. The scheduler works by running a scan immediately "
    "when it starts and then repeating the scan at a configured interval. By default, scans run once "
    "every twenty-four hours, which is suitable for most use cases.",
    body,
))
elements.append(Paragraph(
    "The scheduler can also be configured to run scans weekly instead of daily. This flexibility "
    "allows organizations to choose a schedule that matches their security policies and operational "
    "requirements. The scheduler runs in a separate thread, which means it does not interfere with "
    "the normal operation of the web dashboard. You can run it as a background process on a server "
    "and it will continue to perform scans automatically without any further interaction.",
    body,
))

# ── 11. EMAIL ALERTS ──
elements.append(Paragraph("11. Email Alert System", sec_h1))
elements.append(Paragraph(
    "The email alert system is designed to notify administrators immediately when serious vulnerabilities "
    "are discovered. After each scan completes, the system reviews all findings and sends email "
    "notifications for vulnerabilities classified as Critical or High severity. These are the "
    "vulnerabilities that pose the most immediate risk and require prompt attention.",
    body,
))
elements.append(Paragraph(
    "The alert emails include detailed information about the vulnerability, such as the target that "
    "was scanned, the CVE identifier, the vulnerability name, the severity level, the CVSS score, "
    "and the scan identifier. This information helps the recipient assess the urgency and take "
    "appropriate action. The email system requires an SMTP server to function. For testing and "
    "development, services like Mailtrap provide a safe environment where you can inspect emails "
    "without actually sending them to real recipients. When the alert system is disabled, which is "
    "the default setting, the application logs what it would have sent, allowing you to verify "
    "the configuration before enabling live delivery.",
    body,
))

# ── 12. EXPORTING REPORTS ──
elements.append(Paragraph("12. Exporting Reports", sec_h1))
elements.append(Paragraph(
    "VulnScanner can generate professional reports in two formats: PDF and CSV. The PDF reports "
    "are suitable for formal documentation, compliance reporting, and sharing with stakeholders "
    "who may not be technical. Each PDF report includes a title page with generation timestamp, "
    "target metadata showing what was scanned and when, a severity summary table with counts for "
    "each severity level, and a detailed table of all vulnerabilities found with their CVE identifiers, "
    "names, severity levels, CVSS scores, and current status. The PDFs are generated using the "
    "ReportLab library and have a clean, professional layout.",
    body,
))
elements.append(Paragraph(
    "The CSV reports are useful for data analysis, spreadsheet processing, and integration with "
    "other tools. They contain the same information as the PDF reports but in a structured, "
    "machine-readable format. Each row represents a vulnerability with all its attributes. Reports "
    "can be generated for all scans combined or for a specific scan by providing the scan identifier. "
    "The export functionality is accessible from the dashboard, the scan history page, and the CVE "
    "detail page, making it easy to generate reports from wherever you are viewing the data.",
    body,
))

# ── 13. CI/CD PIPELINE ──
elements.append(PageBreak())
elements.append(Paragraph("13. CI/CD Pipeline", sec_h1))
elements.append(Paragraph(
    "VulnScanner includes a continuous integration and deployment pipeline using GitHub Actions. "
    "This pipeline automates the scanning process so that security assessments happen automatically "
    "without requiring anyone to manually trigger them. The pipeline is configured to run in three "
    "scenarios. First, it runs whenever code is pushed to the main branch of the repository, "
    "ensuring that any changes to the scanning logic are immediately tested. Second, it runs on a "
    "weekly schedule every Monday at six in the morning UTC, providing regular automated security "
    "assessments. Third, it can be triggered manually from the GitHub Actions interface whenever an "
    "ad-hoc scan is needed.",
    body,
))
elements.append(Paragraph(
    "When the pipeline runs, it checks out the latest code, sets up Python, installs all necessary "
    "dependencies including system libraries that OpenVAS requires, executes the scanner against the "
    "configured targets, and uploads the resulting SQLite database as an artifact that can be "
    "downloaded for analysis. If the pipeline fails for any reason, it sends a notification so the "
    "team can investigate. This integration makes VulnScanner suitable for DevSecOps workflows where "
    "security scanning is an integral part of the software development lifecycle.",
    body,
))

# ── 14. DATABASE STRUCTURE ──
elements.append(Paragraph("14. Database Structure", sec_h1))
elements.append(Paragraph(
    "The application uses SQLite as its database engine, which stores all data in a single file called "
    "vulndb.sqlite. This approach makes the application portable and easy to back up. The database "
    "is organized into four tables that store different types of information. The targets table keeps "
    "a record of all hosts that have been scanned, including their names and URLs along with timestamps "
    "of when they were added.",
    body,
))
elements.append(Paragraph(
    "The scans table records every scan that has been performed. It links each scan to its target, "
    "stores the date and time of the scan, the current status such as pending, running, done, or error, "
    "and the counts of vulnerabilities found at each severity level. The vulnerabilities table contains "
    "the detailed findings of each scan. Each vulnerability record includes the CVE identifier, "
    "vulnerability name, severity classification, CVSS score, a description of the vulnerability, "
    "recommended remediation steps, and the current status such as open or fixed.",
    body,
))
elements.append(Paragraph(
    "The alert log table keeps a history of all email notifications that have been sent, recording "
    "which scan and vulnerability triggered the alert, the recipient's email address, the subject "
    "line, and the timestamp when it was sent. The database is created automatically the first time "
    "the application runs, and it uses Write-Ahead Logging mode for better performance when multiple "
    "operations are happening concurrently.",
    body,
))

# ── 15. LEGAL TARGETS ──
elements.append(Paragraph("15. Legal Targets for Practice", sec_h1))
elements.append(Paragraph(
    "When learning about vulnerability scanning or testing the application, it is important to use "
    "targets that explicitly authorize security testing. Scanning systems without permission is "
    "illegal in most jurisdictions and can result in serious legal consequences. VulnScanner comes "
    "with two pre-configured targets that are publicly authorized for testing, but there are several "
    "other well-known targets you can use for practice.",
    body,
))
elements.append(Paragraph(
    "One of the most popular training targets is OWASP Juice Shop, which is a deliberately insecure "
    "web application designed for security training. It contains vulnerabilities from all categories "
    "in the OWASP Top Ten and is an excellent target for practicing vulnerability scanning. It can "
    "be accessed online or run locally using Docker. Another option is WebGoat, which is an OWASP "
    "training application that teaches web application security through hands-on exercises. "
    "The website HackTheBox provides virtual machines and challenges that are specifically designed "
    "for penetration testing practice, though it requires a VPN connection.",
    body,
))
elements.append(Paragraph(
    "For those who want to run targets locally, the Damn Vulnerable Web Application can be run using "
    "Docker. PentesterLab offers a subscription-based platform with progressive security exercises. "
    "Regardless of which target you choose, always verify that you have explicit authorization before "
    "scanning. Many of these resources have terms of service that specify the scope of authorized "
    "testing activities.",
    body,
))

# ── 16. TROUBLESHOOTING ──
elements.append(Paragraph("16. Troubleshooting Common Issues", sec_h1))
elements.append(Paragraph(
    "If you encounter a ModuleNotFoundError when trying to run the application, it likely means the "
    "Python dependencies have not been installed. Running the pip install command from within the "
    "activated virtual environment will resolve this. If the application fails to start because port "
    "5000 is already in use, it means another program is using that port. You can either stop the "
    "other program or set a different port number using the PORT environment variable.",
    body,
))
elements.append(Paragraph(
    "If scans return errors, it is usually because OpenVAS is not installed or the GVM socket is not "
    "available. This is expected behavior and the application automatically falls back to demonstration "
    "mode, which provides realistic scan results without requiring OpenVAS. If email alerts are not "
    "being sent, verify that the ALERT_ENABLED variable is set to true and that the SMTP server "
    "settings are correct. Many email providers require specific security settings and authentication.",
    body,
))
elements.append(Paragraph(
    "If the PDF export feature is not working, it may indicate a problem with the ReportLab library. "
    "Reinstalling the package usually resolves this. If the dashboard appears blank or shows no data, "
    "it means no scans have been performed yet. Simply trigger a scan using the manual scan form or "
    "the API endpoint. If database locking errors occur, they are typically temporary and retrying "
    "the operation resolves them because the database uses Write-Ahead Logging mode for better "
    "concurrency handling. If charts are not rendering on the dashboard, it is because there is no "
    "scan data available. Running a scan will populate the database and the charts will appear "
    "automatically.",
    body,
))

doc.build(elements)
print(f"[+] PDF generated: {OUTPUT}")
