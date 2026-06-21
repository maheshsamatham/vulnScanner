import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from database import get_scan, get_vulnerabilities, log_alert

log = logging.getLogger(__name__)

SMTP_SERVER = os.getenv("SMTP_SERVER", "sandbox.smtp.mailtrap.io")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "scanner@vulnscanner.local")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "admin@example.com")
ALERT_ENABLED = os.getenv("ALERT_ENABLED", "false").lower() == "true"


def send_alert(scan_id, vulnerability_id, cve_id, vuln_name, severity, cvss, target_name, scanner_type="nmap"):
    if not ALERT_ENABLED:
        log.info("Alerts disabled. Would send alert for %s (%s)", cve_id, severity)
        return False

    subject = f"[VulnScanner] {severity}: {cve_id} on {target_name}"
    body = f"""
Vulnerability Detected
======================
Target:     {target_name}
CVE ID:     {cve_id}
Name:       {vuln_name}
Severity:   {severity}
CVSS Score: {cvss}
Scanner:    {scanner_type}
Scan ID:    {scan_id}

Please investigate immediately.
"""

    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = ALERT_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, ALERT_EMAIL, msg.as_string())
        server.quit()
        log.info("Alert sent: %s", subject)
        log_alert(scan_id, vulnerability_id, ALERT_EMAIL, subject)
        return True
    except Exception as e:
        log.error("Failed to send alert: %s", e)
        return False


def send_alerts_for_scan(scan_id):
    vulns = get_vulnerabilities(scan_id=scan_id)
    scan = get_scan(scan_id)
    target_name = scan.get("target_name", "Unknown") if scan else "Unknown"
    scanner_type = scan.get("scan_type", "nmap") if scan else "nmap"

    sent = 0
    for v in vulns:
        if v["severity"] in ("Critical", "High"):
            ok = send_alert(
                scan_id, v["id"], v["cve_id"], v["name"],
                v["severity"], v["cvss_score"], target_name, scanner_type,
            )
            if ok:
                sent += 1
    return sent


def send_report_email(to_email, subject, attachment_data, filename):
    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject

    body = MIMEText("Please find the attached vulnerability report.", "plain")
    msg.attach(body)

    part = MIMEBase("application", "octet-stream")
    part.set_payload(attachment_data if isinstance(attachment_data, bytes) else attachment_data.encode())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename={filename}")
    msg.attach(part)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, to_email, msg.as_string())
        server.quit()
        log.info("Report email sent to %s: %s", to_email, subject)
        return True
    except Exception as e:
        log.error("Failed to send report email: %s", e)
        return False
