import io
import csv
import os
import re
import logging
import functools
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file, Response, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from database import (
    init_db, get_targets, get_scans, get_scan,
    get_vulnerabilities, get_vulnerability_count, get_severity_counts,
    get_scan_stats, get_alert_logs, get_targets_with_stats,
    get_latest_scans_per_target,
    add_target, create_user, get_user_by_username, get_user_by_email, get_user,
)
from scanner import run_scan, _check_openvas_available
from alerts import send_alerts_for_scan, send_report_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "vuln-scanner-secret-key-change-me")


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not email or not password:
            return render_template("register.html", error="All fields are required")
        if password != confirm:
            return render_template("register.html", error="Passwords do not match")
        if get_user_by_username(username):
            return render_template("register.html", error="Username already taken")
        if get_user_by_email(email):
            return render_template("register.html", error="Email already registered")

        pw_hash = generate_password_hash(password)
        user_id = create_user(username, email, pw_hash)
        if user_id is None:
            return render_template("register.html", error="Registration failed")

        session["logged_in"] = True
        session["user_id"] = user_id
        session["username"] = username
        session["email"] = email
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.before_request
def _init():
    init_db()


def _get_scanners_status():
    openvas = _check_openvas_available()
    return {"openvas": openvas}


@app.route("/")
@login_required
def dashboard():
    uid = session.get("user_id")
    alerts = get_alert_logs(limit=10, user_id=uid)
    targets = get_targets(user_id=uid)
    targets_stats = get_targets_with_stats(user_id=uid)
    scanners = _get_scanners_status()

    scans_with_vulns = []
    latest_scans = get_latest_scans_per_target(user_id=uid)
    for s in latest_scans:
        s_vulns = get_vulnerabilities(scan_id=s["id"], user_id=uid)
        scans_with_vulns.append({
            "scan": s,
            "vulns": s_vulns,
        })

    return render_template(
        "dashboard.html",
        scans=latest_scans,
        scans_with_vulns=scans_with_vulns,
        alerts=alerts,
        targets=targets,
        targets_stats=targets_stats,
        scanners=scanners,
    )


@app.route("/api/openvas-status")
@login_required
def api_openvas_status():
    return jsonify(_get_scanners_status())


@app.route("/api/scan-status/<int:scan_id>")
@login_required
def api_scan_status(scan_id):
    from database import get_connection
    conn = get_connection()
    row = conn.execute(
        "SELECT id, status, scan_type, total_critical, total_high, total_medium, total_low FROM scans WHERE id=?",
        (scan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/scan-history")
@login_required
def scan_history():
    scans = get_scans(limit=100, user_id=session.get("user_id"))
    return render_template("scan_history.html", scans=scans)


@app.route("/cve-detail")
@login_required
def cve_detail():
    scan_id = request.args.get("scan_id", type=int)
    severity = request.args.get("severity")
    uid = session.get("user_id")
    if not scan_id:
        return redirect(url_for("scan_history"))
    vulns = get_vulnerabilities(scan_id=scan_id, severity=severity, user_id=uid)
    scan = get_scan(scan_id, user_id=uid)
    return render_template("cve_detail.html", vulns=vulns, scan=scan)


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "").strip()
    name = data.get("name", "Manual Scan")

    if not host:
        return jsonify({"status": "error", "message": "Host is required"}), 400

    if not re.match(r'^https?://', host):
        host = "http://" + host

    scan_id = run_scan(host, name, user_id=session.get("user_id"))
    if scan_id:
        send_alerts_for_scan(scan_id)
        return jsonify({"status": "ok", "scan_id": scan_id})
    return jsonify({"status": "error", "message": "Scan failed"}), 500


@app.route("/api/stats")
@login_required
def api_stats():
    uid = session.get("user_id")
    target_id = request.args.get("target_id", type=int)
    counts = get_severity_counts(user_id=uid, target_id=target_id)
    scans = get_scans(limit=20, user_id=uid)
    stats = get_scan_stats(user_id=uid, target_id=target_id)
    data = {
        "counts": counts,
        "stats": stats,
        "scans": [
            {
                "id": s["id"],
                "target": s["target_name"],
                "host": s["target_host"],
                "date": s["scan_date"],
                "status": s["status"],
                "scan_type": s.get("scan_type", "nmap"),
                "critical": s["total_critical"],
                "high": s["total_high"],
                "medium": s["total_medium"],
                "low": s["total_low"],
            }
            for s in scans
        ],
    }
    return jsonify(data)


@app.route("/export/pdf")
@login_required
def export_pdf():
    scan_id = request.args.get("scan_id", type=int)
    uid = session.get("user_id")
    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=30, rightMargin=30)
    styles = getSampleStyleSheet()
    styles["Title"].fontSize = 20
    styles["Title"].spaceAfter = 6
    elements = []

    elements.append(Paragraph("Vulnerability Scan Report", styles["Title"]))
    elements.append(Paragraph(f"<i>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>", styles["Normal"]))
    elements.append(Spacer(1, 12))

    scan = get_scan(scan_id, user_id=uid)
    if scan:
        meta = [
            ["Target", f"{scan['target_name']} ({scan['target_host']})"],
            ["Scan Date", scan["scan_date"]],
            ["Status", scan["status"]],
            ["Scanner", scan.get("scan_type", "nmap")],
        ]
        mt = Table(meta, colWidths=[100, 350])
        mt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(mt)
        elements.append(Spacer(1, 12))
        vulns = get_vulnerabilities(scan_id=scan_id, user_id=uid)
    else:
        vulns = []

    if not vulns:
        elements.append(Paragraph("No vulnerabilities found. The target appears secure.", styles["Normal"]))
        doc.build(elements)
        buf.seek(0)
        filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

    critical = sum(1 for v in vulns if v["severity"] == "Critical")
    high = sum(1 for v in vulns if v["severity"] == "High")
    medium = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    elements.append(Paragraph("Severity Summary", styles["Heading2"]))
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(critical)],
        ["High", str(high)],
        ["Medium", str(medium)],
        ["Low", str(low)],
        ["Total", str(len(vulns))],
    ]
    st = Table(summary_data, colWidths=[120, 80])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    elements.append(st)
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("Vulnerability Details", styles["Heading2"]))
    data = [["#", "CVE ID", "Name", "Severity", "CVSS", "Status"]]
    for i, v in enumerate(vulns, 1):
        data.append([str(i), v["cve_id"], v["name"][:55], v["severity"], str(v["cvss_score"]), v["status"]])

    t = Table(data, colWidths=[25, 75, 180, 55, 35, 40])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (3, 0), (4, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/export/csv")
@login_required
def export_csv():
    scan_id = request.args.get("scan_id", type=int)
    uid = session.get("user_id")
    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400
    vulns = get_vulnerabilities(scan_id=scan_id, user_id=uid)
    scan = get_scan(scan_id, user_id=uid)

    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["VULNERABILITY SCAN REPORT"])
    writer.writerow(["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    if scan:
        writer.writerow(["Target:", f"{scan.get('target_name','')} ({scan.get('target_host','')})"])
        writer.writerow(["Scan Date:", scan.get("scan_date", "")])
        writer.writerow(["Status:", scan.get("status", "")])
        writer.writerow(["Scanner:", scan.get("scan_type", "nmap")])
    writer.writerow(["Total Findings:", len(vulns)])
    writer.writerow([])

    critical = sum(1 for v in vulns if v["severity"] == "Critical")
    high = sum(1 for v in vulns if v["severity"] == "High")
    medium = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    writer.writerow(["SEVERITY SUMMARY"])
    writer.writerow(["Severity", "Count"])
    writer.writerow(["Critical", critical])
    writer.writerow(["High", high])
    writer.writerow(["Medium", medium])
    writer.writerow(["Low", low])
    writer.writerow([])

    writer.writerow(["VULNERABILITY DETAILS"])
    writer.writerow(["#", "CVE ID", "Name", "Severity", "CVSS Score", "Description", "Solution", "Status", "NVT OID"])
    for i, v in enumerate(vulns, 1):
        writer.writerow([
            i,
            v["cve_id"],
            v["name"],
            v["severity"],
            v["cvss_score"],
            v["description"].replace("\n", " ").strip(),
            v["solution"].replace("\n", " ").strip(),
            v["status"],
            v.get("nvt_oid", ""),
        ])

    buf.seek(0)
    filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/send-report", methods=["POST"])
@login_required
def send_report():
    scan_id = request.form.get("scan_id", type=int)
    report_type = request.form.get("type", "csv")
    email = session.get("email")
    uid = session.get("user_id")

    if not email:
        return jsonify({"status": "error", "message": "No email on your account"}), 400
    if not scan_id:
        return jsonify({"status": "error", "message": "scan_id is required"}), 400

    if report_type == "pdf":
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=30, rightMargin=30)
        styles = getSampleStyleSheet()
        styles["Title"].fontSize = 20
        styles["Title"].spaceAfter = 6
        elements = []
        elements.append(Paragraph("Vulnerability Scan Report", styles["Title"]))
        elements.append(Paragraph(f"<i>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>", styles["Normal"]))
        elements.append(Spacer(1, 12))
        scan = get_scan(scan_id, user_id=uid)
        if scan:
            meta = [
                ["Target", f"{scan['target_name']} ({scan['target_host']})"],
                ["Scan Date", scan["scan_date"]],
                ["Status", scan["status"]],
            ]
            mt = Table(meta, colWidths=[100, 350])
            mt.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(mt)
            elements.append(Spacer(1, 12))
            vulns = get_vulnerabilities(scan_id=scan_id, user_id=uid)
        else:
            vulns = []
        if vulns:
            critical = sum(1 for v in vulns if v["severity"] == "Critical")
            high = sum(1 for v in vulns if v["severity"] == "High")
            medium = sum(1 for v in vulns if v["severity"] == "Medium")
            low = sum(1 for v in vulns if v["severity"] == "Low")
            elements.append(Paragraph("Severity Summary", styles["Heading2"]))
            summary_data = [
                ["Severity", "Count"],
                ["Critical", str(critical)],
                ["High", str(high)],
                ["Medium", str(medium)],
                ["Low", str(low)],
                ["Total", str(len(vulns))],
            ]
            st = Table(summary_data, colWidths=[120, 80])
            st.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            elements.append(st)
            elements.append(Spacer(1, 16))
            elements.append(Paragraph("Vulnerability Details", styles["Heading2"]))
            data = [["#", "CVE ID", "Name", "Severity", "CVSS", "Status"]]
            for i, v in enumerate(vulns, 1):
                data.append([str(i), v["cve_id"], v["name"][:55], v["severity"], str(v["cvss_score"]), v["status"]])
            t = Table(data, colWidths=[25, 75, 180, 55, 35, 40])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("ALIGN", (3, 0), (4, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            elements.append(t)
        else:
            elements.append(Paragraph("No vulnerabilities found. The target appears secure.", styles["Normal"]))
        doc.build(elements)
        buf.seek(0)
        attachment = buf.read()
        filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        send_report_email(email, f"Vulnerability Scan Report - Scan #{scan_id}", attachment, filename)
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        vulns = get_vulnerabilities(scan_id=scan_id, user_id=uid)
        scan = get_scan(scan_id, user_id=uid)
        writer.writerow(["VULNERABILITY SCAN REPORT"])
        writer.writerow(["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        if scan:
            writer.writerow(["Target:", f"{scan.get('target_name','')} ({scan.get('target_host','')})"])
            writer.writerow(["Scan Date:", scan.get("scan_date", "")])
            writer.writerow(["Status:", scan.get("status", "")])
        writer.writerow(["Total Findings:", len(vulns)])
        writer.writerow([])
        critical = sum(1 for v in vulns if v["severity"] == "Critical")
        high = sum(1 for v in vulns if v["severity"] == "High")
        medium = sum(1 for v in vulns if v["severity"] == "Medium")
        low = sum(1 for v in vulns if v["severity"] == "Low")
        writer.writerow(["SEVERITY SUMMARY"])
        writer.writerow(["Severity", "Count"])
        writer.writerow(["Critical", critical])
        writer.writerow(["High", high])
        writer.writerow(["Medium", medium])
        writer.writerow(["Low", low])
        writer.writerow([])
        writer.writerow(["VULNERABILITY DETAILS"])
        writer.writerow(["#", "CVE ID", "Name", "Severity", "CVSS Score", "Description", "Solution", "Status"])
        for i, v in enumerate(vulns, 1):
            writer.writerow([i, v["cve_id"], v["name"], v["severity"], v["cvss_score"],
                             v["description"].replace("\n", " ").strip(),
                             v["solution"].replace("\n", " ").strip(), v["status"]])
        buf.seek(0)
        filename = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d')}.csv"
        send_report_email(email, f"Vulnerability Scan Report - Scan #{scan_id}", buf.getvalue(), filename)

    return jsonify({"status": "ok", "message": f"Report sent to {email}"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
