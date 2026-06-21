import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulndb.sqlite')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            user_id INTEGER,
            scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            scan_type TEXT DEFAULT 'nmap',
            openvas_task_id TEXT DEFAULT '',
            openvas_report_id TEXT DEFAULT '',
            total_critical INTEGER DEFAULT 0,
            total_high INTEGER DEFAULT 0,
            total_medium INTEGER DEFAULT 0,
            total_low INTEGER DEFAULT 0,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            cve_id TEXT DEFAULT '',
            name TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            cvss_score REAL DEFAULT 0.0,
            description TEXT DEFAULT '',
            solution TEXT DEFAULT '',
            nvt_oid TEXT DEFAULT '',
            qod TEXT DEFAULT '',
            status TEXT DEFAULT 'Open',
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            vulnerability_id INTEGER,
            recipient TEXT,
            subject TEXT,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)
    conn.commit()
    conn.close()


def create_user(username, email, password_hash):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                     (username, email, password_hash))
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_target(name, host):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO targets (name, host) VALUES (?, ?)", (name, host))
    conn.commit()
    target_id = cur.lastrowid
    conn.close()
    return target_id


def get_targets(user_id=None):
    conn = get_connection()
    if user_id:
        rows = conn.execute("""
            SELECT DISTINCT t.* FROM targets t
            JOIN scans s ON s.target_id = t.id
            WHERE s.user_id = ?
            ORDER BY t.created_at DESC
        """, (user_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_latest_scans_per_target(user_id=None):
    conn = get_connection()
    if user_id:
        rows = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id IN (
                SELECT COALESCE(
                    (SELECT s2.id FROM scans s2
                     WHERE s2.target_id = s3.target_id AND s2.user_id = ? AND s2.status = 'Done'
                     ORDER BY s2.id DESC LIMIT 1),
                    MAX(s3.id)
                ) FROM scans s3
                WHERE s3.user_id = ?
                GROUP BY s3.target_id
            )
            AND s.user_id = ?
            ORDER BY s.scan_date DESC
        """, (user_id, user_id, user_id)).fetchall()
    else:
        rows = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id IN (
                SELECT COALESCE(
                    (SELECT s2.id FROM scans s2
                     WHERE s2.target_id = s3.target_id AND s2.status = 'Done'
                     ORDER BY s2.id DESC LIMIT 1),
                    MAX(s3.id)
                ) FROM scans s3
                GROUP BY s3.target_id
            )
            ORDER BY s.scan_date DESC
        """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_target(target_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_targets_with_stats(user_id=None):
    conn = get_connection()
    if user_id:
        rows = conn.execute("""
            SELECT t.*,
                COUNT(s.id) as total_scans,
                COALESCE(SUM(CASE WHEN s.status='Done' THEN 1 ELSE 0 END), 0) as completed,
                COALESCE(SUM(s.total_critical), 0) as critical,
                COALESCE(SUM(s.total_high), 0) as high,
                COALESCE(SUM(s.total_medium), 0) as medium,
                COALESCE(SUM(s.total_low), 0) as low,
                COALESCE(SUM(s.total_critical + s.total_high + s.total_medium + s.total_low), 0) as total_vulns
            FROM targets t
            LEFT JOIN scans s ON s.target_id = t.id AND s.user_id = ?
            GROUP BY t.id
            HAVING COUNT(s.id) > 0
            ORDER BY t.created_at DESC
        """, (user_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT t.*,
                COUNT(s.id) as total_scans,
                COALESCE(SUM(CASE WHEN s.status='Done' THEN 1 ELSE 0 END), 0) as completed,
                COALESCE(SUM(s.total_critical), 0) as critical,
                COALESCE(SUM(s.total_high), 0) as high,
                COALESCE(SUM(s.total_medium), 0) as medium,
                COALESCE(SUM(s.total_low), 0) as low,
                COALESCE(SUM(s.total_critical + s.total_high + s.total_medium + s.total_low), 0) as total_vulns
            FROM targets t
            LEFT JOIN scans s ON s.target_id = t.id
            GROUP BY t.id
            HAVING COUNT(s.id) > 0
            ORDER BY t.created_at DESC
        """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_scan(target_id, user_id=None, scan_type="nmap"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (target_id, user_id, scan_type) VALUES (?, ?, ?)",
                (target_id, user_id, scan_type))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def update_scan_status(scan_id, status, critical=0, high=0, medium=0, low=0):
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status=?, total_critical=?, total_high=?, total_medium=?, total_low=? WHERE id=?",
        (status, critical, high, medium, low, scan_id),
    )
    conn.commit()
    conn.close()


def get_scans(limit=50, user_id=None):
    conn = get_connection()
    if user_id:
        rows = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.user_id = ?
            ORDER BY s.scan_date DESC
            LIMIT ?
        """, (user_id, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            ORDER BY s.scan_date DESC
            LIMIT ?
        """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan(scan_id, user_id=None):
    conn = get_connection()
    if user_id:
        row = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id = ? AND s.user_id = ?
        """, (scan_id, user_id)).fetchone()
    else:
        row = conn.execute("""
            SELECT s.*, t.name AS target_name, t.host AS target_host
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id = ?
        """, (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_vulnerability(scan_id, cve_id, name, severity, cvss_score, description, solution, nvt_oid="", qod=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO vulnerabilities (scan_id, cve_id, name, severity, cvss_score, description, solution, nvt_oid, qod) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, cve_id, name, severity, cvss_score, description, solution, nvt_oid, qod),
    )
    conn.commit()
    conn.close()


def get_vulnerabilities(scan_id=None, severity=None, limit=None, user_id=None):
    conn = get_connection()
    query = "SELECT v.*, s.scan_date FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id"
    params = []
    conditions = []
    if user_id:
        conditions.append("s.user_id = ?")
        params.append(user_id)
    if scan_id:
        conditions.append("v.scan_id = ?")
        params.append(scan_id)
    if severity:
        conditions.append("v.severity = ?")
        params.append(severity)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY v.cvss_score DESC, v.id DESC"
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_vulnerability_count(scan_id=None, user_id=None):
    conn = get_connection()
    query = "SELECT COUNT(*) as cnt FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id"
    params = []
    conditions = []
    if user_id:
        conditions.append("s.user_id = ?")
        params.append(user_id)
    if scan_id:
        conditions.append("v.scan_id = ?")
        params.append(scan_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row["cnt"] if row else 0


def get_severity_counts(user_id=None, target_id=None):
    conn = get_connection()
    query = """
        SELECT
            COALESCE(SUM(total_critical), 0) AS critical,
            COALESCE(SUM(total_high), 0) AS high,
            COALESCE(SUM(total_medium), 0) AS medium,
            COALESCE(SUM(total_low), 0) AS low
        FROM scans
        WHERE 1=1
    """
    params = []
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if target_id:
        query += " AND target_id = ?"
        params.append(target_id)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return dict(row)


def get_scan_stats(user_id=None, target_id=None):
    conn = get_connection()
    query = """
        SELECT
            COUNT(*) as total_scans,
            COALESCE(SUM(CASE WHEN status='Done' THEN 1 ELSE 0 END), 0) as completed,
            COALESCE(SUM(total_critical + total_high + total_medium + total_low), 0) as total_vulns,
            COALESCE(SUM(CASE WHEN total_critical + total_high + total_medium + total_low = 0 AND status='Done' THEN 1 ELSE 0 END), 0) as secure_scans
        FROM scans
        WHERE 1=1
    """
    params = []
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if target_id:
        query += " AND target_id = ?"
        params.append(target_id)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return dict(row)


def log_alert(scan_id, vulnerability_id, recipient, subject):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alert_log (scan_id, vulnerability_id, recipient, subject) VALUES (?, ?, ?, ?)",
        (scan_id, vulnerability_id, recipient, subject),
    )
    conn.commit()
    conn.close()


def get_alert_logs(limit=20, user_id=None):
    conn = get_connection()
    if user_id:
        rows = conn.execute("""
            SELECT a.*, v.cve_id, v.name AS vuln_name
            FROM alert_log a
            LEFT JOIN vulnerabilities v ON a.vulnerability_id = v.id
            JOIN scans s ON a.scan_id = s.id
            WHERE s.user_id = ?
            ORDER BY a.sent_at DESC
            LIMIT ?
        """, (user_id, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT a.*, v.cve_id, v.name AS vuln_name
            FROM alert_log a
            LEFT JOIN vulnerabilities v ON a.vulnerability_id = v.id
            ORDER BY a.sent_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
