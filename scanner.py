import os
import re
import time
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

from database import (
    add_target, create_scan, update_scan_status,
    add_vulnerability, get_targets, get_connection,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

OPENVAS_HOST = os.getenv("OPENVAS_HOST", "127.0.0.1")
OPENVAS_PORT = int(os.getenv("OPENVAS_PORT", "9392"))
OPENVAS_USER = os.getenv("OPENVAS_USER", "admin")
OPENVAS_PASS = os.getenv("OPENVAS_PASS", "admin")
OPENVAS_SOCKET = os.getenv("OPENVAS_SOCKET", "/run/gvmd.sock")


def _cvss_to_severity(cvss):
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _clean_host(raw):
    host = raw.strip()
    host = re.sub(r'^https?://', '', host)
    host = re.sub(r'/.*$', '', host)
    host = host.split(':')[0]
    return host


def _check_openvas_available():
    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols import Gmp
        if os.path.exists(OPENVAS_SOCKET):
            connection = UnixSocketConnection(path=OPENVAS_SOCKET)
            with Gmp(connection=connection) as gmp:
                gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
                return True
    except Exception as e:
        log.debug("OpenVAS Unix socket unavailable: %s", e)
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols import Gmp
        connection = TLSConnection(hostname=OPENVAS_HOST, port=OPENVAS_PORT)
        with Gmp(connection=connection) as gmp:
            gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
            return True
    except Exception as e:
        log.debug("OpenVAS TCP unavailable: %s", e)
    return False


def _get_openvas_connection():
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols import Gmp
    if os.path.exists(OPENVAS_SOCKET):
        connection = UnixSocketConnection(path=OPENVAS_SOCKET)
    else:
        connection = TLSConnection(hostname=OPENVAS_HOST, port=OPENVAS_PORT)
    gmp = Gmp(connection=connection)
    gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
    return gmp


def _get_or_create_openvas_target(gmp, host, name):
    resp = gmp.get_targets(filter_string="rows=-1")
    targets_xml = resp.findall("target")
    for t in targets_xml:
        t_hosts = t.find("hosts")
        if t_hosts is not None and host in (t_hosts.text or ""):
            return t.get("id")
    target_id = gmp.create_target(
        name=f"{name} - {datetime.now().strftime('%Y%m%d%H%M%S')}",
        hosts=[host],
    )
    log.info("Created OpenVAS target: %s", target_id)
    return target_id


def _get_scan_config_id(gmp, config_name="Full and fast"):
    resp = gmp.get_scan_configs(filter_string="rows=-1")
    for cfg in resp.findall("config"):
        cname = cfg.find("name")
        if cname is not None and config_name in cname.text:
            return cfg.get("id")
    for cfg in resp.findall("config"):
        cname = cfg.find("name")
        if cname is not None:
            return cfg.get("id")
    return None


def _openvas_scan(target_host, target_name, user_id=None):
    from gvm.protocols import Gmp
    from gvm.transforms import EtreeTransform
    clean = _clean_host(target_host)
    log.info("Starting OpenVAS scan of %s (%s)", target_name, clean)
    gmp = _get_openvas_connection()
    try:
        target_id = _get_or_create_openvas_target(gmp, clean, target_name)
        config_id = _get_scan_config_id(gmp)
        if not config_id:
            log.error("No scan config found in OpenVAS")
            return None
        task_id = gmp.create_task(
            name=f"Scan {target_name} - {datetime.now().strftime('%Y%m%d%H%M%S')}",
            config_id=config_id,
            target_id=target_id,
        )
        log.info("Created OpenVAS task: %s", task_id)
        db_target_id = add_target(target_name, target_host)
        scan_id = create_scan(db_target_id, user_id=user_id, scan_type="openvas")
        conn = get_connection()
        conn.execute("UPDATE scans SET openvas_task_id=? WHERE id=?", (str(task_id), scan_id))
        conn.commit()
        conn.close()
        report_id = gmp.start_task(task_id)
        log.info("Started OpenVAS task, report: %s", report_id)
        conn = get_connection()
        conn.execute("UPDATE scans SET openvas_report_id=?, status=? WHERE id=?",
                     (str(report_id), "Running", scan_id))
        conn.commit()
        conn.close()
        while True:
            time.sleep(5)
            resp = gmp.get_task(task_id)
            task_status_el = resp.find("task/status")
            status = task_status_el.text if task_status_el is not None else "Unknown"
            log.info("OpenVAS scan status: %s", status)
            if status in ("Done", "Stopped", "Failed", "Error"):
                break
        if status == "Done":
            _parse_openvas_results(gmp, report_id, scan_id)
        else:
            update_scan_status(scan_id, status, 0, 0, 0, 0)
        return scan_id
    except Exception as e:
        log.error("OpenVAS scan error: %s", e)
        return None
    finally:
        gmp.disconnect()


def _parse_openvas_results(gmp, report_id, scan_id):
    resp = gmp.get_report(report_id=report_id, details=True)
    results = resp.findall(".//result")
    critical = high = medium = low = 0
    if not results:
        log.info("No OpenVAS results found for report %s", report_id)
        update_scan_status(scan_id, "Done", 0, 0, 0, 0)
        return
    for r in results:
        try:
            name_el = r.find("name")
            name = name_el.text if name_el is not None else "Unknown"
            threat_el = r.find("threat")
            threat = threat_el.text if threat_el is not None else "Log"
            severity_el = r.find("severity")
            cvss = 0.0
            if severity_el is not None:
                try:
                    cvss = float(severity_el.text or "0")
                except ValueError:
                    cvss = 0.0
            nvt = r.find("nvt")
            oid = ""
            cve_id = ""
            description = ""
            solution = ""
            if nvt is not None:
                oid = nvt.get("oid", "")
                nvt_name_el = nvt.find("name")
                if nvt_name_el is not None:
                    name = nvt_name_el.text or name
                tags_el = nvt.find("tags")
                if tags_el is not None:
                    desc_match = re.search(r'summary[=:]((?:(?!\||$).)*)', tags_el.text or "", re.DOTALL)
                    if desc_match:
                        description = desc_match.group(1).strip()
                cve_el = nvt.findall("cve")
                if cve_el:
                    all_cves = [c.text for c in cve_el if c.text and c.text != "NOCVE"]
                    cve_id = all_cves[0] if all_cves else ""
                refs = nvt.findall("ref")
                if refs:
                    for ref in refs:
                        ref_type = ref.get("type", "")
                        ref_id = ref.get("id", "")
                        if ref_type == "cve" and not cve_id:
                            cve_id = ref_id
                solution_el = nvt.find("solution")
                if solution_el is not None:
                    solution = solution_el.text or ""
            severity = _cvss_to_severity(cvss) if cvss > 0 else threat
            if severity == "Critical":
                critical += 1
            elif severity == "High":
                high += 1
            elif severity == "Medium":
                medium += 1
            elif severity == "Low":
                low += 1
            if severity in ("Critical", "High", "Medium", "Low"):
                add_vulnerability(
                    scan_id=scan_id,
                    cve_id=cve_id or f"NVT-{oid[:8]}" if oid else "N/A",
                    name=name,
                    severity=severity,
                    cvss_score=cvss,
                    description=description or f"OpenVAS NVT OID: {oid}\nThreat: {threat}",
                    solution=solution or "No solution provided by vendor.",
                    nvt_oid=oid,
                )
        except Exception as e:
            log.error("Error parsing OpenVAS result: %s", e)
            continue
    update_scan_status(scan_id, "Done", critical, high, medium, low)
    log.info("OpenVAS scan complete: %dC / %dH / %dM / %dL", critical, high, medium, low)


def _parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    results = []
    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for port_el in ports.findall("port"):
            port_id = port_el.get("portid", "")
            protocol = port_el.get("protocol", "tcp")
            service = port_el.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            service_product = service.get("product", "") if service is not None else ""
            service_version = service.get("version", "") if service is not None else ""
            service_str = f"{service_name} {port_id}/{protocol}"
            if service_product:
                service_str += f" ({service_product} {service_version})"
            for script_el in port_el.findall("script"):
                if script_el.get("id") != "vulners":
                    continue
                for cpe_table in script_el.findall("table"):
                    for vuln_table in cpe_table.findall("table"):
                        cve_id = ""
                        cvss = 0.0
                        for elem in vuln_table.findall("elem"):
                            key = elem.get("key", "")
                            if key == "id":
                                cve_id = elem.text or ""
                            elif key == "cvss":
                                try:
                                    cvss = float(elem.text or "0")
                                except ValueError:
                                    cvss = 0.0
                        if cve_id.startswith("CVE-"):
                            results.append({
                                "cve_id": cve_id,
                                "name": f"{service_str} - {cve_id}",
                                "cvss": cvss,
                                "description": f"CVE: {cve_id} (CVSS: {cvss})\nAffected: {service_str}",
                                "solution": "Update to the latest version.",
                            })
    return results


def _nmap_scan(target_host, target_name, user_id=None):
    clean = _clean_host(target_host)
    log.info("Starting nmap vulnerability scan of %s (%s)", target_name, clean)
    cmd = [
        "nmap", "-sV", "--top-ports", "100",
        "--script", "vulners",
        "-T4", "-oX", "-",
        "--unprivileged",
        clean,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        log.error("nmap not found")
        return None
    except subprocess.TimeoutExpired:
        log.error("nmap scan timed out")
        return None
    if proc.returncode != 0:
        log.error("nmap error: %s", proc.stderr.strip())
        return None
    findings = _parse_nmap_xml(proc.stdout)
    db_target_id = add_target(target_name, target_host)
    scan_id = create_scan(db_target_id, user_id=user_id, scan_type="nmap")
    if not findings:
        log.info("No vulnerabilities found for %s", target_host)
        update_scan_status(scan_id, "Done", 0, 0, 0, 0)
        return scan_id
    critical = high = medium = low = 0
    for f in findings:
        severity = _cvss_to_severity(f["cvss"])
        if severity == "Critical":
            critical += 1
        elif severity == "High":
            high += 1
        elif severity == "Medium":
            medium += 1
        else:
            low += 1
        add_vulnerability(
            scan_id=scan_id,
            cve_id=f["cve_id"],
            name=f["name"],
            severity=severity,
            cvss_score=f["cvss"],
            description=f["description"],
            solution=f["solution"],
        )
    update_scan_status(scan_id, "Done", critical, high, medium, low)
    log.info("Nmap scan complete for %s: %dC / %dH / %dM / %dL",
             target_host, critical, high, medium, low)
    return scan_id


def run_scan(target_host, target_name, user_id=None):
    if _check_openvas_available():
        log.info("OpenVAS detected — using OpenVAS scanner")
        return _openvas_scan(target_host, target_name, user_id=user_id)
    log.info("OpenVAS not available — falling back to nmap")
    return _nmap_scan(target_host, target_name, user_id=user_id)


def run_scans_for_all_targets(targets=None):
    if targets is None:
        targets = get_targets()
    results = []
    for t in targets:
        host = t["host"]
        name = t["name"]
        sid = run_scan(host, name)
        results.append((name, host, sid))
    return results


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_scan(host, "CLI-scan")
