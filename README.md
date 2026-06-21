# Advanced Web Vulnerability Scanner

A full-stack vulnerability management system using **OpenVAS / Greenbone Community Edition** as the scanning engine, **Python Flask** as the web dashboard, and **SQLite** as the local database.

## Features

- OpenVAS/GVM native scan automation via `python-gvm`
- Flask dashboard with KPI cards, bar/pie charts, CVE table, scan history
- PDF and CSV report export
- SMTP email alerts for Critical/High vulnerabilities
- Automated scan scheduling (daily/weekly)
- GitHub Actions CI/CD pipeline

## Quick Start

### 1. Install OpenVAS / Greenbone

```bash
sudo add-apt-repository ppa:mrazavi/gvm
sudo apt update
sudo apt install -y gvm gvm-tools
sudo gvm-setup
sudo gvm-fix-permissions
```

Verify: `sudo gvm-check-setup`

### 2. Set up the dashboard

```bash
git clone <your-repo>
cd vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment (optional)

```bash
export SMTP_SERVER=sandbox.smtp.mailtrap.io
export SMTP_PORT=587
export SMTP_USER=your_user
export SMTP_PASS=your_pass
export ALERT_EMAIL=admin@example.com
export ALERT_ENABLED=true
```

### 4. Run

```bash
python app.py
```

Open http://localhost:5000

### 5. Run a scan manually

```bash
python scanner.py
```

## Targets

| Target | URL | Authorization |
|--------|-----|--------------|
| Acunetix TestPHP | http://testphp.vulnweb.com | Publicly authorized |
| Nmap ScanMe | http://scanme.nmap.org | Authorized by nmap.org |

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Dashboard |
| GET | `/scan-history` | Scan history table |
| GET | `/cve-detail` | CVE breakdown |
| POST | `/api/scan` | Trigger a scan |
| GET | `/api/stats` | JSON stats for charts |
| GET | `/export/pdf` | Download PDF report |
| GET | `/export/csv` | Download CSV report |

## CI/CD

The `.github/workflows/scan.yml` pipeline runs scans:
- On every push to `main`
- Weekly (Monday 06:00 UTC)
- Manually via `workflow_dispatch`
