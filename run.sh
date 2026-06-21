#!/usr/bin/env bash
set -e

VENV="$(dirname "$0")/venv"
APP="$(dirname "$0")/app.py"

if [ ! -d "$VENV" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -r "$(dirname "$0")/requirements.txt" --quiet
fi

case "${1:-app}" in
    scan)
        echo "[+] Running vulnerability scan..."
        "$VENV/bin/python" "$(dirname "$0")/scanner.py" "$2"
        ;;
    app)
        echo "[+] Starting VulnScanner dashboard on http://localhost:5000 ..."
        echo "[+] Scanner engine: $(which gvmd 2>/dev/null && echo 'OpenVAS' || echo 'Nmap')"
        "$VENV/bin/python" "$APP"
        ;;
    scheduler)
        echo "[+] Starting scheduler (daily scans)..."
        "$VENV/bin/python" -c "from scheduler import start_scheduler_thread; start_scheduler_thread(interval_days=1); import time; time.sleep(99999)"
        ;;
    *)
        echo "Usage: $0 {app|scan|scheduler} [target]"
        exit 1
        ;;
esac
