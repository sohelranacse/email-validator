# ============================================================
# Auto-install dependencies on first run / new PC
# This runs BEFORE any third-party imports so it can fix itself.
# ============================================================
import sys
import subprocess
import importlib.util
import os

def _ensure_dependencies():
    """
    If key packages are missing, auto-install from requirements.txt.
    Then re-exec the script so the newly installed packages become importable.
    This makes the app "just work" on a brand new Windows PC.
    """
    # Check the packages we actually import (import names, not pip names)
    packages_to_check = [
        ("flask", "flask"),
        ("dns", "dnspython"),
        ("email_validator", "email-validator"),
    ]

    missing = []
    for import_name, pip_name in packages_to_check:
        if importlib.util.find_spec(import_name) is None:
            missing.append(pip_name)

    if not missing:
        return  # All good, continue normally

    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    print("📦 Missing dependencies detected on this machine:")
    print("   " + ", ".join(missing))
    print("   Installing from requirements.txt (this only happens once)...\n")

    try:
        # Use the exact same Python interpreter that launched this script
        cmd = [sys.executable, "-m", "pip", "install", "-r", req_file]
        subprocess.check_call(cmd)
        print("\n✅ Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print("\n❌ Automatic installation failed.")
        print(f"   Error code: {e.returncode}")
        print("\nPlease run this command manually in your terminal, then start the app again:")
        print(f'   "{sys.executable}" -m pip install -r requirements.txt')
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during auto-install: {e}")
        sys.exit(1)

    # Re-spawn the current process so the freshly installed packages are importable.
    # This is the most reliable cross-platform way.
    print("🔄 Restarting the application with the new packages...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)


_ensure_dependencies()
# From this point on it is safe to import third-party packages.

from flask import Flask, render_template_string, request, Response, send_from_directory
import json
import time
import threading
import random
import socket
import smtplib
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

# Global caches and locks for thread safety + speed
mx_cache = {}
mx_lock = threading.Lock()
catch_all_cache = {}
catch_all_lock = threading.Lock()
file_lock = threading.Lock()

class DomainRateLimiter:
    """Prevents hammering any single domain (reduces blocks/bans)."""
    def __init__(self, min_interval=0.28):
        self.min_interval = min_interval
        self.last_check = {}
        self.lock = threading.Lock()

    def wait_for(self, domain):
        sleep_time = 0.0
        with self.lock:
            now = time.time()
            last = self.last_check.get(domain, 0.0)
            elapsed = now - last
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
            self.last_check[domain] = now + sleep_time
        if sleep_time > 0:
            time.sleep(sleep_time)
        with self.lock:
            self.last_check[domain] = time.time()

rate_limiter = DomainRateLimiter(min_interval=0.28)

def get_mx_server(domain):
    """Get best MX server for domain (with A-record fallback). Thread-safe cache."""
    with mx_lock:
        if domain in mx_cache:
            return mx_cache[domain]

    mx_server = None
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_server = sorted(answers, key=lambda r: r.preference)[0].exchange.to_text().rstrip('.')
    except Exception:
        # Fallback: try A record (some domains deliver directly)
        try:
            dns.resolver.resolve(domain, 'A')
            mx_server = domain
        except Exception:
            mx_server = None

    with mx_lock:
        mx_cache[domain] = mx_server
    return mx_server


def is_catch_all_domain(mx_server, domain):
    """Probe with a clearly bogus address. If accepted too -> catch-all domain."""
    with catch_all_lock:
        if domain in catch_all_cache:
            return catch_all_cache[domain]

    bogus = f"no-such-user-{random.randint(10000000, 99999999)}@{domain}"
    is_catch = False
    try:
        server = smtplib.SMTP(timeout=8)
        server.connect(mx_server, 25)
        server.ehlo()
        server.mail('validator@check.local')
        code, _ = server.rcpt(bogus)
        server.quit()
        is_catch = (code == 250)
    except Exception:
        is_catch = False

    with catch_all_lock:
        catch_all_cache[domain] = is_catch
    return is_catch


def verify_email_delivery(email, detect_catch_all=True):
    """
    Best-effort REAL mailbox verification:
    1. Strict syntax (email-validator lib)
    2. MX / mail server lookup
    3. Direct SMTP RCPT TO handshake (the gold standard for "does this mailbox exist?")
    4. Catch-all probe when enabled (highly recommended for accuracy)
    """
    # 1. Syntax validation (far superior to regex)
    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return "invalid_syntax", "Bad email syntax"

    domain = email.rsplit('@', 1)[-1].lower().strip()
    if not domain:
        return "invalid_syntax", "Missing domain"

    # 2. MX lookup
    mx_server = get_mx_server(domain)
    if not mx_server:
        return "no_mx", "Domain has no mail servers (no MX/A records)"

    # 3. Rate limit + SMTP verification
    rate_limiter.wait_for(domain)

    try:
        server = smtplib.SMTP(timeout=12)
        server.connect(mx_server, 25)
        server.ehlo()
        # STARTTLS is optional; many public MXes work without. Uncomment if desired:
        # try:
        #     server.starttls()
        #     server.ehlo()
        # except Exception:
        #     pass

        server.mail('validator@check.local')
        code, message = server.rcpt(email)
        server.quit()

        msg_text = (message.decode(errors='ignore') if isinstance(message, (bytes, bytearray)) else str(message)).strip()[:90]

        if code == 250:
            if detect_catch_all:
                if is_catch_all_domain(mx_server, domain):
                    return "catch_all", "Catch-all domain (accepts mail to any address)"
            return "valid", "Mailbox exists and accepts mail (SMTP 250)"
        elif code in (550, 551, 553, 554):
            return "mailbox_invalid", f"Mailbox does not exist ({code})"
        elif code in (450, 451, 452):
            return "temp_error", f"Temporary rejection / rate limit ({code})"
        else:
            return "smtp_error", f"SMTP response {code}: {msg_text}"

    except smtplib.SMTPConnectError as e:
        return "connection_error", f"Connection refused/blocked ({str(e)[:65]})"
    except (socket.timeout, TimeoutError):
        return "timeout", "Timeout connecting or waiting for server"
    except smtplib.SMTPServerDisconnected:
        return "connection_error", "Server disconnected unexpectedly"
    except Exception as e:
        return "unknown", f"Unexpected error: {str(e)[:65]}"

# --- HTML UI Interface ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Best Real Email Validator • Parallel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { border: none; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-radius: 12px; }
        #logConsole { background-color: #111; color: #00ff66; font-family: 'Courier New', Courier, monospace; height: 340px; overflow-y: auto; padding: 14px; border-radius: 8px; font-size: 13.5px; line-height: 1.35; }
        .stat-badge { font-size: 0.9rem; padding: 6px 10px; }
        .log-valid { color: #2ecc71; }
        .log-catch { color: #f1c40f; }
        .log-invalid { color: #ff5e5e; }
        .log-unknown { color: #95a5a6; }
        .form-range {
            accent-color: #0f766e;
            height: 5px;
        }
        .workers-box {
            background: linear-gradient(145deg, #f8fafc, #f1f5f9);
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 10px 14px;
            margin-bottom: 2px;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="row justify-content-center">
            <div class="col-lg-11 col-xl-10">
                <div class="card p-4 mb-3">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <h3 class="mb-0 text-dark fw-bold">📧 Best Real Email Validator</h3>
                        <span class="badge bg-dark">Parallel • MX + SMTP RCPT + Catch-All</span>
                    </div>
                    <p class="text-muted small mb-3">True mailbox existence check using DNS MX + direct SMTP handshake (no email is sent). Catch-all detection for maximum accuracy.</p>

                    <!-- Controls -->
                    <div class="row g-3 align-items-end mb-3">
                        <!-- Workers -->
                        <div class="col-md-4">
                            <div class="workers-box">
                                <label class="form-label fw-semibold small mb-1">Parallel Workers <span class="text-secondary">(3–10)</span></label>
                                <div class="d-flex align-items-center gap-2">
                                    <input type="range" class="form-range flex-grow-1" id="workersRange" min="3" max="10" step="1" value="5">
                                    <input type="number" id="workersInput" class="form-control form-control-sm text-center" style="width: 62px" min="3" max="10" value="5">
                                </div>
                                <div class="form-text tiny text-secondary">More workers = faster but higher risk of temporary blocks</div>
                            </div>
                        </div>

                        <!-- Catch-all -->
                        <div class="col-md-3">
                            <div class="form-check form-switch mt-1">
                                <input class="form-check-input" type="checkbox" id="catchAllCheck" checked>
                                <label class="form-check-label fw-semibold small" for="catchAllCheck">
                                    Detect catch-all domains<br>
                                    <span class="text-secondary" style="font-size:12px">(more accurate, uses extra probes)</span>
                                </label>
                            </div>
                        </div>

                        <!-- Buttons -->
                        <div class="col-md-5">
                            <div class="d-flex gap-2">
                                <button id="loadDefaultBtn" class="btn btn-outline-secondary px-3" type="button">📂 Load email_list.txt</button>
                                <button id="startBtn" class="btn btn-success px-4 fw-bold flex-grow-1" style="border-radius: 8px;">▶ Start Validation</button>
                            </div>
                        </div>
                    </div>

                    <div class="mb-2">
                        <textarea id="emailsInput" class="form-control" rows="7" placeholder="Paste emails here (one per line) or load email_list.txt&#10;Supports email:password lines too — only email part is used." style="border-radius: 8px; font-family: ui-monospace, monospace; font-size: 14px;"></textarea>
                    </div>

                    <!-- Progress + Status -->
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <div>
                            <span id="statusText" class="fw-semibold text-secondary">Ready — load list or paste emails</span>
                        </div>
                        <div id="progressText" class="fw-bold small text-primary" style="min-width: 90px; text-align: right;"></div>
                    </div>

                    <div class="progress mb-2" style="height: 22px; display: none; border-radius: 999px; overflow: hidden;" id="progressContainer">
                        <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated bg-primary" role="progressbar" style="width: 0%; font-weight: 600;">0%</div>
                    </div>

                    <!-- Live Stats -->
                    <div id="statsRow" class="d-flex flex-wrap gap-2 mb-1" style="display: none;">
                        <span class="badge bg-success stat-badge">🟢 Valid: <span id="cValid">0</span></span>
                        <span class="badge bg-warning text-dark stat-badge">🟡 Catch-all: <span id="cCatch">0</span></span>
                        <span class="badge bg-danger stat-badge">🔴 Invalid: <span id="cInvalid">0</span></span>
                        <span class="badge bg-secondary stat-badge">⚪ Unknown: <span id="cUnknown">0</span></span>
                        <span class="badge bg-info text-dark stat-badge">Total checked: <span id="cTotal">0</span> / <span id="cTotalTarget">0</span></span>
                    </div>

                    <!-- Download Links -->
                    <div id="downloadsSection" class="mt-2 pt-2 border-top" style="display: none;">
                        <div class="small fw-semibold text-secondary mb-1">📥 Download results (updates live):</div>
                        <div class="d-flex flex-wrap gap-2">
                            <a href="/download/actual_email.txt" download
                               class="btn btn-sm btn-success d-flex align-items-center gap-1"
                               style="font-size: 0.82rem; border-radius: 6px; padding-top:2px; padding-bottom:2px;">
                                📥 <span>actual_email.txt</span>
                                <small class="opacity-75 ms-1 d-none d-sm-inline">(valid + catch-all)</small>
                            </a>
                            <a href="/download/wrong_email.txt" download
                               class="btn btn-sm btn-danger d-flex align-items-center gap-1"
                               style="font-size: 0.82rem; border-radius: 6px; padding-top:2px; padding-bottom:2px;">
                                📥 <span>wrong_email.txt</span>
                            </a>
                            <a href="/download/checked_email.txt" download
                               class="btn btn-sm btn-outline-dark d-flex align-items-center gap-1"
                               style="font-size: 0.82rem; border-radius: 6px; padding-top:2px; padding-bottom:2px;">
                                📥 <span>checked_email.txt</span>
                                <small class="opacity-75 ms-1 d-none d-sm-inline">(full details)</small>
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Log -->
                <div class="card p-3">
                    <div class="d-flex justify-content-between align-items-center mb-2 px-1">
                        <h6 class="text-dark fw-bold mb-0">📋 Live Verification Log</h6>
                        <button id="clearLogBtn" class="btn btn-sm btn-outline-secondary py-0 px-2" style="font-size:12px">Clear log</button>
                    </div>
                    <div id="logConsole">Waiting for email list...</div>
                </div>

                <!-- Downloads are now available as buttons above the log (in the main card) -->
            </div>
        </div>
    </div>

    <script>
        // Sync range + number input for workers
        const range = document.getElementById('workersRange');
        const num = document.getElementById('workersInput');
        function syncWorkers(val) {
            range.value = val;
            num.value = val;
        }
        range.addEventListener('input', () => syncWorkers(range.value));
        num.addEventListener('input', () => syncWorkers(num.value));

        // Load default list button
        document.getElementById('loadDefaultBtn').addEventListener('click', async function() {
            const btn = this;
            btn.disabled = true;
            btn.textContent = 'Loading...';
            try {
                const res = await fetch('/load_default');
                const text = await res.text();
                if (text && text.trim()) {
                    document.getElementById('emailsInput').value = text;
                } else {
                    alert('email_list.txt is empty or not found.');
                }
            } catch (e) {
                alert('Failed to load email_list.txt');
            }
            btn.disabled = false;
            btn.textContent = '📂 Load email_list.txt';
        });

        // Clear log
        document.getElementById('clearLogBtn').addEventListener('click', () => {
            document.getElementById('logConsole').innerHTML = '';
        });

        // Main Start
        document.getElementById('startBtn').addEventListener('click', function() {
            let inputText = document.getElementById('emailsInput').value.trim();

            // If empty, try to auto-load default on the fly
            if (!inputText) {
                // We will let backend load email_list.txt automatically
            }

            const workers = parseInt(document.getElementById('workersInput').value) || 5;
            const catchAll = document.getElementById('catchAllCheck').checked ? 1 : 0;

            // UI setup
            document.getElementById('startBtn').disabled = true;
            document.getElementById('loadDefaultBtn').disabled = true;
            document.getElementById('logConsole').innerHTML = '<div style="color:#3498db">🚀 Starting parallel verification engine (workers: ' + workers + ')...</div>';
            document.getElementById('progressContainer').style.display = 'flex';
            document.getElementById('downloadsSection').style.display = 'block';
            const progressBar = document.getElementById('progressBar');
            progressBar.style.width = '0%';
            progressBar.innerText = '0%';
            document.getElementById('progressText').innerText = '';

            // Reset stats
            ['cValid','cCatch','cInvalid','cUnknown','cTotal'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.textContent = '0';
            });
            document.getElementById('cTotalTarget').textContent = '0';
            document.getElementById('statsRow').style.display = 'flex';

            const statusEl = document.getElementById('statusText');
            statusEl.innerText = 'Running...';

            // Build SSE URL
            let url = '/sort_emails?workers=' + workers + '&catch_all=' + catchAll;
            if (inputText) {
                url += '&data=' + encodeURIComponent(inputText);
            }
            const eventSource = new EventSource(url);

            let totalEmails = 0;

            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);

                if (data.type === 'progress') {
                    totalEmails = data.total || totalEmails;
                    progressBar.style.width = data.percentage + '%';
                    progressBar.innerText = data.percentage + '%';
                    document.getElementById('progressText').innerText = `${data.current}/${data.total}`;
                    statusEl.innerText = `Progress: ${data.current} / ${data.total}  (workers: ${workers})`;

                    // Update counters
                    const cValid = document.getElementById('cValid');
                    const cCatch = document.getElementById('cCatch');
                    const cInvalid = document.getElementById('cInvalid');
                    const cUnknown = document.getElementById('cUnknown');
                    const cTotal = document.getElementById('cTotal');
                    const cTarget = document.getElementById('cTotalTarget');

                    cTarget.textContent = data.total;

                    let cls = 'log-invalid', icon = '🔴 [INVALID]';
                    if (data.status === 'valid') {
                        cls = 'log-valid';
                        icon = '🟢 [VALID]';
                        cValid.textContent = parseInt(cValid.textContent) + 1;
                    } else if (data.status === 'catch_all') {
                        cls = 'log-catch';
                        icon = '🟡 [CATCH-ALL]';
                        cCatch.textContent = parseInt(cCatch.textContent) + 1;
                    } else if (data.status === 'invalid') {
                        cInvalid.textContent = parseInt(cInvalid.textContent) + 1;
                    } else {
                        cls = 'log-unknown';
                        icon = '⚪ [UNKNOWN]';
                        cUnknown.textContent = parseInt(cUnknown.textContent) + 1;
                    }
                    cTotal.textContent = parseInt(cTotal.textContent) + 1;

                    const line = `<div class="${cls}" style="margin-bottom:2px;">${icon} ${data.email} — ${data.details}</div>`;
                    const log = document.getElementById('logConsole');
                    log.innerHTML += line;
                    log.scrollTop = log.scrollHeight;
                } 
                else if (data.type === 'complete') {
                    eventSource.close();
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('loadDefaultBtn').disabled = false;
                    statusEl.innerText = 'Finished!';

                    const s = data.summary || {valid:0, catch_all:0, invalid:0, unknown:0, total: totalEmails};
                    const summaryLine = `<div class="mt-2" style="color:#f1c40f; font-weight:600;">🏆 FINISHED — Valid: ${s.valid} | Catch-all: ${s.catch_all} | Invalid: ${s.invalid} | Unknown: ${s.unknown} | Total: ${s.total}</div>`;
                    document.getElementById('logConsole').innerHTML += summaryLine + 
                        `<div style="color:#16a34a; font-size:12.5px; font-weight:500;">✅ Use the 📥 Download buttons above the log (in the main panel) — files are ready.</div>`;
                    document.getElementById('logConsole').scrollTop = document.getElementById('logConsole').scrollHeight;
                }
            };

            eventSource.onerror = function() {
                eventSource.close();
                document.getElementById('startBtn').disabled = false;
                document.getElementById('loadDefaultBtn').disabled = false;
                statusEl.innerText = 'Stopped / Error';
                document.getElementById('logConsole').innerHTML += `<div style="color:#e74c3c;">[Connection closed]</div>`;
            };
        });

        // Auto-load default list into textarea on first visit (nice UX)
        window.addEventListener('DOMContentLoaded', () => {
            const ta = document.getElementById('emailsInput');
            if (!ta.value.trim()) {
                // load silently in background
                fetch('/load_default').then(r => r.text()).then(t => {
                    if (t && t.trim() && !ta.value.trim()) {
                        ta.value = t;
                    }
                }).catch(()=>{});
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/load_default')
def load_default():
    """Return contents of email_list.txt so UI can load it with one click."""
    try:
        with open("email_list.txt", "r", encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/plain")
    except Exception:
        return Response("", mimetype="text/plain")


@app.route('/download/<filename>')
def download_file(filename):
    """Serve the result files for easy download."""
    allowed = {"actual_email.txt", "wrong_email.txt", "checked_email.txt"}
    if filename not in allowed:
        return "File not allowed", 400
    try:
        return send_from_directory(
            directory=".",
            path=filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return "File not found. Please run a validation first.", 404


@app.route('/sort_emails')
def sort_emails():
    raw_data = request.args.get('data', '').strip()

    # Workers (3-10)
    try:
        workers = max(3, min(10, int(request.args.get('workers', '5'))))
    except Exception:
        workers = 5

    detect_catch = request.args.get('catch_all', '1') == '1'

    # If no data passed from UI, auto-load the default file (as requested)
    if not raw_data:
        try:
            with open("email_list.txt", "r", encoding="utf-8") as f:
                raw_data = f.read()
        except FileNotFoundError:
            raw_data = ''

    # Parse + clean + deduplicate (preserve original case)
    emails = []
    for line in raw_data.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Support "email:password" or "email,password" formats
        email = line.split(':', 1)[0].strip()
        if '@' not in email:
            email = line.split(',', 1)[0].strip()
        if email:
            emails.append(email)

    # Dedup by lower-cased key while preserving first-seen casing
    seen = set()
    lines = []
    for e in emails:
        key = e.lower()
        if key not in seen:
            seen.add(key)
            lines.append(e)

    total_emails = len(lines)

    # Clear output files at start of run
    for fname in ("actual_email.txt", "wrong_email.txt", "checked_email.txt"):
        open(fname, "w", encoding="utf-8").close()

    def generate():
        counts = {'valid': 0, 'catch_all': 0, 'invalid': 0, 'unknown': 0}
        completed = 0

        def classify_for_ui(status, details):
            if status == "valid":
                return "valid", details or "Mailbox accepts mail"
            elif status == "catch_all":
                return "catch_all", details or "Catch-all domain"
            elif status in ("invalid_syntax", "no_mx", "mailbox_invalid", "smtp_error", "temp_error"):
                return "invalid", details or status.replace("_", " ").title()
            else:
                return "unknown", details or status.replace("_", " ").title()

        def write_files(email, status, details):
            with file_lock:
                if status in ("valid", "catch_all"):
                    with open("actual_email.txt", "a", encoding="utf-8") as f:
                        f.write(f"{email}\n")
                else:
                    with open("wrong_email.txt", "a", encoding="utf-8") as f:
                        f.write(f"{email}\n")
                with open("checked_email.txt", "a", encoding="utf-8") as f:
                    f.write(f"{email} => {status}: {details}\n")

        if total_emails == 0:
            yield f"data: {json.dumps({'type': 'complete', 'summary': {'total': 0, 'valid': 0, 'catch_all': 0, 'invalid': 0, 'unknown': 0}})}\n\n"
            return

        def task(email):
            status, details = verify_email_delivery(email, detect_catch_all=detect_catch)
            return email, status, details

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="val") as executor:
            future_to_email = {executor.submit(task, email): email for email in lines}

            for future in as_completed(future_to_email):
                email, status, details = future.result()
                display_status, ui_details = classify_for_ui(status, details)

                # Update counters
                if display_status == "valid":
                    counts['valid'] += 1
                elif display_status == "catch_all":
                    counts['catch_all'] += 1
                elif display_status == "invalid":
                    counts['invalid'] += 1
                else:
                    counts['unknown'] += 1

                completed += 1
                percentage = int((completed / total_emails) * 100)

                write_files(email, status, details)

                payload = {
                    'type': 'progress',
                    'current': completed,
                    'total': total_emails,
                    'percentage': percentage,
                    'email': email,
                    'status': display_status,
                    'details': ui_details
                }
                yield f"data: {json.dumps(payload)}\n\n"

        summary = {
            'total': total_emails,
            'valid': counts['valid'],
            'catch_all': counts['catch_all'],
            'invalid': counts['invalid'],
            'unknown': counts['unknown']
        }
        yield f"data: {json.dumps({'type': 'complete', 'summary': summary})}\n\n"

    return Response(generate(), mimetype='text/event-stream')


if __name__ == '__main__':
    print("🌍 Best Real Email Validator running on http://127.0.0.1:5051")
    print("   Default list: email_list.txt | Workers: configurable 3-10 in UI")
    app.run(debug=True, port=5051)