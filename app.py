# =============================================================
# Email Validator — Flask app with parallel SMTP verification
# Auto-installs missing dependencies on first run.
# =============================================================
import sys
import subprocess
import importlib.util
import os


def _ensure_dependencies():
    """Install missing packages from requirements.txt, then restart."""
    required = [("flask", "flask"), ("dns", "dnspython"), ("email_validator", "email-validator")]
    missing = [pip for imp, pip in required if importlib.util.find_spec(imp) is None]
    if not missing:
        return

    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    print(f"Missing packages: {', '.join(missing)}\nInstalling from requirements.txt...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
        print("\nDependencies installed. Restarting...\n")
    except subprocess.CalledProcessError as e:
        print(f"\nAuto-install failed (code {e.returncode}).")
        print(f"Run manually:  {sys.executable} -m pip install -r requirements.txt")
        sys.exit(1)
    os.execv(sys.executable, [sys.executable] + sys.argv)


_ensure_dependencies()

# --- Third-party imports (safe after dependency check) ---
from flask import Flask, render_template_string, request, Response, send_from_directory, jsonify
import json
import time
import threading
import random
import socket
import smtplib
import uuid
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from email_validator import validate_email, EmailNotValidError

# =============================================================
# App setup
# =============================================================
app = Flask(__name__)

# Thread-safe caches
_mx_cache: dict = {}
_mx_lock = threading.Lock()
_catch_cache: dict = {}
_catch_lock = threading.Lock()
_file_lock = threading.Lock()

# Session cancel events: session_id -> threading.Event
_cancel_events: dict = {}
_cancel_lock = threading.Lock()

# Realistic EHLO name (reduces server rejections compared to "localhost")
EHLO_NAME = "mail.outbound-relay.net"

# Major providers that intentionally block unauthenticated SMTP probes.
# For these, valid syntax + live MX record is treated as "likely valid".
PROBE_BLOCKING_PROVIDERS = {
    # Google
    "gmail.com", "googlemail.com",
    # Yahoo / AOL
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.com.br",
    "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it", "yahoo.ca",
    "yahoo.com.au", "yahoo.co.jp", "ymail.com", "rocketmail.com",
    "aol.com", "aim.com",
    # Microsoft
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "live.co.uk",
    "outlook.co.id", "outlook.jp", "outlook.kr", "outlook.de",
    "outlook.fr", "outlook.es", "hotmail.es", "hotmail.it",
    "live.fr", "live.de", "live.nl", "live.it",
    # Apple
    "icloud.com", "me.com", "mac.com",
    # Others
    "protonmail.com", "proton.me", "pm.me",
    "zoho.com", "zohomail.com",
    "yandex.com", "yandex.ru",
    "gmx.com", "gmx.net", "gmx.de",
    "web.de", "mail.ru",
    "fastmail.com", "fastmail.fm",
    "tutanota.com", "tutamail.com", "tuta.io",
    "hey.com",
}


# =============================================================
# Rate limiter — avoids hammering a single domain
# =============================================================
class DomainRateLimiter:
    def __init__(self, min_interval: float = 0.15):
        self.min_interval = min_interval
        self._last: dict = {}
        self._lock = threading.Lock()

    def wait(self, domain: str):
        with self._lock:
            now = time.time()
            wait_sec = max(0.0, self.min_interval - (now - self._last.get(domain, 0.0)))
            self._last[domain] = now + wait_sec
        if wait_sec:
            time.sleep(wait_sec)
        with self._lock:
            self._last[domain] = time.time()


# Default DNS / rate-limit tunables — overridden per session via UI form fields
DEFAULT_DNS_TIMEOUT = 3
DEFAULT_DNS_LIFETIME = 5
DEFAULT_RATE_INTERVAL = 0.15


def _make_dns_resolver(timeout: float = DEFAULT_DNS_TIMEOUT, lifetime: float = DEFAULT_DNS_LIFETIME):
    """Build a DNS resolver with the requested timeouts."""
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = lifetime
    return r


def _make_rate_limiter(min_interval: float = DEFAULT_RATE_INTERVAL) -> DomainRateLimiter:
    """Build a per-domain rate limiter with the requested interval."""
    return DomainRateLimiter(min_interval=min_interval)


# =============================================================
# DNS helpers
# =============================================================
def get_mx_server(domain: str, use_a_fallback: bool = True,
                  dns_timeout: float = DEFAULT_DNS_TIMEOUT,
                  dns_lifetime: float = DEFAULT_DNS_LIFETIME) -> str | None:
    """Return the best MX hostname for domain (with optional A-record fallback). Cached."""
    cache_key = (domain, use_a_fallback, dns_timeout, dns_lifetime)
    with _mx_lock:
        if cache_key in _mx_cache:
            return _mx_cache[cache_key]

    resolver = _make_dns_resolver(dns_timeout, dns_lifetime)
    result = None
    try:
        records = resolver.resolve(domain, "MX")
        result = sorted(records, key=lambda r: r.preference)[0].exchange.to_text().rstrip(".")
    except Exception:
        if use_a_fallback:
            try:
                resolver.resolve(domain, "A")
                result = domain  # domain acts as its own mail server
            except Exception:
                result = None
        else:
            result = None

    with _mx_lock:
        _mx_cache[cache_key] = result
    return result


def prewarm_mx_cache(domains: list[str], max_workers: int = 30,
                     use_a_fallback: bool = True,
                     dns_timeout: float = DEFAULT_DNS_TIMEOUT,
                     dns_lifetime: float = DEFAULT_DNS_LIFETIME):
    """Batch-resolve MX records for all unique domains before SMTP probes."""
    unresolved = []
    with _mx_lock:
        for d in domains:
            cache_key = (d, use_a_fallback, dns_timeout, dns_lifetime)
            if cache_key not in _mx_cache:
                unresolved.append(d)

    if not unresolved:
        return

    def _resolve(d):
        get_mx_server(d, use_a_fallback=use_a_fallback,
                      dns_timeout=dns_timeout, dns_lifetime=dns_lifetime)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unresolved))) as pool:
        pool.map(_resolve, unresolved)


# =============================================================
# Low-level SMTP probe
# =============================================================
def _smtp_probe(host: str, port: int, mail_from: str, rcpt_to: str, timeout: int = 10):
    """
    Open an SMTP connection and perform EHLO + optional STARTTLS + MAIL FROM + RCPT TO.
    Returns (smtp_code, response_text, banner_text).
    Raises any exception on connection/protocol failure.
    """
    server = smtplib.SMTP(timeout=timeout)
    server.connect(host, port)
    banner = (server.welcome or b"").decode(errors="ignore").strip()[:80]
    server.ehlo(EHLO_NAME)
    if server.has_extn("starttls"):
        try:
            server.starttls()
            server.ehlo(EHLO_NAME)
        except Exception:
            pass
    server.mail(mail_from)
    code, msg = server.rcpt(rcpt_to)
    try:
        server.quit()
    except Exception:
        pass
    text = (msg.decode(errors="ignore") if isinstance(msg, (bytes, bytearray)) else str(msg)).strip()[:90]
    return code, text, banner


def _parse_ports(ports_str: str) -> list[int]:
    """Parse '25,587' style string into a unique, ordered list of ints."""
    out: list[int] = []
    seen: set = set()
    for part in str(ports_str or "").split(","):
        p = part.strip()
        if not p:
            continue
        try:
            n = int(p)
        except ValueError:
            continue
        if n in (25, 465, 587, 2525) and n not in seen:
            seen.add(n)
            out.append(n)
    return out or [25]


# =============================================================
# Catch-all detection
# =============================================================
def is_catch_all(host: str, domain: str, ports: list[int] | None = None,
                 timeout: int = 6, rate_limiter: DomainRateLimiter | None = None) -> bool:
    """
    Probe with a random bogus address.
    If the server accepts it (250), the domain is catch-all.
    Result is cached per domain.
    """
    cache_key = (domain, tuple(ports or (25, 587)), timeout)
    with _catch_lock:
        if cache_key in _catch_cache:
            return _catch_cache[cache_key]

    bogus = f"no-such-user-{random.randint(10_000_000, 99_999_999)}@{domain}"
    result = False
    for port in (ports or [25, 587]):
        try:
            if rate_limiter is not None:
                rate_limiter.wait(domain)
            code, _, _ = _smtp_probe(host, port, f"postmaster@{domain}", bogus, timeout=timeout)
            result = (code == 250)
            break
        except Exception:
            continue

    with _catch_lock:
        _catch_cache[cache_key] = result
    return result


# =============================================================
# Main verification logic
# =============================================================
def verify_email(email: str, detect_catch_all: bool = True,
                 cfg: dict | None = None) -> tuple[str, str]:
    """
    Verify a single email address.

    Returns (status, detail_message) where status is one of:
      valid         — SMTP 250 confirmed
      likely_valid  — Known provider blocks probes; syntax + MX look good
      catch_all     — Domain accepts all addresses (cannot confirm individually)
      invalid       — Bad syntax, no MX, or SMTP 5xx rejection
      undetermined  — Server connected but dropped probe without clear answer
      unknown       — Unexpected error

    `cfg` may contain:
      timeout              — SMTP probe timeout in seconds (default 10)
      min_interval         — per-domain rate-limit interval (default 0.15s)
      ports                — list of SMTP ports to try in order (default [25, 587])
      use_a_fallback       — fall back to A-record if no MX (default True)
      skip_syntax          — skip email-validator syntax check (default False)
      known_blocker_fallback — treat blocked providers as likely_valid (default True)
      dns_timeout          — dnspython resolver.timeout (default 3)
      dns_lifetime         — dnspython resolver.lifetime (default 5)
    """
    cfg = cfg or {}
    timeout = int(cfg.get("timeout", 10))
    min_interval = float(cfg.get("min_interval", DEFAULT_RATE_INTERVAL))
    ports = cfg.get("ports") or [25, 587]
    use_a_fallback = bool(cfg.get("use_a_fallback", True))
    skip_syntax = bool(cfg.get("skip_syntax", False))
    known_blocker_enabled = bool(cfg.get("known_blocker_fallback", True))
    dns_timeout = float(cfg.get("dns_timeout", DEFAULT_DNS_TIMEOUT))
    dns_lifetime = float(cfg.get("dns_lifetime", DEFAULT_DNS_LIFETIME))

    rate_limiter = _make_rate_limiter(min_interval)

    # 1. Syntax check
    if not skip_syntax:
        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            return "invalid", "Bad email syntax"

    domain = email.rsplit("@", 1)[-1].lower()
    if not domain:
        return "invalid", "Missing domain part"

    # 2. MX / A record lookup
    mx = get_mx_server(domain, use_a_fallback=use_a_fallback,
                       dns_timeout=dns_timeout, dns_lifetime=dns_lifetime)
    if not mx:
        return "invalid", "No mail server found (no MX or A record)"

    known_blocker = known_blocker_enabled and (domain in PROBE_BLOCKING_PROVIDERS)

    # 3. SMTP probe — try each port with a postmaster sender first,
    #    then a second probe on the first port with an empty sender.
    rate_limiter.wait(domain)

    # Build probe plan: for each user-selected port, try (port, postmaster@) then (port, "")
    probe_plan: list[tuple[int, str]] = []
    for p in ports:
        probe_plan.append((p, f"postmaster@{domain}"))
    if 25 in ports:
        # preserve legacy behaviour: try empty sender on 25 once
        probe_plan.append((25, ""))
    last_error = ("unknown", "Could not complete verification")
    banner = ""

    for attempt, (port, mail_from) in enumerate(probe_plan):
        if attempt > 0:
            rate_limiter.wait(domain)

        try:
            code, msg_text, banner = _smtp_probe(mx, port, mail_from, email, timeout=timeout)

            if code == 250:
                if detect_catch_all and is_catch_all(mx, domain, ports=ports,
                                                     timeout=max(4, timeout - 2),
                                                     rate_limiter=rate_limiter):
                    return "catch_all", "Catch-all domain — accepts mail to any address"
                return "valid", f"Mailbox confirmed (SMTP 250, port {port})"
            elif code in (550, 551, 553, 554):
                return "invalid", f"Mailbox rejected by server (SMTP {code})"
            elif code == 552:
                return "valid", f"Mailbox exists but is full (SMTP 552, port {port})"
            elif code == 541:
                return "invalid", f"Rejected by recipient policy (SMTP 541)"
            elif code == 421:
                return "undetermined", f"Service temporarily unavailable (SMTP 421) — retry later"
            elif code in (450, 451, 452):
                return "undetermined", f"Temporary server rejection (SMTP {code}) — try again later"
            else:
                return "undetermined", f"Unexpected SMTP response {code}: {msg_text}"

        except smtplib.SMTPConnectError as e:
            last_error = ("undetermined", f"Port {port} refused/unreachable: {str(e)[:60]}")
            continue
        except (socket.timeout, TimeoutError):
            reason = (
                "Port 25 may be blocked by your ISP."
                if port == 25
                else "Port 587 requires AUTH; unauthenticated probes timeout."
            )
            last_error = ("undetermined", f"Timeout on port {port}. {reason} Banner: {banner or 'none'}")
            continue
        except smtplib.SMTPServerDisconnected:
            last_error = (
                "undetermined",
                f"Server dropped connection on port {port} after MAIL FROM "
                f"(sender={mail_from or '<>'}, banner: {banner or 'none'})",
            )
            continue
        except Exception as e:
            last_error = ("unknown", f"Error on port {port}: {str(e)[:70]}")
            continue

    # 4. All probes exhausted — known provider fallback
    if known_blocker:
        return (
            "likely_valid",
            f"{domain} is a major provider that blocks SMTP probes from external IPs. "
            "Syntax ✓  MX ✓ — address is very likely valid.",
        )

    return last_error


# =============================================================
# HTML / CSS / JS UI
# =============================================================
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Validator — High Performance</title>
    <meta name="description" content="Validate up to 50,000+ emails with real-time SMTP verification, DNS MX lookup, and catch-all detection. Fast, accurate, cancellable.">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1a1f35;
            --bg-card-hover: #1f2541;
            --bg-input: #0d1225;
            --border: #2a3155;
            --border-focus: #6366f1;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #6366f1;
            --accent-glow: rgba(99, 102, 241, 0.25);
            --green: #22c55e;
            --green-soft: #86efac;
            --green-bg: rgba(34, 197, 94, 0.12);
            --yellow: #eab308;
            --yellow-bg: rgba(234, 179, 8, 0.12);
            --red: #ef4444;
            --red-bg: rgba(239, 68, 68, 0.12);
            --orange: #f97316;
            --orange-bg: rgba(249, 115, 22, 0.12);
            --blue: #3b82f6;
            --blue-bg: rgba(59, 130, 246, 0.12);
            --cyan: #22d3ee;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Animated background */
        body::before {
            content: '';
            position: fixed;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: radial-gradient(ellipse at 20% 50%, rgba(99,102,241,0.06) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 20%, rgba(139,92,246,0.04) 0%, transparent 50%),
                        radial-gradient(ellipse at 50% 80%, rgba(59,130,246,0.04) 0%, transparent 50%);
            animation: bgShift 20s ease-in-out infinite alternate;
            z-index: 0;
        }
        @keyframes bgShift {
            0% { transform: translate(0, 0); }
            100% { transform: translate(-3%, -3%); }
        }

        .app-container {
            position: relative;
            z-index: 1;
            max-width: 1100px;
            margin: 0 auto;
            padding: 24px 20px 40px;
        }

        /* Header */
        .app-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        .app-header h1 {
            font-size: 1.65rem;
            font-weight: 800;
            background: linear-gradient(135deg, #c7d2fe, #6366f1, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        .header-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.72rem;
            font-weight: 600;
            color: var(--cyan);
            background: rgba(34, 211, 238, 0.08);
            border: 1px solid rgba(34, 211, 238, 0.2);
            padding: 5px 12px;
            border-radius: 20px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        /* Card */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 16px;
            transition: border-color 0.3s ease;
        }
        .card:hover { border-color: rgba(99,102,241,0.3); }

        .card-title {
            font-size: 0.82rem;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .card-title .icon { font-size: 1rem; }

        /* Controls grid */
        .controls-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 2fr;
            gap: 16px;
            margin-bottom: 20px;
        }
        @media (max-width: 768px) {
            .controls-grid { grid-template-columns: 1fr; }
        }

        .control-group label {
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input[type="number"] {
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
            font-weight: 600;
            padding: 10px 14px;
            border-radius: 10px;
            width: 90px;
            text-align: center;
            transition: all 0.2s;
            outline: none;
        }
        input[type="number"]:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        /* Toggle switch */
        .toggle-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 4px;
        }
        .toggle {
            position: relative;
            width: 44px;
            height: 24px;
            cursor: pointer;
        }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle-track {
            position: absolute;
            inset: 0;
            background: #334155;
            border-radius: 12px;
            transition: background 0.3s;
        }
        .toggle input:checked + .toggle-track { background: var(--accent); }
        .toggle-knob {
            position: absolute;
            top: 3px; left: 3px;
            width: 18px; height: 18px;
            background: #fff;
            border-radius: 50%;
            transition: transform 0.3s;
            pointer-events: none;
        }
        .toggle input:checked ~ .toggle-knob { transform: translateX(20px); }
        .toggle-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        /* Buttons */
        .btn-row {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 11px 22px;
            border-radius: 10px;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            font-weight: 700;
            cursor: pointer;
            border: none;
            transition: all 0.25s ease;
            letter-spacing: 0.2px;
        }
        .btn:disabled {
            opacity: 0.45;
            cursor: not-allowed;
            transform: none !important;
        }
        .btn-start {
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: #fff;
            flex: 1;
            justify-content: center;
            box-shadow: 0 4px 15px rgba(34,197,94,0.25);
        }
        .btn-start:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(34,197,94,0.35);
        }
        .btn-cancel {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: #fff;
            flex: 1;
            justify-content: center;
            box-shadow: 0 4px 15px rgba(239,68,68,0.25);
            display: none;
        }
        .btn-cancel:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(239,68,68,0.35);
        }
        .btn-cancel.cancelling {
            background: linear-gradient(135deg, #9333ea, #7c3aed);
            box-shadow: 0 4px 15px rgba(147,51,234,0.25);
        }
        .btn-load {
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }
        .btn-load:hover:not(:disabled) {
            border-color: var(--accent);
            color: var(--text-primary);
            transform: translateY(-1px);
        }

        /* Engine Configuration Panel */
        .engine-config {
            margin-top: 18px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--bg-input);
            overflow: hidden;
        }
        .engine-config > summary {
            cursor: pointer;
            padding: 12px 16px;
            font-weight: 600;
            color: var(--text-primary);
            user-select: none;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .engine-config > summary::-webkit-details-marker { display: none; }
        .engine-config > summary::before {
            content: '▸';
            display: inline-block;
            transition: transform 0.15s;
            color: var(--text-secondary);
        }
        .engine-config[open] > summary::before { transform: rotate(90deg); }
        .engine-config > summary:hover { color: var(--accent); }
        .engine-config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 14px;
            padding: 8px 16px 16px;
            border-top: 1px solid var(--border);
        }
        .ec-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .ec-group label {
            display: flex;
            flex-direction: column;
            gap: 2px;
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .ec-hint {
            font-size: 0.7rem;
            font-weight: 400;
            color: var(--text-muted);
            text-transform: none;
            letter-spacing: 0;
        }
        .ec-group input[type="text"],
        .ec-group input[type="number"] {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 10px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        .ec-group input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .ec-toggles { gap: 0; }
        .ec-toggles .toggle-label {
            display: inline-block;
            margin-left: 10px;
            font-size: 0.85rem;
            color: var(--text-primary);
            text-transform: none;
            letter-spacing: 0;
        }
        .ec-actions {
            justify-content: flex-end;
            align-items: flex-end;
        }
        .ec-actions .btn { width: 100%; }

        /* Textarea */
        .email-textarea {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            line-height: 1.55;
            padding: 16px;
            border-radius: 12px;
            resize: vertical;
            min-height: 160px;
            outline: none;
            transition: all 0.2s;
        }
        .email-textarea:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .email-textarea::placeholder { color: var(--text-muted); }

        .email-count {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 6px;
            font-weight: 500;
            font-family: 'JetBrains Mono', monospace;
        }
        .email-count strong { color: var(--accent); }

        /* Progress section */
        .progress-section {
            margin-top: 20px;
            display: none;
        }
        .progress-section.active { display: block; }

        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .progress-status {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
        }
        .progress-status.running { color: var(--cyan); }
        .progress-status.finished { color: var(--green); }
        .progress-status.cancelled { color: var(--orange); }
        .progress-counter {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--accent);
        }

        .progress-track {
            height: 8px;
            background: var(--bg-input);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #6366f1, #818cf8, #a78bfa);
            border-radius: 8px;
            transition: width 0.3s ease;
            position: relative;
        }
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .speed-row {
            display: flex;
            gap: 20px;
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 14px;
        }
        .speed-row span strong { color: var(--text-secondary); }

        /* Stats grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 8px;
            margin-bottom: 0;
        }
        .stat-card {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            border-radius: 10px;
            font-size: 0.78rem;
            font-weight: 600;
        }
        .stat-card .stat-count {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.15rem;
            font-weight: 800;
        }
        .stat-valid     { background: var(--green-bg); color: var(--green); }
        .stat-likely    { background: rgba(134,239,172,0.1); color: var(--green-soft); }
        .stat-catch     { background: var(--yellow-bg); color: var(--yellow); }
        .stat-invalid   { background: var(--red-bg); color: var(--red); }
        .stat-undet     { background: var(--orange-bg); color: var(--orange); }
        .stat-unknown   { background: rgba(148,163,184,0.1); color: var(--text-secondary); }
        .stat-total     { background: var(--blue-bg); color: var(--blue); }

        /* Log console */
        .log-console {
            background: #060a15;
            border: 1px solid rgba(99,102,241,0.15);
            border-radius: 12px;
            padding: 0;
            height: 400px;
            overflow: hidden;
            position: relative;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            line-height: 1.5;
        }
        .log-inner {
            height: 100%;
            overflow-y: auto;
            padding: 14px 16px;
            scroll-behavior: smooth;
        }
        .log-inner::-webkit-scrollbar { width: 6px; }
        .log-inner::-webkit-scrollbar-track { background: transparent; }
        .log-inner::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 3px;
        }

        .log-entry {
            padding: 2px 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .log-valid   { color: #4ade80; }
        .log-likely  { color: #86efac; }
        .log-catch   { color: #facc15; }
        .log-invalid { color: #f87171; }
        .log-undet   { color: #fb923c; }
        .log-unknown { color: #94a3b8; }
        .log-system  { color: #38bdf8; }
        .log-done    { color: #facc15; font-weight: 700; }

        .log-cap-notice {
            position: absolute;
            bottom: 0; left: 0; right: 0;
            background: linear-gradient(transparent, #060a15 70%);
            padding: 20px 16px 10px;
            font-size: 0.7rem;
            color: var(--text-muted);
            text-align: center;
            pointer-events: none;
        }

        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .btn-clear {
            font-size: 0.7rem;
            padding: 4px 10px;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 6px;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            transition: all 0.2s;
        }
        .btn-clear:hover {
            border-color: var(--accent);
            color: var(--text-primary);
        }

        /* Downloads */
        .downloads-section {
            display: none;
        }
        .downloads-section.active { display: block; }

        .download-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 8px;
        }
        .dl-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.78rem;
            font-weight: 600;
            transition: all 0.2s;
        }
        .dl-btn:hover {
            border-color: var(--accent);
            color: var(--text-primary);
            transform: translateY(-1px);
        }
        .dl-btn .dl-icon { font-size: 1.1rem; }
        .dl-btn .dl-sub {
            font-size: 0.65rem;
            color: var(--text-muted);
            font-weight: 400;
        }

        .note-text {
            font-size: 0.7rem;
            color: var(--text-muted);
            margin-top: 10px;
            line-height: 1.5;
        }
        .note-text strong { color: var(--text-secondary); }

        /* Pulse animation for running status */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .pulse { animation: pulse 1.5s ease-in-out infinite; }
    </style>
</head>
<body>
<div class="app-container">

    <!-- Header -->
    <header class="app-header">
        <h1>⚡ Email Validator</h1>
        <span class="header-badge">
            <span>●</span> MX + SMTP + Catch-All
        </span>
    </header>

    <!-- Controls Card -->
    <div class="card">
        <div class="card-title"><span class="icon">⚙️</span> Configuration</div>

        <div class="controls-grid">
            <div class="control-group">
                <label>Parallel Workers</label>
                <input id="workersInput" type="number" min="1" max="50" value="20">
            </div>

            <div class="control-group">
                <label>Options</label>
                <label class="toggle">
                    <input type="checkbox" id="catchAllCheck" checked>
                    <span class="toggle-track"></span>
                    <span class="toggle-knob"></span>
                </label>
                <span class="toggle-label" style="margin-top:4px;display:block">Detect catch-all domains</span>
            </div>

            <div class="control-group">
                <label>Actions</label>
                <div class="btn-row">
                    <button id="loadBtn" class="btn btn-load" type="button">📂 Load File</button>
                    <button id="startBtn" class="btn btn-start" type="button">▶ Start Validation</button>
                    <button id="cancelBtn" class="btn btn-cancel" type="button">⏹ Cancel</button>
                </div>
            </div>
        </div>

        <!-- Engine Configuration Panel -->
        <details id="engineConfig" class="engine-config" open>
            <summary>🔧 Validation Engine — click to expand & customize</summary>
            <div class="engine-config-grid">

                <div class="ec-group">
                    <label for="portsInput">SMTP Ports
                        <span class="ec-hint">comma-separated, tried in order</span>
                    </label>
                    <input id="portsInput" type="text" value="25,587" placeholder="25,587">
                </div>

                <div class="ec-group">
                    <label for="smtpTimeoutInput">SMTP Timeout (sec)
                        <span class="ec-hint">per probe connection</span>
                    </label>
                    <input id="smtpTimeoutInput" type="number" min="2" max="60" step="1" value="10">
                </div>

                <div class="ec-group">
                    <label for="minIntervalInput">Per-Domain Rate Limit (sec)
                        <span class="ec-hint">min seconds between probes to the same domain</span>
                    </label>
                    <input id="minIntervalInput" type="number" min="0" max="5" step="0.05" value="0.15">
                </div>

                <div class="ec-group">
                    <label for="dnsTimeoutInput">DNS Timeout (sec)
                        <span class="ec-hint">dnspython resolver.timeout</span>
                    </label>
                    <input id="dnsTimeoutInput" type="number" min="1" max="30" step="0.5" value="3">
                </div>

                <div class="ec-group">
                    <label for="dnsLifetimeInput">DNS Lifetime (sec)
                        <span class="ec-hint">dnspython resolver.lifetime</span>
                    </label>
                    <input id="dnsLifetimeInput" type="number" min="1" max="30" step="0.5" value="5">
                </div>

                <div class="ec-group ec-toggles">
                    <label class="toggle">
                        <input type="checkbox" id="useAFallbackCheck" checked>
                        <span class="toggle-track"></span>
                        <span class="toggle-knob"></span>
                    </label>
                    <span class="toggle-label">Fall back to A-record if no MX</span>

                    <label class="toggle" style="margin-top:10px">
                        <input type="checkbox" id="skipSyntaxCheck">
                        <span class="toggle-track"></span>
                        <span class="toggle-knob"></span>
                    </label>
                    <span class="toggle-label">Skip syntax check (trust input)</span>

                    <label class="toggle" style="margin-top:10px">
                        <input type="checkbox" id="knownBlockerCheck" checked>
                        <span class="toggle-track"></span>
                        <span class="toggle-knob"></span>
                    </label>
                    <span class="toggle-label">Mark probe-blocking providers as likely_valid</span>

                    <label class="toggle" style="margin-top:10px">
                        <input type="checkbox" id="autoRetryCheck" checked>
                        <span class="toggle-track"></span>
                        <span class="toggle-knob"></span>
                    </label>
                    <span class="toggle-label">Auto-retry undetermined emails</span>
                </div>

                <div class="ec-group ec-actions">
                    <button id="resetConfigBtn" class="btn btn-load" type="button">↺ Reset to Defaults</button>
                </div>

            </div>
        </details>

        <textarea id="emailsInput" class="email-textarea" rows="8"
            placeholder="Paste emails here (one per line) or click Load File to import email_list.txt&#10;&#10;Supports formats: email@example.com, email:password, email,name"></textarea>
        <div id="emailCount" class="email-count">No emails loaded</div>

        <!-- Progress Section -->
        <div id="progressSection" class="progress-section">
            <div class="progress-header">
                <span id="statusText" class="progress-status">Ready</span>
                <span id="progressCounter" class="progress-counter"></span>
            </div>
            <div class="progress-track">
                <div id="progressFill" class="progress-fill"></div>
            </div>
            <div id="speedRow" class="speed-row">
                <span>⚡ <strong id="speedVal">0</strong> emails/sec</span>
                <span>⏱ Elapsed: <strong id="elapsedVal">0s</strong></span>
                <span>📍 ETA: <strong id="etaVal">—</strong></span>
            </div>
            <div class="stats-grid">
                <div class="stat-card stat-valid">
                    <div>🟢<br><span style="font-size:0.65rem">Valid</span></div>
                    <div class="stat-count" id="cValid">0</div>
                </div>
                <div class="stat-card stat-likely">
                    <div>💚<br><span style="font-size:0.65rem">Likely</span></div>
                    <div class="stat-count" id="cLikely">0</div>
                </div>
                <div class="stat-card stat-catch">
                    <div>🟡<br><span style="font-size:0.65rem">Catch-All</span></div>
                    <div class="stat-count" id="cCatch">0</div>
                </div>
                <div class="stat-card stat-invalid">
                    <div>🔴<br><span style="font-size:0.65rem">Invalid</span></div>
                    <div class="stat-count" id="cInvalid">0</div>
                </div>
                <div class="stat-card stat-undet">
                    <div>🟠<br><span style="font-size:0.65rem">Undet.</span></div>
                    <div class="stat-count" id="cUndet">0</div>
                </div>
                <div class="stat-card stat-unknown">
                    <div>⚪<br><span style="font-size:0.65rem">Unknown</span></div>
                    <div class="stat-count" id="cUnknown">0</div>
                </div>
                <div class="stat-card stat-total">
                    <div>📊<br><span style="font-size:0.65rem">Total</span></div>
                    <div class="stat-count"><span id="cTotal">0</span>/<span id="cTarget">0</span></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Log Card -->
    <div class="card">
        <div class="log-header">
            <div class="card-title" style="margin-bottom:0"><span class="icon">📋</span> Live Verification Log</div>
            <button id="clearBtn" class="btn-clear">Clear</button>
        </div>
        <div class="log-console">
            <div id="logConsole" class="log-inner">
                <div class="log-system">Waiting for email list...</div>
            </div>
            <div id="logCapNotice" class="log-cap-notice" style="display:none">
                Showing last <strong>500</strong> entries of <span id="logTotalCount">0</span> results
            </div>
        </div>
    </div>

    <!-- Downloads Card -->
    <div id="downloadsSection" class="card downloads-section">
        <div class="card-title"><span class="icon">📥</span> Download Results</div>
        <div class="download-grid">
            <a href="/download/actual_email.txt" download class="dl-btn">
                <span class="dl-icon">✅</span>
                <div>actual_email.txt<br><span class="dl-sub">valid + likely valid + catch-all</span></div>
            </a>
            <a href="/download/wrong_email.txt" download class="dl-btn">
                <span class="dl-icon">❌</span>
                <div>wrong_email.txt<br><span class="dl-sub">invalid emails</span></div>
            </a>
            <a href="/download/undetermined_email.txt" download class="dl-btn">
                <span class="dl-icon">⚠️</span>
                <div>undetermined_email.txt<br><span class="dl-sub">unclear result — retry later</span></div>
            </a>
            <a href="/download/checked_email.txt" download class="dl-btn">
                <span class="dl-icon">📄</span>
                <div>checked_email.txt<br><span class="dl-sub">full audit log</span></div>
            </a>
        </div>
        <div class="note-text">
            <strong>undetermined</strong> = server connected but dropped probe before giving a clear answer.
            These are NOT confirmed invalid — verify manually or retry later.
        </div>
    </div>

</div>

<script>
const $ = id => document.getElementById(id);

// State
let currentSessionId = null;
let eventSource = null;
let startTime = null;
let totalEmails = 0;
let completedEmails = 0;
let logEntries = [];
const MAX_LOG_ENTRIES = 500;

// Helpers
function formatTime(seconds) {
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return Math.floor(seconds/60) + 'm ' + Math.round(seconds%60) + 's';
    return Math.floor(seconds/3600) + 'h ' + Math.floor((seconds%3600)/60) + 'm';
}

function countEmails(text) {
    if (!text.trim()) return 0;
    return text.trim().split('\\n').filter(l => {
        l = l.trim();
        return l && !l.startsWith('#') && l.includes('@');
    }).length;
}

// Live email count in textarea
$('emailsInput').addEventListener('input', function() {
    const count = countEmails(this.value);
    $('emailCount').innerHTML = count > 0
        ? `<strong>${count.toLocaleString()}</strong> emails loaded`
        : 'No emails loaded';
});

// Load email_list.txt
$('loadBtn').addEventListener('click', async function() {
    this.disabled = true;
    this.textContent = '⏳ Loading...';
    try {
        const text = await fetch('/load_default').then(r => r.text());
        if (text.trim()) {
            $('emailsInput').value = text;
            $('emailsInput').dispatchEvent(new Event('input'));
        } else {
            alert('email_list.txt is empty or not found.');
        }
    } catch {
        alert('Failed to load email_list.txt');
    }
    this.disabled = false;
    this.textContent = '📂 Load File';
});

// Clear log
$('clearBtn').addEventListener('click', () => {
    $('logConsole').innerHTML = '';
    logEntries = [];
    $('logCapNotice').style.display = 'none';
});

// Add log entry with virtual scrolling
function addLogEntry(html) {
    logEntries.push(html);
    const log = $('logConsole');

    // Virtual scrolling: keep only last MAX_LOG_ENTRIES in DOM
    if (logEntries.length > MAX_LOG_ENTRIES) {
        $('logCapNotice').style.display = 'block';
        $('logTotalCount').textContent = logEntries.length.toLocaleString();

        // Rebuild DOM with last 500
        const visibleEntries = logEntries.slice(-MAX_LOG_ENTRIES);
        log.innerHTML = visibleEntries.join('');
    } else {
        log.insertAdjacentHTML('beforeend', html);
    }

    log.scrollTop = log.scrollHeight;
}

// Cancel
$('cancelBtn').addEventListener('click', function() {
    if (!currentSessionId) return;

    this.disabled = true;
    this.classList.add('cancelling');
    this.textContent = '⏳ Cancelling...';

    fetch('/cancel', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({session_id: currentSessionId})
    });
});

// Speed/ETA update loop
let speedInterval = null;
function startSpeedTracker() {
    startTime = Date.now();
    completedEmails = 0;
    speedInterval = setInterval(() => {
        const elapsed = (Date.now() - startTime) / 1000;
        const speed = elapsed > 0 ? completedEmails / elapsed : 0;
        const remaining = totalEmails - completedEmails;
        const eta = speed > 0 ? remaining / speed : 0;

        $('elapsedVal').textContent = formatTime(elapsed);
        $('speedVal').textContent = speed.toFixed(1);
        $('etaVal').textContent = remaining > 0 ? '~' + formatTime(eta) : '—';
    }, 500);
}
function stopSpeedTracker() {
    if (speedInterval) {
        clearInterval(speedInterval);
        speedInterval = null;
    }
    // Final update
    if (startTime) {
        const elapsed = (Date.now() - startTime) / 1000;
        $('elapsedVal').textContent = formatTime(elapsed);
        const speed = elapsed > 0 ? completedEmails / elapsed : 0;
        $('speedVal').textContent = speed.toFixed(1);
        $('etaVal').textContent = 'Done';
    }
}

function resetUI() {
    $('startBtn').disabled = false;
    $('startBtn').style.display = '';
    $('cancelBtn').style.display = 'none';
    $('cancelBtn').disabled = false;
    $('cancelBtn').classList.remove('cancelling');
    $('cancelBtn').textContent = '⏹ Cancel';
    $('loadBtn').disabled = false;
    stopSpeedTracker();
}

// Start validation
const ENGINE_DEFAULTS = {
    ports: '25,587',
    smtp_timeout: 10,
    min_interval: 0.15,
    dns_timeout: 3,
    dns_lifetime: 5,
    use_a_fallback: true,
    skip_syntax: false,
    known_blocker_fallback: true,
    auto_retry: true,
};

function readEngineConfig() {
    return {
        ports: $('portsInput').value.trim() || ENGINE_DEFAULTS.ports,
        smtp_timeout: parseFloat($('smtpTimeoutInput').value) || ENGINE_DEFAULTS.smtp_timeout,
        min_interval: parseFloat($('minIntervalInput').value) || ENGINE_DEFAULTS.min_interval,
        dns_timeout: parseFloat($('dnsTimeoutInput').value) || ENGINE_DEFAULTS.dns_timeout,
        dns_lifetime: parseFloat($('dnsLifetimeInput').value) || ENGINE_DEFAULTS.dns_lifetime,
        use_a_fallback: $('useAFallbackCheck').checked ? 1 : 0,
        skip_syntax: $('skipSyntaxCheck').checked ? 1 : 0,
        known_blocker_fallback: $('knownBlockerCheck').checked ? 1 : 0,
        auto_retry: $('autoRetryCheck').checked ? 1 : 0,
    };
}

$('resetConfigBtn').addEventListener('click', function() {
    $('portsInput').value = ENGINE_DEFAULTS.ports;
    $('smtpTimeoutInput').value = ENGINE_DEFAULTS.smtp_timeout;
    $('minIntervalInput').value = ENGINE_DEFAULTS.min_interval;
    $('dnsTimeoutInput').value = ENGINE_DEFAULTS.dns_timeout;
    $('dnsLifetimeInput').value = ENGINE_DEFAULTS.dns_lifetime;
    $('useAFallbackCheck').checked = ENGINE_DEFAULTS.use_a_fallback;
    $('skipSyntaxCheck').checked = ENGINE_DEFAULTS.skip_syntax;
    $('knownBlockerCheck').checked = ENGINE_DEFAULTS.known_blocker_fallback;
    $('autoRetryCheck').checked = ENGINE_DEFAULTS.auto_retry;
});

$('startBtn').addEventListener('click', function() {
    const inputText = $('emailsInput').value.trim();
    const workers = parseInt($('workersInput').value) || 20;
    const catchAll = $('catchAllCheck').checked ? 1 : 0;
    const ec = readEngineConfig();

    if (!inputText) {
        alert('Please paste emails or load email_list.txt first.');
        return;
    }

    // Generate session ID
    currentSessionId = crypto.randomUUID ? crypto.randomUUID() :
        'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });

    // Reset counters
    logEntries = [];
    completedEmails = 0;
    totalEmails = 0;
    ['cValid','cLikely','cCatch','cInvalid','cUndet','cUnknown','cTotal','cTarget'].forEach(id => {
        $(id).textContent = '0';
    });

    // UI state
    this.disabled = true;
    this.style.display = 'none';
    $('cancelBtn').style.display = 'inline';
    $('cancelBtn').disabled = false;
    $('cancelBtn').classList.remove('cancelling');
    $('cancelBtn').textContent = '⏹ Cancel';
    $('loadBtn').disabled = true;
    $('progressSection').classList.add('active');
    $('progressFill').style.width = '0%';
    $('downloadsSection').classList.add('active');
    $('logConsole').innerHTML = '<div class="log-system">🚀 Starting verification engine (workers: ' + workers + ')...</div>';
    $('logCapNotice').style.display = 'none';
    $('statusText').textContent = 'Starting...';
    $('statusText').className = 'progress-status running pulse';

    startSpeedTracker();

    // POST the data to start validation
    const params = new URLSearchParams();
    params.set('workers', workers);
    params.set('catch_all', catchAll);
    params.set('session_id', currentSessionId);
    params.set('data', inputText);
    params.set('ports', ec.ports);
    params.set('smtp_timeout', ec.smtp_timeout);
    params.set('min_interval', ec.min_interval);
    params.set('dns_timeout', ec.dns_timeout);
    params.set('dns_lifetime', ec.dns_lifetime);
    params.set('use_a_fallback', ec.use_a_fallback);
    params.set('skip_syntax', ec.skip_syntax);
    params.set('known_blocker_fallback', ec.known_blocker_fallback);
    params.set('auto_retry', ec.auto_retry);

    // Log the active config so users can see what they picked
    $('logConsole').innerHTML =
        '<div class="log-system">⚙ Engine config: ' +
        'ports=[' + ec.ports + '], timeout=' + ec.smtp_timeout + 's, ' +
        'rate=' + ec.min_interval + 's, dns=' + ec.dns_timeout + '/' + ec.dns_lifetime + 's, ' +
        'A-fallback=' + (ec.use_a_fallback ? 'on' : 'off') + ', ' +
        'skip-syntax=' + (ec.skip_syntax ? 'on' : 'off') + ', ' +
        'blocker-fallback=' + (ec.known_blocker_fallback ? 'on' : 'off') + ', ' +
        'auto-retry=' + (ec.auto_retry ? 'on' : 'off') + '</div>';

    fetch('/sort_emails', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: params.toString()
    }).then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        function processChunk(chunk) {
            buffer += chunk;
            const lines = buffer.split('\\n');
            buffer = lines.pop(); // keep incomplete line

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const d = JSON.parse(line.slice(6));
                        handleEvent(d);
                    } catch {}
                }
            }
        }

        function pump() {
            reader.read().then(({done, value}) => {
                if (done) {
                    // Process remaining buffer
                    if (buffer.startsWith('data: ')) {
                        try {
                            const d = JSON.parse(buffer.slice(6));
                            handleEvent(d);
                        } catch {}
                    }
                    resetUI();
                    return;
                }
                processChunk(decoder.decode(value, {stream: true}));
                pump();
            }).catch(() => {
                resetUI();
                $('statusText').textContent = 'Connection lost';
                $('statusText').className = 'progress-status cancelled';
                addLogEntry('<div class="log-invalid">[Connection closed]</div>');
            });
        }
        pump();
    }).catch(() => {
        resetUI();
        $('statusText').textContent = 'Connection failed';
        $('statusText').className = 'progress-status cancelled';
        addLogEntry('<div class="log-invalid">[Connection failed]</div>');
    });
});

function handleEvent(d) {
    if (d.type === 'progress') {
        totalEmails = d.total || totalEmails;
        completedEmails = d.current;

        const pct = d.percentage;
        $('progressFill').style.width = pct + '%';
        $('progressCounter').textContent = d.current.toLocaleString() + ' / ' + d.total.toLocaleString();
        $('statusText').textContent = 'Validating: ' + d.current.toLocaleString() + ' / ' + d.total.toLocaleString();
        $('cTarget').textContent = d.total.toLocaleString();

        const STATUS_MAP = {
            valid:        { cls: 'log-valid',   icon: '🟢 [VALID]',         counter: 'cValid'   },
            likely_valid: { cls: 'log-likely',  icon: '💚 [LIKELY VALID]',  counter: 'cLikely'  },
            catch_all:    { cls: 'log-catch',   icon: '🟡 [CATCH-ALL]',     counter: 'cCatch'   },
            invalid:      { cls: 'log-invalid', icon: '🔴 [INVALID]',       counter: 'cInvalid' },
            undetermined: { cls: 'log-undet',   icon: '🟠 [UNDETERMINED]',  counter: 'cUndet'   },
        };
        const s = STATUS_MAP[d.status] || { cls: 'log-unknown', icon: '⚪ [UNKNOWN]', counter: 'cUnknown' };

        $(s.counter).textContent = (parseInt($(s.counter).textContent.replace(/,/g,'')) + 1).toLocaleString();
        $('cTotal').textContent = (parseInt($('cTotal').textContent.replace(/,/g,'')) + 1).toLocaleString();

        addLogEntry('<div class="log-entry ' + s.cls + '">' + s.icon + ' ' + d.email + ' — ' + d.details + '</div>');
    }
    else if (d.type === 'dns_prewarm') {
        addLogEntry('<div class="log-system">🔍 Pre-warming DNS cache for ' + d.domains + ' unique domains...</div>');
    }
    else if (d.type === 'dns_done') {
        addLogEntry('<div class="log-system">✅ DNS cache warmed in ' + d.elapsed + 's — starting SMTP probes</div>');
    }
    else if (d.type === 'retry_start') {
        addLogEntry('<div class="log-system">🔄 Auto-retrying ' + d.count + ' undetermined emails...</div>');
    }
    else if (d.type === 'complete' || d.type === 'cancelled') {
        const sm = d.summary || {};
        const isDone = d.type === 'complete';

        $('statusText').textContent = isDone ? '✅ Finished!' : '⏹ Cancelled';
        $('statusText').className = 'progress-status ' + (isDone ? 'finished' : 'cancelled');

        const label = isDone ? '🏆 DONE' : '⏹ CANCELLED';
        addLogEntry(
            '<div class="log-done">' + label + ' — Valid: ' + (sm.valid||0) +
            ' | Likely Valid: ' + (sm.likely_valid||0) +
            ' | Catch-All: ' + (sm.catch_all||0) +
            ' | Invalid: ' + (sm.invalid||0) +
            ' | Undetermined: ' + (sm.undetermined||0) +
            ' | Unknown: ' + (sm.unknown||0) +
            ' | Total: ' + (sm.total||0) + '</div>'
        );
        if (isDone) {
            addLogEntry('<div class="log-system" style="font-size:0.7rem;margin-top:4px">✅ Download files are ready.</div>');
        } else {
            addLogEntry('<div class="log-system" style="font-size:0.7rem;margin-top:4px">Partial results saved to files. You can download what was completed.</div>');
        }

        resetUI();
    }
}

// Auto-load email_list.txt on page open
window.addEventListener('DOMContentLoaded', () => {
    const ta = $('emailsInput');
    if (!ta.value.trim()) {
        fetch('/load_default').then(r => r.text()).then(t => {
            if (t.trim() && !ta.value.trim()) {
                ta.value = t;
                ta.dispatchEvent(new Event('input'));
            }
        }).catch(() => {});
    }
});
</script>
</body>
</html>"""


# =============================================================
# Flask routes
# =============================================================
@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/load_default")
def load_default():
    """Return the contents of email_list.txt for the UI to pre-load."""
    try:
        with open("email_list.txt", "r", encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/plain")
    except Exception:
        return Response("", mimetype="text/plain")


@app.route("/download/<filename>")
def download_file(filename):
    """Serve one of the result files as a download."""
    allowed = {"actual_email.txt", "wrong_email.txt", "checked_email.txt", "undetermined_email.txt"}
    if filename not in allowed:
        return "File not allowed", 400
    try:
        return send_from_directory(directory=".", path=filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found — run a validation first.", 404


@app.route("/cancel", methods=["POST"])
def cancel_validation():
    """Cancel a running validation session."""
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "")
    if not session_id:
        return jsonify({"error": "No session_id provided"}), 400

    with _cancel_lock:
        evt = _cancel_events.get(session_id)
        if evt:
            evt.set()
            return jsonify({"status": "cancelling", "session_id": session_id})

    return jsonify({"status": "not_found", "session_id": session_id}), 404


@app.route("/sort_emails", methods=["GET", "POST"])
def sort_emails():
    """SSE endpoint: stream per-email results as they complete."""
    src = request.form if request.method == "POST" else request.args
    raw_data = src.get("data", "").strip()
    workers = max(1, min(50, int(src.get("workers", "20") or "20")))
    detect_catch = src.get("catch_all", "1") == "1"
    session_id = src.get("session_id", str(uuid.uuid4()))

    # --- User-defined validation engine configuration ---
    def _f(key, default):
        try:
            return float(src.get(key, default))
        except (TypeError, ValueError):
            return default
    def _i(key, default):
        try:
            return int(src.get(key, default))
        except (TypeError, ValueError):
            return default
    def _b(key, default):
        v = src.get(key, "1" if default else "0")
        return v in ("1", "true", "True", "yes", "on")

    cfg = {
        "timeout": _i("smtp_timeout", 10),
        "min_interval": _f("min_interval", DEFAULT_RATE_INTERVAL),
        "ports": _parse_ports(src.get("ports", "25,587")),
        "use_a_fallback": _b("use_a_fallback", True),
        "skip_syntax": _b("skip_syntax", False),
        "known_blocker_fallback": _b("known_blocker_fallback", True),
        "dns_timeout": _f("dns_timeout", DEFAULT_DNS_TIMEOUT),
        "dns_lifetime": _f("dns_lifetime", DEFAULT_DNS_LIFETIME),
        "auto_retry": _b("auto_retry", True),
    }

    # Fall back to email_list.txt if no data was passed
    if not raw_data:
        try:
            with open("email_list.txt", "r", encoding="utf-8") as f:
                raw_data = f.read()
        except FileNotFoundError:
            raw_data = ""

    # Parse and deduplicate email list
    # Supports plain addresses, "email:password" and "email,other" formats
    seen, emails = set(), []
    for line in raw_data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addr = line.split(":", 1)[0].strip()
        if "@" not in addr:
            addr = line.split(",", 1)[0].strip()
        key = addr.lower()
        if addr and key not in seen:
            seen.add(key)
            emails.append(addr)

    total = len(emails)

    # Register cancel event for this session
    cancel_event = threading.Event()
    with _cancel_lock:
        _cancel_events[session_id] = cancel_event

    # Clear output files before the run
    for fname in ("actual_email.txt", "wrong_email.txt", "checked_email.txt", "undetermined_email.txt"):
        open(fname, "w", encoding="utf-8").close()

    def generate():
        counts = {k: 0 for k in ("valid", "likely_valid", "catch_all", "invalid", "undetermined", "unknown")}

        def ui_status(raw: str, detail: str) -> tuple[str, str]:
            """Map internal status codes to UI display statuses."""
            if raw == "valid":
                return "valid", detail
            if raw == "likely_valid":
                return "likely_valid", detail
            if raw == "catch_all":
                return "catch_all", detail
            if raw == "invalid":
                return "invalid", detail
            if raw == "undetermined":
                return "undetermined", detail
            return "unknown", detail

        def write_result(email: str, raw: str, detail: str):
            with _file_lock:
                if raw in ("valid", "likely_valid", "catch_all"):
                    fname = "actual_email.txt"
                elif raw == "invalid":
                    fname = "wrong_email.txt"
                elif raw == "undetermined":
                    fname = "undetermined_email.txt"
                else:
                    fname = None

                if fname:
                    with open(fname, "a", encoding="utf-8") as f:
                        f.write(email + "\n")

                # Full audit log always
                with open("checked_email.txt", "a", encoding="utf-8") as f:
                    f.write(f"{email} => {raw}: {detail}\n")

        if total == 0:
            yield f"data: {json.dumps({'type': 'complete', 'summary': {k: 0 for k in counts}})}\n\n"
            return

        # Pre-warm DNS cache
        all_domains = list({e.rsplit("@", 1)[-1].lower() for e in emails if "@" in e})
        yield f"data: {json.dumps({'type': 'dns_prewarm', 'domains': len(all_domains)})}\n\n"

        dns_start = time.time()
        prewarm_mx_cache(all_domains, max_workers=min(30, len(all_domains)),
                          use_a_fallback=cfg["use_a_fallback"],
                          dns_timeout=cfg["dns_timeout"],
                          dns_lifetime=cfg["dns_lifetime"])
        dns_elapsed = round(time.time() - dns_start, 1)
        yield f"data: {json.dumps({'type': 'dns_done', 'elapsed': dns_elapsed, 'config': cfg})}\n\n"

        if cancel_event.is_set():
            yield f"data: {json.dumps({'type': 'cancelled', 'summary': {**counts, 'total': 0}})}\n\n"
            return

        def task(email):
            return email, *verify_email(email, detect_catch_all=detect_catch, cfg=cfg)

        completed = 0
        undetermined_emails = []

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ev") as pool:
            futures = {}
            # Submit all emails
            for e in emails:
                if cancel_event.is_set():
                    break
                futures[pool.submit(task, e)] = e

            for future in as_completed(futures):
                if cancel_event.is_set():
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

                try:
                    email, raw, detail = future.result()
                except Exception as exc:
                    email = futures[future]
                    raw, detail = "unknown", f"Worker exception: {str(exc)[:60]}"

                display, ui_detail = ui_status(raw, detail)
                counts[display] = counts.get(display, 0) + 1
                completed += 1
                write_result(email, raw, detail)

                # Track undetermined for retry
                if raw == "undetermined":
                    undetermined_emails.append(email)

                payload = {
                    "type": "progress",
                    "current": completed,
                    "total": total,
                    "percentage": int(completed / total * 100),
                    "email": email,
                    "status": display,
                    "details": ui_detail,
                }
                yield f"data: {json.dumps(payload)}\n\n"

        # Check if cancelled
        if cancel_event.is_set():
            yield f"data: {json.dumps({'type': 'cancelled', 'summary': {**counts, 'total': completed}})}\n\n"
        else:
            # Auto-retry undetermined emails (one pass) — only if user enabled it
            if cfg.get("auto_retry", True) and undetermined_emails and not cancel_event.is_set():
                yield f"data: {json.dumps({'type': 'retry_start', 'count': len(undetermined_emails)})}\n\n"

                # Remove undetermined emails from output file before retry
                with _file_lock:
                    try:
                        with open("undetermined_email.txt", "r", encoding="utf-8") as f:
                            existing = set(f.read().strip().splitlines())
                        retry_set = set(undetermined_emails)
                        remaining_undet = existing - retry_set
                        with open("undetermined_email.txt", "w", encoding="utf-8") as f:
                            for e in remaining_undet:
                                f.write(e + "\n")
                    except Exception:
                        pass

                # Retry with the same config
                def retry_task(email):
                    return email, *verify_email(email, detect_catch_all=detect_catch, cfg=cfg)

                retry_completed = 0
                with ThreadPoolExecutor(max_workers=min(workers, len(undetermined_emails)), thread_name_prefix="retry") as pool:
                    retry_futures = {pool.submit(retry_task, e): e for e in undetermined_emails}
                    for future in as_completed(retry_futures):
                        if cancel_event.is_set():
                            for f in retry_futures:
                                f.cancel()
                            break

                        try:
                            email, raw, detail = future.result()
                        except Exception as exc:
                            email = retry_futures[future]
                            raw, detail = "unknown", f"Retry exception: {str(exc)[:60]}"

                        # Only update if result changed from undetermined
                        if raw != "undetermined":
                            # Adjust counts
                            counts["undetermined"] = max(0, counts["undetermined"] - 1)
                            display, ui_detail = ui_status(raw, detail)
                            counts[display] = counts.get(display, 0) + 1
                            write_result(email, raw, f"[RETRY] {detail}")

                            retry_completed += 1
                            payload = {
                                "type": "progress",
                                "current": completed + retry_completed,
                                "total": total,
                                "percentage": int(completed / total * 100),
                                "email": email,
                                "status": display,
                                "details": f"[RETRY] {ui_detail}",
                            }
                            yield f"data: {json.dumps(payload)}\n\n"
                        else:
                            # Still undetermined, re-write to file
                            with _file_lock:
                                with open("undetermined_email.txt", "a", encoding="utf-8") as f:
                                    f.write(email + "\n")
                                with open("checked_email.txt", "a", encoding="utf-8") as f:
                                    f.write(f"{email} => {raw}: [RETRY] {detail}\n")

            yield f"data: {json.dumps({'type': 'complete', 'summary': {**counts, 'total': total}})}\n\n"

        # Cleanup cancel event
        with _cancel_lock:
            _cancel_events.pop(session_id, None)

    return Response(generate(), mimetype="text/event-stream")


# =============================================================
# Entry point
# =============================================================
if __name__ == "__main__":
    print("Email Validator running at http://127.0.0.1:5051")
    app.run(debug=True, port=5051)