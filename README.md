# 📧 Best Real Email Validator

A modern, local web-based email validation tool that performs **real** mailbox verification using DNS MX records + direct SMTP handshake (no emails are ever sent).

Unlike basic syntax checkers, this tool actually connects to mail servers to determine if an address is deliverable.

---

## ✨ Features

- **Real SMTP Verification** — DNS MX lookup + RCPT TO handshake (the gold standard)
- **User-Configurable Engine** — Every probe knob (ports, timeout, rate-limit, DNS, catch-all, retry) is exposed in the UI before you start
- **Catch-All Detection** — Optional probe to identify domains that accept mail for any address (greatly improves accuracy)
- **Parallel Processing** — Configurable 1–50 concurrent workers with live progress
- **Smart Rate Limiting** — Per-domain throttling to reduce blocks and bans
- **Cooperative Cancellation** — Stop a running validation at any time via the **⏹ Cancel** button
- **Auto Setup** — `run.bat` automatically creates a venv and installs dependencies on first run (works on fresh PCs)
- **Beautiful Live UI** — Real-time logging, stats counters, speed/ETA tracker, and one-click downloads
- **Robust Output** — Clean result files with detailed reasons for every email

---

## 🚀 Quick Start (Recommended for Windows)

1. **Double-click `run.bat`**

   The script will:
   - Detect Python
   - Create a local `.venv` virtual environment (if missing)
   - Auto-install all dependencies from `requirements.txt`
   - Open your browser at `http://127.0.0.1:5051`

2. Paste emails or click **📂 Load email_list.txt**
3. Adjust **Parallel Workers** (1–50)
4. (Optional) Enable/disable catch-all detection
5. (Optional) Open **🔧 Validation Engine** to fine-tune SMTP ports, timeout, rate-limit, DNS, retry, and more
6. Click **▶ Start Validation** (use **⏹ Cancel** any time to stop)

That's it!

### Manual Start

```bash
python app.py
```

Then open http://127.0.0.1:5051 in your browser.

---

## 📦 Requirements

- Python 3.9 or newer
- Internet connection (required for DNS + SMTP checks)
- Outbound port 25 access (many ISPs and corporate networks block this)

Install dependencies manually if needed:

```bash
pip install -r requirements.txt
```

---

## 🛠️ How It Works

1. **Syntax Check** — Uses the professional `email-validator` library (can be skipped via config)
2. **MX Lookup** — Finds the mail server for the domain (with A-record fallback + caching; both are toggleable)
3. **Rate Limiting** — Enforces a per-domain delay (configurable, default ~150ms)
4. **SMTP Handshake** — Connects and issues `MAIL FROM` + `RCPT TO` on each port in your list (default `25`, `587`)
5. **Catch-All Probe** (optional) — Sends a clearly bogus address to detect catch-all domains
6. **Auto-Retry** (optional) — One extra pass for emails that came back as `undetermined`
7. **Cancellation** — A `threading.Event` flips when the user hits Cancel; the worker pool breaks the loop and cancels pending futures

Results are streamed live to the browser via Server-Sent Events (SSE).

---

## 📁 Output Files

After validation, four files are created/updated in the project folder:

| File                      | Contents                                      | Contains |
|---------------------------|-----------------------------------------------|----------|
| `actual_email.txt`        | Confirmed deliverable addresses               | Valid + Likely-valid + Catch-all |
| `wrong_email.txt`         | Invalid / non-existent / rejected             | Invalid + Unknown |
| `undetermined_email.txt`  | Could not be confirmed (transient / blocked)  | Undetermined |
| `checked_email.txt`       | Full audit log with status and reason         | All emails + details |

**Tip:** Use the **📥 Download** buttons in the UI for one-click downloads. Files update live during a run.

---

## ⚙️ Configuration in UI

### Basic
- **Parallel Workers (1–50)**  
  Higher = faster on diverse domain lists.  
  Lower = safer, especially on Gmail/Outlook-heavy lists.

- **Detect catch-all domains** (recommended)  
  Performs an extra probe per domain. Slightly slower but much more accurate.

### 🔧 Validation Engine (advanced)

Click **🔧 Validation Engine** in the UI to expose every engine knob. Defaults are restored with **↺ Reset to Defaults**.

| Field | Default | Effect |
|---|---|---|
| **SMTP Ports** | `25,587` | Comma-separated list of ports to try in order (allowed: 25, 465, 587, 2525) |
| **SMTP Timeout (sec)** | `10` | Per-probe connection timeout |
| **Per-Domain Rate Limit (sec)** | `0.15` | Min seconds between two probes to the same domain |
| **DNS Timeout (sec)** | `3` | `dns.resolver.Resolver.timeout` |
| **DNS Lifetime (sec)** | `5` | `dns.resolver.Resolver.lifetime` |
| **Fall back to A-record if no MX** | ✅ on | Treat the domain itself as its mail server when no MX exists |
| **Skip syntax check** | ⬜ off | Trust input; skip the `email-validator` library check |
| **Mark probe-blocking providers as likely_valid** | ✅ on | Gmail/Outlook/etc. → assume valid when probes are blocked |
| **Auto-retry undetermined emails** | ✅ on | Run a second pass for transient failures |

The active config is logged to the live console on Start, e.g.:

```
⚙ Engine config: ports=[25,587], timeout=10s, rate=0.15s, dns=3/5s,
   A-fallback=on, skip-syntax=off, blocker-fallback=on, auto-retry=on
```

---

## ⚠️ Important Limitations & Notes

- Many large providers (Gmail, Outlook, Yahoo, etc.) apply heavy rate limiting or privacy protections. You may see `connection_error`, `timeout`, or `mailbox_invalid` even for some real addresses.
- Residential ISPs often block outbound port 25. Use a VPS or server with clean SMTP access for best results.
- This tool is for **legitimate** use only (your own lists, permission-based validation, etc.).
- High worker counts increase the chance of temporary IP-based blocks.
- Catch-all domains are inherently uncertain — the tool flags them clearly.

---

## 🖥️ Project Structure

```
email-validator/
├── app.py                  # Main Flask application + UI
├── run.bat                 # One-click Windows launcher (auto venv + install)
├── requirements.txt        # Python dependencies
├── email_list.txt          # Sample input file
├── actual_email.txt        # Generated: valid + likely-valid + catch-all
├── wrong_email.txt         # Generated: invalid + unknown
├── undetermined_email.txt  # Generated: undetermined
├── checked_email.txt       # Generated: full audit log
└── README.md               # This file
```

---

## 💡 Tips for Best Results

- Start with 4–6 workers
- Use diverse domain lists when possible
- Keep catch-all detection enabled for accuracy
- If you see lots of timeouts on port 25, raise the **Per-Domain Rate Limit** or add `587` to **SMTP Ports**
- Re-run problematic domains later (temporary blocks often clear)
- Check `checked_email.txt` for detailed SMTP response codes

---

## 📜 License

This is a personal/local tool. Use responsibly.

---

**Built with Flask + dnspython + email-validator**

Run it, validate your lists, and enjoy fast, honest results. 🚀

If you need to change the maximum workers, rate limit interval, or add other features, the code is well-commented and most tunables are exposed in the **🔧 Validation Engine** panel.