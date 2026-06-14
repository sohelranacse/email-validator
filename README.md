# 📧 Best Real Email Validator

A modern, local web-based email validation tool that performs **real** mailbox verification using DNS MX records + direct SMTP handshake (no emails are ever sent).

Unlike basic syntax checkers, this tool actually connects to mail servers to determine if an address is deliverable.

---

## ✨ Features

- **Real SMTP Verification** — DNS MX lookup + RCPT TO handshake (the gold standard)
- **Catch-All Detection** — Optional probe to identify domains that accept mail for any address (greatly improves accuracy)
- **Parallel Processing** — Configurable 3–10 concurrent workers with live progress
- **Smart Rate Limiting** — Per-domain throttling to reduce blocks and bans
- **Auto Setup** — `run.bat` automatically creates a venv and installs dependencies on first run (works on fresh PCs)
- **Beautiful Live UI** — Real-time logging, stats counters, and one-click downloads
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
3. Adjust **Parallel Workers** (3–10) using the slider
4. (Optional) Enable/disable catch-all detection
5. Click **▶ Start Validation**

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

1. **Syntax Check** — Uses the professional `email-validator` library
2. **MX Lookup** — Finds the mail server for the domain (with A-record fallback + caching)
3. **Rate Limiting** — Enforces ~280ms delay between checks to the same domain
4. **SMTP Handshake** — Connects and issues `MAIL FROM` + `RCPT TO`
5. **Catch-All Probe** (optional) — Sends a clearly bogus address to detect catch-all domains

Results are streamed live to the browser via Server-Sent Events (SSE).

---

## 📁 Output Files

After validation, three files are created/updated in the project folder:

| File                  | Contents                                      | Contains |
|-----------------------|-----------------------------------------------|----------|
| `actual_email.txt`    | Confirmed deliverable addresses               | Valid + Catch-all |
| `wrong_email.txt`     | Invalid / non-existent / rejected             | Everything else |
| `checked_email.txt`   | Full audit log with status and reason         | All emails + details |

**Tip:** Use the **📥 Download** buttons in the UI for one-click downloads. Files update live during a run.

---

## ⚙️ Configuration in UI

- **Parallel Workers (3–10)**  
  Higher = faster on diverse domain lists.  
  Lower = safer, especially on Gmail/Outlook-heavy lists.  
  The UI and backend both enforce the 3–10 range.

- **Detect catch-all domains** (recommended)  
  Performs an extra probe per domain. Slightly slower but much more accurate.

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
├── app.py                 # Main Flask application + UI
├── run.bat                # One-click Windows launcher (auto venv + install)
├── requirements.txt       # Python dependencies
├── email_list.txt         # Sample input file
├── actual_email.txt       # Generated: valid addresses
├── wrong_email.txt        # Generated: invalid addresses
├── checked_email.txt      # Generated: full audit log
└── README.md              # This file
```

---

## 💡 Tips for Best Results

- Start with 4–6 workers
- Use diverse domain lists when possible
- Keep catch-all detection enabled for accuracy
- Re-run problematic domains later (temporary blocks often clear)
- Check `checked_email.txt` for detailed SMTP response codes

---

## 📜 License

This is a personal/local tool. Use responsibly.

---

**Built with Flask + dnspython + email-validator**

Run it, validate your lists, and enjoy fast, honest results. 🚀

If you need to change the maximum workers, rate limit interval, or add other features, the code is well-commented.