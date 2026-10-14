# Email Threat Detection and Forensic Intelligence

## Unified risk assessment and text report

`email_analyzer.analyze_email_message(raw_email)` returns the existing ML and
forensic fields and additionally provides `header_fields`, `risk_assessment`,
and a plain-text `forensic_report`. Reports are returned to the caller; they
are not saved automatically.

`risk_assessment.build_risk_assessment(analysis_result)` uses transparent,
non-probabilistic rules:

- A spam prediction alone is **Medium** priority: it is a review signal, not
  proof of fraud.
- A single distinct warning category is **Medium**. Two or more independent
  signal categories across the classifier and warnings are **High** priority
  for manual review (for example, a spam prediction plus a distinct URL warning).
- Header and local threat findings that describe the same sender-domain
  mismatch are counted once to avoid double-counting.
- Missing/unavailable model output or missing required finding lists produces
  **Inconclusive** when there is not enough core data to assess the message.
- Otherwise, no configured warning is **Low** priority, not a guarantee that
  the message is safe.
- Missing authentication results do not raise priority by themselves.
- Private, loopback, and other non-public IPs are not treated as public attacker
  locations. IP geolocation and live domain reputation remain unconfigured.

`forensic_report.format_forensic_report(assessment)` creates a deterministic
plain-text summary of the assessment. It displays controlled finding
identifiers and validated IP lookup statuses, not raw email, body text, or
arbitrary finding evidence.

These rules are review-priority heuristics, not calibrated risk scores. The
SpamAssassin model addresses spam-versus-ham classification only. The system
does not currently verify phishing, business email compromise, impersonation,
domain reputation, or physical location.

## Local prototype API

FastAPI and Uvicorn must be available in the selected Python environment. Start
the API from the project directory with:

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

The API binds to the local machine by default; it is not configured for
internet-facing use.

Endpoints:

- `GET /` reports the project name and that the API process is running.
- `GET /health` reports whether the model exists and loads, whether the
  analysis modules are available, and whether live providers are configured.
- `POST /analyze` accepts a JSON object with one non-empty `raw_email` string,
up to 1 MiB of UTF-8 email text. It returns the existing model prediction,
header findings, IP lookup status, local threat indicators, risk assessment,
and readable forensic report. Its structured evidence fields include
`sender_addresses`, `authentication_checks`, and `detected_urls`, in addition
to the existing findings and provider statuses. Raw message headers and body
are not returned as fields in the API response.

Example request using synthetic data:

```powershell
$body = @{
  raw_email = "From: Alex <alex@example.test>`nSubject: Meeting notes`nContent-Type: text/plain`n`nSynthetic project update."
} | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/analyze -Method Post -ContentType "application/json" -Body $body
```

Run all existing and API tests from the project directory:

```powershell
python -m unittest -v test_header_analyzer test_saved_model test_email_analyzer test_ip_geolocation test_threat_intelligence test_risk_assessment test_forensic_report test_api
```

This is a local prototype, not a production email-security service. It does
not authenticate clients, comprehensively detect phishing, business email
compromise, or impersonation, or perform live IP geolocation or threat
reputation checks. Submitted email content is analyzed in memory only by this
API; it is not stored or sent to external providers. Do not expose this
unauthenticated prototype to an untrusted network.

## Local browser dashboard

The dashboard uses only HTML, CSS, and vanilla JavaScript and does not save
submitted message content in browser storage. Use two PowerShell windows.

**Window 1 — start the backend** from the project directory:

```powershell
Set-Location 'C:\Users\ADMIN\Desktop\EMAIL'
& 'C:\Users\ADMIN\AppData\Local\Programs\Python\Python313\python.exe' -m uvicorn api:app --host 127.0.0.1 --port 8000
```

**Window 2 — serve the frontend** from the same project directory:

```powershell
Set-Location 'C:\Users\ADMIN\Desktop\EMAIL'
& 'C:\Users\ADMIN\AppData\Local\Programs\Python\Python313\python.exe' -m http.server 5500 --bind 127.0.0.1 --directory frontend
```

Open <http://127.0.0.1:5500> in a browser. `api.py` allows browser requests
only from `http://127.0.0.1:5500` for `GET` and `POST` (plus the required
preflight handling), with no credentials. If you change the frontend origin or
port, update the single exact origin in `api.py`; do not replace it with an
unrestricted wildcard. The dashboard sends email text only to the configured
local backend at `http://127.0.0.1:8000`.

For a manual smoke test, paste synthetic content such as:

```text
From: Alex <alex@example.test>
Subject: Synthetic project update
Content-Type: text/plain; charset=utf-8

This is a synthetic message for testing the local dashboard.
```

Use **Analyze email** to view the returned classification, evidence and report.
The dashboard never opens extracted URLs. **Clear results** removes the pasted
text from the page and clears the displayed analysis. Stop each local server
with `Ctrl+C` in its PowerShell window.
