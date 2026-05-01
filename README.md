# Tee Times Inspector

Safe browser-based diagnostics for golf tee-time booking sites.

The inspector helps decide whether a booking site can be automated with direct HTTP requests, needs browser automation, or needs a hybrid approach. It launches a local browser, lets the user log in manually, records booking-related network traffic, redacts sensitive values, and writes JSON/Markdown reports that can be uploaded to Tee Times course requests.

## Safety

Do not commit credentials, browser sessions, traces, screenshots, or unreviewed HTML.

The inspector does not make a booking by itself. You drive the browser manually. Its optional final guard can intercept and abort a likely final booking request so the request shape can be captured without completing the booking.

Generated reports redact passwords, cookies, auth headers, tokens, member/player/user fields, and form values. Still review reports before sharing them.

## Setup

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

## Run

Open a blank browser and navigate manually:

```bash
python inspect_booking_flow.py
```

For a repeat run, optionally pass a start, login, or booking URL:

```bash
python inspect_booking_flow.py \
  --start-url "https://example-club.example" \
  --login-url "https://example-club.example/login" \
  --booking-url "https://example-club.example/memberbooking/"
```

If the site does not have a separate consent URL, pass `--consent-url ""`.

## What To Do

1. Browse to the club booking site and log in in the opened browser.
2. Press Enter in the terminal.
3. Confirm the real booking page is visible, then press Enter again.
4. In the browser, select date, time, players, and any required options until just before final confirmation.
5. Press Enter in the terminal to arm the final guard.
6. Click the final booking/confirm button in the browser.
7. Press Enter to finish and write the reports.

Reports are written to:

```text
diagnostics/YYYYMMDD-HHMMSS/booking_network_report.json
diagnostics/YYYYMMDD-HHMMSS/booking_network_report.md
```

Upload or paste the JSON/Markdown report into the Tee Times Course Requests page.

## Useful Options

Start with a fresh login:

```bash
python inspect_booking_flow.py --fresh
```

Skip final request interception:

```bash
python inspect_booking_flow.py --no-final-guard
```

Save final page HTML:

```bash
python inspect_booking_flow.py --save-html
```

Only use `--save-html` if you will review the HTML before sharing it.

Save a Playwright trace:

```bash
python inspect_booking_flow.py --trace
```

Traces can include screenshots and personal details. Review before sharing.
