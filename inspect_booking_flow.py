"""
Safely inspect a golf tee-time member-booking flow.

This script launches a real browser, lets you log in locally, records the
network requests and form fields used by the booking flow, and writes a
redacted report that can be shared without exposing passwords, cookies, CSRF
tokens, or member details.

It does NOT make a booking by itself. You drive the browser manually.

Typical use:
    python inspect_booking_flow.py

Then follow the terminal prompts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    from playwright.sync_api import BrowserContext, Page, Request, Response, Route, sync_playwright
except ImportError as exc:  # pragma: no cover - useful local error message
    raise SystemExit(
        "Playwright is not installed. Run:\n"
        "  python -m pip install -r requirements.txt\n"
        "  python -m playwright install chromium\n"
    ) from exc

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

DEFAULT_START_URL = "about:blank"
BOOKING_KEYWORDS = (
    "book",
    "booking",
    "teetime",
    "tee_time",
    "tee-time",
    "reserve",
    "reservation",
    "basket",
    "confirm",
    "checkout",
    "payment",
    "slot",
    "starttime",
)
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|pass|token|csrf|xsrf|auth|authori[sz]ation|cookie|session|sid|secret|key|login|email|e-mail|mail|member|player|user|username|name|phone|mobile|address|postcode|zip|dob|birth|card|payment)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_RE = re.compile(
    r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b\d{10,}\b|bearer\s+[a-z0-9._~+/=-]+)",
    re.IGNORECASE,
)
TEXTUAL_CONTENT_RE = re.compile(r"(json|text|javascript|xml|html|x-www-form-urlencoded)", re.IGNORECASE)
TRACKING_HOST_RE = re.compile(
    r"(^|\.)(google-analytics\.com|googletagmanager\.com|googleadservices\.com|doubleclick\.net)$",
    re.IGNORECASE,
)
BOOKING_QUERY_KEYS = {"book", "booking", "teetime", "tee_time", "starttime", "time", "date", "course", "group", "numslots", "edit", "newbooking"}



def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def value_shape(value: Any) -> Any:
    """Return useful shape metadata without returning the original value."""
    if value is None:
        return {"kind": "null"}
    if isinstance(value, bool):
        return {"kind": "bool"}
    if isinstance(value, int):
        return {"kind": "int", "digits": len(str(abs(value)))}
    if isinstance(value, float):
        return {"kind": "float"}
    if isinstance(value, list):
        return {"kind": "list", "length": len(value), "items": [value_shape(v) for v in value[:5]]}
    if isinstance(value, dict):
        return {"kind": "object", "keys": sorted(str(k) for k in value.keys())}

    text = str(value)
    hints: list[str] = []
    if re.fullmatch(r"\d{1,2}:\d{2}(:\d{2})?", text):
        hints.append("time-like")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) or re.fullmatch(r"\d{1,2}/\d{1,2}/\d{2,4}", text):
        hints.append("date-like")
    if text.isdigit():
        hints.append("numeric-string")
    if len(text) > 40:
        hints.append("long")

    return {"kind": "string", "length": len(text), "empty": text == "", "hints": hints}


def redact_value(value: Any, *, keep_shapes: bool = True) -> Any:
    if keep_shapes:
        return value_shape(value)
    if value is None:
        return None
    text = str(value)
    if SENSITIVE_VALUE_RE.search(text):
        return "<redacted>"
    if len(text) > 120:
        return f"<redacted long value len={len(text)}>"
    return text


def redact_by_key(key: str, value: Any, *, keep_shapes: bool = True) -> Any:
    if SENSITIVE_KEY_RE.search(str(key)):
        return value_shape(value) | {"redacted_reason": "sensitive_key"}
    return redact_value(value, keep_shapes=keep_shapes)


def redact_mapping(mapping: dict[str, Any], *, keep_shapes: bool = True) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in mapping.items():
        key_str = str(key)
        if isinstance(value, dict):
            redacted[key_str] = {k: redact_by_key(k, v, keep_shapes=keep_shapes) for k, v in value.items()}
        elif isinstance(value, list):
            redacted[key_str] = [redact_by_key(key_str, v, keep_shapes=keep_shapes) for v in value[:20]]
            if len(value) > 20:
                redacted[key_str].append(f"<truncated {len(value) - 20} more items>")
        else:
            redacted[key_str] = redact_by_key(key_str, value, keep_shapes=keep_shapes)
    return redacted


def redact_headers(headers: dict[str, str]) -> dict[str, Any]:
    return redact_mapping(dict(headers), keep_shapes=True)


def parse_query_parameters(url: str, *, keep_shapes: bool = True) -> dict[str, Any]:
    """Return query parameters in a readable, redacted structure."""
    parsed = urlparse(url)
    if not parsed.query:
        return {}
    params = parse_qs(parsed.query, keep_blank_values=True)
    result: dict[str, Any] = {}
    for key, values in params.items():
        value: Any = values if len(values) > 1 else values[0]
        result[str(key)] = redact_by_key(str(key), value, keep_shapes=keep_shapes)
    return result


def host_is_tracking(url: str) -> bool:
    host = urlparse(url).netloc.lower().split(":", 1)[0]
    return bool(TRACKING_HOST_RE.search(host))


def query_has_booking_keys(url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.query:
        return False
    keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True).keys()}
    return bool(keys & BOOKING_QUERY_KEYS)


def redact_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url
    params = parse_qs(parsed.query, keep_blank_values=True)
    safe_params: dict[str, list[str]] = {}
    for key, values in params.items():
        safe_params[key] = [json.dumps(redact_by_key(key, value, keep_shapes=True), sort_keys=True) for value in values]
    return urlunparse(parsed._replace(query=urlencode(safe_params, doseq=True)))


def parse_and_redact_body(post_data: str | None) -> Any:
    if not post_data:
        return None

    stripped = post_data.strip()
    if not stripped:
        return None

    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return {"type": "json", "fields": redact_mapping(data, keep_shapes=True)}
        return {"type": "json", "shape": value_shape(data)}
    except Exception:
        pass

    parsed = parse_qs(post_data, keep_blank_values=True)
    if parsed:
        flattened: dict[str, Any] = {}
        for key, values in parsed.items():
            flattened[key] = values if len(values) > 1 else values[0]
        return {"type": "form", "fields": redact_mapping(flattened, keep_shapes=True)}

    return {"type": "raw", "shape": value_shape(post_data)}


def has_booking_keywords(text: str | None) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(keyword in lowered for keyword in BOOKING_KEYWORDS)


def is_same_domain_or_interesting(url: str, domain: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if not domain:
        return parsed.scheme in {"http", "https"} or has_booking_keywords(url)
    return host == domain.lower() or host.endswith("." + domain.lower()) or has_booking_keywords(url)


def request_summary(request: Request, *, domain: str, include_external: bool = False) -> dict[str, Any] | None:
    url = request.url
    post_data = request.post_data
    same_domain = is_same_domain_or_interesting(url, domain)

    # By default, keep the report focused on the club site. Analytics POSTs
    # are noisy and previously confused the "likely booking" detector.
    if not include_external and not same_domain:
        return None
    if not same_domain and request.method == "GET":
        return None

    return {
        "timestamp_utc": utc_now_iso(),
        "method": request.method,
        "url": redact_url(url),
        "url_path": urlparse(url).path,
        "query_parameters": parse_query_parameters(url),
        "resource_type": request.resource_type,
        "headers": redact_headers(request.headers),
        "post_data": parse_and_redact_body(post_data),
        "interesting": {
            "same_domain_or_booking_keyword": same_domain,
            "non_get": request.method.upper() != "GET",
            "url_has_booking_keyword": has_booking_keywords(url),
            "query_has_booking_keys": query_has_booking_keys(url),
            "body_has_booking_keyword": has_booking_keywords(post_data),
            "tracking_host": host_is_tracking(url),
        },
    }


def response_summary(response: Response, *, domain: str, include_external: bool = False) -> dict[str, Any] | None:
    request = response.request
    same_domain = is_same_domain_or_interesting(response.url, domain)
    if not include_external and not same_domain:
        return None
    if not same_domain and request.method == "GET":
        return None
    headers = response.headers
    return {
        "timestamp_utc": utc_now_iso(),
        "status": response.status,
        "method": request.method,
        "url": redact_url(response.url),
        "url_path": urlparse(response.url).path,
        "query_parameters": parse_query_parameters(response.url),
        "content_type": headers.get("content-type", ""),
        "headers": redact_headers(headers),
    }


def risky_final_request(request: Request, *, domain: str) -> bool:
    if host_is_tracking(request.url):
        return False

    parsed = urlparse(request.url)
    same_domain = (
        parsed.scheme in {"http", "https"}
        if not domain
        else parsed.netloc.lower() == domain.lower() or parsed.netloc.lower().endswith("." + domain.lower())
    )
    if not same_domain:
        return False

    # Some booking sites create/edit a booking via a GET navigation with
    # booking-like query parameters, not only via POST.
    if request.method.upper() == "GET" and query_has_booking_keys(request.url):
        query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True).keys()}
        if "book" in query_keys or "newbooking" in query_keys or "edit" in query_keys:
            return True

    method = request.method.upper()
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        text = f"{request.url}\n{request.post_data or ''}".lower()
        return any(keyword in text for keyword in BOOKING_KEYWORDS) or query_has_booking_keys(request.url)

    return False


def wait_for_enter(page: Page, prompt: str) -> None:
    """Wait for Enter while still pumping Playwright events."""
    done = threading.Event()

    def _reader() -> None:
        try:
            input(prompt)
        finally:
            done.set()

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()
    while not done.is_set():
        page.wait_for_timeout(250)


def collect_forms(page: Page) -> list[dict[str, Any]]:
    script = """
    () => Array.from(document.forms).map((form, formIndex) => ({
      formIndex,
      id: form.id || null,
      name: form.getAttribute('name'),
      method: form.method || null,
      action: form.action || null,
      inputs: Array.from(form.querySelectorAll('input, select, textarea, button')).map((el, inputIndex) => ({
        inputIndex,
        tag: el.tagName.toLowerCase(),
        type: el.getAttribute('type'),
        id: el.id || null,
        name: el.getAttribute('name'),
        ariaLabel: el.getAttribute('aria-label'),
        placeholder: el.getAttribute('placeholder'),
        text: (el.innerText || el.textContent || '').trim().slice(0, 80),
        valueLength: (el.value || '').length,
        hasValue: Boolean(el.value),
        checked: el.checked === true,
        optionCount: el.tagName.toLowerCase() === 'select' ? el.options.length : null,
        optionLabels: el.tagName.toLowerCase() === 'select'
          ? Array.from(el.options).slice(0, 25).map(o => (o.text || '').trim().slice(0, 80))
          : null
      }))
    }))
    """
    try:
        forms = page.evaluate(script)
    except Exception as exc:
        return [{"error": f"Could not collect forms: {exc}"}]

    # Do a final Python-side scrub of any labels/text that might contain PII.
    for form in forms:
        form["action"] = redact_url(form.get("action") or "")
        for item in form.get("inputs", []):
            for text_key in ("ariaLabel", "placeholder", "text"):
                if item.get(text_key) and SENSITIVE_VALUE_RE.search(str(item[text_key])):
                    item[text_key] = "<redacted>"
    return forms


def collect_page_actions(page: Page) -> list[dict[str, Any]]:
    script = """
    () => Array.from(document.querySelectorAll('a[href], button, input[type=button], input[type=submit]')).slice(0, 250).map((el, index) => ({
      index,
      tag: el.tagName.toLowerCase(),
      type: el.getAttribute('type'),
      id: el.id || null,
      name: el.getAttribute('name'),
      text: ((el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '') + '').trim().slice(0, 120),
      href: el.href || null,
      onclick: el.getAttribute('onclick') ? '<present>' : null,
      classes: (el.getAttribute('class') || '').split(/\\s+/).filter(Boolean).slice(0, 12)
    }))
    """
    try:
        actions = page.evaluate(script)
    except Exception as exc:
        return [{"error": f"Could not collect page actions: {exc}"}]

    for item in actions:
        if item.get("href"):
            item["href"] = redact_url(item["href"])
        if item.get("text") and SENSITIVE_VALUE_RE.search(str(item["text"])):
            item["text"] = "<redacted>"
    return actions


def collect_storage_summary(context: BrowserContext, page: Page) -> dict[str, Any]:
    cookies = []
    for cookie in context.cookies():
        cookies.append(
            {
                "name": cookie.get("name"),
                "domain": cookie.get("domain"),
                "path": cookie.get("path"),
                "expires": cookie.get("expires"),
                "httpOnly": cookie.get("httpOnly"),
                "secure": cookie.get("secure"),
                "sameSite": cookie.get("sameSite"),
                "value": value_shape(cookie.get("value")),
            }
        )

    try:
        storage_keys = page.evaluate(
            """
            () => ({
              localStorageKeys: Object.keys(window.localStorage || {}),
              sessionStorageKeys: Object.keys(window.sessionStorage || {})
            })
            """
        )
    except Exception as exc:
        storage_keys = {"error": f"Could not collect storage keys: {exc}"}

    return {"cookies": cookies, "browser_storage_keys": storage_keys}


def write_markdown_report(path: Path, report: dict[str, Any]) -> None:
    likely = report.get("likely_booking_requests", [])
    requests = report.get("requests", [])
    forms = report.get("forms_at_finish", [])
    actions = report.get("actions_at_finish", [])

    lines = [
        "# Booking Flow Inspection Report",
        "",
        f"Generated: `{report.get('generated_at_utc')}` UTC",
        f"Start URL: `{report.get('start_url')}`",
        f"Final URL: `{report.get('final_url')}`",
        "",
        "## What this report contains",
        "",
        "- Request URLs, methods, headers, and payload field names/shapes.",
        "- Response status codes and content types.",
        "- Current page form structure.",
        "- Cookie/storage key names only; values are redacted.",
        "",
        "## Likely booking-related requests",
        "",
    ]

    if not likely:
        lines.append("No obvious booking-related non-GET request was captured.")
    else:
        for index, item in enumerate(likely, 1):
            lines.extend(
                [
                    f"### Candidate {index}",
                    "",
                    f"- Method: `{item.get('method')}`",
                    f"- URL: `{item.get('url')}`",
                    f"- Resource type: `{item.get('resource_type')}`",
                    f"- Payload type: `{(item.get('post_data') or {}).get('type')}`",
                    "",
                    "Query parameters:",
                    "",
                    "```json",
                    json.dumps(item.get("query_parameters") or {}, indent=2, sort_keys=True),
                    "```",
                    "",
                    "Payload fields/shapes:",
                    "",
                    "```json",
                    json.dumps((item.get("post_data") or {}).get("fields", item.get("post_data")), indent=2, sort_keys=True),
                    "```",
                    "",
                ]
            )

    lines.extend(
        [
            "## Captured requests summary",
            "",
            f"Total captured request records: **{len(requests)}**",
            "",
        ]
    )

    for index, item in enumerate(requests[:80], 1):
        method = item.get("method")
        url = item.get("url")
        payload_type = (item.get("post_data") or {}).get("type")
        lines.append(f"{index}. `{method}` `{url}`" + (f" — payload: `{payload_type}`" if payload_type else ""))
    if len(requests) > 80:
        lines.append(f"\n...and {len(requests) - 80} more. See JSON report for the full list.")

    lines.extend(
        [
            "",
            "## Forms visible at finish",
            "",
            "```json",
            json.dumps(forms, indent=2, sort_keys=True),
            "```",
            "",
            "## Actions visible at finish",
            "",
            "```json",
            json.dumps(actions, indent=2, sort_keys=True),
            "```",
            "",
            "## Next step",
            "",
            "Share this Markdown report or the JSON report. Do not share screenshots or Playwright traces unless you have checked them for personal information.",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_report(
    *,
    start_url: str,
    login_url: str,
    consent_url: str,
    booking_url: str,
    final_url: str,
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    intercepted: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    storage: dict[str, Any],
) -> dict[str, Any]:
    likely = []
    for item in requests + intercepted:
        interesting = item.get("interesting", {})
        if interesting.get("tracking_host"):
            continue
        path = str(item.get("url_path") or "")
        is_booking_get = item.get("method") == "GET" and "memberbooking" in path and interesting.get("query_has_booking_keys")
        is_booking_mutation = item.get("method") != "GET" and (
            interesting.get("url_has_booking_keyword")
            or interesting.get("query_has_booking_keys")
            or interesting.get("body_has_booking_keyword")
        )
        if is_booking_get or is_booking_mutation or item.get("intercepted_and_aborted"):
            likely.append(item)

    return {
        "generated_at_utc": utc_now_iso(),
        "start_url": start_url,
        "login_url": login_url,
        "consent_url": consent_url,
        "booking_url": booking_url,
        "final_url": final_url,
        "redaction_notice": "Values for cookies, auth headers, passwords, tokens, member/user/player data, and form payloads are redacted to shapes only.",
        "likely_booking_requests": likely,
        "intercepted_final_booking_requests": intercepted,
        "requests": requests,
        "responses": responses,
        "forms_at_finish": forms,
        "actions_at_finish": actions,
        "storage_summary": storage,
    }


def main() -> int:
    if load_dotenv is not None:
        load_dotenv()
    parser = argparse.ArgumentParser(description="Inspect and redact a tee-time booking flow.")
    parser.add_argument("--start-url", default=os.getenv("START_URL", DEFAULT_START_URL), help="Optional URL to open first. Defaults to a blank tab.")
    parser.add_argument("--login-url", default=os.getenv("LOGIN_URL", ""), help="Optional member login URL to open first.")
    parser.add_argument("--consent-url", default=os.getenv("CONSENT_URL", ""), help="Optional consent acceptance URL to visit after login. Use empty string to skip.")
    parser.add_argument("--booking-url", default=os.getenv("BOOKING_URL", ""), help="Optional member booking URL to open after login/consent.")
    parser.add_argument("--url", dest="legacy_url", default=None, help="Deprecated alias for --booking-url.")
    parser.add_argument("--output-dir", default="diagnostics", help="Directory for reports.")
    parser.add_argument("--storage-state", default=".auth/tee_times_inspector_state.json", help="Saved browser session path.")
    parser.add_argument("--fresh", action="store_true", help="Ignore any saved browser session and log in fresh.")
    parser.add_argument("--headless", action="store_true", help="Run browser headless. Not recommended for first run.")
    parser.add_argument("--no-final-guard", action="store_true", help="Do not offer to intercept the final booking POST.")
    parser.add_argument("--save-html", action="store_true", help="Also save the final page HTML. Review before sharing.")
    parser.add_argument("--trace", action="store_true", help="Save a Playwright trace zip. Review before sharing; traces may contain screenshots.")
    parser.add_argument("--include-external", action="store_true", help="Include external non-GET requests such as analytics in the report.")
    parser.add_argument("--no-block-tracking", action="store_true", help="Do not block analytics/tracking requests while inspecting.")
    args = parser.parse_args()

    login_url = args.login_url
    consent_url = args.consent_url
    booking_url = args.legacy_url or args.booking_url
    start_url = login_url or booking_url or args.start_url
    domain = urlparse(booking_url or login_url or args.start_url).netloc
    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.output_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    storage_state_path = Path(args.storage_state)
    storage_state_path.parent.mkdir(parents=True, exist_ok=True)

    captured_requests: list[dict[str, Any]] = []
    captured_responses: list[dict[str, Any]] = []
    intercepted_final_requests: list[dict[str, Any]] = []
    guard = {"armed": False}

    print("\nBooking flow inspector")
    print("======================")
    print(f"Start URL:   {start_url}")
    print(f"Login URL:   {login_url or '<manual>'}")
    print(f"Consent URL: {consent_url or '<skipped/manual>'}")
    print(f"Booking URL: {booking_url or '<manual>'}")
    print("\nYou will log in and operate the site locally. The report will redact secrets and values.")
    print("Important: do not complete a real booking. The optional final guard can capture and abort a likely final booking request.")
    if not args.no_block_tracking:
        print("Analytics/tracking calls will be blocked so they do not confuse the booking detector.\n")
    else:
        print()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=args.headless, slow_mo=80)
        context_kwargs: dict[str, Any] = {"viewport": {"width": 1400, "height": 1000}}
        if storage_state_path.exists() and not args.fresh:
            context_kwargs["storage_state"] = str(storage_state_path)
            print(f"Using saved browser session: {storage_state_path}")
        context = browser.new_context(**context_kwargs)

        if args.trace:
            context.tracing.start(screenshots=True, snapshots=True, sources=False)

        def handle_route(route: Route) -> None:
            request = route.request
            if not args.no_block_tracking and host_is_tracking(request.url):
                route.abort()
                return
            if guard["armed"] and risky_final_request(request, domain=domain):
                summary = request_summary(request, domain=domain, include_external=args.include_external) or {
                    "timestamp_utc": utc_now_iso(),
                    "method": request.method,
                    "url": redact_url(request.url),
                    "url_path": urlparse(request.url).path,
                    "query_parameters": parse_query_parameters(request.url),
                    "post_data": parse_and_redact_body(request.post_data),
                }
                summary["intercepted_and_aborted"] = True
                intercepted_final_requests.append(summary)
                guard["armed"] = False
                print("\nIntercepted and aborted a likely final booking request. You should see the website report a failed/cancelled request.")
                route.abort()
                return
            route.continue_()

        context.route("**/*", handle_route)

        page = context.new_page()

        def on_request(request: Request) -> None:
            summary = request_summary(request, domain=domain, include_external=args.include_external)
            if summary:
                captured_requests.append(summary)

        def on_response(response: Response) -> None:
            summary = response_summary(response, domain=domain, include_external=args.include_external)
            if summary:
                captured_responses.append(summary)

        page.on("request", on_request)
        page.on("response", on_response)

        if start_url != "about:blank":
            page.goto(start_url, wait_until="domcontentloaded")

        wait_for_enter(
            page,
            "Step 1: browse to the club booking site, log in if needed, then press Enter here... ",
        )
        context.storage_state(path=str(storage_state_path))
        print(f"Saved browser session to: {storage_state_path}")

        if consent_url:
            print(f"Opening consent acceptance URL: {consent_url}")
            page.goto(consent_url, wait_until="domcontentloaded")
            page.wait_for_timeout(1000)

        if booking_url:
            print(f"Opening member booking URL: {booking_url}")
            page.goto(booking_url, wait_until="domcontentloaded")

        wait_for_enter(
            page,
            "Step 1b: browse to or confirm the real member booking page is visible, then press Enter to continue... ",
        )

        wait_for_enter(
            page,
            "Step 2: in the browser, navigate/select date/players until you are just BEFORE final confirmation, then press Enter here... ",
        )

        if not args.no_final_guard:
            print("\nFinal guard is ready. After you press Enter, click the final Book/Confirm button in the browser.")
            print("The script will abort the first likely booking POST it sees, while recording the redacted payload shape.")
            wait_for_enter(page, "Press Enter to ARM the final guard, then click the final confirmation button in the browser... ")
            guard["armed"] = True
            # Keep pumping events long enough for the user to click and for the request to be intercepted.
            deadline = time.time() + 45
            while time.time() < deadline and guard["armed"]:
                page.wait_for_timeout(250)
            if guard["armed"]:
                guard["armed"] = False
                print("No likely final booking POST was intercepted during the guard window.")

        wait_for_enter(page, "Step 3: press Enter to finish and write the report... ")

        forms = collect_forms(page)
        actions = collect_page_actions(page)
        storage = collect_storage_summary(context, page)
        final_url = page.url

        if args.save_html:
            html_path = out_dir / "final_page.html"
            html_path.write_text(page.content(), encoding="utf-8")
            print(f"Saved final page HTML to: {html_path} — review before sharing.")

        if args.trace:
            trace_path = out_dir / "playwright_trace.zip"
            context.tracing.stop(path=str(trace_path))
            print(f"Saved Playwright trace to: {trace_path} — review before sharing.")

        report = build_report(
            start_url=start_url,
            login_url=login_url,
            consent_url=consent_url,
            booking_url=booking_url or page.url,
            final_url=final_url,
            requests=captured_requests,
            responses=captured_responses,
            intercepted=intercepted_final_requests,
            forms=forms,
            actions=actions,
            storage=storage,
        )

        json_path = out_dir / "booking_network_report.json"
        md_path = out_dir / "booking_network_report.md"
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        write_markdown_report(md_path, report)

        print("\nDone. Reports written:")
        print(f"  {json_path}")
        print(f"  {md_path}")
        print("\nShare the Markdown or JSON report back here. Avoid sharing trace/html unless you have reviewed them.")

        context.close()
        browser.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
