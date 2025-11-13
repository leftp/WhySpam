
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse
from pathlib import Path
from email import policy
from email.parser import BytesParser
import json, html, time, asyncio, re, socket
from html.parser import HTMLParser

ARCHIVE = Path("/var/mail-archive/json")
RAW_ARCHIVE = Path("/var/mail-archive/raw")
SCREENSHOTS_ARCHIVE = Path("/var/mail-archive/screenshots")
ATTACHMENTS_ARCHIVE = Path("/var/mail-archive/attachments")
FRESH_SKIP_SECONDS = 2.0
MIN_BYTES = 32
MAX_SCAN_FILES = 200
MAX_FILE_SIZE = 256_000
MAX_RULES_DISPLAY = 50
MAX_HEADERS_DISPLAY = 60
MAX_RULE_PREVIEW_LENGTH = 120
TOP_RULES_COUNT = 5

app = FastAPI()

def normalize_item(obj: dict) -> dict:
    if not isinstance(obj, dict):
        return {"subject": "(no subject)", "score": None, "required": None, "is_spam": None, "rules": [], "received_at": None}
    
    sa = obj.get("spamassassin", {})
    legacy_overall = obj.get("overall")
    legacy_rules = obj.get("rules")
    
    meta = obj.get("meta", {})
    headers = obj.get("headers", {})
    subj = meta.get("subject") or headers.get("Subject") or "(no subject)"
    
    rules = []
    score = None
    required = None
    is_spam = None
    
    if sa:
        rules = sa.get("rules", [])
        score = sa.get("score")
        required = sa.get("required")
        is_spam = sa.get("is_spam")
    elif legacy_overall or legacy_rules:
        rules = legacy_rules or []
        legacy_dict = legacy_overall or {}
        score = legacy_dict.get("score")
        required = legacy_dict.get("required")
        is_spam = legacy_dict.get("is_spam")
    
    if (score is None or required is None) and rules:
        try:
            score = round(sum(float(r.get("score", 0)) for r in rules), 2)
        except (ValueError, TypeError):
            pass
        if required is None:
            required = 5.0
        if score is not None:
            is_spam = score >= required
    
    received_at = meta.get("received_at")
    return {"subject": subj, "score": score, "required": required, "is_spam": is_spam, "rules": rules, "received_at": received_at}

def load_reports():
    items=[]
    if not ARCHIVE.exists(): return items
    now=time.time()
    files = sorted(ARCHIVE.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    for p in files:
        try:
            st = p.stat()
            if p.name.startswith(".tmp-"):
                continue
            if st.st_size < MIN_BYTES:
                continue
            if (now - st.st_mtime) < FRESH_SKIP_SECONDS:
                continue
            with p.open("r", encoding="utf-8") as f:
                obj = json.load(f)
            norm = normalize_item(obj)
            norm["file"] = p.name
            items.append(norm)
        except (json.JSONDecodeError, OSError):
            continue
    return items

# Simple glossary to enrich missing descriptions
RULE_GLOSSARY = {
    "MISSING_FROM": "Missing From header.",
    "MISSING_MID": "Missing Message-Id header.",
    "MISSING_DATE": "Missing Date header.",
    "MISSING_HEADERS": "One or more standard headers are missing.",
    "SPF_NONE": "Sender domain publishes no SPF record.",
    "SPF_HELO_NONE": "HELO/EHLO host publishes no SPF record.",
    "RDNS_NONE": "No reverse DNS for connecting host.",
}

# Load rule descriptions from SpamAssassin rules (describe SYMBOL text)
RULE_DESCRIPTIONS: dict[str, str] = {}

def get_rule_description(name: str) -> str | None:
    desc = RULE_DESCRIPTIONS.get(name)
    if desc:
        return desc
    # Lazy, bounded scan to avoid heavy startup costs
    candidates = [
        Path('/opt/sa-rules/kawaiipantsu'),
        Path('/opt/sa-rules/swiftfilter'),
        Path('/usr/share/spamassassin'),
    ]
    pattern = re.compile(r'^\s*describe\s+([A-Za-z0-9_]+)\s+(.*\S)\s*$')
    scanned_files = 0
    for base in candidates:
        if not base.exists():
            continue
        for p in base.rglob('*.cf'):
            scanned_files += 1
            if scanned_files > MAX_SCAN_FILES:
                break
            try:
                # Skip very large files
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
                with p.open('r', errors='ignore') as fh:
                    for line in fh:
                        m = pattern.match(line)
                        if m:
                            n, d = m.group(1), m.group(2)
                            if n not in RULE_DESCRIPTIONS or len(d) > len(RULE_DESCRIPTIONS[n]):
                                RULE_DESCRIPTIONS[n] = d
                            if n == name:
                                return d
            except (OSError, UnicodeDecodeError):
                continue
    return RULE_DESCRIPTIONS.get(name)

class HTMLTextExtractor(HTMLParser):
    """Extract plain text from HTML by stripping tags."""
    def __init__(self):
        super().__init__()
        self.text = []
        self.ignore_tags = {'script', 'style', 'head', 'meta', 'link'}
        self.in_ignore = False
    
    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.ignore_tags:
            self.in_ignore = True
    
    def handle_endtag(self, tag):
        if tag.lower() in self.ignore_tags:
            self.in_ignore = False
        elif tag.lower() in {'p', 'div', 'br', 'li'}:
            self.text.append('\n')
    
    def handle_data(self, data):
        if not self.in_ignore:
            self.text.append(data)
    
    def get_text(self):
        text = ''.join(self.text)
        # Clean up whitespace
        lines = [line.strip() for line in text.split('\n')]
        lines = [line for line in lines if line]
        return '\n'.join(lines)

def parse_raw(raw_path: Path):
    try:
        data = raw_path.read_bytes()
        msg = BytesParser(policy=policy.default).parsebytes(data)
        headers = [(k, str(v)) for k, v in msg.items()]
        plaintext_body = None
        html_body = None
        
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not plaintext_body:
                    try:
                        plaintext_body = part.get_content().strip()
                    except (UnicodeDecodeError, LookupError):
                        pass
                elif ctype == "text/html" and not html_body:
                    try:
                        html_body = part.get_content()
                    except (UnicodeDecodeError, LookupError):
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                html_body = payload.decode('utf-8', errors='replace')
                        except Exception:
                            pass
        else:
            # Non-multipart - check content type
            ctype = msg.get_content_type()
            try:
                body_content = msg.get_content()
                if ctype == "text/plain":
                    plaintext_body = body_content.strip() if body_content else None
                elif ctype == "text/html":
                    html_body = body_content
            except (UnicodeDecodeError, LookupError, AttributeError):
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='replace')
                        if ctype == "text/plain":
                            plaintext_body = content.strip()
                        elif ctype == "text/html" or content.strip().startswith('<'):
                            html_body = content
                except Exception:
                    pass
        
        # If we have plaintext, return it
        if plaintext_body:
            return headers, plaintext_body
        
        # If we have HTML but no plaintext, extract text from HTML
        if html_body:
            try:
                extractor = HTMLTextExtractor()
                extractor.feed(html_body)
                extracted_text = extractor.get_text()
                if extracted_text:
                    return headers, f"[Extracted from HTML]\n\n{extracted_text}"
            except Exception:
                pass
        
        # Fallback: try get_body method
        try:
            body = msg.get_body(preferencelist=("plain",))
            if body:
                content = body.get_content().strip()
                if content:
                    return headers, content
        except (UnicodeDecodeError, LookupError, AttributeError):
            pass
        
        return headers, "(no plaintext body available)"
    except Exception:
        return [], "(failed to parse plaintext body)"

def get_top_positive_rules(rules: list[dict], count: int = TOP_RULES_COUNT) -> list[dict]:
    """Get top N positive-scoring rules sorted by score."""
    return sorted([r for r in rules if r.get("score", 0) > 0], key=lambda r: r.get("score", 0), reverse=True)[:count]

def build_reason(score: float | None, required: float | None, rules: list[dict]) -> str:
    if score is None or required is None:
        return "Insufficient data to determine spam status."
    
    top = get_top_positive_rules(rules)
    parts = ", ".join(f"{html.escape(str(r.get('name')))}+{r.get('score')}" for r in top)
    
    if score < required:
        if not top:
            return f"Not spam: score {score:.2f} below threshold {required:.1f}."
        return f"Not spam (score {score:.2f} < {required:.1f}). Top positive rules: {parts}."
    
    parts = parts or "(none)"
    return f"Spam (score {score:.2f} ≥ {required:.1f}). Top contributors: {parts}."

@app.get("/report/{filename}", response_class=HTMLResponse)
def html_report_detail(filename: str):
    # Expect a JSON file name like <key>.json and corresponding RAW <key>.eml
    jsn_path = ARCHIVE / filename
    if not jsn_path.exists() or not jsn_path.name.endswith(".json"):
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        obj = json.loads(jsn_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        raise HTTPException(status_code=500, detail="Failed to read report JSON")
    key = jsn_path.stem
    raw_path = RAW_ARCHIVE / f"{key}.eml"
    try:
        headers_list, plaintext = parse_raw(raw_path) if raw_path.exists() else ([], "(raw email not archived)")
    except Exception:
        headers_list, plaintext = [], "(failed to parse email)"
    meta = obj.get("meta", {})
    try:
        subj = html.escape(str(meta.get("subject") or "(no subject)"))
    except Exception:
        subj = "(no subject)"
    sa = obj.get("spamassassin", {})
    score = sa.get("score")
    required = sa.get("required")
    is_spam = sa.get("is_spam")
    rules = sa.get("rules", [])
    try:
        reason = build_reason(score, required, rules)
    except Exception:
        reason = "Unable to generate reason"
    def rule_desc(r: dict) -> str:
        try:
            name = str(r.get("name", ""))
            d = (r.get("description") or "").strip()
            # If spamd's report truncated the description, or it's empty, try SA rules map, then glossary
            if not d or d.endswith(':') or d.endswith(' to'):
                desc = get_rule_description(name) or RULE_GLOSSARY.get(name, d)
                return (desc or "").strip()
            # Add note if rule is disabled
            if r.get("disabled"):
                return d + " [DISABLED - score set to 0]"
            return d
        except Exception:
            return "(description unavailable)"
    
    rules_rows = ""
    try:
        sorted_rules = sorted(rules, key=lambda r: float(r.get("score") or 0), reverse=True)[:MAX_RULES_DISPLAY]
        for r in sorted_rules:
            try:
                rule_name = html.escape(str(r.get('name', '?')))
                rule_score_val = r.get('score', 0)
                # Show score as 0.0 if rule is disabled, even if original score was different
                if r.get("disabled"):
                    original_score = r.get("original_score", rule_score_val)
                    rule_score = f"0.0 <span style=\"color:var(--muted);font-size:11px\">(was {original_score:.1f})</span>"
                else:
                    rule_score = html.escape(str(rule_score_val))
                rule_desc_text = html.escape(rule_desc(r))
                rules_rows += f"<tr><td>{rule_name}</td><td>{rule_score}</td><td>{rule_desc_text}</td></tr>"
            except Exception:
                # Skip malformed rules
                continue
    except Exception:
        pass
    
    if not rules_rows:
        rules_rows = "<tr><td colspan=3>(no rules)</td></tr>"
    try:
        score_txt = "n/a" if score is None else f"{score:.2f}" + (f" / {required:.1f}" if required is not None else "")
    except (ValueError, TypeError):
        score_txt = "n/a"
    received_at = meta.get("received_at")
    headers_rows = ""
    try:
        for k, v in headers_list[:MAX_HEADERS_DISPLAY]:
            try:
                headers_rows += f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
            except Exception:
                continue
    except Exception:
        pass
    if not headers_rows:
        headers_rows = "<tr><td colspan=2>(no headers)</td></tr>"
    
    # Extract new analysis sections
    received_headers = obj.get("headers", {}).get("received", [])
    hop_delays = obj.get("headers", {}).get("hop_delays")
    auth_results = obj.get("authentication")
    ip_analysis = obj.get("ip_analysis", {})
    domain_analysis = obj.get("domain_analysis", {})
    urls_data = obj.get("urls", {})
    structure = obj.get("structure", {})
    attachments = obj.get("attachments", {})
    screenshot_data = obj.get("screenshot")
    
    # Build additional sections first (with error handling)
    try:
        received_section = _build_received_section(received_headers, hop_delays)
    except Exception:
        received_section = ""
    try:
        auth_section = _build_auth_section(auth_results)
    except Exception:
        auth_section = ""
    try:
        ip_section = _build_ip_section(ip_analysis)
    except Exception:
        ip_section = ""
    try:
        domain_section = _build_domain_section(domain_analysis)
    except Exception:
        domain_section = ""
    try:
        url_section = _build_url_section(urls_data, screenshot_data)
    except Exception:
        url_section = ""
    try:
        structure_section = _build_structure_section(structure)
    except Exception:
        structure_section = ""
    try:
        attachment_section = _build_attachment_section(attachments)
    except Exception:
        attachment_section = ""
    try:
        screenshot_section = _build_screenshot_section(screenshot_data)
    except Exception:
        screenshot_section = ""
    
    # Build CSS separately to avoid f-string brace escaping issues
    detail_css = """
:root{--bg:#0b1020;--panel:#121a33;--muted:#94a3b8;--text:#e5e7eb;--accent:#60a5fa;--ok:#10b981;--bad:#ef4444}
@media(prefers-color-scheme:light){:root{--bg:#ffffff;--panel:#f8fafc;--muted:#475569;--text:#0f172a;--accent:#2563eb;--ok:#059669;--bad:#dc2626}}
body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
.container{max-width:1200px;margin:24px auto;padding:0 16px}
.panel{background:var(--panel);border:1px solid #1f2a4a;border-radius:10px;padding:16px}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;word-break:break-word}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
table{border-collapse:collapse;width:100%;border-radius:8px;overflow:hidden}
th,td{border-bottom:1px solid #1f2a4a;padding:8px 10px;vertical-align:top}
th{background:#101830;text-align:left;color:var(--muted);font-weight:600}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.subtle{color:var(--muted);font-size:13px}
"""
    pill_bg = '#311317' if is_spam else '#102a1d'
    pill_border = '#7f1d1d' if is_spam else '#064e3b'
    pill_color = '#fecaca' if is_spam else '#bbf7d0'
    html_page = f"""<!doctype html>
<html><head><meta charset=\"utf-8\"><title>Report — {subj}</title>
<style>{detail_css}</style></head><body>
<div class=container>
  <p class=subtle><a href=/report>&larr; Back to list</a></p>
  <h1 style=\"margin:8px 0 4px\">{subj}</h1>
  <p class=subtle style=\"margin:0 0 16px\">Received: {html.escape(received_at or '(unknown)')}</p>
  <div class=grid>
    <div class=panel>
      <h3 style=\"margin:0 0 8px\">SpamAssassin</h3>
      <p class=subtle style=\"margin:0 0 8px\">Score: <strong style=\"color:{pill_color}\">{score_txt}</strong> <span class=pill style=\"display:inline-block;padding:3px 10px;border-radius:999px;background:{pill_bg};border:1px solid {pill_border};color:{pill_color}\">{'Spam' if is_spam else 'Not spam'}</span></p>
      <p style=\"margin:0 0 12px\">{html.escape(reason)}</p>
      <h4 style=\"margin:12px 0 6px\">Rule breakdown</h4>
      <table><tr><th>Rule</th><th>Score</th><th>Description</th></tr>{rules_rows}</table>
    </div>
    <div class=panel>
      <h3 style=\"margin:0 0 8px\">Plaintext body</h3>
      <pre>{html.escape(str(plaintext)) if plaintext else '(no plaintext body)'}</pre>
    </div>
  </div>
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Headers</h3>
    <table><tr><th>Header</th><th>Value</th></tr>{headers_rows}</table>
  </div>
  {received_section}
  {auth_section}
  {ip_section}
  {domain_section}
  {url_section}
  {structure_section}
  {attachment_section}
  {screenshot_section}
</div>
</body></html>"""
    
    return HTMLResponse(content=html_page)

def _build_received_section(received_headers, hop_delays):
    """Build HTML for Received headers analysis."""
    if not received_headers:
        return ""
    
    rows = []
    for i, recv in enumerate(received_headers):
        ip = recv.get("ip", "N/A")
        hostname = recv.get("hostname", "N/A")
        timestamp = recv.get("timestamp", "N/A")
        delay = ""
        if hop_delays and i < len(hop_delays):
            delay = f" (delay: {hop_delays[i]:.2f}s)"
        rows.append(f"<tr><td>{i+1}</td><td>{html.escape(str(ip))}</td><td>{html.escape(str(hostname))}</td><td>{html.escape(str(timestamp))}{delay}</td></tr>")
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Received Headers Analysis</h3>
    <table><tr><th>Hop</th><th>IP</th><th>Hostname</th><th>Timestamp</th></tr>{''.join(rows)}</table>
  </div>"""

def _build_auth_section(auth_results):
    """Build HTML for authentication results."""
    if not auth_results:
        return ""
    
    rows = []
    for auth_type in ["spf", "dkim", "dmarc"]:
        auth_data = auth_results.get(auth_type)
        if auth_data:
            result = auth_data.get("result", "unknown")
            reason = auth_data.get("reason", "")
            status_color = "var(--ok)" if result == "pass" else "var(--bad)" if result == "fail" else "var(--muted)"
            rows.append(f"<tr><td>{auth_type.upper()}</td><td style=\"color:{status_color}\">{html.escape(result)}</td><td>{html.escape(reason or 'N/A')}</td></tr>")
    
    if not rows:
        return ""
    
    # Add spoofing risk warning if present
    spoofing_warning = ""
    spoofing_risk = auth_results.get("spoofing_risk")
    spoofing_flags = auth_results.get("spoofing_flags", [])
    if spoofing_risk:
        risk_color = "var(--bad)" if spoofing_risk == "High" else "var(--muted)" if spoofing_risk == "Low" else "#f59e0b"
        spoofing_warning = f"<p style=\"color:{risk_color};margin:8px 0;font-weight:600\">⚠ Spoofing Risk: {spoofing_risk}"
        if spoofing_flags:
            spoofing_warning += f" ({', '.join(html.escape(f) for f in spoofing_flags)})"
        spoofing_warning += "</p>"
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Authentication Results</h3>
    {spoofing_warning}
    <table><tr><th>Type</th><th>Result</th><th>Reason</th></tr>{''.join(rows)}</table>
  </div>"""

def _build_ip_section(ip_analysis):
    """Build HTML for IP analysis."""
    if not ip_analysis or not ip_analysis.get("all_ips"):
        return ""
    
    rows = []
    for ip_info in ip_analysis.get("all_ips", []):
        ip = ip_info.get("ip", "N/A")
        hostname = ip_info.get("hostname", "N/A")
        rDNS = ip_info.get("reverse_dns") or "N/A"
        rows.append(f"<tr><td>{html.escape(str(ip))}</td><td>{html.escape(str(hostname))}</td><td>{html.escape(str(rDNS))}</td></tr>")
    
    origin_ip = ip_analysis.get("origin_ip", "N/A")
    first_hop = ip_analysis.get("first_hop_ip", "N/A")
    hop_count = ip_analysis.get("hop_count", 0)
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">IP Analysis</h3>
    <p class=subtle style=\"margin:0 0 8px\">Origin IP: <strong>{html.escape(str(origin_ip))}</strong> | First Hop: <strong>{html.escape(str(first_hop))}</strong> | Hops: {hop_count}</p>
    <table><tr><th>IP</th><th>Hostname</th><th>Reverse DNS</th></tr>{''.join(rows)}</table>
  </div>"""

def _build_domain_section(domain_analysis):
    """Build HTML for domain analysis."""
    if not domain_analysis:
        return ""
    
    from_domain = domain_analysis.get("from") or "N/A"
    reply_to = domain_analysis.get("reply_to") or "N/A"
    return_path = domain_analysis.get("return_path") or "N/A"
    msg_id_domain = domain_analysis.get("message_id") or "N/A"
    mismatches = domain_analysis.get("mismatches", [])
    
    mismatch_warning = ""
    if mismatches:
        mismatch_warning = f"<p style=\"color:var(--bad);margin:8px 0\">⚠ Domain mismatch detected: {', '.join(html.escape(d) for d in mismatches)}</p>"
    
    # Add spoofing indicators if present
    spoofing_indicators = domain_analysis.get("spoofing_indicators", [])
    if spoofing_indicators:
        for indicator in spoofing_indicators:
            mismatch_warning += f"<p style=\"color:var(--bad);margin:4px 0;font-size:13px\">⚠ {html.escape(indicator)}</p>"
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Domain Analysis</h3>
    <table>
      <tr><th>From</th><td>{html.escape(str(from_domain))}</td></tr>
      <tr><th>Reply-To</th><td>{html.escape(str(reply_to))}</td></tr>
      <tr><th>Return-Path</th><td>{html.escape(str(return_path))}</td></tr>
      <tr><th>Message-ID Domain</th><td>{html.escape(str(msg_id_domain))}</td></tr>
    </table>
    {mismatch_warning}
  </div>"""

def _build_url_section(urls_data, screenshot_data=None):
    """Build HTML for URL analysis, including URLs from email body, headers, and external resources."""
    urls_from_body = urls_data.get("from_body") or [] if urls_data else []
    urls_from_headers = urls_data.get("from_headers") or [] if urls_data else []
    
    if urls_from_body is None:
        urls_from_body = []
    if urls_from_headers is None:
        urls_from_headers = []
    
    # Also extract URLs from screenshot external resources
    urls_from_resources = []
    if screenshot_data:
        external_resources = screenshot_data.get("external_resources", [])
        for res in external_resources:
            url = res.get("url", "")
            if url and not url.startswith('data:'):  # Skip data URIs
                # Parse the URL to extract domain
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.netloc or "N/A"
                    # Check if it's an IP
                    is_ip = False
                    try:
                        netloc_host = domain.split(':')[0]
                        if netloc_host.startswith('[') and ']' in netloc_host:
                            netloc_host = netloc_host[1:netloc_host.index(']')]
                        socket.inet_aton(netloc_host)
                        is_ip = True
                    except (socket.error, ValueError, AttributeError, OSError):
                        try:
                            if netloc_host.startswith('[') and ']' in netloc_host:
                                netloc_host = netloc_host[1:netloc_host.index(']')]
                            socket.inet_pton(socket.AF_INET6, netloc_host)
                            is_ip = True
                        except (socket.error, ValueError, AttributeError, OSError):
                            pass
                    
                    # Check for shorteners
                    is_shortener = False
                    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
                    if any(s in domain.lower() for s in shorteners):
                        is_shortener = True
                    
                    urls_from_resources.append({
                        "url": url,
                        "domain": domain,
                        "is_ip": is_ip,
                        "is_shortener": is_shortener,
                        "source": "external_resource"
                    })
                except Exception:
                    # If parsing fails, still include the URL
                    urls_from_resources.append({
                        "url": url,
                        "domain": "N/A",
                        "is_ip": False,
                        "is_shortener": False,
                        "source": "external_resource"
                    })
    
    # Combine all URLs and deduplicate by URL
    all_urls_dict = {}
    for url_info in urls_from_body:
        url = url_info.get("url", "")
        if url:
            all_urls_dict[url] = {**url_info, "source": "body"}
    
    for url_info in urls_from_headers:
        url = url_info.get("url", "")
        if url:
            if url not in all_urls_dict:
                all_urls_dict[url] = {**url_info, "source": "header"}
            else:
                # Update source to indicate it's in both
                all_urls_dict[url]["source"] = "body,header"
    
    for url_info in urls_from_resources:
        url = url_info.get("url", "")
        if url:
            if url not in all_urls_dict:
                all_urls_dict[url] = {**url_info}
            else:
                # Update source to include external_resource
                existing_source = all_urls_dict[url].get("source", "")
                if "external_resource" not in existing_source:
                    all_urls_dict[url]["source"] = f"{existing_source},external_resource" if existing_source else "external_resource"
    
    all_urls = list(all_urls_dict.values())
    total_count = len(all_urls)
    
    if total_count == 0:
        return ""
    
    rows = []
    for url_info in all_urls[:50]:  # Increased limit to show more URLs
        url = url_info.get("url", "")
        domain = url_info.get("domain", "N/A")
        is_ip = url_info.get("is_ip", False)
        is_shortener = url_info.get("is_shortener", False)
        source = url_info.get("source", "unknown")
        flags = []
        if is_ip:
            flags.append("IP")
        if is_shortener:
            flags.append("Shortener")
        flag_text = f" ({', '.join(flags)})" if flags else ""
        url_str = str(url) if url else ""
        domain_str = str(domain) if domain else "N/A"
        source_str = html.escape(source.replace("_", " ").title())
        rows.append(f"<tr><td><a href=\"{html.escape(url_str)}\" target=\"_blank\">{html.escape(url_str[:80])}{'...' if len(url_str) > 80 else ''}</a></td><td>{html.escape(domain_str)}{flag_text}</td><td class=subtle>{source_str}</td></tr>")
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">All Links Found ({total_count})</h3>
    <table><tr><th>URL</th><th>Domain</th><th>Source</th></tr>{''.join(rows)}</table>
  </div>"""

def _build_structure_section(structure):
    """Build HTML for email structure analysis."""
    if not structure:
        return ""
    
    is_multipart = structure.get("is_multipart", False)
    content_type = structure.get("content_type") or "N/A"
    encoding = structure.get("encoding") or "N/A"
    missing_headers = structure.get("missing_headers", [])
    part_count = structure.get("part_count", 0)
    part_types = structure.get("part_types", [])
    
    missing_warning = ""
    if missing_headers:
        missing_warning = f"<p style=\"color:var(--bad);margin:8px 0\">⚠ Missing headers: {', '.join(html.escape(str(h)) for h in missing_headers)}</p>"
    
    parts_info = ""
    if is_multipart and part_types:
        parts_info = f"<p class=subtle>Parts: {part_count} ({', '.join(html.escape(str(t)) for t in part_types[:5])})</p>"
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Structure Analysis</h3>
    <table>
      <tr><th>Multipart</th><td>{'Yes' if is_multipart else 'No'}</td></tr>
      <tr><th>Content-Type</th><td>{html.escape(str(content_type))}</td></tr>
      <tr><th>Encoding</th><td>{html.escape(str(encoding))}</td></tr>
    </table>
    {parts_info}
    {missing_warning}
  </div>"""

def _build_attachment_section(attachments):
    """Build HTML for attachment analysis."""
    if not attachments or attachments.get("count", 0) == 0:
        return ""
    
    count = attachments.get("count", 0)
    files = attachments.get("files", [])
    
    # Dangerous extensions that should be flagged
    dangerous_extensions = {
        "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar", "app", "deb", "rpm",
        "msi", "dmg", "sh", "ps1", "psm1", "psd1", "ps1xml", "psc1", "pssc", "cdxml",
        "wsf", "wsc", "ws", "wsh", "hta", "cpl", "msc", "msp", "mst", "lnk", "url",
        "scf", "shb", "vb", "vbe", "jse", "ws", "wsc", "wsh", "ade", "adp", "bas",
        "chm", "crt", "csh", "fxp", "hlp", "inf", "ins", "isp", "its", "js", "jse",
        "ksh", "lnk", "mad", "maf", "mag", "mam", "maq", "mar", "mas", "mat", "mau",
        "mav", "maw", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "msc", "msh", "msh1",
        "msh2", "mshxml", "msh1xml", "msh2xml", "ocx", "ops", "pcd", "pif", "pl",
        "prf", "prg", "pst", "reg", "scf", "sct", "shb", "shs", "tmp", "url", "vb",
        "vbe", "vbs", "wsc", "wsf", "wsh", "xnk"
    }
    
    rows = []
    for f in files[:50]:  # Increased limit
        filename = f.get("filename", "N/A")
        content_type = f.get("content_type", "N/A")
        size = f.get("size", 0)
        extension = f.get("extension", "N/A")
        file_path = f.get("file_path", "")
        size_str = f"{size} bytes" if size < 1024 else f"{size/1024:.2f} KB" if size < 1024*1024 else f"{size/(1024*1024):.2f} MB"
        
        # Check if extension is dangerous
        is_dangerous = False
        if extension and extension.lower() in dangerous_extensions:
            is_dangerous = True
        
        # Build download link if file_path exists
        download_link = ""
        if file_path:
            # file_path is already "attachments/{key}/{filename}", so use it directly
            download_url = f"/archive/{file_path}"
            download_link = f'<a href="{html.escape(download_url)}" target="_blank" style="color:var(--accent)">Download</a>'
        else:
            download_link = "N/A"
        
        # Add warning indicator for dangerous extensions
        extension_display = html.escape(str(extension))
        if is_dangerous:
            extension_display = f'<span style="color:var(--bad);font-weight:bold" title="Potentially dangerous file type">⚠ {extension_display}</span>'
        
        rows.append(f"<tr><td>{html.escape(str(filename))}</td><td>{extension_display}</td><td>{html.escape(str(content_type))}</td><td>{size_str}</td><td>{download_link}</td></tr>")
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Attachments ({count})</h3>
    <table><tr><th>Filename</th><th>Extension</th><th>Type</th><th>Size</th><th>Download</th></tr>{''.join(rows)}</table>
  </div>"""

def _build_screenshot_section(screenshot_data):
    """Build HTML for email screenshot preview."""
    if not screenshot_data:
        return ""
    
    screenshot_path = screenshot_data.get("path")
    error = screenshot_data.get("error")
    external_resources = screenshot_data.get("external_resources", [])
    has_remote_content = screenshot_data.get("has_remote_content", False)
    total_requests = screenshot_data.get("total_external_requests", 0)
    
    # Show error if screenshot generation failed
    if error:
        return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Email Preview</h3>
    <p style=\"color:var(--bad);margin:8px 0\">⚠ Screenshot generation failed: {html.escape(error)}</p>
    <p class=subtle style=\"margin:4px 0\">Check /var/log/score_and_store.err for details</p>
  </div>"""
    
    if not screenshot_path:
        return ""
    
    # Build screenshot image
    screenshot_url = f"/archive/{screenshot_path}"
    screenshot_html = f"<img src=\"{html.escape(screenshot_url)}\" alt=\"Email preview\" style=\"max-width:100%;border:1px solid #1f2a4a;border-radius:8px;margin:8px 0\" />"
    
    # Build external resources list
    resources_html = ""
    if external_resources:
        rows = []
        for res in external_resources[:20]:  # Limit display
            url = res.get("url", "N/A")
            res_type = res.get("type", "unknown")
            status = res.get("status", "N/A")
            size = res.get("size", 0)
            size_str = f"{size} bytes" if size < 1024 else f"{size/1024:.2f} KB" if size else "N/A"
            # Convert status to int if possible for comparison
            try:
                status_int = int(status) if status != "N/A" else None
                if status_int == 200:
                    status_color = "var(--ok)"
                elif status_int and status_int >= 400:
                    status_color = "var(--bad)"
                else:
                    status_color = "var(--muted)"
            except (ValueError, TypeError):
                status_color = "var(--muted)"
            rows.append(f"<tr><td><a href=\"{html.escape(url)}\" target=\"_blank\">{html.escape(url[:80])}{'...' if len(url) > 80 else ''}</a></td><td>{html.escape(str(res_type))}</td><td style=\"color:{status_color}\">{html.escape(str(status))}</td><td>{size_str}</td></tr>")
        
        resources_html = f"""
    <h4 style=\"margin:16px 0 8px\">External Resources Loaded ({total_requests})</h4>
    <table><tr><th>URL</th><th>Type</th><th>Status</th><th>Size</th></tr>{''.join(rows)}</table>"""
    
    # Warning if remote content detected
    warning_html = ""
    if has_remote_content:
        warning_html = f"<p style=\"color:var(--bad);margin:8px 0;font-weight:600\">⚠ This email loaded {total_requests} external resource(s) (images, CSS, fonts, etc.)</p>"
    
    return f"""
  <div class=panel style=\"margin-top:16px\">
    <h3 style=\"margin:0 0 8px\">Email Preview</h3>
    {warning_html}
    {screenshot_html}
    {resources_html}
  </div>"""

@app.get("/archive/attachments/{filepath:path}")
def serve_attachment(filepath: str):
    """Serve attachment files from the mail archive."""
    if ".." in filepath or filepath.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    file_path = ATTACHMENTS_ARCHIVE / filepath
    
    if file_path.exists() and file_path.is_file():
        content_type = "application/octet-stream"
        if file_path.suffix:
            content_types = {
                ".pdf": "application/pdf",
                ".doc": "application/msword",
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".xls": "application/vnd.ms-excel",
                ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".zip": "application/zip",
                ".txt": "text/plain",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".png": "image/png",
                ".gif": "image/gif",
            }
            content_type = content_types.get(file_path.suffix.lower(), "application/octet-stream")
        
        return FileResponse(
            file_path,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{file_path.name}"'}
        )
    
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/archive/{filepath:path}")
def serve_archive_file(filepath: str):
    """Serve files from the mail archive (screenshots, etc.)."""
    if ".." in filepath or filepath.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if filepath.startswith("screenshots/"):
        file_path = SCREENSHOTS_ARCHIVE / filepath.replace("screenshots/", "", 1)
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path, media_type="image/png")
    
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/report", response_class=HTMLResponse)
def html_report():
    items = load_reports()
    rows=[]
    for it in items:
        subj = html.escape(it.get("subject") or "(no subject)")
        score = it.get("score")
        req = it.get("required")
        recv = it.get("received_at") or ""
        score_txt = "n/a" if score is None else f"{score:.2f}" + (f" / {req:.1f}" if req is not None else "")
        rules = it.get("rules") or []
        def full_desc(r: dict) -> str:
            nm = str(r.get('name',''))
            d = (r.get('description') or '').strip()
            if not d or d.endswith(':') or d.endswith(' to'):
                d = get_rule_description(nm) or RULE_GLOSSARY.get(nm, d)
            return d or ''
        def rule_line(r: dict) -> str:
            nm = html.escape(str(r.get('name','?')))
            sc = html.escape(str(r.get('score','?')))
            fd = html.escape(full_desc(r))
            # Preview: first N chars
            preview = (fd[:MAX_RULE_PREVIEW_LENGTH] + '…') if len(fd) > MAX_RULE_PREVIEW_LENGTH else fd
            return f"<span title=\"{fd}\">{nm}: {sc} — {preview}</span>"
        rule_lines = "; ".join(rule_line(r) for r in rules[:3])
        fname = html.escape(it.get("file",""))
        link = f"/report/{fname}" if fname else "#"
        rows.append(f"<tr onclick=\"location.href='{link}'\" style='cursor:pointer'><td>{subj}</td><td>{score_txt}</td><td>{html.escape(recv)}</td><td>{rule_lines or '(none)'}></td><td>{fname}</td></tr>")
    list_css = """
:root{--bg:#0b1020;--panel:#121a33;--muted:#94a3b8;--text:#e5e7eb;--accent:#60a5fa}
@media(prefers-color-scheme:light){:root{--bg:#ffffff;--panel:#f8fafc;--muted:#475569;--text:#0f172a;--accent:#2563eb}}
body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
.container{max-width:100%;margin:24px auto;padding:0 16px}
table{border-collapse:separate;border-spacing:0;width:100%;border-radius:10px;overflow:hidden;table-layout:auto}
th,td{padding:10px 12px;border-bottom:1px solid #1f2a4a;vertical-align:top}
th{background:#101830;text-align:left;color:var(--muted);font-weight:600;white-space:nowrap}
th:nth-child(1),td:nth-child(1){min-width:150px;max-width:300px;word-break:break-word}
th:nth-child(2),td:nth-child(2){width:100px;white-space:nowrap;text-align:center}
th:nth-child(3),td:nth-child(3){width:180px;white-space:nowrap}
th:nth-child(4),td:nth-child(4){min-width:400px;word-break:break-word}
th:nth-child(5),td:nth-child(5){width:250px;white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace}
tr:hover td{background:#0f1831}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.btn{background:transparent;border:1px solid #1f2a4a;color:var(--text);padding:6px 10px;border-radius:8px;cursor:pointer}
"""
    list_js = """
<script>
// SSE refresh when a new report arrives (skip first event to avoid reload loop)
document.addEventListener('DOMContentLoaded', function () {
  try {
    var initialized = false;
    var es = new EventSource('/events/reports');
    es.onmessage = function (ev) {
      if (!initialized) { initialized = true; return; }
      if (ev && ev.data) { window.location.reload(); }
    };
  } catch(e) {}
});

function cleanupArchive(btn) {
  if (confirm('Delete all emails, attachments, and screenshots? This cannot be undone.')) {
    // Disable button during cleanup
    var originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Cleaning...';
    
    fetch('/api/cleanup', {method: 'POST'})
      .then(r => {
        if (!r.ok) {
          return r.text().then(text => {
            throw new Error('HTTP ' + r.status + ': ' + text);
          });
        }
        return r.json();
      })
      .then(d => {
        if (d.success) {
          var msg = 'Successfully deleted ' + (d.deleted || 0) + ' files.';
          if (d.errors && d.errors.length > 0) {
            msg += '\\n\\nSome errors occurred:\\n' + d.errors.slice(0, 5).join('\\n');
            if (d.errors.length > 5) {
              msg += '\\n... and ' + (d.errors.length - 5) + ' more errors.';
            }
          }
          alert(msg);
          // Small delay to ensure filesystem sync before reload
          setTimeout(function() {
            // Force hard refresh with cache-busting
            window.location.href = window.location.pathname + '?t=' + Date.now();
          }, 200);
        } else {
          btn.disabled = false;
          btn.textContent = originalText;
          var errorMsg = d.error || 'Unknown error';
          if (d.errors && d.errors.length > 0) {
            errorMsg += '\\n\\nErrors:\\n' + d.errors.slice(0, 10).join('\\n');
            if (d.errors.length > 10) {
              errorMsg += '\\n... and ' + (d.errors.length - 10) + ' more errors.';
            }
          }
          alert('Cleanup failed: ' + errorMsg);
        }
      })
      .catch(e => {
        btn.disabled = false;
        btn.textContent = originalText;
        console.error('Cleanup error:', e);
        alert('Error: ' + e.message);
      });
  }
}
</script>
"""
    html_page = f"""<!doctype html>
<html><head><meta charset=\"utf-8\"><title>Inbound Mail Reports</title>
<meta http-equiv=\"cache-control\" content=\"no-cache, no-store, must-revalidate\">
<meta http-equiv=\"pragma\" content=\"no-cache\">
<meta http-equiv=\"expires\" content=\"0\">
<style>{list_css}</style>
{list_js}
</head><body>
<div class=container>
  <div class=header>
    <h1 style=\"margin:0\">Inbound Mail Reports</h1>
    <div>
      <button class=btn onclick=\"cleanupArchive(this)\" style=\"margin-right:8px;background:var(--bad);border-color:var(--bad);color:#fff\">Clean All</button>
      <button class=btn onclick=\"window.location.reload()\">Refresh</button>
    </div>
  </div>
  <table>
    <tr><th>Subject</th><th>Score</th><th>Received</th><th>Top Rules</th><th>File</th></tr>
    {''.join(rows) if rows else '<tr><td colspan=\"5\">(no reports yet)</td></tr>'}
  </table>
</div>
</body></html>"""
    # Add cache-control headers to prevent browser caching
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    return HTMLResponse(content=html_page, headers=headers)

@app.post("/api/cleanup")
def cleanup_archive():
    """Delete all archived emails, attachments, and screenshots."""
    import shutil
    import sys
    import os
    deleted_count = 0
    errors = []
    
    try:
        # Delete all JSON files
        if ARCHIVE.exists() and ARCHIVE.is_dir():
            json_files = list(ARCHIVE.glob("*.json"))
            for json_file in json_files:
                try:
                    if json_file.exists() and json_file.is_file():
                        # Check write permission
                        if not os.access(json_file, os.W_OK):
                            errors.append(f"No write permission: {json_file.name}")
                            continue
                        json_file.unlink()
                        if json_file.exists():
                            errors.append(f"Failed to delete {json_file.name} (still exists)")
                        else:
                            deleted_count += 1
                except PermissionError as e:
                    error_msg = f"Permission denied deleting {json_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
                except Exception as e:
                    error_msg = f"Failed to delete {json_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
        
        # Delete all raw email files
        if RAW_ARCHIVE.exists() and RAW_ARCHIVE.is_dir():
            raw_files = list(RAW_ARCHIVE.glob("*.eml"))
            for raw_file in raw_files:
                try:
                    if raw_file.exists() and raw_file.is_file():
                        if not os.access(raw_file, os.W_OK):
                            errors.append(f"No write permission: {raw_file.name}")
                            continue
                        raw_file.unlink()
                        if raw_file.exists():
                            errors.append(f"Failed to delete {raw_file.name} (still exists)")
                        else:
                            deleted_count += 1
                except PermissionError as e:
                    error_msg = f"Permission denied deleting {raw_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
                except Exception as e:
                    error_msg = f"Failed to delete {raw_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
        
        # Delete all screenshots
        if SCREENSHOTS_ARCHIVE.exists() and SCREENSHOTS_ARCHIVE.is_dir():
            screenshot_files = list(SCREENSHOTS_ARCHIVE.glob("*.png"))
            for screenshot_file in screenshot_files:
                try:
                    if screenshot_file.exists() and screenshot_file.is_file():
                        if not os.access(screenshot_file, os.W_OK):
                            errors.append(f"No write permission: {screenshot_file.name}")
                            continue
                        screenshot_file.unlink()
                        if screenshot_file.exists():
                            errors.append(f"Failed to delete {screenshot_file.name} (still exists)")
                        else:
                            deleted_count += 1
                except PermissionError as e:
                    error_msg = f"Permission denied deleting {screenshot_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
                except Exception as e:
                    error_msg = f"Failed to delete {screenshot_file.name}: {e}"
                    sys.stderr.write(f"ERROR: {error_msg}\n")
                    errors.append(error_msg)
        
        # Delete all attachments (recursively delete subdirectories)
        if ATTACHMENTS_ARCHIVE.exists() and ATTACHMENTS_ARCHIVE.is_dir():
            try:
                # Check write permission on directory
                if not os.access(ATTACHMENTS_ARCHIVE, os.W_OK):
                    errors.append(f"No write permission on attachments directory")
                else:
                    attachment_dirs = [d for d in ATTACHMENTS_ARCHIVE.iterdir() if d.is_dir()]
                    for attachment_dir in attachment_dirs:
                        try:
                            files_in_dir = list(attachment_dir.rglob("*"))
                            file_count = sum(1 for f in files_in_dir if f.is_file())
                            deleted_count += file_count
                            shutil.rmtree(attachment_dir)
                            if attachment_dir.exists():
                                errors.append(f"Failed to delete attachment directory {attachment_dir.name} (still exists)")
                        except PermissionError as e:
                            error_msg = f"Permission denied deleting attachment directory {attachment_dir.name}: {e}"
                            sys.stderr.write(f"ERROR: {error_msg}\n")
                            errors.append(error_msg)
                        except Exception as e:
                            error_msg = f"Failed to delete attachment directory {attachment_dir.name}: {e}"
                            sys.stderr.write(f"ERROR: {error_msg}\n")
                            errors.append(error_msg)
            except Exception as e:
                error_msg = f"Error accessing attachments directory: {e}"
                sys.stderr.write(f"ERROR: {error_msg}\n")
                errors.append(error_msg)
        
        # Return success even if some files failed (partial success)
        # Include errors in response for debugging
        response_data = {
            "success": len(errors) == 0,
            "deleted": deleted_count,
            "errors": errors if errors else None
        }
        
        # Add cache-control headers
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        
        return JSONResponse(
            content=response_data,
            headers=headers
        )
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        sys.stderr.write(f"ERROR: Cleanup failed: {e}\n")
        sys.stderr.write(error_trace)
        return JSONResponse(
            content={
                "success": False,
                "error": str(e),
                "deleted": deleted_count,
                "errors": errors if errors else None
            },
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )

@app.get('/events/reports')
async def sse_reports():
    async def event_stream():
        last_key = None
        while True:
            try:
                files = sorted(ARCHIVE.glob('*.json'), key=lambda x: x.stat().st_mtime, reverse=True)
                key = files[0].name if files else None
                if key and key != last_key:
                    last_key = key
                    yield f"data: {key}\n\n"
            except OSError:
                pass
            await asyncio.sleep(1.0)
    return StreamingResponse(event_stream(), media_type='text/event-stream')

