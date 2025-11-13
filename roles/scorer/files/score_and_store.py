
#!/usr/bin/env python3
import sys, os, json, re, time, tempfile, socket, hashlib, base64
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr
from subprocess import Popen, PIPE, DEVNULL
from urllib.parse import urlparse
from datetime import datetime, timezone
import html as html_module
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

os.umask(0o022)

ARCHIVE_BASE="/var/mail-archive"
RAW=os.path.join(ARCHIVE_BASE,"raw")
JSN=os.path.join(ARCHIVE_BASE,"json")
os.makedirs(RAW, exist_ok=True)
os.makedirs(JSN, exist_ok=True)

def run_spamc(b):
    # Increase max message size to 20MB (default is 512KB)
    p = Popen(["/usr/bin/spamc", "-R", "-s", "20971520"], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    out, _ = p.communicate(b)
    return out.decode("utf-8", "replace")

def parse(rep):
    """Improved SpamAssassin report parsing with better regex patterns."""
    sc = None
    req = None
    rules = []
    
    # Try to find score/required in format: "X.X / Y.Y" at start of line
    m = re.search(r'^\s*([+-]?\d+(?:\.\d+)?)\s*/\s*([+-]?\d+(?:\.\d+)?)\s*$', rep, re.M)
    if m:
        try:
            sc = float(m.group(1))
            req = float(m.group(2))
        except (ValueError, IndexError):
            pass
    
    # Try "Content analysis details: (X.X points, Y.Y required)"
    if sc is None:
        m = re.search(r'Content analysis details:\s*\(\s*([+-]?\d+(?:\.\d+)?)\s*points,\s*([+-]?\d+(?:\.\d+)?)\s*required\)', rep)
        if m:
            try:
                sc = float(m.group(1))
                req = float(m.group(2))
            except (ValueError, IndexError):
                pass
    
    # Parse rule lines: "  X.X  RULE_NAME  Description text"
    # Handle multi-line descriptions (continuation lines are indented)
    lines = rep.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        rule_match = re.match(r'^\s*([+-]?\d+(?:\.\d+)?)\s+([A-Z0-9_]+)\s+(.+)$', line)
        if rule_match:
            try:
                score_val = float(rule_match.group(1))
                rule_name = rule_match.group(2)
                desc_parts = [rule_match.group(3).strip()]
                
                base_indent = len(line) - len(line.lstrip())
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    if not next_line.strip() or re.match(r'^\s*[+-]?\d+(?:\.\d+)?\s+[A-Z0-9_]+\s+', next_line):
                        break
                    if len(next_line) - len(next_line.lstrip()) > base_indent:
                        desc_parts.append(next_line.strip())
                        i += 1
                    else:
                        break
                
                full_desc = ' '.join(desc_parts).strip()
                if full_desc:
                    rules.append({"score": score_val, "name": rule_name, "description": full_desc})
            except (ValueError, IndexError):
                i += 1
        else:
            i += 1
    
    # Rules that should be ignored in score calculation (disabled in local.cf)
    # These rules are set to score 0 but may still appear in reports with original scores
    DISABLED_RULES = {
        "RCVD_IN_VALIDITY_SAFE",
        "RCVD_IN_VALIDITY_CERTIFIED",
        "WHITELIST_DOMAIN",
        "WHITELIST_FROM",
        "TRUSTED_RELAY",
        "WHITELIST_RELAY",
        "WHITELIST_FROM_DOMAIN",
        "WHITELIST_TO_DOMAIN",
        "TRUSTED_FROM_DOMAIN"
    }
    
    # Filter out disabled rules from score calculation
    filtered_rules = []
    for r in rules:
        rule_name = r.get("name", "")
        if rule_name in DISABLED_RULES:
            # Preserve original score before setting to 0
            r["original_score"] = r.get("score", 0.0)
            r["score"] = 0.0
            r["disabled"] = True
        filtered_rules.append(r)
    rules = filtered_rules
    
    # Recalculate score to account for disabled rules
    # SpamAssassin's reported score may include disabled rules, so we recalculate
    if rules:
        try:
            calculated_score = round(sum(r.get("score", 0) for r in rules), 2)
            sc = calculated_score
            if req is None:
                req = 5.0
        except (ValueError, TypeError):
            if sc is None and req is None:
                req = 5.0
            pass
    
    return sc, req, rules, rep  # Return full report text too

def parse_received_header(header_value):
    """Parse Received header to extract IP, hostname, timestamp, and other info."""
    result = {
        "ip": None,
        "hostname": None,
        "by": None,
        "from": None,
        "with": None,
        "id": None,
        "timestamp": None,
        "raw": header_value
    }
    
    ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ipv6_pattern = r'\b([0-9a-fA-F:]+::?[0-9a-fA-F:]*)\b'
    ip_match = re.search(ipv4_pattern, header_value) or re.search(ipv6_pattern, header_value)
    if ip_match:
        result["ip"] = ip_match.group(1)
    
    hostname_pattern = r'(?:from|by)\s+([a-zA-Z0-9._-]+(?:\.[a-zA-Z0-9._-]+)*)'
    hostname_match = re.search(hostname_pattern, header_value, re.I)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)
    
    by_match = re.search(r'by\s+([a-zA-Z0-9._-]+)', header_value, re.I)
    if by_match:
        result["by"] = by_match.group(1)
    
    from_match = re.search(r'from\s+([a-zA-Z0-9._-]+)', header_value, re.I)
    if from_match:
        result["from"] = from_match.group(1)
    
    # Extract timestamp (RFC 2822 format)
    try:
        date_match = re.search(r';\s*(.+)$', header_value)
        if date_match:
            date_str = date_match.group(1).strip()
            try:
                dt = parsedate_to_datetime(date_str)
                # Convert to UTC and format properly (avoid double timezone indicators)
                if dt.tzinfo is None:
                    result["timestamp"] = dt.isoformat() + "Z"
                else:
                    dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
                    result["timestamp"] = dt_utc.isoformat() + "Z"
            except (ValueError, TypeError, AttributeError):
                pass
    except Exception:
        pass
    
    return result

def parse_authentication_results(header_value):
    """Parse Authentication-Results header for SPF/DKIM/DMARC results."""
    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "arc": None,
        "raw": header_value
    }
    
    spf_match = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', header_value, re.I)
    if spf_match:
        try:
            reason = spf_match.group(2)
        except IndexError:
            reason = None
        result["spf"] = {
            "result": spf_match.group(1).lower(),
            "reason": reason
        }
    
    dkim_match = re.search(r'dkim=(\w+)(?:\s+\(([^)]+)\))?', header_value, re.I)
    if dkim_match:
        try:
            reason = dkim_match.group(2)
        except IndexError:
            reason = None
        result["dkim"] = {
            "result": dkim_match.group(1).lower(),
            "reason": reason
        }
    
    dmarc_match = re.search(r'dmarc=(\w+)(?:\s+\(([^)]+)\))?', header_value, re.I)
    if dmarc_match:
        try:
            reason = dmarc_match.group(2)
        except IndexError:
            reason = None
        result["dmarc"] = {
            "result": dmarc_match.group(1).lower(),
            "reason": reason
        }
    
    return result

def extract_urls(text, html_content=None):
    """Extract URLs from text and HTML content."""
    urls = []
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.I)
    
    if text:
        for match in url_pattern.finditer(text):
            url = match.group(0).rstrip('.,;:!?)')
            if url not in urls:
                urls.append(url)
    
    if html_content:
        # Extract URLs from HTML attributes (href, src, etc.)
        attr_patterns = [
            r'href\s*=\s*["\']?(https?://[^"\'>\s]+)["\']?',
            r'src\s*=\s*["\']?(https?://[^"\'>\s]+)["\']?',
            r'action\s*=\s*["\']?(https?://[^"\'>\s]+)["\']?',
            r'background\s*=\s*["\']?(https?://[^"\'>\s]+)["\']?',
        ]
        
        for pattern in attr_patterns:
            for match in re.finditer(pattern, html_content, re.I):
                url = match.group(1).rstrip('.,;:!?)')
                if url not in urls:
                    urls.append(url)
        
        html_text = re.sub(r'<[^>]+>', ' ', html_content)
        for match in url_pattern.finditer(html_text):
            url = match.group(0).rstrip('.,;:!?)')
            if url not in urls:
                urls.append(url)
    
    analyzed = []
    for url in urls:
        try:
            parsed = urlparse(url)
            url_info = {
                "url": url,
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "is_ip": False,
                "is_shortener": False,
                "hash": hashlib.sha256(url.encode()).hexdigest()[:16]
            }
            
            netloc = parsed.netloc
            try:
                if netloc.startswith('[') and ']' in netloc:
                    netloc_host = netloc[1:netloc.index(']')]
                else:
                    netloc_host = netloc.split(':')[0]
                
                socket.inet_aton(netloc_host)
                url_info["is_ip"] = True
            except (socket.error, ValueError, AttributeError, OSError):
                # Try IPv6
                try:
                    if netloc.startswith('[') and ']' in netloc:
                        netloc_host = netloc[1:netloc.index(']')]
                    else:
                        netloc_host = netloc.split(':')[0]
                    socket.inet_pton(socket.AF_INET6, netloc_host)
                    url_info["is_ip"] = True
                except (socket.error, ValueError, AttributeError, OSError):
                    pass
            
            # Check for common URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
            if any(s in parsed.netloc.lower() for s in shorteners):
                url_info["is_shortener"] = True
            
            analyzed.append(url_info)
        except Exception:
            # If parsing fails, still include the URL
            analyzed.append({
                "url": url,
                "domain": None,
                "scheme": None,
                "path": None,
                "is_ip": False,
                "is_shortener": False,
                "hash": hashlib.sha256(url.encode()).hexdigest()[:16]
            })
    
    return analyzed

def analyze_ips(received_headers):
    """Analyze IP addresses from Received headers."""
    ips = []
    origin_ip = None
    first_hop_ip = None
    
    if received_headers:
        # First hop is the first Received header (most recent)
        first_hop = received_headers[0]
        if first_hop.get("ip"):
            first_hop_ip = first_hop["ip"]
        
        # Origin IP is from the last Received header (oldest)
        if len(received_headers) > 0:
            origin = received_headers[-1]
            if origin.get("ip"):
                origin_ip = origin["ip"]
        
        # Collect all unique IPs
        seen_ips = set()
        for recv in received_headers:
            ip = recv.get("ip")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                ip_info = {
                    "ip": ip,
                    "hostname": recv.get("hostname"),
                    "reverse_dns": None
                }
                
                # Try reverse DNS lookup (may block, but we catch exceptions)
                # Note: This could be slow, but it's non-critical data
                try:
                    # Set a short timeout to avoid blocking too long
                    socket.setdefaulttimeout(2.0)
                    ip_info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror, socket.timeout, OSError):
                    pass
                finally:
                    # Reset timeout to default
                    socket.setdefaulttimeout(None)
                
                ips.append(ip_info)
    
    return {
        "all_ips": ips,
        "origin_ip": origin_ip,
        "first_hop_ip": first_hop_ip,
        "hop_count": len(received_headers) if received_headers else 0
    }

def extract_domain(email_address):
    """Extract domain from email address."""
    if not email_address:
        return None
    try:
        _, addr = parseaddr(email_address)
        if '@' in addr:
            return addr.split('@')[1].lower()
    except Exception:
        pass
    return None

def analyze_domains(msg):
    """Analyze and compare domains from various headers."""
    domains = {
        "from": None,
        "reply_to": None,
        "return_path": None,
        "message_id": None,
        "mismatches": [],
        "spoofing_indicators": []
    }
    
    # Extract From domain and email
    from_header = msg.get("From", "")
    from_str = str(from_header) if from_header else ""
    domains["from"] = extract_domain(from_str)
    
    # Check for display name vs email mismatch (common spoofing technique)
    if from_str:
        # Extract display name and email separately
        from_addr = parseaddr(from_str)
        display_name = from_addr[0]
        email_addr = from_addr[1]
        if display_name and email_addr:
            display_domain = extract_domain(display_name)
            email_domain = extract_domain(email_addr)
            # If display name contains a domain different from email domain, it's suspicious
            if display_domain and email_domain and display_domain != email_domain:
                domains["spoofing_indicators"].append(
                    f"Display name domain ({display_domain}) differs from email domain ({email_domain})"
                )
    
    # Extract Reply-To domain
    reply_to = msg.get("Reply-To", "")
    domains["reply_to"] = extract_domain(str(reply_to) if reply_to else "")
    
    # Extract Return-Path domain
    return_path = msg.get("Return-Path", "")
    domains["return_path"] = extract_domain(str(return_path) if return_path else "")
    
    # Extract domain from Message-ID
    msg_id = msg.get("Message-ID", "")
    if msg_id:
        msg_id_match = re.search(r'@([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)', msg_id)
        if msg_id_match:
            domains["message_id"] = msg_id_match.group(1).lower()
    
    # Check for domain mismatches (potential impersonation)
    domain_set = {d for d in [domains["from"], domains["reply_to"], domains["return_path"]] if d}
    if len(domain_set) > 1:
        domains["mismatches"] = list(domain_set)
        domains["spoofing_indicators"].append(
            f"Domain mismatch detected: {', '.join(domain_set)}"
        )
    
    return domains

def analyze_structure(msg):
    """Analyze email structure and detect issues."""
    structure = {
        "is_multipart": msg.is_multipart(),
        "content_type": msg.get_content_type(),
        "encoding": msg.get_content_charset(),
        "missing_headers": [],
        "suspicious": []
    }
    
    # Check for missing standard headers
    required_headers = ["From", "Date", "Message-ID"]
    for header in required_headers:
        if not msg.get(header):
            structure["missing_headers"].append(header)
    
    # Check for suspicious combinations
    if msg.is_multipart():
        parts = list(msg.walk())
        structure["part_count"] = len(parts)
        structure["part_types"] = [p.get_content_type() for p in parts if p.get_content_type()]
    
    # Check for encoding issues
    if not structure["encoding"]:
        # Try to detect encoding from Content-Type
        ct = msg.get("Content-Type", "")
        charset_match = re.search(r'charset=([^;\s]+)', ct, re.I)
        if charset_match:
            structure["encoding"] = charset_match.group(1)
    
    return structure

def analyze_attachments(msg, key):
    """Analyze email attachments and save them to disk."""
    attachments = {
        "count": 0,
        "files": []
    }
    
    # Create attachments directory for this email
    attachments_base = os.path.join(ARCHIVE_BASE, "attachments")
    email_attachments_dir = os.path.join(attachments_base, key)
    os.makedirs(email_attachments_dir, exist_ok=True)
    
    if msg.is_multipart():
        attachment_index = 0
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" in content_disposition.lower() or "filename" in content_disposition.lower():
                attachments["count"] += 1
                
                # Extract filename
                filename = None
                filename_match = re.search(r'filename[^;=]*=([^;]+)', content_disposition, re.I)
                if filename_match:
                    filename = filename_match.group(1).strip('"\'')
                
                # Sanitize filename (remove path traversal but keep original name)
                if filename:
                    # Remove path traversal attempts
                    filename = filename.replace('../', '').replace('..\\', '')
                    # Remove any remaining path separators
                    filename = os.path.basename(filename)
                    # If filename is empty after sanitization, use a default
                    if not filename:
                        filename = f"attachment_{attachment_index}"
                else:
                    filename = f"attachment_{attachment_index}"
                
                # Get content type and payload
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                except Exception:
                    continue
                
                if not payload or size == 0:
                    continue
                
                # Calculate SHA256 hash
                file_hash = hashlib.sha256(payload).hexdigest()
                
                # Save attachment to disk
                safe_filename = f"{attachment_index}_{filename}"
                file_path = os.path.join(email_attachments_dir, safe_filename)
                try:
                    with open(file_path, "wb") as f:
                        f.write(payload)
                    os.chmod(file_path, 0o644)
                except Exception as e:
                    sys.stderr.write(f"ERROR: Failed to save attachment {filename}: {e}\n")
                    continue
                
                # Extract file extension
                extension = None
                if filename:
                    ext_match = re.search(r'\.([a-zA-Z0-9]+)$', filename)
                    if ext_match:
                        extension = ext_match.group(1).lower()
                
                # Store relative path for web access
                relative_path = f"attachments/{key}/{safe_filename}"
                
                attachments["files"].append({
                    "filename": filename,
                    "content_type": content_type,
                    "size": size,
                    "extension": extension,
                    "file_path": relative_path,
                    "hash": file_hash
                })
                
                attachment_index += 1
    
    return attachments

def convert_cid_images_to_data_uris(msg, html_content):
    """Convert CID (Content-ID) image references to data URIs."""
    if not html_content or not msg.is_multipart():
        return html_content
    
    # Find all CID references in HTML
    cid_pattern = re.compile(r'src=["\']cid:([^"\']+)["\']', re.I)
    cid_matches = list(cid_pattern.finditer(html_content))
    
    if not cid_matches:
        return html_content
    
    # Build mapping of Content-ID to MIME parts
    cid_map = {}
    for part in msg.walk():
        content_id = part.get("Content-ID", "")
        if content_id:
            # Remove angle brackets if present
            content_id = content_id.strip("<>")
            cid_map[content_id] = part
    
    # Replace CID references with data URIs
    result_html = html_content
    for match in reversed(cid_matches):  # Reverse to maintain positions
        cid_value = match.group(1)
        if cid_value in cid_map:
            part = cid_map[cid_value]
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    content_type = part.get_content_type() or "image/png"
                    base64_data = base64.b64encode(payload).decode('ascii')
                    data_uri = f"data:{content_type};base64,{base64_data}"
                    result_html = result_html[:match.start()] + f'src="{data_uri}"' + result_html[match.end():]
            except Exception:
                # If conversion fails, leave CID reference as-is
                pass
    
    return result_html

def generate_email_screenshot(msg, key, html_body):
    """Generate screenshot of HTML email using Playwright."""
    if not PLAYWRIGHT_AVAILABLE:
        sys.stderr.write("ERROR: Playwright not available - cannot generate screenshot\n")
        return False, [], None
    
    if not html_body:
        sys.stderr.write("ERROR: No HTML body provided for screenshot\n")
        return False, [], None
    
    screenshots_dir = os.path.join(ARCHIVE_BASE, "screenshots")
    os.makedirs(screenshots_dir, exist_ok=True)
    screenshot_path = os.path.join(screenshots_dir, f"{key}.png")
    
    external_resources = []
    
    try:
        # Convert CID images to data URIs
        html_content = convert_cid_images_to_data_uris(msg, html_body)
        
        # Sanitize HTML - remove dangerous elements but keep styling
        # Remove script tags and event handlers
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.I)
        html_content = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.I)
        html_content = re.sub(r'javascript:', '', html_content, flags=re.I)
        
        # Wrap HTML content in a proper HTML document structure if needed
        # Check if it's already a complete HTML document
        html_lower = html_content.lower().strip()
        if not (html_lower.startswith('<!doctype') or html_lower.startswith('<html')):
            # It's a fragment, wrap it in a complete HTML document
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Preview</title>
</head>
<body style="margin:0;padding:16px;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;">
{html_content}
</body>
</html>"""
        
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--disable-javascript', '--no-sandbox', '--disable-setuid-sandbox']
            )
            
            # Create context with network request interception
            context = browser.new_context(
                viewport={'width': 1200, 'height': 800},
                user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            )
            
            page = context.new_page()
            
            # Track all network requests
            def handle_request(request):
                url = request.url
                resource_type = request.resource_type
                # Only log external resources (not data URIs)
                if not url.startswith('data:'):
                    external_resources.append({
                        'url': url,
                        'type': resource_type,
                        'method': request.method
                    })
            
            def handle_response(response):
                url = response.url
                if not url.startswith('data:'):
                    # Update existing entry with response info
                    for res in external_resources:
                        if res['url'] == url:
                            res['status'] = response.status
                            try:
                                res['size'] = len(response.body())
                            except Exception:
                                res['size'] = 0
                            break
            
            page.on('request', handle_request)
            page.on('response', handle_response)
            
            content_set = False
            try:
                page.set_content(html_content, wait_until='networkidle', timeout=30000)
                content_set = True
            except PlaywrightTimeoutError:
                try:
                    page.set_content(html_content, wait_until='domcontentloaded', timeout=10000)
                    time.sleep(2)
                    content_set = True
                except Exception:
                    page.set_content(html_content)
                    time.sleep(1)
                    content_set = True
            
            if not content_set:
                raise Exception("Failed to set page content")
            
            try:
                page.screenshot(path=screenshot_path, full_page=True)
            except Exception as screenshot_err:
                sys.stderr.write(f"ERROR: Screenshot failed: {screenshot_err}\n")
                raise
            
            if not os.path.exists(screenshot_path):
                raise FileNotFoundError(f"Screenshot file was not created at {screenshot_path}")
            
            browser.close()
        
        try:
            os.chmod(screenshot_path, 0o644)
        except OSError:
            pass
        return True, external_resources, f"screenshots/{key}.png"
    
    except PlaywrightTimeoutError:
        # Timeout - still return what we collected
        return False, external_resources, None
    except Exception as e:
        # Any other error - log but don't fail email processing
        # Re-raise with context for debugging
        import traceback
        # Write error to stderr for debugging (won't break email processing)
        sys.stderr.write(f"Screenshot generation error: {str(e)}\n")
        sys.stderr.write(traceback.format_exc())
        return False, external_resources, None

def atomic_write_json(path, obj):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass

def main():
    b = sys.stdin.buffer.read()
    msg = BytesParser(policy=policy.default).parsebytes(b)
    hdr = {k: str(v) for k, v in msg.items()}
    
    # Run SpamAssassin analysis
    spamc_report = run_spamc(b)
    sc, req, rules, full_report = parse(spamc_report)
    
    # Parse Received headers
    received_headers_raw = msg.get_all("Received", [])
    received_headers = [parse_received_header(str(r)) for r in received_headers_raw]
    
    # Calculate hop delays if we have timestamps
    hop_delays = []
    if len(received_headers) > 1:
        for i in range(len(received_headers) - 1):
            curr = received_headers[i].get("timestamp")
            prev = received_headers[i + 1].get("timestamp")
            if curr and prev:
                try:
                    # Parse ISO format strings (handle Z suffix and timezone)
                    # Clean up malformed timestamps that might have both timezone offset and Z
                    def clean_timestamp(ts):
                        if not isinstance(ts, str):
                            return str(ts)
                        # Remove trailing Z if there's already a timezone offset
                        if "+" in ts or (ts.count("-") > 2 and not ts.startswith("-")):
                            # Has timezone offset, remove Z if present
                            ts = ts.rstrip("Z")
                        # Replace standalone Z with +00:00
                        if ts.endswith("Z") and "+" not in ts and "-" not in ts[-6:]:
                            ts = ts.replace("Z", "+00:00")
                        return ts
                    
                    curr_str = clean_timestamp(curr)
                    prev_str = clean_timestamp(prev)
                    
                    # fromisoformat requires Python 3.7+ and specific format
                    curr_dt = datetime.fromisoformat(curr_str)
                    prev_dt = datetime.fromisoformat(prev_str)
                    delay = (curr_dt - prev_dt).total_seconds()
                    hop_delays.append(delay)
                except (ValueError, TypeError, AttributeError):
                    # If fromisoformat fails, skip this delay calculation
                    pass
    
    # Parse authentication results
    auth_results = None
    auth_header = msg.get("Authentication-Results")
    if auth_header:
        auth_results = parse_authentication_results(str(auth_header))
        # Add spoofing risk assessment based on authentication failures
        spoofing_flags = []
        if auth_results.get("spf") and auth_results["spf"].get("result") not in ["pass", "neutral", "none"]:
            spoofing_flags.append("SPF " + auth_results["spf"].get("result", "unknown"))
        if auth_results.get("dkim") and auth_results["dkim"].get("result") not in ["pass", "none"]:
            spoofing_flags.append("DKIM " + auth_results["dkim"].get("result", "unknown"))
        if auth_results.get("dmarc") and auth_results["dmarc"].get("result") not in ["pass", "none"]:
            spoofing_flags.append("DMARC " + auth_results["dmarc"].get("result", "unknown"))
        if spoofing_flags:
            auth_results["spoofing_risk"] = "High" if "fail" in " ".join(spoofing_flags).lower() else "Medium"
            auth_results["spoofing_flags"] = spoofing_flags
        elif auth_results.get("spf", {}).get("result") == "none" and auth_results.get("dkim", {}).get("result") == "none":
            # No authentication at all
            auth_results["spoofing_risk"] = "Low"
            auth_results["spoofing_flags"] = ["No SPF/DKIM authentication"]
    
    # Extract email body content for URL extraction
    plaintext_body = None
    html_body = None
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not plaintext_body:
                    try:
                        plaintext_body = part.get_content()
                    except (UnicodeDecodeError, LookupError):
                        pass
                elif content_type == "text/html" and not html_body:
                    try:
                        html_body = part.get_content()
                        if html_body:
                            html_lower = html_body.lower().strip()
                            if not (html_lower.startswith('<') or '<html' in html_lower or '<body' in html_lower or '<div' in html_lower or '<p>' in html_lower):
                                try:
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        html_body = payload.decode('utf-8', errors='replace')
                                except Exception:
                                    pass
                    except (UnicodeDecodeError, LookupError):
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                html_body = payload.decode('utf-8', errors='replace')
                        except Exception:
                            pass
        else:
            # Non-multipart message - extract body payload
            content_type = msg.get_content_type()
            body_content = None
            
            try:
                payload_bytes = msg.get_payload(decode=True)
                if payload_bytes:
                    try:
                        body_content = payload_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        for encoding in ['latin-1', 'iso-8859-1', 'cp1252']:
                            try:
                                body_content = payload_bytes.decode(encoding, errors='replace')
                                break
                            except Exception:
                                continue
                        if not body_content:
                            body_content = payload_bytes.decode('utf-8', errors='replace')
                else:
                    body_content = None
            except (AttributeError, TypeError):
                try:
                    body_content = msg.get_content()
                except (UnicodeDecodeError, LookupError, AttributeError):
                    body_content = None
            except Exception:
                body_content = None
            
            if body_content:
                # Validate content - ensure it's actual body content, not metadata
                body_stripped = body_content.strip()
                body_lower = body_stripped.lower()
                
                # Check for metadata indicators (headers, etc.) - be less strict
                # Only consider it metadata if it's very short AND clearly just headers
                looks_like_metadata = (
                    len(body_stripped) < 150 and  # Very short
                    ('content-type:' in body_lower or 'subject:' in body_lower) and  # Contains header-like text
                    body_lower.count('\n') < 3 and  # Few line breaks (headers are usually compact)
                    not body_lower.startswith('<')  # Not HTML
                )
                
                # Check if content looks like HTML
                looks_like_html = (
                    body_lower.startswith('<') or 
                    '<html' in body_lower or 
                    '<body' in body_lower or 
                    '<div' in body_lower or 
                    '<p>' in body_lower or
                    body_lower.startswith('<!doctype') or
                    (body_lower.startswith('<') and '</' in body_lower)
                )
                
                if looks_like_metadata and not looks_like_html:
                    plaintext_body = body_content
                elif content_type == "text/html" or looks_like_html:
                    html_body = body_content
                elif content_type == "text/plain":
                    plaintext_body = body_content
                else:
                    if looks_like_html:
                        html_body = body_content
                    else:
                        plaintext_body = body_content
    except Exception:
        pass
    
    urls_from_body = extract_urls(plaintext_body, html_body)
    
    urls_from_headers = []
    for header_name in ["List-Unsubscribe", "List-Unsubscribe-Post", "List-Id"]:
        header_value = msg.get(header_name)
        if header_value:
            header_urls = extract_urls(str(header_value))
            urls_from_headers.extend(header_urls)
    
    # Analyze IPs
    ip_analysis = analyze_ips(received_headers)
    
    # Analyze domains
    domain_analysis = analyze_domains(msg)
    
    # Analyze structure
    structure_analysis = analyze_structure(msg)
    
    # Parse Date header
    date_parsed = None
    date_header = msg.get("Date")
    if date_header:
        try:
            dt = parsedate_to_datetime(str(date_header))
            # Convert to UTC and format properly (avoid double timezone indicators)
            if dt.tzinfo is None:
                # Naive datetime, assume UTC
                date_parsed = dt.isoformat() + "Z"
            else:
                # Timezone-aware datetime, convert to UTC and use Z notation
                dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
                date_parsed = dt_utc.isoformat() + "Z"
        except (ValueError, TypeError, AttributeError):
            pass
    
    # Extract X-Headers
    x_headers = {}
    for key, value in hdr.items():
        if key.startswith("X-") or key.startswith("x-"):
            x_headers[key] = str(value)
    
    # Build output structure
    out = {
        "meta": {
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "message_id": hdr.get("Message-ID"),
            "from": hdr.get("From"),
            "to": msg.get_all("To", []),
            "subject": hdr.get("Subject"),
            "size": len(b),
            "return_path": hdr.get("Return-Path"),
            "reply_to": hdr.get("Reply-To"),
            "date": hdr.get("Date"),
            "date_parsed": date_parsed,
            "content_type": msg.get("Content-Type"),
            "mime_version": hdr.get("MIME-Version"),
            "x_headers": x_headers if x_headers else None
        },
        "spamassassin": {
            "score": sc,
            "required": req,
            "is_spam": (None if (sc is None or req is None) else sc >= req),
            "rules": rules,
            "full_report": full_report
        },
        "headers": {
            "received": received_headers,
            "hop_delays": hop_delays if hop_delays else None
        },
        "authentication": auth_results,
        "ip_analysis": ip_analysis,
        "domain_analysis": domain_analysis,
        "structure": structure_analysis,
        "attachments": {"count": 0, "files": []},  # Will be updated after key is generated
        "urls": {
            "from_body": urls_from_body,
            "from_headers": urls_from_headers if urls_from_headers else None,
            "total_count": len(urls_from_body) + len(urls_from_headers)
        }
    }
    
    key = f"{int(time.time())}_{os.urandom(16).hex()}"
    
    # Analyze attachments now that we have the key
    attachment_analysis = analyze_attachments(msg, key)
    out["attachments"] = attachment_analysis
    
    # Generate screenshot for HTML or plaintext emails
    screenshot_data = None
    content_to_render = None
    
    if html_body:
        content_to_render = html_body
    elif plaintext_body:
        escaped_text = html_module.escape(plaintext_body)
        content_to_render = f"<pre style='font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;white-space:pre-wrap;word-wrap:break-word'>{escaped_text}</pre>"
    
    if content_to_render:
        try:
            # Always add screenshot_data so we can see what happened
            if not PLAYWRIGHT_AVAILABLE:
                screenshot_data = {
                    "path": None,
                    "error": "Playwright not available - check if playwright package is installed",
                    "external_resources": [],
                    "has_remote_content": False,
                    "total_external_requests": 0
                }
            else:
                success, external_resources, screenshot_path = generate_email_screenshot(msg, key, content_to_render)
                if success and screenshot_path:
                    screenshot_data = {
                        "path": screenshot_path,
                        "external_resources": external_resources,
                        "has_remote_content": len(external_resources) > 0,
                        "total_external_requests": len(external_resources),
                        "is_plaintext": not html_body
                    }
                else:
                    # Screenshot generation failed but we don't know why
                    screenshot_data = {
                        "path": None,
                        "error": f"Screenshot generation failed (success={success}, path={screenshot_path})",
                        "external_resources": external_resources if external_resources else [],
                        "has_remote_content": False,
                        "total_external_requests": len(external_resources) if external_resources else 0
                    }
        except Exception as e:
            # Screenshot generation failure should not block email processing
            # But we can log the error for debugging
            import traceback
            error_msg = str(e)[:200]  # Longer error message
            sys.stderr.write(f"Screenshot generation exception: {error_msg}\n")
            sys.stderr.write(traceback.format_exc())
            screenshot_data = {
                "path": None,
                "error": error_msg,
                "external_resources": [],
                "has_remote_content": False,
                "total_external_requests": 0
            }
    
    # Always add screenshot data to output (even if None/error) so we can debug
    if screenshot_data:
        out["screenshot"] = screenshot_data
    elif content_to_render:
        # If we had content but no screenshot_data was set, something went wrong
        out["screenshot"] = {
            "path": None,
            "error": "Screenshot data not set (unexpected error)",
            "external_resources": [],
            "has_remote_content": False,
            "total_external_requests": 0
        }
    
    raw_path = os.path.join(RAW, f"{key}.eml")
    with open(raw_path, "wb") as f:
        f.write(b)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(raw_path, 0o644)
    except OSError:
        pass
    atomic_write_json(os.path.join(JSN, f"{key}.json"), out)

if __name__ == "__main__":
    main()
