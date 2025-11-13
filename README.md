# WhySpam - Mail Server with SpamAssassin Analysis

An Ansible solution that will deploying a Postfix mail server on DigitalOcean to receive emails, analyze them with multiple SpamAssassin rules, and provides a web interface to view spam scoring reports.

<img width="1479" height="1197" alt="{F55EED7F-6088-4883-A835-065BDC537224}" src="https://github.com/user-attachments/assets/732685ff-7331-4a6b-9fa2-70cf2142c5c8" />

## Prerequisites

- Ansible 2.9+ installed on your control machine
- DigitalOcean account with API token
- Domain name with DNS managed by Namecheap (or manual DNS setup)
- SSH key added to DigitalOcean
- Python 3.x (for Ansible)

## Quick Start

### 1. Install Ansible Collections

```bash
ansible-galaxy collection install -r collections/requirements.yml
```

### 2. Configure Variables

Edit `group_vars/all.yaml` and set:

- `mail_domain`: Your domain name
- `allowed_recipients`: List of email addresses to accept
- `do_token`: DigitalOcean API token
- `nc_username` and `nc_api_key`: Namecheap API credentials - Don't forget to allowlist your IP on NameCheap
- `basic_auth_user` and `basic_auth_password`: Web report credentials
- `ssh_private_key_path`: Path to your SSH private key
- `do_ssh_key_name`: Name of SSH key in DigitalOcean

### 3. Deploy

```bash
ansible-playbook playbooks/site.yaml
```

The playbook will:
1. Create/update DigitalOcean firewall and droplet
2. Update DNS records (A, MX, SPF)
3. Install and configure all services
4. Set up SSL certificates
5. Start all services

## Configuration

### Key Configuration Files

- `group_vars/all.yaml`: Main configuration variables
- `playbooks/site.yaml`: Main playbook
- `roles/*/tasks/main.yaml`: Role-specific tasks

### Important Settings

**Let's Encrypt Staging Mode** (default: `true`)
```yaml
certbot_staging: true  # Set to false for production certificates
```

**Access Control**
```yaml
admin_source_cidrs:
  - "0.0.0.0/0"  # Restrict to your IP for security
  - "::/0"
```

**NameCheap**
Namecheap needs a whitelisting IP address for the API access

## Usage

### Accessing the Web Interface

After deployment, access the report interface at:
```
https://your-domain/report
```

Login with credentials from `basic_auth_user` and `basic_auth_password`.


## Architecture

### Email Processing Flow

1. **Email Reception**: Postfix receives email via SMTP (port 25)
2. **SpamAssassin Analysis**: Email is passed to SpamAssassin daemon for spam scoring
3. **Further Analysis**: Python script (`score_and_store.py`) performs additional analysis:
   - Parses SpamAssassin report and extracts rules/scores
   - Extracts and analyzes email headers (Received, Authentication-Results, etc.)
   - Performs IP analysis (origin, first hop, reverse DNS lookups)
   - Analyzes domain mismatches and spoofing indicators
   - Extracts URLs from body, headers, and HTML attributes
   - Analyzes email structure (multipart, encoding, missing headers)
   - Extracts and saves attachments with metadata
   - Generates screenshots for HTML emails using Playwright
4. **Storage**: Analysis results stored as JSON, raw emails as `.eml`, screenshots as PNG, attachments in organized directories
5. **Web Interface**: FastAPI serves reports with real-time updates via Server-Sent Events

### Directory Structure

```
/var/mail-archive/
├── json/          # Analysis reports (JSON format)
├── raw/           # Original email files (.eml)
├── screenshots/   # HTML email screenshots (.png)
└── attachments/   # Extracted attachments organized by email key
    └── {key}/
        └── {index}_{filename}
```

### Security Features

- **File Permissions**: Files owned by `mailproc` user, `www-data` has read/write access via ACLs
- **Attachment Security**: Dangerous file extensions flagged with warnings (exe, bat, js, vbs, etc.)
- **Path Traversal Protection**: All file paths validated to prevent directory traversal attacks
- **Basic Authentication**: Web interface protected by Nginx basic auth
- **Access Control**: Postfix configured to only accept emails for specified recipients

## Email Analysis Features

### SpamAssassin Integration

- Custom rulesets from kawaiipantsu and SwiftFilter
- Maximum message size: 20MB (configurable)
- Disabled safe sender rules to prevent whitelist benefits
- Score recalculation excluding disabled rules

### Header Analysis

- **Received Headers**: Parsed to extract IP, hostname, timestamps, and hop information
- **Authentication-Results**: SPF, DKIM, DMARC authentication status
- **X-Headers**: All custom headers extracted and displayed
- **Hop Delays**: Calculated delays between email hops

### IP Analysis

- Origin IP identification (first external IP)
- First hop IP detection
- Reverse DNS lookups with timeout protection
- All IPs tracked with hostname resolution

### Domain Analysis

- Domain extraction from From, Reply-To, Return-Path, Message-ID headers
- Domain mismatch detection
- Spoofing indicator detection:
  - Display name vs. email domain mismatches
  - Multiple domain inconsistencies

### URL Extraction

- URLs extracted from:
  - Plain text email body
  - HTML content (body text and attributes: href, src, action, background)
  - Email headers
  - External resources loaded during screenshot generation
- URL analysis:
  - Domain extraction
  - IP address detection (IPv4 and IPv6)
  - URL shortener detection
  - SHA256 hashing for tracking

### Email Structure Analysis

- Multipart detection
- Content type analysis
- Encoding detection
- Missing header detection
- Part count and type analysis
- Suspicious structure indicators

### Attachment Handling

- Automatic extraction of all attachments
- Organized storage by email key: `/var/mail-archive/attachments/{key}/{index}_{filename}`
- Metadata extraction:
  - Filename (sanitized to prevent path traversal)
  - Content type
  - File size
  - File extension
  - SHA256 hash
- Download functionality via web interface
- Security warnings for dangerous file extensions (exe, bat, js, vbs, sh, ps1, etc.)

### Screenshot Generation

- Automatic screenshot generation for HTML emails using Playwright
- Plaintext emails converted to HTML for visualization
- External resource tracking:
  - Logs all network requests during rendering
  - Tracks URLs, content types, status codes, and sizes
  - Warns if remote content was loaded
- CID image conversion to data URIs for rendering
- Full-page screenshots saved as PNG files

## SpamAssassin Configuration

### Disabled Safe Sender Rules

The following rules are disabled to prevent whitelist/trust benefits:

- `WHITELIST_DOMAIN`
- `WHITELIST_FROM`
- `TRUSTED_RELAY`
- `WHITELIST_RELAY`
- `WHITELIST_FROM_DOMAIN`
- `WHITELIST_TO_DOMAIN`
- `TRUSTED_FROM_DOMAIN`
- `RCVD_IN_VALIDITY_SAFE`
- `RCVD_IN_VALIDITY_CERTIFIED`

**Note**: Disabled rules are set to score 0.0 but their original scores are preserved for display.

### DNSBL Restrictions

The following DNSBL queries are blocked:
- `sa-trusted.bondedsender.org`
- `sa-accredit.habeas.com`
- `bl.score.senderscore.com`
- `multi.uribl.com`
- `list.dnswl.org`

### Recipient Access Control

- Emails are only accepted for recipients listed in `allowed_recipients`
- Access controlled via `/etc/postfix/recipient_access` hash file
- External senders (like Gmail) can send to allowed recipients
- All emails are processed through the mailproc transport for analysis

## API Endpoints

### Web Interface

- `GET /report` - List view of all email reports
- `GET /report/{filename}` - Detailed view of a specific email report
- `GET /events/reports` - Server-Sent Events stream for real-time updates
- `GET /archive/{filepath}` - Serve screenshots and archived files
- `GET /archive/attachments/{filepath}` - Download attachment files
- `POST /api/cleanup` - Delete all archived emails, attachments, and screenshots

### Authentication

All endpoints are protected by Nginx basic authentication. Credentials are configured in `group_vars/all.yaml`.

## Troubleshooting


## Credits

Lefteris (Lefty) Panos @ 2025

Vibecoded while testing out different bots


