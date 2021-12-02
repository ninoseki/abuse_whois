# abuse_whois

Yet another way to find where to report a domain for abuse.

This tool is highly inspired from the following libraries:

- https://github.com/bradleyjkemp/abwhose
- https://github.com/certsocietegenerale/abuse_finder

## Requirements

- Python 3.7+
- whois

## Installation

```bash
pip install abuse_whois
```

## Usage

### As a library

```python
from abuse_whois import get_get_abuse_contacts

get_abuse_contacts("1.1.1.1")
get_abuse_contacts("github.com")
get_abuse_contacts("https://github.com")
get_abuse_contacts("foo@example.com")
```

### As a CLI tool

```bash
$ abuse_whois 1.1.1.1 | jq .
{
  "address": "1.1.1.1",
  "hostname": "1.1.1.1",
  "ipAddress": "1.1.1.1",
  "sharedHostingProvider": null,
  "registrar": null,
  "hostingProvider": {
    "provider": "Cloudflare",
    "address": "https://www.cloudflare.com/abuse/form",
    "type": "form"
  }
}
```

### As a REST API

```bash
$ uvicorn abuse_whois.api.app:app
INFO:     Started server process [2283]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)

$ http localhost:8000/api/whois/ address=https://github.com
{
    "address": "https://github.com",
    "hostingProvider": {
        "address": "abuse@amazonaws.com",
        "provider": "",
        "type": "email"
    },
    "hostname": "github.com",
    "ipAddress": "52.192.72.89",
    "registrar": {
        "address": "abusecomplaints@markmonitor.com",
        "provider": "MarkMonitor, Inc.",
        "type": "email"
    },
    "sharedHostingProvider": null
}
```
