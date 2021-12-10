# abuse_whois

[![PyPI version](https://badge.fury.io/py/abuse-whois.svg)](https://badge.fury.io/py/abuse-whois)
[![Python CI](https://github.com/ninoseki/abuse_whois/actions/workflows/test.yml/badge.svg)](https://github.com/ninoseki/abuse_whois/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/ninoseki/abuse_whois/badge.svg?branch=main)](https://coveralls.io/github/ninoseki/abuse_whois?branch=main)

Yet another way to find where to report a domain for abuse.

![img](./images/overview.jpg)

This tool is highly inspired from the following libraries:

- https://github.com/bradleyjkemp/abwhose
- https://github.com/certsocietegenerale/abuse_finder

## Requirements

- Python 3.7+
- whois

## Installation

```bash
pip install abuse_whois

# or if you want to use built-in REST API
pip install abuse_whois[api]
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

## Contributions

`abuse_whois` works based on a combination of static rules and a parsing result of whois response.

- Rules:
  - [Registrar and hosting provider](https://github.com/ninoseki/abuse_whois/wiki/Registrar-and-Hosting-Provider)
  - [Shared hosting provider](https://github.com/ninoseki/abuse_whois/wiki/Shared-Hosting)

Please submit a PR (or submit a feature request) if you find something missing.
