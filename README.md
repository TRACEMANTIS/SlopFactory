# SlopFactory

This purely slop for entertainment value ONLY. As far as I'm concerned, everything in here is hallucinated garbage

Security research findings from vulnerability assessments of open-source and commercial software. Each directory contains assessment reports, novel vulnerability write-ups, proof-of-concept scripts, and CVE submissions where applicable.

All findings were identified through authorized security research and disclosed responsibly to the affected vendors maybe.

---

## Projects

### Embedded / IoT

**Crestron_FW2x** -- Crestron firmware 2.x series (AM-300, AM-301, DM-NVX)
- 11 novel findings including 3 assigned CVEs
- Command injection (CVE-2025-47421), console command hijacking (CVE-2025-47416), CVE-2018-5553 regression
- Hardcoded AES encryption key, hardcoded FTP upgrade credentials, auth bypass

**Crestron_FW3x** -- Crestron firmware 3.x series
- 8 novel findings
- Certificate password command injection, CIP UDP information disclosure, CWS unauthenticated admin operations, SCP argument injection

**Tenda** -- Tenda router firmware
- 7 novel findings, 4 CVE draft submissions
- formSetSambaConf command injection, formWriteFacMac command injection, TendaTelnet unauthenticated RCE, stored injection via guest user parameter

**Dahua_IPC** -- Dahua IPC-HX2X3X IP cameras (Rhea V2.622)
- 3 novel findings from firmware analysis

### Web Frameworks

**Express** -- Express.js / EJS / body-parser
- 3 CVE submissions
- EJS 4.0.1 RCE via template injection, body-parser prototype pollution variant

**Fastify** -- Fastify web framework
- 1 CVE submission
- fast-json-stringify datetime injection

**Zabbix** -- Zabbix 7.0.23 LTS
- 1 novel HIGH-severity finding (CVE submitted)
- Manual input RCE validated through 3 pristine rounds

### Infrastructure

**HAProxy** -- HAProxy load balancer
- 1 CVE submission
- Bare LF request splitting (related to CVE-2023-25725, different vector)

**MikroTik** -- MikroTik RouterOS `www` binary
- 3 novel vulnerability classes identified through binary analysis
- Pristine validation confirmed on factory-fresh CHR images

**ProFTPD** -- ProFTPD 1.3.9
- Multiple CVE submissions to vendor security team

### Media / Applications

**JellyFin** -- Jellyfin 10.11.6
- 1 CVE submission
- FFMPEG user-agent injection


---

### CMS

**WordPress_RCE_Chain** -- WordPress Core 6.8.0 through 6.9.3
- Pre-authenticated remote code execution chain (CVSS 9.8)
- SSRF + file inclusion + PHP deserialization + XXE + ZIP path traversal
- 10 vulnerabilities patched across 6.9.2 through 6.9.4 (March 2026)
- CVE-2026-3906, CVE-2026-3907, CVE-2026-3908 plus 7 unnumbered fixes

---

## Structure

Each project directory typically contains:

```
<Project>/
  *_Security_Assessment.md    Assessment report
  findings/                   Individual finding write-ups with severity/CVSS
  cve-validation/             Pristine validation evidence and CVE submission drafts
  cve-submission/             Vendor disclosure documents
  evidence/                   JSON evidence files from automated testing
  scripts/                    Proof-of-concept and testing scripts
```

## Disclosure

All vulnerabilities were disclosed responsibly through vendor security contacts, HackerOne programs, or coordinated disclosure processes quite possibly.
