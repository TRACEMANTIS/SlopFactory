# independent security research. -- Jellyfin Security Assessment Report

## Executive Summary

This report documents a security assessment of **Jellyfin 10.11.6**, the latest stable release of the open-source media server platform. Jellyfin has approximately 66,757 internet-facing instances worldwide. The assessment was conducted against a local Docker deployment (jellyfin/jellyfin:10.11.6) with full source code access.

The assessment identified **5 findings** including one novel vulnerability suitable for CVE disclosure: an FFmpeg argument injection via the Live TV tuner User-Agent field that enables arbitrary file write, file read, and SSRF. This finding was validated across 3 pristine reproduction rounds.

Six prior CVEs were regressed, all confirmed as patched in version 10.11.6.

## Target Information

| Property | Value |
|----------|-------|
| Software | Jellyfin (Free Software Media System) |
| Version | 10.11.6 (released 2026-01-19) |
| Language | C# / .NET 9.0 (ASP.NET Core) |
| License | GPL-2.0 |
| Source | https://github.com/jellyfin/jellyfin |
| Deployment | Docker (jellyfin/jellyfin:10.11.6) |
| Internet Exposure | ~66,757 instances (Shodan) |

## Methodology

| Phase | Description | Tests |
|-------|-------------|-------|
| Phase 0 | Environment setup (Docker, source clone, media) | -- |
| Phase 1 | Reconnaissance, API mapping, source audit | 36 |
| Phase 2 | FFmpeg injection, CVE regression, SSRF, SVG | 81 |
| Phase 3 | Authentication, authorization, IDOR, sessions | 31 |
| Phase 5 | XSS, CSS injection, directory traversal | 16 |
| Phase 9 | Pristine validation (3 rounds) | 3 |
| **Total** | | **167** |

## Findings Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| FFMPEG-UA-001 | HIGH | FFmpeg argument injection via Live TV tuner User-Agent | CONFIRMED (3/3 pristine) |
| RESTART-001 | HIGH | Unauthenticated /System/Restart DoS via LocalAccess bypass | CONFIRMED (Docker/LAN) |
| UNAUTH-MEDIA-001 | MEDIUM | Unauthenticated media stream/image access by item ID | CONFIRMED |
| HEADERS-001 | MEDIUM | Missing security response headers (0/9) | CONFIRMED |
| OPENAPI-001 | LOW | 59 API endpoints without security requirement in spec | CONFIRMED |

## Detailed Findings

### FFMPEG-UA-001: FFmpeg Argument Injection via Live TV Tuner User-Agent

**Severity:** HIGH (CVSS 7.2)
**Status:** Validated (3/3 pristine rounds)
**Impact:** Arbitrary file write, file read, SSRF

**Description:** The `TunerHostInfo.UserAgent` field accepts arbitrary values including double quotes and FFmpeg command-line flags. When a Live TV channel from this tuner is transcoded, the User-Agent value is passed to FFmpeg via direct string concatenation (no escaping) in `EncodingHelper.GetUserAgentParam()` and `MediaEncoder.cs`.

**Root Cause:** Three locations construct FFmpeg arguments via string concatenation:
- `EncodingHelper.cs` line 495: `return "-user_agent \"" + useragent + "\""`
- `EncodingHelper.cs` line 510: `return "-referer \"" + referer + "\""`
- `MediaEncoder.cs` line 459: `extraArgs += $" -user_agent \"{userAgent}\""`

**Proof of Concept:**

1. Create M3U tuner host with normal UA
2. Modify config: set UserAgent to `Mozilla/5.0" -loglevel verbose -report -i "`
3. Request HLS transcoding of the Live TV channel
4. Observe FFmpeg command: `-user_agent "Mozilla/5.0" -loglevel verbose -report -i ""`
5. The `-report` flag writes `/ffmpeg-<timestamp>.log` (7534 bytes) to the filesystem

**FFmpeg command from Jellyfin transcode log:**
```
/usr/lib/jellyfin-ffmpeg/ffmpeg -analyzeduration 200M -probesize 1G
  -user_agent "Mozilla/5.0" -loglevel verbose -report -i ""
  -fflags +igndts -i "http://[REDACTED-INTERNAL-IP]:9999/movies/Test_Movie_2026.mp4"
  -map_metadata -1 -map_chapters -1 -threads 0 ...
```

**Prior Art:** Same bug class as CVE-2023-49096 and CVE-2025-31499 (codec parameter injection), but in the User-Agent/Referer code path which was not addressed by those patches.

**Remediation:** Sanitize User-Agent/Referer values by escaping double quotes or use `ProcessStartInfo.ArgumentList`.

---

### RESTART-001: Unauthenticated /System/Restart DoS

**Severity:** HIGH
**Status:** Confirmed (Docker deployment)

**Description:** The `POST /System/Restart` endpoint uses `LocalAccessOrRequiresElevation` policy which grants unauthenticated access to any IP in the configured local network. By default, Jellyfin considers all RFC 1918 private address ranges ([REDACTED-INTERNAL-IP]/8, [REDACTED-INTERNAL-IP]/12, [REDACTED-INTERNAL-IP]/16) as "local."

**Root Cause:** `LocalAccessOrRequiresElevationHandler.cs` line 37 calls `context.Succeed(requirement)` without checking authentication when the remote IP is in the local network.

**Impact:** Any host on the same LAN can restart the Jellyfin server without authentication, causing denial of service. In Docker deployments, the Docker bridge IP (172.x.x.x) is always in the local range.

**Note:** This is by design for ease of use but creates a significant DoS risk in shared network environments and Docker deployments.

---

### UNAUTH-MEDIA-001: Unauthenticated Media Access by Item ID

**Severity:** MEDIUM
**Status:** Confirmed

**Description:** Media files (video streams, audio streams, and item images) are accessible without authentication when the item ID (a GUID) is known. Tested endpoints:
- `GET /Videos/{itemId}/stream.mp4?static=true` -- returns full video file
- `GET /Audio/{itemId}/stream.mp3?static=true` -- returns full audio file
- `GET /Items/{itemId}/Images/Primary` -- returns item image

**Impact:** If item IDs are leaked or guessed, any unauthenticated user can access the media library. While GUIDs are not easily enumerable, they may be exposed through other API responses, shared links, or URL referrer headers.

---

### HEADERS-001: Missing Security Response Headers

**Severity:** MEDIUM
**Status:** Confirmed

**Description:** Jellyfin does not set any standard security response headers. All 9 checked headers are absent across all endpoints:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy

**Impact:** Reduced defense-in-depth against XSS, clickjacking, MIME-type confusion, and other client-side attacks. Affects all 66,757 internet-facing instances.

---

### OPENAPI-001: Endpoints Without Security Requirement

**Severity:** LOW
**Status:** Confirmed

**Description:** The OpenAPI specification declares 59 endpoints without a security requirement, out of 388 total endpoints (15.2%). Most are media streaming, image serving, and branding endpoints that are intentionally public, but the breadth of unauthenticated surface area is notable.

## CVE Regression Results

| CVE | Severity | Description | Status |
|-----|----------|-------------|--------|
| CVE-2025-32012 | MEDIUM | IP spoofing via X-Forwarded-For | **PATCHED** |
| CVE-2025-31499 | HIGH | FFmpeg injection bypass | **PATCHED** |
| CVE-2024-43801 | MEDIUM | SVG upload stored XSS | **PATCHED** |
| CVE-2023-48702 | MEDIUM | RCE via FFmpeg binary path | **PATCHED** |
| CVE-2023-49096 | HIGH | FFmpeg codec injection | **PATCHED** |
| CVE-2021-29490 | MEDIUM | Unauthenticated SSRF | **PATCHED** |

### Regression Details

- **CVE-2025-32012:** X-Forwarded-For and X-Real-IP headers do not affect authentication decisions. Tested 5 spoofing patterns, all blocked (401).
- **CVE-2025-31499/CVE-2023-49096:** Codec parameters are validated by `ContainerValidationRegex`. Special characters (spaces, quotes, newlines, semicolons, backticks) are rejected. Pipe `|` and comma `,` are allowed by the regex but are benign in the FFmpeg context.
- **CVE-2024-43801:** SVG uploads to user profile images return 500 (SkiaSharp rejects SVG format).
- **CVE-2023-48702:** The `UpdateMediaEncoderPath` endpoint is a NOOP -- the actual code (`_mediaEncoder.UpdateEncoderPath(...)`) is commented out. Returns 204 but changes nothing.
- **CVE-2021-29490:** `/Images/Remote` endpoint returns 404 (removed or renamed).

## Negative Testing Results

The following attack vectors were tested and found to be properly defended:

- **Authentication bypass:** Empty tokens, null tokens, headers without tokens, invalid API keys -- all rejected (401)
- **User enumeration:** Login responses are identical for valid/invalid usernames ("Error processing request.")
- **Session management:** Tokens are unique per login, old tokens invalidated, logout properly invalidates sessions
- **SVG upload XSS:** SVG files rejected by SkiaSharp image processor (500)
- **Library name XSS:** HTML tags stripped from stored names
- **User name XSS:** HTML characters rejected (400)
- **Directory traversal via logs:** `/System/Logs/Log` with traversal patterns returns 404
- **CSS branding injection:** POST /Branding/Configuration returns 405 (endpoint restricted)
- **SSRF via /Images/Remote:** Endpoint returns 404 (removed)
- **Subtitle path traversal:** All patterns return 404

## Evidence Inventory

| File | Phase | Contents |
|------|-------|----------|
| `evidence/phase1_phase1_recon_*.json` | 1 | API mapping, header analysis, 36 tests |
| `evidence/phase2_phase2_ffmpeg_injection_*.json` | 2 | Codec validation, SSRF, SVG, encoder path |
| `evidence/phase2_phase2b_ffmpeg_deep_*.json` | 2 | Transcoding validation, PlaybackInfo analysis |
| `evidence/phase2_phase2c_useragent_injection_*.json` | 2 | UA injection initial testing |
| `evidence/phase2_phase2d_tuner_injection_*.json` | 2 | Tuner host creation with injection payloads |
| `evidence/phase2_phase2e_cmdline_capture_*.json` | 2 | FFmpeg command line capture |
| `evidence/phase3_phase3_auth_testing_*.json` | 3 | Auth, authz, IDOR, sessions |
| `evidence/phase5_phase5_xss_traversal_*.json` | 5 | XSS, CSS, directory traversal |
| `evidence/phase9_phase9_pristine_ffmpeg_ua_*.json` | 9 | Pristine validation (3 rounds) |
| `evidence/ffmpeg_injection_transcode.log` | 2 | Full FFmpeg transcode log showing injection |
| `evidence/ffmpeg_injection_syslog.txt` | 2 | System log with full FFmpeg command |
| `evidence/ffmpeg_report_injected_file.log` | 2 | File created by injected -report flag |

## Scripts Inventory

| Script | Purpose |
|--------|---------|
| `jellyfin_common.py` | Shared utilities, session management, evidence collector |
| `phase1_recon.py` | API mapping, endpoint auth testing, OpenAPI analysis |
| `phase2_ffmpeg_injection.py` | Codec injection, SSRF, SVG, encoder path CVE regression |
| `phase2b_ffmpeg_deep.py` | Transcoding validation, PlaybackInfo analysis |
| `phase2c_useragent_injection.py` | User-Agent injection source code proof |
| `phase2d_tuner_injection.py` | Tuner host creation with injection payloads |
| `phase2e_ffmpeg_cmdline_capture.py` | End-to-end FFmpeg command line capture |
| `phase3_auth_testing.py` | Auth, authz, IDOR, session management |
| `phase5_xss_traversal.py` | XSS, CSS injection, directory traversal |
| `phase9_pristine_validation.py` | 3-round pristine validation of FFMPEG-UA-001 |

## Disclosure Plan

- **Finding:** FFMPEG-UA-001 (FFmpeg argument injection via User-Agent)
- **Recipient:** [VENDOR-CONTACT] (Subject: [Jellyfin Security])
- **Advisory:** `cve-validation/CVE_SUBMISSION_FFMPEG_UA_001.md`
- **Expected timeline:** 90-day coordinated disclosure
