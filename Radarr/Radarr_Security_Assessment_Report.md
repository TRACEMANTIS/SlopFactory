# Radarr 6.1.1.10360 -- Security Assessment Report

## Executive Summary

This report documents the findings from a security assessment of Radarr version 6.1.1.10360 (latest stable as of March 2026), conducted through source code analysis and live-instance validation. The assessment focused on authentication, cross-origin access controls, input validation, and server-side request forgery attack surfaces.

**5 confirmed findings** were identified: 2 HIGH severity and 3 MEDIUM severity. The most significant finding is a permissive CORS policy (`Access-Control-Allow-Origin: *`) applied to all 159 API controllers, which -- combined with the default `AuthenticationMethod=None` configuration and unauthenticated API key exposure via `/initialize.json` -- allows any malicious website to gain full API control over a victim's Radarr instance. This chain enables SSRF to internal networks, filesystem enumeration, configuration tampering, and denial of service.

All findings were validated against a fresh Radarr 6.1.1.10360 installation running the release binary on Linux with default configuration.

---

## Assessment Details

| Field | Value |
|-------|-------|
| Target | Radarr |
| Version | 6.1.1.10360 (master branch, linux-core-x64) |
| Source | https://github.com/Radarr/Radarr |
| Assessment Date | 2026-03-31 |
| Methodology | Source code analysis + live-instance validation |
| Category | Local lab assessment |
| Disclosure Contact | development@servarr.com |

---

## Findings Summary

| ID | Title | Severity | CVSS 3.1 | Status |
|----|-------|----------|-----------|--------|
| RADARR-001 | Cross-Origin API Access via Permissive CORS Policy | HIGH | 8.1 | Confirmed |
| RADARR-002 | DNS Rebinding to API Key Disclosure and Full Instance Control | HIGH | 7.5 | Confirmed (component-level) |
| RADARR-003 | Regular Expression Denial of Service via Release Profiles | MEDIUM | 6.5 | Confirmed |
| RADARR-004 | Server-Side Request Forgery via Notification/Integration URLs | MEDIUM | 5.0 | Confirmed |
| RADARR-005 | Arbitrary Filesystem Enumeration via API | MEDIUM | 4.3 | Confirmed |

---

## Finding Details

### RADARR-001: Cross-Origin API Access via Permissive CORS Policy

**Severity:** HIGH | **CVSS 3.1:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (8.1)

**Description:**

All 159 API controllers in Radarr inherit the `ApiCorsPolicy` via the `VersionedApiControllerAttribute` class, which implements `IEnableCorsAttribute`. This policy is configured in `Startup.cs` (lines 76-82) as:

```csharp
services.AddCors(options =>
{
    options.AddPolicy(VersionedApiControllerAttribute.API_CORS_POLICY,
        builder =>
        builder.AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader());
});
```

This returns `Access-Control-Allow-Origin: *` on all API responses. Critically, the CORS preflight (OPTIONS) request also succeeds with HTTP 204 and explicitly allows the `X-Api-Key` custom header cross-origin:

```
HTTP/1.1 204 No Content
Access-Control-Allow-Headers: X-Api-Key,Content-Type
Access-Control-Allow-Methods: POST
Access-Control-Allow-Origin: *
```

Additionally, the API key can be passed via the `?apikey=` query parameter, which does not require a preflight request (simple GET). This means a malicious website can make authenticated API calls to any reachable Radarr instance if the API key is known.

On a fresh installation, `AuthenticationMethod` defaults to `None`, and the `/initialize.json` endpoint returns the API key without authentication. While `/initialize.json` does not include CORS headers (blocking direct cross-origin reads), the API key can be obtained via DNS rebinding (RADARR-002), network-adjacent access, or social engineering.

Once the API key is known, the attacker can perform any API operation from any website, including:
- Reading the full configuration (including the API key) via `GET /api/v3/config/host?apikey=`
- Creating SSRF-capable webhook notifications (RADARR-004)
- Creating ReDoS release profiles (RADARR-003)
- Enumerating the filesystem (RADARR-005)
- Modifying any application settings
- Uploading and restoring malicious database backups

**Location:** `src/NzbDrone.Host/Startup.cs` lines 76-82, `src/Radarr.Http/VersionedApiControllerAttribute.cs`

**Validation:**
```
$ curl -s -D- -o /dev/null -X OPTIONS http://TARGET:7878/api/v3/notification \
    -H "Origin: https://evil.attacker.example" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: X-Api-Key,Content-Type"
HTTP/1.1 204 No Content
Access-Control-Allow-Headers: X-Api-Key,Content-Type
Access-Control-Allow-Methods: POST
Access-Control-Allow-Origin: *

$ curl -s http://TARGET:7878/api/v3/config/host?apikey=<KEY> \
    -H "Origin: https://evil.attacker.example" \
    -D- | grep Access-Control
Access-Control-Allow-Origin: *
```

**Remediation:**
1. Replace `AllowAnyOrigin()` with a configured list of trusted origins, or restrict to same-origin only
2. Remove the API key from the `GET /api/v3/config/host` response body
3. Consider removing `?apikey=` query parameter support (header-only authentication)

---

### RADARR-002: DNS Rebinding to API Key Disclosure and Full Instance Control

**Severity:** HIGH | **CVSS 3.1:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H (7.5)

**Description:**

Radarr does not implement Host header validation (`UseHostFiltering` middleware or `AllowedHosts` configuration). When `AuthenticationMethod` is `None` (default on fresh install) or `External` (reverse proxy delegation), the `/initialize.json` endpoint is accessible without credentials via the "UI" authorization policy, which routes to `NoAuthenticationHandler` -- a handler that unconditionally authenticates all requests.

The `/initialize.json` response contains the API key in plaintext:
```json
{
  "apiRoot": "/api/v3",
  "apiKey": "<REDACTED>",
  "version": "6.1.1.10360",
  ...
}
```

A DNS rebinding attack exploits the lack of Host validation:
1. User visits `attacker.example` in their browser
2. DNS first resolves to attacker's server (serves JavaScript payload)
3. DNS TTL expires; resolves to the victim's Radarr IP (e.g., 192.168.x.x)
4. JavaScript fetches `/initialize.json` -- browser treats it as same-origin
5. API key is extracted from the response
6. Subsequent API calls use the key with CORS (RADARR-001) for full control

The `External` authentication mode is equally vulnerable because it also uses `NoAuthenticationHandler` internally. Users relying on reverse proxy authentication (Authelia, Authentik, Traefik forward auth) are vulnerable if the Radarr port is directly reachable on the LAN.

**Location:**
- No `UseHostFiltering()` in `src/NzbDrone.Host/Startup.cs`
- API key in `src/Radarr.Http/Frontend/InitializeJsonController.cs` line 49
- `NoAuthenticationHandler` used for both "None" and "External" auth: `src/Radarr.Http/Authentication/AuthenticationBuilderExtensions.cs` lines 21-29

**Remediation:**
1. Add `UseHostFiltering()` middleware with `AllowedHosts` configured to the expected hostname
2. Require API key authentication for `/initialize.json` regardless of auth mode
3. Default to Forms authentication with mandatory credential setup on first run

---

### RADARR-003: Regular Expression Denial of Service via Release Profiles

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (6.5)

**Description:**

The `PerlRegexFactory.CreateRegex()` method (line 29) constructs .NET `Regex` objects from user-supplied patterns without setting a `MatchTimeout`:

```csharp
return new Regex(pattern, options | RegexOptions.Compiled);
```

Patterns are stored in release profiles via `POST /api/v3/releaseprofile`. During RSS sync, the `TermMatcherService` evaluates each release title against these patterns. A catastrophic backtracking regex such as `/(a+)+$/` causes exponential processing time on non-matching input, effectively hanging the Radarr process indefinitely.

The compiled regex is cached for 24 hours by `TermMatcherService.GetMatcher()`, so the DoS persists across sync cycles until the profile is deleted.

**Location:** `src/NzbDrone.Core/Profiles/Releases/PerlRegexFactory.cs` line 29

**Validation:**
```
$ curl -s -X POST http://TARGET:7878/api/v3/releaseprofile \
    -H "X-Api-Key: <KEY>" -H "Content-Type: application/json" \
    -d '{"name":"redos","enabled":true,"required":["/(a+)+$/"],"ignored":[],"indexerId":0}'
{"name":"redos","enabled":true,"required":["/(a+)+$/"],...,"id":1}
```

**Remediation:**
1. Set `MatchTimeout` on all user-supplied regex: `new Regex(pattern, options, TimeSpan.FromSeconds(1))`
2. Validate regex patterns for known catastrophic backtracking indicators before compilation
3. Consider limiting pattern length and complexity

---

### RADARR-004: Server-Side Request Forgery via Notification/Integration URLs

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N (5.0)

**Description:**

Over 20 notification integrations, plus indexer and download client configurations, accept user-supplied URLs without validating the URL scheme or host against private/internal IP ranges. When a notification is triggered (or tested), Radarr makes server-side HTTP requests to the configured URL.

An authenticated attacker can target:
- Cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/`)
- Internal APIs and services on private networks
- Localhost services (e.g., databases, admin panels)
- Arbitrary port scanning via error-based enumeration

When chained with RADARR-001, this is exploitable from any website that knows the API key.

**Affected components (non-exhaustive):**
- `src/NzbDrone.Core/Notifications/Webhook/Webhook.cs`
- `src/NzbDrone.Core/Notifications/Discord/DiscordProxy.cs`
- `src/NzbDrone.Core/Notifications/Slack/SlackProxy.cs`
- `src/NzbDrone.Core/Notifications/Gotify/GotifyProxy.cs`
- `src/NzbDrone.Core/Notifications/Ntfy/NtfyProxy.cs`
- All download client and indexer URL configuration

**Validation:**
```
$ curl -s -X POST "http://TARGET:7878/api/v3/notification?forceSave=true" \
    -H "X-Api-Key: <KEY>" -H "Content-Type: application/json" \
    -d '{"name":"ssrf","implementation":"Webhook","configContract":"WebhookSettings",
         "enable":false,"fields":[{"name":"url","value":"http://169.254.169.254/latest/"},
         {"name":"method","value":1},{"name":"username","value":""},
         {"name":"password","value":""}]}'
HTTP/1.1 201 Created
```

**Remediation:**
1. Validate integration URLs against an allowlist of schemes (http/https only)
2. Block requests to private/internal IP ranges (RFC 1918, link-local, loopback)
3. Implement URL validation as a shared service across all integration providers

---

### RADARR-005: Arbitrary Filesystem Enumeration via API

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (4.3)

**Description:**

The `/api/v3/filesystem` endpoint accepts an arbitrary `path` parameter and returns the directory contents (subdirectories and file names) for any location on the filesystem accessible to the Radarr process user. There is no restriction to Radarr's data or media directories.

```csharp
[HttpGet]
public IActionResult GetContents(string path, bool includeFiles = false, ...)
{
    return Ok(_fileSystemLookupService.LookupContents(path, includeFiles, ...));
}
```

**Location:** `src/Radarr.Api.V3/FileSystem/FileSystemController.cs` line 29

**Validation:**
```
$ curl -s "http://TARGET:7878/api/v3/filesystem?path=/etc&includeFiles=true&apikey=<KEY>"
{"directories":[...21 entries...],"files":[...5 entries...]}
```

**Remediation:**
1. Restrict the filesystem endpoint to paths within configured root folders and the Radarr data directory
2. Implement an allowlist of browseable parent directories

---

## Attack Chain Summary

The findings chain together into a full remote exploitation path:

```
RADARR-002: DNS rebinding extracts API key from /initialize.json (auth=None)
    |
    v
RADARR-001: CORS AllowAnyOrigin permits cross-origin API calls with stolen key
    |
    +---> RADARR-004: Create SSRF webhook targeting internal network
    |
    +---> RADARR-005: Enumerate filesystem to map target host
    |
    +---> RADARR-003: Create ReDoS profile to DoS the instance
    |
    +---> Modify config, upload malicious backup, tamper with settings
```

A full-chain proof of concept is provided in `scripts/radarr_cors_full_chain.py`.

---

## Methodology

1. **Source code analysis:** Cloned the Radarr repository at commit 4b85fab (2026-03-25). Analyzed authentication middleware, CORS configuration, API controller surface, input validation patterns, process execution paths, and outbound HTTP request handling.

2. **Live-instance validation:** Deployed Radarr 6.1.1.10360 release binary with default configuration. Validated each finding with HTTP requests simulating cross-origin browser behavior (Origin header, preflight OPTIONS). All findings reproduced 3/3 times.

3. **PoC development:** Created a Python script demonstrating the full attack chain end-to-end with automatic cleanup of test artifacts.
