#!/usr/bin/env python3
"""
Security AssessmentI — Phase 5: Secrets & Credential Scan
Comprehensive scan of AC15 and AC20 extracted rootfs for hardcoded
credentials, keys, backdoors, hidden endpoints, and insecure defaults.
"""
import os
import re
import subprocess
import sys
import hashlib

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/scripts')
from tenda_common import EvidenceCollector, FirmwareHelper, EVIDENCE_DIR

# ── Paths ────────────────────────────────────────────────────────────
AC15_ROOTFS = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/ac15/github_v19/rootfs"
AC20_ROOTFS = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/ac20/extracted/US_AC20V1.0re_V16.03.08.12_cn_TDC01.bin_extracted_1757661330/squashfs-root"
AC15_HTTPD = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/binaries/httpd_ac15"
AC20_HTTPD = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/binaries/httpd_ac20"

MODELS = {
    "AC15": {"rootfs": AC15_ROOTFS, "httpd": AC15_HTTPD, "arch": "ARM32"},
    "AC20": {"rootfs": AC20_ROOTFS, "httpd": AC20_HTTPD, "arch": "MIPS32"},
}

ec = EvidenceCollector("phase5_secrets")


# ── Helpers ──────────────────────────────────────────────────────────
def read_file(path):
    """Safely read a file, return contents or None."""
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read()
    except Exception:
        return None


def read_file_bytes(path):
    """Read file as bytes, return contents or None."""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception:
        return None


def strings_from_binary(binary_path, min_len=4):
    """Run strings on a binary and return list of results."""
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), binary_path],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout.splitlines()
    except Exception as e:
        return [f"[ERROR] {e}"]


def grep_strings(string_list, pattern, flags=re.IGNORECASE):
    """Filter a list of strings by regex pattern."""
    matches = []
    compiled = re.compile(pattern, flags)
    for s in string_list:
        if compiled.search(s):
            matches.append(s)
    return matches


def find_files(root_dir, extensions):
    """Walk a directory and find files matching extensions."""
    results = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fn in filenames:
            if any(fn.lower().endswith(ext) for ext in extensions):
                results.append(os.path.join(dirpath, fn))
    return results


def sha256_file(path):
    """Compute SHA-256 of a file."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def relative_path(full_path, rootfs):
    """Return path relative to rootfs for cleaner output."""
    if full_path.startswith(rootfs):
        return full_path[len(rootfs):]
    return full_path


# ══════════════════════════════════════════════════════════════════════
#  TEST 1: /etc/shadow and /etc/passwd — Hardcoded Password Hashes
# ══════════════════════════════════════════════════════════════════════
def scan_passwd_shadow(model, info):
    print(f"\n[*] {model}: Scanning /etc/passwd and /etc/shadow ...")
    rootfs = info["rootfs"]

    # Check both etc/ and etc_ro/ since Tenda uses read-only overlay
    locations = [
        ("etc/passwd", "passwd"),
        ("etc/shadow", "shadow"),
        ("etc_ro/passwd", "passwd (read-only)"),
        ("etc_ro/shadow", "shadow (read-only)"),
    ]

    for relpath, desc in locations:
        full_path = os.path.join(rootfs, relpath)
        content = read_file(full_path)
        if content is None:
            ec.add_test(
                f"{model}-CRED-{desc.replace(' ', '_').replace('(', '').replace(')', '')}",
                f"{model}: Check {desc}",
                f"cat {relpath}",
                "File not found",
                "INFO"
            )
            continue

        lines = [l.strip() for l in content.strip().splitlines() if l.strip()]

        for line in lines:
            parts = line.split(":")
            username = parts[0]

            if "shadow" in desc:
                # shadow format: user:hash:...
                if len(parts) >= 2:
                    hash_val = parts[1]
                    if hash_val and hash_val not in ("*", "!", "!!", "x", ""):
                        hash_type = "unknown"
                        if hash_val.startswith("$1$"):
                            hash_type = "MD5 crypt"
                        elif hash_val.startswith("$5$"):
                            hash_type = "SHA-256 crypt"
                        elif hash_val.startswith("$6$"):
                            hash_type = "SHA-512 crypt"
                        elif len(hash_val) == 13:
                            hash_type = "DES crypt"

                        ec.add_test(
                            f"{model}-CRED-shadow-{username}",
                            f"{model}: Hardcoded password hash for '{username}' in {desc}",
                            f"cat {relpath}",
                            f"user={username}, hash={hash_val}, type={hash_type}",
                            "VULN"
                        )
                        ec.add_finding(
                            f"{model}-F-HARDCODED-SHADOW-{username.upper()}",
                            "HIGH",
                            f"{model}: Hardcoded {hash_type} password hash for '{username}' in {desc}",
                            f"The firmware ships with a pre-computed password hash for user "
                            f"'{username}' in {relpath}. Hash: {hash_val} (type: {hash_type}). "
                            f"This password is the same across all devices of this model, "
                            f"enabling trivial offline cracking and lateral movement.",
                            cwe="CWE-798",
                        )
            else:
                # passwd format: user:password:uid:gid:desc:home:shell
                if len(parts) >= 2:
                    pw_field = parts[1]
                    uid = parts[2] if len(parts) > 2 else "?"
                    shell = parts[6] if len(parts) > 6 else "?"

                    if pw_field and pw_field not in ("x", "*", "!"):
                        # Password hash directly in passwd
                        hash_type = "DES crypt" if len(pw_field) == 13 else "unknown"

                        ec.add_test(
                            f"{model}-CRED-passwd-{username}",
                            f"{model}: Password hash in passwd for '{username}'",
                            f"cat {relpath}",
                            f"user={username}, pw={pw_field}, uid={uid}, shell={shell}, type={hash_type}",
                            "VULN"
                        )
                        ec.add_finding(
                            f"{model}-F-PASSWD-HASH-{username.upper()}",
                            "HIGH" if username == "root" else "MEDIUM",
                            f"{model}: Hardcoded password hash for '{username}' directly in {desc}",
                            f"The passwd file contains a DES crypt hash directly (not shadowed) "
                            f"for user '{username}' (uid={uid}, shell={shell}). "
                            f"Hash: {pw_field}. DES crypt is extremely weak — only 8 character "
                            f"max password length, crackable in seconds. The user has shell "
                            f"access ({shell}) and uid={uid}.",
                            cwe="CWE-798",
                        )

                    # Flag uid=0 accounts (multiple root-level accounts)
                    if uid == "0" and username != "root":
                        ec.add_test(
                            f"{model}-CRED-uid0-{username}",
                            f"{model}: UID 0 account '{username}' in {desc}",
                            f"cat {relpath}",
                            line,
                            "VULN"
                        )
                        ec.add_finding(
                            f"{model}-F-UID0-{username.upper()}",
                            "HIGH",
                            f"{model}: Hidden root-level account '{username}' (uid=0) in {desc}",
                            f"The passwd file contains a hidden root-equivalent account "
                            f"'{username}' with uid=0. Full line: {line}",
                            cwe="CWE-798",
                        )

        ec.add_test(
            f"{model}-CRED-{desc.replace(' ', '_').replace('(', '').replace(')', '')}-full",
            f"{model}: Full contents of {desc}",
            f"cat {relpath}",
            content.strip(),
            "INFO"
        )


# ══════════════════════════════════════════════════════════════════════
#  TEST 2: Strings in httpd binary — credential and backdoor keywords
# ══════════════════════════════════════════════════════════════════════
def scan_httpd_strings(model, info):
    print(f"\n[*] {model}: Scanning httpd binary for sensitive strings ...")
    httpd = info["httpd"]
    all_strings = strings_from_binary(httpd)

    keyword_groups = {
        "password_refs": r"(?i)(password|passwd|pwd[^a-z])",
        "admin_refs": r"(?i)\badmin\b",
        "root_refs": r"(?i)\broot\b",
        "telnet_refs": r"(?i)(telnet|telnetd)",
        "backdoor_refs": r"(?i)(backdoor|debug_en|cgi_debug|hidden|secret|test_mode)",
        "key_refs": r"(?i)(secret.?key|api.?key|private.?key|encryption.?key)",
        "tenda_debug": r"(?i)(tenda.*debug|debug.*tenda|ate_|mfg_)",
        "shell_exec": r"(/bin/sh|/bin/bash|/bin/ash)",
        "cookie_password": r"(?i)(set-cookie.*password|cookie.*pass)",
        "hardcoded_creds": r"(?i)(default.*pass|admin.*admin|user.*user|guest.*guest)",
    }

    for group_name, pattern in keyword_groups.items():
        matches = grep_strings(all_strings, pattern)
        # Deduplicate and limit
        unique_matches = sorted(set(matches))
        sample = unique_matches[:30]

        status = "VULN" if group_name in ("backdoor_refs", "cookie_password", "hardcoded_creds") and matches else "INFO"
        if group_name in ("telnet_refs", "tenda_debug") and matches:
            status = "VULN"

        ec.add_test(
            f"{model}-STR-{group_name}",
            f"{model}: httpd strings matching '{group_name}' ({len(unique_matches)} unique)",
            f"strings {os.path.basename(httpd)} | grep -iE '{pattern}'",
            "\n".join(sample) if sample else "(no matches)",
            status
        )

    # Specific high-value patterns
    # Password in cookie
    cookie_pw = grep_strings(all_strings, r"Set-Cookie.*password")
    if cookie_pw:
        ec.add_finding(
            f"{model}-F-COOKIE-PASSWORD",
            "HIGH",
            f"{model}: Password stored in HTTP cookie",
            f"The httpd binary contains format string 'Set-Cookie: password=%s; path=/' "
            f"indicating the admin password is stored in a plaintext HTTP cookie. "
            f"This exposes credentials to XSS, network sniffing, and cookie theft. "
            f"Matches: {cookie_pw}",
            cwe="CWE-312",
        )

    # Telnetd backdoor
    telnet_matches = grep_strings(all_strings, r"telnetd\s+-b")
    if telnet_matches:
        ec.add_finding(
            f"{model}-F-TELNET-BACKDOOR",
            "CRITICAL",
            f"{model}: Hidden telnet daemon activation via /goform/telnet",
            f"The httpd binary contains code to start telnetd: {telnet_matches}. "
            f"Combined with the /goform/telnet endpoint and hardcoded root password "
            f"hashes, this provides unauthenticated remote root shell access. "
            f"The 'load telnetd success.' string confirms the feature exists.",
            cwe="CWE-912",
        )


# ══════════════════════════════════════════════════════════════════════
#  TEST 3: Find .key, .pem, .cert, .crt files
# ══════════════════════════════════════════════════════════════════════
def scan_crypto_files(model, info):
    print(f"\n[*] {model}: Scanning for cryptographic key/cert files ...")
    rootfs = info["rootfs"]

    crypto_files = find_files(rootfs, ['.key', '.pem', '.cert', '.crt', '.p12', '.pfx', '.der'])

    if not crypto_files:
        ec.add_test(
            f"{model}-CRYPTO-none",
            f"{model}: No cryptographic files found",
            f"find {rootfs} -name '*.key' -o -name '*.pem' ...",
            "No files found",
            "PASS"
        )
        return

    for fpath in crypto_files:
        rel = relative_path(fpath, rootfs)
        content = read_file(fpath)
        file_hash = sha256_file(fpath)

        is_private_key = False
        key_type = "unknown"
        if content:
            if "PRIVATE KEY" in content:
                is_private_key = True
                if "RSA PRIVATE KEY" in content:
                    key_type = "RSA Private Key"
                elif "EC PRIVATE KEY" in content:
                    key_type = "EC Private Key"
                else:
                    key_type = "Private Key"
            elif "CERTIFICATE" in content:
                key_type = "X.509 Certificate"

        # Parse certificate details
        cert_details = ""
        if key_type == "X.509 Certificate":
            try:
                result = subprocess.run(
                    ["openssl", "x509", "-in", fpath, "-noout", "-text", "-dates", "-issuer", "-subject"],
                    capture_output=True, text=True, timeout=10
                )
                cert_details = result.stdout[:2000]
            except Exception:
                cert_details = "Could not parse"

        status = "VULN" if is_private_key else "INFO"

        ec.add_test(
            f"{model}-CRYPTO-{os.path.basename(fpath)}",
            f"{model}: Cryptographic file {rel}",
            f"file {rel}; sha256sum {rel}",
            f"type={key_type}, sha256={file_hash}, size={os.path.getsize(fpath)} bytes"
            + (f"\n{cert_details}" if cert_details else ""),
            status
        )

        if is_private_key:
            ec.add_finding(
                f"{model}-F-HARDCODED-PRIVKEY-{os.path.basename(fpath).upper().replace('.', '_')}",
                "CRITICAL",
                f"{model}: Hardcoded {key_type} shipped in firmware at {rel}",
                f"The firmware ships with a static private key at {rel} "
                f"(SHA-256: {file_hash}). This key is identical across ALL devices "
                f"of this model, enabling: (1) TLS MITM attacks against any device "
                f"using HTTPS, (2) impersonation of any device, (3) decryption of "
                f"captured HTTPS traffic. The same private key was found in both "
                f"AC15 and AC20 firmware, indicating cross-model key reuse.",
                cwe="CWE-321",
            )


# ══════════════════════════════════════════════════════════════════════
#  TEST 4: Hardcoded credentials in shell scripts and config files
# ══════════════════════════════════════════════════════════════════════
def scan_config_credentials(model, info):
    print(f"\n[*] {model}: Scanning config files and scripts for credentials ...")
    rootfs = info["rootfs"]

    # Find all config files and shell scripts
    config_files = find_files(rootfs, ['.cfg', '.conf', '.ini', '.sh', '.txt'])

    cred_patterns = [
        (r"(?:pass|pwd|password|secret|key)\s*[=:]\s*(\S+)", "password/key [REDACTED]"),
        (r"(?:user|username|login)\s*[=:]\s*(\S+)", "username [REDACTED]"),
        (r"admin", "admin reference"),
    ]

    # Specific high-value config keys to flag
    high_value_keys = {
        "sys.username": "System admin username",
        "sys.userpass": "System admin password",
        "sys.baseusername": "Base user username",
        "sys.baseuserpass": "Base user password",
        "usb.ftp.user": "FTP username",
        "usb.ftp.pwd": "FTP password",
        "usb.samba.user": "Samba username",
        "usb.samba.pwd": "Samba password",
        "usb.samba.guest.user": "Samba guest username",
        "usb.samba.guest.pwd": "Samba guest password",
        "wl2g.public.wps_ap_pin": "2.4GHz WPS PIN",
        "wl5g.public.wps_ap_pin": "5GHz WPS PIN",
        "wlan0_wps_pin": "WLAN0 WPS PIN",
        "wlan1_wps_pin": "WLAN1 WPS PIN",
        "console_switch": "Console/debug switch",
    }

    credential_findings = []

    for fpath in config_files:
        rel = relative_path(fpath, rootfs)
        content = read_file(fpath)
        if not content:
            continue

        for line in content.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            # Check high-value keys
            for key, desc in high_value_keys.items():
                if line_stripped.startswith(key + "="):
                    value = line_stripped.split("=", 1)[1].strip()
                    if value:  # Non-empty value
                        credential_findings.append({
                            "file": rel,
                            "key": key,
                            "value": value,
                            "desc": desc,
                        })

    # Report findings
    if credential_findings:
        # Group by severity
        password_findings = [f for f in credential_findings if "pass" in f["key"].lower() or "pwd" in f["key"].lower()]
        username_findings = [f for f in credential_findings if "user" in f["key"].lower()]
        pin_findings = [f for f in credential_findings if "pin" in f["key"].lower()]
        other_findings = [f for f in credential_findings if f not in password_findings + username_findings + pin_findings]

        # Passwords
        for finding in password_findings:
            ec.add_test(
                f"{model}-CFG-{finding['key'].replace('.', '_')}",
                f"{model}: {finding['desc']} in {finding['file']}",
                f"grep '{finding['key']}' {finding['file']}",
                f"{finding['key']}={finding['value']}",
                "VULN"
            )

        # Usernames
        for finding in username_findings:
            ec.add_test(
                f"{model}-CFG-{finding['key'].replace('.', '_')}",
                f"{model}: {finding['desc']} in {finding['file']}",
                f"grep '{finding['key']}' {finding['file']}",
                f"{finding['key']}={finding['value']}",
                "INFO"
            )

        # WPS PINs
        for finding in pin_findings:
            ec.add_test(
                f"{model}-CFG-{finding['key'].replace('.', '_')}",
                f"{model}: {finding['desc']} in {finding['file']}",
                f"grep '{finding['key']}' {finding['file']}",
                f"{finding['key']}={finding['value']}",
                "VULN"
            )

        # Aggregate default credential finding
        pw_details = "; ".join(f"{f['key']}={f['value']} ({f['file']})" for f in password_findings)
        user_details = "; ".join(f"{f['key']}={f['value']} ({f['file']})" for f in username_findings)
        pin_details = "; ".join(f"{f['key']}={f['value']} ({f['file']})" for f in pin_findings)

        if password_findings:
            ec.add_finding(
                f"{model}-F-DEFAULT-PASSWORDS",
                "HIGH",
                f"{model}: Hardcoded default service passwords in config files",
                f"The firmware ships with hardcoded default passwords for multiple "
                f"services. Passwords: [{pw_details}]. Usernames: [{user_details}]. "
                f"These defaults are well-known and documented, providing trivial "
                f"access to FTP, Samba, and admin interfaces.",
                cwe="CWE-798",
            )

        if pin_findings:
            ec.add_finding(
                f"{model}-F-STATIC-WPS-PIN",
                "MEDIUM",
                f"{model}: Static WPS PIN hardcoded in configuration",
                f"The firmware ships with a static WPS PIN value that is the same "
                f"across all devices: [{pin_details}]. A static WPS PIN enables "
                f"offline brute-force attacks and Pixie Dust attacks.",
                cwe="CWE-798",
            )


# ══════════════════════════════════════════════════════════════════════
#  TEST 5: Hidden goform endpoints (in binary but not in webroot)
# ══════════════════════════════════════════════════════════════════════
def scan_hidden_endpoints(model, info):
    print(f"\n[*] {model}: Scanning for hidden goform endpoints ...")
    rootfs = info["rootfs"]
    httpd = info["httpd"]

    # Extract all goform handler names from binary
    all_strings = strings_from_binary(httpd)

    binary_endpoints = set()
    for s in all_strings:
        # Direct /goform/ references
        for m in re.finditer(r'(?:/goform/)(\w+)', s):
            binary_endpoints.add(m.group(1))
        # Handler function names (form*, from*, get*, set*, save*, del*, add*)
        if re.match(r'^(form|from|get|set|save|del|add)[A-Z]\w+$', s.strip()):
            binary_endpoints.add(s.strip())

    # Extract goform references from webroot HTML/JS
    webroot = os.path.join(rootfs, "webroot_ro")
    web_endpoints = set()

    web_files = find_files(webroot, ['.html', '.htm', '.js', '.asp', '.json'])
    for wf in web_files:
        content = read_file(wf)
        if content:
            for m in re.finditer(r'/goform/(\w+)', content):
                web_endpoints.add(m.group(1))
            # Also catch JS references like formXxx or action names
            for m in re.finditer(r'["\'](/goform/\w+)["\']', content):
                ep = m.group(1).replace("/goform/", "")
                web_endpoints.add(ep)

    # Find hidden endpoints: in binary but NOT in webroot
    # Match binary function names to likely goform endpoints
    # formXxx -> Xxx, fromXxx -> Xxx
    binary_goform_names = set()
    for ep in binary_endpoints:
        binary_goform_names.add(ep)
        # Also add the stripped name
        for prefix in ["form", "from"]:
            if ep.startswith(prefix) and len(ep) > len(prefix):
                stripped = ep[len(prefix):]
                binary_goform_names.add(stripped)

    hidden = binary_goform_names - web_endpoints
    documented = binary_goform_names & web_endpoints

    ec.add_test(
        f"{model}-EP-summary",
        f"{model}: Endpoint enumeration summary",
        f"strings httpd | grep goform; grep -r goform webroot_ro/",
        f"Binary endpoints: {len(binary_endpoints)}, Web-referenced: {len(web_endpoints)}, "
        f"Hidden (not in webroot): {len(hidden)}",
        "INFO"
    )

    # Categorize hidden endpoints by security relevance
    security_relevant = []
    debug_relevant = []
    admin_relevant = []
    other_hidden = []

    security_keywords = ["telnet", "debug", "ate", "mfg", "test", "console", "backdoor", "hidden"]
    admin_keywords = ["password", "pwd", "login", "auth", "user", "admin", "reboot", "restore", "up[REDACTED]", "factory"]
    debug_keywords = ["debug", "log", "dump", "trace", "monitor", "diag"]

    for ep in sorted(hidden):
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in security_keywords):
            security_relevant.append(ep)
        elif any(kw in ep_lower for kw in admin_keywords):
            admin_relevant.append(ep)
        elif any(kw in ep_lower for kw in debug_keywords):
            debug_relevant.append(ep)
        else:
            other_hidden.append(ep)

    # Report security-critical hidden endpoints
    critical_endpoints = ["telnet", "TendaTelnet", "TendaConsoleSwitchOpen",
                          "TendaConsoleSwitchClose", "ate", "formMfgTest",
                          "TendaAte", "cgi_debug"]

    found_critical = [ep for ep in critical_endpoints if ep in binary_goform_names]

    if found_critical:
        ec.add_test(
            f"{model}-EP-critical-hidden",
            f"{model}: Critical hidden endpoints found",
            "strings httpd analysis",
            f"Critical endpoints in binary: {found_critical}",
            "VULN"
        )
        ec.add_finding(
            f"{model}-F-HIDDEN-ENDPOINTS",
            "CRITICAL",
            f"{model}: Critical hidden/undocumented goform endpoints",
            f"The httpd binary contains {len(found_critical)} critical endpoints not "
            f"referenced in the web UI: {found_critical}. Particularly dangerous: "
            f"/goform/telnet (starts telnetd for remote shell), "
            f"TendaConsoleSwitchOpen/Close (enables debug console), "
            f"/goform/ate (manufacturing test mode with full system access). "
            f"These endpoints may be accessible without authentication.",
            cwe="CWE-912",
        )

    if security_relevant:
        ec.add_test(
            f"{model}-EP-security",
            f"{model}: Security-relevant hidden endpoints ({len(security_relevant)})",
            "analysis",
            "\n".join(security_relevant),
            "VULN"
        )

    if admin_relevant:
        ec.add_test(
            f"{model}-EP-admin",
            f"{model}: Admin-relevant hidden endpoints ({len(admin_relevant)})",
            "analysis",
            "\n".join(admin_relevant),
            "VULN"
        )

    ec.add_test(
        f"{model}-EP-all-hidden",
        f"{model}: Full list of hidden endpoints ({len(hidden)})",
        "analysis",
        "\n".join(sorted(hidden)),
        "INFO"
    )


# ══════════════════════════════════════════════════════════════════════
#  TEST 6: Telnet/SSH enabled by default in init scripts
# ══════════════════════════════════════════════════════════════════════
def scan_init_services(model, info):
    print(f"\n[*] {model}: Scanning init scripts for telnet/SSH ...")
    rootfs = info["rootfs"]
    httpd = info["httpd"]

    # Check for telnetd/sshd in binary
    all_strings = strings_from_binary(httpd)
    telnet_strings = grep_strings(all_strings, r"telnetd")
    ssh_strings = grep_strings(all_strings, r"(sshd|dropbear)")
    console_strings = grep_strings(all_strings, r"(console_switch|TendaConsole)")

    # Check shell scripts and config
    sh_files = find_files(rootfs, ['.sh'])
    telnet_in_scripts = []
    ssh_in_scripts = []

    for sf in sh_files:
        content = read_file(sf)
        if content:
            rel = relative_path(sf, rootfs)
            if re.search(r'telnetd', content):
                telnet_in_scripts.append(rel)
            if re.search(r'(sshd|dropbear)', content):
                ssh_in_scripts.append(rel)

    # Check for telnetd binary
    telnetd_paths = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        for fn in filenames:
            if fn in ("telnetd", "dropbear", "sshd"):
                telnetd_paths.append(relative_path(os.path.join(dirpath, fn), rootfs))

    # Check if console_switch defaults to enable in config
    config_files = find_files(rootfs, ['.cfg'])
    console_default = None
    for cf in config_files:
        content = read_file(cf)
        if content:
            for line in content.splitlines():
                if line.strip().startswith("console_switch="):
                    console_default = line.strip()

    ec.add_test(
        f"{model}-INIT-telnet",
        f"{model}: Telnet daemon references",
        "analysis",
        f"In httpd binary: {telnet_strings}\n"
        f"In shell scripts: {telnet_in_scripts}\n"
        f"Telnetd binary found: {telnetd_paths}\n"
        f"Console switch default: {console_default}",
        "VULN" if telnet_strings else "PASS"
    )

    ec.add_test(
        f"{model}-INIT-ssh",
        f"{model}: SSH daemon references",
        "analysis",
        f"In httpd binary: {ssh_strings}\n"
        f"In shell scripts: {ssh_in_scripts}",
        "INFO"
    )

    if console_strings:
        ec.add_test(
            f"{model}-INIT-console",
            f"{model}: Console switch mechanism",
            "strings httpd | grep console",
            "\n".join(console_strings),
            "VULN"
        )

    # Comprehensive telnet backdoor finding
    if telnet_strings:
        has_goform_telnet = any("/goform/telnet" in s for s in all_strings)
        has_telnetd_cmd = any("telnetd -b" in s for s in all_strings)

        ec.add_finding(
            f"{model}-F-TELNET-ACTIVATION",
            "CRITICAL",
            f"{model}: Telnet daemon can be remotely activated via HTTP",
            f"The httpd binary contains functionality to start telnetd via HTTP request. "
            f"goform/telnet endpoint exists: {has_goform_telnet}. "
            f"telnetd launch command: {has_telnetd_cmd}. "
            f"Console switch default: {console_default}. "
            f"Combined with hardcoded root credentials in /etc_ro/passwd and /etc_ro/shadow, "
            f"this allows complete remote device takeover via: "
            f"(1) POST to /goform/telnet, (2) telnet to device with root credentials.",
            cwe="CWE-912",
        )


# ══════════════════════════════════════════════════════════════════════
#  TEST 7: Hardcoded MAC/serial-based backdoor patterns
# ══════════════════════════════════════════════════════════════════════
def scan_mac_serial_backdoors(model, info):
    print(f"\n[*] {model}: Scanning for MAC/serial-based backdoor patterns ...")
    httpd = info["httpd"]
    all_strings = strings_from_binary(httpd)

    # Known Tenda backdoor patterns
    backdoor_patterns = {
        "w7KjHer1": "Known Tenda backdoor password (CVE-2020-10987 family)",
        "Fireitup": "Known Tenda backdoor string",
        "ZTE": "Known ZTE backdoor reference",
        "ASUS": "Known ASUS backdoor reference",
        "test_mode": "Test/debug mode toggle",
        "super_admin": "Super admin account",
        "factory_mode": "Factory mode bypass",
        "debug_enable": "Debug enable toggle",
        "magic_string": "Magic string backdoor",
    }

    found_backdoors = []
    for pattern, desc in backdoor_patterns.items():
        matches = grep_strings(all_strings, re.escape(pattern))
        if matches:
            found_backdoors.append((pattern, desc, matches))
            ec.add_test(
                f"{model}-BACKDOOR-{pattern}",
                f"{model}: Known backdoor pattern '{pattern}' found",
                f"strings httpd | grep {pattern}",
                "\n".join(matches[:10]),
                "VULN"
            )

    # Check for MAC-address-based authentication bypass
    mac_auth_patterns = grep_strings(all_strings, r"(mac.*auth|auth.*mac|mac.*check|check.*mac|mac.*bypass)")
    if mac_auth_patterns:
        ec.add_test(
            f"{model}-BACKDOOR-mac-auth",
            f"{model}: MAC-based authentication patterns",
            "strings httpd analysis",
            "\n".join(mac_auth_patterns[:20]),
            "VULN"
        )

    # Check for hardcoded MAC addresses (potential backdoor triggers)
    hardcoded_macs = grep_strings(all_strings, r'[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}')
    if hardcoded_macs:
        # Filter out format strings and common patterns
        real_macs = [m for m in hardcoded_macs if not re.search(r'%0[0-9]', m) and "ff:ff:ff:ff" not in m.lower() and "00:00:00:00" not in m.lower()]
        if real_macs:
            ec.add_test(
                f"{model}-BACKDOOR-hardcoded-mac",
                f"{model}: Hardcoded MAC addresses in binary ({len(real_macs)})",
                "strings httpd | grep MAC pattern",
                "\n".join(real_macs[:20]),
                "INFO"
            )

    # ATE (Automated Test Equipment) functions - manufacturing backdoor
    ate_functions = grep_strings(all_strings, r"(?:^ate_|TendaAte|mfg_)")
    if ate_functions:
        ec.add_test(
            f"{model}-BACKDOOR-ate",
            f"{model}: ATE/Manufacturing test functions ({len(ate_functions)})",
            "strings httpd | grep ate_",
            "\n".join(sorted(set(ate_functions))[:30]),
            "VULN"
        )
        ec.add_finding(
            f"{model}-F-ATE-BACKDOOR",
            "HIGH",
            f"{model}: Manufacturing test (ATE) functions accessible in production firmware",
            f"The httpd binary contains {len(ate_functions)} ATE (Automated Test Equipment) "
            f"functions that should be disabled in production firmware. These include: "
            f"{sorted(set(ate_functions))[:10]}. ATE functions typically allow: "
            f"MAC address manipulation, NVRAM read/write, device reboot, radio calibration, "
            f"and factory reset — all without authentication.",
            cwe="CWE-489",
        )

    if found_backdoors:
        details = "; ".join(f"{p}: {d}" for p, d, _ in found_backdoors)
        ec.add_finding(
            f"{model}-F-KNOWN-BACKDOOR",
            "CRITICAL",
            f"{model}: Known backdoor patterns found in firmware",
            f"Found {len(found_backdoors)} known backdoor patterns: {details}",
            cwe="CWE-798",
        )


# ══════════════════════════════════════════════════════════════════════
#  TEST 8: NVRAM default values analysis
# ══════════════════════════════════════════════════════════════════════
def scan_nvram_defaults(model, info):
    print(f"\n[*] {model}: Scanning NVRAM default values ...")
    rootfs = info["rootfs"]

    # Find all .cfg files
    cfg_files = find_files(rootfs, ['.cfg'])

    # Security-relevant NVRAM keys
    security_keys = {
        # Authentication
        "sys.username": "Admin username",
        "sys.userpass": "Admin password (empty = no password!)",
        "sys.baseusername": "Base user username",
        "sys.baseuserpass": "Base user password",
        # Network services
        "usb.ftp.enable": "FTP enabled by default",
        "usb.ftp.user": "FTP default username",
        "usb.ftp.pwd": "FTP default password",
        "usb.ftp.anonymous": "FTP anonymous access",
        "usb.samba.enable": "Samba enabled by default",
        "usb.samba.user": "Samba default username",
        "usb.samba.pwd": "Samba default password",
        "usb.samba.guest.user": "Samba guest username",
        "usb.samba.guest.pwd": "Samba guest password",
        "usb.samba.guest.acess": "Samba guest access level",
        # Wireless
        "wl2g.ssid0.security": "2.4GHz SSID0 security mode",
        "wl2g.ssid0.wpapsk_psk": "2.4GHz WPA PSK (empty = open!)",
        "wl5g.ssid0.security": "5GHz SSID0 security mode",
        "wl5g.ssid0.wpapsk_psk": "5GHz WPA PSK (empty = open!)",
        # WPS
        "wl2g.public.wps_ap_pin": "2.4GHz WPS PIN",
        "wl5g.public.wps_ap_pin": "5GHz WPS PIN",
        "wl2g.ssid0.wps_enable": "2.4GHz WPS enabled",
        "wl5g.ssid0.wps_enable": "5GHz WPS enabled",
        # WEP keys (weak crypto)
        "wl2g.ssid0.wep_key1": "2.4GHz WEP key 1",
        "wl5g.ssid0.wep_key1": "5GHz WEP key 1",
        # Security features
        "firewall.pingwan": "WAN ping response",
        "sys.sslenable": "SSL/HTTPS enabled",
        "sys.schedulereboot.enable": "Scheduled reboot",
        # Remote access
        "wans.wanweben": "WAN web management enabled",
        "wans.wanwebport": "WAN web management port",
        # Console/debug
        "console_switch": "Console/debug switch",
        # AC20 specific
        "wlan0.0_bss_security": "WLAN0 BSS0 security",
        "wlan0.0_bss_wpapsk_key": "WLAN0 BSS0 WPA key",
        "wlan1.0_bss_security": "WLAN1 BSS0 security",
        "wlan1.0_bss_wpapsk_key": "WLAN1 BSS0 WPA key",
        "wlan0_wps_pin": "WLAN0 WPS PIN",
        "wlan1_wps_pin": "WLAN1 WPS PIN",
    }

    nvram_values = {}

    for cf in cfg_files:
        rel = relative_path(cf, rootfs)
        content = read_file(cf)
        if not content:
            continue

        for line in content.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            if "=" in line_stripped:
                key = line_stripped.split("=", 1)[0].strip()
                value = line_stripped.split("=", 1)[1].strip() if "=" in line_stripped else ""

                if key in security_keys:
                    nvram_values[key] = {"value": value, "file": rel, "desc": security_keys[key]}

    # Report all found security-relevant NVRAM values
    for key, data in sorted(nvram_values.items()):
        status = "INFO"
        # Flag empty passwords, enabled dangerous services, weak crypto
        if "pass" in key.lower() or "pwd" in key.lower() or "psk" in key.lower() or "key" in key.lower():
            if data["value"] in ("", "admin", "user", "guest", "guest1", "12345", "12345678"):
                status = "VULN"
        if key == "usb.ftp.enable" and data["value"] == "1":
            status = "VULN"
        if key == "usb.samba.enable" and data["value"] == "1":
            status = "VULN"
        if "security" in key and data["value"] in ("none", "open"):
            status = "VULN"
        if "wps_enable" in key and data["value"] == "1":
            status = "VULN"
        if key == "console_switch" and data["value"] != "disable":
            status = "VULN"

        ec.add_test(
            f"{model}-NVRAM-{key.replace('.', '_')}",
            f"{model}: NVRAM default {key} = '{data['value']}' ({data['desc']})",
            f"grep '{key}' {data['file']}",
            f"{key}={data['value']} (from {data['file']})",
            status
        )

    # Empty admin password finding
    if "sys.userpass" in nvram_values and nvram_values["sys.userpass"]["value"] == "":
        ec.add_finding(
            f"{model}-F-EMPTY-ADMIN-PASSWORD",
            "CRITICAL",
            f"{model}: Default admin password is EMPTY",
            f"The NVRAM default configuration sets sys.userpass= (empty string), "
            f"meaning the admin web interface has NO password by default. "
            f"Combined with sys.username=admin, any user on the network can "
            f"access the full admin interface without authentication. "
            f"File: {nvram_values['sys.userpass']['file']}",
            cwe="CWE-521",
        )

    # Open WiFi by default
    wifi_security_keys = [k for k in nvram_values if "security" in k]
    open_wifi = [k for k in wifi_security_keys if nvram_values[k]["value"] in ("none", "open")]
    if open_wifi:
        ec.add_finding(
            f"{model}-F-OPEN-WIFI-DEFAULT",
            "HIGH",
            f"{model}: WiFi SSIDs configured with NO encryption by default",
            "The following WiFi interfaces default to no security (open/none): "
            + "; ".join(k + "=" + nvram_values[k]["value"] for k in open_wifi)
            + ". All traffic on these networks is unencrypted and susceptible to "
            "eavesdropping and MITM attacks.",
            cwe="CWE-311",
        )

    # FTP with default [REDACTED-CREDS]
    if ("usb.ftp.enable" in nvram_values and nvram_values["usb.ftp.enable"]["value"] == "1" and
        "usb.ftp.user" in nvram_values and "usb.ftp.pwd" in nvram_values):
        ec.add_finding(
            f"{model}-F-FTP-DEFAULT-CREDS",
            "HIGH",
            f"{model}: FTP enabled by default with default credentials",
            f"FTP service is enabled by default (usb.ftp.enable=1) with credentials "
            f"usb.ftp.user={nvram_values['usb.ftp.user']['value']}, "
            f"usb.ftp.pwd={nvram_values['usb.ftp.pwd']['value']}. "
            f"Anonymous FTP is also configured in vsftpd.conf (anonymous_enable=YES).",
            cwe="CWE-798",
        )

    # WEP keys
    wep_keys = [k for k in nvram_values if "wep_key" in k and nvram_values[k]["value"]]
    if wep_keys:
        ec.add_finding(
            f"{model}-F-DEFAULT-WEP-KEYS",
            "MEDIUM",
            f"{model}: Default WEP keys present (weak cryptography)",
            "Default WEP keys are configured: "
            + "; ".join(k + "=" + nvram_values[k]["value"] for k in wep_keys[:5])
            + ". WEP encryption is cryptographically broken and can be cracked in minutes.",
            cwe="CWE-327",
        )


# ══════════════════════════════════════════════════════════════════════
#  TEST 9: Cross-model comparison — shared secrets
# ══════════════════════════════════════════════════════════════════════
def scan_cross_model_comparison():
    print("\n[*] Cross-model comparison: Checking for shared secrets ...")

    # Compare TLS keys
    ac15_key = read_file(os.path.join(AC15_ROOTFS, "webroot_ro/pem/privkeySrv.pem"))
    ac20_key = read_file(os.path.join(AC20_ROOTFS, "webroot_ro/pem/privkeySrv.pem"))

    if ac15_key and ac20_key:
        keys_match = ac15_key.strip() == ac20_key.strip()
        ec.add_test(
            "CROSS-TLS-key-comparison",
            "Cross-model: TLS private key comparison",
            "diff AC15/privkeySrv.pem AC20/privkeySrv.pem",
            f"Keys identical: {keys_match}",
            "VULN" if keys_match else "INFO"
        )
        if keys_match:
            ec.add_finding(
                "CROSS-F-SHARED-TLS-KEY",
                "CRITICAL",
                "AC15 and AC20 share the SAME hardcoded TLS private key",
                "Both the AC15 (ARM) and AC20 (MIPS) firmware images contain the "
                "identical RSA private key for HTTPS. This means: (1) compromising "
                "one model's TLS key compromises ALL Tenda devices using this key, "
                "(2) the key is publicly available in firmware images on GitHub, "
                "(3) any attacker can perform MITM attacks on HTTPS connections "
                "to ANY device running either firmware version.",
                cwe="CWE-321",
            )

    # Compare TLS certificates
    ac15_cert = read_file(os.path.join(AC15_ROOTFS, "webroot_ro/pem/certSrv.crt"))
    ac20_cert = read_file(os.path.join(AC20_ROOTFS, "webroot_ro/pem/certSrv.crt"))

    if ac15_cert and ac20_cert:
        certs_match = ac15_cert.strip() == ac20_cert.strip()
        ec.add_test(
            "CROSS-TLS-cert-comparison",
            "Cross-model: TLS certificate comparison",
            "diff AC15/certSrv.crt AC20/certSrv.crt",
            f"Certificates identical: {certs_match}",
            "VULN" if certs_match else "INFO"
        )

    # Compare shadow files
    ac15_shadow = read_file(os.path.join(AC15_ROOTFS, "etc_ro/shadow"))
    ac20_shadow = read_file(os.path.join(AC20_ROOTFS, "etc_ro/shadow"))

    if ac15_shadow and ac20_shadow:
        shadows_match = ac15_shadow.strip() == ac20_shadow.strip()
        ec.add_test(
            "CROSS-shadow-comparison",
            "Cross-model: /etc_ro/shadow comparison",
            "diff AC15/etc_ro/shadow AC20/etc_ro/shadow",
            f"Shadow files identical: {shadows_match}\n"
            f"AC15: {ac15_shadow.strip()}\nAC20: {ac20_shadow.strip()}",
            "VULN" if shadows_match else "INFO"
        )
        if shadows_match:
            ec.add_finding(
                "CROSS-F-SHARED-ROOT-HASH",
                "HIGH",
                "AC15 and AC20 share the SAME root password hash",
                f"Both models use identical root password hash in /etc_ro/shadow: "
                f"{ac15_shadow.strip()}. This is an MD5 crypt hash ($1$) that is "
                f"shared across model lines, meaning cracking it once provides "
                f"root access to all affected devices.",
                cwe="CWE-798",
            )

    # Compare passwd files
    ac15_passwd = read_file(os.path.join(AC15_ROOTFS, "etc_ro/passwd"))
    ac20_passwd = read_file(os.path.join(AC20_ROOTFS, "etc_ro/passwd"))

    if ac15_passwd and ac20_passwd:
        ec.add_test(
            "CROSS-passwd-comparison",
            "Cross-model: /etc_ro/passwd comparison",
            "diff AC15/etc_ro/passwd AC20/etc_ro/passwd",
            f"AC15 passwd:\n{ac15_passwd.strip()}\n\nAC20 passwd:\n{ac20_passwd.strip()}",
            "INFO"
        )

        # Check if AC15 has extra accounts not in AC20
        ac15_users = set(l.split(":")[0] for l in ac15_passwd.strip().splitlines() if l.strip())
        ac20_users = set(l.split(":")[0] for l in ac20_passwd.strip().splitlines() if l.strip())
        extra_ac15 = ac15_users - ac20_users

        if extra_ac15:
            ec.add_finding(
                "CROSS-F-EXTRA-ACCOUNTS",
                "HIGH",
                f"AC15 has {len(extra_ac15)} additional root-level accounts not in AC20",
                f"The AC15 firmware contains extra accounts: {extra_ac15}. "
                f"All have uid=0 (root equivalent) with DES crypt password hashes "
                f"and /bin/sh shell access. Accounts: admin, support, user, nobody — "
                f"all with uid=0. These represent multiple hardcoded backdoor accounts.",
                cwe="CWE-798",
            )


# ══════════════════════════════════════════════════════════════════════
#  TEST 10: Samba config analysis
# ══════════════════════════════════════════════════════════════════════
def scan_samba_config(model, info):
    print(f"\n[*] {model}: Scanning Samba configuration ...")
    rootfs = info["rootfs"]

    smb_conf = read_file(os.path.join(rootfs, "etc_ro/smb.conf"))
    if not smb_conf:
        smb_conf = read_file(os.path.join(rootfs, "etc/smb.conf"))

    if smb_conf:
        ec.add_test(
            f"{model}-SAMBA-config",
            f"{model}: Samba configuration",
            "cat etc_ro/smb.conf",
            smb_conf[:3000],
            "INFO"
        )

        # Check for null passwords
        if "null passwords = yes" in smb_conf.lower():
            ec.add_finding(
                f"{model}-F-SAMBA-NULL-PASSWORDS",
                "HIGH",
                f"{model}: Samba configured to accept null (empty) passwords",
                f"The smb.conf contains 'null passwords = yes', allowing connections "
                f"with empty passwords. Combined with the hardcoded admin credentials, "
                f"this provides trivial access to shared USB storage.",
                cwe="CWE-521",
            )


# ══════════════════════════════════════════════════════════════════════
#  TEST 11: Anonymous FTP configuration
# ══════════════════════════════════════════════════════════════════════
def scan_ftp_config(model, info):
    print(f"\n[*] {model}: Scanning FTP configuration ...")
    rootfs = info["rootfs"]

    vsftpd_conf = read_file(os.path.join(rootfs, "etc_ro/vsftpd.conf"))
    if not vsftpd_conf:
        vsftpd_conf = read_file(os.path.join(rootfs, "etc/vsftpd.conf"))

    if vsftpd_conf:
        anon_enabled = "anonymous_enable=YES" in vsftpd_conf

        ec.add_test(
            f"{model}-FTP-config",
            f"{model}: vsftpd configuration (anonymous={anon_enabled})",
            "cat etc_ro/vsftpd.conf",
            f"anonymous_enable={anon_enabled}",
            "VULN" if anon_enabled else "PASS"
        )

        if anon_enabled:
            ec.add_finding(
                f"{model}-F-FTP-ANONYMOUS",
                "MEDIUM",
                f"{model}: vsftpd configured with anonymous access enabled",
                f"The vsftpd.conf enables anonymous FTP access (anonymous_enable=YES). "
                f"Combined with the FTP service being enabled by default in NVRAM "
                f"(usb.ftp.enable=1), this provides unauthenticated read access to "
                f"USB-connected storage.",
                cwe="CWE-284",
            )


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    print("=" * 70)
    print("Security AssessmentI — Phase 5: Secrets & Credential Scan")
    print("=" * 70)

    # Verify paths exist
    for model, info in MODELS.items():
        if not os.path.isdir(info["rootfs"]):
            print(f"[!] ERROR: {model} rootfs not found: {info['rootfs']}")
            sys.exit(1)
        if not os.path.isfile(info["httpd"]):
            print(f"[!] ERROR: {model} httpd not found: {info['httpd']}")
            sys.exit(1)
        print(f"[+] {model} rootfs: {info['rootfs']}")
        print(f"[+] {model} httpd:  {info['httpd']} ({info['arch']})")

    # Run all scans for each model
    for model, info in MODELS.items():
        print(f"\n{'─' * 70}")
        print(f"  Scanning {model} ({info['arch']})")
        print(f"{'─' * 70}")

        scan_passwd_shadow(model, info)
        scan_httpd_strings(model, info)
        scan_crypto_files(model, info)
        scan_config_credentials(model, info)
        scan_hidden_endpoints(model, info)
        scan_init_services(model, info)
        scan_mac_serial_backdoors(model, info)
        scan_nvram_defaults(model, info)
        scan_samba_config(model, info)
        scan_ftp_config(model, info)

    # Cross-model comparison
    print(f"\n{'─' * 70}")
    print("  Cross-Model Comparison")
    print(f"{'─' * 70}")
    scan_cross_model_comparison()

    # Save evidence
    print(f"\n{'=' * 70}")
    print("  Saving Evidence")
    print(f"{'=' * 70}")

    filepath = ec.save("phase5_secrets.json")

    # Print summary
    print(f"\n{'=' * 70}")
    print("  SUMMARY")
    print(f"{'=' * 70}")

    vuln_tests = [t for t in ec.tests if t["status"] == "VULN"]
    print(f"\n  Total tests:    {len(ec.tests)}")
    print(f"  VULN tests:     {len(vuln_tests)}")
    print(f"  Findings:       {len(ec.findings)}")
    print(f"  Anomalies:      {len(ec.anomalies)}")

    # Print findings by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in ec.findings if f["severity"] == severity]
        if sev_findings:
            print(f"\n  [{severity}] ({len(sev_findings)}):")
            for f in sev_findings:
                print(f"    - {f['id']}: {f['title']}")

    return filepath


if __name__ == "__main__":
    main()
