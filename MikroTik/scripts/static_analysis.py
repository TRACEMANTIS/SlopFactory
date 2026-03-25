#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Phase 1: Static Analysis
Security assessment of firmware extracted from CHR disk image.

Performs:
  1. Firmware extraction from CHR raw disk image (partition mount + squashfs)
  2. Binary security analysis (checksec, strings, readelf, unsafe functions)
  3. Radare2 function analysis on key binaries (www, mproxy, login)
  4. Winbox handler enumeration in /nova/bin/
  5. Configuration analysis (hardcoded credentials, default keys)
  6. NPK package structure extraction
  7. Shared library analysis

Target image: /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/chr-7.20.8.img
Requires: sudo (for loop mount), unsquashfs, binwalk, readelf, strings, r2

Evidence output:
  - evidence/static_analysis.json
  - evidence/binary_checksec.json
  - source/ (extracted filesystem)
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

import json
import os
import re
import struct
import subprocess
import shutil
import glob as glob_mod
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────

CHR_IMAGE = BASE_DIR / "chr-7.20.8.img"
SOURCE_DIR = BASE_DIR / "source"
EXTRACT_DIR = SOURCE_DIR / "squashfs-root"

# Mount points (under /tmp for cleanup)
MOUNT_P1 = Path("/tmp/mikrotik_static_p1")
MOUNT_P2 = Path("/tmp/mikrotik_static_p2")

# Partition layout from fdisk (sector size = 512)
SECTOR_SIZE = 512
PART1_START_SECTOR = 34
PART1_SECTORS = 65536
PART2_START_SECTOR = 65570
PART2_SECTORS = 192478

PART1_OFFSET = PART1_START_SECTOR * SECTOR_SIZE   # 17408
PART1_SIZE = PART1_SECTORS * SECTOR_SIZE
PART2_OFFSET = PART2_START_SECTOR * SECTOR_SIZE    # 33571840
PART2_SIZE = PART2_SECTORS * SECTOR_SIZE

# Squashfs offset within the NPK image file (var/pdb/system/image)
SQUASHFS_OFFSET_IN_IMAGE = 4096

# Key binaries to analyze in depth
KEY_BINARIES = [
    "nova/bin/www",
    "nova/bin/mproxy",
    "nova/bin/login",
    "nova/bin/ftpd",
    "nova/bin/sshd" if os.path.exists("placeholder") else "bndl/security/nova/bin/sshd",
    "nova/bin/resolver",
    "nova/bin/snmp",
    "nova/bin/user",
    "nova/bin/fileman",
    "nova/bin/ssld",
    "nova/bin/btest",
    "nova/bin/cloud",
    "nova/bin/telnet",
]

# Binaries for radare2 deep analysis (function listing)
R2_DEEP_BINARIES = [
    "nova/bin/www",
    "nova/bin/mproxy",
    "nova/bin/login",
    "nova/bin/ftpd",
]

# Unsafe C functions to search for
UNSAFE_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "vsprintf",
    "gets", "scanf", "sscanf", "fscanf",
    "strncpy",  # not unsafe per se, but often misused
    "strtok",   # not thread-safe
    "realpath",
    "system", "popen", "exec",
    "mktemp",
]

# Interesting string patterns for security review
INTERESTING_PATTERNS = {
    "hardcoded_ips": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "urls": re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE),
    "passwords": re.compile(r'(?:password|passwd|pass|pwd|secret|credential|token)[=: ]+\S+', re.IGNORECASE),
    "format_strings": re.compile(r'%[0-9]*[sndxoufegp]'),
    "sql_keywords": re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b.*\b(?:FROM|INTO|TABLE|WHERE|SET)\b', re.IGNORECASE),
    "crypto_constants": re.compile(r'(?:AES|DES|RSA|SHA[0-9]*|MD5|HMAC|CBC|ECB|GCM|CHACHA)', re.IGNORECASE),
    "paths": re.compile(r'(?:/nova/|/home/|/rw/|/tmp/|/var/|/proc/|/sys/|/dev/)[^\s"\']*'),
    "private_keys": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
    "base64_blobs": re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
    "debug_messages": re.compile(r'(?:DEBUG|TRACE|TODO|FIXME|HACK|XXX|KLUDGE)', re.IGNORECASE),
    "email_addresses": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "shell_commands": re.compile(r'(?:/bin/sh|/bin/bash|/usr/bin/|/sbin/)'),
}


# ── Helper Functions ──────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=120, shell=False):
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=shell)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError as e:
        return "", f"Command not found: {e}", -2
    except Exception as e:
        return "", str(e), -99


def sha256_file(filepath):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


def file_size_human(size_bytes):
    """Human-readable file size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


# ── Section 1: Firmware Extraction ────────────────────────────────────────────

def extract_firmware(ec):
    """Extract RouterOS filesystem from CHR disk image."""
    log("=" * 60)
    log("SECTION 1: Firmware Extraction from CHR Disk Image")
    log("=" * 60)

    # ── 1.1 Verify image file ──
    if not CHR_IMAGE.exists():
        ec.add_test("firmware", "image_exists", "CHR image file exists",
                     "FAIL — image not found", anomaly=True)
        return False

    img_size = CHR_IMAGE.stat().st_size
    img_hash = sha256_file(CHR_IMAGE)
    ec.add_test("firmware", "image_exists", "CHR image file exists",
                f"PASS — {file_size_human(img_size)}, SHA256={img_hash[:16]}...",
                details={"path": str(CHR_IMAGE), "size": img_size, "sha256": img_hash})

    # ── 1.2 Partition layout with fdisk ──
    stdout, stderr, rc = run_cmd(["fdisk", "-l", str(CHR_IMAGE)])
    partitions = []
    if rc == 0:
        for line in stdout.splitlines():
            if line.startswith(str(CHR_IMAGE)):
                partitions.append(line.strip())
    ec.add_test("firmware", "fdisk_layout", "Identify partition layout",
                f"PASS — {len(partitions)} partitions found",
                details={"fdisk_output": stdout.strip(), "partitions": partitions})

    # ── 1.3 Binwalk signature scan ──
    stdout, stderr, rc = run_cmd(["binwalk", str(CHR_IMAGE)], timeout=60)
    signatures = []
    squashfs_offsets = []
    ext_partitions = []
    if rc == 0:
        for line in stdout.splitlines():
            line_stripped = line.strip()
            if line_stripped and not line_stripped.startswith("DECIMAL") and not line_stripped.startswith("---"):
                signatures.append(line_stripped)
                if "squashfs" in line_stripped.lower():
                    squashfs_offsets.append(line_stripped)
                if "EXT filesystem" in line_stripped:
                    ext_partitions.append(line_stripped)

    ec.add_test("firmware", "binwalk_scan", "Binwalk signature scan of disk image",
                f"PASS — {len(signatures)} signatures, {len(ext_partitions)} EXT partitions, "
                f"{len(squashfs_offsets)} squashfs (in NPK image)",
                details={
                    "total_signatures": len(signatures),
                    "ext_partitions": ext_partitions,
                    "squashfs_signatures": squashfs_offsets,
                    "xz_compressed_blocks": sum(1 for s in signatures if "xz compressed" in s.lower()),
                })

    # ── 1.4 Clean up any previous mounts ──
    for mp in [MOUNT_P1, MOUNT_P2]:
        run_cmd(f"sudo umount {mp}", shell=True)
    run_cmd("sudo losetup -D", shell=True)

    # ── 1.5 Mount partition 1 (Boot) ──
    MOUNT_P1.mkdir(parents=True, exist_ok=True)
    stdout, stderr, rc = run_cmd(
        f"sudo mount -o loop,ro,offset={PART1_OFFSET} {CHR_IMAGE} {MOUNT_P1}", shell=True)
    p1_files = []
    if rc == 0:
        for root, dirs, files in os.walk(str(MOUNT_P1)):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, str(MOUNT_P1))
                try:
                    fsize = os.path.getsize(fpath)
                except:
                    fsize = 0
                p1_files.append({"path": rel, "size": fsize})
        ec.add_test("firmware", "mount_boot_partition", "Mount partition 1 (RouterOS Boot, ext2)",
                     f"PASS — {len(p1_files)} files",
                     details={"files": p1_files, "mount_point": str(MOUNT_P1)})
    else:
        ec.add_test("firmware", "mount_boot_partition", "Mount partition 1",
                     f"FAIL — {stderr.strip()}", anomaly=True)

    # ── 1.6 Mount partition 2 (RouterOS main) ──
    MOUNT_P2.mkdir(parents=True, exist_ok=True)
    # Use explicit loop device to avoid overlap
    run_cmd("sudo losetup -D", shell=True)
    run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
    # Re-mount p1 on loop0
    run_cmd(f"sudo mount -o loop,ro,offset={PART1_OFFSET} {CHR_IMAGE} {MOUNT_P1}", shell=True)
    # Set up p2 on a separate loop device
    stdout_lo, stderr_lo, rc_lo = run_cmd(
        f"sudo losetup -f --show -o {PART2_OFFSET} --sizelimit {PART2_SIZE} -r {CHR_IMAGE}",
        shell=True)
    p2_mounted = False
    if rc_lo == 0:
        loop_dev = stdout_lo.strip()
        stdout2, stderr2, rc2 = run_cmd(f"sudo mount -r {loop_dev} {MOUNT_P2}", shell=True)
        if rc2 == 0:
            p2_mounted = True
        else:
            # Fallback: direct offset mount (umount p1 first if overlapping)
            run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
            run_cmd(f"sudo losetup -D", shell=True)
            stdout2, stderr2, rc2 = run_cmd(
                f"sudo mount -o loop,ro,offset={PART2_OFFSET} {CHR_IMAGE} {MOUNT_P2}", shell=True)
            p2_mounted = (rc2 == 0)

    p2_files = []
    if p2_mounted:
        for root, dirs, files in os.walk(str(MOUNT_P2)):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, str(MOUNT_P2))
                try:
                    fsize = os.path.getsize(fpath)
                except:
                    fsize = 0
                p2_files.append({"path": rel, "size": fsize})
        ec.add_test("firmware", "mount_routeros_partition", "Mount partition 2 (RouterOS, ext3)",
                     f"PASS — {len(p2_files)} files",
                     details={"files": p2_files, "mount_point": str(MOUNT_P2)})
    else:
        ec.add_test("firmware", "mount_routeros_partition", "Mount partition 2",
                     f"FAIL — could not mount", anomaly=True)
        return False

    # ── 1.7 Check NPK image header ──
    npk_image_path = MOUNT_P2 / "var" / "pdb" / "system" / "image"
    if npk_image_path.exists():
        npk_size = npk_image_path.stat().st_size
        npk_hash = sha256_file(npk_image_path)

        # Read NPK header
        npk_header = {}
        try:
            with open(npk_image_path, "rb") as f:
                header_data = f.read(512)
                # NPK magic: 1ef1d0ba
                magic = struct.unpack("<I", header_data[0:4])[0]
                npk_header["magic"] = f"0x{magic:08x}"
                npk_header["is_npk"] = (magic == 0xbad0f11e)
                # Package name at offset 0x14
                name_start = header_data.find(b'system')
                if name_start >= 0:
                    npk_header["package_name"] = "system"
                # Architecture
                arch_offset = header_data.find(b'i386')
                if arch_offset >= 0:
                    npk_header["architecture"] = "i386"
                else:
                    arch_offset = header_data.find(b'x86_64')
                    if arch_offset >= 0:
                        npk_header["architecture"] = "x86_64"
                # Description
                desc_start = header_data.find(b'Main package')
                if desc_start >= 0:
                    desc_end = header_data.find(b'\x00', desc_start)
                    npk_header["description"] = header_data[desc_start:desc_end].decode('ascii', errors='replace')
                # Channel
                channel_start = header_data.find(b'long-term')
                if channel_start >= 0:
                    npk_header["channel"] = "long-term"
                # SHA256 in header
                sha_start = header_data.find(b'5057b')
                if sha_start >= 0:
                    sha_end = header_data.find(b'\x00', sha_start)
                    npk_header["header_sha256"] = header_data[sha_start:sha_end].decode('ascii', errors='replace')
        except Exception as e:
            npk_header["parse_error"] = str(e)

        ec.add_test("firmware", "npk_image_header", "Parse NPK system image header",
                     f"PASS — {file_size_human(npk_size)}, magic={npk_header.get('magic', 'unknown')}",
                     details={"size": npk_size, "sha256": npk_hash, "header": npk_header})
    else:
        ec.add_test("firmware", "npk_image_header", "NPK system image",
                     "FAIL — image file not found", anomaly=True)
        return False

    # ── 1.8 Extract squashfs from NPK image ──
    if EXTRACT_DIR.exists():
        log(f"  Removing previous extraction at {EXTRACT_DIR}")
        shutil.rmtree(str(EXTRACT_DIR), ignore_errors=True)

    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    stdout, stderr, rc = run_cmd(
        f"sudo unsquashfs -o {SQUASHFS_OFFSET_IN_IMAGE} -d {EXTRACT_DIR} -f {npk_image_path}",
        shell=True, timeout=120)

    if rc != 0:
        # Fallback: try extracting the squashfs portion first
        log("  unsquashfs with offset failed, trying dd + unsquashfs...")
        tmp_sqfs = "/tmp/mikrotik_squashfs.img"
        run_cmd(f"sudo dd if={npk_image_path} of={tmp_sqfs} bs=1 skip={SQUASHFS_OFFSET_IN_IMAGE} count=20000000",
                shell=True, timeout=60)
        stdout, stderr, rc = run_cmd(
            f"sudo unsquashfs -d {EXTRACT_DIR} -f {tmp_sqfs}",
            shell=True, timeout=120)
        run_cmd(f"rm -f {tmp_sqfs}", shell=True)

    if rc != 0:
        # Fallback 2: binwalk extraction
        log("  unsquashfs failed, trying binwalk extraction...")
        stdout, stderr, rc = run_cmd(
            f"sudo binwalk -e -C {SOURCE_DIR} {npk_image_path}",
            shell=True, timeout=180)

    # Fix permissions so non-root can read
    run_cmd(f"sudo chmod -R a+rX {EXTRACT_DIR}", shell=True)

    # Count extracted files
    extracted_files = 0
    extracted_dirs = 0
    if EXTRACT_DIR.exists():
        for root, dirs, files in os.walk(str(EXTRACT_DIR)):
            extracted_files += len(files)
            extracted_dirs += len(dirs)

    if extracted_files > 0:
        ec.add_test("firmware", "squashfs_extraction", "Extract squashfs filesystem from NPK image",
                     f"PASS — {extracted_files} files in {extracted_dirs} directories",
                     details={"extract_dir": str(EXTRACT_DIR),
                              "file_count": extracted_files,
                              "dir_count": extracted_dirs})
    else:
        ec.add_test("firmware", "squashfs_extraction", "Extract squashfs filesystem",
                     f"FAIL — no files extracted: {stderr.strip()}", anomaly=True)
        return False

    # ── 1.9 Verify key directories exist ──
    expected_dirs = ["nova/bin", "lib", "bin"]
    for d in expected_dirs:
        dpath = EXTRACT_DIR / d
        exists = dpath.exists() and dpath.is_dir()
        if exists:
            contents = os.listdir(str(dpath))
            ec.add_test("firmware", f"dir_{d.replace('/', '_')}",
                         f"Verify extracted directory: {d}",
                         f"PASS — {len(contents)} entries",
                         details={"entries": sorted(contents)})
        else:
            ec.add_test("firmware", f"dir_{d.replace('/', '_')}",
                         f"Verify extracted directory: {d}",
                         "MISSING", anomaly=True)

    # ── 1.10 Check autorun script ──
    autorun_path = MOUNT_P2 / "rw" / "autorun.scr"
    if autorun_path.exists():
        try:
            with open(autorun_path, "r", errors="replace") as f:
                autorun_content = f.read()
            ec.add_test("firmware", "autorun_script", "Check autorun.scr in rw partition",
                         f"PRESENT — {len(autorun_content)} bytes",
                         details={"content": autorun_content[:2000]},
                         anomaly=len(autorun_content.strip()) > 0)
        except:
            ec.add_test("firmware", "autorun_script", "Check autorun.scr",
                         "EXISTS but unreadable", anomaly=True)
    else:
        ec.add_test("firmware", "autorun_script", "Check autorun.scr in rw partition",
                     "NOT PRESENT")

    # ── 1.11 Check serial number file ──
    serial_path = MOUNT_P2 / "nova" / "etc" / "serial"
    if serial_path.exists():
        try:
            with open(serial_path, "r", errors="replace") as f:
                serial_content = f.read().strip()
            ec.add_test("firmware", "serial_number", "Extract device serial number",
                         f"FOUND — {serial_content}",
                         details={"serial": serial_content})
        except:
            pass

    # ── 1.12 Clean up mounts ──
    run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
    run_cmd(f"sudo umount {MOUNT_P2}", shell=True)
    run_cmd("sudo losetup -D", shell=True)

    return True


# ── Section 2: Binary Security Analysis (checksec) ───────────────────────────

def analyze_binary_security(ec):
    """Check binary hardening: RELRO, stack canary, NX, PIE, RPATH."""
    log("=" * 60)
    log("SECTION 2: Binary Security Analysis (checksec)")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("checksec", "extract_dir", "Extracted filesystem available",
                     "FAIL — extraction not found", anomaly=True)
        return {}

    checksec_results = {}

    # Collect all ELF binaries
    all_binaries = []

    # nova/bin/ binaries
    nova_bin = EXTRACT_DIR / "nova" / "bin"
    if nova_bin.exists():
        for f in sorted(os.listdir(str(nova_bin))):
            fpath = nova_bin / f
            if fpath.is_file():
                all_binaries.append(("nova/bin/" + f, str(fpath)))

    # bndl/*/nova/bin/ binaries
    bndl_dir = EXTRACT_DIR / "bndl"
    if bndl_dir.exists():
        for bundle in sorted(os.listdir(str(bndl_dir))):
            bndl_nova_bin = bndl_dir / bundle / "nova" / "bin"
            if bndl_nova_bin.exists():
                for f in sorted(os.listdir(str(bndl_nova_bin))):
                    fpath = bndl_nova_bin / f
                    if fpath.is_file():
                        all_binaries.append((f"bndl/{bundle}/nova/bin/{f}", str(fpath)))

    # /bin/ binaries
    bin_dir = EXTRACT_DIR / "bin"
    if bin_dir.exists():
        for f in sorted(os.listdir(str(bin_dir))):
            fpath = bin_dir / f
            if fpath.is_file():
                all_binaries.append(("bin/" + f, str(fpath)))

    # /lib/ shared libraries
    lib_dir = EXTRACT_DIR / "lib"
    if lib_dir.exists():
        for f in sorted(os.listdir(str(lib_dir))):
            if f.endswith(".so") or ".so." in f:
                fpath = lib_dir / f
                if fpath.is_file():
                    all_binaries.append(("lib/" + f, str(fpath)))

    # bndl/*/lib/ shared libraries
    if bndl_dir.exists():
        for bundle in sorted(os.listdir(str(bndl_dir))):
            bndl_lib = bndl_dir / bundle / "lib"
            if bndl_lib.exists():
                for f in sorted(os.listdir(str(bndl_lib))):
                    if f.endswith(".so") or ".so." in f:
                        fpath = bndl_lib / f
                        if fpath.is_file():
                            all_binaries.append((f"bndl/{bundle}/lib/{f}", str(fpath)))

    ec.add_test("checksec", "binary_enumeration", "Enumerate all ELF binaries and libraries",
                f"PASS — {len(all_binaries)} files found",
                details={"binary_list": [b[0] for b in all_binaries]})

    # Analyze each binary
    no_relro = []
    no_canary = []
    no_nx = []
    no_pie = []
    has_rpath = []
    has_runpath = []

    for rel_path, abs_path in all_binaries:
        result = analyze_single_binary_checksec(rel_path, abs_path)
        if result:
            checksec_results[rel_path] = result

            # Track weaknesses
            if result.get("relro") == "No RELRO":
                no_relro.append(rel_path)
            if not result.get("stack_canary", False):
                no_canary.append(rel_path)
            if not result.get("nx", False):
                no_nx.append(rel_path)
            if not result.get("pie", False):
                no_pie.append(rel_path)
            if result.get("rpath"):
                has_rpath.append(rel_path)
            if result.get("runpath"):
                has_runpath.append(rel_path)

    # Summary tests
    total = len(checksec_results)

    ec.add_test("checksec", "relro_summary", "RELRO (Relocation Read-Only) across all binaries",
                f"{total - len(no_relro)}/{total} have RELRO, {len(no_relro)} without",
                details={"no_relro": no_relro},
                anomaly=len(no_relro) > total * 0.5)

    ec.add_test("checksec", "canary_summary", "Stack canary across all binaries",
                f"{total - len(no_canary)}/{total} have canary, {len(no_canary)} without",
                details={"no_canary": no_canary},
                anomaly=len(no_canary) > total * 0.3)

    ec.add_test("checksec", "nx_summary", "NX (No-Execute) across all binaries",
                f"{total - len(no_nx)}/{total} have NX, {len(no_nx)} without",
                details={"no_nx": no_nx},
                anomaly=len(no_nx) > 0)

    ec.add_test("checksec", "pie_summary", "PIE (Position Independent Executable) across all binaries",
                f"{total - len(no_pie)}/{total} have PIE, {len(no_pie)} without",
                details={"no_pie": no_pie},
                anomaly=len(no_pie) > total * 0.5)

    if has_rpath:
        ec.add_test("checksec", "rpath_found", "RPATH set in binaries (potential hijack vector)",
                     f"FOUND in {len(has_rpath)} binaries",
                     details={"binaries": has_rpath}, anomaly=True)

    if has_runpath:
        ec.add_test("checksec", "runpath_found", "RUNPATH set in binaries",
                     f"FOUND in {len(has_runpath)} binaries",
                     details={"binaries": has_runpath}, anomaly=True)

    # Findings for systemic issues
    if len(no_relro) > total * 0.5 and total > 0:
        ec.add_finding("MEDIUM", "Majority of binaries lack RELRO protection",
                       f"{len(no_relro)}/{total} binaries have no RELRO. "
                       "GOT overwrite attacks are feasible.",
                       cwe="CWE-119")

    if len(no_canary) > total * 0.5 and total > 0:
        ec.add_finding("MEDIUM", "Majority of binaries lack stack canaries",
                       f"{len(no_canary)}/{total} binaries have no stack canary. "
                       "Stack buffer overflow exploitation is easier.",
                       cwe="CWE-120")

    if len(no_pie) > total * 0.5 and total > 0:
        ec.add_finding("LOW", "Majority of binaries lack PIE",
                       f"{len(no_pie)}/{total} binaries are not position-independent. "
                       "ASLR bypass is easier with known base addresses.",
                       cwe="CWE-119")

    if len(no_nx) > 0:
        ec.add_finding("HIGH", "Binaries without NX (executable stack)",
                       f"{len(no_nx)} binaries have executable stack. "
                       "Stack-based shellcode execution is possible.",
                       evidence_refs=no_nx, cwe="CWE-119")

    return checksec_results


def analyze_single_binary_checksec(rel_path, abs_path):
    """Perform checksec-equivalent analysis on a single binary."""
    result = {
        "path": rel_path,
        "file_type": None,
        "arch": None,
        "relro": "No RELRO",
        "stack_canary": False,
        "nx": False,
        "pie": False,
        "rpath": None,
        "runpath": None,
        "stripped": False,
        "static": False,
        "size": 0,
    }

    try:
        result["size"] = os.path.getsize(abs_path)
    except:
        pass

    # file type
    stdout, _, rc = run_cmd(["file", abs_path])
    if rc == 0:
        result["file_type"] = stdout.strip()
        if "stripped" in stdout:
            result["stripped"] = True
        if "statically linked" in stdout:
            result["static"] = True
        if "32-bit" in stdout:
            result["arch"] = "i386"
        elif "64-bit" in stdout:
            result["arch"] = "x86_64"

    # readelf analysis
    stdout, _, rc = run_cmd(["readelf", "-l", "-d", "-s", abs_path])
    if rc != 0:
        return result

    readelf_output = stdout

    # Check RELRO
    if "GNU_RELRO" in readelf_output:
        result["relro"] = "Partial RELRO"
        # Full RELRO requires BIND_NOW
        if "BIND_NOW" in readelf_output:
            result["relro"] = "Full RELRO"

    # Check NX (No-Execute stack)
    # Look for GNU_STACK segment
    for line in readelf_output.splitlines():
        if "GNU_STACK" in line:
            # If no 'E' (execute) flag, NX is enabled
            # Format: GNU_STACK ... RW  or RWE
            if "RWE" not in line and " E " not in line:
                result["nx"] = True
            break
    else:
        # No GNU_STACK means NX may not apply; for static binaries, check differently
        if result["static"]:
            result["nx"] = False  # static binaries often lack this

    # Check PIE
    stdout_h, _, rc_h = run_cmd(["readelf", "-h", abs_path])
    if rc_h == 0:
        if "DYN" in stdout_h and "Type:" in stdout_h:
            for line in stdout_h.splitlines():
                if "Type:" in line and "DYN" in line:
                    result["pie"] = True
                    break

    # Check stack canary (look for __stack_chk_fail in symbols)
    stdout_s, _, rc_s = run_cmd(["readelf", "-s", abs_path])
    if rc_s == 0:
        if "__stack_chk_fail" in stdout_s or "__stack_chk_guard" in stdout_s:
            result["stack_canary"] = True

    # Also check dynamic symbols
    stdout_d, _, rc_d = run_cmd(["readelf", "--dyn-syms", abs_path])
    if rc_d == 0:
        if "__stack_chk_fail" in stdout_d:
            result["stack_canary"] = True

    # Check RPATH / RUNPATH
    if "RPATH" in readelf_output:
        for line in readelf_output.splitlines():
            if "RPATH" in line and "Library" not in line:
                result["rpath"] = line.strip()
    if "RUNPATH" in readelf_output:
        for line in readelf_output.splitlines():
            if "RUNPATH" in line:
                result["runpath"] = line.strip()

    return result


# ── Section 3: Strings Analysis ──────────────────────────────────────────────

def analyze_strings(ec):
    """Extract and categorize interesting strings from key binaries."""
    log("=" * 60)
    log("SECTION 3: Strings Analysis on Key Binaries")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("strings", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    # Analyze key binaries
    binaries_to_analyze = []
    for rel in KEY_BINARIES:
        abs_path = EXTRACT_DIR / rel
        if abs_path.exists():
            binaries_to_analyze.append((rel, str(abs_path)))

    # Also add the main shared libraries
    lib_dir = EXTRACT_DIR / "lib"
    if lib_dir.exists():
        for f in sorted(os.listdir(str(lib_dir))):
            if f.endswith(".so"):
                binaries_to_analyze.append(("lib/" + f, str(lib_dir / f)))

    ec.add_test("strings", "targets_found", "Binaries available for strings analysis",
                f"PASS — {len(binaries_to_analyze)} binaries",
                details={"binaries": [b[0] for b in binaries_to_analyze]})

    all_findings = {}
    total_interesting = 0

    for rel_path, abs_path in binaries_to_analyze:
        log(f"  Analyzing strings: {rel_path}")
        stdout, _, rc = run_cmd(["strings", "-a", abs_path], timeout=30)
        if rc != 0:
            continue

        all_strings = stdout.splitlines()
        binary_findings = {
            "total_strings": len(all_strings),
            "categories": {},
        }

        for category, pattern in INTERESTING_PATTERNS.items():
            matches = set()
            for s in all_strings:
                found = pattern.findall(s)
                for m in found:
                    if isinstance(m, tuple):
                        m = m[0]
                    if len(m) > 3:  # skip trivially short matches
                        matches.add(m)

            if matches:
                # Limit to 50 per category to keep evidence manageable
                matches_list = sorted(matches)[:50]
                binary_findings["categories"][category] = {
                    "count": len(matches),
                    "samples": matches_list
                }
                total_interesting += len(matches)

        all_findings[rel_path] = binary_findings

        # Report per-binary summary
        cats = binary_findings["categories"]
        cat_summary = ", ".join(f"{k}={v['count']}" for k, v in cats.items() if v['count'] > 0)
        ec.add_test("strings", f"strings_{rel_path.replace('/', '_')}",
                     f"Strings analysis: {rel_path}",
                     f"{len(all_strings)} strings — {cat_summary or 'no interesting patterns'}",
                     details={"total_strings": len(all_strings),
                              "category_counts": {k: v['count'] for k, v in cats.items()}})

    # Check for hardcoded credentials across all binaries
    credential_hits = []
    for rel_path, findings in all_findings.items():
        pw_cat = findings["categories"].get("passwords", {})
        if pw_cat.get("count", 0) > 0:
            credential_hits.append({
                "binary": rel_path,
                "matches": pw_cat.get("samples", [])[:10]
            })

    if credential_hits:
        ec.add_finding("MEDIUM", "Potential hardcoded credentials in binaries",
                       f"Password-like strings found in {len(credential_hits)} binaries",
                       evidence_refs=[h["binary"] for h in credential_hits],
                       cwe="CWE-798")
        ec.add_test("strings", "hardcoded_credentials",
                     "Check for hardcoded credential strings",
                     f"FOUND in {len(credential_hits)} binaries",
                     details={"hits": credential_hits}, anomaly=True)
    else:
        ec.add_test("strings", "hardcoded_credentials",
                     "Check for hardcoded credential strings",
                     "NONE FOUND")

    # Check for private key material
    pk_hits = []
    for rel_path, findings in all_findings.items():
        pk_cat = findings["categories"].get("private_keys", {})
        if pk_cat.get("count", 0) > 0:
            pk_hits.append(rel_path)

    if pk_hits:
        ec.add_finding("HIGH", "Private key material embedded in binaries",
                       f"Private key markers found in: {', '.join(pk_hits)}",
                       cwe="CWE-321")

    ec.add_test("strings", "private_keys_check", "Check for embedded private key material",
                f"{'FOUND in ' + str(len(pk_hits)) + ' binaries' if pk_hits else 'NONE FOUND'}",
                anomaly=bool(pk_hits))

    # Check for debug/TODO messages
    debug_hits = []
    for rel_path, findings in all_findings.items():
        dbg_cat = findings["categories"].get("debug_messages", {})
        if dbg_cat.get("count", 0) > 0:
            debug_hits.append({
                "binary": rel_path,
                "count": dbg_cat["count"],
                "samples": dbg_cat.get("samples", [])[:5]
            })

    ec.add_test("strings", "debug_messages", "Check for debug/TODO/FIXME messages",
                f"{'FOUND in ' + str(len(debug_hits)) + ' binaries' if debug_hits else 'NONE FOUND'}",
                details={"hits": debug_hits} if debug_hits else None,
                anomaly=bool(debug_hits))

    # URL extraction summary
    url_hits = {}
    for rel_path, findings in all_findings.items():
        url_cat = findings["categories"].get("urls", {})
        if url_cat.get("count", 0) > 0:
            url_hits[rel_path] = url_cat.get("samples", [])[:20]

    if url_hits:
        all_urls = set()
        for urls in url_hits.values():
            all_urls.update(urls)
        ec.add_test("strings", "embedded_urls", "Extract embedded URLs from binaries",
                     f"FOUND {len(all_urls)} unique URLs across {len(url_hits)} binaries",
                     details={"urls": sorted(all_urls)[:100],
                              "per_binary": {k: len(v) for k, v in url_hits.items()}})
    else:
        ec.add_test("strings", "embedded_urls", "Extract embedded URLs from binaries",
                     "NONE FOUND")

    return all_findings


# ── Section 4: Unsafe C Function Detection ────────────────────────────────────

def analyze_unsafe_functions(ec):
    """Search for unsafe C function usage via strings and readelf symbol tables."""
    log("=" * 60)
    log("SECTION 4: Unsafe C Function Detection")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("unsafe_funcs", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    # Collect all ELF binaries
    all_binaries = []
    nova_bin = EXTRACT_DIR / "nova" / "bin"
    if nova_bin.exists():
        for f in sorted(os.listdir(str(nova_bin))):
            fpath = nova_bin / f
            if fpath.is_file():
                all_binaries.append(("nova/bin/" + f, str(fpath)))

    bndl_dir = EXTRACT_DIR / "bndl"
    if bndl_dir.exists():
        for bundle in sorted(os.listdir(str(bndl_dir))):
            bndl_nova_bin = bndl_dir / bundle / "nova" / "bin"
            if bndl_nova_bin.exists():
                for f in sorted(os.listdir(str(bndl_nova_bin))):
                    fpath = bndl_nova_bin / f
                    if fpath.is_file():
                        all_binaries.append((f"bndl/{bundle}/nova/bin/{f}", str(fpath)))

    lib_dir = EXTRACT_DIR / "lib"
    if lib_dir.exists():
        for f in sorted(os.listdir(str(lib_dir))):
            if f.endswith(".so"):
                all_binaries.append(("lib/" + f, str(lib_dir / f)))

    # Check each binary for unsafe function imports
    unsafe_summary = {}  # function -> list of binaries

    for rel_path, abs_path in all_binaries:
        # Check dynamic symbol imports
        stdout, _, rc = run_cmd(["readelf", "--dyn-syms", "-W", abs_path])
        if rc != 0:
            # Try static symbol table for statically linked binaries
            stdout, _, rc = run_cmd(["readelf", "-s", "-W", abs_path])
        if rc != 0:
            continue

        binary_unsafe = []
        for func in UNSAFE_FUNCTIONS:
            # Match the function name as a symbol (avoid partial matches)
            # Symbol table has function names like: strcpy@@GLIBC_2.0
            pattern = re.compile(r'\b' + re.escape(func) + r'(?:@@|\b)')
            if pattern.search(stdout):
                binary_unsafe.append(func)
                if func not in unsafe_summary:
                    unsafe_summary[func] = []
                unsafe_summary[func].append(rel_path)

        if binary_unsafe:
            ec.add_test("unsafe_funcs", f"unsafe_{rel_path.replace('/', '_')}",
                         f"Unsafe functions in {rel_path}",
                         f"FOUND: {', '.join(binary_unsafe)}",
                         details={"functions": binary_unsafe},
                         anomaly=True)

    # Overall summary
    if unsafe_summary:
        total_refs = sum(len(v) for v in unsafe_summary.values())
        ec.add_test("unsafe_funcs", "unsafe_summary",
                     "Unsafe C function usage across all binaries",
                     f"{len(unsafe_summary)} unique unsafe functions, {total_refs} total references",
                     details={f: {"count": len(bins), "binaries": bins}
                              for f, bins in sorted(unsafe_summary.items())},
                     anomaly=True)

        # Key unsafe functions that are particularly dangerous
        critical_funcs = ["gets", "strcpy", "sprintf", "strcat", "scanf"]
        critical_found = {f: unsafe_summary[f] for f in critical_funcs if f in unsafe_summary}
        if critical_found:
            func_list = ", ".join(f"{f}({len(v)} binaries)" for f, v in critical_found.items())
            ec.add_finding("MEDIUM",
                           "Critical unsafe C functions used across firmware",
                           f"Dangerous functions found: {func_list}. "
                           "These functions do not perform bounds checking and are "
                           "common sources of buffer overflow vulnerabilities.",
                           evidence_refs=list(set(b for v in critical_found.values() for b in v)),
                           cwe="CWE-120")
    else:
        ec.add_test("unsafe_funcs", "unsafe_summary",
                     "Unsafe C function usage across all binaries",
                     "NONE FOUND — all binaries use safe alternatives")


# ── Section 5: Radare2 Deep Analysis ─────────────────────────────────────────

def analyze_r2_functions(ec):
    """Use radare2 to list functions in key binaries."""
    log("=" * 60)
    log("SECTION 5: Radare2 Function Analysis")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("r2", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    r2_results = {}

    for rel_path in R2_DEEP_BINARIES:
        abs_path = EXTRACT_DIR / rel_path
        if not abs_path.exists():
            # Try bndl path for sshd
            if "sshd" in rel_path:
                abs_path = EXTRACT_DIR / "bndl" / "security" / "nova" / "bin" / "sshd"
            if not abs_path.exists():
                ec.add_test("r2", f"r2_{rel_path.replace('/', '_')}",
                             f"Radare2 analysis: {rel_path}",
                             "SKIP — binary not found")
                continue

        log(f"  Radare2 function analysis: {rel_path} (this may take a moment)...")

        # Run r2 with analysis and function list
        # Use -q (quiet) -c (commands) with aaa (full analysis) then afl (function list)
        stdout, stderr, rc = run_cmd(
            ["r2", "-q", "-c", "aaa;afl", str(abs_path)],
            timeout=180)

        if rc != 0 and not stdout:
            # Fallback: try with just aa (basic analysis)
            stdout, stderr, rc = run_cmd(
                ["r2", "-q", "-c", "aa;afl", str(abs_path)],
                timeout=120)

        if stdout:
            functions = []
            interesting_funcs = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                functions.append(line)
                # Look for security-relevant function names
                lower = line.lower()
                for keyword in ["auth", "login", "pass", "crypt", "hash", "key",
                                "cert", "verify", "check", "parse", "decode",
                                "upload", "download", "exec", "command", "shell",
                                "admin", "root", "permission", "access", "buffer",
                                "alloc", "free", "copy", "memcpy", "strcpy"]:
                    if keyword in lower:
                        interesting_funcs.append(line)
                        break

            r2_results[rel_path] = {
                "total_functions": len(functions),
                "interesting_functions": interesting_funcs,
                "all_functions": functions[:500],  # cap for evidence size
            }

            ec.add_test("r2", f"r2_{rel_path.replace('/', '_')}",
                         f"Radare2 function listing: {rel_path}",
                         f"{len(functions)} functions, {len(interesting_funcs)} security-relevant",
                         details={
                             "total_functions": len(functions),
                             "interesting_count": len(interesting_funcs),
                             "interesting_functions": interesting_funcs[:50],
                         })
        else:
            ec.add_test("r2", f"r2_{rel_path.replace('/', '_')}",
                         f"Radare2 function listing: {rel_path}",
                         f"FAIL — no output: {stderr.strip()[:200]}",
                         anomaly=True)

    # Also run r2 to get imports for the www binary (web server attack surface)
    www_path = EXTRACT_DIR / "nova" / "bin" / "www"
    if www_path.exists():
        log("  Radare2 import analysis: nova/bin/www")
        stdout, _, rc = run_cmd(
            ["r2", "-q", "-c", "aa;ii", str(www_path)], timeout=120)
        if stdout:
            imports = [line.strip() for line in stdout.splitlines() if line.strip()]
            ec.add_test("r2", "r2_www_imports", "Radare2 import table: nova/bin/www",
                         f"{len(imports)} imports",
                         details={"imports": imports[:200]})

    # mproxy sections analysis
    mproxy_path = EXTRACT_DIR / "nova" / "bin" / "mproxy"
    if mproxy_path.exists():
        log("  Radare2 section analysis: nova/bin/mproxy (Winbox proxy)")
        stdout, _, rc = run_cmd(
            ["r2", "-q", "-c", "iS", str(mproxy_path)], timeout=60)
        if stdout:
            sections = [line.strip() for line in stdout.splitlines() if line.strip()]
            ec.add_test("r2", "r2_mproxy_sections", "Radare2 sections: nova/bin/mproxy",
                         f"{len(sections)} sections",
                         details={"sections": sections})

    return r2_results


# ── Section 6: Winbox Handler Enumeration ─────────────────────────────────────

def enumerate_handlers(ec):
    """Map all Winbox handler binaries in /nova/bin/ and bundle directories."""
    log("=" * 60)
    log("SECTION 6: Winbox Handler Enumeration")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("handlers", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    handlers = []

    # Core handlers in nova/bin/
    nova_bin = EXTRACT_DIR / "nova" / "bin"
    if nova_bin.exists():
        for f in sorted(os.listdir(str(nova_bin))):
            fpath = nova_bin / f
            if fpath.is_file():
                finfo = get_handler_info(f, str(fpath))
                finfo["location"] = "core"
                finfo["rel_path"] = "nova/bin/" + f
                handlers.append(finfo)

    # Bundle handlers
    bndl_dir = EXTRACT_DIR / "bndl"
    if bndl_dir.exists():
        for bundle in sorted(os.listdir(str(bndl_dir))):
            bndl_nova_bin = bndl_dir / bundle / "nova" / "bin"
            if bndl_nova_bin.exists():
                for f in sorted(os.listdir(str(bndl_nova_bin))):
                    fpath = bndl_nova_bin / f
                    if fpath.is_file():
                        finfo = get_handler_info(f, str(fpath))
                        finfo["location"] = f"bndl/{bundle}"
                        finfo["rel_path"] = f"bndl/{bundle}/nova/bin/{f}"
                        handlers.append(finfo)

    ec.add_test("handlers", "handler_enumeration",
                 "Enumerate all Winbox handler binaries",
                 f"{len(handlers)} handlers ({sum(1 for h in handlers if h['location'] == 'core')} core, "
                 f"{sum(1 for h in handlers if h['location'] != 'core')} bundled)",
                 details={"handlers": handlers})

    # Categorize by functionality
    categories = {
        "networking": ["net", "route", "bridge2", "arpd", "vrrp", "igmpproxy",
                        "detnet", "mesh", "discover", "ping", "traceroute", "macping",
                        "mactel", "romon", "natpmp", "ptp"],
        "security": ["user", "cerm", "cerm-worker", "keyman", "dot1x", "radius",
                      "ssld", "letsencrypt", "socks", "socksify"],
        "web_services": ["www", "ftpd", "tftpd", "snmp", "upnp", "email",
                          "cloud", "quickset"],
        "management": ["login", "mproxy", "telnet", "sermgr", "sertcp", "mepty",
                        "agent", "btest", "figman", "fileman", "profiler"],
        "system": ["sys2", "log", "logmaker", "backup", "diskd", "installer",
                    "loader", "modprobed", "moduler", "mode", "watchdog", "panicsl",
                    "led", "lcdstat", "havecardbus", "parser", "undo", "sstore",
                    "crossfig", "portman"],
        "monitoring": ["graphing", "trafflow", "trafficgen", "sniffer", "rtrace",
                        "kidcontrol"],
        "tunneling": ["ppp", "ppp-worker", "ipsec", "ipsec-worker", "ssh", "sshd",
                       "hotspot", "wproxy"],
        "dns_ntp": ["resolver", "resolver_ctl", "ntp"],
        "dhcp": ["dhcp", "dhcpclient", "ippool", "ippool6", "radvd"],
    }

    categorized = {}
    uncategorized = []
    for h in handlers:
        found_cat = False
        for cat, names in categories.items():
            if h["name"] in names:
                if cat not in categorized:
                    categorized[cat] = []
                categorized[cat].append(h["name"])
                found_cat = True
                break
        if not found_cat:
            uncategorized.append(h["name"])

    ec.add_test("handlers", "handler_categories",
                 "Categorize handlers by functionality",
                 f"{len(categorized)} categories, {len(uncategorized)} uncategorized",
                 details={"categories": categorized, "uncategorized": uncategorized})

    # Find the largest binaries (more code = more attack surface)
    sorted_by_size = sorted(handlers, key=lambda h: h.get("size", 0), reverse=True)
    top_10 = sorted_by_size[:10]
    ec.add_test("handlers", "largest_binaries",
                 "Top 10 largest handler binaries (most attack surface)",
                 ", ".join(f"{h['name']}({file_size_human(h['size'])})" for h in top_10),
                 details={"top_10": top_10})

    # Identify network-facing handlers (key attack surface)
    network_facing = ["www", "mproxy", "ftpd", "sshd", "snmp", "telnet",
                       "btest", "cloud", "hotspot", "resolver", "dhcp",
                       "ppp", "login", "agent", "upnp", "tftpd"]
    nf_handlers = [h for h in handlers if h["name"] in network_facing]
    ec.add_test("handlers", "network_facing",
                 "Identify network-facing handlers (primary attack surface)",
                 f"{len(nf_handlers)} network-facing handlers",
                 details={"handlers": [h["name"] for h in nf_handlers]})

    # Console module memory files (.mem)
    mem_files = []
    for root, dirs, files in os.walk(str(EXTRACT_DIR)):
        for f in files:
            if f.endswith(".mem"):
                rel = os.path.relpath(os.path.join(root, f), str(EXTRACT_DIR))
                mem_files.append(rel)

    if mem_files:
        ec.add_test("handlers", "console_modules",
                     "Console module definition files (.mem)",
                     f"{len(mem_files)} module files found",
                     details={"files": mem_files})

    return handlers


def get_handler_info(name, abs_path):
    """Get basic info about a handler binary."""
    info = {"name": name, "size": 0, "type": "unknown", "arch": "unknown"}
    try:
        info["size"] = os.path.getsize(abs_path)
    except:
        pass

    stdout, _, rc = run_cmd(["file", abs_path])
    if rc == 0:
        info["type"] = stdout.strip()
        if "32-bit" in stdout:
            info["arch"] = "i386"
        elif "64-bit" in stdout:
            info["arch"] = "x86_64"

    return info


# ── Section 7: Configuration Analysis ────────────────────────────────────────

def analyze_configuration(ec):
    """Analyze default configurations, hardcoded credentials, default keys."""
    log("=" * 60)
    log("SECTION 7: Configuration Analysis")
    log("=" * 60)

    # ── 7.1 Check for default config files in extracted filesystem ──
    config_files = []
    if EXTRACT_DIR.exists():
        for root, dirs, files in os.walk(str(EXTRACT_DIR)):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, str(EXTRACT_DIR))
                lower = f.lower()
                if any(ext in lower for ext in [".conf", ".cfg", ".ini", ".xml",
                                                 ".json", ".pem", ".key", ".crt",
                                                 ".html", ".txt", ".scr"]):
                    config_files.append(rel)

    ec.add_test("config", "config_files", "Configuration and data files in firmware",
                f"{len(config_files)} files found",
                details={"files": sorted(config_files)})

    # ── 7.2 Check hotspot default pages for security issues ──
    hotspot_dir = EXTRACT_DIR / "bndl" / "hotspot" / "home" / "web" / "hotspot"
    if hotspot_dir.exists():
        hotspot_files = []
        for f in sorted(os.listdir(str(hotspot_dir))):
            hotspot_files.append(f)

        # Check login.html for credential handling
        login_html = hotspot_dir / "login.html"
        if login_html.exists():
            try:
                with open(login_html, "r", errors="replace") as fh:
                    content = fh.read()
                issues = []
                if "password" in content.lower():
                    issues.append("contains password field")
                if "md5" in content.lower():
                    issues.append("uses MD5 hashing")
                if "http://" in content and "https://" not in content:
                    issues.append("may transmit over HTTP")
                if "<form" in content.lower() and "action" in content.lower():
                    issues.append("has form submission")

                ec.add_test("config", "hotspot_login", "Hotspot login page security review",
                             f"{'ISSUES: ' + ', '.join(issues) if issues else 'OK'}",
                             details={"issues": issues, "file_size": len(content)},
                             anomaly=bool(issues))
            except:
                pass

        # Check md5.js
        md5_js = hotspot_dir / "md5.js"
        if md5_js.exists():
            ec.add_test("config", "hotspot_md5", "Hotspot uses MD5 for password hashing",
                         "FOUND — md5.js present in hotspot package",
                         details={"file": "bndl/hotspot/home/web/hotspot/md5.js"},
                         anomaly=True)
            ec.add_finding("LOW", "Hotspot login uses MD5 password hashing",
                           "The default hotspot captive portal uses MD5 for password "
                           "hashing (md5.js). MD5 is cryptographically broken and "
                           "should not be used for password protection.",
                           cwe="CWE-328")

        ec.add_test("config", "hotspot_files", "Default hotspot template files",
                     f"{len(hotspot_files)} files",
                     details={"files": hotspot_files})

    # ── 7.3 Check for hardcoded keys/certificates ──
    key_files = []
    cert_files = []
    if EXTRACT_DIR.exists():
        for root, dirs, files in os.walk(str(EXTRACT_DIR)):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, str(EXTRACT_DIR))
                if f.endswith((".key", ".pem")):
                    key_files.append(rel)
                elif f.endswith((".crt", ".cer")):
                    cert_files.append(rel)

    if key_files:
        ec.add_test("config", "embedded_keys", "Embedded key files in firmware",
                     f"FOUND — {len(key_files)} key files",
                     details={"files": key_files}, anomaly=True)
        ec.add_finding("MEDIUM", "Key material embedded in firmware image",
                       f"Found {len(key_files)} key files in firmware: {', '.join(key_files)}",
                       cwe="CWE-321")
    else:
        ec.add_test("config", "embedded_keys", "Embedded key files in firmware",
                     "NONE FOUND")

    if cert_files:
        ec.add_test("config", "embedded_certs", "Embedded certificate files in firmware",
                     f"FOUND — {len(cert_files)} certificate files",
                     details={"files": cert_files})

    # ── 7.4 Scan all text-like files for credentials ──
    cred_patterns = [
        re.compile(r'password\s*[:=]\s*["\']?(\S+)', re.IGNORECASE),
        re.compile(r'passwd\s*[:=]\s*["\']?(\S+)', re.IGNORECASE),
        re.compile(r'secret\s*[:=]\s*["\']?(\S+)', re.IGNORECASE),
        re.compile(r'api[_-]?key\s*[:=]\s*["\']?(\S+)', re.IGNORECASE),
        re.compile(r'token\s*[:=]\s*["\']?(\S+)', re.IGNORECASE),
    ]
    cred_hits = []
    if EXTRACT_DIR.exists():
        for root, dirs, files in os.walk(str(EXTRACT_DIR)):
            for f in files:
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, str(EXTRACT_DIR))
                # Only check text-ish files
                if not any(f.endswith(ext) for ext in
                           [".html", ".txt", ".js", ".json", ".xml", ".conf",
                            ".cfg", ".ini", ".sh", ".scr", ".info"]):
                    continue
                try:
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read(50000)  # limit read
                    for pat in cred_patterns:
                        matches = pat.findall(content)
                        if matches:
                            cred_hits.append({
                                "file": rel,
                                "pattern": pat.pattern[:40],
                                "matches": matches[:5]
                            })
                except:
                    pass

    ec.add_test("config", "credential_scan", "Scan text files for hardcoded credentials",
                f"{'FOUND ' + str(len(cred_hits)) + ' hits' if cred_hits else 'NONE FOUND'}",
                details={"hits": cred_hits} if cred_hits else None,
                anomaly=bool(cred_hits))

    # ── 7.5 Fetch live configuration from router ──
    log("  Fetching live configuration from router via REST API...")
    live_config = {}
    config_endpoints = {
        "system_identity": "/rest/system/identity",
        "system_resource": "/rest/system/resource",
        "ip_service": "/rest/ip/service",
        "user_list": "/rest/user",
        "ip_firewall_filter": "/rest/ip/firewall/filter",
        "ip_firewall_nat": "/rest/ip/firewall/nat",
        "system_ntp_client": "/rest/system/ntp/client",
        "snmp_community": "/rest/snmp/community",
        "tool_mac_server": "/rest/tool/mac-server",
        "ip_dns": "/rest/ip/dns",
        "system_logging": "/rest/system/logging",
        "ip_neighbor_discovery": "/rest/ip/neighbor-discovery-settings",
        "system_package": "/rest/system/package",
        "interface": "/rest/interface",
    }

    for name, endpoint in config_endpoints.items():
        code, data = rest_get(endpoint)
        if code == 200:
            live_config[name] = data
        else:
            live_config[name] = {"error": code, "data": data}

    # Check for insecure defaults
    insecure_defaults = []

    # Check enabled services
    services = live_config.get("ip_service", [])
    if isinstance(services, list):
        for svc in services:
            svc_name = svc.get("name", "unknown")
            disabled = svc.get("disabled", "true")
            port = svc.get("port", "?")
            if disabled == "false" or disabled is False:
                if svc_name in ["ftp", "telnet", "api", "www"]:
                    insecure_defaults.append(f"{svc_name} enabled on port {port} (unencrypted)")

    if insecure_defaults:
        ec.add_test("config", "insecure_services", "Insecure services enabled by default",
                     f"FOUND — {len(insecure_defaults)} insecure services",
                     details={"services": insecure_defaults}, anomaly=True)
        ec.add_finding("MEDIUM", "Insecure management services enabled",
                       f"The following unencrypted services are enabled: "
                       f"{', '.join(insecure_defaults)}. "
                       "Credentials and data transmitted in cleartext.",
                       cwe="CWE-319")
    else:
        ec.add_test("config", "insecure_services", "Check for insecure enabled services",
                     "All sensitive services properly configured")

    # Check SNMP community strings
    snmp_communities = live_config.get("snmp_community", [])
    if isinstance(snmp_communities, list):
        default_communities = [c for c in snmp_communities
                                if c.get("name") in ["public", "private"]]
        if default_communities:
            ec.add_test("config", "snmp_defaults", "Default SNMP community strings",
                         f"FOUND — {len(default_communities)} default communities",
                         details={"communities": default_communities}, anomaly=True)
            ec.add_finding("LOW", "Default SNMP community strings present",
                           "Default SNMP community strings (public/private) are configured. "
                           "These allow unauthenticated information disclosure.",
                           cwe="CWE-798")
        else:
            ec.add_test("config", "snmp_defaults", "Default SNMP community strings",
                         "NONE — custom communities only")

    # Check MAC-Telnet/Winbox access
    mac_server = live_config.get("tool_mac_server", {})
    ec.add_test("config", "mac_server", "MAC-Telnet server configuration",
                f"Config: {json.dumps(mac_server)[:200]}",
                details={"config": mac_server})

    # Check firewall rules
    fw_filter = live_config.get("ip_firewall_filter", [])
    if isinstance(fw_filter, list):
        ec.add_test("config", "firewall_rules", "Firewall filter rules",
                     f"{len(fw_filter)} rules configured",
                     details={"rule_count": len(fw_filter),
                              "rules": fw_filter[:20]},
                     anomaly=len(fw_filter) == 0)
        if len(fw_filter) == 0:
            ec.add_finding("LOW", "No firewall rules configured",
                           "The router has no IP firewall filter rules. "
                           "All traffic to management interfaces is unrestricted.",
                           cwe="CWE-284")

    # Check neighbor discovery
    nd_settings = live_config.get("ip_neighbor_discovery", {})
    ec.add_test("config", "neighbor_discovery", "Neighbor discovery settings",
                f"Config: {json.dumps(nd_settings)[:200]}",
                details={"config": nd_settings})

    # Save live config for reference
    config_file = CONFIGS_DIR / "live_config_snapshot.json"
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        json.dump(live_config, f, indent=2, default=str)
    ec.add_test("config", "live_config_saved", "Save live configuration snapshot",
                f"Saved to {config_file}",
                details={"endpoints_fetched": len(live_config),
                          "successful": sum(1 for v in live_config.values()
                                            if not (isinstance(v, dict) and "error" in v))})

    # Check installed packages
    packages = live_config.get("system_package", [])
    if isinstance(packages, list):
        pkg_list = []
        for pkg in packages:
            pkg_list.append({
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "unknown"),
                "disabled": pkg.get("disabled", "unknown"),
            })
        ec.add_test("config", "installed_packages", "Installed RouterOS packages",
                     f"{len(pkg_list)} packages",
                     details={"packages": pkg_list})

    return live_config


# ── Section 8: NPK Package Structure ─────────────────────────────────────────

def analyze_npk_structure(ec):
    """Analyze NPK package structure and bundle layout."""
    log("=" * 60)
    log("SECTION 8: NPK Package & Bundle Structure Analysis")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("npk", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    # ── 8.1 Enumerate bundles ──
    bndl_dir = EXTRACT_DIR / "bndl"
    bundles = {}
    if bndl_dir.exists():
        for bundle_name in sorted(os.listdir(str(bndl_dir))):
            bundle_path = bndl_dir / bundle_name
            if not bundle_path.is_dir():
                continue

            bundle_info = {
                "name": bundle_name,
                "binaries": [],
                "libraries": [],
                "web_assets": [],
                "modules": [],
                "other_files": [],
                "total_size": 0,
            }

            for root, dirs, files in os.walk(str(bundle_path)):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, str(bundle_path))
                    try:
                        fsize = os.path.getsize(fpath)
                    except:
                        fsize = 0
                    bundle_info["total_size"] += fsize

                    if "/nova/bin/" in rel or rel.startswith("nova/bin/"):
                        bundle_info["binaries"].append(f)
                    elif f.endswith(".so"):
                        bundle_info["libraries"].append(f)
                    elif "/web/" in rel or "/home/web/" in rel:
                        bundle_info["web_assets"].append(rel)
                    elif f.endswith(".mem"):
                        bundle_info["modules"].append(rel)
                    else:
                        bundle_info["other_files"].append(rel)

            bundles[bundle_name] = bundle_info

        ec.add_test("npk", "bundle_enumeration", "Enumerate RouterOS bundles",
                     f"{len(bundles)} bundles found",
                     details={"bundles": {k: {
                         "binaries": v["binaries"],
                         "libraries": v["libraries"],
                         "total_size": v["total_size"],
                         "web_assets_count": len(v["web_assets"]),
                     } for k, v in bundles.items()}})

    # ── 8.2 Kernel module analysis ──
    modules_dir = EXTRACT_DIR / "lib" / "modules"
    kernel_modules = []
    kernel_version = None
    if modules_dir.exists():
        for root, dirs, files in os.walk(str(modules_dir)):
            for d in dirs:
                # First level directory is kernel version
                if kernel_version is None and root == str(modules_dir):
                    kernel_version = d
            for f in files:
                if f.endswith(".ko"):
                    rel = os.path.relpath(os.path.join(root, f), str(modules_dir))
                    kernel_modules.append(rel)

    ec.add_test("npk", "kernel_modules", "Kernel modules in firmware",
                f"{len(kernel_modules)} modules, kernel version: {kernel_version or 'unknown'}",
                details={"kernel_version": kernel_version,
                          "modules": sorted(kernel_modules)})

    # Check for known vulnerable kernel module patterns
    if kernel_version:
        ec.add_test("npk", "kernel_version", f"RouterOS kernel version: {kernel_version}",
                     f"Kernel {kernel_version}",
                     details={"version": kernel_version},
                     anomaly="5.6.3" in str(kernel_version))  # old kernel

    # ── 8.3 WebFig asset analysis ──
    webfig_files = []
    if EXTRACT_DIR.exists():
        for root, dirs, files in os.walk(str(EXTRACT_DIR)):
            for f in files:
                if "webfig" in root.lower() or f.endswith((".jg", ".jg.gz")):
                    rel = os.path.relpath(os.path.join(root, f), str(EXTRACT_DIR))
                    webfig_files.append(rel)

    ec.add_test("npk", "webfig_assets", "WebFig web interface assets",
                f"{len(webfig_files)} files",
                details={"files": sorted(webfig_files)})

    # ── 8.4 Shared library dependency mapping ──
    lib_dir = EXTRACT_DIR / "lib"
    shared_libs = {}
    if lib_dir.exists():
        for f in sorted(os.listdir(str(lib_dir))):
            if f.endswith(".so") or ".so." in f:
                fpath = lib_dir / f
                if fpath.is_file():
                    fsize = fpath.stat().st_size
                    fhash = sha256_file(str(fpath))
                    shared_libs[f] = {
                        "size": fsize,
                        "size_human": file_size_human(fsize),
                        "sha256": fhash,
                    }

    ec.add_test("npk", "shared_libraries", "Core shared libraries",
                f"{len(shared_libs)} libraries",
                details={"libraries": shared_libs})

    # ── 8.5 Firmware files and special entries ──
    firmware_dir = EXTRACT_DIR / "lib" / "firmware"
    fw_files = []
    if firmware_dir.exists():
        for root, dirs, files in os.walk(str(firmware_dir)):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), str(EXTRACT_DIR))
                fw_files.append(rel)

    ec.add_test("npk", "device_firmware", "Embedded device firmware files",
                f"{len(fw_files)} firmware files",
                details={"files": sorted(fw_files)})

    return bundles


# ── Section 9: Library-Specific Deep Dive ────────────────────────────────────

def analyze_key_libraries(ec):
    """Deep analysis of security-critical shared libraries."""
    log("=" * 60)
    log("SECTION 9: Security-Critical Library Analysis")
    log("=" * 60)

    if not EXTRACT_DIR.exists():
        ec.add_test("libraries", "extract_dir", "Extracted filesystem available",
                     "FAIL", anomaly=True)
        return

    lib_dir = EXTRACT_DIR / "lib"
    if not lib_dir.exists():
        ec.add_test("libraries", "lib_dir", "Library directory exists",
                     "FAIL", anomaly=True)
        return

    # Key libraries to analyze
    critical_libs = [
        ("libucrypto.so", "Cryptographic library"),
        ("libjson.so", "JSON parsing library"),
        ("libwww.so", "Web server library"),
        ("libuhttp.so", "HTTP library"),
        ("libumsg.so", "Message handling library"),
        ("libc.so", "Custom C library (uClibc/musl)"),
        ("libuc++.so", "C++ standard library"),
        ("libubox.so", "Utility box library"),
        ("libeap.so", "EAP authentication library"),
        ("liburadius.so", "RADIUS client library"),
        ("libxml.so", "XML parsing library"),
        ("libuxml++.so", "XML++ library"),
        ("libufiber.so", "Fiber/coroutine library"),
        ("librappsup.so", "Router app support library"),
    ]

    for lib_name, description in critical_libs:
        lib_path = lib_dir / lib_name
        if not lib_path.exists():
            continue

        log(f"  Analyzing: {lib_name} ({description})")

        # Get strings related to crypto
        stdout, _, rc = run_cmd(["strings", "-a", str(lib_path)], timeout=30)
        if rc != 0:
            continue

        all_strings = stdout.splitlines()

        # Library-specific analysis
        lib_details = {
            "description": description,
            "size": lib_path.stat().st_size,
            "total_strings": len(all_strings),
        }

        if "crypto" in lib_name.lower():
            # Look for crypto algorithms
            algos = set()
            for s in all_strings:
                for algo in ["AES", "DES", "3DES", "RSA", "EC", "ECDSA", "ECDH",
                              "SHA1", "SHA256", "SHA384", "SHA512", "SHA-1", "SHA-256",
                              "MD5", "HMAC", "ChaCha20", "Poly1305", "GCM", "CBC",
                              "CTR", "CCM", "Ed25519", "Curve25519", "X25519",
                              "secp256r1", "secp384r1", "prime256v1"]:
                    if algo.lower() in s.lower():
                        algos.add(algo)
            lib_details["crypto_algorithms"] = sorted(algos)

            # Check for weak algorithms
            weak = [a for a in algos if a.upper() in ["DES", "MD5", "SHA1", "SHA-1", "3DES", "RC4"]]
            if weak:
                ec.add_test("libraries", f"weak_crypto_{lib_name}",
                             f"Weak cryptographic algorithms in {lib_name}",
                             f"FOUND: {', '.join(weak)}",
                             details={"weak_algorithms": weak}, anomaly=True)

        if "json" in lib_name.lower():
            # Look for parser vulnerability indicators
            depth_refs = [s for s in all_strings if "depth" in s.lower() or "nest" in s.lower()]
            size_refs = [s for s in all_strings if "size" in s.lower() or "limit" in s.lower() or "max" in s.lower()]
            lib_details["depth_references"] = depth_refs[:10]
            lib_details["size_references"] = size_refs[:10]

        if "http" in lib_name.lower() or "www" in lib_name.lower():
            # Look for HTTP methods, headers, error codes
            methods = set()
            for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]:
                if any(m in s for s in all_strings):
                    methods.add(m)
            lib_details["http_methods"] = sorted(methods)

            # Check for potentially dangerous TRACE/CONNECT
            if "TRACE" in methods:
                ec.add_test("libraries", "http_trace_method",
                             "HTTP TRACE method supported in web library",
                             "SUPPORTED",
                             anomaly=True)

        # Check for version strings
        versions = [s for s in all_strings if re.match(r'^\d+\.\d+(\.\d+)?$', s.strip())]
        if versions:
            lib_details["version_strings"] = versions[:10]

        ec.add_test("libraries", f"lib_{lib_name.replace('.', '_')}",
                     f"Library analysis: {lib_name} ({description})",
                     f"{len(all_strings)} strings, {file_size_human(lib_path.stat().st_size)}",
                     details=lib_details)

    # Check libc identification (uClibc vs musl vs glibc)
    libc_path = lib_dir / "libc.so"
    if libc_path.exists():
        stdout, _, _ = run_cmd(["strings", "-a", str(libc_path)], timeout=30)
        libc_id = "unknown"
        if stdout:
            if "uClibc" in stdout:
                libc_id = "uClibc"
            elif "musl" in stdout:
                libc_id = "musl"
            elif "GLIBC" in stdout or "GNU C Library" in stdout:
                libc_id = "glibc"
            # Extract version
            for line in stdout.splitlines():
                if any(v in line for v in ["uClibc", "musl", "GLIBC", "GNU C Library"]):
                    libc_id = line.strip()
                    break

        ec.add_test("libraries", "libc_identification",
                     "Identify C library implementation",
                     f"{libc_id}",
                     details={"identification": libc_id},
                     anomaly="uClibc" in libc_id)  # uClibc has known issues


# ── Section 10: EFI and Boot Analysis ─────────────────────────────────────────

def analyze_boot(ec):
    """Analyze boot components for secure boot, signing, etc."""
    log("=" * 60)
    log("SECTION 10: Boot & EFI Analysis")
    log("=" * 60)

    # Re-mount partition 1 for EFI analysis
    MOUNT_P1.mkdir(parents=True, exist_ok=True)
    run_cmd(f"sudo mount -o loop,ro,offset={PART1_OFFSET} {CHR_IMAGE} {MOUNT_P1}", shell=True)

    efi_boot = MOUNT_P1 / "EFI" / "BOOT" / "BOOTX64.EFI"
    if efi_boot.exists():
        efi_size = efi_boot.stat().st_size
        efi_hash = sha256_file(str(efi_boot))

        stdout, _, rc = run_cmd(["file", str(efi_boot)])
        ec.add_test("boot", "efi_bootloader", "EFI bootloader analysis",
                     f"PRESENT — {file_size_human(efi_size)}, SHA256={efi_hash[:16]}...",
                     details={
                         "size": efi_size,
                         "sha256": efi_hash,
                         "file_type": stdout.strip() if rc == 0 else "unknown",
                     })

        # Check for secure boot signatures
        stdout, _, rc = run_cmd(["strings", "-a", str(efi_boot)], timeout=30)
        if stdout:
            sb_indicators = []
            for s in stdout.splitlines():
                lower = s.lower()
                if any(kw in lower for kw in ["secure boot", "signature", "certificate",
                                                "authenticode", "pkcs", "x509"]):
                    sb_indicators.append(s)

            ec.add_test("boot", "secure_boot_check",
                         "Check for Secure Boot indicators in EFI bootloader",
                         f"{'FOUND ' + str(len(sb_indicators)) + ' indicators' if sb_indicators else 'NONE FOUND'}",
                         details={"indicators": sb_indicators[:20]})
    else:
        ec.add_test("boot", "efi_bootloader", "EFI bootloader analysis",
                     "NOT FOUND")

    # Analyze milo bootloader (in partition 2)
    # Re-mount p2
    MOUNT_P2.mkdir(parents=True, exist_ok=True)
    run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
    run_cmd("sudo losetup -D", shell=True)
    run_cmd(f"sudo mount -o loop,ro,offset={PART1_OFFSET} {CHR_IMAGE} {MOUNT_P1}", shell=True)

    lo_out, _, _ = run_cmd(
        f"sudo losetup -f --show -o {PART2_OFFSET} --sizelimit {PART2_SIZE} -r {CHR_IMAGE}",
        shell=True)
    if lo_out.strip():
        run_cmd(f"sudo mount -r {lo_out.strip()} {MOUNT_P2}", shell=True)

    milo_path = MOUNT_P2 / "bin" / "milo"
    if milo_path.exists():
        milo_size = milo_path.stat().st_size
        stdout, _, rc = run_cmd(["file", str(milo_path)])

        ec.add_test("boot", "milo_bootloader", "MikroTik milo bootloader analysis",
                     f"PRESENT — {file_size_human(milo_size)}, {stdout.strip() if rc == 0 else 'unknown'}",
                     details={"size": milo_size})

        # Strings in milo
        stdout, _, rc = run_cmd(["strings", "-a", str(milo_path)], timeout=30)
        if stdout:
            milo_strings = stdout.splitlines()
            interesting = [s for s in milo_strings if len(s) > 5 and not s.startswith(".")]
            ec.add_test("boot", "milo_strings", "Strings in milo bootloader",
                         f"{len(milo_strings)} total, {len(interesting)} meaningful",
                         details={"sample_strings": interesting[:50]})

    # Analyze bash (RouterOS shell?)
    bash_path = MOUNT_P2 / "bin" / "bash"
    if bash_path.exists():
        stdout, _, rc = run_cmd(["file", str(bash_path)])
        bash_size = bash_path.stat().st_size
        ec.add_test("boot", "shell_binary", "RouterOS shell binary (bin/bash)",
                     f"PRESENT — {file_size_human(bash_size)}, {stdout.strip() if rc == 0 else 'unknown'}",
                     details={"size": bash_size, "type": stdout.strip() if rc == 0 else "unknown"})

    # Clean up
    run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
    run_cmd(f"sudo umount {MOUNT_P2}", shell=True)
    run_cmd("sudo losetup -D", shell=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Phase 1: Static Analysis")
    log(f"Image: {CHR_IMAGE}")
    log(f"Target: {TARGET}")
    log(f"Extraction directory: {EXTRACT_DIR}")
    log("=" * 60)

    # Ensure directories exist
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    ec = EvidenceCollector("static_analysis.py", "Phase 1 — Static Analysis")

    # Track section results
    sections_completed = []
    sections_failed = []

    # ── Section 1: Firmware Extraction ──
    try:
        result = extract_firmware(ec)
        if result:
            sections_completed.append("firmware_extraction")
        else:
            sections_failed.append("firmware_extraction")
            log("WARNING: Firmware extraction failed. Binary analysis sections will be limited.")
    except Exception as e:
        log(f"ERROR in firmware extraction: {e}")
        sections_failed.append("firmware_extraction")
        import traceback
        traceback.print_exc()

    # ── Section 2: Binary Security (checksec) ──
    checksec_data = {}
    try:
        checksec_data = analyze_binary_security(ec)
        sections_completed.append("binary_checksec")
    except Exception as e:
        log(f"ERROR in binary security analysis: {e}")
        sections_failed.append("binary_checksec")
        import traceback
        traceback.print_exc()

    # Save checksec results separately
    if checksec_data:
        checksec_file = EVIDENCE_DIR / "binary_checksec.json"
        with open(checksec_file, "w") as f:
            json.dump({
                "metadata": {
                    "script": "static_analysis.py",
                    "section": "binary_checksec",
                    "timestamp": datetime.now().isoformat(),
                    "total_binaries": len(checksec_data),
                },
                "results": checksec_data,
            }, f, indent=2, default=str)
        log(f"Checksec results saved to {checksec_file}")

    # ── Section 3: Strings Analysis ──
    try:
        analyze_strings(ec)
        sections_completed.append("strings_analysis")
    except Exception as e:
        log(f"ERROR in strings analysis: {e}")
        sections_failed.append("strings_analysis")
        import traceback
        traceback.print_exc()

    # ── Section 4: Unsafe Function Detection ──
    try:
        analyze_unsafe_functions(ec)
        sections_completed.append("unsafe_functions")
    except Exception as e:
        log(f"ERROR in unsafe function detection: {e}")
        sections_failed.append("unsafe_functions")
        import traceback
        traceback.print_exc()

    # ── Section 5: Radare2 Analysis ──
    try:
        analyze_r2_functions(ec)
        sections_completed.append("r2_analysis")
    except Exception as e:
        log(f"ERROR in radare2 analysis: {e}")
        sections_failed.append("r2_analysis")
        import traceback
        traceback.print_exc()

    # ── Section 6: Handler Enumeration ──
    try:
        enumerate_handlers(ec)
        sections_completed.append("handler_enumeration")
    except Exception as e:
        log(f"ERROR in handler enumeration: {e}")
        sections_failed.append("handler_enumeration")
        import traceback
        traceback.print_exc()

    # ── Section 7: Configuration Analysis ──
    try:
        analyze_configuration(ec)
        sections_completed.append("configuration_analysis")
    except Exception as e:
        log(f"ERROR in configuration analysis: {e}")
        sections_failed.append("configuration_analysis")
        import traceback
        traceback.print_exc()

    # ── Section 8: NPK Package Structure ──
    try:
        analyze_npk_structure(ec)
        sections_completed.append("npk_analysis")
    except Exception as e:
        log(f"ERROR in NPK analysis: {e}")
        sections_failed.append("npk_analysis")
        import traceback
        traceback.print_exc()

    # ── Section 9: Library Analysis ──
    try:
        analyze_key_libraries(ec)
        sections_completed.append("library_analysis")
    except Exception as e:
        log(f"ERROR in library analysis: {e}")
        sections_failed.append("library_analysis")
        import traceback
        traceback.print_exc()

    # ── Section 10: Boot Analysis ──
    try:
        analyze_boot(ec)
        sections_completed.append("boot_analysis")
    except Exception as e:
        log(f"ERROR in boot analysis: {e}")
        sections_failed.append("boot_analysis")
        import traceback
        traceback.print_exc()

    # ── Final Cleanup ──
    log("=" * 60)
    log("Cleaning up mounts...")
    run_cmd(f"sudo umount {MOUNT_P1}", shell=True)
    run_cmd(f"sudo umount {MOUNT_P2}", shell=True)
    run_cmd("sudo losetup -D", shell=True)

    # Add metadata summary
    ec.results["metadata"]["sections_completed"] = sections_completed
    ec.results["metadata"]["sections_failed"] = sections_failed

    # ── Save Evidence ──
    ec.save("static_analysis.json")
    ec.summary()

    log(f"\nSections completed: {len(sections_completed)}/{len(sections_completed) + len(sections_failed)}")
    if sections_failed:
        log(f"Sections failed: {', '.join(sections_failed)}")

    log(f"\nEvidence files:")
    log(f"  - {EVIDENCE_DIR}/static_analysis.json")
    log(f"  - {EVIDENCE_DIR}/binary_checksec.json")
    log(f"  - {CONFIGS_DIR}/live_config_snapshot.json")
    log(f"  - {EXTRACT_DIR}/ (extracted filesystem)")


if __name__ == "__main__":
    main()
