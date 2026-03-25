#!/usr/bin/env python3
"""
ProFTPD 1.3.9 boofuzz State Machine Fuzzer
independent security research. — Phase 2

Full FTP state machine with pre-auth and post-auth fuzzing.
"""

import os
import sys
import json
import time
from datetime import datetime

try:
    from boofuzz import *
except ImportError:
    print("[!] boofuzz not installed. Install with: pip install boofuzz")
    sys.exit(1)

HOST = "127.0.0.1"
PORT = 21
USER = "ftptest"
PASS = "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def check_alive(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """Post-test callback to check if server is alive"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        data = s.recv(1024)
        s.close()
        if b"220" not in data:
            raise Exception("Server not responding properly")
    except Exception as e:
        # Server crashed!
        fuzz_data_logger.log_info(f"SERVER CRASH DETECTED: {e}")
        raise

def main():
    print("=" * 60)
    print("ProFTPD 1.3.9 boofuzz State Machine Fuzzer")
    print("=" * 60)

    session = Session(
        target=Target(
            connection=TCPSocketConnection(HOST, PORT),
        ),
        sleep_time=0.1,
        restart_sleep_time=3,
        post_test_case_callbacks=[check_alive],
        fuzz_loggers=[FuzzLoggerText()],
        keep_web_open=False,
        web_port=26000,
    )

    # Define FTP state machine

    # Pre-auth: USER command
    s_initialize("USER")
    s_string("USER", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("ftptest", name="username", fuzzable=True, max_len=1024)
    s_static("\r\n")

    # PASS command
    s_initialize("PASS")
    s_string("PASS", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("ftptest123", name="password", fuzzable=True, max_len=1024)
    s_static("\r\n")

    # Post-auth commands
    # CWD
    s_initialize("CWD")
    s_string("CWD", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp", name="path", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # MKD
    s_initialize("MKD")
    s_string("MKD", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("testdir", name="dirname", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # STOR
    s_initialize("STOR")
    s_string("STOR", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("testfile", name="filename", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # RETR
    s_initialize("RETR")
    s_string("RETR", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("testfile", name="filename", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # DELE
    s_initialize("DELE")
    s_string("DELE", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("testfile", name="filename", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # LIST
    s_initialize("LIST")
    s_string("LIST", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("*", name="pattern", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # SITE CPFR
    s_initialize("SITE_CPFR")
    s_string("SITE CPFR", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/etc/passwd", name="source", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # SITE CPTO
    s_initialize("SITE_CPTO")
    s_string("SITE CPTO", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/test", name="dest", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # SITE SYMLINK
    s_initialize("SITE_SYMLINK")
    s_string("SITE SYMLINK", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/src", name="source", fuzzable=True, max_len=1024)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/dst", name="dest", fuzzable=True, max_len=1024)
    s_static("\r\n")

    # SITE CHMOD
    s_initialize("SITE_CHMOD")
    s_string("SITE CHMOD", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("777", name="mode", fuzzable=True, max_len=256)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/test", name="path", fuzzable=True, max_len=1024)
    s_static("\r\n")

    # RNFR / RNTO
    s_initialize("RNFR")
    s_string("RNFR", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/old", name="oldpath", fuzzable=True, max_len=2048)
    s_static("\r\n")

    s_initialize("RNTO")
    s_string("RNTO", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp/new", name="newpath", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # STAT
    s_initialize("STAT")
    s_string("STAT", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/tmp", name="path", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # SIZE
    s_initialize("SIZE")
    s_string("SIZE", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/etc/passwd", name="path", fuzzable=True, max_len=2048)
    s_static("\r\n")

    # QUIT
    s_initialize("QUIT")
    s_static("QUIT\r\n")

    # Build state machine
    session.connect(s_get("USER"))
    session.connect(s_get("USER"), s_get("PASS"))
    # Post-auth transitions
    session.connect(s_get("PASS"), s_get("CWD"))
    session.connect(s_get("PASS"), s_get("MKD"))
    session.connect(s_get("PASS"), s_get("STOR"))
    session.connect(s_get("PASS"), s_get("RETR"))
    session.connect(s_get("PASS"), s_get("DELE"))
    session.connect(s_get("PASS"), s_get("LIST"))
    session.connect(s_get("PASS"), s_get("SITE_CPFR"))
    session.connect(s_get("SITE_CPFR"), s_get("SITE_CPTO"))
    session.connect(s_get("PASS"), s_get("SITE_SYMLINK"))
    session.connect(s_get("PASS"), s_get("SITE_CHMOD"))
    session.connect(s_get("PASS"), s_get("RNFR"))
    session.connect(s_get("RNFR"), s_get("RNTO"))
    session.connect(s_get("PASS"), s_get("STAT"))
    session.connect(s_get("PASS"), s_get("SIZE"))

    print(f"\n[*] Starting boofuzz session...")
    print(f"[*] Monitor web UI at http://localhost:26000")

    session.fuzz()

    # Save results summary
    summary = {
        "fuzzer": "boofuzz_ftp_statemachine",
        "target": f"ProFTPD 1.3.9 at {HOST}:{PORT}",
        "date": datetime.now().isoformat(),
        "notes": "See boofuzz database for detailed results"
    }

    with open(os.path.join(EVIDENCE_DIR, "boofuzz_summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n[*] boofuzz session complete")


if __name__ == "__main__":
    main()
