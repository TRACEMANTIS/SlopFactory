#!/bin/bash
# ProFTPD Phase 4 — GDB Trace of E2BIG Silent Disconnect
# Attaches to a child process during the E2BIG path to capture the call stack
# at the point of pr_session_disconnect.

EVIDENCE_DIR="/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"
GDB_LOG="$EVIDENCE_DIR/phase4_gdb_e2big_trace.txt"

# Trigger script runs in background, GDB attaches to child
python3 - <<'PYEOF' &
import socket, time
s = socket.socket()
s.settimeout(30)
s.connect(('127.0.0.1', 21))
s.recv(512)  # banner
# Send USER with large arg — will trigger E2BIG path
s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
time.sleep(12)  # Hold connection open while GDB attaches
s.close()
PYEOF
TRIGGER_PID=$!

# Give the connection time to be forked
sleep 0.5

# Find the child process (most recent proftpd child)
CHILD_PID=$(pgrep -n -P $(pgrep -o proftpd) 2>/dev/null || pgrep -n proftpd 2>/dev/null)
echo "Trigger PID: $TRIGGER_PID"
echo "ProFTPD child PID: $CHILD_PID"

if [ -z "$CHILD_PID" ]; then
    echo "No child process found, trying master PID"
    CHILD_PID=$(pgrep -n proftpd)
fi

echo "Attaching GDB to PID $CHILD_PID..."

# GDB batch: set breakpoints on key functions, then run bt when hit
sudo gdb -batch \
    -ex "set pagination off" \
    -ex "set auto-load safe-path /" \
    -ex "attach $CHILD_PID" \
    -ex "break pr_session_disconnect" \
    -ex "commands 1" \
    -ex "  echo === pr_session_disconnect called ===" \
    -ex "  backtrace" \
    -ex "  info registers" \
    -ex "  continue" \
    -ex "end" \
    -ex "continue" \
    -ex "quit" \
    /usr/sbin/proftpd 2>&1 | tee "$GDB_LOG"

# Wait for trigger to finish
wait $TRIGGER_PID 2>/dev/null
echo ""
echo "GDB trace saved to $GDB_LOG"
