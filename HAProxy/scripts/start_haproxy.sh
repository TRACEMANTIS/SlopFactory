#!/bin/bash
# Start HAProxy with backend servers for security testing
# Usage: ./start_haproxy.sh [asan|clean] [config]
# Default: asan build with haproxy-all.cfg

set -e

BASE="/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy"
BUILD="${1:-asan}"
CONFIG="${2:-haproxy-all.cfg}"

# Select binary
if [ "$BUILD" = "asan" ]; then
    HAPROXY="$BASE/source/haproxy-asan"
    echo "[*] Using ASAN build (memory error detection enabled)"
elif [ "$BUILD" = "clean" ]; then
    HAPROXY="$BASE/source/haproxy-clean"
    echo "[*] Using clean build (for fuzzing/performance)"
else
    echo "Usage: $0 [asan|clean] [config-file]"
    exit 1
fi

CONFIG_PATH="$BASE/configs/$CONFIG"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "[-] Config not found: $CONFIG_PATH"
    exit 1
fi

# Kill any existing instances
pkill -f haproxy-asan 2>/dev/null || true
pkill -f haproxy-clean 2>/dev/null || true
pkill -f backend_server.py 2>/dev/null || true
sleep 1

# Start backend servers
echo "[*] Starting backend echo servers on 9090, 9091..."
python3 "$BASE/scripts/backend_server.py" 9090 9091 &
BACKEND_PID=$!
sleep 1

# Validate config
echo "[*] Validating config: $CONFIG"
if ! $HAPROXY -c -f "$CONFIG_PATH" 2>&1; then
    echo "[-] Config validation failed!"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

# Start HAProxy
echo "[*] Starting HAProxy ($BUILD) with $CONFIG..."
$HAPROXY -f "$CONFIG_PATH" -db &
HAPROXY_PID=$!
sleep 2

# Verify
echo "[*] Verifying services..."
if kill -0 $HAPROXY_PID 2>/dev/null; then
    echo "[+] HAProxy running (PID: $HAPROXY_PID)"
else
    echo "[-] HAProxy failed to start!"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

echo "[+] Backend servers running (PID: $BACKEND_PID)"
echo ""
echo "Services:"
echo "  HTTP/1.1:     http://127.0.0.1:8080"
echo "  HTTPS/H2:     https://127.0.0.1:8443"
echo "  QUIC/H3:      https://127.0.0.1:8443 (UDP)"
echo "  QUIC-only:    https://127.0.0.1:4443 (UDP)"
echo "  Lua:          http://127.0.0.1:8085"
echo "  TCP:          127.0.0.1:8888"
echo "  Stats:        http://127.0.0.1:8404/stats (admin:TestPass123)"
echo "  Prometheus:   http://127.0.0.1:8404/metrics"
echo "  CLI socket:   /tmp/haproxy.sock"
echo ""
echo "To stop: kill $HAPROXY_PID $BACKEND_PID"

wait
