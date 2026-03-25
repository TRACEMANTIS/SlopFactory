#!/usr/bin/env python3
"""
TendaAssmt Phase 1d: Authentication Analysis & Cross-Model Comparison
Documents which endpoints bypass authentication in AC15 and AC20.
"""
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/scripts')
from tenda_common import EvidenceCollector, EVIDENCE_DIR

ec = EvidenceCollector("phase1d_auth_analysis")

# ====== AUTHENTICATION BYPASS WHITELIST ======
# Extracted from R7WebsSecurityHandler disassembly via r2

ac15_unauth = {
    "goform_endpoints": [
        "/goform/ate",
        "/goform/getRebootStatus",
        "/goform/GetRouterStatus",
        "/goform/GetUSBStatus",
        "/goform/getWanParameters",
        "/goform/telnet",
        "/goform/WifiApScan"
    ],
    "web_paths": [
        "/error.asp",
        "/favicon.ico",
        "/index.html",
        "/kns-query",
        "/lang/",
        "/login.asp",
        "/login/Auth",
        "/loginerr.html",
        "/logout/Auth",
        "/public/",
        "/redirect.html",
        "/wdinfo.php",
        "/webroot/main.html"
    ],
    "handler_vaddr": "0x0002f500",
    "handler_size": 5500,
    "handler_name": "R7WebsSecurityHandler"
}

ac20_unauth = {
    "goform_endpoints": [
        "/goform/ate",
        "/goform/getLoginInfo",
        "/goform/getRebootStatus",
        "/goform/GetRouterStatus",
        "/goform/GetUSBStatus",
        "/goform/getWanParameters",
        "/goform/telnet",
        "/goform/WifiApScan"
    ],
    "web_paths": [
        "/error.asp",
        "/favicon.ico",
        "/index.html",
        "/kns-query",
        "/lang/",
        "/login.asp",
        "/login/Auth",
        "/loginerr.html",
        "/logout/Auth",
        "/public/",
        "/redirect.html",
        "/wdinfo.php",
        "/webroot/main.html"
    ],
    "handler_vaddr": "0x00435150",
    "handler_size": 8940,
    "handler_name": "R7WebsSecurityHandler"
}

# ====== CRITICAL ANALYSIS ======
print("=" * 70)
print("TendaAssmt Phase 1d: Authentication Analysis")
print("=" * 70)

print("\n[!] UNAUTHENTICATED GOFORM ENDPOINTS:")
print("\n--- AC15 (7 endpoints) ---")
for ep in ac15_unauth["goform_endpoints"]:
    print(f"  {ep}")

print("\n--- AC20 (8 endpoints - includes getLoginInfo) ---")
for ep in ac20_unauth["goform_endpoints"]:
    marker = " [AC20-ONLY]" if ep == "/goform/getLoginInfo" else ""
    print(f"  {ep}{marker}")

# What each unauthenticated endpoint does:
unauth_analysis = {
    "/goform/ate": {
        "risk": "CRITICAL",
        "description": "Manufacturing ATE test endpoint. May allow arbitrary command execution or device reconfiguration without authentication.",
        "handler": "ate handler (not named form*)",
        "notes": "ATE = Advanced Test Equipment. Common backdoor in Tenda devices."
    },
    "/goform/telnet": {
        "risk": "CRITICAL",
        "description": "Enables/disables telnet daemon without authentication. Direct RCE vector if telnet is enabled.",
        "handler": "telnet handler",
        "notes": "CVE-2025-9090 targets this endpoint in AC20. Check if AC15 is also vulnerable."
    },
    "/goform/GetRouterStatus": {
        "risk": "MEDIUM",
        "description": "Returns router status information without authentication. Information disclosure.",
        "handler": "formGetRouterStatus",
        "notes": "May leak WAN IP, firmware version, connected clients."
    },
    "/goform/getWanParameters": {
        "risk": "MEDIUM",
        "description": "Returns WAN connection parameters without authentication.",
        "handler": "formGetWanParameter",
        "notes": "May leak ISP credentials, WAN IP, DNS servers."
    },
    "/goform/GetUSBStatus": {
        "risk": "LOW",
        "description": "Returns USB device status. Minor info disclosure.",
        "handler": "formGetUSBStatus",
        "notes": "Limited impact."
    },
    "/goform/getRebootStatus": {
        "risk": "LOW",
        "description": "Returns device reboot status.",
        "handler": "formGetRebootStatus (inline)",
        "notes": "Limited impact."
    },
    "/goform/WifiApScan": {
        "risk": "MEDIUM",
        "description": "Triggers WiFi AP scanning without authentication.",
        "handler": "formWifiApScan",
        "notes": "May leak nearby AP information. Repeated scanning could be used for DoS."
    },
    "/goform/getLoginInfo": {
        "risk": "HIGH",
        "description": "AC20-ONLY. Returns login-related information without authentication.",
        "handler": "formGetLoginInfo",
        "notes": "May leak session info, password hashes, or login state. HIGH priority for analysis."
    }
}

print("\n[!] RISK ANALYSIS OF UNAUTHENTICATED ENDPOINTS:")
print("-" * 70)
for ep, analysis in sorted(unauth_analysis.items(), key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x[1]["risk"]]):
    print(f"\n  {ep}")
    print(f"    Risk: {analysis['risk']}")
    print(f"    {analysis['description']}")
    print(f"    Handler: {analysis['handler']}")
    print(f"    Notes: {analysis['notes']}")

# Record findings
for ep, analysis in unauth_analysis.items():
    if analysis["risk"] in ("CRITICAL", "HIGH"):
        ec.add_finding(
            f"UNAUTH-{ep.split('/')[-1]}",
            analysis["risk"],
            f"Unauthenticated access to {ep}",
            json.dumps(analysis, indent=2),
            cwe="CWE-306",
            endpoint=ep
        )

# ====== CROSS-MODEL COMPARISON ======
print("\n" + "=" * 70)
print("CROSS-MODEL COMPARISON: AC15 vs AC20")
print("=" * 70)

# Handler differences
ac15_handlers = set([
    "formAliScheduleStatus", "formBulletinSet", "formDLNAserver", "formExpandDlnaFile",
    "form_fast_setting_pppoe_set", "formGetAllWanInfo", "formGetAutoQosInfo",
    "formGetBandWidthSpeed", "formGetDdosDefenceList", "formGetDeviceDetail",
    "formGetDhcpServer", "formGetIPv6Info", "formGetIPv6LanStatus", "formGetIPv6WanStatus",
    "formGetPortStatus", "formGetSambaConf", "formGetSysInfo", "formGetSystemSet",
    "formGetUsbCfg", "formGetUsbPrint", "formGetUSBStatus", "formGetWanNum",
    "formGetWanStatistic", "formGetWanStatus", "formMfgTest", "formNatSet",
    "formQuickIndex", "formSetAutoQosInfo", "formSetCfm", "formSetClientState",
    "formSetIPv6LanStatus", "formSetIPv6WanStatus", "formSetSambaConf", "formSetSpeedWan",
    "formSetUsbPrint", "formsetUsbUnload", "formTendaGetDhcpClients",
    "formTendaGetGuestDhcpClients", "formTendaModelStatus", "formWifiClientList",
    "formWifiClientListAll", "formWifiConfigGet", "formWifiDhcpGuestGet",
    "formWifiDhcpGuestLists", "formWifiDhcpGuestSet", "formWifiMacFilterGet",
    "formWifiMacFilterSet", "formWifiMultiSsid", "formWifiStatistic",
    "formWifiStatisticClear", "formWifiStatus", "formWifiWpsOOB", "formWifiWpsStart",
    "formWriteFacMac"
])

ac20_handlers = set([
    "formDefineTendDa", "formDefineUcloudv2", "formGetLoginInfo", "formGetProduct",
    "formSetIPv6status", "form_SyncAccount_get", "formWifiAntijamGet",
    "formWifiAntijamSet", "formWifiRadioSet_send_msg"
])

print(f"\nAC15-only handlers: {len(ac15_handlers)}")
print(f"AC20-only handlers: {len(ac20_handlers)}")
print(f"\nAC20-UNIQUE handlers (priority targets for novel findings):")
for h in sorted(ac20_handlers):
    print(f"  - {h}")

print(f"\nAC15-UNIQUE handlers with HIGH research value:")
high_value_ac15 = ["formMfgTest", "formWriteFacMac", "formSetCfm", "formNatSet",
                   "formSetClientState", "formSetSpeedWan", "formQuickIndex"]
for h in high_value_ac15:
    print(f"  - {h}")

# Record cross-model test
ec.add_test(
    "CROSS-MODEL-DIFF",
    "Cross-model handler comparison: AC15 vs AC20",
    "r2 symbol table comparison",
    json.dumps({
        "ac15_total_handlers": 120,
        "ac20_total_handlers": 75,
        "ac15_only": sorted(list(ac15_handlers)),
        "ac20_only": sorted(list(ac20_handlers)),
        "shared_count": 66
    }, indent=2),
    status="INFO"
)

# Record auth analysis
ec.add_test(
    "AC15-UNAUTH",
    "AC15 unauthenticated goform endpoints",
    "R7WebsSecurityHandler disassembly analysis",
    json.dumps(ac15_unauth, indent=2),
    status="VULN"
)

ec.add_test(
    "AC20-UNAUTH",
    "AC20 unauthenticated goform endpoints",
    "R7WebsSecurityHandler disassembly analysis",
    json.dumps(ac20_unauth, indent=2),
    status="VULN"
)

# Key finding: the "goform/" prefix match
ec.add_finding(
    "UNAUTH-PREFIX-MATCH",
    "HIGH",
    "AC20 R7WebsSecurityHandler contains bare 'goform/' prefix match",
    "The AC20 security handler contains a strncmp against 'goform/' (without leading /). "
    "This may allow auth bypass by requesting 'goform/SetFirewallCfg' directly (without /goform/ prefix) "
    "or through URL path manipulation. Needs dynamic testing to confirm.",
    cwe="CWE-287",
    endpoint="goform/*"
)

ec.save("phase1d_auth_analysis.json")
print(f"\n[*] Phase 1d complete. Evidence saved.")
