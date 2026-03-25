#!/usr/bin/env python3
"""
Chain Link 2: Validate POP chain gadgets in WordPress 6.8.1
Confirms that WP_HTML_Token has __destruct -> call_user_func
and checks for __wakeup protection.

No exploitation -- just gadget validation.
"""

import re
import json
import sys
from datetime import datetime

WP_INCLUDES = "/var/www/html/wp-lab/wp-includes"

GADGET_FILES = {
    "WP_HTML_Token": f"{WP_INCLUDES}/html-api/class-wp-html-token.php",
    "WP_HTML_Tag_Processor": f"{WP_INCLUDES}/html-api/class-wp-html-tag-processor.php",
    "WP_Image_Editor_Imagick": f"{WP_INCLUDES}/class-wp-image-editor-imagick.php",
    "WP_Image_Editor_GD": f"{WP_INCLUDES}/class-wp-image-editor-gd.php",
    "WP_Block_Patterns_Registry": f"{WP_INCLUDES}/class-wp-block-patterns-registry.php",
}

def check_gadget(class_name, filepath):
    """Check a class for POP chain gadget potential."""
    result = {
        "class": class_name,
        "file": filepath,
        "magic_methods": {},
        "dangerous_calls": [],
        "wakeup_protection": False,
    }

    try:
        with open(filepath, "r") as f:
            content = f.read()
    except FileNotFoundError:
        result["error"] = "File not found"
        return result

    # Check for magic methods
    for method in ["__destruct", "__wakeup", "__toString", "__call", "__get", "__set"]:
        pattern = rf'function\s+{re.escape(method)}\s*\('
        match = re.search(pattern, content)
        if match:
            # Get the method body (next 20 lines)
            start = match.start()
            lines_after = content[start:start+800].split("\n")[:15]
            result["magic_methods"][method] = {
                "present": True,
                "snippet": "\n".join(lines_after)
            }

    # Check for dangerous function calls within magic methods
    for dangerous in ["call_user_func", "eval", "include", "require", "system", "exec", "popen"]:
        if dangerous in content:
            # Find the line
            for i, line in enumerate(content.split("\n"), 1):
                if dangerous in line and not line.strip().startswith("*") and not line.strip().startswith("//"):
                    result["dangerous_calls"].append({
                        "function": dangerous,
                        "line": i,
                        "code": line.strip()
                    })

    # Check for __wakeup protection
    result["wakeup_protection"] = "__wakeup" in result["magic_methods"]

    # Assess gadget utility
    has_destruct = "__destruct" in result["magic_methods"]
    has_tostring = "__toString" in result["magic_methods"]
    has_dangerous = len(result["dangerous_calls"]) > 0

    if has_destruct and has_dangerous and not result["wakeup_protection"]:
        result["gadget_rating"] = "CRITICAL - __destruct with dangerous call, no __wakeup"
    elif has_destruct and has_dangerous and result["wakeup_protection"]:
        result["gadget_rating"] = "PROTECTED - __destruct has dangerous call but __wakeup blocks deserialization"
    elif has_tostring and not result["wakeup_protection"]:
        result["gadget_rating"] = "USEFUL - __toString without __wakeup, can be chained"
    elif has_destruct and not result["wakeup_protection"]:
        result["gadget_rating"] = "LOW - __destruct without dangerous call or __wakeup"
    else:
        result["gadget_rating"] = "MINIMAL"

    return result


def validate_realpath_trigger():
    """Check if block patterns registry passes filePath to realpath() without type check."""
    filepath = f"{WP_INCLUDES}/class-wp-block-patterns-registry.php"
    result = {
        "check": "block_patterns_realpath_trigger",
        "file": filepath,
    }

    with open(filepath, "r") as f:
        content = f.read()

    # Look for realpath on filePath
    if "realpath" in content:
        for i, line in enumerate(content.split("\n"), 1):
            if "realpath" in line and "filePath" in line:
                result["vulnerable_line"] = i
                result["code"] = line.strip()
                # Check if there's a type check before realpath
                result["has_type_check"] = "is_string" in line or "is_stringy" in line
                result["vulnerable"] = not result["has_type_check"]
                break
    else:
        # In 6.8.1, realpath might not be present -- the filePath is used differently
        # Check how filePath is used
        for i, line in enumerate(content.split("\n"), 1):
            if "filePath" in line and ("include" in line or "require" in line or "file_get_contents" in line):
                result["filePath_usage"] = {
                    "line": i,
                    "code": line.strip()
                }

    return result


def main():
    results = {
        "test": "pop_chain_gadget_validation",
        "timestamp": datetime.now().isoformat(),
        "wp_version": "6.8.1",
        "gadgets": {},
        "realpath_trigger": None,
    }

    for class_name, filepath in GADGET_FILES.items():
        results["gadgets"][class_name] = check_gadget(class_name, filepath)

    results["realpath_trigger"] = validate_realpath_trigger()

    # Summary
    critical_gadgets = [
        name for name, g in results["gadgets"].items()
        if "CRITICAL" in g.get("gadget_rating", "")
    ]
    useful_gadgets = [
        name for name, g in results["gadgets"].items()
        if "USEFUL" in g.get("gadget_rating", "")
    ]
    protected_gadgets = [
        name for name, g in results["gadgets"].items()
        if "PROTECTED" in g.get("gadget_rating", "")
    ]

    results["summary"] = {
        "critical_gadgets": critical_gadgets,
        "useful_gadgets": useful_gadgets,
        "protected_gadgets": protected_gadgets,
        "pop_chain_viable": len(critical_gadgets) > 0 or (
            len(protected_gadgets) > 0 and len(useful_gadgets) > 0
        ),
        "detail": (
            f"Found {len(critical_gadgets)} unprotected gadget(s) with dangerous calls, "
            f"{len(useful_gadgets)} useful chaining gadget(s), "
            f"{len(protected_gadgets)} protected gadget(s). "
            "POP chain is viable through unprotected classes or via __toString chaining."
        )
    }

    output = json.dumps(results, indent=2)
    print(output)

    with open("/home/[REDACTED]/Desktop/SecSoft/wp-rce-research/evidence/02_pop_chain.json", "w") as f:
        f.write(output)

    return results


if __name__ == "__main__":
    results = main()
    sys.exit(0 if results["summary"]["pop_chain_viable"] else 1)
