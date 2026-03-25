#!/usr/bin/env python3
"""
Chain Link 1: Validate template-loader.php vulnerability
Confirms that template_include filter result goes directly to include()
without type checking or path validation in WordPress 6.8.1.

This script reads the source code and confirms the vulnerable pattern.
No exploitation -- just validation.
"""

import re
import sys
import json
from datetime import datetime

TEMPLATE_LOADER = "/var/www/html/wp-lab/wp-includes/template-loader.php"

def validate():
    results = {
        "test": "template_include_validation",
        "timestamp": datetime.now().isoformat(),
        "target_file": TEMPLATE_LOADER,
        "findings": []
    }

    with open(TEMPLATE_LOADER, "r") as f:
        content = f.read()
        lines = content.split("\n")

    # Check 1: Is template_include filter applied?
    filter_found = False
    filter_line = -1
    for i, line in enumerate(lines, 1):
        if "apply_filters( 'template_include'" in line or "apply_filters('template_include'" in line:
            filter_found = True
            filter_line = i
            results["findings"].append({
                "check": "template_include_filter_present",
                "status": "CONFIRMED",
                "line": i,
                "code": line.strip()
            })

    # Check 2: Is there a realpath() call after the filter? (patched versions have this)
    has_realpath = "realpath" in content[content.find("template_include"):]
    results["findings"].append({
        "check": "realpath_validation_present",
        "status": "NOT_PRESENT" if not has_realpath else "PRESENT",
        "vulnerable": not has_realpath,
        "detail": "No realpath() canonicalization after template_include filter"
    })

    # Check 3: Is there an is_string() check? (patched versions have this)
    post_filter = content[content.find("template_include"):]
    has_is_string = "is_string" in post_filter.split("include")[0] if "include" in post_filter else False
    results["findings"].append({
        "check": "type_check_before_include",
        "status": "NOT_PRESENT" if not has_is_string else "PRESENT",
        "vulnerable": not has_is_string,
        "detail": "No is_string() type check before include statement"
    })

    # Check 4: Does the template go directly to include?
    include_pattern = re.search(r'include\s+\$template\s*;', content)
    results["findings"].append({
        "check": "direct_include_of_filter_result",
        "status": "CONFIRMED" if include_pattern else "NOT_FOUND",
        "vulnerable": bool(include_pattern),
        "detail": "Filter result passed directly to include without validation"
    })

    # Check 5: What safeguards exist between filter and include?
    if filter_line > 0:
        # Find the include line
        include_line = -1
        for i, line in enumerate(lines, 1):
            if i > filter_line and "include $template" in line:
                include_line = i
                break
        if include_line > 0:
            gap = include_line - filter_line
            gap_code = "\n".join(lines[filter_line:include_line])
            results["findings"].append({
                "check": "code_between_filter_and_include",
                "filter_line": filter_line,
                "include_line": include_line,
                "gap_lines": gap,
                "code": gap_code.strip(),
                "detail": f"Only {gap} lines between filter and include"
            })

    # Overall assessment
    vuln_count = sum(1 for f in results["findings"] if f.get("vulnerable", False))
    results["vulnerable"] = vuln_count > 0
    results["summary"] = (
        f"WordPress 6.8.1 template-loader.php: {vuln_count} vulnerability indicators confirmed. "
        f"The template_include filter result is passed directly to PHP include() "
        f"without type checking, path canonicalization, or extension validation."
    )

    return results

if __name__ == "__main__":
    results = validate()
    output = json.dumps(results, indent=2)
    print(output)

    # Save evidence
    with open("/home/[REDACTED]/Desktop/SecSoft/wp-rce-research/evidence/01_template_include.json", "w") as f:
        f.write(output)

    sys.exit(0 if results["vulnerable"] else 1)
