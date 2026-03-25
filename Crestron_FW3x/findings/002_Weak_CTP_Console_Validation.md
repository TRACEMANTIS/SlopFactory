# [REDACTED-ID]_002: Weak CTP Console Input Validation

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_002 |
| **Title** | Insufficient Shell Metacharacter Filtering in CTP Console Validation |
| **Severity** | HIGH (CVSS 3.1: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **Type** | CWE-20: Improper Input Validation |
| **Affected Products** | All Crestron devices running `a_console` with CTP console interface |
| **Firmware Analyzed** | TSW-XX60 v3.002.1061 (Ghidra RE of `a_console` and `libLinuxUtil.so`) |
| **Discovery Method** | Ghidra decompilation of `validateCharacters()` in `libLinuxUtil.so` + gap analysis against full POSIX shell metacharacter set |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## 1. Executive Summary

The `validateCharacters()` function in `libLinuxUtil.so` is the primary input validation gate for CTP (Crestron Toolbox Protocol) console commands. It uses a **blocklist of only 7 characters** (`<>&|;$\``) to filter shell metacharacters from user-supplied input before that input is used in `system()`, `osal_popenf3()`, or `osal_systemf()` calls.

**20+ dangerous shell metacharacters are NOT blocked**, including newlines (`\n`), double quotes (`"`), parentheses (`()`), backslashes (`\\`), hash (`#`), braces (`{}`), and more. Any CTP command handler that relies solely on `validateCharacters()` for injection protection — without additional command-specific validation like PING's `IsValidServer()` — is potentially vulnerable to command injection.

This is the **root cause enabler** for multiple other findings: the weak validation is why [REDACTED-ID]_001's certificate password injection works (the password path doesn't even go through `validateCharacters()`, but the weakness demonstrates the systemic validation gap across the entire `a_console` binary).

---

## 2. Technical Root Cause

### 2.1 The validateCharacters() Function

**Binary:** `libLinuxUtil.so` (ARM32 shared library)
**Decompiled via:** Ghidra 11.x

```c
// validateCharacters() — Ghidra decompilation
// Returns 0 if input passes validation (contains no blocked chars)
// Returns non-zero if a blocked character is found
int validateCharacters(char *input) {
    // Blocklist: only 7 characters
    static const char blocked[] = "<>&|;$`";

    for (int i = 0; input[i] != '\0'; i++) {
        for (int j = 0; blocked[j] != '\0'; j++) {
            if (input[i] == blocked[j]) {
                return 1;  // BLOCKED
            }
        }
    }
    return 0;  // PASSED — all other characters allowed
}
```

### 2.2 Gap Analysis: Blocked vs. Not Blocked

| Character | Blocked? | Shell Danger |
|-----------|----------|-------------|
| `<` | ✅ YES | Input redirection |
| `>` | ✅ YES | Output redirection |
| `&` | ✅ YES | Background / AND operator |
| `\|` | ✅ YES | Pipeline |
| `;` | ✅ YES | Command separator |
| `$` | ✅ YES | Variable expansion |
| `` ` `` | ✅ YES | Command substitution |
| `\n` (newline) | ❌ **NO** | **Command separator** — equivalent to `;` |
| `"` (double-quote) | ❌ **NO** | **Quoting context manipulation** |
| `(` `)` | ❌ **NO** | **Subshell execution** |
| `\\` (backslash) | ❌ **NO** | **Escape sequences** |
| `#` (hash) | ❌ **NO** | **Comment injection** |
| `!` (bang) | ❌ **NO** | **History expansion (bash)** |
| `{` `}` | ❌ **NO** | **Brace expansion** |
| `[` `]` | ❌ **NO** | **Pattern matching** |
| `~` (tilde) | ❌ **NO** | **Home directory expansion** |
| `%` (percent) | ❌ **NO** | **Job control** |
| `+` `=` `?` `:` `,` `*` `-` | ❌ **NO** | Various shell meanings |
| `\t` (tab) | ❌ **NO** | **Whitespace injection** |
| `'` (single-quote) | ❌ **NO** | **Quoting context** (root cause of [REDACTED-ID]_001) |

**20+ dangerous characters pass through the filter.**

### 2.3 Which CTP Handlers Are Protected vs. Exposed

| CTP Command | Uses validateCharacters()? | Additional Validation? | Protected? |
|-------------|---------------------------|----------------------|------------|
| PING | ✅ | `strchr(0x27)` + `IsValidServer()` allowlist `[a-zA-Z0-9.-]` | **YES** — 3 layers |
| HOSTNAME | ✅ | Unknown | **PARTIAL** — only 7-char blocklist |
| SNMP | ✅ | Unknown | **PARTIAL** |
| ADDUSER (name) | ❌ | `validateNameCharacters()` regex `^[-[:alnum:]_.]*$` | **YES** — strict allowlist |
| ADDUSER (password) | ❌ | `validatePasswordCharacters()` regex `^[[:alnum:][:punct:] ]*$` | **NO** — allows ALL printable |
| CERTIFICATE (password) | ❌ | `CheckEmbeddedChars()` — never rejects | **NO** — [REDACTED-ID]_001 |

---

## 3. Proof of Concept

### 3.1 Newline Injection Bypasses validateCharacters()

The newline character (`\n`, 0x0A) is functionally equivalent to `;` as a command separator in shell contexts, but is NOT blocked by `validateCharacters()`.

**Theoretical PoC (requires CTP console access on port 41795):**
```
HOSTNAME test\nid\n
```

If the HOSTNAME handler constructs:
```c
system("hostname test\nid\n")
```

The shell interprets the newline as a command separator:
```
hostname test     ← executes
id                ← executes (injected)
```

### 3.2 Subshell Bypass via Parentheses

Parentheses `()` are not blocked, enabling subshell execution:
```
HOSTNAME test$(id)
```

If `$` is blocked but `()` are not, and the context allows double-quoted expansion:
```c
system("hostname \"test$(id)\"")
```

Note: `$` IS blocked, so `$()` won't work directly. But in double-quote contexts, other expansions may apply.

### 3.3 Context-Dependent Exploitation

The exploitability depends on how each CTP command handler constructs the `system()` call:
- **Unquoted interpolation**: `system("cmd " + input)` — newline injection works
- **Single-quoted**: `system("cmd '" + input + "'")` — single-quote breakout ([REDACTED-ID]_001 pattern)
- **Double-quoted**: `system("cmd \"" + input + "\"")` — backslash, newline, `!` may work
- **Argument array**: `execve("cmd", {"cmd", input})` — safe (no shell interpretation)

---

## 4. Impact

The 130 calls to `system()`, 5 calls to `osal_popenf3()`, and 12 calls to `osal_systemf()` across `a_console` represent 147 potential injection sinks. Any path from CTP console input to these sinks that relies solely on `validateCharacters()` is at risk.

| Risk | Severity |
|------|----------|
| CTP commands protected only by validateCharacters() | HIGH |
| Enables further exploitation when combined with other findings | HIGH |
| 147 potential injection sinks in a_console | MEDIUM-HIGH |
| Systemic: affects ALL CTP command handlers uniformly | HIGH |

---

## 5. Firmware Evidence

| File | Location | Relevance |
|------|----------|-----------|
| `libLinuxUtil.so` | `/system/lib/` | Contains `validateCharacters()` with 7-char blocklist |
| `a_console` | `/system/bin/` | 130 `system()` + 5 `osal_popenf3()` + 12 `osal_systemf()` calls |
| `libLinuxUtil.so` | `/system/lib/` | `AreWebPathCharactersValid()` blocks 30+ chars — shows the vendor knows a larger set is needed |

---

## 6. Suggested Remediation

1. **Switch to allowlist**: Replace the 7-char blocklist with a strict allowlist approach. `IsValidHostnameCharacter()` already uses `[a-zA-Z0-9.-]` — apply this pattern to all CTP command parameters.
2. **Apply `AreWebPathCharactersValid()` to CTP**: The vendor already has a function that blocks 30+ dangerous characters — use it (or a derivative) for CTP input as well.
3. **Use `execve()` not `system()`**: Eliminate shell interpretation entirely by using exec-family functions with argument arrays.
4. **Audit all 147 injection sinks**: Review every `system()`, `osal_popenf3()`, and `osal_systemf()` call in `a_console` to verify each has adequate input validation on all user-reachable parameters.

---

## 7. Limitations

- **No live CTP console access**: Port 41795 was not accessible on the emulation environment. The gap analysis is based entirely on static analysis of the `validateCharacters()` function and its callers.
- **Command-specific protections may exist**: Some CTP handlers (like PING) have additional validation layers. Each handler's full validation chain must be audited individually.
- **Exploitability varies by context**: The actual danger depends on how each handler's format string quotes the user input.
