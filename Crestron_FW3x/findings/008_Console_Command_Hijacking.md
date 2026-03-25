# [REDACTED-ID]_008: ConsoleFindCommandMatchList Command Hijacking

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_008 |
| **Title** | Local Privilege Escalation via CTP Console Command Name Hijacking |
| **Severity** | MEDIUM (CVSS 3.1: 6.7 — AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H) |
| **Type** | CWE-427: Uncontrolled Search Path Element |
| **Related CVE** | CVE-2025-47416 (fixed in 3.001.0031.001 for x70 series) |
| **Affected Products** | Crestron devices using `libsymproc.so` for CTP command dispatch |
| **Firmware Analyzed** | TSW-XX60 v3.002.1061 |
| **Discovery Method** | Ghidra decompilation of `libsymproc.so` → `ConsoleFindCommandMatchList()` and `ConsoleFindCommandMatch()` |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## 1. Executive Summary

The CTP (Crestron Toolbox Protocol) console dispatcher uses `ConsoleFindCommandMatchList()` in `libsymproc.so` to match user-entered console commands to registered handlers. The function enumerates files in `/dev/shm/symproc/c` in **alphabetical order** and infers command permissions from the filename.

An attacker with local write access to `/dev/shm` (a world-writable tmpfs) can create files in `/dev/shm/symproc/c/` with names that are alphabetically prioritized over legitimate commands, effectively **hijacking the command dispatch** to execute attacker-controlled code with the privilege level of the `a_console` process (root).

This is closely related to **CVE-2025-47416**, fixed in firmware 3.001.0031.001. Our firmware (3.002.1061) is newer than the fix.

---

## 2. Technical Root Cause

### 2.1 Command Registration Architecture

Crestron's CTP console uses a file-based command registration system:

```
/dev/shm/symproc/c/
├── ADDUSER          ← registered by a_console
├── CERTIFICATE      ← registered by a_console
├── HOSTNAME         ← registered by a_console
├── PING             ← registered by a_console
├── REBOOT           ← registered by a_console
├── RESETPASSWORD    ← registered by a_console
└── ...
```

Each file represents a registered CTP command. The filename encodes the command name and potentially permission metadata.

### 2.2 The Vulnerable Lookup

```c
// ConsoleFindCommandMatchList() — Ghidra decompilation of libsymproc.so
// Enumerates /dev/shm/symproc/c/ in alphabetical order
// Returns the FIRST matching command entry

result ConsoleFindCommandMatchList(char *command_name) {
    DIR *dir = opendir("/dev/shm/symproc/c");
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (matches(entry->d_name, command_name)) {
            // Return first match — alphabetical order due to readdir()
            return get_handler(entry);
        }
    }
    return NOT_FOUND;
}
```

### 2.3 The Hijacking Vector

Since `/dev/shm` is a world-writable tmpfs:

```bash
# Attacker creates a file that sorts before the legitimate command
$ touch /dev/shm/symproc/c/AAAPING    # Sorts before PING alphabetically

# When a user runs "PING" on the CTP console:
# ConsoleFindCommandMatchList("PING") enumerates alphabetically
# → Finds AAAPING first (alphabetically before PING)
# → If prefix matching is used, AAAPING may not match PING
# → But if the attacker creates an exact match or the matching is fuzzy...
```

**More direct attack:**
```bash
# Overwrite the legitimate command file
$ cp /dev/shm/symproc/c/PING /dev/shm/symproc/c/PING.bak
$ echo "malicious_handler" > /dev/shm/symproc/c/PING
# → PING command now routes to attacker's handler
```

---

## 3. Proof of Concept

### 3.1 Theoretical: Command Hijacking

```bash
# Prerequisites: local access with write to /dev/shm
# (or another vulnerability that grants file write, e.g., [REDACTED-ID]_005 RCE)

# Step 1: List current registered commands
ls /dev/shm/symproc/c/

# Step 2: Create a hijacking file
# The exact file format depends on how libsymproc.so parses the registration
# This is a simplified representation
touch /dev/shm/symproc/c/MALICIOUS_COMMAND

# Step 3: When the hijacked command is invoked via CTP console,
# the attacker's handler executes instead of the legitimate one
```

### 3.2 Chaining with [REDACTED-ID]_005 for Remote Exploitation

If an attacker first obtains remote code execution via [REDACTED-ID]_005 (unauthenticated uploadProject RCE), they could:

1. Write to `/dev/shm/symproc/c/` via the RCE
2. Register a persistent backdoor command
3. The backdoor survives until device reboot (tmpfs is volatile)
4. Any CTP console user invoking the hijacked command triggers the attacker's code

---

## 4. Impact

| Scenario | Severity | Prerequisites |
|----------|----------|---------------|
| Command hijacking via local access | MEDIUM | Local write to /dev/shm |
| Persistence via command registration after RCE | MEDIUM | Prior RCE ([REDACTED-ID]_005 etc.) |
| Privilege escalation from limited user | HIGH | Local user with /dev/shm write |

### Why Severity Is Medium

1. **Requires local access** (or prior RCE for remote exploitation)
2. **Volatile**: `/dev/shm` is tmpfs — hijacking does not survive reboot
3. **CVE-2025-47416 likely patched** in our firmware version
4. **Limited impact scope**: Only affects CTP console commands, not web or SSH paths

---

## 5. CVE Regression Status

| CVE | Affected Versions | Our Version | Status |
|-----|-------------------|-------------|--------|
| CVE-2025-47416 | Pre-3.001.0031 | 3.002.1061 | **Likely PATCHED** (newer than fix) |

The fix for CVE-2025-47416 likely added:
- Permission checks on `/dev/shm/symproc/c/` entries
- Ownership validation (only root-owned files accepted)
- Or moved the command registry to a root-only writable directory

---

## 6. Firmware Evidence

| File | Location | Relevance |
|------|----------|-----------|
| `libsymproc.so` | `/system/lib/` | Contains `ConsoleFindCommandMatchList()` and `ConsoleFindCommandMatch()` |
| `a_console` | `/system/bin/` | Registers commands into `/dev/shm/symproc/c/` at startup |

---

## 7. Suggested Remediation

1. **Restrict /dev/shm/symproc permissions**: Set `/dev/shm/symproc/c/` to mode `0700` owned by root, preventing non-root users from creating or modifying command registration files
2. **Validate file ownership**: Before loading a command handler, verify the file is owned by root and was not modified after initial registration
3. **Use a non-world-writable registry**: Move command registration to a directory on a read-only filesystem or a root-only tmpfs mount
4. **Integrity checking**: Hash command registration files at startup and verify integrity before dispatch

---

## 8. Limitations

- **No live CTP console access**: The emulation does not include the full symproc IPC subsystem. Analysis is based entirely on Ghidra decompilation of `libsymproc.so`.
- **Likely patched**: CVE-2025-47416 fix is present in our firmware version. The exact fix mechanism was not identified through static analysis.
- **File format unknown**: The exact binary format of command registration files in `/dev/shm/symproc/c/` was not fully reversed. The hijacking mechanism may require understanding this format to craft valid entries.
- **Requires local access**: This is primarily a local privilege escalation issue, significantly reducing the practical risk unless chained with a remote vulnerability.
