# [REDACTED-ID]_F003: SDP Serializer snprintf Accumulator Stack Buffer Overflow

## Classification

| Field | Value |
|-------|-------|
| **ID** | [REDACTED-ID]_F003 |
| **Severity** | CRITICAL (code-level), MEDIUM (exploitability -- post-auth default) |
| **Type** | Stack Buffer Overflow / Remote Code Execution |
| **Pre-Auth** | NO (default Digest config); YES (if RtspAuthType=0) |
| **CVSS 3.1** | 9.8 if pre-auth (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **CVSS 3.1** | 8.8 if post-auth (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **Affected** | Dahua IPC firmware V2.622.x (Rhea), likely V2.620.x+ |
| **Binary** | sonia (SDP serializer functions in 0x33e000-0x340b00) |
| **Source Ref** | Src/Protocol/SdpParser.cpp |

## Summary

Multiple SDP serializer functions in sonia contain a critical vulnerability where the snprintf return value is accumulated without bounds checking. When the total serialized SDP content exceeds 2050 bytes, the size parameter passed to snprintf wraps to a huge unsigned value (~4GB), causing unbounded stack writes. With NX disabled and no stack canary, this yields direct code execution.

## Root Cause

Per C99, `snprintf(buf, size, fmt, ...)` returns the number of characters that **would have been written** if the buffer were large enough -- NOT the actual count written. The SDP serializer uses the return value as an offset accumulator:

```c
// Pseudocode reconstruction from VMA 0x33e1b8
char buf[2052];   // sp+0x2c
int offset = initial_marker_len;  // ~4
int max_size = 2050;

for (node = list->head; node != list->end; node = node->next) {
    // BUG: snprintf returns intended-write count, not actual
    offset += snprintf(buf + offset, max_size - offset, fmt, node->data);
    // When offset > 2050:
    //   max_size - offset = negative (wraps to ~4GB unsigned)
    //   Next snprintf writes UNBOUNDED past buffer
}
if (offset > 2) {
    strcpy(buf + offset - 1, "\r\n");  // Also OOB
}
```

## Affected Functions (8 instances)

| VMA | SDP Line | Frame Size | Buffer | Loop? |
|-----|----------|-----------|--------|-------|
| **0x33e1b8** | z= (timezone) | 2100 | sp+0x2c, 2048B | YES |
| **0x340a40** | m= (media) | 2332 | sp+0x114, 2052B | YES |
| **0x33e5b0** | e= (email) | ~2060 | -- | YES |
| **0x33e690** | c/b (conn/bw) | ~2060 | -- | YES |
| **0x33e710** | t= (time) | ~2064 | -- | YES |
| **0x33e7d0** | t= (time sub) | ~2064 | -- | YES |
| **0x33e830** | a= (attribute) | ~2068 | -- | YES |
| **0x33e25c** | z= (timezone) | 2084 | -- | YES |

## Exploitation Analysis

### Stack Layout (0x33e1b8 primary instance)

```
sp+0x000 to sp+0x02b: local variables
sp+0x02c to sp+0x82b: SDP buffer (2048 bytes, memset to 0)
sp+0x82c to sp+0x833: remaining frame (8 bytes)
sp+0x834: saved r4
sp+0x838: saved r5
sp+0x83c: saved r6
sp+0x840: saved r7
sp+0x844: saved r8
sp+0x848: saved r9
sp+0x84c: saved sl
sp+0x850: saved fp
sp+0x854: saved lr -> loaded into PC on return (ldmia sp!, {..., pc})
```

**Overflow to PC: 2088 bytes from buffer start (sp+0x2c)**

### Protection Status

| Protection | Status | Impact |
|-----------|--------|--------|
| Stack canary | **NONE** | No detection of overflow |
| NX (DEP) | **DISABLED** | Shellcode executable on stack |
| PIE/ASLR | **No PIE** | Fixed addresses, no bypass needed |
| RELRO | **NONE** | GOT overwrite also possible |

### Attack Vector

1. Establish authenticated RTSP session (or exploit auth_type=0 misconfiguration)
2. Send RTSP ANNOUNCE with SDP body containing many `a=` attribute lines
3. Total serialized attribute content must exceed 2050 bytes
4. SDP gets parsed into internal linked list
5. When list is re-serialized (e.g., for recording/proxying), accumulator wraps
6. snprintf writes shellcode past buffer end into saved registers
7. Function return loads attacker-controlled PC from stack
8. ARM32 Thumb shellcode executes (reverse shell)

### Pre-Auth Reachability

Under **default Digest configuration**: POST-AUTH only. RTSP session must be authenticated before DESCRIBE/SETUP/ANNOUNCE handlers execute.

Under **misconfigured None auth (auth_type=0)**: PRE-AUTH. All RTSP methods including ANNOUNCE process without authentication.

## Novelty Assessment

**NOVEL** -- No SDP serializer overflow was identified in OG3. OG3 focused on DVRIP, UPnP, SNMP, and HTTP Digest. The SDP dispatch table and serializer vulnerability pattern is new.

## Impact

- Remote code execution as root (sonia runs as root)
- Full device compromise
- 8 vulnerable instances across different SDP line types
- Any one is sufficient for exploitation

## Remediation

1. Cap the accumulator: `offset = MIN(offset + ret, max_size - 1)`
2. Or: check `if (offset >= max_size) break;` before next iteration
3. Replace snprintf loop pattern with proper bound-checked serialization
4. Enable NX (stack non-executable) on sonia binary
5. Enable stack canaries in all functions
