# [REDACTED-ID]_F001: Pre-Auth Security Question Brute Force (No Rate Limiting)

## Classification

| Field | Value |
|-------|-------|
| **ID** | [REDACTED-ID]_F001 |
| **Severity** | HIGH |
| **Type** | Authentication Bypass / Logic Flaw |
| **Pre-Auth** | YES -- CResetPwdHandler has zero CheckWebSession calls |
| **CVSS 3.1** | 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected** | Dahua IPC firmware V2.622.x (Rhea), likely V2.620.x+ |
| **Binary** | sonia (CResetPwdHandler @ 0x4c9318) |
| **Source Ref** | Src/ResetPwdHandler.cpp |

## Summary

The `PasswdFind.checkQuestionAnswer` RPC method in Dahua's `sonia` binary accepts unlimited authentication attempts against security question answers without any rate limiting, account lockout, or CAPTCHA mechanism. Combined with the pre-auth `getSecretQuestion` and `getStatus` methods, an attacker on the network can brute-force security question answers for any user account.

## Technical Details

### Pre-Auth Confirmation

The CResetPwdHandler class (VMA range 0x4c7400-0x4cad00) was scanned for calls to `CheckWebSession` (located at 0x4c1bd8 in sonia). **Zero calls found.** All 13 registered RPC methods in this handler are accessible without authentication.

### Handler Analysis (0x4c9318)

```
Function: PasswdFind.checkQuestionAnswer handler
VMA:      0x4c9318
Frame:    508 bytes (sub sp, #0x1fc)
Source:   Src/ResetPwdHandler.cpp

Flow:
1. Parse JSON: extract "user" and "question" array with "answer" fields
2. Validate JSON structure (0x4c9340-0x4c9372)
3. Get IPasswdFind interface (vtable call at 0x4c940c)
4. Call checkQuestionAnswer backend (blx r6 at 0x4c9424, vtable[0x58/4])
5. Return {"checkResult":"true"} or {"checkResult":"false"}

Rate limiting: NONE
Lockout: NONE
Timing-safe comparison: NOT in handler (delegated to backend)
```

### Supporting Pre-Auth Methods

| Method | Purpose | Handler |
|--------|---------|---------|
| DevInit.getStatus | Check if security questions configured | 0x4c7740 |
| PasswdFind.getSecretQuestion | Retrieve configured questions | 0x4c8be8 |
| SecretQuestion.getAllQuestion | List all available questions | 0x4c816c |
| PasswdFind.getBasicInfo | Get device SN + vendor | 0x4c738c |

## Novelty Assessment

**NOVEL** -- distinct from [REDACTED-ID]_F014 (PasswdFind.checkAuthCode prediction):
- [REDACTED-ID]_F014: Predicts MD5-based auth code from pre-auth device info (serial number)
- [REDACTED-ID]_F001: Brute-forces security question answers without rate limiting
- Different code paths, different attack mechanism, different RPC methods
- `resetPwdByQuestion` and `checkQuestionAnswer` are Rhea-exclusive (not in Themis V2.620)

## Attack Chain

```
1. DevInit.getStatus
   -> Returns: Init=true, SecretQuestion=true
   -> Confirms security questions are configured

2. PasswdFind.getSecretQuestion (target: "admin")
   -> Returns: configured question text(s)

3. PasswdFind.checkQuestionAnswer (LOOP, unlimited attempts)
   -> Input: {"user":"admin", "question":[{"answer":"candidate"}]}
   -> Output: {"checkResult":"false"} or {"checkResult":"true"}
   -> No lockout, no delay, no CAPTCHA

4. PasswdFind.resetPwdByQuestion ([REDACTED-ID]_F002)
   -> Input: {"user":"admin", "question":[{"answer":"correct"}], "pwd":"attacker_pw"}
   -> Result: Admin password changed
```

## Impact

- Complete account takeover of any user including admin
- Chains with [REDACTED-ID]_F002 for full password reset
- Enables subsequent exploitation of all post-auth vulnerabilities
- Affects all Rhea-series devices with security questions enabled

## Remediation

1. Implement account lockout after N failed attempts (e.g., 5 attempts, 15-minute lockout)
2. Add exponential backoff on failed verification
3. Consider CAPTCHA or secondary verification for password reset flows
4. Log and alert on repeated failed attempts

## Reproduction Steps

See: `scripts/poc_og4_f001_f002_question_brute.py`
