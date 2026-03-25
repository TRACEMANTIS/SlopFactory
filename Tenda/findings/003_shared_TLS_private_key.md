# [REDACTED-ID]_003: Hardcoded Shared TLS Private Key Across All Devices

## Summary

Both Tenda AC15 and AC20 firmware ship with an identical RSA private key at `/webroot_ro/pem/privkeySrv.pem`. This key is embedded in the firmware image, publicly available in GitHub repositories, and shared across ALL devices of both models. Any attacker with this key can perform MITM attacks against the HTTPS management interface of any Tenda AC15 or AC20 device.

## Affected Products

| Product | Firmware Version | Key Location |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 | /webroot_ro/pem/privkeySrv.pem |
| Tenda AC20 | V16.03.08.12 | /webroot_ro/pem/privkeySrv.pem |
| Potentially ALL Tenda AC-series | Multiple | Same key |

## Vulnerability Details

The self-signed certificate and private key are:
- Issued: 2010-09-30
- Expiry: 2030 (20-year validity)
- Key type: RSA
- **Identical across both ARM (AC15) and MIPS (AC20) architectures**
- Stored in plaintext in the firmware filesystem
- Publicly available via GitHub firmware repositories

## Impact

- **MITM:** Any attacker who extracts the key from public firmware images can decrypt HTTPS traffic to/from the router's management interface
- **Credential theft:** Admin credentials transmitted over "HTTPS" can be captured
- **Combined with [REDACTED-ID]_002:** If admin password is captured via MITM, attacker can access all authenticated endpoints

## CVSS v3.1

**Score: 7.4 (High)** — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

## CWE Classification

- **CWE-321:** Use of Hard-coded Cryptographic Key
- **CWE-295:** Improper Certificate Validation

## Status

- **Discovery:** Filesystem analysis of extracted firmware
- **Validation:** Key confirmed identical across both models via hash comparison
