# [REDACTED-ID]_002: Hardcoded Firmware Up[REDACTED] FTP Credentials

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_002 |
| **Title** | Hardcoded FTP Credentials in Firmware Up[REDACTED] Script |
| **Severity** | CRITICAL (if internal network accessible) / HIGH (general) |
| **Type** | CWE-798: Use of Hard-coded Credentials |
| **Affected Products** | DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, TS-1542-C, MERCURY, and all Crestron devices sharing the FW 2.x codebase |
| **Firmware Analyzed** | DMPS3 AirMedia PufVersion 1.5010.00023 (Build: February 23, 2024) |
| **Discovery Method** | Static analysis of `/system/bin/crestronUp[REDACTED].sh` shell script |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## Summary

The firmware up[REDACTED] shell script `/system/bin/crestronUp[REDACTED].sh` contains hardcoded FTP credentials (`buildUser` / `password`) used to download firmware images from an internal build server at IP address `[REDACTED-INTERNAL-IP]`. These credentials are also referenced in the `a_console` binary, which invokes the up[REDACTED] script with the credentials as command-line arguments.

The credentials are plaintext in a world-readable shell script shipped in every firmware image. An attacker who gains access to the internal build network ([REDACTED-INTERNAL-IP]/x) -- or who can perform ARP spoofing, DNS poisoning, or MITM on the up[REDACTED] path -- can intercept the FTP connection and serve malicious firmware to the device. Since FTP transmits credentials and data in cleartext, the entire up[REDACTED] channel is unprotected.

---

## Affected Component

| Component | Details |
|-----------|---------|
| **Script** | `/system/bin/crestronUp[REDACTED].sh` |
| **Username** | `buildUser` |
| **Password** | `password` |
| **Server IP** | `[REDACTED-INTERNAL-IP]` |
| **Protocol** | FTP (plaintext, no TLS) |
| **FTP Client** | `busybox ftpget` |
| **Caller** | `a_console` binary (CTP UP[REDACTED] command handler) |
| **Invocation** | `crestronUp[REDACTED].sh [REDACTED-INTERNAL-IP] buildUser password uboot-env` |

---

## Technical Details

### 2.1 Hardcoded Credentials in crestronUp[REDACTED].sh

The shell script defines default credentials as shell variables:

```bash
#!/bin/busybox sh
# /system/bin/crestronUp[REDACTED].sh

# Default credentials for FTP firmware download
DEFAULT_USER="buildUser"
DEFAULT_PASSWORD="password"

# Parse arguments or use defaults
IP=${1:-[REDACTED-INTERNAL-IP]}
USER=${2:-$DEFAULT_USER}
PASSWORD=${3:-$DEFAULT_PASSWORD}
COMPONENT=${4:-uboot-env}

# Download firmware via FTP (cleartext)
busybox ftpget -u$USER -p$PASSWORD $IP /tmp/firmware_$COMPONENT.bin firmware/$COMPONENT.bin
```

### 2.2 Invocation from a_console

The `a_console` binary (667 KB, ARM32) contains a reference to the full up[REDACTED] command with all credentials visible as a string literal:

```
/system/bin/crestronUp[REDACTED].sh [REDACTED-INTERNAL-IP] buildUser password uboot-env
```

This string is used by the CTP UP[REDACTED] command handler. When a CTP `UP[REDACTED]` command is received (via the CTP console on port 41795, or via the CWS `upgradeFirmware()` function), `a_console` invokes the up[REDACTED] script with the hardcoded IP and credentials.

### 2.3 FTP Transfer (No Encryption)

The `busybox ftpget` command performs a standard FTP transfer:
- Credentials sent in plaintext (`USER buildUser\r\n`, `PASS password\r\n`)
- Firmware binary downloaded in plaintext
- No TLS/SSL wrapper
- No integrity verification (no hash check, no signature verification) of the downloaded firmware

### 2.4 Build Server Assumptions

The IP `[REDACTED-INTERNAL-IP]` is an RFC 1918 private address, suggesting this is Crestron's internal build/staging server. The credentials appear to be development/build-system defaults that were never removed from production firmware. The username `buildUser` strongly suggests a CI/CD pipeline or build automation account.

---

## Impact

| Scenario | Impact | Severity |
|----------|--------|----------|
| MITM on up[REDACTED] path | Attacker serves malicious firmware to device | CRITICAL |
| Network-adjacent attacker spoofs [REDACTED-INTERNAL-IP] | Device downloads attacker-controlled firmware | CRITICAL |
| Internal network compromise | Attacker authenticates to build FTP server | HIGH |
| Credential reuse | If `buildUser`/`password` is reused on other internal systems | HIGH |
| Information disclosure | Attacker learns internal build infrastructure details | MEDIUM |

### Attack Scenario 1: Malicious Firmware via MITM

1. Attacker gains network adjacency to a Crestron device (e.g., same VLAN, compromised switch, VPN access)
2. Attacker configures a rogue FTP server responding to connections on port 21
3. Attacker uses ARP spoofing or IP aliasing to respond as `[REDACTED-INTERNAL-IP]`
4. When the device initiates a firmware up[REDACTED] (manually triggered or via CTP/CWS command), it connects to the attacker's FTP server
5. The attacker serves a malicious firmware image
6. The device installs the malicious firmware -- no signature or integrity check prevents this

### Attack Scenario 2: Build Server Access

1. Attacker extracts credentials from publicly downloadable firmware
2. If the build server `[REDACTED-INTERNAL-IP]` is reachable (e.g., via VPN, misconfigured routing, or from a compromised device on the internal network), the attacker authenticates to the FTP server
3. The attacker may download proprietary firmware builds, upload trojaned firmware, or pivot further into the build infrastructure

---

## Evidence

### String Evidence from crestronUp[REDACTED].sh

```
DEFAULT_PASSWORD="password"
DEFAULT_USER="buildUser"
busybox ftpget -u$USER -p$PASSWORD $IP
```

### String Evidence from a_console

```
/system/bin/crestronUp[REDACTED].sh [REDACTED-INTERNAL-IP] buildUser password uboot-env
```

### Fleet Fingerprint Context

[N] of [N] probed Crestron hosts ([REDACTED]%) are running FW 2.x firmware and carry this script. All devices with this firmware version contain identical credentials.

---

## Reproduction Steps (for vendor)

1. Obtain the DMPS3 AirMedia firmware PUF file (version 1.5010.00023)
2. Extract the `system.img` filesystem:
   ```bash
   binwalk -e dmps3_airmedia_1.5010.00023.puf
   mount -o loop,ro system.img /mnt/fw
   ```
3. Read the up[REDACTED] script:
   ```bash
   cat /mnt/fw/system/bin/crestronUp[REDACTED].sh
   ```
4. Observe the hardcoded credentials:
   - `DEFAULT_USER="buildUser"`
   - `DEFAULT_PASSWORD="password"`
5. Confirm the a_console reference:
   ```bash
   strings /mnt/fw/system/bin/a_console | grep crestronUp[REDACTED]
   # Output: /system/bin/crestronUp[REDACTED].sh [REDACTED-INTERNAL-IP] buildUser password uboot-env
   ```
6. To validate the MITM scenario:
   - Set up an FTP server on a machine aliased as [REDACTED-INTERNAL-IP]
   - Trigger a firmware up[REDACTED] on the device
   - Observe the device connecting with `buildUser`/`password` and downloading the served file

---

## Suggested Fix

1. **Remove hardcoded credentials** from the up[REDACTED] script and the `a_console` binary. Credentials for firmware downloads should never be embedded in production firmware.
2. **Replace FTP with HTTPS** for firmware downloads. Use TLS with certificate pinning to prevent MITM attacks on the up[REDACTED] channel.
3. **Implement firmware signature verification.** Before installing any downloaded firmware image, verify a cryptographic signature (e.g., RSA-2048 or Ed25519) against a trusted public key embedded in the bootloader. This is the single most important mitigation -- even if the transport is compromised, unsigned firmware should be rejected.
4. **Rotate the build server credentials immediately.** The credentials `buildUser`/`password` should be considered fully compromised since they are present in every firmware image ever shipped with this version.
5. **Audit for credential reuse.** Verify that `buildUser`/`password` is not used on any other internal systems, build pipelines, or cloud services.
6. **Network segmentation.** Ensure the build server at `[REDACTED-INTERNAL-IP]` is not reachable from production device networks or the internet.

---

## Status

| Item | Status |
|------|--------|
| **Discovery** | Confirmed via static analysis (shell script + binary strings) |
| **Credential extraction** | Confirmed -- plaintext in downloadable firmware |
| **MITM validation** | Pending -- requires network-adjacent test environment |
| **Build server reachability** | Not tested ([REDACTED-INTERNAL-IP] is private address space) |
| **Exploitability** | HIGH (credentials publicly extractable; FTP is inherently insecure) |

---

## CWE Reference

- **CWE-798:** Use of Hard-coded Credentials
- **CWE-319:** Cleartext Transmission of Sensitive Information (FTP credentials and firmware in plaintext)
- **CWE-494:** Download of Code Without Integrity Check (no firmware signature verification)
- **Related:** CWE-259 (Use of Hard-coded Password), CWE-522 (Insufficiently Protected Credentials)
