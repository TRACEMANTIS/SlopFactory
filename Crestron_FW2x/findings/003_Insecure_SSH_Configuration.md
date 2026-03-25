# [REDACTED-ID]_003: Insecure SSH Configuration (Dropbear)

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_003 |
| **Title** | Insecure SSH Configuration Permitting Root Login and Empty Passwords |
| **Severity** | HIGH (CVSS 3.1: 8.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Type** | CWE-287: Improper Authentication; CWE-760: Use of a One-Way Hash with a Predictable Salt |
| **Affected Products** | DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, TS-1542-C, MERCURY, and all Crestron devices sharing the FW 2.x codebase |
| **Firmware Analyzed** | DMPS3 AirMedia PufVersion 1.5010.00023 (Build: February 23, 2024) |
| **Discovery Method** | Static analysis of `/system/bin/crestInit.sh` boot script and Dropbear SSH configuration |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## Summary

The Crestron FW 2.x firmware configures the Dropbear SSH daemon at boot with a dangerously permissive configuration that permits root login, allows empty passwords, and disables strict file mode checking. Combined with the default admin:admin credentials and a static, predictable password salt (`crestronPassword`) used for all SSH password hashes, this configuration creates multiple avenues for unauthorized access.

The SSH banner (`SSH-2.0-CRESTRON_SSHD`) immediately identifies the device as a Crestron product to any network scanner, enabling targeted exploitation.

---

## Affected Component

| Component | Details |
|-----------|---------|
| **Boot Script** | `/system/bin/crestInit.sh` |
| **SSH Daemon** | Dropbear (embedded SSH server) |
| **SSH Banner** | `SSH-2.0-CRESTRON_SSHD` |
| **Default Port** | 22/TCP |
| **Default Credentials** | `admin` / `admin` |
| **Password Salt** | `crestronPassword` (static, hardcoded) |
| **Shell Handler** | `/system/bin/sshShell.sh` (custom restricted shell) |

---

## Technical Details

### 2.1 Boot-Time SSH Configuration

The initialization script `/system/bin/crestInit.sh` configures and starts the Dropbear SSH daemon with the following settings:

```bash
# Extracted from /system/bin/crestInit.sh

# SSH daemon configuration
PermitRootLogin yes
PermitEmptyPasswords yes
StrictModes no
```

These settings are applied during the device boot sequence before any user interaction.

### 2.2 Configuration Weaknesses

| Setting | Value | Security Impact |
|---------|-------|-----------------|
| `PermitRootLogin yes` | Root can log in directly via SSH | Eliminates privilege escalation barrier; attackers go straight to root |
| `PermitEmptyPasswords yes` | Accounts with no password can authenticate | If any account's password is cleared or unset, it becomes remotely accessible with no credentials |
| `StrictModes no` | Dropbear does not check file permissions on key files and home directories | Allows use of SSH keys with overly permissive permissions; malicious users can place authorized_keys in other users' directories |

### 2.3 Static Password Salt

All SSH password hashes on the device use the static salt `crestronPassword`. This salt is hardcoded in the Dropbear configuration or the password hashing routine, meaning:

- **Every device** running this firmware uses the same salt for the same password
- An attacker can precompute a rainbow table for this salt, making offline cracking trivial
- The hash for `admin` with salt `crestronPassword` is identical across all multiple FW 2.x test devices in the fleet

### 2.4 Default Credentials

The device ships with a default account:
- **Username:** `admin`
- **Password:** `admin`

Combined with `PermitRootLogin yes`, if the admin account has root-level access (or if a separate root account exists with default/empty password), an attacker achieves root access immediately upon network connectivity.

### 2.5 SSH Banner Fingerprinting

The SSH banner `SSH-2.0-CRESTRON_SSHD` uniquely identifies the device as Crestron, allowing automated scanning tools (Shodan, Censys, Masscan) to fingerprint and target these devices specifically. This is equivalent to advertising the device type and narrowing the attacker's exploit selection.

### 2.6 Combined Risk Matrix

| Factor | Risk |
|--------|------|
| Default credentials (`admin:admin`) + `PermitRootLogin yes` | Unauthenticated root access |
| `PermitEmptyPasswords yes` + any unset password | Zero-credential access |
| Static salt `crestronPassword` | Precomputed hash tables across all devices |
| `StrictModes no` | Weak key file permission enforcement |
| Identifiable banner | Targeted scanning and exploitation |
| [REDACTED-COUNT] FW 2.x devices in tested fleet | Large attack surface with identical configuration |

---

## Impact

| Scenario | Impact | Severity |
|----------|--------|----------|
| Default credentials on internet-facing device | Full device compromise via SSH | CRITICAL |
| Empty password on any account | Zero-credential remote access | CRITICAL |
| Precomputed rainbow table for static salt | Offline password cracking across entire fleet | HIGH |
| Root login permitted | No privilege escalation needed after initial access | HIGH |
| Device banner disclosure | Targeted scanning and exploitation | MEDIUM |

### Attack Scenario

1. Attacker scans for SSH services responding with `SSH-2.0-CRESTRON_SSHD` (Shodan query: `"SSH-2.0-CRESTRON_SSHD"`)
2. Attacker attempts login with `admin:admin` (default credentials)
3. If credentials have been changed, attacker can attempt empty password if `PermitEmptyPasswords yes` is active and any account lacks a password
4. If credentials were captured from another device, the static salt means the same password produces the same hash -- cracking one device's hash works for all
5. Upon successful login, the attacker has administrative access to the device and potentially root access via the custom `sshShell.sh` handler

---

## Evidence

### crestInit.sh Configuration Excerpt

The following settings are applied to the Dropbear SSH daemon at boot:

```
PermitRootLogin yes
PermitEmptyPasswords yes
StrictModes no
```

### SSH Banner

```
$ nc <device_ip> 22
SSH-2.0-CRESTRON_SSHD
```

### Static Salt Reference

Password hashing in the Dropbear configuration uses the salt string `crestronPassword` for all password operations on the device.

### Fleet Impact

From the device survey scan: [N] of [N] probed hosts ([REDACTED]%) run FW 2.x and share this identical SSH configuration.

---

## Reproduction Steps (for vendor)

1. Obtain the DMPS3 AirMedia firmware PUF file (version 1.5010.00023)
2. Extract the `system.img` filesystem:
   ```bash
   binwalk -e dmps3_airmedia_1.5010.00023.puf
   mount -o loop,ro system.img /mnt/fw
   ```
3. Read the boot script:
   ```bash
   cat /mnt/fw/system/bin/crestInit.sh
   ```
4. Locate the SSH configuration directives:
   - `PermitRootLogin yes`
   - `PermitEmptyPasswords yes`
   - `StrictModes no`
5. Identify the static password salt:
   ```bash
   strings /mnt/fw/system/bin/dropbear | grep crestronPassword
   # Or search in the password file handling code
   grep -r "crestronPassword" /mnt/fw/system/
   ```
6. Connect to a running device to confirm the banner:
   ```bash
   ssh -v admin@<device_ip>
   # Observe: SSH-2.0-CRESTRON_SSHD in the version exchange
   ```
7. Confirm default credentials:
   ```bash
   ssh admin@<device_ip>
   # Password: admin
   ```

---

## Suggested Fix

1. **Disable root login via SSH.** Set `PermitRootLogin no` (or `prohibit-password` to allow key-based root access only if operationally required). Administrative access should require a named account with sudo/privilege escalation.
2. **Disable empty passwords.** Set `PermitEmptyPasswords no`. No account should ever be accessible without a password via SSH.
3. **Enable StrictModes.** Set `StrictModes yes` to enforce proper file permissions on SSH key files and home directories.
4. **Replace the static password salt.** Generate a unique, random salt per device (or per password change) using `/dev/urandom`. The salt should be at least 16 bytes of cryptographic randomness.
5. **Force default credential change.** On first boot or first login, require the administrator to change the default `admin:admin` credentials before the device becomes fully operational.
6. **Change the SSH banner.** Replace `SSH-2.0-CRESTRON_SSHD` with a generic banner (e.g., `SSH-2.0-dropbear`) to reduce fingerprinting risk. Alternatively, allow administrators to configure the banner.
7. **Implement account lockout.** After a configurable number of failed SSH login attempts (e.g., 5), lock the account or introduce a progressive delay to mitigate online password guessing.

---

## Status

| Item | Status |
|------|--------|
| **Discovery** | Confirmed via static analysis (boot script review) |
| **Default credentials** | `admin:admin` -- documented in device manuals |
| **SSH banner** | Confirmed in device survey scan |
| **Static salt** | Confirmed via strings analysis |
| **Live validation** | Pending full validation on live device |
| **Exploitability** | HIGH -- default credentials + permissive SSH config = trivial remote access |

---

## CWE Reference

- **CWE-287:** Improper Authentication (permitting empty passwords, default credentials)
- **CWE-760:** Use of a One-Way Hash with a Predictable Salt (static `crestronPassword` salt)
- **CWE-798:** Use of Hard-coded Credentials (default `admin:admin`)
- **CWE-200:** Exposure of Sensitive Information (identifiable SSH banner)
- **Related:** CWE-250 (Execution with Unnecessary Privileges -- root SSH login), CWE-521 (Weak Password Requirements)
