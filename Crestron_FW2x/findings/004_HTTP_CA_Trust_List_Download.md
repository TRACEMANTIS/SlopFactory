# [REDACTED-ID]_004: CA Trust List Downloaded Over HTTP (Cleartext)

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_004 |
| **Title** | CA Certificate Trust List Downloaded Over Unencrypted HTTP |
| **Severity** | HIGH (CVSS 3.1: 8.1 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Type** | CWE-319: Cleartext Transmission of Sensitive Information |
| **Affected Products** | DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, TS-1542-C, MERCURY, and all Crestron devices sharing the FW 2.x codebase |
| **Firmware Analyzed** | DMPS3 AirMedia PufVersion 1.5010.00023 (Build: February 23, 2024) |
| **Discovery Method** | Static analysis of `a_console` binary (strings extraction) |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## Summary

The Crestron FW 2.x firmware downloads its CA (Certificate Authority) trust list from `http://pki.crestron.io/pki/crestron-device-calist.zip` using plain HTTP -- not HTTPS. This URL is embedded as a string constant in the `a_console` binary.

The CA trust list defines which Certificate Authorities the device trusts for TLS connections (e.g., to Crestron cloud services, XiO Cloud, firmware update servers). By downloading this list over an unencrypted channel, the device is vulnerable to a man-in-the-middle (MITM) attack where an attacker on the network path substitutes a malicious CA list. Once the device trusts the attacker's CA, the attacker can issue fraudulent TLS certificates that the device will accept, enabling interception of all subsequent TLS-protected communications.

---

## Affected Component

| Component | Details |
|-----------|---------|
| **Binary** | `a_console` (667 KB, ARM32 EABI5) |
| **URL** | `http://pki.crestron.io/pki/crestron-device-calist.zip` |
| **Protocol** | HTTP (plaintext, port 80) |
| **Content** | CA certificate trust list (ZIP archive containing CA certificates) |
| **Purpose** | Populate device's trusted CA store for TLS validation |

---

## Technical Details

### 2.1 The HTTP URL

The following URL is embedded as a string constant in the `a_console` binary:

```
http://pki.crestron.io/pki/crestron-device-calist.zip
```

Key observations:
- The scheme is `http://` (plaintext), not `https://` (TLS-encrypted)
- The domain `pki.crestron.io` suggests this is Crestron's Public Key Infrastructure endpoint
- The file `crestron-device-calist.zip` is a ZIP archive containing CA certificates that the device will trust

### 2.2 Why This Matters

The CA trust list is the root of trust for all TLS connections made by the device. If an attacker can substitute this list, they can:

1. **Add their own CA certificate** to the trust list
2. **Issue certificates** for any domain (e.g., `*.crestron.com`, `*.xio.cloud`) signed by their rogue CA
3. **Intercept all TLS traffic** from the device -- the device will accept the attacker's certificates as valid
4. **Modify firmware updates, cloud communications, and configuration data** in transit

This is a "trust bootstrap" problem: the mechanism that establishes TLS trust is itself not protected by TLS.

### 2.3 MITM Attack Window

The CA list download occurs during device initialization or certificate store refresh operations. The attack window exists whenever:
- The device boots and initializes its certificate store
- The device performs a periodic CA list refresh
- An administrator triggers a certificate store update

During this window, any attacker positioned between the device and `pki.crestron.io` on the network path can intercept and modify the HTTP response.

### 2.4 No Integrity Verification

There is no evidence of a secondary integrity verification mechanism (e.g., a detached PGP signature, a hash file downloaded over a separate authenticated channel, or certificate pinning) that would detect tampering with the downloaded ZIP file. The device appears to trust the downloaded content based solely on the HTTP response.

---

## Impact

| Scenario | Impact | Severity |
|----------|--------|----------|
| MITM substitution of CA trust list | Attacker becomes trusted CA for all device TLS connections | CRITICAL |
| TLS interception of cloud communications | Attacker reads/modifies XiO Cloud, Fusion Cloud traffic | HIGH |
| Firmware update interception | Attacker modifies firmware updates in transit | CRITICAL |
| Credential interception | Attacker captures authentication tokens sent over TLS | HIGH |
| Persistent compromise | Rogue CA persists in trust store until next refresh | HIGH |

### Attack Scenario

1. Attacker positions themselves on the network path between the Crestron device and the internet (e.g., compromised router, ARP spoofing on the LAN, malicious WiFi access point, compromised ISP)
2. Device initiates HTTP request to `http://pki.crestron.io/pki/crestron-device-calist.zip`
3. Attacker intercepts the request and serves a modified ZIP archive containing:
   - All legitimate Crestron CA certificates (to maintain normal operation)
   - The attacker's rogue CA certificate (appended to the list)
4. Device imports the CA list, now trusting the attacker's CA
5. Attacker uses their rogue CA to issue a certificate for `*.crestron.com` (or any domain the device communicates with)
6. All subsequent TLS connections from the device to Crestron services are transparently intercepted by the attacker
7. Attacker can read configuration data, modify firmware updates, capture credentials, and inject commands

### MITM Implementation

```bash
# Attacker creates a rogue CA
openssl req -x509 -newkey rsa:2048 -keyout rogue-ca.key -out rogue-ca.crt -days 365 -nodes \
    -subj "/CN=Attacker CA"

# Attacker prepares a modified CA list ZIP
cp legitimate-calist.zip modified-calist.zip
zip -j modified-calist.zip rogue-ca.crt

# Attacker uses mitmproxy, Bettercap, or iptables REDIRECT to intercept HTTP traffic to pki.crestron.io
# and serve modified-calist.zip in the response
```

---

## Evidence

### String Evidence from a_console

```
$ strings a_console | grep pki.crestron
http://pki.crestron.io/pki/crestron-device-calist.zip
```

### Protocol Confirmation

The URL uses the `http://` scheme (port 80, no encryption). No corresponding `https://` URL for the same resource was found in the binary.

### Fleet Impact

[N] of [N] probed hosts ([REDACTED]%) run FW 2.x firmware containing this URL. All devices with this firmware version download their CA trust list over the same unencrypted channel.

---

## Reproduction Steps (for vendor)

1. Obtain the DMPS3 AirMedia firmware PUF file (version 1.5010.00023)
2. Extract the `a_console` binary:
   ```bash
   binwalk -e dmps3_airmedia_1.5010.00023.puf
   mount -o loop,ro system.img /mnt/fw
   cp /mnt/fw/system/bin/a_console .
   ```
3. Confirm the HTTP URL:
   ```bash
   strings a_console | grep "http://pki.crestron"
   # Output: http://pki.crestron.io/pki/crestron-device-calist.zip
   ```
4. To validate the MITM scenario:
   - Set up a test network with a MITM proxy (e.g., mitmproxy, Bettercap)
   - Configure the proxy to intercept requests to `pki.crestron.io` and serve a modified ZIP
   - Boot or trigger a CA refresh on the Crestron device
   - Verify the device imports the modified CA list by checking its certificate store
5. Confirm no HTTPS alternative exists:
   ```bash
   strings a_console | grep "https://pki.crestron"
   # Expected: no output (HTTPS variant not present)
   ```

---

## Suggested Fix

1. **Use HTTPS for CA trust list downloads.** Change the URL to `https://pki.crestron.io/pki/crestron-device-calist.zip` with proper TLS certificate validation. This is the minimum necessary fix.
2. **Pin the server certificate or CA.** Since this is a Crestron-controlled server, pin the specific TLS certificate (or its issuing CA) used by `pki.crestron.io` in the device firmware. This prevents MITM even if the attacker compromises a public CA.
3. **Sign the CA trust list.** Digitally sign the `crestron-device-calist.zip` file with a Crestron code-signing key. The device should verify the signature before importing any certificates. The signing key's public counterpart should be embedded in the firmware (in a read-only partition).
4. **Bootstrap trust from firmware.** Ship a baseline CA trust list in the firmware image itself. Only allow additive updates from authenticated, signed sources. Never replace the entire trust store from a network download without cryptographic verification.
5. **Implement certificate transparency logging.** Log all CA list updates (source, timestamp, hash of imported list) to the device audit log for forensic analysis.

---

## Status

| Item | Status |
|------|--------|
| **Discovery** | Confirmed via static analysis (strings in `a_console`) |
| **HTTP URL** | Confirmed -- `http://` scheme, no HTTPS alternative in binary |
| **MITM validation** | Pending -- requires network-adjacent test environment |
| **Server availability** | Not tested -- `pki.crestron.io` reachability not verified |
| **Exploitability** | HIGH -- HTTP MITM is well-understood; tools are freely available |

---

## CWE Reference

- **CWE-319:** Cleartext Transmission of Sensitive Information (CA list downloaded over HTTP)
- **CWE-295:** Improper Certificate Validation (trust bootstrap over unauthenticated channel)
- **CWE-494:** Download of Code Without Integrity Check (no signature verification on CA list)
- **Related:** CWE-300 (Channel Accessible by Non-Endpoint -- MITM), CWE-345 (Insufficient Verification of Data Authenticity)
