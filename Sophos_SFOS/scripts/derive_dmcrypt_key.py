#!/usr/bin/env python3
"""
Sophos SFOS dm-crypt Key Derivation Reimplementation

Reversed from loadfw.static fcn.00418fe8 (Sophos SFOS 22.0.0.411)

The key derivation takes two inputs:
  - arg1 (int): disk sector size (typically 512)
  - arg2 (str): device path (e.g., "/dev/sda", "/dev/vda")

Algorithm:
  1. SHA-1 hash the device path string -> hash1 (20 bytes)
  2. Fill 32-byte key buffer by cycling through hash1: key_buf[i] = hash1[i % 20]
  3. SHA-1 hash the 4-byte little-endian arg1 -> hash2 (20 bytes)
  4. XOR key_buf with hash2 cycling: key_buf[i] ^= hash2[i % 20]
  5. XOR first 4 bytes of key_buf with arg1 bytes at specific positions:
     for i in 0..3: key_buf[(i*8) & 0x18] ^= (arg1 >> (i*8)) & 0xFF
  6. XOR each byte with a hardcoded constant table (32 bytes)
  7. Result is the 256-bit AES key for dm-crypt aes-cbc-essiv:sha256

Author: researcher
Date: 2026-03-28
"""

import hashlib
import struct
import sys

# Hardcoded XOR table extracted from the switch statement in fcn.00418fe8
# Cases 0-31, each XOR constant (low byte of the sign-extended value)
XOR_TABLE = [
    0xE9,  # case 0
    0x8A,  # case 1
    0x7B,  # case 2
    0xA5,  # case 3
    0xF3,  # case 4
    0x84,  # case 5
    0x4B,  # case 6
    0x40,  # case 7
    0xBC,  # case 8
    0x60,  # case 9
    0xA9,  # case 10
    0x38,  # case 11
    0x7A,  # case 12
    0xDB,  # case 13
    0xC7,  # case 14
    0x6B,  # case 15
    0x33,  # case 16
    0x5E,  # case 17
    0x6C,  # case 18
    0x89,  # case 19
    0x67,  # case 20
    0xCE,  # case 21
    0x4D,  # case 22
    0x4C,  # case 23
    0xA7,  # case 24
    0x87,  # case 25
    0xCB,  # case 26
    0x02,  # case 27
    0xEB,  # case 28
    0xA9,  # case 29
    0xAD,  # case 30
    0xAF,  # case 31
]


def derive_key(sector_size: int, device_path: str) -> bytes:
    """
    Derive the dm-crypt AES-256 key for a Sophos SFOS root partition.

    Args:
        sector_size: Disk sector size (typically 512)
        device_path: Device path string (e.g., "/dev/sda")

    Returns:
        32-byte AES key
    """
    # Step 1: SHA-1 hash the device path
    hash1 = hashlib.sha1(device_path.encode('ascii')).digest()  # 20 bytes

    # Step 2: Fill 32-byte key buffer cycling through hash1
    key_buf = bytearray(32)
    for i in range(32):
        key_buf[i] = hash1[i % 20]

    # Step 3: SHA-1 hash the sector_size as 4-byte little-endian
    arg1_bytes = struct.pack('<I', sector_size)
    hash2 = hashlib.sha1(arg1_bytes).digest()  # 20 bytes

    # Step 4: XOR key_buf with hash2 cycling
    for i in range(32):
        key_buf[i] ^= hash2[i % 20]

    # Step 5: XOR specific positions with arg1 bytes
    for i in range(4):
        pos = (i * 8) & 0x18  # positions 0, 8, 16, 24
        key_buf[pos] ^= (sector_size >> (i * 8)) & 0xFF

    # Step 6: XOR with hardcoded constant table
    output = bytearray(32)
    for i in range(32):
        output[i] = key_buf[i] ^ XOR_TABLE[i]

    return bytes(output)


def main():
    # Common Sophos device paths and sector sizes
    test_cases = [
        (512, "/dev/sda"),     # IDE/SATA (most common for hardware + QEMU IDE)
        (512, "/dev/vda"),     # virtio (QEMU with virtio-blk)
        (512, "/dev/hda"),     # legacy IDE
        (512, "/dev/mmcblk0"), # eMMC (XGS88 series)
        (512, "/dev/md0"),     # RAID
    ]

    if len(sys.argv) == 3:
        sector_size = int(sys.argv[1])
        device_path = sys.argv[2]
        test_cases = [(sector_size, device_path)]

    for sector_size, device_path in test_cases:
        key = derive_key(sector_size, device_path)
        hex_key = key.hex()
        print(f"Device: {device_path}  Sector: {sector_size}")
        print(f"  Key (hex): {hex_key}")
        print(f"  Key (raw): {key!r}")
        print()


if __name__ == "__main__":
    main()
