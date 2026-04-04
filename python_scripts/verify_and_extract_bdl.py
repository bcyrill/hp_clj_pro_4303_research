#!/usr/bin/env python3
"""
HP BDL (Bundle) Firmware File Verifier

Parses and verifies HP LaserJet BDL firmware update bundles.
Performs: header CRC validation, item table CRC validation, file CRC validation,
HP CSS signature verification, and optional extraction/decryption of .gtx1 payloads.

The .gtx1 files use AES-256-CBC encryption (16-byte IV prefix, PKCS#7 padding).
The digests.txt files inside each package contain SHA-256 hashes of the decrypted
plaintext — these serve dual purpose as both verification hashes AND key derivation input.

The AES-256 key is derived per-file using the TrustZone formula:
  AES_key = SHA-256(PLATFORM_PREFIX || PLATFORM_UUID || bytes.fromhex(digest_hex))
where the digest_hex comes from digests.txt for each encrypted file.

Format reference: BDL_Format_Documentation.md
Target: HP Color LaserJet Pro MFP 4301-4303 series (TX54 / Dune-Selene platform)

Usage:
    python3 verify_and_extract_bdl.py <file.bdl> [--extract <dir>] [--verbose] [--no-sig]
    python3 verify_and_extract_bdl.py <file.bdl> --decrypt --extract <dir>
    python3 verify_and_extract_bdl.py <file.bdl> --decrypt --key <hex_key> --extract <dir>
"""

import argparse
import base64
import configparser
import hashlib
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Known HP bundle validation public keys (PEM-encoded RSA-2048)
# Extracted from libframework.so in the HP Color LaserJet Pro MFP 4301-4303 firmware.
#
# BundleValidationKeyTable in libframework.so contains 4 entries.
# Each entry: { char* name, uint32_t flags, KeyDataSlot[12] }
#
# flags=1 → development/platform key (restricted in secure boot)
# flags=2 → production key (always available)
# ---------------------------------------------------------------------------
KNOWN_KEYS = {
    # Verified against actual BDL signature (libframework.so @ 0x358603)
    "SIRIUS-LINUX-APPLICATION-HPB": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA46zZjFMRrf0KFelIxXnf\n"
        "VpbxZwv/wXA7AAfMtVFNU1dR6aTtM5/Bzv8Zg6lztlctnCmK14zt9L98PZ38760P\n"
        "vgasBZy/feGJxjumLVVsX5IBTtJg1cTaKGtHGi9bFSLnHUhvw5m27Asca5N2gEjN\n"
        "w9UqYEAnJ05Iow289mrc8BsnPr8Dvh902eWlprBEA22nR0lXIh0539OKxy2mKK3M\n"
        "bpmiiFKGNitfwPqNMho3dU1WlbEUCIDw4iAgO0qEdLOp7OwZjCrPtA7zGCzvTRQT\n"
        "OcUEmH2xur/lfalZ1XwRM9mrOcfCRTvyQDscOOoc50OK1lHJpfPkp5lvuRwqYf5g\n"
        "twIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
    ),
    # libframework.so @ 0x358340
    "PRSSDEV-Key-IPG-RD": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtMTXi0oiaYdgwbwqKCCJ\n"
        "jb0TCOmVgwa7bBIxfKBRr3Th5Te5kFnhuMc8O1LQEZFUbkRDxRGj2n0tPCxZbi39\n"
        "aYPpAXY4ycHe0p9Pbn5cObCvkUrvN5/NLlZGakJFa8Hg90SXcxB3XJ0AiHzn/Qd4\n"
        "Fogpn+GCZao6HcqtG8xAA45J42vIv5OaVDVRK8Ob6jC31TwP7lsl7Bi+aKbOwBrN\n"
        "jLm2AjOi+pjQsOB6GZ/caRw7HrtjsS8YeWZe2EfvooHUat4RaY8umCMtL+wFDPXm\n"
        "kQJBTfwwF2bbrmqZ6083rgmaLtMySREwQEEj9PrU6B3Ei8AaXDcSqcdiy0lq4woO\n"
        "swIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
    ),
    # libframework.so @ 0x3587d0
    "TestDEV-Key-IPG-RD": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJwBm8wtZoFHwkCX+8xC\n"
        "06FbWFsouZHMArv1s3GFMCJ0scqCn7sc/wG5/l2hYAsPSre1nlWUlFOnYYl+RE7A\n"
        "ycxOukibm9BnyegeFnnUmdaOhYI6faxwewbl0ZOoW31P/MNTUCXykA/ydc3naoY4\n"
        "0AzHwwilrRh5ZRLrGDUnz+53AYroEUC+0J2GsSwcXye2sI9RQvdoDkk+uFIsNvZ5\n"
        "sdhC6ZOrLOK67MjKoBladGAXcjU9ODE1olxOjGnOIN1Njpjrom3sLDSmwNnrWHlA\n"
        "5OA+qaxSLIlmmETE8P3eUfUAp5dkiNH00JsF+UxdzKOn07/GJ39SJMegFhESltlo\n"
        "zQIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
    ),
    # lib01f1dd40.so @ 0x1f229ac
    "LFP-FW-INTEGRATORS-HPB-2022-1": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3SJLV+iK4hl5yxzxpH/Q\n"
        "GMeb3unE7PVq/4drOakI9gVDelMTBjGcloGLoRbTyBaTE5BNsfc7laMQl3HZ3I/O\n"
        "JdE7upAGldDwEB1CIx7bAgExT/yqc3mraYd8g2laufm35P9VZoFVLp+B0QdHXous\n"
        "t0BerK8j4yz7gWEp8dyB8G771dCdgwtUjMosGgCYsPROwkggmvSjQCq2KBe1voFr\n"
        "96zh7Q4YMqydfUChzZC0tVW/Oy4p+JvyNc4YJrBp2WBVscjeXqbZaH7EMiWK7aUk\n"
        "bxdhNPoW5MmoguDWTj53nvR9eKMzUaiQnxC2UqI2ffwc9+QytCAAkszYDs6IQiWr\n"
        "uQIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
    ),
}

# Known package type UUIDs (RFC 4122 on-disk mixed-endian)
PACKAGE_TYPES = {
    bytes.fromhex("9d33cb83bdf6e0408c4559e409579b58"): "LBI",
    bytes.fromhex("9d33cb83bdf6e0408c4559e409579b59"): "ROOTFS",
    bytes.fromhex("9d33cb83bdf6e0408c4559e409579b5a"): "DATAFS",
    bytes.fromhex("f50ecc2526725c469f0a190aaaef9175"): "ECLIPSE",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CommonHeader:
    """Shared 800-byte prefix for BDL and ipkg headers."""
    magic: bytes
    version_major: int
    version_minor: int
    header_size: int
    header_crc: int
    item_count: int
    item_table_crc: int
    timestamp: int
    reserved: int
    version_string: str
    vendor: str
    name: str
    raw: bytes = field(repr=False, default=b"")

    STRUCT_SIZE = 0x320  # 800 bytes

    @classmethod
    def parse(cls, data: bytes) -> "CommonHeader":
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError(f"CommonHeader requires {cls.STRUCT_SIZE} bytes, got {len(data)}")
        magic = data[0:4]
        vmaj, vmin = struct.unpack_from("<HH", data, 4)
        hdr_size, hdr_crc, item_count, item_table_crc, ts, rsv = struct.unpack_from("<IIIIII", data, 8)
        vs = data[0x20:0x120].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vendor = data[0x120:0x220].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        name = data[0x220:0x320].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return cls(magic=magic, version_major=vmaj, version_minor=vmin,
                   header_size=hdr_size, header_crc=hdr_crc,
                   item_count=item_count, item_table_crc=item_table_crc,
                   timestamp=ts, reserved=rsv,
                   version_string=vs, vendor=vendor, name=name, raw=data[:cls.STRUCT_SIZE])


@dataclass
class BdlHeader:
    """Full 2345-byte BDL bundle header."""
    common: CommonHeader
    bundle_type: int
    options: int
    description: str
    identifier: str
    support_url: str
    support_phone: str
    support_email: str
    serial_number: str
    raw: bytes = field(repr=False, default=b"")

    STRUCT_SIZE = 0x929  # 2345 bytes

    @classmethod
    def parse(cls, data: bytes) -> "BdlHeader":
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError(f"BdlHeader requires {cls.STRUCT_SIZE} bytes, got {len(data)}")
        common = CommonHeader.parse(data)
        if common.magic != b"ibdl":
            raise ValueError(f"Invalid BDL magic: {common.magic!r} (expected b'ibdl')")
        btype = struct.unpack_from("<I", data, 0x320)[0]
        opts = struct.unpack_from("<I", data, 0x324)[0]
        # 0x328 = _pad0 (1 byte, skip)
        desc = data[0x329:0x429].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        ident = data[0x429:0x529].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        surl = data[0x529:0x629].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sphone = data[0x629:0x729].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        semail = data[0x729:0x829].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sn = data[0x829:0x929].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return cls(common=common, bundle_type=btype, options=opts,
                   description=desc, identifier=ident,
                   support_url=surl, support_phone=sphone,
                   support_email=semail, serial_number=sn,
                   raw=data[:cls.STRUCT_SIZE])


@dataclass
class PakHeader:
    """Full 1085-byte ipkg package header."""
    common: CommonHeader
    type_uuid: bytes
    install_options: int
    install_phase: int
    package_options: int
    description: str
    raw: bytes = field(repr=False, default=b"")

    STRUCT_SIZE = 0x43D  # 1085 bytes

    @classmethod
    def parse(cls, data: bytes) -> "PakHeader":
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError(f"PakHeader requires {cls.STRUCT_SIZE} bytes, got {len(data)}")
        common = CommonHeader.parse(data)
        if common.magic != b"ipkg":
            raise ValueError(f"Invalid ipkg magic: {common.magic!r} (expected b'ipkg')")
        type_uuid = data[0x320:0x330]
        iopts = struct.unpack_from("<I", data, 0x330)[0]
        iphase = struct.unpack_from("<I", data, 0x334)[0]
        popts = struct.unpack_from("<I", data, 0x338)[0]
        # 0x33C = _pad0 (1 byte, skip)
        desc = data[0x33D:0x43D].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return cls(common=common, type_uuid=type_uuid,
                   install_options=iopts, install_phase=iphase,
                   package_options=popts, description=desc,
                   raw=data[:cls.STRUCT_SIZE])

    def type_name(self) -> str:
        return PACKAGE_TYPES.get(self.type_uuid, f"UNKNOWN({self.type_uuid.hex()})")

    def uuid_rfc4122(self) -> str:
        """Format on-disk UUID as RFC 4122 string (mixed-endian conversion)."""
        u = self.type_uuid
        return (f"{u[0]:02x}{u[1]:02x}{u[2]:02x}{u[3]:02x}-"
                f"{u[4]:02x}{u[5]:02x}-{u[6]:02x}{u[7]:02x}-"
                f"{u[8]:02x}{u[9]:02x}-"
                f"{u[10]:02x}{u[11]:02x}{u[12]:02x}{u[13]:02x}{u[14]:02x}{u[15]:02x}")


@dataclass
class PackageTableEntry:
    offset: int
    size: int

    @classmethod
    def parse(cls, data: bytes) -> "PackageTableEntry":
        off, sz = struct.unpack_from("<QQ", data, 0)
        return cls(offset=off, size=sz)


@dataclass
class FileTableEntry:
    filename: str
    file_offset: int
    file_size: int
    crc32: int

    STRUCT_SIZE = 0x114  # 276 bytes

    @classmethod
    def parse(cls, data: bytes) -> "FileTableEntry":
        fname = data[0:256].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        foff, fsz = struct.unpack_from("<QQ", data, 0x100)
        crc = struct.unpack_from("<I", data, 0x110)[0]
        return cls(filename=fname, file_offset=foff, file_size=fsz, crc32=crc)


@dataclass
class HpCssSignature:
    """Parsed HP CSS (Code Signing Service) signature block."""
    key_name: str
    hash_algo: str
    signature: bytes
    fingerprint_length: int
    block_offset: int
    block_size: int


# ---------------------------------------------------------------------------
# CRC verification helpers
# ---------------------------------------------------------------------------

def verify_header_crc(raw_header: bytes, crc_offset: int = 0x0C) -> Tuple[bool, int, int]:
    """Verify CRC-32 of a header, excluding the headerCrc field itself."""
    stored = struct.unpack_from("<I", raw_header, crc_offset)[0]
    check_data = bytearray(raw_header)
    check_data[crc_offset:crc_offset + 4] = b"\x00\x00\x00\x00"
    computed = zlib.crc32(bytes(check_data)) & 0xFFFFFFFF
    return (stored == computed, stored, computed)


def verify_item_table_crc(table_data: bytes, stored_crc: int) -> Tuple[bool, int, int]:
    """Verify CRC-32 of an item table (package table or file table)."""
    computed = zlib.crc32(table_data) & 0xFFFFFFFF
    return (stored_crc == computed, stored_crc, computed)


# ---------------------------------------------------------------------------
# HP CSS Signature parsing
# ---------------------------------------------------------------------------

def parse_hp_css_signature(f, file_size: int) -> Optional[HpCssSignature]:
    """Find and parse the HP CSS signature block at the end of the file."""
    search_size = min(10000, file_size)
    f.seek(file_size - search_size)
    tail = f.read(search_size)

    # Search for the exact begin marker (not just "Begin HP..." which requires
    # newline walk-back that fails in binary data)
    begin_marker = b"--=</Begin HP Signed File Fingerprint"
    idx = tail.find(begin_marker)
    if idx < 0:
        return None

    block_offset = file_size - search_size + idx
    block_data = tail[idx:].decode("ascii", errors="replace")

    key_name = ""
    hash_algo = ""
    sig_b64 = ""
    fp_length = 0

    for line in block_data.split("\n"):
        line = line.strip()
        if line.startswith("Key:"):
            key_name = line.split(":", 1)[1].strip()
        elif line.startswith("Hash:"):
            hash_algo = line.split(":", 1)[1].strip()
        elif line.startswith("Signature:"):
            sig_b64 = line.split(":", 1)[1].strip()
        elif line.startswith("Fingerprint Length:"):
            fp_length = int(line.split(":", 1)[1].strip())

    if not sig_b64:
        return None

    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return None

    return HpCssSignature(
        key_name=key_name, hash_algo=hash_algo, signature=sig_bytes,
        fingerprint_length=fp_length, block_offset=block_offset,
        block_size=file_size - block_offset,
    )


def verify_hp_css_signature(f, sig: HpCssSignature, verbose: bool = False) -> bool:
    """Verify the HP CSS RSA signature over the file content."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    except ImportError:
        print("  [!] cryptography library not installed — cannot verify RSA signature")
        print("      Install with: pip install cryptography")
        return False

    pem_str = KNOWN_KEYS.get(sig.key_name)
    if pem_str is None:
        print(f"  [!] Unknown signing key: {sig.key_name}")
        print(f"      Known keys: {', '.join(KNOWN_KEYS.keys())}")
        return False

    pubkey = serialization.load_pem_public_key(pem_str.encode())

    # Read the signed content (everything before the signature block)
    f.seek(0)
    content = f.read(sig.block_offset)

    if verbose:
        content_hash = hashlib.sha256(content).hexdigest()
        print(f"  Signed content:  {len(content):,} bytes (0x{len(content):X})")
        print(f"  Content SHA-256: {content_hash}")
        print(f"  Signature size:  {len(sig.signature)} bytes")

    # HP CSS uses PKCS#1 v1.5 RSA signature: RSA(SHA-256(content))
    # The cryptography library's verify() hashes internally
    try:
        pubkey.verify(
            sig.signature,
            content,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        if verbose:
            print(f"  Verify error:    {e}")
        return False


# ---------------------------------------------------------------------------
# Decryption support
# ---------------------------------------------------------------------------

_BDL_KEYS_CONF = Path(__file__).with_name("bdl_keys.conf")

# Cached key material — populated lazily by _get_key_material().
_key_material: Optional[Tuple[bytes, bytes]] = None


def _get_key_material() -> Tuple[bytes, bytes]:
    """Return (PLATFORM_PREFIX, PLATFORM_UUID), loading bdl_keys.conf on first call.

    Raises a clear error when the config file is missing or values are empty.
    """
    global _key_material
    if _key_material is not None:
        return _key_material

    cfg_path = _BDL_KEYS_CONF
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Key configuration not found: {cfg_path}\n"
            "Decryption requires a bdl_keys.conf file next to this script.\n"
            "It must contain [key_derivation] with 'platform_prefix' and "
            "'platform_uuid' values."
        )

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path, encoding="utf-8")

    try:
        prefix = cfg.get("key_derivation", "platform_prefix")
        uuid = cfg.get("key_derivation", "platform_uuid")
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        raise ValueError(
            f"bdl_keys.conf is missing required key_derivation entries: {exc}\n"
            "Both 'platform_prefix' and 'platform_uuid' must be set in the "
            "[key_derivation] section."
        ) from exc

    if not prefix.strip():
        raise ValueError(
            "bdl_keys.conf: 'platform_prefix' in [key_derivation] is empty. "
            "A non-empty value is required for AES key derivation."
        )
    if not uuid.strip():
        raise ValueError(
            "bdl_keys.conf: 'platform_uuid' in [key_derivation] is empty. "
            "A non-empty value is required for AES key derivation."
        )

    _key_material = (prefix.encode(), uuid.encode())
    return _key_material


def derive_aes_key(digest_hex: str) -> str:
    """Derive the AES-256 key for a .gtx1 file from its digests.txt hash.

    The key derivation replicates the TrustZone Security_ComputeDeviceHash function:
      AES_key = SHA-256(PLATFORM_PREFIX || PLATFORM_UUID || bytes.fromhex(digest_hex))

    Args:
        digest_hex: The SHA-256 hex string from digests.txt for the encrypted file.
    Returns:
        The derived AES-256 key as a 64-character hex string.
    Raises:
        FileNotFoundError: If bdl_keys.conf is missing.
        ValueError: If key values are empty or malformed.
    """
    platform_prefix, platform_uuid = _get_key_material()
    h = hashlib.sha256()
    h.update(platform_prefix)            # 28 bytes
    h.update(platform_uuid[:36])         # 36 bytes (0x24)
    h.update(bytes.fromhex(digest_hex))  # 32 bytes (0x20)
    return h.hexdigest()


def decrypt_gtx1(ciphertext_with_iv: bytes, hex_key: str) -> Optional[bytes]:
    """Decrypt a .gtx1 AES-256-CBC payload. Returns plaintext or None on failure.

    The .gtx1 format is: 16-byte IV ‖ AES-256-CBC ciphertext (PKCS#7 padded).
    The key can be provided directly or auto-derived from the digests.txt hash
    using derive_aes_key().
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
    except ImportError:
        print("  [!] cryptography library not installed — cannot decrypt")
        return None

    if len(hex_key) != 64:
        print(f"  [!] Invalid AES key length: {len(hex_key)} hex chars (expected 64)")
        return None

    key = bytes.fromhex(hex_key)
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    unpadder = PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except Exception:
        # Padding removal failed — key is likely wrong
        print("      [!] PKCS#7 unpadding failed — wrong key?")
        plaintext = padded

    return plaintext


def parse_digests_txt(data: bytes) -> dict:
    """Parse a KVP digests.txt file into a dict of filename → value.

    Despite the historical assumption that these are AES keys, the values are
    actually SHA-256 hashes of the decrypted plaintext, used by the firmware's
    FileWriter::getHexDigest() for post-decryption integrity verification.
    """
    result = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return result


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class BdlParser:
    def __init__(self, filepath: str, verbose: bool = False):
        self.filepath = filepath
        self.verbose = verbose
        self.file_size = os.path.getsize(filepath)
        self.bdl_header: Optional[BdlHeader] = None
        self.package_table: List[PackageTableEntry] = []
        self.packages: List[Tuple[PakHeader, List[FileTableEntry]]] = []
        self.signature: Optional[HpCssSignature] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse(self):
        with open(self.filepath, "rb") as f:
            self._parse_bdl_header(f)
            self._parse_package_table(f)
            self._parse_packages(f)
            self._parse_signature(f)

    def _parse_bdl_header(self, f):
        f.seek(0)
        data = f.read(BdlHeader.STRUCT_SIZE)
        self.bdl_header = BdlHeader.parse(data)

    def _parse_package_table(self, f):
        hdr = self.bdl_header.common
        f.seek(hdr.header_size)
        table_size = hdr.item_count * 16
        table_data = f.read(table_size)
        for i in range(hdr.item_count):
            entry = PackageTableEntry.parse(table_data[i * 16:(i + 1) * 16])
            self.package_table.append(entry)

    def _parse_packages(self, f):
        for pte in self.package_table:
            f.seek(pte.offset)
            pak_data = f.read(PakHeader.STRUCT_SIZE)
            pak = PakHeader.parse(pak_data)

            # Read file table
            files = []
            ft_data = f.read(pak.common.item_count * FileTableEntry.STRUCT_SIZE)
            for i in range(pak.common.item_count):
                fe = FileTableEntry.parse(ft_data[i * FileTableEntry.STRUCT_SIZE:(i + 1) * FileTableEntry.STRUCT_SIZE])
                files.append(fe)

            self.packages.append((pak, files))

    def _parse_signature(self, f):
        self.signature = parse_hp_css_signature(f, self.file_size)

    def verify_all(self, skip_signature: bool = False, do_decrypt: bool = False,
                   extract_dir: Optional[str] = None, aes_key_hex: Optional[str] = None) -> bool:
        all_ok = True
        with open(self.filepath, "rb") as f:
            all_ok &= self._verify_bdl_header()
            all_ok &= self._verify_package_table(f)
            all_ok &= self._verify_packages(f, do_decrypt, extract_dir, aes_key_hex)
            if not skip_signature:
                all_ok &= self._verify_signature(f)
            else:
                print("\n[*] Signature verification skipped (--no-sig)")
        return all_ok

    def _verify_bdl_header(self) -> bool:
        hdr = self.bdl_header
        print("=" * 70)
        print("BDL BUNDLE HEADER")
        print("=" * 70)
        print(f"  Magic:       {hdr.common.magic.decode('ascii', errors='replace')}")
        print(f"  Format:      v{hdr.common.version_major}.{hdr.common.version_minor}")
        print(f"  Header Size: 0x{hdr.common.header_size:X} ({hdr.common.header_size} bytes)")
        print(f"  Packages:    {hdr.common.item_count}")
        ts = hdr.common.timestamp
        try:
            dt = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, ValueError, OverflowError):
            dt = "invalid"
        print(f"  Timestamp:   {ts} ({dt})")
        print(f"  Version:     {hdr.common.version_string}")
        print(f"  Vendor:      {hdr.common.vendor}")
        print(f"  Name:        {hdr.common.name}")
        print(f"  Type:        0x{hdr.bundle_type:X}")
        print(f"  Options:     0x{hdr.options:X}")
        print(f"  Description: {hdr.description}")
        print(f"  Identifier:  {hdr.identifier}")
        if hdr.support_url:
            print(f"  Support URL: {hdr.support_url}")
        if hdr.serial_number:
            print(f"  Serial:      {hdr.serial_number}")

        # Verify header CRC
        ok, stored, computed = verify_header_crc(hdr.raw)
        status = "OK" if ok else "FAILED"
        sym = "✓" if ok else "✗"
        print(f"\n  Header CRC:  {sym} {status} (stored=0x{stored:08X} computed=0x{computed:08X})")
        if not ok:
            self.errors.append(f"BDL header CRC mismatch: stored=0x{stored:08X} computed=0x{computed:08X}")
        return ok

    def _verify_package_table(self, f) -> bool:
        hdr = self.bdl_header.common
        f.seek(hdr.header_size)
        table_data = f.read(hdr.item_count * 16)
        ok, stored, computed = verify_item_table_crc(table_data, hdr.item_table_crc)
        sym = "✓" if ok else "✗"
        status = "OK" if ok else "FAILED"
        print(f"  Table CRC:   {sym} {status} (stored=0x{stored:08X} computed=0x{computed:08X})")
        if not ok:
            self.errors.append(f"Package table CRC mismatch")
        return ok

    def _verify_packages(self, f, do_decrypt: bool, extract_dir: Optional[str],
                         aes_key_hex: Optional[str] = None) -> bool:
        all_ok = True
        for pkg_idx, (pte, (pak, files)) in enumerate(zip(self.package_table, self.packages)):
            print(f"\n{'=' * 70}")
            print(f"PACKAGE {pkg_idx}: {pak.common.name}")
            print(f"{'=' * 70}")
            print(f"  Offset:          0x{pte.offset:X}")
            print(f"  Size:            0x{pte.size:X} ({pte.size:,} bytes)")
            print(f"  Format:          v{pak.common.version_major}.{pak.common.version_minor}")
            print(f"  Version:         {pak.common.version_string}")
            print(f"  Type UUID:       {pak.uuid_rfc4122()}")
            print(f"  Type Name:       {pak.type_name()}")
            print(f"  Description:     {pak.description}")
            print(f"  Install Options: 0x{pak.install_options:X}")
            print(f"  Install Phase:   0x{pak.install_phase:X}")
            print(f"  Package Options: 0x{pak.package_options:X}")
            print(f"  Files:           {pak.common.item_count}")

            # Verify package header CRC
            ok, stored, computed = verify_header_crc(pak.raw)
            sym = "✓" if ok else "✗"
            status = "OK" if ok else "FAILED"
            print(f"\n  Header CRC:      {sym} {status} (stored=0x{stored:08X} computed=0x{computed:08X})")
            if not ok:
                self.errors.append(f"Package {pkg_idx} ({pak.common.name}) header CRC mismatch")
                all_ok = False

            # Verify file table CRC
            f.seek(pte.offset + PakHeader.STRUCT_SIZE)
            ft_data = f.read(pak.common.item_count * FileTableEntry.STRUCT_SIZE)
            ok, stored, computed = verify_item_table_crc(ft_data, pak.common.item_table_crc)
            sym = "✓" if ok else "✗"
            status = "OK" if ok else "FAILED"
            print(f"  File Table CRC:  {sym} {status} (stored=0x{stored:08X} computed=0x{computed:08X})")
            if not ok:
                self.errors.append(f"Package {pkg_idx} ({pak.common.name}) file table CRC mismatch")
                all_ok = False

            # Parse digests.txt if present (contains SHA-256 hashes of decrypted plaintext)
            digests = {}
            for fe in files:
                if fe.filename == "digests.txt":
                    abs_off = pte.offset + fe.file_offset
                    f.seek(abs_off)
                    digests = parse_digests_txt(f.read(fe.file_size))
                    if self.verbose:
                        print(f"\n  digests.txt entries: {list(digests.keys())}")
                    break

            # Verify each file
            print()
            for file_idx, fe in enumerate(files):
                abs_offset = pte.offset + fe.file_offset
                f.seek(abs_offset)
                file_data = f.read(fe.file_size)
                actual_crc = zlib.crc32(file_data) & 0xFFFFFFFF
                crc_ok = actual_crc == fe.crc32
                sym = "✓" if crc_ok else "✗"
                status = "OK" if crc_ok else "FAILED"
                is_encrypted = fe.filename.endswith(".gtx1")
                enc_tag = " [AES-256-CBC]" if is_encrypted else ""

                print(f"  [{file_idx}] {fe.filename}{enc_tag}")
                print(f"      Offset: 0x{fe.file_offset:X} (abs 0x{abs_offset:X})")
                print(f"      Size:   {fe.file_size:,} bytes")
                print(f"      CRC-32: {sym} {status} (stored=0x{fe.crc32:08X} computed=0x{actual_crc:08X})")

                if not crc_ok:
                    self.errors.append(
                        f"Package {pkg_idx} file '{fe.filename}' CRC mismatch: "
                        f"stored=0x{fe.crc32:08X} computed=0x{actual_crc:08X}")
                    all_ok = False

                # Show SHA-256 digest from digests.txt if available
                expected_hash = digests.get(fe.filename)
                if expected_hash:
                    print(f"      SHA-256: {expected_hash[:16]}...{expected_hash[-16:]} (expected plaintext hash)")

                # Decrypt if requested (auto-derive from digests.txt or use explicit --key)
                if do_decrypt and is_encrypted and crc_ok:
                    # Determine key: explicit --key overrides auto-derivation
                    use_key = aes_key_hex
                    key_source = "explicit"
                    if not use_key and expected_hash:
                        use_key = derive_aes_key(expected_hash)
                        key_source = "auto-derived"
                    if use_key:
                        if self.verbose:
                            print(f"      Key:     {use_key[:16]}...{use_key[-16:]} ({key_source})")
                        plaintext = decrypt_gtx1(file_data, use_key)
                        if plaintext is not None:
                            print(f"      Decrypt: ✓ OK ({len(plaintext):,} bytes plaintext)")
                            # Verify SHA-256 of decrypted data against digests.txt
                            if expected_hash:
                                actual_hash = hashlib.sha256(plaintext).hexdigest()
                                hash_ok = actual_hash == expected_hash
                                h_sym = "✓" if hash_ok else "✗"
                                h_status = "MATCH" if hash_ok else "MISMATCH"
                                print(f"      Verify:  {h_sym} SHA-256 {h_status}")
                                if self.verbose:
                                    print(f"               expected: {expected_hash}")
                                    print(f"               actual:   {actual_hash}")
                                if not hash_ok:
                                    self.warnings.append(
                                        f"SHA-256 mismatch for decrypted {fe.filename} "
                                        f"(wrong key?)")
                            if extract_dir:
                                out_name = fe.filename.replace(".gtx1", "")
                                out_path = os.path.join(extract_dir, f"pkg{pkg_idx}_{pak.common.name}", out_name)
                                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                with open(out_path, "wb") as out_f:
                                    out_f.write(plaintext)
                                print(f"      Saved:   {out_path}")
                        else:
                            print(f"      Decrypt: ✗ FAILED (PKCS#7 padding error – wrong key?)")
                            self.warnings.append(f"Failed to decrypt {fe.filename}")
                    else:
                        print(f"      Decrypt: ✗ No digest in digests.txt for key derivation")
                        self.warnings.append(
                            f"Cannot decrypt {fe.filename}: no digest available for "
                            f"auto-derivation. Use --key <hex> to supply an explicit key.")

                # Extract raw files if requested
                if extract_dir:
                    # For encrypted files without decryption, extract the raw .gtx1
                    if is_encrypted and not (do_decrypt and (aes_key_hex or expected_hash)):
                        out_path = os.path.join(extract_dir, f"pkg{pkg_idx}_{pak.common.name}", fe.filename)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, "wb") as out_f:
                            out_f.write(file_data)
                        print(f"      Saved:   {out_path} (raw encrypted)")
                    elif not is_encrypted:
                        out_path = os.path.join(extract_dir, f"pkg{pkg_idx}_{pak.common.name}", fe.filename)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, "wb") as out_f:
                            out_f.write(file_data)
                        print(f"      Saved:   {out_path}")

        return all_ok

    def _verify_signature(self, f) -> bool:
        print(f"\n{'=' * 70}")
        print("HP CSS SIGNATURE VERIFICATION")
        print(f"{'=' * 70}")

        if self.signature is None:
            print("  [!] No HP CSS signature block found")
            self.errors.append("No HP CSS signature block found")
            return False

        sig = self.signature
        print(f"  Block Offset:    0x{sig.block_offset:X}")
        print(f"  Block Size:      {sig.block_size} bytes")
        print(f"  Key Name:        {sig.key_name}")
        print(f"  Hash Algorithm:  {sig.hash_algo}")
        print(f"  Signature Size:  {len(sig.signature)} bytes")
        print(f"  Fingerprint Len: {sig.fingerprint_length}")

        key_known = sig.key_name in KNOWN_KEYS
        print(f"  Key Known:       {'Yes' if key_known else 'No'}")

        ok = verify_hp_css_signature(f, sig, verbose=self.verbose)
        sym = "✓" if ok else "✗"
        status = "VALID" if ok else "INVALID"
        print(f"\n  Signature:       {sym} {status}")

        if not ok:
            self.errors.append(f"HP CSS signature verification failed (key={sig.key_name})")
        return ok

    def print_summary(self):
        print(f"\n{'=' * 70}")
        print("SUMMARY")
        print(f"{'=' * 70}")
        print(f"  File:     {os.path.basename(self.filepath)}")
        print(f"  Size:     {self.file_size:,} bytes")
        print(f"  Packages: {len(self.packages)}")

        total_files = sum(len(files) for _, files in self.packages)
        print(f"  Files:    {total_files}")

        if self.errors:
            print(f"\n  ERRORS ({len(self.errors)}):")
            for e in self.errors:
                print(f"    ✗ {e}")
        if self.warnings:
            print(f"\n  WARNINGS ({len(self.warnings)}):")
            for w in self.warnings:
                print(f"    ⚠ {w}")
        if not self.errors and not self.warnings:
            print(f"\n  ✓ All checks passed")

        return len(self.errors) == 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="HP BDL Firmware Bundle Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s firmware.bdl                              Parse and verify CRCs + signature
  %(prog)s firmware.bdl --verbose                    Show extra detail (hashes, etc.)
  %(prog)s firmware.bdl --no-sig                     Skip RSA signature verification
  %(prog)s firmware.bdl --extract ./out              Extract all files to ./out/
  %(prog)s firmware.bdl --decrypt --extract ./out              Auto-derive keys and extract
  %(prog)s firmware.bdl --decrypt --key <hex> --extract ./out  Decrypt with explicit key

Note: AES-256 keys are auto-derived from digests.txt using the TrustZone
Security_ComputeDeviceHash formula: SHA-256(platform_prefix || platform_uuid || digest_bytes).
Use --key to override with an explicit key for all encrypted files.
        """,
    )
    parser.add_argument("bdl_file", help="Path to the BDL firmware file")
    parser.add_argument("--extract", metavar="DIR", help="Extract files to directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-sig", action="store_true", help="Skip signature verification")
    parser.add_argument("--decrypt", action="store_true",
                        help="Decrypt .gtx1 payloads (auto-derives key from digests.txt, "
                             "or use --key to override)")
    parser.add_argument("--key", metavar="HEX",
                        help="AES-256 key as 64-char hex string (overrides auto-derivation)")

    args = parser.parse_args()

    # --decrypt without --key is allowed: keys are auto-derived from digests.txt
    # using the TrustZone Security_ComputeDeviceHash formula

    if args.key:
        args.key = args.key.strip()
        if len(args.key) != 64:
            parser.error(f"--key must be exactly 64 hex characters (256 bits), got {len(args.key)}")
        try:
            bytes.fromhex(args.key)
        except ValueError:
            parser.error("--key must be a valid hex string")

    if not os.path.isfile(args.bdl_file):
        print(f"Error: File not found: {args.bdl_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing: {args.bdl_file}")
    print(f"Size:    {os.path.getsize(args.bdl_file):,} bytes")
    print()

    bdl = BdlParser(args.bdl_file, verbose=args.verbose)

    try:
        bdl.parse()
    except Exception as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)

    ok = bdl.verify_all(
        skip_signature=args.no_sig,
        do_decrypt=args.decrypt,
        extract_dir=args.extract,
        aes_key_hex=args.key,
    )

    bdl.print_summary()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
