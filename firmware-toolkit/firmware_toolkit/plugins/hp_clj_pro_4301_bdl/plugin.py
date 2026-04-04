"""Firmware layer plugin for the HP CLJ Pro 4301-4303 BDL (Bundle) format.

The BDL format is the top-level firmware update container distributed by HP
for LaserJet printers.  It bundles one or more packages (LBI, rootfs, datafs,
eclipse), each of which contains one or more files (digests.txt, encrypted
firmware payloads such as .gtx1 AES-256-CBC blobs).

Structure
---------
+0x000  BdlHeader (2345 bytes)
          CommonHeader  800B   magic "ibdl", version, sizes, CRCs, strings
          type          4B     bundle type (e.g. 0x300)
          options       4B     bitmask
          pad0          1B     always 0
          description   256B   human-readable description
          identifier    256B   bundle identifier
          support_url   256B
          support_phone 256B
          support_email 256B
          serial_number 256B

+0x929  PackageTable (16 bytes × item_count)
          offset        8B     absolute byte offset to PakHeader
          size          8B     total package size

+pkg_offset  PakHeader (1085 bytes) per package
          CommonHeader  800B   magic "ipkg", version, sizes, CRCs, strings
          type_uuid     16B    package type UUID
          install_*     12B    options, phase, package_options
          pad0          1B
          description   256B

+pak+1085  FileTable (276 bytes × file_count)
          filename      256B   null-terminated
          file_offset   8B     relative to package start
          file_size     8B
          crc32         4B

All multi-byte integers are little-endian.  CRC-32 uses zlib.crc32.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import logging
import os
import struct
import zlib
from pathlib import Path
from typing import Any

from kaitaistruct import KaitaiStream

from firmware_toolkit.core.base_plugin import (
    ConversionInfo,
    FirmwarePlugin,
    PackResult,
    PluginInfo,
    PluginOption,
    UnpackResult,
    file_sha256,
)

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

BDL_MAGIC = b"ibdl"
PKG_MAGIC = b"ipkg"

BDL_HEADER_SIZE = 2345   # 0x929
PAK_HEADER_SIZE = 1085   # 0x43D
COMMON_HEADER_SIZE = 800
PKG_TABLE_ENTRY_SIZE = 16
FILE_TABLE_ENTRY_SIZE = 276

# Offsets within CommonHeader
OFF_HEADER_CRC = 12      # u4 at offset 0x0C
OFF_ITEM_TABLE_CRC = 20  # u4 at offset 0x14

# Variant identifiers
VARIANT_BUNDLE = "bdl_bundle"
VARIANT_EXTRACTED = "bdl_extracted"

MANIFEST_NAME = "bdl_manifest.json"

# Known package type UUIDs
PACKAGE_TYPE_UUIDS = {
    "9d33cb83bdf6e0408c4559e409579b58": "lbi",
    "9d33cb83bdf6e0408c4559e409579b59": "rootfs",
    "9d33cb83bdf6e0408c4559e409579b5a": "datafs",
    "f50ecc2526725c469f0a190aaaef9175": "eclipse",
}


# ── Helpers ──────────────────────────────────────────────────────────

def _crc32(data: bytes) -> int:
    """Compute CRC-32 matching zlib convention (unsigned)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def _verify_header_crc(header_bytes: bytearray, label: str) -> None:
    """Verify header CRC by zeroing the CRC field and recomputing."""
    stored_crc = struct.unpack_from("<I", header_bytes, OFF_HEADER_CRC)[0]
    check = bytearray(header_bytes)
    struct.pack_into("<I", check, OFF_HEADER_CRC, 0)
    computed = _crc32(bytes(check))
    if stored_crc != computed:
        raise ValueError(
            f"{label} header CRC mismatch: stored 0x{stored_crc:08X}, "
            f"computed 0x{computed:08X}"
        )
    logger.debug("%s header CRC OK (0x%08X)", label, stored_crc)


def _verify_table_crc(table_bytes: bytes, stored_crc: int, label: str) -> None:
    """Verify item table CRC."""
    computed = _crc32(table_bytes)
    if stored_crc != computed:
        raise ValueError(
            f"{label} table CRC mismatch: stored 0x{stored_crc:08X}, "
            f"computed 0x{computed:08X}"
        )
    logger.debug("%s table CRC OK (0x%08X)", label, stored_crc)


def _read_strz(data: bytes) -> str:
    """Read null-terminated ASCII string from fixed-width field."""
    idx = data.find(b"\x00")
    if idx >= 0:
        data = data[:idx]
    return data.decode("ASCII", errors="replace")


def _pack_strz(value: str, field_size: int) -> bytes:
    """Pack a string into a fixed-width null-terminated field."""
    encoded = value.encode("ASCII")
    if len(encoded) >= field_size:
        encoded = encoded[: field_size - 1]
    return encoded + b"\x00" * (field_size - len(encoded))


def _uuid_bytes_to_hex(data: bytes) -> str:
    """Convert 16-byte UUID to plain hex string."""
    return data.hex()


def _hex_to_uuid_bytes(hex_str: str) -> bytes:
    """Convert plain hex string to 16-byte UUID."""
    return bytes.fromhex(hex_str)


def _sha256(data: bytes) -> str:
    """SHA-256 hex digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


# ── Encryption / Decryption helpers ──────────────────────────────────

_KEYS_CONF = Path(__file__).with_name("keys.conf")

# Cached key material — populated lazily by _get_key_material().
_key_material: tuple[bytes, bytes] | None = None


def _get_key_material() -> tuple[bytes, bytes]:
    """Return (PLATFORM_PREFIX, PLATFORM_UUID), loading keys.conf on first call.

    Raises a clear error when the config file is missing or the values are
    empty, but only at the point where key material is actually needed
    (i.e. encryption / decryption), so that other BDL operations that do
    not require crypto keep working regardless.
    """
    global _key_material
    if _key_material is not None:
        return _key_material

    cfg_path = _KEYS_CONF
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Key configuration not found: {cfg_path}\n"
            "Encryption/decryption requires a keys.conf file next to the "
            "BDL plugin.\nSee keys.conf.example or supply your own."
        )

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path, encoding="utf-8")

    try:
        prefix = cfg.get("key_derivation", "platform_prefix")
        uuid = cfg.get("key_derivation", "platform_uuid")
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        raise ValueError(
            f"keys.conf is missing required key_derivation entries: {exc}\n"
            "Both 'platform_prefix' and 'platform_uuid' must be set in the "
            "[key_derivation] section."
        ) from exc

    if not prefix.strip():
        raise ValueError(
            "keys.conf: 'platform_prefix' in [key_derivation] is empty. "
            "A non-empty value is required for AES key derivation."
        )
    if not uuid.strip():
        raise ValueError(
            "keys.conf: 'platform_uuid' in [key_derivation] is empty. "
            "A non-empty value is required for AES key derivation."
        )

    _key_material = (prefix.encode(), uuid.encode())
    return _key_material


def _derive_aes_key(digest_hex: str) -> str:
    """Derive the AES-256 key for a .gtx1 file from its digests.txt hash.

    Replicates the TrustZone Security_ComputeDeviceHash function:
      AES_key = SHA-256(PLATFORM_PREFIX || PLATFORM_UUID || bytes.fromhex(digest_hex))

    Args:
        digest_hex: SHA-256 hex string from digests.txt for the encrypted file.
    Returns:
        Derived AES-256 key as a 64-character hex string.
    Raises:
        FileNotFoundError: If keys.conf is missing.
        ValueError: If key values are empty or malformed.
    """
    platform_prefix, platform_uuid = _get_key_material()
    h = hashlib.sha256()
    h.update(platform_prefix)
    h.update(platform_uuid[:36])
    h.update(bytes.fromhex(digest_hex))
    return h.hexdigest()


def _decrypt_gtx1(ciphertext_with_iv: bytes, hex_key: str) -> bytes:
    """Decrypt a .gtx1 AES-256-CBC payload.

    Format: 16-byte IV || AES-256-CBC ciphertext (PKCS#7 padded).
    Requires the ``cryptography`` package.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    key = bytes.fromhex(hex_key)
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _encrypt_gtx1(plaintext: bytes, hex_key: str) -> bytes:
    """Encrypt plaintext into .gtx1 AES-256-CBC format.

    Returns: 16-byte random IV || AES-256-CBC ciphertext (PKCS#7 padded).
    Requires the ``cryptography`` package.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    key = bytes.fromhex(hex_key)
    iv = os.urandom(16)

    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def _parse_digests_txt(data: bytes) -> dict[str, str]:
    """Parse a KVP digests.txt file into a dict of filename → SHA-256 hex.

    The values are SHA-256 hashes of the decrypted plaintext, used by the
    firmware's FileWriter::getHexDigest() for post-decryption integrity
    verification.  They also serve as input to the AES key derivation.
    """
    result: dict[str, str] = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _build_digests_txt(digests: dict[str, str]) -> bytes:
    """Serialize a filename → SHA-256 dict back into digests.txt format."""
    lines = [f"{k}={v}" for k, v in digests.items()]
    return ("\n".join(lines) + "\n").encode("ascii")


# ── Binary header builders ───────────────────────────────────────────

def _build_common_header(
    magic: bytes,
    version_major: int,
    version_minor: int,
    header_size: int,
    item_count: int,
    timestamp: int,
    version_string: str,
    vendor: str,
    name: str,
) -> bytearray:
    """Build an 800-byte CommonHeader (CRC fields zeroed for now)."""
    buf = bytearray(COMMON_HEADER_SIZE)
    struct.pack_into("<4s", buf, 0, magic)
    struct.pack_into("<H", buf, 4, version_major)
    struct.pack_into("<H", buf, 6, version_minor)
    struct.pack_into("<I", buf, 8, header_size)
    # header_crc at 12 — left as 0, filled later
    struct.pack_into("<I", buf, 16, item_count)
    # item_table_crc at 20 — left as 0, filled later
    struct.pack_into("<I", buf, 24, timestamp)
    struct.pack_into("<I", buf, 28, 0)  # reserved
    buf[32:32 + 256] = _pack_strz(version_string, 256)
    buf[288:288 + 256] = _pack_strz(vendor, 256)
    buf[544:544 + 256] = _pack_strz(name, 256)
    return buf


def _build_bdl_header(manifest: dict) -> bytearray:
    """Build the full 2345-byte BdlHeader from manifest data."""
    hdr = manifest["bdl_header"]
    common = _build_common_header(
        magic=BDL_MAGIC,
        version_major=hdr["version_major"],
        version_minor=hdr["version_minor"],
        header_size=BDL_HEADER_SIZE,
        item_count=len(manifest["packages"]),
        timestamp=hdr["timestamp"],
        version_string=hdr["version_string"],
        vendor=hdr["vendor"],
        name=hdr["name"],
    )
    buf = bytearray(BDL_HEADER_SIZE)
    buf[:COMMON_HEADER_SIZE] = common
    offset = COMMON_HEADER_SIZE
    struct.pack_into("<I", buf, offset, hdr["type"]); offset += 4
    struct.pack_into("<I", buf, offset, hdr["options"]); offset += 4
    buf[offset] = 0; offset += 1  # pad0
    buf[offset:offset + 256] = _pack_strz(hdr.get("description", ""), 256); offset += 256
    buf[offset:offset + 256] = _pack_strz(hdr.get("identifier", ""), 256); offset += 256
    buf[offset:offset + 256] = _pack_strz(hdr.get("support_url", ""), 256); offset += 256
    buf[offset:offset + 256] = _pack_strz(hdr.get("support_phone", ""), 256); offset += 256
    buf[offset:offset + 256] = _pack_strz(hdr.get("support_email", ""), 256); offset += 256
    buf[offset:offset + 256] = _pack_strz(hdr.get("serial_number", ""), 256); offset += 256
    assert offset == BDL_HEADER_SIZE, f"BDL header size mismatch: {offset}"
    return buf


def _build_pak_header(pkg_manifest: dict, file_count: int) -> bytearray:
    """Build a 1085-byte PakHeader from package manifest data."""
    ph = pkg_manifest["pak_header"]
    common = _build_common_header(
        magic=PKG_MAGIC,
        version_major=ph["version_major"],
        version_minor=ph["version_minor"],
        header_size=PAK_HEADER_SIZE,
        item_count=file_count,
        timestamp=ph["timestamp"],
        version_string=ph["version_string"],
        vendor=ph["vendor"],
        name=ph.get("name", pkg_manifest["name"]),
    )
    buf = bytearray(PAK_HEADER_SIZE)
    buf[:COMMON_HEADER_SIZE] = common
    offset = COMMON_HEADER_SIZE
    buf[offset:offset + 16] = _hex_to_uuid_bytes(ph["type_uuid"]); offset += 16
    struct.pack_into("<I", buf, offset, ph["install_options"]); offset += 4
    struct.pack_into("<I", buf, offset, ph["install_phase"]); offset += 4
    struct.pack_into("<I", buf, offset, ph["package_options"]); offset += 4
    buf[offset] = 0; offset += 1  # pad0
    buf[offset:offset + 256] = _pack_strz(ph.get("description", ""), 256); offset += 256
    assert offset == PAK_HEADER_SIZE, f"PAK header size mismatch: {offset}"
    return buf


def _set_header_crc(header_buf: bytearray) -> None:
    """Compute and store header_crc in-place (zero the field, CRC, write back)."""
    struct.pack_into("<I", header_buf, OFF_HEADER_CRC, 0)
    crc = _crc32(bytes(header_buf))
    struct.pack_into("<I", header_buf, OFF_HEADER_CRC, crc)


def _set_item_table_crc(header_buf: bytearray, table_bytes: bytes) -> None:
    """Compute and store item_table_crc in the header."""
    crc = _crc32(table_bytes)
    struct.pack_into("<I", header_buf, OFF_ITEM_TABLE_CRC, crc)


# ── Plugin class ─────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """HP CLJ Pro 4301-4303 BDL (Bundle) firmware container plugin."""

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="HP CLJ Pro 4301 BDL",
            description="HP Color LaserJet Pro 4301-4303 BDL firmware bundle container",
            version="1.0.0",
            format_id="hp_clj_pro_4301_bdl",
            supported_variants=[VARIANT_BUNDLE, VARIANT_EXTRACTED],
            conversions=self.get_conversions(),
            ksy_files=["hp_clj_pro_4301_bdl.ksy"],
        )

    def get_options(self) -> list[PluginOption]:
        return [
            PluginOption(
                flag="--decrypt",
                description=(
                    "Decrypt .gtx1 AES-256-CBC payloads during unpack "
                    "(derives keys from digests.txt via TrustZone formula). "
                    "During pack, re-encrypt decrypted files back to .gtx1."
                ),
                kwarg_name="decrypt",
                kwarg_value=True,
                default=False,
                applies_to="both",
            ),
            PluginOption(
                flag="--key",
                description=(
                    "Explicit AES-256 key (64 hex chars) to use instead of "
                    "auto-derivation from digests.txt. Applies to all .gtx1 files."
                ),
                kwarg_name="aes_key",
                default=None,
                applies_to="both",
                takes_value=True,
                metavar="HEX_KEY",
            ),
        ]

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_BUNDLE,
                target_variant=VARIANT_EXTRACTED,
                description="Extract BDL bundle into packages and files",
            ),
            ConversionInfo(
                source_variant=VARIANT_EXTRACTED,
                target_variant=VARIANT_BUNDLE,
                description="Repack extracted packages and files into BDL bundle",
            ),
        ]

    # ── Identification ────────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_file():
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                if magic == BDL_MAGIC:
                    return VARIANT_BUNDLE
            except OSError:
                pass
        elif path.is_dir():
            if (path / MANIFEST_NAME).exists():
                return VARIANT_EXTRACTED
        return None

    # ── Unpack ────────────────────────────────────────────────────────

    def unpack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> UnpackResult:
        if source_variant is None:
            source_variant = self.identify(input_path)
        if source_variant != VARIANT_BUNDLE:
            raise ValueError(f"Cannot unpack variant '{source_variant}', expected '{VARIANT_BUNDLE}'")

        do_decrypt: bool = kwargs.get("decrypt", False)
        aes_key: str | None = kwargs.get("aes_key")
        if aes_key and len(aes_key) != 64:
            raise ValueError(f"AES key must be 64 hex characters, got {len(aes_key)}")

        source_hash = file_sha256(input_path)

        with open(input_path, "rb") as f:
            raw = f.read()

        # ── Parse BDL Header ──
        bdl_hdr_bytes = bytearray(raw[:BDL_HEADER_SIZE])
        _verify_header_crc(bdl_hdr_bytes, "BDL")

        common = self._parse_common_header(raw, 0)
        item_count = common["item_count"]
        logger.info("BDL: %d packages, version %s", item_count, common["version_string"])

        # BDL-specific fields after CommonHeader
        off = COMMON_HEADER_SIZE
        bdl_type = struct.unpack_from("<I", raw, off)[0]; off += 4
        bdl_options = struct.unpack_from("<I", raw, off)[0]; off += 4
        off += 1  # pad0
        bdl_description = _read_strz(raw[off:off + 256]); off += 256
        bdl_identifier = _read_strz(raw[off:off + 256]); off += 256
        bdl_support_url = _read_strz(raw[off:off + 256]); off += 256
        bdl_support_phone = _read_strz(raw[off:off + 256]); off += 256
        bdl_support_email = _read_strz(raw[off:off + 256]); off += 256
        bdl_serial_number = _read_strz(raw[off:off + 256]); off += 256

        # ── Parse Package Table ──
        pkg_table_start = BDL_HEADER_SIZE
        pkg_table_bytes = raw[pkg_table_start:pkg_table_start + item_count * PKG_TABLE_ENTRY_SIZE]
        _verify_table_crc(pkg_table_bytes, common["item_table_crc"], "BDL package table")

        pkg_entries = []
        for i in range(item_count):
            base = pkg_table_start + i * PKG_TABLE_ENTRY_SIZE
            pkg_offset, pkg_size = struct.unpack_from("<QQ", raw, base)
            pkg_entries.append((pkg_offset, pkg_size))
            logger.debug("Package %d: offset=0x%X, size=%d", i, pkg_offset, pkg_size)

        # ── Detect trailing data (e.g. HP signature fingerprint) ──
        bdl_data_end = 0
        for pkg_offset, pkg_size in pkg_entries:
            end = pkg_offset + pkg_size
            if end > bdl_data_end:
                bdl_data_end = end
        trailing_data = raw[bdl_data_end:] if bdl_data_end < len(raw) else b""
        if trailing_data:
            logger.info("BDL has %d bytes of trailing data (e.g. HP signature)", len(trailing_data))

        # ── Extract packages ──
        output_path.mkdir(parents=True, exist_ok=True)
        packages_manifest = []

        for pkg_idx, (pkg_offset, pkg_size) in enumerate(pkg_entries):
            # Parse PakHeader
            pak_hdr_bytes = bytearray(raw[pkg_offset:pkg_offset + PAK_HEADER_SIZE])
            _verify_header_crc(pak_hdr_bytes, f"Package {pkg_idx}")

            pak_common = self._parse_common_header(raw, pkg_offset)
            file_count = pak_common["item_count"]

            # Package-specific fields
            poff = pkg_offset + COMMON_HEADER_SIZE
            type_uuid = raw[poff:poff + 16]; poff += 16
            install_options = struct.unpack_from("<I", raw, poff)[0]; poff += 4
            install_phase = struct.unpack_from("<I", raw, poff)[0]; poff += 4
            package_options = struct.unpack_from("<I", raw, poff)[0]; poff += 4
            poff += 1  # pad0
            pak_description = _read_strz(raw[poff:poff + 256]); poff += 256

            uuid_hex = _uuid_bytes_to_hex(type_uuid)
            pkg_name = PACKAGE_TYPE_UUIDS.get(uuid_hex, pak_common["name"])
            logger.info(
                "Package %d: '%s' (%s), %d files",
                pkg_idx, pkg_name, uuid_hex, file_count,
            )

            # Parse FileTable
            ft_start = pkg_offset + PAK_HEADER_SIZE
            ft_bytes = raw[ft_start:ft_start + file_count * FILE_TABLE_ENTRY_SIZE]
            _verify_table_crc(ft_bytes, pak_common["item_table_crc"], f"Package {pkg_idx} file table")

            # Create package directory
            pkg_dir = output_path / pkg_name
            pkg_dir.mkdir(parents=True, exist_ok=True)

            # First pass: read all file entries and data, verify CRCs
            file_entries: list[tuple[str, int, int, int, bytes]] = []  # (name, offset, size, crc, data)
            for fi in range(file_count):
                fbase = ft_start + fi * FILE_TABLE_ENTRY_SIZE
                filename = _read_strz(raw[fbase:fbase + 256])
                file_offset = struct.unpack_from("<Q", raw, fbase + 256)[0]
                file_size = struct.unpack_from("<Q", raw, fbase + 264)[0]
                file_crc = struct.unpack_from("<I", raw, fbase + 272)[0]

                abs_offset = pkg_offset + file_offset
                file_data = raw[abs_offset:abs_offset + file_size]

                computed_crc = _crc32(file_data)
                if file_crc != computed_crc:
                    raise ValueError(
                        f"File CRC mismatch for '{filename}' in package '{pkg_name}': "
                        f"stored 0x{file_crc:08X}, computed 0x{computed_crc:08X}"
                    )
                logger.debug(
                    "  File '%s': offset=0x%X, size=%d, CRC OK",
                    filename, file_offset, file_size,
                )
                file_entries.append((filename, file_offset, file_size, file_crc, file_data))

            # Parse digests.txt if present (needed for key derivation)
            digests: dict[str, str] = {}
            if do_decrypt:
                for fname, _, _, _, fdata in file_entries:
                    if fname == "digests.txt":
                        digests = _parse_digests_txt(fdata)
                        logger.debug("  digests.txt entries: %s", list(digests.keys()))
                        break

            # Second pass: write files (with optional decryption)
            files_manifest = []
            for filename, file_offset, file_size, file_crc, file_data in file_entries:
                is_encrypted = filename.endswith(".gtx1")
                decrypted = False
                write_data = file_data
                write_name = filename

                if do_decrypt and is_encrypted:
                    # Determine key: explicit --key overrides auto-derivation
                    use_key = aes_key
                    if not use_key:
                        expected_hash = digests.get(filename)
                        if expected_hash:
                            use_key = _derive_aes_key(expected_hash)
                        else:
                            logger.warning(
                                "  No digest for '%s' — cannot derive key, "
                                "extracting raw .gtx1",
                                filename,
                            )
                    if use_key:
                        plaintext = _decrypt_gtx1(file_data, use_key)
                        # Verify SHA-256 against digests.txt
                        expected_hash = digests.get(filename)
                        if expected_hash:
                            actual_hash = _sha256(plaintext)
                            if actual_hash != expected_hash:
                                raise ValueError(
                                    f"SHA-256 mismatch after decrypting '{filename}': "
                                    f"expected {expected_hash}, got {actual_hash}"
                                )
                            logger.debug("  '%s' decrypted, SHA-256 verified", filename)
                        write_data = plaintext
                        write_name = filename[:-5]  # strip .gtx1
                        decrypted = True
                        logger.info(
                            "  Decrypted '%s' → '%s' (%d bytes)",
                            filename, write_name, len(plaintext),
                        )

                out_file = pkg_dir / write_name
                out_file.write_bytes(write_data)

                entry: dict[str, Any] = {
                    "filename": write_name,
                    "size": len(write_data),
                    "crc32": f"{file_crc:08x}",
                    "sha256": _sha256(write_data),
                    "file_offset": file_offset,
                }
                if decrypted:
                    entry["decrypted_from"] = filename
                    expected = digests.get(filename)
                    if expected:
                        entry["plaintext_digest"] = expected
                files_manifest.append(entry)

            packages_manifest.append({
                "name": pkg_name,
                "pak_header": {
                    "version_major": pak_common["version_major"],
                    "version_minor": pak_common["version_minor"],
                    "timestamp": pak_common["timestamp"],
                    "version_string": pak_common["version_string"],
                    "vendor": pak_common["vendor"],
                    "name": pak_common["name"],
                    "type_uuid": uuid_hex,
                    "install_options": install_options,
                    "install_phase": install_phase,
                    "package_options": package_options,
                    "description": pak_description,
                },
                "files": files_manifest,
            })

        # ── Write manifest ──
        manifest = {
            "format": "hp_clj_pro_4301_bdl",
            "bdl_header": {
                "version_major": common["version_major"],
                "version_minor": common["version_minor"],
                "timestamp": common["timestamp"],
                "version_string": common["version_string"],
                "vendor": common["vendor"],
                "name": common["name"],
                "type": bdl_type,
                "options": bdl_options,
                "description": bdl_description,
                "identifier": bdl_identifier,
                "support_url": bdl_support_url,
                "support_phone": bdl_support_phone,
                "support_email": bdl_support_email,
                "serial_number": bdl_serial_number,
            },
            "packages": packages_manifest,
        }

        # Save trailing data (HP signature) if present
        if trailing_data:
            trailing_file = output_path / "trailing_signature.bin"
            trailing_file.write_bytes(trailing_data)
            manifest["trailing_data"] = {
                "filename": "trailing_signature.bin",
                "size": len(trailing_data),
                "sha256": _sha256(trailing_data),
            }

        manifest_path = output_path / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

        output_hash = file_sha256(manifest_path)
        return UnpackResult(
            output_path=output_path,
            source_variant=VARIANT_BUNDLE,
            target_variant=VARIANT_EXTRACTED,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "packages": len(packages_manifest),
                "total_files": sum(len(p["files"]) for p in packages_manifest),
            },
        )

    # ── Pack ──────────────────────────────────────────────────────────

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        if source_variant is None:
            source_variant = self.identify(input_path)
        if source_variant != VARIANT_EXTRACTED:
            raise ValueError(f"Cannot pack variant '{source_variant}', expected '{VARIANT_EXTRACTED}'")

        do_decrypt: bool = kwargs.get("decrypt", False)
        aes_key: str | None = kwargs.get("aes_key")
        if aes_key and len(aes_key) != 64:
            raise ValueError(f"AES key must be 64 hex characters, got {len(aes_key)}")

        source_hash = file_sha256(input_path / MANIFEST_NAME)

        manifest_path = input_path / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text())

        num_packages = len(manifest["packages"])

        # ── Build each package's binary blob ──
        # Each package = PakHeader + FileTable + file_data...
        package_blobs: list[bytes] = []

        for pkg in manifest["packages"]:
            pkg_name = pkg["name"]
            files = pkg["files"]

            # Read all file data, re-encrypting decrypted files if --decrypt
            pack_files: list[tuple[str, bytes]] = []  # (filename_for_table, data)
            new_digests: dict[str, str] | None = None

            for finfo in files:
                fpath = input_path / pkg_name / finfo["filename"]
                raw_data = fpath.read_bytes()
                enc_filename = finfo.get("decrypted_from")

                if enc_filename and do_decrypt:
                    # This file was decrypted during unpack — re-encrypt it
                    plaintext = raw_data
                    plaintext_hash = _sha256(plaintext)

                    use_key = aes_key
                    if not use_key:
                        digest_hex = finfo.get("plaintext_digest", plaintext_hash)
                        use_key = _derive_aes_key(digest_hex)

                    encrypted = _encrypt_gtx1(plaintext, use_key)
                    logger.info(
                        "  Encrypted '%s' → '%s' (%d bytes)",
                        finfo["filename"], enc_filename, len(encrypted),
                    )
                    pack_files.append((enc_filename, encrypted))

                    # Update digests for re-serialization
                    if new_digests is None:
                        new_digests = {}
                    new_digests[enc_filename] = plaintext_hash
                elif finfo["filename"] == "digests.txt" and new_digests is not None:
                    # Defer — will be rebuilt after processing all files
                    pack_files.append(("digests.txt", b"__PLACEHOLDER__"))
                else:
                    pack_files.append((finfo["filename"], raw_data))

            # Rebuild digests.txt if we re-encrypted any files
            if new_digests is not None:
                # Merge: start from existing digests.txt content on disk, overlay
                digests_path = input_path / pkg_name / "digests.txt"
                existing_digests: dict[str, str] = {}
                if digests_path.exists():
                    existing_digests = _parse_digests_txt(digests_path.read_bytes())
                existing_digests.update(new_digests)
                digests_data = _build_digests_txt(existing_digests)
                # Replace placeholder (or append if digests.txt wasn't in original)
                replaced = False
                for i, (fn, _) in enumerate(pack_files):
                    if fn == "digests.txt":
                        pack_files[i] = ("digests.txt", digests_data)
                        replaced = True
                        break
                if not replaced:
                    pack_files.insert(0, ("digests.txt", digests_data))

            file_count = len(pack_files)

            # Compute file offsets (relative to package start = PakHeader position)
            # Layout: PakHeader (1085) + FileTable (276 × N) + file data...
            data_start = PAK_HEADER_SIZE + file_count * FILE_TABLE_ENTRY_SIZE

            file_data_list: list[bytes] = [d for _, d in pack_files]
            file_entries: list[tuple[int, int, int]] = []  # (offset, size, crc)
            current_offset = data_start
            for fdata in file_data_list:
                fsize = len(fdata)
                fcrc = _crc32(fdata)
                file_entries.append((current_offset, fsize, fcrc))
                current_offset += fsize

            # Build FileTable
            ft_buf = bytearray(file_count * FILE_TABLE_ENTRY_SIZE)
            for fi, (fn, _) in enumerate(pack_files):
                fbase = fi * FILE_TABLE_ENTRY_SIZE
                ft_buf[fbase:fbase + 256] = _pack_strz(fn, 256)
                fo, fs, fc = file_entries[fi]
                struct.pack_into("<Q", ft_buf, fbase + 256, fo)
                struct.pack_into("<Q", ft_buf, fbase + 264, fs)
                struct.pack_into("<I", ft_buf, fbase + 272, fc)

            # Build PakHeader
            pak_buf = _build_pak_header(pkg, file_count)
            _set_item_table_crc(pak_buf, bytes(ft_buf))
            _set_header_crc(pak_buf)

            # Assemble package blob
            blob = bytes(pak_buf) + bytes(ft_buf)
            for fdata in file_data_list:
                blob += fdata

            package_blobs.append(blob)

        # ── Build PackageTable ──
        # Compute absolute offsets: BDL header + package table + accumulated package sizes
        pkg_table_size = num_packages * PKG_TABLE_ENTRY_SIZE
        first_pkg_offset = BDL_HEADER_SIZE + pkg_table_size

        pkg_table_buf = bytearray(pkg_table_size)
        current_pkg_offset = first_pkg_offset
        for i, blob in enumerate(package_blobs):
            struct.pack_into("<Q", pkg_table_buf, i * PKG_TABLE_ENTRY_SIZE, current_pkg_offset)
            struct.pack_into("<Q", pkg_table_buf, i * PKG_TABLE_ENTRY_SIZE + 8, len(blob))
            current_pkg_offset += len(blob)

        # ── Build BDL Header ──
        bdl_buf = _build_bdl_header(manifest)
        _set_item_table_crc(bdl_buf, bytes(pkg_table_buf))
        _set_header_crc(bdl_buf)

        # ── Write output ──
        with open(output_path, "wb") as f:
            f.write(bytes(bdl_buf))
            f.write(bytes(pkg_table_buf))
            for blob in package_blobs:
                f.write(blob)

            # Append trailing data (HP signature) if present
            trailing_info = manifest.get("trailing_data")
            if trailing_info:
                trailing_file = input_path / trailing_info["filename"]
                if trailing_file.exists():
                    f.write(trailing_file.read_bytes())
                    logger.info("Appended %d bytes of trailing data", trailing_info["size"])

        output_hash = file_sha256(output_path)
        return PackResult(
            output_path=output_path,
            source_variant=VARIANT_EXTRACTED,
            target_variant=VARIANT_BUNDLE,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "packages": num_packages,
                "total_files": sum(len(p["files"]) for p in manifest["packages"]),
                "output_size": output_path.stat().st_size,
            },
        )

    # ── Parse (Kaitai) ────────────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        if variant is None:
            variant = self.identify(path)
        if variant != VARIANT_BUNDLE:
            raise ValueError(
                f"Kaitai parsing requires variant '{VARIANT_BUNDLE}', got '{variant}'"
            )
        from .kaitai import HpCljPro4301Bdl as Parser

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))

    # ── Internal helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_common_header(raw: bytes, offset: int) -> dict:
        """Parse the 800-byte CommonHeader at *offset* into a dict."""
        magic = raw[offset:offset + 4]
        version_major = struct.unpack_from("<H", raw, offset + 4)[0]
        version_minor = struct.unpack_from("<H", raw, offset + 6)[0]
        header_size = struct.unpack_from("<I", raw, offset + 8)[0]
        header_crc = struct.unpack_from("<I", raw, offset + 12)[0]
        item_count = struct.unpack_from("<I", raw, offset + 16)[0]
        item_table_crc = struct.unpack_from("<I", raw, offset + 20)[0]
        timestamp = struct.unpack_from("<I", raw, offset + 24)[0]
        reserved = struct.unpack_from("<I", raw, offset + 28)[0]
        version_string = _read_strz(raw[offset + 32:offset + 288])
        vendor = _read_strz(raw[offset + 288:offset + 544])
        name = _read_strz(raw[offset + 544:offset + 800])
        return {
            "magic": magic,
            "version_major": version_major,
            "version_minor": version_minor,
            "header_size": header_size,
            "header_crc": header_crc,
            "item_count": item_count,
            "item_table_crc": item_table_crc,
            "timestamp": timestamp,
            "reserved": reserved,
            "version_string": version_string,
            "vendor": vendor,
            "name": name,
        }
