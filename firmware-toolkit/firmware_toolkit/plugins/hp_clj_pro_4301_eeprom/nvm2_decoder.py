"""NVM2 object decoder for the M24256BW EEPROM plugin.

This module is purely analytical - it does not modify the EEPROM.
It walks the TLV-encoded object region of an NVM2 image, resolves
object IDs to their ASCII names (using the table extracted from
libNvram.so), and - when a DUID or chip ID is supplied - performs the
Layer-1 XOR decryption that HP firmware applies on read.

Cryptographic primitives (sourced from python_scripts/decrypt_pin.py,
which in turn came from libNvram.so 0x3acfc / 0x3b860):

    DUID           = SHA-256(chipid[16] || CRC32_BE(chipid)[4])           (32 B)
    vendor_uuid    = VENDOR_UUIDS[(obj_id >> 16) & 0xFF]  (36-char dashed)
    K[i]           = SHA-256(vendor_uuid || varname)[i] XOR DUID[i]       (32 B)
    plaintext[i]   = ciphertext[i] XOR K[i % 32]

The vendor-UUID table was recovered from the dispatch table at
libNvram.so 0x68b2c and cross-checked against libframework.so _INIT_24.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Per-tag vendor UUIDs (lowercase dashed 36-char form).
# The tag is the HIGH byte of a 24-bit object ID. Mapping recovered
# from libNvram.so 0x68b2c.
VENDOR_UUIDS: dict[int, str] = {
    0x01: "4e565241-4d5f-5355-4944-5f5641525300",  # HP_DUNE_NUMERIC / NVRAM_SUID_VARS\0 (16 bytes, trailing NUL pad)
    0x02: "48505f44-554e-455f-5345-5454494e4753",  # HP_DUNE_SETTINGS
    0x03: "845e3285-c67c-4f4b-9aa4-0ae91bd35089",  # BIOS_SETTINGS
    0x04: "0429e79e-d9ba-412e-a2bc-1f3d245041ce",  # DEVICE_CONFIG
    0x05: "1429e79e-d9ba-412e-a2bc-1f3d245041ce",  # DEVICE_INFO
    0x0a: "4e565241-4d5f-4c4f-4341-4c5f54455354",  # NVRAM_LOCAL_TEST
    0x7f: "4e4f535f-4545-5052-4f4d-5f4e5652414d",  # NOS_EEPROM_NVRAM (plaintext path)
}

# Defaults for this plugin.
DEFAULT_EEPROM_SIZE = 32768
DEFAULT_NVM2_OFFSET = 0x0200  # where the NVM2 header (magic byte) lives.
DEFAULT_TLV_SCAN_MAX_DATA_SIZE = 10000  # sanity cap

# Root-page pointer: 2 bytes at EEPROM 0x01FE-0x01FF, big-endian.
# Written by the kernel's NVM2 driver (``_write_root_page`` at
# 0xb0498754 on this build) and physically precedes the NVM2 header.
# 0xFFFF on both reference dumps (kernel never committed a root page).
ROOT_PAGE_POINTER_OFFSET = 0x01FE
ROOT_PAGE_POINTER_SIZE = 2

# NVM2 header offsets (duplicated from plugin.py so this module stays
# importable standalone for testing).
_HDR_MAGIC = 0x00
_HDR_VERSION_INFO = 0x04
_HDR_OBJECT_COUNT = 0x08
_HDR_MAX_OBJECTS = 0x0A
_HDR_ALLOC_BITMAP = 0x0C
_HDR_SPAN_BITMAP = 0x0E
_HDR_DEBUG_LEVEL = 0x10
_HDR_GENERATION = 0x11
_HEADER_SIZE = 0x13


def parse_root_page_pointer(eeprom_data: bytes) -> int:
    """Return the NVM2 root-page pointer (uint16 BE at 0x01FE) from an EEPROM image."""
    if len(eeprom_data) < ROOT_PAGE_POINTER_OFFSET + ROOT_PAGE_POINTER_SIZE:
        raise ValueError(
            f"EEPROM too short: {len(eeprom_data)} bytes (need >= "
            f"{ROOT_PAGE_POINTER_OFFSET + ROOT_PAGE_POINTER_SIZE})"
        )
    (value,) = struct.unpack_from(">H", eeprom_data, ROOT_PAGE_POINTER_OFFSET)
    return value


def encode_root_page_pointer(value: int) -> bytes:
    """Encode the 2-byte big-endian root-page pointer value."""
    if not isinstance(value, int):
        raise TypeError(
            f"root page pointer must be int, got {type(value).__name__}"
        )
    if not 0 <= value <= 0xFFFF:
        raise ValueError(
            f"root page pointer out of range [0, 0xFFFF]: 0x{value:X}"
        )
    return value.to_bytes(2, "big")


# ---------------------------------------------------------------------
# Name-ID table
# ---------------------------------------------------------------------

_NAME_ID_TABLE_PATH = Path(__file__).parent / "data" / "nvm_name_id_table.json"
_NAME_ID_CACHE: dict[int, str] | None = None


def load_name_id_table() -> dict[int, str]:
    """Load (and cache) the NVM object name-ID table.

    The table is shipped as data/nvm_name_id_table.json next to this
    module and was extracted from the string table embedded in
    libNvram.so (0x5fe4c..0x67964, 3939 entries).
    """
    global _NAME_ID_CACHE
    if _NAME_ID_CACHE is not None:
        return _NAME_ID_CACHE
    raw = json.loads(_NAME_ID_TABLE_PATH.read_text())
    names = raw["names"] if isinstance(raw, dict) and "names" in raw else raw
    _NAME_ID_CACHE = {int(k, 16): v for k, v in names.items()}
    return _NAME_ID_CACHE


def resolve_name(obj_id: int) -> str | None:
    """Resolve a 24-bit NVM object ID to its ASCII name.

    The lookup ignores the high tag byte - HP's libNvram.so keys
    variables only by the low 16 bits of the OID within a namespace,
    and every name in the inventory shares the same low-16-bit key
    space across tag classes. Returns None if unknown.
    """
    table = load_name_id_table()
    return table.get(obj_id & 0xFFFF)


# ---------------------------------------------------------------------
# DUID derivation
# ---------------------------------------------------------------------

def duid_from_chipid(chipid: bytes) -> bytes:
    """Derive the 32-byte DUID from a 16-byte chip ID.

    Algorithm (from bootloader FUN_9ff2069a):

        crc = CRC32_IEEE(chipid)              (4 bytes, big-endian)
        duid = SHA-256(chipid || crc)         (32 bytes)
    """
    if len(chipid) != 16:
        raise ValueError(f"chipid must be 16 bytes, got {len(chipid)}")
    crc_be = struct.pack(">I", binascii.crc32(chipid) & 0xFFFFFFFF)
    return hashlib.sha256(chipid + crc_be).digest()


def parse_hex_arg(value: str, expected_bytes: int, label: str) -> bytes:
    """Parse a hex string CLI argument into bytes with a length check."""
    cleaned = (
        value.strip().lower().replace("0x", "").replace(":", "").replace("-", "")
    )
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"{label}: not valid hex ({e})") from e
    if len(raw) != expected_bytes:
        raise ValueError(
            f"{label}: expected {expected_bytes} bytes "
            f"({expected_bytes * 2} hex chars), got {len(raw)}"
        )
    return raw


# ---------------------------------------------------------------------
# Layer-1 XOR
# ---------------------------------------------------------------------

def layer1_keystream(obj_id: int, varname: str, duid: bytes) -> bytes:
    """Compute the 32-byte Layer-1 keystream stripe for an object.

    plaintext[i] = ciphertext[i] XOR K[i % 32] where
    K[i] = SHA-256(uuid_str || varname)[i] XOR DUID[i].
    """
    tag = (obj_id >> 16) & 0xFF
    uuid_str = VENDOR_UUIDS.get(tag, "")
    sha = hashlib.sha256((uuid_str + varname).encode("ascii")).digest()
    if len(duid) != 32:
        raise ValueError(f"DUID must be 32 bytes, got {len(duid)}")
    return bytes(s ^ d for s, d in zip(sha, duid))


def layer1_decrypt(
    ciphertext: bytes, obj_id: int, varname: str, duid: bytes
) -> bytes:
    """Reverse the Layer-1 XOR for a single object."""
    ks = layer1_keystream(obj_id, varname, duid)
    return bytes(c ^ ks[i % 32] for i, c in enumerate(ciphertext))


# ---------------------------------------------------------------------
# NVM2 header
# ---------------------------------------------------------------------

@dataclass
class Nvm2Header:
    magic: int
    version: int
    key_id: int
    object_count: int
    max_objects: int
    alloc_bitmap_offset: int   # absolute EEPROM offset
    span_bitmap_offset: int    # absolute EEPROM offset
    debug_level: int
    generation: int

    @property
    def bitmap_size(self) -> int:
        """Inferred bitmap size in bytes.

        NVM2 pads each bitmap to a full page. In practice the two
        bitmaps are laid out back-to-back, so the most reliable
        measurement is the distance between span_bitmap_offset and
        alloc_bitmap_offset. We fall back to ceil(max_objects / 8)
        rounded up to 8 bytes if the two bitmaps aren't adjacent
        (defensive - not observed on any dump examined so far).
        """
        gap = abs(self.alloc_bitmap_offset - self.span_bitmap_offset)
        if gap > 0:
            return gap
        min_bits = (self.max_objects + 7) // 8
        return (min_bits + 7) & ~7  # round up to 8-byte boundary


def parse_nvm2_header(nvm2_data: bytes) -> Nvm2Header:
    """Parse the 19-byte NVM2 header from the NVM2 region bytes."""
    if len(nvm2_data) < _HEADER_SIZE:
        raise ValueError(
            f"NVM2 region too short: {len(nvm2_data)} bytes "
            f"(need >= {_HEADER_SIZE})"
        )
    (magic,) = struct.unpack_from("<I", nvm2_data, _HDR_MAGIC)
    (version_info,) = struct.unpack_from("<I", nvm2_data, _HDR_VERSION_INFO)
    (object_count,) = struct.unpack_from("<H", nvm2_data, _HDR_OBJECT_COUNT)
    (max_objects,) = struct.unpack_from("<H", nvm2_data, _HDR_MAX_OBJECTS)
    (alloc_off,) = struct.unpack_from("<H", nvm2_data, _HDR_ALLOC_BITMAP)
    (span_off,) = struct.unpack_from("<H", nvm2_data, _HDR_SPAN_BITMAP)
    debug_level = nvm2_data[_HDR_DEBUG_LEVEL]
    (generation,) = struct.unpack_from("<H", nvm2_data, _HDR_GENERATION)

    return Nvm2Header(
        magic=magic,
        version=version_info & 0xFFFF,
        key_id=(version_info >> 16) & 0xFFFF,
        object_count=object_count,
        max_objects=max_objects,
        alloc_bitmap_offset=alloc_off,
        span_bitmap_offset=span_off,
        debug_level=debug_level,
        generation=generation,
    )


def tlv_start_offset(hdr: Nvm2Header) -> int:
    """Return the absolute EEPROM offset where TLV records begin.

    TLVs start immediately after the later of the two bitmaps. Each
    bitmap is ceil(max_objects / 8) bytes long, padded to a page.
    """
    bsize = hdr.bitmap_size
    return max(
        hdr.alloc_bitmap_offset + bsize,
        hdr.span_bitmap_offset + bsize,
    )


# ---------------------------------------------------------------------
# TLV walk
# ---------------------------------------------------------------------

@dataclass
class Nvm2Record:
    """One TLV record decoded from the NVM2 object region.

    Offsets are absolute (within the 32 KB EEPROM image).
    """
    offset: int                 # abs EEPROM offset of the record start
    obj_id: int                 # 24-bit object ID (high byte = vendor tag)
    tag: int                    # vendor tag = (obj_id >> 16) & 0xFF
    header_size: int            # 3, 4 or 5
    data_size: int              # payload length (bytes)
    cipher: bytes               # encrypted payload as stored in EEPROM
    name: str | None = None     # resolved from name-ID table
    vendor_uuid: str | None = None  # vendor UUID string for the tag
    # Populated only when a DUID is supplied to walk():
    plaintext: bytes | None = None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "offset": f"0x{self.offset:04X}",
            "obj_id": f"0x{self.obj_id:06X}",
            "tag": f"0x{self.tag:02X}",
            "name": self.name,
            "vendor_uuid": self.vendor_uuid,
            "header_size": self.header_size,
            "data_size": self.data_size,
            "cipher_hex": self.cipher.hex(),
        }
        if self.plaintext is not None:
            d["plaintext_hex"] = self.plaintext.hex()
            stripped = self.plaintext.rstrip(b"\x00")
            try:
                ascii_preview = stripped.decode("utf-8")
                if all(
                    32 <= ord(c) < 127 or c in ("\n", "\r", "\t")
                    for c in ascii_preview
                ):
                    d["ascii_preview"] = ascii_preview
            except UnicodeDecodeError:
                pass
        return d


def _decode_tlv_header(buf: bytes, pos: int) -> tuple[int, int, int] | None:
    """Decode a TLV header at buf[pos:].

    Returns (obj_id, header_size, data_size) or None if the bytes
    don't form a plausible header.
    """
    if pos + 3 > len(buf):
        return None
    b0 = buf[pos]
    b1 = buf[pos + 1]
    b2 = buf[pos + 2]
    obj_id = (b0 << 16) | ((b2 & 0x3F) << 8) | b1
    size_format = (b2 >> 6) & 0x3

    if size_format == 0:
        return obj_id, 3, 1
    if size_format == 1:
        return obj_id, 3, 2
    if size_format == 2:
        return obj_id, 3, 4

    # size_format == 3 -> extended size (1 or 2 bytes)
    if pos + 3 >= len(buf):
        return None
    b3 = buf[pos + 3]
    if (b3 & 0x80) == 0:
        return obj_id, 4, b3 & 0x7F
    if pos + 4 >= len(buf):
        return None
    b4 = buf[pos + 4]
    return obj_id, 5, ((b3 & 0x7F) << 8) | b4


def walk(
    eeprom_data: bytes,
    *,
    nvm2_offset: int = DEFAULT_NVM2_OFFSET,
    duid: bytes | None = None,
    max_data_size: int = DEFAULT_TLV_SCAN_MAX_DATA_SIZE,
) -> tuple[Nvm2Header, list[Nvm2Record]]:
    """Walk all TLV records in an EEPROM image.

    Parameters
    ----------
    eeprom_data
        Raw 32 KB EEPROM image.
    nvm2_offset
        Absolute offset of the NVM2 region (default 0x0200).
    duid
        Optional 32-byte DUID. If supplied, every record's plaintext
        field is populated via Layer-1 XOR.
    max_data_size
        Records whose decoded data_size exceeds this cap are treated
        as junk and the scan advances one byte.

    Returns
    -------
    (header, records) where records is in on-disk order.
    """
    nvm2 = eeprom_data[nvm2_offset:]
    hdr = parse_nvm2_header(nvm2)
    start = tlv_start_offset(hdr)

    records: list[Nvm2Record] = []
    pos = start

    while pos < len(eeprom_data) - 2:
        if eeprom_data[pos] == 0xFF:
            pos += 1
            continue

        decoded = _decode_tlv_header(eeprom_data, pos)
        if decoded is None:
            break
        obj_id, hsz, dsz = decoded

        if dsz > max_data_size:
            pos += 1
            continue

        data_start = pos + hsz
        data_end = data_start + dsz
        if data_end > len(eeprom_data):
            break

        cipher = bytes(eeprom_data[data_start:data_end])
        tag = (obj_id >> 16) & 0xFF
        name = resolve_name(obj_id)
        rec = Nvm2Record(
            offset=pos,
            obj_id=obj_id,
            tag=tag,
            header_size=hsz,
            data_size=dsz,
            cipher=cipher,
            name=name,
            vendor_uuid=VENDOR_UUIDS.get(tag),
        )

        if duid is not None and name is not None and tag in VENDOR_UUIDS:
            rec.plaintext = layer1_decrypt(cipher, obj_id, name, duid)

        records.append(rec)
        pos = data_end

    return hdr, records


# ---------------------------------------------------------------------
# Sidecar-builder helpers
# ---------------------------------------------------------------------

def build_layout_json(
    hdr: Nvm2Header,
    records: list[Nvm2Record],
    *,
    root_page_pointer: int,
) -> dict[str, Any]:
    """Produce the nvm2_layout.json sidecar content.

    Covers the NVM2 header, the 2-byte root-page pointer that
    physically precedes the header at 0x01FE, and a compact slot map.
    Does not include decoded payload data (that lives in
    nvm2_objects.json).

    ``root_page_pointer`` is authoritative: ``plugin.pack`` writes
    these 2 bytes at EEPROM 0x01FE based on this value. 0xFFFF =
    unprogrammed (the state on every reference dump in this corpus).
    """
    return {
        "root_page_pointer": f"0x{root_page_pointer:04X}",
        "nvm2_header": {
            "magic": f"0x{hdr.magic:08X}",
            "version": hdr.version,
            "key_id": hdr.key_id,
            "object_count": hdr.object_count,
            "max_objects": hdr.max_objects,
            "alloc_bitmap_offset": f"0x{hdr.alloc_bitmap_offset:04X}",
            "span_bitmap_offset": f"0x{hdr.span_bitmap_offset:04X}",
            "bitmap_size_bytes": hdr.bitmap_size,
            "debug_level": f"0x{hdr.debug_level:02X}",
            "generation_counter": hdr.generation,
            "tlv_region_start": f"0x{tlv_start_offset(hdr):04X}",
        },
        "record_count": len(records),
        "slots": [
            {
                "offset": f"0x{r.offset:04X}",
                "obj_id": f"0x{r.obj_id:06X}",
                "name": r.name,
                "header_size": r.header_size,
                "data_size": r.data_size,
            }
            for r in records
        ],
    }


def parse_root_page_pointer_from_sidecar(value: Any) -> int:
    """Parse the ``root_page_pointer`` value from ``nvm2_layout.json``.

    Accepts either an integer or a hex-string (``"0xFFFF"``). Returns
    the integer in ``[0, 0xFFFF]``. Raises ``ValueError`` for any
    other shape.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        n = value
    elif isinstance(value, str):
        s = value.strip()
        try:
            n = int(s, 0) if s else -1
        except ValueError as exc:
            raise ValueError(
                f"nvm2_layout.json 'root_page_pointer' is not a valid "
                f"integer literal: {value!r}"
            ) from exc
    else:
        raise ValueError(
            f"nvm2_layout.json 'root_page_pointer' must be int or str, "
            f"got {type(value).__name__}"
        )
    if not 0 <= n <= 0xFFFF:
        raise ValueError(
            f"nvm2_layout.json 'root_page_pointer' out of range "
            f"[0, 0xFFFF]: 0x{n:X}"
        )
    return n


def build_objects_json(
    records: list[Nvm2Record],
    *,
    duid_used: bool,
    source_sha256: str,
) -> dict[str, Any]:
    """Produce the nvm2_objects.json sidecar content."""
    return {
        "_schema": "hp_clj_pro_4301_eeprom/nvm2_objects.json",
        "_note": (
            "NVM2 TLV records with raw Layer-1 XOR ciphertext. "
            "If a DUID was supplied, the Layer-1 plaintext is included."
        ),
        "source_sha256": source_sha256,
        "duid_applied": duid_used,
        "vendor_uuids": {f"0x{k:02X}": v for k, v in VENDOR_UUIDS.items()},
        "counts": {
            "total": len(records),
            "resolved_names": sum(1 for r in records if r.name is not None),
        },
        "records": [r.to_json() for r in records],
    }
