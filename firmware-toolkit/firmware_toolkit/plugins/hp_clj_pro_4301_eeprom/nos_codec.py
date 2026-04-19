"""NOS region codec for the HP Dune/Selene M24256BW EEPROM plugin.

The NOS region covers the bootloader-managed first 0x1FE bytes of the
EEPROM. (The 2 bytes at 0x1FE-0x1FF are the NVM2 kernel's root-page
pointer and are modelled on the NVM2 side, not here.) The NOS region
holds three *structurally distinct* tiers of NVM state, each modelled
by its own dataclass:

    Tier 1 (0x000-0x0C1, 194 B)  -- :class:`NosPartition`
        Offsets are defined by a sub-partition table in the second-
        stage bootloader. On this printer, NVM2_CONTROL = 0x44 selects
        the type-0x40 table (21 entries at binary address 0x9FF33AA4),
        which maps part_id 0x00 -> NVM2_CONTROL @ 0x000, part_id 0x09
        -> BOARD_ID @ 0x00C, part_id 0x0D -> SERIAL_NUMBER @ 0x02F,
        and so on. Each partition has an HP-assigned ``part_id`` byte
        that the bootloader's ``NVM_ReadField`` / ``NVM_WriteField``
        API uses as its lookup key.

        These fields are stored with one of four protection types:
            prot0   primary + mirror(XOR 0xFF) + 1B checksum   (2N+1 B)
            prot1   primary only                               (  N   B)
            prot2   primary + mirror(XOR 0xFF)                 (2N    B)
            prot3   primary + mirror(XOR 0xFF) + 1B checksum   (2N+1 B)

        prot0 and prot3 use the same algorithm but differ in the
        ``prot_type`` seed mixed into the checksum.

    Tier 2 (0x100-0x130, 49 B)   -- :class:`NosFlatField`
        Hard-coded address-mapped cache, keyed by a separate
        ``field_id`` byte (0x10..0x1C) that indexes into a distinct
        flat-field table in the bootloader. Not partitioned, so
        there are no internal/gap entries. Most entries are prot1
        (raw). MPCA_BPCA_PAIRING (0x12B) is prot2. MAP2_VERSION
        (0x100) is the sole little-endian exception in an otherwise
        big-endian region.

    Tier 3 (0x131-0x1FD, 205 B)  -- :class:`NosNvmField`
        The "NOS NVM extension" region: bytes not in the bootloader's
        flat table but still within (or adjacent to) its RAM-cached
        span (0x000-0x135). Contains userspace-only NOS NVM variables
        (accessed via ``libNvram.so``, keyed by their own NVM IDs) and
        the opaque inter-region filler that follows. Two entries:

            * ``backup_device_pin`` @ 0x131 (4 B, NOS NVM ID 0x94,
              little-endian cleartext integer, prot 1)
            * ``nos_nvm_reserved`` @ 0x135 (201 B, PROT_RAW / raw_bytes
              -- 0x135 is the tail byte of the RAM-cached region,
              0x136-0x1FD is the 0xFF-filled gap before the root-page
              pointer)

Tier-1 coverage is complete between 0x000 and 0x0FF: firmware-
internal partitions (0x17 @ 0x001, 0x18 @ 0x008, 0x08 dynamic gap
@ 0x011, 0x19 @ 0x05A, 0x1A @ 0x060, counter_config 0x06 @ 0x0B4,
remaining_space 0x07 @ 0x0C2) are modelled as opaque ``raw_bytes``
partitions under the synthetic PROT_RAW protection type, so their
bytes round-trip through JSON verbatim even though their internal
semantics are unknown. With Tier 3 in place every byte of the NOS
region 0x000-0x1FD is covered by exactly one entry.

This module is stateless. The sidecar emitted by ``plugin.unpack`` is
a schema-v3 JSON document that mirrors the tier split:

    {
        "schema_version": 3,
        "partitions":     {<NosPartition name>: value, ...},
        "flat_fields":    {<NosFlatField name>: value, ...},
        "nos_nvm_fields": {<NosNvmField name>:  value, ...},
        ...
    }

``overlay_nos_fields(nos_base, partitions=..., flat_fields=...,
nos_nvm_fields=...)`` returns a new 510-byte NOS region (plus 2 bytes
of 0xFF root-pointer padding to keep the buffer 512 B) where each
named entry has been re-encoded into the base bytes. Entries whose
requested value equals the base value are preserved verbatim (primary,
mirror, and checksum bytes all), so uninitialized prot2 fields like
BOOT_FLAGS3 = 0xFF/0xFF round-trip correctly. ``plugin.pack``
synthesizes the NOS region from scratch starting from ``b"\\xFF" *
NOS_REGION_SIZE`` rather than reading a captured ``nos_region.bin``,
so the sidecar is the authoritative source of truth.

References
----------
* ``documentation_current/HP_Dune_Selene_EEPROM_Layout.md`` sections
  4-5 (field descriptor table, protection types, checksum algorithm),
  section 6a (type-0x40 sub-partition table), section 5b row at
  offset 0x131 (BackupDevicePin), and the Tier-2 flat field table
  for ``field_id`` values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

# ---- Module-level constants ---------------------------------------

NOS_REGION_SIZE = 0x200  # 512 bytes


# ---- Layout (nvm2_control) validation -----------------------------
#
# NOS byte 0x000 is NVM2_CONTROL. Its upper nibble selects one of the
# bootloader's sub-partition tables (type 0x30, 0x33, 0x40, ...); its
# lower nibble tunes a size parameter for the dynamic-gap partition
# inside that table. Because the sub-partition table determines the
# absolute offset of every other Tier-1 field, this codec is only
# valid for selectors whose layout we have verified end-to-end.
#
# Current support:
#   * 0x44 (type 0x40, low=4)  -- verified against our corpus and
#     cross-checked with the bootloader binary at 0x9FF33AA4. The
#     type-0x40 formula for the dynamic gap (partition 0x08) is
#     size = (low_nibble + 3) * 4 + 2, so low=4 -> 30 B, matching
#     the observed 0x011..0x02E range.
#
# Known-but-unimplemented selectors (distinct sub-partition tables
# documented in the Layout doc but not yet modelled here):
#   * 0x30, 0x33        -- type-0x30 family
#   * 0x40..0x4F (!=44) -- same type-0x40 table but with a different
#                          dynamic-gap size; offsets from 0x011 onward
#                          would shift by (low-4)*4 bytes.
#
# Any other byte value is "unrecognized" -- either a corrupt dump, a
# newer firmware that introduced a selector we have not seen, or a
# different product variant. The codec refuses to proceed rather than
# decode the rest of the region against an unknown layout.

SUPPORTED_LAYOUT_SELECTORS: frozenset[int] = frozenset({0x44})

_KNOWN_TYPE_30_SELECTORS: frozenset[int] = frozenset({0x30, 0x33})
_KNOWN_TYPE_40_SELECTORS: frozenset[int] = frozenset(range(0x40, 0x50))

KNOWN_LAYOUT_SELECTORS: frozenset[int] = frozenset(
    SUPPORTED_LAYOUT_SELECTORS
    | _KNOWN_TYPE_30_SELECTORS
    | _KNOWN_TYPE_40_SELECTORS
)


class LayoutNotImplementedError(ValueError):
    """Raised when NVM2_CONTROL names a documented-but-unimplemented layout.

    The dump is well-formed but uses a sub-partition table variant we
    have not modelled in this codec. Proceeding would mis-align every
    Tier-1 field offset, so the codec refuses rather than silently
    decode garbage.
    """


class LayoutUnrecognizedError(ValueError):
    """Raised when NVM2_CONTROL is neither supported nor documented.

    The byte does not match any sub-partition table we have seen in
    the bootloader binary. Likely causes: corrupted dump, newer
    firmware with a new layout, or a different product line.
    """


def _describe_type_40_variant(selector: int) -> str:
    """Describe a type-0x40 selector variant for diagnostic messages."""
    low = selector & 0x0F
    gap_size = (low + 3) * 4 + 2
    return (
        f"type-0x40 family, low nibble = 0x{low:X} -> dynamic-gap "
        f"partition 0x08 size = {gap_size} B "
        f"(formula: (low + 3) * 4 + 2)"
    )


def validate_layout_selector(value: int) -> None:
    """Validate the NVM2_CONTROL byte against this codec's layout support.

    ``value`` is the first byte of the NOS region (NOS offset 0x000).
    The callable form is chosen so plugin.unpack/pack can pass either
    the raw int from ``nos_data[0]`` or the primary byte they just
    re-encoded via ``encode_field_primary``.

    Raises:
        TypeError              -- ``value`` is not an int in 0..0xFF.
        LayoutNotImplementedError -- selector is documented but not
            implemented (e.g. 0x30, 0x33, or a type-0x40 variant other
            than 0x44). The dump is well-formed; this codec just does
            not yet model that layout.
        LayoutUnrecognizedError -- selector is neither supported nor
            one of the bootloader's documented sub-partition tables.

    Returns ``None`` on success so the caller can chain it inline.
    """
    if not isinstance(value, int):
        raise TypeError(
            f"NVM2_CONTROL must be an int, got {type(value).__name__}"
        )
    if not 0 <= value <= 0xFF:
        raise TypeError(
            f"NVM2_CONTROL must fit in one byte (0..0xFF), got 0x{value:X}"
        )
    if value in SUPPORTED_LAYOUT_SELECTORS:
        return
    if value in KNOWN_LAYOUT_SELECTORS:
        if value in _KNOWN_TYPE_30_SELECTORS:
            variant = f"type-0x30 family (selector 0x{value:02X})"
        else:
            variant = _describe_type_40_variant(value)
        supported = ", ".join(
            f"0x{s:02X}" for s in sorted(SUPPORTED_LAYOUT_SELECTORS)
        )
        raise LayoutNotImplementedError(
            f"NVM2_CONTROL = 0x{value:02X} selects a documented but "
            f"unimplemented sub-partition table: {variant}. "
            f"This codec only supports: {supported}. Every Tier-1 "
            f"field offset would shift under the requested layout; "
            f"refusing to proceed rather than decode against the "
            f"wrong offsets."
        )
    supported = ", ".join(
        f"0x{s:02X}" for s in sorted(SUPPORTED_LAYOUT_SELECTORS)
    )
    raise LayoutUnrecognizedError(
        f"NVM2_CONTROL = 0x{value:02X} does not match any known "
        f"sub-partition table. Known selectors: "
        + ", ".join(f"0x{s:02X}" for s in sorted(KNOWN_LAYOUT_SELECTORS))
        + f". Supported by this codec: {supported}. Possible causes: "
        f"corrupt dump, newer firmware, or a different product variant."
    )


# ---- Protection-layer primitives ----------------------------------
#
# These functions operate on the *primary* bytes of a field (length
# == semantic width N). They produce the on-disk byte sequence as it
# appears in the NOS region, including mirror and checksum where
# applicable.

def _nvm_checksum(primary: bytes, prot_type: int) -> int:
    """NVM_ComputeChecksum for the primary copy (libNvram.so 0x4befc).

    The bootloader implementation takes an `is_primary` flag whose
    only effect is to XOR a 0x00/0xFF mask onto every byte. Mirror
    bytes (primary XOR 0xFF) with mask 0xFF yield the same result as
    primary bytes with mask 0x00, so we compute the checksum over the
    primary bytes with `is_primary=True` (mask=0x00).

    Pseudocode (from the binary / Layout doc section 4):

        result = primary[0] XOR 0xFF XOR prot_type
        for i in 1..len-1:
            result = (result XOR primary[i]) & 0xFF
    """
    if not primary:
        raise ValueError("checksum requires at least one input byte")
    result = primary[0] ^ 0xFF ^ prot_type
    for b in primary[1:]:
        result = (result ^ b) & 0xFF
    return result & 0xFF


def _xor_mirror(primary: bytes) -> bytes:
    return bytes(b ^ 0xFF for b in primary)


def pack_prot0(primary: bytes) -> bytes:
    """prot0 (2N+1 B): primary + mirror(XOR 0xFF) + checksum.

    Used by BOARD_ID (0x00C, N=2).
    """
    return primary + _xor_mirror(primary) + bytes([_nvm_checksum(primary, 0)])


def pack_prot1(primary: bytes) -> bytes:
    """prot1 (N B): primary only, no redundancy."""
    return primary


def pack_prot2(primary: bytes) -> bytes:
    """prot2 (2N B): primary + mirror(XOR 0xFF), no checksum.

    Note: uninitialized prot2 fields are stored as 0xFF/0xFF on flash
    (not 0xFF/0x00), which *deliberately* fails the mirror XOR check
    so the bootloader treats the field as zero-valued. If you need to
    preserve that state during a pack, leave the field value at its
    current JSON value -- `overlay_nos_fields()` will then skip the
    re-encode and keep the raw bytes verbatim.
    """
    return primary + _xor_mirror(primary)


def pack_prot3(primary: bytes) -> bytes:
    """prot3 (2N+1 B): primary + mirror + checksum (prot_type seed = 3).

    Used by SERIAL_NUMBER (0x02F, N=20).
    """
    return primary + _xor_mirror(primary) + bytes([_nvm_checksum(primary, 3)])


# Synthetic "raw" protection type: not a bootloader protection layer
# but a codec-side marker meaning "this partition is not modelled by
# any of prot0/1/2/3; store its bytes verbatim without mirror or
# checksum". Used for firmware-internal partitions (0x17, 0x18, 0x08,
# 0x19, 0x1A, counter_config, remaining_space) whose internal byte
# layout is not known and whose contents round-trip byte-for-byte.
PROT_RAW = 4


def pack_raw(primary: bytes) -> bytes:
    """PROT_RAW (N B): opaque bytes, no redundancy, no checksum."""
    return bytes(primary)


_PACKERS = {
    0: pack_prot0,
    1: pack_prot1,
    2: pack_prot2,
    3: pack_prot3,
    PROT_RAW: pack_raw,
}


def _on_disk_width(prot: int, width: int) -> int:
    if prot == 0 or prot == 3:
        return 2 * width + 1
    if prot == 1:
        return width
    if prot == 2:
        return 2 * width
    if prot == PROT_RAW:
        return width
    raise ValueError(f"unknown protection type: {prot}")


def unpack_primary(raw: bytes, prot: int, width: int) -> bytes:
    """Return the primary-copy bytes from an on-disk field slice.

    The caller is responsible for passing a slice of the correct
    length (`_on_disk_width(prot, width)`). This function does not
    validate the mirror or checksum -- use `verify_field()` for that.
    """
    if prot not in _PACKERS:
        raise ValueError(f"unknown protection type: {prot}")
    expected = _on_disk_width(prot, width)
    if len(raw) != expected:
        raise ValueError(
            f"prot{prot} field of width {width} expects "
            f"{expected} on-disk bytes, got {len(raw)}"
        )
    return bytes(raw[:width])


def verify_field(raw: bytes, prot: int, width: int) -> str:
    """Check mirror/checksum integrity of an on-disk field slice.

    Returns one of:
        "ok"                 - everything matches the protection rules
        "prot1_no_check"     - prot1 has no redundancy to check
        "raw_no_check"       - PROT_RAW has no redundancy to check
        "mirror_mismatch"    - primary XOR mirror != 0xFF on >=1 byte
        "checksum_mismatch"  - stored checksum byte wrong
    """
    primary = bytes(raw[:width])
    if prot == 1:
        return "prot1_no_check"
    if prot == PROT_RAW:
        return "raw_no_check"
    mirror = bytes(raw[width:2 * width])
    if _xor_mirror(primary) != mirror:
        return "mirror_mismatch"
    if prot == 0 or prot == 3:
        stored_cks = raw[2 * width]
        computed_cks = _nvm_checksum(primary, prot)
        if stored_cks != computed_cks:
            return "checksum_mismatch"
    return "ok"


# ---- Serialization helpers (bytes <-> JSON values) ----------------
#
# Each `fmt` string picks an encode/decode pair. Encode converts a
# JSON-level value (int / str) back to the primary-bytes representation
# of width `field.width`. Decode does the reverse.

def _decode_uint_be(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def _decode_uint_le(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


def _encode_uint_be(value: Any, width: int) -> bytes:
    n = int(value, 0) if isinstance(value, str) else int(value)
    return n.to_bytes(width, "big")


def _encode_uint_le(value: Any, width: int) -> bytes:
    n = int(value, 0) if isinstance(value, str) else int(value)
    return n.to_bytes(width, "little")


def _decode_hex_be(raw: bytes) -> str:
    return "0x" + raw.hex().upper()


def _encode_hex_be(value: Any, width: int) -> bytes:
    if isinstance(value, int):
        return value.to_bytes(width, "big")
    s = value.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = s.replace("_", "").replace(" ", "")
    # Left-pad to the expected width so short-form "0x42" writes into
    # a 4-byte BE field as 0x00000042 rather than raising.
    if len(s) > width * 2:
        raise ValueError(
            f"hex value {value!r} too wide for {width}-byte field"
        )
    s = s.rjust(width * 2, "0")
    return bytes.fromhex(s)


def _decode_ascii(raw: bytes) -> str:
    # NOS ASCII fields are null-padded. Strip from the first NUL on.
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def _encode_ascii(value: Any, width: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"ASCII field expects str, got {type(value).__name__}")
    b = value.encode("ascii", errors="strict")
    if len(b) > width:
        raise ValueError(
            f"ASCII value {value!r} is {len(b)} bytes; field holds {width}"
        )
    return b.ljust(width, b"\x00")


def _decode_mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def _encode_mac(value: Any, width: int) -> bytes:
    if width != 6:
        raise ValueError(f"MAC field must be 6 bytes wide, got {width}")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise TypeError(f"MAC field expects str, got {type(value).__name__}")
    s = value.strip().replace("-", ":").replace(".", ":")
    parts = [p for p in s.split(":") if p]
    if len(parts) != 6:
        raise ValueError(
            f"MAC string {value!r} must have 6 octets, got {len(parts)}"
        )
    return bytes(int(p, 16) for p in parts)


def _decode_hex_raw(raw: bytes) -> str:
    # No "0x" prefix; lowercase hex so round-trip is textually stable.
    return raw.hex()


def _encode_hex_raw(value: Any, width: int) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
    else:
        if not isinstance(value, str):
            raise TypeError(
                f"hex_raw field expects str, got {type(value).__name__}"
            )
        s = value.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        s = s.replace(":", "").replace(" ", "").replace("_", "")
        if len(s) % 2:
            raise ValueError(f"hex_raw value has odd nibble count: {value!r}")
        b = bytes.fromhex(s)
    if len(b) != width:
        raise ValueError(
            f"hex_raw value is {len(b)} bytes; field holds {width}"
        )
    return b


def _decode_raw_bytes(raw: bytes) -> str:
    """Decode an opaque byte region as a ``0xAABBCC...`` uppercase string.

    Used for firmware-internal partitions whose internal structure is
    not modelled. The ``0x`` prefix distinguishes this visually from
    the lowercase no-prefix ``hex_raw`` format used by fields that
    have a documented semantic meaning.
    """
    return "0x" + raw.hex().upper()


def _encode_raw_bytes(value: Any, width: int) -> bytes:
    """Encode an opaque byte region from ``0xAABBCC...`` or raw bytes.

    Strict-length: the caller must supply exactly ``width`` bytes
    (``width * 2`` hex nibbles, optional ``0x`` prefix). Unlike
    ``hex_be`` this does not left-pad -- opaque regions have no
    notion of "high" vs "low" bytes, so padding would silently
    corrupt the layout.
    """
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
    else:
        if not isinstance(value, str):
            raise TypeError(
                f"raw_bytes field expects str, got {type(value).__name__}"
            )
        s = value.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        s = s.replace(":", "").replace(" ", "").replace("_", "")
        if len(s) % 2:
            raise ValueError(
                f"raw_bytes value has odd nibble count: {value!r}"
            )
        b = bytes.fromhex(s)
    if len(b) != width:
        raise ValueError(
            f"raw_bytes value is {len(b)} bytes; field holds exactly "
            f"{width} (no padding is performed)"
        )
    return b


# ---- counter_data: structured crash-log records --------------------
#
# counter_data is a circular buffer of 5 fixed-width crash records
# (14 B each = 70 B total). Each record is written by
# ``NVM_PanicCrashWriter`` (bootloader 0x9ff1a10a) on panic. The
# Layout doc's Section 10 is the canonical reference for this struct:
#
#     +0x00  4B BE   crash_code    Boot_PanicDispatch param_1
#                                  (Assert: CRC16(file\0) | code<<16;
#                                   PanicWithCode: caller-defined)
#     +0x04  2B BE   error_code    Boot_PanicDispatch param_4 (ushort)
#     +0x06  4B BE   detail        param_2: source filename pointer
#                                  or line/context
#     +0x0A  4B BE   timestamp     Boot_GetTimestamp snapshot (0 if
#                                  hardware timer not yet initialized)
#
# All fields are big-endian (consistent with the rest of Tier-1 NOS).

_COUNTER_SLOT_SIZE = 14
_COUNTER_SLOT_COUNT = 5


def _decode_counter_slot(raw: bytes) -> dict[str, Any]:
    if len(raw) != _COUNTER_SLOT_SIZE:
        raise ValueError(
            f"counter slot expects {_COUNTER_SLOT_SIZE} bytes, got {len(raw)}"
        )
    return {
        "crash_code": "0x{:08X}".format(int.from_bytes(raw[0:4], "big")),
        "error_code": "0x{:04X}".format(int.from_bytes(raw[4:6], "big")),
        "detail":     "0x{:08X}".format(int.from_bytes(raw[6:10], "big")),
        "timestamp":  int.from_bytes(raw[10:14], "big"),
    }


def _encode_counter_slot(slot: dict[str, Any]) -> bytes:
    if not isinstance(slot, dict):
        raise TypeError(
            f"counter_data slot expects dict, got {type(slot).__name__}"
        )
    unknown = set(slot) - {"crash_code", "error_code", "detail", "timestamp"}
    if unknown:
        raise ValueError(
            "counter_data slot has unknown key(s): "
            + ", ".join(sorted(unknown))
        )

    def _asint(v: Any) -> int:
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            return int(v, 0)
        raise TypeError(
            f"counter_data slot field expects int or str, got "
            f"{type(v).__name__}"
        )
    crash_code = _asint(slot.get("crash_code", 0))
    error_code = _asint(slot.get("error_code", 0))
    detail     = _asint(slot.get("detail", 0))
    timestamp  = _asint(slot.get("timestamp", 0))
    return (
        crash_code.to_bytes(4, "big")
        + error_code.to_bytes(2, "big")
        + detail.to_bytes(4, "big")
        + timestamp.to_bytes(4, "big")
    )


def _decode_counter_data(raw: bytes) -> dict[str, Any]:
    if len(raw) != _COUNTER_SLOT_SIZE * _COUNTER_SLOT_COUNT:
        raise ValueError(
            f"counter_data expects "
            f"{_COUNTER_SLOT_SIZE * _COUNTER_SLOT_COUNT} bytes, got {len(raw)}"
        )
    return {
        "slots": [
            _decode_counter_slot(
                raw[i * _COUNTER_SLOT_SIZE:(i + 1) * _COUNTER_SLOT_SIZE]
            )
            for i in range(_COUNTER_SLOT_COUNT)
        ]
    }


def _encode_counter_data(value: Any, width: int) -> bytes:
    """Encode counter_data from either a dict ``{"slots": [...]}`` or a
    raw hex string (useful for deliberate fuzzing / raw overrides).
    """
    if width != _COUNTER_SLOT_SIZE * _COUNTER_SLOT_COUNT:
        raise ValueError(
            f"counter_data field must be {_COUNTER_SLOT_SIZE * _COUNTER_SLOT_COUNT} "
            f"bytes, got width={width}"
        )
    if isinstance(value, (bytes, bytearray)):
        out = bytes(value)
    elif isinstance(value, str):
        out = _encode_hex_raw(value, width)
    elif isinstance(value, dict):
        slots = value.get("slots")
        if slots is None:
            raise ValueError(
                "counter_data dict must have a 'slots' key"
            )
        if not isinstance(slots, list):
            raise TypeError(
                f"counter_data.slots must be a list, got "
                f"{type(slots).__name__}"
            )
        if len(slots) != _COUNTER_SLOT_COUNT:
            raise ValueError(
                f"counter_data.slots must have exactly "
                f"{_COUNTER_SLOT_COUNT} entries, got {len(slots)}"
            )
        unknown = set(value) - {"slots"}
        if unknown:
            raise ValueError(
                "counter_data dict has unknown key(s): "
                + ", ".join(sorted(unknown))
            )
        out = b"".join(_encode_counter_slot(s) for s in slots)
    else:
        raise TypeError(
            f"counter_data expects dict, hex string, or bytes; got "
            f"{type(value).__name__}"
        )
    if len(out) != width:
        raise ValueError(
            f"counter_data encoding produced {len(out)} bytes, expected {width}"
        )
    return out


# ---- counter_state: index + bank + XOR checksum --------------------
#
# 2 bytes at NOS offset 0x0B2:
#     byte[0] = (bank_flag << 7) | (index & 0x7F)
#     byte[1] = XOR of all 70 counter_data bytes
#
# The checksum is cross-field: byte[1] depends on counter_data. Pack
# enforces this invariant via the consistency registry below; the
# encoder itself accepts whatever the caller passes and does not
# recompute. See ``overlay_nos_fields`` for the auto-fill shortcut
# where the dict is passed without a ``checksum`` key.

def _decode_counter_state(raw: bytes) -> dict[str, Any]:
    if len(raw) != 2:
        raise ValueError(f"counter_state expects 2 bytes, got {len(raw)}")
    b0 = raw[0]
    return {
        "index": b0 & 0x7F,
        "bank": (b0 >> 7) & 0x01,
        "checksum": "0x{:02X}".format(raw[1]),
    }


def _encode_counter_state(value: Any, width: int) -> bytes:
    if width != 2:
        raise ValueError(
            f"counter_state field must be 2 bytes, got width={width}"
        )
    if isinstance(value, (bytes, bytearray)):
        out = bytes(value)
    elif isinstance(value, str):
        out = _encode_hex_be(value, width)
    elif isinstance(value, dict):
        unknown = set(value) - {"index", "bank", "checksum"}
        if unknown:
            raise ValueError(
                "counter_state dict has unknown key(s): "
                + ", ".join(sorted(unknown))
            )
        if "checksum" not in value:
            raise ValueError(
                "counter_state dict is missing 'checksum'; auto-fill "
                "is handled by overlay_nos_fields and should have "
                "populated it before reaching the encoder"
            )

        def _asint(v: Any) -> int:
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                return int(v, 0)
            raise TypeError(
                f"counter_state field expects int or str, got "
                f"{type(v).__name__}"
            )
        index = _asint(value.get("index", 0))
        bank  = _asint(value.get("bank", 0))
        cks   = _asint(value["checksum"])
        if not 0 <= index <= 0x7F:
            raise ValueError(
                f"counter_state.index must fit in 7 bits (0..127), got {index}"
            )
        if bank not in (0, 1):
            raise ValueError(
                f"counter_state.bank must be 0 or 1, got {bank}"
            )
        if not 0 <= cks <= 0xFF:
            raise ValueError(
                f"counter_state.checksum must fit in 1 byte, got "
                f"0x{cks:X}"
            )
        out = bytes([((bank & 1) << 7) | (index & 0x7F), cks & 0xFF])
    else:
        raise TypeError(
            f"counter_state expects dict, hex string, or bytes; got "
            f"{type(value).__name__}"
        )
    if len(out) != width:
        raise ValueError(
            f"counter_state encoding produced {len(out)} bytes, expected {width}"
        )
    return out


_DECODERS = {
    "uint_be":          _decode_uint_be,
    "uint_le":          _decode_uint_le,
    "hex_be":           _decode_hex_be,
    "ascii":            _decode_ascii,
    "mac":              _decode_mac,
    "hex_raw":          _decode_hex_raw,
    "raw_bytes":        _decode_raw_bytes,
    "counter_data":     _decode_counter_data,
    "counter_state":    _decode_counter_state,
}

_ENCODERS = {
    "uint_be":          _encode_uint_be,
    "uint_le":          _encode_uint_le,
    "hex_be":           _encode_hex_be,
    "ascii":            _encode_ascii,
    "mac":              _encode_mac,
    "hex_raw":          _encode_hex_raw,
    "raw_bytes":        _encode_raw_bytes,
    "counter_data":     _encode_counter_data,
    "counter_state":    _encode_counter_state,
}


# ---- Entry descriptor types ---------------------------------------
#
# Tier 1 and Tier 2 have structurally different roles in the
# bootloader, so we model them as separate dataclasses. Both expose
# the same read/encode surface (``offset``, ``width``, ``prot``,
# ``fmt``, ``on_disk_width``, ``end_offset``) so codec helpers can
# work on either via duck typing, but the *identity* of an entry
# differs:
#
#   * A :class:`NosPartition` is one row of the bootloader's type-0x40
#     sub-partition table (binary address 0x9FF33AA4); its ``part_id``
#     is the lookup key that ``NVM_ReadField`` / ``NVM_WriteField``
#     use. Firmware-internal partitions (0x17, 0x18, 0x08 dynamic
#     gap, 0x19, 0x1A, counter_config 0x06, remaining 0x07) have no
#     documented public API but are still modelled as opaque entries
#     with the synthetic PROT_RAW protection type + ``raw_bytes``
#     format, so every byte in 0x000-0x0FF round-trips through JSON.
#
#   * A :class:`NosFlatField` lives in the Tier-2 flat table whose
#     entries are keyed by ``field_id`` (0x10..0x1C). This table is
#     not partitioned; every byte between 0x100 and 0x130 belongs to
#     exactly one named entry, so our Tier-2 coverage is complete.
#
# The two ID spaces do NOT collide only because they index different
# tables; ``field_id = 0x17`` (BOOT_FLAGS2 at 0x121) and
# ``part_id = 0x17`` (an internal partition at 0x001) are unrelated.

@dataclass(frozen=True)
class NosPartition:
    """One entry in the bootloader's Tier-1 sub-partition table.

    Attributes
    ----------
    name : str
        JSON key used in the ``"partitions"`` section of
        ``nos_fields.json``.
    part_id : int
        Partition ID byte assigned by HP (the key used by the
        bootloader's ``NVM_ReadField`` / ``NVM_WriteField`` API).
    offset : int
        Absolute byte offset within the 512-byte NOS region. Computed
        by the bootloader at boot time by accumulating sizes through
        the sub-partition table; we record the resolved offset here
        because our corpus only sees ``NVM2_CONTROL = 0x44``.
    width : int
        Semantic width in bytes (the "N" from the Layout doc's field
        table -- what the caller sees, not the on-disk length).
    prot : int
        Protection type 0/1/2/3 (see module docstring).
    fmt : str
        Serialization format for JSON representation. See
        ``_DECODERS`` / ``_ENCODERS``.
    note : str
        Free-form comment, surfaced in diagnostics only.
    """

    name: str
    part_id: int
    offset: int
    width: int
    prot: int
    fmt: str
    note: str = ""

    tier: str = "partition"

    @property
    def on_disk_width(self) -> int:
        return _on_disk_width(self.prot, self.width)

    @property
    def end_offset(self) -> int:
        return self.offset + self.on_disk_width


@dataclass(frozen=True)
class NosFlatField:
    """One entry in the bootloader's Tier-2 flat-field table.

    Attributes
    ----------
    name : str
        JSON key used in the ``"flat_fields"`` section of
        ``nos_fields.json``.
    field_id : int
        Flat-field ID byte (the key the Tier-2 table uses). Disjoint
        from :attr:`NosPartition.part_id` -- they index different
        tables in the bootloader.
    offset : int
        Absolute byte offset within the 512-byte NOS region.
    width : int
        Semantic width in bytes.
    prot : int
        Protection type 1 or 2. The vast majority of Tier-2 fields
        are prot1 (no redundancy); ``mpca_bpca_pairing`` is the sole
        prot2 entry (primary + mirror).
    fmt : str
        Serialization format for JSON representation. See
        ``_DECODERS`` / ``_ENCODERS``.
    note : str
        Free-form comment, surfaced in diagnostics only.
    """

    name: str
    field_id: int
    offset: int
    width: int
    prot: int
    fmt: str
    note: str = ""

    tier: str = "flat_field"

    @property
    def on_disk_width(self) -> int:
        return _on_disk_width(self.prot, self.width)

    @property
    def end_offset(self) -> int:
        return self.offset + self.on_disk_width


@dataclass(frozen=True)
class NosNvmField:
    """One entry in the Tier-3 "NOS NVM extension" table (0x131-0x1FD).

    These bytes are not managed by the bootloader's flat table but are
    still part of the first 512 bytes of the EEPROM that the bootloader
    caches in RAM (0x000-0x135) and that userspace ``libNvram.so`` can
    read/write through its NOS NVM API. The tier also absorbs the
    opaque inter-region filler (0x135-0x1FD) so that every byte of the
    modelled NOS region (0x000-0x1FD) belongs to exactly one entry.

    Attributes
    ----------
    name : str
        JSON key used in the ``"nos_nvm_fields"`` section of
        ``nos_fields.json``.
    nvm_id : Optional[int]
        NOS NVM variable ID assigned by ``libNvram.so`` (e.g. 0x94 for
        BackupDevicePin). ``None`` for pure filler entries that have no
        programmatic identity.
    offset : int
        Absolute byte offset within the 512-byte NOS region.
    width : int
        Semantic width in bytes.
    prot : int
        Protection type. Tier-3 entries use either ``prot 1`` (raw
        userspace variables, no mirror/checksum) or :data:`PROT_RAW`
        (opaque filler).
    fmt : str
        Serialization format for JSON representation. See
        ``_DECODERS`` / ``_ENCODERS``.
    note : str
        Free-form comment, surfaced in diagnostics only.
    """

    name: str
    nvm_id: Optional[int]
    offset: int
    width: int
    prot: int
    fmt: str
    note: str = ""

    tier: str = "nos_nvm_field"

    @property
    def on_disk_width(self) -> int:
        return _on_disk_width(self.prot, self.width)

    @property
    def end_offset(self) -> int:
        return self.offset + self.on_disk_width


# Union alias: helpers that don't care about the tier distinction
# accept any of the three dataclasses. We keep this as a plain type
# alias rather than a Protocol because the on-disk behaviour is
# identical once ``prot`` + ``width`` + ``fmt`` are known.
NosEntry = "NosPartition | NosFlatField | NosNvmField"


# ---- Tier-1 partition table (source of truth) ---------------------
#
# All offsets are absolute within the NOS region (0x000-0x1FD) and
# valid only when NVM2_CONTROL = 0x44 (type-0x40 sub-partition table);
# changing NVM2_CONTROL would shift the layout (enforced by
# ``validate_layout_selector``). ``part_id`` values are taken from the
# Layout doc's "Complete Sub-Partition Table (Type 0x40, Active)".
#
# Every sub-partition from the bootloader table is represented here.
# "Named" partitions (nvm2_control, board_id, serial_number, ...) use
# the semantic encoding documented by HP (hex_be, ascii, counter_data,
# etc.). "Firmware-internal" partitions (0x17, 0x18, 0x08, 0x19, 0x1A,
# counter_config 0x06, remaining_space 0x07) have no documented public
# API in the bootloader's NVM_ReadField / NVM_WriteField surface and
# their internal byte layout is not known. We expose them with the
# synthetic PROT_RAW protection type and the ``raw_bytes`` format so
# their contents still round-trip through JSON byte-for-byte and can
# be inspected, but semantic interpretation is intentionally absent.
#
# The zero-width boundary marker partition 0x11 (at offset 0x06C, size
# 0) is not modelled: it occupies no bytes on disk and exists only as
# a table row that separates the field block from the counter block.
#
# Dynamic-gap note: partition 0x08 has size
# (NVM2_CONTROL_low_nibble + 3) * 4 + 2. We hard-code 30 B here
# because the layout validator refuses any selector other than 0x44.
PARTITION_TABLE: list[NosPartition] = [
    NosPartition("nvm2_control",        0x00, 0x000,  1, 1, "hex_be",
                 "Partition control byte (upper nibble = type; lower = "
                 "size of partition 0x08)"),
    NosPartition("internal_17",         0x17, 0x001,  4, PROT_RAW, "raw_bytes",
                 "Firmware-internal partition; purpose undocumented in "
                 "the public NVM API; opaque bytes preserved verbatim."),
    NosPartition("map_revision",        0x01, 0x005,  1, 1, "hex_be",
                 "NVM map revision counter"),
    NosPartition("power_state",         0x0A, 0x006,  1, 2, "hex_be",
                 "Power state flag (prot2)"),
    NosPartition("internal_18",         0x18, 0x008,  4, PROT_RAW, "raw_bytes",
                 "Firmware-internal partition; purpose undocumented in "
                 "the public NVM API; opaque bytes preserved verbatim."),
    NosPartition("board_id",            0x09, 0x00C,  2, 0, "hex_be",
                 "Hardware board identifier (prot0, 2B primary)"),
    NosPartition("internal_08_gap",     0x08, 0x011, 30, PROT_RAW, "raw_bytes",
                 "Dynamic-gap partition (size = (nvm2_control_low_nibble"
                 " + 3) * 4 + 2). Locked at 30 B because this codec "
                 "only supports nvm2_control = 0x44."),
    NosPartition("serial_number",       0x0D, 0x02F, 20, 3, "ascii",
                 "Device serial number (prot3, 20B ASCII null-padded)"),
    NosPartition("boot_flags",          0x0E, 0x058,  1, 2, "hex_be",
                 "Boot/recovery flags (prot2)"),
    NosPartition("internal_19",         0x19, 0x05A,  2, PROT_RAW, "raw_bytes",
                 "Firmware-internal partition; purpose undocumented in "
                 "the public NVM API; opaque bytes preserved verbatim."),
    NosPartition("boot_flags3",         0x10, 0x05C,  1, 2, "hex_be",
                 "Additional boot flags (prot2, uninitialized = 0xFF/0xFF)"),
    NosPartition("power_state2",        0x12, 0x05E,  1, 2, "hex_be",
                 "Secondary power state (prot2, uninitialized = 0xFF/0xFF)"),
    NosPartition("internal_1A",         0x1A, 0x060,  2, PROT_RAW, "raw_bytes",
                 "Firmware-internal partition; purpose undocumented in "
                 "the public NVM API; opaque bytes preserved verbatim."),
    NosPartition("assert_seq_num",      0x14, 0x062,  4, 1, "hex_be",
                 "Assertion sequence number (prot1, big-endian)"),
    NosPartition("psku_config",         0x15, 0x066,  4, 1, "hex_be",
                 "Product SKU configuration (prot1, big-endian)"),
    NosPartition("eeprom_recov_count",  0x16, 0x06A,  2, 1, "uint_be",
                 "EEPROM recovery counter (prot1, BE uint16)"),
    NosPartition("counter_data",        0x04, 0x06C, 70, 1, "counter_data",
                 "Circular crash log: 5 x 14B records (crash_code "
                 "u32be, error_code u16be, detail u32be, timestamp "
                 "u32be). Integrity is enforced by counter_state "
                 "checksum"),
    NosPartition("counter_state",       0x05, 0x0B2,  2, 1, "counter_state",
                 "byte[0]=(bank<<7)|(index&0x7F); byte[1]=XOR "
                 "checksum of all 70 counter_data bytes. Cross-field "
                 "consistency is enforced at pack time (see "
                 "CONSISTENCY_CHECKS)"),
    NosPartition("counter_config",      0x06, 0x0B4, 14, PROT_RAW, "raw_bytes",
                 "Reserved/unused counter-config region (0xFF fill in "
                 "both reference dumps)."),
    NosPartition("remaining_space",     0x07, 0x0C2, 62, PROT_RAW, "raw_bytes",
                 "Remaining tail of the partitioned sub-region (0x0C2.."
                 "0x0FF). Typically 0xFF fill; preserved verbatim."),
]


# ---- Tier-2 flat-field table (source of truth) --------------------
#
# All offsets are absolute within the NOS region. ``field_id`` values
# are taken from the Tier-2 table entries in the second-stage
# bootloader (cross-referenced with the 010 Editor BT template).
FLAT_FIELD_TABLE: list[NosFlatField] = [
    NosFlatField("map2_version",            0x10, 0x100,  2, 1, "uint_le",
                 "Flat-region map version (sole LE field in NOS)"),
    NosFlatField("pca_serial",              0x11, 0x102, 10, 1, "ascii",
                 "PCA serial number (10B ASCII null-padded)"),
    NosFlatField("eth0_mac",                0x12, 0x10C,  6, 1, "mac",
                 "ETH0 MAC"),
    NosFlatField("wlan0_mac",               0x13, 0x112,  6, 1, "mac",
                 "WLAN0 MAC"),
    NosFlatField("wlan1_mac",               0x14, 0x118,  6, 1, "mac",
                 "WLAN1 MAC"),
    NosFlatField("power_cycle_count",       0x15, 0x11E,  2, 1, "uint_be",
                 "Power cycle counter (BE uint16)"),
    NosFlatField("secure_vars",             0x16, 0x120,  1, 1, "hex_be",
                 "Secure vars flag"),
    NosFlatField("boot_flags2",             0x17, 0x121,  2, 1, "hex_be",
                 "NOS NVM name MISC_BITS_1. BE uint16; bit 4 = "
                 "recovery partition failed (1st-stage)"),
    NosFlatField("misc_1",                  0x18, 0x123,  4, 1, "hex_be",
                 "4B, usually 0xFFFFFFFF (empty)"),
    NosFlatField("save_recover_id",         0x19, 0x127,  4, 1, "hex_be",
                 "4B, usually 0xFFFFFFFF (empty)"),
    NosFlatField("mpca_bpca_pairing",       0x1A, 0x12B,  1, 2, "hex_be",
                 "MPCA/BPCA pairing status (prot2; 0xFF unprogrammed)"),
    NosFlatField("misc_2",                  0x1B, 0x12D,  2, 1, "hex_be",
                 "NOS NVM name MISC_BITS_2"),
    NosFlatField("eeprom_recov_count_flat", 0x1C, 0x12F,  2, 1, "hex_be",
                 "Flat-region recovery count. Formerly UNKNOWN_1C; "
                 "NOS NVM name EEPROM_RECOV_COUNT. Distinct from "
                 "partitioned eeprom_recov_count at 0x06A."),
]


# ---- Tier-3 NOS NVM extension table (source of truth) -------------
#
# Covers 0x131-0x1FD: bytes not in the bootloader's flat table but
# still part of the NOS region. Contains userspace-only NOS NVM
# variables (accessed via libNvram.so using their own NOS NVM IDs)
# and the opaque filler that runs up to the NVM2 root-page pointer
# at 0x1FE-0x1FF. The root-page pointer itself is *not* modelled
# here -- it belongs to the NVM2 region (see plugin.py /
# nvm2_decoder.py) and the pack path writes those 2 bytes from
# nvm2_region.bin / nvm2_layout.json.
NOS_NVM_FIELD_TABLE: list[NosNvmField] = [
    NosNvmField("backup_device_pin",    0x94, 0x131,   4, 1, "hex_be",
                "BackupDevicePin. NOS NVM only -- accessed by "
                "libNvram.so userspace (not in the bootloader flat "
                "table); 4 bytes, cleartext. On disk the firmware "
                "treats these as a little-endian integer, but the "
                "sidecar stores them as a ``\"0xAABBCCDD\"`` hex "
                "string in on-disk byte order (so \"0xFFFFFFFF\" when "
                "unprogrammed). To recover the logical LE integer, "
                "byte-reverse the hex. See "
                "HP_Dune_Selene_PIN_Analysis.md section 8.3."),
    NosNvmField("nos_nvm_reserved",     None, 0x135, 201, PROT_RAW, "raw_bytes",
                "Inter-region filler. 0x135 is the tail byte of the "
                "bootloader's RAM-cached span (bootloader caches "
                "0x000-0x135); 0x136-0x1FD is 0xFF-filled gap. "
                "Preserved verbatim so any device-specific state "
                "round-trips without interpretation."),
]


# Build once: name -> entry lookups, frozen after module load.
_PARTITION_BY_NAME: dict[str, NosPartition] = {
    p.name: p for p in PARTITION_TABLE
}
_FLAT_FIELD_BY_NAME: dict[str, NosFlatField] = {
    f.name: f for f in FLAT_FIELD_TABLE
}
_NOS_NVM_FIELD_BY_NAME: dict[str, NosNvmField] = {
    n.name: n for n in NOS_NVM_FIELD_TABLE
}


def get_partition(name: str) -> NosPartition:
    try:
        return _PARTITION_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"unknown NOS partition: {name!r}") from exc


def get_flat_field(name: str) -> NosFlatField:
    try:
        return _FLAT_FIELD_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"unknown NOS flat field: {name!r}") from exc


def get_nos_nvm_field(name: str) -> NosNvmField:
    try:
        return _NOS_NVM_FIELD_BY_NAME[name]
    except KeyError as exc:
        raise KeyError(f"unknown NOS NVM field: {name!r}") from exc


def get_entry(name: str) -> NosEntry:  # type: ignore[valid-type]
    """Look up an entry by name across all three tiers.

    Used by tier-agnostic code (``overlay_nos_fields``, consistency
    helpers) that iterates in offset order. Callers that care about
    the distinction should use :func:`get_partition`,
    :func:`get_flat_field`, or :func:`get_nos_nvm_field` instead.
    """
    if name in _PARTITION_BY_NAME:
        return _PARTITION_BY_NAME[name]
    if name in _FLAT_FIELD_BY_NAME:
        return _FLAT_FIELD_BY_NAME[name]
    if name in _NOS_NVM_FIELD_BY_NAME:
        return _NOS_NVM_FIELD_BY_NAME[name]
    raise KeyError(f"unknown NOS entry: {name!r}")


def iter_partitions() -> Iterable[NosPartition]:
    """Iterate the Tier-1 partition table in offset order."""
    return iter(PARTITION_TABLE)


def iter_flat_fields() -> Iterable[NosFlatField]:
    """Iterate the Tier-2 flat field table in offset order."""
    return iter(FLAT_FIELD_TABLE)


def iter_nos_nvm_fields() -> Iterable[NosNvmField]:
    """Iterate the Tier-3 NOS NVM extension table in offset order."""
    return iter(NOS_NVM_FIELD_TABLE)


def iter_entries() -> "Iterable[NosEntry]":
    """Iterate every entry (all three tiers) in EEPROM offset order.

    Because Tier-1 ends at 0x0C1, Tier-2 runs 0x100-0x130, and Tier-3
    starts at 0x131, simple chaining preserves absolute offset
    ordering.
    """
    for p in PARTITION_TABLE:
        yield p
    for f in FLAT_FIELD_TABLE:
        yield f
    for n in NOS_NVM_FIELD_TABLE:
        yield n


def _check_no_overlaps() -> None:
    """Sanity check at import time: no two entry slices overlap.

    If this fires, something in one of the tables is wrong -- overlap
    would mean two entries writing the same bytes.
    """
    last_end = -1
    last_entry: "NosEntry | None" = None
    for e in iter_entries():
        if e.offset < last_end:
            raise AssertionError(
                "NOS entry overlap: "
                f"{last_entry.name} "                # type: ignore[union-attr]
                f"[0x{last_entry.offset:03X}-"       # type: ignore[union-attr]
                f"0x{last_entry.end_offset - 1:03X}] "  # type: ignore[union-attr]
                f"vs {e.name} [0x{e.offset:03X}-"
                f"0x{e.end_offset - 1:03X}]"
            )
        if e.end_offset > NOS_REGION_SIZE:
            raise AssertionError(
                f"NOS entry {e.name} at 0x{e.offset:03X} extends past "
                f"NOS end 0x{NOS_REGION_SIZE:03X}"
            )
        last_end = max(last_end, e.end_offset)
        last_entry = e


_check_no_overlaps()


# ---- High-level API -----------------------------------------------

def decode_field(nos: bytes, entry: "NosEntry") -> Any:
    """Decode one entry's value from the NOS region.

    ``entry`` is either a :class:`NosPartition` (Tier 1) or a
    :class:`NosFlatField` (Tier 2); the decode path uses only the
    shared ``offset``/``width``/``prot``/``fmt`` attributes.
    """
    raw = nos[entry.offset:entry.offset + entry.on_disk_width]
    primary = unpack_primary(raw, entry.prot, entry.width)
    return _DECODERS[entry.fmt](primary)


def encode_field_primary(entry: "NosEntry", value: Any) -> bytes:
    """Encode a JSON value into primary bytes (length == entry.width)."""
    primary = _ENCODERS[entry.fmt](value, entry.width)
    if len(primary) != entry.width:
        raise ValueError(
            f"entry {entry.name!r}: encoder produced {len(primary)} "
            f"bytes, expected {entry.width}"
        )
    return primary


def encode_field_on_disk(entry: "NosEntry", value: Any) -> bytes:
    """Encode a JSON value into the full on-disk bytes for that entry.

    Applies the protection layer (mirror, checksum) as appropriate.
    """
    primary = encode_field_primary(entry, value)
    return _PACKERS[entry.prot](primary)


def decode_nos_fields(nos: bytes) -> dict[str, dict[str, Any]]:
    """Decode every known NOS entry from a 512-byte NOS region.

    Returns a nested dict with the three-tier shape used by the
    schema-v3 sidecar::

        {
            "partitions":     {<NosPartition name>: value, ...},
            "flat_fields":    {<NosFlatField name>: value, ...},
            "nos_nvm_fields": {<NosNvmField name>:  value, ...},
        }

    Raises ValueError if ``nos`` is shorter than NOS_REGION_SIZE. Does
    *not* verify mirror/checksum integrity -- the primary copy is
    trusted. Use :func:`diagnose_nos_fields` for integrity checking.
    """
    if len(nos) < NOS_REGION_SIZE:
        raise ValueError(
            f"NOS region too short: {len(nos)} bytes "
            f"(expected >= {NOS_REGION_SIZE})"
        )
    return {
        "partitions": {
            p.name: decode_field(nos, p) for p in PARTITION_TABLE
        },
        "flat_fields": {
            f.name: decode_field(nos, f) for f in FLAT_FIELD_TABLE
        },
        "nos_nvm_fields": {
            n.name: decode_field(nos, n) for n in NOS_NVM_FIELD_TABLE
        },
    }


def _raise_misplaced_names(
    unknown_in_bucket: set[str],
    bucket_label: str,
    other_buckets: "list[tuple[dict[str, Any], str]]",
) -> None:
    """Build a tier-aware KeyError for names that landed in the wrong dict.

    ``other_buckets`` is a list of ``(lookup_dict, human_label)`` pairs.
    Names that are valid in one of those buckets are reported with a
    "these names belong to <label>" hint; anything else is reported as
    genuinely unknown.
    """
    misplaced_by_label: dict[str, list[str]] = {}
    really_unknown = set(unknown_in_bucket)
    for other_dict, other_label in other_buckets:
        hits = sorted(really_unknown & set(other_dict))
        if hits:
            misplaced_by_label[other_label] = hits
            really_unknown -= set(hits)
    msgs: list[str] = []
    if really_unknown:
        msgs.append(
            f"unknown {bucket_label} entry/entries: "
            + ", ".join(sorted(really_unknown))
        )
    for label, names in misplaced_by_label.items():
        msgs.append(
            f"these names are {label}, not {bucket_label} entries: "
            + ", ".join(names)
        )
    raise KeyError("; ".join(msgs))


def overlay_nos_fields(
    nos_base: bytes,
    *,
    partitions: Optional[dict[str, Any]] = None,
    flat_fields: Optional[dict[str, Any]] = None,
    nos_nvm_fields: Optional[dict[str, Any]] = None,
) -> bytes:
    """Return a new NOS region with requested entries re-encoded over ``nos_base``.

    Tier-aware signature: Tier-1 partition values go in ``partitions``,
    Tier-2 flat field values go in ``flat_fields``, and Tier-3 NOS NVM
    extension values go in ``nos_nvm_fields``. Unknown names in the
    wrong bucket raise ``KeyError`` -- e.g. passing ``boot_flags2`` (a
    Tier-2 flat field) in ``partitions=`` is refused because it would
    otherwise silently no-op.

    Strategy (base + overlay with preservation-on-equality):

    1. Start from a mutable copy of ``nos_base``.
    2. For each entry whose name is present in the matching dict,
       compute the requested primary bytes.
    3. If the requested primary bytes equal the current primary bytes
       in the base, skip this entry entirely -- its mirror/checksum
       bytes stay verbatim. This correctly preserves quirky states
       like uninitialized-prot2 fields (0xFF/0xFF on disk, which
       deliberately fails the mirror XOR check).
    4. Otherwise, re-encode the entry (primary + mirror + checksum as
       dictated by ``entry.prot``) and splice it into the buffer.

    Entries absent from all dicts are not touched.
    """
    if len(nos_base) != NOS_REGION_SIZE:
        raise ValueError(
            f"NOS base must be exactly {NOS_REGION_SIZE} bytes, got "
            f"{len(nos_base)}"
        )

    partitions = dict(partitions) if partitions else {}
    flat_fields = dict(flat_fields) if flat_fields else {}
    nos_nvm_fields = dict(nos_nvm_fields) if nos_nvm_fields else {}

    # Validate names up front so a typo doesn't partially apply some
    # writes before raising. Tier-cross-contamination (e.g. putting a
    # flat_field name in partitions=) is flagged with a tier hint so
    # the caller can fix their JSON structure rather than their name.
    unknown_partitions = set(partitions) - set(_PARTITION_BY_NAME)
    if unknown_partitions:
        _raise_misplaced_names(
            unknown_partitions,
            "partitions",
            [
                (_FLAT_FIELD_BY_NAME, "Tier-2 flat fields"),
                (_NOS_NVM_FIELD_BY_NAME, "Tier-3 NOS NVM fields"),
            ],
        )

    unknown_flat = set(flat_fields) - set(_FLAT_FIELD_BY_NAME)
    if unknown_flat:
        _raise_misplaced_names(
            unknown_flat,
            "flat_fields",
            [
                (_PARTITION_BY_NAME, "Tier-1 partitions"),
                (_NOS_NVM_FIELD_BY_NAME, "Tier-3 NOS NVM fields"),
            ],
        )

    unknown_nos_nvm = set(nos_nvm_fields) - set(_NOS_NVM_FIELD_BY_NAME)
    if unknown_nos_nvm:
        _raise_misplaced_names(
            unknown_nos_nvm,
            "nos_nvm_fields",
            [
                (_PARTITION_BY_NAME, "Tier-1 partitions"),
                (_FLAT_FIELD_BY_NAME, "Tier-2 flat fields"),
            ],
        )

    buf = bytearray(nos_base)

    # Iterate in offset order across all three tiers. This matters for
    # the counter_state auto-fill below: counter_data (0x06C) must
    # already be written to ``buf`` by the time we reach counter_state
    # (0x0B2).
    for entry in iter_entries():
        if entry.tier == "partition":
            source = partitions
        elif entry.tier == "flat_field":
            source = flat_fields
        else:  # nos_nvm_field
            source = nos_nvm_fields
        if entry.name not in source:
            continue
        value = source[entry.name]

        # counter_state Shape A: dict without an explicit ``checksum``
        # key means "recompute from counter_data".
        if (
            entry.name == "counter_state"
            and isinstance(value, dict)
            and "checksum" not in value
        ):
            cd = get_partition("counter_data")
            cd_bytes = bytes(buf[cd.offset:cd.end_offset])
            cksum = 0
            for b in cd_bytes:
                cksum ^= b
            value = dict(value)
            value["checksum"] = "0x{:02X}".format(cksum)

        requested_primary = encode_field_primary(entry, value)
        current_primary = bytes(buf[entry.offset:entry.offset + entry.width])
        if requested_primary == current_primary:
            # No change -- preserve base bytes (mirror/checksum included).
            continue
        on_disk = _PACKERS[entry.prot](requested_primary)
        assert len(on_disk) == entry.on_disk_width, (
            f"packer for {entry.name!r} produced {len(on_disk)} bytes, "
            f"expected {entry.on_disk_width}"
        )
        buf[entry.offset:entry.offset + entry.on_disk_width] = on_disk

    return bytes(buf)


# ---- Cross-field consistency checks --------------------------------
#
# Some NOS fields carry integrity information about *other* NOS
# fields (currently: counter_state.checksum covers counter_data).
# Unlike the intra-field prot0/2/3 mirror and checksum bytes -- which
# are always deterministically recomputed by the packers -- these
# cross-field invariants depend on whichever values the user chose to
# write, so we cannot silently "fix" them without second-guessing the
# caller. Instead, ``check_nos_consistency`` reports every broken
# invariant, and the caller (``plugin.pack``) decides whether to
# refuse the input or continue under an explicit ``--force`` override.

@dataclass(frozen=True)
class NosConsistencyIssue:
    """One cross-field invariant that the current NOS bytes violate."""

    name: str
    description: str
    message: str


@dataclass(frozen=True)
class NosConsistencyCheck:
    """A registered cross-field invariant.

    ``verify(nos)`` returns ``(True, None)`` when the invariant holds,
    or ``(False, detail_message)`` when it is violated.

    ``covered_fields`` lists every NOS field whose bytes are
    semantically "covered" by this check. When a ``base`` buffer is
    supplied to :func:`check_nos_consistency`, a failing invariant is
    reported only if at least one of these fields' bytes differ
    between ``base`` and the buffer being checked -- otherwise the
    failure is *inherited* from the base (e.g. an uninitialized dump
    whose counter_state.checksum = 0xFF does not match its zero XOR)
    and round-tripping it byte-identically must not be blocked.
    """

    name: str
    description: str
    covered_fields: tuple[str, ...]
    verify: Callable[[bytes], "tuple[bool, Optional[str]]"]


def _xor_over_field(nos: bytes, entry_name: str) -> int:
    e = get_entry(entry_name)
    cksum = 0
    for b in nos[e.offset:e.end_offset]:
        cksum ^= b
    return cksum & 0xFF


def _check_counter_state_checksum(
    nos: bytes,
) -> "tuple[bool, Optional[str]]":
    cs = get_entry("counter_state")
    # counter_state byte 1 is the stored XOR of all 70 counter_data bytes.
    stored = nos[cs.offset + 1]
    computed = _xor_over_field(nos, "counter_data")
    if stored == computed:
        return (True, None)
    return (
        False,
        "counter_state.checksum = 0x{:02X}, but XOR of counter_data "
        "bytes = 0x{:02X}".format(stored, computed),
    )


# Ordered registry of cross-field invariants. New entries are append-
# only; every entry must be documented in the Layout doc.
CONSISTENCY_CHECKS: list[NosConsistencyCheck] = [
    NosConsistencyCheck(
        name="counter_state.checksum_over_counter_data",
        description=(
            "counter_state byte[1] must equal the XOR of all 70 "
            "counter_data bytes (see Layout doc section 10)"
        ),
        covered_fields=("counter_data", "counter_state"),
        verify=_check_counter_state_checksum,
    ),
]


def _fields_changed(
    nos: bytes, base: bytes, entry_names: Iterable[str],
) -> bool:
    """True if any byte in any of ``entry_names`` differs between nos and base."""
    for name in entry_names:
        e = get_entry(name)
        if nos[e.offset:e.end_offset] != base[e.offset:e.end_offset]:
            return True
    return False


def list_consistency_violations(nos: bytes) -> list[str]:
    """Return the names of every currently-violated invariant.

    A convenience wrapper around ``check_nos_consistency(nos,
    base=None)`` for callers that only need the check names (e.g.
    unpack recording them into the sidecar for later suppression
    during pack).
    """
    return [i.name for i in check_nos_consistency(nos, base=None)]


def check_nos_consistency(
    nos: bytes,
    base: Optional[bytes] = None,
    *,
    allowed_violations: "Iterable[str] | None" = None,
) -> list[NosConsistencyIssue]:
    """Return the list of violated cross-field invariants.

    An empty list means every registered invariant holds.

    When ``base`` is supplied, failing invariants are *only* reported
    if at least one of the check's ``covered_fields`` has changed
    between ``base`` and ``nos``. Pre-existing inconsistencies
    inherited from ``base`` are suppressed so a byte-identical
    round-trip of a partially-uninitialized dump does not get blocked.

    When ``allowed_violations`` is supplied, any invariant whose
    ``name`` appears in that set is suppressed unconditionally. This
    is used by the synthesize-from-scratch pack path, which has no
    pre-overlay base to diff against: the set is built by unpack
    (``list_consistency_violations``) and travels through
    ``nos_fields.json`` as ``"_pre_existing_violations"``. A violation
    that is *not* in the allow-list is a freshly authored violation
    and gets reported.

    When both are ``None``, every violation is reported -- use this
    for raw diagnostics or when validating standalone content.
    """
    if len(nos) != NOS_REGION_SIZE:
        raise ValueError(
            f"NOS region must be exactly {NOS_REGION_SIZE} bytes, got "
            f"{len(nos)}"
        )
    if base is not None and len(base) != NOS_REGION_SIZE:
        raise ValueError(
            f"NOS base must be exactly {NOS_REGION_SIZE} bytes, got "
            f"{len(base)}"
        )
    allowed = set(allowed_violations) if allowed_violations else set()
    issues: list[NosConsistencyIssue] = []
    for c in CONSISTENCY_CHECKS:
        ok, msg = c.verify(nos)
        if ok:
            continue
        if c.name in allowed:
            continue
        if base is not None and not _fields_changed(
            nos, base, c.covered_fields
        ):
            # Violation is inherited verbatim from the base; skip.
            continue
        issues.append(NosConsistencyIssue(
            name=c.name,
            description=c.description,
            message=msg or "invariant violated",
        ))
    return issues


def format_consistency_error(
    issues: list[NosConsistencyIssue],
    sidecar_name: str = "nos_fields.json",
) -> str:
    """Build a human-readable error message with remediation options."""
    lines = ["NOS consistency check failed:", ""]
    for i in issues:
        lines.append(f"  {i.name}:")
        lines.append(f"    {i.message}")
        lines.append(f"    ({i.description})")
        lines.append("")
    lines.append("To resolve, pick one:")
    lines.append(
        f"  1. Auto-fill: remove the checksum key(s) from {sidecar_name} "
        "(pack will recompute them)."
    )
    lines.append(
        "  2. Hand-fix: update the checksum value(s) to match the "
        "recomputed bytes shown above."
    )
    lines.append(
        "  3. Bypass: re-run pack with --force to write a deliberately "
        "inconsistent region (never alters encoder semantics; only "
        "suppresses this safety check)."
    )
    return "\n".join(lines)


def diagnose_nos_fields(nos: bytes) -> list[dict[str, Any]]:
    """Return a list of per-entry diagnostic records.

    Each record has ``name``, ``tier``, ``offset``, ``on_disk_width``,
    ``prot``, ``integrity`` (from `verify_field()`), and ``value``
    (decoded primary). Useful for spotting entries where the dump
    deviates from the protection formulas (e.g. uninitialized prot2
    fields that store 0xFF/0xFF instead of 0xFF/0x00).
    """
    if len(nos) < NOS_REGION_SIZE:
        raise ValueError(
            f"NOS region too short: {len(nos)} bytes "
            f"(expected >= {NOS_REGION_SIZE})"
        )
    out: list[dict[str, Any]] = []
    for e in iter_entries():
        raw = nos[e.offset:e.offset + e.on_disk_width]
        status = verify_field(raw, e.prot, e.width)
        out.append({
            "name": e.name,
            "tier": e.tier,
            "offset": e.offset,
            "on_disk_width": e.on_disk_width,
            "prot": e.prot,
            "integrity": status,
            "value": decode_field(nos, e),
        })
    return out
