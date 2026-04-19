"""Firmware plugin for STMicroelectronics M24256BW EEPROM dumps.

Supports conversion between two variants:

- eeprom: Full 32 KB EEPROM dump file.
- zones: Directory containing the individual zone files extracted from
  the dump.

The M24256BW (256 Kbit = 32 KB) EEPROM uses a layered NVM architecture:

    NOS region  [0x000-0x1FD]   510 B  Bootloader NVM (three tiers):
        Tier 1  [0x000-0x0C1]   194 B  Partitioned fields
                (NVM2_CONTROL, BOARD_ID, SERIAL_NUMBER, BOOT_FLAGS,
                 crash log)
        Tier 2  [0x100-0x130]    49 B  Bootloader flat fields
                (MAP2_VERSION, PCA serial, ETH0/WLAN MACs,
                 POWER_CYCLE_COUNT, SECURE_VARS, BOOT_FLAGS2, ...)
        Tier 3  [0x131-0x1FD]   205 B  NOS NVM extension
                (BackupDevicePin + opaque inter-region filler)

    NVM2 region [0x1FE-0x7FFF] ~31 KB Kernel NVM2 object storage
        - root_page_pointer (2B BE at 0x1FE, kernel-written)
        - NVM2 header (19B at 0x200: magic / version / bitmaps)
        - bitmaps + page-based variable-length TLV objects

Multi-byte bootloader fields are big-endian. The kernel NVM2 region
is managed by the Linux kernel NVM driver; its header and object
metadata are little-endian. NVM2 magic: 0x7EEDC0DE. The 2-byte root-
page pointer that precedes the NVM2 header at 0x01FE is big-endian.

Plugin capabilities
-------------------
* unpack (eeprom -> zones): splits the 32 KB dump into nvm2_region.bin
  (now including the 2-byte root-page pointer prefix at 0x01FE) plus
  these sidecars:
      - eeprom_manifest.json : canonical zone manifest used by pack()
      - nos_fields.json      : decoded NOS fields (schema v3:
                               partitions / flat_fields /
                               nos_nvm_fields); the sole source of
                               truth for the NOS region -- pack()
                               synthesizes 0x000-0x1FD from this
                               sidecar starting from all-0xFF.
      - nvm2_layout.json     : root_page_pointer + NVM2 header + TLV
                               slot map. The root_page_pointer key is
                               authoritative and is applied on top of
                               nvm2_region.bin during pack.
      - nvm2_objects.json    : every TLV record, plus Layer-1 plaintext
                               when --chipid or --duid is supplied
                               (analysis only).

* pack (zones -> eeprom): reassembles the 32 KB dump by (a) splicing
  nvm2_region.bin at 0x01FE, (b) overriding the first 2 bytes with
  nvm2_layout.json's ``root_page_pointer`` when they differ, and
  (c) synthesizing the NOS region (0x000-0x1FD) from scratch by
  overlaying nos_fields.json's three tier dicts onto ``b"\\xFF" *
  0x1FE`` using preserve-on-equality semantics:

      - Entries whose JSON value equals the base are left untouched
        (mirror and checksum bytes pass through verbatim).
      - Entries whose JSON value differs are re-encoded with the
        correct protection layer (prot0 / prot1 / prot2 / prot3 /
        raw) and spliced back into the buffer.
      - ``partitions.nvm2_control`` is validated through the layout
        selector and must remain 0x44 (the only supported sub-
        partition-table variant for this codec).

  The schema v3 sidecar is mandatory -- legacy v1/v2 sidecars are
  refused with a migration hint.
"""

from __future__ import annotations

import json
import logging
import struct
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
from . import nos_codec, nvm2_decoder

logger = logging.getLogger(__name__)

# ---- Constants ------------------------------------------------------

EEPROM_SIZE = 32768  # 32 KB

# Region boundaries in the final EEPROM image:
#
#   NOS         0x0000-0x01FD  (510 B, bootloader-managed, 3 tiers)
#   NVM2        0x01FE-0x7FFF  (31746 B, kernel-managed; includes the
#                               2-byte root-page pointer at 0x01FE)
NOS_REGION_OFFSET = 0x0000
NOS_REGION_SIZE = 0x200    # still 512 B internally for the synth
                           # buffer (last 2 bytes are 0xFF padding,
                           # overwritten by the NVM2 splice below).
NVM2_REGION_OFFSET = 0x01FE
NVM2_REGION_SIZE = EEPROM_SIZE - NVM2_REGION_OFFSET  # 31,746 bytes
# Where the NVM2 header (magic / version / ...) starts, absolute
# EEPROM offset. The 2 bytes that precede it are the big-endian
# root-page pointer (see nvm2_decoder.ROOT_PAGE_POINTER_OFFSET).
NVM2_HEADER_OFFSET = 0x0200
NVM2_MAGIC = b"\xde\xc0\xed\x7e"  # 0x7EEDC0DE as LE uint32

# Schema version emitted by unpack() and required by pack() for
# nos_fields.json. v3 introduced the tier-3 ``nos_nvm_fields`` bucket
# and migrated the NVM2 root-page pointer out of the NOS region.
NOS_FIELDS_SCHEMA_VERSION = 3

# Variant identifiers
VARIANT_EEPROM = "eeprom"
VARIANT_ZONES = "zones"

MANIFEST_NAME = "eeprom_manifest.json"

# Sidecar JSON files produced by unpack().
#
# nos_fields.json is the *sole* source of truth for the NOS region:
# pack() synthesizes 0x000-0x1FD from it, starting from all-0xFF,
# applying preserve-on-equality semantics on a per-entry basis.
#
# nvm2_layout.json's ``root_page_pointer`` key is authoritative for
# the 2 bytes at 0x01FE. The rest of nvm2_layout.json and all of
# nvm2_objects.json are analysis-only -- pack() reassembles the NVM2
# body byte-for-byte from nvm2_region.bin.
NOS_FIELDS_NAME = "nos_fields.json"
NVM2_LAYOUT_NAME = "nvm2_layout.json"
NVM2_OBJECTS_NAME = "nvm2_objects.json"

# ---- NOS tier offsets ---------------------------------------------
#
# The authoritative source of truth for NOS Tier-1/Tier-2/Tier-3
# entry offsets, widths, protection types, and serialization is
# ``nos_codec.PARTITION_TABLE`` / ``FLAT_FIELD_TABLE`` /
# ``NOS_NVM_FIELD_TABLE``. Anything that needs an offset should go
# through ``nos_codec.get_partition(name)`` /
# ``nos_codec.get_flat_field(name)`` /
# ``nos_codec.get_nos_nvm_field(name)`` (or tier-agnostic
# ``nos_codec.get_entry(name)``) rather than a module-level constant
# here.

# ---- NVM2 header offsets (rel. to NVM2 header start, 0x200) -------
NVM2_HDR_MAGIC = 0x00
NVM2_HDR_VERSION_INFO = 0x04
NVM2_HDR_OBJECT_COUNT = 0x08
NVM2_HDR_MAX_OBJECTS = 0x0A
NVM2_HDR_ALLOC_BITMAP = 0x0C
NVM2_HDR_SPAN_BITMAP = 0x0E
NVM2_HDR_DEBUG_LEVEL = 0x10
NVM2_HDR_GENERATION = 0x11
NVM2_HEADER_SIZE = 0x13


def _extract_nos_identity(data: bytes) -> dict[str, dict[str, Any]]:
    """Decode every NOS entry into the schema-v3 tier-split layout.

    This is a thin wrapper around :func:`nos_codec.decode_nos_fields`
    that validates input length and delegates the actual work. The
    returned dict has the schema-v3 shape::

        {
            "partitions":     {<NosPartition name>: value, ...},
            "flat_fields":    {<NosFlatField name>: value, ...},
            "nos_nvm_fields": {<NosNvmField name>:  value, ...},
        }

    Coverage: 35 entries spanning 0x000-0x1FD contiguously. Tier 1
    contributes 20 partitions (0x000-0x0C1, including 7 opaque
    firmware-internal entries). Tier 2 contributes 13 flat fields
    (0x100-0x130). Tier 3 contributes 2 NOS NVM extension entries
    (BackupDevicePin @ 0x131 and the nos_nvm_reserved filler that
    runs from 0x135 up to the NVM2 root-page pointer at 0x1FE).
    """
    return nos_codec.decode_nos_fields(data)


def _extract_nvm2_header(data: bytes) -> dict[str, Any]:
    """Extract the NVM2 header fields (19 bytes starting at the caller-supplied slice).

    The caller passes a bytes object whose byte 0 is the NVM2 magic
    (i.e. ``eeprom_data[NVM2_HEADER_OFFSET:]``). All header offsets
    in this function are relative to byte 0 of that slice.
    """
    if len(data) < NVM2_HEADER_SIZE:
        raise ValueError(
            "NVM2 header slice too short: {} bytes (expected >= {})".format(
                len(data), NVM2_HEADER_SIZE
            )
        )

    (magic,) = struct.unpack_from("<I", data, NVM2_HDR_MAGIC)
    (version_info,) = struct.unpack_from("<I", data, NVM2_HDR_VERSION_INFO)
    (object_count,) = struct.unpack_from("<H", data, NVM2_HDR_OBJECT_COUNT)
    (max_objects,) = struct.unpack_from("<H", data, NVM2_HDR_MAX_OBJECTS)
    (alloc_bitmap_offset,) = struct.unpack_from(
        "<H", data, NVM2_HDR_ALLOC_BITMAP
    )
    (span_bitmap_offset,) = struct.unpack_from(
        "<H", data, NVM2_HDR_SPAN_BITMAP
    )
    debug_level = data[NVM2_HDR_DEBUG_LEVEL]
    (generation,) = struct.unpack_from("<H", data, NVM2_HDR_GENERATION)

    key_id = (version_info >> 16) & 0xFFFF
    version = version_info & 0xFFFF

    return {
        "magic": "0x{:08X}".format(magic),
        "version_info": "0x{:08X}".format(version_info),
        "key_id": key_id,
        "version": version,
        "object_count": object_count,
        "max_objects": max_objects,
        "alloc_bitmap_offset": "0x{:04X}".format(alloc_bitmap_offset),
        "span_bitmap_offset": "0x{:04X}".format(span_bitmap_offset),
        "debug_level": "0x{:02X}".format(debug_level),
        "generation_counter": generation,
    }


def _resolve_duid(
    chipid_hex: str | None,
    duid_hex: str | None,
) -> bytes | None:
    """Turn the --chipid / --duid CLI options into a 32-byte DUID.

    Returns None when neither option was supplied. Raises ValueError
    when both are supplied, or when the hex is malformed.
    """
    if chipid_hex and duid_hex:
        raise ValueError("Supply either --chipid OR --duid, not both")
    if duid_hex:
        return nvm2_decoder.parse_hex_arg(duid_hex, 32, "--duid")
    if chipid_hex:
        chipid = nvm2_decoder.parse_hex_arg(chipid_hex, 16, "--chipid")
        return nvm2_decoder.duid_from_chipid(chipid)
    return None


class Plugin(FirmwarePlugin):
    """M24256BW EEPROM firmware plugin."""

    # ---- Metadata --------------------------------------------------

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="EEPROM M24256BW",
            description=(
                "STMicroelectronics M24256BW 32 KB I2C EEPROM dump "
                "handler. Splits a full dump into NOS region "
                "(bootloader NVM) and NVM2 region (kernel object "
                "store), or reassembles them. Emits JSON sidecars with "
                "decoded NOS fields, NVM2 layout, and per-object TLV "
                "records (with Layer-1 XOR decryption when --chipid "
                "or --duid is supplied)."
            ),
            version="0.2.0",
            format_id="hp_clj_pro_4301_eeprom",
            supported_variants=[VARIANT_EEPROM, VARIANT_ZONES],
            conversions=self.get_conversions(),
            ksy_files=["hp_clj_pro_4301_eeprom.ksy"],
        )

    # ---- Options ---------------------------------------------------

    def get_options(self) -> list[PluginOption]:
        """Plugin CLI options.

        unpack:
            --chipid / --duid : enable Layer-1 XOR decryption of NVM2
            objects. Both are optional; without them the sidecar still
            lists every record and its ciphertext, just no plaintext.

        pack:
            --force : bypass NOS cross-field consistency checks (e.g.
            counter_state.checksum must equal the XOR of counter_data).
            Never alters encoder semantics -- the bytes written are
            still fully determined by the sidecar JSON. Use only when
            you deliberately want an inconsistent region (boot-recovery
            fuzzing, etc.).
        """
        return [
            PluginOption(
                flag="--chipid",
                description=(
                    "16-byte SoC chip ID (32 hex chars). The 32-byte "
                    "DUID is derived as "
                    "SHA-256(chipid || CRC32_BE(chipid)). Enables "
                    "Layer-1 XOR decryption of NVM2 objects."
                ),
                kwarg_name="chipid",
                applies_to="unpack",
                takes_value=True,
                metavar="HEX32",
            ),
            PluginOption(
                flag="--duid",
                description=(
                    "32-byte NVRAM Device UID (64 hex chars). "
                    "Alternative to --chipid when the DUID has already "
                    "been recovered."
                ),
                kwarg_name="duid",
                applies_to="unpack",
                takes_value=True,
                metavar="HEX64",
            ),
            PluginOption(
                flag="--force",
                description=(
                    "Bypass NOS cross-field consistency checks during "
                    "pack. Encoder semantics are unchanged; the flag "
                    "only suppresses the safety error that fires when "
                    "counter_state.checksum does not match counter_data."
                ),
                kwarg_name="force",
                applies_to="pack",
                takes_value=False,
            ),
        ]

    # ---- Identification --------------------------------------------

    def identify(self, path: Path) -> str | None:
        # Directory with manifest -> zones
        if path.is_dir():
            manifest = path / MANIFEST_NAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                    if data.get("format_id") == "hp_clj_pro_4301_eeprom":
                        return VARIANT_ZONES
                except Exception:
                    pass
            return None

        # File: must be exactly 32 KB with NVM2 magic at 0x200
        if path.stat().st_size != EEPROM_SIZE:
            return None

        with open(path, "rb") as f:
            # NVM2 magic is at NVM2_HEADER_OFFSET (0x0200); the 2
            # bytes at NVM2_REGION_OFFSET (0x01FE-0x01FF) are the
            # kernel-managed root-page pointer that physically
            # precedes the header.
            f.seek(NVM2_HEADER_OFFSET)
            magic = f.read(4)
            if magic == NVM2_MAGIC:
                return VARIANT_EEPROM

        return None

    # ---- Conversions -----------------------------------------------

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_EEPROM,
                target_variant=VARIANT_ZONES,
                description="Extract EEPROM regions (NOS + NVM2)",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_ZONES,
                target_variant=VARIANT_EEPROM,
                description="Reassemble EEPROM from region files",
                lossy=False,
            ),
        ]

    # ---- Unpack (eeprom -> zones) ----------------------------------

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
        if source_variant != VARIANT_EEPROM:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_EEPROM}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_ZONES
        source_hash = file_sha256(input_path)

        # Resolve optional decryption key (--chipid / --duid).
        duid = _resolve_duid(kwargs.get("chipid"), kwargs.get("duid"))

        eeprom_data = input_path.read_bytes()
        if len(eeprom_data) != EEPROM_SIZE:
            raise ValueError(
                f"Expected {EEPROM_SIZE} bytes, got {len(eeprom_data)}"
            )

        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Unpacking EEPROM %s (%d bytes) -> %s/ "
            "(1 zone + 3 JSON sidecars)",
            input_path.name, len(eeprom_data), output_path.name,
        )
        if duid is not None:
            logger.info(
                "  Layer-1 decryption enabled (DUID=%s...)",
                duid[:8].hex(),
            )

        # Validate the sub-partition-table selector (NOS byte 0x000)
        # before decoding anything else. The codec is only valid for
        # NVM2_CONTROL values whose layout has been verified; other
        # documented variants would shift every Tier-1 field offset.
        #
        # We decode the 0x000-0x1FD range (all three NOS tiers) for
        # the sidecar; the trailing 2 bytes at 0x1FE-0x1FF belong to
        # the NVM2 root-page pointer and are handled via
        # nvm2_layout.json / nvm2_region.bin, not via nos_codec.
        nos_decode_window = eeprom_data[
            NOS_REGION_OFFSET:NOS_REGION_OFFSET + NOS_REGION_SIZE
        ]
        nos_codec.validate_layout_selector(nos_decode_window[0])

        # Extract NVM2 region (0x01FE-0x7FFF, kernel-managed, now
        # includes the 2-byte root-page pointer as its prefix).
        nvm2_region_data = eeprom_data[NVM2_REGION_OFFSET:]
        nvm2_file = output_path / "nvm2_region.bin"
        nvm2_file.write_bytes(nvm2_region_data)
        nvm2_sha = file_sha256(nvm2_file)
        logger.info(
            "  nvm2_region     offset=0x%04X  size=%5d  %s",
            NVM2_REGION_OFFSET, len(nvm2_region_data), nvm2_sha[:16],
        )

        # Extract identity metadata from NOS region (Tier 1 + Tier 2 + Tier 3)
        identity = _extract_nos_identity(nos_decode_window)
        logger.info(
            "  Identity: serial=%s  eth0=%s  wlan0=%s  pca=%s",
            identity["partitions"]["serial_number"],
            identity["flat_fields"]["eth0_mac"],
            identity["flat_fields"]["wlan0_mac"],
            identity["flat_fields"]["pca_serial"],
        )

        # Extract NVM2 header metadata (the 19-byte header starts at
        # NVM2_HEADER_OFFSET = 0x0200; the 2 bytes preceding it are
        # the root-page pointer and live in nvm2_layout.json).
        nvm2_header_slice = eeprom_data[NVM2_HEADER_OFFSET:]
        nvm2_header = _extract_nvm2_header(nvm2_header_slice)
        root_page_pointer = nvm2_decoder.parse_root_page_pointer(eeprom_data)
        logger.info(
            "  NVM2: root_ptr=0x%04X  magic=%s  objects=%d/%d  generation=%d",
            root_page_pointer,
            nvm2_header["magic"],
            nvm2_header["object_count"],
            nvm2_header["max_objects"],
            nvm2_header["generation_counter"],
        )

        # Sidecar JSON.
        #
        # 1. nos_fields.json  : decoded NOS entries (all three tiers).
        #                       Sole source of truth for the NOS
        #                       region: pack() synthesizes 0x000-0x1FD
        #                       from this sidecar alone.
        # 2. nvm2_layout.json : root_page_pointer + NVM2 header + TLV
        #                       slot map. root_page_pointer is
        #                       authoritative; the rest is analysis
        #                       only.
        # 3. nvm2_objects.json: every TLV record, optionally with
        #                       Layer-1 plaintext (--chipid/--duid)
        #                       (analysis only).

        # Record any cross-field consistency violations present in the
        # source dump. pack() uses these names to suppress expected
        # failures (e.g. uninitialised counter_state.checksum 0xFF vs
        # counter_data XOR 0x00) so byte-identical round-trip still
        # works; any violation the caller subsequently *authors* by
        # editing the sidecar is still caught.
        pre_existing_violations = nos_codec.list_consistency_violations(
            nos_decode_window
        )
        if pre_existing_violations:
            logger.info(
                "  NOS pre-existing consistency violations: %s",
                ", ".join(pre_existing_violations),
            )

        nos_fields_path = output_path / NOS_FIELDS_NAME
        nos_fields_path.write_text(json.dumps(
            {
                "_schema": "hp_clj_pro_4301_eeprom/nos_fields.json",
                "schema_version": NOS_FIELDS_SCHEMA_VERSION,
                "_note": (
                    "Decoded bootloader NOS region (0x000-0x1FD), "
                    f"schema v{NOS_FIELDS_SCHEMA_VERSION}. Three "
                    "tiers: ``partitions`` = Tier-1 entries (0x000-"
                    "0x0C1) keyed by the bootloader's partition-table "
                    "``part_id``, stored with primary/mirror/checksum "
                    "protection (prot0/1/2/3); ``flat_fields`` = "
                    "Tier-2 entries (0x100-0x130) keyed by the "
                    "bootloader flat-table ``field_id``, mostly raw "
                    "(prot1); ``nos_nvm_fields`` = Tier-3 entries "
                    "(0x131-0x1FD), NOS NVM extension region managed "
                    "only by libNvram.so userspace plus opaque inter-"
                    "region filler. This sidecar is the sole source "
                    "of truth: pack() synthesizes the NOS region from "
                    "scratch starting from all-0xFF, using preserve-"
                    "on-equality semantics -- an entry whose value "
                    "matches the synthesized base keeps its mirror/"
                    "checksum bytes untouched, while a changed entry "
                    "is re-encoded under the correct protection "
                    "layer. The ``partitions.nvm2_control`` field is "
                    "guarded by validate_layout_selector: any value "
                    "whose layout has not been verified is refused."
                ),
                "source_sha256": source_hash,
                "_pre_existing_violations": pre_existing_violations,
                "partitions": identity["partitions"],
                "flat_fields": identity["flat_fields"],
                "nos_nvm_fields": identity["nos_nvm_fields"],
            },
            indent=2,
        ))

        decoder_hdr, decoder_records = nvm2_decoder.walk(
            eeprom_data, nvm2_offset=NVM2_HEADER_OFFSET, duid=duid,
        )
        if decoder_hdr.object_count != len(decoder_records):
            logger.warning(
                "NVM2 object_count in header (%d) != TLV records "
                "walked (%d)",
                decoder_hdr.object_count, len(decoder_records),
            )

        layout_json = nvm2_decoder.build_layout_json(
            decoder_hdr, decoder_records,
            root_page_pointer=root_page_pointer,
        )
        layout_path = output_path / NVM2_LAYOUT_NAME
        layout_path.write_text(json.dumps(layout_json, indent=2))

        objects_json = nvm2_decoder.build_objects_json(
            decoder_records,
            duid_used=(duid is not None),
            source_sha256=source_hash,
        )
        objects_path = output_path / NVM2_OBJECTS_NAME
        objects_path.write_text(json.dumps(objects_json, indent=2))

        if duid is not None:
            logger.info(
                "  NVM2 records decoded with Layer-1 plaintext: %d",
                len(decoder_records),
            )
        else:
            logger.info(
                "  NVM2 records walked (ciphertext only): %d",
                len(decoder_records),
            )

        # Write manifest (carries only metadata not otherwise
        # reachable: zone list, NVM2 header summary, root-page
        # pointer hint). The decoded NOS region lives in
        # ``nos_fields.json`` alone and is not duplicated here.
        #
        # Schema v5: nos_region.bin has been removed. The NOS region
        # is synthesized at pack time from nos_fields.json (schema v3)
        # alone. nvm2_region.bin now starts at 0x01FE to include the
        # 2-byte root-page pointer as its prefix; the authoritative
        # value for those 2 bytes is in nvm2_layout.json.
        # Schema v6: the ``identity`` key (a full copy of the decoded
        # NOS region) has been removed -- that data now lives in
        # ``nos_fields.json`` alone. Consumers that want a quick
        # identity summary should json.loads() that sidecar directly.
        # Schema v7: the ``nvm2_header`` and ``root_page_pointer`` keys
        # have been removed from the manifest (and from
        # ``UnpackResult.metadata``). Both were verbatim copies of
        # fields that already live in ``nvm2_layout.json``; that
        # sidecar is now the sole source of truth for NVM2 layout
        # metadata. Consumers that want those values should
        # json.loads() ``nvm2_layout.json`` directly.
        manifest = {
            "format_id": "hp_clj_pro_4301_eeprom",
            "version": 7,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "eeprom_size": EEPROM_SIZE,
            "zones": [
                {
                    "name": "nvm2_region",
                    "filename": "nvm2_region.bin",
                    "offset": NVM2_REGION_OFFSET,
                    "size": NVM2_REGION_SIZE,
                    "sha256": nvm2_sha,
                    "description": (
                        "NVM2 -- kernel page-based object storage "
                        "(includes the 2-byte root-page pointer at its "
                        "first 2 bytes, EEPROM 0x01FE-0x01FF)"
                    ),
                },
            ],
            "sidecars": [
                {
                    "filename": NOS_FIELDS_NAME,
                    "description": (
                        "Decoded NOS entries (schema v3): "
                        "``partitions`` (Tier 1), ``flat_fields`` "
                        "(Tier 2), and ``nos_nvm_fields`` (Tier 3) "
                        "dicts. Sole source of truth for the NOS "
                        "region -- pack() synthesizes 0x000-0x1FD "
                        "from this sidecar alone."
                    ),
                    "analysis_only": False,
                },
                {
                    "filename": NVM2_LAYOUT_NAME,
                    "description": (
                        "root_page_pointer (authoritative) + NVM2 "
                        "header + TLV slot map"
                    ),
                    "analysis_only": False,
                },
                {
                    "filename": NVM2_OBJECTS_NAME,
                    "description": (
                        "Per-object TLV records (with Layer-1 plaintext "
                        "when --chipid/--duid supplied)"
                    ),
                    "analysis_only": True,
                },
            ],
            # NOTE: ``nvm2_header`` and ``root_page_pointer`` are *not*
            # duplicated into the manifest -- those values live
            # authoritatively in ``nvm2_layout.json``. This manifest
            # stays small and zone/sidecar-focused; downstream tools
            # that need NVM2 metadata should json.loads() the layout
            # sidecar directly.
            "nvm2_objects_decoded": len(decoder_records),
            "layer1_decryption_applied": duid is not None,
        }
        # NOTE: The decoded NOS region (partitions / flat_fields /
        # nos_nvm_fields) is *not* duplicated into the manifest or
        # into UnpackResult.metadata. The sole source of truth for
        # those values is ``nos_fields.json``; re-reading that file
        # is a one-line json.loads() for any downstream consumer
        # that wants identity summaries.
        manifest_path = output_path / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash="(directory)",
            metadata={
                "num_zones": 1,
                "zones": {
                    "nvm2_region": NVM2_REGION_SIZE,
                },
                # nvm2_header / root_page_pointer intentionally not
                # duplicated here -- they live in nvm2_layout.json.
                "nvm2_objects_decoded": len(decoder_records),
                "layer1_decryption_applied": duid is not None,
            },
        )

    # ---- Pack (zones -> eeprom) ------------------------------------

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        if source_variant is None:
            if input_path.is_dir():
                source_variant = VARIANT_ZONES
            else:
                source_variant = self.identify(input_path)

        if source_variant != VARIANT_ZONES:
            raise ValueError(
                f"Pack expects variant '{VARIANT_ZONES}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_EEPROM

        if not input_path.is_dir():
            raise ValueError(f"{input_path} is not a directory")

        manifest_path = input_path / MANIFEST_NAME
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"Missing {MANIFEST_NAME} in {input_path}"
            )

        manifest = json.loads(manifest_path.read_text())
        eeprom_size = manifest["eeprom_size"]
        zone_infos = manifest["zones"]

        logger.info(
            "Packing EEPROM %s/ -> %s (%d zones, eeprom_size=%d)",
            input_path.name, output_path.name,
            len(zone_infos), eeprom_size,
        )

        # Pre-fill with 0xFF (erased EEPROM state)
        buf = bytearray(b"\xff" * eeprom_size)

        for zi in zone_infos:
            zone_file = input_path / zi["filename"]
            if not zone_file.exists():
                raise FileNotFoundError(
                    f"Missing zone file: {zi['filename']}"
                )

            data = zone_file.read_bytes()
            offset = zi["offset"]

            # Verify the zone fits within the EEPROM
            if offset + len(data) > eeprom_size:
                raise ValueError(
                    f"Zone '{zi['name']}' at offset 0x{offset:04X} "
                    f"with size {len(data)} exceeds EEPROM size "
                    f"{eeprom_size}"
                )

            buf[offset:offset + len(data)] = data

            logger.info(
                "  %-16s  offset=0x%04X  size=%5d",
                zi["name"], offset, len(data),
            )

        # NOS synthesize-from-scratch.
        #
        # Unlike the pre-schema-v3 path (which overlaid edits on top
        # of a captured nos_region.bin), pack() now builds the NOS
        # region entirely from nos_fields.json. The base is a blank
        # ``b"\xFF" * NOS_REGION_SIZE`` buffer; every entry in all
        # three tiers is re-encoded from the sidecar value.
        #
        # Preserve-on-equality still applies -- an entry whose JSON
        # value encodes to the same primary bytes as the base (0xFF)
        # leaves the mirror/checksum bytes untouched, which matters
        # for uninitialised prot2 fields whose on-disk representation
        # (0xFF/0xFF) deliberately fails the mirror XOR check.
        #
        # The 2 bytes at 0x1FE-0x1FF in the synthesized NOS buffer
        # are left at 0xFF and get overwritten later by the NVM2
        # splice (which places nvm2_region.bin at 0x1FE, and whose
        # first 2 bytes are the root-page pointer).
        #
        # ``partitions.nvm2_control`` is validated through the layout
        # selector: any value whose sub-partition-table variant this
        # codec does not support is refused.
        nos_fields_path = input_path / NOS_FIELDS_NAME
        if not nos_fields_path.exists():
            raise FileNotFoundError(
                f"Missing {NOS_FIELDS_NAME} in {input_path}. The NOS "
                "region is synthesized from this sidecar alone; there "
                "is no nos_region.bin fallback."
            )
        try:
            sidecar = json.loads(nos_fields_path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{NOS_FIELDS_NAME} is not valid JSON: {exc}"
            ) from exc

        # Schema gating: v3 is the only accepted shape. v1 ("fields":
        # {...}) and v2 (no "nos_nvm_fields", no root-page-pointer
        # migration) are refused with a clear re-run hint.
        schema_version = sidecar.get("schema_version")
        if schema_version != NOS_FIELDS_SCHEMA_VERSION:
            if "fields" in sidecar and (
                "partitions" not in sidecar
                and "flat_fields" not in sidecar
            ):
                legacy = "v1 ('fields' blob)"
            elif (
                "partitions" in sidecar
                and "flat_fields" in sidecar
                and "nos_nvm_fields" not in sidecar
            ):
                legacy = "v2 (no 'nos_nvm_fields')"
            else:
                legacy = f"schema_version={schema_version!r}"
            raise ValueError(
                f"{NOS_FIELDS_NAME} is a legacy sidecar ({legacy}). "
                f"This plugin requires schema v{NOS_FIELDS_SCHEMA_VERSION}: "
                "re-run unpack on an EEPROM dump to regenerate. The "
                "new schema adds 'nos_nvm_fields' (Tier 3, "
                "BackupDevicePin + filler at 0x131-0x1FD) and moves "
                "the NVM2 root-page pointer into nvm2_layout.json / "
                "nvm2_region.bin."
            )

        partitions_in = sidecar.get("partitions") or {}
        flat_in = sidecar.get("flat_fields") or {}
        nos_nvm_in = sidecar.get("nos_nvm_fields") or {}

        # Validate the requested nvm2_control selector up front so a
        # typo in the sidecar is rejected before we synthesize
        # anything. The synthesized base has nvm2_control = 0xFF
        # (all-0xFF init), so equality with the base is impossible
        # and the selector is always re-encoded.
        if "nvm2_control" in partitions_in:
            ctrl = nos_codec.get_partition("nvm2_control")
            requested = nos_codec.encode_field_primary(
                ctrl, partitions_in["nvm2_control"],
            )
            nos_codec.validate_layout_selector(requested[0])

        nos_synth_base = b"\xff" * NOS_REGION_SIZE
        nos_synthesized = nos_codec.overlay_nos_fields(
            nos_synth_base,
            partitions=partitions_in,
            flat_fields=flat_in,
            nos_nvm_fields=nos_nvm_in,
        )
        nos_codec.validate_layout_selector(nos_synthesized[0])

        # Log the set of entries that actually changed from the blank
        # base. This matches the old "NOS overlay" log for parity.
        nos_overlay_changes: list[str] = []
        for entry in nos_codec.iter_entries():
            if (
                nos_synth_base[entry.offset:entry.end_offset]
                != nos_synthesized[entry.offset:entry.end_offset]
            ):
                nos_overlay_changes.append(f"{entry.tier}:{entry.name}")
        logger.info(
            "  NOS synthesize: %d entry/entries re-encoded from %s",
            len(nos_overlay_changes), NOS_FIELDS_NAME,
        )

        # Splice the synthesized NOS at 0x000. We only copy the first
        # NVM2_REGION_OFFSET bytes (0x01FE) so the last 2 bytes of
        # the 512-byte synth buffer (always 0xFF, since no entry
        # models them) do not overwrite the root-page-pointer bytes
        # that came from nvm2_region.bin. (For defence-in-depth we
        # also assert those last 2 bytes are 0xFF before splicing.)
        assert nos_synthesized[NVM2_REGION_OFFSET:NOS_REGION_SIZE] == b"\xff\xff", (
            "NOS synthesize produced non-0xFF bytes at 0x1FE-0x1FF "
            "(no entry should model that range)"
        )
        buf[NOS_REGION_OFFSET:NVM2_REGION_OFFSET] = (
            nos_synthesized[NOS_REGION_OFFSET:NVM2_REGION_OFFSET]
        )

        # Root-page-pointer override from nvm2_layout.json.
        #
        # The 2 bytes at 0x01FE-0x01FF arrived via nvm2_region.bin's
        # first 2 bytes. If the sidecar's ``root_page_pointer`` key
        # encodes to a different value, re-write those bytes so the
        # JSON stays authoritative. Missing key = defer to
        # nvm2_region.bin (preserve-on-absence).
        root_pointer_override: str | None = None
        layout_path = input_path / NVM2_LAYOUT_NAME
        if layout_path.exists():
            try:
                layout_sidecar = json.loads(layout_path.read_text())
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{NVM2_LAYOUT_NAME} is not valid JSON: {exc}"
                ) from exc
            if "root_page_pointer" in layout_sidecar:
                rpp_int = nvm2_decoder.parse_root_page_pointer_from_sidecar(
                    layout_sidecar["root_page_pointer"]
                )
                rpp_bytes = nvm2_decoder.encode_root_page_pointer(rpp_int)
                current = bytes(
                    buf[NVM2_REGION_OFFSET:NVM2_REGION_OFFSET + 2]
                )
                if rpp_bytes != current:
                    buf[NVM2_REGION_OFFSET:NVM2_REGION_OFFSET + 2] = rpp_bytes
                    root_pointer_override = (
                        f"0x{current.hex().upper()} -> 0x{rpp_bytes.hex().upper()}"
                    )
                    logger.info(
                        "  NVM2 root_page_pointer: %s (from %s)",
                        root_pointer_override, NVM2_LAYOUT_NAME,
                    )

        # NOS cross-field consistency check.
        #
        # Some NOS fields store integrity information about *other*
        # NOS fields (currently counter_state.checksum covers all 70
        # bytes of counter_data). These invariants cannot be silently
        # fixed up by the packer without second-guessing the user, so
        # we verify them after synthesis and either (a) refuse the
        # pack with a remediation message, or (b) under --force, log
        # and continue so the caller can deliberately write an
        # inconsistent region (boot-recovery fuzzing, etc.).
        #
        # With synthesize-from-scratch there is no pre-overlay
        # "base" to diff against. Instead we honour the sidecar's
        # ``_pre_existing_violations`` list: any check name there is
        # suppressed so uninitialised dumps (where counter_state
        # checksum 0xFF deliberately disagrees with counter_data XOR
        # 0x00) still round-trip byte-identically. A violation *not*
        # in that list means the caller edited the sidecar in a way
        # that newly broke the invariant, and must fix the JSON or
        # use --force.
        force = bool(kwargs.get("force", False))
        allowed_violations = sidecar.get("_pre_existing_violations") or []
        if not isinstance(allowed_violations, list):
            raise ValueError(
                f"{NOS_FIELDS_NAME}: '_pre_existing_violations' must be "
                f"a list of check names, got {type(allowed_violations).__name__}"
            )
        nos_final = bytes(
            buf[NOS_REGION_OFFSET:NOS_REGION_OFFSET + NOS_REGION_SIZE]
        )
        consistency_issues = nos_codec.check_nos_consistency(
            nos_final,
            base=None,
            allowed_violations=allowed_violations,
        )
        if consistency_issues and not force:
            raise ValueError(
                nos_codec.format_consistency_error(
                    consistency_issues, sidecar_name=NOS_FIELDS_NAME,
                )
            )
        if consistency_issues and force:
            logger.warning(
                "NOS consistency check(s) failed; continuing under --force:"
            )
            for issue in consistency_issues:
                logger.warning("  %s: %s", issue.name, issue.message)

        output_path.write_bytes(buf)
        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash="(directory)",
            output_hash=output_hash,
            metadata={
                "num_zones": len(zone_infos),
                "eeprom_size": eeprom_size,
                "nos_synthesized": True,
                "nos_overlay_fields": nos_overlay_changes,
                "root_pointer_override": root_pointer_override,
                "nos_consistency_ok": not consistency_issues,
                "nos_consistency_issues": [
                    {"name": i.name, "message": i.message}
                    for i in consistency_issues
                ],
                "force_applied": force and bool(consistency_issues),
            },
        )

    # ---- Kaitai Struct parsing -------------------------------------

    def parse(self, path: Path, variant: str | None = None) -> Any:
        if variant is None:
            variant = self.identify(path)
        if variant != VARIANT_EEPROM:
            raise ValueError(
                f"Kaitai parsing only supports '{VARIANT_EEPROM}', "
                f"got '{variant}'"
            )

        from .kaitai import HpCljPro4301Eeprom as Parser

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))
