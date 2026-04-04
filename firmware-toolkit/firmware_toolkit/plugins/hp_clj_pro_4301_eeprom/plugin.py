"""Firmware plugin for STMicroelectronics M24256BW EEPROM dumps.

Supports conversion between two variants:

- **eeprom**: Full 32 KB EEPROM dump file.
- **zones**: Directory containing the individual zone files extracted
  from the dump.

The M24256BW (256 Kbit = 32 KB) EEPROM uses a three-tier NVM architecture:

    Tier 1  [0x000-0x0C1]   194 B  Bootloader partitioned fields
            (NVM2_CONTROL, BOARD_ID, SERIAL_NUMBER, BOOT_FLAGS, crash log)
    Tier 2  [0x100-0x131]    50 B  Bootloader flat fields
            (MAP2_VERSION, PCA serial, ETH0/WLAN MACs, POWER_CYCLE_COUNT,
             SECURE_VARS, BOOT_FLAGS2)
    Tier 3  [0x200-0x7FFF]  ~31 KB Kernel NVM2 object storage
            (NVM2 header + bitmaps + page-based variable-length objects)

The NOS region (0x000-0x1FF, 512 B) is managed by the bootloader.
Multi-byte bootloader fields are big-endian.

The kernel NVM2 region (0x200+) is managed by the Linux kernel NVM driver.
Its header and object metadata are little-endian.  NVM2 magic: 0x7EEDC0DE.
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
    UnpackResult,
    file_sha256,
)

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

EEPROM_SIZE = 32768  # 32 KB
NOS_REGION_OFFSET = 0x0000
NOS_REGION_SIZE = 0x200   # 512 bytes (bootloader-managed)
NVM2_REGION_OFFSET = 0x200
NVM2_REGION_SIZE = EEPROM_SIZE - NVM2_REGION_OFFSET  # 31,744 bytes
NVM2_MAGIC = b"\xde\xc0\xed\x7e"  # 0x7EEDC0DE as LE uint32

# Variant identifiers
VARIANT_EEPROM = "eeprom"
VARIANT_ZONES = "zones"

MANIFEST_NAME = "eeprom_manifest.json"

# ── Tier 1: Partitioned field offsets (0x000–0x0C1) ──────────────
# Layout defined by type 0x40 sub-partition table.
# Multi-byte values are big-endian (bootloader NVM_ReadField convention).
PART_NVM2_CONTROL = 0x000       # 1 byte, partition control (0x44 = type 0x40)
PART_MAP_REVISION = 0x005       # 1 byte, NVM map revision
PART_POWER_STATE = 0x006        # 2 bytes (prot2: primary + mirror XOR 0xFF)
PART_BOARD_ID = 0x00C           # 5 bytes (prot0: 2B primary + 2B mirror + 1B checksum)
PART_SERIAL_NUMBER = 0x02F      # 41 bytes (prot3: 20B primary + 20B mirror + 1B checksum)
PART_BOOT_FLAGS = 0x058         # 2 bytes (prot2: primary + mirror)
PART_BOOT_FLAGS3 = 0x05C        # 2 bytes (prot2: primary + mirror)
PART_POWER_STATE2 = 0x05E       # 2 bytes (prot2: primary + mirror)
PART_ASSERT_SEQ_NUM = 0x062     # 4 bytes (prot1, big-endian)
PART_PSKU_CONFIG = 0x066        # 4 bytes (prot1, big-endian)
PART_EEPROM_RECOV_COUNT = 0x06A # 2 bytes (prot1, big-endian)
PART_COUNTER_DATA = 0x06C       # 70 bytes (5 × 14B crash records, big-endian)
PART_COUNTER_STATE = 0x0B2      # 2 bytes (index+bank, XOR checksum)

# ── Tier 2: Flat field offsets (0x100–0x131) ─────────────────────
# 13 fields, contiguous, accessed via flat table (partition_id > 0x80).
# Multi-byte values are big-endian (same NVM_ReadField convention).
FLAT_MAP2_VERSION = 0x100         # 2 bytes, LE (exception: written by kernel)
FLAT_PCA_SERIAL = 0x102           # 10 bytes, ASCII NUL-padded
FLAT_ETH0_MAC = 0x10C             # 6 bytes, network byte order
FLAT_WLAN0_MAC = 0x112            # 6 bytes, network byte order
FLAT_WLAN1_MAC = 0x118            # 6 bytes, network byte order
FLAT_POWER_CYCLE_COUNT = 0x11E    # 2 bytes, big-endian
FLAT_SECURE_VARS = 0x120          # 1 byte (bit2=TBD, bit7=SW Secure Boot override)
FLAT_BOOT_FLAGS2 = 0x121          # 2 bytes, big-endian
FLAT_MISC_1 = 0x123               # 4 bytes
FLAT_SAVE_RECOVER_ID = 0x127      # 4 bytes
FLAT_MPCA_BPCA_PAIRING = 0x12B   # 2 bytes (prot2: primary + mirror)
FLAT_MISC_2 = 0x12D               # 2 bytes
FLAT_UNKNOWN_1C = 0x12F           # 2 bytes

# ── Tier 3: NVM2 header offsets (relative to NVM2 region, 0x200) ─
NVM2_HDR_MAGIC = 0x00           # 4 bytes, LE uint32 (0x7EEDC0DE)
NVM2_HDR_VERSION_INFO = 0x04    # 4 bytes, LE uint32 ((key_id << 16) | version)
NVM2_HDR_OBJECT_COUNT = 0x08    # 2 bytes, LE uint16
NVM2_HDR_MAX_OBJECTS = 0x0A     # 2 bytes, LE uint16
NVM2_HDR_ALLOC_BITMAP = 0x0C    # 2 bytes, LE uint16 (EEPROM offset, e.g. 0x0280)
NVM2_HDR_SPAN_BITMAP = 0x0E     # 2 bytes, LE uint16 (EEPROM offset, e.g. 0x0240)
NVM2_HDR_DEBUG_LEVEL = 0x10     # 1 byte
NVM2_HDR_GENERATION = 0x11      # 2 bytes, LE uint16
NVM2_HEADER_SIZE = 0x13         # 19 bytes total


def _format_mac(raw: bytes) -> str:
    """Format 6 raw bytes as a colon-separated MAC address string."""
    return ":".join("{:02X}".format(b) for b in raw)


def _extract_nos_identity(data: bytes) -> dict[str, Any]:
    """Extract identity fields from the NOS region (512 bytes).

    Reads Tier 1 (partitioned) and Tier 2 (flat) bootloader fields.
    Returns a dict of human-readable field values suitable for
    inclusion in the manifest and UnpackResult metadata.
    """
    if len(data) < NOS_REGION_SIZE:
        raise ValueError(
            "NOS region too short: {} bytes (expected {})".format(
                len(data), NOS_REGION_SIZE
            )
        )

    # ── Tier 1: Partitioned fields ──

    nvm2_control = data[PART_NVM2_CONTROL]
    map_revision = data[PART_MAP_REVISION]

    # POWER_STATE (prot2: primary + mirror)
    power_state = data[PART_POWER_STATE]

    # BOARD_ID (prot0: 2B primary + 2B mirror + 1B checksum)
    board_id_raw = data[PART_BOARD_ID:PART_BOARD_ID + 2]
    board_id = "0x{:02X}{:02X}".format(board_id_raw[0], board_id_raw[1])

    # SERIAL_NUMBER (prot3: 20B primary + 20B mirror + 1B checksum)
    serial_raw = data[PART_SERIAL_NUMBER:PART_SERIAL_NUMBER + 20]
    serial_number = serial_raw.split(b"\x00")[0].decode("ascii", errors="replace")

    # BOOT_FLAGS (prot2: primary + mirror)
    boot_flags = data[PART_BOOT_FLAGS]

    # PSKU_CONFIG (prot1, 4 bytes big-endian)
    (psku_config,) = struct.unpack_from(">I", data, PART_PSKU_CONFIG)

    # EEPROM_RECOV_COUNT (prot1, 2 bytes big-endian)
    (eeprom_recov_count,) = struct.unpack_from(">H", data, PART_EEPROM_RECOV_COUNT)

    # ── Tier 2: Flat fields ──

    # MAP2_VERSION (LE — exception, written by kernel)
    (map2_version,) = struct.unpack_from("<H", data, FLAT_MAP2_VERSION)

    # PcaSerialNumber (10 bytes ASCII)
    pca_serial_raw = data[FLAT_PCA_SERIAL:FLAT_PCA_SERIAL + 10]
    pca_serial = pca_serial_raw.split(b"\x00")[0].decode("ascii", errors="replace")

    # ETH0 MAC at 0x10C
    eth0_mac = _format_mac(data[FLAT_ETH0_MAC:FLAT_ETH0_MAC + 6])

    # WLAN0 MAC at 0x112
    wlan0_mac = _format_mac(data[FLAT_WLAN0_MAC:FLAT_WLAN0_MAC + 6])

    # WLAN1 MAC at 0x118
    wlan1_mac = _format_mac(data[FLAT_WLAN1_MAC:FLAT_WLAN1_MAC + 6])

    # POWER_CYCLE_COUNT at 0x11E (2 bytes, big-endian)
    (power_cycle_count,) = struct.unpack_from(">H", data, FLAT_POWER_CYCLE_COUNT)

    # SECURE_VARS at 0x120
    secure_vars = data[FLAT_SECURE_VARS]

    # BOOT_FLAGS2 at 0x121 (2 bytes, big-endian)
    (boot_flags2,) = struct.unpack_from(">H", data, FLAT_BOOT_FLAGS2)

    return {
        "nvm2_control": "0x{:02X}".format(nvm2_control),
        "map_revision": "0x{:02X}".format(map_revision),
        "power_state": "0x{:02X}".format(power_state),
        "board_id": board_id,
        "serial_number": serial_number,
        "boot_flags": "0x{:02X}".format(boot_flags),
        "psku_config": "0x{:08X}".format(psku_config),
        "eeprom_recov_count": eeprom_recov_count,
        "map2_version": map2_version,
        "pca_serial": pca_serial,
        "eth0_mac": eth0_mac,
        "wlan0_mac": wlan0_mac,
        "wlan1_mac": wlan1_mac,
        "power_cycle_count": power_cycle_count,
        "secure_vars": "0x{:02X}".format(secure_vars),
        "boot_flags2": "0x{:04X}".format(boot_flags2),
    }


def _extract_nvm2_header(data: bytes) -> dict[str, Any]:
    """Extract the NVM2 header fields (19 bytes at EEPROM offset 0x200).

    *data* is the raw NVM2 region bytes (starting at EEPROM offset 0x0200).
    """
    if len(data) < NVM2_HEADER_SIZE:
        raise ValueError(
            "NVM2 region too short: {} bytes (expected >= {})".format(
                len(data), NVM2_HEADER_SIZE
            )
        )

    (magic,) = struct.unpack_from("<I", data, NVM2_HDR_MAGIC)
    (version_info,) = struct.unpack_from("<I", data, NVM2_HDR_VERSION_INFO)
    (object_count,) = struct.unpack_from("<H", data, NVM2_HDR_OBJECT_COUNT)
    (max_objects,) = struct.unpack_from("<H", data, NVM2_HDR_MAX_OBJECTS)
    (alloc_bitmap_offset,) = struct.unpack_from("<H", data, NVM2_HDR_ALLOC_BITMAP)
    (span_bitmap_offset,) = struct.unpack_from("<H", data, NVM2_HDR_SPAN_BITMAP)
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


class Plugin(FirmwarePlugin):
    """M24256BW EEPROM firmware plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="EEPROM M24256BW",
            description=(
                "STMicroelectronics M24256BW 32 KB I2C EEPROM dump handler. "
                "Splits a full dump into NOS region (bootloader NVM) and "
                "NVM2 region (kernel object store), or reassembles them."
            ),
            version="0.1.0",
            format_id="hp_clj_pro_4301_eeprom",
            supported_variants=[VARIANT_EEPROM, VARIANT_ZONES],
            conversions=self.get_conversions(),
            ksy_files=["hp_tx54_eeprom.ksy"],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        # Directory with manifest → zones
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
            f.seek(NVM2_REGION_OFFSET)
            magic = f.read(4)
            if magic == NVM2_MAGIC:
                return VARIANT_EEPROM

        return None

    # ── Conversions ──────────────────────────────────────────────────

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

    # ── Unpack (eeprom → zones) ──────────────────────────────────────

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

        eeprom_data = input_path.read_bytes()
        if len(eeprom_data) != EEPROM_SIZE:
            raise ValueError(
                f"Expected {EEPROM_SIZE} bytes, got {len(eeprom_data)}"
            )

        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Unpacking EEPROM %s (%d bytes) → %s/ (2 regions)",
            input_path.name, len(eeprom_data), output_path.name,
        )

        # Extract NOS region (0x000–0x1FF, bootloader-managed)
        nos_data = eeprom_data[NOS_REGION_OFFSET:NOS_REGION_OFFSET + NOS_REGION_SIZE]
        nos_file = output_path / "nos_region.bin"
        nos_file.write_bytes(nos_data)
        nos_sha = file_sha256(nos_file)
        logger.info(
            "  nos_region      offset=0x%04X  size=%5d  %s",
            NOS_REGION_OFFSET, len(nos_data), nos_sha[:16],
        )

        # Extract NVM2 region (0x200–0x7FFF, kernel-managed)
        nvm2_data = eeprom_data[NVM2_REGION_OFFSET:]
        nvm2_file = output_path / "nvm2_region.bin"
        nvm2_file.write_bytes(nvm2_data)
        nvm2_sha = file_sha256(nvm2_file)
        logger.info(
            "  nvm2_region     offset=0x%04X  size=%5d  %s",
            NVM2_REGION_OFFSET, len(nvm2_data), nvm2_sha[:16],
        )

        # Extract identity metadata from NOS region (Tier 1 + Tier 2)
        identity = _extract_nos_identity(nos_data)
        logger.info(
            "  Identity: serial=%s  eth0=%s  wlan0=%s  pca=%s",
            identity["serial_number"],
            identity["eth0_mac"],
            identity["wlan0_mac"],
            identity["pca_serial"],
        )

        # Extract NVM2 header metadata (Tier 3)
        nvm2_header = _extract_nvm2_header(nvm2_data)
        logger.info(
            "  NVM2: magic=%s  objects=%d/%d  generation=%d",
            nvm2_header["magic"],
            nvm2_header["object_count"],
            nvm2_header["max_objects"],
            nvm2_header["generation_counter"],
        )

        # Write manifest (enriched with identity and NVM2 header)
        manifest = {
            "format_id": "hp_clj_pro_4301_eeprom",
            "version": 3,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "eeprom_size": EEPROM_SIZE,
            "zones": [
                {
                    "name": "nos_region",
                    "filename": "nos_region.bin",
                    "offset": NOS_REGION_OFFSET,
                    "size": NOS_REGION_SIZE,
                    "sha256": nos_sha,
                    "description": "NOS NVM — bootloader partitioned + flat fields",
                },
                {
                    "name": "nvm2_region",
                    "filename": "nvm2_region.bin",
                    "offset": NVM2_REGION_OFFSET,
                    "size": NVM2_REGION_SIZE,
                    "sha256": nvm2_sha,
                    "description": "NVM2 — kernel page-based object storage",
                },
            ],
            "identity": identity,
            "nvm2_header": nvm2_header,
        }
        manifest_path = output_path / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash="(directory)",
            metadata={
                "num_zones": 2,
                "zones": {
                    "nos_region": NOS_REGION_SIZE,
                    "nvm2_region": NVM2_REGION_SIZE,
                },
                "identity": identity,
                "nvm2_header": nvm2_header,
            },
        )

    # ── Pack (zones → eeprom) ────────────────────────────────────────

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
            "Packing EEPROM %s/ → %s (%d zones, eeprom_size=%d)",
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
                    f"Zone '{zi['name']}' at offset 0x{offset:04X} with "
                    f"size {len(data)} exceeds EEPROM size {eeprom_size}"
                )

            buf[offset:offset + len(data)] = data

            logger.info(
                "  %-16s  offset=0x%04X  size=%5d",
                zi["name"], offset, len(data),
            )

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
            },
        )

    # ── Kaitai Struct parsing ────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        if variant is None:
            variant = self.identify(path)
        if variant != VARIANT_EEPROM:
            raise ValueError(
                f"Kaitai parsing only supports '{VARIANT_EEPROM}', "
                f"got '{variant}'"
            )

        from .kaitai.hp_tx54_eeprom import HpTx54Eeprom as Parser

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))
