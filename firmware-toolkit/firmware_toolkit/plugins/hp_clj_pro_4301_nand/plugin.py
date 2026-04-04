"""Firmware layer plugin for the HP Color LaserJet Pro MFP 4301-4303.

This plugin operates on a 512 MB NAND dump **without OOB** (the output
of the ``nand_th58bvg2s3hta00`` plugin's unpack step) and splits it
into the six MTD partitions defined by the device tree, or reassembles
them back into a full NAND image.

Partition map (from DTS ``flash@38008000``):

    mtd0  Boot            0x00000000   256 KB    RO
    mtd1  UpdatableLBI    0x00040000   5 MB      RO
    mtd2  RootFS          0x00540000   ~263 MB   RO
    mtd3  RWFS            0x10C00000   ~142 MB   RW
    mtd4  RecoveryRootFS  0x19A60000   ~97 MB    RO
    mtd5  RecoveryLBI     0x1FB60000   ~4.6 MB   RO

Identification heuristics:
    - File size exactly 512 MB (536,870,912 bytes)
    - UpdatableLBI magic ``0xBAD2BFED`` at offset ``0x00040000``
    - UBI magic ``UBI#`` at offset ``0x00540000`` (RootFS)
"""

from __future__ import annotations

import json
import logging
import struct
from dataclasses import dataclass
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

NAND_SIZE = 0x20000000  # 512 MB

# LBI magic (big-endian)
LBI_MAGIC = b"\xba\xd2\xbf\xed"

# UBI magic
UBI_MAGIC = b"UBI#"

# Variant identifiers
VARIANT_FULL_NAND = "full_nand"
VARIANT_PARTITIONS = "partitions"


@dataclass(frozen=True)
class PartitionDef:
    """Definition of one MTD partition."""
    index: int
    label: str
    offset: int
    size: int
    readonly: bool
    filename: str
    description: str


# Partition table — order matters (must be sequential, gap-free)
PARTITIONS: list[PartitionDef] = [
    PartitionDef(
        index=0,
        label="Boot",
        offset=0x00000000,
        size=0x00040000,
        readonly=True,
        filename="mtd0_boot.bin",
        description="First-stage bootloader",
    ),
    PartitionDef(
        index=1,
        label="UpdatableLBI",
        offset=0x00040000,
        size=0x00500000,
        readonly=True,
        filename="mtd1_updatable_lbi.bin",
        description="Loadable Boot Image (BL2 + kernel + DTB + logo + auth)",
    ),
    PartitionDef(
        index=2,
        label="RootFS",
        offset=0x00540000,
        size=0x106C0000,
        readonly=True,
        filename="mtd2_rootfs.bin",
        description="Main root filesystem (UBI)",
    ),
    PartitionDef(
        index=3,
        label="RWFS",
        offset=0x10C00000,
        size=0x08E60000,
        readonly=False,
        filename="mtd3_rwfs.bin",
        description="Read-write filesystem (UBI)",
    ),
    PartitionDef(
        index=4,
        label="RecoveryRootFS",
        offset=0x19A60000,
        size=0x06100000,
        readonly=True,
        filename="mtd4_recovery_rootfs.bin",
        description="Recovery root filesystem (UBI)",
    ),
    PartitionDef(
        index=5,
        label="RecoveryLBI",
        offset=0x1FB60000,
        size=0x004A0000,
        readonly=True,
        filename="mtd5_recovery_lbi.bin",
        description="Recovery Loadable Boot Image",
    ),
]

# Sanity check: partitions must be contiguous and cover the full NAND
assert PARTITIONS[0].offset == 0
for _i in range(1, len(PARTITIONS)):
    assert PARTITIONS[_i].offset == PARTITIONS[_i - 1].offset + PARTITIONS[_i - 1].size
assert PARTITIONS[-1].offset + PARTITIONS[-1].size == NAND_SIZE

MANIFEST_NAME = "partition_manifest.json"


class Plugin(FirmwarePlugin):
    """HP Color LaserJet Pro MFP 4301-4303 firmware layer plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="HP CLJ Pro 4301-4303 Firmware",
            description=(
                "HP Color LaserJet Pro MFP 4301-4303 (TX54 platform) "
                "NAND partition layout. Splits/reassembles the 512 MB "
                "NAND image into 6 MTD partitions."
            ),
            version="0.1.0",
            format_id="hp_clj_pro_4301_nand",
            supported_variants=[VARIANT_FULL_NAND, VARIANT_PARTITIONS],
            conversions=self.get_conversions(),
            ksy_files=["hp_clj_pro_4301_nand.ksy"],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        """Identify by file size + magic bytes.

        For a directory containing partition files, check for the
        partition manifest.
        """
        if path.is_dir():
            manifest = path / MANIFEST_NAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                    if data.get("format_id") == "hp_clj_pro_4301_nand":
                        return VARIANT_PARTITIONS
                except Exception:
                    pass
            return None

        if path.stat().st_size != NAND_SIZE:
            return None

        with open(path, "rb") as f:
            # Check LBI magic at mtd1 offset
            f.seek(PARTITIONS[1].offset)
            if f.read(4) != LBI_MAGIC:
                return None

            # Check UBI magic at mtd2 offset
            f.seek(PARTITIONS[2].offset)
            if f.read(4) != UBI_MAGIC:
                return None

        return VARIANT_FULL_NAND

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_FULL_NAND,
                target_variant=VARIANT_PARTITIONS,
                description="Split NAND image into MTD partition files",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_PARTITIONS,
                target_variant=VARIANT_FULL_NAND,
                description="Reassemble MTD partition files into NAND image",
                lossy=False,
            ),
        ]

    # ── Unpack (full_nand → partitions) ──────────────────────────────

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
        if source_variant != VARIANT_FULL_NAND:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_FULL_NAND}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_PARTITIONS
        source_hash = file_sha256(input_path)

        # output_path is treated as a directory for partition files
        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Unpacking %s → %s/ (%d partitions)",
            input_path.name, output_path.name, len(PARTITIONS),
        )

        partition_info = []
        with open(input_path, "rb") as f_in:
            for part in PARTITIONS:
                f_in.seek(part.offset)
                out_file = output_path / part.filename
                data = f_in.read(part.size)
                out_file.write_bytes(data)
                sha = file_sha256(out_file)
                logger.info(
                    "  mtd%d %-20s  0x%08X  %10d bytes  %s",
                    part.index, part.label, part.offset, part.size, sha[:16],
                )
                partition_info.append({
                    "index": part.index,
                    "label": part.label,
                    "filename": part.filename,
                    "offset": part.offset,
                    "size": part.size,
                    "readonly": part.readonly,
                    "sha256": sha,
                })

        # Write partition manifest for re-packing
        manifest = {
            "format_id": "hp_clj_pro_4301_nand",
            "version": 1,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "nand_size": NAND_SIZE,
            "partitions": partition_info,
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
                "partition_count": len(PARTITIONS),
                "partitions": {p.label: p.size for p in PARTITIONS},
            },
        )

    # ── Pack (partitions → full_nand) ────────────────────────────────

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
                source_variant = VARIANT_PARTITIONS
            else:
                source_variant = self.identify(input_path)

        if source_variant != VARIANT_PARTITIONS:
            raise ValueError(
                f"Pack expects variant '{VARIANT_PARTITIONS}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_FULL_NAND

        # input_path must be a directory with partition files
        if not input_path.is_dir():
            raise ValueError(f"{input_path} is not a directory")

        # Load manifest for validation
        manifest_path = input_path / MANIFEST_NAME
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            logger.info("Using partition manifest from %s", manifest_path)
        else:
            manifest = None
            logger.warning("No partition manifest found, using default layout")

        logger.info(
            "Packing %s/ → %s (%d partitions)",
            input_path.name, output_path.name, len(PARTITIONS),
        )

        with open(output_path, "wb") as f_out:
            for part in PARTITIONS:
                part_file = input_path / part.filename
                if not part_file.exists():
                    raise FileNotFoundError(
                        f"Missing partition file: {part.filename}"
                    )

                data = part_file.read_bytes()
                if len(data) != part.size:
                    raise ValueError(
                        f"Partition {part.label} ({part.filename}) is "
                        f"{len(data)} bytes, expected {part.size}"
                    )

                f_out.seek(part.offset)
                f_out.write(data)
                logger.info(
                    "  mtd%d %-20s  0x%08X  %10d bytes",
                    part.index, part.label, part.offset, len(data),
                )

        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash="(directory)",
            output_hash=output_hash,
            metadata={
                "partition_count": len(PARTITIONS),
                "nand_size": NAND_SIZE,
            },
        )

    # ── Kaitai Struct parsing ────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        """Parse a full NAND image with the Kaitai Struct parser."""
        if variant is None:
            variant = self.identify(path)
        if variant != VARIANT_FULL_NAND:
            raise ValueError(
                f"Kaitai parsing only supports '{VARIANT_FULL_NAND}' "
                f"variant, got '{variant}'"
            )

        from .kaitai import HpCljPro4301Nand as Parser

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))
