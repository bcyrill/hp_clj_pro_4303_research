"""Firmware layer plugin for the HP CLJ Pro 4301-4303 Boot partition.

The 256 KB boot partition (mtd0) uses an A/B redundancy layout:
two identical 128 KB copies of the first-stage bootloader (BL1).

    Copy A:  offset 0x00000  (128 KB)
    Copy B:  offset 0x20000  (128 KB)

Each copy starts with an ARM big-endian exception vector table
(8 × ``LDR PC, [PC, #0x18]``  →  opcode ``0x18F09FE5``).

Unpack extracts a single BL1 image (copy A) after verifying that
A and B are identical.  Pack writes the BL1 image into both slots.
"""

from __future__ import annotations

import json
import logging
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

BOOT_PARTITION_SIZE = 0x40000   # 256 KB
COPY_SIZE = 0x20000             # 128 KB

# ARM big-endian exception vector: LDR PC, [PC, #0x18]
ARM_BE_LDR_PC = b"\x18\xf0\x9f\xe5"

# Variant identifiers
VARIANT_AB = "boot_ab"
VARIANT_SINGLE = "boot_single"

BL1_FILENAME = "bl1.bin"
MANIFEST_NAME = "boot_manifest.json"


class Plugin(FirmwarePlugin):
    """HP CLJ Pro 4301-4303 Boot partition A/B plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="HP CLJ Pro 4301 Boot (A/B)",
            description=(
                "HP CLJ Pro 4301-4303 boot partition layer. "
                "Splits the 256 KB A/B redundant boot partition into "
                "a single 128 KB BL1 image, or duplicates it back."
            ),
            version="0.1.0",
            format_id="hp_clj_pro_4301_boot",
            supported_variants=[VARIANT_AB, VARIANT_SINGLE],
            conversions=self.get_conversions(),
            ksy_files=["hp_clj_pro_4301_boot.ksy"],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        """Identify by size and ARM exception vector magic."""
        if path.is_dir():
            manifest = path / MANIFEST_NAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                    if data.get("format_id") == "hp_clj_pro_4301_boot":
                        return VARIANT_SINGLE
                except Exception:
                    pass
            return None

        size = path.stat().st_size

        if size == BOOT_PARTITION_SIZE:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == ARM_BE_LDR_PC:
                    return VARIANT_AB
            return None

        if size == COPY_SIZE:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == ARM_BE_LDR_PC:
                    return VARIANT_SINGLE
            return None

        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_AB,
                target_variant=VARIANT_SINGLE,
                description=(
                    "Extract single BL1 copy from A/B boot partition"
                ),
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_SINGLE,
                target_variant=VARIANT_AB,
                description=(
                    "Duplicate BL1 into A/B boot partition"
                ),
                lossy=False,
            ),
        ]

    # ── Unpack (boot_ab → boot_single) ──────────────────────────────

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
        if source_variant != VARIANT_AB:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_AB}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_SINGLE
        source_hash = file_sha256(input_path)

        with open(input_path, "rb") as f:
            copy_a = f.read(COPY_SIZE)
            copy_b = f.read(COPY_SIZE)

        copies_identical = copy_a == copy_b

        logger.info(
            "Unpacking %s (A/B boot, %d bytes) → %s",
            input_path.name, BOOT_PARTITION_SIZE, output_path.name,
        )

        if copies_identical:
            logger.info("  Copy A and B are identical")
        else:
            logger.warning(
                "  Copy A and B DIFFER — extracting copy A. "
                "Copy B will be saved separately."
            )

        # If output_path is a directory, write files inside it;
        # otherwise treat it as the BL1 output file directly.
        if output_path.suffix == "" and not output_path.exists():
            # Treat as directory
            output_path.mkdir(parents=True, exist_ok=True)
            bl1_path = output_path / BL1_FILENAME
        else:
            bl1_path = output_path

        bl1_path.write_bytes(copy_a)

        metadata = {
            "copy_size": COPY_SIZE,
            "copies_identical": copies_identical,
        }

        # If copies differ, save B separately and note the divergence
        if not copies_identical:
            if bl1_path.parent != bl1_path:
                b_path = bl1_path.parent / "bl1_copy_b.bin"
            else:
                b_path = bl1_path.with_name("bl1_copy_b.bin")
            b_path.write_bytes(copy_b)
            metadata["copy_b_path"] = str(b_path)
            metadata["copy_b_sha256"] = file_sha256(b_path)
            logger.info("  Saved divergent copy B to %s", b_path.name)

        # Write manifest for re-packing
        if bl1_path.parent.is_dir():
            manifest = {
                "format_id": "hp_clj_pro_4301_boot",
                "version": 1,
                "source_file": input_path.name,
                "source_sha256": source_hash,
                "copies_identical": copies_identical,
                "copy_size": COPY_SIZE,
            }
            manifest_path = bl1_path.parent / MANIFEST_NAME
            manifest_path.write_text(json.dumps(manifest, indent=2))

        output_hash = file_sha256(bl1_path)

        return UnpackResult(
            output_path=bl1_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )

    # ── Pack (boot_single → boot_ab) ────────────────────────────────

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

        # Handle directory input (look for bl1.bin inside)
        bl1_path = input_path
        if input_path.is_dir():
            source_variant = VARIANT_SINGLE
            bl1_path = input_path / BL1_FILENAME
            if not bl1_path.exists():
                raise FileNotFoundError(
                    f"Missing {BL1_FILENAME} in {input_path}"
                )

        if source_variant != VARIANT_SINGLE:
            raise ValueError(
                f"Pack expects variant '{VARIANT_SINGLE}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_AB
        source_hash = file_sha256(bl1_path)

        bl1_data = bl1_path.read_bytes()
        if len(bl1_data) != COPY_SIZE:
            raise ValueError(
                f"BL1 image is {len(bl1_data)} bytes, "
                f"expected {COPY_SIZE}"
            )

        logger.info(
            "Packing %s (BL1, %d bytes) → %s (A/B boot, %d bytes)",
            bl1_path.name, COPY_SIZE,
            output_path.name, BOOT_PARTITION_SIZE,
        )

        # Write A + B (identical copies)
        with open(output_path, "wb") as f:
            f.write(bl1_data)
            f.write(bl1_data)

        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "copy_size": COPY_SIZE,
                "boot_partition_size": BOOT_PARTITION_SIZE,
            },
        )

    # ── Kaitai Struct parsing ────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        if variant is None:
            variant = self.identify(path)
        if variant != VARIANT_AB:
            raise ValueError(
                f"Kaitai parsing only supports '{VARIANT_AB}', "
                f"got '{variant}'"
            )

        from .kaitai import HpCljPro4301Boot as Parser

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))
