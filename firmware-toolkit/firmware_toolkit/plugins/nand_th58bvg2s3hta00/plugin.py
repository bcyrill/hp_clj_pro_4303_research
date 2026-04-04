"""Firmware plugin for Toshiba TH58BVG2S3HTA00 NAND flash dumps.

Supports conversion between two variants:

- **with_oob**: Raw NAND dump including 64-byte OOB/ECC per page
  (2112 bytes per page = 2048 data + 64 OOB).
- **without_oob**: Stripped dump with only user data
  (2048 bytes per page).

The OOB area layout (64 bytes):
    Bytes  0–11:  Spare/metadata buffer
    Bytes 12–24:  BCH ECC for data chunk 0  (bytes   0– 511)
    Bytes 25–37:  BCH ECC for data chunk 1  (bytes 512–1023)
    Bytes 38–50:  BCH ECC for data chunk 2  (bytes 1024–1535)
    Bytes 51–63:  BCH ECC for data chunk 3  (bytes 1536–2047)

ECC: BCH(polynomial=8219, t=8), computed directly on raw data (no inversion, no bit swap).
"""

from __future__ import annotations

import logging
import os
import sys
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

# ── NAND geometry ────────────────────────────────────────────────────
PAGE_DATA_SIZE = 2048
PAGE_OOB_SIZE = 64
PAGE_TOTAL_SIZE = PAGE_DATA_SIZE + PAGE_OOB_SIZE  # 2112

CHUNK_SIZE = 512
CHUNKS_PER_PAGE = 4
SPARE_BUFFER_SIZE = 12
ECC_CODE_SIZE = 13

PAGES_PER_BLOCK = 64
NUM_BLOCKS = 4096
TOTAL_PAGES = PAGES_PER_BLOCK * NUM_BLOCKS  # 262 144

# Variant identifiers
VARIANT_WITH_OOB = "with_oob"
VARIANT_WITHOUT_OOB = "without_oob"

# ECC parameters
ECC_POLYNOMIAL = 8219
ECC_CORRECTION_CAPACITY = 8


def _have_bchlib() -> bool:
    """Check whether bchlib is importable."""
    try:
        import bchlib  # noqa: F401
        return True
    except ImportError:
        return False


def _compute_ecc_for_chunk(data_chunk: bytes) -> bytes:
    """Compute BCH ECC for a 512-byte data chunk.

    The ECC is calculated directly on the raw data using
    BCH(polynomial=8219, t=8) without bit inversion or swapping.
    """
    import bchlib

    bch = bchlib.BCH(
        t=ECC_CORRECTION_CAPACITY,
        prim_poly=ECC_POLYNOMIAL,
        swap_bits=False,
    )
    return bytes(bch.encode(bytearray(data_chunk)))


_ERASED_PAGE = b"\xff" * PAGE_DATA_SIZE
_ERASED_OOB = b"\xff" * PAGE_OOB_SIZE


def _build_oob(page_data: bytes, spare: bytes | None = None) -> bytes:
    """Build a 64-byte OOB area for a 2048-byte data page.

    Computes fresh ECC codes for each 512-byte chunk.  If *spare* is
    ``None`` the spare buffer is filled with 0xFF (erased state).

    Erased pages (all-0xFF data and spare) retain all-0xFF OOB to
    match the natural erased NAND state — hardware does not store
    computed ECC for pages that were never programmed.
    """
    # Erased pages keep all-FF OOB (natural NAND erased state)
    if page_data == _ERASED_PAGE and (spare is None or spare == b"\xff" * SPARE_BUFFER_SIZE):
        return _ERASED_OOB

    if spare is None:
        spare = b"\xff" * SPARE_BUFFER_SIZE
    else:
        spare = bytes(spare[:SPARE_BUFFER_SIZE]).ljust(SPARE_BUFFER_SIZE, b"\xff")

    oob = bytearray(spare)
    for i in range(CHUNKS_PER_PAGE):
        chunk = page_data[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
        oob.extend(_compute_ecc_for_chunk(chunk))

    assert len(oob) == PAGE_OOB_SIZE, f"OOB is {len(oob)} bytes, expected {PAGE_OOB_SIZE}"
    return bytes(oob)


class Plugin(FirmwarePlugin):
    """NAND TH58BVG2S3HTA00 firmware plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="NAND TH58BVG2S3HTA00",
            description=(
                "Toshiba TH58BVG2S3HTA00 4Gbit NAND flash dump handler. "
                "Converts between raw dumps with and without OOB/ECC data."
            ),
            version="0.1.0",
            format_id="nand_th58bvg2s3hta00",
            supported_variants=[VARIANT_WITH_OOB, VARIANT_WITHOUT_OOB],
            conversions=self.get_conversions(),
            ksy_files=[
                "nand_th58bvg2s3hta00_with_oob.ksy",
                "nand_th58bvg2s3hta00_without_oob.ksy",
            ],
        )

    # ── Plugin-specific CLI options ──────────────────────────────────

    def get_options(self) -> list[PluginOption]:
        return [
            PluginOption(
                flag="--no-ecc",
                description="Skip ECC computation (fill OOB with 0xFF)",
                kwarg_name="compute_ecc",
                kwarg_value=False,
                default=None,
                applies_to="pack",
            ),
        ]

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        """Identify the variant by file size.

        with_oob:    262144 × 2112 = 553 648 128 bytes
        without_oob: 262144 × 2048 = 536 870 912 bytes
        """
        size = path.stat().st_size

        if size == TOTAL_PAGES * PAGE_TOTAL_SIZE:
            return VARIANT_WITH_OOB
        if size == TOTAL_PAGES * PAGE_DATA_SIZE:
            return VARIANT_WITHOUT_OOB
        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        has_bch = _have_bchlib()
        return [
            ConversionInfo(
                source_variant=VARIANT_WITH_OOB,
                target_variant=VARIANT_WITHOUT_OOB,
                description="Strip OOB/ECC data from raw NAND dump",
                lossy=True,  # OOB metadata is discarded
            ),
            ConversionInfo(
                source_variant=VARIANT_WITHOUT_OOB,
                target_variant=VARIANT_WITH_OOB,
                description="Add OOB area with freshly computed BCH ECC",
                lossy=False,
                available=has_bch,
                missing_deps=[] if has_bch else ["bchlib"],
            ),
        ]

    # ── Unpack (with_oob → without_oob) ─────────────────────────────

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
        if source_variant is None:
            raise ValueError(f"Cannot identify variant of {input_path}")

        if source_variant != VARIANT_WITH_OOB:
            raise ValueError(
                f"Unpack expects source variant '{VARIANT_WITH_OOB}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_WITHOUT_OOB
        source_hash = file_sha256(input_path)

        file_size = input_path.stat().st_size
        total_pages = file_size // PAGE_TOTAL_SIZE

        logger.info(
            "Unpacking %s (%s) → %s (%s), %d pages",
            input_path.name, source_variant,
            output_path.name, target_variant,
            total_pages,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            for page_idx in range(total_pages):
                page = f_in.read(PAGE_TOTAL_SIZE)
                if len(page) < PAGE_TOTAL_SIZE:
                    break
                # Extract user data (first 2048 bytes), discard OOB
                f_out.write(page[:PAGE_DATA_SIZE])

                if (page_idx + 1) % 50000 == 0 or page_idx == total_pages - 1:
                    pct = (page_idx + 1) / total_pages * 100
                    logger.info("  %6.1f%% — page %d / %d", pct, page_idx + 1, total_pages)

        output_hash = file_sha256(output_path)

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "total_pages": total_pages,
                "page_data_size": PAGE_DATA_SIZE,
                "page_oob_size": PAGE_OOB_SIZE,
            },
        )

    # ── Pack (without_oob → with_oob) ───────────────────────────────

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
        if source_variant is None:
            raise ValueError(f"Cannot identify variant of {input_path}")

        if source_variant != VARIANT_WITHOUT_OOB:
            raise ValueError(
                f"Pack expects source variant '{VARIANT_WITHOUT_OOB}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_WITH_OOB

        compute_ecc = kwargs.get("compute_ecc", True)
        if compute_ecc and not _have_bchlib():
            raise RuntimeError(
                "bchlib is required to compute ECC. "
                "Install it with: pip install bchlib"
            )

        source_hash = file_sha256(input_path)
        file_size = input_path.stat().st_size
        total_pages = file_size // PAGE_DATA_SIZE

        logger.info(
            "Packing %s (%s) → %s (%s), %d pages, ecc=%s",
            input_path.name, source_variant,
            output_path.name, target_variant,
            total_pages, compute_ecc,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            for page_idx in range(total_pages):
                page_data = f_in.read(PAGE_DATA_SIZE)
                if len(page_data) < PAGE_DATA_SIZE:
                    break

                f_out.write(page_data)

                if compute_ecc:
                    oob = _build_oob(page_data)
                else:
                    # Fill with 0xFF (erased NAND state)
                    oob = b"\xff" * PAGE_OOB_SIZE

                f_out.write(oob)

                if (page_idx + 1) % 50000 == 0 or page_idx == total_pages - 1:
                    pct = (page_idx + 1) / total_pages * 100
                    logger.info("  %6.1f%% — page %d / %d", pct, page_idx + 1, total_pages)

        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "total_pages": total_pages,
                "ecc_computed": compute_ecc,
                "ecc_polynomial": ECC_POLYNOMIAL if compute_ecc else None,
                "ecc_correction_capacity": ECC_CORRECTION_CAPACITY if compute_ecc else None,
            },
        )

    # ── Kaitai Struct parsing ────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        """Parse with the appropriate Kaitai Struct parser.

        WARNING: For large dumps this loads the entire structure into
        memory.  Use only for inspection / small files.
        """
        if variant is None:
            variant = self.identify(path)

        if variant == VARIANT_WITH_OOB:
            from .kaitai import NandTh58bvg2s3hta00WithOob as Parser
        elif variant == VARIANT_WITHOUT_OOB:
            from .kaitai import NandTh58bvg2s3hta00WithoutOob as Parser
        else:
            raise ValueError(f"Unknown variant: {variant}")

        with open(path, "rb") as f:
            return Parser(KaitaiStream(f))
