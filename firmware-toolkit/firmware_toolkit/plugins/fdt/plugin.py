"""Firmware plugin for Flattened Device Tree (DTB/FDT) blobs.

Supports decompilation of DTB (binary) files to DTS (source) format
using the pyfdt library.

- **dtb**: Flattened Device Tree binary blob (magic 0xD00DFEED).
- **dts**: Device Tree Source text file.

Only unpack (DTB → DTS) is supported; pack is not implemented as
DTS → DTB compilation is typically done by the device tree compiler
(dtc) toolchain.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

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

# DTB magic: 0xD00DFEED stored as big-endian bytes
DTB_MAGIC = b"\xd0\x0d\xfe\xed"

VARIANT_DTB = "dtb"
VARIANT_DTS = "dts"


def _have_pyfdt() -> bool:
    """Check whether pyfdt is importable."""
    try:
        from pyfdt.pyfdt import FdtBlobParse  # noqa: F401
        return True
    except ImportError:
        return False


class Plugin(FirmwarePlugin):
    """Flattened Device Tree plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="Flattened Device Tree",
            description=(
                "Flattened Device Tree (FDT/DTB) handler. "
                "Decompiles DTB binary blobs to DTS source text."
            ),
            version="0.1.0",
            format_id="fdt",
            supported_variants=[VARIANT_DTB, VARIANT_DTS],
            conversions=self.get_conversions(),
            ksy_files=[],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_dir():
            return None

        # DTS files: check extension
        if path.suffix.lower() == ".dts":
            return VARIANT_DTS

        # DTB files: check magic bytes
        if path.stat().st_size < 4:
            return None

        with open(path, "rb") as f:
            magic = f.read(4)
            if magic == DTB_MAGIC:
                return VARIANT_DTB

        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        has_pyfdt = _have_pyfdt()
        return [
            ConversionInfo(
                source_variant=VARIANT_DTB,
                target_variant=VARIANT_DTS,
                description="Decompile DTB binary to DTS source",
                lossy=False,
                available=has_pyfdt,
                missing_deps=[] if has_pyfdt else ["pyfdt"],
            ),
        ]

    # ── Unpack (dtb → dts) ──────────────────────────────────────────

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
        if source_variant != VARIANT_DTB:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_DTB}', "
                f"got '{source_variant}'"
            )

        if not _have_pyfdt():
            raise RuntimeError(
                "pyfdt is required to decompile DTB files. "
                "Install it with: pip install pyfdt"
            )

        target_variant = target_variant or VARIANT_DTS
        source_hash = file_sha256(input_path)

        from pyfdt.pyfdt import FdtBlobParse

        logger.info(
            "Decompiling DTB %s → %s",
            input_path.name, output_path.name,
        )

        with open(input_path, "rb") as f:
            dtb = FdtBlobParse(f)

        fdt = dtb.to_fdt()
        dts_text = fdt.to_dts()

        # If output_path is an existing directory or has no extension
        # (likely intended as a directory), place the .dts file inside it.
        if output_path.is_dir() or (
            not output_path.suffix and not output_path.exists()
        ):
            output_path.mkdir(parents=True, exist_ok=True)
            output_path = output_path / input_path.with_suffix(".dts").name
        elif output_path.suffix.lower() != ".dts":
            output_path = output_path.with_suffix(".dts")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(dts_text, encoding="utf-8")
        output_hash = file_sha256(output_path)

        # Extract model/compatible for metadata
        model = None
        compatible = None
        try:
            root = fdt.get_rootnode()
            for prop in root:
                if hasattr(prop, "get_name"):
                    name = prop.get_name()
                    if name == "model":
                        model = prop.strings[0] if hasattr(prop, "strings") else str(prop)
                    elif name == "compatible":
                        compatible = prop.strings[0] if hasattr(prop, "strings") else str(prop)
        except Exception:
            pass

        metadata: dict[str, Any] = {
            "dts_size": len(dts_text),
            "dtb_size": input_path.stat().st_size,
        }
        if model:
            metadata["model"] = model
        if compatible:
            metadata["compatible"] = compatible

        logger.info(
            "  DTB %d bytes → DTS %d chars%s",
            metadata["dtb_size"], metadata["dts_size"],
            f" (model={model})" if model else "",
        )

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )

    # ── Pack (not implemented) ───────────────────────────────────────

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        raise NotImplementedError(
            "DTS → DTB compilation is not supported. "
            "Use the device tree compiler (dtc) directly."
        )
