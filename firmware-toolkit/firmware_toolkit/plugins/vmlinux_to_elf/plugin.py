"""Firmware plugin for converting raw kernel images to symbolized ELF files.

Uses the ``vmlinux-to-elf`` tool to decompress and convert raw kernel
binaries (zImage, bzImage, Image, vmlinux, or symbol-stripped ELF) into
fully-symbolized ELF files suitable for analysis in disassemblers such
as Binary Ninja or Ghidra.

Supported input formats (auto-detected by vmlinux-to-elf):
  - ARM zImage (magic 0x016F2818 at offset 0x24)
  - ARM64 Image (magic ``ARM\\x64`` at offset 0x38)
  - Compressed vmlinux (gzip, LZ4, XZ, LZMA, LZO, zstd)
  - Raw vmlinux
  - ELF without symbols

This is a **one-way** conversion plugin.  Pack is not supported because
the raw kernel image is preserved by the LBI plugin for repacking.
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
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

TOOL_NAME = "vmlinux-to-elf"

# ARM zImage magic at offset 0x24
ARM_ZIMAGE_MAGIC = 0x016F2818

# ARM64 Image magic "ARM\x64" at offset 0x38
ARM64_IMAGE_MAGIC = b"ARM\x64"

# ELF magic
ELF_MAGIC = b"\x7fELF"

# Compressed stream signatures (first bytes)
GZIP_MAGIC = b"\x1f\x8b"
XZ_MAGIC = b"\xfd7zXZ\x00"
LZMA_MAGIC_BYTE = 0x5D       # LZMA streams typically start with 0x5D
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

VARIANT_KERNEL_IMAGE = "kernel_image"
VARIANT_VMLINUX_ELF = "vmlinux_elf"


# ── Helpers ──────────────────────────────────────────────────────────

def _tool_available() -> bool:
    """Return True if vmlinux-to-elf is found on PATH."""
    return shutil.which(TOOL_NAME) is not None


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run a command, raising on failure with stderr details."""
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        **kwargs,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result


def _is_arm_zimage(data: bytes) -> bool:
    """Check for ARM zImage magic at offset 0x24."""
    if len(data) < 0x28:
        return False
    magic = struct.unpack_from("<I", data, 0x24)[0]
    return magic == ARM_ZIMAGE_MAGIC


def _is_arm64_image(data: bytes) -> bool:
    """Check for ARM64 Image magic at offset 0x38."""
    if len(data) < 0x3C:
        return False
    return data[0x38:0x3C] == ARM64_IMAGE_MAGIC


def _is_compressed_kernel(data: bytes) -> bool:
    """Check for common compressed-stream signatures at offset 0."""
    if len(data) < 6:
        return False
    if data[:2] == GZIP_MAGIC:
        return True
    if data[:6] == XZ_MAGIC:
        return True
    if data[0] == LZMA_MAGIC_BYTE:
        return True
    if data[:4] in (LZ4_LEGACY_MAGIC, LZ4_FRAME_MAGIC):
        return True
    if data[:4] == ZSTD_MAGIC:
        return True
    return False


def _elf_has_symtab(path: Path) -> bool:
    """Return True if the ELF file at *path* contains a .symtab section.

    Uses a lightweight scan of ELF section headers rather than importing
    a full ELF library.
    """
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if ident[:4] != ELF_MAGIC:
                return False

            ei_class = ident[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = ident[5]   # 1 = little-endian, 2 = big-endian
            fmt = "<" if ei_data == 1 else ">"

            if ei_class == 1:
                # ELF32
                f.seek(0)
                hdr = f.read(52)
                e_shoff = struct.unpack_from(f"{fmt}I", hdr, 32)[0]
                e_shentsize = struct.unpack_from(f"{fmt}H", hdr, 46)[0]
                e_shnum = struct.unpack_from(f"{fmt}H", hdr, 48)[0]
                e_shstrndx = struct.unpack_from(f"{fmt}H", hdr, 50)[0]
                sh_name_off = 0
                sh_type_off = 4
            elif ei_class == 2:
                # ELF64
                f.seek(0)
                hdr = f.read(64)
                e_shoff = struct.unpack_from(f"{fmt}Q", hdr, 40)[0]
                e_shentsize = struct.unpack_from(f"{fmt}H", hdr, 58)[0]
                e_shnum = struct.unpack_from(f"{fmt}H", hdr, 60)[0]
                e_shstrndx = struct.unpack_from(f"{fmt}H", hdr, 62)[0]
                sh_name_off = 0
                sh_type_off = 4
            else:
                return False

            if e_shoff == 0 or e_shnum == 0:
                return False

            # SHT_SYMTAB = 2
            for i in range(e_shnum):
                f.seek(e_shoff + i * e_shentsize + sh_type_off)
                sh_type_bytes = f.read(4)
                if len(sh_type_bytes) < 4:
                    break
                sh_type = struct.unpack_from(f"{fmt}I", sh_type_bytes, 0)[0]
                if sh_type == 2:  # SHT_SYMTAB
                    return True

            return False
    except OSError:
        return False


# ── Plugin class ─────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """vmlinux-to-elf kernel image conversion plugin."""

    # ── Metadata ──────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        available = _tool_available()
        return PluginInfo(
            name="vmlinux-to-elf",
            description=(
                "Converts raw kernel images (zImage, Image, vmlinux) into "
                "fully-symbolized ELF files using vmlinux-to-elf"
            ),
            version="1.0.0",
            format_id="vmlinux_to_elf",
            supported_variants=[VARIANT_KERNEL_IMAGE, VARIANT_VMLINUX_ELF],
            conversions=self.get_conversions(),
        )

    def get_conversions(self) -> list[ConversionInfo]:
        available = _tool_available()
        return [
            ConversionInfo(
                source_variant=VARIANT_KERNEL_IMAGE,
                target_variant=VARIANT_VMLINUX_ELF,
                description="Convert raw kernel image to symbolized ELF",
                lossy=True,  # cannot reverse ELF back to zImage
                available=available,
                missing_deps=[] if available else [TOOL_NAME],
            ),
        ]

    # ── Identification ────────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if not path.is_file():
            return None

        try:
            with open(path, "rb") as f:
                header = f.read(0x40)  # 64 bytes is enough for all checks
        except OSError:
            return None

        if len(header) < 4:
            return None

        # Check for output: ELF with symbol table → already converted
        if header[:4] == ELF_MAGIC:
            if _elf_has_symtab(path):
                return VARIANT_VMLINUX_ELF
            else:
                # ELF without symbols — can still be converted
                return VARIANT_KERNEL_IMAGE

        # ARM zImage
        if _is_arm_zimage(header):
            return VARIANT_KERNEL_IMAGE

        # ARM64 Image
        if _is_arm64_image(header):
            return VARIANT_KERNEL_IMAGE

        # Compressed kernel stream
        if _is_compressed_kernel(header):
            return VARIANT_KERNEL_IMAGE

        return None

    # ── Unpack (convert) ──────────────────────────────────────────────

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
        if source_variant != VARIANT_KERNEL_IMAGE:
            raise ValueError(
                f"Cannot convert variant '{source_variant}', "
                f"expected '{VARIANT_KERNEL_IMAGE}'"
            )

        if not _tool_available():
            raise RuntimeError(
                f"'{TOOL_NAME}' is not installed or not on PATH. "
                f"Install with: pip install vmlinux-to-elf"
            )

        source_hash = file_sha256(input_path)
        input_size = input_path.stat().st_size

        # If output_path is a directory, derive filename from input with .elf suffix
        if output_path.is_dir():
            elf_name = input_path.stem + ".elf"
            output_file = output_path / elf_name
        else:
            output_file = output_path

        # vmlinux-to-elf writes a single output file
        _run([TOOL_NAME, str(input_path), str(output_file)])

        output_size = output_file.stat().st_size
        output_hash = file_sha256(output_file)

        logger.info(
            "Converted kernel image (%d bytes) → ELF (%d bytes)",
            input_size,
            output_size,
        )

        return UnpackResult(
            output_path=output_file,
            source_variant=VARIANT_KERNEL_IMAGE,
            target_variant=VARIANT_VMLINUX_ELF,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata={
                "input_size": input_size,
                "output_size": output_size,
            },
        )

    # ── Pack (not supported) ──────────────────────────────────────────

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        raise NotImplementedError(
            "vmlinux-to-elf is a one-way analysis conversion. "
            "The raw kernel image is preserved by the LBI plugin for repacking."
        )
