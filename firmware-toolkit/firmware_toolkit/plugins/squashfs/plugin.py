"""Firmware plugin for SquashFS filesystem images.

Supports unpacking a SquashFS image into extracted files and repacking
an extracted directory tree back into a SquashFS image.

- **squashfs_image**: Packed SquashFS filesystem image file.
- **squashfs_extracted**: Directory containing extracted filesystem tree
  and a ``squashfs_manifest.json`` with superblock metadata needed for
  faithful repacking.

Uses the system ``unsquashfs`` / ``mksquashfs`` tools (squashfs-tools).
"""

from __future__ import annotations

import json
import logging
import re
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

# SquashFS magic bytes (little-endian and big-endian)
SQFS_MAGIC_LE = b"hsqs"  # 0x73717368
SQFS_MAGIC_BE = b"sqsh"  # 0x68737173

VARIANT_SQUASHFS_IMAGE = "squashfs_image"
VARIANT_SQUASHFS_EXTRACTED = "squashfs_extracted"

MANIFEST_FILENAME = "squashfs_manifest.json"
EXTRACTED_DIRNAME = "squashfs-root"


# ── Helpers ──────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    """Return True if *name* is found on PATH."""
    return shutil.which(name) is not None


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


def _read_creation_time(image_path: Path) -> int | None:
    """Read the mkfs_time field from the SquashFS superblock (uint32 LE at offset 8)."""
    try:
        with open(image_path, "rb") as f:
            f.seek(8)
            raw = f.read(4)
            if len(raw) == 4:
                return struct.unpack("<I", raw)[0]
    except OSError:
        pass
    return None


def _parse_superblock(image_path: Path) -> dict[str, Any]:
    """Run ``unsquashfs -s`` and parse the superblock info into a dict."""
    result = _run(["unsquashfs", "-s", str(image_path)])
    info: dict[str, Any] = {}

    for line in result.stdout.splitlines():
        line = line.strip()

        # Version — e.g. "Found a valid SQUASHFS 4:0 superblock on ..."
        m = re.search(r"SQUASHFS\s+(\d+:\d+)\s+superblock", line)
        if m:
            info["version"] = m.group(1)
            continue

        # Creation time — skip the human-readable line; we read epoch
        # directly from the superblock binary (more reliable).

        # Filesystem size — "Filesystem size 183553099 bytes ..."
        m = re.search(r"Filesystem size\s+([\d.]+)\s+bytes", line)
        if m:
            info["filesystem_size"] = int(float(m.group(1)))
            continue

        # Compression — "Compression gzip"
        m = re.match(r"Compression\s+(\S+)", line)
        if m:
            info["compression"] = m.group(1)
            continue

        # Block size — "Block size 131072"
        m = re.match(r"Block size\s+(\d+)", line)
        if m:
            info["block_size"] = int(m.group(1))
            continue

        # NFS exportable
        if "exportable via NFS" in line:
            info["exportable"] = True

        # Xattrs
        if line.startswith("Xattrs"):
            info["xattrs"] = "not" not in line.lower()

        # Duplicates
        if "Duplicates" in line:
            info["duplicates_removed"] = "removed" in line.lower()

        # Fragments compressed — "Fragments are compressed"
        m = re.match(r"Fragments are\s+(\S+)", line)
        if m:
            info["fragments_compressed"] = m.group(1) == "compressed"
            continue

        # Number of fragments — "Number of fragments 312"
        m = re.match(r"Number of fragments\s+(\d+)", line)
        if m:
            info["num_fragments"] = int(m.group(1))
            continue

        # Number of inodes — "Number of inodes 7273"
        m = re.match(r"Number of inodes\s+(\d+)", line)
        if m:
            info["num_inodes"] = int(m.group(1))
            continue

        # Number of ids — "Number of ids 12"
        m = re.match(r"Number of ids\s+(\d+)", line)
        if m:
            info["num_ids"] = int(m.group(1))
            continue

    # Read creation_time directly from the binary superblock (epoch UTC)
    ctime = _read_creation_time(image_path)
    if ctime is not None:
        info["creation_time"] = ctime

    # Default exportable to False if not found
    info.setdefault("exportable", False)
    info.setdefault("xattrs", False)
    info.setdefault("duplicates_removed", True)

    return info


# ── Plugin class ─────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """Plugin for SquashFS filesystem images."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        unsquashfs_ok = _tool_available("unsquashfs")
        mksquashfs_ok = _tool_available("mksquashfs")
        missing: list[str] = []
        if not unsquashfs_ok:
            missing.append("unsquashfs")
        if not mksquashfs_ok:
            missing.append("mksquashfs")

        return PluginInfo(
            name="squashfs",
            description=(
                "SquashFS filesystem image handler. "
                "Extracts files from SquashFS images and repacks directory "
                "trees back into SquashFS images using squashfs-tools."
            ),
            version="0.1.0",
            format_id="squashfs",
            supported_variants=[
                VARIANT_SQUASHFS_IMAGE,
                VARIANT_SQUASHFS_EXTRACTED,
            ],
            conversions=self.get_conversions(),
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_file():
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                if magic in (SQFS_MAGIC_LE, SQFS_MAGIC_BE):
                    return VARIANT_SQUASHFS_IMAGE
            except OSError:
                pass
        elif path.is_dir():
            if (path / MANIFEST_FILENAME).is_file():
                return VARIANT_SQUASHFS_EXTRACTED
        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        unsquashfs_ok = _tool_available("unsquashfs")
        mksquashfs_ok = _tool_available("mksquashfs")

        return [
            ConversionInfo(
                source_variant=VARIANT_SQUASHFS_IMAGE,
                target_variant=VARIANT_SQUASHFS_EXTRACTED,
                description="Extract SquashFS image to directory tree",
                lossy=False,
                available=unsquashfs_ok,
                missing_deps=[] if unsquashfs_ok else ["unsquashfs (squashfs-tools)"],
            ),
            ConversionInfo(
                source_variant=VARIANT_SQUASHFS_EXTRACTED,
                target_variant=VARIANT_SQUASHFS_IMAGE,
                description="Repack directory tree into SquashFS image",
                lossy=False,
                available=mksquashfs_ok,
                missing_deps=[] if mksquashfs_ok else ["mksquashfs (squashfs-tools)"],
            ),
        ]

    # ── Unpack ───────────────────────────────────────────────────────

    def unpack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> UnpackResult:
        """Extract a SquashFS image to a directory tree.

        *input_path* is the SquashFS image file.
        *output_path* is the directory where the extracted tree and
        manifest will be written.
        """
        if source_variant is None:
            source_variant = self.identify(input_path) or VARIANT_SQUASHFS_IMAGE
        if target_variant is None:
            target_variant = VARIANT_SQUASHFS_EXTRACTED

        if source_variant != VARIANT_SQUASHFS_IMAGE:
            raise ValueError(
                f"unpack expects source variant '{VARIANT_SQUASHFS_IMAGE}', "
                f"got '{source_variant}'"
            )

        source_hash = file_sha256(input_path)
        output_path.mkdir(parents=True, exist_ok=True)
        extract_dir = output_path / EXTRACTED_DIRNAME

        # ── Parse superblock for manifest ────────────────────────────
        logger.info("Parsing SquashFS superblock: %s", input_path)
        sb_info = _parse_superblock(input_path)

        # ── Extract filesystem ───────────────────────────────────────
        logger.info("Extracting SquashFS image to: %s", extract_dir)

        # Remove target dir if it exists (unsquashfs -f won't clean)
        if extract_dir.exists():
            shutil.rmtree(extract_dir)

        cmd = [
            "unsquashfs",
            "-d", str(extract_dir),
            "-n",   # no progress bar
            "-f",   # force (overwrite)
            str(input_path),
        ]
        _run(cmd)

        # ── Write manifest ───────────────────────────────────────────
        manifest = {
            "format": "squashfs",
            "version": sb_info.get("version", "4:0"),
            "compression": sb_info.get("compression", "gzip"),
            "block_size": sb_info.get("block_size", 131072),
            "exportable": sb_info.get("exportable", False),
            "xattrs": sb_info.get("xattrs", False),
            "duplicates_removed": sb_info.get("duplicates_removed", True),
            "creation_time": sb_info.get("creation_time"),
            "filesystem_size": sb_info.get("filesystem_size"),
            "num_inodes": sb_info.get("num_inodes"),
            "num_fragments": sb_info.get("num_fragments"),
        }

        manifest_path = output_path / MANIFEST_FILENAME
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        logger.info("Wrote manifest: %s", manifest_path)

        # Compute output hash over the manifest (represents the extraction)
        output_hash = file_sha256(manifest_path)

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=manifest,
        )

    # ── Pack ─────────────────────────────────────────────────────────

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        """Repack an extracted directory tree into a SquashFS image.

        *input_path* is the directory containing ``squashfs-root/`` and
        ``squashfs_manifest.json``.
        *output_path* is the SquashFS image file to create.
        """
        if source_variant is None:
            source_variant = self.identify(input_path) or VARIANT_SQUASHFS_EXTRACTED
        if target_variant is None:
            target_variant = VARIANT_SQUASHFS_IMAGE

        if source_variant != VARIANT_SQUASHFS_EXTRACTED:
            raise ValueError(
                f"pack expects source variant '{VARIANT_SQUASHFS_EXTRACTED}', "
                f"got '{source_variant}'"
            )

        # ── Read manifest ────────────────────────────────────────────
        manifest_path = input_path / MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"Manifest not found: {manifest_path}. "
                f"Was this directory created by unpack()?"
            )
        manifest = json.loads(manifest_path.read_text())
        source_hash = file_sha256(manifest_path)

        extract_dir = input_path / EXTRACTED_DIRNAME
        if not extract_dir.is_dir():
            raise FileNotFoundError(
                f"Extracted tree not found: {extract_dir}. "
                f"Expected '{EXTRACTED_DIRNAME}/' inside {input_path}."
            )

        # ── Build mksquashfs command ─────────────────────────────────
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove output if it exists (mksquashfs appends by default)
        if output_path.exists():
            output_path.unlink()

        cmd = [
            "mksquashfs",
            str(extract_dir),
            str(output_path),
        ]

        # Compression
        compression = manifest.get("compression", "gzip")
        cmd.extend(["-comp", compression])

        # Block size
        block_size = manifest.get("block_size", 131072)
        cmd.extend(["-b", str(block_size)])

        # NFS export
        if not manifest.get("exportable", False):
            cmd.append("-no-exports")

        # Extended attributes
        if manifest.get("xattrs", False):
            cmd.append("-xattrs")
        else:
            cmd.append("-no-xattrs")

        # Duplicate detection
        if not manifest.get("duplicates_removed", True):
            cmd.append("-no-duplicates")

        # Creation time — use -mkfs-time if available
        creation_time = manifest.get("creation_time")
        if creation_time is not None:
            cmd.extend(["-mkfs-time", str(creation_time)])
            # Also set file timestamps to avoid embedding current time
            cmd.extend(["-all-time", str(creation_time)])

        # Quiet output
        cmd.append("-noappend")
        cmd.append("-quiet")

        logger.info("Repacking SquashFS image: %s", output_path)
        _run(cmd)

        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=manifest,
        )
