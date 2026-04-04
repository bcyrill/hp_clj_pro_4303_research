"""Firmware layer plugin for the HP CLJ Pro 4301-4303 Loadable Boot Image (LBI).

The LBI format is used for both the UpdatableLBI (mtd1) and RecoveryLBI
(mtd5) partitions.  It bundles multiple firmware components in a single
image with a compact header.

Structure
---------
+0x000  Base header (20 bytes)
          magic        4B   0xBAD2BFED (big-endian)
          version      4B   format version (1)
          header_size  4B   total header + descriptors (bytes)
          num_sections 4B   number of section descriptors
          data_start   4B   offset of first section data; also alignment

+0x014  Section descriptors (24 bytes each × num_sections)
          role_flags   4B   section role (0x80=ENTRY, 0x2000=SIG,
                            0x800=OVERRIDE_DEST, 0x01=AUTH_COMPANION)
          load_address 4B   DRAM target (0 if not loaded)
          size         4B   section data size (0 for auth block)
          image_type   4B   toolchain image type tag (NOT read by bootloader):
                            0x0=plain, 0x4=DTB, 0xA=zImage
          entry_point  4B   execution entry (non-zero for BL2 only)
          reserved     4B

+data_start  Section data (back-to-back, each aligned to data_start)
             Sections whose header size is 0 consume all remaining
             data until the next alignment boundary or partition end.

Known sections (indices stable across firmware versions):
    0  Boot logo BMP
    1  Second-stage bootloader (BL2)
    2  Device Tree Blob (DTB)
    3  Kernel zImage
    4  Authentication block (SecureBoot header + RSA-2048 sig)
"""

from __future__ import annotations

import io
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

LBI_MAGIC = b"\xba\xd2\xbf\xed"
BASE_HEADER_SIZE = 20
DESCRIPTOR_SIZE = 24

# NAND page+OOB parameters (for raw dumps that include spare data)
NAND_PAGE_SIZE = 0x800   # 2048 bytes
NAND_OOB_SIZE = 0x40     # 64 bytes
NAND_STRIDE = NAND_PAGE_SIZE + NAND_OOB_SIZE  # 2112 bytes

# Well-known section names (by index)
SECTION_NAMES = {
    0: "boot_logo",
    1: "bl2",
    2: "dtb",
    3: "kernel_zimage",
    4: "auth_block",
}

SECTION_EXTENSIONS = {
    0: ".bmp",
    1: ".bin",
    2: ".dtb",
    3: ".bin",
    4: ".bin",
}

# Variant identifiers
VARIANT_LBI = "lbi"
VARIANT_LBI_NAND_OOB = "lbi_nand_oob"
VARIANT_SECTIONS = "lbi_sections"

MANIFEST_NAME = "lbi_manifest.json"

# Section role_flags bit definitions (from BL1/BL2 reverse engineering)
ROLE_AUTH_COMPANION = 0x0001  # Auth-section companion bit (set on auth block)
ROLE_ENTRY          = 0x0080  # Section has executable entry point (BL2)
ROLE_OVERRIDE_DEST  = 0x0800  # Override load_address with framebuffer addr
ROLE_SIG            = 0x2000  # Section contains authentication signature

# Section image_type values (toolchain metadata, NOT read by bootloader)
IMAGE_TYPE_PLAIN  = 0x00   # Plain data / BL2 executable
IMAGE_TYPE_DTB    = 0x04   # Device Tree Blob
IMAGE_TYPE_ZIMAGE = 0x0A   # ARM zImage compressed kernel


def _is_nand_oob(data: bytes) -> bool:
    """Return True if *data* looks like a NAND page+OOB dump containing
    an LBI image.

    Detection heuristic:
      1. File size must be evenly divisible by the page+OOB stride
         (2112 bytes).
      2. The LBI magic must appear at offset 0 of the first page.
      3. The LBI version field (bytes 4-8) should parse to 1.
    """
    if len(data) < NAND_STRIDE or len(data) % NAND_STRIDE != 0:
        return False
    if data[:4] != LBI_MAGIC:
        return False
    version = struct.unpack(">I", data[4:8])[0]
    return version == 1


def _strip_oob(data: bytes) -> bytes:
    """Strip 64-byte NAND OOB spare blocks from a page+OOB dump.

    The LBI header and section layout refer to logical (OOB-free)
    offsets, so OOB must be stripped before any parsing.
    """
    num_pages = len(data) // NAND_STRIDE
    pages = []
    for i in range(num_pages):
        page_start = i * NAND_STRIDE
        pages.append(data[page_start : page_start + NAND_PAGE_SIZE])

    stripped = b"".join(pages)
    logger.info(
        "Stripped NAND OOB (%d pages × %d+%d): %d → %d bytes.",
        num_pages, NAND_PAGE_SIZE, NAND_OOB_SIZE,
        len(data), len(stripped),
    )
    return stripped


def _insert_oob(data: bytes) -> bytes:
    """Re-interleave 64-byte OOB spare blocks after each 2048-byte page.

    Used during ``pack()`` to reproduce the original page+OOB format
    when the manifest indicates the source was a raw NAND dump with OOB.
    OOB bytes are filled with 0xFF (erased-state).
    """
    if len(data) % NAND_PAGE_SIZE != 0:
        # Pad to full page
        pad = NAND_PAGE_SIZE - (len(data) % NAND_PAGE_SIZE)
        data = data + b"\xff" * pad

    num_pages = len(data) // NAND_PAGE_SIZE
    oob_block = b"\xff" * NAND_OOB_SIZE
    parts = []
    for i in range(num_pages):
        page_start = i * NAND_PAGE_SIZE
        parts.append(data[page_start : page_start + NAND_PAGE_SIZE])
        parts.append(oob_block)
    return b"".join(parts)


@dataclass
class SectionInfo:
    """Parsed section descriptor + computed data offset."""
    index: int
    role_flags: int
    load_address: int
    size: int
    image_type: int
    entry_point: int
    reserved: int
    data_offset: int          # computed: byte offset in LBI file
    data_size: int            # actual bytes to extract


def _parse_lbi_header(data: bytes) -> tuple[dict, list[SectionInfo]]:
    """Parse LBI base header and section descriptors.

    Returns (header_dict, list_of_SectionInfo).
    """
    if data[:4] != LBI_MAGIC:
        raise ValueError(f"Bad LBI magic: {data[:4].hex()}")

    version, header_size, num_sections, data_start = struct.unpack(
        ">4I", data[4:20]
    )

    header = {
        "version": version,
        "header_size": header_size,
        "num_sections": num_sections,
        "data_start": data_start,
    }

    sections: list[SectionInfo] = []
    offset = data_start  # first section data begins here

    for i in range(num_sections):
        desc_off = BASE_HEADER_SIZE + i * DESCRIPTOR_SIZE
        fields = struct.unpack(">6I", data[desc_off : desc_off + DESCRIPTOR_SIZE])

        sec = SectionInfo(
            index=i,
            role_flags=fields[0],
            load_address=fields[1],
            size=fields[2],
            image_type=fields[3],
            entry_point=fields[4],
            reserved=fields[5],
            data_offset=offset,
            data_size=0,  # computed below
        )

        if sec.size > 0:
            sec.data_size = sec.size
            end = offset + sec.size
            offset = ((end + data_start - 1) // data_start) * data_start
        else:
            # Size-zero section (e.g. auth block): data extends to next
            # alignment boundary or end of meaningful content.
            # We determine actual size by scanning for trailing 0xFF/0x00.
            sec.data_size = 0  # will be resolved at extraction time
            # Don't advance offset — next section (if any) starts here

        sections.append(sec)

    # ── Validate descriptor table ──
    entry_sections = [s for s in sections if s.role_flags & ROLE_ENTRY]
    if len(entry_sections) != 1:
        logger.warning(
            "Expected exactly 1 ENTRY (0x%04X) section, found %d",
            ROLE_ENTRY, len(entry_sections),
        )

    if sections and not (sections[-1].role_flags & ROLE_SIG):
        logger.warning(
            "Last section (#%d) missing SIG flag (0x%04X); "
            "role_flags=0x%04X",
            sections[-1].index, ROLE_SIG, sections[-1].role_flags,
        )

    return header, sections


def _build_lbi_header(
    header: dict,
    sections: list[SectionInfo],
) -> bytes:
    """Rebuild the LBI header bytes from parsed structures."""
    buf = bytearray()
    buf.extend(LBI_MAGIC)
    buf.extend(struct.pack(
        ">4I",
        header["version"],
        header["header_size"],
        header["num_sections"],
        header["data_start"],
    ))
    for sec in sections:
        buf.extend(struct.pack(
            ">6I",
            sec.role_flags,
            sec.load_address,
            sec.size,
            sec.image_type,
            sec.entry_point,
            sec.reserved,
        ))
    return bytes(buf)


class Plugin(FirmwarePlugin):
    """HP CLJ Pro 4301-4303 Loadable Boot Image plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="HP CLJ Pro 4301 LBI",
            description=(
                "HP CLJ Pro 4301-4303 Loadable Boot Image format. "
                "Splits an LBI partition into its component sections "
                "(BMP logo, BL2, DTB, kernel, auth block) or reassembles them."
            ),
            version="0.1.0",
            format_id="hp_clj_pro_4301_lbi",
            supported_variants=[VARIANT_LBI, VARIANT_LBI_NAND_OOB, VARIANT_SECTIONS],
            conversions=self.get_conversions(),
            ksy_files=["hp_clj_pro_4301_lbi.ksy"],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_dir():
            manifest = path / MANIFEST_NAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                    if data.get("format_id") == "hp_clj_pro_4301_lbi":
                        return VARIANT_SECTIONS
                except Exception:
                    pass
            return None

        file_size = path.stat().st_size
        if file_size < BASE_HEADER_SIZE:
            return None

        # Read enough to check both plain LBI and page+OOB format.
        # The LBI magic is always at byte 0 regardless of OOB presence.
        with open(path, "rb") as f:
            head = f.read(min(file_size, NAND_STRIDE))

        if head[:4] != LBI_MAGIC:
            return None

        # Distinguish page+OOB from plain LBI:
        #   page+OOB → file size divisible by 2112, version == 1
        if _is_nand_oob(head + b"\x00" * max(0, NAND_STRIDE - len(head))):
            # Need the full-file size check too
            if file_size % NAND_STRIDE == 0:
                return VARIANT_LBI_NAND_OOB

        return VARIANT_LBI

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_LBI,
                target_variant=VARIANT_SECTIONS,
                description="Extract LBI sections (logo, BL2, DTB, kernel, auth)",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_LBI_NAND_OOB,
                target_variant=VARIANT_SECTIONS,
                description="Strip NAND OOB and extract LBI sections",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_SECTIONS,
                target_variant=VARIANT_LBI,
                description="Reassemble LBI from section files",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_SECTIONS,
                target_variant=VARIANT_LBI_NAND_OOB,
                description="Reassemble LBI with NAND page+OOB interleaving",
                lossy=False,
            ),
        ]

    # ── Unpack (lbi → sections) ──────────────────────────────────────

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
        if source_variant not in (VARIANT_LBI, VARIANT_LBI_NAND_OOB):
            raise ValueError(
                f"Unpack expects variant '{VARIANT_LBI}' or "
                f"'{VARIANT_LBI_NAND_OOB}', got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_SECTIONS
        source_hash = file_sha256(input_path)

        raw_data = input_path.read_bytes()
        has_oob = source_variant == VARIANT_LBI_NAND_OOB
        lbi_data = _strip_oob(raw_data) if has_oob else raw_data
        partition_size = len(lbi_data)
        header, sections = _parse_lbi_header(lbi_data)

        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Unpacking LBI %s (%d bytes, %d sections) → %s/",
            input_path.name, partition_size,
            header["num_sections"], output_path.name,
        )

        section_manifest = []
        for sec in sections:
            name = SECTION_NAMES.get(sec.index, f"section_{sec.index}")
            ext = SECTION_EXTENSIONS.get(sec.index, ".bin")
            filename = f"{sec.index}_{name}{ext}"

            if sec.data_size > 0:
                data = lbi_data[sec.data_offset : sec.data_offset + sec.data_size]
            else:
                # Zero-size section: extract from data_offset to the end
                # of meaningful content (strip trailing 0x00/0xFF padding)
                raw = lbi_data[sec.data_offset:]
                # Find last non-padding byte
                end_idx = len(raw)
                while end_idx > 0 and raw[end_idx - 1] in (0x00, 0xFF):
                    end_idx -= 1
                data = raw[:end_idx]
                sec.data_size = len(data)

            out_file = output_path / filename
            out_file.write_bytes(data)
            sha = file_sha256(out_file)

            logger.info(
                "  section %d %-16s  offset=0x%06X  size=%8d  load=0x%08X  %s",
                sec.index, name, sec.data_offset, len(data),
                sec.load_address, sha[:16],
            )

            section_manifest.append({
                "index": sec.index,
                "name": name,
                "filename": filename,
                "role_flags": sec.role_flags,
                "load_address": sec.load_address,
                "size_in_header": sec.size,
                "actual_size": len(data),
                "image_type": sec.image_type,
                "entry_point": sec.entry_point,
                "reserved": sec.reserved,
                "data_offset": sec.data_offset,
                "sha256": sha,
            })

        # Write manifest
        manifest = {
            "format_id": "hp_clj_pro_4301_lbi",
            "version": 1,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "partition_size": partition_size,
            "source_variant": source_variant,
            "header": header,
            "sections": section_manifest,
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
                "num_sections": header["num_sections"],
                "sections": {
                    SECTION_NAMES.get(s.index, f"section_{s.index}"): s.data_size
                    for s in sections
                },
            },
        )

    # ── Pack (sections → lbi) ────────────────────────────────────────

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
                source_variant = VARIANT_SECTIONS
            else:
                source_variant = self.identify(input_path)

        if source_variant != VARIANT_SECTIONS:
            raise ValueError(
                f"Pack expects variant '{VARIANT_SECTIONS}', "
                f"got '{source_variant}'"
            )

        if not input_path.is_dir():
            raise ValueError(f"{input_path} is not a directory")

        manifest_path = input_path / MANIFEST_NAME
        if not manifest_path.exists():
            raise FileNotFoundError(f"Missing {MANIFEST_NAME} in {input_path}")

        manifest = json.loads(manifest_path.read_text())

        # Default target variant: match whatever the source was originally
        # unpacked from (lbi or lbi_nand_oob), stored in the manifest.
        if target_variant is None:
            target_variant = manifest.get(
                "source_variant", VARIANT_LBI,
            )

        header = manifest["header"]
        partition_size = manifest["partition_size"]
        sec_infos = manifest["sections"]
        data_start = header["data_start"]

        logger.info(
            "Packing LBI %s/ → %s (%d sections, partition_size=%d)",
            input_path.name, output_path.name,
            len(sec_infos), partition_size,
        )

        # Read actual section file sizes and recompute offsets.
        # The LBI format stores section sizes in the descriptors but
        # NOT offsets — those are derived sequentially at parse time.
        # This means we can freely change section sizes as long as the
        # total still fits within the partition.
        file_data: list[bytes] = []
        for si in sec_infos:
            sec_file = input_path / si["filename"]
            if not sec_file.exists():
                raise FileNotFoundError(f"Missing section file: {si['filename']}")
            file_data.append(sec_file.read_bytes())

        # Rebuild section descriptors with recomputed offsets
        sections: list[SectionInfo] = []
        offset = data_start
        for si, data in zip(sec_infos, file_data):
            # Sections with size 0 in the original header (e.g. auth
            # block) keep size=0 in the descriptor — the loader infers
            # their extent.  All other sections get the actual file size.
            header_size_field = 0 if si["size_in_header"] == 0 else len(data)

            sec = SectionInfo(
                index=si["index"],
                role_flags=si["role_flags"],
                load_address=si["load_address"],
                size=header_size_field,
                image_type=si["image_type"],
                entry_point=si["entry_point"],
                reserved=si["reserved"],
                data_offset=offset,
                data_size=len(data),
            )
            sections.append(sec)

            # Advance offset past data, aligned to data_start
            end = offset + len(data)
            offset = ((end + data_start - 1) // data_start) * data_start

        # Verify everything fits
        if offset > partition_size:
            raise ValueError(
                f"Packed sections require {offset} bytes but partition "
                f"is only {partition_size} bytes. Reduce section sizes or "
                f"increase partition_size in the manifest."
            )

        # Build output buffer, pre-filled with 0xFF
        buf = bytearray(b"\xff" * partition_size)

        # Write header
        hdr_bytes = _build_lbi_header(header, sections)
        buf[: len(hdr_bytes)] = hdr_bytes

        # Pad header to data_start with 0xFF (already done by pre-fill)

        # Write section data
        for sec, si, data in zip(sections, sec_infos, file_data):
            buf[sec.data_offset : sec.data_offset + len(data)] = data

            # Sections with size 0 in the header (e.g. auth block) use
            # 0x00 padding between the data end and the next alignment
            # boundary, unlike regular sections which use 0xFF.
            if sec.size == 0 and len(data) > 0:
                data_end = sec.data_offset + len(data)
                aligned_end = ((data_end + data_start - 1) // data_start) * data_start
                buf[data_end:aligned_end] = b"\x00" * (aligned_end - data_end)

            logger.info(
                "  section %d %-16s  offset=0x%06X  size=%8d",
                sec.index, si["name"], sec.data_offset, len(data),
            )

        # If the target is a page+OOB variant, re-interleave OOB spare
        # bytes so the output matches the raw NAND dump format.
        if target_variant == VARIANT_LBI_NAND_OOB:
            buf = _insert_oob(bytes(buf))
            logger.info(
                "Re-inserted NAND OOB: %d → %d bytes.",
                partition_size, len(buf),
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
                "num_sections": len(sections),
                "partition_size": partition_size,
            },
        )

    # ── Kaitai Struct parsing ────────────────────────────────────────

    def parse(self, path: Path, variant: str | None = None) -> Any:
        if variant is None:
            variant = self.identify(path)
        if variant not in (VARIANT_LBI, VARIANT_LBI_NAND_OOB):
            raise ValueError(
                f"Kaitai parsing only supports '{VARIANT_LBI}' or "
                f"'{VARIANT_LBI_NAND_OOB}', got '{variant}'"
            )

        from .kaitai import HpCljPro4301Lbi as Parser

        raw = path.read_bytes()
        if variant == VARIANT_LBI_NAND_OOB:
            raw = _strip_oob(raw)
        return Parser(KaitaiStream(io.BytesIO(raw)))
