"""Firmware plugin for UBI (Unsorted Block Images).

Supports unpacking a raw UBI image into its constituent volume data
files and repacking volume data back into a UBI image.

- **ubi_image**: Raw UBI image as found on an MTD partition.
- **ubi_volumes**: Directory containing extracted volume data files and
  a ``ubi_manifest.json`` manifest that records the exact image layout.

The plugin implements a pure-Python UBI parser and builder so that no
external tools (ubinize, mtd-utils) are required.
"""

from __future__ import annotations

import json
import logging
import struct
import zlib
from dataclasses import dataclass, field
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

UBI_EC_HDR_MAGIC = b"UBI#"  # 0x55424923
UBI_VID_HDR_MAGIC = b"UBI!"  # 0x55424921

UBI_EC_HDR_SIZE = 64
UBI_VID_HDR_SIZE = 64
UBI_VTBL_RECORD_SIZE = 172
UBI_MAX_VOLUMES = 128

UBI_LAYOUT_VOL_ID = 0x7FFFEFFF

# Volume types
UBI_VID_DYNAMIC = 1
UBI_VID_STATIC = 2

VARIANT_UBI_IMAGE = "ubi_image"
VARIANT_UBI_VOLUMES = "ubi_volumes"

MANIFEST_FILENAME = "ubi_manifest.json"
PEB_HEADERS_FILENAME = "peb_headers.bin"


# ── CRC helper ───────────────────────────────────────────────────────

def _ubi_crc32(data: bytes) -> int:
    """Compute UBI-style CRC-32 (kernel crc32 with seed 0xFFFFFFFF)."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class EcHeader:
    """UBI Erase Counter header (64 bytes at start of each PEB)."""
    magic: bytes = UBI_EC_HDR_MAGIC
    version: int = 1
    ec: int = 0
    vid_hdr_offset: int = 512
    data_offset: int = 2048
    image_seq: int = 0
    hdr_crc: int = 0

    def pack(self) -> bytes:
        buf = bytearray(UBI_EC_HDR_SIZE)
        struct.pack_into(">4sBxxxQIII", buf, 0,
                         self.magic, self.version, self.ec,
                         self.vid_hdr_offset, self.data_offset,
                         self.image_seq)
        # Padding bytes 28-59 are zero
        crc = _ubi_crc32(bytes(buf[:60]))
        struct.pack_into(">I", buf, 60, crc)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> "EcHeader":
        magic = data[0:4]
        version = data[4]
        ec = struct.unpack(">Q", data[8:16])[0]
        vid_hdr_offset = struct.unpack(">I", data[16:20])[0]
        data_offset = struct.unpack(">I", data[20:24])[0]
        image_seq = struct.unpack(">I", data[24:28])[0]
        hdr_crc = struct.unpack(">I", data[60:64])[0]
        return cls(magic=magic, version=version, ec=ec,
                   vid_hdr_offset=vid_hdr_offset,
                   data_offset=data_offset,
                   image_seq=image_seq, hdr_crc=hdr_crc)


@dataclass
class VidHeader:
    """UBI Volume Identifier header (64 bytes at vid_hdr_offset)."""
    magic: bytes = UBI_VID_HDR_MAGIC
    version: int = 1
    vol_type: int = UBI_VID_DYNAMIC
    copy_flag: int = 0
    compat: int = 0
    vol_id: int = 0
    lnum: int = 0
    data_size: int = 0
    used_ebs: int = 0
    data_pad: int = 0
    data_crc: int = 0
    sqnum: int = 0
    hdr_crc: int = 0

    def pack(self) -> bytes:
        buf = bytearray(UBI_VID_HDR_SIZE)
        struct.pack_into(">4sBBBBIIxxxx", buf, 0,
                         self.magic, self.version, self.vol_type,
                         self.copy_flag, self.compat,
                         self.vol_id, self.lnum)
        # data_size at offset 20
        struct.pack_into(">I", buf, 20, self.data_size)
        # used_ebs at offset 24
        struct.pack_into(">I", buf, 24, self.used_ebs)
        # data_pad at offset 28
        struct.pack_into(">I", buf, 28, self.data_pad)
        # data_crc at offset 32
        struct.pack_into(">I", buf, 32, self.data_crc)
        # sqnum at offset 40
        struct.pack_into(">Q", buf, 40, self.sqnum)
        # CRC over bytes 0-59
        crc = _ubi_crc32(bytes(buf[:60]))
        struct.pack_into(">I", buf, 60, crc)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> "VidHeader":
        magic = data[0:4]
        version = data[4]
        vol_type = data[5]
        copy_flag = data[6]
        compat = data[7]
        vol_id = struct.unpack(">I", data[8:12])[0]
        lnum = struct.unpack(">I", data[12:16])[0]
        data_size = struct.unpack(">I", data[20:24])[0]
        used_ebs = struct.unpack(">I", data[24:28])[0]
        data_pad = struct.unpack(">I", data[28:32])[0]
        data_crc = struct.unpack(">I", data[32:36])[0]
        sqnum = struct.unpack(">Q", data[40:48])[0]
        hdr_crc = struct.unpack(">I", data[60:64])[0]
        return cls(magic=magic, version=version, vol_type=vol_type,
                   copy_flag=copy_flag, compat=compat,
                   vol_id=vol_id, lnum=lnum,
                   data_size=data_size, used_ebs=used_ebs,
                   data_pad=data_pad, data_crc=data_crc,
                   sqnum=sqnum, hdr_crc=hdr_crc)


@dataclass
class VtblRecord:
    """UBI Volume Table record (172 bytes)."""
    reserved_pebs: int = 0
    alignment: int = 0
    data_pad: int = 0
    vol_type: int = 0
    upd_marker: int = 0
    name_len: int = 0
    name: str = ""
    flags: int = 0
    crc: int = 0

    def pack(self) -> bytes:
        buf = bytearray(UBI_VTBL_RECORD_SIZE)
        struct.pack_into(">IIIBBH", buf, 0,
                         self.reserved_pebs, self.alignment,
                         self.data_pad, self.vol_type,
                         self.upd_marker, self.name_len)
        # Name at offset 16, up to 128 bytes
        name_bytes = self.name.encode("utf-8")[:128]
        buf[16:16 + len(name_bytes)] = name_bytes
        # Flags at offset 144
        buf[144] = self.flags
        # CRC over bytes 0-167
        crc = _ubi_crc32(bytes(buf[:168]))
        struct.pack_into(">I", buf, 168, crc)
        return bytes(buf)

    @classmethod
    def parse(cls, data: bytes) -> "VtblRecord":
        reserved_pebs = struct.unpack(">I", data[0:4])[0]
        alignment = struct.unpack(">I", data[4:8])[0]
        data_pad = struct.unpack(">I", data[8:12])[0]
        vol_type = data[12]
        upd_marker = data[13]
        name_len = struct.unpack(">H", data[14:16])[0]
        name = data[16:16 + name_len].decode("utf-8", errors="replace") if name_len else ""
        flags = data[144]
        crc = struct.unpack(">I", data[168:172])[0]
        return cls(reserved_pebs=reserved_pebs, alignment=alignment,
                   data_pad=data_pad, vol_type=vol_type,
                   upd_marker=upd_marker, name_len=name_len,
                   name=name, flags=flags, crc=crc)


@dataclass
class PebInfo:
    """Parsed information about a single PEB."""
    index: int
    ec_hdr: EcHeader | None = None
    vid_hdr: VidHeader | None = None
    peb_type: str = "unknown"  # "layout", "data", "free", "empty"


@dataclass
class VolumeInfo:
    """Parsed volume metadata."""
    vol_id: int
    name: str
    vol_type: int
    reserved_pebs: int
    alignment: int
    data_pad: int
    flags: int
    leb_count: int = 0


# ── UBI image parser ────────────────────────────────────────────────

def parse_ubi_image(path: Path) -> dict[str, Any]:
    """Parse a UBI image and return full structural information.

    Returns a dict with keys: peb_size, vid_hdr_offset, data_offset,
    leb_size, image_seq, num_pebs, peb_map, volumes, vtbl_records,
    free_pebs, empty_pebs.
    """
    file_size = path.stat().st_size

    with open(path, "rb") as f:
        # Read first EC header to determine geometry
        first_ec = f.read(UBI_EC_HDR_SIZE)
        if first_ec[:4] != UBI_EC_HDR_MAGIC:
            raise ValueError("Not a UBI image: bad EC header magic")
        ec0 = EcHeader.parse(first_ec)

        vid_hdr_offset = ec0.vid_hdr_offset
        data_offset = ec0.data_offset
        image_seq = ec0.image_seq

        # Determine PEB size by scanning — try common sizes
        # The PEB size must divide the file evenly, and the second PEB
        # must also start with a valid EC header.
        peb_size = None
        for candidate in [131072, 65536, 262144, 16384, 32768, 524288]:
            if file_size % candidate != 0 and file_size >= candidate * 2:
                continue
            if file_size < candidate * 2:
                continue
            f.seek(candidate)
            probe = f.read(4)
            if probe in (UBI_EC_HDR_MAGIC, b"\xff\xff\xff\xff", b"\x00\x00\x00\x00"):
                peb_size = candidate
                break

        if peb_size is None:
            raise ValueError("Cannot determine PEB size")

        num_pebs = file_size // peb_size
        leb_size = peb_size - data_offset

        logger.info(
            "UBI image: %d PEBs, PEB=%d, LEB=%d, vid_off=%d, data_off=%d, "
            "image_seq=%d",
            num_pebs, peb_size, leb_size, vid_hdr_offset, data_offset,
            image_seq,
        )

        # Scan all PEBs
        peb_map: list[dict[str, Any]] = []
        layout_pebs: list[int] = []
        data_pebs: dict[int, list[dict[str, Any]]] = {}  # vol_id → list
        free_pebs: list[int] = []
        empty_pebs: list[int] = []  # All-zero PEBs

        for i in range(num_pebs):
            f.seek(i * peb_size)
            ec_raw = f.read(UBI_EC_HDR_SIZE)

            if ec_raw[:4] == b"\x00\x00\x00\x00":
                empty_pebs.append(i)
                peb_map.append({"index": i, "type": "empty"})
                continue

            if ec_raw[:4] == b"\xff\xff\xff\xff":
                free_pebs.append(i)
                peb_map.append({"index": i, "type": "erased"})
                continue

            if ec_raw[:4] != UBI_EC_HDR_MAGIC:
                empty_pebs.append(i)
                peb_map.append({"index": i, "type": "unknown",
                                "magic": ec_raw[:4].hex()})
                continue

            ec_hdr = EcHeader.parse(ec_raw)

            # Read VID header
            f.seek(i * peb_size + vid_hdr_offset)
            vid_raw = f.read(UBI_VID_HDR_SIZE)

            if vid_raw[:4] != UBI_VID_HDR_MAGIC:
                # EC header present but no VID → free PEB
                free_pebs.append(i)
                peb_map.append({
                    "index": i, "type": "free",
                    "ec": ec_hdr.ec,
                })
                continue

            vid_hdr = VidHeader.parse(vid_raw)

            if vid_hdr.vol_id == UBI_LAYOUT_VOL_ID:
                layout_pebs.append(i)
                peb_map.append({
                    "index": i, "type": "layout",
                    "ec": ec_hdr.ec, "lnum": vid_hdr.lnum,
                    "sqnum": vid_hdr.sqnum, "compat": vid_hdr.compat,
                })
            else:
                if vid_hdr.vol_id not in data_pebs:
                    data_pebs[vid_hdr.vol_id] = []
                data_pebs[vid_hdr.vol_id].append({
                    "peb": i, "lnum": vid_hdr.lnum,
                    "ec": ec_hdr.ec, "sqnum": vid_hdr.sqnum,
                    "vol_type": vid_hdr.vol_type,
                    "copy_flag": vid_hdr.copy_flag,
                    "data_size": vid_hdr.data_size,
                    "used_ebs": vid_hdr.used_ebs,
                    "data_pad": vid_hdr.data_pad,
                    "data_crc": vid_hdr.data_crc,
                })
                peb_map.append({
                    "index": i, "type": "data",
                    "vol_id": vid_hdr.vol_id, "lnum": vid_hdr.lnum,
                    "ec": ec_hdr.ec, "sqnum": vid_hdr.sqnum,
                })

        # Parse volume table from first layout PEB
        vtbl_records: list[dict[str, Any]] = []
        volumes: list[VolumeInfo] = []

        if layout_pebs:
            f.seek(layout_pebs[0] * peb_size + data_offset)
            vtbl_data = f.read(leb_size)

            for vi in range(UBI_MAX_VOLUMES):
                offset = vi * UBI_VTBL_RECORD_SIZE
                rec_data = vtbl_data[offset:offset + UBI_VTBL_RECORD_SIZE]
                rec = VtblRecord.parse(rec_data)

                if rec.reserved_pebs == 0 and rec.name_len == 0:
                    continue

                vtbl_records.append({
                    "vol_id": vi,
                    "name": rec.name,
                    "reserved_pebs": rec.reserved_pebs,
                    "alignment": rec.alignment,
                    "data_pad": rec.data_pad,
                    "vol_type": rec.vol_type,
                    "upd_marker": rec.upd_marker,
                    "name_len": rec.name_len,
                    "flags": rec.flags,
                })

                leb_count = len(data_pebs.get(vi, []))
                volumes.append(VolumeInfo(
                    vol_id=vi, name=rec.name, vol_type=rec.vol_type,
                    reserved_pebs=rec.reserved_pebs,
                    alignment=rec.alignment, data_pad=rec.data_pad,
                    flags=rec.flags, leb_count=leb_count,
                ))

    return {
        "peb_size": peb_size,
        "vid_hdr_offset": vid_hdr_offset,
        "data_offset": data_offset,
        "leb_size": leb_size,
        "image_seq": image_seq,
        "num_pebs": num_pebs,
        "peb_map": peb_map,
        "layout_pebs": layout_pebs,
        "data_pebs": data_pebs,
        "volumes": volumes,
        "vtbl_records": vtbl_records,
        "free_pebs": free_pebs,
        "empty_pebs": empty_pebs,
    }


def extract_volume(
    image_path: Path,
    vol_id: int,
    peb_entries: list[dict[str, Any]],
    peb_size: int,
    data_offset: int,
    leb_size: int,
    output_path: Path,
) -> int:
    """Extract a single UBI volume to a file.

    Returns the number of bytes written.
    """
    # Sort by LEB number
    sorted_pebs = sorted(peb_entries, key=lambda x: x["lnum"])

    with open(image_path, "rb") as src, open(output_path, "wb") as dst:
        written = 0
        for entry in sorted_pebs:
            peb_idx = entry["peb"]
            src.seek(peb_idx * peb_size + data_offset)
            leb_data = src.read(leb_size)
            dst.write(leb_data)
            written += len(leb_data)

    return written


def save_peb_headers(
    image_path: Path,
    num_pebs: int,
    peb_size: int,
    data_offset: int,
    output_path: Path,
) -> None:
    """Save the raw header area of every PEB to a binary file.

    Each PEB contributes exactly ``data_offset`` bytes (typically 2048),
    stored contiguously.  This preserves any sub-page metadata or gap
    content that exists between the VID header and data area, which is
    needed for byte-identical roundtrips.
    """
    with open(image_path, "rb") as src, open(output_path, "wb") as dst:
        for i in range(num_pebs):
            src.seek(i * peb_size)
            hdr = src.read(data_offset)
            dst.write(hdr)


# ── UBI image builder ───────────────────────────────────────────────

def _adjust_peb_map(
    manifest: dict[str, Any],
    volume_data: dict[int, bytes],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Adjust the PEB map when volume sizes have changed.

    If a volume shrank, excess data PEBs (those whose LEB numbers are
    beyond the new volume size) are converted to free PEBs.

    If a volume grew, free PEBs are recruited as new data PEBs to hold
    the additional LEBs.

    Returns the adjusted ``(peb_map, vtbl_records)`` — both may be
    modified copies of the originals.
    """
    leb_size = manifest["leb_size"]
    peb_map = [dict(e) for e in manifest["peb_map"]]  # deep copy
    vtbl_records = [dict(r) for r in manifest["vtbl_records"]]

    for vol_info in manifest["volumes"]:
        vol_id = vol_info["vol_id"]
        vol_bytes = volume_data.get(vol_id, b"")
        needed_lebs = (len(vol_bytes) + leb_size - 1) // leb_size

        # Count current data PEBs for this volume
        current_data = [
            (i, e) for i, e in enumerate(peb_map)
            if e["type"] == "data" and e.get("vol_id") == vol_id
        ]
        current_lebs = len(current_data)

        if needed_lebs == current_lebs:
            continue  # No change needed

        if needed_lebs < current_lebs:
            # Volume shrank — convert excess data PEBs to free
            # Sort by LEB number descending so we remove the highest first
            current_data.sort(key=lambda x: x[1]["lnum"], reverse=True)
            excess = current_lebs - needed_lebs
            freed = 0
            for map_idx, entry in current_data:
                if freed >= excess:
                    break
                if entry["lnum"] >= needed_lebs:
                    logger.info(
                        "  Volume %d: converting PEB %d (LEB %d) "
                        "from data to free",
                        vol_id, entry["index"], entry["lnum"],
                    )
                    peb_map[map_idx] = {
                        "index": entry["index"],
                        "type": "free",
                        "ec": entry.get("ec", 0),
                    }
                    freed += 1

            logger.info(
                "  Volume %d shrank: %d → %d LEBs, freed %d PEBs",
                vol_id, current_lebs, needed_lebs, freed,
            )

        else:
            # Volume grew — recruit free PEBs as new data PEBs
            extra_needed = needed_lebs - current_lebs
            # Recruit from "free" PEBs first (have EC header), then
            # "erased" PEBs (all-0xFF, no EC header yet)
            free_indices = [
                i for i, e in enumerate(peb_map)
                if e["type"] in ("free", "erased")
            ]

            if extra_needed > len(free_indices):
                raise ValueError(
                    f"Volume {vol_id} needs {extra_needed} additional "
                    f"PEBs but only {len(free_indices)} free PEBs are "
                    f"available.  The volume data ({len(vol_bytes)} bytes, "
                    f"{needed_lebs} LEBs) does not fit."
                )

            # Find the vol_type from existing data PEBs
            vol_type = UBI_VID_DYNAMIC
            for _, e in current_data:
                vol_type = e.get("vol_type", UBI_VID_DYNAMIC)
                break

            # Assign free PEBs to new LEB numbers
            next_lnum = current_lebs
            recruited = 0
            for fi in free_indices:
                if recruited >= extra_needed:
                    break
                old_entry = peb_map[fi]
                logger.info(
                    "  Volume %d: converting PEB %d from free to data "
                    "(LEB %d)",
                    vol_id, old_entry["index"], next_lnum,
                )
                peb_map[fi] = {
                    "index": old_entry["index"],
                    "type": "data",
                    "vol_id": vol_id,
                    "lnum": next_lnum,
                    "ec": old_entry.get("ec", 0),
                    "sqnum": 0,
                    "vol_type": vol_type,
                    "copy_flag": 0,
                    "data_size": 0,
                    "used_ebs": 0,
                    "data_pad": 0,
                    "data_crc": 0,
                }
                next_lnum += 1
                recruited += 1

            logger.info(
                "  Volume %d grew: %d → %d LEBs, recruited %d PEBs",
                vol_id, current_lebs, needed_lebs, recruited,
            )

        # Update reserved_pebs in volume table
        for vr in vtbl_records:
            if vr["vol_id"] == vol_id:
                vr["reserved_pebs"] = needed_lebs
                break

    return peb_map, vtbl_records


def build_ubi_image(
    manifest: dict[str, Any],
    volume_files: dict[int, Path],
    output_path: Path,
    peb_headers_path: Path | None = None,
) -> None:
    """Build a UBI image from manifest and volume data files.

    This is a pure-Python replacement for ubinize.  It reconstructs
    the image using the exact PEB layout recorded in the manifest.

    If *peb_headers_path* is provided, the raw PEB header areas
    (EC header, VID header, and any gap/sub-page content) are
    restored verbatim from that file for a byte-identical roundtrip.

    When the volume data differs in size from what was originally
    extracted, the PEB map is automatically adjusted: excess data
    PEBs become free, or free PEBs are recruited as data PEBs.
    """
    peb_size = manifest["peb_size"]
    vid_hdr_offset = manifest["vid_hdr_offset"]
    data_offset = manifest["data_offset"]
    leb_size = manifest["leb_size"]
    image_seq = manifest["image_seq"]

    # Pre-read all volume data
    volume_data: dict[int, bytes] = {}
    for vol_id, vpath in volume_files.items():
        volume_data[vol_id] = vpath.read_bytes()

    # Adjust PEB map if volume sizes changed
    peb_map, vtbl_records = _adjust_peb_map(manifest, volume_data)

    # Load saved PEB headers if available
    saved_headers: bytes | None = None
    if peb_headers_path and peb_headers_path.exists():
        saved_headers = peb_headers_path.read_bytes()
        logger.info("  Using saved PEB headers for header restoration")

    # Build the volume table LEB data
    vtbl_leb = _build_vtbl_leb(vtbl_records, leb_size)

    with open(output_path, "wb") as f:
        for peb_info in peb_map:
            peb_idx = peb_info["index"]
            f.seek(peb_idx * peb_size)
            peb_type = peb_info["type"]

            if peb_type in ("empty", "unknown"):
                # All-zero PEB
                f.write(b"\x00" * peb_size)

            elif peb_type == "erased":
                # All-0xFF PEB (fully erased)
                f.write(b"\xff" * peb_size)

            elif peb_type == "free":
                buf = bytearray(b"\xff" * peb_size)
                if saved_headers:
                    hdr = saved_headers[
                        peb_idx * data_offset:(peb_idx + 1) * data_offset
                    ]
                    buf[:data_offset] = hdr
                    # Clear the VID header — this PEB may have been
                    # converted from data to free, so the saved header
                    # still has a VID.  Wipe it to 0xFF so UBI sees
                    # this as an erased PEB with only an EC header.
                    buf[vid_hdr_offset:data_offset] = (
                        b"\xff" * (data_offset - vid_hdr_offset)
                    )
                else:
                    ec = EcHeader(
                        ec=peb_info.get("ec", 0),
                        vid_hdr_offset=vid_hdr_offset,
                        data_offset=data_offset,
                        image_seq=image_seq,
                    )
                    buf[:UBI_EC_HDR_SIZE] = ec.pack()
                f.write(bytes(buf))

            elif peb_type == "layout":
                buf = bytearray(b"\xff" * peb_size)
                if saved_headers:
                    hdr = saved_headers[
                        peb_idx * data_offset:(peb_idx + 1) * data_offset
                    ]
                    buf[:data_offset] = hdr
                else:
                    lnum = peb_info["lnum"]
                    ec = EcHeader(
                        ec=peb_info.get("ec", 0),
                        vid_hdr_offset=vid_hdr_offset,
                        data_offset=data_offset,
                        image_seq=image_seq,
                    )
                    buf[:UBI_EC_HDR_SIZE] = ec.pack()
                    vid = VidHeader(
                        vol_type=UBI_VID_DYNAMIC,
                        compat=peb_info.get("compat", 5),
                        vol_id=UBI_LAYOUT_VOL_ID,
                        lnum=lnum,
                        sqnum=peb_info.get("sqnum", 0),
                    )
                    buf[vid_hdr_offset:vid_hdr_offset + UBI_VID_HDR_SIZE] = (
                        vid.pack()
                    )
                # Volume table data always goes in the data area
                buf[data_offset:data_offset + len(vtbl_leb)] = vtbl_leb
                f.write(bytes(buf))

            elif peb_type == "data":
                vol_id = peb_info["vol_id"]
                lnum = peb_info["lnum"]

                buf = bytearray(b"\xff" * peb_size)

                if saved_headers:
                    hdr = saved_headers[
                        peb_idx * data_offset:(peb_idx + 1) * data_offset
                    ]
                    buf[:data_offset] = hdr
                    # If this is a newly recruited PEB (was erased/free),
                    # the saved header may not have a valid EC header.
                    # Check and generate one if needed.
                    if buf[:4] != UBI_EC_HDR_MAGIC:
                        ec = EcHeader(
                            ec=peb_info.get("ec", 0),
                            vid_hdr_offset=vid_hdr_offset,
                            data_offset=data_offset,
                            image_seq=image_seq,
                        )
                        buf[:UBI_EC_HDR_SIZE] = ec.pack()
                    # Always regenerate the VID header for data PEBs
                    # so newly recruited PEBs get a valid VID and any
                    # LEB remapping is applied correctly.
                    vid = VidHeader(
                        vol_type=peb_info.get("vol_type", UBI_VID_DYNAMIC),
                        copy_flag=peb_info.get("copy_flag", 0),
                        vol_id=vol_id,
                        lnum=lnum,
                        data_size=peb_info.get("data_size", 0),
                        used_ebs=peb_info.get("used_ebs", 0),
                        data_pad=peb_info.get("data_pad", 0),
                        data_crc=peb_info.get("data_crc", 0),
                        sqnum=peb_info.get("sqnum", 0),
                    )
                    buf[vid_hdr_offset:vid_hdr_offset + UBI_VID_HDR_SIZE] = (
                        vid.pack()
                    )
                else:
                    ec = EcHeader(
                        ec=peb_info.get("ec", 0),
                        vid_hdr_offset=vid_hdr_offset,
                        data_offset=data_offset,
                        image_seq=image_seq,
                    )
                    buf[:UBI_EC_HDR_SIZE] = ec.pack()
                    vid = VidHeader(
                        vol_type=peb_info.get("vol_type", UBI_VID_DYNAMIC),
                        copy_flag=peb_info.get("copy_flag", 0),
                        vol_id=vol_id,
                        lnum=lnum,
                        data_size=peb_info.get("data_size", 0),
                        used_ebs=peb_info.get("used_ebs", 0),
                        data_pad=peb_info.get("data_pad", 0),
                        data_crc=peb_info.get("data_crc", 0),
                        sqnum=peb_info.get("sqnum", 0),
                    )
                    buf[vid_hdr_offset:vid_hdr_offset + UBI_VID_HDR_SIZE] = (
                        vid.pack()
                    )

                # LEB data from volume file
                vol_bytes = volume_data.get(vol_id, b"")
                leb_start = lnum * leb_size
                leb_end = leb_start + leb_size
                leb_data = vol_bytes[leb_start:leb_end]
                buf[data_offset:data_offset + len(leb_data)] = leb_data

                f.write(bytes(buf))

            else:
                f.write(b"\xff" * peb_size)


def _build_vtbl_leb(vtbl_records: list[dict[str, Any]], leb_size: int) -> bytes:
    """Build the volume table LEB from records."""
    buf = bytearray(b"\xff" * leb_size)
    # VTBL records area: first 128*172 bytes, rest stays 0xFF
    vtbl_area = bytearray(UBI_MAX_VOLUMES * UBI_VTBL_RECORD_SIZE)
    for vi in range(UBI_MAX_VOLUMES):
        offset = vi * UBI_VTBL_RECORD_SIZE
        # Find matching record
        rec_dict = None
        for r in vtbl_records:
            if r["vol_id"] == vi:
                rec_dict = r
                break

        if rec_dict:
            rec = VtblRecord(
                reserved_pebs=rec_dict["reserved_pebs"],
                alignment=rec_dict["alignment"],
                data_pad=rec_dict["data_pad"],
                vol_type=rec_dict["vol_type"],
                upd_marker=rec_dict.get("upd_marker", 0),
                name_len=rec_dict["name_len"],
                name=rec_dict["name"],
                flags=rec_dict.get("flags", 0),
            )
        else:
            # Empty record
            rec = VtblRecord()

        rec_bytes = rec.pack()
        vtbl_area[offset:offset + UBI_VTBL_RECORD_SIZE] = rec_bytes

    buf[:len(vtbl_area)] = vtbl_area
    return bytes(buf)


# ── Plugin ──────────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """UBI (Unsorted Block Images) plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="UBI Image",
            description=(
                "UBI (Unsorted Block Images) handler. "
                "Extracts volume data from raw UBI images and "
                "repacks them with a pure-Python builder."
            ),
            version="0.1.0",
            format_id="ubi",
            supported_variants=[VARIANT_UBI_IMAGE, VARIANT_UBI_VOLUMES],
            conversions=self.get_conversions(),
            ksy_files=[],
        )

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_dir():
            # Check for manifest file
            if (path / MANIFEST_FILENAME).is_file():
                return VARIANT_UBI_VOLUMES
            return None

        if path.stat().st_size < UBI_EC_HDR_SIZE:
            return None

        with open(path, "rb") as f:
            magic = f.read(4)
            if magic == UBI_EC_HDR_MAGIC:
                return VARIANT_UBI_IMAGE

        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_UBI_IMAGE,
                target_variant=VARIANT_UBI_VOLUMES,
                description="Extract UBI volume data from image",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_UBI_VOLUMES,
                target_variant=VARIANT_UBI_IMAGE,
                description="Build UBI image from volume data",
                lossy=False,
            ),
        ]

    # ── Unpack (ubi_image → ubi_volumes) ─────────────────────────────

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
        if source_variant != VARIANT_UBI_IMAGE:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_UBI_IMAGE}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_UBI_VOLUMES
        source_hash = file_sha256(input_path)

        # Parse the UBI image
        info = parse_ubi_image(input_path)

        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)

        # Extract each volume
        extracted_files: list[str] = []
        for vol in info["volumes"]:
            vol_id = vol.vol_id
            vol_name = vol.name or f"vol{vol_id}"
            vol_pebs = info["data_pebs"].get(vol_id, [])

            if not vol_pebs:
                logger.warning("Volume %d (%s) has no data PEBs", vol_id, vol_name)
                continue

            # Determine output filename
            out_file = output_path / f"vol{vol_id}_{vol_name}.bin"
            nbytes = extract_volume(
                input_path, vol_id, vol_pebs,
                info["peb_size"], info["data_offset"],
                info["leb_size"], out_file,
            )
            extracted_files.append(out_file.name)

            logger.info(
                "  Volume %d (%s): %d LEBs, %d bytes → %s",
                vol_id, vol_name, len(vol_pebs), nbytes, out_file.name,
            )

        # Save raw PEB header areas for byte-identical roundtrip
        peb_headers_path = output_path / PEB_HEADERS_FILENAME
        save_peb_headers(
            input_path, info["num_pebs"],
            info["peb_size"], info["data_offset"],
            peb_headers_path,
        )
        logger.info(
            "  Saved PEB headers: %d bytes",
            peb_headers_path.stat().st_size,
        )

        # Build manifest with all PEB-level details needed for repacking
        # Enrich data PEB map entries with VID header fields
        enriched_peb_map = []
        for peb_info in info["peb_map"]:
            entry = dict(peb_info)
            if entry["type"] == "data":
                vol_id = entry["vol_id"]
                lnum = entry["lnum"]
                # Find matching data_peb entry
                for dp in info["data_pebs"].get(vol_id, []):
                    if dp["peb"] == entry["index"] and dp["lnum"] == lnum:
                        entry["vol_type"] = dp["vol_type"]
                        entry["copy_flag"] = dp["copy_flag"]
                        entry["data_size"] = dp["data_size"]
                        entry["used_ebs"] = dp["used_ebs"]
                        entry["data_pad"] = dp["data_pad"]
                        entry["data_crc"] = dp["data_crc"]
                        break
            enriched_peb_map.append(entry)

        manifest = {
            "peb_size": info["peb_size"],
            "vid_hdr_offset": info["vid_hdr_offset"],
            "data_offset": info["data_offset"],
            "leb_size": info["leb_size"],
            "image_seq": info["image_seq"],
            "num_pebs": info["num_pebs"],
            "peb_map": enriched_peb_map,
            "vtbl_records": info["vtbl_records"],
            "volumes": [
                {
                    "vol_id": v.vol_id,
                    "name": v.name,
                    "vol_type": v.vol_type,
                    "reserved_pebs": v.reserved_pebs,
                    "alignment": v.alignment,
                    "data_pad": v.data_pad,
                    "flags": v.flags,
                    "leb_count": v.leb_count,
                    "filename": f"vol{v.vol_id}_{v.name}.bin",
                }
                for v in info["volumes"]
            ],
            "extracted_files": extracted_files,
            "free_peb_count": len(info["free_pebs"]),
            "empty_peb_count": len(info["empty_pebs"]),
        }

        manifest_path = output_path / MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        # Compute output hash from manifest
        output_hash = file_sha256(manifest_path)

        metadata: dict[str, Any] = {
            "peb_size": info["peb_size"],
            "leb_size": info["leb_size"],
            "num_pebs": info["num_pebs"],
            "image_seq": info["image_seq"],
            "num_volumes": len(info["volumes"]),
            "free_pebs": len(info["free_pebs"]),
            "empty_pebs": len(info["empty_pebs"]),
        }
        for vol in info["volumes"]:
            metadata[f"vol{vol.vol_id}_name"] = vol.name
            metadata[f"vol{vol.vol_id}_lebs"] = vol.leb_count
            metadata[f"vol{vol.vol_id}_type"] = (
                "dynamic" if vol.vol_type == UBI_VID_DYNAMIC else "static"
            )

        logger.info(
            "Extracted %d volume(s) from UBI image (%d PEBs)",
            len(info["volumes"]), info["num_pebs"],
        )

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )

    # ── Pack (ubi_volumes → ubi_image) ──────────────────────────────

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
        if source_variant != VARIANT_UBI_VOLUMES:
            raise ValueError(
                f"Pack expects variant '{VARIANT_UBI_VOLUMES}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_UBI_IMAGE
        source_hash = file_sha256(input_path / MANIFEST_FILENAME)

        # Load manifest
        manifest_path = input_path / MANIFEST_FILENAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        # Locate volume data files
        volume_files: dict[int, Path] = {}
        for vol_info in manifest["volumes"]:
            vol_id = vol_info["vol_id"]
            vol_file = input_path / vol_info["filename"]
            if not vol_file.exists():
                raise FileNotFoundError(
                    f"Volume data file not found: {vol_file}"
                )
            volume_files[vol_id] = vol_file

        # Ensure output path has a file extension
        if output_path.is_dir() or (
            not output_path.suffix and not output_path.exists()
        ):
            output_path.mkdir(parents=True, exist_ok=True)
            output_path = output_path / "ubi_image.bin"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Check for saved PEB headers
        peb_headers_path = input_path / PEB_HEADERS_FILENAME
        if not peb_headers_path.exists():
            peb_headers_path = None

        logger.info(
            "Building UBI image: %d PEBs, PEB=%d, %d volume(s)",
            manifest["num_pebs"], manifest["peb_size"],
            len(manifest["volumes"]),
        )

        # Build the image
        build_ubi_image(manifest, volume_files, output_path, peb_headers_path)

        output_hash = file_sha256(output_path)

        metadata: dict[str, Any] = {
            "peb_size": manifest["peb_size"],
            "num_pebs": manifest["num_pebs"],
            "image_size": output_path.stat().st_size,
            "num_volumes": len(manifest["volumes"]),
        }

        logger.info("  UBI image written: %s", output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )
