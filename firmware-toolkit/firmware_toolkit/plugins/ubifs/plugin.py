"""Firmware plugin for UBIFS (UBI File System).

Extracts files from a raw UBIFS volume image.  Two extraction strategies
are supported:

1. **Index-tree walk** (preferred) — Parses the master node to locate the
   B-tree root, then walks the index tree to discover all inodes,
   directory entries, and data nodes.  This is the correct, efficient
   approach and produces authoritative results.

2. **Raw node scan** (fallback) — Scans every node in the volume
   sequentially, bypassing the index tree.  For each inode, directory
   entry, and data chunk the latest version (by sequence number) is
   kept.  This is robust against corrupted or dirty indexes (e.g. from
   live system dumps where the journal was not cleanly committed).

The plugin tries strategy 1 first.  If it fails (corrupted index,
missing master node, etc.) it automatically falls back to strategy 2
and emits a warning.

- **ubifs_volume**: Raw UBIFS volume data (as extracted by the UBI plugin).
- **ubifs_files**: Directory containing the extracted filesystem tree and
  a ``ubifs_manifest.json`` manifest with inode/file metadata.

Supports LZO, ZLIB, and uncompressed data nodes.  ZSTD support can be
added if needed (requires the ``zstandard`` package).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import logging
import os
import shutil
import stat
import struct
import subprocess
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

UBIFS_NODE_MAGIC = 0x06101831

# Common header size (magic + crc + sqnum + len + node_type + group_type + pad)
UBIFS_CH_SIZE = 24

# On-disk key length in content node headers (zero-padded to 16 bytes)
UBIFS_KEY_LEN = 16

# On-disk key length in index branches (only 8 meaningful bytes)
UBIFS_BRANCH_KEY_LEN = 8

# Node types
UBIFS_INO_NODE = 0   # inode
UBIFS_DATA_NODE = 1  # file data chunk
UBIFS_DENT_NODE = 2  # directory entry
UBIFS_XENT_NODE = 3  # extended attribute entry
UBIFS_TRUN_NODE = 4  # truncation
UBIFS_PAD_NODE = 5   # padding
UBIFS_SB_NODE = 6    # superblock
UBIFS_MST_NODE = 7   # master
UBIFS_REF_NODE = 8   # reference (log)
UBIFS_IDX_NODE = 9   # index

# Compression types
UBIFS_COMPR_NONE = 0
UBIFS_COMPR_LZO = 1
UBIFS_COMPR_ZLIB = 2
UBIFS_COMPR_ZSTD = 3

# UBIFS key type bits (bits 29-31 of second word)
UBIFS_KEY_TYPE_MASK = 0xE0000000
UBIFS_KEY_BLOCK_MASK = 0x1FFFFFFF

# Key types (encoded in bits 29-31)
UBIFS_KEY_TYPE_INO = 0
UBIFS_KEY_TYPE_DATA = 1
UBIFS_KEY_TYPE_DENT = 2
UBIFS_KEY_TYPE_XENT = 3

# Inode types (in directory entries)
UBIFS_ITYPE_REG = 0   # regular file
UBIFS_ITYPE_DIR = 1   # directory
UBIFS_ITYPE_LNK = 2   # symbolic link
UBIFS_ITYPE_BLK = 3   # block device
UBIFS_ITYPE_CHR = 4   # character device
UBIFS_ITYPE_FIFO = 5  # FIFO
UBIFS_ITYPE_SOCK = 6  # socket

# Index branch size: lnum(4) + offs(4) + len(4) + key(8) = 20 (matches kernel)
UBIFS_BRANCH_SIZE = 4 + 4 + 4 + UBIFS_BRANCH_KEY_LEN  # 20

VARIANT_UBIFS_VOLUME = "ubifs_volume"
VARIANT_UBIFS_FILES = "ubifs_files"

MANIFEST_FILENAME = "ubifs_manifest.json"

# Extraction method names for manifest/metadata
METHOD_INDEX = "index"
METHOD_SCAN = "scan"

EXTRACTED_DIRNAME = "rootfs"

# Compression ID → mkfs.ubifs --compr name
_COMPR_ID_TO_NAME: dict[int, str] = {
    UBIFS_COMPR_NONE: "none",
    UBIFS_COMPR_LZO: "lzo",
    UBIFS_COMPR_ZLIB: "zlib",
    UBIFS_COMPR_ZSTD: "zstd",
}


def _tool_available(name: str) -> bool:
    """Return True if *name* is found on PATH."""
    return shutil.which(name) is not None


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run a command, raising on failure with stderr details."""
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result


# ── LZO decompression via ctypes ────────────────────────────────────

_lzo_lib = None


def _get_lzo() -> ctypes.CDLL:
    """Lazily load liblzo2."""
    global _lzo_lib
    if _lzo_lib is None:
        lib_name = ctypes.util.find_library("lzo2")
        if lib_name is None:
            # Try common paths directly
            for candidate in ("liblzo2.so.2", "liblzo2.so", "liblzo2.dylib"):
                try:
                    _lzo_lib = ctypes.CDLL(candidate)
                    break
                except OSError:
                    continue
            if _lzo_lib is None:
                raise RuntimeError(
                    "liblzo2 not found.  Install it with: "
                    "apt install liblzo2-dev (Debian/Ubuntu) or "
                    "brew install lzo (macOS)"
                )
        else:
            _lzo_lib = ctypes.CDLL(lib_name)
    return _lzo_lib


def _lzo_decompress(src: bytes, dst_len: int) -> bytes:
    """Decompress LZO1X data using liblzo2 via ctypes."""
    lzo = _get_lzo()
    dst = ctypes.create_string_buffer(dst_len)
    dst_len_c = ctypes.c_size_t(dst_len)
    wrkmem = ctypes.create_string_buffer(1)
    ret = lzo.lzo1x_decompress_safe(
        src, len(src),
        dst, ctypes.byref(dst_len_c),
        wrkmem,
    )
    if ret != 0:
        raise RuntimeError(f"LZO decompression failed (error code {ret})")
    return dst.raw[: dst_len_c.value]


# ── Decompression dispatcher ────────────────────────────────────────

def _decompress(data: bytes, compr_type: int, out_len: int) -> bytes:
    """Decompress a UBIFS data chunk."""
    if compr_type == UBIFS_COMPR_NONE:
        return data[:out_len]
    elif compr_type == UBIFS_COMPR_LZO:
        return _lzo_decompress(data, out_len)
    elif compr_type == UBIFS_COMPR_ZLIB:
        return zlib.decompress(data)[:out_len]
    elif compr_type == UBIFS_COMPR_ZSTD:
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data, max_output_size=out_len)[:out_len]
        except ImportError:
            raise RuntimeError(
                "ZSTD compression encountered but 'zstandard' package "
                "is not installed.  Install with: pip install zstandard"
            )
    else:
        raise ValueError(f"Unknown UBIFS compression type: {compr_type}")


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class UbifsSuperblock:
    """Parsed UBIFS superblock (SB node)."""
    key_hash: int = 0
    key_fmt: int = 0
    flags: int = 0
    min_io_size: int = 0
    leb_size: int = 0
    leb_cnt: int = 0
    max_leb_cnt: int = 0
    max_bud_bytes: int = 0
    log_lebs: int = 0
    lpt_lebs: int = 0
    orph_lebs: int = 0
    jhead_cnt: int = 0
    fanout: int = 0
    lsave_cnt: int = 0
    fmt_version: int = 0
    default_compr: int = 0


@dataclass
class UbifsMasterNode:
    """Parsed UBIFS master node."""
    highest_inum: int = 0
    cmt_no: int = 0
    flags: int = 0
    log_lnum: int = 0
    root_lnum: int = 0
    root_offs: int = 0
    root_len: int = 0
    gc_lnum: int = 0
    ihead_lnum: int = 0
    ihead_offs: int = 0
    index_size: int = 0
    leb_cnt: int = 0


@dataclass
class UbifsInode:
    """Parsed UBIFS inode node."""
    inum: int = 0
    sqnum: int = 0
    # From inode-specific fields (after common header + key)
    creat_sqnum: int = 0
    size: int = 0
    atime_sec: int = 0
    ctime_sec: int = 0
    mtime_sec: int = 0
    nlink: int = 0
    uid: int = 0
    gid: int = 0
    mode: int = 0
    flags: int = 0
    data_len: int = 0
    # Inline symlink target or inline data
    inline_data: bytes = b""


@dataclass
class UbifsDent:
    """Parsed UBIFS directory entry node."""
    parent_inum: int = 0
    sqnum: int = 0
    target_inum: int = 0
    itype: int = 0
    name: str = ""


@dataclass
class UbifsDataChunk:
    """Parsed UBIFS data node (one block of file data)."""
    inum: int = 0
    block_num: int = 0
    sqnum: int = 0
    compr_type: int = 0
    out_len: int = 0
    data: bytes = b""


# ── Common node parsers ──────────────────────────────────────────────

def _parse_common_header(buf: bytes, off: int) -> tuple[int, int, int, int] | None:
    """Parse the UBIFS common header at *off*.

    Returns ``(sqnum, node_len, node_type, group_type)`` or ``None``
    if the magic doesn't match.
    """
    if off + UBIFS_CH_SIZE > len(buf):
        return None
    magic = struct.unpack_from("<I", buf, off)[0]
    if magic != UBIFS_NODE_MAGIC:
        return None
    sqnum = struct.unpack_from("<Q", buf, off + 8)[0]
    node_len = struct.unpack_from("<I", buf, off + 16)[0]
    node_type = buf[off + 20]
    group_type = buf[off + 21]
    return sqnum, node_len, node_type, group_type


def _parse_superblock(buf: bytes, off: int) -> UbifsSuperblock:
    """Parse a superblock node starting at *off*."""
    p = off + UBIFS_CH_SIZE
    sb = UbifsSuperblock()
    sb.key_hash = buf[p + 2]
    sb.key_fmt = buf[p + 3]
    sb.flags = struct.unpack_from("<I", buf, p + 4)[0]
    sb.min_io_size = struct.unpack_from("<I", buf, p + 8)[0]
    sb.leb_size = struct.unpack_from("<I", buf, p + 12)[0]
    sb.leb_cnt = struct.unpack_from("<I", buf, p + 16)[0]
    sb.max_leb_cnt = struct.unpack_from("<I", buf, p + 20)[0]
    sb.max_bud_bytes = struct.unpack_from("<Q", buf, p + 24)[0]
    sb.log_lebs = struct.unpack_from("<I", buf, p + 32)[0]
    sb.lpt_lebs = struct.unpack_from("<I", buf, p + 36)[0]
    sb.orph_lebs = struct.unpack_from("<I", buf, p + 40)[0]
    sb.jhead_cnt = struct.unpack_from("<I", buf, p + 44)[0]
    sb.fanout = struct.unpack_from("<I", buf, p + 48)[0]
    sb.lsave_cnt = struct.unpack_from("<I", buf, p + 52)[0]
    sb.fmt_version = struct.unpack_from("<I", buf, p + 56)[0]
    sb.default_compr = struct.unpack_from("<H", buf, p + 60)[0]
    return sb


def _parse_master_node(buf: bytes, off: int) -> UbifsMasterNode:
    """Parse a master node starting at *off*."""
    p = off + UBIFS_CH_SIZE
    mst = UbifsMasterNode()
    mst.highest_inum = struct.unpack_from("<Q", buf, p)[0]
    mst.cmt_no = struct.unpack_from("<Q", buf, p + 8)[0]
    mst.flags = struct.unpack_from("<I", buf, p + 16)[0]
    mst.log_lnum = struct.unpack_from("<I", buf, p + 20)[0]
    mst.root_lnum = struct.unpack_from("<I", buf, p + 24)[0]
    mst.root_offs = struct.unpack_from("<I", buf, p + 28)[0]
    mst.root_len = struct.unpack_from("<I", buf, p + 32)[0]
    mst.gc_lnum = struct.unpack_from("<I", buf, p + 36)[0]
    mst.ihead_lnum = struct.unpack_from("<I", buf, p + 40)[0]
    mst.ihead_offs = struct.unpack_from("<I", buf, p + 44)[0]
    mst.index_size = struct.unpack_from("<Q", buf, p + 48)[0]
    mst.leb_cnt = struct.unpack_from("<I", buf, p + 120)[0]
    return mst


def _parse_inode_node(
    buf: bytes, off: int, sqnum: int, node_len: int,
) -> UbifsInode:
    """Parse an inode node starting at *off*."""
    p = off + UBIFS_CH_SIZE
    inum = struct.unpack_from("<I", buf, p)[0]

    q = p + UBIFS_KEY_LEN
    ino = UbifsInode(inum=inum, sqnum=sqnum)
    ino.creat_sqnum = struct.unpack_from("<Q", buf, q)[0]
    ino.size = struct.unpack_from("<Q", buf, q + 8)[0]
    ino.atime_sec = struct.unpack_from("<q", buf, q + 16)[0]
    ino.ctime_sec = struct.unpack_from("<q", buf, q + 24)[0]
    ino.mtime_sec = struct.unpack_from("<q", buf, q + 32)[0]
    ino.nlink = struct.unpack_from("<I", buf, q + 52)[0]
    ino.uid = struct.unpack_from("<I", buf, q + 56)[0]
    ino.gid = struct.unpack_from("<I", buf, q + 60)[0]
    ino.mode = struct.unpack_from("<I", buf, q + 64)[0]
    ino.flags = struct.unpack_from("<I", buf, q + 68)[0]
    ino.data_len = struct.unpack_from("<I", buf, q + 72)[0]

    # Inline data starts at q + 132 (after all inode fields)
    inline_off = q + 132
    if ino.data_len > 0 and inline_off + ino.data_len <= off + node_len:
        compr_type = struct.unpack_from("<H", buf, q + 106)[0]
        raw = buf[inline_off: inline_off + (node_len - (inline_off - off))]
        if compr_type == UBIFS_COMPR_NONE:
            ino.inline_data = bytes(raw[:ino.data_len])
        else:
            try:
                ino.inline_data = _decompress(
                    bytes(raw), compr_type, ino.data_len
                )
            except Exception:
                ino.inline_data = bytes(raw[:ino.data_len])

    return ino


def _parse_dent_node(
    buf: bytes, off: int, sqnum: int, node_len: int,
) -> UbifsDent:
    """Parse a directory entry (or xattr entry) node."""
    p = off + UBIFS_CH_SIZE
    parent_inum = struct.unpack_from("<I", buf, p)[0]

    q = p + UBIFS_KEY_LEN
    dent = UbifsDent(parent_inum=parent_inum, sqnum=sqnum)
    dent.target_inum = struct.unpack_from("<Q", buf, q)[0]
    dent.itype = buf[q + 9]
    nlen = struct.unpack_from("<H", buf, q + 10)[0]
    name_start = q + 16
    if name_start + nlen <= off + node_len:
        dent.name = buf[name_start: name_start + nlen].decode(
            "utf-8", errors="replace"
        ).rstrip("\x00")

    return dent


def _parse_data_node(
    buf: bytes, off: int, sqnum: int, node_len: int,
) -> UbifsDataChunk:
    """Parse a data node (file content chunk)."""
    p = off + UBIFS_CH_SIZE
    inum = struct.unpack_from("<I", buf, p)[0]
    block_word = struct.unpack_from("<I", buf, p + 4)[0]
    block_num = block_word & UBIFS_KEY_BLOCK_MASK

    q = p + UBIFS_KEY_LEN
    out_len = struct.unpack_from("<I", buf, q)[0]
    compr_type = struct.unpack_from("<H", buf, q + 4)[0]
    data_start = q + 8
    data_len = node_len - (data_start - off)

    return UbifsDataChunk(
        inum=inum,
        block_num=block_num,
        sqnum=sqnum,
        compr_type=compr_type,
        out_len=out_len,
        data=bytes(buf[data_start: data_start + data_len]),
    )


# ── Strategy 1: Index-tree walk ─────────────────────────────────────

class IndexCorruptedError(Exception):
    """Raised when the UBIFS index tree cannot be walked."""
    pass


def _read_node_at(
    data: bytes, leb_size: int, lnum: int, offs: int, expected_len: int,
) -> bytes:
    """Read raw node bytes at a given LEB number and offset.

    Raises :class:`IndexCorruptedError` if the read is out of bounds or
    the node magic is invalid.
    """
    abs_off = lnum * leb_size + offs
    if abs_off < 0 or abs_off + UBIFS_CH_SIZE > len(data):
        raise IndexCorruptedError(
            f"Node at LEB {lnum} offset {offs} is out of bounds "
            f"(abs {abs_off}, volume size {len(data)})"
        )

    magic = struct.unpack_from("<I", data, abs_off)[0]
    if magic != UBIFS_NODE_MAGIC:
        raise IndexCorruptedError(
            f"Bad magic 0x{magic:08x} at LEB {lnum} offset {offs} "
            f"(expected 0x{UBIFS_NODE_MAGIC:08x})"
        )

    node_len = struct.unpack_from("<I", data, abs_off + 16)[0]
    if node_len < UBIFS_CH_SIZE or abs_off + node_len > len(data):
        raise IndexCorruptedError(
            f"Invalid node length {node_len} at LEB {lnum} offset {offs}"
        )

    return bytes(data[abs_off: abs_off + node_len])


def _walk_index(
    data: bytes,
    leb_size: int,
    lnum: int,
    offs: int,
    node_len: int,
    inodes: dict[int, UbifsInode],
    dents: dict[tuple[int, str], UbifsDent],
    data_chunks: dict[tuple[int, int], UbifsDataChunk],
    stats: dict[str, int],
    depth: int = 0,
) -> None:
    """Recursively walk the UBIFS B-tree index.

    At internal nodes (level > 0), each branch points to a child index
    node.  At leaf nodes (level == 0), each branch points to an actual
    content node (inode, dent, or data).
    """
    if depth > 64:
        raise IndexCorruptedError("Index tree depth exceeds 64 — likely a loop")

    node_data = _read_node_at(data, leb_size, lnum, offs, node_len)
    hdr = _parse_common_header(node_data, 0)
    if hdr is None:
        raise IndexCorruptedError(f"Cannot parse header at LEB {lnum} offs {offs}")

    sqnum, nlen, node_type, _ = hdr
    if node_type != UBIFS_IDX_NODE:
        raise IndexCorruptedError(
            f"Expected index node (type 9) at LEB {lnum} offs {offs}, "
            f"got type {node_type}"
        )

    stats["idx_nodes"] += 1

    # Index node: after common header (24 bytes)
    # child_cnt (LE16), level (LE16), then branches
    child_cnt = struct.unpack_from("<H", node_data, 24)[0]
    level = struct.unpack_from("<H", node_data, 26)[0]

    for i in range(child_cnt):
        bp = 28 + i * UBIFS_BRANCH_SIZE
        if bp + UBIFS_BRANCH_SIZE > len(node_data):
            raise IndexCorruptedError(
                f"Branch {i} at LEB {lnum} offs {offs} exceeds node boundary"
            )

        b_lnum = struct.unpack_from("<I", node_data, bp)[0]
        b_offs = struct.unpack_from("<I", node_data, bp + 4)[0]
        b_len = struct.unpack_from("<I", node_data, bp + 8)[0]

        if level > 0:
            # Internal node — recurse into child index
            _walk_index(
                data, leb_size, b_lnum, b_offs, b_len,
                inodes, dents, data_chunks, stats,
                depth=depth + 1,
            )
        else:
            # Leaf node — branch points to an actual content node
            try:
                leaf_data = _read_node_at(data, leb_size, b_lnum, b_offs, b_len)
            except IndexCorruptedError:
                stats["parse_errors"] += 1
                continue

            leaf_hdr = _parse_common_header(leaf_data, 0)
            if leaf_hdr is None:
                stats["parse_errors"] += 1
                continue

            leaf_sqnum, leaf_len, leaf_type, _ = leaf_hdr
            stats["nodes_total"] += 1

            try:
                if leaf_type == UBIFS_INO_NODE:
                    stats["ino_nodes"] += 1
                    ino = _parse_inode_node(leaf_data, 0, leaf_sqnum, leaf_len)
                    if ino.inum not in inodes or leaf_sqnum > inodes[ino.inum].sqnum:
                        inodes[ino.inum] = ino

                elif leaf_type == UBIFS_DENT_NODE:
                    stats["dent_nodes"] += 1
                    dent = _parse_dent_node(leaf_data, 0, leaf_sqnum, leaf_len)
                    key = (dent.parent_inum, dent.name)
                    if key not in dents or leaf_sqnum > dents[key].sqnum:
                        dents[key] = dent

                elif leaf_type == UBIFS_DATA_NODE:
                    stats["data_nodes"] += 1
                    chunk = _parse_data_node(leaf_data, 0, leaf_sqnum, leaf_len)
                    key = (chunk.inum, chunk.block_num)
                    if key not in data_chunks or leaf_sqnum > data_chunks[key].sqnum:
                        data_chunks[key] = chunk

                else:
                    stats["other_nodes"] += 1

            except Exception as exc:
                stats["parse_errors"] += 1
                if stats["parse_errors"] <= 10:
                    logger.warning(
                        "Parse error at LEB %d offset %d (type %d): %s",
                        b_lnum, b_offs, leaf_type, exc,
                    )


def extract_via_index(
    data: bytes,
    leb_size: int,
    superblock: UbifsSuperblock,
) -> dict[str, Any]:
    """Extract UBIFS contents by walking the index tree.

    Raises :class:`IndexCorruptedError` if the index cannot be walked.

    Returns the same dict structure as :func:`scan_ubifs_volume`.
    """
    vol_len = len(data)
    num_lebs = vol_len // leb_size

    # Parse master node — scan LEBs 1 and 2 for the latest copy.
    # Multiple master nodes can be stacked in one LEB at min_io-aligned
    # offsets (one per commit).  We need the highest sqnum across both.
    master: UbifsMasterNode | None = None
    best_sqnum = -1
    min_io = max(superblock.min_io_size, 8)

    for mst_leb in (1, 2):
        if mst_leb >= num_lebs:
            continue
        base = mst_leb * leb_size
        for slot_off in range(0, leb_size, min_io):
            abs_off = base + slot_off
            if abs_off + UBIFS_CH_SIZE > vol_len:
                break
            hdr = _parse_common_header(data, abs_off)
            if hdr is None or hdr[2] != UBIFS_MST_NODE:
                continue
            candidate = _parse_master_node(data, abs_off)
            if hdr[0] > best_sqnum:  # hdr[0] is sqnum
                master = candidate
                best_sqnum = hdr[0]

    if master is None:
        raise IndexCorruptedError("No valid master node found in LEBs 1 or 2")

    logger.info(
        "Master node: root at LEB %d offset %d (len %d), "
        "highest_inum=%d, cmt_no=%d",
        master.root_lnum, master.root_offs, master.root_len,
        master.highest_inum, master.cmt_no,
    )

    inodes: dict[int, UbifsInode] = {}
    dents: dict[tuple[int, str], UbifsDent] = {}
    data_chunks: dict[tuple[int, int], UbifsDataChunk] = {}
    stats: dict[str, int] = {
        "lebs_scanned": 0,
        "lebs_empty": 0,
        "nodes_total": 0,
        "sb_nodes": 1,
        "ino_nodes": 0,
        "dent_nodes": 0,
        "data_nodes": 0,
        "idx_nodes": 0,
        "other_nodes": 0,
        "parse_errors": 0,
    }

    # Walk the B-tree from the root
    _walk_index(
        data, leb_size,
        master.root_lnum, master.root_offs, master.root_len,
        inodes, dents, data_chunks, stats,
    )

    logger.info(
        "Index walk complete: %d content nodes (%d inodes, %d dents, "
        "%d data chunks), %d index nodes, %d parse errors",
        stats["nodes_total"], stats["ino_nodes"],
        stats["dent_nodes"], stats["data_nodes"],
        stats["idx_nodes"], stats["parse_errors"],
    )

    # Sanity check — we should have at least the root inode
    if 1 not in inodes:
        raise IndexCorruptedError(
            "Index walk completed but root inode (inum 1) was not found"
        )

    return {
        "superblock": superblock,
        "inodes": inodes,
        "dents": dents,
        "data_chunks": data_chunks,
        "stats": stats,
    }


# ── Strategy 2: Raw node scan (fallback) ────────────────────────────

def scan_ubifs_volume(
    data: bytes | memoryview,
    leb_size: int | None = None,
) -> dict[str, Any]:
    """Scan an entire UBIFS volume image by walking all nodes.

    Returns a dict containing:
      - ``superblock``: :class:`UbifsSuperblock` or *None*
      - ``inodes``: dict mapping inum → latest :class:`UbifsInode`
      - ``dents``: dict mapping (parent_inum, name) → latest :class:`UbifsDent`
      - ``data_chunks``: dict mapping (inum, block_num) → latest :class:`UbifsDataChunk`
      - ``stats``: scan statistics
    """
    vol_len = len(data)

    if leb_size is None:
        hdr = _parse_common_header(data, 0)
        if hdr and hdr[2] == UBIFS_SB_NODE:
            sb = _parse_superblock(data, 0)
            leb_size = sb.leb_size
            logger.info("Auto-detected LEB size from superblock: %d", leb_size)
        else:
            leb_size = vol_len
            logger.warning(
                "Could not detect LEB size, treating entire volume as one LEB"
            )

    num_lebs = vol_len // leb_size
    logger.info(
        "Scanning UBIFS volume: %d bytes, %d LEBs (LEB size %d)",
        vol_len, num_lebs, leb_size,
    )

    superblock: UbifsSuperblock | None = None
    inodes: dict[int, UbifsInode] = {}
    dents: dict[tuple[int, str], UbifsDent] = {}
    data_chunks: dict[tuple[int, int], UbifsDataChunk] = {}

    stats = {
        "lebs_scanned": 0,
        "lebs_empty": 0,
        "nodes_total": 0,
        "sb_nodes": 0,
        "ino_nodes": 0,
        "dent_nodes": 0,
        "data_nodes": 0,
        "idx_nodes": 0,
        "other_nodes": 0,
        "parse_errors": 0,
    }

    for leb_idx in range(num_lebs):
        leb_off = leb_idx * leb_size
        leb_data = data[leb_off: leb_off + leb_size]

        if leb_data[:4] in (b"\xff\xff\xff\xff", b"\x00\x00\x00\x00"):
            stats["lebs_empty"] += 1
            stats["lebs_scanned"] += 1
            continue

        stats["lebs_scanned"] += 1
        off = 0

        while off < leb_size - UBIFS_CH_SIZE:
            hdr = _parse_common_header(leb_data, off)
            if hdr is None:
                off += 8
                continue

            sqnum, node_len, node_type, _ = hdr
            if node_len < UBIFS_CH_SIZE or node_len > leb_size - off:
                off += 8
                continue

            stats["nodes_total"] += 1

            try:
                if node_type == UBIFS_SB_NODE:
                    stats["sb_nodes"] += 1
                    superblock = _parse_superblock(leb_data, off)

                elif node_type == UBIFS_INO_NODE:
                    stats["ino_nodes"] += 1
                    ino = _parse_inode_node(leb_data, off, sqnum, node_len)
                    if ino.inum not in inodes or sqnum > inodes[ino.inum].sqnum:
                        inodes[ino.inum] = ino

                elif node_type == UBIFS_DENT_NODE:
                    stats["dent_nodes"] += 1
                    dent = _parse_dent_node(leb_data, off, sqnum, node_len)
                    key = (dent.parent_inum, dent.name)
                    if key not in dents or sqnum > dents[key].sqnum:
                        dents[key] = dent

                elif node_type == UBIFS_DATA_NODE:
                    stats["data_nodes"] += 1
                    chunk = _parse_data_node(leb_data, off, sqnum, node_len)
                    key = (chunk.inum, chunk.block_num)
                    if key not in data_chunks or sqnum > data_chunks[key].sqnum:
                        data_chunks[key] = chunk

                elif node_type == UBIFS_IDX_NODE:
                    stats["idx_nodes"] += 1
                else:
                    stats["other_nodes"] += 1

            except Exception as exc:
                stats["parse_errors"] += 1
                if stats["parse_errors"] <= 10:
                    logger.warning(
                        "Parse error at LEB %d offset %d (type %d): %s",
                        leb_idx, off, node_type, exc,
                    )

            off += node_len
            off = (off + 7) & ~7

    logger.info(
        "Scan complete: %d nodes (%d inodes, %d dents, %d data chunks), "
        "%d parse errors",
        stats["nodes_total"], stats["ino_nodes"],
        stats["dent_nodes"], stats["data_nodes"],
        stats["parse_errors"],
    )

    return {
        "superblock": superblock,
        "inodes": inodes,
        "dents": dents,
        "data_chunks": data_chunks,
        "stats": stats,
    }


# ── Unified extraction entry point ──────────────────────────────────

def extract_ubifs_nodes(
    data: bytes,
) -> tuple[dict[str, Any], str]:
    """Extract UBIFS node data using the best available strategy.

    Tries the index-tree walk first.  If that fails, falls back to a
    full raw node scan and emits a warning.

    Returns ``(scan_result, method)`` where *method* is ``"index"``
    or ``"scan"``.
    """
    # Parse superblock (always in LEB 0)
    hdr = _parse_common_header(data, 0)
    if hdr is None or hdr[2] != UBIFS_SB_NODE:
        raise ValueError("Not a UBIFS volume: no superblock at LEB 0")

    superblock = _parse_superblock(data, 0)
    leb_size = superblock.leb_size

    # Strategy 1: index-tree walk
    try:
        logger.info("Attempting index-tree walk extraction...")
        result = extract_via_index(data, leb_size, superblock)
        logger.info("Index-tree extraction succeeded")
        return result, METHOD_INDEX
    except IndexCorruptedError as exc:
        logger.warning(
            "Index-tree extraction failed: %s — falling back to raw "
            "node scan (this is slower but handles corrupted indexes)",
            exc,
        )

    # Strategy 2: raw node scan
    logger.info("Using raw node scan extraction (fallback)...")
    result = scan_ubifs_volume(data, leb_size=leb_size)
    # The raw scan finds the superblock itself, but we already have it
    if result["superblock"] is None:
        result["superblock"] = superblock
    return result, METHOD_SCAN


# ── File reassembly ─────────────────────────────────────────────────

BLOCK_SIZE = 4096  # UBIFS default block size


def _reassemble_file(
    inum: int,
    inode: UbifsInode,
    data_chunks: dict[tuple[int, int], UbifsDataChunk],
    output_path: Path,
) -> int:
    """Reassemble a regular file from its data chunks.

    Returns the number of bytes written.
    """
    file_size = inode.size

    if file_size == 0:
        output_path.write_bytes(b"")
        return 0

    # Check for inline data (small files stored directly in the inode)
    if inode.inline_data and inode.data_len > 0:
        out_data = inode.inline_data[:file_size]
        output_path.write_bytes(out_data)
        return len(out_data)

    # Collect all data chunks for this inode
    total_blocks = (file_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    max_block = -1
    chunks_for_inum = {}
    for (ci, bn), chunk in data_chunks.items():
        if ci == inum:
            chunks_for_inum[bn] = chunk
            if bn > max_block:
                max_block = bn

    if not chunks_for_inum:
        output_path.write_bytes(b"\x00" * file_size)
        return file_size

    with open(output_path, "wb") as f:
        written = 0
        for block_num in range(max(total_blocks, max_block + 1)):
            block_off = block_num * BLOCK_SIZE
            if block_off >= file_size:
                break

            remaining = min(BLOCK_SIZE, file_size - block_off)

            if block_num in chunks_for_inum:
                chunk = chunks_for_inum[block_num]
                try:
                    decompressed = _decompress(
                        chunk.data, chunk.compr_type, chunk.out_len
                    )
                    f.write(decompressed[:remaining])
                    written += min(len(decompressed), remaining)
                except Exception as exc:
                    logger.warning(
                        "Decompression error for inode %d block %d: %s",
                        inum, block_num, exc,
                    )
                    f.write(b"\x00" * remaining)
                    written += remaining
            else:
                f.write(b"\x00" * remaining)
                written += remaining

    return written


# ── Filesystem tree extraction ──────────────────────────────────────

def extract_ubifs(
    scan_result: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """Extract the UBIFS filesystem tree to *output_dir*.

    Uses the pre-scanned node data from :func:`scan_ubifs_volume` or
    :func:`extract_via_index`.

    Returns a manifest dict with file metadata.
    """
    inodes = scan_result["inodes"]
    dents = scan_result["dents"]
    data_chunks = scan_result["data_chunks"]
    superblock = scan_result["superblock"]

    output_dir.mkdir(parents=True, exist_ok=True)

    # Build parent→children map from directory entries
    children: dict[int, list[UbifsDent]] = {}
    for (_parent, _name), dent in dents.items():
        if dent.parent_inum not in children:
            children[dent.parent_inum] = []
        children[dent.parent_inum].append(dent)

    manifest_entries: list[dict[str, Any]] = []
    errors: list[str] = []

    def _walk(inum: int, fs_path: str, disk_path: Path) -> None:
        inode = inodes.get(inum)
        if inode is None:
            errors.append(f"Missing inode {inum} for path {fs_path}")
            return

        mode = inode.mode
        is_dir = stat.S_ISDIR(mode)
        is_reg = stat.S_ISREG(mode)
        is_lnk = stat.S_ISLNK(mode)

        entry: dict[str, Any] = {
            "path": fs_path,
            "inum": inum,
            "mode": f"{mode:06o}",
            "uid": inode.uid,
            "gid": inode.gid,
            "size": inode.size,
            "mtime": inode.mtime_sec,
            "nlink": inode.nlink,
        }

        if is_dir:
            entry["type"] = "dir"
            disk_path.mkdir(parents=True, exist_ok=True)
            manifest_entries.append(entry)

            for dent in sorted(
                children.get(inum, []), key=lambda d: d.name
            ):
                if dent.name in (".", ".."):
                    continue
                if dent.target_inum == 0:
                    continue
                child_path = (
                    f"{fs_path}/{dent.name}"
                    if fs_path != "/"
                    else f"/{dent.name}"
                )
                _walk(dent.target_inum, child_path, disk_path / dent.name)

        elif is_reg:
            entry["type"] = "file"
            nbytes = _reassemble_file(inum, inode, data_chunks, disk_path)
            entry["extracted_size"] = nbytes
            manifest_entries.append(entry)

        elif is_lnk:
            entry["type"] = "symlink"
            target = ""
            if inode.inline_data:
                target = inode.inline_data.decode(
                    "utf-8", errors="replace"
                ).rstrip("\x00")
            entry["target"] = target
            manifest_entries.append(entry)

            try:
                if disk_path.exists() or disk_path.is_symlink():
                    disk_path.unlink()
                disk_path.symlink_to(target)
            except OSError as exc:
                logger.warning(
                    "Cannot create symlink %s → %s: %s",
                    disk_path, target, exc,
                )

        elif stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
            entry["type"] = "blkdev" if stat.S_ISBLK(mode) else "chrdev"
            if inode.inline_data and len(inode.inline_data) >= 8:
                rdev = struct.unpack_from("<Q", inode.inline_data, 0)[0]
                entry["rdev_major"] = os.major(rdev)
                entry["rdev_minor"] = os.minor(rdev)
            manifest_entries.append(entry)

        elif stat.S_ISFIFO(mode):
            entry["type"] = "fifo"
            manifest_entries.append(entry)

        elif stat.S_ISSOCK(mode):
            entry["type"] = "socket"
            manifest_entries.append(entry)

        else:
            entry["type"] = "unknown"
            manifest_entries.append(entry)

    root_out = output_dir / "rootfs"
    _walk(1, "/", root_out)

    manifest = {
        "format": "ubifs",
        "leb_size": superblock.leb_size if superblock else None,
        "leb_cnt": superblock.leb_cnt if superblock else None,
        "min_io_size": superblock.min_io_size if superblock else None,
        "default_compr": superblock.default_compr if superblock else None,
        "fmt_version": superblock.fmt_version if superblock else None,
        "total_inodes": len(inodes),
        "total_dents": len(dents),
        "total_data_chunks": len(data_chunks),
        "scan_stats": scan_result["stats"],
        "files": manifest_entries,
        "errors": errors,
    }

    return manifest


# ── Plugin ──────────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """UBIFS (UBI File System) plugin.

    Extracts files from UBIFS volume images.  Tries index-tree walking
    first for efficiency, and falls back to raw node scanning if the
    index is corrupted.
    """

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="UBIFS Volume",
            description=(
                "UBIFS filesystem handler.  Extracts files from raw "
                "UBIFS volume images and repacks directory trees back "
                "into UBIFS volumes.  Uses index-tree walking when "
                "possible, with automatic fallback to raw node scanning "
                "for corrupted indexes.  Pack requires mkfs.ubifs."
            ),
            version="0.3.0",
            format_id="ubifs",
            supported_variants=[VARIANT_UBIFS_VOLUME, VARIANT_UBIFS_FILES],
            conversions=self.get_conversions(),
            ksy_files=[],
        )

    def identify(self, path: Path) -> str | None:
        if path.is_dir():
            if (path / MANIFEST_FILENAME).is_file():
                return VARIANT_UBIFS_FILES
            return None

        if path.stat().st_size < UBIFS_CH_SIZE:
            return None

        with open(path, "rb") as f:
            magic = struct.unpack("<I", f.read(4))[0]
            if magic == UBIFS_NODE_MAGIC:
                f.seek(20)
                node_type = f.read(1)
                if node_type and node_type[0] == UBIFS_SB_NODE:
                    return VARIANT_UBIFS_VOLUME

        return None

    def get_conversions(self) -> list[ConversionInfo]:
        mkfs_ok = _tool_available("mkfs.ubifs")
        return [
            ConversionInfo(
                source_variant=VARIANT_UBIFS_VOLUME,
                target_variant=VARIANT_UBIFS_FILES,
                description="Extract files from UBIFS volume image",
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_UBIFS_FILES,
                target_variant=VARIANT_UBIFS_VOLUME,
                description="Repack extracted files into UBIFS volume image",
                lossy=False,
                available=mkfs_ok,
                missing_deps=[] if mkfs_ok else ["mkfs.ubifs (mtd-utils)"],
            ),
        ]

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
        if source_variant != VARIANT_UBIFS_VOLUME:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_UBIFS_VOLUME}', "
                f"got '{source_variant}'"
            )

        target_variant = target_variant or VARIANT_UBIFS_FILES
        source_hash = file_sha256(input_path)

        logger.info("Reading UBIFS volume: %s", input_path)
        vol_data = input_path.read_bytes()

        # Try index-tree walk first, fall back to raw scan
        scan_result, method = extract_ubifs_nodes(vol_data)

        if method == METHOD_SCAN:
            logger.warning(
                "WARNING: Extraction used raw node scan fallback.  "
                "The UBIFS index tree is corrupted (possibly from a "
                "live system dump).  Results should be correct but may "
                "include stale data from the journal."
            )

        # Extract filesystem tree
        output_path.mkdir(parents=True, exist_ok=True)
        manifest = extract_ubifs(scan_result, output_path)
        manifest["extraction_method"] = method

        # Write manifest
        manifest_path = output_path / MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2), encoding="utf-8",
        )

        output_hash = file_sha256(manifest_path)

        file_count = sum(
            1 for e in manifest["files"] if e["type"] == "file"
        )
        dir_count = sum(
            1 for e in manifest["files"] if e["type"] == "dir"
        )
        symlink_count = sum(
            1 for e in manifest["files"] if e["type"] == "symlink"
        )

        metadata: dict[str, Any] = {
            "extraction_method": method,
            "leb_size": manifest.get("leb_size"),
            "leb_cnt": manifest.get("leb_cnt"),
            "default_compr": manifest.get("default_compr"),
            "total_inodes": manifest["total_inodes"],
            "total_files": file_count,
            "total_dirs": dir_count,
            "total_symlinks": symlink_count,
            "total_data_chunks": manifest["total_data_chunks"],
            "parse_errors": manifest["scan_stats"]["parse_errors"],
            "extraction_errors": len(manifest["errors"]),
        }

        method_label = (
            "index-tree walk" if method == METHOD_INDEX
            else "raw node scan (fallback)"
        )
        logger.info(
            "Extracted UBIFS via %s: %d files, %d dirs, %d symlinks "
            "(%d errors)",
            method_label, file_count, dir_count, symlink_count,
            len(manifest["errors"]),
        )

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        """Repack an extracted UBIFS directory tree into a volume image.

        *input_path* is the directory containing ``rootfs/`` and
        ``ubifs_manifest.json``.
        *output_path* is the UBIFS volume image file to create.

        Requires ``mkfs.ubifs`` from the mtd-utils package.
        """
        if source_variant is None:
            source_variant = self.identify(input_path) or VARIANT_UBIFS_FILES
        if target_variant is None:
            target_variant = VARIANT_UBIFS_VOLUME

        if source_variant != VARIANT_UBIFS_FILES:
            raise ValueError(
                f"pack expects source variant '{VARIANT_UBIFS_FILES}', "
                f"got '{source_variant}'"
            )

        if not _tool_available("mkfs.ubifs"):
            raise RuntimeError(
                "mkfs.ubifs not found on PATH.  Install mtd-utils: "
                "  apt-get install mtd-utils"
            )

        # ── Read manifest ────────────────────────────────────────────
        manifest_path = input_path / MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"Manifest not found: {manifest_path}.  "
                f"Was this directory created by unpack()?"
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        source_hash = file_sha256(manifest_path)

        rootfs_dir = input_path / EXTRACTED_DIRNAME
        if not rootfs_dir.is_dir():
            raise FileNotFoundError(
                f"Extracted tree not found: {rootfs_dir}.  "
                f"Expected '{EXTRACTED_DIRNAME}/' inside {input_path}."
            )

        # ── Extract parameters from manifest ─────────────────────────
        min_io = manifest.get("min_io_size")
        leb_size = manifest.get("leb_size")
        leb_cnt = manifest.get("leb_cnt")

        if not all((min_io, leb_size, leb_cnt)):
            raise ValueError(
                "Manifest is missing required fields: "
                "min_io_size, leb_size, leb_cnt"
            )

        compr_id = manifest.get("default_compr", UBIFS_COMPR_LZO)
        compr_name = _COMPR_ID_TO_NAME.get(compr_id, "lzo")

        # ── Build mkfs.ubifs command ─────────────────────────────────
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "mkfs.ubifs",
            "-r", str(rootfs_dir),
            "-m", str(min_io),
            "-e", str(leb_size),
            "-c", str(leb_cnt),
            "-x", compr_name,
            "-o", str(output_path),
        ]

        # Build device table for special files (block/char devices,
        # fifos, sockets) that mkfs.ubifs can't pick up from the
        # directory tree when not running as root.
        devtable_lines = self._build_device_table(manifest)
        devtable_path: Path | None = None
        if devtable_lines:
            devtable_path = input_path / ".ubifs_devtable.txt"
            devtable_path.write_text(
                "\n".join(devtable_lines) + "\n", encoding="utf-8",
            )
            cmd.extend(["-D", str(devtable_path)])

        logger.info("Repacking UBIFS volume: %s", output_path)
        logger.debug("  min_io=%d  leb_size=%d  leb_cnt=%d  compr=%s",
                      min_io, leb_size, leb_cnt, compr_name)

        try:
            _run(cmd)
        finally:
            # Clean up temporary device table
            if devtable_path and devtable_path.exists():
                devtable_path.unlink()

        output_hash = file_sha256(output_path)

        metadata: dict[str, Any] = {
            "min_io_size": min_io,
            "leb_size": leb_size,
            "leb_cnt": leb_cnt,
            "compression": compr_name,
        }

        logger.info("UBIFS volume repacked: %s (%d bytes)",
                     output_path, output_path.stat().st_size)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash=output_hash,
            metadata=metadata,
        )

    @staticmethod
    def _build_device_table(manifest: dict) -> list[str]:
        """Build a mkfs.ubifs device table for special files.

        mkfs.ubifs uses a genext2fs-style device table to create
        device nodes, set ownership, and permissions that cannot be
        represented on the host filesystem (e.g. when not running as
        root).

        Format: <path> <type> <mode> <uid> <gid> <major> <minor> <start> <inc> <count>
        """
        lines: list[str] = []

        for entry in manifest.get("files", []):
            ftype = entry.get("type", "")
            path = entry.get("path", "")

            if not path or path == "/":
                continue

            # Normalise path for device table (no leading slash)
            dtpath = path.lstrip("/")

            if ftype == "blkdev":
                major = entry.get("rdev_major", 0)
                minor = entry.get("rdev_minor", 0)
                mode = int(entry.get("mode", "060660"), 8) & 0o7777
                uid = entry.get("uid", 0)
                gid = entry.get("gid", 0)
                lines.append(
                    f"/{dtpath}\tb\t{mode:o}\t{uid}\t{gid}\t{major}\t{minor}\t0\t0\t-"
                )
            elif ftype == "chrdev":
                major = entry.get("rdev_major", 0)
                minor = entry.get("rdev_minor", 0)
                mode = int(entry.get("mode", "020660"), 8) & 0o7777
                uid = entry.get("uid", 0)
                gid = entry.get("gid", 0)
                lines.append(
                    f"/{dtpath}\tc\t{mode:o}\t{uid}\t{gid}\t{major}\t{minor}\t0\t0\t-"
                )
            elif ftype == "fifo":
                mode = int(entry.get("mode", "010644"), 8) & 0o7777
                uid = entry.get("uid", 0)
                gid = entry.get("gid", 0)
                lines.append(
                    f"/{dtpath}\tp\t{mode:o}\t{uid}\t{gid}\t-\t-\t0\t0\t-"
                )

        return lines
