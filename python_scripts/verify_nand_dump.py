#!/usr/bin/env python3
"""
HP Dune/Selene (CLJ Pro 4301-4303 / TX54) NAND Secure Boot Verification Tool

Independently verifies the full secure boot chain of a raw NAND dump (with OOB)
from an HP Dune/Selene printer. Checks four partitions:

  - UpdatableLBI & RecoveryLBI: Extracts the LBI container, recomputes the
    streaming SHA-256 over the image data, and verifies the RSA-2048 PKCS#1 v1.5
    signature using the embedded key index (SecureBoot_Init param 0x08BA).

  - RootFS & RecoveryRootFS: Scans UBI erase blocks via raw page reads (bypassing
    ECC), assembles the per-block SHA-256 hash table in logical erase block (lnum)
    order, and verifies the RSA-2048 signature (SecureBoot_VerifyData param 0x08BB).

Requires a companion rsa_key_table.json with the RSA-2048 public keys.

Usage: verify_nand_dump.py [--mode auto|gf-table|constraint] <nand_dump_with_oob.bin>

Options:
  --mode auto        (default) Extract GF table from TZ firmware; fall back to
                     constraint verification if extraction fails.
  --mode gf-table    Force use of the embedded GF table. Abort if extraction fails.
  --mode constraint  Skip GF table extraction entirely and use pair-level GF
                     constraint verification.
"""

import argparse
import struct
import hashlib
import json
import sys
from pathlib import Path
from collections import defaultdict

import bchlib

# ─── NAND Geometry ───
PAGE_DATA   = 2048
PAGE_OOB    = 64
PAGE_RAW    = PAGE_DATA + PAGE_OOB  # 2112
PAGES_PER_BLOCK = 64
BLOCK_DATA  = PAGE_DATA * PAGES_PER_BLOCK  # 131072 = 128 KiB
BLOCK_RAW   = PAGE_RAW * PAGES_PER_BLOCK   # 135168

# ─── ECC Parameters ───
CHUNK_SIZE       = 512       # Each page is split into 4 x 512-byte chunks
CHUNKS_PER_PAGE  = 4
SPARE_SIZE       = 12        # OOB bytes 0-11: spare/metadata
ECC_CODE_SIZE    = 13        # 13 bytes BCH ECC per chunk
ECC_POLYNOMIAL   = 8219
ECC_T            = 8         # Correction capacity: 8 bits per 512-byte chunk

# ─── Partition Table (from DTB) ───
PARTITIONS = {
    'Boot':           (0x00000000, 0x00040000),
    'UpdatableLBI':   (0x00040000, 0x00500000),
    'RootFS':         (0x00540000, 0x106C0000),
    'RWFS':           (0x10C00000, 0x08E60000),
    'RecoveryRootFS': (0x19A60000, 0x06100000),
    'RecoveryLBI':    (0x1FB60000, 0x004A0000),
}

# ─── File paths ───
RSA_KEYS_FILE = str(Path(__file__).resolve().parent / 'rsa_key_table.json')


class NANDReader:
    """Reads data from a raw NAND dump with OOB, with BCH ECC verification and correction.

    OOB layout (64 bytes per page):
        Bytes  0-11:  Spare/metadata buffer
        Bytes 12-24:  BCH ECC for data chunk 0  (bytes    0- 511)
        Bytes 25-37:  BCH ECC for data chunk 1  (bytes  512-1023)
        Bytes 38-50:  BCH ECC for data chunk 2  (bytes 1024-1535)
        Bytes 51-63:  BCH ECC for data chunk 3  (bytes 1536-2047)

    ECC: BCH(polynomial=8219, t=8), computed directly on raw data.
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.f = open(filepath, 'rb')
        self.f.seek(0, 2)
        self.total_size = self.f.tell()
        self.total_pages = self.total_size // PAGE_RAW
        self.total_blocks = self.total_pages // PAGES_PER_BLOCK

        # Initialize BCH codec
        self.bch = bchlib.BCH(t=ECC_T, prim_poly=ECC_POLYNOMIAL, swap_bits=False)

        # ECC statistics
        self.ecc_stats = {
            'pages_read': 0,
            'pages_clean': 0,        # No bit errors
            'pages_corrected': 0,    # Had errors, corrected by ECC
            'pages_uncorrectable': 0, # Errors beyond ECC capacity
            'pages_erased': 0,       # All-0xFF (erased NAND)
            'total_bitflips': 0,     # Total bit errors corrected
            'max_bitflips_page': 0,  # Worst-case bitflips on a single page
        }

        print(f"NAND: {self.total_size} bytes, {self.total_pages} pages, {self.total_blocks} blocks")
        print(f"ECC:  BCH(poly={ECC_POLYNOMIAL}, t={ECC_T}), {ECC_CODE_SIZE}B per {CHUNK_SIZE}B chunk")

    def close(self):
        self.f.close()

    def print_ecc_stats(self):
        """Print ECC statistics summary."""
        s = self.ecc_stats
        print(f"\n  ECC Statistics:")
        print(f"    Pages read:          {s['pages_read']}")
        print(f"    Pages clean:         {s['pages_clean']}")
        print(f"    Pages corrected:     {s['pages_corrected']}")
        print(f"    Pages uncorrectable: {s['pages_uncorrectable']}")
        print(f"    Pages erased:        {s['pages_erased']}")
        print(f"    Total bitflips:      {s['total_bitflips']}")
        print(f"    Max bitflips/page:   {s['max_bitflips_page']}")

    def reset_ecc_stats(self):
        """Reset ECC statistics for a new verification run."""
        for k in self.ecc_stats:
            self.ecc_stats[k] = 0

    def _read_raw_page(self, page_num):
        """Read a raw page (data + OOB) from the NAND dump file."""
        self.f.seek(page_num * PAGE_RAW)
        raw = self.f.read(PAGE_RAW)
        data = bytearray(raw[:PAGE_DATA])
        oob = raw[PAGE_DATA:]
        return data, oob

    def _is_erased(self, data, oob):
        """Check if a page is in erased state (all 0xFF)."""
        return all(b == 0xFF for b in data) and all(b == 0xFF for b in oob)

    def _extract_ecc_codes(self, oob):
        """Extract the 4 ECC codes from the OOB area.

        Returns list of 4 x 13-byte ECC codes.
        """
        ecc_codes = []
        for i in range(CHUNKS_PER_PAGE):
            start = SPARE_SIZE + i * ECC_CODE_SIZE
            ecc_codes.append(bytearray(oob[start:start + ECC_CODE_SIZE]))
        return ecc_codes

    def read_page_data_ecc(self, page_num):
        """Read a page with ECC verification and correction.

        Returns:
            tuple: (corrected_data: bytes, page_status: str, bitflips: int)
                page_status: 'clean', 'corrected', 'uncorrectable', or 'erased'
                bitflips: total number of bit errors corrected on this page
        """
        data, oob = self._read_raw_page(page_num)
        self.ecc_stats['pages_read'] += 1

        # Check for erased page
        if self._is_erased(data, oob):
            self.ecc_stats['pages_erased'] += 1
            return bytes(data), 'erased', 0

        ecc_codes = self._extract_ecc_codes(oob)
        page_bitflips = 0
        page_status = 'clean'

        for chunk_idx in range(CHUNKS_PER_PAGE):
            chunk_start = chunk_idx * CHUNK_SIZE
            chunk_data = bytearray(data[chunk_start:chunk_start + CHUNK_SIZE])
            chunk_ecc = ecc_codes[chunk_idx]

            bitflips = self.bch.decode(chunk_data, chunk_ecc)

            if bitflips == 0:
                # No errors in this chunk
                pass
            elif bitflips > 0:
                # Errors found and correctable — apply correction
                self.bch.correct(chunk_data, chunk_ecc)
                data[chunk_start:chunk_start + CHUNK_SIZE] = chunk_data
                page_bitflips += bitflips
                page_status = 'corrected'
            else:
                # bitflips == -1: uncorrectable
                page_status = 'uncorrectable'
                self.ecc_stats['pages_uncorrectable'] += 1
                return bytes(data), 'uncorrectable', 0

        if page_status == 'clean':
            self.ecc_stats['pages_clean'] += 1
        elif page_status == 'corrected':
            self.ecc_stats['pages_corrected'] += 1
            self.ecc_stats['total_bitflips'] += page_bitflips
            if page_bitflips > self.ecc_stats['max_bitflips_page']:
                self.ecc_stats['max_bitflips_page'] = page_bitflips

        return bytes(data), page_status, page_bitflips

    def read_page_data(self, page_num):
        """Read the ECC-corrected data (2048 bytes) of a page."""
        data, status, bitflips = self.read_page_data_ecc(page_num)
        return data

    def read_page_oob(self, page_num):
        """Read the OOB portion (64 bytes) of a page."""
        self.f.seek(page_num * PAGE_RAW + PAGE_DATA)
        return self.f.read(PAGE_OOB)

    def read_data(self, data_offset, length):
        """Read contiguous data bytes from data-space with ECC correction."""
        result = bytearray()
        remaining = length
        current_offset = data_offset
        while remaining > 0:
            page_num = current_offset // PAGE_DATA
            page_off = current_offset % PAGE_DATA
            chunk_len = min(remaining, PAGE_DATA - page_off)
            page_data = self.read_page_data(page_num)
            result.extend(page_data[page_off:page_off + chunk_len])
            current_offset += chunk_len
            remaining -= chunk_len
        return bytes(result)

    def read_block_data(self, block_num):
        """Read all ECC-corrected data from a block (128 KiB)."""
        first_page = block_num * PAGES_PER_BLOCK
        data = bytearray()
        for p in range(PAGES_PER_BLOCK):
            data.extend(self.read_page_data(first_page + p))
        return bytes(data)

    def is_block_erased(self, block_num):
        """Check if a block appears erased (all 0xFF)."""
        first_page = block_num * PAGES_PER_BLOCK
        data, oob = self._read_raw_page(first_page)
        return self._is_erased(data, oob)


def parse_lbi_header(data):
    """Parse LBI base header and section descriptors."""
    magic, fmt_ver, hdr_size, num_sections, data_start = struct.unpack('>5I', data[:20])
    header = {
        'magic': magic,
        'format_version': fmt_ver,
        'header_size': hdr_size,
        'num_sections': num_sections,
        'data_start': data_start,
    }
    sections = []
    for i in range(num_sections):
        off = 20 + i * 24
        role, load, size, img_type, entry, resv = struct.unpack('>6I', data[off:off+24])
        sections.append({
            'index': i,
            'role_flags': role,
            'load_address': load,
            'size': size,
            'image_type': img_type,
            'entry_point': entry,
        })
    return header, sections


def role_to_str(role):
    """Convert role flags to readable string."""
    parts = []
    if role & 0x0001: parts.append('AUTH_COMPANION')
    if role & 0x0080: parts.append('ENTRY')
    if role & 0x0800: parts.append('OVERRIDE_DEST')
    if role & 0x2000: parts.append('SIG')
    return '|'.join(parts) if parts else 'NONE'


def verify_lbi_signature(nand, partition_name='UpdatableLBI'):
    """
    Extract LBI from NAND, recompute streaming SHA-256, and verify RSA-2048 signature.

    The streaming verification covers all section data from data_start through
    the auth block offset (coverage field in auth header).
    """
    part_start, part_size = PARTITIONS[partition_name]
    print(f"\n{'='*70}")
    print(f"LBI Signature Verification: {partition_name}")
    print(f"  Partition: 0x{part_start:08X} - 0x{part_start+part_size:08X} ({part_size//1024} KiB)")
    print(f"{'='*70}")

    # Read LBI header
    hdr_data = nand.read_data(part_start, 512)
    header, sections = parse_lbi_header(hdr_data)

    magic_ok = header['magic'] == 0xBAD2BFED
    print(f"\n  Magic:        0x{header['magic']:08X} {'OK' if magic_ok else 'MISMATCH!'}")
    print(f"  Format ver:   {header['format_version']}")
    print(f"  Header size:  0x{header['header_size']:X}")
    print(f"  Num sections: {header['num_sections']}")
    print(f"  Data start:   0x{header['data_start']:X}")

    if not magic_ok:
        print("  ERROR: Bad magic, aborting.")
        return False

    # Print section table
    print(f"\n  Section Table:")
    auth_section = None
    section_offsets = []
    current_offset = header['data_start']
    for s in sections:
        role_str = role_to_str(s['role_flags'])
        print(f"    [{s['index']}] {role_str:30s} offset=0x{current_offset:06X} size=0x{s['size']:06X} load=0x{s['load_address']:08X}")
        section_offsets.append(current_offset)
        if s['role_flags'] & 0x2000:  # SIG
            auth_section = s
            auth_offset = current_offset
        if s['size'] > 0:
            current_offset += s['size']
            # Align to data_start boundary
            align = header['data_start']
            current_offset = (current_offset + align - 1) & ~(align - 1)
        else:
            # Auth block is 320 bytes but descriptor says size=0
            current_offset += 320

    if auth_section is None:
        print("  ERROR: No auth section found.")
        return False

    # Read auth block
    auth_data = nand.read_data(part_start + auth_offset, 320)
    algo_sel = auth_data[0]
    crypto_prov = auth_data[1]
    # Coverage: big-endian 32-bit from bytes[2:6]
    coverage = struct.unpack('>I', auth_data[2:6])[0]
    key_index = struct.unpack('>H', auth_data[6:8])[0]
    sig_length = struct.unpack('>H', auth_data[8:10])[0]
    rsa_sig = auth_data[10:10 + sig_length]

    print(f"\n  Auth Block at LBI offset 0x{auth_offset:06X}:")
    print(f"    Algorithm:      0x{algo_sel:02X} ({'SHA-256 streaming' if algo_sel == 2 else 'unknown'})")
    print(f"    Crypto prov:    0x{crypto_prov:02X}")
    print(f"    Coverage:       0x{coverage:08X} ({coverage} bytes)")
    print(f"    Key index:      0x{key_index:04X} ({key_index})")
    print(f"    Sig length:     {sig_length} bytes")
    print(f"    RSA sig:        {rsa_sig[:16].hex()}...")

    # Verify coverage matches auth block offset
    if coverage == auth_offset:
        print(f"    Coverage check: OK (matches auth block offset 0x{auth_offset:06X})")
    else:
        print(f"    Coverage check: MISMATCH (expected 0x{auth_offset:06X})")

    # ─── Recompute streaming SHA-256 ───
    # From decompilation of SecureBoot_FeedData (0x9FF1DF96):
    #   After auth data is complete, for SHA-256 mode (_DAT_dff34214 == 2):
    #     SHA256_Init(ctx)
    #     SHA256_Update(ctx, auth_header, 6)   ← 6-byte auth header prefix
    #     SHA256_Update(ctx, key_index_BE, 2)  ← 2-byte key_index (big-endian)
    #   Then SecureBoot_Verify (0x9FF1E194) feeds data pages:
    #     SHA256_Update(ctx, data, len)
    #   SecureBoot_FinalizeVerification (0x9FF1E372):
    #     SHA256_Final(ctx, hash) → CryptoProvider_RSAVerify
    #
    # So the hash = SHA256(auth_header[6] + key_index_BE[2] + data[0:coverage])

    nand.reset_ecc_stats()

    # Build the 8-byte prefix that the bootloader feeds to SHA-256 first.
    #
    # From decompilation of NAND_LoadLBIPartition (0x9FF2160C):
    #   movw r0, #0x8ba          ; init param = 0x08BA
    #   bl   SecureBoot_Init     ; _DAT_dff73cc8 = 0x08BA
    #
    # SecureBoot_FeedData then does:
    #   SHA256_Update(ctx, auth_header, 6)                 ← raw auth header bytes
    #   SHA256_Update(ctx, &_DAT_dff73cc8_bigendian, 2)    ← init param in BE = [0x08, 0xBA]
    #
    # NOTE: The 2-byte suffix is NOT the key_index from the auth block (0x0014),
    #       but the SecureBoot_Init parameter (0x08BA) stored in _DAT_dff73cc8.
    SECURE_BOOT_INIT_PARAM = 0x08BA
    auth_prefix = auth_data[:6]                                 # [algo, provider, coverage_BE[4]]
    init_param_be = struct.pack('>H', SECURE_BOOT_INIT_PARAM)  # [0x08, 0xBA]
    prefix = auth_prefix + init_param_be
    print(f"\n  Hash prefix (8 bytes): {prefix.hex()}")
    print(f"    auth_header[6]:  {auth_prefix.hex()}")
    print(f"    init_param(BE):  {init_param_be.hex()} (SecureBoot_Init param = 0x{SECURE_BOOT_INIT_PARAM:04X})")

    # ── Compute streaming SHA-256 ──
    # Hash = SHA256(prefix[8] + LBI[0:coverage])
    # Where LBI[0:coverage] is read from the partition start for `coverage` bytes.
    print(f"\n  Computing SHA-256 over prefix(8) + LBI[0:0x{coverage:X}] ({coverage} bytes)...")

    sha = hashlib.sha256()
    sha.update(prefix)

    remaining = coverage
    off = part_start
    while remaining > 0:
        chunk = min(remaining, PAGE_DATA * 16)
        data = nand.read_data(off, chunk)
        sha.update(data)
        off += chunk
        remaining -= chunk

    computed_hash = sha.digest()
    print(f"  Computed SHA-256: {computed_hash.hex()}")
    nand.print_ecc_stats()

    # ── RSA-2048 PKCS#1 v1.5 Verification ──
    with open(RSA_KEYS_FILE, 'r') as f:
        keys = json.load(f)

    key_entry = None
    for k in keys:
        if k['key_id'] == key_index:
            key_entry = k
            break

    if key_entry is None:
        print(f"  ERROR: Key ID {key_index} not found in key table!")
        return False

    print(f"\n  RSA Key: id={key_entry['key_id']} flags={key_entry['flags']} ({key_entry['flag_desc']})")

    # RSA verification: sig^e mod n, then check PKCS#1 v1.5 padding
    n = int(key_entry['modulus_hex'], 16)
    e = key_entry['exponent']

    # Convert signature to integer (big-endian)
    sig_int = int.from_bytes(rsa_sig, 'big')

    # RSA operation: m = sig^e mod n
    m = pow(sig_int, e, n)

    # Convert back to bytes
    m_bytes = m.to_bytes(256, 'big')

    print(f"  RSA decrypted:    {m_bytes[:20].hex()}...")

    # Check PKCS#1 v1.5 structure: 00 01 FF...FF 00 <DigestInfo>
    # DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 <hash>
    SHA256_DIGESTINFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

    if m_bytes[0] == 0x00 and m_bytes[1] == 0x01:
        # Find the 0x00 separator after the 0xFF padding
        sep_idx = m_bytes.index(0x00, 2)
        # Check all padding is 0xFF
        padding_ok = all(b == 0xFF for b in m_bytes[2:sep_idx])
        digest_info = m_bytes[sep_idx + 1:]

        if padding_ok and digest_info[:len(SHA256_DIGESTINFO_PREFIX)] == SHA256_DIGESTINFO_PREFIX:
            embedded_hash = digest_info[len(SHA256_DIGESTINFO_PREFIX):]
            print(f"  PKCS#1 v1.5:      Valid structure (padding={sep_idx-2} FF bytes)")
            print(f"  Embedded SHA-256: {embedded_hash.hex()}")
            print(f"  Computed SHA-256: {computed_hash.hex()}")

            if embedded_hash == computed_hash:
                print(f"\n  *** RSA SIGNATURE VERIFICATION: PASS ***")
                return True
            else:
                print(f"\n  *** RSA SIGNATURE VERIFICATION: FAIL (hash mismatch) ***")
                return False
        else:
            print(f"  PKCS#1 v1.5: Invalid DigestInfo or padding")
            print(f"  Padding OK: {padding_ok}")
            print(f"  DigestInfo prefix match: {digest_info[:len(SHA256_DIGESTINFO_PREFIX)] == SHA256_DIGESTINFO_PREFIX}")
            # Show what we got
            print(f"  Got prefix: {digest_info[:len(SHA256_DIGESTINFO_PREFIX)].hex()}")
            print(f"  Expected:   {SHA256_DIGESTINFO_PREFIX.hex()}")
            return False
    else:
        print(f"  PKCS#1 v1.5: Invalid header (expected 00 01, got {m_bytes[0]:02x} {m_bytes[1]:02x})")
        return False


def verify_rootfs_hash_table(nand, partition_name='RootFS'):
    """
    Verify the per-block SHA-256 hash table for a RootFS partition.

    NAND block structure (from Ghidra decompilation):
      Each block's first page contains:
        - UBI EC header at offset 0x000 (magic: "UBI#" = 0x55424923)
        - UBI VID header at offset 0x200 (magic: "UBI!" = 0x55424921)
          - vol_id at VID+0x08 (page offset 0x208)
          - lnum at VID+0x0C (page offset 0x20C) — logical erase block number
          - sqnum at VID+0x18 (page offset 0x218) — sequence number
        - 32-byte SHA-256 hash at offset 0x600 (NAND_CopyBlockHeader @ 0x9FF15A2C)
        - 266-byte auth header at offset 0x620 (NAND_CopyImageHeader @ 0x9FF15A4E)
          (auth header only present on the block with lnum=0, i.e., the first data block)

    Partition layout (UBI):
        Blocks with no VID header: UBI internal (EC-only, volume table, spare)
        Blocks with vol_id=0x7FFFEFFF: UBI layout volume (volume table copies)
        Blocks with vol_id=0, lnum=N: Data blocks (logical erase block N)

    Hash table assembly (LBI_ReassembleBlockHeaders @ 0x9FF16386):
        - The hash table is indexed by UBI logical erase block number (lnum),
          NOT by physical block position.
        - LBI_ReassembleBlockHeaders skips bad blocks in the physical buffer
          using LBI_FindNextGoodBlock, effectively mapping physical blocks
          to their logical positions.
        - Number of entries = coverage / 32 (from auth header)
        - For duplicate lnums (UBI wear-leveling), the highest sqnum wins.

    Verification (SecureBoot_VerifyData @ 0x9FF16310):
        SecureBoot_Init(0x8BB) → prefix suffix = [0x08, 0xBB]
        Hash = SHA256(auth_header[0:6] + [0x08, 0xBB] + hash_entries[0:coverage])
    """
    part_start, part_size = PARTITIONS[partition_name]
    num_blocks = part_size // BLOCK_DATA
    start_block = part_start // BLOCK_DATA

    print(f"\n{'='*70}")
    print(f"RootFS Hash Table Verification: {partition_name}")
    print(f"  Partition: 0x{part_start:08X} - 0x{part_start+part_size:08X} ({part_size//1024} KiB)")
    print(f"  Blocks: {start_block} to {start_block + num_blocks - 1} ({num_blocks} blocks)")
    print(f"{'='*70}")

    nand.reset_ecc_stats()

    # ── Step 1: Scan all blocks, read UBI headers and per-block hashes ──
    # Use raw page reads (no ECC) since kernel-written UBI blocks use a different
    # ECC scheme than the bootloader's BCH(8219, t=8).
    auth_header = None
    erased_blocks = 0
    data_blocks = 0
    ubi_internal = 0
    no_vid_blocks = 0

    # Map: lnum → (hash_bytes, sqnum) — for deduplication
    lnum_to_hash = {}

    for i in range(num_blocks):
        block_num = start_block + i
        first_page = block_num * PAGES_PER_BLOCK

        # Read raw page (bypass ECC which uses wrong parameters for kernel blocks)
        nand.f.seek(first_page * PAGE_RAW)
        raw = nand.f.read(PAGE_DATA)
        page_data = raw

        # Check for erased page
        if all(b == 0xFF for b in page_data[:32]):
            erased_blocks += 1
            continue

        # Check UBI EC header
        ubi_magic = page_data[0:4]
        if ubi_magic != b'UBI#':
            continue  # Not a UBI block

        # Check UBI VID header at offset 0x200
        vid_magic = page_data[0x200:0x204]
        if vid_magic != b'UBI!':
            no_vid_blocks += 1
            continue  # No VID header (spare block, EC-only)

        # Parse VID header fields
        vol_id = struct.unpack('>I', page_data[0x208:0x20C])[0]
        lnum = struct.unpack('>I', page_data[0x20C:0x210])[0]
        sqnum = struct.unpack('>Q', page_data[0x218:0x220])[0]

        # Skip UBI internal volumes (volume table, etc.)
        if vol_id != 0:
            ubi_internal += 1
            continue

        data_blocks += 1

        # Extract 32-byte hash at offset 0x600
        block_hash = page_data[0x600:0x620]

        # Store hash by lnum, keeping highest sqnum for duplicates
        if lnum not in lnum_to_hash or sqnum > lnum_to_hash[lnum][1]:
            lnum_to_hash[lnum] = (block_hash, sqnum)

        # Auth header is on the block with lnum=0 (first data block)
        if lnum == 0 and auth_header is None:
            candidate = page_data[0x620:0x630]
            if len(candidate) >= 10 and candidate[0] == 0x02:
                sig_len = struct.unpack('>H', candidate[8:10])[0]
                if sig_len == 256:
                    auth_header = page_data[0x620:0x620 + 0x10A]

    print(f"\n  UBI block scan:")
    print(f"    Data blocks (vol 0):  {data_blocks} ({len(lnum_to_hash)} unique lnums)")
    print(f"    UBI internal:         {ubi_internal}")
    print(f"    No VID header:        {no_vid_blocks}")
    print(f"    Erased:               {erased_blocks}")

    if auth_header is None:
        print("  ERROR: No auth header found in partition!")
        return False

    # ── Step 2: Parse auth header ──
    algo_sel = auth_header[0]
    crypto_prov = auth_header[1]
    coverage = struct.unpack('>I', auth_header[2:6])[0]
    key_index = struct.unpack('>H', auth_header[6:8])[0]
    sig_length = struct.unpack('>H', auth_header[8:10])[0]
    rsa_sig = auth_header[10:10 + sig_length]

    num_hash_entries = coverage // 32

    print(f"\n  Auth Header (lnum=0 block, page offset 0x620):")
    print(f"    Algorithm:      0x{algo_sel:02X} ({'SHA-256 streaming' if algo_sel == 2 else 'unknown'})")
    print(f"    Crypto prov:    0x{crypto_prov:02X}")
    print(f"    Coverage:       0x{coverage:08X} ({coverage} bytes = {num_hash_entries} x 32)")
    print(f"    Key index:      0x{key_index:04X} ({key_index})")
    print(f"    Sig length:     {sig_length} bytes")
    print(f"    RSA sig:        {rsa_sig[:16].hex()}...")

    # ── Step 3: Assemble hash table by lnum order ──
    # The hash table is indexed by UBI logical erase block number (lnum).
    # LBI_ReassembleBlockHeaders uses LBI_FindNextGoodBlock to skip physical
    # blocks that are bad/empty, effectively mapping hashes to their lnum positions.
    assembled = bytearray(num_hash_entries * 32)  # Zero-filled
    present = 0
    missing = 0

    for lnum_val in range(num_hash_entries):
        if lnum_val in lnum_to_hash:
            h, _ = lnum_to_hash[lnum_val]
            assembled[lnum_val * 32:(lnum_val + 1) * 32] = h
            present += 1
        else:
            missing += 1

    print(f"\n  Hash table assembly (lnum-ordered):")
    print(f"    Entries: {num_hash_entries} (lnum 0 to {num_hash_entries - 1})")
    print(f"    Present: {present}")
    print(f"    Missing: {missing} (zero-filled)")

    # ── Step 4: Compute SHA-256 with prefix ──
    # SecureBoot_VerifyData uses SecureBoot_Init(0x8BB), so the prefix suffix
    # is [0x08, 0xBB] (different from LBI's 0x08BA).
    VERIFY_DATA_INIT_PARAM = 0x08BB
    auth_prefix = auth_header[:6]
    init_param_be = struct.pack('>H', VERIFY_DATA_INIT_PARAM)
    prefix = auth_prefix + init_param_be

    print(f"\n  Hash prefix (8 bytes): {prefix.hex()}")
    print(f"    auth_header[6]:  {auth_prefix.hex()}")
    print(f"    init_param(BE):  {init_param_be.hex()} (SecureBoot_VerifyData init = 0x{VERIFY_DATA_INIT_PARAM:04X})")
    print(f"  Computing SHA-256 over prefix(8) + hash_table({coverage} bytes)...")

    sha = hashlib.sha256()
    sha.update(prefix)
    sha.update(bytes(assembled[:coverage]))
    computed_hash = sha.digest()
    print(f"  Computed SHA-256: {computed_hash.hex()}")

    # ── Step 5: RSA-2048 PKCS#1 v1.5 Verification ──
    with open(RSA_KEYS_FILE, 'r') as f:
        keys = json.load(f)

    key_entry = None
    for k in keys:
        if k['key_id'] == key_index:
            key_entry = k
            break

    if key_entry is None:
        print(f"  ERROR: Key ID {key_index} not found in key table!")
        return False

    print(f"\n  RSA Key: id={key_entry['key_id']} flags={key_entry['flags']} ({key_entry['flag_desc']})")

    n = int(key_entry['modulus_hex'], 16)
    e = key_entry['exponent']
    sig_int = int.from_bytes(rsa_sig, 'big')
    m = pow(sig_int, e, n)
    m_bytes = m.to_bytes(256, 'big')

    print(f"  RSA decrypted:    {m_bytes[:20].hex()}...")

    SHA256_DIGESTINFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

    if m_bytes[0] != 0x00 or m_bytes[1] != 0x01:
        print(f"  PKCS#1 v1.5: Invalid header ({m_bytes[0]:02x} {m_bytes[1]:02x})")
        return False

    try:
        sep_idx = m_bytes.index(0x00, 2)
    except ValueError:
        print("  PKCS#1 v1.5: No separator found")
        return False

    padding_ok = all(b == 0xFF for b in m_bytes[2:sep_idx])
    digest_info = m_bytes[sep_idx + 1:]

    if not padding_ok or digest_info[:len(SHA256_DIGESTINFO_PREFIX)] != SHA256_DIGESTINFO_PREFIX:
        print(f"  PKCS#1 v1.5: Invalid DigestInfo or padding")
        return False

    embedded_hash = digest_info[len(SHA256_DIGESTINFO_PREFIX):]
    print(f"  PKCS#1 v1.5:      Valid structure (padding={sep_idx-2} FF bytes)")
    print(f"  Embedded SHA-256: {embedded_hash.hex()}")
    print(f"  Computed SHA-256: {computed_hash.hex()}")

    if embedded_hash == computed_hash:
        print(f"\n  *** ROOTFS HASH TABLE SIGNATURE: PASS ***")
        return True

    print(f"\n  *** ROOTFS HASH TABLE SIGNATURE: FAIL (hash mismatch) ***")
    return False


def compute_block_hash(nand, block_num):
    """Compute block SHA-256 exactly as the kernel's get_digest_constprop_0 does.

    From Ghidra decompilation of get_digest_constprop_0 (kernel @ b03e7fb8):
      - Hashes all 64 pages of the block sequentially with SHA-256
      - Page 0 is modified before hashing (volatile fields set to 0xFF):
          offset 0x08-0x0F  (8 bytes)  → EC header erase counter
          offset 0x18-0x1B  (4 bytes)  → EC header image_seq
          offset 0x3C-0x3F  (4 bytes)  → EC header hdr_crc
          offset 0x600-0x729 (298 bytes) → stored hash + auth header area
      - Pages 1-63 are hashed as-is (raw data, no ECC correction needed
        since the HP NAND controller uses embedded ECC transparently)

    The resulting 32-byte SHA-256 is what the kernel sends to TrustZone for
    authentication via smc_mm_guid().
    """
    sha = hashlib.sha256()

    for page in range(PAGES_PER_BLOCK):
        # Read raw page data (bypass BCH ECC — the NAND controller handles
        # ECC transparently via "embedded EC" mode, and the raw dump data
        # already reflects the ECC-corrected state for clean dumps)
        page_num = block_num * PAGES_PER_BLOCK + page
        nand.f.seek(page_num * PAGE_RAW)
        page_data = bytearray(nand.f.read(PAGE_DATA))

        if page == 0:
            # Mask volatile fields before hashing (kernel does this to ensure
            # the hash is stable across erase cycles and rewriting)
            page_data[0x08:0x10] = b'\xFF' * 8    # EC header erase counter
            page_data[0x18:0x1C] = b'\xFF' * 4    # EC header image_seq
            page_data[0x3C:0x40] = b'\xFF' * 4    # EC header hdr_crc
            page_data[0x600:0x72A] = b'\xFF' * 298 # stored hash + auth area

        sha.update(bytes(page_data))

    return sha.digest()


def _read_nand_data(nand, data_offset, length):
    """Read contiguous data bytes from data-space (raw, no ECC correction).

    Handles page/OOB stride so callers can treat the dump as a flat data buffer.
    """
    result = bytearray()
    remaining = length
    cur_off = data_offset
    while remaining > 0:
        page = cur_off // PAGE_DATA
        page_off = cur_off % PAGE_DATA
        chunk = min(remaining, PAGE_DATA - page_off)
        nand.f.seek(page * PAGE_RAW + page_off)
        result.extend(nand.f.read(chunk))
        cur_off += chunk
        remaining -= chunk
    return bytes(result)


def _collect_gf_test_blocks(nand, partition_name='RootFS', max_blocks=8):
    """Collect a handful of (lnum, stored_hash, computed_sha256) tuples for GF table validation.

    These are used to verify a candidate GF table by checking that the scramble
    produces the stored hash.
    """
    part_start, part_size = PARTITIONS[partition_name]
    start_block = part_start // BLOCK_DATA
    num_blocks = part_size // BLOCK_DATA
    test_blocks = []

    for i in range(num_blocks):
        block_num = start_block + i
        first_page = block_num * PAGES_PER_BLOCK
        nand.f.seek(first_page * PAGE_RAW)
        page_data = nand.f.read(PAGE_DATA)

        if all(b == 0xFF for b in page_data[:32]):
            continue
        if page_data[0:4] != b'UBI#' or page_data[0x200:0x204] != b'UBI!':
            continue
        vol_id = struct.unpack('>I', page_data[0x208:0x20C])[0]
        if vol_id != 0:
            continue

        lnum = struct.unpack('>I', page_data[0x20C:0x210])[0]
        stored_hash = bytes(page_data[0x600:0x620])

        # Compute block SHA-256 (kernel algorithm with page-0 masking)
        computed = compute_block_hash(nand, block_num)
        test_blocks.append((lnum, stored_hash, computed))
        if len(test_blocks) >= max_blocks:
            break

    return test_blocks


def _validate_gf_candidate(candidate, test_blocks, section_param):
    """Check if a 512-byte candidate GF table produces correct scrambled hashes
    for all test blocks with the given section_param."""
    for lnum, stored, computed in test_blocks:
        for i in range(32):
            pos_idx = (i + lnum + section_param) & 0x1FF
            expected = candidate[pos_idx] ^ candidate[computed[i]]
            if expected != stored[i]:
                return False
    return True


def extract_gf_table(nand):
    """Extract the 512-byte GF table from the TZ firmware in UpdatableLBI.

    The GF table is embedded in the TZ firmware binary (section [1] of the
    UpdatableLBI partition). Its exact offset varies between firmware versions
    (e.g. 0x23394 for FW 6.28.1.35, 0x22D30 for other builds).

    Strategy:
      1. Parse the LBI header to locate and read the TZ firmware section.
      2. Try known offsets first (fast path).
      3. If none match, brute-force search the TZ binary for any 512-byte
         sequence that correctly scrambles test blocks from RootFS.

    Returns the 512-byte GF table, or None if extraction fails.
    """
    # Known GF table offsets within the TZ binary (from different FW versions)
    KNOWN_GF_OFFSETS = [0x23394, 0x22D30]
    GF_TABLE_SIZE = 512
    UPDATABLE_LBI_START = 0x00040000

    try:
        # ── Parse LBI header ──
        page_num = UPDATABLE_LBI_START // PAGE_DATA
        nand.f.seek(page_num * PAGE_RAW)
        lbi_header = nand.f.read(PAGE_DATA)

        magic = struct.unpack('>I', lbi_header[:4])[0]
        if magic != 0xBAD2BFED:
            return None

        _, _, _, num_sections, data_start = struct.unpack('>5I', lbi_header[:20])

        # Find section [1] (TZ firmware)
        current_offset = data_start
        tz_offset = None
        tz_size = None
        for i in range(num_sections):
            off = 20 + i * 24
            role, load, size, _, _, _ = struct.unpack('>6I', lbi_header[off:off+24])
            if i == 1:
                tz_offset = current_offset
                tz_size = size
                break
            if size > 0:
                current_offset += size
                current_offset = (current_offset + data_start - 1) & ~(data_start - 1)
            else:
                current_offset += 320

        if tz_offset is None or tz_size is None:
            return None

        # ── Read entire TZ section into memory ──
        tz_abs_start = UPDATABLE_LBI_START + tz_offset
        tz_data = _read_nand_data(nand, tz_abs_start, tz_size)

        # ── Collect test blocks for validation ──
        section_param = SECTION_PARAMS['RootFS']  # Use RootFS (more blocks)
        test_blocks = _collect_gf_test_blocks(nand, 'RootFS', max_blocks=8)
        if not test_blocks:
            print("    WARNING: No RootFS test blocks available for GF table validation")
            return None

        # ── Fast path: try known offsets ──
        for known_off in KNOWN_GF_OFFSETS:
            if known_off + GF_TABLE_SIZE > len(tz_data):
                continue
            candidate = tz_data[known_off:known_off + GF_TABLE_SIZE]
            if all(b == 0 for b in candidate) or all(b == 0xFF for b in candidate):
                continue
            if _validate_gf_candidate(candidate, test_blocks, section_param):
                print(f"    Found GF table at known TZ offset 0x{known_off:05X}")
                return bytes(candidate)

        # ── Slow path: brute-force search the entire TZ binary ──
        print(f"    Known offsets failed, searching {len(tz_data)} bytes of TZ firmware...")
        for offset in range(len(tz_data) - GF_TABLE_SIZE + 1):
            candidate = tz_data[offset:offset + GF_TABLE_SIZE]
            # Quick reject: first test block, first byte only
            lnum0, stored0, computed0 = test_blocks[0]
            pos_idx = (0 + lnum0 + section_param) & 0x1FF
            if (candidate[pos_idx] ^ candidate[computed0[0]]) != stored0[0]:
                continue
            # Full validation
            if _validate_gf_candidate(candidate, test_blocks, section_param):
                print(f"    Found GF table at TZ offset 0x{offset:05X} (new location)")
                return bytes(candidate)

        print("    GF table not found in TZ firmware")
        return None
    except Exception as e:
        print(f"    Exception during GF table extraction: {e}")
        return None


def gf_scramble(gf_table, sha256_hash, lnum, section_param):
    """Apply the GF(2^8) scramble to produce the stored hash.

    Replicates ECC_XORWithGFTable @ 9ff2ce58:
      stored[i] = GF_TABLE[(i + lnum + section_param) & 0x1FF] ^ GF_TABLE[sha256[i]]
    """
    result = bytearray(32)
    for i in range(32):
        pos_idx = (i + lnum + section_param) & 0x1FF
        val_idx = sha256_hash[i]
        result[i] = gf_table[pos_idx] ^ gf_table[val_idx]
    return bytes(result)


# Section param per partition — determines position index offset in GF scramble.
# Stored in TZ RAM at 0xDFF5D550 (RootFS) and 0xDFF70EF4 (RecoveryRootFS).
SECTION_PARAMS = {
    'RootFS':         4,
    'RecoveryRootFS': 6,
}


def verify_rootfs_block_hashes(nand, partition_name='RootFS', gf_table=None):
    """
    Verify per-block data integrity for a RootFS partition.

    Uses two verification modes:
      1. Direct GF-table verification (preferred): If the GF table is available
         (extracted from UpdatableLBI/TZ firmware at binary offset 0x23394), compute
         the expected GF-scrambled hash for each block and compare directly against
         the stored hash. This provides exact, byte-for-byte verification identical
         to what TrustZone performs at runtime.

      2. Pair-level GF constraint verification (fallback): If the GF table cannot
         be extracted, build a constraint table from all blocks' (pos, val) → xor
         mappings and verify consistency. This is slightly weaker (unseen GF pairs
         cannot be checked) but still highly reliable with ~500+ blocks.

    TZ firmware references (dune_selene_kexec_trusted_fw.bin):
      - FS_AuthenticateBlock @ 9ff164da: calls ECC_XORWithGFTable then Memcmp
      - ECC_XORWithGFTable @ 9ff2ce58: GF_TABLE[(i+offset+section)&0x1FF] ^ GF_TABLE[hash[i]]
      - FS_CalcLogicalBlockOffset @ 9ff1648e: computes logical offset from physical block

    Kernel references (kernel_6.28.elf):
      - get_digest_constprop_0 @ b03e7fb8: SHA-256 computation with page 0 masking
      - hp_nand_fsa_get_readable_2 @ b03e745c: sends hash to TZ via SMC
    """
    part_start, part_size = PARTITIONS[partition_name]
    num_blocks = part_size // BLOCK_DATA
    start_block = part_start // BLOCK_DATA

    print(f"\n{'='*70}")
    print(f"Per-Block Hash Verification: {partition_name}")
    print(f"  Partition: 0x{part_start:08X} - 0x{part_start+part_size:08X} ({part_size//1024} KiB)")
    print(f"  Blocks: {start_block} to {start_block + num_blocks - 1} ({num_blocks} blocks)")
    print(f"{'='*70}")

    use_gf_table = gf_table is not None
    if use_gf_table:
        section_param = SECTION_PARAMS[partition_name]
        print(f"  Mode: Direct GF-table verification (section_param={section_param})")
    else:
        section_param = 0  # Arbitrary base for constraint mode
        print(f"  Mode: Pair-level GF constraint verification (fallback)")

    # ── Step 1: Scan UBI blocks and collect stored hashes ──
    print(f"\n  Scanning UBI blocks...")
    block_info = {}  # lnum → (block_num, stored_hash, sqnum)

    for i in range(num_blocks):
        block_num = start_block + i
        first_page = block_num * PAGES_PER_BLOCK

        nand.f.seek(first_page * PAGE_RAW)
        page_data = nand.f.read(PAGE_DATA)

        if all(b == 0xFF for b in page_data[:32]):
            continue
        if page_data[0:4] != b'UBI#':
            continue
        if page_data[0x200:0x204] != b'UBI!':
            continue

        vol_id = struct.unpack('>I', page_data[0x208:0x20C])[0]
        lnum = struct.unpack('>I', page_data[0x20C:0x210])[0]
        sqnum = struct.unpack('>Q', page_data[0x218:0x220])[0]

        if vol_id != 0:
            continue

        stored_hash = page_data[0x600:0x620]

        if lnum not in block_info or sqnum > block_info[lnum][2]:
            block_info[lnum] = (block_num, stored_hash, sqnum)

    # Build final list of blocks to verify (one per lnum, highest sqnum)
    all_data_blocks = []
    for lnum in sorted(block_info.keys()):
        block_num, stored_hash, sqnum = block_info[lnum]
        all_data_blocks.append((block_num, lnum, stored_hash))

    print(f"    Data blocks: {len(all_data_blocks)} unique lnums")

    # ── Step 2: Compute SHA-256 for all blocks ──
    if use_gf_table:
        print(f"  Computing block hashes and verifying against GF-scrambled expectations...")
    else:
        print(f"  Computing block hashes and building GF constraint table...")

    gf_constraints = {}  # Only used in fallback mode
    constraint_conflicts = 0
    block_hashes = {}  # block_num → computed_sha256

    for idx, (block_num, lnum, stored_hash) in enumerate(all_data_blocks):
        computed = compute_block_hash(nand, block_num)
        block_hashes[block_num] = computed

        if not use_gf_table:
            # Fallback: build constraint table
            for i in range(32):
                pos_idx = (i + lnum + section_param) & 0x1FF
                val_idx = computed[i]
                xor_val = stored_hash[i]

                key = (pos_idx, val_idx)
                if key in gf_constraints:
                    if gf_constraints[key] != xor_val:
                        constraint_conflicts += 1
                else:
                    gf_constraints[key] = xor_val

        if (idx + 1) % 100 == 0:
            print(f"    Processed {idx + 1}/{len(all_data_blocks)} blocks...")

    if not use_gf_table:
        print(f"    GF constraint table: {len(gf_constraints)} unique pairs")
        if constraint_conflicts > 0:
            print(f"    WARNING: {constraint_conflicts} constraint conflicts detected")
            print(f"             (indicates bit errors or data corruption in some blocks)")

    # ── Step 3: Verify each block ──
    if use_gf_table:
        print(f"\n  Verifying block hashes (direct GF-table comparison)...")
    else:
        print(f"\n  Verifying block hashes against GF constraint table...")

    verified_ok = 0
    verified_fail = 0
    unverifiable_bytes = 0
    total_bytes_checked = 0
    failed_blocks = []

    for block_num, lnum, stored_hash in all_data_blocks:
        computed = block_hashes[block_num]

        if use_gf_table:
            # Direct mode: compute expected stored hash and compare
            expected = gf_scramble(gf_table, computed, lnum, section_param)
            total_bytes_checked += 32
            if expected == stored_hash:
                verified_ok += 1
            else:
                verified_fail += 1
                mismatches = sum(1 for a, b in zip(expected, stored_hash) if a != b)
                failed_blocks.append((block_num, lnum, mismatches, 32))
        else:
            # Fallback: pair-level constraint check
            block_ok = True
            block_checked = 0
            block_mismatches = 0

            for i in range(32):
                pos_idx = (i + lnum + section_param) & 0x1FF
                val_idx = computed[i]
                xor_val = stored_hash[i]

                key = (pos_idx, val_idx)
                if key in gf_constraints:
                    total_bytes_checked += 1
                    block_checked += 1
                    if gf_constraints[key] != xor_val:
                        block_ok = False
                        block_mismatches += 1
                else:
                    unverifiable_bytes += 1

            if block_ok:
                verified_ok += 1
            else:
                verified_fail += 1
                failed_blocks.append((block_num, lnum, block_mismatches, block_checked))

    print(f"\n  Results:")
    print(f"    Blocks verified OK:    {verified_ok}")
    print(f"    Blocks with errors:    {verified_fail}")
    print(f"    Bytes checked:         {total_bytes_checked}")
    if not use_gf_table:
        print(f"    Bytes uncoverable:     {unverifiable_bytes} (unseen GF pairs)")

    if failed_blocks:
        print(f"\n  Failed blocks (potential data corruption):")
        for block_num, lnum, mismatches, checked in failed_blocks[:20]:
            print(f"    Block {block_num} (lnum={lnum}): {mismatches}/{checked} byte mismatches")
        if len(failed_blocks) > 20:
            print(f"    ... and {len(failed_blocks) - 20} more")

    if not use_gf_table:
        # Coverage analysis only relevant for constraint mode
        pos_covered = set()
        val_covered = set()
        for (pi, vi) in gf_constraints:
            pos_covered.add(pi)
            val_covered.add(vi)
        print(f"\n  GF constraint coverage:")
        print(f"    Position indices: {len(pos_covered)}/512")
        print(f"    Value bytes:      {len(val_covered)}/256")
        print(f"    Total pairs:      {len(gf_constraints)}")

    success = verified_fail == 0
    if success:
        print(f"\n  *** PER-BLOCK HASH VERIFICATION: PASS ({verified_ok} blocks) ***")
    else:
        print(f"\n  *** PER-BLOCK HASH VERIFICATION: FAIL ({verified_fail} blocks with errors) ***")

    return success


def main():
    parser = argparse.ArgumentParser(
        description='HP Dune/Selene NAND Secure Boot Verification Tool',
    )
    parser.add_argument('nand_dump', metavar='nand_dump.bin',
                        help='Raw NAND dump with OOB (e.g. nand_with_oob.bin)')
    parser.add_argument('--mode', choices=['auto', 'gf-table', 'constraint'],
                        default='auto',
                        help='Hash verification mode: '
                             '"auto" (default) extracts GF table, falls back to constraints; '
                             '"gf-table" forces embedded GF table (aborts if unavailable); '
                             '"constraint" skips GF table and uses pair-level constraint verification')
    args = parser.parse_args()

    nand_file = args.nand_dump
    mode = args.mode

    print("HP Dune/Selene NAND Verification Tool")
    print("=" * 70)
    print(f"NAND file: {nand_file}")
    print(f"Hash verification mode: {mode}")

    nand = NANDReader(nand_file)

    # 1. Verify UpdatableLBI RSA signature
    lbi_ok = verify_lbi_signature(nand, 'UpdatableLBI')

    # 2. Verify RecoveryLBI RSA signature
    rec_lbi_ok = verify_lbi_signature(nand, 'RecoveryLBI')

    # 3. Verify RootFS hash table signature
    rootfs_ok = verify_rootfs_hash_table(nand, 'RootFS')

    # 4. Verify RecoveryRootFS hash table signature
    rec_rootfs_ok = verify_rootfs_hash_table(nand, 'RecoveryRootFS')

    # 5. Resolve GF table based on mode
    gf_table = None
    print(f"\n{'='*70}")

    if mode == 'constraint':
        print(f"GF Table: Skipped (--mode constraint)")
        print(f"{'='*70}")
        print(f"  Mode: Pair-level GF constraint verification (forced)")
    else:
        print(f"Extracting GF Table from TZ Firmware")
        print(f"{'='*70}")
        gf_table = extract_gf_table(nand)
        if gf_table is not None:
            print(f"  GF table extracted: {len(gf_table)} bytes")
            print(f"  First 16 bytes: {gf_table[:16].hex()}")
            print(f"  Mode: Direct GF-table hash verification")
        else:
            if mode == 'gf-table':
                print(f"  ERROR: Could not extract GF table from UpdatableLBI/TZ firmware")
                print(f"  Aborting: --mode gf-table was specified but extraction failed.")
                nand.close()
                sys.exit(2)
            else:
                print(f"  WARNING: Could not extract GF table from UpdatableLBI/TZ firmware")
                print(f"  Mode: Falling back to pair-level GF constraint verification")

    # 6. Verify per-block hashes for RootFS
    rootfs_blocks_ok = verify_rootfs_block_hashes(nand, 'RootFS', gf_table)

    # 7. Verify per-block hashes for RecoveryRootFS
    rec_rootfs_blocks_ok = verify_rootfs_block_hashes(nand, 'RecoveryRootFS', gf_table)

    # Summary
    print(f"\n{'='*70}")
    print(f"VERIFICATION SUMMARY")
    print(f"{'='*70}")
    results = [
        ('UpdatableLBI RSA', lbi_ok),
        ('RecoveryLBI RSA', rec_lbi_ok),
        ('RootFS Hash Table RSA', rootfs_ok),
        ('RecoveryRootFS Hash Table RSA', rec_rootfs_ok),
        ('RootFS Per-Block Hashes', rootfs_blocks_ok),
        ('RecoveryRootFS Per-Block Hashes', rec_rootfs_blocks_ok),
    ]
    for name, ok in results:
        status = 'PASS' if ok else 'FAIL'
        print(f"  {name:35s} [{status}]")

    nand.close()


if __name__ == '__main__':
    main()
