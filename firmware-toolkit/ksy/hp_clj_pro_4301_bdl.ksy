meta:
  id: hp_clj_pro_4301_bdl
  title: HP CLJ Pro 4301-4303 BDL (Bundle) Firmware Image
  file-extension: bdl
  endian: le
  license: MIT

doc: |
  BDL (Bundle) firmware update container format used by HP LaserJet
  printers.  Contains one or more packages (LBI, rootfs, datafs,
  eclipse), each holding one or more files (digests.txt, encrypted
  firmware payloads).

  Structure:
    - BdlHeader (2345 bytes, magic "ibdl")
    - PackageTable (16 bytes × N entries)
    - Package data (PakHeader + FileTable + file data) × N

  All multi-byte integers are little-endian.  All string fields are
  null-terminated, fixed-width character arrays.  Structures use packed
  alignment (no padding between fields).

  CRC-32 verification:
    - BdlHeader.header_crc: CRC-32 over header bytes with the CRC
      field itself zeroed out.
    - BdlHeader.item_table_crc: CRC-32 of the PackageTable bytes.
    - PakHeader.header_crc / item_table_crc: same semantics for
      the package header and its file table.
    - FileTableEntry.crc32: CRC-32 of the file data payload.

seq:
  - id: bdl_header
    type: bdl_header

  - id: package_table
    type: package_table_entry
    repeat: expr
    repeat-expr: bdl_header.common.item_count

types:
  # ── Shared 800-byte header prefix ────────────────────────────────
  common_header:
    doc: |
      800-byte common header prefix shared by BdlHeader and PakHeader.
      Contains magic, version, sizes, CRCs, timestamps, and three
      256-byte string fields (version_string, vendor, name).
    seq:
      - id: magic
        size: 4
        doc: |
          Format magic.  "ibdl" (0x6962646C) for bundle headers,
          "ipkg" (0x69706B67) for package headers.
      - id: version_major
        type: u2
        doc: Format version major (e.g. 1).
      - id: version_minor
        type: u2
        doc: Format version minor (e.g. 1 for BDL, 3 for packages).
      - id: header_size
        type: u4
        doc: Total header struct size in bytes (2345 for BDL, 1085 for PAK).
      - id: header_crc
        type: u4
        doc: CRC-32 of the header, computed with this field zeroed.
      - id: item_count
        type: u4
        doc: |
          Number of sub-items.  For BDL: number of packages.
          For PAK: number of files.
      - id: item_table_crc
        type: u4
        doc: CRC-32 of the item table that immediately follows the header.
      - id: timestamp
        type: u4
        doc: Unix epoch build timestamp.
      - id: reserved
        type: u4
        doc: Reserved (always 0).
      - id: version_string
        size: 256
        type: strz
        encoding: ASCII
        doc: |
          Firmware version string, e.g. "6.28.1.35-202511201716".
      - id: vendor
        size: 256
        type: strz
        encoding: ASCII
        doc: Vendor name, e.g. "HP".
      - id: name
        size: 256
        type: strz
        encoding: ASCII
        doc: |
          Bundle name (device model list) or package name
          (e.g. "lbi", "rootfs").

  # ── BDL Header (2345 bytes) ──────────────────────────────────────
  bdl_header:
    doc: |
      Bundle header.  Extends CommonHeader with bundle-specific fields.
      Total size: 2345 bytes (0x929).  Magic is "ibdl".
      Note: the pad0 byte at 0x328 causes subsequent 256-byte string
      fields to be unaligned (packed layout).
    seq:
      - id: common
        type: common_header
      - id: type
        type: u4
        doc: Bundle type (e.g. 0x300).
      - id: options
        type: u4
        doc: Bundle options bitmask.
      - id: pad0
        type: u1
        doc: Alignment/version byte (always 0).
      - id: description
        size: 256
        type: strz
        encoding: ASCII
        doc: |
          Human-readable bundle description, e.g.
          "HP Color LaserJet Pro MFP 4300 Series Firmware".
      - id: identifier
        size: 256
        type: strz
        encoding: ASCII
        doc: Bundle identifier, e.g. "706D66-0005".
      - id: support_url
        size: 256
        type: strz
        encoding: ASCII
        doc: Support URL.
      - id: support_phone
        size: 256
        type: strz
        encoding: ASCII
        doc: Support phone number.
      - id: support_email
        size: 256
        type: strz
        encoding: ASCII
        doc: Support email address.
      - id: serial_number
        size: 256
        type: strz
        encoding: ASCII
        doc: Serial number.

  # ── Package Table Entry (16 bytes) ───────────────────────────────
  package_table_entry:
    doc: |
      Entry in the package table that follows the BdlHeader.
      Provides the absolute byte offset and total size of each package.
    seq:
      - id: offset
        type: u8
        doc: |
          Byte offset from start of BDL file to the PakHeader
          of this package.
      - id: size
        type: u8
        doc: |
          Total size of the package (PakHeader + FileTable +
          all file data).

  # ── Package Header (1085 bytes) ──────────────────────────────────
  pak_header:
    doc: |
      Package header.  Extends CommonHeader with package-specific
      fields.  Total size: 1085 bytes (0x43D).  Magic is "ipkg".
    seq:
      - id: common
        type: common_header
      - id: type_uuid
        size: 16
        doc: |
          Package type UUID (16 bytes, RFC 4122 mixed-endian on disk).
          Known types:
            LBI:     9d33cb83-bdf6-e040-8c45-59e409579b58
            ROOTFS:  9d33cb83-bdf6-e040-8c45-59e409579b59
            DATAFS:  9d33cb83-bdf6-e040-8c45-59e409579b5a
            ECLIPSE: f50ecc25-2672-5c46-9f0a-190aaaef9175
      - id: install_options
        type: u4
        doc: Installation options bitmask (e.g. 0x17F).
      - id: install_phase
        type: u4
        doc: Installation phase.
      - id: package_options
        type: u4
        doc: Package options bitmask.
      - id: pad0
        type: u1
        doc: Alignment/version byte (always 0).
      - id: description
        size: 256
        type: strz
        encoding: ASCII
        doc: |
          Human-readable package description, e.g.
          "Updatable LBI Package".

  # ── File Table Entry (276 bytes) ─────────────────────────────────
  file_table_entry:
    doc: |
      Entry in the file table that follows each PakHeader.
      The file_offset is relative to the start of the containing
      package (the PakHeader position), NOT the BDL file start.
    seq:
      - id: filename
        size: 256
        type: strz
        encoding: ASCII
        doc: Null-terminated filename (e.g. "digests.txt").
      - id: file_offset
        type: u8
        doc: |
          Byte offset of file data, relative to the start of
          the containing package (PakHeader position).
      - id: file_size
        type: u8
        doc: Size of the file data in bytes.
      - id: crc32
        type: u4
        doc: CRC-32 of the file data.
