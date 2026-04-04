meta:
  id: hp_clj_pro_4301_lbi
  title: HP CLJ Pro 4301-4303 Loadable Boot Image (LBI)
  file-extension: bin
  endian: be
  license: MIT

doc: |
  Loadable Boot Image (LBI) format used by the HP Color LaserJet
  Pro MFP 4301-4303 (TX54 platform) for both the UpdatableLBI
  (mtd1) and RecoveryLBI (mtd5) partitions.

  Structure:
    - 20-byte base header (magic, version, total header size,
      section count, data start offset)
    - N section descriptors of 24 bytes each
    - Padding (0xFF) from end of descriptors to data_start
    - Section data, each padded to data_start alignment
    - Trailing 0xFF padding to partition end

  The header size field equals 20 + N * 24 (base + descriptors).
  Section data offsets are computed sequentially: each section's
  data immediately follows the previous section's data, aligned
  up to the data_start boundary (typically 0x800 = 2048 bytes).

  Known sections (5 in this firmware):
    0: Boot logo (BMP image)
    1: Second-stage bootloader (BL2, ARM BE code)
    2: Device Tree Blob (DTB, magic 0xD00DFEED)
    3: Kernel zImage (ARM BE, compressed Linux kernel)
    4: Authentication block (SecureBoot header + RSA-2048 sig)

seq:
  - id: header
    type: lbi_header

  - id: section_descriptors
    type: section_descriptor
    repeat: expr
    repeat-expr: header.num_sections

  - id: header_padding
    size: header.data_start - header.header_size

types:
  lbi_header:
    doc: |
      20-byte base header for the LBI format.
    seq:
      - id: magic
        size: 4
        doc: LBI magic bytes (0xBAD2BFED big-endian).
      - id: version
        type: u4
        doc: Format version (observed value 1).
      - id: header_size
        type: u4
        doc: |
          Total size of header + descriptors in bytes.
          Equals 20 + num_sections * 24.
      - id: num_sections
        type: u4
        doc: Number of section descriptors that follow.
      - id: data_start
        type: u4
        doc: |
          Byte offset where section data begins.  Also used
          as the alignment boundary for each section's data.
          Typically 0x800 (2048).

  section_descriptor:
    doc: |
      24-byte section descriptor.  Describes one payload section
      within the LBI image.

      Data offsets are NOT stored per-descriptor; they are
      computed sequentially starting from data_start, with each
      section aligned up to the data_start boundary.

      Validation rules (from BL1 reverse engineering):
        - Exactly one section must have ENTRY (0x0080) in role_flags.
        - The last section must have SIG (0x2000) in role_flags.
    seq:
      - id: role_flags
        type: u4
        doc: |
          Section role flags (bit field):
            0x0001 = AUTH_COMPANION — auth-section companion bit (set on auth block)
            0x0080 = ENTRY — section has an executable entry point (BL2)
            0x0800 = OVERRIDE_DEST — override load_address with framebuffer address
            0x2000 = SIG   — section contains authentication signature
          Observed values: 0x0800 (BMP), 0x0080 (BL2),
          0x0000 (DTB/kernel), 0x2001 (auth block = SIG|AUTH_COMPANION).
      - id: load_address
        type: u4
        doc: |
          DRAM load address for this section (0 if not loaded).
          BL2: 0x9FF10680, DTB: 0x93F3A000, Kernel: 0x81000000.
      - id: size
        type: u4
        doc: |
          Size of section data in bytes.  May be 0 for the
          auth block (section 4), whose size is implicit.
      - id: image_type
        type: u4
        doc: |
          Toolchain image type tag.  Written by LBI packing tool but
          NOT read by either bootloader stage (confirmed by decompilation).
          Section identification relies entirely on role_flags bits.
          Values:
            0x00 = plain data / BL2 executable
            0x04 = Device Tree Blob (DTB)
            0x0A = ARM zImage (compressed kernel)
          Observed: 0x00 for BMP/BL2/auth, 0x04 for DTB, 0x0A for kernel.
      - id: entry_point
        type: u4
        doc: |
          Execution entry point address (non-zero only for BL2).
          BL2 entry: 0x9FF10F24 = load_address + 0x8A4.
      - id: reserved
        type: u4
        doc: Reserved / padding (always 0).
