# HP Color LaserJet Pro 4301 MFP — M24256BW EEPROM Layout
# Dune/Selene platform, STMicroelectronics M24256BW 32 KiB I2C EEPROM.
#
# Structural skeleton only — the full field-by-field decomposition
# (counter_data records, prot0/1/2/3 mirror + checksum structure,
# NVM2 TLV objects, etc.) is kept in:
#
#   * 010_editor_templates/HP_Dune_Selene_EEPROM.bt
#   * documentation_current/HP_Dune_Selene_EEPROM_Layout.md
#   * firmware-toolkit/plugins/hp_clj_pro_4301_eeprom/nos_codec.py
#
# This file models the top-level zones at the granularity needed by
# tools that just want to slice the image into well-named blobs
# (NOS / NVM2) with the correct boundaries as of firmware 6.28.1.47
# and the current firmware_toolkit codec.
#
# ─── Codec tiering (firmware_toolkit) ────────────────────────────
#  NOS Tier-1: partitioned fields (0x000-0x0C1)
#  NOS Tier-2: bootloader flat fields (0x100-0x130, 13 entries)
#  NOS Tier-3: NOS NVM extension (0x131-0x1FD)
#               - backup_device_pin @0x131 (4 B, NVM ID 0x94)
#               - nos_nvm_reserved  @0x135 (201 B, opaque filler)
#  NVM2 region: 0x1FE-0x7FFF (root-page pointer then header + pages)
#
# Source: Reverse-engineered from dune_selene_nandboot.bin,
# dune_selene_kexec_trusted_fw.bin, and kernel_6.17.elf.

meta:
  id: hp_clj_pro_4301_eeprom
  title: HP Color LaserJet Pro 4301 MFP M24256BW EEPROM Dump
  file-extension: bin
  endian: le

seq:
  - id: nos_region
    type: nos_region
    size: 0x1FE
    doc: |
      NOS region (0x000-0x1FD, 510 bytes). Bootloader-managed
      three-tier model: partitioned + flat + NOS NVM extension.
  - id: nvm2_region
    type: nvm2_region
    doc: |
      NVM2 region (0x01FE-0x7FFF, 31,746 bytes). Starts with
      the 2-byte big-endian root-page pointer at 0x01FE-0x01FF,
      followed by the NVM2 header at 0x0200 and the page-based
      object storage from 0x02C0 onward.

types:

  # ──────────────────────────────────────────────
  # NOS Region (0x000–0x1FD, 510 bytes)
  # ──────────────────────────────────────────────
  nos_region:
    doc: |
      NOS region. Ends at 0x1FD; the 2 bytes at 0x1FE-0x1FF
      physically sit between NOS and NVM2 but belong to the
      NVM2 region in the firmware-toolkit codec's sidecar model.
    seq:
      - id: partitioned_region
        size: 0xC2
        doc: |
          NOS Tier-1 — partitioned fields (0x000-0x0C1).
          Layout defined by the type 0x40 sub-partition table
          at binary address 0x9FF33AA4 in the second-stage
          bootloader (21 entries). See HP_Dune_Selene_EEPROM_Layout.md
          §6 for the full field table.
      - id: partition_tail_fill
        size: 0x100 - 0xC2
        doc: "Unused partition tail (0x0C2-0x0FF, 0xFF fill, 62 B)."
      - id: flat_fields
        type: flat_fields
        size: 0x31
        doc: |
          NOS Tier-2 — bootloader flat fields (0x100-0x130, 49 B).
          13 fields accessed via the flat table at RAM 0xDFB30C20
          (partition_id > 0x80). Multi-byte integers are big-endian
          (NVM_ReadField convention) with MAP2_VERSION as the LE
          exception.
      - id: nos_nvm_extension
        type: nos_nvm_extension
        size: 0x1FE - 0x131
        doc: |
          NOS Tier-3 — NOS NVM extension (0x131-0x1FD, 205 B).
          Bytes that are part of the NOS region but NOT in the
          bootloader's flat table. Accessed by the userspace NOS
          NVM system (libNvram.so).

  flat_fields:
    doc: "13 bootloader flat NVM fields at 0x100-0x130."
    seq:
      - id: map2_version
        type: u2le
        doc: |
          MAP2_VERSION (0x100, LE uint16). Exception to BE convention:
          written by the kernel NVM driver in LE mode (value 1 = v1).
      - id: pca_serial_number
        size: 10
        doc: "PcaSerialNumber (0x102-0x10B, 10 B ASCII, e.g. '25640V1A')."
      - id: eth0_mac
        size: 6
        doc: "ETH0_MAC_ADDR (0x10C-0x111, 6 B network byte order)."
      - id: wlan0_mac
        size: 6
        doc: "WLAN0_MAC_ADDR (0x112-0x117, 6 B network byte order)."
      - id: wlan1_mac
        size: 6
        doc: "WLAN1_MAC_ADDR (0x118-0x11D, 6 B network byte order)."
      - id: power_cycle_count
        size: 2
        doc: "POWER_CYCLE_COUNT (0x11E-0x11F, 2 B big-endian)."
      - id: secure_vars
        type: u1
        doc: |
          SECURE_VARS (0x120, 1 B). bit2 = purpose TBD,
          bit7 = SW Secure Boot override (HW fuse at 0x3C001048
          is the primary control).
      - id: boot_flags2
        size: 2
        doc: |
          BOOT_FLAGS2 (0x121-0x122, 2 B big-endian). bit2 =
          updatable partition failed, bit3 = recovery mode set,
          bit4 = recovery partition failed, bit5 = recovery cleared,
          bit8/9 = UI boot mode, bit12 = factory reset.
      - id: misc_1
        size: 4
        doc: "MISC_1 (0x123-0x126, 4 B; 0xFFFFFFFF = empty)."
      - id: save_recover_id
        size: 4
        doc: "SAVE_RECOVER_ID (0x127-0x12A, 4 B; 0xFFFFFFFF = empty)."
      - id: mpca_bpca_pairing
        size: 2
        doc: "MPCA_BPCA_PAIRING (0x12B-0x12C, prot2: primary + mirror)."
      - id: misc_2
        size: 2
        doc: "MISC_2 (0x12D-0x12E, 2 B; 0xFFFF = empty)."
      - id: eeprom_recov_count_flat
        size: 2
        doc: |
          EEPROM_RECOV_COUNT_FLAT (0x12F-0x130, 2 B BE).
          NOS NVM name 'EEPROM_RECOV_COUNT'; distinct from the
          partitioned EEPROM_RECOV_COUNT at 0x06A.

  nos_nvm_extension:
    doc: |
      NOS Tier-3 entries. Accessed by libNvram.so using NOS NVM
      IDs outside the bootloader's flat-table range.
    seq:
      - id: backup_device_pin
        size: 4
        doc: |
          BackupDevicePin (NOS NVM ID 0x94, 0x131-0x134, 4 B).
          Firmware treats this as a little-endian integer in RAM;
          on disk the bytes appear in on-disk order. The
          firmware-toolkit sidecar serialises these 4 bytes as a
          hex string "0xAABBCCDD" in on-disk byte order (so
          "0xFFFFFFFF" when unprogrammed). Byte-reverse to
          recover the logical LE integer. See
          HP_Dune_Selene_PIN_Analysis.md §8.3.
      - id: nos_nvm_reserved
        size: 201
        doc: |
          Opaque filler (0x135-0x1FD, 201 B). First byte (0x135)
          is the tail of the bootloader's RAM-cached span
          (0x000-0x135); bytes 0x136-0x1FD are 0xFF-filled in
          all observed dumps. Preserved verbatim by the codec.

  # ──────────────────────────────────────────────
  # NVM2 Region (0x1FE–0x7FFF, 31,746 bytes)
  # ──────────────────────────────────────────────
  nvm2_region:
    doc: |
      Kernel-managed NVM2 region. Starts with the 2-byte BE
      root-page pointer (physically outside but logically part
      of NVM2), followed by the 19-byte header at 0x200,
      header padding to the end of page 8, span + allocation
      bitmaps, and page-based object storage.
    seq:
      - id: root_page_pointer
        type: u2be
        doc: |
          Root page pointer (0x1FE-0x1FF, big-endian uint16).
          Written by kernel _write_root_page(). Points to page 8
          (value 0x0008 => 0x0008 * 64 = 0x200). Observed: 0xFFFF
          on the fixture dumps (unwritten — kernel falls back to
          scanning for the magic).
      - id: header
        type: nvm2_header
        doc: "NVM2 header (19 B at 0x200)."
      - id: header_padding
        size: 0x240 - 0x213
        doc: "Header padding (0x213-0x23F, 45 B, 0xFF fill)."
      - id: span_bitmap
        size: 64
        doc: |
          Span bitmap (page 9, 0x240-0x27F). Each bit marks a
          continuation page of a multi-page object. Set by
          _nvm_allocate() for pages > first of a span.
      - id: alloc_bitmap
        size: 64
        doc: |
          Allocation bitmap (page 10, 0x280-0x2BF). Each bit
          marks a page that contains NVM object data.
      - id: object_pages
        size-eos: true
        doc: |
          Page-based object storage from page 11 (0x2C0) to EOF.
          Variable-length headers (3-5 B encoding 22-bit object
          IDs + length classes). See
          firmware_toolkit/plugins/hp_clj_pro_4301_eeprom/nvm2_decoder.py
          for the full TLV walker; the byte-level format is also
          summarised in HP_Dune_Selene_EEPROM_Layout.md §9.

  nvm2_header:
    doc: |
      NVM2 header (19 B at EEPROM offset 0x200). All fields are
      little-endian.
    seq:
      - id: magic
        type: u4le
        doc: "NVM2 magic: 0x7EEDC0DE."
      - id: version_info
        type: u4le
        doc: |
          Composite (key_id << 16) | version. key_id from device-tree
          hp_key_id (1), version = 2. Observed: 0x00010002.
      - id: object_count
        type: u2le
        doc: "Active NVM object count."
      - id: max_objects
        type: u2le
        doc: "Max object-table capacity (300)."
      - id: alloc_bitmap_offset
        type: u2le
        doc: "Allocation bitmap EEPROM offset (0x0280, page 10)."
      - id: span_bitmap_offset
        type: u2le
        doc: "Span bitmap EEPROM offset (0x0240, page 9)."
      - id: debug_level
        type: u1
        doc: "Debug verbosity for kernel NVM driver (0xFF = disabled)."
      - id: generation_counter
        type: u2le
        doc: |
          Generation / recovery counter
          (sysfs: eeprom_recovery_count, a.k.a. format_count).
