# HP TX54 (Dune/Selene) Platform — M24256BW EEPROM Layout
# STMicroelectronics M24256BW 32 KiB I2C EEPROM (addr 0x50, controller 0x3C029000).
#
# Three-tier NVM architecture:
#   Tier 1  [0x000-0x0C1]  Bootloader partitioned fields (type 0x40 sub-partition table)
#   Tier 2  [0x100-0x131]  Bootloader flat fields (partition_id > 0x80)
#   Tier 3  [0x200-0x7FFF] Kernel NVM2 object storage (magic 0x7EEDC0DE)
#
# NOS region (0x000-0x1FF, 512 B) is bootloader-managed.
# Multi-byte bootloader fields are big-endian.
# NVM2 region (0x200+) is kernel-managed, little-endian metadata.
#
# Source: Reverse-engineered from dune_selene_nandboot.bin,
# dune_selene_kexec_trusted_fw.bin, and kernel_6.17.elf.
meta:
  id: hp_tx54_eeprom
  title: HP TX54 Printer M24256BW EEPROM Dump
  file-extension: dump
  endian: le

seq:
  - id: nos_region
    type: nos_nvm_region
    size: 0x200
    doc: "NOS NVM region (0x000-0x1FF): bootloader partitioned + flat fields (512 bytes)"
  - id: nvm2_region
    type: nvm2_object_storage
    doc: "NVM2 region (0x200-0x7FFF): kernel page-based object storage"

types:

  # ──────────────────────────────────────────────
  # NOS NVM Region (0x000–0x1FF)
  # Contains Tier 1 (partitioned) and Tier 2 (flat) fields.
  # ──────────────────────────────────────────────
  nos_nvm_region:
    doc: |
      NOS NVM region managed by the bootloader (512 bytes).

      Tier 1: Partitioned fields (0x000-0x0C1) — layout defined by
      type 0x40 sub-partition table at binary address 0x9FF33AA4.
      Field offsets computed by accumulating entry sizes.

      Tier 2: Flat fields (0x100-0x131) — 13 fields via flat table
      (partition_id > 0x80). First 0x136 bytes cached in RAM at boot.

      Multi-byte values are big-endian (NVM_ReadField convention).
    seq:
      # ── Tier 1: Partitioned fields ──

      - id: nvm2_control
        type: u1
        doc: |
          NVM partition control byte (0x44 = type 0x40, lower nibble 4).
          Upper nibble selects sub-partition table, lower nibble controls
          dynamic gap sizing: size = (nibble + 3) * 4 + 2 = 30 bytes.

      - id: internal_0x17
        size: 4
        doc: "Internal partition 0x17 (0x001-0x004)"

      - id: map_revision
        type: u1
        doc: "MAP_REVISION (0x005, prot1)"

      - id: power_state
        size: 2
        doc: |
          POWER_STATE (0x006-0x007, prot2: primary + mirror XOR 0xFF).
          Bit 0: power-on flag, bit 2: abnormal shutdown (triggers recovery),
          bit 4: debug mode, bit 5: boot attempted.

      - id: internal_0x18
        size: 4
        doc: "Internal partition 0x18 (0x008-0x00B)"

      - id: board_id
        size: 5
        doc: |
          BOARD_ID (0x00C-0x010, prot0: 2B primary + 2B mirror + 1B checksum).
          Primary bytes are the hardware board identifier (e.g. 0xA284).

      - id: dynamic_gap
        size: 30
        doc: |
          Dynamic gap partition 0x08 (0x011-0x02E).
          Size = (NVM2_CONTROL lower nibble + 3) * 4 + 2 = 30 for 0x44.

      - id: serial_number_field
        size: 41
        doc: |
          SERIAL_NUMBER (0x02F-0x057, prot3: 20B primary + 20B mirror + 1B checksum).
          Primary bytes contain NUL-terminated ASCII serial (e.g. 'THBTTBB0M9').

      - id: boot_flags
        size: 2
        doc: |
          BOOT_FLAGS (0x058-0x059, prot2: primary + mirror XOR 0xFF).
          Bit 0: power-on pending, bit 1: recovery mode,
          bit 2: bad updatable partition, bit 5: validated,
          bit 6: one-time recovery, bit 7: NVM initialized (factory-set).

      - id: internal_0x19
        size: 2
        doc: "Internal partition 0x19 (0x05A-0x05B)"

      - id: boot_flags3
        size: 2
        doc: |
          BOOT_FLAGS3 (0x05C-0x05D, prot2).
          Bit 7: one-time recovery clear. 0xFF/0xFF = uninitialized.

      - id: power_state2
        size: 2
        doc: |
          POWER_STATE2 (0x05E-0x05F, prot2).
          Bit 1: recovery flag, bit 2: bad updatable partition.
          0xFF/0xFF = uninitialized.

      - id: internal_0x1a
        size: 2
        doc: "Internal partition 0x1A (0x060-0x061)"

      - id: assert_seq_num
        size: 4
        doc: "ASSERT_SEQ_NUM (0x062-0x065, prot1, 4 bytes big-endian)"

      - id: psku_config
        size: 4
        doc: "PSKU_CONFIG (0x066-0x069, prot1, 4 bytes big-endian)"

      - id: eeprom_recov_count
        size: 2
        doc: "EEPROM_RECOV_COUNT (0x06A-0x06B, prot1, 2 bytes big-endian)"

      # Entry 16 (part_id=0x11, size=0) is a zero-size boundary marker at 0x06C

      - id: counter_data
        size: 70
        doc: |
          Counter_Data (0x06C-0x0B1): circular crash/panic log,
          5 slots of 14 bytes each. Records are big-endian:
          [4B crash_code][2B error_code][4B detail][4B timestamp].

      - id: counter_state
        size: 2
        doc: |
          Counter_State (0x0B2-0x0B3):
          byte[0] bits[6:0] = write index (0-4), bit[7] = bank flag.
          byte[1] = XOR checksum of all 70 Counter_Data bytes.

      - id: counter_config
        size: 14
        doc: "Counter_Config (0x0B4-0x0C1): reserved/unused (0xFF fill)"

      - id: remaining_partition_space
        size: 62
        doc: "Remaining partition space (0x0C2-0x0FF, 0xFF fill)"

      # ── Tier 2: Flat fields (0x100-0x131) ──

      - id: map2_version
        type: u2le
        doc: |
          MAP2_VERSION (0x100, LE uint16). Exception to BE convention:
          written by kernel NVM driver in LE mode (value 1 = version 1).

      - id: pca_serial_number
        size: 10
        doc: |
          PcaSerialNumber (0x102-0x10B, 10 bytes ASCII).
          PCA (Printed Circuit Assembly) serial (e.g. '25640V1A').

      - id: eth0_mac
        size: 6
        doc: |
          ETH0_MAC_ADDR (0x10C-0x111, 6 bytes network byte order).
          Primary Ethernet MAC address.

      - id: wlan0_mac
        size: 6
        doc: |
          WLAN0_MAC_ADDR (0x112-0x117, 6 bytes network byte order).
          First wireless MAC address.

      - id: wlan1_mac
        size: 6
        doc: |
          WLAN1_MAC_ADDR (0x118-0x11D, 6 bytes network byte order).
          Second wireless MAC address.

      - id: power_cycle_count_raw
        size: 2
        doc: |
          POWER_CYCLE_COUNT (0x11E-0x11F, 2 bytes big-endian).
          Monotonic power-cycle counter.

      - id: secure_vars
        type: u1
        doc: |
          SECURE_VARS (0x120, 1 byte).
          Bit 2: purpose TBD. Bit 7: SW Secure Boot override
          (HW fuse at 0x3C001048 is the primary control).

      - id: boot_flags2_raw
        size: 2
        doc: |
          BOOT_FLAGS2 (0x121-0x122, 2 bytes big-endian).
          Bit 2: updatable partition failed, bit 3: recovery mode set,
          bit 4: recovery partition failed, bit 5: recovery cleared,
          bit 8/9: UI boot mode, bit 12: factory reset requested.

      - id: misc_1
        size: 4
        doc: "MISC_1 (0x123-0x126, 4 bytes, 0xFFFFFFFF = empty)"

      - id: save_recover_id
        size: 4
        doc: "SAVE_RECOVER_ID (0x127-0x12A, 4 bytes, 0xFFFFFFFF = empty)"

      - id: mpca_bpca_pairing
        size: 2
        doc: "MPCA_BPCA_PAIRING (0x12B-0x12C, prot2: primary + mirror)"

      - id: misc_2
        size: 2
        doc: "MISC_2 (0x12D-0x12E, 2 bytes, 0xFFFF = empty)"

      - id: unknown_1c
        size: 2
        doc: "UNKNOWN_1C (0x12F-0x130, 2 bytes)"

      - id: flat_tail
        size: 1
        doc: "End of flat field region (0x131)"

      - id: flat_cache_tail
        size: 4
        doc: "Flat cache tail (0x132-0x135, end of RAM-cached region)"

      - id: unused_gap
        size: 0x1FE - 0x136
        doc: "Unused gap (0x136-0x1FD, 0xFF fill)"

      - id: root_page_ptr_raw
        size: 2
        doc: |
          Root page pointer (0x1FE-0x1FF, big-endian uint16).
          Written by kernel _write_root_page(). Observed: 0xFFFF.

  # ──────────────────────────────────────────────
  # NVM2 Object Storage Region (0x200–0x7FFF)
  # ──────────────────────────────────────────────
  nvm2_object_storage:
    doc: |
      Kernel NVM2 object storage region.  Contains a 19-byte header,
      span bitmap (page 9), allocation bitmap (page 10), and
      page-based variable-length objects from page 11 onward.
      All header integers are little-endian.
    seq:
      - id: header
        type: nvm2_header
        doc: "NVM2 header (19 bytes at offset 0x200)"
      - id: header_padding
        size: 0x240 - 0x213
        doc: "Header padding (0x213-0x23F, 0xFF fill)"
      - id: span_bitmap
        size: 64
        doc: |
          Span bitmap (page 9, 0x240-0x27F). Each bit marks a
          continuation page of a multi-page object.
      - id: alloc_bitmap
        size: 64
        doc: |
          Allocation bitmap (page 10, 0x280-0x2BF). Each bit marks
          a page that contains NVM object data.
      - id: object_pages
        size-eos: true
        doc: |
          NVM object storage area (page 11+, 0x2C0 onward).
          Objects have variable-length headers (3-5 bytes):
            B0, B1, B2, [B3, [B4]]
            Object ID (22-bit) = (B0 << 16) | ((B2 & 0x3F) << 8) | B1
            End marker: 0xFF 0xFF 0xFF
            Size encoding (B2[7:6]):
              00: 3-byte hdr, size=1; 01: 3-byte hdr, size=2
              10: 3-byte hdr, size=4; 11: extended (B3/B4)
          Objects are parsed per-page using the allocation bitmap.

  nvm2_header:
    doc: |
      NVM2 header (19 bytes at EEPROM offset 0x200).
      Written by kernel _write_root_page() and _format_nvm().
      All fields are little-endian.
    seq:
      - id: magic
        type: u4le
        doc: "NVM2 magic: 0x7EEDC0DE (LE uint32)"
      - id: version_info
        type: u4le
        doc: |
          Composite field: (key_id << 16) | version.
          key_id from device tree hp_key_id (value 1), version = 2.
          Observed: 0x00010002.
      - id: object_count
        type: u2le
        doc: "Active NVM object count (e.g. 268 old dump, 291 new dump)"
      - id: max_objects
        type: u2le
        doc: "Max object table capacity (300)"
      - id: alloc_bitmap_offset
        type: u2le
        doc: "Allocation bitmap EEPROM offset (0x0280 = page 10)"
      - id: span_bitmap_offset
        type: u2le
        doc: "Span bitmap EEPROM offset (0x0240 = page 9)"
      - id: debug_level
        type: u1
        doc: "Debug verbosity for kernel NVM driver (0xFF = disabled)"
      - id: generation_counter
        type: u2le
        doc: "Generation / recovery counter (sysfs: eeprom_recovery_count)"
