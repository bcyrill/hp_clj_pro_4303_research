meta:
  id: hp_clj_pro_4301_nand
  title: HP Color LaserJet Pro MFP 4301-4303 NAND Partition Layout
  file-extension: bin
  endian: be
  license: MIT

doc: |
  Partition layout for the HP Color LaserJet Pro MFP 4301-4303
  (HP TX54 platform) NAND flash, as defined by the device tree
  node `flash@38008000`.

  This structure describes the logical partition map applied to
  the raw 512 MB NAND user data (without OOB/ECC).  The same
  TH58BVG2S3HTA00 NAND chip may be used by other devices with
  different partition layouts.

  SoC:  ARM Cortex-A7 (dual-core), custom HP ASIC
  ISA:  Big-endian ARM32
  NAND: 512 MB (TH58BVG2S3HTA00, 4 Gbit)

  Partition map (6 MTD partitions):
    mtd0  Boot            0x00000000  256 KB      RO
    mtd1  UpdatableLBI    0x00040000  5 MB        RO
    mtd2  RootFS          0x00540000  ~263 MB     RO
    mtd3  RWFS            0x10C00000  ~142 MB     RW
    mtd4  RecoveryRootFS  0x19A60000  ~97 MB      RO
    mtd5  RecoveryLBI     0x1FB60000  ~4.6 MB     RO

seq:
  - id: mtd0_boot
    size: 0x40000
    doc: |
      Boot partition (mtd0). 256 KB, read-only.
      Contains the first-stage bootloader (ARM exception vector
      table at offset 0, branch instructions 0x18F09FE5).

  - id: mtd1_updatable_lbi
    size: 0x500000
    doc: |
      UpdatableLBI partition (mtd1). 5 MB, read-only.
      Loadable Boot Image containing: boot logo BMP,
      second-stage bootloader (BL2), device tree blob,
      kernel zImage, and authentication block.
      Magic: 0xBAD2BFED (big-endian).

  - id: mtd2_rootfs
    size: 0x106c0000
    doc: |
      RootFS partition (mtd2). ~263 MB, read-only.
      UBI volume containing the main root filesystem.
      Magic: 0x55424923 ("UBI#").

  - id: mtd3_rwfs
    size: 0x8e60000
    doc: |
      RWFS partition (mtd3). ~142 MB, read-write.
      UBI volume containing the read-write filesystem
      for persistent device configuration and data.
      Magic: 0x55424923 ("UBI#").

  - id: mtd4_recovery_rootfs
    size: 0x6100000
    doc: |
      RecoveryRootFS partition (mtd4). ~97 MB, read-only.
      UBI volume containing the recovery root filesystem.
      Magic: 0x55424923 ("UBI#").

  - id: mtd5_recovery_lbi
    size: 0x4a0000
    doc: |
      RecoveryLBI partition (mtd5). ~4.6 MB, read-only.
      Recovery Loadable Boot Image, structurally identical
      to mtd1 (same magic 0xBAD2BFED, same RSA public key).
