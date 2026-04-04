meta:
  id: hp_clj_pro_4301_boot
  title: HP CLJ Pro 4301-4303 Boot Partition (A/B Layout)
  file-extension: bin
  endian: be
  license: MIT

doc: |
  Boot partition (mtd0) layout for the HP Color LaserJet Pro
  MFP 4301-4303 (HP TX54 platform).

  The 256 KB boot partition contains two identical 128 KB copies
  of the first-stage bootloader (BL1), arranged as an A/B
  redundancy scheme.  The SoC reads copy A first; if it fails
  integrity checks, it falls back to copy B.

  Each copy begins with an ARM big-endian exception vector table
  (8 × LDR PC instructions at 0x18F09FE5).

  Total size: 256 KB (262,144 bytes)
  Copy size:  128 KB (131,072 bytes) each

seq:
  - id: copy_a
    size: 0x20000
    doc: |
      Primary bootloader copy (A).  128 KB.
      Starts with ARM big-endian exception vector table.

  - id: copy_b
    size: 0x20000
    doc: |
      Redundant bootloader copy (B).  128 KB.
      Identical to copy A under normal conditions.
