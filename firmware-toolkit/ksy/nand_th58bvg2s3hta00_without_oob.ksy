meta:
  id: nand_th58bvg2s3hta00_without_oob
  title: Toshiba TH58BVG2S3HTA00 NAND Flash Dump (without OOB/ECC)
  file-extension: bin
  endian: le
  license: MIT

doc: |
  Kaitai Struct definition for a raw NAND flash dump from a
  Toshiba TH58BVG2S3HTA00 chip with the OOB/ECC area stripped.

  This format contains only the user data pages without any
  spare area or ECC codes.

  Chip specifications:
    - Capacity: 4 Gbit (512 MB user data)
    - Page size: 2048 bytes (data only)
    - Pages per block: 64
    - Blocks: 4096
    - Total pages: 262144

seq:
  - id: pages
    type: nand_page
    repeat: eos

types:
  nand_page:
    doc: A single NAND page containing 2048 bytes of user data.
    seq:
      - id: data
        size: 2048
