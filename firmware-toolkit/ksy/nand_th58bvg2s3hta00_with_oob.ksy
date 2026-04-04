meta:
  id: nand_th58bvg2s3hta00_with_oob
  title: Toshiba TH58BVG2S3HTA00 NAND Flash Dump (with OOB/ECC)
  file-extension: bin
  endian: le
  license: MIT

doc: |
  Kaitai Struct definition for a raw NAND flash dump from a
  Toshiba TH58BVG2S3HTA00 chip, including the Out-Of-Band (OOB)
  spare area with ECC data.

  Chip specifications:
    - Capacity: 4 Gbit (512 MB user data)
    - Page size: 2048 bytes data + 64 bytes OOB = 2112 bytes total
    - Pages per block: 64
    - Blocks: 4096
    - Total pages: 262144

  OOB layout (64 bytes):
    - Bytes 0-11:  Spare/metadata buffer (bad block markers, etc.)
    - Bytes 12-24: ECC for data chunk 0 (512 bytes @ offset 0)
    - Bytes 25-37: ECC for data chunk 1 (512 bytes @ offset 512)
    - Bytes 38-50: ECC for data chunk 2 (512 bytes @ offset 1024)
    - Bytes 51-63: ECC for data chunk 3 (512 bytes @ offset 1536)

  ECC algorithm: BCH with polynomial 0x201B (8219), correction
  capacity t=8, computed directly on raw data (no bit inversion,
  no bit swapping).

seq:
  - id: pages
    type: nand_page
    repeat: eos

types:
  nand_page:
    doc: |
      A single NAND page consisting of 2048 bytes of user data
      split into four 512-byte chunks, followed by a 64-byte OOB
      area containing spare metadata and per-chunk ECC codes.
    seq:
      - id: data_chunks
        type: data_chunk
        repeat: expr
        repeat-expr: 4
      - id: oob
        type: oob_area

  data_chunk:
    doc: A 512-byte data chunk within a NAND page.
    seq:
      - id: data
        size: 512

  oob_area:
    doc: |
      The 64-byte Out-Of-Band area appended to each NAND page.
      Contains a 12-byte spare/metadata buffer followed by four
      13-byte BCH ECC codes, one per data chunk.
    seq:
      - id: spare_buffer
        size: 12
        doc: |
          Spare metadata area. Typically contains bad block markers
          and controller-specific metadata.
      - id: ecc_chunks
        type: ecc_code
        repeat: expr
        repeat-expr: 4

  ecc_code:
    doc: |
      A 13-byte BCH ECC code for one 512-byte data chunk.
      Algorithm: BCH(8219, t=8) on raw data (no inversion, no bit swap).
    seq:
      - id: code
        size: 13
