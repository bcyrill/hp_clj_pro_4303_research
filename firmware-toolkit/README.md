# firmware-toolkit

Extensible firmware unpacking, patching and packing toolkit for the HP Color LaserJet Pro MFP 4301-4303 (TX54 platform). Provides a plugin-based architecture for working with layered firmware formats from raw NAND flash dumps down to individual filesystem files.

## Architecture

The toolkit is built around a plugin system where each firmware format is handled by an independent plugin. Plugins declare the format variants they support and the conversions between them. The CLI auto-discovers plugins, identifies input files, and routes operations to the correct plugin.

```
firmware_toolkit/
  cli.py                  Command-line interface
  core/
    base_plugin.py        FirmwarePlugin base class and data types
    plugin_manager.py     Plugin discovery and registration
    context.py            Processing chain context (.firmware-toolkit.json)
  plugins/
    <format_name>/
      __init__.py
      plugin.py           Plugin class (must be named `Plugin`)
      kaitai/             Optional Kaitai Struct parsers
        __init__.py
        <format>.py
```

Plugins auto-register by being placed under `firmware_toolkit/plugins/`. Each plugin module must export a class named `Plugin` that inherits from `FirmwarePlugin`.


## Installation

Requires Python 3.10+.

```bash
pip install -e .
```

Core dependency: `kaitaistruct>=0.10`. Optional: `bchlib>=1.0` for BCH ECC computation.

### Key configuration

The BDL and EXP plugins require cryptographic key material for encryption and decryption operations. These values are stored in `keys.conf` files alongside each plugin rather than in the Python source code, so they can be reviewed and updated independently.

Each plugin that needs key material ships with a `keys.conf` that must be populated before using encryption or decryption features:

| Plugin | Config file | Required for |
|--------|-------------|--------------|
| `hp_clj_pro_4301_bdl` | `plugins/hp_clj_pro_4301_bdl/keys.conf` | Decrypting/encrypting `.gtx1` AES-256-CBC payloads |
| `hp_clj_pro_4301_exp` | `plugins/hp_clj_pro_4301_exp/keys.conf` | Decrypting/encrypting `.exp` backup archives |

If a `keys.conf` file is missing or contains empty values, the plugin will raise an error when an operation that requires key material is attempted. Non-cryptographic operations (identification, listing, metadata extraction) continue to work without it.

See the comments inside each `keys.conf` for details on the expected values and where they originate from.

### External tools

External tools used by some plugins (see individual plugin sections for details):

| Tool | Used by | Install |
|------|---------|---------|
| `unsquashfs` / `mksquashfs` | squashfs | `apt install squashfs-tools` |
| `mkfs.ubifs` | ubifs (pack) | `apt install mtd-utils` |
| `vmlinux-to-elf` | vmlinux_to_elf | `pip install vmlinux-to-elf` |
| `pyfdt` | fdt | `pip install pyfdt` |


## CLI Reference

```
firmware-toolkit [-v] {list,identify,conversions,unpack,pack} ...
```

The `-v` flag enables verbose/debug logging.


### identify

Probe a file or directory and report which plugin and variant matches.

```bash
firmware-toolkit identify <path>
```

Each plugin's `identify()` method checks magic bytes, file sizes, or the presence of manifest files. The first match wins. Use `-f FORMAT` on `unpack`/`pack` to override.


### list

Show all loaded plugins with their versions, variants, conversions, KSY files, and registered CLI options.

```bash
firmware-toolkit list
```


### conversions

Show all available format conversions across all plugins.

```bash
firmware-toolkit conversions
```

Conversions marked `[lossy]` cannot perfectly round-trip. Conversions marked `[unavailable]` are missing an external tool dependency.


### unpack

Convert a firmware file from a packed variant to an extracted variant.

```bash
firmware-toolkit unpack <input> -o <output> [-f FORMAT] [-s SOURCE_VARIANT] [-t TARGET_VARIANT]
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output path. If it is a directory (or ends with `/`), the plugin decides the filename. If omitted, defaults to `<input>.unpacked.bin`. |
| `-f`, `--format` | Force a specific plugin by format ID instead of auto-detecting. |
| `-s`, `--source-variant` | Override the auto-detected source variant. |
| `-t`, `--target-variant` | Select a specific target variant when a plugin offers multiple. |

After unpacking, a `.firmware-toolkit.json` context file is saved alongside the output. This context tracks the processing chain so that `pack` can reverse it.


### pack

Reverse an unpack operation, converting an extracted variant back to its packed form.

```bash
firmware-toolkit pack <input> -o <output> [-f FORMAT] [-s SOURCE_VARIANT] [-t TARGET_VARIANT]
```

Plugins may register additional options. Currently available:

| Flag | Plugin | Description |
|------|--------|-------------|
| `--no-ecc` | nand_th58bvg2s3hta00 | Skip BCH ECC computation, fill OOB spare area with `0xFF`. |


## Firmware Layer Model

The HP CLJ Pro 4301 firmware is structured as a stack of nested containers. The toolkit processes each layer independently:

```
.bdl firmware bundle         (hp_clj_pro_4301_bdl)
  +-- lbi package
  |     +-- digests.txt
  |     +-- Ulbi.bin.gtx1    AES-256-CBC encrypted LBI
  +-- rootfs package
        +-- digests.txt
        +-- URootfs.bin.gtx1  AES-256-CBC encrypted UBI image

Raw NAND dump with OOB/ECC   (nand_th58bvg2s3hta00)
  +-- NAND without OOB        (nand_th58bvg2s3hta00)
       +-- mtd0  Boot         (hp_clj_pro_4301_nand / hp_clj_pro_4301_boot)
       |    +-- BL1 A copy
       |    +-- BL1 B copy
       +-- mtd1  UpdatableLBI  (hp_clj_pro_4301_lbi)
       |    +-- 0_boot_logo.bmp
       |    +-- 1_bl2.bin
       |    +-- 2_dtb.dtb      (fdt)
       |    +-- 3_kernel_zimage.bin  (vmlinux_to_elf)
       |    +-- 4_auth_block.bin
       +-- mtd2  RootFS UBI    (ubi)
       |    +-- SquashFS volume  (squashfs)
       |         +-- rootfs files
       +-- mtd3  RWFS UBI      (ubi)
       |    +-- UBIFS volume   (ubifs)
       |         +-- read-write filesystem files
       +-- mtd4  RecoveryRootFS UBI  (ubi)
       |    +-- SquashFS volume  (squashfs)
       |         +-- rootfs files
       +-- mtd5  RecoveryLBI   (hp_clj_pro_4301_lbi)

I2C EEPROM dump               (hp_clj_pro_4301_eeprom)
  +-- Zone 1: NVM identity (512 B)
  +-- Zone 2: Journaled NVM object store (31.5 KB)
```


## Processing Chain Examples

### Full NAND extraction (raw dump with OOB to rootfs files)

```bash
# Strip OOB/ECC from raw NAND dump
firmware-toolkit unpack nand_dump.bin -o nand_no_oob.bin

# Split into MTD partitions
firmware-toolkit unpack nand_no_oob.bin -o partitions/

# Extract LBI sections (boot logo, BL2, DTB, kernel, auth)
firmware-toolkit unpack partitions/mtd1_updatable_lbi.bin -o mtd1_sections/

# Decompile device tree
firmware-toolkit unpack mtd1_sections/2_dtb.dtb -o mtd1_sections/2_dtb.dts

# Convert kernel to symbolized ELF for analysis
firmware-toolkit unpack mtd1_sections/3_kernel_zimage.bin -o kernel/

# Extract UBI volumes from RootFS partition
firmware-toolkit unpack partitions/mtd2_rootfs.bin -o mtd2_ubi/

# Extract SquashFS image (mtd2 UBI volume contains SquashFS directly)
firmware-toolkit unpack mtd2_ubi/vol_0.bin -o squashfs_root/
```

### Repack after modifying boot logo

```bash
# Edit the BMP (keep within size budget — see LBI constraints below)
# ...

# Reassemble LBI from sections
firmware-toolkit pack mtd1_sections/ -o partitions/mtd1_updatable_lbi.bin

# Reassemble NAND from partitions
firmware-toolkit pack partitions/ -o nand_no_oob.bin

# Add OOB with BCH ECC
firmware-toolkit pack nand_no_oob.bin -o nand_with_ecc.bin
```

### BDL firmware bundle extraction

```bash
# Extract packages from BDL bundle
firmware-toolkit unpack firmware.bdl -o bdl_extracted/

# Repack (produces byte-identical output including HP signature)
firmware-toolkit pack bdl_extracted/ -o firmware_repacked.bdl
```


## Plugin Reference

### nand_th58bvg2s3hta00 — NAND TH58BVG2S3HTA00

Toshiba 4 Gbit (512 MB) NAND flash dump handler. Converts between raw dumps with and without OOB/ECC data.

| Property | Value |
|----------|-------|
| Format ID | `nand_th58bvg2s3hta00` |
| Version | 0.1.0 |
| Page size | 2048 bytes data + 64 bytes OOB |
| OOB layout | 12 B spare + 4 x 13 B BCH ECC |
| ECC | BCH(polynomial=8219, t=8) |
| KSY files | `nand_th58bvg2s3hta00_with_oob.ksy`, `nand_th58bvg2s3hta00_without_oob.ksy` |

**Variants:**

- `with_oob` — Raw NAND dump, 2112 bytes per page (data + OOB). File size: 553,648,128 bytes.
- `without_oob` — Data-only dump, 2048 bytes per page. File size: 536,870,912 bytes (512 MB).

**Conversions:**

| From | To | Notes |
|------|----|-------|
| `with_oob` | `without_oob` | Strips OOB. Lossy (ECC data discarded). |
| `without_oob` | `with_oob` | Computes fresh BCH ECC. Use `--no-ecc` to fill with `0xFF` instead. |

**Identification:** File size of exactly 553,648,128 bytes (262,144 pages x 2112 bytes) for `with_oob` or 536,870,912 bytes (512 MB) for `without_oob`.

---

### hp_clj_pro_4301_nand — NAND Partition Layout

Splits the 512 MB NAND image into 6 MTD partitions or reassembles them.

| Property | Value |
|----------|-------|
| Format ID | `hp_clj_pro_4301_nand` |
| Version | 0.1.0 |
| KSY files | `hp_clj_pro_4301_nand.ksy` |

**Partition map:**

| MTD | Name | Filename | Offset | Size |
|-----|------|----------|--------|------|
| mtd0 | Boot | `mtd0_boot.bin` | 0x00000000 | 256 KB |
| mtd1 | UpdatableLBI | `mtd1_updatable_lbi.bin` | 0x00040000 | 5.0 MB |
| mtd2 | RootFS | `mtd2_rootfs.bin` | 0x00540000 | 262.8 MB |
| mtd3 | RWFS | `mtd3_rwfs.bin` | 0x10C00000 | 142.4 MB |
| mtd4 | RecoveryRootFS | `mtd4_recovery_rootfs.bin` | 0x19A60000 | 97.0 MB |
| mtd5 | RecoveryLBI | `mtd5_recovery_lbi.bin` | 0x1FB60000 | 4.6 MB |

**Variants:**

- `full_nand` — Single 512 MB file. Identified by size + LBI magic at 0x00040000 + UBI magic at 0x00540000.
- `partitions` — Directory of `mtd<N>_<name>.bin` files + `nand_manifest.json`.

---

### hp_clj_pro_4301_boot — Boot Partition (A/B)

Handles the 256 KB boot partition containing two redundant copies of the BL1 first-stage bootloader.

| Property | Value |
|----------|-------|
| Format ID | `hp_clj_pro_4301_boot` |
| Version | 0.1.0 |
| BL1 size | 128 KB per copy |
| Architecture | ARM big-endian |
| KSY files | `hp_clj_pro_4301_boot.ksy` |

**Variants:**

- `boot_ab` — 256 KB file with two BL1 copies (A at offset 0, B at offset 0x20000).
- `boot_single` — Single 128 KB BL1 image.

**Identification:** 256 KB file with ARM exception vector table (8x LDR PC pattern).

---

### hp_clj_pro_4301_lbi — Loadable Boot Image

Splits an LBI partition into its component sections or reassembles them. Used for both UpdatableLBI (mtd1) and RecoveryLBI (mtd5).

| Property | Value |
|----------|-------|
| Format ID | `hp_clj_pro_4301_lbi` |
| Version | 0.1.0 |
| Header magic | `0xBAD2BFED` (big-endian) |
| KSY files | `hp_clj_pro_4301_lbi.ksy` |

**Section layout:**

| Index | Name | Extension | Content |
|-------|------|-----------|---------|
| 0 | boot_logo | `.bmp` | 480x272 24-bit BMP (boot display) |
| 1 | bl2 | `.bin` | Second-stage bootloader (ARM BE) |
| 2 | dtb | `.dtb` | Device Tree Blob |
| 3 | kernel_zimage | `.bin` | Compressed Linux kernel (ARM BE) |
| 4 | auth_block | `.bin` | HMAC-SHA1 + SHA-256 + RSA-2048 signature |

**Variants:**

- `lbi` — Packed LBI file with 20-byte header + section descriptors + data aligned to 0x800.
- `lbi_sections` — Directory of extracted section files + `lbi_manifest.json`.

**Size constraints:** The mtd1 partition is exactly 5,242,880 bytes (5 MB). Sections are packed back-to-back with alignment padding. The boot logo BMP has roughly 1 MB of headroom before sections overflow the partition.

---

### hp_clj_pro_4301_bdl — BDL Firmware Bundle

Top-level firmware update container distributed by HP. Bundles one or more packages (LBI, rootfs, datafs, eclipse), each containing files (digests.txt, encrypted payloads).

| Property | Value |
|----------|-------|
| Format ID | `hp_clj_pro_4301_bdl` |
| Version | 1.0.0 |
| Header magic | `ibdl` |
| Package magic | `ipkg` |
| Byte order | Little-endian |
| KSY files | `hp_clj_pro_4301_bdl.ksy` |

**Structure:**

```
BdlHeader (2345 bytes)
  CommonHeader (800 B): magic, version, sizes, CRCs, timestamps, strings
  Bundle-specific: type, options, description, identifier, support fields
PackageTable (16 B x N): absolute offset + size per package
Package (repeated N times):
  PakHeader (1085 B): CommonHeader + type UUID + install options + description
  FileTable (276 B x M): filename + relative offset + size + CRC-32
  File data (back-to-back)
[Trailing HP signature fingerprint]
```

**CRC scheme:** Header CRC computed with the CRC field zeroed, then written at offset 0x0C. Item table CRC at offset 0x14 covers the following table bytes. Per-file CRC-32 via `zlib.crc32`.

**Known package type UUIDs:**

| UUID (hex) | Package |
|------------|---------|
| `...9b58` | LBI |
| `...9b59` | RootFS |
| `...9b5a` | DataFS |
| `f50ecc25...9175` | Eclipse |

**Variants:**

- `bdl_bundle` — Packed BDL file. Identified by `ibdl` magic.
- `bdl_extracted` — Directory with package subdirectories + `bdl_manifest.json` + optional `trailing_signature.bin`.

**Key configuration:** Encryption and decryption of `.gtx1` payloads requires a valid `keys.conf` in the plugin directory. See [Key configuration](#key-configuration) above.

**Round-trip:** Byte-identical (including the trailing HP digital signature).

---

### hp_clj_pro_4301_eeprom — I2C EEPROM

STMicroelectronics M24256BW 32 KB I2C EEPROM dump handler.

| Property | Value |
|----------|-------|
| Format ID | `hp_clj_pro_4301_eeprom` |
| Version | 0.1.0 |
| Chip | M24256BW, 32 KB |
| KSY files | `hp_tx54_eeprom.ksy` |

**Zones:**

- Zone 1 (offset 0x000, 512 B): Raw NVM identity data.
- Zone 2 (offset 0x200, 31.5 KB): Journaled NVM object store. Magic `0xDEC0ED7E`. Variable-length TLV entries.

**Variants:**

- `eeprom` — Full 32 KB dump.
- `zones` — Directory with `zone1_identity.bin`, `zone2_journal.bin`, and `eeprom_manifest.json`.

---

### fdt — Flattened Device Tree

Decompiles DTB binary blobs to DTS source text using the `pyfdt` library.

| Property | Value |
|----------|-------|
| Format ID | `fdt` |
| Version | 0.1.0 |
| DTB magic | `0xD00DFEED` (big-endian) |
| External dep | `pyfdt` (`pip install pyfdt`) |

**Variants:**

- `dtb` — Binary Device Tree Blob.
- `dts` — Device Tree Source text.

**Conversions:** One-way only (`dtb` to `dts`). DTS to DTB compilation is handled by the `dtc` toolchain.

---

### ubi — UBI Image

Pure-Python UBI (Unsorted Block Images) parser and builder. No external tools required.

| Property | Value |
|----------|-------|
| Format ID | `ubi` |
| Version | 0.1.0 |
| EC header magic | `UBI#` |
| VID header magic | `UBI!` |

**Variants:**

- `ubi_image` — Raw UBI image (typically an MTD partition dump).
- `ubi_volumes` — Directory with extracted volume files + `ubi_manifest.json`.

The builder supports adjusting the PEB map when volume sizes change (e.g., after modifying the UBIFS filesystem inside a volume).

---

### ubifs — UBIFS Volume

Extracts files from UBIFS volume images and repacks directory trees back into UBIFS volumes.

| Property | Value |
|----------|-------|
| Format ID | `ubifs` |
| Version | 0.3.0 |
| Superblock magic | `0x06101831` |
| External dep (pack) | `mkfs.ubifs` from `mtd-utils` |

**Extraction strategies:**

1. **Index-tree walk** (preferred): Follows the UBIFS index B-tree for fast, correct extraction.
2. **Raw node scan** (fallback): Scans all LEBs for data/inode nodes. Used automatically when the index is corrupted.

**Supported compression:** LZO, ZLIB, ZSTD, none.

**Variants:**

- `ubifs_volume` — Raw UBIFS volume image.
- `ubifs_files` — Directory with extracted rootfs + `ubifs_manifest.json`.

**Pack parameters** (from manifest): `min_io_size`, `leb_size`, `leb_cnt`, `default_compr`. The `-c` (max LEB count) parameter sets a ceiling, not an allocation — UBI manages PEBs on demand, so the filesystem can grow after repacking.

---

### squashfs — SquashFS Filesystem

Extracts SquashFS images and repacks directory trees using system `squashfs-tools`.

| Property | Value |
|----------|-------|
| Format ID | `squashfs` |
| Version | 0.1.0 |
| Magic | `hsqs` (LE) or `sqsh` (BE) |
| External dep | `unsquashfs` / `mksquashfs` from `squashfs-tools` |

**Variants:**

- `squashfs_image` — Packed SquashFS image.
- `squashfs_extracted` — Directory with `squashfs-root/` tree + `squashfs_manifest.json`.

**Manifest preserves:** version, compression algorithm, block size, NFS exportability, xattrs, creation time (read directly from superblock binary at offset 8 to avoid timezone ambiguity), fragment and inode counts.

---

### vmlinux_to_elf — Kernel Image to ELF

Converts raw kernel images to fully-symbolized ELF files using the `vmlinux-to-elf` tool. Symbols are extracted from the kernel's embedded kallsyms table.

| Property | Value |
|----------|-------|
| Format ID | `vmlinux_to_elf` |
| Version | 1.0.0 |
| External dep | `vmlinux-to-elf` (`pip install vmlinux-to-elf`) |

**Supported input formats:**

- ARM zImage (magic `0x016F2818` at offset 0x24)
- ARM64 Image (magic `ARM\x64` at offset 0x38)
- Compressed vmlinux (gzip, LZ4, XZ, LZMA, zstd)
- Raw vmlinux
- ELF without symbol table

**Variants:**

- `kernel_image` — Raw kernel binary or symbol-stripped ELF.
- `vmlinux_elf` — ELF with `.symtab` section (symbols from kallsyms).

**Conversions:** One-way only (`kernel_image` to `vmlinux_elf`). The raw kernel image is preserved by the LBI plugin for repacking.

When `-o` points to a directory (or a path ending with `/`), the output filename is derived from the input with an `.elf` suffix.


## Kaitai Struct Integration

Format definitions are maintained as `.ksy` files in the `ksy/` directory:

| File | Format |
|------|--------|
| `hp_clj_pro_4301_bdl.ksy` | BDL firmware bundle |
| `hp_clj_pro_4301_boot.ksy` | Boot partition (A/B) |
| `hp_clj_pro_4301_lbi.ksy` | Loadable Boot Image |
| `hp_clj_pro_4301_nand.ksy` | NAND partition layout |
| `hp_tx54_eeprom.ksy` | EEPROM layout |
| `nand_th58bvg2s3hta00_with_oob.ksy` | NAND pages with OOB |
| `nand_th58bvg2s3hta00_without_oob.ksy` | NAND pages without OOB |

The hand-written Python parsers (compiled from the KSY definitions) live under each plugin's `kaitai/` subdirectory and are accessible via the plugin's `parse()` method:

```python
from firmware_toolkit.core import PluginManager

mgr = PluginManager()
mgr.discover()

plugin = mgr.get_plugin("hp_clj_pro_4301_lbi")
parsed = plugin.parse(Path("mtd1_updatable_lbi.bin"))
print(parsed.header.magic)
print(parsed.header.num_sections)
```


## Plugin Development

To add a new format, create a package under `firmware_toolkit/plugins/<format_name>/` with a `plugin.py` that exports a `Plugin` class:

```python
from firmware_toolkit.core.base_plugin import (
    ConversionInfo, FirmwarePlugin, PackResult,
    PluginInfo, UnpackResult, file_sha256,
)

class Plugin(FirmwarePlugin):
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="My Format",
            description="...",
            version="0.1.0",
            format_id="my_format",
            supported_variants=["packed", "extracted"],
            conversions=self.get_conversions(),
        )

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant="packed",
                target_variant="extracted",
                description="Extract ...",
            ),
        ]

    def identify(self, path: Path) -> str | None:
        # Check magic bytes, file size, manifest presence, etc.
        ...

    def unpack(self, input_path, output_path, source_variant=None,
               target_variant=None, **kwargs) -> UnpackResult:
        ...

    def pack(self, input_path, output_path, source_variant=None,
             target_variant=None, **kwargs) -> PackResult:
        ...
```

Plugins can optionally register CLI options via `get_options()` returning a list of `PluginOption` instances, and provide Kaitai Struct parsing via `parse()`.


## Processing Context

After each `unpack` operation, the CLI saves a `.firmware-toolkit.json` file alongside the output. This JSON file records the processing chain (format ID, variants, file hashes, metadata) so that subsequent `pack` operations can automatically select the correct plugin and parameters.

This enables a workflow where you can `unpack` through multiple layers, modify files in the innermost layer, and then `pack` back up through each layer without manually specifying format flags.
