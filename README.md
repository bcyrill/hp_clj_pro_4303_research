# HP Color LaserJet Pro MFP 4303 Security Research

Security research and reverse engineering of the HP Color LaserJet Pro MFP 4301-4303 series (HP Dune/Selene platform, TX54 SoC). This repository contains firmware analysis tooling, Ghidra extensions, and standalone scripts developed during the research.

## Target Hardware

- **Printer series:** HP Color LaserJet Pro MFP 4301 / 4302 / 4303
- **Platform codename:** Dune / Selene
- **SoC:** HP TX54 (ARMv7-A, ARM BE8 byte-invariant big-endian)
- **NAND flash:** Toshiba TH58BVG2S3HTA00 (4 Gbit)
- **Firmware versions analyzed:** 6.17.5.40-202503181735 and 6.28.1.35-202511201716

## Repository Structure

### `firmware-toolkit/`

Extensible Python toolkit for unpacking, patching, and repacking firmware images. Built around a plugin architecture where each firmware format layer (raw NAND, UBI/UBIFS, SquashFS, BDL bundles, LBI containers, EEPROM, boot images) is handled by an independent plugin. Includes Kaitai Struct format definitions under `ksy/`.

```
pip install -e ./firmware-toolkit
firmware-toolkit identify <file>
firmware-toolkit unpack <file> -o <output_dir>
firmware-toolkit pack <dir> -o <output_file>
```

Requires Python 3.10+. The BDL and EXP plugins use `keys.conf` files for cryptographic key material (AES key-derivation constants, salts, IVs). These files ship with empty values and must be populated before any encryption or decryption operations will work. See [`firmware-toolkit/README.md`](firmware-toolkit/README.md) for full CLI reference, plugin documentation, and key configuration details.

### `ghidra_loader/`

Ghidra extension (`HPDuneSeleneLoader`) for loading first-stage and second-stage bootloader binaries with correct ARM BE8 settings, load addresses, entry points, and a DTS-derived peripheral memory map. Also includes Ghidra scripts for applying the full memory map and importing/exporting function databases from Binary Ninja.

- **Pre-built extension:** `HPDuneSeleneLoader/dist/ghidra_12.0.4_PUBLIC_20260313_HPDuneSeleneLoader.zip`
- **Ghidra scripts:** `HPDuneSeleneLoader/ghidra_scripts/`

### `010_editor_templates/`

Binary templates for [010 Editor](https://www.sweetscape.com/010editor/) to parse firmware formats at the hex level:

- `HP_Dune_Selene_BDL_Firmware.bt` — BDL firmware update bundle
- `HP_Dune_Selene_EEPROM.bt` — EEPROM layout
- `HP_Dune_Selene_LBI.bt` — LBI bootloader container (data-only, OOB stripped)
- `HP_Dune_Selene_ULBI.bt` — Updatable LBI with NAND OOB/ECC interleaved (as packaged inside BDL bundles)

### `python_scripts/`

Standalone Python scripts for specific research tasks:

| File | Purpose |
|------|---------|
| `verify_and_extract_bdl.py` | Verify and extract BDL firmware bundles (header CRCs, HP CSS RSA signature, optional .gtx1 AES-256-CBC decryption) |
| `verify_nand_dump.py` | Verify the Secure Boot chain of a raw NAND dump (RSA-2048 signature verification of LBI and RootFS partitions) |
| `rsa_key_table.json` | BL1 Secure Boot RSA-2048 public keys extracted from the bootloader key table — used by `verify_nand_dump.py` for partition signature verification |
| `bdl_keys.conf` | AES-256 key-derivation constants for BDL .gtx1 decryption — must be populated before using `verify_and_extract_bdl.py --decrypt` |

## Accuracy Notice

This security research was conducted with the assistance of [Claude](https://claude.ai) (Anthropic). The documentation, reverse engineering analysis, and associated tooling may contain inaccuracies and errors. Findings should be independently verified before being relied upon.

## Disclaimer

This research is published for educational and defensive security purposes. The tools and documentation are intended to help security researchers, firmware developers, and IT administrators understand the security architecture of the HP Color LaserJet Pro MFP 4301-4303 platform. Use responsibly and in accordance with applicable laws.
