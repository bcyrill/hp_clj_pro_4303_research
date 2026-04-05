# Manual Key Extraction from HP CLJ Pro 4301-4303 NAND Dumps

This document describes how to manually locate and extract the cryptographic key material needed by the firmware-toolkit BDL and EXP plugins from a raw NAND flash dump.

No prior knowledge of any key values is assumed.  Every step is derived from code analysis — following function call chains, cross-references, and data-flow in the binaries.

---

## Prerequisites

| Tool | Purpose |
|---|---|
| Ghidra (with ARM/Thumb support) | Disassembly and decompilation of ARM binaries |
| `ubi_reader` (Python) | Extract UBI volume images from raw NAND partitions |
| `unsquashfs` (squashfs-tools) | Extract files from SquashFS filesystem images |
| Hex editor | Inspect raw binary data |

---

## Part 1 — NAND Dump Preparation

The NAND chip is a Toshiba TH58BVG2S3HTA00 (4 Gbit). Dumps may include per-page OOB (Out-Of-Band) data containing BCH ECC.

If the dump is 553,648,128 bytes (262,144 pages × 2,112 bytes), it includes OOB.  Strip it by extracting only the first 2,048 bytes of each 2,112-byte page to produce a 536,870,912-byte image.

The NAND is partitioned into six MTD regions.  The two relevant to key extraction are:

| Partition | Offset | Size | Contents |
|---|---|---|---|
| mtd1 — UpdatableLBI | 0x00040000 | 0x00500000 | Loadable Boot Image (BL1 → BL2 → kernel) |
| mtd2 — RootFS | 0x00540000 | 0x106C0000 | UBI container holding the SquashFS root filesystem |

---

## Part 2 — BDL Keys: `platform_prefix` and `platform_uuid`

These two strings are inputs to a SHA-256 computation inside the TrustZone second-stage bootloader (BL2).  The goal is to find that SHA-256 call and read the values it hashes.

### Step 2.1 — Extract the BL2 binary from the LBI partition

Read the LBI partition (mtd1) from the NAND image starting at offset 0x00040000.

The LBI container uses a big-endian header:

```
Offset  Size  Field
0x00    4     Magic: 0xBAD2BFED
0x04    4     Version
0x08    4     Header size (total header + descriptors)
0x0C    4     Number of section descriptors
0x10    4     data_start (offset of first section's data; also alignment)
```

Immediately after the 20-byte base header, there are N section descriptors of 24 bytes each:

```
Offset  Size  Field
0x00    4     role_flags
0x04    4     load_address
0x08    4     size
0x0C    4     image_type
0x10    4     entry_point
0x14    4     reserved
```

The BL2 section is identified by `role_flags & 0x0080` (the ENTRY flag).  It will also have a non-zero `entry_point`.

Section data begins at the `data_start` offset.  Sections are stored sequentially, each aligned to `data_start` boundaries.  Walk the descriptors, accumulating offsets, until you reach the BL2 section.  Note both the data and the `load_address` — you will need it to resolve virtual addresses.

Extract the BL2 data into a standalone file and record its `load_address` (e.g. `0x9FF10680` in firmware 6.28).

### Step 2.2 — Load BL2 into Ghidra

Create a new Ghidra project and import the extracted BL2 binary.  Configure:

- **Processor:** ARM / v7 / 32-bit
- **Endianness:** little-endian for instructions (the BL2 is **BE8** — big-endian data, little-endian instructions; Thumb2 opcodes are stored little-endian, but multi-byte data values in memory are big-endian)
- **Base address:** the `load_address` from the LBI section descriptor

Because of BE8, Ghidra's ARM/little-endian mode will correctly decode all instructions.  However, be aware that multi-byte data constants embedded in the binary (integers, pointers in data tables) are stored **big-endian**.  String bytes are unaffected since they are single-byte ASCII.  When reading 16-bit or 32-bit values from data sections in a hex editor, interpret them as big-endian.

The BL2 executes in TrustZone, which applies an additional virtual-address mapping.  In the firmware studied so far, addresses in the `0x9FFx_xxxx` range are remapped to `0xDFFx_xxxx` at runtime (+0x40000000).  Ghidra may display either form depending on how the binary is loaded.

Run auto-analysis.  Because the binary is stripped (no symbol table), Ghidra will not label functions automatically — you will need to navigate by cross-references.

### Step 2.3 — Locate the SHA-256 implementation

Search the BL2 **data** for the SHA-256 initial hash values H0 and H1.  Because the BL2 is BE8, multi-byte data values are stored **big-endian**.  Search for the 8-byte sequence:

```
6A 09 E6 67 BB 67 AE 85
```

This is H0 (`0x6A09E667`) followed by H1 (`0xBB67AE85`).  The remaining six words (H2–H7) will follow immediately.

Alternatively, search for the first four round constants (K table): `0x428A2F98`, `0x71374491`, `0xB5C0BF6F`, `0xE9B5DBA5` — each stored big-endian.

Once you find the H0 data, identify the code that references it.  In the Thumb2 disassembly, look for a `MOVW` / `MOVT` pair that loads the address of this data (accounting for the TrustZone +0x40000000 VA mapping).  This MOVW/MOVT pair is inside **SHA256_Init**.

> **Important:** SHA256_Init is typically a **leaf function** (it does not call other functions).  Its prologue may be just `PUSH {r5}` — without LR — so scanning backward for `PUSH {…, LR}` to find the function start **will miss it**.  Instead, determine the entry point by checking which address other functions branch to:  scan the BL2 for Thumb2 `BL` (Branch with Link) instructions, and find the most common BL target in the few bytes *before* the H0 MOVW instruction.  That target address is SHA256_Init's entry point.

From SHA256_Init, identify the related functions by looking at its callers' code:

- **SHA256_Update** — feeds data into the hash.  Takes three arguments: `(ctx, data_ptr, length)`.
- **SHA256_Final** — finalises the hash and writes the 32-byte digest.

Label these functions in Ghidra.

### Step 2.4 — Find Security_ComputeDeviceHash

Look at the callers of SHA256_Init.  For each caller, determine the function boundaries (scan forward from the `PUSH {…, LR}` prologue to the *next* `PUSH {…, LR}` to avoid premature termination at conditional early-return `POP {PC}` instructions).  Within each caller's function body, count how many times each BL target is called (excluding SHA256_Init itself).  You are looking for the caller that has another target called exactly **three times** — that target is SHA256_Update, and the caller is Security_ComputeDeviceHash.

The call pattern is:

```
SHA256_Init(ctx)
len = Strlen(ptr_A)
SHA256_Update(ctx, ptr_A, len)       ← first input: length from Strlen
SHA256_Update(ctx, ptr_B, 0x24)      ← second input: fixed length 0x24 (36)
SHA256_Update(ctx, ptr_C, 0x20)      ← third input: fixed length 0x20 (32)
SHA256_Final(ctx, output)
```

The three SHA256_Update calls hash three distinct inputs.  The third (0x20 = 32 bytes) is a hex-decoded digest supplied at runtime; it is not a static key.  The first two are the values you need.

In the Thumb2 disassembly, the function loads two 32-bit data addresses using `MOVW` / `MOVT` instruction pairs (each pair sets the low and high 16 bits of a register).  Decode these to obtain the runtime virtual addresses.

### Step 2.5 — Read the key strings

Within Security_ComputeDeviceHash, find all `MOVW` / `MOVT` instruction pairs.  Resolve each to a binary offset:

```
file_offset = (runtime_VA - 0x40000000) - load_address
```

If the addresses are already in the `0x9FFx_xxxx` range (depending on how Ghidra loaded the file), subtract only `load_address`.

Read the null-terminated ASCII string at each resolved offset.  You should find exactly two printable strings (other MOVW/MOVT pairs will point to code addresses, non-string data, or stack-relative values — discard those).

**Distinguishing the two strings:**  Scan backward from each of the three SHA256_Update `BL` call sites for a `MOVS R2, #imm8` instruction (which sets the length argument).  You will find:

- One call preceded by `MOVS R2, #0x20` — the 32-byte digest (runtime data, not a key).
- One call preceded by `MOVS R2, #0x24` — the string passed with fixed length 36 is the **platform_uuid**.
- One call with no fixed-immediate length (its length comes from Strlen's return value) — that string is the **platform_prefix**.

Alternatively, the string whose length equals the non-0x20 immediate (0x24 = 36) is the `platform_uuid`; the other is the `platform_prefix`.

Record both values.  These are the `platform_prefix` and `platform_uuid` fields for the BDL plugin's `keys.conf`.

> **Automated alternative:** The `FindBdlKeys.java` Ghidra script automates this entire procedure (Steps 2.3–2.5).  Run it in Ghidra after loading the BL2 binary as ARM:LEBE:32:v7LEInstruction with auto-analysis.  The script does not rely on function names — it locates SHA256_Init via the H0 constants, then identifies Security_ComputeDeviceHash by its 3× SHA256_Update call pattern, and reads the key strings directly from memory.

### Step 2.6 — Verification

The BDL key derivation formula is:

```
AES_key = SHA-256(platform_prefix || platform_uuid || HexDecode(digest_hex))
```

where `digest_hex` comes from the `digests.txt` file inside each BDL package.  You can verify your extracted values by decrypting a known `.gtx1` file from a BDL update.

---

## Part 3 — EXP Keys: `firmware_salt`, `outer_iv`, and `default_family`

These values are used by the export/import encryption in `lib01f1dd40.so`, the main userspace shared library.  They reside inside the SquashFS root filesystem on the mtd2 partition.

### Step 3.1 — Extract the root filesystem

Read mtd2 (offset 0x00540000, size 0x106C0000) from the NAND image.

The partition contains a UBI (Unsorted Block Images) container.  Extract the UBI volume images:

```
ubireader_extract_images -o ubi_out mtd2_rootfs.bin
```

Among the extracted volumes, locate the SquashFS image (it will begin with the magic `hsqs`).  Extract it:

```
unsquashfs -d rootfs squashfs_volume.ubifs
```

You now have a full copy of the printer's root filesystem.

### Step 3.2 — Load lib01f1dd40.so into Ghidra

The main shared library is at `core/lib/lib01f1dd40.so` inside the extracted rootfs.  This is a large (≈40 MB) 32-bit ARM ELF shared object.  Import it into Ghidra as ARM / v7 / little-endian and run auto-analysis.

The binary is stripped, but because it is a proper ELF with section headers, Ghidra can identify most function boundaries automatically.  The `.dynsym` table provides names for imported functions (e.g. OpenSSL's `EVP_DecryptInit`, `EVP_CIPHER_CTX_new`, `BIO_new`, the `dune::framework::core::md5::MD5` class, etc.).

### Step 3.3 — Find the outer-layer key derivation (firmware_salt)

The export encryption uses MD5-based key derivation.  The most reliable entry point is the `raw_digest` method of the `dune::framework::core::md5::MD5` class.  Find all code-section functions named `raw_digest` (skip EXTERNAL-block stubs), then find their callers — the callers with size > 100 bytes are the key derivation functions.

> **Automated alternative:** The `FindExpKeys.java` Ghidra script automates this entire procedure (Parts 3.3 and 3.4).  Run it in Ghidra after loading `lib01f1dd40.so` with auto-analysis.

You are looking for a function that performs:

```
MD5_Init(ctx)
MD5_Update(ctx, password, password_len)
MD5_Update(ctx, salt, salt_len)
MD5_Finalize(ctx)
digest = MD5_raw_digest(ctx)     ← 16 bytes
key = digest || digest           ← 32 bytes (duplicated)
```

This function derives the outer AES-256 key.  It has **three distinct code paths** for three types of encryption operations, all within the same function body.  Each path computes a different salt:

1. **Backup path** (param_3 == 0): retrieves 32 bytes from a TrustZone keystore service.
2. **Export with family string** (param_6 is non-NULL): computes `MD5hex(family_string)` and uses that as the salt.
3. **Export without family string** (fallback): loads a fixed salt string from the binary's read-only data.

Path 3 is where the `firmware_salt` is loaded.  In the decompiled code, this path creates a 16-byte (0x10) `std::string` and populates it from a data address.  The code looks like:

```c
local_size = 0x10;
buffer = string::_M_create(&local, &local_size);
*buffer       = *(int*)(DATA_ADDR + 0);
*(buffer + 1) = *(int*)(DATA_ADDR + 4);
*(buffer + 2) = *(int*)(DATA_ADDR + 8);
*(buffer + 3) = *(int*)(DATA_ADDR + 12);
```

The `DATA_ADDR` is loaded via a GOT-relative reference.  Follow it to find the 16-byte null-terminated string in `.rodata`.  This is the `firmware_salt`.

### Step 3.4 — Find the outer IV

Alternatively, find all code-section functions named `EVP_EncryptInit` (not EXTERNAL stubs).  Find their callers with body size ≥ 100 bytes — these are the encryption functions.  Among each encryption function's callees, look for the sequential IV fill described below.

The encryption function:

1. Calls a vtable method to determine the cipher type and IV size (resolves to AES-256-CBC).
2. Allocates a buffer of IV-size bytes.
3. Calls a function to **fill the IV buffer** (sequential fill for outer layer, or base64 decode for per-file inner layer).
4. Calls `EVP_EncryptInit(ctx, cipher, key, iv_buffer)`.

> **Note:** The export path uses `EVP_EncryptInit` (not `EVP_DecryptInit`).  The corresponding decrypt path exists separately.  Either can be used as an entry point, but `EVP_EncryptInit` is more direct for the export feature.

The IV-filling function is a short subroutine that receives the buffer pointer and the desired size.  When decompiled, it reduces to:

```c
void fill_iv(object *self, vector *buffer, uint size) {
    resize_buffer(buffer, size);
    if (size != 0) {
        i = 0;
        do {
            value = i + START_VALUE;
            buffer[i] = (byte) value;
            i = value;
        } while (size != value);
    }
}
```

This is a simple loop: `buffer[i] = i + START_VALUE` for i from 0 to size−1.

Read the `START_VALUE` from the disassembly.  It is the immediate operand of the Thumb `ADDS Rd, Rn, #imm` instruction inside the loop.  Combined with the buffer size (determined by the cipher — 16 bytes for AES-CBC), the IV is:

```
outer_iv = [START_VALUE, START_VALUE+1, START_VALUE+2, ..., START_VALUE+15]
```

Record the IV as a comma-separated list of decimal byte values.

To find this function without knowing its address: in the encryption function, look at the callees.  Two sub-functions handle IV generation depending on the operation type: one fills the IV sequentially (for the outer layer), and the other decodes a base64-encoded IV (for per-file inner encryption).  You want the sequential one — it is the simpler of the two and does not reference `BIO_f_base64`.

### Step 3.5 — Find the default family string

The inner-layer key derivation (Path 2 in Step 3.3) uses `MD5hex(family_string)` as its salt.  The family string is not embedded in `lib01f1dd40.so` — it is read from a product configuration CSV file at runtime.

In the extracted rootfs, look for CSV files under the product resources directory:

```
core/product/resources/*/derivatives/default.csv
```

Open the CSV.  It contains printer model metadata.  Look for a row where the second column (field name) is `ModelFamily`.  The fourth column of that row contains the family string.

This is the `default_family` value.

### Step 3.6 — Verification

The outer-layer encryption is AES-256-CBC:

```
half = MD5(password + firmware_salt)
key  = half || half                       (32 bytes)
iv   = outer_iv                           (16 bytes)
plaintext = AES-256-CBC-decrypt(ciphertext, key, iv)
```

The decrypted plaintext should begin with `\x1f\x8b` (gzip magic).

The inner-layer encryption for individual files is:

```
salt_hex = MD5hex(default_family)
half     = MD5(password + salt_hex)
key      = half || half                   (32 bytes)
iv       = base64decode(encryptIV)[:16]   (per-file, from index.json)
plaintext = AES-256-CBC-decrypt(ciphertext, key, iv)
```

---

## Part 4 — Summary of extracted values

After completing the procedure above, you will have:

| Key | Source | Used by |
|---|---|---|
| `platform_prefix` | BL2 TrustZone binary, first SHA256_Update input | BDL plugin |
| `platform_uuid` | BL2 TrustZone binary, second SHA256_Update input (0x24 bytes) | BDL plugin |
| `firmware_salt` | lib01f1dd40.so `.rodata`, loaded by fallback key derivation path | EXP plugin |
| `outer_iv` | lib01f1dd40.so `.text`, generated by sequential-fill function | EXP plugin |
| `default_family` | `default.csv` in rootfs product resources | EXP plugin |

Place these values in the respective `keys.conf` files for the firmware-toolkit plugins.
