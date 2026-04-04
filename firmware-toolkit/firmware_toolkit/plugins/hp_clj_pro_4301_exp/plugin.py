"""Firmware layer plugin for HP CLJ Pro 4301-4303 Export files (.exp).

Export files are encrypted archives used by the HP Color LaserJet Pro MFP
4301-4303 (and related models) for backup/restore of printer settings.

File format
-----------
The .exp file is an AES-256-CBC encrypted blob.  Decrypted, it contains
a gzip-compressed TAR archive holding:

  index.json        Manifest listing every content section and file entry.
  index.json.sig    Encrypted MD5 signature of index.json (integrity check).
  <section_id>/<file_path>  Content files (JSON or binary blobs).

Encryption architecture (lib01f1dd40.so_6.28)
----------------------------------------------
Outer layer (the whole .exp file):
    AES-256-CBC, fixed IV = 0x01..0x10.
    Key = MD5(password + FIRMWARE_SALT) doubled to 32 bytes.
    FIRMWARE_SALT = b"" (rodata 0x02237114).

Inner blobs (10 files marked ``encrypted: true`` in index.json):
    AES-256-CBC, per-file IV from base64 ``encryptIV`` field.
    Key = MD5(password + MD5hex(family_string)) doubled to 32 bytes.
    

index.json.sig:
    Same key as inner blobs.
    Format: base64(ciphertext) + "\\n\\n" + base64(32-byte IV buffer) + "\\n\\n".
    Plaintext = 32-char MD5 hex of index.json.

TAR layout:
    Member paths are prefixed with "./" by the firmware.
    Content files: ./<section_id>/<file_path>
    Metadata:      ./index.json, ./index.json.sig
"""

from __future__ import annotations

import base64
import configparser
import gzip
import hashlib
import io
import json
import logging
import os
import tarfile
from pathlib import Path
from typing import Any

from firmware_toolkit.core.base_plugin import (
    ConversionInfo,
    FirmwarePlugin,
    PackResult,
    PluginInfo,
    PluginOption,
    UnpackResult,
    file_sha256,
)

logger = logging.getLogger(__name__)


# ── Lazy pycryptodome import ─────────────────────────────────────────

def _crypto():
    """Return (AES, pad, unpad) from pycryptodome, raising if missing."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        return AES, pad, unpad
    except ImportError:
        raise RuntimeError(
            "pycryptodome is required for export file operations. "
            "Install it with: pip install pycryptodome"
        )


# ── Constants ────────────────────────────────────────────────────────

_KEYS_CONF = Path(__file__).with_name("keys.conf")

MANIFEST_NAME = "exp_manifest.json"

# Variant identifiers
VARIANT_EXP = "exp"
VARIANT_EXP_CONTENTS = "exp_contents"

# Cached key material — populated lazily by _get_key_material().
_key_material: tuple[bytes, str, bytes] | None = None


def _get_key_material() -> tuple[bytes, str, bytes]:
    """Return (FIRMWARE_SALT, DEFAULT_FAMILY, OUTER_IV), loading on first call.

    Raises a clear error when the config file is missing or values are empty,
    but only at the point where key material is actually needed (i.e.
    encryption / decryption), so that other EXP operations keep working.
    """
    global _key_material
    if _key_material is not None:
        return _key_material

    cfg_path = _KEYS_CONF
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Key configuration not found: {cfg_path}\n"
            "Encryption/decryption requires a keys.conf file next to the "
            "EXP plugin.\nSee keys.conf.example or supply your own."
        )

    cfg = configparser.ConfigParser()
    cfg.read(cfg_path, encoding="utf-8")

    try:
        salt_str = cfg.get("encryption", "firmware_salt")
        family = cfg.get("encryption", "default_family")
        iv_str = cfg.get("encryption", "outer_iv")
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        raise ValueError(
            f"keys.conf is missing required encryption entries: {exc}\n"
            "All of 'firmware_salt', 'default_family', and 'outer_iv' must "
            "be set in the [encryption] section."
        ) from exc

    if not salt_str.strip():
        raise ValueError(
            "keys.conf: 'firmware_salt' in [encryption] is empty. "
            "A non-empty value is required for AES key derivation."
        )
    if not family.strip():
        raise ValueError(
            "keys.conf: 'default_family' in [encryption] is empty. "
            "A non-empty value is required for inner-blob key derivation."
        )
    if not iv_str.strip():
        raise ValueError(
            "keys.conf: 'outer_iv' in [encryption] is empty. "
            "A non-empty value is required for outer-layer decryption."
        )

    firmware_salt = salt_str.strip().encode()
    default_family = family.strip()
    outer_iv = bytes(int(b.strip()) for b in iv_str.split(","))

    _key_material = (firmware_salt, default_family, outer_iv)
    return _key_material


# ── Key derivation ───────────────────────────────────────────────────

def _derive_outer_key(password: str | bytes) -> bytes:
    """Derive 32-byte AES-256 key for the outer .exp layer.

    Algorithm (FUN_0066c7f4, Path 2):
      half = MD5(password + FIRMWARE_SALT)  →  16 bytes
      key  = half + half                     →  32 bytes

    Raises:
        FileNotFoundError: If keys.conf is missing.
        ValueError: If key values are empty or malformed.
    """
    firmware_salt, _, _ = _get_key_material()
    pwd = password.encode() if isinstance(password, str) else password
    half = hashlib.md5(pwd + firmware_salt).digest()
    return half + half


def _derive_inner_key(password: str | bytes,
                      family: str | None = None) -> bytes:
    """Derive 32-byte AES-256 key for inner blobs and index.json.sig.

    Algorithm (FUN_0066c7f4, Path 3):
      salt_hex = MD5hex(family)              →  32 ASCII bytes
      half     = MD5(password + salt_hex)    →  16 bytes
      key      = half + half                  →  32 bytes

    Raises:
        FileNotFoundError: If keys.conf is missing.
        ValueError: If key values are empty or malformed.
    """
    _, default_family, _ = _get_key_material()
    if family is None:
        family = default_family
    pwd = password.encode() if isinstance(password, str) else password
    fam = family.encode() if isinstance(family, str) else family
    salt_hex = hashlib.md5(fam).hexdigest().encode("ascii")
    half = hashlib.md5(pwd + salt_hex).digest()
    return half + half


# ── AES-256-CBC helpers ──────────────────────────────────────────────

def _aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    """AES-256-CBC decrypt with PKCS#7 unpadding.  Returns None on error."""
    if len(key) != 32 or len(iv) != 16 or len(ciphertext) % 16 != 0:
        return None
    AES, _pad, unpad = _crypto()
    try:
        raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        return unpad(raw, 16)
    except Exception:
        return None


def _aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt with PKCS#7 padding."""
    AES, pad, _unpad = _crypto()
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))


# ── Outer layer ──────────────────────────────────────────────────────

def _decrypt_outer(data: bytes, key: bytes) -> bytes | None:
    """Decrypt outer AES-256-CBC layer → gzip-compressed TAR, or None."""
    _, _, outer_iv = _get_key_material()
    plain = _aes_decrypt(data, key, outer_iv)
    if plain is None or plain[:2] != b"\x1f\x8b":
        return None
    return plain


def _encrypt_outer(gzip_data: bytes, key: bytes) -> bytes:
    """Encrypt gzip-compressed TAR with outer AES-256-CBC."""
    _, _, outer_iv = _get_key_material()
    return _aes_encrypt(gzip_data, key, outer_iv)


# ── Inner blobs ──────────────────────────────────────────────────────

def _decrypt_inner(enc_data: bytes, encrypt_iv_b64: str,
                   key: bytes) -> bytes | None:
    """Decrypt a per-file inner blob using its base64-encoded IV field."""
    iv_buf = base64.b64decode(encrypt_iv_b64.strip())
    return _aes_decrypt(enc_data, key, iv_buf[:16])


def _encrypt_inner(plaintext: bytes, key: bytes,
                   iv_buf_b64: str | None = None) -> tuple[bytes, str]:
    """Encrypt a plaintext blob.  Returns (ciphertext, encryptIV_b64).

    If *iv_buf_b64* is provided, reuse that IV buffer for a
    deterministic round-trip.  Otherwise generate a fresh random IV.
    """
    if iv_buf_b64:
        iv_buf = base64.b64decode(iv_buf_b64.strip())
    else:
        iv_buf = os.urandom(32)
    ciphertext = _aes_encrypt(plaintext, key, iv_buf[:16])
    eiv_b64 = base64.b64encode(iv_buf).decode("ascii") + "\n"
    return ciphertext, eiv_b64


# ── index.json.sig ───────────────────────────────────────────────────

def _verify_sig(index_data: bytes, sig_text: bytes,
                key: bytes) -> bool:
    """Return True if index.json.sig authenticates the given index.json."""
    text = sig_text.decode("utf-8", errors="replace")
    parts = [p.strip() for p in text.strip().split("\n\n") if p.strip()]
    if len(parts) < 2:
        return False
    try:
        ciphertext = base64.b64decode(parts[0])
        iv_buf = base64.b64decode(parts[1])
    except Exception:
        return False
    plain = _aes_decrypt(ciphertext, key, iv_buf[:16])
    if plain is None:
        return False
    try:
        return plain.decode("ascii").strip() == hashlib.md5(index_data).hexdigest()
    except Exception:
        return False


def _parse_sig_iv(sig_text: bytes) -> str | None:
    """Extract the base64-encoded IV buffer from an index.json.sig."""
    text = sig_text.decode("utf-8", errors="replace")
    parts = [p.strip() for p in text.strip().split("\n\n") if p.strip()]
    if len(parts) >= 2:
        return parts[1]
    return None


def _create_sig(index_data: bytes, key: bytes,
                iv_buf_b64: str | None = None) -> bytes:
    """Create an index.json.sig for the given index.json bytes.

    If *iv_buf_b64* is provided, reuse that IV buffer (deterministic
    round-trip).  Otherwise generate a fresh random IV.
    """
    md5_hex = hashlib.md5(index_data).hexdigest().encode("ascii")
    if iv_buf_b64:
        iv_buf = base64.b64decode(iv_buf_b64)
    else:
        iv_buf = os.urandom(32)
    ciphertext = _aes_encrypt(md5_hex, key, iv_buf[:16])
    text = (base64.b64encode(ciphertext).decode("ascii") + "\n\n"
            + base64.b64encode(iv_buf).decode("ascii") + "\n\n")
    return text.encode("utf-8")


# ── TAR helpers ──────────────────────────────────────────────────────

def _normalize_tar_path(name: str) -> str:
    """Strip leading './' from TAR member names (firmware adds this)."""
    return name.lstrip("./")


def _read_tar(gzip_data: bytes) -> tuple[dict[str, bytes], list[str], int]:
    """Decompress gzip, parse TAR.

    Returns ``(files_dict, member_order, gz_mtime)`` where
    *files_dict* maps normalised paths to contents,
    *member_order* is the original TAR member ordering, and
    *gz_mtime* is the timestamp from the gzip header.
    """
    import struct as _struct

    # Extract gzip mtime (uint32 LE at offset 4)
    gz_mtime = 0
    if len(gzip_data) >= 8:
        gz_mtime = _struct.unpack_from("<I", gzip_data, 4)[0]

    with gzip.open(io.BytesIO(gzip_data)) as gz:
        tar_data = gz.read()
    files: dict[str, bytes] = {}
    order: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(tar_data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            fobj = tf.extractfile(member)
            if fobj:
                key = _normalize_tar_path(member.name)
                files[key] = fobj.read()
                order.append(key)
    return files, order, gz_mtime


def _tar_header(name: str, size: int) -> bytes:
    """Build a 512-byte POSIX ustar TAR header matching the firmware's format.

    The firmware uses space-terminated octal fields (``"000664 \\0"``),
    while Python's :mod:`tarfile` uses null-terminated
    (``"0000664\\0"``).  We write raw bytes to get a bit-identical
    round-trip.
    """
    def _stn(s: str, length: int) -> bytes:
        """String field: null-padded."""
        return s.encode("utf-8")[:length].ljust(length, b"\x00")

    def _octs(val: int, length: int) -> bytes:
        """Octal field with *space + null* terminator (firmware style).

        ``length`` includes the trailing space + null (e.g. 8 for mode).
        Result: ``"OOOOOO \\0"`` for length=8.
        """
        digits = length - 2  # room for space + null
        return f"{val:0{digits}o} ".encode("ascii") + b"\x00"

    def _octs_size(val: int, length: int) -> bytes:
        """Octal field with *space* terminator (for size / mtime).

        ``length`` is 12.  Result: ``"OOOOOOOOOOO "`` for length=12.
        """
        digits = length - 1  # room for trailing space
        return f"{val:0{digits}o} ".encode("ascii")

    hdr = bytearray(512)
    hdr[0:100] = _stn(name, 100)
    hdr[100:108] = _octs(0o664, 8)       # mode
    hdr[108:116] = _octs(0, 8)           # uid
    hdr[116:124] = _octs(0, 8)           # gid
    hdr[124:136] = _octs_size(size, 12)  # size
    hdr[136:148] = _octs_size(0, 12)     # mtime
    # Placeholder checksum: 8 spaces (for checksum computation)
    hdr[148:156] = b"        "
    hdr[156:157] = b"0"                  # typeflag: regular file
    # linkname: 100 bytes of \0 (already zero)
    hdr[257:263] = b"ustar\x00"          # magic
    hdr[263:265] = b"00"                 # version
    # uname, gname: 32 bytes of \0 each (already zero)
    hdr[329:337] = _octs(0, 8)           # devmajor
    hdr[337:345] = _octs(0, 8)           # devminor
    # prefix: 155 bytes of \0 (already zero)

    # Compute and write checksum
    chksum = sum(hdr) & 0o7777777
    hdr[148:156] = f"{chksum:06o}\x00 ".encode("ascii")

    return bytes(hdr)


def _write_tar(files: dict[str, bytes],
               gz_mtime: int = 0) -> bytes:
    """Build a gzip-compressed TAR from {member_path: bytes}.

    Reproduces the firmware's TAR conventions exactly:
    - Member paths are prefixed with ``./``
    - POSIX ustar headers with space-terminated octal fields
    - mtime=0, uid=0, gid=0, uname='', gname='', mode=0o664
    - No directory entries
    - gzip level 6 (zlib default, matching firmware)

    *gz_mtime* is written into the gzip header.  Pass the original
    value from the manifest for faithful round-trips.
    """
    tar_buf = io.BytesIO()
    for name, content in files.items():
        tar_name = f"./{name}" if not name.startswith("./") else name
        tar_buf.write(_tar_header(tar_name, len(content)))
        tar_buf.write(content)
        # Pad to 512-byte block boundary
        remainder = len(content) % 512
        if remainder:
            tar_buf.write(b"\x00" * (512 - remainder))
    # End-of-archive: two 512-byte zero blocks
    tar_buf.write(b"\x00" * 1024)

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=gz_mtime,
                        compresslevel=6) as gz:
        gz.write(tar_buf.getvalue())

    # Patch the OS byte in the gzip header to 0x03 (Unix) to match
    # the firmware's output.  Python writes 0xFF (unknown).
    raw = gz_buf.getvalue()
    if len(raw) > 9 and raw[9] != 0x03:
        raw = raw[:9] + b"\x03" + raw[10:]
    return raw


# ── index.json helpers ───────────────────────────────────────────────

def _build_encrypt_iv_map(index: dict) -> dict[str, str]:
    """Extract {tar_path: encryptIV_b64} from parsed index.json."""
    eiv_map: dict[str, str] = {}
    for section in index.get("content", []):
        sid = section.get("id", "")
        for entry in section.get("files", []):
            fpath = entry.get("path")
            eiv = entry.get("encryptIV")
            if fpath and eiv:
                eiv_map[f"{sid}/{fpath}"] = eiv
                eiv_map[fpath] = eiv
    return eiv_map


# ── Plugin ───────────────────────────────────────────────────────────

class Plugin(FirmwarePlugin):
    """HP CLJ Pro 4301-4303 Export file (.exp) plugin."""

    # ── Metadata ─────────────────────────────────────────────────────

    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="HP CLJ Pro 4301 Export",
            description=(
                "HP CLJ Pro 4301-4303 encrypted export file (.exp). "
                "Decrypts the outer AES-256-CBC layer, extracts the "
                "gzip-TAR archive, optionally decrypts inner-encrypted "
                "blobs, and verifies index.json.sig integrity."
            ),
            version="0.1.0",
            format_id="hp_clj_pro_4301_exp",
            supported_variants=[VARIANT_EXP, VARIANT_EXP_CONTENTS],
            conversions=self.get_conversions(),
        )

    # ── Plugin-specific CLI options ──────────────────────────────────

    def get_options(self) -> list[PluginOption]:
        return [
            PluginOption(
                flag="--password",
                description=(
                    "Export password (set when the backup was created "
                    "on the printer)"
                ),
                kwarg_name="password",
                default=None,
                applies_to="both",
                takes_value=True,
                metavar="PWD",
            ),
            PluginOption(
                flag="--family",
                description=(
                    "Device family string for inner-key derivation "
                    "(default: from keys.conf)"
                ),
                kwarg_name="family",
                default=None,
                applies_to="both",
                takes_value=True,
                metavar="STRING",
            ),
            PluginOption(
                flag="--decrypt-inner",
                description=(
                    "Also decrypt per-file inner AES-256-CBC blobs "
                    "during unpack"
                ),
                kwarg_name="decrypt_inner",
                kwarg_value=True,
                default=False,
                applies_to="unpack",
            ),
            PluginOption(
                flag="--no-encrypt-inner",
                description=(
                    "Do not re-encrypt inner blobs during pack "
                    "(use when files are already ciphertext)"
                ),
                kwarg_name="no_encrypt_inner",
                kwarg_value=True,
                default=False,
                applies_to="pack",
            ),
        ]

    # ── Identification ───────────────────────────────────────────────

    def identify(self, path: Path) -> str | None:
        if path.is_dir():
            manifest = path / MANIFEST_NAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                    if data.get("format_id") == "hp_clj_pro_4301_exp":
                        return VARIANT_EXP_CONTENTS
                except Exception:
                    pass
            return None

        # .exp files are AES-256-CBC encrypted: the file size must be
        # a multiple of the AES block size (16 bytes) and non-trivially
        # large (the smallest valid archive exceeds a few KB).
        if not path.is_file():
            return None

        file_size = path.stat().st_size
        if file_size < 64 or file_size % 16 != 0:
            return None

        # Heuristic: the file extension should be .exp, since an
        # encrypted blob has no usable magic bytes.  We also accept
        # files whose name starts with "Export" (the firmware's default
        # naming convention: Export-<model>-<timestamp>.exp).
        name = path.name.lower()
        if name.endswith(".exp"):
            return VARIANT_EXP
        if path.name.startswith("Export") and file_size % 16 == 0:
            return VARIANT_EXP

        return None

    # ── Conversions ──────────────────────────────────────────────────

    def get_conversions(self) -> list[ConversionInfo]:
        return [
            ConversionInfo(
                source_variant=VARIANT_EXP,
                target_variant=VARIANT_EXP_CONTENTS,
                description=(
                    "Decrypt and extract .exp archive to directory"
                ),
                lossy=False,
            ),
            ConversionInfo(
                source_variant=VARIANT_EXP_CONTENTS,
                target_variant=VARIANT_EXP,
                description=(
                    "Re-encrypt directory contents into .exp file"
                ),
                lossy=False,
            ),
        ]

    # ── Unpack (exp → contents) ──────────────────────────────────────

    def unpack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> UnpackResult:
        if source_variant is None:
            source_variant = self.identify(input_path)
        if source_variant != VARIANT_EXP:
            raise ValueError(
                f"Unpack expects variant '{VARIANT_EXP}', "
                f"got '{source_variant}'"
            )

        password = kwargs.get("password")
        if not password:
            raise ValueError(
                "Export password is required.  Pass --password <pwd>."
            )

        _, default_family, _ = _get_key_material()
        family = kwargs.get("family") or default_family
        decrypt_inner = kwargs.get("decrypt_inner", False)
        target_variant = target_variant or VARIANT_EXP_CONTENTS
        source_hash = file_sha256(input_path)

        outer_key = _derive_outer_key(password)
        inner_key = _derive_inner_key(password, family)

        logger.info(
            "Outer key: %s  Inner key: %s",
            outer_key.hex(), inner_key.hex(),
        )

        # ── Outer decryption ──
        enc_data = input_path.read_bytes()
        gzip_data = _decrypt_outer(enc_data, outer_key)
        if gzip_data is None:
            raise ValueError(
                "Outer decryption failed — wrong password or not a "
                "valid .exp file."
            )

        logger.info(
            "Outer decryption OK: %d → %d bytes gzip-TAR.",
            len(enc_data), len(gzip_data),
        )

        # ── TAR extraction ──
        files, tar_order, gz_mtime = _read_tar(gzip_data)
        logger.info("TAR contains %d files.", len(files))

        # ── Parse index.json ──
        index: dict | None = None
        eiv_map: dict[str, str] = {}
        if "index.json" in files:
            try:
                index = json.loads(files["index.json"])
                eiv_map = _build_encrypt_iv_map(index)
            except Exception as exc:
                logger.warning("index.json parse error: %s", exc)

        # ── Verify index.json.sig ──
        sig_ok: bool | None = None
        sig_iv_b64: str | None = None
        if "index.json.sig" in files and "index.json" in files:
            sig_iv_b64 = _parse_sig_iv(files["index.json.sig"])
            sig_ok = _verify_sig(
                files["index.json"], files["index.json.sig"], inner_key,
            )
            if sig_ok:
                logger.info("index.json.sig: PASS")
            else:
                logger.warning("index.json.sig: FAIL")

        # ── Decrypt inner blobs ──
        inner_decrypted: list[str] = []
        if decrypt_inner and eiv_map:
            for tar_path, eiv in eiv_map.items():
                if tar_path not in files:
                    continue
                enc = files[tar_path]
                plain = _decrypt_inner(enc, eiv, inner_key)
                if plain is not None:
                    files[tar_path] = plain
                    inner_decrypted.append(tar_path)
                    logger.info(
                        "Inner decrypt: %s (%d → %d bytes)",
                        tar_path, len(enc), len(plain),
                    )
                else:
                    logger.warning("Inner decrypt FAILED: %s", tar_path)

        # ── Write to disk ──
        output_path.mkdir(parents=True, exist_ok=True)
        for tar_path, content in files.items():
            dest = output_path / tar_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

        logger.info(
            "Unpacked %d files → %s/", len(files), output_path.name,
        )

        # ── Write manifest ──
        # Count content sections and encrypted files from index.json
        n_sections = 0
        n_encrypted = 0
        if index:
            content = index.get("content", [])
            n_sections = len(content)
            n_encrypted = sum(
                1
                for sec in content
                for f in sec.get("files", [])
                if f.get("encrypted")
            )

        manifest = {
            "format_id": "hp_clj_pro_4301_exp",
            "version": 1,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "source_size": len(enc_data),
            "family": family,
            "inner_decrypted": decrypt_inner,
            "inner_iv_map": eiv_map if decrypt_inner else {},
            "sig_verified": sig_ok,
            "sig_iv": sig_iv_b64,
            "gz_mtime": gz_mtime,
            "tar_order": tar_order,
        }
        manifest_path = output_path / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return UnpackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash=source_hash,
            output_hash="(directory)",
            metadata={
                "files": len(files),
                "sections": n_sections,
                "encrypted_files": n_encrypted,
                "inner_decrypted": len(inner_decrypted),
                "sig_verified": sig_ok,
            },
        )

    # ── Pack (contents → exp) ────────────────────────────────────────

    def pack(
        self,
        input_path: Path,
        output_path: Path,
        source_variant: str | None = None,
        target_variant: str | None = None,
        **kwargs: Any,
    ) -> PackResult:
        if source_variant is None:
            if input_path.is_dir():
                source_variant = VARIANT_EXP_CONTENTS
            else:
                source_variant = self.identify(input_path)

        if source_variant != VARIANT_EXP_CONTENTS:
            raise ValueError(
                f"Pack expects variant '{VARIANT_EXP_CONTENTS}', "
                f"got '{source_variant}'"
            )

        password = kwargs.get("password")
        if not password:
            raise ValueError(
                "Export password is required.  Pass --password <pwd>."
            )

        # Read manifest for defaults (family, inner_decrypted state)
        manifest_path = input_path / MANIFEST_NAME
        manifest: dict = {}
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())

        _, default_family, _ = _get_key_material()
        family = kwargs.get("family") or manifest.get(
            "family", default_family,
        )
        no_encrypt_inner = kwargs.get("no_encrypt_inner", False)
        # Determine whether inner blobs need re-encryption:
        #   - If unpack used --decrypt-inner, the files on disk are
        #     plaintext → we MUST re-encrypt (unless --no-encrypt-inner).
        #   - If unpack did NOT decrypt them, the files are still
        #     ciphertext → we must NOT re-encrypt (double-encryption).
        inner_was_decrypted = manifest.get("inner_decrypted", False)
        if no_encrypt_inner:
            encrypt_inner = False
        elif inner_was_decrypted:
            encrypt_inner = True
        else:
            encrypt_inner = False
        target_variant = target_variant or VARIANT_EXP

        if not input_path.is_dir():
            raise ValueError(f"{input_path} is not a directory")

        outer_key = _derive_outer_key(password)
        inner_key = _derive_inner_key(password, family)
        inner_iv_map: dict[str, str] = manifest.get("inner_iv_map", {})

        # ── Read index.json ──
        index_path = input_path / "index.json"
        if not index_path.exists():
            raise FileNotFoundError(
                f"index.json not found in {input_path}"
            )
        index = json.loads(index_path.read_bytes())

        # ── Build TAR file dict ──
        tar_files: dict[str, bytes] = {}

        for section in index.get("content", []):
            sid = section.get("id", "")
            for entry in section.get("files", []):
                fpath = entry.get("path")
                if not fpath:
                    continue

                # Resolve on-disk location (section-namespaced or flat)
                candidates = [input_path / sid / fpath, input_path / fpath]
                file_path = next((p for p in candidates if p.exists()), None)
                if file_path is None:
                    logger.warning("Missing: %s/%s — skipped", sid, fpath)
                    continue

                plaintext = file_path.read_bytes()
                tar_key = f"{sid}/{fpath}" if sid else fpath

                if encrypt_inner and entry.get("encrypted"):
                    # Plaintext on disk → encrypt (reuse original IV
                    # if available for deterministic round-trip)
                    orig_iv = (inner_iv_map.get(tar_key)
                               or inner_iv_map.get(fpath))
                    ciphertext, eiv_b64 = _encrypt_inner(
                        plaintext, inner_key, iv_buf_b64=orig_iv,
                    )
                    entry["encryptIV"] = eiv_b64
                    entry["md5"] = hashlib.md5(ciphertext).hexdigest()
                    tar_files[tar_key] = ciphertext
                    logger.info(
                        "Encrypt: %s (%d → %d bytes)",
                        fpath, len(plaintext), len(ciphertext),
                    )
                else:
                    # Either a non-encrypted file, or an encrypted file
                    # being passed through as-is (already ciphertext).
                    # Recompute MD5 on the file data for non-encrypted
                    # entries; preserve existing MD5 for passthrough.
                    if not entry.get("encrypted"):
                        entry["md5"] = hashlib.md5(plaintext).hexdigest()
                    # else: keep original md5 and encryptIV from index
                    tar_files[tar_key] = plaintext
                    logger.info("Add: %s (%d bytes)", fpath, len(plaintext))

        # ── Serialize updated index.json ──
        index_bytes = json.dumps(
            index, indent=2, ensure_ascii=False,
        ).encode("utf-8")
        tar_files["index.json"] = index_bytes

        # ── Generate index.json.sig (reuse original IV if available) ──
        sig_iv_b64 = manifest.get("sig_iv")
        tar_files["index.json.sig"] = _create_sig(
            index_bytes, inner_key, iv_buf_b64=sig_iv_b64,
        )
        sig_md5 = hashlib.md5(index_bytes).hexdigest()
        logger.info("Signed index.json (MD5=%s)", sig_md5)

        # ── Restore original TAR member order ──
        saved_order = manifest.get("tar_order")
        if saved_order:
            ordered: dict[str, bytes] = {}
            for key in saved_order:
                if key in tar_files:
                    ordered[key] = tar_files.pop(key)
            # Append any remaining entries not in the saved order
            ordered.update(tar_files)
            tar_files = ordered

        # ── Build gzip-TAR ──
        gz_mtime = manifest.get("gz_mtime", 0)
        gzip_data = _write_tar(tar_files, gz_mtime=gz_mtime)
        logger.info(
            "TAR+gz: %d bytes (%d entries)", len(gzip_data), len(tar_files),
        )

        # ── Outer AES-256-CBC encryption ──
        ciphertext = _encrypt_outer(gzip_data, outer_key)
        logger.info(
            "Output: %d bytes (AES-256-CBC outer layer)", len(ciphertext),
        )

        output_path.write_bytes(ciphertext)
        output_hash = file_sha256(output_path)

        return PackResult(
            output_path=output_path,
            source_variant=source_variant,
            target_variant=target_variant,
            source_hash="(directory)",
            output_hash=output_hash,
            metadata={
                "files": len(tar_files),
                "output_size": len(ciphertext),
            },
        )
