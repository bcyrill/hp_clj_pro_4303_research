# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpCljPro4301Boot(KaitaiStruct):
    """Boot partition (mtd0) layout for the HP Color LaserJet Pro
    MFP 4301-4303 (HP TX54 platform).
    
    The 256 KB boot partition contains two identical 128 KB copies
    of the first-stage bootloader (BL1), arranged as an A/B
    redundancy scheme.  The SoC reads copy A first; if it fails
    integrity checks, it falls back to copy B.
    
    Each copy begins with an ARM big-endian exception vector table
    (8 × LDR PC instructions at 0x18F09FE5).
    
    Total size: 256 KB (262,144 bytes)
    Copy size:  128 KB (131,072 bytes) each
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.copy_a = self._io.read_bytes(131072)
        self.copy_b = self._io.read_bytes(131072)


