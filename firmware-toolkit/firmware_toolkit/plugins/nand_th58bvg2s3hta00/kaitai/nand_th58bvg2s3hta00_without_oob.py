# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class NandTh58bvg2s3hta00WithoutOob(KaitaiStruct):
    """Kaitai Struct definition for a raw NAND flash dump from a
    Toshiba TH58BVG2S3HTA00 chip with the OOB/ECC area stripped.
    
    This format contains only the user data pages without any
    spare area or ECC codes.
    
    Chip specifications:
      - Capacity: 4 Gbit (512 MB user data)
      - Page size: 2048 bytes (data only)
      - Pages per block: 64
      - Blocks: 4096
      - Total pages: 262144
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.pages = []
        i = 0
        while not self._io.is_eof():
            self.pages.append(NandTh58bvg2s3hta00WithoutOob.NandPage(self._io, self, self._root))
            i += 1


    class NandPage(KaitaiStruct):
        """A single NAND page containing 2048 bytes of user data."""
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes(2048)



