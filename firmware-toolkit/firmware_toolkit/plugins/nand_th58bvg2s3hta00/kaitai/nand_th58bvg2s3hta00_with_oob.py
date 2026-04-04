# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class NandTh58bvg2s3hta00WithOob(KaitaiStruct):
    """Kaitai Struct definition for a raw NAND flash dump from a
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
    capacity t=8, operating on bit-inverted data with swapped bits.
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
            self.pages.append(NandTh58bvg2s3hta00WithOob.NandPage(self._io, self, self._root))
            i += 1


    class NandPage(KaitaiStruct):
        """A single NAND page consisting of 2048 bytes of user data
        split into four 512-byte chunks, followed by a 64-byte OOB
        area containing spare metadata and per-chunk ECC codes.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data_chunks = []
            for i in range(4):
                self.data_chunks.append(NandTh58bvg2s3hta00WithOob.DataChunk(self._io, self, self._root))

            self.oob = NandTh58bvg2s3hta00WithOob.OobArea(self._io, self, self._root)


    class DataChunk(KaitaiStruct):
        """A 512-byte data chunk within a NAND page."""
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes(512)


    class OobArea(KaitaiStruct):
        """The 64-byte Out-Of-Band area appended to each NAND page.
        Contains a 12-byte spare/metadata buffer followed by four
        13-byte BCH ECC codes, one per data chunk.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.spare_buffer = self._io.read_bytes(12)
            self.ecc_chunks = []
            for i in range(4):
                self.ecc_chunks.append(NandTh58bvg2s3hta00WithOob.EccCode(self._io, self, self._root))



    class EccCode(KaitaiStruct):
        """A 13-byte BCH ECC code for one 512-byte data chunk.
        Algorithm: BCH(8219, t=8) on bit-inverted, bit-swapped data.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._io.read_bytes(13)



