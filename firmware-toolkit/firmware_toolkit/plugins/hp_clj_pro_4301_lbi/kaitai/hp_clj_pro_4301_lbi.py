# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpCljPro4301Lbi(KaitaiStruct):
    """Loadable Boot Image (LBI) format used by the HP Color LaserJet
    Pro MFP 4301-4303 (TX54 platform) for both the UpdatableLBI
    (mtd1) and RecoveryLBI (mtd5) partitions.

    Structure:
      - 20-byte base header (magic, version, total header size,
        section count, data start offset)
      - N section descriptors of 24 bytes each
      - Padding (0xFF) from end of descriptors to data_start
      - Section data, each padded to data_start alignment
      - Trailing 0xFF padding to partition end

    The header size field equals 20 + N * 24 (base + descriptors).
    Section data offsets are computed sequentially: each section's
    data immediately follows the previous section's data, aligned
    up to the data_start boundary (typically 0x800 = 2048 bytes).

    Known sections (5 in this firmware):
      0: Boot logo (BMP image)
      1: Second-stage bootloader (BL2, ARM BE code)
      2: Device Tree Blob (DTB, magic 0xD00DFEED)
      3: Kernel zImage (ARM BE, compressed Linux kernel)
      4: Authentication block (SecureBoot header + RSA-2048 sig)
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = HpCljPro4301Lbi.LbiHeader(self._io, self, self._root)
        self.section_descriptors = []
        for i in range(self.header.num_sections):
            self.section_descriptors.append(HpCljPro4301Lbi.SectionDescriptor(self._io, self, self._root))

        self.header_padding = self._io.read_bytes((self.header.data_start - self.header.header_size))

    class LbiHeader(KaitaiStruct):
        """20-byte base header for the LBI format.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            self.version = self._io.read_u4be()
            self.header_size = self._io.read_u4be()
            self.num_sections = self._io.read_u4be()
            self.data_start = self._io.read_u4be()


    class SectionDescriptor(KaitaiStruct):
        """24-byte section descriptor.  Describes one payload section
        within the LBI image.

        Data offsets are NOT stored per-descriptor; they are
        computed sequentially starting from data_start, with each
        section aligned up to the data_start boundary.

        Validation rules (from BL1 reverse engineering):
          - Exactly one section must have ENTRY (0x0080) in role_flags.
          - The last section must have SIG (0x2000) in role_flags.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.role_flags = self._io.read_u4be()
            self.load_address = self._io.read_u4be()
            self.size = self._io.read_u4be()
            self.image_type = self._io.read_u4be()
            self.entry_point = self._io.read_u4be()
            self.reserved = self._io.read_u4be()


