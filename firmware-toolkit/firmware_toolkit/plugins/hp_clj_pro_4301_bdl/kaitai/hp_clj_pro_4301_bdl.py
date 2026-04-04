# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpCljPro4301Bdl(KaitaiStruct):
    """BDL (Bundle) firmware update container format used by HP LaserJet
    printers.  Contains one or more packages (LBI, rootfs, datafs,
    eclipse), each holding one or more files (digests.txt, encrypted
    firmware payloads).

    Structure:
      - BdlHeader (2345 bytes, magic "ibdl")
      - PackageTable (16 bytes x N entries)
      - Package data (PakHeader + FileTable + file data) x N

    All multi-byte integers are little-endian.  All string fields are
    null-terminated, fixed-width character arrays.
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.bdl_header = HpCljPro4301Bdl.BdlHeader(self._io, self, self._root)
        self.package_table = []
        for i in range(self.bdl_header.common.item_count):
            self.package_table.append(HpCljPro4301Bdl.PackageTableEntry(self._io, self, self._root))

    class CommonHeader(KaitaiStruct):
        """800-byte common header prefix shared by BdlHeader and PakHeader.
        Contains magic, version, sizes, CRCs, timestamps, and three
        256-byte string fields (version_string, vendor, name).
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            self.version_major = self._io.read_u2le()
            self.version_minor = self._io.read_u2le()
            self.header_size = self._io.read_u4le()
            self.header_crc = self._io.read_u4le()
            self.item_count = self._io.read_u4le()
            self.item_table_crc = self._io.read_u4le()
            self.timestamp = self._io.read_u4le()
            self.reserved = self._io.read_u4le()
            self._raw_version_string = self._io.read_bytes(256)
            self.version_string = (self._raw_version_string).split(b'\x00')[0].decode('ASCII')
            self._raw_vendor = self._io.read_bytes(256)
            self.vendor = (self._raw_vendor).split(b'\x00')[0].decode('ASCII')
            self._raw_name = self._io.read_bytes(256)
            self.name = (self._raw_name).split(b'\x00')[0].decode('ASCII')

    class BdlHeader(KaitaiStruct):
        """Bundle header.  Extends CommonHeader with bundle-specific fields.
        Total size: 2345 bytes (0x929).  Magic is "ibdl".
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.common = HpCljPro4301Bdl.CommonHeader(self._io, self, self._root)
            self.type = self._io.read_u4le()
            self.options = self._io.read_u4le()
            self.pad0 = self._io.read_u1()
            self._raw_description = self._io.read_bytes(256)
            self.description = (self._raw_description).split(b'\x00')[0].decode('ASCII')
            self._raw_identifier = self._io.read_bytes(256)
            self.identifier = (self._raw_identifier).split(b'\x00')[0].decode('ASCII')
            self._raw_support_url = self._io.read_bytes(256)
            self.support_url = (self._raw_support_url).split(b'\x00')[0].decode('ASCII')
            self._raw_support_phone = self._io.read_bytes(256)
            self.support_phone = (self._raw_support_phone).split(b'\x00')[0].decode('ASCII')
            self._raw_support_email = self._io.read_bytes(256)
            self.support_email = (self._raw_support_email).split(b'\x00')[0].decode('ASCII')
            self._raw_serial_number = self._io.read_bytes(256)
            self.serial_number = (self._raw_serial_number).split(b'\x00')[0].decode('ASCII')

    class PakHeader(KaitaiStruct):
        """Package header.  Extends CommonHeader with package-specific
        fields.  Total size: 1085 bytes (0x43D).  Magic is "ipkg".
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.common = HpCljPro4301Bdl.CommonHeader(self._io, self, self._root)
            self.type_uuid = self._io.read_bytes(16)
            self.install_options = self._io.read_u4le()
            self.install_phase = self._io.read_u4le()
            self.package_options = self._io.read_u4le()
            self.pad0 = self._io.read_u1()
            self._raw_description = self._io.read_bytes(256)
            self.description = (self._raw_description).split(b'\x00')[0].decode('ASCII')

    class PackageTableEntry(KaitaiStruct):
        """Entry in the package table that follows the BdlHeader.
        Provides the absolute byte offset and total size of each package.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u8le()
            self.size = self._io.read_u8le()

    class FileTableEntry(KaitaiStruct):
        """Entry in the file table that follows each PakHeader.
        The file_offset is relative to the start of the containing
        package (the PakHeader position), NOT the BDL file start.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_filename = self._io.read_bytes(256)
            self.filename = (self._raw_filename).split(b'\x00')[0].decode('ASCII')
            self.file_offset = self._io.read_u8le()
            self.file_size = self._io.read_u8le()
            self.crc32 = self._io.read_u4le()
