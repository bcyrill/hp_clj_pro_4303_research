# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpCljPro4301Eeprom(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self._raw_nos_region = self._io.read_bytes(510)
        _io__raw_nos_region = KaitaiStream(BytesIO(self._raw_nos_region))
        self.nos_region = HpCljPro4301Eeprom.NosRegion(_io__raw_nos_region, self, self._root)
        self.nvm2_region = HpCljPro4301Eeprom.Nvm2Region(self._io, self, self._root)

    class Nvm2Header(KaitaiStruct):
        """NVM2 header (19 B at EEPROM offset 0x200). All fields are
        little-endian.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_u4le()
            self.version_info = self._io.read_u4le()
            self.object_count = self._io.read_u2le()
            self.max_objects = self._io.read_u2le()
            self.alloc_bitmap_offset = self._io.read_u2le()
            self.span_bitmap_offset = self._io.read_u2le()
            self.debug_level = self._io.read_u1()
            self.generation_counter = self._io.read_u2le()


    class Nvm2Region(KaitaiStruct):
        """Kernel-managed NVM2 region. Starts with the 2-byte BE
        root-page pointer (physically outside but logically part
        of NVM2), followed by the 19-byte header at 0x200,
        header padding to the end of page 8, span + allocation
        bitmaps, and page-based object storage.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.root_page_pointer = self._io.read_u2be()
            self.header = HpCljPro4301Eeprom.Nvm2Header(self._io, self, self._root)
            self.header_padding = self._io.read_bytes((576 - 531))
            self.span_bitmap = self._io.read_bytes(64)
            self.alloc_bitmap = self._io.read_bytes(64)
            self.object_pages = self._io.read_bytes_full()


    class FlatFields(KaitaiStruct):
        """13 bootloader flat NVM fields at 0x100-0x130."""
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.map2_version = self._io.read_u2le()
            self.pca_serial_number = self._io.read_bytes(10)
            self.eth0_mac = self._io.read_bytes(6)
            self.wlan0_mac = self._io.read_bytes(6)
            self.wlan1_mac = self._io.read_bytes(6)
            self.power_cycle_count = self._io.read_bytes(2)
            self.secure_vars = self._io.read_u1()
            self.boot_flags2 = self._io.read_bytes(2)
            self.misc_1 = self._io.read_bytes(4)
            self.save_recover_id = self._io.read_bytes(4)
            self.mpca_bpca_pairing = self._io.read_bytes(2)
            self.misc_2 = self._io.read_bytes(2)
            self.eeprom_recov_count_flat = self._io.read_bytes(2)


    class NosRegion(KaitaiStruct):
        """NOS region. Ends at 0x1FD; the 2 bytes at 0x1FE-0x1FF
        physically sit between NOS and NVM2 but belong to the
        NVM2 region in the firmware-toolkit codec's sidecar model.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.partitioned_region = self._io.read_bytes(194)
            self.partition_tail_fill = self._io.read_bytes((256 - 194))
            self._raw_flat_fields = self._io.read_bytes(49)
            _io__raw_flat_fields = KaitaiStream(BytesIO(self._raw_flat_fields))
            self.flat_fields = HpCljPro4301Eeprom.FlatFields(_io__raw_flat_fields, self, self._root)
            self._raw_nos_nvm_extension = self._io.read_bytes((510 - 305))
            _io__raw_nos_nvm_extension = KaitaiStream(BytesIO(self._raw_nos_nvm_extension))
            self.nos_nvm_extension = HpCljPro4301Eeprom.NosNvmExtension(_io__raw_nos_nvm_extension, self, self._root)


    class NosNvmExtension(KaitaiStruct):
        """NOS Tier-3 entries. Accessed by libNvram.so using NOS NVM
        IDs outside the bootloader's flat-table range.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.backup_device_pin = self._io.read_bytes(4)
            self.nos_nvm_reserved = self._io.read_bytes(201)



