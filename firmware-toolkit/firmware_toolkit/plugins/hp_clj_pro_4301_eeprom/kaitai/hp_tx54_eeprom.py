# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpTx54Eeprom(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self._raw_nos_region = self._io.read_bytes(0x200)
        _io__raw_nos_region = KaitaiStream(BytesIO(self._raw_nos_region))
        self.nos_region = HpTx54Eeprom.NosNvmRegion(_io__raw_nos_region, self, self._root)
        self.nvm2_region = HpTx54Eeprom.Nvm2ObjectStorage(self._io, self, self._root)

    class NosNvmRegion(KaitaiStruct):
        """NOS NVM region managed by the bootloader (512 bytes).

        Tier 1: Partitioned fields (0x000-0x0C1) -- layout defined by
        type 0x40 sub-partition table at binary address 0x9FF33AA4.
        Field offsets computed by accumulating entry sizes.

        Tier 2: Flat fields (0x100-0x131) -- 13 fields via flat table
        (partition_id > 0x80). First 0x136 bytes cached in RAM at boot.

        Multi-byte values are big-endian (NVM_ReadField convention).
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            # -- Tier 1: Partitioned fields --
            self.nvm2_control = self._io.read_u1()
            self.internal_0x17 = self._io.read_bytes(4)
            self.map_revision = self._io.read_u1()
            self.power_state = self._io.read_bytes(2)
            self.internal_0x18 = self._io.read_bytes(4)
            self.board_id = self._io.read_bytes(5)
            self.dynamic_gap = self._io.read_bytes(30)
            self.serial_number_field = self._io.read_bytes(41)
            self.boot_flags = self._io.read_bytes(2)
            self.internal_0x19 = self._io.read_bytes(2)
            self.boot_flags3 = self._io.read_bytes(2)
            self.power_state2 = self._io.read_bytes(2)
            self.internal_0x1a = self._io.read_bytes(2)
            self.assert_seq_num = self._io.read_bytes(4)
            self.psku_config = self._io.read_bytes(4)
            self.eeprom_recov_count = self._io.read_bytes(2)
            self.counter_data = self._io.read_bytes(70)
            self.counter_state = self._io.read_bytes(2)
            self.counter_config = self._io.read_bytes(14)
            self.remaining_partition_space = self._io.read_bytes(62)

            # -- Tier 2: Flat fields (0x100-0x131) --
            self.map2_version = self._io.read_u2le()
            self.pca_serial_number = self._io.read_bytes(10)
            self.eth0_mac = self._io.read_bytes(6)
            self.wlan0_mac = self._io.read_bytes(6)
            self.wlan1_mac = self._io.read_bytes(6)
            self.power_cycle_count_raw = self._io.read_bytes(2)
            self.secure_vars = self._io.read_u1()
            self.boot_flags2_raw = self._io.read_bytes(2)
            self.misc_1 = self._io.read_bytes(4)
            self.save_recover_id = self._io.read_bytes(4)
            self.mpca_bpca_pairing = self._io.read_bytes(2)
            self.misc_2 = self._io.read_bytes(2)
            self.unknown_1c = self._io.read_bytes(2)
            self.flat_tail = self._io.read_bytes(1)
            self.flat_cache_tail = self._io.read_bytes(4)
            self.unused_gap = self._io.read_bytes(0x1FE - 0x136)
            self.root_page_ptr_raw = self._io.read_bytes(2)


    class Nvm2ObjectStorage(KaitaiStruct):
        """Kernel NVM2 object storage region.  Contains a 19-byte header,
        span bitmap (page 9), allocation bitmap (page 10), and
        page-based variable-length objects from page 11 onward.
        All header integers are little-endian.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.header = HpTx54Eeprom.Nvm2Header(self._io, self, self._root)
            self.header_padding = self._io.read_bytes(0x240 - 0x213)
            self.span_bitmap = self._io.read_bytes(64)
            self.alloc_bitmap = self._io.read_bytes(64)
            self.object_pages = self._io.read_bytes_full()


    class Nvm2Header(KaitaiStruct):
        """NVM2 header (19 bytes at EEPROM offset 0x200).
        Written by kernel _write_root_page() and _format_nvm().
        All fields are little-endian.
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


