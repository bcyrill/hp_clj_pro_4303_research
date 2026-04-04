# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class HpCljPro4301Nand(KaitaiStruct):
    """Partition layout for the HP Color LaserJet Pro MFP 4301-4303
    (HP TX54 platform) NAND flash, as defined by the device tree
    node `flash@38008000`.
    
    This structure describes the logical partition map applied to
    the raw 512 MB NAND user data (without OOB/ECC).  The same
    TH58BVG2S3HTA00 NAND chip may be used by other devices with
    different partition layouts.
    
    SoC:  ARM Cortex-A7 (dual-core), custom HP ASIC
    ISA:  Big-endian ARM32
    NAND: 512 MB (TH58BVG2S3HTA00, 4 Gbit)
    
    Partition map (6 MTD partitions):
      mtd0  Boot            0x00000000  256 KB      RO
      mtd1  UpdatableLBI    0x00040000  5 MB        RO
      mtd2  RootFS          0x00540000  ~263 MB     RO
      mtd3  RWFS            0x10C00000  ~142 MB     RW
      mtd4  RecoveryRootFS  0x19A60000  ~97 MB      RO
      mtd5  RecoveryLBI     0x1FB60000  ~4.6 MB     RO
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.mtd0_boot = self._io.read_bytes(262144)
        self.mtd1_updatable_lbi = self._io.read_bytes(5242880)
        self.mtd2_rootfs = self._io.read_bytes(275513344)
        self.mtd3_rwfs = self._io.read_bytes(149291008)
        self.mtd4_recovery_rootfs = self._io.read_bytes(101711872)
        self.mtd5_recovery_lbi = self._io.read_bytes(4849664)


