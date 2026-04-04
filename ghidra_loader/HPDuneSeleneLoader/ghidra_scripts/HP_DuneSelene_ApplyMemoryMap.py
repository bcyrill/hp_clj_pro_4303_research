# HP Dune/Selene Bootloader – Apply DTS-derived Memory Map
#
# Ghidra Python script to apply the full peripheral memory map and
# reserved-memory regions derived from the HP tx54 kernel.dts to an
# already-imported HP Color LaserJet Pro MFP 4301-4303 bootloader image.
#
# Usage:
#   1. Import the raw binary into Ghidra:
#        - Language: ARM:LEBE:32:v7LEInstruction  (ARMv7 BE8)
#        - For nandboot:        base address 0x3C200000
#        - For kexec_trusted_fw: base address 0x9FF10680
#   2. Run this script from the Script Manager.
#   3. The script auto-detects the stage from the program name and
#      creates all peripheral MMIO blocks, DRAM regions, labels, and
#      partition info.
#
# @category HP.Bootloader
# @author
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryBlockType

import ghidra.program.model.address as addr_mod


# =====================================================================
#  Configuration
# =====================================================================

NANDBOOT_BASE  = 0x3C200000
NANDBOOT_ENTRY = 0x3C200A04

KEXEC_BASE     = 0x9FF10680
KEXEC_ENTRY    = 0x9FF10F24

SRAM_BASE      = 0x3C180000
SRAM_PRE_SIZE  = NANDBOOT_BASE - SRAM_BASE  # 0x80000

DRAM_BASE = 0x80000000
DRAM_SIZE = 0x20000000  # 512 MiB physical

# Peripheral MMIO definitions: (name, address, size, comment)
PERIPHERALS = [
    # NAND flash controller
    ("NAND_FLASH_CTRL",  0x38008000, 0x700,
     "hp,flash - NAND flash controller"),

    # CCI-400 interconnect
    ("CCI400",           0x38390000, 0x6000,
     "arm,cci-400 - Cache Coherent Interconnect"),

    # GIC
    ("GIC_DIST",         0x38401000, 0x1000,
     "arm,cortex-a7-gic - GIC Distributor"),
    ("GIC_CPU_IF",       0x38402000, 0x2000,
     "arm,cortex-a7-gic - GIC CPU Interface"),

    # Clock / system config
    ("SDIOH_CLK_SEL",    0x3C004008, 0x04,
     "Arasan SDIO host - clock select register"),
    ("CLOCKSYS_DIV",     0x3C004010, 0x04,
     "Arasan SDIO host - clocksys divider register"),
    ("SDIOH_DRV_STR",    0x3C00D070, 0x04,
     "Arasan SDIO host - drive-strength register"),
    ("SDIO_PAD_VOLT",    0x3C00D094, 0x04,
     "Arasan SDIO host - pad voltage register"),

    # Reset controller
    ("RESET_CTRL",       0x3C013000, 0x100,
     "hp,reset - Reset controller (secure)"),

    # SPI
    ("SPI_SPIRF_0",      0x3C015000, 0x100,
     "hp-spi-spirf - SPI controller 0"),
    ("SPI_SPIRF_1",      0x3C016000, 0x100,
     "hp-spi-spirf - SPI controller 1"),

    # Ethernet clock/misc
    ("ETH_CLK_CTRL",     0x3C01E000, 0x30,
     "Ethernet / MDIO clock control registers"),

    # USB PHY
    ("USB_PHY_0",        0x3C021000, 0x100,
     "hp,usb-phy - USB PHY register bank 0"),
    ("USB_PHY_1",        0x3C022000, 0x100,
     "hp,usb-phy - USB PHY register bank 1"),

    # I2C
    ("I2C_INST_0",       0x3C029000, 0x100,
     "hp,i2c-1 - I2C instance 0 (bus 2, EEPROM)"),
    ("I2C_INST_3",       0x3C02F000, 0x100,
     "hp,i2c - I2C instance 3 (bus 1)"),

    # Ethernet MAC
    ("ETHERNET",         0x3C174000, 0x100,
     "hp,hpumac-3.0 - Ethernet MAC (includes MDIO at +0x80)"),

    # SRAM (USB endpoint SRAM, 0x1D00 bytes per DTS)
    # The broader range 0x3C180000-0x3C200000 is shared between
    # SRAM and peripheral MMIO.  Only the USB SRAM portion is mapped;
    # the rest is covered by individual peripheral blocks below.
    ("SRAM",             0x3C180000, 0x1D00,
     "On-chip SRAM - USB endpoint SRAM; nandboot mapped at 0x3C200000"),

    # USB host controllers
    ("USB_HOST_CTRL",    0x3C19E000, 0x100,
     "hp,usb_host - USB host controller"),
    ("USB_EHCI",         0x3C19F000, 0x100,
     "generic-ehci - EHCI registers (big-endian)"),
    ("USB_OHCI",         0x3C1A0000, 0x100,
     "generic-ohci - OHCI registers (big-endian)"),

    # USB device controller endpoints
    ("USB_EP0",          0x3C1A2000, 0x40, "UDC endpoint 0 (bidi)"),
    ("USB_EP1",          0x3C1A3000, 0x40, "UDC endpoint 1 (bulk)"),
    ("USB_EP2",          0x3C1A4000, 0x40, "UDC endpoint 2 (bulk)"),
    ("USB_EP3",          0x3C1A5000, 0x40, "UDC endpoint 3 (bulk)"),
    ("USB_EP4",          0x3C1A6000, 0x40, "UDC endpoint 4 (bulk)"),
    ("USB_EP5",          0x3C1A7000, 0x40, "UDC endpoint 5 (bulk)"),
    ("USB_EP6",          0x3C1A8000, 0x40, "UDC endpoint 6 (bulk)"),
    ("USB_EP7",          0x3C1A9000, 0x40, "UDC endpoint 7 (bulk)"),
    ("USB_EP8",          0x3C1AA000, 0x40, "UDC endpoint 8 (bulk)"),
    ("USB_EP9",          0x3C1AB000, 0x40, "UDC endpoint 9 (bulk)"),
    ("USB_EP10",         0x3C1AC000, 0x40, "UDC endpoint 10 (bulk)"),
    ("USB_EP11",         0x3C1AD000, 0x40, "UDC endpoint 11 (bulk)"),
    ("USB_EP12",         0x3C1AE000, 0x40, "UDC endpoint 12 (bulk)"),
    ("USB_EP13",         0x3C1AF000, 0x40, "UDC endpoint 13 (bulk)"),
    ("USB_EP14",         0x3C1B0000, 0x40, "UDC endpoint 14 (bulk)"),
    ("USB_EP15",         0x3C1B1000, 0x40, "UDC endpoint 15 (bulk)"),

    # USB device controller
    ("USB_DEV_CTRL",     0x3C1B2000, 0x80,
     "hp,usb-device / hp-udc - USB device controller"),

    # SDIO (Arasan)
    ("SDIO_HOST",        0x3C1B4000, 0x100,
     "hp,arasan_sdio_host0 - SDIO host IP"),
    ("SDIO_HOST_CFG",    0x3C1B5000, 0x100,
     "Arasan SDIO host - configuration registers"),

    # Audio
    ("AUDIO",            0x3C1BC000, 0x100,
     "hp-audio - Audio controller"),

    # GPIO
    ("GPIO",             0x3C1C6000, 0xA60,
     "hp-gpio - GPIO controller"),

    # UARTs
    ("UART0",            0x3C1C7000, 0x100,
     "hp,rs-uart - UART 0 (serial0, 115200 console)"),
    ("UART1",            0x3C1C8000, 0x100,
     "hp,rs-uart - UART 1 (serial1)"),
    ("UART2",            0x3C1C9000, 0x100,
     "hp,rs-uart - UART 2 (disabled)"),
    ("UART3",            0x3C1CA000, 0x100,
     "hp,rs-uart - UART 3 (disabled, 64-byte FIFO)"),

    # ARM Cortex-A7 configuration
    ("ARM_A7_CFG_0",     0x3C540000, 0x100,
     "hp,arm-a7-config - Configuration bank 0"),
    ("ARM_A7_CFG_1",     0x3C541000, 0x100,
     "hp,arm-a7-config - Configuration bank 1"),
    ("ARM_A7_CFG_2",     0x3C542000, 0x1100,
     "hp,arm-a7-config - Configuration bank 2"),

    # Hardware trace
    ("HW_TRACE",         0x3C896000, 0x1000,
     "hp,hwtrace - Hardware trace (BE data, slot=4)"),

    # Microkernel power management
    ("UKERNEL_PM",       0x3F826000, 0x300,
     "ukernel_pm_driver - Microkernel power management"),

    # LCD controller
    ("LCD_CTRL",         0x3F99A000, 0x70,
     "hp,lcdc - LCD controller main"),
    ("LCD_CFG_1",        0x3F99C000, 0x30,
     "hp,lcdc - LCD config bank 1"),
    ("LCD_CFG_2",        0x3F99E000, 0x18,
     "hp,lcdc - LCD config bank 2"),

    # Microkernel SRAM
    ("UKERNEL_SRAM_WR",  0x3F9A0000, 0x400,
     "mmio-sram - Microkernel SRAM (write region)"),
    ("UKERNEL_SRAM_RD",  0x3F9A0400, 0x400,
     "mmio-sram - Microkernel SRAM (read region)"),

    # LCD layers
    ("LCD_LAYER_0",      0x3F9A2000, 0x38,
     "hp,lcdc - LCD layer 0"),
    ("LCD_LAYER_1",      0x3F9A4000, 0x38,
     "hp,lcdc - LCD layer 1"),
    ("LCD_LAYER_2",      0x3F9A6000, 0x38,
     "hp,lcdc - LCD layer 2"),
    ("LCD_CURSOR",       0x3F9A8000, 0x20,
     "hp,lcdc - LCD cursor"),
]

# Reserved-memory landmarks: (name, address, comment)
RESERVED_LABELS = [
    ("kernel_load",     0x81000000,
     "phys_load_addr - kernel load address"),
    ("rpc_memory",      0x93E00000,
     "reserved-memory - RPC shared memory (0x100000)"),
    ("devicetree_load", 0x93F3A000,
     "phys_load_addr - device-tree blob load address"),
    ("cgd_buffer",      0x93F40000,
     "reserved-memory - CGD frame buffer (0xC0000)"),
    ("shared_memory",   0x94000000,
     "reserved-memory - DuneSharedMemory (0x9700000)"),
    ("dox_memory",      0x9D700000,
     "reserved-memory - DOX remote processor (0x2800000, no-map)"),
    ("trusted_fw",      0x9FF00000,
     "reserved-memory - Trusted firmware (0x100000, no-map)"),
]

# NAND flash partition table
NAND_PARTITIONS = [
    ("Boot",           0x00000000, 0x00040000, True),
    ("UpdatableLBI",   0x00040000, 0x00500000, True),
    ("RootFS",         0x00540000, 0x106C0000, True),
    ("RWFS",           0x10C00000, 0x08E60000, False),
    ("RecoveryRootFS", 0x19A60000, 0x06100000, True),
    ("RecoveryLBI",    0x1FB60000, 0x004A0000, True),
]


# =====================================================================
#  Helper functions
# =====================================================================

def get_space():
    return currentProgram.getAddressFactory().getDefaultAddressSpace()


def to_addr(offset):
    return get_space().getAddress(offset)


def create_volatile_block(name, address, size, comment):
    """Create a volatile (MMIO) uninitialized memory block."""
    memory = currentProgram.getMemory()
    try:
        a = to_addr(address)
        block = memory.createUninitializedBlock(name, a, size, False)
        block.setRead(True)
        block.setWrite(True)
        block.setExecute(False)
        block.setVolatile(True)

        currentProgram.getSymbolTable().createLabel(
            a, name + "_BASE", SourceType.IMPORTED)
        currentProgram.getListing().setComment(
            a, CodeUnit.PLATE_COMMENT, comment)
        return True
    except Exception as e:
        println("  Skipping %s: %s" % (name, str(e)))
        return False


def create_uninit_block(name, address, size, comment):
    """Create a non-volatile uninitialized memory block (DRAM)."""
    memory = currentProgram.getMemory()
    try:
        a = to_addr(address)
        block = memory.createUninitializedBlock(name, a, size, False)
        block.setRead(True)
        block.setWrite(True)
        block.setExecute(True)
        block.setComment(comment)
        return True
    except Exception as e:
        println("  Warning: %s: %s" % (name, str(e)))
        return False


def add_label(address, name, comment=None):
    """Add a label (and optional plate comment) at an address."""
    memory = currentProgram.getMemory()
    a = to_addr(address)
    if not memory.contains(a):
        return False
    try:
        currentProgram.getSymbolTable().createLabel(
            a, name, SourceType.IMPORTED)
        if comment:
            currentProgram.getListing().setComment(
                a, CodeUnit.PLATE_COMMENT, comment)
        return True
    except Exception as e:
        println("  Warning: label %s: %s" % (name, str(e)))
        return False


# =====================================================================
#  Main script
# =====================================================================

def detect_stage():
    """Auto-detect which bootloader stage based on program name or
    existing memory blocks."""
    name = currentProgram.getName().lower()
    if "nandboot" in name:
        return "nandboot"
    elif "kexec" in name or "trusted" in name:
        return "kexec_trusted_fw"
    else:
        # Try to detect from existing code block addresses
        memory = currentProgram.getMemory()
        for block in memory.getBlocks():
            start = block.getStart().getOffset()
            if start == NANDBOOT_BASE:
                return "nandboot"
            elif start == KEXEC_BASE:
                return "kexec_trusted_fw"
        return None


def run():
    stage = detect_stage()
    if stage is None:
        choice = askChoice(
            "HP Dune/Selene Bootloader",
            "Which bootloader stage is this?",
            ["First stage (nandboot)", "Second stage (kexec_trusted_fw)"],
            "First stage (nandboot)")
        stage = "nandboot" if "nandboot" in choice else "kexec_trusted_fw"

    if stage == "nandboot":
        baseAddr  = NANDBOOT_BASE
        entryAddr = NANDBOOT_ENTRY
    else:
        baseAddr  = KEXEC_BASE
        entryAddr = KEXEC_ENTRY

    println("HP Dune/Selene %s – applying DTS memory map..." % stage)
    println("  Base: 0x%08X  Entry: 0x%08X" % (baseAddr, entryAddr))

    # --- SRAM region for nandboot ---
    memory = currentProgram.getMemory()
    if stage == "nandboot":
        # Ensure the code block is writable (it's in SRAM)
        for block in memory.getBlocks():
            if block.getStart().getOffset() == NANDBOOT_BASE:
                block.setWrite(True)
                block.setComment(
                    "HP Dune/Selene nandboot - ARM Cortex-A7 BE8 (mapped into on-chip SRAM)")
                break
        # SRAM base is at 0x3C180000 but the range up to 0x3C200000
        # is shared with peripheral MMIO.  The SRAM block (0x1D00 bytes)
        # and peripherals are created individually in the peripheral loop.

    # --- Entry point ---
    entry = to_addr(entryAddr)
    if memory.contains(entry):
        currentProgram.getSymbolTable().addExternalEntryPoint(entry)
        add_label(entryAddr, "_entry",
                  "HP Dune/Selene %s entry point" % stage)
        println("  Entry point set at 0x%08X" % entryAddr)

    # --- ARM exception vector table (nandboot) ---
    if stage == "nandboot":
        println("Adding ARM exception vector table labels...")
        vector_names = [
            "vector_reset",           # 0x00
            "vector_undef",           # 0x04
            "vector_svc",             # 0x08 - Supervisor Call (SWI)
            "vector_prefetch_abort",  # 0x0C
            "vector_data_abort",      # 0x10
            "vector_reserved",        # 0x14
            "vector_irq",             # 0x18
            "vector_fiq",             # 0x1C
        ]
        for i, vname in enumerate(vector_names):
            add_label(baseAddr + (i * 4), vname)
        add_label(baseAddr, None,
                  "ARM exception vector table\n"
                  "SRAM base: 0x%08X\n"
                  "Binary mapped at: 0x%08X\n"
                  "Reset vector -> 0x%08X" % (SRAM_BASE, baseAddr, entryAddr))

    # --- Peripheral MMIO regions ---
    println("Creating %d peripheral MMIO regions..." % len(PERIPHERALS))
    created = 0
    for name, addr, size, comment in PERIPHERALS:
        if create_volatile_block(name, addr, size, comment):
            created += 1
    println("  Created %d / %d peripheral blocks" % (created, len(PERIPHERALS)))

    # --- DRAM regions ---
    println("Creating DRAM regions...")
    if stage == "nandboot":
        create_uninit_block("DRAM", DRAM_BASE, DRAM_SIZE,
            "Main DRAM - 512 MiB physical (477 MiB to Linux)")
    else:
        dram_before = 0x9FF00000 - DRAM_BASE
        create_uninit_block("DRAM", DRAM_BASE, dram_before,
            "Main DRAM up to trusted-FW boundary")

        hdr_size = baseAddr - 0x9FF00000
        if hdr_size > 0:
            create_uninit_block("TRUSTED_FW_HDR", 0x9FF00000, hdr_size,
                "Trusted FW region before kexec image")

        # Find end of loaded code block
        code_end = 0
        for block in memory.getBlocks():
            start = block.getStart().getOffset()
            if start == baseAddr:
                code_end = start + block.getSize()
                break

        tf_end = 0x9FF00000 + 0x100000
        if code_end > 0 and code_end < tf_end:
            create_uninit_block("TRUSTED_FW_TAIL", code_end, tf_end - code_end,
                "Trusted FW region after kexec image")

    # --- Reserved-memory landmark labels ---
    println("Adding reserved-memory labels...")
    for name, addr, comment in RESERVED_LABELS:
        add_label(addr, name, comment)

    # --- NAND partition info ---
    flash_addr = to_addr(0x38008000)
    if memory.contains(flash_addr):
        parts_text = "NAND Flash Partition Table:\n"
        for pname, poff, psize, ro in NAND_PARTITIONS:
            flag = "(ro)" if ro else "(rw)"
            parts_text += "  %-16s  0x%08X  size 0x%08X  %s\n" % (
                pname, poff, psize, flag)
        currentProgram.getListing().setComment(
            flash_addr, CodeUnit.PLATE_COMMENT, parts_text)

    # --- Cross-stage reference labels ---
    add_label(NANDBOOT_BASE,  "NANDBOOT_LOAD_ADDR")
    add_label(NANDBOOT_ENTRY, "NANDBOOT_ENTRY")
    add_label(KEXEC_BASE,     "KEXEC_TFW_LOAD_ADDR")
    add_label(KEXEC_ENTRY,    "KEXEC_TFW_ENTRY")

    println("Done. HP Dune/Selene %s memory map applied." % stage)


# Wrap in a transaction
from ghidra.program.model.listing import Program
txId = currentProgram.startTransaction("HP Dune/Selene Memory Map")
try:
    run()
    currentProgram.endTransaction(txId, True)
except Exception as e:
    currentProgram.endTransaction(txId, False)
    println("ERROR: " + str(e))
    raise
