/**
 * Ghidra Loader for HP Color LaserJet Pro MFP 4301-4303 (Dune/Selene platform)
 * bootloader images.
 *
 * Supports two stages:
 *   - First stage  (NAND boot):       dune_selene_nandboot.bin
 *       Load address 0x3C200000, entry point 0x3C200A04
 *   - Second stage (kexec trusted FW): dune_selene_kexec_trusted_fw.bin
 *       Load address 0x9FF10680, entry point 0x9FF10F24
 *
 * Both images use ARM BE8 (byte-invariant big-endian): instructions are
 * little-endian while data is big-endian.  Ghidra's ARM:LEBE:32:v7LEInstruction
 * language handles this correctly for ARMv7-A cores in BE8 mode.
 *
 * The peripheral memory map and reserved-memory regions are derived from the
 * accompanying kernel.dts (device-tree source) for the HP tx54 SoC.
 */
package hpduneselene;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitor;

public class HPDuneSeleneLoader extends AbstractLibrarySupportLoader {

    /* --------------------------------------------------------------------
     *  Stage identification
     * ----------------------------------------------------------------- */
    private static final String LOADER_NAME = "HP Dune/Selene Bootloader (BE8)";

    private static final String NANDBOOT_TAG        = "nandboot";
    private static final String KEXEC_TRUSTED_TAG   = "kexec_trusted_fw";

    /* First stage – NAND boot */
    private static final long NANDBOOT_BASE  = 0x3C200000L;
    private static final long NANDBOOT_ENTRY = 0x3C200A04L;

    /* Second stage – kexec trusted firmware */
    private static final long KEXEC_BASE     = 0x9FF10680L;
    private static final long KEXEC_ENTRY    = 0x9FF10F24L;

    /* On-chip SRAM – the nandboot binary is mapped within this region */
    private static final long SRAM_BASE      = 0x3C180000L;
    private static final long SRAM_PRE_SIZE  = NANDBOOT_BASE - SRAM_BASE;  /* 0x80000 */

    /* ====================================================================
     *  Peripheral / memory-region definitions derived from kernel.dts
     * ==================================================================*/

    /**
     * A simple descriptor for a memory-mapped I/O peripheral block.
     */
    private static class PeriphDef {
        final String name;
        final long   addr;
        final long   size;
        final String comment;

        PeriphDef(String name, long addr, long size, String comment) {
            this.name    = name;
            this.addr    = addr;
            this.size    = size;
            this.comment = comment;
        }
    }

    /* Peripheral MMIO regions ------------------------------------------ */
    private static final PeriphDef[] PERIPHERALS = {

        /* ---- NAND flash controller ---- */
        new PeriphDef("NAND_FLASH_CTRL",  0x38008000L, 0x700,
            "hp,flash – NAND flash controller"),

        /* ---- CCI-400 interconnect ---- */
        new PeriphDef("CCI400",           0x38390000L, 0x6000,
            "arm,cci-400 – Cache Coherent Interconnect"),

        /* ---- GIC (Generic Interrupt Controller) ---- */
        new PeriphDef("GIC_DIST",         0x38401000L, 0x1000,
            "arm,cortex-a7-gic – GIC Distributor"),
        new PeriphDef("GIC_CPU_IF",       0x38402000L, 0x2000,
            "arm,cortex-a7-gic – GIC CPU Interface"),

        /* ---- Clock / system config registers ---- */
        new PeriphDef("SDIOH_CLK_SEL",    0x3C004008L, 0x04,
            "Arasan SDIO host – clock select register"),
        new PeriphDef("CLOCKSYS_DIV",     0x3C004010L, 0x04,
            "Arasan SDIO host – clocksys divider register"),
        new PeriphDef("SDIOH_DRV_STR",    0x3C00D070L, 0x04,
            "Arasan SDIO host – drive-strength register"),
        new PeriphDef("SDIO_PAD_VOLT",    0x3C00D094L, 0x04,
            "Arasan SDIO host – pad voltage register"),

        /* ---- Reset controller ---- */
        new PeriphDef("RESET_CTRL",       0x3C013000L, 0x100,
            "hp,reset – Reset controller (secure)"),

        /* ---- SPI (SPIRF) ---- */
        new PeriphDef("SPI_SPIRF_0",      0x3C015000L, 0x100,
            "hp-spi-spirf – SPI controller 0"),
        new PeriphDef("SPI_SPIRF_1",      0x3C016000L, 0x100,
            "hp-spi-spirf – SPI controller 1"),

        /* ---- Ethernet / clock misc ---- */
        new PeriphDef("ETH_CLK_CTRL",     0x3C01E000L, 0x30,
            "Ethernet / MDIO clock control registers"),

        /* ---- USB PHY ---- */
        new PeriphDef("USB_PHY_0",        0x3C021000L, 0x100,
            "hp,usb-phy – USB PHY register bank 0"),
        new PeriphDef("USB_PHY_1",        0x3C022000L, 0x100,
            "hp,usb-phy – USB PHY register bank 1"),

        /* ---- I2C ---- */
        new PeriphDef("I2C_INST_0",       0x3C029000L, 0x100,
            "hp,i2c-1 – I2C instance 0 (bus 2, EEPROM)"),
        new PeriphDef("I2C_INST_3",       0x3C02F000L, 0x100,
            "hp,i2c – I2C instance 3 (bus 1)"),

        /* ---- Ethernet MAC / MDIO ---- */
        new PeriphDef("ETHERNET",         0x3C174000L, 0x100,
            "hp,hpumac-3.0 – Ethernet MAC (includes MDIO at +0x80)"),

        /* ---- SRAM (USB endpoint SRAM, 0x1D00 bytes per DTS) ----
         * The broader range 0x3C180000–0x3C200000 is shared between
         * SRAM and peripheral MMIO.  We only map the USB SRAM portion
         * here; the rest of this range is covered by individual
         * peripheral blocks (USB host, endpoints, SDIO, etc.). */
        new PeriphDef("SRAM",             0x3C180000L, 0x1D00,
            "On-chip SRAM – USB endpoint SRAM; nandboot mapped at 0x3C200000"),

        /* ---- USB host controllers ---- */
        new PeriphDef("USB_HOST_CTRL",    0x3C19E000L, 0x100,
            "hp,usb_host – USB host controller"),
        new PeriphDef("USB_EHCI",         0x3C19F000L, 0x100,
            "generic-ehci – EHCI registers (big-endian)"),
        new PeriphDef("USB_OHCI",         0x3C1A0000L, 0x100,
            "generic-ohci – OHCI registers (big-endian)"),

        /* ---- USB device controller endpoints ---- */
        new PeriphDef("USB_EP0",          0x3C1A2000L, 0x40, "UDC endpoint 0 (bidi)"),
        new PeriphDef("USB_EP1",          0x3C1A3000L, 0x40, "UDC endpoint 1 (bulk)"),
        new PeriphDef("USB_EP2",          0x3C1A4000L, 0x40, "UDC endpoint 2 (bulk)"),
        new PeriphDef("USB_EP3",          0x3C1A5000L, 0x40, "UDC endpoint 3 (bulk)"),
        new PeriphDef("USB_EP4",          0x3C1A6000L, 0x40, "UDC endpoint 4 (bulk)"),
        new PeriphDef("USB_EP5",          0x3C1A7000L, 0x40, "UDC endpoint 5 (bulk)"),
        new PeriphDef("USB_EP6",          0x3C1A8000L, 0x40, "UDC endpoint 6 (bulk)"),
        new PeriphDef("USB_EP7",          0x3C1A9000L, 0x40, "UDC endpoint 7 (bulk)"),
        new PeriphDef("USB_EP8",          0x3C1AA000L, 0x40, "UDC endpoint 8 (bulk)"),
        new PeriphDef("USB_EP9",          0x3C1AB000L, 0x40, "UDC endpoint 9 (bulk)"),
        new PeriphDef("USB_EP10",         0x3C1AC000L, 0x40, "UDC endpoint 10 (bulk)"),
        new PeriphDef("USB_EP11",         0x3C1AD000L, 0x40, "UDC endpoint 11 (bulk)"),
        new PeriphDef("USB_EP12",         0x3C1AE000L, 0x40, "UDC endpoint 12 (bulk)"),
        new PeriphDef("USB_EP13",         0x3C1AF000L, 0x40, "UDC endpoint 13 (bulk)"),
        new PeriphDef("USB_EP14",         0x3C1B0000L, 0x40, "UDC endpoint 14 (bulk)"),
        new PeriphDef("USB_EP15",         0x3C1B1000L, 0x40, "UDC endpoint 15 (bulk)"),

        /* ---- USB device controller ---- */
        new PeriphDef("USB_DEV_CTRL",     0x3C1B2000L, 0x80,
            "hp,usb-device / hp-udc – USB device controller"),

        /* ---- SDIO (Arasan) ---- */
        new PeriphDef("SDIO_HOST",        0x3C1B4000L, 0x100,
            "hp,arasan_sdio_host0 – SDIO host IP"),
        new PeriphDef("SDIO_HOST_CFG",    0x3C1B5000L, 0x100,
            "Arasan SDIO host – configuration registers"),

        /* ---- Audio ---- */
        new PeriphDef("AUDIO",            0x3C1BC000L, 0x100,
            "hp-audio – Audio controller"),

        /* ---- GPIO ---- */
        new PeriphDef("GPIO",             0x3C1C6000L, 0xA60,
            "hp-gpio – GPIO controller"),

        /* ---- UARTs ---- */
        new PeriphDef("UART0",            0x3C1C7000L, 0x100,
            "hp,rs-uart – UART 0 (serial0, 115200 console)"),
        new PeriphDef("UART1",            0x3C1C8000L, 0x100,
            "hp,rs-uart – UART 1 (serial1)"),
        new PeriphDef("UART2",            0x3C1C9000L, 0x100,
            "hp,rs-uart – UART 2 (disabled)"),
        new PeriphDef("UART3",            0x3C1CA000L, 0x100,
            "hp,rs-uart – UART 3 (disabled, 64-byte FIFO)"),

        /* ---- ARM Cortex-A7 configuration ---- */
        new PeriphDef("ARM_A7_CFG_0",    0x3C540000L, 0x100,
            "hp,arm-a7-config – Configuration bank 0"),
        new PeriphDef("ARM_A7_CFG_1",    0x3C541000L, 0x100,
            "hp,arm-a7-config – Configuration bank 1"),
        new PeriphDef("ARM_A7_CFG_2",    0x3C542000L, 0x1100,
            "hp,arm-a7-config – Configuration bank 2"),

        /* ---- Hardware trace ---- */
        new PeriphDef("HW_TRACE",         0x3C896000L, 0x1000,
            "hp,hwtrace – Hardware trace (BE data, slot=4)"),

        /* ---- Microkernel power management ---- */
        new PeriphDef("UKERNEL_PM",       0x3F826000L, 0x300,
            "ukernel_pm_driver – Microkernel power management"),

        /* ---- LCD controller (multiple register banks) ---- */
        new PeriphDef("LCD_CTRL",         0x3F99A000L, 0x70,
            "hp,lcdc – LCD controller main"),
        new PeriphDef("LCD_CFG_1",        0x3F99C000L, 0x30,
            "hp,lcdc – LCD config bank 1"),
        new PeriphDef("LCD_CFG_2",        0x3F99E000L, 0x18,
            "hp,lcdc – LCD config bank 2"),

        /* ---- Microkernel SRAM ---- */
        new PeriphDef("UKERNEL_SRAM_WR",  0x3F9A0000L, 0x400,
            "mmio-sram – Microkernel SRAM (write region)"),
        new PeriphDef("UKERNEL_SRAM_RD",  0x3F9A0400L, 0x400,
            "mmio-sram – Microkernel SRAM (read region)"),

        /* ---- LCD controller continued ---- */
        new PeriphDef("LCD_LAYER_0",      0x3F9A2000L, 0x38,
            "hp,lcdc – LCD layer 0"),
        new PeriphDef("LCD_LAYER_1",      0x3F9A4000L, 0x38,
            "hp,lcdc – LCD layer 1"),
        new PeriphDef("LCD_LAYER_2",      0x3F9A6000L, 0x38,
            "hp,lcdc – LCD layer 2"),
        new PeriphDef("LCD_CURSOR",       0x3F9A8000L, 0x20,
            "hp,lcdc – LCD cursor"),
    };

    /* DRAM / reserved-memory landmark addresses (from DTS) ------------- */
    private static final long DRAM_BASE       = 0x80000000L;
    private static final long DRAM_SIZE       = 0x20000000L;   /* 512 MiB physical */
    private static final long DRAM_LINUX_SIZE = 0x1D700000L;   /* 477 MiB for Linux */

    /**
     * A descriptor for a notable DRAM sub-region or landmark address.
     */
    private static class MemRegionDef {
        final String name;
        final long   addr;
        final long   size;
        final String comment;

        MemRegionDef(String name, long addr, long size, String comment) {
            this.name    = name;
            this.addr    = addr;
            this.size    = size;
            this.comment = comment;
        }
    }

    private static final MemRegionDef[] RESERVED_REGIONS = {
        new MemRegionDef("kernel_load",       0x81000000L, 0,
            "phys_load_addr – kernel load address"),
        new MemRegionDef("rpc_memory",        0x93E00000L, 0x100000L,
            "reserved-memory – RPC shared memory"),
        new MemRegionDef("cgd_buffer",        0x93F40000L, 0x0C0000L,
            "reserved-memory – CGD frame buffer"),
        new MemRegionDef("devicetree_load",   0x93F3A000L, 0,
            "phys_load_addr – device-tree blob load address"),
        new MemRegionDef("shared_memory",     0x94000000L, 0x9700000L,
            "reserved-memory – DuneSharedMemory (FIFO, 64-byte aligned)"),
        new MemRegionDef("dox_memory",        0x9D700000L, 0x2800000L,
            "reserved-memory – DOX remote processor memory (no-map)"),
        new MemRegionDef("trusted_fw",        0x9FF00000L, 0x0100000L,
            "reserved-memory – Trusted firmware region (no-map)"),
    };

    /* NAND flash partition table (informational labels) ---------------- */
    private static class NandPartDef {
        final String name;
        final long   offset;
        final long   size;
        final boolean readOnly;

        NandPartDef(String name, long offset, long size, boolean readOnly) {
            this.name     = name;
            this.offset   = offset;
            this.size     = size;
            this.readOnly = readOnly;
        }
    }

    private static final NandPartDef[] NAND_PARTITIONS = {
        new NandPartDef("Boot",            0x00000000L, 0x00040000L, true),
        new NandPartDef("UpdatableLBI",    0x00040000L, 0x00500000L, true),
        new NandPartDef("RootFS",          0x00540000L, 0x106C0000L, true),
        new NandPartDef("RWFS",            0x10C00000L, 0x08E60000L, false),
        new NandPartDef("RecoveryRootFS",  0x19A60000L, 0x06100000L, true),
        new NandPartDef("RecoveryLBI",     0x1FB60000L, 0x004A0000L, true),
    };

    /* ====================================================================
     *  Loader interface
     * ==================================================================*/

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    /**
     * Identify whether we can load this file.  We match on filename
     * containing either "nandboot" or "kexec_trusted_fw".
     */
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
            throws IOException {

        List<LoadSpec> specs = new ArrayList<>();
        String lowerName = provider.getName().toLowerCase();

        if (lowerName.contains(NANDBOOT_TAG) || lowerName.contains(KEXEC_TRUSTED_TAG)) {
            /*
             * ARM:LEBE:32:v7LEInstruction – Ghidra's ARM BE8 language.
             * For ARMv7-A (Cortex-A7) in BE8 mode, instructions are stored
             * little-endian while data accesses are big-endian.
             */
            specs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("ARM:LEBE:32:v7LEInstruction", "default"), true));
        }

        return specs;
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
            throws CancelledException, IOException {

        ByteProvider provider = settings.provider();
        TaskMonitor monitor   = settings.monitor();
        MessageLog log        = settings.log();

        String lowerName = provider.getName().toLowerCase();
        boolean isNandboot = lowerName.contains(NANDBOOT_TAG);

        long baseAddr  = isNandboot ? NANDBOOT_BASE  : KEXEC_BASE;
        long entryAddr = isNandboot ? NANDBOOT_ENTRY  : KEXEC_ENTRY;
        String stage   = isNandboot ? "nandboot"      : "kexec_trusted_fw";

        FlatProgramAPI api = new FlatProgramAPI(program, monitor);
        Memory memory      = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symTab = program.getSymbolTable();

        try {
            /* ----------------------------------------------------------
             *  1) Load the binary image
             * -------------------------------------------------------- */
            monitor.setMessage("Loading " + stage + " image...");
            Address loadAddress = space.getAddress(baseAddr);

            /*
             * For the first-stage bootloader the binary is mapped into
             * on-chip SRAM (base 0x3C180000) at offset 0x3C200000.
             * The ARM exception vector table sits at 0x3C200000 and the
             * reset vector points to the entry point at 0x3C200A04.
             * We create the SRAM region before the binary as a separate
             * uninitialized block.
             *
             * For the second-stage bootloader the binary resides in
             * the trusted-FW reserved DRAM region at 0x9FF10680.
             */
            try (InputStream is = provider.getInputStream(0)) {
                MemoryBlock codeBlock = memory.createInitializedBlock(
                    stage, loadAddress, is, provider.length(), monitor, false);
                codeBlock.setRead(true);
                codeBlock.setWrite(true);   /* SRAM / RAM – writable */
                codeBlock.setExecute(true);
                codeBlock.setComment(
                    "HP Dune/Selene " + stage + " – ARM Cortex-A7 BE8" +
                    (isNandboot ? " (mapped into on-chip SRAM)" : " (trusted-FW DRAM)"));
            }

            /* SRAM base is at 0x3C180000 but the range up to 0x3C200000
             * is shared with peripheral MMIO (USB, SDIO, GPIO, UARTs).
             * The SRAM block (0x1D00 bytes) and peripherals are created
             * individually in step 3 below. */

            /* ----------------------------------------------------------
             *  2) Entry point and vector table
             *
             * NOTE: Do NOT call program.setImageBase() here.  All blocks
             * are created at absolute addresses.  Calling setImageBase
             * with commit=true would shift every existing block by the
             * base address delta, corrupting the memory map.
             * -------------------------------------------------------- */
            Address entry = space.getAddress(entryAddr);
            symTab.addExternalEntryPoint(entry);
            try {
                symTab.createLabel(entry, "_entry", SourceType.IMPORTED);
            } catch (InvalidInputException e) {
                log.appendMsg("Warning: could not create entry label: " + e.getMessage());
            }

            /* ARM exception vector table at the load base.
             * Each vector is a 4-byte instruction (branch / LDR PC). */
            if (isNandboot) {
                String[] vectorNames = {
                    "vector_reset",           /* 0x00 */
                    "vector_undef",           /* 0x04 */
                    "vector_svc",             /* 0x08 – Supervisor Call (SWI) */
                    "vector_prefetch_abort",  /* 0x0C */
                    "vector_data_abort",      /* 0x10 */
                    "vector_reserved",        /* 0x14 */
                    "vector_irq",             /* 0x18 */
                    "vector_fiq",             /* 0x1C */
                };
                for (int i = 0; i < vectorNames.length; i++) {
                    Address va = space.getAddress(baseAddr + (i * 4));
                    try {
                        symTab.createLabel(va, vectorNames[i],
                            SourceType.IMPORTED);
                    } catch (InvalidInputException e) {
                        log.appendMsg("Warning: vector label: " + e.getMessage());
                    }
                }
                /* Plate comment on the vector table */
                setPlateComment(program, loadAddress,
                    "ARM exception vector table\n" +
                    "SRAM base: 0x" + Long.toHexString(SRAM_BASE) + "\n" +
                    "Binary mapped at: 0x" + Long.toHexString(baseAddr) + "\n" +
                    "Reset vector -> 0x" + Long.toHexString(entryAddr));
            }

            /* ----------------------------------------------------------
             *  3) Create peripheral MMIO regions
             * -------------------------------------------------------- */
            monitor.setMessage("Creating peripheral memory map...");
            for (PeriphDef p : PERIPHERALS) {
                createVolatileBlock(memory, space, symTab, p.name,
                    p.addr, p.size, p.comment, log);
            }

            /* ----------------------------------------------------------
             *  4) Create DRAM regions
             * -------------------------------------------------------- */
            monitor.setMessage("Creating DRAM regions...");
            if (isNandboot) {
                /* Nandboot: code is at 0x3C2xxxxx (SoC space), so
                 * the entire 512 MiB DRAM window is available. */
                createUninitBlock(memory, space, "DRAM",
                    DRAM_BASE, DRAM_SIZE,
                    "Main DRAM – 512 MiB physical (477 MiB to Linux)", log);
            } else {
                /* kexec_trusted_fw sits inside the trusted-FW reserved
                 * region at 0x9FF00000.  Create DRAM up to that point,
                 * then a small header region before the code. */
                long dramBeforeTF = 0x9FF00000L - DRAM_BASE;
                createUninitBlock(memory, space, "DRAM",
                    DRAM_BASE, dramBeforeTF,
                    "Main DRAM up to trusted-FW boundary", log);

                long hdrSize = baseAddr - 0x9FF00000L;
                if (hdrSize > 0) {
                    createUninitBlock(memory, space, "TRUSTED_FW_HDR",
                        0x9FF00000L, hdrSize,
                        "Trusted FW region before kexec image", log);
                }

                /* Trailing region after the loaded binary (if any) */
                long codeEnd = baseAddr + provider.length();
                long tfEnd   = 0x9FF00000L + 0x100000L;
                if (codeEnd < tfEnd) {
                    createUninitBlock(memory, space, "TRUSTED_FW_TAIL",
                        codeEnd, tfEnd - codeEnd,
                        "Trusted FW region after kexec image", log);
                }
            }

            /* ----------------------------------------------------------
             *  5) Add landmark labels in DRAM
             * -------------------------------------------------------- */
            monitor.setMessage("Adding reserved-memory labels...");
            for (MemRegionDef r : RESERVED_REGIONS) {
                Address a = space.getAddress(r.addr);
                /* Only add labels inside existing blocks to avoid errors */
                if (memory.contains(a)) {
                    try {
                        symTab.createLabel(a, r.name, SourceType.IMPORTED);
                        setPlateComment(program, a, r.comment);
                    } catch (InvalidInputException e) {
                        log.appendMsg("Warning: label " + r.name + ": " + e.getMessage());
                    }
                }
            }

            /* ----------------------------------------------------------
             *  6) Add NAND partition info as plate comments on the
             *     flash controller base address (informational).
             * -------------------------------------------------------- */
            Address flashBase = space.getAddress(0x38008000L);
            if (memory.contains(flashBase)) {
                StringBuilder sb = new StringBuilder();
                sb.append("NAND Flash Partition Table:\n");
                for (NandPartDef np : NAND_PARTITIONS) {
                    sb.append(String.format("  %-16s  0x%08X  size 0x%08X  %s\n",
                        np.name, np.offset, np.size,
                        np.readOnly ? "(ro)" : "(rw)"));
                }
                setPlateComment(program, flashBase, sb.toString());
            }

            /* ----------------------------------------------------------
             *  7) Add SoC-level informational labels
             * -------------------------------------------------------- */
            addInfoLabel(symTab, space, memory, 0x3C200000L,
                "NANDBOOT_LOAD_ADDR", log);
            addInfoLabel(symTab, space, memory, 0x3C200A04L,
                "NANDBOOT_ENTRY", log);
            addInfoLabel(symTab, space, memory, 0x9FF10680L,
                "KEXEC_TFW_LOAD_ADDR", log);
            addInfoLabel(symTab, space, memory, 0x9FF10F24L,
                "KEXEC_TFW_ENTRY", log);

            log.appendMsg("HP Dune/Selene " + stage +
                " loaded successfully at 0x" + Long.toHexString(baseAddr));

        } catch (Exception e) {
            throw new IOException("Failed to load HP Dune/Selene image: " +
                e.getMessage(), e);
        }
    }

    /* ====================================================================
     *  Helper methods
     * ==================================================================*/

    /**
     * Create an uninitialized, volatile memory block for an MMIO peripheral
     * and add a label + plate comment at its base address.
     */
    private void createVolatileBlock(Memory memory, AddressSpace space,
            SymbolTable symTab, String name, long addr, long size,
            String comment, MessageLog log) {
        try {
            Address a = space.getAddress(addr);
            MemoryBlock block = memory.createUninitializedBlock(
                name, a, size, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            block.setVolatile(true);

            symTab.createLabel(a, name + "_BASE", SourceType.IMPORTED);
            /* Add the DTS-derived description as a plate comment */
            setPlateComment(memory.getProgram(), a, comment);
        } catch (MemoryConflictException e) {
            log.appendMsg("Skipping " + name + " (conflict): " + e.getMessage());
        } catch (AddressOverflowException e) {
            log.appendMsg("Skipping " + name + " (overflow): " + e.getMessage());
        } catch (InvalidInputException e) {
            log.appendMsg("Warning: label for " + name + ": " + e.getMessage());
        } catch (Exception e) {
            log.appendMsg("Error creating " + name + ": " + e.getMessage());
        }
    }

    /**
     * Create a plain uninitialized (non-volatile) memory block – used for
     * DRAM regions.
     */
    private void createUninitBlock(Memory memory, AddressSpace space,
            String name, long addr, long size, String comment,
            MessageLog log) {
        try {
            Address a = space.getAddress(addr);
            MemoryBlock block = memory.createUninitializedBlock(
                name, a, size, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(true);
            block.setComment(comment);
        } catch (Exception e) {
            log.appendMsg("Warning: DRAM block " + name + ": " + e.getMessage());
        }
    }

    /**
     * Set a plate comment on a CodeUnit at the given address.
     * Uses the non-deprecated CodeUnit.setComment() API.
     */
    private void setPlateComment(Program program, Address addr, String comment) {
        CodeUnit cu = program.getListing().getCodeUnitAt(addr);
        if (cu != null) {
            cu.setComment(CommentType.PLATE, comment);
        }
    }

    /**
     * Add an informational label if the address falls within an existing
     * memory block (silently skips otherwise).
     */
    private void addInfoLabel(SymbolTable symTab, AddressSpace space,
            Memory memory, long addr, String label, MessageLog log) {
        try {
            Address a = space.getAddress(addr);
            if (memory.contains(a)) {
                symTab.createLabel(a, label, SourceType.IMPORTED);
            }
        } catch (InvalidInputException e) {
            log.appendMsg("Warning: label " + label + ": " + e.getMessage());
        }
    }

}
