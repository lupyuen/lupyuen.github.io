# Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone

📝 _25 Aug 2022_

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-title.png)

_Ghidra with Apache NuttX RTOS for Arm Cortex-A53_

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/what)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) (Real-Time Operating System) runs on 64-bit __Arm Cortex-A53__ with Multiple Cores...

-   [__NuttX on Arm Cortex-A53__](https://github.com/apache/nuttx/tree/master/boards/arm64/qemu/qemu-armv8a)

__Pine64 PinePhone__ is based on the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) with 4 Cores of Arm Cortex-A53...

-   [__PinePhone Wiki__](https://wiki.pine64.org/index.php/PinePhone)

Will NuttX run on PinePhone? Let's find out!

_Why NuttX?_

NuttX is a __tiny operating system__. It might be a fun way to teach more people about the internals of Phone Operating Systems. (Without digging deep into the Linux Stack)

Someday we might have a cheap, fast, responsive and tweakable phone running on NuttX!

_But why an RTOS for PinePhone? What about drivers and apps?_

Yep we have interesting challenges running NuttX on PinePhone, we'll talk more below.

First we experiment with NuttX on Arm Cortex-A53, __emulated with QEMU__. Then we discuss how it might work on PinePhone...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

Many thanks to [__qinwei2004__](https://github.com/qinwei2004) and the NuttX Team for implementing [__Cortex-A53 support__](https://github.com/apache/nuttx/pull/6478)!

# Download NuttX

__NuttX Mainline__ has the latest support for Arm Cortex-A53. We download the Source Code for our experiment...

```bash
## Create NuttX Directory
mkdir nuttx
cd nuttx

## Download NuttX OS
git clone \
    --recursive \
    https://github.com/apache/nuttx \
    nuttx

## Download NuttX Apps
git clone \
    --recursive \
    https://github.com/apache/nuttx-apps \
    apps

## We'll build NuttX inside nuttx/nuttx
cd nuttx
```

[(Having problems? Try my __`arm64`__ branch)](https://github.com/lupyuen/pinephone-nuttx#download-nuttx)

We'll build NuttX in a while. Install the __Build Prerequisites__ below, but skip the RISC-V Toolchain...

-   [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

Let's download the Arm64 Toolchain instead...

![Arm64 Toolchain](https://lupyuen.github.io/images/arm-toolchain.png)

# Download Toolchain

We'll __cross-compile Arm64 NuttX__ on our computer. Download the Arm Toolchain for __AArch64 ELF Bare-Metal Target `aarch64-none-elf`__...

-   [__Arm GNU Toolchain Downloads__](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

For Linux x64 and WSL:

-   [gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf.tar.xz](https://developer.arm.com/-/media/Files/downloads/gnu/11.2-2022.02/binrel/gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf.tar.xz)

For macOS:

-   [arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.pkg](https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.pkg)

(I don't recommend building NuttX on Plain Old Windows CMD, please use WSL instead)

Add the downloaded Arm Toolchain to the __`PATH`__...

```bash
## For Linux x64 and WSL:
export PATH="$PATH:$HOME/gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf/bin"

## For macOS:
export PATH="$PATH:/Applications/ArmGNUToolchain/11.3.rel1/aarch64-none-elf/bin"
```

Check the Arm Toolchain...

```bash
$ aarch64-none-elf-gcc -v
gcc version 11.3.1 20220712 (Arm GNU Toolchain 11.3.Rel1)
```

[(Based on the instructions here)](https://github.com/apache/nuttx/tree/master/boards/arm64/qemu/qemu-armv8a)

# Download QEMU

Our experiment today will run on any Linux / macOS / Windows computer, __no PinePhone needed__.

That's because we're emulating Arm Cortex-A53 with the awesome [__QEMU Machine Emulator__](https://www.qemu.org/).

Download and install QEMU...

-   [__Download QEMU__](https://www.qemu.org/download/)

For macOS we may use __`brew`__...

```bash
brew install qemu
```

QEMU runs surprisingly well for emulating 64-bit Arm Cortex-A53, especially for a light operating system like NuttX.

![Build NuttX](https://lupyuen.github.io/images/arm-build.png)

# Build NuttX: Single Core

We'll run two experiments with QEMU...

-   NuttX on a __Single Core__ of Arm Cortex-A53

-   NuttX on __4 Cores__ of Arm Cortex-A53

Which works like 4 Arm64 Processors running in parallel, similar to PinePhone.

First we build NuttX for a __Single Core__ of Arm Cortex-A53...

```bash
## Configure NuttX for Single Core
./tools/configure.sh -l qemu-armv8a:nsh

## Build NuttX
make

## Dump the disassembly to nuttx.S
aarch64-none-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

[(See the Build Log)](https://gist.github.com/lupyuen/2c5db82c3103f52ed7ca99804f9220c1)

(On an old MacBook Pro 2012, NuttX builds in 2 minutes)

The NuttX Output Files may be found here...

-   [__NuttX for Arm Cortex-A53 Single Core__](https://github.com/lupyuen/pinephone-nuttx/releases/tag/v1.0.1)

The output file [__`nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.1/nuttx) is the Arm64 [__ELF Executable__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) that we'll run in the next step.

# Test NuttX: Single Core

We're ready to run NuttX! This is how we test __NuttX on QEMU__ with a Single Core of Arm Cortex-A53...

```bash
## Start QEMU (Single Core) with NuttX
qemu-system-aarch64 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

[(More about QEMU "virt" Machine)](https://www.qemu.org/docs/master/system/arm/virt.html)

QEMU shows this...

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x402c4000, heap_size=0x7d3c000
gic_validate_dist_version: GICv3 version detect
gic_validate_dist_version: GICD_TYPER = 0x37a0007
gic_validate_dist_version: 224 SPIs implemented
gic_validate_dist_version: 0 Extended SPIs implemented
gic_validate_dist_version: Distributor has no Range Selector support
gic_validate_redist_version: GICD_TYPER = 0x1000011
gic_validate_redist_version: 16 PPIs implemented
gic_validate_redist_version: no VLPI support, no direct LPI support
up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 62.50MHz, cycle 62500
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x402a7000 _einit: 0x402a7000 _stext: 0x40280000 _etext: 0x402a8000
nsh: sysinit: fopen failed: 2
nsh: mkfatfs: command not found

NuttShell (NSH) NuttX-10.4.0
nsh> nx_start: CPU0: Beginning Idle Loop
```

Welcome to NuttX Land!

Enter "__`help`__" or "__`?`__" to see the __NuttX Commands__...

```text
nsh> help
help usage:  help [-v] [<cmd>]

  .         cd        dmesg     help      mount     rmdir     true      xd        
  [         cp        echo      hexdump   mv        set       truncate  
  ?         cmp       exec      kill      printf    sleep     uname     
  basename  dirname   exit      ls        ps        source    umount    
  break     dd        false     mkdir     pwd       test      unset     
  cat       df        free      mkrd      rm        time      usleep    

Builtin Apps:
  getprime  hello     nsh       ostest    sh        
```

To be really sure that we're __emulating Arm64__...

```text
nsh> uname -a
NuttX 10.3.0-RC2 1e8f2a8 Aug 23 2022 07:04:54 arm64 qemu-armv8a
```

[__"Hello World"__](https://github.com/apache/nuttx-apps/blob/master/examples/hello/hello_main.c) works as expected...

```text
nsh> hello
task_spawn: name=hello entry=0x4029b594 file_actions=0x402c9580 attr=0x402c9588 argv=0x402c96d0
spawn_execattrs: Setting policy=2 priority=100 for pid=3
Hello, World!!
```

NuttX is [__POSIX Compliant__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html), so the Developer Experience feels very much like Linux (but much smaller)...

```text
nsh> ls /
/:
 dev/
 etc/
 proc/
```

We started the Bare Minimum of __NuttX Devices__...

```text
nsh> ls /dev
/dev:
 console
 null
 ram0
 ram2
 ttyS0
 zero
```

With a few __Background Processes__...

```text
nsh> ls /proc
/proc:
 0/
 1/
 2/
 meminfo
 memdump
 fs/
 self/
 uptime
 version
```

And NuttX runs __everything in RAM__, no File System needed (for today)...

```text
nsh> ls /etc
/etc:
 init.d/

nsh> ls /etc/init.d
/etc/init.d:
 rcS

nsh> cat /etc/init.d/rcS
## Create a RAMDISK and mount it at /tmp
mkrd -m 2 -s 512 1024
mkfatfs /dev/ram2
mount -t vfat /dev/ram2 /tmp
```

Press __Ctrl-C__ to quit QEMU.

# Build NuttX: Multi Core

From Single Core to Multi Core! Now we build NuttX for __4 Cores__ of Arm Cortex-A53...

```bash
## Erase the NuttX Configuration
make distclean

## Configure NuttX for 4 Cores
./tools/configure.sh -l qemu-armv8a:nsh_smp

## Build NuttX
make

## Dump the disassembly to nuttx.S
aarch64-none-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

The NuttX Output Files may be found here...

-   [__NuttX for Arm Cortex-A53 Multi-Core__](https://github.com/lupyuen/pinephone-nuttx/releases/tag/v1.0.0)

# Test NuttX: Multi Core

And this is how we test NuttX on QEMU with __4 Cores__ of Arm Cortex-A53...

```bash
## Start QEMU (4 Cores) with NuttX
qemu-system-aarch64 \
  -smp 4 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

Note that __`smp`__ is set to 4. [(Symmetric Multi-Processing)](https://developer.arm.com/documentation/den0024/a/Multi-core-processors/Multi-processing-systems/Symmetric-multi-processing?lang=en)

QEMU shows this...

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
```

NuttX boots on the __First Core__ of our emulated Arm Cortex-A53...

```text
[CPU0] psci_detect: Detected PSCI v1.1
[CPU0] nx_start: Entry
[CPU0] up_allocate_heap: heap_start=0x0x402db000, heap_size=0x7d25000
[CPU0] gic_validate_dist_version: GICv3 version detect
[CPU0] gic_validate_dist_version: GICD_TYPER = 0x37a0007
[CPU0] gic_validate_dist_version: 224 SPIs implemented
[CPU0] gic_validate_dist_version: 0 Extended SPIs implemented
[CPU0] gic_validate_dist_version: Distributor has no Range Selector support
[CPU0] gic_validate_redist_version: GICD_TYPER = 0x1000001
[CPU0] gic_validate_redist_version: 16 PPIs implemented
[CPU0] gic_validate_redist_version: no VLPI support, no direct LPI support
[CPU0] up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 62.50MHz, cycle 62500
[CPU0] uart_register: Registering /dev/console
[CPU0] uart_register: Registering /dev/ttyS0
```

Here comes excitement: NuttX boots on the __Second Core__ of our Arm Cortex-A53!

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

[CPU1] gic_validate_redist_version: GICD_TYPER = 0x101000101
[CPU1] gic_validate_redist_version: 16 PPIs implemented
[CPU1] gic_validate_redist_version: no VLPI support, no direct LPI support
[CPU1] nx_idle_trampoline: CPU1: Beginning Idle Loop
[CPU0] arm64_start_cpu: Secondary CPU core 1 (MPID:0x1) is up
```

Followed by the __Third Core__...

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

[CPU2] gic_validate_redist_version: GICD_TYPER = 0x201000201
[CPU2] gic_validate_redist_version: 16 PPIs implemented
[CPU2] gic_validate_redist_version: no VLPI support, no direct LPI support
[CPU2] nx_idle_trampoline: CPU2: Beginning Idle Loop
[CPU0] arm64_start_cpu: Secondary CPU core 2 (MPID:0x2) is up
```

Finally all __4 Cores__ are up!

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

[CPU3] gic_validate_redist_version: GICD_TYPER = 0x301000311
[CPU3] gic_validate_redist_version: 16 PPIs implemented
[CPU3] gic_validate_redist_version: no VLPI support, no direct LPI support
[CPU0] arm64_start_cpu: Secondary CPU core 3 (MPID:0x3) is up
[CPU0] work_start_highpri: Starting high-priority kernel worker thread(s)
[CPU0] nx_start_application: Starting init thread
[CPU3] nx_idle_trampoline: CPU3: Beginning Idle Loop
[CPU0] nx_start: CPU0: Beginning Idle Loop
```

__NuttX Shell__ appears...

```text
nsh: sysinit: fopen failed: 2
nsh: mkfatfs: command not found
NuttShell (NSH) NuttX-10.4.0
nsh>
```

Even though we have 4 Cores, everything works as expected...

```text
nsh> uname -a
NuttX 10.3.0-RC2 1e8f2a8 Aug 21 2022 15:57:35 arm64 qemu-armv8a

nsh> hello
[CPU0] task_spawn: name=hello entry=0x4029cee4 file_actions=0x402e52b0 attr=0x402e52b8 argv=0x402e5400
[CPU0] spawn_execattrs: Setting policy=2 priority=100 for pid=6
Hello, World!
```

[__Symmetric Multi-Processing__](https://developer.arm.com/documentation/den0024/a/Multi-core-processors/Multi-processing-systems/Symmetric-multi-processing?lang=en) never looked so cool!

(Can we use QEMU to emulate parts of PinePhone? That would be extremely helpful for testing!)

![Arm64 Architecture-Specific Source Files](https://lupyuen.github.io/images/arm-source.png)

[_Arm64 Architecture-Specific Source Files_](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common)

# Inside NuttX for Arm64

_What's inside the NuttX code for Arm Cortex-A53?_

Let's browse the __Source Files__ for the implementation of Cortex-A53 on NuttX.

NuttX treats QEMU as a __Target Board__ (as though it was a dev board). Here are the Source Files and Build Configuration for the __QEMU Board__...

-   [boards/arm64/qemu/qemu-armv8a](https://github.com/apache/nuttx/tree/master/boards/arm64/qemu/qemu-armv8a)

(We'll clone this to create a Target Board for PinePhone)

The __Board-Specific Drivers__ for QEMU are started in [qemu_bringup.c](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/src/qemu_bringup.c)

(We'll start the PinePhone Drivers here)

The QEMU Board calls the __QEMU Architecture-Specific Drivers__ at...

-   [arch/arm64/src/qemu](https://github.com/apache/nuttx/tree/master/arch/arm64/src/qemu)

The __UART Driver__ is located at [qemu_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_serial.c) and [qemu_lowputc.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S)

(For PinePhone we'll create a UART Driver for Allwinner A64 SoC. I2C, SPI and other Low-Level A64 Drivers will be located here too)

The QEMU Functions (Board and Architecture) call the __Arm64 Architecture Functions__ (pic above)...

-   [arch/arm64/src/common](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common)

Which implement all kinds of Arm64 Features: [__FPU__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_fpu.c), [__Interrupts__](https://github.com/lupyuen/pinephone-nuttx#interrupt-controller), [__MMU__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c), [__Tasks__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_task_sched.c), [__Timers__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_arch_timer.c)...

(We'll reuse them for PinePhone)

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-ghidra1.png)

# NuttX Image

_NuttX can't possibly boot on PinePhone right?_

It might! Let's compare our __NuttX Image__ with a __PinePhone Linux Image__. And find out what needs to be patched.

Follow these steps to load our [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx) into [__Ghidra__](https://ghidra-sre.org/), the popular open-source tool for Reverse Engineering...

-   [__"Analyse NuttX Image with Ghidra"__](https://lupyuen.github.io/articles/arm#appendix-analyse-nuttx-image-with-ghidra)

Ghidra says that our NuttX Image will be loaded at address __`0x4028` `0000`__. (Pic above)

The Arm64 Instructions at the top of our NuttX Image will jump to __`real_start`__ (to skip the header)...

```text
40280000 4d 5a 00 91     add        x13,x18,#0x16
40280004 0f 00 00 14     b          real_start
```

After the header, __`real_start`__ is defined at `0x4028` `0040` with the Startup Code...

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-title.png)

We see something interesting: The __Magic Number `ARM\x64`__ appears at address `0x4028` `0038`. (Offset `0x38`)

Searching the net for this Magic Number reveals that it's actually an __Arm64 Linux Kernel Header!__

When we refer to the [__NuttX Disassembly `nuttx.S`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx.S), we find happiness: [arch/arm64/src/common/arm64_head.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L79-L117)

```text
  /* Kernel startup entry point.
   * ---------------------------
   *
   * The requirements are:
   *   MMU = off, D-cache = off, I-cache = on or off,
   *   x0 = physical address to the FDT blob.
   *       it will be used when NuttX support device tree in the future
   *
   * This must be the very first address in the loaded image.
   * It should be loaded at any 4K-aligned address.
   */
  .globl __start;
__start:

  /* DO NOT MODIFY. Image header expected by Linux boot-loaders.
   *
   * This add instruction has no meaningful effect except that
   * its opcode forms the magic "MZ" signature of a PE/COFF file
   * that is required for UEFI applications.
   *
   * Some bootloader (such imx8 uboot) checking the magic "MZ" to see
   * if the image is a valid Linux image. but modifying the bootLoader is
   * unnecessary unless we need to do a customize secure boot.
   * so just put the ''MZ" in the header to make bootloader happiness
   */

  add     x13, x18, #0x16      /* the magic "MZ" signature */
  b       real_start           /* branch to kernel start */
```

[("MZ" refers to Mark Zbikowski)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

Yep that's the jump to __`real_start`__ that we saw earlier.

Followed by this header...

```text
  .quad   0x480000              /* Image load offset from start of RAM */
  .quad   _e_initstack - __start         /* Effective size of kernel image, little-endian */
  .quad   __HEAD_FLAGS         /* Informative flags, little-endian */
  .quad   0                    /* reserved */
  .quad   0                    /* reserved */
  .quad   0                    /* reserved */
  .ascii  "ARM\x64"            /* Magic number, "ARM\x64" */
  .long   0                    /* reserved */

real_start: ...
```

Our NuttX Image actually follows the __Arm64 Linux Kernel Image Format__! As defined here...

-   [__"Booting AArch64 Linux"__](https://www.kernel.org/doc/html/latest/arm64/booting.html)

The doc says that a Linux Kernel Image (for Arm64) begins with this __64-byte header__...

```text
u32 code0;                    /* Executable code */
u32 code1;                    /* Executable code */
u64 text_offset;              /* Image load offset, little endian */
u64 image_size;               /* Effective Image size, little endian */
u64 flags;                    /* kernel flags, little endian */
u64 res2      = 0;            /* reserved */
u64 res3      = 0;            /* reserved */
u64 res4      = 0;            /* reserved */
u32 magic     = 0x644d5241;   /* Magic number, little endian, "ARM\x64" */
u32 res5;                     /* reserved (used for PE COFF offset) */
```

[(Source)](https://www.kernel.org/doc/html/latest/arm64/booting.html)

_Is there a proper Linux Header in our NuttX Image?_

Let's do a quick check on our NuttX Header.

The __Image Load Offset__ in our NuttX Header is __`0x48` `0000`__ as we've seen earlier...

```text
.quad   0x480000  /* Image load offset from start of RAM */
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L107)

Our RAM starts at __`0x4000` `0000`__. (We'll see later)

This means that our NuttX Image will be loaded at __`0x4048` `0000`__.

But Ghidra (and the Arm Disassembly) says that our NuttX Image is actually loaded at __`0x4028` `0000`__! (Instead of `0x4048` `0000`)

Maybe the Image Load Offset should have been __`0x28` `0000`__? (Instead of `0x48` `0000`)

Everything else in the NuttX Header looks like a __proper Linux Kernel Header__.

Yep our NuttX Image might actually boot on PinePhone with some patching!

![NuttX RAM](https://lupyuen.github.io/images/arm-ram.png)

# NuttX RAM

_How do we know that RAM starts at `0x4000` `0000`?_

__RAM Size and RAM Start__ are defined in the NuttX Configuration for Arm64 (pic above): [nsh/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/nsh/defconfig#L48-L49) and [nsh_smp/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/nsh_smp/defconfig#L47-L48)

```text
CONFIG_RAM_SIZE=134217728
CONFIG_RAM_START=0x40000000
```

That's 128 MB RAM. Which should fit inside PinePhone's 2 GB RAM.

_Why is our NuttX Image loaded at `0x4028` `0000`?_

Our NuttX Image was built with this __Linker Command__, as observed with "`make` `--trace`"...

```bash
aarch64-none-elf-ld \
  --entry=__start \
  -nostdlib \
  --cref \
  -Map=nuttx/nuttx/nuttx.map \
  -Tnuttx/nuttx/boards/arm64/qemu/qemu-armv8a/scripts/dramboot.ld  \
  -L nuttx/nuttx/staging \
  -L nuttx/nuttx/arch/arm64/src/board  \
  -o nuttx/nuttx/nuttx arm64_head.o  \
  --start-group \
  -lsched \
  -ldrivers \
  -lboards \
  -lc \
  -lmm \
  -larch \
  -lapps \
  -lfs \
  -lbinfmt \
  -lboard /Applications/ArmGNUToolchain/11.3.rel1/aarch64-none-elf/bin/../lib/gcc/aarch64-none-elf/11.3.1/libgcc.a /Applications/ArmGNUToolchain/11.3.rel1/aarch64-none-elf/bin/../lib/gcc/aarch64-none-elf/11.3.1/../../../../aarch64-none-elf/lib/libm.a \
  --end-group
```

In the Linker Command above, we see the __NuttX Linker Script__...

-   [boards/arm64/qemu/qemu-armv8a/scripts/dramboot.ld](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/scripts/dramboot.ld#L30-L33)

Which defines __`_start`__ as `0x4028` `0000`...

```text
SECTIONS
{
  . = 0x40280000;  /* uboot load address */
  _start = .;
```

That's why our NuttX Image is loaded at `0x4028` `0000`!

_Will this work with PinePhone?_

We'll change __`_start`__ to __`0x4000` `0000`__ for PinePhone.

In a while we'll see that Start of RAM is __`0x4000` `0000`__ and Image Load Offset is 0 for a PinePhone Linux Image.

[(__UPDATE:__ Start of RAM should be __`0x4008` `0000`__ instead)](https://lupyuen.github.io/articles/arm#appendix-pinephone-uart-log)

[(__UPDATE:__ We don't need to change the Image Load Offset)](https://lupyuen.github.io/articles/uboot#porting-notes)

(What's the significance of `0x4028` `0000`? Something specific to NXP i.MX8?)

![For "Language" select AARCH64:LE:v8A:default](https://lupyuen.github.io/images/arm-ghidra7.png)

# PinePhone Image

We've seen our NuttX Image (which actually looks like a Linux Kernel Image). Now we compare with a __PinePhone Linux Kernel Image__ and find out what needs to be patched in NuttX.

We'll analyse the Linux Kernel in the __PinePhone Jumpdrive Image__, since it's small...

-   [__dreemurrs-embedded/Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive)

Here are the steps...

1.  Download [__`pine64-pinephone.img.xz`__](https://github.com/dreemurrs-embedded/Jumpdrive/releases/download/0.8/pine64-pinephone.img.xz)

1.  Extract the files from the microSD Image with [__Balena Etcher__](https://www.balena.io/etcher/)

1.  Expand the extracted files...

    ```bash
    gunzip Image.gz
    gunzip initramfs.gz
    tar xvf initramfs
    ```

1.  Follow these steps to import the uncompressed __`Image`__ (Linux Kernel) into Ghidra

    [__"Analyse PinePhone Image with Ghidra"__](https://lupyuen.github.io/articles/arm#appendix-analyse-pinephone-image-with-ghidra)

1.  Check that we've set the "Language" as __"AARCH64:LE:v8A:default"__. (Pic above)

Here's the Jumpdrive __`Image`__ (Linux Kernel) in Ghidra...

![Ghidra with PinePhone Linux Image](https://lupyuen.github.io/images/arm-ghidra2.png)

_That's the Linux Kernel Header?_

Right! The [__Linux Kernel Header__](https://www.kernel.org/doc/html/latest/arm64/booting.html) shows...

-   __Magic Number__ is `ARM\x64`

    (At offset `0x38`)

-   __Image Load Offset__ is `0`

    (At offset `0x08`, pic above)

The __First Instruction__ at `0x4000` `0000` jumps to `0x4081` `0000` (to skip the Linux Kernel Header)...

```text
40000000 00 40 20 14  b FUN_40810000
```

[(Sorry Mr Zbikowski, PinePhone doesn't need your Magic Signature)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

The __Linux Kernel Code__ actually begins at `0x4081` `0000`...

![Ghidra with PinePhone Linux Image](https://lupyuen.github.io/images/arm-ghidra3.png)

After comparing our NuttX Image with a PinePhone Linux Image, we conclude that they look quite similar!

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

# Will NuttX Boot On PinePhone?

_So will NuttX boot on PinePhone?_

It's highly plausible! We discovered (with happiness) that NuttX already generates an Arm64 __Linux Kernel Header.__

Thus NuttX could be a __drop-in replacement__ for the PinePhone Linux Kernel! We just need to...

1.  Write [__PinePhone Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive) to a microSD Card (pic above)

1.  Overwrite __`Image.gz`__ by the (gzipped) NuttX Binary Image __`nuttx.bin`__

1.  Insert microSD Card into PinePhone

1.  Power on PinePhone

And NuttX will (theoretically) __boot on PinePhone!__

_But NuttX needs some changes for PinePhone?_

Yep 3 things we'll modify in NuttX, as mentioned earlier...

-   Change __`_start`__ to __`0x4000` `0000`__ (from `0x4028` `0000`) in the NuttX Linker Script: [dramboot.ld](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/scripts/dramboot.ld#L30-L33)

    ```text
    SECTIONS
    {
    /* TODO: Change to 0x40000000 for PinePhone */
    . = 0x40280000;  /* uboot load address */
    _start = .;
    ```

    [(UPDATE: `_start` / Start of RAM should be __`0x4008` `0000`__ instead)](https://lupyuen.github.io/articles/arm#appendix-pinephone-uart-log)

-  Change __Image Load Offset__ in our NuttX Header to __`0x0`__ (from `0x48` `0000`): [arm64_head.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L107)

    ```text
    /* TODO: Change to 0x0 for PinePhone */
    .quad   0x480000  /* Image load offset from start of RAM */
    ```

-   Increase the __RAM Size__ to __2 GB__ (from 128 MB): [nsh/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/nsh/defconfig#L48-L49) and [nsh_smp/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/nsh_smp/defconfig#L47-L48)

    ```text
    /* TODO: Increase to 2 GB for PinePhone */
    CONFIG_RAM_SIZE=134217728
    CONFIG_RAM_START=0x40000000
    ```

    (We'll increase the RAM Size later, since we don't need much RAM now)

_Will we see anything when NuttX boots on PinePhone?_

Not yet. We need to implement the UART Driver for NuttX...

[__UPDATE:__ NuttX boots on PinePhone yay!](https://lupyuen.github.io/articles/uboot)

![NuttX boots on PinePhone yay!](https://lupyuen.github.io/images/uboot-title.png)

[_NuttX boots on PinePhone yay!_](https://lupyuen.github.io/articles/uboot)

# UART Driver for NuttX

We won't see any output from NuttX until we implement the __UART Driver for NuttX__.

__For QEMU:__ These are the Source Files for the UART Driver (PL011)...

-   [arch/arm64/src/qemu/qemu_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_serial.c)

-   [arch/arm64/src/qemu/qemu_lowputc.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S)

    [(More about PL011 UART)](https://krinkinmu.github.io/2020/11/29/PL011.html)

We'll redo the code above for the __PinePhone UART Driver__ (based on Allwinner A64 SoC)...

-   [__UART0 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

-   [__Allwinner A64 UART__](https://linux-sunxi.org/UART)

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

-   [__Allwinner A64 Info__](https://linux-sunxi.org/A64)

__UPDATE:__ We now have a partial implementation of the [__PinePhone UART Driver__](https://lupyuen.github.io/articles/uboot)

_Where's the UART Port on PinePhone?_

To access the UART Port on PinePhone, we'll use this __USB Serial Debug Cable__...

-   [__PinePhone Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

Which connects to PinePhone's __Headphone Port.__ Genius!

[(Remember to flip the Headphone Switch to OFF)](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration)

PinePhone's __UART Log__ will look like this...

-   [__"PinePhone UART Log"__](https://lupyuen.github.io/articles/arm#appendix-pinephone-uart-log)

![PinePhone UART Port in disguise](https://lupyuen.github.io/images/arm-uart.jpg)

[_PinePhone UART Port in disguise_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# PinePhone on RTOS

_Will an RTOS work well on Phones?_

[__BlackBerry 10__](https://en.wikipedia.org/wiki/BlackBerry_10) phones ran on [__QNX__](https://en.wikipedia.org/wiki/QNX), which is a Real-Time Operating System. (10 years ago!)

_What's an RTOS anyway?_

On a [__Real-Time Operating System (RTOS)__](https://en.wikipedia.org/wiki/Real-time_operating_system), the Task Scheduling Behaviour is predictable. Like: Task X will be scheduled to run __within Y microseconds__.

An RTOS is not designed for High Processing Throughput. But it will guarantee (somewhat) that a Task will respond within a fixed period of time.

_What does it mean for PinePhone on RTOS?_

With an RTOS, I'm guessing the PinePhone User Interface will feel __more responsive__? And Incoming Calls and Text Messages will hopefully pop up quicker.

That assumes we'll assign the correct __Priority for each Task__. It sounds like we're micro-managing the resources on PinePhone, but I'm curious to see the actual outcome.

(And it will be super educational!)

_But NuttX might be too tiny for PinePhone?_

A tiny operating system (like NuttX), might be good for __teaching the internals__ of a Phone Operating System.

We might not get all PinePhone features to work.  But at least we'll understand every single feature that we built!

Tiny OSes are also easier to tweak. Think of the super-tweakable [__PineTime Smartwatch__](https://wiki.pine64.org/index.php/PineTime), which also runs on an RTOS. (FreeRTOS)

(Maybe someday PineTime, PinePhone and Pinebook Pro will run NuttX for Educational Purposes!)

![PinePhone on Linux with a Zig GTK App](https://lupyuen.github.io/images/pinephone-title.jpg)

[_PinePhone on Linux with a Zig GTK App_](https://lupyuen.github.io/articles/pinephone)

# PinePhone Drivers and Apps

_Are there NuttX Drivers for PinePhone?_

Here comes the hard part: We have to __code the Nuttx Driver__ for each PinePhone component...

-   [__LCD Display / Touch Panel__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.11_LCM/CTP)

-   [__4G LTE Modem__](https://lupyuen.github.io/articles/lte)

-   [__WiFi / BLE__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.14_WIFI+BT)

-   [__eMMC__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.7_NAND/eMMC)

-   [__Power Management__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.6_POWER)

-   [__Allwinner A64 SoC__](https://linux-sunxi.org/A64)

-   [__And more...__](https://wiki.pine64.org/wiki/PinePhone_component_list)

PinePhone's __Device Tree__ tells us what drivers we need...

-   [__"PinePhone Device Tree"__](https://github.com/lupyuen/pinephone-nuttx#pinephone-device-tree)

Some drivers might already exist in NuttX...

-   [__NuttX Drivers__](https://github.com/apache/nuttx/tree/master/drivers)

We've previously created NuttX Drivers for another Touchscreen Device: [__Pine64 PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2). (Pic below)

_Do we really need all these PinePhone Drivers?_

For __Educational Purposes__, we might not need all PinePhone Drivers.

Just pick the PinePhone Drivers that we need, compile them into NuttX, copy to microSD and boot up PinePhone.

Might be a quick way to __experiment with the internals__ of NuttX on PinePhone!

_What about NuttX Apps for PinePhone?_

NuttX is bundled with some __Demos and Utilities__...

-   [__NuttX Apps__](https://github.com/apache/nuttx-apps)

But we'll probably create our own __GUI Apps__ for PinePhone, like with __Zig and LVGL__...

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

(Can we build PinePhone Drivers the safer way with Zig? Might be interesting to explore!)

_What about X11 Apps?_

According to [__Alan Carvalho de Assis__](https://www.linkedin.com/in/acassis/)...

-   [__Tab Window Manager__](https://github.com/apache/nuttx-apps/tree/master/graphics/twm4nx) (Tom's Window Manager) has been ported from X11 to NuttX

-   (Coming Soon) [__Nano-X Window System__](http://www.microwindows.org/) might make it easier to port X11 Apps to NuttX

Stay tuned for updates!

[(Need a Wayland Compositor? This Zig one looks portable)](https://github.com/dreinharth/byway)

![NuttX on a Touchscreen Device: Pine64 PineDio Stack BL604](https://lupyuen.github.io/images/pinedio2-title.jpg)

[_NuttX on a Touchscreen Device: Pine64 PineDio Stack BL604_](https://lupyuen.github.io/articles/pinedio2)

# What's Next

Please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

__NuttX on PinePhone__ might take a while to become a __Daily Driver__...

But today NuttX is ready to turn PinePhone into a valuable __Learning Resource__!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/wwz1ep/apache_nuttx_rtos_on_arm_cortexa53_how_it_might/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/arm.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/arm.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1561843749168173056)

1.  What happens when we power on PinePhone? How does it start the Kernel Image in the microSD Card?

    Check out these docs for Allwinner A64...

    [__A64 Boot ROM__](https://linux-sunxi.org/BROM#A64)

    [__A64 U-Boot__](https://linux-sunxi.org/U-Boot)

    [__A64 U-Boot SPL__](https://linux-sunxi.org/BROM#U-Boot_SPL_limitations)

    [__SD Card Layout__](https://linux-sunxi.org/Bootable_SD_card#SD_Card_Layout)

![PinePhone connected to USB Serial Debug Cable](https://lupyuen.github.io/images/arm-uart2.jpg)

[_PinePhone connected to USB Serial Debug Cable_](https://lupyuen.github.io/articles/arm#uart-driver-for-nuttx)

# Appendix: PinePhone UART Log

Earlier we talked about connecting a __USB Serial Debug Cable__ to PinePhone...

-   [__"UART Driver for NuttX"__](https://lupyuen.github.io/articles/arm#uart-driver-for-nuttx)

With the USB Serial Debug Cable we captured the __UART Log__ below from PinePhone running [__Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive)...

```text
$ screen /dev/ttyUSB0 115200

DRAM: 2048 MiB
Trying to boot from MMC1
NOTICE:  BL31: v2.2(release):v2.2-904-gf9ea3a629
NOTICE:  BL31: Built : 15:32:12, Apr  9 2020
NOTICE:  BL31: Detected Allwinner A64/H64/R18 SoC (1689)
NOTICE:  BL31: Found U-Boot DTB at 0x4064410, model: PinePhone
NOTICE:  PSCI: System suspend is unavailable

U-Boot 2020.07 (Nov 08 2020 - 00:15:12 +0100)

DRAM:  2 GiB
MMC:   Device 'mmc@1c11000': seq 1 is in use by 'mmc@1c10000'
mmc@1c0f000: 0, mmc@1c10000: 2, mmc@1c11000: 1
Loading Environment from FAT... *** Warning - bad CRC, using default environment

starting USB...
No working controllers found
Hit any key to stop autoboot:  0 
switch to partitions #0, OK
mmc0 is current device
Scanning mmc 0:1...
Found U-Boot script /boot.scr
653 bytes read in 3 ms (211.9 KiB/s)
## Executing script at 4fc00000
gpio: pin 114 (gpio 114) value is 1
4275261 bytes read in 192 ms (21.2 MiB/s)
Uncompressed size: 10170376 = 0x9B3008
36162 bytes read in 4 ms (8.6 MiB/s)
1078500 bytes read in 50 ms (20.6 MiB/s)
## Flattened Device Tree blob at 4fa00000
   Booting using the fdt blob at 0x4fa00000
   Loading Ramdisk to 49ef8000, end 49fff4e4 ... OK
   Loading Device Tree to 0000000049eec000, end 0000000049ef7d41 ... OK

Starting kernel ...

/ # uname -a
Linux (none) 5.9.1jumpdrive #3 SMP Sun Nov 8 00:41:50 CET 2020 aarch64 GNU/Linux

/ # ls
bin                info.sh            root               telnet_connect.sh
config             init               sbin               usr
dev                init_functions.sh  splash.ppm
error.ppm.gz       linuxrc            splash.ppm.gz
etc                proc               sys
```

We hope to see a similar UART Log when NuttX boots successfully on PinePhone.

_What's `boot.scr`?_

```text
Found U-Boot script /boot.scr
```

According to the log above, the U-Boot Bootloader runs the __U-Boot Script `boot.scr`__ to...

-   Light up the PinePhone LED (I think?)

-   Load `Image.gz` into RAM

    (At `0x4408` `0000`)

-   Unzip `Image.gz` in RAM

    (At `0x4008` `0000`)

-   Load the Linux Device Tree...

    `sun50i-a64-pinephone-1.2.dtb`

    (At `0x4FA0` `0000`)

-   Load the RAM File System `initramfs.gz`

    (At `0x4FE0` `0000`)

-   Boot the Unzipped Linux Kernel in `Image`

    (At `0x4008` `0000`)

Here's the Source File: [Jumpdrive/src/pine64-pinephone.txt](https://github.com/dreemurrs-embedded/Jumpdrive/blob/master/src/pine64-pinephone.txt)

```bash
setenv kernel_addr_z 0x44080000

setenv bootargs loglevel=0 silent console=tty0 vt.global_cursor_default=0

gpio set 114

if load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_z} /Image.gz; then
  unzip ${kernel_addr_z} ${kernel_addr_r}
  if load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} /sun50i-a64-pinephone-1.2.dtb; then
    if load ${devtype} ${devnum}:${distro_bootpart} ${ramdisk_addr_r} /initramfs.gz; then
      booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r};
    else
      booti ${kernel_addr_r} - ${fdt_addr_r};
    fi;
  fi;
fi
```

The above U-Boot Script __`pine64-pinephone.txt`__ is compiled to __`boot.scr`__ by this Makefile: [Jumpdrive/Makefile](https://github.com/dreemurrs-embedded/Jumpdrive/blob/master/Makefile#L207-L209)

```text
%.scr: src/%.txt
	@echo "MKIMG $@"
	@mkimage -A arm -O linux -T script -C none -n "U-Boot boot script" -d $< $@
```

[(__`mkimage`__ is documented here)](https://manpages.ubuntu.com/manpages/bionic/man1/mkimage.1.html)

_What are fdt_addr_r, kernel_addr_r and ramdisk_addr_r?_

They are __Environment Variables__ defined in U-Boot...

```text
=> printenv
fdt_addr_r=0x4FA00000
kernel_addr_r=0x40080000
ramdisk_addr_r=0x4FE00000
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx#pinephone-u-boot-log)

U-Boot says that the __Start of RAM `kernel_addr_r`__ is __`0x4008` `0000`__.

__For NuttX:__ We might need to modify the above U-Boot Script because...

-   NuttX doesn't need the __Linux Device Tree__

-   NuttX doesn't need the __RAM File System__ either

-   Which frees up more RAM for NuttX

[(More about U-Boot Bootloader)](https://lupyuen.github.io/articles/arm#notes)

# Appendix: Analyse NuttX Image with Ghidra

This is how we analyse our [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx) with [__Ghidra__](https://ghidra-sre.org/)...

(Works for any ELF file actually)

1.  Install [__Java Dev Kit (JDK) 11__](https://adoptium.net/releases.html?variant=openjdk11&jvmVariant=hotspot) (64-bit)

1.  Download a [__Ghidra Release File__](https://github.com/NationalSecurityAgency/ghidra/releases).

    Extract the Ghidra Release File.

1.  Launch Ghidra...

    ```bash
    ## For Linux and macOS
    ./ghidraRun
    
    ## For Windows
    ghidraRun.bat
    ```

1.  The __Ghidra Help Window__ appears, with plenty of useful info that's not available elsewhere.

    Minimise the Ghidra Help Window for now.
    
    (But remember to browse it when we have the time!)

1.  In the __Ghidra Main Window__, click __File__ → __New Project__

    For __Project Type__: Select __Non-Shared Project__

    For __Project Name__: Enter __"My Project"__

    ![New Ghidra Project](https://lupyuen.github.io/images/arm-ghidra4.png)

1.  Click __File__ → __Import File__

    Select our [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx) 

1.  Ghidra detects that our Executable is __"AARCH64:LE:v8A:default"__.

    Click __OK__ and __OK__ again.

    ![Import Ghidra File](https://lupyuen.github.io/images/arm-ghidra5.png)

1.  Double-click our ELF File __`nuttx`__

    The __CodeBrowser Window__ appears.

    (With a dragon-like spectre)

1.  When prompted to analyze, click __Yes__ and __Analyze__.

    Ignore the warnings.

    ![Ghidra Analysis Options](https://lupyuen.github.io/images/arm-ghidra6.png)

And we're done with the analysis! We should see this...

![NuttX Image analysed with Ghidra](https://lupyuen.github.io/images/arm-ghidra9.png)

In case of problems, check these docs...

-   [__"Ghidra Installation Guide"__](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html)

-   [__"An Introduction to Ghidra"__](https://git.mst.edu/slbnmc/ici-wiki/-/wikis/Tool-Guides/An-Introduction-to-Ghidra)

-   [__Ghidra Repo__](https://github.com/NationalSecurityAgency/ghidra)

Also check the Ghidra Help Window that we have minimised.

# Appendix: Analyse PinePhone Image with Ghidra

This is how we analyse the __PinePhone Linux Kernel Image__ with [__Ghidra__](https://ghidra-sre.org/)...

1.  Assume that we've extracted and uncompressed the PinePhone Kernel __`Image`__...

    [__"PinePhone Image"__](https://lupyuen.github.io/articles/arm#pinephone-image)

1.  Assume that we've created a __Ghidra Project__

    (From the previous section)

1.  Go back to the __Ghidra Project Window__: "My Project"

    Click __File__ → __Import File__

    Select our PinePhone Kernel __`Image`__

1.  At the right of __Language__, click the __"`...`" Button__ 

1.  Enter __`aarch`__ into the Filter Box. Select...
    -   Processor: __`AARCH64`__
    -   Variant: __`v8A`__
    -   Size: __`64`__
    -   Endian: __`little`__
    -   Compiler: __`default`__

    Click __OK__. 
    
    Language should now show __"AARCH64:LE:v8A:default"__

    ![For "Language" select AARCH64:LE:v8A:default](https://lupyuen.github.io/images/arm-ghidra7.png)

1.  Click __OK__ and __OK__ again.

1.  Double-click our __`Image`__ File

    The __CodeBrowser Window__ appears.

    (With a dragon-like spectre)

1.  When prompted to analyze, click __Yes__ and __Analyze__.

    Ignore the warnings.

    ![Ghidra Analysis Options](https://lupyuen.github.io/images/arm-ghidra6.png)

1.  __Start of RAM__ is `0x4000` `0000` according to the PinePhone Memory Map...

    [__Allwinner A64 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

    __Image Load Offset__ is `0` according to the Linux Kernel Header (offset `0x08`)

    [(__UPDATE:__ Start of RAM should be __`0x4008` `0000`__ instead)](https://lupyuen.github.io/articles/arm#appendix-pinephone-uart-log)

    [(__UPDATE:__ We don't need to change the Image Load Offset)](https://lupyuen.github.io/articles/uboot#porting-notes)

1.  So we shift our PinePhone Image to start at __`0x4000` `0000`__...

    Click __Window__ → __Memory Map__

    Click __ram__

    Click the icon at top right with the Four Arrows (pic below)

    (The icon says "Move a block to another address")

    Set __New Start Address__ to __`40000000`__

![Change Start Address to 40000000](https://lupyuen.github.io/images/arm-ghidra8.png)

And we're done with the analysis! We should see this...

![PinePhone Image analysed with Ghidra](https://lupyuen.github.io/images/arm-ghidra10.png)
