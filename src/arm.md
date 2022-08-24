# Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone

📝 _30 Aug 2022_

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-title.png)

_Ghidra with Apache NuttX RTOS for Arm Cortex-A53_

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) (Real-Time Operating System) runs on 64-bit __Arm Cortex-A53__ with Multiple Cores...

-   [__NuttX on Arm Cortex-A53__](https://github.com/apache/incubator-nuttx/tree/master/boards/arm64/qemu/qemu-a53)

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

Many thanks to [__qinwei2004__](https://github.com/qinwei2004) and the NuttX Team for implementing [__Cortex-A53 support__](https://github.com/apache/incubator-nuttx/pull/6478)!

# Download NuttX

__NuttX Mainline__ has the latest support for Arm Cortex-A53. Let's download the Source Code for our experiment...

```bash
## Create NuttX Directory
mkdir nuttx
cd nuttx

## Download NuttX OS
git clone \
    --recursive \
    https://github.com/apache/incubator-nuttx \
    nuttx

## Download NuttX Apps
git clone \
    --recursive \
    https://github.com/apache/incubator-nuttx-apps \
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

[(Based on the instructions here)](https://github.com/apache/incubator-nuttx/tree/master/boards/arm64/qemu/qemu-a53)

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

Let's build NuttX...

> ![Build NuttX](https://lupyuen.github.io/images/arm-build.png)

# Build NuttX: Single Core

We'll run two experiments with QEMU...

-   NuttX on a __Single Core__ of Arm Cortex-A53

-   NuttX on __4 Cores__ of Arm Cortex-A53

Which works like 4 Arm64 Processors running in parallel, similar to PinePhone.

First we build NuttX for a __Single Core__ of Arm Cortex-A53...

```bash
## Configure NuttX for Single Core
./tools/configure.sh -l qemu-a53:nsh

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

# Test NuttX with QEMU: Single Core

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
NuttX 10.3.0-RC2 1e8f2a8 Aug 23 2022 07:04:54 arm64 qemu-a53
```

[__"Hello World"__](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/hello/hello_main.c) works as expected...

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
# Create a RAMDISK and mount it at /tmp

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
./tools/configure.sh -l qemu-a53:nsh_smp

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

# Test NuttX with QEMU: Multi Core

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
NuttX 10.3.0-RC2 1e8f2a8 Aug 21 2022 15:57:35 arm64 qemu-a53

nsh> hello
[CPU0] task_spawn: name=hello entry=0x4029cee4 file_actions=0x402e52b0 attr=0x402e52b8 argv=0x402e5400
[CPU0] spawn_execattrs: Setting policy=2 priority=100 for pid=6
Hello, World!
```

[__Symmetric Multi-Processing__](https://developer.arm.com/documentation/den0024/a/Multi-core-processors/Multi-processing-systems/Symmetric-multi-processing?lang=en) never looked so cool!

(Can we use QEMU to emulate parts of PinePhone? That would be extremely helpful for testing!)

![Arm64 Architecture-Specific Source Files](https://lupyuen.github.io/images/arm-source.png)

[_Arm64 Architecture-Specific Source Files_](https://github.com/apache/incubator-nuttx/tree/master/arch/arm64/src/common)

# Inside NuttX for Cortex-A53

_What's inside the NuttX code for Cortex-A53?_

Let's browse the __Source Files__ for the implementation of Cortex-A53 on NuttX.

NuttX treats QEMU as a __Target Board__ (as though it was a dev board). Here are the Source Files and Build Configuration for the __QEMU Board__...

-   [nuttx/boards/arm64/qemu/qemu-a53](https://github.com/apache/incubator-nuttx/tree/master/boards/arm64/qemu/qemu-a53)

(We'll clone this to create a Target Board for PinePhone)

The __Board-Specific Drivers__ for QEMU are started in [qemu_bringup.c](https://github.com/apache/incubator-nuttx/blob/master/boards/arm64/qemu/qemu-a53/src/qemu_bringup.c)

(We'll start the PinePhone Drivers here)

The QEMU Board calls the __QEMU Architecture-Specific Drivers__ at...

-   [nuttx/arch/arm64/src/qemu](https://github.com/apache/incubator-nuttx/tree/master/arch/arm64/src/qemu)

The __UART Driver__ is located at [qemu_serial.c](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/qemu/qemu_serial.c) and [qemu_lowputc.S](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S)

(For PinePhone we'll create a UART Driver for Allwinner A64 SoC. I2C, SPI and other Low-Level A64 Drivers will be located here too)

The QEMU Functions (Board and Architecture) call the __Arm64 Architecture Functions__ (pic above)...

-   [nuttx/arch/arm64/src/common](https://github.com/apache/incubator-nuttx/tree/master/arch/arm64/src/common)

Which implement all kinds of Arm64 Features: [__FPU__](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/common/arm64_fpu.c), [__Interrupts__](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/common/arm64_gicv3.c), [__MMU__](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c), [__Tasks__](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/common/arm64_task_sched.c), [__Timers__](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/common/arm64_arch_timer.c)...

(We'll reuse them for PinePhone)

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-ghidra1.png)

# NuttX Image

_NuttX can't possibly boot on PinePhone right?_

It might! Let's compare our __NuttX Image__ with a __PinePhone Linux Image__. And find out what needs to be patched.

We load our [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx) into [__Ghidra__](https://ghidra-sre.org/), the popular open-source tool for Reverse Engineering.

Ghidra says that our NuttX Image will be loaded at address __`0x4028 0000`__. (Pic above)

The Arm64 Instructions at the top of our NuttX Image will jump to __`real_start`__ (to skip the header)...

```text
40280000 4d 5a 00 91     add        x13,x18,#0x16
40280004 0f 00 00 14     b          real_start
```

After the header, __`real_start`__ is defined at `0x4028 0040` with the Startup Code...

![Ghidra with Apache NuttX RTOS for Arm Cortex-A53](https://lupyuen.github.io/images/arm-title.png)

We see something interesting: The __Magic Number `ARM\x64`__ appears at address `0x4028 0038`. (Offset `0x38`)

Searching the net for this Magic Number reveals that it's actually an __Arm64 Linux Kernel Header!__

When we refer to the [__NuttX Disassembly `nuttx.S`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.0/nuttx.S), we find happiness: [arch/arm64/src/common/arm64_head.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L79-L117)

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

[("MZ" refers to Mark Zbikowski)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

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

The __Image Load Offset__ in our NuttX Header is __`0x48 0000`__ as we've seen earlier...

```text
.quad   0x480000  /* Image load offset from start of RAM */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L107)

Our RAM starts at __`0x4000 0000`__. (We'll see later)

This means that our NuttX Image will be loaded at __`0x4048 0000`__.

But Ghidra (and the Arm Disassembly) says that our NuttX Image is actually loaded at __`0x4028 0000`__! (Instead of `0x4048 0000`)

Maybe the Image Load Offset should have been __`0x28 0000`__? (Instead of `0x48 0000`)

Everything else in the NuttX Header looks like a proper Linux Kernel Header. Yep our NuttX Image might actually boot on PinePhone with some patching!

# NuttX RAM

_How do we know that RAM starts at `0x4000 0000`?_

__RAM Size and RAM Start__ are defined in the NuttX Configuration for Arm64: [nsh_smp/defconfig](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/boards/arm64/qemu/qemu-a53/configs/nsh_smp/defconfig#L47-L48)

```text
CONFIG_RAM_SIZE=134217728
CONFIG_RAM_START=0x40000000
```

That's 128 MB RAM. Which should fit inside PinePhone's 2 GB RAM.

_Why is our NuttX Image loaded at `0x4028 0000`?_

Our NuttX Image was built with this __Linker Command__, as observed with "`make --trace`"...

```bash
aarch64-none-elf-ld \
  --entry=__start \
  -nostdlib \
  --cref \
  -Map=nuttx/nuttx/nuttx.map \
  -Tnuttx/nuttx/boards/arm64/qemu/qemu-a53/scripts/dramboot.ld  \
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

-   [boards/arm64/qemu/qemu-a53/scripts/dramboot.ld](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/boards/arm64/qemu/qemu-a53/scripts/dramboot.ld#L30-L33)

Which defines __`_start`__ as `0x4028 0000`...

```text
SECTIONS
{
  . = 0x40280000;  /* uboot load address */
  _start = .;
```

That's why our NuttX Image is loaded at `0x4028 0000`!

_Will this work with PinePhone?_

We'll change `_start` to __`0x4000 0000`__ for PinePhone.

In a while we'll see that Start of RAM is __`0x4000 0000`__ and Image Load Offset is 0 for a PinePhone Linux Image.

(What's the significance of `0x4028 0000`? Something specific to NXP i.MX8?)

# PinePhone Image

We've seen our NuttX Image (which actually looks like a Linux Kernel Image). Let's compare with a __PinePhone Linux Kernel Image__ and see what needs to be patched in NuttX.

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

1.  Import the uncompressed __`Image`__ (Linux Kernel) into Ghidra

1.  For "Language" select "AARCH64:LE:v8A:default"...
    -   Processor: `AARCH64`
    -   Variant: `v8A`
    -   Size: `64`
    -   Endian: `little`
    -   Compiler: `default`

![For "Language" select AARCH64:LE:v8A:default](https://lupyuen.github.io/images/Screenshot%202022-08-22%20at%203.39.06%20PM.png)

Here's the Jumpdrive `Image` (Linux Kernel) in Ghidra...

![Ghidra with PinePhone Linux Image](https://lupyuen.github.io/images/arm-ghidra2.png)

_We should see the Linux Kernel Header?_

Yep when we check the [__Linux Kernel Header__](https://www.kernel.org/doc/html/latest/arm64/booting.html)...

-   __Magic Number__ `ARM\x64` appears at offset `0x38`

-   __Image Load Offset__ is 0

Now the __Start of RAM__ is `0x4000 0000` according to the PinePhone Memory Map...

-   [__Allwinner A64 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

So we shift `Image` in Ghidra to start at `0x4000 0000`...

-   Click Window > Memory Map

-   Click "ram"

-   Click the 4-Arrows icon ("Move a block to another address")

-   Change "New Start Address" to `40000000`

![Change Start Address to 40000000](https://lupyuen.github.io/images/Screenshot%202022-08-21%20at%207.07.15%20PM.png)

The first instruction at `0x4000 0000` jumps to `0x4081 0000` (to skip the Linux Kernel Header)...

```text
40000000 00 40 20 14     b          FUN_40810000
```

[(Sorry Mr Zbikowski, we don't need your Magic Signature)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

The __Linux Kernel Code__ actually begins at `0x4081 0000`...

![Ghidra with PinePhone Linux Image](https://lupyuen.github.io/images/arm-ghidra3.png)

# Will NuttX Boot On PinePhone?

TODO

_So will NuttX boot on PinePhone?_

It's highly plausible! We discovered (with happiness) that NuttX already generates an Arm64 Linux Kernel Header.

So NuttX could be a drop-in replacement for the PinePhone Linux Kernel! We just need to...

-   Write PinePhone Jumpdrive to a microSD Card (with Etcher, in FAT format)

-   Overwrite `Image.gz` by the (gzipped) NuttX Binary Image `nuttx.bin.gz`

-   Insert the microSD Card into PinePhone

-   Power on PinePhone

And NuttX should (theoretically) boot on PinePhone!

As mentioned earlier, we should rebuild NuttX so that `__start` is changed to 0x4000 0000 (from 0x4028 0000), as defined in the NuttX Linker Script: [boards/arm64/qemu/qemu-a53/scripts/dramboot.ld](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/boards/arm64/qemu/qemu-a53/scripts/dramboot.ld#L30-L33)

```text
SECTIONS
{
  /* TODO: Change to 0x4000000 for PinePhone */
  . = 0x40280000;  /* uboot load address */
  _start = .;
```

Also the Image Load Offset in our NuttX Image Header should be changed to 0x0 (from 0x48 0000): [arch/arm64/src/common/arm64_head.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L107)

```text
    /* TODO: Change to 0x0 for PinePhone */
    .quad   0x480000              /* Image load offset from start of RAM */
```

We'll increase the RAM Size to 2 GB (from 128 MB): [boards/arm64/qemu/qemu-a53/configs/nsh_smp/defconfig](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/boards/arm64/qemu/qemu-a53/configs/nsh_smp/defconfig#L47-L48)

```text
/* TODO: Increase to 2 GB for PinePhone */
CONFIG_RAM_SIZE=134217728
CONFIG_RAM_START=0x40000000
```

_But will we see anything when NuttX boots on PinePhone?_

Not yet. We'll need to implement the UART Driver for NuttX...

# UART Driver for NuttX

TODO

We won't see any output from NuttX until we implement the UART Driver for NuttX.

These are the Source Files for the QEMU UART Driver (PL011)...

-   [arch/arm64/src/qemu/qemu_serial.c](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/qemu/qemu_serial.c)

-   [arch/arm64/src/qemu/qemu_lowputc.S](https://github.com/apache/incubator-nuttx/blob/master/arch/arm64/src/qemu/qemu_lowputc.S)

    [(More about PL011 UART)](https://krinkinmu.github.io/2020/11/29/PL011.html)

We'll replace the code above with the UART Driver for Allwinner A64 SoC...

-   [UART0 Memory Map](https://linux-sunxi.org/A64/Memory_map)

-   [Allwinner A64 UART](https://linux-sunxi.org/UART)

-   [Allwinner A64 User Manual](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

-   [Allwinner A64 Info](https://linux-sunxi.org/A64)

To access the UART Port on PinePhone, we'll use this USB Serial Debug Cable...

-   [PinePhone Serial Debug Cable](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

Which connects to the Headphone Port. Genius!

[(Remember to flip the Headphone Switch to OFF)](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration)

![PinePhone UART Port in disguise](https://lupyuen.github.io/images/arm-uart.jpg)

[_PinePhone UART Port in disguise_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# PinePhone on RTOS

TODO

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

Tiny OSes are also easier to tweak. Think of the super-tweakable __PineTime Smartwatch__, which also runs on an RTOS. (FreeRTOS)

(Maybe someday PineTime, PinePhone and Pinebook Pro will run NuttX for __Educational Purposes__!)

![PinePhone on Linux with a Zig GTK App](https://lupyuen.github.io/images/pinephone-title.jpg)

[_PinePhone on Linux with a Zig GTK App_](https://lupyuen.github.io/articles/pinephone)

# PinePhone Drivers and Apps

TODO

Here comes the hard part.

No drivers? Well PinePhone comes bundled with a fixed set of peripherals...

-   [__LCD Display / Touch Panel__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.11_LCM/CTP)

-   [__LTE Modem__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.15_MODEM-4G)

-   [__WiFi / BLE__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.14_WIFI+BT)

-   [__eMMC__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.7_NAND/eMMC)

-   [__Power Management__](https://wiki.pine64.org/wiki/PinePhone_component_list#P.6_POWER)

-   And more

And interfaces: UART, I2C, SPI, ...

Just build the drivers and we're done? (Yep I sound really naive now)

Just like PineDio Stack BL604: Display, Touch Panel, LoRaWAN, ...

For Educational Purposes, we might not need all the PinePhone Drivers. Just pick the NuttX Drivers that we need, compile them into NuttX, copy to microSD and boot up PinePhone.

No apps? Might be interesting to build PinePhone Apps the safer way with Zig

Simple apps might work with LVGL and Zig

Can we build PinePhone Drivers in Zig?

TODO: From [__Alan Carvalho de Assis__](https://www.linkedin.com/in/acassis/)

-   I ran NuttX on PCDuino (ARM Cortex-A9 I think)

-   also NuttX on iMX6 and BeagleBoneBlack

-   nice to try evolve NuttX on Desktop direction

-   Tom Window Manager that Greg ported to NuttX

-   TODO: port NanoX (nxlib/microwindows) it could open doors to port X11 graphic applications from Linux

# What's Next

TODO

There's plenty to be done, please lemme know if you're keen to help! 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/arm.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/arm.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1561843749168173056)

1.  TODO: Boot Docs

    [__A64 Boot ROM__](https://linux-sunxi.org/BROM#A64)

    [__A64 U-Boot__](https://linux-sunxi.org/U-Boot)

    [__A64 U-Boot SPL__](https://linux-sunxi.org/BROM#U-Boot_SPL_limitations)

    [__SD Card Layout__](https://linux-sunxi.org/Bootable_SD_card#SD_Card_Layout)
