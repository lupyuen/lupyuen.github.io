# Star64 JH7110 + NuttX RTOS: RISC-V Semihosting and Initial RAM Disk

📝 _28 Jul 2023_

![Booting NuttX on Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-title.jpg)

> _Once upon a time: There was a Very Naive Bloke (me!) who connected a __Smartwatch to the internet...___

> _Anyone in world could __flash their own firmware__ on the watch, and watch it run on a __Live Video Stream__!_

> _Until a Wise Person (politely) flashed some __very clever firmware__ on the watch, that could __access other devices__ connected to the watch..._

> _All because of __Semihosting__!_

Yep [__this really happened!__](https://liliputing.com/you-can-flash-firmware-on-this-pinetime-smartwatch-in-singapore-over-the-internet/) (Thankfully it was a [__harmless experiment__](https://github.com/lupyuen/remote-pinetime-bot/blob/master/README.md#semihosting-security))

Three years later we're still having __Semihosting Problems__, but on a different gadget: the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer. (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html), the same SoC in VisionFive2)

In this article, we find out...

- What's __RISC-V Semihosting__

- Why it crashes [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx2) on Star64

- How it affects the __Apps Filesystem__ in NuttX

- How we replaced Semihosting by __Initial RAM Disk "initrd"__ (pic above)

- After testing on __QEMU Emulator__

- Thanks to NuttX on __LiteX Arty-A7__ for the guidance!

![Star64 RISC-V SBC](https://lupyuen.github.io/images/nuttx2-star64.jpg)

# NuttX Crashes On Star64

In the last article, we tried porting Apache NuttX RTOS from __QEMU Emulator to Star64 JH7110 SBC__...

- [__"Star64 JH7110 + NuttX RTOS: RISC-V Privilege Levels and UART Registers"__](https://lupyuen.github.io/articles/privilege)

NuttX seems to boot OK for a while...

```text
123067DFHBC
qemu_rv_kernel_mappings: map I/O regions
qemu_rv_kernel_mappings: map kernel text
qemu_rv_kernel_mappings: map kernel data
qemu_rv_kernel_mappings: connect the L1 and L2 page tables
qemu_rv_kernel_mappings: map the page pool
qemu_rv_mm_init: mmu_enable: satp=1077956608
Inx_start: Entry
elf_initialize: Registering ELF
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x404069e8
```

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

But then NuttX crashes with a __RISC-V Exception__...

```text
EXCEPTION: Breakpoint
MCAUSE:    00000003
EPC:       40200434
MTVAL:     00000000
```

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

Let's find out why...

![NuttX crashes due to a Semihosting Problem](https://lupyuen.github.io/images/privilege-run2.png)

# Decipher the RISC-V Exception

_NuttX crashes with this RISC-V Exception..._

_What does it mean?_

```text
EXCEPTION: Breakpoint
MCAUSE:    00000003
EPC:       40200434
MTVAL:     00000000
```

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

According to the [__Machine Cause Register (MCAUSE)__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:mcause), value 3 says that it's a __"Machine Software Interrupt"__.

Which means that NuttX has intentionally triggered a __Software Interrupt__. Probably to execute a Special Function.

_Something special? Like what?_

We look up the __Exception Program Counter (EPC) `0x4020` `0434`__ in our NuttX Disassembly...

```text
nuttx/arch/risc-v/src/common/riscv_semihost.S:37
smh_call():
  // Register A0 contains the Semihosting Operation Number.
  // Register A1 contains the Semihosting Parameter.
  // Shift Left (does nothing)
  40200430: 01f01013  slli zero, zero, 0x1f

  // Crashes here:
  // Trigger Semihosting Breakpoint
  40200434: 00100073  ebreak

  // Shift Right (does nothing)
  // Encodes the Semihosting Call Number 7
  40200438: 40705013  srai zero, zero, 0x7
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_semihost.S#L38)

The code above has a special RISC-V Instruction...

```text
ebreak
```

_What's this ebreak?_

From the [__RISC-V Spec__](https://five-embeddev.com/quickref/instructions.html#-rv32--environment-call-and-breakpoints)...

> "The EBREAK instruction is used to return control to a debugging environment"

> "EBREAK was primarily designed to be used by a debugger to cause execution to stop and fall back into the debugger"

OK thanks but we're not doing any debugging! 

The next part is more helpful...

> "Another use of EBREAK is to support __Semihosting__, where the execution environment includes a debugger that can provide services over an Alternate System Call Interface built around the EBREAK instruction"

Aha! NuttX is making a special [__System Call to Semihosting__](https://embeddedinn.xyz/articles/tutorial/understanding-riscv-semihosting/)!

(We'll see why)

> "Because the RISC-V base ISA does not provide more than one EBREAK instruction, RISC-V Semihosting uses a __special sequence of instructions__ to distinguish a Semihosting EBREAK from a Debugger Inserted EBREAK"

Which explains this (strange) preceding RISC-V Instruction...

```text
// Shift Left the value 0x1F
// into Register X0...
// Which is always 0!
slli zero, zero, 0x1f
```

That doesn't do anything meaningful!

Let's talk about Semihosting...

![NuttX calls Semihosting to read the Apps Filesystem](https://lupyuen.github.io/images/semihost-qemu3.jpg)

# NuttX Calls Semihosting

_Who calls ebreak? And why?_

__`ebreak`__ is called by [__smh_call__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_semihost.S#L20-L40), which is called by [__host_call__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_hostfs.c#L52-L71)...

```c
// NuttX calls Semihosting to
// access the Host Filesystem
static long host_call(
  unsigned int nbr,  // Semihosting Operation Number
  void *parm,        // Semihosting Parameter
  size_t size        // Size of Parameter
) {
  // Call Semihosting via `ebreak`
  long ret = smh_call(
    nbr,  // Semihosting Operation Number
    parm  // Semihosting Parameter
  );
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_hostfs.c#L52-L71)

_What's this operation number?_

The __Semihosting Operation Numbers__ are defined here: [riscv_hostfs.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_hostfs.c#L38-L48)

```c
// Semihosting Operation Numbers
// (For File Operations)
#define HOST_OPEN   0x01
#define HOST_CLOSE  0x02
#define HOST_WRITE  0x05
#define HOST_READ   0x06
#define HOST_SEEK   0x0a
#define HOST_FLEN   0x0c
#define HOST_REMOVE 0x0e
#define HOST_RENAME 0x0f
#define HOST_ERROR  0x13
```

_Aha! NuttX is calling Semihosting to access the File System!_

Indeed! When we log [__host_call__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_hostfs.c#L52-L71), we see...

```text
host_call:
  nbr=0x1 (HOST_OPEN)
  parm=0x40406778
  size=24
```

Which calls Semihosting to __open a file.__

_Open what file?_

If we look back at the __NuttX Crash Log__...

```text
nx_start_application: 
  Starting init task: /system/bin/init
load_absmodule: 
  Loading /system/bin/init
elf_loadbinary: 
  Loading file: /system/bin/init
elf_init: filename: 
  /system/bin/init loadinfo: 0x404069e8
riscv_exception:
  EXCEPTION: Breakpoint
```

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

NuttX is trying to read the file __/system/bin/init__ via Semihosting!

Why did it fail? Let's find out...

# NuttX Apps Filesystem

_What's /system/bin/init?_

_Why is NuttX reading it at startup?_

Remember we copied __NuttX from QEMU__ and (naively) ran it on Star64?

We backtrack to the origin (NuttX on QEMU) and figure out what's __/system/bin/init__...

```bash
## Build NuttX QEMU in Kernel Mode
tools/configure.sh rv-virt:knsh64
make V=1 -j7

## Build Apps Filesystem for NuttX QEMU
make export V=1
pushd ../apps
./tools/mkimport.sh \
  -z -x \
  ../nuttx/nuttx-export-*.tar.gz
make import V=1
popd

## Dump the `init` disassembly to `init.S`
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  ../apps/bin/init \
  >init.S \
  2>&1
```

[(Source)](https://nuttx.apache.org/docs/latest/platforms/risc-v/qemu-rv/boards/rv-virt/index.html)

[(Why we use __Kernel Mode__)](https://lupyuen.github.io/articles/privilege#nuttx-flat-mode-becomes-kernel-mode)

The above commands will build the __Apps Filesystem__ for NuttX QEMU.

Which includes __/system/bin/init__...

```bash
$ ls ../apps/bin       
getprime
hello
init
sh
```

_Isn't it supposed to be /system/bin/init? Not /apps/bin/init?_

When we check the __NuttX Build Configuration__...

```bash
$ grep INIT .config
CONFIG_INIT_FILE=y
CONFIG_INIT_ARGS=""
CONFIG_INIT_FILEPATH="/system/bin/init"
CONFIG_INIT_MOUNT=y
CONFIG_INIT_MOUNT_SOURCE=""
CONFIG_INIT_MOUNT_TARGET="/system"
CONFIG_INIT_MOUNT_FSTYPE="hostfs"
CONFIG_INIT_MOUNT_FLAGS=0x1
CONFIG_INIT_MOUNT_DATA="fs=../apps"
CONFIG_PATH_INITIAL="/system/bin"
CONFIG_NSH_ARCHINIT=y
```

[(Source)](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

We see that NuttX will mount the __/apps__ filesystem as __/system__, via the [__Semihosting Host Filesystem__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_hostfs.c).

That's why it appears as __/system/bin/init__!

_What's inside /system/bin/init?_

The RISC-V Disassembly of __/system/bin/init__ shows this...

```text
apps/system/nsh/nsh_main.c:52
  0000006e <main>:
    int main(int argc, FAR char *argv[]) {
```

[(Source)](https://github.com/lupyuen2/wip-nuttx/releases/download/star64c-0.0.1/init.S)

Yep it's the Compiled ELF Executable of the [__NuttX Shell `nsh`__](https://github.com/lupyuen2/wip-nuttx-apps/blob/star64c/system/nsh/nsh_main.c#L40-L85)!

Now everything makes sense...

1.  At Startup: NuttX tries to load __/system/bin/init__ to start the [__NuttX Shell `nsh`__](https://github.com/lupyuen2/wip-nuttx-apps/blob/star64c/system/nsh/nsh_main.c#L40-L85)

1.  But it Fails: Because __/system/bin/init__ doesn't exist in the Semihosting Filesystem on Star64!

This is why Semihosting won't work on Star64...

![QEMU reads the Apps Filesystem over Semihosting](https://lupyuen.github.io/images/semihost-qemu.jpg)

# Semihosting on NuttX QEMU

_Why Semihosting won't work on Star64 SBC?_

[__Semihosting__](https://embeddedinn.xyz/articles/tutorial/understanding-riscv-semihosting/) was created for [__Hardware Debuggers__](https://en.wikipedia.org/wiki/Debugger#Hardware_support_for_debugging) and [__Virtual Machine Hypervisors__](https://en.wikipedia.org/wiki/Hypervisor), like QEMU Emulator.

The pic above shows how it works: Semihosting enables a Virtual Machine (like NuttX) to __"Break Out" of its Sandbox__ to access the Filesystem on the Host Machine / Our Computer.

(Remember our story at the top of the article? Be careful with Semihosting!)

That's why we __Enable Semihosting__ when we run NuttX on QEMU...

```bash
## Start NuttX on QEMU
## with Semihosting Enabled
qemu-system-riscv64 \
  -kernel nuttx \
  -cpu rv64 \
  -M virt,aclint=on \
  -semihosting \
  -bios none \
  -nographic
```

[(Source)](https://lupyuen.github.io/articles/riscv#qemu-emulator-for-risc-v)

(Remove __`-bios none`__ for newer versions of NuttX)

So that NuttX can access the __Apps Filesystem__ (from previous section) as a Semihosting Filesystem! (Pic above)

[(More about __RISC-V Semihosting__)](https://embeddedinn.xyz/articles/tutorial/understanding-riscv-semihosting/)

[(See the __Semihosting Spec__)](https://github.com/riscv-software-src/riscv-semihosting/blob/main/riscv-semihosting-spec.adoc)

_This won't work on Star64?_

Semihosting won't work because NuttX for Star64 runs on __Real SBC Hardware__ (Bare Metal)...

There's nothing to "break out" to!

![Initial RAM Disk for NuttX](https://lupyuen.github.io/images/semihost-star64a.jpg)

_If not Semihosting... Then what?_

In the world of Linux (and QEMU), there's something cool called an [__Initial RAM Disk (initrd)__](https://en.wikipedia.org/wiki/Initial_ramdisk)...

- It's a __RAM Disk__, located in RAM (pic above)

- But it's an __Initial__ RAM Disk. Which means there's a Filesystem inside, preloaded with Files and Directories.

Perfect for our NuttX Apps Filesystem!

_That's awesome but where do we start?_

We begin by modding NuttX QEMU to load the Initial RAM Disk...

![NuttX for QEMU will mount the Apps Filesystem from an Initial RAM Disk](https://lupyuen.github.io/images/semihost-qemu2.jpg)

# Modify NuttX QEMU for Initial RAM Disk

_NuttX QEMU will load an Initial RAM Disk..._

_Instead of using Semihosting. How?_

In the previous section, we said that...

- [__Initial RAM Disk (initrd)__](https://en.wikipedia.org/wiki/Initial_ramdisk) is a __RAM Disk__, located in RAM (pic above)

- But it's an __Initial__ RAM Disk. Which means there's a Filesystem inside, preloaded with Files and Directories.

To modify NuttX QEMU to load an __Initial RAM Disk__, we define the address of the __RAM Disk Memory__ in the Linker Script: [ld-kernel64.script](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel64.script#L20-L54)

```text
MEMORY
{
  ...
  /* Added RAM Disk Memory (Max 16 MB) */
  ramdisk (rwx) : ORIGIN = 0x80800000, LENGTH = 16M   /* w/ cache */
}

/* Increased Page Heap for RAM Disk */
__pgheap_size = LENGTH(pgram) + LENGTH(ramdisk);
/* Previously: __pgheap_size = LENGTH(pgram); */

/* Added RAM Disk Symbols */
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size  = LENGTH(ramdisk);
__ramdisk_end   = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

(__`0x8080` `0000`__ is the next available RAM Address)

At NuttX Startup, we __mount the RAM Disk__: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L83-L179)

```c
// Called at NuttX Startup
void board_late_initialize(void) {

  // Mount the RAM Disk
  mount_ramdisk();

  // Perform board-specific initialization
#ifdef CONFIG_NSH_ARCHINIT
  mount(NULL, "/proc", "procfs", 0, NULL);
#endif
}

// Mount the RAM Disk
int mount_ramdisk(void) {

  // Define the ROMFS
  struct boardioc_romdisk_s desc;
  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;

  // Mount the ROMFS
  int ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
  // Omitted: Handle Errors
```

(More about ROMFS in a while)

Before mounting, we copy the RAM Disk from __`0x8400` `0000`__ to __ramdisk_start__: [qemu_rv_mm_init.c](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L271-L280)

```c
void qemu_rv_kernel_mappings(void) {
  ...
  // Copy RAM Disk from 0x8400 0000 to
  // `__ramdisk_start` (`__ramdisk_size` bytes)
  // TODO: RAM Disk must not exceed `__ramdisk_size` bytes
  memcpy(                     // Copy the RAM Disk...
    (void *)__ramdisk_start,  // To RAM Disk Memory
    (void *)0x84000000,       // From QEMU initrd Address
    (size_t)__ramdisk_size    // For 16 MB
  );
```

(More about __`0x8400` `0000`__ in a while)

[(Somehow __map_region__ crashes when we map the RAM Disk Memory)](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L280-L287)

Things get really wonky when we exceed the bounds of the RAM Disk. So we __validate the bounds__: [fs_romfsutil.c](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/fs/romfs/fs_romfsutil.c#L79-L84)

```c
// While reading from RAM Disk...
static uint32_t romfs_devread32(struct romfs_mountpt_s *rm, int ndx) {

  // If we're reading beyond the bounds of
  // RAM Disk Memory, halt (and catch fire)
  DEBUGASSERT(
    &rm->rm_buffer[ndx] <
      __ramdisk_start + (size_t)__ramdisk_size
  );
```

Finally we configure NuttX QEMU to mount the __Initial RAM Disk as ROMFS__ (instead of Semihosting): [knsh64/defconfig](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

```bash
CONFIG_BOARDCTL_ROMDISK=y
CONFIG_BOARD_LATE_INITIALIZE=y
CONFIG_FS_ROMFS=y
CONFIG_INIT_FILEPATH="/system/bin/init"
CONFIG_INIT_MOUNT=y
CONFIG_INIT_MOUNT_FLAGS=0x1
CONFIG_INIT_MOUNT_TARGET="/system/bin"

## We removed these...
## CONFIG_FS_HOSTFS=y
## CONFIG_RISCV_SEMIHOSTING_HOSTFS=y
```

[(How we configured NuttX for RAM Disk)](https://lupyuen.github.io/articles/semihost#appendix-configure-nuttx-for-initial-ram-disk)

That's it! These are the files that we modified in NuttX QEMU to load the Initial RAM Disk (without Semihosting)...

- [__Modified Files for NuttX QEMU with Initial RAM Disk__](https://github.com/lupyuen2/wip-nuttx/pull/33/files)

_What's ROMFS?_

[__ROMFS__](https://en.wikipedia.org/wiki/Romfs) is the __Filesystem Format__ of our Initial RAM Disk. (It defines how the Files and Directories are stored in the RAM Disk)

We could have used a FAT or EXT4 or NTFS Filesystem... But ROMFS is a lot simpler for NuttX.

[(More about __ROMFS in NuttX__)](https://nuttx.apache.org/docs/latest/components/filesystem.html)

_Why did we copy the RAM Disk from __`0x8400` `0000`__?_

QEMU loads the Initial RAM Disk into RAM at __`0x8400` `0000`__...

- [__"RAM Disk Address for RISC-V QEMU"__](https://lupyuen.github.io/articles/semihost#appendix-ram-disk-address-for-risc-v-qemu)

That's why we copied the RAM Disk from __`0x8400` `0000`__ to __ramdisk_start__.

_Wow how did we figure out all this?_

Actually we had plenty of guidance from NuttX on __LiteX Arty-A7__. Here's our Detailed Analysis...

- [__"Initial RAM Disk for LiteX Arty-A7"__](https://lupyuen.github.io/articles/semihost#appendix-initial-ram-disk-for-litex-arty-a7)

![Booting NuttX QEMU with Initial RAM Disk](https://lupyuen.github.io/images/semihost-runqemu.png)

# Boot NuttX QEMU with Initial RAM Disk

We're ready to run our modified NuttX QEMU... That loads the Initial RAM Disk!

We build NuttX QEMU in Kernel Mode (as before). Then we generate the Initial RAM Disk __initrd__...

```bash
## Omitted: Build NuttX QEMU in Kernel Mode
...
## Omitted: Build Apps Filesystem for NuttX QEMU
...
## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"
```

[(See the __Build Steps__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/ramdisk-0.0.1)

[(See the __Build Log__)](https://gist.github.com/lupyuen/394bc4da808ee5e4f5fb8da70cb2ae3e)

[(__genromfs__ generates a __ROM FS Filesystem__)](https://manpages.ubuntu.com/manpages/trusty/man8/genromfs.8.html)

[(Inside a __ROM FS Filesystem__)](https://lupyuen.github.io/articles/romfs#inside-a-rom-fs-filesystem)

This creates an Initial RAM Disk __initrd__ (in ROMFS format) that's 7.9 MB...

```text
$ ls -l initrd
-rw-r--r--  1 7902208 initrd
```

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/ramdisk-0.0.1)

Finally we start QEMU and __load our Initial RAM Disk__...

```bash
## Start NuttX on QEMU
## with Initial RAM Disk `initrd`
qemu-system-riscv64 \
  -kernel nuttx \
  -initrd initrd \
  -cpu rv64 \
  -M virt,aclint=on \
  -semihosting \
  -bios none \
  -nographic
```

[(Source)](https://www.qemu.org/docs/master/system/riscv/virt.html#running-linux-kernel)

(Remove __`-bios none`__ for newer versions of NuttX)

And NuttX QEMU boots OK with our Initial RAM Disk yay! (Ignore the warnings)

```text
ABC
nx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize:
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
up_exit: TCB=0x802088d0 exiting

NuttShell (NSH) NuttX-12.0.3
nsh> nx_start: CPU0: Beginning Idle Loop
nsh>
```

[(See the __Run Log__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/ramdisk-0.0.1)

[(See the __Detailed Run Log__)](https://gist.github.com/lupyuen/8afee5b07b61bb7f9f202f7f8c5e3ab3)

We see __exec_spawn__ warnings like this...

```text
nsh> ls -l /system/bin/init
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
 -r-xr-xr-x 3278720 /system/bin/init
```

But it's OK to ignore them, because "__`ls`__" is a built-in Shell Command.

(Not an Executable File from our Apps Filesystem)

Now that we figured out Initial RAM Disk on QEMU, let's do the same for Star64...

![Booting NuttX on Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-title.jpg)

# NuttX Star64 with Initial RAM Disk

One last thing for today: Booting NuttX on __Star64 with Initial RAM Disk__! (Instead of Semihosting)

We modify NuttX Star64 with the exact same steps as [__NuttX QEMU with Initial RAM Disk__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk)...

- [__Modified Files for Initial RAM Disk on Star64__](https://github.com/lupyuen2/wip-nuttx/pull/34/files)

- [__qemu_rv_mm_init.c__](https://github.com/lupyuen2/wip-nuttx/pull/34/files#diff-a663261ea6b68497baecd83562df554d2c7903261090bf627042860d90fb920f): Copy RAM Disk at Startup

- [__qemu_rv_appinit.c__](https://github.com/lupyuen2/wip-nuttx/pull/34/files#diff-beeaeb03fa5642002a542446c89251c9a7c5c1681cfe915387740ea0975e91b3): Mount RAM Disk at Startup

- [__fs_romfsutil.c__](https://github.com/lupyuen2/wip-nuttx/pull/34/files#diff-a1d53d0735749ccfb3072e986511d0b6cae6f7ce850d8c91195cc027201a0132): Validate RAM Disk Bounds

- [__ld-kernel64.script__](https://github.com/lupyuen2/wip-nuttx/pull/34/files#diff-fbe356a2692accfbf05c87b4b1a3ecb7275bf38d06f9ceb7730928249f15d605): Linker Script with RAM Disk Memory

- [__knsh64/defconfig__](https://github.com/lupyuen2/wip-nuttx/pull/34/files#diff-4018c37bf9b08236b37a84273281d5511d48596be9e0e4c0980d730aa95dbbe8): Build Configuration for RAM Disk

  [(How we configured NuttX for RAM Disk)](https://lupyuen.github.io/articles/semihost#appendix-configure-nuttx-for-initial-ram-disk)

Note that we copy the Initial RAM Disk from __`0x4610` `0000`__ (instead of QEMU's `0x8400` `0000`): [jh7110_mm_init.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_mm_init.c#L268-L275)

```c
// Copy RAM Disk from 0x4610 0000 to
// `__ramdisk_start` (`__ramdisk_size` bytes)
// TODO: RAM Disk must not exceed `__ramdisk_size` bytes
memcpy(                     // Copy the RAM Disk...
  (void *)__ramdisk_start,  // To RAM Disk Memory
  (void *)0x46100000,       // From U-Boot initrd Address
  (size_t)__ramdisk_size    // For 16 MB
);
```

[(U-Boot Bootloader loads the RAM Disk at __`0x4610` `0000`__)](https://lupyuen.github.io/articles/semihost#appendix-ram-disk-address-for-risc-v-qemu)

And the __RAM Disk Memory__ is now located at __`0x40A0` `0000`__ (the next available RAM Address): [ld.script](https://github.com/apache/nuttx/blob/master/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L56)

```text
MEMORY
{
  ...
  /* Added RAM Disk Memory (Max 16 MB) */
  ramdisk (rwx) : ORIGIN = 0x40A00000, LENGTH = 16M   /* w/ cache */
}

/* Increased Page Heap for RAM Disk */
__pgheap_size = LENGTH(pgram) + LENGTH(ramdisk);
/* Previously: __pgheap_size = LENGTH(pgram); */

/* Added RAM Disk Symbols */
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size  = LENGTH(ramdisk);
__ramdisk_end   = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

The [__other modified files__](https://github.com/lupyuen2/wip-nuttx/pull/34/files) are the same as for NuttX QEMU with Initial RAM Disk.

[(How to increase the __RAM Disk Limit__)](https://github.com/lupyuen/nuttx-star64#increase-ram-disk-limit)

[(NuttX Apps are limited to __4 MB RAM__)](https://github.com/lupyuen/nuttx-star64#memory-map-for-ram-disk)

[(How to increase the __Page Heap Size__)](https://github.com/lupyuen/nuttx-star64#increase-page-heap-size)

_How do we run this on Star64?_

We build NuttX Star64, generate the Initial RAM Disk __initrd__ and copy to our TFTP Folder [(for __Network Booting__)](https://lupyuen.github.io/articles/semihost#appendix-boot-nuttx-over-tftp-with-initial-ram-disk)...

```bash
## Omitted: Build NuttX Star64
...
## Omitted: Build Apps Filesystem for NuttX Star64
...
## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"

## Copy NuttX Binary Image, Device Tree and
## Initial RAM Disk to TFTP Folder
cp nuttx.bin $HOME/tftproot/Image
cp jh7110-star64-pine64.dtb $HOME/tftproot
cp initrd $HOME/tftproot
```

[(See the __Build Steps__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/star64c-0.0.1)

[(See the __Build Log__)](https://gist.github.com/lupyuen/ae59a840c94280ce8d618699278a0436)

[(__genromfs__ generates a __ROM FS Filesystem__)](https://manpages.ubuntu.com/manpages/trusty/man8/genromfs.8.html)

[(Inside a __ROM FS Filesystem__)](https://lupyuen.github.io/articles/romfs#inside-a-rom-fs-filesystem)

Our Initial RAM Disk __initrd__ (with ROMFS inside) is 7.9 MB (slightly bigger)...

```text
$ ls -l initrd
-rw-r--r--  1 7930880 initrd
```

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/star64c-0.0.1)

And we boot NuttX on Star64 over TFTP or a microSD Card...

- [__"Boot NuttX over TFTP with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#appendix-boot-nuttx-over-tftp-with-initial-ram-disk)

- [__"NuttX in a Bootable microSD"__](https://lupyuen.github.io/articles/release#nuttx-in-a-bootable-microsd)

_Does it work?_

Now Star64 JH7110 boots OK with the Initial RAM Disk yay! (Not completely though)

```text
Starting kernel ...
123067DFHBCI
nx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
nx_start: CPU0: Beginning Idle Loop
```

[(See the __Output Log__)](https://github.com/lupyuen2/wip-nuttx/releases/tag/star64c-0.0.1)

So many questions (pic below)...

- Why no __NuttX Shell__?

  Was it started correctly?

  ([__nx_start_application__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L297-L299) returned Process ID 3, seems OK)

- Is __Console Output__ working in NuttX Shell?

  (Highly sus!)

- Is our [__Interrupt Controller__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/hardware/jh7110_memorymap.h#L27-L33) OK?

  [(See __CONFIG_16550_UART0_IRQ__)](https://github.com/apache/nuttx/blob/master/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L10-L18)

  [(See the __JH7110 U74 Memory Map__)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html)

- Are we using the right [__User Address Space__](https://github.com/apache/nuttx/blob/master/boards/risc-v/jh7110/star64/include/board_memorymap.h#L33-L38)?

  And the right [__I/O Address Space__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_mm_init.c#L46-L51)?

- How to handle [__RISC-V Timers in Supervisor Mode__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_timerisr.c#L151-L210)?

  Do we need [__OpenSBI Timers__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/riscv-sbi.adoc#timer-extension-eid-0x54494d45-time)?

We'll find out in the next article!

- [__"Star64 JH7110 + NuttX RTOS: RISC-V PLIC Interrupts and Serial I/O"__](https://lupyuen.github.io/articles/plic)

![NuttX Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-runstar64.png)

# What's Next

No more __Semihosting Problems__ with NuttX on Star64 JH7110 SBC!

- We discovered that NuttX calls __RISC-V Semihosting__

  (To access the Apps Filesystem)

- But it crashes __NuttX on Star64__

  (Because Semihosting won't work on Bare Metal)

- NuttX Shell lives in the NuttX __Apps Filesystem__

  (So it's mandatory for booting NuttX)

- Thus we replaced Semihosting by __Initial RAM Disk "initrd"__

  (And it works on Star64!)

- By adapting the code from NuttX on __LiteX Arty-A7__

  (Which we also tested on __QEMU Emulator__)

- Now we need to figure out why __NuttX Shell__ won't appear...

  [__"Star64 JH7110 + NuttX RTOS: RISC-V PLIC Interrupts and Serial I/O"__](https://lupyuen.github.io/articles/plic)
  
Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36901287)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18551)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/semihost.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/semihost.md)

![Booting NuttX on Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-title.jpg)

# Appendix: Boot NuttX over TFTP with Initial RAM Disk

Previously we configured Star64's U-Boot Bootloader to __boot NuttX over TFTP__...

- [__"Star64 JH7110 RISC-V SBC: Boot from Network with U-Boot and TFTP"__](https://lupyuen.github.io/articles/tftp)

Now we need to tweak the U-Boot Settings to boot with our __Initial RAM Disk__.

Star64's U-Boot Bootloader loads our Initial RAM Disk at __`0x4610` `0000`__...

```bash
ramdisk_addr_r=0x46100000
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

Which means that we need to add these __TFTP Commands__ to U-Boot Bootloader...

```bash
## Added this: Assume Initial RAM Disk is max 16 MB
setenv ramdisk_size 0x1000000
printenv ramdisk_size
saveenv

## Load Kernel and Device Tree over TFTP
tftpboot ${kernel_addr_r} ${tftp_server}:Image
tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb
fdt addr ${fdt_addr_r}

## Added this: Load Initial RAM Disk over TFTP
tftpboot ${ramdisk_addr_r} ${tftp_server}:initrd

## Changed this: Replaced `-` by `ramdisk_addr_r:ramdisk_size`
booti ${kernel_addr_r} ${ramdisk_addr_r}:${ramdisk_size} ${fdt_addr_r}
```

Which will change our __U-Boot Boot Script__ to...

```bash
## Load the NuttX Image from TFTP Server
## kernel_addr_r=0x40200000
## tftp_server=192.168.x.x
if tftpboot ${kernel_addr_r} ${tftp_server}:Image;
then

  ## Load the Device Tree from TFTP Server
  ## fdt_addr_r=0x46000000
  if tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb;
  then

    ## Set the RAM Address of Device Tree
    ## fdt_addr_r=0x46000000
    if fdt addr ${fdt_addr_r};
    then

      ## Load the Intial RAM Disk from TFTP Server
      ## ramdisk_addr_r=0x46100000
      if tftpboot ${ramdisk_addr_r} ${tftp_server}:initrd;
      then

        ## Boot the NuttX Image with the Initial RAM Disk and Device Tree
        ## kernel_addr_r=0x40200000
        ## ramdisk_addr_r=0x46100000
        ## ramdisk_size=0x1000000
        ## fdt_addr_r=0x46000000
        booti ${kernel_addr_r} ${ramdisk_addr_r}:${ramdisk_size} ${fdt_addr_r};
      fi;
    fi;
  fi;
fi
```

Which becomes...

```bash
## Assume Initial RAM Disk is max 16 MB
setenv ramdisk_size 0x1000000
## Check that it's correct
printenv ramdisk_size
## Save it for future reboots
saveenv

## Add the Boot Command for TFTP
setenv bootcmd_tftp 'if tftpboot ${kernel_addr_r} ${tftp_server}:Image ; then if tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb ; then if fdt addr ${fdt_addr_r} ; then if tftpboot ${ramdisk_addr_r} ${tftp_server}:initrd ; then booti ${kernel_addr_r} ${ramdisk_addr_r}:${ramdisk_size} ${fdt_addr_r} ; fi ; fi ; fi ; fi'
## Check that it's correct
printenv bootcmd_tftp
## Save it for future reboots
saveenv
```

[(Remember to set __tftp_server__ and __boot_targets__)](https://lupyuen.github.io/articles/tftp#configure-u-boot-for-tftp)

Run the above commands in U-Boot. 

Copy the Initial RAM Disk __initrd__ to the TFTP Folder...

```bash
## Copy NuttX Binary Image, Device Tree and
## Initial RAM Disk to TFTP Folder
cp nuttx.bin $HOME/tftproot/Image
cp jh7110-star64-pine64.dtb $HOME/tftproot
cp initrd $HOME/tftproot
```

[(Source)](https://lupyuen.github.io/articles/semihost#nuttx-star64-with-initial-ram-disk)

Power Star64 off and on.

NuttX now boots with our Initial RAM Disk over TFTP...

- [__"NuttX Star64 with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#nuttx-star64-with-initial-ram-disk)

  [(Watch the Demo on YouTube)](https://youtu.be/TdSJdiQFsv8)

Here's the __U-Boot Log__...

```text
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'Image'.
Load address: 0x40200000
Loading: 9 MiB/s
done
Bytes transferred = 2097800 (200288 hex)
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'jh7110-star64-pine64.dtb'.
Load address: 0x46000000
Loading: 8 MiB/s
done
Bytes transferred = 50235 (c43b hex)
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'initrd'.
Load address: 0x46100000
Loading: 371.1 KiB/s
done
Bytes transferred = 7930880 (790400 hex)
## Flattened Device Tree blob at 46000000
   Booting using the fdt blob at 0x46000000
   Using Device Tree in place at 0000000046000000, end 000000004600f43a
Starting kernel ...
```

_What if we omit the RAM Disk Size?_

U-Boot won't boot NuttX if we omit the RAM Disk Size...

```bash
## If we omit RAM Disk Size:
## Boot Fails
$ booti ${kernel_addr_r} ${ramdisk_addr_r} ${fdt_addr_r}
Wrong Ramdisk Image Format
Ramdisk image is corrupt or invalid
```

So we hardcode a maximum RAM Disk Size of 16 MB...

```bash
## If we assume RAM Disk Size is max 16 MB:
## Boots OK
$ booti ${kernel_addr_r} ${ramdisk_addr_r}:0x1000000 ${fdt_addr_r}
```

Let's talk about the NuttX Configuration for Initial RAM Disk...

![NuttX Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-runstar64.png)

# Appendix: Configure NuttX for Initial RAM Disk

Earlier we configured NuttX QEMU and NuttX Star64 to boot with our __Initial RAM Disk__...

- [__"NuttX QEMU with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk)

- [__"NuttX Star64 with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#nuttx-star64-with-initial-ram-disk)

Here are the steps for updating the NuttX Build Configuration in `make menuconfig`...

1.  Board Selection > Enable boardctl() interface > Enable application space creation of ROM disks

1.  RTOS Features > RTOS hooks > Custom board late initialization   

1.  File Systems > ROMFS file system 

1.  RTOS Features > Tasks and Scheduling > Auto-mount init file system 

    Set to `/system/bin`

1.  Build Setup > Debug Options > File System Debug Features > File System Error, Warnings and Info Output

1.  Disable: File Systems > Host File System   

1.  Manually delete from [nsh/defconfig](https://github.com/apache/nuttx/blob/master/boards/risc-v/jh7110/star64/configs/nsh/defconfig)...

    ```text
    CONFIG_HOST_MACOS=y
    CONFIG_INIT_MOUNT_DATA="fs=../apps"
    CONFIG_INIT_MOUNT_FSTYPE="hostfs"
    CONFIG_INIT_MOUNT_SOURCE=""
    ```

The steps above will produce the updated Build Configuration Files...

- __NuttX for QEMU:__ [__knsh64/defconfig__](https://github.com/lupyuen2/wip-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

- __NuttX for Star64:__ [__nsh/defconfig__](https://github.com/apache/nuttx/blob/master/boards/risc-v/jh7110/star64/configs/nsh/defconfig)

# Appendix: RAM Disk Address for RISC-V QEMU

_We need the RAM Disk Address for RISC-V QEMU..._

_Can we enable logging for RISC-V QEMU?_

Yep we use this QEMU Option: __`-trace "*"`__

```bash
## Start NuttX on QEMU
## with Initial RAM Disk `initrd`
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -initrd initrd \
  -nographic \
  -trace "*"
```

(Remove __`-bios none`__ for newer versions of NuttX)

In the QEMU Command above, we load the Initial RAM Disk __initrd__.

To discover the RAM Address of the Initial RAM Disk, we check the __QEMU Trace Log__...

```text
resettablloader_write_rom nuttx
  ELF program header segment 0:
  @0x80000000 size=0x2b374 ROM=0
loader_write_rom nuttx
  ELF program header segment 1:
  @0x80200000 size=0x2a1 ROM=0
loader_write_rom initrd:
  @0x84000000 size=0x2fc3e8 ROM=0
loader_write_rom fdt:
  @0x87000000 size=0x100000 ROM=0
```

This says that QEMU loads our Initial RAM Disk __initrd__ at __`0x8400` `0000`__

(And QEMU loads our Kernel at __`0x8000` `0000`__, Device Tree at __`0x8700` `0000`__)

We set the RAM Address of the Initial RAM Disk here...

- [__"Modify NuttX QEMU for Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk)

We thought the Initial RAM Disk Address could be discovered from the Device Tree for RISC-V QEMU. But nope it's not there...

# Appendix: Device Tree for RISC-V QEMU

To dump the Device Tree for RISC-V QEMU, we specify __`dumpdtb`__...

```bash
## Dump Device Tree for RISC-V QEMU
## Remove `-bios none` for newer versions of NuttX
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on,dumpdtb=qemu-riscv64.dtb \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic

## Convert Device Tree to text format
dtc \
  -o qemu-riscv64.dts \
  -O dts \
  -I dtb \
  qemu-riscv64.dtb
```

[(__dtc__ decompiles a Device Tree)](https://manpages.ubuntu.com/manpages/xenial/man1/dtc.1.html)

This produces the Device Tree for RISC-V QEMU...

- [__qemu-riscv64.dts: Device Tree for RISC-V QEMU__](https://github.com/lupyuen/nuttx-star64/blob/main/qemu-riscv64.dts)

Which is helpful for browsing the Memory Addresses of I/O Peripherals in QEMU.

# Appendix: Initial RAM Disk for LiteX Arty-A7

Earlier we modified NuttX QEMU and NuttX Star64 to load our __Initial RAM Disk__...

- [__"NuttX QEMU with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk)

- [__"NuttX Star64 with Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost#nuttx-star64-with-initial-ram-disk)

We did it with plenty of guidance from NuttX on __LiteX Arty-A7__, below is our Detailed Analysis.

To __generate the RAM Disk__ for LiteX Arty-A7, we run this command...

```bash
## Generate the Initial RAM Disk `romfs.img`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f romfs.img \
  -d ../apps/bin \ 
  -V "NuttXBootVol"
```

[(Source)](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/cores/vexriscv_smp/index.html)

[(About __genromfs__)](https://manpages.ubuntu.com/manpages/trusty/man8/genromfs.8.html)

[(Inside a __ROM FS Filesystem__)](https://lupyuen.github.io/articles/romfs#inside-a-rom-fs-filesystem)

[(About NuttX RAM Disks and ROM Disks)](https://cwiki.apache.org/confluence/plugins/servlet/mobile?contentId=139629548#content/view/139629548)

[__LiteX Memory Map__](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/cores/vexriscv_smp/index.html#booting) tells us where the RAM Disk is loaded: __`0x40C0` `0000`__

```text
"romfs.img":   "0x40C00000",
"nuttx.bin":   "0x40000000",
"opensbi.bin": "0x40f00000"
```

This is the __LiteX Build Configuration__ for mounting the RAM Disk: [knsh/defconfig](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/configs/knsh/defconfig)

```bash
CONFIG_BOARDCTL_ROMDISK=y
CONFIG_BOARD_LATE_INITIALIZE=y
CONFIG_BUILD_KERNEL=y
CONFIG_FS_ROMFS=y
CONFIG_INIT_FILEPATH="/system/bin/init"
CONFIG_INIT_MOUNT=y
CONFIG_INIT_MOUNT_FLAGS=0x1
CONFIG_INIT_MOUNT_TARGET="/system/bin"
CONFIG_LITEX_APPLICATION_RAMDISK=y
CONFIG_NSH_FILE_APPS=y
CONFIG_NSH_READLINE=y
CONFIG_PATH_INITIAL="/system/bin"
CONFIG_RAM_SIZE=4194304
CONFIG_RAM_START=0x40400000
CONFIG_RAW_BINARY=y
CONFIG_SYSTEM_NSH_PROGNAME="init"
CONFIG_TESTING_GETPRIME=y
```

Which is consistent with the NuttX Doc on [__NSH Start-Up Script__](https://nuttx.apache.org/docs/latest/applications/nsh/nsh.html#nsh-start-up-script)...

```text
CONFIG_DISABLE_MOUNTPOINT not set
CONFIG_FS_ROMFS enabled
```

We mount the RAM Disk at __LiteX Startup__: [litex_appinit.c](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/src/litex_appinit.c#L76-L103)

```c
void board_late_initialize(void)
{
#ifdef CONFIG_LITEX_APPLICATION_RAMDISK
  litex_mount_ramdisk();
#endif

  litex_bringup();
}
```

Which calls __litex_mount_ramdisk__ to mount the RAM Disk: [litex_ramdisk.c](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/src/litex_ramdisk.c#L41-L98)

```c
#ifndef CONFIG_BUILD_KERNEL
#error "Ramdisk usage is intended to be used with kernel build only"
#endif

#define SECTORSIZE   512
#define NSECTORS(b)  (((b) + SECTORSIZE - 1) / SECTORSIZE)
#define RAMDISK_DEVICE_MINOR 0

// Mount a ramdisk defined in the ld-kernel.script to /dev/ramX.
// The ramdisk is intended to contain a romfs with applications which can
// be spawned at runtime.
int litex_mount_ramdisk(void)
{
  int ret;
  struct boardioc_romdisk_s desc;

  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;

  ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Ramdisk register failed: %s\n", strerror(errno));
      syslog(LOG_ERR, "Ramdisk mountpoint /dev/ram%d\n",
                                          RAMDISK_DEVICE_MINOR);
      syslog(LOG_ERR, "Ramdisk length %u, origin %x\n",
                                          (ssize_t)__ramdisk_size,
                                          (uintptr_t)__ramdisk_start);
    }

  return ret;
}
```

__ramdisk_start__ and __ramdisk_size__ are defined in the __LiteX Memory Map__: [board_memorymap.h](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/include/board_memorymap.h#L58-L91)

```c
/* RAMDisk */
#define RAMDISK_START     (uintptr_t)__ramdisk_start
#define RAMDISK_SIZE      (uintptr_t)__ramdisk_size

/* ramdisk (RW) */
extern uint8_t          __ramdisk_start[];
extern uint8_t          __ramdisk_size[];
```

And also in the __LiteX Linker Script__: [ld-kernel.script](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/scripts/ld-kernel.script#L20-L49)

```text
MEMORY
{
  kflash (rx)   : ORIGIN = 0x40000000, LENGTH = 4096K   /* w/ cache */
  ksram (rwx)   : ORIGIN = 0x40400000, LENGTH = 4096K   /* w/ cache */
  pgram (rwx)   : ORIGIN = 0x40800000, LENGTH = 4096K   /* w/ cache */
  ramdisk (rwx) : ORIGIN = 0x40C00000, LENGTH = 4096K   /* w/ cache */
}
...
/* Page heap */
__pgheap_start = ORIGIN(pgram);
__pgheap_size = LENGTH(pgram) + LENGTH(ramdisk);

/* Application ramdisk */
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size = LENGTH(ramdisk);
__ramdisk_end  = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

Note that __pgheap_size__ needs to include __ramdisk__ size.
