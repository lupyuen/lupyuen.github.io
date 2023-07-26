# Star64 JH7110 + NuttX RTOS: RISC-V Semihosting and Initial RAM Disk

📝 _2 Aug 2023_

![TODO](https://lupyuen.github.io/images/semihost-title.jpg)

> _Once upon a time: There was a Very Naive Bloke (me!) who connected a __Smartwatch to the internet...___

> _Anyone in world could __flash their own firmware__ on the watch, and watch it run on a __Live Video Stream__!_

> _Until a Wise Person (politely) flashed some __very clever firmware__ on the watch, that could __access other devices__ connected to the watch..._

> _All because of __Semihosting__!_

Yep [__this really happened!__](https://liliputing.com/you-can-flash-firmware-on-this-pinetime-smartwatch-in-singapore-over-the-internet/) (Thankfully it was a [__harmless experiment__](https://github.com/lupyuen/remote-pinetime-bot/blob/master/README.md#semihosting-security))

Three years later we're still having __Semihosting Problems__, but on a different gadget: the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer. (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article, we find out...

- What's __RISC-V Semihosting__

- Why it crashes [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx2) on Star64

- What's the __Apps Filesystem__ for NuttX

- How we replaced Semihosting by __Initial RAM Disk "initrd"__ (pic above)

- After testing on __QEMU Emulator__

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

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_semihost.S#L38)

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

# NuttX Calls Semihosting

_Who calls ebreak? And why?_

__`ebreak`__ is called by [__smh_call__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_semihost.S#L20-L40), which is called by [__host_call__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_hostfs.c#L55-L75)...

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

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_hostfs.c#L55-L75)

_What's this operation number?_

The __Semihosting Operation Numbers__ are defined here: [riscv_hostfs.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_hostfs.c#L41-L49)

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

Indeed! When we log [__host_call__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_hostfs.c#L55-L75), we see...

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

[(Source)](https://github.com/apache/nuttx/tree/master/boards/risc-v/qemu-rv/rv-virt)

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

We see that NuttX will mount the __/apps__ filesystem as __/system__, via the [__Semihosting Host Filesystem__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/common/riscv_hostfs.c).

That's why it appears as __/system/bin/init__!

_What's inside /system/bin/init?_

The RISC-V Disassembly of __/system/bin/init__ shows this...

```text
apps/system/nsh/nsh_main.c:52
  0000006e <main>:
    int main(int argc, FAR char *argv[]) {
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/star64c-0.0.1/init.S)

Yep it's the Compiled ELF Executable of the [__NuttX Shell `nsh`__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/star64c/system/nsh/nsh_main.c#L40-L85)!

Now everything makes sense...

1.  At Startup: NuttX tries to load __/system/bin/init__ to start the [__NuttX Shell `nsh`__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/star64c/system/nsh/nsh_main.c#L40-L85)

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
  -smp 8 \
  -M virt,aclint=on \
  -semihosting \
  -bios none \
  -nographic
```

[(Source)](https://lupyuen.github.io/articles/riscv#qemu-emulator-for-risc-v)

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

To modify NuttX QEMU to load an __Initial RAM Disk__, we define the address of the __RAM Disk Memory__ in the Linker Script: [ld-kernel64.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel64.script#L20-L54)

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

At NuttX Startup, we __mount the RAM Disk__: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L83C1-L179C2)

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

We copied the RAM Disk from __`0x8400` `0000`__ to __ramdisk_start__: [qemu_rv_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L271-L280)

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

[(Somehow __map_region__ crashes when we map the RAM Disk Memory)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L280-L287)

Things get really wonky when we exceed the bounds of the RAM Disk. So we __validate the bounds__: [fs_romfsutil.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/fs/romfs/fs_romfsutil.c#L85-L105)

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

Finally we configure NuttX QEMU to mount the __Initial RAM Disk as ROMFS__ (instead of Semihosting): [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

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

That's it! These are the files that we modified in NuttX QEMU to load the Initial RAM Disk (without Semihosting)...

- [__Modified Files for NuttX QEMU with Initial RAM Disk__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/33/files)

_What's ROMFS?_

[__ROMFS__](https://en.wikipedia.org/wiki/Romfs) is the __Filesystem Format__ of our Initial RAM Disk. (It defines how the Files and Directories are stored in the RAM Disk)

We could have used a FAT or EXT4 or NTFS Filesystem... But ROMFS is a lot simpler for NuttX.

_Why did we copy the RAM Disk from __`0x8400` `0000`__?_

QEMU loads the Initial RAM Disk into RAM at __`0x8400` `0000`__...

- [__"RAM Disk Address for RISC-V QEMU"__](https://github.com/lupyuen/nuttx-star64#ram-disk-address-for-risc-v-qemu)

That's why we copied the RAM Disk from __`0x8400` `0000`__ to __ramdisk_start__.

TODO: LiteX Arty-A7

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

[(See the earlier __Build Steps__)](https://lupyuen.github.io/articles/semihost#nuttx-apps-filesystem)

[(__genromfs__ generates a __ROMFS Filesystem__)](https://www.systutorials.com/docs/linux/man/8-genromfs/)

This creates an Initial RAM Disk __initrd__ (in ROMFS format) that's 7.9 MB...

```text
$ ls -l initrd
-rw-r--r--  1 7902208 initrd
```

Finally we start QEMU and __load the Initial RAM Disk__...

```bash
## Start NuttX on QEMU
## with Initial RAM Disk `initrd`
qemu-system-riscv64 \
  -kernel nuttx \
  -initrd initrd \
  -cpu rv64 \
  -smp 8 \
  -M virt,aclint=on \
  -semihosting \
  -bios none \
  -nographic
```

[(Source)](https://www.qemu.org/docs/master/system/riscv/virt.html#running-linux-kernel)

TODO

And it boots OK on QEMU yay!

[See the Run Log](https://gist.github.com/lupyuen/8afee5b07b61bb7f9f202f7f8c5e3ab3)

# NuttX Star64 with Initial RAM Disk

TODO

Now we can modify NuttX for Star64 JH7110 RISC-V SBC to mount the Apps Filesystem from an Initial RAM Disk. (Instead of Semihosting)

![NuttX for Star64 JH7110 RISC-V SBC will mount the Apps Filesystem from an Initial RAM Disk](https://lupyuen.github.io/images/semihost-star64.jpg)

We follow the steps from QEMU Kernel Mode's Initial RAM Disk. (See previous section)

We build NuttX Star64 in Kernel Mode: [Build Steps](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/master/boards/risc-v/qemu-rv/rv-virt)

```bash
## Build NuttX Star64 in Kernel Mode
tools/configure.sh rv-virt:knsh64
make V=1 -j7

## Build Apps Filesystem
make export V=1
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make import V=1
popd
```

We generate the Initial RAM Disk `initrd` and copy to TFTP Folder (for Network Booting)...

```bash
## Generate Initial RAM Disk
cd nuttx
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"

## Copy NuttX Binary Image, Device Tree and Initial RAM Disk to TFTP Folder
cp nuttx.bin $HOME/tftproot/Image
cp ../jh7110-star64-pine64.dtb $HOME/tftproot
cp initrd $HOME/tftproot
```

[(About `genromfs`)](https://www.systutorials.com/docs/linux/man/8-genromfs/)

Initial RAM Disk `initrd` is 7.9 MB...

```text
→ ls -l initrd
-rw-r--r--  1 7930880 Jul 21 13:41 initrd
```

Below are the files that we changed in NuttX for Star64 to load the Initial RAM Disk (instead of Semihosting)...

- [Modified Files for Initial RAM Disk on Star64](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/34/files)

These are the same changes that we made earlier for QEMU Kernel Mode's Initial RAM Disk.

(For a detailed explanation of the modified files, see the previous section_

Note that we copy the Initial RAM Disk from `0x4610` `0000` (instead of QEMU's `0x8400` `0000`): [qemu_rv_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L271-L280)

```c
// Copy 0x46100000 to __ramdisk_start (__ramdisk_size bytes)
// TODO: RAM Disk must not exceed __ramdisk_size bytes
memcpy((void *)__ramdisk_start, (void *)0x46100000, (size_t)__ramdisk_size);
```

(Why `0x4610` `0000`? See `ramdisk_addr_r` below)

This is how we updated the NuttX Build Configuration in `make menuconfig`...

- Board Selection > Enable boardctl() interface > Enable application space creation of ROM disks

- RTOS Features > RTOS hooks > Custom board late initialization   

- File Systems > ROMFS file system 

- RTOS Features > Tasks and Scheduling > Auto-mount init file system 

  Set to `/system/bin`

- Build Setup > Debug Options > File System Debug Features > File System Error, Warnings and Info Output

- Disable: File Systems > Host File System   

- Manually delete from [`knsh64/defconfig`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)...

  ```text
  CONFIG_HOST_MACOS=y
  CONFIG_INIT_MOUNT_DATA="fs=../apps"
  CONFIG_INIT_MOUNT_FSTYPE="hostfs"
  CONFIG_INIT_MOUNT_SOURCE=""
  ```

Updated Build Configuration: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

_What is the RAM Address of the Initial RAM Disk in Star64?_

Initial RAM Disk is loaded by Star64's U-Boot Bootloader at `0x4610` `0000`...

```bash
ramdisk_addr_r=0x46100000
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

Which means that we need to add these TFTP Commands to U-Boot Bootloader...

```bash
## Assume Initial RAM Disk is max 16 MB
setenv ramdisk_size 0x1000000
## Check that it's correct
printenv ramdisk_size
## Save it for future reboots
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

Which will change our U-Boot Boot Script to...

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

_What happens if we omit the RAM Disk Size?_

```text
$ booti ${kernel_addr_r} ${ramdisk_addr_r} ${fdt_addr_r}
Wrong Ramdisk Image Format
Ramdisk image is corrupt or invalid

## Assume max 16 MB
$ booti ${kernel_addr_r} ${ramdisk_addr_r}:0x1000000 ${fdt_addr_r}
## Boots OK
```

_Does the Initial RAM Disk work on Star64?_

Star64 JH7110 boots OK with the Initial RAM Disk yay!

```text
StarFive # booti ${kernel_addr_r} ${ramdisk_addr_r}:0x1000000 ${fdt_addr_r}
## Flattened Device Tree blob at 46000000
   Booting using the fdt blob at 0x46000000
   Using Device Tree in place at 0000000046000000, end 000000004600f43a

Starting kernel ...

clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFHBCInx_start: Entry
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

TODO: Why no shell?

TODO: Why `nx_start_application: ret=3`?

TODO: Check User Address Space

TODO: Boot from MicroSD with Initial RAM Disk

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/semihost.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/semihost.md)

# Appendix: Initial RAM Disk for LiteX Arty-A7

TODO

Let's modify NuttX for QEMU to mount the Apps Filesystem from an Initial RAM Disk (instead of Semihosting).

(So later we can replicate this on Star64 JH7110 SBC)

First we look at the Initial RAM Disk for LiteX Arty-A7...

[(About NuttX RAM Disks and ROM Disks)](https://cwiki.apache.org/confluence/plugins/servlet/mobile?contentId=139629548#content/view/139629548)

To generate the RAM Disk, we run this command: [VexRISCV_SMP Core](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/cores/vexriscv_smp/index.html)

```bash
cd nuttx
genromfs -f romfs.img -d ../apps/bin -V "NuttXBootVol"
```

[(About `genromfs`)](https://www.systutorials.com/docs/linux/man/8-genromfs/)

LiteX Memory Map says where the RAM Disk is loaded...

```text
"romfs.img":   "0x40C00000",
"nuttx.bin":   "0x40000000",
"opensbi.bin": "0x40f00000"
```

This is the LiteX Build Configuration for mounting the RAM Disk: [knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/litex/arty_a7/configs/knsh/defconfig#L34)

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

According to [NSH Start-Up Script](https://nuttx.apache.org/docs/latest/applications/nsh/nsh.html#nsh-start-up-script):

```text
CONFIG_DISABLE_MOUNTPOINT not set
CONFIG_FS_ROMFS enabled
```

The RAM Disk is mounted at LiteX Startup: [litex_appinit.c](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/src/litex_appinit.c#L76-L103)

```c
void board_late_initialize(void)
{
  #ifdef CONFIG_LITEX_APPLICATION_RAMDISK
  litex_mount_ramdisk();
  #endif

  litex_bringup();
}
```

`litex_bringup` mounts the RAM Disk at startup: [litex_ramdisk.c](https://github.com/apache/nuttx/blob/master/boards/risc-v/litex/arty_a7/src/litex_ramdisk.c#L41-L98)

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

`__ramdisk_start` is defined in [board_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/boards/risc-v/litex/arty_a7/include/board_memorymap.h#L58-L91):

```c
/* RAMDisk */
#define RAMDISK_START     (uintptr_t)__ramdisk_start
#define RAMDISK_SIZE      (uintptr_t)__ramdisk_size

/* ramdisk (RW) */
extern uint8_t          __ramdisk_start[];
extern uint8_t          __ramdisk_size[];
```

And [ld-kernel.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/boards/risc-v/litex/arty_a7/scripts/ld-kernel.script#L20-L49):

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

Note that `__pgheap_size` needs to include `ramdisk`.

# Appendix: RAM Disk Address for RISC-V QEMU

TODO

_Can we enable logging for RISC-V QEMU?_

Yep we use the `-trace "*"` option like this...

```bash
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -initrd initrd \
  -nographic \
  -trace "*"
```

In the QEMU Command above we loaded the Initial RAM Disk `initrd`.

To discover the RAM Address of the Initial RAM Disk, we check the QEMU Trace Log:

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

So Initial RAM Disk is loaded at `0x8400` `0000`

(`__ramdisk_start` from the previous section)

Also we see that Kernel is loaded at `0x8000` `0000`, Device Tree at `0x8700` `0000`.

We thought the Initial RAM Disk Address could be discovered from the Device Tree for RISC-V QEMU. But nope it's not there...

# Appendix: Device Tree for RISC-V QEMU

TODO

To dump the Device Tree for QEMU RISC-V, we specify `dumpdtb`...

```bash
## Dump Device Tree for QEMU RISC-V
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on,dumpdtb=qemu-riscv64.dtb \
  -cpu rv64 \
  -smp 8 \
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

This produces the Device Tree for QEMU RISC-V...

- [qemu-riscv64.dts: Device Tree for QEMU RISC-V](https://github.com/lupyuen/nuttx-star64/blob/main/qemu-riscv64.dts)

Which is helpful for browsing the Memory Addresses of I/O Peripherals.
