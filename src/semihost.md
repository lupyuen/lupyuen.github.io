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

The next part is more relevant...

> "Another use of EBREAK is to support __Semihosting__, where the execution environment includes a debugger that can provide services over an Alternate System Call Interface built around the EBREAK instruction"

Aha! NuttX is making a special __System Call to Semihosting__!

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



TODO

So NuttX crashes on Star64 because it's trying to read `/system/bin/init` via Semihosting!

(See next section)

[(More about __RISC-V Semihosting__)](https://embeddedinn.xyz/articles/tutorial/understanding-riscv-semihosting/)

[(See the __Semihosting Spec__)](https://github.com/riscv-software-src/riscv-semihosting/blob/main/riscv-semihosting-spec.adoc)

Let's disable Semihosting and replace by Initial RAM Disk and ROMFS.

(See https://github.com/apache/nuttx/issues/9501)

![QEMU reads the Apps Filesystem over Semihosting](https://lupyuen.github.io/images/semihost-qemu.jpg)

Here's the Crash Dump after we disabled Semihosting...

```text
123067DFHBCqemu_rv_kernel_mappings: map I/O regions
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
host_call: nbr=0x1, parm=0x40406788, size=24
_assert: Current Version: NuttX  12.0.3 6ed2880-dirty Jul 15 2023 21:00:59 risc-v
_assert: Assertion failed panic: at file: common/riscv_hostfs.c:58 task: Idle Task 0x40200cd0
up_dump_register: EPC: 000000004020f590
up_dump_register: A0: 0000000040401630 A1: 000000000000003a A2: 0000000040219ee8 A3: 0000000000000000
up_dump_register: A4: 000000000000000a A5: 0000000000000000 A6: 0000000000000009 A7: 0000000000000068
up_dump_register: T0: 0000000000000030 T1: 0000000000000009 T2: 0000000000000020 T3: 000000000000002a
up_dump_register: T4: 000000000000002e T5: 00000000000001ff T6: 000000000000002d
up_dump_register: S0: 0000000000000000 S1: 0000000040400b28 S2: 0000000040401768 S3: 0000000040219ee8
up_dump_register: S4: 0000000040229b10 S5: 000000000000003a S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 00000000fff47194 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 0000000040406650 FP: 0000000000000000 TP: 0000000000000001 RA: 000000004020f590
dump_stack: User Stack:
dump_stack:   base: 0x40406030
dump_stack:   size: 00003024
dump_stack:     sp: 0x40406650
stack_dump: 0x40406640: 40406650 00000000 4020f688 00000000 00000000 00000000 40212bc8 00000000
stack_dump: 0x40406660: deadbeef deadbeef 40406680 00000000 deadbeef deadbeef 7474754e 00000058
stack_dump: 0x40406680: 404066b8 00000000 00000001 00000000 40406788 00000000 40205cc0 00000000
stack_dump: 0x404066a0: 00000074 00000000 fffffff8 2e323100 00332e30 00000000 40229ae8 00000000
stack_dump: 0x404066c0: 65366708 38383264 69642d30 20797472 206c754a 32203531 20333230 303a3132
stack_dump: 0x404066e0: 39353a30 00000000 0000000a 00000000 00000000 73697200 00762d63 00000000
stack_dump: 0x40406700: ffff9fef ffffffff 40406740 00000000 fff47194 00000000 00000000 00000000
stack_dump: 0x40406720: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406740: 40408720 00000000 40406968 00000000 00000000 00000000 40204e80 00000000
stack_dump: 0x40406760: 00000074 00000000 40213e3c 00000000 fff47194 00000000 40213e64 00000000
stack_dump: 0x40406780: 00000000 00000000 404067d0 00000000 00000001 00000000 00000010 00000000
stack_dump: 0x404067a0: 40408720 00000000 40213f7e 00000000 00000000 00000000 4020c7d6 00000000
stack_dump: 0x404067c0: 00000800 00000000 40219e70 00000000 612f2e2e 2f737070 2f6e6962 74696e69
stack_dump: 0x404067e0: 00000a00 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406800: fff47194 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406820: 00000000 00000000 00000000 00000000 40219e68 00000000 404069e8 00000000
stack_dump: 0x40406840: 40219e68 00000000 40212bc8 00000000 402276b6 00000000 40406870 00000000
stack_dump: 0x40406860: 00000000 00000000 fffffffc ffffffff 40219e68 00000000 404069e8 00000000
stack_dump: 0x40406880: 40400170 00000000 40204fd4 00000000 0000006c 00000000 404069e8 00000000
stack_dump: 0x404068a0: 40400170 00000000 40205098 00000000 40406908 00000000 40208f50 00000000
stack_dump: 0x404068c0: 40406908 00000000 4020c8b0 00000000 40219e68 00000000 404086d0 00000000
stack_dump: 0x404068e0: ffffffda ffffffff 40215b2a 00000000 40406968 00000000 00000001 00000000
stack_dump: 0x40406900: 40400b28 00000000 40219e70 00000000 404086d0 00000000 40407e30 00000000
stack_dump: 0x40406920: 40407370 00000000 40219e70 00000000 00000000 00000000 40219e01 00000000
stack_dump: 0x40406940: 404069e8 00000000 404069e8 00000000 40219e68 00000000 4020dfc6 00000000
stack_dump: 0x40406960: 40219e68 00000000 40205ec8 00000000 fff47194 00000000 404069b0 00000000
stack_dump: 0x40406980: 00000000 00000000 40205ee8 00000000 00000000 00000000 404069b0 00000000
stack_dump: 0x404069a0: 40408830 00000000 4020d876 00000000 40226b00 00000000 40219e68 00000000
stack_dump: 0x404069c0: 40408830 00000000 00000000 00000000 40219e68 00000000 4020d87e 00000000
stack_dump: 0x404069e0: 40406a18 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a00: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a20: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a40: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a60: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a80: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406aa0: 40227710 00000000 40219e68 00000000 40408830 00000000 404001f8 00000000
stack_dump: 0x40406ac0: fffffffe ffffffff 4020eb20 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406ae0: 40406b60 00000000 40406b68 00000000 40219e68 00000000 40408830 00000000
stack_dump: 0x40406b00: 00000c00 00000000 4020d374 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406b20: 00000000 00000000 fffda848 00000000 fffffff3 ffffffff 40400b18 00000000
stack_dump: 0x40406b40: 4040177c 00000000 00000064 00000000 00000c00 00000000 40200fde 00000000
stack_dump: 0x40406b60: 00000000 00000000 40016400 00000000 00000000 00000000 00000c00 00000000
stack_dump: 0x40406b80: 4040177c 00000000 40401780 00000000 40400b28 00000000 40200ed0 00000000
stack_dump: 0x40406ba0: 40600000 00000000 00400000 00000000 00000026 00000000 00000003 00000000
stack_dump: 0x40406bc0: fff47194 00000000 ffff1428 00000000 10000000 00000000 402004fe 00000000
stack_dump: 0x40406be0: 00000400 00000000 4020053c 00000000 00000000 00000000 402000de 00000000
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- -------- 0x404002b0      2048         0     0.0%    irq
dump_task:       0     0   0 FIFO     Kthread N-- Running            0000000000000000 0x40406030      3024      2248    74.3%    Idle Task
dump_task:       1     1 100 RR       Kthread --- Waiting Unlock     0000000000000000 0x4040a060      1952       264    13.5%    lpwork 0x404013e0
```

# NuttX Apps Filesystem

TODO

_Where is `/system/bin/init`? Why is it loaded by NuttX over Semihosting?_

`/system/bin/init` is needed for starting the NuttX Shell (and NuttX Apps) on Star64 JH7110 SBC.

We see it in the NuttX Build Configuration...

```text
→ grep INIT .config
CONFIG_INIT_FILE=y
CONFIG_INIT_ARGS=""
CONFIG_INIT_STACKSIZE=3072
CONFIG_INIT_PRIORITY=100
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

Which says that `../apps` is mounted as `/system`, via Semihosting HostFS.

That's how `/system/bin/init` gets loaded over Semihosting...

```
→ ls ../apps/bin       
getprime hello    init     sh
```

![QEMU reads the Apps Filesystem over Semihosting](https://lupyuen.github.io/images/semihost-qemu.jpg)

We traced the Semihosting Calls in QEMU Kernel Mode, here's what we observed...

[QEMU Kernel Mode Run Log](https://gist.github.com/lupyuen/6888376da6561bdc060c2459dffdef01)

```text
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x802069e8
hostfs_open: relpath=bin/init, oflags=0x1, mode=0x1b6
...
NuttShell (NSH) NuttX-12.2.1-RC0
nsh> nx_start: CPU0: Beginning Idle Loop

nsh> 
nsh> uname -a
posix_spawn: pid=0xc0202978 path=uname file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
hostfs_stat: relpath=bin/uname
host_call: nbr=0x1, parm=0x80208fe0, size=24
exec_spawn: ERROR: Failed to load program 'uname': -2
nxposix_spawn_exec: ERROR: exec failed: 2
NuttX 12.2.1-RC0 cafbbb1 Jul 15 2023 16:55:00 risc-v rv-virt
nsh> 
nsh> ls /
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
hostfs_stat: relpath=bin/ls
host_call: nbr=0x1, parm=0x80208fe0, size=24
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
/:
 dev/
 proc/
 system/
nsh> 
nsh> ls /system
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
hostfs_stat: relpath=bin/ls
host_call: nbr=0x1, parm=0x80208fe0, size=24
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
hostfs_stat: relpath=
host_call: nbr=0x1, parm=0x80209180, size=24
host_call: nbr=0xc, parm=0x80209180, size=8
host_call: nbr=0x2, parm=0x80209190, size=8
 /system
nsh> 
nsh> ls /system/bin
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
hostfs_stat: relpath=bin/ls
host_call: nbr=0x1, parm=0x80208fe0, size=24
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
hostfs_stat: relpath=bin
host_call: nbr=0x1, parm=0x80209180, size=24
host_call: nbr=0xc, parm=0x80209180, size=8
host_call: nbr=0x2, parm=0x80209190, size=8
 /system/bin
nsh> 
nsh> ls /system/bin/init
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
hostfs_stat: relpath=bin/ls
host_call: nbr=0x1, parm=0x80208fe0, size=24
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
hostfs_stat: relpath=bin/init
host_call: nbr=0x1, parm=0x80209180, size=24
host_call: nbr=0xc, parm=0x80209180, size=8
host_call: nbr=0x2, parm=0x80209190, size=8
 /system/bin/init
```

Semihosting won't work on Star64 SBC. Let's replace this with Initial RAM Disk and ROMFS...

(See https://github.com/apache/nuttx/issues/9501)

# Modify NuttX QEMU to Load Initial RAM Disk

TODO

Now we can modify NuttX for QEMU to mount the Apps Filesystem from an Initial RAM Disk instead of Semihosting.

(So later we can replicate this on Star64 JH7110 SBC)

![NuttX for QEMU will mount the Apps Filesystem from an Initial RAM Disk](https://lupyuen.github.io/images/semihost-qemu2.jpg)

We follow the steps from LiteX Arty-A7 (from the previous section)...

We build NuttX QEMU in Kernel Mode: [Build Steps](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/master/boards/risc-v/qemu-rv/rv-virt)

```bash
## Build NuttX QEMU Kernel Mode
./tools/configure.sh rv-virt:knsh64 
make V=1 -j7

## Build Apps Filesystem
make export V=1
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make import V=1
popd
```

We generate the Initial RAM Disk `initrd`...

```bash
cd nuttx
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
```

[(About `genromfs`)](https://www.systutorials.com/docs/linux/man/8-genromfs/)

Initial RAM Disk `initrd` is 7.9 MB...

```text
→ ls -l initrd
-rw-r--r--  1 7902208 Jul 21 13:41 initrd
```

This is how we load the Initial RAM Disk on QEMU: [‘virt’ Generic Virtual Platform (virt)](https://www.qemu.org/docs/master/system/riscv/virt.html#running-linux-kernel)

```bash
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -initrd initrd \
  -nographic
```

_What is the RAM Address of the Initial RAM Disk in QEMU?_

Initial RAM Disk is loaded by QEMU at `0x8400` `0000`...

- ["RAM Disk Address for RISC-V QEMU"](https://github.com/lupyuen/nuttx-star64#ram-disk-address-for-risc-v-qemu)

Below are the files that we changed in NuttX for QEMU to load the Initial RAM Disk (instead of Semihosting)...

- [Modified Files for QEMU with Initial RAM Disk](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/33/files)

We configured QEMU to mount the RAM Disk as ROMFS (instead of Semihosting): [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig)

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

We defined the RAM Disk Memory in the Linker Script: [ld-kernel64.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel64.script#L20-L54)

```text
MEMORY
{
  ...
  /* Added RAM Disk */
  ramdisk (rwx) : ORIGIN = 0x80800000, LENGTH = 16M   /* w/ cache */

  /* This won't work, crashes with a Memory Mgmt Fault...
     ramdisk (rwx) : ORIGIN = 0x84000000, LENGTH = 16M */   /* w/ cache */
}

/* Added RAM Disk */
/* Page heap */

__pgheap_start = ORIGIN(pgram);
__pgheap_size = LENGTH(pgram) + LENGTH(ramdisk);
/* Previously: __pgheap_size = LENGTH(pgram); */

/* Added RAM Disk */
/* Application ramdisk */

__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size = LENGTH(ramdisk);
__ramdisk_end  = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

(We increased RAM Disk Memory from 4 MB to 16 MB because our RAM Disk is now bigger)

At Startup, we mount the RAM Disk: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L83C1-L179C2)

```c
// Called at NuttX Startup
void board_late_initialize(void) {
  // Mount the RAM Disk
  mount_ramdisk();

  /* Perform board-specific initialization */
#ifdef CONFIG_NSH_ARCHINIT
  mount(NULL, "/proc", "procfs", 0, NULL);
#endif
}

// Mount the RAM Disk
int mount_ramdisk(void) {
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
      syslog(LOG_ERR, "Ramdisk length %lu, origin %lx\n",
                                          (ssize_t)__ramdisk_size,
                                          (uintptr_t)__ramdisk_start);
    }

  return ret;
}
```

We copied the RAM Disk from the QEMU Address (0x84000000) to the NuttX Address (__ramdisk_start): [qemu_rv_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L271-L280)

```c
void qemu_rv_kernel_mappings(void) {
  ...
  // Copy 0x84000000 to __ramdisk_start (__ramdisk_size bytes)
  // TODO: RAM Disk must not exceed __ramdisk_size bytes
  memcpy((void *)__ramdisk_start, (void *)0x84000000, (size_t)__ramdisk_size);
```

[(Because somehow `map_region` crashes when we try to map 0x84000000)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/arch/risc-v/src/qemu-rv/qemu_rv_mm_init.c#L280-L287)

We check that the RAM Disk Memory is sufficient: [fs_romfsutil.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk/fs/romfs/fs_romfsutil.c#L85-L105)

```c
static uint32_t romfs_devread32(struct romfs_mountpt_s *rm, int ndx) {
  //// Stop if RAM Disk Memory is too small
  DEBUGASSERT(&rm->rm_buffer[ndx] < __ramdisk_start + (size_t)__ramdisk_size); ////
```

Before making the above changes, here's the log for QEMU Kernel Mode with Semihosting...

```text
+ genromfs -f initrd -d ../apps/bin -V NuttXBootVol
+ riscv64-unknown-elf-size nuttx
   text    data     bss     dec     hex filename
 171581     673   21872  194126   2f64e nuttx
+ riscv64-unknown-elf-objcopy -O binary nuttx nuttx.bin
+ cp .config nuttx.config
+ riscv64-unknown-elf-objdump -t -S --demangle --line-numbers --wide nuttx
+ sleep 10
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -initrd initrd -nographic
ABCnx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
hostfs_stat: relpath=bin/init
hostfs_open: relpath=bin/init, oflags=0x1, mode=0x1b6
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3

NuttShell (NSH) NuttX-12.0.3
nsh> nx_start: CPU0: Beginning Idle Loop
```

Now we run QEMU Kernel Mode with Initial RAM Disk, without Semihosting...

And it boots OK on QEMU yay!

[See the Run Log](https://gist.github.com/lupyuen/8afee5b07b61bb7f9f202f7f8c5e3ab3)

# Load Initial RAM Disk in NuttX Star64

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
