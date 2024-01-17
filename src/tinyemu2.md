# Emulate Ox64 BL808 in the Web Browser: Experiments with TinyEMU RISC-V Emulator and Apache NuttX RTOS

📝 _31 Jan 2024_

![Ox64 BL808 Emulator with TinyEMU RISC-V Emulator and Apache NuttX RTOS](https://lupyuen.github.io/images/tinyemu2-title.png)

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/ox64)

TODO: [_(Watch on YouTube)_](https://youtu.be/KYrdwzIsgeQ)

_In olden times we had Computer Games (plus Operating Systems) on 5.25-inch __Floppy Disks__. And we'd boot the Floppy Disks (clakety-clack) on __Apple II Computers__ with 64 KB RAM._

Today (40 years later) we boot __microSD Cards__ (clickety-click) on [__Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V Single-Board Computers with 64 MB RAM. (Pic below)

_What if we could turn it into a_ [__Virtual Ox64 SBC__](https://lupyuen.github.io/nuttx-tinyemu/ox64) _that boots in our_ [__Web Browser__](https://lupyuen.github.io/nuttx-tinyemu/ox64)? _(Pic above) Exactly like an_ [__Emulated Apple II__](https://www.scullinsteel.com/apple2/#dos33master)!

In this article we...

- Take [__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) precompiled for Ox64

  (Without any modifications!)

- Boot it on the [__TinyEMU RISC-V Emulator__](https://github.com/fernandotcl/TinyEMU)

  [(Which runs in a __Web Browser__)](https://www.barebox.org/jsbarebox/?graphic=1)

- Create our own [__Emulator for Ox64 SBC__](https://lupyuen.github.io/nuttx-tinyemu/ox64)

  (With minor tweaks to TinyEMU)

- And run everything in our __Web Browser__!

  (Thanks to WebAssembly)

_Why NuttX?_

[__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) is a tiny operating system for [__64-bit RISC-V Machines__](https://lupyuen.github.io/articles/riscv) and many other platforms. (Arm, x64, ESP32, ...)

TODO: Simpler to troubleshoot

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sd.jpg)

# Install TinyEMU Emulator

_What's this TinyEMU?_

[__TinyEMU__](https://github.com/fernandotcl/TinyEMU) is a barebones __64-bit RISC-V Emulator__.

It doesn't have all the features of QEMU Emulator. But TinyEMU runs in a [__Web Browser__](https://www.barebox.org/jsbarebox/?graphic=1) and it's much simpler for modding!

We begin by installing (our modded) __TinyEMU for the Command Line__...

```bash
## Download TinyEMU modded for Ox64
git clone https://github.com/lupyuen/ox64-tinyemu
cd ox64-tinyemu

## For Ubuntu:
sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev libsdl2-dev
make

## For macOS:
brew install openssl sdl2
make CFLAGS=-I$(brew --prefix)/opt/openssl/include LDFLAGS=-L$(brew --prefix)/opt/openssl/lib CONFIG_MACOS=y
```

[(See the __Build Script__)](https://github.com/lupyuen/ox64-tinyemu/blob/main/.github/workflows/ci.yml)

_What about TinyEMU for the Web Browser?_

No Worries! Everything that runs in __Command Line__ TinyEMU... Will also run in __Web Browser__ TinyEMU!

We tweak TinyEMU for Ox64...

# Change RISC-V Addresses in TinyEMU

_TinyEMU needs to emulate our Ox64 BL808 SBC. What shall we tweak?_

TinyEMU is hardcoded to run at __Fixed RISC-V Addresses__. (Yep it's really barebones!)

We tweak the RISC-V Addresses in TinyEMU, so that they match the __Bouffalo Lab BL808 SoC__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L66-L82)

```c
// RISC-V Addresses for TinyEMU (modded for Ox64 BL808)
#define LOW_RAM_SIZE    0x00010000ul  // 64 KB of Boot Code at Address 0x0
#define RAM_BASE_ADDR   0x50200000ul  // Our Kernel boots here
#define PLIC_BASE_ADDR  0xe0000000ul  // Platform-Level Interrupt Controller (PLIC)
#define PLIC_SIZE       0x00400000ul  // Address Range of PLIC
#define CLINT_BASE_ADDR 0x02000000ul  // TODO: CLINT is Unused
#define CLINT_SIZE      0x000c0000ul  // TODO: CLINT is Unused
...
#define PLIC_HART_BASE  0x201000  // Hart 0 S-Mode Priority Threshold in PLIC
#define PLIC_HART_SIZE  0x1000    // Address Range of Hart 0 PLIC
```

TODO: Where did we get the addresses?

_What's this Boot Code?_

TinyEMU needs a tiny chunk of __RISC-V Machine Code__ that will jump to our __Kernel Image__ (and pass the Device Tree): [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L862-L872)

```c
// At TinyEMU Startup: Init the Emulated RAM...
static void copy_bios(...) {
  ...
  // Init the TinyEMU Boot Code at Address 0x1000 (ram_ptr is 0x0)
  uint32_t *q = (uint32_t *)(ram_ptr + 0x1000);

  // Load into Register T0 the RAM_BASE_ADDR (0x5020_0000)
  // Load into Register A1 the Binary Device Tree
  q[0] = 0x297 + RAM_BASE_ADDR - 0x1000;    // auipc t0, jump_addr
  q[1] = 0x597;                             // auipc a1, dtb
  q[2] = 0x58593 + ((fdt_addr - 4) << 20);  // addi  a1, a1, dtb

  // Load into Register A0 the Hart ID (RISC-V CPU ID: 0)
  // Jump to Register T0: Our Kernel at RAM_BASE_ADDR (0x5020_0000)
  q[3] = 0xf1402573;  // csrr a0, mhartid
  q[4] = 0x00028067;  // jalr zero, t0, jump_addr
```

And that's our barebones Ox64 Emulator! Let's run it...

[(Remember to enable __Exception Logging__)](https://github.com/lupyuen/ox64-tinyemu/commit/ff10a3065701d049f079ee5f1f6246e47a8345d6)

# Run TinyEMU Emulator

_We modded TinyEMU to emulate Ox64. What happens when we run it?_

We see signs of life... __NuttX Kernel__ is actually booting in our Ox64 Emulator!

```bash
## Download the TinyEMU Config and NuttX Kernel Image
$ wget https://raw.githubusercontent.com/lupyuen/nuttx-tinyemu/main/docs/ox64/root-riscv64.cfg
$ wget https://github.com/lupyuen/nuttx-tinyemu/raw/main/docs/ox64/Image

## Boot TinyEMU with NuttX Kernel
$ temu root-riscv64.cfg | more

csr_write: csr=0x104 val=0x0
csr_write: csr=0x105 val=0x50200090
csr_write: csr=0x100 val=0x200000000
csr_write: csr=0x140 val=0x50400cd0
csr_write: csr=0x180 val=0x0
csr_write: csr=0x105 val=0x50200090
csr_write: csr=0x100 val=0x200002000
csr_write: csr=0x003 val=0x0
csr_write: csr=0x100 val=0x8000000200006000

target_read_slow:
  invalid physical address
  0x30002084
target_write_slow: 
  invalid physical address 
  0x30002088
```

[(See the Complete Log)](https://gist.github.com/lupyuen/6dafe6052eef7c30450a30e4ce1f94fb)

_What's root-riscv64.cfg?_

It's the __TinyEMU Config__ that will boot NuttX Kernel in our Ox64 Emulator: [root-riscv64.cfg](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/ox64/root-riscv64.cfg)

```json
/* VM configuration file */
{
  version: 1,
  machine: "riscv64",
  memory_size: 256,
  bios: "Image",
}
```

__`Image`__ is the __NuttX Kernel Image__ comes from a typical [__NuttX Build for Ox64__](https://github.com/lupyuen/nuttx-ox64/releases).

_What are the CSR Writes?_

```bash
csr_write: csr=0x104 val=0x0
csr_write: csr=0x105 val=0x50200090
csr_write: csr=0x100 val=0x200000000
```

CSR refers to [__Control and Status Registers__](https://five-embeddev.com/quickref/csrs.html). They're the System Registers in our RISC-V SoC (BL808)...

- [__CSR `0x104`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-interrupt-registers-sip-and-sie): __Supervisor-Mode Interrupt Enable__

  (Enable or Disable Interrupts)

- [__CSR `0x105`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-trap-vector-base-address-register-stvec): __Supervisor-Mode Trap Vector Base Address__

  (Set the Interrupt Vector Table)

- [__CSR `0x100`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sstatus): __Supervisor-Mode Status__

  TODO: (Set the Status)

  (Why Supervisor-Mode? We'll find out later)

_Why is it writing to CSR Registers?_

This comes from our __NuttX Boot Code__

TODO: NuttX Boot Code

# UART Registers for BL808 SoC

_What are 0x3000_2084 and 0x3000_2088? Why are they invalid?_

```yaml
target_read_slow:
  invalid physical address
  0x30002084
target_write_slow: 
  invalid physical address 
  0x30002088
```

TODO

From our [BL808 UART Docs](https://lupyuen.github.io/articles/ox2#print-to-serial-console)...

- 0x3000_2088 (uart_fifo_wdata) means NuttX is writing to the UART Output Register. It's printing something to the console! [(BL808 Reference Manual, Page 428)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

- 0x3000_2084 (uart_fifo_config_1) means NuttX is checking if UART Transmit is ready. [(BL808 Reference Manual, Page 427)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

  [(`*0x30002084 & 0x3f` must be non-zero to indicate that UART Transmit is ready)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L594-L615)

- That's why we always see "read 0x3000_2084" before "write 0x3000_2088".

  [(See `bl808_send`)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L594-L615)

Note that we're still booting in RISC-V Machine Mode! This will cause problems later, because NuttX Ox64 expects to boot in RISC-V Supervisor Mode. (Due to OpenSBI)

# Intercept UART Registers for Ox64 BL808 Emulator

TODO

Let's intercept the "read 0x3000_2084" and "write 0x3000_2088" in TinyEMU Emulator for Ox64 BL808, so we can print the UART Output.

We handle all "read 0x3000_2084" (uart_fifo_config_1) by returning 32 (TX FIFO Available Count), to tell NuttX that the UART Port is always ready to transmit: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/commit/14badbc271f6dfe9602b889e4636c855833874d3)

```c
/* return 0 if OK, != 0 if exception */
int target_read_slow(RISCVCPUState *s, mem_uint_t *pval, target_ulong addr, int size_log2) {
...        
  pr = get_phys_mem_range(s->mem_map, paddr);
  if (!pr) {
    //// Begin Test: Intercept Memory-Mapped I/O
    switch(paddr & 0xfffffffffffful) {  // TODO: Why does NuttX read from 0x4000000030002084?
    case 0x30002084:     // uart_fifo_config_1: Is UART Ready?
      ret = 32; break; // UART TX is always ready, default TX FIFO Available is 32

    default:  // Unknown Memory-Mapped I/O
#ifdef DUMP_INVALID_MEM_ACCESS
      printf("target_read_slow: invalid physical address 0x");
      print_target_ulong(paddr);
      printf("\n");
#endif
      return 0;
    }
    //// End Test
```

We handle all "write 0x3000_2088" (uart_fifo_wdata) by printing the character to the UART Output Register: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/commit/14badbc271f6dfe9602b889e4636c855833874d3)

```c
/* return 0 if OK, != 0 if exception */
int target_write_slow(RISCVCPUState *s, target_ulong addr, mem_uint_t val, int size_log2) {
...
  pr = get_phys_mem_range(s->mem_map, paddr);
  if (!pr) {
    //// Begin Test: Intercept Memory-Mapped I/O
    switch(paddr & 0xfffffffffffful) {  // TODO: Why does NuttX write to 0x4000000030002088?
    case 0x30002088:  // uart_fifo_wdata: UART Output
      putchar(val); break;  // Print the character

    default:  // Unknown Memory-Mapped I/O
#ifdef DUMP_INVALID_MEM_ACCESS
      printf("target_write_slow: invalid physical address 0x");
      print_target_ulong(paddr);
      printf("\n");
#endif                
    }
    //// End Test
```

Here's the [TinyEMU Log for Intercepted UART Registers](https://gist.github.com/lupyuen/efb6750b317f52b629c115ac16635177). We see NuttX booting on TinyEMU yay!

```text
$ temu root-riscv64.cfg | more
virtio_console_init
ABCnx_start: Entry
mm_initialize: Heap: name=Kmem, start=0x50407c00 size=2065408
mm_addregion: [Kmem] Region 1: base=0x50407ea8 size=2064720
mm_malloc: Allocated 0x50407ed0, size 704
mm_malloc: Allocated 0x50408190, size 48
...
uart_register: Registering /dev/console
target_read_slow: invalid physical address 0x0000000030002024
target_write_slow: invalid physical address 0x0000000030002024
work_start_lowpri kernel worker thread(s)
uart_register: Registering /dev/console
target_read_slow: invalid physical address 0x0000000030002024
target_write_slow: invalid physical address 0x0000000030002024
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_applicaystem/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Fa: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
mm_initialize: Heap: name=(null), start=0x80200000 size=528384
mm_addregion: [(null)] Region 1: base=0x802002a8 size=527696
mm_initialize: Heap: name=(null), start=0x80200000 size=528384
mm_addregion: [(null)] Region 1: base=0x802002a8 size=527696
up_exit: TCB=0x504098d0 exiting
raise_exception2: cause=8, tval=0x0
pc =00000000800019c6 ra =0000000080000086 sp =0000000080202bc0 gp =0000000000000000
tp =0000000000000000 t0 =0000000000000000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000001 s1 =0000000080202010 a0 =000000000000000d a1 =0000000000000000
a2 =0000000080202bc8 a3 =0000000080202010 a4 =0000000080000030 a5 =0000000000000000
a6 =0000000000000101 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=U mstatus=0000000a0006806
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
raise_exception2: cause=2, tval=0x0
raise_exception2: cause=2, tval=0x0
...
raise_exception2: cause=2, tval=0x0
up_exit: TCB=0x504098d0 exiting
raise_exception2: cause=8, tval=0x0
pc =00000000800019c6 ra =0000000080000086 sp =0000000080202bc0 gp =0000000000000000
tp =0000000000000000 t0 =0000000000000000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000001 s1 =0000000080202010 a0 =000000000000000d a1 =0000000000000000
a2 =0000000080202bc8 a3 =0000000080202010 a4 =0000000080000030 a5 =0000000000000000
a6 =00000000000001 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=U mstatus=0000000a00040021 cycles=82846806
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
raise_exception2: cause=2, tval=0x0
raise_exception2: cause=2, tval=0x0
```

TODO: Why does NuttX read from 0x4000000030002084? Probably due to T-Head C906 MMU Flags

TODO: What is `raise_exception2: cause=2, tval=0x0`?

TODO: Why is NuttX Shell started twice? Because it failed? (`/system/bin/init`)

# NuttX Exception in Ox64 BL808 Emulator

TODO

_What is `raise_exception2: cause=8`?_

From the [TinyEMU Log for Intercepted UART Registers](https://gist.github.com/lupyuen/efb6750b317f52b629c115ac16635177)...

```text
up_exit: TCB=0x504098d0 exiting
raise_exception2: cause=8, tval=0x0
pc =00000000800019c6 ra =0000000080000086 sp =0000000080202bc0 gp =0000000000000000
tp =0000000000000000 t0 =0000000000000000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000001 s1 =0000000080202010 a0 =000000000000000d a1 =0000000000000000
a2 =0000000080202bc8 a3 =0000000080202010 a4 =0000000080000030 a5 =0000000000000000
a6 =0000000000000101 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=U mstatus=0000000a0006806
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
raise_exception2: cause=2, tval=0x0
```

We look up the offending Code Address: `pc=8000_19c6`. This address comes from the NuttX App Virtual Memory: [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/heapcrash/boards/risc-v/bl808/ox64/configs/nsh/defconfig#L17-L30)

```bash
CONFIG_ARCH_TEXT_VBASE=0x80000000
CONFIG_ARCH_TEXT_NPAGES=128
CONFIG_ARCH_DATA_VBASE=0x80100000
CONFIG_ARCH_DATA_NPAGES=128
CONFIG_ARCH_HEAP_VBASE=0x80200000
CONFIG_ARCH_HEAP_NPAGES=128
```

The only NuttX App we're running is the NuttX Shell. So we look up the RISC-V Disassembly for the NuttX Shell: [init.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/ox64/init.S#L45327-L45358)

```text
nuttx/syscall/proxies/PROXY_sched_getparam.c:8
int sched_getparam(pid_t parm1, FAR struct sched_param * parm2) {
...
00000000000019c6 <.LVL4>:
nuttx/include/arch/syscall.h:229
  asm volatile
    19c6:	00000073          	ecall
```

0x19c6 is an ECALL from NuttX App (RISC-V User Mode) to NuttX Kernel (RISC-V Supervisor Mode). Our NuttX Shell is making a System Call to NuttX Kernel!

Which fails because everything runs in RISC-V Machine Mode right now. We will need to start TinyEMU in RISC-V Supervisor Mode (instead of Machine Mode).

[(We quit if mcause=2, otherwise it will loop forever)](https://github.com/lupyuen/ox64-tinyemu/commit/9da5b066c9fe29ef46b93ff8174662d5e6858038)

# Emulate Ox64 BL808 in Web Browser

TODO

_Will our Ox64 BL808 Emulator run in the Web Browser?_

Let's find out! First we fix the [TinyEMU Build for Emscripten](https://github.com/lupyuen/ox64-tinyemu/commit/170abb06b58a58328efa8a1874795f1daac0b7a7).

Print to Device Console instead of JavaScript Console:

https://github.com/lupyuen/ox64-tinyemu/commit/41383b85be0f0a16369d2661338487dd28a56a75

And it runs OK in Web Browser yay!

https://lupyuen.github.io/nuttx-tinyemu/ox64/

TODO: Emulate BL808 GPIO to Blink an LED

# Emulate Ox64 BL808 SBC with TinyEMU

TODO

Objective: Take the NuttX Kernel built for [Ox64 BL808 SBC](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358). And boot it on TinyEMU RISC-V Emulator in the Web Browser!

1.  Fix these RISC-V Addresses in TinyEMU to follow BL808 Memory Map: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

    ```c
    #define LOW_RAM_SIZE   0x00010000 /* 64KB */
    #define RAM_BASE_ADDR  0x80000000
    #define CLINT_BASE_ADDR 0x02000000
    #define CLINT_SIZE      0x000c0000
    #define DEFAULT_HTIF_BASE_ADDR 0x40008000
    #define VIRTIO_BASE_ADDR 0x40010000
    #define VIRTIO_SIZE      0x1000
    #define VIRTIO_IRQ       1
    #define PLIC_BASE_ADDR 0x40100000
    #define PLIC_SIZE      0x00400000
    #define FRAMEBUFFER_BASE_ADDR 0x41000000

    #define RTC_FREQ 10000000
    #define RTC_FREQ_DIV 16 /* arbitrary, relative to CPU freq to have a
                              10 MHz frequency */
    ```

1.  Start TinyEMU in RISC-V Supervisor Mode (instead of Machine Mode)

    (So we don't need OpenSBI and U-Boot Bootloader)

1.  Emulate [OpenSBI Timer](https://lupyuen.github.io/articles/nim#appendix-opensbi-timer-for-nuttx)

    (Intercept the Supervisor-To-Machine Mode ECALL)

1.  Emulate BL808 UART I/O (Memory Mapped I/O and PLIC Interrupts)

    (So we can run NuttX Shell)

1.  Emulate BL808 GPIO Output (Memory Mapped I/O)

    (So we can test Nim Blinky)

Let's try booting NuttX Ox64 on TinyEMU...

TODO: Wrap TinyEMU with Zig for Memory Safety and WebAssembly?

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tinyemu2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tinyemu2.md)
