# Emulate Ox64 BL808 in the Web Browser: Experiments with TinyEMU RISC-V Emulator and Apache NuttX RTOS

📝 _31 Jan 2024_

![Ox64 BL808 Emulator with TinyEMU RISC-V Emulator and Apache NuttX RTOS](https://lupyuen.github.io/images/tinyemu2-title.png)

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/ox64)

TODO: [_(Watch on YouTube)_](https://youtu.be/KYrdwzIsgeQ)

_In olden times we had Computer Games (plus Operating Systems) on 5.25-inch __Floppy Disks__. And we'd boot the Floppy Disks (clackety-clack) on __Apple II Computers__ with 64 KB RAM._

Today (40 years later) we boot __microSD Cards__ (clickety-click) on [__Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V Single-Board Computers with 64 MB RAM. (Pic below)

_What if we could turn it into a_ [__Virtual Ox64 SBC__](https://lupyuen.github.io/nuttx-tinyemu/ox64) _that boots in our_ [__Web Browser__](https://lupyuen.github.io/nuttx-tinyemu/ox64)? _(Pic above) Exactly like an_ [__Emulated Apple II__](https://www.scullinsteel.com/apple2/#dos33master)!

In this article we...

- Take [__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) precompiled for Ox64

  (Without any modifications)

- Boot it on the [__TinyEMU RISC-V Emulator__](https://github.com/fernandotcl/TinyEMU)

  [(Which runs in a __Web Browser__)](https://www.barebox.org/jsbarebox/?graphic=1)

- Create our own [__Emulator for Ox64 SBC__](https://lupyuen.github.io/nuttx-tinyemu/ox64)

  (With minor tweaks to TinyEMU)

- And run everything in our __Web Browser__

  (Thanks to WebAssembly)

_Why NuttX?_

[__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) is a tiny operating system for [__64-bit RISC-V Machines__](https://lupyuen.github.io/articles/riscv). (Also Arm, x64, ESP32, ...)

Which makes it easier to understand __everything that happens__ as NuttX boots on our Ox64 Emulator.

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

No Worries! Everything that runs in __Command Line__ TinyEMU... Will also run in __Web Browser__ TinyEMU.

We tweak TinyEMU for Ox64...

# Change RISC-V Addresses in TinyEMU

_TinyEMU needs to emulate our Ox64 BL808 SBC. What shall we tweak?_

TinyEMU is hardcoded to run at __Fixed RISC-V Addresses__. (Yep it's really barebones)

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

[(See the __Complete Log__)](https://gist.github.com/lupyuen/6dafe6052eef7c30450a30e4ce1f94fb)

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

__`Image`__ is the __NuttX Kernel Image__ that comes from a typical [__NuttX Build for Ox64__](https://github.com/lupyuen/nuttx-ox64/releases).

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

Let's talk about the invalid reads and writes...

TODO: BL808 UART Registers

# UART Registers for BL808 SoC

_What are 0x3000_2084 and 0x3000_2088? Why are they Invalid Addresses?_

```yaml
target_read_slow:
  invalid physical address
  0x30002084

target_write_slow: 
  invalid physical address 
  0x30002088
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/6dafe6052eef7c30450a30e4ce1f94fb)

We dig around the [__BL808 Reference Manual__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) (pic above) and we discover these __UART Registers__...

- __`0x3000_2088`__ is [__uart_fifo_wdata__ (Page 428)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) 

  We write to this UART Register to __print a character__ to UART Output.

- __`0x3000_2084`__ is [__uart_fifo_config_1__ (Page 427)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) 

  We read this UART Register to check if __UART Transmit is ready__ (for more output).

- Which explains why we always see "__read `0x3000_2084`__" before "__write `0x3000_2088`__"...

  NuttX Kernel is trying to [__print something__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L594-L615) to the UART Console!

  ```c
  // NuttX sends a character to the UART Port...
  void bl808_send(struct uart_dev_s *dev, int ch) {
    ...
    // Wait for Transmit FIFO to be empty.
    // FIFO_CONFIG_1 is 0x3000_2084
    // TX_CNT_MASK is 0x3F
    while ((getreg32(BL808_UART_FIFO_CONFIG_1(uart_idx)) &
      UART_FIFO_CONFIG_1_TX_CNT_MASK) == 0) {}

    // Write character to Transmit FIFO.
    // FIFO_WDATA is 0x3000_2088
    putreg32(ch, BL808_UART_FIFO_WDATA(uart_idx));
  ```

  [(`0x3000_2000` is the __UART3 Base Address__, Page 41)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

  [(More about __BL808 UART__)](https://lupyuen.github.io/articles/ox2#print-to-serial-console)...

_But why are they Invalid Addresses?_

We haven't defined in TinyEMU the addresses for __Memory-Mapped Input / Output__. (Like for UART Registers)

That's why TinyEMU __won't read and write__ our UART Registers. Let's fix this...

# Intercept the UART Registers

_NuttX tries to print something but fails..._

_How to fix the UART Registers in our Ox64 Emulator?_

Inside TinyEMU, we intercept all "__read `0x3000_2084`__" and "__write `0x3000_2088`__". And we pretend to be a __UART Port__...

## Emulate the UART Status

Earlier we said...

> __`0x3000_2084`__ is [__uart_fifo_config_1__ (Page 427)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) 

> _We read this UART Register to check if __UART Transmit is ready__ (for more output)_

In TinyEMU: We intercept "__read `0x3000_2084`__" and return the value `32`: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L377-L392)

```c
// TinyEMU reads a Memory Address...
int target_read_slow(RISCVCPUState *s, mem_uint_t *pval, target_ulong addr, int size_log2) {
...
  // If the Memory Address is not mapped...
  pr = get_phys_mem_range(s->mem_map, paddr);
  if (!pr) {
    // Because of T-Head MMU Flags, Emulator might read from 0x4000000030002084 
    // https://lupyuen.github.io/articles/plic3#t-head-errata
    switch(paddr & 0xfffffffffffful) {  

      // If we're reading uart_fifo_config_1:
      // Tell Emulator that UART Transmit is always ready
      case 0x30002084:
        ret = 32; break;

      // If Unknown Address:
      // Print "target_read_slow: invalid physical address"
      default:
        ...
```

_Why 32?_

Our __NuttX UART Driver__ checks the lower bits of __`0x3000_2084`__: [bl808_serial.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L594-L615)

```c
// NuttX sends a character to the UART Port...
void bl808_send(struct uart_dev_s *dev, int ch) {
  ...
  // Wait for Transmit FIFO to be empty.
  // FIFO_CONFIG_1 is 0x3000_2084
  // TX_CNT_MASK is 0x3F
  while ((getreg32(BL808_UART_FIFO_CONFIG_1(uart_idx)) &
    UART_FIFO_CONFIG_1_TX_CNT_MASK) == 0) {}

  // Omitted: Write character to Transmit FIFO.
```

And the [__UART Transmit Buffer Size__ (Page 427)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) defaults to `32`. Thus we always return `32`.

## Emulate the UART Output

Earlier we saw...

> __`0x3000_2088`__ is [__uart_fifo_wdata__ (Page 428)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) 

> _We write to this UART Register to __print a character__ to UART Output_

In TinyEMU: We intercept all "__write `0x3000_2088`__" by printing the character: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L472-L490)

```c
// TinyEMU writes to a Memory Address...
int target_write_slow(RISCVCPUState *s, target_ulong addr, mem_uint_t val, int size_log2) {
...
  // If the Memory Address is not mapped...
  pr = get_phys_mem_range(s->mem_map, paddr);
  if (!pr) {
    // Because of T-Head MMU Flags, Emulator might write to 0x4000000030002088
    // https://lupyuen.github.io/articles/plic3#t-head-errata
    switch(paddr & 0xfffffffffffful) { 

      // If we're writing to uart_fifo_wdata:
      // Print the character
      case 0x30002088:
        char buf[1];
        buf[0] = val;
        print_console(NULL, buf, 1);
        break;

      // If Unknown Address:
      // Print "target_write_slow: invalid physical address"
      default:
        ...
```
[(__print_console__ is defined here)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1127-L1138)

[(__riscv_machine_init__ inits the console)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L956-L963)

# Emulator Prints To Console

_We modded our Ox64 Emulator to handle UART Output. Does it work?_

Yep, we see NuttX booting on our Ox64 Emulator yay!

```bash
## Boot TinyEMU with NuttX Kernel
$ temu root-riscv64.cfg | more

ABC
nx_start: Entry
mm_initialize: Heap: name=Kmem, start=0x50407c00 size=2065408
mm_addregion:  [Kmem] Region 1: base=0x50407ea8 size=2064720
uart_register: Registering /dev/console
target_read_slow:  invalid physical address 0x0000000030002024
target_write_slow: invalid physical address 0x0000000030002024
work_start_lowpri: Starting low-priority kernel worker thread(s)

nx_start_application: Starting init task: /system/bin/init
mm_initialize: Heap: name=(null), start=0x80200000 size=528384
mm_addregion: [(null)] Region 1: base=0x802002a8 size=527696
up_exit: TCB=0x504098d0 exiting
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/efb6750b317f52b629c115ac16635177)

Followed by this __RISC-V Exception__...

```bash
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
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/efb6750b317f52b629c115ac16635177)

Why? We investigate the alligator in the vest...

# RISC-V Exception in Emulator

_What's this RISC-V Exception?_

```yaml
raise_exception2:
  cause=8, tval=0x0
  pc=800019c6
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/efb6750b317f52b629c115ac16635177)

We look up the offending Code Address: __`0x8000_19C6`__.

This address comes from the Virtual Memory of a __NuttX App__ (not the NuttX Kernel): [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/heapcrash/boards/risc-v/bl808/ox64/configs/nsh/defconfig#L17-L30)

```bash
## Virtual Memory of NuttX Apps:
## Code, Data and Heap
CONFIG_ARCH_TEXT_VBASE=0x80000000
CONFIG_ARCH_DATA_VBASE=0x80100000
CONFIG_ARCH_HEAP_VBASE=0x80200000
```

_What NuttX App are we running?_

The only NuttX App we're running at Startup is the __NuttX Shell__.

Thus we look up the __RISC-V Disassembly__ for the NuttX Shell: [init.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/ox64/init.S#L45327-L45358)

```c
nuttx/syscall/proxies/PROXY_sched_getparam.c:8
  int sched_getparam(pid_t parm1, FAR struct sched_param * parm2) {
  ...
  nuttx/include/arch/syscall.h:229
    19c6: 00000073  ecall
```

_What's ecall?_

At `0x19C6` we see the __RISC-V ECALL Instruction__ that will jump from our NuttX App (RISC-V User Mode) to NuttX Kernel (RISC-V Supervisor Mode). 

Hence our NuttX Shell is making a __System Call__ to NuttX Kernel!

Why did it fail? We'll come back to this, first we surf the web...

[(We quit if __MCAUSE is 2__, otherwise we loop forever)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L1142-L1147)

# Emulator in the Web Browser

_Will our Ox64 Emulator run in the Web Browser?_

TODO

Let's find out! First we fix the [TinyEMU Build for Emscripten](https://github.com/lupyuen/ox64-tinyemu/commit/170abb06b58a58328efa8a1874795f1daac0b7a7).

[And it runs OK in Web Browser yay!](https://lupyuen.github.io/nuttx-tinyemu/ox64/)

TODO: Emulate BL808 GPIO to Blink an LED

_What about Console Input?_

Console Input requires [__UART Interrupts__](https://lupyuen.github.io/articles/plic2). We'll implement UART Interrupts soon. (Pic below)

One more thing to tweak...

![UART Interrupts for Ox64 BL808 SBC](https://lupyuen.github.io/images/plic2-registers.jpg)

# Machine Mode vs Supervisor Mode

_Back to our earlier question: Why did our System Call fail?_

Our NuttX App (NuttX Shell) tried to make a __System Call (ECALL)__ to NuttX Kernel. And it failed: [init.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/ox64/init.S#L45327-L45358)

```c
nuttx/syscall/proxies/PROXY_sched_getparam.c:8
  int sched_getparam(pid_t parm1, FAR struct sched_param * parm2) {
  ...
  // ECALL fails with a RISC-V Exception
  nuttx/include/arch/syscall.h:229
    19c6: 00000073  ecall
```

TODO: (See the __Source Code__)

_What's ECALL again?_

The __RISC-V ECALL Instruction__ normally jumps...

- From our __NuttX App__

  (In __RISC-V User Mode__)
  
- To the __NuttX Kernel__

  (In __RISC-V Supervisor Mode__)

- In order to make a __System Call__

  (Which failed)

__System Calls__ are absolutely essential. That's how our apps will execute system functions, like printing to the Console Output.

_Why did ECALL fail?_

That's because our NuttX App is actually running in __RISC-V Machine Mode__, not User Mode!

Machine Mode is the __most powerful mode__ in a RISC-V System, more powerful than Supervisor Mode and User Mode...

And Machine Mode __can't possibly make ECALLS__ to a Higher Mode!

TODO: Pic of Machine, Supervisor, User Modes. Start / System Call (ECALL)

_Huh! How did that happen?_

TinyEMU always __starts in Machine Mode__. Everything we saw today: That's all running in (super-powerful) Machine Mode.

But a __Real Ox64 SBC__ is a little different...

1.  Ox64 boots the __OpenSBI Supervisor Binary Interface__ in __Machine Mode__...

    (Think BIOS, but for RISC-V Machines)

1.  Which starts the __U-Boot Bootloader__ in __Supervisor Mode__...

1.  Which starts the __NuttX Kernel__, also in __Supervisor Mode__...

1.  And NuttX Kernel starts the __NuttX Apps__ in __User Mode__

TODO: Pic of OpenSBI, U-Boot, Kernel, Apps

_So we need to start NuttX Kernel in Supervisor Mode?_

Yep, we need more tweaks in TinyEMU to start NuttX in Supervisor Mode. (Instead of Machine Mode)

TODO: (Maybe in the TinyEMU Boot Code)

TODO: Pic of TinyEMU, Kernel, Apps. Start / System Call (ECALL). Emulate OpenSBI Timer

_Any other gotchas?_

There's a tiny quirk: NuttX Kernel will __make an ECALL__ too...

NuttX Kernel makes a __System Call to OpenSBI__ to set the System Timer. (Pic above)

_Do we plan to boot OpenSBI on TinyEMU?_

That's not necessary. We'll __emulate the OpenSBI__ System Timer in TinyEMU. (Pic above)

TODO: More about System Timer

(It's truly amazing we managed to boot so much in Machine Mode)

TODO

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
