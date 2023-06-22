# 64-bit RISC-V with Apache NuttX RTOS

📝 _1 Jul 2023_

![Apache NuttX RTOS on 64-bit QEMU RISC-V Emulator](https://lupyuen.github.io/images/riscv-title.png)

[__Apache NuttX__](https://nuttx.apache.org/docs/latest/index.html) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

(Think Linux, but a lot smaller and simpler)

In this article we'll...

-   Boot NuttX RTOS on a __64-bit RISC-V__ device

-   Explore the __Boot Code__ that starts NuttX on RISC-V

-   And learn a little __RISC-V Assembly__!

_But we need RISC-V Hardware?_

No worries! We'll run NuttX on the __QEMU Emulator__ for 64-bit RISC-V.

(Which will work on Linux, macOS and Windows machines)

# Boot NuttX on 64-bit RISC-V QEMU

We begin by __booting NuttX RTOS__ on RISC-V QEMU Emulator (64-bit)...

1.  Download and install [__QEMU Emulator__](https://www.qemu.org/download/)...

    For macOS we may use __`brew`__...

    ```bash
    brew install qemu
    ```

1.  Download __`nuttx`__ from the [__NuttX Release__](https://github.com/lupyuen/lupyuen.github.io/releases/tag/nuttx-riscv64)...

    [__nuttx: NuttX Image for 64-bit RISC-V QEMU__](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx)

    If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

1.  Start the __QEMU RISC-V Emulator__ (64-bit) with NuttX RTOS...

    ```bash
    qemu-system-riscv64 \
      -semihosting \
      -M virt,aclint=on \
      -cpu rv64 \
      -smp 8 \
      -bios none \
      -kernel nuttx \
      -nographic
    ```

1.  NuttX is now running in the QEMU Emluator!

    ```text
    uart_register: Registering /dev/console
    uart_register: Registering /dev/ttyS0
    nx_start_application: Starting init thread

    NuttShell (NSH) NuttX-12.1.0-RC0
    nsh> nx_start: CPU0: Beginning Idle Loop
    nsh>
    ```

    [(See the Complete Log)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

1.  Enter "__help__" to see the available commands...

    ```text
    nsh> help
    help usage:  help [-v] [<cmd>]

        .         break     dd        exit      ls        ps        source    umount
        [         cat       df        false     mkdir     pwd       test      unset
        ?         cd        dmesg     free      mkrd      rm        time      uptime
        alias     cp        echo      help      mount     rmdir     true      usleep
        unalias   cmp       env       hexdump   mv        set       truncate  xd
        basename  dirname   exec      kill      printf    sleep     uname

    Builtin Apps:
        nsh     ostest  sh
    ```

1.  NuttX works like a tiny version of Linux, so the commands will look familiar...

    ```text
    nsh> uname -a
    NuttX 12.1.0-RC0 275db39 Jun 16 2023 20:22:08 risc-v rv-virt

    nsh> ls /dev
    /dev:
    console
    null
    ttyS0
    zero

    nsh> ps
      PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK           STACK   USED  FILLED COMMAND
        0     0   0 FIFO     Kthread N-- Ready              0000000000000000 002000 001224  61.2%  Idle Task
        1     1 100 RR       Task    --- Running            0000000000000000 002992 002024  67.6%  nsh_main
    nsh>
    ```

    [(See the Complete Log)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

TODO

# QEMU Emulator for RISC-V

_Earlier we ran this command. What does it mean?_

```bash
qemu-system-riscv64 \
  -kernel nuttx \
  -cpu rv64 \
  -smp 8 \
  -M virt,aclint=on \
  -semihosting \
  -bios none \
  -nographic
```

The above command starts the [__QEMU Emulator for RISC-V__](https://www.qemu.org/docs/master/system/target-riscv.html) (64-bit) with...

- Kernel Image: __nuttx__ 

- CPU: [__64-bit RISC-V__](https://www.qemu.org/docs/master/system/target-riscv.html)

- Symmetric Multiprocessing: __8 CPU Cores__

- Machine: [__Generic Virtual Platform (virt)__](https://www.qemu.org/docs/master/system/riscv/virt.html)

- Handle Interrupts with [__Advanced Core Local Interruptor (ACLINT)__](https://patchwork.kernel.org/project/qemu-devel/cover/20210724122407.2486558-1-anup.patel@wdc.com/)

  (Instead of the older SiFive CLINT)

- Enable [__Semihosting Debugging__](https://www.qemu.org/docs/master/about/emulation.html#semihosting) without BIOS

TODO

# QEMU Starts NuttX

_What happens when NuttX RTOS boots on QEMU?_

Let's find out by tracing the __RISC-V Boot Code__ in NuttX!

Earlier we ran this command to generate the [__RISC-V Disassembly__](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu) for the NuttX Kernel...

```bash
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

This produces [__nuttx.S__](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx.S), the disassembled NuttX Kernel for RISC-V.

[__nuttx.S__](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx.S) begins with this RISC-V code...

```text
0000000080000000 <__start>:
nuttx/arch/risc-v/src/chip/qemu_rv_head.S:46
__start:
  /* Load mhartid (cpuid) */
  csrr a0, mhartid
    80000000:	f1402573  csrr  a0, mhartid
```

This says...

- NuttX Boot Code is at [__qemu_rv_head.S__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L41-L120)

- NuttX Kernel begins execution at address __`0x8000` `0000`__

  (Why? What if NuttX is started by the U-Boot Bootloader?)

TODO

# RISC-V Boot Code in NuttX

TODO

1.  Get the __CPU ID__

1.  Set the __Stack Pointer__

1.  Check the __Number of CPUs__

1.  Disable __Interrupts__

1.  Load the __Vector Base Address__

1.  Jump to __qemu_rv_start__

Let's decipher the RISC-V Instructions in our Boot Code...

## Get CPU ID

This is how we fetch the __CPU ID__ in RISC-V Assembly: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L43-L47)

```text
/* Load mhartid (cpuid) */
csrr  a0, mhartid
```

Let's break it down...

- __csrr__ is the RISC-V Instruction that reads the [__Control and Status Register__](https://five-embeddev.com/riscv-isa-manual/latest/csr.html)

  (Which contains the CPU ID)

- __a0__ is the RISC-V Register that will be loaded with the CPU ID.

  According to the [__RISC-V EABI__](https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc) (Embedded Application Binary Interface), __a0__ is actually an alias for the Official RISC-V Register __x10__.

  ("a" refers to "Function Call Argument")

- __mhartid__ says that we'll read from the [__Hart ID Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid), containing the ID of the Hardware Thread ("Hart") that's running our code.

  (Equivalent to CPU ID)

So the above line of code will load the CPU ID into Register __x10__.

(We'll call it __a0__ for convenience)

## Disable Interrupts

To __disable interrupts__ in RISC-V, we do this: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L98-L102)

```text
/* Disable all interrupts (i.e. timer, external) in mie */
csrw  mie, zero
```

Which means...

- __csrw__ will write to the [__Control and Status Register__](https://five-embeddev.com/riscv-isa-manual/latest/csr.html)

  (Which controls interrupts and other things)

- __mie__ says that we'll write to the [__Machine Interrupt Enable Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-interrupt-registers-mip-and-mie)

  (0 to Disable Interrupts, 1 to Enable)

- __zero__ says that we'll read from [__Register x0__](https://five-embeddev.com/quickref/regs_abi.html)...

  Which always reads as 0!

Thus the instruction will set the Machine Interrupt Enable Register to 0, which will disable interrupts.

(Yeah RISC-V has a funny concept of "0")

## Wait for Interrupt

TODO

```text
  csrw mie, zero
  wfi

wfi: Wait for Interrupt
which will never happen because we disabled interrupts
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#wfi
```

## Load Vector Base Address

TODO

[trap_vec](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_vectors.S)

```text
  la   t0, __trap_vec
  csrw mtvec, t0

csrw: Write Control and Status Register
https://five-embeddev.com/riscv-isa-manual/latest/csr.html

mtvec: Machine Trap-Vector Base-Address Register
The mtvec register is an MXLEN-bit WARL read/write register that holds trap vector configuration, consisting of a vector base address (BASE) and a vector mode (MODE).
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-vector-base-address-register-mtvec
```

## 32-bit vs 64-bit RISC-V

TODO

```text
#ifdef CONFIG_ARCH_RV32
  slli t1, a0, 2
#else
  slli t1, a0, 3
#endif

works with 32-bit and 64-bit modes!
sounds like "silly"
but it's Logical Shift Left
https://five-embeddev.com/riscv-isa-manual/latest/rv64.html#integer-computational-instructions
```

## Other Instructions

_What about the other RISC-V Instructions in our Boot Code?_

Let's skim through the rest...

TODO

```text
  bnez a0, 1f
  la   sp, QEMU_RV_IDLESTACK_TOP
  j    2f
  li   t1, 1
  blt  a0, t1, 3f
  add  t0, t0, t1
  REGLOAD sp, 0(t0)
  jal  x1, qemu_rv_start
  ret
```

[REGLOAD](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_internal.h#L55-L63) expands to __ld__

# Jump to Start

TODO

```text
qemu_rv_start
https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L151
Calls nx_start
```

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/riscv.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/riscv.md)

# Appendix: Build Apache NuttX RTOS for 64-bit RISC-V QEMU

The easiest way to run __Apache NuttX RTOS on 64-bit RISC-V__ is to download the __NuttX Image__ and boot it on QEMU Emulator...

-   TODO: [__"Boot NuttX on PinePhone"__](TODO)

But if we're keen to __build NuttX ourselves__, here are the steps...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

1.  Download and configure NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh rv-virt:nsh64
    make menuconfig
    ```

1.  In __menuconfig__, browse to "__Build Setup__ > __Debug Options__"

    Select the following options...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Informational Debug Output
    Enable Debug Assertions
    Scheduler Debug Features
    Scheduler Error Output
    Scheduler Warnings Output
    Scheduler Informational Output
    ```

    Save and exit __menuconfig__.

1.  Build the NuttX Project and dump the RISC-V Disassembly...

    ```bash
    make V=1 -j7

    riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1
    ```

    [(See the Build Log)](https://gist.github.com/lupyuen/9d9b89dfd91b27f93459828178b83b77)

    [(See the Build Outputs)](https://github.com/lupyuen/lupyuen.github.io/releases/tag/nuttx-riscv64)

1.  This produces the NuttX Image __nuttx__ that we may boot on QEMU RISC-V Emulator...

    TODO: Boot NuttX

# Appendix: Compile Apache NuttX RTOS for 64-bit RISC-V QEMU

TODO

```bash
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv64imac \
  -mabi=lp64 \
  -mcmodel=medany \
  -isystem nuttx/include \
  -D__NuttX__ \
  -DNDEBUG \
  -D__KERNEL__  \
  -pipe \
  -I nuttx/arch/risc-v/src/chip \
  -I nuttx/arch/risc-v/src/common \
  -I nuttx/sched    chip/qemu_rv_start.c \
  -o  qemu_rv_start.o

rv64imac: no floating-point

lp64: Long pointers are 64-bit, no floating-point arguments will be passed in registers.
https://gcc.gnu.org/onlinedocs/gcc-9.1.0/gcc/RISC-V-Options.html

-mcmodel=medany
Generate code for the medium-any code model. The program and its statically defined symbols must be within any single 2 GiB address range. Programs can be statically or dynamically linked.
Sounds like a burger (or fast-food AI model?)
```

# Appendix: Download Toolchain for 64-bit RISC-V

Follow these steps to download the __64-bit RISC-V Toolchain__ for building Apache NuttX RTOS on Linux, macOS or Windows...

1.  Download the [__riscv64-unknown-elf RISC-V Toolchain__](https://github.com/sifive/freedom-tools/releases/tag/v2020.12.0) for Linux, macOS or Windows...

    -   [__Ubuntu Linux__](https://static.dev.sifive.com/dev-tools/freedom-tools/v2020.12/riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-linux-ubuntu14.tar.gz)

    -   [__CentOS Linux__](https://static.dev.sifive.com/dev-tools/freedom-tools/v2020.12/riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-linux-centos6.tar.gz)

    -   [__macOS__](https://static.dev.sifive.com/dev-tools/freedom-tools/v2020.12/riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-apple-darwin.tar.gz)

    -   [__Windows MinGW__](https://static.dev.sifive.com/dev-tools/freedom-tools/v2020.12/riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-w64-mingw32.zip)

1.  Extract the Downloaded Toolchain

1.  Add the extracted toolchain to the __`PATH`__ Environment Variable...

    ```text
    riscv64-unknown-elf-toolchain-.../bin
    ```

1.  Check the RISC-V Toolchain...

    ```bash
    riscv64-unknown-elf-gcc -v
    ```
