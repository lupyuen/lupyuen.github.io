# 64-bit RISC-V with Apache NuttX Real-Time Operating System

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

![Building Apache NuttX RTOS in 4 minutes](https://lupyuen.github.io/images/riscv-build.png)

[_Building Apache NuttX RTOS in 4 minutes_](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

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

1.  NuttX is now running in the QEMU Emluator! (Pic below)

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

![Apache NuttX RTOS on RISC-V QEMU](https://lupyuen.github.io/images/riscv-title.png)

[_Apache NuttX RTOS on RISC-V QEMU_](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

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

  [(Instead of the older SiFive Core Local Interruptor CLINT)](https://five-embeddev.com/baremetal/interrupts/#the-machine-mode-interrupts)

- Enable [__Semihosting Debugging__](https://www.qemu.org/docs/master/about/emulation.html#semihosting) without BIOS

_Which RISC-V Instructions are supported by QEMU?_

QEMU's RISC-V [__Generic Virtual Platform (virt)__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices) supports __RV64GC__, which is equivalent to [__RV64IMAFDCZicsr_Zifencei__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions) (phew)...

| | |
|:-:|:-|
| __RV64I__ | 64-bit Base Integer Instruction Set
| __M__ | Integer Multiplication and Division
| __A__ | Atomic Instructions
| __F__ | Single-Precision Floating-Point
| __D__ | Double-Precision Floating-Point
| __C__ | Compressed Instructions
| __Zicsr__ | Control and Status Register (CSR) Instructions
| __Zifencei__ | Instruction-Fetch Fence

[(Source)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

We'll meet these instructions shortly.

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

![RISC-V Boot Code for Apache NuttX RTOS](https://lupyuen.github.io/images/riscv-code.png)

[_RISC-V Boot Code for Apache NuttX RTOS_](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S)

# RISC-V Boot Code in NuttX

TODO

1.  Get the [__CPU ID__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L41-L47)

1.  Check the [__Number of CPUs__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L54-L68)

1.  Set the [__Stack Pointer__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L68-L98)

1.  Disable [__Interrupts__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L96-L102)

1.  Load the [__Interrupt Vector__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L102-L105)

1.  Jump to [__qemu_rv_start__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L105-L109)

Let's decipher the RISC-V Instructions in our Boot Code...

## Get CPU ID

This is how we fetch the __CPU ID__ in RISC-V Assembly: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L43-L47)

```text
/* Load mhartid (cpuid) */
csrr  a0, mhartid
```

Let's break it down...

- __`csrr`__ is the RISC-V Instruction that reads the [__Control and Status Register__](https://five-embeddev.com/riscv-isa-manual/latest/csr.html)

  (Which contains the CPU ID)

- __`a0`__ is the RISC-V Register that will be loaded with the CPU ID.

  According to the [__RISC-V EABI__](https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc#3-register-usage-and-symbolic-names) (Embedded Application Binary Interface), __a0__ is actually an alias for the Official RISC-V Register __x10__.

  ("a" refers to "Function Call Argument")

- __`mhartid`__ says that we'll read from the [__Hart ID Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid), containing the ID of the Hardware Thread ("Hart") that's running our code.

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

- __`csrw`__ will write to the [__Control and Status Register__](https://five-embeddev.com/riscv-isa-manual/latest/csr.html)

  (Which controls interrupts and other things)

- __`mie`__ says that we'll write to the [__Machine Interrupt Enable Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-interrupt-registers-mip-and-mie)

  (0 to Disable Interrupts, 1 to Enable)

- __`zero`__ says that we'll read from [__Register x0__](https://five-embeddev.com/quickref/regs_abi.html)...

  Which always reads as 0!

Thus the above instruction will set the Machine Interrupt Enable Register to 0, which will disable interrupts.

(Yeah RISC-V has a funny concept of "0")

## Wait for Interrupt

Now check out this curious combination of instructions: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L62-L68)

```text
/* Wait forever */
csrw  mie, zero
wfi
```

From the previous section, we know that "__csrw mie, zero__" will disable interrupts.

But __`wfi`__ will [__Wait for Interrupt__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#wfi)...

Which will never happen because we disabled interrupts!

Thus the above code will get stuck there, __waiting forever__. (Intentionally)

## Load Interrupt Vector

RISC-V handles interrupts by looking up the [__Interrupt Vector Table__](https://five-embeddev.com/quickref/interrupts.html).

This is how we load the __Address of the Vector Table__: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L102-L105)

```text
/* Load address of Interrupt Vector Table */
la    t0, __trap_vec
csrw  mtvec, t0
```

- [__`la`__](https://michaeljclark.github.io/asm.html#:~:text=The%20la%20(load%20address)%20instruction,command%20line%20options%20or%20an%20.) loads the Address of the Vector Table into __Register t0__

  [(Which is aliased to __Register x5__)](https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc#3-register-usage-and-symbolic-names)

  [(__trap_vec__ is defined here)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_vectors.S)

- __`csrw`__ writes __t0__ into the [__Control and Status Register__](https://five-embeddev.com/riscv-isa-manual/latest/csr.html) at...

- __`mtvec`__, the [__Machine Trap-Vector Base-Address Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-vector-base-address-register-mtvec)

Which loads the address of our Interrupt Vector Table.

[(__`la`__ is actually a Pseudo-Instruction that expands to __`auipc`__ and __`addi`__)](https://michaeljclark.github.io/asm.html#:~:text=The%20la%20(load%20address)%20instruction,command%20line%20options%20or%20an%20.)

[(__`auipc`__ loads an Address Offset from the Program Counter)](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions)

[(__`addi`__ adds an Immediate Value to a Register)](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions)

## 32-bit vs 64-bit RISC-V

Adapting 32-bit code for 64-bit sounds hard... But it's easy peasy for RISC-V!

Our Boot Code uses an Assembler Macro to figure out if we're running __32-bit or 64-bit__ RISC-V: [qemu_rv_head.S](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L73-L82)

```text
#ifdef CONFIG_ARCH_RV32
  /* Do this for 32-bit RISC-V */
  slli t1, a0, 2

#else
  /* Do this for 64-bit RISC-V */
  slli t1, a0, 3
#endif
```

Which means that the exact same Boot Code will run on __32-bit AND 64-bit RISC-V__!

(__`slli`__ sounds "silly", but it's [__Logical Shift Left__](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions))

(__CONFIG_ARCH_RV32__ is derived from our [__NuttX Build Configuration__](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig))

## Other Instructions

_What about the other RISC-V Instructions in our Boot Code?_

Let's skim through the rest...

- [__`bnez`__](https://five-embeddev.com/quickref/instructions.html#-c--control-transfer-instructions) jumps to __Label `1f`__ if __Register a0__ is Non-Zero

  ```text
  bnez  a0, 1f
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L47-L50)

- [__`j`__](https://five-embeddev.com/quickref/instructions.html#-c--control-transfer-instructions) jumps to __Label `2f`__

  (We'll explain Labels in a while)

  ```text
  j  2f
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L52-L54)

- [__`li`__](https://itnext.io/risc-v-instruction-set-cheatsheet-70961b4bbe8#:~:text=You%20can%20see%20some%20instructions,of%20different%20RISC%2DV%20instructions.) loads the __Value 1__ into __Register t1__

  [(__`li`__ is a Pseudo-Instruction that expands to __`addi`__)](https://itnext.io/risc-v-instruction-set-cheatsheet-70961b4bbe8#:~:text=You%20can%20see%20some%20instructions,of%20different%20RISC%2DV%20instructions.)

  [(__`addi`__ adds an Immediate Value to a Register)](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions)

  ```text
  li  t1, 1
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L59-L62)

- [__`blt`__](https://five-embeddev.com/quickref/instructions.html#-rv32--conditional-branches) branches to __Label `3f`__ if __Register a0__ is less than __Register t1__

  (And grabs a sandwich)

  ```text
  blt  a0, t1, 3f
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L62-L65)

- [__`add`__](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-computational-instructions) sets __Register t0__ to the value of __Register t0__ + __Register t1__

  [(__t1__ is aliased to __Register x15__)](https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc#3-register-usage-and-symbolic-names)

  ```text
  add  t0, t0, t1
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L80-L82)

- [__`REGLOAD`__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_internal.h#L55-L63) is an Assembly Macro that expands to __`ld`__

  [__`ld`__](https://five-embeddev.com/quickref/instructions.html#-rv64--load-and-store-instructions) loads __Register t0__ to the __Stack Pointer Register__

  [(Which is aliased to __Register x2__)](https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc#3-register-usage-and-symbolic-names)

  ```text
  REGLOAD  sp, 0(t0)
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L82-L86)

- [__`jal`__](https://five-embeddev.com/quickref/instructions.html#-rv32--programmers-model-for-base-integer-isa) (Jump And Link) will jump to the address __qemu_rv_start__ and store the Return Address in __Register x1__

  (Works like a Function Call)

  ```text
  jal  x1, qemu_rv_start
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L105-L109)

- [__`ret`__](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#-a-listing-of-standard-risc-v-pseudoinstructions) returns from a Function Call.

  [(__`ret`__ is a Pseudo-Instruction that expands to __`jalr`__)](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#-a-listing-of-standard-risc-v-pseudoinstructions)

  [(__`jalr`__ "Jump And Link Register" will jump to the Return Address stored in __Register x1__)](https://five-embeddev.com/quickref/instructions.html#-rv32--unconditional-jumps)

  ```text
  ret
  ```

  [(Source)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L117-L120)

  [(See the list of all __RISC-V Instructions__)](https://five-embeddev.com/quickref/instructions.html)

  [(And __RISC-V Pseudo-Instructions__)](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#-a-listing-of-standard-risc-v-pseudoinstructions)

_Why are the RISC-V Labels named "1f", "2f", "3f"?_

[__"`1f`"__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L47-L50) refers to the [__Local Label "`1`"__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L53-L56) with a [__Forward Reference__](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#labels).

(Instead of a [__Backward Reference__](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#labels))

Let's jump to __qemu_rv_start__...

# Jump to Start

_Our Boot Code jumps to qemu_rv_start..._

_What happens next?_

[__qemu_rv_start__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L151) is the very first C Function that NuttX runs when it boots. It will...

1.  Configure the [__Floating-Point Unit__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L105-L108)

1.  Clear the [__BSS Memory__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L113-L117)

1.  Initialise the [__Serial Port__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L119-L123)

1.  Initialise the [__Memory Management Unit__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L129-L135)

1.  Call [__nx_start__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L135-L139)

_What happens in nx_start?_

[__nx_start__](https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L297-L707) will initialise a whole bunch of NuttX things...

- [__"After Primary Routine (nx_start)"__](https://lupyuen.github.io/articles/unicorn2#after-primary-routine)

Which will start the NuttX Shell.

And that's how NuttX RTOS boots on QEMU Emulator for RISC-V!

_Why are we doing all this?_

TODO

# What's Next

TODO

(We welcome __your contribution__ to Apache NuttX RTOS!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/riscv.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/riscv.md)

![Build Apache NuttX RTOS for 64-bit RISC-V QEMU](https://lupyuen.github.io/images/riscv-build.png)

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
