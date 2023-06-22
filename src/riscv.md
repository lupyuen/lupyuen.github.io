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

TODO

1.  Download __`nuttx`__ from the [__NuttX Release__](https://github.com/lupyuen/lupyuen.github.io/releases/tag/nuttx-riscv64)...

    [__nuttx: NuttX Image for 64-bit RISC-V QEMU__](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx)

    (If we prefer to __build NuttX__ ourselves: [__Follow these steps__](TODO))

1.  Copy the downloaded __`Image.gz`__ and overwrite the file on the microSD Card.

    (Pic above)

1.  Insert the microSD Card into PinePhone and power up PinePhone.

    NuttX boots on PinePhone and shows a [__Test Pattern__](https://lupyuen.github.io/images/dsi3-title.jpg).

    (Very briefly)

1.  TODO: Enter __`help`__ to see the available commands.

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

# RISC-V Boot Code in NuttX

TODO

```bash
https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L41-L120

qemu_rv_start
https://github.com/apache/nuttx/blob/master/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L151
Calls nx_start

qemu-system-riscv64
https://www.qemu.org/docs/master/system/target-riscv.html

  -M virt,aclint=on \
‘virt’ Generic Virtual Platform (virt)
https://www.qemu.org/docs/master/system/riscv/virt.html

ACLINT devices will be emulated instead of SiFive CLINT

  /* Load mhartid (cpuid) */
  csrr a0, mhartid

csrr: Read Control and Status Register
https://five-embeddev.com/riscv-isa-manual/latest/csr.html

a0: x10
Embedded ABI (EABI) vs Unix ABI (UABI)
https://github.com/riscv-non-isa/riscv-eabi-spec/blob/master/EABI.adoc

mhartid: Hart ID Register, ID of the hardware thread running the code.
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid

#ifdef CONFIG_ARCH_RV32
  slli t1, a0, 2
#else
  slli t1, a0, 3
#endif

works with 32-bit and 64-bit modes!
sounds like "silly"
but it's Logical Shift Left
https://five-embeddev.com/riscv-isa-manual/latest/rv64.html#integer-computational-instructions

  /* Disable all interrupts (i.e. timer, external) in mie */
	csrw	mie, zero

csrw: Write Control and Status Register
https://five-embeddev.com/riscv-isa-manual/latest/csr.html

mie: Machine Interrupt Enable Register
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-interrupt-registers-mip-and-mie

zero: x0 Register, which is always 0
https://five-embeddev.com/quickref/regs_abi.html

  csrw mie, zero
  wfi

wfi: Wait for Interrupt
which will never happen because we disabled interrupts
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#wfi

  la   t0, __trap_vec
  csrw mtvec, t0

csrw: Write Control and Status Register
https://five-embeddev.com/riscv-isa-manual/latest/csr.html

mtvec: Machine Trap-Vector Base-Address Register
The mtvec register is an MXLEN-bit WARL read/write register that holds trap vector configuration, consisting of a vector base address (BASE) and a vector mode (MODE).
https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-vector-base-address-register-mtvec
```

TODO: Other instructions

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
    ```

1.  Build the NuttX Project...

    ```bash
    make V=1 -j7
    ```

    [(See the Build Log)](https://gist.github.com/lupyuen/9d9b89dfd91b27f93459828178b83b77)

1.  This produces the NuttX Image __nuttx__ that we may boot on QEMU RISC-V Emulator

TODO

```bash
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1

make menuconfig
Build Setup > Debug Options
│ │            [*] Enable Debug Features                                                          │ │
  │ │                  *** Debug SYSLOG Output Controls ***                                         │ │
  │ │            [*]   Enable Error Output                                                          │ │
  │ │            [*]     Enable Warnings Output                                                     │ │
  │ │            [*]       Enable Informational Debug Output

  │ │            [*]   Scheduler Debug Features                                                     │ │
  │ │            [*]     Scheduler Error Output                                                     │ │
  │ │            [*]     Scheduler Warnings Output                                                  │ │
  │ │            [*]     Scheduler Informational Output
```

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
