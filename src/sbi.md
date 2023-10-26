# Star64 JH7110 RISC-V SBC: Experiments with OpenSBI (Supervisor Binary Interface)

📝 _31 Oct 2023_

![OpenSBI on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-title.png)

Bare Metal Programming on a __RISC-V SBC__ (Single-Board Computer) sounds difficult... Thankfully we can get help from __OpenSBI__! (Supervisor Binary Interface)

In this article, we call OpenSBI to...

- Print to the __Serial Console__

- Set a __System Timer__

- Query the __RISC-V CPUs__

- Fetch the __System Information__

- And __Shutdown / Reboot our SBC__

We'll do this on the [__Star64 JH7110 RISC-V SBC__](https://wiki.pine64.org/wiki/STAR64). (Pic below)

(The same steps will work OK on __StarFive VisionFive2__, __Milk-V Mars__ and other SBCs based on the [__StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html))

_We're running Bare Metal Code on our SBC?_

Not quite, but close to the Metal!

We're running our code with [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/release) (RTOS). NuttX lets us inject our Test Code into its tiny Kernel and boot it easily on our SBC.

(Without messing around with the Linux Kernel)

_Why are we doing this?_

Right now we're __porting NuttX RTOS__ to the Star64 SBC.

The experiments that we run today will be super helpful as we __integrate NuttX with OpenSBI__ for System Timers, CPU Scheduling and other System Functions.

![Pine64 Star64 RISC-V SBC](https://lupyuen.github.io/images/release-star64.jpg)

# OpenSBI Supervisor Binary Interface

_What's this OpenSBI?_

When we power up our RISC-V SBC, we'll see OpenSBI in the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64)...

```text
U-Boot SPL 2021.10 (Jan 19 2023 - 04:09:41 +0800)
DDR version: dc2e84f0.
Trying to boot from SPI
OpenSBI v1.2
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|
Platform Name             : StarFive VisionFive V2
Platform Features         : medeleg
Platform HART Count       : 5
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 4000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : jh7110-hsm
Platform PMU Device       : ---
Platform Reboot Device    : pm-reset
Platform Shutdown Device  : pm-reset
Firmware Base             : 0x40000000
Firmware Size             : 288 KB
Runtime SBI Version       : 1.0
```

[(Source)](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64)

[__OpenSBI (Open Source Supervisor Binary Interface)__](https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/) is the first thing that boots on our SBC.

OpenSBI provides Secure Access to the __Low-Level System Functions__ (controlling CPUs, Timers, Interrupts) for the JH7110 SoC, as described in the SPI Spec...

- [__RISC-V Supervisor Binary Interface Spec__](https://github.com/riscv-non-isa/riscv-sbi-doc)

  [(More about __OpenSBI for Star64__)](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64)

_Can't we access the Low-Level System Features without OpenSBI?_

Our code runs in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels), which doesn't allow direct access to Low-Level System Features, like for starting a CPU. (Pic below)

(NuttX Kernel, Linux Kernel and U-Boot Bootloader all run in Supervisor Mode)

OpenSBI runs in [__RISC-V Machine Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels), which has complete access to Low-Level System Features. That's why we call OpenSBI from our code.

![OpenSBI runs in RISC-V Machine Mode](https://lupyuen.github.io/images/privilege-title.jpg)

# Call OpenSBI from NuttX

_How to call OpenSBI from our code?_

Suppose we're calling OpenSBI to print something to the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64) like so: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L155-L237)

```c
// After NuttX Kernel boots on JH7110...
void board_late_initialize(void) {
  ...
  // Call OpenSBI to print something
  test_opensbi();
}

// Call OpenSBI to print something. Based on
// https://github.com/riscv-software-src/opensbi/blob/master/firmware/payloads/test_main.c
// https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/
int test_opensbi(void) {

  // Print `123` with (Legacy) Console Putchar.
  // Call sbi_console_putchar: Extension ID 1, Function ID 0
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-legacy.adoc
  sbi_ecall(
    SBI_EXT_0_1_CONSOLE_PUTCHAR,  // Extension ID: 1
    0,    // Function ID: 0
    '1',  // Character to be printed
    0, 0, 0, 0, 0  // Other Parameters (unused)
  );

  // Do the same, but print `2` and `3`
  sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '2', 0, 0, 0, 0, 0);
  sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '3', 0, 0, 0, 0, 0);
```

This calls the (Legacy) [__Console Putchar Function__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#52-extension-console-putchar-eid-0x01) from the SBI Spec...

- __Extension ID:__ 1 (Console Putchar)

- __Function ID:__ 0

- __Parameter:__ Character to be printed

(There's a newer version of this, we'll soon see)

_What's this ecall to SBI?_

Remember that OpenSBI runs in (super-privileged) __RISC-V Machine Mode__. And our code runs in (less-privileged) __RISC-V Supervisor Mode__.

To jump from Supervisor Mode to Machine Mode, we execute the [__`ecall` RISC-V Instruction__](https://five-embeddev.com/quickref/instructions.html#-rv32--rv32) like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L268-L299)

```c
// Make an `ecall` to OpenSBI. Based on
// https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L52-L77
// https://github.com/riscv-software-src/opensbi/blob/master/firmware/payloads/test_main.c
static struct sbiret sbi_ecall(
  unsigned int extid,  // Extension ID
  unsigned int fid,    // Function ID
  uintptr_t parm0, uintptr_t parm1,  // Parameters 0 and 1
  uintptr_t parm2, uintptr_t parm3,  // Parameters 2 and 3
  uintptr_t parm4, uintptr_t parm5   // Parameters 4 and 5
) {
  // Pass the Extension ID, Function ID and Parameters
  // in RISC-V Registers A0 to A7
  register long r0 asm("a0") = (long)(parm0);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);
  register long r4 asm("a4") = (long)(parm4);
  register long r5 asm("a5") = (long)(parm5);
  register long r6 asm("a6") = (long)(fid);
  register long r7 asm("a7") = (long)(extid);

  // Execute the `ecall` RISC-V Instruction.
  // Output Registers: A0 and A1
  // Input Registers: A2 to A7
  // Clobbers the Memory
  asm volatile (
    "ecall"
    : "+r"(r0), "+r"(r1)
    : "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r6), "r"(r7)
    : "memory"
  );

  // Return the OpenSBI Error and Value
  struct sbiret ret;
  ret.error = r0;
  ret.value = r1;
  return ret;
}
```

[(See the __RISC-V Disassembly__)](https://gist.github.com/lupyuen/4cd98a4075d5b528940095b39fd5b445)

Now we run this on our SBC...

[(How __`ecall`__ works in OpenSBI)](https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/)

[(More about OpenSBI)](https://courses.stephenmarz.com/my-courses/cosc562/risc-v/opensbi-calls/)

TODO: Pic of NuttX  

# Run NuttX with OpenSBI

_Will our Test Code print correctly to the Serial Console?_

Let's find out!

1.  Follow these steps to download __Apache NuttX RTOS__ and compile the NuttX Kernel and Apps...

    [__"Build NuttX for Star64"__](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

1.  Locate this __NuttX Source File__...

    ```text
    nuttx/boards/risc-v/jh7110/star64/src/jh7110_appinit.c
    ```

    Replace the contents of that file by this __Test Code__...

    [__jh7110_appinit.c: OpenSBI Test Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c)

1.  Rebuild the __NuttX Kernel__...

    ```text
    $ make
    $ riscv64-unknown-elf-objcopy -O binary nuttx nuttx.bin
    ```

1.  Copy the NuttX Kernel and NuttX Apps to a __microSD Card__...

    [__"NuttX in a Bootable microSD"__](https://lupyuen.github.io/articles/release#nuttx-in-a-bootable-microsd)

1.  Insert the microSD Card into our SBC and power up...

    [__"Boot NuttX on Star64"__](https://lupyuen.github.io/articles/release#boot-nuttx-on-star64)

    [(Or boot our SBC over the __Network with TFTP__)](https://lupyuen.github.io/articles/tftp)

When we boot the Modified NuttX Kernel on our SBC, we see "__`123`__" printed on the Serial Console...

```text
Starting kernel ...
123
NuttShell (NSH) NuttX-12.0.3
nsh> 
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L300-L310)

Yep our OpenSBI Experiment works yay!

# OpenSBI Debug Console

_But that's calling the Legacy Console Putchar Function. What about the newer Debug Console Functions?_

Yeah we called the Legacy Console Putchar Function, which is [__expected to be deprecated__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#5-legacy-extensions-eids-0x00---0x0f).

Let's call the newer [__Debug Console Functions__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc) in OpenSBI. This function [__prints a string__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-fid-0) to the Debug Console...

- __Extension ID:__ `0x4442` `434E` "DBCN"

- __Function ID:__ 0 (Console Write)

- __Parameter 0:__ String Length

- __Parameter 1:__ Low Address of String

- __Parameter 2:__ High Address of String

And this function [__prints a single character__](nction-console-write-byte-fid-2)...

- __Extension ID:__ `0x4442` `434E` "DBCN"

- __Function ID:__ 2 (Console Write Byte)

- __Parameter 0:__ Character to be printed

This is how we print to the __Debug Console__: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L237-L265)

```c
// Print `456` to Debug Console as a String.
// Call sbi_debug_console_write: EID 0x4442434E "DBCN", FID 0
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-fid-0
const char *str = "456";
struct sbiret sret = sbi_ecall(
  SBI_EXT_DBCN,  // Extension ID: 0x4442434E "DBCN"
  SBI_EXT_DBCN_CONSOLE_WRITE,  // Function ID: 0
  strlen(str),         // Number of bytes
  (unsigned long)str,  // Address Low
  0,                   // Address High
  0, 0, 0              // Unused
);
_info("debug_console_write: value=%d, error=%d\n", sret.value, sret.error);
// Not supported by SBI v1.0, this will return SBI_ERR_NOT_SUPPORTED

// Print `789` to Debug Console, byte by byte.
// Call sbi_debug_console_write_byte: EID 0x4442434E "DBCN", FID 2
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-byte-fid-2
sret = sbi_ecall(
  SBI_EXT_DBCN,  // Extension ID: 0x4442434E "DBCN"
  SBI_EXT_DBCN_CONSOLE_WRITE_BYTE,  // Function ID: 2
  '7',           // Character to be printed
  0, 0, 0, 0, 0  // Other Parameters (unused)
);

// Do the same, but print `8` and `9`
sret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, '8', 0, 0, 0, 0, 0);
sret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, '9', 0, 0, 0, 0, 0);
_info("debug_console_write_byte: value=%d, error=%d\n", sret.value, sret.error);
// Not supported by SBI v1.0, this will return SBI_ERR_NOT_SUPPORTED
```

But our Test Code fails with error [__NOT_SUPPORTED__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L266-L277)...

```text
debug_console_write:
  value=0, error=-2
debug_console_write_byte:
  value=0, error=-2
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L300-L310)

Why? Let's find out...

# Read the SBI Version

TODO

Get SBI specification version (FID #0)

[sbi_get_spec_version](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#41-function-get-sbi-specification-version-fid-0)

_Why is the Debug Console not supported on JH7110 OpenSBI?_

If we trace the StarFive JH7110 Source Code...

1.  Browse to [github.com/starfive-tech/VisionFive2](https://github.com/starfive-tech/VisionFive2)

1.  Click the [opensbi Folder](https://github.com/starfive-tech/opensbi/tree/c6a092cd80112529cb2e92e180767ff5341b22a3)

It says...

> OpenSBI fully supports SBI specification v0.2

Current version of SBI Spec is 2.0 (draft). OpenSBI implements a 4-year-old spec?

But then we see this: [sbi_ecall.h](https://github.com/starfive-tech/opensbi/blob/c6a092cd80112529cb2e92e180767ff5341b22a3/include/sbi/sbi_ecall.h#L16-L17)

```c
#define SBI_ECALL_VERSION_MAJOR		1
#define SBI_ECALL_VERSION_MINOR		0
```

Which is returned by [GET_SPEC_VERSION](https://github.com/starfive-tech/opensbi/blob/c6a092cd80112529cb2e92e180767ff5341b22a3/lib/sbi/sbi_ecall_base.c#L43-L48). So JH7110 OpenSBI probably implements SBI v1.0.

SBI v1.0 also appears in the JH7110 OpenSBI Log...

```text
Runtime SBI Version: 1.0
```

[(Source)](https://gist.github.com/lupyuen/1e009a3343da70257d6f24400339053f#file-nuttx-scheme-star64-log-L30)

![SBI v1.0 appears in the JH7110 OpenSBI Log](https://lupyuen.github.io/images/sbi-title.png)

_What exactly is in SBI v0.2 and v1.0?_

Here are the SBI Specs...

- [SBI Spec v0.2](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v0.2.0/riscv-sbi.adoc) (Jan 2020)

- [SBI Spec v1.0](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc) (Mar 2022)

Definitely no Debug Console in there!

_When was Debug Console added to the SBI Spec?_

Debug Console appears in [SBI Spec v2.0 RC1](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v2.0-rc1/riscv-sbi.adoc) (Jun 2023), but there isn't an official SBI Spec v2.0 yet.

And the Debug Console code is already inside JH7110 OpenSBI: [sbi_ecall_dbcn.c](https://github.com/starfive-tech/opensbi/blob/c6a092cd80112529cb2e92e180767ff5341b22a3/lib/sbi/sbi_ecall_dbcn.c)

_So why can't we call the Debug Console?_

Our JH7110 Firmware seems to be built in [Jan 2023](https://gist.github.com/lupyuen/1e009a3343da70257d6f24400339053f#file-nuttx-scheme-star64-log-L4). But Debug Console was only implemented in [Feb 2023](https://github.com/starfive-tech/opensbi/commits/c6a092cd80112529cb2e92e180767ff5341b22a3/lib/sbi/sbi_ecall_dbcn.c)! Maybe that's why we can't call the Debug Console on JH7110 OpenSBI.

FYI: Upstream OpenSBI now supports [SBI 2.0](https://github.com/riscv-software-src/opensbi/commit/cbdd86973901b6be2a1a2d3d6b54f3184fdf9a44)

TODO: Call sbi_get_spec_version, sbi_get_impl_id, sbi_get_impl_version, sbi_probe_extension, sbi_get_mvendorid, sbi_get_marchid, sbi_get_mimpid

# Set a System Timer

TODO

Set Timer (FID #0)

[sbi_set_timer](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#61-function-set-timer-fid-0)

[jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L384-L388)

```c
  // Set Timer
  // Call sbi_set_timer: EID 0x54494D45 "TIME", FID 0
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#61-function-set-timer-fid-0
  sret = sbi_ecall(SBI_EXT_TIME, SBI_EXT_TIME_SET_TIMER, 0, 0, 0, 0, 0, 0);
  _info("set_timer: value=0x%x, error=%d\n", sret.value, sret.error);
```

# Query the RISC-V CPUs

TODO

HART get status (FID #2)

[sbi_hart_get_status](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#93-function-hart-get-status-fid-2)

HSM = Hart State Management (Not Hardware Security Module)

[jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L376-L382)

```c
  // HART Get Status
  // Call sbi_hart_get_status: EID 0x48534D "HSM", FID 2
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#93-function-hart-get-status-fid-2
  for (uintptr_t hart = 0; hart < 6; hart++) {
    sret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_GET_STATUS, hart, 0, 0, 0, 0, 0);
    _info("hart_get_status[%d]: value=0x%x, error=%d\n", hart, sret.value, sret.error);
  }
```

# Fetch the System Info

TODO

[jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L336-L374)

```c
  // Get SBI Implementation ID
  // Call sbi_get_impl_id: EID 0x10, FID 1
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#42-function-get-sbi-implementation-id-fid-1
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID, 0, 0, 0, 0, 0, 0);
  _info("get_impl_id: value=0x%x, error=%d\n", sret.value, sret.error);

  // Get SBI Implementation Version
  // Call sbi_get_impl_version: EID 0x10, FID 2
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#43-function-get-sbi-implementation-version-fid-2
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION, 0, 0, 0, 0, 0, 0);
  _info("get_impl_version: value=0x%x, error=%d\n", sret.value, sret.error);

  // Get Machine Vendor ID
  // Call sbi_get_mvendorid: EID 0x10, FID 4
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#45-function-get-machine-vendor-id-fid-4
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MVENDORID, 0, 0, 0, 0, 0, 0);
  _info("get_mvendorid: value=0x%x, error=%d\n", sret.value, sret.error);

  // Get Machine Architecture ID
  // Call sbi_get_marchid: EID 0x10, FID 5
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#46-function-get-machine-architecture-id-fid-5
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MARCHID, 0, 0, 0, 0, 0, 0);
  _info("get_marchid: value=0x%x, error=%d\n", sret.value, sret.error);

  // Get Machine Implementation ID
  // Call sbi_get_mimpid: EID 0x10, FID 6
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#47-function-get-machine-implementation-id-fid-6
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MIMPID, 0, 0, 0, 0, 0, 0);
  _info("get_mimpid: value=0x%x, error=%d\n", sret.value, sret.error);

  // Probe SBI Extension: Base Extension
  // Call sbi_probe_extension: EID 0x10, FID 3
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#44-function-probe-sbi-extension-fid-3
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE, 0, 0, 0, 0, 0);
  _info("probe_extension[0x10]: value=0x%x, error=%d\n", sret.value, sret.error);

  // Probe SBI Extension: Debug Console Extension
  sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_DBCN, 0, 0, 0, 0, 0);
  _info("probe_extension[0x4442434E]: value=0x%x, error=%d\n", sret.value, sret.error);
```

# Shutdown and Reboot the SBC

TODO

[jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L390-L402)

```c
  // System Reset: Shutdown
  // Call sbi_system_reset: EID 0x53525354 "SRST", FID 0
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#101-function-system-reset-fid-0
  // sret = sbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET, SBI_SRST_RESET_TYPE_SHUTDOWN, SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);
  // _info("system_reset[shutdown]: value=0x%x, error=%d\n", sret.value, sret.error);

  // System Reset: Cold Reboot
  // sret = sbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET, SBI_SRST_RESET_TYPE_COLD_REBOOT, SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);
  // _info("system_reset[cold_reboot]: value=0x%x, error=%d\n", sret.value, sret.error);

  // System Reset: Warm Reboot
  sret = sbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET, SBI_SRST_RESET_TYPE_WARM_REBOOT, SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);
  _info("system_reset[warm_reboot]: value=0x%x, error=%d\n", sret.value, sret.error);
```

[Shutdown Log](https://gist.github.com/lupyuen/5748e125df2f6b6fd4902f80ab3e9ed1)

# Integrate OpenSBI with NuttX

TODO

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/sbi.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/sbi.md)
