# Star64 JH7110 RISC-V SBC: Experiments with OpenSBI (Supervisor Binary Interface)

📝 _28 Oct 2023_

![OpenSBI on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-title.png)

Bare Metal Programming on a __RISC-V SBC__ (Single-Board Computer) sounds difficult... Thankfully we can get help from __OpenSBI__! (Supervisor Binary Interface)

In this article, we call OpenSBI to...

- Print to the __Serial Console__

- Set a __System Timer__

- Query the __RISC-V CPUs__

- Fetch the __System Information__

We'll do this on the [__Star64 JH7110 RISC-V SBC__](https://wiki.pine64.org/wiki/STAR64). (Pic below)

(The same steps will work OK on __StarFive VisionFive2__, __Milk-V Mars__ and other SBCs based on the [__StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html))

_We're running Bare Metal Code on our SBC?_

Not quite, but close to the Metal!

We're running our code with [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/release) (RTOS). NuttX lets us inject our code into its tiny Kernel and boot it easily on our SBC.

(Without messing around with the Linux Kernel)

_Why are we doing this?_

Right now we're __porting NuttX RTOS__ to the Star64 SBC. The experiments that we run today will be super helpful as we __integrate NuttX with OpenSBI__ for System Timers, CPU Scheduling and other System Functions.

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

Suppose we're calling OpenSBI to print something to the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64).

TODO

We run this __`ecall`__ to jump from NuttX (in RISC-V Supervisor Mode) to OpenSBI (in RISC-V Machine Mode)...

- [__riscv_sbi.c: Calling OpenSBI in NuttX__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L52-L77)

  [(How __`ecall`__ works in OpenSBI)](https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/)

  [(More about OpenSBI)](https://courses.stephenmarz.com/my-courses/cosc562/risc-v/opensbi-calls/)

Like this...

From [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L155-L237)

```c
// After NuttX boots on JH7110...
void board_late_initialize(void) {
  ...
  // Make an ecall to OpenSBI
  int ret = test_opensbi();
  DEBUGASSERT(ret == OK);
}

// Make an ecall to OpenSBI. Based on
// https://github.com/riscv-software-src/opensbi/blob/master/firmware/payloads/test_main.c
// https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/
int test_opensbi(void) {
  // Print `123` to Debug Console with Legacy Console Putchar.
  // Call sbi_console_putchar: EID 0x01, FID 0
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-legacy.adoc
  sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '1', 0, 0, 0, 0, 0);
  sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '2', 0, 0, 0, 0, 0);
  sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, '3', 0, 0, 0, 0, 0);
```

__`sbi_ecall`__ makes an __`ecall`__ to jump from NuttX (in RISC-V Supervisor Mode) to OpenSBI (in RISC-V Machine Mode)...

From [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L268-L299)

```c
// Make an ecall to OpenSBI. Based on
// https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L52-L77
// https://github.com/riscv-software-src/opensbi/blob/master/firmware/payloads/test_main.c
static struct sbiret sbi_ecall(unsigned int extid, unsigned int fid,
                                  uintptr_t parm0, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3,
                                  uintptr_t parm4, uintptr_t parm5)
{
  struct sbiret ret;
  register long r0 asm("a0") = (long)(parm0);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);
  register long r4 asm("a4") = (long)(parm4);
  register long r5 asm("a5") = (long)(parm5);
  register long r6 asm("a6") = (long)(fid);
  register long r7 asm("a7") = (long)(extid);

  asm volatile
    (
     "ecall"
     : "+r"(r0), "+r"(r1)
     : "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r6), "r"(r7)
     : "memory"
     );

  ret.error = r0;
  ret.value = r1;
  return ret;
}
```

When we run our Modified NuttX Kernel on Star64 JH7110, we see `123` printed on the Debug Console. Yay!

```text
Starting kernel ...
123
NuttShell (NSH) NuttX-12.0.3
nsh> 
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L300-L310)

# Run NuttX with OpenSBI

TODO

# OpenSBI Debug Console

TODO

_But that's calling the Legacy Console Putchar Function. What about the newer Debug Console Functions?_

Let's call the newer [Debug Console Functions](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc) in OpenSBI...

From [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L237-L265)

```c
  // TODO: Not supported by SBI v1.0, this will return SBI_ERR_NOT_SUPPORTED
  // Print `456` to Debug Console.
  // Call sbi_debug_console_write: EID 0x4442434E, FID 0
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-fid-0
  const char *str = "456";
	struct sbiret sret = sbi_ecall(
    SBI_EXT_DBCN,  // Extension ID
    SBI_EXT_DBCN_CONSOLE_WRITE,  // Function ID
		strlen(str),         // Number of bytes
    (unsigned long)str,  // Address Low
    0,                   // Address High
    0, 0, 0              // Unused
  );
  _info("sret.value=%d, sret.error=%d\n", sret.value, sret.error);
  // DEBUGASSERT(sret.error == SBI_SUCCESS);
  // DEBUGASSERT(sret.value == strlen(str));

  // TODO: Not supported by SBI v1.0, this will return SBI_ERR_NOT_SUPPORTED
  // Print `789` to Debug Console.
  // Call sbi_debug_console_write_byte: EID 0x4442434E, FID 2
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-byte-fid-2
  sret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, '7', 0, 0, 0, 0, 0);
  sret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, '8', 0, 0, 0, 0, 0);
  sret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, '9', 0, 0, 0, 0, 0);
  _info("sret.value=%d, sret.error=%d\n", sret.value, sret.error);
  // DEBUGASSERT(sret.error == SBI_SUCCESS);
  // DEBUGASSERT(sret.value == strlen(str));
```

But it fails with `SBI_ERR_NOT_SUPPORTED`...

```text
Starting kernel ...
test_opensbi: sret.value=0, sret.error=-2
test_opensbi: sret.value=0, sret.error=-2
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L300-L310)

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

# Query the RISC-V CPUs

TODO

# Fetch the System Info

TODO

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
