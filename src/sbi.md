# Star64 JH7110 RISC-V SBC: Experiments with OpenSBI (Supervisor Binary Interface)

📝 _31 Oct 2023_

![OpenSBI on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-title.png)

Bare Metal Programming on a __RISC-V SBC__ (Single-Board Computer) sounds difficult... Thankfully we can get help from the [__OpenSBI Supervisor Binary Interface__](https://github.com/riscv-software-src/opensbi)!

(A little like [__BIOS__](https://en.wikipedia.org/wiki/BIOS), but for RISC-V)

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

[__OpenSBI (Open Source Supervisor Binary Interface)__](https://github.com/riscv-software-src/opensbi) is the first thing that boots on our JH7110 RISC-V SBC...

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

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d)

OpenSBI provides Secure Access to the __Low-Level System Functions__ (controlling CPUs, Timers, Interrupts) for the JH7110 SoC, as described in the SBI Spec...

- [__RISC-V Supervisor Binary Interface Spec__](https://github.com/riscv-non-isa/riscv-sbi-doc)

  [(More about __OpenSBI for Star64__)](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64)

_Can we access the Low-Level System Features without OpenSBI?_

Our code runs in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels), which doesn't allow direct access to Low-Level System Features, like for starting a CPU. (Pic below)

(NuttX Kernel, Linux Kernel and U-Boot Bootloader all run in Supervisor Mode)

OpenSBI runs in [__RISC-V Machine Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels), which has complete access to Low-Level System Features. That's why we call OpenSBI from our code.

![OpenSBI runs in RISC-V Machine Mode](https://lupyuen.github.io/images/privilege-title.jpg)

# Call OpenSBI from NuttX

_How to call OpenSBI from our code?_

Suppose we're calling OpenSBI to print something to the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64) like so: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L154-L301)

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

To jump from Supervisor Mode to Machine Mode, we execute the [__`ecall` RISC-V Instruction__](https://five-embeddev.com/quickref/instructions.html#-rv32--rv32) like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L406-L437)

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

  // Execute the `ecall` RISC-V Instruction
  // Input+Output Registers: A0 and A1
  // Input-Only Registers: A2 to A7
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

[(__sbiret__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L277-L284)

[(See the __RISC-V Disassembly__)](https://gist.github.com/lupyuen/4cd98a4075d5b528940095b39fd5b445)

Now we run this on our SBC...

![NuttX calls OpenSBI on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-run2.png)

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

When we boot the Modified NuttX Kernel on our SBC, we see "__`123`__" printed on the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64) (pic above)...

```text
Starting kernel ...
123
NuttShell (NSH) NuttX-12.0.3
nsh> 
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L151-L157)

Our OpenSBI Experiment works OK yay!

![NuttX calls OpenSBI Debug Console on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-run3.png)

# OpenSBI Debug Console

_But that's calling the Legacy Console Putchar Function..._

_What about the newer Debug Console Functions?_

Yeah we called the Legacy Console Putchar Function, which is [__expected to be deprecated__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#5-legacy-extensions-eids-0x00---0x0f).

Let's call the newer [__Debug Console Functions__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc) in OpenSBI. This function [__prints a string__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-fid-0) to the Debug Console...

- __Extension ID:__ `0x4442` `434E` "DBCN"

- __Function ID:__ 0 (Console Write)

- __Parameter 0:__ String Length

- __Parameter 1:__ Low Address of String

- __Parameter 2:__ High Address of String

And this function [__prints a single character__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-byte-fid-2)...

- __Extension ID:__ `0x4442` `434E` "DBCN"

- __Function ID:__ 2 (Console Write Byte)

- __Parameter 0:__ Character to be printed

This is how we print to the __Debug Console__: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L301-L329)

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
  0, 0, 0              // Other Parameters (unused)
);
_info("debug_console_write: value=%d, error=%d\n", sret.value, sret.error);

// Print `789` to Debug Console, byte by byte.
// Call sbi_debug_console_write_byte: EID 0x4442434E "DBCN", FID 2
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc#function-console-write-byte-fid-2
sret = sbi_ecall(
  SBI_EXT_DBCN,  // Extension ID: 0x4442434E "DBCN"
  SBI_EXT_DBCN_CONSOLE_WRITE_BYTE,  // Function ID: 2
  '7',           // Character to be printed
  0, 0, 0, 0, 0  // Other Parameters (unused)
);
_info("debug_console_write_byte: value=%d, error=%d\n", sret.value, sret.error);
// Omitted: Do the same, but print `8` and `9`
```

But our Test Code fails with error [__NOT_SUPPORTED__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L266-L277) (pic above)...

```text
debug_console_write:
  value=0, error=-2

debug_console_write_byte:
  value=0, error=-2
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L156-L157)

Why? Let's find out...

# Read the SBI Version

_We tried printing to Debug Console but failed..._

_Maybe OpenSBI in our SBC doesn't support Debug Console?_

Debug Console was introduced in [__SBI Spec Version 2.0__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc).

To get the [__SBI Spec Version__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#41-function-get-sbi-specification-version-fid-0) supported by our SBC, we call this SBI Function...

- __Extension ID:__ `0x10` (Base Extension)

- __Function ID:__ 0 (SBI Spec Version)

Like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L329-L335)

```c
// Get SBI Spec Version
// Call sbi_get_spec_version: EID 0x10, FID 0
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#41-function-get-sbi-specification-version-fid-0
sret = sbi_ecall(
  SBI_EXT_BASE,     // Extension ID: 0x10 
  SBI_EXT_BASE_GET_SPEC_VERSION,  // Function ID: 0
  0, 0, 0, 0, 0, 0  // Parameters (unused)
);
_info("get_spec_version: value=0x%x, error=%d\n", sret.value, sret.error);
```

Which tells us...

```text
get_spec_version:
  value=0x1000000
  error=0
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L158)

__`0x100` `0000`__ says that the SBI Spec Version is...

- __Major Version:__ 1 (Bits 24 to 30)

- __Minor Version:__ 0 (Bits 0 to 23)

Thus our SBC supports [__SBI Spec Version 1.0__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc).

Aha! Our SBC doesn't support Debug Console, because this feature was introduced in [__Version 2.0__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-debug-console.adoc)!

Mystery solved! Actually if we're super observant, SBI Version 1.0 also appears when our __SBC boots OpenSBI__ (pic below)...

```text
Runtime SBI Version: 1.0
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L27)

_Is our SBC stuck forever with SBI Version 1.0?_

Actually we can upgrade OpenSBI by reflashing the [__Onboard SPI Flash__](https://github.com/starfive-tech/VisionFive2#appendix-iii-updating-spl-and-u-boot-binaries-under-u-boot).

But let's stick with SBI Version 1.0 for now.

[(Mainline OpenSBI now supports __SBI 2.0 and Debug Console__)](https://github.com/riscv-software-src/opensbi/commit/cbdd86973901b6be2a1a2d3d6b54f3184fdf9a44)


![SBI v1.0 appears in the JH7110 OpenSBI Log](https://lupyuen.github.io/images/sbi-title.png)

# Probe the SBI Extensions

_Bummer our SBC doesn't support Debug Console..._

_How to check if our SBC supports ANY specific feature?_

SBI lets us [__Probe its Extensions__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#44-function-probe-sbi-extension-fid-3) to discover the Supported SBI Extensions (like Debug Console)...

- __Extension ID:__ `0x10` (Base Extension)

- __Function ID:__ 3 (Probe SBI Extension)

- __Parameter 0:__ Extension ID to be probed

Like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L365-L375)

```c
// Probe SBI Extension: Base Extension
// Call sbi_probe_extension: EID 0x10, FID 3
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#44-function-probe-sbi-extension-fid-3
struct sbiret sret = sbi_ecall(
  SBI_EXT_BASE,   // Extension ID: 0x10 
  SBI_EXT_BASE_PROBE_EXT,  // Function ID: 3
  SBI_EXT_BASE,  // Probe for "Base Extension": 0x10
  0, 0, 0, 0, 0  // Other Parameters (unused)
);
_info("probe_extension[0x10]: value=0x%x, error=%d\n", sret.value, sret.error);

// Probe SBI Extension: Debug Console Extension.
// Same as above, but we change the parameter to
// "Debug Console" 0x4442434E.
sret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_DBCN, 0, 0, 0, 0, 0);
_info("probe_extension[0x4442434E]: value=0x%x, error=%d\n", sret.value, sret.error);
```

Which will show...

```text
probe_extension[0x10]:
  value=0x1, error=0

probe_extension[0x4442434E]:
  value=0x0, error=0
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L164-L165)

Hence we learn that...

- __Base Extension__ (`0x10`) is supported

- __Debug Console Extension__ (`0x4442` `434E`) is NOT supported

Thus we always __Probe the Extensions__ before calling them!

![NuttX calls OpenSBI Hart State Management on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-run4.png)

# Query the RISC-V CPUs

_OK so OpenSBI can do trivial things..._

_What about controlling the CPUs?_

Now we experiment with the __RISC-V CPU Cores__ ("Hart" / Hardware Thread) in our SBC.

We call [__Hart State Management (HSM)__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#9-hart-state-management-extension-eid-0x48534d-hsm) to query the [__Hart Status__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#93-function-hart-get-status-fid-2)...

- __Extension ID:__ `0x48` `534D` "HSM"

- __Function ID:__ 2 (Get Hart Status)

- __Parameter 0:__ Hart ID (CPU Core ID)

[(Not to be confused with Hardware Security Module)](https://en.wikipedia.org/wiki/Hardware_security_module)

Here's how: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L375-L383)

```c
// For each Hart ID from 0 to 5...
for (uintptr_t hart = 0; hart < 6; hart++) {

  // HART Get Status
  // Call sbi_hart_get_status: EID 0x48534D "HSM", FID 2
  // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#93-function-hart-get-status-fid-2
  struct sbiret sret = sbi_ecall(
    SBI_EXT_HSM,    // Extension ID: 0x48534D "HSM"
    SBI_EXT_HSM_HART_GET_STATUS,   // Function ID: 2
    hart,          // Parameter 0: Hart ID
    0, 0, 0, 0, 0  // Other Parameters (unused)
  );
  _info("hart_get_status[%d]: value=0x%x, error=%d\n", hart, sret.value, sret.error);
}
```

Our SBC says (pic above)...

```text
hart_get_status[0]: value=0x1, error=0
hart_get_status[1]: value=0x0, error=0
hart_get_status[2]: value=0x1, error=0
hart_get_status[3]: value=0x1, error=0
hart_get_status[4]: value=0x1, error=0
hart_get_status[5]: value=0x0, error=-3
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L166-L171)

When we [__decode the values__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#table_hsm_states), we learn that...

- __Hart 1__ is Running

- __Other Harts__ are Stopped

- __Hart 5__ doesn't exist, because our SBC has only 5 CPU Cores (0 to 4)

_Huh? Why is Hart 0 stopped while Hart 1 is running?_

According to the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 96), there are 5 RISC-V Cores in JH7110 (pic below)...

- __Hart 0:__ S7 Monitor Core (RV64IMACB)

- __Harts 1 to 4:__ U74 Application Cores (RV64GCB)

OpenSBI and NuttX will boot on the __First Application Core__. That's why Hart 1 is running. (And not Hart 0)

_How do we start a Hart?_

(With a Defibrillator heh heh)

Check out these SBI Functions...

- [__Start Hart__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#91-function-hart-start-fid-0)

- [__Stop Hart__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#92-function-hart-stop-fid-1)

- [__Suspend Hart__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#94-function-hart-suspend-fid-3)

In future we'll call these SBI Functions to start NuttX on Multiple CPUs.

[(More about __Hart States__)](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#9-hart-state-management-extension-eid-0x48534d-hsm)

![5 RISC-V Cores in JH7110 SoC](https://lupyuen.github.io/images/plic-title.jpg)

# Shutdown and Reboot the SBC

_OpenSBI looks mighty powerful. Can it control our ENTIRE SBC?_

Yep! OpenSBI supports [__System Reset__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#101-function-system-reset-fid-0) for...

- __Shutdown__: "physical power down of the entire system"

- __Cold Reboot__: "physical power cycle of the entire system"

- __Warm Reboot__: "power cycle of main processor and parts of the system but not the entire system"

Which we call like so: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L389-L403)

```c
// System Reset: Shutdown
// Call sbi_system_reset: EID 0x53525354 "SRST", FID 0
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#101-function-system-reset-fid-0
struct sbiret sret = sbi_ecall(
  SBI_EXT_SRST, SBI_EXT_SRST_RESET,  // System Reset
  SBI_SRST_RESET_TYPE_SHUTDOWN,      // Shutdown
  SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);

// System Reset: Cold Reboot
sret = sbi_ecall(
  SBI_EXT_SRST, SBI_EXT_SRST_RESET,  // System Reset
  SBI_SRST_RESET_TYPE_COLD_REBOOT,   // Cold Reboot
  SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);

// System Reset: Warm Reboot
sret = sbi_ecall(
  SBI_EXT_SRST, SBI_EXT_SRST_RESET,  // System Reset
  SBI_SRST_RESET_TYPE_WARM_REBOOT,   // Warm Reboot
  SBI_SRST_RESET_REASON_NONE, 0, 0, 0, 0);
```

_What happens when we run this?_

- __Shutdown__: Our SBC prints this and halts (without catching fire, pic below)...

  ```text
  i2c read: write daddr 36 to
  cannot read pmic power register
  ```

  [(Source)](https://gist.github.com/lupyuen/5748e125df2f6b6fd4902f80ab3e9ed1#file-star64-opensbi-shutdown-log-L173-L183)

- __Cold Reboot__: Same behaviour as Shutdown. (Pic below)

  (Not yet implemented on JH7110?)

- __Warm Reboot__: Not supported on our SBC...

  ```text
  system_reset[warm_reboot]:
    value=0x0
    error=-2
  ```

  [(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L173)

![OpenSBI Shutdown on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-shutdown.png)

# Set a System Timer

_NuttX / Linux Kernel runs in RISC-V Supervisor Mode (not Machine Mode)..._

_How will it control the System Timer?_

That's why OpenSBI provides the [__Set Timer__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#61-function-set-timer-fid-0) function: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L383-L389)

```c
// Set Timer
// Call sbi_set_timer: EID 0x54494D45 "TIME", FID 0
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#61-function-set-timer-fid-0
sret = sbi_ecall(
  SBI_EXT_TIME,  // Extension ID: 0x54494D45 "TIME"
  SBI_EXT_TIME_SET_TIMER,  // Function ID: 0
  0,  // TODO: Absolute Time for Timer Expiry
  0, 0, 0, 0, 0);
```

It doesn't seem to do anything...

```text
set_timer:
  value=0x0
  error=0
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L172)

But that's because our SBC will [__trigger an interrupt__](https://courses.stephenmarz.com/my-courses/cosc562/risc-v/opensbi-calls/) when the System Timer expires.

Someday NuttX will call this function to [__set the System Timer__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L82-L108).

![NuttX fetches OpenSBI System Info on Star64 JH7110 RISC-V SBC](https://lupyuen.github.io/images/sbi-run5.png)

# Fetch the System Info

_Earlier we called OpenSBI to fetch the SBI Spec Version..._

_What else can we fetch from OpenSBI?_

We can snoop a whole bunch of [__System Info__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#4-base-extension-eid-0x10) like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/sbi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L335-L365)

```c
// Get SBI Implementation ID: EID 0x10, FID 1
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#42-function-get-sbi-implementation-id-fid-1
struct sbiret sret = sbi_ecall(
  SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID, 0, 0, 0, 0, 0, 0);

// Get SBI Implementation Version: EID 0x10, FID 2
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#43-function-get-sbi-implementation-version-fid-2
struct sbiret sret = sbi_ecall(
  SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION, 0, 0, 0, 0, 0, 0);

// Get Machine Vendor ID: EID 0x10, FID 4
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#45-function-get-machine-vendor-id-fid-4
sret = sbi_ecall(
  SBI_EXT_BASE, SBI_EXT_BASE_GET_MVENDORID, 0, 0, 0, 0, 0, 0);

// Get Machine Architecture ID: EID 0x10, FID 5
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#46-function-get-machine-architecture-id-fid-5
sret = sbi_ecall(
  SBI_EXT_BASE, SBI_EXT_BASE_GET_MARCHID, 0, 0, 0, 0, 0, 0);

// Get Machine Implementation ID: EID 0x10, FID 6
// https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#47-function-get-machine-implementation-id-fid-6
sret = sbi_ecall(
  SBI_EXT_BASE, SBI_EXT_BASE_GET_MIMPID, 0, 0, 0, 0, 0, 0);

// Omitted: Print `sret.value` and `sret.error`
```

Our SBC will print (pic above)...

```c
// OpenSBI Implementation ID is 1
get_impl_id: 0x1

// OpenSBI Version is 1.2
get_impl_version: 0x10002

// RISC-V Vendor is SiFive
get_mvendorid: 0x489

// RISC-V Machine Architecture is SiFive U7 Series
get_marchid: 0x7

// RISC-V Machine Implementation is 0x4210427 (?)
get_mimpid: 0x4210427
```

[(Source)](https://gist.github.com/lupyuen/f5e609e32f68b59a2c33ba7f4022999d#file-star64-opensbi-log-L159-L163)

The last 3 values are documented in the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf). (Pages 136 to 137)

# Integrate OpenSBI with NuttX

_Phew that's plenty of OpenSBI Functions..._

_How will NuttX use them?_

As we port __Apache NuttX RTOS__ to Star64 JH7110 SBC, we shall call...

- [__SBI Hart State Management__](https://lupyuen.github.io/articles/sbi#query-the-risc-v-cpus) to start NuttX on Multiple CPUs

  (Including the [__RV64IMACB Monitor Core__](https://lupyuen.github.io/articles/sbi#query-the-risc-v-cpus))

- [__SBI Inter-Processor Interrupts__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#7-ipi-extension-eid-0x735049-spi-s-mode-ipi) to communicate across CPUs

- [__SBI Timer__](https://lupyuen.github.io/articles/sbi#set-a-system-timer) to set the [__System Timer__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L82-L108)

- [__SBI RFENCE__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#8-rfence-extension-eid-0x52464e43-rfnc) to flush [__Device I/O and Memory Accesses__](https://five-embeddev.com/quickref/instructions.html#-rv32--secfence)

- [__Performance Monitoring__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#11-performance-monitoring-unit-extension-eid-0x504d55-pmu) might be helpful for NuttX

- [__Shutdown and Reboot__](https://lupyuen.github.io/articles/sbi#shutdown-and-reboot-the-sbc) because what goes up, must come down

And we'll [__Probe the SBI Extensions__](https://lupyuen.github.io/articles/sbi#probe-the-sbi-extensions) before calling them.

_Can NuttX Apps call OpenSBI?_

Nope, only the __NuttX Kernel__ is allowed to call OpenSBI.

That's because NuttX Apps run in [__RISC-V User Mode__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu). When NuttX Apps execute the __`ecall` Instruction__, they will jump from User Mode to Supervisor Mode to execute [__NuttX Kernel Functions__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu). (Not OpenSBI Functions)

Thus NuttX Apps are prevented from calling OpenSBI to meddle with CPUs, Timers and Interrupts. (Which should be meddled by the NuttX Kernel anyway)

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
