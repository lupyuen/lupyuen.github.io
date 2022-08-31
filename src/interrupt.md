# NuttX RTOS on PinePhone: Fixing the Interrupts

📝 _6 Sep 2022_

![Tracing Arm64 Interrupts on QEMU Emulator can get... Really messy](https://lupyuen.github.io/images/interrupt-title.jpg)

_Tracing Arm64 Interrupts on QEMU Emulator can get... Really messy_

Creating our own __Operating System__ (non-Linux) for __Pine64 PinePhone__ can be super challenging...

-   How does PinePhone handle Interrupts?

-   What's a Generic Interrupt Controller? (GIC)

-   Why is PinePhone's GIC particularly problematic?

-   What's an Exception Level? (EL)

-   Why does EL matter for handling Arm64 Interrupts?

We'll answer these questions today as we port __Apache NuttX RTOS__ to PinePhone.

Let's dive into our __Porting Journal__ for NuttX on PinePhone...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

And relive the very first __Interrupt issue__ that we hit...

```text
HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
arm64_gic_initialize: no distributor detected, giving up
```

![Partial list of Shared Peripheral Interrupts for Allwinner A64's GIC](https://lupyuen.github.io/images/interrupt-peripheral.jpg)

_Partial list of Shared Peripheral Interrupts for Allwinner A64's GIC_

# Generic Interrupt Controller

_What's a GIC?_

A __Generic Interrupt Controller (GIC)__ works like a typical Interrupt Controller in a CPU. It manages Interrupts for the Arm64 CPU.

Except that GIC is a special chunk of silicon that lives __inside the Allwinner A64 SoC__. (Outside the Arm64 CPU)

_Huh? Arm64 CPU doesn't have its own Interrupt Controller?_

Interrupting gets complicated... Remember PinePhone runs on __4 Arm64 CPUs?__

The 4 CPUs must handle the Interrupts triggered by __all kinds of Peripherals__: UART, I2C, DMA, USB, microSD, eMMC, ...

We do this the __flexible, efficient__ way with a GIC, which supports...

-   __Shared Peripheral Interrupts (SPI)__

    GIC can route Peripheral Interrupts to __one or multiple CPUs__

    (Pic above)

-   __Private Peripheral Interrupts (PPI)__

    GIC can route Peripheral Interrupts to a __single CPU__

-   __Software-Generated Interrupts (SGI)__

    GIC lets CPUs to __talk to each other__ by triggering Software Interrupts

    (Anyone remember Silicon Graphics?)

Allwinner A64's GIC supports __157 Interrupt Sources__: 16 Software-Generated, 16 Private and 125 Shared.

The GIC in Allwinner A64 is a little problematic, let's talk...

![Allwinner A64 runs on Arm GIC Version 2](https://lupyuen.github.io/images/interrupt-gic.jpg)

_Allwinner A64 runs on Arm GIC Version 2_

# Allwinner A64 GIC

_What's this GIC error we saw earlier?_

```text
HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
arm64_gic_initialize: no distributor detected, giving up
```

When we boot NuttX RTOS, it expects PinePhone to provide a modern __Generic Interrupt Controller (GIC), Version 3__.

But the [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) (page 210, "GIC") says that PinePhone runs on...

-   [__Arm GIC PL400__](https://developer.arm.com/documentation/ddi0471/b/introduction/about-the-gic-400), which is based on...

-   [__Arm GIC Version 2__](https://developer.arm.com/documentation/ihi0048/latest/)

Our GIC Version 2 is from 2011, when Arm CPUs were still 32-bit... That's __11 years ago!__

So we need to fix NuttX and downgrade GIC Version 3 __back to GIC Version 2__, specially for PinePhone.

_We're sure that PinePhone runs on GIC Version 2?_

Let's verify! This code reads the __GIC Version__ from PinePhone: [arch/arm64/src/common/arm64_gicv3.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L710-L734)

```c
// Init GIC v2 for PinePhone
int arm64_gic_initialize(void) {
  sinfo("TODO: Init GIC for PinePhone\n");
  sinfo("CONFIG_GICD_BASE=%p\n", CONFIG_GICD_BASE);
  sinfo("CONFIG_GICR_BASE=%p\n", CONFIG_GICR_BASE);

  // To verify the GIC Version, read the Peripheral ID2 Register (ICPIDR2) at Offset 0xFE8 of GIC Distributor.
  // Bits 4 to 7 of ICPIDR2 are...
  // - 0x1 for GIC Version 1
  // - 0x2 for GIC Version 2
  // GIC Distributor is at 0x01C80000 + 0x1000
  const uint8_t *ICPIDR2 = (const uint8_t *) (CONFIG_GICD_BASE + 0xFE8);
  uint8_t version = (*ICPIDR2 >> 4) & 0b1111;
  sinfo("GIC Version is %d\n", version);
  DEBUGASSERT(version == 2);
```

Here's the output...

```text
arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx#pinephone-u-boot-log)

Yep PinePhone runs on __GIC Version 2__. Bummer.

_What are GICD and GICR?_

__GICD (GIC Distributor)__ and __GICR (GIC CPU Interface)__ are the addresses for accessing the GIC on PinePhone.

According to [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) (page 74, "Memory Mapping"), the GIC is located at...

| Module | Address | Remarks
| :----- | :------ | :------
| GIC_DIST | `0x01C8` `0000` + `0x1000`| GIC Distributor (GICD)
| GIC_CPUIF | `0x01C8` `0000` + `0x2000`| GIC CPU Interface (GICR)

Which we define in NuttX as: [arch/arm64/include/qemu/chip.h](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/include/qemu/chip.h#L38-L62)

```c
// PinePhone Generic Interrupt Controller
// GIC_DIST:  0x01C80000 + 0x1000
// GIC_CPUIF: 0x01C80000 + 0x2000
#define CONFIG_GICD_BASE 0x01C81000  
#define CONFIG_GICR_BASE 0x01C82000  
```

Back to our headache of GIC Version 2...

# GIC Version 2

_Does NuttX support GIC Version 2 for PinePhone?_

Yes NuttX supports __Generic Interrupt Controller (GIC) Version 2__ but there's a catch... It's for __Arm32 CPUs, not Arm64 CPUs!__

-   [arch/arm/src/armv7-a/arm_gicv2.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm/src/armv7-a/arm_gicv2.c)

-   [arch/arm/src/armv7-a/arm_gicv2_dump.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm/src/armv7-a/arm_gicv2_dump.c)

-   [arch/arm/src/armv7-a/gic.h](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm/src/armv7-a/gic.h)

Remember: GIC Version 2 was created for Arm32.

_So we port NuttX's GIC Version 2 from Arm32 to Arm64?_

Kinda. We did a __horrible hack__... Don't try this at home! (Unless you have a ten-foot pole) [arch/arm64/src/common/arm64_gicv3.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L765-L823)

```c
// GIC v2 for PinePhone:
// Reuse the implementation of Arm32 GIC v2
#define PINEPHONE_GICv2
#define CONFIG_ARMV7A_HAVE_GICv2
#define CONFIG_ARCH_TRUSTZONE_NONSECURE

// Override...
// MPCORE_ICD_VBASE: GIC Distributor
// MPCORE_ICC_VBASE: GIC CPU Interface
#include "../arch/arm/src/armv7-a/mpcore.h"
#undef  MPCORE_ICD_VBASE
#undef  MPCORE_ICC_VBASE
#define MPCORE_ICD_VBASE CONFIG_GICD_BASE  // 0x01C81000  
#define MPCORE_ICC_VBASE CONFIG_GICR_BASE  // 0x01C82000  

// Inject Arm32 GIC v2 Implementation
#include "../arch/arm/src/armv7-a/arm_gicv2.c"
```

[(We commented out the __GIC Version 3__ code as __`NOTUSED`__)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c)

_What! Did we just `#include` the GIC Version 2 Source Code from Arm32 into Arm64?_

Yep it's an awful trick but it seems to work!

We made __minor tweaks__ to GIC Version 2 to compile with Arm64...

-   [Changes to arm_gicv2.c](https://github.com/lupyuen/incubator-nuttx/commit/6fa0e7e5d2beddad07890c83d2ee428a3f2b8a62#diff-6e1132aef124dabaf94c200ab06d65c7bc2b9967bf76a46aba71a7f43b5fb219)

-   [Changes to arm_gicv2_dump.c](https://github.com/lupyuen/incubator-nuttx/commit/4fc2669fef62d12ba1dd428f2daf03d3bc362501#diff-eb05c977988d59202a9472f6fa7f9dc290724662ad6d15a4ba99b8f1fc1dc8f8)

-   [Changes to gic.h](https://github.com/lupyuen/incubator-nuttx/commit/6fa0e7e5d2beddad07890c83d2ee428a3f2b8a62#diff-b4fcb67b71de954c942ead9bb0868e720a5802c90743f0a1883f84b7565e1a0f)

We rewrote this function for Arm64 because we're passing __64-bit Registers__ (instead of 32-bit): [arm64_gicv3.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L795-L822)

```c
// Decode IRQ for PinePhone.
// Based on arm_decodeirq in arm_gicv2.c.
// Previously we passed 32-bit Registers as `uint32_t *`
uint64_t * arm64_decodeirq(uint64_t * regs) {
  /* Omitted: Get the interrupt ID */
  ...
  /* Dispatch the Arm64 interrupt */
  regs = arm64_doirq(irq, regs);
```

Everything else stays the same! Well except for...

-   [__`arm64_gic_initialize`__](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L713-L743)

-   [__`arm64_gic_secondary_init`__](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L753-L760)

-   [__`arm64_gic_irq_set_priority`__](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L162-L196)

_Injecting Arm32 into Arm64 sounds so reckless... Will it work?_

Let's test our reckless GIC Version 2 with QEMU Emulator...

# Test PinePhone GIC with QEMU

_Will our hacked GIC Version 2 run on PinePhone?_

Before testing on PinePhone, let's test our Generic Interrupt Controller (GIC) Version 2 on __QEMU Emulator__.

Follow these steps to build NuttX for __QEMU with GIC Version 2__...

-   [__"Test PinePhone GIC with QEMU"__](https://github.com/lupyuen/pinephone-nuttx#test-pinephone-gic-with-qemu)

Enter this to __start QEMU with NuttX__ and GIC Version 2...

```bash
## Run GIC Version 2 with QEMU
qemu-system-aarch64 \
  -smp 4 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=2 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

Note that "__`gic-version=2`__" instead of the usual GIC Version 3 for Arm64.

Also we simulated 4 Cores of Arm Cortex-A53 (similar to PinePhone): "__`-smp 4`__"

We see this in QEMU...

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x402c4000, heap_size=0x7d3c000
arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x8000000
arm64_gic_initialize: CONFIG_GICR_BASE=0x8010000
arm64_gic_initialize: GIC Version is 2

up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 62.50MHz, cycle 62500
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0

work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x402a7000 _einit: 0x402a7000 _stext: 0x40280000 _etext: 0x402a8000
nsh: sysinit: fopen failed: 2
nsh: mkfatfs: command not found

NuttShell (NSH) NuttX-10.3.0-RC2
nsh>
nx_start: CPU0: Beginning Idle Loop
```

Yep NuttX with GIC Version 2 boots OK on QEMU, and will probably run on PinePhone!

_How did we get the GIC Base Addresses for QEMU?_

```text
CONFIG_GICD_BASE=0x8000000
CONFIG_GICR_BASE=0x8010000
```

We got the Base Addresses for GIC Distributor (__`CONFIG_GICD_BASE`__) and GIC CPU Interface (__`CONFIG_GICR_BASE`__) by dumping the Device Tree from QEMU...

```bash
## Dump Device Tree for GIC Version 2
qemu-system-aarch64 \
  -smp 4 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=2,dumpdtb=gicv2.dtb \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx

## Convert Device Tree to text format
dtc -o gicv2.dts -O dts -I dtb gicv2.dtb
```

The Base Addresses are revealed in the __GIC Version 2 Device Tree__: [gicv2.dts](https://github.com/lupyuen/incubator-nuttx/blob/gicv2/gicv2.dts#L324)...

```text
intc@8000000 {
reg = <
    0x00 0x8000000 0x00 0x10000  //  GIC Distributor:   0x8000000
    0x00 0x8010000 0x00 0x10000  //  GIC CPU Interface: 0x8010000
    0x00 0x8030000 0x00 0x10000  //  VGIC Virtual Interface Control: 0x8030000
    0x00 0x8040000 0x00 0x10000  //  VGIC Virtual CPU Interface:     0x8040000
>;
compatible = "arm,cortex-a15-gic";
```

[(More about this)](https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt)

Which we defined in NuttX at...

-   [arch/arm64/include/qemu/chip.h](https://github.com/lupyuen/incubator-nuttx/blob/gicv2/arch/arm64/include/qemu/chip.h#L38-L40)

# PinePhone Hangs At Startup

_NuttX should boot OK on PinePhone right?_

We followed these steps to __boot NuttX on PinePhone__ (with GIC Version 2)...

-   [__"NuttX Boot Log"__](https://github.com/lupyuen/pinephone-nuttx#nuttx-boot-log)

But __NuttX got stuck__ on PinePhone in a very curious way...

```text
arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2
up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
uart_regi
```

NuttX got stuck __while printing a line!__

And it happened a short while after we started the __System Timer__: __`up_timer_initialize`__

[(More about System Timer)](https://github.com/lupyuen/pinephone-nuttx#system-timer)

_Something in the System Timer caused this?_

Yep! If we __disabled the System Timer__, PinePhone will continue to boot.

Remember that the System Timer will trigger Interrupts periodically...

Perhaps we're __handling Interrupts incorrectly?__

Let's investigate...

# Timer Interrupt Isn't Handled

_Why did PinePhone hang while handling System Timer Interrupts?_

_Was the Timer Interrupt Handler called?_

We verified that __Timer Interrupt Handler [arm64_arch_timer_compare_isr](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.c#L134-L161)__ was NEVER called.

(We checked by calling [__`up_putc`__](https://github.com/lupyuen/pinephone-nuttx#boot-debugging), which prints directly to the UART Port)

So something went wrong BEFORE calling the Interrupt Handler. Let's backtrack...

_Is the Interrupt Vector Table pointing correctly to the Timer Interrupt Handler?_

NuttX defines an __Interrupt Vector Table__ for dispatching Interrupt Handlers...

-   [__"Handling Interrupts"__](https://github.com/lupyuen/pinephone-nuttx#handling-interrupts)

We dumped NuttX's Interrupt Vector Table...

-   [__"Dump Interrupt Vector Table"__](https://github.com/lupyuen/pinephone-nuttx#dump-interrupt-vector-table)

And verified that the Timer Interrupt Handler is set correctly in the table.

_Maybe something went wrong when NuttX tried to call the Interrupt Handler?_

NuttX should call [__Interrupt Dispatcher `irq_dispatch`__](https://github.com/lupyuen/pinephone-nuttx#handling-interrupts) to dispatch the Interrupt Handler...

But nope, __`irq_dispatch`__ was never called.

_Some error occurred and NuttX threw an Unexpected Interrupt?_

Nope, the [__Unexpected Interrupt Handler `irq_unexpected_isr`__](https://github.com/lupyuen/pinephone-nuttx#handling-interrupts) was never called either.

_OK I'm really stumped. Did something go bad deep inside Arm64 Interrupts?_

Possibly! Let's talk about the Arm64 Vector Table...

![Vector Base Address Register, EL1](https://lupyuen.github.io/images/interrupt-vbar.jpg)

# Arm64 Vector Table Is Wrong

_When an Interrupt is triggered, what happens in the Arm64 CPU?_

According to the [__Arm Cortex-A53 Technical Reference Manual__](https://documentation-service.arm.com/static/5e9075f9c8052b1608761519?token=) (page 4-121), the CPU reads the __Vector Base Address Register (EL1)__ to locate the Arm64 Vector Table. (Pic above)

(Why EL1? We'll explain in a while)

The __Arm64 Vector Table__ looks like this...

![Arm64 Vector Table](https://lupyuen.github.io/images/interrupt-vector.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_vector_table.S#L93-L131)

Which we define in NuttX as __`_vector_table`__: [arch/arm64/src/common/arm64_vector_table.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_vector_table.S#L93-L232)

```text
GTEXT(_vector_table)
SECTION_SUBSEC_FUNC(exc_vector_table,_vector_table_section,_vector_table)
  ...
  /* Current EL with SP0 / IRQ */
  .align 7
  arm64_enter_exception x0, x1
  b    arm64_irq_handler
  ...
  /* Current EL with SPx / IRQ */
  .align 7
  arm64_enter_exception x0, x1
  b    arm64_irq_handler
```

[(__`arm64_enter_exception`__ is defined here)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_vector_table.S#L41-L87)

[(__`arm64_irq_handler`__ is the NuttX IRQ Handler)](https://github.com/lupyuen/pinephone-nuttx#handling-interrupts)

_So Vector Base Address Register (EL1) should point to `_vector_table`?_

Let's find out! This is how we read __Vector Base Address Register (EL1)__: [arch/arm64/src/common/arm64_arch_timer.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.c#L212-L235)

```c
void up_timer_initialize(void) {
  ...
  // For PinePhone: Read Vector Base Address Register EL1
  extern void *_vector_table[];
  sinfo("_vector_table=%p\n", _vector_table);
  sinfo("Before writing: vbar_el1=%p\n", read_sysreg(vbar_el1));
```

Here's the output on PinePhone...

```text
_vector_table=0x400a7000
Before writing: vbar_el1=0x40227000
```

Aha! __`_vector_table`__ is at __`0x400a` `7000`__... But Vector Base Address Register (EL1) says __`0x4022` `7000`!__

Our Arm64 CPU is pointing to the __wrong Arm64 Vector Table__... Hence our Interrupt Handler is never called!

Let's fix it: [arch/arm64/src/common/arm64_arch_timer.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.c#L212-L235)

```c
  // For PinePhone: Write Vector Base Address Register EL1
  write_sysreg((uint64_t)_vector_table, vbar_el1);
  ARM64_ISB();

  // For PinePhone: Read Vector Base Address Register EL1
  sinfo("After writing: vbar_el1=%p\n", read_sysreg(vbar_el1));
```

This writes the correct value of __`_vector_table`__ back into Vector Base Address Register EL1. Here's the output on PinePhone...

```text
_vector_table=0x400a7000
Before writing: vbar_el1=0x40227000
After writing:  vbar_el1=0x400a7000
```

Yep Vector Base Address Register (EL1) is now correct.

Our Interrupt Handlers are now working fine... And PinePhone boots successfully yay! 🎉

```text
HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x400c4000, heap_size=0x7f3c000
arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2

up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
up_timer_initialize: _vector_table=0x400a7000
up_timer_initialize: Before writing: vbar_el1=0x40227000
up_timer_initialize: After writing:  vbar_el1=0x400a7000

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x400a7000 _einit: 0x400a7000 _stext: 0x40080000 _etext: 0x400a8000
nx_start: CPU0: Beginning Idle Loop
```

Let's talk about EL1...

# Exception Levels

_What's EL1?_

EL1 is __Exception Level 1__. As defined in [__Arm Cortex-A53 Technical Reference Manual__](https://documentation-service.arm.com/static/5e9075f9c8052b1608761519?token=) page 3-5 ("Exception Level")...

> The ARMv8 exception model defines exception levels EL0-EL3, where:

> - EL0 has the lowest software execution privilege, and execution at EL0 is called unprivileged execution.

> - Increased exception levels, from 1 to 3, indicate increased software execution privilege.

> - EL2 provides support for processor virtualization.

> - EL3 provides support for a secure state, see Security state on page 3-6.

So __EL1 is (kinda) privileged__, suitable for running OS Kernel code. (Like NuttX)

NuttX runs mostly in __EL1__ and briefly in __EL2__ (at startup)...

```text
HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
```

(Remember that EL1 is less privileged than EL2, which supports Processor Virtualization)

That's why we talked about the EL1 Vector Base Address Register in the previous section.

_So there's a Vector Base Address Register for EL1, EL2 and EL3?_

Indeed! Each Exception Level has its own Arm64 Vector Table.

(Except EL0)

_Who loads the EL1 Vector Base Address Register?_

The EL1 Vector Base Address Register is loaded during __EL1 Initialisation__ at startup: [arch/arm64/src/common/arm64_boot.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_boot.c#L132-L162)

```c
void arm64_boot_el1_init(void) {
  /* Setup vector table */
  write_sysreg((uint64_t)_vector_table, vbar_el1);
  ARM64_ISB();
```

__`arm64_boot_el1_init`__ is called by our Startup Code: [arch/arm64/src/common/arm64_head.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L216-L230)

```text
    PRINT(switch_el1, "- Boot from EL1\r\n")

    /* EL1 init */
    bl    arm64_boot_el1_init

    /* set SP_ELx and Enable SError interrupts */
    msr   SPSel, #1
    msr   DAIFClr, #(DAIFCLR_ABT_BIT)
    isb

jump_to_c_entry:
    PRINT(jump_to_c_entry, "- Boot to C runtime for OS Initialize\r\n")
    ret x25
```

_So how did our Vector Base Address Register get messed up? And why is it off by exactly `0x18` `0000`?_

TODO

# Memory Map

TODO

PinePhone depends on Arm's Memory Management Unit (MMU). We defined two MMU Memory Regions for PinePhone: RAM and Device I/O: [arch/arm64/include/qemu/chip.h](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/include/qemu/chip.h#L38-L62)

```c
// PinePhone Generic Interrupt Controller
// GIC_DIST:  0x01C80000 + 0x1000
// GIC_CPUIF: 0x01C80000 + 0x2000
#define CONFIG_GICD_BASE          0x01C81000  
#define CONFIG_GICR_BASE          0x01C82000  

// Previously:
// #define CONFIG_GICD_BASE          0x8000000
// #define CONFIG_GICR_BASE          0x80a0000

// PinePhone RAM: 0x4000 0000 to 0x4800 0000
#define CONFIG_RAMBANK1_ADDR      0x40000000
#define CONFIG_RAMBANK1_SIZE      MB(128)

// PinePhone Device I/O: 0x0 to 0x2000 0000
#define CONFIG_DEVICEIO_BASEADDR  0x00000000
#define CONFIG_DEVICEIO_SIZE      MB(512)

// Previously:
// #define CONFIG_DEVICEIO_BASEADDR  0x7000000
// #define CONFIG_DEVICEIO_SIZE      MB(512)

// PinePhone uboot load address (kernel_addr_r)
#define CONFIG_LOAD_BASE          0x40080000
// Previously: #define CONFIG_LOAD_BASE          0x40280000
```

We also changed CONFIG_LOAD_BASE for PinePhone's Kernel Start Address (kernel_addr_r).

_How are the MMU Memory Regions used?_

NuttX initialises the Arm MMU with the MMU Memory Regions at startup: [arch/arm64/src/qemu/qemu_boot.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_boot.c#L52-L67)

```c
static const struct arm_mmu_region mmu_regions[] =
{
  MMU_REGION_FLAT_ENTRY("DEVICE_REGION",
                        CONFIG_DEVICEIO_BASEADDR, MB(512),
                        MT_DEVICE_NGNRNE | MT_RW | MT_SECURE),

  MMU_REGION_FLAT_ENTRY("DRAM0_S0",
                        CONFIG_RAMBANK1_ADDR, MB(512),
                        MT_NORMAL | MT_RW | MT_SECURE),
};

const struct arm_mmu_config mmu_config =
{
  .num_regions = ARRAY_SIZE(mmu_regions),
  .mmu_regions = mmu_regions,
};
```

The Arm MMU Initialisation is done by `arm64_mmu_init`, defined in [arch/arm64/src/common/arm64_mmu.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_mmu.c#L571-L622)

We'll talk more about the Arm MMU in the next section...

# Boot Sequence

TODO

This section describes the Boot Sequence for NuttX on PinePhone.

The Startup Code (in Arm64 Assembly) inits the Arm64 System Registers, UART Port and jumps to `arm64_boot_secondary_c_routine` (in C): [arch/arm64/src/common/arm64_head.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L228-L230)

```text
    ldr    x25, =arm64_boot_secondary_c_routine
    ...
jump_to_c_entry:
    PRINT(jump_to_c_entry, "- Boot to C runtime for OS Initialize\r\n")
    ret x25
```

`arm64_boot_primary_c_routine` inits the BSS, calls `arm64_chip_boot` to init the Arm64 CPU, and `nx_start` to start the NuttX processes: [arch/arm64/src/common/arm64_boot.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_boot.c#L179-L189)

```c
void arm64_boot_primary_c_routine(void)
{
  boot_early_memset(_START_BSS, 0, _END_BSS - _START_BSS);
  arm64_chip_boot();
  nx_start();
}
```

`arm64_chip_boot` calls `arm64_mmu_init` to enable the Arm Memory Management Unit, and `qemu_board_initialize` to init the Board Drivers: [arch/arm64/src/qemu/qemu_boot.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_boot.c#L81-L105)

```c
void arm64_chip_boot(void)
{
  /* MAP IO and DRAM, enable MMU. */

  arm64_mmu_init(true);

#ifdef CONFIG_SMP
  arm64_psci_init("smc");

#endif

  /* Perform board-specific device initialization. This would include
   * configuration of board specific resources such as GPIOs, LEDs, etc.
   */

  qemu_board_initialize();

#ifdef USE_EARLYSERIALINIT
  /* Perform early serial initialization if we are going to use the serial
   * driver.
   */

  qemu_earlyserialinit();
#endif
}
```

`arm64_mmu_init` is defined in [arch/arm64/src/common/arm64_mmu.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_mmu.c#L571-L622)

The next section talks about debugging the Boot Sequence...

# Boot Debugging

TODO

_How can we debug NuttX while it boots?_

We may call `up_putc` to print characters to the Serial Console and troubleshoot the Boot Sequence: [arch/arm64/src/common/arm64_boot.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_boot.c#L179-L189)

```c
void arm64_boot_primary_c_routine(void)
{
  int up_putc(int ch);  // For debugging
  up_putc('0');  // For debugging
  boot_early_memset(_START_BSS, 0, _END_BSS - _START_BSS);
  up_putc('1');  // For debugging
  arm64_chip_boot();
  up_putc('2');  // For debugging
  nx_start();
}
```

This prints "012" to the Serial Console as NuttX boots.


# NuttX Boot Log

TODO

Here's the UART Log of NuttX booting on PinePhone...

```text
DRAM: 2048 MiB
Trying to boot from MMC1
NOTICE:  BL31: v2.2(release):v2.2-904-gf9ea3a629
NOTICE:  BL31: Built : 15:32:12, Apr  9 2020
NOTICE:  BL31: Detected Allwinner A64/H64/R18 SoC (1689)
NOTICE:  BL31: Found U-Boot DTB at 0x4064410, model: PinePhone
NOTICE:  PSCI: System suspend is unavailable

U-Boot 2020.07 (Nov 08 2020 - 00:15:12 +0100)

DRAM:  2 GiB
MMC:   Device 'mmc@1c11000': seq 1 is in use by 'mmc@1c10000'
mmc@1c0f000: 0, mmc@1c10000: 2, mmc@1c11000: 1
Loading Environment from FAT... *** Warning - bad CRC, using default environment

starting USB...
No working controllers found
Hit any key to stop autoboot:  0 
switch to partitions #0, OK
mmc0 is current device
Scanning mmc 0:1...
Found U-Boot script /boot.scr
653 bytes read in 3 ms (211.9 KiB/s)
## Executing script at 4fc00000
gpio: pin 114 (gpio 114) value is 1
99784 bytes read in 8 ms (11.9 MiB/s)
Uncompressed size: 278528 = 0x44000
36162 bytes read in 4 ms (8.6 MiB/s)
1078500 bytes read in 51 ms (20.2 MiB/s)
## Flattened Device Tree blob at 4fa00000
   Booting using the fdt blob at 0x4fa00000
   Loading Ramdisk to 49ef8000, end 49fff4e4 ... OK
   Loading Device Tree to 0000000049eec000, end 0000000049ef7d41 ... OK

Starting kernel ...

HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
nx_start: Entry
up_allocate_heap: heap_start=0x0x400c4000, heap_size=0x7f3c000
arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2
up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
up_timer_initialize: _vector_table=0x400a7000
up_timer_initialize: Before writing: vbar_el1=0x40227000
up_timer_initialize: After writing: vbar_el1=0x400a7000
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x400a7000 _einit: 0x400a7000 _stext: 0x40080000 _etext: 0x400a8000
nx_start: CPU0: Beginning Idle Loop
```

_Where's the rest of the boot output?_

We expect to see this output when NuttX boots...

-   ["Test NuttX: Single Core"](https://lupyuen.github.io/articles/arm#test-nuttx-single-core)

But PinePhone stops halfway. Let's find out why...

# System Timer 

TODO

NuttX starts the System Timer when it boots. Here's how the System Timer is started: [arch/arm64/src/common/arm64_arch_timer.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.c#L212-L233)

```c
void up_timer_initialize(void)
{
  uint64_t curr_cycle;

  arch_timer_rate   = arm64_arch_timer_get_cntfrq();
  cycle_per_tick    = ((uint64_t)arch_timer_rate / (uint64_t)TICK_PER_SEC);

  sinfo("%s: cp15 timer(s) running at %lu.%02luMHz, cycle %ld\n", __func__,
        (unsigned long)arch_timer_rate / 1000000,
        (unsigned long)(arch_timer_rate / 10000) % 100, cycle_per_tick);

  irq_attach(ARM_ARCH_TIMER_IRQ, arm64_arch_timer_compare_isr, 0);
  arm64_gic_irq_set_priority(ARM_ARCH_TIMER_IRQ, ARM_ARCH_TIMER_PRIO,
                             ARM_ARCH_TIMER_FLAGS);

  curr_cycle = arm64_arch_timer_count();
  arm64_arch_timer_set_compare(curr_cycle + cycle_per_tick);
  arm64_arch_timer_enable(true);

  up_enable_irq(ARM_ARCH_TIMER_IRQ);
  arm64_arch_timer_set_irq_mask(false);
}
```

At every tick, the System Timer triggers an interrupt that calls [`arm64_arch_timer_compare_isr`](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.c#L109-L169)

(`CONFIG_SCHED_TICKLESS` is undefined)

__Timer IRQ `ARM_ARCH_TIMER_IRQ`__ is defined in [arch/arm64/src/common/arm64_arch_timer.h](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_arch_timer.h#L38-L45)

```c
#define CONFIG_ARM_TIMER_SECURE_IRQ         (GIC_PPI_INT_BASE + 13)
#define CONFIG_ARM_TIMER_NON_SECURE_IRQ     (GIC_PPI_INT_BASE + 14)
#define CONFIG_ARM_TIMER_VIRTUAL_IRQ        (GIC_PPI_INT_BASE + 11)
#define CONFIG_ARM_TIMER_HYP_IRQ            (GIC_PPI_INT_BASE + 10)

#define ARM_ARCH_TIMER_IRQ	CONFIG_ARM_TIMER_VIRTUAL_IRQ
#define ARM_ARCH_TIMER_PRIO	IRQ_DEFAULT_PRIORITY
#define ARM_ARCH_TIMER_FLAGS	IRQ_TYPE_LEVEL
```

`GIC_PPI_INT_BASE` is defined in [arch/arm64/src/common/arm64_gic.h](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gic.h#L120-L128)

```c
#define GIC_SGI_INT_BASE            0
#define GIC_PPI_INT_BASE            16
#define GIC_IS_SGI(intid)           (((intid) >= GIC_SGI_INT_BASE) && \
                                     ((intid) < GIC_PPI_INT_BASE))

#define GIC_SPI_INT_BASE            32
#define GIC_NUM_INTR_PER_REG        32
#define GIC_NUM_CFG_PER_REG         16
#define GIC_NUM_PRI_PER_REG         4
```

# GIC Register Dump

TODO

Below is the dump of PinePhone's registers for [Arm Generic Interrupt Controller version 2](https://developer.arm.com/documentation/ihi0048/latest/)...

# What's Next

TODO

_Will NuttX work with all PinePhone features?_

__NuttX on PinePhone__ might take a while to become a __Daily Driver__...

-   [__"PinePhone on RTOS"__](https://lupyuen.github.io/articles/arm#pinephone-on-rtos)

-   [__"PinePhone Drivers and Apps"__](https://lupyuen.github.io/articles/arm#pinephone-drivers-and-apps)

But today NuttX is ready to turn PinePhone into a valuable __Learning Resource__!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/interrupt.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/interrupt.md)

# Notes

1.  TODO
