# RISC-V Ox64 BL808 SBC: UART Interrupt and Platform-Level Interrupt Controller (PLIC)

📝 _7 Dec 2023_

![Platform-Level Interrupt Controller for Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/plic2-registers.jpg)

> _"It’s time for the little red chicken’s bedtime story - and a reminder from Papa to try not to interrupt. But the chicken can’t help herself!"_

> — ["Interrupting Chicken"](https://share.libbyapp.com/title/4190211)

Our Story today is all about __RISC-V Interrupts__ on the tiny adorable [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) 64-bit Single-Board Computer (pic below)...

- What's inside the __Platform-Level Interrupt Controller__ (PLIC)

- __Setting up the PLIC__ at startup

- __Enabling the PLIC Interrupt__ for Serial Console

- __Handling PLIC Interrupts__ for UART Input

  [(Based on __Bouffalo Lab BL808 SoC__)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

We'll walk through the steps with a simple barebones operating system: [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

Though we'll hit a bumpy journey with our work-in-progress __NuttX on Ox64__...

- __Leaky Writes__ seem to affect adjacent PLIC Registers

- __Interrupt Claim__ doesn't seem to work right

  [(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

We begin our story...

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sd.jpg)

# Platform-Level Interrupt Controller

_What's this PLIC?_

[__Platform-Level Interrupt Controller__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#plic) (PLIC) is the hardware inside our BL808 SoC that controls the forwarding of __Peripheral Interrupts__ to our 64-bit RISC-V CPU. (Pic below)

(Like Interrupts for UART, I2C, SPI, ...)

Each Interrupt is identified by a __RISC-V IRQ Number__. (__IRQ__ means Interrupt Request Number)

NuttX uses its own __NuttX IRQ Number__...

- NuttX IRQ = 25 + RISC-V IRQ

That's because NuttX reserves a bunch of IRQ Numbers for Internal Use. (Hence the Offset of 25)

Pressing a key in the Ox64 Serial Console will fire an Interrupt in PLIC. First we need the IRQ Number for Serial Console...

[(PLIC is documented in __C906 User Manual__, Page 74)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

[(See the __Official PLIC Spec__)](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#plic)

![BL808 Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-bl808a.jpg)

# UART Interrupt

_What's the Interrupt Number for the Serial Console?_

To enable Text Input in the __Ox64 Serial Console__, we need the UART Interrupt Number...

- We're running on the __D0 Multimedia Core__ of the BL808 SoC

  (Pic above)

- Connected to the D0 Multimedia Core is the __UART3 Controller__ for Serial Console

  (Pic below)

- According to the table below: RISC-V IRQ Number for UART3 is...

  __IRQ_NUM_BASE + 4__

- Also in the table...

  __IRQ_NUM_BASE__ is __16__

Therefore the __RISC-V IRQ Number__ for our Serial Console (UART3) is __20__.

Remember that NuttX uses its own __NuttX IRQ Number__...

- NuttX IRQ = 25 + RISC-V IRQ

Thus later we'll handle __NuttX IRQ Number 45__ in our code. And our Ox64 Serial Console will support Text Input!

_How did we get the UART Driver for Ox64 BL808?_

We copied the __NuttX UART Driver__ from BL602 to BL808, since the UART Controllers are similar...

- [__"UART Driver for Ox64"__](https://lupyuen.github.io/articles/plic2#appendix-uart-driver-for-ox64)

![BL808 Reference Manual (Page 44)](https://lupyuen.github.io/images/plic2-irq.jpg)

[_BL808 Reference Manual (Page 44)_](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

# Initialise the Interrupts

_How shall we get started with PLIC?_

We walk through the steps to __prepare the Platform-Level Interrupt Controller__ (PLIC) at startup...

1.  __Disable all Interrupts__

    (Because we're about to configure them)

1.  Clear the __Outstanding Interrupts__

    (So we won't get stuck at startup)

1.  Set the __Interrupt Priority__

    (To the Lowest Priority)

1.  Set the __Interrupt Threshold__

    (Allowing Interrupts to be fired later)

![Disable Interrupts](https://lupyuen.github.io/images/plic2-registers3a.jpg)

## Disable all Interrupts

We begin by __disabling all Interrupts__ in PLIC.

Writing 0 to the __Interrupt Enable__ Register (pic above) will disable all PLIC Interrupts: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L41-L61)

```c
// Init the Platform-Level Interrupt Controller
void up_irqinitialize(void) {

  // Disable Supervisor-Mode Interrupts (SIE Register)
  up_irq_save();

  // Disable all External Interrupts
  // PLIC_ENABLE1 is 0xE000_2080
  // PLIC_ENABLE2 is 0xE000_2084
  // putreg32(V, A) writes 32-bit value V to address A
  putreg32(0x0, PLIC_ENABLE1);  // RISC-V IRQ 1  to 31
  putreg32(0x0, PLIC_ENABLE2);  // RISC-V IRQ 32 to 63
```

[(__up_irq_save__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/include/irq.h#L674-L703)

[(__putreg32__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_internal.h#L124-L132)

[(__PLIC_ENABLE__ and other PLIC Offsets)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/hardware/jh7110_plic.h#L34-L49)

[(NuttX calls __up_irqinitialize__ at startup)](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

Hence at startup, all PLIC Interrupts are disabled until we __enable them later__ (in PLIC).

![Clear Interrupts](https://lupyuen.github.io/images/plic2-registers5a.jpg)

## Clear the Interrupts

Next we __Claim and Complete__ the Outstanding Interrupts, so they won't bother us at startup (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L61-L68)

```c
  // Claim and Complete the Outstanding Interrupts
  // PLIC_CLAIM is 0xE020_1004
  // getreg32(A) reads a 32-bit value from address A
  uintptr_t val = getreg32(PLIC_CLAIM);
  putreg32(val, PLIC_CLAIM);
```

[(__getreg32__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_internal.h#L124-L132)

(More about __Claim and Complete__ in a while)

![Set Interrupt Priority](https://lupyuen.github.io/images/plic2-registers1.jpg)

## Set the Interrupt Priority

We initialise the __Interrupt Priority__ of all Interrupts to 1 (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L75C1-L90)

```c
  // Set Priority for all External Interrupts to 1 (Lowest)
  // NR_IRQS is 83 (TODO: BL808 only supports 82 Peripheral Interrupts)
  // PLIC_PRIORITY is 0xE000_0000
  for (int id = 1; id <= NR_IRQS; id++) {
    putreg32(
      1,  // Value
      (uintptr_t)(PLIC_PRIORITY + 4 * id)  // Address
    );
  }
```

_Why set Interrupt Priority to 1?_

- 1 is the __Lowest Interrupt Priority__

- Default Interrupt Priority is 0, but it's __not valid__

- Interrupt won't actually fire until we __enable it later__ (in PLIC)

![Set Interrupt Threshold](https://lupyuen.github.io/images/plic2-registers2.jpg)

## Set the Interrupt Threshold

Finally we set the __Interrupt Threshold__ to 0 (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L90-L114)

```c
  // Set Interrupt Threshold to 0
  // (Permits all External Interrupts)
  // PLIC_THRESHOLD is 0xE020_1000
  putreg32(0, PLIC_THRESHOLD);

  // Attach the Common RISC-V Exception Handlers
  // TODO: Do this earlier
  riscv_exception_attach();

  // Enable Supervisor-Mode Interrupts (SIE Register)
  up_irq_enable();
}
```

[(__riscv_exception_attach__ is here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_exception.c#L89-L142)

[(__up_irq_enable__ is here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L208-L223)

_Why set Interrupt Threshold to 0?_

- Earlier we set the __Interrupt Priority to 1__ for All Interrupts

- Since __Interrupt Priority > Interrupt Threshold__ (0)...

  All Interrupts will be __allowed to fire__

- Remember: Interrupts won't actually fire until we __enable them later__ (in PLIC)

And we're done initing the PLIC at startup!

![Enable Interrupt](https://lupyuen.github.io/images/plic2-registers3.jpg)

# Enable the Interrupt

_Our Platform-Level Interrupt Controller (PLIC) is all ready for action..._

_How will we enable Interrupts in PLIC?_

Suppose we're enabling __RISC-V IRQ 20__ for UART3 Interrupt.

All we need to do is to flip __Bit 20__ to 1 in the __Interrupt Enable__ Register (pic above). Like so: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L158-L208)

```c
// Enable the NuttX IRQ specified by `irq`
// UART3 Interrupt is RISC-V IRQ 20
// Which is NuttX IRQ 45 (Offset by 25)
void up_enable_irq(int irq) {

  // Omitted: Enable Inter-CPU Interrupts (SIE Register)
  // Omitted: Enable Timer Interrupts (TIE Register)

  // If this is an External Interrupt...
  if (irq > RISCV_IRQ_EXT) {

    // Subtract 25 from NuttX IRQ to get the RISC-V IRQ
    int extirq = irq - RISCV_IRQ_EXT;

    // Set the Interrupt Enable Bit for `extirq` in PLIC
    // PLIC_ENABLE1 is 0xE000_2080
    // PLIC_ENABLE2 is 0xE000_2084
    if (0 <= extirq && extirq <= 63) {
      modifyreg32(
        PLIC_ENABLE1 + (4 * (extirq / 32)),  // Address
        0,  // Clear Bits
        1 << (extirq % 32)  // Set Bits
      );
    }
    else { PANIC(); }  // IRQ not supported (for now)
  }
}
```

[(__modifyreg32__ is here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_modifyreg32.c#L37-L57)

And PLIC will happily accept RISC-V IRQ 20 whenever we press a key!

(On the Serial Console, pic above)

_Who calls up_enable_irq?_

At startup, NuttX calls [__bl602_attach__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L383-L442) to attach the UART Interrupt Handler...

```c
// Attach UART Interrupt Handler
static int bl602_attach(struct uart_dev_s *dev) {
  ...
  // Enable Interrupt for UART3.
  // `irq` is NuttX IRQ 45
  up_enable_irq(priv->irq);
```

Which will call [__up_enable_irq__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L158-L208) to enable the UART3 Interrupt.

We're halfway through our Grand Plan of __PLIC Interrupts__! (Steps 1, 2 and 3, pic below)

We pause a moment to talk about Harts...

![Registers for Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-registers.jpg)

# Hart 0, Supervisor Mode

_The pic above: Why does it say "Hart 0, Supervisor Mode"?_

__"Hart"__ is a RISC-V CPU Core.

("Hardware Thread")

__"Hart 0"__ refers to the (one and only) __64-bit RISC-V Core__ inside the BL808 SoC...

![Inside the BL808 SoC](https://lupyuen.github.io/images/plic2-bl808a.jpg)

That runs our NuttX RTOS.

_Does the Hart Number matter?_

Most certainly! Inside the __StarFive JH7110 SoC__ (for Star64 SBC), there are __5 Harts__...

![Inside the StarFive JH7110](https://lupyuen.github.io/images/plic2-bl808b.jpg)

NuttX boots on __Hart 1__. So the PLIC Settings will use Hart 1. (Not Hart 0)

And the __PLIC Register Offsets__ are different for Hart 0 vs Hart 1. Thus the Hart Number really matters!

_Why "Supervisor Mode"?_

1.  __RISC-V Machine Mode__ is the most powerful mode in our RISC-V SBC.

    [__OpenSBI Supervisor Binary Interface__](https://lupyuen.github.io/articles/sbi) runs in Machine Mode.

    (It's like BIOS for RISC-V)

1.  __RISC-V Supervisor Mode__ is less powerful than Machine Mode.

    __NuttX Kernel__ runs in Supervisor Mode.
    
    (Linux too!)

1.  __RISC-V User Mode__ is the least powerful mode.

    __NuttX Apps__ run in User Mode.

    (Same for Linux Apps)

PLIC has a different set of registers for Machine Mode vs Supervisor Mode.

That's why we specify __Supervisor Mode__ for the PLIC Registers.

Heading back to our (interrupted) story...

![Handle Interrupt](https://lupyuen.github.io/images/plic2-registers4.jpg)

# Handle the Interrupt

_What happens when we press a key on the Serial Console? (Pic above)_

_How will PLIC handle the UART Interrupt?_

This is how we __handle Interrupts__ with the Platform-Level Interrupt Controller (PLIC)...

1.  __Claim__ the Interrupt

    (To acknowledge the Interrupt)

1.  __Dispatch__ the Interrupt

    (Call the Interrupt Handler)

1.  __Complete__ the Interrupt

    (Tell PLIC we're done)

1.  Optional: Inspect and reset the __Pending Interrupts__

    (In case we're really curious)

![Interrupt Claim Register](https://lupyuen.github.io/images/plic2-registers5.jpg)

## Claim the Interrupt

_How will we know which RISC-V Interrupt has been fired?_

That's why we have the __Interrupt Claim__ Register! (Pic above)

We read the Interrupt Claim Register to get the __RISC-V IRQ Number__ that has been fired: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L76)

```c
// Dispatch the RISC-V Interrupt
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs) {

  // Compute the (Interim) NuttX IRQ Number
  // Based on the Interrupt Vector Number
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);

  // If this is an External Interrupt...
  if (RISCV_IRQ_EXT == irq) {

    // Read the RISC-V IRQ Number
    // From PLIC Claim Register
    // Which also Claims the Interrupt
    // PLIC_CLAIM is 0xE020_1004
    uintptr_t val = getreg32(PLIC_CLAIM);

    // Compute the Actual NuttX IRQ Number:
    // RISC-V IRQ Number + 25 (RISCV_IRQ_EXT)
    irq += val;
  }
  // Up Next: Dispatch and Complete the Interrupt
```

_What exactly are we "claiming"?_

When we [__Claim an Interrupt__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#interrupt-claims) (by reading the Interrupt Claim Register)...

We're telling the PLIC: "Yes we __acknowledge the Interrupt__, but we're not done yet!"

In a while we shall Complete the Interrupt. (To tell PLIC we're done)

[(__riscv_dispatch_irq__ is called by the RISC-V Common Exception Handler)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_exception_common.S#L63-L177)

## Dispatch the Interrupt

We have Claimed the Interrupt. It's time to do some work: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L76-L85)

```c
  // Omitted: Claim the Interrupt
  ...
  // Remember: `irq` is now the ACTUAL NuttX IRQ Number:
  // RISC-V IRQ Number + 25 (RISCV_IRQ_EXT)

  // If the RISC-V IRQ Number is valid (non-zero)...
  if (RISCV_IRQ_EXT != irq) {

    // Call the Interrupt Handler
    regs = riscv_doirq(irq, regs);
  }
  // Up Next: Complete the Interrupt
```

For UART Interrupts: [__riscv_doirq__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_doirq.c#L58-L134) will call [__uart_interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L285-L343) to handle the keypress.

(That's because at startup, [__bl602_attach__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L383-L442) has registered [__uart_interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L285-L343) as the UART Interrupt Handler)

![Interrupt Claim Register](https://lupyuen.github.io/images/plic2-registers5.jpg)

## Complete the Interrupt

To tell PLIC we're done, we write the RISC-V IRQ Number back to the __Interrupt Claim__ Register.

(Yep the same one we read earlier! Pic above)

This will [__Complete the Interrupt__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#interrupt-completion), so PLIC can fire the next one: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L85-L105)

```c
  // Omitted: Claim and Dispatch the Interrupt
  ...
  // If this is an External Interrupt...
  if (RISCV_IRQ_EXT <= irq) {

    // Compute the RISC-V IRQ Number
    // and Complete the Interrupt.
    // PLIC_CLAIM is 0xE020_1004
    putreg32(               // We write the...
      irq - RISCV_IRQ_EXT,  // RISC-V IRQ Number (RISCV_IRQ_EXT = 25)
      PLIC_CLAIM            // To PLIC Claim (Complete) Register
    );
  }

  // Return the Registers to the Caller
  return regs;
}
```

And that's how we handle PLIC Interrupts!

![Interrupt Pending Register](https://lupyuen.github.io/images/plic2-registers6.jpg)

## Pending Interrupts

_What's with the Pending Interrupts?_

Normally the Interrupt Claim Register is perfectly adequate for handling Interrupts.

But if we're really curious: PLIC has an __Interrupt Pending__ Register (pic above) that will tell us which Interrupts are awaiting Claiming or Completion: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L62-L71)

```c
// Check the Pending Interrupts...
// Read PLIC_IP0: Interrupt Pending for interrupts 1 to 31
uintptr_t ip0 = getreg32(0xe0001000);

// If Bit 20 is set...
if (ip0 & (1 << 20)) {
  // Then UART3 Interrupt was fired (RISC-V IRQ 20)
  val = 20;
}
```

To tell PLIC we're done: We __clear the Individual Bits__ in the Interrupt Pending Register: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L94-L101)

```c
// Clear the Pending Interrupts...
// Set PLIC_IP0: Interrupt Pending for interrupts 1 to 31
putreg32(0, 0xe0001000);

// TODO: Clear the Individual Bits instead of wiping out the Entire Register
```

One again, we don't need really need this. We'll stash this as our __Backup Plan__ in case things go wrong.

(Oh yes, things will go wrong in a while)

![Set Interrupt Priority](https://lupyuen.github.io/images/plic2-registers1.jpg)

# Trouble with Interrupt Priority

_I sense a twist in our story..._

Earlier we initialised the [__Interrupt Priorities to 1__](https://lupyuen.github.io/articles/plic2#set-the-interrupt-priority) at startup (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L75C1-L90)

```c
// Init the Platform-Level Interrupt Controller
void up_irqinitialize(void) {
  ...
  // Set Priority for all External Interrupts to 1 (Lowest)
  // NR_IRQS is 83 (TODO: BL808 only supports 82 Peripheral Interrupts)
  // PLIC_PRIORITY is 0xE000_0000
  for (int id = 1; id <= NR_IRQS; id++) {
    putreg32(
      1,  // Value
      (uintptr_t)(PLIC_PRIORITY + 4 * id)  // Address
    );
  }

  // Dump the Interrupt Priorities
  infodumpbuffer("PLIC Interrupt Priority: After", 0xe0000004, 0x50 * 4);
```

When we [__boot NuttX on Ox64__](https://lupyuen.github.io/articles/plic2#appendix-build-and-run-nuttx), something strange happens...

```text
PLIC Interrupt Priority: After (0xe0000004):
0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L152-L172)

_Everything becomes zero! Why???_

Yeah this is totally baffling! And no Interrupts get fired, because __Interrupt Priority 0 is NOT valid__.

Let's set the Interrupt Priority specifically for __RISC-V IRQ 20__ (UART3 Interrupt): [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L444-L465)

```c
// Test the setting of PLIC Interrupt Priority
// For RISC-V IRQ 20 only
void test_interrupt_priority(void) {
  // Read the values before setting Interrupt Priority
  uint32_t before50 = *(volatile uint32_t *) 0xe0000050UL;  // RISC-V IRQ 20
  uint32_t before54 = *(volatile uint32_t *) 0xe0000054UL;  // RISC-V IRQ 21

  // Set the Interrupt Priority
  // for 0x50 (IRQ 20) but NOT 0x54 (IRQ 21)
  *(volatile uint32_t *) 0xe0000050UL = 1;

  // Read the values after setting Interrupt Priority
  uint32_t after50 = *(volatile uint32_t *) 0xe0000050UL;  // RISC-V IRQ 20
  uint32_t after54 = *(volatile uint32_t *) 0xe0000054UL;  // RISC-V IRQ 21

  // Dump before and after values:
  _info("before50=%u, before54=%u, after50=%u, after54=%u\n",
    before50, before54, after50, after54);
}
```

Again we get odd results (pic below)...

```text
before50=0, before54=0
after50=1,  after54=1
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L258-L260)

IRQ 20 is set correctly: _"after50=1"_

However __IRQ 21 is also set__! _"after54=1"_

_Hmmm... Our writing seems to have leaked over to the next 32-bit word?_

Yeah we see the __Leaky Write__ again when we set the __Interrupt Enable__ Register...

```text
// Before setting Interrupt Enable: Everything is 0
PLIC Hart 0 S-Mode Interrupt Enable: Before (0xe0002080):
0000  00 00 00 00 00 00 00 00                          ........        

// Set Interrupt Enable for RISC-V IRQ 20 (Bit 20)
up_enable_irq: extirq=20, addr=0xe0002080, val=0x1048576

// After setting Interrupt Enable:
// Bit 20 is also set in the next word!
PLIC Hart 0 S-Mode Interrupt Enable: After (0xe0002080):
0000  00 00 10 00 00 00 10 00                          ........  
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L196-L200)

Interrupt Enable has leaked over from __`0xE000` `2080`__ to __`0xE000` `2084`__!

Thus we have an unexplained problem of __Leaky Writes__, affecting the Interrupt Priority and Interrupt Enable Registers.

Up Next: More worries...

![Leaky Write for PLIC Interrupt Priority](https://lupyuen.github.io/images/plic2-title.jpg)

# More Trouble with Interrupt Claim

We talked earlier about [__Handling Interrupts__](https://lupyuen.github.io/articles/plic2#handle-the-interrupt)...

![Claim Interrupt](https://lupyuen.github.io/images/plic2-registers5.jpg)

And how we fetch the __RISC-V IRQ Number__ from the [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#claim-the-interrupt) Register: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L62)

```c
// Dispatch the RISC-V Interrupt
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs) {

  // Compute the (Interim) NuttX IRQ Number
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);

  // If this is an External Interrupt...
  if (RISCV_IRQ_EXT == irq) {

    // Read the RISC-V IRQ Number
    // From PLIC Claim Register
    // Which also Claims the Interrupt
    // PLIC_CLAIM is 0xE020_1004
    uintptr_t val = getreg32(PLIC_CLAIM);
```

_What happens when we run this?_

On Ox64 we see NuttX booting normally to the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-12.0.3
nsh>
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L294-L325)

When we __press a key__ on the Serial Console (to trigger a UART Interrupt)...

```text
riscv_dispatch_irq:
  claim=0
```

Our Interrupt Handler says that the __Interrupt Claim Register is 0__...

Which means we can't read the __RISC-V IRQ Number__!

We activate our Backup Plan...

![Pending Interrupts](https://lupyuen.github.io/images/plic2-registers6.jpg)

# Backup Plan

_What's our Backup Plan for Handling Interrupts?_

We can get the RISC-V IRQ Number by reading the [__Interrupt Pending__](https://lupyuen.github.io/articles/plic2#pending-interrupts) Register (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L62-L76)

```c
// If Interrupt Claimed is 0...
if (val == 0) {
  // Check the Pending Interrupts...
  // Read PLIC_IP0: Interrupt Pending for interrupts 1 to 31
  uintptr_t ip0 = getreg32(0xe0001000);

  // If Bit 20 is set...
  if (ip0 & (1 << 20)) {
    // Then UART3 Interrupt was fired (RISC-V IRQ 20)
    val = 20;
  }
}

// Compute the Actual NuttX IRQ Number:
// RISC-V IRQ Number + 25 (RISCV_IRQ_EXT)
irq += val;

// Omitted: Call the Interrupt Handler
// and Complete the Interrupt
```

Which tells us the correct __RISC-V IRQ Number__ for UART3 yay!

```text
riscv_dispatch_irq:
  irq=45
```

(__NuttX IRQ 45__ means __RISC-V IRQ 20__)

Don't forget to __clear the Pending Interrupts__: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L94-L101)

```c
// Clear the Pending Interrupts
// TODO: Clear the Individual Bits instead of wiping out the Entire Register
putreg32(0, 0xe0001000);  // PLIC_IP0: Interrupt Pending for interrupts 1 to 31
putreg32(0, 0xe0001004);  // PLIC_IP1: Interrupt Pending for interrupts 32 to 63

// Dump the Pending Interrupts
infodumpbuffer("PLIC Interrupt Pending", 0xe0001000, 2 * 4);

// Yep works great, Pending Interrupts have been cleared...
// PLIC Interrupt Pending (0xe0001000):
// 0000  00 00 00 00 00 00 00 00                          ........        
```

_Does it work for UART Input?_

Since we've correctly identified the IRQ Number, [__riscv_dispatch_irq__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105) will (eventually) call [__bl602_receive__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L859-L904) to read the UART Input (pic below)...

```text
bl602_receive: rxdata=-1
bl602_receive: rxdata=0x0
```

But the [__UART Input is empty__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L892-L901)! We need to troubleshoot our UART Driver some more.

Meanwhile we wrap up our story for today...

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L294-L325)

[(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

![NuttX boots OK on Ox64 BL808! But UART Input is null](https://lupyuen.github.io/images/plic2-run.png)

# All Things Considered

_Feels like we're wading into murky greyish territory... Like Jaws meets Twilight Zone on the Beach?_

Yeah we said this [__last time__](https://lupyuen.github.io/articles/ox2#begin-with-star64-nuttx), and it's happening now...

> _"If RISC-V ain't RISC-V on SiFive vs T-Head: We'll find out!"_

The PLIC Code in this article was __originally tested OK__ with...

- [__StarFive JH7110 SoC__](https://lupyuen.github.io/articles/plic) in RISC-V Supervisor Mode

  (Based on SiFive U74 Core)

- [__T-Head C906 Core__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/c906/c906_irq.c) in RISC-V Machine Mode

  (Ox64 BL808 runs on the C906 Core)

- But NOT __T-Head C906__ in __RISC-V Supervisor Mode__

  (Which might explain our troubles)

Today we're hitting 2 Strange Issues in the __BL808 (C906) PLIC__...

- [__Leaky Writes__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) to PLIC Registers

  (Writing to one register will affect the next)

- [__PLIC Claim Register__](https://lupyuen.github.io/articles/plic2#more-trouble-with-interrupt-claim) always reads as 0

  (Instead of RISC-V External Interrupt Number)

Which shouldn't happen because PLIC is in the [__Official RISC-V Spec__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#plic)! So many questions...

1.  _Any clue what's causing this?_

    The __Leaky Writes__ don't seem to happen [__before enabling the MMU__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L282-L298) (Memory Management Unit)...

    ```text
    // Before enabling Memory Mgmt Unit...
    jh7110_mm_init: Test Interrupt Priority

    // No Leaky Writes!
    test_interrupt_priority:
      before50=0, before54=0
      after50=1,  after54=0

    // Leaky Writes after enabling Memory Mgmt Unit
    jh7110_kernel_mppings: map I/O regions
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L118-L120)

    So it might be a problem with our MMU Settings.

    [(More about __Memory Management Unit__)](https://lupyuen.github.io/articles/mmu)

    [(__U-Boot Bootloader__ doesn't have Leaky Writes)](https://github.com/lupyuen/nuttx-ox64#strangeness-in-ox64-bl808-plic)

1.  _What if we configure the MMU differently?_

    We moved the PLIC from [__Level 2 Page Tables__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L249-L258) up to [__Level 1__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L240-L245)...

    Same problem.

1.  _Something special about the C906 MMU?_

    According to the [__C906 User Manual__](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf) (Page 53), the C906 MMU supports __Extended Page Attributes__. Which might affect us?

    [(More about __C906 Extended Page Attributes__)](https://github.com/lupyuen/nuttx-ox64#strangeness-in-ox64-bl808-plic)

1.  _What about the C906 PLIC?_

    According to the [__Linux PLIC Driver__](https://lore.kernel.org/lkml/CAJF2gTS8Z+6Ewy0D5+0X_h2Jz4BqsJp7wEC5F0iNaDsSpiE2aw@mail.gmail.com/)...

    "The T-HEAD C9xx SoC implements a modified/custom T-HEAD PLIC
    specification which will mask current IRQ upon read to CLAIM register
    and will unmask the IRQ upon write to CLAIM register"

    Will this affect our Interrupt Claim?

    [(More about __C906 PLIC__)](https://github.com/lupyuen/nuttx-ox64#uart-interrupt-for-ox64-bl808)

1.  _Maybe the GCC Compiler didn't generate the right code?_

    We wrote [__RISC-V Assembly__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L487-L531), disabling [__DCACHE / ICACHE__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L531-L608) and with [__SFENCE__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e76886a665fb9b8fe4f52c25e2f80877a62f415c/arch/risc-v/src/jh7110/bl602_serial.c#L446-L489).

    Still the same.

1.  _Perhaps our problem is Leaky Reads? Not Leaky Writes?_

    Hmmm... Perhaps!

Can we finish our Sad Story with a Happier Conclusion? Please lemme know! 🙏

# What's Next

TODO: Today we talked about __Interrupting Chickens__ and __Ox64 BL808 SBC__...

We'll do much more for __NuttX on Ox64 BL808__, stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/plic2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/plic2.md)

# Appendix: UART Driver for Ox64

_How did we create the NuttX UART Driver for Ox64 BL808?_

Today NuttX supports the 32-bit predecessor of BL808: [__Bouffalo Lab BL602__](https://github.com/apache/nuttx/tree/master/arch/risc-v/src/bl602).

When we compare these UARTs...

- __BL808 UART Controller__

  [(__BL808 Reference Manual__, Page 402)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

- __BL602 UART Controller__

  [(__BL602 Reference Manual__, Page 126)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

We discover that BL808 UART works the __same way as BL602__!

Thus we'll simply copy the [__NuttX Driver for BL602 UART__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_serial.c) to Ox64.

Here's the UART Driver __ported to BL808__: [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c)

_What did we change?_

We hardcoded the __UART3 Base Address__: [bl602_uart.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/hardware/bl602_uart.h#L30-L41)

```c
// UART3 Base Address
#define BL602_UART0_BASE   0x30002000
#define BL602_UART_BASE(n) (BL602_UART0_BASE)
```

We fixed the __NuttX Start Code__ to call our new UART Driver: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_start.c#L175-L184)

```c
// At Startup, init the new UART Driver
void riscv_earlyserialinit(void) {
  bl602_earlyserialinit();
}

// Same here
void riscv_serialinit(void) {
  bl602_serialinit();
}
```

And the UART Driver works OK for printing output to the Ox64 Serial Console! (But not for input, pic below)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L112-L325)

[(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

![NuttX boots OK on Ox64 BL808! But UART Input is null](https://lupyuen.github.io/images/plic2-run.png)

# Appendix: Build and Run NuttX

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__, with PLIC partially working.

(Console Input is not yet fixed)

This is how we download and build NuttX for Ox64 BL808 SBC...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch ox64b \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch ox64b \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Build NuttX
cd nuttx
tools/configure.sh star64:nsh
make

## Export the NuttX Kernel
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

[(And enable __Scheduler Info Output__)](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

Then we build the __Initial RAM Disk__ that contains NuttX Shell and NuttX Apps...

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image
```

[(See the __Build Script__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

[(Why the __64 KB Padding__)](https://lupyuen.github.io/articles/app#pad-the-initial-ram-disk)

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

Then we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Overwrite the microSD Linux Image by the __NuttX Kernel__...

```bash
## Overwrite the Linux Image
## on Ox64 microSD
cp Image \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH). (Pic above)

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L112-L325)

[(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

![Drawing the Platform-Level Interrupt Controller for Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/plic2-draw.jpg)
