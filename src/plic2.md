# RISC-V Ox64 BL808 SBC: UART Interrupt and Platform-Level Interrupt Controller (PLIC)

📝 _7 Dec 2023_

![TODO](https://lupyuen.github.io/images/plic2-registers.jpg)

> _"It’s time for the little red chicken’s bedtime story - and a reminder from Papa to try not to interrupt. But the chicken can’t help herself!"_

> — ["Interrupting Chicken"](https://share.libbyapp.com/title/4190211)

Our Story today is all about __RISC-V Interrupts__ on the tiny [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) 64-bit Single-Board Computer (pic below)...

- What's inside the __Platform-Level Interrupt Controller__ (PLIC)

- __Setting up the PLIC__ at startup

- __Enabling the PLIC Interrupt__ for UART Input

- __Handling PLIC Interrupts__ for UART

We'll walk through the steps with a simpler operating system: [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

Though we'll hit a bumpy journey with our work-in-progress __NuttX on Ox64__...

- __Leaky Writes__ seem to be affecting adjacent PLIC Registers

- __Interrupt Claim__ doesn't seem to be working right

We begin our story...

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sd.jpg)

# Platform-Level Interrupt Controller

_What's this PLIC?_

TODO: PLIC doc

(__IRQ__ means Interrupt Request Number)

NuttX IRQ Number = 25 + RISC-V IRQ Number

NuttX reserves a bunch of IRQ Numbers for Internal Use. Hence the Offset of 25.

![BL808 Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-bl808a.jpg)

# UART Interrupt

TODO

![BL808 UART3 Interrupt](https://lupyuen.github.io/images/plic2-irq.jpg)

# Initialise the Interrupts

TODO

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

[(__PLIC_ENABLE__ and other PLIC Offsets are defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/hardware/jh7110_plic.h#L34-L49)

[(NuttX calls __up_irqinitialize__ at startup)](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

Hence at startup, all PLIC Interrupts are disabled until we __enable them later__ (in PLIC).

![Clear Interrupts](https://lupyuen.github.io/images/plic2-registers5a.jpg)

## Clear the Interrupts

Next we __Claim and Complete__ the Outstanding Interrupts (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L61-L68)

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

Finally we set the PLIC __Interrupt Threshold__ to 0 (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L90-L114)

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

Suppose we're enabling __RISC-V IRQ 20__ for UART3 Interrupts.

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

And PLIC will happily accept RISC-V IRQ 20 whenever we press a key! (On the Serial Console, pic above)

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

__"Hart"__ is a RISC-V CPU Core. ("Hardware Thread")

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

Now we head back to our (interrupted) story...

![Handle Interrupt](https://lupyuen.github.io/images/plic2-registers4.jpg)

# Handle the Interrupt

_What happens when we press a key on the Serial Console? (Pic above)_

_How will PLIC handle the UART Interrupt?_

TODO

![Claim Interrupt](https://lupyuen.github.io/images/plic2-registers5.jpg)

## Claim the Interrupt

_How will we know which RISC-V Interrupt has been fired?_

That's why we have the __Interrupt Claim__ Register! (Pic above)

We read the Interrupt Claim Register to get the __RISC-V IRQ Number__ that has been fired: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

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
    uintptr_t val = getreg32(PLIC_CLAIM);

    // Compute the Actual NuttX IRQ Number:
    // RISC-V IRQ Number + 25 (RISCV_IRQ_EXT)
    irq += val;
  }
  // Up Next: Dispatch and Complete the Interrupt
```

_What exactly are we "claiming"?_

When we [__Claim an Interrupt__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#interrupt-claims) (by reading the Interrupt Claim Register)...

We're telling the PLIC: "Yes we acknowledge the Interrupt, but we're not done yet!"

In a while we shall Complete the Interrupt.

TODO: How NuttX calls __riscv_dispatch_irq__

TODO: Why claim? Multiple CPUs

## Dispatch the Interrupt

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

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

TODO: riscv_doirq

## Complete the Interrupt

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

```c
  // Omitted: Claim and Dispatch the Interrupt
  ...
  // If this is an External Interrupt...
  if (RISCV_IRQ_EXT <= irq) {

    // Compute the RISC-V IRQ Number
    // and Complete the Interrupt.
    putreg32(
      irq - RISCV_IRQ_EXT,  // RISC-V IRQ Number (RISCV_IRQ_EXT = 25)
      PLIC_CLAIM            // PLIC Claim (Complete) Register
    );
  }

  // Return the Registers to the Caller
  return regs;
}
```

TODO

![Pending Interrupts](https://lupyuen.github.io/images/plic2-registers6.jpg)

## Pending Interrupts

_What's with the Pending Interrupts? (Pic above)_

TODO: Normally the Claim / Complete is perfectly adequate for handling interrupts 

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

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

TODO: Backup Plan

```c
// Clear the Pending Interrupts...
// Set PLIC_IP0: Interrupt Pending for interrupts 1 to 31
putreg32(0, 0xe0001000);

// TODO: Clear the Individual Bits instead of wiping out the Entire Register
```

![Set Interrupt Priority](https://lupyuen.github.io/images/plic2-registers1.jpg)

# Trouble with Interrupt Priority

TODO

Earlier we said that we initialise the __Interrupt Priorities to 1__ at startup: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L75C1-L90)

```c
// Init the Platform-Level Interrupt Controller
void up_irqinitialize(void) {
  ...
  // Set Priority for all External Interrupts to 1 (Lowest)
  for (int id = 1; id <= NR_IRQS; id++) {
    putreg32(
      1,  // Value
      (uintptr_t)(PLIC_PRIORITY + 4 * id)  // Address
    );
  }

  // Dump the Interrupt Priorities
  infodumpbuffer("PLIC Interrupt Priority: After", 0xe0000004, 0x50 * 4);
```

When we run this on Ox64, something strange happens...

```text
PLIC Interrupt Priority: After (0xe0000004):
0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L150-L170)

_Everything becomes zero! Why???_

Yeah this is totally baffling! And no Interrupts get fired, because __Interrupt Priority 0 is invalid__.

Let's set the Interrupt Priority specifically for __RISC-V IRQ 20__ (UART3 Interrupt): [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L444-L465)

```c
// Test the setting of PLIC Interrupt Priority
// For RISC-V IRQ 20 only
void test_interrupt_priority(void) {
  // Read the values before setting Interrupt Priority
  uint32_t before50 = *(volatile uint32_t *) 0xe0000050UL;  // RISC-V IRQ 20
  uint32_t before54 = *(volatile uint32_t *) 0xe0000054UL;  // RISC-V IRQ 21

  // Set the Interrupt Priority
  // for 0x50 but NOT 0x54
  *(volatile uint32_t *) 0xe0000050UL = 1;

  // Read the values after setting Interrupt Priority
  uint32_t after50 = *(volatile uint32_t *) 0xe0000050UL;  // RISC-V IRQ 20
  uint32_t after54 = *(volatile uint32_t *) 0xe0000054UL;  // RISC-V IRQ 21

  // Dump before and after values:
  _info("before50=%u, before54=%u, after50=%u, after54=%u\n",
    before50, before54, after50, after54);
}
```

Again we get odd results...

```text
before50=0, before54=0
after50=1,  after54=1
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L257)

IRQ 20 is set correctly. But __IRQ 21 is also set__! (Pic below)

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

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L194-L198)

Thus we have an unexplained problem of __Leaky Writes__, affecting the Interrupt Priority and Interrupt Enable Registers.

Up next, we have more worries...

![TODO](https://lupyuen.github.io/images/plic2-title.jpg)

# More Trouble with Interrupt Claim

TODO

We talked earlier about __Handling Interrupts__...

![Claim Interrupt](https://lupyuen.github.io/images/plic2-registers5.jpg)

And how we fetch the __RISC-V IRQ Number__ from the __Interrupt Claim__ Register: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

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
    uintptr_t val = getreg32(PLIC_CLAIM);
```

_What happens when we run this?_

On Ox64 we see NuttX booting normally to the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-12.0.3
nsh>
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L293-L308)

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

_We have a Backup Plan for Handling Interrupts?_

Our Backup Plan is to figure out the IRQ Number by reading the __Interrupt Pending__ Register (pic above): [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

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
  }

  // Omitted: Call the Interrupt Handler
  // and Complete the Interrupt
```

Which tells us the __RISC-V IRQ Number__ yay!

```text
riscv_dispatch_irq:
  irq=45
```

(__NuttX IRQ 45__ means __RISC-V IRQ 20__)

Don't forget the __clear the Pending Interrupts__: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L48-L105)

```c
  // Clear the Pending Interrupts
  putreg32(0, 0xe0001000);  // PLIC_IP0: Interrupt Pending for interrupts 1 to 31
  putreg32(0, 0xe0001004);  // PLIC_IP1: Interrupt Pending for interrupts 32 to 63

  // Dump the Pending Interrupts
  infodumpbuffer("PLIC Interrupt Pending", 0xe0001000, 2 * 4);

  // Yep works great, Pending Interrupts have been cleared...
  // PLIC Interrupt Pending (0xe0001000):
  // 0000  00 00 00 00 00 00 00 00                          ........        
```

TODO

```text
bl602_receive: rxdata=-1
bl602_receive: rxdata=0x0
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L293-L308)

TODO: Screenshot

# All Things Considered

_Feels like we're wading into murky greyish territory... Like Jaws meets Twilight Zone on the Beach?_

Yeah we said this [__last time__](https://lupyuen.github.io/articles/ox2#begin-with-star64-nuttx) and it's happening now...

> "If RISC-V ain't RISC-V on SiFive vs T-Head: We'll find out!"

The PLIC Code in this article was __originally tested OK__ with...

- [__StarFive JH7110 SoC__](https://lupyuen.github.io/articles/plic) in RISC-V Supervisor Mode

  (Based on SiFive U74 Core)

- [__T-Head C906 Core__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/c906/c906_irq.c) in RISC-V Machine Mode

  (Ox64 BL808 runs on the C906 Core)

- But NOT __T-Head C906__ in __RISC-V Supervisor Mode__

  (Which might explain our troubles)

Today we're hitting 2 strange issues in the __BL808 (C906) PLIC__...

- __Leaky Writes__ to PLIC Registers

  (Writing to one register will affect the next)

- __PLIC Claim Register__ always reads as 0

  (Instead of the RISC-V External Interrupt Number)

So many questions...

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

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5#file-ox64-nuttx-int-clear-pending-log-L116-L118)

    So it might be a problem with our MMU Settings.

    [(More about __Memory Management Unit__)](https://lupyuen.github.io/articles/mmu)

    [(__U-Boot Bootloader__ doesn't have Leaky Writes)](https://github.com/lupyuen/nuttx-ox64#strangeness-in-ox64-bl808-plic)

1.  _What if we configure the MMU differently?_

    We moved the PLIC from [__Level 2 Page Tables__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L249-L258) up to [__Level 1__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L240-L245)...

    Same problem.

1.  _Something special about the C906 MMU?_

    According to the [__C906 User Manual__](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)  (Page 53), the C906 MMU supports __Extended Page Attributes__. Which might affect us?

    [(More about __C906 Extended Page Attributes__)](https://github.com/lupyuen/nuttx-ox64#strangeness-in-ox64-bl808-plic)

1.  _What about the C906 PLIC?_

    According to the [__Linux PLIC Driver__](https://lore.kernel.org/lkml/CAJF2gTS8Z+6Ewy0D5+0X_h2Jz4BqsJp7wEC5F0iNaDsSpiE2aw@mail.gmail.com/)...

    > "The T-HEAD C9xx SoC implements a modified/custom T-HEAD PLIC
    specification which will mask current IRQ upon read to CLAIM register
    and will unmask the IRQ upon write to CLAIM register"

    Will this affect our Interrupt Claim?

    [(More about __C906 PLIC__)](https://github.com/lupyuen/nuttx-ox64#strangeness-in-ox64-bl808-plic)

1.  _Maybe the GCC Compiler didn't generate the right code?_

    We wrote [__RISC-V Assembly__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L487-L531) with [__DCACHE / ICACHE__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L531-L608) and [__SFENCE__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e76886a665fb9b8fe4f52c25e2f80877a62f415c/arch/risc-v/src/jh7110/bl602_serial.c#L446-L489).

    Still the same.

1.  _Perhaps our problem is Leaky Reads? Not Leaky Writes?_

    Hmmm... Perhaps!

# What's Next

TODO

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

# Appendix: NuttX UART Driver for Ox64

TODO

BL808 UART is mostly identical to BL602 UART, so we ported the NuttX BL602 UART Driver to BL808.

Here's the UART Driver ported to BL808: [bl602_serial.c] (https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/bl602_serial.c)

We hardcoded the UART3 Base Address: [bl602_uart.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/hardware/bl602_uart.h#L30-L41)

```c
#define BL602_UART0_BASE 0x30002000
#define BL602_UART_BASE(n) (BL602_UART0_BASE)
// Previously: #define BL602_UART_BASE(n)    (BL602_UART0_BASE + (n * (BL602_UART1_BASE - BL602_UART0_BASE)))
```

We fixed the NuttX Start Code to call our new UART Driver: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L175-L184)

```c
void riscv_earlyserialinit(void) {
  bl602_earlyserialinit();
}

void riscv_serialinit(void) {
  bl602_serialinit();
}
```

We disabled UART Interrupts for now: [bl602_attach and bl602_detach](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/bl602_serial.c#L377-L431)

And the UART Driver works! [(See the log)](https://gist.github.com/lupyuen/74a44a3e432e159c62cc2df6a726cb89)

TODO: /dev/ttyS0 is missing

TODO: Enable UART Interrupts

# Appendix: UART Interrupt for Ox64

TODO

Let's fix the UART Interrupts for NuttX on Ox64 BL808!

We fix the PLIC Offsets according to [C906 User Manual (Page 77)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

_What's the UART3 IRQ?_

From the Linux Device Tree...

```text
serial@30002000 {
  compatible = "bflb,bl808-uart";
  reg = <0x30002000 0x1000>;
  interrupts = <0x14 0x04>;
  clocks = <0x04>;
  status = "okay";
  phandle = <0x0a>;
};
```

Thus...

- RISC-V IRQ = 0x14 = 20

- UART3 Int = (IRQ_NUM_BASE + 4)

- IRQ_NUM_BASE = 16

- NuttX IRQ = 45 (Offset by RISCV_IRQ_EXT)

- RISCV_IRQ_EXT = 25
