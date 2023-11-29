# RISC-V Ox64 BL808 SBC: UART Interrupt and Platform-Level Interrupt Controller (PLIC)

📝 _7 Dec 2023_

![TODO](https://lupyuen.github.io/images/plic2-title.jpg)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) (Real-Time Operating System) for [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) 64-bit RISC-V SBC (pic below)...

TODO

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sd.jpg)

# Initialise Interrupts

TODO

![Disable Interrupts](https://lupyuen.github.io/images/plic2-registers3a.jpg)

## Disable Interrupts

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L49-L60)

```c
void up_irqinitialize(void) {
  /* Disable S-Mode interrupts */

  up_irq_save();

  /* Attach the common interrupt handler */

  //// TODO: riscv_exception_attach();

  /* Disable all global interrupts */

  putreg32(0x0, JH7110_PLIC_ENABLE1);
  putreg32(0x0, JH7110_PLIC_ENABLE2);
```

![Clear Interrupts](https://lupyuen.github.io/images/plic2-registers5a.jpg)

## Clear Interrupts

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L63-L66)

```c
  /* Clear pendings in PLIC */

  uintptr_t val = getreg32(JH7110_PLIC_CLAIM);
  putreg32(val, JH7110_PLIC_CLAIM);
```

![Set Interrupt Priority](https://lupyuen.github.io/images/plic2-registers1.jpg)

## Set Interrupt Priority

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L76-L85)

```c
  /* Set priority for all global interrupts to 1 (lowest) */

  int id;

  infodumpbuffer("PLIC Interrupt Priority: Before", 0xe0000004, 0x50 * 4); ////
  for (id = 1; id <= NR_IRQS; id++)
    {
      putreg32(1, (uintptr_t)(JH7110_PLIC_PRIORITY + 4 * id));
    }
  infodumpbuffer("PLIC Interrupt Priority: After", 0xe0000004, 0x50 * 4); ////
```

![Set Interrupt Threshold](https://lupyuen.github.io/images/plic2-registers2.jpg)

## Set Interrupt Threshold

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L87-L108)

```c
  /* Set irq threshold to 0 (permits all global interrupts) */

  putreg32(0, JH7110_PLIC_THRESHOLD);

  /* Attach the common interrupt handler */

  riscv_exception_attach(); //// TODO: Should move earlier

  /* And finally, enable interrupts */

  up_irq_enable();
```

![Enable Interrupt](https://lupyuen.github.io/images/plic2-registers3.jpg)

# Enable Interrupt

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq.c#L155-L199)

```c
/****************************************************************************
 * Name: up_enable_irq
 *
 * Description:
 *   Enable the IRQ specified by 'irq'
 *
 ****************************************************************************/

void up_enable_irq(int irq)
{
  _info("irq=%d\n", irq); ////
  int extirq;

  if (irq == RISCV_IRQ_SOFT)
    {
      /* Read sstatus & set software interrupt enable in sie */

      SET_CSR(CSR_IE, IE_SIE);
    }
  else if (irq == RISCV_IRQ_TIMER)
    {
      /* Read sstatus & set timer interrupt enable in sie */

      SET_CSR(CSR_IE, IE_TIE);
    }
  else if (irq > RISCV_IRQ_EXT)
    {
      extirq = irq - RISCV_IRQ_EXT;

      /* Set enable bit for the irq */

      if (0 <= extirq && extirq <= 63)
        {
          infodumpbuffer("PLIC Hart 0 S-Mode Interrupt Enable: Before", 0xe0002080, 2 * 4);////
          _info("extirq=%d, addr=%p, val=0x%d\n", extirq, (uintptr_t)JH7110_PLIC_ENABLE1 + (4 * (extirq / 32)), 1 << (extirq % 32)); ////
          modifyreg32(JH7110_PLIC_ENABLE1 + (4 * (extirq / 32)),
                      0, 1 << (extirq % 32));
          infodumpbuffer("PLIC Hart 0 S-Mode Interrupt Enable: After", 0xe0002080, 2 * 4);////
        }
      else
        {
          PANIC();
        }
    }
}
```

![Handle Interrupt](https://lupyuen.github.io/images/plic2-registers4.jpg)

# Handle Interrupt

TODO

[jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/jh7110_irq_dispatch.c#L52-L134)

```c
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs)
{
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);

  /* Firstly, check if the irq is machine external interrupt */

  if (RISCV_IRQ_EXT == irq)
    {
      uintptr_t val = getreg32(JH7110_PLIC_CLAIM);

      ////Begin
      if (val == 0) {
        // Check Pending Interrupts
        uintptr_t ip0 = getreg32(0xe0001000);  // PLIC_IP0: Interrupt Pending for interrupts 1 to 31
        uintptr_t ip1 = getreg32(0xe0001004);  // PLIC_IP1: Interrupt Pending for interrupts 32 to 63
        // if (ip1 & (1 << 20)) { val = 52; }  // EMAC
        if (ip0 & (1 << 20)) { val = 20; }  // UART
      }
      ////End

      /* Add the value to nuttx irq which is offset to the mext */

      irq += val;
    }

  /* EXT means no interrupt */

  if (RISCV_IRQ_EXT != irq)
    {
      /* Deliver the IRQ */

      // _info("Do irq=%d\n", irq);////
      regs = riscv_doirq(irq, regs);
    }

  if (RISCV_IRQ_EXT <= irq)
    {
      uintptr_t claim = getreg32(JH7110_PLIC_CLAIM);////
      /* Then write PLIC_CLAIM to clear pending in PLIC */

      putreg32(irq - RISCV_IRQ_EXT, JH7110_PLIC_CLAIM);
      ////Begin
      // Clear Pending Interrupts
      putreg32(0, 0xe0001000);  // PLIC_IP0: Interrupt Pending for interrupts 1 to 31
      putreg32(0, 0xe0001004);  // PLIC_IP1: Interrupt Pending for interrupts 32 to 63
      ////End
    }

  return regs;
}
```

![Claim Interrupt](https://lupyuen.github.io/images/plic2-registers5.jpg)

## Claim Interrupt

TODO

## Complete Interrupt

TODO

![Pending Interrupts](https://lupyuen.github.io/images/plic2-registers6.jpg)

## Pending Interrupts

TODO

![Registers for Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-registers.jpg)

# NuttX UART Driver for Ox64

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

# UART Interrupt for Ox64

TODO

![BL808 vs JH7110](https://lupyuen.github.io/images/plic2-bl808.jpg)

![BL808](https://lupyuen.github.io/images/plic2-bl808a.jpg)

![JH7110](https://lupyuen.github.io/images/plic2-bl808b.jpg)

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

We show the UART Interrupt Status...

```text
bl602_attach: BL602_UART_INT_STS=0x84
bl602_attach: BL602_UART_INT_MASK=0xfff
bl602_attach: BL602_UART_INT_CLEAR=0x0
bl602_attach: BL602_UART_INT_EN=0xfff
```

[(Source)](https://gist.github.com/lupyuen/c3f187af9f5c81594ddf8f854de2ed0a)

"urx_fer_int = 1" means "UART RX FIFO error interrupt, auto-cleared when FIFO overflow/underflow error flag is cleared"

We clear the RX FIFO Underflow, but still no UART Interrupts...

```text
bl602_attach: BL602_UART_FIFO_CONFIG_0=0x80
bl602_attach: BL602_UART_FIFO_CONFIG_0=0x8
```

We dump the PLIC and UART Registers in U-Boot...

```bash
## UART Registers
=> md 0x30002000 0x36
30002000: 00001705 00000701 00130013 00000000  ................
30002010: 009f0070 0000006f 0000000f 00000000  p...o..........
30002020: 00000012 00000fff 00000000 00000fff  ................
30002030: 00000001 00000000 00000000 00000000  ................
30002040: 00000000 00000000 00000003 00000000  ................
30002050: 0026ffff 00000002 00000000 00000000  ..&.............
30002060: 00000000 00000000 00000000 00000000  ................
30002070: 00000000 00000000 00000000 00000000  ................
30002080: 00000000 07070000 0000000a 00000078  ............x...
30002090: 00000000 00000000 00000000 00000000  ................
300020a0: 00000000 00000000 00000000 00000000  ................
300020b0: 00000000 00000000 00000000 00000000  ................
300020c0: 00000000 00000000 00000000 00000000  ................
300020d0: 00000000 00000000                    ........

## PLIC Interrupt Priority
=> md 0xe0000004 0x50
e0000004: 00000000 00000000 00000000 00000000  ................
e0000014: 00000000 00000000 00000000 00000000  ................
e0000024: 00000000 00000000 00000000 00000000  ................
e0000034: 00000000 00000000 00000000 00000000  ................
e0000044: 00000000 00000000 00000000 00000000  ................
e0000054: 00000000 00000000 00000000 00000000  ................
e0000064: 00000000 00000000 00000000 00000000  ................
e0000074: 00000000 00000000 00000000 00000000  ................
e0000084: 00000000 00000000 00000000 00000000  ................
e0000094: 00000000 00000000 00000000 00000000  ................
e00000a4: 00000000 00000000 00000000 00000000  ................
e00000b4: 00000000 00000000 00000000 00000000  ................
e00000c4: 00000000 00000000 00000000 00000000  ................
e00000d4: 00000000 00000000 00000000 00000000  ................
e00000e4: 00000000 00000000 00000000 00000000  ................
e00000f4: 00000000 00000000 00000000 00000000  ................
e0000104: 00000000 00000000 00000000 00000000  ................
e0000114: 00000000 00000000 00000000 00000000  ................
e0000124: 00000000 00000000 00000000 00000000  ................
e0000134: 00000000 00000000 00000000 00000000  ................

## PLIC Hart 0 S-Mode Interrupt Enable
=> md 0xe0002080 2
e0002080: 00000000 00000000                    ........

## PLIC Hart 0 S-Mode Priority Threshold
=> md 0xe0201000 2
e0201000: 00000007 00000000                    ........

## PLIC Hart 0 S-Mode Claim / Complete
=> md 0xe0201004 1
e0201004: 00000000                             ....

## Interrupt Pending
=> md 0xe0001000 2
e0001000: 00000000 00000000                    ........

## PLIC Hart 0 M-Mode Interrupt Enable
=> md 0xe0002000 2
e0002000: 00000000 00000000                    ........

## PLIC Hart 0 M-Mode Priority Threshold
=> md 0xe0200000 2
e0200000: 00000007 00000000                    ........

## PLIC Hart 0 M-Mode Claim / Complete
=> md 0xe0200004 1
e0200004: 00000000                             ....

## Doesn't work: PLIC permission control register
## md 0xe01ffffc 1
```

TODO: Why UART Interrupt not enabled? U-Boot and OpenSBI don't use UART Interrupts?

TODO: What is Priority Threshold 7?

But after enabling UART IRQ, PLIC Interrupt Priority is 0 and Invalid!

```text
PLIC Interrupt Priority (0xe0000004):
0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

We set PLIC Interrupt Priority to 1 ourselves...

```text
bl602_attach: Set PLIC Interrupt Priority to 1
PLIC Interrupt Priority (0xe0000004):
0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0040  00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00  ................
0050  01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ...............
00e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0130  00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00  ................
```

Then [IRQ 25 is OK yay!](https://gist.github.com/lupyuen/af6112c80db6907e5e5dec3519af53ff)

```text
riscv_dispatch_irq: irq=8
riscv_dispatch_irq: irq=8

NuttShell (NSH) NuttX-12.0.3
riscv_dispatch_irq: irq=25
riscv_dispatch_irq: irq=25
riscv_dispatch_irq: irq=25
```

But UART Interrupt can't be handled because [PLIC Claim is 0](https://gist.github.com/lupyuen/e1e6bf670ee4eefa0f968f1901407419)...

```text
riscv_dispatch_irq: Do irq=8
NuttShell (NSH) NuttX-12.0.3
riscv_dispatch_irq: irq=25, claim=0
riscv_dispatch_irq: *0xe0201004=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        
```

_Why is PLIC Claim = 0?_

This means that there are no External Interrupts triggered. So NuttX does nothing, again and again, till it becomes too busy to respond.

But Interrupt Pending is actually set for 2 External Interrupts!

_What are the 2 Interrupts Pending?_

```text
PLIC Interrupt Pending (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        
```

- (0xe0001000) PLIC_IP0: Interrupt Pending for interrupts 1 to 31

  0x100000 = (1 << 20) = IRQ 20 (UART3)

- (0xe0001004) PLIC_IP1: Interrupt Pending for interrupts 32 to 63

  0x100000 = (1 << 20) = IRQ 52 (EMAC2)

  TODO: Why EMAC2? We didn't enable the interrupt

We [handle Interrupt Pending](https://gist.github.com/lupyuen/84959d9ba79498a13a759b5b86c6fa29) ourselves...

```text
riscv_dispatch_irq: irq=25, claim=0
riscv_dispatch_irq: *0xe0201004=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        
riscv_dispatch_irq: Do irq=45
After Claim (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        

riscv_dispatch_irq: irq=25, claim=0
riscv_dispatch_irq: *0xe0201004=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        
riscv_dispatch_irq: Do irq=45
After Claim (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........
```

"Do IRQ" now works! But Interrupt Pending is not cleared, after we Claimed the interrupt.

_Doesn't NuttX already implement C906 PLIC?_

Yep but for Machine Mode only...

- [c906_irq.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/c906/c906_irq.c)

- [c906_irq_dispatch.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/c906/c906_irq_dispatch.c)

_What if we copy this code into Ox64 PLIC?_

```c
// From arch/risc-v/src/c906/c906_irq.c
/* Clear pendings in PLIC */
uintptr_t val = getreg32(JH7110_PLIC_CLAIM);
putreg32(val, JH7110_PLIC_CLAIM);
```

Still the same, Claim = 0...

```text
riscv_dispatch_irq: irq=25, claim=0
riscv_dispatch_irq: *0xe0201004=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 10 00 00 00 10 00                          ........        
```

_Something special about T-Head C906 PLIC?_

According to the Linux Device Tree, Ox64 uses this PLIC Driver: "thead,c900-plic"

```text
interrupt-controller@e0000000 {
  compatible = "thead,c900-plic";
```

Then from this [Linux Patch](https://lore.kernel.org/lkml/CAJF2gTS8Z+6Ewy0D5+0X_h2Jz4BqsJp7wEC5F0iNaDsSpiE2aw@mail.gmail.com/)

> "The T-HEAD C9xx SoC implements a modified/custom T-HEAD PLIC
specification which will mask current IRQ upon read to CLAIM register
and will unmask the IRQ upon write to CLAIM register. The
thead,c900-plic compatible string represents the custom T-HEAD PLIC
specification."

"thead,c900-plic" is implemented in Linux here: [irq-sifive-plic.c](https://github.com/torvalds/linux/blob/master/drivers/irqchip/irq-sifive-plic.c#L574-L582)

Which sets [PLIC_QUIRK_EDGE_INTERRUPT](https://github.com/torvalds/linux/blob/master/drivers/irqchip/irq-sifive-plic.c#L64), which is used by...

- [plic_irq_set_type](https://github.com/torvalds/linux/blob/master/drivers/irqchip/irq-sifive-plic.c#L212-L235)

- [plic_irq_domain_translate](https://github.com/torvalds/linux/blob/master/drivers/irqchip/irq-sifive-plic.c#L312-L325)

  Which calls [irq_domain_translate_twocell](https://github.com/torvalds/linux/blob/master/kernel/irq/irqdomain.c#L1060-L1081)

  (Instead of the normal [irq_domain_translate_onecell](https://github.com/torvalds/linux/blob/master/kernel/irq/irqdomain.c#L1043-L1060))

_What does it do?_

From another [Linux Patch](https://lore.kernel.org/all/20220630100241.35233-3-samuel@sholland.org/)

> The Renesas RZ/Five SoC has a RISC-V AX45MP AndesCore with NCEPLIC100. The
NCEPLIC100 supports both edge-triggered and level-triggered interrupts. In
case of edge-triggered interrupts NCEPLIC100 ignores the next interrupt
edge until the previous completion message has been received and
NCEPLIC100 doesn't support pending interrupt counter, hence losing the
interrupts if not acknowledged in time.

> So the workaround for edge-triggered interrupts to be handled correctly
and without losing is that it needs to be acknowledged first and then
handler must be run so that we don't miss on the next edge-triggered
interrupt.

TODO: Fix this for Ox64 NuttX

After Clearing the Pending Interrupts, [NuttX responds to Key Presses yay!](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5)

```text
NuttShell (NSH) NuttX-12.0.3
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
nsh> riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
nx_start: CPU0: Beginning Idle Loop
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
ˇriscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........ 
```

But Claim is still 0 though.

TODO: Key press not read correctly

TODO: Why is up_irqinitialize not setting Interrupt Priority properly? Signed arithmetic? Or delay?

# Strangeness in Ox64 PLIC

TODO

_PLIC in Ox64 BL808 is acting really strange..._

_Why is Interrupt Priority set for 4 Interrupts, when we only set 1 (for UART)?_

```text
bl602_attach: Set PLIC Interrupt Priority to 1
PLIC Interrupt Priority (0xe0000004):
...
0040  00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00  ................
0050  01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
```

_Maybe it's a problem with the RISC-V Code generated by GCC?_

Let's do a simple test: [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/jh7110/bl602_serial.c#L447-L473)

```c
// Test the setting of PLIC Interrupt Priority
void test_interrupt_priority(void) {
  static uint32_t before1 = 0xFF;
  static uint32_t before2 = 0xFF;
  static uint32_t after1 = 0xFF;
  static uint32_t after2 = 0xFF;

  // Read the values before setting Interrupt Priority
  before1 = *(volatile uint32_t *) 0xe0000050UL;
  before2 = *(volatile uint32_t *) 0xe0000054UL;

  // Set the Interrupt Priority
  *(volatile uint32_t *) 0xe0000050UL = 1;

  // Read the values after setting Interrupt Priority
  after1 = *(volatile uint32_t *) 0xe0000050UL;
  after2 = *(volatile uint32_t *) 0xe0000054UL;
  _info("before1=%u, before2=%u, after1=%u, after2=%u\n", before1, before2, after1, after2);
}
```

The Interrupt Priority [wasn't be set correctly](https://gist.github.com/lupyuen/4e8ca1f0c0c2bd3b22a8b63f098abdd5). Why did 0xe0000054 change from 0 to 1?

```text
bl602_attach: Test Interrupt Priority
test_interrupt_priority: before1=0, before2=0, after1=1, after2=1
```

Here's the Disassembly, which looks OK...

```text
0000000050200daa <test_interrupt_priority>:
test_interrupt_priority():
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:451
  uint32_t before1 = *(volatile uint32_t *) 0xe0000050;
    50200daa:	461d                	li	a2,7
    50200dac:	0676                	slli	a2,a2,0x1d

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:454
  *(volatile uint32_t *) 0xe0000050 = 1;
    50200dae:	4785                	li	a5,1

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:451
  uint32_t before1 = *(volatile uint32_t *) 0xe0000050;
    50200db0:	4a34                	lw	a3,80(a2)

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:452
  uint32_t before2 = *(volatile uint32_t *) 0xe0000054;
    50200db2:	4a78                	lw	a4,84(a2)

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:454
  *(volatile uint32_t *) 0xe0000050 = 1;
    50200db4:	ca3c                	sw	a5,80(a2)

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:457
  uint32_t after1 = *(volatile uint32_t *) 0xe0000050;
    50200db6:	4a3c                	lw	a5,80(a2)

/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:458
  uint32_t after2 = *(volatile uint32_t *) 0xe0000054;
    50200db8:	05462803          	lw	a6,84(a2)
```

_Maybe we need to flush the CPU Cache?_

Nope `sfence` doesn't help...

```text
0000000050200daa <test_interrupt_priority>:
test_interrupt_priority():
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:451
  uint32_t before1 = *(volatile uint32_t *) 0xe0000050;
    50200daa:	461d                	li	a2,7
    50200dac:	0676                	slli	a2,a2,0x1d
    50200dae:	4a34                	lw	a3,80(a2)
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:452
  uint32_t before2 = *(volatile uint32_t *) 0xe0000054;
    50200db0:	4a78                	lw	a4,84(a2)
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:455
  *(volatile uint32_t *) 0xe0000050 = 1;
    50200db2:	4785                	li	a5,1
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:451
  uint32_t before1 = *(volatile uint32_t *) 0xe0000050;
    50200db4:	2681                	sext.w	a3,a3
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:452
  uint32_t before2 = *(volatile uint32_t *) 0xe0000054;
    50200db6:	2701                	sext.w	a4,a4
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:455
  *(volatile uint32_t *) 0xe0000050 = 1;
    50200db8:	ca3c                	sw	a5,80(a2)
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:458
  __asm__ __volatile__
    50200dba:	12000073          	sfence.vma
    50200dbe:	0330000f          	fence	rw,rw
    50200dc2:	0000100f          	fence.i
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:467
  uint32_t after1 = *(volatile uint32_t *) 0xe0000050;
    50200dc6:	4a3c                	lw	a5,80(a2)
    50200dc8:	2781                	sext.w	a5,a5
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:469
  __asm__ __volatile__
    50200dca:	12000073          	sfence.vma
    50200dce:	0330000f          	fence	rw,rw
    50200dd2:	0000100f          	fence.i
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:477
  uint32_t after2 = *(volatile uint32_t *) 0xe0000054;
    50200dd6:	05462803          	lw	a6,84(a2)
    50200dda:	2801                	sext.w	a6,a6
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/bl602_serial.c:479
  __asm__ __volatile__
    50200ddc:	12000073          	sfence.vma
    50200de0:	0330000f          	fence	rw,rw
    50200de4:	0000100f          	fence.i
```

Let's do the same with U-Boot Bootloader. It looks OK, doesn't have the same problem...

```bash
## Read the values before setting Interrupt Priority
=> md 0xe0000050 1
e0000050: 00000000                             ....
=> md 0xe0000054 1
e0000054: 00000000                             ....

## Set the Interrupt Priority
=> mw 0xe0000050 0x01 1

## Read the values after setting Interrupt Priority
=> md 0xe0000050 1
e0000050: 00000001                             ....
=> md 0xe0000054 1
e0000054: 00000000                             ....
```

And U-Boot doesn't use MMU.

_Could it be caused by MMU?_

Let's try setting Interrupt Priority before MMU Init. It works OK!

```text
123jh7110_copy_ramdisk: _edata=0x50400258, _sbss=0x504002a0, _ebss=0x50408000, JH7110_IDLESTACK_TOP=0x50408c00
jh7110_copy_ramdisk: ramdisk_addr=0x50410291
jh7110_copy_ramdisk: size=8192000
ABCjh7110_mm_init: Test Interrupt Priority
test_interrupt_priority: before1=0, before2=0, after1=1, after2=0
jh7110_kernel_mappings: map I/O regions
```

When we set Interrupt Priority after MMU Init, it looks incorrect...

```text
123jh7110_copy_ramdisk: _edata=0x50400258, _sbss=0x504002a0, _ebss=0x50408000, JH7110_IDLESTACK_TOP=0x50408c00
jh7110_copy_ramdisk: ramdisk_addr=0x50410291
jh7110_copy_ramdisk: size=8192000
ABCjh7110_kernel_mappings: map I/O regions
jh7110_kernel_mappings: map PLIC as Interrupt L2
jh7110_kernel_mappings: connect the L1 and Interrupt L2 page tables for PLIC
jh7110_kernel_mappings: map kernel text
jh7110_kernel_mappings: map kernel data
jh7110_kernel_mappings: connect the L1 and L2 page tables
jh7110_kernel_mappings: map the page pool
mmu_satp_reg: pgbase=0x50407000, asid=0x0, reg=0x8000000000050407
mmu_write_satp: reg=0x8000000000050407
jh7110_mm_init: Test Interrupt Priority
test_interrupt_priority: before1=0, before2=0, after1=0, after2=0
nx_start: Entry
```

So it's an MMU problem!

_Why is MMU messing up our updates to Ox64 BL808 PLIC?_

We might have missed something specific to C906 MMU. Here are the Extended Page Attributes, from [C906 User Manual (Page 53)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

- __SO – Strong order__ (Bit 63)

  Indicates the access order required by memory.

  0: no strong order (Normal-memory)

  1: strong order (Device)

  The default value is no strong order.

- __C – Cacheable__ (Bit 62)

  0: Non-cacheable

  1: Cacheable

  The default value is Non-cacheable.

- __B – Buffer__ (Bit 61)

  0: Non-bufferable

  1: Bufferable

  The default value is Non-bufferable

Also...

> "C906 extended page attributes exist only when the MAEE bit in the MXSTATUS register is 1."

TODO: Set MAEE Bit in MXSTATUS Register

TODO: [d0_lowload Boot Code](https://github.com/openbouffalo/OBLFR/blob/master/apps/d0_lowload/src/rv32i_xtheade_lz4.S) doesn't set MXSTATUS

TODO: Set Strong Order (Bit 63) in MMU Page Table Entries. Retest the setting of PLIC Interrupt Priority

_What if we disable and re-enable MMU, while setting PLIC Interrupt Priority?_

Yep seems to work...

```text
jh7110_mm_init: Disable MMU
mmu_write_satp: reg=0
jh7110_mm_init: Test Interrupt Priority
test_interrupt_priority: before1=0, before2=0, after1=1, after2=0
jh7110_mm_init: Enable MMU
```

# T-Head vs SiFive

TODO

_Feels like we're wading into murky greyish brackish territory... Like Jaws meets Twilight Zone on the Beach..._

Yeah we said last time

Sv39 and PLIC are officially speced

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

![TODO](https://lupyuen.github.io/images/plic2-draw.jpg)
