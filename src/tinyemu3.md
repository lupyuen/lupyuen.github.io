# Automated Testing with Ox64 BL808 Emulator (Apache NuttX RTOS)

📝 _29 Jan 2024_

![Automated Testing with Ox64 BL808 Emulator (Apache NuttX RTOS)](https://lupyuen.github.io/images/tinyemu3-title.png)

_Every day we're auto-building Apache NuttX RTOS for Ox64 BL808 SBC..._

_Can we test NuttX on Ox64 automatically after building?_

Yes we can! With a little help from the __Ox64 BL808 Emulator__ that we created last week...

- [__"Emulate Ox64 BL808 in the Web Browser: Experiments with TinyEMU RISC-V Emulator and Apache NuttX RTOS"__](https://lupyuen.github.io/articles/tinyemu2)

_But our Ox64 Emulator was incomplete?_

Today we fill in the missing pieces of our Ox64 Emulator and call it for __Automated Testing__...

- We boot NuttX in __Supervisor Mode__

  (Instead of Machine Mode)

- Emulate OpenSBI for setting the __System Timer__

  (And read the System Time)

- Emulate the UART Interrupts for __Console Input__

  (By modding the VirtIO Console)

- Execute everything with __Expect Scripting__

  (TODO)

- Which becomes our __Daily Automated Testing__

  (Triggered every day by GitHub Actions)

We begin with the easier bit: Scripting our Ox64 Emulator...

![Ox64 BL808 Emulator runs in a Web Browser too](https://lupyuen.github.io/images/tinyemu2-title.png)

[_Ox64 BL808 Emulator runs in a Web Browser too_](https://lupyuen.github.io/nuttx-tinyemu/timer)

# Scripting The Expected

_What's this "Expect Scripting"?_

__`expect`__ is a cool Command-Line Tool that sends commands to another app and checks the responses.

_How is it used for Automated Testing?_

Normally when we start our Ox64 Emulator, it boots NuttX and __waits for our command__...

```text
## Start our Ox64 Emulator with NuttX
$ ./temu nuttx.cfg

TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh>
```

[(__nuttx.cfg__ is our __TinyEMU Config__)](https://github.com/lupyuen/nuttx-ox64/blob/main/nuttx.cfg)

With an __Expect Script__, we can __feed our commands automatically__ into the Emulator!

```text
## Run our Expect Script...
$ ./nuttx.exp

## Which starts the Ox64 Emulator...
spawn ./temu nuttx.cfg

  ## And sends a Command to the Emulator
  nsh> uname -a
  NuttX 12.4.0-RC0 55ec92e181 Jan 24 2024 00:11:08 risc-v ox64
  nsh> 
```

That's why we create an Expect Script to test Ox64 NuttX.

_What's nuttx.exp?_

That's our __Expect Script__ containing the commands that will be sent to our Emulator: [nuttx.exp](https://github.com/lupyuen/nuttx-ox64/blob/main/nuttx.exp)

```bash
#!/usr/bin/expect
## Expect Script for Testing NuttX with Ox64 BL808 Emulator

## For every 1 character sent, wait 0.001 milliseconds
set send_slow {1 0.001}

## Start the Ox64 BL808 Emulator
spawn ./temu nuttx.cfg

## Wait for the prompt and enter `uname -a`
## `send -s` will send slowly (0.001 ms per char)
expect "nsh> "
send -s "uname -a\r"
```

_Will it work for complicated tests?_

Yep we may use __Pattern Matching__ and __Timeout Detection__ in our script: [nuttx.exp](https://github.com/lupyuen/nuttx-ox64/blob/main/nuttx.exp)

```bash
## Wait for the prompt and enter `ostest`
expect "nsh> "
send -s "ostest\r"

## Wait at most 30 seconds
set timeout 30

## Check the response...
expect {
  ## If we see this message, exit normally
  "ostest_main: Exiting with status -1" { exit 0 }

  ## If timeout, exit with an error
  timeout { exit 1 }
}
```

Which works great for thoroughly exercising __NuttX on our Ox64 Emulator__...

```text
## Run our Expect Script to start Ox64 Emulator...
$ ./nuttx.exp
spawn ./temu nuttx.cfg

  ## And run all kinds of NuttX Tests
  nsh> ostest
  ...
  ostest_main: Exiting with status -1
  nsh>

## Our Expect Script completes successfully
```

[(See the __Test Log__)](https://gist.github.com/lupyuen/1693ffb16ae943e44faada4428335eb0)

![Daily Automated Testing with Ox64 BL808 Emulator (Apache NuttX RTOS)](https://lupyuen.github.io/images/tinyemu3-test.jpg)

# Daily Automated Testing

_We run this every day?_

__GitHub Actions__ will start our Automated Test every day at 12:55am (GMT): [ox64-test.yml](https://github.com/lupyuen/nuttx-ox64/blob/main/.github/workflows/ox64-test.yml)

```yaml
## Run our Automated Test
## Every day at 0:55 UTC
## (After Daily Build at 0:00 UTC)
on:
  schedule:
    - cron: '55 0 * * *'
```

[(Why not one o'clock? __It's too busy__)](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule)

We build our __Ox64 BL808 Emulator__: [ox64-test.yml](https://github.com/lupyuen/nuttx-ox64/blob/main/.github/workflows/ox64-test.yml#L18-L58)

```bash
## Install `expect` and the Build Prerequisites on Ubuntu
sudo apt -y update
sudo apt -y install \
  expect libcurl4-openssl-dev libssl-dev zlib1g-dev libsdl2-dev wget

## Build Ox64 BL808 Emulator
git clone https://github.com/lupyuen/ox64-tinyemu
pushd ox64-tinyemu
make
cp temu ..
popd
```

Download the __Daily NuttX Build__...

```bash
## Location of Daily NuttX Builds
## `outputs.date` looks like `2024-01-25`
url=https://github.com/lupyuen/nuttx-ox64/releases/download/nuttx-ox64-${{ steps.date.outputs.date }}

## Download the NuttX Build and show the Git Hash
wget $url/Image
wget $url/nuttx.hash
cat nuttx.hash
```

[(__NuttX Builds__ are here)](https://github.com/lupyuen/nuttx-ox64/tags)

[(__outputs.date__ is defined here)](https://github.com/lupyuen/nuttx-ox64/blob/main/.github/workflows/ox64-test.yml#L25-L29)

And start our __Test Script__...

```bash
## Download the Test Script from
## https://github.com/lupyuen/nuttx-ox64
url=https://github.com/lupyuen/nuttx-ox64/raw/main
wget $url/nuttx.cfg
wget $url/nuttx.exp

## Run the Test Script
chmod +x nuttx.exp
./nuttx.exp
```

[(__nuttx.cfg__ is our __TinyEMU Config__)](https://github.com/lupyuen/nuttx-ox64/blob/main/nuttx.cfg)

[(__nuttx.exp__ is our __Expect Script__)](https://github.com/lupyuen/nuttx-ox64/blob/main/nuttx.exp)

That's everything we need for Daily Automated Testing! Our Ox64 Emulator will emulate [__`ostest`__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/ostest_main.c) and launch a whole bunch of tests...

<span style="font-size:90%">

| | | |
|:--|:--|:--|
| [__Standard I/O__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/ostest_main.c#L622-L639) | [__Environment Variables__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/ostest_main.c#L146-L209) | [__Stream VBuf__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/setvbuf.c)
| [__Mutex__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/mutex.c) | [__Start Thread__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/cancel.c) | [__Robust Mutex__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/robust.c)
| [__Semaphore__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/sem.c) | [__Timed Semaphore__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/semtimed.c) | [__Condition Variables__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/cond.c)
| [__PThread Exit__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/pthread_exit.c) | [__Timed Wait__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/timedwait.c) | [__Message Queue__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/mqueue.c)
| [__Timed Message Queue__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/timedmqueue.c) | [__Signal Handler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/sighand.c) | [__Nested Signal Handler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/signest.c)
| [__POSIX Timer__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/posixtimer.c) | [__Round-Robin Scheduler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/roundrobin.c) | [__PThread Barrier__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/barrier.c)
| [__Scheduler Lock__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/schedlock.c) | [(See the __Test Log__)](https://gist.github.com/lupyuen/1693ffb16ae943e44faada4428335eb0) | [(See the __Daily Logs__)](https://github.com/lupyuen/nuttx-ox64/actions/workflows/ox64-test.yml)

</span>

![NuttX Kernel won't work in Machine Mode](https://lupyuen.github.io/images/tinyemu2-flow2.jpg)

# Boot NuttX in Supervisor Mode

_Ox64 Automated Testing doesn't look so hard?_

That's because most of the tough work was done in our __Ox64 BL808 Emulator__! Let's look back at the challenging bits...

_What's this Supervisor Mode? Why does it matter?_

We created our Ox64 Emulator with the [__TinyEMU RISC-V Emulator__](https://lupyuen.github.io/articles/tinyemu2). And TinyEMU boots NuttX in __RISC-V Machine Mode__. (Pic above)

Which won't work because NuttX expects to run in __RISC-V Supervisor Mode__...

- [__"Machine Mode vs Supervisor Mode"__](https://lupyuen.github.io/articles/tinyemu2#machine-mode-vs-supervisor-mode)

_All Operating Systems should boot in (super-powerful) Machine Mode. Right?_

Actually a __RISC-V SBC__ (like Ox64) will boot the [__OpenSBI Supervisor Binary Interface__](https://lupyuen.github.io/articles/sbi) in __Machine Mode__...

Followed by the [__NuttX Kernel__](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow) (or Linux Kernel) in __Supervisor Mode__...

![Ox64 SBC will run in Machine, Supervisor AND User Modes](https://lupyuen.github.io/images/tinyemu2-flow.jpg)

_How to fix this?_

We tweak TinyEMU to boot NuttX in __Supervisor Mode__ (instead of Machine Mode)...

![TinyEMU will boot NuttX in Supervisor Mode](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

We do this in the __TinyEMU Boot Code__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L874-L885)

```c
// At Startup: Init the TinyEMU Boot Code...
void copy_bios(...) {
  ...
  // Load RAM_BASE_ADDR into Register T0.
  // That's 0x5020_0000, the Start Address of
  // NuttX Kernel (Linux too)
  auipc t0, RAM_BASE_ADDR

  // Load the Device Tree into Register A1.
  // (Used by Linux but not NuttX)
  auipc a1, dtb
  addi  a1, a1, dtb

  // Load the Hart ID (CPU ID: 0) into Register A0
  csrr  a0, mhartid
```

The code above comes from the original TinyEMU Emulator.

Next comes the code that we specially inserted for our __Ox64 Emulator__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L882-L960)

```c
  // Previously: We jump to RAM_BASE_ADDR in Machine Mode
  // Now: We jump to RAM_BASE_ADDR in Supervisor Mode...

  // Delegate all Exceptions to Supervisor Mode (instead of Machine Mode)
  // We set MEDELEG CSR Register to 0xFFFF
  lui   a5, 0x10   ; nop  // A5 is 0x10000
  addiw a5, a5, -1 ; nop  // A5 is 0xFFFF
  csrw  medeleg, a5

  // Delegate all Interrupts to Supervisor Mode (instead of Machine Mode)
  // We set MIDELEG CSR Register to 0xFFFF
  csrw  mideleg, a5

  // Rightfully: Follow the OpenSBI Settings for Ox64
  // Boot HART MIDELEG: 0x0222
  // Boot HART MEDELEG: 0xB109
```

[(__MEDELEG and MIDELEG__ are explained here)](https://lupyuen.github.io/articles/tinyemu3#appendix-boot-nuttx-in-supervisor-mode)

The code above delegates all __Exceptions and Interrupts__ to __RISC-V Supervisor Mode__. (Instead of Machine Mode)

Next we set the __Previous Privilege Mode__ to Supervisor Mode (we'll see why)...

```c
  // Clear these bits in MSTATUS CSR Register...
  // MPP (Bits 11 and 12): Clear the Previous Privilege Mode
  lui   a5, 0xffffe ; nop
  addiw a5, a5, 2047
  csrc  mstatus, a5

  // Set these bits in MSTATUS CSR Register...
  // MPPS (Bit 11): Previous Privilege Mode is Supervisor Mode
  // SUM  (Bit 18): Allow Supervisor Mode to access Memory of User Mode
  lui   a5, 0x41
  addiw a5, a5, -2048
  csrs  mstatus, a5
```

[(__MSTATUS and SUM__ are explained here)](https://lupyuen.github.io/articles/tinyemu3#appendix-boot-nuttx-in-supervisor-mode)

Why set Previous Privilege to Supervisor Mode? So we can execute an __MRET (Return from Machine Mode)__ that will jump to the Previous Privilege... __Supervisor Mode!__

```c
  // Jump to RAM_BASE_ADDR in Supervisor Mode:
  // Set the MEPC CSR Register, then Return from Machine Mode
  csrw  mepc, t0
  mret
```

_Do we need so much Boot Code?_

Yes! Check out what happens if we remove some bits of our Boot Code from TinyEMU...

- [__"Boot NuttX in Supervisor Mode"__](https://lupyuen.github.io/articles/tinyemu3#appendix-boot-nuttx-in-supervisor-mode)

![TinyEMU will emulate the System Timer](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

# Emulate the System Timer

_NuttX can't access the System Timer because it runs in RISC-V Supervisor Mode..._

_What can we do to help NuttX?_

NuttX will make a __System Call (ECALL)__ to OpenSBI to start the System Timer (pic above)...

- [__"OpenSBI Timer for NuttX"__](https://lupyuen.github.io/articles/nim#appendix-opensbi-timer-for-nuttx)

And NuttX reads the System Time through the __TIME CSR Register__: [riscv_sbi.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_sbi.c#L108-L141)

```c
// Fetch the System Time...
uint64_t riscv_sbi_get_time(void) {

  // Read the TIME CSR Register, which becomes
  // the `RDTIME` RISC-V Instruction
  return READ_CSR(time);
}
```

Thus we emulate the [__OpenSBI System Timer__](https://lupyuen.github.io/articles/sbi#set-a-system-timer) and the [__TIME CSR Register__](https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers).

__At Startup:__ We search for the ECALL to OpenSBI and remember the __ECALL Address__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L916-L927)

```c
// Scan the Kernel Image for Special Instructions...
uint8_t *kernel_ptr = get_ram_ptr(s, RAM_BASE_ADDR, TRUE);
for (int i = 0; i < 0x10000; i++) {

  // If we find the ECALL Instruction:
  // 00000073 ecall
  const uint8_t ecall[] = { 0x73, 0x00, 0x00, 0x00 };
  if (memcmp(&kernel_ptr[i], ecall, sizeof(ecall)) == 0) {

    // Remember the ECALL Address
    ecall_addr = RAM_BASE_ADDR + i;
  }
```

The [__TIME CSR Register__](https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers) gets assembled into the [__RDTIME RISC-V Instruction__](https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers)...

However __RDTIME__ isn't supported by TinyEMU. [(Needs the __Zicntr Extension__)](https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers)

Hence we patch __RDTIME__ to become __ECALL__ and we emulate later: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L927-L937)

```c
  // If we find the RDTIME Instruction: (Read System Time)
  // c0102573 rdtime a0
  const uint8_t rdtime[] = { 0x73, 0x25, 0x10, 0xc0 };
  if (memcmp(&kernel_ptr[i], rdtime, sizeof(rdtime)) == 0) {

    // Patch RDTIME to become ECALL
    memcpy(&kernel_ptr[i], ecall,  sizeof(ecall));

    // Remember the RDTIME Address
    rdtime_addr = RAM_BASE_ADDR + i;
  }
```

How to handle both ECALLs? Check the details here...

- [__"Start the System Timer"__](https://lupyuen.github.io/articles/tinyemu3#appendix-start-the-system-timer)

- [__"Read the System Time"__](https://lupyuen.github.io/articles/tinyemu3#appendix-read-the-system-time)

- [__"Trigger the Timer Interrupt"__](https://lupyuen.github.io/articles/tinyemu3#appendix-trigger-the-timer-interrupt)

_Anything else we patched?_

We patched these Special RISC-V Instructions to become ECALL:  [__DCACHE.IALL__ and __SYNC.S__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L937-L956)

These instructions are specific to __T-Head C906 CPU__ (and won't work in TinyEMU). NuttX calls them to [__Flush the MMU Cache__](https://lupyuen.github.io/articles/mmu#appendix-flush-the-mmu-cache-for-t-head-c906).

(Though we don't emulate them right now)

![UART Interrupts for Ox64 BL808 SBC](https://lupyuen.github.io/images/plic2-registers.jpg)

# Emulate the UART Interrupts

_Ox64 SBC has a UART Controller that will handle Console Input..._

_How did we emulate the Ox64 UART Controller?_

Previously we emulated the __BL808 UART Registers__ to do Console Output...

- [__"Intercept the UART Registers"__](https://lupyuen.github.io/articles/tinyemu2#intercept-the-uart-registers)

Console Input is a little more tricky... We need to emulate __UART Interrupts__! (Pic above)

- [__"UART Interrupt and Platform-Level Interrupt Controller"__](https://lupyuen.github.io/articles/plic2)

_Is there a TinyEMU UART Controller that we can reuse?_

TinyEMU has a [__VirtIO Console__](https://lupyuen.github.io/articles/tinyemu#virtio-console) that emulates a UART Controller.

Let's hack TinyEMU's VirtIO Console so that it behaves like [__BL808 UART Controller__](https://lupyuen.github.io/articles/plic2#appendix-uart-driver-for-ox64).

We tweak the __VirtIO Interrupt Number__ so it works like BL808 UART3: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L69-L85)

```c
// VirtIO now emulates
// BL808 UART3 Interrupt
#define VIRTIO_IRQ 20
```

When we detect a keypress, we trigger the __UART Interrupt__: [virtio.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1338-L1347)

```c
// When we receive a keypress...
int virtio_console_write_data(VIRTIODevice *s, const uint8_t *buf, int buf_len) {

  // Pass the keypress to NuttX later
  set_input(buf[0]);

  // Trigger the UART Interrupt
  s->int_status |= 1;
  set_irq(s->irq, 1);
```

[(__set_input__ is defined here)](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L2697-L2704)

[(__set_irq__ is defined here)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L319-L332)

When we run this: TinyEMU loops forever handling UART Interrupts :-(

_Surely we need to Clear the UART Interrupt?_

We check our __NuttX UART Driver__: [bl808_serial.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L166-L224)

```c
// NuttX Interrupt Handler for BL808 UART
int uart_interrupt(int irq, void *context, void *arg) {

  // At 0x3000_2020: Read the UART Interrupt Status (uart_int_sts)
  int_status = getreg32(BL808_UART_INT_STS(uart_idx));

  // At 0x3000_2024: Read the UART Interrupt Mask (uart_int_mask)
  int_mask = getreg32(BL808_UART_INT_MASK(uart_idx));

  // If there's UART Input...
  if ((int_status & UART_INT_STS_URX_END_INT) &&
    !(int_mask & UART_INT_MASK_CR_URX_END_MASK)) {

    // At 0x3000_2028: Clear the UART Interrupt (uart_int_clear)
    putreg32(UART_INT_CLEAR_CR_URX_END_CLR, BL808_UART_INT_CLEAR(uart_idx));

    // At 0x3000_208C: Read the UART Input (uart_fifo_rdata)
    uart_recvchars(dev);
```

[(__uart_recvchars__ is defined here)](https://github.com/apache/nuttx/blob/master/drivers/serial/serial_io.c#L107-L268)

Aha! We must emulate the __BL808 UART Registers__ above...

1.  [__UART Interrupt Status__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L402-L407) should say there's UART Input

    [(__uart_int_sts__, Page 419)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

1.  [__UART Interrupt Mask__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L407-L412) should return 0

    [(__uart_int_mask__, Page 420)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

1.  [__UART Clear Interrupt__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L526-L532) should clear the VirtIO Interrupt

    [(__uart_int_clear__, Page 421)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

1.  [__UART Input__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L412-L422) should return the keypress

    [(__uart_fifo_rdata__, Page 428)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

Now we see NuttX correctly handling the UART Interrupt triggered by TinyEMU...

```text
## When we press a key...
## TinyEMU triggers the UART Interrupt
plic_set_irq: irq_num=20, state=1
plic_update_mip: set_mip, pending=0x80000, served=0x0
raise_exception: cause=-2147483639
raise_exception2: cause=-2147483639, tval=0x0

## NuttX Claims the UART Interrupt
plic_read: offset=0x201004
plic_update_mip: reset_mip, pending=0x80000, served=0x80000

## NuttX handles the UART Interrupt in Interrupt Handler
virtio_ack_irq
plic_set_irq: irq_num=20, state=0
plic_update_mip: reset_mip, pending=0x0, served=0x80000

## NuttX Completes the UART Interrupt
plic_write: offset=0x201004, val=0x14
plic_update_mip: reset_mip, pending=0x0, served=0x0
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340#file-ox64-tinyemu-log-L129-L172)

Finally Console Input works OK yay!

- [Live Demo of __Ox64 BL808 Emulator__](https://lupyuen.github.io/nuttx-tinyemu/timer)

- [Watch the __Demo on YouTube__](https://youtu.be/FAxaMt6A59I)

Some more tweaks to TinyEMU VirtIO for Console Input...

1.  We disable the [__Console Resize Event__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1370-L1382)

    (Because it crashes NuttX at startup)

1.  We always allow [__VirtIO to Write Data__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1297-L1313)

1.  We're always [__Ready for VirtIO Writes__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1313-L1338)

# What's Next

TODO

We created a tool that's super helpful for __validating our Daily NuttX Builds__, whether they'll actually boot OK on Ox64...

TODO

We tried creating a [__PinePhone Emulator__](https://lupyuen.github.io/articles/unicorn2), but Arm64 Emulation was way too difficult. Ox64 with RISC-V is so much easier!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tinyemu3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tinyemu3.md)

![TinyEMU will boot NuttX in Supervisor Mode](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

# Appendix: Boot NuttX in Supervisor Mode

Earlier we saw a big chunk of __TinyEMU Boot Code__ (pic above) that will start __NuttX in RISC-V Supervisor Mode__ (instead of Machine Mode)...

- [__"Boot NuttX in Supervisor Mode"__](https://lupyuen.github.io/articles/tinyemu3#boot-nuttx-in-supervisor-mode)

_Can't we call MRET directly? And jump from Machine Mode to Supervisor Mode?_

```c
  // Load RAM_BASE_ADDR into Register T0.
  // That's 0x5020_0000, the Start Address of
  // NuttX Kernel (Linux too)
  auipc t0, RAM_BASE_ADDR

  // Testing: Can we jump like this?
  // Jump to RAM_BASE_ADDR in Supervisor Mode:
  // Set the MEPC CSR Register, then Return from Machine Mode
  csrw  mepc, t0
  mret
```

Watch what happens when we run it...

```bash
## Illegal Instruction in RISC-V User Mode (priv=U)
raise_exception2: cause=2, tval=0x10401073
pc =0000000050200074 ra =0000000000000000 sp =0000000050407c00 gp =0000000000000000
priv=U mstatus=0000000a00000080 cycles=13
```

TinyEMU halts with an __Illegal Instuction__. The offending code comes from...

```text
nuttx/arch/risc-v/src/chip/bl808_head.S:124
  /* Disable all interrupts (i.e. timer, external) in sie */
  csrw sie, zero
    50200074: 10401073  csrw sie, zero
```

_Why is this instruction invalid?_

"__`csrw sie`__" writes to SIE (Supervisor-Mode Interrupt Enable). And SIE is a __Supervisor-Mode__ CSR Register.

The instruction is invalid because we're running in __RISC-V User Mode__ (__`priv=U`__), not Supervisor Mode!

Somehow __MRET__ has jumped from Machine Mode to User Mode. To fix this, we set the __Previous Privilege Mode__ to Supervisor Mode...

```c
  // Clear these bits in MSTATUS CSR Register...
  // MPP (Bits 11 and 12): Clear the Previous Privilege Mode
  lui   a5, 0xffffe ; nop
  addiw a5, a5, 2047
  csrc  mstatus, a5

  // Set these bits in MSTATUS CSR Register...
  // MPPS (Bit 11): Previous Privilege Mode is Supervisor Mode
  // SUM  (Bit 18): Allow Supervisor Mode to access Memory of User Mode
  lui   a5, 0x41
  addiw a5, a5, -2048
  csrs  mstatus, a5

  // Return from Machine Mode to Supervisor Mode
  mret
```

[(__MSTATUS__ is explained here)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush)

[(__SUM__ is needed for NuttX Apps)](https://lupyuen.github.io/articles/app#kernel-accesses-app-memory)

[(Why __Register A5__? Because we copied from the __NuttX QEMU Boot Code__)](https://gist.github.com/lupyuen/368744ef01b7feba10c022cd4f4c5ef2#file-nuttx-start-s-L1282-L1314)

(Why __NOP__? Because TinyEMU needs every instruction padded to 32 bits)

_Now what happens?_

NuttX Shell makes a __System Call (ECALL)__ to NuttX Kernel. Which is supposed to jump from RISC-V User Mode to __Supervisor Mode__...

```bash
## NuttX Kernel starts NuttX Shell
nx_start_application: Starting init task: /system/bin/init

## NuttX Shell makes an ECALL from User Mode (priv=U)
raise_exception2: cause=8, tval=0x0
pc=00000000800019c6
priv=U mstatus=0000000a000400a1 cycles=79648442
mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080

## But TinyEMU jumps to Machine Mode! (priv=M)
raise_exception2: cause=2, tval=0x0
pc=0000000000000000
priv=M mstatus=0000000a000400a1 cycles=79648467
mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
```

Nope, it actually jumps from RISC-V User Mode (__`priv=U`__) to __Machine Mode__ (__`priv=M`__)! (Instead of Supervisor Mode)

To fix this: We delegate all __Exceptions and Interrupts__ to __RISC-V Supervisor Mode__. (Instead of Machine Mode)

```c
  // Previously: We jump to RAM_BASE_ADDR in Machine Mode
  // Now: We jump to RAM_BASE_ADDR in Supervisor Mode...

  // Delegate all Exceptions to Supervisor Mode (instead of Machine Mode)
  // We set MEDELEG CSR Register to 0xFFFF
  lui   a5, 0x10   ; nop  // A5 is 0x10000
  addiw a5, a5, -1 ; nop  // A5 is 0xFFFF
  csrw  medeleg, a5

  // Delegate all Interrupts to Supervisor Mode (instead of Machine Mode)
  // We set MIDELEG CSR Register to 0xFFFF
  csrw  mideleg, a5

  // Rightfully: Follow the OpenSBI Settings for Ox64
  // Boot HART MIDELEG: 0x0222
  // Boot HART MEDELEG: 0xB109
```

(__MEDELEG__ is the Machine Exception Delegation Register)

(__MIDELEG__ is the Machine Interrupt Delegation Register)

[(__MEDELEG and MIDELEG__ are explained here)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-delegation-registers-medeleg-and-mideleg)

Finally NuttX Shell starts OK! User-Mode ECALLs are working perfectly yay!

```text
nx_start_application:
  Starting init task:
    /system/bin/init
NuttShell (NSH) NuttX-12.4.0
nsh>
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340)

And that's why we need the big chunk of [__TinyEMU Boot Code__](https://lupyuen.github.io/articles/tinyemu3#boot-nuttx-in-supervisor-mode) that we saw earlier.

![TinyEMU will emulate the System Timer](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

# Appendix: Start the System Timer

Earlier we talked about emulating OpenSBI for __starting the System Timer__ (pic above)...

- [__"Emulate the System Timer"__](https://lupyuen.github.io/articles/tinyemu3#emulate-the-system-timer)

And at startup, we captured the address of the __System Call (ECALL)__ from NuttX Kernel (Supervisor Mode) to OpenSBI (Machine Mode).

This is how we emulate the __ECALL to OpenSBI__: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L1164-L1182)

```c
// Called by TinyEMU to handle RISC-V Exceptions
void raise_exception2(RISCVCPUState *s, uint32_t cause, target_ulong tval) {
  ...
  // If this is an ECALL from Supervisor Mode...
  // (Not ECALL from User Mode)
  if (cause == CAUSE_SUPERVISOR_ECALL) {

    // If Program Counter is the
    // ECALL to OpenSBI...
    if (s->pc == ecall_addr) {

      // We emulate the OpenSBI Set Timer Function:
      // https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v1.0.0/riscv-sbi.adoc#61-function-set-timer-fid-0

      // Clear the Pending Timer Interrupt Bit
      // (Says the SBI Spec)
      riscv_cpu_reset_mip(s, MIP_STIP);

      // If Parameter A0 is not -1, set the System Timer (timecmp)
      // Parameter A0 is Register X10
      uint64_t timecmp = s->reg[10];
      if (timecmp != (uint64_t) -1) {
        set_timecmp(NULL, timecmp);
      }

      // Skip to the next instruction (RET)
      s->pc += 4;
      return;          
```

__set_timecmp__ sets the __Machine-Mode System Timer__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1225-L1235)

```c
// Set the System Timer
void set_timecmp(RISCVMachine *machine0, uint64_t timecmp) {

  // At Startup: Remember the RISC-V Machine and return
  static RISCVMachine *machine = NULL;
  if (machine0 != NULL) { machine = machine0; return; }

  // Otherwise set the System Timer
  if (machine == NULL) { puts("set_timecmp: machine is null"); return; }
  machine->timecmp = timecmp;
}
```

[(__set_timecmp__ is initialised by __riscv_machine_init__)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1136-L1140)

Note that nothing will happen unless we trigger a __Supervisor-Mode Timer Interrupt__ to NuttX...

- [__"Trigger the Timer Interrupt"__](https://lupyuen.github.io/articles/tinyemu3#appendix-trigger-the-timer-interrupt)

_We're emulating the OpenSBI System Timer with the Machine-Mode System Timer?_

Exactly! We do the same for reading the System Time...

# Appendix: Read the System Time

Just now we talked about emulating the RDTIME RISC-V Instruction for __reading the System Time__...

- [__"Emulate the System Timer"__](https://lupyuen.github.io/articles/tinyemu3#emulate-the-system-timer)

And at startup we...

- Captured the address of the __RDTIME Instruction__

- Patched the RDTIME Instruction to become a __System Call (ECALL)__

This is how we emulate the Patched ECALL to __read the System Time__: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L1183-L1195)

```c
// Called by TinyEMU to handle RISC-V Exceptions
void raise_exception2(RISCVCPUState *s, uint32_t cause, target_ulong tval) {
  ...
  // If this is an ECALL from Supervisor Mode...
  // (Not ECALL from User Mode)
  if (cause == CAUSE_SUPERVISOR_ECALL) {

    // If Program Counter is the
    // (formerly) RDTIME Instruction...
    if (s->pc == rdtime_addr) {

      // We emulate the RDTIME Instruction to fetch the System Time:
      // https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers

      // Return the System Time in Register A0
      // Which is aliased to Register X10
      s->reg[10] = real_time;

      // Skip to the next instruction (RET)
      s->pc += 4;
      return; 
```

[(__set_timecmp__ is explained here)](https://lupyuen.github.io/articles/tinyemu3#appendix-start-the-system-timer)

[(__real_time__ is explained in the next section)](https://lupyuen.github.io/articles/tinyemu3#appendix-trigger-the-timer-interrupt)

Note that nothing will happen unless we trigger a __Supervisor-Mode Timer Interrupt__ to NuttX...

- [__"Trigger the Timer Interrupt"__](https://lupyuen.github.io/articles/tinyemu3#appendix-trigger-the-timer-interrupt)

# Appendix: Trigger the Timer Interrupt

Previously we discussed the emulation of the __System Timer__ (pic above)...

- [__"Emulate the System Timer"__](https://lupyuen.github.io/articles/tinyemu3#emulate-the-system-timer)

- [__"Start the System Timer"__](https://lupyuen.github.io/articles/tinyemu3#appendix-start-the-system-timer)

- [__"Read the System Time"__](https://lupyuen.github.io/articles/tinyemu3#appendix-read-the-system-time)

But nothing will happen unless we trigger a __Supervisor-Mode Timer Interrupt__ to NuttX!

This is how we trigger the __Timer Interrupt__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1172-L1182)

```c
// Called by TinyEMU periodically to check the System Timer
static int riscv_machine_get_sleep_duration(VirtMachine *s1, int delay) {
  ...
  // Pass the System Time to raise_exception2()
  real_time = rtc_get_time(m);

  // If the System Timer has expired...
  if (!(riscv_cpu_get_mip(s) & MIP_STIP)) {

    // Trigger the Timer Interrupt for Supervisor Mode
    const int64_t delay2 = m->timecmp - rtc_get_time(m);
    if (delay2 <= 0) {
      riscv_cpu_set_mip(s, MIP_STIP);
    }
  }
```

Again we're using the __Machine-Mode System Timer__, to trigger the Supervisor-Mode Timer Interrupt.

With this Timer Interrupt, __`usleep`__ (and other Timer Functions) will work perfectly in NuttX...

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> usleep 1
nsh> 
```

[(See the __Timer Log__)](https://gist.github.com/lupyuen/31bde9c2563e8ea2f1764fb95c6ea0fc)
