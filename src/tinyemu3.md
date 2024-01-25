# Automated Testing with Ox64 BL808 Emulator (Apache NuttX RTOS)

📝 _29 Jan 2024_

![Automated Testing with Ox64 BL808 Emulator (Apache NuttX RTOS)](https://lupyuen.github.io/images/tinyemu3-title.png)

_Every day we're auto-building Apache NuttX RTOS for Ox64 BL808 SBC..._

_Can we test NuttX on Ox64 automatically after building?_

Yes we can! With a little help from the __Ox64 BL808 Emulator__ that we created last week...

- [__"Emulate Ox64 BL808 in the Web Browser: Experiments with TinyEMU RISC-V Emulator and Apache NuttX RTOS"__](https://lupyuen.github.io/articles/tinyemu2)

_But our Ox64 Emulator was incomplete?_

Today we fill in the missing pieces of our Ox64 Emulator and call it for __Automated Testing__...

- TODO: Boot NuttX in Supervisor Mode

- TODO: Emulate UART Interrupts for Console Input

- TODO: Emulate OpenSBI for System Timer

- TODO: Fix the System Timer

- TODO: Scripting The Expected

- TODO: Daily Automated Testing

We begin with the easier bit: Scripting our Ox64 Emulator...

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

But with an __Expect Script__, we can __feed our commands automatically__ into the Emulator!

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

[(See the __Test Log__)](https://github.com/lupyuen/nuttx-ox64/actions/workflows/ox64-test.yml)

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

[(See the __Test Log__)](https://github.com/lupyuen/nuttx-ox64/actions/workflows/ox64-test.yml)

| | | |
|:--|:--|:--|
| [__Standard I/O__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/ostest_main.c#L622-L639) | [__Environment Variables__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/ostest_main.c#L146-L209) | [__Stream VBuf__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/setvbuf.c)
| [__Mutex__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/mutex.c) | [__Start Thread__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/cancel.c) | [__Robust Mutex__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/robust.c)
| [__Semaphore__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/sem.c) | [__Timed Semaphore__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/semtimed.c) | [__Condition Variables__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/cond.c)
| [__PThread Exit__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/pthread_exit.c) | [__Timed Wait__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/timedwait.c) | [__Message Queue__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/mqueue.c)
| [__Timed Message Queue__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/timedmqueue.c) | [__Signal Handler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/sighand.c) | [__Nested Signal Handler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/signest.c)
| [__POSIX Timer__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/posixtimer.c) | [__Round-Robin Scheduler__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/roundrobin.c) | [__PThread Barrier__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/barrier.c)
| [__Scheduler Lock__](https://github.com/apache/nuttx-apps/tree/master/testing/ostest/schedlock.c)

</span>

![NuttX Kernel won't work in Machine Mode](https://lupyuen.github.io/images/tinyemu2-flow2.jpg)

# Boot NuttX in Supervisor Mode

_Ox64 Automated Testing doesn't look so hard?_

That's because most of the tough work was done in our __Ox64 BL808 Emulator__! Let's look back at the challenging bits...

_What's this Supervisor Mode? Why does it matter?_

TinyEMU Emulator boots NuttX in __RISC-V Machine Mode__. (Pic above)

Which won't work because NuttX expects to run in __RISC-V Supervisor Mode__...

- [__"Machine Mode vs Supervisor Mode"__](https://lupyuen.github.io/articles/tinyemu2#machine-mode-vs-supervisor-mode)

_But all Operating Systems should boot in Machine Mode. Right?_

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

(Why __NOP__? Because TinyEMU needs every instruction padded to 32 bits)

The code above delegates all __Exceptions and Interrupts__ to __RISC-V Supervisor Mode__. (Instead of Machine Mode)

[(__MIDELEG and MEDELEG__ are explained here)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-delegation-registers-medeleg-and-mideleg)

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

[(__MSTATUS__ is explained here)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush)

[(__SUM__ is needed for NuttX Apps)](https://lupyuen.github.io/articles/app#kernel-accesses-app-memory)

[(Why __Register A5__? Because we copied from the __NuttX QEMU Boot Code__)](https://gist.github.com/lupyuen/368744ef01b7feba10c022cd4f4c5ef2#file-nuttx-start-s-L1282-L1314)

Why set Previous Privilege to Supervisor Mode? So we can execute an __MRET (Return from Machine Mode)__ that will jump to the Previous Privilege... __Supervisor Mode!__

```c
  // Jump to RAM_BASE_ADDR in Supervisor Mode:
  // Set the MEPC CSR Register, then Return from Machine Mode
  csrw  mepc, t0
  mret
```

_Do we need so much Boot Code?_

Yes! Check out what happens if we remove some bits of our Boot Code from TinyEMU...

TODO: Appendix

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

But __RDTIME__ isn't supported by TinyEMU. [(Needs the __Zicntr Extension__)](https://five-embeddev.com/riscv-isa-manual/latest/counters.html#zicntr-standard-extension-for-base-counters-and-timers)

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

TODO: Appendix

_Anything else we patched?_

We patched these Special RISC-V Instructions to become ECALL:  [__DCACHE.IALL__ and __SYNC.S__](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L937-L956)

These instructions are specific to __T-Head C906 CPU__. NuttX calls them to [__Flush the MMU Cache__](https://lupyuen.github.io/articles/mmu#appendix-flush-the-mmu-cache-for-t-head-c906).

(Though we won't emulate them yet)

TODO: [Emulator Timer Log](https://gist.github.com/lupyuen/31bde9c2563e8ea2f1764fb95c6ea0fc)

Test `ostest`...

```text
semtimed_test: Starting poster thread
semtimed_test: Set thread 1 priority to 191
semtimed_test: Starting poster thread 3
semtimed_test: Set thread 3 priority to 64
semtimed_test: Waiting for two second timeout
poster_func: Waiting for 1 second
semtimed_test: ERROR: sem_timedwait failed with: 110
_assert: Current Version: NuttX  12.4.0-RC0 55ec92e181 Jan 24 2024 00:11:51 risc
-v
_assert: Assertion failed (_Bool)0: at file: semtimed.c:240 task: ostest process
: ostest 0x8000004a
up_dump_register: EPC: 0000000050202008
```

TODO: [Remove the Timer Interrupt Interval because ostest will fail](https://github.com/lupyuen/ox64-tinyemu/commit/169dd727a5e06bdc95ac3f32e1f1b119c3cbbb75)

TODO: [`ostest` is OK yay!](https://lupyuen.github.io/nuttx-tinyemu/timer/)

![UART Interrupts for Ox64 BL808 SBC](https://lupyuen.github.io/images/plic2-registers.jpg)

# Emulate the UART Interrupts

_Ox64 SBC has a UART Controller that will handle Console Input..._

_How did we emulate the Ox64 UART Controller?_

Previously we emulated the __BL808 UART Registers__ to do Console Output...

- [__"Intercept the UART Registers"__](https://lupyuen.github.io/articles/tinyemu2#intercept-the-uart-registers)

But Console Input is a little more tricky... We need to emulate __UART Interrupts__! (Pic above)

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

TODO: set_input is defined here

TODO: set_irq is defined here

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

TODO: uart_recvchars is defined here

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

[(See the Complete Log)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340#file-ox64-tinyemu-log-L129-L172)

Finally Console Input works OK yay!

- [Live Demo of __Ox64 BL808 Emulator__](https://lupyuen.github.io/nuttx-tinyemu/timer)

- [Watch the __Demo on YouTube__](https://youtu.be/FAxaMt6A59I)

A few more tweaks to TinyEMU VirtIO for Console Input...

1.  We disable the [__Console Resize Event__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1370-L1382)

    (Because it crashes NuttX at startup)

1.  We always allow [__VirtIO to Write Data__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1297-L1313)

1.  We're always [__Ready for VirtIO Writes__](https://github.com/lupyuen/ox64-tinyemu/blob/main/virtio.c#L1313-L1338)

# What's Next

TODO

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

TODO

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

TODO: machine exception delegation register (medeleg) and machine interrupt delegation register ( mideleg)

TODO: [MCAUSE](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:mcause)

TODO

_NuttX needs to boot in Supervisor Mode, not Machine Mode. How to fix this in TinyEMU?_

We copy to TinyEMU Boot Code the Machine-Mode Start Code from [NuttX Start Code for 64-bit RISC-V Kernel Mode (rv-virt:knsh64)](https://gist.github.com/lupyuen/368744ef01b7feba10c022cd4f4c5ef2)...

- [Execute the MRET Instruction to jump from Machine Mode to Supervisor Mode](https://github.com/lupyuen/ox64-tinyemu/commit/e62d49f1a8b27002871f712e80b1785442e23393)

- [Dump the RISC-V Registers MCAUSE 2: Illegal Instruction](https://github.com/lupyuen/ox64-tinyemu/commit/37c2d1169706a56afbd2d7d2a13624b58269e1ef#diff-2080434ac7de762b1948a6bc493874b21b9e3df3de8b9e52de23bfdcec354abd) (for easier troubleshooting)

![TinyEMU will boot NuttX in Supervisor Mode](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

```text
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
virtio_console_init
csr_write: csr=0x341 val=0x0000000050200000
raise_exception2: cause=2, tval=0x10401073
pc =0000000050200074 ra =0000000000000000 sp =0000000050407c00 gp =0000000000000000
tp =0000000000000000 t0 =0000000050200000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000000 s1 =0000000000000000 a0 =0000000000000000 a1 =0000000000001040
a2 =0000000000000000 a3 =0000000000000000 a4 =0000000000000000 a5 =0000000000000000
a6 =0000000000000000 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =fffffffffffffff3 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=U mstatus=0000000a00000080 cycles=13
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
raise_exception2: cause=2, tval=0x0
pc =0000000000000000 ra =0000000000000000 sp =0000000050407c00 gp = 
```

Which fails with an Illegal Instuction. The offending code comes from...

```text
nuttx/arch/risc-v/src/chip/bl808_head.S:124
2:
  /* Disable all interrupts (i.e. timer, external) in sie */
  csrw	sie, zero
    50200074:	10401073          	csrw	sie,zero
```

_Why is this instruction invalid?_

`csrw sie,zero` is invalid because we're in User Mode (`priv=U`), not Supervisor Mode. And SIE is a Supervisor-Mode CSR Register.

So we [set MSTATUS to Supervisor Mode and enable SUM](https://github.com/lupyuen/ox64-tinyemu/commit/d379d92bfe544681e0560306a1aad96f5792da9e).

```text
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
virtio_console_init
raise_exception2: cause=2, tval=0x879b0000
pc =0000000000001012 ra =0000000000000000 sp =0000000000000000 gp =0000000000000000
tp =0000000000000000 t0 =0000000050200000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000000 s1 =0000000000000000 a0 =0000000000000000 a1 =0000000000001040
a2 =0000000000000000 a3 =0000000000000000 a4 =0000000000000000 a5 =ffffffffffffe000
a6 =0000000000000000 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=M mstatus=0000000a00000000 cycles=4
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
tinyemu: Unknown mcause 2, quitting
```

Now we hit an Illegal Instruction caused by an unpadded 16-bit instruction: 0x879b0000.

TinyEMU requires all Boot Code Instructions to be 32-bit. So we [insert NOP (0x0001) to pad 16-bit RISC-V Instructions to 32-bit](https://github.com/lupyuen/ox64-tinyemu/commit/23a36478cf03561d40f357f876284c09722ce455).

```text
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
up_exit: TCB=0x504098d0 exiting

raise_exception2: cause=8, tval=0x0
pc =00000000800019c6 ra =0000000080000086 sp =0000000080202bc0 gp =0000000000000000
tp =0000000000000000 t0 =0000000000000000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000001 s1 =0000000080202010 a0 =000000000000000d a1 =0000000000000000
a2 =0000000080202bc8 a3 =0000000080202010 a4 =0000000080000030 a5 =0000000000000000
a6 =0000000000000101 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=U mstatus=0000000a000400a1 cycles=79648442
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080

raise_exception2: cause=2, tval=0x0
pc =0000000000000000 ra =0000000080000086 sp =0000000080202bc0 gp =0000000000000000
tp =0000000000000000 t0 =0000000000000000 t1 =0000000000000000 t2 =0000000000000000
s0 =0000000000000001 s1 =0000000080202010 a0 =000000000000000d a1 =0000000000000000
a2 =0000000080202bc8 a3 =0000000080202010 a4 =0000000080000030 a5 =0000000000000000
a6 =0000000000000101 a7 =0000000000000000 s2 =0000000000000000 s3 =0000000000000000
s4 =0000000000000000 s5 =0000000000000000 s6 =0000000000000000 s7 =0000000000000000
s8 =0000000000000000 s9 =0000000000000000 s10=0000000000000000 s11=0000000000000000
t3 =0000000000000000 t4 =0000000000000000 t5 =0000000000000000 t6 =0000000000000000
priv=M mstatus=0000000a000400a1 cycles=79648467
 mideleg=0000000000000000 mie=0000000000000000 mip=0000000000000080
tinyemu: Unknown mcause 2, quitting
```

But the ECALL goes from User Mode (`priv=U`) to Machine Mode (`priv=M`), not Supervisor Mode!

We [set the Exception and Interrupt delegation for Supervisor Mode](https://github.com/lupyuen/ox64-tinyemu/commit/9536e86217bcccbe15272dc4450eac9fab173b03).

Finally NuttX Shell starts OK yay! User Mode ECALLs are working perfectly!

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/timer)

[_(Watch the Demo on YouTube)_](https://youtu.be/FAxaMt6A59I)

```text
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
up_exit: TCB=0x504098d0 exiting
NuttShell (NSH) NuttX-12.4.0
nsh>
nx_start: CPU0: Beginning Idle Loop
```

[(See the Complete Log)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340)

![TinyEMU will emulate the System Timer](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

# Appendix: Start the System Timer

TODO

[riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L1164-L1182)

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

      // If Parameter A0 is not -1, set the System Timer (timecmp)
      // Parameter A0 is Register X10
      uint64_t timecmp = s->reg[10];
      if (timecmp != (uint64_t) -1) {
        set_timecmp(NULL, timecmp);
        // TODO: We clear the Pending Timer Interrupt Bit.
      }

      // Skip to the next instruction (RET)
      s->pc += 4;
      return;          
```

__set_timecmp__ sets the System Timer: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1225-L1235)

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

# Appendix: Read the System Time

TODO

[riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L1183-L1195)

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

TODO: __set_timecmp__ is here

TODO: real_time is set by

# Appendix: Trigger the Timer Interrupt

TODO

[riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_machine.c#L1172-L1182)

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

TODO

[For OpenSBI Set Timer: Clear the pending timer interrupt bit](https://github.com/lupyuen/ox64-tinyemu/commit/758287cc3aa8165303c6a726292e665af099aefd)

[For RDTIME: Return the time](https://github.com/lupyuen/ox64-tinyemu/commit/1bcf19a4b2354bc47b515a3fe2f2e8a427e3900d)

[Regularly trigger the Supervisor-Mode Timer Interrupt](https://github.com/lupyuen/ox64-tinyemu/commit/ddedb862a786e52b17cf3331752d50662eddffd3)

`usleep` works OK yay!

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> usleep 1
nsh> 
```
