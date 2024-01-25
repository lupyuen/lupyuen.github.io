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

![UART Interrupts for Ox64 BL808 SBC](https://lupyuen.github.io/images/plic2-registers.jpg)

# Emulate UART Interrupts

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

  // At 0x3000_2020: Read the UART Interrupt Status
  int_status = getreg32(BL808_UART_INT_STS(uart_idx));

  // At 0x3000_2024: Read the UART Interrupt Mask
  int_mask = getreg32(BL808_UART_INT_MASK(uart_idx));

  // If there's UART Input...
  if ((int_status & UART_INT_STS_URX_END_INT) &&
    !(int_mask & UART_INT_MASK_CR_URX_END_MASK)) {

    // At 0x3000_2028: Clear the UART Interrupt
    putreg32(UART_INT_CLEAR_CR_URX_END_CLR, BL808_UART_INT_CLEAR(uart_idx));

    // At 0x3000_208C: Read the UART Input
    uart_recvchars(dev);
```

TODO: uart_recvchars is defined here

Aha! We must emulate the __BL808 UART Registers__ above...

TODO

- Fix the UART Interrupt Status: [BL808_UART_INT_STS (0x30002020) must return UART_INT_STS_URX_END_INT (1 << 1)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L402-L407)

- Fix the UART Interrupt Mask: [BL808_UART_INT_MASK (0x30002024) must NOT return UART_INT_MASK_CR_URX_END_MASK (1 << 1)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L407-L412)

- To prevent looping: [Clear the interrupt after setting BL808_UART_INT_CLEAR (0x30002028)](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L526-L532)

- [BL808_UART_FIFO_RDATA_OFFSET (0x3000208c) returns the Input Char](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L412-L422)

Now it doesn't loop!

```text
nx_start: CPU0: Beginning Idle Loop
[a]
plic_set_irq: irq_num=20, state=1
plic_update_mip: set_mip, pending=0x80000, served=0x0
raise_exception: cause=-2147483639
raise_exception2: cause=-2147483639, tval=0x0

## Claim Interrupt
plic_read: offset=0x201004
plic_update_mip: reset_mip, pending=0x80000, served=0x80000

## Handle Interrupt in Interrupt Handler
virtio_ack_irq
plic_set_irq: irq_num=20, state=0
plic_update_mip: reset_mip, pending=0x0, served=0x80000

## Complete Interrupt
plic_write: offset=0x201004, val=0x14
plic_update_mip: reset_mip, pending=0x0, served=0x0
```


Console Input works OK yay!

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/smode)

[_(Watch the Demo on YouTube)_](https://youtu.be/FAxaMt6A59I)

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
ABCnx_start: Entry
uart_register: Registering /dev/console
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
up_exit: TCB=0x504098d0 exiting
 
NuttShell (NSH) NuttX-12.4.0
nsh> nx_start: CPU0: Beginning Idle Loop
 
nsh> ls
posix_spawn: pid=0x80202978 path=ls file_actions=0x80202980 attr=0x80202988 argv
=0x80202a28
nxposix_spawn_exec: ERROR: exec failed: 2
/:
 dev/
 proc/
 system/
nsh> uname -a
posix_spawn: pid=0x80202978 path=uname file_actions=0x80202980 attr=0x80202988 a
rgv=0x80202a28
nxposix_spawn_exec: ERROR: exec failed: 2
NuttX 12.4.0 96c2707 Jan 18 2024 12:07:28 risc-v ox64
```

[(See the Complete Log)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340)

- [Disable Console Resize event because it crashes VM Guest at startup](https://github.com/lupyuen/ox64-tinyemu/commit/dc869fe6a9a726d413e8a83c56cf40f271c6fe3c)

- [We always allow VirtIO Write Data](https://github.com/lupyuen/ox64-tinyemu/commit/93cd86a7311986e5063cb0c8e368f89cdae73e27)

- [Ww're always ready for VirtIO Writes](https://github.com/lupyuen/ox64-tinyemu/commit/b893255b42a8aaa443f7264dc06537b96326b414)


# Emulate OpenSBI for System Timer

TODO

![TinyEMU will boot NuttX in Supervisor Mode](https://lupyuen.github.io/images/tinyemu2-flow3.jpg)

_How to emulate the OpenSBI ECALL to start the System Timer?_

For now we ignore the OpenSBI ECALL from NuttX, we'll fix later...

- [Emulate OpenSBI for System Timer](https://github.com/lupyuen/ox64-tinyemu/commit/ab58cd2dc6a1d94b9bd13faa0f402a7ada4b270d)

Strangely TinyEMU crashes with an Illegal Instruction Exception at RDTTIME (Read System Timer). We patch it with NOP and handle later...

- [Patch the RDTTIME (Read System Timer) with NOP for now. We will support later.](https://github.com/lupyuen/ox64-tinyemu/commit/5cb2fb4e263b9e965777f567b053a0914f3cf368)

The [Latest NuttX Build](https://github.com/lupyuen/nuttx-ox64/releases/tag/nuttx-ox64-2024-01-20) includes an OpenSBI ECALL. And it works OK with TinyEMU yay!

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/smode)

[_(Watch the Demo on YouTube)_](https://youtu.be/FAxaMt6A59I)

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
Patched RDTTIME (Read System Timer) at 0x5020bad6
ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> uname -a
NuttX 12.4.0-RC0 4c41d84d21 Jan 20 2024 00:10:33 risc-v ox64
nsh> help
help usage:  help [-v] [<cmd>]
 
    .           cp          exit        mkrd        set         unset
    [           cmp         false       mount       sleep       uptime
    ?           dirname     fdinfo      mv          source      usleep
    alias       dd          free        pidof       test        xd
    unalias     df          help        printf      time
    basename    dmesg       hexdump     ps          true
    break       echo        kill        pwd         truncate
    cat         env         ls          rm          uname
    cd          exec        mkdir       rmdir       umount
nsh>
```

[(See the Complete Log)](https://gist.github.com/lupyuen/de071bf54b603f4aaff3954648dcc340)

# Fix the System Timer

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

[Patch DCACHE.IALL and SYNC.S to become ECALL](https://github.com/lupyuen/ox64-tinyemu/commit/b8671f76414747b6902a7dcb89f6fc3c8184075f)

[Handle System Timer with mtimecmp](https://github.com/lupyuen/ox64-tinyemu/commit/f00d40c0de3d97e93844626c0edfd3b19e8252db)

[Emulator Timer Log](https://gist.github.com/lupyuen/31bde9c2563e8ea2f1764fb95c6ea0fc)

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

[Remove the Timer Interrupt Interval because ostest will fail](https://github.com/lupyuen/ox64-tinyemu/commit/169dd727a5e06bdc95ac3f32e1f1b119c3cbbb75)

`ostest` is OK yay!

https://lupyuen.github.io/nuttx-tinyemu/timer/

`expect` script works OK with Ox64 BL808 Emulator...

```bash
#!/usr/bin/expect
set send_slow {1 0.001}
spawn /Users/Luppy/riscv/ox64-tinyemu/temu root-riscv64.cfg

expect "nsh> "
send -s "uname -a\r"

expect "nsh> "
send -s "ostest\r"
expect "ostest_main: Exiting with status -1"
expect "nsh> "
```

We'll run this for Daily Automated Testing, right after the Daily Automated Build.

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

[_(Live Demo of Ox64 BL808 Emulator)_](https://lupyuen.github.io/nuttx-tinyemu/smode)

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
