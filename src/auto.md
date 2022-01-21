# Auto Flash and Test NuttX on RISC-V BL602

📝 _26 Jan 2022_

![PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test](https://lupyuen.github.io/images/auto-title.jpg)

_PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test_

Suppose we're __testing embedded firmware__ on the [__BL602 RISC-V SoC__](https://lupyuen.github.io/articles/pinecone).  And the firmware changes __every day__ (due to Daily Updates from upstream).

Instead of flipping a jumper, restarting the board, flashing over UART, restarting again, repeating every day...

Is there a way to __Automatically Flash and Test__ the Daily Updates?

Yes we can, by connecting BL602 to a __Linux Single-Board Computer__! 

Today we shall create a Linux Script that will...

-   __Auto-Flash__ the Daily Build of [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx) to BL602

-   __Auto-Boot__ NuttX on BL602 after flashing

-   __Auto-Test__ NuttX by sending a command that tests the GPIO Input / Output / Interrupts, SPI, ADC, Timers, Message Queues, PThreads, Strong Random Number Generator and Internal Temperature Sensor

    [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=JtnOyl5cYjo)

    (Spoilers: It's LoRaWAN!)

-   If NuttX crashes, __Auto-Decode__ the NuttX Stack Trace and show us the Source Code that caused the crash

    [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=Kf3G1hGoLIs)

_Why are we doing this?_

-   Might be useful for __Release Testing__ of NuttX (and other operating systems) on real hardware

-   By auto-testing the __LoRaWAN Stack__ on NuttX, we can be sure that GPIO Input / Output / Interrupts, SPI, ADC, ... are all working OK with the latest Daily Build of NuttX

-   I write articles about NuttX OS. I need to pick the __Latest Stable Build__ of NuttX for testing the NuttX code in my articles. [(Like these)](https://lupyuen.github.io/articles/book#nuttx-on-bl602)

_Will this work for other microcontrollers?_

-   __ESP32__ has 2 buttons for flashing (BOOT and EN), very similar to BL602. Our Auto Flash and Test Script might work for ESP32 with some tweaking.

-   __Arm Microcontrollers__ may be auto flashed and debugged with an OpenOCD Script. [(Check out Remote PineTime)](https://github.com/lupyuen/remote-pinetime-bot)

![PineCone BL602 in Flashing Mode with GPIO 8 set to High. Sorry the jumper got mangled due to a soldering accident 🙏](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

_PineCone BL602 in Flashing Mode with GPIO 8 set to High. Sorry the jumper got mangled due to a soldering accident 🙏_

# BL602 Basics

This is how we work with BL602...

1.  __Connect BL602__ to our computer's USB port

1.  Flip the __GPIO 8 Jumper__ to __High__ (pic above)

1.  Press the __Reset Button (RST)__.

    BL602 is now in __Flashing Mode__.

1.  Flash BL602 over USB UART with [__blflash__](https://github.com/spacemeowx2/blflash)...

    ```bash
    $ blflash flash nuttx.bin --port /dev/ttyUSB0
    Start connection...
    Connection Succeed
    Sending eflash_loader...
    Program flash...
    ...
    Success
    ```

1.  Flip the __GPIO 8 Jumper__ to  __Low__ (pic below)

    ![PineCone BL602 in Normal Mode with GPIO 8 set to Low](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the __Reset Button (RST)__.

    BL602 is now in __Normal Mode__ (Non-Flashing).

1.  Launch a __Serial Terminal__ to test the BL602 Firmware

1.  When we're done, close the Serial Terminal and repeat the __Flash-Test Cycle__

Over the past __14 months__ I've been doing this over and over again. Until last week I wondered...

Can we automate this with a __Single-Board Computer__?

And indeed we can! (Duh!) Here's how...

![PineCone BL602 RISC-V Board (lower right) connected to Single-Board Computer (top) and Semtech SX1262 LoRa Transceiver (lower left)](https://lupyuen.github.io/images/auto-title.jpg)

_PineCone BL602 RISC-V Board (lower right) connected to Single-Board Computer (top) and Semtech SX1262 LoRa Transceiver (lower left)_

# Connect BL602 to Single-Board Computer

Connect BL602 to a __Single-Board Computer (SBC)__ as shown in the pic above...

| SBC    | BL602    | Function
| -------|----------|----------
| __GPIO 2__ | GPIO 8   | Flashing Mode (Long Green)
| __GPIO 3__ | RST      | Reset (Long Yellow)
| __GND__    | GND      | Ground
| __USB__    | USB      | USB UART

(Ground is missing from the pic)

Check that BL602 is __firmly seated__ on the Breadboard! The USB Connector tends to __dislodge the BL602 Board__ from the Breadboard when the USB Cable wriggles too much.

For auto-testing LoRaWAN, we also connect BL602 to [__Semtech SX1262 LoRa Transceiver__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) (pic above)...

- [__"Connect SX1262"__](https://lupyuen.github.io/articles/spi2#connect-sx1262)

Clearer pic of the __GPIO 8__ (Flashing Mode) and __Reset Pins__ on PineCone BL602...

![GPIO 8 and Reset Pins](https://lupyuen.github.io/images/auto-connect.jpg)

No more flipping the jumper and smashing the button! Let's control GPIO 8 and Reset Pins with our Linux SBC.

# Control GPIO with Linux

Recall that __GPIO 2 and 3__ on our Linux SBC are connected to BL602 for the __Flashing and Reset__ Functions...

| SBC    | BL602    | Function
| -------|----------|----------
| __GPIO 2__ | GPIO 8   | Flashing Mode
| __GPIO 3__ | RST      | Reset

Let's control GPIO 2 and 3 with a Bash Script.

![Control GPIO with Linux](https://lupyuen.github.io/images/auto-script2.png)

## Enable GPIO

Our Bash Script begins by __enabling GPIO 2 and 3__: [remote-bl602/scripts/test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L42-L48)

```bash
##  Enable GPIO 2 and 3 (if not already enabled)
if [ ! -d /sys/class/gpio/gpio2 ]; then
  echo 2 >/sys/class/gpio/export
  sleep 1
fi
if [ ! -d /sys/class/gpio/gpio3 ]; then
  echo 3 >/sys/class/gpio/export
  sleep 1
fi
```

[(__/sys/class/gpio__ comes from the Linux sysfs Interface)](https://www.ics.com/blog/gpio-programming-using-sysfs-interface)

After enabling GPIO 2 and 3, these __GPIO Interfaces__ will appear in Linux...

-   __/sys/class/gpio/gpio2__

-   __/sys/class/gpio/gpio3__

Let's configure them.

## Configure GPIO Output

Our script configures GPIO 2 and 3 for __GPIO Output__ (instead of GPIO Input): [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L50-L52)

```bash
##  Set GPIO 2 and 3 as output
echo out >/sys/class/gpio/gpio2/direction
echo out >/sys/class/gpio/gpio3/direction
```

Now we're ready to toggle GPIO 2 and 3 to flash and reset BL602!

## Enter Flashing Mode

To enter __Flashing Mode__, our script sets GPIO 2 to __High__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L54-L55)

```bash
##  Set GPIO 2 to High (BL602 Flashing Mode)
echo 1 >/sys/class/gpio/gpio2/value
sleep 1
```

But to make it happen we need to restart BL602, coming up next...

## Reset BL602

To __restart BL602__ (and actually enter Flashing Mode), our script toggles GPIO 3 __High-Low-High__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L57-L65)

```bash
##  Toggle GPIO 3 High-Low-High (Reset BL602)
echo 1 >/sys/class/gpio/gpio3/value
sleep 1
echo 0 >/sys/class/gpio/gpio3/value
sleep 1
echo 1 >/sys/class/gpio/gpio3/value
sleep 1
```

BL602 is now in __Flashing Mode__!

## Flash BL602

Our script runs [__blflash__](https://github.com/spacemeowx2/blflash) to flash BL602 over USB UART: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L67-L72)

```bash
##  BL602 is now in Flashing Mode.
##  Flash BL602 over USB UART with blflash.
blflash flash \
  /tmp/nuttx.bin \
  --port /dev/ttyUSB0
sleep 1
```

(__nuttx.bin__ is the Daily Upstream Build of NuttX OS, as explained in the Appendix)

Our firmware has been flashed automagically!

## Exit Flashing Mode

Now we return to __Normal Mode__ (Non-Flashing) by setting GPIO 2 to __Low__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L74-L80)

```bash
##  Set GPIO 2 to Low (BL602 Normal Mode)
echo 0 >/sys/class/gpio/gpio2/value
sleep 1
```

We effect the change by __restarting BL602__...

```bash
##  Toggle GPIO 3 High-Low-High (Reset BL602)
echo 1 >/sys/class/gpio/gpio3/value
sleep 1
echo 0 >/sys/class/gpio/gpio3/value
sleep 1
echo 1 >/sys/class/gpio/gpio3/value
sleep 1
```

BL602 starts booting our firmware, but we need some prep...

## Show BL602 Output

We're ready to show the output from our BL602 Firmware (NuttX). Our script sets the USB UART's Baud Rate to __2 Mbps__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L82-L98)

```bash
##  BL602 is now in Normal Mode.
##  Set USB UART to 2 Mbps.
stty \
  -F /dev/ttyUSB0 \
  raw 2000000
```

(Otherwise the output will be garbled)

Then our script __streams the output__ from BL602 over USB UART...

```
##  Show the BL602 output and capture to /tmp/test.log.
##  Run this in the background so we can kill it later.
cat /dev/ttyUSB0 \
  | tee /tmp/test.log &
```

And captures the output to __test.log__ for analysis. (Which we'll explain shortly)

This runs as a __Background Task__ (`&`) because we want the script to continue running (in the Foreground) as the BL602 output continues to stream (in the Background).

_But nothing appears in the output?_

Yep because BL602 has __already booted__ our firmware. The Boot Messages have whooshed by before we captured them.

To see the __Boot Messages__, our script restarts BL602 yet again...

```bash
##  Toggle GPIO 3 High-Low-High (Reset BL602)
echo 1 >/sys/class/gpio/gpio3/value
sleep 1
echo 0 >/sys/class/gpio/gpio3/value
sleep 1
echo 1 >/sys/class/gpio/gpio3/value
sleep 1

##  Wait a while for BL602 to finish booting
sleep 1

##  Omitted: Send test command and analyse the BL602 output
...
```

(We'll talk later about the output analysis)

Remember that the BL602 output is still being streamed in a Background Task. Our script __terminates the Background Task__ like so: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L196-L197)

```bash
##  Kill the background task that captures the BL602 output
kill %1
```

And we're done!

_So this script totally replaces a human flipping the jumper and smashing the button on BL602?_

Yep our Linux Script totally controls the __Flashing and Reset__ Functions on BL602... No more human intervention!

Here's a demo of our script flipping GPIO 2 and 3 and switching the flashing mode...

-   [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=d8x0Y-OraXo)

# Run The Script

We've seen the __Auto Flash and Test__ Script, let's run it on our Linux SBC!

Enter this at the Linux command prompt...

```bash
##  Allow the user to access the GPIO and UART ports
sudo usermod -a -G gpio $USER
sudo usermod -a -G dialout $USER

##  Install Rust: https://rustup.rs/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

##  Add Rust to the PATH
source $HOME/.cargo/env

##  Install blflash
cargo install blflash

##  Download the script
git clone --recursive https://github.com/lupyuen/remote-bl602

##  Run the script
remote-bl602/scripts/test.sh
```

Our script flashes and runs NuttX on BL602 like so...

-   [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=_82og3-gEwA)

Let's study the script output: [__upstream-2022-01-21__](https://github.com/lupyuen/incubator-nuttx/releases/tag/upstream-2022-01-21)

![Auto Flash and Test Script](https://lupyuen.github.io/images/auto-run.png)

## Download NuttX

Our script begins by [__downloading Today's Upstream Build__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L20-L40) of NuttX: [upstream-2022-01-21](https://github.com/lupyuen/incubator-nuttx/releases/tag/upstream-2022-01-21)

```text
+ BUILD_PREFIX=upstream
+ BUILD_DATE=2022-01-21
----- Download the latest upstream NuttX build for 2022-01-21
+ wget -q https://github.com/lupyuen/incubator-nuttx/releases/download/upstream-2022-01-21/nuttx.zip -O /tmp/nuttx.zip
```

(__nuttx.zip__ is built daily by GitHub Actions, as explained in the Appendix)

Our script unzips __nuttx.zip__, which includes the following files...

```text
+ pushd /tmp
+ unzip -o nuttx.zip
Archive:  nuttx.zip
  inflating: nuttx
  inflating: nuttx.S
  inflating: nuttx.bin
  inflating: nuttx.config
  inflating: nuttx.hex
  inflating: nuttx.manifest
  inflating: nuttx.map
+ popd
```

-   __nuttx__: Firmware in ELF Format

-   __nuttx.bin__: Firmware Binary to be flashed

-   __nuttx.S__: RISC-V Disassembly for the firmware

-   __nuttx.map__: Linker Map for the firmware

-   __nuttx.config__: Build Configuration (from .config)

## Flash NuttX

Next we switch BL602 to __Flashing Mode__ by flipping GPIO 2 and 3 (which we've seen earlier)...

```text
Enable GPIO 2 and 3
Set GPIO 2 and 3 as output
Set GPIO 2 to High (BL602 Flashing Mode)
Toggle GPIO 3 High-Low-High (Reset BL602)
Toggle GPIO 3 High-Low-High (Reset BL602 again)
BL602 is now in Flashing Mode
```

We flash the downloaded NuttX Firmware __nuttx.bin__ to BL602 with [__blflash__](https://github.com/spacemeowx2/blflash)...

```text
----- Flash BL602 over USB UART with blflash
+ blflash flash /tmp/nuttx.bin --port /dev/ttyUSB0
Start connection...
Connection Succeed
Sending eflash_loader...
Entered eflash_loader
Program flash...
Success
```

## Boot NuttX

After flashing, we switch BL602 back to __Normal Mode__ by flipping GPIO 2 and 3...

```text
Set GPIO 2 to Low (BL602 Normal Mode)
Toggle GPIO 3 High-Low-High (Reset BL602)
BL602 is now in Normal Mode
Toggle GPIO 3 High-Low-High (Reset BL602)
```

BL602 boots the NuttX Firmware and starts the __NuttX Shell__...

```text
----- Here is the BL602 Output...
gpio_pin_register: Registering /dev/gpio0
gpio_pin_register: Registering /dev/gpio1
gpint_enable: Disable the interrupt
gpio_pin_register: Registering /dev/gpio2
bl602_spi_setfrequency: frequency=400000, actual=0
bl602_spi_setbits: nbits=8
bl602_spi_setmode: mode=0

NuttShell (NSH) NuttX-10.2.0
nsh>
```

## Test NuttX

Our script [__sends a Test Command__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L106-L111) to BL602 and the NuttX Shell...

```text
----- Send command to BL602: lorawan_test
lorawan_test
nsh: lorawan_test: command not found
nsh>
```

__lorawan_test__ is missing because the Upstream Build doesn't include the LoRaWAN Stack.

But that's OK, we'll see LoRaWAN in action when we test the Release Build of NuttX.

```text
===== Boot OK
```

Our script [__analyses the output__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L113-L134) and determines that NuttX has booted successfully. 

We're done with the __simplest scenario__ for Auto Flash and Test! Now we have a quick and nifty way to discover if Today's Upstream Build of NuttX boots OK on BL602.

[(I run the script every day to check the stability of the BL602 build)](https://github.com/lupyuen/incubator-nuttx/releases)

![Flash & Test NuttX on BL602... Remotely from a Phone!](https://lupyuen.github.io/images/auto-remote.png)

# NuttX Crash Analysis

_What happens when NuttX crashes during testing?_

NuttX shows a __Stack Trace__ like this...

![NuttX Stack Trace](https://lupyuen.github.io/images/auto-stack.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/releases/tag/upstream-2022-01-17)

Let's walk through the steps to __decode the Stack Trace__, then we'll learn how our script decodes the Stack Trace for us.

## Decode Stack Trace

At the top is the __Assertion Failure__ message...

```text
irq_unexpected_isr: ERROR irq: 1
up_assert: Assertion failed at file:irq/irq_unexpectedisr.c line: 51 task: Idle Task
```

__Always enable Debug Assertions__ in our NuttX Build Configuration. They are super helpful for catching problems. [(Here's how)](https://lupyuen.github.io/articles/spi2#enable-logging)

Next we see the __Register Dump__...

```text
riscv_registerdump: EPC: deadbeee
riscv_registerdump: A0: 00000002 A1: 420146b0 A2: 42015140 A3: 420141c
riscv_registerdump: A4: 420150d0 A5: 00000000 A6: 00000002 A7: 00000000
riscv_registerdump: T0: 00006000 T1: 00000003 T2: 41bd5588 T3: 00000064
riscv_registerdump: T4: 00000000 T5: 00000000 T6: c48ae7e4
riscv_registerdump: S0: deadbeef S1: deadbeef S2: 420146b0 S3: 42014000
riscv_registerdump: S4: 42015000 S5: 42012510 S6: 00000001 S7: 23007000
riscv_registerdump: S8: 4201fa38 S9: 00000001 S10: 00000c40 S11: 42010510
riscv_registerdump: SP: 420126b0 FP: deadbeef TP: 0c8a646d RA: deadbeef
```

Followed by the __Interrupt Stack__...

```text
riscv_dumpstate: sp:     420144b0
riscv_dumpstate: IRQ stack:
riscv_dumpstate:   base: 42012540
riscv_dumpstate:   size: 00002000
```

The __Stack Dump__...

```text
riscv_stackdump: 420144a0: 00001fe0 23011000 420144f0 230053a0 deadbeef deadbeef 23010ca4 00000033
riscv_stackdump: 420144c0: deadbeef 00000001 4201fa38 23007000 00000001 42012510 42015000 00000001
riscv_stackdump: 420144e0: 420125a8 42014000 42014500 230042e2 42014834 80007800 42014510 23001d3e
riscv_stackdump: 42014500: 420171c0 42014000 42014520 23001cdc deadbeef deadbeef 42014540 23000db4
riscv_stackdump: 42014520: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef 00000000 23000d04
```

The __User Stack__...

```text
riscv_dumpstate: sp:     420126b0
riscv_dumpstate: User stack:
riscv_dumpstate:   base: 42010530
riscv_dumpstate:   size: 00001fe0
```

Finally the __Task List__...

```text
riscv_showtasks:    PID    PRI      USED     STACK   FILLED    COMMAND
riscv_showtasks:   ----   ----      8088      8192    98.7%!   irq
riscv_dump_task:      0      0       436      8160     5.3%    Idle Task
riscv_dump_task:      1    100       516      8144     6.3%    nsh_main
```

(The Interrupt Stack __irq__ seems to be overflowing, it might have caused NuttX to crash)

In a while we'll select the interesting addresses from above and decode them.

## Disassemble The Firmware

Before decoding the addresses, let's prepare the __RISC-V Disassembly__ of our BL602 Firmware...

```bash
## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/.github/workflows/bl602.yml#L109-L114)

This generates the Disassembly File __nuttx.S__, which we'll use in the next step.

[(Here's a sample __nuttx.S__)](https://github.com/lupyuen/incubator-nuttx/releases/download/upstream-2022-01-17/nuttx.zip)

## Decode Addresses

From the Stack Trace above, we look for __Code and Data Addresses__ in the and decode them...

-   __BL602 Code Addresses__ have the form __`23xxxxxx`__

-   __BL602 Data Addresses__ have the form __`42xxxxxx`__

Let's pick a Code Address: __`230053a0`__

We search for the address in the Disassembly File [__nuttx.S__](https://github.com/lupyuen/incubator-nuttx/releases/download/upstream-2022-01-17/nuttx.zip) like so...

```bash
grep \
  --context=5 \
  --color=auto \
  "230053a0:" \
  nuttx.S
```

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L153-L166)

Which shows...

```text
nuttx/arch/risc-v/src/common/riscv_assert.c:364
  if (CURRENT_REGS)
    sp = CURRENT_REGS[REG_SP];
```

This is the __Source Code__ for address __`230053a0`__.

Repeat this process for the __other Code Addresses__: `230042e2`, `23001cdc`, `23000db4`, `23000d04`, ...

And we should have a fairly good idea how our firmware crashed.

_What about the Data Addresses `42xxxxxx`?_

Let's pick a Data Address: __`42012510`__

We search for the address in the Disassembly File [__nuttx.S__](https://github.com/lupyuen/incubator-nuttx/releases/download/upstream-2022-01-17/nuttx.zip) like this...

```bash
grep \
  --color=auto \
  "^42012510" \
  nuttx.S \
  | grep -v "noinit"
```

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L177-L190)

Which shows...

```text
42012510 ... g_idleargv
```

This says that __g_idleargv__ is the name of the variable at address __`42012510`__.

![Auto Crash Analysis](https://lupyuen.github.io/images/auto-stack2.png)

## Auto Analysis

TODO

Now our Crash Analysis Script shows the matching Source Code whenever #NuttX crashes 👍

![](https://lupyuen.github.io/images/auto-stack3.png)

We also match up the Data Addresses in the #NuttX Stack Trace with the RISC-V Disassembly ... Not very interesting now, might be useful later

![](https://lupyuen.github.io/images/auto-stack4.png)

Here's a demo of #BL602 Auto Flash & Test ... With #NuttX Crash Analysis

[__Watch the demo on YouTube__](https://www.youtube.com/watch?v=Kf3G1hGoLIs)

# LoRaWAN Test

TODO9

```bash
##  Download the Release Build (instead of the Upstream Build)
export BUILD_PREFIX=release

##  Download this date of the build
export BUILD_DATE=2022-01-19

##  Run the script
remote-bl602/scripts/test.sh
```

[release-2022-01-19](https://github.com/lupyuen/incubator-nuttx/releases/tag/release-2022-01-19)

We update #BL602 Auto Flash & Test to send the "lorawan_test" command ... Which will start the LoRaWAN Test on #NuttX OS

![](https://lupyuen.github.io/images/auto-script3.png)

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L108-L111)

#BL602 Auto Flash & Test ... Now auto-tests the #LoRaWAN Stack on Apache #NuttX OS! 🎉

[__Watch the demo on YouTube__](https://www.youtube.com/watch?v=JtnOyl5cYjo)

[(Source)](https://github.com/lupyuen/remote-bl602/)

TODO4

#LoRaWAN is a great Auto-Test for Apache #NuttX OS ... It tests GPIO Input / Output / Interrupt, SPI, Timers, Message Queues, PThreads AND Strong Random Number Generator!

![](https://lupyuen.github.io/images/auto-lorawan.png)

[(Source)](https://github.com/lupyuen/remote-bl602/)

TODO5

If #BL602 Auto-Test successfully joins a #LoRaWAN Network ... Means that everything is super hunky dory on Apache #NuttX OS ... GPIO Input / Output / Interrupt, SPI, Timers, Message Queues, PThreads AND Strong Random Number Generator! 👍

![](https://lupyuen.github.io/images/auto-lorawan2.png)

[(Source)](https://github.com/lupyuen/remote-bl602/#output-log-for-release-build)

# Merge Updates From NuttX

TODO16

```bash
##  Download the Downstream Build (instead of the Upstream Build)
export BUILD_PREFIX=downstream

##  Download this date of the build
export BUILD_DATE=2022-01-19

##  Run the script
remote-bl602/scripts/test.sh
```

[downstream-2022-01-19](https://github.com/lupyuen/incubator-nuttx/releases/tag/downstream-2022-01-19)

Merged a huge bunch of #NuttX Upstream Updates ... LoRaWAN still works great! 🎉 Testing upstream updates is so much easier with #BL602 Auto Flash & Test 👍

![](https://lupyuen.github.io/images/auto-merge.png)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/auto.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/auto.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1482152780051935238)

# Appendix: Build NuttX with GitHub Actions

TODO15

Let's Auto-Flash & Test the Daily Upstream Build of Apache #NuttX OS ... Auto-Built & Published by GitHub Actions

![](https://lupyuen.github.io/images/auto-script.png)

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L17-L21)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/.github/workflows/bl602.yml#L82-L112)

Here's how we configure our #NuttX Build in GitHub Actions ... To enable errors, warnings, info messages and assertions

![](https://lupyuen.github.io/images/auto-workflow2.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/.github/workflows/bl602.yml#L59-L63)

TODO89

Here's how we enable #LoRaWAN for our #NuttX Build in GitHub Actions ... Let's do Automated NuttX Testing with LoRaWAN! 👍

![](https://lupyuen.github.io/images/auto-workflow3.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/.github/workflows/bl602-commit.yml#L91-L200)

TODO2

![](https://lupyuen.github.io/images/auto-crash.png)

TODO3

![](https://lupyuen.github.io/images/auto-crash2.png)

TODO14

![](https://lupyuen.github.io/images/auto-workflow.png)

# Appendix: Fix LoRaWAN Nonce

TODO

#BL602 Auto Flash & Test creates Duplicate #LoRaWAN Nonces ... Because the Boot Timing is always identical! Let's fix this by adding Internal Temperature Sensor Data to the Entropy Pool

![](https://lupyuen.github.io/images/auto-nonce.png)

[(Source)](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce)

TODO

Here's how we read #BL602's Internal Temperature Sensor ... And add the data to the Entropy Pool in #NuttX OS ... To create truly random LoRaWAN Nonces

![](https://lupyuen.github.io/images/auto-nonce2.png)

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L772-L797)

TODO

#NuttX now generates different #LoRaWAN Nonces for every #BL602 Flash & Test ... And the Join Network Request always succeeds! 🎉

![](https://lupyuen.github.io/images/auto-nonce3.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/releases/tag/release-2022-01-19)
