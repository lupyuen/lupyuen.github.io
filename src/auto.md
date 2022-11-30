# Auto Flash and Test NuttX on RISC-V BL602

📝 _26 Jan 2022_

![PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test](https://lupyuen.github.io/images/auto-title.jpg)

_PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test_

[__UPDATE:__ Check out the new article on Automated Testing for PineDio Stack BL604](https://lupyuen.github.io/articles/auto2)

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

-   BL602 Devs can easily download the __latest tested build__ from GitHub Releases...

    [__NuttX Releases for BL602__](https://github.com/lupyuen/nuttx/releases?q=%22download%2Frelease%22&expanded=true)

_Will this work for other microcontrollers?_

-   __ESP32__ has 2 buttons for flashing (BOOT and EN), very similar to BL602. Our Auto Flash and Test Script might work for ESP32 with some tweaking.

-   __Arm Microcontrollers__ may be auto flashed and debugged with an OpenOCD Script. [(Check out Remote PineTime)](https://github.com/lupyuen/remote-pinetime-bot)

![PineCone BL602 in Flashing Mode with GPIO 8 set to High. Sorry the jumper got mangled due to a soldering accident 🙏](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

_PineCone BL602 in Flashing Mode with GPIO 8 set to High. Sorry the jumper got mangled due to a soldering accident_ 🙏

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

    BL602 is now in __Normal Mode__. (Non-Flashing)

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

![GPIO 8 and Reset Pins](https://lupyuen.github.io/images/auto-connect2.jpg)

No more flipping the jumper and smashing the button! Let's control GPIO 8 and Reset Pins with our Linux SBC.

# Control GPIO with Linux

Recall that __GPIO 2 and 3__ on our Linux SBC are connected to BL602 for the __Flashing and Reset__ Functions...

| SBC    | BL602    | Function
| -------|----------|----------
| __GPIO 2__ | GPIO 8   | Flashing Mode
| __GPIO 3__ | RST      | Reset

Let's control GPIO 2 and 3 with a Bash Script...

-   [__remote-bl602/scripts/test.sh__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh)

![Control GPIO with Linux](https://lupyuen.github.io/images/auto-script2.png)

## Enable GPIO

Our Bash Script begins by __enabling GPIO 2 and 3__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L42-L48)

```bash
##  Enable GPIO 2 and 3 (if not already enabled)
if [ ! -d /sys/class/gpio/gpio2 ]; then
  echo  2 >/sys/class/gpio/export
  sleep 1
fi
if [ ! -d /sys/class/gpio/gpio3 ]; then
  echo  3 >/sys/class/gpio/export
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
echo  1 >/sys/class/gpio/gpio2/value
sleep 1
```

But to make it happen we need to restart BL602, coming up next...

## Reset BL602

To __restart BL602__ (and actually enter Flashing Mode), our script toggles GPIO 3 __High-Low-High__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L57-L65)

```bash
##  Toggle GPIO 3 High-Low-High (Reset BL602)
echo  1 >/sys/class/gpio/gpio3/value
sleep 1
echo  0 >/sys/class/gpio/gpio3/value
sleep 1
echo  1 >/sys/class/gpio/gpio3/value
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

[(__nuttx.bin__ is the Daily Upstream Build of NuttX OS, as explained in the Appendix)](https://lupyuen.github.io/articles/auto#appendix-build-nuttx-with-github-actions)

Our firmware has been flashed automagically!

## Exit Flashing Mode

Now we return to __Normal Mode__ (Non-Flashing) by setting GPIO 2 to __Low__: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L74-L80)

```bash
##  Set GPIO 2 to Low (BL602 Normal Mode)
echo  0 >/sys/class/gpio/gpio2/value
sleep 1
```

We effect the change by __restarting BL602__...

```bash
##  Toggle GPIO 3 High-Low-High (Reset BL602)
echo  1 >/sys/class/gpio/gpio3/value
sleep 1
echo  0 >/sys/class/gpio/gpio3/value
sleep 1
echo  1 >/sys/class/gpio/gpio3/value
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
echo  1 >/sys/class/gpio/gpio3/value ; sleep 1
echo  0 >/sys/class/gpio/gpio3/value ; sleep 1
echo  1 >/sys/class/gpio/gpio3/value ; sleep 1

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
sudo usermod -a -G gpio    $USER
sudo usermod -a -G dialout $USER

##  Logout and login to refresh the permissions
logout

##  Install Rust: https://rustup.rs/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

##  Add Rust to the PATH
source $HOME/.cargo/env

##  Install blflash
cargo install blflash

##  Download the script
git clone --recursive https://github.com/lupyuen/remote-bl602

##  Optional: Select the type of build (upstream / downstream / release)
##  export BUILD_PREFIX=upstream

##  Optional: Select the date of the build
##  export BUILD_DATE=2022-01-19

##  Run the script
remote-bl602/scripts/test.sh
```

(For Arch Linux and Manjaro: Change "dialout" to "uucp")

Our script flashes and runs NuttX on BL602 like so...

-   [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=_82og3-gEwA)

Let's study the script output: [__upstream-2022-01-21__](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-21)

![Auto Flash and Test Script](https://lupyuen.github.io/images/auto-run.jpg)

## Download NuttX

Our script begins by [__downloading Today's Upstream Build__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L20-L40) of NuttX: [upstream-2022-01-21](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-21)

```text
+ BUILD_PREFIX=upstream
+ BUILD_DATE=2022-01-21
----- Download the latest upstream NuttX build for 2022-01-21
+ wget -q \
  https://github.com/lupyuen/nuttx/releases/download/upstream-2022-01-21/nuttx.zip \
  -O /tmp/nuttx.zip
```

[(__nuttx.zip__ is built daily by GitHub Actions, as explained in the Appendix)](https://lupyuen.github.io/articles/auto#appendix-build-nuttx-with-github-actions)

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

[(I run the script every day to check the stability of the BL602 build)](https://github.com/lupyuen/nuttx/releases)

![Flash & Test NuttX on BL602... Remotely from a Phone!](https://lupyuen.github.io/images/auto-remote.jpg)

# NuttX Crash Analysis

_What happens when NuttX crashes during testing?_

NuttX shows a __Stack Trace__ like this...

![NuttX Stack Trace](https://lupyuen.github.io/images/auto-stack.jpg)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

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

![Stack Overflow?](https://lupyuen.github.io/images/auto-crash2.png)

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

[(Source)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602.yml#L109-L114)

This generates the Disassembly File __nuttx.S__, which we'll use in the next step.

[(Here's a sample __nuttx.S__)](https://github.com/lupyuen/nuttx/releases/download/upstream-2022-01-17/nuttx.zip)

## Decode Addresses

From the Stack Trace above, we look for __Code and Data Addresses__ and decode them...

-   __BL602 Code Addresses__ have the form __`23xxxxxx`__

-   __BL602 Data Addresses__ have the form __`42xxxxxx`__

Let's pick a Code Address: __`230053a0`__

We search for the address in the Disassembly File [__nuttx.S__](https://github.com/lupyuen/nuttx/releases/download/upstream-2022-01-17/nuttx.zip) like so...

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

(Which is in the Assertion Handler, doesn't look helpful)

Repeat this process for the __other Code Addresses__: `230042e2`, `23001cdc`, `23000db4`, `23000d04`, ...

And we should have a fairly good idea how our firmware crashed.

[(See the results)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

_What about the Data Addresses `42xxxxxx`?_

Let's pick a Data Address: __`42012510`__

We search for the address in the Disassembly File [__nuttx.S__](https://github.com/lupyuen/nuttx/releases/download/upstream-2022-01-17/nuttx.zip) like this...

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

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L136-L194)

## Auto Analysis

_Decoding a NuttX Stack Trace looks mighty tedious!_

Thankfully our __Auto Flash and Test__ Script automates everything for us!

-   When our script detects that [__NuttX has crashed__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L100-L103)...

-   It searches for all [__BL602 Code Addresses__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L143-L151) in the NuttX Stack Trace

-   And shows the [__matching Source Code__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L153-L166) for the Code Addresses

-   It does the same to [__decode BL602 Data Addresses__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L168-L190)

-   RISC-V Disassembly for the NuttX Firmware is [__generated by GitHub Actions__](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602.yml#L109-L114) during the Daily Upstream Build

Here's a demo of Auto Flash and Test with __Auto Crash Analysis__...

-   [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=Kf3G1hGoLIs)

-   [__See the Output Log__](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

The __Source Code__ decoded from a Stack Trace looks like this...

![Source Code decoded from Stack Trace](https://lupyuen.github.io/images/auto-stack3.png)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

These are the __Data Addresses__ decoded from the Stack Trace...

![Data Addresses in Stack Trace](https://lupyuen.github.io/images/auto-stack4.jpg)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

There's a __Design Flaw__ in our script that needs fixing... It doesn't detect crashes while running the SPI, LoRaWAN and Touch Panel Tests. [(See this)](https://gist.github.com/lupyuen/02764452fde605e04b626614be4562ed)

(We should probably use a __State Machine__ instead of a long chain of hacky "if-else" statements)

# LoRaWAN Test

_What's the best way to auto-test all the NuttX functions: GPIO, SPI, ADC, Interrupts, Timers, Threads, Message Queues, Random Number Generator, ...?_

[__LoRaWAN__](https://lupyuen.github.io/articles/lorawan3) is the perfect way to give NuttX a __thorough workout__!

-   __GPIO Input__: LoRaWAN reads a GPIO Input to poll the [__Busy State__](https://lupyuen.github.io/articles/sx1262#check-busy-state) of the LoRa Transceiver

-   __GPIO Output__: [__Chip Select__](https://lupyuen.github.io/articles/sx1262#initialise-spi) for the LoRa Transceiver

-   __GPIO Interrupt__: Triggered by LoRa Transceiver when a [__LoRa Packet is received__](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt)

-   __SPI__: LoRa Transceiver talks on the [__SPI Bus__](https://lupyuen.github.io/articles/sx1262#initialise-spi)

-   __ADC__: Used by the Internal Temperature Sensor (See below)

-   __Timer__: Triggers the [__periodic sending__](https://lupyuen.github.io/articles/lorawan3#message-interval) of Data Packets

-   __Message Queue__: Handles [__Transmit / Receive / Timeout Events__](https://lupyuen.github.io/articles/sx1262#event-queue)

-   __PThread__: LoRaWAN handles events with a [__Background Thread__](https://lupyuen.github.io/articles/sx1262#start-dio1-thread)

-   __Strong Random Number Generator__: Generates non-repeating [__LoRaWAN Nonces__](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce)

-   __Internal Temperature Sensor__: Seeds the Entropy Pool for the Random Number Generator [(Here's why)](https://lupyuen.github.io/articles/auto#appendix-fix-lorawan-nonce)

We shall run this __LoRaWAN Stack__ to connect to the LoRaWAN Network (ChirpStack) and transmit a Data Packet...

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

To run the __LoRaWAN Auto-Test__ we switch to the __Release Build__ (instead of the Upstream Build)...

```bash
##  Download the Release Build (instead of the Upstream Build)
export BUILD_PREFIX=release

##  Download this date of the build
export BUILD_DATE=2022-01-19

##  Run the script
remote-bl602/scripts/test.sh
```

(Release Build includes the LoRaWAN Stack)

After booting NuttX, our script sends the __Test LoRaWAN__ command to the NuttX Shell: [test.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L106-L116)

```bash
##  If BL602 has not crashed, send the test command to BL602
echo "lorawan_test" >/dev/ttyUSB0

##  Wait a while for the test command to run
sleep 30

##  Check whether BL602 has joined the LoRaWAN Network
set +e  ##  Don't exit when any command fails
match=$(grep "JOINED" /tmp/test.log)
set -e  ##  Exit when any command fails
```

And it watches for this output message...

```text
###### =========== MLME-Confirm ============ ######
STATUS: OK
###### ===========   JOINED     ============ ######
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

Which means that BL602 has successfully joined the __LoRaWAN Network__...

```text
===== All OK! BL602 has successfully joined the LoRaWAN Network
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

And everything has tested OK on NuttX!

![BL602 successfully joins the LoRaWAN Network](https://lupyuen.github.io/images/auto-lorawan2.png)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

Here's the demo of the __LoRaWAN Auto-Test__...

-   [__Watch the demo on YouTube__](https://www.youtube.com/watch?v=JtnOyl5cYjo)

-   [__See the Output Log__](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

![LoRaWAN Auto-Test](https://lupyuen.github.io/images/auto-lorawan.png)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

# Merge Updates From NuttX

_Back to our original question: Why are we doing all this?_

My situation is kinda complicated, I need to worry about __3 branches__ of the NuttX Code...

-   __Upstream Branch__: Daily Upstream Updates from from the [__master branch__](https://github.com/apache/nuttx) of Apache's NuttX Repo

    (Without the LoRaWAN Stack)

-   __Release Branch__: This is the [__master branch__](https://github.com/lupyuen/nuttx) of my repo that I reference in my NuttX Articles

    (Includes the LoRaWAN Stack)

-   __Downstream Branch__: This is the [__downstream branch__](https://github.com/lupyuen/nuttx/tree/downstream) of my repo that merges the updates from the above 2 branches

    (Includes the LoRaWAN Stack)

This is how we keep them __in sync__...

![Merge Updates From NuttX](https://lupyuen.github.io/images/auto-merge.jpg)

1.  We __build Upstream NuttX__ every day with GitHub Actions. [(See this)](https://lupyuen.github.io/articles/auto#appendix-build-nuttx-with-github-actions)

    We run our __Auto Flash and Test__ Script daily to check if the build boots OK on BL602.

    (Upstream NuttX doesn't include the LoRaWAN Stack)

2.  If the Upstream Build is OK, we __merge Upstream NuttX__ into our Downstream Branch.

3.  We also __merge the Release Branch__ (from our previous NuttX Article) to the Downstream Branch.

    (Which includes the LoRaWAN Stack)

4.  After merging the branches, we run __Auto Flash and Test__ to verify that LoRaWAN runs OK on BL602.

5.  If LoRaWAN runs OK, we __merge the Downstream Branch__ to the Release Branch.

6.  We run __Auto Flash and Test__ one last time on the Release Branch to be really sure that LoRaWAN is still OK.

7.  We feature the __updated Release Branch__ in our next NuttX Article.

Looks complicated, but that's how we keep our NuttX Articles in sync with the latest updates from Upstream NuttX.

(Which ensures that the code in our NuttX Articles won't go obsolete too soon)

_How do we run Auto Flash and Test on the Downstream Build?_

Like this...

```bash
##  Download the Downstream Build (instead of the Upstream Build)
export BUILD_PREFIX=downstream

##  Download this date of the build
export BUILD_DATE=2022-01-19

##  Run the script
remote-bl602/scripts/test.sh
```

[(See the output)](https://github.com/lupyuen/nuttx/releases/tag/downstream-2022-01-19)

_Can we solve this by merging the LoRaWAN Stack upstream?_

The LoRaWAN Stack is __not ready to be upstreamed__ because it uses different Coding Conventions. [(See this)](https://lupyuen.github.io/articles/lorawan3#notes)

Even if we could, we would need an __automated, remote way to test__ if the LoRaWAN Stack is still working when there are changes to Upstream NuttX.

(Our Auto Flash and Test Script would be super helpful here)

But for now... No more worries about merging hundreds of upstream commits (and thousands of changed files) into our NuttX Repo! 👍

![Merge updates from upstream](https://lupyuen.github.io/images/auto-merge.png)

[(Source)](https://github.com/lupyuen/nuttx/pull/21)

# What's Next

[__UPDATE:__ Check out the new article on Automated Testing for PineDio Stack BL604](https://lupyuen.github.io/articles/auto2)

After 14 months of flipping the jumper and smashing the button on BL602, I'm so glad we have an automated way to Flash and Test BL602!

I hope the Flash and Test Script will make your NuttX Development more productive on BL602... Possibly on other microcontrollers too!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/sbzwon/auto_flash_and_test_nuttx_on_riscv_bl602/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/auto.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/auto.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1482152780051935238)

![Building NuttX with GitHub Actions](https://lupyuen.github.io/images/auto-workflow.jpg)

# Appendix: Build NuttX with GitHub Actions

We auto-build the Upstream (Apache) version of NuttX every day with __GitHub Actions__, producing these files...

-   __nuttx__: Firmware in ELF Format

-   __nuttx.bin__: Firmware Binary to be flashed

-   __nuttx.S__: RISC-V Disassembly for the firmware

-   __nuttx.map__: Linker Map for the firmware

-   __nuttx.config__: Build Configuration (from .config)

Which are consumed by our Flash and Test Script.

In this section we study the workflow for the Upstream Build...

-   [__Upstream Build:__ .github/workflows/bl602.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602.yml)

Similar workflows are used for the Release and Downstream Builds...

-   [__Release Build:__ .github/workflows/bl602-commit.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml)

-   [__Downstream Build:__ .github/workflows/bl602-downstream.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-downstream.yml)

## Build Schedule

The Upstream Build is scheduled __every day at 0:30 UTC__: [bl602.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602.yml)

```yaml
name: BL602 Upstream
on:
  ## Run every day at 0:30 UTC, because 0:00 UTC seems too busy for the scheduler
  schedule:
    - cron: '30 0 * * *'
```

(The build will actually start at around __1:45 UTC__, depending on the available server capacity at GitHub Actions)

Note that the scheduled run is __not guaranteed__, it may be cancelled if GitHub Actions is too busy. [(See this)](https://github.community/t/no-assurance-on-scheduled-jobs/133753/2)

## Install Build Tools

First we install the __Build Tools__ needed by NuttX...

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Install Build Tools
      run:  |
        sudo apt -y update
        sudo apt -y install \
          bison flex gettext texinfo libncurses5-dev libncursesw5-dev \
          gperf automake libtool pkg-config build-essential gperf genromfs \
          libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev \
          libexpat-dev gcc-multilib g++-multilib u-boot-tools util-linux \
          kconfig-frontends \
          wget
```

## Install Toolchain

We download the __RISC-V GCC Toolchain__ (riscv64-unknown-elf-gcc) hosted at SiFive...

```yaml
    - name: Install Toolchain
      run:  |
        wget https://static.dev.sifive.com/dev-tools/riscv64-unknown-elf-gcc-8.3.0-2019.08.0-x86_64-linux-ubuntu14.tar.gz
        tar -xf riscv64-unknown-elf-gcc*.tar.gz
```

## Checkout Source Files

We checkout the __NuttX Source Files__ from the Apache repo...

```yaml
    - name: Checkout Source Files
      run:  |
        mkdir nuttx
        cd nuttx
        git clone https://github.com/apache/nuttx nuttx
        git clone https://github.com/apache/nuttx-apps apps
```

[(For Release and Downstream Builds we checkout from the repo __lupyuen/nuttx__)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L37-L42)

We're almost ready to build NuttX, but first we configure the NuttX Build.

![Enable errors, warnings, info messages and assertions](https://lupyuen.github.io/images/auto-workflow2.png)

[(Source)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602.yml#L50-L114)

## Configure Build

For the NuttX Build we __configure BL602__ as the target...

```yaml          
    - name: Build
      run: |
        ## Add toolchain to PATH
        export PATH=$PATH:$PWD/riscv64-unknown-elf-gcc-8.3.0-2019.08.0-x86_64-linux-ubuntu14/bin
        cd nuttx/nuttx
        
        ## Configure the build
        ./tools/configure.sh bl602evb:nsh
```

This creates the Build Config File __.config__.

Then we tweak the Build Config to show __Errors, Warnings, Info Messages and Assertions__...

```yaml        
        ## Enable errors, warnings, info messages and assertions
        kconfig-tweak --enable CONFIG_DEBUG_ERROR
        kconfig-tweak --enable CONFIG_DEBUG_WARN
        kconfig-tweak --enable CONFIG_DEBUG_INFO
        kconfig-tweak --enable CONFIG_DEBUG_ASSERTIONS

        ## Enable GPIO errors, warnings and info messages
        kconfig-tweak --enable CONFIG_DEBUG_GPIO
        kconfig-tweak --enable CONFIG_DEBUG_GPIO_ERROR
        kconfig-tweak --enable CONFIG_DEBUG_GPIO_WARN
        kconfig-tweak --enable CONFIG_DEBUG_GPIO_INFO

        ## Enable SPI errors, warnings and info messages
        kconfig-tweak --enable CONFIG_DEBUG_SPI
        kconfig-tweak --enable CONFIG_DEBUG_SPI_ERROR
        kconfig-tweak --enable CONFIG_DEBUG_SPI_WARN
        kconfig-tweak --enable CONFIG_DEBUG_SPI_INFO
```

[(See this)](https://lupyuen.github.io/articles/spi2#enable-logging)

We enable __Floating Point, Stack Canaries__ and 2 commands: __"help" and "ls"__...

```yaml
        ## Enable Floating Point
        kconfig-tweak --enable CONFIG_LIBC_FLOATINGPOINT

        ## Enable Compiler Stack Canaries
        kconfig-tweak --enable CONFIG_STACK_CANARIES

        ## Enable NuttX Shell commands: help, ls
        kconfig-tweak --disable CONFIG_NSH_DISABLE_HELP
        kconfig-tweak --disable CONFIG_NSH_DISABLE_LS
```

We enable the __GPIO Driver and Test App__...

```yaml
        ## Enable GPIO
        kconfig-tweak --enable CONFIG_DEV_GPIO
        kconfig-tweak --set-val CONFIG_DEV_GPIO_NSIGNALS 1

        ## Enable GPIO Test App
        kconfig-tweak --enable CONFIG_EXAMPLES_GPIO
        kconfig-tweak --set-str CONFIG_EXAMPLES_GPIO_PROGNAME "gpio"
        kconfig-tweak --set-val CONFIG_EXAMPLES_GPIO_PRIORITY 100
        kconfig-tweak --set-val CONFIG_EXAMPLES_GPIO_STACKSIZE 2048
```

[(See this)](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

We enable the __BL602 SPI Driver__...

```yaml
        ## Enable SPI
        kconfig-tweak --enable CONFIG_BL602_SPI0
        kconfig-tweak --enable CONFIG_SPI
        kconfig-tweak --enable CONFIG_SPI_EXCHANGE
        kconfig-tweak --enable CONFIG_SPI_DRIVER
```

[(See this)](https://lupyuen.github.io/articles/spi2#enable-spi)

Finally we copy the Build Config to __nuttx.config__ so that we may download and inspect later...

```yaml
        ## Preserve the build config
        cp .config nuttx.config
```

We're ready to build NuttX!

[(For Release and Downstream Builds we also enable the LoRaWAN Stack)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L130-L217)

![For the Release and Downstream Builds we also enable the LoRaWAN Stack](https://lupyuen.github.io/images/auto-workflow3.jpg)

[(Source)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L130-L217)

## Build NuttX

This builds the __NuttX Firmware__...

```yaml
        ## Run the build
        make
```

Which creates the Firmware Binary __nuttx.bin__ (for flashing) and the Firmware ELF __nuttx__.

(The build completes in under 3 minutes)

We dump the __RISC-V Disassembly__ of the Firmware ELF to __nuttx.S__...

```yaml
        ## Dump the disassembly to nuttx.S
        riscv64-unknown-elf-objdump \
          -t -S --demangle --line-numbers --wide \
          nuttx \
          >nuttx.S \
          2>&1
```

__nuttx.S__ will be used by our Flash and Test Script to do Crash Analysis.

## Upload Build Outputs

We upload all __Build Outputs__ (including the Build Config __nuttx.config__) as Artifacts so that we may download later...

```yaml
    - name: Upload Build Outputs
      uses: actions/upload-artifact@v2
      with:
        name: nuttx.zip
        path: nuttx/nuttx/nuttx*
```

The NuttX Build Outputs are now available for downloading as Artifacts, but they are __protected by GitHub Login__.

To allow our Flash and Test Script to access the files without GitHub Authentication, we publish the files as a __GitHub Release__...

## Publish Release

The final task in our GitHub Actions workflow is to publish the NuttX Build Outputs as a __GitHub Release__.

(Which will be downloaded by our Flash and Test Script)

Let's run through the steps to __publish a GitHub Release__ that looks like this...

-   [__upstream-2022-01-19__](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-19)

First we zip the NuttX Build Outputs into __nuttx.zip__...

```yaml
    - name: Zip Build Outputs
      run: |
        cd nuttx/nuttx
        zip nuttx.zip nuttx*
```

Next we get the Current Date: __2022-01-19__

```yaml
    - name: Get Current Date
      id: date
      run: echo "::set-output name=date::$(date +'%Y-%m-%d')"
```

We create a __Draft Release__ tagged as __upstream-2022-01-19__...

```yaml        
    - name: Create Draft Release
      id: create_release
      uses: actions/create-release@v1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        tag_name: upstream-${{ steps.date.outputs.date }}
        release_name: upstream-${{ steps.date.outputs.date }}
        draft: true
        prerelease: false
```

We upload __nuttx.zip__ to the Draft Release...

```yaml
    - name: Upload Release
      uses: actions/upload-release-asset@v1.0.1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        upload_url: ${{ steps.create_release.outputs.upload_url }}
        asset_path: nuttx/nuttx/nuttx.zip
        asset_name: nuttx.zip
        asset_content_type: application/zip
```

And __publish the Release__...

```yaml
    - name: Publish Release
      uses: eregon/publish-release@v1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        release_id: ${{ steps.create_release.outputs.id }}
```

The end! That's how we build Upstream NuttX every day and publish the Build Outputs.

Check out the workflows for the __Release and Downstream__ Builds...

-   [__Release Build:__ .github/workflows/bl602-commit.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml)

-   [__Downstream Build:__ .github/workflows/bl602-downstream.yml](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-downstream.yml)

_How are they different from the Upstream Build?_

The __Release and Downstream__ Builds...

-   Are __triggered by commits__ to the Release (master) and Downstream Branches (instead of scheduled time)

    [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L5-L14)

-   Checkout the Source Files from a different repo: __lupyuen/nuttx__

    [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L37-L42)

-   Enable the __LoRaWAN Stack__

    [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L130-L217)

-   Update the __BL602 Pin Definitions__ to accommodate the Semtech SX1262 LoRa Transceiver

    [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L44-L80)

![Duplicate LoRaWAN Nonce](https://lupyuen.github.io/images/auto-nonce.png)

# Appendix: Fix LoRaWAN Nonce

_What's a LoRaWAN Nonce?_

Our LoRaWAN Stack transmits a random number called a __Nonce__ when it joins a LoRaWAN Network.

To prevent [__Replay Attacks__](https://en.wikipedia.org/wiki/Replay_attack), the Nonce __must be unique__ and should never be reused.

[(More about the Join Nonce)](https://lupyuen.github.io/articles/wisgate#nonce)

_Is there a problem with LoRaWAN Nonces?_

Our LoRaWAN Gateway (ChirpStack) says that it has detected __Duplicate Nonces__. ("validate dev-nonce error" in the pic above)

Because of Duplicate Nonces, our device __can't join the LoRaWAN Network__. (Until after repeated retries)

_But our LoRaWAN Nonces are totally random right?_

We generate Nonces with NuttX's __Strong Random Number Generator__ with __Entropy Pool__.

Which generates totally random numbers in the __real world__.

But our Auto Flash and Test Script boots and runs NuttX __so predictably__ that the __same random numbers are re-generated__ at each boot.

[(More about Strong Random Number Generator)](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce)

_How shall we fix our LoRaWAN Nonces?_

To fix this, we take data from an unpredictable source: __Internal Temperature Sensor__...

And feed the Temperature Sensor Data into NuttX's __Entropy Pool__.

So that the Strong Random Number Generator will generate totally random numbers once again.

This is how we do it: [lorawan_test/lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L772-L797)

```c
//  If we are using Entropy Pool and the BL602 ADC is available,
//  add the Internal Temperature Sensor data to the Entropy Pool.
//  This prevents duplicate Join Nonce during BL602 Auto Flash and Test.
static void init_entropy_pool(void) {
  //  Repeat 4 times to get good entropy (16 bytes)
  for (int i = 0; i < 4; i++) {
    //  Read the Internal Temperature Sensor
    float temp = 0.0;
    get_tsen_adc(&temp, 1);

    //  Add Sensor Data (4 bytes) to Entropy Pool
    up_rngaddentropy(                  //  Add integers to Entropy Pool...
      RND_SRC_SENSOR,                  //  Source is Sensor Data
      (FAR const uint32_t *) &temp,    //  Integers to be added
      sizeof(temp) / sizeof(uint32_t)  //  How many integers (1)
    );
  }

  //  Force reseeding random number generator from entropy pool
  up_rngreseed();
}
```

[(__get_tsen_adc__ is defined here)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L706-L770)

[(__get_tsen_adc__ calls BL602 ADC Library, which will be replaced by BL602 ADC Driver when it's available)](https://github.com/lupyuen/bl602_adc)

This code adds 4 bytes of Temperature Sensor Data 4 times, adding a total of __16 bytes to the Entropy Pool__.

(Which should be sufficiently unpredictable!)

The output shows that the __Internal Temperature__ is indeed random: [release-2022-01-19](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh> lorawan_test

init_entropy_pool
temperature = 30.181866 Celsius
temperature = 29.794918 Celsius
temperature = 30.439829 Celsius
temperature = 28.376112 Celsius
```

Our LoRaWAN Stack now generates __different LoRaWAN Nonces__ for every Flash and Test. And the Join Network Request always succeeds! 🎉

![Join Network Request always succeeds](https://lupyuen.github.io/images/auto-nonce3.jpg)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-19)
