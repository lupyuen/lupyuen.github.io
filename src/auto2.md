# (Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board

📝 _22 May 2022_

![PineDio Stack BL604 (left, with unglam rubber band) and PineCone BL602 (right) connected to Single-Board Computer for Automated Testing](https://lupyuen.github.io/images/auto2-title.jpg)

_PineDio Stack BL604 (left, with unglam rubber band) and PineCone BL602 (right) connected to Single-Board Computer for Automated Testing_

Pine64 is about to launch their most exciting RISC-V IoT gadget: [__PineDio Stack BL604 RISC-V Board__](https://lupyuen.github.io/articles/pinedio2) with Touch Screen, LoRa and many other features.

This is a cautionary tale concerning Alice, Bob and Chow, the __(Hypothetical) Embedded Devs__ collaborating remotely on the newly-released PineDio Stack...

> __Alice__: Hi All! I'm building an __I2C Driver__ for PineDio Stack's Accelerometer. Where can I get the latest build of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/pinedio2) for PineDio Stack?

> __Bob__: You'll have to compile it yourself from the [__source code here__](https://github.com/lupyuen/nuttx/tree/pinedio). But beware... Some folks reported (unconfirmed) that it might run differently depending on the RISC-V Compiler Toolchain.

> __Chow__: OH CR*P! PineDio Stack's [__I2C Touch Panel__](https://lupyuen.github.io/articles/touch) is no longer responding to touch! What changed?!

> __Alice__: Is it because of the I2C Accelerometer Driver that I just committed to the repo?

> __Bob__: Uhhh I think it might be the BL602 Updates from [__NuttX Mainline__](https://github.com/apache/nuttx) that I merged last night. I __forgot to test__ the changes. I think [__SPI and LoRaWAN__](https://lupyuen.github.io/articles/lorawan3) are broken too. Sorry!

Sounds like a nightmare, but this story could be real. [__Robert Lipe__](https://www.robertlipe.com/) and I are already facing similar challenges today.

Let's intervene and rewrite the narrative...

> __Alice__: Hi All! I'm building an __I2C Driver__ for PineDio Stack's Accelerometer. Where can I get the latest build of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/pinedio2) for PineDio Stack?

> __Bob__: Just download the Compiled Firmware from the [__GitHub Releases here__](https://github.com/lupyuen/nuttx/releases?q=%22download%2Fpinedio%22&expanded=true). It was [__built automatically__](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml#L33-L76) by GitHub Actions with the same RISC-V Compiler Toolchain that we're all using.

> __Chow__: Hmmm PineDio Stack's [__I2C Touch Panel__](https://lupyuen.github.io/articles/touch) works a little wonky today. What changed?

> __Alice__: It can't be caused by my new I2C Accelerometer Driver. My changes to the repo are still awaiting __Automated Testing__.

> __Bob__: I merged the BL602 Updates from [__NuttX Mainline__](https://github.com/apache/nuttx) last night. The I2C Touch Panel worked perfectly OK during Automated Testing, here's the evidence: [__Automated Testing Log__](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10). Maybe we do some static discharge? Switch off the AC, open the windows, remove all metal objects, ...

![Automated Testing Log for PineDio Stack](https://lupyuen.github.io/images/auto2-release.jpg)

[_Automated Testing Log for PineDio Stack_](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

This article explains how we accomplished all that with PineDio Stack...

-   __Fully Automated Testing__ of all __NuttX Releases__ for PineDio Stack: GPIO, SPI, Timers, Multithreading, LoRaWAN

    [(Watch the demo on YouTube)](https://youtu.be/JX7rWqWTOW4)

-   Includes Automated Testing of __NuttX Mainline Updates__

-   Mostly Automated Testing of __I2C Touch Panel__

    (Needs one Human Touch, in lieu of a Robot Finger)

-   __Firmware Builds__ are auto-downloaded from __GitHub Releases__ for testing

    (Auto-published by GitHub Actions)

-   __Testing Logs__ are auto-uploaded to GitHub Releases as Release Notes

    [(See the Testing Log)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

Let's dive into the __Auto Flash and Test Script__ for PineDio Stack...

-   [__`lupyuen/remote-bl602`__](https://github.com/lupyuen/remote-bl602)

![PineDio Stack BL604 connected to LoRa Antenna (swiped from the IoT Course I used to teach)](https://lupyuen.github.io/images/auto2-pinedio2.jpg)

_PineDio Stack BL604 connected to LoRa Antenna (swiped from the IoT Course I used to teach)_

# Testing Checkpoints

Before we study the script, let's break down the Automated Testing into a series of __Testing Checkpoints__.

These are our success criteria for NuttX on PineDio Stack...

-   __NuttX must boot__ on PineDio Stack, with NuttX Drivers loaded _(Checkpoint Alpha)_

-   __NuttX must not crash__ on PineDio Stack _(Checkpoint Bravo)_

    (If NuttX crashes, our script runs a Crash Analysis)

-   __SPI Transmit and Receive__ must work _(Checkpoint Charlie)_

-   __GPIO Input, Output and Interrupt__ must work _(Checkpoint Delta)_

    (Also Timers and Multithreading with SX1262 LoRa Transceiver)

-   __I2C Transmit and Receive__ must work _(Checkpoint Echo)_

    (With CST816S Touch Panel)

To run the above tests automatically, let's connect PineDio Stack to a __Single-Board Computer__.

![GPIO 8, Reset and Ground on PineDio Stack BL604](https://lupyuen.github.io/images/auto2-pinedio3a.jpg)

_GPIO 8, Reset and Ground on PineDio Stack BL604_

# Connect PineDio Stack to SBC

Our __Automated Testing Script__ runs on a Single-Board Computer (SBC) to...

-   Control the __Flashing and Testing__ of PineDio Stack

    (Via USB, GPIO 8 and Reset)

-   Capture the __Test Log__ and upload to the GitHub Release

    (Over USB)

We __connect PineDio Stack__ to our SBC like so...

| SBC     | BL604    | Function
| --------|----------|----------
| GPIO 5  | GPIO 8 _(GPIO Port)_  | Flashing Mode
| GPIO 6  | RST _(JTAG Port)_     | Reset
| GND     | GND _(JTAG Port)_     | Ground
| USB     | USB Port              | USB UART

__GPIO 8__ is exposed on the GPIO Port (inside PineDio Stack). __Reset and Ground__ are exposed on the JTAG Port (outside PineDio Stack).

(See the pic above)

The __GPIO 8 Jumper__ must be set to __Low (Non-Flashing Mode)__...

> ![GPIO 8 Jumper must be set to Low (Non-Flashing Mode)](https://lupyuen.github.io/images/auto2-jumper.jpg)

(Or the LoRaWAN Test will fail because the timers get triggered too quickly, not sure why)

Remember to connect a __LoRa Antenna__! [(See this)](https://lupyuen.github.io/images/auto2-pinedio2.jpg)

Close the __Back Cover__ of PineDio Stack, without the GPS Base Board.

We'll see something similar to the pic below. We're ready to run our Automated Testing Script!

_So PineDio Stack will be permanently connected to our SBC?_

Yep I have a __Spare PineDio Stack__ permanently connected to my SBC.

This PineDio Stack has a faulty ST7789 Display (hence it's a spare), so we __can't auto-test the ST7789 Display__.

(But since ST7789 Display and SX1262 LoRa Transceiver are connected to the same SPI Bus, it should be OK to test only the SX1262 Transceiver)

![PineDio Stack BL604 connected to SBC](https://lupyuen.github.io/images/auto2-pinedio.jpg)

_PineDio Stack BL604 connected to SBC_

# Run Automated Test

To run the [__Automated Testing Script__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh) on our Single-Board Computer...

```bash
##  Allow the user to access the GPIO and UART ports
sudo usermod -a -G gpio    $USER
sudo usermod -a -G dialout $USER

##  Logout and login to refresh the permissions
logout

##  TODO: Install rustup, select default option.
##  See https://rustup.rs

##  Install blflash for flashing PineDio Stack
##  https://github.com/spacemeowx2/blflash
cargo install blflash

##  Download the flash and test script
git clone --recursive https://github.com/lupyuen/remote-bl602/

##  Always sync the clock before running the script
sudo apt install ntpdate
sudo ntpdate -u time.nist.gov
date

##  Run the script for Auto Flash and Test for PineDio Stack BL604.
##  Capture the Test Log in /tmp/release.log
script -c remote-bl602/scripts/pinedio.sh /tmp/release.log

##  TODO: Install the GitHub CLI for uploading Release Notes: https://cli.github.com
##  Log in a GitHub Token that has "repo" and "read:org" permissions

##  Optional: Upload the Test Log to the GitHub Release Notes
remote-bl602/scripts/upload.sh
```

[(Watch the demo on YouTube)](https://youtu.be/JX7rWqWTOW4)

This will download and test __Today's Build__ of NuttX for PineDio Stack (published on GitHub Releases).

[(Here's the build for 2022-05-10)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

If the Automated Test succeeds, we'll see...

```text
Download the latest pinedio NuttX build for 2022-05-10
Flash BL602 over USB UART with blflash
...
All OK! BL602 has successfully joined the LoRaWAN Network
All OK! BL604 has responded to touch
```

[(See the Test Log)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

Beware: The script __fails silently__ if there's no NuttX Build for today. (Sorry!)

_Can we pick a different NuttX Build?_

We pick a __NuttX Build__ from this list...

-   [__NuttX Builds for PineDio Stack__](https://github.com/lupyuen/nuttx/releases?q=%22download%2Fpinedio%22&expanded=true)

Then we set __BUILD_DATE__ like so...

```bash
##  Tell the script to download the build for 2022-05-10
export BUILD_DATE=2022-05-10

##  Run the script for Auto Flash and Test for PineDio Stack BL604.
##  Capture the Test Log in /tmp/release.log
script -c remote-bl602/scripts/pinedio.sh /tmp/release.log
```

_Will this work over SSH?_

Yep we may run the Automated Test __remotely over SSH__...

```bash
ssh my-sbc remote-bl602/scripts/pinedio.sh
```

## Automated NuttX Build

_How is NuttX for PineDio Stack built and published to GitHub Releases?_

Whenever we commit changes to the [__NuttX Repo for PineDio Stack__](https://github.com/lupyuen/nuttx/tree/pinedio), GitHub Actions will trigger a new NuttX Build and __publish the built firmware__ to GitHub Releases...

-   [__GitHub Actions Workflow for PineDio Stack__](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml)

    [(More about the GitHub Actions Workflow)](https://lupyuen.github.io/articles/auto#appendix-build-nuttx-with-github-actions)

Our script __downloads the NuttX Firmware__ from GitHub Releases for Automated Testing: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L14-L42)

```bash
##  BUILD_PREFIX is "pinedio"
##  BUILD_DATE defaults to today's date, like "2022-05-10"

##  Download the NuttX Firmware from GitHub Releases
wget -q https://github.com/lupyuen/nuttx/releases/download/$BUILD_PREFIX-$BUILD_DATE/nuttx.zip -O /tmp/nuttx.zip
pushd /tmp
unzip -o nuttx.zip
popd

##  Write the Release Tag for uploading the Test Log later:
##  "pinedio-2022-05-10"
echo "$BUILD_PREFIX-$BUILD_DATE" >/tmp/release.tag
```

We'll see __release.tag__ later when we upload the Test Log to the GitHub Release.

Let's walk through the Automated Testing Script and find out how it implements each Testing Checkpoint.

> ![NuttX booting on PineDio Stack](https://lupyuen.github.io/images/auto2-boot1.png)

> _NuttX booting on PineDio Stack_

# NuttX Must Boot

_(Checkpoint Alpha)_

Earlier we saw our Automated Testing Script downloading the NuttX Firmware from GitHub Releases.

At the first checkpoint, our script __flashes the NuttX Firmware__ to PineDio Stack...

```text
Set GPIO 5 to High (BL602 Flashing Mode)
Toggle GPIO 6 High-Low-High (Reset BL602)
BL602 is now in Flashing Mode

Flash BL602 over USB UART with blflash
+ blflash flash /tmp/nuttx.bin --port /dev/ttyUSB0
Sending eflash_loader...
Program flash... 
Success
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

Our script restarts PineDio Stack in __Flashing Mode__ and calls __blflash__ to flash the NuttX Firmware.

[(__blflash__ is explained here)](https://lupyuen.github.io/articles/flash#flash-bl602-firmware-with-linux-macos-and-windows)

Next our script restarts PineDio Stack in __Normal Mode__ to start the NuttX Firmware...

```text
Set GPIO 5 to Low (BL602 Normal Mode)
Toggle GPIO 6 High-Low-High (Reset BL602)
BL602 is now in Normal Mode

NuttShell (NSH) NuttX-10.3.0-RC0
nsh>
```

The NuttX Shell appears. Our script sends this command to reveal the __NuttX Commit ID__ and Build Timestamp...

```text
nsh> uname -a
NuttX 10.3.0-RC0 3e60d2211d May 10 2022 01:55:54 risc-v bl602evb
```

Then it lists the __Device Drivers__ loaded on NuttX...

```text
nsh> ls /dev
/dev:
 console  i2c0
 gpio10   input0
 gpio12   lcd0
 gpio14   null
 gpio15   spi0
 gpio19   spitest0
 gpio20   timer0
 gpio21   urandom
 gpio3    zero
 gpio9
```

Shown above are these __NuttX Device Drivers__: [__GPIO Expander__](https://lupyuen.github.io/articles/expander), [__I2C__](https://lupyuen.github.io/articles/bme280), [__Touch Input__](https://lupyuen.github.io/articles/touch), [__LCD Display__](https://lupyuen.github.io/articles/st7789), [__SPI Test__](https://lupyuen.github.io/articles/spi2), [__Timer__](https://lupyuen.github.io/articles/lorawan3#appendix-posix-timers-and-message-queues) and [__Random Number Generator__](https://lupyuen.github.io/articles/lorawan3#appendix-random-number-generator-with-entropy-pool).

Yep NuttX has successfully booted on PineDio Stack! Let's dive into our Automated Testing Script and see the implementation of the operations above.

![Flashing NuttX to PineDio Stack](https://lupyuen.github.io/images/nuttx-flash2.png)

[_Flashing NuttX to PineDio Stack_](https://lupyuen.github.io/articles/pinedio2#flash-pinedio-stack)

## Checkpoint Alpha

Our script controls PineDio Stack through GPIO 5 and 6 on our SBC...

-   __SBC GPIO 5__: Selects Flashing Mode or Normal Mode on PineDio Stack

    (Connected to PineDio Stack GPIO 8)

-   __SBC GPIO 6__: Restarts PineDio Stack

    (Connected to PineDio Stack Reset Pin)

This is how our script __configures GPIO 5 and 6__ on our SBC: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L44-L110)

```bash
##  Enable GPIO 5 and 6
if [ ! -d /sys/class/gpio/gpio5 ]; then
  echo 5 >/sys/class/gpio/export ; sleep 1  ##  Must sleep or next GPIO command will fail with "Permission Denied"
fi
if [ ! -d /sys/class/gpio/gpio6 ]; then
  echo 6 >/sys/class/gpio/export ; sleep 1  ##  Must sleep or next GPIO command will fail with "Permission Denied"
fi

##  Set GPIO 5 and 6 as output
echo out >/sys/class/gpio/gpio5/direction
echo out >/sys/class/gpio/gpio6/direction
```

To switch PineDio Stack to __Flashing Mode__, we set GPIO 5 to High and restart PineDio Stack...

```bash
##  Set GPIO 5 to High (BL602 Flashing Mode)
echo 1 >/sys/class/gpio/gpio5/value ; sleep 1

##  Toggle GPIO 6 High-Low-High (Reset BL602)
echo 1 >/sys/class/gpio/gpio6/value ; sleep 1
echo 0 >/sys/class/gpio/gpio6/value ; sleep 1
echo 1 >/sys/class/gpio/gpio6/value ; sleep 1
```

We run the __blflash__ command to flash the NuttX Firmware...

```bash
##  BL602 is now in Flashing Mode
##  Flash BL602 over USB UART with blflash
set -x  ##  Enable echo
blflash flash /tmp/nuttx.bin --port /dev/ttyUSB0
set +x  ##  Disable echo
sleep 1
```

[(__blflash__ is explained here)](https://lupyuen.github.io/articles/flash#flash-bl602-firmware-with-linux-macos-and-windows)

After flashing NuttX, we switch PineDio Stack back to __Normal Mode__...

```bash
##  Set GPIO 5 to Low (BL602 Normal Mode)
echo 0 >/sys/class/gpio/gpio5/value ; sleep 1

##  Toggle GPIO 6 High-Low-High (Reset BL602)
echo 1 >/sys/class/gpio/gpio6/value ; sleep 1
echo 0 >/sys/class/gpio/gpio6/value ; sleep 1
echo 1 >/sys/class/gpio/gpio6/value ; sleep 1
```

We configure the USB Port for 2 Mbps and __capture the Console Output__ from PineDio Stack...

```bash
##  Set USB UART to 2 Mbps
stty -F /dev/ttyUSB0 raw 2000000

##  Show the BL602 output and capture to /tmp/test.log.
##  Run this in the background so we can kill it later.
cat /dev/ttyUSB0 | tee /tmp/test.log &
```

Finally we send the __uname__ and __ls__ commands, to show the NuttX Build Details and the loaded Device Drivers...

```bash
##  If BL602 has not crashed, send the test command to BL602
echo "uname -a" >/dev/ttyUSB0 ; sleep 1
echo "ls /dev"  >/dev/ttyUSB0 ; sleep 1
```

Let's move on to the second checkpoint.

![NuttX Stack Trace](https://lupyuen.github.io/images/auto-stack.jpg)

[_NuttX Register and Stack Dump_](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

# NuttX Must Not Crash

_(Checkpoint Bravo)_

_What happens when NuttX crashes during testing?_

NuttX shows a __Register and Stack Dump__, like the pic above...

```text
irq_unexpected_isr: ERROR irq: 1
up_assert: Assertion failed at file:irq/irq_unexpectedisr.c line: 51 task: Idle Task
riscv_registerdump: EPC: deadbeee
riscv_registerdump: A0: 00000002 A1: 420146b0 A2: 42015140 A3: 420141c
...
riscv_stackdump: 420144a0: 00001fe0 23011000 420144f0 230053a0 deadbeef deadbeef 23010ca4 00000033
riscv_stackdump: 420144c0: deadbeef 00000001 4201fa38 23007000 00000001 42012510 42015000 00000001
```

Our script can't proceed with the Automated Testing, but it can help us make sense of these numbers to __understand why NuttX crashed__.

Our script detects the crash and does a __Crash Analysis__ (pic below)...

```text
----- Crash Analysis
Code Address 230053a0:
arch/risc-v/src/common/riscv_assert.c:364
  if (CURRENT_REGS)
    sp = CURRENT_REGS[REG_SP];

Code Address 230042e2:
libs/libc/assert/lib_assert.c:37
  exit(EXIT_FAILURE);
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

Through this Crash Analysis, we get some idea __which lines of code__ caused the crash.

And hopefully we can heal NuttX on PineDio Stack!

![NuttX Crash Analysis](https://lupyuen.github.io/images/auto-stack3.png)

[_NuttX Crash Analysis_](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-01-17)

## Checkpoint Bravo

Over to the implementation. Our script detects that NuttX has crashed when it sees the __registerdump__ keyword: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L102-L105)

```bash
##  Check whether BL602 has crashed
set +e  ##  Don't exit when any command fails
match=$(grep "registerdump" /tmp/test.log)
set -e  ##  Exit when any command fails

##  If NuttX has booted properly, run the LoRaWAN Test
if [ "$match" != "" ]; then
  ...
else
  ##  If NuttX has crashed, do the Crash Analysis
  ...
```

Then it proceeds to __decode the Stack Dump__ by matching the addresses with the __RISC-V Disassembly__: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L153-L211)

```bash
##  If NuttX has crashed, do the Crash Analysis.
##  Find all code addresses 23?????? in the Output Log, remove duplicates, skip 23007000.
##  Returns a newline-delimited list of addresses: "23011000\n230053a0\n..."
grep --extended-regexp \
  --only-matching \
  "23[0-9a-f]{6}" \
  /tmp/test.log \
  | grep -v "23007000" \
  | uniq \
  >/tmp/test.addr

##  For every address, show the corresponding line in the disassembly
for addr in $(cat /tmp/test.addr); do
  ##  Skip addresses that don't match
  match=$(grep "$addr:" /tmp/nuttx.S)
  if [ "$match" != "" ]; then
    echo "----- Code Address $addr"
    grep \
      --context=5 \
      --color=auto \
      "$addr:" \
      /tmp/nuttx.S
    echo
  fi
done
```

The Crash Analysis is explained here...

-   [__"NuttX Crash Analysis"__](https://lupyuen.github.io/articles/auto#nuttx-crash-analysis)

There's a __Design Flaw__ in our script that needs fixing... It doesn't detect crashes while running the SPI, LoRaWAN and Touch Panel Tests. [(See this)](https://gist.github.com/lupyuen/02764452fde605e04b626614be4562ed)

(We should probably use a __State Machine__ instead of a long chain of hacky "if-else" statements)

![Shared SPI Bus on PineDio Stack](https://lupyuen.github.io/images/pinedio-spi2.jpg)

[_Shared SPI Bus on PineDio Stack_](https://lupyuen.github.io/articles/pinedio2#appendix-shared-spi-bus)

# SPI Test

_(Checkpoint Charlie)_

PineDio Stack has a complex __SPI Bus__ that's shared by __3 SPI Devices__ (pic above)...

-   __SPI Flash__

-   __SX1262 LoRa Transceiver__

-   __ST7789 Display__

    [(MISO and MOSI are swapped for ST7789)](https://lupyuen.github.io/articles/pinedio2#swap-miso--mosi)

That's why we created an [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table) to manage the SPI Devices. 

_How do we test the SPI Bus and the SPI Device Table?_

Our script sends an SPI Command to the SX1262 LoRa Transceiver to __read an SX1262 Register__...

```text
nsh> spi_test2
Get Status: received
  a2 22 
SX1262 Status is 2
Read Register 8: received
  a2 a2 a2 a2 80 
SX1262 Register 8 is 0x80
SX1262 is OK
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

__spi_test2__ says that __SX1262 Register 8__ has value __`0x80`__, which is correct.

If we receive any other value for SX1262 Register 8...

```text
SX1262 Register 8 is 0x00
Error: SX1262 is NOT OK. Check the SPI connection
```

Then our script halts with an error.

Let's look at the implementation of the checkpoint.

## Checkpoint Charlie

Our script executes the SPI Test by sending the __spi_test2__ command to PineDio Stack: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L108-L111)

```bash
echo "spi_test2" >/dev/ttyUSB0 ; sleep 2
```

And verifies that the result is correct: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L122-L130)

```bash
##  Check whether SX1262 is OK
set +e  ##  Don't exit when any command fails
match=$(grep "SX1262 Register 8 is 0x80" /tmp/test.log)
set +e  ##  Don't exit when any command fails

##  If SX1262 is not OK, quit
if [ "$match" == "" ]; then
  echo; echo "===== Error: SX1262 is NOT OK. Check the SPI connection"
  test_status=unknown
```

Source code for __spi_test2__ is located here...

-   [__examples/spi_test2__](https://github.com/lupyuen/nuttx-apps/blob/pinedio/examples/spi_test2/spi_test2_main.c)

Note that __spi_test2__ calls the __SPI Test Driver "/dev/spitest0"__ which is explained here...

-   [__"Inside the SPI Test Driver"__](https://lupyuen.github.io/articles/spi2#inside-the-spi-test-driver)

_Why doesn't it call the standard SPI Driver "/dev/spi0" instead?_

That's because the SPI Test Driver presents a [__simpler interface__](https://lupyuen.github.io/articles/spi2#inside-the-spi-test-app) when we access the SPI Port from our NuttX App (in User Space).

At the next checkpoint, the LoRaWAN Test App will call the SPI Test Driver to talk to the SX1262 LoRa Transceiver.

[(We might switch to "/dev/spitest1" to fix an SPI Race Condition)](https://lupyuen.github.io/articles/pinedio2#sx1262-chip-select)

_What about testing the SPI Flash and ST7789 Display?_

In future we might test the __SPI Flash__ by reading the JEDEC ID.

Testing the __ST7789 Display__ will be more tricky because it needs visual inspection. If you have any ideas, lemme know!

![PineDio Stack talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway](https://lupyuen.github.io/images/lorawan3-title.jpg)

[_PineDio Stack talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway_](https://lupyuen.github.io/articles/lorawan3)

# LoRaWAN Test

_(Checkpoint Delta)_

Now comes the most complicated checkpoint: __LoRaWAN Test__.

For this test our script shall do some wireless comms...

1.  Send a __Join LoRaWAN Network__ Request

    (To our ChirpStack LoRaWAN Gateway)

1.  Wait for the __Join Network Response__ from gateway

1.  Then send a __LoRaWAN Data Packet__ to the gateway

_How will we know if LoRa and LoRaWAN are working OK on PineDio Stack?_

Step 3 will succeed only if...

-   PineDio Stack __correctly transmits__ the Join Network Request over LoRa and LoRaWAN

    (Step 1)

-   And PineDio Stack __correctly receives__ the Join Network Response over LoRa and LoRaWAN

    (Step 2)

Thus our script works well for verifying that both LoRa and LoRaWAN work OK on PineDio Stack.

_Which NuttX features will be tested in the LoRaWAN Test?_

Plenty! We'll test these features in the LoRaWAN Test...

-   __GPIO Input__: Read the Busy Status from SX1262 via GPIO Expander [(See this)](https://lupyuen.github.io/articles/sx1262#check-busy-state)

-   __GPIO Output__: Enable Chip Select for SX1262 via GPIO Expander [(See this)](https://lupyuen.github.io/articles/sx1262#spi-interface)

-   __GPIO Interrupt__: Triggered when SX1262 transmits or receives a LoRa Packet [(See this)](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt)

-   __SPI__: Transfer data and commands to SX1262 via SPI Test Driver [(See this)](https://lupyuen.github.io/articles/sx1262#spi-interface)

-   __ADC and Internal Temperature Sensor__: Seed the Strong Random Number Generator [(See this)](https://lupyuen.github.io/articles/auto#appendix-fix-lorawan-nonce)

-   __Timers__: Detect timeouts for transmit and receive [(See this)](https://lupyuen.github.io/articles/lorawan3#lorawan-event-loop)

-   __Multithreading__: Background thread handles received LoRa Packets [(See this)](https://lupyuen.github.io/articles/sx1262#start-dio1-thread)

-   __Message Queue__: Handles received LoRa Packets [(See this)](https://lupyuen.github.io/articles/sx1262#event-queue)

-   __Strong Random Number Generator__: Generate the LoRaWAN Nonce [(See this)](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce)

_Alright let's run the LoRaWAN Test already!_

Our script starts the LoRaWAN Test by sending the __lorawan_test__ command to PineDio Stack...

```text
nsh> lorawan_test
init_entropy_pool
temperature = 25.667484 Celsius
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

The test begins by reading BL604's [__Internal Temperature Sensor__](https://lupyuen.github.io/articles/auto#appendix-fix-lorawan-nonce) and using the temperature value to seed the [__Strong Random Number Generator__](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce).

Then we send the __Join LoRaWAN Network__ Request to our LoRaWAN Gateway (ChirpStack)...

```text
=========== MLME-Request ============
              MLME_JOIN              
=====================================
STATUS      : OK
```

We receive the correct __Join Network Response__ from our LoRaWAN Gateway...

```text
=========== MLME-Confirm ============
STATUS      : OK
===========   JOINED     ============
OTAA
DevAddr     : 00F76FBF
DATA RATE   : DR_2
```

PineDio Stack has successfully joined the LoRaWAN Network!

We proceed to send a __LoRaWAN Data Packet__ _("Hi NuttX")_ to our LoRaWAN Gateway...

```text
=========== MCPS-Confirm ============
STATUS      : OK
=====   UPLINK FRAME        1   =====
CLASS       : A
TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00
DATA RATE   : DR_3
U/L FREQ    : 923400000
TX POWER    : 0
CHANNEL MASK: 0003
```

Finally our script reports that the LoRaWAN Test has succeeded...

```text
All OK! BL602 has successfully joined the LoRaWAN Network
```

Which means that GPIO Input / Ouput / Interrupt, SPI, ADC, Timers, Multithreading, Message Queues and Strong Random Number Generator are all working OK!

## Checkpoint Delta

To run the LoRaWAN Test, our script sends the __lorawan_test__ command to PineDio Stack: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L132-L134)

```bash
##  Send the LoRaWAN Test Command
echo "lorawan_test" >/dev/ttyUSB0

##  Wait 20 seconds to join the LoRaWAN Network
sleep 20
```

And checks whether PineDio Stack has successfully __joined the LoRaWAN Network__: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L139-L146)

```bash
##  Check whether BL602 has joined the LoRaWAN Network
set +e  ##  Don't exit when any command fails
match=$(grep "JOINED" /tmp/test.log)
set -e  ##  Exit when any command fails

##  If BL602 has joined the LoRaWAN Network, then everything is super hunky dory!
if [ "$match" != "" ]; then
  echo; echo "===== All OK! BL602 has successfully joined the LoRaWAN Network"
```

_What happens if PineDio Stack fails to join the LoRaWAN Network?_

PineDio Stack will __retry repeatedly__ until it hits the timeout after 20 seconds.

Be sure that the __LoRaWAN Gateway Settings__ are correct! The gateway will silently drop invalid requests without notifying our device.

(More about this in a while)

_What's inside lorawan_test?_

__lorawan_test__ is the LoRaWAN Test App that's described in this article...

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

The app was ported from [__Semtech's LoRaWAN Stack__](https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c) to NuttX and calls these __NuttX Libraries__...

-   [__LoRaWAN Library__](https://github.com/lupyuen/LoRaMac-node-nuttx) (ported from Semtech)

-   [__SX1262 Library__](https://github.com/lupyuen/lora-sx1262/tree/lorawan) (also ported from Semtech)

-   [__NimBLE Porting Layer__](https://github.com/lupyuen/nimble-porting-nuttx) (for Timers, Multithreading and Message Queues)

The __Device Drivers__ called by the app are...

-   [__SPI Test Driver__](https://lupyuen.github.io/articles/spi2#spi-test-app-and-driver): /dev/spitest0

    (Which calls the SPI Driver and [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table))

-   [__GPIO Expander__](https://github.com/lupyuen/bl602_expander): 

    -   /dev/gpio10 (SX1262 Busy)
    -   /dev/gpio15 (SX1262 Chip Select)
    -   /dev/gpio19 (SX1262 DIO1)

_What about the ChirpStack LoRaWAN Gateway? What needs to be configured?_

For the LoRaWAN Test to succeed, we must configure the __Device EUI, Join EUI and App Key__ from the ChirpStack LoRaWAN Gateway...

-   [__"Device EUI, Join EUI and App Key"__](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

Also verify that the __LoRaWAN Frequency__ is correct...

-   [__"LoRaWAN Frequency"__](https://lupyuen.github.io/articles/lorawan3#lorawan-frequency)

_Isn't the LoRaWAN Test testing way too much? GPIO, SPI, ADC, Timers, Multithreading, ..._

Yeah someday we ought to build __smaller tests for specific features__ like GPIO, ADC, Timers, Multithreading, ... Similar to our SPI Test.

But for now we'll have to live with the inconvenience of identifying which specific feature could have caused the LoRaWAN Test to fail.

![LVGL Test App for testing the Touch Panel](https://lupyuen.github.io/images/touch-title.jpg)

[_LVGL Test App for testing the Touch Panel_](https://lupyuen.github.io/articles/touch)

# Touch Panel Test

_(Checkpoint Echo)_

For our final checkpoint we shall test...

-   [__I2C Driver "/dev/i2c0"__](https://lupyuen.github.io/articles/bme280) from NuttX

-   [__CST816S Touch Panel "/dev/input0"__](https://lupyuen.github.io/articles/touch) connected to the I2C Bus

_Why not test the I2C Accelerometer instead?_

[__PineDio Stack's Accelerometer__](https://lupyuen.github.io/articles/pinedio2#accelerometer) is connected to the same I2C Bus as the Touch Panel.

But we're not testing the Accelerometer because...

-   We don't have a __NuttX Driver__ for the Accelerometer

-   Touch Panel is __probably more important__ than the Accelerometer for most devs

_How do we test the Touch Panel and I2C Bus?_

Our [__LVGL Test App__](https://lupyuen.github.io/articles/touch#run-the-driver) includes a __Touchscreen Calibration__ step that records the points touched on the Touch Panel.

We'll run the app, tap the screen and verify that the Touch Panel generates __valid Touch Data__ over I2C when touched.

_So this isn't automated?_

Well our script starts the app automatically, but we need to run over and __tap the screen__ when prompted. Here's how it works...

Our script sends the __lvgltest__ command to start the LVGL Test App...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open: 
HELLO HUMAN: TOUCH PINEDIO STACK NOW
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

The script prompts us to touch the screen.

When we touch the screen, the __CST816S Touch Panel Driver__ shows a __Touch Down Event__ with the coordinates of the touched point (read over I2C)...

```text
DOWN: id=0, touch=0, x=83, y=106
```

As we lift our finger off the screen, the driver shows a __Touch Up Event__...

```text
Invalid touch data: id=9, touch=2, x=639, y=1688
UP: id=0, touch=2, x=83, y=106
```

[(Why the Touch Data is invalid)](https://lupyuen.github.io/articles/touch#touch-up-event)

Our script __detects the Touch Up Event__ and reports that the test has succeeded...

```text
All OK! BL604 has responded to touch
```

Yep PineDio Stack's Touch Panel and I2C Bus are working OK!

## Checkpoint Echo

The Touch Panel Test lives in a separate script: [__pinedio2.sh__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio2.sh)

We __launch the second script__ after completing the LoRaWAN Test: [pinedio.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio.sh#L219-L222)

```bash
##  Start the second script: pinedio2.sh
SCRIPT_PATH="${BASH_SOURCE}"
SCRIPT_DIR="$(cd -P "$(dirname -- "${SCRIPT_PATH}")" >/dev/null 2>&1 && pwd)"
$SCRIPT_DIR/pinedio2.sh
```

The second script sends the __lvgltest__ command to start the LVGL Test App: [pinedio2.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio2.sh#L102-L108)

```bash
##  Send command to PineDio Stack: lvgltest
echo "lvgltest" >/dev/ttyUSB0 ; sleep 1
echo ; echo "----- HELLO HUMAN: TOUCH PINEDIO STACK NOW" ; sleep 2

##  Wait 30 seconds for the screen to be tapped
sleep 30
```

And prompts us to tap the screen.

30 seconds later our script searches for a __Touch Up Event__: [pinedio2.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/pinedio2.sh#L110-L117)

```bash
##  Check whether BL604 has responded to touch
set +e  ##  Don't exit when any command fails
match=$(grep "cst816s_get_touch_data: UP: id=0, touch=" /tmp/test.log)
set -e  ##  Exit when any command fails

##  If BL604 has responded to touch, then everything is super hunky dory!
if [ "$match" != "" ]; then
  echo; echo "===== All OK! BL604 has responded to touch"
```

And reports that the test has succeeded.

_What's inside lvgltest?_

__lvgltest__ is our Test App for the __LVGL Graphics Library__...

-   [__LVGL Test App__](https://github.com/lupyuen/lvgltest-nuttx)

When the app starts, it runs a __Touchscreen Calibration__...

-   [__Source Code for Touchscreen Calibration__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c)

-   [__Watch the Demo on YouTube__](https://youtube.com/shorts/2Nzjrlp5lcE?feature=share)

Which we're using to test PineDio Stack's Touch Panel.

_But the Touchreen Calibration needs us to tap the 4 corners. Our script only watches for one tap?_

Yeah remember that my Spare PineDio Stack has a defective ST7789 Display. So we can't see the 4 corners anyway.

Hopefully __tapping the screen once__ in the centre will be sufficient for testing the Touch Panel.

(Our script should probably validate that the reported coordinates are close to the centre of the screen)

_Can we fully automate the Touch Panel Test? And do away with the Manual Tapping?_

Yep we need some kind of __Robot Finger__ to tap the screen.

The finger thingy needs to apply __sufficient pressure__ to the screen (but not too much) in order to wake up the Touch Panel. [(See this)](https://lupyuen.github.io/articles/touch#cst816s-touch-panel)

We could use a [__Motorised Controller__](https://web.archive.org/web/20220518023458/https://www.aliexpress.com/item/1005002449391401.html) with an attached [__Stylus__](https://web.archive.org/web/20220518023454/https://www.aliexpress.com/item/32831863881.html).

Or a [__Servo Motor__](https://www.seeedstudio.com/Grove-Servo.html) wrapped with an [__Electrostatic Discharge Bag__](https://youtu.be/mb3zcacDGPc).

Hope it fits inside our Automated Testing Enclosure: [__IKEA 365+ 5.2L Food Container__](https://www.ikea.com/sg/en/p/ikea-365-food-container-with-lid-rectangular-plastic-s69276794/)...

![Our Automated Testing Enclosure: IKEA 365+ 5.2L Food Container](https://lupyuen.github.io/images/auto2-box.jpg)

# Upload Test Log

The lesson we learnt from Alice, Bob and Chow: It's super helpful to __preserve the Automated Test Logs__ for every NuttX Release!

-   [__Automated Test Log for PineDio Stack__](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

(Especially when collaborating across time zones)

![Automated Test Log for PineDio Stack](https://lupyuen.github.io/images/auto2-release.jpg)

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-10)

This how we __upload the Automated Test Log__ to GitHub Release Notes...

```bash
##  Run the script for Auto Flash and Test for PineDio Stack BL604.
##  Capture the Test Log in /tmp/release.log
script -c remote-bl602/scripts/pinedio.sh /tmp/release.log

##  TODO: Install the GitHub CLI for uploading Release Notes: https://cli.github.com
##  Log in a GitHub Token that has "repo" and "read:org" permissions

##  Optional: Upload the Test Log to the GitHub Release Notes
remote-bl602/scripts/upload.sh
```

The __script__ command runs our Automated Testing Script and captures the Automated Test Log into __/tmp/release.log__.

Our Upload Script [__upload.sh__](https://github.com/lupyuen/remote-bl602/blob/main/scripts/upload.sh) reads the Automated Test Log and __uploads to GitHub Release Notes__.

_So the Upload Script needs write access to GitHub Release Notes?_

Yes our Upload Script calls the __GitHub CLI__ to upload the Automated Test Log to GitHub Release Notes...

-   [__GitHub CLI__](https://cli.github.com)

We need to install the GitHub CLI and log in with a __GitHub Token__ that has permission to update the Release Notes...

```bash
##  TODO: Create a new GitHub Token at 
##  https://github.com/settings/tokens/new
##  Token must have "repo" and "read:org" permissions

##  Log in with the GitHub Token
gh auth login --with-token

##  Verify that GitHub CLI can access GitHub Releases
gh release list --repo lupyuen/nuttx
```

_What's inside our Upload Script?_

Our Upload Script assumes that the [__GitHub Actions Workflow__](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml) has published a [__GitHub Release__](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml#L93-L100) with [__Auto-Generated Release Notes__](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml#L100).

The script begins by calling the __GitHub CLI to download__ the Auto-Generated Release Notes: [upload.sh](https://github.com/lupyuen/remote-bl602/blob/main/scripts/upload.sh)

```bash
##  Assumes the following files are present...
##  /tmp/release.log: Test Log
##  /tmp/release.tag: Release Tag (like pinedio-2022-05-10)

##  Preserve the Auto-Generated GitHub Release Notes.
##  Fetch the current GitHub Release Notes and extract the body text, like:
##  "Merge updates from master by @lupyuen in https://github.com/lupyuen/nuttx/pull/82"
gh release view \
  `cat /tmp/release.tag` \
  --json body \
  --jq '.body' \
  --repo lupyuen/nuttx \
  >/tmp/release.old
```

[("__gh release view__" is explained here)](https://cli.github.com/manual/gh_release_view)

In case the script is run twice, we search for the __Previous Automated Test Log__...

```bash
##  Find the position of the Previous Test Log, starting with "```"
cat /tmp/release.old \
  | grep '```' --max-count=1 --byte-offset \
  | sed 's/:.*//g' \
  >/tmp/previous-log.txt
prev=`cat /tmp/previous-log.txt`
```

And we __remove the Previous Test Log__, while retaining the Auto-Generated Release Notes...

```bash
##  If Previous Test Log exists, discard it
if [ "$prev" != '' ]; then
  cat /tmp/release.old \
    | head --bytes=$prev \
    >>/tmp/release2.log
else
  ##  Else copy the entire Release Notes
  cat /tmp/release.old \
    >>/tmp/release2.log
  echo "" >>/tmp/release2.log
fi
```

Just before adding the Automated Test Log, we insert the __Test Status__...

```bash
##  Show the Test Status, like "All OK! BL602 has successfully joined the LoRaWAN Network"
grep "^===== " /tmp/release.log \
  | colrm 1 6 \
  >>/tmp/release2.log
```

Then we __embed the Automated Test Log__, taking care of the Special Characters...

```bash
##  Enquote the Test Log without Carriage Return and Terminal Control Characters
##  https://stackoverflow.com/questions/17998978/removing-colors-from-output
echo '```text' >>/tmp/release2.log
cat /tmp/release.log \
  | tr -d '\r' \
  | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g' \
  >>/tmp/release2.log
echo '```' >>/tmp/release2.log
```

Finally we call the __GitHub CLI to upload__ the Auto-Generated Release Notes appended with the Automated Test Log...

```bash
##  Upload the Test Log to the GitHub Release Notes
gh release edit \
  `cat /tmp/release.tag` \
  --notes-file /tmp/release2.log \
  --repo lupyuen/nuttx
```

[("__gh release edit__" is explained here)](https://cli.github.com/manual/gh_release_edit)

That's it for uploading the Automated Test Log to GitHub!

![PineDio Stack BL604 (top) and PineCone BL602 (bottom) connected to Single-Board Computer for Automated Testing](https://lupyuen.github.io/images/auto2-connect.jpg)

_PineDio Stack BL604 (top) and PineCone BL602 (bottom) connected to Single-Board Computer for Automated Testing_

# Merge Updates From NuttX

_Is PineDio Stack fully supported by NuttX Mainline?_

Not yet. Our fork of NuttX for PineDio Stack has __Experimental Features__ that aren't ready to be upstreamed into [__NuttX Mainline__](https://github.com/apache/nuttx)...

-   [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table)

-   [__GPIO Expander__](https://lupyuen.github.io/articles/expander)

-   [__CST816S Touch Panel Driver__](https://lupyuen.github.io/articles/touch)

-   [__LoRa and LoRaWAN Libraries__](https://lupyuen.github.io/articles/lorawan3)

Thus the onus is on us to __pull the updates regularly__ from NuttX Mainline and make sure they work on PineDio Stack.

_So PineDio Stack might not have the latest features from NuttX Mainline?_

We're merging updates from NuttX Mainline into the PineDio Stack repo roughly __every 2 weeks__. (Depends on my writing mood)

All NuttX Updates are tested on __PineCone BL602__ first, then merged and tested on __PineDio Stack BL604__. (Because PineCone is way more popular than PineDio Stack right now)

That's why we need the __complicated setup__ for Automated Testing with PineCone and PineDio Stack. (Pic above)

[(More about the USB Ports for PineCone and PineDio Stack)](https://lupyuen.github.io/articles/auto2?23#appendix-select-usb-device)

_Which means we have 2 branches of NuttX: BL602 and BL604?_

Yep. We're now testing and maintaining two __Stable Branches__ of NuttX for public consumption on BL602 and BL604...

-   [__PineCone (Release) Branch__](https://github.com/lupyuen/nuttx) for PineCone BL602

-   [__PineDio Branch__](https://github.com/lupyuen/nuttx/tree/pinedio) for PineDio Stack BL604

(Same for NuttX Apps)

_How do we keep NuttX Mainline in sync with PineCone and PineDio Stack?_

Very carefully! And with lots of __Automation__. (GitHub Actions and Automated Testing)

Let's watch how the __updates from NuttX Mainline__ get merged into PineCone and PineDio Stack...

-   NuttX Mainline → PineCone Branch → PineDio Branch

And how __updates from PineDio Stack__ get merged back into PineCone...

-   PineDio Branch → PineCone Branch

Ultimately the PineCone and PineDio Branches will have the __exact same code__, tested OK on PineCone and PineDio Stack. (With different build settings)

![Merge Updates From NuttX to PineDio Stack](https://lupyuen.github.io/images/auto2-merge1.jpg)

## PineCone to PineDio Stack

The pic above shows how we __merge the updates from NuttX Mainline__  into the PineCone and PineDio Branches...

1.  Every day we build __Mainline NuttX (Upstream)__ every day with GitHub Actions. [(See this)](https://lupyuen.github.io/articles/auto#appendix-build-nuttx-with-github-actions)

    Also daily we run our __Automated Testing__ to verify that the Upstream Build boots OK on PineCone BL602. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/upstream-2022-05-22)

    (Upstream Build doesn't include the LoRaWAN Stack)

2.  Every 2 weeks (roughly), we merge Upstream NuttX into our [__Downstream Branch__](https://github.com/lupyuen/nuttx/tree/downstream). [(Like this)](https://github.com/lupyuen/nuttx/commit/70decce2bf2754e331648c24bcfbb7e377376f52)

    GitHub Actions triggers a build for the __Downstream Branch__. [(See this)](https://github.com/lupyuen/nuttx/blob/downstream/.github/workflows/bl602-downstream.yml#L7-L272)

    Our __Automated Testing__ verifies the Downstream Build with LoRaWAN on PineCone BL602. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/downstream-2022-05-24)

3.  If the Downstream Branch has tested OK, we merge the Downstream Branch to the __PineCone (Release) Branch__. [(Like this)](https://github.com/lupyuen/nuttx/pull/87)

    GitHub Actions triggers a build for the __PineCone Branch__. [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L7-L272)

    Our __Automated Testing__ verifies the PineCone (Release) Build with LoRaWAN on PineCone BL602. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-05-24)

4.  If the PineCone Branch has tested OK, we __merge the PineCone (Release) Branch__ to the PineDio Branch. [(Like this)](https://github.com/lupyuen/nuttx/pull/88)

    GitHub Actions triggers a build for the __PineDio Branch__. [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L7-L272)

    We run our __Automated Testing__ on PineDio Stack to verify that the PineDio Build works OK with LoRaWAN and Touch Panel. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-24)

That's what we do today to keep PineCone and PineDio Branches in sync with NuttX Mainline.

(We do the same for [__NuttX Apps__](https://github.com/lupyuen/nuttx-apps), just before every merge of NuttX OS)

![Merge Updates From PineDio Stack to PineCone](https://lupyuen.github.io/images/auto2-merge2.jpg)

## PineDio Stack to PineCone

Now Reverse Uno: The pic above shows how we __merge the updates from PineDio Branch__ back to PineCone Branch (like when we add a new feature for PineDio Stack)...

1.  When we commit a change to the __PineDio Branch__, GitHub Actions triggers a build of the branch. [(See this)](https://github.com/lupyuen/nuttx/blob/pinedio/.github/workflows/pinedio.yml#L7-L77)

    We run our __Automated Testing__ on PineDio Stack to verify that the build works OK with LoRaWAN and Touch Panel. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/pinedio-2022-05-23)

1.  If the PineDio Branch has tested OK, we merge the PineDio Branch to the __PineCone (Release) Branch__. [(Like this)](https://github.com/lupyuen/nuttx/pull/85)

    GitHub Actions triggers a build for the __PineCone Branch__. [(See this)](https://github.com/lupyuen/nuttx/blob/master/.github/workflows/bl602-commit.yml#L7-L272)

    Our __Automated Testing__ verifies the PineCone (Release) Build with LoRaWAN on PineCone BL602. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-05-23)

1.  If the PineCone Branch has tested OK, we merge the PineCone (Release) Branch to the __Downstream Branch__. [(Like this)](https://github.com/lupyuen/nuttx/pull/86)

    GitHub Actions triggers a build for the __Downstream Branch__. [(See this)](https://github.com/lupyuen/nuttx/blob/downstream/.github/workflows/bl602-downstream.yml#L7-L272)

    For one last time, we run our __Automated Testing__ on PineCone BL602 to verify that the Downstream Build works OK with LoRaWAN. [(Like this)](https://github.com/lupyuen/nuttx/releases/tag/downstream-2022-05-23)

    Downstream Branch is now ready to __accept new updates__ from NuttX Mainline. (Within the next 2 weeks)

That's what we do today to sync the PineDio and PineCone Branches.

(We do the same for [__NuttX Apps__](https://github.com/lupyuen/nuttx-apps), just before every merge of NuttX OS)

![GPIO Expander for PineDio Stack](https://lupyuen.github.io/images/expander-title.jpg)

[_GPIO Expander for PineDio Stack_](https://lupyuen.github.io/articles/expander)

## Merge Conflicts

_Hol' up... PineCone Branch merges updates from NuttX Mainline AND PineDio Branch? Won't they clash?_

Yep maintaining the PineCone (Release) Branch is a delicate process...

We need to assure __peaceful coexistence__ of the features from both NuttX Mainline and PineDio Stack.

Suppose NuttX Mainline implements a new feature: [__SPI DMA for BL602__](https://lupyuen.github.io/articles/pinedio2#spi-direct-memory-access)...

-   We need to merge the SPI DMA changes into __SPI Driver__ for the PineCone Branch: [__bl602_spi.c__](https://github.com/lupyuen/nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c)

-   But recall that the SPI Driver for the PineCone Branch also includes the [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table) for PineDio Stack: [__bl602_spi.c__](https://github.com/lupyuen/nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L1335-L1473)

-   Thus we need to __merge the SPI DMA__ changes very carefully into the SPI Driver. (Possibly changing the SPI Device Table too)

-   To make the merging easier, we have __demarcated the SPI Device Table__ with the __PINEDIO_STACK_BL604__ macro: [__bl602_spi.c__](https://github.com/lupyuen/nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L1335-L1473)

    ```c
    //  If this is PineDio Stack...
    #ifdef PINEDIO_STACK_BL604
    //  Code for SPI Device Table goes here...
    #endif  //  PINEDIO_STACK_BL604
    ```

-   __PINEDIO_STACK_BL604__ is defined below, should probably be improved: [__board.h__](https://github.com/lupyuen/nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L147-L151)

    ```c
    //  Identify as PineDio Stack if both ST7789 and CST816S are present
    #if defined(CONFIG_LCD_ST7789) && defined(CONFIG_INPUT_CST816S)
    #define PINEDIO_STACK_BL604
    #endif  //  CONFIG_LCD_ST7789 && CONFIG_INPUT_CST816S
    ```

_Is there a cleaner way to merge updates from NuttX Mainline?_

The cleaner way to merge updates from NuttX Mainline might be to __split the NuttX Drivers__ for PineCone and PineDio Stack.

We did this for the __NuttX GPIO Driver__...

-   PineCone BL602 uses the [__BL602 EVB GPIO Driver__](https://lupyuen.github.io/articles/expander#bl602-evb-limitations)

-   PineDio Stack BL604 uses the [__GPIO Expander Driver__](https://lupyuen.github.io/articles/expander)

We select the GPIO Driver through [__Kconfig and Menuconfig__](https://lupyuen.github.io/articles/expander#load-gpio-expander). Or through the __NuttX Build Configuration__...

```bash
## Configure build for PineCone BL602
./tools/configure.sh bl602evb:pinecone

## Configure build for PineDio Stack BL604
./tools/configure.sh bl602evb:pinedio
```

[(See the PineCone config)](https://github.com/lupyuen/nuttx/blob/master/boards/risc-v/bl602/bl602evb/configs/pinecone/defconfig)

[(See the PineDio Stack config)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig)

[(How we resolve Merge Conflicts between NuttX Mainline and our Downstream Branch)](https://gist.github.com/lupyuen/a6396ccbe9427087e73e5f29bf570eda)

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/pinedio2-inside5.jpg)

[_Inside PineDio Stack BL604_](https://lupyuen.github.io/articles/pinedio2)

# Why NuttX

_Wow looks like we're doing Everything Everywhere All at Once / Daily / Fortnightly for NuttX on PineDio Stack! Why are we doing all this?_

PineDio Stack is the __most complex IoT gadget__ I've seen... [__All 23 GPIOs__](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment) in use, some multiplexed!

Thus we need a __Common Framework__ to manage the complexity. And the framework shall be easily adopted by Alice, Bob, Chow and other devs worldwide to __create Apps and Drivers__ for PineDio Stack.

The Common Framework that we have selected is __Apache NuttX RTOS!__

NuttX __looks like Linux__ (shrunk to a tiny footprint), so hopefully it appeals to coders familiar with Linux.

_Isn't it difficult to coordinate our devs everywhere?_

That's why we have __automated everything__ as much as possible, from Automated Builds (GitHub Actions) to Automated Testing.

Updates are synced from __NuttX Mainline__ every 2 weeks, so PineDio Stack Devs will experience the same features as other NuttX Devs worldwide.

With our grand plan, no dev gets left behind across the time zones!

_Are there other options?_

NuttX is the only __Community-Supported RTOS__ for BL602 and BL604.

If community support is not required, we could consider these alternatives...

-   [__BL IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk)

    (Supports WiFi and is based on FreeRTOS)

-   [__BL MCU SDK__](https://github.com/bouffalolab/bl_mcu_sdk)

    (Doesn't support WiFi, also based on FreeRTOS)

But we might face serious challenges creating complex firmware for PineDio Stack.

# What's Next

I hope Alice, Bob and Chow will have a great time creating NuttX Drivers and Apps on PineDio Stack... And you too!

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/RISCV/comments/uv2kzb/mostly_automated_testing_of_apache_nuttx_rtos_on/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/auto2.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/auto2.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1519541046803271682)

1.  Automated Testing of __PineCone BL602__ is explained here...

    [__"Auto Flash and Test NuttX on RISC-V BL602"__](https://lupyuen.github.io/articles/auto)

1.  The ST7789 Display on our Spare PineDio Stack for Automated Testing is faulty. How will we know if the __ST7789 Driver is working?__

    Right now I'm manually running the LVGL Test App on my Main PineDio Stack (with a functioning display), to check if the ST7789 Driver is OK.

    The test results are manually recorded in the Pull Request. [(See this)](https://github.com/lupyuen/nuttx/pull/88)

1.  What if the Kconfig files in NuttX Mainline get updated? How do we sync the updates to the __PineDio Stack Build Config__?

    Here's how we sync the updates to the PineDio Stack Build Config, right after merging NuttX Mainline with PineDio Stack...

    ```bash
    ## Configure build for PineDio Stack BL604
    ./tools/configure.sh bl602evb:pinedio

    ## Copy the updated Build Config to our repo
    cp .config boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig

    ## So the next time we configure the build,
    ## we will use the updated Build Config...
    ## ./tools/configure.sh bl602evb:pinedio
    ```

![PineDio Stack BL604 (top) and PineCone BL602 (bottom) connected to Single-Board Computer for Automated Testing](https://lupyuen.github.io/images/auto2-connect.jpg)

_PineDio Stack BL604 (top) and PineCone BL602 (bottom) connected to Single-Board Computer for Automated Testing_

# Appendix: Select USB Device

When we connect both PineDio Stack BL604 and PineCone BL602 to our Single-Board Computer (pic above), we'll see two USB Devices: __/dev/ttyUSB0__ and __/dev/ttyUSB1__

_How will we know which USB Device is for PineDio Stack and PineCone?_

Do this...

```bash
## Show /dev/ttyUSB0
lsusb -v -s 1:3 2>&1 | grep bcdDevice | colrm 1 23

## Show /dev/ttyUSB1
lsusb -v -s 1:4 2>&1 | grep bcdDevice | colrm 1 23

## Output for Pinedio Stack BL604:
## 2.64
## See https://gist.github.com/lupyuen/dc8c482f2b31b25d329cd93dc44f0044

## Output for PineCone BL602:
## 2.63
## See https://gist.github.com/lupyuen/3ba0dc0789fd282bbfcf9dd5c3ff8908
```

Here's how we __override the Default USB Device__ for PineDio Stack...

```bash
##  Tell the script to use /dev/ttyUSB1
##  (Default is /dev/ttyUSB0)
export USB_DEVICE=/dev/ttyUSB1

##  Auto flash and test PineDio Stack BL604 at /dev/ttyUSB1
remote-bl602/scripts/pinedio.sh
```

__TODO:__ We should automate this selection of USB Device in our Automated Testing Script.
