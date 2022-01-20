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
fi
if [ ! -d /sys/class/gpio/gpio3 ]; then
  echo 3 >/sys/class/gpio/export
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

TODO

```bash
##  Enter superuser mode
sudo bash

##  Install Rust as superuser: https://rustup.rs/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

##  Add Rust to the PATH
source $HOME/.cargo/env

##  Install blflash as superuser
cargo install blflash

##  Exit superuser mode
exit

##  Download the script
git clone --recursive https://github.com/lupyuen/remote-bl602

##  Run the script as superuser
sudo remote-bl602/scripts/test.sh
```

(Alternatively we may set the GPIO and UART permissions, so we don't need superuser access)

Auto Flash and Test on #BL602 the latest #NuttX Build ... Yep it works! 🎉

[__Watch the demo on YouTube__](https://www.youtube.com/watch?v=_82og3-gEwA)

[(Source)](https://github.com/lupyuen/remote-bl602)

TODO88

Let's Auto-Flash & Test the Daily Upstream Build of Apache #NuttX OS ... Auto-Built & Published by GitHub Actions

![](https://lupyuen.github.io/images/auto-script.png)

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L17-L21)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/.github/workflows/bl602.yml#L82-L112)

TODO6

Auto Flash and Test on #BL602 is really helpful for picking a Stable Daily Build of #NuttX for BL602 ... So I can test it as I write my NuttX articles 👍

![](https://lupyuen.github.io/images/auto-run.png)

[(Source)](https://github.com/lupyuen/remote-bl602)

# Crash Analysis

TODO10

What are these addresses in the #NuttX Stack Trace? Let's do Auto Crash Analysis for #BL602 ... And see the Source Code for the Stack Trace 

![](https://lupyuen.github.io/images/auto-stack.png)

[(Source)](https://github.com/lupyuen/remote-bl602/#output-log-for-upstream-build)

TODO11

Our Crash Analysis Script finds #BL602 Code Addresses in the Output Log ... And shows the matching Source Code from the #NuttX RISC-V Disassembly ... Which was auto-generated by GitHub Actions

![](https://lupyuen.github.io/images/auto-stack2.png)

[(Source)](https://github.com/lupyuen/remote-bl602/blob/main/scripts/test.sh#L129-L152)


TODO12

Now our Crash Analysis Script shows the matching Source Code whenever #NuttX crashes 👍

![](https://lupyuen.github.io/images/auto-stack3.png)

[(Source)](https://github.com/lupyuen/remote-bl602/#output-log-for-upstream-build)

TODO13

We also match up the Data Addresses in the #NuttX Stack Trace with the RISC-V Disassembly ... Not very interesting now, might be useful later

![](https://lupyuen.github.io/images/auto-stack4.png)

[(Source)](https://github.com/lupyuen/remote-bl602/#output-log-for-upstream-build)


Here's a demo of #BL602 Auto Flash & Test ... With #NuttX Crash Analysis

[__Watch the demo on YouTube__](https://www.youtube.com/watch?v=Kf3G1hGoLIs)

[(Source)](https://github.com/lupyuen/remote-bl602/)

TODO17

Now we can Flash & Test Apache #NuttX OS on #BL602 ... Remotely from a Phone! 🎉

![](https://lupyuen.github.io/images/auto-remote.png)

[(Source)](https://github.com/lupyuen/remote-bl602/)

# LoRaWAN Test

TODO9

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
