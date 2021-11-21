# Apache NuttX OS on RISC-V BL602 and BL604

📝 _26 Nov 2021_

![Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/nuttx-title.jpg)

_Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board_

Among all Embedded Operating Systems, __Apache NuttX is truly unique__ because...

-   NuttX runs on __8-bit, 16-bit, 32-bit AND 64-bit__ microcontrollers...

    Spanning popular platforms like __RISC-V, Arm, ESP32, AVR, x86,__ ...

    [(See this)](https://nuttx.apache.org/docs/latest/introduction/supported_platforms.html)

-   NuttX is [__strictly compliant with POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance).

    Which means that NuttX Applications shall access the __Microcontroller Hardware__ by calling _open(), read(), write(), ioctl(), ..._

    (Looks like Linux Lite!)

-   For [__BL602 and BL604__](https://lupyuen.github.io/articles/pinecone): NuttX and FreeRTOS are the only operating systems supported on the RISC-V + WiFi + Bluetooth LE SoCs.

-   If you're wondering: NuttX is named after its creator [__Gregory Nutt__](https://en.m.wikipedia.org/wiki/NuttX). And X because it's POSIX Compliant.

Today we shall __build, flash and run__ NuttX on the [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V Boards. (Pic above)

(The steps in this article should work on __any BL602 or BL604 Board__: Pinenut, DT-BL10, MagicHome BL602, ...)

We'll briefly explore the __internals of NuttX__ to understand how it works...

-   [__NuttX OS: incubator-nuttx__](https://github.com/apache/incubator-nuttx)

-   [__NuttX Apps: incubator-nuttx-apps__](https://github.com/apache/incubator-nuttx-apps)

Coding a microcontroller with __Linux-like (POSIX)__ functions might sound odd, but we'll discuss the benefits in a while.

(And we might have an interesting way to support __Embedded Rust on NuttX!__)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

# Boot NuttX

Follow the steps below to __build, flash and run__ NuttX for BL602 and BL604...

-   [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/nuttx#appendix-build-flash-and-run-nuttx)

We should see the __NuttX Shell__ on our Serial Terminal...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

The default NuttX Firmware includes two __Demo Apps__...

-   [__NuttX Hello Demo__](https://github.com/apache/incubator-nuttx-apps/tree/master/examples/hello)

-   [__NuttX Timer Demo__](https://github.com/apache/incubator-nuttx-apps/tree/master/examples/timer)

Let's test the Demo Apps.

![Booting NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

# Hello Demo

At the __NuttX Shell__, enter...

```bash
hello
```

We should see...

```text
Hello, World!!
```

(Yep this is the plain and simple __Hello World__ app!)

The Source Code looks very familiar: [hello_main.c](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/hello/hello_main.c)

```c
#include <nuttx/config.h>
#include <stdio.h>

int main(int argc, FAR char *argv[])
{
  printf("Hello, World!!\n");
  return 0;
}
```

It looks exactly like on __Linux!__ (Almost)

That's because NuttX is __POSIX Compliant__. It supports Linux features like _stdio, main()_ and _printf()._

Let's run the Timer Demo App.

![Hello and Timer Demo Apps](https://lupyuen.github.io/images/nuttx-demo2.png)

# Timer Demo

At the __NuttX Shell__, enter...

```bash
timer
```

We should see some __Timeout Messages__. (Pic above)

This Demo App accesses the __System Timer__ in an interesting way: [timer_main.c](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/timer/timer_main.c)

![Timer Demo App](https://lupyuen.github.io/images/nuttx-timer2.png)

1.  __/dev/timer0__ points to the System Timer

    (Everything is a file... Just like Linux!)

1.  We call __open()__ to open the System Timer

1.  __ioctl()__ to set the Timeout

1.  __sigaction()__ to register the Timeout Handler

As expected, __open(), ioctl()__ and __sigaction()__ are common functions found on Linux.

NuttX Apps really look like Linux Apps!

![help, ls and gpio commands](https://lupyuen.github.io/images/nuttx-gpio2a.png)

# Configure NuttX

TODO

#NuttX Demo Apps are configured before build with "make menuconfig"

```bash
make menuconfig
```

[Configuring NuttX](https://nuttx.apache.org/docs/latest/quickstart/configuring.html)

## Enable help and ls

TODO

Let's enable the "help" and "ls" Shell Commands in #BL602 #NuttX

![](https://lupyuen.github.io/images/nuttx-menu10.png)

TODO15

![](https://lupyuen.github.io/images/nuttx-menu11.png)

TODO52

![](https://lupyuen.github.io/images/nuttx-menu13a.png)

## Enable GPIO Driver

TODO

Let's test GPIO on #BL602 #NuttX ... By enabling the GPIO Driver

![](https://lupyuen.github.io/images/nuttx-menu5.png)

TODO10

![](https://lupyuen.github.io/images/nuttx-menu6.png)

TODO53

![](https://lupyuen.github.io/images/nuttx-menu7a.png)

## Enable GPIO Demo

TODO

After the GPIO Driver has been enabled, select the GPIO Demo in #BL602 #NuttX

![](https://lupyuen.github.io/images/nuttx-menu.png)

TODO5

![](https://lupyuen.github.io/images/nuttx-menu2.png)

TODO54

![](https://lupyuen.github.io/images/nuttx-menu9a.png)

TODO6

![](https://lupyuen.github.io/images/nuttx-apps.png)

TODO11

![](https://lupyuen.github.io/images/nuttx-menu8.png)

## Rebuild NuttX

__Rebuild and copy__ the NuttX Firmware...

```bash
##  Rebuild NuttX
make

##  For Linux: Change $HOME/blflash to the full path of blflash
cp nuttx.bin $HOME/blflash

##  For WSL: Change /mnt/c/blflash to the full path of blflash in Windows
##  /mnt/c/blflash refers to c:\blflash
cp nuttx.bin /mnt/c/blflash
```

__Flash and run__ the NuttX Firmware...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

TODO

"help" shows the commands available on #BL602 #NuttX ... "ls /dev" reveals the GPIO Pins that we may control ... Yep everything looks like a file!

![](https://lupyuen.github.io/images/nuttx-gpio2a.png)

# Configure Pins

TODO

No device tree

Here are the Pin Definitions for #BL602 #NuttX ... We'll change this in a while

![](https://lupyuen.github.io/images/nuttx-pins2.png)

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h)

TODO44

How shall we flip GPIO 11, the Blue LED on PineCone #BL602? We edit the #NuttX GPIO Pin Definition ... And GPIO 11 becomes "/dev/gpout1"

From [board.h](https://github.com/apache/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L42-L49)

```c
////  GPIO Output Pin:
////  Changed GPIO_PIN1 to GPIO_PIN11 (Blue LED on PineCone BL602)
////  Changed GPIO_PULLDOWN to GPIO_FLOAT
#define BOARD_GPIO_OUT1   (GPIO_OUTPUT | GPIO_FLOAT | \
                           GPIO_FUNC_SWGPIO | GPIO_PIN11)

////  Previously:
////  #define BOARD_GPIO_OUT1   (GPIO_OUTPUT | GPIO_PULLDOWN | \
////                             GPIO_FUNC_SWGPIO | GPIO_PIN1)
```

![](https://lupyuen.github.io/images/nuttx-gpio3a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L45-L53)

# GPIO Demo

TODO13

```bash
gpio -o 1 /dev/gpout1
gpio -o 0 /dev/gpout1
```

![](https://lupyuen.github.io/images/nuttx-gpio.png)

TODO45

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

# GPIO Driver

TODO

GPIO Demo calls "ioctl" to control the GPIO Pins on #BL602 #NuttX

[GPIO ioctl interface](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/ioexpander/gpio.h)

![](https://lupyuen.github.io/images/nuttx-gpio10a.png)

[(Source)](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/gpio/gpio_main.c)

# BASIC Interpreter

TODO

![](https://lupyuen.github.io/images/nuttx-basic1.png)

TODO33

[Enable peek and poke](https://github.com/lupyuen/incubator-nuttx-apps/commit/cda8a79fae74ea85f276302b67d32c01adb561bc)

![](https://lupyuen.github.io/images/nuttx-basic3.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/interpreters/bas/bas_fs.c#L1862-L1889)

TODO34

Blinking the #BL602 LED ... Works on #NuttX BASIC too! 🎉

```text
nsh> bas
bas 2.4
Copyright 1999-2014 Michael Haardt.
This is free software with ABSOLUTELY NO WARRANTY.
>
>
> print peek(&h40000188)
 0
> poke &h40000188, &h800
>
>
> print peek(&h40000188)
 2048
> poke &h40000188, &h00
>
>
>
```

![](https://lupyuen.github.io/images/nuttx-basic2a.png)

# SPI Demo

TODO

Spi demo: lseek, read, write

[lsm330spi_test](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/lsm330spi_test/lsm330spi_test_main.c)

SPI interface:

[spi.h](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

# Why NuttX?

TODO

Applications are portable

Looks like Linux

LoRa Driver for NuttX

Copy from Linux Driver

Here are the #BL602 Peripherals supported by #NuttX OS

![](https://lupyuen.github.io/images/nuttx-bl602.png)

[(Source)](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html#bl602-peripheral-support)

TODO

As we've seen, #NuttX has its own HAL for #BL602 ... Which differs from BL602 IoT SDK ... So we expect some quirks

![](https://lupyuen.github.io/images/nuttx-hal.png)

TODO

Though SPI with DMA is not yet supported on #BL602 #NuttX OS

![](https://lupyuen.github.io/images/nuttx-dma2.png)

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L734-L761)

# Rust on NuttX

TODO

Implement Rust Embedded HAL on NuttX

Portable to other implementations of NuttX

Might become a friendlier API for NuttX

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/nuttx.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nuttx.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1460322823122014211)

1.  TODO: ["How to install NuttX on BL602"](https://acassis.wordpress.com/2021/01/24/how-to-install-nuttx-on-bl602/)

# Appendix: Build, Flash and Run NuttX

Below are the steps to __build, flash and run__ NuttX on BL602 and BL604.

## Build NuttX

Let's build NuttX on __Linux (Ubuntu)__ or __WSL (Ubuntu)__...

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

1.  Download the __RISC-V GCC Toolchain__ from BL602 IoT SDK...

    ```bash
    git clone https://github.com/lupyuen/bl_iot_sdk
    ```

1.  Edit __~/.bashrc__ (or equivalent) and add...

    ```text
    ##  TODO: Change $HOME/bl_iot_sdk to the full path of bl_iot_sdk
    PATH="$HOME/bl_iot_sdk/toolchain/riscv/Linux/bin:$PATH"
    ```

1.  Update the __PATH__...

    ```bash
    . ~/.bashrc
    ```

1.  Install the __Build Tools__...

    ```bash
    sudo apt install \
      bison flex gettext texinfo libncurses5-dev libncursesw5-dev \
      gperf automake libtool pkg-config build-essential gperf genromfs \
      libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev \
      libexpat-dev gcc-multilib g++-multilib picocom u-boot-tools util-linux \
      kconfig-frontends
    ```

1.  Download NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/incubator-nuttx.git nuttx
    git clone https://github.com/apache/incubator-nuttx-apps apps
    ```

1.  Configure NuttX...

    ```bash
    cd nuttx
    ./tools/configure.sh bl602evb:nsh
    ```

1.  We should see...

    ```text
    configuration written to .config
    ```

    [(See the complete log)](https://gist.github.com/lupyuen/41f40b782769e611770724510fc8db2c)

1.  Build NuttX...

    ```bash
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  Copy the __NuttX Firmware__ to the __blflash__ directory...

    ```bash
    ##  For Linux: Change $HOME/blflash to the full path of blflash
    cp nuttx.bin $HOME/blflash

    ##  For WSL: Change /mnt/c/blflash to the full path of blflash in Windows
    ##  /mnt/c/blflash refers to c:\blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    (We'll cover __blflash__ in the next section)

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Press the Reset Button

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

## For Linux:
sudo cargo run flash nuttx.bin \
    --port /dev/ttyUSB0

## For macOS:
cargo run flash nuttx.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

## For Windows: Change COM5 to the BL602 / BL604 Serial Port
cargo run flash nuttx.bin --port COM5
```

(For WSL: Do this under plain old Windows CMD, not WSL, because blflash needs to access the COM port)

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Press the Reset Button

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

# Appendix: Fix GPIO Output

TODO

Flipping GPIO 11 doesn't blink the LED on #BL602 #NuttX ... Let's investigate 🤔

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

#NuttX writes correctly to the GPIO 11 Output Register at 0x40000188 (BL602_GPIO_CFGCTL32)

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

TODO47

#NuttX configures #BL602 GPIO 11 (0x40000114) with GPIO Input Disabled ... But it doesn't Enable GPIO Output 🤔

![](https://lupyuen.github.io/images/nuttx-gpio6c.png)

TODO51

#BL602 Reference Manual says we should set the GPIO Output Enable Register ... But it's missing from the docs ... Where is the register? 🤔

![](https://lupyuen.github.io/images/nuttx-gpio9a.png)

[(Source)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

TODO49

#BL602 IoT SDK says that GPIO Output Enable Register is at 0x40000190 (GLB_GPIO_CFGCTL34) ... Let's set this register in #NuttX

![](https://lupyuen.github.io/images/nuttx-gpio7a.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1990-L2010)

TODO50

We mod #BL602 #NuttX to set the GPIO Output Enable Register at 0x40000190 (BL602_GPIO_CFGCTL34)

```c
  ...
  modifyreg32(regaddr, mask, cfg);
  
  // Enable GPIO Output if requested
  if (!(cfgset & GPIO_INPUT))
    {
      modifyreg32(
        BL602_GPIO_CFGCTL34, 
        0, 
        (1 << pin)
      );
    }
```

![](https://lupyuen.github.io/images/nuttx-gpio8a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/pull/1/files)

TODO48

After fixing GPIO Output, #NuttX now blinks the Blue LED (GPIO 11) on PineCone #BL602! 🎉

```text
nsh> gpio -o 1 /dev/gpout1
Driver: /dev/gpout1
  Output pin:    Value=0
  Writing:       Value=1

bl602_configgpio:
  pin=16
  addr=0x40000120
  clearbits=0xffff
  setbits=0x711


bl602_configgpio:
  pin=7
  addr=0x4000010c
  clearbits=0xffff0000
  setbits=0x7110000


bl602_configgpio:
  pin=16
  addr=0x40000120
  clearbits=0xffff
  setbits=0x711


bl602_configgpio:
  pin=7
  addr=0x4000010c
  clearbits=0xffff0000
  setbits=0x7110000


bl602_configgpio:
  pin=0
  addr=0x40000100
  clearbits=0xffff
  setbits=0xb11


bl602_configgpio:
  pin=11
  addr=0x40000114
  clearbits=0xffff0000
  setbits=0xb000000


bl602_configgpio enable output:
  pin=11
  addr=0x40000190
  clearbits=0x0
  setbits=0x800


bl602_configgpio:
  pin=2
  addr=0x40000104
  clearbits=0xffff
  setbits=0xb11



bl602_gpiowrite high:
  pin=11
  addr=0x40000188
  clearbits=0x0
  setbits=0x800

  Verify:        Value=1
nsh>
nsh>
nsh> gpio -o 0 /dev/gpout1
Driver: /dev/gpout1
  Output pin:    Value=1
  Writing:       Value=0

bl602_gpiowrite low:
  pin=11
  addr=0x40000188
  clearbits=0x800
  setbits=0x0

  Verify:        Value=0
nsh>
```

[(See complete log)](https://gist.github.com/lupyuen/4331ed3e326fb827c391e0f4e07c26c5)

![](https://lupyuen.github.io/images/nuttx-gpio6d.png)

[Debug GPIO Output](https://github.com/lupyuen/incubator-nuttx/commit/3b25611bdfd1ebd8097f3319053a25546ed39052)
