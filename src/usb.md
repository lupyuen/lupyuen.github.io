# Build a Linux Driver for PineDio LoRa SX1262 USB Adapter

📝 _30 Oct 2021_

_What if our Laptop Computer could talk to other devices..._

_Over a Long Range, Low Bandwidth wireless network like LoRa?_

[(Up to 5 km or 3 miles in urban areas... 15 km or 10 miles in rural areas!)](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan/)

Yep that's possible today... With [__Pinebook Pro__](https://wiki.pine64.org/wiki/Pinebook_Pro) and the [__PineDio LoRa SX1262 USB Adapter__](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)! (Pic below)

This article explains how we built the __LoRa SX1262 Driver__ for PineDio USB Adapter and tested it on Pinebook Pro (Manjaro Linux Arm64)...

-   [__github.com/lupyuen/lora-sx1262__](https://github.com/lupyuen/lora-sx1262)

Our LoRa SX1262 Driver is __still incomplete__ (it's not a Kernel Driver yet), but the driver __talks OK to other LoRa Devices__. (With some limitations)

Read on to learn more...

![PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-title.jpg)

# PineDio LoRa USB Adapter

PineDio LoRa USB Adapter looks like a simple dongle...

1.  Take a [__CH341 USB-to-Serial Interface Module__](http://www.wch-ic.com/products/CH341.html)

    (Top half of pic below)

1.  Connect it to a [__Semtech SX1262 LoRa Module__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) over SPI

    (Bottom half of pic below)

And we get the PineDio LoRa USB Adapter!

![Schematic for PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-schematic.jpg)

[(Source)](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

_So CH341 exposes the SPI Interface for SX1262 over USB?_

Yep Pinebook Pro shall __control SX1262 over SPI__, bridged by CH341.

Which means that we need to install a __CH341 SPI Driver__ on Pinebook Pro.

(More about this in a while)

_What about other pins on SX1262: DIO1 and NRESET?_

__DIO1__ is used by SX1262 to signal that a LoRa Packet has been received.

__NRESET__ is toggled by our computer to reset the SX1262 module.

Pinebook Pro shall control these pins via the __GPIO Interface on CH341__, as we'll see in a while.

[(More about PineDio USB)](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

[(CH341 Datasheet)](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

# LoRa SX1262 Driver for PineDio USB

_Where did the PineDio USB LoRa Driver come from?_

Believe it or not... The PineDio USB LoRa Driver is the exact same driver running on __PineCone BL602__ and __PineDio Stack BL604__! (Pic above)

-   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

-   [__"LoRaWAN on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/lorawan2)

But modified to talk to __CH341 SPI for PineDio USB__.

(And compiled for Arm64 instead of RISC-V 32-bit)

The BL602 / BL604 LoRa Driver was ported from __Semtech's Reference Implementation__ of SX1262 Driver...

-   [__LoRaMac-node/radio/sx126x__](https://github.com/Lora-net/LoRaMac-node/tree/master/src/radio/sx126x)

![The Things Network in Singapore](https://lupyuen.github.io/images/lorawan2-ttn3.png)

[(Source)](https://lupyuen.github.io/articles/lorawan2#seeking-volunteers)

## LoRaWAN Support

_There are many LoRa Drivers out there, why did we port Semtech's Reference Driver?_

That's because Semtech's Reference Driver __supports LoRaWAN__, which adds security features to low-level LoRa.

[(Like for authentication and encryption)](https://lupyuen.github.io/articles/lorawan2#security)

_How useful is LoRaWAN? Will we be using it?_

Someday we might connect PineDio USB to a __LoRaWAN Network__ like...

-   [__The Things Network__](https://lupyuen.github.io/articles/ttn): Free-to-use public global LoRaWAN Network for IoT devices. (Pic above)

-   [__Helium__](https://www.helium.com/lorawan): Commercial global LoRaWAN Network for IoT devices.

Thus it's good to build a LoRa Driver for PineDio USB that will support LoRaWAN in future.

[(I tried porting this new driver by Semtech... But gave up when I discovered it doesn't support LoRaWAN)](https://github.com/Lora-net/sx126x_driver)

## NimBLE Porting Layer

_Do we call any open source libraries in our PineDio USB Driver?_

Yes we call __NimBLE Porting Layer__, the open source library for Multithreading Functions...

-   [__Multitask with NimBLE Porting Layer__](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

To transmit and receive LoRa Messages we need __Timers and Background Threads__. Which are provided by NimBLE Porting Layer.

_Have we used NimBLE Porting Layer before?_

Yep we used NimBLE Porting Layer in the __LoRa SX1262 and SX1276 Drivers__ for BL602...

-   [__"PineCone BL602 RISC-V Board Receives LoRa Packets"__](https://lupyuen.github.io/articles/lora2)

So we're really fortunate that NimBLE Porting Layer complies on Arm64 Linux as well.

[(It's part of PineTime InfiniTime too!)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/dfu#nimble-stack-for-bluetooth-le-on-pinetime)

# Read SX1262 Registers

_What's the simplest way to test our USB PineDio Driver?_

To test whether our USB PineDio Driver is working with CH341 SPI, we can read the __LoRa SX1262 Registers__.

Here's how: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L74-L81)

```c
/// Main Function
int main(void) {
  //  Read SX1262 registers 0x00 to 0x0F
  read_registers();
}

/// Read SX1262 registers
static void read_registers(void) {
  //  Init the SPI port
  SX126xIoInit();

  //  Read and print the first 16 registers: 0 to 15
  for (uint16_t addr = 0; addr < 0x10; addr++) {
    //  Read the register
    uint8_t val = SX126xReadRegister(addr);

    //  Print the register value
    printf("Register 0x%02x = 0x%02x\r\n", addr, val);
  }
}
```

In our Main Function we call __read_registers__ and __SX126xReadRegister__ to read a bunch of SX1262 Registers. (`0x00` to `0x0F`)

In our PineDio USB Driver, __SX126xReadRegister__ calls __SX126xReadRegisters__ and __sx126x_read_register__ to read each register: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L268-L281)

```c
/// Read an SX1262 Register at the specified address
uint8_t SX126xReadRegister(uint16_t address) {
  //  Read one register and return the value
  uint8_t data;
  SX126xReadRegisters(address, &data, 1);
  return data;
}

/// Read one or more SX1262 Registers at the specified address.
/// `size` is the number of registers to read.
void SX126xReadRegisters(uint16_t address, uint8_t *buffer, uint16_t size) {
  //  Wake up SX1262 if sleeping
  SX126xCheckDeviceReady();

  //  Read the SX1262 registers
  int rc = sx126x_read_register(NULL, address, buffer, size);
  assert(rc == 0);

  //  Wait for SX1262 to be ready
  SX126xWaitOnBusy();
}
```

(We'll see __SX126xCheckDeviceReady__ and __SX126xWaitOnBusy__ in a while)

__sx126x_read_register__ reads a register by sending the Read Register Command to SX1262 over SPI: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L486-L495)

```c
/// Send a Read Register Command to SX1262 over SPI
/// and return the results in `buffer`. `size` is the
/// number of registers to read.
static int sx126x_read_register(const void* context, const uint16_t address, uint8_t* buffer, const uint8_t size) {
  //  Reserve 4 bytes for our SX1262 Command Buffer
  uint8_t buf[SX126X_SIZE_READ_REGISTER] = { 0 };

  //  Init the SX1262 Command Buffer
  buf[0] = RADIO_READ_REGISTER;       //  Command ID
  buf[1] = (uint8_t) (address >> 8);  //  MSB of Register ID
  buf[2] = (uint8_t) (address >> 0);  //  LSB of Register ID
  buf[3] = 0;                         //  Unused

  //  Transmit the Command Buffer over SPI 
  //  and receive the Result Buffer
  int status = sx126x_hal_read( 
    context,  //  Context (unsued)
    buf,      //  Command Buffer
    SX126X_SIZE_READ_REGISTER,  //  Command Buffer Size: 4 bytes
    buffer,   //  Result Buffer
    size,     //  Result Buffer Size
    NULL      //  Status not required
  );
  return status;
}
```

And the values of the registers are returned by SX1262 over SPI.

(More about __sx126x_hal_read__ later)

## Run the Driver

Follow the instructions in the Appendix to __download, build and run__ the PineDio USB Driver.

Remember to edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

```c
#define READ_REGISTERS
```

Build and run the PineDio USB Driver...

```bash
## Build PineDio USB Driver
make

## Run PineDio USB Driver
sudo ./lora-sx1262
```

And watch for these __SX1262 Register Values__...

```text
Register 0x00 = 0x00
...
Register 0x08 = 0x80
Register 0x09 = 0x00
Register 0x0a = 0x01
```

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#read-registers)

If we see these values... Our PineDio USB Driver is talking correctly to CH341 SPI and SX1262!

Note that the values above will change when we __transmit and receive LoRa Messages__.

Let's do that next.

![Reading SX1262 Registers](https://lupyuen.github.io/images/usb-registers3.png)

## Source Files for Linux

_We're seeing layers of code, like an onion? (Or Shrek)_

Yep we have __layers of Source Files__ in our SX1262 Driver...

1.  Source Files __specific to Linux__

    (For PineDio USB and Pinebook Pro)

1.  Source Files __specific to BL602 and BL604__

    (For PineCone BL602 and PineDio Stack BL604)

1.  Source Files __common to all platforms__

    (For Linux, BL602 and BL604)

The Source Files __specific to Linux__ are...

-   [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c)

    (Main Program for Linux)

-   [__src/sx126x-linux.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c)

    (Linux Interface for SX1262 Driver)

-   [__npl/linux/src__](https://github.com/lupyuen/lora-sx1262/tree/master/npl/linux/src)

    (NimBLE Porting Layer for Linux)

All other Source Files are shared by Linux, BL602 and BL604.

(Except [__sx126x-board.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-board.c) which is the BL602 / BL604 Interface for SX1262)

# Transmit LoRa Message

TODO

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#send-message)

![](https://lupyuen.github.io/images/usb-transmit2.png)

TODO

![](https://lupyuen.github.io/images/usb-chirp2.png)

# Receive LoRa Message

TODO

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#receive-message)

![](https://lupyuen.github.io/images/usb-receive4.png)

TODO19

![](https://lupyuen.github.io/images/usb-receive5.png)

# Sleep

TODO

![](https://lupyuen.github.io/images/usb-sleep3.png)

# CH341 SPI

TODO

-   [CH341 Datasheet](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

-   [CH341 Interfaces (Chinese)](http://www.wch.cn/downloads/CH341DS2_PDF.html)

CAUTION: Sending a LoRa Message on PineDio USB (not BL602) above 29 bytes will cause message corruption!

CAUTION: Receiving a LoRa Message on PineDio USB (not BL602) above 28 bytes will cause message corruption!

(CH341 SPI seems to have trouble transferring a block of 32 bytes)

![](https://lupyuen.github.io/images/usb-spi6.png)

TODO23

![](https://lupyuen.github.io/images/usb-spi7.png)

TODO24

![](https://lupyuen.github.io/images/usb-spi8.png)

TODO25

![](https://lupyuen.github.io/images/usb-spi5.png)

# CH341 GPIO

TODO

Note that the CH341 GPIO programming is incomplete. We need to...

1.  Init the GPIO Pins: `SX126xIoInit`
    
    [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L65-L77)

1.  Register GPIO Interrupt Handler for DIO1: `SX126xIoIrqInit`

    [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L79-L91)

1.  Reset SX1262 via GPIO: `SX126xReset`

    (For now we reset SX1262 by manually unplugging PineDio USB)

    [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L149-L169)

1.  Check SX1262 Busy State via GPIO: `SX126xWaitOnBusy`

    (For now we sleep 10 milliseconds)

    [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L171-L182)

1.  Get DIO1 Pin State: `SX126xGetDio1PinState`

    [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L337-L344)

We also need Background Threads to receive LoRa Messages in the background...

[main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L355-L408)

More about PineDio USB and CH341 GPIO:

[PineDio Wiki](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

![](https://lupyuen.github.io/images/lora2-handler.png)

# WisBlock

TODO

![](https://lupyuen.github.io/images/usb-wisblock5.png)

TODO28

![](https://lupyuen.github.io/images/usb-wisblock6.png)

TODO29

![](https://lupyuen.github.io/images/usb-wisblock4.png)

# What's Next

TODO

LoRa Gateway for Internet

LoRaWAN

Backport to PineDio Stack

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/usb.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/usb.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1451548895461326858)

# Appendix: Build PineDio USB Driver

TODO

To build PineDio USB Driver on Pinebook Pro Manjaro Arm64...

```bash
## Install DKMS
sudo pacman -Syu dkms base-devel --needed

## Install Kernel Headers for Manjaro: https://linuxconfig.org/manjaro-linux-kernel-headers-installation
uname -r 
## Should show "5.14.12-1-MANJARO-ARM" or similar
sudo pacman -S linux-headers
pacman -Q | grep headers
## Should show "linux-headers 5.14.12-1" or similar

## Reboot to be safe
sudo reboot now

## Install CH341 SPI Driver
git clone https://github.com/rogerjames99/spi-ch341-usb.git
pushd spi-ch341-usb
## TODO: Edit Makefile and change...
##   KERNEL_DIR  = /usr/src/linux-headers-$(KVERSION)/
## To...
##   KERNEL_DIR  = /lib/modules/$(KVERSION)/build
make
sudo make install
popd

## Unload the module ch341 if it has been automatically loaded
lsmod | grep ch341
sudo rmmod ch341

## Load the new module
sudo modprobe spi-ch341-usb

## Plug in PineDio USB and check that the module has been correctly loaded.
## See dmesg Log below. This needs to be checked every time we reboot
## our computer and when we plug in PineDio USB.
dmesg

## If we see "spi_ch341_usb: loading out-of-tree module taints kernel",
## Unplug PineDio USB, run "sudo rmmod ch341", plug in PineDio USB again
## and recheck dmesg.

## Download PineDio USB Driver
git clone --recursive https://github.com/lupyuen/lora-sx1262
cd lora-sx1262

## TODO: Edit src/main.c and uncomment READ_REGISTERS, SEND_MESSAGE or RECEIVE_MESSAGE.
## See "PineDio USB Operations" below

## Build PineDio USB Driver
make

## Run PineDio USB Driver Demo.
## See Output Log below.
sudo ./lora-sx1262
```

More about PineDio USB and CH341 SPI:

[PineDio Wiki](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

## PineDio USB Operations

The PineDio USB Demo supports 3 operations...

1.  Read SX1262 Registers:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define READ_REGISTERS
    ```

    (See the Read Register Log below)

1.  Send LoRa Message:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define SEND_MESSAGE
    ```

    (See the Send Message Log below)

1.  Receive LoRa Message:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define RECEIVE_MESSAGE
    ```

    (See the Receive Message Log below)

# Appendix: PineDio USB dmesg Log

## Connect USB

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#connect-usb)

dmesg Log when plugging PineDio USB to Pinebook Pro...

```text
usb 3-1:
new full-speed USB device number 2 using xhci-hcd
New USB device found, idVendor=1a86, idProduct=5512, bcdDevice= 3.04
New USB device strings: Mfr=0, Product=2, SerialNumber=0
Product: USB UART-LPT

spi-ch341-usb 3-1:1.0:
  ch341_usb_probe:
    connect device
    bNumEndpoints=3
      endpoint=0 type=2 dir=1 addr=2
      endpoint=1 type=2 dir=0 addr=2
      endpoint=2 type=3 dir=1 addr=1

  ch341_cfg_probe:
    output cs0 SPI slave with cs=0
    output cs0    gpio=0  irq=0 
    output cs1 SPI slave with cs=1
    output cs1    gpio=1  irq=1 
    output cs2 SPI slave with cs=2
    output cs2    gpio=2  irq=2 
    input  gpio4  gpio=3  irq=3 
    input  gpio6  gpio=4  irq=4 
    input  err    gpio=5  irq=5 
    input  pemp   gpio=6  irq=6 
    input  int    gpio=7  irq=7 (hwirq)
    input  slct   gpio=8  irq=8 
    input  wait   gpio=9  irq=9 
    input  autofd gpio=10 irq=10 
    input  addr   gpio=11 irq=11 
    output ini    gpio=12 irq=12 
    output write  gpio=13 irq=13 
    output scl    gpio=14 irq=14 
    output sda    gpio=15 irq=15 

  ch341_spi_probe:
    start
    SPI master connected to SPI bus 1
    SPI device /dev/spidev1.0 created
    SPI device /dev/spidev1.1 created
    SPI device /dev/spidev1.2 created
    done

  ch341_irq_probe:
    start
    irq_base=94
    done

  ch341_gpio_probe: 
    start

  ch341_gpio_get_direction:
    gpio=cs0    dir=0
    gpio=cs1    dir=0
    gpio=cs2    dir=0
    gpio=gpio4  dir=1
    gpio=gpio6  dir=1
    gpio=err    dir=1
    gpio=pemp   dir=1
    gpio=int    dir=1
    gpio=slct   dir=1
    gpio=wait   dir=1
    gpio=autofd dir=1
    gpio=addr   dir=1
    gpio=ini    dir=0
    gpio=write  dir=0
    gpio=scl    dir=0
    gpio=sda    dir=0

  ch341_gpio_probe:
    registered GPIOs from 496 to 511
    done
    connected

  ch341_gpio_poll_function:
    start

usbcore: registered new interface driver ch341
usbserial: USB Serial support registered for ch341-uart
```

This means that the newer CH341 SPI Driver has been loaded.

If we see this instead...

```text
usb 3-1: new full-speed USB device number 2 using xhci-hcd
usb 3-1: New USB device found, idVendor=1a86, idProduct=5512, bcdDevice= 3.04
usb 3-1: New USB device strings: Mfr=0, Product=2, SerialNumber=0
usb 3-1: Product: USB UART-LPT
usbcore: registered new interface driver ch341
usbserial: USB Serial support registered for ch341-uart
ch341 3-1:1.0: ch341-uart converter detected
usb 3-1: ch341-uart converter now attached to ttyUSB0
spi_ch341_usb: loading out-of-tree module taints kernel.
usbcore: registered new interface driver spi-ch341-usb
```

It means the older CH341 Non-SPI Driver has been loaded.

To fix this...

1.  Unplug PineDio USB

1.  Enter...

    ```bash
    sudo rmmod ch341
    ```

1.  Plug in PineDio USB

1.  Enter...

    ```bash
    dmesg
    ```

    And recheck the messages.

## Send Message

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#send-message-1)

dmesg Log when PineDio USB is transmitting a 29-byte LoRa Packet...

__CAUTION: Sending a LoRa Message on PineDio USB (not BL602) above 29 bytes will cause message corruption!__

```text
audit: type=1105 audit(1634994194.295:1270): pid=72110 uid=1000 auid=1000 ses=4 subj==unconfined msg='op=PAM:session_open grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/3 res=success'
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
audit: type=1701 audit(1634994203.075:1271): auid=1000 uid=0 gid=0 ses=4 subj==unconfined pid=72111 comm="lora-sx1262" exe="/home/luppy/lora-sx1262/lora-sx1262" sig=6 res=1
```

Note that if we try to transmit a 64-byte packet, it won't appear in the dmesg Log.

## Receive Message

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#receive-message-1)

dmesg Log when PineDio USB is receiving a 28-byte LoRa Packet...

__CAUTION: Receiving a LoRa Message on PineDio USB (not BL602) above 28 bytes will cause message corruption!__

```text
audit: type=1105 audit(1635046697.907:371): pid=29045 uid=1000 auid=1000 ses=7 subj==unconfined msg='op=PAM:session_open grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/5 res=success'
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
audit: type=1106 audit(1635046711.037:372): pid=29045 uid=1000 auid=1000 ses=7 subj==unconfined msg='op=PAM:session_close grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/5 res=success'
```
