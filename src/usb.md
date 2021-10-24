# Build a Linux Driver for PineDio LoRa SX1262 USB Adapter

📝 _30 Oct 2021_

TODO

How we build a LoRa SX1262 Driver for PineDio USB Adapter... And test it on PineBook Pro

-   [__github.com/lupyuen/lora-sx1262__](https://github.com/lupyuen/lora-sx1262)

userland library not kernel driver
tho someday 

![PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-title.jpg)

# BL602 Driver

TODO

Read the articles...

-   ["PineCone BL602 Talks LoRaWAN"](https://lupyuen.github.io/articles/lorawan)

-   ["LoRaWAN on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/lorawan2)

The design of the SX1262 Driver is similar to the SX1276 Driver, which is explained in these articles...

-   ["Connect PineCone BL602 to LoRa Transceiver"](https://lupyuen.github.io/articles/lora)

-   ["PineCone BL602 RISC-V Board Receives LoRa Packets"](https://lupyuen.github.io/articles/lora2)

__CAUTION: Sending a LoRa Message on PineDio USB (not BL602) above 29 bytes will cause message corruption!__

__CAUTION: Receiving a LoRa Message on PineDio USB (not BL602) above 28 bytes will cause message corruption!__

(CH341 SPI seems to have trouble transferring a block of 32 bytes)

Ported from Semtech's Reference Implementation of SX1262 Driver...

https://github.com/Lora-net/LoRaMac-node/tree/master/src/radio/sx126x

# Read SX1262 Registers

TODO

![](https://lupyuen.github.io/images/usb-registers3.png)

# Transmit LoRa Message

TODO

![](https://lupyuen.github.io/images/usb-transmit2.png)

TODO

![](https://lupyuen.github.io/images/usb-chirp2.png)

# Receive LoRa Message

TODO

![](https://lupyuen.github.io/images/usb-receive4.png)

TODO19

![](https://lupyuen.github.io/images/usb-receive5.png)

# Sleep

TODO

![](https://lupyuen.github.io/images/usb-sleep3.png)

# CH341 SPI

TODO

-   [CH340 Datasheet (English)](http://www.wch-ic.com/downloads/CH340DS1_PDF.html)

-   [CH341 Datasheet (Chinese)](http://www.wch.cn/downloads/CH341DS1_PDF.html)

-   [CH341 Interfaces (Chinese)](http://www.wch.cn/downloads/CH341DS2_PDF.html)

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
    
    https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L65-L77

1.  Register GPIO Interrupt Handler for DIO1: `SX126xIoIrqInit`

    https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L79-L91

1.  Reset SX1262 via GPIO: `SX126xReset`

    (For now we reset SX1262 by manually unplugging PineDio USB)

    https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L149-L169

1.  Check SX1262 Busy State via GPIO: `SX126xWaitOnBusy`

    (For now we sleep 10 milliseconds)

    https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L171-L182

1.  Get DIO1 Pin State: `SX126xGetDio1PinState`

    https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L337-L344

We also need Background Threads to receive LoRa Messages in the background...

https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L355-L408

More about PineDio USB and CH341 GPIO:

https://wiki.pine64.org/wiki/JF%27s_note_on_PineDio_devices#RAW_LoRa_communication_between_USB_LoRa_adapter_and_PineDio_STACK

# WisBlock

TODO

![](https://lupyuen.github.io/images/usb-wisblock5.png)

TODO28

![](https://lupyuen.github.io/images/usb-wisblock6.png)

TODO29

![](https://lupyuen.github.io/images/usb-wisblock4.png)

# What's Next

TODO

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

https://wiki.pine64.org/wiki/JF%27s_note_on_PineDio_devices#RAW_LoRa_communication_between_USB_LoRa_adapter_and_PineDio_STACK
