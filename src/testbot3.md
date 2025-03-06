# PR Test Bot for PinePhone (Apache NuttX RTOS)

📝 _23 Mar 2025_

![SDWire MicroSD Multiplexer with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-title.jpg)

Earlier we created a [__PR Test Bot__](TODO) that will __Build and Test__ the Pull Requests for __Apache NuttX RTOS__. Our Test Bot kicks into action when we post a [__PR Comment__](TODO)...

```bash
## For Oz64 SG2000 RISC-V SBC:
@nuttxpr test oz64:nsh

## For QEMU Emulator: Arm64 and RISC-V
@nuttxpr test TODO
@nuttxpr test TODO
```

Today we extend our Test Bot to Build and Test the Pull Requests for [__PINE64 PinePhone__](TODO). Yep on the __Real PinePhone Hardware__!

```bash
@nuttxpr test pinephone:nsh
```

- We used Special Hardware: __SDWire MicroSD Multiplexer__ _(pic above)_

- Controlled by a Single-Board Computer: __Yuzuki Avaota-A1__ _(Open Hardware)_

- __PinePhone Test Bot__ kinda works!

- Though __PinePhone Battery__ complicates Hardware Testing

- We might pivot to another __Arm64 Single-Board Computer__

- Maybe we'll port NuttX to __Allwinner A527 SoC__?

TODO: I ordered another _(batteryless)_ [__Arm64 Single-Board Computer__](https://nuttx.apache.org/docs/latest/platforms/arm64/bcm2711/boards/raspberrypi-4b/index.html). Hope it works better with Test Bot than PinePhone!

![SDWire MicroSD Multiplexer](https://lupyuen.org/images/testbot3-mux.jpg)

# SDWire MicroSD Multiplexer

_MicroSD Multiplexer: What's that? (Pic above)_

[__SDWire MicroSD Multiplexer__](https://www.tindie.com/products/3mdeb/sd-wire-sd-card-reader-sd-card-mux/) is an ingenious gadget that allows __Two Devices__ to access One Single __MicroSD Card__. _(One device at a time, not simultaneously)_

_Why would we need it?_

To Test NuttX on __Arm64 Devices__ _(PinePhone)_, we need...

- A Computer _("Test Server")_ to copy the NuttX Image to a __MicroSD Card__

- Then boot it on the __Arm64 Device__ _("Test Device")_

Our Test Bot got no fingers and it can't __Physically Swap__ a MicroSD between Test Server and Test Device.

Thus it needs a MicroSD Multiplexer to __Electically Swap__ the MicroSD between the two machines...

TODO: Pic of mux

_How does it work?_

Inside SDWire is the TODO Multiplexer. Works like FTDI, supports TODO Data Lanes. Our Test Bot will run a Command-Line Tool (provided by SDWire) to "swap" the MicroSD between our Test Server and Test Device.

Let's prepare our Test Server: Avaota-A1 SBC...

![TODO](https://lupyuen.org/images/testbot3-sbc.jpg)

# Yuzuki Avaota-A1 SBC

_What's this Single-Board Computer? (Pic above)_ 

To assemble our Test Bot, I bought a [__Yuzuki Avaota-A1__](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/) Single-Board Computer.  Download the [__Latest AvaotaOS Release__](https://github.com/AvaotaSBC/AvaotaOS/releases) _(Ubuntu Noble GNOME)_ and uncompress it...

```bash
wget https://github.com/AvaotaSBC/AvaotaOS/releases/download/0.3.0.4/AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
xz -d AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
```

Write the __`.img`__ file to a MicroSD with [__Balena Etcher__](TODO). Boot our SBC with the MicroSD and __Login via SSH__...

```bash
## User `avaota`, Password `avaota`
$ ssh avaota@avaota-a1
Password: avaota

## Root Password is also `avaota`
$ sudo 
Password: 密码：avaota
```

[(See the __Boot Log__)](https://gist.github.com/lupyuen/dd4beb052ce07c36d41d409631c6d68b)

While Booting: Our SBC shows a helpful message on the __Onboard LCD__, it should disappear in a while...

![TODO](https://lupyuen.org/images/testbot3-lcd.jpg)

_Hmmm our SBC is forever showing "Booting Linux"?_

Make sure we're booting Avaota OS, not [__Armbian Ubuntu__](TODO)! Which fails with a [__Page Table Panic__](https://gist.github.com/lupyuen/32876ee9696d60e6e95c839c0a937ad4)...

```text
Kernel panic - not syncing:
Failed to allocate page table page
```

Also: Always boot Avaota OS from MicroSD! Fresh from the Factory, our SBC boots to [__Android by Default__](https://gist.github.com/lupyuen/f0195a2ccdd40906b80e2a360b1782ba)!

```text
Linux version 5.15.119-gc08c29131003 (yuzuki@YuzukiKoddo)
Android (8490178, based on r450784d)
clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6)
```

![TODO](https://lupyuen.org/images/testbot3-uart.jpg)

_How to troubleshoot? And see the Boot Logs above?_

Connect a [__USB UART Dongle__](https://pine64.com/product/serial-console-woodpecker-edition/) (CH340 or CP2102) to these pins (pic above)

| Avaota-A1 | USB UART | Colour |
|:------------:|:--------:|:------:|
| __GND__ (Pin 6)	| __GND__ | _Yellow_ |
| __TX__ (Pin 8) |	__RX__ | _Orange_ |
| __RX__ (Pin 10)	| __TX__ | _Red_ |

__Boot Log__ will appear at _/dev/ttyUSB0_...

```bash
screen /dev/ttyUSB0 115200
```

_Why choose Avaota-A1?_

It's [__Open Source Hardware__](https://liliputing.com/yuzuki-avaota-a1-is-a-55-single-board-pc-with-8-arm-cortex-a55-cpu-cores-and-an-embedded-risc-v-core/), available from Multiple Makers. [_(Quite affordable too: $55)_](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/)

TODO: [Avaota A1: Default U-Boot in eMMC. No network :-(](https://gist.github.com/lupyuen/366f1ffefc8231670ffd58a3b88ae8e5)

![TODO](https://lupyuen.org/images/testbot3-mux2.jpg)

# Connect SDWire to SBC

With a __Micro-USB Data Cable__: Connect __SDWire MicroSD Multiplexer__ to our SBC (pic above). Check that it's a USB Data Cable, __Not Power Cable__. And Mini-USB won't work either.

On our SBC, run __`dmesg`__ to watch the Magic of SDWire...

<span style="font-size:80%">

```bash
## Show the Linux Kernel Log
$ dmesg

## Linux discovers our USB Device
usb 1-1: New USB device found, idVendor=0424, idProduct=2640, bcdDevice= 0.00
hub 1-1:1.0: USB hub found
hub 1-1:1.0: 3 ports detected

## Yep it's MicroSD Storage Device
usb 1-1.1: New USB device found, idVendor=0424, idProduct=4050, bcdDevice= 1.76
usb 1-1.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
usb 1-1.1: Product: Ultra Fast Media Reader
usb-storage 1-1.1:1.0: USB Mass Storage device detected
scsi host0: usb-storage 1-1.1:1.0

## Aha! It's also an SDWire Multiplexer
usb 1-1.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
usb 1-1.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
usb 1-1.2: Product: sd-wire
usb 1-1.2: Manufacturer: SRPOL
usb 1-1.2: SerialNumber: sd-wire_02-09

## MicroSD is now accessible at /dev/sda1
scsi 0:0:0:0: Direct-Access Generic Ultra HS-SD/MMC 1.76 PQ: 0 ANSI: 0
sd 0:0:0:0: [sda] 30318592 512-byte logical blocks: (15.5 GB/14.5 GiB)
sd 0:0:0:0: [sda] Write Protect is off
sd 0:0:0:0: [sda] Mode Sense: 23 00 00 00
sd 0:0:0:0: [sda] No Caching mode page found
sd 0:0:0:0: [sda] Assuming drive cache: write through
sd 0:0:0:0: [sda] Attached SCSI removable disk
sda: sda1
```

</span>

![TODO](https://lupyuen.org/images/testbot3-mux3.jpg)

# Compile the SDWire Tools

_How to control SDWire? And flip the MicroSD from Test Server to Test Device?_

Based on the [__SDWire Instructions__](https://docs.dasharo.com/transparent-validation/sd-wire/usage-validation/), we install the __SDWire Tools__...

```bash
## Download the Source Code for `sd-mux-ctrl`
sudo apt-get install libftdi1-dev libpopt-dev cmake pkg-config
git clone https://github.com/3mdeb/sd-mux
cd sd-mux

## Build and Install `sd-mux-ctrl`
mkdir build
cd build
cmake ..
make
sudo make install
```

When we connect SDWire to our SBC, the __Blue LED__ turns on. (Pic left above)

By Default, SDWire runs in __Test Server Mode__: MicroSD is connected to our SBC. Let's flip this.

Run __`dmesg` `-w`__ in a new window to observe the System Messages. Do this to enumerate the __SDWire Devices__...

```bash
$ sudo sd-mux-ctrl --list
Number of FTDI devices found: 1
Dev: 0, Manufacturer: SRPOL
Serial: sd-wire_02-09, Description: sd-wire
```

Take Note of the __Serial ID__: _sd-wire_02-09_. We'll use it below.

Now we Flip the MicroSD from Test Server to __Test Device__ _(DUT: "Device Under Test")_

```bash
## Flip the MicroSD to Test Device: 
## Copy the Serial ID from above
$ sudo sd-mux-ctrl \
  --device-serial=sd-wire_02-09 \
  --dut

## dmesg shows:
## sda: detected capacity change from 30318592 to 0
```

__Green LED__ turns on (pic right above). And _/dev/sda1_ is no longer accessible. Yep our MicroSD has flipped to the Test Device!

Finally do this...

```bash
## Flip the MicroSD to Test Server
## Copy the Serial ID from above
$ sudo sd-mux-ctrl \
  --device-serial=sd-wire_02-09 \
  --ts

## dmesg shows:
## sd 0:0:0:0: [sda] 30318592 512-byte logical blocks: (15.5 GB/14.5 GiB)
## sda: detected capacity change from 0 to 30318592
## sda: sda1
```

__Blue LED__ turns on (pic left above), _/dev/sda1_ is back on our SBC. Everything works hunky dory yay!

# Mount the MicroSD

_How to access the MicroSD at /dev/sda1?_

We mount _/dev/sda1_ like this, to read and write the __MicroSD Files__...

```bash
## Flip the MicroSD to Test Server
## Copy the Serial ID from above
$ sudo sd-mux-ctrl \
  --device-serial=sd-wire_02-09 \
  --ts

## Mount the MicroSD to /tmp/sda1
$ mkdir /tmp/sda1
$ sudo mount /dev/sda1 /tmp/sda1

## MicroSD is now writeable at /tmp/sda1
$ ls -l /tmp/sda1
Image.gz
boot.scr
initramfs.gz
sun50i-a64-pinephone-1.0.dtb
```

Remember to __Unmount the MicroSD__ before switching back, or the MicroSD Files might get corrupted...

```bash
## Unmount the MicroSD
$ sudo umount /tmp/sda1

## Flip the MicroSD to Test Device: 
## Copy the Serial ID from above
$ sudo sd-mux-ctrl \
  --device-serial=sd-wire_02-09 \
  --dut
```

![TODO](https://lupyuen.org/images/testbot3-pinephone.jpg)

# Connect SDWire to PinePhone

_SDWire works OK with our SBC. What next?_

Moment of Truth! We slot SDWire MicroSD Multiplexer into __PinePhone as Test Device__. (Pic above)


# U-Boot

TODO: testbot3-uboot.jpg

![TODO](https://lupyuen.org/images/testbot3-uboot.jpg)


# USB UART

```bash
##  Allow the user to access the USB UART ports
sudo usermod -a -G dialout $USER
##  Logout and login to refresh the permissions
logout
```




# Inside SDWire

https://github.com/3mdeb/sd-mux/blob/master/src/main.cpp

# What's Next

TODO

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/testbot3.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot3.md)
