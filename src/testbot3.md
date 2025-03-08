# PR Test Bot for PinePhone (Apache NuttX RTOS)

📝 _23 Mar 2025_

![SDWire MicroSD Multiplexer with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-title.jpg)

Earlier we created a [__PR Test Bot__](https://lupyuen.github.io/articles/testbot) that will __Build and Test__ the Pull Requests for __Apache NuttX RTOS__. Our Test Bot kicks into action when we post a [__PR Comment__](https://lupyuen.github.io/articles/testbot2)...

```bash
## For Oz64 SG2000 RISC-V SBC
@nuttxpr test oz64:nsh

## For QEMU Emulator: Arm64 and RISC-V
@nuttxpr test qemu-armv8a:netnsh
@nuttxpr test rv-virt:knsh64
```

Today we extend our Test Bot to Build and Test the Pull Requests for [__PINE64 PinePhone__](https://lupyuen.github.io/articles/what). Yep on the __Real Arm64 PinePhone Hardware__!

```bash
@nuttxpr test pinephone:nsh
```

- We used Special Hardware: __SDWire MicroSD Multiplexer__ _(pic above)_

- Controlled by a Single-Board Computer: __Yuzuki Avaota-A1__ _(Open Hardware)_

- __PinePhone Test Bot__ kinda works!

- Though __PinePhone Battery__ complicates Hardware Testing

- We might pivot to another __Arm64 Single-Board Computer__

- Maybe we'll port NuttX to __Allwinner A527 SoC__?

![SDWire MicroSD Multiplexer](https://lupyuen.org/images/testbot3-mux.jpg)

# SDWire MicroSD Multiplexer

_MicroSD Multiplexer: What's that? (Pic above)_

[__SDWire MicroSD Multiplexer__](https://www.tindie.com/products/3mdeb/sd-wire-sd-card-reader-sd-card-mux/) is an ingenious gadget that allows __Two Devices__ to access One Single __MicroSD Card__. _(One device at a time, not simultaneously)_

_Why would we need it?_

To Test NuttX on __Arm64 Devices__ _(PinePhone)_, we need...

- A Computer _("Test Server")_ to copy the NuttX Image to a __MicroSD Card__

- Then boot it on the __Arm64 Device__ _("Test Device")_

Our Test Bot got no fingers and it can't __Physically Swap__ a MicroSD between Test Server and Test Device.

That's I bought a MicroSD Multiplexer to __Electically Swap__ the MicroSD between the two machines...

![MicroSD Multiplexer for Test Bot](https://lupyuen.org/images/testbot2-flow.jpg)

_How does it work?_

According to [__SDWire Schematic__](https://docs.dasharo.com/transparent-validation/sd-wire/specification/#pcb-elements-and-scheme), the gadget has a [__TS3A27518EPWR__](https://www.ti.com/product/TS3A27518E) Multiplexer inside. _(Works like FTDI, but 6 Data Channels)_

Our Test Bot will run a Command-Line Tool (provided by SDWire) to "swap" the MicroSD between our Test Server and Test Device.

__Micro-USB Port__ of SDWire exposes two functions...

1.  __USB Mass Storage:__ For reading and writing the MicroSD

1.  __SDWire Multiplexer:__ For swapping the MicroSD between devices

Let's prepare our Test Server: Avaota-A1 SBC...

![Yuzuki Avaota-A1 SBC with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-sbc.jpg)

# Yuzuki Avaota-A1 SBC

_What's this Single-Board Computer? (Pic above)_ 

To assemble our Test Bot, I bought a [__Yuzuki Avaota-A1__](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/) Single-Board Computer.  Download the [__Latest AvaotaOS Release__](https://github.com/AvaotaSBC/AvaotaOS/releases) _(Ubuntu Noble GNOME)_ and uncompress it...

```bash
wget https://github.com/AvaotaSBC/AvaotaOS/releases/download/0.3.0.4/AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
xz -d AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
```

Write the __`.img`__ file to a MicroSD with [__Balena Etcher__](https://etcher.balena.io/). Boot our SBC with the MicroSD and __Login via SSH__...

```bash
## User `avaota`, Password `avaota`
$ ssh avaota@avaota-a1
Password: avaota

## Root Password is also `avaota`
$ sudo 
Password: avaota
```

[(See the __Boot Log__)](https://gist.github.com/lupyuen/dd4beb052ce07c36d41d409631c6d68b)

While Booting: Our SBC shows a helpful message on the __Onboard LCD__, it should disappear in a while...

![Avaota-A1 SBC with Onboard LCD](https://lupyuen.org/images/testbot3-lcd.jpg)

_Hmmm our SBC is forever showing "Booting Linux"?_

Make sure we're booting Avaota OS, not [__Armbian Ubuntu__](https://www.armbian.com/avaota-a1/). Armbian will fail with a [__Page Table Panic__](https://gist.github.com/lupyuen/32876ee9696d60e6e95c839c0a937ad4)...

```text
Kernel panic - not syncing:
Failed to allocate page table page
```

Also: Always boot Avaota OS from MicroSD! Fresh from the Factory, our SBC eMMC boots to [__Android by Default__](https://gist.github.com/lupyuen/f0195a2ccdd40906b80e2a360b1782ba)!

```text
Linux version 5.15.119-gc08c29131003 (yuzuki@YuzukiKoddo)
Android (8490178, based on r450784d)
clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6)
```

![Avaota-A1 SBC connected to USB UART](https://lupyuen.org/images/testbot3-uart.jpg)

_How to troubleshoot? And see the Boot Logs above?_

Connect a [__USB UART Dongle__](https://pine64.com/product/serial-console-woodpecker-edition/) (CH340 or CP2102) to these pins (pic above)

| Avaota-A1 | USB UART | Colour |
|:------------:|:--------:|:------:|
| __GND__ (Pin 6)	| __GND__ | _Yellow_ |
| __TX__ (Pin 8) |	__RX__ | _Orange_ |
| __RX__ (Pin 10)	| __TX__ | _Red_ |

__Boot Log__ will appear at _/dev/ttyUSB0_...

```bash
## Allow the user to access the USB UART port
## Logout and login to refresh the permissions
sudo usermod -a -G dialout $USER
logout

## Connect to USB UART Console
screen /dev/ttyUSB0 115200
```

_Why choose Avaota-A1?_

It's [__Open Source Hardware__](https://liliputing.com/yuzuki-avaota-a1-is-a-55-single-board-pc-with-8-arm-cortex-a55-cpu-cores-and-an-embedded-risc-v-core/), available from Multiple Makers. [_(Quite affordable too: $55)_](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/)

![SDWire connected to Avaota-A1 SBC](https://lupyuen.org/images/testbot3-mux2.jpg)

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

## Yep it's a MicroSD Storage Device
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

![SDWire: Blue for Test Server, Green for Test Device](https://lupyuen.org/images/testbot3-mux3.jpg)

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
## Flip the MicroSD to Test Device
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

![Flip the MicroSD to Test Server](https://lupyuen.org/images/testbot3-test1.png)

_What's inside sd-mux-ctrl?_

__sd-mux-ctrl__ calls the __FTDI Library__ to flip the multiplexer. Single, elegant and very clever: [sd-mux/main.cpp](https://github.com/3mdeb/sd-mux/blob/master/src/main.cpp#L484-L556)

```c
// When we select a Mux Target: Test Server or Test Device...
int selectTarget(Target target, CCOptionValue options[]) { ...

  // Compute the Pin State based on Mux Target
  pinState = 0x00;
  pinState |= 0xF0; // Upper half of the byte sets all pins to output (SDWire has only one bit - 0)
  pinState |=       // Lower half of the byte sets state of output pins.
    (target == T_DUT)
    ? 0x00
    : 0x01;

  // Call FTDI Library to apply the Pin State
  ftdi_set_bitmode(ftdi, pinState, BITMODE_CBUS);
```

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

## Flip the MicroSD to Test Device
## Copy the Serial ID from above
$ sudo sd-mux-ctrl \
  --device-serial=sd-wire_02-09 \
  --dut
```

![SDWire connected to PinePhone](https://lupyuen.org/images/testbot3-pinephone.jpg)

# Test SDWire with PinePhone

_SDWire works OK with our SBC. What next?_

Moment of Truth! We connect __SDWire MicroSD Multiplexer__ into...

- __Test Device: PinePhone__ _(Pic above)_

- __Test Server: Avaota-A1 SBC__ _(Via Micro-USB)_

Which is easier with [__PinePhone MicroSD Extender__](https://pine64.com/product/pinephone-microsd-extender/)...

![SDWire MicroSD Multiplexer with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-title.jpg)

_Does it work?_

Let's assume our [__Build Server__](https://lupyuen.github.io/articles/testbot#control-our-oz64-sbc) has compiled the PR Code into a __NuttX Image__...

![MicroSD Multiplexer for Test Bot](https://lupyuen.org/images/testbot2-flow.jpg)

1.  We flip the __MicroSD to SBC__ _(Test Server)_, and mount the MicroSD...

    ```bash
    ## Flip the MicroSD to Test Server
    ## Mount the MicroSD to /tmp/sda1
    sudo sd-mux-ctrl --device-serial=sd-wire_02-09 --ts
    mkdir /tmp/sda1
    sudo mount /dev/sda1 /tmp/sda1
    ```

    ![Flip the MicroSD to Test Server](https://lupyuen.org/images/testbot3-test1.png)

1.  Copy the __NuttX Image__ to MicroSD...

    ```bash
    ## Copy the NuttX Image to MicroSD
    cp Image.gz /tmp/sda1
    ```

1.  Unmount the MicroSD, and flip the __MicroSD to PinePhone__ _(Test Device)_

    ```bash
    ## Unmount the MicroSD
    ## Flip the MicroSD to Test Device
    sudo umount /tmp/sda1
    sudo sd-mux-ctrl --device-serial=sd-wire_02-09 --dut
    ```

    ![Flip the MicroSD to Test Device](https://lupyuen.org/images/testbot3-test2.png)

1.  Power on PinePhone with a [__Smart Power Plug__](https://lupyuen.github.io/articles/testbot#power-up-our-oz64-sbc)

    _(Thanks to Home Assistant API)_

    ![PinePhone boots NuttX yay](https://lupyuen.org/images/testbot3-test3.png)

1.  PinePhone boots NuttX yay!

    ```bash
    NuttShell (NSH) NuttX-12.8.0
    nsh> uname -a
    NuttX 12.8.0 3bf704ad13 Dec 31 2024 14:18:14 arm64 pinephone
    ```

    [(Watch the __Demo on YouTube__)](https://youtu.be/lYiIEip0zII)

![Complications with PinePhone Battery](https://lupyuen.org/images/lvgl2-title.jpg)

# Complications with PinePhone Battery

_Huh! PinePhone will power up with a Smart Power Plug?_

OK our PinePhone is a little wonky: The __Power Button__ won't work any more. But powering up the __USB-C Port__ on PinePhone will boot just fine.

_What about the PinePhone Battery?_

Yeah it gets complicated: USB-C Power __will charge up__ the PinePhone Battery. Which means PinePhone __won't shut down__ when we power off the USB-C Port!

Thus we have an Automated Way to Power Up PinePhone. And it gets stuck there until the __PinePhone Battery totally drains__. This is _utterly ungood_ for our Test Bot sigh.

_Why not do it on a Battery-Less Device?_

I ordered another _(battery-less)_ [__Arm64 Single-Board Computer__](https://nuttx.apache.org/docs/latest/platforms/arm64/bcm2711/boards/raspberrypi-4b/index.html). Hope it works better with Test Bot than PinePhone!

There's another intriguing solution...

![Yuzuki Avaota-A1 SBC with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-sbc.jpg)

# Port NuttX to Allwinner A527 SoC

_How about booting and testing NuttX on Avaota-A1 SBC?_

Exactly! Here's why Avaota-A1 SBC should run NuttX...

- __Avaota-A1__ has the latest Octa-Core Arm64 SoC: __Allwinner A527__

  _(Bonus: There's a tiny RISC-V Core inside)_

- [__NuttX Kernel Build__](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode) sounds ideal for Allwinner A527 SoC

  _(Instead of the restrictive Flat Build)_

- __Avaota-A1__ could be the first Arm64 Port of NuttX Kernel Build

  [_(NXP i.MX93 might be another)_](https://github.com/apache/nuttx/pull/15556)

- __SDWire MicroSD Multiplexer__: Avaota SBC was previously the __Test Server__, now it becomes the __Test Device__

  _(Porting NuttX gets a lot quicker)_

- __Open-Source RTOS__ _(NuttX)_ tested on __Open-Source Hardware__ _(Avaota-A1)_ ... Perfectly sensible!

We'll take the NuttX Kernel Build for [__QEMU Arm64__](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig), boot it on Avaota-A1 SBC. We're making terrific progress with [__NuttX on Avaota SBC__](https://github.com/lupyuen/nuttx-avaota-a1)...

> ![NuttX on Avaota-A1](https://lupyuen.org/images/testbot3-port.png)

_Isn't it faster to port NuttX with U-Boot TFTP?_

Yeah for RISC-V Ports we boot [__NuttX over TFTP__](https://lupyuen.github.io/articles/starpro64#boot-nuttx-over-tftp). But Avaota U-Boot [__doesn't support TFTP__](https://gist.github.com/lupyuen/366f1ffefc8231670ffd58a3b88ae8e5), so it's back to MicroSD sigh. (Pic below)

Well thankfully we have a __MicroSD Multiplexer__ that will make MicroSD Swapping a lot easier! (Not forgetting our [__Smart Power Plug__](https://lupyuen.github.io/articles/testbot#power-up-our-oz64-sbc))

![Avaota A1: Default U-Boot in eMMC. No network :-(](https://lupyuen.org/images/testbot3-uboot.jpg)

# What's Next

Next Article: We chat about porting [__NuttX to Avaota-A1 SBC__](https://github.com/lupyuen/nuttx-avaota-a1). Stay tuned!

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/testbot3.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot3.md)
