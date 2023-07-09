# Booting RISC-V Linux on Star64 JH7110 SBC

📝 _4 Jul 2023_

![Star64 JH7110 RISC-V SBC with Woodpecker USB Serial Adapter](https://lupyuen.github.io/images/linux-title.jpg)

[_Star64 JH7110 RISC-V SBC with Woodpecker USB Serial Adapter_](https://wiki.pine64.org/wiki/STAR64)

Previously we talked about the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer. (Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

And we inspected the Linux Images for Star64...

- [__"Inspecting the RISC-V Linux Images for Star64 JH7110 SBC"__](https://lupyuen.github.io/articles/star64)

Today we'll boot them on Star64! We'll soon see...

- __Yocto Linux__ boots OK on Star64

  (Even KDE Plasma)

- __Armbian Linux__ is not quite ready

  (Missing Device Tree)

- __Apache NuttX RTOS__ boots a bit

  (Thanks to Armbian)

- Helped by __OpenSBI__ and __U-Boot Bootloader__

  (We'll explain why)

Read on for the details...

_What's NuttX?_

[__Apache NuttX__](https://lupyuen.github.io/articles/riscv) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

The analysis that we do today will be super helpful for [__porting NuttX to Star64__](https://lupyuen.github.io/articles/riscv#jump-to-start).

![UART0 TX and RX on GPIO Header Pins 8 and 10](https://lupyuen.github.io/images/star64-uart1.jpg)

# Serial Console on Star64

Before we begin, let's connect a __USB Serial Adapter__ to Star64. (So we can see the Boot Log)

We'll use the [__Pine64 Woodpecker Serial Adapter__](https://pine64.com/product/serial-console-woodpecker-edition/). (Any CH340 or similar adapter should work)

According to [__Star64 Schematic__](https://files.pine64.org/doc/star64/Star64_Schematic_V1.1_20230504.pdf) (Page 18), __UART0 TX and RX__ (GPIO 5 and 6) are connected to the __GPIO Header__ (Pins 8 and 10). (Pic above)

Thus we connect these pins...

| Star64 GPIO Header | [USB Serial Adapter](https://pine64.com/product/serial-console-woodpecker-edition/) | Wire Colour |
|:----:|:----:|:----|
| Pin 6 (GND) | GND | Brown
| Pin 8 (TX) | RX | Red
| Pin 10 (RX) | TX | Orange

On our USB Serial Adapter, set the Voltage Jumper to __3V3__. (Instead of 5V, pic below)

![Pine64 Woodpecker Serial Adapter](https://lupyuen.github.io/images/star64-uart3.jpg)

On our computer, connect to the USB Serial Port at __115.2 kbps__...

```bash
screen /dev/ttyUSB0 115200
```

Insert the __microSD Card__ (from next section) and power up Star64.

Verify that the __DIP Switches__ for GPIO 0 and 1 are set to __Low and Low__. (Default setting, pic below)

So Star64 should start the U-Boot Bootloader from __Internal Flash Memory__.

[(DIP Switch Labels are inverted: __"ON KE"__ actually means __"Low"__)](https://wiki.pine64.org/wiki/STAR64#Prototype_Bringup_Notes)

![DIP Switches for GPIO 0 and 1 are set to Low and Low](https://lupyuen.github.io/images/star64-uart2.jpg)

# Boot Yocto Linux on Star64

_What's Yocto Linux?_

[__Yocto__](https://www.yoctoproject.org/) provides tools for creating a Custom Linux Image. (Like for Star64)

Yocto is like baking [__Sourdough Bread__](https://lupyuen.github.io/articles/sourdough)...

We start with the base (Sourdough Starter + Flour), then we add fruits, nuts, seeds, chocolate, ... Baked into a delicious loaf that's uniquely ours!

(Compare with Linux Distros, which is like buying a loaf of bread)

_Ahem enough with the bread..._

Righto! We download the [__Yocto Minimal Image for Star64__](https://github.com/Fishwaldo/meta-pine64)...

-   [__star64-image-minimal 1.2__](https://pine64.my-ho.st:8443/star64-image-minimal-star64-1.2.wic.bz2)

Uncompress the __.bz2__ file, rename as __.img__.

(Balena Etcher won't work with __.bz2__ files!)

Write the __.img__ file to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

When we boot the microSD Card on Star64, the __OpenSBI (Supervisor Binary Interface)__ appears (loaded from Internal Flash Memory)...

```text
OpenSBI v1.2
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|
Platform Name: StarFive VisionFive V2
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/b23edf50cecbee13e5aab3c0bae6c528)

(We'll explain OpenSBI in a while)

OpenSBI starts the [__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/board/starfive/visionfive2.html#flashing) (also loaded from Internal Flash Memory)...

```text
U-Boot 2021.10 (Jan 19 2023 - 04:09:41 +0800), Build: jenkins-github_visionfive2-6
CPU:   rv64imacu
Model: StarFive VisionFive V2
DRAM:  8 GiB
```

U-Boot Bootloader loads the [__Yocto Linux Kernel__](https://lupyuen.github.io/articles/star64#yocto-image-for-star64), [__Initial RAM Disk__](https://docs.kernel.org/admin-guide/initrd.html) and [__Flattened Device Tree (FDT)__](https://u-boot.readthedocs.io/en/latest/develop/devicetree/index.html) from the microSD Card...

```text
Loading kernel from FIT Image at a0000000 ...
  Load Address: 0x40200000
  Entry Point:  0x40200000
Loading ramdisk from FIT Image at a0000000 ...
  Load Address: 0x46100000
Loading fdt from FIT Image at a0000000 ...
  Load Address: 0x46000000
  Loading fdt from 0xa094e97c to 0x46000000
  Booting using the fdt blob at 0x46000000
  Uncompressing Kernel Image
Booting kernel in
  Flattened Device Tree blob at 46000000
  Booting using the fdt blob at 0x46000000
  Using Device Tree in place at 0000000046000000, end 000000004600efff
```

[(Packed into a __FIT: Flat Image Tree__)](https://lupyuen.github.io/articles/star64#yocto-image-for-star64)

And boots the [__Yocto Linux Kernel__](https://lupyuen.github.io/articles/star64#yocto-image-for-star64)...

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
Linux version 5.15.107 (oe-user@oe-host) 
  (riscv64-pine64-linux-gcc (GCC) 11.3.0, GNU ld (GNU Binutils) 2.38.20220708) 
  #1 SMP Mon May 15 17:57:25 UTC 2023
```

We log in with __root__ or __pine64__...

| Username | Password |
|:--|:--| 
| `root` | `pine64`
| `pine64` | `pine64`

[(Source)](https://github.com/Fishwaldo/meta-pine64#usernames)

```text
PinIx 1.2 star64 hvc0
star64 login: root
Password: pine64

root@star64:~# uname -a
Linux star64 5.15.107 #1 SMP Mon May 15 17:57:25 UTC 2023
  riscv64 riscv64 riscv64 GNU/Linux
```

[(Source)](https://gist.github.com/lupyuen/b23edf50cecbee13e5aab3c0bae6c528)

Yep the Yocto Minimal Image boots OK on Star64! Let's do something more colourful...

![Yocto Linux with KDE Plasma on Star64](https://lupyuen.github.io/images/star64-plasma.jpg)

# Yocto Linux with KDE Plasma

_Yocto Minimal looks so dull. Is there anything graphical?_

Yep! Let's download the [__Yocto Plasma Image for Star64__](https://github.com/Fishwaldo/meta-pine64)...

-   [__star64-image-plasma__](https://pine64.my-ho.st:8443/star64-image-plasma-star64-1.2.wic.bz2)

Uncompress the __.bz2__ file, rename as __.img__.

Write it to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

When we boot the microSD Card on Star64, the KDE Plasma Desktop Environment runs OK on a HDMI Display! (Pic above)

Remember to log in as __root__ or __pine64__...

| Username | Password |
|:--|:--| 
| `root` | `pine64`
| `pine64` | `pine64`

[(Source)](https://github.com/Fishwaldo/meta-pine64#usernames)

![Armbian Image for Star64](https://lupyuen.github.io/images/star64-armbian.png)

# Boot Armbian Linux on Star64

_What about other Linux Distros?_

Let's boot Armbian Linux on Star64! We download the [__Armbian Image for Star64__](https://www.armbian.com/star64/)...

-   [__Armbian 23.8 Lunar for Star64 (Minimal)__](https://github.com/armbianro/os/releases/download/23.8.0-trunk.69/Armbian_23.8.0-trunk.69_Star64_lunar_edge_5.15.0_minimal.img.xz)

Uncompress the __.xz__ file. Write the __.img__ file to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

_What happens when we boot the microSD on Star64?_

Sadly, Armbian won't boot on Star64!

```text
Retrieving file: /boot/uInitrd
  10911538 bytes read in 466 ms (22.3 MiB/s)
Retrieving file: /boot/Image
  22040576 bytes read in 936 ms (22.5 MiB/s)
Retrieving file: /boot/dtb/starfive/jh7110-star64-pine64.dtb
  Failed to load '/boot/dtb/starfive/jh7110-star64-pine64.dtb'
```

[(Source)](https://gist.github.com/lupyuen/d73ace627318375fe20e90e4950f9c50)

That's because the [__Flattened Device Tree (FDT)__](https://u-boot.readthedocs.io/en/latest/develop/devicetree/index.html) is missing...

- [__Armbian Image fails to boot__](https://lupyuen.github.io/articles/star64#armbian-image-for-star64)

So Armbian is not quite ready for Star64. But no worries! Armbian will be super helpful for booting NuttX RTOS, as we'll soon see.

_When will Linux Distros officially support Star64 and JH7110?_

Real soon! Check the upstreaming progress here...

- [__JH7110 Upstream Status__](https://rvspace.org/en/project/JH7110_Upstream_Plan)

![OpenSBI and U-Boot Bootloader on Star64](https://lupyuen.github.io/images/star64-opensbi.jpg)

# OpenSBI Supervisor Binary Interface

_Earlier we saw OpenSBI when booting Star64..._

_What's OpenSBI?_

```text
U-Boot SPL 2021.10 (Jan 19 2023 - 04:09:41 +0800)
DDR version: dc2e84f0.
Trying to boot from SPI
OpenSBI v1.2
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|
Platform Name             : StarFive VisionFive V2
Platform Features         : medeleg
Platform HART Count       : 5
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 4000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : jh7110-hsm
Platform PMU Device       : ---
Platform Reboot Device    : pm-reset
Platform Shutdown Device  : pm-reset
Firmware Base             : 0x40000000
Firmware Size             : 288 KB
Runtime SBI Version       : 1.0
```

[(Source)](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64)

[__OpenSBI (Open Source Supervisor Binary Interface)__](https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/) is the first thing that boots on Star64.

OpenSBI provides Secure Access to the __Low-Level System Functions__ (controlling CPUs, Timers, Interrupts) for the JH7110 SoC...

- [__RISC-V Supervisor Binary Interface__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/riscv-sbi.pdf)

This says that [__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/board/starfive/visionfive2.html#flashing) will be started next (at Address [__`0x4020` `0000`__](https://github.com/u-boot/u-boot/blob/master/board/starfive/visionfive2/Kconfig#L14-L19))...

```text
Domain0 Name              : root
Domain0 Boot HART         : 1
Domain0 HARTs             : 0*,1*,2*,3*,4*
Domain0 Region00          : 0x0000000002000000-0x000000000200ffff (I)
Domain0 Region01          : 0x0000000040000000-0x000000004007ffff ()
Domain0 Region02          : 0x0000000000000000-0xffffffffffffffff (R,W,X)
Domain0 Next Address      : 0x0000000040200000
Domain0 Next Arg1         : 0x0000000042200000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes
```

[("S-mode" refers to __Supervisor Mode__)](https://github.com/lupyuen/nuttx-star64#nuttx-fails-to-get-hart-id)

(What's `0x4220` `0000`?)

And the __RISC-V Hardware Thread__ (HART) will support ["__rv64imafdcbx__"](https://lupyuen.github.io/articles/riscv#qemu-emulator-for-risc-v)...

```text
Boot HART ID              : 1
Boot HART Domain          : root
Boot HART Priv Version    : v1.11
Boot HART Base ISA        : rv64imafdcbx
Boot HART ISA Extensions  : none
Boot HART PMP Count       : 8
Boot HART PMP Granularity : 4096
Boot HART PMP Address Bits: 34
Boot HART MHPM Count      : 2
Boot HART MIDELEG         : 0x0000000000000222
Boot HART MEDELEG         : 0x000000000000b109
```

[(A __RISC-V HART__ is equivalent to a Single CPU Core)](https://lupyuen.github.io/articles/riscv#get-cpu-id)

[(More about __OpenSBI for Star64__)](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64)

Let's jump to U-Boot...

# U-Boot Bootloader for Star64

_What happens when U-Boot Bootloader starts on Star64?_

Star64 loads __U-Boot Bootloader__ from Internal Flash Memory into RAM Address [__`0x4020` `0000`__](https://github.com/u-boot/u-boot/blob/master/board/starfive/visionfive2/Kconfig#L14-L19) and runs it...

```text
U-Boot 2021.10 (Jan 19 2023 - 04:09:41 +0800), Build: jenkins-github_visionfive2-6
CPU:   rv64imacu
Model: StarFive VisionFive V2
DRAM:  8 GiB
MMC:   sdio0@16010000: 0, sdio1@16020000: 1
Loading Environment from SPIFlash... 
SF: Detected gd25lq128 with page size 256 Bytes, erase size 4 KiB, total 16 MiB
*** Warning - bad CRC, using default environment
Hit any key to stop autoboot
```

[(Source)](https://lupyuen.github.io/articles/linux#appendix-u-boot-bootloader-log-for-star64)

Suppose there's __no microSD Card inserted__.

U-Boot tries to __load the Linux Image__ from the microSD Card, but fails...

```text
Card did not respond to voltage select! : -110
Couldn't find partition mmc 0:3
Can't set block device
Importing environment from mmc0 ...
## Warning: Input data exceeds 1048576 bytes - truncated
## Info: input data size = 1048578 = 0x100002
Card did not respond to voltage select! : -110
Couldn't find partition mmc 1:2
Can't set block device
## Warning: defaulting to text format
## Error: "boot2" not defined
Card did not respond to voltage select! : -110
```

Then it tries to load the Linux Image __from the Network__, but also fails...

```text
ethernet@16030000 Waiting for PHY auto negotiation to complete.........
TIMEOUT !
phy_startup() failed: -110
FAILED: -110
ethernet@16040000 Waiting for PHY auto negotiation to complete......... 
TIMEOUT !
StarFive # 
```

And stops at the __U-Boot Command Prompt__.  Here's our chance to experiment with U-Boot!

Enter "__printenv__" to see the __U-Boot Settings__...

```text
StarFive # printenv
boot_prefixes=/ /boot/
boot_syslinux_conf=extlinux/extlinux.conf
bootdir=/boot
bootenv=uEnv.txt
kernel_addr_r=0x40200000
memory_addr=40000000
memory_size=200000000
ver=U-Boot 2021.10 (Jan 19 2023 - 04:09:41 +0800)
...
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

U-Boot says that...

- __Boot Configuration__ will be loaded from microSD at

  [__/boot/extlinux/extlinux.conf__](https://lupyuen.github.io/articles/star64#armbian-image-for-star64)

- __Linux Kernel__ will be loaded at RAM Address [__kernel_addr_r__](https://u-boot.readthedocs.io/en/latest/develop/bootstd.html#environment-variables)

  __`0x4020` `0000`__

We'll use these in the next section.

To see the other __U-Boot Commands__, enter "__help__"...

```text
StarFive # help
boot      - boot default, i.e., run 'bootcmd'
bootefi   - Boots an EFI payload from memory
bootelf   - Boot from an ELF image in memory
booti     - boot Linux kernel 'Image' format from memory
bootm     - boot application image from memory
bootp     - boot image via network using BOOTP/TFTP protocol
setenv    - set environment variables
printenv  - print environment variables
...
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-commands-for-star64)

[(More about __U-Boot for Star64__)](https://lupyuen.github.io/articles/linux#appendix-u-boot-bootloader-log-for-star64)

Finally let's talk about NuttX...

![Boot Apache NuttX RTOS on Star64](https://lupyuen.github.io/images/star64-nuttx.png)

# Boot Apache NuttX RTOS on Star64

_Will NuttX RTOS boot on Star64?_

Let's review everything that we learnt today...

1.  Boot Configuration is loaded from microSD at [__/boot/extlinux/extlinux.conf__](https://lupyuen.github.io/articles/star64#armbian-image-for-star64)

1.  Armbian Image fails to boot because the [__Device Tree is missing__](https://lupyuen.github.io/articles/linux#boot-armbian-linux-on-star64)

1.  Though the [__Armbian Kernel loads OK__](https://lupyuen.github.io/articles/linux#boot-armbian-linux-on-star64) with U-Boot Bootloader

1.  U-Boot Bootloader will boot Linux Kernels at [__RAM Address `0x4020` `0000`__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

So why don't we patch the Armbian Image to __boot NuttX instead__...

1.  Keep the same Boot Configuration at __extlinux.conf__

1.  But fix the __Missing Device Tree__ for NuttX

1.  Overwrite the Armbian Kernel by __NuttX Kernel__

1.  And compile NuttX to boot at __`0x4020` `0000`__

Let's do it! We take the [__Armbian microSD Card__](https://lupyuen.github.io/articles/linux#boot-armbian-linux-on-star64) and patch it...

```bash
## Fix the Missing Device Tree
sudo chmod go+w /run/media/$USER/armbi_root/boot
sudo chmod go+w /run/media/$USER/armbi_root/boot/dtb/starfive
cp \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-visionfive-v2.dtb \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-star64-pine64.dtb

## We assume that `nuttx` contains the NuttX ELF Image.
## Export the NuttX Binary Image to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Delete Armbian Kernel `/boot/Image`
rm /run/media/$USER/armbi_root/boot/Image

## Copy `nuttx.bin` to Armbian Kernel `/boot/Image`
cp nuttx.bin /run/media/$USER/armbi_root/boot/Image
```

[(Source)](https://github.com/lupyuen/nuttx-star64#boot-nuttx-on-star64)

_What's this NuttX ELF Image "nuttx"?_

We generate the __NuttX ELF Image__ by compiling [__NuttX for 64-bit RISC-V QEMU__](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu) with these tweaks...

- [__"NuttX prints to QEMU Console"__](https://github.com/lupyuen/nuttx-star64#nuttx-prints-to-qemu-console)

- [__"UART Base Address for Star64"__](https://github.com/lupyuen/nuttx-star64#uart-base-address-for-star64)

- [__"RISC-V Linux Kernel Header"__](https://github.com/lupyuen/nuttx-star64#risc-v-linux-kernel-header)

- [__"Set Start Address of NuttX Kernel"__](https://github.com/lupyuen/nuttx-star64#set-start-address-of-nuttx-kernel)

We'll explain why in the next article.

_Does it boot?_

When we insert the microSD Card into Star64 and power up...

NuttX boots and prints "__`123`__" yay! (Pic above)

[(As printed by our __Boot Code__)](https://github.com/lupyuen/nuttx-star64#nuttx-prints-to-qemu-console)

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123
```

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-star64#boot-nuttx-on-star64)

But NuttX crashes right after that...

```text
Unhandled exception: Illegal instruction
EPC: 000000004020005c RA: 00000000fff471c6 TVAL: 00000000f1402573
EPC: ffffffff804ba05c RA: 00000000402011c6 reloc adjusted

SP:  00000000ff733630 GP:  00000000ff735e00 TP:  0000000000000001
T0:  0000000010000000 T1:  0000000000000033 T2:  7869662e6b637366
S0:  0000000000000400 S1:  00000000ffff1428 A0:  0000000000000001
A1:  0000000046000000 A2:  0000000000000600 A3:  0000000000004000
A4:  0000000000000000 A5:  0000000040200000 A6:  00000000fffd5708
A7:  0000000000000000 S2:  00000000fff47194 S3:  0000000000000003
S4:  fffffffffffffff3 S5:  00000000fffdbb50 S6:  0000000000000000
S7:  0000000000000000 S8:  00000000fff47194 S9:  0000000000000002
S10: 0000000000000000 S11: 0000000000000000 T3:  0000000000000023
T4:  000000004600b5cc T5:  000000000000ff00 T6:  000000004600b5cc

Code: 0313 0320 8023 0062 0313 0330 8023 0062 (2573 f140)

resetting ...
reset not supported yet
### ERROR ### Please RESET the board ###
```

[(Source)](https://github.com/lupyuen/nuttx-star64#boot-nuttx-on-star64)

Why did NuttX crash at __`0x4020` `005C`__? All shall be revealed in the next article!

-   [__"Apache NuttX RTOS on RISC-V: Star64 JH7110 SBC"__](https://lupyuen.github.io/articles/nuttx2)

![Cody AI Assistant tries to explain our RISC-V Exception](https://lupyuen.github.io/images/star64-exception.jpg)

_Cody AI Assistant tries to explain our RISC-V Exception_

# What's Next

Please join me in the next article as we talk about Apache NuttX RTOS for Star64 SBC...

-   [__"Apache NuttX RTOS on RISC-V: Star64 JH7110 SBC"__](https://lupyuen.github.io/articles/nuttx2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36579963)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18449)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/linux.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/linux.md)

![U-Boot Bootloader Log](https://lupyuen.github.io/images/star64-opensbi.jpg)

# Appendix: OpenSBI Log for Star64

[__OpenSBI (Open Source Supervisor Binary Interface)__](https://www.thegoodpenguin.co.uk/blog/an-overview-of-opensbi/) is the first thing that boots on Star64. (Loaded from Internal Flash Memory)

OpenSBI provides Secure Access to the __Low-Level System Functions__ (controlling CPUs, Timers, Interrupts) for the JH7110 SoC...

- [__RISC-V Supervisor Binary Interface__](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/riscv-sbi.pdf)

__OpenSBI for Star64__ is documented here...

- [__U-Boot for StarFive VisionFive2__](https://u-boot.readthedocs.io/en/latest/board/starfive/visionfive2.html)

__Source Code__ for OpenSBI is at...

- [__github.com/riscv-software-src/opensbi__](https://github.com/riscv-software-src/opensbi)

- [__opensbi/platform/generic/starfive__](https://github.com/riscv-software-src/opensbi/tree/master/platform/generic/starfive)

Here's the OpenSBI Log for Star64...

```text
U-Boot SPL 2021.10 (Jan 19 2023 - 04:09:41 +0800)
DDR version: dc2e84f0.
Trying to boot from SPI

OpenSBI v1.2
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name             : StarFive VisionFive V2
Platform Features         : medeleg
Platform HART Count       : 5
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 4000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : jh7110-hsm
Platform PMU Device       : ---
Platform Reboot Device    : pm-reset
Platform Shutdown Device  : pm-reset
Firmware Base             : 0x40000000
Firmware Size             : 288 KB
Runtime SBI Version       : 1.0

Domain0 Name              : root
Domain0 Boot HART         : 1
Domain0 HARTs             : 0*,1*,2*,3*,4*
Domain0 Region00          : 0x0000000002000000-0x000000000200ffff (I)
Domain0 Region01          : 0x0000000040000000-0x000000004007ffff ()
Domain0 Region02          : 0x0000000000000000-0xffffffffffffffff (R,W,X)
Domain0 Next Address      : 0x0000000040200000
Domain0 Next Arg1         : 0x0000000042200000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes

Boot HART ID              : 1
Boot HART Domain          : root
Boot HART Priv Version    : v1.11
Boot HART Base ISA        : rv64imafdcbx
Boot HART ISA Extensions  : none
Boot HART PMP Count       : 8
Boot HART PMP Granularity : 4096
Boot HART PMP Address Bits: 34
Boot HART MHPM Count      : 2
Boot HART MIDELEG         : 0x0000000000000222
Boot HART MEDELEG         : 0x000000000000b109
```

After OpenSBI, Star64 runs U-Boot Bootloader...

# Appendix: U-Boot Bootloader Log for Star64

[__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/index.html) is loaded from Internal Flash Memory, runs right after OpenSBI, and starts the Linux Kernel for Star64, as documented here...

- [__U-Boot for StarFive VisionFive2__](https://u-boot.readthedocs.io/en/latest/board/starfive/visionfive2.html)

The U-Boot __Build Settings__ for Star64 are here...

- [__board/starfive/visionfive2/Kconfig__](https://github.com/u-boot/u-boot/blob/master/board/starfive/visionfive2/Kconfig#L14-L19)

__Source Code__ for U-Boot is at...

- [__github.com/u-boot/u-boot__](https://github.com/u-boot/u-boot)

Here's the log for U-Boot Bootloader on Star64 (without microSD Card inserted)...

```text
U-Boot 2021.10 (Jan 19 2023 - 04:09:41 +0800), Build: jenkins-github_visionfive2-6

CPU:   rv64imacu
Model: StarFive VisionFive V2
DRAM:  8 GiB
MMC:   sdio0@16010000: 0, sdio1@16020000: 1
Loading Environment from SPIFlash... SF: Detected gd25lq128 with page size 256 Bytes, erase size 4 KiB, total 16 MiB
*** Warning - bad CRC, using default environment

StarFive EEPROM format v2

--------EEPROM INFO--------
Vendor : PINE64
Product full SN: STAR64V1-2310-D008E000-00000003
data version: 0x2
PCB revision: 0xc1
BOM revision: A
Ethernet MAC0 address: 6c:cf:39:00:75:5d
Ethernet MAC1 address: 6c:cf:39:00:75:5e
--------EEPROM INFO--------

In:    serial@10000000
Out:   serial@10000000
Err:   serial@10000000
Model: StarFive VisionFive V2
Net:   eth0: ethernet@16030000, eth1: ethernet@16040000
Card did not respond to voltage select! : -110
Card did not respond to voltage select! : -110
bootmode flash device 0
Card did not respond to voltage select! : -110
Hit any key to stop autoboot:  2  1  0 
Card did not respond to voltage select! : -110
Couldn't find partition mmc 0:3
Can't set block device
Importing environment from mmc0 ...
## Warning: Input data exceeds 1048576 bytes - truncated
## Info: input data size = 1048578 = 0x100002
Card did not respond to voltage select! : -110
Couldn't find partition mmc 1:2
Can't set block device
## Warning: defaulting to text format
## Error: "boot2" not defined
Card did not respond to voltage select! : -110
ethernet@16030000 Waiting for PHY auto negotiation to complete......... TIMEOUT !
phy_startup() failed: -110FAILED: -110ethernet@16040000 Waiting for PHY auto negotiation to complete......... TIMEOUT !
phy_startup() failed: -110FAILED: -110ethernet@16030000 Waiting for PHY auto negotiation to complete......... TIMEOUT !
phy_startup() failed: -110FAILED: -110ethernet@16040000 Waiting for PHY auto negotiation to complete......... TIMEOUT !
phy_startup() failed: -110FAILED: -110StarFive # 
StarFive # 
```

Which is OK because we haven't inserted a microSD Card.

## U-Boot Settings for Star64

Here are the __U-Boot Settings__ for Star64...

[(Derived from the __Build Settings__)](https://github.com/u-boot/u-boot/blob/master/board/starfive/visionfive2/Kconfig#L14-L19)

```text
StarFive # printenv
baudrate=115200
boot_a_script=load ${devtype} ${devnum}:${distro_bootpart} ${scriptaddr} ${prefix}${script}; source ${scriptaddr}
boot_efi_binary=load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_r} efi/boot/bootriscv64.efi; if fdt addr ${fdt_addr_r}; then bootefi ${kernel_addr_r} ${fdt_addr_r};else bootefi ${kernel_addr_r} ${fdtcontroladdr};fi
boot_efi_bootmgr=if fdt addr ${fdt_addr_r}; then bootefi bootmgr ${fdt_addr_r};else bootefi bootmgr;fi
boot_extlinux=sysboot ${devtype} ${devnum}:${distro_bootpart} any ${scriptaddr} ${prefix}${boot_syslinux_conf}
boot_prefixes=/ /boot/
boot_script_dhcp=boot.scr.uimg
boot_scripts=boot.scr.uimg boot.scr
boot_syslinux_conf=extlinux/extlinux.conf
boot_targets=mmc0 dhcp 
bootargs=console=ttyS0,115200  debug rootwait  earlycon=sbi
bootcmd=run load_vf2_env;run importbootenv;run load_distro_uenv;run boot2;run distro_bootcmd
bootcmd_dhcp=devtype=dhcp; if dhcp ${scriptaddr} ${boot_script_dhcp}; then source ${scriptaddr}; fi;setenv efi_fdtfile ${fdtfile}; setenv efi_old_vci ${bootp_vci};setenv efi_old_arch ${bootp_arch};setenv bootp_vci PXEClient:Arch:00027:UNDI:003000;setenv bootp_arch 0x1b;if dhcp ${kernel_addr_r}; then tftpboot ${fdt_addr_r} dtb/${efi_fdtfile};if fdt addr ${fdt_addr_r}; then bootefi ${kernel_addr_r} ${fdt_addr_r}; else bootefi ${kernel_addr_r} ${fdtcontroladdr};fi;fi;setenv bootp_vci ${efi_old_vci};setenv bootp_arch ${efi_old_arch};setenv efi_fdtfile;setenv efi_old_arch;setenv efi_old_vci;
bootcmd_distro=run fdt_loaddtb; run fdt_sizecheck; run set_fdt_distro; sysboot mmc ${fatbootpart} fat c0000000 ${bootdir}/${boot_syslinux_conf}; 
bootcmd_mmc0=devnum=0; run mmc_boot
bootdelay=2
bootdir=/boot
bootenv=uEnv.txt
bootmode=flash
bootpart=0:3
chip_vision=UNKOWN
chipa_gmac_set=fdt set /soc/ethernet@16030000/ethernet-phy@0 tx_inverted_10 <0x0>;fdt set /soc/ethernet@16030000/ethernet-phy@0 tx_inverted_100 <0x0>;fdt set /soc/ethernet@16030000/ethernet-phy@0 tx_inverted_1000 <0x0>;fdt set /soc/ethernet@16030000/ethernet-phy@0 tx_delay_sel <0x9>;fdt set /soc/ethernet@16040000/ethernet-phy@1 tx_inverted_10 <0x0>;fdt set /soc/ethernet@16040000/ethernet-phy@1 tx_inverted_100 <0x0>;fdt set /soc/ethernet@16040000/ethernet-phy@1 tx_inverted_1000 <0x0>;fdt set /soc/ethernet@16040000/ethernet-phy@1 tx_delay_sel <0x9> 
chipa_set=if test ${chip_vision} = A; then run chipa_gmac_set;fi; 
chipa_set_linux=fdt addr ${fdt_addr_r};run visionfive2_mem_set;run chipa_set;
chipa_set_linux_force=fdt addr ${fdt_addr_r};run visionfive2_mem_set;run chipa_gmac_set; 
chipa_set_uboot=fdt addr ${uboot_fdt_addr};run chipa_set;
chipa_set_uboot_force=fdt addr ${uboot_fdt_addr};run chipa_gmac_set; 
devnum=0
distro_bootcmd=for target in ${boot_targets}; do run bootcmd_${target}; done
distroloadaddr=0xb0000000
efi_dtb_prefixes=/ /dtb/ /dtb/current/
eth0addr=6c:cf:39:00:75:5d
eth1addr=6c:cf:39:00:75:5e
ethact=ethernet@16030000
ethaddr=6c:cf:39:00:75:5d
ext4bootenv=ext4load mmc ${bootpart} ${loadaddr} ${bootdir}/${bootenv}
fatbootpart=1:2
fdt_addr_r=0x46000000
fdt_high=0xffffffffffffffff
fdt_loaddtb=fatload mmc ${fatbootpart} ${fdt_addr_r} ${bootdir}/dtbs/${fdtfile}; fdt addr ${fdt_addr_r}; 
fdt_sizecheck=fatsize mmc ${fatbootpart} ${bootdir}/dtbs/${fdtfile}; 
fdtaddr=fffc6aa0
fdtcontroladdr=fffc6aa0
fdtfile=starfive/starfive_visionfive2.dtb
importbootenv=echo Importing environment from mmc${devnum} ...; env import -t ${loadaddr} ${filesize}
initrd_high=0xffffffffffffffff
ipaddr=192.168.120.230
kernel_addr_r=0x40200000
load_distro_uenv=fatload mmc ${fatbootpart} ${distroloadaddr} ${bootdir}/${bootenv}; env import ${distroloadaddr} 17c; 
load_efi_dtb=load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} ${prefix}${efi_fdtfile}
load_vf2_env=fatload mmc ${bootpart} ${loadaddr} ${testenv}
loadaddr=0xa0000000
loadbootenv=fatload mmc ${bootpart} ${loadaddr} ${bootenv}
memory_addr=40000000
memory_size=200000000
mmc_boot=if mmc dev ${devnum}; then devtype=mmc; run scan_dev_for_boot_part; fi
mmcbootenv=run scan_mmc_dev; setenv bootpart ${devnum}:${mmcpart}; if mmc rescan; then run loadbootenv && run importbootenv; run ext4bootenv && run importbootenv; if test -n $uenvcmd; then echo Running uenvcmd ...; run uenvcmd; fi; fi
mmcpart=3
netmask=255.255.255.0
partitions=name=loader1,start=17K,size=1M,type=${type_guid_gpt_loader1};name=loader2,size=4MB,type=${type_guid_gpt_loader2};name=system,size=-,bootable,type=${type_guid_gpt_system};
preboot=run chipa_set_uboot;run mmcbootenv
pxefile_addr_r=0x45900000
ramdisk_addr_r=0x46100000
scan_dev_for_boot=echo Scanning ${devtype} ${devnum}:${distro_bootpart}...; for prefix in ${boot_prefixes}; do run scan_dev_for_extlinux; run scan_dev_for_scripts; done;run scan_dev_for_efi;
scan_dev_for_boot_part=part list ${devtype} ${devnum} -bootable devplist; env exists devplist || setenv devplist 1; for distro_bootpart in ${devplist}; do if fstype ${devtype} ${devnum}:${distro_bootpart} bootfstype; then run scan_dev_for_boot; fi; done; setenv devplist
scan_dev_for_efi=setenv efi_fdtfile ${fdtfile}; for prefix in ${efi_dtb_prefixes}; do if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${efi_fdtfile}; then run load_efi_dtb; fi;done;run boot_efi_bootmgr;if test -e ${devtype} ${devnum}:${distro_bootpart} efi/boot/bootriscv64.efi; then echo Found EFI removable media binary efi/boot/bootriscv64.efi; run boot_efi_binary; echo EFI LOAD FAILED: continuing...; fi; setenv efi_fdtfile
scan_dev_for_extlinux=if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${boot_syslinux_conf}; then echo Found ${prefix}${boot_syslinux_conf}; run boot_extlinux; echo SCRIPT FAILED: continuing...; fi
scan_dev_for_scripts=for script in ${boot_scripts}; do if test -e ${devtype} ${devnum}:${distro_bootpart} ${prefix}${script}; then echo Found U-Boot script ${prefix}${script}; run boot_a_script; echo SCRIPT FAILED: continuing...; fi; done
scan_mmc_dev=if test ${bootmode} = flash; then if mmc dev ${devnum}; then echo found device ${devnum};else setenv devnum 0;mmc dev 0;fi; fi; echo bootmode ${bootmode} device ${devnum};
scan_sf_for_scripts=${devtype} read ${scriptaddr} ${script_offset_f} ${script_size_f}; source ${scriptaddr}; echo SCRIPT FAILED: continuing...
script_offset_f=0x1fff000
script_size_f=0x1000
scriptaddr=0x43900000
serial#=STAR64V1-2310-D008E000-00000003
set_fdt_distro=if test ${chip_vision} = A; then if test ${memory_size} = 200000000; then run chipa_gmac_set;run visionfive2_mem_set;fatwrite mmc ${fatbootpart} ${fdt_addr_r} ${bootdir}/dtbs/${fdtfile} ${filesize};else run chipa_gmac_set;run visionfive2_mem_set;fatwrite mmc ${fatbootpart} ${fdt_addr_r} ${bootdir}/dtbs/${fdtfile} ${filesize};fi;else run visionfive2_mem_set;fatwrite mmc ${fatbootpart} ${fdt_addr_r} ${bootdir}/dtbs/${fdtfile} ${filesize};fi; 
sf_boot=if sf probe ${busnum}; then devtype=sf; run scan_sf_for_scripts; fi
stderr=serial@10000000
stdin=serial@10000000
stdout=serial@10000000
testenv=vf2_uEnv.txt
type_guid_gpt_loader1=5B193300-FC78-40CD-8002-E86C45580B47
type_guid_gpt_loader2=2E54B353-1271-4842-806F-E436D6AF6985
type_guid_gpt_system=0FC63DAF-8483-4772-8E79-3D69D8477DE4
uboot_fdt_addr=0xfffc6aa0
ver=U-Boot 2021.10 (Jan 19 2023 - 04:09:41 +0800)
visionfive2_mem_set=fdt memory ${memory_addr} ${memory_size};

Environment size: 7246/65532 bytes
```

## U-Boot Commands for Star64

Here are the __U-Boot Commands__ for Star64...

[(Derived from the __Build Settings__)](https://github.com/u-boot/u-boot/blob/master/board/starfive/visionfive2/Kconfig#L14-L19)

```text
StarFive # help
?         - alias for 'help'
base      - print or set address offset
bdinfo    - print Board Info structure
blkcache  - block cache diagnostics and control
boot      - boot default, i.e., run 'bootcmd'
bootd     - boot default, i.e., run 'bootcmd'
bootefi   - Boots an EFI payload from memory
bootelf   - Boot from an ELF image in memory
booti     - boot Linux kernel 'Image' format from memory
bootm     - boot application image from memory
bootp     - boot image via network using BOOTP/TFTP protocol
bootvx    - Boot vxWorks from an ELF image
cmp       - memory compare
config    - print .config
coninfo   - print console devices and information
cp        - memory copy
cpu       - display information about CPUs
crc32     - checksum calculation
dhcp      - boot image via network using DHCP/TFTP protocol
dm        - Driver model low level access
echo      - echo args to console
editenv   - edit environment variable
eeprom    - EEPROM sub-system
efidebug  - Configure UEFI environment
env       - environment handling commands
erase     - erase FLASH memory
eraseenv  - erase environment variables from persistent storage
exit      - exit script
ext2load  - load binary file from a Ext2 filesystem
ext2ls    - list files in a directory (default /)
ext4load  - load binary file from a Ext4 filesystem
ext4ls    - list files in a directory (default /)
ext4size  - determine a file's size
ext4write - create a file in the root directory
false     - do nothing, unsuccessfully
fatinfo   - print information about filesystem
fatload   - load binary file from a dos filesystem
fatls     - list files in a directory (default /)
fatmkdir  - create a directory
fatrm     - delete a file
fatsize   - determine a file's size
fatwrite  - write file into a dos filesystem
fdt       - flattened device tree utility commands
flinfo    - print FLASH memory information
fstype    - Look up a filesystem type
fstypes   - List supported filesystem types
fsuuid    - Look up a filesystem UUID
go        - start application at address 'addr'
gpio      - query and control gpio pins
gpt       - GUID Partition Table
gzwrite   - unzip and write memory to block device
help      - print command description/usage
i2c       - I2C sub-system
iminfo    - print header information for application image
imxtract  - extract a part of a multi-image
itest     - return true/false on integer compare
ln        - Create a symbolic link
load      - load binary file from a filesystem
loadb     - load binary file over serial line (kermit mode)
loads     - load S-Record file over serial line
loadx     - load binary file over serial line (xmodem mode)
loady     - load binary file over serial line (ymodem mode)
log       - log system
loop      - infinite loop on address range
ls        - list files in a directory (default /)
lzmadec   - lzma uncompress a memory region
mac       - display and program the system ID and MAC addresses in EEPROM
md        - memory display
misc      - Access miscellaneous devices with MISC uclass driver APIs
mm        - memory modify (auto-incrementing address)
mmc       - MMC sub system
mmcinfo   - display MMC info
mw        - memory write (fill)
net       - NET sub-system
nfs       - boot image via network using NFS protocol
nm        - memory modify (constant address)
panic     - Panic with optional message
part      - disk partition related commands
ping      - send ICMP ECHO_REQUEST to network host
pinmux    - show pin-controller muxing
printenv  - print environment variables
protect   - enable or disable FLASH write protection
random    - fill memory with random pattern
reset     - Perform RESET of the CPU
run       - run commands in an environment variable
save      - save file to a filesystem
saveenv   - save environment variables to persistent storage
setenv    - set environment variables
setexpr   - set environment variable as the result of eval expression
sf        - SPI flash sub-system
showvar   - print local hushshell variables
size      - determine a file's size
sleep     - delay execution for some time
source    - run script from memory
sysboot   - command to get and boot from syslinux files
test      - minimal test like /bin/sh
tftpboot  - boot image via network using TFTP protocol
tftpput   - TFTP put command, for uploading files to a server
true      - do nothing, successfully
unlz4     - lz4 uncompress a memory region
unzip     - unzip a memory region
version   - print monitor, compiler and linker version
```
