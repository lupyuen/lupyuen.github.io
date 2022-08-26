# PinePhone boots Apache NuttX RTOS

📝 _1 Sep 2022_

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title.png)

_Apache NuttX RTOS booting on Pine64 PinePhone_

Suppose we're creating our own Operating System (non-Linux)  for Pine64 PinePhone...

-   What's the file format?
-   Where in RAM should it run?
-   Can we make a microSD that will boot our OS?
-   What happens when PinePhone powers on?

This article explains how we ported Apache NuttX RTOS to PinePhone. And we'll answer these questions along the way!

Let's dive in and walk through the steps...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Allwinner A64 SoC User Manual](https://lupyuen.github.io/images/uboot-a64.jpg)

[_Allwinner A64 SoC User Manual_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Allwinner A64 SoC

_What's inside PinePhone?_

At the heart of PinePhone is the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) (System-on-a-Chip) with 4 Cores of 64-bit __Arm Cortex-A53__...

-   [__PinePhone Wiki__](https://wiki.pine64.org/index.php/PinePhone)

-   [__Allwinner A64 Info__](https://linux-sunxi.org/A64)

-   [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

The A64 SoC in PinePhone comes with __2GB RAM__ (or 3GB RAM via a mainboard upgrade)...

-   [__Allwinner A64 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

A64's __Memory Map__ says that the RAM starts at address __`0x4000` `0000`__.

_So our OS will run at `0x4000` `0000`?_

Not quite! Our OS will actually be loaded at __`0x4008` `0000`__

We'll see why in a while, but first we talk about a Very Important Cable...

![PinePhone connected to USB Serial Debug Cable](https://lupyuen.github.io/images/arm-uart2.jpg)

[_PinePhone connected to USB Serial Debug Cable_](https://lupyuen.github.io/articles/arm#uart-driver-for-nuttx)

# USB Serial Debug Cable

_Can we watch what happens when PinePhone boots?_

There's a magical cable for that: __USB Serial Debug Cable__ (pic above)...

-   [__PinePhone Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

It connects to PinePhone's __Headphone Port__ (pic below) and exposes PinePhone's hidden __UART Port.__ Genius!

[(Remember to flip the Headphone Switch to OFF)](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration)

I highly recommend the USB Serial Debug Cable for __PinePhone Hacking__.

_What secrets will the Debug Cable reveal?_

We'll find out shortly! First we need to prep our microSD Card for hacking...

![PinePhone UART Port in disguise](https://lupyuen.github.io/images/arm-uart.jpg)

[_PinePhone UART Port in disguise_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# PinePhone Jumpdrive

Let's watch and learn how a __Linux Kernel__ boots on PinePhone.

We pick a small, simple Linux Kernel: __PinePhone Jumpdrive__...

-   [__dreemurrs-embedded/Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive)

And prepare a __microSD Card__ for Jumpdrive...

1.  Download [__`pine64-pinephone.img.xz`__](https://github.com/dreemurrs-embedded/Jumpdrive/releases/download/0.8/pine64-pinephone.img.xz)

1.  Write the downloaded file to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/)

1.  Insert the microSD Card into PinePhone

Don't power up PinePhone yet! We need to talk about PinePhone's Bootloader...

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

_PinePhone Jumpdrive on microSD_

# U-Boot Bootloader

_What happens when we power up PinePhone?_

The [__U-Boot Bootloader__](https://en.wikipedia.org/wiki/Das_U-Boot) runs, searching for a Linux Kernel to boot (on microSD or eMMC)...

-   [__Allwinner A64 Boot ROM__](https://linux-sunxi.org/BROM#A64)

-   [__Allwinner A64 U-Boot__](https://linux-sunxi.org/U-Boot)

-   [__Allwinner A64 U-Boot SPL__](https://linux-sunxi.org/BROM#U-Boot_SPL_limitations)

    (Secondary Program Loader)

-   [__SD Card Layout__](https://linux-sunxi.org/Bootable_SD_card#SD_Card_Layout)

_Whoa! These docs look so dry..._

There's an easier way to grok U-Boot. Let's watch PinePhone boot Jumpdrive!

# Boot Log

Now we can see what happens when PinePhone boots...

1.  Insert the __Jumpdrive microSD__ into PinePhone

1.  Flip PinePhone's [__Headphone Switch__](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration) to OFF

1.  Connect our computer to PinePhone via the [__USB Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

1.  Launch a __Serial Terminal__ (115.2 kbps) on our computer and connect to PinePhone...

    For Linux:

    ```bash
    ## Change ttyUSB0 to the USB Serial Device
    sudo screen /dev/ttyUSB0 115200
    ```

    For macOS: Use __`screen`__ or [__CoolTerm__](https://freeware.the-meiers.org/)

    For Windows: Use [__PuTTY__](https://www.putty.org/)

1.  Power up PinePhone

This is the __Boot Log__ that we'll see...

```text
$ sudo screen /dev/ttyUSB0 115200

DRAM: 2048 MiB
Trying to boot from MMC1
NOTICE:  BL31: v2.2(release):v2.2-904-gf9ea3a629
NOTICE:  BL31: Built : 15:32:12, Apr  9 2020
NOTICE:  BL31: Detected Allwinner A64/H64/R18 SoC (1689)
NOTICE:  BL31: Found U-Boot DTB at 0x4064410, model: PinePhone
NOTICE:  PSCI: System suspend is unavailable
```

__BL31__ refers to [__Arm Trusted Firmware__](https://chromium.googlesource.com/chromiumos/third_party/arm-trusted-firmware/+/v1.2-rc0/docs/firmware-design.md), the very first thing that runs on PinePhone.

BL31 finds the __Device Tree__ (DTB) for the U-Boot Bootloader, and starts U-Boot...

```text
U-Boot 2020.07 (Nov 08 2020 - 00:15:12 +0100)
DRAM:  2 GiB
MMC:   Device 'mmc@1c11000': seq 1 is in use by 'mmc@1c10000'
mmc@1c0f000: 0, mmc@1c10000: 2, mmc@1c11000: 1
Loading Environment from FAT... *** Warning - bad CRC, using default environment

starting USB...
No working controllers found
Hit any key to stop autoboot:  0 
```

Yep U-Boot __can be stopped!__ Later we'll hit some keys to stop U-Boot and run some commands.

But for now we let U-Boot do its booting thing...

```text
switch to partitions #0, OK
mmc0 is current device
Scanning mmc 0:1...
Found U-Boot script /boot.scr
653 bytes read in 3 ms (211.9 KiB/s)
```

U-Boot scans our microSD and discovers a __U-Boot Script `boot.scr`__

We'll talk more about the script, which __loads the Linux Kernel__ into RAM and starts it...

```text
## Executing script at 4fc00000
gpio: pin 114 (gpio 114) value is 1
4275261 bytes read in 192 ms (21.2 MiB/s)
Uncompressed size: 10170376 = 0x9B3008
36162 bytes read in 4 ms (8.6 MiB/s)
1078500 bytes read in 50 ms (20.6 MiB/s)
## Flattened Device Tree blob at 4fa00000
   Booting using the fdt blob at 0x4fa00000
   Loading Ramdisk to 49ef8000, end 49fff4e4 ... OK
   Loading Device Tree to 0000000049eec000, end 0000000049ef7d41 ... OK

Starting kernel ...
/ #
```

The __Linux Kernel__ is running! It works like we expect...

```text
/ # uname -a
Linux (none) 5.9.1jumpdrive #3 SMP Sun Nov 8 00:41:50 CET 2020 aarch64 GNU/Linux

/ # ls
bin                info.sh            root               telnet_connect.sh
config             init               sbin               usr
dev                init_functions.sh  splash.ppm
error.ppm.gz       linuxrc            splash.ppm.gz
etc                proc               sys
```

And that's how PinePhone boots a Linux Kernel, thanks to the U-Boot Bootloader!

# Boot Script

_What's `boot.scr`?_

```text
Found U-Boot script /boot.scr
```

According to the log above, the U-Boot Bootloader runs the __U-Boot Script `boot.scr`__ to...

-   Light up the PinePhone LED (I think?)

-   Load the __Linux Kernel `Image.gz`__ into RAM

    (At `0x4408` `0000`)

-   Unzip the __Linux Kernel `Image.gz`__ in RAM

    (At `0x4008` `0000`)

-   Load the __Linux Device Tree__...

    `sun50i-a64-pinephone-1.2.dtb`

    (At `0x4FA0` `0000`)

-   Load the __RAM File System `initramfs.gz`__

    (At `0x4FE0` `0000`)

-   Boot the __Unzipped Linux Kernel__ in RAM

    (At `0x4008` `0000`)

Here's the Source File: [Jumpdrive/src/pine64-pinephone.txt](https://github.com/dreemurrs-embedded/Jumpdrive/blob/master/src/pine64-pinephone.txt)

```bash
setenv kernel_addr_z 0x44080000

setenv bootargs loglevel=0 silent console=tty0 vt.global_cursor_default=0

gpio set 114

if load ${devtype} ${devnum}:${distro_bootpart} ${kernel_addr_z} /Image.gz; then
  unzip ${kernel_addr_z} ${kernel_addr_r}
  if load ${devtype} ${devnum}:${distro_bootpart} ${fdt_addr_r} /sun50i-a64-pinephone-1.2.dtb; then
    if load ${devtype} ${devnum}:${distro_bootpart} ${ramdisk_addr_r} /initramfs.gz; then
      booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r};
    else
      booti ${kernel_addr_r} - ${fdt_addr_r};
    fi;
  fi;
fi
```

(We'll explain fdt_addr_r, kernel_addr_r and ramdisk_addr_r)

The above U-Boot Script __`pine64-pinephone.txt`__ is compiled to __`boot.scr`__ by this Makefile: [Jumpdrive/Makefile](https://github.com/dreemurrs-embedded/Jumpdrive/blob/master/Makefile#L207-L209)

```text
%.scr: src/%.txt
	@echo "MKIMG $@"
	@mkimage -A arm -O linux -T script -C none -n "U-Boot boot script" -d $< $@
```

[(__`mkimage`__ is documented here)](https://manpages.ubuntu.com/manpages/bionic/man1/mkimage.1.html)

# Boot Address

_What are fdt_addr_r, kernel_addr_r and ramdisk_addr_r?_

They are __Environment Variables__ defined in U-Boot. To see the variables in U-Boot...

1.  Power off PinePhone

1.  On our computer's Serial Terminal, keep hitting Enter, don't stop...

1.  Power up PinePhone

U-Boot should stop and reveal the __U-Boot Prompt__...

```text
U-Boot 2020.07 (Nov 08 2020 - 00:15:12 +0100)
Hit any key to stop autoboot:
=>
```

Enter __`printenv`__ to print the __Environment Variables__...

```text
=> printenv
kernel_addr_r=0x40080000
fdt_addr_r=0x4FA00000
ramdisk_addr_r=0x4FE00000
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx#pinephone-u-boot-log)

When we match these addresses with our [__U-Boot Script__](https://github.com/dreemurrs-embedded/Jumpdrive/blob/master/src/pine64-pinephone.txt), we discover...

-   __`kernel_addr_r`__: Linux Kernel `Image` will be unzipped into RAM at __`0x4008` `0000`__. And it will execute at that address.

-   __`fdt_addr_r`__: Linux Device Tree `sun50i*.dtb` will be loaded into RAM at __`0x4FA0` `0000`__

-   __`ramdisk_addr_r`__: Linux RAM File System `initramfs` will be loaded into RAM at __`0x4FE0` `0000`__

_Aha! That's why our kernel must start at `0x4008` `0000`!_

Yep! We can...

-   Compile our own operating system to start at __`0x4008` `0000`__

-   Replace __`Image.gz`__ in the microSD by our compiled OS (gzipped)

And PinePhone will boot our own OS! (Theoretically)

But there's a catch: U-Boot expects to find a Linux Kernel Header in our OS...

# Linux Kernel Header

_What! A Linux Kernel Header in our non-Linux OS?_

Yep it's totally strange, but U-Boot Bootloader expects our OS to begin with an __Arm64 Linux Kernel Header__ as defined here...

-   [__"Booting AArch64 Linux"__](https://www.kernel.org/doc/html/latest/arm64/booting.html)

The doc says that a Linux Kernel Image (for Arm64) should begin with this __64-byte header__...

```text
u32 code0;                    /* Executable code */
u32 code1;                    /* Executable code */
u64 text_offset;              /* Image load offset, little endian */
u64 image_size;               /* Effective Image size, little endian */
u64 flags;                    /* kernel flags, little endian */
u64 res2      = 0;            /* reserved */
u64 res3      = 0;            /* reserved */
u64 res4      = 0;            /* reserved */
u32 magic     = 0x644d5241;   /* Magic number, little endian, "ARM\x64" */
u32 res5;                     /* reserved (used for PE COFF offset) */
```

[(Source)](https://www.kernel.org/doc/html/latest/arm64/booting.html)

Let's make a Linux Kernel Header to appease U-Boot...

# NuttX Header

_How do we make a Linux Kernel Header in our non-Linux OS?_

Apache NuttX RTOS can help!

This is how we created the __Arm64 Linux Kernel Header__ in NuttX: [nuttx/arch/arm64/src/common/arm64_head.S](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_head.S#L79-L117)

```text
  /* Kernel startup entry point.
   * ---------------------------
   *
   * This must be the very first address in the loaded image.
   * It should be loaded at any 4K-aligned address.
   * __start will be set to 0x4008 0000 in the Linker Script
   */
  .globl __start;
__start:

  /* DO NOT MODIFY. Image header expected by Linux boot-loaders.
   *
   * This add instruction has no meaningful effect except that
   * its opcode forms the magic "MZ" signature of a PE/COFF file
   * that is required for UEFI applications.
   */
  add     x13, x18, #0x16      /* the magic "MZ" signature */
  b       real_start           /* branch to kernel start */
```

(NuttX OS code begins at __`real_start`__ after the header)

[("MZ" refers to Mark Zbikowski)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

Then comes the rest of the header...

```text
  .quad   0x0000               /* PinePhone Image load offset from start of RAM */
  .quad   _e_initstack - __start         /* Effective size of kernel image, little-endian */
  .quad   __HEAD_FLAGS         /* Informative flags, little-endian */
  .quad   0                    /* reserved */
  .quad   0                    /* reserved */
  .quad   0                    /* reserved */
  .ascii  "ARM\x64"            /* Magic number, "ARM\x64" */
  .long   0                    /* reserved */

/* NuttX OS Code begins here, after the header */
real_start: ... 
```

_What's the value of `__start`?_

Remember __`kernel_addr_r`__, the Kernel Start Address from U-Boot?

In NuttX, we define the Kernel Start Address __`__start`__ as __`0x4008` `0000`__ in our Linker Script: [nuttx/boards/arm64/qemu/qemu-a53/scripts/dramboot](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/boards/arm64/qemu/qemu-a53/scripts/dramboot.ld#L30-L34)

```text
SECTIONS
{
  /* PinePhone uboot load address (kernel_addr_r) */
  . = 0x40080000;
  _start = .;
```

We're almost ready to boot NuttX on PinePhone!

_Will we see anything when NuttX boots on PinePhone?_

Not yet. We need to implement the UART Driver for NuttX...

# UART Output

TODO

![TODO](https://lupyuen.github.io/images/uboot-uart1.png)

TODO

![TODO](https://lupyuen.github.io/images/uboot-uart2.png)

# NuttX Log

TODO

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title2.png)

# NuttX Source Code

TODO

# What's Next

__NuttX on PinePhone__ might take a while to become a __Daily Driver__...

But today NuttX is ready to turn PinePhone into a valuable __Learning Resource__!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/uboot.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/uboot.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1561843749168173056)
