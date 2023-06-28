# Inspecting the RISC-V Linux Images for Star64 SBC

📝 _7 Jul 2023_

![Pine64 Star64 64-bit RISC-V SBC](https://lupyuen.github.io/images/star64-title.jpg)

[__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) is a new 64-bit RISC-V SBC, based on the [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC.

[(Star64 version 1.1 was released May 2023)](https://wiki.pine64.org/wiki/STAR64#Board_Information,_Schematics_and_Certifications)

In this article we'll...

-   Look inside the brand new __Linux Images__ for Star64

-   __Decompile with Ghidra__ the RISC-V Linux Kernel

-   Figure out how __Apache NuttX RTOS__ might run on Star64

We won't actually run anything on Star64 yet. We'll save the fun parts for the next article!

_What's NuttX?_

[__Apache NuttX__](https://lupyuen.github.io/articles/riscv) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

The analysis that we do today will be super helpful for [__porting NuttX to Star64__](https://lupyuen.github.io/articles/riscv#jump-to-start).

Let's inspect the microSD Images...

!["All we need is a microSD"](https://lupyuen.github.io/images/star64-microsd.jpg)

_"All we need is a microSD"_

# Linux Images for Star64

According to [__Software Releases for Star64__](https://wiki.pine64.org/wiki/STAR64#Software_releases), we have these Linux Images...

-   [__Armbian Images__](https://www.armbian.com/star64/)

    Let's inspect [__Armbian 23.8 Lunar (Minimal)__](https://github.com/armbianro/os/releases/download/23.8.0-trunk.56/Armbian_23.8.0-trunk.56_Star64_lunar_edge_5.15.0_minimal.img.xz)

-   [__Yocto Images__](https://github.com/Fishwaldo/meta-pine64) at [__pine64.my-ho.st__](https://pine64.my-ho.st:8443/)

    We pick [__star64-image-minimal 1.2__](https://pine64.my-ho.st:8443/star64-image-minimal-star64-1.2.wic.bz2)

_What about other Linux Distros?_

Linux on RISC-V is in __Active Development__, many distros are not quite ready for the StarFive JH7110 SoC.

Check out the current state of RISC-V Linux...

-   [__Linux on RISC-V (2022)__](https://docs.google.com/presentation/d/1A0A6DnGyXR_MPpeg7QunQbv_yePPqid_uRswQe8Sj8M/edit#slide=id.p)

-   [__Linux 6.4 supports StarFive JH7110 SoC__](https://www.cnx-software.com/2023/06/26/linux-6-4-release-main-changes-arm-risc-v-and-mips-architectures/)

-   [__Star64 GPU not supported yet__](https://github.com/Fishwaldo/meta-pine64#quickstart)

![Armbian Image for Star64](https://lupyuen.github.io/images/star64-armbian.png)

# Armbian Image for Star64

We begin with the __Armbian Image for Star64__...

-   [__Armbian 23.8 Lunar for Star64 (Minimal)__](https://github.com/armbianro/os/releases/download/23.8.0-trunk.56/Armbian_23.8.0-trunk.56_Star64_lunar_edge_5.15.0_minimal.img.xz)

Uncompress the __.xz__ file, mount the __.img__ file on Linux / macOS / Windows as an ISO Volume.

The pic above shows that the Armbian Image contains 1 used partition: __armbi_root__ (612 MB), that contains the __Linux Root Filesystem__.

Plus one unused partition (4 MB) at the top. (Why?)

_What will happen when it boots?_

Let's check the configuration for [__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/index.html) at __/boot/uEnv.txt__...

```text
fdt_high=0xffffffffffffffff
initrd_high=0xffffffffffffffff

kernel_addr_r=0x44000000
kernel_comp_addr_r=0x90000000
kernel_comp_size=0x10000000

fdt_addr_r=0x48000000
ramdisk_addr_r=0x48100000

## Move distro to first boot to speed up booting
boot_targets=distro mmc1 dhcp 

distro_bootpart=1

## Fix missing bootcmd
bootcmd=run bootcmd_distro
```

[__kernel_addr_r__](https://u-boot.readthedocs.io/en/latest/develop/bootstd.html#environment-variables) says that Linux Kernel will be loaded at RAM Address __`0x4400` `0000`__...

```text
kernel_addr_r=0x44000000
```

(Yocto boots Linux at a different address, as we'll see)

This probably means that U-Boot Bootloader is loaded at __`0x4000` `0000`__.

[(Which is consistent with the __JH7110 Memory Map__)](https://doc-en.rvspace.org/JH7110/PDF/JH7110_TRM_StarFive_Preliminary_V2.pdf#memory_map)

U-Boot Bootloader will also read the options from __/boot/extlinux/extlinux.conf__...

```text
label Armbian
  kernel /boot/Image
  initrd /boot/uInitrd
  fdt /boot/dtb/starfive/jh7110-star64-pine64.dtb
  append root=UUID=99f62df4-be35-475c-99ef-2ba3f74fe6b5 console=ttyS0,115200n8 console=tty0 earlycon=sbi rootflags=data=writeback stmmaceth=chain_mode:1 rw rw no_console_suspend consoleblank=0 fsck.fix=yes fsck.repair=yes net.ifnames=0 splash plymouth.ignore-serial-consoles
```

This says that U-Boot will load the Linux Kernel Image from __/boot/Image__.

(Which is sym-linked to __/boot/vmlinuz-5.15.0-starfive2__)

_Everything looks hunky dory?_

Nope the __Flattened Device Tree (FDT)__ is missing!

```text
fdt /boot/dtb/starfive/jh7110-star64-pine64.dtb
```

Which means that Armbian will [__fail to boot__](https://github.com/lupyuen/nuttx-star64#boot-armbian-on-star64) on Star64!

```text
Retrieving file: /boot/uInitrd
10911538 bytes read in 466 ms (22.3 MiB/s)
Retrieving file: /boot/Image
22040576 bytes read in 936 ms (22.5 MiB/s)
Retrieving file: /boot/dtb/starfive/jh7110-star64-pine64.dtb
Failed to load '/boot/dtb/starfive/jh7110-star64-pine64.dtb'
```

[(Source)](https://github.com/lupyuen/nuttx-star64#boot-armbian-on-star64)

Here's the list of __Device Trees__...

```text
→ ls /Volumes/armbi_root/boot/dtb-5.15.0-starfive2/starfive
evb-overlay                      jh7110-evb-usbdevice.dtb
jh7110-evb-can-pdm-pwmdac.dtb    jh7110-evb.dtb
jh7110-evb-dvp-rgb2hdmi.dtb      jh7110-fpga.dtb
jh7110-evb-i2s-ac108.dtb         jh7110-visionfive-v2-A10.dtb
jh7110-evb-pcie-i2s-sd.dtb       jh7110-visionfive-v2-A11.dtb
jh7110-evb-spi-uart2.dtb         jh7110-visionfive-v2-ac108.dtb
jh7110-evb-uart1-rgb2hdmi.dtb    jh7110-visionfive-v2-wm8960.dtb
jh7110-evb-uart4-emmc-spdif.dtb  jh7110-visionfive-v2.dtb
jh7110-evb-uart5-pwm-i2c-tdm.dtb vf2-overlay
```

For reference, here are the other files in __/boot__...

```text
→ ls -l /Volumes/armbi_root/boot
total 94416
lrwxrwxrwx       24 Jun 21 13:59 Image -> vmlinuz-5.15.0-starfive2
-rw-r--r--  4276712 Jun 21 12:16 System.map-5.15.0-starfive2
-rw-r--r--     1536 Jun 21 14:00 armbian_first_run.txt.template
-rw-r--r--    38518 Jun 21 14:00 boot.bmp
-rw-r--r--   144938 Jun 21 12:16 config-5.15.0-starfive2
lrwxrwxrwx       20 Jun 21 13:59 dtb -> dtb-5.15.0-starfive2
drwxr-xr-x        0 Jun 21 13:59 dtb-5.15.0-starfive2
drwxrwxr-x        0 Jun 21 13:58 extlinux
lrwxrwxrwx       27 Jun 21 13:59 initrd.img -> initrd.img-5.15.0-starfive2
-rw-r--r-- 10911474 Jun 21 14:01 initrd.img-5.15.0-starfive2
lrwxrwxrwx       27 Jun 21 13:59 initrd.img.old -> initrd.img-5.15.0-starfive2
-rw-rw-r--      341 Jun 21 14:00 uEnv.txt
lrwxrwxrwx       24 Jun 21 14:01 uInitrd -> uInitrd-5.15.0-starfive2
-rw-r--r-- 10911538 Jun 21 14:01 uInitrd-5.15.0-starfive2
lrwxrwxrwx       24 Jun 21 13:59 vmlinuz -> vmlinuz-5.15.0-starfive2
-rw-r--r-- 22040576 Jun 21 12:16 vmlinuz-5.15.0-starfive2
lrwxrwxrwx       24 Jun 21 13:59 vmlinuz.old -> vmlinuz-5.15.0-starfive2
```

_What's initrd?_

```text
initrd /boot/uInitrd
```

__initrd__ is the [__Initial RAM Disk__](https://docs.kernel.org/admin-guide/initrd.html) that will be loaded into RAM while starting the Linux Kernel.

According to the [__U-Boot Bootloader Log__](https://github.com/lupyuen/nuttx-star64#boot-armbian-on-star64)...

1.  __Initial RAM Disk__ will be loaded first:

    __/boot/uInitrd__

1.  Followed by __Linux Kernel__:

    __/boot/Image__

1.  Then __Device Tree__

    (Which is missing)

Let's compare Armbian with Yocto...

![Yocto Image for Star64](https://lupyuen.github.io/images/star64-yocto.png)

# Yocto Image for Star64

The __Yocto Image for Star64__ looks more complicated than Armbian (but it works)...

-   [__star64-image-minimal 1.2__](https://pine64.my-ho.st:8443/star64-image-minimal-star64-1.2.wic.bz2)

Uncompress the __.bz2__ file, rename as __.img__.

(Balena Etcher won't work with __.bz2__ files!)

Write the __.img__ file to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

Insert the microSD Card into a Linux Machine. (Like Pinebook Pro)

From the pic above, we see 4 used partitions...

-   __spl__ (2 MB): For [__Secondary Program Loader__](https://github.com/u-boot/u-boot) (Why?)

-   __uboot__ (4 MB): For [__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/index.html) (Why?)

-   __boot__ (380 MB): U-Boot Configuration and Linux Kernel Image

-   __root__ (686 MB): Linux Root Filesystem

Plus one unused partition (2 MB) at the top. (Why?)

_What will happen when it boots?_

__boot__ partition has 2 files...

```text
$ ls -l /run/media/luppy/boot
total 14808
-rw-r--r-- 15151064 fitImage
-rw-r--r--     1562 vf2_uEnv.txt
```

__/boot/vf2_uEnv.txt__ contains the configuration for [__U-Boot Bootloader__](https://u-boot.readthedocs.io/en/latest/index.html)...

```text
## This is the sample jh7110_uEnv.txt file for starfive visionfive U-boot
## The current convention (SUBJECT TO CHANGE) is that this file
## will be loaded from the third partition on the
## MMC card.
partnum=3

## The FIT file to boot from
fitfile=fitImage

## for addr info
fileaddr=0xa0000000
fdtaddr=0x46000000
## boot Linux flat or compressed 'Image' stored at 'kernel_addr_r'
kernel_addr_r=0x40200000
irdaddr=46100000
irdsize=5f00000
...
```

[(See the Complete File)](https://github.com/lupyuen/nuttx-star64#yocto-image-for-star64)

[__kernel_addr_r__](https://u-boot.readthedocs.io/en/latest/develop/bootstd.html#environment-variables) says that Linux Kernel will be loaded at RAM Address __`0x4020` `0000`__...

```text
## boot Linux flat or compressed 'Image' stored at 'kernel_addr_r'
kernel_addr_r=0x40200000
```

(Different from Armbian's __`0x4400` `0000`__)

Also different from Armbian: Yocto boots from the [__Flat Image Tree (FIT)__](https://u-boot.readthedocs.io/en/latest/usage/fit/index.html#) at __/boot/fitImage__

```text
## The FIT file to boot from
fitfile=fitImage
```

Which packs everything into a Single FIT File: __Kernel Image, RAM Disk, Device Tree__...

```text
Loading kernel from FIT Image at a0000000 ...
Loading ramdisk from FIT Image at a0000000 ...
Loading fdt from FIT Image at a0000000 ...
```

[(Source)](https://gist.github.com/lupyuen/b23edf50cecbee13e5aab3c0bae6c528)

Yocto's __/root/boot__ looks different from Armbian...

```text
$ ls -l /run/media/luppy/root/boot
total 24376
lrwxrwxrwx       17 fitImage -> fitImage-5.15.107
-rw-r--r--  9807808 fitImage-5.15.107
-rw-r--r-- 15151064 fitImage-initramfs-5.15.107
```

Yocto looks more complicated than Armbian, but it boots OK on Star64!

![U-Boot Bootloader Log](https://lupyuen.github.io/images/star64-opensbi.jpg)

# Boot NuttX with U-Boot Bootloader

_When we port NuttX RTOS to Star64..._

_Will NuttX boot with Armbian or Yocto settings?_

Armbian looks simpler than Yocto, since it uses a plain Kernel Image File __/boot/Image__. 

(Instead of Yocto's complicated Flat Image Tree)

Hence for NuttX we'll adopt the Armbian Boot Settings, overwriting __/boot/Image__ by the __NuttX Kernel Image__. 

And hopefully U-Boot Bootloader will __boot NuttX on Star64__! Assuming that we fix these...

-   Compile NuttX Kernel to boot at __`0x4400` `0000`__

-   Use a placeholder for __Device Tree__ (since it's missing)

-   Use the special File Format for __Linux Kernel Image__ ("MZ")

Let's figure out the File Format for __/boot/Image__...

![Armbian Kernel Image](https://lupyuen.github.io/images/star64-kernel.png)

# Inside the Kernel Image

_What's inside the Linux Kernel Image?_

Let's look inside the __Armbian Kernel Image__ at __/boot/Image__.

(Which is sym-linked to __/boot/vmlinuz-5.15.0-starfive2__)

Open the file with a [__Hex Editor__](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor). (Pic above)

See the "RISCV" at __`0x30`__? That's the __Magic Number__ for the __RISC-V Linux Image Header__!

-   [__"Boot Image Header in RISC-V Linux"__](https://www.kernel.org/doc/html/latest/riscv/boot-image-header.html)

```text
u32 code0;                /* Executable code */
u32 code1;                /* Executable code */
u64 text_offset;          /* Image load offset, little endian */
u64 image_size;           /* Effective Image size, little endian */
u64 flags;                /* kernel flags, little endian */
u32 version;              /* Version of this header */
u32 res1 = 0;             /* Reserved */
u64 res2 = 0;             /* Reserved */
u64 magic = 0x5643534952; /* Magic number, little endian, "RISCV" */
u32 magic2 = 0x05435352;  /* Magic number 2, little endian, "RSC\x05" */
u32 res3;                 /* Reserved for PE COFF offset */
```

Our NuttX Kernel shall __recreate this RISC-V Linux Image Header__.

(Or U-Boot Bootloader might refuse to boot NuttX)

_Why does the pic show "MZ" at 0x0? Who is "MZ"?_

We'll find out in a while.

First we decompile the Kernel Image...

# Decompile Kernel with Ghidra

_Can we actually see the RISC-V Code inside the Linux Kernel?_

Yep! Let's decompile the Armbian Kernel with [__Ghidra__](https://github.com/NationalSecurityAgency/ghidra), the popular tool for Reverse Engineering...

1.  In Ghidra, create a __New Project__

1.  Click __File__ > __Import File__

1.  Select __boot/vmlinuz-5.15.0-starfive2__ and enter these Import Options...

    __Format:__ Raw Binary

    __Language:__ RISCV > RV64GC (RISCV:LE:64:RV64GC:gcc)

    [(StarFive JH7110 has 4 × RV64GC U74 Application Cores)](https://doc-en.rvspace.org/JH7110/Datasheet/JH7110_DS/c_u74_quad_core.html)

    __Options > Base Address:__ `0x44000000`

    (Based on the U-Boot Configuration from above)

    (Ghidra thinks it's PE Format because of "MZ"... But it's not!)

    ![Load the Armbian Linux Kernel Image into Ghidra](https://lupyuen.github.io/images/star64-ghidra.png)

    ![Load the Armbian Linux Kernel Image into Ghidra](https://lupyuen.github.io/images/star64-ghidra2.png)

1.  In the Ghidra Project, double-click __vmlinuz-5.15.0-starfive2__

    Analyse the file with the Default Options.

We'll see the __Decompiled Linux Kernel__ in Ghidra...

![Disassembled Linux Kernel in Ghidra](https://lupyuen.github.io/images/star64-ghidra3.png)

At Address __`0x4400` `0002`__ we see a Jump to __FUN_440010c8__.

Double-click __FUN_440010c8__ to see the Linux Boot Code...

![Linux Boot Code in Ghidra](https://lupyuen.github.io/images/star64-ghidra4.png)

The [__CSR Instructions__](https://lupyuen.github.io/articles/riscv#get-cpu-id) look interesting, but we'll skip them today.

(TODO: Where's the source file?)

_The first RISC-V Instruction looks kinda sus..._

```text
// Load -13 into Register S4
li  s4,-0xd

// Jump to Actual Boot Code
j   FUN_440010c8
```

It's highly sus because the First Instruction doesn't do anything meaningful!

Remember the __"MZ"__ at the top of our Kernel Image?

![Armbian Kernel Image](https://lupyuen.github.io/images/star64-kernel.png)

For [__Legacy Reasons__](https://en.wikipedia.org/wiki/DOS_MZ_executable), the Linux Kernel embeds "MZ" to signify that it's a PE / COFF File, to look like a [__UEFI Application__](https://lupyuen.github.io/articles/uboot#nuttx-header).

The RISC-V Instruction __`li`__ assembles into Machine Code as __"MZ"__. That's why it's the first instruction in the Linux Kernel!

We'll recreate "MZ" in our NuttX Kernel too.

[("MZ" refers to __Mark Zbikowski__)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

![Yocto Plasma on Star64](https://lupyuen.github.io/images/star64-plasma.jpg)

[_Yocto Plasma on Star64_](https://github.com/lupyuen/nuttx-star64#boot-yocto-plasma-on-star64)

# What's Next

Today we've completed our Linux Homework... Without a Star64 SBC!

-   We inspected the brand new __Linux Images__ for Star64

-   We __decompiled with Ghidra__ the RISC-V Linux Kernel

-   And we have some idea how __Apache NuttX RTOS__ might run on Star64

Please join me in the next article as we actually boot Linux on Star64! (Pic above)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/star64.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/star64.md)
