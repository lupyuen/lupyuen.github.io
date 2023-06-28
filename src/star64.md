# Inspecting the RISC-V Linux Images for Star64 SBC

📝 _7 Jul 2023_

![Pine64 Star64 64-bit RISC-V SBC](https://lupyuen.github.io/images/star64-title.jpg)

TODO

[__Apache NuttX__](https://nuttx.apache.org/docs/latest/index.html) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

# Linux Images for Star64

TODO

Let's examine the Linux Images for Star64 SBC, to see how U-Boot Bootloader is configured. (We'll boot NuttX later with U-Boot)

According to [Software Releases for Star64](https://wiki.pine64.org/wiki/STAR64#Software_releases), we have...

-   [Yocto Images](https://github.com/Fishwaldo/meta-pine64) at [pine64.my-ho.st](https://pine64.my-ho.st:8443/)

    Let's inspect [star64-image-minimal](https://pine64.my-ho.st:8443/star64-image-minimal-star64-1.2.wic.bz2)

-   [Armbian Images](https://www.armbian.com/star64/)

    Let's inspect [Armbian 23.8 Lunar (Minimal)](https://github.com/armbianro/os/releases/download/23.8.0-trunk.56/Armbian_23.8.0-trunk.56_Star64_lunar_edge_5.15.0_minimal.img.xz)

Current state of RISC-V Linux: [Linux on RISC-V (2022)](https://docs.google.com/presentation/d/1A0A6DnGyXR_MPpeg7QunQbv_yePPqid_uRswQe8Sj8M/edit#slide=id.p)

# Armbian Image for Star64

TODO

Let's inspect the Armbian Image for Star64: [Armbian 23.8 Lunar (Minimal)](https://github.com/armbianro/os/releases/download/23.8.0-trunk.56/Armbian_23.8.0-trunk.56_Star64_lunar_edge_5.15.0_minimal.img.xz)

Uncompress the .xz, mount the .img file on Linux / macOS / Windows as an ISO Volume.

The image contains 1 used partition: `armbi_root` (612 MB) that contains the Linux Root Filesystem.

Plus one unused partition (4 MB) at the top. (Why?)

![Armbian Image for Star64](https://lupyuen.github.io/images/star64-armbian.png)

We see the U-Boot Bootloader Configuration at `armbi_root/boot/uEnv.txt`...

```text
fdt_high=0xffffffffffffffff
initrd_high=0xffffffffffffffff

kernel_addr_r=0x44000000
kernel_comp_addr_r=0x90000000
kernel_comp_size=0x10000000

fdt_addr_r=0x48000000
ramdisk_addr_r=0x48100000

# Move distro to first boot to speed up booting
boot_targets=distro mmc1 dhcp 

distro_bootpart=1

# Fix missing bootcmd
bootcmd=run bootcmd_distro
```

[`kernel_addr_r`](https://u-boot.readthedocs.io/en/latest/develop/bootstd.html#environment-variables) says that Linux Kernel will be loaded at `0x4400` `0000`...

```text
kernel_addr_r=0x44000000
```

(Yocto Image boots Linux Kernel at a different address, see next section)

This probably means that U-Boot Bootloader is loaded at `0x4000` `0000`.

U-Boot Bootloader will also read the options from `armbi_root/boot/extlinux/extlinux.conf`...

```text
label Armbian
  kernel /boot/Image
  initrd /boot/uInitrd
  fdt /boot/dtb/starfive/jh7110-star64-pine64.dtb
  append root=UUID=99f62df4-be35-475c-99ef-2ba3f74fe6b5 console=ttyS0,115200n8 console=tty0 earlycon=sbi rootflags=data=writeback stmmaceth=chain_mode:1 rw rw no_console_suspend consoleblank=0 fsck.fix=yes fsck.repair=yes net.ifnames=0 splash plymouth.ignore-serial-consoles
```

This says that U-Boot will load the Linux Kernel from `armbi_root/boot/Image`

Which is sym-linked to `armbi_root/boot/vmlinuz-5.15.0-starfive2`

But the Flattened Device Tree (FDT) is missing! `/boot/dtb/starfive/jh7110-star64-pine64.dtb`

Which will fail the Armbian boot. (As we'll see later)

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

Here are the files in `armbi_root/boot`...

```text
→ ls -l /Volumes/armbi_root/boot
total 94416
lrwxrwxrwx  1 Luppy  staff        24 Jun 21 13:59 Image -> vmlinuz-5.15.0-starfive2
-rw-r--r--  1 Luppy  staff   4276712 Jun 21 12:16 System.map-5.15.0-starfive2
-rw-r--r--  1 Luppy  staff      1536 Jun 21 14:00 armbian_first_run.txt.template
-rw-r--r--  1 Luppy  staff     38518 Jun 21 14:00 boot.bmp
-rw-r--r--  1 Luppy  staff    144938 Jun 21 12:16 config-5.15.0-starfive2
lrwxrwxrwx  1 Luppy  staff        20 Jun 21 13:59 dtb -> dtb-5.15.0-starfive2
drwxr-xr-x  1 Luppy  staff         0 Jun 21 13:59 dtb-5.15.0-starfive2
drwxrwxr-x  1 Luppy  staff         0 Jun 21 13:58 extlinux
lrwxrwxrwx  1 Luppy  staff        27 Jun 21 13:59 initrd.img -> initrd.img-5.15.0-starfive2
-rw-r--r--  1 Luppy  staff  10911474 Jun 21 14:01 initrd.img-5.15.0-starfive2
lrwxrwxrwx  1 Luppy  staff        27 Jun 21 13:59 initrd.img.old -> initrd.img-5.15.0-starfive2
-rw-rw-r--  1 Luppy  staff       341 Jun 21 14:00 uEnv.txt
lrwxrwxrwx  1 Luppy  staff        24 Jun 21 14:01 uInitrd -> uInitrd-5.15.0-starfive2
-rw-r--r--  1 Luppy  staff  10911538 Jun 21 14:01 uInitrd-5.15.0-starfive2
lrwxrwxrwx  1 Luppy  staff        24 Jun 21 13:59 vmlinuz -> vmlinuz-5.15.0-starfive2
-rw-r--r--  1 Luppy  staff  22040576 Jun 21 12:16 vmlinuz-5.15.0-starfive2
lrwxrwxrwx  1 Luppy  staff        24 Jun 21 13:59 vmlinuz.old -> vmlinuz-5.15.0-starfive2
```

TODO: Explain `boot/uInitrd` RAM Disk

# Yocto Image for Star64

TODO

Let's inspect the Yocto Image for Star64: [star64-image-minimal](https://pine64.my-ho.st:8443/star64-image-minimal-star64-1.2.wic.bz2)

Uncompress the .bz2, rename as .img. Balena Etcher won't work with .bz2 files!

Write the .img to a microSD Card with Balena Etcher. Insert the microSD Card into a Linux Machine. (Like Pinebook Pro)

We see 4 used partitions...

-   spl (2 MB): [Secondary Program Loader](https://github.com/u-boot/u-boot)

-   uboot (4 MB): [U-Boot Bootloader](https://u-boot.readthedocs.io/en/latest/index.html)

-   boot (380 MB): U-Boot Configuration and Linux Kernel Image

-   root (686 MB): Linux Root Filesystem

Plus one unused partition (2 MB) at the top. (Why?)

![Yocto Image for Star64](https://lupyuen.github.io/images/star64-yocto.png)

`boot` partition has 2 files...

```text
$ ls -l /run/media/luppy/boot
total 14808
-rw-r--r-- 1 luppy luppy 15151064 Apr  6  2011 fitImage
-rw-r--r-- 1 luppy luppy     1562 Apr  6  2011 vf2_uEnv.txt
```

`boot/vf2_uEnv.txt` contains the U-Boot Bootloader Configuration...

```text
# This is the sample jh7110_uEnv.txt file for starfive visionfive U-boot
# The current convention (SUBJECT TO CHANGE) is that this file
# will be loaded from the third partition on the
# MMC card.
#devnum=1
partnum=3

# The FIT file to boot from
fitfile=fitImage

# for debugging boot
bootargs_ext=if test ${devnum} = 0; then setenv bootargs "earlyprintk console=tty1 console=ttyS0,115200 rootwait earlycon=sbi root=/dev/mmcblk0p4"; else setenv bootargs "earlyprintk console=tty1 console=ttyS0,115200 rootwait earlycon=sbi root=/dev/mmcblk1p4"; fi;
#bootargs=earlyprintk console=ttyS0,115200 debug rootwait earlycon=sbi root=/dev/mmcblk1p4

# for addr info
fileaddr=0xa0000000
fdtaddr=0x46000000
# boot Linux flat or compressed 'Image' stored at 'kernel_addr_r'
kernel_addr_r=0x40200000
irdaddr=46100000
irdsize=5f00000

# Use the FDT in the FIT image..
setupfdt1=fdt addr ${fdtaddr}; fdt resize;

setupird=setexpr irdend ${irdaddr} + ${irdsize}; fdt set /chosen linux,initrd-start <0x0 0x${irdaddr}>; fdt set /chosen linux,initrd-end <0x0 0x${irdend}>

setupfdt2=fdt set /chosen bootargs "${bootargs}";

bootwait=setenv _delay ${bootdelay}; echo ${_delay}; while test ${_delay} > 0; do sleep 1; setexpr _delay ${_delay} - 1; echo ${_delay}; done

boot2=run bootargs_ext; mmc dev ${devnum}; fatload mmc ${devnum}:${partnum} ${fileaddr} ${fitfile}; bootm start ${fileaddr}; run setupfdt1;run setupird;run setupfdt2; bootm loados ${fileaddr}; run chipa_set_linux; run cpu_vol_set; echo "Booting kernel in"; booti ${kernel_addr_r} ${irdaddr}:${filesize} ${fdtaddr}
```

[`kernel_addr_r`](https://u-boot.readthedocs.io/en/latest/develop/bootstd.html#environment-variables) says that Linux Kernel will be loaded at `0x4020` `0000`...

```text
# boot Linux flat or compressed 'Image' stored at 'kernel_addr_r'
kernel_addr_r=0x40200000
```

(Different from Armbian: `0x4400` `0000`)

Yocto boots from the [Flat Image Tree (FIT)](https://u-boot.readthedocs.io/en/latest/usage/fit/index.html#): `boot/fitImage`

Yocto's `root/boot` looks different from Armbian...

```text
$ ls -l /run/media/luppy/root/boot
total 24376
lrwxrwxrwx 1 root root       17 Mar  9  2018 fitImage -> fitImage-5.15.107
-rw-r--r-- 1 root root  9807808 Mar  9  2018 fitImage-5.15.107
-rw-r--r-- 1 root root 15151064 Mar  9  2018 fitImage-initramfs-5.15.107
```

# Boot NuttX with U-Boot Bootloader

TODO

_Will we boot NuttX with Armbian or Yocto settings? `0x4400` `0000` or `0x4020` `0000`?_

Armbian looks simpler, since it uses a plain Linux Kernel Image File `Image`. (Instead of Yocto's complicated Flat Image Tree)

Hence we'll overwrite Armbian's `armbi_root/boot/Image` by the NuttX Kernel Image.

We'll compile NuttX Kernel to boot at `0x4400` `0000`.

NuttX Kernel will begin with a RISC-V Linux Header. (See next section)

We'll use a Temporary File for the Flattened Device Tree (FDT) since it's missing from Armbian.

# Inside the Armbian Kernel Image

TODO

_What's inside the Armbian Linux Kernel Image?_

Let's look inside `armbi_root/boot/vmlinuz-5.15.0-starfive2`...

![Armbian Kernel Image](https://lupyuen.github.io/images/star64-kernel.png)

See the "RISCV" at `0x30`? That's the Magic Number for the RISC-V Linux Image Header!

-   ["Boot image header in RISC-V Linux"](https://www.kernel.org/doc/html/latest/riscv/boot-image-header.html)

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

Let's decompile the Kernel Image...

TODO: Explain MZ and the funny RISC-V instruction at the top

# Decompile Armbian Kernel Image with Ghidra

TODO

We decompile the Armbian Linux Kernel Image with [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

In Ghidra, create a New Project. Click File > Import File.

Select `armbi_root/boot/vmlinuz-5.15.0-starfive2` and enter these Import Options...

-   Format: Raw Binary

-   Language: RISCV > RV64GC (RISCV:LE:64:RV64GC:gcc)

    [(StarFive JH7110 has 4 × RV64GC U74 Application Cores)](https://doc-en.rvspace.org/JH7110/Datasheet/JH7110_DS/c_u74_quad_core.html)

-   Options > Base Address: 0x44000000

    (Based on the U-Boot Configuration from above)

![Load the Armbian Linux Kernel Image into Ghidra](https://lupyuen.github.io/images/star64-ghidra.png)

![Load the Armbian Linux Kernel Image into Ghidra](https://lupyuen.github.io/images/star64-ghidra2.png)

Double-click `vmlinuz-5.15.0-starfive2`, analyse the file with the Default Options.

Ghidra displays the Decompiled Linux Kernel...

![Disassembled Linux Kernel in Ghidra](https://lupyuen.github.io/images/star64-ghidra3.png)

At Address `0x4400` `0002` we see a Jump to `FUN_440010ac`.

Double-click `FUN_440010ac` to see the Linux Boot Code...

![Linux Boot Code in Ghidra](https://lupyuen.github.io/images/star64-ghidra4.png)

TODO: Explain MZ and the funny RISC-V instruction at the top

TODO: Where is the source file?

TODO: Any interesting CSR Instructions?

![Yocto Plasma on Star64](https://lupyuen.github.io/images/star64-plasma.jpg)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/star64.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/star64.md)
