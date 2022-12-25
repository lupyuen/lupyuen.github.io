# PinePhone boots Apache NuttX RTOS

📝 _28 Aug 2022_

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title.png)

[_Apache NuttX RTOS booting on Pine64 PinePhone_](https://github.com/lupyuen/pinephone-nuttx#nuttx-boot-log)

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/uboot#appendix-pinephone-is-now-supported-by-apache-nuttx-rtos)

Suppose we're creating our own __Operating System__ (non-Linux) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   What's the File Format?

-   Where in RAM should it run?

-   Can we make a microSD that will boot our OS?

-   What happens when PinePhone powers on?

This article explains how we ported [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/arm) to PinePhone. And we'll answer the questions along the way!

Let's walk through the steps to create our own __PinePhone Operating System__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Allwinner A64 SoC User Manual](https://lupyuen.github.io/images/uboot-a64.jpg)

[_Allwinner A64 SoC User Manual_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# Allwinner A64 SoC

_What's inside PinePhone?_

At the heart of PinePhone is the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) (System-on-a-Chip) with 4 Cores of 64-bit __Arm Cortex-A53__...

-   [__PinePhone Wiki__](https://wiki.pine64.org/index.php/PinePhone)

-   [__Allwinner A64 Info__](https://linux-sunxi.org/A64)

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

The A64 SoC in PinePhone comes with __2GB RAM__ (or 3GB RAM via a mainboard upgrade)...

-   [__Allwinner A64 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

A64's __Memory Map__ says that the RAM starts at address __`0x4000` `0000`__.

_So our OS will run at `0x4000` `0000`?_

Not quite! Our OS will actually be loaded at __`0x4008` `0000`__

We'll see why in a while, but first we talk about a Very Important Cable...

![PinePhone connected to USB Serial Debug Cable](https://lupyuen.github.io/images/arm-uart2.jpg)

[_PinePhone connected to USB Serial Debug Cable_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

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

[_PinePhone Jumpdrive on microSD_](https://github.com/dreemurrs-embedded/Jumpdrive)

# U-Boot Bootloader

_What happens when we power up PinePhone?_

The [__U-Boot Bootloader__](https://en.wikipedia.org/wiki/Das_U-Boot) runs, searching for a Linux Kernel to boot (on microSD or eMMC)...

-   [__Allwinner A64 Boot ROM__](https://linux-sunxi.org/BROM#A64)

-   [__Allwinner A64 U-Boot__](https://linux-sunxi.org/U-Boot)

-   [__Allwinner A64 U-Boot SPL__](https://linux-sunxi.org/BROM#U-Boot_SPL_limitations)

    (Secondary Program Loader)

-   [__SD Card Layout__](https://linux-sunxi.org/Bootable_SD_card#SD_Card_Layout)

_Whoa! These docs look so superdry..._

There's an easier way to grok U-Boot. Let's watch PinePhone boot Jumpdrive!

![U-Boot Bootloader on PinePhone](https://lupyuen.github.io/images/uboot-uboot.png)

[_U-Boot Bootloader on PinePhone_](https://lupyuen.github.io/articles/arm#appendix-pinephone-uart-log)

# Boot Log

Now we're ready to watch what happens when PinePhone boots...

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

(We'll talk more about the script)

The U-Boot Script __loads the Linux Kernel__ into RAM and starts it...

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

(We'll explain _fdt_addr_r_, _kernel_addr_r_ and _ramdisk_addr_r_)

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

_Aha that's why our kernel must start at `0x4008` `0000`!_

Yep! Thus we can...

-   Compile our own operating system to start at __`0x4008` `0000`__

-   Replace __`Image.gz`__ in the microSD by our compiled OS (gzipped)

And PinePhone will __boot our own OS!__ (Theoretically)

But there's a catch: U-Boot expects to find a Linux Kernel Header in our OS...

# Linux Kernel Header

_What! A Linux Kernel Header in our non-Linux OS?_

Yep it's totally strange, but U-Boot Bootloader expects our OS to begin with an __Arm64 Linux Kernel Header__ as defined here...

-   [__"Booting AArch64 Linux"__](https://www.kernel.org/doc/html/latest/arm64/booting.html)

The doc says that a Linux Kernel Image (for Arm64) should begin with this __64-byte header__...

```text
u32 code0;              /* Executable code */
u32 code1;              /* Executable code */
u64 text_offset;        /* Image load offset, little endian */
u64 image_size;         /* Effective Image size, little endian */
u64 flags;              /* kernel flags, little endian */
u64 res2  = 0;          /* reserved */
u64 res3  = 0;          /* reserved */
u64 res4  = 0;          /* reserved */
u32 magic = 0x644d5241; /* Magic number, little endian, "ARM\x64" */
u32 res5;               /* reserved (used for PE COFF offset) */
```

[(Source)](https://www.kernel.org/doc/html/latest/arm64/booting.html)

Let's make a Linux Kernel Header to appease U-Boot...

# NuttX Header

_How do we make a Linux Kernel Header in our non-Linux OS?_

Apache NuttX RTOS can help!

This is how we created the __Arm64 Linux Kernel Header__ in NuttX: [arch/arm64/src/common/arm64_head.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L79-L117)

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
  add     x13, x18, #0x16  /* the magic "MZ" signature */
  b       real_start       /* branch to kernel start */
```

[("MZ" refers to Mark Zbikowski)](https://en.wikipedia.org/wiki/DOS_MZ_executable)

The header begins at __Kernel Start Address `0x4008` `0000`__.

At the top of the header we jump to __`real_start`__ to skip the header.

(NuttX code begins at __`real_start`__ after the header)

Then comes the rest of the header...

```text
  /* PinePhone Image load offset from start of RAM */
  .quad   0x0000  

  /* Effective size of kernel image, little-endian */
  .quad   _e_initstack - __start

  /* Informative flags, little-endian */
  .quad   __HEAD_FLAGS

  .quad   0          /* reserved */
  .quad   0          /* reserved */
  .quad   0          /* reserved */
  .ascii  "ARM\x64"  /* Magic number, "ARM\x64" */
  .long   0          /* reserved */

/* NuttX OS Code begins here, after the header */
real_start: ... 
```

[(__`_e_initstack`__ is End of Stack Space)](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/scripts/dramboot.ld#L97-L106)

[(__`__HEAD_FLAGS`__ is defined here)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L41-L49)

[(__UPDATE:__ We don't need to change the Image Load Offset)](https://lupyuen.github.io/articles/uboot#porting-notes)

_What's the value of `__start`?_

Remember __`kernel_addr_r`__, the [__Kernel Start Address__](https://lupyuen.github.io/articles/uboot#boot-address) from U-Boot?

In NuttX, we define the Kernel Start Address __`__start`__ as __`0x4008` `0000`__ in our Linker Script: [boards/arm64/qemu/qemu-a53/scripts/dramboot](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/scripts/dramboot.ld#L30-L34)

```text
SECTIONS
{
  /* PinePhone uboot load address (kernel_addr_r) */
  . = 0x40080000;
  _start = .;
```

We also updated the Kernel Start Address in the NuttX __Memory Map__...

-   [__"Memory Map"__](https://github.com/lupyuen/pinephone-nuttx#memory-map)

We're almost ready to boot NuttX on PinePhone!

_Will we see anything when NuttX boots on PinePhone?_

Not yet. We need to implement the UART Driver...

![Allwinner A64 UART Controller Registers](https://lupyuen.github.io/images/uboot-uart1.png)

[_Allwinner A64 UART Controller Registers_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# UART Output

Our operating system will show some output on PinePhone's __Serial Debug Console__ as it boots.

To do that, we'll talk to the __UART Controller__ on the Allwinner A64 SoC...

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

Flip the [__A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) to page 562 ("UART") and we'll see the __UART Registers__. (Pic above)

PinePhone's Serial Console is connected to __UART0__ at Base Address __`0x01C2` `8000`__

The First Register of UART0 is what we need: __UART_THR__ at __`0x01C2` `8000`__...

![A64 UART Register UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

_What's UART_THR?_

__UART_THR__ is the __Transmit Holding Register__.

We'll write our output data to __`0x01C2` `8000`__, byte by byte, and the data will appear in the Serial Console. Let's do that!

_Did we forget something?_

Rightfully we should wait for __THR Empty__ (Transmit Buffer Empty) before sending our data.

And we should initialise the __UART Baud Rate__. We'll come back to this.

# NuttX UART Macros

NuttX writes to the UART Port with some clever __Arm Assembly Macros__.

This Assembly Code in NuttX...

```text
cpu_boot:
  PRINT(cpu_boot, "- Ready to Boot CPU\r\n")
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L176-L179)

Calls our [__`PRINT` Macro__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L58-L69) to print a string at startup.

Which is super convenient because our [__Startup Code__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S) has plenty of Assembly Code!

_What's inside the macro?_

Our [__`PRINT` Macro__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L58-L69) calls...

-   [__`boot_stage_puts`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L292-L308) Function, which calls...

-   [__`up_lowputc`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L81-L91) Function

Which loads our __UART Base Address__...

```text
/* PinePhone Allwinner A64 UART0 Base Address: */
#define UART0_BASE_ADDRESS 0x1C28000

/* Print a character on the UART - this function is called by C
 * x0: character to print
 */
GTEXT(up_lowputc)
SECTION_FUNC(text, up_lowputc)
  ldr   x15, =UART0_BASE_ADDRESS  /* Load UART Base Address */
  early_uart_ready    x15, w2     /* Wait for UART ready    */
  early_uart_transmit x15, w0     /* Transmit to UART       */
  ret
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L81-L91) 

And calls [__`early_uart_transmit`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L87-L94) Macro to transmit a character...

```text
/* UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
  /* Write to UART_THR (Transmit Holding Register) */
  strb  \wt, [\xb]
.endm
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L81-L91)

That's how we print a string to the console at startup!

_What's `early_uart_ready`?_

__`early_uart_ready`__ Macro waits for the UART Port to be __ready to transmit__, as explained here...

-   [__"Wait for UART Ready"__](https://lupyuen.github.io/articles/uboot#wait-for-uart-ready)

_How do we initialise the UART Port?_

Right now we don't __initialise the UART Port__ because U-Boot has kindly done it for us. Eventually this needs to be fixed: [qemu_lowputc.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L51-L72)

```text
/* UART initialization
 * xb: register which contains the UART base address
 * c: scratch register number
 */
GTEXT(up_earlyserialinit)
SECTION_FUNC(text, up_earlyserialinit)
  ## TODO: Set PinePhone Allwinner A64 Baud Rate Divisor:
  ## Write to UART_LCR (DLAB), UART_DLL and UART_DLH
  ...
```

[(__`up_earlyserialinit`__ is called by our Startup Code)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L168-L176)

More about this in the Appendix...

-   [__"Initialise UART"__](https://lupyuen.github.io/articles/uboot#initialise-uart)

We're finally ready to boot our own PinePhone Operating System!

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title2.png)

[_Apache NuttX RTOS booting on Pine64 PinePhone_](https://github.com/lupyuen/pinephone-nuttx#nuttx-boot-log)

# PinePhone Boots NuttX

_Can we boot our own OS on PinePhone... By replacing a single file on Jumpdrive microSD?_

Earlier we said that we'll overwrite __`Image.gz` on Jumpdrive microSD__ to boot our own OS...

-   [__"Boot Address"__](https://lupyuen.github.io/articles/uboot#boot-address)

Let's do it!

1.  Prepare a microSD Card with __PinePhone Jumpdrive__...

    [__"PinePhone Jumpdrive"__](https://lupyuen.github.io/articles/uboot#pinephone-jumpdrive)

1.  Follow these steps to __build Apache NuttX RTOS__...

    [__"Build NuttX for PinePhone"__](https://lupyuen.github.io/articles/uboot#appendix-build-nuttx-for-pinephone)

    Or __download `nuttx.bin`__ from here (includes BASIC Interpreter)...

    [__NuttX Binary Image for PinePhone: `nuttx.bin`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/nuttx.bin)

1.  Compress the __NuttX Binary Image__...

    ```bash
    ## Compress the NuttX Binary Image
    cp nuttx.bin Image
    rm -f Image.gz
    gzip Image
    ```

    Or __download `Image.gz`__ from here (includes BASIC Interpreter)...

    [__Compressed NuttX Binary Image: `Image.gz`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/Image.gz)

1.  Overwrite __`Image.gz`__ on __Jumpdrive microSD__...

    ```bash
    ## Copy compressed NuttX Binary Image to Jumpdrive microSD
    ## TODO: Change the microSD Path
    cp Image.gz "/Volumes/NO NAME"
    ```

1.  Connect PinePhone to our computer with a __USB Serial Debug Cable__...

    [__"Boot Log"__](https://lupyuen.github.io/articles/uboot#boot-log)

1.  Insert __Jumpdrive microSD__ into PinePhone and power up

On our computer's [__Serial Terminal__](https://lupyuen.github.io/articles/uboot#boot-log), we see PinePhone's __U-Boot Bootloader__ loading NuttX RTOS into RAM...

```text
U-Boot 2020.07 (Nov 08 2020 - 00:15:12 +0100)
Found U-Boot script /boot.scr
653 bytes read in 3 ms (211.9 KiB/s)
## Executing script at 4fc00000
gpio: pin 114 (gpio 114) value is 1
99784 bytes read in 8 ms (11.9 MiB/s)
Uncompressed size: 278528 = 0x44000
36162 bytes read in 4 ms (8.6 MiB/s)
1078500 bytes read in 51 ms (20.2 MiB/s)
## Flattened Device Tree blob at 4fa00000
   Booting using the fdt blob at 0x4fa00000
   Loading Ramdisk to 49ef8000, end 49fff4e4 ... OK
   Loading Device Tree to 0000000049eec000, end 0000000049ef7d41 ... OK
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx#nuttx-boot-log)

Then NuttX runs...

```text
Starting kernel ...

HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x400c4000, heap_size=0x7f3c000

arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2

up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
up_timer_initialize: _vector_table=0x400a7000
up_timer_initialize: Before writing: vbar_el1=0x40227000
up_timer_initialize: After writing: vbar_el1=0x400a7000

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0

work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x400a7000 _einit: 0x400a7000 _stext: 0x40080000 _etext: 0x400a8000
nsh: sysinit: fopen failed: 2

nshn:x _msktfaarttf:s :C PcUo0m:m aBnedg innonti nfgo uInddle  L oNouptt
 Shell (NSH) NuttX-10.3.0-RC2
```
(Yeah the output is slightly garbled, the UART Driver needs fixing)

__NuttX Shell__ works perfectly OK on PinePhone...

```text
nsh> uname -a
NuttX 10.3.0-RC2 fc909c6-dirty Sep  1 2022 17:05:44 arm64 qemu-armv8a

nsh> help
help usage:  help [-v] [<cmd>]

  .         cd        dmesg     help      mount     rmdir     true      xd        
  [         cp        echo      hexdump   mv        set       truncate  
  ?         cmp       exec      kill      printf    sleep     uname     
  basename  dirname   exit      ls        ps        source    umount    
  break     dd        false     mkdir     pwd       test      unset     
  cat       df        free      mkrd      rm        time      usleep    

Builtin Apps:
  getprime  hello     nsh       ostest    sh        

nsh> hello
task_spawn: name=hello entry=0x4009b1a0 file_actions=0x400c9580 attr=0x400c9588 argv=0x400c96d0
spawn_execattrs: Setting policy=2 priority=100 for pid=3
Hello, World!!

nsh> ls /dev
/dev:
 console
 null
 ram0
 ram2
 ttyS0
 zero
```

[__Watch the Demo on YouTube__](https://youtube.com/shorts/WmRzfCiWV6o?feature=share)

[__Another Demo Video__](https://youtu.be/MJDxCcKAv0g)

Yep NuttX boots on PinePhone... After replacing a single __`Image.gz`__ file!

# Upcoming Fixes

Right now we're running NuttX on a __Single Arm64 CPU__. In future we might run on all __4 Arm64 CPUs__ of PinePhone...

-   [__"Multi Core SMP"__](https://github.com/lupyuen/pinephone-nuttx#multi-core-smp)

We fixed some issues with __Arm64 Interrupts__ on PinePhone...

-   [__"NuttX RTOS on PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

And we fixed UART Input in our [__UART Driver__](https://lupyuen.github.io/articles/uboot#uart-driver)...

-   [__"NuttX RTOS on PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

Now we're ready to __build the Missing Drivers__ for PinePhone! Like MIPI DSI Display, I2C Touch Panel, LTE Modem, ...

-   [__"PinePhone Device Tree"__](https://github.com/lupyuen/pinephone-nuttx#pinephone-device-tree)

Below are tips for debugging the __NuttX Boot Sequence__ on PinePhone...

1.  [__"Boot Sequence"__](https://github.com/lupyuen/pinephone-nuttx#boot-sequence)

1.  [__"Boot Debugging"__](https://github.com/lupyuen/pinephone-nuttx#boot-debugging)

1.  [__"Memory Map"__](https://github.com/lupyuen/pinephone-nuttx#memory-map)

1.  [__"Handling Interrupts"__](https://github.com/lupyuen/pinephone-nuttx#handling-interrupts)

1.  [__"Dump Interrupt Vector Table"__](https://github.com/lupyuen/pinephone-nuttx#dump-interrupt-vector-table)

1.  [__"Interrupt Debugging"__](https://github.com/lupyuen/pinephone-nuttx#interrupt-debugging)

![Arm64 Source Files in NuttX](https://lupyuen.github.io/images/arm-source.png)

[_Arm64 Source Files in NuttX_](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common)

# NuttX Source Code

Apache NuttX RTOS has plenty of __Arm64 Code__ that will be helpful to creators of PinePhone Operating Systems.

The __Arm64 Architecture Functions__ (pic above) are defined here...

-   [arch/arm64/src/common](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common)

These functions implement all kinds of Arm64 Features: [__FPU__](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common/arm64_fpu.c), [__Interrupts__](https://github.com/lupyuen/pinephone-nuttx#interrupt-controller), [__MMU__](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common/arm64_mmu.c), [__Tasks__](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common/arm64_task_sched.c), [__Timers__](https://github.com/apache/nuttx/tree/master/arch/arm64/src/common/arm64_arch_timer.c), ...

The __Arm64 Startup Code__ (including Linux Kernel Header) is at...

-   [arch/arm64/src/common/arm64_head.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S)

Previously NuttX supports only one __Arm64 Target Board__: QEMU Emulator.

Below are the Source Files and Build Configuration for __QEMU Emulator__...

-   [boards/arm64/qemu/qemu-armv8a](https://github.com/apache/nuttx/tree/master/boards/arm64/qemu/qemu-armv8a)

We clone this to create a Target Board for PinePhone...

-   [boards/arm64/a64/pinephone](https://github.com/apache/nuttx/tree/master/boards/arm64/a64/pinephone)

And we start the __Board-Specific Drivers__ for PinePhone in [pinephone_bringup.c](https://github.com/apache/nuttx/tree/master/boards/arm64/a64/pinephone/src/pinephone_bringup.c)

Our Board calls the __Architecture-Specific Drivers__ at...

-   [arch/arm64/src/a64](https://github.com/apache/nuttx/tree/master/arch/arm64/src/a64)

The __UART Driver__ is located at [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c) and [a64_lowputc.S](https://github.com/apache/nuttx/tree/master/arch/arm64/src/a64/a64_lowputc.S)

[(More about UART Driver)](https://lupyuen.github.io/articles/uboot#uart-driver)

The __QEMU Target for NuttX__ is described in this article...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

# What's Next

It's indeed possible to __boot our own OS__ on PinePhone... By __replacing a single file__ on Jumpdrive microSD!

We've done that with __Apache NuttX RTOS__, which has plenty of code that will be helpful for PinePhone OS Developers.

_Will NuttX work with all PinePhone features?_

__NuttX on PinePhone__ might take a while to become a __Daily Driver__...

-   [__"PinePhone on RTOS"__](https://lupyuen.github.io/articles/arm#pinephone-on-rtos)

-   [__"PinePhone Drivers and Apps"__](https://lupyuen.github.io/articles/arm#pinephone-drivers-and-apps)

But today NuttX is ready to turn PinePhone into a valuable __Learning Resource__!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/wz0hit/pinephone_boots_apache_nuttx_rtos/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/uboot.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/uboot.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1564380402110070785)

1.  Check out this detailed doc on porting __Genode OS__ to PinePhone...

    [__"Genode Operating System Framework 22.05"__](https://genode.org/documentation/genode-platforms-22-05.pdf)

    PinePhone's __Touch Display__ is explained in pages 171 to 197.

    PinePhone's __LTE Modem__ is covered in pages 198 to 204.

# Appendix: PinePhone is now supported by Apache NuttX RTOS

PinePhone is now officially supported by [__Apache NuttX Mainline!__](https://github.com/apache/nuttx)

Follow these steps to build and boot the [__`master` branch of NuttX__](https://github.com/apache/nuttx)...

-   [__"Apache NuttX RTOS for PINE64 PinePhone"__](https://github.com/apache/nuttx/blob/master/Documentation/platforms/arm/a64/boards/pinephone/index.rst)

    [(Install the Prerequisites)](https://nuttx.apache.org/docs/latest/quickstart/install.html#prerequisites)

    [(Clone the git Repositories)](https://nuttx.apache.org/docs/latest/quickstart/install.html#download-nuttx)

Or download the __Build Outputs__ from...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/nuttx-11.0.0-pinephone)

We'll see this on the __Serial Console__...

-   [__"Log of Apache NuttX RTOS on PinePhone"__](https://gist.github.com/lupyuen/e49a22a9e39b7c024b984bea40377712)

We have updated these articles to point to the PinePhone code in NuttX Mainline...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

## Upcoming Features

__Upcoming Features__ for NuttX on PinePhone...

1.  __PIO, PWM and LED Drivers__ for Allwinner A64

    (Needed for PinePhone's Display Backlight)

    [__"Display Backlight"__](https://lupyuen.github.io/articles/de#appendix-display-backlight)

    PIO Driver will be based on Allwinner A10 [__a1x_pio.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/a1x/a1x_pio.c), [__a1x_pio.h__](https://github.com/apache/nuttx/blob/master/arch/arm/src/a1x/a1x_pio.h) and [__hardware/a1x_pio.h__](https://github.com/apache/nuttx/blob/master/arch/arm/src/a1x/hardware/a1x_pio.h)

1.  __MIPI Display Serial Interface Driver__ for Allwinner A64, based on...

    [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

    [__"Enable MIPI DSI Block"__](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

    [__"Start MIPI DSI HSC and HSD"__](https://lupyuen.github.io/articles/dsi#appendix-start-mipi-dsi-hsc-and-hsd)

1.  __Display Engine Driver__ for Allwinner A64, based on...

    [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

1.  __PMIC, TCON0, DPHY and LCD Panel Drivers__ for PinePhone and Allwinner A64, based on...

    [__"Power Management Integrated Circuit"__](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit)

    [__"Timing Controller (TCON0)"__](https://lupyuen.github.io/articles/de#appendix-timing-controller-tcon0)

    [__"Enable MIPI Display Physical Layer (DPHY)"__](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-display-physical-layer-dphy)

    [__"Reset LCD Panel"__](https://lupyuen.github.io/articles/de#appendix-reset-lcd-panel)

And we'll be able to render graphics on PinePhone's LCD Display. Stay Tuned!

## Upcoming Fixes

These are the __Upcoming Fixes__ for NuttX on PinePhone...

1.  Fix the garbled __Startup Messages__

    [(More about this)](https://github.com/apache/nuttx/pull/7692)

1.  __RAM Size__ will be increased to 2 GB: [chip.h](https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L45-L48)

    ```c
    // Allwinner A64 Memory Map
    // TODO: Increase RAM to 2 GB
    #define CONFIG_RAMBANK1_ADDR      0x40000000
    #define CONFIG_RAMBANK1_SIZE      MB(128)
    ```

1.  Only __Single Core CPU__ has been tested on PinePhone: [pinephone/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/configs/nsh/defconfig)

    We shall test __Quad Core CPU__ on PinePhone: [qemu-armv8a/nsh_smp/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/nsh_smp/defconfig#L0-L1)

    ```text
    ## TODO: Enable Symmetric Multiprocessing (SMP) for PinePhone
    CONFIG_ARCH_INTERRUPTSTACK=8192
    CONFIG_DEFAULT_TASK_STACKSIZE=16384
    CONFIG_IDLETHREAD_STACKSIZE=16384
    CONFIG_PTHREAD_STACK_MIN=16384
    CONFIG_SMP=y
    CONFIG_SYSTEM_TASKSET=y
    CONFIG_TESTING_OSTEST_STACKSIZE=16384
    CONFIG_TESTING_SMP=y
    ```

1.  Enable __Memory Protection__ so that NuttX Apps can't access NuttX Kernel Memory and Hardware Registers.

## Porting Notes

__Porting Notes__ for NuttX on PinePhone...

1.  [__Image Load Offset__](https://lupyuen.github.io/articles/uboot#nuttx-header) in the Linux Kernel Header isn't used: [arm64_head.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L79-L117)

    ```text
    .quad 0x480000 /* Image load offset from start of RAM */
    ```

    NuttX boots OK without changing the Image Load Offset.

    (Seems the Image Load Offset is not used by the U-Boot Bootloader. It's probably used by the Linux Kernel only)

1.  Previously the __Vector Base Address Register__ for EL1 was set incorrectly. [(See this)](https://lupyuen.github.io/articles/interrupt#arm64-vector-table-is-wrong)

    The new code doesn't have this problem.
    
    (Is it due to the Image Load Offset?)

![Build NuttX](https://lupyuen.github.io/images/arm-build.png)

# Appendix: Build NuttX for PinePhone

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/uboot#appendix-pinephone-is-now-supported-by-apache-nuttx-rtos)

Follow these steps to build __Apache NuttX RTOS__ for PinePhone...

## Download NuttX

Download the Source Code for NuttX...

```bash
## Create NuttX Directory
mkdir nuttx
cd nuttx

## Download NuttX OS
git clone \
  https://github.com/apache/nuttx \
  nuttx

## Download NuttX Apps
git clone \
  https://github.com/apache/nuttx-apps \
  apps

## We'll build NuttX inside nuttx/nuttx
cd nuttx
```

## Install Prerequisites

Install the __Build Prerequisites__ below, but skip the RISC-V Toolchain...

-   [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

## Download Toolchain

Download the Arm Toolchain for __AArch64 Bare-Metal Target `aarch64-none-elf`__...

-   [__Arm GNU Toolchain Downloads__](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

    (Skip the section for Beta Releases)

For Linux x64 and WSL:

-   [gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf.tar.xz](https://developer.arm.com/-/media/Files/downloads/gnu/11.2-2022.02/binrel/gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf.tar.xz)

For macOS:

-   [arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.pkg](https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.pkg)

(I don't recommend building NuttX on Plain Old Windows CMD, please use WSL instead)

Add the downloaded Arm Toolchain to the __`PATH`__...

```bash
## For Linux x64 and WSL:
export PATH="$PATH:$HOME/gcc-arm-11.2-2022.02-x86_64-aarch64-none-elf/bin"

## For macOS:
export PATH="$PATH:/Applications/ArmGNUToolchain/11.3.rel1/aarch64-none-elf/bin"
```

Check the Arm Toolchain...

```bash
$ aarch64-none-elf-gcc -v
gcc version 11.3.1 20220712 (Arm GNU Toolchain 11.3.Rel1)
```

## Build NuttX

Finally we __configure and build__ NuttX...

```bash
## Configure NuttX for Arm Cortex-A53 Single Core
## For PinePhone: Change "qemu-armv8a:nsh" to "pinephone:nsh"
./tools/configure.sh -l qemu-armv8a:nsh

## Build NuttX
make

## Dump the disassembly to nuttx.S
aarch64-none-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

[(See the Build Log)](https://gist.github.com/lupyuen/2c5db82c3103f52ed7ca99804f9220c1)

[(See our Build Script)](https://gist.github.com/lupyuen/7e828ea476d12cffa5e535a215723908)

On an old MacBook Pro 2012, NuttX builds in 2 minutes.

If we wish to use the __BASIC Interpreter__, follow these steps to enable it...

-   [__"Enable BASIC"__](https://lupyuen.github.io/articles/nuttx#enable-basic)

Then run __`make`__ to rebuild NuttX.

If the build fails with this error...

```text
token "@" is not valid in preprocessor
```

Look for this file in the Arm64 Toolchain...

```text
gcc-arm-none-eabi/arm-none-eabi/include/_newlib_version.h
```

And [__apply this patch__](https://github.com/apache/nuttx/pull/7284/commits/518b0eb31cb66f25b590ae9a79ab16c319b96b94#diff-12291efd8a0ded1bc38bad733d99e4840ae5112b465c04287f91ba5169612c73).

## Output Files

The NuttX Output Files may be found here...

-   [__Apache NuttX RTOS for PinePhone__](https://github.com/lupyuen/pinephone-nuttx/releases/tag/v1.0.12)

The [__NuttX Binary Image `nuttx.bin`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/nuttx.bin) will be gzipped and copied to Jumpdrive microSD as __`Image.gz`__...

-   [__"PinePhone Boots NuttX"__](https://lupyuen.github.io/articles/uboot#pinephone-boots-nuttx)

For Troubleshooting: Refer to these files...

-   [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/nuttx)

-   [__NuttX Arm Disassembly `nuttx.S`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/nuttx.S)

This article explains how we may load the [__NuttX ELF Image `nuttx`__](https://github.com/lupyuen/pinephone-nuttx/releases/download/v1.0.12/nuttx) into Ghidra for inspection...

-   [__"Analyse NuttX Image with Ghidra"__](https://lupyuen.github.io/articles/arm#appendix-analyse-nuttx-image-with-ghidra)

# Appendix: Allwinner A64 UART

Earlier we talked about our implementation of __Allwinner A64 UART__...

-   [__`early_uart_ready`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L72-L85) needs to wait for UART to be __ready to transmit__

-   [__`up_earlyserialinit`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L51-L60) needs to __initialise the UART Port__

-   [__UART Driver__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c) needs to support __UART Input__

Let's talk about these changes...

![Allwinner A64 UART Register UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

[_Allwinner A64 UART Register UART_THR_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

## Wait for UART Ready

_How do we wait for the UART Port to be ready before we transmit data?_

See the pic above. According to the __Allwinner A64 UART__ doc (page 563, "UART")...

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

We should write data to the UART Port...

ONLY WHEN the __THRE Bit__ is set.

(THRE means __Transmit Holding Register Empty__)

_Where's the THRE Bit?_

THRE Bit is __Bit 5__ (`0x20`) of UART_LSR.

__UART_LSR__ (Line Status Register) is at __Offset `0x14`__ from the UART Base Address.

In Arm64 Assembly, this is how we wait for the UART to be ready: [a64_lowputc.S](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L60-L72)

```text
/* PinePhone Allwinner A64: 
 * Wait for UART to be ready to transmit
 * xb: register which contains the UART base address
 * wt: scratch register number
 */

.macro early_uart_ready xb, wt
1:
  /* Load the Line Status Register at Offset 0x14 from UART Base Address */
  ldrh  \wt, [\xb, #0x14]

  /* Check the THRE Bit (Tx Holding Register Empty) */
  tst   \wt, #0x20

  /* If UART is not ready (THRE=0), jump back to label `1:` */
  b.eq  1b                     
.endm
```

## Initialise UART

_How will we initialise the UART Port?_

According to the __Allwinner A64 UART__ doc (page 562, "UART")...

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

We might __initialise the UART Port__ in [__`up_earlyserialinit`__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L51-L60) like so...

1.  Set __DLAB Flag__ to allow update of UART Divisor...

    ```text
    ldr  x15, =UART1_BASE_ADDRESS
    mov  x0,  #0x80
    strb w0,  [x15, #0x0C]
    ```

1.  Write the __UART Divisor__ (Least Significant Byte) to UART_DLL...

    ```text
    mov  x0, #(divisor % 256)
    strb w0, [x15, #0x00]
    ```

1.  Write the __UART Divisor__ (Most Significant Byte) to UART_DLH...

    ```text
    mov  x0, #(divisor / 256)
    strb w0, [x15, #0x04]
    ```

1.  Clear __DLAB Flag__ to disallow update of UART Divisor...

    ```text
    mov  x0, #0x00
    strb w0, [x15, #0x0C]
    ```

[(Confused? __`x0`__ and __`w0`__ are actually the same register, 64-bit vs 32-bit)](https://developer.arm.com/documentation/102374/0100/Registers-in-AArch64---general-purpose-registers)

Where...

-   __DLAB (Divisor Latch Access Bit)__ is Bit 7 of UART_LCR

-   __UART_LCR (Line Control Register)__ is at Offset `0x0C` of the UART Base Address

-   __UART_DLL (Divisor Latch Low)__ is at Offset `0x00`

-   __UART_DLH (Divisor Latch High)__ is at Offset `0x04`

-   __UART Divisor__ is computed as...

    (Serial Clock Frequency / 16) / Baud Rate

__TODO:__ What is the Serial Clock Frequency (SCLK)?

## UART Driver

We have implemented the __UART Driver__ for PinePhone's Allwinner A64 UART Port...

-   [arch/arm64/src/a64/a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c) 

Check out the details in this article...

-   [__"NuttX RTOS on PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)
