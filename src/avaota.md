# Porting Apache NuttX RTOS to Avaota-A1 SBC (Allwinner A527 SoC)

📝 _9 Apr 2025_

![Avaota-A1 SBC with SDWire MicroSD Multiplexer and Smart Power Plug](https://lupyuen.org/images/avaota-title.jpg)

[_(Watch the Demo on YouTube)_](https://youtu.be/PxaMcmMAzlM)

This article explains how we ported NuttX from [__QEMU Arm64 Kernel Build__](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig) to [__PINE64 Yuzuki Avaota-A1 SBC__](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/) based on [__Allwinner A527 SoC__](https://linux-sunxi.org/A523) ... Completed within [__24 Hours__](https://github.com/lupyuen2/wip-nuttx/commits/avaota)!

_Why are we doing this?_

- Anyone porting NuttX from __QEMU to Real SBC__? This walkthrough shall be mighty helpful!

- Avaota-A1 SBC is [__Open Source Hardware__](https://github.com/AvaotaSBC/Avaota-A1) _(CERN OHL Licensed)_. PINE64 sells it today, maybe we'll see more manufacturers.

- This could be the First Port of [__Arm64 in NuttX Kernel Build__](https://lupyuen.github.io/articles/privilege#nuttx-flat-mode-becomes-kernel-mode). _(NXP i.MX93 might be another?)_

- We'll run it as [__PR Test Bot__](https://lupyuen.github.io/articles/testbot3) for validating __Arm64 Pull Requests__ on Real Hardware. PR Test Bot will be fully automated thanks to the [__MicroSD Multiplexer__](https://lupyuen.github.io/articles/testbot3).

We're ready for volunteers to build __NuttX Drivers for Avaota-A1 / Allwinner A527__ _(GPIO, SPI, I2C, MIPI CSI / DSI, Ethernet, WiFi, ...)_ Please lemme know! 🙏

- [__Sunxi Docs on Allwinner A527__](https://linux-sunxi.org/A523)

- [__Allwinner A527 Datasheet__](https://linux-sunxi.org/File:A527_Datasheet_V0.93.pdf)

- [__Allwinner A523 User Manual__](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) _(A527 is similar to A523)_

- [__Avaota-A1 Schematic__](https://github.com/AvaotaSBC/Avaota-A1/blob/master/hardware/v1.4/01_SCH/SCH_Avaota%20Pi%20A_2024-05-20.pdf)

_(BTW I bought all the hardware covered in this article. Nope, nothing was sponsored: Avaota-A1, SDWire, IKEA TRETAKT)_

![Avaota-A1 SBC connected to USB UART](https://lupyuen.org/images/testbot3-uart.jpg)

# Boot Linux on our SBC

Nifty Trick for Booting NuttX on __Any Arm64 SBC__ (RISC-V too)

- __Arm64 Bootloader__ _(U-Boot / SyterKit)_ will boot Linux by loading the __`Image`__ file

  _(Containing the Linux Kernel)_

- Thus we __"Hijack" the `Image` file__, replace it by __NuttX Kernel__

- Which means __NuttX Kernel__ shall look and feel like a __Linux Kernel__

- That's why we have a [__Linux Kernel Header__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L89-L116) at the top of NuttX

To begin, we observe our SBC and its _Natural Behaviour_... How does it __Boot Linux?__

1.  Connect a [__USB UART Dongle__](https://pine64.com/product/serial-console-woodpecker-edition/) (CH340 or CP2102) to the __UART0 Port__ (pic above)

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

1.  Download the [__Latest AvaotaOS Release__](https://github.com/AvaotaSBC/AvaotaOS/releases) _(Ubuntu Noble GNOME)_ and uncompress it...

    ```bash
    wget https://github.com/AvaotaSBC/AvaotaOS/releases/download/0.3.0.4/AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
    xz -d AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
    ```

1.  Write the __`.img`__ file to a MicroSD with [__Balena Etcher__](https://etcher.balena.io/).

1.  Insert the MicroSD into our SBC and [__Boot AvaotaOS__](https://gist.github.com/lupyuen/dd4beb052ce07c36d41d409631c6d68b). We'll see the Boot Log...

    ```bash
    read /Image addr=40800000
    Kernel addr: 0x40800000
    BL31: v2.5(debug):9241004a9
    sunxi-arisc driver is starting
    ERROR: Error initializing runtime service opteed_fast
    ```

1.  Aha! __Kernel Boot Address__ _0x4080_0000_ is super important, we'll use it in a while

# NuttX Kernel Build for Arm64 QEMU

Follow these steps to Build and Run NuttX for [__Arm64 QEMU (Kernel Build)__](https://nuttx.apache.org/docs/latest/platforms/arm64/qemu/boards/qemu-armv8a/index.html)

```bash
## Build NuttX Kernel (NuttX Kernel Build)
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx
tools/configure.sh qemu-armv8a:knsh
make -j

## Build NuttX Apps (NuttX Kernel Build)
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Boot NuttX on QEMU
qemu-system-aarch64 \
  -semihosting \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

Check that it works...

```bash
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

NuttShell (NSH) NuttX-12.8.0
nsh> uname -a
nxposix_spawn_exec: ERROR: exec failed: 2
NuttX 12.8.0 96eb5e7819 Mar 13 2025 15:45:11 arm64 qemu-armv8a

nsh> hello
Hello, World!!

## No worries about `nxposix_spawn_exec`
## To Quit: Press Ctrl-a then x
```

We're ready to boot __`nuttx.bin`__ on our SBC.

> ![NuttX Kernel Build will call out to HostFS Semihosting](https://lupyuen.org/images/semihost-qemu.jpg)

_What's this semihosting business in QEMU?_

```bash
## Boot NuttX on QEMU, needs Semihosting
qemu-system-aarch64 \
  -semihosting ...
```

NuttX Kernel Build will call out to [__HostFS Semihosting__](https://lupyuen.github.io/articles/testbot2#semihosting-breakout) (pic above) to access NSH Shell and NuttX Apps. We'll change this for our SBC.

_Why start with NuttX Kernel Build? Not NuttX Flat Build?_

Our SBC is a mighty monster with __Eight Arm64 Cores__ and plenty of RAM _(2 GB)_. It makes more sense to boot [__NuttX Kernel Build__](https://lupyuen.github.io/articles/privilege#nuttx-flat-mode-becomes-kernel-mode) and run lots of cool powerful NuttX App, thanks to [__Virtual Memory__](https://lupyuen.github.io/articles/privilege#nuttx-flat-mode-becomes-kernel-mode).

_(NuttX Flat Build was created for Simpler Microcontrollers with Limited RAM)_

![Yuzuki Avaota-A1 SBC with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-sbc.jpg)

# Boot NuttX on our SBC

Remember the [__MicroSD we downloaded__](https://lupyuen.github.io/articles/avaota#boot-linux-on-our-sbc)? Inside the MicroSD is a 28 MB Linux Kernel, named "__`Image`__"

```bash
$ ls -l /media/$USER/YOUR_SD
   78769  bl31.bin
  180233  config-5.15.154-ga464bc4feaff
     512  dtb
     512  extlinux
27783176  Image
  180228  scp.bin
   12960  splash.bin
 5193581  System.map-5.15.154-ga464bc4feaff
 6497300  uInitrd
```

We replace it with NuttX...

1.  Take the NuttX Kernel __`nuttx.bin`__ from the previous section

    _(Yes the QEMU one)_

1.  Overwrite the __`Image`__ file by __`nuttx.bin`__...

    ```bash
    ## Copy and overwrite `Image` on MicroSD
    mv /media/$USER/YOUR_SD/Image /media/$USER/YOUR_SD/Image.old
    cp nuttx.bin /media/$USER/YOUR_SD/Image

    ## `Image` should be a lot smaller now
    ls -l /media/$USER/YOUR_SD/Image
    umount /media/$USER/YOUR_SD
    ```

1.  Insert the MicroSD into our SBC. Boot it...

    ```bash
    read /Image addr=40800000
    Kernel addr: 0x40800000
    BL31: v2.5(debug):9241004a9
    sunxi-arisc driver is starting
    ERROR: Error initializing runtime service opteed_fast
    ```

Nothing happens. We tweak this iteratively, in tiny steps...

# Print to UART in Arm64 Assembly

_Is NuttX actually booting on our SBC?_

Let's print something. __UART0 Base Address__ is here...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 1839 |
|:-------------------------------:|:---------|
| __Module__ | __Base Address__
| UART0 | _0x0250\_0000_

</div>
</p>

16550 Transmit Register is at __Offset 0__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 1839 |
|:-------------------------------:|:---------|
| __Offset__ | __Register__
| _0x0000_ | UART_THR _(Transmit Holding Register)_
| _0x0004_ | UART_DLH _(Divisor Latch High Register)_
| _0x0008_ | UART_IIR _(Interrupt Identity Register)_
| _0x000C_ | UART_LCR _(Line Control)_

</div>
</p>

Which means we can [__Print to UART__](https://github.com/lupyuen2/wip-nuttx/commit/029056c7e0da092e4d3a211b5f5b22b7014ba333) like so...

```c
// Print `123` to UART0
*(volatile uint8_t *) 0x02500000 = '1';
*(volatile uint8_t *) 0x02500000 = '2';
*(volatile uint8_t *) 0x02500000 = '3';
```

But we'll do it in __Arm64 Assembly__: [arm64_head.S](https://github.com/lupyuen2/wip-nuttx/commit/be2f1c55aa24eda9cd8652aa0bf38251335e9d01)

```c
/* Bootloader starts NuttX here */
__start:
  add x13, x18, #0x16 /* "MZ": Magic Number for Linux Kernel Header */
  b   real_start      /* Jump to Executable Code      */
  ...                 /* Omitted: Linux Kernel Header */

/* Executable Code begins here */
/* We print `123` to UART0     */
real_start:

  /* Load UART0 Base Address into Register X15 */
  mov  x15, #0x02500000

  /* Load character `1` into Register W16 */
  mov  w16, #0x31

  /* Store the lower byte from Register W16 (`1`) to UART0 Base Address */
  strb w16, [x15]

  /* Load and Store the lower byte from Register W16 (`2`) to UART0 Base Address */
  mov  w16, #0x32
  strb w16, [x15]

  /* Load and Store the lower byte from Register W16 (`3`) to UART0 Base Address */
  mov  w16, #0x33
  strb w16, [x15]
```

[_(RISC-V? Same same)_](https://lupyuen.github.io/articles/sg2000#print-to-uart-in-risc-v-assembly)

Rebuild NuttX and recopy __`nuttx.bin`__ to MicroSD, overwriting the __`Image`__ file. NuttX will boot and [__print `123`__](https://gist.github.com/lupyuen/14188c44049a14e3581523c593fdf2d8)! 🎉

```bash
read /Image addr=40800000
Kernel addr: 0x40800000
BL31: v2.5(debug):9241004a9
sunxi-arisc driver is starting
ERROR: Error initializing runtime service opteed_fast
123
```

Indeed NuttX is booting on our SBC, then crashing later. _(Ignore the error: opteed_fast)_

_Why print in Arm64 Assembly? Why not C?_

1.  Arm64 Assembly is the __very first thing that boots__ when Bootloader starts NuttX

1.  This happens __before anything complicated__ and crash-prone begins: UART Driver, Memory Management Unit, Task Scheduler, ...

1.  The Arm64 Assembly above is __Address-Independent Code__: It will execute at Any Arm64 Address

Next we move our code and make it Address-Dependent...

# Set the Start Address

_NuttX boots a tiny bit on our SBC. Where's the rest?_

Our SBC boots NuttX at a different address from QEMU. We set the __Start Address__ inside NuttX...

```bash
read /Image addr=40800000
Kernel addr: 0x40800000
123
```

1.  Remember the [__Boot Log__](https://lupyuen.github.io/articles/avaota#boot-linux-on-our-sbc) from earlier? It says that the [__SyterKit Bootloader__](https://github.com/YuzukiHD/SyterKit) starts NuttX at __Address `0x4080_0000`__. We set it here: [ld-kernel.script](https://github.com/lupyuen2/wip-nuttx/commit/c38e1f7c014e1af648a33847fc795930ba995bca)

    ```c
    MEMORY {
      /* Previously: QEMU boots at 0x4028_0000 */
      dram (rwx)  : ORIGIN = 0x40800000, LENGTH = 2M

      /* Previously: QEMU Paged Memory is at 0x4028_0000 */
      pgram (rwx) : ORIGIN = 0x40A00000, LENGTH = 4M   /* w/ cache */

      /* Why? Because 0x4080_0000 + 2 MB = 0x40A0_0000 */
    ```

    _(Note that Paged Memory Pool shifts down)_

1.  Since we changed the __Paged Memory Pool__ _(pgram)_, we update _ARCH_PGPOOL_PBASE_ and _VBASE_: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/eb33ac06f88dda557bc8ac97bec7d6cbad4ccb86)

    ```bash
    ## Physical Address of Paged Memory Pool
    ## Previously: QEMU Paged Memory is at 0x4028_0000
    CONFIG_ARCH_PGPOOL_PBASE=0x40A00000

    ## Virtual Address of Paged Memory Pool
    ## Previously: QEMU Paged Memory is at 0x4028_0000
    CONFIG_ARCH_PGPOOL_VBASE=0x40A00000
    ```

    _(Paged Memory Pool shall be dished out as Virtual Memory to NuttX Apps)_

1.  NuttX QEMU declares the [__RAM Size as 128 MB__](https://github.com/lupyuen2/wip-nuttx/commit/005900ef7e1a1480b8df975d0dcd190fbfc60a45) in _RAMBANK1_SIZE_. We set _RAM_SIZE_ accordingly: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/c8fbc5b86c2bf1dd7b8243b301b0790115c9c4ca)

    ```bash
    ## RAM Size is a paltry 128 MB
    CONFIG_RAM_SIZE=134217728
    ```

    _(Kinda tiny, but sufficient)_

1.  __Linux Kernel Header__ has an incorrect __Image Load Offset__. Arm64 Bootloaders don't care, we'll let it be...

    ```c
    /* Bootloader starts NuttX here, followed by Linux Kernel Header */
    __start:
      ...
      /* Image Load Offset from Start of RAM         */
      /* Boot Address - CONFIG_RAM_START = 0x800000  */
      /* But we won't change this, since it's unused */
      .quad 0x800000
    ```

With these mods, our C Code in NuttX shall boot correctly. FYI: Boot Address also appears on the Onboard LCD...

![Avaota-A1 SBC with Onboard LCD](https://lupyuen.org/images/testbot3-lcd.jpg)

# UART Driver for 16550

_Our C Code can print to UART now?_

To watch the __Boot Progress__ _(Sesame Street-style)_, we can print primitively to UART like this: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/commit/029056c7e0da092e4d3a211b5f5b22b7014ba333)

```c
// 0x0250_0000 is the UART0 Base Address
void arm64_boot_primary_c_routine(void) {
  *(volatile uint8_t *) 0x02500000 = 'A';
  arm64_chip_boot();
  ...

void arm64_chip_boot(void) {
  *(volatile uint8_t *) 0x02500000 = 'B';
  arm64_mmu_init(true);  // Init the Memory Mgmt Unit

  *(volatile uint8_t *) 0x02500000 = 'C';
  arm64_enable_mte();    // Init the Memory Tag Extension

  *(volatile uint8_t *) 0x02500000 = 'D';
  qemu_board_initialize();  // Init the Board

  *(volatile uint8_t *) 0x02500000 = 'E';
  arm64_earlyserialinit();  // Init the Serial Driver

  *(volatile uint8_t *) 0x02500000 = 'F';
  syslog_rpmsg_init_early(...);  // Init the System Logger

  *(volatile uint8_t *) 0x02500000 = 'G';
  up_perf_init(..);  // Init the Performance Counters
```

Beyond Big Bird: We need the __16550 UART Driver__. Based on the [__A527 UART Doc__](https://lupyuen.github.io/articles/avaota#print-to-uart-in-arm64-assembly)...

1.  __NuttX Boot Code__ _(Arm64 Assembly)_ will print to UART. We patch it: [qemu_lowputc.S](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-60cebb895326dea641e32d31ff39511acf127a30c9ac8f275590e7524737366e)

    ```c
    // Base Address and Baud Rate for 16550 UART
    #define UART1_BASE_ADDRESS          0x02500000
    #define EARLY_UART_PL011_BAUD_RATE  115200
    ```

1. __NuttX Boot Code__ will drop UART Output, unless we wait for UART Ready: [qemu_lowputc.S](https://github.com/lupyuen2/wip-nuttx/commit/544323e7c0e66c4df0d1312d4837147d420bc19d)

    ```c
    /* Wait for 16550 UART to be ready to transmit
    * xb: Register that contains the UART Base Address
    * wt: Scratch register number */
    .macro early_uart_ready xb, wt
    1:
      ldrh  \wt, [\xb, #0x14] /* UART_LSR (Line Status Register) */
      tst   \wt, #0x20        /* Check THRE (TX Holding Register Empty) */
      b.eq  1b                /* Wait for the UART to be ready (THRE=1) */
    .endm
    ```

    [_(Thanks to PinePhone)_](https://lupyuen.github.io/articles/uboot#wait-for-uart-ready)

1.  QEMU uses PL011 UART. We switch to __16550 UART__: [qemu_serial.c](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-aefbee7ddc3221be7383185346b81cff77d382eb6f308ecdccb44466d0437108)

    ```c
    // Switch from PL011 UART (QEMU) to 16550 UART
    #include <nuttx/serial/uart_16550.h>

    // Enable the 16550 Console UART at Startup
    void arm64_earlyserialinit(void) {
      // Previously for QEMU: pl011_earlyserialinit
      u16550_earlyserialinit();
    }

    // Ditto but not so early
    void arm64_serialinit(void) {
      // Previous for QEMU: pl011_serialinit
      u16550_serialinit();
    }
    ```

1.  __16550 UART__ shall be configured: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-6adf2d1a1e5d57ee68c7493a2b52c07c4e260e60d846a9ee7b8f8a6df5d8cb64)

    ```bash
    CONFIG_16550_ADDRWIDTH=0
    CONFIG_16550_REGINCR=4
    CONFIG_16550_UART0=y
    CONFIG_16550_UART0_BASE=0x02500000
    CONFIG_16550_UART0_CLOCK=198144000
    CONFIG_16550_UART0_IRQ=125
    CONFIG_16550_UART0_SERIAL_CONSOLE=y
    CONFIG_16550_UART=y
    CONFIG_16550_WAIT_LCR=y
    CONFIG_SERIAL_UART_ARCH_MMIO=y
    ```

1.  __PL011 UART__ shall be removed: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/8fc8ed6ba84cfea86184f61d9c4d7c8e21329987)

    ```bash
    ## Remove PL011 UART from NuttX Config:
    ## CONFIG_UART1_BASE=0x9000000
    ## CONFIG_UART1_IRQ=33
    ## CONFIG_UART1_PL011=y
    ## CONFIG_UART1_SERIAL_CONSOLE=y
    ## CONFIG_UART_PL011=y
    ```

1.  __16550_UART0_CLOCK__ isn't quite correct, we'll [__settle later__](https://lupyuen.github.io/articles/avaota#nuttx-config). Meanwhile we disable the __UART Clock Configuration__: [uart_16550.c](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-f208234edbfb636de240a0fef1c85f9cecb37876d5bc91ffb759f70a1e96b1d1)

    ```c
    // We disable the UART Clock Configuration...
    static int u16550_setup(FAR struct uart_dev_s *dev) { ...
    #ifdef FIX_LATER  // We'll fix it later
      // Enter DLAB=1
      u16550_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));

      // Omitted: Set the UART Baud Divisor
      // ...

      // Clear DLAB
      u16550_serialout(priv, UART_LCR_OFFSET, lcr);
    #endif
    ```

Same old drill: Rebuild, recopy and reboot NuttX. We see [__plenty more debug output__](https://gist.github.com/lupyuen/563ed00d3f6e9f7fb9b27268d4eae26b)...

```bash
123
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
AB
```

OK the _repeated rebuilding, recopying and rebooting_ of NuttX is getting really tiresome. We automate...

![Avaota-A1 SBC with SDWire MicroSD Multiplexer and Smart Power Plug](https://lupyuen.org/images/testbot2-flow3.jpg)

# MicroSD Multiplexer + Smart Power Plug

_What if we could rebuild-recopy-reboot NuttX... In One Single Script?_

Thankfully our Avaota-A1 SBC is connected to [__SDWire MicroSD Multiplexer__](https://lupyuen.github.io/articles/avaota#appendix-sdwire-microsd-multiplexer) and [__Smart Power Plug__](https://lupyuen.github.io/articles/testbot#power-up-our-oz64-sbc) (pic above). Our Build Script shall do __everything__ for us...

1.  Copy __NuttX to MicroSD__

1.  __Swap the MicroSD__ from our Test PC to SBC

1.  __Power up SBC__ and boot NuttX

1.  How it looks? [__Watch the Demo__](https://youtu.be/PxaMcmMAzlM)

![Avaota-A1 SBC with SDWire MicroSD Multiplexer and Smart Power Plug](https://lupyuen.org/images/avaota-title.jpg)

Here's our nifty __Build Script__: [run.sh](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

```bash
## Build NuttX and Apps (NuttX Kernel Build)
make -j
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Generate the Initial RAM Disk
## Prepare a Padding with 64 KB of zeroes
## Append Padding and Initial RAM Disk to the NuttX Kernel
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
head -c 65536 /dev/zero >/tmp/nuttx.pad
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image

## Get the Home Assistant Token
## That we copied from http://localhost:8123/profile/security
## export token=xxxx
. $HOME/home-assistant-token.sh

## Power Off the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_off"}' \
  http://localhost:8123/api/services/automation/trigger

## Copy NuttX Image to MicroSD
## No password needed for sudo, see below
## Change `thinkcentre` to your Test PC
scp Image thinkcentre:/tmp/Image
ssh thinkcentre ls -l /tmp/Image
ssh thinkcentre sudo /home/user/copy-image.sh

## Power On the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_on"}' \
  http://localhost:8123/api/services/automation/trigger

## Wait for SBC to finish booting
sleep 30

## Power Off the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_off"}' \
  http://localhost:8123/api/services/automation/trigger
```

[(See the __Build Log__)](https://gist.github.com/lupyuen/6c0607daa0a8f37bda37cc80e76259ee)

[(Watch the __Demo on YouTube__)](https://youtu.be/PxaMcmMAzlM)

![Smart Power Plug in IKEA App and Google Home](https://lupyuen.org/images/starpro64-power1.jpg)

This script assumes that we have...

- Installed a [__Home Assistant Server__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _(Works fine with Docker)_

- Added the Smart Power Plug to [__Google Assistant__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _"Avaota Power" (pic above)_

- Installed the [__Google Assistant SDK__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug) for Home Assistant

  _(So we don't need Zigbee programming)_

- Created the [__Power Automation__](https://lupyuen.github.io/articles/sg2000a#call-the-home-assistant-api) in Home Assistant

  _"Avaota Power On"_ and _"Avaota Power Off" (pic below)_

![Smart Power Plug in Home Assistant](https://lupyuen.org/images/starpro64-power2.jpg)

_What's copy_image.sh?_

This is the script that copies our NuttX Image to MicroSD, via the __SDWire MicroSD Multiplexer__, explained here...

- [__"SDWire MicroSD Multiplexer"__](https://lupyuen.github.io/articles/avaota#appendix-sdwire-microsd-multiplexer)

# Arm64 Memory Management Unit

_It's getting late. Can we get back to NuttX now?_

[__24 Hours__](https://github.com/lupyuen2/wip-nuttx/commits/avaota) is all we need no worries! Earlier we saw NuttX [__stuck at "AB"__](https://lupyuen.github.io/articles/avaota#uart-driver-for-16550)...

```bash
123
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
AB
```

Which says that NuttX is stranded inside __arm64_mmu_init__: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/commit/029056c7e0da092e4d3a211b5f5b22b7014ba333)

```c
// 0x0250_0000 is the UART0 Base Address
void arm64_boot_primary_c_routine(void) {
  *(volatile uint8_t *) 0x02500000 = 'A';
  arm64_chip_boot();
  ...

// `AB` means that NuttX is stuck inside arm64_mmu_init()
void arm64_chip_boot(void) {
  *(volatile uint8_t *) 0x02500000 = 'B';
  arm64_mmu_init(true);  // Init the Memory Mgmt Unit

  // Stuck above, never came here
  *(volatile uint8_t *) 0x02500000 = 'C';
  arm64_enable_mte();    // Init the Memory Tag Extension
```

_What's arm64_mmu_init?_

NuttX calls __arm64_mmu_init__ to start the Arm64 __Memory Management Unit (MMU)__. We add some logs inside: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/pull/96/files#diff-230f2ffd9be0a8ce48d4c9fb79df8f003b0c31fa0a18b6c0876ede5b4e334bb9)

```c
// Enable Debugging for MMU
#define CONFIG_MMU_ASSERT 1
#define CONFIG_MMU_DEBUG  1
#define trace_printf _info

// We fix the Debug Output, changing `%lux` to `%p`
static void init_xlat_tables(const struct arm_mmu_region *region) {
  ...
  sinfo("mmap: virt %p phys %p size %p\n", virt, phys, size);

// To enable the MMU at Exception Level 1...
static void enable_mmu_el1(unsigned int flags) {
  ...
  // Flush the Cached Data before Enabling MMU
  _info("UP_MB");
  UP_MB();

  // Enable the MMU and Data Cache
  _info("Enable the MMU and data cache");
  write_sysreg(value | SCTLR_M_BIT | SCTLR_C_BIT, sctlr_el1);

  // Ensure that MMU Enable takes effect immediately
  _info("UP_ISB");
  UP_ISB();
```

And we Enable the Logs for __Scheduler and Memory Manager__: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/pull/96/files#diff-6adf2d1a1e5d57ee68c7493a2b52c07c4e260e60d846a9ee7b8f8a6df5d8cb64)

```bash
## Enable Logging for Memory Manager
CONFIG_DEBUG_MM=y
CONFIG_DEBUG_MM_ERROR=y
CONFIG_DEBUG_MM_INFO=y
CONFIG_DEBUG_MM_WARN=y

## Enable Logging for Scheduler
CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
```

Ah OK we're stuck just before [__Enabling the MMU__](https://gist.github.com/lupyuen/544a5d8f3fab2ab7c9d06d2e1583f362)...

```bash
## Init the MMU Page Translation Tables
init_xlat_tables: mmap: virt 0x7000000    phys 0x7000000    size 0x20000000
init_xlat_tables: mmap: virt 0x40000000   phys 0x40000000   size 0x8000000
init_xlat_tables: mmap: virt 0x4010000000 phys 0x4010000000 size 0x10000000
init_xlat_tables: mmap: virt 0x8000000000 phys 0x8000000000 size 0x8000000000
init_xlat_tables: mmap: virt 0x3eff0000 phys 0x3eff0000 size 0x10000
init_xlat_tables: mmap: virt 0x40800000 phys 0x40800000 size 0x2a000
init_xlat_tables: mmap: virt 0x4082a000 phys 0x4082a000 size 0x6000
init_xlat_tables: mmap: virt 0x40830000 phys 0x40830000 size 0x13000
init_xlat_tables: mmap: virt 0x40a00000 phys 0x40a00000 size 0x400000

## Enable the MMU at Exception Level 1
enable_mmu_el1: UP_MB
enable_mmu_el1: Enable the MMU and data cache
```

[(__Exception Level__ explained)](https://lupyuen.github.io/articles/interrupt#exception-levels)

Something sus about the above [__Mystery Addresses__](https://gist.github.com/lupyuen/544a5d8f3fab2ab7c9d06d2e1583f362), what are they?

<p>

| Virtual | Physical | Size |
|:-------:|:--------:|:----:|
| _0x0700_0000_ | 0x0700_0000    | _0x2000_0000_
| _0x4000_0000_ | 0x4000_0000    | _0x0800_0000_
| _0x40_1000_0000_ | 0x40_1000_0000 | _0x1000_0000_
| _0x80_0000_0000_ | 0x80_0000_0000 | _0x80_0000_0000_
| _0x3EFF_0000_ | 0x3EFF_0000 | _0x0001_0000_
| _0x4080_0000_ | 0x4080_0000 | _0x0002_A000_
| _0x4082_A000_ | 0x4082_A000 | _0x0000_6000_
| _0x4083_0000_ | 0x4083_0000 | _0x0001_3000_
| _0x40A0_0000_ | 0x40A0_0000 | _0x0040_0000_

</p>

![A527 Memory Map](https://lupyuen.org/images/avaota-memory.jpg)

# Fix the Memory Map

_Why do we need Arm64 MMU? (Memory Management Unit)_

We require MMU for...

- __Memory Protection__: Prevent Applications _(and Kernel)_ from meddling with things _(in System Memory)_ that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of _"Imaginary Memory"_ at Exotic Addresses _(0x8000_0000!)_

  But in reality: They're System RAM recycled from boring old addresses _(like 0x40A0_4000)_

If we don't configure MMU with the correct __Memory Map__...

- __NuttX Kernel__ won't boot: _"Help! I can't access my Kernel Code and Data!"_

- __NuttX Apps__ won't run: _"Whoops where's the App Code and Data that Kernel promised?"_

_Arm64 MMU won't turn on. Maybe our Memory Map is incorrect?_

We verify our __A527 Memory Map__ (pic above)

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 40 |
|:--------------------------------|:---------|
| __Module__ | __Address__
| Boot ROM & SRAM | _0x0000_0000_ to ...
| PCIE | _0x2000_0000_ to _0x2FFF_FFFF_
| DRAM | _0x4000_0000_ to ...

</div>
</p>

How does this compare with NuttX? We do extra __MMU Logging__: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/commit/9488ecb5d8eb199bdbe16adabef483cf9cf04843)

```c
// Print the Names of the MMU Memory Regions
static void init_xlat_tables(const struct arm_mmu_region *region) { ...
  _info("name=%s\n", region->name);
  sinfo("mmap: virt %p phys %p size %p\n", virt, phys, size);
```

Ah much clearer! Now we see the __Names of Memory Regions__ for the MMU...

<p>

| Name | Physical | Size |
|:--------|:--------:|:----:|
| _DEVICE_REGION_ | 0x0700_0000 | _0x2000_0000_
| _DRAM0_S0_ | 0x4000_0000 | _0x0800_0000_
| _PCI_CFG_ | 0x40_1000_0000 | _0x1000_0000_
| _PCI_MEM_ | 0x80_0000_0000 | _0x80_0000_0000_
| _PCI_IO_ | 0x3EFF_0000 | _0x0001_0000_
| _nx_code_ | 0x4080_0000 | _0x0002_A000_
| _nx_rodata_ | 0x4082_A000 | _0x0000_6000_
| _nx_data_ | 0x4083_0000 | _0x0001_3000_
| _nx_pgpool_ | 0x40A0_0000 | _0x0040_0000_

</p>

Two Tweaks...

- __DEVICE_REGION__: This says I/O Memory Space ends at _0x2700_0000_. Based on the earlier __A527 Memory Map__, we extend this to _0x4000_0000 (1 GB)_: [qemu/chip.h](https://github.com/lupyuen2/wip-nuttx/commit/005900ef7e1a1480b8df975d0dcd190fbfc60a45)

  ```c
  // Fix the I/O Memory Space: Base Address and Size
  #define CONFIG_DEVICEIO_BASEADDR 0x00000000
  #define CONFIG_DEVICEIO_SIZE     MB(1024)

  // We don't need PCI, for now
  // #define CONFIG_PCI_CFG_BASEADDR 0x4010000000
  // #define CONFIG_PCI_CFG_SIZE     MB(256)
  // #define CONFIG_PCI_MEM_BASEADDR 0x8000000000
  // #define CONFIG_PCI_MEM_SIZE     GB(512)
  // #define CONFIG_PCI_IO_BASEADDR  0x3eff0000
  // #define CONFIG_PCI_IO_SIZE      KB(64)
  ```

- __PCI__: We remove these for now: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/commit/ca273d05e015089a33072997738bf588b899f8e7)

  ```c
  static const struct arm_mmu_region g_mmu_regions[] = {
    ...
    // We don't need PCI, for now
    // MMU_REGION_FLAT_ENTRY("PCI_CFG", ...
    // MMU_REGION_FLAT_ENTRY("PCI_MEM", ...
    // MMU_REGION_FLAT_ENTRY("PCI_IO", ...
  ```

The rest are hunky dory...

- __DRAM0_S0__ says that RAM Address Space ends at _0x4800_0000 (128 MB)_ 
  
  _(Kinda small, but sufficient for now)_

- __nx_code__ _(0x4080_0000)_: Kernel Code begins here

- __nx_rodata__ _(0x4082_A000)_: Read-Only Data for Kernel

- __nx_data__ _(0x4083_0000)_: Read-Write Data for Kernel

- __nx_pgpool__ _(0x40A0_0000)_: Remember the [__Paged Memory Pool__](https://lupyuen.github.io/articles/avaota#set-the-start-address)? This shall be dished out as __Virtual Memory__ to NuttX Apps

We rebuild, recopy, reboot NuttX. Our Memory Map looks [__much better now__](https://gist.github.com/lupyuen/ad4cec0dee8a21f3f404144be180fa14)...

<p>

| Name | Physical | Size |
|:--------|:--------:|:----:|
| _DEVICE_REGION_ | 0x0000_0000 | _0x4000_0000_
| _DRAM0_S0_ | 0x4000_0000 | _0x0800_0000_
| _nx_code_ | 0x4080_0000 | _0x0002_A000_
| _nx_rodata_ | 0x4082_A000 | _0x0000_6000_
| _nx_data_ | 0x4083_0000 | _0x0001_3000_
| _nx_pgpool_ | 0x40A0_0000 | _0x0040_0000_

</p>

Though it crashes elsewhere...

# Arm64 Generic Interrupt Controller

_Why is NuttX failing with an Undefined Instruction?_

```bash
gic_validate_dist_version: No GIC version detect
arm64_gic_initialize: no distributor detected, giving up ret=-19
...
nx_start_application: Starting init task: /system/bin/init
arm64_el1_undef: Undefined instruction at 0x408276e4, dump:
Assertion failed panic: at file: common/arm64_fatal.c:572
```

Yeah this failure is [__totally misleading__](https://gist.github.com/lupyuen/3a7d1e791ac14905532db2d768ae230f). Real Culprit: NuttX couldn't __Init the GIC__...

```bash
No GIC version detect
No distributor detected, giving up
```

_What's this GIC?_

It's the Arm64 [__Generic Interrupt Controller (GIC)__](https://developer.arm.com/documentation/198123/0302/What-is-a-Generic-Interrupt-Controller-), version 3. GIC shall...

- Receive __Input / Output Interrupts__

  _(Like keypresses)_

- Forward them to a __CPU Core__ for processing

  _(Works like RISC-V PLIC)_

GIC is here...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 263 |
|:-------------------------------:|:---------|
| __Module__ | __Base Address__
| GIC | _0x0340_0000_

</div>
</p>

Which has these __GIC Registers__ inside, handling 8 Arm64 Cores...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 263 |
|:-------------------------------:|:---------|
| __Offset__ | __Register__
| _0x00_0000_ | GICD_CTLR  _(Distributor Control Register)_
| _0x06_0000_ | GICR_CTLR_C0  _(Redistributor Control Register, Core 0)_
| _0x08_0000_ | GICR_CTLR_C1  _(Ditto, Core 1)_
| _0x0A_0000_ | GICR_CTLR_C2  _(Ditto, Core 2)_
| _0x0C_0000_ | GICR_CTLR_C3  _(Ditto, Core 3)_
| _0x0E_0000_ | GICR_CTLR_C4  _(Ditto, Core 4)_
| _0x10_0000_ | GICR_CTLR_C5  _(Ditto, Core 5)_
| _0x12_0000_ | GICR_CTLR_C6  _(Ditto, Core 6)_
| _0x14_0000_ | GICR_CTLR_C7  _(Ditto, Core 7)_
| _0x16_0000_ | GICDA_CTLR  _(Distributor Control Register A)_

</div>
</p>

Based on the above, we set the __Addresses of GICD and GICR__ _(Distributor / Redistributor)_: [qemu/chip.h](https://github.com/lupyuen2/wip-nuttx/commit/f3a26dbba69a0714bc91d0c345b8fba5e0835b76)

```c
// Base Address of GIC Distributor and Redistributor
#define CONFIG_GICD_BASE   0x3400000
#define CONFIG_GICR_BASE   0x3460000

// Spaced 0x20000 bytes per Arm64 Core
#define CONFIG_GICR_OFFSET 0x20000
```

Remember to [__Disable Memory Manager Logging__](https://github.com/lupyuen2/wip-nuttx/commit/10c7173b142f4a0480d742688c72499b76f66f83). NuttX GIC Driver starts correctly and [__complains no more__](https://gist.github.com/lupyuen/3c587ac0f32be155c8f9a9e4ca18676c)!

```bash
## SPI = Physical Interrupt Signal (not the typical SPI)
gic_validate_dist_version:
  GICv3 version detect
  GICD_TYPER = 0x7b0408
  256 SPIs implemented
```

We'll call GIC to handle UART Interrupts. Before that: We need NSH Shell...

![NuttX Apps Filesystem on ROMFS](https://lupyuen.org/images/avaota-initrd1.jpg)

# NuttX Apps Filesystem

_Are we done yet?_

For a __Simple NuttX Port__ _(Flat Build)_: Congrats, just fix the [__UART Interrupt__](https://lupyuen.github.io/articles/avaota#fix-the-uart-interrupt) and we're done!

However we're doing __NuttX Kernel Build__. Which [__needs more work__](https://gist.github.com/lupyuen/3c587ac0f32be155c8f9a9e4ca18676c)...

```bash
nx_start_application:
  Starting init task: /system/bin/init
arm64_el1_undef:
  Undefined instruction at 0x408274a4
Assertion failed panic:
  common/arm64_fatal.c:572
```

_What's /system/bin/init? Why is it failing?_

_/system/bin/init_ is __NSH Shell__. NuttX Kernel Build will load NuttX Apps from a __Local Filesystem__, which is missing right now. _(NuttX Flat Build will bind binary Apps directly into Kernel)_

To solve this: We bundle the NuttX Apps together into a __ROMFS Filesystem__...

```bash
## Generate the Initial RAM Disk
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"
```

Then we package NuttX Kernel + NuttX Apps into a __NuttX Image__...

```bash
## Prepare a Padding with 64 KB of zeroes
## Append Padding and Initial RAM Disk to the NuttX Kernel
head -c 65536 /dev/zero >/tmp/nuttx.pad
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image
```

[(See the __Build Script__)](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

When NuttX Boots: It will...

1.  Find the __ROMFS Filesystem__

1.  Mount it as a __RAM Disk__

1.  Allowing NuttX Kernel to start __NSH Shell__

    _(And other NuttX Apps)_

Everything is explained here...

- [__"NuttX Apps Filesystem"__](https://lupyuen.github.io/articles/avaota#appendix-nuttx-apps-filesystem)

NSH Prompt still missing? It won't appear until we handle the UART Interrupt...

![NuttX on Avaota-A1](https://lupyuen.org/images/testbot3-port.png)

# Fix the UART Interrupt

One Last Thing: Settle the __UART Interrupt__ and we're done!

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 256 |
|:-------------------------------:|:--------:|
| __Interrupt Number__ | __Interrupt Source__
| 34 | UART0

</div>
</p>

This is how we set the __UART0 Interrupt__ and watch for keypresses: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/cd6da8f5378eb493528e57c61f887b6585ab8eaf#diff-6adf2d1a1e5d57ee68c7493a2b52c07c4e260e60d846a9ee7b8f8a6df5d8cb64)

```bash
## Set the UART0 Interrupt to 34
CONFIG_16550_UART0_IRQ=34
```

To Wrap Up: We Disable Logging for [__Memory Manager and Scheduler__](https://github.com/lupyuen2/wip-nuttx/commit/6c5c1a5f9fb1c939d8e75a5e9544b1a5261165ee). And [__Disable MMU Debugging__](https://github.com/lupyuen2/wip-nuttx/commit/e5c1b0449d3764d63d447eb96eb7186a27f77c88).

__NSH Prompt__ finally appears and __OSTest completes successfully__. Our NuttX Porting is complete yay!

```bash
NuttShell (NSH) NuttX-12.4.0
nsh> uname -a
NuttX 12.4.0 6c5c1a5f9f-dirty Mar  8 2025 21:57:02 arm64 qemu-armv8a

nsh> ostest
...
user_main: Exiting
ostest_main: Exiting with status 0
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/c2248e7537ca98333d47e33b232217b6)

[(See the __Final Code__)](https://lupyuen.github.io/articles/avaota#appendix-port-nuttx-to-avaota-a1)

[(Ready for __NuttX Upstreaming__)](https://lupyuen.github.io/articles/avaota#appendix-upstream-nuttx-for-avaota-a1)

_NSH Prompt won't appear if UART Interrupt is disabled?_

That's because NSH runs as a __NuttX App in User Space__. When NSH Shell prints this...

```bash
NuttShell (NSH) NuttX-12.4.0
nsh>
```

It calls the __Serial Driver__. Which will wait for a __UART Interrupt__ to signal that the __Transmit Buffer__ is empty and available.

Thus if UART Interrupt is disabled, nothing gets printed in NuttX Apps. [(Explained here)](https://lupyuen.github.io/articles/plic#no-console-output-from-nuttx-apps)

![NuttX might run OK on Radxa Cubie A5E (Allwinner T527)](https://lupyuen.org/images/avaota-cubie.jpg)

[_NuttX might run OK on Radxa Cubie A5E (Allwinner T527)_](https://arace.tech/products/radxa-cubie-a5e)

# What's Next

Right now we're upstreaming Avatoa-A1 SBC to __NuttX Mainline__...

- [__"Port NuttX to Avaota-A1"__](https://lupyuen.github.io/articles/avaota#appendix-port-nuttx-to-avaota-a1)

- [__"Upstream NuttX for Avaota-A1"__](https://lupyuen.github.io/articles/avaota#appendix-upstream-nuttx-for-avaota-a1)

We're seeking volunteers to build __NuttX Drivers for Avaota-A1__ _(GPIO, SPI, I2C, MIPI CSI / DSI, Ethernet, WiFi, ...)_ Please lemme know!

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

[__lupyuen.org/src/avaota.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/avaota.md)

![Yuzuki Avaota-A1 SBC with PinePhone MicroSD Extender](https://lupyuen.org/images/testbot3-sbc.jpg)

# Appendix: Build NuttX for Avaota-A1

To boot __NuttX on Avatoa-A1__: We may download __`Image`__ from here...

- [__NuttX Release for Avatoa-A1 SBC__](https://github.com/lupyuen2/wip-nuttx/releases/tag/avaota2-1)

Or follow these steps to compile our _(Work-In-Progress)_ __NuttX for Avaota-A1__: [run.sh](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

```bash
## Download Source Code for NuttX and Apps
git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch avaota
git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch avaota
cd nuttx

## Build NuttX and Apps (NuttX Kernel Build)
tools/configure.sh qemu-armv8a:knsh
make -j
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Generate the Initial RAM Disk
## Prepare a Padding with 64 KB of zeroes
## Append Padding and Initial RAM Disk to the NuttX Kernel
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
head -c 65536 /dev/zero >/tmp/nuttx.pad
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image
```

Read on to boot the NuttX Image on our SBC...

[(See the __Build Log__)](https://gist.github.com/lupyuen/6c0607daa0a8f37bda37cc80e76259ee)

![NuttX on Avaota-A1](https://lupyuen.org/images/testbot3-port.png)

# Appendix: Boot NuttX on Avaota-A1

Earlier we built [__NuttX for Avaota-A1__](https://lupyuen.github.io/articles/avaota#appendix-build-nuttx-for-avaota-a1) and created the __`Image`__ file, containing the NuttX Kernel + NuttX Apps. Let's boot it on MicroSD...

1.  Prepare the __AvaotaOS MicroSD__...

    [__"Boot NuttX Kernel on our SBC"__](https://lupyuen.github.io/articles/avaota#boot-nuttx-kernel-on-our-sbc)

1.  Copy the __NuttX Image__ to MicroSD...

    ```bash
    ## Copy NuttX Image to AvaotaOS MicroSD
    ## Overwrite the `Image` file
    mv /media/$USER/YOUR_SD/Image /media/$USER/YOUR_SD/Image.old
    cp Image /media/$USER/YOUR_SD/Image

    ## Unmount and boot it on Avaota-A1
    ls -l /media/$USER/YOUR_SD/Image
    umount /media/$USER/YOUR_SD
    ```

1.  __Boot the MicroSD__ on our SBC

We can automate the last two steps with a [__MicroSD Multiplexer__](https://lupyuen.github.io/articles/avaota#microsd-multiplexer--smart-power-plug) and [__Smart Power Plug__](https://lupyuen.github.io/articles/avaota#microsd-multiplexer--smart-power-plug)...

```bash
## Get the Home Assistant Token
## That we copied from http://localhost:8123/profile/security
## export token=xxxx
. $HOME/home-assistant-token.sh

## Power Off the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_off"}' \
  http://localhost:8123/api/services/automation/trigger

## Copy NuttX Image to MicroSD
## No password needed for sudo, see below
## Change `thinkcentre` to your Test PC
scp Image thinkcentre:/tmp/Image
ssh thinkcentre ls -l /tmp/Image
ssh thinkcentre sudo /home/user/copy-image.sh

## Power On the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_on"}' \
  http://localhost:8123/api/services/automation/trigger

## Wait for SBC to finish testing
echo Press Enter to Power Off
read

## Power Off the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.avaota_power_off"}' \
  http://localhost:8123/api/services/automation/trigger
```

[(Watch the __Demo on YouTube__)](https://youtu.be/PxaMcmMAzlM)

[(__copy-image.sh__ is explained here)](https://lupyuen.github.io/articles/avaota#microsd-multiplexer--smart-power-plug)

[(__Smart Power Plug__ also)](https://lupyuen.github.io/articles/avaota#microsd-multiplexer--smart-power-plug)

NuttX boots to NSH Shell. And passes OSTest yay!

<span style="font-size:60%">

```text
NOTICE:  BL31: v2.5(debug):9241004a9
NOTICE:  BL31: Built : 13:37:46, Nov 16 2023
NOTICE:  BL31: No DTB found.
NOTICE:  [SCP] :wait arisc ready....
NOTICE:  [SCP] :arisc version: []
NOTICE:  [SCP] :arisc startup ready
NOTICE:  [SCP] :arisc startup notify message feedback
NOTICE:  [SCP] :sunxi-arisc driver is starting
ERROR:   Error initializing runtime service opteed_fast
123
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
ABarm64_mmu_init:
setup_page_tables:
enable_mmu_el1:
enable_mmu_el1: UP_MB
enable_mmu_el1: Enable the MMU and data cache
up_allocate_kheap: CONFIG_RAM_END=0x48000000, g_idle_topstack=0x40847000
qemu_bringup:
mount_ramdisk:
nx_start_application: ret=0
board_app_initialize:

NuttShell (NSH) NuttX-12.4.0
nsh> uname -a
NuttX 12.4.0 6c5c1a5f9f-dirty Mar  8 2025 21:57:02 arm64 qemu-armv8a

nsh> free
      total       used       free    maxused    maxfree  nused  nfree name
  125538304      33848  125504456      52992  125484976     58      5 Kmem
    4194304     245760    3948544               3948544               Page

nsh> ps
  PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK            STACK    USED FILLED COMMAND
    0     0   0 FIFO     Kthread   - Ready              0000000000000000 0008176 0000928  11.3%  Idle_Task
    1     0 192 RR       Kthread   - Waiting  Semaphore 0000000000000000 0008112 0000992  12.2%  hpwork 0x40834568 0x408345b8
    2     0 100 RR       Kthread   - Waiting  Semaphore 0000000000000000 0008112 0000992  12.2%  lpwork 0x408344e8 0x40834538
    4     4 100 RR       Task      - Running            0000000000000000 0008128 0002192  26.9%  /system/bin/init

nsh> ls -l /dev
/dev:
 crw-rw-rw-           0 console
 crw-rw-rw-           0 null
 brw-rw-rw-    16777216 ram0
 crw-rw-rw-           0 ttyS0
 crw-rw-rw-           0 zero

nsh> hello
Hello, World!!

nsh> getprime
Set thread priority to 10
Set thread policy to SCHED_RR
Start thread #0
thread #0 started, looking for primes < 10000, doing 10 run(s)
thread #0 finished, found 1230 primes, last one was 9973
Done
getprime took 162 msec

nsh> ostest
...
Final memory usage:
VARIABLE  BEFORE   AFTER
======== ======== ========
arena        a000    26000
ordblks         2        4
mxordblk     6ff8    1aff8
uordblks     27e8     6700
fordblks     7818    1f900
user_main: Exiting
ostest_main: Exiting with status 0
nsh>
```

</span>

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/c2248e7537ca98333d47e33b232217b6)

![Upstreaming NuttX for Avaota-A1](https://lupyuen.org/images/avaota-pr.png)

# Appendix: Upstream NuttX for Avaota-A1

In this article we ported NuttX QEMU Arm64 (Kernel Build) iteratively to Avaota-A1. What's Next: Upstreaming our code to __NuttX Mainline__!

Here's how we copy-n-pasted our [__Modified Files__](https://github.com/lupyuen2/wip-nuttx/pull/99/commits) into a proper __NuttX Arch__ _(Allwinner A527)_ and __NuttX Board__ _(Avaota-A1)_

<span style="font-size:80%">

1.  [Copy qemu folders to a527. Copy qemu-armv8a folder to avaota-a1.](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/7de76c10aef43fef010eb002eae9330c4333650a)

1.  [Rename qemu files to a527. Rename qemu-armv8a files to avaota-a1.](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/740f0a0c57439fc39dc216476021fad114f6e6b2)

1.  [Rewrite "qemu-armv8a" to "avaota-a1". Rewrite "qemu" to "a527".](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/1011208093b294c36399b7a04a135c08a18b7186)

1.  [Rewrite "A527_ARMV8A" to "AVAOTA_A1"](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/ddf662a9036e7cc6742a034a3983f3b0f9b5bf07)

1.  [Add the Arch and Board](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/fe65a2d43f896b7eaeb996c463a99d5244a9b67d)

1.  [Apply the changes from _github.com/lupyuen2/wip-nuttx/pull/98/files_ <br> OSTest passes yay!](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c)

1.  [Remove the unused NuttX Configs](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/837e0478617da7d8c886cbb3291ff90e3fc07c33)

1.  [Rename knsh to nsh](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/1934b999880c37f67c0dfa456555b160a945145c)

1.  [Add the Arch and Board Docs](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/5d9b19fd314a342167948245e9cfb002d82a8802)

1.  [And Much More](https://github.com/lupyuen2/wip-nuttx/pull/99/commits)

</span>

__Upstreaming__ becomes lotsa copypasta...

1.  We create a __Staging PR__ in our own repo...

    [_github.com/lupyuen2/wip-nuttx/pull/99_](https://github.com/lupyuen2/wip-nuttx/pull/99)

1.  Dump the list of __Modified Files__...

    <span style="font-size:60%">

    ```bash
    ## Change this to our Staging PR
    $ pr=https://github.com/lupyuen2/wip-pinephone-nuttx/pull/99
    $ curl -L $pr.diff \
      | grep "diff --git" \
      | sort \
      | cut -d" " -f3 \
      | cut -c3-

    ## Here are the Modified Files for our PR
    Documentation/platforms/arm64/a527/boards/avaota-a1/avaota-a1.jpg
    Documentation/platforms/arm64/a527/boards/avaota-a1/index.rst
    Documentation/platforms/arm64/a527/index.rst
    arch/arm64/Kconfig
    arch/arm64/include/a527/chip.h
    arch/arm64/include/a527/irq.h
    arch/arm64/src/a527/CMakeLists.txt
    arch/arm64/src/a527/Kconfig
    arch/arm64/src/a527/Make.defs
    arch/arm64/src/a527/a527_boot.c
    arch/arm64/src/a527/a527_boot.h
    arch/arm64/src/a527/a527_initialize.c
    arch/arm64/src/a527/a527_lowputc.S
    arch/arm64/src/a527/a527_serial.c
    arch/arm64/src/a527/a527_textheap.c
    arch/arm64/src/a527/a527_timer.c
    arch/arm64/src/a527/chip.h
    boards/Kconfig
    boards/arm64/a527/avaota-a1/CMakeLists.txt
    boards/arm64/a527/avaota-a1/Kconfig
    boards/arm64/a527/avaota-a1/configs/nsh/defconfig
    boards/arm64/a527/avaota-a1/include/board.h
    boards/arm64/a527/avaota-a1/include/board_memorymap.h
    boards/arm64/a527/avaota-a1/scripts/Make.defs
    boards/arm64/a527/avaota-a1/scripts/gnu-elf.ld
    boards/arm64/a527/avaota-a1/scripts/ld.script
    boards/arm64/a527/avaota-a1/src/CMakeLists.txt
    boards/arm64/a527/avaota-a1/src/Makefile
    boards/arm64/a527/avaota-a1/src/a527_appinit.c
    boards/arm64/a527/avaota-a1/src/a527_boardinit.c
    boards/arm64/a527/avaota-a1/src/a527_bringup.c
    boards/arm64/a527/avaota-a1/src/a527_power.c
    boards/arm64/a527/avaota-a1/src/avaota-a1.h
    ```

    </span>

1.  Check __nxstyle__ on the Modified Files...

    <span style="font-size:60%">

    ```bash
    ## Run nxstyle on the Modified Files
    nxstyle Documentation/platforms/arm64/a527/boards/avaota-a1/avaota-a1.jpg
    nxstyle Documentation/platforms/arm64/a527/boards/avaota-a1/index.rst
    nxstyle Documentation/platforms/arm64/a527/index.rst
    nxstyle arch/arm64/Kconfig
    nxstyle arch/arm64/include/a527/chip.h
    nxstyle arch/arm64/include/a527/irq.h
    nxstyle arch/arm64/src/a527/CMakeLists.txt
    nxstyle arch/arm64/src/a527/Kconfig
    nxstyle arch/arm64/src/a527/Make.defs
    nxstyle arch/arm64/src/a527/a527_boot.c
    nxstyle arch/arm64/src/a527/a527_boot.h
    nxstyle arch/arm64/src/a527/a527_initialize.c
    nxstyle arch/arm64/src/a527/a527_lowputc.S
    nxstyle arch/arm64/src/a527/a527_serial.c
    nxstyle arch/arm64/src/a527/a527_textheap.c
    nxstyle arch/arm64/src/a527/a527_timer.c
    nxstyle arch/arm64/src/a527/chip.h
    nxstyle boards/Kconfig
    nxstyle boards/arm64/a527/avaota-a1/CMakeLists.txt
    nxstyle boards/arm64/a527/avaota-a1/Kconfig
    nxstyle boards/arm64/a527/avaota-a1/configs/nsh/defconfig
    nxstyle boards/arm64/a527/avaota-a1/include/board.h
    nxstyle boards/arm64/a527/avaota-a1/include/board_memorymap.h
    nxstyle boards/arm64/a527/avaota-a1/scripts/Make.defs
    nxstyle boards/arm64/a527/avaota-a1/scripts/gnu-elf.ld
    nxstyle boards/arm64/a527/avaota-a1/scripts/ld.script
    nxstyle boards/arm64/a527/avaota-a1/src/CMakeLists.txt
    nxstyle boards/arm64/a527/avaota-a1/src/Makefile
    nxstyle boards/arm64/a527/avaota-a1/src/a527_appinit.c
    nxstyle boards/arm64/a527/avaota-a1/src/a527_boardinit.c
    nxstyle boards/arm64/a527/avaota-a1/src/a527_bringup.c
    nxstyle boards/arm64/a527/avaota-a1/src/a527_power.c
    nxstyle boards/arm64/a527/avaota-a1/src/avaota-a1.h
    ```

    </span>

1.  Copy the Arch Files into the __Arch Pull Request__

    [__"arch/arm64/a527: Add support for Allwinner A527 SoC"__](https://github.com/lupyuen2/wip-nuttx/pull/100)

    <span style="font-size:60%">

    ```bash
    ## Download the Branch for Avaota Arch (initially empty)
    pushd /tmp 
    git clone https://github.com/lupyuen2/wip-nuttx avaota-arch --branch avaota-arch
    popd

    ## Copy the Arch Files from src to dest
    function copy_files() {
      src=.
      dest=/tmp/avaota-arch
      for file in \
        Documentation/platforms/arm64/a527/index.rst \
        arch/arm64/Kconfig \
        arch/arm64/include/a527/chip.h \
        arch/arm64/include/a527/irq.h \
        arch/arm64/src/a527/CMakeLists.txt \
        arch/arm64/src/a527/Kconfig \
        arch/arm64/src/a527/Make.defs \
        arch/arm64/src/a527/a527_boot.c \
        arch/arm64/src/a527/a527_boot.h \
        arch/arm64/src/a527/a527_initialize.c \
        arch/arm64/src/a527/a527_lowputc.S \
        arch/arm64/src/a527/a527_serial.c \
        arch/arm64/src/a527/a527_textheap.c \
        arch/arm64/src/a527/a527_timer.c \
        arch/arm64/src/a527/chip.h \

      do
        src_file=$src/$file
        dest_file=$dest/$file
        dest_dir=$(dirname -- "$dest_file")
        set -x
        mkdir -p $dest_dir
        cp $src_file $dest_file
        set +x
      done
    }

    ## Copy and commit /tmp/avaota-arch
    ## Remove the "Supported Boards" (toctree) from Arch Doc
    copy_files
    code /tmp/avaota-arch
    ```

    </span>

1.  Copy the Board Files into the __Board Pull Request__

    <span style="font-size:60%">

    ```bash
    ## Download the Branch for Avaota Board (initially empty)
    pushd /tmp 
    git clone https://github.com/lupyuen2/wip-nuttx avaota-board --branch avaota-board
    popd

    ## Copy the Board Files from src to dest
    ## Copy the Arch Doc again because we restored the "Supported Boards" 
    function copy_files() {
      src=.
      dest=/tmp/avaota-board
      for file in \
        Documentation/platforms/arm64/a527/index.rst \
        Documentation/platforms/arm64/a527/boards/avaota-a1/avaota-a1.jpg \
        Documentation/platforms/arm64/a527/boards/avaota-a1/index.rst \
        boards/Kconfig \
        boards/arm64/a527/avaota-a1/CMakeLists.txt \
        boards/arm64/a527/avaota-a1/Kconfig \
        boards/arm64/a527/avaota-a1/configs/nsh/defconfig \
        boards/arm64/a527/avaota-a1/include/board.h \
        boards/arm64/a527/avaota-a1/include/board_memorymap.h \
        boards/arm64/a527/avaota-a1/scripts/Make.defs \
        boards/arm64/a527/avaota-a1/scripts/gnu-elf.ld \
        boards/arm64/a527/avaota-a1/scripts/ld.script \
        boards/arm64/a527/avaota-a1/src/CMakeLists.txt \
        boards/arm64/a527/avaota-a1/src/Makefile \
        boards/arm64/a527/avaota-a1/src/a527_appinit.c \
        boards/arm64/a527/avaota-a1/src/a527_boardinit.c \
        boards/arm64/a527/avaota-a1/src/a527_bringup.c \
        boards/arm64/a527/avaota-a1/src/a527_power.c \
        boards/arm64/a527/avaota-a1/src/avaota-a1.h \

      do
        src_file=$src/$file
        dest_file=$dest/$file
        dest_dir=$(dirname -- "$dest_file")
        set -x
        mkdir -p $dest_dir
        cp $src_file $dest_file
        set +x
      done
    }

    ## Copy and commit /tmp/avaota-board
    copy_files
    code /tmp/avaota-board
    ```

    </span>

1.  Remember to create [__Two Commits Per PR__](https://github.com/lupyuen2/wip-nuttx/pull/100/commits): One Commit for Code, Another Commit for Docs

    ![Two Commits Per PR: One Commit for Code, Another Commit for Docs](https://lupyuen.org/images/avaota-commit.png)

1.  Need to [__Squash the Commits__](https://lupyuen.github.io/articles/pr#squash-the-commits) (or amend them), but another Code or Doc Commit is stuck in between?

    ![Before Reordering the Commit](https://lupyuen.org/images/avaota-commit2.png)

    Try [__Reordering the Commits__](https://docs.github.com/en/desktop/managing-commits/reordering-commits-in-github-desktop) to the top, before squashing or amending.

    ![After Reordering the Commit](https://lupyuen.org/images/avaota-commit3.png)

1.  Now we're finally ready to Submit our Pull Requests!

![SDWire MicroSD Multiplexer](https://lupyuen.org/images/testbot3-mux.jpg)

# Appendix: SDWire MicroSD Multiplexer

Let's make our Tweak-Build-Test Cycle quicker for NuttX. We use __SDWire MicroSD Multiplexer__ (pic above) to flip our MicroSD between __Test PC and SBC__...

- [__"SDWire MicroSD Multiplexer"__](https://lupyuen.github.io/articles/testbot3#sdwire-microsd-multiplexer)

SDWire needs [__Plenty of Sudo Passwords__](https://lupyuen.github.io/articles/testbot3#mount-the-microsd) to flip the multiplexer, mount the filesystem, copy to MicroSD. We make it Sudo Password-Less with [__visudo__](https://help.ubuntu.com/community/Sudoers)...

1.  Wrap all the __Sudo Commands__ into a script: [copy-image.sh](https://gist.github.com/lupyuen/5000c86cbdda0d5e564f244d1d87076a)

    ```bash
    ## Create a Bash Script: copy-image.sh
    ## Containing these commands...

    set -e  ## Exit when any command fails
    set -x  ## Echo commands
    whoami  ## I am root!

    ## Copy /tmp/Image to MicroSD
    sd-mux-ctrl --device-serial=sd-wire_02-09 --ts
    sleep 5
    mkdir -p /tmp/sda1
    mount /dev/sda1 /tmp/sda1
    cp /tmp/Image /tmp/sda1/
    ls -l /tmp/sda1

    ## Unmount MicroSD and flip it to the Test Device (PinePhone)
    umount /tmp/sda1
    sd-mux-ctrl --device-serial=sd-wire_02-09 --dut
    ```

1.  Configure __visudo__ so that our script will run as __Sudo Without Password__...

    ```bash
    ## Make our script executable
    ## Start the Sudoers Editor
    chmod +x /home/user/copy-image.sh
    sudo visudo

    ## Add this line:
    user ALL=(ALL) NOPASSWD: /home/user/copy-image.sh
    ```

1.  Then we can trigger our script remotely via SSH, __Without Sudo Password__: [run.sh](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

    ```bash
    ## Copy NuttX Image to MicroSD
    ## No password needed for sudo yay!
    scp Image thinkcentre:/tmp/Image
    ssh thinkcentre \
      ls -l /tmp/Image
    ssh thinkcentre \
      sudo /home/user/copy-image.sh
    ```

1.  Everything goes into our [__Build Script for NuttX__](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

![NuttX Apps Filesystem in ROMFS](https://lupyuen.org/images/avaota-initrd1.jpg)

# Appendix: NuttX Apps Filesystem

Earlier we talked about the __ROMFS Filesystem for NuttX Apps__ _(Initial RAM Disk, pic above)_

- [__"NuttX Apps Filesystem"__](https://lupyuen.github.io/articles/avaota#nuttx-apps-filesystem)

This section explains how we implemented the NuttX Apps Filesystem...

- [__Modified Files__ for NuttX Apps Filesystem](https://github.com/lupyuen2/wip-nuttx/pull/97/files)

After this implementation, _/system/bin/init_ (NSH Shell) shall [__start successfully__](https://gist.github.com/lupyuen/ccb645efa72f6793743c033fade0b3ac)...

```text
qemu_bringup:
mount_ramdisk:
nx_start_application: ret=0
nx_start_application: Starting init task: /system/bin/init
nxtask_activate: /system/bin/init pid=4,TCB=0x408469f0
nxtask_exit: AppBringUp pid=3,TCB=0x40846190
board_app_initialize:
nx_start: CPU0: Beginning Idle Loop
```

## HostFS becomes ROMFS

QEMU uses [__Semihosting and HostFS__](https://lupyuen.github.io/articles/testbot2#semihosting-breakout) to access the NuttX Apps Filesystem. We change to __ROMFS__... [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-6adf2d1a1e5d57ee68c7493a2b52c07c4e260e60d846a9ee7b8f8a6df5d8cb64)

```bash
## We added ROMFS...
CONFIG_BOARDCTL_ROMDISK=y
CONFIG_BOARD_LATE_INITIALIZE=y
CONFIG_INIT_MOUNT_TARGET="/system/bin"

## And removed Semihosting HostFS...
## CONFIG_FS_HOSTFS=y
## CONFIG_ARM64_SEMIHOSTING_HOSTFS=y
## CONFIG_ARM64_SEMIHOSTING_HOSTFS_CACHE_COHERENCE=y
## CONFIG_INIT_MOUNT_DATA="fs=../apps"
## CONFIG_INIT_MOUNT_FSTYPE="hostfs"
## CONFIG_INIT_MOUNT_SOURCE=""
## CONFIG_INIT_MOUNT_TARGET="/system"
```

_BOARD_LATE_INITIALIZE_ is needed because we'll __Mount the ROMFS Filesystem__ inside _qemu_bringup()_. (See below)

## Linker Script

We reserve __16 MB of RAM__ for the ROMFS Filesystem that will host the NuttX Apps: [ld-kernel.script](https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-f0706cd747d2f1be1eeb64d50821afb1e25d5bb26e964e2679268a83dcff0afc)

```c
/* Linker Script: We added the RAM Disk (16 MB) */
MEMORY {
  dram (rwx)    : ORIGIN = 0x40800000, LENGTH = 2M
  pgram (rwx)   : ORIGIN = 0x40A00000, LENGTH = 4M    /* w/ cache */
  ramdisk (rwx) : ORIGIN = 0x40E00000, LENGTH = 16M   /* w/ cache */
}

/* We'll reference these in our code */
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size  = LENGTH(ramdisk);
__ramdisk_end   = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

## Mount the ROMFS

__At Startup:__ We mount the __ROMFS Filesystem__ _(inside RAM)_ as _/dev/ram0_: [qemu_bringup.c](https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-f8d388b76b0b37563184a5a174f18970ff6771d6a048e0e792967ab265d6f7eb)

```c
// At NuttX Startup...
int qemu_bringup(void) {
  // We Mount the RAM Disk
  mount_ramdisk();
  ...
}

// Mount a RAM Disk defined in ld.script to /dev/ramX.  The RAM Disk
// contains a ROMFS filesystem with applications that can be spawned at
// runtime.
static int mount_ramdisk(void) {
  struct boardioc_romdisk_s desc;
  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;

  int ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
  if (ret < 0) {
    syslog(LOG_ERR, "Ramdisk register failed: %s\n", strerror(errno));
    syslog(LOG_ERR, "Ramdisk mountpoint /dev/ram%d\n",RAMDISK_DEVICE_MINOR);
    syslog(LOG_ERR, "Ramdisk length %lu, origin %lx\n", (ssize_t)__ramdisk_size, (uintptr_t)__ramdisk_start);
  }
  return ret;
}

// RAM Disk Definition
#define SECTORSIZE   512
#define NSECTORS(b)  (((b) + SECTORSIZE - 1) / SECTORSIZE)
#define RAMDISK_DEVICE_MINOR 0
```

## Copy the ROMFS

__But Before That:__ We safely copy the __ROMFS Filesystem__ _(Initial RAM Disk)_ from the NuttX Image into the __`ramdisk` Memory Region__...

![Mounting the ROMFS Filesystem](https://lupyuen.org/images/avaota-initrd2.jpg)

This happens just after Bootloader starts NuttX: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-be208bc5be54608eca3885cf169183ede375400c559700bb423c81d7b2787431)

```c
// Needed for the `aligned_data` macro
#include <nuttx/compiler.h>

// Just after Bootloader has started NuttX...
void arm64_chip_boot(void) {

  // We copy the RAM Disk
  qemu_copy_ramdisk();

  // Omitted: Other initialisation (MMU, ...)
  arm64_mmu_init(true);
  ...
}

// Copy the RAM Disk from NuttX Image to RAM Disk Region.
static void qemu_copy_ramdisk(void) {
  const uint8_t aligned_data(8) header[8] = "-rom1fs-";
  const uint8_t *limit = (uint8_t *)g_idle_topstack + (256 * 1024);
  uint8_t *ramdisk_addr = NULL;
  uint8_t *addr;
  uint32_t size;

  // After Idle Stack Top, search for "-rom1fs-". This is the RAM Disk Address.
  // Limit search to 256 KB after Idle Stack Top.
  for (addr = g_idle_topstack; addr < limit; addr += 8) {
      if (memcmp(addr, header, sizeof(header)) == 0) {
        ramdisk_addr = addr;
        break;
      }
  }

  // Stop if RAM Disk is missing
  if (ramdisk_addr == NULL) {
    _err("Missing RAM Disk. Check the initrd padding.");
    PANIC();
  }

  // Read the Filesystem Size from the next 4 bytes (Big Endian)
  size = (ramdisk_addr[8] << 24) + (ramdisk_addr[9] << 16) +
         (ramdisk_addr[10] << 8) + ramdisk_addr[11] + 0x1f0;

  // Filesystem Size must be less than RAM Disk Memory Region
  if (size > (size_t)__ramdisk_size) {
    _err("RAM Disk Region too small. Increase by %lu bytes.\n", size - (size_t)__ramdisk_size);
    PANIC();
  }

  // Copy the RAM Disk from NuttX Image to RAM Disk Region.
  // __ramdisk_start overlaps with ramdisk_addr + size.
  qemu_copy_overlap(__ramdisk_start, ramdisk_addr, size);
}

// Copy an overlapping memory region.  dest overlaps with src + count.
static void qemu_copy_overlap(uint8_t *dest, const uint8_t *src, size_t count) {
  uint8_t *d = dest + count - 1;
  const uint8_t *s = src + count - 1;
  if (dest <= src) { _err("dest and src should overlap"); PANIC(); }
  while (count--) {
    volatile uint8_t c = *s;  // Prevent compiler optimization
    *d = c;
    d--;
    s--;
  }
} 

// RAM Disk Region is defined in Linker Script
extern uint8_t __ramdisk_start[];
extern uint8_t __ramdisk_size[];
```

[(Moved here)](https://github.com/lupyuen2/wip-nuttx/blob/71b0ea678c08d9d1390e4d669876f99d93496ecf/arch/arm64/src/a527/a527_boot.c#L69-L170)

_Why the aligned addresses?_

```c
// Header is aligned to 8 bytes
const uint8_t
  aligned_data(8) header[8] =
  "-rom1fs-";

// Address is also aligned to 8 bytes
for (
  addr = g_idle_topstack;
  addr < limit;
  addr += 8
) {
  // Otherwise this will hit Alignment Fault
  memcmp(addr, header, sizeof(header));
  ...
}
```

We align our Memory Accesses to __8 Bytes__. Otherwise we'll hit an [__Alignment Fault__](https://gist.github.com/lupyuen/f10af7903461f44689203d0e02fb9949)...

```bash
## Alignment Fault at `memcmp(addr, header, sizeof(header))`
default_fatal_handler:
  (IFSC/DFSC) for Data/Instruction aborts:
  alignment fault
```

[_(Strangely: This Alignment isn't needed for RISC-V)_](https://github.com/lupyuen2/wip-nuttx/blob/b92f051e337d095491f8406b2d99fdd2f6fa5b3e/arch/risc-v/src/eic7700x/eic7700x_start.c#L110-L144)

![Porting NuttX to Avaota-A1](https://lupyuen.org/images/avaota-pr2.png)

# Appendix: Port NuttX to Avaota-A1

In this article, we took NuttX for __Arm64 QEMU knsh (Kernel Build)__ and changed it slightly for __Avaota-A1 SBC__. To help our PR Reviewers: This section explains the __Modified Code__ in our Pull Request...

- [__Modified Files__ for Avaota-A1](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c)

__Only Seven Files__ were modified from QEMU NuttX. All other files were simply copied and renamed, from QEMU NuttX to Avaota-A1. (Pic above)

## Memory Map

[_arch/arm64/include/a527/chip.h_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-90c2e9d244c0b30507a1c22d2374875c4672d39fe84e280f4a73c4935eede8fe)

We define the __I/O Memory Space__...

```c
// I/O Memory Space
#define CONFIG_DEVICEIO_BASEADDR   0x00000000
#define CONFIG_DEVICEIO_SIZE       MB(1024)

// Kernel Boot Address from SBC Bootloader
#define CONFIG_LOAD_BASE           0x40800000
```

Based on the __A527 Memory Map__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 40 |
|:--------------------------------|:---------|
| __Module__ | __Address__
| Boot ROM & SRAM | _0x0000_0000_ to ...
| PCIE | _0x2000_0000_ to _0x2FFF_FFFF_
| DRAM | _0x4000_0000_ to ...

</div>
</p>

[(Explained here)](https://lupyuen.github.io/articles/avaota#fix-the-memory-map)

## GIC Interrupt Controller

[_arch/arm64/include/a527/chip.h_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-90c2e9d244c0b30507a1c22d2374875c4672d39fe84e280f4a73c4935eede8fe)

We set the __GIC Base Addresses__...

```c
// GICD and GICD Base Addresses
#define CONFIG_GICD_BASE           0x3400000
#define CONFIG_GICR_BASE           0x3460000
```

Based on the __GIC Doc__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 263 |
|:-------------------------------:|:---------|
| __Module__ | __Base Address__
| GIC | _0x0340_0000_

</div>
</p>

And __GIC Registers__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 263 |
|:-------------------------------:|:---------|
| __Offset__ | __Register__
| _0x00_0000_ | GICD_CTLR  _(Distributor Control Register)_
| _0x06_0000_ | GICR_CTLR_C0  _(Redistributor Control Register, Core 0)_
| _0x08_0000_ | GICR_CTLR_C1  _(Ditto, Core 1)_
| _0x0A_0000_ | GICR_CTLR_C2  _(Ditto, Core 2)_
| _0x0C_0000_ | GICR_CTLR_C3  _(Ditto, Core 3)_
| _0x0E_0000_ | GICR_CTLR_C4  _(Ditto, Core 4)_
| _0x10_0000_ | GICR_CTLR_C5  _(Ditto, Core 5)_
| _0x12_0000_ | GICR_CTLR_C6  _(Ditto, Core 6)_
| _0x14_0000_ | GICR_CTLR_C7  _(Ditto, Core 7)_
| _0x16_0000_ | GICDA_CTLR  _(Distributor Control Register A)_

</div>
</p>

[(Explained here)](https://lupyuen.github.io/articles/avaota#arm64-generic-interrupt-controller)

<hr>

[_boards/arm64/a527/avaota-a1/configs/nsh/defconfig_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-89d849e89568645806e7cde6f80877786891ed21659d281b9413db67e6eff0c1)

We set the __UART0 Interrupt__...

```bash
## Set the UART0 Interrupt to 34
CONFIG_16550_UART0_IRQ=34
```

Based on the A527 Doc...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 256 |
|:-------------------------------:|:--------:|
| __Interrupt Number__ | __Interrupt Source__
| 34 | UART0

</div>
</p>

[(Explained here)](https://lupyuen.github.io/articles/avaota#fix-the-uart-interrupt)

## Arm64 Boot Code

[_arch/arm64/src/a527/a527_lowputc.S_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-faa554bbda31c1c014a2df5f83ab406dd9e57d39fff982ce45fdb627f63e468d)

We updated the Arm64 Boot Code for __16550 UART Driver__...

1.  We modified the __UART Base Address__...

    ```c
    // Base Address for 16550 UART
    #define UART0_BASE_ADDRESS 0x02500000
    ```

1.  QEMU was using PL011 UART. We fixed this for 16550 UART, to __Wait for UART Ready__ [(derived from NuttX A64)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L62-L74)

    ```c
    /* Wait for 16550 UART to be ready to transmit
    * xb: Register that contains the UART Base Address
    * wt: Scratch register number */
    .macro early_uart_ready xb, wt
    1:
      ldrh  \wt, [\xb, #0x14] /* UART_LSR (Line Status Register) */
      tst   \wt, #0x20        /* Check THRE (TX Holding Register Empty) */
      b.eq  1b                /* Wait for the UART to be ready (THRE=1) */
    .endm
    ```

__UART Base Address__ came from the A527 Doc...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 1839 |
|:-------------------------------:|:---------|
| __Module__ | __Base Address__
| UART0 | _0x0250\_0000_

</div>
</p>

With these __UART Registers__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 1839 |
|:-------------------------------:|:---------|
| __Offset__ | __Register__
| _0x0000_ | UART_THR _(Transmit Holding Register)_
| _0x0004_ | UART_DLH _(Divisor Latch High Register)_
| _0x0008_ | UART_IIR _(Interrupt Identity Register)_
| _0x000C_ | UART_LCR _(Line Control)_

</div>
</p>

[(Explained here)](https://lupyuen.github.io/articles/avaota#print-to-uart-in-arm64-assembly)

![Mounting the ROMFS Filesystem containing the NuttX Apps](https://lupyuen.org/images/avaota-initrd2.jpg)

## NuttX Start Code

[_arch/arm64/src/a527/a527_boot.c_](https://github.com/lupyuen2/wip-nuttx/blob/71b0ea678c08d9d1390e4d669876f99d93496ecf/arch/arm64/src/a527/a527_boot.c#L69-L170)

__At NuttX Startup:__ We mount the __ROMFS Filesystem__ _(Initial RAM Disk, pic above)_ containing the __NuttX Apps__...

- [__"NuttX Apps Filesystem"__](https://lupyuen.github.io/articles/avaota#appendix-nuttx-apps-filesystem)

How? We safely copy the __ROMFS Filesystem__ from the NuttX Image into the __`ramdisk` Memory Region__. This code comes from [__NuttX EIC7700X__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/eic7700x/eic7700x_start.c#L72-L183)...

```c
// Needed for the `aligned_data` macro
#include <nuttx/compiler.h>

// Just after Bootloader has started NuttX...
void arm64_chip_boot(void) {

  // We copy the RAM Disk
  qemu_copy_ramdisk();

  // Omitted: Other initialisation (MMU, ...)
  arm64_mmu_init(true);
  ...
}

// Copy the RAM Disk from NuttX Image to RAM Disk Region.
static void a527_copy_ramdisk(void) {
  const uint8_t aligned_data(8) header[8] = "-rom1fs-";
  const uint8_t *limit = (uint8_t *)g_idle_topstack + (256 * 1024);
  uint8_t *ramdisk_addr = NULL;
  uint8_t *addr;
  uint32_t size;

  // After Idle Stack Top, search for "-rom1fs-". This is the RAM Disk Address.
  // Limit search to 256 KB after Idle Stack Top.
  for (addr = g_idle_topstack; addr < limit; addr += 8) {
      if (memcmp(addr, header, sizeof(header)) == 0) {
        ramdisk_addr = addr;
        break;
      }
  }

  // Stop if RAM Disk is missing
  if (ramdisk_addr == NULL) {
    _err("Missing RAM Disk. Check the initrd padding.");
    PANIC();
  }

  // Read the Filesystem Size from the next 4 bytes (Big Endian)
  size = (ramdisk_addr[8] << 24) + (ramdisk_addr[9] << 16) +
         (ramdisk_addr[10] << 8) + ramdisk_addr[11] + 0x1f0;

  // Filesystem Size must be less than RAM Disk Memory Region
  if (size > (size_t)__ramdisk_size) {
    _err("RAM Disk Region too small. Increase by %lu bytes.\n", size - (size_t)__ramdisk_size);
    PANIC();
  }

  // Copy the RAM Disk from NuttX Image to RAM Disk Region.
  // __ramdisk_start overlaps with ramdisk_addr + size.
  a527_copy_overlap(__ramdisk_start, ramdisk_addr, size);
}

// Copy an overlapping memory region.  dest overlaps with src + count.
static void a527_copy_overlap(uint8_t *dest, const uint8_t *src, size_t count) {
  uint8_t *d = dest + count - 1;
  const uint8_t *s = src + count - 1;
  if (dest <= src) { _err("dest and src should overlap"); PANIC(); }
  while (count--) {
    volatile uint8_t c = *s;  // Prevent compiler optimization
    *d = c;
    d--;
    s--;
  }
} 

// RAM Disk Region is defined in Linker Script
extern uint8_t __ramdisk_start[];
extern uint8_t __ramdisk_size[];
```

[(Previously here)](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-29f9a5b9711e05525c0f249e0b9096a1e613bbde5783436f448a21b36ced2de0)

_Why the aligned addresses?_

```c
// Header is aligned to 8 bytes
const uint8_t
  aligned_data(8) header[8] =
  "-rom1fs-";

// Address is also aligned to 8 bytes
for (
  addr = g_idle_topstack;
  addr < limit;
  addr += 8
) {
  // Otherwise this will hit Alignment Fault
  memcmp(addr, header, sizeof(header));
  ...
}
```

We align our Memory Accesses to __8 Bytes__. Otherwise we'll hit an [__Alignment Fault__](https://gist.github.com/lupyuen/f10af7903461f44689203d0e02fb9949)...

```bash
## Alignment Fault at `memcmp(addr, header, sizeof(header))`
default_fatal_handler:
  (IFSC/DFSC) for Data/Instruction aborts:
  alignment fault
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#appendix-nuttx-apps-filesystem)

## Board Bringup Code

[_boards/arm64/a527/avaota-a1/src/a527_bringup.c_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-5c21dc796c75ebe2ddd15175015333e013d3966e6e779432eda183363ae1d7b2)

__At Board Startup:__ We mount the __ROMFS Filesystem__ _(inside RAM)_ as _/dev/ram0_...

```c
// At NuttX Startup...
int a527_bringup(void) {
  // We Mount the RAM Disk
  mount_ramdisk();
  ...
}

// Mount a RAM Disk defined in ld.script to /dev/ramX.  The RAM Disk
// contains a ROMFS filesystem with applications that can be spawned at
// runtime.
static int mount_ramdisk(void) {
  struct boardioc_romdisk_s desc;
  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;

  int ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
  if (ret < 0) {
    syslog(LOG_ERR, "Ramdisk register failed: %s\n", strerror(errno));
    syslog(LOG_ERR, "Ramdisk mountpoint /dev/ram%d\n",RAMDISK_DEVICE_MINOR);
    syslog(LOG_ERR, "Ramdisk length %lu, origin %lx\n", (ssize_t)__ramdisk_size, (uintptr_t)__ramdisk_start);
  }
  return ret;
}

// RAM Disk Definition
#define SECTORSIZE   512
#define NSECTORS(b)  (((b) + SECTORSIZE - 1) / SECTORSIZE)
#define RAMDISK_DEVICE_MINOR 0
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#mount-the-romfs)

## Linker Script

[_boards/arm64/a527/avaota-a1/scripts/ld.script_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-239ddf89006a4d4e2858b9f3c4fa8165245fd7d21ed0a33a971c70c4deaf9d4a)

We reserve __16 MB of RAM__ for the ROMFS Filesystem that will host the NuttX Apps...

```c
/* Linker Script: We moved the Paged Pool and added the RAM Disk (16 MB) */
MEMORY {
  /* Previously: QEMU boots at 0x4028_0000 */
  dram (rwx)  : ORIGIN = 0x40800000, LENGTH = 2M

  /* Previously: QEMU Paged Memory is at 0x4028_0000 */
  /* Why? Because 0x4080_0000 + 2 MB = 0x40A0_0000   */
  pgram (rwx) : ORIGIN = 0x40A00000, LENGTH = 4M   /* w/ cache */

  /* Added the RAM Disk */
  ramdisk (rwx) : ORIGIN = 0x40E00000, LENGTH = 16M   /* w/ cache */
}

/* We'll reference these in our code */
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size  = LENGTH(ramdisk);
__ramdisk_end   = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

Also we moved the __Paged Pool__ because the Boot Address has changed to _0x4080_0000_.

[(Explained here)](https://lupyuen.github.io/articles/avaota#linker-script)

## NuttX Config

[_boards/arm64/a527/avaota-a1/configs/nsh/defconfig_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-89d849e89568645806e7cde6f80877786891ed21659d281b9413db67e6eff0c1)

Since we changed the __Paged Memory Pool__ _(pgram)_, we update _ARCH_PGPOOL_PBASE_ and _VBASE_: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/eb33ac06f88dda557bc8ac97bec7d6cbad4ccb86)

```bash
## Physical Address of Paged Memory Pool
## Previously: QEMU Paged Memory is at 0x4028_0000
CONFIG_ARCH_PGPOOL_PBASE=0x40A00000

## Virtual Address of Paged Memory Pool
## Previously: QEMU Paged Memory is at 0x4028_0000
CONFIG_ARCH_PGPOOL_VBASE=0x40A00000
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#set-the-start-address)

NuttX QEMU declares the [__RAM Size as 128 MB__](https://github.com/lupyuen2/wip-nuttx/commit/005900ef7e1a1480b8df975d0dcd190fbfc60a45) in _RAMBANK1_SIZE_. We set _RAM_SIZE_ accordingly...

```bash
## RAM Size is 128 MB
CONFIG_RAM_SIZE=134217728
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#set-the-start-address)

Based on the __16550 UART Registers__ above: We configured the 16550 UART and removed PL011 UART...

```bash
CONFIG_16550_ADDRWIDTH=0
CONFIG_16550_REGINCR=4
CONFIG_16550_UART0=y
CONFIG_16550_UART0_BASE=0x02500000
CONFIG_16550_UART0_CLOCK=23040000
CONFIG_16550_UART0_IRQ=125
CONFIG_16550_UART0_SERIAL_CONSOLE=y
CONFIG_16550_UART=y
CONFIG_16550_WAIT_LCR=y
CONFIG_SERIAL_UART_ARCH_MMIO=y
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#uart-driver-for-16550)

__16550_UART0_CLOCK__ was computed according to [__these instructions__](https://lupyuen.github.io/articles/release#appendix-uart-clock-for-jh7110)...

```bash
NuttX UART Debug Log shows:
  dlm = 0x00
  dll = 0x0D

We know that:
  dlm = 0x00 = (div >> 8)
  dll = 0x0D = (div & 0xFF)

Which means:
  div = 0x0D

We know that:
  baud = 115200
  div  = (uartclk + (baud << 3)) / (baud << 4)

Therefore:
  0x0D    = (uartclk + 921600) / 1843200
  uartclk = (0x0D * 1843200) - 921600
          = 23040000
```

<hr>

[_arch/arm64/src/a527/a527_serial.c_](https://github.com/lupyuen2/wip-nuttx/pull/99/commits/61d055d5040e6aee8d99507b00dbfb5b47c6cd3c#diff-7a8c921d26a5ea6904550ec7769d456e91598786ed4f7aacfed2642f53227dc6)

QEMU was using PL011 UART. We switched the Serial Driver to __16550 UART__...

```c
// Switch from PL011 UART (QEMU) to 16550 UART
#include <nuttx/serial/uart_16550.h>

// Enable the 16550 Console UART at Startup
void arm64_earlyserialinit(void) {
  // Previously for QEMU: pl011_earlyserialinit
  u16550_earlyserialinit();
}

// Ditto but not so early
void arm64_serialinit(void) {
  // Previous for QEMU: pl011_serialinit
  u16550_serialinit();
}
```

[(Explained here)](https://lupyuen.github.io/articles/avaota#uart-driver-for-16550)
