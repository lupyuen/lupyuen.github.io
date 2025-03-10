# Porting Apache NuttX RTOS to Avaota-A1 SBC (Allwinner A527 SoC)

📝 _9 Apr 2025_

![Avaota-A1 SBC with SDWire MicroSD Multiplexer and Smart Power Plug](https://lupyuen.org/images/avaota-title.jpg)

<span style="font-size:80%">

[_(Watch the Demo on YouTube)_](https://youtu.be/PxaMcmMAzlM)

</span>

TODO

_Why are we doing this?_

- Anyone porting NuttX from __QEMU to Real SBC__? This walkthrough shall be mighty helpful!

TI ported NuttX to a simpler A527 board, the Avaota-A1 SBC by PINE64 ($55): https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/

Avaota-A1 SBC is Open Source Hardware (CERN OHL Licensed). PINE64 sells it today, maybe we'll see more manufacturers with the same design: https://github.com/AvaotaSBC/Avaota-A1

I think NuttX on Avaota-A1 (Allwinner A527) will be super interesting because:

(1) It's one of the first ports of Arm64 in NuttX Kernel Build (NXP i.MX93 might be another?)

(2) We'll run it as PR Test Bot for Validating Arm64 PRs

(3) PR Test Bot will be fully automated thanks to SDWire MicroSD Mux: https://lupyuen.org/articles/testbot3.html

Next article I'll explain how I ported NuttX from QEMU Arm64 (knsh) to Avaota-A1, completed within 24 hours.

Octa-Core CPU

Here's the story 

Build NuttX for 
Port NuttX to 

Schematic: https://github.com/AvaotaSBC/Avaota-A1/blob/master/hardware/v1.4/01_SCH/SCH_Avaota%20Pi%20A_2024-05-20.pdf

# Boot Linux on our SBC

Nifty Trick for Booting NuttX on __Any Arm64 SBC__ (RISC-V too)

- __Arm64 Bootloader__ _(U-Boot / SyterKit)_ will boot Linux by loading the __`Image`__ file

  _(Containing the Linux Kernel)_

- Thus we __"Hijack" the `Image` File__, replace it by __NuttX Kernel__

- Which means __NuttX Kernel__ shall look and feel like a __Linux Kernel__

- That's why we have a [__Linux Kernel Header__](TODO) at the top of NuttX

To begin, we observe our SBC and its _Natural Behaviour_: How does it __Boot Linux?__

TODO: Download

TODO: MicroSD

TODO: Load Address

TODO: LCD Screen too

Download the [__Latest AvaotaOS Release__](https://github.com/AvaotaSBC/AvaotaOS/releases) _(Ubuntu Noble GNOME)_ and uncompress it...

```bash
wget https://github.com/AvaotaSBC/AvaotaOS/releases/download/0.3.0.4/AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
xz -d AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
```

Write the __`.img`__ file to a MicroSD with [__Balena Etcher__](https://etcher.balena.io/).

We'll overwrite the `Image` file by `nuttx.bin`...

# NuttX Kernel Build for Arm64 QEMU

Follow these steps to Build and Run NuttX for [__Arm64 QEMU (Kernel Build)__](TODO)

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
TODO
```

TODO: Why Kernel Build

# Boot NuttX Kernel on our SBC

TODO: Kernel Only, no apps

TODO: 28 MB Linux Kernel

[Build Log](https://gist.github.com/lupyuen/6c0607daa0a8f37bda37cc80e76259ee)

```bash
$ ls -l /TODO
total 40261
-rwxr-xr-x 1 root root    78769 Feb 22 01:06 bl31.bin
-rwxr-xr-x 1 root root   180233 Feb 21 22:21 config-5.15.154-ga464bc4feaff
drwxr-xr-x 3 root root      512 Feb 21 22:56 dtb
drwxr-xr-x 2 root root      512 Feb 22 01:06 extlinux
-rwxr-xr-x 1 root root 27783176 Mar  7 21:24 Image
-rwxr-xr-x 1 root root   180228 Feb 22 01:06 scp.bin
-rwxr-xr-x 1 root root    12960 Feb 22 01:06 splash.bin
-rwxr-xr-x 1 root root  5193581 Feb 21 22:21 System.map-5.15.154-ga464bc4feaff
-rwxr-xr-x 1 root root  6497300 Feb 22 01:06 uInitrd
```

TODO: We'll overwrite the `Image` file by `nuttx.bin`...

```bash
mv /TODO/Image /TODO/Image.old
cp nuttx.bin /TODO/Image
ls -l /TODO/Image
## Should be a lot smaller
umount /TODO
```

Nothing happens. We do some logging...

# Print to UART in Arm64 Assembly

_Is NuttX actually booting?_

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

But let's do it in __Arm64 Assembly__: [arm64_head.S](https://github.com/lupyuen2/wip-nuttx/commit/be2f1c55aa24eda9cd8652aa0bf38251335e9d01)

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

Rebuild NuttX and recopy __`nuttx.bin`__ to MicroSD, overwriting the __`Image`__ file. NuttX boot and [__prints `123` yay__](https://gist.github.com/lupyuen/14188c44049a14e3581523c593fdf2d8)!

```bash
read /Image addr=40800000
Kernel addr: 0x40800000
BL31: v2.5(debug):9241004a9
sunxi-arisc driver is starting
ERROR: Error initializing runtime service opteed_fast
123
```

(Ignore the _opteed_fast_ error)

_Why print in Arm64 Assembly? Why not C?_

1.  Arm64 Assembly is the __very first thing that boots__ when Bootloader starts NuttX

1.  This happens __before anything complicated__ begins: UART Driver, Memory Management Unit, Task Scheduler, ...

1.  The Arm64 Assembly above is __Address-Independent Code__: It will execute at Any Arm64 Address

Next we move our code and make it Address-Dependent...

# Set the Start Address

_NuttX boots a tiny bit on our SBC. Where's the rest?_

Our SBC boots NuttX at a different address from QEMU. We fix the __Start Address__ inside NuttX...

```bash
read /Image addr=40800000
Kernel addr: 0x40800000
123
```

1.  Remember the [__Boot Log__](TODO) from earlier? It says that the [__SyterKit Bootloader__](https://github.com/YuzukiHD/SyterKit) starts NuttX at __Address `0x4080_0000`__. We fix it here: [ld-kernel.script](https://github.com/lupyuen2/wip-nuttx/commit/c38e1f7c014e1af648a33847fc795930ba995bca)

    ```c
    MEMORY {
      /* Previously: QEMU boots at 0x4028_0000 */
      dram (rwx)  : ORIGIN = 0x40800000, LENGTH = 2M

      /* Previously: QEMU Paged Memory is at 0x4028_0000 */
      pgram (rwx) : ORIGIN = 0x40A00000, LENGTH = 4M   /* w/ cache */
    }
    ```

1.  Since we changed the __Paged Memory Pool__ _(pgram)_, we update _CONFIG_ARCH_PGPOOL_PBASE_ and _CONFIG_ARCH_PGPOOL_VBASE_ too: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/eb33ac06f88dda557bc8ac97bec7d6cbad4ccb86)

    ```bash
    ## Physical Address of Paged Memory Pool
    ## Previously: QEMU Paged Memory is at 0x4028_0000
    CONFIG_ARCH_PGPOOL_PBASE=0x40A00000

    ## Virtual Address of Paged Memory Pool
    ## Previously: QEMU Paged Memory is at 0x4028_0000
    CONFIG_ARCH_PGPOOL_VBASE=0x40A00000
    ```

1.  NuttX QEMU declares the [__RAM Size as 128 MB__](https://github.com/lupyuen2/wip-nuttx/commit/005900ef7e1a1480b8df975d0dcd190fbfc60a45) _(CONFIG_RAMBANK1_SIZE)_. We set _CONFIG_RAM_SIZE_ to match _CONFIG_RAMBANK1_SIZE_: [configs/knsh/defconfig](https://github.com/lupyuen2/wip-nuttx/commit/c8fbc5b86c2bf1dd7b8243b301b0790115c9c4ca)

    ```bash
    ## RAM Size is a paltry 128 MB
    CONFIG_RAM_SIZE=134217728
    ```

    _(Kinda tiny, but sufficient)_

1.  __Linux Kernel Header__ needs patching. We set the __Image Load Offset__ to _0x80\_0000_: [arm64_head.S](https://github.com/lupyuen2/wip-nuttx/commit/be2f1c55aa24eda9cd8652aa0bf38251335e9d01)

    ```c
    /* Bootloader starts NuttX here, followed by Linux Kernel Header */
    __start:
      ...
      /* Image Load Offset from Start of RAM          */
      /* Previously: QEMU set this to 0x480000 (why?) */
      .quad 0x800000
    ```

That's because...

- [__Start of RAM__](https://github.com/lupyuen2/wip-nuttx/blob/avaota/boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig#L85) is _0x4000\_0000_

  ```bash
  CONFIG_RAM_START=0x40000000
  ```

- Bootloader starts NuttX at _0x4080\_0000_

- Subtract the above to get __Image Load Offset__: _0x80\_0000_

With these fixes, our C Code in NuttX shall boot correctly.

TODO: LCD also

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
  arm64_enable_mte();    // TODO

  *(volatile uint8_t *) 0x02500000 = 'D';
  qemu_board_initialize();  // Init the Board

  *(volatile uint8_t *) 0x02500000 = 'E';
  arm64_earlyserialinit();  // Init the Serial Driver

  *(volatile uint8_t *) 0x02500000 = 'F';
  syslog_rpmsg_init_early(...);  // Init the System Logger

  *(volatile uint8_t *) 0x02500000 = 'G';
  up_perf_init(..);  // Init the Performance Counters
```

Beyond Big Bird: We need the __16550 UART Driver__...

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

    [_(Thanks to PinePhone)_](TODO)

1.  QEMU uses PL011 UART. We switch to __16550 UART__: [qemu_serial.c](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-aefbee7ddc3221be7383185346b81cff77d382eb6f308ecdccb44466d0437108)

    ```c
    // Switch from PL011 UART (QEMU) to 16550 UART
    #include <nuttx/serial/uart_16550.h>

    // Enable the 16550 Console UART at Startup
    void arm64_earlyserialinit(void) {
      // Previously for QEMU: pl011_earlyserialinit
      u16550_earlyserialinit();
    }

    // TODO
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

1.  __16550_UART0_CLOCK__ isn't quite correct, we'll [__fix it later__](TODO). Meanwhile we disable the __UART Clock Configuration__: [uart_16550.c](https://github.com/lupyuen2/wip-nuttx/commit/0cde58d84c16f255cb12e5a647ebeee3b6a8dd5f#diff-f208234edbfb636de240a0fef1c85f9cecb37876d5bc91ffb759f70a1e96b1d1)

    ```c
    // We disable the UART Clock Configuration...
    static int u16550_setup(FAR struct uart_dev_s *dev) { ...
    #ifdef TODO  // We'll fix it later
      // Enter DLAB=1
      u16550_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));

      // Omitted: Set the UART Baud Divisor
      // ...

      // Clear DLAB
      u16550_serialout(priv, UART_LCR_OFFSET, lcr);
    #endif
    ```

Same old drill: Rebuild, recopy and reboot NuttX. We see plenty more [__debug output yay__](https://gist.github.com/lupyuen/563ed00d3f6e9f7fb9b27268d4eae26b)!

```bash
123
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
AB
```

OK the repeated rebuilding, recopying and rebooting of NuttX is getting really tiresome. Let's automate...

# Build NuttX for Avaota-A1

_What if we could rebuild-recopy-reboot NuttX... In One Single Script?_

[(Watch the __Demo on YouTube__)](https://youtu.be/PxaMcmMAzlM)

Well thankfully we have a __MicroSD Multiplexer__ that will make MicroSD Swapping a lot easier! (Not forgetting our [__Smart Power Plug__](https://lupyuen.github.io/articles/testbot#power-up-our-oz64-sbc))

Our Avaota-A1 SBC is connected to SDWire MicroSD Multiplexer and Smart Power Plug (pic above). So our Build Script will do __everything__ for us:

- Copy NuttX to MicroSD

- Swap MicroSD from our Test PC to SBC

- Power up SBC and boot NuttX!

See the Build Script:
- https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587

```bash
## Build NuttX and Apps (NuttX Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch avaota
git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch avaota
cd nuttx
tools/configure.sh qemu-armv8a:knsh
make -j
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Generate the Initial RAM Disk
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.pad

## Append Padding and Initial RAM Disk to the NuttX Kernel
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image

## Get the Home Assistant Token, copied from http://localhost:8123/profile/security
## token=xxxx
set +x  ##  Disable echo
. $HOME/home-assistant-token.sh
set -x  ##  Enable echo

set +x  ##  Disable echo
echo "----- Power Off the SBC"
curl \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "automation.starpro64_power_off"}' \
    http://localhost:8123/api/services/automation/trigger
set -x  ##  Enable echo

## Copy NuttX Image to MicroSD
## No password needed for sudo, see below
scp Image thinkcentre:/tmp/Image
ssh thinkcentre ls -l /tmp/Image
ssh thinkcentre sudo /home/user/copy-image.sh

set +x  ##  Disable echo
echo "----- Power On the SBC"
curl \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "automation.starpro64_power_on"}' \
    http://localhost:8123/api/services/automation/trigger
set -x  ##  Enable echo

## Wait for SBC to finish booting
sleep 30

set +x  ##  Disable echo
echo "----- Power Off the SBC"
curl \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "automation.starpro64_power_off"}' \
    http://localhost:8123/api/services/automation/trigger
set -x  ##  Enable echo
```

[(See the __Build Log__)](https://gist.github.com/lupyuen/6c0607daa0a8f37bda37cc80e76259ee)

(__copy-image.sh__ is explained below)

# Passwordless Sudo

Let's make our Build-Test Cycle quicker. We do Passwordless Sudo for flipping our SDWire Mux

SDWire Mux needs plenty of Sudo Passwords to flip the mux, mount the filesystem, copy to MicroSD.

Let's make it Sudo Password-Less with visudo: https://help.ubuntu.com/community/Sudoers

```bash
## Start the Sudoers Editor
sudo visudo

## Add this line:
user ALL=(ALL) NOPASSWD: /home/user/copy-image.sh
```

Edit /home/user/copy-image.sh...

```bash
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

## Unmount MicroSD and flip it to the Test Device (Avaota-A1 SBC)
umount /tmp/sda1
sd-mux-ctrl --device-serial=sd-wire_02-09 --dut
```

(Remember to `chmod +x /home/user/copy-image.sh`)

Now we can run copy-image.sh without a password yay!

```bash
## Sudo will NOT prompt for password yay!
sudo /home/user/copy-image.sh

## Also works over SSH: Copy NuttX Image to MicroSD
## No password needed for sudo yay!
scp nuttx.bin thinkcentre:/tmp/Image
ssh thinkcentre ls -l /tmp/Image
ssh thinkcentre sudo /home/user/copy-image.sh
```

[(See the __Build Script__)](https://gist.github.com/lupyuen/a4ac110fb8610a976c0ce2621cbb8587)

# Arm64 Memory Management Unit

Earlier we saw NuttX [__stuck at "`AB`"__](TODO)...

```bash
123
- Ready to Boot Primary CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
AB
```

Which says that NuttX is stuck inside __arm64_mmu_init__: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/commit/029056c7e0da092e4d3a211b5f5b22b7014ba333)

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
  arm64_enable_mte();    // TODO
```

_What's arm64_mmu_init?_

NuttX calls __arm64_mmu_init__ to initialise the Arm64 __Memory Management Unit (MMU)__. We add some logs inside: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/pull/96/files#diff-230f2ffd9be0a8ce48d4c9fb79df8f003b0c31fa0a18b6c0876ede5b4e334bb9)

```c
// Enable debugging for MMU.
#define CONFIG_MMU_ASSERT 1
#define CONFIG_MMU_DEBUG  1
#define trace_printf _info

// We fix the debug output, changing `%lux` to `%p`
static void init_xlat_tables(const struct arm_mmu_region *region) {
  ...
  sinfo("mmap: virt %p phys %p size %p\n", virt, phys, size);

// To enable the MMU at EL1...
static void enable_mmu_el1(unsigned int flags) {
  ...
  // Ensure these changes are seen before MMU is enabled
  _info("UP_MB");
  UP_MB();

  // Enable the MMU and Data Cache
  _info("Enable the MMU and data cache");
  write_sysreg(value | SCTLR_M_BIT | SCTLR_C_BIT, sctlr_el1);

  // Ensure the MMU Enable takes effect immediately
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

Ah OK we're stuck just before [__Enabling the MMU and Data Cache__](https://gist.github.com/lupyuen/544a5d8f3fab2ab7c9d06d2e1583f362)...

```bash
arm64_mmu_init: xlat tables:
arm64_mmu_init: base table(L0): 0x4083c000, 512 entries
arm64_mmu_init: 0: 0x40832000
arm64_mmu_init: 1: 0x40833000
arm64_mmu_init: 2: 0x40834000
arm64_mmu_init: 3: 0x40835000
arm64_mmu_init: 4: 0x40836000
arm64_mmu_init: 5: 0x40837000
arm64_mmu_init: 6: 0x40838000
arm64_mmu_init: 7: 0x40839000
arm64_mmu_init: 8: 0x4083a000
arm64_mmu_init: 9: 0x4083b000
setup_page_tables:
init_xlat_tables: mmap: virt 0x7000000 phys 0x7000000 size 0x20000000
set_pte_table_desc:
set_pte_table_desc: 0x4083c000: [Table] 0x40832000
set_pte_table_desc:
set_pte_table_desc: 0x40832000: [Table] 0x40833000
init_xlat_tables: mmap: virt 0x40000000 phys 0x40000000 size 0x8000000
set_pte_table_desc:
set_pte_table_desc: 0x40832008: [Table] 0x40834000
init_xlat_tables: mmap: virt 0x4010000000 phys 0x4010000000 size 0x10000000
set_pte_table_desc:
set_pte_table_desc: 0x40832800: [Table] 0x40835000
init_xlat_tables: mmap: virt 0x8000000000 phys 0x8000000000 size 0x8000000000
init_xlat_tables: mmap: virt 0x3eff0000 phys 0x3eff0000 size 0x10000
set_pte_table_desc:
set_pte_table_desc: 0x40833fb8: [Table] 0x40836000
init_xlat_tables: mmap: virt 0x40800000 phys 0x40800000 size 0x2a000
split_pte_block_desc: Splitting existing PTE 0x40834020(L2)
set_pte_table_desc:
set_pte_table_desc: 0x40834020: [Table] 0x40837000
init_xlat_tables: mmap: virt 0x4082a000 phys 0x4082a000 size 0x6000
init_xlat_tables: mmap: virt 0x40830000 phys 0x40830000 size 0x13000
init_xlat_tables: mmap: virt 0x40a00000 phys 0x40a00000 size 0x400000
enable_mmu_el1:
enable_mmu_el1: UP_MB
enable_mmu_el1: Enable the MMU and data cache
```

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

# Fix the NuttX Memory Map

_Arm64 MMU won't turn on. Maybe our Memory Map is incorrect?_

Let's verify our __Memory Map__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 42 |
|:--------------------------------|:---------|
| __Module__ | __Address__
| Boot ROM & SRAM | _0x0000_0000_ to ...
| PCIE | _0x2000_0000_ to _0x2FFF_FFFF_
| DRAM | _0x4000_0000_ to ...

</div>
</p>

How does this compare with NuttX? We do extra logging for __Memory Management Unit (MMU)__: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/commit/9488ecb5d8eb199bdbe16adabef483cf9cf04843)

```c
// Log the Names of the Memory Regions
static void init_xlat_tables(const struct arm_mmu_region *region) { ...
  _info("name=%s\n", region->name);
  sinfo("mmap: virt %p phys %p size %p\n", virt, phys, size);
```

Ah much clearer! Now we see the __Names of Memory Regions__...

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

- __PCI__: Let's remove these for now: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/commit/ca273d05e015089a33072997738bf588b899f8e7)

  ```c
  static const struct arm_mmu_region g_mmu_regions[] = {
    ...
    // We don't need PCI, for now
    // MMU_REGION_FLAT_ENTRY("PCI_CFG", ...
    // MMU_REGION_FLAT_ENTRY("PCI_MEM", ...
    // MMU_REGION_FLAT_ENTRY("PCI_IO", ...
  ```

The rest are hunky dory...

- TODO __DRAM0_S0__ says that RAM Address Space ends at _0x4800_0000 (128 MB)_. Which is kinda small, let's embiggen.

- __nx_code__ _(0x4080_0000)_: Kernel Code begins here

- __nx_rodata__ _(0x4082_A000)_: Read-Only Data for Kernel

- __nx_data__ _(0x4083_0000)_: Read-Write Data for Kernel

- __nx_pgpool__ _(0x40A0_0000)_: Remember the __Paged Memory Pool__? This will be dished out as __Virtual Memory__ to NuttX Apps

Rebuild, recopy, reboot NuttX. Our Memory Map looks [__much better now__](https://gist.github.com/lupyuen/ad4cec0dee8a21f3f404144be180fa14)...

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

# Arm64 Global Interrupt Controller

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

It's the Arm64 [__Generic Interrupt Controller (GIC)__](TODO), version 3. GIC will...

- Receive __I/O Interrupts__

  _(Like keypresses)_

- And forward them to an __Arm64 CPU Core__ for processing

  _(Works like RISC-V PLIC)_

GIC is here...

| [A523 User Manual](https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf) | Page 263 |
|:-------------------------------:|:---------|
| __Module__ | __Base Address__
| GIC | _0x0340_0000_

With these __GIC Registers__, handling 8 Arm64 Cores...

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
| _0x16_0000_ | GICDA_CTLR  _(Ditto, Core 1)_

Based on the above, we set the __Addresses of GICD and GICR__ _(Distributor / Redistributor)_: [qemu/chip.h](https://github.com/lupyuen2/wip-nuttx/commit/f3a26dbba69a0714bc91d0c345b8fba5e0835b76)

```c
// Base Address of GIC Distributor and Redistributor
#define CONFIG_GICD_BASE   0x3400000
#define CONFIG_GICR_BASE   0x3460000

// Spaced 0x20000 bytes per Arm64 Core
#define CONFIG_GICR_OFFSET 0x20000
```

Remember to [__Disable Memory Manager Logging__](https://github.com/lupyuen2/wip-nuttx/commit/10c7173b142f4a0480d742688c72499b76f66f83). NuttX GIC Driver [__complains no more__](https://gist.github.com/lupyuen/3c587ac0f32be155c8f9a9e4ca18676c)!

```bash
## SPI = Physical Interrupt Signal (not the typical SPI)
gic_validate_dist_version:
  GICv3 version detect
  GICD_TYPER = 0x7b0408
  256 SPIs implemented
```

# NuttX Apps Filesystem

_Are we done yet?_

If we're doing a __Simple NuttX Port__ _(Flat Build)_: Congrats just fix the [__UART Interrupt__](TODO) and we're done!

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

_/system/bin/init_ is __NSH Shell__. That's how NuttX Kernel Build works: It loads NuttX Apps from a __Local Filesystem__. _(Instead of binding Apps into Kernel)_

We bundle the NuttX Apps together into a __ROM FS Filesystem__...

```bash
TODO
```

Then we package NuttX Kernel + NuttX Apps into a __NuttX Image__...

```bash
TODO
```

[(See the __Build Script__)](TODO)

When NuttX Boots: It will find the ROM FS Filesystem, and Mount it as a __RAM Disk__. Which will allow NuttX Kernel to start __NSH Shell__ and other NuttX Apps. Everything is explained here...

- TODO: Appendix

NSH Prompt still missing? It won't appear until we fix the UART Interrupt...

# Fix the UART Interrupt

One Last Thing: Fix the __UART Interrupt__ and we're done!

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

__NSH Prompt__ finally appears. And __OSTest completes successfully__ yay!

```bash
TODO
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/c2248e7537ca98333d47e33b232217b6)

_Very odd. NSH Prompt won't appear if UART Interrupt is disabled?_

That's because NSH runs as a __NuttX App in User Space__. When NSH Shell prints this...

```bash
nsh>
```

It calls the __Serial Driver__. Which will wait for a __UART Interrupt__ to signal that the Transmit Buffer is empty and available. Thus if UART Interrupt is disabled, nothing gets printed in NuttX Apps. [(Explained here)](TODO)

# TODO

![Apache NuttX RTOS for Avaota-A1 SBC (Allwinner A527 SoC)](https://lupyuen.org/images/testbot2-flow3.jpg)

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

We'll take the NuttX Kernel Build for [__QEMU Arm64__](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig), boot it on Avaota-A1 SBC. We're making terrific progress with __NuttX on Avaota SBC__...

![NuttX on Avaota-A1](https://lupyuen.org/images/testbot3-port.png)

_Isn't it faster to port NuttX with U-Boot TFTP?_

Yeah for RISC-V Ports we boot [__NuttX over TFTP__](https://lupyuen.github.io/articles/starpro64#boot-nuttx-over-tftp). But Avaota U-Boot [__doesn't support TFTP__](https://gist.github.com/lupyuen/366f1ffefc8231670ffd58a3b88ae8e5), so it's back to MicroSD sigh. (Pic below)

# Boot NuttX for Avaota-A1

[(Watch the __Demo on YouTube__)](https://youtu.be/PxaMcmMAzlM)

NuttX boots to NSH Shell. And passes OSTest yay!

Here's the latest NuttX Boot Log:
- https://gist.github.com/lupyuen/c2248e7537ca98333d47e33b232217b6

<span style="font-size:60%">

```text
[    0.000255][I]  _____     _           _____ _ _
[    0.006320][I] |   __|_ _| |_ ___ ___|  |  |_| |_
[    0.012456][I] |__   | | |  _| -_|  _|    -| | _|
[    0.018566][I] |_____|_  |_| |___|_| |__|__|_|_|
[    0.024719][I]       |___|
[    0.030820][I] ***********************************
[    0.036948][I]  SyterKit v0.4.0 Commit: e4c0651
[    0.042781][I]  github.com/YuzukiHD/SyterKit
[    0.048882][I] ***********************************
[    0.054992][I]  Built by: arm-none-eabi-gcc 13.2.1
[    0.061119][I]
[    0.063943][I] Model: AvaotaSBC Avaota A1 board.
[    0.069856][I] Core: Arm Octa-Core Cortex-A55 v65 r2p0
[    0.076356][I] Chip SID = 0300ff1071c048247590d120506d1ed4
[    0.083280][I] Chip type = A527M000000H Chip Version = 2
[    0.091391][I] PMU: Found AXP717 PMU, Addr 0x35
[    0.098200][I] PMU: Found AXP323 PMU
[    0.112870][I] DRAM BOOT DRIVE INFO: V0.6581
[    0.118326][I] Set DRAM Voltage to 1160mv
[    0.123524][I] DRAM_VCC set to 1160 mv
[    0.247920][I] DRAM retraining ten
[    0.266135][I] [AUTO DEBUG]32bit,2 ranks training success!
[    0.296290][I] Soft Training Version: T2.0
[    1.819657][I] [SOFT TRAINING] CLK=1200M Stable memtest pass
[    1.826565][I] DRAM CLK =1200 MHZ
[    1.830992][I] DRAM Type =8 (3:DDR3,4:DDR4,6:LPDDR2,7:LPDDR3,8:LPDDR4)
[    1.843100][I] DRAM SIZE =4096 MBytes, para1 = 310a, para2 = 10001000, tpr13 = 6061
[    1.853431][I] DRAM simple test OK.
[    1.858011][I] Init DRAM Done, DRAM Size = 4096M
[    2.278300][I] SMHC: sdhci0 controller initialized
[    2.305826][I]   Capacity: 59.48GB
[    2.310439][I] SHMC: SD card detected
[    2.319537][I] FATFS: read bl31.bin addr=48000000
[    2.339744][I] FATFS: read in 13ms at 5.92MB/S
[    2.345498][I] FATFS: read scp.bin addr=48100000
[    2.374729][I] FATFS: read in 22ms at 8.00MB/S
[    2.380481][I] FATFS: read extlinux/extlinux.conf addr=40020000
[    2.389436][I] FATFS: read in 1ms at 0.29MB/S
[    2.395095][I] FATFS: read splash.bin addr=40080000
[    2.403142][I] FATFS: read in 1ms at 12.66MB/S
[    3.193943][I] FATFS: read /Image addr=40800000
[    3.341455][I] FATFS: read in 143ms at 8.86MB/S
[    3.347308][I] FATFS: read /dtb/allwinner/sun55i-t527-avaota-a1.dtb addr=40400000
[    3.400140][I] FATFS: read in 19ms at 7.46MB/S
[    3.405891][I] FATFS: read /uInitrd addr=43000000
[    4.113508][I] FATFS: read in 702ms at 9.04MB/S
[    4.119356][I] Initrd load 0x43000000, Size 0x00632414
[    5.376346][W] FDT: bootargs is null, using extlinux.conf append.
[    5.688989][I] EXTLINUX: load extlinux done, now booting...
[    5.695984][I] ATF: Kernel addr: 0x40800000
[    5.701523][I] ATF: Kernel DTB addr: 0x40400000
[    5.891085][I] disable mmu ok...
[    5.895615][I] disable dcache ok...
[    5.900478][I] disable icache ok...
[    5.905342][I] free interrupt ok...
NOTICE:  BL31: v2.5(debug):9241004a9
NOTICE:  BL31: Built : 13:37:46, Nov 16 2023
NOTICE:  BL31: No DTB found.
NOTICE:  [SCP] :wait arisc ready....
NOTICE:  [SCP] :arisc version: []
NOTICE:  [SCP] :arisc startup ready
NOTICE:  [SCP] :arisc startup notify message feedback
NOTICE:  [SCP] :sunxi-arisc driver is starting
ERROR:   Error initializing runtime service opteed_fast
123- Ready to Boot Primary CPU
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

How did we get here? Let's walk through the steps...

# Allwinner A527 Docs

We used these docs (A527 is a variant of A523)

- https://linux-sunxi.org/A523
- https://linux-sunxi.org/File:A527_Datasheet_V0.93.pdf
- https://linux-sunxi.org/File:A523_User_Manual_V1.1_merged_cleaned.pdf

# Work In Progress

We take NuttX for Arm64 QEMU knsh (Kernel Build) and tweak it iteratively for Avaota-A1 SBC, based on Allwinner A527 SoC...


# What's Next

TODO

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

# Appendix: NuttX Apps Filesystem

https://github.com/lupyuen2/wip-nuttx/pull/97/files


arch/arm64/src/qemu/qemu_boot.c

https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-be208bc5be54608eca3885cf169183ede375400c559700bb423c81d7b2787431

```c
extern uint8_t __ramdisk_start[];
extern uint8_t __ramdisk_size[];

/****************************************************************************
 * Name: qemu_copy_overlap
 *
 * Description:
 *   Copy an overlapping memory region.  dest overlaps with src + count.
 *
 * Input Parameters:
 *   dest  - Destination address
 *   src   - Source address
 *   count - Number of bytes to copy
 *
 ****************************************************************************/

static void qemu_copy_overlap(uint8_t *dest, const uint8_t *src,
                              size_t count)
{
  uint8_t *d = dest + count - 1;
  const uint8_t *s = src + count - 1;

  if (dest <= src)
    {
      _err("dest and src should overlap");
      PANIC();
    }

  while (count--)
    {
      volatile uint8_t c = *s;  /* Prevent compiler optimization */
      *d = c;
      d--;
      s--;
    }
} 

/****************************************************************************
 * Name: qemu_copy_ramdisk
 *
 * Description:
 *   Copy the RAM Disk from NuttX Image to RAM Disk Region.
 *
 ****************************************************************************/

static void qemu_copy_ramdisk(void)
{
  char header[8] __attribute__((aligned(8))) = "-rom1fs-";
  const uint8_t *limit = (uint8_t *)g_idle_topstack + (256 * 1024);
  uint8_t *ramdisk_addr = NULL;
  uint8_t *addr;
  uint32_t size;

  /* After _edata, search for "-rom1fs-". This is the RAM Disk Address.
   * Limit search to 256 KB after Idle Stack Top.
   */

  binfo("_edata=%p, _sbss=%p, _ebss=%p, idlestack_top=%p\n",
        (void *)_edata, (void *)_sbss, (void *)_ebss,
        (void *)g_idle_topstack);
  for (addr = g_idle_topstack; addr < limit; addr += 8)
    {
      if (addr == _edata) { _info("addr=%p, header=%p, sizeof(header)=%d\n", addr, header, sizeof(header)); } ////
      if (memcmp(addr, header, sizeof(header)) == 0)
        {
          ramdisk_addr = addr;
          break;
        }
    }

  /* Stop if RAM Disk is missing */

  binfo("ramdisk_addr=%p\n", ramdisk_addr);
  if (ramdisk_addr == NULL)
    {
      _err("Missing RAM Disk. Check the initrd padding.");
      PANIC();
    }

  /* RAM Disk must be after Idle Stack, to prevent overwriting */

  // if (ramdisk_addr <= (uint8_t *)g_idle_topstack)
  //   {
  //     const size_t pad = (size_t)g_idle_topstack - (size_t)ramdisk_addr;
  //     _err("RAM Disk must be after Idle Stack. Increase initrd padding "
  //           "by %d bytes.", pad);
  //     PANIC();
  //   }

  /* Read the Filesystem Size from the next 4 bytes (Big Endian) */

  size = (ramdisk_addr[8] << 24) + (ramdisk_addr[9] << 16) +
         (ramdisk_addr[10] << 8) + ramdisk_addr[11] + 0x1f0;
  binfo("size=%d\n", size);

  /* Filesystem Size must be less than RAM Disk Memory Region */

  if (size > (size_t)__ramdisk_size)
    {
      _err("RAM Disk Region too small. Increase by %ul bytes.\n",
            size - (size_t)__ramdisk_size);
      PANIC();
    }

  /* Copy the RAM Disk from NuttX Image to RAM Disk Region.
   * __ramdisk_start overlaps with ramdisk_addr + size.
   */

  qemu_copy_overlap(__ramdisk_start, ramdisk_addr, size);
}

void arm64_chip_boot(void)
{
  /* Copy the RAM Disk */

  qemu_copy_ramdisk();
  /* MAP IO and DRAM, enable MMU. */

  *(volatile uint8_t *) 0x02500000 = 'B'; ////
  arm64_mmu_init(true);
```

boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig

https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-6adf2d1a1e5d57ee68c7493a2b52c07c4e260e60d846a9ee7b8f8a6df5d8cb64

```bash
## CONFIG_FS_HOSTFS=y
## CONFIG_ARM64_SEMIHOSTING_HOSTFS=y
## CONFIG_ARM64_SEMIHOSTING_HOSTFS_CACHE_COHERENCE=y

## CONFIG_INIT_MOUNT_DATA="fs=../apps"
## CONFIG_INIT_MOUNT_FSTYPE="hostfs"
## CONFIG_INIT_MOUNT_SOURCE=""
## CONFIG_INIT_MOUNT_TARGET="/system"


CONFIG_BOARDCTL_ROMDISK=y
CONFIG_BOARD_LATE_INITIALIZE=y
CONFIG_INIT_MOUNT_TARGET="/system/bin"
```

boards/arm64/qemu/qemu-armv8a/scripts/ld-kernel.script

https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-f0706cd747d2f1be1eeb64d50821afb1e25d5bb26e964e2679268a83dcff0afc

```c
MEMORY
{
  dram (rwx)    : ORIGIN = 0x40800000, LENGTH = 2M
  pgram (rwx)   : ORIGIN = 0x40A00000, LENGTH = 4M    /* w/ cache */
  ramdisk (rwx) : ORIGIN = 0x40E00000, LENGTH = 16M   /* w/ cache */
}

/* Application ramdisk */

__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size  = LENGTH(ramdisk);
__ramdisk_end   = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

boards/arm64/qemu/qemu-armv8a/src/qemu_bringup.c

https://github.com/lupyuen2/wip-nuttx/pull/97/files#diff-f8d388b76b0b37563184a5a174f18970ff6771d6a048e0e792967ab265d6f7eb

```c
/* RAM Disk Definition */

#define SECTORSIZE   512
#define NSECTORS(b)  (((b) + SECTORSIZE - 1) / SECTORSIZE)
#define RAMDISK_DEVICE_MINOR 0

/****************************************************************************
 * Name: mount_ramdisk
 *
 * Description:
 *  Mount a RAM Disk defined in ld.script to /dev/ramX.  The RAM Disk
 *  contains a ROMFS filesystem with applications that can be spawned at
 *  runtime.
 *
 * Returned Value:
 *   OK is returned on success.
 *   -ERRORNO is returned on failure.
 *
 ****************************************************************************/

static int mount_ramdisk(void)
{
  _info("\n"); ////
  int ret;
  struct boardioc_romdisk_s desc;

  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;

  ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Ramdisk register failed: %s\n", strerror(errno));
      syslog(LOG_ERR, "Ramdisk mountpoint /dev/ram%d\n",
             RAMDISK_DEVICE_MINOR);
      syslog(LOG_ERR, "Ramdisk length %lu, origin %lx\n",
             (ssize_t)__ramdisk_size, (uintptr_t)__ramdisk_start);
    }

  return ret;
}

int qemu_bringup(void)
{
  /* Mount the RAM Disk */

  mount_ramdisk();
```

Remove HostFS for Semihosting
- https://github.com/lupyuen2/wip-nuttx/commit/40c4ab530dad2b7db0f354a2fa4b5e0f5263fb4e

OK the Initial Filesystem is no longer available:
- https://gist.github.com/lupyuen/e74c29049f20c76a2c4fe6f863d55507

Add the Initial RAM Disk
- https://github.com/lupyuen2/wip-nuttx/commit/cf5fe66b97f4526fb8dfc993415ac04ce96f4c13

Enable Logging for RAM Disk
- https://github.com/lupyuen2/wip-nuttx/commit/60007f1b97b6af4445c793904c30d65ebbebb337

`default_fatal_handler: (IFSC/DFSC) for Data/Instruction aborts: alignment fault`
- https://gist.github.com/lupyuen/f10af7903461f44689203d0e02fb9949

Our RAM Disk Copier is accessing misligned addresses. Let's fix the alignment...

Align RAM Disk Address to 8 bytes. Search from Idle Stack Top instead of EDATA.
- https://github.com/lupyuen2/wip-nuttx/commit/07d9c387a7cb06ccec53e20eecd0c4bb9bad7109

Log the Mount Error
- https://github.com/lupyuen2/wip-nuttx/commit/38538f99333868f85b67e2cb22958fe496e285d6

Mounting of ROMFS fails
- https://gist.github.com/lupyuen/d12e44f653d5c5597ecae6845e49e738

```text
nx_start_application: ret=-15
dump_assert_info: Assertion failed : at file: init/nx_bringup.c:361
```

Which is...

```c
#define ENOTBLK             15
#define ENOTBLK_STR         "Block device required"
```

Why is /dev/ram0 not a Block Device?

```c
$ grep INIT .config
# CONFIG_BOARDCTL_FINALINIT is not set
# CONFIG_INIT_NONE is not set
CONFIG_INIT_FILE=y
CONFIG_INIT_ARGS=""
CONFIG_INIT_STACKSIZE=8192
CONFIG_INIT_PRIORITY=100
CONFIG_INIT_FILEPATH="/system/bin/init"
CONFIG_INIT_MOUNT=y
CONFIG_INIT_MOUNT_SOURCE="/dev/ram0"
CONFIG_INIT_MOUNT_TARGET="/system/bin"
CONFIG_INIT_MOUNT_FSTYPE="romfs"
CONFIG_INIT_MOUNT_FLAGS=0x1
CONFIG_INIT_MOUNT_DATA=""
```

We check the logs...

Enable Filesystem Logging
- https://github.com/lupyuen2/wip-nuttx/commit/cc4dffd60fd223a7c1f6b513dc99e1fa98a48496

`Failed to find /dev/ram0`
- https://gist.github.com/lupyuen/805c2be2a3333a90c96926a26ec2d8cc

```text
find_blockdriver: pathname="/dev/ram0"
find_blockdriver: ERROR: Failed to find /dev/ram0
nx_mount: ERROR: Failed to find block driver /dev/ram0
nx_start_application: ret=-15
```

Is /dev/ram0 created? Ah we forgot to Mount the RAM Disk!

# Appendix: Mount the RAM Disk

Let's mount the RAM Disk...

Mount the RAM Disk
- https://github.com/lupyuen2/wip-nuttx/commit/65ae74507e95189e96816161b0c1a820722ca8a2

/system/bin/init starts successfully yay!
- https://gist.github.com/lupyuen/ccb645efa72f6793743c033fade0b3ac

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
