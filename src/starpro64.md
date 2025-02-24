# StarPro64 EIC7700X RISC-V SBC: Maybe LLM on NPU on NuttX?

📝 _16 Apr 2025_

![StarPro64 EIC7700X RISC-V SBC: Maybe LLM on NPU on NuttX?](https://lupyuen.org/images/starpro64-title.jpg)

TODO

StarPro64 EIC7700X is the (literally) Hot New RISC-V SBC by PINE64.

Star64 power

IKEA Smart Power Plug

iTerm: Edit > Paste Special > Paste Slowly

Settings > Advanced > Pasteboard

Delay in seconds between chunks when Pasting Slowly: 1 second

Number of bytes to paste in each chunk when Pasting Slowly: 16

Well documented

NuttX: Power efficient AI

_StarPro64 is just an upgraded Star64?_

Nope it's a totally different beast!

Docs are so much better! (??? pages)

_(Thanks to PINE64 for providing the Prototype StarPro64)_

# ESWIN EIC7700X RISC-V SoC

TODO: NPU

![TODO](https://lupyuen.org/images/starpro64-fan2.jpg)

TODO

![TODO](https://lupyuen.org/images/starpro64-uart.jpg)

# Boot Without MicroSD

_What happens if we boot StarPro64? Fresh from the box?_

We monitor the __UART0 Port__ for Debug Messages. Connect our __USB UART Dongle__ (CH340 or CP2102) to these pins (pic above)...

| StarPro64 | USB UART | Colour |
|:------------:|:--------:|:------:|
| __GND__ (Pin 6)	| __GND__ | _Yellow_ |
| __TX__ (Pin 8) |	__RX__ | _Blue_ |
| __RX__ (Pin 10)	| __TX__ | _Green_ |

(Same Pins as the __GPIO Header__ on Oz64 SG2000 and Star64 JH7110)

Connect to the USB UART at __115.2 kbps__...

```bash
screen /dev/ttyUSB0 115200
```

Power up the board with a __Power Adapter__. [(Same one as __Star64 JH7110__)](TODO)

We'll see [__OpenSBI__](TODO)...

<span style="font-size:80%">

```text
OpenSBI v1.5
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|
Platform Name             : ESWIN EIC7700 EVB
Platform Features         : medeleg
Platform HART Count       : 4
Platform Console Device   : uart8250
Firmware Base             : 0x80000000

Domain0 Boot HART         : 2
Domain0 HARTs             : 0*,1*,2*,3*
Domain0 Next Address      : 0x0000000080200000

Boot HART ID              : 2
Boot HART Base ISA        : rv64imafdchx
Boot HART ISA Extensions  : sscofpmf,zihpm,sdtrig
Boot HART MIDELEG         : 0x0000000000002666
Boot HART MEDELEG         : 0x0000000000f0b509
```

</span>

Then [__U-Boot Bootloader__](TODO)...

<span style="font-size:80%">

```text
U-Boot 2024.01-gaa36f0b4 (Jan 23 2025 - 02:49:59 +0000)
CPU:     rv64imafdc_zba_zbb
Model:   ESWIN EIC7700 EVB
DRAM:    32 GiB (effective 16 GiB)
llCore:  143 devices, 31 uclasses, devicetree: separate
Warning: Device tree includes old 'u-boot,dm-' tags: please fix by 2023.07!
MMC:    sdhci@50450000: 0, sd@50460000: 1

Loading Environment from SPIFlash...
SF: Detected w25q128fw with page size 256 Bytes, erase size 4 KiB, total 16 MiB
*** Warning - bad CRC, using default environment
No SATA device found!
Hit any key to stop autoboot:  0
=>
```

</span>

And it stops at U-Boot, waiting to boot from MicroSD or eMMC. Let's init our eMMC...

[(See the __Boot Log__)](https://gist.github.com/lupyuen/9db7b36f3cdf26f7b7f75c0d35177ee7)

![TODO](https://lupyuen.org/images/starpro64-hdmi.jpg)

_HDMI Output will show U-Boot, but not OpenSBI_

# Download the Linux Image

_Is there a Linux Image for StarPro64?_

The fine folks at [__PLCT Lab RockOS__](https://github.com/rockos-riscv) are busy preparing the __Linux Image__ for StarPro64. Thanks to [__@icenowy__](https://nightcord.de/@icenowy/114027871300585376), we have a [__Preview Version__](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/) of the Linux Image...

1. __Bootloader (OpenSBI + U-Boot)__

   [_bootloader\_secboot\_ddr5\_pine64-starpro64.bin_](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/bootloader_secboot_ddr5_pine64-starpro64.bin)

1. __Linux Boot Image (Linux Kernel)__

   [_boot-rockos-20250123-210346.ext4.zst_](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/boot-rockos-20250123-210346.ext4.zst)

1. __Linux Root Image (Linux Filesystem)__

   [_root-rockos-20250123-210346.ext4.zst_](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/root-rockos-20250123-210346.ext4.zst)

Uncompress the files and rename them. Copy them to a [__USB Drive__](TODO) (not MicroSD)

```bash
$ ls -lh *.bin *.zst
4.2M  bootloader_secboot_ddr5_pine64-starpro64.bin
154M  boot-rockos-20250123-210346.ext4.zst
2.3G  root-rockos-20250123-210346.ext4.zst

$ unzstd boot-rockos-20250123-210346.ext4.zst
boot-rockos-20250123-210346.ext4.zst: 524288000 bytes

$ unzstd root-rockos-20250123-210346.ext4.zst
root-rockos-20250123-210346.ext4.zst: 7516192768 bytes

$ mv boot-rockos-20250123-210346.ext4 boot.ext4
$ mv root-rockos-20250123-210346.ext4 root.ext4

$ ls -lh *.bin *.ext4
4.2M  bootloader_secboot_ddr5_pine64-starpro64.bin
500M  boot.ext4
7.0G  root.ext4

$ cp *.bin *.ext4 /media/$USER/YOUR_USB_DRIVE
```

We'll skip the [__MicroSD Image__](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/sdcard-rockos-20250123-210346.img.zst), because [__MicroSD Interface__](TODO) wasn't working reliably on our Prototype StarPro64.

![TODO](https://lupyuen.org/images/starpro64-emmc.jpg)

# Prepare the Linux Image

_How to load the Linux Image into eMMC?_

Based on the [__Official Doc__](TODO)...

1. Connect our __eMMC to StarPro64__ (pic above)

1. Connect our __USB Drive__ from previous section

1. __At U-Boot:__ Press __Ctrl-C__ to stop Autoboot

1. Verify that the __eMMC is OK__...

   ```bash
   $ ls mmc 0
   [ Nothing ]

   $ mmc part
   [ Nothing ]
   ```

1. First Time Only: __GPT Partition__ our eMMC...

   ```bash
   $ echo $partitions
   partitions=
     name=boot,start=1MiB,size=2048MiB,type=${typeid_filesystem},uuid=${uuid_boot};
     name=swap,size=4096MiB,type=${typeid_swap},uuid=${uuid_swap};
     name=root,size=-,type=${typeid_filesystem},uuid=${uuid_root}

   $ run gpt_partition
   $ mmc part
   1 0x00000800 0x001007ff "boot"
   2 0x00100800 0x009007ff "swap"
   3 0x00900800 0x0e677fde "root"
   ```

1. Verify that our __USB Drive__ works...

   ```bash
   $ ls usb 0
    524288000 boot.ext4
   7516192768 root.ext4
      4380760 bootloader_secboot_ddr5_pine64-starpro64.bin   
   ```

1. Install the __Bootloader, Boot Image and Root Image__, from USB Drive to eMMC...

   ```bash
   $ es_fs update usb 0 boot.ext4 mmc 0:1
   mmc has been successfully writen in mmc 0:1

   $ es_fs update usb 0 root.ext4 mmc 0:3
   mmc has been successfully writen in mmc 0:3

   $ ext4load usb 0 0x100000000 bootloader_secboot_ddr5_pine64-starpro64.bin
   4380760 bytes read in 162 ms (25.8 MiB/s)

   $ es_burn write 0x100000000 flash
   bootloader write OK
   ```

   [(See the __eMMC Log__)](https://gist.github.com/lupyuen/a07e8dcd56d3fb306dce8983f4924702)

1. __Beware of Overheating!__ Keep StarPro64 cool, or the previous step might corrupt the __SPI Boot Flash__ and cause unspeakable agony...

![TODO](https://lupyuen.org/images/starpro64-fan.jpg)

# StarPro64 Gets Smokin' Hot!

_Something is smelling like barbecue?_

Whoa StarPro64 is on fire: Drop it, stop it and __power off__! StarPro64 will show [__PLL Errors__](https://gist.github.com/lupyuen/47170b4c4d7117ac495c5faede48280b#file-gistfile1-txt-L796-L894) when it overheats...

```bash
pll failed.
pll failed.
pll failed.
```

Also watch for [__Thermal Errors__](https://gist.github.com/lupyuen/89e1e87e7f213b6f52f31987f254b32f#file-gistfile1-txt-L1940-L1947) when booting Linux...

```bash
thermal thermal_zone0: thermal0:
critical temperature reached, shutting down
reboot: HARDWARE PROTECTION shutdown (Temperature too high)
```

Install a [__USB Fan__](https://www.lazada.sg/products/i2932991583-s20178422377.html), preferably something stronger. _(Pic above, boxed up with IKEA 365+)_

But don't power it with the USB Port on StarPro64! Instead, connect it to our [__Smart Power Plug__](TODO).

_Anything else we should worry about?_

The [__MicroSD Interface__](TODO) wasn't working well on our Prototype StarPro64. The MicroSD Card deactivated itself after a bit of U-Boot Access.

Hence the __Headless Ironman__: USB Drive on StarPro64...

![TODO](https://lupyuen.org/images/starpro64-ironman.jpg)

# Boot the Linux Image

_Earlier we flashed Linux to eMMC. Can we boot Linux now?_

Yep just power up StarPro64. eMMC will __Boot Linux__...

<span style="font-size:80%">

```text
U-Boot menu
1:      RockOS GNU/Linux 6.6.73-win2030
2:      RockOS GNU/Linux 6.6.73-win2030 (rescue target)
Enter choice: 1:        RockOS GNU/Linux 6.6.73-win2030
Retrieving file: /vmlinuz-6.6.73-win2030
Retrieving file: /initrd.img-6.6.73-win2030
append: root=PARTUUID=b0f77ad6-36cd-4a99-a8c0-31d73649aa08 console=ttyS0,115200 root=PARTUUID=b0f77ad6-36cd-4a99-a8c0-31d73649aa08 rootfstype=ext4 rootwait rw earlycon selinux=0 LANG=en_US.UTF-8

Retrieving file: /dtbs/linux-image-6.6.73-win2030/eswin/eic7700-pine64-starpro64.dtb
   Uncompressing Kernel Image
Moving Image from 0x84000000 to 0x80200000, end=81e63000
## Flattened Device Tree blob at 88000000
   Booting using the fdt blob at 0x88000000
Working FDT set to 88000000
ERROR: reserving fdt memory region failed (addr=fffff000 size=1000 flags=4)
   Using Device Tree in place at 0000000088000000, end 0000000088027af4
Working FDT set to 88000000

Starting kernel ...
Linux version 6.6.73-win2030 (riscv@riscv-builder) (riscv64-unknown-linux-gnu-gcc () 13.2.0, GNU ld (GNU Binutils) 2.42) #2025.01.23.02.46+aeb0f375c SMP Thu Jan 23 03:08:39 UTC 2025
Machine model: Pine64 StarPro64
...
mmc0: Timeout waiting for hardware interrupt.
mmc0: sdhci: ============ SDHCI REGISTER DUMP ===========
mmc0: sdhci: Sys addr:  0x00000008 | Version:  0x00000005
mmc0: sdhci: Blk size:  0x00007200 | Blk cnt:  0x00000000
```

</span>

Sadly the [__Preview Version__](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/) of RockOS won't boot correctly on our Prototype StarPro64. Hopefully we'll sort this out real soon! (Pic below)

[(See the __Boot Log__)](https://gist.github.com/lupyuen/89e1e87e7f213b6f52f31987f254b32f)

![TODO](https://lupyuen.org/images/starpro64-linux.jpg)

# Settings for U-Boot Bootloader

_Bummer. What else can we boot on StarPro64?_

Let's snoop around [__U-Boot Bootloader__](TODO). And figure out how to boot [__Apache NuttX RTOS__](TODO).

Power up StarPro64 and press __Ctrl-C__. At the __U-Boot Prompt__: We enter these commands...

```bash
$ help
printenv  - print environment variables
saveenv   - save environment variables to persistent storage
net       - NET sub-system
dhcp      - boot image via network using DHCP/TFTP protocol
tftpboot  - load file via network using TFTP protocol
fdt       - flattened device tree utility commands
booti     - boot Linux kernel 'Image' format from memory

$ printenv
fdt_addr_r=0x88000000
kernel_addr_r=0x84000000
loadaddr=0x80200000
```

[(See the __U-Boot Log__)](https://gist.github.com/lupyuen/9db7b36f3cdf26f7b7f75c0d35177ee7)

A-ha! This says...

- U-Boot supports booting over TFTP: [__Trivial File Transfer Protocol__](TODO)

- It will load the __Kernel Image__ _(Linux / NuttX)_ into RAM at __`0x8400` `0000`__

- Then it will move the Kernel Image to __`0x8020` `0000`__ and boot there

- Also it loads the __Device Tree__ into __`0x8800` `0000`__

Thanks U-Boot! You told us everything we need to Boot NuttX...

> ![TODO](https://lupyuen.org/images/starpro64-nuttx.png)

# Boot NuttX over TFTP

_How to boot NuttX over TFTP?_

1.  Install our __TFTP Server__: Follow the [__instructions here__](https://lupyuen.github.io/articles/tftp#install-tftp-server)

1.  Copy these files to our TFTP Server...

    [__NuttX Image: Image-starpro64__](https://github.com/lupyuen2/wip-nuttx/releases/download/sg2000-1/TODO)

    [__Device Tree: jh7110-star64-pine64.dtb__](https://github.com/lupyuen2/wip-nuttx/releases/download/sg2000-1/TODO)

    ```bash
    TODO
    ```

    [(How to __Build NuttX__ ourselves)](TODO)

1.  Power up StarPro64 and press __Ctrl-C__

1.  At the __U-Boot Prompt__: Enter these commands...

    ```bash
    ## Check if the Network Adapter is alive
    ## "eth0 : ethernet@50400000 f6:70:f9:6e:73:ae active"
    net list

    ## Set the U-Boot TFTP Server
    ## TODO: Change to your TFTP Server
    setenv tftp_server 192.168.31.10

    ## Save the U-Boot Config for future reboots
    saveenv

    ## Fetch the IP Address over DHCP
    ## Load the NuttX Image from TFTP Server
    ## kernel_addr_r=TODO
    dhcp ${kernel_addr_r} ${tftp_server}:Image-starpro64

    ## Load the Device Tree from TFTP Server
    ## fdt_addr_r=TODO
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb

    ## Set the RAM Address of Device Tree
    ## fdt_addr_r=TODO
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    fdt addr ${fdt_addr_r}

    ## Boot the NuttX Image with the Device Tree
    ## kernel_addr_r=TODO
    ## fdt_addr_r=TODO
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    booti ${kernel_addr_r} - ${fdt_addr_r}
    ```

    [_(U-Boot dropping chars? Try __iTerm > Edit > Paste Special > Paste Slowly__)_](TODO)

1.  NuttX boots OK on StarPro64 yay! (Pic above)

    ```text
    TODO
    ```

1.  How did we port NuttX to StarPro64? Check the details here...

    [__"TODO"__](TODO)

_We type these commands EVERY TIME we boot?_

We can automate: Just do this once, and NuttX will __Auto-Boot__ whenever we power up...

```bash
## Add the Boot Command for TFTP
setenv bootcmd_tftp 'dhcp ${kernel_addr_r} ${tftp_server}:Image-starpro64 ; tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb ; fdt addr ${fdt_addr_r} ; booti ${kernel_addr_r} - ${fdt_addr_r}'

## Save it for future reboots
saveenv

## Test the Boot Command for TFTP, then reboot
run bootcmd_tftp

## Remember the Original Boot Command: `bootflow scan -lb`
setenv orig_bootcmd "$bootcmd"

## Prepend TFTP to the Boot Command: `run bootcmd_tftp ; bootflow scan -lb`
setenv bootcmd "run bootcmd_tftp ; $bootcmd"

## Save it for future reboots
saveenv
```

[_(U-Boot dropping chars? Try __iTerm > Edit > Paste Special > Paste Slowly__)_](TODO)

TODO: [(What about __Static IP__?)](https://github.com/lupyuen/nuttx-sg2000/issues/1)

TODO: [(How to __Undo Auto-Boot__)](https://github.com/lupyuen/nuttx-sg2000/issues/1#issuecomment-2114415245)

TODO: Press Ctrl-C to stop

TODO: Pic of Smart Plug, Fan, Ubuntu PC, StarPro64, USB Serial, TFTP Server

# Smart Power Plug

_Powering StarPro64 on and off: Gets so tiresome ain't it?_

Try a __Smart Power Plug__, integrated with our Build Script...

![TODO](https://lupyuen.org/images/starpro64-power1.jpg)

TODO

![TODO](https://lupyuen.org/images/starpro64-power2.jpg)

https://gist.github.com/lupyuen/16cd1ba3a56de1928cb956503ebdb9ac#file-run-sh-L118-L163

```bash
## Get the Home Assistant Token, copied from http://localhost:8123/profile/security
## export token=xxxx
. $HOME/home-assistant-token.sh

## Power Off the SBC"
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.starpro64_off"}' \
  http://localhost:8123/api/services/automation/trigger

## Power On the SBC
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.starpro64_on"}' \
  http://localhost:8123/api/services/automation/trigger

## Wait for SBC Testing to complete
echo Press Enter to Power Off
read

## Power Off the SBC"
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.starpro64_off"}' \
  http://localhost:8123/api/services/automation/trigger
```

Remember the [__USB Fan__](TODO)? It goes into our Smart Power Plug as a Power Jenga like so...

> ![TODO](https://lupyuen.org/images/starpro64-power3.jpg)

# Appendix: Build NuttX for StarPro64

_Earlier we booted Image-starpro64 over TFTP. How to get the file?_

We may download the NuttX Image File __`Image-starpro64`__ from here...

- [__Daily Build: NuttX for SG2000__](https://github.com/lupyuen/nuttx-sg2000/tags)

If we prefer to build NuttX ourselves...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv-none-elf__ (xPack)...
    
    [__"xPack GNU RISC-V Embedded GCC Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-xpack-gnu-risc-v-embedded-gcc-toolchain-for-64-bit-risc-v)

1.  Download and Build __NuttX for StarPro64__ (work-in-progress)...

    ```bash
    git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch starpro64
    git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch starpro64
    cd nuttx
    tools/configure.sh milkv_duos:nsh

    ## Build the NuttX Kernel and Apps
    make -j
    make -j export
    pushd ../apps
    ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    make -j import
    popd

    ## Generate Initial RAM Disk
    ## Prepare a Padding with 64 KB of zeroes
    ## Append Padding and Initial RAM Disk to NuttX Kernel
    genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
    head -c 65536 /dev/zero >/tmp/nuttx.pad
    cat nuttx.bin /tmp/nuttx.pad initrd \
      >Image

    ## Copy NuttX Image to TFTP Server
    scp Image tftpserver:/tftpboot/Image-starpro64
    ssh tftpserver ls -l /tftpboot/Image-starpro64

    ## In U-Boot: Boot NuttX over TFTP
    ## setenv tftp_server 192.168.31.10 ; dhcp ${kernel_addr_r} ${tftp_server}:Image-starpro64 ; tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb ; fdt addr ${fdt_addr_r} ; booti ${kernel_addr_r} - ${fdt_addr_r}
    ```

    [(See the __Build Script__)](TODO)

    [(See the __Build Log__)](TODO)

    [(See the __Build Outputs__)](TODO)

1.  The steps above assume that we've installed our TFTP Server, according to the [__instructions here__](https://lupyuen.github.io/articles/tftp#install-tftp-server)

1.  Then follow these steps to boot NuttX on StarPro64...

    [__"Boot NuttX over TFTP"__](TODO)

1.  Powering StarPro64 on and off can get tiresome. Try a Smart Power Plug, integrated with our Build Script...

    [__"TODO"__](TODO)

1.  How did we port NuttX to StarPro64? Check the details here...

    [__"TODO"__](TODO)

![Virtual Memory for NuttX Apps](https://lupyuen.github.io/images/mmu-l3user.jpg)

_Why the RAM Disk? Isn't NuttX an RTOS?_

StarPro64 uses a RAM Disk because it runs in __NuttX Kernel Mode__ (instead of the typical Flat Mode). This means we can do __Memory Protection__ and __Virtual Memory__ for Apps. (Pic above)

But it also means we need to bundle the __NuttX Apps as ELF Files__, hence the RAM Disk...

- [__"NuttX Apps and Initial RAM Disk"__](https://lupyuen.github.io/articles/app)

Most of the NuttX Platforms run on __NuttX Flat Mode__, which has NuttX Apps Statically-Linked into the NuttX Kernel.

NuttX Flat Mode works well for Small Microcontrollers. But StarPro64 and other SoCs will need the more sophisticated __NuttX Kernel Mode__...

- [__"NuttX Flat Mode vs Kernel Mode"__](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode)

# Appendix: Port NuttX to StarPro64

_How did we port NuttX to StarPro64? In under One Week?_

We took the NuttX Port of __Milk-V Duo S (Oz64 SG2000)__ and tweaked it for __StarPro64 EIC7700X__, with these minor modifications...

- [__Modified Files: NuttX for StarPro64__](https://github.com/lupyuen2/wip-nuttx/pull/93/files)

Here's what we changed...

<hr>

[arch/risc-v/Kconfig](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-9c348f27c59e1ed0d1d9c24e172d233747ee09835ab0aa7f156da1b7caa6a5fb)

```bash
config ARCH_CHIP_SG2000
	select ARCH_RV_CPUID_MAP
```

TODO
disable thead mmu flags
app addr env
nuttx/arch/risc-v/Kconfig
remove ARCH_MMU_EXT_THEAD

<hr>

[arch/risc-v/include/sg2000/irq.h](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-523f77920746a4b6cb3e02ef9dfb71223593ae328aa8019e8d8fd730b828ab9f)

```c
#define NR_IRQS (RISCV_IRQ_SEXT + 458)
```

EIC7700X supports __458 External Interrupts__...

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 374 |
|:--------------------------------|:---------|
|Max Interrupts | 458

<hr>

[arch/risc-v/src/sg2000/hardware/sg2000_memorymap.h](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-14db47e674d6ddcbffc6f855a536a173b5833e3bd96a3490a45f1ef94e3b2767)

```c
#define SG2000_PLIC_BASE 0x0C000000ul
```

__PLIC Base Address__ is specified here...

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 239 |
|:--------------------------------|:---------|
|PLIC Memory Map | 0x0C00_0000 

<hr>

[arch/risc-v/src/sg2000/hardware/sg2000_plic.h](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-64c2a42d4a59409becf86f2967d2a27ff48635231437f56620d3e86a28002a28)

[(__Multiple Harts__ explained here)](TODO)

```c
/* Interrupt Priority */

#define SG2000_PLIC_PRIORITY (SG2000_PLIC_BASE + 0x000000)

/* Hart 0 S-Mode Interrupt Enable */

#define SG2000_PLIC_ENABLE0     (SG2000_PLIC_BASE + 0x002080)
#define SG2000_PLIC_ENABLE_HART (0x100)

/* Hart 0 S-Mode Priority Threshold */

#define SG2000_PLIC_THRESHOLD0     (SG2000_PLIC_BASE + 0x201000)
#define SG2000_PLIC_THRESHOLD_HART (0x2000)

/* Hart 0 S-Mode Claim / Complete */

#define SG2000_PLIC_CLAIM0     (SG2000_PLIC_BASE + 0x201004)
#define SG2000_PLIC_CLAIM_HART (0x2000)
```

TODO

<hr>

[arch/risc-v/src/sg2000/sg2000_head.S](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-d8bd71e8ea93fc23ec348eeaca3d45f89dc896eff80311583d758d42e6e8fc58)

[(__Multiple Harts__ explained here)](TODO)

```c
  .quad   0x4000000            /* Kernel size (fdt_addr_r-kernel_addr_r) */
```

TODO

```c
real_start:

  /* Print `123` to UART */
  /* Load UART Base Address to Register t0 */
  li  t0, 0x50900000

  /* Load `1` to Register t1 */
  li  t1, 0x31
  /* Store byte from Register t1 to UART Base Address, Offset 0 */
  sb  t1, 0(t0)

  /* Load `2` to Register t1 */
  li  t1, 0x32
  /* Store byte from Register t1 to UART Base Address, Offset 0 */
  sb  t1, 0(t0)

  /* Load `3` to Register t1 */
  li  t1, 0x33
  /* Store byte from Register t1 to UART Base Address, Offset 0 */
  sb  t1, 0(t0)
```

TODO

```c
  /* If a0 (hartid) >= t1 (the number of CPUs), stop here */

  /* TODO: Enable this for SMP
  blt  a0, t1, 3f
  csrw CSR_SIE, zero
  wfi
  */

3:
  /* Set stack pointer to the idle thread stack */
  li a2, 0
  riscv_set_inital_sp SG2000_IDLESTACK_BASE, SMP_STACK_SIZE, a2

  /* TODO: Enable this for SMP
  riscv_set_inital_sp SG2000_IDLESTACK_BASE, SMP_STACK_SIZE, a0
  */
```

<hr>

[arch/risc-v/src/sg2000/sg2000_irq.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-0c39d310c3819d6b7bfecb05f6a203019d0f937b171abe539f299fa37805b366)

[(__Multiple Harts__ explained here)](TODO)

```c
  /* Disable all global interrupts */

  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++)
    {
      addr = SG2000_PLIC_ENABLE0 + (hart * SG2000_PLIC_ENABLE_HART);
      for (offset = 0; offset < (NR_IRQS - RISCV_IRQ_EXT) >> 3; offset += 4)
        {
          putreg32(0x0, addr + offset);          
        }
    }

  /* Clear pendings in PLIC */

  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++)
    {
      addr = SG2000_PLIC_CLAIM0 + (hart * SG2000_PLIC_CLAIM_HART);
      claim = getreg32(addr);
      putreg32(claim, addr);
    }

  /* Set irq threshold to 0 (permits all global interrupts) */

  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++)
    {
      addr = SG2000_PLIC_THRESHOLD0 +
             (hart * SG2000_PLIC_THRESHOLD_HART);
      putreg32(0, addr);
    }
```

TODO

```c
void up_disable_irq(int irq) {
      ...
      /* Clear enable bit for the irq */

      if (0 <= extirq && extirq <= NR_IRQS - RISCV_IRQ_EXT)
        {
          addr = SG2000_PLIC_ENABLE0 + 
                 (boot_hartid * SG2000_PLIC_ENABLE_HART);
          modifyreg32(addr + (4 * (extirq / 32)),
                      1 << (extirq % 32), 0);
        }
```
TODO

```c
void up_enable_irq(int irq) {
      ...
      /* Set enable bit for the irq */

      if (0 <= extirq && extirq <= NR_IRQS - RISCV_IRQ_EXT)
        {
          addr = SG2000_PLIC_ENABLE0 + 
                 (boot_hartid * SG2000_PLIC_ENABLE_HART);
          modifyreg32(addr + (4 * (extirq / 32)),
                      0, 1 << (extirq % 32));
        }
```

<hr>

[arch/risc-v/src/sg2000/sg2000_irq_dispatch.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-75ceaf9a0a70840fc2e15cea303fff5e9d2339d4f524574df94b5d0ec46e37ea)

[(__Multiple Harts__ explained here)](TODO)

```c
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs)
{
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);
  uintptr_t claim = SG2000_PLIC_CLAIM0 + 
                    (boot_hartid * SG2000_PLIC_CLAIM_HART);
      ...
      uintptr_t val = getreg32(claim);
      ...
      /* Then write PLIC_CLAIM to clear pending in PLIC */

      putreg32(irq - RISCV_IRQ_EXT, claim);
```

<hr>

[arch/risc-v/src/sg2000/sg2000_mm_init.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-cacefdc3058a54e86027d411b0a6711d8a322b1750150521d5c640e72daa8b5f)

```c
#define MMU_IO_BASE      (0x00000000ul)
#define MMU_IO_SIZE      (0x80000000ul)
```

We derived the above from the __EIC7700X Memory Map__...

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 380 |
|:--------------------------------|:---------|
| System Memory Map
| System Space (Low) | 0000_0000 to 8000_0000
| Memory Space | 8000_0000 to 10_0000_0000

We removed all __T-Head MMU Extensions__, including __mmu_flush_cache__.

<hr>

[arch/risc-v/src/sg2000/sg2000_start.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-84111f6f800efef513a2420c571ea39fe2068d19cff6c1eab015da0f9755b9c7)

[(__Multiple Harts__ explained here)](TODO)

```c
//// TODO
struct sbiret_s
{
  intreg_t    error;
  uintreg_t   value;
};
typedef struct sbiret_s sbiret_t;
static void sg2000_boot_secondary(void);
static int riscv_sbi_boot_secondary(uintreg_t hartid, uintreg_t addr);
static sbiret_t sbi_ecall(unsigned int extid, unsigned int fid,
                          uintreg_t parm0, uintreg_t parm1,
                          uintreg_t parm2, uintreg_t parm3,
                          uintreg_t parm4, uintreg_t parm5);

#define SBI_EXT_HSM (0x0048534D)
#define SBI_EXT_HSM_HART_START (0x0)

int boot_hartid = -1;

void sg2000_start_s(int mhartid)
{
  /* Configure FPU */

  riscv_fpuconfig();

  if (mhartid != boot_hartid)
    {
      goto cpux;
    }
    ...

cpux:

  /* Non-Boot Hart starts here */

  *(volatile uint8_t *) 0x50900000ul = 'H';
  *(volatile uint8_t *) 0x50900000ul = 'a';
  *(volatile uint8_t *) 0x50900000ul = 'r';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = '0' + mhartid;
  *(volatile uint8_t *) 0x50900000ul = '\r';
  *(volatile uint8_t *) 0x50900000ul = '\n';

  ...

void sg2000_start(int mhartid)
{
  *(volatile uint8_t *) 0x50900000ul = 'H';
  *(volatile uint8_t *) 0x50900000ul = 'e';
  *(volatile uint8_t *) 0x50900000ul = 'l';
  *(volatile uint8_t *) 0x50900000ul = 'l';
  *(volatile uint8_t *) 0x50900000ul = 'o';
  *(volatile uint8_t *) 0x50900000ul = ' ';
  *(volatile uint8_t *) 0x50900000ul = 'N';
  *(volatile uint8_t *) 0x50900000ul = 'u';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = 'X';
  *(volatile uint8_t *) 0x50900000ul = '!';
  *(volatile uint8_t *) 0x50900000ul = '\r';
  *(volatile uint8_t *) 0x50900000ul = '\n';

  *(volatile uint8_t *) 0x50900000ul = 'H';
  *(volatile uint8_t *) 0x50900000ul = 'a';
  *(volatile uint8_t *) 0x50900000ul = 'r';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = '0' + mhartid;
  *(volatile uint8_t *) 0x50900000ul = '\r';
  *(volatile uint8_t *) 0x50900000ul = '\n';
  up_mdelay(1000);  // Wait a while for UART Queue to flush

  /* If Boot Hart is not 0, restart with Hart 0 */

  if (mhartid != 0)
    {
      /* Clear the BSS */

      sg2000_clear_bss();

      /* Restart with Hart 0 */

      riscv_sbi_boot_secondary(0, (uintptr_t)&__start);

      /* Let this Hart idle forever */

      while (true)
        {
          asm("WFI");
        }  
      PANIC(); /* Should not come here */
    }

  /* Init the globals once only. Remember the Boot Hart. */

  if (boot_hartid < 0)
    {
      boot_hartid = mhartid;

      /* Clear the BSS */

      sg2000_clear_bss();

      /* Boot the other cores */

      // TODO: sg2000_boot_secondary();

      /* Copy the RAM Disk */

      sg2000_copy_ramdisk();
      /* Initialize the per CPU areas */
      riscv_percpu_add_hart(mhartid);
    }

/****************************************************************************
 * Name: riscv_hartid_to_cpuid
 *
 * Description:
 *   Convert physical core number to logical core number.
 *
 ****************************************************************************/

int weak_function riscv_hartid_to_cpuid(int hart)
{
  /* Boot Hart is CPU 0. Renumber the Other Harts. */

  if (hart == boot_hartid)
    {
      return 0;
    }
  else if (hart < boot_hartid)
    {
      return hart + 1;
    }
  else
    {
      return hart;
    }
}

/****************************************************************************
 * Name: riscv_cpuid_to_hartid
 *
 * Description:
 *   Convert logical core number to physical core number.
 *
 ****************************************************************************/

int weak_function riscv_cpuid_to_hartid(int cpu)
{
  /* Boot Hart is CPU 0. Renumber the Other Harts. */

  if (cpu == 0)
    {
      return boot_hartid;
    }
  else if (cpu < boot_hartid + 1)
    {
      return cpu - 1;
    }
  else
    {
      return cpu;
    }
}

static void sg2000_boot_secondary(void)
{
  int i;

  for (i = 0; i < CONFIG_SMP_NCPUS; i++)
    {
      if (i == boot_hartid)
        {
          continue;
        }

      riscv_sbi_boot_secondary(i, (uintptr_t)&__start);
    }
}

static int riscv_sbi_boot_secondary(uintreg_t hartid, uintreg_t addr)
{
  sbiret_t ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
                           hartid, addr, 0, 0, 0, 0);

  if (ret.error < 0)
    {
      _err("Boot Hart %d failed\n", hartid);
      PANIC();
    }

  return 0;
}

static sbiret_t sbi_ecall(unsigned int extid, unsigned int fid,
                          uintreg_t parm0, uintreg_t parm1,
                          uintreg_t parm2, uintreg_t parm3,
                          uintreg_t parm4, uintreg_t parm5)
{
  register long r0 asm("a0") = (long)(parm0);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);
  register long r4 asm("a4") = (long)(parm4);
  register long r5 asm("a5") = (long)(parm5);
  register long r6 asm("a6") = (long)(fid);
  register long r7 asm("a7") = (long)(extid);
  sbiret_t ret;

  asm volatile
    (
     "ecall"
     : "+r"(r0), "+r"(r1)
     : "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r6), "r"(r7)
     : "memory"
     );

  ret.error = r0;
  ret.value = (uintreg_t)r1;

  return ret;
}
```

<hr>

[arch/risc-v/src/sg2000/sg2000_timerisr.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-1c190e766d71f3e5a43109b975405c9e43b2d01e50f748b0f0c19a8d942caffe)

```c
#define MTIMER_FREQ 1000000ul
```

<hr>

[boards/risc-v/sg2000/milkv_duos/configs/nsh/defconfig](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-82b3bf6ae151a2f4e1fb9b23de18af9fd683accc70aff2c88e0b5d6d0e26904b)

```bash
CONFIG_16550_REGINCR=4
CONFIG_16550_UART0_BASE=0x50900000
CONFIG_16550_UART0_CLOCK=23040000
CONFIG_16550_UART0_IRQ=125

CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
```

__16550_REGINCR__ is 4 because the UART Registers are spaced 4 bytes apart...

| [EIC7700X Tech Ref #4](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part4.pdf) | Page 524 |
|:--------------------------------|:---------|
| UART Register Offset
| 0x0 | Receive Buffer Register (RBR)
| 0x4 | Interrupt Enable Register (IER)
| 0x8 | Interrupt Identification Register (IIR)

__UART0 Base Address__ is here...

| [EIC7700X Tech Ref #4](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part4.pdf) | Page 353 |
|:--------------------------------|:---------|
| Peripheral Address Space
| UART0 | 0x5090_0000

__Why IRQ 125?__ UART0 Interrupt Number is 100, we add 25 because of TODO...

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 366 |
|:--------------------------------|:---------|
|UART0 Interrupt Number | 100 _(lsp_uart0_intr)_

TODO: __16550_UART0_CLOCK__

<hr>

[drivers/serial/uart_16550.c](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-f208234edbfb636de240a0fef1c85f9cecb37876d5bc91ffb759f70a1e96b1d1)

```c
#ifdef TODO  //  Compute CONFIG_16550_UART0_CLOCK
  /* Enter DLAB=1 */

  u16550_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));
  ...
  /* Clear DLAB */

  u16550_serialout(priv, UART_LCR_OFFSET, lcr);
#endif  // TODO
```

# Appendix: Multiple Harts on StarPro64

_Multiple Harts are problematic. Why?_

Inside EIC7700X SoC: We have __Four Harts__ (RISC-V CPU Cores) numbered 0 to 3.

This SoC will boot OpenSBI on __Any Random Hart__, 0 to 3! Which means U-Boot and NuttX will subsequently boot on the __Same Random Hart__.

_What's the problem?_

NuttX assumes that it always __Boots on Hart 0__. This code __will fail__ when it boots on Harts 1 to 3: [__TODO__](TODO)

_How to fix this?_

Our workaround is to __Always Reboot NuttX on Hart 0__.

TODO

_Can't we start One Hart and ignore the Other Harts?_

TODO: Affinity

_How to enable Multple Harts?_

TODO

# ESWIN AI Sample User Guide

https://github.com/eswincomputing/eic7x-images/releases/tag/Debian-v1.0.0-p550-20241230

https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/ESWIN_AI_Sample_User_Guide.pdf

```text
ESWIN provides users with the desktop version of the Debian image files. the default username and
password for the system are both "eswin / eswin".
Download the Debian-v1.0.0-p550-20241230 version system image via the link
https://github.com/eswincomputing/eic7x-images/releases. The image file is as follows:
EIC7x_Release_Images_p550_20241230
└── hifive-premier-p550
 ├── bootloader_P550.bin
 ├── boot-P550-20250126-011559.ext4
└── root-P550-20250126-011559.ext4
```

# UART

```text
## First Time Only
echo "defscrollback 1000000" >> ~/.screenrc

set -x
for (( ; ; )) do 
  screen /dev/ttyUSB* 115200
  sleep 5
done
```

Same pins as Star64 and Oz64 SG2000

Garbage: Compute CONFIG_16550_UART0_CLOCK

CONFIG_16550_UART0_IRQ=125

100 + 25

# Multiple CPU

https://gist.github.com/lupyuen/7278c35c3d556a5d4574668b54272fef

```text
Starting kernel ...

123Hello NuttX!
2ABC[CPU2] nx_start: Entry
[CPU2] uart_register: Registering /dev/console
[CPU2] uart_register: Registering /dev/ttyS0
[CPU2] dump_assert_info: Current Version: NuttX  12.4.0 01cbd0ca38-dirty Feb 20 2025 19:56:29 risc-v
[CPU2] dump_assert_info: Assertion failed up_cpu_index() == 0: at file: init/nx_start.c:745 task(CPU2): CPU2 IDLE process: Kernel 0x802019a6
[CPU2] up_dump_register: EPC: 0000000080216ffc
```

Boot HART ID = 0. OSTest OK yay!

https://gist.github.com/lupyuen/47170b4c4d7117ac495c5faede48280b

Boot HART ID = 2. Boot fail :-(

https://gist.github.com/lupyuen/66f93f69b29ba77f9b0c9eb7f78f1f95

![TODO](https://lupyuen.org/images/starpro64-hartid0.png)

StarPro64 will boot on a Random Hart: 0 to 3. But NuttX only boots on Hart 0!

We need to fix the PLIC Driver in NuttX, which only works on Hart 0...

- [NuttX boots OK on Hart 0](https://gist.github.com/lupyuen/47170b4c4d7117ac495c5faede48280b)

   ```text
   Boot HART ID              : 0
   ...
   [CPU0] nx_start: Entry
   [CPU0] nx_start: CPU0: Beginning Idle Loop

   NuttShell (NSH) NuttX-12.4.0
   nsh> hello
   Hello, World!!   
   ```

- [NuttX won't boot on other Harts](https://gist.github.com/lupyuen/66f93f69b29ba77f9b0c9eb7f78f1f95)

   ```text
   Boot HART ID              : 2
   ...
   [CPU0] nx_start: Entry
   [CPU0] nx_start: CPU0: Beginning Idle Loop
   [ Stuck here ]
   ```

# PLIC Multiple Harts

Page 240 (Skip the M-Modes)

```text
Address Width Attr. Description
0x0C00_2080 4B RW Start Hart 0 S-Mode interrupt enables
0x0C00_20C0 4B RW End Hart 0 S-Mode interrupt enables

0x0C00_2180 4B RW Start Hart 1 S-Mode interrupt enables
0x0C00_21C0 4B RW End Hart 1 S-Mode interrupt enables

0x0C00_2280 4B RW Start Hart 2 S-Mode interrupt enables
0x0C00_22C0 4B RW End Hart 2 S-Mode interrupt enables
```

- 0x0C00_2080: Hart 0 S-Mode Interrupt Enable
- 0x0C00_2180: Hart 1 S-Mode Interrupt Enable
- 0x0C00_2280: Hart 2 S-Mode Interrupt Enable

Interrupt Enable: Skip 0x100 per hart

Page 241 (Skip the M-Modes)

```text
Address Width Attr. Description
0x0C20_1000 4B RW Hart 0 S-Mode priority threshold
0x0C20_1004 4B RW Hart 0 S-Mode claim/ complete

0x0C20_3000 4B RW Hart 1 S-Mode priority threshold
0x0C20_3004 4B RW Hart 1 S-Mode claim/ complete

0x0C20_5000 4B RW Hart 2 S-Mode priority threshold
0x0C20_5004 4B RW Hart 2 S-Mode claim/ complete
```

priority threshold: Skip 0x2000 per hart

claim/ complete: Skip 0x2000 per hart

[Hart ID 2. OK yay!](https://gist.github.com/lupyuen/0f5d4ad0697bef7839cb92875abba1b0)

[Hart ID 1. OK yay!](https://gist.github.com/lupyuen/9bdfad6d283945effc994923ae99117a)

Fix the sleep. too slow. factor of 25

[waiter_func: Thread 2 waiting on semaphore](https://gist.github.com/lupyuen/5553ee833440ceb3e2a85cdb5515ed65)

[__Watch the Demo on YouTube__](https://youtu.be/70DQ4YlQMMw)

[__See the NuttX Log__](https://gist.github.com/lupyuen/901365650d8f908a7caa431de4e84ff6)

# Build Loop

make

make app

power off

power on

read

power off

# Semaphore Fail

https://gist.github.com/lupyuen/901365650d8f908a7caa431de4e84ff6

```text
user_main: semaphore test
sem_test: Initializing semaphore to 0
sem_test: Starting waiter thread 1
sem_test: Set thread 1 priority to 191

<<
???
>>

sem_test: Starting waiter thread 2
sem_test: Set thread 2 priority to 128
waiter_func: Thread 2 Started
<<<
waiter_func: Thread 2 initial semaphore value = 0
>>>
waiter_func: Thread 2 waiting on semaphore
```

Compare with SG2000: https://github.com/lupyuen/nuttx-sg2000/releases/tag/nuttx-sg2000-2025-02-23

```text
user_main: semaphore test
sem_test: Initializing semaphore to 0
sem_test: Starting waiter thread 1
sem_test: Set thread 1 priority to 191

<<
waiter_func: Thread 1 Started
>>

sem_test: Starting waiter thread 2
waiter_func: Thread 1 initial semaphore value = 0
sem_test: Set thread 2 priority to 128
waiter_func: Thread 1 waiting on semaphore
waiter_func: Thread 2 Started
<<<
waiter_func: Thread 2 initial semaphore value = -1
>>>
waiter_func: Thread 2 waiting on semaphore
sem_test: Starting poster thread 3
```

Thread 1 isn't started!

https://github.com/lupyuen2/wip-nuttx-apps/blob/starpro64/testing/ostest/ostest_main.c#L435-L439

```c
      /* Verify pthreads and semaphores */

      printf("\nuser_main: semaphore test\n");
      sem_test();
      check_test_memory_usage();
```

https://github.com/lupyuen2/wip-nuttx-apps/blob/starpro64/testing/ostest/sem.c#L49-L73

```c
static void *waiter_func(void *parameter)
{
  int id  = (int)((intptr_t)parameter);
  int status;
  int value;

  printf("waiter_func: Thread %d Started\n",  id);

  /* Take the semaphore */

  status = sem_getvalue(&sem, &value);
  if (status < 0)
    {
      printf("waiter_func: "
             "ERROR thread %d could not get semaphore value\n",  id);
      ASSERT(false);
    }
  else
    {
      printf("waiter_func: "
             "Thread %d initial semaphore value = %d\n",  id, value);
    }

  printf("waiter_func: Thread %d waiting on semaphore\n",  id);
  status = sem_wait(&sem);
```

sem_wait:

https://github.com/apache/nuttx/blob/824dd706177444d020ebb20acdc08c294ab0db37/libs/libc/semaphore/sem_wait.c#L59

```c
int sem_wait(FAR sem_t *sem)
{
  int errcode;
  int ret;

  if (sem == NULL)
    {
      set_errno(EINVAL);
      return ERROR;
    }

  /* sem_wait() is a cancellation point */

  if (enter_cancellation_point())
    {
#ifdef CONFIG_CANCELLATION_POINTS
      /* If there is a pending cancellation, then do not perform
       * the wait.  Exit now with ECANCELED.
       */

      errcode = ECANCELED;
      goto errout_with_cancelpt;
#endif
    }

  /* Let nxsem_wait() do the real work */

  ret = nxsem_wait(sem);
  if (ret < 0)
    {
      errcode = -ret;
      goto errout_with_cancelpt;
    }

  leave_cancellation_point();
  return OK;

errout_with_cancelpt:
  set_errno(errcode);
  leave_cancellation_point();
  return ERROR;
}
```

nxsem_wait: https://github.com/lupyuen2/wip-nuttx/blob/starpro64/sched/semaphore/sem_wait.c#L248-L271

```c
int nxsem_wait(FAR sem_t *sem)
{
  /* This API should not be called from interrupt handlers & idleloop */

  DEBUGASSERT(sem != NULL && up_interrupt_context() == false);
  DEBUGASSERT(!OSINIT_IDLELOOP() || !sched_idletask());

  /* If this is a mutex, we can try to get the mutex in fast mode,
   * else try to get it in slow mode.
   */

#if !defined(CONFIG_PRIORITY_INHERITANCE) && !defined(CONFIG_PRIORITY_PROTECT)
  if (sem->flags & SEM_TYPE_MUTEX)
    {
      int32_t old = 1;
      if (atomic_try_cmpxchg_acquire(NXSEM_COUNT(sem), &old, 0))
        {
          return OK;
        }
    }
#endif

  return nxsem_wait_slow(sem);
}
```

nxsem_wait in disassembly: nuttx.S

```text
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:260
  /* If this is a mutex, we can try to get the mutex in fast mode,
   * else try to get it in slow mode.
   */

#if !defined(CONFIG_PRIORITY_INHERITANCE) && !defined(CONFIG_PRIORITY_PROTECT)
  if (sem->flags & SEM_TYPE_MUTEX)
    80204f96:	0044c783          	lbu	a5,4(s1)
    80204f9a:	8b91                	and	a5,a5,4
    80204f9c:	e7a1                	bnez	a5,80204fe4 <nxsem_wait+0xbc>
nxsem_wait_slow():
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:82
  flags = enter_critical_section();
    80204f9e:	b5bfc0ef          	jal	80201af8 <enter_critical_section_wo_note>
    80204fa2:	89aa                	mv	s3,a0
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:88
  if (atomic_fetch_sub(NXSEM_COUNT(sem), 1) > 0)
    80204fa4:	577d                	li	a4,-1
    80204fa6:	0f50000f          	fence	iorw,ow
    80204faa:	04e4a7af          	amoadd.w.aq	a5,a4,(s1)
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:88 (discriminator 1)
    80204fae:	2781                	sext.w	a5,a5
    80204fb0:	04f04e63          	bgtz	a5,8020500c <nxsem_wait+0xe4>
up_irq_save():
/Users/luppy/starpro64/nuttx/include/arch/irq.h:766
  __asm__ __volatile__
    80204fb4:	4a09                	li	s4,2
    80204fb6:	100a3a73          	csrrc	s4,sstatus,s4
this_task():
/Users/luppy/starpro64/nuttx/sched/sched/sched.h:381
    80204fba:	80efc0ef          	jal	80200fc8 <up_this_cpu>
/Users/luppy/starpro64/nuttx/sched/sched/sched.h:381 (discriminator 1)
    80204fbe:	001fe917          	auipc	s2,0x1fe
    80204fc2:	ef290913          	add	s2,s2,-270 # 80402eb0 <g_assignedtasks>
    80204fc6:	00451793          	sll	a5,a0,0x4
    80204fca:	97ca                	add	a5,a5,s2
    80204fcc:	6380                	ld	s0,0(a5)
up_irq_restore():
/Users/luppy/starpro64/nuttx/include/arch/irq.h:792
  __asm__ __volatile__
    80204fce:	100a1073          	csrw	sstatus,s4
nxsem_wait_slow():
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:118 (discriminator 1)
      DEBUGASSERT(rtcb->waitobj == NULL);
    80204fd2:	6c7c                	ld	a5,216(s0)
    80204fd4:	c3a9                	beqz	a5,80205016 <nxsem_wait+0xee>
    80204fd6:	0001b617          	auipc	a2,0x1b
    80204fda:	1a260613          	add	a2,a2,418 # 80220178 <_srodata+0x1200>
    80204fde:	07600593          	li	a1,118
    80204fe2:	b78d                	j	80204f44 <nxsem_wait+0x1c>
nxsem_wait():
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:263
    {
      int32_t old = 1;
      if (atomic_try_cmpxchg_acquire(NXSEM_COUNT(sem), &old, 0))
    80204fe4:	4705                	li	a4,1
    80204fe6:	1004a7af          	lr.w	a5,(s1)
    80204fea:	00e79563          	bne	a5,a4,80204ff4 <nxsem_wait+0xcc>
    80204fee:	1c04a6af          	sc.w.aq	a3,zero,(s1)
    80204ff2:	faf5                	bnez	a3,80204fe6 <nxsem_wait+0xbe>
    80204ff4:	37fd                	addw	a5,a5,-1
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:265
        {
          return OK;
    80204ff6:	4401                	li	s0,0
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:263
      if (atomic_try_cmpxchg_acquire(NXSEM_COUNT(sem), &old, 0))
    80204ff8:	f3dd                	bnez	a5,80204f9e <nxsem_wait+0x76>
/Users/luppy/starpro64/nuttx/sched/semaphore/sem_wait.c:271
        }
    }
#endif

  return nxsem_wait_slow(sem);
}
```

Log sem_wait

https://github.com/lupyuen2/wip-nuttx/blob/starpro64b/sched/semaphore/sem_wait.c#L170-L172

```c
      *(volatile uint8_t *) 0x50900000ul = '3'; ////
      up_switch_context(this_task(), rtcb);
      *(volatile uint8_t *) 0x50900000ul = '4'; ////
```

Output log:

```text
430101010101010101010101010101010100
4343E43n43d43 43o43f43 43t43e43s43t43 43m43e43m43o43r43y43 43u43s43a43g43e43:43
4343V43A43R43I43A43B43L401013E43 43 43B43E43F43O43R43E43 43 43 43A43F43T43E43R43
4343=43=43=43=43=43=43=43=43 43=43=43=43=43=43=43=43=401013 43=43=43=43=43=43=43=43=43
4343a43r43e43n43a43 43 43 43 43 43 43 43843143043043043 43 43 43 43843143043043043
  43o40101010101010101[CPU0] nxtask_activate: ostest pid=21,TCB=0x80413028
430133r43d43b43l43k43s43 43 43 43 43 43 43 43 43 43343 43 43 43 43 43 43 43 43343
4343m43x43o43r43d43b43l43k43 401013 43 43 43743843f43f43843 43 43 43 43743843f43f43843
  43u43o43r43d43b43l43k43s43 43 43 43 43 43443543843843 43 43 43 40101010101[CPU0] nxtask_activate: ostest pid=25,TCB=0x80413e08
43013 43443543843843
4343f43o43r43d43b43l43k43s43 43 43 43 43743c43a43743843 43 43 43 43743c43a401013743843
4343
4343u43s43e43r43_43m43a43i43n43:43 43s43e43m43a43p43h43o43r43e43 43t43e43s43t43
  43s43e43m43_43t43e43s43t43:43 43I43n43i43t43i43a43l43i401013z43i43n43g43 43s43e43m43a43p43h43o43r43e43 43t43o43 43043
  43s43e43m43_43t43e43s43t43:43 43S43t43a43r43t43i43n43g43 43w43a43i43t43er thread 1
sem_test: Set thread 1 priority to 191
sem_test: Starting waiter thread 2
sem_test: Set thread 2 priority to 128
waiter_func: Thread 2 Started
waiter_func: Thread 2 initial semaphore value = 0
waiter_func: Thread 2 waiting on semaphore
```

https://github.com/lupyuen2/wip-nuttx/blob/starpro64b/sched/semaphore/sem_wait.c#L76-L84

```c

  /* The following operations must be performed with interrupts
   * disabled because nxsem_post() may be called from an interrupt
   * handler.
   */

   *(volatile uint8_t *) 0x50900000ul = '5'; ////
   flags = enter_critical_section();
   *(volatile uint8_t *) 0x50900000ul = '6'; ////
```

Output log:

```text
84565631456563045656304565630456563 456563 456563 456563 456563845656314565630456563045656304565456563
      456563o40101010101010101[CPU0] nxtask_activate: ostest pid=21,TCB=0x80413028
010156563563r456563d456563b456563l456563k456563s456563 456563 456563 456563 456563 456563 4565634565633 456563 4565633456563 456563 456563 456563 456563 456563 456563 456563 4565633456563
      456563m456563x456563o456563r456563d456563b456563l456563k456563 4010156563 456563 456563 45656374565638456563f456563f4565638456563 456563 456563 456563 45656374565638456563f456563f4565638456563
      456563u456563o456563r456563d456563b456563l456563k456563s456563 456563 456563 456563 456563 4565634456563545656384565638456563 456563 456563 456563 40101010101[CPU0] nxtask_activate: ostest pid=25,TCB=0x80413e08
456563563 4565634456563545656384565638456563
      456563f456563o456563r456563d456563b456563l456563k456563s456563 456563 456563 456563 4565637456563c456563a45656374565638456563 456563 456563 456563 4565637456563c456563a401015656374565638456563
456563456563
      456563u456563s456563e456563r456563_456563m456563a456563i456563n456563:456563 456563s4565634565633m456563a456563p456563h456563o456563r456563e456563 456563t456563e456563s456563t456563
      456563s456563e456563m456563_456563t456563e456563s456563t456563:456563 456563I456563n456563i456563t456563i456563a456563l456563i4010156563z456563i456563n456563g456563 456563s456563e456563m456563a456563p456563h456563o456563r456563e456563 456563t456563o456563 4565630456563
      456563s456563e456563m456563_456563t456563e456563s456563t456563:456563 456563S456563t456563a456563r456563t456563i456563n456563g456563 456563w456563a456563i456563t4563er thread 1
sem_test: Set thread 1 priority to 191
sem_test: Starting waiter thread 2
sem_test: Set thread 2 priority to 128
waiter_func: Thread 2 Started
waiter_func: Thread 2 initial semaphore value = 0
waiter_func: Thread 2 waiting on semaphore
```

Hang in up_switch_context:

up_switch_context:

```text
000000008020d362 <up_switch_context>:
up_switch_context():
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_switchcontext.c:61
 *   rtcb: Refers to the running task which will be blocked.
 *
 ****************************************************************************/

void up_switch_context(struct tcb_s *tcb, struct tcb_s *rtcb)
{
    8020d362:	1101                	add	sp,sp,-32
    8020d364:	e822                	sd	s0,16(sp)
    8020d366:	e426                	sd	s1,8(sp)
    8020d368:	e04a                	sd	s2,0(sp)
    8020d36a:	ec06                	sd	ra,24(sp)
    8020d36c:	842a                	mv	s0,a0
    8020d36e:	84ae                	mv	s1,a1
up_irq_save():
/Users/luppy/starpro64/nuttx/include/arch/irq.h:766
    8020d370:	4909                	li	s2,2
    8020d372:	10093973          	csrrc	s2,sstatus,s2
up_interrupt_context():
/Users/luppy/starpro64/nuttx/include/arch/irq.h:832
  bool ret = g_interrupt_context[up_this_cpu()];
    8020d376:	c53f30ef          	jal	80200fc8 <up_this_cpu>
/Users/luppy/starpro64/nuttx/include/arch/irq.h:832 (discriminator 1)
    8020d37a:	001f9797          	auipc	a5,0x1f9
    8020d37e:	5de78793          	add	a5,a5,1502 # 80406958 <g_interrupt_context>
    8020d382:	97aa                	add	a5,a5,a0
    8020d384:	0007c783          	lbu	a5,0(a5)
    8020d388:	0ff7f793          	zext.b	a5,a5
up_irq_restore():
/Users/luppy/starpro64/nuttx/include/arch/irq.h:792
  __asm__ __volatile__
    8020d38c:	10091073          	csrw	sstatus,s2
up_switch_context():
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_switchcontext.c:64 (discriminator 1)
  /* Are we in an interrupt handler? */

  if (up_interrupt_context())
    8020d390:	c785                	beqz	a5,8020d3b8 <up_switch_context+0x56>
riscv_savecontext():
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_internal.h:262
  riscv_savefpu(tcb->xcp.regs, riscv_fpuregs(tcb));
    8020d392:	1504b503          	ld	a0,336(s1)
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_internal.h:262 (discriminator 1)
    8020d396:	10850593          	add	a1,a0,264
    8020d39a:	868f30ef          	jal	80200402 <riscv_savefpu>
riscv_restorecontext():
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_internal.h:277
  riscv_restorefpu(tcb->xcp.regs, riscv_fpuregs(tcb));
    8020d39e:	15043503          	ld	a0,336(s0)
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_internal.h:277 (discriminator 1)
    8020d3a2:	10850593          	add	a1,a0,264
    8020d3a6:	8f8f30ef          	jal	8020049e <riscv_restorefpu>
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_internal.h:289
  __asm__ __volatile__("mv tp, %0" : : "r"(tcb));
    8020d3aa:	8222                	mv	tp,s0
up_switch_context():
/Users/luppy/starpro64/nuttx/arch/risc-v/src/common/riscv_switchcontext.c:93
       * head of the ready-to-run list.  It does not 'return' in the
       * normal sense.  When it does return, it is because the blocked
       * task is again ready to run and has execution priority.
       */
    }
}
```

# Thread 1 isn't started!

pthread_create: https://github.com/lupyuen2/wip-nuttx/blob/starpro64b/libs/libc/pthread/pthread_create.c#L88-L93

```c
int pthread_create(FAR pthread_t *thread, FAR const pthread_attr_t *attr,
                   pthread_startroutine_t pthread_entry, pthread_addr_t arg)
{
  return nx_pthread_create(pthread_startup, thread, attr, pthread_entry,
                           arg);
}
```

nx_pthread_create: https://github.com/lupyuen2/wip-nuttx/blob/starpro64b/sched/pthread/pthread_create.c#L179-L412

```c
int nx_pthread_create(pthread_trampoline_t trampoline, FAR pthread_t *thread,
                      FAR const pthread_attr_t *attr,
                      pthread_startroutine_t entry, pthread_addr_t arg)
{
  pthread_attr_t default_attr = g_default_pthread_attr;
  FAR struct pthread_tcb_s *ptcb;
  struct sched_param param;
  FAR struct tcb_s *parent;
  int policy;
  int errcode;
  int ret;

  DEBUGASSERT(trampoline != NULL);

  parent = this_task();
  DEBUGASSERT(parent != NULL);

  /* If attributes were not supplied, use the default attributes */

  if (!attr)
    {
      /* Inherit parent priority by default. except idle */

      if (!is_idle_task(parent))
        {
          default_attr.priority = parent->sched_priority;
        }

      attr = &default_attr;
    }

  /* Allocate a TCB for the new task. */

  ptcb = kmm_zalloc(sizeof(struct pthread_tcb_s));
  if (!ptcb)
    {
      serr("ERROR: Failed to allocate TCB\n");
      return ENOMEM;
    }

  ptcb->cmn.flags |= TCB_FLAG_FREE_TCB;

  /* Initialize the task join */

  nxtask_joininit(&ptcb->cmn);

#ifndef CONFIG_PTHREAD_MUTEX_UNSAFE
  spin_lock_init(&ptcb->cmn.mutex_lock);
#endif

  /* Bind the parent's group to the new TCB (we have not yet joined the
   * group).
   */

  group_bind(ptcb);

#ifdef CONFIG_ARCH_ADDRENV
  /* Share the address environment of the parent task group. */

  ret = addrenv_join(this_task(), (FAR struct tcb_s *)ptcb);
  if (ret < 0)
    {
      errcode = -ret;
      goto errout_with_tcb;
    }
#endif

  if (attr->detachstate == PTHREAD_CREATE_DETACHED)
    {
      ptcb->cmn.flags |= TCB_FLAG_DETACHED;
    }

  if (attr->stackaddr)
    {
      /* Use pre-allocated stack */

      ret = up_use_stack((FAR struct tcb_s *)ptcb, attr->stackaddr,
                         attr->stacksize);
    }
  else
    {
      /* Allocate the stack for the TCB */

      ret = up_create_stack((FAR struct tcb_s *)ptcb, attr->stacksize,
                            TCB_FLAG_TTYPE_PTHREAD);
    }

  if (ret != OK)
    {
      errcode = ENOMEM;
      goto errout_with_tcb;
    }

#if defined(CONFIG_ARCH_ADDRENV) && \
    defined(CONFIG_BUILD_KERNEL) && defined(CONFIG_ARCH_KERNEL_STACK)
  /* Allocate the kernel stack */

  ret = up_addrenv_kstackalloc(&ptcb->cmn);
  if (ret < 0)
    {
      errcode = ENOMEM;
      goto errout_with_tcb;
    }
#endif

  /* Initialize thread local storage */

  ret = tls_init_info(&ptcb->cmn);
  if (ret != OK)
    {
      errcode = -ret;
      goto errout_with_tcb;
    }

  /* Should we use the priority and scheduler specified in the pthread
   * attributes?  Or should we use the current thread's priority and
   * scheduler?
   */

  if (attr->inheritsched == PTHREAD_INHERIT_SCHED)
    {
      /* Get the priority (and any other scheduling parameters) for this
       * thread.
       */

      ret = nxsched_get_param(0, &param);
      if (ret < 0)
        {
          errcode = -ret;
          goto errout_with_tcb;
        }

      /* Get the scheduler policy for this thread */

      policy = nxsched_get_scheduler(0);
      if (policy < 0)
        {
          errcode = -policy;
          goto errout_with_tcb;
        }
    }
  else
    {
      /* Use the scheduler policy and policy the attributes */

      policy                             = attr->policy;
      param.sched_priority               = attr->priority;

#ifdef CONFIG_SCHED_SPORADIC
      param.sched_ss_low_priority        = attr->low_priority;
      param.sched_ss_max_repl            = attr->max_repl;
      param.sched_ss_repl_period.tv_sec  = attr->repl_period.tv_sec;
      param.sched_ss_repl_period.tv_nsec = attr->repl_period.tv_nsec;
      param.sched_ss_init_budget.tv_sec  = attr->budget.tv_sec;
      param.sched_ss_init_budget.tv_nsec = attr->budget.tv_nsec;
#endif
    }

#ifdef CONFIG_SCHED_SPORADIC
  if (policy == SCHED_SPORADIC)
    {
      FAR struct sporadic_s *sporadic;
      sclock_t repl_ticks;
      sclock_t budget_ticks;

      /* Convert timespec values to system clock ticks */

      repl_ticks = clock_time2ticks(&param.sched_ss_repl_period);
      budget_ticks = clock_time2ticks(&param.sched_ss_init_budget);

      /* The replenishment period must be greater than or equal to the
       * budget period.
       */

      if (repl_ticks < budget_ticks)
        {
          errcode = EINVAL;
          goto errout_with_tcb;
        }

      /* Initialize the sporadic policy */

      ret = nxsched_initialize_sporadic(&ptcb->cmn);
      if (ret >= 0)
        {
          sporadic               = ptcb->cmn.sporadic;
          DEBUGASSERT(sporadic != NULL);

          /* Save the sporadic scheduling parameters */

          sporadic->hi_priority  = param.sched_priority;
          sporadic->low_priority = param.sched_ss_low_priority;
          sporadic->max_repl     = param.sched_ss_max_repl;
          sporadic->repl_period  = repl_ticks;
          sporadic->budget       = budget_ticks;

          /* And start the first replenishment interval */

          ret = nxsched_start_sporadic(&ptcb->cmn);
        }

      /* Handle any failures */

      if (ret < 0)
        {
          errcode = -ret;
          goto errout_with_tcb;
        }
    }
#endif

  /* Initialize the task control block */

  ret = pthread_setup_scheduler(ptcb, param.sched_priority, pthread_start,
                                entry);
  if (ret != OK)
    {
      errcode = EBUSY;
      goto errout_with_tcb;
    }

#ifdef CONFIG_SMP
  /* pthread_setup_scheduler() will set the affinity mask by inheriting the
   * setting from the parent task.  We need to override this setting
   * with the value from the pthread attributes unless that value is
   * zero:  Zero is the default value and simply means to inherit the
   * parent thread's affinity mask.
   */

  if (attr->affinity != 0)
    {
      ptcb->cmn.affinity = attr->affinity;
    }
#endif
```

How to set affinity?

# Multiple CPU

boot_hartid=2
hart=0, cpu=1
hart=1, cpu=2
hart=2, cpu=0
hart=3, cpu=3

cpu=0, hart=2
cpu=1, hart=0
cpu=2, hart=1
cpu=3, hart=3

```text
123Hello NuttX!
Hart1
ABC[123Hello NuttX!
Hart0
Hart0
CPU0] nx_start: Entry
[CPU0] uart_register: Registering /dev/console
[CPU0] uart_register: Registering /dev/ttyS0
[CPU0] up_cpu_start: CPU=1
V[CCP[UC0P]U 0]r idsucvm_pc_pauss_ebroto_t:in CfPo:U0  CSurtarretnetd
2er[sCPioU0n]:  nNxu_titdX l e1_2t.r4am.p0o 0l2i6n5e:46 C7P5Ucb0-: diBregtiyn nFeibn g 23I dl20e 2L5o o20p:
 9:44 risc-v
[CPU0] dump_assert_info: Assertion failed (g_cpu_irqset & (1 << cpu)) == 0: at file: irq/irq_csection.c:232 task(CPU0): CPU0 IDLE process: Kernel 0x80201dfa
[CPU0] up_dump_register: EPC: 0000000080202d1a
```

TODO: Support non-zero boot hart.

https://github.com/lupyuen2/wip-nuttx/blob/starpro64c/arch/risc-v/src/common/riscv_macros.S#L383-L423

```text
/****************************************************************************
 * Name: riscv_set_inital_sp
 *
 * Description:
 *   Set inital sp for riscv core. This function should be only called
 *   when initing.
 *
 *   sp (stack top) = sp base + idle stack size * hart id
 *   sp (stack base) = sp (stack top) + idle stack size * - XCPTCONTEXT_SIZE
 *
 *   Note: The XCPTCONTEXT_SIZE byte after stack base is reserved for
 *         up_initial_state since we are already running and using
 *         the per CPU idle stack.
 *
 *   TODO: Support non-zero boot hart.
 *
 * Parameter:
 *   base - Pointer to where the stack is allocated (e.g. _ebss)
 *   size - Stack size for pre cpu to allocate
 *   hartid - Hart id register of this hart (Usually a0)
 *
 ****************************************************************************/
.macro riscv_set_inital_sp base, size, hartid
  la      t0, \base
  li      t1, \size
  mul     t1, \hartid, t1
  add     t0, t0, t1

  /* ensure the last XCPTCONTEXT_SIZE is reserved for non boot CPU */

  bnez \hartid, 998f
  li   t1, STACK_ALIGN_DOWN(\size)
  j    999f

998:
  li   t1, STACK_ALIGN_DOWN(\size - XCPTCONTEXT_SIZE)

999:
  add  t0, t0, t1
  mv   sp, t0
.endm
```

Stack is full:

```text
Starting kernel ...

123Hello NuttX!
Hart2
123123123ABC[CPU0] nx_start: Entry
[CPU0] uart_register: Registering /dev/console
[CPU0] uart_register: Registering /dev/ttyS0
[CPU0] up_cpu_start: CPU=1
VeCCP[UC0P]U 0]r isdcuvm_p_capsus_ebroto_t:i nfCPoU: 0C uStrraertnte d
: [rCsPioU0n:]  Nnuxt_tiXd l e_1t2r.a4m.p0o 9l8ian4e:d 65CPaU601:-d iBretgiy nFnienbg  23I d2le02 5Lo 2op1
 13:42 risc-v
[CPU0] dump_assert_info: Assertion failed (g_cpu_irqset & (1 << cpu)) == 0: at file: irq/irq_csection.c:232 task(CPU0): CPU0 IDLE process: Kernel 0x80201dfa
[CPU0] up_dump_register: EPC: 0000000080202d1a
[CPU0] up_dump_register: A0: 0000000080404d30 A1: 00000000000000e8 A2: 000000008021fc28 A3: 0000000000000000
[CPU0] up_dump_register: A4: 0000000080402740 A5: 0000000000000002 A6: 0000000000000000 A7: 0000000000735049
[CPU0] up_dump_register: T0: 00000000802000c0 T1: 0000000000000007 T2: 0000000000000000 T3: 000000008040d090
[CPU0] up_dump_register: T4: 000000008040d088 T5: 0000000080200000 T6: 00000000ed4ec178
[CPU0] up_dump_register: S0: 0000000000000210 S1: 0000000080402760 S2: 0000000000000000 S3: 000000008021fc28
[CPU0] up_dump_register: S4: 000000008021fb50 S5: 0000000080406968 S6: 00000000000000e8 S7: 0000000000000004
[CPU0] up_dump_register: S8: 0000000080404d30 S9: 8000000200046020 S10: 0000000080201dfa S11: 00000000802022da
[CPU0] up_dump_register: SP: 000000008040cd00 FP: 0000000000000210 TP: 0000000080402760 RA: 0000000080202d1a
[CPU0] dump_stacks: ERROR: Stack pointer is not within the stack
[CPU0] dump_stackinfo: IRQ Stack:
[CPU0] dump_stackinfo:   base: 0x80401e60
[CPU0] dump_stackinfo:   size: 00002048
[CPU0] stack_dump: 0x80402660: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[CPU0] dump_stackinfo: Kernel Stack:
[CPU0] dump_stackinfo:   base: 0
[CPU0] dump_stackinfo:   size: 00003072
[CPU0] stack_dump: 0xc00: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[CPU0] dump_stackinfo: User Stack:
[CPU0] dump_stackinfo:   base: 0x8040b010
[CPU0] dump_stackinfo:   size: 00003056
[CPU0] stack_dump: 0x8040b938: 000000008040b9d0 0000000000000020 0000000080209e02 deadbeefdeadbeef 000000008040b9d0 000000008040b9d0 000000008021f0ea deadbeefdeadbeef
[CPU0] stack_dump: 0x8040b978: 0000000080228928 0000000000000001 000000008040ba20 000000000000000a 0000000080209e02 fffffffffffffffc 000000008040ba20 000000008040ba20
[CPU0] stack_dump: 0x8040b9b8: 000000008021f0ea deadbeefdeadbeef 000000008021fabf 0000000000000001 0000000000000000 000000008040bb80 0000000000000000 fffffffffffffffc
[CPU0] stack_dump: 0x8040b9f8: 000000000000000a 000000008040bae8 000000008021dacc deadbeefdeadbeef 0a0000008022a320 0000000000000000 000000000000002e 000000008040bae8
[CPU0] stack_dump: 0x8040ba38: 000000008020b02a 0000000000002000 0000000000000004 8000000a00006800 0000000000000030 fffffffffffffff3 0000000000000000 000000008040bb38
[CPU0] stack_dump: 0x8040ba78: 0000000000000000 0000000000000000 0000000080043710 0000000000002000 0000000000000004 8000000a00006800 0000000000000000 fffffffffffffff3
[CPU0] stack_dump: 0x8040bab8: 0000000000000000 000000008040bb38 000000008021faa0 0000000000000007 000000008021beb0 deadbeefdeadbeef deadbeef00000035 000000008021da8c
[CPU0] stack_dump: 0x8040baf8: 000000008021da2a 000000008020bdc6 deadbeef0000000a 0000000080200000 0000000000000000 deadbeefdeadbeef 000000008020c052 deadbeefdeadbeef
[CPU0] stack_dump: 0x8040bb38: 000000008040bb70 deadbeefdeadbeef 000000008020c072 0000000000000002 000000008040bb70 0000000080402760 0000000080202310 000000008022a320
[CPU0] stack_dump: 0x8040bb78: 0000000000000000 0000000080402740 0000000000000002 0000000000000009 000000000000000f deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef
[CPU0] stack_dump: 0x8040bbb8: deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef deadbeefdeadbeef
[CPU0] stack_dump: 0x8040bbf8: deadbeefdeadbeef 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[CPU0] dump_fatal_info: Dump CPU1: RUNNING
[CPU0] dump_fatal_info: Dump CPU2: RUNNING
[CPU0] dump_fatal_info: Dump CPU3: RUNNING
[CPU0] dump_tasks:    PID GROUP   CPU PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
[CPU0] dump_tasks:   ----   ---     0 --- -------- ------- --- ------- ---------- ---------------- 0x80401e60      2048         0     0.0%    irq
[CPU0] dump_tasks:   ----   ---     1 --- -------- ------- --- ------- ---------- ---------------- 0x80401660      2048         0     0.0%    irq
[CPU0] dump_tasks:   ----   ---     2 --- -------- ------- --- ------- ---------- ---------------- 0x80400e60      2048         0     0.0%    irq
[CPU0] dump_tasks:   ----   ---     3 --- -------- ------- --- ------- ---------- ---------------- 0x80400660      2048         0     0.0%    irq
[CPU0] dump_task:       0     0     0   0 FIFO     Kthread -   Running            0000000000000000 0x8040b010      3056       712    23.2%    CPU0 IDLE
[CPU0] dump_task:       1     0     1   0 FIFO     Kthread -   Running            0000000000000000 0x8040bc10      3056       528    17.2%    CPU1 IDLE
[CPU0] dump_task:       2     0     2   0 FIFO     Kthread -   Running            0000000000000000 0x8040c810      3056      2824    92.4%!   CPU2 IDLE
[CPU0] dump_task:       3     0     3   0 FIFO     Kthread -   Running            0000000000000000 0x8040d410      3056      3056   100.0%!   CPU3 IDLE
```

# Disable SMP

https://github.com/lupyuen2/wip-nuttx/commit/6b321e1cd56bf74b0529711bfad62780291f841b

Remove these from defconfig:

```bash
CONFIG_SMP=y
CONFIG_SMP_NCPUS=4
```

[Apache NuttX RTOS on StarPro64: OSTest runs OK yay! (ESWIN EIC7700X)](https://gist.github.com/lupyuen/2823528f7b53375f080256bc798b2bf5)

[__Watch the Demo on YouTube__](https://youtu.be/Yr7aYNIMUsw)

Apache NuttX RTOS on StarPro64: Build Script

https://gist.github.com/lupyuen/16cd1ba3a56de1928cb956503ebdb9ac

We could actually allow a Remote Developer to boot and test NuttX on StarPro64 ... From anywhere in the world!

![TODO](https://lupyuen.org/images/starpro64-ostest.png)

# TODO

https://github.com/rockos-riscv

🤔 Booting #StarPro64 @ThePine64 (#RISCV #ESWIN EIC7700X)

Source: https://pine64.org/2024/10/02/september_2024/#starpro64

#RISCV ESWIN EIC7700X Technical Reference Manual (#StarPro64)

https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual

#RISCV #ESWIN EIC7700X: Qwen #LLM on NPU (#StarPro64)

Source: https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/ESWIN_AI_Sample_User_Guide.pdf

#RISCV #ESWIN EIC7700X: NPU Driver (#StarPro64)

https://github.com/eswincomputing/linux-stable/tree/linux-6.6.18-EIC7X/drivers/soc/eswin/ai_driver/npu

__llama.cpp__ _(C++)_

https://github.com/ggml-org/llama.cpp

or __ollama__ _(GoLang)_

https://github.com/ollama/ollama/blob/main/model/models/llama/model.go

_Qwen is an odd name innit?_

Qwen will sound confusing to Bilingual Folks...

- It's NOT supposed to rhyme with Gwen Stefani / Gwen Stacy

- Instead it's pronounced __"Q Wen"__

- And it confuses me: _"Q = Question"_ and _"Wen = 问 = Question"_, thus contracting to _"QQ"_, which means _"Bouncy"_

- Thankfully _"Q Wen"_ actually means something: __"千问"__ _(Ask a Thousand Questions, "Qian1 Wen4")_

- Which is short for __"通义千问"__ _(Tong1 Yi4 Qian1 Wen4)_, meaning [__"通情，达义"__](https://baike.baidu.com/item/%E9%80%9A%E4%B9%89/64394178)

<span style="font-size:80%">

_(Here's an idea for Sci-Fi Horror: We installed an LLM Sensor in a Remote Uninhabited Island. One day our LLM Sensor sends us sinister words: "EVIL", "DEATH", "DOOM"...)_

</span>

southern islands of singapore
identify pic of creatures or sea life
rainforest critters or underwater creatures
in one word
"DUCK", "OCTOPUS"

strings
ghidra
npu driver
ollama

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

[__lupyuen.org/src/starpro64.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/starpro64.md)
