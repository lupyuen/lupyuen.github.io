# StarPro64 EIC7700X RISC-V SBC: Maybe LLM on NPU on NuttX?

📝 _16 Apr 2025_

![StarPro64 EIC7700X RISC-V SBC: Maybe LLM on NPU on NuttX?](https://lupyuen.org/images/starpro64-title.jpg)

[(Watch the __NuttX Demo__ on YouTube)](https://youtu.be/Yr7aYNIMUsw)

[__StarPro64 EIC7700X__](https://pine64.org/2024/10/02/september_2024/#starpro64) is the (literally) _Hot_ New RISC-V SBC by PINE64.

TODO

_(Thanks to PINE64 for providing the Prototype StarPro64)_

![StarPro64 EIC7700X RISC-V SBC](https://lupyuen.org/images/starpro64-fan2.jpg)

# ESWIN EIC7700X RISC-V SoC

_StarPro64: Isn't it a souped-up Star64?_

Nope it's a totally different beast! _(From a different SoC Maker)_

Inside StarPro64 is the __ESWIN EIC7700X SoC__. It has __Four RISC-V Cores__ and it's based on __SiFive Architecture__ _(a bit like JH7110 SoC)_

![ESWIN EIC7700X SoC](https://lupyuen.org/images/starpro64-arch.jpg)

But its super-speedy [__Neural Processing Unit__](https://www.sifive.com/document-file/eic7700x-datasheet) (NPU) makes it a very special _(llama?)_ beast. Later we'll talk about the [__Fun LLM Experiments__](TODO) that we can run on the NPU.

_(20 TOPS INT8: 20 Trillion Ops Per Second for 8-bit Integers)_

> ![ESWIN EIC7700X NPU](https://lupyuen.org/images/starpro64-npu.jpg)

[__EIC7700X Technical Reference Manual__](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual) is probably the best among the RISC-V SoCs _(BL808, SG2000, JH7110)_

- [__Part 1: Hardware, System, Interrupts__](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf)

- [__Part 2: Memory Interface, Image / Video Processors__](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part2.pdf)

- [__Part 3: Video Input / Output__](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part3.pdf)

- [__Part 4: Peripherals, USB, PCI, Ethernet__](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part4.pdf)

We go hands-on...

![Connecting USB UART Dongle to StarPro64](https://lupyuen.org/images/starpro64-uart.jpg)

# Boot Without MicroSD

_What happens if we boot StarPro64? Fresh from the box?_

We monitor the __UART0 Port__ for Debug Messages. Connect our [__USB UART Dongle__](https://pine64.com/product/serial-console-woodpecker-edition/) (CH340 or CP2102) to these pins (pic above)...

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

Power up the board with a __Power Adapter__. [(Same one as __Star64 JH7110__)](https://pine64.com/product/12v-5a-us-power-supply/)

We'll see [__OpenSBI__](https://lupyuen.github.io/articles/sbi)...

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

Then [__U-Boot Bootloader__](https://docs.u-boot.org/en/latest/index.html)...

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

![HDMI Output will show U-Boot, but not OpenSBI](https://lupyuen.org/images/starpro64-hdmi.jpg)

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

Uncompress the files and rename them. Copy them to a [__USB Drive__](https://qoto.org/@lupyuen/114036829364673417) (not MicroSD)

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

We'll skip the [__MicroSD Image__](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/sdcard-rockos-20250123-210346.img.zst), because [__MicroSD Interface__](https://qoto.org/@lupyuen/114036829364673417) wasn't working reliably on our Prototype StarPro64.

![StarPro64 with eMMC](https://lupyuen.org/images/starpro64-emmc.jpg)

# Prepare the Linux Image

_How to load the Linux Image into eMMC?_

Based on the [__ESWIN Official Doc__](https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/Development_board_image_installation_and_upgrade_manual.pdf)...

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

![StarPro64 with USB Fan](https://lupyuen.org/images/starpro64-fan.jpg)

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

But don't power it with the USB Port on StarPro64! Instead, connect it to our [__Smart Power Plug__](https://lupyuen.github.io/articles/starpro64#smart-power-plug).

_Anything else we should worry about?_

The [__MicroSD Interface__](https://qoto.org/@lupyuen/114036829364673417) wasn't working well on our Prototype StarPro64. The MicroSD Card deactivated itself after a bit of U-Boot Access.

Hence the __Headless Ironman__: USB Drive on StarPro64...

![Headless Ironman: USB Drive on StarPro64](https://lupyuen.org/images/starpro64-ironman.jpg)

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

Sadly the [__Preview Version__](https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/) of RockOS won't boot correctly on our Prototype StarPro64 (pic below). Hopefully we'll sort this out real soon and do some [__Serious NPU LLM__](https://lupyuen.github.io/articles/starpro64#llm-on-npu-on-nuttx)!

[(See the __Boot Log__)](https://gist.github.com/lupyuen/89e1e87e7f213b6f52f31987f254b32f)

![RockOS won't boot correctly on our Prototype StarPro64](https://lupyuen.org/images/starpro64-linux.jpg)

# Settings for U-Boot Bootloader

_Bummer. What else can we boot on StarPro64?_

Let's snoop around [__U-Boot Bootloader__](https://docs.u-boot.org/en/latest/index.html). And figure out how to boot [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html).

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

- U-Boot supports booting over TFTP: [__Trivial File Transfer Protocol__](https://lupyuen.github.io/articles/tftp)

- It will load the __Kernel Image__ _(Linux / NuttX)_ into RAM at __`0x8400` `0000`__

- Then it will move the Kernel Image to __`0x8020` `0000`__ and boot there

- Also it loads the __Device Tree__ into __`0x8800` `0000`__

Thanks U-Boot! You told us everything we need to Boot NuttX...

![Booting NuttX over TFTP](https://lupyuen.org/images/starpro64-flow2.jpg)

# Boot NuttX over TFTP

_How to boot NuttX over TFTP? (Pic above)_

1.  Install our __TFTP Server__: Follow the [__instructions here__](https://lupyuen.github.io/articles/tftp#install-tftp-server)

1.  Copy these files to our TFTP Server...

    [__NuttX Image: Image-starpro64__](https://github.com/lupyuen2/wip-nuttx/releases/download/sg2000-1/TODO)

    [__Device Tree: jh7110-star64-pine64.dtb__](https://github.com/lupyuen2/wip-nuttx/releases/download/sg2000-1/TODO)

    ```bash
    ## Copy NuttX Image and Device Tree to TFTP Server
    scp Image tftpserver:/tftpboot/Image-starpro64
    scp jh7110-star64-pine64.dtb tftpserver:/tftpboot/
    ssh tftpserver ls -l /tftpboot/
    ```

    [(How to __Build NuttX__ ourselves)](https://lupyuen.github.io/articles/starpro64#appendix-build-nuttx-for-starpro64)

    (NuttX won't read the __Device Tree__)

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
    ## kernel_addr_r=0x84000000
    dhcp ${kernel_addr_r} ${tftp_server}:Image-starpro64

    ## Load the Device Tree from TFTP Server
    ## fdt_addr_r=0x88000000
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb

    ## Set the RAM Address of Device Tree
    ## fdt_addr_r=0x88000000
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    fdt addr ${fdt_addr_r}

    ## Boot the NuttX Image with the Device Tree
    ## kernel_addr_r=0x84000000
    ## fdt_addr_r=0x88000000
    ## TODO: Fix the Device Tree, it's not needed by NuttX
    booti ${kernel_addr_r} - ${fdt_addr_r}
    ```

    <span style="font-size:80%">

    [(U-Boot dropping chars? Try __iTerm > Edit > Paste Special > Paste Slowly__)](https://lupyuen.github.io/articles/starpro64#paste-slowly)

    </span>

1.  NuttX boots OK on StarPro64 yay! (Pic below)

    ```bash
    NuttShell (NSH) NuttX-12.4.0
    nsh> uname -a
    NuttX 12.4.0 83424f8d26 Feb 24 2025 06:50:22 risc-v milkv_duos

    nsh> hello
    Hello, World!!

    nsh> getprime
    getprime took 148 msec    

    user_main: Exiting
    ostest_main: Exiting with status 0
    ```

    [(See the __NuttX Log__)](https://gist.github.com/lupyuen/2823528f7b53375f080256bc798b2bf5)

    [(Watch the __Demo on YouTube__)](https://youtu.be/Yr7aYNIMUsw)

1.  How did we port NuttX to StarPro64? Check the details here...

    [__"Port NuttX to StarPro64"__](https://lupyuen.github.io/articles/starpro64#appendix-port-nuttx-to-starpro64)

![NuttX boots OK on StarPro64 yay!](https://lupyuen.org/images/starpro64-ostest.png)

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

<span style="font-size:80%">

[(U-Boot dropping chars? Try __iTerm > Edit > Paste Special > Paste Slowly__)](https://lupyuen.github.io/articles/starpro64#paste-slowly)

</span>

TODO: [(What about __Static IP__?)](https://github.com/lupyuen/nuttx-sg2000/issues/1)

TODO: [(How to __Undo Auto-Boot__)](https://github.com/lupyuen/nuttx-sg2000/issues/1#issuecomment-2114415245)

TODO: Press Ctrl-C to stop

Now comes the really fun part, that turns StarPro64 EIC7700X into a totally different beast from Star64 JH7110...

![StarPro64 with Touchscreen](https://lupyuen.org/images/starpro64-touchscreen.jpg)

# LLM on NPU on NuttX?

_Oh really? Large Language Model on Single-Board Computer? (Eyes roll)_

Hear me out...

1.  [__20 TOPS INT8__](https://www.eswincomputing.com/en/bocupload/2024/06/19/17187920991529ene8q.pdf): That's the spec of the speedy __Neural Processing Unit__ (NPU) inside StarPro64. _(20 Trillion Ops Per Second for 8-bit Integers)_

    Yeah an [__Offline Disconnected LLM__](https://github.com/ggml-org/llama.cpp?tab=readme-ov-file#description) will run _(somewhat)_ OK on any CPU. But this NPU is designed for such LLMs. _(Goodbye "TensorFlow Lite")_

1.  [__Qwen LLM__](https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/ESWIN_AI_Sample_User_Guide.pdf) runs locally on EIC7700X NPU today. Probably Next: [__Llama LLM__](https://www.llama.com/) and [__DeepSeek LLM__](https://github.com/deepseek-ai/DeepSeek-LLM)?

    _(Qwen 2 with 0.5 Billion Parameters, pic below)_

    ![Qwen LLM on ETC7700X NPU](https://lupyuen.org/images/starpro64-qwen.jpg)

1.  __Offline Disconnected LLM on SBC__ might be useful for __Smart Home Security__...

    _"Hi LLM: Please connect my Home Security System to this Doorbell Camera and my IKEA Zigbee Lights and Xiaomi Motion Sensor and Samsung TV"_

1.  __Creature Sensor__ Maybe? A Remote Sensor that uses Cameras to identify Rainforest Critters and Underwater Creatures. But everything it sees becomes ultra-compressed into __16 bytes of text__...

    _"DUCK!" "OCTOPUS!" (Pic below)_

1.  [__EIC7700X NPU Driver__](https://github.com/eswincomputing/linux-stable/tree/linux-6.6.18-EIC7X/drivers/soc/eswin/ai_driver/npu) is Dual-Licensed: BSD and GPL. Which means we can run it on all kinds of platforms and build interesting apps.

1.  __Will it be Expensive?__ We hear that StarPro64 will be priced _super affordably_. Works with a Touchscreen too. (Pic above)

    This is the right time to experiment with an __Offline Disconnected LLM__!

![LLM Creature Sensor: A Remote Sensor that uses Cameras to identify Rainforest Critters and Underwater Creatures. But everything it sees becomes ultra-compressed into 16 bytes of text](https://lupyuen.org/images/starpro64-sensor.jpg)

<span style="font-size:80%">

(Here's an idea for Sci-Fi Horror: We install an LLM Sensor in a Remote Uninhabited Island. One day we receive sinister words from our LLM Sensor: "EVIL!", "DEATH!", "DOOM!"...)

</span>

_Isn't Linux a little wonky on StarPro64?_

Ah here's our opportunity to create a _"Power Efficient" (?)_ LLM with NuttX...

- We port the [__EIC7700X NPU Driver__](https://github.com/eswincomputing/linux-stable/tree/linux-6.6.18-EIC7X/drivers/soc/eswin/ai_driver/npu) to NuttX. _(Dual-Licensed: BSD and GPL)_

- To Execute the LLM Models: We'll need [__llama.cpp__](https://github.com/ggml-org/llama.cpp) _(C++)_ or [__ollama__](https://github.com/ollama/ollama/blob/main/model/models/llama/model.go) _(GoLang)_

_Odd name innit: Qwen?_

__Qwen__ will sound confusing to Bilingual Folks...

- It's NOT supposed to rhyme with Gwen Stefani / Gwen Stacy

- Instead it's pronounced __"Q Wen"__

- And it confuses me: _"Q = Question"_ and _"Wen = 问 = Question"_, thus contracting to _"QQ"_, which means _"Bouncy"_

- Thankfully _"Q Wen"_ actually means something: __"千问"__ _(Ask a Thousand Questions, "Qian1 Wen4")_

- Which is short for __"通义千问"__ _(Tong1 Yi4 Qian1 Wen4)_, meaning [__"通情，达义"__](https://baike.baidu.com/item/%E9%80%9A%E4%B9%89/64394178)

![StarPro64 with Smart Power Plug](https://lupyuen.org/images/starpro64-flow.jpg)

# Smart Power Plug

_Flipping StarPro64 on and off. Again and again. Must be an easier way?_

Try a __Smart Power Plug__ (pic above), integrated with our Build Script.

In our [__Demo Video__](https://youtu.be/Yr7aYNIMUsw): Skip to [__00:35__](https://youtu.be/Yr7aYNIMUsw?t=35) and watch our Build Script auto-power up StarPro64...

```bash
TODO
```

How it works? Here's our __Build Script__: [run.sh](https://gist.github.com/lupyuen/16cd1ba3a56de1928cb956503ebdb9ac#file-run-sh-L118-L163)

```bash
## Omitted: Build NuttX Image
TODO

## Get the Home Assistant Token, copied from http://localhost:8123/profile/security
## export token=xxxx
. $HOME/home-assistant-token.sh

## Power Off the SBC
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

## Wait Manually for SBC Testing to complete
## Don't wait too long, it will overheat!
echo Press Enter to Power Off
read

## Power Off the SBC, because it will overheat!
## Excessive Heatiness needs Oldenlandia Cooling Water?  
curl \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "automation.starpro64_off"}' \
  http://localhost:8123/api/services/automation/trigger
```

[(See the __Build Script__)](https://gist.github.com/lupyuen/16cd1ba3a56de1928cb956503ebdb9ac#file-run-sh-L118-L163)

[(See the __Build Log__](TODO)

![Smart Power Plug in IKEA App and Google Home](https://lupyuen.org/images/starpro64-power1.jpg)

This script assumes that we have...

- Installed a [__Home Assistant Server__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _(Works fine with Docker)_

- Added the Smart Power Plug to [__Google Assistant__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _"StarPro64 Power" (pic above)_

- Installed the [__Google Assistant SDK__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug) for Home Assistant

  _(So we don't need Zigbee programming)_

- Created the [__Power Automation__](https://lupyuen.github.io/articles/sg2000a#call-the-home-assistant-api) in Home Assistant

  _"StarPro64 Power On"_ and _"StarPro64 Power Off" (pic below)_

![Smart Power Plug in Home Assistant](https://lupyuen.org/images/starpro64-power2.jpg)

_Smart Power Plug might disconnect USB UART sometimes?_

To work around this: We run a loop for the __UART Terminal__...

```bash
## First Time Only
echo "defscrollback 1000000" >> ~/.screenrc

## On Power Off: USB Serial might disconnect
## So we reconnect forever
set -x
for (( ; ; )) do 
  screen /dev/ttyUSB* 115200
  sleep 5
done
```

_(We could actually allow a Remote Developer to boot and test NuttX on StarPro64... From anywhere in the world!)_

Remember the [__USB Fan__](https://lupyuen.github.io/articles/starpro64#starpro64-gets-smokin-hot)? It goes into our Smart Power Plug as a Power Jenga like so...

> ![USB Fan goes into our Smart Power Plug as a Power Jenga](https://lupyuen.org/images/starpro64-power3.jpg)

# What's Next

We're upstreaming StarPro64 to __NuttX Mainline__ right now! Stay tuned for updates.

Many Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. 

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

![NuttX boots only on Hart 0](https://lupyuen.org/images/starpro64-hartid0.png)

# Appendix: Multiple Harts on StarPro64

_Multiple Harts are problematic. Why?_

Inside EIC7700X SoC: We have __Four Harts__ (RISC-V CPU Cores) numbered 0 to 3.

This SoC will boot OpenSBI on __Any Random Hart__, 0 to 3! Which means U-Boot and NuttX will subsequently boot on the __Same Random Hart__.

_What's the problem?_

NuttX assumes that it always __Boots on Hart 0__. (Pic above)

This code __will fail__ when NuttX boots on Harts 1 to 3: [__riscv_set_inital_sp__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_macros.S#L383-L423)

```bash
## Set inital sp for riscv core. This function should be only called when initing.
## TODO: Support Non-Zero Boot Hart.
.macro riscv_set_inital_sp base, size, hartid
  la      t0, \base
  li      t1, \size
  mul     t1, \hartid, t1
  add     t0, t0, t1

  ## Ensure the last XCPTCONTEXT_SIZE is reserved for non boot CPU
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

_How to fix this?_

Our workaround is to [__Always Reboot NuttX on Hart 0__](https://lupyuen.github.io/articles/starpro64#nuttx-start-code)...

- __If Boot Hart is Not 0:__

  Restart NuttX with Hart 0

- __If Boot Hart is 0:__

  Continue Starting NuttX

_Harts vs CPUs: What's the difference?_

NuttX insists on booting with CPU 0. Otherwise it fails with this [__nx_start Error__](https://gist.github.com/lupyuen/7278c35c3d556a5d4574668b54272fef)...

```bash
[CPU2] dump_assert_info:
Assertion failed up_cpu_index() == 0: 
at file: init/nx_start.c:745 task(CPU2):
CPU2 IDLE process: Kernel 0x802019a6
```

That's why we [__Renumber the CPUs__](https://lupyuen.github.io/articles/starpro64#nuttx-start-code): Boot Hart is always __CPU 0__. Other Harts become __CPUs 1 to 3__. For Example: If _boot_hartid=2_ then...
- _hart=0, cpu=1_
- _hart=1, cpu=2_
- _hart=2, cpu=0_
- _hart=3, cpu=3_

_Can't we use One Hart and ignore the Other Harts?_

OK Mister Cold-Harted... We tried [__Enabling One Hart Only (CPU 0)__](https://github.com/lupyuen2/wip-nuttx/commits/starpro64c). But OSTest [__hangs at sem_test__](https://gist.github.com/lupyuen/901365650d8f908a7caa431de4e84ff6)..

```bash
## OSTest hangs for StarPro64 when we enable One Hart only...
user_main: semaphore test
sem_test: Initializing semaphore to 0
sem_test: Starting waiter thread 1
sem_test: Set thread 1 priority to 191
## Oops: Thread 1 is NOT started!

sem_test: Starting waiter thread 2
sem_test: Set thread 2 priority to 128
waiter_func: Thread 2 Started

## Oops: Semaphore Value should be -1!
waiter_func: Thread 2 initial semaphore value = 0
waiter_func: Thread 2 waiting on semaphore
## Hangs here
```

Compare the above with [__SG2000 sem_test__](https://github.com/lupyuen/nuttx-sg2000/releases/tag/nuttx-sg2000-2025-02-23)...

```bash
## OSTest runs OK for SG2000...
user_main: semaphore test
sem_test: Initializing semaphore to 0
sem_test: Starting waiter thread 1
sem_test: Set thread 1 priority to 191
## Yep Thread 1 is started
waiter_func: Thread 1 Started

sem_test: Starting waiter thread 2
waiter_func: Thread 1 initial semaphore value = 0
sem_test: Set thread 2 priority to 128
waiter_func: Thread 1 waiting on semaphore
waiter_func: Thread 2 Started

## Yep Semaphore Value is -1
waiter_func: Thread 2 initial semaphore value = -1
waiter_func: Thread 2 waiting on semaphore
sem_test: Starting poster thread 3
## Completes successfully
```

Here's the problem: [__sem_test__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/sem.c#L159-L253) calls [__nx_pthread_create__](https://github.com/apache/nuttx/blob/master/sched/pthread/pthread_create.c#L179-L412) to create a PThread for Thread #1...

```c
int nx_pthread_create(...) { ...
#ifdef CONFIG_SMP
  // pthread_setup_scheduler() will set the affinity mask by inheriting the
  // setting from the parent task.  We need to override this setting
  // with the value from the pthread attributes unless that value is
  // zero:  Zero is the default value and simply means to inherit the
  // parent thread's affinity mask.
  if (attr->affinity != 0) {
    ptcb->cmn.affinity = attr->affinity;
  }
#endif
```

But the New Thread defaults to __No CPU Affinity__, it __Lacks Affinity for CPU 0__.

So it gets allocated to __Another CPU__. Which never runs! 

Hence [__sem_test loops forever__](https://github.com/apache/nuttx-apps/blob/master/testing/ostest/sem.c#L244-L253) waiting for the Semaphore Value to change.

[(Watch the __Demo on YouTube__)](https://youtu.be/70DQ4YlQMMw)

[(See the __NuttX Log__](https://gist.github.com/lupyuen/901365650d8f908a7caa431de4e84ff6)

_In Future: How to enable Multiple Harts?_

To __Enable Multiple Harts__ in future, we undo these changes...

- [__"StarPro64: Disable SMP"__](https://github.com/lupyuen2/wip-nuttx/commit/6b321e1cd56bf74b0529711bfad62780291f841b)

Remember to update the [__StarPro64 defconfig__](https://github.com/lupyuen2/wip-nuttx/commit/6b321e1cd56bf74b0529711bfad62780291f841b#diff-82b3bf6ae151a2f4e1fb9b23de18af9fd683accc70aff2c88e0b5d6d0e26904b)...

```bash
## Enable SMP with 4 CPUs
CONFIG_SMP=y
CONFIG_SMP_NCPUS=4
```

And remember to fix [__riscv_set_inital_sp__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_macros.S#L383-L423).

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

    [(See the __Build Script__)](https://gist.github.com/lupyuen/16cd1ba3a56de1928cb956503ebdb9ac)

    [(See the __Build Log__](TODO)

    [(See the __Build Outputs__)](TODO)

1.  The steps above assume that we've installed our TFTP Server, according to the [__instructions here__](https://lupyuen.github.io/articles/tftp#install-tftp-server)

1.  Then follow these steps to boot NuttX on StarPro64...

    [__"Boot NuttX over TFTP"__](https://lupyuen.github.io/articles/starpro64#boot-nuttx-over-tftp)

1.  Powering StarPro64 on and off can get tiresome. Try a Smart Power Plug, integrated with our Build Script...

    [__"Smart Power Plug"__](https://lupyuen.github.io/articles/starpro64#smart-power-plug)

1.  How did we port NuttX to StarPro64? Check the details here...

    [__"Port NuttX to StarPro64"__](https://lupyuen.github.io/articles/starpro64#appendix-port-nuttx-to-starpro64)

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

## RISC-V Boot Code

[_arch/risc-v/src/sg2000/sg2000_head.S_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-d8bd71e8ea93fc23ec348eeaca3d45f89dc896eff80311583d758d42e6e8fc58)

This is the __RISC-V Boot Code__ that runs first when U-Boot Bootloader starts NuttX.

In the __Linux Kernel Header__: We modified the Kernel Size based on U-Boot `fdt_addr_r` - `kernel_addr_r`.

This ensures that the __Entire NuttX Image__ (including Initial RAM Disk) will be copied correctly from `kernel_addr_r` _(0x8400_0000)_ to `loadaddr` _(0x8020_0000)_

```c
/* Linux Kernel Header*/
__start:
  ...
  .quad  0x4000000  /* Kernel size (fdt_addr_r-kernel_addr_r) */
```

We inserted this code to print "`123`" to UART0 at startup...

```c
/* NuttX Boots Here */
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

The Original Code assumes that we always __Boot at Hart 0__. But EIC7700X will [__Boot From Any Hart__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64). (0 to 3)

This modification allows NuttX to Boot from any Hart...

```c
  /* TODO SMP: Enable this for SMP
  /* If a0 (hartid) >= t1 (the number of CPUs), stop here
  blt  a0, t1, 3f
  csrw CSR_SIE, zero
  wfi
  */

3:
  /* Set stack pointer to the idle thread stack */
  li a2, 0
  riscv_set_inital_sp SG2000_IDLESTACK_BASE, SMP_STACK_SIZE, a2

  /* TODO SMP: Enable this for SMP
  riscv_set_inital_sp SG2000_IDLESTACK_BASE, SMP_STACK_SIZE, a0
  */
```

Right now we support __One Single Hart__ for EIC7700X. "`TODO` `SMP`" flags the code that will be modified (in future) to support Multiple Harts for EIC7700X.

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

## NuttX Start Code

[_arch/risc-v/src/sg2000/sg2000_start.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-84111f6f800efef513a2420c571ea39fe2068d19cff6c1eab015da0f9755b9c7)

NuttX boots here, called by the RISC-V Boot Code (from above). We made these changes to allow [__Booting from Any Hart__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)...

- __If Boot Hart is Not 0:__

  Restart NuttX with Hart 0

- __If Boot Hart is 0:__

  Continue Starting NuttX

```c
// We remember the Boot Hart ID (0 to 3)
int boot_hartid = -1;

// NuttX boots here, called by the RISC-V Assembly Boot Code
void sg2000_start(int mhartid) {

  // UART Driver is not up yet. We print the primitive way.
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

  // Print the Hart ID (0 to 3)
  *(volatile uint8_t *) 0x50900000ul = 'H';
  *(volatile uint8_t *) 0x50900000ul = 'a';
  *(volatile uint8_t *) 0x50900000ul = 'r';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = '0' + mhartid;
  *(volatile uint8_t *) 0x50900000ul = '\r';
  *(volatile uint8_t *) 0x50900000ul = '\n';
  up_mdelay(1000);  // Wait a while for UART Queue to flush

  // If Boot Hart is not 0: Restart NuttX with Hart 0
  if (mhartid != 0) {

    //  Clear the BSS and Restart with Hart 0
    //  __start points to our RISC-V Assembly Start Code
    sg2000_clear_bss();
    riscv_sbi_boot_secondary(0, (uintptr_t)&__start);

    // Let this Hart idle forever (while Hart 0 runs)
    while (true) { asm("WFI"); }  
    PANIC();  // Should never come here
  }

  // Else Boot Hart is 0: We have successfully booted NuttX on Hart 0!
  if (boot_hartid < 0) {

    // Init the globals once only. Remember the Boot Hart.
    // Clear the BSS
    boot_hartid = mhartid;
    sg2000_clear_bss();

    // TODO SMP: Start the Other Harts by calling OpenSBI
    // sg2000_boot_secondary();

    // Copy the RAM Disk
    // Initialize the per CPU areas
    sg2000_copy_ramdisk();
    riscv_percpu_add_hart(mhartid);
  }
  // Omitted: Call sg2000_start_s
```

The code below will be used (in future) to support [__Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)...

```c
// Boot NuttX on the Hart
void sg2000_start_s(int mhartid) {

  // Configure the FPU
  // If this is not the Boot Hart: Jump to cpux
  riscv_fpuconfig();
  if (mhartid != boot_hartid) { goto cpux; }

  // Omitted: Boot Hart starts here and calls nx_start()
  ...

cpux:
  // TODO SMP: Non-Boot Hart starts here.
  // We print the Hart ID and init the NuttX CPU
  *(volatile uint8_t *) 0x50900000ul = 'H';
  *(volatile uint8_t *) 0x50900000ul = 'a';
  *(volatile uint8_t *) 0x50900000ul = 'r';
  *(volatile uint8_t *) 0x50900000ul = 't';
  *(volatile uint8_t *) 0x50900000ul = '0' + mhartid;
  *(volatile uint8_t *) 0x50900000ul = '\r';
  *(volatile uint8_t *) 0x50900000ul = '\n';
  riscv_cpu_boot(mhartid);
```

How to __Restart NuttX on Hart 0__? By calling __OpenSBI__...

```c
// We start a Hart (0 to 3) by calling OpenSBI
// addr points to our RISC-V Assembly Start Code
static int riscv_sbi_boot_secondary(uintreg_t hartid, uintreg_t addr) {

  // Make an ECALL to OpenSBI
  sbiret_t ret = sbi_ecall(
    SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
    hartid, addr, 0, 0, 0, 0
  );

  // Check for OpenSBI Errors
  if (ret.error < 0) { _err("Boot Hart %d failed\n", hartid); PANIC(); }
  return 0;
}

// Make an ECALL to OpenSBI
static sbiret_t sbi_ecall(unsigned int extid, unsigned int fid, uintreg_t parm0, uintreg_t parm1, uintreg_t parm2, uintreg_t parm3, uintreg_t parm4, uintreg_t parm5) {
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

// OpenSBI returns an Error Code and Result Value
struct sbiret_s {
  intreg_t    error;
  uintreg_t   value;
};
typedef struct sbiret_s sbiret_t;

// These are the Standard OpenSBI Extension Codes
#define SBI_EXT_HSM (0x0048534D)
#define SBI_EXT_HSM_HART_START (0x0)
```

[__For Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64) in future: We shall start the other Non-Boot Harts by calling OpenSBI...

```c
// TODO SMP: Start the other Non-Boot Harts by calling OpenSBI
static void sg2000_boot_secondary(void) {
  for (int i = 0; i < CONFIG_SMP_NCPUS; i++) {
    if (i == boot_hartid) { continue; }
    riscv_sbi_boot_secondary(i, (uintptr_t)&__start);
  }
}
```

[__For Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64) in future: NuttX insists on [__Booting with CPU 0 Only__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64). Thus we set __Boot Hart as CPU 0__, and we Renumber the Other Harts...

```c
// TODO SMP: Convert Hart ID to CPU ID.
// Boot Hart is CPU 0. Renumber the Other Harts.
int weak_function riscv_hartid_to_cpuid(int hart) {
  if (hart == boot_hartid)
    { return 0; }
  else if (hart < boot_hartid)
    { return hart + 1; }
  else
    { return hart; }
}

// TODO SMP: Convert CPU ID to Hart ID.
// Boot Hart is CPU 0. Renumber the Other Harts.
int weak_function riscv_cpuid_to_hartid(int cpu) {
  if (cpu == 0)
    { return boot_hartid; }
  else if (cpu < boot_hartid + 1)
    { return cpu - 1; }
  else
    { return cpu; }
}
```

__For Example:__ If _boot_hartid=2_ then...
- _hart=0, cpu=1_
- _hart=1, cpu=2_
- _hart=2, cpu=0_
- _hart=3, cpu=3_

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

## PLIC Interrupt Controller

[_arch/risc-v/include/sg2000/irq.h_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-523f77920746a4b6cb3e02ef9dfb71223593ae328aa8019e8d8fd730b828ab9f)

```c
// Number of External Interrupts
// Offset by RISCV_IRQ_SEXT
#define NR_IRQS (RISCV_IRQ_SEXT + 458)
```

That's because EIC7700X supports __458 External Interrupts__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 374 |
|:--------------------------------|:---------|
|Max Interrupts | 458

</div>
</p>
<hr>

[_arch/risc-v/src/sg2000/hardware/sg2000_memorymap.h_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-14db47e674d6ddcbffc6f855a536a173b5833e3bd96a3490a45f1ef94e3b2767)

```c
// PLIC Base Address
#define SG2000_PLIC_BASE 0x0C000000ul
```

__PLIC Base Address__ is specified here...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 239 |
|:--------------------------------|:---------|
|PLIC Memory Map | _0x0C00_0000_ 

</div>
</p>
<hr>

[_arch/risc-v/src/sg2000/hardware/sg2000_plic.h_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-64c2a42d4a59409becf86f2967d2a27ff48635231437f56620d3e86a28002a28)

```c
// PLIC Interrupt Priority: Single Global Register
#define SG2000_PLIC_PRIORITY (SG2000_PLIC_BASE + 0x000000)

// Hart 0 S-Mode Interrupt Enable and Offset Between Harts
#define SG2000_PLIC_ENABLE0     (SG2000_PLIC_BASE + 0x002080)
#define SG2000_PLIC_ENABLE_HART (0x100)

// Hart 0 S-Mode Priority Threshold and Offset Between Harts
#define SG2000_PLIC_THRESHOLD0     (SG2000_PLIC_BASE + 0x201000)
#define SG2000_PLIC_THRESHOLD_HART (0x2000)

// Hart 0 S-Mode Claim / Complete and Offset Between Harts
#define SG2000_PLIC_CLAIM0     (SG2000_PLIC_BASE + 0x201004)
#define SG2000_PLIC_CLAIM_HART (0x2000)
```

__Interrupt Enable: PLIC_ENABLE_HART__ is _0x100_ because we skip _0x100_ bytes per Hart...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 240 |
|:--------------------------------|:---------|
| _(Skip the M-Modes)_
| _0x0C00_2080_ | Start Hart 0 S-Mode interrupt enables
| _0x0C00_2180_ | Start Hart 1 S-Mode interrupt enables
| _0x0C00_2280_ | Start Hart 2 S-Mode interrupt enables

</div>
</p>

__Priority Threshold: PLIC_THRESHOLD_HART__ is _0x2000_ because we skip _0x2000_ bytes per Hart

__Claim / Complete: PLIC_CLAIM_HART__ is _0x2000_ because we skip _0x2000_ bytes per Hart

Which comes from this...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 241 |
|:--------------------------------|:---------|
| _(Skip the M-Modes)_
| _0x0C20_1000_ | Hart 0 S-Mode Priority Threshold
| _0x0C20_1004_ | Hart 0 S-Mode Claim / Complete
| _0x0C20_3000_ | Hart 1 S-Mode Priority Threshold
| _0x0C20_3004_ | Hart 1 S-Mode Claim / Complete
| _0x0C20_5000_ | Hart 2 S-Mode Priority Threshold
| _0x0C20_5004_ | Hart 2 S-Mode Claim / Complete

</div>
</p>

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

<hr>

[_arch/risc-v/src/sg2000/sg2000_irq.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-0c39d310c3819d6b7bfecb05f6a203019d0f937b171abe539f299fa37805b366)

In future we shall support [__Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64). That's why we extended this code to __Initialize the Interrupts__ for Harts 0 to 3...

```c
// Initialize the Interrupts
void up_irqinitialize(void) { ...

  // Disable all global interrupts
  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++) {
    addr = SG2000_PLIC_ENABLE0 + (hart * SG2000_PLIC_ENABLE_HART);
    for (offset = 0; offset < (NR_IRQS - RISCV_IRQ_EXT) >> 3; offset += 4) {
      putreg32(0x0, addr + offset);          
    }
  }

  // Clear pendings in PLIC
  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++) {
    addr = SG2000_PLIC_CLAIM0 + (hart * SG2000_PLIC_CLAIM_HART);
    claim = getreg32(addr);
    putreg32(claim, addr);
  }

  // Set irq threshold to 0 (permits all global interrupts)
  for (hart = 0; hart < CONFIG_SMP_NCPUS; hart++) {
    addr = SG2000_PLIC_THRESHOLD0 + (hart * SG2000_PLIC_THRESHOLD_HART);
    putreg32(0, addr);
  }
```

We do this to __Disable the Interrupts__ for Boot Hart 0 to 3 (in future)

```c
// Disable the Interrupt
void up_disable_irq(int irq) { ...

  // Clear enable bit for the irq
  if (0 <= extirq && extirq <= NR_IRQS - RISCV_IRQ_EXT) {
    addr = SG2000_PLIC_ENABLE0 + 
           (boot_hartid * SG2000_PLIC_ENABLE_HART);
    modifyreg32(addr + (4 * (extirq / 32)),
                1 << (extirq % 32), 0);
  }
```

And this to __Enable the Interrupts__ for Boot Hart 0 to 3 (in future)

```c
// Enable the Interrupt
void up_enable_irq(int irq) { ...

  // Set enable bit for the irq
  if (0 <= extirq && extirq <= NR_IRQS - RISCV_IRQ_EXT) {
    addr = SG2000_PLIC_ENABLE0 + 
           (boot_hartid * SG2000_PLIC_ENABLE_HART);
    modifyreg32(addr + (4 * (extirq / 32)),
                0, 1 << (extirq % 32));
  }
```

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

<hr>

[_arch/risc-v/src/sg2000/sg2000_irq_dispatch.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-75ceaf9a0a70840fc2e15cea303fff5e9d2339d4f524574df94b5d0ec46e37ea)

In future we shall support [__Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64). That's why we extended this code to __Dispatch the Interrupt__ for Boot Hart 0 to 3...

```c
// Dispatch the Interrupt
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs) {
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);
  uintptr_t claim = SG2000_PLIC_CLAIM0 + 
                    (boot_hartid * SG2000_PLIC_CLAIM_HART);
  ...
  // Read the PLIC_CLAIM for the Boot Hart
  uintptr_t val = getreg32(claim);
  ...
  // Write PLIC_CLAIM to clear pending for Boot Hart
  putreg32(irq - RISCV_IRQ_EXT, claim);
```

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

## Memory Map

[_arch/risc-v/src/sg2000/sg2000_mm_init.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-cacefdc3058a54e86027d411b0a6711d8a322b1750150521d5c640e72daa8b5f)

```c
// I/O Memory Map
#define MMU_IO_BASE (0x00000000ul)
#define MMU_IO_SIZE (0x80000000ul)
```

We derived the above from the __EIC7700X Memory Map__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 380 |
|:--------------------------------|:---------|
| System Memory Map
| System Space (Low) | _0x0000_0000_ to _0x8000_0000_
| Memory Space | _0x8000_0000_ to _0x10_0000_0000_

</div>
</p>

The rest of the Memory Map is identical to SG2000. We removed all __T-Head MMU Extensions__, including __mmu_flush_cache__.

## NuttX Config

[_arch/risc-v/Kconfig_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-9c348f27c59e1ed0d1d9c24e172d233747ee09835ab0aa7f156da1b7caa6a5fb)

In future we shall support [__Multiple Harts__](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64). This __Arch Config__ will enable the __Hart-To-CPU Mapping__ we saw earlier: _riscv_hartid_to_cpuid, riscv_cpuid_to_hartid_

```bash
config ARCH_CHIP_SG2000
	select ARCH_RV_CPUID_MAP
```

Also we removed __ARCH_MMU_EXT_THEAD__. (T-Head MMU Extensions)

[(__Multiple Harts__ explained)](https://lupyuen.github.io/articles/starpro64#appendix-multiple-harts-on-starpro64)

<hr>

[_boards/risc-v/sg2000/milkv_duos/configs/nsh/defconfig_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-82b3bf6ae151a2f4e1fb9b23de18af9fd683accc70aff2c88e0b5d6d0e26904b)

We modified the __NuttX Board Config__ for UART...

```bash
## UART0 Configuration
CONFIG_16550_REGINCR=4
CONFIG_16550_UART0_BASE=0x50900000
CONFIG_16550_UART0_CLOCK=23040000
CONFIG_16550_UART0_IRQ=125

## Enable Scheduler Debugging
CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
```

__16550_REGINCR__ is 4 because the UART Registers are spaced 4 bytes apart...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #4](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part4.pdf) | Page 524 |
|:--------------------------------|:---------|
| UART Register Offset
| _0x0_ | Receive Buffer Register (RBR)
| _0x4_ | Interrupt Enable Register (IER)
| _0x8_ | Interrupt Identification Register (IIR)

</div>
</p>

__UART0 Base Address__ is here...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #4](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part4.pdf) | Page 353 |
|:--------------------------------|:---------|
| Peripheral Address Space
| UART0 | _0x5090_0000_

</div>
</p>

__Why IRQ 125?__ UART0 Interrupt Number is 100, we add 25 because of _RISCV_IRQ_SEXT_...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| [EIC7700X Tech Ref #1](https://github.com/eswincomputing/EIC7700X-SoC-Technical-Reference-Manual/releases/download/v1.0.0-20250103/EIC7700X_SoC_Technical_Reference_Manual_Part1.pdf) | Page 366 |
|:--------------------------------|:---------|
|UART0 Interrupt Number | 100 _(lsp_uart0_intr)_

</div>
</p>

<hr>

[_drivers/serial/uart_16550.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-f208234edbfb636de240a0fef1c85f9cecb37876d5bc91ffb759f70a1e96b1d1)

We commented out this code that __Configures the UART Clock__...

```c
// Configure the UART Clock
static int u16550_setup(FAR struct uart_dev_s *dev) { ...

#ifdef TODO
  // Enter DLAB=1
  u16550_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));
  // Omitted: Configure the UART Clock
  ...
  // Clear DLAB
  u16550_serialout(priv, UART_LCR_OFFSET, lcr);
#endif
```

This will be restored when we have computed [__16550_UART0_CLOCK__](https://lupyuen.github.io/articles/release#appendix-uart-clock-for-jh7110).

<hr>

[_arch/risc-v/src/sg2000/sg2000_timerisr.c_](https://github.com/lupyuen2/wip-nuttx/pull/93/files#diff-1c190e766d71f3e5a43109b975405c9e43b2d01e50f748b0f0c19a8d942caffe)

Finally we changed the __RISC-V Timer Frequency__...

```c
// Previously for SG2000: 25000000ul
#define MTIMER_FREQ 1000000ul
```

## Paste Slowly

_U-Boot Bootloader is dropping chars when we paste long lines. How now brown cow?_

__In iTerm__: Try __Edit > Paste Special > Paste Slowly__

__But Before That:__ Click __Settings > Advanced > Pasteboard__

- _"Delay in seconds between chunks when Pasting Slowly"_

  Set to __1 second__

- _"Number of bytes to paste in each chunk when Pasting Slowly"_

  Set to __16 bytes__

<hr>

And that's how we ported NuttX to StarPro64! [(See the __NuttX Log__)](https://gist.github.com/lupyuen/2823528f7b53375f080256bc798b2bf5)

![NuttX boots OK on StarPro64 yay!](https://lupyuen.org/images/starpro64-ostest.png)
