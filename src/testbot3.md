# PR Test Bot for PinePhone (Apache NuttX RTOS)

📝 _23 Mar 2025_

![PR Test Bot for PinePhone (Apache NuttX RTOS)](https://lupyuen.org/images/testbot3-title.jpg)

Earlier we created a [__PR Test Bot__](TODO) that will __Build and Test__ the Pull Requests for __Apache NuttX RTOS__. Our Test Bot kicks into action when we post a [__PR Comment__](TODO)...

```bash
## For Oz64 SG2000 RISC-V SBC:
@nuttxpr test oz64:nsh

## For QEMU Emulator: Arm64 and RISC-V
@nuttxpr test TODO
@nuttxpr test TODO
```

Today we extend our Test Bot to Build and Test the Pull Requests for [__PINE64 PinePhone__](TODO). Yep on the __Real PinePhone Hardware__!

```bash
@nuttxpr test pinephone:nsh
```

- We used Special Hardware: __SDWire MicroSD Multiplexer__ _(pic above)_

- Controlled by a Single-Board Computer: __Yuzuki Avaota-A1__ _(Open Hardware)_

- __PinePhone Test Bot__ kinda works!

- Though __PinePhone Battery__ complicates Hardware Testing

- We might pivot to another __Arm64 Single-Board Computer__

- Maybe we'll port NuttX to __Allwinner A527 SoC__?

TODO: I bought. Yuzuki Avaota-A1 is open hardware. [_(Quite affordable too: $55)_](https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/)

TODO: I ordered another _(batteryless)_ [__Arm64 Single-Board Computer__](https://nuttx.apache.org/docs/latest/platforms/arm64/bcm2711/boards/raspberrypi-4b/index.html). Hope it works better with Test Bot than PinePhone!

TODO: Pic of SDWire

# SDWire MicroSD Multiplexer

_MicroSD Multiplexer: What's that?_

[__SDWire MicroSD Multiplexer__](TODO) (pic above) is a brilliant gadget that allows __Two Devices__ to access One Single __MicroSD Card__. _(One device at a time, not simultaneously)_

_Why would we need it?_

For Testing NuttX on __Arm64 Devices__ _(PinePhone)_: 

# Install Linux

```bash
https://github.com/AvaotaSBC/AvaotaOS/releases

https://github.com/AvaotaSBC/AvaotaOS/releases/download/0.3.0.4/AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz

xz -d AvaotaOS-0.3.0.4-noble-gnome-arm64-avaota-a1.img.xz
Etcher

标准用户：

用户名：avaota
密码：avaota
根用户

用户名：root
密码：avaota

ssh avaota@avaota-a1
```

Avaota A1: Boot to AvaotaOS Noble GNOME OK!

https://gist.github.com/lupyuen/dd4beb052ce07c36d41d409631c6d68b

Armbian Ubuntu won't boot:

https://gist.github.com/lupyuen/32876ee9696d60e6e95c839c0a937ad4

```text
ERROR:   Error initializing runtime service opteed_fast
[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x412fd050]
[    0.000000] Linux version 5.15.154-legacy-sun55iw3-syterkit (build@armbian) (aarch64-linux-gnu-gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP PREEMPT Mon Jan 6 07:05:34 UTC 2025
[    0.000000] Machine model: Avaota A1
[    0.000000] earlycon: uart8250 at MMIO32 0x0000000002500000 (options '')
[    0.000000] printk: bootconsole [uart8250] enabled
[    0.000000] Reserved memory: created DMA memory pool at 0x000000004ac00000, size 0 MiB
[    0.000000] OF: reserved mem: initialized node vdev0buffer@4ac00000, compatible id shared-dma-pool
[    0.000000] Reserved memory: created DMA memory pool at 0x000000004ae00000, size 0 MiB
[    0.000000] OF: reserved mem: initialized node vdev0buffer@4ae00000, compatible id shared-dma-pool
[    0.000000] Reserved memory: created DMA memory pool at 0x000000004ae44000, size 0 MiB
[    0.000000] OF: reserved mem: initialized node dsp0_rpbuf@4ae44000, compatible id shared-dma-pool
[    0.000000] Kernel panic - not syncing: Failed to allocate page table page
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.15.154-legacy-sun55iw3-syterkit #1
[    0.000000] Hardware name: Avaota A1 (DT)
[    0.000000] Call trace:
[    0.000000]  dump_backtrace+0x0/0x1b0
[    0.000000]  show_stack+0x18/0x24
[    0.000000]  dump_stack_lvl+0x7c/0xa8
[    0.000000]  dump_stack+0x18/0x34
[    0.000000]  panic+0x188/0x334
[    0.000000]  early_pgtable_alloc+0x34/0xa8
[    0.000000]  __create_pgd_mapping+0x3a8/0x6a4
[    0.000000]  map_kernel_segment+0x74/0xdc
[    0.000000]  paging_init+0x104/0x528
[    0.000000]  setup_arch+0x264/0x57c
[    0.000000]  start_kernel+0x7c/0x8f0
[    0.000000]  __primary_switched+0xa0/0xa8
[    0.000000] ---[ end Kernel panic - not syncing: Failed to allocate page table page ]---
```

Factory default: Boot to Android

https://gist.github.com/lupyuen/f0195a2ccdd40906b80e2a360b1782ba

```text
Hit any key to stop autoboot:  0
ramdisk use init boot
Android's image name: arm64
[04.634]Starting kernel ...

[04.637][mmc]: mmc exit start
[04.654][mmc]: mmc 2 exit ok
NOTICE:  [SCP] :wait arisc ready....
NOTICE:  [SCP] :arisc version: [001bf1581dbae091dc22b8772b739ccafacdd4b5rid-]
NOTICE:  [SCP] :arisc startup ready
NOTICE:  [SCP] :arisc startup notify message feedback
NOTICE:  [SCP] :sunxi-arisc driver is starting
BL3-1: Next image address = 0x40080000
BL3-1: Next image spsr = 0x3c5
[    0.000000][    T0] Booting Linux on physical CPU 0x0000000000 [0x412fd050]
[    0.000000][    T0] Linux version 5.15.119-gc08c29131003 (yuzuki@YuzukiKoddo) (Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6), LLD 14.0.6) #22 SMP PREEMPT Sat Sep 14 19:49:30 CST 2024
[    0.000000][    T0] Machine model: AvaotaSBC,Avaota A1
[    0.000000][    T0] Stack Depot is disabled
[    0.000000][    T0] KVM is not available. Ignoring kvm-arm.mode
[    0.000000][    T0] earlycon: uart8250 at MMIO32 0x0000000002500000 (options '')
[    0.000000][    T0] printk: bootconsole [uart8250] enabled
[    0.000000][    T0] efi: UEFI not found.
[    0.000000][    T0] [Firmware Bug]: Kernel image misaligned at boot, please fix your bootloader!
[    0.000000][    T0] OF: reserved mem: 0x0000000000020000..0x000000000002ffff (64 KiB) nomap non-reusable mcu0iram@20000
[    0.000000][    T0] OF: reserved mem: 0x0000000000030000..0x0000000000037fff (32 KiB) nomap non-reusable mcu0dram0@30000
[    0.000000][    T0] OF: reserved mem: 0x0000000000038000..0x000000000003ffff (32 KiB) nomap non-reusable mcu0dram1@38000
[    0.000000][    T0] OF: reserved mem: 0x0000000007280000..0x00000000072bffff (256 KiB) nomap non-reusable riscvsram0@7280000
[    0.000000][    T0] OF: reserved mem: 0x00000000072c0000..0x00000000072fffff (256 KiB) nomap non-reusable riscvsram1@72c0000
[    0.000000][    T0] OF: reserved mem: 0x0000000048000000..0x0000000048ffffff (16384 KiB) map non-reusable bl31
[    0.000000][    T0] OF: reserved mem: 0x000000004a000000..0x000000004a9fffff (10240 KiB) nomap non-reusable dsp0ddr@4a000000
[    0.000000][    T0] OF: reserved mem: 0x000000004ab00000..0x000000004ab0ffff (64 KiB) nomap non-reusable dsp_share_space@4ab00000
[    0.000000][    T0] Reserved memory: created DMA memory pool at 0x000000004ac00000, size 0 MiB
```

Avaota A1: Default U-Boot in eMMC. No network :-(

https://gist.github.com/lupyuen/366f1ffefc8231670ffd58a3b88ae8e5

# USB UART

```bash
##  Allow the user to access the USB UART ports
sudo usermod -a -G dialout $USER
##  Logout and login to refresh the permissions
logout
```

# Connect SDWire

#SDWire MicroSD Multiplexer connected to #Yuzuki Avaota-A1 SBC ... When was the last you saw a Micro-USB Data Cable 😂

```text
## Disconnect then reconnect
$ dmesg

[ 1829.473620] usb 1-1: USB disconnect, device number 2
[ 1829.473656] usb 1-1.1: USB disconnect, device number 3
[ 1829.535380] usb 1-1.2: USB disconnect, device number 4

[ 1829.813511] usb 1-1: new full-speed USB device number 5 using xhci-hcd
[ 1833.469452] usb 1-1: new high-speed USB device number 6 using xhci-hcd
[ 1833.617735] usb 1-1: New USB device found, idVendor=0424, idProduct=2640, bcdDevice= 0.00
[ 1833.617771] usb 1-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[ 1833.625490] hub 1-1:1.0: USB hub found
[ 1833.625626] hub 1-1:1.0: 3 ports detected
[ 1833.913607] usb 1-1.1: new high-speed USB device number 7 using xhci-hcd
[ 1834.019412] usb 1-1.1: New USB device found, idVendor=0424, idProduct=4050, bcdDevice= 1.76
[ 1834.019446] usb 1-1.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 1834.019465] usb 1-1.1: Product: Ultra Fast Media Reader
[ 1834.019480] usb 1-1.1: Manufacturer: Generic
[ 1834.019494] usb 1-1.1: SerialNumber: 000000264001
[ 1834.021126] usb-storage 1-1.1:1.0: USB Mass Storage device detected
[ 1834.023454] scsi host0: usb-storage 1-1.1:1.0
[ 1834.101528] usb 1-1.2: new full-speed USB device number 8 using xhci-hcd
[ 1834.209026] usb 1-1.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
[ 1834.209060] usb 1-1.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 1834.209080] usb 1-1.2: Product: sd-wire
[ 1834.209094] usb 1-1.2: Manufacturer: SRPOL
[ 1834.209108] usb 1-1.2: SerialNumber: sd-wire_02-09
[ 1835.034363] scsi 0:0:0:0: Direct-Access     Generic  Ultra HS-SD/MMC  1.76 PQ: 0 ANSI: 0
[ 1835.036652] sd 0:0:0:0: [sda] 30318592 512-byte logical blocks: (15.5 GB/14.5 GiB)
[ 1835.037460] sd 0:0:0:0: [sda] Write Protect is off
[ 1835.037486] sd 0:0:0:0: [sda] Mode Sense: 23 00 00 00
[ 1835.038526] sd 0:0:0:0: [sda] No Caching mode page found
[ 1835.044589] sd 0:0:0:0: [sda] Assuming drive cache: write through
[ 1835.055251]  sda: sda1
[ 1835.058244] sd 0:0:0:0: [sda] Attached SCSI removable disk

avaota@avaota-a1:~$
```

# Compile SDWire

Getting Started

https://docs.dasharo.com/transparent-validation/sd-wire/getting-started/

Usage

https://docs.dasharo.com/transparent-validation/sd-wire/usage-validation/

```bash
sudo apt-get install libftdi1-dev libpopt-dev cmake pkg-config
git clone https://github.com/3mdeb/sd-mux
cd sd-mux
mkdir build
cd build
cmake ..
make
sudo make install
```

Test SDWire. Default Blue LED, MicroSD Enabled. Open `dmesg -w` in a new window.

```bash
$ sudo sd-mux-ctrl --list
Number of FTDI devices found: 1
Dev: 0, Manufacturer: SRPOL, Serial: sd-wire_02-09, Description: sd-wire

## Test Server: Blue LED
$ sudo sd-mux-ctrl --device-serial=sd-wire_02-09 --ts

dmesg:
[ 4132.212882] sd 0:0:0:0: [sda] 30318592 512-byte logical blocks: (15.5 GB/14.5 GiB)
[ 4132.214999] sda: detected capacity change from 0 to 30318592
[ 4132.216313]  sda: sda1

## Test Device: Green LED
$ sudo sd-mux-ctrl --device-serial=sd-wire_02-09 --dut

dmesg:
[ 4089.816219] sda: detected capacity change from 30318592 to 0
```

# Mount MicroSD

```bash
avaota@avaota-a1:~/sd-mux/build$ mkdir /tmp/sda1
avaota@avaota-a1:~/sd-mux/build$ sudo mount /dev/sda1 /tmp/sda1
avaota@avaota-a1:~/sd-mux/build$ ls -l /tmp/sda1
total 5453
-rwxr-xr-x 1 root root  118737 Dec 31 06:18 Image.gz
-rwxr-xr-x 1 root root 4275261 May 23  2021 Image.gz.old
-rwxr-xr-x 1 root root     653 May 23  2021 boot.scr
-rwxr-xr-x 1 root root 1078500 May 23  2021 initramfs.gz
-rwxr-xr-x 1 root root   35865 May 23  2021 sun50i-a64-pinephone-1.0.dtb
-rwxr-xr-x 1 root root   36080 May 23  2021 sun50i-a64-pinephone-1.1.dtb
-rwxr-xr-x 1 root root   36162 May 23  2021 sun50i-a64-pinephone-1.2.dtb
```

Unmount:

```bash
$ sudo umount /tmp/sda1
```

# Inside SDWire

https://github.com/3mdeb/sd-mux/blob/master/src/main.cpp

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

[__lupyuen.org/src/testbot3.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot3.md)
