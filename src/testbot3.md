# PR Test Bot for PinePhone (Apache NuttX RTOS)

📝 _23 Mar 2025_

![PR Test Bot for PinePhone (Apache NuttX RTOS)](https://lupyuen.org/images/testbot3-title.jpg)

TODO

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
[  206.598377] usb 1-1: new high-speed USB device number 2 using xhci-hcd
[  206.746607] usb 1-1: New USB device found, idVendor=0424, idProduct=2640, bcdDevice= 0.00
[  206.746641] usb 1-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[  206.755688] hub 1-1:1.0: USB hub found
[  206.755793] hub 1-1:1.0: 3 ports detected
[  207.042371] usb 1-1.1: new high-speed USB device number 3 using xhci-hcd
[  207.152422] usb 1-1.1: New USB device found, idVendor=0424, idProduct=4050, bcdDevice= 1.76
[  207.152456] usb 1-1.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[  207.152476] usb 1-1.1: Product: Ultra Fast Media Reader
[  207.152491] usb 1-1.1: Manufacturer: Generic
[  207.152505] usb 1-1.1: SerialNumber: 000000264001
[  207.154346] usb-storage 1-1.1:1.0: USB Mass Storage device detected
[  207.155098] scsi host0: usb-storage 1-1.1:1.0
[  207.242334] usb 1-1.2: new full-speed USB device number 4 using xhci-hcd
[  207.348855] usb 1-1.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
[  207.348892] usb 1-1.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[  207.348911] usb 1-1.2: Product: sd-wire
[  207.348925] usb 1-1.2: Manufacturer: SRPOL
[  207.348940] usb 1-1.2: SerialNumber: sd-wire_02-09
[  208.489961] scsi 0:0:0:0: Direct-Access     Generic  Ultra HS-SD/MMC  1.76 PQ: 0 ANSI: 0
[  211.036252] sd 0:0:0:0: [sda] Spinning up disk...
[  212.478440] .
[  212.479627] sd 0:0:0:0: [sda] Media removed, stopped polling
[  212.482893] sd 0:0:0:0: [sda] Attached SCSI removable disk
avaota@avaota-a1:~$
```

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
