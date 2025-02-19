# StarPro64 RISC-V SBC: LLM on NPU on NuttX?

📝 _16 Apr 2025_

![TODO](https://lupyuen.org/images/starpro64-title.jpg)

TODO

Star64 power

Beware: Very Hot!

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

# Download MicroSD

https://github.com/eswincomputing/eic7x-images/releases/tag/Debian-v1.0.0-p550-20241230

https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/Development_board_image_installation_and_upgrade_manual.pdf

https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/EIC7x_Release_Images_p550_20241230.zip.001

https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/EIC7x_Release_Images_p550_20241230.zip.002

```bash
sudo apt install p7zip-full
7z x EIC7x_Release_Images_p550_20241230.zip.001
```

# U-Boot

https://gist.github.com/lupyuen/9db7b36f3cdf26f7b7f75c0d35177ee7

```text
OpenSBI v1.0
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name             : ESWIN EIC770X
Platform Features         : none
Platform HART Count       : 4
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 1000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : ---
Platform Reboot Device    : eswin_eic770x_reset
Platform Shutdown Device  : eswin_eic770x_reset
Firmware Base             : 0x80000000
Firmware Size             : 308 KB
Runtime SBI Version       : 0.3

Domain0 Name              : root
Domain0 Boot HART         : 1
Domain0 HARTs             : 0*,1*,2*,3*
Domain0 Region00          : 0x0000000002000000-0x000000000200ffff (I)
Domain0 Region01          : 0x0000000080000000-0x000000008007ffff ()
Domain0 Region02          : 0x0000001000000000-0x0000007fffffffff (M)
Domain0 Region03          : 0x0000000000000000-0xffffffffffffffff (R,W,X)
Domain0 Next Address      : 0x0000000080200000
Domain0 Next Arg1         : 0x00000000f8000000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes

Boot HART ID              : 1
Boot HART Domain          : root
Boot HART ISA             : rv64imafdcsuhx
Boot HART Features        : scounteren,mcounteren,mcountinhibit,sscofpmf
Boot HART PMP Count       : 16
Boot HART PMP Granularity : 4096
Boot HART PMP Address Bits: 39
Boot HART MHPM Count      : 4
Boot HART MIDELEG         : 0x0000000000002666
Boot HART MEDELEG         : 0x0000000000f00509
ll

U-Boot 2024.01 (Oct 21 2024 - 12:03:34 +0800)

CPU:   rv64imafdc_zba_zbb
Model: ESWIN EIC7700 StarPro64
DRAM:  32 GiB (effective 16 GiB)
llCore:  123 devices, 31 uclasses, devicetree: separate
Warning: Device tree includes old 'u-boot,dm-' tags: please fix by 2023.07!
MMC:   sdhci@50450000: 0, sd@50460000: 1
Loading Environment from SPIFlash... SF: Detected w25q128fw with page size 256 Bytes, erase size 4 KiB, total 16 MiB
*** Warning - bad CRC, using default environment

[display_init]Eswin UBOOT DRM driver version: v1.0.1
xfer: num: 2, addr: 0x50
xfer: num: 2, addr: 0x50
Monitor has basic audio support
mode:1920x1080
[display_init]Detailed mode clock 148500 kHz, flags[5]
    H: 1920 2008 2052 2200
    V: 1080 1084 1089 1125
bus_format: 100a
[eswin_dc_init]regs=0x00000000502c0000, regsbak=0x00000000ed9398a0
[eswin_dc_init]:layer:0 hdisplay = 1920, htotal = 2200.hsync_st:2008.hsync_end:2052
[eswin_dc_init]: vdisplay = 1080, vtotal = 1125.vsync_st:1084.vsync_end:1089
[eswin_dc_init]: src_width = 1920, src_height = 1080.
CEA mode used vic=16
final pixclk = 148500000 tmdsclk = 148500000
PHY powered down in 0 iterations
PHY PLL locked 1 iterations
PHY powered down in 1 iterations
PHY PLL locked 1 iterations
sink has audio support
hdmi_set_clk_regenerator: fs=48000Hz ftdms=148.500MHz N=6144 cts=148500
In:    serial,usbkbd
Out:   vidconsole,serial
Err:   vidconsole,serial
Bootspi flash write protection enabled
Get board info from flash
ERROR: There is no valid hardware board information!!!
sdhci_transfer_data: Transfer data timeout
Finish lpcpu boot
Net:   eqos_probe(dev=00000000ed92dad0):
eqos_probe_resources_core(dev=00000000ed92dad0):
eqos_probe_resources_core: tx_descs=00000000ed94b300, rx_descs=00000000ed94b340
eqos_probe_resources_core: tx_dma_buf=00000000ed94b3c0
eqos_probe_resources_core: rx_dma_buf=00000000ed94ba40
eqos_probe_resources_core: rx_pkt=00000000ed94d350
eqos_probe_resources_core: OK
eqos_probe_resources_eswin(dev=00000000ed92dad0):
eqos_get_interface_eswin(dev=00000000ed92dad0):
eqos_probe_resources_eswin: OK
eqos_probe: OK

Warning: ethernet@50400000 (eth0) using random MAC address - ca:d4:cf:fa:18:ba
eth0: ethernet@50400000eqos_probe(dev=00000000ed92dcd0):
eqos_probe_resources_core(dev=00000000ed92dcd0):
eqos_probe_resources_core: tx_descs=00000000ed94dd80, rx_descs=00000000ed94ddc0
eqos_probe_resources_core: tx_dma_buf=00000000ed94de40
eqos_probe_resources_core: rx_dma_buf=00000000ed94e4c0
eqos_probe_resources_core: rx_pkt=00000000ed94fdd0
eqos_probe_resources_core: OK
eqos_probe_resources_eswin(dev=00000000ed92dcd0):
eqos_get_interface_eswin(dev=00000000ed92dcd0):
eqos_probe_resources_eswin: OK
eqos_probe: OK

Warning: ethernet@50410000 (eth1) using random MAC address - 62:3c:84:68:ca:a1
, eth1: ethernet@50410000
Working FDT set to ed913170
starting USB...
Bus usb1@50490000: Register 2000140 NbrPorts 2
Starting the controller
USB XHCI 1.10
scanning bus usb1@50490000 for devices... 3 USB Device(s) found
       scanning usb for storage devices... 0 Storage Device(s) found
No SATA device found!
Hit any key to stop autoboot:  0
=> Δ�^BJ��L�^P
Unknown command 'Δ�^BJ��L�^P' - try 'help'
=>
Unknown command 'Δ�^BJ��L�^P' - try 'help'
=> )�^BJ�'^�^BJ�
>
> help
> <INTERRUPT>
=> help
?         - alias for 'help'
base      - print or set address offset
bdinfo    - print Board Info structure
blkcache  - block cache diagnostics and control
boot      - boot default, i.e., run 'bootcmd'
bootd     - boot default, i.e., run 'bootcmd'
bootefi   - Boots an EFI payload from memory
bootelf   - Boot from an ELF image in memory
bootflow  - Boot flows
booti     - boot Linux kernel 'Image' format from memory
bootm     - boot application image from memory
bootp     - boot image via network using BOOTP/TFTP protocol
bootspi_region_wp- Enable/Disable write protection for boot spi flash region
bootspi_wp- Enable or disable BootSPI write protection
bootvx    - Boot vxWorks from an ELF image
clk_test  - test clock functionality
cls       - clear screen
cmp       - memory compare
coninfo   - print console devices and information
cp        - memory copy
cpu       - display information about CPUs
crc32     - checksum calculation
date      - get/set/reset date & time
dhcp      - boot image via network using DHCP/TFTP protocol
dm        - Driver model low level access
echo      - echo args to console
editenv   - edit environment variable
eficonfig - provide menu-driven UEFI variable maintenance interface
efidebug  - Configure UEFI environment
env       - environment handling commands
erase     - erase FLASH memory
eraseenv  - erase environment variables from persistent storage
es_burn   - ESWIN burn tool
es_fs     - ESWIN write filesystem image file into sata/mmc
es_otp    - ESWIN OTP sub-system
exit      - exit script
ext2load  - load binary file from a Ext2 filesystem
ext2ls    - list files in a directory (default /)
ext4load  - load binary file from a Ext4 filesystem
ext4ls    - list files in a directory (default /)
ext4size  - determine a file's size
ext4write - create a file in the root directory
false     - do nothing, unsuccessfully
fastboot  - run as a fastboot usb or udp device
fatinfo   - print information about filesystem
fatload   - load binary file from a dos filesystem
fatls     - list files in a directory (default /)
fatmkdir  - create a directory
fatrm     - delete a file
fatsize   - determine a file's size
fatwrite  - write file into a dos filesystem
fdt       - flattened device tree utility commands
flinfo    - print FLASH memory information
fstype    - Look up a filesystem type
fstypes   - List supported filesystem types
go        - start application at address 'addr'
gpio      - query and control gpio pins
gpt       - GUID Partition Table
gzwrite   - unzip and write memory to block device
help      - print command description/usage
i2c       - I2C sub-system
iminfo    - print header information for application image
imxtract  - extract a part of a multi-image
itest     - return true/false on integer compare
lcdputs   - print string on video framebuffer
led       - manage LEDs
ln        - Create a symbolic link
load      - load binary file from a filesystem
loadb     - load binary file over serial line (kermit mode)
loads     - load S-Record file over serial line
loadx     - load binary file over serial line (xmodem mode)
loady     - load binary file over serial line (ymodem mode)
loop      - infinite loop on address range
ls        - list files in a directory (default /)
lsblk     - list block drivers and devices
lzmadec   - lzma uncompress a memory region
md        - memory display
mdio      - MDIO utility commands
mii       - MII utility commands
mkfsfat   - Put the core in spin loop (Secure Boot Only)
mm        - memory modify (auto-incrementing address)
mmc       - MMC sub system
mmcinfo   - display MMC info
mtd       - MTD utils
mw        - memory write (fill)
net       - NET sub-system
nm        - memory modify (constant address)
nvme      - NVM Express sub-system
panic     - Panic with optional message
part      - disk partition related commands
pci       - list and access PCI Configuration Space
ping      - send ICMP ECHO_REQUEST to network host
pinmux    - show pin-controller muxing
poweroff  - Perform POWEROFF of the device
printenv  - print environment variables
protect   - enable or disable FLASH write protection
pxe       - get and boot from pxe files
random    - fill memory with random pattern
read_regs - read and print value from dc8k regs
reset     - Perform RESET of the CPU
run       - run commands in an environment variable
sata      - SATA sub system
save      - save file to a filesystem
saveenv   - save environment variables to persistent storage
sbi       - display SBI information
setcurs   - set cursor position within screen
setenv    - set environment variables
setexpr   - set environment variable as the result of eval expression
sf        - SPI flash sub-system
showvar   - print local hushshell variables
size      - determine a file's size
sleep     - delay execution for some time
source    - run script from memory
sspi      - SPI utility command
sysboot   - command to get and boot from syslinux files
test      - minimal test like /bin/sh
tftpboot  - load file via network using TFTP protocol
tftpput   - TFTP put command, for uploading files to a server
tftpsrv   - act as a TFTP server and boot the first received file
true      - do nothing, successfully
umbox     - Test mailbox in u-boot
unlz4     - lz4 uncompress a memory region
unzip     - unzip a memory region
usb       - USB sub-system
usbboot   - boot from USB device
version   - print monitor, compiler and linker version
write_back- write and print value from dc8k regs
write_regs- write and print value from dc8k regs
=> printenv
arch=riscv
baudrate=115200
board=eic7700_evb
board_name=eic7700_evb
boot_conf_addr_r=0xc0000000
boot_conf_file=/extlinux/extlinux.conf
bootcmd=sysboot mmc ${emmc_dev}:1 any $boot_conf_addr_r $boot_conf_file;
bootdelay=5
cpu=eic7700
emmc_dev=0
eth1addr=62:3c:84:68:ca:a1
ethaddr=ca:d4:cf:fa:18:ba
fdt_addr=ed913170
fdt_addr_r=0x88000000
fdt_high=0xffffffffffffffff
fdtaddr=ed913170
fdtcontroladdr=ed913170
fdtfile=eswin/eic7700-evb-a2.dtb
gpt_partition=gpt write mmc ${emmc_dev} $partitions
initrd_high=0xffffffffffffffff
kernel_addr_r=0x84000000
kernel_comp_addr_r=0x98300000
kernel_comp_size=0x10000000
loadaddr=0x80200000
partitions=name=boot,start=1MiB,size=512MiB,type=${typeid_efi},uuid=${uuid_boot};name=swap,size=4096MiB,type=${typeid_swap},uuid=${uuid_swap};name=root,size=-,type=${typeid_filesystem},uuid=${uuid_root}
preboot=setenv fdt_addr ${fdtcontroladdr};fdt addr ${fdtcontroladdr};usb start;sata init;
pxefile_addr_r=0x88200000
ram_size=32
ramdisk_addr_r=0x88300000
scriptaddr=0x88100000
sdupdate=ext4load mmc 1:1 0x90000000 sdupdate.scr;source 0x90000000
stderr=vidconsole,serial
stdin=serial,usbkbd
stdout=vidconsole,serial
typeid_efi=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
typeid_filesystem=0FC63DAF-8483-4772-8E79-3D69D8477DE4
typeid_swap=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F
usbupdate=ext4load usb 0 0x90000000 usbupdate.scr;source 0x90000000
uuid_boot=44b7cb94-f58c-4ba6-bfa4-7d2dce09a3a5
uuid_root=80a5a8e9-c744-491a-93c1-4f4194fd690a
uuid_swap=5ebcaaf0-e098-43b9-beef-1f8deedd135e
vendor=eswin

Environment size: 1516/524284 bytes
=>
```

# UART

```text
https://pinout.xyz/

Yellow - GND - pin 6
Blue - Tx - pin 8
Green - Rx - pin 10

screen /dev/ttyUSB0 115200
```

# New RockOS

https://fast-mirror.isrc.ac.cn/rockos/images/generic/20241230_20250124/

```bash
$ unzstd boot-rockos-20250123-210346.ext4.zst
boot-rockos-20250123-210346.ext4.zst: 524288000 bytes

$ unzstd root-rockos-20250123-210346.ext4.zst
root-rockos-20250123-210346.ext4.zst: 7516192768 bytes

$ ls -lh
total 20786832
-rw-r--r--  1 luppy  wheel   500M Feb 19 09:52 boot-rockos-20250123-210346.ext4
-rw-r--r--@ 1 luppy  wheel   154M Feb 19 10:24 boot-rockos-20250123-210346.ext4.zst
-rw-r--r--  1 luppy  wheel   7.0G Feb 19 10:24 root-rockos-20250123-210346.ext4
-rw-r--r--@ 1 luppy  wheel   2.3G Feb 19 10:24 root-rockos-20250123-210346.ext4.zst
```

https://gist.github.com/lupyuen/a07e8dcd56d3fb306dce8983f4924702

```text
copy the ext4 files to usb drive
rename to boot.ext4, root.ext4

uboot:
Hit any key to stop autoboot
ls mmc 0
mmc part

if not partitioned:
echo $partitions
run gpt_partition
mmc part

ls usb 0
es_fs update usb 0 boot.ext4 mmc 0:1
es_fs update usb 0 root.ext4 mmc 0:3

ext4load usb 0 0x100000000 bootloader_secboot_ddr5_pine64-starpro64.bin
es_burn write 0x100000000 flash
```

Boot Fail: https://gist.github.com/lupyuen/89e1e87e7f213b6f52f31987f254b32f

https://gist.github.com/lupyuen/89e1e87e7f213b6f52f31987f254b32f#file-gistfile1-txt-L1940-L1947

```text
[  132.081330] thermal thermal_zone0: thermal0: critical temperature reached, shutting down
[  132.089435] reboot: HARDWARE PROTECTION shutdown (Temperature too high)
thermal thermal_zone0: thermal0: critical temperature reached, shutting down
reboot: HARDWARE PROTECTION shutdown (Temperature too high)
```

# TODO

https://github.com/rockos-riscv

🤔 Booting #StarPro64 @ThePine64 (#RISCV #ESWIN EIC7700X)

Source: https://pine64.org/2024/10/02/september_2024/#starpro64

#RISCV ESWIN EIC7700X Technical Reference Manual (#StarPro64)

https://github.com/eswincomputing/EIC7

#RISCV #ESWIN EIC7700X: Qwen #LLM on NPU (#StarPro64)

Source: https://github.com/eswincomputing/eic7x-images/releases/download/Debian-v1.0.0-p550-20241230/ESWIN_AI_Sample_User_Guide.pdf

#RISCV #ESWIN EIC7700X: NPU Driver (#StarPro64)

https://github.com/eswincomputing/linux-stable/tree/linux-6.6.18-EIC7X/drivers/soc/eswin/ai_driver/npu

通义_百度百科

https://baike.baidu.com/item/%E9%80%9A%E4%B9%89/64394178

ollama

https://github.com/ollama/ollama/blob/main/model/models/llama/model.go

qwen the name
gwen stafani / gwen stacy
qwen = question wen = qq = bouncy

southern islands of singapore
identify pic of creatures or sea life
rainforest critters or underwater creatures
in one word
Duck, octopus 

_(Here's an idea for Horror Sci-Fi: We installed an LLM Sensor in a Remote Island. One day our LLM Sensor sends us sinister words like "evil", "death", "doom"...)_

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
