# StarPro64 EIC7700X RISC-V SBC: Maybe LLM on NPU on NuttX?

📝 _16 Apr 2025_

![TODO](https://lupyuen.org/images/starpro64-title.jpg)

TODO

StarPro64 EIC7700X is the (literally) Hot New RISC-V SBC by PINE64.

Star64 power

IKEA Smart Power Plug

Beware: Very Hot!

```text
pll failed.
pll failed.
pll failed.
```

If something smells like barbeque: Drop it, stop it and power off!

iTerm: Edit > Paste Special > Paste Slowly

Settings > Advanced > Pasteboard

Delay in seconds between chunks when Pasting Slowly: 1 second

Number of bytes to paste in each chunk when Pasting Slowly: 16

Well documented

NuttX: Power efficient AI

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
Platform IPI Device       : aclint-mswi
Platform Timer Device     : aclint-mtimer @ 1000000Hz
Platform Console Device   : uart8250
Platform HSM Device       : ---
Platform PMU Device       : ---
Platform Reboot Device    : eswin_eic770x_reset
Platform Shutdown Device  : eswin_eic770x_reset
Platform Suspend Device   : ---
Platform CPPC Device      : ---
Firmware Base             : 0x80000000
Firmware Size             : 357 KB
Firmware RW Offset        : 0x40000
Firmware RW Size          : 101 KB
Firmware Heap Offset      : 0x4f000
Firmware Heap Size        : 41 KB (total), 2 KB (reserved), 11 KB (used), 27 KB (free)
Firmware Scratch Size     : 4096 B (total), 416 B (used), 3680 B (free)
Runtime SBI Version       : 2.0

Domain0 Name              : root
Domain0 Boot HART         : 2
Domain0 HARTs             : 0*,1*,2*,3*
Domain0 Region00          : 0x0000000002000000-0x000000000200ffff M: (I,R,W) S/U: ()
Domain0 Region01          : 0x0000000080000000-0x000000008007ffff M: (R,W) S/U: ()
Domain0 Region02          : 0x000000c000000000-0x000000d000000000 M: () S/U: (R,W)
Domain0 Region03          : 0x0000001000000000-0x0000008000000000 M: () S/U: ()
Domain0 Region04          : 0x0000000000000000-0xffffffffffffffff M: () S/U: (R,W,X)
Domain0 Next Address      : 0x0000000080200000
Domain0 Next Arg1         : 0x00000000f8000000
Domain0 Next Mode         : S-mode
Domain0 SysReset          : yes
Domain0 SysSuspend        : yes

Boot HART ID              : 2
Boot HART Domain          : root
Boot HART Priv Version    : v1.11
Boot HART Base ISA        : rv64imafdchx
Boot HART ISA Extensions  : sscofpmf,zihpm,sdtrig
Boot HART PMP Count       : 8
Boot HART PMP Granularity : 12 bits
Boot HART PMP Address Bits: 39
Boot HART MHPM Info       : 4 (0x00000078)
Boot HART Debug Triggers  : 4 triggers
Boot HART MIDELEG         : 0x0000000000002666
Boot HART MEDELEG         : 0x0000000000f0b509

Hardware Feature[7C1]: 0x4000
Hardware Feature[7C2]: 0x80
Hardware Feature[7C3]: 0x104095c1be241
Hardware Feature[7C4]: 0x1d3ff
ll

U-Boot 2024.01-gaa36f0b4 (Jan 23 2025 - 02:49:59 +0000)

CPU:   rv64imafdc_zba_zbb
Model: ESWIN EIC7700 EVB
DRAM:  32 GiB (effective 16 GiB)
llCore:  143 devices, 31 uclasses, devicetree: separate
Warning: Device tree includes old 'u-boot,dm-' tags: please fix by 2023.07!
MMC:   sdhci@50450000: 0, sd@50460000: 1
Loading Environment from SPIFlash... SF: Detected w25q128fw with page size 256 Bytes, erase size 4 KiB, total 16 MiB
*** Warning - bad CRC, using default environment

[display_init]Eswin UBOOT DRM driver version: v1.0.1
In:    serial,usbkbd
Out:   vidconsole,serial
Err:   vidconsole,serial
Success to initialize SPI flash at spi@51800000
Bootspi flash write protection enabled
Get board info from flash
ERROR: There is no valid hardware board information!!!
Cpu volatge need boost above 1.6 Ghz!
sdhci_transfer_data: Transfer data timeout
Low power features will not be supported!
Net:
Warning: ethernet@50400000 (eth0) using random MAC address - fa:c6:22:64:80:d4
eth0: ethernet@50400000
Working FDT set to ed4ecb90
starting USB...
Bus usb1@50490000: Register 2000140 NbrPorts 2
Starting the controller
USB XHCI 1.10
scanning bus usb1@50490000 for devices... 2 USB Device(s) found
       scanning usb for storage devices... 0 Storage Device(s) found
No SATA device found!
Autoboot in 5 seconds

=> help
?         - alias for 'help'
base      - print or set address offset
bdinfo    - print Board Info structure
blkcache  - block cache diagnostics and control
bmp       - manipulate BMP image data
boot      - boot default, i.e., run 'bootcmd'
bootd     - boot default, i.e., run 'bootcmd'
bootdev   - Boot devices
bootefi   - Boots an EFI payload from memory
bootelf   - Boot from an ELF image in memory
bootflow  - Boot flows
booti     - boot Linux kernel 'Image' format from memory
bootm     - boot application image from memory
bootmeth  - Boot methods
bootp     - boot image via network using BOOTP/TFTP protocol
bootspi   - BOOTSPI flash sub-system
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
vbe       - Verified Boot for Embedded
version   - print monitor, compiler and linker version
write_back- write and print value from dc8k regs
write_regs- write and print value from dc8k regs

=> printenv
arch=riscv
baudrate=115200
board=eic7700_evb
board_name=eic7700_evb
boot_conf_addr_r=0xc0000000
bootcmd=bootflow scan -lb
bootdelay=5
cpu=eic770x
emmc_dev=0
ethact=ethernet@50400000
ethaddr=fa:c6:22:64:80:d4
fdt_addr=ed4ecb90
fdt_addr_r=0x88000000
fdt_high=0xffffffffffffffff
fdtaddr=ed4ecb90
fdtcontroladdr=ed4ecb90
fdtfile=eswin/eic7700-pine64-starpro64.dtb
gpt_partition=gpt write mmc ${emmc_dev} $partitions
initrd_high=0xffffffffffffffff
kernel_addr_r=0x84000000
kernel_comp_addr_r=0x98300000
kernel_comp_size=0x10000000
loadaddr=0x80200000
partitions=name=boot,start=1MiB,size=2048MiB,type=${typeid_filesystem},uuid=${uuid_boot};name=swap,size=4096MiB,type=${typeid_swap},uuid=${uuid_swap};name=root,size=-,type=${typeid_filesystem},uuid=${uuid_root}
preboot=setenv fdt_addr ${fdtcontroladdr};fdt addr ${fdtcontroladdr};usb start;sata init;nvme scan
pxefile_addr_r=0x88200000
ramdisk_addr_r=0x88300000
scriptaddr=0x88100000
sdupdate=ext4load mmc 1:1 0x90000000 sdupdate.scr;source 0x90000000
splashimage=0xe0000000
splashpos=1660,0
stderr=vidconsole,serial
stdin=serial,usbkbd
stdout=vidconsole,serial
typeid_filesystem=0FC63DAF-8483-4772-8E79-3D69D8477DE4
typeid_swap=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F
usbupdate=ext4load usb 0 0x90000000 usbupdate.scr;source 0x90000000
uuid_boot=44b7cb94-f58c-4ba6-bfa4-7d2dce09a3a5
uuid_root=b0f77ad6-36cd-4a99-a8c0-31d73649aa08
uuid_swap=5ebcaaf0-e098-43b9-beef-1f8deedd135e
vendor=eswin

Environment size: 1435/524284 bytes
```

TODO

```text
  .quad   0x4000000            /* Kernel size (fdt_addr_r-kernel_addr_r) */
```

# UART

```text
https://pinout.xyz/

Yellow - GND - pin 6
Blue - Tx - pin 8
Green - Rx - pin 10

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

# Power Plug

```bash
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
    -d '{"entity_id": "automation.pi_power_off"}' \
    http://localhost:8123/api/services/automation/trigger
set -x  ##  Enable echo

set +x  ##  Disable echo
echo "----- Power On the SBC"
curl \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "automation.pi_power_on"}' \
    http://localhost:8123/api/services/automation/trigger
set -x  ##  Enable echo
```

# New RockOS

https://nightcord.de/@icenowy/114027871300585376

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
Or press Ctrl-C
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

# Boot NuttX over TFTP

https://lupyuen.github.io/articles/sg2000


```bash
$ net list
eth0 : ethernet@50400000 f6:70:f9:6e:73:ae active

## Set the U-Boot TFTP Server
## TODO: Change to your TFTP Server
setenv tftp_server 192.168.31.10

## Save the U-Boot Config for future reboots
saveenv

## Fetch the IP Address over DHCP
## Load the NuttX Image from TFTP Server
## kernel_addr_r=0x80200000
dhcp ${kernel_addr_r} ${tftp_server}:Image-starpro64

## Load the Device Tree from TFTP Server
## fdt_addr_r=0x81200000
## TODO: Fix the Device Tree, it's not needed by NuttX
tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb

## Set the RAM Address of Device Tree
## fdt_addr_r=0x81200000
## TODO: Fix the Device Tree, it's not needed by NuttX
fdt addr ${fdt_addr_r}

## Boot the NuttX Image with the Device Tree
## kernel_addr_r=0x80200000
## fdt_addr_r=0x81200000
## TODO: Fix the Device Tree, it's not needed by NuttX
booti ${kernel_addr_r} - ${fdt_addr_r}
```

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

Press Ctrl-C to stop

(Dropping Chars? Try __Edit > Paste Special > Paste Slowly__)

https://gist.github.com/lupyuen/b03a16604f3e9465e2fd9d63d08734a9

```text
=> booti ${kernel_addr_r} - ${fdt_addr_r}
Moving Image from 0x84000000 to 0x80200000, end=80408000
## Flattened Device Tree blob at 88000000
   Booting using the fdt blob at 0x88000000
Working FDT set to 88000000
   Using Device Tree in place at 0000000088000000, end 0000000088008446
Working FDT set to 88000000

Starting kernel ...
```

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

Apache NuttX RTOS on StarPro64: OSTest runs OK yay! (ESWIN EIC7700X)

https://gist.github.com/lupyuen/2823528f7b53375f080256bc798b2bf5

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
