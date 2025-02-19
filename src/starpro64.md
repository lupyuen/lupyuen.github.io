# StarPro64 RISC-V SBC: LLM on NPU on NuttX?

📝 _16 Apr 2025_

![TODO](https://lupyuen.org/images/starpro64-title.jpg)

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
Register 2000140 NbrPorts 2
Starting the controller
USB XHCI 1.10
scanning bus usb1@50490000 for devices... 3 USB Device(s) found
       scanning usb for storage devices... 0 Storage Device(s) found
No SATA device found!
Hit any key to stop autoboot:  0
=> ��^P
Unknown command '��^P' - try 'help'
=>
Unknown command '��^P' - try 'help'
=> ���^BJ}��9�^�^L^�^
Unknown command '���^BJ}��9�^�^L^�^' - try 'help'
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
eth1addr=c2:cd:69:98:98:e0
ethaddr=5a:55:75:91:ad:ae
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

here's an idea for horror sci-fi
llm sensor sends sinister words like "evil", "death", "doom"

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
