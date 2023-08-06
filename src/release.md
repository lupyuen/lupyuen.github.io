# Star64 JH7110 + NuttX RTOS: Creating the First Release

📝 _12 Aug 2023_

![TODO](https://lupyuen.github.io/images/release-title.png)

TODO

We're almost ready with our barebones port of [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) to [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

TODO

This article is probably helpful for folks who wish to...

- Add a new __NuttX Arch__ (SoC) or __NuttX Board__

- Create __NuttX Drivers__ (or __NuttX Apps__) for Star64 (or JH7110)

- Or simply understand how we __boot a Modern SBC__ from scratch!

![Star64 RISC-V SBC](https://lupyuen.github.io/images/nuttx2-star64.jpg)

# Build NuttX for Star64

TODO

From the previous section we saw that JH7110 triggers too many spurious UART interrupts...

- ["Spurious UART Interrupts"](https://lupyuen.github.io/articles/plic#spurious-uart-interrupts)

JH7110 uses a Synopsys DesignWare 8250 UART that has a peculiar problem with the Line Control Register (LCR)... If we write to LCR while the UART is busy, it will trigger spurious UART Interrupts.

The fix is to wait for the UART to be not busy before writing to LCR. Here's my proposed patch for the NuttX 16550 UART Driver...

- ["Fix the Spurious UART Interrupts"](https://lupyuen.github.io/articles/plic#appendix-fix-the-spurious-uart-interrupts)

After fixing the spurious UART interrupts, now NuttX boots OK on Star64 yay!

![NuttX boots OK on Star64 JH7110](https://lupyuen.github.io/images/star64-bootok.png)

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
BCnx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
up_exit: TCB=0x40409890 exiting
nx_start: CPU0: Beginning Idle Loop

NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
posix_spawn: pid=0xc0202978 path=uname file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
exec_spawn: ERROR: Failed to load program 'uname': -2
nxposix_spawn_exec: ERROR: exec failed: 2
NuttX 12.0.3 7a92743-dirty Aug  3 2023 18:06:04 risc-v star64
nsh> ls -l
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
/:
 dr--r--r--       0 dev/
 dr--r--r--       0 proc/
 dr--r--r--       0 system/
nsh> 
```

[(Watch the Demo Video on YouTube)](https://youtu.be/6vQ-TXXojbQ)

[(See the Complete Log)](https://gist.github.com/lupyuen/eef8de0817ceed2072b2bacc925cdd96)

_How did we build NuttX for Star64?_

To build NuttX for Star64, [install the prerequisites](https://nuttx.apache.org/docs/latest/quickstart/install.html) and [clone the git repositories](https://nuttx.apache.org/docs/latest/quickstart/install.html) for ``nuttx`` and ``apps``.

Before building NuttX for Star64, download the __RISC-V Toolchain riscv64-unknown-elf__ from [SiFive RISC-V Tools](https://github.com/sifive/freedom-tools/releases/tag/v2020.12.0).

Add the downloaded toolchain `riscv64-unknown-elf-toolchain-.../bin` to the `PATH` Environment Variable.

Check the RISC-V Toolchain:

```bash
$ riscv64-unknown-elf-gcc -v
```

Configure the NuttX project and build the project:

```bash
$ cd nuttx
$ tools/configure.sh star64:nsh
$ make
$ riscv64-unknown-elf-objcopy -O binary nuttx nuttx.bin
```

This produces the NuttX Kernel ``nuttx.bin``.  Next, build the NuttX Apps Filesystem:

```bash
$ make export
$ pushd ../apps
$ tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
$ make import
$ popd
$ genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
```

This generates the Initial RAM Disk ``initrd``.

Download the [Device Tree jh7110-visionfive-v2.dtb](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/jh7110-visionfive-v2.dtb) from [StarFive VisionFive2 Software Releases](https://github.com/starfive-tech/VisionFive2/releases) into the ``nuttx`` folder.

Now we create a Bootable MicroSD...

[(See the Build Outputs)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

[(See the Build Steps)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

[(See the Build Log)](https://gist.github.com/lupyuen/c6dc9aeec74d399029ebaf46ac16ef79)

# NuttX in a Bootable microSD

TODO

_How do we create a Bootable MicroSD for NuttX?_

From the previous section, we have the NuttX Kernel ``nuttx.bin``, Initial RAM Disk ``initrd`` and Device Tree `jh7110-visionfive-v2.dtb`.

We'll pack all 3 files into a Flat Image Tree (FIT).

Inside the ``nuttx`` folder, create a Text File named ``nuttx.its``
with the following content: [nuttx.its](https://github.com/lupyuen/nuttx-star64/blob/main/nuttx.its)

```text
/dts-v1/;

/ {
  description = "NuttX FIT image";
  #address-cells = <2>;

  images {
    vmlinux {
      description = "vmlinux";
      data = /incbin/("./nuttx.bin");
      type = "kernel";
      arch = "riscv";
      os = "linux";
      load = <0x0 0x40200000>;
      entry = <0x0 0x40200000>;
      compression = "none";
    };

    ramdisk {
      description = "buildroot initramfs";
      data = /incbin/("./initrd");
      type = "ramdisk";
      arch = "riscv";
      os = "linux";
      load = <0x0 0x46100000>;
      compression = "none";
      hash-1 {
        algo = "sha256";
      };
    };

    fdt {
      data = /incbin/("./jh7110-visionfive-v2.dtb");
      type = "flat_dt";
      arch = "riscv";
      load = <0x0 0x46000000>;
      compression = "none";
      hash-1 {
        algo = "sha256";
      };
    };
  };

  configurations {
    default = "nuttx";

    nuttx {
      description = "NuttX";
      kernel = "vmlinux";
      fdt = "fdt";
      loadables = "ramdisk";
    };
  };
};
```

[(Based on visionfive2-fit-image.its)](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/conf/visionfive2-fit-image.its)

Package the NuttX Kernel, Initial RAM Disk and Device Tree into a
Flat Image Tree:

```bash
## For macOS:
brew install u-boot-tools
## For Linux:
sudo apt install u-boot-tools

## Generate FIT Image from `nuttx.bin`, `initrd` and `jh7110-visionfive-v2.dtb`.
## `nuttx.its` must be in the same directory as the NuttX binaries!
mkimage \
  -f nuttx.its \
  -A riscv \
  -O linux \
  -T flat_dt \
  starfiveu.fit

## To check FIT image
mkimage -l starfiveu.fit
```

We will see...

```text
→ mkimage -f nuttx.its -A riscv -O linux -T flat_dt starfiveu.fit
FIT description: NuttX FIT image
Created:         Fri Aug  4 23:20:52 2023
 Image 0 (vmlinux)
  Description:  vmlinux
  Created:      Fri Aug  4 23:20:52 2023
  Type:         Kernel Image
  Compression:  uncompressed
  Data Size:    2097800 Bytes = 2048.63 KiB = 2.00 MiB
  Architecture: RISC-V
  OS:           Linux
  Load Address: 0x40200000
  Entry Point:  0x40200000
 Image 1 (ramdisk)
  Description:  buildroot initramfs
  Created:      Fri Aug  4 23:20:52 2023
  Type:         RAMDisk Image
  Compression:  uncompressed
  Data Size:    8086528 Bytes = 7897.00 KiB = 7.71 MiB
  Architecture: RISC-V
  OS:           Linux
  Load Address: 0x46100000
  Entry Point:  unavailable
  Hash algo:    sha256
  Hash value:   44b3603e6e611ade7361a936aab09def23651399d4a0a3c284f47082d788e877
 Image 2 (fdt)
  Description:  unavailable
  Created:      Fri Aug  4 23:20:52 2023
  Type:         Flat Device Tree
  Compression:  uncompressed
  Data Size:    50235 Bytes = 49.06 KiB = 0.05 MiB
  Architecture: RISC-V
  Load Address: 0x46000000
  Hash algo:    sha256
  Hash value:   42767c996f0544f513280805b41f996446df8b3956c656bdbb782125ae8ffeec
 Default Configuration: 'nuttx220569'
 Configuration 0 (nuttx220569)
  Description:  NuttX
  Kernel:       vmlinux
  FDT:          fdt
  Loadables:    ramdisk
```

The Flat Image Tree ``starfiveu.fit`` will be copied to a microSD Card
in the next step.

To prepare the microSD Card, download the [microSD Image sdcard.img](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/sdcard.img) from [StarFive VisionFive2 Software Releases](https://github.com/starfive-tech/VisionFive2/releases)

Write the downloaded image to a microSD Card with [Balena Etcher](https://www.balena.io/etcher/) or [GNOME Disks](https://wiki.gnome.org/Apps/Disks).

Copy the file ``starfiveu.fit`` from the previous section and overwrite the file on the microSD Card.

```bash
## Copy to microSD
cp starfiveu.fit "/Volumes/NO NAME"
ls -l "/Volumes/NO NAME/starfiveu.fit"

## Unmount microSD
## TODO: Verify that /dev/disk2 is microSD
diskutil unmountDisk /dev/disk2
```

# Boot NuttX on Star64

TODO

Check that Star64 is connected to our computer via a USB Serial Adapter.

Insert the microSD Card into Star64 and power up Star64.
NuttX boots on Star64 and NuttShell (nsh) appears in the Serial Console.

To see the available commands in NuttShell:

```bash
$ help
```

[Booting NuttX over TFTP](https://lupyuen.github.io/articles/tftp) is also supported on Star64.

[(See the Build Outputs)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

[(See the Build Steps)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

[(See the Build Log)](https://gist.github.com/lupyuen/c6dc9aeec74d399029ebaf46ac16ef79)

More about Flat Image Tree...

- [Flattened Image Tree (FIT) Format](https://u-boot.readthedocs.io/en/latest/usage/fit/source_file_format.html)

- [Single kernel and FDT blob](https://u-boot.readthedocs.io/en/latest/usage/fit/kernel_fdt.html)

- [Multiple kernels, ramdisks and FDT blobs](https://u-boot.readthedocs.io/en/latest/usage/fit/multi.html)

TODO: Why use sdcard.img

# NuttX Startup on Star64

TODO

1.  OpenSBI

1.  U-Boot Bootloader

1.  NuttX Kernel

1.  NuttX Shell (NSH)

1.  NuttX Apps

1.  System Calls

1.  Serial I/O

Memory Mgmt

# Add NuttX Arch and Board for Star64 JH7110

TODO

_How did we add Star64 JH7110 to NuttX as a new Arch and Board?_

We added Star64 JH7110 to NuttX with 3 Pull Requests...

1.  First we fix any dependencies needed by Star64 JH7110. This PR fixes the 16550 UART Driver used by JH7110...

    [Fix 16550 UART](https://github.com/apache/nuttx/pull/10019)

1.  Next we submit the PR that implements the JH7110 SoC as a __NuttX Arch__...

    [Add support for JH7110 SoC](https://github.com/apache/nuttx/pull/10069)

    We add JH7110 to the Kconfig for the RISC-V SoCs: [arch/risc-v/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-9c348f27c59e1ed0d1d9c24e172d233747ee09835ab0aa7f156da1b7caa6a5fb)

    And we create a Kconfig for JH7110: [arch/risc-v/src/jh7110/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-36a3009882ced77a24e9a7fd7ce3cf481ded4655f1adc366e7722a87ceab293b)

    Then we add the source files for JH7110 at...

    [arch/risc-v/src/jh7110](https://github.com/apache/nuttx/tree/master/arch/risc-v/src/jh7110)

1.  Finally we submit the PR that implements Star64 SBC as a __NuttX Board__...

    [Add support for Star64 SBC](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

    We add Star64 to the Kconfig for the NuttX Boards: [nuttx/boards/Kconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-60cc096e3a9b22a769602cbbc3b0f5e7731e72db7b0338da04fcf665ed753b64)

    We create a Kconfig for Star64: [nuttx/boards/risc-v/jh7110/star64/Kconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-76f41ff047f7cc79980a18f527aa05f1337be8416d3d946048b099743f10631c)

    And we add the source files for Star64 at...

    [boards/risc-v/jh7110/star64](https://github.com/apache/nuttx/tree/master/boards/risc-v/jh7110/star64)

1.  In the same PR, update the __NuttX Docs__...

    Add JH7110 and Star64 to the list of supported platforms:
    
    [nuttx/Documentation/introduction/detailed_support.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-d8a0e68fcb8fcb7e919c4b01226b6a25f888ed297145b82c719875cf8e6f5ae4)

    Create a page for the JH7110 NuttX Arch:

    [nuttx/Documentation/platforms/risc-v/jh7110/index.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-79d8d013e3cbf7600551f1ac23beb5db8bd234a0067576bfe0997b16e5d5c148)

    Under JH7110, create a page for the Star64 NuttX Board:
    
    [nuttx/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-a57fa454397c544c8a717c35212a88d3e3e0c77c9c6e402f5bb52dfeb62e1349)

_Seems we need to copy a bunch of source files across branches?_

No sweat! Suppose we created a staging PR in our own repo...

- [github.com/lupyuen2/wip-pinephone-nuttx/pull/40](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

This command produces a list of changed files...

```bash
## TODO: Change this to your PR
pr=https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40
curl -L $pr.diff \
  | grep "diff --git" \
  | sort \
  | cut -d" " -f3 \
  | cut -c3-
```

Like this...

```text
boards/risc-v/jh7110/star64/include/board.h
boards/risc-v/jh7110/star64/include/board_memorymap.h
boards/risc-v/jh7110/star64/scripts/Make.defs
boards/risc-v/jh7110/star64/scripts/ld.script
```

That we can copy to another branch in a script...

```bash
b=$HOME/new_branch
mkdir -p $b/boards/risc-v/jh7110/star64/include
mkdir -p $b/boards/risc-v/jh7110/star64/scripts

a=boards/risc-v/jh7110/star64/include/board.h
cp $a $b/$a
a=boards/risc-v/jh7110/star64/include/board_memorymap.h
cp $a $b/$a
a=boards/risc-v/jh7110/star64/scripts/Make.defs
cp $a $b/$a
a=boards/risc-v/jh7110/star64/scripts/ld.script
cp $a $b/$a
```

_How did we generate the NuttX Build Configuration?_

The NuttX Build Configuration for Star64 is at...

[boards/risc-v/jh7110/star64/configs/nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40/files#diff-cdbd91013d0074f15d469491b707d1d6576752bd7b7b9ec6ed311edba8ab4b53)

We generated the `defconfig` with this command...

```bash
make menuconfig \
  && make savedefconfig \
  && grep -v CONFIG_HOST defconfig \
  >boards/risc-v/jh7110/star64/configs/nsh/defconfig
```

During development, we should enable additional debug options...

```text
CONFIG_DEBUG_ASSERTIONS=y
CONFIG_DEBUG_ASSERTIONS_EXPRESSION=y
CONFIG_DEBUG_BINFMT=y
CONFIG_DEBUG_BINFMT_ERROR=y
CONFIG_DEBUG_BINFMT_WARN=y
CONFIG_DEBUG_ERROR=y
CONFIG_DEBUG_FEATURES=y
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_FS_ERROR=y
CONFIG_DEBUG_FS_WARN=y
CONFIG_DEBUG_FULLOPT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_MM=y
CONFIG_DEBUG_MM_ERROR=y
CONFIG_DEBUG_MM_WARN=y
CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
CONFIG_DEBUG_SYMBOLS=y
CONFIG_DEBUG_WARN=y
```

- BINFMT is the Binary Loader, good for troubleshooting NuttX App ELF loading issues

- SCHED is for Task Scheduler, which will show the spawning of NuttX App Tasks

- MM is for Memory Management, for troubleshooting Memory Mapping issues

- FS is for File System

Before merging with NuttX Mainline, remove the BINFMT, FS, MM and SCHED debug options.

# Upcoming Features

TODO: GPIO

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/release.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/release.md)

# Appendix: StarFive VisionFive2 Software Release

TODO

StarFive VisionFive2 Software Releases seem to boot OK on Star64...

- [VisionFive2 Software Releases](https://github.com/starfive-tech/VisionFive2/releases)

- [SD Card Image](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/sdcard.img)

[(See the Boot Log for Star64)](https://gist.github.com/lupyuen/030e4feb2fa95319290f3027032c24a8)

Login with...

```text
buildroot login: root
Password: starfive
```

Based on the files above, we figured out how to generate the Flat Image Tree for NuttX: [Makefile](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/Makefile#L279-L283)

Also we see the script that generates the SD Card Image: [genimage.sh](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/genimage.sh)

```bash
genimage \
	--rootpath "${ROOTPATH_TMP}"     \
	--tmppath "${GENIMAGE_TMP}"    \
	--inputpath "${INPUT_DIR}"  \
	--outputpath "${OUTPUT_DIR}" \
	--config genimage-vf2.cfg
```

The SD Card Partitions are defined in [genimage-vf2.cfg](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/conf/genimage-vf2.cfg):

```text
image sdcard.img {
	hdimage {
		gpt = true
	}

	partition spl {
		image = "work/u-boot-spl.bin.normal.out"
		partition-type-uuid = 2E54B353-1271-4842-806F-E436D6AF6985
		offset = 2M
		size = 2M
	}

	partition uboot {
		image = "work/visionfive2_fw_payload.img"
		partition-type-uuid = 5B193300-FC78-40CD-8002-E86C45580B47
		offset = 4M
		size = 4M
	}

	partition image {
		# partition-type = 0xC
		partition-type-uuid = EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
		image = "work/starfive-visionfive2-vfat.part"
		offset = 8M
		size = 292M
	}

	partition root {
		# partition-type = 0x83
		partition-type-uuid = 0FC63DAF-8483-4772-8E79-3D69D8477DE4
		image = "work/buildroot_rootfs/images/rootfs.ext4"
		offset = 300M
		bootable = true
	}
}
```

Useful for creating our own SD Card Partitions!

(We won't need the `spl`, `uboot` and `root` partitions for NuttX)

# Appendix: UART Clock for JH7110

TODO

_How did we figure out the UART Clock for JH7110?_

```bash
CONFIG_16550_UART0_CLOCK=23040000
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/57d5bba4723b58c7bb947f9fa206be377c80c8d0/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L10-L18)

We logged the values of DLM and DLL in the UART Driver during startup...

```c
uint32_t dlm = u16550_serialin(priv, UART_DLM_OFFSET);
uint32_t dll = u16550_serialin(priv, UART_DLL_OFFSET);
```

[(We capture DLM and DLL only when DLAB=1)](https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L817-L851)

(Be careful to print only when DLAB=0)

According to our log, DLM is 0 and DLL is 13. Which means..

```text
dlm =  0 = (div >> 8)
dll = 13 = (div & 0xff)
```

Which gives `div=13`. Now since `baud=115200` at startup...

```text
div = (uartclk + (baud << 3)) / (baud << 4)
13  = (uartclk + 921600) / 1843200
uartclk = (13 * 1843200) - 921600
        = 23040000
```

Thus `uartclk=23040000`. And that's why we set...

```bash
CONFIG_16550_UART0_CLOCK=23040000
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/57d5bba4723b58c7bb947f9fa206be377c80c8d0/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L10-L18)

