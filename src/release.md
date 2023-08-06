# Star64 JH7110 + NuttX RTOS: Creating the First Release

📝 _12 Aug 2023_

![Apache NuttX RTOS boots OK on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-title.png)

[__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) is now officially supported on [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html), the same SoC in VisionFive2)

In this article we explain how we __created the First Release__ of NuttX for Star64 JH7110...

- __Building NuttX__ for Star64

- Creating a __Bootable microSD__ with NuttX Kernel and Initial RAM Disk

- What happens during __NuttX Startup__

- Adding the __NuttX Arch__ (JH7110) and __NuttX Board__ (Star64)

- __Upcoming Features__ for NuttX on Star64

Which is probably helpful for folks who wish to...

- Add a new __NuttX Arch__ (SoC) or __NuttX Board__

- Create __NuttX Drivers__ (or __NuttX Apps__) for Star64 (or VisionFive2)

- Or simply understand how we __boot a Modern SBC__ from scratch!

[(Watch the __Demo Video__ on YouTube)](https://youtu.be/6vQ-TXXojbQ)

![Star64 RISC-V SBC](https://lupyuen.github.io/images/nuttx2-star64.jpg)

# Build NuttX for Star64

Let's walk through the steps to __build NuttX for Star64__...

1.  Install the [__NuttX Build Tools__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

1.  Download the __NuttX Repositories__...

    ```bash
    $ git clone https://github.com/apache/nuttx.git nuttx
    $ git clone https://github.com/apache/nuttx-apps apps
    ```

1.  Download the __RISC-V Toolchain riscv64-unknown-elf__ from [__SiFive RISC-V Tools__](https://github.com/sifive/freedom-tools/releases/tag/v2020.12.0).

    Add the downloaded toolchain "__riscv64-unknown-elf-toolchain-.../bin__" to the __PATH__ Environment Variable.

    Check the RISC-V Toolchain:

    ```bash
    $ riscv64-unknown-elf-gcc -v
    ```

1.  Configure and __build the NuttX Project__...

    ```bash
    $ cd nuttx
    $ tools/configure.sh star64:nsh
    $ make
    $ riscv64-unknown-elf-objcopy -O binary nuttx nuttx.bin
    ```

    This produces the NuttX Kernel [__nuttx.bin__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/nuttx.bin)
    
1.  Build the __NuttX Apps Filesystem__...

    ```bash
    $ make export
    $ pushd ../apps
    $ tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    $ make import
    $ popd
    $ genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
    ```

    This generates the Initial RAM Disk [__initrd__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/initrd)

1.  Download the Device Tree [__jh7110-visionfive-v2.dtb__](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/jh7110-visionfive-v2.dtb) from [__StarFive VisionFive2 Software Releases__](https://github.com/starfive-tech/VisionFive2/releases).

    Save it into the __nuttx__ folder. Or do this...

    ```bash
    $ wget https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/jh7110-visionfive-v2.dtb
    ```

    (NuttX doesn't need a Device Tree, but it's needed by U-Boot)

1.  (Optional) For easier debugging, we might create the following...

    ```bash
    ## Copy the config
    $ cp .config nuttx.config

    ## Dump the Kernel disassembly to `nuttx.S`
    $ riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1

    ## Dump the NSH `init` disassembly to `init.S`
    $ riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      ../
    ```

    [(See the Build Outputs)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

    [(See the Build Steps)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110b-0.0.1)

    [(See the Build Log)](https://gist.github.com/lupyuen/c6dc9aeec74d399029ebaf46ac16ef79)

Now we create a Bootable microSD...

TODO

_NuttX goes into the partition that has NO NAME_

# NuttX in a Bootable microSD

_How do we create a Bootable microSD for NuttX?_

From the previous section, we have...

1.  NuttX Kernel: [__nuttx.bin__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/nuttx.bin)

1.  Initial RAM Disk: [__initrd__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/initrd)

1.  Device Tree: [__jh7110-visionfive-v2.dtb__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/jh7110-visionfive-v2.dtb)

We pack all 3 files into a __Flat Image Tree (FIT)__...

Inside the __nuttx__ folder, create a Text File named __nuttx.its__
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

Or do this...

```bash
$ wget https://raw.githubusercontent.com/lupyuen/nuttx-star64/main/nuttx.its
```

[(Based on visionfive2-fit-image.its)](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/conf/visionfive2-fit-image.its)

Package the NuttX Kernel, Initial RAM Disk and Device Tree into a
Flat Image Tree...

```bash
## For macOS:
$ brew install u-boot-tools
## For Linux:
$ sudo apt install u-boot-tools

## Generate FIT Image from `nuttx.bin`, 
## `initrd` and `jh7110-visionfive-v2.dtb`.
## `nuttx.its` must be in the same 
## directory as the NuttX binaries!
$ mkimage \
  -f nuttx.its \
  -A riscv \
  -O linux \
  -T flat_dt \
  starfiveu.fit

## To check FIT image
$ mkimage -l starfiveu.fit
```

We'll see the __NuttX Kernel__...

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
```

Followed by the __Initial RAM Disk__ (containing __NuttX Apps__)...

```text
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
```

Finally the __Device Tree__ (not used by NuttX)...

```text
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
 Default Configuration: 'nuttx'
 Configuration 0 (nuttx)
  Description:  NuttX
  Kernel:       vmlinux
  FDT:          fdt
  Loadables:    ramdisk
```

This produces the Flat Image Tree [__starfiveu.fit__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/starfiveu.fit), which we'll copy later to a microSD Card.

To prepare the microSD Card, download the microSD Image [__sdcard.img__](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/sdcard.img) from [__StarFive VisionFive2 Software Releases__](https://github.com/starfive-tech/VisionFive2/releases).

Write the downloaded image to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

Copy the file [__starfiveu.fit__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110b-0.0.1/starfiveu.fit) from above and overwrite the file on the microSD Card...

```bash
## For macOS: Copy to microSD
cp starfiveu.fit "/Volumes/NO NAME"
ls -l "/Volumes/NO NAME/starfiveu.fit"

## For macOS: Unmount the microSD
## TODO: Verify that /dev/disk2 is microSD
diskutil unmountDisk /dev/disk2
```

We're ready to boot NuttX on Star64!

[(More about __Flat Image Tree__)](https://u-boot.readthedocs.io/en/latest/usage/fit/source_file_format.html)

[(How __sdcard.img__ was created)](https://lupyuen.github.io/articles/release#appendix-starfive-visionfive2-software-release)

![Apache NuttX RTOS boots OK on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-title.png)

# Boot NuttX on Star64

TODO

Connect Star64 to our computer with a __USB Serial Adapter__...

- [__"Serial Console on Star64"__](https://lupyuen.github.io/articles/linux#serial-console-on-star64)

Insert the microSD Card into Star64 and power up Star64.
NuttX boots on Star64 and NuttShell (nsh) appears in the Serial Console.

To see the available commands in NuttShell:

```bash
$ help
```

[(Watch the __Demo Video__ on YouTube)](https://youtu.be/6vQ-TXXojbQ)

[__Booting NuttX over TFTP__](https://lupyuen.github.io/articles/tftp) is also supported on Star64.

_What happens at startup?_

1.  __OpenSBI (Supervisor Binary Interface)__ is the first thing that boots on our SBC...

    [__"OpenSBI Supervisor Binary Interface"__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface)

    (In [__RISC-V Machine Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels))

1.  __U-Boot Bootloader__ is next (in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels))...

    [__"U-Boot Bootloader for Star64"__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

    Which loads the...

1.  __NuttX Kernel__ (also in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels))

    Which starts the...

1.  __NuttX Boot Code__ (in RISC-V Assembly)...

    [__"NuttX in Supervisor Mode (Boot Code)"__](https://lupyuen.github.io/articles/nuttx2#appendix-nuttx-in-supervisor-mode)

    Which calls the...

1.  __NuttX Start Code__ (in C)...

    [__"Initialise RISC-V Supervisor Mode: jh7110_start"__](https://lupyuen.github.io/articles/privilege#initialise-risc-v-supervisor-mode)

    Which calls [__jh7110_start_s__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_start.c#L82-L129) and...

1.  [__jh7110_mm_init__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_mm_init.c#L259-L284) to initialise the __Memory Mangement Unit__ (for Kernel Memory Protection) and...

    [__nx_start__](https://lupyuen.github.io/articles/unicorn2#after-primary-routine) to start the __NuttX Drivers__ and [__Initial RAM Disk__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk) (containing the __NuttX Apps__)...

    And starts...

1.  __NuttX Shell__ (NSH) for the Command-Line Interface...

    [__"NuttX Apps Filesystem: init / nsh"__](https://lupyuen.github.io/articles/semihost#nuttx-apps-filesystem)

    (Phew!)

__NuttX Shell__ (NSH) and __NuttX Apps__ will run in __RISC-V User Mode__ and make...

1.  __System Calls__ to NuttX Kernel, jumping from User Mode to Supervisor Mode...

    [__"ECALL from RISC-V User Mode to Supervisor Mode"__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu)

    Like when doing...

1.  __Serial I/O__ for Console Input and Output...

    [__"Serial Output in NuttX"__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu)

    [__"Serial Input in NuttX"__](https://lupyuen.github.io/articles/plic#serial-input-in-nuttx-qemu)

    Which will trigger...

1.  __RISC-V Interrupts__ for the 16550 UART Controller...

    [__"Platform-Level Interrupt Controller"__](https://lupyuen.github.io/articles/plic#platform-level-interrupt-controller)

And that's everything that happens when NuttX boots on Star64!

# Add the NuttX Arch and Board

_How did we add Star64 JH7110 to NuttX?_

When we add a new board to NuttX, we do it in 4 steps...

1.  Patch the __NuttX Dependencies__

    [(Like this)](https://github.com/apache/nuttx/pull/10019)

1.  Add the __NuttX Arch__ (JH7110 SoC)

    [(Like this)](https://github.com/apache/nuttx/pull/10069)

1.  Add the __NuttX Board__ (Star64 SBC)

    [(Like this)](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

1.  Update the __NuttX Documentation__

    [(Also here)](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

This is how we did it for Star64 SBC (with JH7110 SoC) in __3 Pull Requests__...

## Patch the NuttX Dependencies

First we patch any __NuttX Dependencies__ needed by Star64 JH7110. 

JH7110 triggers too many __spurious UART interrupts__...

- [__"Spurious UART Interrupts"__](https://lupyuen.github.io/articles/plic#spurious-uart-interrupts)

JH7110 uses a __Synopsys DesignWare 8250 UART__ that has a peculiar problem with the __Line Control Register (LCR)__... If we write to LCR while the UART is busy, it will trigger spurious UART Interrupts.

The fix is to __wait for the UART__ to be not busy before writing to LCR. We submitted this Pull Request to fix the __NuttX 16550 UART Driver__...

- [__"serial/uart_16550: Wait before setting Line Control Register"__](https://github.com/apache/nuttx/pull/10019)

  [(How to submit a __Pull Request__ for NuttX)](https://lupyuen.github.io/articles/pr)

## Add the NuttX Arch

TODO

Next we submit the PR that implements the JH7110 SoC as a __NuttX Arch__...

[Add support for JH7110 SoC](https://github.com/apache/nuttx/pull/10069)

We add JH7110 to the Kconfig for the RISC-V SoCs: [arch/risc-v/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-9c348f27c59e1ed0d1d9c24e172d233747ee09835ab0aa7f156da1b7caa6a5fb)

And we create a Kconfig for JH7110: [arch/risc-v/src/jh7110/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-36a3009882ced77a24e9a7fd7ce3cf481ded4655f1adc366e7722a87ceab293b)

Then we add the source files for JH7110 at...

[arch/risc-v/src/jh7110](https://github.com/apache/nuttx/tree/master/arch/risc-v/src/jh7110)

## Add the NuttX Board

TODO

Finally we submit the PR that implements Star64 SBC as a __NuttX Board__...

[Add support for Star64 SBC](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

We add Star64 to the Kconfig for the NuttX Boards: [nuttx/boards/Kconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-60cc096e3a9b22a769602cbbc3b0f5e7731e72db7b0338da04fcf665ed753b64)

We create a Kconfig for Star64: [nuttx/boards/risc-v/jh7110/star64/Kconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-76f41ff047f7cc79980a18f527aa05f1337be8416d3d946048b099743f10631c)

And we add the source files for Star64 at...

[boards/risc-v/jh7110/star64](https://github.com/apache/nuttx/tree/master/boards/risc-v/jh7110/star64)

We'll talk about the Documentation in the next section.

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

That we can copy to another branch in a (barebones) script...

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

[boards/risc-v/jh7110/star64/ configs/nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40/files#diff-cdbd91013d0074f15d469491b707d1d6576752bd7b7b9ec6ed311edba8ab4b53)

We generated the `defconfig` with this command...

```bash
make menuconfig \
  && make savedefconfig \
  && grep -v CONFIG_HOST defconfig \
  >boards/risc-v/jh7110/star64/configs/nsh/defconfig
```

[(How we computed the __UART Clock__)](https://lupyuen.github.io/articles/release#appendix-uart-clock-for-jh7110)

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

![TODO](https://lupyuen.github.io/images/release-doc3.png)

# Update the NuttX Docs

TODO

In the same PR, update the __NuttX Docs__...

Add JH7110 and Star64 to the list of supported platforms: (pic above)

[Documentation/introduction/ detailed_support.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-d8a0e68fcb8fcb7e919c4b01226b6a25f888ed297145b82c719875cf8e6f5ae4)

![TODO](https://lupyuen.github.io/images/release-doc2.png)

Create a page for the JH7110 NuttX Arch: (pic above)

[Documentation/platforms/risc-v/ jh7110/index.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-79d8d013e3cbf7600551f1ac23beb5db8bd234a0067576bfe0997b16e5d5c148)

![TODO](https://lupyuen.github.io/images/release-doc1.png)

Under JH7110, create a page for the Star64 NuttX Board: (pic above)

[Documentation/platforms/risc-v/ jh7110/boards/star64/index.rst](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/38/files#diff-a57fa454397c544c8a717c35212a88d3e3e0c77c9c6e402f5bb52dfeb62e1349)

To update and preview the NuttX Docs, follow the instructions here...

-   [__"NuttX Documentation"__](https://nuttx.apache.org/docs/latest/contributing/documentation.html)

    [(See the Log)](https://gist.github.com/lupyuen/c061ac688f430ef11a1c60e0b284a1fe)

![Testing Apache NuttX RTOS on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-star64.jpg)

# Upcoming Features

_How will we create the missing drivers?_

We welcome [__your contribution to NuttX__](https://lupyuen.github.io/articles/pr)!

Here are the relevant docs from...

- [__J7110 Technical Reference Manual__](https://doc-en.rvspace.org/JH7110/TRM/)

- [__VisionFive 2 Developing and Porting Guide__](https://doc-en.rvspace.org/Doc_Center/sdk_developer_guide.html)

__GPIO:__

- [GPIO Programming Reference](https://doc-en.rvspace.org/JH7110/TRM/JH7110_DS/gpio_program_ref.html)

- [GPIO Source Code Structure](https://doc-en.rvspace.org/VisionFive2/DG_GPIO/JH7110_SDK/code_structure_gpio.html)

  [(pinctrl-starfive-jh7110.c)](https://github.com/torvalds/linux/blob/master/drivers/pinctrl/starfive/pinctrl-starfive-jh7110.c)

- [SDK for GPIO](http://doc-en.rvspace.org/VisionFive2/DG_GPIO/)

__RTC, SPI, UART, DMA, I2C, I2S, PWM:__

- [RTC Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_RTC/)

- [SPI Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_SPI/)

- [UART Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_UART/)

- [DMA Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_DMA/)

- [SDK for I2C](http://doc-en.rvspace.org/VisionFive2/DG_I2C/)

- [SDK for I2S](http://doc-en.rvspace.org/VisionFive2/DG_I2S/)

- [PWM Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_PWM/)

__USB, Ethernet:__

- [USB Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_USB/)

- [Ethernet Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/PG_Ethernet/)

__Display:__

- [Display Subsystem](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/display_subsystem.html)

- [SDK for HDMI](http://doc-en.rvspace.org/VisionFive2/DG_HDMI/)

- [Display Controller Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Display/)

- [GPU Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_GPU/)

- [Multimedia Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Multimedia/)

- [LCD Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_LCD/)

__Image Sensor Processor:__

- [ISP Reference](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/isp_rgb.html)

- [ISP Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_ISP/)

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

