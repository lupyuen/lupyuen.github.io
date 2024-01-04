# Star64 JH7110 + NuttX RTOS: Creating the First Release for the RISC-V SBC

📝 _7 Aug 2023_

![Apache NuttX RTOS boots OK on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-title.png)

[_(Also on __Hackster.io__)_](https://www.hackster.io/lupyuen/rtos-on-a-risc-v-sbc-star64-jh7110-apache-nuttx-2a7429)

[__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) now officially supports [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Works on [__StarFive VisionFive2 SBC__](https://github.com/lupyuen/lupyuen.github.io/issues/19#issuecomment-1715054007) too, since both SBCs are based on [__StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html))

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

1.  Install the __NuttX Build Prerequisites__, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the __RISC-V Toolchain riscv64-unknown-elf__...

    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

    Add the downloaded toolchain to the __PATH__ Environment Variable.
    
    Check the RISC-V Toolchain:

    ```bash
    $ riscv64-unknown-elf-gcc -v
    ```

1.  Download the __NuttX Repositories__...

    ```bash
    $ mkdir nuttx
    $ cd nuttx
    $ git clone https://github.com/apache/nuttx.git nuttx
    $ git clone https://github.com/apache/nuttx-apps apps
    ```

1.  Configure and __build the NuttX Project__...

    ```bash
    $ cd nuttx
    $ tools/configure.sh star64:nsh
    $ make
    $ riscv64-unknown-elf-objcopy -O binary nuttx nuttx.bin
    ```

    This produces the NuttX Kernel [__nuttx.bin__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/nuttx.bin)

    [(Missing __`math.h`__? See this)](https://lupyuen.github.io/articles/release#appendix-missing-mathh)

1.  Build the __NuttX Apps Filesystem__...

    ```bash
    $ make export
    $ pushd ../apps
    $ tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    $ make import
    $ popd
    $ genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
    ```

    This generates the Initial RAM Disk [__initrd__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/initrd)

1.  Download the Device Tree [__jh7110-visionfive-v2.dtb__](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/jh7110-visionfive-v2.dtb) from [__StarFive VisionFive2 Software Releases__](https://github.com/starfive-tech/VisionFive2/releases).

    Save it into the __nuttx__ folder. Or do this...

    ```bash
    $ wget https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/jh7110-visionfive-v2.dtb
    ```

    (NuttX doesn't need a Device Tree, but U-Boot Bootloader needs it)

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

    [(See the Build Outputs)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110c-1.0.0)

    [(See the Build Steps)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/jh7110c-1.0.0)

    [(See the Build Log)](https://gist.github.com/lupyuen/c6dc9aeec74d399029ebaf46ac16ef79)

    [(GitHub Actions Workflow)](https://github.com/lupyuen/nuttx-star64/blob/main/.github/workflows/star64.yml)

    [(Automated Daily Builds)](https://github.com/lupyuen/nuttx-star64/releases)

    [(Shell Script to Build and Run NuttX)](https://gist.github.com/lupyuen/62392f5644f903232f5fcde2d5b9a03d)

Now we create a Bootable microSD...

![NuttX goes into the FAT Partition on the microSD](https://lupyuen.github.io/images/release-microsd.png)

_NuttX goes into the FAT Partition on the microSD_

# NuttX in a Bootable microSD

_How do we create a Bootable microSD for NuttX?_

From the previous section, we have...

- NuttX Kernel: [__nuttx.bin__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/nuttx.bin)

- Initial RAM Disk: [__initrd__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/initrd)

- Device Tree: [__jh7110-visionfive-v2.dtb__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/jh7110-visionfive-v2.dtb)

Now we pack all 3 files into a __Flat Image Tree (FIT)__...

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

Package the NuttX Kernel, Initial RAM Disk and Device Tree into a Flat Image Tree...

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

This produces the Flat Image Tree [__starfiveu.fit__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/starfiveu.fit), which we'll copy later to a microSD Card.

To prepare the microSD Card, download the microSD Image [__sdcard.img__](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/sdcard.img) from [__StarFive VisionFive2 Software Releases__](https://github.com/starfive-tech/VisionFive2/releases).

Write the downloaded image to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks). [(Or use __`dd`__)](https://gist.github.com/lupyuen/aae995d942d5ec3ffa6629667bcc3ae6)

Copy the file [__starfiveu.fit__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/jh7110c-1.0.0/starfiveu.fit) from above and overwrite the file on the microSD Card...

```bash
## For macOS: Copy to microSD
cp starfiveu.fit "/Volumes/NO NAME"

## For macOS: Unmount the microSD
## TODO: Verify that /dev/disk2 is microSD
diskutil unmountDisk /dev/disk2
```

We're ready to boot NuttX on Star64!

[(More about __Flat Image Tree__)](https://u-boot.readthedocs.io/en/latest/usage/fit/source_file_format.html)

[(How __sdcard.img__ was created)](https://lupyuen.github.io/articles/release#appendix-starfive-visionfive2-software-release)

![Apache NuttX RTOS boots OK on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-title.png)

# Boot NuttX on Star64

Connect Star64 to our computer with a __USB Serial Adapter__...

- [__"Serial Console on Star64"__](https://lupyuen.github.io/articles/linux#serial-console-on-star64)

Insert the microSD Card into Star64 and power up Star64.
NuttX boots on Star64 and __NuttShell (nsh)__ appears in the Serial Console.

To see the available commands in NuttShell:

```bash
$ help
```

[(Watch the __Demo Video__ on YouTube)](https://youtu.be/6vQ-TXXojbQ)

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/eef8de0817ceed2072b2bacc925cdd96)

[__Booting NuttX over TFTP__](https://lupyuen.github.io/articles/tftp) is also supported on Star64.

![Booting NuttX over the Network with TFTP](https://lupyuen.github.io/images/tftp-flow.jpg)

# NuttX Startup Explained

Step by step, here's everything that happens when NuttX boots on our SBC...

![OpenSBI and U-Boot Bootloader](https://lupyuen.github.io/images/star64-opensbi.jpg)

1.  [__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface) is the first thing that boots on our RISC-V SBC.

    OpenSBI provides Secure Access to the [__Low-Level System Functions__](https://github.com/riscv-non-isa/riscv-sbi-doc) (controlling CPUs, Timers, Interrupts) for the JH7110 SoC.
    
    OpenSBI boots in [__RISC-V Machine Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels), the most powerful mode in a RISC-V system.

    [__"OpenSBI Supervisor Binary Interface"__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface)

    ![OpenSBI starts U-Boot Bootloader](https://lupyuen.github.io/images/privilege-title.jpg)

1.  [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) starts after OpenSBI, in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels).

    (Which is less powerful than Machine Mode)

    [__"U-Boot Bootloader for Star64"__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

    ![Star64 boots with NuttX Kernel, Device Tree and Initial RAM Disk](https://lupyuen.github.io/images/semihost-title.jpg)

1.  U-Boot Bootloader loads into RAM the [__NuttX Kernel__](https://lupyuen.github.io/articles/nuttx2#risc-v-linux-kernel-header), __Device Tree__ and [__Initial RAM Disk__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk).

    Inside the Initial RAM Disk: __NuttX Shell__ and __NuttX Apps__.

1.  __NuttX Kernel__ starts in [__RISC-V Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels) and executes the __NuttX Boot Code__ (in RISC-V Assembly).

    [__"NuttX in Supervisor Mode (Boot Code)"__](https://lupyuen.github.io/articles/nuttx2#appendix-nuttx-in-supervisor-mode)

1.  [__NuttX Start Code__](https://lupyuen.github.io/articles/privilege#initialise-risc-v-supervisor-mode) (in C) runs next.

    It prepares the [__RISC-V Memory Management Unit__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_mm_init.c#L259-L284), to protect the Kernel Memory and I/O Memory.

    [__"Initialise RISC-V Supervisor Mode: jh7110_start"__](https://lupyuen.github.io/articles/privilege#initialise-risc-v-supervisor-mode) and [__jh7110_start_s__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/jh7110_start.c#L82-L129)

1.  [__NuttX Kernel (nx_start)__](https://lupyuen.github.io/articles/unicorn2#after-primary-routine) starts the __NuttX Drivers__ and mounts the [__Initial RAM Disk__](https://lupyuen.github.io/articles/semihost#modify-nuttx-qemu-for-initial-ram-disk) (containing the NuttX Shell and Apps)

1.  Followed by the [__NuttX Shell (NSH)__](https://lupyuen.github.io/articles/semihost#nuttx-apps-filesystem), for the Command-Line Interface

    [__"NuttX Apps Filesystem: init / nsh"__](https://lupyuen.github.io/articles/semihost#nuttx-apps-filesystem)

Finally we talk about the __NuttX Shell and Apps__...

1.  __NuttX Shell__ (NSH) and __NuttX Apps__ (like "hello") will run in __RISC-V User Mode__.

    (Which is the least powerful mode)

1.  They will make [__System Calls__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu) to NuttX Kernel, jumping from __User Mode__ to __Supervisor Mode__. (And back)

    [__"ECALL from RISC-V User Mode to Supervisor Mode"__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu)

1.  System Calls will happen when NuttX Shell and Apps do [__Console Output__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu) and [__Console Input__](https://lupyuen.github.io/articles/plic#serial-input-in-nuttx-qemu).

    [__"Serial Output in NuttX"__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu)

    [__"Serial Input in NuttX"__](https://lupyuen.github.io/articles/plic#serial-input-in-nuttx-qemu)

1.  Which will trigger __RISC-V Interrupts__ in the 16550 UART Controller.

    [__"Platform-Level Interrupt Controller"__](https://lupyuen.github.io/articles/plic#platform-level-interrupt-controller)

    ![UART Interrupts are handled by the RISC-V Platform-Level Interrupt Controller (PLIC)](https://lupyuen.github.io/images/plic-title.jpg)

And that's everything that happens when NuttX boots on Star64!

_But NuttX doesn't actually need a Device Tree!_

Yeah but because the Flat Image Tree needs a Device Tree, we do it anyway.

_We created all this code from scratch?_

Actually most of the code came from [__NuttX for QEMU RISC-V__](https://lupyuen.github.io/articles/riscv)! (In Kernel Mode)

It's amazing that we reused so much code from NuttX QEMU. And ported everything to Star64 within 2 months!

_What's the catch?_

We have some __Size Limitations__ on the Initial RAM Disk, NuttX Apps and NuttX Stacks. Here are the workarounds...

- [__"Increase RAM Disk Limit"__](https://github.com/lupyuen/nuttx-star64#increase-ram-disk-limit)

- [__"Memory Map for RAM Disk"__](https://github.com/lupyuen/nuttx-star64#memory-map-for-ram-disk)

- [__"Increase Page Heap Size"__](https://github.com/lupyuen/nuttx-star64#increase-page-heap-size)

- [__"Test the Page Heap"__](https://github.com/lupyuen/nuttx-star64#test-the-page-heap)

- [__"Increase Stack Size"__](https://github.com/lupyuen/nuttx-star64#increase-stack-size)

Porting __Linux / Unix / POSIX Apps__ to NuttX might need extra work, check out this example...

- [__"Scheme Interpreter crashes on NuttX"__](https://github.com/lupyuen/nuttx-star64#scheme-interpreter-crashes-on-nuttx)

- [__"Increase Stack Size for Scheme Interpreter"__](https://github.com/lupyuen/nuttx-star64#increase-stack-size-for-scheme-interpreter)

- [__"Analyse the Stack Dump for Scheme Interpreter"__](https://github.com/lupyuen/nuttx-star64#analyse-the-stack-dump-for-scheme-interpreter)

![Pull Request for NuttX Board](https://lupyuen.github.io/images/release-pr2.jpg)

# Add the NuttX Arch and Board

_How did we add Star64 JH7110 to NuttX?_

When we add a new board to NuttX, we do it in 4 steps...

1.  Patch the __NuttX Dependencies__

    [(Like this)](https://github.com/apache/nuttx/pull/10019)

1.  Add the __NuttX Arch__ (JH7110 SoC)

    [(Like this)](https://github.com/apache/nuttx/pull/10069)

1.  Add the __NuttX Board__ (Star64 SBC)

    [(Like this)](https://github.com/apache/nuttx/pull/10094)

1.  Update the __NuttX Documentation__

    [(Also here)](https://github.com/apache/nuttx/pull/10094)

This is how we did it for Star64 SBC (with JH7110 SoC) in __3 Pull Requests__...

## Patch the NuttX Dependencies

First we patch any __NuttX Dependencies__ needed by Star64 JH7110. 

We discovered that JH7110 triggers too many __spurious UART interrupts__...

- [__"Spurious UART Interrupts"__](https://lupyuen.github.io/articles/plic#spurious-uart-interrupts)

JH7110 uses a __Synopsys DesignWare 8250 UART__ that has a peculiar problem with the __Line Control Register (LCR)__... If we write to LCR while the UART is busy, it will trigger spurious UART Interrupts.

The fix is to __wait for the UART__ to be not busy before writing to LCR. We submitted this Pull Request to fix the __NuttX 16550 UART Driver__...

- [__"serial/uart_16550: Wait before setting Line Control Register"__](https://github.com/apache/nuttx/pull/10019)

Wait for the Pull Request to be merged. Then we add the NuttX Arch...

[(How to submit a __Pull Request__ for NuttX)](https://lupyuen.github.io/articles/pr)

## Add the NuttX Arch

Next we submit the Pull Request that implements the support for JH7110 SoC as a __NuttX Arch__...

- [__"arch/risc-v: Add support for StarFive JH7110 SoC"__](https://github.com/apache/nuttx/pull/10069)

We insert JH7110 SoC into the __Kconfig for the RISC-V SoCs__: [arch/risc-v/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-9c348f27c59e1ed0d1d9c24e172d233747ee09835ab0aa7f156da1b7caa6a5fb)

```text
config ARCH_CHIP_JH7110
	bool "StarFive JH7110"
	select ARCH_RV64
	select ARCH_RV_ISA_M
	select ARCH_RV_ISA_A
	select ARCH_RV_ISA_C
	select ARCH_HAVE_FPU
	select ARCH_HAVE_DPFPU
	select ARCH_HAVE_MULTICPU
	select ARCH_HAVE_MPU
	select ARCH_HAVE_MMU
	select ARCH_MMU_TYPE_SV39
	select ARCH_HAVE_ADDRENV
	select ARCH_NEED_ADDRENV_MAPPING
	select ARCH_HAVE_S_MODE
	select ONESHOT
	select ALARM_ARCH
	---help---
		StarFive JH7110 SoC.
...
config ARCH_CHIP
	...
	default "jh7110"	if ARCH_CHIP_JH7110
...
if ARCH_CHIP_JH7110
source "arch/risc-v/src/jh7110/Kconfig"
endif
```

(Remember to indent with Tabs, not Spaces!)

And we create a __Kconfig for JH7110 SoC__: [arch/risc-v/src/jh7110/Kconfig](https://github.com/apache/nuttx/pull/10069/files#diff-36a3009882ced77a24e9a7fd7ce3cf481ded4655f1adc366e7722a87ceab293b)

Then we add the __NuttX Arch Source Files__ for JH7110 SoC at...

- [__arch/risc-v/src/jh7110__](https://github.com/apache/nuttx/tree/master/arch/risc-v/src/jh7110)

  [(Description of each file)](https://github.com/apache/nuttx/pull/10069)

## Add the NuttX Board

Finally we create the Pull Request that implements the support for Star64 SBC as a __NuttX Board__...

- [__"boards/risc-v: Add support for PINE64 Star64 JH7110 SBC"__](https://github.com/apache/nuttx/pull/10094)

We insert Star64 SBC into the __Kconfig for NuttX Boards__: [nuttx/boards/Kconfig](https://github.com/apache/nuttx/pull/10094/files#diff-60cc096e3a9b22a769602cbbc3b0f5e7731e72db7b0338da04fcf665ed753b64)

```text
config ARCH_BOARD_JH7110_STAR64
	bool "PINE64 Star64"
	depends on ARCH_CHIP_JH7110
	---help---
		This options selects support for NuttX on PINE64 Star64 based
		on StarFive JH7110 SoC.
...
config ARCH_BOARD
	...
	default "star64"                    if ARCH_BOARD_JH7110_STAR64
...
if ARCH_BOARD_JH7110_STAR64
source "boards/risc-v/jh7110/star64/Kconfig"
endif
```

(Remember to indent with Tabs, not Spaces!)

We create a __Kconfig for Star64 SBC__: [nuttx/boards/risc-v/jh7110/star64/Kconfig](https://github.com/apache/nuttx/pull/10094/files#diff-76f41ff047f7cc79980a18f527aa05f1337be8416d3d946048b099743f10631c)

And we add the __NuttX Board Source Files__ for Star64 SBC at...

- [__boards/risc-v/jh7110/star64__](https://github.com/apache/nuttx/tree/master/boards/risc-v/jh7110/star64)

  [(Description of each file)](https://github.com/apache/nuttx/pull/10094)

But don't submit the Pull Request yet! We'll add the __NuttX Documentation__ in the next section.

_We're good for RISC-V. What about Arm?_

This is how we add a __NuttX Arch and Board for Arm64__...

-   [__"arch/arm64: Add support for PINE64 PinePhone"__](https://github.com/apache/nuttx/pull/7692)

Though we probably should have split it into multiple Pull Requests like for RISC-V.

_Seems we need to copy a bunch of source files across branches?_

No sweat! Suppose we created a staging Pull Request in our own repo...

- [github.com/lupyuen2/wip-pinephone-nuttx/pull/40](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/40)

This command produces a list of __Modified Files in our Pull Request__...

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

That we can __copy to another branch__ in a simple script...

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

- [__boards/risc-v/jh7110/star64/ configs/nsh/defconfig__](https://github.com/apache/nuttx/pull/10094/files#diff-cdbd91013d0074f15d469491b707d1d6576752bd7b7b9ec6ed311edba8ab4b53)

We generated the __defconfig__ with this command...

```bash
make menuconfig \
  && make savedefconfig \
  && grep -v CONFIG_HOST defconfig \
  >boards/risc-v/jh7110/star64/configs/nsh/defconfig
```

[(How we computed the __UART Clock__)](https://lupyuen.github.io/articles/release#appendix-uart-clock-for-jh7110)

During development, we should enable additional __Debug Options__...

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

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L49-L69)

- __BINFMT__ is the Binary Loader, good for troubleshooting NuttX App ELF loading issues

- __SCHED__ is for Task Scheduler, which will show the spawning of NuttX App Tasks

- __MM__ is for Memory Management, for troubleshooting Memory Mapping issues

- __FS__ is for File System, like the Initial RAM Disk

Before merging with NuttX Mainline, remember to remove the Debug Options for BINFMT, FS, MM and SCHED.

![JH7110 NuttX Arch](https://lupyuen.github.io/images/release-doc2.png)

# Update the NuttX Docs

Earlier we created a Pull Request to [__add a new NuttX Board__](https://lupyuen.github.io/articles/release#add-the-nuttx-board).

In the same Pull Request, we update the __NuttX Docs__ like so...

Create a page for the __JH7110 NuttX Arch__ (pic above)...

[Documentation/platforms/risc-v/ jh7110/index.rst](https://github.com/apache/nuttx/pull/10094/files#diff-79d8d013e3cbf7600551f1ac23beb5db8bd234a0067576bfe0997b16e5d5c148)

```text
===============
StarFive JH7110
===============

`StarFive JH7110 <https://doc-en.rvspace.org/Doc_Center/jh7110.html>`_ is a 64-bit RISC-V SoC that features:

- **CPU:** SiFive RISC-V U74 Application Cores (4 cores, RV64GCB) and SiFive RISC-V S7 Monitor Core (single core, RV64IMACB)
...
```

(Which goes under "RISC-V" because it's a RISC-V SoC)

[(Tips for __Restructured Text__)](https://thomas-cokelaer.info/tutorials/sphinx/rest_syntax.html)

![Star64 NuttX Board](https://lupyuen.github.io/images/release-doc1.png)

Under JH7110, create a page for the __Star64 NuttX Board__ (pic above)...

[Documentation/platforms/risc-v/ jh7110/boards/star64/index.rst](https://github.com/apache/nuttx/pull/10094/files#diff-a57fa454397c544c8a717c35212a88d3e3e0c77c9c6e402f5bb52dfeb62e1349)

```text
=============
PINE64 Star64
=============

`Star64 <https://wiki.pine64.org/wiki/STAR64>`_ is a 64-bit RISC-V based
Single Board Computer powered by StarFive JH7110 Quad-Core SiFive U74 64-Bit CPU,
Imagination Technology BX-4-32 GPU and supports up to 8GB 1866MHz LPDDR4 memory.
...
```

On that page, remember to document the steps to __Build and Boot NuttX__...

- [__Toolchain__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#risc-v-toolchain) and [__Building__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#building)

- [__Serial Console__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#serial-console) and [__Booting__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#booting) 

- [__Configurations__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#configurations) and [__Peripheral Support__](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/Documentation/platforms/risc-v/jh7110/boards/star64/index.rst#peripheral-support)

To update and preview the NuttX Docs, follow the instructions here...

-   [__"NuttX Documentation"__](https://nuttx.apache.org/docs/latest/contributing/documentation.html)

    [(See the Log)](https://gist.github.com/lupyuen/c061ac688f430ef11a1c60e0b284a1fe)

And now we're ready to submit the Pull Request. That's how we add a NuttX Arch and NuttX Board!

![Testing Apache NuttX RTOS on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-star64.jpg)

# Upcoming Features

_How will we create the missing drivers for Star64 JH7110?_

We welcome [__your contribution to NuttX__](https://lupyuen.github.io/articles/pr)!

Based on the official docs...

- [__JH7110 Technical Reference Manual__](https://doc-en.rvspace.org/JH7110/TRM/)

- [__VisionFive 2 Developing and Porting Guide__](https://doc-en.rvspace.org/Doc_Center/sdk_developer_guide.html)

We have started working on the __HDMI Support for NuttX__ on Star64 JH7110...

- [__"RISC-V Star64 JH7110: Inside the Display Controller"__](https://lupyuen.github.io/articles/display2)

Here are the relevant docs for the other JH7110 Peripherals...

__GPIO:__

- [GPIO Programming Reference](https://doc-en.rvspace.org/JH7110/TRM/JH7110_DS/gpio_program_ref.html)

- [GPIO Source Code Structure](https://doc-en.rvspace.org/VisionFive2/DG_GPIO/JH7110_SDK/code_structure_gpio.html)

  [(pinctrl-starfive-jh7110.c)](https://github.com/torvalds/linux/blob/master/drivers/pinctrl/starfive/pinctrl-starfive-jh7110.c)

- [SDK for GPIO](http://doc-en.rvspace.org/VisionFive2/DG_GPIO/)

__I2C:__

- [SDK for I2C](http://doc-en.rvspace.org/VisionFive2/DG_I2C/)

  (Based on [DesignWare I2C](https://github.com/torvalds/linux/blob/master/drivers/i2c/busses/i2c-designware-core.h))
  
  This NuttX I2C Driver might work: [cxd56_i2c.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/cxd56xx/cxd56_i2c.c)

- ["Power Up the I2C Controller for Star64 JH7110"](https://github.com/lupyuen/nuttx-star64#power-up-the-i2c-controller-for-star64-jh7110)

- ["Explore the I2C Controller for Star64 JH7110"](https://github.com/lupyuen/nuttx-star64#explore-the-i2c-controller-for-star64-jh7110)

- [Search for "DesignWare DW_apb_i2c Databook"](https://www.google.com/search?q=%22DesignWare+DW_apb_i2c+Databook%22)

__RTC, SPI, UART, DMA, I2S, PWM:__

- [RTC Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_RTC/)

- [SPI Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_SPI/)

- [UART Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_UART/)

- [DMA Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_DMA/)

- [SDK for I2S](http://doc-en.rvspace.org/VisionFive2/DG_I2S/)

- [PWM Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_PWM/)

__USB, Ethernet:__

- [USB Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_USB/)

- [Ethernet Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/PG_Ethernet/)

__Image Sensor Processor:__

- [ISP Reference](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/isp_rgb.html)

- [ISP Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_ISP/)

__Display:__

- [Display Subsystem](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/display_subsystem.html)

- [SDK for HDMI](http://doc-en.rvspace.org/VisionFive2/DG_HDMI/)

- [Display Controller Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Display/)

- [GPU Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_GPU/)

- [Multimedia Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Multimedia/)

- [MIPI LCD Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_LCD/)

We hope to test NuttX soon on the [__PineTab-V RISC-V Tablet__](https://wiki.pine64.org/wiki/PineTab-V). Stay tuned for updates!

__TODO:__ Fix the System Timer by calling OpenSBI, similar to [__Ox64 BL808__](https://github.com/apache/nuttx/pull/11472)

![Apache NuttX RTOS boots OK on StarFive VisionFive2 SBC](https://lupyuen.github.io/images/release-visionfive.jpg)

# What's Next

Today we finally have NuttX running on a __Single-Board Computer__: Star64 JH7110 SBC! (And StarFive VisionFive2, pic above)

- We talked about __building NuttX__ for Star64

- Booting NuttX Kernel (and Initial RAM Disk) with a __Bootable microSD__

- We stepped through everything that happens during __NuttX Startup__

- Hopefully this article will be helpful if you're adding a __NuttX Arch__ or __NuttX Board__

- Stay tuned for __Upcoming Features__ on Star64 and VisionFive2 

  (Maybe PineTab-V too!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=37032141)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18585)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/release.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/release.md)

# Appendix: Missing Math.h

_Why did the NuttX Build fail with missing `math.h`?_

```text
$ sudo apt install \
  gcc-riscv64-unknown-elf \
  picolibc-riscv64-unknown-elf

$ make
./stdio/lib_dtoa_engine.c:40:10:
  fatal error: math.h: No such file or directory
  #include <math.h>
```

If the NuttX Build fails due to missing __`math.h`__, install the __xPack GNU RISC-V Embedded GCC Toolchain__...

- [__"xPack GNU RISC-V Embedded GCC Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-xpack-gnu-risc-v-embedded-gcc-toolchain-for-64-bit-risc-v)

_Is there another solution?_

Here's a quick hack: Edit the file __`nuttx/.config`__ and add...

```text
NEED_MATH_H=y
CONFIG_LIBM=y
```

This fixes the NuttX Build to use the NuttX Version of  __`math.h`__. (Instead of the System Version)

NuttX Kernel will boot OK if we don't actually use any Math Functions. But NuttX Apps will fail to load if they call Math Functions. (Like __`floor`__)

[(See this)](https://lists.apache.org/thread/1lzjphvlhr0b6b4tdq6k1l4rhy900h0z)

[(More about __CONFIG_LIBM__)](https://cwiki.apache.org/confluence/display/NUTTX/Integrating+with+Newlib)

[(Thanks to __Ken Dickey__ for the tip!)](https://github.com/KenDickey)

# Appendix: StarFive VisionFive2 Software Release

The __StarFive VisionFive2 Software Release__ was helpful for creating the Bootable microSD for NuttX.

The Software Release includes an __SD Card Image__ that boots OK on Star64...

- [__VisionFive2 Software Releases__](https://github.com/starfive-tech/VisionFive2/releases)

- [__SD Card Image__](https://github.com/starfive-tech/VisionFive2/releases/download/VF2_v3.1.5/sdcard.img)

  Login with...

  ```text
  buildroot login: root
  Password: starfive
  ```

  [(See the Boot Log for Star64)](https://gist.github.com/lupyuen/030e4feb2fa95319290f3027032c24a8)

(We reused the SD Card Image for NuttX)

Based on the files above, we figured out how to generate the __Flat Image Tree__ for NuttX...

- [__Makefile__](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/Makefile#L279-L283)

- [__visionfive2-fit-image.its__](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/conf/visionfive2-fit-image.its)

Also we see the script that generates the __SD Card Image__: [genimage.sh](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/genimage.sh)

```bash
genimage \
  --rootpath "${ROOTPATH_TMP}"     \
  --tmppath "${GENIMAGE_TMP}"    \
  --inputpath "${INPUT_DIR}"  \
  --outputpath "${OUTPUT_DIR}" \
  --config genimage-vf2.cfg
```

The __SD Card Partitions__ are defined here: [genimage-vf2.cfg](https://github.com/starfive-tech/VisionFive2/blob/JH7110_VisionFive2_devel/conf/genimage-vf2.cfg)

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

(We won't need the __spl__, __uboot__ and __root__ partitions for NuttX)

# Appendix: UART Clock for JH7110

_How did we figure out the UART Clock for JH7110?_

```bash
CONFIG_16550_UART0_CLOCK=23040000
```

[(Source)](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L10-L18)

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

[(Source)](https://github.com/apache/nuttx/blob/52527d9915ea0ba1d7e75bb9f2f81356bb2b8ba9/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L10-L18)

_Shouldn't we get the UART Clock from the SoC Datasheet?_

Yep absolutely! For JH7110 there isn't a complete Datasheet, the docs only point to the Linux Device Tree. That's why we derived the UART Clock ourselves.

Sometimes we work backwards when __porting NuttX to SBCs__...

1.  Assume that the UART Driver is already configured by U-Boot

1.  Get the simple UART Driver working, without configuring the UART

1.  Figure out the right values of DLL and DLM, so that UART Driver will configure the UART correctly

1.  DLL and DLM will be reused by other UARTs: UART 1, 2, 3, ...

__For Ox64 BL808 SBC:__ We skipped the UART Configuration completely. Which is OK because we won't use the other UART Ports anyway...

- [__bl808_uart_configure__ in __bl808_serial.c__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl808/bl808_serial.c#L225-L238)

  [(More about __BL808 UART__)](https://lupyuen.github.io/articles/plic2#appendix-uart-driver-for-ox64)

So if we're building the UART Driver ourselves and it's incomplete, it's OK to upstream it first and __complete it later__. That's how we did it for __PinePhone on Allwinner A64__...

- [__History of a64_serial.c__](https://github.com/apache/nuttx/commits/master/arch/arm64/src/a64/a64_serial.c)
