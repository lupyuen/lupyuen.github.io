# Star64 JH7110 RISC-V SBC: Boot from Network with U-Boot and TFTP

📝 _19 Jul 2023_

![Pine64 Star64 JH7110 64-bit RISC-V SBC](https://lupyuen.github.io/images/tftp-title.jpg)

Testing a new Operating System like [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx2) (or Linux) can get _painfully tedious_ on a Single-Board Computer...

Swapping, reflashing and rebooting a MicroSD Card, [__again and again and again__](https://lupyuen.github.io/articles/nuttx2#boot-nuttx-on-star64)!

[(Like how we tested __NuttX on PinePhone__)](https://github.com/lupyuen/pinephone-nuttx)

Thankfully there's a better way: Booting NuttX (or Linux) over the __Local Network__, with __U-Boot Bootloader__ and __TFTP__!

Today we'll configure TFTP Network Boot on [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64), the new 64-bit RISC-V Single-Board Computer (SBC).

(Powered by [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

![Boot from Network with U-Boot and TFTP](https://lupyuen.github.io/images/tftp-flow.jpg)

# Boot From Network

The pic above shows our __Grand Plan__ for today...

0.  We'll install __TFTP Server__ on our Computer

    (Which will provide the Kernel Image and Device Tree for Star64)

0.  Star64 SBC will fetch the __Kernel Image__ from our Computer

    (NuttX or Linux)

0.  Our SBC will load the __Kernel into RAM__

    (At RAM Address `0x4020` `0000`)

0.  Star64 will fetch the __Linux Device Tree__ from our Computer

    (NuttX doesn't need it, but we'll do it anyway)

0.  Our SBC will load the __Device Tree into RAM__

    (At RAM Address `0x4600` `0000`)

0.  Star64 will __boot the Kernel__ and Device Tree from RAM

    (NuttX or Linux)

0.  We'll configure the SBC to do this __every time it powers on__

    (It will try MicroSD first, before the Network Boot)

_Do we install anything on our SBC?_

Everything we need is already in the __Internal Flash Memory__ of our SBC!

Inside our SBC Flash Memory is the [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64). Which normally boots from MicroSD, but can be configured for __Network Boot__.

Let's find out how...

# Setup TFTP Server

_What's this TFTP Server?_

That's a simple program (running on our computer) that handles the [__Trivial File Transfer Protocol (TFTP)__](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol).

It dishes out files over the __Local Network__ (via UDP not TCP), when requested by our SBC.

Follow these steps to install the [__`tftpd` TFTP Server__](https://crates.io/crates/tftpd) on our Linux / macOS / Windows Computer...

```bash
## Install `tftpd` in Rust
cargo install tftpd

## Create a folder for the TFTP Files
mkdir $HOME/tftproot

## Start the TFTP Server. Needs `sudo` because
## Port 69 is a privileged low port.
sudo tftpd -i 0.0.0.0 -p 69 -d "$HOME/tftproot"
```

([__`tftp_server`__](https://crates.io/crates/tftp_server) won't work, it only supports localhost)

We should see...

```text
Running TFTP Server on 0.0.0.0:69 in $HOME/tftproot

## Later we'll see the dishy files...
## Sending a.txt to 127.0.0.1:57125
## Sent a.txt to 127.0.0.1:57125
## Sending a.txt to 192.168.x.x:33499
## Sent a.txt to 192.168.x.x:33499
```

Let's __test the server__...

```bash
## Create a Test File for TFTP
echo Test123 >$HOME/tftproot/a.txt

## Fetch the Test File over TFTP.
## TODO: Change `192.168.x.x` to our Computer's IP Address
curl -v tftp://127.0.0.1/a.txt
curl -v tftp://192.168.x.x/a.txt
```

(__`localhost`__ won't work because of IPv6, I think)

We should see our __Test File__...

```text
* Trying 192.168.x.x:69...
* getpeername() failed with errno 107: Transport endpoint is not connected
* Connected to 192.168.x.x () port 69 (#0)
* getpeername() failed with errno 107: Transport endpoint is not connected
* set timeouts for state 0; Total  300000, retry 6 maxtry 50
...
Test123
```

(Ignore the warnings)

Our TFTP Server is up! In the olden days we would actually do this...

```text
$ tftp 127.0.0.1
tftp> get a.txt
Received 8 bytes in 0.0 seconds
tftp> quit
```

[(Just like __FTP__)](https://en.wikipedia.org/wiki/File_Transfer_Protocol)

But __`curl`__ is so much simpler!

![Armbian MicroSD for Star64](https://lupyuen.github.io/images/star64-armbian.png)

[_Armbian MicroSD for Star64_](https://lupyuen.github.io/articles/linux#boot-armbian-linux-on-star64)

# Copy Kernel to TFTP Server

_How to copy the Kernel to our TFTP Server?_

We build __Apache NuttX RTOS__ with these steps...

- [__"Apache NuttX RTOS for Star64"__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64-0.0.1)

This produces the [__NuttX Kernel Image `nuttx.bin`__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/star64-0.0.1/nuttx.bin) that we'll copy to our TFTP Folder...

```bash
## Copy NuttX Binary Image `nuttx.bin` to TFTP Folder
cp nuttx.bin $HOME/tftproot/Image

## Test NuttX Binary Image over TFTP.
## TODO: Change `192.168.x.x` to our Computer's IP Address
curl -v tftp://192.168.x.x/Image

## We should see:
## `Warning: Binary output can mess up your terminal`
```

__For Linux:__ Copy the Linux Kernel File __`Image`__ to our TFTP Folder.

_What about the Linux Device Tree?_

(We won't need it for NuttX, but let's do it anyway)

__For NuttX:__ Copy the Device Tree from the [__Armbian MicroSD__](https://lupyuen.github.io/articles/linux#boot-armbian-linux-on-star64) to our TFTP Folder...

```bash
## Copy the Device Tree from Armbian microSD
cp \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-visionfive-v2.dtb \
  jh7110-star64-pine64.dtb

## Copy to TFTP Folder
cp jh7110-star64-pine64.dtb $HOME/tftproot

## Test Device Tree over TFTP
## TODO: Change `192.168.x.x` to our Computer's IP Address
curl -v tftp://192.168.x.x/jh7110-star64-pine64.dtb

## We should see:
## `Warning: Binary output can mess up your terminal`
```

__For Linux:__ Just copy the Linux Device Tree __jh7110-star64-pine64.dtb__ to our TFTP Folder.

![Boot from Network with U-Boot and TFTP](https://lupyuen.github.io/images/tftp-flow.jpg)

# Test U-Boot with TFTP

We're ready to test U-Boot Bootloader with TFTP!

Connect Star64 to the __Ethernet Wired Network__ (pic above).

Connect to the [__Serial Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64) and power up without a MicroSD Card.

Star64 __fails to boot__ over the network, but that's OK...

```text
BOOTP broadcast 1
*** Unhandled DHCP Option in OFFER/ACK: 43
DHCP client bound to address 192.168.x.x (351 ms)

TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'boot.scr.uimg'.
Load address: 0x43900000
  TFTP server died; starting again

Load address: 0x40200000
  TFTP server died; starting again
StarFive #
```

[(Source)](https://github.com/lupyuen/nuttx-star64#u-boot-bootloader-log-for-tftp)

That's because we don't have a [__BOOTP Server__](https://en.wikipedia.org/wiki/Bootstrap_Protocol) or a __DHCP+TFTP__ Combo Server.

Since we have a Dedicated TFTP Server, we run these __U-Boot Commands__ at the prompt...

```bash
## Set the TFTP Server IP
## TODO: Change `192.168.x.x` to our Computer's IP Address
setenv tftp_server 192.168.x.x

## Load the NuttX Image from TFTP Server
## kernel_addr_r=0x40200000
## tftp_server=192.168.x.x
tftpboot ${kernel_addr_r} ${tftp_server}:Image

## Load the Device Tree from TFTP Server
## fdt_addr_r=0x46000000
## tftp_server=192.168.x.x
tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb

## Set the RAM Address of Device Tree
## fdt_addr_r=0x46000000
fdt addr ${fdt_addr_r}

## Boot the NuttX Image with the Device Tree
## kernel_addr_r=0x40200000
## fdt_addr_r=0x46000000
booti ${kernel_addr_r} - ${fdt_addr_r}
```

TODO: __tftpboot__ explained here

TODO: __fdt__ explained here

TODO: __booti__ explained here

Our Star64 SBC will (pic above)...

1.  __Fetch the Kernel__ over TFTP

1.  __Load the Kernel__ into RAM

1.  __Fetch the Device Tree__ over TFTP

1.  __Load the Device Tree__ into RAM

1.  __Boot the Kernel__

Like so...

```text
StarFive # setenv tftp_server 192.168.x.x

StarFive # tftpboot ${kernel_addr_r} ${tftp_server}:Image
Filename 'Image'.
Load address: 0x40200000
Loading: 221.7 KiB/s done
Bytes transferred = 2097832 (2002a8 hex)

StarFive # tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb
Filename 'jh7110-star64-pine64.dtb'.
Load address: 0x46000000
Loading: 374 KiB/s done
Bytes transferred = 50235 (c43b hex)

StarFive # fdt addr ${fdt_addr_r}

StarFive # booti ${kernel_addr_r} - ${fdt_addr_r}
Flattened Device Tree blob at 46000000
Booting using the fdt blob at 0x46000000
Using Device Tree in place at 0000000046000000, end 000000004600f43a
```

And NuttX (or Linux) boots magically over the Network, no more MicroSD yay!

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFAGHBC
```

[(Source)](https://github.com/lupyuen/nuttx-star64#u-boot-bootloader-log-for-tftp)

TODO: RAM Disk

[(Inspired by this article)](https://community.arm.com/oss-platforms/w/docs/495/tftp-remote-network-kernel-using-u-boot)

# Configure U-Boot for TFTP

_But can we Auto-Boot from Network, every time we power on?_

Sure can! The trick is to use the __saveenv__ command, which will save the U-Boot Settings into the Internal Flash Memory...

```bash
## Remember the TFTP Server IP.
## TODO: Change `192.168.x.x` to our Computer's IP Address
setenv tftp_server 192.168.x.x
## Check that it's correct
printenv tftp_server
## Save it for future reboots
saveenv

## Add the Boot Command for TFTP
setenv bootcmd_tftp 'if tftpboot ${kernel_addr_r} ${tftp_server}:Image ; then if tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb ; then if fdt addr ${fdt_addr_r} ; then booti ${kernel_addr_r} - ${fdt_addr_r} ; fi ; fi ; fi'
## Check that it's correct
printenv bootcmd_tftp
## Save it for future reboots
saveenv

## Test the Boot Command for TFTP, then reboot
run bootcmd_tftp

## Remember the Original Boot Targets
setenv orig_boot_targets "$boot_targets"
## Should show `mmc0 dhcp`
printenv boot_targets
## Save it for future reboots
saveenv

## Add TFTP to the Boot Targets
setenv boot_targets "$boot_targets tftp"
## Should show `mmc0 dhcp  tftp`
printenv boot_targets
## Save it for future reboots
saveenv
```

Now Star64 will __Auto-Boot from the Network__, every time we power up!

(It will try to boot from MicroSD before Network)

If we change our mind, we can switch back to the __Original Boot Targets__...

```bash
## Restore the Boot Targets
setenv boot_targets "$orig_boot_targets"
## Should show `mmc0 dhcp`
printenv boot_targets
## Save it for future reboots
saveenv
```

_What's boot_targets?_

U-Boot Bootloader defines a list of __Targets for Auto-Booting__...

```text
## On Power Up: Try booting from MicroSD,
## then from DHCP+TFTP Combo Server
boot_targets=mmc0 dhcp 
```

We added __TFTP to the Boot Targets__ (ignore the space)...

```
## We added TFTP to the Boot Targets
boot_targets=mmc0 dhcp  tftp
```

Thus U-Boot will execute the Boot Script __bootcmd_tftp__ at startup.

TODO: As explained here

_What's bootcmd_tftp?_

__bootcmd_tftp__ expands to this U-Boot Script...

```bash
## Load the NuttX Image from TFTP Server
## kernel_addr_r=0x40200000
## tftp_server=192.168.x.x
if tftpboot ${kernel_addr_r} ${tftp_server}:Image;
then

  ## Load the Device Tree from TFTP Server
  ## fdt_addr_r=0x46000000
  if tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb;
  then

    ## Set the RAM Address of Device Tree
    ## fdt_addr_r=0x46000000
    if fdt addr ${fdt_addr_r};
    then

      ## Boot the NuttX Image with the Device Tree
      ## kernel_addr_r=0x40200000
      ## fdt_addr_r=0x46000000
      booti ${kernel_addr_r} - ${fdt_addr_r};
    fi;
  fi;
fi
```

Which does the same thing as the previous section: Boot NuttX (or Linux) over the Network at startup.

[(See the __U-Boot Settings__)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tftp.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tftp.md)

# Appendix: Boot Script for U-Boot Bootloader

_Earlier we saw boot_targets and bootcmd_tftp. How do they work?_

We talked about __boot_targets__ and __bootcmd_tftp__...

- [__"Configure U-Boot for TFTP"__](https://lupyuen.github.io/articles/tftp#configure-u-boot-for-tftp)

Let's figure out how they will __Auto-Boot NuttX__ (or Linux) from the Network...

1.  At startup, U-Boot Bootloader always executes the __Boot Script__ in [__bootcmd__](https://u-boot.readthedocs.io/en/latest/usage/environment.html#list-of-environment-variables).

1.  __bootcmd__ is set to...

    ```bash
    ## Load the VF2 Environment from MMC
    run load_vf2_env;

    ## Import the Environment from MMC
    run importbootenv;

    ## Load the Distro Environment from MMC
    run load_distro_uenv;

    ## Run `boot2` script (missing)
    run boot2;

    ## Run the Boot Command for every Boot Target
    run distro_bootcmd
    ```

    [(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

    Which executes __distro_bootcmd__

1.  __distro_bootcmd__ is set to...

    ```bash
    ## For Every Boot Target...
    for target in ${boot_targets};

      ## Run the Boot Command for the Target
      do run bootcmd_${target};
    done
    ```

    [(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

1.  Previously we changed __boot_targets__ to...

    ```text
    mmc0 dhcp  tftp
    ```

    [(Source)](https://lupyuen.github.io/articles/tftp#configure-u-boot-for-tftp)

    Which means U-Boot will execute this sequence...

    - __bootcmd_mmc0__: Try to boot from MicroSD

    - __bootcmd_dhcp__: Try to boot from DHCP+TFTP Combo Server

    - __bootcmd_tftp__: Try to boot from TFTP

1.  We saw __bootcmd_tftp__ earlier...

    [__"Configure U-Boot for TFTP"__](https://lupyuen.github.io/articles/tftp#configure-u-boot-for-tftp)

    It boots NuttX (or Linux) over the Network via TFTP.

And that's how U-Boot Bootloader boots NuttX (or Linux) over the Network at startup!

## Boot from MMC0

_What's in bootcmd_mmc0?_

__bootcmd_mmc0__ tries to boot from MicroSD...

```bash
## Set Device Number
devnum=0;

## Boot from MMC
run mmc_boot
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

__mmc_boot__ is...

```bash
if mmc dev ${devnum};
then 
  devtype=mmc;
  run scan_dev_for_boot_part;
fi;

mmcbootenv=run scan_mmc_dev;
setenv bootpart ${devnum}:${mmcpart};

if mmc rescan;
then 
  run loadbootenv && run importbootenv;
  run ext4bootenv && run importbootenv;

  if test -n $uenvcmd;
  then
    echo Running uenvcmd ...;
    run uenvcmd;
  fi;
fi
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

## Boot from DHCP

_What about bootcmd_dhcp?_

__bootcmd_dhcp__ tries to boot from DHCP+TFTP Combo Server.

It assumes that the DHCP Server is also a TFTP Server.

__bootcmd_dhcp__ is set to...

```bash
devtype=dhcp;

## Load the Boot Script from DHCP+TFTP Server
## scriptaddr=0x43900000
## boot_script_dhcp=boot.scr.uimg
if dhcp ${scriptaddr} ${boot_script_dhcp};
then
  source ${scriptaddr};
fi;

## Set the EFI Variables
## fdtfile=starfive/starfive_visionfive2.dtb
setenv efi_fdtfile ${fdtfile};
setenv efi_old_vci ${bootp_vci};
setenv efi_old_arch ${bootp_arch};
setenv bootp_vci PXEClient:Arch:00027:UNDI:003000;
setenv bootp_arch 0x1b;

## Load the Kernel Image from DHCP+TFTP Server...
## kernel_addr_r=0x40200000
if dhcp ${kernel_addr_r};
then

  ## Load the Device Tree from the DHCP+TFTP Server
  ## fdt_addr_r=0x46000000
  ## efi_fdtfile=starfive/starfive_visionfive2.dtb
  tftpboot ${fdt_addr_r} dtb/${efi_fdtfile};

  ## Set the RAM Address of Device Tree
  ## fdt_addr_r=0x46000000
  if fdt addr ${fdt_addr_r};
  then

    ## Boot the EFI Kernel Image
    ## fdt_addr_r=0x46000000
    bootefi ${kernel_addr_r} ${fdt_addr_r};
  else

    ## Boot the EFI Kernel Image
    ## fdtcontroladdr=fffc6aa0
    bootefi ${kernel_addr_r} ${fdtcontroladdr};
  fi;
fi;

## Unset the EFI Variables
setenv bootp_vci ${efi_old_vci};
setenv bootp_arch ${efi_old_arch};
setenv efi_fdtfile;
setenv efi_old_arch;
setenv efi_old_vci;
```

[(Source)](https://lupyuen.github.io/articles/linux#u-boot-settings-for-star64)

TODO: __dhcp__ explained here

TODO: __tftpboot__ explained here

TODO: __fdt__ explained here

TODO: __booti__ explained here

# Appendix: Commands for U-Boot Bootloader

Here are the __U-Boot Bootloader Commands__ mentioned in this article...

## dhcp Command

dhcp - boot image via network using DHCP/TFTP protocol

- dhcp [loadAddress] [[hostIPaddr:]bootfilename]

[(Source)](https://github.com/u-boot/u-boot/blob/master/cmd/net.c#L144-L150)

## tftpboot Command

tftpboot - boot image via network using TFTP protocol

- tftpboot [loadAddress] [[hostIPaddr:]bootfilename]

[(Source)](https://github.com/u-boot/u-boot/blob/master/cmd/net.c#L61-L69)

(Same as __dhcp__ Command?)

## booti Command

booti - boot Linux kernel 'Image' format from memory

- booti [addr [initrd[:size]] [fdt]]

  boot Linux flat or compressed 'Image' stored at 'addr'

  The argument 'initrd' is optional and specifies the address
  of an initrd in memory. The optional parameter ':size' allows
  specifying the size of a RAW initrd.

  Currently only booting from gz, bz2, lzma and lz4 compression
  types are supported. In order to boot from any of these compressed
  images, user have to set kernel_comp_addr_r and kernel_comp_size environment
  variables beforehand.

  Since booting a Linux kernel requires a flat device-tree, a
  third argument providing the address of the device-tree blob
  is required. To boot a kernel with a device-tree blob but
  without an initrd image, use a '-' for the initrd argument.

[(Source)](https://github.com/u-boot/u-boot/blob/master/cmd/net.c#L61-L69)

## bootefi Command

bootefi - Boots an EFI payload from memory

- bootefi \<image address> [fdt address]
  
  boot EFI payload stored at address \<image address>.

  If specified, the device tree located at \<fdt address> gets
  exposed as EFI configuration table.

- bootefi bootmgr [fdt address]

  load and boot EFI payload based on BootOrder/BootXXXX variables.

  If specified, the device tree located at \<fdt address> gets
  exposed as EFI configuration table.

TODO: Source

TODO: Doesn't work for NuttX...

```text
StarFive # bootefi ${kernel_addr_r} ${fdt_addr_r}
Card did not respond to voltage select! : -110
Card did not respond to voltage select! : -110
No EFI system partition
No UEFI binary known at 0x40200000
```

TODO: [`autoload`](https://u-boot.readthedocs.io/en/latest/usage/environment.html) setting is...

```text
autoload:
if set to “no” (any string beginning with ‘n’), “bootp” and “dhcp” will just load perform a lookup of the configuration from the BOOTP server, but not try to load any image.
```

## fdt Command 

fdt - flattened device tree utility commands

- fdt addr [-c]  \<addr> [\<length>]   

  Set the [control] fdt location to \<addr>

- fdt apply \<addr>                    

  Apply overlay to the DT

- fdt move   \<fdt> \<newaddr> \<length> 

  Copy the fdt to \<addr> and make it active

- fdt resize [\<extrasize>]            

  Resize fdt to size + padding to 4k addr + some optional \<extrasize> if needed

- fdt print  \<path> [\<prop>]          

  Recursive print starting at \<path>

- fdt list   \<path> [\<prop>]          

  Print one level starting at \<path>

- fdt get value \<var> \<path> \<prop>   

  Get \<property> and store in \<var>

- fdt get name \<var> \<path> \<index>   

  Get name of node \<index> and store in \<var>

- fdt get addr \<var> \<path> \<prop>    

  Get start address of \<property> and store in \<var>

- fdt get size \<var> \<path> [\<prop>]  

  Get size of [\<property>] or num nodes and store in \<var>

- fdt set    \<path> \<prop> [\<val>]    

  Set \<property> [to \<val>]

- fdt mknode \<path> \<node>            

  Create a new node after \<path>

- fdt rm     \<path> [\<prop>]          

  Delete the node or \<property>

- fdt header [get \<var> \<member>]     

  Display header info

  get - get header member \<member> and store it in \<var>

- fdt bootcpu \<id>                    

  Set boot cpuid

- fdt memory \<addr> \<size>            

  Add/Update memory node

- fdt rsvmem print                    

  Show current mem reserves

- fdt rsvmem add \<addr> \<size>        

  Add a mem reserve

- fdt rsvmem delete \<index>           

  Delete a mem reserves

- fdt chosen [\<start> \<end>]          

  Add/update the /chosen branch in the tree

  \<start>/\<end> - initrd start/end addr

NOTE: Dereference aliases by omitting the leading '/', e.g. fdt print ethernet0.

TODO: Source
