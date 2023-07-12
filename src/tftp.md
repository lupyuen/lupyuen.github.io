# Star64 JH7110 RISC-V SBC: Boot from Network with U-Boot and TFTP

📝 _19 Jul 2023_

![Pine64 Star64 JH7110 64-bit RISC-V SBC](https://lupyuen.github.io/images/tftp-title.jpg)

Testing a new Operating System like [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) (or Linux) can get _painfully tedious_ on a Single-Board Computer...

Swapping, reflashing and rebooting a MicroSD Card, again and again and again!

[(Like how we tested __NuttX on PinePhone__)](https://github.com/lupyuen/pinephone-nuttx)

Thankfully there's a better way: Booting NuttX (or Linux) over the __Local Network__, with __U-Boot Bootloader__ and __TFTP__!

Today we'll configure TFTP Network Boot on [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64), the new 64-bit RISC-V Single-Board Computer (SBC).

(Powered by [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

![Boot from Network with U-Boot and TFTP](https://lupyuen.github.io/images/tftp-flow.jpg)

# Boot From Network

The pic above shows our grand plan for today...

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

_Do we need to install anything on our SBC?_

TODO

# Setup TFTP Server

_What's this TFTP Server?_

TODO

First we set up a TFTP Server with [`tftpd`](https://crates.io/crates/tftpd)...

```bash
cargo install tftpd
mkdir $HOME/tftproot
sudo tftpd -i 0.0.0.0 -p 69 -d "$HOME/tftproot"
## `sudo` because port 69 is a privileged low port
```

([`tftp_server`](https://crates.io/crates/tftp_server) won't work, it only supports localhost)

We should see...

```text
Running TFTP Server on 0.0.0.0:69 in $HOME/tftproot
Sending a.txt to 127.0.0.1:57125
Sent a.txt to 127.0.0.1:57125
Sending a.txt to 192.168.x.x:33499
Sent a.txt to 192.168.x.x:33499
```

Let's test the TFTP Server...

```bash
echo Test123 >$HOME/tftproot/a.txt
curl -v tftp://127.0.0.1/a.txt
curl -v tftp://192.168.x.x/a.txt
```

(`localhost` won't work because of IPv6, I think)

We should see...

```text
$ curl -v tftp://192.168.x.x/a.txt
*   Trying 192.168.x.x:69...
* getpeername() failed with errno 107: Transport endpoint is not connected
* Connected to 192.168.x.x () port 69 (#0)
* getpeername() failed with errno 107: Transport endpoint is not connected
* set timeouts for state 0; Total  300000, retry 6 maxtry 50
* got option=(tsize) value=(8)
* tsize parsed from OACK (8)
* got option=(blksize) value=(512)
* blksize parsed from OACK (512) requested (512)
* got option=(timeout) value=(6)
* Connected for receive
* set timeouts for state 1; Total  0, retry 72 maxtry 50
Test123
* Closing connection 0
```

If it fails...

```text
$ curl -v tftp://192.168.x.x/a.txt
*   Trying 192.168.x.x:69...
* getpeername() failed with errno 107: Transport endpoint is not connected
* Connected to 192.168.x.x () port 69 (#0)
* getpeername() failed with errno 107: Transport endpoint is not connected
* set timeouts for state 0; Total  300000, retry 6 maxtry 50
```

In the olden days we would actually do this...

```text
$ tftp 127.0.0.1
tftp> get a.txt
Received 8 bytes in 0.0 seconds
tftp> quit
```

Just like FTP!

# Copy NuttX Image to TFTP Server

TODO

Next we copy the NuttX Image and Device Tree to the TFTP Folder...

```bash
## Copy the Device Tree from Armbian microSD
cp \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-visionfive-v2.dtb \
  jh7110-star64-pine64.dtb

## Copy NuttX Binary Image and Device Tree to TFTP Folder
## `nuttx.bin` comes from here:
## https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64-0.0.1
cp nuttx.bin $HOME/tftproot/Image
cp jh7110-star64-pine64.dtb $HOME/tftproot

## Test NuttX Binary Image and Device Tree over FTP
curl -v tftp://192.168.x.x/Image
curl -v tftp://192.168.x.x/jh7110-star64-pine64.dtb

## Show see
## Warning: Binary output can mess up your terminal. Use "--output -" to tell 
## Warning: curl to output it to your terminal anyway, or consider "--output 
## Warning: <FILE>" to save to a file.
```

# Test U-Boot with TFTP

TODO

Now we boot Star64 JH7110 SBC and test the TFTP Commands.

Connect Star64 SBC to the Ethernet wired network and power up.

Star64 fails to boot over the network (because we don't have a [BOOTP Server](https://en.wikipedia.org/wiki/Bootstrap_Protocol) or DHCP+TFTP Combo Server), but that's OK...

```text
ethernet@16030000 Waiting for PHY auto negotiation to complete....... done
BOOTP broadcast 1
*** Unhandled DHCP Option in OFFER/ACK: 43
*** Unhandled DHCP Option in OFFER/ACK: 43
DHCP client bound to address 192.168.x.x (351 ms)
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'boot.scr.uimg'.
Load address: 0x43900000
Loading: *
TFTP server died; starting again
BOOTP broadcast 1
*** Unhandled DHCP Option in OFFER/ACK: 43
*** Unhandled DHCP Option in OFFER/ACK: 43
DHCP client bound to address 192.168.x.x (576 ms)
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'boot.scr.uimg'.
Load address: 0x40200000
Loading: *
TFTP server died; starting again
StarFive #
```

[(Source)](https://github.com/lupyuen/nuttx-star64#u-boot-bootloader-log-for-tftp)

Run these commands...

```bash
## Set the TFTP Server IP
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

[(Inspired by this article)](https://community.arm.com/oss-platforms/w/docs/495/tftp-remote-network-kernel-using-u-boot)

We should see...

```text
StarFive # setenv tftp_server 192.168.x.x

StarFive # tftpboot ${kernel_addr_r} ${tftp_server}:Image
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'Image'.
Load address: 0x40200000
Loading: #############################################################T ####
#################################################################
#############
221.7 KiB/s
done
Bytes transferred = 2097832 (2002a8 hex)

StarFive # tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb
Using ethernet@16030000 device
TFTP from server 192.168.x.x; our IP address is 192.168.x.x
Filename 'jh7110-star64-pine64.dtb'.
Load address: 0x46000000
Loading: ####
374 KiB/s
done
Bytes transferred = 50235 (c43b hex)

StarFive # fdt addr ${fdt_addr_r}

StarFive # booti ${kernel_addr_r} - ${fdt_addr_r}
## Flattened Device Tree blob at 46000000
   Booting using the fdt blob at 0x46000000
   Using Device Tree in place at 0000000046000000, end 000000004600f43a

Starting kernel ...

clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFAGHBC
```

[(Source)](https://github.com/lupyuen/nuttx-star64#u-boot-bootloader-log-for-tftp)

# Configure U-Boot for TFTP

TODO

Let's configure U-Boot so that it will boot from TFTP every time we power up!

```bash
## Remember the TFTP Server IP
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

## Test the Boot Command for TFTP
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

`bootcmd_tftp` expands to...

```bash
## Load the NuttX Image from TFTP Server
## kernel_addr_r=0x40200000
## tftp_server=192.168.x.x
if tftpboot ${kernel_addr_r} ${tftp_server}:Image ;
then

  ## Load the Device Tree from TFTP Server
  ## fdt_addr_r=0x46000000
  if tftpboot ${fdt_addr_r} ${tftp_server}:jh7110-star64-pine64.dtb ;
  then

    ## Set the RAM Address of Device Tree
    ## fdt_addr_r=0x46000000
    if fdt addr ${fdt_addr_r} ;
    then

      ## Boot the NuttX Image with the Device Tree
      ## kernel_addr_r=0x40200000
      ## fdt_addr_r=0x46000000
      booti ${kernel_addr_r} - ${fdt_addr_r} ;
    fi ;
  fi ;
fi
```

[(From here)](https://community.arm.com/oss-platforms/w/docs/495/tftp-remote-network-kernel-using-u-boot) This is a persistent change, i.e. the device will boot via TFTP on every power up. To revert back to the default boot behaviour:

```bash
## Restore the Boot Targets
setenv boot_targets "$orig_boot_targets"
## Should show `mmc0 dhcp`
printenv boot_targets
## Save it for future reboots
saveenv
```

# U-Boot Commands for Network Boot

TODO

_How does it work?_

`bootcmd` is now...

```text
bootcmd=run load_vf2_env;run importbootenv;run load_distro_uenv;run boot2;run distro_bootcmd

load_vf2_env=fatload mmc ${bootpart} ${loadaddr} ${testenv}

importbootenv=echo Importing environment from mmc${devnum} ...; env import -t ${loadaddr} ${filesize}

load_distro_uenv=fatload mmc ${fatbootpart} ${distroloadaddr} ${bootdir}/${bootenv}; env import ${distroloadaddr} 17c; 

boot2 not defined, comes from `boot/vf2_uEnv.txt`
```

`bootcmd` calls `distro_bootcmd`, which runs `bootcmd_mmc0` and `bootcmd_dhcp`...

```text
distro_bootcmd=for target in ${boot_targets}; do run bootcmd_${target}; done

boot_targets=mmc0 dhcp 

bootcmd_mmc0=devnum=0; run mmc_boot

bootcmd_distro=run fdt_loaddtb; run fdt_sizecheck; run set_fdt_distro; sysboot mmc ${fatbootpart} fat c0000000 ${bootdir}/${boot_syslinux_conf}; 
```

`bootcmd_dhcp` is...

```text
bootcmd_dhcp=devtype=dhcp; if dhcp ${scriptaddr} ${boot_script_dhcp}; then source ${scriptaddr}; fi;setenv efi_fdtfile ${fdtfile}; setenv efi_old_vci ${bootp_vci};setenv efi_old_arch ${bootp_arch};setenv bootp_vci PXEClient:Arch:00027:UNDI:003000;setenv bootp_arch 0x1b;if dhcp ${kernel_addr_r}; then tftpboot ${fdt_addr_r} dtb/${efi_fdtfile};if fdt addr ${fdt_addr_r}; then bootefi ${kernel_addr_r} ${fdt_addr_r}; else bootefi ${kernel_addr_r} ${fdtcontroladdr};fi;fi;setenv bootp_vci ${efi_old_vci};setenv bootp_arch ${efi_old_arch};setenv efi_fdtfile;setenv efi_old_arch;setenv efi_old_vci;
```

Which expands to...

```bash
devtype=dhcp

## Load the Boot Script from DHCP+TFTP Server
## scriptaddr=0x43900000
## boot_script_dhcp=boot.scr.uimg
if dhcp ${scriptaddr} ${boot_script_dhcp}
then
  source ${scriptaddr}
fi

## Set the EFI Variables
## fdtfile=starfive/starfive_visionfive2.dtb
setenv efi_fdtfile ${fdtfile}
setenv efi_old_vci ${bootp_vci}
setenv efi_old_arch ${bootp_arch}
setenv bootp_vci PXEClient:Arch:00027:UNDI:003000
setenv bootp_arch 0x1b

## Load the Kernel Image from DHCP+TFTP Server...
## kernel_addr_r=0x40200000
if dhcp ${kernel_addr_r}
then

  ## Load the Device Tree from the DHCP+TFTP Server
  ## fdt_addr_r=0x46000000
  ## efi_fdtfile=starfive/starfive_visionfive2.dtb
  tftpboot ${fdt_addr_r} dtb/${efi_fdtfile}

  ## Set the RAM Address of Device Tree
  ## fdt_addr_r=0x46000000
  if fdt addr ${fdt_addr_r}
  then

    ## Boot the EFI Kernel Image
    ## fdt_addr_r=0x46000000
    bootefi ${kernel_addr_r} ${fdt_addr_r}
  else

    ## Boot the EFI Kernel Image
    ## fdtcontroladdr=fffc6aa0
    bootefi ${kernel_addr_r} ${fdtcontroladdr}
  fi
fi

## Unset the EFI Variables
setenv bootp_vci ${efi_old_vci}
setenv bootp_arch ${efi_old_arch}
setenv efi_fdtfile
setenv efi_old_arch
setenv efi_old_vci
```

`dhcp` command is...

```text
dhcp - boot image via network using DHCP/TFTP protocol

Usage:
dhcp [loadAddress] [[hostIPaddr:]bootfilename]
```

(Assume [DHCP/TFTP](https://www.emcraft.com/som/using-dhcp) is not used)

`tftpboot` command is...

```text
tftpboot - boot image via network using TFTP protocol

Usage:
tftpboot [loadAddress] [[hostIPaddr:]bootfilename]
```

`fdt` command is...

```text
fdt - flattened device tree utility commands

Usage:
fdt addr [-c]  <addr> [<length>]   - Set the [control] fdt location to <addr>
fdt apply <addr>                    - Apply overlay to the DT
fdt move   <fdt> <newaddr> <length> - Copy the fdt to <addr> and make it active
fdt resize [<extrasize>]            - Resize fdt to size + padding to 4k addr + some optional <extrasize> if needed
fdt print  <path> [<prop>]          - Recursive print starting at <path>
fdt list   <path> [<prop>]          - Print one level starting at <path>
fdt get value <var> <path> <prop>   - Get <property> and store in <var>
fdt get name <var> <path> <index>   - Get name of node <index> and store in <var>
fdt get addr <var> <path> <prop>    - Get start address of <property> and store in <var>
fdt get size <var> <path> [<prop>]  - Get size of [<property>] or num nodes and store in <var>
fdt set    <path> <prop> [<val>]    - Set <property> [to <val>]
fdt mknode <path> <node>            - Create a new node after <path>
fdt rm     <path> [<prop>]          - Delete the node or <property>
fdt header [get <var> <member>]     - Display header info
                                      get - get header member <member> and store it in <var>
fdt bootcpu <id>                    - Set boot cpuid
fdt memory <addr> <size>            - Add/Update memory node
fdt rsvmem print                    - Show current mem reserves
fdt rsvmem add <addr> <size>        - Add a mem reserve
fdt rsvmem delete <index>           - Delete a mem reserves
fdt chosen [<start> <end>]          - Add/update the /chosen branch in the tree
                                        <start>/<end> - initrd start/end addr
NOTE: Dereference aliases by omitting the leading '/', e.g. fdt print ethernet0.
```

`booti` command is...

```text
booti - boot Linux kernel 'Image' format from memory

Usage:
booti [addr [initrd[:size]] [fdt]]
    - boot Linux flat or compressed 'Image' stored at 'addr'
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
```

`bootefi` command is...

```text
bootefi - Boots an EFI payload from memory

Usage:
bootefi <image address> [fdt address]
  - boot EFI payload stored at address <image address>.
    If specified, the device tree located at <fdt address> gets
    exposed as EFI configuration table.
bootefi bootmgr [fdt address]
  - load and boot EFI payload based on BootOrder/BootXXXX variables.

    If specified, the device tree located at <fdt address> gets
    exposed as EFI configuration table.
```

Doesn't work for NuttX...

```text
StarFive # bootefi ${kernel_addr_r} ${fdt_addr_r}
Card did not respond to voltage select! : -110
Card did not respond to voltage select! : -110
No EFI system partition
No UEFI binary known at 0x40200000
```

[`autoload`](https://u-boot.readthedocs.io/en/latest/usage/environment.html) setting is...

```text
autoload:
if set to “no” (any string beginning with ‘n’), “bootp” and “dhcp” will just load perform a lookup of the configuration from the BOOTP server, but not try to load any image.
```

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
