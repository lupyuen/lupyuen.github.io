# BL602 EFlash Loader: Reverse Engineered with Ghidra

📝 _2 Feb 2022_

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/loader-title.jpg)

[_Pine64 PineDio Stack BL604 RISC-V Board_](https://lupyuen.github.io/articles/pinedio2)

Something special happens when we __flash firmware__ to [__BL602 and BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V boards...

It starts a tiny program __inside the board__ to make flashing possible: The __EFlash Loader__.

Step by step we shall __uncover what's inside__ EFlash Loader, thanks to [__Ghidra__](https://ghidra-sre.org/) the popular tool for Software Reverse Engineering.

_Why are we doing this?_

-   EFlash Loader is a critical part of the __Flashing Process__

    (Good to understand how it works)

-   __No Source Code__ is available for EFlash Loader

    [(According to GitHub Code Search)](https://github.com/search?q=bflb_eflash_loader_cmd_write_flash&type=code)

-   EFlash Loader is __small__ (37 KB) and __self-contained__

    [(32-bit RISC-V, specifically RV32IMACF)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

-   EFlash Loader gets __updated occasionally__, so it's good for us to see what's changed

This is my first time using Ghidra so this might be a fun and educational exercise!

(But please bear with my ignorance 🙏)

![Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

[_Pine64 PineCone BL602 RISC-V Board_](https://lupyuen.github.io/articles/pinecone)

# About EFlash Loader

_How does EFlash Loader flash firmware to BL602?_

Here's what happens when we run a __Firmware Flasher__ on our computer to flash BL602...

![EFlash Loader Flow](https://lupyuen.github.io/images/loader-flow.jpg)

1.  Firmware Flasher __sends the EFlash Loader__ executable to BL602

    (Via USB UART, in 4 KB chunks)

1.  BL602 receives and __starts the EFlash Loader__

    (Assuming BL602 is in Flashing Mode)

1.  Firmware Flasher __sends the Flashing Image__ to EFlash Loader

    (In 8 KB chunks)

1.  EFlash Loader __writes the Flashing Image__ to BL602's Embedded Flash

1.  Firmware Flasher verifies with EFlash Loader that the Flashing Image was __written correctly__

    (With SHA256 hashing)

Flashing firmware to BL602 with [__blflash__](https://github.com/spacemeowx2/blflash) looks like this...

-   [__Watch the demo on YouTube__](https://youtu.be/JtnOyl5cYjo)

    (First 20 seconds)

```text
$ blflash flash nuttx.bin  \
  --port /dev/ttyUSB0

Start connection...
5ms send count 55
handshake sent elapsed 252µs
Connection Succeed

Sending eflash_loader...
Finished 2s 11KiB/s

5ms send count 500
handshake sent elapsed 5ms
Entered eflash_loader

Erase flash addr: 10000 size: 346432
Program flash... 
Program done 4s 82KiB/s
Success
```

[(Source)](https://github.com/lupyuen/nuttx/releases/tag/release-2022-01-25)

We see that blflash sends the __EFlash Loader__ to BL602, followed by the __Flashing Image__.

(Which gets written to BL602's Embedded Flash by EFlash Loader)

We have Source Code for everything __except EFlash Loader__... What's really happening inside EFlash Loader?

> ![ELF Executable for EFlash Loader](https://lupyuen.github.io/images/loader-files.jpg)

> [(Source)](https://github.com/bouffalolab/bl_iot_sdk/tree/master/flash_tool/chips/bl602/eflash_loader)

## Thank You ELF

_Can we uncover the inner workings of EFlash Loader?_

Yes we can!

Bouffalo Lab (creator of BL602) has recently uploaded the [__ELF Executable__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) for EFlash Loader (pic above). Which makes Reverse Engineering much easier.

(Because of the debugging symbols inside)

-   [__EFlash Loader ELF: eflash_loader.elf__](https://github.com/bouffalolab/bl_iot_sdk/blob/master/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

    [(Dated 17 Jan 2022)](https://github.com/bouffalolab/bl_iot_sdk/blob/5fa118c59ef89adb319583ea277ea54e27d60fbb/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

Let's decompile the EFlash Loader ELF with Ghidra!

![EFlash Loader decompiled with Ghidra](https://lupyuen.github.io/images/loader-ghidra.jpg)

[(Source)](https://github.com/bouffalolab/bl_iot_sdk/blob/master/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

# Decompile with Ghidra

This is how we decompile the EFlash Loader ELF [__eflash_loader.elf__](https://github.com/bouffalolab/bl_iot_sdk/blob/master/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf) with [__Ghidra__](https://ghidra-sre.org/)...

-   [__Watch the video on YouTube__](https://youtu.be/3Ikn8Y775Lk)

(Works for any ELF file actually)

1.  Install [__Java Dev Kit (JDK) 11__](https://adoptium.net/releases.html?variant=openjdk11&jvmVariant=hotspot) (64-bit)

1.  Download a [__Ghidra Release File__](https://github.com/NationalSecurityAgency/ghidra/releases).

    Extract the Ghidra Release File.

1.  Launch Ghidra...

    ```bash
    ## For Linux and macOS
    ./ghidraRun
    
    ## For Windows
    ghidraRun.bat
    ```

1.  The __Ghidra Help Window__ appears, with plenty of useful info that's not available elsewhere.

    Minimise the Ghidra Help Window for now.
    
    (But remember to browse it when we have the time!)

1.  In the __Ghidra Main Window__, click __File__ → __New Project__

    For __Project Type__: Select __Non-Shared Project__

    For __Project Name__: Enter __"My Project"__

1.  Click __File__ → __Import File__

    Select our ELF File: [__eflash_loader.elf__](https://github.com/bouffalolab/bl_iot_sdk/blob/master/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

1.  Ghidra detects that our RISC-V Executable is __RV32GC__.

    Click __OK__ and __OK__ again.

1.  Double-click our ELF File: __eflash_loader.elf__

    The __CodeBrowser Window__ appears.

    (With a dragon-like spectre)

1.  When prompted to analyze, click __Yes__ and __Analyze__.

    Ignore the warnings.

    (We'll browse the decompiled C code shortly)

And we're done with the decompilation! (Screenshot above)

In case of problems, check these docs...

-   [__"Ghidra Installation Guide"__](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html)

-   [__"An Introduction to Ghidra"__](https://git.mst.edu/slbnmc/ici-wiki/-/wikis/Tool-Guides/An-Introduction-to-Ghidra)

-   [__Ghidra Repo__](https://github.com/NationalSecurityAgency/ghidra)

Also check the Ghidra Help Window that we have minimised.

![Export to C](https://lupyuen.github.io/images/loader-export.png)

## Export To C

Ghidra has decompiled our ELF File into C code. To __export the C code__ to a file...

1.  In the __CodeBrowser Window__, click __File__ → __Export Program__

1.  For __Format__: Select __C / C++__

1.  Click __OK__

    (Pic above)

We'll get a C Source File with roughly __10,000 lines of code__...

-   [__eflash_loader.c__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c)

Which is rather cumbersome to navigate, so we'll use the __Ghidra CodeBrowser__ to browse our C code in a while.

## RV32GC vs RV32IMACF

_Ghidra says our executable is RV32GC. Shouldn't it be RV32IMACF?_

BL602 Executables are compiled for the __RV32IMACF__ RISC-V Instruction Set and Extensions...

| Designation | Meaning |
|:---:|:---|
| __`RV32I`__ | 32-bit RISC-V with Base Integer Instructions
| __`M`__ | Integer Multiplication + Division
| __`A`__ | Atomic Instructions
| __`C`__ | Compressed Instructions
| __`F`__ | Single-Precision Floating-Point

[(Source)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

Ghidra thinks our executable is __RV32GC__, which is all of the above plus __Double-Precision Floating-Point__.

That's probably OK for our Reverse Engineering, since our executable won't have any Double-Precision Floating-Point instructions.

(If we import an ESP32-C3 RISC-V ELF, will Ghidra say it's RV32IMC? Lemme know!)

![Ghidra Symbol Tree](https://lupyuen.github.io/images/loader-symboltree.png)

# Decompiled Main Function

Let's locate the __Main Function__ in our decompiled code...

1.  In the __CodeBrowser Window__, look for the __Symbol Tree Pane__ at left centre

    (Pic above)

1.  Expand __"Functions"__

1.  Double-click on __"entry"__

    [__Watch the video on YouTube__](https://youtu.be/3Ikn8Y775Lk?t=61)

__entry__ is located at `0x2201 0000`, the start address of executable code. Thus it's the __first thing that runs__ when EFlash Loader starts.

In the __Decompile Pane__ (pic above, right side), we see the decompiled code for the __entry__ function: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2663-L2672)

```c
//  EFlash Loader starts here
void entry(void) {

  //  Init BL602 hardware
  SystemInit();

  //  Init BL602 memory
  start_load();

  //  Run the EFlash Loader
  main();
```

Aha we found the Main function! Double-click on __"main"__.

The Decompile Pane jumps to the __Main Function__: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2803-L2863)

```c
//  Main Function for EFlash Loader
int main(void) {
  //  Init BL602 Clock
  HBN_Set_ROOT_CLK_Sel(...);
  ...
  //  Init EFlash Loader
  bflb_eflash_loader_interface_init();
  bflb_set_low_speed_flash_clock();
  ...
  //  Init Embedded Flash
  SFlash_Init(...);
  bflb_spi_flash_init(...);
  SFlash_GetJedecId(...);
  SFlash_Qspi_Enable(...);
  ...
  //  Run the EFlash Loader
  bflb_eflash_loader_main();
```

The Decompiled Main Function is surprisingly readable (pic below). Kudos to the Ghidra Team!

This code suggests that all the exciting action happens inside __bflb_eflash_loader_main__. Which we'll examine in a while.

![Main Function](https://lupyuen.github.io/images/loader-code.png)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2803-L2863)

## Call Graph

_All this verbose code hurts my eyes. Can we browse the code graphically?_

Yes we can! Follow these steps to render the __Call Graph__ for our Decompiled Function...

1.  Click __Graph__ → __Calls__

1.  Click the __Arrangement__ drop-down box

    (Second drop-down from the right)

1.  Select __"Compact Radial"__

We'll see the Call Graph below. Which kinda suggests that something exciting happens inside __bflb_eflash_loader_main__.

Let's go there now!

![Call Graph](https://lupyuen.github.io/images/loader-call.png)

# Decompiled Main Loop

Let's continue the trail from the Main Function.

In the __Decompile Pane__ (right pane), double-click on __bflb_eflash_loader_main__.

Inside the decompiled function we see a loop that __receives and executes Flashing Commands__: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L4031-L4108)

```c
//  Main Loop for EFlash Loader
int32_t bflb_eflash_loader_main(void) {    
  //  Do Handshake
  do {
    i = boot_if_handshake_poll(...);
  } while (i == 0xfffe);

  //  If Handshake is OK...
  if (i == 0) {

    //  Init Flashing Commands
    bflb_eflash_loader_cmd_init();

NextCommand:
    do {
      //  Receive Flashing Command over UART
      do {
        boot_if_recv(...);
      } while (...);

      //  Execute Flashing Command
      i = bflb_eflash_loader_cmd_process(...);

      //  Process next command
      goto NextCommand;

    } while (...);
  }
}
```

The code above calls __bflb_eflash_loader_cmd_process__ to execute the Flashing Command received over UART (from the Firmware Flasher).

Let's find out how it executes Flashing Commands.

![Main Loop](https://lupyuen.github.io/images/loader-code2.png)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L4031-L4108)

## Execute Flashing Command

Double-click on __bflb_eflash_loader_cmd_process__. This code appears: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3814-L3844)

```c
//  Execute a Flashing Command with the specified Command ID and parameters
int32_t bflb_eflash_loader_cmd_process(uint8_t cmdid, uint8_t *data, uint16_t len) {
  
  //  Omitted: Lookup the Command ID 
  //  in list of Flashing Commands
  ...

  //  If Flashing Command is enabled...
  if (eflash_loader_cmds[i].enabled == 1 && ...) {
    
    //  Execute the Flashing Command
    ret = (*eflash_loader_cmds[i].cmd_process)();
    return ret;
  }
```

Interesting! We see that EFlash Loader has a list of Flashing Commands: __eflash_loader_cmds__.

The code above looks up __eflash_loader_cmds__ for the Flashing Command (by Command ID).  And executes the command by calling __cmd_process__.

![Execute Flashing Command](https://lupyuen.github.io/images/loader-code3.png)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3814-L3844)

What are the Flashing Commands supported by EFlash Loader? We'll find out next.

![Flashing Commands](https://lupyuen.github.io/images/loader-flow2a.jpg)

# Decipher Flashing Commands

Recall that __eflash_loader_cmds__ defines the list of Flashing Commands supported by EFlash Loader.

In the __Decompile Pane__ (right pane), double-click on __eflash_loader_cmds__.

This appears in the __Listing Pane__ (centre pane)...

![24 Flashing Commands](https://lupyuen.github.io/images/loader-commands2.png)

Hover our mouse over __eflash_loader_cmds__.

Ghidra says that __24 Flashing Commands__ are defined inside the array. Let's decipher them...

![Flashing Commands deciphered by Ghidra](https://lupyuen.github.io/images/loader-commands3.png)

1.  Expand the array __eflash_loader_cmds__ to see all 24 Flashing Commands

    (See pic above)

1.  For each Flashing Command, hover our mouse as shown above

    (Or double-click it)

1.  Ghidra reveals the function that handles the Flashing Command

    (Like __bflb_eflash_loader_cmd_get_bootinfo__)

Now we know all 24 Flashing Commands. Neat!

## List of Flashing Commands

Here are all __24 Flashing Commands__ supported by EFlash Loader, as decoded by Ghidra from __eflash_loader_cmds__...

| ID | ASCII | Flashing Command
| :--: | :--: | --- 
| `10` | `LF` | [*___get_bootinfo__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2867-L2879)
| `21` | `!` | [*___reset__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2939-L2950)
| `30` | `0` | [*___erase_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3133-L3194)
| `31` | `1` | [*___write_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3258-L3300)
| `3F` | `?` | [*___write_flash_with_decompress__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3693-L3798)
| `32` | `2` | [*___read_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3374-L3427)
| `34` | `4` | [*___xip_read_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3434-L3487)
| `3A` | `:` | [*___write_flash_check__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3001-L3008)
| `3B` | `;` | [*___set_flash_para__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3635-L3689)
| `3C` | `<` | [*___flash_chip_erase__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3113-L3129)
| `3D` | `=` | [*___readSha_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3491-L3544)
| `3E` | `>` | [*___xip_readSha_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3548-L3601)
| `40` | `@` | [*___write_efuse__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3065-L3109)
| `41` | `A` | [*___read_efuse__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3014-L3058)
| `42` | `B` | [*___read_mac_addr__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3605-L3629)
| `50` | `P` | [*___write_mem__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2975-L2997)
| `51` | `Q` | [*___read_mem__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3213-L3254)
| `71` | `q` | [*___read_log__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2897-L2909)
| `60` | ` | [*___xip_read_flash_start__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2913-L2922)
| `61` | `a` | [*___xip_read_flash_finish__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2926-L2935)
| `36` | `6` | [*___read_jedec_id__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2883-L2893)
| `37` | `7` | [*___read_status_register__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3339-L3367)
| `38` | `8` | [*___write_status_register__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3306-L3335)
| `33` | `3` | [*___flash_boot__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3198-L3209)

(__`*`__ denotes __bflb_eflash_loader_cmd__)

7 of the above Flashing Commands are documented in the [__BL602 ISP Protocol__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en)...

| ID | Documented Command
| :--: | --- 
| `10` | Get Boot Info
| `3C` | Chip Erase
| `30` | Flash Erase
| `31` | Flash Program
| `3A` | Flash Program Check
| `32` | Flash Read
| `3D` | SHA256 Read

The other 17 Flashing Commands are undocumented.

(Which might be interesting for future exploration!)

![Flashing States](https://lupyuen.github.io/images/loader-flow2b.jpg)

# Flashing States

You can't tell which way the train went by looking at the tracks... So let's switch over to the (already documented) __Firmware Flasher__ and understand how it calls the Flashing Commands.

-   [__bouffalolab/BLOpenFlasher__](https://github.com/bouffalolab/BLOpenFlasher)

The Firmware Flasher works like a __State Machine__. Each __Flashing State__ triggers a Flashing Command...

![Flashing States](https://lupyuen.github.io/images/loader-flasher.png)

[(Source)](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L195-L245)

Below are the __Flashing States__ and Flashing Command IDs derived from [__util_program.go__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go)...

| Flashing State | ID | On Success |
| :--- | :--- | :--- |
| [__ConfigReset__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L118-L133) | | *Reset
| [*__Reset__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L135-L193) | | *ShakeHand
| [*__ShakeHand__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L195-L206) | `55` | *BootInfo
| [*__BootInfo__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L208-L215) | `10` | *BootHeader
| [*__BootHeader__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L217-L230) | `11` | *SegHeader
| [*__SegHeader__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L232-L245) | `17` | *SegData
| [*__SegData__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L247-L264) | `18` | *CheckImage
| [*__CheckImage__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L266-L274) | `19` | *RunImage
| [*__RunImage__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L276-L284) | `1A` | *Reshake
| [*__Reshake__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L286-L300) | `55` | *LoadFile
| [*__LoadFile__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L302-L344) |  | *EraseFlash^
| [*__EraseFlash__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L353-L378) | `30` | *ProgramFlash
| [*__ProgramFlash__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L380-L408) | `31` | *ProgramOK^
| [*__ProgramOK__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L410-L418) | `3A` | *Sha256
| [*__Sha256__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L420-L449) | `3D` | *LoadFile
| [*__ProgramFinish__](https://github.com/bouffalolab/BLOpenFlasher/blob/main/utils/util_program.go#L451-L468) | `55` | *ProgramFinish

__`*`__ denotes __Cmd__ (like __CmdReset__)

__`^`__ denotes multiple states

[(See the complete table)](https://github.com/lupyuen/bl602-eflash-loader#flashing-states)

Now that we have the Flashing States and the Flashing Commands, let's match them.

![Match Flashing States and Commands](https://lupyuen.github.io/images/loader-flow2c.jpg)

# Match Flashing States and Commands

Right now we have two interesting lists...

-   [__Flashing Commands__](https://github.com/lupyuen/bl602-eflash-loader#flashing-commands) supported by the EFlash Loader

    (As uncovered by Ghidra)

-   [__Flashing States__](https://github.com/lupyuen/bl602-eflash-loader#flashing-states) for the Firmware Flasher's State Machine

    (By reading the BLOpenFlasher source code)

Let's match the two lists and find out which Flashing Commands are __actually called during flashing__...

| ID | ASCII | Flashing Command
| :--: | :--: | --- 
| `10` | `LF` | Get Boot Info<br>[*___get_bootinfo__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L2867-L2879)
| `30` | `0` | Flash Erase<br>[*___erase_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3133-L3194)
| `31` | `1` | Flash Program<br>[*___write_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3258-L3300)
| `3A` | `:` | Flash Program Check<br>[*___write_flash_check__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3001-L3008)
| `3D` | `=` | SHA256 Read<br>[*___readSha_flash__](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3491-L3544)

(__`*`__ denotes __bflb_eflash_loader_cmd__)

Out of 24 commands, only __5 Flashing Commands__ are actually called during flashing!

(`3C` Chip Erase and `32` Flash Read aren't used while flashing BL602, according to BLOpenFlasher)

And out of the 5 Flashing Commands, only 1 looks interesting...

-   __Flash Program: bflb_eflash_loader_cmd_write_flash__

Let's study the Decompiled Code and find out how it writes to the Embedded Flash.

![Match Flashing States and Commands](https://lupyuen.github.io/images/loader-match2.jpg)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader)

# Flash Program

In the __Symbol Tree Pane__ (left centre), enter this into the __Filter Box__...

```text
bflb_eflash_loader_cmd_write_flash
```

Double-click on the function __bflb_eflash_loader_cmd_write_flash__.

This is the decompiled Flashing Command that __writes the Flashing Image__ (received via UART) to Embedded Flash: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3258-L3300)

```c
//  Flashing Command that writes Flashing Image to Embedded Flash
int32_t bflb_eflash_loader_cmd_write_flash(uint16_t cmd,uint8_t *data,uint16_t len) {

  //  Write Flashing Image to Embedded Flash
  bflb_spi_flash_program(...);

  //  Return result to Firmware Flasher
  bflb_eflash_loader_cmd_ack(...);
```

The code above calls __bflb_spi_flash_program__ to write the Flashing Image to the Embedded Flash.

Let's look inside the function...

![Flashing Command that writes Flashing Image to Embedded Flash](https://lupyuen.github.io/images/loader-code4.png)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L3258-L3300)

## Write To Flash

In the __Decompile Pane__ (right pane), double-click on __bflb_spi_flash_program__. This appears: [eflash_loader.c](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L4901-L4910)

```c
//  Write Flashing Image to Embedded Flash
int32_t bflb_spi_flash_program(uint32_t addr,uint8_t *data,uint32_t len) {
  
  //  Call BL602 ROM to write to Embedded Flash
  SFlash_Program(...);
```

This function calls __SFlash_Program__ to write to Embedded Flash.

__SFlash_Program__ is defined in the __BL602 ROM__...

-   [__SFlash_Program (BL602 ROM)__](https://github.com/bouffalolab/bl_iot_sdk/blob/master/components/platform/soc/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_romapi.c#L539-L542)

Source Code is available in the __BL602 IoT SDK__...

-   [__SFlash_Program (BL602 IoT SDK)__](https://github.com/bouffalolab/bl_iot_sdk/blob/master/components/platform/soc/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_sflash.c#L581-L662)

We're all done with our Reverse Engineering of BL602 EFlash Loader! 🎉

![Write Flashing Image to Embedded Flash](https://lupyuen.github.io/images/loader-code5.jpg)

[(Source)](https://github.com/lupyuen/bl602-eflash-loader/blob/main/eflash_loader.c#L4901-L4910)

# How The Train Goes

Thanks to Ghidra we now know everything about EFlash Loader...

-   We discovered [__24 Flashing Commands__](https://lupyuen.github.io/articles/loader#decipher-flashing-commands) supported by EFlash Loader

    (17 Flashing Commands are undocumented)

-   [__Firmware Flasher__](https://lupyuen.github.io/articles/loader#flashing-states) runs a State Machine that __sends Flashing Commands__ to EFlash Loader over UART

-   When EFlash Loader receives the [__"Flash Program"__](https://lupyuen.github.io/articles/loader#flash-program) command from Firmware Flasher, it calls [__BL602 ROM__](https://lupyuen.github.io/articles/loader#write-to-flash) to write the received image to Embedded Flash

-   Source Code for [__BL602 ROM__](https://lupyuen.github.io/articles/loader#write-to-flash) is available, so we already understand how it works

Over the past year we speculated on the inner workings of EFlash Loader...

-   [__"Flashing Firmware to BL602"__](https://lupyuen.github.io/articles/flash)

Finally we know what's inside!

_What happens after the Flashing Image has been written to Embedded Flash?_

The Flashing Image is compressed with XZ Compression.

The image is decompressed and mapped to XIP Memory (Executable in Place) by the BL602 Bootloader...

-   [__"BL602 Bootloader"__](https://lupyuen.github.io/articles/boot)

And the new firmware starts running on BL602.

# What's Next

I had fun reverse enginnering the BL602 EFlash Loader... My first time using Ghidra!

And I hope you found this article useful for real-world reverse engineering with Ghidra.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/ReverseEngineering/comments/sht2hj/bl602_eflash_loader_reverse_engineered_with_ghidra/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/loader.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/loader.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1486187004232867842)

1.  Many thanks to [__BraveHeartFLOSSDev__](https://github.com/BraveHeartFLOSSDev) for the inspiration! We previously collaborated on this article...

    [__"Reverse Engineering WiFi on RISC-V BL602"__](https://lupyuen.github.io/articles/wifi)

1.  There are 2 versions of the EFlash Loader ELF File...

    [__eflash_loader.elf__ (17 Jan 2022)](https://github.com/bouffalolab/bl_iot_sdk/blob/5fa118c59ef89adb319583ea277ea54e27d60fbb/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

    [__eflash_loader.elf__ (1 Nov 2021)](https://github.com/bouffalolab/bl_iot_sdk/blob/07ceb89192cd720e1645e6c37081c85960a33580/flash_tool/chips/bl602/eflash_loader/eflash_loader.elf)

    Might be interesting to compare the decompiled code and discover the changes!

    [(Here's why)](https://github.com/spacemeowx2/blflash/issues/9#issuecomment-1026808893)

1.  Does Firmware Flasher send the EFlash Loader ELF to BL602?

    Nope it sends the stripped binary for the EFlash Loader, which is easier to load and run on BL602: [eflash_loader_40m.bin](https://github.com/bouffalolab/bl_iot_sdk/blob/master/flash_tool/chips/bl602/eflash_loader/eflash_loader_40m.bin)

    Bouffalo Lab used to provide only the stripped binary for EFlash Loader, not the ELF...

    [bl_iot_sdk/flash_tool/chips/ bl602/eflash_loader](https://github.com/bouffalolab/bl_iot_sdk/tree/master/flash_tool/chips/bl602/eflash_loader)

    But since Nov 2021 they started uploading the ELF. Which is how we did the reverse engineering with Ghidra. Lucky us ;-)
