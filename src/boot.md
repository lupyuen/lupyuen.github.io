# BL602 Bootloader

📝 _10 Jun 2021_

_How is our firmware loaded into BL602's flash memory?_

_How does BL602 prevent tampering of firmware?_

All this and much, much more shall be explained as we learn about the __BL602 Boot2 Bootloader__.

# BL602 Boot2 Bootloader

Let's ponder what happens when we flash to BL602 the firmware that we have built...

(We'll call it the __Application Firmware__)

_Sounds easy! We transfer the Application Firmware from our computer to BL602 (over USB)..._

_Then BL602 writes the Application Firmware to flash memory. Right?_

Not quite. We talked about flashing Application Firmware in the article...

-   [__"Flashing Firmware to PineCone BL602"__](https://lupyuen.github.io/articles/flash)

During flashing, we transfer a __Flashing Image__ from our computer to BL602 over USB.

The Flashing Image contains...

1.  __Boot2 Bootloader `blsp_boot2.bin`__

    (Written to the Flashing Image as `boot2image.bin`)

1.  __Application Firmware `bl602.bin`__

    (Written to the Flashing Image as `fwimage.bin`)

1.  __Partition Table `partition.bin`__ and __Device Tree `ro_params.dtb`__

Here's how the Flashing Image is constructed...

![Flashing BL602 firmware](https://lupyuen.github.io/images/boot-title.jpg)

_Why is the Boot2 Bootloader transferred to BL602 during flashing?_

During flashing, our Application Firmware isn't written directly to BL602's __XIP Flash Memory__.

Instead, __BL602 runs the Boot2 Bootloader__ which...

1.  __Extracts our Application Firmware__ from the transferred Flashing Image

1.  __Writes our Application Firmware__ to XIP Flash Memory

1.  __Starts our Application Firmware__ from XIP Flash Memory

XIP means [__Execute In Place__](https://en.wikipedia.org/wiki/Execute_in_place).

It refers to the __External Flash Memory (SPI Flash)__ that will store our executable firmware code.

_Isn't External Flash Memory too slow for running firmware code?_

XIP uses __Cache Memory__ (RAM) to speed up access to External Flash Memory.

This Cache Memory makes it possible to run firmware code stored in Flash Memory.

_Where is the Boot2 Bootloader located?_

BL602 runs the Boot2 Bootloader from XIP Flash Memory at address __`0x2300 0000`__.

Yep it's the __same address as our Application Firmware__!

_So the Bootloader overwrites itself by our Application Firmware?_

Not quite. We'll learn later how the __Boot2 Bootloader remaps the XIP Flash Memory__ to start the Application Firmware.

_Is Boot2 really a Bootloader?_

On other microcontrollers, the Bootloader is the first thing that runs when powered on. (Before jumping to the Application Firmware)

On BL602, the Boot2 Bootloader also __installs new Application Firmware__ into XIP Flash Memory.

[(Somewhat similar to the MCUBoot Bootloader for PineTime Smart Watch)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot)

_Why so complicated?_

BL602's Boot2 Bootloader allows Application Firmware to be __flashed securely__ to XIP Flash Memory...

1.  Boot2 Bootloader supports __flashing of AES-Encrypted Application Firmware__

    (So it's possible to push encrypted firmware updates over-the-air)

1.  Boot2 Bootloader can use __Digital Signatures__ to verify that the Application Firmware is authentic

    (Prevents tampering of firmware updates)

We'll learn more about BL602 firmware security in a while.

![BL602 Boot2 Bootloader runs at address `0x2300 0000`](https://lupyuen.github.io/images/boot-loader.png)

_BL602 Boot2 Bootloader runs at address `0x2300 0000`_

# Inside the Bootloader

To understand the BL602 Bootloader, let's look at the code inside...

![Bootloader Main Function](https://lupyuen.github.io/images/boot-main.png)

From [`bl602_boot2/blsp_boot2.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L389-L571)

1.  The Bootloader starts by fetching the __Clock Configuration and SPI Flash Configuration__ from the Flashing Image [(See this)](https://lupyuen.github.io/articles/flash#appendix-bl602-efuse-configuration)

    ```c
    //  SPI Flash Configuration
    SPI_Flash_Cfg_Type flashCfg;

    //  EFuse Hardware Configuration
    Boot_Efuse_HW_Config efuseCfg;

    int main(void) {
        ...
      //  It's better not enable interrupt
      //  BLSP_Boot2_Init_Timer();

      //  Set RAM Max size
      BLSP_Boot2_Disable_Other_Cache();

      //  Flush cache to get parameter
      BLSP_Boot2_Flush_XIP_Cache();

      Boot_Clk_Config clkCfg;  //  Clock Configuration
      ret = BLSP_Boot2_Get_Clk_Cfg(&clkCfg);

      ret |= SF_Cfg_Get_Flash_Cfg_Need_Lock(0, &flashCfg);
      BLSP_Boot2_Flush_XIP_Cache();
    ```

1.  Next the Bootloader __initialises the Hardware Platform__...

    ```c
      bflb_platform_print_set(BLSP_Boot2_Get_Log_Disable_Flag());

      bflb_platform_init(BLSP_Boot2_Get_Baudrate());

      bflb_platform_deinit_time();
    ```

1.  We fetch the __EFuse Configuration__ (for decrypting the Application Firmware and for verifying the firmware signature)

    ```c
      MSG_DBG("Get efuse config\r\n");
      BLSP_Boot2_Get_Efuse_Cfg(&efuseCfg);
    ```

1.  We __reset the Security Engine__ (for AES Encryption operations)

    ```c
      //  Reset Sec_Eng for using
      BLSP_Boot2_Reset_Sec_Eng();
    ```

1.  The Bootloader supports __multicore CPUs__.  (Each core will start the Application Firmware with different parameters)

    BL602 is a single-core CPU, so the __CPU Count__ will be set to 1...

    ```c
      if (BLSP_Boot2_Get_Feature_Flag() != BLSP_BOOT2_SP_FLAG) {
        //  Get CPU count info
        cpuCount = BLSP_Boot2_Get_CPU_Count();
      } else {
        cpuCount = 1;
      }
    ```

1.  We __fetch the Application Firmware Name__ from the Flashing Image.

    Our Application Firmware is always named __"`FW`"__ [(See this)](https://lupyuen.github.io/articles/flash#appendix-bl602-partition-table)

    ```c
      //  Get power save mode
      psMode = BLSP_Read_Power_Save_Mode();

      //  Get User specified firmware
      uint8_t userFwName[9] = {0};  //  Firmware Name
      ARCH_MemCpy_Fast(
        userFwName,
        BLSP_Get_User_Specified_Fw(),
        4);
    ```

1.  We register the functions that will be called to __Erase, Write and Read the Partition Table__...

    ```c
      if (BLSP_Boot2_8M_Support_Flag()) {
        //  Set flash operation function, read via sbus
        PtTable_Set_Flash_Operation(PtTable_Flash_Erase,
          PtTable_Flash_Write, PtTable_Flash_Read);
      } else {
        //  Set flash operation function, read via xip
        PtTable_Set_Flash_Operation(PtTable_Flash_Erase,
          PtTable_Flash_Write, PtTable_Flash_Read);
      }
    ```

    (Yes the parameters for both calls of `PtTable_Set_Flash_Operation` are identical)

1.  The Bootloader enters two loops...

    -   __Outer Loop "`while`"__: Loops until the writing (or rollback) of Application Firmware is complete

    -   __Inner Loop "`do`"__: Loops through the Partition Table Entries until the writing of Application Firmware to XIP Flash Memory is complete 

    ```c
      while (1) {
        tempMode = 0;
        do {
    ```

    Let's probe the inner loop...

1.  We fetch the next __Partition Table Entry__ from the Flashing Image...

    ```c
          activeID = PtTable_Get_Active_Partition_Need_Lock(ptTableStuff);
          if (PT_TABLE_ID_INVALID==activeID){ BLSP_Boot2_On_Error("No valid PT\r\n"); }

          BLSP_Boot2_Get_MFG_StartReq(
            activeID,
            &ptTableStuff[activeID], 
            &ptEntry[0],
            userFwName);
    ```

1.  We skip these two conditions because our Application Firmware is named "`FW`" and we're running on a single-core CPU...

    ```c
          //  Get entry and boot
          if (userFwName[0] == '0') {
            //  Skip this code because our Firmware Name is "FW"
            ...
          } else if (userFwName[0] == '1' && cpuCount > 1) {
            //  Skip this code because our CPU Count is 1 (single core)
            ...
          } 
    ```

1.  Now comes the fun part!

    The Bootloader __extracts the Application Firmware__ (from the Flashing Image) and __writes it to XIP Flash Memory__...

    ```c
          else {
            ptParsed = BLSP_Boot2_Deal_One_FW(
              activeID,
              &ptTableStuff[activeID],
              &ptEntry[0],
              NULL,
              PT_ENTRY_FW_CPU0);

            if (ptParsed == 0) { continue; }
            if (cpuCount > 1) {
              //  Skip this code because our CPU Count is 1 (single core)
              ...
            }
          }
    ```

    We'll study __`BLSP_Boot2_Deal_One_FW`__ in the next chapter.

1.  The Inner Loop repeats until it has located and processed the Application Firmware...

    ```c
          ptParsed = 1;
        } while (ptParsed == 0);
    ```

1.  Now that the Application Firmware has been written to XIP Flash Memory, let's get ready to start the Application Firmware!    

    We stage the __Partition Table Entry__ that will be passed to the firmware...

    ```c
        //  Pass data to App
        BLSP_Boot2_Pass_Parameter(NULL, 0);

        //  Pass active partition table ID
        BLSP_Boot2_Pass_Parameter(&activeID, 4);

        //  Pass active partition table content: table header + entries + crc32
        BLSP_Boot2_Pass_Parameter(
          &ptTableStuff[activeID],
          sizeof(PtTable_Config) + 4
            + ptTableStuff[activeID].ptTable.entryCnt
              * sizeof(PtTable_Entry_Config));
    ```

1.  We pass the __Flash Configuration__ too...

    ```c
        //  Pass flash config
        if (ptEntry[0].Address[ptEntry[0].activeIndex] != 0) {
          XIP_SFlash_Read_Via_Cache_Need_Lock(
            BLSP_BOOT2_XIP_BASE 
              + ptEntry[0].Address[ptEntry[0].activeIndex] 
              + 8,
            flashCfgBuf,
            sizeof(flashCfgBuf));

          //  Include magic and CRC32
          BLSP_Boot2_Pass_Parameter(
            flashCfgBuf,
            sizeof(flashCfgBuf));
        }
    ```

1.  We initialise the __Boot Header__ for each core (in a multicore CPU)

    ```c
        MSG_DBG("Boot start\r\n");
        for (i = 0; i < cpuCount; i++) {
          bootHeaderAddr[i] = ptEntry[i].Address[ptEntry[i].activeIndex];
        }
    ```

1.  Finally we __jump to the Application Firmware__ that has been written to XIP Flash Memory...

    ```c
    #ifdef BLSP_BOOT2_ROLLBACK  //  This is true
        //  Test mode is not need roll back
        if (rollBacked == 0 && tempMode == 0) {
          ret = BLSP_MediaBoot_Main(bootHeaderAddr, bootRollback, 1);
        } else {
          ret = BLSP_MediaBoot_Main(bootHeaderAddr, bootRollback, 0);
        }
    #else  //  This is false
        ...
    #endif
        //  Fail in temp mode, continue to boot normal image
        if (tempMode == 1) { continue; }
    ```

    (__`BLSP_BOOT2_ROLLBACK`__ is defined because the Bootloader supports firmware rollback)

    We'll cover __`BLSP_MediaBoot_Main`__ in a while.

1.  What happens if the Bootloader fails to update or start the new Application Firmware?

    The Bootloader will __rollback the Application Firmware__ and restore the previous version into XIP Flash Memory...

    ```c
    #ifdef BLSP_BOOT2_ROLLBACK  //  This is true
        //  If rollback is done, we still fail, break
        if (rollBacked) { break; }
        for (i = 0; i < cpuCount; i++) {
          if (bootRollback[i] != 0) {
            if (BFLB_BOOT2_SUCCESS == BLSP_Boot2_Rollback_PtEntry(
              activeID, &ptTableStuff[activeID], &ptEntry[i])) {
              rollBacked = 1;
            }
          }
        }
        //  If need no rollback, boot fail due to other reseaon instead of imgae issue, break
        if (rollBacked == 0) { break; }
    #else  //  This is false
        ...
    #endif
      }
    ```

    (The Outer Loop ends here)

1.  The Main Function of the Bootloader will never return, because the Bootloader __always jumps to the Application Firmware__...

    ```c
      //  We should never get here unless boot fail
      MSG_ERR("Media boot return %d\r\n",ret);
      while (1) {
        MSG_ERR("BLSP boot2 fail\r\n");
        ARCH_Delay_MS(500);
      }
    }
    ```

That's how the Bootloader installs our Application Firmware and starts the firmware!

![Bootloader Main Function](https://lupyuen.github.io/images/boot-main2.png)

# Install Application Firmware

As we've seen, the Bootloader calls __`BLSP_Boot2_Deal_One_FW`__ to...

1.  __Extract the Application Firmware__ from the Flashing Image

1.  __Write the Application Firmware__ to XIP Flash Memory

Here's how it works: [`blsp_boot2.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L271-L313)

```c
//  Boot2 deal with one firmware.
//  Return 0 for partition table changed, need re-parse.
//  Return 1 for partition table or entry parsed successfully.
static int BLSP_Boot2_Deal_One_FW(
  PtTable_ID_Type activeID,       //  Active partition table ID
  PtTable_Stuff_Config *ptStuff,  //  Pointer of partition table stuff
  PtTable_Entry_Config *ptEntry,  //  Pointer of active entry
  uint8_t *fwName,                //  Firmware name pointer
  PtTable_Entry_Type type) {      //  Firmware name ID
  uint32_t ret;

  if (fwName != NULL) {
    MSG_DBG("Get FW:%s\r\n", fwName);
    ret = PtTable_Get_Active_Entries_By_Name(ptStuff, fwName, ptEntry);
  } else {
    MSG_DBG("Get FW ID:%d\r\n", type);
    ret = PtTable_Get_Active_Entries_By_ID(ptStuff, type, ptEntry);
  }
```

__`BLSP_Boot2_Deal_One_FW`__ starts by fetching the __Partition Table Entry__ for our Application Firmware named "`FW`".

Then it __extracts the Application Firmware__ from the Flashing Image...

```c
  if (PT_ERROR_SUCCESS != ret) {
    MSG_ERR("Entry not found\r\n");
  } else {
    BLSP_Dump_PtEntry(ptEntry);
    MSG_DBG("Check Img\r\n");
    if (BLSP_Boot2_Check_XZ_FW(activeID, ptStuff, ptEntry) == 1) {
      return 0;
    }
```

[__`BLSP_Boot2_Check_XZ_FW`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L190-L224) extracts and decompresses the Application Firmware. [(XZ Compression)](https://en.wikipedia.org/wiki/XZ_Utils)

Now that we have the decompressed Application Firmware, we __write the firmware to XIP Flash Memory__...

```c
    //  Check if this partition need copy
    if (ptEntry->activeIndex >= 2) {
      if (BFLB_BOOT2_SUCCESS == BLSP_Boot2_Do_FW_Copy(
        activeID, 
        ptStuff, 
        ptEntry)) {
        return 0;
      }
    }
  }
  return 1;
}
```

In the next chapter we study __`BLSP_Boot2_Do_FW_Copy`__.

![Bootloader installing Application Firmware](https://lupyuen.github.io/images/boot-install.png)

# Write Firmware to XIP Flash

Previously on "Days Of Our Lives"... The Bootloader decompresses the Application Firmware and calls __`BLSP_Boot2_Do_FW_Copy`__ to write the firmware to XIP Flash Memory.

Watch what happens next: [`blsp_boot2.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L226-L269)

```c
//  Buffer for writing to XIP Flash Memory
#define BFLB_BOOT2_READBUF_SIZE  4 * 1024
uint8_t boot2ReadBuf[BFLB_BOOT2_READBUF_SIZE] __attribute__((section(".system_ram")));

//  Boot2 copy firmware from OTA region to normal region
static int BLSP_Boot2_Do_FW_Copy(
  PtTable_ID_Type activeID,         //  Active partition table ID
  PtTable_Stuff_Config *ptStuff,    //  Pointer of partition table stuff
  PtTable_Entry_Config *ptEntry) {  //  Pointer of active entry

  uint8_t activeIndex = ptEntry->activeIndex;
  uint32_t srcAddress = ptEntry->Address[activeIndex&0x01];
  uint32_t destAddress = ptEntry->Address[!(activeIndex&0x01)];
  uint32_t destMaxSize = ptEntry->maxLen[!(activeIndex&0x01)];
  uint32_t totalLen = ptEntry->len;
  uint32_t dealLen = 0;
  uint32_t curLen = 0;
```

__`BLSP_Boot2_Do_FW_Copy`__ starts by fetching the __Partition Table Entry__ for the Application Firmware, containing __Source Address, Destination Address and Firmware Length__.

(More about the Partition Table in the next chapter)

Then it __erases the XIP Flash Memory__ at the Destination Address...

```c
  if (SUCCESS != XIP_SFlash_Erase_Need_Lock(
    &flashCfg,
    destAddress,
    destAddress+destMaxSize - 1)) {
    MSG_ERR("Erase flash fail");
    return BFLB_BOOT2_FLASH_ERASE_ERROR;
  }
```

Next we handle the decompressed Application Firmware, chunk by chunk (4 KB)

```c
  while (dealLen < totalLen) {
    curLen = totalLen - dealLen;
    if (curLen > sizeof(boot2ReadBuf)) {
      curLen = sizeof(boot2ReadBuf);
    }
```

We __read the decompressed Application Firmware__ (in 4 KB chunks)

```c
    if (BFLB_BOOT2_SUCCESS != BLSP_MediaBoot_Read(
      srcAddress,
      boot2ReadBuf,
      curLen)) {
      MSG_ERR("Read FW fail when copy\r\n");
      return BFLB_BOOT2_FLASH_READ_ERROR;
    }
```

We __write the firmware to XIP Flash Memory__ (in 4 KB chunks)

```c
    if (SUCCESS != XIP_SFlash_Write_Need_Lock(
      &flashCfg,
      destAddress,
      boot2ReadBuf,
      curLen)) {
      MSG_ERR("Write flash fail");
      return BFLB_BOOT2_FLASH_WRITE_ERROR;
    }
```

Finally we repeat the steps with the __next 4 KB chunk__, until the entire decompressed Application Firmware is written to XIP Flash Memory...

```c
    srcAddress += curLen;
    destAddress += curLen;
    dealLen += curLen;
  }
  return BFLB_BOOT2_SUCCESS;
}
```

![Bootloader writing firmware to XIP flash](https://lupyuen.github.io/images/boot-write.png)

# BL602 Partition Table

_The Bootloader appears to be driven by the Partition Table (from the Flashing Image). What's inside the Partition Table?_

Each entry of the __Partition Table__ describes a __section of the Flashing Image__.

Here's the __Partition Table Entry__ that describes our __Application Firmware__...

```text
[[pt_entry]]
type     = 0
name     = "FW"
device   = 0
address0 = 0x10000
size0    = 0xC8000
address1 = 0xD8000
size1    = 0x88000
len      = 0
```

[(From this BL602 Partition Table)](https://lupyuen.github.io/articles/flash#appendix-bl602-partition-table)

This Partition Table Entry says that our Application Firmware (compressed) is located in the Flash Image at __offset `0x10000` with size `0xC8000`__ (compressed).

(But why are there two firmware sections `0x10000` and `0xD8000`?)

With this information, our Bootloader will be able to decompress the Application Firmware and write to XIP Flash Memory... 

```c
static int BLSP_Boot2_Do_FW_Copy( ... ) {
  //  Fetch the Partition Table Entry for the Application Firmware
  uint8_t activeIndex = ptEntry->activeIndex;
  uint32_t srcAddress = ptEntry->Address[activeIndex&0x01];
  uint32_t destAddress = ptEntry->Address[!(activeIndex&0x01)];
  uint32_t destMaxSize = ptEntry->maxLen[!(activeIndex&0x01)];
  uint32_t totalLen = ptEntry->len;
```

[(We've seen this earlier in `blsp_boot2.c`)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L226-L269)

__Exercise for the Reader:__ Please take these two things...

1.  __`pt_entry`__ Partition Table Entry above

1.  __`BLSP_Boot2_Do_FW_Copy`__ code above

Match them and verify that the code makes sense!

(Maybe we'll figure out why there are two firmware sections `0x10000` and `0xD8000`)

[More about BL602 Partition Table](https://lupyuen.github.io/articles/flash#partition-table)

![Matching the BL602 Partition Table](https://lupyuen.github.io/images/boot-partition.png)

# BL602 ROM Driver API

Earlier we've seen these functions called by the Bootloader to __access XIP Flash Memory__...

-   __XIP_SFlash_Erase_Need_Lock__: Erase XIP Flash Memory

-   __XIP_SFlash_Read_Via_Cache_Need_Lock__: Read XIP Flash Memory

-   __XIP_SFlash_Write_Need_Lock__: Write XIP Flash Memory

_These XIP Flash Memory Functions are defined in the Bootloader right?_

Not quite... The XIP Flash Memory Functions are located in the __BL602 Boot ROM__!

_Shiver me timbers and call me Shirley! What's the BL602 Boot ROM?_

__BL602 Boot ROM__ is the region of __Read-Only Memory at `0x2100 0000`__ that contains...

1.  __Boot Code__ that's run whenever we power on (or reset) BL602

    (The Boot Code runs just before the Bootloader)

1.  __ROM Driver API__ called by the Bootloader

    (Like the XIP Flash Memory Functions above)

_Why put the ROM Driver API in the Boot ROM?_

-   We __reduce the Bootloader size__ by placing the low-level functions in Boot ROM

-   Some ROM Driver Functions need to run in a __secure, tamper-proof ROM environment__

    (Like the functions for decrypting and verifying Application Firmware)

_Wait this sounds familiar...?_

Our computers have a similar Boot ROM... It's called the [__Unified Extensible Firmware Interface (UEFI)__](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)

It contains secure boot code that's run whenever we power on our computer.

In the next chapter we shall explore the __Table of ROM Driver API Functions__ located in ROM API at __`0x2101 0800`__

From [`bl602_romdriver.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_romdriver.h) ...

![ROM Driver API in Boot ROM](https://lupyuen.github.io/images/boot-driver5.png)

# Locating the ROM Driver API

_How did we find out that the ROM Driver API is located in Boot ROM?_

Let's look at the __RISC-V Disassembly for the Bootloader__: [`bl602_boot2.S`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v8.0.2/bl602_boot2.S)

```c
__ALWAYS_INLINE BL_Err_Type ATTR_TCM_SECTION 
XIP_SFlash_Read_Via_Cache_Need_Lock(
  uint32_t addr,
  uint8_t *data, 
  uint32_t len) {
  return RomDriver_XIP_SFlash_Read_Via_Cache_Need_Lock(
    addr, 
    data, 
    len);
}
```

That's the C definition of the function [__XIP_SFlash_Read_Via_Cache_Need_Lock__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_romapi.c#L833-L836).

(Which is called by the Bootloader to read XIP Flash Memory)

_The function looks kinda empty?_

Yes, because __XIP_SFlash_Read_Via_Cache_Need_Lock__ is a __Stub Function__.

It forwards the Function Call to the __Real Function: RomDriver_XIP_SFlash_Read_Via_Cache _Need_Lock__.

_Where is the Real Function for reading XIP Flash Memory?_

After the code above we see the RISC-V Assembly Code that the GCC Compiler has emitted for our Stub Function...

```text
2201050a <XIP_SFlash_Read_Via_Cache_Need_Lock>:
2201050a:	210117b7          	lui	a5,0x21011
2201050e:	aa47a303          	lw	t1,-1372(a5) # 21010aa4 <StackSize+0x210106a4>
22010512:	8302                jr	t1
```

_So the Real Function is located at `0x2101 0aa4`?_

Right! __RomDriver_XIP_SFlash_Read_Via_Cache _Need_Lock__ is located in the Boot ROM at `0x2101 0aa4`.

(Remember that the Boot ROM lives at `0x2100 0000` to `0x2101 FFFF`)

Hence when the Bootloader reads XIP Flash Memory...

1.  Bootloader calls the __Stub Function__ at `0x2201 050a`

    (Located in ITCM)

1.  Stub Function calls the __Real Function__ at `0x2101 0aa4`

    (Located in Boot ROM)

_What's ITCM?_

ITCM means __Instruction Tightly Coupled Memory__.

This is __Cache Memory__ (RAM) that has been configured (via the Level 1 Cache Controller) for code execution.

(See "Chapter 7: L1C (Level 1 Cache)" in the BL602 Reference Manual)

_What are the functions in the ROM Driver API?_

The __ROM Driver Functions__ are listed in [`bl602_romdriver.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_romdriver.c#L80-L269) and [`bl602_romdriver.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_romdriver.h)

The functions cover...

-  Power On / Off, Power Management, Reset

-  Memory Access, Flash Memory

-  GPIO, EFuse and Delay

The __Bootloader Linker Map [`bl602_boot2.map`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v8.0.2/bl602_boot2.map)__ reveals the __Table of ROM Driver Stub Functions__ at ITCM address `0x2201 0000`...

![ROM Driver Functions](https://lupyuen.github.io/images/boot-driver.png)

# Start the Firmware

Earlier we've seen the Bootloader calling __`BLSP_MediaBoot_Main`__ to start our Application Firmware.

Let's look inside the function: [`blsp_media_boot.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_media_boot.c#L337-L434)

```c
 //  Media boot main process
int32_t BLSP_MediaBoot_Main(
  uint32_t cpuBootheaderAddr[BFLB_BOOT2_CPU_MAX],  //  CPU bootheader address list
  uint8_t cpuRollBack[BFLB_BOOT2_CPU_MAX],         //  CPU need roll back flag hold list
  uint8_t rollBack) {  //  1 for rollback when imge error occurs, 0 for not rollback when imge error occurs
    
  //  Omitted: Reset some parameters
  ...    
  //  Omitted: Try to boot from flash
  ret = BLSP_MediaBoot_Parse_One_FW(
    &bootImgCfg[i],
    bootHeaderAddr[i],
    bootHeaderAddr[i] + BFLB_FW_IMG_OFFSET_AFTER_HEADER);
  ...
  //  Omitted: Get MSP and PC value
  ...    
  //  Fix invalid PC and MSP
  BLSP_Fix_Invalid_MSP_PC();   
       
  //  Prepare jump to entry
  BLSP_MediaBoot_Pre_Jump();
    
  //  We should never get here unless something is wrong
  return BFLB_BOOT2_FAIL;
}
```

This code calls __`BLSP_MediaBoot_Pre_Jump`__ to start the firmware.

Let's trace it: [`blsp_common.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_common.c#L113-L133)

```c
//  Media boot pre-jump
int32_t BLSP_MediaBoot_Pre_Jump(void) {
  //  Security Engine deinit
  BLSP_Boot2_Reset_Sec_Eng();
    
  //  Platform deinit
  bflb_platform_deinit(); 
    
  //  Jump to entry point
  BLSP_Boot2_Jump_Entry();    
  return BFLB_BOOT2_SUCCESS;
}
```

Here we clean up the Security Engine and the Hardware Platform after use.

Then we call __`BLSP_Boot2_Jump_Entry`__ to jump to the Application Firmware.

Let's probe deeper: [`blsp_common.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_common.c#L165-L257)

```c
//  Boot2 jump to entryPoint
void ATTR_TCM_SECTION BLSP_Boot2_Jump_Entry(void) {
  ...    
  BLSP_Sboot_Finish();    
        
  //  Enable cache with flash offset.
  //  Note: After this, should be no flash direct read,
  //  If need to read, should take flash offset into consideration
  if (0 != efuseCfg.encrypted[0]) {
    //  For encrypted img, use non-continuous read
    ret = BLSP_Boot2_Set_Cache(
      0,
      &flashCfg,
      &bootImgCfg[0]);
  } else {
    //  For unencrypted img, use continuous read
    ret = BLSP_Boot2_Set_Cache(
      1,
      &flashCfg,
      &bootImgCfg[0]);
  }
  //  Omitted: Set decryption before reading MSP and PC
  ...    
  //  Omitted: Handle Other CPU's entry point
  ...    
  //  Handle CPU0's entry point
  if (bootImgCfg[0].imgValid) {
    pentry = (pentry_t) bootImgCfg[0].entryPoint;
    if (bootImgCfg[0].mspVal != 0) {
      __set_MSP(bootImgCfg[0].mspVal);
    }
    ...
    //  Jump to the entry point
    if (pentry != NULL) { pentry(); }
  }   
```

As expected, the function ends by __jumping to the Entry Point__ of our Application Firmware: `pentry`

But before that, it calls __`BLSP_Boot2_Set_Cache`__ to fix up the XIP Flash Memory.

Let's find out why.

# Remap XIP Flash

Remember that the __Bootloader and Application Firmware__ are both programmed to run at the __same XIP Flash Memory address `0x2300 0000`__.

_Does the Bootloader overwrite itself with the Application Firmware?_

Not quite! Here's the answer, many thanks to [__9names on Twitter__](https://twitter.com/__9names/status/1401152245693960193)...

> "It doesn't overwrite itself, that's the trick.
What is at `0x23000000` depends on how the cache is configured, you can change it!"

> "See [`BLSP_Boot2_Jump_Entry` in `blsp_common.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_common.c#L165-L257) for an example. This is what makes it possible to boot multiple applications without patching the firmware"

TODO

__`BLSP_Boot2_Set_Cache`__

From [`blsp_port.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_port.c#L423-L485)

```c
/****************************************************************************//**
 * @brief  Media boot set cache according to image config
 *
 * @param  None
 *
 * @return BL_Err_Type
 *
*******************************************************************************/
int32_t ATTR_TCM_SECTION BLSP_Boot2_Set_Cache(uint8_t contRead,SPI_Flash_Cfg_Type *flashCfg,Boot_Image_Config *bootImgCfg)
{
  ...
  if (bootImgCfg[0].cacheEnable) {
    if ((bootImgCfg[0].entryPoint & 0xFF000000) == BLSP_BOOT2_XIP_BASE) {
      SF_Ctrl_Set_Flash_Image_Offset(
        bootImgCfg[0].imgStart.flashOffset
      );
      SFlash_Cache_Read_Enable(
        flashCfg,
        SF_CTRL_QIO_MODE,
        contRead,
        bootImgCfg[0].
        cacheWayDisable
      );
```

Match with [this Flashing Image Configuration](https://lupyuen.github.io/articles/flash#appendix-bl602-efuse-configuration)

-   `cacheEnable` is true

-   `entryPoint` is `BLSP_BOOT2_XIP_BASE` (`0x2300 0000`)

-   `imgStart` is `0x2000`

# EFuse Security

TODO

![](https://lupyuen.github.io/images/boot-efuse.png)

TODO

# BL602 Firmware Boot Code

TODO

![](https://lupyuen.github.io/images/boot-code.png)

TODO

# Other Bootloaders

TODO

1.  ESP32 Secure Boot

    https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html

1.  RP2040

    XIP Flash Memory, Second Stage Bootloader (boot_stage2), Hardware Flash API (hardware_flash)

    [RP2040 Doc](https://datasheets.raspberrypi.org/pico/raspberry-pi-pico-c-sdk.pdf)

    [More about RP2040 XIP Flash](https://kevinboone.me/picoflash.html?i=2)

1.  PineTime Bootloader

    -   [__"MCUBoot Bootloader for PineTime Smart Watch"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot)

    Check out this interview that explains the design rationale for the PineTime Bootloader...

    -   [__"Interview with Lup, creator of PineTime's bootloader"__](https://www.ncartron.org/interview-with-lup-creator-of-pinetimes-bootloader.html)

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/boot.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/boot.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1398855867030593538)

1.  Checking the bootloader

    TODO

    ![](https://lupyuen.github.io/images/boot-compare.png)

    TODO

![](https://lupyuen.github.io/images/boot-driver2.png)

TODO

![](https://lupyuen.github.io/images/boot-driver3.png)

TODO

![](https://lupyuen.github.io/images/boot-driver4.png)

TODO

![](https://lupyuen.github.io/images/boot-rust.png)

TODO

`BLSP_Boot2_Deal_One_FW`

`BLSP_Boot2_Check_XZ_FW`

`BLSP_Boot2_Do_FW_Copy`

`BLSP_MediaBoot_Read`

`BLSP_MediaBoot_Main`
