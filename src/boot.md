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

1.  __Writes our Application Firmware__ to XIP Flash Memory at address __`0x2300 0000`__.

(XIP means "Execute In Place", it refers to the BL602 Flash Memory that will store our executable firmware code)

_Where is the Boot2 Bootloader located?_

BL602 runs the Boot2 Bootloader from XIP Flash Memory at address __`0x2300 0000`__.

Yep it's the __same address as our Application Firmware__!

_So the Bootloader overwrites itself by our Application Firmware?_

Yes indeed. We'll learn later how the __Boot2 Bootloader overwrites itself__ by the Application Firmware.

_Is Boot2 really a Bootloader?_

On other microcontrollers, the Bootloader is the first thing that runs when powered on. (Before jumping to the Application Firmware)

On BL602, the Boot2 Bootloader __runs only when we flash new Application Firmware__. (So that the Application Firmware may be loaded into XIP Flash Memory)

So the Bootloader concept is a little different for BL602... It's more like an __"Application Firmware Loader"__

_Why so complicated?_

BL602's Boot2 Bootloader allows Application Firmware to be __flashed securely__ to XIP Flash Memory...

1.  Boot2 Bootloader supports __flashing of AES-Encrypted Application Firmware__

    (So it's possible to push encrypted firmware updates over-the-air)

1.  Boot2 Bootloader can use __Digital Signatures__ to verify that the Application Firmware is authentic

    (Prevents tampering of firmware updates)

We'll learn more about firmware security.

![BL602 Boot2 Bootloader runs at address `0x2300 0000`](https://lupyuen.github.io/images/boot-loader.png)

_BL602 Boot2 Bootloader runs at address `0x2300 0000`_

# Inside the Bootloader

To understand the BL602 Bootloader, let's look at the code inside...

![Bootloader Main Function](https://lupyuen.github.io/images/boot-main.png)

From [`bl602_boot2/blsp_boot2.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_boot2/bl602_boot2/blsp_boot2.c#L389-L571)

1.  TODO

    ```c
    int main(void) {
        ...
        //  It's better not enable interrupt
        //  BLSP_Boot2_Init_Timer();

        //  Set RAM Max size
        BLSP_Boot2_Disable_Other_Cache();

        //  Flush cache to get parameter
        BLSP_Boot2_Flush_XIP_Cache();
        ret = BLSP_Boot2_Get_Clk_Cfg(&clkCfg);
        ret |= SF_Cfg_Get_Flash_Cfg_Need_Lock(0,&flashCfg);
        BLSP_Boot2_Flush_XIP_Cache();
    ```

1.  TODO

    ```c
        bflb_platform_print_set(BLSP_Boot2_Get_Log_Disable_Flag());
        bflb_platform_init(BLSP_Boot2_Get_Baudrate());
        bflb_platform_deinit_time();
    ```

1.  TODO

    ```c
        MSG_DBG("Get efuse config\r\n");
        BLSP_Boot2_Get_Efuse_Cfg(&efuseCfg);
    ```

1.  TODO

    ```c
        //  Reset Sec_Eng for using
        BLSP_Boot2_Reset_Sec_Eng();
    ```

1.  TODO

    ```c
        if(BLSP_Boot2_Get_Feature_Flag()!=BLSP_BOOT2_SP_FLAG){
            //  Get CPU count info
            cpuCount=BLSP_Boot2_Get_CPU_Count();
        } else {
            cpuCount=1;
        }
    ```

1.  TODO

    ```c
        //  Get power save mode
        psMode=BLSP_Read_Power_Save_Mode();
    ```

1.  TODO

    ```c
        //  Get User specified FW
        ARCH_MemCpy_Fast(userFwName,BLSP_Get_User_Specified_Fw(),4);
    ```

1.  TODO

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

1.  TODO

    ```c
        while(1) {
            tempMode=0;
            do {
                activeID = PtTable_Get_Active_Partition_Need_Lock(ptTableStuff);
                if (PT_TABLE_ID_INVALID==activeID){
                    BLSP_Boot2_On_Error("No valid PT\r\n");
                }

                BLSP_Boot2_Get_MFG_StartReq(
                    activeID,
                    &ptTableStuff[activeID], 
                    &ptEntry[0],
                    userFwName);

                //  Get entry and boot
                if (userFwName[0] == '0') {
                    ptParsed = BLSP_Boot2_Deal_One_FW(
                        activeID,
                        &ptTableStuff[activeID],
                        &ptEntry[0],
                        &userFwName[1],
                        PT_ENTRY_FW_CPU0);
                    if (ptParsed == 0) {
                        continue;
                    } else {
                        BLSP_Clr_User_Specified_Fw();
                    }
                    tempMode = 1;
                    userFwName[0] = 0;
                } else if (userFwName[0] == '1' && cpuCount > 1) {
                    ptParsed = BLSP_Boot2_Deal_One_FW(
                        activeID,
                        &ptTableStuff[activeID],
                        &ptEntry[1],
                        &userFwName[1],
                        PT_ENTRY_FW_CPU1);
                    if (ptParsed == 0) {
                        continue;
                    } else {
                        BLSP_Clr_User_Specified_Fw();
                    }
                    tempMode = 1;
                    userFwName[0] = 0;
                } else {
                    ptParsed = BLSP_Boot2_Deal_One_FW(
                        activeID,
                        &ptTableStuff[activeID],
                        &ptEntry[0],
                        NULL,
                        PT_ENTRY_FW_CPU0);
                    if (ptParsed == 0) {
                        continue;
                    }
                    if (cpuCount > 1) {
                        ptParsed = BLSP_Boot2_Deal_One_FW(
                            activeID,
                            &ptTableStuff[activeID],
                            &ptEntry[1],
                            NULL,
                            PT_ENTRY_FW_CPU1);
                        if (ptParsed == 0) {
                            continue;
                        }
                    }
                }
                ptParsed = 1;
            } while (ptParsed == 0);
    ```

1.  TODO

    ```c
            /* Pass data to App*/
            BLSP_Boot2_Pass_Parameter(NULL,0);
            /* Pass active partition table ID */
            BLSP_Boot2_Pass_Parameter(&activeID,4);
            /* Pass active partition table content: table header+ entries +crc32 */
            BLSP_Boot2_Pass_Parameter(&ptTableStuff[activeID],sizeof(PtTable_Config)+4+
                                        ptTableStuff[activeID].ptTable.entryCnt*sizeof(PtTable_Entry_Config));
    ```

1.  TODO

    ```c
            /* Pass flash config */
            if(ptEntry[0].Address[ptEntry[0].activeIndex]!=0){
                XIP_SFlash_Read_Via_Cache_Need_Lock(BLSP_BOOT2_XIP_BASE+ptEntry[0].Address[ptEntry[0].activeIndex]+8,flashCfgBuf,sizeof(flashCfgBuf));
                /* Include magic and CRC32 */
                BLSP_Boot2_Pass_Parameter(flashCfgBuf,sizeof(flashCfgBuf));
            }
    ```

1.  TODO

    ```c
            MSG_DBG("Boot start\r\n");
            for(i=0;i<cpuCount;i++){
                bootHeaderAddr[i]=ptEntry[i].Address[ptEntry[i].activeIndex];
            }
    ```

1.  TODO

    ```c
    #ifdef BLSP_BOOT2_ROLLBACK
            /* Test mode is not need roll back */
            if(rollBacked==0 && tempMode==0){
                ret=BLSP_MediaBoot_Main(bootHeaderAddr,bootRollback,1);
            }else{
                ret=BLSP_MediaBoot_Main(bootHeaderAddr,bootRollback,0);
            }
    #else
            ret=BLSP_MediaBoot_Main(bootHeaderAddr,bootRollback,0);
    #endif
    ```

1.  TODO

    ```c
            /* Fail in temp mode,continue to boot normal image */
            if(tempMode==1){
                continue;
            }
    ```

1.  TODO

    ```c
    #ifdef BLSP_BOOT2_ROLLBACK
            /* If rollback is done, we still fail, break */
            if(rollBacked){
                break;
            }
            MSG_DBG("Boot return %d\r\n",ret);
            MSG_WAR("Check Rollback\r\n");
            for(i=0;i<cpuCount;i++){
                if(bootRollback[i]!=0){
                    MSG_WAR("Rollback %d\r\n",i);
                    if(BFLB_BOOT2_SUCCESS==BLSP_Boot2_Rollback_PtEntry(activeID,&ptTableStuff[activeID],&ptEntry[i])){
                        rollBacked=1;
                    }
                }
            }
            /* If need no rollback, boot fail due to other reseaon instead of imgae issue,break */
            if(rollBacked==0){
                break;
            }
    #else
            break;
    #endif
        }
    ```

1.  TODO

    ```c
        /* We should never get here unless boot fail */
        MSG_ERR("Media boot return %d\r\n",ret);
        while(1){
            MSG_ERR("BLSP boot2 fail\r\n");
            ARCH_Delay_MS(500);
        }
    }
    ```

TODO

![Bootloader Main Function](https://lupyuen.github.io/images/boot-main2.png)

# Install Application Firmware

TODO

![](https://lupyuen.github.io/images/boot-install.png)

TODO

# Write Firmware to XIP Flash

TODO

![](https://lupyuen.github.io/images/boot-write.png)

TODO

# EFuse Security

TODO

![](https://lupyuen.github.io/images/boot-efuse.png)

TODO

# BL602 ROM Driver API

TODO

![](https://lupyuen.github.io/images/boot-driver.png)

TODO

![](https://lupyuen.github.io/images/boot-driver2.png)

TODO

![](https://lupyuen.github.io/images/boot-driver3.png)

TODO

![](https://lupyuen.github.io/images/boot-driver4.png)

TODO

![](https://lupyuen.github.io/images/boot-driver5.png)

TODO

![](https://lupyuen.github.io/images/boot-rust.png)

TODO

[Unified Extensible Firmware Interface](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)

# BL602 Partition Table

TODO

![](https://lupyuen.github.io/images/boot-partition.png)

TODO

# BL602 Firmware Boot Code

TODO

![](https://lupyuen.github.io/images/boot-code.png)

TODO

# Other Bootloaders

TODO

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
