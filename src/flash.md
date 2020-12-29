# Flashing Firmware to PineCone BL602

![Flashing Firmware to PineCone BL602](https://lupyuen.github.io/images/pinecone-flash-steps.png)

📝 _29 Dec 2020_

Based on [`github.com/bouffalolab/BLOpenFlasher/flash_tool.go`](https://github.com/bouffalolab/BLOpenFlasher/blob/main/flash_tool.go)

# Generate Partition
        
Partition Table:       
"bl602/partition/partition_cfg_2M.toml",
                
Output:              
"bl602/image/partition.bin",                   

# Boot To Image                                                                     
            
EFuse Configuration:        
"bl602/efuse_bootheader/efuse_bootheader_cfg.conf",
                    
Boot Binary:                 
"bl602/builtin_imgs/blsp_boot2.bin",
                            
Output:                     
"bl602/image/boot2image.bin",
                                    
FWOffset:
0x2000,     

Boot2 Firmware:
https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/bl602_boot2

# Generate Firmware Image                                                                            
            
EFuse Configuration:            
"bl602/efuse_bootheader/efuse_bootheader_cfg.conf",
                    
Firmware Binary:                
"bl602/bl602.bin",
                            
Output:                        
"bl602/image/fwimage.bin",
                                    
FWOffset:
0x1000,                                     

https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/efuse.html

number of eFuses which can store system and user parameters. Each eFuse is a one-bit field which can be programmed to 1 after which it cannot be reverted back to 0. Some of system parameters are using these eFuse bits directly by hardware modules 

# Device Tree to DTB
                                           
Script:
"dts2dtb.py",

Device Tree:
"bl602/device_tree/bl_factory_params_IoTKitA_40M.dts",

Output:
"bl602/image/ro_params.dtb"

# Flash to ROM
    	
utils.StartProgram:
    			                            
"bl602/image/boot2image.bin			                            
0x000000",
    			                                    
"bl602/image/partition.bin 			                                    
0xE000",
    			                                            
"bl602/image/partition.bin                                          
0xF000",
    			                                                    
"bl602/image/fwimage.bin                                                   
0x10000",
    			                                                            
"bl602/image/ro_params.dtb                                                        
0x1F8000",   			                                                                

```    			                                                                    
utils.StartProgram(   			                                                                    
"/dev/ttyUSB0", 
nil, 
512000, 
"bl602/eflash_loader/eflash_loader_40m.bin", 
2000000, 
bins, 
5000
) 			                                                                    
```

https://github.com/bouffalolab/BLOpenFlasher/issues/2

two baudrate setting: 512000 is for downloading eflash_loader.bin, and 2000000 for downloading the generated bins.

# BL602 Partition Table

[`github.com/bouffalolab/BLOpenFlasher/bl602/partition/partition_cfg_2M.toml`](https://github.com/bouffalolab/BLOpenFlasher/blob/main/bl602/partition/partition_cfg_2M.toml)

```text
[pt_table]
#partition table is 4K in size
address0 = 0xE000
address1 = 0xF000

[[pt_entry]]
type = 0
name = "FW"
device = 0
address0 = 0x10000
size0 = 0xC8000
address1 = 0xD8000
size1 = 0x88000
# compressed image must set len,normal image can left it to 0
len = 0

[[pt_entry]]
type = 2
name = "mfg"
device = 0
address0 = 0x160000
size0 = 0x32000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0

[[pt_entry]]
type = 3
name = "media"
device = 0
address0 = 0x192000
size0 = 0x57000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0

[[pt_entry]]
type = 4
name = "PSM"
device = 0
address0 = 0x1E9000
size0 = 0x8000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0

[[pt_entry]]
type = 5
name = "KEY"
device = 0
address0 = 0x1F1000
size0 = 0x2000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0

[[pt_entry]]
type = 6
name = "DATA"
device = 0
address0 = 0x1F3000
size0 = 0x5000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0


[[pt_entry]]
type = 7
name = "factory"
device = 0
address0 = 0x1F8000
size0 = 0x7000
address1 = 0
size1 = 0
# compressed image must set len,normal image can left it to 0
len = 0

#if user want to put RF calibration data on flash, uncomment following pt entry
#[[pt_entry]]
#type = 8
#name = "rf_para"
#device = 0
#address0 = 0x1FF000
#size0 = 0x1000
#address1 = 0
#size1 = 0
## compressed image must set len,normal image can left it to 0
#len = 0
```

# BL602 Device Tree

Note that the WiFi SSID configuration is stored here.

https://github.com/bouffalolab/BLOpenFlasher/blob/main/bl602/device_tree/bl_factory_params_IoTKitA_40M.dts

```text
/dts-v1/;
/include/ "bl602_base.dtsi";
// version: 17
// last_comp_version: 16
// boot_cpuid_phys: 0x0

/ {
    model = "bl bl602 AVB board";
    compatible = "bl,bl602-sample", "bl,bl602-common";
    #address-cells = <0x1>;
    #size-cells = <0x1>;
    gpio {
        #address-cells = <1>;
        #size-cells = <1>;
        max_num = <40>;
        gpio0 {                                  
            status = "okay";                     
            pin  = <5>;                          
            feature = "led";                     
            active = "Hi"; //Hi or Lo
            mode = "blink"; //blink or hearbeat
            time = <100>; //duration for this mode
        };
        gpio1 {                                  
            status = "disable";                     
            pin  = <6>;                          
            feature = "led";                     
            active = "Hi"; //Hi or Lo
            mode = "blink"; //blink or hearbeat
            time = <100>; //duration for this mode
        };
        gpio2 {
            status = "okay";
            pin = <2>;
            feature = "button";
            active = "Hi";
            mode = "multipress";
            button {
                debounce = <10>;
                short_press_ms {
                    start = <100>;
                    end = <3000>;
                    kevent = <2>;
                };
                long_press_ms {
                    start = <6000>;
                    end = <10000>;
                    kevent = <3>;
                };
                longlong_press_ms {
                    start = <15000>;
                    kevent = <4>;
                };
                trig_level = "Hi";
            };
            hbn_use = "disable";
        };
    };
    i2s {
        #address-cells = <1>;
        #size-cells = <1>;
        i2s@40017000 {
            status = "okay";
            compatible = "bl602_i2s";
            reg = <0x40017000 0x100>;
            mclk_only = "okay";
            pin {
                mclk = <11>;
            };
        };
        i2s@40017100 {
            status = "okay";
            compatible = "bl602_i2s";
            reg = <0x40017100 0x100>;
            mclk_only = "disable";
            pin {
                bclk = <12>;
                fs = <29>;
                do = <30>;
                di = <31>;
            };
        };
    };
    i2c {
        #address-cells = <1>;
        #size-cells = <1>;
        i2c@40011000 {
            status = "okay";
            compatible = "bl602_i2c";
            reg = <0x40011000 0x100>;
            pin {
                scl = <32>;
                sda = <13>;
            };
            devices {
                list_addr = <0x18 0x21>;
                list_driver = "i2c_es8311", "i2c_gc0308>";
            };
        };
        i2c@40011100 {
            status = "disable";
            compatible = "bl602_i2c";
            reg = <0x40011100 0x100>;
            pin {
                /*empty here*/
            };
        };
    };
    timer {
        #address-cells = <1>;
        #size-cells = <1>;
        timer@40014000 {
            status = "disable";
            compatible = "bl602_timer";
            reg = <0x40014000 0x100>;
        };
        timer@40014100 {
            status = "disable";
            compatible = "bl602_timer";
            reg = <0x40014100 0x100>;
        };
    };
    pwm {
        #address-cells = <1>;
        #size-cells = <1>;
        pwm@4000A420 {
            status = "okay";
            compatible = "bl602_pwm";
            reg = <0x4000A420 0x20>;
            path = "/dev/pwm0";
            id = <0>;
            pin = <0>;
            freq = <800000>;
            duty = <50>;
        };
        pwm@4000A440 {
            status = "disable";
            reg = <0x4000A440 0x20>;
            path = "/dev/pwm1";
            id = <1>;
            pin = <1>;
            freq = <5000>;
            duty = <50>;
        };
        pwm@4000A460 {
            status = "disable";
            reg = <0x4000A460 0x20>;
            path = "/dev/pwm2";
            id = <2>;
            pin = <2>;
            freq = <5000>;
            duty = <50>;
        };
        pwm@4000A480 {
            status = "disable";
            reg = <0x4000A480 0x20>;
            path = "/dev/pwm3";
            id = <3>;
            pin = <3>;
            freq = <5000>;
            duty = <50>;
        };
        pwm@4000A4A0 {
            status = "disable";
            reg = <0x4000A4A0 0x20>;
            path = "/dev/pwm4";
            id = <4>;
            pin = <4>;
            freq = <5000>;
            duty = <50>;
        };
    };
    ir {
        #address-cells = <1>;
        #size-cells = <1>;
        ctrltype = <0>;
        tx {
            status = "disable";
            pin = <11>;         // only support 11
            mode = "NEC";       // NEC、ExtenedNEC、RC5、SWM
            interval = <100>;   // ms
            active_mode = "Hi"; //Hi、Lo
        };
        rx {
            status = "okay";
            pin = <12>;         // only support 12 13
            mode = "NEC";       // NEC、ExtenedNEC、RC5、SWM
            active_mode = "Hi"; //Hi、Lo
        };
    };
    uart {
        #address-cells = <1>;
        #size-cells = <1>;
        uart@4000A000 {
            status = "okay";
            id = <0>;
            compatible = "bl602_uart";
            path = "/dev/ttyS0";
            baudrate = <2000000>;
            pin {
                rx = <7>;
                tx = <16>;
            };
            buf_size {
                rx_size = <512>;
                tx_size = <512>;
            };
            feature {
                tx = "okay";
                rx = "okay";
                cts = "disable";
                rts = "disable";
            };
        };
        uart@4000A100 {
            status = "okay";
            id = <1>;
            compatible = "bl602_uart";
            path = "/dev/ttyS1";
            baudrate = <115200>;
            pin {
                rx = <3>;
                tx = <4>;
            };
            buf_size {
                rx_size = <512>;
                tx_size = <512>;
            };
            feature {
                tx = "okay";
                rx = "okay";
                cts = "disable";
                rts = "disable";
            };
        };
    };
    spi {
        #address-cells = <1>;
        #size-cells = <1>;
        spi@4000F000 {
            status = "okay";         /* okay disable */
            mode = "master";
            reg = <0x4000F000 0x100>;   /* 4KB */
            path = "/dev/spi0";
            port = <0>;
            polar_phase = <1>;                 /* 0,1,2,3 */
            freq = <6000000>;
            pin {
                clk = <3>;
                cs = <2>;
                mosi = <1>;
                miso = <0>;
            };
            dma_cfg {
                tx_dma_ch = <2>;
                rx_dma_ch = <3>;
            };
        };
    };
    gpip {
        #address-cells = <1>;
        #size-cells = <1>;
        adc_key {
            status = "disable";
            pin = <9>;
            interrupt  = <3>;
            key_vol = <0 100 400 300 500>;
            key_pcb = "SW1", "SW2", "SW3", "SW4","SW5";
            key_event = "Usr1", "Usr2", "Start", "Up", "Down";
            key_raw = <1 2 3 4 5>;
        };
    };
    qspi {
        #address-cells = <1>;
        #size-cells = <1>;
        qspi@4000A000 {
            status = "disable";
            reg = <0x4000A000 0x1000>;/* 4KB */
        };
    };
    wifi {
        #address-cells = <1>;
        #size-cells = <1>;
        region {
            country_code = <86>;
        };
        mac {
            mode = "MBF";
            sta_mac_addr = [C8 43 57 82 73 40];
            ap_mac_addr = [C8 43 57 82 73 02];
        };
        sta {
            ssid = "yourssid";
            pwd = "yourapssword";
            auto_connect_enable = <0>;
        };
        ap {
            ssid = "bl_test_005";
            pwd = "12345678";
            ap_channel = <11>;
            auto_chan_detect = "disable";
        };
        brd_rf {
            xtal_mode = "MF";
            xtal = <36 36 0 60 60>;
            /*
            pwr_table = <   4 3 3 186
                            4 3 4 176
                            4 3 5 167
                            3 3 0 159
                            3 3 1 149
                            3 3 2 140
                            3 3 3 129
                            3 3 4 119
                            3 3 5 110
                            2 3 0 101
                            2 3 1 91
                            2 3 2 82
                            2 3 3 72
                            2 3 4 62
                            2 3 5 52
                            1 3 3 10>;
            */
            pwr_mode = "bf";//B: only use power offset in EFUSE; b: use power offset in EFUSE with incremental mode; F: only use power offset in Flash; f: use power offset in Flash with incremental mode
            pwr_table_11b = <20 20 20 18>;//1Mbps 2Mbps 5.5Mbps 11Mbps
            pwr_table_11g = <18 18 18 18 18 18 14 14>; //6Mbps 9Mbps 12Mbps 18MBps 24Mbps 36Mbps 48Mbps 54Mbps
            pwr_table_11n = <18 18 18 18 18 16 14 14>; //MCS0 MCS1 MCS2 MCS3 MCS4 MCS5 MCS6 MCS7
            pwr_offset = <10 10 10 10 10 10 10 10 10 10 10 10 10 10>;//due to the limit of current DTC, negative value is used. So we work around by adding all the poweroffset with 10. so 8 represents -2; 10 represents 0; 13 represents 3
            channel_div_table = <0x1EEC4EC4 0x1EFCB7CB 0x1F0D20D2 0x1F1D89D8 0x1F2DF2DF 0x1F3E5BE5 0x1F4EC4EC 0x1F5F2DF2 0x1F6F96F9 0x1F800000 0x1F906906 0x1FA0D20D 0x1FB13B13 0x1FD89D89 0x201F81F8>;
            channel_cnt_table = <0xA78A 0xA7E3 0xA83C 0xA895 0xA8ED 0xA946 0xA99F 0xA9F8 0xAA51 0xAAAA 0xAB03 0xAB5C 0xABB5 0xAC8A>;
            lo_fcal_div = <0x56B>;
        };
    };
    bluetooth {
        #address-cells = <1>;
        #size-cells = <1>;
        brd_rf {
            pwr_table_ble = <13>;  //range:-3~15dbm; if set -3, please set 253 here
        };
    };
};
```

# BL602 EFuse Configuration

[`github.com/bouffalolab/BLOpenFlasher/bl602/efuse_bootheader/efuse_bootheader_cfg.conf`](https://github.com/bouffalolab/BLOpenFlasher/blob/main/bl602/efuse_bootheader/efuse_bootheader_cfg.conf)

```text
[EFUSE_CFG]
########################################################################
#2bits
ef_sf_aes_mode = 0
#2bits
ef_sboot_sign_mode = 0
#2bits
ef_sboot_en = 0
#2bits
ef_dbg_jtag_dis = 0
#4bits
ef_dbg_mode = 0
#32bits
ef_dbg_pwd_low = 0
#32bits
ef_dbg_pwd_high = 0
###################################################################
ef_key_slot_2_w0 = 0
ef_key_slot_2_w1 = 0
ef_key_slot_2_w2 = 0
ef_key_slot_2_w3 = 0
ef_key_slot_3_w0 = 0
ef_key_slot_3_w1 = 0
ef_key_slot_3_w2 = 0
ef_key_slot_3_w3 = 0
ef_key_slot_4_w0 = 0
ef_key_slot_4_w1 = 0
ef_key_slot_4_w2 = 0
ef_key_slot_4_w3 = 0

wr_lock_key_slot_4_l = 0
wr_lock_dbg_pwd = 0
wr_lock_key_slot_2 = 0
wr_lock_key_slot_3 = 0
wr_lock_key_slot_4_h = 0
rd_lock_dbg_pwd = 0
rd_lock_key_slot_2 = 0
rd_lock_key_slot_3 = 0
rd_lock_key_slot_4 = 0

[BOOTHEADER_CFG]
magic_code = 0x504e4642
revision = 0x01
#########################flash cfg#############################
flashcfg_magic_code = 0x47464346
#flashcfg_magic_code=0
io_mode = 4
cont_read_support = 1
#0.5T sfctrl_clk_delay=0 sfctrl_clk_invert=3
#1 T sfctrl_clk_delay=1 sfctrl_clk_invert=1
#1.5T sfctrl_clk_delay=1 sfctrl_clk_invert=3
sfctrl_clk_delay = 1
sfctrl_clk_invert = 0x01

reset_en_cmd = 0x66
reset_cmd = 0x99
exit_contread_cmd = 0xff
exit_contread_cmd_size = 3

jedecid_cmd = 0x9f
jedecid_cmd_dmy_clk = 0
qpi_jedecid_cmd = 0x9f
qpi_jedecid_dmy_clk = 0

sector_size = 4
mfg_id = 0xef
page_size = 256

chip_erase_cmd = 0xc7
sector_erase_cmd = 0x20
blk32k_erase_cmd = 0x52
blk64k_erase_cmd = 0xd8

write_enable_cmd = 0x06
page_prog_cmd = 0x02
qpage_prog_cmd = 0x32
qual_page_prog_addr_mode = 0

fast_read_cmd = 0x0b
fast_read_dmy_clk = 1
qpi_fast_read_cmd = 0x0b
qpi_fast_read_dmy_clk = 1

fast_read_do_cmd = 0x3b
fast_read_do_dmy_clk = 1
fast_read_dio_cmd = 0xbb
fast_read_dio_dmy_clk = 0

fast_read_qo_cmd = 0x6b
fast_read_qo_dmy_clk = 1
fast_read_qio_cmd = 0xeb
fast_read_qio_dmy_clk = 2

qpi_fast_read_qio_cmd = 0xeb
qpi_fast_read_qio_dmy_clk = 2
qpi_page_prog_cmd = 0x02
write_vreg_enable_cmd = 0x50

wel_reg_index = 0
qe_reg_index = 1
busy_reg_index = 0
wel_bit_pos = 1

qe_bit_pos = 1
busy_bit_pos = 0
wel_reg_write_len = 2
wel_reg_read_len = 1

qe_reg_write_len = 1
qe_reg_read_len = 1
release_power_down = 0xab
busy_reg_read_len = 1

reg_read_cmd0 = 0x05
reg_read_cmd1 = 0x35

reg_write_cmd0 = 0x01
reg_write_cmd1 = 0x31

enter_qpi_cmd = 0x38
exit_qpi_cmd = 0xff
cont_read_code = 0x20
cont_read_exit_code = 0xff

burst_wrap_cmd = 0x77
burst_wrap_dmy_clk = 0x03
burst_wrap_data_mode = 2
burst_wrap_code = 0x40

de_burst_wrap_cmd = 0x77
de_burst_wrap_cmd_dmy_clk = 0x03
de_burst_wrap_code_mode = 2
de_burst_wrap_code = 0xF0

sector_erase_time = 300
blk32k_erase_time = 1200

blk64k_erase_time = 1200
page_prog_time = 5

chip_erase_time = 200000
power_down_delay = 3
qe_data = 0

flashcfg_crc32 = 0

#########################clk cfg####################################
clkcfg_magic_code = 0x47464350
#clkcfg_magic_code=0

#0:Not use XTAL to set PLL,1:XTAL is 24M ,2:XTAL is 32M ,3:XTAL is 38.4M
#4:XTAL is 40M,5:XTAL is 26M,6:XTAL is RC32M
xtal_type = 4
#0:RC32M,1:XTAL,2:PLL 48M,3:PLL 120M,4:PLL 160M,5:PLL 192M
pll_clk = 4
hclk_div = 0
bclk_div = 1
#0:120M,1:XCLK(RC32M or XTAL),2:48M,3:80M,4:BCLK,5:96M
flash_clk_type = 3
flash_clk_div = 1
clkcfg_crc32 = 0

########################boot cfg####################################
#1:ECC
sign = 0
#1:AES128,2:AES256,3:AES192
encrypt_type = 0
key_sel = 0
no_segment = 1
cache_enable = 1
notload_in_bootrom = 0
aes_region_lock = 0
cache_way_disable = 0x03
crc_ignore = 0
hash_ignore = 0

########################image cfg####################################
#total image len or segment count 
img_len = 0x100
bootentry = 0
#img RAM address or flash offset 
img_start = 0x2000

#img hash
hash_0 = 0xdeadbeef
hash_1 = 0
hash_2 = 0
hash_3 = 0
hash_4 = 0
hash_5 = 0
hash_6 = 0
hash_7 = 0

crc32 = 0xdeadbeef
```
