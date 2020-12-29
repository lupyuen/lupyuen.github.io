# Flashing Firmware to PineCone BL602

![Flashing Firmware to PineCone BL602](https://lupyuen.github.io/images/pinecone-flash-steps.png)

📝 _29 Dec 2020_

Based on [`github.com/bouffalolab/BLOpenFlasher/flash_tool.go`](https://github.com/bouffalolab/BLOpenFlasher/blob/main/flash_tool.go)

# Generate Partition
        
Input:       
"bl602/partition/partition_cfg_2M.toml",
                
Output:              
"bl602/image/partition.bin",                   

# Boot To Image                                                                     
            
Input:        
"bl602/efuse_bootheader/efuse_bootheader_cfg.conf",
                    
Boot Binary:                 
"bl602/builtin_imgs/blsp_boot2.bin",
                            
Output:                     
"bl602/image/boot2image.bin",
                                    
FWOffset:
0x2000,     

# Generate Firmware Image                                                                            
            
Input:            
"bl602/efuse_bootheader/efuse_bootheader_cfg.conf",
                    
Firmware Binary:                
"bl602/bl602.bin",
                            
Output:                        
"bl602/image/fwimage.bin",
                                    
FWOffset:

0x1000,                                     

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

```    			                                                                    utils.StartProgram(   			                                                                    
"/dev/ttyUSB0", 
nil, 
512000, 
"bl602/eflash_loader/eflash_loader_40m.bin", 
2000000, 
bins, 
5000
) 			                                                                    
```
