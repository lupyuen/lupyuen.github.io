# NuttX RTOS for PinePhone: LCD Panel

📝 _2 Jan 2023_

![PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lcd-title.jpg)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and renders a Test Pattern! (Pic above)

-   [__Watch the Demo on YouTube__](https://www.youtube.com/shorts/UzR7xLZCc0c)

Let's find out what's inside our NuttX Kernel Driver for __PinePhone's LCD Panel__...

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Xingbangda XBD599 LCD Panel

The LCD Panel inside PinePhone is [__Xingbangda XBD599__](https://pine64.com/product/pinephone-5-99-lcd-panel-with-touch-screen/) [(兴邦达)](https://web.archive.org/web/20221210083141/http://xingbangda.cn/) with...

-   5.95-inch IPS Display
-   1440 x 720 Resolution
-   16 Million Colors
-   Backlight with Pulse-Width Modulation (PWM)
-   Sitronix ST7703 LCD Controller
    [(ST7703 Datasheet)](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

(Includes a Capacitive Touch Panel, but we'll skip it today)

The Xingbangda XBD599 LCD Panel is connected to PinePhone's Allwinner A64 SoC over a [__MIPI Display Serial Interface (DSI)__](https://lupyuen.github.io/articles/dsi). (Pic above)

_Why is there an ST7703 LCD Controller inside the LCD Panel?_

Talking over MIPI DSI can get complicated... It runs on packets of data with CRCs and Checksums, over parallel wires.

Later we'll see that ST7703 LCD Controller handles...

-   MIPI DSI __Initialisation Commands__

    (At startup)

-   __Rendering of Pixels__ over MIPI DSI

    (After startup)

Let's start with something simpler without ST7703...

-   Turn on the __LCD Panel Backlight__

    (With PIO and PWM)

-   __Reset__ the LCD Panel
  
    (With PIO)

-   __Power on__ the LCD Panel

    (With PMIC)

![Backlight on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-backlight.png)

[_Backlight on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# LCD Panel Backlight

First thing we do when booting PinePhone is to turn on the __LCD Panel Backlight__... Otherwise the LCD Display stays dark!

The [__PinePhone Schematic (Page 11)__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) says that the LCD Panel Backlight is controlled by two pins (pic above)...

-   __PL10__ for Pulse-Width Modulation (PWM)

-   __PH10__ for PIO (Similar to GPIO)

[(__AP3127__ is a PWM Controller)](https://www.diodes.com/assets/Datasheets/products_inactive_data/AP3127_H.pdf)

This is how we __turn on the backlight__ in our NuttX LCD Driver: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L845-L921)

```c
// Turn on the LCD Backlight
int pinephone_lcd_backlight_enable(
  uint32_t percent  // Brightness percentage, typically 90
) {
  // Configure PL10 for PWM
  a64_pio_config(LCD_PWM);  // LCD_PWM is PL10
```

We begin by configuring __PL10 for PWM__.

[(__a64_pio_config__ comes from our NuttX PIO Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L91-L253)

Next we disable PWM through the __R_PWM Port__ on Allwinner A64...

```c
  // R_PWM Control Register (Undocumented)
  // Assume same as PWM Control Register (A64 Page 194)
  // Set SCLK_CH0_GATING (Bit 6) to 0 (Mask)
  modreg32(  // Modify a Register...
    0,                // Set these bits
    SCLK_CH0_GATING,  // Mask these bits
    R_PWM_CTRL_REG    // Register Address
  );
```

The __R_PWM Port__ isn't documented in the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf).

But thanks to [__Reverse-Engineering__](https://lupyuen.github.io/articles/de#appendix-display-backlight), we figured out how it works: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L88-L103)

```c
  // R_PWM Control Register (Undocumented)
  // Assume same as PWM Control Register (A64 Page 194)
  #define R_PWM_CTRL_REG            (A64_RPWM_ADDR + 0)
  #define PWM_CH0_PRESCAL(n)        ((n) << 0)
  #define PWM_CH0_EN                (1 << 4)
  #define SCLK_CH0_GATING           (1 << 6)

  // R_PWM Channel 0 Period Register (Undocumented)
  // Assume same as PWM Channel 0 Period Register (A64 Page 195)
  #define R_PWM_CH0_PERIOD          (A64_RPWM_ADDR + 4)
  #define PWM_CH0_ENTIRE_ACT_CYS(n) ((n) << 0)
  #define PWM_CH0_ENTIRE_CYS(n)     ((n) << 16)
```

Then we set the __PWM Period and Duty Cycle__: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L845-L921)

```c
  // R_PWM Channel 0 Period Register (Undocumented)
  // Assume same as PWM Channel 0 Period Register (A64 Page 195)
  // Set PWM_CH0_ENTIRE_CYS (Bits 16 to 31) to PWM Period
  // Set PWM_CH0_ENTIRE_ACT_CYS (Bits 0 to 15) to PWM Period * Percent / 100
  // `BACKLIGHT_PWM_PERIOD` is 1,199 PWM cycles
  // `percent` (brightness percent) is typically 90
  uint32_t period = 
    PWM_CH0_ENTIRE_CYS(BACKLIGHT_PWM_PERIOD) |
    PWM_CH0_ENTIRE_ACT_CYS(BACKLIGHT_PWM_PERIOD * percent / 100);
  putreg32(           // Write to Register...
    period,           // Register Value
    R_PWM_CH0_PERIOD  // Register Address
  );
```

Finally we __enable PWM__...

```c
  // R_PWM Control Register (Undocumented)
  // Assume same as PWM Control Register (A64 Page 194)
  // Set SCLK_CH0_GATING (Bit 6) to 1 (Pass)
  // Set PWM_CH0_EN (Bit 4) to 1 (Enable)
  // Set PWM_CH0_PRESCAL (Bits 0 to 3) to 0b1111 (Prescaler 1)
  uint32_t ctrl = SCLK_CH0_GATING |
    PWM_CH0_EN |
    PWM_CH0_PRESCAL(0b1111);
  putreg32(         // Write to Register...
    ctrl,           // Register Value
    R_PWM_CTRL_REG  // Register Address
  );
```

One last thing: We configure __PH10 for Output__ and set it to High...

```c
  // Configure PH10 for Output
  a64_pio_config(LCD_BL_EN);  // LCD_BL_EN is PH10

  // Set PH10 to High
  a64_pio_write(LCD_BL_EN, true);
  return OK;
}
```

[(__a64_pio_write__ comes from our NuttX PIO Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L254-L299)

This enables the [__AP3127 PWM Controller__](https://www.diodes.com/assets/Datasheets/products_inactive_data/AP3127_H.pdf). And switches on the LCD Backlight! (Pic above)

Now that the Backlight is on, let's reset the LCD Panel and prepare for action...

![LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/de-reset.jpg)

[_LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Reset LCD Panel

At startup, we need to __toggle the LCD Reset__ from Low to High in this specific sequence...

1.  Reset __LCD Panel__ to __Low__

1.  Power on the LCD Panel's __MIPI Display Serial Interface (DSI)__

    (Via the Power Management Integrated Circuit)

1.  __Wait__ 15 milliseconds

1.  __Enable MIPI DSI__ on Allwinner A64 SoC

1.  __Enable MIPI D-PHY__ on Allwinner A64 SoC

1.  Reset __LCD Panel__ to __High__

Followed by more MIPI DSI and Display Engine operations.

_How will we toggle LCD Reset?_

The [__PinePhone Schematic (Page 11)__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) says that __LCD Reset__ is controlled on __PD23__. (Pic above)

(DLDO2 is powered by the PMIC)

Let's do it: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L922-L958)

```c
// Reset the LCD Panel
int pinephone_lcd_panel_reset(
  bool val  // Set Reset to High or Low
) {
  // Reset LCD Panel at PD23 (Active Low)
  // Configure PD23 for Output
  a64_pio_config(LCD_RESET);  // LCD_RESET is PD23
  
  // Set PD23 to High or Low
  a64_pio_write(LCD_RESET, val);
  return OK;
}
```

The code above configures __PD23 for Output__, and sets PD23 to High or Low.

[(__a64_pio_config__ comes from our NuttX PIO Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L91-L253)

[(__a64_pio_write__ too)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L254-L299)

And that's how we reset the LCD Panel! Now we power on the LCD Panel...

![AXP803 PMIC on PinePhone Schematic (Page 3)](https://lupyuen.github.io/images/de-pmic.png)

[_AXP803 PMIC on PinePhone Schematic (Page 3)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Power On LCD Panel

_How do we power on the LCD Panel?_

The LCD Panel won't respond to our MIPI DSI Commands until __we power it on__.

The [__PinePhone Schematic (Page 3)__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) says that the MIPI DSI Port of the LCD Panel (DLDO2 / VCC-MIPI) is powered by...

-   [__X-Powers AXP803 Power Management Integrated Circuit (PMIC)__](https://files.pine64.org/doc/datasheet/pine64/AXP803_Datasheet_V1.0.pdf)

    (Pics above and below)

This is how we talk to the __AXP803 PMIC__: [pinephone_pmic.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L169-L282)

```c
// Initialise the Power Mgmt IC
int pinephone_pmic_init(void) {
  // Set DLDO1 Voltage to 3.3V.
  // DLDO1 powers the Front Camera / USB HSIC / I2C Sensors.

  // DLDO1 Voltage Control (AXP803 Page 52)
  // Set Voltage (Bits 0 to 4) to 26 (2.6V + 0.7V = 3.3V)
  pmic_write(               // Write to PMIC Register...
    DLDO1_VOLTAGE_CONTROL,  // PMIC Register
    DLDO1_VOLTAGE(26)       // PMIC Value
  );

  // Power on DLDO1:
  // Output Power On-Off Control 2 (AXP803 Page 51)
  // Set DLDO1 On-Off Control (Bit 3) to 1 (Power On)
  pmic_clrsetbits(  // Clear and set bits in PMIC Register...
    OUTPUT_POWER_ON_OFF_CONTROL2,  // Set these bits
    0,                             // Clear these bits
    DLDO1_ON_OFF_CONTROL           // PMIC Register
  );
```

__DLDO1 Power Output__ on the PMIC powers the __Front Camera, USB HSIC and I2C Sensors__ on PinePhone.

In the code above, we set __DLDO1 Voltage to 3.3V__ and power it on.

(We'll talk about __pmic_write__ and __pmic_clrsetbits__ in a while)

Next we set __LDO Voltage to 3.3V__ and power on the __Capacitive Touch Panel__...

```c
  // Set LDO Voltage to 3.3V.
  // GPIO0LDO powers the Capacitive Touch Panel.

  // GPIO0LDO and GPIO0 High Level Voltage Setting (AXP803 Page 77)
  // Set GPIO0LDO and GPIO0 High Level Voltage (Bits 0 to 4) to 26
  // (2.6V + 0.7V = 3.3V)
  pmic_write(  // Write to PMIC Register...
    GPIO0LDO_HIGH_LEVEL_VOLTAGE_SETTING,  // PMIC Register
    GPIO0LDO_HIGH_LEVEL_VOLTAGE(26)       // PMIC Value
  );

  // Enable LDO Mode on GPIO0:
  // GPIO0 (GPADC) Control (AXP803 Page 76)
  // Set GPIO0 Pin Function Control (Bits 0 to 2) to 0b11 (Low Noise LDO on)
  pmic_write(  // Write to PMIC Register...
    GPIO0_CONTROL,            // PMIC Register
    GPIO0_PIN_FUNCTION(0b11)  // PMIC Value
  );
```

Next comes the LCD Panel: We set __DLDO2 Voltage to 1.8V__ and power on the __MIPI DSI Port__ of the LCD Panel...

```c
  // Set DLDO2 Voltage to 1.8V.
  // DLDO2 powers the MIPI DSI Interface of Xingbangda XBD599 LCD Panel.

  // DLDO2 Voltage Control (AXP803 Page 52)
  // Set Voltage (Bits 0 to 4) to 11 (1.1V + 0.7V = 1.8V)
  pmic_write(  // Write to PMIC Register...
    DLDO2_VOLTAGE_CONTROL,  // PMIC Register
    DLDO2_VOLTAGE(11)       // PMIC Value
  );

  // Power on DLDO2:
  // Output Power On-Off Control 2 (AXP803 Page 51)
  // Set DLDO2 On-Off Control (Bit 4) to 1 (Power On)
  pmic_clrsetbits(  // Clear and set bits in PMIC Register...
    OUTPUT_POWER_ON_OFF_CONTROL2,  // Set these bits
    0,                             // Clear these bits
    DLDO2_ON_OFF_CONTROL           // PMIC Register
  );
  return OK;
}
```

Our LCD Panel is powered up and ready to receive MIPI DSI Commands!

(Right after we reset LCD Panel to High)

_What are pmic_write and pmic_clrsetbits?_

The AXP803 PMIC is connected to Allwinner A64 SoC on the __Reduced Serial Bus__. Which is a special bus designed for PMICs.

From [__Allwinner A80 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A80_User_Manual_v1.3.1_20150513.pdf) (Page 918)...

> "The RSB (reduced serial bus) Host Controller is designed to communicate with RSB Device using two push-pull wires."

> "It supports a simplified two wire protocol (RSB) on a push-pull bus. The transfer speed can be up to 20MHz and the performance will be improved much."

(Reduced Serial Bus seems to work like I2C, but specifically for PMICs)

Thus to control AXP803 PMIC, __pmic_write__ will talk to the PMIC over the __Reduced Serial Bus__: [pinephone_pmic.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L88-L119)

```c
// Write a byte to an AXP803 PMIC Register
static int pmic_write(
  uint8_t reg,  // AXP803 Register ID
  uint8_t val   // Byte to be written
) {
  //  Write to AXP803 PMIC on Reduced Serial Bus
  a64_rsb_write(
    AXP803_RT_ADDR,  // RSB Address is 0x2D
    reg,             // AXP803 Register ID
    val              // AXP803 Register Value
  );
  return OK;
}
```

[(__a64_rsb_write__ comes from our NuttX Driver for Reduced Serial Bus)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_rsb.c#L239-L293)

__pmic_clrsetbits__ works the same way, it's defined here: [pinephone_pmic.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L120-L164)

![_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://lupyuen.github.io/images/dsi-connector.png)

[_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Initialise LCD Controller

We've done quite a bit on our LCD Panel...

1.  Switch on __LCD Backlight__

1.  Reset __LCD Panel__ to __Low__

1.  Power on the LCD Panel's __MIPI Display Serial Interface (DSI)__

1.  Reset __LCD Panel__ to __High__

Now it's time to initialise the __Sitronix ST7703 LCD Controller__ inside the LCD Panel!

-   [__Sitronix ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

We do that by sending __20 Initialisation Commands__ over MIPI DSI.

_What kind of Initialisation Commands?_

Here's a __simple Initialisation Command__ with 4 bytes: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L121-L133)

```c
// Initialization Commands for Sitronix ST7703 LCD Controller:
// Command #1: SETEXTC (ST7703 Page 131)
// Enable USER Command
static const uint8_t g_pinephone_setextc[] = {
  0xb9,  // SETEXTC (ST7703 Page 131): Enable USER Command
  0xf1,  // Enable User command
  0x12,  // (Continued)
  0x83   // (Continued)
};
```

And here's a long Initialisation Command with __64 bytes__: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L432-L535)

```c
// Command #16: SETGIP1 (ST7703 Page 163)
// Set forward GIP timing
static const uint8_t g_pinephone_setgip1[] = {
  0xe9,  // SETGIP1: Set forward GIP timing
  0x82,  // SHR0, SHR1, CHR, CHR2 refer to Internal DE (REF_EN = 1); (PANEL_SEL = 2)
  0x10,  // Starting position of GIP STV group 0 = 4102 HSYNC (SHR0 Bits 8-12 = 0x10)
  0x06,  // (SHR0 Bits 0-7 = 0x06)
  0x05,  // Starting position of GIP STV group 1 = 1442 HSYNC (SHR1 Bits 8-12 = 0x05)
  0xa2,  // (SHR1 Bits 0-7 = 0xA2)
  0x0a,  // Distance of STV rising edge and HYSNC = 10*2 Fosc (SPON  Bits 0-7 = 0x0A)
  0xa5,  // Distance of STV falling edge and HYSNC = 165*2 Fosc (SPOFF Bits 0-7 = 0xA5)
  ...
```

We need to send all 20 Initialisation Commands as documented here...

-   [__"Initialise LCD Controller"__](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

_How will we send the Initialisation Commands?_

This is how we __send the 20 Initialisation Commands__ to ST7703 LCD Controller over the MIPI DSI Bus: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L959-L1016)

```c
// Send 20 Initialisation Commands to ST7703 LCD Controller
int pinephone_lcd_panel_init(void) {

  // For every ST7703 Initialisation Command...
  const int cmd_len = sizeof(g_pinephone_commands) /
                      sizeof(g_pinephone_commands[0]);
  for (int i = 0; i < cmd_len; i++) {

    // Get the ST7703 command and length
    const uint8_t *cmd = g_pinephone_commands[i].cmd;
    const uint8_t len  = g_pinephone_commands[i].len;

    //  If command is null, wait 120 milliseconds
    if (cmd == NULL) {
      up_mdelay(120);
      continue;
    }

    // Send the command to ST7703 over MIPI DSI
    write_dcs(cmd, len);
  }
  return OK;
}
```

[(__write_dcs__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L780-L840)

[(How it works)](https://lupyuen.github.io/articles/dsi3#send-mipi-dsi-packet)

_What's g_pinephone_commands?__

That's our __Consolidated List__ of 20 Initialisation Commands: [pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L684-L775)

```c
// 20 Initialization Commands to be sent to ST7703 LCD Controller
static const struct pinephone_cmd_s g_pinephone_commands[] = {
  { g_pinephone_setextc,      sizeof(g_pinephone_setextc) },
  { g_pinephone_setmipi,      sizeof(g_pinephone_setmipi) },
  { g_pinephone_setpower_ext, sizeof(g_pinephone_setpower_ext) },
  ...
```

We're done with the initialisation of the ST7703 LCD Controller inside our LCD Panel! Let's render something...

![Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Render LCD Display

_So our LCD Driver will send MIPI DSI Commands to render graphics on PinePhone's LCD Display?_

It gets complicated (pic above)...

-   __At Startup:__ Our LCD Driver sends MIPI DSI Commands to initialise the __ST7703 LCD Controller__.

    [(As explained earlier)](https://lupyuen.github.io/articles/lcd#initialise-lcd-controller)

-   __After Startup:__ Allwinner A64's __Display Engine__ and __Timing Controller (TCON0)__ pump pixels continuously to the LCD Panel over MIPI DSI.

    (Bypassing our LCD Driver)

Thus our LCD Driver is called __only at startup__ to initialise the LCD Controller (ST7703).

_Why so complicated?_

Yeah but this Rendering Pipeline is __super efficient__!

PinePhone doesn't need to handle Interrupts while rendering the display... Everything is __done in Hardware!__ (Allwinner A64 SoC)

The pixel data is pumped from RAM Framebuffers via __Direct Memory Access (DMA)__. Which is also done in Hardware. (Pic above)

_How do we render graphics with Display Engine and Timing Controller TCON0?_

Our NuttX Kernel Drivers for __Display Engine__ and __Timing Controller TCON0__ are explained here...

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

Let's find out how the drivers are called at startup.

![Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Complete Display Driver

TODO

[pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_display.c)

```c
int up_fbinitialize(int display) {

  // Turn on Display Backlight.
  // BACKLIGHT_BRIGHTNESS_PERCENT is 90
  pinephone_lcd_backlight_enable(BACKLIGHT_BRIGHTNESS_PERCENT);

  // Init Timing Controller TCON0
  a64_tcon0_init(PANEL_WIDTH, PANEL_HEIGHT);

  // Reset LCD Panel to Low
  pinephone_lcd_panel_reset(false);

  // Init PMIC
  pinephone_pmic_init();

  // Wait 15 milliseconds for power supply and power-on init
  up_mdelay(15);

  // Enable MIPI DSI
  a64_mipi_dsi_enable();

  // Enable MIPI D-PHY
  a64_mipi_dphy_enable();

  // Reset LCD Panel to High
  pinephone_lcd_panel_reset(true);

  // Wait 15 milliseconds for LCD Panel
  up_mdelay(15);

  // Initialise ST7703 LCD Controller
  pinephone_lcd_panel_init();

  // Start MIPI DSI Bus in HSC and HSD modes
  a64_mipi_dsi_start();

  // Init Display Engine
  a64_de_init();

  // Wait 160 milliseconds for Display Engine
  up_mdelay(160);

  // Render Frame Buffers with Display Engine
  render_framebuffers();
  return OK;
}
```

TODO: Who calls up_fbinitialize

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lcd.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lcd.md)
