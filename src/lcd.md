# NuttX RTOS for PinePhone: LCD Panel

📝 _2 Jan 2023_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lcd-title.jpg)

TODO: [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) 

TODO

-   [__Watch the Demo on YouTube__](https://www.youtube.com/shorts/UzR7xLZCc0c)

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

Talking over MIPI DSI can get complicated. Later we'll see that ST7703 LCD Controller handles...

-   MIPI DSI __Initialisation Commands__

    (At startup)

-   __Rendering of Pixels__ over MIPI DSI

    (After startup)

Let's start with something simpler without ST7703...

-   Turning on the __LCD Panel Backlight__ (PIO and PWM)

-   __Resetting__ the LCD Panel (PIO)

-   __Powering on__ the LCD Panel (PMIC)

![Backlight on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-backlight.png)

[_Backlight on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# LCD Panel Backlight

TODO

[pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L845-L921)

```c
int pinephone_lcd_backlight_enable(uint32_t percent)
{
  int ret;
  uint32_t period;

  /* Configure PL10 for PWM */

  ginfo("Configure PL10 for PWM\n");
  ret = a64_pio_config(LCD_PWM);
  if (ret < 0)
    {
      gerr("Configure PL10 failed: %d\n", ret);
      return ret;
    }

  /* R_PWM Control Register (Undocumented)
   * Assume same as PWM Control Register (A64 Page 194)
   * Set SCLK_CH0_GATING (Bit 6) to 0 (Mask)
   */

  ginfo("Disable R_PWM\n");
  modreg32(0, SCLK_CH0_GATING, R_PWM_CTRL_REG);

  /* R_PWM Channel 0 Period Register (Undocumented)
   * Assume same as PWM Channel 0 Period Register (A64 Page 195)
   * Set PWM_CH0_ENTIRE_CYS (Bits 16 to 31) to PWM Period
   * Set PWM_CH0_ENTIRE_ACT_CYS (Bits 0 to 15) to PWM Period * Percent / 100
   */

  ginfo("Configure R_PWM Period\n");
  period = PWM_CH0_ENTIRE_CYS(BACKLIGHT_PWM_PERIOD) |
           PWM_CH0_ENTIRE_ACT_CYS(BACKLIGHT_PWM_PERIOD * percent / 100);
  putreg32(period, R_PWM_CH0_PERIOD);

  /* R_PWM Control Register (Undocumented)
   * Assume same as PWM Control Register (A64 Page 194)
   * Set SCLK_CH0_GATING (Bit 6) to 1 (Pass)
   * Set PWM_CH0_EN (Bit 4) to 1 (Enable)
   * Set PWM_CH0_PRESCAL (Bits 0 to 3) to 0b1111 (Prescaler 1)
   */

  ginfo("Enable R_PWM\n");
  uint32_t ctrl = SCLK_CH0_GATING | PWM_CH0_EN | PWM_CH0_PRESCAL(0b1111);
  putreg32(ctrl, R_PWM_CTRL_REG);

  /* Configure PH10 for Output */

  ginfo("Configure PH10 for Output\n");
  ret = a64_pio_config(LCD_BL_EN);
  if (ret < 0)
    {
      gerr("Configure PH10 failed: %d\n", ret);
      return ret;
    }

  /* Set PH10 to High */

  ginfo("Set PH10 to High\n");
  a64_pio_write(LCD_BL_EN, true);

  return OK;
}
```

[(__AP3127__ is a PWM Controller)](https://www.diodes.com/assets/Datasheets/products_inactive_data/AP3127_H.pdf)

![LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/de-reset.jpg)

[_LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Reset LCD Panel

TODO

[pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L922-L958)

```c
int pinephone_lcd_panel_reset(bool val)
{
  int ret;

  /* Reset LCD Panel at PD23 (Active Low), configure PD23 for Output */

  ginfo("Configure PD23 for Output\n");
  ret = a64_pio_config(LCD_RESET);
  if (ret < 0)
    {
      gerr("Configure PD23 failed: %d\n", ret);
      return ret;
    }

  /* Set PD23 to High or Low */

  ginfo("Set PD23 to %d\n", val);
  a64_pio_write(LCD_RESET, val);

  return OK;
}
```

![AXP803 PMIC on PinePhone Schematic (Page 3)](https://lupyuen.github.io/images/de-pmic.png)

[_AXP803 PMIC on PinePhone Schematic (Page 3)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Power On LCD Panel

TODO

[pinephone_pmic.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L169-L282)

```c
int pinephone_pmic_init(void)
{
  int ret;

  /* Set DLDO1 Voltage to 3.3V. DLDO1 powers the Front Camera / USB HSIC /
   * I2C Sensors.
   */

  /* DLDO1 Voltage Control (AXP803 Page 52)
   * Set Voltage (Bits 0 to 4) to 26 (2.6V + 0.7V = 3.3V)
   */

  batinfo("Set DLDO1 Voltage to 3.3V\n");
  ret = pmic_write(DLDO1_VOLTAGE_CONTROL, DLDO1_VOLTAGE(26));
  if (ret < 0)
    {
      baterr("Set DLDO1 failed: %d\n", ret);
      return ret;
    }

  /* Power on DLDO1 */

  /* Output Power On-Off Control 2 (AXP803 Page 51)
   * Set DLDO1 On-Off Control (Bit 3) to 1 (Power On)
   */

  ret = pmic_clrsetbits(OUTPUT_POWER_ON_OFF_CONTROL2, 0,
                        DLDO1_ON_OFF_CONTROL);
  if (ret < 0)
    {
      baterr("Power on DLDO1 failed: %d\n", ret);
      return ret;
    }

  /* Set LDO Voltage to 3.3V. GPIO0LDO powers the Capacitive Touch Panel. */

  /* GPIO0LDO and GPIO0 High Level Voltage Setting (AXP803 Page 77)
   * Set GPIO0LDO and GPIO0 High Level Voltage (Bits 0 to 4) to 26
   * (2.6V + 0.7V = 3.3V)
   */

  batinfo("Set LDO Voltage to 3.3V\n");
  ret = pmic_write(GPIO0LDO_HIGH_LEVEL_VOLTAGE_SETTING,
                   GPIO0LDO_HIGH_LEVEL_VOLTAGE(26));
  if (ret < 0)
    {
      baterr("Set LDO failed: %d\n", ret);
      return ret;
    }

  /* Enable LDO Mode on GPIO0 */

  /* GPIO0 (GPADC) Control (AXP803 Page 76)
   * Set GPIO0 Pin Function Control (Bits 0 to 2) to 0b11 (Low Noise LDO on)
   */

  batinfo("Enable LDO mode on GPIO0\n");
  ret = pmic_write(GPIO0_CONTROL, GPIO0_PIN_FUNCTION(0b11));
  if (ret < 0)
    {
      baterr("Enable LDO failed: %d\n", ret);
      return ret;
    }

  /* Set DLDO2 Voltage to 1.8V. DLDO2 powers the MIPI DSI Interface of
   * Xingbangda XBD599 LCD Panel.
   */

  /* DLDO2 Voltage Control (AXP803 Page 52)
   * Set Voltage (Bits 0 to 4) to 11 (1.1V + 0.7V = 1.8V)
   */

  batinfo("Set DLDO2 Voltage to 1.8V\n");
  ret = pmic_write(DLDO2_VOLTAGE_CONTROL, DLDO2_VOLTAGE(11));
  if (ret < 0)
    {
      baterr("Set DLDO2 failed: %d\n", ret);
      return ret;
    }

  /* Power on DLDO2 */

  /* Output Power On-Off Control 2 (AXP803 Page 51)
   * Set DLDO2 On-Off Control (Bit 4) to 1 (Power On)
   */

  ret = pmic_clrsetbits(OUTPUT_POWER_ON_OFF_CONTROL2, 0x0,
                        DLDO2_ON_OFF_CONTROL);
  if (ret < 0)
    {
      baterr("Power on DLDO2 failed: %d\n", ret);
      return ret;
    }

  return OK;
}
```

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Initialise LCD Controller

TODO

[pinephone_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_lcd.c#L959-L1016)

```c
int pinephone_lcd_panel_init(void)
{
  int i;
  int ret;
  const int cmd_len = sizeof(g_pinephone_commands) /
                      sizeof(g_pinephone_commands[0]);

  /* For every ST7703 Initialization Command */

  ginfo("Init ST7703 LCD Controller\n");
  for (i = 0; i < cmd_len; i++)
    {
      /* Get the ST7703 command and length */

      const uint8_t *cmd = g_pinephone_commands[i].cmd;
      const uint8_t len = g_pinephone_commands[i].len;

      /* If command is null, wait 120 milliseconds */

      if (cmd == NULL)
        {
          up_mdelay(120);
          continue;
        }

      /* Send the command to ST7703 over MIPI DSI */

      ret = write_dcs(cmd, len);
      if (ret < 0)
        {
          gerr("Write DCS failed: %d\n", ret);
          return ret;
        }
    }

  return OK;
}
```

![_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://lupyuen.github.io/images/dsi-connector.png)

[_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Render LCD Display

TODO

# Complete Display Driver

TODO

[pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/lcd/boards/arm64/a64/pinephone/src/pinephone_display.c)

```c
int up_fbinitialize(int display)
{
  int ret;
  static bool initialized = false;

  /* Allow multiple calls */

  DEBUGASSERT(display == 0);
  if (initialized)
    {
      return OK;
    }

  initialized = true;

  /* Turn on Display Backlight */

  ret = pinephone_lcd_backlight_enable(BACKLIGHT_BRIGHTNESS_PERCENT);
  if (ret < 0)
    {
      gerr("Enable Backlight failed: %d\n", ret);
      return ret;
    }

  /* Init Timing Controller TCON0 */

  ret = a64_tcon0_init(PANEL_WIDTH, PANEL_HEIGHT);
  if (ret < 0)
    {
      gerr("Init Timing Controller TCON0 failed: %d\n", ret);
      return ret;
    }

  /* Reset LCD Panel to Low */

  ret = pinephone_lcd_panel_reset(false);
  if (ret < 0)
    {
      gerr("Reset LCD Panel failed: %d\n", ret);
      return ret;
    }

  /* Init PMIC */

  ret = pinephone_pmic_init();
  if (ret < 0)
    {
      gerr("Init PMIC failed: %d\n", ret);
      return ret;
    }

  /* Wait 15 milliseconds for power supply and power-on init */

  up_mdelay(15);

  /* Enable MIPI DSI */

  ret = a64_mipi_dsi_enable();
  if (ret < 0)
    {
      gerr("Enable MIPI DSI failed: %d\n", ret);
      return ret;
    }

  /* Enable MIPI D-PHY */

  ret = a64_mipi_dphy_enable();
  if (ret < 0)
    {
      gerr("Enable MIPI D-PHY failed: %d\n", ret);
      return ret;
    }

  /* Reset LCD Panel to High */

  ret = pinephone_lcd_panel_reset(true);
  if (ret < 0)
    {
      gerr("Reset LCD Panel failed: %d\n", ret);
      return ret;
    }

  /* Wait 15 milliseconds for LCD Panel */

  up_mdelay(15);

  /* Initialise ST7703 LCD Controller */

  ret = pinephone_lcd_panel_init();
  if (ret < 0)
    {
      gerr("Init ST7703 LCD Controller failed: %d\n", ret);
      return ret;
    }

  /* Start MIPI DSI Bus in HSC and HSD modes */

  ret = a64_mipi_dsi_start();
  if (ret < 0)
    {
      gerr("Start MIPI DSI failed: %d\n", ret);
      return ret;
    }

  /* Init Display Engine */

  ret = a64_de_init();
  if (ret < 0)
    {
      gerr("Init Display Engine failed: %d\n", ret);
      return ret;
    }

  /* Wait 160 milliseconds for Display Engine */

  up_mdelay(160);

  /* Render Frame Buffers with Display Engine */

  ret = render_framebuffers();
  if (ret < 0)
    {
      gerr("Display Engine Frame Buffers failed: %d\n", ret);
      return ret;
    }

  return OK;
}

```

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
