# NuttX RTOS for PinePhone: Blinking the LEDs

📝 _30 Sep 2022_

![Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS](https://lupyuen.github.io/images/pio-title.webp)

_Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS_

Programming the __GPIO Hardware__ on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) looks complicated... But it's not that different from microcontrollers!

(Like PineTime Smartwatch and PineCone BL602)

Today we shall learn...

-   How to __blink the LEDs__ on PinePhone

-   What's the __Allwinner A64 Port Controller__

-   What's inside the __Linux Device Tree__

-   How we configure and __flip the GPIOs__

-   How to do this in __C and BASIC__ (pic above)

We shall experiment with PinePhone's GPIO Hardware by booting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) on PinePhone.

_Why boot NuttX RTOS on PinePhone? Why not Linux?_

NuttX RTOS is a super-tiny, Linux-like operating system that gives us __"Unlocked Access"__ to all PinePhone Hardware.

Thus it's easier to directly manipulate the Hardware Registers on PinePhone.

[(Like with __`peek`__ and __`poke`__ in BASIC)](https://en.wikipedia.org/wiki/PEEK_and_POKE)

_Will it mess up the Linux installed on PinePhone?_

We shall boot NuttX safely with a __microSD Card__, we won't touch the Linux Distro on PinePhone.

Let's dive into our __NuttX Porting Journal__ and find out how we blinked the PinePhone LEDs...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![LEDs on PinePhone Schematic](https://lupyuen.github.io/images/pio-schematic.png)

[_LEDs on PinePhone Schematic_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone Schematic

Let's flip to Page 11 of the __PinePhone Schematic__ to understand how the PinePhone LEDs are connected...

-   [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)  

From the pic above, we see that PinePhone has __3 LEDs__...

-   __Red LED__ is connected to __PD18__

    (PD18-LED-R)

-   __Green LED__ is connected to __PD19__

    (PD19-LED-G)

-   __Blue LED__ is connected to __PD20__

    (PD20-LED-B)

Thus we may control the Red, Green and Blue LEDs by flipping PD18, 19 and 20.

_What are PD18, 19 and 20?_

PD18, 19 and 20 are the GPIO Numbers for the __Allwinner A64 SoC__.

The GPIO Numbers look odd, but we'll explain in the next section.

_Any more LEDs on PinePhone?_

Yep there's a huge LED on PinePhone: __Backlight__ for PinePhone's LCD Display.

Based on the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (page 11)...

-   __Backlight Enable__ is connected to __GPIO PH10__

    (PH10-LCD-BL-EN)

-   __Backlight PWM__ is connected to __PWM PL10__

    (PL10-LCD-PWM)

In a while we shall flip __GPIO PH10__ to turn the Backlight on and off.

_Why is the Backlight connected to PWM?_

That's a clever way to __dim the Backlight__.

With [__Pulse-Width Modulation (PWM)__](https://en.wikipedia.org/wiki/Pulse-width_modulation), we may blink the Backlight rapidly to make it seem dimmer.

Let's talk about GPIOs...

![Allwinner A64 User Manual (Page 376)](https://lupyuen.github.io/images/pio-register1.png)

[_Allwinner A64 User Manual (Page 376)_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Allwinner A64 Port Controller

_How many GPIOs does PinePhone support?_

The Allwinner A64 SoC in PinePhone supports a whopping... __103 GPIOs__!

All managed by A64's __Port Controller__.

(Plus another 13 Multi-Functional Pins, like for PWM)

_Whoa that's a lot of GPIOs to manage!_

That's why the A64 Port Controller divides the 103 GPIOs into __7 Ports__ for easier management.

The 7 Ports are named as __Port B__ to __Port H__. (Pic above)

Remember PD18, 19 and 20 for the PinePhone LEDs?

That's short for __Port D__, Pin Numbers __18, 19 and 20__.

Now it becomes clear what we need to do: We shall configure Port D pins 18, 19 and 20 to control the LEDs.

How will we configure Port D? Let's study the registers...

![Allwinner A64 User Manual (Page 376)](https://lupyuen.github.io/images/pio-register2.png)

[_Allwinner A64 User Manual (Page 376)_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Port Controller Registers

Page 376 of the [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) says that the Port Controller's __Base Address__ is __`0x01C2` `0800`__ (pic above)

Which we define like so...

```c
// PIO Base Address for PinePhone 
// Allwinner A64 Port Controller (GPIO)
#define PIO_BASE_ADDRESS 0x01C20800
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L83-L122)

Then comes a bunch of registers that will configure the GPIOs and set their values...

-   __Pn_CFG0, 1, 2 and 3__: Configure the GPIO

-   __Pn_DAT__: Read or write the GPIO

Since we're writing to GPIOs __PD18, 19 and 20__ for the PinePhone LEDs, we shall entertain ourselves with...

-   __PD_CFG2__: To configure PD18, 19 and 20

-   __PD_DAT__: To write PD18, 19 and 20

But why __PD_CFG2__ instead of PD_CFG0, 1 or 3? Find out next...

![Allwinner A64 User Manual (Page 387)](https://lupyuen.github.io/images/pio-register3.png)

[_Allwinner A64 User Manual (Page 387)_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Configure GPIO

Remember our mission for today is to configure GPIOs __PD18, 19 and 20__.

Page 387 of the [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) says that all we need is __PD_CFG2__ at Offset __`0x74`__. (Pic above)

__PD_CFG2__ is a 32-bit Hardware Register. The bits that we need to twiddle are...

-   __PD18_SELECT:__ Bits __8 to 10__ of PD_CFG2

-   __PD19_SELECT:__ Bits __12 to 14__ of PD_CFG2

-   __PD20_SELECT:__ Bits __16 to 18__ of PD_CFG2

The pic above says we need to set the bits to __`001`__ to configure the __GPIOs for Output__.

This is how we configure __PD18 for GPIO Output__: [examples/hello/hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

```c
// PIO Base Address for PinePhone Allwinner A64 Port Controller (GPIO)
#define PIO_BASE_ADDRESS 0x01C20800

// Turn on the PinePhone Red, Green and Blue LEDs
static void test_led(void)
{
  // From PinePhone Schematic: https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf
  // - Red LED:   GPIO PD18 (PD18-LED-R)
  // - Green LED: GPIO PD19 (PD19-LED-G)
  // - Blue LED:  GPIO PD20 (PD20-LED-B)

  // Write to PD Configure Register 2 (PD_CFG2_REG)
  // Offset: 0x74
  uint32_t *pd_cfg2_reg = (uint32_t *)
    (PIO_BASE_ADDRESS + 0x74);

  // Bits 10 to 8: PD18_SELECT (Default 0x7)
  // 000: Input    001: Output
  // 010: LCD_CLK  011: LVDS_VPC
  // 100: RGMII_TXD0/MII_TXD0/RMII_TXD0 101: Reserved
  // 110: Reserved 111: IO Disable
  *pd_cfg2_reg = 
    (*pd_cfg2_reg & ~(0b111 << 8))  // Clear the bits
    | (0b001 << 8);                 // Set the bits for Output
```

Then we configure __PD19 and 20 for GPIO Output__: [hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

```c
  // Bits 14 to 12: PD19_SELECT (Default 0x7)
  // 000: Input    001: Output
  // 010: LCD_DE   011: LVDS_VNC
  // 100: RGMII_TXCK/MII_TXCK/RMII_TXCK 101: Reserved
  // 110: Reserved 111: IO Disable
  *pd_cfg2_reg = 
    (*pd_cfg2_reg & ~(0b111 << 12))  // Clear the bits
    | (0b001 << 12);                 // Set the bits for Output

  // Bits 18 to 16: PD20_SELECT (Default 0x7)
  // 000: Input     001: Output
  // 010: LCD_HSYNC 011: LVDS_VP3
  // 100: RGMII_TXCTL/MII_TXEN/RMII_TXEN 101: Reserved
  // 110: Reserved  111: IO Disable
  *pd_cfg2_reg = 
    (*pd_cfg2_reg & ~(0b111 << 16))  // Clear the bits
    | (0b001 << 16);                 // Set the bits for Output
  printf("pd_cfg2_reg=0x%x\n", *pd_cfg2_reg);
```

PD18, 19 and 20 have been configured for GPIO Output!

Now we set the GPIO Output...

![Allwinner A64 User Manual (Page 388)](https://lupyuen.github.io/images/pio-register4.png)

[_Allwinner A64 User Manual (Page 388)_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Set GPIO

Our final job for today: __Set the GPIO Output__ for PD18, 19 and 20. So that we can blink the PinePhone LEDs!

Page 388 of the [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) says that we need to tweak Register __PD_DATA__ at Offset __`0x7C`__. (Pic above)

To set PD18, 19 and 20 to High, we set __Bits 18, 19 and 20__ of PD_DATA to 1.

This is how we do it: [hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

```c
// PIO Base Address for PinePhone Allwinner A64 Port Controller (GPIO)
#define PIO_BASE_ADDRESS 0x01C20800

// Turn on the PinePhone Red, Green and Blue LEDs
static void test_led(void)
{
  // From PinePhone Schematic: https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf
  // - Red LED:   GPIO PD18 (PD18-LED-R)
  // - Green LED: GPIO PD19 (PD19-LED-G)
  // - Blue LED:  GPIO PD20 (PD20-LED-B)

  // Omitted: Configure PD18, 19, 20 for GPIO Output
  ...

  // Write to PD Data Register (PD_DATA_REG)
  // Offset: 0x7C
  uint32_t *pd_data_reg = (uint32_t *)
    (PIO_BASE_ADDRESS + 0x7C);

  // Bits 24 to 0: PD_DAT (Default 0)
  // If the port is configured as input, the corresponding bit is the pin state. If
  // the port is configured as output, the pin state is the same as the
  // corresponding bit. The read bit value is the value setup by software. If the
  // port is configured as functional pin, the undefined value will be read.
  *pd_data_reg |= (1 << 18);  // Set Bit 18 for PD18
  *pd_data_reg |= (1 << 19);  // Set Bit 19 for PD19
  *pd_data_reg |= (1 << 20);  // Set Bit 20 for PD20
  printf("pd_data_reg=0x%x\n", *pd_data_reg);
}
```

And we're done lighting up the LEDs on PinePhone!

Let's test it on PinePhone...

# Boot NuttX on PinePhone

Now we shall boot [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) on PinePhone, and watch our C program light up the LEDs!

_Will it mess up our PinePhone?_

No worries, we shall boot NuttX safely with a __microSD Card__, we won't touch the Linux Distro on PinePhone.

Follow these steps to __download NuttX__ and copy to a microSD Card...

-   [__"PinePhone Boots NuttX"__](https://lupyuen.github.io/articles/uboot#pinephone-boots-nuttx)

Connect PinePhone to our computer with a __USB Serial Debug Cable__...

-   [__"Boot Log"__](https://lupyuen.github.io/articles/uboot#boot-log)

Insert the microSD into PinePhone and power it on.

On our computer's [__Serial Terminal__](https://lupyuen.github.io/articles/uboot#boot-log), we should see...

```text
Starting kernel ...
HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
...
Shell (NSH) NuttX-10.3.0-RC2
nsh> 
```

Enter this command to run our [hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c) Test Program...

```bash
hello
```

We see the values of the Registers PD_CFG2 and PD_DATA...

```text
nsh> hello
...
pd_cfg2_reg=0x77711177
pd_data_reg=0x1c0000
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx#backlight-and-leds)

[(Watch the Demo on YouTube)](https://youtu.be/MJDxCcKAv0g)

PinePhone's Red, Green and Blue LEDs turn on and appear as white.

Yep we have successfully lit up the LEDs on PinePhone!

# PinePhone Backlight

Remember we said earlier that __PinePhone's Backlight__ is connected to __GPIO PH10__?

To turn on the Backlight, we would need to tweak...

-   __Register PH_CFG1__ (Offset `0x100`): To configure PH10

    (Bits 8 to 10)

-   __Register PH_DATA__ (Offset `0x10C`): To set PH10

    (Bit 10)

Here's how we turn on PinePhone's Backlight connected to GPIO PH10: [examples/hello/hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L83-L122)

```c
// PIO Base Address for PinePhone Allwinner A64 Port Controller (GPIO)
#define PIO_BASE_ADDRESS 0x01C20800

// Turn on the PinePhone Backlight
static void test_backlight(void)
{
  // From PinePhone Schematic: https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf
  // - Backlight Enable: GPIO PH10 (PH10-LCD-BL-EN)
  // - Backlight PWM:    PWM  PL10 (PL10-LCD-PWM)
  // We won't handle the PWM yet

  // Write to PH Configure Register 1 (PH_CFG1_REG)
  // Offset: 0x100
  uint32_t *ph_cfg1_reg = (uint32_t *)
    (PIO_BASE_ADDRESS + 0x100);

  // Bits 10 to 8: PH10_SELECT (Default 0x7)
  // 000: Input     001: Output
  // 010: MIC_CLK   011: Reserved
  // 100: Reserved  101: Reserved
  // 110: PH_EINT10 111: IO Disable
  *ph_cfg1_reg = 
    (*ph_cfg1_reg & ~(0b111 << 8))  // Clear the bits
    | (0b001 << 8);                 // Set the bits for Output
  printf("ph_cfg1_reg=0x%x\n", *ph_cfg1_reg);

  // Write to PH Data Register (PH_DATA_REG)
  // Offset: 0x10C
  uint32_t *ph_data_reg = (uint32_t *)
    (PIO_BASE_ADDRESS + 0x10C);

  // Bits 11 to 0: PH_DAT (Default 0)
  // If the port is configured as input, the corresponding bit is the pin state. If
  // the port is configured as output, the pin state is the same as the
  // corresponding bit. The read bit value is the value setup by software.
  // If the port is configured as functional pin, the undefined value will
  // be read.
  *ph_data_reg |= (1 << 10);  // Set Bit 10 for PH10
  printf("ph_data_reg=0x%x\n", *ph_data_reg);
}
```

When we run the Test Program, we see the values of the Registers PH_CFG1 and PH_DATA...

```text
nsh> hello
...
ph_cfg1_reg=0x7177
ph_data_reg=0x400
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx#backlight-and-leds)

[(Watch the Demo on YouTube)](https://youtu.be/MJDxCcKAv0g)

And PinePhone's Backlight lights up!

# BASIC Blinks The LEDs

TODO

In the previous section we lit up PinePhone's Red, Green and Blue LEDs. Below are the values we wrote to the Allwinner A64 Port Controller...

```text
pd_cfg2_reg=0x77711177
pd_data_reg=0x1c0000
```

Let's do the same in BASIC! Which is great for interactive experimenting with PinePhone Hardware.

This will enable GPIO Output for PD18 (Red), PD19 (Green), PD20 (Blue) in the Register `pd_cfg2_reg` (0x1C20874)...

```text
poke &h1C20874, &h77711177
```

This will light up Red, Green and Blue LEDs via the Register `pd_data_reg` (0x1C2087C)...

```text
poke &h1C2087C, &h1C0000
```

And this will turn off all 3 LEDs via `pd_data_reg` (0x1C2087C)...

```text
poke &h1C2087C, &h0000
```

Install the BASIC Interpreter in NuttX...

-   ["Enable BASIC"](https://lupyuen.github.io/articles/nuttx#enable-basic)

And enter these commands to blink the PinePhone LEDs (off and on)...

[__Watch the Demo on YouTube__](https://youtu.be/OTIHMIRd1s4)

```text
nsh> bas
task_spawn: name=bas entry=0x4009b340 file_actions=0x400f3580 attr=0x400f3588 argv=0x400f36d0
spawn_execattrs: Setting policy=2 priority=100 for pid=7
bas 2.4
Copyright 1999-2014 Michael Haardt.
This is free software with ABSOLUTELY NO WARRANTY.

> print peek(&h1C20874)
 2004316535 

> poke &h1C20874, &h77711177

> print peek(&h1C20874)
 2003898743 

> print peek(&h1C2087C)
 262144 

> poke &h1C2087C, &h0000

> print peek(&h1C2087C)
 0 

> poke &h1C2087C, &h1C0000

> print peek(&h1C2087C)
 1835008  
```

Or run it in a loop like so...

```text
10 'Enable GPIO Output for PD18, PD19 and PD20
20 poke &h1C20874, &h77711177
30 'Turn off GPIOs PD18, PD19 and PD20
40 poke &h1C2087C, &h0
50 sleep 5
60 'Turn on GPIOs PD18, PD19 and PD20
70 poke &h1C2087C, &h1C0000
80 sleep 5
90 goto 40
run
```

We patched NuttX BASIC so that it supports `peek` and `poke`: [interpreters/bas/bas_fs.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/interpreters/bas/bas_fs.c#L1862-L1889)

```c
int FS_memInput(int address)
{
  //  Return the 32-bit word at the specified address.
  //  TODO: Quit if address is invalid.
  return *(int *)(uint64_t) address;

  //  Previously:
  //  FS_errmsg = _("Direct memory access not available");
  //  return -1;
}

int FS_memOutput(int address, int value)
{
  //  Set the 32-bit word at the specified address
  //  TODO: Quit if address is invalid.
  *(int *)(uint64_t) address = value;
  return 0;

  //  Previously:
  //  FS_errmsg = _("Direct memory access not available");
  //  return -1;
}
```

Note that addresses are passed as 32-bit `int`, so some 64-bit addresses will not be accessible via `peek` and `poke`.

# What's Next

TODO: GPIO Driver

TODO: MIPI DSI: I have zero idea what I'm doing... But it would be super hilarious if it works!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pio.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pio.md)

# Appendix: PinePhone Device Tree

TODO

Let's figure out how Allwinner A64's Display Timing Controller (TCON0) talks to PinePhone's MIPI DSI Display. (So we can build NuttX Drivers)

More info on PinePhone Display...

-   ["Genode Operating System Framework 22.05"](https://genode.org/documentation/genode-platforms-22-05.pdf), pages 171 to 197.

We tried tweaking the TCON0 Controller but the display is still blank (maybe backlight is off?)

-   [examples/hello/hello_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L75-L234)

Below is the Device Tree for PinePhone's Linux Kernel...

-   [PinePhone Device Tree: sun50i-a64-pinephone-1.2.dts](sun50i-a64-pinephone-1.2.dts)

We converted the Device Tree with this command...

```
## Convert Device Tree to text format
dtc \
  -o sun50i-a64-pinephone-1.2.dts \
  -O dts \
  -I dtb \
  sun50i-a64-pinephone-1.2.dtb
```

`sun50i-a64-pinephone-1.2.dtb` came from the [Jumpdrive microSD](https://lupyuen.github.io/articles/uboot#pinephone-jumpdrive).

High-level doc of Linux Drivers...

-   [devicetree/bindings/display/sunxi/sun4i-drm.txt](https://www.kernel.org/doc/Documentation/devicetree/bindings/display/sunxi/sun4i-drm.txt)

PinePhone Schematic shows the connections for Display, Touch Panel and Backlight...

-   [PinePhone v1.2b Released Schematic](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

Here are the interesting bits from the PinePhone Linux Device Tree: [sun50i-a64-pinephone-1.2.dts](sun50i-a64-pinephone-1.2.dts)

## LCD Controller (TCON0)

TODO

```text
lcd-controller@1c0c000 {
  compatible = "allwinner,sun50i-a64-tcon-lcd\0allwinner,sun8i-a83t-tcon-lcd";
  reg = <0x1c0c000 0x1000>;
  interrupts = <0x00 0x56 0x04>;
  clocks = <0x02 0x2f 0x02 0x64>;
  clock-names = "ahb\0tcon-ch0";
  clock-output-names = "tcon-pixel-clock";
  #clock-cells = <0x00>;
  resets = <0x02 0x18 0x02 0x23>;
  reset-names = "lcd\0lvds";

  ports {
    #address-cells = <0x01>;
    #size-cells = <0x00>;

    // TCON0: MIPI DSI Display
    port@0 {
      #address-cells = <0x01>;
      #size-cells = <0x00>;
      reg = <0x00>;

      endpoint@0 {
        reg = <0x00>;
        remote-endpoint = <0x22>;
        phandle = <0x1e>;
      };

      endpoint@1 {
        reg = <0x01>;
        remote-endpoint = <0x23>;
        phandle = <0x20>;
      };
    };

    // TCON1: HDMI
    port@1 { ... };
  };
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L446-L492)

## MIPI DSI Interface

TODO

```text
dsi@1ca0000 {
  compatible = "allwinner,sun50i-a64-mipi-dsi";
  reg = <0x1ca0000 0x1000>;
  interrupts = <0x00 0x59 0x04>;
  clocks = <0x02 0x1c>;
  resets = <0x02 0x05>;
  phys = <0x53>;
  phy-names = "dphy";
  status = "okay";
  #address-cells = <0x01>;
  #size-cells = <0x00>;
  vcc-dsi-supply = <0x45>;

  port {

    endpoint {
      remote-endpoint = <0x54>;
      phandle = <0x24>;
    };
  };

  panel@0 {
    compatible = "xingbangda,xbd599";
    reg = <0x00>;
    reset-gpios = <0x2b 0x03 0x17 0x01>;
    iovcc-supply = <0x55>;
    vcc-supply = <0x48>;
    backlight = <0x56>;
  };
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1327-L1356)

## Display PHY

TODO

```text
d-phy@1ca1000 {
  compatible = "allwinner,sun50i-a64-mipi-dphy\0allwinner,sun6i-a31-mipi-dphy";
  reg = <0x1ca1000 0x1000>;
  clocks = <0x02 0x1c 0x02 0x71>;
  clock-names = "bus\0mod";
  resets = <0x02 0x05>;
  status = "okay";
  #phy-cells = <0x00>;
  phandle = <0x53>;
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1358-L1367)

## Backlight PWM

TODO

```text
backlight {
  compatible = "pwm-backlight";
  pwms = <0x62 0x00 0xc350 0x01>;
  enable-gpios = <0x2b 0x07 0x0a 0x00>;
  power-supply = <0x48>;
  brightness-levels = <0x1388 0x1480 0x1582 0x16e2 0x18c9 0x1b4b 0x1e7d 0x2277 0x274e 0x2d17 0x33e7 0x3bd5 0x44f6 0x4f5f 0x5b28 0x6864 0x7729 0x878e 0x99a7 0xad8b 0xc350>;
  num-interpolated-steps = <0x32>;
  default-brightness-level = <0x1f4>;
  phandle = <0x56>;
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1832-L1841)

From [PinePhone Schematic](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)...

-   Backlight Enable: GPIO PH10 (PH10-LCD-BL-EN)

-   Backlight PWM: PWM PL10 (PL10-LCD-PWM)

## LED

TODO

```text
leds {
  compatible = "gpio-leds";

  blue {
    function = "indicator";
    color = <0x03>;
    gpios = <0x2b 0x03 0x14 0x00>;
    retain-state-suspended;
  };

  green {
    function = "indicator";
    color = <0x02>;
    gpios = <0x2b 0x03 0x12 0x00>;
    retain-state-suspended;
  };

  red {
    function = "indicator";
    color = <0x01>;
    gpios = <0x2b 0x03 0x13 0x00>;
    retain-state-suspended;
  };
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1940-L1963)

From [PinePhone Schematic](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)...

-   Red LED: GPIO PD18 (PD18-LED-R)

-   Green LED: GPIO PD19 (PD19-LED-G)

-   Blue LED: GPIO PD20 (PD20-LED-B)

## Framebuffer

TODO

```text
framebuffer-lcd {
  compatible = "allwinner,simple-framebuffer\0simple-framebuffer";
  allwinner,pipeline = "mixer0-lcd0";
  clocks = <0x02 0x64 0x03 0x06>;
  status = "disabled";
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L16-L21)

## Display Engine

TODO

```text
display-engine {
  compatible = "allwinner,sun50i-a64-display-engine";
  allwinner,pipelines = <0x07 0x08>;
  status = "okay";
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L98-L102)

## Touch Panel

TODO

```text
touchscreen@5d {
  compatible = "goodix,gt917s";
  reg = <0x5d>;
  interrupt-parent = <0x2b>;
  interrupts = <0x07 0x04 0x04>;
  irq-gpios = <0x2b 0x07 0x04 0x00>;
  reset-gpios = <0x2b 0x07 0x0b 0x00>;
  AVDD28-supply = <0x48>;
  VDDIO-supply = <0x48>;
  touchscreen-size-x = <0x2d0>;
  touchscreen-size-y = <0x5a0>;
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1125-L1136)

## Video Codec

TODO

```text
video-codec@1c0e000 {
  compatible = "allwinner,sun50i-a64-video-engine";
  reg = <0x1c0e000 0x1000>;
  clocks = <0x02 0x2e 0x02 0x6a 0x02 0x5f>;
  clock-names = "ahb\0mod\0ram";
  resets = <0x02 0x17>;
  interrupts = <0x00 0x3a 0x04>;
  allwinner,sram = <0x28 0x01>;
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L539-L547)

## GPU

TODO

```text
gpu@1c40000 {
  compatible = "allwinner,sun50i-a64-mali\0arm,mali-400";
  reg = <0x1c40000 0x10000>;
  interrupts = <0x00 0x61 0x04 0x00 0x62 0x04 0x00 0x63 0x04 0x00 0x64 0x04 0x00 0x66 0x04 0x00 0x67 0x04 0x00 0x65 0x04>;
  interrupt-names = "gp\0gpmmu\0pp0\0ppmmu0\0pp1\0ppmmu1\0pmu";
  clocks = <0x02 0x35 0x02 0x72>;
  clock-names = "bus\0core";
  resets = <0x02 0x1f>;
  assigned-clocks = <0x02 0x72>;
  assigned-clock-rates = <0x1dcd6500>;
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1246-L1256)

## Deinterlace

TODO

```text
deinterlace@1e00000 {
  compatible = "allwinner,sun50i-a64-deinterlace\0allwinner,sun8i-h3-deinterlace";
  reg = <0x1e00000 0x20000>;
  clocks = <0x02 0x31 0x02 0x66 0x02 0x61>;
  clock-names = "bus\0mod\0ram";
  resets = <0x02 0x1a>;
  interrupts = <0x00 0x5d 0x04>;
  interconnects = <0x57 0x09>;
  interconnect-names = "dma-mem";
};
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1369-L1378)

![TODO](https://lupyuen.github.io/images/pio-title.jpg)
