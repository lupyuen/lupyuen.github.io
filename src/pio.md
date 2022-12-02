# NuttX RTOS for PinePhone: Blinking the LEDs

📝 _22 Sep 2022_

![Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS](https://lupyuen.github.io/images/pio-title.webp)

_Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS_

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/uboot#appendix-pinephone-is-now-supported-by-apache-nuttx-rtos)

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

![LEDs on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-schematic.png)

[_LEDs on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone Schematic

Let's turn to Page 11 of the __PinePhone Schematic__ to understand how the PinePhone LEDs are connected...

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

(There's also the __Flash LED__ for PinePhone's Back Camera, enabled by __GPIO PC3__ and triggered by __GPIO PD24__. See page 10 of the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf))

Let's talk about GPIOs...

![Allwinner A64 User Manual (Page 376)](https://lupyuen.github.io/images/pio-register1.png)

[_Allwinner A64 User Manual (Page 376)_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

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

[_Allwinner A64 User Manual (Page 376)_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# Port Controller Registers

Page 376 of the [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) says that the Port Controller's __Base Address__ is __`0x01C2` `0800`__ (pic above)

Which we define like so...

```c
// PIO Base Address for PinePhone 
// Allwinner A64 Port Controller (GPIO)
#define PIO_BASE_ADDRESS 0x01C20800
```

[(Source)](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L83-L122)

Then comes a bunch of registers that will configure the GPIOs and set their values...

-   __Pn_CFG0, 1, 2 and 3__: Configure the GPIO

-   __Pn_DAT__: Read or write the GPIO

Since we're writing to GPIOs __PD18, 19 and 20__ for the PinePhone LEDs, we shall entertain ourselves with...

-   __PD_CFG2__: To configure PD18, 19 and 20

-   __PD_DAT__: To write PD18, 19 and 20

But why __PD_CFG2__ instead of PD_CFG0, 1 or 3? Find out next...

![Allwinner A64 User Manual (Page 387)](https://lupyuen.github.io/images/pio-register3.png)

[_Allwinner A64 User Manual (Page 387)_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# Configure GPIO

Remember our mission for today is to configure GPIOs __PD18, 19 and 20__.

Page 387 of the [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) says that all we need is __PD_CFG2__ at Offset __`0x74`__. (Pic above)

__PD_CFG2__ is a 32-bit Hardware Register. The bits that we need to twiddle are...

-   __PD18_SELECT:__ Bits __8 to 10__ of PD_CFG2

-   __PD19_SELECT:__ Bits __12 to 14__ of PD_CFG2

-   __PD20_SELECT:__ Bits __16 to 18__ of PD_CFG2

The pic above says we need to set the bits to __`001`__ to configure the __GPIOs for Output__.

This is how we configure __PD18 for GPIO Output__: [examples/hello/hello_main.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

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

Then we configure __PD19 and 20 for GPIO Output__: [hello_main.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

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

[_Allwinner A64 User Manual (Page 388)_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# Set GPIO

Our final job for today: __Set the GPIO Output__ for PD18, 19 and 20. So that we can blink the PinePhone LEDs!

Page 388 of the [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) says that we need to tweak Register __PD_DATA__ at Offset __`0x7C`__. (Pic above)

To set PD18, 19 and 20 to High, we set __Bits 18, 19 and 20__ of PD_DATA to 1.

This is how we do it: [hello_main.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L124-L179)

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

![Booting NuttX on PinePhone](https://lupyuen.github.io/images/pio-run1.png)

# Boot NuttX on PinePhone

Now we shall boot [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) on PinePhone, and watch our C program light up the LEDs!

_Will it mess up our PinePhone?_

No worries, we shall boot NuttX safely with a __microSD Card__, we won't touch the Linux Distro on PinePhone.

Follow these steps to __download NuttX__ and copy to a microSD Card...

-   [__"PinePhone Boots NuttX"__](https://lupyuen.github.io/articles/uboot#pinephone-boots-nuttx)

If we're building NuttX ourselves...

-   Copy the code from [__hello_main.c__](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c) to...

    ```text
    apps/examples/hello/hello_main.c
    ```

-   Check that the __BASIC Interpreter__ has been enabled in the NuttX Build...

    [__"Enable BASIC"__](https://lupyuen.github.io/articles/nuttx#enable-basic)

-   Apply this patch to enable __Peek and Poke__ in BASIC...

    [__"Enable Peek and Poke in BASIC"__](https://lupyuen.github.io/articles/pio#appendix-enable-peek-and-poke-in-basic)

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

Enter this command to run our [hello_main.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c) Test Program...

```bash
hello
```

We see the values of the Registers PD_CFG2 and PD_DATA (pic above)...

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

![Backlight on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-backlight.png)

[_Backlight on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone Backlight

Remember we said earlier that __PinePhone's Backlight__ is connected to __GPIO PH10__? (Pic above)

To turn on the Backlight, we would need to tweak...

-   __Register PH_CFG1__ (Offset `0x100`): To configure PH10

    (Bits 8 to 10)

-   __Register PH_DATA__ (Offset `0x10C`): To set PH10

    (Bit 10)

Here's how we turn on PinePhone's Backlight connected to GPIO PH10: [examples/hello/hello_main.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/examples/hello/hello_main.c#L83-L122)

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

__UPDATE:__ PWM also needs to be configured for Port PL10 [(See this)](https://lupyuen.github.io/articles/dsi#appendix-display-backlight)

![Controlling PinePhone's LEDs With BASIC](https://lupyuen.github.io/images/pio-run2.png)

# Control LEDs With BASIC

_Is there a simpler, interactive way to experiment with PinePhone LEDs?_

The [__BASIC Interpreter__](https://en.wikipedia.org/wiki/BASIC) will let us flip the GPIOs (and LEDs) on the fly!

To start the BASIC Interpreter in NuttX Shell, enter __"`bas`"__...

```text
nsh> bas
bas 2.4
Copyright 1999-2014 Michael Haardt.
> 
```

Earlier we saw these values for the Registers __PD_CFG2__ (configure GPIO Output) and __PD_DATA__ (write GPIO Output) when lit up the PinePhone LEDs...

```text
pd_cfg2_reg=0x77711177
pd_data_reg=0x1c0000
```

When we merge the above with the Register Addresses, we get...

-   __PD_CFG2__ is at Address __`0x1C2` `0874`__

    (Base Address `0x01C2` `0800` + Offset `0x74`)

    We write the value __`0x7771` `1177`__ to configure PD18, 19 and 20 for GPIO Output.

-   __PD_DATA__ is at Address __`0x1C2` `087C`__

    (Base Address `0x01C2` `0800` + Offset `0x7C`)

    We write the value __`0x1C` `0000`__ to set PD18, 19 and 20 to High.

OK we're ready to do this in BASIC! We'll call [__`poke`__](https://en.wikipedia.org/wiki/PEEK_and_POKE) with the above Addresses and Values.

At the BASIC Prompt, enter this to configure __PD18, 19 and 20 for GPIO Output__...

```text
poke &h1C20874, &h77711177
```

Then enter this to set __PD18, 19 and 20 to High__...

```text
poke &h1C2087C, &h1C0000
```

Yep PinePhone's Red, Green and Blue LEDs turn on and appear as white!

Finally enter this to set __PD18, 19 and 20 to Low__...

```text
poke &h1C2087C, &h0
```

And watch PinePhone's LEDs switch off!

[(Watch the Demo on YouTube)](https://youtu.be/OTIHMIRd1s4)

_So the `poke` command will write a value to any address?_

Yep [__`poke`__](https://en.wikipedia.org/wiki/PEEK_and_POKE) is a throwback to the old days when we called it to light up individual pixels on the [__Apple \]\[ Graphics Display__](https://en.wikipedia.org/wiki/Apple_II_graphics).

Today we call __`poke`__ to light up the PinePhone LEDs!

[(__`poke`__ works for 32-bit addresses, but not 64-bit addresses)](https://lupyuen.github.io/articles/pio#appendix-enable-peek-and-poke-in-basic)

_Isn't there a `peek` command?_

Indeed! [__`peek`__](https://en.wikipedia.org/wiki/PEEK_and_POKE) will read the value from an address.

Enter these __`peek`__ and __`poke`__ commands to watch the Register Values change as we configure the GPIOs and blink them (pic above)...

```text
> print peek(&h1C20874)
 2004316535 

> poke &h1C20874, &h77711177

> print peek(&h1C20874)
 2003898743 

> print peek(&h1C2087C)
 262144 

> poke &h1C2087C, &h0

> print peek(&h1C2087C)
 0 

> poke &h1C2087C, &h1C0000

> print peek(&h1C2087C)
 1835008  
```

BASIC works great for quick, interactive experiments with PinePhone GPIOs and LEDs!

![Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS](https://lupyuen.github.io/images/pio-title.webp)

# BASIC Blinks The LEDs

_Isn't BASIC a programming language? Surely we can do sophisticated stuff?_

Yep we can write __BASIC Programs__ the old-school (Apple ][) way and run them on PinePhone!

Paste these lines of BASIC Code into the BASIC Prompt...

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
```

And run the BASIC Program by entering...

```bash
run
```

PinePhone's LEDs will blink on and off every 5 seconds, exactly like the animated pic above.

Thus we have a simple, scripted way to manipulate PinePhone's Hardware Registers on the fly!

_Is it really OK to `poke` around PinePhone?_

Since we have __full direct access__ to the PinePhone Hardware, make sure we're __`poke`__-ing the right addresses on PinePhone!

For safety, future versions of NuttX RTOS for PinePhone may disable direct access to the Hardware Registers. (By enabling the Arm64 Memory Management Unit)

When that happens, we shall access the PinePhone GPIOs through the protected [__GPIO Driver__](https://lupyuen.github.io/articles/nuttx#gpio-driver) in the NuttX Kernel.

[(How we enabled __`peek`__ and __`poke`__ for the BASIC Interpreter)](https://lupyuen.github.io/articles/pio#appendix-enable-peek-and-poke-in-basic)

![PinePhone's Linux Device Tree](https://lupyuen.github.io/images/pio-devicetree.png)

# Linux Device Tree

_Is there another way to discover the PinePhone Hardware... Without browsing the PinePhone Schematic?_

Yep the __Linux Device Tree__ describes everything about PinePhone Hardware in Text Format (pic above)...

-   [__"PinePhone Device Tree"__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree)

To access the PinePhone Hardware, the __Linux Kernel__ refers to the Linux Device Tree. (Similar to the Windows Registry)

So the Linux Device Tree will reveal all kinds of goodies about the PinePhone Hardware.

Here's the part that describes PinePhone's __Blue LED__... 

```text
leds {
  compatible = "gpio-leds";

  blue {
    function = "indicator";
    color = <0x03>;
    gpios = <0x2b 0x03 0x14 0x00>;
    retain-state-suspended;
  };
```

[(Source)](https://lupyuen.github.io/articles/pio#led)

We interpret __`gpios`__ as...

-   __`0x2b`__: GPIO (I think?)

-   __`0x03`__: GPIO Port 3 (PD)

-   __`0x14`__: GPIO Pin 20 (PD20)

-   __`0x00`__: Unused (I think?)

Which looks correct, since the Blue LED is connected to GPIO PD20.

The __Green and Red LEDs__ (PD18 and 19) look similar...

```text
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
```

[(Source)](https://lupyuen.github.io/articles/pio#led)

__PinePhone's Backlight__ looks more complicated, since it combines GPIO and [__Pulse-Width Modulation (PWM)__](https://en.wikipedia.org/wiki/Pulse-width_modulation)...

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

[(Source)](https://lupyuen.github.io/articles/pio#backlight-pwm)

This says that Backlight PWM is PL10 and Backlight GPIO is PH10. (With multiple levels of Backlight Brightness)

_Is the Linux Device Tree helpful?_

We're now creating a NuttX Driver for PinePhone's __LCD Display__.

When we snoop around the Linux Device Tree, we might discover some helpful info on PinePhone's Display Hardware...

-   [__"LCD Controller (TCON0)"__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0)

-   [__"MIPI DSI Interface"__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface)

-   [__"Display PHY"__](https://lupyuen.github.io/articles/pio#display-phy)

-   [__"Framebuffer"__](https://lupyuen.github.io/articles/pio#framebuffer)

-   [__"Display Engine"__](https://lupyuen.github.io/articles/pio#display-engine)

__UPDATE:__ We have documented PinePhone's MIPI Display Serial Interface and Display Engine in these articles...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

# What's Next

Today we had fun with __`peek`__ and __`poke`__ while experimenting with PinePhone's LEDs and GPIOs.

Soon we shall create a [__NuttX GPIO Driver__](https://lupyuen.github.io/articles/nuttx#gpio-driver) that will access PinePhone's GPIO Hardware in the NuttX Kernel.

And eventually we shall build NuttX Drivers for PinePhone's [__LCD Display__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0) and [__Touch Panel__](https://lupyuen.github.io/articles/pio#touch-panel)!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/xjzack/nuttx_rtos_for_pinephone_blinking_the_leds/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pio.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pio.md)

# Appendix: Enable Peek and Poke in BASIC

Earlier we ran the __BASIC Interpreter__ in NuttX RTOS to experiment with the PinePhone GPIOs and LEDs...

-   [__"Control LEDs With BASIC"__](https://lupyuen.github.io/articles/pio#control-leds-with-basic)

Then we entered these __`peek`__ and __`poke`__ commands to read and write the Memory Addresses of the GPIO Hardware on PinePhone...

```text
> print peek(&h1C20874)
 2004316535 

> poke &h1C20874, &h77711177

> print peek(&h1C20874)
 2003898743 
```

For safety, the BASIC Interpreter won't allow us to __`peek`__ and __`poke`__ Memory Addresses.

This is how we patched the BASIC Interpreter to support __`peek`__ and __`poke`__: [interpreters/bas/bas_fs.c](https://github.com/lupyuen/nuttx-apps/blob/pinephone/interpreters/bas/bas_fs.c#L1862-L1889)

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

Note that Memory Addresses are passed as 32-bit __`int`__, so some 64-bit addresses will not be accessible via __`peek`__ and __`poke`__.

![PinePhone's Linux Device Tree](https://lupyuen.github.io/images/pio-devicetree.png)

# Appendix: PinePhone Device Tree

The __Linux Device Tree__ describes everything about PinePhone Hardware in Text Format.

To access the PinePhone Hardware, the __Linux Kernel__ refers to the Linux Device Tree. (Similar to the Windows Registry)

So the Linux Device Tree will reveal all kinds of goodies about the PinePhone Hardware.

Earlier we saw snippets of the Device Tree for PinePhone's LEDs and Backlight...

-   [__"Linux Device Tree"__](https://lupyuen.github.io/articles/pio#linux-device-tree)

Now we shall see the parts of the Device Tree relevant to PinePhone's __LCD Display__ and __Touch Panel__.

_Why are we doing this?_

We're now __creating NuttX Drivers__ for PinePhone's LCD Display and Touch Panel.

When we snoop around the Linux Device Tree, we might discover some helpful info for creating the drivers.

_How did we get the Linux Device Tree for PinePhone?_

This is the Device Tree (in Text Format) for PinePhone's Linux Kernel...

-   [__PinePhone Device Tree: sun50i-a64-pinephone-1.2.dts__](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts)

We converted the Device Tree to Text Format with this command...

```
## Convert Device Tree to text format
dtc \
  -o sun50i-a64-pinephone-1.2.dts \
  -O dts \
  -I dtb \
  sun50i-a64-pinephone-1.2.dtb
```

__sun50i-a64-pinephone-1.2.dtb__ came from the [__Jumpdrive microSD__](https://lupyuen.github.io/articles/uboot#pinephone-jumpdrive)...

-   [__PinePhone Jumpdrive Image: pine64-pinephone.img.xz__](https://github.com/dreemurrs-embedded/Jumpdrive/releases/download/0.8/pine64-pinephone.img.xz)

Below are the interesting bits from the PinePhone Linux Device Tree: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts)

![Allwinner A64 User Manual (Page 498)](https://lupyuen.github.io/images/pio-display.png)

_[Allwinner A64 User Manual (Page 498)](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)_

## LCD Controller (TCON0)

Check out the article...

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

Inside the Allwinner A64 SoC, TCON0 is the [__Timing Controller__](https://www.kernel.org/doc/Documentation/devicetree/bindings/display/sunxi/sun4i-drm.txt) for PinePhone's LCD Display.

(Yeah the name sounds odd... A64's Timing Controller actually works like a huge pixel pump)

According to [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) (Chapter 6: "Display", Page 498), A64 has __2 TCON Controllers__ (pic above)...

-   __TCON0__: For PinePhone's [__Xingbangda XBD599__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface) LCD Display

    (With [__MIPI DSI__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface) and [__MIPI D-PHY__](https://lupyuen.github.io/articles/pio#display-phy))

-   __TCON1__: For HDMI Output

We shall only concern ourselves with __TCON0__. (Not TCON1)

(More about TCON in [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf), Section 6.2: "TCON", Page 500)

PinePhone's Linux Device Tree says this about the __TCON0 Timing Controller__ at Address __`0x1C0` `C000`__: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L446-L492)

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

Searching online for `"sun8i-a83t-tcon-lcd"` gives us the __Linux Driver for Allwinner A64 TCON__...

-   [__sun4i_tcon.c__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun4i_tcon.c)

Which looks like a helpful reference for creating our TCON0 Driver for NuttX RTOS.

Here's the high-level doc for the Linux Driver for Allwinner A64 TCON...

-   [__sun4i-drm.txt__](https://www.kernel.org/doc/Documentation/devicetree/bindings/display/sunxi/sun4i-drm.txt)

More about PinePhone Display...

-   [__"Genode Operating System Framework 22.05"__](https://genode.org/documentation/genode-platforms-22-05.pdf)

    (Pages 171 to 197)

_How did we search online for the Linux Driver?_

Suppose we're searching for the Allwinner A64 TCON Driver.

From the Linux Device Tree above, the __"compatible"__ field reveals the name of the driver: `sun8i-a83t-tcon-lcd`

Head over to [__GitHub Code Search__](https://github.com/search).

Enter the __Driver Name__, including quotes: `"sun8i-a83t-tcon-lcd"`

Click __"Code"__. Under __"Languages"__, filter by __C Language__.

We'll see a bunch of matching C Source Files. Take note of the __File Path__, like _"gpu/drm/sun4i/sun4i_tcon.c"_

The Linux Driver we seek shall be located at [__github.com/torvalds/linux/drivers__](https://github.com/torvalds/linux/tree/master/drivers), concatenated with the File Path.

![Allwinner A64 User Manual (Page 500)](https://lupyuen.github.io/images/pio-tcon0.png)

_[Allwinner A64 User Manual (Page 500)](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)_

## MIPI DSI Interface

Check out the articles...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

Allwinner A64's Timing Controller (TCON0) controls PinePhone's LCD Display via the [__Display Serial Interface (DSI)__](https://en.wikipedia.org/wiki/Display_Serial_Interface), as defined by the [__Mobile Industry Processor Interface (MIPI) Alliance__](https://en.wikipedia.org/wiki/MIPI_Alliance).

PinePhone's Linux Device Tree reveals this about A64's __MIPI DSI Interface__ at Address __`0x1CA` `0000`__: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1327-L1356)

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

From above we see that PinePhone is connected to [__Xingbangda XBD599__](https://patchwork.kernel.org/project/dri-devel/patch/20200311163329.221840-4-icenowy@aosc.io/) 5.99-inch 720x1440 MIPI-DSI IPS LCD Panel, which is based on __Sitronix ST7703 LCD Controller__...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

Searching online for `"xingbangda,xbd599"` gives us the __Linux Driver for Sitronix ST7703 LCD Controller__...

-   [__panel-sitronix-st7703.c__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c)

In that file, [__xbd599_init_sequence__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333) describes the ST7703 Commands for initialising the Xingbangda XBD599 LCD Panel.

(__DSI DCS__ refers to the [__MIPI-DSI Display Command Set__](https://docs.zephyrproject.org/latest/hardware/peripherals/mipi_dsi.html))

Searching online for `"sun50i-a64-mipi-dsi"` gives us the __Linux Driver for A64 MIPI DSI__...

-   [__sun6i_mipi_dsi.c__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c)

The __MIPI DSI Registers__ are not documented in the A64 User Manual. However they seem to be documented in the __Allwinner A31 User Manual__...

-   [__Allwinner A31 User Manual__](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

    (Section 7.6: "MIPI DSI", Page 836)

Zephyr OS has a __Generic MIPI DSI Driver__, which might be helpful since it has the same licensing as NuttX RTOS...

-   [__mipi_dsi.h__](https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/drivers/mipi_dsi.h)

-   [__mipi_dsi.c__](https://github.com/zephyrproject-rtos/zephyr/blob/main/drivers/mipi_dsi/mipi_dsi.c)

-   [__Zephyr Docs for MIPI DSI__](https://docs.zephyrproject.org/latest/hardware/peripherals/mipi_dsi.html)

-   [__Zephyr Test for MIPI DSI__](https://github.com/zephyrproject-rtos/zephyr-testing/blob/main/tests/drivers/mipi_dsi/api/src/main.c)

## Display PHY

__UPDATE:__ We're now creating the MIPI Display PHY Driver for NuttX [(See this)](https://lupyuen.github.io/articles/de2#appendix-upcoming-features-in-pinephone-display-driver)

[__MIPI D-PHY__](https://www.intel.com/content/www/us/en/docs/programmable/683092/current/introduction-to-mipi-d-phy.html) is the __Physical Layer Standard__ for the [__MIPI DSI Protocol__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface).

It specifies how Allwinner A64's [__MIPI DSI Interface__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface) should talk to PinePhone's [__Xingbangda XBD599 LCD Display__](https://lupyuen.github.io/articles/pio#mipi-dsi-interface) over Physical Wires.

PinePhone's Linux Device Tree says this about Allwinner A64's __MIPI D-PHY__ at Address __`0x1CA` `1000`__: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1358-L1367)

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

Searching online for `"sun6i-a31-mipi-dphy"` uncovers the __Linux Driver for A64 MIPI D-PHY__...

-   [__phy-sun6i-mipi-dphy.c__](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c)

## Display Engine

Check out the articles...

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

According to [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) (Section 6.1: "DE2.0", Page 499), A64 has a __Display Engine__ that renders the display pipeline.

(Display Engine handles image buffering, scaling, mixing, ...)

See this doc for the details...

-   [__Allwinner Display Engine 2.0 Specifications__](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Here's the definition in PinePhone's Linux Device Tree: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L98-L102)

```text
display-engine {
  compatible = "allwinner,sun50i-a64-display-engine";
  allwinner,pipelines = <0x07 0x08>;
  status = "okay";
};
```

Searching online for `"sun50i-a64-display-engine"` gives us this __Linux Driver for A64 Display Engine__...

-   [__sun4i_drv.c__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun4i_drv.c)

The __u-boot Project__ has another driver for A64 Display Engine...

-   [__sunxi_de2.c__](https://github.com/ARM-software/u-boot/blob/master/drivers/video/sunxi/sunxi_de2.c)

## Framebuffer

PinePhone's Linux Device Tree defines a high-level __Framebuffer__ for apps to render graphics: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L16-L21)

```text
framebuffer-lcd {
  compatible = "allwinner,simple-framebuffer\0simple-framebuffer";
  allwinner,pipeline = "mixer0-lcd0";
  clocks = <0x02 0x64 0x03 0x06>;
  status = "disabled";
};
```

We might build a similar Framebuffer Device in NuttX for rendering graphics with the LVGL GUI Library.

## Touch Panel

PinePhone has a __Goodix GT917S Touch Panel__ that talks on I2C.

Here's the definition in PinePhone's Linux Device Tree: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1125-L1136)

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

Searching online for `"goodix,gt917s"` gives us this __Linux Driver for Goodix GT917S Touch Panel__...

-   [goodix.c](https://github.com/torvalds/linux/blob/master/drivers/input/touchscreen/goodix.c)

## Video Codec

PinePhone's Linux Device Tree includes a __Video Codec__ for A64's Video Engine: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L539-L547)

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

## GPU

PinePhone's Linux Device Tree talks about the __GPU__ too: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1246-L1256)

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

## Deinterlace

And this is probably for __Deinterlacing Videos__: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1369-L1378)

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

Which might not be necessary if we're building a simple Display Driver.

![LEDs on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-schematic.png)

[_LEDs on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

## LED

PinePhone's Linux Device Tree describes the __Red, Green and Blue LEDs__ like so: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1940-L1963)

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

For the Blue LED, we interpret __`gpios`__ as...

-   __`0x2b`__: GPIO (I think?)

-   __`0x03`__: GPIO Port 3 (PD)

-   __`0x14`__: GPIO Pin 20 (PD20)

-   __`0x00`__: Unused (I think?)

Based on the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (page 11, pic above), we know that the LEDs are connected to...

-   __Red LED:__ GPIO PD18 (PD18-LED-R)

-   __Green LED:__ GPIO PD19 (PD19-LED-G)

-   __Blue LED:__ GPIO PD20 (PD20-LED-B)

Hence the Device Tree matches the PinePhone Schematic.

![Backlight on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-backlight.png)

[_Backlight on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

## Backlight PWM

PinePhone's Linux Device Tree describes the __Backlight__ like this: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1832-L1841)

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

We interpret __`enable-gpios`__ as...

-   __`0x2b`__: GPIO (I think?)

-   __`0x07`__: GPIO Port 7 (PH)

-   __`0x0a`__: GPIO Pin 10 (PH10)

-   __`0x00`__: Unused (I think?)

From the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (page 11, pic above) we see that the Backlight is connected to...

-   __Backlight Enable:__ GPIO PH10 (PH10-LCD-BL-EN)

-   __Backlight PWM:__ PWM PL10 (PL10-LCD-PWM)

Thus the Device Tree matches the PinePhone Schematic.

![Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS](https://lupyuen.github.io/images/pio-title.jpg)
