# NuttX RTOS for PinePhone: 4G LTE Modem

📝 _12 Apr 2023_

![Quectel EG25-G LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

[_Quectel EG25-G LTE Modem inside PinePhone_](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

What makes [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a phone? It's the [__4G LTE Modem__](https://en.wikipedia.org/wiki/LTE_(telecommunication)) inside that makes Phone Calls and sends Text Messages!

Now we're building a [__Feature Phone__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) with [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System). To make things simpler, we're writing down __everything we know__ about the 4G LTE Modem, and how it works inside PinePhone...

-   What's the __Quectel EG25-G LTE Modem__

-   How it's __connected inside PinePhone__

-   How we make __Phone Calls__ and send __Text Messages__

-   How we __power up__ the LTE Modem

-   __Programming the LTE Modem__ with UART, USB and Apache NuttX RTOS

Read on to learn all about PinePhone's 4G LTE Modem...

![Quectel EG25-G LTE Modem](https://lupyuen.github.io/images/usb2-modem.jpg)

[_Quectel EG25-G LTE Modem_](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

# Quectel EG25-G LTE Modem

_What's this LTE Modem?_

Inside PinePhone is the [__Quectel EG25-G LTE Modem__](https://wiki.pine64.org/index.php/PinePhone#Modem) for [__4G LTE__](https://en.wikipedia.org/wiki/LTE_(telecommunication)) Voice Calls, SMS and Mobile Data, plus GPS (pic above)...

-   [__Quectel EG25-G Datasheet__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

-   [__EG25-G Hardware Design__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_Hardware_Design_V1.4.pdf)

To control the LTE Modem, we send __AT Commands__...

-   [__EG25-G AT Commands__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

-   [__EG25-G GNSS__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_GNSS_Application_Note_V1.3.pdf)

-   [__Get Started with AT Commands__](https://www.twilio.com/docs/iot/supersim/works-with-super-sim/quectel-eg25-g)

So to dial the number __`1711`__, we send this AT Command...

```text
ATD1711;
```

The LTE Modem has similar AT Commands for SMS and Mobile Data.

[(EG25-G runs on __Qualcomm MDM 9607__ with a Cortex-A7 CPU inside)](https://xnux.eu/devices/feature/modem-pp.html#toc-modem-on-pinephone)

_How to send the AT Commands to LTE Modem?_

The LTE Modem accepts __AT Commands__ in two ways (pic below)...

-   Via the __UART Port (Serial)__

    Which is Slower: Up to 921.6 kbps

-   Via the __USB Port (USB Serial)__

    Which is Faster: Up to 480 Mbps

So if we're sending and receiving __lots of 4G Mobile Data__, USB is the better way.

(UART Interface is probably sufficient for a Feature Phone)

Let's talk about the UART and USB Interfaces...

![Data Interfaces for LTE Modem](https://lupyuen.github.io/images/lte-title4.jpg)

# Data Interfaces for LTE Modem

_There's a band of bass players in my PinePhone?_

Ahem the [__Baseband Processor__](https://en.wikipedia.org/wiki/Baseband_processor) inside the LTE Modem (pic above) is the hardware that handles the __Radio Functions__ for 4G LTE and GPS.

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the Baseband Processor talks to PinePhone (Allwinner A64) over the following __Data Interfaces__ (pic above)...

-   __USB__ ⇆ A64 Port __USB1__ _(USB Serial)_

    For AT Commands and GPS Output. (Up to 480 Mbps)

-   __SIM__ ⇆ PinePhone 4G SIM Card

    For connecting to the 4G LTE Mobile Network.

-   __PCM__ ⇆ A64 Port __PCM0__

    [__PCM Digital Audio Stream__](https://en.wikipedia.org/wiki/Pulse-code_modulation) for 4G Voice Calls.

-   __UART__ ⇆ A64 Port __UART3__ _(RX / TX)_, __UART4__ _(CTS / RTS)_, __PB2__ _(DTR)_

    Simpler, alternative interface for AT Commands.
    
    (Default 115.2 kbps, up to 921.6 kbps)

UART is slower than USB, so we should probably use USB instead of UART.

(Unless we're building a simple Feature Phone without GPS)

PinePhone also controls the LTE Modem with a bunch of GPIO Pins...

![Control Pins for LTE Modem](https://lupyuen.github.io/images/lte-title3.jpg)

# Control Pins for LTE Modem

_PinePhone's LTE Modem is controlled only by AT Commands?_

There's more! According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the LTE Modem is controlled by the following GPIO Pins (pic above)...

-   __Baseband Power__ ← A64 Port __PL7__

    Supplies power to LTE Modem.

    (Also connected to Battery Power VBAT and Power Management DCDC1)

-   __Power Key__ ← A64 Port __PB3__

    Power up the LTE Modem.

    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

-   __Reset__ ← A64 Port __PC4__

    Reset the LTE Modem.

    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

We'll control the above GPIO Pins to __power up the LTE Modem__ at startup. (More in the next section)

Also at startup, we'll read this GPIO Pin to check if the __LTE Modem is hunky dory__...

-   __Status__ → A64 Port __PH9__

    Read the Modem Status.

    [(See this)](https://lupyuen.github.io/articles/lte#status-indication)

These GPIO Pins control the __Airplane Mode__ and __Sleep State__...

-   __Disable__ ← A64 Port __PH8__

    Enable or Disable Airplane Mode.

    [(See this)](https://lupyuen.github.io/articles/lte#other-interface-pins)

-   __AP Ready__ ← A64 Port __PH7__

    Set the Modem Sleep State.

    [(See this)](https://lupyuen.github.io/articles/lte#other-interface-pins)

And the LTE Modem signals PinePhone on this GPIO Pin for __Incoming Calls__...

-   __Ring Indicator__ → A64 Port __PL6__

    Indicates Incoming Calls.

    [(See this)](https://lupyuen.github.io/articles/lte#main-uart-interface)

Let's power up the LTE Modem...

![LTE Modem Power](https://lupyuen.github.io/images/lte-title1.jpg)

# LTE Modem Power

_How will we power up the LTE Modem?_

[__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15) says that PinePhone controls the power via __GPIO Pin PL7__ (pic above)...

-   __RF Power__ ← A64 Port __PL7__

    Supplies power to the Radio Frequency Transmitter and Receiver.
    
    (4G LTE and GPS Transceiver)

-   __Baseband Power__ ← A64 Port __PL7__

    Supplies power to the Baseband Processor.

    (4G LTE and GPS Radio Functions)

__GPIO Pin PL7__ (bottom left) switches on the __Battery Power 4G-BAT__ (top left)...

![LTE Modem Power](https://lupyuen.github.io/images/lte-power.png)

[_PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

Which powers the __LTE Modem via VBAT_BB__ (top right).

Thus LTE Modem won't power up without the Lithium-ion Battery.

[(__WPM1481__ is a Power Controller)](https://datasheet.lcsc.com/lcsc/1811131731_WILLSEMI-Will-Semicon-WPM1481-6-TR_C239798.pdf)

_What's Switch SW1-A? (Bottom left)_

[__Hardware Privacy Switch 1 (Modem)__](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration) should be set to "On".

Or the LTE Modem won't power on!

(Indeed that's a Hardware Switch, not a Soft Switch)

_So we set GPIO Pin PL7 and the modem powers on?_

There's a __Soft Switch__ inside the LTE Modem that we need to toggle...

-   __Power Key__ ← A64 Port __PB3__

    Power up the LTE Modem.
    
    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

Sounds complicated, but we'll explain the complete Power Up Sequence in a while.

(Power Key works like the press-and-hold Power Button on vintage Nokia Phones)

_Anything else to power up the LTE Modem?_

In a while we'll set the __Reset Pin__ and check the __Status Pin__...

-   __Reset__ ← A64 Port __PC4__

    Reset the LTE Modem.

    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

-   __Status__ → A64 Port __PH9__

    Read the Modem Status.

    [(See this)](https://lupyuen.github.io/articles/lte#status-indication)

We need to program PinePhone's __Power Management Integrated Circuit (PMIC)__ to supply __3.3 V on DCDC1__.  Here's why...

![LTE Modem Power Output](https://lupyuen.github.io/images/lte-title2.jpg)

# Power Output

_Wait there's a Power Output for the LTE Modem?_

Yeah it gets confusing. The LTE Modem __outputs 1.8 Volts__ to PinePhone (pic above)...

-   __Power Output (1.8 V)__ → PinePhone __VDD_EXT__

    Power Output from LTE Modem to PinePhone. (1.8 V)

    [(See this)](https://lupyuen.github.io/articles/lte#power-supply)

Which goes into PinePhone's __Voltage Translators__ as __VDD_EXT__ (top left)...

![LTE Modem Power Output](https://lupyuen.github.io/images/lte-vddext.png)

[_PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

[(__TXB0104__ is a Voltage Translator)](https://www.ti.com/lit/ds/symlink/txb0104.pdf)

The circuit above converts the __UART Signals__ (TX / RX / CTS / RTS)...

-   From __1.8 V (LTE Modem, left)__

-   To __3.3 V (PinePhone, right)__

Voltage Translators are also used for the [__LTE Modem Control Pins__](https://lupyuen.github.io/articles/lte#control-pins-for-lte-modem).

_What's DCDC1? (Top right)_

We need to program PinePhone's [__Power Management Integrated Circuit (PMIC)__](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit) to supply __3.3 V on DCDC1__.

Otherwise the UART Port (and the Control Pins) will get blocked by the Voltage Translators.

_Why 1.8 V for the LTE Modem?_

Most parts of the LTE Modem run on 3.3 V... Just that it needs to power up the __SIM Card at 1.8 V__. [(See this)](https://en.wikipedia.org/wiki/SIM_card#Design)

(Remember that the SIM Card is actually a microcontroller)

This [__Low Voltage Signaling__](https://www.sdcard.org/developers/sd-standard-overview/low-voltage-signaling/) is probably meant for newer, power-efficient gadgets. [(Like this)](https://www.sdcard.org/developers/sd-standard-overview/low-voltage-signaling/)

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

# Power On LTE Modem

_Whoa LTE Modem has more pins than a Bowling Alley! (Pic above)_

_How exactly do we power up the LTE Modem?_

Earlier we spoke about PinePhone's __GPIO Pins__ that control the LTE Modem...

| LTE Modem Pin | A64 GPIO Pin |
|:--------------|:--------:|
| [__RF Power__](https://lupyuen.github.io/articles/lte#lte-modem-power) | ← __PL7__
| [__Baseband Power__](https://lupyuen.github.io/articles/lte#lte-modem-power) | ← __PL7__
| [__Reset__](https://lupyuen.github.io/articles/lte#lte-modem-power) | ←  __PC4__
| [__Power Key__](https://lupyuen.github.io/articles/lte#lte-modem-power) | ← __PB3__
| [__Disable__](https://lupyuen.github.io/articles/lte#control-pins-for-lte-modem) | ← __PH8__
| [__Status__](https://lupyuen.github.io/articles/lte#lte-modem-power) | → __PH9__

This is how we control the GPIO Pins to __power up the LTE Modem__...

1.  Program PinePhone's [__Power Management Integrated Circuit (PMIC)__](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit) to supply __3.3 V on DCDC1__

    [(Like this)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/0216f6968a82a73b67fb48a276b3c0550c47008a/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L294-L340)

    (Skip this if DCDC1 is already powered on)

1.  Set __PL7 to High__ to power on the RF Transceiver and Baseband Processor

1.  Set __PC4 to High__ to deassert LTE Modem Reset

1.  Set __PB3 to High__ to prepare the Power Key for startup

1.  __Wait 30 milliseconds__ for VBAT Power Supply to be stable

1.  Toggle __PB3 (Power Key)__ to start the LTE Modem, like this:

    Set __PB3 to Low__ for at least 500 ms...
    
    Then set __PB3 to High__.

1.  Set __PH8 to High__ to disable Airplane Mode

1.  __Read PH9__ to check the LTE Modem Status:

    PH9 goes from __High to Low__ when the LTE Modem is ready, in 2.5 seconds.

1.  __UART and USB Interfaces__ will be operational in 13 seconds

[__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 41) beautifully illustrates the __Power On Sequence__...

![LTE Modem Power](https://lupyuen.github.io/images/lte-power2.png)

_LTE Modem Status goes High to Low when the LTE Modem is ready. Any gotchas?_

We might NOT be able to __read the LTE Modem Status reliably__ via GPIO Pin PH9.

This will affect our NuttX Testing, as we'll soon see.

[(More about this)](https://lupyuen.github.io/articles/lte#status-indication)

_Power Key looks funky: High → Low → High..._

Yeah the Power Key is probably inspired by the press-and-hold Power Button on vintage Nokia Phones.

Let's implement the steps with Apache NuttX RTOS...

# Power Up wth NuttX

_We've seen the Power On Sequence for LTE Modem..._

_How will we implement it in Apache NuttX RTOS?_

This is how we implement the LTE Modem's __Power On Sequence__ in NuttX: [a64_usbhost.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/bcd8b474a61309dbaaaad85383a1a10789d237ab/a64_usbhost.c#L337-L464)

```c
// Read PH9 to check LTE Modem Status
#define STATUS (PIO_INPUT | PIO_PORT_PIOH | PIO_PIN9)
a64_pio_config(STATUS);  // TODO: Check result
_info("Status=%d\n", a64_pio_read(STATUS));
```

[(__a64_pio_config__ comes from A64 PIO Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L175-L343)

[(__a64_pio_read__ too)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L391-L419)

We begin by reading PH9 for the __LTE Modem Status__.

Next we power up __3.3 V on DCDC1__ with PinePhone's Power Management Integrated Circuit (PMIC)...

```c
// Power on DCDC1
// TODO: Don't do this if DCDC1 is already powered on
pinephone_pmic_usb_init();

// Print the status
_info("Status=%d\n", a64_pio_read(STATUS));

// Wait 1 second for DCDC1 to be stable
up_mdelay(1000);
// Omitted: Print the status
```

[(__pinephone_pmic_usb_init__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/0216f6968a82a73b67fb48a276b3c0550c47008a/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L294-L340)

Then we set PL7 to High to __power up the RF Transceiver and Baseband Processor__...

```c
// Set PL7 to High to Power On LTE Modem (4G-PWR-BAT)
// Configure PWR_BAT (PL7) for Output
#define P_OUTPUT (PIO_OUTPUT | PIO_PULL_NONE | PIO_DRIVE_MEDLOW | \
                  PIO_INT_NONE | PIO_OUTPUT_SET)
#define PWR_BAT (P_OUTPUT | PIO_PORT_PIOL | PIO_PIN7)
a64_pio_config(PWR_BAT);  // TODO: Check result

// Set PWR_BAT (PL7) to High
a64_pio_write(PWR_BAT, true);
// Omitted: Print the status

// Wait 1 second and check the status
up_mdelay(1000);
// Omitted: Print the status
```

[(__a64_pio_write__ comes from A64 PIO Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L345-L389)

We set PC4 to High to __deassert the LTE Modem Reset__...

```c
// Set PC4 to High to Deassert LTE Modem Reset (BB-RESET / RESET_N)
// Configure RESET_N (PC4) for Output
#define RESET_N (P_OUTPUT | PIO_PORT_PIOC | PIO_PIN4)
a64_pio_config(RESET_N);  // TODO: Check result

// Set RESET_N (PC4) to High
a64_pio_write(RESET_N, true);
// Omitted: Print the status
```

Now we __toggle PB3 for the Power Key__: High → 30 ms → Low → 500 ms → High...

```c
// Set PB3 to Power On LTE Modem (BB-PWRKEY / PWRKEY).
// PWRKEY should be pulled down at least 500 ms, then pulled up.
// Configure PWRKEY (PB3) for Output
#define PWRKEY (P_OUTPUT | PIO_PORT_PIOB | PIO_PIN3)
a64_pio_config(PWRKEY);  // TODO: Check result

// Set PWRKEY (PB3) to High
a64_pio_write(PWRKEY, true);
// Omitted: Print the status

// Wait 30 ms for VBAT to be stable
up_mdelay(30);
// Omitted: Print the status

// Set PWRKEY (PB3) to Low
a64_pio_write(PWRKEY, false);
// Omitted: Print the status

// Wait 500 ms for PWRKEY
up_mdelay(500);
// Omitted: Print the status

// Set PWRKEY (PB3) to High
a64_pio_write(PWRKEY, true);
// Omitted: Print the status
```

Finally we set PH8 to High to __disable Airplane Mode__...

```c
// Set PH8 to High to Disable Airplane Mode (BB-DISABLE / W_DISABLE#)
// Configure W_DISABLE (PH8) for Output
#define W_DISABLE (P_OUTPUT | PIO_PORT_PIOH | PIO_PIN8)
a64_pio_config(W_DISABLE);  // TODO: Check result

// Set W_DISABLE (PH8) to High
a64_pio_write(W_DISABLE, true);

// For Debugging: Print the status every 2 seconds
_info("Status=%d\n", a64_pio_read(STATUS));
up_mdelay(2000); _info("Status=%d\n", a64_pio_read(STATUS));
up_mdelay(2000); _info("Status=%d\n", a64_pio_read(STATUS));
up_mdelay(2000); _info("Status=%d\n", a64_pio_read(STATUS));
```

And we print the status. Let's run this!

![Powering up LTE Modem on Apache NuttX RTOS](https://lupyuen.github.io/images/lte-run.png)

[_Powering up LTE Modem on Apache NuttX RTOS_](https://github.com/lupyuen/pinephone-nuttx-usb/blob/893c7c914c0594d93fa4f75ce20bc990c4583454/README.md#output-log)

# Is LTE Modem Up?

_We've implemented the Power On Sequence for LTE Modem..._

_Does it work on Apache NuttX RTOS?_

The results look a little peculiar. Here's the output when NuttX powers up the LTE Modem...

```text
pinephone_pmic_usb_init: Set DCDC1 Voltage to 3.3V
pmic_write: reg=0x20, val=0x11
a64_rsb_write: rt_addr=0x2d, reg_addr=0x20, value=0x11
pmic_clrsetbits: reg=0x10, clr_mask=0x0, set_mask=0x1
a64_rsb_read: rt_addr=0x2d, reg_addr=0x10
a64_rsb_write: rt_addr=0x2d, reg_addr=0x10, value=0x37
a64_usbhost_initialize: Status=0

Wait 1000 ms
Status=0
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/893c7c914c0594d93fa4f75ce20bc990c4583454/README.md#output-log)

NuttX begins by setting the __DCDC1 Voltage to 3.3 V__ through the Power Management Integrated Circuit (PMIC).

(Actually we should skip this if DCDC1 is already powered on)

[(__RSB__ refers to the __Reduced Serial Bus__)](https://lupyuen.github.io/articles/de#appendix-reduced-serial-bus)

Then it __switches on the power__ (PL7) and __deasserts the reset__ (PC4)...

```text
Set PWR_BAT (PL7) to High
Status=1

Set RESET_N (PC4) to High
Status=1
```

Toggle the __Power Key (PB3)__: High → Low → High...

```text
Set PWRKEY (PB3) to High
Wait 30 ms for VBAT to be stable

Set PWRKEY (PB3) to Low
Wait 500 ms

Set PWRKEY (PB3) to High
Status=1
```

And __disable Airplane Mode__ (PH8)...

```text
Set W_DISABLE (PH8) to High
Status=1
```

The LTE Modem should have powered up. But the __LTE Modem Status (PH9)__ stays at High...

```text
(Wait 2 seconds)
Status=1
(Wait 2 seconds)
Status=1
(Wait 2 seconds)
Status=1
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/893c7c914c0594d93fa4f75ce20bc990c4583454/README.md#output-log)

_This doesn't look right..._

Yeah we expect the LTE Modem Status to go __Low after 2.5 seconds__...

![LTE Modem Power](https://lupyuen.github.io/images/lte-power2.png)

[(EG25-G Hardware Design, Page 41)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

_Why did the LTE Modem Status get stuck at High?_

Maybe because of this...

"Currently STATUS pin is connected to PWRKEY and to PB3."

"__STATUS can't be read reliably__ since voltage divider from R1526 and R1517 places the STATUS signal at 0V or 0.5\*Vcc-IO, which is unspecified input value according to A64 datasheet"

"(Vih is 0.7\*Vcc-IO, Vil is 0.3\*Vcc-IO, the range in between is unspecified)" 

[(Source)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Open_Questions_2)

Which means we __can't read the LTE Modem Status__ to check reliably whether the modem is powered up.

_Is there another way to verify whether the LTE Modem is up?_

Let's check the UART Port...

![PinePhone Schematic (Page 15)](https://lupyuen.github.io/images/lte-vddext.png)

[_PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

[(__TXB0104__ is a Voltage Translator)](https://www.ti.com/lit/ds/symlink/txb0104.pdf)

# Test UART with NuttX

_We can't check the LTE Modem Status on NuttX..._

_How else can we verify if the modem is up?_

The LTE Modem to connected to PinePhone (Allwinner A64) at these UART Ports (pic above)...

-   __A64 Port UART3__: RX and TX

-   __A64 Port UART4__: CTS and RTS

-   __A64 Port PB2__: DTR

    (Default 115.2 kbps, up to 921.6 kbps)

Thus we may __check UART3__ to see if the LTE Modem responds to [__AT Commands__](https://lupyuen.github.io/articles/lte#quectel-eg25-g-lte-modem).

[(After 12 seconds from power up)](https://lupyuen.github.io/articles/lte#power-on-lte-modem)

(Do we need UART4 and PB2?)

_UART3 works with NuttX?_

We need to fix the PinePhone UART Driver [__configure the UART Port__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L160-L180).

We'll copy from the NuttX UART Driver for Allwinner A1X: [__a1x_serial.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/a1x/a1x_serial.c#L695-L987)

Like this...

-   [__"Configure UART Port"__](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

-   [__"Test UART3 Port"__](https://github.com/lupyuen/pinephone-nuttx#test-uart3-port)

There's another way to test the LTE Modem: Via USB...

![USB Controller Block Diagram from Allwinner A64 User Manual](https://lupyuen.github.io/images/usb3-title.jpg)

[_USB Controller Block Diagram from Allwinner A64 User Manual_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

# Test USB with NuttX

_We talked about testing the LTE Modem the UART way..._

_What about the USB way?_

Yep the __USB Interface__ should work for testing the LTE Modem...

-   __USB__ ⇆ A64 Port __USB1__ _(USB Serial)_

    (Up to 480 Mbps)

_How's that coming along?_

We fixed the [__NuttX USB EHCI Driver__](https://lupyuen.github.io/articles/usb3) (pic above) to handle USB Interrupts...

-   [__"Enumerate USB Devices on PinePhone"__](https://github.com/lupyuen/pinephone-nuttx-usb#enumerate-usb-devices-on-pinephone)

-   [__"Handle USB Interrupt"__](https://github.com/lupyuen/pinephone-nuttx-usb#handle-usb-interrupt)

But somehow the LTE Modem __isn't triggering any USB Interrupts__ (13 seconds after startup)...

Which __fails the enumeration__ of USB Devices (like the LTE Modem). And we can't connect to the USB Interface of the LTE Modem.

(Maybe something else in the USB Controller needs to be configured or powered up?)

Stay tuned for updates on UART and USB Testing!

[(This crash needs to be fixed when __USB Hub Support__ is enabled)](https://github.com/lupyuen/pinephone-nuttx-usb#ls-crashes-when-usb-hub-support-is-enabled)

![Quectel EG25-G LTE Modem inside PinePhone](https://lupyuen.github.io/images/wayland-sd.jpg)

[_Quectel EG25-G LTE Modem inside PinePhone_](https://wiki.pine64.org/index.php/PinePhone#Modem)

# What's Next

I hope this article was helpful for learning about PinePhone's 4G LTE Modem...

-   What's the __Quectel EG25-G LTE Modem__

-   How it's __connected inside PinePhone__

-   How we make __Phone Calls__ and send __Text Messages__

-   How we __power up__ the LTE Modem

-   __Programming the LTE Modem__ with UART, USB and Apache NuttX RTOS

We'll share more details when the LTE Modem is responding OK to UART and USB on NuttX!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/12i3qzi/nuttx_rtos_for_pinephone_4g_lte_modem/)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=35519549)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lte.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lte.md)

# Notes

1.  There's plenty more inside PinePhone's LTE Modem. Check out these articles...

    [__"Genode: PinePhone Telephony"__](https://genodians.org/ssumpf/2022-05-09-telephony)

    [__"PinePhone Power Management"__](https://wiki.pine64.org/wiki/PinePhone_Power_Management)

    [__"Modem on PinePhone"__](https://xnux.eu/devices/feature/modem-pp.html)

    [__"Audio on PinePhone"__](https://xnux.eu/devices/feature/audio-pp.html)

    [__"EG25-G Reverse Engineering"__](https://xnux.eu/devices/feature/modem-pp-reveng.html)

    [__"OSDev: PinePhone"__](https://wiki.osdev.org/PinePhone)

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

# Appendix: LTE Modem Pins

_What's the purpose of the above LTE Modem pins?_

This section describes the purpose of every LTE Modem pin connected to PinePhone...

## Power Supply

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 22)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| VDD_EXT | 7 | PO | Provide 1.8 V for external circuit

[(__PO__ is Power Output)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

## Power On / Off

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 22)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| PWRKEY | 21 | DI | Turn on / off the module
| RESET_N | 20 | DI | Reset signal of the module

[(__DI__ is Digital Input)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

-   PWRKEY should be pulled down at least 500 ms, then pulled up
    
    [(EG25-G Hardware Design, Page 41)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

-   "Make sure that VBAT is stable before pulling down PWRKEY pin. It is recommended that the time between powering up VBAT and pulling down PWRKEY pin is no less than 30 ms."
    
    [(EG25-G Hardware Design, Page 41)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

-   "The RESET_N pin can be used to reset the module. The module can be reset by driving RESET_N to a low level voltage for 150–460 ms"

    [(EG25-G Hardware Design, Page 42)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

## Status Indication

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 22)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| STATUS | 61 | OD | Indicate the module operating status

[(__OD__ is Open Drain)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

-   When PWRKEY is pulled Low, STATUS goes High for ≥2.5 s, then STATUS goes Low

    [(EG25-G Hardware Design, Page 41)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

-   Note that STATUS can't be read reliably...

    "Currently STATUS pin is connected to PWRKEY and to PB3."

    "__STATUS can't be read reliably__ since voltage divider from R1526 and R1517 places the STATUS signal at 0V or 0.5\*Vcc-IO, which is unspecified input value according to A64 datasheet"

    "(Vih is 0.7\*Vcc-IO, Vil is 0.3\*Vcc-IO, the range in between is unspecified)" 

    [(Source)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Open_Questions_2)

## USB Interface

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 22)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| USB_VBUS | 71 | PI | USB connection detection

[(__PI__ is Power Input)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

## Main UART Interface

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 24)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| RI | 62 | DO | Ring indicator

[(__DO__ is Digital Output)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

-   Voltage Level is 1.8 V

## Other Interface Pins

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 32)...

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| W_DISABLE# | 4 | DI | Airplane mode control
| AP_READY | 2 | DI | Application processor sleep state detection

[(__DI__ is Digital Input)](https://lupyuen.github.io/articles/lte#io-parameters-definition)

-   Voltage Level is 1.8 V

-   "The W_DISABLE# pin is pulled up by default. Driving it to low level will let the module enter airplane mode"

    [(EG25-G Hardware Design, Page 37)](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

## I/O Parameters Definition

From [__EG25-G Hardware Design__](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf) (Page 21)...

| Type | Description
|:-----|:-----------
| AI | Analog Input
| AO | Analog Output
| DI | Digital Input
| DO | Digital Output
| IO | Bidirectional
| OD | Open Drain
| PI | Power Input
| PO | Power Output
