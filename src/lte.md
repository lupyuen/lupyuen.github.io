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

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the Baseband Processor talks to PinePhone (Allwinner A64) over the following __Data Interfaces__...

-   __USB__ ⇆ A64 Port __USB1__ _(USB Serial)_

    For AT Commands and GPS Output. (Up to 480 Mbps)

-   __SIM__ ⇆ PinePhone 4G SIM Card

    For connecting to the 4G LTE Mobile Network.

-   __PCM__ ⇆ A64 Port __PCM0__

    Digital Audio Stream for 4G Voice Calls.

-   __UART__ ⇆ A64 Port __UART3__ _(RX / TX)_, __UART4__ _(CTS / RTS)_

    Simpler, alternative interface for AT Commands.
    
    (Default 115.2 kbps, up to 921.6 kbps)

UART is slower than USB, so we should probably use USB instead of UART.

(Unless we're building a simple Feature Phone without GPS)

PinePhone controls the LTE Modem with a bunch of pins...

![Control Pins for LTE Modem](https://lupyuen.github.io/images/lte-title3.jpg)

# Control Pins for LTE Modem

_PinePhone's LTE Modem is controlled only by AT Commands?_

There's more! According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the LTE Modem is also controlled by the following GPIO Pins...

-   __Baseband Power__ ← A64 Port __PL7__

    Supplies power to LTE Modem.

    (Also connected to Battery Power VBAT and Power Management DCDC1)

-   __Power Key__ ← A64 Port __PB3__

    Power up the LTE Modem.

    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

-   __Reset__ ← A64 Port __PC4__

    Reset the LTE Modem.

We'll control the above GPIO Pins to __power up the LTE Modem__ at startup.

(More in the next section)

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

![LTE Modem Power](https://lupyuen.github.io/images/lte-title1.jpg)

# LTE Modem Power

TODO

-   __RF Power__ ← A64 Port __PL7__

    Supplies power to the RF Transceiver.

    (Also connected to Battery Power VBAT and Power Management DCDC1)

-   __Baseband Power__ ← A64 Port __PL7__

    Supplies power to LTE Modem.

    (Also connected to Battery Power VBAT and Power Management DCDC1)

TODO: Hardware switch

![LTE Modem Power](https://lupyuen.github.io/images/lte-power.png)

TODO

-   __Power Key__ ← A64 Port __PB3__

    Power up the LTE Modem.
    
    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

-   __Reset__ ← A64 Port __PC4__

    Reset the LTE Modem.

    [(See this)](https://lupyuen.github.io/articles/lte#power-on--off)

-   __Status__ → A64 Port __PH9__

    Read the Modem Status.

    [(See this)](https://lupyuen.github.io/articles/lte#status-indication)

TODO

![LTE Modem Power Output](https://lupyuen.github.io/images/lte-title2.jpg)

# Power Output

_Wait there's a Power Output for the LTE Modem?_

TODO

-   __Power Output__ → PinePhone __VDD_EXT__

    Power Output from LTE Modem to PinePhone.

    [(See this)](https://lupyuen.github.io/articles/lte#power-supply)

TODO: VDD_EXT is super confusing

![LTE Modem Power Output](https://lupyuen.github.io/images/lte-vddext.png)

TODO

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

# Power On LTE Modem

TODO

_How to power up PinePhone's LTE Modem?_

According to PinePhone Schematic Page 15, the LTE Modem is connected to...

-   Power DCDC1: From PMIC, 3.3V [(See this)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Current_Assignments)

-   Power VBAT: PL7 (4G-PWR-BAT) [(See this)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Current_Assignments)

-   Power VDD_EXT: From LTE Modem (EG25-G HW Design Page 22)

-   Reset: BB-RESET (RESET_N) -> PC4-RESET-4G

-   Power Key: BB-PWRKEY (PWRKEY) -> PB3-PWRKEY-4G

-   Disable: BB-DISABLE (W_DISABLE#) -> PH8-DISABLE-4G

-   Status: PH9-STATUS

-   Ring Indicator: PMIC ALDO2  1.8V / PL6 (RI) [(See this)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Current_Assignments)

-   AP Ready: BB-AP-READY (AP_READY) -> PH7-AP-READY

(LTE Modem Pins are explained in the next section)

So to power up PinePhone's LTE Modem, we need to...

1.  Program PMIC to output DCDC1 at 3.3V

1.  Set PL7 to High to Power On LTE Modem (4G-PWR-BAT)

1.  Set PC4 to High to Deassert LTE Modem Reset (BB-RESET / RESET_N)

1.  Wait 30 ms for VBAT to be stable

1.  Set PB3 to Power On LTE Modem (BB-PWRKEY / PWRKEY). PWRKEY should be pulled down at least 500 ms, then pulled up.

1.  Set PH8 to High to Enable LTE Modem and Disable Airplane Mode (BB-DISABLE / W_DISABLE#)

1.  Read PH9 to check LTE Modem Status

1.  In Future: Read PL6 to handle Ring Indicator / [Unsolicited Result Code](https://embeddedfreak.wordpress.com/2008/08/19/handling-urc-unsolicited-result-code-in-hayes-at-command/)

1.  In Future: Set PH7 to High or Low for Sleep State

To do this in NuttX, our code looks like this: [a64_usbhost.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/3ceaf44c23b85ec105a0d85cd377f4a55eff5ef5/a64_usbhost.c#L337-L421)

```c
// Read PH9 to check LTE Modem Status
#define STATUS (PIO_INPUT | PIO_PORT_PIOH | PIO_PIN9)
ret = a64_pio_config(STATUS);
DEBUGASSERT(ret == OK);
_info("Status=%d\n", a64_pio_read(STATUS));

// Power on DCDC1
int pinephone_pmic_usb_init(void);
ret = pinephone_pmic_usb_init();
DEBUGASSERT(ret == OK);
_info("Status=%d\n", a64_pio_read(STATUS));

// Wait 1000 ms
_info("Wait 1000 ms\n");
up_mdelay(1000);
_info("Status=%d\n", a64_pio_read(STATUS));

// Set PL7 to High to Power On LTE Modem (4G-PWR-BAT)

#define P_OUTPUT (PIO_OUTPUT | PIO_PULL_NONE | PIO_DRIVE_MEDLOW | \
                PIO_INT_NONE | PIO_OUTPUT_SET)
#define PWR_BAT (P_OUTPUT | PIO_PORT_PIOL | PIO_PIN7)
_info("Configure PWR_BAT (PL7) for Output\n");
ret = a64_pio_config(PWR_BAT);
DEBUGASSERT(ret >= 0);

_info("Set PWR_BAT (PL7) to High\n");
a64_pio_write(PWR_BAT, true);
_info("Status=%d\n", a64_pio_read(STATUS));

// Wait 1000 ms
_info("Wait 1000 ms\n");
up_mdelay(1000);
_info("Status=%d\n", a64_pio_read(STATUS));

// Set PC4 to High to Deassert LTE Modem Reset (BB-RESET / RESET_N)

#define RESET_N (P_OUTPUT | PIO_PORT_PIOC | PIO_PIN4)
_info("Configure RESET_N (PC4) for Output\n");
ret = a64_pio_config(RESET_N);
DEBUGASSERT(ret >= 0);

_info("Set RESET_N (PC4) to High\n");
a64_pio_write(RESET_N, true);
_info("Status=%d\n", a64_pio_read(STATUS));

// Wait 30 ms for VBAT to be stable
_info("Wait 30 ms for VBAT to be stable\n");
up_mdelay(30);
_info("Status=%d\n", a64_pio_read(STATUS));

// Set PB3 to Power On LTE Modem (BB-PWRKEY / PWRKEY).
// PWRKEY should be pulled down at least 500 ms, then pulled up.

#define PWRKEY (P_OUTPUT | PIO_PORT_PIOB | PIO_PIN3)
_info("Configure PWRKEY (PB3) for Output\n");
ret = a64_pio_config(PWRKEY);
DEBUGASSERT(ret >= 0);

_info("Set PWRKEY (PB3) to Low\n");
a64_pio_write(PWRKEY, false);
_info("Status=%d\n", a64_pio_read(STATUS));

_info("Wait 500 ms\n");
up_mdelay(500);
_info("Status=%d\n", a64_pio_read(STATUS));

_info("Set PWRKEY (PB3) to High\n");
a64_pio_write(PWRKEY, true);
_info("Status=%d\n", a64_pio_read(STATUS));

// Set PH8 to High to Enable LTE Modem and Disable Airplane Mode (BB-DISABLE / W_DISABLE#)

#define W_DISABLE (P_OUTPUT | PIO_PORT_PIOH | PIO_PIN8)
_info("Configure W_DISABLE (PH8) for Output\n");
ret = a64_pio_config(W_DISABLE);
DEBUGASSERT(ret >= 0);

_info("Set W_DISABLE (PH8) to High\n");
a64_pio_write(W_DISABLE, true);
_info("Status=%d\n", a64_pio_read(STATUS));

// TODO: Read PL6 to handle Ring Indicator / [Unsolicited Result Code](https://embeddedfreak.wordpress.com/2008/08/19/handling-urc-unsolicited-result-code-in-hayes-at-command/)

// TODO: Set PH7 to High or Low for Sleep State
```

[(`pinephone_pmic_usb_init` is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/0216f6968a82a73b67fb48a276b3c0550c47008a/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L294-L340)

TODO: Why does LTE Modem Status change from Low to High, then stay at High? [(See this)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/6fb84655b4ed19af7209817cc01b2a589798620a/README.md#output-log)

Is it because of this...

"Currently STATUS pin is connected to PWRKEY and to PB3. STATUS can't be read reliably since voltage divider from R1526 and R1517 places the STATUS signal at 0V or 0.5\*Vcc-IO, which is unspecified input value according to A64 datasheet (Vih is 0.7\*Vcc-IO, Vil is 0.3\*Vcc-IO, the range in between is unspecified)." 

[(Source)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Open_Questions_2)

References:

-   [PinePhone Power Management](https://wiki.pine64.org/wiki/PinePhone_Power_Management)

-   [OSDev PinePhone](https://wiki.osdev.org/PinePhone)

-   [Genode PinePhone Telephony](https://genodians.org/ssumpf/2022-05-09-telephony)

# LTE Modem UART

TODO: LTE Modem UART

-   BB-TX: PD1-UART3_RX

-   BB-RX: PD0-UART3_TX

-   BB-CTS: PD5-UART4_CTS

-   BB-RTS: PD4-UART4_RTS

-   BB-DTR: PB2-DTR

[Modem on PinePhone](https://xnux.eu/devices/feature/modem-pp.html)

[Audio on PinePhone](https://xnux.eu/devices/feature/audio-pp.html)

[EG25-G reverse engineering](https://xnux.eu/devices/feature/modem-pp-reveng.html)

![Quectel EG25-G LTE Modem inside PinePhone](https://lupyuen.github.io/images/wayland-sd.jpg)

[_Quectel EG25-G LTE Modem inside PinePhone_](https://wiki.pine64.org/index.php/PinePhone#Modem)

# What's Next

TODO

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lte.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lte.md)

# Appendix: LTE Modem Pins

TODO

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

_What's the purpose of the above LTE Modem pins?_

From [Quectel EG25-G Hardware Design](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)...

## Power Supply

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| VDD_EXT | 7 | PO | Provide 1.8 V for external circuit

## Power On / Off

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| PWRKEY | 21 | DI | Turn on / off the module
| RESET_N | 20 | DI | Reset signal of the module

-   PWRKEY should be pulled down at least 500 ms, then pulled up
    
    (EG25-G HW Design, Page 41)

-   "Make sure that VBAT is stable before pulling down PWRKEY pin. It is recommended that the time between powering up VBAT and pulling down PWRKEY pin is no less than 30 ms."
    
    (EG25-G HW Design, Page 41)

-   "The RESET_N pin can be used to reset the module. The module can be reset by driving RESET_N to a low level voltage for 150–460 ms"

    (EG25-G HW Design, Page 42)

## Status Indication

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| STATUS | 61 | OD | Indicate the module operating status

-   When PWRKEY is pulled Low, STATUS goes High for ≥2.5 s, then STATUS goes Low

    (EG25-G HW Design, Page 41)

## USB Interface

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| USB_VBUS | 71 | PI | USB connection detection

## Main UART Interface

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| RI | 62 | DO | Ring indicator

## Other Interface Pins

TODO

| Pin Name | Pin No. | I/O | Description
|:---------|:-------:|:---:|:-----------
| W_DISABLE# | 4 | DI | Airplane mode control
| AP_READY | 2 | DI | Application processor sleep state detection

-   "The W_DISABLE# pin is pulled up by default. Driving it to low level will let the module enter airplane mode"

    (EG25-G HW Design, Page 37)

## I/O Parameters Definition

TODO

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
