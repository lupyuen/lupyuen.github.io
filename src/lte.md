# NuttX RTOS for PinePhone: 4G LTE Modem

📝 _12 Apr 2023_

![(Quectel EG25-G Hardware Design)](https://lupyuen.github.io/images/lte-title.jpg)

[_(Quectel EG25-G Hardware Design)_](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)

TODO

Weeks ago we talked about porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone). And how we might turn it into a __Feature Phone__...

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

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

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

The code looks like this...

https://github.com/lupyuen/pinephone-nuttx-usb/blob/3ceaf44c23b85ec105a0d85cd377f4a55eff5ef5/a64_usbhost.c#L337-L421

[(`pinephone_pmic_usb_init` is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/0216f6968a82a73b67fb48a276b3c0550c47008a/boards/arm64/a64/pinephone/src/pinephone_pmic.c#L294-L340)

TODO: Why does LTE Modem Status change from Low to High, then stay at High? [(See this)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/6fb84655b4ed19af7209817cc01b2a589798620a/README.md#output-log)

Is it because of this...

> "Currently STATUS pin is connected to PWRKEY and to PB3. STATUS can't be read reliably since voltage divider from R1526 and R1517 places the STATUS signal at 0V or 0.5\*Vcc-IO, which is unspecified input value according to A64 datasheet (Vih is 0.7\*Vcc-IO, Vil is 0.3\*Vcc-IO, the range in between is unspecified)." 

[(Source)](https://wiki.pine64.org/wiki/PinePhone_Power_Management#Open_Questions_2)

References:

-   [PinePhone Power Management](https://wiki.pine64.org/wiki/PinePhone_Power_Management)

-   [OSDev PinePhone](https://wiki.osdev.org/PinePhone)

-   [Genode PinePhone Telephony](https://genodians.org/ssumpf/2022-05-09-telephony)

# LTE Modem Pins

TODO

![LTE Modem inside PinePhone](https://lupyuen.github.io/images/lte-title.jpg)

_What's the purpose of the above LTE Modem pins?_

From [Quectel EG25-G Hardware Design](https://wiki.pine64.org/images/2/20/Quectel_EG25-G_Hardware_Design_V1.4.pdf)...

__Power-on/off__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| PWRKEY | 21 | DI | Turn on/off the module | VH = 0.8 V | The output voltage is 0.8V because of the diode drop in the Qualcomm chipset.
| RESET_N | 20 | DI | Reset signal of the module | VIHmax = 2.1 V, VIHmin = 1.3 V, VILmax = 0.5 V | If unused, keep it open.

-   PWRKEY should be pulled down at least 500 ms, then pulled up
    
    (EG25-G HW Design, Page 41)

-   "Make sure that VBAT is stable before pulling down PWRKEY pin. It is recommended that the time between powering up VBAT and pulling down PWRKEY pin is no less than 30 ms."
    
    (EG25-G HW Design, Page 41)

-   "The RESET_N pin can be used to reset the module. The module can be reset by driving RESET_N to a low level voltage for 150–460 ms"

    (EG25-G HW Design, Page 42)

__Other Interface Pins__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| W_DISABLE# | 4 | DI | Airplane mode control | VILmin = -0.3 V, VILmax = 0.6 V, VIHmin = 1.2 V, VIHmax = 2.0 V | 1.8 V power domain. Pull-up by default. At low voltage level, module can enter into airplane mode. If unused, keep it open.
| AP_READY | 2 | DI | Application processor sleep state detection | VILmin = -0.3 V, VILmax = 0.6 V, VIHmin = 1.2 V, VIHmax = 2.0 V | 1.8 V power domain. If unused, keep it open.

-   "The W_DISABLE# pin is pulled up by default. Driving it to low level will let the module enter airplane mode"

    (EG25-G HW Design, Page 37)

__USB Interface__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| USB_VBUS | 71 | PI | USB connection detection | Vmax = 5.25 V, Vmin = 3.0 V, Vnorm = 5.0 V, Typical: 5.0 V | If unused, keep it open.

__Status Indication__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| STATUS | 61 | OD | Indicate the module operating status. | The drive current should be less than 0.9 mA | An external pull-up resistor is required. If unused, keep it open.

-   When PWRKEY is pulled Low, STATUS goes High for ≥2.5 s, then STATUS goes Low

    (EG25-G HW Design, Page 41)

__Main UART Interface__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| RI | 62 | DO | Ring indicator | VOLmax = 0.45 V, VOHmin = 1.35 V | 1.8 V power domain. If unused, keep it open

__Power Supply__

| Pin Name | Pin No. | I/O | Description | DC Characteristics | Comment
|----------|---------|-----|-------------|--------------------|--------
| VDD_EXT | 7 | PO | Provide 1.8 V for external circuit | Vnorm = 1.8 V, IOmax = 50 mA | Power supply for external GPIO’s pull up circuits. If unused, keep it open.

__I/O Parameters Definition__

| Type | Description
|------|------------
| AI | Analog Input
| AO | Analog Output
| DI | Digital Input
| DO | Digital Output
| IO | Bidirectional
| OD | Open Drain
| PI | Power Input
| PO | Power Output

# LTE Modem UART

TODO: LTE Modem UART

-   BB-TX: PD1-UART3_RX

-   BB-RX: PD0-UART3_TX

-   BB-CTS: PD5-UART4_CTS

-   BB-RTS: PD4-UART4_RTS

-   BB-DTR: PB2-DTR

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
