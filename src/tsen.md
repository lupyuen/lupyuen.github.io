# Internal Temperature Sensor on BL602

📝 _14 Oct 2021_

This may surprise most folks... The [__BL602 and BL604 RISC-V SoCs__](https://lupyuen.github.io/articles/pinecone) have an __Internal Temperature Sensor__!

The Internal Temperature Sensor is not documented in the BL602 / BL604 Datasheet. But it's buried deep inside the [__BL602 / BL604 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en).

(Under "Analog-to-Digital Converter")

Today we shall...

1.  __Read the Internal Temperature Sensor__ on BL602 and BL604

1.  __Transmit the temperature__ over LoRaWAN to __The Things Network__ (with CBOR Encoding)

1.  __Chart the temperature__ with __Grafana__ (the open-source visualisation tool)

![Internal Temperature Sensor visualised with Grafana](https://lupyuen.github.io/images/tsen-title.jpg)

The firmware has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (pic below). But it should work on __any BL602 or BL604 Board__: [__Ai-Thinker Ai-WB2__](https://docs.ai-thinker.com/en/wb2), PineCone BL602, Pinenut, DT-BL10, MagicHome BL602, ...

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

# Where's the Internal Temperature Sensor?

The Internal Temperature Sensor is inside the __Analog-to-Digital Converter (ADC)__ on BL602 and BL604...

![Internal Temperature Sensor in ADC](https://lupyuen.github.io/images/tsen-ref3.png)

[(From BL602 / BL604 Reference Manual)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

The Internal Temperature Sensor behaves like an __Analog Input__. Which we call the ADC to measure.

[(More about BL602 ADC)](https://lupyuen.github.io/articles/adc#bl602-adc-in-c)

The steps for reading the Internal Temperature Sensor seem complicated...

![Reading the Internal Temperature Sensor](https://lupyuen.github.io/images/tsen-ref4.png)

[(From BL602 / BL604 Reference Manual)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

But thankfully there's an (undocumented) function in the BL602 IoT SDK that __reads the Internal Temperature Sensor__!

Let's call the function now.

(Internal Temperature Sensors based on ADC are available on many microcontrollers, like [STM32 Blue Pill](https://lupyuen.github.io/articles/connect-stm32-blue-pill-to-esp8266-with-apache-mynewt))

![Reading the Internal Temperature Sensor the Quick Way](https://lupyuen.github.io/images/tsen-code4.png)

# The Quick Way

To read the Internal Temperature Sensor the Quick Way, we call [__bl_tsen_adc_get__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c#L224-L282) from the __ADC Hardware Abstraction Layer (HAL)__: [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L15-L29)

```c
#include <bl_adc.h>  //  For BL602 Internal Temperature Sensor

/// Read BL602 / BL604's Internal Temperature Sensor as Integer
void read_tsen(char *buf, int len, int argc, char **argv) {
  //  Temperature in Celsius
  int16_t temp = 0;

  //  Read the Internal Temperature Sensor as Integer
  int rc = bl_tsen_adc_get(
    &temp,  //  Temperature in Celsius
    1       //  0 to disable logging, 1 to enable logging
  );
  assert(rc == 0);

  //  Show the temperature
  printf("Returned Temperature = %d Celsius\r\n", temp);
}
```

Let's build, flash and run the [__pinedio_tsen__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_tsen) demo firmware...

-   [__"Build and Run Internal Temperature Sensor Firmware"__](https://lupyuen.github.io/articles/tsen?1#appendix-build-and-run-internal-temperature-sensor-firmware)

At the BL602 / BL604 Command Prompt, enter this command...

```bash
read_tsen
```

The first result will look odd...

```text
temperature = -90.932541 Celsius
Returned Temperature = -90 Celsius
```

Running __read_tsen__ again will produce the right result...

```text
temperature = 43.467045 Celsius
Returned Temperature = 43 Celsius
```

## Quick But Inaccurate

We discover __two issues with the Quick Way__ of reading the Internal Temperature Sensor...

1.  First Result is __way too low__...

    ```text
    temperature = -90.932541 Celsius
    Returned Temperature = -90 Celsius
    ```

    (Workaround: Discard the first result returned by __bl_tsen_adc_get__)

1.  According to the internal log, the temperature is a __Floating-Point Number__...

    ```text
    temperature = 43.467045 Celsius
    Returned Temperature = 43 Celsius
    ```

    But the returned value is a __Truncated Integer!__

    (Sorry, no workaround for this)

Yep our Quick Way is also the __Inaccurate Way__!

Let's fix both issues.

![Reading the Internal Temperature Sensor the Quick Way](https://lupyuen.github.io/images/tsen-output3.png)

# The Accurate Way

To read the Internal Temperature Sensor the __Accurate Way__, we copy the [__bl_tsen_adc_get__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c#L224-L282) function and __change two things__...

1.  __Wait a while__ as we initialise the ADC for the first time

    (100 milliseconds)

1.  __Return the temperature as Float__

    (Instead of Integer)

Below is __get_tsen_adc__, our modded function (with all the fixings): [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L47-L109)

```c
#include <bl_adc.h>     //  For BL602 ADC HAL
#include <bl602_adc.h>  //  For BL602 ADC Standard Driver
#include <bl602_glb.h>  //  For BL602 Global Register Standard Driver
#include <FreeRTOS.h>   //  For FreeRTOS
#include <task.h>       //  For vTaskDelay

/// Read the Internal Temperature Sensor as Float. Returns 0 if successful.
/// Based on bl_tsen_adc_get in https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c#L224-L282
static int get_tsen_adc(
  float *temp,      //  Pointer to float to store the temperature
  uint8_t log_flag  //  0 to disable logging, 1 to enable logging
) {
  assert(temp != NULL);
  static uint16_t tsen_offset = 0xFFFF;
  float val = 0.0;

  //  If the offset has not been fetched...
  if (0xFFFF == tsen_offset) {
    //  Define the ADC configuration
    tsen_offset = 0;
    ADC_CFG_Type adcCfg = {
      .v18Sel=ADC_V18_SEL_1P82V,                /*!< ADC 1.8V select */
      .v11Sel=ADC_V11_SEL_1P1V,                 /*!< ADC 1.1V select */
      .clkDiv=ADC_CLK_DIV_32,                   /*!< Clock divider */
      .gain1=ADC_PGA_GAIN_1,                    /*!< PGA gain 1 */
      .gain2=ADC_PGA_GAIN_1,                    /*!< PGA gain 2 */
      .chopMode=ADC_CHOP_MOD_AZ_PGA_ON,         /*!< ADC chop mode select */
      .biasSel=ADC_BIAS_SEL_MAIN_BANDGAP,       /*!< ADC current form main bandgap or aon bandgap */
      .vcm=ADC_PGA_VCM_1V,                      /*!< ADC VCM value */
      .vref=ADC_VREF_2V,                        /*!< ADC voltage reference */
      .inputMode=ADC_INPUT_SINGLE_END,          /*!< ADC input signal type */
      .resWidth=ADC_DATA_WIDTH_16_WITH_256_AVERAGE,  /*!< ADC resolution and oversample rate */
      .offsetCalibEn=0,                         /*!< Offset calibration enable */
      .offsetCalibVal=0,                        /*!< Offset calibration value */
    };
    ADC_FIFO_Cfg_Type adcFifoCfg = {
      .fifoThreshold = ADC_FIFO_THRESHOLD_1,
      .dmaEn = DISABLE,
    };

    //  Enable and reset the ADC
    GLB_Set_ADC_CLK(ENABLE,GLB_ADC_CLK_96M, 7);
    ADC_Disable();
    ADC_Enable();
    ADC_Reset();

    //  Configure the ADC and Internal Temperature Sensor
    ADC_Init(&adcCfg);
    ADC_Channel_Config(ADC_CHAN_TSEN_P, ADC_CHAN_GND, 0);
    ADC_Tsen_Init(ADC_TSEN_MOD_INTERNAL_DIODE);
    ADC_FIFO_Cfg(&adcFifoCfg);

    //  Fetch the offset
    BL_Err_Type rc = ADC_Trim_TSEN(&tsen_offset);
    assert(rc != ERROR);  //  Read efuse data failed

    //  Must wait 100 milliseconds or returned temperature will be negative
    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
  //  Read the temperature based on the offset
  val = TSEN_Get_Temp(tsen_offset);
  if (log_flag) {
    printf("offset = %d\r\n", tsen_offset);
    printf("temperature = %f Celsius\r\n", val);
  }
  //  Return the temperature
  *temp = val;
  return 0;
}
```

Note that __get_tsen_adc__ now returns the temperature as __Float__ (instead of Integer)...

```c
static int get_tsen_adc(
  float *temp,      //  Pointer to float to store the temperature
  uint8_t log_flag  //  0 to disable logging, 1 to enable logging
);
```

And we added a __100-millisecond delay__ when initialising the ADC for the first time...

```c
//  If the offset has not been fetched...
if (0xFFFF == tsen_offset) {
  ...
  //  Must wait 100 milliseconds or 
  //  returned temperature will be negative
  vTaskDelay(100 / portTICK_PERIOD_MS);
```

Let's call __get_tsen_adc__ now.

![Reading the Internal Temperature Sensor the Accurate Way](https://lupyuen.github.io/images/tsen-code5.png)

## Read Temperature as Float

We're ready to read the Internal Temperature Sensor the __Accurate Way__!

The code below looks similar to the earlier code except...

1.  We now call our modded function __get_tsen_adc__

    (Instead of the BL602 ADC HAL)

1.  Which __returns a Float__

    (Instead of Integer)

From [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L31-L45)...

```c
/// Read BL602 / BL604's Internal Temperature Sensor as Float
void read_tsen2(char *buf, int len, int argc, char **argv) {
  //  Temperature in Celsius
  float temp = 0;

  //  Read the Internal Temperature Sensor as Float
  int rc = get_tsen_adc(
    &temp,  //  Temperature in Celsius
    1       //  0 to disable logging, 1 to enable logging
  );
  assert(rc == 0);

  //  Show the temperature
  printf("Returned Temperature = %f Celsius\r\n", temp);
}
```

Let's build, flash and run the [__pinedio_tsen__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_tsen) demo firmware...

-   [__"Build and Run Internal Temperature Sensor Firmware"__](https://lupyuen.github.io/articles/tsen?1#appendix-build-and-run-internal-temperature-sensor-firmware)

At the BL602 / BL604 Command Prompt, enter this command a few times...

```bash
read_tsen2
```

The results look consistent...

```text
offset = 2175
temperature = 44.369923 Celsius
Returned Temperature = 44.369923 Celsius

offset = 2175
temperature = 43.596027 Celsius
Returned Temperature = 43.596027 Celsius

offset = 2175
temperature = 43.596027 Celsius
Returned Temperature = 43.596027 Celsius
```

(No more Sub-Zero Temperatures!)

And the temperature is returned as Float.

(No more Integers!)

![Reading the Internal Temperature Sensor the Accurate Way](https://lupyuen.github.io/images/tsen-output4.png)

# LoRaWAN and The Things Network

Since we have an __Onboard Temperature Sensor__ (though it runs a little hot), let's turn BL602 and BL604 into an __IoT Sensor Device__ for LoRaWAN and The Things Network!

We'll create this LoRaWAN Command for BL602 and BL604...

```bash
las_app_tx_tsen 2 0 4000 10 60
```

Which means...

-   Transmit to __LoRaWAN Port 2__

-   With sensor values __`t`__ (Internal Temperature) and __`l`__ (Light Level: `4000`)

    (Encoded with CBOR)

-   Transmit __`10` times__

-   At intervals of __`60` seconds__

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

[(More about CBOR)](https://lupyuen.github.io/articles/cbor)

[(More about The Things Network)](https://lupyuen.github.io/articles/ttn)

![Transmit internal temperature to LoRaWAN](https://lupyuen.github.io/images/tsen-command2.png)

## LoRaWAN Command

__las_app_tx_tsen__ is defined like so: [pinedio_lorawan/lorawan.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L1059-L1227)

```c
/// Transmit Internal Temperature Sensor Data to LoRaWAN, encoded with CBOR. The command
///   las_app_tx_tsen 2 0 2345 10 60
/// Will transmit the CBOR payload
///   { "t": 1234, "l": 2345 }
/// To port 2, unconfirmed (0), for 10 times, with a 60 second interval.
/// Assuming that the Internal Temperature Sensor returns 12.34 degrees Celsius.
void las_cmd_app_tx_tsen(char *buf0, int len0, int argc, char **argv) {
  //  Get port number
  uint8_t port = parse_ull_bounds(argv[1], 1, 255, &rc);

  //  Get unconfirmed / confirmed packet type
  uint8_t pkt_type = parse_ull_bounds(argv[2], 0, 1, &rc);

  //  Get l value
  uint16_t l = parse_ull_bounds(argv[3], 0, 65535, &rc);

  //  Get count
  uint16_t count = parse_ull_bounds(argv[4], 0, 65535, &rc);

  //  Get interval
  uint16_t interval = parse_ull_bounds(argv[5], 0, 65535, &rc);
```

We begin by fetching the __command-line arguments__.

For each message that we shall transmit...

```c
  //  Repeat count times
  for (int i = 0; i < count; i++) {

    //  Wait for interval seconds
    if (i > 0) { vTaskDelay(interval * 1000 / portTICK_PERIOD_MS); }

    //  Read Internal Temperature Sensor as a Float
    float temp = 0;
    int rc = get_tsen_adc(
      &temp,  //  Temperature in Celsius
      1       //  0 to disable logging, 1 to enable logging
    );
    assert(rc == 0);
```

We __read the Internal Temperature Sensor__ as a Float.

Next we __scale up the temperature 100 times__ and truncate as Integer...

```c
    //  Scale the temperature up 100 times and truncate as integer:
    //  12.34 ºC becomes 1234
    int16_t t = temp * 100;
```

[(Because encoding the temperature as `1234` requires fewer bytes than `12.34`)](https://lupyuen.github.io/articles/cbor#floating-point-numbers)

We encode the temperature (and light level) with CBOR and __transmit as a LoRaWAN message__...

```c
    //  Omitted: Encode into CBOR for { "t": ????, "l": ???? }
    uint8_t output[50];
    ...

    //  Allocate a pbuf
    struct pbuf *om = lora_pkt_alloc(output_len);

    //  Copy the encoded CBOR into the pbuf
    rc = pbuf_copyinto(om, 0, output, output_len);

    //  Send the pbuf
    rc = lora_app_port_send(port, mcps_type, om);
```

Which goes all the way to __The Things Network__! Assuming that we have configured our LoRaWAN settings for The Things Network.

[(CBOR Encoding is explained here)](https://lupyuen.github.io/articles/cbor#encode-sensor-data-with-tinycbor)

[(Sending a LoRaWAN Packet is explained here)](https://lupyuen.github.io/articles/cbor#send-lorawan-packet)

## Run the LoRaWAN Firmware

Let's build, flash and run the updated LoRaWAN Firmware: [__pinedio_lorawan__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan)

-   [__"Build and Run LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen?1#appendix-build-and-run-lorawan-firmware)

At the BL602 / BL604 Command Prompt, enter this command...

```bash
las_app_tx_tsen 2 0 4000 10 60
```

Which means...

-   Transmit to __LoRaWAN Port 2__

-   With sensor values __`t`__ (Internal Temperature) and __`l`__ (Light Level: `4000`)

    (Encoded with CBOR)

-   Transmit __`10` times__

-   At intervals of __`60` seconds__

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

We should see the Internal Temperature transmitted over LoRaWAN every 60 seconds...

```text
temperature = 44.885849 Celsius
Encode CBOR: { t: 4488, l: 4000 }
CBOR Output: 11 bytes
  0xa2 0x61 0x74 0x19 0x11 0x88 0x61 0x6c 0x19 0x0f 0xa0
  ...
temperature = 47.207531 Celsius
Encode CBOR: { t: 4720, l: 4000 }
CBOR Output: 11 bytes
  0xa2 0x61 0x74 0x19 0x12 0x70 0x61 0x6c 0x19 0x0f 0xa0
  ...
```

[(See the complete log)](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan#output-log)

Let's check the transmitted Sensor Data with Grafana and Roblox.

![Visualising The Things Network Sensor Data with Grafana](https://lupyuen.github.io/images/grafana-flow.jpg)

[(Source)](https://lupyuen.github.io/articles/grafana)

# Grafana and Roblox

In an earlier article we have configured __Grafana__ (the open source visualisation tool) to read Sensor Data from __The Things Network__. And chart the Sensor Data in real time...

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

Follow the instructions below to __install and configure Grafana__...

-   [__"Configure Grafana Data Source"__](https://lupyuen.github.io/articles/grafana#configure-grafana-data-source)

Start the Grafana service and run the __las_app_tx_tsen__ command from the previous chapter.

We should see this chart in Grafana after 10 minutes...

![PineDio Stack BL604 Internal Temperature rendered with Grafana](https://lupyuen.github.io/images/tsen-grafana2.png)

(Note that the temperatures have been scaled up 100 times)

## The Fun Way

There's another way to see the Sensor Data (in a fun way): __Roblox__...

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

(Yep the multiplayer 3D world!)

Follow the instructions below to __install and configure Roblox__...

-   [__"Roblox Mirroring In Action"__](https://lupyuen.github.io/articles/roblox#roblox-mirroring-in-action)

We should see the temperature rendered by Roblox as a glowing thing...

![PineDio Stack BL604 Internal Temperature rendered with Roblox](https://lupyuen.github.io/images/tsen-roblox2.png)

And the output log shows our temperature, scaled by 100 times.

(Like `4875` for `48.75` ºC)

[(Sounds rather warm, even for Sunny Singapore. Is it correct? 🤔 Lemme know what's your BL602 / BL604 temperature!)](https://twitter.com/SravanSenthiln1/status/1448485854536613888)

![Storing The Things Network Sensor Data with Prometheus](https://lupyuen.github.io/images/grafana-flow2.jpg)

[(Source)](https://lupyuen.github.io/articles/grafana#store-data-with-prometheus)

# What's Next

Today we have turned BL602 and BL604 into a basic __IoT Sensor Device__ that transmits its Internal Temperature to __LoRaWAN and The Things Network__.

In the next article we shall build a better __IoT Monitoring System__ that stores the __Sensor Data with Prometheus__ and visualises the data in a __Grafana Dashboard__...

-   [__"Monitor IoT Devices in The Things Network with Prometheus and Grafana"__](https://lupyuen.github.io/articles/prometheus)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/q7u64g/internal_temperature_sensor_on_bl602/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/tsen.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tsen.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1447635784228487169)

# Appendix: Build and Run Internal Temperature Sensor Firmware

Here are the steps to build, flash and run the __Internal Temperature Sensor Firmware for BL602 and BL604__...

-   [__bl_iot_sdk/customer_app/pinedio_tsen__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_tsen)

## Build Internal Temperature Sensor Firmware

Download the firmware...

```bash
## Download the master branch of lupyuen's bl_iot_sdk
git clone --recursive --branch master https://github.com/lupyuen/bl_iot_sdk
```

Build the Firmware Binary File `pinedio_tsen.bin`...

```bash
## TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

cd bl_iot_sdk/customer_app/pinedio_tsen
make

## For WSL: Copy the firmware to /mnt/c/blflash, which refers to c:\blflash in Windows
mkdir /mnt/c/blflash
cp build_out/pinedio_tsen.bin /mnt/c/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

## Flash Internal Temperature Sensor Firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `pinedio_tsen.bin` has been copied to the `blflash` folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `pinedio_tsen.bin` to BL602 / BL604 over UART...

```bash
## For Linux:
blflash flash build_out/pinedio_tsen.bin \
    --port /dev/ttyUSB0

## For macOS:
blflash flash build_out/pinedio_tsen.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

## For Windows: Change COM5 to the BL602 / BL604 Serial Port
blflash flash c:\blflash\pinedio_tsen.bin --port COM5
```

(For WSL: Do this under plain old Windows CMD, not WSL, because blflash needs to access the COM port)

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run Internal Temperature Sensor Firmware

Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602 / BL604](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

# Appendix: Build and Run LoRaWAN Firmware

Here are the steps to build, flash and run the __LoRaWAN Firmware for PineDio Stack BL604__...

-   [__bl_iot_sdk/customer_app/pinedio_lorawan__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan)

## Build LoRaWAN Firmware

Download the [__LoRaWAN firmware and driver source code__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan)...

```bash
## Download the master branch of lupyuen's bl_iot_sdk
git clone --recursive --branch master https://github.com/lupyuen/bl_iot_sdk
```

In the `customer_app/pinedio_lorawan` folder, edit [`Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/Makefile) and find this setting...

```text
CFLAGS += -DCONFIG_LORA_NODE_REGION=1
```

Change "`1`" to your LoRa Region...

| Value | Region 
| :---  | :---
| 0 | No region
| 1 | AS band on 923MHz
| 2 | Australian band on 915MHz
| 3 | Chinese band on 470MHz
| 4 | Chinese band on 779MHz
| 5 | European band on 433MHz
| 6 | European band on 868MHz
| 7 | South Korean band on 920MHz
| 8 | India band on 865MHz
| 9 | North American band on 915MHz
| 10 | North American band on 915MHz with a maximum of 16 channels

The __GPIO Pin Numbers__ for LoRa SX1262 are defined in...

```text
components/3rdparty/lora-sx1262/include/sx126x-board.h
```

They have been configured for PineDio Stack. (So no changes needed)

Build the Firmware Binary File `pinedio_lorawan.bin`...

```bash
## TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

cd bl_iot_sdk/customer_app/pinedio_lorawan
make

## For WSL: Copy the firmware to /mnt/c/blflash, which refers to c:\blflash in Windows
mkdir /mnt/c/blflash
cp build_out/pinedio_lorawan.bin /mnt/c/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

## Flash LoRaWAN Firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `pinedio_lorawan.bin` has been copied to the `blflash` folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `pinedio_lorawan.bin` to BL602 / BL604 over UART...

```bash
## For Linux:
blflash flash build_out/pinedio_lorawan.bin \
    --port /dev/ttyUSB0

## For macOS:
blflash flash build_out/pinedio_lorawan.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

## For Windows: Change COM5 to the BL602 / BL604 Serial Port
blflash flash c:\blflash\pinedio_lorawan.bin --port COM5
```

(For WSL: Do this under plain old Windows CMD, not WSL, because blflash needs to access the COM port)

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run LoRaWAN Firmware

Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602 / BL604](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter LoRaWAN Commands

Let's enter the LoRaWAN Commands to join The Things Network and transmit a Data Packet!

1.  Log on to __The Things Network__. Browse to our Device and copy these values...

    __JoinEUI__ (Join Extended Unique Identifier)

    __DevEUI__ (Device Extended Unique Identifier)

    __AppKey__ (Application Key)

    [(Instructions here)](https://lupyuen.github.io/articles/ttn#join-device-to-the-things-network)

1.  In the BL602 / BL604 terminal, press Enter to reveal the command prompt.

1.  First we start the __Background Task__ that will handle LoRa packets...

    Enter this command...

    ```text
    create_task
    ```

    [(`create_task` is explained here)](https://lupyuen.github.io/articles/lora2#event-queue)

1.  Next we initialise the __LoRa SX1262 and LoRaWAN Drivers__...

    ```bash
    init_lorawan
    ```

    [(`init_lorawan` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L175-L181)

1.  Set the __DevEUI__...

    ```bash
    las_wr_dev_eui 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA
    ```

    Change "`0xAB:0xBA:...`" to your __DevEUI__

    (Remember to change the __"`,`"__ delimiter to __"`:`"__)

1.  Set the __JoinEUI__...

    ```bash
    las_wr_app_eui 0x00:0x00:0x00:0x00:0x00:0x00:0x00:0x00
    ```

    Change "`0x00:0x00:...`" to your __JoinEUI__

    (Yep change the __"`,`"__ delimiter to __"`:`"__)

1.  Set the __AppKey__...

    ```bash
    las_wr_app_key 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA
    ```

    Change "`0xAB:0xBA:...`" to your __AppKey__

    (Again change __"`,`"__ to __"`:`"__)
    
1.  We send a request to __join The Things Network__...

    ```bash
    las_join 1
    ```

    "`1`" means try only once.

    [(`las_join` is explained here)](https://lupyuen.github.io/articles/lorawan#join-network-request)

1.  Finally we open an __Application Port__ that will connect to The Things Network...

    ```bash
    las_app_port open 2
    ```

    "`2`" is the Application Port Number

    [(`las_app_port` is explained here)](https://lupyuen.github.io/articles/lorawan#open-lorawan-port)

    [(See the complete log)](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan#output-log)
