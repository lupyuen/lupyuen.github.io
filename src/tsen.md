# Internal Temperature Sensor on BL602

📝 _20 Oct 2021_

This may surprise most folks... The BL602 and BL604 RISC-V SoCs have an __Internal Temperature Sensor__!

The Internal Temperature Sensor is not documented in the BL602 / BL604 Datasheet. But it's buried deep inside the [__BL602 / BL604 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en).

(Under "Analog-to-Digital Converter")

Today we shall...

1.  __Read the Internal Temperature Sensor__ on BL602 and BL604

1.  __Transmit the temperature__ over LoRaWAN to __The Things Network__ (with CBOR Encoding)

1.  __Chart the temperature__ with __Grafana__ (the open-source visualisation tool)

![Internal Temperature Sensor visualised with Grafana](https://lupyuen.github.io/images/tsen-title.jpg)

The firmware has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio), but it should work on __any BL602 or BL604 Board__: PineCone BL602, Pinenut, DT-BL10, MagicHome BL602, ...

# Where's the Internal Temperature Sensor?

The Internal Temperature Sensor is inside the __Analog-to-Digital Converter (ADC)__ on BL602 and BL604...

![Internal Temperatuer Sensor in ADC](https://lupyuen.github.io/images/tsen-ref3.png)

[(From BL602 / BL604 Reference Manual)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

The Internal Temperature Sensor behaves like an __Analog Input__. Which we call the ADC to measure.

[(More about BL602 ADC)](https://lupyuen.github.io/articles/adc#bl602-adc-in-c)

The steps for reading the Internal Temperature Sensor seem complicated...

![Reading the Internal Temperatuer Sensor](https://lupyuen.github.io/images/tsen-ref4.png)

[(From BL602 / BL604 Reference Manual)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

But thankfully there's an (undocumented) function in the BL602 IoT SDK that __reads the Internal Temperature Sensor__!

Let's call the function now.

(Internal Temperature Sensors based on ADC are available on many microcontrollers, like [STM32 Blue Pill](https://lupyuen.github.io/articles/connect-stm32-blue-pill-to-esp8266-with-apache-mynewt))

![Reading the Internal Temperatue Sensor the Quick Way](https://lupyuen.github.io/images/tsen-code4.png)

# The Quick Way

To read the Internal Temperature Sensor the Quick Way, we call [__bl_tsen_adc_get__](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/components/hal_drv/bl602_hal/bl_adc.c#L224-L282) from the __ADC Hardware Abstraction Layer (HAL)__: [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L15-L29)

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

Let's build, flash and run the demo firmware...

-   [__customer_app/pinedio_tsen__](https://github.com/lupyuen/bl_iot_sdk/tree/tsen/customer_app/pinedio_tsen)

Enter the command...

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

![Reading the Internal Temperatue Sensor the Quick Way](https://lupyuen.github.io/images/tsen-output3.png)

# The Accurate Way

To read the Internal Temperature Sensor the __Accurate Way__, we copy the [__bl_tsen_adc_get__](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/components/hal_drv/bl602_hal/bl_adc.c#L224-L282) function and __change two things__...

1.  __Wait a while__ as we initialise the ADC for the first time

    (100 milliseconds)

1.  __Return the temperature as Float__

    (Instead of Integer)

Below is __get_tsen_adc__, our modded function (with all the fixings): [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L47-L109)

```c
#include <bl_adc.h>     //  For BL602 ADC HAL
#include <bl602_adc.h>  //  For BL602 ADC Standard Driver
#include <bl602_glb.h>  //  For BL602 Global Register Standard Driver
#include <FreeRTOS.h>   //  For FreeRTOS
#include <task.h>       //  For vTaskDelay

/// Read the Internal Temperature Sensor as Float. Returns 0 if successful.
/// Based on bl_tsen_adc_get in https://github.com/lupyuen/bl_iot_sdk/blob/tsen/components/hal_drv/bl602_hal/bl_adc.c#L224-L282
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

![Reading the Internal Temperatue Sensor the Accurate Way](https://lupyuen.github.io/images/tsen-code5.png)

## Read Temperature as Float

We're ready to read the Internal Temperature Sensor the __Accurate Way__!

The code below looks similar to the earlier code except...

1.  We now call our modded function __get_tsen_adc__

    (Instead of the BL602 ADC HAL)

1.  Which __returns a Float__

    (Instead of Integer)

From [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L31-L45)...

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

Let's build, flash and run the demo firmware...

-   [__customer_app/pinedio_tsen__](https://github.com/lupyuen/bl_iot_sdk/tree/tsen/customer_app/pinedio_tsen)

Enter this command a few times...

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

![Reading the Internal Temperatue Sensor the Accurate Way](https://lupyuen.github.io/images/tsen-output4.png)

# LoRaWAN and The Things Network

TODO

```bash
las_app_tx_tsen 2 0 4000 10 60
```

This means...

-   Transmit to __LoRaWAN Port 2__

-   That contains the values __`t`__ (Internal Temperature) and __`l=4000`__ (Light Level)

    (Encoded with CBOR)

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

-   Transmit __`10` times__

-   At intervals of __`60` seconds__

TODO

![](https://lupyuen.github.io/images/tsen-command2.png)

TODO

From [pinedio_lorawan/lorawan.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L1059-L1227)

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

TODO

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

TODO

```c
    //  Scale the temperature up 100 times and truncate as integer:
    //  12.34 ºC becomes 1234
    int16_t t = temp * 100;

    //  Omitted: Encode into CBOR for { "t": ????, "l": ???? }
    uint8_t output[50];
    ...
```

TODO

```c
    //  Allocate a pbuf
    struct pbuf *om = lora_pkt_alloc(output_len);

    //  Copy the encoded CBOR into the pbuf
    rc = pbuf_copyinto(om, 0, output, output_len);

    //  Send the pbuf
    rc = lora_app_port_send(port, mcps_type, om);
```

Let's build, flash and run the updated LoRaWAN Firmware...

-   [__customer_app/pinedio_lorawan__](https://github.com/lupyuen/bl_iot_sdk/tree/tsen/customer_app/pinedio_lorawan)

Enter this command...

```bash
las_app_tx_tsen 2 0 4000 10 60
```

This means...

-   Transmit to __LoRaWAN Port 2__

-   That contains the values __`t`__ (Internal Temperature) and __`l=4000`__ (Light Level)

    (Encoded with CBOR)

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

-   Transmit __`10` times__

-   At intervals of __`60` seconds__

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

[(See the complete log)](https://github.com/lupyuen/bl_iot_sdk/tree/tsen/customer_app/pinedio_lorawan#output-log)

# Grafana and Roblox

TODO

![](https://lupyuen.github.io/images/tsen-grafana2.png)

TODO

![](https://lupyuen.github.io/images/tsen-roblox2.png)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/tsen.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tsen.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1447635784228487169)
