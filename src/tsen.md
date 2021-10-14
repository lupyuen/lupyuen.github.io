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

# The Quick Way

TODO

From [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L15-L29)

```c
#include <bl_adc.h>     //  For BL602 Internal Temperature Sensor

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

![](https://lupyuen.github.io/images/tsen-code4.png)

TODO13

![](https://lupyuen.github.io/images/tsen-output3.png)

# The Accurate Way

TODO

From [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L47-L113)

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

  if (0xFFFF == tsen_offset) {
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

    GLB_Set_ADC_CLK(ENABLE,GLB_ADC_CLK_96M, 7);

    ADC_Disable();
    ADC_Enable();

    ADC_Reset();

    ADC_Init(&adcCfg);
    ADC_Channel_Config(ADC_CHAN_TSEN_P, ADC_CHAN_GND, 0);
    ADC_Tsen_Init(ADC_TSEN_MOD_INTERNAL_DIODE);

    ADC_FIFO_Cfg(&adcFifoCfg);

    if (ADC_Trim_TSEN(&tsen_offset) == ERROR) {
      printf("read efuse data failed\r\n");
    }
    assert(ADC_Trim_TSEN(&tsen_offset) != ERROR);

    //  Must wait 100 milliseconds or returned temperature will be negative
    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
  val = TSEN_Get_Temp(tsen_offset);
  if (log_flag) {
    printf("offset = %d\r\n", tsen_offset);
    printf("temperature = %f Celsius\r\n", val);
  }

  if (temp) {
    *temp = val;
  }
  return 0;
}
```

TODO

From [pinedio_tsen/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/tsen/customer_app/pinedio_tsen/pinedio_tsen/demo.c#L31-L45)

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

![](https://lupyuen.github.io/images/tsen-code5.png)

TODO6

![](https://lupyuen.github.io/images/tsen-code6.png)

TODO14

![](https://lupyuen.github.io/images/tsen-output4.png)

# LoRaWAN and The Things Network

TODO

```bash
las_app_tx_tsen 2 0 4000 10 60
```

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
  int rc = 0;
  //  Validate number of arguments
  if (argc < 6) { printf("Invalid # of arguments\r\n"); goto cmd_app_tx_tsen_err; }

  //  Get port number
  uint8_t port = parse_ull_bounds(argv[1], 1, 255, &rc);
  if (rc != 0) { printf("Invalid port %s. Must be 1 - 255\r\n", argv[1]); return;}

  //  Get unconfirmed / confirmed packet type
  uint8_t pkt_type = parse_ull_bounds(argv[2], 0, 1, &rc);
  if (rc != 0) { printf("Invalid type %s. Must be 0 (unconfirmed) or 1 (confirmed)\r\n", argv[2]); return; }

  //  Get l value
  uint16_t l = parse_ull_bounds(argv[3], 0, 65535, &rc);
  if (rc != 0) { printf("Invalid l value %s. Must be 0 - 65535\r\n", argv[3]); return; }

  //  Get count
  uint16_t count = parse_ull_bounds(argv[4], 0, 65535, &rc);
  if (rc != 0) { printf("Invalid count %s. Must be 0 - 65535\r\n", argv[4]); return; }

  //  Get interval
  uint16_t interval = parse_ull_bounds(argv[5], 0, 65535, &rc);
  if (rc != 0) { printf("Invalid interval %s. Must be 0 - 65535\r\n", argv[5]); return; }

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

    //  Scale the temperature up 100 times and truncate
    int16_t t = temp * 100;
    printf("Encode CBOR: { t: %d, l: %d }\r\n", t, l);

    //  Encode into CBOR for { "t": ????, "l": ???? }
    //  Max output size is 50 bytes (which fits in a LoRa packet)
    uint8_t output[50];

    //  Our CBOR Encoder and Map Encoder
    CborEncoder encoder, mapEncoder;

    //  Init our CBOR Encoder
    cbor_encoder_init(
      &encoder,        //  CBOR Encoder
      output,          //  Output Buffer
      sizeof(output),  //  Output Buffer Size
      0                //  Options
    );

    //  Create a Map Encoder that maps keys to values
    CborError res = cbor_encoder_create_map(
      &encoder,     //  CBOR Encoder
      &mapEncoder,  //  Map Encoder
      2             //  Number of Key-Value Pairs
    );    
    assert(res == CborNoError);

    //  First Key-Value Pair: Map the Key
    res = cbor_encode_text_stringz(
      &mapEncoder,  //  Map Encoder
      "t"           //  Key
    );    
    assert(res == CborNoError);

    //  First Key-Value Pair: Map the Value
    res = cbor_encode_int(
      &mapEncoder,  //  Map Encoder 
      t             //  Value
    );
    assert(res == CborNoError);

    //  Second Key-Value Pair: Map the Key
    res = cbor_encode_text_stringz(
      &mapEncoder,  //  Map Encoder
      "l"           //  Key
    );    
    assert(res == CborNoError);

    //  Second Key-Value Pair: Map the Value
    res = cbor_encode_int(
      &mapEncoder,  //  Map Encoder 
      l             //  Value
    );
    assert(res == CborNoError);

    //  Close the Map Encoder
    res = cbor_encoder_close_container(
      &encoder,    //  CBOR Encoder
      &mapEncoder  //  Map Encoder
    );
    assert(res == CborNoError);

    //  How many bytes were encoded
    size_t output_len = cbor_encoder_get_buffer_size(
      &encoder,  //  CBOR Encoder
      output     //  Output Buffer
    );
    printf("CBOR Output: %d bytes\r\n  ", output_len);

    //  Dump the encoded CBOR output (11 bytes):
    //  0xa2 0x61 0x74 0x19 0x04 0xd2 0x61 0x6c 0x19 0x09 0x29
    for (int i = 0; i < output_len; i++) {
      printf("0x%02x ", output[i]);
    }    
    printf("\r\n");

    //  Validate the output size
    if (lora_app_mtu() < output_len) {
      printf("Can send at max %d bytes\r\n", lora_app_mtu());
      return;
    }

    //  Attempt to allocate a pbuf
    struct pbuf *om = lora_pkt_alloc(output_len);
    if (!om) {
      printf("Unable to allocate pbuf\r\n");
      return;
    }

    //  Set unconfirmed / confirmed packet type
    Mcps_t mcps_type;
    if (pkt_type == 0) {
      mcps_type = MCPS_UNCONFIRMED;
    } else {
      mcps_type = MCPS_CONFIRMED;
    }

    //  Copy the encoded CBOR into the pbuf
    rc = pbuf_copyinto(om, 0, output, output_len);
    assert(rc == 0);

    //  Send the pbuf
    rc = lora_app_port_send(port, mcps_type, om);
    if (rc) {
      printf("Failed to send to port %u err=%d\r\n", port, rc);
      pbuf_free(om);
    } else {
      printf("Packet sent on port %u\r\n", port);
    }        
  }
```

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
