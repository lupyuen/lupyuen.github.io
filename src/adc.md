# Rust on RISC-V BL602: Is It Sunny?

📝 _8 Aug 2021_

Today we shall magically transform [__any RISC-V BL602 Board__](https://lupyuen.github.io/articles/pinecone) into a __Light Sensor!__

We'll code this firmware in C, then __port it to Rust.__

(By calling the [__Rust Wrapper for BL602 IoT SDK__](https://crates.io/crates/bl602-sdk))

_Wait... Do all BL602 Boards have an onboard Light Sensor?_

Nope, all we need is a __BL602 Board with an LED__!

Reading the LED with BL602's __Analog-to-Digital Converter (ADC)__ will turn it into a simple, improvised Light Sensor.

_Amazing! Will this work with any BL602 Board?_

I tested this with [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and its onboard LED.

It will probably work with any BL602 / BL604 Board with an __onboard or external LED:__ PineDio Stack, Pinenut, DT-BL10, MagicHome BL602, ...

_Will our Light Sensor detect any kind of light?_

Our LED-turned-Light-Sensor works best for __detecting sunlight__... We'll learn why in a while.

(Yep It's Always Sunny in Singapore ... So this Sunlight Sensor won't be so useful in Singapore 😂)

![Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon](https://lupyuen.github.io/images/adc-title.jpg)

_Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon_

# BL602 ADC in C

On PineCone BL602, there's a __Blue LED__ connected on __GPIO Pin Number 11__...

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

[(From PineCone RGB LED Schematic)](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

For light sensing, we shall __read the voltage__ from this LED GPIO with BL602's Analog-to-Digital Converter (ADC).

(Because LEDs will produce a current when exposed to light. [See this](https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227))

Let's study the __C Firmware for BL602 ADC__: [`sdk_app_adc2`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/)

We shall...

1.  __Initialise the ADC Channel__ for the LED GPIO

1.  __Compute the average value__ of the ADC Samples that have been read

## Definitions

We start by defining the __GPIO Pin Number__ that will be read via ADC: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L13-L31)

```c
/// GPIO Pin Number that will be configured as ADC Input.
/// PineCone Blue LED is connected on BL602 GPIO 11.
/// PineCone Green LED is connected on BL602 GPIO 14.
/// Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
/// TODO: Change the GPIO Pin Number for your BL602 board
#define ADC_GPIO 11
```

__Not all GPIOs__ are supported by BL602's ADC!

According to the BL602 Reference Manual, only the following GPIOs are __supported for ADC__: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15

![ADC GPIO Pin Numbers](https://lupyuen.github.io/images/adc-pins.png)

(Look at the __Analog__ column)

Next we define the __ADC Frequency__. We shall read 10,000 ADC Samples every second...

```c
/// We set the ADC Frequency to 10 kHz according to <https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227>
/// This is 10,000 samples per second.
#define ADC_FREQUENCY 10000  //  Hz
```

For computing the average, we shall remember the __last 1,000 ADC Samples read__...

```c
/// We shall read 1,000 ADC samples, which will take 0.1 seconds
#define ADC_SAMPLES 1000
```

Finally we set the __ADC Gain__ to increase the sensitivity of the ADC...

```c
/// Set ADC Gain to Level 1 to increase the ADC sensitivity.
/// To disable ADC Gain, set `ADC_GAIN1` and `ADC_GAIN2` to `ADC_PGA_GAIN_NONE`.
/// See <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_adc.h#L133-L144>
#define ADC_GAIN1 ADC_PGA_GAIN_1
#define ADC_GAIN2 ADC_PGA_GAIN_1
```

More about ADC Gain in a while.

## Initialise the ADC Channel

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L36-L77)

```c
/// Command to init the ADC Channel and start reading the ADC Samples.
/// Based on `hal_adc_init` in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_adc.c#L50-L102>
void init_adc(char *buf, int len, int argc, char **argv) {
    //  Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
    assert(ADC_GPIO==4 || ADC_GPIO==5 || ADC_GPIO==6 || ADC_GPIO==9 || ADC_GPIO==10 || ADC_GPIO==11 || ADC_GPIO==12 || ADC_GPIO==13 || ADC_GPIO==14 || ADC_GPIO==15);

    //  For Single-Channel Conversion Mode, frequency must be between 500 and 16,000 Hz
    assert(ADC_FREQUENCY >= 500 && ADC_FREQUENCY <= 16000);

    //  Init the ADC Frequency for Single-Channel Conversion Mode
    int rc = bl_adc_freq_init(1, ADC_FREQUENCY);
    assert(rc == 0);
```

TODO

```c
    //  Init the ADC GPIO for Single-Channel Conversion Mode
    rc = bl_adc_init(1, ADC_GPIO);
    assert(rc == 0);
```

TODO

```c
    //  Enable ADC Gain to increase the ADC sensitivity
    rc = set_adc_gain(ADC_GAIN1, ADC_GAIN2);
    assert(rc == 0);
```

TODO

```c
    //  Init DMA for the ADC Channel for Single-Channel Conversion Mode
    rc = bl_adc_dma_init(1, ADC_SAMPLES);
    assert(rc == 0);
```

TODO

```c
    //  Configure the GPIO Pin as ADC Input, no pullup, no pulldown
    rc = bl_adc_gpio_init(ADC_GPIO);
    assert(rc == 0);
```

TODO

```c
    //  Get the ADC Channel Number for the GPIO Pin
    int channel = bl_adc_get_channel_by_gpio(ADC_GPIO);

    //  Get the DMA Context for the ADC Channel
    adc_ctx_t *ctx = bl_dma_find_ctx_by_channel(ADC_DMA_CHANNEL);
    assert(ctx != NULL);
```

TODO

```c
    //  Indicate that the GPIO has been configured for ADC
    ctx->chan_init_table |= (1 << channel);
```

TODO

```c
    //  Start reading the ADC via DMA
    bl_adc_start();
}
```

## Read the ADC Channel

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L79-L116)

```c
/// Command to compute the average value of the ADC Samples that have just been read.
/// Based on `hal_adc_get_data` in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_adc.c#L142-L179>
void read_adc(char *buf, int len, int argc, char **argv) {
    //  Static array that will store 1,000 ADC Samples
    static uint32_t adc_data[ADC_SAMPLES];

    //  Get the ADC Channel Number for the GPIO Pin
    int channel = bl_adc_get_channel_by_gpio(ADC_GPIO);
    
    //  Get the DMA Context for the ADC Channel
    adc_ctx_t *ctx = bl_dma_find_ctx_by_channel(ADC_DMA_CHANNEL);
    assert(ctx != NULL);

    //  Verify that the GPIO has been configured for ADC
    assert(((1 << channel) & ctx->chan_init_table) != 0);

    //  If ADC Sampling is not finished, try again later    
    if (ctx->channel_data == NULL) {
        printf("ADC Sampling not finished\r\n");
        return;
    }

    //  Copy the read ADC Samples to the static array
    memcpy(
        (uint8_t*) adc_data,             //  Destination
        (uint8_t*) (ctx->channel_data),  //  Source
        sizeof(adc_data)                 //  Size
    );  

    //  Compute the average value of the ADC Samples
    uint32_t sum = 0;
    for (int i = 0; i < ADC_SAMPLES; i++) {
        //  Scale up the ADC Sample to the range 0 to 3199
        uint32_t scaled = ((adc_data[i] & 0xffff) * 3200) >> 16;
        sum += scaled;
    }
    printf("Average: %lu\r\n", (sum / ADC_SAMPLES));
}
```

## Run the C Firmware

TODO

```text
# init_adc

[In darkness]

# read_adc
Average: 1416

# read_adc
Average: 1416

# read_adc
Average: 1416

[In sunlight]

# read_adc
Average: 1408

# read_adc
Average: 1408

# read_adc
Average: 1408

[In darkness]

# read_adc
Average: 1417

# read_adc
Average: 1416

# read_adc
Average: 1416
```

![](https://lupyuen.github.io/images/adc-demo.png)

## Set the ADC Gain

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L118-L146)

```c
/// Enable ADC Gain to increase the ADC sensitivity.
/// Based on ADC_Init in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_adc.c#L152-L230>
static int set_adc_gain(uint32_t gain1, uint32_t gain2) {
    //  Read the ADC Configuration Hardware Register
    uint32_t reg = BL_RD_REG(AON_BASE, AON_GPADC_REG_CONFIG2);

    //  Set the ADC Gain
    reg = BL_SET_REG_BITS_VAL(reg, AON_GPADC_PGA1_GAIN, gain1);
    reg = BL_SET_REG_BITS_VAL(reg, AON_GPADC_PGA2_GAIN, gain2);

    //  Set the ADC Chop Mode
    if (gain1 != ADC_PGA_GAIN_NONE || gain2 != ADC_PGA_GAIN_NONE) {
        reg = BL_SET_REG_BITS_VAL(reg, AON_GPADC_CHOP_MODE, 2);
    } else {
        reg = BL_SET_REG_BITS_VAL(reg, AON_GPADC_CHOP_MODE, 1);        
    }

    //  Enable the ADC PGA
    reg = BL_CLR_REG_BIT(reg, AON_GPADC_PGA_VCMI_EN);
    if (gain1 != ADC_PGA_GAIN_NONE || gain2 != ADC_PGA_GAIN_NONE) {
        reg = BL_SET_REG_BIT(reg, AON_GPADC_PGA_EN);
    } else {
        reg = BL_CLR_REG_BIT(reg, AON_GPADC_PGA_EN);
    }

    //  Update the ADC Configuration Hardware Register
    BL_WR_REG(AON_BASE, AON_GPADC_REG_CONFIG2, reg);
    return 0;
}
```

# BL602 ADC in Rust

TODO

# Build the BL602 Rust Firmware

TODO

![](https://lupyuen.github.io/images/adc-build.png)

# Flash the BL602 Rust Firmware

TODO

# Run the BL602 Rust Firmware

TODO

![](https://lupyuen.github.io/images/adc-demo2.png)

# Why Sunlight?

TODO

# Rust Wrapper for BL602 IoT SDK

TODO

# Call C Functions from Rust

TODO

# Convert C Pointers to Rust

TODO

![](https://lupyuen.github.io/images/adc-cast.png)

![Testing the improvised Light Sensor on PineCone BL602 with Pinebook Pro](https://lupyuen.github.io/images/adc-pinebook.jpg)

_Testing the improvised Light Sensor on PineCone BL602 with Pinebook Pro_

# What's Next

Many Thanks to my [GitHub Sponsors](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/o4u9e7/machine_learning_on_riscv_bl602_with_tensorflow/)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/adc.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/adc.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread on Rust Wrapper for BL602 IoT SDK](https://twitter.com/MisterTechBlog/status/1416608940876435462)

    And [this Twitter Thread on BL602 ADC](https://twitter.com/MisterTechBlog/status/1418025678251773954)

1.  ADC High Level HAL

    TODO

    ![BL602 ADC High Level HAL](https://lupyuen.github.io/images/adc-highlevel.png)

![Testing the improvised Light Sensor on PineCone BL602](https://lupyuen.github.io/images/adc-title2.jpg)

TODO1

![](https://lupyuen.github.io/images/adc-average.png)

TODO2

![](https://lupyuen.github.io/images/adc-bindgen.png)

TODO4

![](https://lupyuen.github.io/images/adc-compare.png)

TODO6

![](https://lupyuen.github.io/images/adc-copy.png)

TODO7

![](https://lupyuen.github.io/images/adc-doc.png)

TODO10

![](https://lupyuen.github.io/images/adc-doc2.png)

TODO11

![](https://lupyuen.github.io/images/adc-doc3.jpg)

TODO12

![](https://lupyuen.github.io/images/adc-doc4.jpg)

TODO13

![](https://lupyuen.github.io/images/adc-doc5.jpg)

TODO14

![](https://lupyuen.github.io/images/adc-doc6.jpg)

TODO15

![](https://lupyuen.github.io/images/adc-doclink.png)

TODO16

![](https://lupyuen.github.io/images/adc-doclink2.png)

TODO17

![](https://lupyuen.github.io/images/adc-doclink3.png)

TODO18

![](https://lupyuen.github.io/images/adc-format.jpg)

TODO19

![](https://lupyuen.github.io/images/adc-gain.png)

TODO20

![](https://lupyuen.github.io/images/adc-gain2.png)

TODO21

![](https://lupyuen.github.io/images/adc-gpio.png)

TODO22

![](https://lupyuen.github.io/images/adc-hal.png)

TODO23

![](https://lupyuen.github.io/images/adc-prefix.png)

TODO27

![](https://lupyuen.github.io/images/adc-rust.png)

TODO28

![](https://lupyuen.github.io/images/adc-rust2.png)

TODO29

![](https://lupyuen.github.io/images/adc-rustwrapper.png)

TODO30

![](https://lupyuen.github.io/images/adc-spi.png)
