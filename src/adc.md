# Rust on RISC-V BL602: Is It Sunny?

📝 _3 Aug 2021_

Today we shall magically transform [__any RISC-V BL602 Board__](https://lupyuen.github.io/articles/pinecone) into a __Light Sensor!__

We'll do this two ways...

1.  First we code the firmware in C

    (By calling the BL602 IoT SDK)

1.  Then we port the C firmware to Rust with...

    [__Rust Wrapper for BL602 IoT SDK__](https://crates.io/crates/bl602-sdk)

    (New to Rust? No worries we have tips for you!)

_Wait... Do all BL602 Boards have an onboard Light Sensor?_

Nope, all we need is a __BL602 Board with an LED__!

Reading the LED with BL602's __Analog-to-Digital Converter (ADC)__ will turn it into a simple, improvised Light Sensor.

_Amazing! Will this work with any BL602 Board?_

We have tested this with [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and its onboard LED.

It will probably work with any BL602 / BL604 Board with an __onboard or external LED:__ PineDio Stack, Pinenut, DT-BL10, MagicHome BL602, ...

_Will our Light Sensor detect any kind of light?_

Our LED-turned-Light-Sensor works best for __detecting sunlight__... We'll learn why in a while.

(Yep It's Always Sunny in Singapore ... So this Sunlight Sensor won't be so useful in Singapore 😂)

![Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon](https://lupyuen.github.io/images/adc-title.jpg)

_Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon_

# BL602 ADC in C

On PineCone BL602, there's a __Blue LED__ connected on __GPIO Pin Number 11__...

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

[(From PineCone BL602 Schematic)](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

For light sensing, we shall __read the voltage__ from this LED GPIO with BL602's Analog-to-Digital Converter (ADC).

(Because LEDs will produce a current when exposed to light. [See this](https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227))

Let's study the __C Firmware for BL602 ADC__: [`sdk_app_adc2`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/)

By calling the [__BL602 ADC Low Level HAL__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c) (Hardware Abstraction Layer), we shall...

1.  __Initialise the ADC Channel__ for reading our LED GPIO

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

Here's how we __initialise the ADC Channel__ for reading our LED GPIO: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L36-L77)

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

Our __`init_adc` Command__ begins by validating the GPIO Pin Number and ADC Frequency.

Then it calls __`bl_adc_freq_init`__ to set the __ADC Frequency__.

(Functions named `bl_adc_*` are defined in the [BL602 ADC Low Level HAL](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c))

The first parameter to `bl_adc_freq_init` selects the __ADC Mode__...

-   ADC Mode 0: __Scan Conversion Mode__

    BL602 ADC Controller reads __One ADC Sample__ from __Multiple ADC Channels.__

    (So it's scanning across multiple ADC Channels, recording one sample per channel)

-   ADC Mode 1: __Single-Channel Conversion Mode__

    BL602 ADC Controller reads __Multiple ADC Samples__ continuously from __One ADC Channel.__

    (This is the mode we're using)

Next we set the __ADC GPIO Pin Number__ for ADC Mode 1 (Single-Channel Conversion)...

```c
  //  Init the ADC GPIO for Single-Channel Conversion Mode
  rc = bl_adc_init(1, ADC_GPIO);
  assert(rc == 0);
```

To increase the ADC sensitivity, we set the __ADC Gain__...

```c
  //  Enable ADC Gain to increase the ADC sensitivity
  rc = set_adc_gain(ADC_GAIN1, ADC_GAIN2);
  assert(rc == 0);
```

(More about this in a while)

BL602 ADC Controller shall transfer the ADC Samples directly into RAM, thanks to the __Direct Memory Access (DMA) Controller__...

```c
  //  Init DMA for the ADC Channel for Single-Channel Conversion Mode
  rc = bl_adc_dma_init(1, ADC_SAMPLES);
  assert(rc == 0);
```

(First parameter of `bl_adc_dma_init` is the ADC Mode)

We configure the GPIO Pin for __ADC Input__...

```c
  //  Configure the GPIO Pin as ADC Input, no pullup, no pulldown
  rc = bl_adc_gpio_init(ADC_GPIO);
  assert(rc == 0);
```

We set the __DMA Context__ for the ADC Channel...

```c
  //  Get the ADC Channel Number for the GPIO Pin
  int channel = bl_adc_get_channel_by_gpio(ADC_GPIO);

  //  Get the DMA Context for the ADC Channel
  adc_ctx_t *ctx = bl_dma_find_ctx_by_channel(ADC_DMA_CHANNEL);
  assert(ctx != NULL);

  //  Indicate that the GPIO has been configured for ADC
  ctx->chan_init_table |= (1 << channel);
```

(`bl_dma_find_ctx_by_channel` is defined in [BL602 DMA HAL](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_dma.c))

Finally we __start the ADC Channel__...

```c
  //  Start reading the ADC via DMA
  bl_adc_start();
}
```

BL602 ADC Controller will __read the ADC Samples continuously__ (from the GPIO Pin) into RAM (until we stop the ADC Channel).

## Read the ADC Channel

_After starting the ADC Channel, how do we fetch the ADC Samples that have been read?_

Let's find out in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L79-L116) ...

```c
/// Command to compute the average value of the ADC Samples that have just been read.
/// Based on `hal_adc_get_data` in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_adc.c#L142-L179>
void read_adc(char *buf, int len, int argc, char **argv) {
  //  Get the ADC Channel Number for the GPIO Pin
  int channel = bl_adc_get_channel_by_gpio(ADC_GPIO);
    
  //  Get the DMA Context for the ADC Channel
  adc_ctx_t *ctx = bl_dma_find_ctx_by_channel(ADC_DMA_CHANNEL);
  assert(ctx != NULL);

  //  Verify that the GPIO has been configured for ADC
  assert(((1 << channel) & ctx->chan_init_table) != 0);
```

Our __`read_adc` Command__ begins by verifying the __DMA Context__ for the ADC Channel.

Next we check whether the __ADC Sampling__ has been completed for the ADC Channel...

```c
  //  If ADC Sampling is not finished, try again later    
  if (ctx->channel_data == NULL) {
    printf("ADC Sampling not finished\r\n");
    return;
  }
```

Remember that the BL602 ADC Controller will __read ADC Samples continuously__ and write the last 1,000 samples to RAM (via DMA).

Let's __copy the last 1,000 ADC Samples__ from the DMA Context (in RAM) to a Static Array `adc_data`...

```c
  //  Static array that will store 1,000 ADC Samples
  static uint32_t adc_data[ADC_SAMPLES];

  //  Copy the read ADC Samples to the static array
  memcpy(
    (uint8_t*) adc_data,             //  Destination
    (uint8_t*) (ctx->channel_data),  //  Source
    sizeof(adc_data)                 //  Size
  );  
```

Then we compute the __average value of the ADC Samples__ in `adc_data`...

```c
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

The default ADC Configuration has roughly __12 Bits of Resolution per ADC Sample__.

Thus we scale each ADC Sample to the range __0 to 3199__.

And that's how we code BL602 ADC Firmware in C!

![Running the BL602 ADC Firmware in C](https://lupyuen.github.io/images/adc-demo.png)

## Run the C Firmware

Watch what happens when we __flash and run__ the C Firmware for BL602 ADC: [`sdk_app_adc2`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/)

1.  Enter this command to __initialise the ADC Channel__...

    ```text
    # init_adc
    ```

    (We've seen this function earlier)

1.  Place the BL602 Board (with LED) in a __dark place__.

1.  Enter the `read_adc` command a few times to get the __average values__ of the last 1,000 ADC Samples...

    ```text
    # read_adc
    Average: 1416

    # read_adc
    Average: 1416

    # read_adc
    Average: 1416
    ```

1.  Now place the BL602 Board (with LED) __under sunlight__.

1.  Enter the `read_adc` command a few times...

    ```text
    # read_adc
    Average: 1408

    # read_adc
    Average: 1408

    # read_adc
    Average: 1408
    ```

    Note that the average values have __dropped from 1416 to 1408.__

1.  Place the BL602 Board (with LED) __back in the dark__ and check the average values...

    ```text
    # read_adc
    Average: 1417

    # read_adc
    Average: 1416

    # read_adc
    Average: 1416
    ```

    The average values have __increased from 1408 to 1416.__

    Yep our improvised BL602 Light Sensor works!

![Setting the ADC Gain](https://lupyuen.github.io/images/adc-gain2.png)

## Set the ADC Gain

Let's chat about __ADC Gain__, which we used when reading the LED as a Light Sensor. 

(ADC Gain probably won't be needed for reading most types of ADC Inputs)

_Why do we need ADC Gain when reading an LED?_

Our LED generates a __tiny bit of current__ when exposed to light. To measure that tiny bit of current, we need to increase the ADC sensitivity.

Thus we __increase the ADC Gain__. (By default there's no ADC Gain)

_BL602 HAL has a function that sets the ADC Gain right?_

Sadly no. We need to go really low-level and call the [__BL602 Standard Driver for ADC__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_adc.c#L152-L230).

(The BL602 Standard Driver directly manipulates the BL602 Hardware Registers)

Here's the low-level code that __sets the ADC Gain__: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L118-L146)

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

# Create a BL602 Rust Project

Before diving into the Rust Firmware, let's walk through the steps for __creating a BL602 Rust Project__ (like `sdk_app_rust_adc`)...

1.  __Download the Source Code__ for BL602 IoT SDK...

    ```bash
    git clone --recursive https://github.com/lupyuen/bl_iot_sdk
    ```

1.  __Copy the Project Folder__ for an existing Rust Project in __`bl_iot_sdk/customer_app`__, like `sdk_app_rust_gpio` ...

    -   [__Project Folder for `sdk_app_rust_gpio`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_rust_gpio)

1.  __Paste the Project Folder__ into __`bl_iot_sdk/customer_app`__ and rename it (like `sdk_app_rust_adc`)...

    ![BL602 Rust Project](https://lupyuen.github.io/images/adc-project.png)

    Be sure to __rename the Sub Folder__ too. (The `sdk_app_rust_adc` inside `sdk_app_rust_adc`)

    __Delete the `build_out` folder__ if it exists.

1.  __Edit the `Makefile`__ in the new folder and set the Project Name: [`sdk_app_rust_adc/Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/Makefile)

    ```text
    #  Set the project name
    PROJECT_NAME := sdk_app_rust_adc
    ```

1.  Set the __GCC Compiler Options__ (if any) in the Makefile [`sdk_app_rust_adc / sdk_app_rust_adc / bouffalo.mk`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/bouffalo.mk)

1.  Edit the __`run.sh` script__ in the new folder and set the Project Name: [`sdk_app_rust_adc/run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/run.sh)

    ```bash
    #  Set the project name
    export APP_NAME=sdk_app_rust_adc
    ```

1.  Replace the __Rust Source Code__ in [`sdk_app_rust_adc/ rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs) 

1.  See the Appendix for the steps to define the __Rust Commands__ for the Command-Line Interface in [`sdk_app_rust_adc / demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c#L47-L55)

1.  Remember to edit __`README.md`__ and fill in the project details

# BL602 ADC in Rust

Now we study the __Rust Firmware for BL602 ADC__: [`sdk_app_rust_adc`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc)

We have __converted the C Firmware to Rust__ line by line, so the Rust code will look highly similar to C.

Recall that our firmware implements two commands...

1.  __Initialise the ADC Channel__ for reading our LED GPIO

1.  __Compute the average value__ of the ADC Samples that have been read

Here is the Rust implementation...

## Definitions

We start by declaring to the Rust Compiler that we're calling the __Rust Core Library__ (instead of Rust Standard Library): [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L1-L37)

```rust
#![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems
```

(Rust Standard Library is too heavy for embedded programs)

Next we __import the functions__ from Rust Core Library that will be used in a while...

```rust
//  Import Libraries
use core::{          //  Rust Core Library
  fmt::Write,        //  String Formatting    
  mem::transmute,    //  Pointer Casting
  panic::PanicInfo,  //  Panic Handler
};
```

We import the __Rust Wrapper for BL602 IoT SDK__...

```rust
use bl602_sdk::{     //  Rust Wrapper for BL602 IoT SDK
  adc,               //  ADC HAL
  dma,               //  DMA HAL
  puts,              //  Console Output
  Ptr,               //  C Pointer
  String,            //  Strings (limited to 64 chars)
};
```

We shall read __GPIO 11__ (the Blue LED) as ADC Input...

```rust
/// GPIO Pin Number that will be configured as ADC Input.
/// PineCone Blue LED is connected on BL602 GPIO 11.
/// PineCone Green LED is connected on BL602 GPIO 14.
/// Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
/// TODO: Change the GPIO Pin Number for your BL602 board
const ADC_GPIO: i32 = 11;
```

BL602 ADC Controller shall read __10,000 ADC Samples per second__, and remember the last __100 ADC Samples__...

```rust
/// We set the ADC Frequency to 10 kHz according to <https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227>
/// This is 10,000 samples per second.
const ADC_FREQUENCY: u32 = 10000;  //  Hz

/// We shall read 100 ADC samples, which will take 0.01 seconds
const ADC_SAMPLES: usize = 100;
```

(`usize` is similar to `size_t` in C, it's used to represent the size of arrays)

We shall set the __ADC Gain__ to increase the ADC sensitivity...

```rust
/// Set ADC Gain to Level 1 to increase the ADC sensitivity.
/// To disable ADC Gain, set `ADC_GAIN1` and `ADC_GAIN2` to `ADC_PGA_GAIN_NONE`.
/// See <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_adc.h#L133-L144>
const ADC_GAIN1: u32 = ADC_PGA_GAIN_1;
const ADC_GAIN2: u32 = ADC_PGA_GAIN_1;
```

But __`ADC_PGA_GAIN_1`__ is missing from our Rust Wrapper.

Thus we copy the value from BL602 IoT SDK and define it here...

```rust
const ADC_PGA_GAIN_1: u32 = 1;  //  From <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_adc.h#L133-L144>
```

![Rust Firmware for BL602 ADC](https://lupyuen.github.io/images/adc-rust.png)

## Initialise the ADC Channel

Here's our Rust Function __`init_adc`__ that will be called by the BL602 Command-Line Interface: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L39-L100)

```rust
/// Command to init the ADC Channel and start reading the ADC Samples.
/// Based on `hal_adc_init` in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_adc.c#L50-L102>
#[no_mangle]             //  Don't mangle the function name
extern "C" fn init_adc(  //  Declare `extern "C"` because it will be called by BL602 firmware
  _result: *mut u8,        //  Result to be returned to command-line interface (char *)
  _len:  i32,              //  Size of result buffer (int)
  _argc: i32,              //  Number of command line args (int)
  _argv: *const *const u8  //  Array of command line args (char **)
) {
  puts("[Rust] Init ADC");
```

(We won't be parsing the command-line arguments, so let's ignore the parameters passed to `init_adc`)

We start by validating the GPIO Pin Number and ADC Frequency...

```rust
  //  Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
  assert!(ADC_GPIO==4 || ADC_GPIO==5 || ADC_GPIO==6 || ADC_GPIO==9 || ADC_GPIO==10 || ADC_GPIO==11 || ADC_GPIO==12 || ADC_GPIO==13 || ADC_GPIO==14 || ADC_GPIO==15);

  //  For Single-Channel Conversion Mode, frequency must be between 500 and 16,000 Hz
  assert!(ADC_FREQUENCY >= 500 && ADC_FREQUENCY <= 16000);
```

(Remember: Not all GPIOs are supported for ADC!)

Next we select __ADC Mode 1__ (Single-Channel Conversion) and set the __ADC Frequency__...

```rust
  //  Init the ADC Frequency for Single-Channel Conversion Mode
  adc::freq_init(1, ADC_FREQUENCY)
    .expect("ADC Freq failed");
```

We set the __ADC GPIO Pin Number__ for ADC Mode 1...

```rust
  //  Init the ADC GPIO for Single-Channel Conversion Mode
  adc::init(1, ADC_GPIO)
    .expect("ADC Init failed");
```

To increase the ADC sensitivity, we set the __ADC Gain__...

```rust
  //  Enable ADC Gain to increase the ADC sensitivity
  let rc = unsafe { set_adc_gain(ADC_GAIN1, ADC_GAIN2) };  //  Unsafe because we are calling C function
  assert!(rc == 0);
```

(This calls our C function `set_adc_gain`, which shall be explained below)

BL602 ADC Controller shall transfer the ADC Samples directly into RAM, thanks to the __Direct Memory Access (DMA) Controller__...

```rust
  //  Init DMA for the ADC Channel for Single-Channel Conversion Mode
  adc::dma_init(1, ADC_SAMPLES as u32)
    .expect("DMA Init failed");
```

(First parameter of `dma_init` is the ADC Mode)

We configure the GPIO Pin for __ADC Input__...

```rust
  //  Configure the GPIO Pin as ADC Input, no pullup, no pulldown
  adc::gpio_init(ADC_GPIO)
    .expect("ADC GPIO failed");
```

And we fetch the __DMA Context__ for the ADC Channel...

```rust
  //  Get the ADC Channel Number for the GPIO Pin
  let channel = adc::get_channel_by_gpio(ADC_GPIO)
    .expect("ADC Channel failed");

  //  Get the DMA Context for the ADC Channel
  let ptr = dma::find_ctx_by_channel(adc::ADC_DMA_CHANNEL as i32)
    .expect("DMA Ctx failed");
```

However the returned pointer `ptr` is actually a "`void *`" pointer from C.

To use the pointer in Rust, we cast it to a __DMA Context Pointer__...

```rust
  //  Cast the returned C Pointer (void *) to a DMA Context Pointer (adc_ctx *)
  let ctx = unsafe {     //  Unsafe because we are casting a pointer
    transmute::<         //  Cast the type...
      Ptr,               //  From C Pointer (void *)
      *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
    >(ptr)               //  For this pointer
  };
```

(More about `transmute` in the Appendix)

Now we may update the __DMA Context__ for the ADC Channel...

```rust
  //  Indicate that the GPIO has been configured for ADC
  unsafe {  //  Unsafe because we are dereferencing a pointer
    (*ctx).chan_init_table |= 1 << channel;
  }
```

(We flag this as `unsafe` because we're dereferencing a pointer: `ctx`)

Finally we __start the ADC Channel__...

```rust
  //  Start reading the ADC via DMA
  adc::start()
    .expect("ADC Start failed");
}
```

BL602 ADC Controller will __read the ADC Samples continuously__ (from the GPIO Pin) into RAM (until we stop the ADC Channel).

![Rust Firmware to read BL602 ADC](https://lupyuen.github.io/images/adc-rust2.png)

## Read the ADC Channel

_Our ADC Channel has been started, how do we average the ADC Samples that have been read?_

Let's check out the Rust Function __`read_adc`__ in [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L102-L165) ...

```rust
/// Command to compute the average value of the ADC Samples that have just been read.
/// Based on `hal_adc_get_data` in <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_adc.c#L142-L179>
#[no_mangle]              //  Don't mangle the function name
extern "C" fn read_adc(   //  Declare `extern "C"` because it will be called by BL602 firmware
  _result: *mut u8,        //  Result to be returned to command-line interface (char *)
  _len:  i32,              //  Size of result buffer (int)
  _argc: i32,              //  Number of command line args (int)
  _argv: *const *const u8  //  Array of command line args (char **)
) {
```

First we fetch the __DMA Context__ for the ADC Channel...

```rust
  //  Get the ADC Channel Number for the GPIO Pin
  let channel = adc::get_channel_by_gpio(ADC_GPIO)
    .expect("ADC Channel failed");
  
  //  Get the DMA Context for the ADC Channel
  let ptr = dma::find_ctx_by_channel(adc::ADC_DMA_CHANNEL as i32)
    .expect("DMA Ctx failed");
```

Again we cast the returned C pointer `ptr` to a __DMA Context Pointer__...

```rust
  //  Cast the returned C Pointer (void *) to a DMA Context Pointer (adc_ctx *)
  let ctx = unsafe {     //  Unsafe because we are casting a pointer
    transmute::<         //  Cast the type...
      Ptr,               //  From C Pointer (void *)
      *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
    >(ptr)               //  For this pointer
  };
```

(More about `transmute` in the Appendix)

Now we may verify the __DMA Context__ for the ADC Channel...

```rust
  //  Verify that the GPIO has been configured for ADC
  unsafe {  //  Unsafe because we are dereferencing a pointer
    assert!(((1 << channel) & (*ctx).chan_init_table) != 0);
  }
```

(We flag this as `unsafe` because we're dereferencing a pointer: `ctx`)

And we check whether the __ADC Sampling__ has been completed for the ADC Channel (`channel_data` shouldn't be null)...

```rust
  //  If ADC Sampling is not finished, try again later    
  if unsafe { (*ctx).channel_data.is_null() } {  //  Unsafe because we are dereferencing a pointer
    puts("ADC Sampling not finished");
    return;
  }
```

(Again we flag as `unsafe` because we're dereferencing the pointer `ctx`)

Remember that the BL602 ADC Controller will __read ADC Samples continuously__ and write the last 100 samples to RAM (via DMA).

We define an array `adc_data` to store the last 100 samples temporarily (on the stack)...

```rust
  //  Array that will store the last 100 ADC Samples
  //  (`ADC_SAMPLES` is 100)
  let mut adc_data: [u32; ADC_SAMPLES]
    = [0; ADC_SAMPLES];  //  Init array to 100 zeroes
```

(Rust requires all variables to be initialised, so we set the array to 100 zeroes)

Let's __copy the last 100 ADC Samples__ from the DMA Context (in RAM) to our array `adc_data` (on the stack)...

```rust
  //  Copy the read ADC Samples to the array
  unsafe {                    //  Unsafe because we are copying raw memory
    core::ptr::copy(          //  Copy the memory...
      (*ctx).channel_data,    //  From Source (ADC DMA data)
      adc_data.as_mut_ptr(),  //  To Destination (mutable pointer to adc_data)
      adc_data.len()          //  Number of Items (each item is uint32 or 4 bytes)
    );    
  }
```

(More about this in the Appendix)

(`adc_data.len()` returns the array length: 100)

Then we compute the __average value of the ADC Samples__ in `adc_data`...

```rust
  //  Compute the average value of the ADC Samples
  let mut sum = 0;
  for i in 0..ADC_SAMPLES {  //  From 0 to 99, `..` excludes 100
    //  Scale up the ADC Sample to the range 0 to 3199
    let scaled = ((adc_data[i] & 0xffff) * 3200) >> 16;
    sum += scaled;
  }
  let avg = sum / ADC_SAMPLES as u32;
```

We scale each ADC Sample to the range __0 to 3199__. (Because the default ADC Configuration produces 12-bit samples)

Finally we compose a __formatted string with the average value__ and display it...

```rust
  //  Format the output
  let mut buf = String::new();
  write!(buf, "[Rust] Average: {}", avg)
    .expect("buf overflow");

  //  Display the formatted output
  puts(&buf);
}
```

(Yep Rust will helpfully __check for buffer overflow__... safer than `sprintf`!)

Default String Size is __64 characters__, as defined in the BL602 Rust Wrapper.

(Similar to "`char[64]`" in C)

The __formatted output__ will appear like so...

![Output from Rust Firmware](https://lupyuen.github.io/images/adc-format.jpg)

And we're done... That's how we code BL602 ADC Firmware in Rust!

# Build the BL602 Rust Firmware

We may download the Rust Firmware Binary File __`sdk_app_rust_adc.bin`__ from...

-  [__`sdk_app_rust_adc` Binary Release__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v11.0.0.0)

Or follow these steps to build the Rust Firmware `sdk_app_rust_adc.bin`...

1.  Install __`rustup`, `blflash` and `xpack-riscv-none-embed-gcc`__

    -   [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

    -   [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

    -   [__"Install `xpack-riscv-none-embed-gcc`"__](https://lupyuen.github.io/articles/debug#install-gdb)

1.  Download the __source code__ for the BL602 Rust Firmware...

    ```bash
    # Download the adc branch of lupyuen's bl_iot_sdk
    git clone --recursive --branch adc https://github.com/lupyuen/bl_iot_sdk
    cd bl_iot_sdk/customer_app/sdk_app_rust_adc
    ```

1.  Edit the script [__`run.sh`__](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/run.sh) in the `sdk_app_rust_adc` folder.

    This build script was created for macOS, but can be modified to run on Linux x64 and Windows WSL.

1.  In `run.sh`, set the following variables to the downloaded folders for `blflash` and `xpack-riscv-none-embed-gcc`...

    ```bash
    #  Where blflash is located
    export BLFLASH_PATH=$PWD/../../../blflash

    #  Where GCC is located
    export GCC_PATH=$PWD/../../../xpack-riscv-none-embed-gcc
    ```

    Save the changes into `run.sh`

1.  Build the firmware...

    ```bash
    ./run.sh
    ```

1.  We should see...

    ```text
    ----- Building Rust app and BL602 firmware for riscv32imacf-unknown-none-elf / sdk_app_rust_adc...

    ----- Build BL602 Firmware
    + make
    ...
    LD build_out/sdk_app_rust_adc.elf
    ld: undefined reference to `init_adc'
    ld: undefined reference to `read_adc'
    ----- Ignore undefined references to Rust Library
    ```

    This means that the __C code from our BL602 Firmware__ has been built successfully.

1.  Next the script __compiles our Rust code__ into a static library: `libapp.a`

    ```text
    ----- Build Rust Library
    + rustup default nightly

    + cargo build \
        --target ../riscv32imacf-unknown-none-elf.json \
        -Z build-std=core

    Updating crates.io index
    Compiling compiler_builtins v0.1.46
    Compiling core v0.0.0
    ...
    Compiling bl602-macros v0.0.2
    Compiling bl602-sdk v0.0.6
    Compiling app v0.0.1 (bl_iot_sdk/customer_app/sdk_app_rust_adc/rust)
    Finished dev [unoptimized + debuginfo] target(s) in 23.55s
    ```

1.  Finally the script __links the Rust static library__ into our BL602 firmware...

    ```text
    ----- Link BL602 Firmware with Rust Library
    + make
    use existing version.txt file
    LD build_out/sdk_app_rust_adc.elf
    Generating BIN File to build_out/sdk_app_rust_adc.bin
    ...
    Building Finish. To flash build output.
    ```

    Ignore the error from `blflash`, we'll fix this in a while.

1.  Our __BL602 Rust Firmware file__ has been generated at...

    ```text
    build_out/sdk_app_rust_adc.bin
    ```

    Let's flash this to BL602 and run it!

Check out the complete build log here...

-   [__Build Log for BL602 Rust Firmware__](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/run.sh#L135-L497)

[More about the build script](https://lupyuen.github.io/articles/rust#appendix-build-script-for-bl602-rust-firmware)

[More about the custom Rust target](https://lupyuen.github.io/articles/rust#rust-targets)

![Building the BL602 Rust Firmware](https://lupyuen.github.io/images/adc-build.jpg)

# Flash the BL602 Rust Firmware

Here's how we flash the Rust Firmware file `sdk_app_rust_adc.bin` to BL602...

1.  Set BL602 to __Flashing Mode__ and restart the board...

    __For PineCone:__

    -   Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

    -   Press the Reset Button

    __For BL10:__

    -   Connect BL10 to the USB port

    -   Press and hold the __D8 Button (GPIO 8)__

    -   Press and release the __EN Button (Reset)__

    -   Release the D8 Button

    __For Pinenut and MagicHome BL602:__

    -   Disconnect the board from the USB Port

    -   Connect __GPIO 8__ to __3.3V__

    -   Reconnect the board to the USB port

1.  __For macOS:__

    Enter this at the command prompt...

    ```bash
    ./run.sh
    ```

    The script should automatically flash the firmware after building...

    ```text
    ----- Flash BL602 Firmware

    + cargo run flash sdk_app_rust_adc.bin \
        --port /dev/tty.usbserial-1410 \
        --initial-baud-rate 230400 \
        --baud-rate 230400

    Finished dev [unoptimized + debuginfo] target(s) in 0.61s
    Running `target/debug/blflash flash sdk_app_rust_adc.bin --port /dev/tty.usbserial-1420 --initial-baud-rate 230400 --baud-rate 230400`
    Start connection...
    5ms send count 115
    handshake sent elapsed 104.593µs
    Connection Succeed
    Bootrom version: 1
    Boot info: BootInfo { len: 14, bootrom_version: 1, otp_info: [0, 0, 0, 0, 3, 0, 0, 0, 61, 9d, c0, 5, b9, 18, 1d, 0] }
    Sending eflash_loader...
    Finished 1.595620342s 17.92KB/s
    5ms send count 115
    handshake sent elapsed 81.908µs
    Entered eflash_loader
    Skip segment addr: 0 size: 47504 sha256 matches
    Skip segment addr: e000 size: 272 sha256 matches
    Skip segment addr: f000 size: 272 sha256 matches
    Erase flash addr: 10000 size: 135808
    Program flash... ed8a4cdacbc4c1543c74584d7297ad876b6731104856a10dff4166c123c6637d
    Program done 7.40735771s 17.91KB/s
    Skip segment addr: 1f8000 size: 5671 sha256 matches
    Success
    ```

    (We might need to edit the script to use the right serial port)

1.  __For Linux and Windows:__

    Copy `build_out/sdk_app_rust_adc.bin` to the `blflash` folder.

    Then enter this at the command prompt...

    ```bash
    # TODO: Change this to the downloaded blflash folder
    cd blflash

    # For Linux:
    sudo cargo run flash sdk_app_lora.bin \
        --port /dev/ttyUSB0

    # For Windows: Change COM5 to the BL602 Serial Port
    cargo run flash sdk_app_lora.bin --port COM5
    ```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Running the BL602 Rust Firmware](https://lupyuen.github.io/images/adc-demo2.png)

# Run the BL602 Rust Firmware

Finally we run the BL602 Rust Firmware...

1.  Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

    __For PineCone:__

    -   Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

    -   Press the Reset Button

    __For BL10:__

    -   Press and release the __EN Button (Reset)__

    __For Pinenut and MagicHome BL602:__

    -   Disconnect the board from the USB Port

    -   Connect __GPIO 8__ to __GND__

    -   Reconnect the board to the USB port

1.  __For macOS:__

    The `run.sh` script should automatically launch CoolTerm after flashing...

    ```text
    ----- Run BL602 Firmware
    + open -a CoolTerm
    ```

    [More about CoolTerm](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

    __For Linux:__

    Connect to BL602's UART Port at 2 Mbps like so...

    ```bash
    sudo screen /dev/ttyUSB0 2000000
    ```

    __For Windows:__ 

    Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

    __Alternatively:__ 

    Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

    [More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

1.  In the serial console, enter the `init_adc` command to __initialise the ADC Channel__...

    ```text
    # init_adc
    [Rust] Init ADC
    ```

    (We've seen this function earlier)

1.  Place the BL602 Board (with LED) in a __dark place__.

1.  Enter the `read_adc` command a few times to get the __average values__ of the last 1,000 ADC Samples...

    ```text
    # read_adc
    [Rust] Average: 1417
    # read_adc
    [Rust] Average: 1417
    # read_adc
    [Rust] Average: 1417
    ```

1.  Now place the BL602 Board (with LED) __under sunlight__.

1.  Enter the `read_adc` command a few times...

    ```text
    # read_adc
    [Rust] Average: 1411
    # read_adc
    [Rust] Average: 1411
    # read_adc
    [Rust] Average: 1412
    ```

    Note that the average values have __dropped from 1417 to 1412.__

1.  Place the BL602 Board (with LED) __back in the dark__ and check the average values...

    ```text
    # read_adc
    [Rust] Average: 1417
    # read_adc
    [Rust] Average: 1417
    # read_adc
    [Rust] Average: 1417
    ```

    The average values have __increased from 1412 to 1417.__

    Our improvised BL602 Light Sensor works in Rust yay!

# From C To Rust

_I'm new to Rust. Is there an easier way to jump from C to Rust?_

Today we've seen that it's feasible to __translate C Firmware into Rust__ line by line...

![Compare C and Rust](https://lupyuen.github.io/images/adc-compare.png)

Which is great for embedded developers new to Rust!

Just be mindful of the __differences between C and Rust__...

1.  __BL602 HAL Functions__ have been renamed for Rust.

    (Like "`bl_adc_init`" becomes "`adc::init`")

    To see the list of BL602 HAL Functions for Rust, [check out the `bl602-sdk` documentation](https://docs.rs/bl602-sdk).

    (More about this in the next chapter)

1.  In Rust we check for __BL602 HAL Errors__ by calling "`expect`" instead of "`assert`".

    (Rust Compiler will warn us if we forget to "`expect`")

1.  Rust is __super strict about Mutability__... Only variables and pointers declared "`mut`" can be changed.

    (That's why we write "`*mut i32`" to get a pointer to an integer whose value may be changed)

1.  __Pointer Deferencing__ like "`ptr->field`" doesn't work in Rust.

    We rewrite it in Rust as "`(*ptr).field`"

1.  Rust will helpfully __check for Buffer Overflow__.

    (No more silent "`sprintf`" overflow!)

    For BL602 Rust Wrapper the default string size is __64 characters__.

    (Similar to "`char[64]`" in C)

1.  All Rust variables shall be __initialised__ before use.

    (Even arrays and structs!)

Let's talk about "`unsafe`" code in Rust... 

## Safer Rust

Rust reminds us to be Extra Careful when we work with __C Functions and C Pointers__.

That's why we need to flag the following code as __`unsafe`__...

1.  __Calling C Functions__

    ```rust
    //  Call the C function `set_adc_gain`
    unsafe { set_adc_gain(ADC_GAIN1, ADC_GAIN2) };
    ```

    (More about this in the Appendix)

1.  __Casting C Pointers__ to Rust
    
    ```rust
    //  Cast a C Pointer to a Rust Pointer
    let ctx = unsafe {
      transmute::<         //  Cast the type...
        Ptr,               //  From C Pointer (void *)
        *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
      >(ptr)               //  For this pointer
    };
    ```

    (More about this in the Appendix)

1.  __Dereferencing C Pointers__

    ```rust
    //  Dereference a C Pointer (ctx)
    unsafe {
      (*ctx).chan_init_table = ...
    }
    ```

1.  __Copying Memory__ with C Pointers

    ```rust
    //  Copy memory with a C Pointer (channel_data)
    unsafe {
      core::ptr::copy(          //  Copy the memory...
        (*ctx).channel_data,    //  From Source (ADC DMA data)
        adc_data.as_mut_ptr(),  //  To Destination (mutable pointer to adc_data)
        adc_data.len()          //  Number of Items (each item is uint32 or 4 bytes)
      );    
    }
    ```

    (More about this in the Appendix)

Accessing __Static Variables__ is also "`unsafe`". Let's talk about this...

## Static Variables in Rust

Earlier we saw this Rust code for __averaging the ADC Samples__...

```rust
//  `adc_data` will store 100 ADC Samples (`ADC_SAMPLES` is 100)
let mut adc_data: [u32; ADC_SAMPLES] = [0; ADC_SAMPLES];

//  Omitted: Copy data into `adc_data`
...

//  Compute average of `adc_data`
for i in 0..ADC_SAMPLES {
  //  Get value from `adc_data`
  let scaled = adc_data[i] & ...
```

Note that __`adc_data` lives on the stack__.

That's a huge chunk of data on the stack... __400 bytes!__

_What if we turn `adc_data` into a Static Array?_

We convert `adc_data` to a Static Array like this...

```rust
//  `adc_data` becomes a Static Array
static mut adc_data: [u32; ADC_SAMPLES] = [0; ADC_SAMPLES];
```

`adc_data` no longer lives on the stack, it's now in Static Memory.

_What's the catch?_

Unfortunately __Static Variables in Rust are `unsafe`__.

Thus all references to `adc_data` must be __flagged as `unsafe`__...

```rust
//  `adc_data` is now unsafe because it's a Static Variable
let scaled = unsafe { adc_data[i] } & ...
```

Which makes the code harder to read. That's why we left `adc_data` on the stack for this tutorial.

_Why are Static Variables `unsafe`?_

Because it's potentially possible to execute the above code in __multiple tasks__...

Which produces undefined behaviour when multiple tasks __access the same Static Variable__.

So it's perfectly OK to use Static Variables in Rust. Just that we need to...

1.  Flag the Static Variables as __`unsafe`__

1.  Ensure ourselves that Static Variables are only accessed by __one task at a time__

![Rust Wrapper for BL602 IoT SDK](https://lupyuen.github.io/images/adc-crate.png)

# Rust Wrapper for BL602 IoT SDK

_The BL602 Rust Wrapper Functions look mighty similar to the C Functions from the BL602 IoT SDK. How is this possible?_

Because the Rust Functions were __automatically generated from BL602 IoT SDK!__

We ran a script to generate the __Rust Wrapper for BL602 IoT SDK__.

And we published the Rust Wrapper on __`crates.io`__...

-   [__`bl602-sdk`: Rust Wrapper for BL602 IoT SDK__](https://crates.io/crates/bl602-sdk)

_Which functions from the BL602 IoT SDK are supported?_

Today our BL602 Rust Wrapper supports...

| | | |
| ----- | ----- | ----- |
| ◾ [__ADC__](https://docs.rs/bl602-sdk/latest/bl602_sdk/adc/index.html) |  ◾ [__I2C__](https://docs.rs/bl602-sdk/latest/bl602_sdk/i2c/index.html) | ◾ [__UART__](https://docs.rs/bl602-sdk/latest/bl602_sdk/uart/index.html)  
| ◾ [__DMA__](https://docs.rs/bl602-sdk/latest/bl602_sdk/dma/index.html) | ◾ [__PWM__](https://docs.rs/bl602-sdk/latest/bl602_sdk/pwm/index.html) | ◾ [__WiFi__](https://docs.rs/bl602-sdk/latest/bl602_sdk/wifi/index.html)
◾ [__GPIO__](https://docs.rs/bl602-sdk/latest/bl602_sdk/gpio/index.html) | ◾ [__SPI__](https://docs.rs/bl602-sdk/latest/bl602_sdk/spi/index.html)

[(See the complete list)](https://docs.rs/bl602-sdk)

_How do we add the BL602 Rust Wrapper to our Rust Project?_

Just add __`bl602-sdk`__ to the Rust project configuration: [`rust/Cargo.toml`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/Cargo.toml#L9-L11)

```text
# External Rust libraries used by this module.  See crates.io.
[dependencies]
bl602-sdk = "0.0.6"  # Rust Wrapper for BL602 IoT SDK: https://crates.io/crates/bl602-sdk
```

[(Change `"0.0.6"` to the latest version on `crates.io`)](https://crates.io/crates/bl602-sdk)

The BL602 Rust Wrapper will be auto-downloaded from `crates.io` when building the project.

![BL602 Rust Wrapper Documentation](https://lupyuen.github.io/images/adc-doc2.png)

_Is the BL602 Rust Wrapper documented?_

Yep! Every Rust Function is linked to the section in [__"The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book) that explains how we call the function...

-   [__Documentation for BL602 Rust Wrapper__](https://docs.rs/bl602-sdk)

(Check the Appendix to learn more about the BL602 Rust Wrapper)

Here's a sample project that calls the Rust Wrapper for GPIO...

![Rust Wrapper for GPIO](https://lupyuen.github.io/images/adc-gpio.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_gpio/rust/src/lib.rs)

# Why Sunlight?

_Why does our BL602 LED detect only sunlight? And not other kinds of light?_

We're guessing because...

1.  Sunlight is __more intense__

    (And produces more current)

1.  We used the __Blue LED__ on PineCone BL602

    (Which is sensitive to the spectrum of Blue - Indigo - Violet - Ultra-Violet (UV) light)

__LED Light Sensitivity__ is [explained in this article](https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227)...

> As a photodiode, an LED is sensitive to __wavelengths equal to or shorter than the predominant wavelength it emits__. A green LED would be sensitive to blue light and to some green light, but not to yellow or red light. 

Also according to [Sravan Senthilnathan on Twitter](https://twitter.com/SravanSenthiln1/status/1418044068567797765
)...

> This is possible due to the __blue LED's semiconductor bandgap__ being one appropriate to absorb the UV spectrum sun light. Here is more info about it:
[Aluminium gallium nitride on Wikipedia](https://en.wikipedia.org/wiki/Aluminium_gallium_nitride)

And according to [Dan Lafleur on LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:6823802475091501056?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6823802475091501056%2C6824139561749372928%29)...

> The technique I used to measure light level with an LED was to __reverse bias the LED and then time the discharge__. The light level is time based. The higher the light level the longer it takes to discharge the reversed bias junction.

[(More about measuring the Discharge Duration of an LED)](https://www.sparkfun.com/news/2161)

Here's [another comment](https://www.linkedin.com/feed/update/urn:li:activity:6823802475091501056?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6823802475091501056%2C6823807829040881664%29)...

> Yes, I have used LEDs as light sensors in class projects. The point is that they are not just emitters. A selection of red, green and blue LEDs can be used to build a crude __colour detector__. It works.

That sounds interesting...

_PineCone BL602 has Red, Green and Blue LEDs. Can we use the other LEDs?_

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

[(From PineCone BL602 Schematic)](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

Unfortunately __PineCone's Red LED__ is connected on GPIO 17, which is not supported for ADC.

But __PineCone's Green LED__ (GPIO 14) should work OK with ADC.

__Exercise For The Reader:__ Use PineCone's Green LED (instead of the Blue LED) as an ADC Light Sensor. What kind of light does it detect?

(This article was inspired by the __BBC micro:bit__, which uses LED as a Light Sensor. [See this](https://learn.adafruit.com/micro-bit-lesson-4-sensing-light-and-temperature/built-in-light-sensor))

![Testing the improvised Light Sensor on PineCone BL602 with Pinebook Pro](https://lupyuen.github.io/images/adc-pinebook.jpg)

_Testing the improvised Light Sensor on PineCone BL602 with Pinebook Pro_

# What's Next

Today we've seen that it's viable to create __Rust Firmware__ for BL602... Just call the __Rust Wrapper for BL602 IoT SDK__!

Soon we shall test the Rust Firmware on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/07/15/july-update/)... As we explore whether it's feasible to teach __Rust as a Safer Way__ to create firmware for BL602 and BL604.

Also we might __Simulate BL602 Rust Firmware__ in a Web Browser with __WebAssembly__!

-   [__BL602 / BL604 Simulator in WebAssembly__](https://github.com/lupyuen/bl602-simulator)

-   [__Follow the updates on Twitter__](https://twitter.com/MisterTechBlog/status/1423169766080933891)

    ![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/owr2xp/rust_on_riscv_bl602_is_it_sunny/)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/adc.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/adc.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread on Rust Wrapper for BL602 IoT SDK](https://twitter.com/MisterTechBlog/status/1416608940876435462)

    And [this Twitter Thread on BL602 ADC](https://twitter.com/MisterTechBlog/status/1418025678251773954)

1.  Are there other ways to run __Rust Firmware on BL602__? See this...

    [__"Rust On BL602: Two More Ways"__](https://lupyuen.github.io/articles/rust#rust-on-bl602-two-more-ways)

1.  We may also use BL602 ADC HAL to read the __BL602 Internal Temperature Sensor__...

    -   [Read BL602 Internal Temperature Sensor via ADC Low Level HAL](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c#L224-L282)

1.  Is there a __simpler way to code ADC Firmware__ in C?

    Yes, we could call the __ADC High Level HAL__.
    
    (Instead of the ADC Low Level HAL that we've seen)

    Here's our ADC Firmware, rewritten to call the __ADC High Level HAL__...

    ![BL602 ADC High Level HAL](https://lupyuen.github.io/images/adc-highlevel.png)

    [(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc/sdk_app_adc/demo.c)

    But the ADC High Level HAL won't let us set the __ADC Gain__.

    We need to __patch the ADC Low Level HAL__ like so...

    ![Setting the ADC Gain by patching the ADC High Level HAL](https://lupyuen.github.io/images/adc-gain.png)

    [(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/adc/components/hal_drv/bl602_hal/bl_adc.c#L339-L389)

    Also note that the ADC High Level HAL doesn't allow us to compute the __average of the ADC Samples__.

    It returns only one ADC Sample.

1.  __ESP32__ has something similar to the BL602 Rust Wrapper...

    -   [`esp-idf-sys`](https://github.com/esp-rs/esp-idf-sys) defines the Rust Bindings for ESP32 IDF SDK (generated with `bindgen`)

    -   [`esp-idf-hal`](https://github.com/esp-rs/esp-idf-hal) wraps `esp-idf-sys` into a Rust Embedded HAL for ESP32

    -   [More about Rust on ESP32](https://mabez.dev/blog/posts/esp-rust-espressif/)

    (Perhaps someday we might wrap the BL602 Rust Wrapper into a Rust Embedded HAL for BL602 / BL604)

# Appendix: Call C Functions from Rust

_How do we call our own C Functions from Rust?_

Earlier we saw this Rust code that __sets the ADC Gain__: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L64-L66)

```rust
//  In Rust: Enable ADC Gain to increase the ADC sensitivity
unsafe { set_adc_gain(ADC_GAIN1, ADC_GAIN2) };  //  Unsafe because we are calling C function
```

This calls the C Function `set_adc_gain`, which we have __imported into Rust__ here: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L180-L184)

```rust
//  In Rust: Import C Function
extern "C" {
  /// Enable ADC Gain to increase the ADC sensitivity.
  /// Defined in customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c
  fn set_adc_gain(gain1: u32, gain2: u32) -> i32;
}
```

__`set_adc_gain`__ is defined in this C source file: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c#L11-L42)

_What about the rest of the code in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c)?_

The rest of the C code in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c) is needed to set up the __Command-Line Interface__ for our BL602 Firmware.

We define the __Rust Commands__ for the Command-Line Interface like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c#L47-L55)

```c
/// In C: Import Rust functions from customer_app/sdk_app_rust_adc/rust/src/lib.rs
void init_adc(char *buf, int len, int argc, char **argv);
void read_adc(char *buf, int len, int argc, char **argv);

/// List of commands. STATIC_CLI_CMD_ATTRIBUTE makes these commands static
const static struct cli_command cmds_user[] STATIC_CLI_CMD_ATTRIBUTE = {
    {"init_adc",        "Init ADC Channel",          init_adc},
    {"read_adc",        "Read ADC Channel",          read_adc},
};
```

This defines the commands `init_adc` and `read_adc`, which are mapped to the respective Rust Functions.

# Appendix: Cast C Pointers in Rust

_How do we cast C Pointers in Rust?_

In the C version of our ADC Firmware, we implicitly cast a "`void *`" pointer to "`adc_ctx *`" pointer like this: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L88-L90)

```c
//  In C: Get the pointer (void *) for DMA Context
void *ptr = ...

//  Cast the returned pointer (void *) to a DMA Context Pointer (adc_ctx *)
struct adc_ctx *ctx = (struct adc_ctx *) ptr;
```

Here we're [Downcasting](https://en.wikipedia.org/wiki/Downcasting) a General Type (`void *`) to a Specific Type (`adc_ctx *`).

To do the same in Rust, we need to be super explicit about __what we're casting__: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L119-L129)

```rust
//  In Rust: Get the C Pointer (void *) for DMA Context
let ptr = ...

//  Cast the returned C Pointer (void *) to a DMA Context Pointer (adc_ctx *)
let ctx = unsafe {     //  Unsafe because we are casting a pointer
  transmute::<         //  Cast the type...
    Ptr,               //  From C Pointer (void *)
    *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
  >(ptr)               //  For this pointer
};
```

__`transmute`__ is the Rust Core Library Function that will cast our value (`ptr`) from one type to another...

```rust
transmute::< FromType , ToType >( ptr )
```

Where...

-   From Type is __`Ptr`__

    `Ptr` is our short form for the "`void *`" pointer in Rust.
    
    [(See this)](https://docs.rs/bl602-sdk/latest/bl602_sdk/type.Ptr.html)

-   To Type is __`*mut adc::adc_ctx`__

    Which is a mutable pointer to `adc_ctx`
    
    (Equivalent to "`adc_ctx *`" in C)

[(More about `transmute`)](https://doc.rust-lang.org/core/mem/fn.transmute.html)

![Casting a C Pointer in Rust](https://lupyuen.github.io/images/adc-cast.png)

# Appendix: Copy Memory with C Pointers

_How do we copy memory with C Pointers?_

Earlier we saw this code in our C Firmware: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c#L101-L106)

```c
//  Array that will store ADC Samples
uint32_t adc_data[ADC_SAMPLES];

//  Copy the read ADC Samples to the array
memcpy(
  (uint8_t*) adc_data,             //  Destination
  (uint8_t*) (ctx->channel_data),  //  Source
  sizeof(adc_data)                 //  Size
);  
```

This code __copies the ADC Samples__ from the DMA buffer to the array `adc_data`.

Here's the equivalent code in Rust: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L142-L149)

```rust
//  Array that will store the last 100 ADC Samples (`ADC_SAMPLES` is 100)
let mut adc_data: [u32; ADC_SAMPLES]
  = [0; ADC_SAMPLES];  //  Init array to 100 zeroes

//  Copy the read ADC Samples to the array
unsafe {                    //  Unsafe because we are copying raw memory
  core::ptr::copy(          //  Copy the memory...
    (*ctx).channel_data,    //  From Source (ADC DMA data)
    adc_data.as_mut_ptr(),  //  To Destination (mutable pointer to adc_data)
    adc_data.len()          //  Number of Items (each item is uint32 or 4 bytes)
  );    
}
```

Note the differences...

1.  For Rust the __Source Pointer__ is the first parameter, followed by the __Destination Pointer__

    (This is flipped from `memcpy` in C)

1.  For Rust the third parameter is the __Number of Items__ to be copied. (100 items)

    (For `memcpy` the third parameter specifies the number of bytes to copy, i.e. 400 bytes)

![Copy ADC data in Rust](https://lupyuen.github.io/images/adc-copy.png)

# Appendix: Generating the Rust Wrapper for BL602 IoT SDK

_How was the BL602 Rust Wrapper generated for publishing on [`crates.io`](https://crates.io/crates/bl602-sdk)?_

Two tools were used to generate the __Rust Wrapper for BL602 IoT SDK__...

1.  [__`bindgen`__](https://rust-lang.github.io/rust-bindgen): Command-line tool that generates the __Rust Bindings__ for a C API.

    (As specified by C Header Files)

1.  [__`safe_wrap`__](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs): A Rust Procedural Macro we wrote to transform the BL602 C Types to __safer Rust-Friendly Types__.

    (Including the "`expect`" checking for return values)

Here are the steps for __generating the Rust Wrapper__...

```bash
#  Install bindgen and clang: https://rust-lang.github.io/rust-bindgen/requirements.html 
cargo install bindgen
sudo apt install llvm-dev libclang-dev clang

#  Download the source code
git clone --recursive https://github.com/lupyuen/bl602-rust-wrapper
git clone --recursive https://github.com/lupyuen/bl_iot_sdk

#  Generate the Rust Bindings for BL602 IoT SDK
cd bl602-rust-wrapper
scripts/gen-bindings.sh

#  Build the docs and the test project
scripts/build.sh
```

![BL602 Rust Wrapper generated by bindgen and safe_wrap](https://lupyuen.github.io/images/adc-bindgen.png)

## How it works

This script...

-   [`scripts/gen-bindings.sh`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/scripts/gen-bindings.sh)

Calls __`bindgen`__ to read the BL602 IoT SDK __Header Files__...

```c
//  Function Declarations from BL602 IoT SDK (GPIO HAL)
//  https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.h
int bl_gpio_enable_output(uint8_t pin, uint8_t pullup, uint8_t pulldown);
int bl_gpio_output_set(uint8_t pin, uint8_t value);
```

To produce the __Rust Bindings__ for BL602 IoT SDK...

-   [`bl602-sdk/src/gpio.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-sdk/src/gpio.rs)
-   [`bl602-sdk/src/adc.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-sdk/src/adc.rs)
-   [More Bindings](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-sdk/src)

```rust
//  Rust Bindings for BL602 GPIO generated by gen-bindings.sh
#[safe_wrap(_)] extern "C" {
    pub fn bl_gpio_enable_output(pin: u8, pullup: u8, pulldown: u8) -> ::cty::c_int;
}

#[safe_wrap(_)] extern "C" {
    pub fn bl_gpio_output_set(pin: u8, value: u8) -> ::cty::c_int;
}
```

(`safe_wrap` was inserted by an `sed` script in `gen-bindings.sh`)

When the above Rust Bindings are compiled, they invoke the __`safe_wrap` Procedural Macro__...

-   [`bl602-macros/src/safe_wrap.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs)

To produce the __Rust Wrapper__ for BL602 IoT SDK...

-   [Expanded `safe_wrap` macros: `logs/sdk-expanded.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/logs/sdk-expanded.rs)

```rust
//  Expanded version of `safe_wrap` macros for the GPIO Rust Bindings
#[doc = "Configure a GPIO Pin for Output Mode. See `bl_gpio_enable_output` in \"Enable GPIO\" <https://lupyuen.github.io/articles/led#enable-gpio>"]
pub fn enable_output(pin: u8, pullup: u8, pulldown: u8)
    -> BlResult<()> {
    "----------Extern Decl----------";
    extern "C" {
        pub fn bl_gpio_enable_output(pin: u8, pullup: u8, pulldown: u8)
        -> ::cty::c_int;
    }
    "----------Validation----------";
    unsafe {
        "----------Call----------";
        let res =
            bl_gpio_enable_output(pin as u8, pullup as u8,
                                    pulldown as u8);
        "----------Result----------";
        match res { 0 => Ok(()), _ => Err(BlError::from(res)), }
    }
}

#[doc = "Set output value of GPIO Pin. See `bl_gpio_output_set` in \"Read and Write GPIO\" <https://lupyuen.github.io/articles/led#read-and-write-gpio>"]
pub fn output_set(pin: u8, value: u8) -> BlResult<()> {
    "----------Extern Decl----------";
    extern "C" {
        pub fn bl_gpio_output_set(pin: u8, value: u8)
        -> ::cty::c_int;
    }
    "----------Validation----------";
    unsafe {
        "----------Call----------";
        let res = bl_gpio_output_set(pin as u8, value as u8);
        "----------Result----------";
        match res { 0 => Ok(()), _ => Err(BlError::from(res)), }
    }
}
```

(More about __`doc`__ in the next section)

Note that the `safe_wrap` macro converts the BL602 return values to a __Rust Result Type__...

```rust
match res { 
    0 => Ok(()), 
    _ => Err(BlError::from(res))
}
```

Which enables the caller to check for errors with __`expect`__.

We build the docs and the test project with this script...

-   [`scripts/build.sh`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/scripts/build.sh)

-   [See the build log](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/README.md#build-log)

In the previous article we attempted to code the BL602 Rust Wrapper by hand...

-   [__"Run Rust RISC-V Firmware with BL602 IoT SDK"__](https://lupyuen.github.io/articles/rust)

![BL602 Rust Wrapper Documentation](https://lupyuen.github.io/images/adc-doc2.png)

## Inject the docs

_How did we create the docs for BL602 Rust Wrapper? (Pic above)_

-   [__Documentation for BL602 Rust Wrapper__](https://docs.rs/bl602-sdk)

Sadly BL602 IoT SDK doesn't have much documentation... But much of the SDK is already documented in [__"The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)!

So we linked each Rust Wrapper Function to the relevant section in "The RISC-V BL602 Book".

We do this through the __Rust `doc` Attribute__...

```rust
//  Expanded version of `safe_wrap` macros for the GPIO Rust Bindings
#[doc = "Configure a GPIO Pin for Output Mode. See `bl_gpio_enable_output` in \"Enable GPIO\" <https://lupyuen.github.io/articles/led#enable-gpio>"]
pub fn enable_output(pin: u8, pullup: u8, pulldown: u8) { ...

#[doc = "Set output value of GPIO Pin. See `bl_gpio_output_set` in \"Read and Write GPIO\" <https://lupyuen.github.io/articles/led#read-and-write-gpio>"]
pub fn output_set(pin: u8, value: u8) -> BlResult<()> { ...
```

![Documentation links to be injected](https://lupyuen.github.io/images/adc-doclink.png)

_How did we inject the doc links into the `doc` Attribute?_

For each Rust Wrapper Function, the links to ["The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book) are defined in this __Markdown Text File__...

-   [`bl602-sdk/doclinks.md`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-sdk/doclinks.md)

```text
| Function              | Description                           | Section             | URL
| --------------------- | ------------------------------------- | ------------------- | ---
| bl_gpio_enable_output | Configure a GPIO Pin for Output Mode. | Enable GPIO         | https://lupyuen.github.io/articles/led#enable-gpio
| bl_gpio_output_set    | Set the output value of a GPIO Pin.   | Read and Write GPIO | https://lupyuen.github.io/articles/led#read-and-write-gpio
```

When our Rust Firmware is compiled, the `safe_wrap` macro __loads the Markdown File__ into memory...

![Loading the documentation links](https://lupyuen.github.io/images/adc-doclink2.png)

[(Source)](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs#L532-L573)

And __injects the doc links__ into the `doc` attribute...

![Injecting the documentation links](https://lupyuen.github.io/images/adc-doclink3.png)

[(Source)](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs#L476-L530)

And the links to "The RISC-V BL602 Book" will magically appear in the Rust Docs!

-   [__Documentation for BL602 Rust Wrapper__](https://docs.rs/bl602-sdk)

![Renaming the Rust Functions](https://lupyuen.github.io/images/adc-prefix.png)

## Rename the functions

The `safe_wrap` macro also __shortens the names__ of the Rust Wrapper Functions.

Here's the original function from the BL602 IoT SDK...

```text
bl_gpio_enable_output
```

And here's the Rust Wrapper function shortened by `safe_wrap`...

```text
gpio::enable_output
```

`transform_function_name` contains the code that renames the functions: [`safe_wrap.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs#L476-L530)

![Testing the improvised Light Sensor on PineCone BL602](https://lupyuen.github.io/images/adc-title2.jpg)

_Testing the improvised Light Sensor on PineCone BL602_
