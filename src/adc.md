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

Let's __copy the last 1,000 ADC Samples__ from the DMA Context (in RAM) to a Static Buffer `adc_data`...

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

TODO

[`sdk_app_rust_gpio`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_gpio)

# BL602 ADC in Rust

TODO

Let's study the __Rust Firmware for BL602 ADC__: [`sdk_app_rust_adc`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc)

## Definitions

TODO

From [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L1-L37)

```rust
#![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems

//  Import Libraries
use core::{          //  Rust Core Library
  fmt::Write,        //  String Formatting    
  mem::transmute,    //  Pointer Casting
  panic::PanicInfo,  //  Panic Handler
};
use bl602_sdk::{     //  Rust Wrapper for BL602 IoT SDK
  adc,               //  ADC HAL
  dma,               //  DMA HAL
  puts,              //  Console Output
  Ptr,               //  C Pointer
  String,            //  Strings (limited to 64 chars)
};

/// GPIO Pin Number that will be configured as ADC Input.
/// PineCone Blue LED is connected on BL602 GPIO 11.
/// PineCone Green LED is connected on BL602 GPIO 14.
/// Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
/// TODO: Change the GPIO Pin Number for your BL602 board
const ADC_GPIO: i32 = 11;

/// We set the ADC Frequency to 10 kHz according to <https://wiki.analog.com/university/courses/electronics/electronics-lab-led-sensor?rev=1551786227>
/// This is 10,000 samples per second.
const ADC_FREQUENCY: u32 = 10000;  //  Hz

/// We shall read 100 ADC samples, which will take 0.01 seconds
const ADC_SAMPLES: usize = 100;

/// Set ADC Gain to Level 1 to increase the ADC sensitivity.
/// To disable ADC Gain, set `ADC_GAIN1` and `ADC_GAIN2` to `ADC_PGA_GAIN_NONE`.
/// See <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_adc.h#L133-L144>
const ADC_GAIN1: u32 = ADC_PGA_GAIN_1;
const ADC_GAIN2: u32 = ADC_PGA_GAIN_1;
const ADC_PGA_GAIN_1: u32 = 1;  //  From <https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_adc.h#L133-L144>
```

## Initialise the ADC Channel

TODO

From [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L39-L100)

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

  //  Only these GPIOs are supported: 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
  assert!(ADC_GPIO==4 || ADC_GPIO==5 || ADC_GPIO==6 || ADC_GPIO==9 || ADC_GPIO==10 || ADC_GPIO==11 || ADC_GPIO==12 || ADC_GPIO==13 || ADC_GPIO==14 || ADC_GPIO==15);

  //  For Single-Channel Conversion Mode, frequency must be between 500 and 16,000 Hz
  assert!(ADC_FREQUENCY >= 500 && ADC_FREQUENCY <= 16000);

  //  Init the ADC Frequency for Single-Channel Conversion Mode
  adc::freq_init(1, ADC_FREQUENCY)
    .expect("ADC Freq failed");

  //  Init the ADC GPIO for Single-Channel Conversion Mode
  adc::init(1, ADC_GPIO)
    .expect("ADC Init failed");

  //  Enable ADC Gain to increase the ADC sensitivity
  let rc = unsafe { set_adc_gain(ADC_GAIN1, ADC_GAIN2) };  //  Unsafe because we are calling C function
  assert!(rc == 0);

  //  Init DMA for the ADC Channel for Single-Channel Conversion Mode
  adc::dma_init(1, ADC_SAMPLES as u32)
    .expect("DMA Init failed");

  //  Configure the GPIO Pin as ADC Input, no pullup, no pulldown
  adc::gpio_init(ADC_GPIO)
    .expect("ADC GPIO failed");

  //  Get the ADC Channel Number for the GPIO Pin
  let channel = adc::get_channel_by_gpio(ADC_GPIO)
    .expect("ADC Channel failed");

  //  Get the DMA Context for the ADC Channel
  let ptr = dma::find_ctx_by_channel(adc::ADC_DMA_CHANNEL as i32)
    .expect("DMA Ctx failed");

  //  Cast the returned C Pointer (void *) to a DMA Context Pointer (adc_ctx *)
  let ctx = unsafe {     //  Unsafe because we are casting a pointer
    transmute::<         //  Cast the type...
      Ptr,               //  From C Pointer (void *)
      *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
    >(ptr)               //  For this pointer
  };

  //  Indicate that the GPIO has been configured for ADC
  unsafe {  //  Unsafe because we are dereferencing a pointer
    (*ctx).chan_init_table |= 1 << channel;
  }

  //  Start reading the ADC via DMA
  adc::start()
    .expect("ADC Start failed");
}
```

## Read the ADC Channel

TODO

From [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L102-L165)

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
  //  Array that will store last 1,000 ADC Samples
  let mut adc_data: [u32; ADC_SAMPLES]
    = [0; ADC_SAMPLES];  //  Init array to zeroes

  //  Get the ADC Channel Number for the GPIO Pin
  let channel = adc::get_channel_by_gpio(ADC_GPIO)
    .expect("ADC Channel failed");
  
  //  Get the DMA Context for the ADC Channel
  let ptr = dma::find_ctx_by_channel(adc::ADC_DMA_CHANNEL as i32)
    .expect("DMA Ctx failed");

  //  Cast the returned C Pointer (void *) to a DMA Context Pointer (adc_ctx *)
  let ctx = unsafe {     //  Unsafe because we are casting a pointer
    transmute::<         //  Cast the type...
      Ptr,               //  From C Pointer (void *)
      *mut adc::adc_ctx  //  To DMA Context Pointer (adc_ctx *)
    >(ptr)               //  For this pointer
  };

  //  Verify that the GPIO has been configured for ADC
  unsafe {  //  Unsafe because we are dereferencing a pointer
    assert!(((1 << channel) & (*ctx).chan_init_table) != 0);
  }

  //  If ADC Sampling is not finished, try again later    
  if unsafe { (*ctx).channel_data.is_null() } {  //  Unsafe because we are dereferencing a pointer
    puts("ADC Sampling not finished");
    return;
  }

  //  Copy the read ADC Samples to the static array
  unsafe {                    //  Unsafe because we are copying raw memory
    core::ptr::copy(          //  Copy the memory...
      (*ctx).channel_data,    //  From Source (ADC DMA data)
      adc_data.as_mut_ptr(),  //  To Destination (mutable pointer to adc_data)
      adc_data.len()          //  Number of Items (each item is uint32 or 4 bytes)
    );    
  }

  //  Compute the average value of the ADC Samples
  let mut sum = 0;
  for i in 0..ADC_SAMPLES {
    //  Scale up the ADC Sample to the range 0 to 3199
    let scaled = ((adc_data[i] & 0xffff) * 3200) >> 16;
    sum += scaled;
  }
  let avg = sum / ADC_SAMPLES as u32;

  //  Format the output and display it
  let mut buf = String::new();
  write!(buf, "[Rust] Average: {}", avg)
    .expect("buf overflow");
  puts(&buf);
}
```

# Build the BL602 Rust Firmware

TODO

![](https://lupyuen.github.io/images/adc-build.png)

# Flash the BL602 Rust Firmware

TODO

# Run the BL602 Rust Firmware

TODO

```text
[In darkness]

# init_adc
[Rust] Init ADC
# read_adc
[Rust] Average: 1417
# read_adc
[Rust] Average: 1417
# read_adc
[Rust] Average: 1417

[In sunlight]

# read_adc
[Rust] Average: 1414
# read_adc
[Rust] Average: 1411
# read_adc
[Rust] Average: 1411
# read_adc
[Rust] Average: 1412

[In darkness]

# read_adc
[Rust] Average: 1417
# read_adc
[Rust] Average: 1417
# read_adc
[Rust] Average: 1417
```

![](https://lupyuen.github.io/images/adc-demo2.png)

# Compare C and Rust

TODO

![](https://lupyuen.github.io/images/adc-compare.png)

# Rust Wrapper for BL602 IoT SDK

TODO

From [`Cargo.toml`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/Cargo.toml#L9-L11)

```text
# External Rust libraries used by this module.  See crates.io.
[dependencies]
bl602-sdk = "0.0.6"  # Rust Wrapper for BL602 IoT SDK: https://crates.io/crates/bl602-sdk
```

# Call C Functions from Rust

TODO

From [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_rust_adc/rust/src/lib.rs#L180-L184)

```rust
extern "C" {  //  Import C Function
  /// Enable ADC Gain to increase the ADC sensitivity.
  /// Defined in customer_app/sdk_app_rust_adc/sdk_app_rust_adc/demo.c
  fn set_adc_gain(gain1: u32, gain2: u32) -> i32;
}
```

# Convert C Pointers to Rust

TODO

![](https://lupyuen.github.io/images/adc-cast.png)

# Why Sunlight?

TODO

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
