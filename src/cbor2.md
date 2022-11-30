# Encode Sensor Data with CBOR on Apache NuttX OS

📝 _10 Jan 2022_

Suppose we're creating an IoT Gadget with [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx) that transmits __Sensor Data__ from two sensors: __Temperature Sensor and Light Sensor__...

```json
{ 
  "t": 1234, 
  "l": 2345 
}
```

(Located in a Greenhouse perhaps)

And we're transmitting over a __low-power wireless network__ like LoRa, Zigbee or Bluetooth LE.

We could transmit __19 bytes of JSON__. But there's a more compact way to do it....

[__Concise Binary Object Representation (CBOR)__](https://en.wikipedia.org/wiki/CBOR), which works like a binary, compressed form of JSON.

And we need only __11 bytes of CBOR__!

![Encoding Sensor Data with CBOR](https://lupyuen.github.io/images/cbor2-title.jpg)

Today we'll learn to encode Sensor Data with the __TinyCBOR Library__ that we have ported to Apache NuttX OS...

-   [__lupyuen2/tinycbor-nuttx__](https://github.com/lupyuen2/tinycbor-nuttx)

The library has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2), but it should work on __any NuttX Platform__ (like ESP32)

[(__tinycbor-nuttx__ is a fork of TinyCBOR with minimal changes)](https://lupyuen.github.io/articles/cbor2#appendix-porting-tinycbor-to-nuttx)

_Must we scrimp and save every single byte?_

Yes, __every single byte matters__ for low-power wireless networks!

1.  Low-power wireless networks operate on Radio Frequency Bands that are __shared with many other gadgets__.

    They are prone to __collisions and interference__.

    The __smaller the data packet__, the higher the chance that it will be __transmitted successfully__!

1.  When we transmit LoRa packets to __The Things Network__ (the free public global LoRa network), we're limited by their [__Fair Use Policy__](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network).

    [(Roughly __12 bytes__ per message, assuming 10 messages per hour)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

    JSON is too big for this. But CBOR works well!

    (In the next article we'll watch the TinyCBOR Library in action for encoding Sensor Data in The Things Network)

# Encode Sensor Data with TinyCBOR

We begin by encoding one data field into CBOR...

```json
{ 
  "t": 1234
}
```

We call this a __CBOR Map__ that maps a __Key__ ("`t`") to a __Value__ (`1234`)...

> ![CBOR Map with 1 Key-Value Pair](https://lupyuen.github.io/images/cbor-map.png)

Let's look at the code from our NuttX App that encodes the above into CBOR...

-   [__lupyuen/tinycbor_test__](https://github.com/lupyuen/tinycbor_test)

## Output Buffer and CBOR Encoder

First we create an __Output Buffer__ that will hold the encoded CBOR data: [tinycbor_test_main.c](https://github.com/lupyuen/tinycbor_test/blob/main/tinycbor_test_main.c#L22-L82)

```c
#include "../libs/libtinycbor/src/cbor.h"  //  For TinyCBOR Library

/// Test CBOR Encoding for { "t": 1234 }
static void test_cbor(void) {

  //  Max output size is 50 bytes (which fits in a LoRa packet)
  uint8_t output[50];
```

[(50 bytes is the max packet size for LoRaWAN AS923 Data Rate 2)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

__Output Buffer Size__ is important: Calls to the __TinyCBOR library will fail__ if we run out of buffer space!

Next we define the __CBOR Encoder__ (from TinyCBOR) that will encode our data...

```c
  //  Our CBOR Encoder and Map Encoder
  CborEncoder encoder, mapEncoder;
```

As well as the __Map Encoder__ that will encode our CBOR Map.

We __initialise the CBOR Encoder__ like so...

```c
  //  Init our CBOR Encoder
  cbor_encoder_init(
    &encoder,        //  CBOR Encoder
    output,          //  Output Buffer
    sizeof(output),  //  Output Buffer Size
    0                //  Options (always 0)
  );
```

## Create Map Encoder

Now we create the __Map Encoder__ that will encode our CBOR Map...

```c
  //  Create a Map Encoder that maps keys to values
  CborError res = cbor_encoder_create_map(
    &encoder,     //  CBOR Encoder
    &mapEncoder,  //  Map Encoder
    1             //  Number of Key-Value Pairs
  );    
  assert(res == CborNoError);
```

The last parameter (`1`) is important: It must match the __Number of Key-Value Pairs__ (like `"t": 1234`) that we shall encode.

## Encode Key and Value

We encode the __Key__ ("`t`") into the CBOR Map...

```c
  //  First Key-Value Pair: Map the Key
  res = cbor_encode_text_stringz(
    &mapEncoder,  //  Map Encoder
    "t"           //  Key
  );    
  assert(res == CborNoError);
```

Followed by the __Value__ (`1234`)...

```c
  //  First Key-Value Pair: Map the Value
  res = cbor_encode_int(
    &mapEncoder,  //  Map Encoder 
    1234          //  Value
  );
  assert(res == CborNoError);
```

__cbor_encode_int__ encodes __64-bit Signed Integers__.

(We'll look at other data types in a while)

## Close Map Encoder

We're done with our CBOR Map, so we __close the Map Encoder__...

```c
  //  Close the Map Encoder
  res = cbor_encoder_close_container(
    &encoder,    //  CBOR Encoder
    &mapEncoder  //  Map Encoder
  );
  assert(res == CborNoError);
```

Our CBOR Encoding is complete!

## Get Encoded Output

To work with the Encoded CBOR Output, we need to know __how many bytes__ have been encoded...

```c
  //  How many bytes were encoded
  size_t output_len = cbor_encoder_get_buffer_size(
    &encoder,  //  CBOR Encoder
    output     //  Output Buffer
  );
  printf("CBOR Output: %d bytes\n", output_len);
```

For the demo we __dump the encoded CBOR data__ to the console...

```c
  //  Dump the encoded CBOR output (6 bytes):
  //  0xa1 0x61 0x74 0x19 0x04 0xd2
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\n", output[i]);
  }
}
```

And that's how we call the TinyCBOR Library to work with CBOR data!

Let's watch what happens when we run the firmware...

> ![Calling the TinyCBOR Library](https://lupyuen.github.io/images/cbor-code.png)

## Download Source Code

To test CBOR Encoding on NuttX, download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch cbor https://github.com/lupyuen/nuttx nuttx
git clone --recursive --branch cbor https://github.com/lupyuen/nuttx-apps apps
```

Or if we prefer to __add TinyCBOR__ to our NuttX Project, follow these instructions...

-   [__"Install TinyCBOR Library"__](https://github.com/lupyuen2/tinycbor-nuttx)

-   [__"Install TinyCBOR Test App"__](https://github.com/lupyuen/tinycbor_test)

[(__For PineDio Stack BL604:__ The TinyCBOR Library and Test App are already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

## Build The Firmware

Let's build the NuttX Firmware with TinyCBOR inside...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded the __NuttX Source Code__...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/cbor2#download-source-code)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  In menuconfig, check the box for...

    __"Library Routines"__ → __"TinyCBOR Library"__

1.  Check the box for...

    __"Application Configuration"__ → __"Examples"__ → __"TinyCBOR Test App"__

1.  Save the configuration and exit menuconfig

    [(See the .config for BL602 and BL604)](https://gist.github.com/lupyuen/63393052eba1f347422ef24c589fb9f4)

1.  Build, flash and run the NuttX Firmware...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/cbor2#appendix-build-flash-and-run-nuttx)

## Magic Happens

In the NuttX Shell, enter...

```bash
tinycbor_test
```

We'll see 6 bytes of __Encoded CBOR Output__ for "test_cbor"...

```text
test_cbor: Encoding { "t": 1234 }
CBOR Output: 6 bytes
  0xa1
  0x61
  0x74
  0x19
  0x04
  0xd2
```

We have just compressed __10 bytes of JSON__...

```json
{ 
  "t": 1234
}
```

Into __6 bytes of CBOR__.

We have scrimped and saved __4 bytes__!

![Encoded CBOR Output](https://lupyuen.github.io/images/cbor2-run3.png)

# Add Another Field

Now we __add another field__ to our CBOR Encoding...

```json
{ 
  "t": 1234, 
  "l": 2345 
}
```

And watch how our program changes to accommodate the second field.

> ![CBOR Map with 2 Key-Value Pairs](https://lupyuen.github.io/images/cbor-map2.png)

## Modify Map Encoder

We begin the same way as before: [tinycbor_test_main.c](https://github.com/lupyuen/tinycbor_test/blob/main/tinycbor_test_main.c#L84-L158)

```c
/// Test CBOR Encoding for { "t": 1234, "l": 2345 }
static void test_cbor2(void) {

  //  Max output size is 50 bytes (which fits in a LoRa packet)
  uint8_t output[50];

  //  Our CBOR Encoder and Map Encoder
  CborEncoder encoder, mapEncoder;

  //  Init our CBOR Encoder
  cbor_encoder_init( ... );
```

Now we __create the Map Encoder__ with a tiny modification...

```c  
  //  Create a Map Encoder that maps keys to values
  CborError res = cbor_encoder_create_map(
    &encoder,     //  CBOR Encoder
    &mapEncoder,  //  Map Encoder
    2             //  Number of Key-Value Pairs
  );    
  assert(res == CborNoError);
```

We changed the __Number of Key-Value Pairs__ to `2`.

(Previously it was `1`)

## Encode First Key and Value

We encode the __First Key and Value__ the same way as before...

```c
  //  First Key-Value Pair: Map the Key
  res = cbor_encode_text_stringz(
    &mapEncoder,  //  Map Encoder
    "t"           //  Key
  );    
  assert(res == CborNoError);

  //  First Key-Value Pair: Map the Value
  res = cbor_encode_int(
    &mapEncoder,  //  Map Encoder 
    1234          //  Value
  );
  assert(res == CborNoError);
```

(Yep no changes above)

## Encode Second Key and Value

This part is new: We encode the __Second Key and Value__ ("`l`" and `2345`)...

```c
  //  Second Key-Value Pair: Map the Key
  res = cbor_encode_text_stringz(
    &mapEncoder,  //  Map Encoder
    "l"           //  Key
  );    
  assert(res == CborNoError);

  //  Second Key-Value Pair: Map the Value
  res = cbor_encode_int(
    &mapEncoder,  //  Map Encoder 
    2345          //  Value
  );
  assert(res == CborNoError);
```

And the rest of the code is the same...

```c
  //  Close the Map Encoder
  res = cbor_encoder_close_container( ... );

  //  How many bytes were encoded
  size_t output_len = cbor_encoder_get_buffer_size( ... );

  //  Dump the encoded CBOR output (11 bytes):
  //  0xa2 0x61 0x74 0x19 0x04 0xd2 0x61 0x6c 0x19 0x09 0x29
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\n", output[i]);
  }
}
```

Recap: To add a data field to our CBOR Encoding, we...

1.  Modify the call to __cbor_encoder_create_map__ and update the __Number of Key-Value Pairs__ (`2`)

1.  Add the new __Key and Value__  ("`l`" and `2345`) to the CBOR Map

Everything else stays the same.

> ![Add a second field](https://lupyuen.github.io/images/cbor-code2.png)

## Watch the Magic

In the NuttX Shell, enter...

```bash
tinycbor_test
```

We'll see 11 bytes of __Encoded CBOR Output__ for "test_cbor2"...

```text
test_cbor2: Encoding { "t": 1234, "l": 2345 }
CBOR Output: 11 bytes
  0xa2
  0x61
  0x74
  0x19
  0x04
  0xd2
  0x61
  0x6c
  0x19
  0x09
  0x29
```

We have just compressed __19 bytes of JSON__ into __11 bytes of CBOR__.

__8 bytes__ saved!

![Encoding Sensor Data with CBOR](https://lupyuen.github.io/images/cbor2-title.jpg)

# CBOR Data Types

_We've been encoding 64-bit Signed Integers. What other Data Types can we encode?_

Below are the __CBOR Data Types__ and their respective __Encoder Functions__ from the TinyCBOR Library...

## Numbers

-   __Signed Integer__ (64 bits): [cbor_encode_int](https://intel.github.io/tinycbor/current/a00046.html#gabbf6e10fd963d673f5ad293dff4a67a9)

    (We called this earlier. Works for positive and negative integers)

-   __Unsigned Integer__ (64 bits): [cbor_encode_uint](https://intel.github.io/tinycbor/current/a00046.html#ga2b898ce6f5821c5aba8b6f0020c4b5ba)

    (Positive integers only)

-   __Negative Integer__ (64 bits): [cbor_encode_negative_int](https://intel.github.io/tinycbor/current/a00046.html#ga0e84daa854e0480f4a3758bcb46b9b60)

    (Negative integers only)

-   __Floating-Point Number__ (16, 32 or 64 bits): 

    (See the next chapter)

## Strings

-   __Null-Terminated String__: [cbor_encode_text_stringz](https://intel.github.io/tinycbor/current/a00046.html#ga6df3eff486535322f66584dc5431f9e9)

    (We called this earlier to encode our Keys)

-   __Text String__: [cbor_encode_text_string](https://intel.github.io/tinycbor/current/a00046.html#ga4fa673c63e85b1fd6f8067aca4ccdde4)

    (For strings that are not null-terminated)

-   __Byte String__: [cbor_encode_byte_string](https://intel.github.io/tinycbor/current/a00046.html#ga1260b72bb0f067fd3c68d49a6b5f58d0)

    (For strings containing binary data)

## Other Types

-   __Boolean__: [cbor_encode_boolean](https://intel.github.io/tinycbor/current/a00046.html#ga857154b97cad978f4afb3e2f809051bd)

-   __Null__: [cbor_encode_null](https://intel.github.io/tinycbor/current/a00046.html#ga30b769ff1da73ed8b4536f551347c5ed)

-   __Undefined__: [cbor_encode_undefined](https://intel.github.io/tinycbor/current/a00046.html#ga9d9f0668e2cf69352a45095006efab4f)

For the complete list of CBOR Encoder Functions, refer to the TinyCBOR docs...

-   [__TinyCBOR: Encoding To CBOR__](https://intel.github.io/tinycbor/current/a00046.html)

CBOR Data Types are explained in the CBOR Specification...

-   [__CBOR Data Models__](https://www.rfc-editor.org/rfc/rfc8949.html#name-cbor-data-models)

To experiment with CBOR Encoding and Decoding, try the [__CBOR Playground__](http://cbor.me/)...

![CBOR Playground](https://lupyuen.github.io/images/grafana-cbor5.png)

# Floating-Point Numbers

The CBOR spec says that there are [__3 ways to encode floats__](https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and-)...

-   [__Half-Precision Float__](https://en.m.wikipedia.org/wiki/Half-precision_floating-point_format) (16 bits): [cbor_encode_half_float](https://intel.github.io/tinycbor/current/a00046.html#gad8e5a125cfaceb9a32528e620e003bc6)

    (__3.3__ significant decimal digits. [See this](https://en.m.wikipedia.org/wiki/Half-precision_floating-point_format#IEEE_754_half-precision_binary_floating-point_format:_binary16))

-   [__Single-Precision Float__](https://en.m.wikipedia.org/wiki/Single-precision_floating-point_format) (32 bits): [cbor_encode_float](https://intel.github.io/tinycbor/current/a00046.html#gae981ee934ef22ce4c5b52f8069e1b15c)

    (__6 to 9__ significant decimal digits. [See this](https://en.m.wikipedia.org/wiki/Single-precision_floating-point_format#IEEE_754_single-precision_binary_floating-point_format:_binary32))

-   [__Double-Precision Float__](https://en.m.wikipedia.org/wiki/Double-precision_floating-point_format) (64 bits): [cbor_encode_double](https://intel.github.io/tinycbor/current/a00046.html#ga211aa80dc5b793ee8dd74d24cb9e7ca6)

    (__15 to 17__ significant decimal digits. [See this](https://en.m.wikipedia.org/wiki/Double-precision_floating-point_format#IEEE_754_double-precision_binary_floating-point_format:_binary64))

_How do we select the proper float encoding?_

Suppose we're encoding Temperature Data (like `12.34` ºC) that could range from __`0.00` ºC to `99.99` ºC__.

This means that we need __4 significant decimal digits__.

Which is too many for a Half-Precision Float (16 bits), but OK for a __Single-Precision Float__ (32 bits).

Thus we need __5 bytes__ to encode the Temperature Data. (Including the CBOR Initial Byte)

## Encode Floats as Integers

_Huh? If we encode an integer like `1234`, we need only __3 bytes__!_

That's why in this article we __scale up 100 times__ for the Temperature Data and __encode as an integer__ instead.

(So `1234` actually means `12.34` ºC)

__2 bytes__ saved!

(Our scaling of Sensor Data is similar to [Fixed-Point Representation](https://en.wikipedia.org/wiki/Fixed-point_arithmetic#Fixed-point_representation))

## Accuracy and Precision

_Is it meaningful to record temperatures that are accurate to 0.01 ºC?_

_How much accuracy do we need for Sensor Data anyway?_

The accuracy for our Sensor Data depends on...

1. Our monitoring requirements, and

1. Accuracy of our sensors

Learn more about Accuracy and Precision of Sensor Data...

-   [IoT’s Lesser Known Power: “Good Enough” Data Accuracy](https://kotahi.net/iots-lesser-known-power-good-enough-data-accuracy/)

# Decode CBOR

_For decoding CBOR packets, can we call the TinyCBOR Library?_

Sure, we can call the __Decoder Functions__ in the TinyCBOR Library...

-   [__TinyCBOR: Parsing CBOR streams__](https://intel.github.io/tinycbor/current/a00047.html)

-   [__TinyCBOR: Converting CBOR to text__](https://intel.github.io/tinycbor/current/a00048.html)

-   [__TinyCBOR: Converting CBOR to JSON__](https://intel.github.io/tinycbor/current/a00049.html)

If we're transmitting CBOR packets to a server (or cloud), we can decode them with a __CBOR Library for Node.js, Go, Rust,__ ...

-   [__CBOR Implementations__](https://cbor.io/impls.html)

We can decode CBOR Payloads in __The Things Network__ with a CBOR Payload Formatter...

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

For Grafana we used a __Go Library for CBOR__...

-   [__"Decode CBOR in Go"__](https://lupyuen.github.io/articles/grafana#decode-cbor-in-go)

There's even a CBOR Library for __Roblox and Lua Scripting__...

-   [__"Decode Base64 and CBOR in Roblox"__](https://github.com/lupyuen/roblox-the-things-network#decode-base64-and-cbor-in-roblox)

TinyCBOR is available on various __Embedded Operating Systems__...

-   [__Apache Mynewt__](https://github.com/apache/mynewt-core/tree/master/encoding/tinycbor)

-   [__RIOT__](https://doc.riot-os.org/group__pkg__tinycbor.html)

-   [__Zephyr__](https://docs.zephyrproject.org/latest/reference/kconfig/CONFIG_TINYCBOR.html)

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# What's Next

In the next few articles we'll build a __complete IoT Sensor Device__ with NuttX...

1.  We'll take the __LoRaWAN Stack__ from the previous article...

    [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

1.  Read BL602's [__Internal Temperature Sensor__](https://lupyuen.github.io/articles/tsen) to get real Sensor Data...

    [__"ADC and Internal Temperature Sensor Library"__](https://github.com/lupyuen/bl602_adc_test)

1.  Compress the Sensor Data with CBOR

    (As explained in this article)

1.  Transmit the compressed Sensor Data to [__The Things Network__](https://lupyuen.github.io/articles/ttn) over LoRaWAN
    
    (Pic below)

But first we'll take a short detour to explore [__Rust on NuttX__](https://lupyuen.github.io/articles/nuttx#rust-on-nuttx)...

-   [__"Rust on Apache NuttX OS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

Stay Tuned!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/embedded_oc/comments/s0507e/encode_sensor_data_with_cbor_on_apache_nuttx_os/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/cbor2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/cbor2.md)

![NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN](https://lupyuen.github.io/images/lorawan3-ttn.png)

_NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN_

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1478613072973418498?s=20)

# Appendix: Build, Flash and Run NuttX

_(For BL602 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Build NuttX

Follow these steps to build NuttX for BL602 or ESP32...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded the __NuttX Source Code__ and configured the build...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/cbor2#download-source-code)

    [__"Build the Firmware"__](https://lupyuen.github.io/articles/cbor2#build-the-firmware)

1.  To build NuttX, enter this command...

    ```bash
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log for BL602)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"ESP32 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

__For ESP32:__ [__See instructions here__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html#flashing) [(Also check out this article)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

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

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## For Linux: Change "/dev/ttyUSB0" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the BL602 / BL604 Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/nuttx/issues/4336)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

__For ESP32:__ Use Picocom to connect to ESP32 over UART...

```bash
picocom -b 115200 /dev/ttyUSB0
```

[(More about this)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

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

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

__macOS Tip:__ Here's the script I use to build, flash and run NuttX on macOS, all in a single step: [run.sh](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

![Script to build, flash and run NuttX on macOS](https://lupyuen.github.io/images/spi2-script.png)

[(Source)](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

# Appendix: Porting TinyCBOR to NuttX

Below are the fixes we made while porting the TinyCBOR library to NuttX...

-   [__"Fix open_memstream for NuttX"__](https://github.com/lupyuen2/tinycbor-nuttx/commit/cc12fca92c69f36a2be9ea6df7677420dc7a84dd)
