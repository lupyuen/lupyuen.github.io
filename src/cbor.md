# Encode Sensor Data with CBOR on BL602

📝 _5 Oct 2021_

Suppose we're creating an IoT Gadget that transmits __Sensor Data__ from a __Temperature Sensor__ and a __Light Sensor__...

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

![Encoding Sensor Data with CBOR on BL602](https://lupyuen.github.io/images/cbor-title.jpg)

Today we'll learn to encode Sensor Data with the __TinyCBOR Library__ that we have ported to the [__BL602__](https://lupyuen.github.io/articles/pinecone) and [__BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V SoCs...

-   [__lupyuen/tinycbor-bl602__](https://github.com/lupyuen/tinycbor-bl602)

The library has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2), but it should work on __any BL602 or BL604 Board__: [__Ai-Thinker Ai-WB2__](https://docs.ai-thinker.com/en/wb2), PineCone BL602, Pinenut, DT-BL10, MagicHome BL602, ...

_Must we scrimp and save every single byte?_

Yes, __every single byte matters__ for low-power wireless networks!

1.  Low-power wireless networks operate on Radio Frequency Bands that are __shared with many other gadgets__.

    They are prone to __collisions and interference__.

    The __smaller the data packet__, the higher the chance that it will be __transmitted successfully__!

1.  When we transmit LoRa packets to __The Things Network__ (the free public global LoRa network), we're limited by their [__Fair Use Policy__](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network).

    [(Roughly __12 bytes__ per message, assuming 10 messages per hour)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

    JSON is too big for this. But CBOR works well!

    In a while we'll watch the TinyCBOR Library in action for encoding Sensor Data in The Things Network.

# Encode Sensor Data with TinyCBOR

We begin by encoding one data field into CBOR...

```json
{ 
  "t": 1234
}
```

We call this a __CBOR Map__ that maps a __Key__ ("`t`") to a __Value__ (`1234`)...

> ![CBOR Map with 1 Key-Value Pair](https://lupyuen.github.io/images/cbor-map.png)

Let's look at the code from our firmware that encodes the above into CBOR...

-   [__pinedio_cbor Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_cbor)

## Output Buffer and CBOR Encoder

First we create an __Output Buffer__ that will hold the encoded CBOR data: [pinedio_cbor/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_cbor/pinedio_cbor/demo.c#L9-L66)

```c
/// Test CBOR Encoding for { "t": 1234 }
static void test_cbor(char *buf, int len, int argc, char **argv) {

  //  Max output size is 50 bytes (which fits in a LoRa packet)
  uint8_t output[50];
```

[(50 bytes is the max packet size for The Things Network AS923 DR2)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

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
  printf("CBOR Output: %d bytes\r\n", output_len);
```

For the demo we __dump the encoded CBOR data__ to the console...

```c
  //  Dump the encoded CBOR output (6 bytes):
  //  0xa1 0x61 0x74 0x19 0x04 0xd2
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\r\n", output[i]);
  }
}
```

And that's how we call the TinyCBOR Library to work with CBOR data!

Let's watch what happens when we run the firmware...

> ![Calling the TinyCBOR Library](https://lupyuen.github.io/images/cbor-code.png)

## Magic Happens

Follow the steps in the Appendix to __build, flash and run__ the CBOR Firmware...

-   [__"Build and Run CBOR Firmware"__](https://lupyuen.github.io/articles/cbor#appendix-build-and-run-cbor-firmware)

At the BL602 / BL604 Command Prompt, enter...

```bash
test_cbor
```

We'll see 6 bytes of __Encoded CBOR Output__...

```text
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

![Encoded CBOR Output](https://lupyuen.github.io/images/cbor-output2.png)

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

We begin the same way as before: [pinedio_cbor/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_cbor/pinedio_cbor/demo.c#L68-L139)

```c
/// Test CBOR Encoding for { "t": 1234, "l": 2345 }
static void test_cbor2( ... ) {

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
    printf("  0x%02x\r\n", output[i]);
  }
}
```

Recap: To add a data field to our CBOR Encoding, we...

1.  Modify the call to __cbor_encoder_create_map__ and update the __Number of Key-Value Pairs__ (`2`)

1.  Add the new __Key and Value__  ("`l`" and `2345`) to the CBOR Map

Everything else stays the same.

> ![Add a second field](https://lupyuen.github.io/images/cbor-code2.png)

## Watch the Magic

Follow the steps in the Appendix to __build, flash and run__ the CBOR Firmware...

-   [__"Build and Run CBOR Firmware"__](https://lupyuen.github.io/articles/cbor#appendix-build-and-run-cbor-firmware)

At the BL602 / BL604 Command Prompt, enter...

```bash
test_cbor2
```

This time we'll see 11 bytes of __Encoded CBOR Output__...

```text
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

If we wish to call TinyCBOR from an existing BL602 / BL604 project, check the Appendix...

-   [__"Add TinyCBOR to Your Project"__](https://lupyuen.github.io/articles/cbor#appendix-add-tinycbor-to-your-project)

![Encoding Sensor Data with CBOR on BL602](https://lupyuen.github.io/images/cbor-title.jpg)

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

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

_PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)_

# LoRaWAN With CBOR

Let's watch CBOR in action on a real wireless network... As [__PineDio Stack BL604__](https://lupyuen.github.io/articles/lorawan2) talks to [__The Things Network over LoRaWAN__](https://lupyuen.github.io/articles/ttn)!

In a while we shall run this LoRaWAN Command...

```bash
las_app_tx_cbor 2 0 1234 2345
```

This means...

-   Transmit a LoRaWAN Packet to __Port 2__

-   That contains the values __`t=1234`__ (Temperature), __`l=2345`__ (Light Level)

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

Our CBOR Encoding happens inside the __las_app_tx_cbor__ function: [pinedio_lorawan/lorawan.c](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L893-L1050)

```c
/// Transmit CBOR payload to LoRaWAN. The command
///   las_app_tx_cbor 2 0 1234 2345
/// Will transmit the CBOR payload
///   { "t": 1234, "l": 2345 }
/// To port 2, unconfirmed (0).
void las_cmd_app_tx_cbor( ... ) {
  ...
  //  Get the "t" value from command args
  uint16_t t = parse_ull_bounds(argv[3], 0, 65535, &rc);
    
  //  Get the "l" value from command args
  uint16_t l = parse_ull_bounds(argv[4], 0, 65535, &rc);
```

In the code above we get the values of __"`t`"__ (Temperature Sensor) and __"`l`"__ (Light Sensor) from the command line arguments.

(Our sensors are simulated for now)

Watch how we encode "`t`" and "`l`" and transmit them...

## Encode Sensor Data

This part looks super familiar: We initialise our __CBOR Encoder and Map Encoder__...

```c
  //  Encode into CBOR for { "t": ????, "l": ???? }
  //  Max output size is 50 bytes (which fits in a LoRa packet)
  uint8_t output[50];

  //  Our CBOR Encoder and Map Encoder
  CborEncoder encoder, mapEncoder;

  //  Init our CBOR Encoder
  cbor_encoder_init( ... );

  //  Create a Map Encoder that maps keys to values (2 pairs)
  CborError res = cbor_encoder_create_map( ... );
```

Next we encode the __Key and Value for "`t`"__...

```c
  //  First Key-Value Pair: Map the Key ("t")
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
```

Then we encode the __Key and Value for "`l`"__...

```c
  //  Second Key-Value Pair: Map the Key ("l")
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
```

And we __close the Map Encoder__...

```c
  //  Close the Map Encoder
  res = cbor_encoder_close_container( ... );

  //  How many bytes were encoded
  size_t output_len = cbor_encoder_get_buffer_size( ... );
```

## Send LoRaWAN Packet

We're ready to transmit our encoded Sensor Data!

First we __allocate a Packet Buffer__ for our LoRaWAN Packet...

```c
  //  Validate the output size
  if (lora_app_mtu() < output_len) { return; }  //  Output too big

  //  Attempt to allocate a Packet Buffer
  struct pbuf *om = lora_pkt_alloc(output_len);
  if (!om) { return; }  //  Unable to allocate Packet Buffer
```

Next we __copy our encoded Sensor Data__ into the Packet Buffer...

```c
  //  Copy the encoded CBOR into the Packet Buffer
  rc = pbuf_copyinto(om, 0, output, output_len);
  assert(rc == 0);
```

Finally we __transmit the Packet Buffer__...

```c
  //  Send the Packet Buffer
  rc = lora_app_port_send(port, mcps_type, om);

  //  Omitted: Check the return code
```

That's how we encode Sensor Data and transmit over LoRaWAN!

![Encoding Sensor Data and transmitting over LoRaWAN](https://lupyuen.github.io/images/cbor-code3.png)

## CBOR In Action

Follow the instructions in the Appendix to __build, flash and run__ the LoRaWAN Firmware...

-   [__"Build and Run LoRaWAN Firmware"__](https://lupyuen.github.io/articles/cbor#appendix-build-and-run-lorawan-firmware)

At the BL602 / BL604 Command Prompt, enter this command...

```bash
las_app_tx_cbor 2 0 1234 2345
```

This means...

-   Transmit a LoRaWAN Packet to __Port 2__

-   That contains the values __`t=1234`__ (Temperature), __`l=2345`__ (Light Level)

-   `0` means that this is an __Unconfirmed Message__

    (Because we're not expecting an acknowledgement)

Our Sensor Data has been transmitted via LoRaWAN to The Things Network!

_How do we see the Sensor Data in The Things Network?_

We could use __Grafana__, the open source tool for data visualisation...

![Sensor Data visualised with Grafana](https://lupyuen.github.io/images/cbor-grafana.jpg)

Check out this article for the details...

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

See also this demo of PineDio Stack with Roblox and The Things Network...

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox#digital-twin-demo)

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

# What's Next

For the next article we shall take a quick detour and explore PineDio Stack transmitting Sensor Data to [__Roblox via The Things Network__](https://github.com/lupyuen/roblox-the-things-network).

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

Then we shall head back and transmit BL602 / BL604's __Internal Temperature Sensor Data__ to The Things Network.

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/q1ir5x/encode_sensor_data_with_cbor_on_bl602/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/cbor.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/cbor.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1441626008931602433)

# Appendix: Build and Run CBOR Firmware

Here are the steps to build, flash and run the __CBOR Firmware for BL602 and BL604__...

-   [__bl_iot_sdk/customer_app/pinedio_cbor__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_cbor)

(If we wish to add the TinyCBOR Library to an existing BL602 / BL604 project, check the next chapter)

## Build CBOR Firmware

Download the firmware...

```bash
## Download the master branch of lupyuen's bl_iot_sdk
git clone --recursive --branch master https://github.com/lupyuen/bl_iot_sdk
```

Build the Firmware Binary File `pinedio_cbor.bin`...

```bash
## TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

cd bl_iot_sdk/customer_app/pinedio_cbor
make

## For WSL: Copy the firmware to /mnt/c/blflash, which refers to c:\blflash in Windows
mkdir /mnt/c/blflash
cp build_out/pinedio_cbor.bin /mnt/c/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

## Flash CBOR Firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `pinedio_cbor.bin` has been copied to the `blflash` folder.

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

Enter these commands to flash `pinedio_cbor.bin` to BL602 / BL604 over UART...

```bash
## For Linux:
blflash flash build_out/pinedio_cbor.bin \
    --port /dev/ttyUSB0

## For macOS:
blflash flash build_out/pinedio_cbor.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

## For Windows: Change COM5 to the BL602 / BL604 Serial Port
blflash flash c:\blflash\pinedio_cbor.bin --port COM5
```

(For WSL: Do this under plain old Windows CMD, not WSL, because blflash needs to access the COM port)

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run CBOR Firmware

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

# Appendix: Add TinyCBOR to Your Project

Here are the steps for __adding the TinyCBOR Library__ to an existing BL602 or BL604 project...

-   [__lupyuen/tinycbor-bl602__](https://github.com/lupyuen/tinycbor-bl602)

We assume there's an existing __bl_iot_sdk__ folder.

Add __tinycbor-bl602__ as a submodule under __bl_iot_sdk/components/3rdparty__...

```bash
cd bl_iot_sdk/components/3rdparty
git submodule add https://github.com/lupyuen/tinycbor-bl602
```

Edit the __Makefile__ for our project...

```text
## Insert this line into the COMPONENTS block
COMPONENTS_TINYCBOR := tinycbor-bl602
...

## Insert this line into INCLUDE_COMPONENTS block
INCLUDE_COMPONENTS += $(COMPONENTS_TINYCBOR)
...

## This should appear after INCLUDE_COMPONENTS block
include $(BL60X_SDK_PATH)/make_scripts_riscv/project.mk
```

[(See a sample Makefile)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_cbor/Makefile#L21-L36)

Include __"cbor.h"__ in our source file...

```c
##include "cbor.h"  //  For Tiny CBOR Library
```

And start coding with TinyCBOR!

[(See a sample source file)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_cbor/pinedio_cbor/demo.c)

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

    [(`init_lorawan` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L168-L174)

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

1.  We open an __Application Port__ that will connect to The Things Network...

    ```bash
    las_app_port open 2
    ```

    "`2`" is the Application Port Number

    [(`las_app_port` is explained here)](https://lupyuen.github.io/articles/lorawan#open-lorawan-port)

1.  Finally we __send a data packet to The Things Network__ over LoRaWAN...

    ```bash
    las_app_tx_cbor 2 0 1234 2345
    ```

    This means...

    -   Transmit a LoRaWAN Packet to __Port 2__

    -   That contains the values __`t=1234`__ (Temperature), __`l=2345`__ (Light Level)

    -   `0` means that this is an __Unconfirmed Message__

        (Because we're not expecting an acknowledgement)

    Our Sensor Data has been transmitted via LoRaWAN to The Things Network!

    [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

    [__See the output log__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_lorawan/README.md#output-log)

Check out this demo of PineDio Stack with Roblox and The Things Network...

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox#digital-twin-demo)

# Appendix: Porting TinyCBOR to BL602

Below are the fixes we made while porting the TinyCBOR library to BL602 / BL604...
 
-   ["Fix fall through"](https://github.com/lupyuen/tinycbor-bl602/commit/971dca84b0b036a4ed44aa808e6eb18033161170)

-   ["Fix RetType, LenType"](https://github.com/lupyuen/tinycbor-bl602/commit/c32bbc7696a54578f050467f1e182f4fd0f9bb9a)

-   ["Fix open_memstream"](https://github.com/lupyuen/tinycbor-bl602/commit/65f857a3f2c8f0169ff215047fbcf7cd956eb55a)

-   ["Don't use memstream"](https://github.com/lupyuen/tinycbor-bl602/commit/0594d2f29646f65db22a60102d25c7aa675e9cae)
