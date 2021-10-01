# Encode Sensor Data with CBOR on BL602

📝 _6 Oct 2021_

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

Today we'll learn to encode Sensor Data with the __TinyCBOR Library__ that we have ported to the [__BL602__](https://lupyuen.github.io/articles/pinecone) and [__BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V SoCs...

-   [__lupyuen/tinycbor-bl602__](https://github.com/lupyuen/tinycbor-bl602)

The library has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio), but it should work on __any BL602 or BL604 Board__: PineCone BL602, Pinenut, DT-BL10, MagicHome BL602, ...

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

-   [__pinedio_cbor Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/cbor/customer_app/pinedio_cbor)

## Output Buffer and CBOR Encoder

First we create an __Output Buffer__ that will hold the encoded CBOR data: [pinedio_cbor/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/cbor/customer_app/pinedio_cbor/pinedio_cbor/demo.c#L9-L66)

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

The last parameter (`1`) is important: It must match the __number of Key-Value Pairs__ (like `"t": 1234`) that we shall encode.

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

Follow the steps in the Appendix to __build, flash and run__ the firmware.

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

TODO

From [pinedio_cbor/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/cbor/customer_app/pinedio_cbor/pinedio_cbor/demo.c#L68-L139)

```c
/// Test CBOR Encoding for { "t": 1234, "l": 2345 }
static void test_cbor2(char *buf, int len, int argc, char **argv) {
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
    1234          //  Value
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
    2345          //  Value
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
  printf("CBOR Output: %d bytes\r\n", output_len);

  //  Dump the encoded CBOR output (11 bytes):
  //  0xa2 0x61 0x74 0x19 0x04 0xd2 0x61 0x6c 0x19 0x09 0x29
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\r\n", output[i]);
  }
}
```

TODO

```bash
test_cbor2
```

TODO

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

![Encoded CBOR Output](https://lupyuen.github.io/images/cbor-output.png)

To experiment with CBOR, try the [__CBOR Playground__](http://cbor.me/)...

![CBOR Playground](https://lupyuen.github.io/images/grafana-cbor5.png)

[(More about CBOR implementations)](https://cbor.io/impls.html)

> ![](https://lupyuen.github.io/images/cbor-code2.png)

# Other Data Types

TODO

-   [__TinyCBOR Docs__](https://intel.github.io/tinycbor/current/)

What exactly are __"`t`"__ and __"`l`"__ in our Sensor Data?

```json
{ 
    "t": 1234, 
    "l": 2345 
}
```

"`t`" and "`l`" represent our (imaginary) __Temperature Sensor__ and __Light Sensor__.

We __shortened the Field Names__ to fit the Sensor Data into 11 bytes of CBOR.

With Grafana we can map "`t`" and "`l`" to their full names for display.
    
Why is the temperature transmitted as an __integer__: `1234`?

That's because __floating-point numbers compress poorly__ with CBOR unless we select the proper encoding.

(Either 3 bytes, 5 bytes or 9 bytes per float. See the next note)

Instead we assume that our integer data has been __scaled up 100 times__.

(So `1234` actually means `12.34` ºC)

We may configure Grafana to divide our integer data by 100 when rendering the values.

# Floating-Point Numbers

TODO

If we're actually __encoding floats in CBOR__, how do we select the proper encoding?

The CBOR spec says that there are [__3 ways to encode floats__](https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and-)...

-   [IEEE 754 __Half-Precision__ Float (16 bits)](https://en.m.wikipedia.org/wiki/Half-precision_floating-point_format)

    (__3.3__ significant decimal digits)

-   [IEEE 754 __Single-Precision__ Float (32 bits)](https://en.m.wikipedia.org/wiki/Single-precision_floating-point_format)

    (__6 to 9__ significant decimal digits)

-   [IEEE 754 __Double-Precision__ Float (64 bits)](https://en.m.wikipedia.org/wiki/Double-precision_floating-point_format)

    (__15 to 17__ significant decimal digits)

What would be the proper encoding for a float (like 12.34) that could range from 0.00 to 99.99?

This means that we need __4 significant decimal digits__.

Which is too many for a Half-Precision Float (16 bits), but OK for a __Single-Precision__ Float (32 bits).

Thus we need __5 bytes__ to encode the float. (Including the CBOR Initial Byte)

# CBOR on LoRaWAN

TODO

From [pinedio_lorawan/lorawan.c](https://github.com/lupyuen/bl_iot_sdk/blob/cbor/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L893-L1050)

```c
/// Transmit CBOR payload to LoRaWAN. The command
///   las_app_tx_cbor 2 0 1234 2345
/// Will transmit the CBOR payload
///   { "t": 1234, "l": 2345 }
/// To port 2, unconfirmed (0).
void
las_cmd_app_tx_cbor(char *buf0, int len0, int argc, char **argv) {
  int rc;
  //  Validate number of arguments
  if (argc < 5) {
    printf("Invalid # of arguments\r\n");
    goto cmd_app_tx_cbor_err;
  }
  //  Get port number
  uint8_t port = parse_ull_bounds(argv[1], 1, 255, &rc);
  if (rc != 0) {
    printf("Invalid port %s. Must be 1 - 255\r\n", argv[1]);
    return;
  }
  //  Get unconfirmed / confirmed packet type
  uint8_t pkt_type = parse_ull_bounds(argv[2], 0, 1, &rc);
  if (rc != 0) {
    printf("Invalid type. Must be 0 (unconfirmed) or 1 (confirmed)\r\n");
    return;
  }
  //  Get t value
  uint16_t t = parse_ull_bounds(argv[3], 0, 65535, &rc);
  if (rc != 0) {
    printf("Invalid t value %s. Must be 0 - 65535\r\n", argv[3]);
    return;
  }
  //  Get l value
  uint16_t l = parse_ull_bounds(argv[4], 0, 65535, &rc);
  if (rc != 0) {
    printf("Invalid l value %s. Must be 0 - 65535\r\n", argv[4]);
    return;
  }

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
  printf("CBOR Output: %d bytes\r\n", output_len);

  //  Dump the encoded CBOR output (11 bytes):
  //  0xa2 0x61 0x74 0x19 0x04 0xd2 0x61 0x6c 0x19 0x09 0x29
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\r\n", output[i]);
  }    

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

  return;

cmd_app_tx_cbor_err:
  printf("Usage:\r\n");
  printf("\tlas_app_tx_cbor <port> <type> <t> <l>\r\n");
  printf("Where:\r\n");
  printf("\tport = port number on which to send\r\n");
  printf("\ttype = 0 for unconfirmed, 1 for confirmed\r\n");
  printf("\tt    = Value for t\r\n");
  printf("\tl    = Value for l\r\n");
  printf("\tex: las_app_tx_cbor 2 0 1234 2345\r\n");

  return;
}
```

TODO

![](https://lupyuen.github.io/images/cbor-code3.png)

TODO

![](https://lupyuen.github.io/images/cbor-grafana.jpg)

# Decoding CBOR

TODO

[(More about CBOR implementations)](https://cbor.io/impls.html)

# Accuracy vs Precision

TODO

Is it meaningful to record temperatures that are accurate to 0.01 ºC?

How much accuracy do we need for Sensor Data anyway?

The accuracy for our Sensor Data depends on...

1. Our monitoring requirements, and

1. Accuracy of our sensors

Learn more about Accuracy and Precision of Sensor Data...

-   ["IoT’s Lesser Known Power: “Good Enough” Data Accuracy"](https://kotahi.net/iots-lesser-known-power-good-enough-data-accuracy/)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/cbor.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/cbor.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1441626008931602433)

# Appendix: Build And Run CBOR Firmware

TODO

-   [__bl_iot_sdk/customer_app/pinedio_cbor__](https://github.com/lupyuen/bl_iot_sdk/tree/cbor/customer_app/pinedio_cbor)

# Appendix: Add TinyCBOR To Your Project

TODO

-   [__lupyuen/tinycbor-bl602__](https://github.com/lupyuen/tinycbor-bl602)
