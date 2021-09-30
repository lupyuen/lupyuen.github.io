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

The lbrary has been tested on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio), but it should work on __any BL602 or BL604 Board__: PineCone BL602, Pinenut, DT-BL10, MagicHome BL602, ...

_Must we scrimp and save every single byte?_

Yes, __every single byte matters__ for low-power wireless networks!

1.  Low-power wireless networks operate on Radio Frequency Bands that are __shared with many other gadgets__.

    They are prone to __collisions and interference__.

    The __smaller the data packet__, the higher the chance that it will be __transmitted successfully__!

1.  When we transmit LoRa packets to __The Things Network__ (the free public global LoRa network), we're limited by their __Fair Use__ policy.

    [(Roughly __12 bytes__ per message, assuming 10 messages per hour)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

    JSON is too big for this. But CBOR works well!

    In a while we'll watch the TinyCBOR Library in action for encoding Sensor Data in The Things Network.

# Encode Sensor Data with TinyCBOR

TODO

From [pinedio_cbor/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/cbor/customer_app/pinedio_cbor/pinedio_cbor/demo.c#L9-L66)

```c
/// Test CBOR Encoding for { "t": 1234 }
static void test_cbor(char *buf, int len, int argc, char **argv) {
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
    1             //  Number of Key-Value Pairs
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

  //  Dump the encoded CBOR output (6 bytes):
  //  0xa1 0x61 0x74 0x19 0x04 0xd2
  for (int i = 0; i < output_len; i++) {
    printf("  0x%02x\r\n", output[i]);
  }
}
```

TODO

```bash
test_cbor
```

TODO

```text
CBOR Output: 6 bytes
  0xa1
  0x61
  0x74
  0x19
  0x04
  0xd2
```

![](https://lupyuen.github.io/images/cbor-code.png)

# Add Another Field

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

To experiment with CBOR, try the [__CBOR Playground__](http://cbor.me/)...

![CBOR Playground](https://lupyuen.github.io/images/grafana-cbor5.png)

[(More about CBOR implementations)](https://cbor.io/impls.html)

![](https://lupyuen.github.io/images/cbor-code2.png)

# Other Data Types

TODO

# Build and Run the Firmware

TODO

# Floating-Point Numbers

TODO

# The Things Network

TODO

![](https://lupyuen.github.io/images/cbor-code3.png)

# Accuracy vs Precision

TODO

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

1.  What exactly are __"`t`"__ and __"`l`"__ in our Sensor Data?

    ```json
    { 
      "t": 1234, 
      "l": 2345 
    }
    ```

    "`t`" and "`l`" represent our (imaginary) __Temperature Sensor__ and __Light Sensor__.

    We __shortened the Field Names__ to fit the Sensor Data into 11 bytes of CBOR.

    With Grafana we can map "`t`" and "`l`" to their full names for display.
    
1.  Why is the temperature transmitted as an __integer__: `1234`?

    That's because __floating-point numbers compress poorly__ with CBOR unless we select the proper encoding.

    (Either 3 bytes, 5 bytes or 9 bytes per float. See the next note)

    Instead we assume that our integer data has been __scaled up 100 times__.

    (So `1234` actually means `12.34` ºC)

    We may configure Grafana to divide our integer data by 100 when rendering the values.

1.  If we're actually __encoding floats in CBOR__, how do we select the proper encoding?

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

    (Thanks to [__@chrysn__](https://chaos.social/@chrysn/107003343164025849) for highlighting this!)

1.  Is it meaningful to record temperatures that are accurate to 0.01 ºC?

    How much accuracy do we need for Sensor Data anyway?

    The accuracy for our Sensor Data depends on...

    1. Our monitoring requirements, and

    1. Accuracy of our sensors

    Learn more about Accuracy and Precision of Sensor Data...

    ["IoT’s Lesser Known Power: “Good Enough” Data Accuracy"](https://kotahi.net/iots-lesser-known-power-good-enough-data-accuracy/)

