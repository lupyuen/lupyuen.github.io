# Connect IKEA Air Quality Sensor to Apache NuttX OS

📝 _12 Feb 2022_

![IKEA VINDRIKTNING Air Quality Sensor seated on Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/images/ikea-title.jpg)

_[IKEA VINDRIKTNING Air Quality Sensor](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) seated on [Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/articles/gateway)_

[__IKEA VINDRIKTNING__](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) is a $12 hackable Air Quality Sensor that measures [__PM 2.5 (Particulate Matter__)](https://www.epa.gov/pm-pollution/particulate-matter-pm-basics) with reasonable accuracy.

Let's connect the IKEA Sensor to a RISC-V Microcontroller Board: [__Pine64 PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (pic below) running on [__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) operating system.

(Our code will run on ESP32 too)

_Why are we doing this?_

-   The sensor is __affordable and available__ at our local IKEA store

-   Might be a fun intro to __Embedded Programming__

-   But some __soldering needed!__ We'll walk through the steps.

-   __Apache NuttX__ is a tiny Linux-like operating system for microcontrollers. So our code will look familiar to Linux coders.

-   Eventually we'll transmit the PM 2.5 data wirelessly over [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) to [__The Things Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/). (Thanks to the onboard LoRa Transceiver on PineDio Stack)

-   Imagine connecting a community of Air Quality Sensors miles apart (because of LoRa's long range). That would be super interesting for __Environment Monitoring__!

In a while we'll dive into the code that talks to the IKEA Sensor...

-   [__lupyuen/ikea_air_quality_sensor__](https://github.com/lupyuen/ikea_air_quality_sensor)

But first let's solder and wire up the IKEA Sensor!

_Will it work with Arduino?_

Check out these projects...

-   [__esp8266-vindriktning-particle-sensor__](https://github.com/Hypfer/esp8266-vindriktning-particle-sensor)

-   [__ESPHome on ESP32__](https://style.oversubstance.net/2021/08/diy-use-an-ikea-vindriktning-air-quality-sensor-in-home-assistant-with-esphome/)

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/loader-title.jpg)

[_Pine64 PineDio Stack BL604 RISC-V Board_](https://lupyuen.github.io/articles/pinedio2)

# About IKEA Air Quality Sensor

I found the VINDRIKTNING sensor at my local IKEA Store (IKEA Tampines Singapore) in the Lighting Section...

(Near the Air Purifiers. Wow IKEA has Air Purifiers now)

![IKEA VINDRIKTNING Air Quality Sensor at IKEA Tampines Singapore in the Lighting Section near the Air Purifiers](https://lupyuen.github.io/images/ikea-sensor3.jpg)

Connect the sensor to a USB-C Power Cable (not included) and it lights up in __Red, Amber or Green__...

![IKEA VINDRIKTNING Air Quality Sensor powered on](https://lupyuen.github.io/images/ikea-sensor4.jpg)

| Colour | PM 2.5 (μg/m³) | Air Quality
| ------ | :------: | -----------
| Green | 0 - 35 | Good
| Amber | 36 - 85 | OK
| Red | 86 and above | Not good

[(Watch it in action on YouTube)](https://youtu.be/wyXb3aSPet4)

[(IKEA VINDRIKTNING Manual)](https://www.ikea.com/us/en/manuals/vindriktning-air-quality-sensor__AA-2289325-1.pdf)

_Huh? This sensor outputs only 3 levels of Air Quality?_

Actually the sensor is capable of measuring PM 2.5 from __0 to 1,000 μg/m³__... Just that we need to __wire it ourselves__ to get the PM 2.5 value.

The brilliant folks at the [__Home Assistant Project__](https://community.home-assistant.io/t/ikea-vindriktning-air-quality-sensor/324599) discovered that inside the IKEA Sensor is a [__PM1006 Infrared LED Particle Sensor__](https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)...

![PM1006 Infrared LED Particle Sensor](https://lupyuen.github.io/images/ikea-datasheet.png)

[(From PM1006 Datasheet)](https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

The PM1006 Sensor exposes a __UART (Serial) Port__ that transmits the PM 2.5 value, encoded like so...

![PM1006 Sensor inside IKEA VINDRIKTNING Air Quality Sensor transmits PM 2.5 over UART](https://lupyuen.github.io/images/ikea-datasheet2.png)

[(From PM1006 Datasheet)](https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

To get the PM 2.5 data, let's wire up the UART Port with a little soldering.

(FYI: Inside the IKEA Sensor is another microcontroller that talks to PM1006. Periodically it triggers the PM1006 command that measures PM 2.5)

[(__Caution:__ The UART Port runs at 5V, not 3.3V)](https://lupyuen.github.io/articles/ikea#notes)

![Inside the IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder.jpg)

# Solder UART Port

Follow these steps to __solder the UART (Serial) Port__ on the IKEA VINDRIKTNING Sensor (so we can access the PM 2.5 data)...

1.  Unscrew the __4 screws__ on the back of the IKEA Sensor

1.  Flip open the __Back Cover__ to reveal the Circuit Board

    (Pic above)

1.  __Solder these Circular Pads__ on the Circuit Board...

    | IKEA Sensor | UART Pin | Wire Colour
    |:--:|:--:|:--:
    | REST | TX | Blue
    | GND | GND | Black

    (Pic below)

1.  Stay clear of the __Surface Mounted Components!__

    (Near the GND Pad)

1.  Pardon my horrid soldering...

    If you're curious how I did it, check the Appendix for the __Soldering Steps__...

    [__"Solder UART Port on IKEA VINDRIKTNING Air Quality Sensor"__](https://lupyuen.github.io/articles/ikea#appendix-solder-uart-port-on-ikea-vindriktning-air-quality-sensor)

    (Hint: Use Sticky Tape and very fine Solder Wire)

1.  Test our handiwork with a __Multimeter__.

    Note that the REST and GND Pins are exposed as tiny strips at the top of the pic below. Perfect for Multimeter Testing!

1.  Optional: I used __Bus Pirate__ to sniff the UART Port and inspect the data transmitted by the sensor. [(See the details in the Appendix)](https://lupyuen.github.io/articles/ikea#appendix-test-with-bus-pirate)

![UART Port soldered to IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder3.jpg)

# Connect to PineDio Stack BL604

Now that we have exposed the UART Port on IKEA Air Quality Sensor, let's connect it to our Microcontroller Board: [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2)

| From | To | Wire Colour
| :---- | :---- | :----
| __IKEA REST__   | Resistor R1  | Blue
| __IKEA GND__    | PineDio GND <br> Pin 20 | Black
| __Resistor R1__ | Resistor R2 | _(Breadboard)_
| __Resistor R2__ | Resistor R3 | _(Breadboard)_
| __Resistor R1__ | PineDio RX <br> GPIO 3 / Pin 14 | Red
| __Resistor R3__ | PineDio GND <br> Pin 20 | Green
| _(Unused)_  | PineDio TX <br> GPIO 4 / Pin 13 |

(R1, R2 and R3 are 3 Resistors with the same resistance, like 2.2 kΩ in the pic below)

[("PineDio Pin" refers to the 20-pin GPIO Connector on PineDio Stack)](https://lupyuen.github.io/articles/pinedio#logic-analyser)

![IKEA VINDRIKTNING Air Quality Sensor connected to Pine64 PineDio Stack BL604 RISC-V Board with Voltage Divider](https://lupyuen.github.io/images/ikea-divider3.jpg)

_Why the resistors?_

That's because IKEA Sensor's __UART Port runs at 5V__, not 3.3V. [(See this)](https://lupyuen.github.io/articles/ikea#notes)

And our Microcontroller Board is __not 5V Tolerant__.

To convert the 5V UART Port to 3.3V, we connect 3 Resistors (of the same resistance) as a [__Voltage Divider__](https://learn.sparkfun.com/tutorials/voltage-dividers/all)...

![IKEA VINDRIKTNING Air Quality Sensor connected to Pine64 PineDio Stack BL604 RISC-V Board with Voltage Divider](https://lupyuen.github.io/images/ikea-divider3a.jpg)

_How did we get GPIO 3 and 4?_

The __GPIO Pin Numbers__ for the UART Port (UART1) are defined in [board.h](https://github.com/lupyuen/nuttx/blob/ikea/boards/risc-v/bl602/bl602evb/include/board.h#L63-L66)

```c
#define BOARD_UART_1_RX_PIN \
  (GPIO_INPUT     | GPIO_PULLUP | \
   GPIO_FUNC_UART | GPIO_PIN3)

#define BOARD_UART_1_TX_PIN \
  (GPIO_INPUT     | GPIO_PULLUP | \
   GPIO_FUNC_UART | GPIO_PIN4)
```

[(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

__For ESP32:__ The GPIO Pin Numbers for the UART Port (UART1) are defined in [Kconfig](https://github.com/lupyuen/nuttx/blob/ikea/arch/xtensa/src/esp32/Kconfig#L661-L669) and menuconfig...

```text
config ESP32_UART1_TXPIN
  int "UART1 Tx Pin"
  default 10
  range 0 39

config ESP32_UART1_RXPIN
  int "UART1 Rx Pin"
  default 9
  range 0 39
```

Connect the __USB Ports__ of IKEA Sensor and PineDio Stack to our computer.

(Remember: __Only One Power Source__ for both gadgets!)

It looks messy with 2 USB Cables hanging off our computer, but we'll live with it for now.

# NuttX App

We're all ready to read the PM 2.5 data from the IKEA Air Quality Sensor!

Let's dive into the Source Code of our NuttX App that will __read and process the PM 2.5 data__...

-   [__ikea_air_quality_sensor_main.c__](https://github.com/lupyuen/ikea_air_quality_sensor/blob/main/ikea_air_quality_sensor_main.c)

But first: What's inside the PM 2.5 data?

![PM1006 Sensor inside IKEA VINDRIKTNING Air Quality Sensor transmits PM 2.5 over UART](https://lupyuen.github.io/images/ikea-datasheet3.png)

[(From PM1006 Datasheet)](https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

## Sensor Data Frame

The IKEA Sensor transmits a stream of __Sensor Data__ that looks like this...

```text
16  11  0B  00  00  00  17  00  00  02  FF  00  00  00  21  02  00  00  0B  88
16  11  0B  00  00  00  17  00  00  02  FF  00  00  00  21  02  00  00  0B  88
16  11  0B  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0B  80
16  11  0B  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0B  80
```

[(Watch the demo on YouTube)](https://youtu.be/TyG-dJCx8OQ)

See the pattern? The data comes in chunks of __20 bytes__. Let's call it a __Sensor Data Frame__.

Each Sensor Data Frame __starts with this header__...

```text
16  11  0B
```

If we look back at the [__PM1006 Datasheet__](https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf) (pic above), we realise that the 20-byte Sensor Data Frame ("Response") may be decoded like so...

| Field | Value
| :--- | :---
| Header | `16 11 0B`
| _(Unused)_ | `00 00`
| __PM 2.5__ | __`00 17`__
| _(Unused)_ | `00 00 02 FF 00 00`
| _(Unused)_ | `00 21 02 00 00 0B`
| Checksum | `88`

This gives the __PM 2.5 value of 23__ (`0x0017`).

![20-byte Sensor Data Frames from IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-gps2.png)

_What about the Checksum?_

To validate the Checksum, all 20 bytes __must add up to 0__.

We skip the Sensor Data Frames that don't add up to 0.

Thus we have a plan for __reading and processing__ the PM 2.5 data...

1.  __Read the data__ into a 20-byte Sensor Data Frame

    (We shift the data into the 20-byte frame, byte by byte)

1.  __Check the Header__ in the Sensor Data Frame

    (Header should be `16 11 0B`)

1.  __Validate the Checksum__ in the Sensor Data Frame

    (All bytes must add up to 0)

1.  __Extract the PM 2.5 value__ from the Sensor Data Frame

    (And process the PM 2.5 value)

## Main Loop

This is the __Main Loop__ that runs the steps above: [ikea_air_quality_sensor_main.c](https://github.com/lupyuen/ikea_air_quality_sensor/blob/main/ikea_air_quality_sensor_main.c#L46-L77)

```c
//  Current data in the Sensor Data Frame (20 bytes)
static uint8_t frame[20];

//  Read and process the Sensor Data from IKEA Air Quality Sensor
int main(int argc, FAR char *argv[]) {

  //  Open the UART port
  int fd = open("/dev/ttyS1", O_RDONLY);
  if (fd < 0) { printf("Unable to open /dev/ttyS1\n"); return 1; }
```

We begin by __opening the UART Port__ at __/dev/ttyS1__.

Next we loop forever, __reading bytes from the UART Port__ and handling them...

```c
  //  Forever process bytes from the UART port
  for (;;) {
    //  Read a byte from the UART port
    char ch;
    read(fd, &ch, 1);
    printf("%02x  ", ch);
```

After reading a byte, we shift it into the __Sensor Data Frame__ (20 bytes)...

```c
    //  Append to Sensor Data Frame after shifting the bytes.
    //  We always append bytes to the frame (instead of replacing bytes)
    //  because UART is unreliable and bytes may be dropped.
    for (int i = 0; i < sizeof(frame) - 1; i++) {
      frame[i] = frame[i + 1];
    }
    frame[sizeof(frame) - 1] = ch;
```

We check if the Sensor Data Frame contains a valid __Header and Checksum__...

```c
    //  If frame is complete and valid...
    if (frame_is_valid()) {
      //  Process the frame
      process_frame();
    }   
```

If the Sensor Data Frame is valid, we process the data in the frame.

Let's jump into __frame_is_valid__ and __process_frame__.

![Main Loop](https://lupyuen.github.io/images/ikea-code2.png)

## Validate Sensor Data

This is how we __validate the Sensor Data Frame__: [ikea_air_quality_sensor_main.c](https://github.com/lupyuen/ikea_air_quality_sensor/blob/main/ikea_air_quality_sensor_main.c#L79-L102)

```c
//  Header for Sensor Data Frame
static const uint8_t PM1006_RESPONSE_HEADER[] = 
    { 0x16, 0x11, 0x0B };

//  Return true if we have received a complete and valid Sensor Data Frame
static bool frame_is_valid(void) {

  //  Check the header at frame[0..2]
  if (memcmp(frame, PM1006_RESPONSE_HEADER, sizeof(PM1006_RESPONSE_HEADER)) != 0) {
    //  Header not found
    return false;
  }
```

We verify that the Sensor Data Frame contains the __Header: `16 11 0B`__

Next we __sum up all the bytes__ in the Sensor Data Frame...

```c
  //  Compute sum of all bytes in the frame
  uint8_t sum = 0;
  for (int i = 0; i < sizeof(frame); i++) {
    sum += frame[i];
  }
```

(Including the Checksum at the last byte)

And we verify that the __sum is 0__...

```c
  //  All bytes must add to 0 (because of checksum at the last byte)
  if (sum != 0) {
    //  Invalid checksum
    printf("\nPM1006 checksum is wrong: %02x, expected zero\n", sum);
    return false;
  }
```

Now that the Sensor Data Frame is __complete and valid__...

```c
  //  We have received a complete and valid response frame
  return true;
}
```

We proceed to process the PM 2.5 data inside the frame.

![Validate Sensor Data](https://lupyuen.github.io/images/ikea-code3.png)

## Process Sensor Data

To process the Sensor Data Frame, we extract the __PM 2.5 value__ from the frame: [ikea_air_quality_sensor_main.c](https://github.com/lupyuen/ikea_air_quality_sensor/blob/main/ikea_air_quality_sensor_main.c#L104-L114)

```c
//  Process the PM 2.5 data in the Sensor Data Frame
static void process_frame(void) {

  //  frame[3..4] is unused
  //  frame[5..6] is our PM2.5 reading
  //  In the datasheet, frame[3..6] is called DF1-DF4:
  //  https://github.com/arendst/Tasmota/files/7083662/PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf

  const int pm_2_5_concentration = 
    frame[5] * 256 + 
    frame[6];
```

Right now we're not really using the PM 2.5 data...

```c
  //  TODO: Transmit the sensor data
  printf("\nGot PM2.5 Concentration: %d µg/m³\n", pm_2_5_concentration);
}
```

But in the next article we'll transmit the data wirelessly over [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) to [__The Things Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/).

(Thanks to the onboard LoRa Transceiver on PineDio Stack)

The code in our NuttX App was inspired by the [__Arduino__](https://github.com/Hypfer/esp8266-vindriktning-particle-sensor/blob/master/src/SerialCom.h#L26-L63) and [__ESPHome__](https://github.com/esphome/esphome/blob/dev/esphome/components/pm1006/pm1006.cpp#L57-L96) modules for the IKEA Sensor.

![Process Sensor Data](https://lupyuen.github.io/images/ikea-code4.png)

# Run NuttX App

We're ready to run our NuttX App to __read and process the PM 2.5__ Sensor Data!

1.  Follow these steps to __build, flash and run NuttX__...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/ikea#appendix-build-flash-and-run-nuttx)

    Remember to enable the __UART1 Port /dev/ttyS1__ and set it to __9,600 bps__...

    ![Enable UART1 and set to 9,600 bps](https://lupyuen.github.io/images/ikea-uart3.jpg)

    [(Here's how)](https://lupyuen.github.io/articles/ikea#configure-nuttx)

1.  At the NuttX Shell, enter this command...

    ```bash
    ls /dev
    ```

    We should see our UART Port configured at __/dev/ttyS1__...

    ```text
    /dev:
    console
    null
    timer0
    ttyS1
    zero
    ```

    Which is connected to our IKEA Sensor.

1.  Enter this command to __dump the output__ from our IKEA Sensor...

    ```bash
    cat /dev/ttyS1
    ```

    We should see some meaningless ASCII data...

    ```text
    3(1>
    2'0A
    2%0C
    1$/F
    ```

    [(Watch the demo on YouTube)](https://youtu.be/iFf8_f7ExUI)

    But that's OK, it means that our IKEA Sensor is alive.

1.  Finally enter this command to __run our NuttX App__ for the IKEA Sensor...

    ```bash
    ikea_air_quality_sensor
    ```

    We should see the 20-byte __Sensor Data Frames__ and the decoded __PM 2.5 values__...

    ```text
    16  11  0b  00  00  00  17  00  00  02  ff  00  00  00  21  02  00  00  0b  88
    Got PM2.5 Concentration: 23 µg/m³

    16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
    Got PM2.5 Concentration: 24 µg/m³

    16  11  0b  00  00  00  17  00  00  03  01  00  00  00  21  02  00  00  0b  85
    Got PM2.5 Concentration: 23 µg/m³
    ```

    [(Watch the demo on YouTube)](https://youtu.be/dUHlG67pB3M)

![Our NuttX App reads PM 2.5 data from IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-code5.png)

Congratulations we have successfully read the PM 2.5 values from the IKEA VINDRIKTNING Air Quality Sensor! 🎉

![NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN](https://lupyuen.github.io/images/lorawan3-ttn.png)

# What's Next

In the next article we shall transmit the PM 2.5 data wirelessly over [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) to [__The Things Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/). (Thanks to the onboard LoRa Transceiver on PineDio Stack)

Imagine connecting a community of Air Quality Sensors miles apart (because of LoRa's long range). That would be super interesting for __Environment Monitoring__!

[(We'll visualise the PM 2.5 data with __Prometheus__ and __Grafana__)](https://lupyuen.github.io/articles/prometheus)

Stay Tuned!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/sptmad/connect_ikea_air_quality_sensor_to_apache_nuttx_os/?utm_source=share&utm_medium=web2x&context=3)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ikea.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ikea.md)

![UART Port of IKEA VINDRIKTNING Air Quality Sensor runs at 5V, not 3.3V](https://lupyuen.github.io/images/ikea-5v.jpg)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1490147828458405889)

1.  According to the PM1006 Datasheet, the UART Port runs at [__5V Logic Level__](https://lupyuen.github.io/articles/ikea#about-ikea-air-quality-sensor) (instead of 3.3V, see pic above).

    Apparently some folks are using the 5V UART Port just fine without converting to 3.3V. [(See this)](https://github.com/Hypfer/esp8266-vindriktning-particle-sensor/issues/44)

    But to protect our microcontroller (which is not 5V Tolerant) we need a [__Voltage Divider__](https://learn.sparkfun.com/tutorials/voltage-dividers/all)...

    ![Voltage Divider for UART Port of IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-divider.jpg)

    (With 3 resistors of the same value)

    The pic shows it's not exactly 3.3V, but as long as our Logic High is above 2V, we should be fine. [(See this)](https://learn.sparkfun.com/tutorials/logic-levels/33-v-cmos-logic-levels)

1.  Each Sensor Data Frame has 20 bytes. Why are so many bytes unused?

    IKEA Air Quality Sensor uses the PM1006 Sensor, which is a cheaper version of PM1006K. 

    On PM1006K we get more data fields: PM 1.0 and PM 10. These fields are not available on PM1006, hence we have unused bytes in the Sensor Data Frame.

    [(PM1006K Datasheet)](https://en.gassensor.com.cn/Product_files/Specifications/LED%20Particle%20Sensor%20PM1006K%20Specification.pdf)

![Very Fine Solder Wire (0.38 mm diameter) and 22 AWG Solid Core Wire](https://lupyuen.github.io/images/ikea-wire.jpg)

# Appendix: Solder UART Port on IKEA VINDRIKTNING Air Quality Sensor

Here's how I soldered the __UART (Serial) Port__ on the IKEA VINDRIKTNING Air Quality Sensor.

(Sorry I'm terribly inexperienced with soldering 🙏)

I used __very fine Solder Wire__ (0.38 mm diameter) because it creates very tiny, precise blobs of solder. And __22 AWG Solid Core Wire__ (Blue and Black).

(See pic above)

Here are the steps...

1.  Unscrew the __Back Cover__ to reveal the Circuit Board

    [(Here's how)](https://lupyuen.github.io/articles/ikea#solder-uart-port)

    ![Inside the IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder.jpg)

1.  We'll solder these __Circular Pads__ on the Circuit Board...

    | IKEA Sensor | UART Pin | Wire Colour
    |:--:|:--:|:--:
    | REST | TX | Blue
    | GND | GND | Black

    [(See the pic)](https://lupyuen.github.io/images/ikea-solder3.jpg)

1.  We start with the __REST Pad__.

    Mask out with __Sticky Tape__ all the parts around the REST Pad that should NOT be soldered.

    ![Mask out with Sticky Tape all the parts around the REST Pad on IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder2.jpg)

1.  With our Soldering Iron, drop a __tiny blob of Molten Solder__ on the REST Pad.

    (Very fine Solder Wire really helps)

1.  Carefully place our __Blue Solid Core Wire__ (or similar) on top of the Solder Blob. 

    (Now hardened)

1.  __Gently tap__ our Soldering Iron on top of the wire.

    The wire should sink into the Molten Blob of Solder.

1.  Quickly __adjust the wire__ to make sure it doesn't touch any components on the Circuit Board.

    When cooled, the wire stays in the hardened Solder Blob.

1.  Now we solder the __GND Pad__.

    Mask out with __Sticky Tape__ all the parts around the GND Pad that should NOT be soldered.

    (Especially the Surface Mounted Components near the GND Pad)

1.  Repeat the earlier steps to __solder the GND Pad__ with our __Black Solid Core Wire__.

    Stay clear of the __Surface Mounted Components!__

    ![Soldered GND Pad](https://lupyuen.github.io/images/ikea-solder5.jpg)

1.  Remove the __Sticky Tape__. We're done!

    ![UART Port soldered to IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder3.jpg)

1.  Bend the __Solid Core Wires__ and bind them with Sticky Tape so they don't get dislodged easily.

    ![Bend the Solid Core Wire soldered to IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder4.jpg)

1.  Test our handiwork with a __Multimeter__.

    (The UART Port runs at 5V, not 3.3V)

    ![UART Port of IKEA VINDRIKTNING Air Quality Sensor runs at 5V, not 3.3V](https://lupyuen.github.io/images/ikea-5v.jpg)

# Appendix: Test with Bus Pirate

Before testing with Apache NuttX OS, we sniffed the UART Port on IKEA VINDRIKTNING Air Quality Sensor with [__Bus Pirate__](http://dangerousprototypes.com/docs/Bus_Pirate).

Connect Bus Pirate to the IKEA Sensor as follows...

| Bus Pirate | IKEA Sensor | Wire Colour
|:---|:--:|:---
| Data In (MISO) | REST | Blue
| GND | GND | Black

![IKEA VINDRIKTNING Air Quality Sensor connected to Bus Pirate](https://lupyuen.github.io/images/ikea-buspirate.jpg)

Connect the USB Ports of the IKEA Sensor and Bus Pirate to the same computer. Remember: Only One Power Source for both gadgets!

Enter these Bus Pirate commands to capture the UART output from the IKEA Sensor (9600 bps, 8 bits, no parity, 1 stop bit)...

```text
HiZ> m

1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)
(1)> 3

Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. Input Custom BAUD
11. Auto-Baud Detection (Activity Required)
(1)> 5

Data bits and parity:
 1. 8, NONE *default 
 2. 8, EVEN 
 3. 8, ODD 
 4. 9, NONE
(1)>

Stop bits:
 1. 1 *default
 2. 2
(1)>

Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>

Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)
(1)>

Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

UART> W
POWER SUPPLIES ON
Clutch engaged!!!
```

[(Watch the demo on YouTube)](https://youtu.be/QOJF6hAhFv4)

[(More about Bus Pirate interfacing with UART)](http://dangerousprototypes.com/docs/UART)

To see the ASCII Output from the IKEA Sensor, enter this Bus Pirate command...

```text
UART> (2)
Raw UART input
Any key to exit
<@:
   <B:
[6C:;8
[9C:;8
[12C9:7 
[16C997!
[20C987"
```

[(Watch the demo on YouTube)](https://youtu.be/QOJF6hAhFv4)

[(See the complete log)](https://gist.github.com/lupyuen/f40454dda8e3d7f279fb6ef721add465)

To see the Binary Output from the IKEA Sensor, enter this...

```text
UART> {
UART LIVE DISPLAY, } TO STOP
```

We should see the 20-byte Sensor Data Frames with PM 2.5 encoded inside...

![Bus Pirate shows the output from IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-buspirate2.jpg)

[(See the complete log)](https://gist.github.com/lupyuen/db0c97b12bd1070e17cd2e570a5aa810)

[(Another binary log)](https://gist.github.com/lupyuen/ebe4c0628fc9ea2e124e6f00d8246b49)

# Appendix: Build, Flash and Run NuttX

_(For BL602, BL604 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602, BL604 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Download NuttX

To use the IKEA Air Quality Sensor with NuttX, download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch ikea https://github.com/lupyuen/nuttx nuttx
git clone --recursive --branch ikea https://github.com/lupyuen/nuttx-apps apps
```

Or if we prefer to __add the IKEA Air Quality Sensor App__ to our NuttX Project, follow these instructions...

-   [__"Install IKEA Air Quality Sensor App"__](https://github.com/lupyuen/ikea_air_quality_sensor#install-app)

[(__For PineDio Stack BL604:__ The app is already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

## Configure NuttX

Now we configure our NuttX project...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

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

1.  Enable UART1...

    __For BL602 / BL604:__ Check the box for __"System Type"__ → __"BL602 Peripheral Support"__ → __"UART1"__

    __For ESP32:__ Check the box for __"System Type"__ → __"ESP32 Peripheral Select"__ → __"UART 1"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

    ![Enable UART1 and set to 9,600 bps](https://lupyuen.github.io/images/ikea-uart3.jpg)

1.  Set UART1 to 9,600 bps...

    Select __"Device Drivers"__ → __"Serial Driver Support"__ → __"UART1 Configuration"__
   
    Set __"BAUD rate"__ to __9600__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable __cat__ and __ls__ commands...

    Select __"Application Configuration"__ → __"NSH Library"__ → __"Disable Individual commands"__
    
    Uncheck __"Disable cat"__

    Uncheck __"Disable ls"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable __Logging and Assertion Checks__...

    Select __"Build Setup"__ → __"Debug Options"__

    Check the boxes for the following...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Debug Assertions
    ```

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Save the configuration and exit menuconfig

    [(See the .config for BL602 and BL604)](https://gist.github.com/lupyuen/f4d9cfc19fb433df43ba8c6f57c6543a)

The IKEA Sensor will be connected to NuttX at __/dev/ttyS1__

## Build NuttX

Follow these steps to build NuttX for BL602, BL604 or ESP32...

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

    [(See the complete log for BL602 / BL604)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 / BL604 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"ESP32 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

__For ESP32:__ [__See instructions here__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html#flashing) [(Also check out this article)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602 / BL604:__ Follow these steps to install __blflash__...

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

__For BL602 / BL604:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

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

![Trekking 13 km to IKEA on the horizon in search of VINDRIKTNING](https://lupyuen.github.io/images/ikea-trek.jpg)

_Trekking 13 km to IKEA on the horizon in search of VINDRIKTNING_
