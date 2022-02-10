# Connect IKEA Air Quality Sensor to Apache NuttX OS

📝 _16 Feb 2022_

![IKEA VINDRIKTNING Air Quality Sensor seated on Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/images/ikea-title.jpg)

_[IKEA VINDRIKTNING Air Quality Sensor](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) seated on [Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/articles/gateway)_

[__IKEA VINDRIKTNING__](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) is a $12 hackable Air Quality Sensor that measures [__PM 2.5 (Particulate Matter__)](https://www.epa.gov/pm-pollution/particulate-matter-pm-basics) with reasonable accuracy.

Let's connect the IKEA Sensor to a RISC-V Microcontroller Board: [__Pine64 PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) (pic below) running on [__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) operating system.

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

[_Pine64 PineDio Stack BL604 RISC-V Board_](https://lupyuen.github.io/articles/pinedio)

# About IKEA Air Quality Sensor

I found the VINDRIKTNING sensor at my local IKEA Store (IKEA Tampines Singapore) in the Lighting Section...

(Near the Air Purifiers. Wow IKEA has Air Purifiers now)

![IKEA VINDRIKTNING Air Quality Sensor at IKEA Tampines Singapore](https://lupyuen.github.io/images/ikea-sensor3.jpg)

Connect the sensor to a USB-C Power Cable (not included) and it lights up in __Red, Amber or Green__...

![IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-sensor4.jpg)

| Colour | PM 2.5 (μg/m³) | Air Quality
| ------ | :------: | -----------
| Green | 0 - 35 | Good
| Amber | 36 - 85 | OK
| Red | 86 and above | Not good

[(Watch it in action on YouTube)](https://youtu.be/wyXb3aSPet4)

[(IKEA VINDRIKTNING Manual)](https://www.ikea.com/us/en/manuals/vindriktning-air-quality-sensor__AA-2289325-1.pdf)

_Huh? This sensor outputs only 3 levels of Air Quality?_

Actually the sensor is capable of measuring PM 2.5 from __0 to 1,000 μg/m³__... Just that we need to __wire it ourselves__ to get the PM 2.5 value.

The brilliant folks at the [__Home Assistant Project__](https://community.home-assistant.io/t/ikea-vindriktning-air-quality-sensor/324599) discovered that inside the IKEA Sensor is a [__PM1006 Infrared LED Particle Sensor__](http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)...

![PM1006 Infrared LED Particle Sensor](https://lupyuen.github.io/images/ikea-datasheet.png)

[(From PM1006 Datasheet)](http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

The PM1006 Sensor exposes a __UART (Serial) Port__ that transmits the PM 2.5 value, encoded like so...

![PM1006 Sensor transmits PM 2.5 over UART](https://lupyuen.github.io/images/ikea-datasheet2.png)

[(From PM1006 Datasheet)](http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

To get the PM 2.5 data, let's wire up the UART Port with a little soldering.

(FYI: Inside the IKEA Sensor is another microcontroller that talks to PM1006. Periodically it triggers the PM1006 command that measures PM 2.5)

[(Caution: The UART Port runs at 4.5V)](https://lupyuen.github.io/articles/ikea#notes)

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

    If you're curious how I did it, check the Appendix for the __Soldering Steps__.

    (Hint: Use Sticky Tape and very fine Solder Wire)

1.  Test our handiwork with a __Multimeter__.

    Note that the REST and GND Pins are exposed as tiny strips at the top of the pic below. Perfect for Multimeter Testing!

1.  Optional: I used __Bus Pirate__ to sniff the UART Port and inspect the data transmitted by the sensor. See the details in the Appendix.

![UART Port soldered to IKEA VINDRIKTNING Air Quality Sensor](https://lupyuen.github.io/images/ikea-solder3.jpg)

# Connect to PineDio Stack BL604

Now that we have exposed the UART Port on IKEA Air Quality Sensor, let's connect it to our Microcontroller Board: [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio)

| Function | GPIO | PineDio Stack | IKEA Sensor | Wire Colour
| :---: | :---: | :---: | :---: | :---:
| RX | 3 | Pin 14 | REST | Blue
| TX | 4 | Pin 13 | Unused |
| GND | GND | Pin 20 | GND | Black

[("PineDio Stack" column refers to the 20-pin GPIO Connector on PineDio Stack)](https://lupyuen.github.io/articles/pinedio#logic-analyser)

![IKEA VINDRIKTNING Air Quality Sensor connected to Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/ikea-pinedio.jpg)

The __GPIO Pin Numbers__ for the UART Port (UART1) are defined in [board.h](https://github.com/lupyuen/incubator-nuttx/blob/ikea/boards/risc-v/bl602/bl602evb/include/board.h#L63-L66)

```c
#define BOARD_UART_1_RX_PIN \
  (GPIO_INPUT     | GPIO_PULLUP | \
   GPIO_FUNC_UART | GPIO_PIN3)

#define BOARD_UART_1_TX_PIN \
  (GPIO_INPUT     | GPIO_PULLUP | \
   GPIO_FUNC_UART | GPIO_PIN4)
```

__For ESP32:__ The GPIO Pin Numbers for the UART Port (UART1) are defined in [Kconfig](https://github.com/lupyuen/incubator-nuttx/blob/ikea/arch/xtensa/src/esp32/Kconfig#L661-L669)

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

It looks messy with 2 USB Cables hanging off our computer, but we'll live with it for now...

> ![IKEA VINDRIKTNING Air Quality Sensor and Pine64 PineDio Stack BL604 RISC-V Board connected to our computer](https://lupyuen.github.io/images/ikea-pinedio2.jpg)

# NuttX App

We're all ready to read the PM 2.5 data from the IKEA Air Quality Sensor!

Let's dive into the Source Code of our NuttX App that will __read and process the PM 2.5 data__...

-   [__ikea_air_quality_sensor_main.c__](https://github.com/lupyuen/ikea_air_quality_sensor/blob/main/ikea_air_quality_sensor_main.c)

But first: What's inside the PM 2.5 data?

![PM1006 Sensor transmits PM 2.5 over UART](https://lupyuen.github.io/images/ikea-datasheet3.png)

[(From PM1006 Datasheet)](http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf)

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

If we look back at the [__PM1006 Datasheet__](http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf) (pic above), we realise that the 20-byte Sensor Data Frame ("Response") may be decoded like so...

| Field | Value
| :--- | :---
| Header | `16 11 0B`
| _(Unused)_ | `00 00`
| __PM 2.5__ | __`00 17`__
| _(Unused)_ | `00 00 02 FF 00 00`
| _(Unused)_ | `00 21 02 00 00 0B`
| Checksum | `88`

This gives the __PM 2.5 value of 23__ (`0x0017`).

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
static const uint8_t PM1006_RESPONSE_HEADER[] = { 0x16, 0x11, 0x0B };

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
  //  http://www.jdscompany.co.kr/download.asp?gubun=07&filename=PM1006_LED_PARTICLE_SENSOR_MODULE_SPECIFICATIONS.pdf

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

TODO

![](https://lupyuen.github.io/images/ikea-code5.png)

# Install App

TODO

To add this repo to your NuttX project...

```bash
## TODO: Change this to the path of our "incubator-nuttx-apps/examples" folder
pushd nuttx/apps/examples
git submodule add https://github.com/lupyuen/ikea_air_quality_sensor
popd
```

Then update the NuttX Build Config...

```bash
## TODO: Change this to the path of our "incubator-nuttx" folder
cd nuttx/nuttx

## Preserve the Build Config
cp .config ../config

## Erase the Build Config and Kconfig files
make distclean

## For BL602: Configure the build for BL602
./tools/configure.sh bl602evb:nsh

## For ESP32: Configure the build for ESP32.
## TODO: Change "esp32-devkitc" to our ESP32 board.
./tools/configure.sh esp32-devkitc:nsh

## Restore the Build Config
cp ../config .config

## Edit the Build Config
make menuconfig 
```

In menuconfig, enable the IKEA Air Quality Sensor App under "Application Configuration" → "Examples".

# Configure Apache NuttX OS

TODO

We configure the UART Port on Apache NuttX OS for the IKEA Sensor...

```bash
make menuconfig
```

Enable UART1:
- Select "System Type → BL602 Peripheral Support"
- Check "UART1"

Set to 9600 bps:
- Select "Device Drivers → Serial Driver Support → UART1 Configuration"
- Set "BAUD rate" to 9600

Enable `cat`:
- Select "Application Configuration → NSH Library → Disable Individual commands"
- Uncheck "Disable cat"

Build and flash NuttX OS to PineDio Stack BL604.

IKEA Sensor is now connected to NuttX OS at `/dev/ttyS1`

TODO14

![](https://lupyuen.github.io/images/ikea-uart3.png)

# Output Log

TODO

Run the following command to test the IKEA Sensor on NuttX OS...

```text
nsh> ikea_air_quality_sensor
16  11  0b  00  00  00  17  00  00  02  ff  00  00  00  21  02  00  00  0b  88
Got PM2.5 Concentration: 23 µg/m³
16  11  0b  00  00  00  17  00  00  02  ff  00  00  00  21  02  00  00  0b  88
Got PM2.5 Concentration: 23 µg/m³
16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  03  00  00  00  22  02  00  00  0b  81
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  02  00  00  00  22  02  00  00  0b  82
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  02  00  00  00  22  02  00  00  0b  82
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  02  00  00  00  22  02  00  00  0b  82
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  04  00  00  00  22  02  00  00  0b  80
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  03  00  00  00  22  02  00  00  0b  81
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  03  00  00  00  22  02  00  00  0b  81
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  18  00  00  03  02  00  00  00  22  02  00  00  0b  82
Got PM2.5 Concentration: 24 µg/m³
16  11  0b  00  00  00  17  00  00  03  01  00  00  00  21  02  00  00  0b  85
Got PM2.5 Concentration: 23 µg/m³
16  11  0b  00  00  00  17  00  00  03  00  00  00  00  21  02  00  00  0b  86
Got PM2.5 Concentration: 23 µg/m³
```

[Watch the demo on YouTube](https://youtu.be/dUHlG67pB3M)

# Test with Apache NuttX OS

TODO

Here's a quick way to test the IKEA Sensor with NuttX OS. Enter these NuttX commands to read the UART port and dump the data...

```text
nsh> ls /dev
/dev:
 console
 gpio0
 gpio1
 gpio2
 null
 spi0
 spitest0
 timer0
 ttyS1
 urandom
 zero
nsh> cat /dev/ttyS1

3(1>
    2'0A
        2%0C
            1$/F
                .,T
                   .,T
                      .
                       .,V
                          .,V
                             -+Y
                                -+Y
```

[Watch the demo on YouTube](https://youtu.be/iFf8_f7ExUI)

To see the binary data, modify the GPS Demo App: [gps_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/examples/gps/gps_main.c)...

```c
/* Read until we complete a line */
cnt = 0;
do
  {
    read(fd, &ch, 1);
    //  Insert this line to dump the data in hex:
    printf("%02x  ", ch);
```

Build and run the modified GPS Demo App...

```text
nsh> gps
00  00  
16  11  0b  00  00  00  39  00  00  03  39  00  00  00  37  01  00  00  00  21  
16  11  0b  00  00  00  2b  00  00  03  17  00  00  00  29  01  00  00  00  5f  
16  11  0b  00  00  00  32  00  00  03  26  00  00  00  30  01  00  00  00  42 
16  11  0b  00  00  00  31  00  00  03  24  00  00  00  2f  01  00  00  00  46  
16  11  0b  00  00  00  31  00  00  03  24  00  00  00  2f  01  00  00  00  46  
16  11  0b  00  00  00  31  00  00  03  23  00  00  00  2f  01  00  00  00  47  
16  11  0b  00  00  00  31  00  00  03  22  00  00  00  2f  01  00  00  00  48  
16  11  0b  00  00  00  30  00  00  03  21  00  00  00  2e  01  00  00  00  4b  
16  11  0b  00  00  00  2f  00  00  03  1f  00  00  00  2d  01  00  00  00  4f  
16  11  0b  00  00  00  2f  00  00  03  1f  00  00  00  2d  01  00  00  00  4f  
16  11  0b  00  00  00  2f  00  00  03  1f  00  00  00  2d  01  00  00  00  4f  
16  11  0b  00  00  00  2f  00  00  03  1e  00  00  00  2d  01  00  00  00  50  
16  11  0b  00  00  00  2f  00  00  03  1e  00  00  00  2d  01  00  00  00  50  
16  11  0b  00  00  00  2f  00  00  03  1d  00  00  00  2d  01  00  00  00  51  
16  11  0b  00  00  00  2e  00  00  03  1c  00  00  00  2c  01  00  00  00  54  
16  11  0b  00  00  00  2e  00  00  03  1c  00  00  00  2c  01  00  00  00  54  
16  11  0b  00  00  00  2e  00  00  03  1c  00  00  00  2c  01  00  00  00  54
```

[Watch the demo on YouTube](https://youtu.be/TyG-dJCx8OQ)

Yep we see the 20-byte frames of Sensor Data, and the PM 2.5 encoded inside!

PM 2.5 = 46 (`0x002e`)

TODO15

![](https://lupyuen.github.io/images/ikea-gps.png)

TODO16

![](https://lupyuen.github.io/images/ikea-gps2.png)

# Connect to LoRaWAN and The Things Network

TODO

# Visualise with Prometheus and Grafana

TODO

# References

TODO

-   ["Use an IKEA VINDRIKTNING air quality sensor in Home Assistant with ESPHome"](https://style.oversubstance.net/2021/08/diy-use-an-ikea-vindriktning-air-quality-sensor-in-home-assistant-with-esphome/)

-   [IKEA VINDRIKTNING Manual](https://www.ikea.com/us/en/manuals/vindriktning-air-quality-sensor__AA-2289325-1.pdf)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ikea.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ikea.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1490147828458405889)

1.  According to the PM1006 Datasheet, the UART Port runs at [__4.5V Logic Level__](https://lupyuen.github.io/articles/ikea#about-ikea-air-quality-sensor) (instead of 3.3V). Don't we need a [__Voltage Divider__](https://learn.sparkfun.com/tutorials/voltage-dividers/all) to protect our microcontroller, which is not 5V Tolerant?

    Apparently some folks are using the UART Port just fine without a Voltage Divider. [(See this)](https://github.com/Hypfer/esp8266-vindriktning-particle-sensor/issues/44)

    But to be really safe we ought to use a Voltage Divider.

# Appendix: Solder UART Port on IKEA VINDRIKTNING Air Quality Sensor

TODO

Use very fine Solder Wire for tiny blobs of solder

22 AWG Solid Core Wire

TODO7

![](https://lupyuen.github.io/images/ikea-solder.jpg)

TODO8: Cover with Sticky Tape

![](https://lupyuen.github.io/images/ikea-solder2.jpg)

TODO11: Solder the REST Pad

Drop a tiny blob of molten solder on the REST Pad

Place the wire on top of the solder blob (now hardened)

Gently tap our Soldering Iron on top of the wire

The wire should sink into the molten blob

Quickly adjust the wire to make sure it doesn't touch any components on the Circuit Board

When cooled, the wire stays in the hardened blob

![](https://lupyuen.github.io/images/ikea-solder5.jpg)

TODO9: Cover the REST Pad. Solder the GND Pad.

![](https://lupyuen.github.io/images/ikea-solder3.jpg)

TODO10: Result

![](https://lupyuen.github.io/images/ikea-solder4.jpg)

# Appendix: Test with Bus Pirate

TODO

Before testing with Apache NuttX OS, we sniffed the IKEA Sensor's UART Port with Bus Pirate. Connect Bus Pirate to IKEA Sensor as follows...

| Bus Pirate | IKEA Sensor | Wire Colour
|:---|:--:|:---
| Data In (MISO) | REST | Blue
| GND | GND | Black

Connect USB Ports of IKEA Sensor and Bus Pirate to the same computer. Remember: Only One Power Source!

Enter these Bus Pirate commands to capture the UART output from IKEA Sensor (9600 bps, 8 bits, no parity, 1 stop bit)...

```text
HiZ>m
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

(1)>3
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

(1)>5
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
UART>W
POWER SUPPLIES ON
Clutch engaged!!!
```

[Watch the demo on YouTube](https://youtu.be/QOJF6hAhFv4)

See below for the ASCII and Binary Logs.

[(More about Bus Pirate interfacing with UART)](http://dangerousprototypes.com/docs/UART)

## ASCII Log

TODO

ASCII Log of UART Output from IKEA Sensor...

[Watch the demo on YouTube](https://youtu.be/QOJF6hAhFv4)

```text
UART>(2)
Raw UART input
Any key to exit

<@:
   <B:
[6C:;8
[9C:;8
[12C9:7 
[16C997!
[20C987"
[24C876%
[28C876%
[32C876%
[36C866&
[40C856'
[44C745*
[48C745*
[52C745*
[56C745*
[60C735+
[64C614/
[68C614/
[72C614/
[76C614/
[79C
[37;80H 624.
[4C624.
[8C624.
[12C614/
[16C614/
[20C614/
[24C6040
[28C6040
[32C5/33
[36C5.34
[40C4,28
[44C4,28
[48C5-35
[52C5.34
[56C5.34
[60C5-35
[64C4,28
[68C2%0C
[72C2%0C
[76C2&0B
[79C
[37;80H 2'0A
[4C3)1=
[8C3*1<
[12C4+29
```

[(See the complete log)](https://gist.github.com/lupyuen/f40454dda8e3d7f279fb6ef721add465)

## Binary Log

TODO

Binary Log of UART Output from IKEA Sensor...

```text
UART>{
UART LIVE DISPLAY, } TO STOP
UART>
READ: -f 0x00
UART>
READ: -f 0x00
UART>
READ: -f 0x00
UART>
READ: 0x16
UART>
READ: 0x11
UART>
READ: 0x0B
UART>
READ: 0x00
UART>
READ: 0x00
UART>
READ: 0x00
UART>
READ: 0x3D
UART>
READ: 0x00
UART>
READ: 0x00
UART>
READ: 0x03
UART>
READ: 0x45
UART>
READ: 0x00
UART>
READ: 0x00
UART>
READ: 0x00
UART>
READ: 0x3B
UART>
READ: 0x01
UART>
READ: 0x00
UART>
READ: 0x00
UART>
```

[(See the complete log)](https://gist.github.com/lupyuen/db0c97b12bd1070e17cd2e570a5aa810)

[(Another binary log)](https://gist.github.com/lupyuen/ebe4c0628fc9ea2e124e6f00d8246b49)

TODO12

![IKEA VINDRIKTNING Air Quality Sensor connected to Bus Pirate](https://lupyuen.github.io/images/ikea-buspirate.jpg)

TODO13

![](https://lupyuen.github.io/images/ikea-buspirate2.png)

TODO

![Trekking 13 km to IKEA on the horizon in search of VINDRIKTNING](https://lupyuen.github.io/images/ikea-trek.png)

_Trekking 13 km to IKEA on the horizon in search of VINDRIKTNING_
