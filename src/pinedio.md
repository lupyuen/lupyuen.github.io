# PineDio Stack BL604 RISC-V Board: Testing The Prototype

📝 _3 Sep 2021_

_What's it like to create __Open Source Software__ (and firmware) for brand new __Prototype Hardware__?_

_What interesting challenges will we encounter?_

Find out how we create new firmware to test (and improve) Pine64's newest and hottest prototype: __PineDio Stack BL604 RISC-V Board!__

> ⚠️ ___Obligatory Disclaimer:__ Features included in The Prototype are not complete, and will most certainly undergo changes before becoming available for public consumption. (Burp) They are described here for testing, exploration, education and entertainment purposes only. The Prototype shall NOT be used in production gadgets. (Like toasters, microwave ovens, and most definitely not, pressure cookers)_

The kind (and super cool) folks at Pine64 told me that I would be receiving a fun new gadget that's...

1.  Based on [__BL604 RISC-V + WiFi + Bluetooth LE SoC__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_DS/en), which is the upsized sibling of [__Bouffalo Lab's BL602 SoC__](https://lupyuen.github.io/articles/pinecone).

    (BL604 has 32 GPIOs vs BL602's 16 GPIOs. So it's like comparing millipedes and centipedes, I guess)

1.  And BL604 is supposed to be __100% compatible with BL602__

    (Is it really 100% compatible? We'll find out in a while!)

1.  Has an __ST7789 SPI Display__

    (Imagine the possibilities)

1.  Has an onboard __LoRa SX1262 Transceiver__ for low-power, long-range, low-bandwidth networking

    (Wow!)

1.  Plus __SPI Flash, Battery Charging Chip, Motion Sensor__ (optional) and __Heart Rate Sensor__ (optional)!

After some shipping delays at Shenzhen (due to flooding or pandemic?) I received something totally unexpected...

![Solar Panel?](https://lupyuen.github.io/images/pinedio-solar.jpg)

__A Solar Panel!__

(Yeah Singapore is super sunny... Is this mockery? 🤔)

But a Solar Panel with a __JTAG Cable__? That's highly unusual. 

Opening the gadget reveals the hidden treasure inside: __PineDio Stack BL604 Board!__

![Inside the Solar Panel: PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-inside.jpg)

That's typical of __Prototype Hardware__ fresh from the factory: No docs, no fancy packaging, no branding either.

(Ground Plane is also missing, which we'll fix before FCC Certification)

We shall explore PineDio Stack ourselves... And __document all our findings__ for the sake of the Open Source Community!

![PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-title.jpg)

# Connect The Display

_What's on the underside of PineDio Stack?_

Unscrewing the board (from the glue sticks?) reveals the __LCD Display Connector__ on the underside of the board...

![PineDio Stack Underside](https://lupyuen.github.io/images/pinedio-back.jpg)

The connector matches this familiar __ST7789 SPI Display__ that was shipped with PineDio Stack...

![ST7789 SPI Display](https://lupyuen.github.io/images/pinedio-display3.jpg)

So we snapped the ST7789 Display to the board...

![ST7789 Display connected to PineDio Stack](https://lupyuen.github.io/images/pinedio-display4.jpg)

And we get an unusual contraption: A __Solar Panel with LCD Display inside__!

![Solar Panel with an LCD Display inside](https://lupyuen.github.io/images/pinedio-display5.jpg)

We're ready to test our firmware on PineDio Stack!

# BL604 Blinky

_What's the first thing that we run on a brand new prototype board?_

__Blinky Firmware__ of course! (Yep the firmware that blinks the LED)

```c
/// PineDio Stack LCD Backlight is connected on GPIO 21
#define LED_GPIO 21

/// Blink the LED
void blinky(char *buf, int len, int argc, char **argv) {
  //  Show a message on the serial console
  puts("Hello from Blinky!");

  //  Configure the LED GPIO for output (instead of input)
  int rc = bl_gpio_enable_output(
    LED_GPIO,  //  GPIO pin number
    0,         //  No GPIO pullup
    0          //  No GPIO pulldown
  );
  assert(rc == 0);  //  Halt on error

  //  Blink the LED 5 times
  for (int i = 0; i < 10; i++) {

    //  Toggle the LED GPIO between 0 (on) and 1 (off)
    rc = bl_gpio_output_set(  //  Set the GPIO output (from BL602 GPIO HAL)
      LED_GPIO,               //  GPIO pin number
      i % 2                   //  0 for low, 1 for high
    );
    assert(rc == 0);  //  Halt on error

    //  Sleep 1 second
    time_delay(                 //  Sleep by number of ticks (from NimBLE Porting Layer)
      time_ms_to_ticks32(1000)  //  Convert 1,000 milliseconds to ticks (from NimBLE Porting Layer)
    );
  }
  //  Return to the command-line interface
}
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_blinky/pinedio_blinky/demo.c)

This BL604 Blinky code is __100% identical__ to the [BL602 version of Blinky](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_blinky/sdk_app_blinky/demo.c). Except for the GPIO Pin Number...

```c
/// PineDio Stack LCD Backlight is connected on GPIO 21
#define LED_GPIO 21
```

(We're blinking the Backlight of the ST7789 Display)

We __build the BL604 Blinky Firmware__ the exact same way as BL602...

```bash
#  Download the 3wire branch of lupyuen's bl_iot_sdk
git clone --recursive --branch 3wire https://github.com/lupyuen/bl_iot_sdk
cd customer_app/pinedio_blinky

#  Build for BL602 (Should this be BL604?)
export CONFIG_CHIP_NAME=BL602

#  Where BL602 / BL604 IoT SDK is located
export BL60X_SDK_PATH=$PWD/../..

#  Build the firmware: build_out/pinedio_blinky.bin
make
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_blinky/run.sh)

Let's flash the firmware to the board!

# Flashing Firmware To BL604

TODO

![](https://lupyuen.github.io/images/pinedio-zoom.jpg)

Remove the battery

Missing jumper, No reset button

# BL604 SPI

TODO

Backward compatible, Spi quirks

# Logic Analyser

_Always have a Logic Analyser ready when testing Prototype Hardware!_

TODO

![](https://lupyuen.github.io/images/pinedio-gpio.jpg)

TODO

![](https://lupyuen.github.io/images/pinedio-logic.jpg)

TODO11

![](https://lupyuen.github.io/images/pinedio-logic2.jpg)

# ST7789 Display

TODO

![](https://lupyuen.github.io/images/pinedio-display2.jpg)

# 9-Bit SPI?

TODO

![](https://lupyuen.github.io/images/st7789-4wire.jpg)

TODO

![](https://lupyuen.github.io/images/st7789-3wire.jpg)

# Arduino GFX Ported To BL604

TODO

Bl602 book, Created from scratch with few official docs, But lots of experimentation and reading the SDK code

# What's Next

TODO

Volunteers Needed!

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/08/15/introducing-the-pinenote/)... As we explore whether it's feasible to teach Embedded Programming for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinedio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinedio.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1429273222780887041)

![](https://lupyuen.github.io/images/pinedio-box.jpg)
