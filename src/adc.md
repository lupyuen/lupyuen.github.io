# Rust on RISC-V BL602: Is It Sunny?

📝 _8 Aug 2021_

Today we shall magically transform __any RISC-V BL602 Board__ into a __Light Sensor!__

We'll build this in C, then __port it to Rust.__

_Wait... Do all BL602 Boards have an onboard Light Sensor?_

Nope, all we need is a __BL602 Board with an LED__!

Reading the LED with BL602's __Analog-to-Digital Converter (ADC)__ will turn it into a __simple, improvised Light Sensor.__ Amazing!

_Will this work with any BL602 Board?_

I tested this with __PineCone BL602__ and its onboard LED.

It will probably work with any BL602 Board with an __onboard or external LED.__

_Will our Light Sensor detect any kind of light?_

Our LED-turned-Light-Sensor works best for __detecting sunlight__.

(Yep It's Always Sunny in Singapore ... So this Sunlight Sensor won't be so useful in Singapore 😂)

![Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon](https://lupyuen.github.io/images/adc-title.jpg)

_Testing the improvised Light Sensor on PineCone BL602 RISC-V Board. BTW that's the moon_

# BL602 ADC in C

TODO

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

_PineCone RGB LED Schematic_

# BL602 ADC in Rust

TODO

# Build the BL602 Rust Firmware

TODO

# Flash the BL602 Rust Firmware

TODO

# Run the BL602 Rust Firmware

TODO

# Rust Wrapper for BL602 IoT SDK

TODO

# Call C Functions from Rust

TODO

# Convert C Pointers to Rust

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

![Testing the improvised Light Sensor on PineCone BL602](https://lupyuen.github.io/images/adc-title2.jpg)
