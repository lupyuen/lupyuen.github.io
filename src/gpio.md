# Mynewt GPIO ported to PineCone BL602 RISC-V Board

📝 _15 Jan 2021_

A month ago we started porting __Apache Mynewt__, a modern embedded operating system, to PineCone BL602...

-   [__"Porting Mynewt to PineCone BL602"__](https://lupyuen.github.io/articles/mynewt)

Then last week we learnt about the __Hardware Abstraction Layer__ provided by the __BL602 IoT SDK__ for controlling GPIO...

-   [__"Control PineCone BL602 RGB LED with GPIO and PWM"__](https://lupyuen.github.io/articles/led)

Today we shall...

1.   __Embed BL602's Hardware Abstraction Layer__ inside Mynewt

1.   __Map Mynewt's GPIO Functions__ to BL602's Hardware Abstraction Layer

If you're new to PineCone BL602, check out my article...

-   [__"Quick Peek of PineCone BL602 RISC-V Evaluation Board"__](https://lupyuen.github.io/articles/pinecone)

![PineCone BL602 RISC-V Evaluation Board with LED controlled by Apache Mynewt](https://lupyuen.github.io/images/gpio-title.jpg)

_PineCone BL602 RISC-V Evaluation Board with LED controlled by Apache Mynewt_

# Our Mynewt GPIO Program

Here's the Mynewt Program that actually runs on our PineCone BL602 Board and switches on the Blue LED: [`main.c`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/apps/blinky/src/main.c)

```c
#include <sysinit/sysinit.h>  //  Init Functions
#include <os/os.h>            //  Mynewt Functions
#include <bsp/bsp.h>          //  Board Support Package
#include <hal/hal_gpio.h>     //  Mynewt HAL for GPIO

//  Define the LED GPIOs: 11 (Blue), 14 (Green), 17 (Red)
#define LED_BLUE_PIN  11
#define LED_GREEN_PIN 14
#define LED_RED_PIN   17

int main(int argc, char **argv) {
    //  Initialise Mynewt drivers
    sysinit();

    //  Set the LED GPIOs to output mode. 
    //  Switch off the LEDs (1 = Off)
    hal_gpio_init_out(LED_BLUE_PIN,  1);
    hal_gpio_init_out(LED_GREEN_PIN, 1);
    hal_gpio_init_out(LED_RED_PIN,   1);

    //  Switch on Blue LED (0 = On)
    hal_gpio_write(LED_BLUE_PIN,  0);

    //  Loop forever
    for(;;) {}
}
```

We're looking at the beauty of Mynewt... Minimal fuss, easy to read, perfect for __learning embedded programming!__

Mynewt Programs are __Portable__ too... `hal_gpio_init_out` and `hal_gpio_write` will work on many microcontrollers: STM32 Blue Pill (Arm), Nordic Semi nRF52 (Arm too), SiFive HiFive1 (RISC-V)... And now PineCone BL602 (RISC-V yay!)

The GPIO Pin numbers will differ. But on PineCone, this Mynewt Program lights up the Blue LED, exactly like the pic above.

Let's find out how we made this work.

# But Why Mynewt?

>_We have many options for learning Embedded Programming on PineCone BL602... Why Mynewt?_

Let's review the options available today for learning Embedded Programming on PineCone BL602...

>_BL602's native IoT SDK looks easy for coding BL602 in C... Supports Multitasking through FreeRTOS (like reading sensor data and sending to network concurrently)_

But with __BL602 IoT SDK__ we'll be locked in to BL602. Our programs won't run on other microcontrollers. 

And we can't easily port programs from other devices to BL602 either.

>_What if we wrap up the BL602 IoT SDK with Arduino Libraries?_

__Arduino__ is kinda ancient for embedded coding. (And the Bit Banging looks disturbing) 

Could there be a modern alternative that works better with today's multitasking microcontrollers?

>_Like Mbed OS? The newer Arduino SAMD boards support mbed OS_

__Mbed OS__ looks complex for learners. (Based on C++)

And Mbed OS was created by Arm so...

>_Zephyr? It's well supported by Linux Foundation and many microcontroller manufacturers_

Maybe something simpler than __Zephyr__?

As simple as the program above? (We'll save Zephyr for the bravest embedded professionals)

>_Alrighty Nitpicky... We're left with Mynewt. But it's not as popular as Zephyr_

__Mynewt__ was designed as a simple tiny OS... And that's OK!

(Mynewt is named after "minute" i.e. "small", not the lizard)

Mynewt is easy to port to BL602. And our porting work will benefit Zephyr later.

>_What about Embedded Rust? We have many fans._

__Embedded Rust__ looks very promising... Clean and safe embedded coding.

There's ongoing work on Embedded Rust for BL602 so let's wait for it.

Meanwhile I'll do Rust the shortcut way... Run it on top of Mynewt. (Instead of Bare Metal)

>_So we'll have Rust on Mynewt?_

Yep! Very soon we shall write embedded programs for PineCone BL602 the simpler safer way in __Rust and Mynewt__. (Without the headaches of C Pointers!)

# What's Next

TODO

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gpio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gpio.md)
