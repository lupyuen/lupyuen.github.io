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

The GPIO Pin Numbers will differ. But on PineCone, this Mynewt Program lights up the Blue LED, exactly like the pic above.

Let's find out how we made this work.

# But Why Mynewt?

>_We have many options for learning Embedded Programming on PineCone BL602... Why Mynewt?_

-   Let's review the options available today for learning Embedded Programming on PineCone BL602...

>_BL602's native IoT SDK looks easy for coding BL602 in C... Supports Multitasking through FreeRTOS (like reading sensor data and sending to network concurrently)_

-   But with __BL602 IoT SDK__ we'll be locked in to BL602. Our programs won't run on other microcontrollers. 

    And we can't easily port programs from other devices to BL602 either.

>_What if we wrap up the BL602 IoT SDK with Arduino Libraries?_

-   __Arduino__ is kinda ancient for embedded coding. (And the Bit Banging looks disturbing) 

    Could there be a modern alternative that works better with today's multitasking microcontrollers?

>_Like Mbed OS? The newer Arduino SAMD boards support mbed OS_

-   __Mbed OS__ looks complex for learners. (Based on C++)

    And Mbed OS was created by Arm so...

>_Zephyr? It's well supported by Linux Foundation and many microcontroller manufacturers_

-   Maybe something simpler than __Zephyr__? As simple as the program above? 

    Something that compiles easily on Linux, macOS and Windows... Without WSL and Docker?
    
    (We'll save Zephyr for the bravest embedded professionals)

>_Alrighty Nitpicky... We're left with Mynewt. But it's not as popular as Zephyr_

-   __Mynewt__ was designed as a simple tiny OS... And that's OK!

    (Mynewt is named after "minute" i.e. "small", not the lizard)

    Mynewt is easy to port to BL602. And our porting work will benefit Zephyr later.

>_What about Embedded Rust? We have many fans._

-   __Embedded Rust__ looks very promising... Clean and safe embedded coding.

    There's ongoing work on Embedded Rust for BL602 so let's wait for it.

    Meanwhile I'll do Rust the shortcut way... Run it on top of Mynewt. (Instead of Bare Metal)

>_So we'll have Rust on Mynewt?_

-   Yep! Very soon we shall write embedded programs for PineCone BL602 the simpler safer way in __Rust and Mynewt__. (Without the headaches of C Pointers!)

# Mynewt and BL602 Layers

_How does Mynewt create programs that are portable to other microcontrollers?_

By using layers of code that isolate the differences between microcontrollers (like BL602) and boards (like PineCone).

(Dressing in layers is a very good thing... Especially in Winter!)

Here's how we layer the code in Mynewt...

![Mynewt and BL602 IoT SDK Layers](https://lupyuen.github.io/images/gpio-stack.png)

1.  __Main Function__: We've seen the Main Function at the top of the article... It lights up the Blue LED.

    Assuming that the GPIO Pin Number is defined correctly, the same Main Function will light up the LED __on any microcontroller__.

    That's why this is portable, __Hardware Independent__ code. A key feature of modern embedded operating systems.

1.  __Board Support Package__: This layer contains code that's specific to the Hardware Board, like PineCone.

    The Blue LED is connected at GPIO 11 on PineCone... And these details will vary depending on the BL602 Board that we use (say PineCone vs Pinenut).

    So it makes sense to capture such __Board Specific__ details inside the Board Support Package layer.

1.  __Microcontroller Package__: This layer is specific to the Microcontroller (like BL602). The Microcontroller Package is reused by all Boards that are based on the same Microcontroller (like PineCone and Pinenut).

1.  __Hardware Abstraction Layer__: This layer is lifted directly from the __BL602 IoT SDK__ (with minimal changes).

    Here we find the functions that control the BL602 hardware: GPIO, PWM, UART, I2C, SPI, ...

1.  __Standard Driver__: This layer is unique to BL602. The Hardware Abstraction Layer in BL602 calls this layer to access the Hardware Registers to perform hardware functions.

_What about the rest of the BL602 IoT SDK?_

We have integrated the smallest subset of functions from the BL602 SDK that are needed for Mynewt. The rest are not needed (yet).

In particular, we don't compile under Mynewt the FreeRTOS driver code from the BL602 SDK. Because running two operating systems side by side would be a disaster!

# GitHub Actions Workflow

TODO

[`.github/workflows/main.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.github/workflows/main.yml)

```yaml
# GitHub Actions Workflow to build Rust+Mynewt Firmware for PineCone BL602

# Name of this Workflow
name: Build Firmware

# When to run this Workflow...
on:

  # Run this Workflow when files are updated (Pushed) in this Branch
  push:
    branches: [ main ]
    
  # Also run this Workflow when a Pull Request is created or updated in this Branch
  pull_request:
    branches: [ main ]

# Steps to run for the Workflow
jobs:
  build:

    # Run these steps on Ubuntu
    runs-on: ubuntu-latest

    steps:
        
    #########################################################################################
    # Checkout
      
    - name: Checkout source files
      uses: actions/checkout@v2
      with:
        submodules: 'recursive'

    - name: Check cache for newt
      id:   cache-newt
      uses: actions/cache@v2
      env:
        cache-name: cache-newt
      with:
        path: ${{ runner.temp }}/mynewt-newt
        key:  ${{ runner.os }}-build-${{ env.cache-name }}
        restore-keys: ${{ runner.os }}-build-${{ env.cache-name }}

    - name: Install newt
      if:   steps.cache-newt.outputs.cache-hit != 'true'  # Install newt if not found in cache
      run:  |
        source scripts/install-version.sh
        cd ${{ runner.temp }}
        git clone --branch $mynewt_version https://github.com/apache/mynewt-newt/
        cd mynewt-newt/
        ./build.sh
        newt/newt version
        export PATH=$PATH:${{ runner.temp }}/mynewt-newt/newt
        newt version

    - name: Show files
      run:  set ; pwd ; ls -l

    #########################################################################################
    # Download and Cache Dependencies

    # - name: Fetch cache for Rust Toolchain
    #   id:   cache-rust
    #   uses: actions/cache@v2
    #   with:
    #     path: |
    #       ~/.cargo/registry
    #       ~/.cargo/git
    #       target
    #     key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    # - name: Install Rust Target thumbv7em-none-eabihf
    #   run:  |
    #     rustup default nightly
    #     rustup target add thumbv7em-none-eabihf
    
    - name: Check cache for xPack RISC-V Toolchain xpack-riscv-none-embed-gcc
      id:   cache-toolchain
      uses: actions/cache@v2
      env:
        cache-name: cache-toolchain
      with:
        path: xpack-riscv-none-embed-gcc
        key:  ${{ runner.os }}-build-${{ env.cache-name }}
        restore-keys: ${{ runner.os }}-build-${{ env.cache-name }}

    - name: Install xPack RISC-V Toolchain xpack-riscv-none-embed-gcc
      if:   steps.cache-toolchain.outputs.cache-hit != 'true'  # Install toolchain if not found in cache
      run:  |
        wget -qO- https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz | tar -xz
        mv xpack-riscv-none-embed-gcc-* xpack-riscv-none-embed-gcc

    #########################################################################################
    # Build and Upload Rust+Mynewt Application Firmware

    - name: Build Application Firmware
      run:  |
        export PATH=$PATH:${{ runner.temp }}/mynewt-newt/newt
        ./scripts/build-app.sh

    - name: Upload Application Firmware
      uses: actions/upload-artifact@v2
      with:
        name: blinky.elf
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.elf

    - name: Upload Application Firmware Outputs
      uses: actions/upload-artifact@v2
      with:
        name: blinky.zip
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.*

    #########################################################################################
    # Finish

    - name: Find output
      run:  |
        find bin/targets/pinecone_app/app/apps/blinky -name "blinky.*" -ls
      
# RISC-V Toolchain will only be cached if the build succeeds.
# So make sure that the first build always succeeds, e.g. comment out the "Build" step.
```

# What's Next

TODO

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gpio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gpio.md)
