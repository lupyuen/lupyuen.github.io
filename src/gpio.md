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

The LED GPIOs are defined in [`bsp/bsp.h`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/include/bsp/bsp.h)...

```c
//  Define the LED GPIOs: 11 (Blue), 14 (Green), 17 (Red)
#define LED_BLUE_PIN  11
#define LED_GREEN_PIN 14
#define LED_RED_PIN   17
```

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

    -   [__Main Function: `main.c`__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/apps/blinky/src/main.c)

1.  __Board Support Package__: This layer contains code that's specific to the Hardware Board, like PineCone.

    The Blue LED is connected at GPIO 11 on PineCone... And these details will vary depending on the BL602 Board that we use (say PineCone vs Pinenut).

    So it makes sense to capture such __Board Specific__ details inside the Board Support Package layer.

    -   [__PineCone Board Support Package: `hw/bsp/pinecone`__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone)

1.  __Microcontroller Package__: This layer is specific to the Microcontroller (like BL602). The Microcontroller Package is reused by all Boards that are based on the same Microcontroller (like PineCone and Pinenut).

    -   [__BL602 Microcontroller Package: `hw/mcu/bl/bl602`__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602)

1.  __Hardware Abstraction Layer__: This layer is lifted directly from the __BL602 IoT SDK__ (with minimal changes).

    Here we find the functions that control the BL602 hardware: GPIO, PWM, UART, I2C, SPI, ...

    -   [__BL602 Hardware Abstraction Layer: `components/hal_drv/bl602_hal`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal)

1.  __Standard Driver__: This layer is unique to BL602. The Hardware Abstraction Layer in BL602 calls this layer to access the Hardware Registers to perform hardware functions.

    -   [__BL602 Standard Driver: `components/bl602/ bl602_std/bl602_std/StdDriver`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src)

_What about the rest of the BL602 IoT SDK?_

We have integrated the smallest subset of functions from the BL602 SDK that are needed for Mynewt. The rest are not needed (yet).

In particular, we don't compile under Mynewt the FreeRTOS driver code from the BL602 SDK. Because running two operating systems side by side would be a disaster!

# Calling the Mynewt and BL602 Layers

To better understand the Mynewt and BL602 Layers, let's walk through the chain of function calls for a GPIO operation...

![Mynewt and BL602 IoT SDK Layers](https://lupyuen.github.io/images/gpio-stack2.png)

1.  In the Hardware-Agnostic __Main Function__, we set the LED GPIO to output mode like so: [`main.c`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/apps/blinky/src/main.c)

    ```c
    int main(int argc, char **argv) {
        //  Set the Blue LED GPIO to output mode
        hal_gpio_init_out(LED_BLUE_PIN,  1);
    ```

    The Mynewt GPIO Function `hal_gpio_init_out` works on any microcontroller.

1.  __`LED_BLUE_PIN`__ is the GPIO Pin Number for the Blue LED.

    The LED GPIO Pin Number will differ across Boards, so `LED_BLUE_PIN` is defined in the __Board Support Package for PineCone__: [`bsp/bsp.h`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/include/bsp/bsp.h)

    ```c
    //  Define the Blue LED GPIO
    #define LED_BLUE_PIN  11
    ```

1.  __`hal_gpio_init_out`__ is a standard Mynewt GPIO Function that works on any microcontroller. But its implementation is specific to the microcontroller.

    Here's the implementation of `hal_gpio_init_out` in our __Microcontroller Package for BL602__: [`bl602/hal_gpio.c`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/src/hal_gpio.c)

    ```c
    int hal_gpio_init_out(int pin, int val) {
        int rc = bl_gpio_enable_output(pin, 0, 0);
    ```

1.  The above implementation calls __`bl_gpio_enable_output`__, which is defined in the __Hardware Abstraction Layer from BL602 IoT SDK__: [`bl602_hal/bl_gpio.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.c)

    ```c
    int bl_gpio_enable_output(uint8_t pin, uint8_t pullup, uint8_t pulldown) {
        ...
        GLB_GPIO_Init(&cfg);
    ```

1.  And finally we call __`GLB_GPIO_Init`__, which is defined in the __Standard Driver from BL602 IoT SDK__: [`StdDriver/bl602_glb.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c)

    GLB refers to __BL602's Global Register__.
    
    `GLB_GPIO_Init` manipulates the GLB Hardware Register to control the GPIO Hardware and switch GPIO 11 to output mode.

# Compile BL602 SDK under Mynewt

_How do we specify which folders of BL602 IoT SDK to compile under Mynewt?_

Remember that we're compiling the smallest subset of functions from the BL602 IoT SDK that are needed for Mynewt...

1.  __BL602 Hardware Abstraction Layer__: [`hal_drv/bl602_hal`](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/hal_drv/bl602_hal)

1.  __BL602 Standard Driver__: [`bl602/bl602_std/ bl602_std/StdDriver`](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/bl602/bl602_std/bl602_std/StdDriver)

We specify these folders in Mynewt's Microcontroller Package for BL602: [`hw/mcu/bl/ bl602/pkg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/pkg.yml)

```yaml
pkg.src_dirs:
    - src
    # Select the BL602 IoT SDK folders to be included for the build
    - ext/bl_iot_sdk/components/hal_drv/bl602_hal
    - ext/bl_iot_sdk/components/bl602/bl602_std/bl602_std/StdDriver/Src
```

The Microcontroller Package for BL602 also specifies the Include Folders and the GCC Compiler Options: [`pkg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/pkg.yml)

```yaml
pkg.cflags: 
    - -march=rv32imac 
    - -mabi=ilp32
    # BL602 IoT SDK definitions
    - -DCONF_USER_ENABLE_PSRAM 
    - -DconfigUSE_TICKLESS_IDLE=0 
    - -DFEATURE_WIFI_DISABLE=1 
    - -DCFG_FREERTOS 
    - -DARCH_RISCV 
    - -DBL602 
    ...
    # Where the BL602 IoT SDK include files are located
    - -Ihw/mcu/bl/bl602/ext/bl_iot_sdk/components/bl602/bl602_std/bl602_std/Common/partition
    - -Ihw/mcu/bl/bl602/ext/bl_iot_sdk/components/bl602/bl602_std/bl602_std/Common/sim_print
    - -Ihw/mcu/bl/bl602/ext/bl_iot_sdk/components/bl602/bl602_std/bl602_std/Common/soft_crc
    ...
```

The above options were obtained by running `make` in Trace Mode when building the BL602 IoT SDK...

```bash
make --trace
```

To preserve the integrity of the BL602 IoT SDK, the entire SDK is mounted under the Mynewt Project as a Git Submodule at...

-   [`hw/mcu/bl/bl602/ext`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/ext)

# FreeRTOS References in BL602 SDK

_Does the BL602 IoT SDK depend on any External Library?_

Unfortunately yes... The BL602 IoT SDK (Hardware Abstraction Layer) depends on FreeRTOS. And this complicates the porting to Mynewt.

Let's look at this code from the BL602 Security (Crypto) HAL: [`bl602_hal/bl_sec.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_sec.c)

```c
int bl_sec_init(void) {
    g_bl_sec_sha_mutex = xSemaphoreCreateMutexStatic(&sha_mutex_buf);
```

This code calls FreeRTOS to create a Mutex (Mutually Exclusive Lock) to prevent tasks from accessing some shared data concurrently.

Mynewt fails to compile this because `xSemaphoreCreateMutexStatic` isn't defined. To work around this, we gave Mynewt a Mock Declaration for the undefined function: [`semphr.h`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/include/semphr.h)

It compiles OK under Mynewt for now. But eventually we need to implement `xSemaphoreCreateMutexStatic` with a Mynewt Semaphore.

Here are the other Mock Declarations for FreeRTOS on Mynewt...
-   [`hw/mcu/bl/bl602/include`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/include)

_Should the BL602 Hardware Abstraction Layer call FreeRTOS?_

This is highly unusual... The Hardware Abstraction Layer (HAL) is Low-Level Code that's meant to called by various Operating Systems. So we don't expect BL602 HAL to call FreeRTOS directly.

(STM32 Blue Pill HAL and nRF52 HAL don't call any Operating Systems either)

This unusual structure seems similar to ESP32, where FreeRTOS is embedded into the ESP32 HAL.

We can still go ahead and port Mynewt (and other Operating Systems) to BL602. Just that we need to emulate the FreeRTOS functions in Mynewt (and other Operating Systems).

# Fix BL602 SDK for Mynewt

Mynewt is strict and uptight when compiling C code with GCC... Any warnings emitted by GCC will fail the Mynewt build.

We made the following fixes to the BL602 IoT SDK to resolve the warnings...

## Mismatched Types

Here we're passing `adc_pin` as a number: [`components/hal_drv/ bl602_hal/bl_adc.c`](https://github.com/pine64/bl_iot_sdk/compare/master...lupyuen:fix-gcc-warnings#diff-50c41592b050878713231111ff6302905f1f2aa7bedff6b250ff6fd6d219cc33)

```c
uint8_t adc_pin = gpio_num;
GLB_GPIO_Func_Init(GPIO_FUN_ANALOG, &adc_pin, 1);
//  Fails because GCC expects adc_pin to be an enum, not a number
```

Which displeases the GCC Compiler because the function `GLB_GPIO_Func_Init` expects an enum `GLB_GPIO_Type`, not a number.

The fix is simple...

```c
//  Declare as enum instead of number
GLB_GPIO_Type adc_pin = gpio_num;
```

## Buffer Overflow

This potential Buffer Overflow seems scary: [`components/hal_drv/ bl602_hal/hal_button.c`](https://github.com/pine64/bl_iot_sdk/compare/master...lupyuen:fix-gcc-warnings#diff-c60188dbf9788696071897d85f50ea1e97b474a7271f6f5de3b46241184c7902)

```c
int i = ...;
char gpio_node[10] = "gpio";
sprintf(gpio_node, "gpio%d", i);
//  Fails because gpio_node may overflow
```

GCC thinks that `i` may exceed 5 digits (because it's a 32-bit integer), causing `gpio_node` to overflow.

For our safety (and to placate GCC), we switch `sprintf` to `snprintf`, which limits the output size...

```c
//  Limit formatting to size of gpio_node
snprintf(gpio_node, sizeof(gpio_node), "gpio%d", i);
```

## External Pointer Reference

Here we use a pointer that's defined in a GCC Linker Script: [`components/hal_drv/ bl602_hal/hal_sys.c`](https://github.com/pine64/bl_iot_sdk/compare/master...lupyuen:fix-gcc-warnings#diff-29ee70160cf58784272419fe4769f988b944038e2d68800b3f51aa179feea412)

```c
extern uint8_t __global_pointer_head$;
memset(&__global_pointer_head$, 0, 0x498);
//  Fails because the pointer references a single byte, not 0x498 bytes
```

GCC thinks that the pointer references a single byte... Copying `0x498` bytes to the pointer would surely cause an overflow!

Thus we do the right thing and tell GCC that it's really a pointer to an array of `0x498` bytes...

```c
//  Pointer to an array of 0x498 bytes
extern uint8_t __global_pointer_head$[0x498];
```

## Pull Request and Pending Analysis

The above fixes (plus a few minor ones) have been submitted upstream as a Pull Request...

-   [__Fix GCC Warning for BL602 SDK on Mynewt__](https://github.com/pine64/bl_iot_sdk/pull/84)

4 fixes have not been pushed upstream yet, because they need more Impact Analysis...

1.  Variable set but not used

    -   [`components/hal_drv/ bl602_hal/hal_board.c`](https://github.com/pine64/bl_iot_sdk/pull/84#discussion_r549207518)

1.  Mismatched format strings

    -   [`components/bl602/bl602_std/ bl602_std/StdDriver/Src/ bl602_common.c`](https://github.com/lupyuen/bl_iot_sdk/commit/2393379c2fd9177cd62484667a0ce07157370e43#diff-99dc1c18d04bd746c17e484406a6f9e5fe733c1f9751adb364ad636253f5c1ae)

1.  Misplaced main function

    -   [`components/bl602/bl602_std/ bl602_std/StdDriver/Src/ bl602_mfg_flash.c`](https://github.com/lupyuen/bl_iot_sdk/commit/2393379c2fd9177cd62484667a0ce07157370e43#diff-d1eb6a16f4855132d64e9decec8de3b44d06d52c03e6825a0dc71dd595cbe157)

1.  Missing include

    -   [`components/bl602/bl602_std/ bl602_std/StdDriver/Src/ bl602_romdriver.c`](https://github.com/lupyuen/bl_iot_sdk/commit/2393379c2fd9177cd62484667a0ce07157370e43#diff-3b9ce4151983dedcd6bc4e3788a8b30b249ff106bd987df589b409cc72f9f2b9)

# Automated Build with GitHub Actions

When porting Mynewt to BL602, it's good to make sure that we don't break any existing code by accident. (Especially the BL602 IoT SDK, which we have tweaked slightly for Mynewt)

That's why we use GitHub Actions to build automatically the Mynewt code (plus the core parts of BL602 IoT SDK) whenever we commit any changes.

Here's the GitHub Actions Workflow that's triggered for Automated Builds: [`.github/workflows/main.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.github/workflows/main.yml)

## Trigger Conditions

TODO

```yaml
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
```

## Build Platform

TODO

```yaml
# Steps to run for the Workflow
jobs:
  build:
    # Run these steps on Ubuntu
    runs-on: ubuntu-latest
```

## Checkout Source Files

TODO

```yaml
    steps:
        
    #########################################################################################
    # Checkout
      
    - name: Checkout source files
      uses: actions/checkout@v2
      with:
        submodules: 'recursive'
```

## Check Cache for newt

TODO

```yaml
    - name: Check cache for newt
      id:   cache-newt
      uses: actions/cache@v2
      env:
        cache-name: cache-newt
      with:
        path: ${{ runner.temp }}/mynewt-newt
        key:  ${{ runner.os }}-build-${{ env.cache-name }}
        restore-keys: ${{ runner.os }}-build-${{ env.cache-name }}
```

## Download and Build newt

TODO

```yaml
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
```

## Show Files

TODO

```yaml
    - name: Show files
      run:  set ; pwd ; ls -l
```

## Check Cache for GCC

TODO

```yaml
    #########################################################################################
    # Download and Cache Dependencies
    
    - name: Check cache for xPack RISC-V Toolchain xpack-riscv-none-embed-gcc
      id:   cache-toolchain
      uses: actions/cache@v2
      env:
        cache-name: cache-toolchain
      with:
        path: xpack-riscv-none-embed-gcc
        key:  ${{ runner.os }}-build-${{ env.cache-name }}
        restore-keys: ${{ runner.os }}-build-${{ env.cache-name }}
```

## Download GCC

TODO

```yaml
    - name: Install xPack RISC-V Toolchain xpack-riscv-none-embed-gcc
      if:   steps.cache-toolchain.outputs.cache-hit != 'true'  # Install toolchain if not found in cache
      run:  |
        wget -qO- https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz | tar -xz
        mv xpack-riscv-none-embed-gcc-* xpack-riscv-none-embed-gcc
```

## Build Mynewt Firmware

TODO

```yaml
    #########################################################################################
    # Build and Upload Rust+Mynewt Application Firmware

    - name: Build Application Firmware
      run:  |
        export PATH=$PATH:${{ runner.temp }}/mynewt-newt/newt
        ./scripts/build-app.sh
```

## Upload Mynewt Firmware

TODO

```yaml
    - name: Upload Application Firmware
      uses: actions/upload-artifact@v2
      with:
        name: blinky.elf
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

TODO

```yaml
    - name: Upload Application Firmware Outputs
      uses: actions/upload-artifact@v2
      with:
        name: blinky.zip
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.*
```

## Show Output

TODO

```yaml
    #########################################################################################
    # Finish

    - name: Find output
      run:  |
        find bin/targets/pinecone_app/app/apps/blinky -name "blinky.*" -ls
```

## Caching Considerations

TODO

```yaml
# RISC-V Toolchain will only be cached if the build succeeds.
# So make sure that the first build always succeeds, e.g. comment out the "Build" step.
```

TODO

```text
path: /home/runner/work/_temp/mynewt-newt
    key: Linux-build-cache-newt
        restore-keys: Linux-build-cache-newt
          env:
              cache-name: cache-newt

actions/cache@v2
  with:
      path: xpack-riscv-none-embed-gcc
          key: Linux-build-cache-toolchain
              restore-keys: Linux-build-cache-toolchain
                env:
                    cache-name: cache-toolchain

```

# Run Mynewt on PineCone

TODO

# What's Next

TODO

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gpio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gpio.md)
