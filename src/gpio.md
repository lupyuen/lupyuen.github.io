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

When porting Mynewt to BL602, it's good to make sure that we don't __break any existing code by accident__. (Especially the BL602 IoT SDK, which we have tweaked slightly for Mynewt)

That's why we use __GitHub Actions to compile automatically__ the Mynewt code (plus the core parts of BL602 IoT SDK) whenever we __commit any changes__.

_How long does GitHub take to compile our Mynewt + BL602 SDK Code?_

__TWO MINUTES__. Thus if we ever commit some bad code (that can't be compiled) into the repo, GitHub will alert us in TWO MINUTES (via email) that something has gone terribly wrong in our repo.

We'll see the results of the Automated Build here (please log in to GitHub first)...

-   [__GitHub Actions for `pinecone-rust-mynewt`__](https://github.com/lupyuen/pinecone-rust-mynewt/actions)

To complete the build in TWO MINUTES, we use some caching magic inside our GitHub Actions Workflow.

Let's learn how it works: [`.github/workflows/main.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.github/workflows/main.yml)

## Trigger Conditions

At the top of the GitHub Actions Workflow, we state the conditions that will trigger the Automated Build...

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

This says that the Automated Build will be triggered whenever we commit code to the `main` branch. Or when we create a Pull Request for the `main` branch.

## Build Environment

We'll use an Ubuntu x64 virtual machine (hosted at GitHub) to compile our code...

```yaml
# Steps to run for the Workflow
jobs:
  build:
    # Run these steps on Ubuntu
    runs-on: ubuntu-latest
```

## Checkout Source Files

Here begins the steps for our Mynewt + BL602 SDK Automated Build with GitHub Actions.

First we check out the source files from the repo recursively, including the following submodules...

1.  BL602 IoT SDK at [`hw/mcu/bl/bl602/ext`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/ext)

1.  Mynewt Core, NimBLE, MCU Manager and MCUBoot at [`repos`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/repos)

```yaml
    steps:        
    - name: Checkout source files
      uses: actions/checkout@v2
      with:
        submodules: 'recursive'
```

## Check Cache for newt

Mynewt doesn't use `make` to build... It uses its own [build tool named `newt`](https://github.com/apache/mynewt-newt/).

Developed in Go, `newt` runs on Linux, macOS and Windows CMD.

We fetch the `newt` executable from our GitHub Actions Cache, if it exists...

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

(If `newt` isn't found in our cache, we build `newt` and cache it in the next step)

Each cache has a name, ours is `cache-newt`...

```yaml
      env:
        cache-name: cache-newt
```

The Cache Action `actions/cache` requires 3 parameters: `path`, `key` and `restore-keys`...

```yaml
      with:
        path: ${{ runner.temp }}/mynewt-newt
        key:  ${{ runner.os }}-build-${{ env.cache-name }}
        restore-keys: ${{ runner.os }}-build-${{ env.cache-name }}
```

Given that our GitHub Actions Environment is defined as...

```text
runner.temp    = /home/runner/work/_temp
runner.os      = Linux
env.cache-name = cache-newt
```

Our parameters will get expanded to...

```yaml
path:         /home/runner/work/_temp/mynewt-newt
key:          Linux-build-cache-newt
restore-keys: Linux-build-cache-newt
```

Thus the Cache Action will cache and restore the `newt` folder at this temporary folder...

```text
path: /home/runner/work/_temp/mynewt-newt
```

And to avoid confusion with other caches in the same workflow, we give it a unique key...

```text
key: Linux-build-cache-newt
```

## Download and Build newt

Here's how we download and build `newt` if it doesn't exist in our cache...

```yaml
    - name: Install newt
      # Install newt if not found in cache
      if:   steps.cache-newt.outputs.cache-hit != 'true'  
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

(We set `mynewt_version` to `mynewt_1_8_0_tag` in [`scripts/install-version.sh`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/scripts/install-version.sh))

Note the condition: We execute this step only when `newt` doesn't exist in our cache...

```yaml
      # Install newt if not found in cache
      if:   steps.cache-newt.outputs.cache-hit != 'true'
```

(`steps.cache-newt` refers to the cache checking from the previous step)

After building `newt`, the Cache Action `actions/cache` (from the previous step) caches our `newt` folder...

```text
path:  /home/runner/work/_temp/mynewt-newt
```

And restores the `newt` folder whenever we run the Automated Build.

This caching enables us to complete the Automated Build in two minutes. We'll use caching again for the GCC Compiler.

## Show Files

TODO

```yaml
    - name: Show files
      run:  set ; pwd ; ls -l
```

![Mynewt Automated Build completed in 2 minutes](https://lupyuen.github.io/images/gpio-action.png)

_Mynewt Automated Build completed in 2 minutes_

## Check Cache for GCC Compiler

Remember how we cached the `newt` tool to cut down on the build time? We'll do the same for our GCC Compiler...

```yaml
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

First we try to load the GCC Compiler from the cache with these settings...

```text
path:         xpack-riscv-none-embed-gcc
key:          Linux-build-cache-toolchain
restore-keys: Linux-build-cache-toolchain
```

If the GCC Compiler exists in our cache, the Cache Action will restore the GCC folder `xpack-riscv-none-embed-gcc` into the current directory (which is the root of our repo).

## Download GCC Compiler

If the GCC Compiler doesn't exist in our cache, we download the [__xPack RISC-V Toolchain: `xpack-riscv-none-embed-gcc`__](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases)

```yaml
    - name: Install xPack RISC-V Toolchain xpack-riscv-none-embed-gcc
      # Install toolchain if not found in cache
      if:   steps.cache-toolchain.outputs.cache-hit != 'true'  
      run:  |
        wget -qO- https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz | tar -xz
        mv xpack-riscv-none-embed-gcc-* xpack-riscv-none-embed-gcc
```

(Remember: We check `steps.cache-toolchain` and skip this step if the GCC Compiler is already in our cache)

After downloading the GCC Compiler, the Cache Action `actions/cache` (from the previous step) caches our GCC folder...

```text
path:  xpack-riscv-none-embed-gcc
```

Caching the GCC Compiler is essential for reducing the Automated Build time to 2 minutes... Because each download of the xPack RISC-V Toolchain takes a whopping __400 MB!__ (Zipped!)

## Build Mynewt Firmware

Now that we have the build tools ready (`newt` and GCC Compiler), let's build Mynewt with GitHub Actions...

```yaml
    - name: Build Application Firmware
      run:  |
        export PATH=$PATH:${{ runner.temp }}/mynewt-newt/newt
        ./scripts/build-app.sh
```

This sets the path of `newt` and calls the build script: [`scripts/build-app.sh`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/scripts/build-app.sh)

```bash
#  Add GCC to the PATH
export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"

#  Build the Mynewt Firmware
newt build pinecone_app

#  Display the firmware size
newt size -v pinecone_app
```

We can see the results of the Automated Build here (please log in to GitHub first)...

-   [__GitHub Actions for `pinecone-rust-mynewt`__](https://github.com/lupyuen/pinecone-rust-mynewt/actions)

Here's a peek at the Automated Build log at GitHub Actions...

```text
Linking /home/runner/work/pinecone-rust-mynewt/pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
Target successfully built: targets/pinecone_app
+ newt size -v pinecone_app
Size of Application Image: app
Mem flash: 0x22008000-0x22014000
Mem ram: 0x22014000-0x22020000
```

Note that the "Flash Memory" actually points to the Cache Memory at `0x2200 8000`.

This means that our firmware is meant to be tested and debugged with OpenOCD and GDB (or VSCode). (Instead of being flashed to Flash Memory)

```text
  flash     ram 
      6     529 *fill*
    172       0 @apache-mynewt-core_hw_hal.a
   4442    8213 @apache-mynewt-core_kernel_os.a
     80       0 @apache-mynewt-core_libc_baselibc.a
    702     128 @apache-mynewt-core_sys_flash_map.a
      2       0 @apache-mynewt-core_sys_log_modlog.a
    782      29 @apache-mynewt-core_sys_mfg.a
     30       5 @apache-mynewt-core_sys_sysinit.a
     72       0 @apache-mynewt-core_util_mem.a
     36       0 apps_blinky.a
     44      12 hw_bsp_pinecone.a
   3486     228 hw_mcu_bl_bl602.a
     92       0 pinecone_app-sysinit-app.a
    292    1064 libg.a
```

Here are the components of our firmware. The BL602 IoT SDK (GPIO HAL and Standard Driver) occupies 3.4 KB of code and read-only data in `hw_mcu_bl_bl602.a`.

The Mynewt Kernel `apache-mynewt-core_kernel_os.a` occupies 4.3 KB of code and read-only data, plus another 8 KB of read-write data in RAM. (Mostly for the Kernel Stack)

```text
Loading compiler /home/runner/work/pinecone-rust-mynewt/pinecone-rust-mynewt/compiler/riscv-none-embed, buildProfile debug
objsize
   text	   data	    bss	    dec	    hex	filename
  11318	     28	   9100	  20446	   4fde	/home/runner/work/pinecone-rust-mynewt/pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

The build creates a Firmware ELF File `blinky.elf` that contains 11 KB of code and read-only data.

## Upload Mynewt Firmware

To save the firmware files generated by the Automated Build (and allow anyone to download), we call `actions/upload-artifact`...

```yaml
    - name: Upload Application Firmware
      uses: actions/upload-artifact@v2
      with:
        name: blinky.elf
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

Here we save the Mynewt Firmware ELF File `blinky.elf` as an Artifact, to make it accessible for everyone to download. [Download here](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v2.0.0/blinky.elf)

```yaml
    - name: Upload Application Firmware Outputs
      uses: actions/upload-artifact@v2
      with:
        name: blinky.zip
        path: bin/targets/pinecone_app/app/apps/blinky/blinky.*
```

Next we upload another Artifact named `blinky.zip` that contains some useful files from the Mynewt Automated Build...

1.  `blinky.elf.bin`: Mynewt Firmware Binary.

    Contains only the firmware code and read-only data, without the debugging symbols.
    
    -   [Download here](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v2.0.0/blinky.elf.bin)

1.  `blinky.elf.map`: GCC Linker Map for our Mynewt Firmware. 

    Shows the addresses of every function and global variable in our firmware.

    -   [Download here](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v2.0.0/blinky.elf.map)

1.  `blinky.elf.lst`: RISC-V Assembly Code for our Mynewt Firmware.

    Disassembled from our firmware build.

    -   [Download here](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v2.0.0/blinky.elf.lst)

## Show Output

TODO

```yaml
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

# Run Mynewt on PineCone

To test and debug the updated Mynewt on PineCone with our Linux / macOS / Windows computer...

1.  Download and install `newt`, GCC, OpenOCD, VSCode and `pinecone-rust-mynewt`...

    ["Build the Firmware"](https://lupyuen.github.io/articles/mynewt#build-the-firmware)

1.  Build the Mynewt firmware on our computer using the instructions above.

    Alternatively, [download `blinky.elf` from here](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v2.0.0/blinky.elf) and copy it to...

    ```text
    pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky
    ```

1.  Connect PineCone to our computer with a JTAG Debugger and start the VSCode Debugger...

    ["Debug Firmware with VSCode"](https://lupyuen.github.io/articles/mynewt#debug-firmware-with-vscode)

In the GDB Debug Console we'll see this...

```text
Breakpoint 1 at 0x220092ba: file apps/blinky/src/main.c, line 30.
Breakpoint 2 at 0x22008242: file repos/apache-mynewt-core/kernel/os/src/arch/rv32imac/os_fault.c, line 30.
Remote debugging using | xpack-openocd/bin/openocd -c "gdb_port pipe; log_output openocd.log" -f openocd.cfg
Running executable
xPack OpenOCD, x86_64 Open On-Chip Debugger 0.10.0+dev-00378-ge5be992df (2020-06-26-12:31)
```

This says that we have set two breakpoints. And that OpenOCD has been started, talking to PineCone.

```text
0x21000000 in ?? ()
Not implemented stop reason (assuming exception): undefined
```

OpenOCD has taken control of BL602 and has halted the execution at address `0x2100 0000`

Which is really interesting because `0x2100 0000` is the address of __BL602's Boot ROM__.  Thus we have evidence that BL602 starts running the Boot ROM code at `0x2100 0000` whenever it reboots.

```text
Loading section .init, size 0xa2 lma 0x22008000
Loading section .text, size 0x1c1c lma 0x220080a4
Loading section .tcm_code, size 0xaa0 lma 0x22009cc0
Loading section .rodata, size 0x94 lma 0x2200a760
Loading section .sdata2.HFXOSC_PLL_256_MHZ, size 0x8 lma 0x2200a7f4
Loading section .sdata2._global_impure_ptr, size 0x4 lma 0x2200a7fc
Loading section .data, size 0x438 lma 0x2200a800
Loading section .sdata, size 0x1c lma 0x2200ac38
Start address 0x22008000, load size 11346
Transfer rate: 2 KB/sec, 1418 bytes/write.
```

Our GDB Script ([see this](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.vscode/launch.json#L15-L39)) has loaded our firmware to BL602 at address `0x2200 8000`, which is in Cache Memory.

(BL602 doesn't support flashing firmware to Flash Memory with OpenOCD. [More details](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd%26GDB/en))

```text
Breakpoint 1, main (argc=0, argv=0x0) at apps/blinky/src/main.c:30
30	int main(int argc, char **argv) {
```

When the debugger code hits the first breakpoint (in the `main` function), click the Continue button in the Debug Toolbar. (Or press F5)

# JTAG Foiled By GPIO

Calamity strikes as our Mynewt GPIO Firmware runs.

Yes the Blue LED lights up, but we also see this error in GDB...

```text
Debugger is not authenticated to target Debug Module. (dmstatus=0x0).
Use `riscv authdata_read` and `riscv authdata_write` commands to authenticate.
```

That's because PineCone's RGB LED is __connected to the same pins as the JTAG port!__

| PineCone Pin | LED Pin | JTAG Pin |
|:---|:---|:---|
| `IO 11` | __`Blue`__  | __`TDO`__
| `IO 14` | __`Green`__ | __`TCK`__
| `IO 17` | __`Red`__   | __`TDI`__

(See ["If you love the LED... Set it free!"](https://lupyuen.github.io/articles/openocd#if-you-love-the-led-set-it-free))

TODO

![Sensors and actuators to be tested with PineCone BL602](https://lupyuen.github.io/images/gpio-sensors.jpg)

_Sensors and actuators to be tested with PineCone BL602_

# What's Next

TODO

DHT11

[More about BME280](https://medium.com/coinmonks/watch-stm32-blue-pill-juggle-two-spi-sensors-with-dma-20cd1aa89869?source=friends_link&sk=eea71070ce6d9aea3a6108e882749a99)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gpio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gpio.md)

# Appendix: Inventory of Sensors and Actuators

![Sensors and actuators to be tested with PineCone BL602](https://lupyuen.github.io/images/gpio-sensors.jpg)

_Sensors and actuators to be tested with PineCone BL602_

## Sensors

| Sensor | Outputs |
|:---|:---|
| Linear Hall | Analog, Digital
| Shock Switch | Digital
| Knock Switch | Digital
| Mini Reed Switch | Digital
| Analog Temperature | Analog
| Analog & Digital <br>Temperature | Analog, Digital
| Button Switch | Digital
| Tilt Switch | Digital
| Photoresistor | Analog
| Digital Temperature <br>& Humidity (DHT11) | Digital (Serial)
| High Sensitivity Audio | Analog, Digital
| Metal Touch | Analog, Digital
| Flame | Analog, Digital

## Actuators

| Actuator | Input |
|:---|:---|
| Laser Transmitter | Digital
| Active Buzzer | Digital
| Passive Buzzer | Digital
| Relay | Digital

## Sensor + Actuator

| Sensor + Actuator | Input / Output |
|:---|:---|
| Infrared Transmitter & Receiver | Digital
