# Visual Programming with Zig and NuttX Sensors

📝 _20 Aug 2022_

![Visual Programming with Zig and NuttX Sensors on Blockly](https://lupyuen.github.io/images/visual-title.jpg)

_What if we could drag-and-drop NuttX Sensors... To create IoT Sensor Apps?_

Let's find out!

TODO: And we'll run it on Pine64's [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone).

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

-   [__lupyuen3/blockly-zig-nuttx__](https://github.com/lupyuen3/blockly-zig-nuttx)

And learn how how we ended up here...

-   [__Blockly with Zig (Work in Progress)__](https://lupyuen3.github.io/blockly-zig-nuttx/demos/code/)

-   [__Watch the Demo on YouTube__](https://youtu.be/192ZKA-1OqY)

# Zig Sensor App

TODO

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-connect.jpg)

# Connect BME280 Sensor

TODO

For testing the Zig Sensor App, we connect the BME280 Sensor (I2C) to Pine64's [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone) (pic above)...

| BL602 Pin | BME280 Pin | Wire Colour
|:---:|:---:|:---|
| __`GPIO 1`__ | `SDA` | Green 
| __`GPIO 2`__ | `SCL` | Blue
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

The __I2C Pins__ on BL602 are defined here: [board.h](https://github.com/lupyuen/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L91-L98)

```c
/* I2C Configuration */
#define BOARD_I2C_SCL \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | \
  GPIO_PIN2)
#define BOARD_I2C_SDA \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | \
  GPIO_PIN1)
```

[(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

# Compile Zig App

TODO

Below are the steps to __compile our Zig Sensor App__ for Apache NuttX RTOS and BL602 RISC-V SoC.

First we download the latest version of __Zig Compiler__ (0.10.0 or later), extract it and add to PATH...

-   [__Zig Compiler Downloads__](https://ziglang.org/download/)

Then we download and compile __Apache NuttX RTOS__ for BL602...

-   [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/nuttx#build-nuttx)

Check that the following have been enabled in the NuttX Build...

-   [__I2C0 Port__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__I2C Character Driver__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__BME280 Driver__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__Sensor Driver Test App__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

Remember to set [__"Sensor Driver Test Stack Size"__](https://lupyuen.github.io/articles/bme280#configure-nuttx) to __4096__.

(Because our Zig App needs additional Stack Space)

After building NuttX, we download and compile our __Zig Sensor App__...

```bash
##  Download our Zig Sensor App for NuttX
git clone --recursive https://github.com/lupyuen/visual-zig-nuttx
cd visual-zig-nuttx

##  Compile the Zig App for BL602
##  (RV32IMACF with Hardware Floating-Point)
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
zig build-obj \
  --verbose-cimport \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -isystem "$HOME/nuttx/nuttx/include" \
  -I "$HOME/nuttx/apps/include" \
  sensortest.zig
```

[(See the Compile Log)](https://gist.github.com/lupyuen/8d7a2a360bc4d14264c77f82da58b3dc)

Note that __target__ and __mcpu__ are specific to BL602...

-   [__"Zig Target"__](https://lupyuen.github.io/articles/zig#zig-target)

_How did we get the Compiler Options `-isystem` and `-I`?_

Remember that we'll link our Compiled Zig App into the NuttX Firmware.

Hence the __Zig Compiler Options must be the same__ as the GCC Options used to compile NuttX.

[(See the GCC Options for NuttX)](https://github.com/lupyuen/visual-zig-nuttx#sensor-test-app-in-c)

Next comes a quirk specific to BL602: We must __patch the ELF Header__ from Software Floating-Point ABI to Hardware Floating-Point ABI...

```bash
##  Patch the ELF Header of `sensortest.o` from 
##  Soft-Float ABI to Hard-Float ABI
xxd -c 1 sensortest.o \
  | sed 's/00000024: 01/00000024: 03/' \
  | xxd -r -c 1 - sensortest2.o
cp sensortest2.o sensortest.o
```

[(More about this)](https://lupyuen.github.io/articles/zig#patch-elf-header)

Finally we inject our __Compiled Zig App__ into the NuttX Project Directory and link it into the __NuttX Firmware__...

```bash
##  Copy the compiled app to NuttX and overwrite `sensortest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp sensortest.o $HOME/nuttx/apps/testing/sensortest/sensortest*.o

##  Build NuttX to link the Zig Object from `sensortest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make

##  For WSL: Copy the NuttX Firmware to c:\blflash for flashing
mkdir /mnt/c/blflash
cp nuttx.bin /mnt/c/blflash
```

We're ready to run our Zig App!

![Zig Sensor App](https://lupyuen.github.io/images/sensor-run1a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#read-barometer-sensor)

# Run Zig App

TODO

Follow these steps to __flash and boot NuttX__ (with our Zig App inside) on BL602...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

In the NuttX Shell, enter this command to start our Zig App...

```bash
sensortest test
```

Which reads the __Air Pressure and Temperature__ from the BME280 Barometer Sensor...

```text
nsh> sensortest test
Zig Sensor Test
test_sensor
pressure:1007.66
temperature:27.70
```

This says that the Air Pressure is __1,007.66 millibars__ and the Temperature is __27.70 °C__.

Then enter this...

```bash
sensortest test2
```

Which reads the __Humidity__ from the BME280 Humidity Sensor...

```text
nsh> sensortest test2
Zig Sensor Test
test_sensor2
humidity:78.81
```

This says that the Relative Humidity is __78.81 %__.

Yep our Zig Sensor App reads the Air Pressure, Temperature and Humidity correctly from BME280 Sensor yay!

![Multiple Sensors](https://lupyuen.github.io/images/sensor-run2a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#clean-up)

# What's Next

TODO

Check out my earlier work on Zig, NuttX, LoRaWAN and LVGL...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/visual.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/visual.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1557857587667775489)
