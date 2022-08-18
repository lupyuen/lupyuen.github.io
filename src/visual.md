# Visual Programming with Zig and NuttX Sensors

📝 _19 Aug 2022_

![Visual Programming with Zig and NuttX Sensors on Blockly](https://lupyuen.github.io/images/visual-title.jpg)

_What if we could drag-and-drop NuttX Sensors... To create quick prototypes for IoT Sensor Apps?_

Let's do it! The pic above shows the __IoT Sensor App__ that we'll build with __Visual Programming__, the drag-and-drag way.

This produces a [__Zig Program__](https://ziglang.org/) that will...

-   Read the Sensor Data from a __NuttX Sensor__ (like Bosch BME280)
    
-   Encode the Sensor Data (with CBOR)

-   Transmit the encoded data to a __Wireless IoT Network__ (like LoRaWAN)

And it has been tested with [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) on Pine64's [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone). (Pic below)

_Why are we doing this?_

Programming NuttX Sensors today feels rather cumbersome, with lots of __Boilerplate Code__ and Error Handling. Which might overwhelm those among us who are new to NuttX Sensors.

Perhaps we can wrap the code into a __Visual Component__ that we'll simply pick and drop into our program?

This might also be perfect for __quick experiments__ with various NuttX Sensors.

(More about this below)

_Why Zig?_

Zig has neat features (like __Type Inference__ and __Compile-Time Expressions__) that will greatly simplify the code that's auto-generated for our Visual Program.

We could have done this in C... But it would've taken a lot more time and effort.

(We'll come back to this)

_Let's get started!_

We'll head down into the Source Code for our project...

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

-   [__lupyuen3/blockly-zig-nuttx__](https://github.com/lupyuen3/blockly-zig-nuttx)

And learn how how we ended up here...

-   [__Blockly with Zig and NuttX (Work in Progress)__](https://lupyuen3.github.io/blockly-zig-nuttx/demos/code/)

-   [__Watch the Demo on YouTube__](https://youtu.be/GL2VWO4wNcA)

![PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)](https://lupyuen.github.io/images/spi2-title.jpg)

[_PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)_](https://lupyuen.github.io/articles/spi2)

# Blockly for IoT Sensor Apps

_What's an IoT Sensor App anyway?_

Suppose we're building an __IoT Sensor Device__ that will monitor Temperature, Humidity and Air Pressure.

The firmware in our device will periodically __read and transmit the Sensor Data__ like this...

![IoT Sensor App](https://lupyuen.github.io/images/blockly-iot.jpg)

Which we might build as an __IoT Sensor App__ like so...

![IoT Sensor App in Blockly](https://lupyuen.github.io/images/visual-block6.jpg)

That's our focus for today: Create NuttX Firmware that will...

-   __Read__ a NuttX Sensor (like Bosch BME280)
    
-   __Encode__ the Sensor Data with [__CBOR__](https://lupyuen.github.io/articles/cbor2)

-   __Transmit__ the Sensor Data over [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

_How will we do the drag-n-drop?_

We'll implement the visual coding with [__Blockly__](https://developers.google.com/blockly), the Scratch-like browser-based coding toolkit.

Previously we have __customised Blockly__ to generate Zig Programs...

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

Now we'll extend Blockly to produce IoT Sensor Apps.

![NuttX Blocks that we have added to Blockly](https://lupyuen.github.io/images/visual-block8.jpg)

[_NuttX Blocks that we have added to Blockly_](https://lupyuen3.github.io/blockly-zig-nuttx/demos/code/)

# NuttX Blocks

In Blockly, we create programs by picking and dropping __Interlocking Blocks__.

Each Block will emit __Zig Code__ that we'll compile and run with NuttX.

To support IoT Sensor Apps, we extend Blockly and add the following __NuttX Blocks__ (pic above)...

-   __BME280 Sensor Block__: Read Temperature / Humidity / Pressure from [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/)

-   __Compose Message Block__: Compose a [__CBOR Message__](https://lupyuen.github.io/articles/cbor2) with our Sensor Data

-   __Transmit Message Block__: Transmit a CBOR Message to [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

-   __Every Block__: Do something every X seconds

Let's inspect our NuttX Blocks and the Zig Code that they produce.

![BME280 Sensor Block](https://lupyuen.github.io/images/visual-block5.jpg)

## BME280 Sensor Block

As pictured above, our __BME280 Sensor Block__ reads Temperature, Humidity and Pressure from the [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/).

Our Sensor Block will generate this __Zig Code__...

```zig
try sen.readSensor(           // Read BME280 Sensor
  c.struct_sensor_baro,       // Sensor Data Struct
  "temperature",              // Sensor Data Field
  "/dev/sensor/sensor_baro0"  // Path of Sensor Device
);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

This calls our Zig Function [__readSensor__](https://lupyuen.github.io/articles/visual#appendix-read-sensor-data) to read a NuttX Sensor at the specified path.

[(__readSensor__ is defined in the Sensor Module __sen__)](https://lupyuen.github.io/articles/visual#appendix-read-sensor-data)

_What's `try`?_

That's how we __handle errors__ in Zig. If __readSensor__ fails with an error, we stop the current function and return the error to the caller.

_But struct_sensor_baro is not a value, it's a Struct Type!_

Yep [__struct_sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) is actually a Struct Type that Zig has auto-imported from NuttX. [(As defined here)](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355)

_So Zig will let us pass Struct Types to a Function?_

That's the neat thing about Zig... It will let us pass __Compile-Time Expressions__ (like Struct Types) to Zig Functions (like __readSensor__).

The Zig Compiler will __substitute the Struct Type__ inside the code for __readSensor__. (Which works like a C Macro)

Another neat thing: __"temperature"__ above is also a Compile-Time Expression, because it's a Field Name in the [__sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) Struct. Metaprogramming gets so cool!

[(More about __readSensor__ in the Appendix)](https://lupyuen.github.io/articles/visual#appendix-read-sensor-data)

_Why the full path "/dev/sensor/sensor_baro0"? Why not just "baro0"?_

Call me stupendously stubborn, but I think it might be better for learners to see the full path of NuttX Sensors?

So we have a better understanding of NuttX Sensors and how to troubleshoot them.

[(The NuttX Sensor Path has just been renamed to "/dev/uorb/sensor_baro0")](https://github.com/apache/incubator-nuttx/blob/master/drivers/sensors/sensor.c#L50)

_What about other sensors? BMP280, ADXL345, LSM330, ..._

We plan to create a __Sensor Block for every sensor__ that's supported by NuttX.

Thus we can build all kinds of IoT Sensor Apps by dragging-n-dropping the Sensor Blocks for BMP280, ADXL345, LSM330, ...

![Compose Message Block](https://lupyuen.github.io/images/visual-block7b.jpg)

## Compose Message Block

The __Compose Message Block__ composes a [__CBOR Message__](https://lupyuen.github.io/articles/cbor2) with the specified Keys (Field Names) and Values (Sensor Data).

(Think of CBOR as a compact, binary form of JSON)

CBOR Messages usually require __fewer bytes than JSON__ to represent the same data. They work better with Low-Bandwidth Networks. (Like LoRaWAN)

The Block above will generate this __Zig Code__...

```zig
const msg = try composeCbor(.{  // Compose CBOR Message
  "t", temperature,
  "p", pressure,
  "h", humidity,
});
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Which calls our Zig Function [__composeCbor__](https://lupyuen.github.io/articles/visual#appendix-encode-sensor-data) to create the CBOR Message.

_What's `.{ ... }`?_

That's how we pass a __Variable Number of Arguments__ to a Zig Function.

_Is it safe? What if we make a mistake and omit a Key or a Value?_

__composeCbor__ uses __Compile-Time Validation__ to verify that the parameters are OK.

If we omit a Key or a Value (or if they have the wrong Types), the Zig Compiler will stop us during compilation.

[(__composeCbor__ is explained here)](https://lupyuen.github.io/articles/visual#appendix-encode-sensor-data)

![Transmit Message Block](https://lupyuen.github.io/images/visual-block7c.jpg)

## Transmit Message Block

The __Transmit Message Block__ (above) transmits a CBOR Message to [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) (the low-power, long-range, low-bandwidth IoT Network)...

```zig
// Transmit message to LoRaWAN
try transmitLorawan(msg);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

And probably other __IoT Networks__ in future: NB-IoT, LTE-M, Matter, Bluetooth, WiFi, MQTT, ...

[(__transmitLorawan__ is explained here)](https://lupyuen.github.io/articles/visual#appendix-transmit-sensor-data)

![Every Block](https://lupyuen.github.io/images/visual-block10.jpg)

## Every Block

Lastly we have the __Every Block__ (above) that executes the Enclosed Blocks every X seconds...

```zig
// Every 10 seconds...
while (true) {
  // TODO: Enclosed Blocks
  ...

  // Wait 10 seconds
  _ = c.sleep(10);
}
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

_What's "`_ = `something"?_

Zig Compiler helpfully stops us if we forget to use the __Return Value__ of a function.

We write "`_ = ...`" to tell Zig Compiler that we won't use the Return Value of the __sleep__ function. (Imported from NuttX)

_Sleepy fish? This sleeping looks fishy..._

Yep this __sleep__ won't work for some types of IoT Sensor Apps.

We'll revisit this in a while.

_How did we add these NuttX Blocks to Blockly?_

Blockly provides __Blockly Developer Tools__ for creating our Custom Blocks.

We'll explain the steps in the Appendix...

-   [__"Create Custom Blocks"__](https://lupyuen.github.io/articles/visual#appendix-create-custom-blocks)

# Test NuttX Blocks

To test the NuttX Blocks, let's drag-n-drop an IoT Sensor App that will...

-   __Read Sensor Data:__ Read the Temperature, Pressure and Humidity from BME280 Sensor

-   __Print Sensor Data:__ Print the above values

-   __Compose Message:__ Create a CBOR Message with the Temperature, Pressure and Humidity values

-   __Transmit Message:__ Send the CBOR Message to LoRaWAN

First we download our __Zig Sensor App__ (that imports the NuttX Sensor API into Zig)...

```bash
##  Download our Zig Sensor App for NuttX
git clone --recursive https://github.com/lupyuen/visual-zig-nuttx
```

(We'll paste our generated Zig Program inside here)

Now head over to our __Custom Blockly Website__...

-   [__Blockly with Zig and NuttX (Work in Progress)__](https://lupyuen3.github.io/blockly-zig-nuttx/demos/code/)

Drag-n-drop the Blocks to assemble this Visual Program...

![IoT Sensor App](https://lupyuen.github.io/images/visual-block6.jpg)

To find the above Blocks, click the __Blocks Toolbox__ (at left) and look under __"Sensors"__, __"Variables"__ and __"Text"__...

-   [__Watch the Demo on YouTube__](https://youtu.be/GL2VWO4wNcA)

Note that we read __Humidity__ from __"sensor_humi0"__ instead of "sensor_baro0".

Click the __Zig Tab__. We'll see this Zig Program...

```zig
/// Main Function
pub fn main() !void {

  // Every 10 seconds...
  while (true) {
    const temperature = try sen.readSensor(  // Read BME280 Sensor
      c.struct_sensor_baro,       // Sensor Data Struct
      "temperature",              // Sensor Data Field
      "/dev/sensor/sensor_baro0"  // Path of Sensor Device
    );
    debug("temperature={}", .{ temperature });

    const pressure = try sen.readSensor(  // Read BME280 Sensor
      c.struct_sensor_baro,       // Sensor Data Struct
      "pressure",                 // Sensor Data Field
      "/dev/sensor/sensor_baro0"  // Path of Sensor Device
    );
    debug("pressure={}", .{ pressure });

    const humidity = try sen.readSensor(  // Read BME280 Sensor
      c.struct_sensor_humi,       // Sensor Data Struct
      "humidity",                 // Sensor Data Field
      "/dev/sensor/sensor_humi0"  // Path of Sensor Device
    );
    debug("humidity={}", .{ humidity });

    const msg = try composeCbor(.{  // Compose CBOR Message
      "t", temperature,
      "p", pressure,
      "h", humidity,
    });

    // Transmit message to LoRaWAN
    try transmitLorawan(msg);

    // Wait 10 seconds
    _ = c.sleep(10);
  }
}
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Copy the code inside the __Main Function__. (Yep copy the __while__ loop)

Paste the code inside the __Zig Sensor App__ that we have downloaded earlier...

-   [__visual-zig-nuttx/visual.zig__](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

(Look for "Paste Visual Program Here")

_Can we save the Blocks? So we don't need to drag them again when retesting?_

Click the __JSON Tab__ and copy the Blockly JSON that appears.

Whenever we reload Blockly, just paste the Blockly JSON back into the JSON Tab. The Blocks will be automagically restored.

[(See the Blockly JSON)](https://gist.github.com/lupyuen/f7466a2e208eb68fd01a788c829b57e9)

We're ready to build and test our IoT Sensor App! But first we prep our hardware...

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-connect.jpg)

[_Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor_](https://lupyuen.github.io/articles/sensor)

# Connect BME280 Sensor

For testing our IoT Sensor App, we connect the BME280 Sensor (I2C) to Pine64's [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone) (pic above)...

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

Below are the steps to __compile our IoT Sensor App__ for NuttX.

We download the latest version of __Zig Compiler__ (0.10.0 or later), extract it and add to PATH...

-   [__Zig Compiler Downloads__](https://ziglang.org/download/)

Then we download and compile __NuttX for BL602__...

-   [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/nuttx#build-nuttx)

The downloaded version of NuttX already includes our __BME280 Driver__...

-   [__"Apache NuttX Driver for BME280 Sensor"__](https://lupyuen.github.io/articles/bme280)

Check that the following have been enabled in the NuttX Build...

-   [__I2C0 Port__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__I2C Character Driver__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__BME280 Driver__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

-   [__Sensor Driver Test App__](https://lupyuen.github.io/articles/bme280#configure-nuttx)

Remember to set [__"Sensor Driver Test Stack Size"__](https://lupyuen.github.io/articles/bme280#configure-nuttx) to __4096__.

(Because our Zig App needs additional Stack Space)

After building NuttX, compile our __IoT Sensor App__...

```bash
##  Zig Sensor App that we have downloaded earlier.
##  TODO: Paste our visual program into visual-zig-nuttx/visual.zig
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

[(See the Compile Log)](https://gist.github.com/lupyuen/eddfb4a11ed306d478f47adece9d6e1a)

Note that __target__ and __mcpu__ are specific to BL602...

-   [__"Zig Target"__](https://lupyuen.github.io/articles/zig#zig-target)

Also specific to BL602 is the __ARCH_RISCV__ Macro in [visual-zig-nuttx/sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L11)

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

We're ready to run our IoT Sensor App!

![IoT Sensor App running on PineCone BL602](https://lupyuen.github.io/images/visual-run1.png)

_IoT Sensor App running on PineCone BL602_

# Run Zig App

Follow these steps to __flash and boot NuttX__ (with our Zig App inside) on BL602...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

In the NuttX Shell, enter this command to start our __IoT Sensor App__...

```bash
sensortest visual
```

[(__sensortest__ is explained here)](https://lupyuen.github.io/articles/sensor#main-function)

Our IoT Sensor App should correctly read the __Temperature, Pressure and Humidity__ from BME280 Sensor, and transmit the values to LoRaWAN (simulated)...

```text
NuttShell (NSH) NuttX-10.3.0
nsh> sensortest visual
Zig Sensor Test
Start main

temperature=31.05
pressure=1007.44
humidity=71.49
composeCbor
  t: 31.05
  p: 1007.44
  h: 71.49
  msg=t:31.05,p:1007.44,h:71.49,
transmitLorawan
  msg=t:31.05,p:1007.44,h:71.49,

temperature=31.15
pressure=1007.40
humidity=70.86
composeCbor
  t: 31.15
  p: 1007.40
  h: 70.86
  msg=t:31.15,p:1007.40,h:70.86,
transmitLorawan
  msg=t:31.15,p:1007.40,h:70.86,
```

[(See the Complete Log)](https://github.com/lupyuen/visual-zig-nuttx#test-visual-zig-sensor-app)

Yep we have successfully created an IoT Sensor App with Blockly, Zig and NuttX! 🎉

_Can we test without NuttX?_

To test our IoT Sensor App on __Linux / macOS / Windows__ (instead of NuttX), add the stubs below to simulate a NuttX Sensor...

-   [__"Test Stubs"__](https://github.com/lupyuen/visual-zig-nuttx#test-stubs)

# Why Zig

_Once again... Why are we doing this in Zig?_

It's __easier to generate__ Zig Code for our IoT Sensor App. That's because Zig supports...

-   __Type Inference__: Zig Compiler will fill in the missing Types

-   __Compile-Time Expressions__: Zig Compiler will let us manipulate Struct Types and Fields at Compile-Time

-   __Compile-Time Variable Arguments__: Zig Compiler will validate the Variable Arguments for our Function

We could have programmed Blockly to generate C Code. But it would be messy, here's why...

## Type Inference

In many Compiled Languages (including C), we need to __specify the Types__ for our Constants (and Variables)...

```zig
// This is a Float (f32)
const temperature: f32 = try sen.readSensor(...);

// This is a Struct (CborMessage)
const msg: CborMessage = try composeCbor(...);
```

But thanks to __Type Inference__, we may omit the Types in Zig...

```zig
// Zig Compiler infers that this is a Float
const temperature = try sen.readSensor(...);

// Zig Compiler infers that this is a Struct
const msg = try composeCbor(...);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

This simplifies the __Code Generation__ in Blockly, since we don't track the Types.

## Compile-Time Expressions

Earlier we saw this for reading the BME280 Sensor...

```zig
// Read Temperature from BME280 Sensor
temperature = try sen.readSensor(
  c.struct_sensor_baro,       // Sensor Data Struct
  "temperature",              // Sensor Data Field
  "/dev/sensor/sensor_baro0"  // Path of Sensor Device
);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Looks concise and tidy, but __readSensor__ has 2 surprises...

-   [__struct_sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) is actually a __Struct Type__

    (Auto-imported by Zig from NuttX)

-   __"temperature"__ is actually a __Struct Field Name__

    (From the [__sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) Struct)

The Zig Compiler will __substitute the Struct Type__ and Field Name inside the code for __readSensor__. (Which works like a C Macro)

[(More about __readSensor__ in the Appendix)](https://lupyuen.github.io/articles/visual#appendix-read-sensor-data)

_Is this doable in C?_

Possibly, if we define a C Macro that embeds the entire __readSensor__ function.

(Which might be a headache for maintenance)

## Variable Arguments

Zig has a neat way of handling __Variable Arguments__ at Compile-Time.

Remember __composeCbor__ from earlier?

```zig
// Compose CBOR Message with a 
// Variable Number of Keys and Values
const msg = try composeCbor(.{
  "t", temperature,
  "p", pressure,
  "h", humidity,
});
```

__composeCbor__ accepts a __Variable Number of Arguments__ and it uses __Compile-Time Validation__ to verify that the parameters are OK.

If we omit a Key or a Value (or if they have the wrong Types), the Zig Compiler will stop us during compilation.

[(__composeCbor__ is explained here)](https://lupyuen.github.io/articles/visual#appendix-encode-sensor-data)

_Could we have done this in C?_

In C, we would call some [__messy macros__](https://github.com/lupyuen/stm32bluepill-mynewt-sensor/blob/master/libs/sensor_coap/include/sensor_coap/sensor_coap.h#L219-L323) to validate and manipulate the parameters at Compile-Time.

Or implement as [__Variadic Functions in C__](https://en.cppreference.com/w/c/variadic), without the Compile-Time Type Checking.

That's why Zig is a better target for Automated Code Generation in Blockly.

![Expected firmware for our IoT Sensor Device](https://lupyuen.github.io/images/blockly-iot.jpg)

[_Expected firmware for our IoT Sensor Device_](https://lupyuen.github.io/articles/visual#blockly-for-iot-sensor-apps)

# Real World Complications

Remember earlier we drew the pic above for our __IoT Sensor Firmware__?

Then we kinda glossed over the details and made this __IoT Sensor App__...

> ![IoT Sensor App](https://lupyuen.github.io/images/visual-block6.jpg)

To run this in the __Real World__, we need some tweaks...

_Is it really OK to transmit messages to LoRaWAN every 10 seconds?_

Nope it's NOT OK to send messages every 10 seconds! LoRaWAN imposes limits on the __Message Rate__.

We can send one LoRaWAN Message roughly __every 20 to 60 seconds__, depending on the Message Size.

[(More about this)](https://lupyuen.github.io/articles/lorawan3#message-interval)

_So we tweak the Loop to run every 60 seconds?_

Well then our Sensor Data (Temperature / Pressure / Humidity) would become __stale and inaccurate__.

We need to __collect and aggregate__ the Sensor Data more often.

This means splitting into two loops: __Read Sensor Loop__ and __Transmit Loop__...

![Multiple Loops](https://lupyuen.github.io/images/visual-block12.jpg)

(We'll explain "x100" in the next section)

Missing from the pic: We need to compute the __Average Temperature / Pressure / Humidity__ over the past 60 seconds.

And we __transmit the Average Sensor Data__. (Instead of the Raw Sensor Data)

This gives us better Sensor Data through __frequent sampling__, even though we're sending one message every minute.

(Some sensors like BME280 can actually do frequent sampling on their own. Check for [__Standby Interval__](https://lupyuen.github.io/articles/bme280#standby-interval))

_Will Blockly and Zig support two Loops?_

Not yet. With two Loops, we have the problem of __Sleepy Fishes__...

```zig
// Read Sensor Loop...
while (true) {
  ...
  // Wait 30 seconds
  _ = c.sleep(30);
}

// Transmit Loop...
while (true) {
  ...
  // Wait 60 seconds
  _ = c.sleep(60);
}

// Oops! Transmit Loop will never run!
```

We loop forever (calling __sleep__) in the First Loop, thus we'll never reach the Second Loop.

_So we should do this with Timers instead?_

Yep our Loops shall be implemented with proper __Multithreaded Timers__.

Like from [__NimBLE Porting Layer__](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer). (Or just plain NuttX Timers)

Let's sum up the tweaks that we need...

![Grand Plan for our IoT Sensor App](https://lupyuen.github.io/images/sensor-visual.jpg)

_Grand Plan for our IoT Sensor App_

# Upcoming Fixes

In the previous section we talked about the __quirks in our IoT Sensor App__ and why it won't work in the Real World.

This is how we'll fix it...

## Multithreading and Synchronisation

-   __sleep__ won't work for Multiple Loops. We'll switch to __Multithreaded Timers__ instead

    (From [__NimBLE Porting Layer__](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer) or just plain NuttX Timers)

-   Our Read Sensor Loop needs to pass the __Aggregated Sensor Data__ to Transmit Loop

-   Since both Loops run concurrently, we need to __Lock the Sensor Data__ during access

    (Hence the Locking and Averaging in the sketch above)

## Message Constraints

-   Our app shall transmit LoRaWAN Messages __every 60 seconds__, due to the Message Rate limits. [(Here's why)](https://lupyuen.github.io/articles/lorawan3#message-interval)

-   CBOR Messages are smaller if we encode our __Sensor Data as Integers__ (instead of Floating-Point Numbers)

    We propose to scale up our Sensor Data by 100 (pic below) and encode them as Integers. (Which preserves 2 decimal places)

    [(More about CBOR Encoding)](https://lupyuen.github.io/articles/cbor2#floating-point-numbers)

-   We'll probably test LoRaWAN with Waveshare's [__LoRa SX1262 Breakout Board__](https://www.waveshare.com/wiki/Pico-LoRa-SX1262) (non-sponsored)

    (Because our current LoRa SX1262 Board is reserved for [__NuttX Automated Testing__](https://lupyuen.github.io/articles/auto))

-   Waveshare's [__I2C Multi-Sensor Board__](https://www.waveshare.com/wiki/Pico-Environment-Sensor) (non-sponsored) looks super interesting for mixing-n-matching Multiple Sensors

![Sensor Data scaled by 100 and encoded as integers](https://lupyuen.github.io/images/visual-block11.jpg)

_Sensor Data scaled by 100 and encoded as integers_

## Blockly Limitations

-   Some Blocks won't emit __valid Zig Code__

    [(Our Zig Code Generator for Blockly is incomplete)](https://lupyuen.github.io/articles/blockly#code-generator)

-   __Double Asssignment__ fails with Zig and Blockly...

    ![Double Asssignment](https://lupyuen.github.io/images/blockly-run12.jpg)

    [(More about this)](https://lupyuen.github.io/articles/blockly#constants-vs-variables)

-   __Shadowed Identifiers__ won't work either...

    ![Shadowed Identifiers](https://lupyuen.github.io/images/blockly-run15.jpg)

    [(More about this)](https://lupyuen.github.io/articles/blockly#constants-vs-variables)

-   Copying the Zig Code from Blockly into NuttX feels cumbersome. We might streamline this by wrapping Blockly as a __Desktop App.__

    [(More about this)](https://lupyuen.github.io/articles/blockly#desktop-and-mobile)

There's plenty to be fixed, please lemme know if you're keen to help! 🙏

![Connect a Sensor to our Microcontroller and it pops up in Blockly!](https://lupyuen.github.io/images/visual-arduino.jpg)

_Connect a Sensor to our Microcontroller and it pops up in Blockly!_

# Visual Arduino?

[__Alan Carvalho de Assis__](https://www.linkedin.com/in/acassis/) has a brilliant idea for an Embedded Dev Tool that's __modular, visual, plug-and-play__...

>   "I think creating some modular solution to compete with Arduino could be nice! Imagine that instead of wiring modules in the breadboard people just plug the device in the board and it recognize the device and add it to some graphical interface"

>   "For example, you just plug a temperature sensor module in your board and it will identify the module type and you can pass this Temperature variable to use in your logic application"

Just __connect a Sensor__ to our Microcontroller... And it pops up in __Blockly__, all ready for us to read the Sensor Data! (Pic above)

To detect the Sensor, we could use [__SPD (Serial Presence Detection)__](https://en.m.wikipedia.org/wiki/Serial_presence_detect), like for DDR Memory Modules.

(Or maybe we scan the I2C Bus and read the Chip ID?)

What do you think? Please let us know! 🙏

(Would be great if we could create a Proof-of-Concept using Universal Perforated Board)

![Up Next: Prometheus, Grafana and The Things Network](https://lupyuen.github.io/images/prometheus-title.jpg)

[_Up Next: Prometheus, Grafana and The Things Network_](https://lupyuen.github.io/articles/prometheus)

# What's Next

This has been an exhilarating journey into __IoT, Zig and Visual Programming__ that spans four articles (including this one)...

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

I hope you'll join me for more!

Check out my earlier work on Zig and NuttX...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

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

![BME280 Sensor Block](https://lupyuen.github.io/images/visual-block1.jpg)

_BME280 Sensor Block_

# Appendix: Read Sensor Data

As pictured above, our __BME280 Sensor Block__ reads Temperature, Humidity and Pressure from the [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/).

The Blocks above will generate this __Zig Code__...

```zig
// Read the Temperature
const temperature = try sen.readSensor(
  c.struct_sensor_baro,       // Sensor Data Struct to be read
  "temperature",              // Sensor Data Field to be returned
  "/dev/sensor/sensor_baro0"  // Path of Sensor Device
);

// Print the Temperature
debug("temperature={}", .{ temperature });
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Looks concise and tidy, but __readSensor__ has 2 surprises...

-   [__struct_sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) is actually a __Struct Type__

    (Auto-imported by Zig from NuttX)

-   __"temperature"__ is actually a __Struct Field Name__

    (From the [__sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) Struct)

The Zig Compiler will __substitute the Struct Type__ and Field Name inside the code for __readSensor__. (Which works like a C Macro)

_How does it work?_

__readSensor__ declares the Sensor Data Struct Type and Sensor Data Field as __`comptime`__...

```zig
/// Read a Sensor and return the Sensor Data
pub fn readSensor(
  comptime SensorType: type,        // Sensor Data Struct to be read, like c.struct_sensor_baro
  comptime field_name: []const u8,  // Sensor Data Field to be returned, like "temperature"
  device_path: []const u8           // Path of Sensor Device, like "/dev/sensor/sensor_baro0"
) !f32 { ...
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L34-L108)

Which means that Zig Compiler will __substitute the values__ at Compile-Time (like a C Macro)...

-   __SensorType__ changes to __c.struct_sensor_baro__

-   __field_name__ changes to __"temperature"__

__readSensor__ will then use __SensorType__ to refer to the [__sensor_baro__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L348-L355) Struct...

```zig
  // Define the Sensor Data Type.
  // Zig Compiler replaces `SensorType` by `c.struct_sensor_baro`
  var sensor_data = std.mem.zeroes(
    SensorType
  );
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L89-L92)

And __readSensor__ will use __field_name__ to refer to the __"temperature"__ field...

```zig
  // Return the Sensor Data Field.
  // Zig Compiler replaces `field_name` by "temperature"
  return @field(
    sensor_data,  // Sensor Data Type from above
    field_name    // Field Name is "temperature"
  );
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L106-L107)

Check out this doc for details on __`comptime`__ and Zig Metaprogramming...

-   [__"Zig Metaprogramming"__](https://ikrima.dev/dev-notes/zig/zig-metaprogramming/)

_What's inside readSensor?_

Let's look at the implementation of __readSensor__ in [sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L34-L108) and walk through the steps for reading a NuttX Sensor...

## Open Sensor Device

We begin by __opening the NuttX Sensor Device__: [sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L34-L108)

```zig
/// Read a Sensor and return the Sensor Data
pub fn readSensor(
  comptime SensorType: type,        // Sensor Data Struct to be read, like c.struct_sensor_baro
  comptime field_name: []const u8,  // Sensor Data Field to be returned, like "temperature"
  device_path: []const u8           // Path of Sensor Device, like "/dev/sensor/sensor_baro0"
) !f32 {

  // Open the Sensor Device
  const fd = c.open(
    &device_path[0],           // Path of Sensor Device
    c.O_RDONLY | c.O_NONBLOCK  // Open for read-only
  );
```

__`open()`__ should look familiar... On Linux we open Devices the same way.

_What's "`[]const u8`"?_

That's a __Slice of Bytes__, roughly equivalent to a String in C.

[(More about Slices)](https://lupyuen.github.io/articles/sensor#slice-vs-string)

_What's "`!f32`"?_

That's the __Return Type__ of our function...

-   Our function returns the Sensor Data as a 32-bit __Floating-Point Number__

    (Hence "`f32`")

-   But it might return an __Error__

    (Hence the "`!`")

_Why the "`c.`" prefix?_

We write "`c.`_something_" for Functions, Types and Macros __imported from C__.

[(As explained here)](https://lupyuen.github.io/articles/sensor#import-nuttx-functions)

Next we check if the Sensor Device has been __successfully opened__...

```zig
  // Check for error
  if (fd < 0) {
    std.log.err(
      "Failed to open device:{s}",
      .{ c.strerror(errno()) }
    );
    return error.OpenError;
  }
```

If the Sensor Device doesn't exist, we print a Formatted Message to the __Error Log__ and return an Error.

[(__OpenError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L152-L163)

_What's "`{s}`"?_

That's for printing a __Formatted String__ in Zig.

It's equivalent to "`%s`" in C...

```c
printf("Failed to open device:%s", strerror(errno()));
```

_What's "`.{ ... }`"?_

That's how we pass a __list of Arguments__ when printing a Formatted Message.

If we have no Arguments, we write "`.{}`"

[("`.{ ... }`" creates an Anonymous Struct)](https://ziglang.org/documentation/master/#Anonymous-Struct-Literals)

## Close Sensor Device (Deferred)

We've just opened the Sensor Device and we must __close it later__...

But the Control Flow gets complicated because we might need to __handle Errors__ and quit early. In C we'd code this with "`goto`".

For Zig we do this nifty trick...

```zig
  // Close the Sensor Device when this function returns
  defer {
    _ = c.close(fd);
  }
```

When we write __"`defer`"__, this chunk of code will be executed __when our function returns__.

This brilliantly solves our headache of __closing the Sensor Device__ when we hit Errors later.

_Why the "`_ =` something"?_

Zig Compiler stops us if we forget to use the __Return Value__ of a Function.

We write "`_ =` _something_" to tell Zig Compiler that we're not using the Return Value.

## Set Standby Interval

Some sensors (like BME280) will automatically measure Sensor Data at __Periodic Intervals__. [(Like this)](https://lupyuen.github.io/articles/bme280#standby-interval)

Let's assume that our sensor will measure Sensor Data __every 1 second__...

```zig
  // Set Standby Interval
  const interval: c_uint = 1_000_000;  // 1,000,000 microseconds (1 second)
  var ret = c.ioctl(
    fd,                  // Sensor Device
    SNIOC_SET_INTERVAL,  // ioctl Command
    interval             // Standby Interval
  );
```

(__c_uint__ is equivalent to "unsigned int" in C)

In case of error, we quit...

```zig
  // Check for error
  if (ret < 0 and errno() != c.ENOTSUP) {
    std.log.err("Failed to set interval:{s}", .{ c.strerror(errno()) });
    return error.IntervalError;
  }
```

[(__IntervalError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L152-L163)

Which also closes the Sensor Device. (Due to our earlier "`defer`")

## Set Batch Latency

We set the __Batch Latency__, if it's needed by our sensor...

```zig
  // Set Batch Latency
  const latency: c_uint = 0;  // No latency
  ret = c.ioctl(
    fd,             // Sensor Device
    c.SNIOC_BATCH,  // ioctl Command
    latency         // Batch Latency
  );
```

And we check for error...

```zig
  // Check for error
  if (ret < 0 and errno() != c.ENOTSUP) {
    std.log.err("Failed to batch:{s}", .{ c.strerror(errno()) });
    return error.BatchError;
  }
```

[(__BatchError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L152-L163)

## Poll Sensor

After the enabling the sensor, we __poll the sensor__ to check if Sensor Data is available...

```zig
  // Poll for Sensor Data
  var fds = std.mem.zeroes(c.struct_pollfd);
  fds.fd = fd;
  fds.events = c.POLLIN;
  ret = c.poll(&fds, 1, -1);

  // Check if Sensor Data is available
  if (ret <= 0) {
    std.log.err("Sensor data not available", .{});
    return error.DataError;
  }
```

__std.mem.zeroes__ creates a __pollfd__ Struct that's initialised with nulls.

(The struct lives on the stack)

## Read Sensor Data

We __allocate a buffer__ (on the stack) to receive the Sensor Data...

```zig
  // Define the Sensor Data Type
  var sensor_data = std.mem.zeroes(
    SensorType
  );
  const len = @sizeOf(
    @TypeOf(sensor_data)
  );
```

Remember that __SensorType__ is a __`comptime`__ Compile-Time Type.

Zig Compiler will change __SensorType__ to a Struct Type like __c.struct_sensor_baro__

__std.mem.zeroes__ returns a Sensor Data Struct, initialised with nulls.

We __read the Sensor Data__ into the struct...

```zig
  // Read the Sensor Data
  const read_len = c.read(fd, &sensor_data, len);

  // Check size of Sensor Data
  if (read_len < len) {
    std.log.err("Sensor data incorrect size", .{});
    return error.SizeError;
  }
```

## Return Sensor Data

Finally we return the __Sensor Data Field__...

```zig
  // Return the Sensor Data Field
  return @field(
    sensor_data,  // Sensor Data Type from above
    field_name    // Field Name like "temperature"
  );
}
```

Remember that __field_name__ is a __`comptime`__ Compile-Time String.

Zig Compiler will change __field_name__ to a Field Name like __"temperature"__

And that's how __readSensor__ reads the Sensor Data from a NuttX Sensor!

![Compose Message Block](https://lupyuen.github.io/images/visual-block7b.jpg)

_Compose Message Block_

# Appendix: Encode Sensor Data

The __Compose Message Block__ composes a [__CBOR Message__](https://lupyuen.github.io/articles/cbor2) with the specified Keys (Field Names) and Values (Sensor Data).

(Think of CBOR as a compact, binary form of JSON)

CBOR Messages usually require __fewer bytes than JSON__ to represent the same data. They work better with Low-Bandwidth Networks. (Like LoRaWAN)

The Block above will generate this __Zig Code__...

```zig
const msg = try composeCbor(.{  // Compose CBOR Message
  "t", temperature,
  "p", pressure,
  "h", humidity,
});
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Which will show this output...

```text
composeCbor
  t: 31.05
  p: 1007.44
  h: 71.49
  msg=t:31.05,p:1007.44,h:71.49,
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#test-visual-zig-sensor-app)

_composeCbor accepts a variable number of arguments? Strings as well as numbers?_

Yep, here's the implementation of __composeCbor__: [visual.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig#L59-L102)

```zig
/// TODO: Compose CBOR Message with Key-Value Pairs
/// https://lupyuen.github.io/articles/cbor2
fn composeCbor(args: anytype) !CborMessage {
  debug("composeCbor", .{});
  comptime {
    assert(args.len % 2 == 0);  // Missing Key or Value
  }

  // Process each field...
  comptime var i: usize = 0;
  var msg = CborMessage{};
  inline while (i < args.len) : (i += 2) {

    // Get the key and value
    const key   = args[i];
    const value = args[i + 1];

    // Print the key and value
    debug("  {s}: {}", .{
      @as([]const u8, key),
      floatToFixed(value)
    });

    // Format the message for testing
    var slice = std.fmt.bufPrint(
      msg.buf[msg.len..], 
      "{s}:{},",
      .{
        @as([]const u8, key),
        floatToFixed(value)
      }
    ) catch { _ = std.log.err("Error: buf too small", .{}); return error.Overflow; };
    msg.len += slice.len;
  }
  debug("  msg={s}", .{ msg.buf[0..msg.len] });
  return msg;
}
```

[(__floatToFixed__ is explained here)](https://lupyuen.github.io/articles/sensor#appendix-fixed-point-sensor-data)

__CborMessage__ is a Struct that contains the CBOR Buffer...

```zig
/// TODO: CBOR Message
/// https://lupyuen.github.io/articles/cbor2
const CborMessage = struct {
  buf: [256]u8 = undefined,  // Limit to 256 bytes
  len: usize = 0,            // Length of buffer
};
```

Note that __composeCbor__'s parameter is declared as __`anytype`__...

```zig
fn composeCbor(args: anytype) { ...
```

That's why __composeCbor__ accepts a variable number of arguments with different types.

To handle each argument, the Zig Compiler will unroll (expand) this __`inline`__ __`comptime`__ loop during compilation...

```zig
  // Zig Compiler will unroll (expand) this Loop.
  // Process each field...
  comptime var i: usize = 0;
  inline while (i < args.len) : (i += 2) {

    // Get the key and value
    const key   = args[i];
    const value = args[i + 1];

    // Print the key and value
    debug("  {s}: {}", .{
      @as([]const u8, key),
      floatToFixed(value)
    });
    ...
  }
```

(Think of it as a C Macro, expanding our code during compilation)

Thus if we have 3 pairs of Key-Values, Zig Compiler will emit the above code 3 times.

[(__floatToFixed__ is explained here)](https://lupyuen.github.io/articles/sensor#appendix-fixed-point-sensor-data)

_What happens if we omit a Key or a Value when calling composeCbor?_

This __`comptime`__ Assertion Check will __fail during compilation__...

```zig
// This assertion fails at Compile-Time
// if we're missing a Key or a Value
comptime {
  assert(args.len % 2 == 0);
}
```

_What happens if we pass incorrect Types for the Key or Value?_

__composeCbor__ expects the following Types...

-   Key should be a (string-like) __Byte Slice__ (`[]const u8`)

-   Value should be a __Floating-Point Number__ (`f32`)

If the Types are incorrect, Zig Compiler will stop us here __during compilation__...

```zig
    // Print the key and value
    debug("  {s}: {}", .{
      @as([]const u8, key),
      floatToFixed(value)
    });
```

[(__floatToFixed__ is explained here)](https://lupyuen.github.io/articles/sensor#appendix-fixed-point-sensor-data)

Hence __composeCbor__ might look fragile with its Variable Arguments and Types...

```zig
const msg = try composeCbor(.{  // Compose CBOR Message
  "t", temperature,
  "p", pressure,
  "h", humidity,
});
```

But Zig Compiler will actually stop us during compilation if we pass invalid arguments.

_The implementation of CBOR Encoding is missing?_

Yep we shall import the __TinyCBOR Library__ from C to implement the CBOR Encoding in __composeCbor__...

-   [__"Encode Sensor Data with CBOR"__](https://lupyuen.github.io/articles/cbor2)

![Transmit Message Block](https://lupyuen.github.io/images/visual-block7c.jpg)

_Transmit Message Block_

# Appendix: Transmit Sensor Data

The __Transmit Message Block__ (above) transmits a CBOR Message to [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) (the low-power, long-range, low-bandwidth IoT Network)...

```zig
// Transmit message to LoRaWAN
try transmitLorawan(msg);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

Which will show this output...

```text
transmitLorawan
  msg=t:31.05,p:1007.44,h:71.49,
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#test-visual-zig-sensor-app)

The implementation of __transmitLorawan__ is currently a stub...

```zig
/// TODO: Transmit message to LoRaWAN
fn transmitLorawan(msg: CborMessage) !void { 
  debug("transmitLorawan", .{});
  debug("  msg={s}", .{ msg.buf[0..msg.len] });
}
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig#L107-L111)

We shall implement LoRaWAN Messaging by calling the __LoRaWAN Library__ that's imported from C...

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

![Blockly Developer Tools](https://lupyuen.github.io/images/visual-block3.jpg)

_Blockly Developer Tools_

# Appendix: Create Custom Blocks

In the previous article we have __customised Blockly__ to generate Zig Programs...

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

For this article we __added Custom Blocks__ to Blockly to produce IoT Sensor Apps...

-   [__"Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#custom-block)

-   [__"Create Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#create-custom-block)

-   [__"Export Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#export-custom-block)

This is how we __loaded our Custom Blocks__ into Blockly...

-   [__"Load Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#load-custom-block)

-   [__"Show Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#show-custom-block)

Each Custom Block has a __Code Generator__ that will emit Zig Code...

-   [__"Code Generator for Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#code-generator-for-custom-block)

-   [__"Build Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#build-custom-block)

-   [__"Test Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#test-custom-block)

The __Compose Message Block__ is more sophisticated, we implemented it as a Custom Extension in Blockly...

-   [__"Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#custom-extension)

-   [__"Code Generator for Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#code-generator-for-custom-extension)

-   [__"Test Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#test-custom-extension)

Official docs for __Blockly Custom Blocks__...

-   [__"Customise Blockly"__](https://developers.google.com/blockly/guides/create-custom-blocks/overview)

![Block Exporter in Blockly Developer Tools](https://lupyuen.github.io/images/visual-block4.jpg)

_Block Exporter in Blockly Developer Tools_
