# Visual Programming with Zig and NuttX Sensors

📝 _20 Aug 2022_

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

We'll explain below.

# Test NuttX Blocks

To test the NuttX Blocks, let's drag-n-drop an IoT Sensor App that will...

-   __Read Sensor Data:__ Read the Temperature, Pressure and Humidity from BME280 Sensor

-   __Print Sensor Data:__ Print the Temperature, Pressure and Humidity values

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

We're ready to build and test our IoT Sensor App with NuttX! But first we prep our hardware...

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

First we download the latest version of __Zig Compiler__ (0.10.0 or later), extract it and add to PATH...

-   [__Zig Compiler Downloads__](https://ziglang.org/download/)

Then we download and compile __Apache NuttX RTOS__ for BL602...

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

In the NuttX Shell, enter this command to start our IoT Sensor App...

```bash
sensortest visual
```

Our IoT Sensor App should correctly read the Temperature, Pressure and Humidity from BME280 Sensor, and transmit the values to LoRaWAN (simulated)...

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

To test the Zig program above on Linux / macOS / Windows (instead of NuttX), add the stubs below to simulate a NuttX Sensor...

-   [__"Test Stubs"__](https://github.com/lupyuen/visual-zig-nuttx#test-stubs)

# Why Zig

_Once again... Why are we doing this in Zig?_

It's __easier to generate__ Zig Code for our IoT Sensor App. That's because Zig supports...

1.  __Type Inference__

1.  __Compile-Time Expressions__

1.  __Compile-Time Variable Arguments__

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
// Zig infers that this is a Float
const temperature = try sen.readSensor(...);

// Zig infers that this is a Struct
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

(Some sensors like BME280 can actually do frequent sampling on their own)

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

Like from __NimBLE Porting Layer__. (Or just plain NuttX Timers)

Let's sum up the tweaks that we need...

![Grand Plan for our IoT Sensor App](https://lupyuen.github.io/images/sensor-visual.jpg)

_Grand Plan for our IoT Sensor App_

# Upcoming Fixes

In the previous section we talked about the __quirks in our IoT Sensor App__ and why it won't work in the Real World.

This is how we'll fix it...

## Multithreading and Synchronisation

-   __sleep__ won't work for Multiple Loops. We'll switch to __Multithreaded Timers__ instead

    (From __NimBLE Porting Layer__ or just plain NuttX Timers)

-   Our Read Sensor Loop needs to pass the __Aggregated Sensor Data__ to Transmit Loop

-   Since both Loops are running concurrently, we need to __Lock the Sensor Data__ during access

    (Hence the locking and averaging in the pic above)

## Message Constraints

-   We'll transmit LoRaWAN Messages __every 60 seconds__, due to the Message Rate limits. [(Here's why)](https://lupyuen.github.io/articles/lorawan3#message-interval)

-   We'll probably test LoRaWAN with [__Waveshare LoRa SX1262 Breakout Board__](https://www.waveshare.com/wiki/Pico-LoRa-SX1262) (non-sponsored)

    (Because our current LoRa SX1262 Board is reserved for [__NuttX Automated Testing__](https://lupyuen.github.io/articles/auto))

TODO: scale 100

TODO: Pine64 sensors, [Waveshare I2C Multi-Sensor Board](https://www.waveshare.com/wiki/Pico-Environment-Sensor) (non-sponsored)

![Compose Message Block, scaled by 100](https://lupyuen.github.io/images/visual-block11.jpg)

## Blockly Limitations

TODO: Const vs var

TODO: Multiple assignment

![Connect a Sensor to our Microcontroller and it pops up in Blockly!](https://lupyuen.github.io/images/visual-arduino.jpg)

_Connect a Sensor to our Microcontroller and it pops up in Blockly!_

# Visual Arduino?

[__Alan Carvalho de Assis__](https://www.linkedin.com/in/acassis/) has a brilliant idea for an Embedded Dev Tool that's __modular, visual, plug-and-play__...

>   "I think creating some modular solution to compete with Arduino could be nice! Imagine that instead of wiring modules in the breadboard people just plug the device in the board and it recognize the device and add it to some graphical interface"

>   "For example, you just plug a temperature sensor module in your board and it will identify the module type and you can pass this Temperature variable to use in your logic application"

Just __connect a Sensor__ to our Microcontroller... And it pops up in __Blockly__! (Pic above)

To detect the Sensor, we could use [__SPD (Serial Presence Detection)__](https://en.m.wikipedia.org/wiki/Serial_presence_detect), like for DDR Memory Modules.

(Or maybe we scan the I2C Bus and read the Chip ID?)

What do you think? Please let us know! 🙏

(Would be great if we could create a Proof-of-Concept using Universal Perforated Board)

# What's Next

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

![BME280 Sensor Block](https://lupyuen.github.io/images/visual-block1.jpg)

# Appendix: Read Sensor Data

TODO

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

Here's the implementation of `readSensor`...

[visual-zig-nuttx/sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L34-L108)

Note that the Sensor Data Struct Type and the Sensor Data Field are declared as `comptime`...

```zig
/// Read a Sensor and return the Sensor Data
pub fn readSensor(
    comptime SensorType: type,        // Sensor Data Struct to be read, like c.struct_sensor_baro
    comptime field_name: []const u8,  // Sensor Data Field to be returned, like "temperature"
    device_path: []const u8           // Path of Sensor Device, like "/dev/sensor/sensor_baro0"
) !f32 { ...
```

Which means that the values will be substituted at Compile-Time. (Works like a C Macro)

We can then refer to the Sensor Data Struct `sensor_baro` like this...

```zig
    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(
        SensorType
    );
```

And return a field `temperature` like this...

```zig
    // Return the Sensor Data Field
    return @field(sensor_data, field_name);
```

Thus this program...

[visual-zig-nuttx/visual.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig#L27-L61)

Produces this output...

```text
NuttShell (NSH) NuttX-10.3.0
nsh> sensortest visual
Zig Sensor Test
Start main
...
temperature=30.18
pressure=1007.69
humidity=68.67
End main
```

TODO

[visual-zig-nuttx/sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L34-L108)

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

    // Check for error
    if (fd < 0) {
        std.log.err("Failed to open device:{s}", .{ c.strerror(errno()) });
        return error.OpenError;
    }

    // Close the Sensor Device when this function returns
    defer {
        _ = c.close(fd);
    }

    // Set Standby Interval
    const interval: c_uint = 1_000_000;  // 1,000,000 microseconds (1 second)
    var ret = c.ioctl(fd, c.SNIOC_SET_INTERVAL, interval);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to set interval:{s}", .{ c.strerror(errno()) });
        return error.IntervalError;
    }

    // Set Batch Latency
    const latency: c_uint = 0;  // No latency
    ret = c.ioctl(fd, c.SNIOC_BATCH, latency);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to batch:{s}", .{ c.strerror(errno()) });
        return error.BatchError;
    }

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

    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(
        SensorType
    );
    const len = @sizeOf(
        @TypeOf(sensor_data)
    );

    // Read the Sensor Data
    const read_len = c.read(fd, &sensor_data, len);

    // Check size of Sensor Data
    if (read_len < len) {
        std.log.err("Sensor data incorrect size", .{});
        return error.SizeError;
    }

    // Return the Sensor Data Field
    return @field(sensor_data, field_name);
}
```

[__"Zig Metaprogramming"__](https://ikrima.dev/dev-notes/zig/zig-metaprogramming/)

![Compose Message Block](https://lupyuen.github.io/images/visual-block7b.jpg)

# Appendix: Encode Sensor Data

TODO

The __Compose Message Block__ composes a [__CBOR Message__](https://lupyuen.github.io/articles/cbor2) with the specified Keys (Field Names) and Values (Sensor Data).

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

_`composeCbor` will work for a variable number of arguments? Strings as well as numbers?_

Yep, here's the implementation of `composeCbor`: [visual.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig#L65-L108)

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

/// TODO: CBOR Message
/// https://lupyuen.github.io/articles/cbor2
const CborMessage = struct {
    buf: [256]u8 = undefined,  // Limit to 256 chars
    len: usize = 0,
};
```

Note that `composeCbor` is declared as `anytype`...

```zig
fn composeCbor(args: anytype) { ...
```

That's why `composeCbor` accepts a variable number of arguments with different types.

To handle each argument, this `inline` / `comptime` loop is unrolled at Compile-Time...

```zig
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

_What happens if we omit a Key or a Value when calling `composeCbor`?_

This `comptime` assertion check will fail at Compile-Time...

```zig
comptime {
    assert(args.len % 2 == 0);  // Missing Key or Value
}
```

![Transmit Message Block](https://lupyuen.github.io/images/visual-block7c.jpg)

# Appendix: Transmit Sensor Data

TODO

The __Transmit Message Block__ (above) transmits a CBOR Message to [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) (the low-power, long-range, low-bandwidth IoT Network)...

```zig
// Transmit message to LoRaWAN
try transmitLorawan(msg);
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/visual.zig)

# Appendix: Create Custom Blocks

TODO: Previously we have __customised Blockly__ to generate Zig Programs...

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

Now we'll extend Blockly to produce IoT Sensor Apps.

-   [__"Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#custom-block)

-   [__"Create Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#create-custom-block)

-   [__"Export Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#export-custom-block)

-   [__"Load Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#load-custom-block)

-   [__"Show Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#show-custom-block)

-   [__"Code Generator for Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#code-generator-for-custom-block)

-   [__"Build Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#build-custom-block)

-   [__"Test Custom Block"__](https://github.com/lupyuen3/blockly-zig-nuttx#test-custom-block)

-   [__"Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#custom-extension)

-   [__"Code Generator for Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#code-generator-for-custom-extension)

-   [__"Test Custom Extension"__](https://github.com/lupyuen3/blockly-zig-nuttx#test-custom-extension)

-   [__"Test Stubs"__](https://github.com/lupyuen3/blockly-zig-nuttx#test-stubs)

-   [__"Transmit Message"__](https://github.com/lupyuen3/blockly-zig-nuttx#transmit-message)

TODO3

![TODO](https://lupyuen.github.io/images/visual-block3.jpg)

TODO4

![TODO](https://lupyuen.github.io/images/visual-block4.jpg)

TODO
