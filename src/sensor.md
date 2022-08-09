# Read NuttX Sensor Data with Zig

📝 _29 Jul 2022_

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-title.jpg)

With [__Zig Programming Language__](https://ziglang.org), we have a fun new way to create Embedded Applications for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/).

Today we shall write a Zig program that reads a NuttX Sensor: [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/) for Temperture, Humidity and Air Pressure.

And we'll run it on Pine64's [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone). (Pic above)

(The steps will be similar for other sensors and microcontrollers)

_Why are we doing this in Zig?_

Zig is super helpful for __writing safer programs__ because it catches problems at runtime: Overflow, Underflow, Array Out-of-Bounds and more. [(See the list)](https://ziglang.org/documentation/master/#Undefined-Behavior)

The code we see today will be useful for programming __IoT Gadgets__ with Zig. We'll use the code in upcoming projects for __LoRaWAN and Visual Programming__. (Details below)

_What if we're not familiar with Zig?_

This article assumes that we're familiar with C. The Zig-ish parts shall be explained with examples in C.

[(Tips for learning Zig)](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

_But really... What if we prefer to do this in C?_

NuttX already provides an excellent __Sensor Test App__ in C...

-   [__sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/testing/sensortest/sensortest.c)

That inspired the Zig program in this article...

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

Let's dive in and find out how we read NuttX Sensors with Zig!

__Note:__ The NuttX Sensor API has been updated in Jul / Aug 2022. [(See the changes)](https://lupyuen.github.io/articles/sensor#appendix-updates-to-nuttx-sensor-api)

# Bosch BME280 Sensor

For today we'll call this NuttX Driver for __Bosch BME280 Sensor__...

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

The BME280 Driver exposes two __NuttX Sensor Devices__...

-   __Barometer Sensor:__ /dev/sensor/sensor_baro0

    (For Temperature and Air Pressure)

-   __Humidity Sensor:__ /dev/sensor/sensor_humi0

    (For Humidity)

We shall read both Sensor Devices to fetch the Sensor Data for __Temperature, Air Pressue and Humidity.__

![Read Barometer Sensor](https://lupyuen.github.io/images/sensor-code2a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

# Read Barometer Sensor

Let's walk through the code to read the Temperature and Air Pressure from our __NuttX Barometer Sensor__ at "/dev/sensor/sensor_baro0"...

-   Open Sensor Device

-   Set Standby Interval

-   Set Batch Latency

-   Poll Sensor

-   Read Sensor Data

-   Print Sensor Data

-   Close Sensor Device

## Open Sensor Device

We begin by __opening the Sensor Device__: [sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

```zig
/// Read Pressure and Temperature from 
/// Barometer Sensor "/dev/sensor/sensor_baro0"
fn test_sensor() !void {

  // Open the Sensor Device
  const fd = c.open(
    "/dev/sensor/sensor_baro0",       // Path of Sensor Device
    c.O_RDONLY | c.O_NONBLOCK  // Open for read-only
  );
```

__`open()`__ should look familiar... On Linux we open Devices the same way.

_What's "`!void`"?_

That's the __Return Type__ of our function...

-   Our function doesn't return any value

    (Hence "`void`")

-   But it might return an __Error__

    (Hence the "`!`")

_Why the "`c.`" prefix?_

We write "`c.`_something_" for Functions, Types and Macros __imported from C__.

(More about this in a while)

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

[(__OpenError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L55-L65)

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
  // Close the Sensor Device when 
  // this function returns
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
  // TODO: Remove this definition when 
  // SNIOC_SET_INTERVAL has been been fixed: 
  // https://github.com/apache/incubator-nuttx/issues/6642
  const SNIOC_SET_INTERVAL = c._SNIOC(0x0081);

  // Set Standby Interval
  var interval: c_uint = 1_000_000;  // 1,000,000 microseconds (1 second)
  var ret = c.ioctl(
    fd,                  // Sensor Device
    SNIOC_SET_INTERVAL,  // ioctl Command
    &interval            // Standby Interval
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

[(__IntervalError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L55-L65)

Which also closes the Sensor Device. (Due to our earlier "`defer`")

## Set Batch Latency

We set the __Batch Latency__, if it's needed by our sensor...

```zig
  // Set Batch Latency
  var latency: c_uint = 0;  // No latency
  ret = c.ioctl(
    fd,             // Sensor Device
    c.SNIOC_BATCH,  // ioctl Command
    &latency        // Batch Latency
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

[(__BatchError__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L55-L65)

## Poll Sensor

After the enabling the sensor, we __poll the sensor__ to check if Sensor Data is available...

```zig
  // Prepare to poll Sensor
  var fds = std.mem.zeroes(
    c.struct_pollfd
  );
  fds.fd = fd;
  fds.events = c.POLLIN;
```

__std.mem.zeroes__ creates a __pollfd__ Struct that's initialised with nulls.

(The struct lives on the stack)

After populating the struct, we poll it...

```zig
  // Poll for Sensor Data
  ret = c.poll(&fds, 1, -1);

  // Check if Sensor Data is available
  if (ret <= 0) {
    std.log.err("Sensor data not available", .{});
    return error.DataError;
  }
```

We're finally ready to read the Sensor Data!

## Read Sensor Data

We __allocate a buffer__ (on the stack) to receive the Sensor Data...

```zig
  // Define the Sensor Data Type
  var sensor_data = std.mem.zeroes(
    c.struct_sensor_baro
  );
  // Size of the Sensor Data
  const len = @sizeOf(
    @TypeOf(sensor_data)
  );
```

__std.mem.zeroes__ returns a __sensor_baro__ Struct, initialised with nulls.

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

And convert the Pressure and Temperature from Floating-Point to __Fixed-Point Numbers__...

```zig
  // Convert the Sensor Data 
  // to Fixed-Point Numbers
  const pressure = floatToFixed(
    sensor_data.pressure
  );
  const temperature = floatToFixed(
    sensor_data.temperature
  );
```

[(__floatToFixed__ is explained here)](https://lupyuen.github.io/articles/sensor#appendix-fixed-point-sensor-data)

Our Fixed-Point Numbers are similar to Floating-Point Numbers, but truncated to __2 Decimal Places__.

[(Why we use Fixed-Point Numbers)](https://lupyuen.github.io/articles/sensor#appendix-fixed-point-sensor-data)

## Print Sensor Data

Now we have the Pressure and Temperature as Fixed-Point Numbers, let's __print the Sensor Data__...

```zig
  // Print the Sensor Data
  debug("pressure:{}.{:0>2}", .{
    pressure.int, 
    pressure.frac 
  });
  debug("temperature:{}.{:0>2}", .{
    temperature.int,
    temperature.frac 
  });

  // Will be printed as...
  // pressure:1007.66
  // temperature:27.70
```

_What are "int" and "frac"?_

Our Fixed-Point Number has two Integer components...

-   __int__: The Integer part

-   __frac__: The Fraction part, scaled by 100

So to represent `123.45`, we break it down as...

-   __int__ = `123`

-   __frac__ = `45`

_Why print the numbers as "`{}.{:0>2}`"?_

Our Format String "`{}.{:0>2}`" says...

|   |   |
|:---:|:---|
| `{}` | Print __int__ as a number
| `.` | Print `.`
| `{:0>2}` | Print __frac__ as a 2-digit number, padded at the left by `0`

Which gives us the printed output `123.45`

[(More about Format Strings)](https://ziglearn.org/chapter-2/#formatting-specifiers)

And we're done reading the Temperature and Pressure from the NuttX Barometer Sensor!

_Have we forgotten to close the sensor?_

Remember earlier we did this...

```zig
  // Close the Sensor Device when 
  // this function returns
  defer {
    _ = c.close(fd);
  }
```

This closes the sensor automagically when we return from the function. Super handy!

![Read Barometer Sensor](https://lupyuen.github.io/images/sensor-code3a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

# Read Humidity Sensor

_What about the Humidity from our BME280 Sensor?_

We read the __Humidity Sensor Data__ the exact same way as above, with a few tweaks: [sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L147-L234)

```zig
/// Read Humidity from Humidity Sensor 
/// "/dev/sensor/sensor_humi0"
fn test_sensor2() !void {

  // Open the Sensor Device
  const fd = c.open(
    "/dev/sensor/sensor_humi0",       // Path of Sensor Device
    c.O_RDONLY | c.O_NONBLOCK  // Open for read-only
  );
```

In the code above we changed the __path of the Sensor Device__.

The Sensor Data Struct becomes __sensor_humi__...

```zig
  // Define the Sensor Data Type
  var sensor_data = std.mem.zeroes(
    c.struct_sensor_humi
  );
```

Which contains a single value for the __Humidity Sensor Data__...

```zig
  // Read the Sensor Data
  const read_len = c.read(fd, &sensor_data, len);

  // Omitted: Check size of Sensor Data
  ...

  // Convert the Sensor Data 
  // to Fixed-Point Number
  const humidity = floatToFixed(
    sensor_data.humidity
  );

  // Print the Sensor Data
  debug("humidity:{}.{:0>2}", .{
    humidity.int, 
    humidity.frac 
  });

  // Will be printed as...
  // humidity:78.81
```

And we're done!

_Where's the list of Sensor Data Structs?_

The __NuttX Sensor Data Structs__ are defined at...

-   [__include/nuttx/sensors/sensor.h__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L290-L545)

_What about the Sensor Device Names like baro0 and humi0?_

Here's the list of __NuttX Sensor Device Names__...

-   [__testing/sensortest/sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/testing/sensortest/sensortest.c#L86-L119)

_How are test_sensor and test_sensor2 called?_

They are called by our __Zig Main Function__.

(More about this in a while)

![Import NuttX Functions, Types and Macros](https://lupyuen.github.io/images/sensor-code5a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L6-L30)

# Import NuttX Functions

_How do we import into Zig the NuttX Functions? open(), ioctl(), read(), ..._

This is how we __import the NuttX Functions, Types and Macros__ from C into Zig: [sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L6-L30)

```zig
/// Import the Sensor Library from C
pub const c = @cImport({
  // NuttX Defines
  @cDefine("__NuttX__",  "");
  @cDefine("NDEBUG",     "");
  @cDefine("ARCH_RISCV", "");

  // This is equivalent to...
  // #define __NuttX__
  // #define NDEBUG
  // #define ARCH_RISCV
```

[(__@cImport__ is documented here)](https://ziglang.org/documentation/master/#Import-from-C-Header-File)

At the top we set the __#define Macros__ that will be referenced by the NuttX Header Files coming up.

The settings above are specific to NuttX for BL602. [(Because of the GCC Options)](https://github.com/lupyuen/visual-zig-nuttx#sensor-test-app-in-c)

Next comes a workaround for a __C Macro Error__ that appears on Zig with NuttX...

```zig
  // Workaround for "Unable to translate macro: undefined identifier `LL`"
  @cDefine("LL", "");
  @cDefine("__int_c_join(a, b)", "a");  //  Bypass zig/lib/include/stdint.h
```

[(More about this)](https://lupyuen.github.io/articles/iot#appendix-macro-error)

Then we import the __C Header Files__ for NuttX...

```zig
  // NuttX Header Files. This is equivalent to...
  // #include "...";
  @cInclude("arch/types.h");
  @cInclude("../../nuttx/include/limits.h");
  @cInclude("nuttx/sensors/sensor.h");
  @cInclude("nuttx/config.h");
  @cInclude("sys/ioctl.h");
  @cInclude("inttypes.h");
  @cInclude("unistd.h");
  @cInclude("stdlib.h");
  @cInclude("stdio.h");
  @cInclude("fcntl.h");
  @cInclude("poll.h");
});
```

"types.h" and "limits.h" are needed for NuttX compatibility. [(See this)](https://lupyuen.github.io/articles/iot#appendix-zig-compiler-as-drop-in-replacement-for-gcc)

The other includes were copied from the __NuttX Sensor Test App__ in C: [sensortest.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/testing/sensortest/sensortest.c#L34-L42)

_What about NuttX Structs like sensor_baro and sensor_humi?_

__NuttX Structs__ will be automatically imported with the code above.

NuttX Macros like __O_RDONLY__ and __SNIOC_BATCH__ will get imported too.

_Why do we write "`c.`something" when we call NuttX functions? Like "c.open()"?_

Remember that we import all NuttX Functions, Types and Macros into the __"`c`" Namespace__...

```zig
/// Import Functions, Types and Macros into "c" Namespace
pub const c = @cImport({ ... });
```

That's why we write "`c.`_something_" when we refer to NuttX Functions, Types and Macros.

![Main Function](https://lupyuen.github.io/images/sensor-code4a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L3-L51)

# Main Function

One more thing before we run our Zig program: The __Main Function__.

We begin by importing the Zig Standard Library and __NuttX Sensor Definitions__: [sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L3-L51)

```zig
/// Import the Zig Standard Library
const std = @import("std");

/// Import the NuttX Sensor Definitions
const sen = @import("./sensor.zig");

/// Import the NuttX Sensor Library
const c = sen.c;

/// Import the Multi-Sensor Module
const multi = @import("./multisensor.zig");
```

[(__sensor.zig__ is located here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig)

__sen.c__ refers to the [__C Namespace__](https://lupyuen.github.io/articles/sensor#import-nuttx-functions) that contains the Functions, Types and Macros imported from NuttX.

(We'll talk about the Multi-Sensor Module in a while)

Next we declare our __Main Function__ that will be called by NuttX...

```zig
/// Main Function that will be called by NuttX. 
/// We read the Sensor Data from a Sensor.
pub export fn sensortest_main(
    argc: c_int, 
    argv: [*c]const [*c]u8
) c_int {

  // Quit if no args specified
  if (argc <= 1) { usage(); return -1; }
```

[(__usage__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L236-L253)

_Why is argv declared as "[\*c]const [\*c]u8"?_

That's because...

-   "__[\*c]u8__" is a C Pointer to an Unknown Number of Unsigned Bytes

    (Like "uint8_t *" in C)

-   "__[\*c]const [\*c]u8__" is a C Pointer to an Unknown Number of the above C Pointers

    (Like "uint8_t *[]" in C)

So it's roughly equivalent to "char **argv" in C.

[(More about C Pointers in Zig)](https://ziglang.org/documentation/master/#C-Pointers)

We check the __Command-Line Argument__ passed to our program...

```zig
  // Run a command like "test" or "test2"
  if (argc == 2) {

    // Convert the command to a Slice
    const cmd = std.mem.span(argv[1]);
```

Assume that "__argv[1]__" points to "test", the command-line arg for our program.

[__std.mem.span__](https://ziglang.org/documentation/0.9.1/std/#root;mem.span) converts "test" to a __Zig Slice__.

Let's pretend a Slice works like a "String", we'll explain in the next section.

This is how we __compare our Slice__ with a String (that's actually another Slice)...

```zig
    // If the Slice is "test"...
    if (std.mem.eql(u8, cmd, "test")) {

      // Read the Barometer Sensor
      test_sensor()
        catch { return -1; };
      return 0;
    }
```

So if the command-line arg is "test", we call __test_sensor__ to read the Barometer Sensor. [(As seen earlier)](https://lupyuen.github.io/articles/sensor#read-barometer-sensor)

If __test_sensor__ returns an Error, the __catch__ clause says that we quit.

And if the command-line arg is "test2"...

```zig
    // If the Slice is "test2"...
    else if (std.mem.eql(u8, cmd, "test2")) {

      // Read the Humidity Sensor
      test_sensor2()
        catch { return -1; };
      return 0;
    }
  }
```

We call __test_sensor2__ to read the Humidity Sensor. [(As seen earlier)](https://lupyuen.github.io/articles/sensor#read-humidity-sensor)

For other command-line args we run a __Multi-Sensor Test__...

```zig
  // Read the Sensor specified by the Command-Line Options
  multi.test_multisensor(argc, argv)
    catch |err| {

      // Handle the error
      if (err == error.OptionError or err == error.NameError) { usage(); }
      return -1;
    };

  return 0;
}
```

(We'll talk about Multi-Sensor Test in a while)

That's all for our Main Function!

_What's "|err|"?_

If our function __test_multisensor__ fails with an Error...

```zig
  multi.test_multisensor(argc, argv)
    catch |err| {
      // Do something with err
    }
```

Then __err__ will be set to the Error returned by __test_multisensor__.

# Slice vs String

_Why do we need Slices? The usual Strings are perfectly splendid right?_

Strings in C (like __argv[1]__ from the previous section) are represented like this...

![Strings in C](https://lupyuen.github.io/images/sensor-slice1.jpg)

That's a Pointer to an Array of characters, __terminated by Null__.

_What if we make a mistake and overwrite the Terminating Null?_

Disaster Ensues! Our String would overrun the Array and cause __Undefined Behaviour__ when we read the String!

That's why we have __Slices__, a safer way to represent Strings (and other buffers with dynamic sizes)...

![Zig Slice](https://lupyuen.github.io/images/sensor-slice2.jpg)

A Slice has two components...

-   __Pointer__ to an Array of characters (or another type)

-   __Length__ of the Array (excluding the null)

Because Slices are restricted by Length, it's a little harder to overrun our Strings by accident.

(If we access the bytes beyond the bounds of the Slice, our program halts with a [__Runtime Panic__](https://ziglang.org/documentation/master/#Index-out-of-Bounds))

To convert a Null-Terminated String to a Slice, we call [__std.mem.span__](https://ziglang.org/documentation/0.9.1/std/#root;mem.span)...

```zig
// Convert the command-line arg to a Slice
const slice = std.mem.span(argv[1]);
```

And to compare two Slices, we call __std.mem.eql__...

```zig
// If the Slice is "test"...
if (std.mem.eql(u8, slice, "test")) {
  ...
}
```

__u8__ (unsigned byte) refers to the type of data in the Slice.

To convert a Slice back to a C Pointer, we write __&slice[0]__...

```zig
// Pass the Slice as a C Pointer
const fd = c.open(
  &slice[0], 
  c.O_RDONLY | c.O_NONBLOCK
);
// Slice must be null-terminated.
// Triggers a runtime panic if the Slice is empty.
```

[(More about Slices)](https://ziglang.org/documentation/master/#Slices)

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-connect.jpg)

# Connect BME280 Sensor

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

# Multiple Sensors

_To test a different sensor, do we rewrite the Zig Sensor App?_

_Is there an easier way to test any NuttX Sensor?_

This is how we test __any NuttX Sensor__, without rewriting our app...

```text
nsh> sensortest -n 1 baro0
Zig Sensor Test
test_multisensor
SensorTest: Test /dev/sensor/sensor_baro0  with interval(1000000), latency(0)
value1:1007.65
value2:27.68
SensorTest: Received message: baro0, number:1/1
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#clean-up)

Just specify the name of the Sensor Device ("baro0") as the Command-Line Argument.

("-n 1" means read the Sensor Data once)

And this is how we read "humi0"...

```text
nsh> sensortest -n 1 humi0
Zig Sensor Test
test_multisensor
SensorTest: Test /dev/sensor/sensor_humi0  with interval(1000000), latency(0)
value:78.91
SensorTest: Received message: humi0, number:1/1
```

[(Source)](https://github.com/lupyuen/visual-zig-nuttx#clean-up)

From the above output we see that Air Pressure is __1,007.65 millibars__, Temperature is __27.68 °C__ and Relative Humidity is __78.91 %__.

[(See the Command-Line Arguments)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L236-L253)

_Which sensors are supported?_

Here's the list of __Sensor Devices__ supported by the app...

-   [__testing/sensortest/sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/testing/sensortest/sensortest.c#L86-L119)

To understand the printed values (like "value1" and "value2"), we refer to the __Sensor Data Structs__...

-   [__include/nuttx/sensors/sensor.h__](https://github.com/lupyuen/incubator-nuttx/blob/master/include/nuttx/sensors/sensor.h#L290-L545)

_How does it work?_

Inside our Zig Sensor App is a __Multi-Sensor Module__ that handles all kinds of sensors...

-   [__multisensor.zig__](https://github.com/lupyuen/visual-zig-nuttx/blob/main/multisensor.zig)

The Zig code was converted from the __NuttX Sensor Test App__ in C...

-   [__sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/testing/sensortest/sensortest.c)

Which is explained here...

-   [__"Sensor Test App"__](https://lupyuen.github.io/articles/bme280#sensor-test-app)

Below are the steps for converting the Sensor Test App from C to Zig...

-   [__Auto-Translate Sensor App to Zig__](https://github.com/lupyuen/visual-zig-nuttx#auto-translate-sensor-app-to-zig)

-   [__Sensor App in Zig__](https://github.com/lupyuen/visual-zig-nuttx#sensor-app-in-zig)

-   [__Run Zig Sensor App__](https://github.com/lupyuen/visual-zig-nuttx#run-zig-sensor-app)

-   [__Fix Floating-Point Values__](https://github.com/lupyuen/visual-zig-nuttx#fix-floating-point-values)

-   [__Floating-Point Link Error__](https://github.com/lupyuen/visual-zig-nuttx#floating-point-link-error)

-   [__Fixed-Point Printing__](https://github.com/lupyuen/visual-zig-nuttx#fixed-point-printing)

-   [__Change to Static Buffer__](https://github.com/lupyuen/visual-zig-nuttx#change-to-static-buffer)

-   [__Incorrect Alignment__](https://github.com/lupyuen/visual-zig-nuttx#incorrect-alignment)

-   [__Clean Up__](https://github.com/lupyuen/visual-zig-nuttx#clean-up)

![Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/iot-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)_

# LoRaWAN and Visual Programming

_Once again... Why are we doing this in Zig?_

We said earlier that Zig is super helpful for __writing safer programs__ because it catches problems at runtime: Overflow, Underflow, Array Out-of-Bounds and more. [(See the list)](https://ziglang.org/documentation/master/#Undefined-Behavior)

And we plan to use the Zig code in this article for upcoming __LoRaWAN and Visual Programming__ projects.

_Isn't LoRaWAN the long-range, low-power, low-bandwidth Wireless Network for IoT Gadgets?_

Yep we have previously created a Zig app for the [__LoRaWAN Wireless Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/)...

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

Now we can integrate the Sensor Code from this article... To create the firmware for an IoT Gadget that actually __transmits real Sensor Data__!

We'll compress the Sensor Data with __CBOR__...

-   [__"Encode Sensor Data with CBOR on Apache NuttX OS"__](https://lupyuen.github.io/articles/cbor2)

And monitor the Sensor Data with __Prometheus and Grafana__...

-   [__"Monitor IoT Devices in The Things Network with Prometheus and Grafana"__](https://lupyuen.github.io/articles/prometheus)

_And this LoRaWAN App will work for all kinds of NuttX Sensors?_

Righto our Zig LoRaWAN App will eventually support __all types of NuttX Sensors__.

But we've seen today that each kind of NuttX Sensor needs a lot of __boilerplate code__ (and error handling) to support every sensor.

_Can we auto-generate the boilerplate code for each NuttX Sensor?_

I'm about to experiment with __Visual Programming__ for NuttX Sensors.

Perhaps we can [__drag-n-drop a NuttX Sensor__](https://github.com/lupyuen3/blockly-zig-nuttx) into our LoRaWAN App...

And __auto-generate the Zig code__ for the NuttX Sensor! (Pic below)

That would be an awesome way to mix-n-match various NuttX Sensors for IoT Gadgets!

![Visual Programming for Zig with NuttX Sensors](https://lupyuen.github.io/images/sensor-visual.jpg)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx)

# What's Next

I hope you find this article helpful for creating your own Sensor App. Lemme know what you're building!

In the coming weeks I shall [__customise Blockly__](https://github.com/lupyuen3/blockly-zig-nuttx) to auto-generate the Zig Sensor App. Someday we'll create Sensor Apps the drag-n-drop way!

-   [__"Visual Programming for Zig with NuttX Sensors"__](https://github.com/lupyuen/visual-zig-nuttx)

-   [__Blockly Source Code__](https://github.com/lupyuen3/blockly-zig-nuttx)

To learn more about Zig, check out these tips...

-   [__"Learning Zig"__](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

See my earlier work on Zig, NuttX, LoRaWAN and LVGL...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/Zig/comments/warst3/read_nuttx_sensor_data_with_zig/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/sensor.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/sensor.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1548909434440585216)

1.  The design of the __NuttX Sensor API__ is discussed here...

    [__"Unified Management for Sensor"__](https://github.com/apache/incubator-nuttx/pull/2039)

1.  Our Zig App includes a [__Custom Logger__](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L281-L316) and [__Panic Handler__](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L255-L279). They are explained below...

    [__"Logging"__](https://lupyuen.github.io/articles/iot#appendix-logging)

    [__"Panic Handler"__](https://lupyuen.github.io/articles/iot#appendix-panic-handler)

![Converting to fixed-point number](https://lupyuen.github.io/images/sensor-code1a.png)

[(Source)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L39-L49)

# Appendix: Fixed-Point Sensor Data

_How do we use Fixed-Point Numbers for Sensor Data?_

Our Zig Sensor App reads Sensor Data as __Floating-Point Numbers__...

-   [__"Read Sensor Data"__](https://lupyuen.github.io/articles/sensor#read-sensor-data)

-   [__"Print Sensor Data"__](https://lupyuen.github.io/articles/sensor#print-sensor-data)

And converts the Sensor Data to [__Fixed-Point Numbers__](https://en.wikipedia.org/wiki/Fixed-point_arithmetic) (2 decimal places) for printing...

```zig
// Convert Pressure to a Fixed-Point Number
const pressure = floatToFixed(
  sensor_data.pressure
);

// Print the Pressure as a Fixed-Point Number
debug("pressure:{}.{:0>2}", .{
  pressure.int, 
  pressure.frac 
});
```

(More about __floatToFixed__ in a while)

(Someday we might simplify the printing with [__Custom Formatting__](https://ziglearn.org/chapter-2/#formatting))

_What are "int" and "frac"?_

Our Fixed-Point Number has two Integer components...

-   __int__: The Integer part

-   __frac__: The Fraction part, scaled by 100

So to represent `123.456`, we break it down as...

-   __int__ = `123`

-   __frac__ = `45`

We drop the final digit `6` when we convert to Fixed-Point.

_Why handle Sensor Data as Fixed-Point Numbers? Why not Floating-Point?_

When we tried printing the Sensor Data as Floating-Point Numbers, we hit some __Linking and Runtime Issues__...

-   [__"Fix Floating-Point Values"__](https://github.com/lupyuen/visual-zig-nuttx#fix-floating-point-values)

-   [__"Floating-Point Link Error"__](https://github.com/lupyuen/visual-zig-nuttx#floating-point-link-error)

-   [__"Fixed-Point Printing"__](https://github.com/lupyuen/visual-zig-nuttx#fixed-point-printing)

Computations on Floating-Point Numbers are OK, only printing is affected. So we print the numbers as Fixed-Point instead.

(We observed these issues with Zig Compiler version 0.10.0, they might have been fixed in later versions of the compiler)

_Isn't our Sensor Data less precise in Fixed-Point?_

Yep we lose some precision with Fixed-Point Numbers. (Like the final digit `6` from earlier)

But most IoT Gadgets will __truncate Sensor Data__ before transmission anyway.

And for some data formats (like CBOR), we need __fewer bytes__ to transmit Fixed-Point Numbers instead of Floating-Point...

-   [__"Floating-Point Numbers (CBOR)"__](https://lupyuen.github.io/articles/cbor2#floating-point-numbers)

Thus we'll probably stick to Fixed-Point Numbers for our upcoming IoT projects.

_How do we convert Floating-Point to Fixed-Point?_

Below is the implementation of __floatToFixed__, which receives a Floating-Point Number and returns the Fixed-Point Number (as a Struct): [sensor.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L39-L49)

```zig
/// Convert the float to a fixed-point number (`int`.`frac`) with 2 decimal places.
/// We do this because `debug` has a problem with floats.
pub fn floatToFixed(f: f32) struct { int: i32, frac: u8 } {
  const scaled = @floatToInt(i32, f * 100.0);
  const rem = @rem(scaled, 100);
  const rem_abs = if (rem < 0) -rem else rem;
  return .{
    .int  = @divTrunc(scaled, 100),
    .frac = @intCast(u8, rem_abs),
  };
}
```

(See the docs: [__@floatToInt__](https://ziglang.org/documentation/master/#floatToInt), [__@rem__](https://ziglang.org/documentation/master/#rem), [__@divTrunc__](https://ziglang.org/documentation/master/#divTrunc), [__@intCast__](https://ziglang.org/documentation/master/#intCast))

This code has been tested for positive and negative numbers.

# Appendix: Updates to NuttX Sensor API

This section describes the changes in the __NuttX Sensor API__ for Jul / Aug 2022. We have updated the code in this article for these changes...

-   __Device Paths__ for NuttX Sensors have been changed from "/dev/sensor/\*" to "/dev/sensor/sensor_\*"

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/bd9431f21f952b40dc3d5a10cbb786e4e1eb1a71)

-   __Sensor Structs__ have been renamed from `sensor_event_*` to `sensor_*`

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/06e776d2e96e49c1f1b7594b2ff1d1c5617450a6)

-   __Activate / Deactivate Sensor (SNIOC_ACTIVATE)__ is no longer needed

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/5064ad014d84989f6461da6720b8b53a9b29194c)

-   __Sensor Batch (SNIOC_BATCH)__ now accepts a Latency Value instead of a Pointer

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/5753856d345783383fedb7a8313b9b58b5cef5d3)

-   __Sensor Interval (SNIOC_SET_INTERVAL)__ now accepts an Interval Value instead of a Pointer

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/783047f74d921917b55566a85c86361bf02b46b6)

-   __SNIOC_SET_INTERVAL__ was previously defined twice with different values. This has been fixed.

    [(See the changes)](https://github.com/lupyuen/visual-zig-nuttx/commit/62295db3a7dfdaed3fb11607c43f15a00b3e0523)

Our BME280 Driver has also been updated for the new Sensor API...

-   __Sensor Operations (sensor_ops_s)__ now include a Struct File parameter

    [(See the changes)](https://github.com/lupyuen/bme280-nuttx/commit/30755ca105d741b44d8889485b5f209183fffe35)

-   __Set Interval (bme280_set_interval)__ now accepts an unsigned long pointer (previously unsigned int pointer)

    [(See the changes)](https://github.com/lupyuen/bme280-nuttx/commit/3923cf436886fd5260932d880d818b8b9cc4bc31)

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-title2.jpg)
