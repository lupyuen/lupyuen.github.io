# Read NuttX Sensor Data with Zig

📝 _31 Jul 2022_

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-title.jpg)

With __Zig programming language__, we now have a fun new way to create embedded applications for __Apache NuttX RTOS__.

Today we shall write a Zig program to read a NuttX Sensor: __Bosch BME280 Sensor__ (Temperture / Humidity / Air Pressure).

And we'll run it on Pine64's __PineCone BL604 RISC-V Board__. (Pic above)

(The steps will be similar for other sensors and microcontrollers)

_What if we're not familiar with Zig?_

This article assumes that we're familiar with C.

The Zig-ish parts shall be explained with examples in C.

[(If we're keen to learn Zig, see this)](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

_But really... If we prefer to do this in C?_

NuttX provides an excellent __Sensor Test App__ in C...

-   [__sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/testing/sensortest/sensortest.c)

The Zig program in this article is derived from the NuttX Sensor Test App.

_Why are we doing this in Zig?_

TODO: Upcoming LoRaWAN, Visual Programming

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

TODO: [Changes to NuttX Sensors](https://github.com/apache/incubator-nuttx/commits/master/include/nuttx/sensors/sensor.h)

# Bosch BME280 Sensor

TODO

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

"/dev/sensor/baro0": Pressure and Temperature

"/dev/sensor/humi0": Humidity

# Read Barometer Sensor

Let's walk through the steps to read the Temperature and Air Pressure from our __NuttX Barometer Sensor__...

-   Open Sensor Device

-   Set Standby Interval

-   Set Batch Latency

-   Enable Sensor

-   Poll Sensor

-   Read Sensor Data

-   Print Sensor Data

-   Disable Sensor

-   Close Sensor Device

## Open Sensor Device

We begin by __opening the Sensor Device__: [sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

```zig
/// Read Pressure and Temperature from 
/// Barometer Sensor "/dev/sensor/baro0"
fn test_sensor() !void {

  // Open the Sensor Device
  const fd = c.open(
    "/dev/sensor/baro0",       // Path of Sensor Device
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

Some sensors (like BME280) will automatically measure Sensor Data at __Periodic Intervals__. [(See this)](https://lupyuen.github.io/articles/bme280#standby-interval)

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

## Enable Sensor

This is how we __enable our sensor__ before reading Sensor Data...

```zig
  // Enable Sensor and switch to Normal Power Mode
  ret = c.ioctl(
    fd,                // Sensor Device
    c.SNIOC_ACTIVATE,  // ioctl Command
    @as(c_int, 1)      // Enable Sensor
  );

  // Check for error
  if (ret < 0 and errno() != c.ENOTSUP) {
    std.log.err("Failed to enable sensor:{s}", .{ c.strerror(errno()) });
    return error.EnableError;
  }
```

_Why the "@as(c_int, 1)"?_

As we've seen, Zig can __infer the types__ of our variables and constants. (So we don't need to specify the types ourselves)

But __ioctl()__ is declared in C as...

```c
int ioctl(int fd, int req, ...);
```

Note that the Third Parameter __doesn't specify a type__ and Zig Compiler gets stumped.

That's why in Zig we write the Third Parameter as...

```zig
@as(c_int, 1)
```

Which means that we pass the value `1` as a __C Integer Type__.

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
  // If Sensor Data is available...
  if (c.poll(&fds, 1, -1) > 0) {

    // Coming up: Read Sensor Data...
```

We're finally ready to read the Sensor Data!

## Read Sensor Data

We __allocate a buffer__ (on the stack) to receive the Sensor Data...

```zig
    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(
      c.struct_sensor_event_baro
    );
    // Size of the Sensor Data
    const len = @sizeOf(
      @TypeOf(sensor_data)
    );
```

__std.mem.zeroes__ returns a __sensor_event_baro__ Struct, initialised with nulls.

We __read the Sensor Data__ into the struct...

```zig
    // Read the Sensor Data
    if (c.read(fd, &sensor_data, len) >= len) {

      // Convert the Sensor Data to Fixed-Point Numbers
      const pressure = float_to_fixed(
        sensor_data.pressure
      );
      const temperature = float_to_fixed(
        sensor_data.temperature
      );
```

[(__float_to_fixed__ is defined here)](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensor.zig#L40-L50)

And convert the Pressure and Temperature from Floating-Point to __Fixed-Point Numbers__.

Which are similar to Floating-Point Numbers, but truncated to __2 Decimal Places__.

(More about Fixed-Point Numbers in a while)

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

Our Fixed-Point Numbers have two components...

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

In case we can't read the Sensor Data, we write to the Error Log...

```zig        
    } else { std.log.err("Sensor data incorrect size", .{}); }
  } else { std.log.err("Sensor data not available", .{}); }
```

## Disable Sensor

We finish by __disabling the sensor__...

```zig
  // Disable Sensor and switch to Low Power Mode
  ret = c.ioctl(
    fd,                // Sensor Device
    c.SNIOC_ACTIVATE,  // ioctl Command
    @as(c_int, 0)      // Disable Sensor
  );

  // Check for error
  if (ret < 0) {
    std.log.err("Failed to disable sensor:{s}", .{ c.strerror(errno()) });
    return error.DisableError;
  }
}
```

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

# Read Humidity Sensor

_What about the Humidity from our BME280 Sensor?_

We read the __Humidity Sensor Data__ the exact same way as above, with a few tweaks: [sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L147-L234)

```zig
/// Read Humidity from Humidity Sensor 
/// "/dev/sensor/humi0"
fn test_sensor2() !void {

  // Open the Sensor Device
  const fd = c.open(
    "/dev/sensor/humi0",       // Path of Sensor Device
    c.O_RDONLY | c.O_NONBLOCK  // Open for read-only
  );
```

In the code above we changed the __path of the Sensor Device__.

The Sensor Data Struct becomes __sensor_event_humi__...

```zig
  // If Sensor Data is available...
  if (c.poll(&fds, 1, -1) > 0) {

    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(
      c.struct_sensor_event_humi
    );
    // Size of the Sensor Data
    const len = @sizeOf(
      @TypeOf(sensor_data)
    );
```

Which contains a single value for the __Humidity Sensor Data__...

```zig
    // Read the Sensor Data
    if (c.read(fd, &sensor_data, len) >= len) {

      // Convert the Sensor Data to Fixed-Point Numbers
      const humidity = float_to_fixed(
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

-   [__include/nuttx/sensors/sensor.h__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/sensors/sensor.h#L290-L545)

_What about the Sensor Device Names like baro0 and humi0?_

Here's the list of __NuttX Sensor Device Names__...

-   [__testing/sensortest/sensortest.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/testing/sensortest/sensortest.c#L86-L119)

# Import NuttX Functions

TODO

# Main Function

TODO

![Pine64 PineCone BL602 RISC-V Board connected to Bosch BME280 Sensor](https://lupyuen.github.io/images/sensor-connect.jpg)

# Connect BME280 Sensor

TODO

For testing the Zig Sensor App, we connect the BME280 Sensor (Temperature / Humidity / Air Pressure) to Pine64's [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone)...

| BL602 Pin | BME280 Pin | Wire Colour
|:---:|:---:|:---|
| __`GPIO 1`__ | `SDA` | Green 
| __`GPIO 2`__ | `SCL` | Blue
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

# Run Zig App

TODO

Here's the Air Pressure and Temperature read from the BME280 Barometer Sensor...

```text
nsh> sensortest test
Zig Sensor Test
test_sensor
pressure:1007.66
temperature:27.70
```

Here's the Humidity read from the BME280 Humidity Sensor...

```text
nsh> sensortest test2
Zig Sensor Test
test_sensor2
humidity:78.81
```

# Fixed-Point Sensor Data

TODO

# Multiple Sensors

TODO

# What's Next

TODO

Here are some tips for learning Zig...

-   [__"Learning Zig"__](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

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

[__lupyuen.github.io/src/lvgl.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1548909434440585216)
