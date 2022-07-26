# Read NuttX Sensor Data with Zig

📝 _31 Jul 2022_

![TODO](https://lupyuen.github.io/images/sensor-title.jpg)

TODO

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

TODO: What if we're not familiar with Zig?

TODO: Upcoming LoRaWAN, Visual Programming

[Changes to NuttX Sensors](https://github.com/apache/incubator-nuttx/commits/master/include/nuttx/sensors/sensor.h)

# Bosch BME280 Sensor

TODO

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

"/dev/sensor/baro0": Pressure and Temperature

"/dev/sensor/humi0": Humidity

# Read Barometer Sensor

TODO

[sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

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

We write "`c.`_something_" to refer to Functions and Macros __imported from C__.

(More about this in a while)

Next we check if the Sensor Device has been __successfully opened__...

```zig
  // Check for error
  if (fd < 0) {
    std.log.err("Failed to open device:{s}", .{ c.strerror(errno()) });
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

That's how we pass a __list of Arguments__ for a Formatted Message.

If we have no Arguments, we write "`.{}`"

[("`.{ ... }`" creates an Anonymous Struct)](https://ziglang.org/documentation/master/#Anonymous-Struct-Literals)

## Close Sensor Device (Deferred)

We've just opened the Sensor Device and we must __close it later__...

But the Control Flow gets complicated because we might need to __handle Errors__ and quit early. In C we'd use "`goto`" to code this.

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

Some sensors (like BME280) will automatically measure Sensor Data at __Periodic Intervals__.

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

In case of error we quit...

```zig
  // Check for error
  if (ret < 0 and errno() != c.ENOTSUP) {
    std.log.err("Failed to set interval:{s}", .{ c.strerror(errno()) });
    return error.IntervalError;
  }
```

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

As we've seen, Zig is pretty smart in __inferring the types__ of our variables and constants.

But __ioctl()__ is declared in C as...

```c
int ioctl(int fd, int req, ...);
```

Note that the Third Parameter __doesn't specify a type__ and Zig Compiler gets stumped.

That's why in Zig we explicitly pass the Third Parameter as...

```zig
@as(c_int, 1)
```

Which means that we pass the value `1` as a C Integer Type.

## Poll Sensor

TODO

```zig
  // Prepare to poll Sensor
  var fds = std.mem.zeroes(c.struct_pollfd);
  fds.fd = fd;
  fds.events = c.POLLIN;
```

TODO

```zig
  // If Sensor Data is available...
  if (c.poll(&fds, 1, -1) > 0) {
```

## Read Sensor Data

TODO

```zig
    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(c.struct_sensor_event_baro);
    const len = @sizeOf(@TypeOf(sensor_data));
```

TODO

```zig
    // Read the Sensor Data
    if (c.read(fd, &sensor_data, len) >= len) {

      // Convert the Sensor Data to Fixed-Point Numbers
      const pressure    = float_to_fixed(sensor_data.pressure);
      const temperature = float_to_fixed(sensor_data.temperature);
```

## Print Sensor Data

TODO

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
```

TODO

```zig        
    } else { std.log.err("Sensor data incorrect size", .{}); }
  } else { std.log.err("Sensor data not available", .{}); }
```

## Disable Sensor

TODO

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

TODO

Here's the Air Pressure and Temperature read from the BME280 Barometer Sensor...

```text
nsh> sensortest test
Zig Sensor Test
test_sensor
pressure:1007.66
temperature:27.70
```

# Read Humidity Sensor

TODO

[sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L147-L234)

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

TODO

```zig
  // If Sensor Data is available...
  if (c.poll(&fds, 1, -1) > 0) {

    // Define the Sensor Data Type
    var sensor_data = std.mem.zeroes(c.struct_sensor_event_humi);
    const len = @sizeOf(@TypeOf(sensor_data));

    // Read the Sensor Data
    if (c.read(fd, &sensor_data, len) >= len) {

      // Convert the Sensor Data to Fixed-Point Numbers
      const humidity = float_to_fixed(sensor_data.humidity);

      // Print the Sensor Data
      debug("humidity:{}.{:0>2}", .{
        humidity.int, 
        humidity.frac 
      });
```

Here's the Humidity read from the BME280 Humidity Sensor...

```text
nsh> sensortest test2
Zig Sensor Test
test_sensor2
humidity:78.81
```

# Import NuttX Functions

TODO

# Connect BME280 Sensor

TODO

For testing the Zig Sensor App, we connect the BME280 Sensor (Temperature / Humidity / Air Pressure) to Pine64's [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone)...

| BL602 Pin | BME280 Pin | Wire Colour
|:---:|:---:|:---|
| __`GPIO 1`__ | `SDA` | Green 
| __`GPIO 2`__ | `SCL` | Blue
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

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
