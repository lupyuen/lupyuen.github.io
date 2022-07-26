# Read NuttX Sensor Data with Zig

📝 _31 Jul 2022_

![TODO](https://lupyuen.github.io/images/sensor-title.jpg)

TODO

-   [__lupyuen/visual-zig-nuttx__](https://github.com/lupyuen/visual-zig-nuttx)

[Changes to NuttX Sensors](https://github.com/apache/incubator-nuttx/commits/master/include/nuttx/sensors/sensor.h)

# Read Barometer Sensor

TODO

[sensortest.zig](https://github.com/lupyuen/visual-zig-nuttx/blob/main/sensortest.zig#L53-L145)

```zig
/// Read Pressure and Temperature from Barometer Sensor "/dev/sensor/baro0"
fn test_sensor() !void {
    debug("test_sensor", .{});

    // Open the Sensor Device
    const fd = c.open(
        "/dev/sensor/baro0",       // Path of Sensor Device
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
    // TODO: Remove this definition when SNIOC_SET_INTERVAL has been been fixed: https://github.com/apache/incubator-nuttx/issues/6642
    const SNIOC_SET_INTERVAL = c._SNIOC(0x0081);
    var interval: c_uint = 1_000_000;  // 1,000,000 microseconds (1 second)
    var ret = c.ioctl(fd, SNIOC_SET_INTERVAL, &interval);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to set interval:{s}", .{ c.strerror(errno()) });
        return error.IntervalError;
    }

    // Set Batch Latency
    var latency: c_uint = 0;  // No latency
    ret = c.ioctl(fd, c.SNIOC_BATCH, &latency);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to batch:{s}", .{ c.strerror(errno()) });
        return error.BatchError;
    }

    // Enable Sensor and switch to Normal Power Mode
    ret = c.ioctl(fd, c.SNIOC_ACTIVATE, @as(c_int, 1));

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to enable sensor:{s}", .{ c.strerror(errno()) });
        return error.EnableError;
    }

    // Prepare to poll Sensor
    var fds = std.mem.zeroes(c.struct_pollfd);
    fds.fd = fd;
    fds.events = c.POLLIN;

    // If Sensor Data is available...
    if (c.poll(&fds, 1, -1) > 0) {

        // Define the Sensor Data Type
        var sensor_data = std.mem.zeroes(c.struct_sensor_event_baro);
        const len = @sizeOf(@TypeOf(sensor_data));

        // Read the Sensor Data
        if (c.read(fd, &sensor_data, len) >= len) {

            // Convert the Sensor Data to Fixed-Point Numbers
            const pressure    = float_to_fixed(sensor_data.pressure);
            const temperature = float_to_fixed(sensor_data.temperature);

            // Print the Sensor Data
            debug("pressure:{}.{:0>2}", .{
                pressure.int, 
                pressure.frac 
            });
            debug("temperature:{}.{:0>2}", .{
                temperature.int,
                temperature.frac 
            });
            
        } else { std.log.err("Sensor data incorrect size", .{}); }
    } else { std.log.err("Sensor data not available", .{}); }

    // Disable Sensor and switch to Low Power Mode
    ret = c.ioctl(fd, c.SNIOC_ACTIVATE, @as(c_int, 0));

    // Check for error
    if (ret < 0) {
        std.log.err("Failed to disable sensor:{s}", .{ c.strerror(errno()) });
        return error.DisableError;
    }
}
```

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
/// Read Humidity from Humidity Sensor "/dev/sensor/humi0"
fn test_sensor2() !void {
    debug("test_sensor2", .{});

    // Open the Sensor Device
    const fd = c.open(
        "/dev/sensor/humi0",       // Path of Sensor Device
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
    // TODO: Remove this definition when SNIOC_SET_INTERVAL has been been fixed: https://github.com/apache/incubator-nuttx/issues/6642
    const SNIOC_SET_INTERVAL = c._SNIOC(0x0081);
    var interval: c_uint = 1_000_000;  // 1,000,000 microseconds (1 second)
    var ret = c.ioctl(fd, SNIOC_SET_INTERVAL, &interval);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to set interval:{s}", .{ c.strerror(errno()) });
        return error.IntervalError;
    }

    // Set Batch Latency
    var latency: c_uint = 0;  // No latency
    ret = c.ioctl(fd, c.SNIOC_BATCH, &latency);

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to batch:{s}", .{ c.strerror(errno()) });
        return error.BatchError;
    }

    // Enable Sensor and switch to Normal Power Mode
    ret = c.ioctl(fd, c.SNIOC_ACTIVATE, @as(c_int, 1));

    // Check for error
    if (ret < 0 and errno() != c.ENOTSUP) {
        std.log.err("Failed to enable sensor:{s}", .{ c.strerror(errno()) });
        return error.EnableError;
    }

    // Prepare to poll Sensor
    var fds = std.mem.zeroes(c.struct_pollfd);
    fds.fd = fd;
    fds.events = c.POLLIN;

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

        } else { std.log.err("Sensor data incorrect size", .{}); }
    } else { std.log.err("Sensor data not available", .{}); }

    // Disable Sensor and switch to Low Power Mode
    ret = c.ioctl(fd, c.SNIOC_ACTIVATE, @as(c_int, 0));

    // Check for error
    if (ret < 0) {
        std.log.err("Failed to disable sensor:{s}", .{ c.strerror(errno()) });
        return error.DisableError;
    }
}
```

Here's the Humidity read from the BME280 Humidity Sensor...

```text
nsh> sensortest test2
Zig Sensor Test
test_sensor2
humidity:78.81
```

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
