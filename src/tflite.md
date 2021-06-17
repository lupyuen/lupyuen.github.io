# Machine Learning on RISC-V BL602 with TensorFlow Lite

📝 _22 Jun 2021_

How a Human teaches a Machine to light up an LED...

> _Human:_ Hello Machine, please light up the LED in a fun and interesting way.

> _Machine:_ OK I shall light up the LED: on - off - on -off - on - off...

![On - Off - On - Off](https://lupyuen.github.io/images/tflite-chart1.jpg)

> _Human:_ That's not very fun and interesting.

> _Machine:_ OK Hooman... Define fun and interesting.

> _Human:_ Make the LED glow gently brighter and dimmer, brighter and dimmer, and so on.

> _Machine:_ Like a wavy curve? Please teach me to draw a wavy curve.

> _Human:_ Like this...

![Wavy Curve](https://lupyuen.github.io/images/tflite-chart2.jpg)

> _Machine:_ OK I have been trained. I shall now use my trained model to infer the values of the wavy curve. And light up the LED in a fun and interesting way.

-   [__Watch the Demo Video on YouTube__](https://youtu.be/EFpYJ3qsmEY)

This sounds like Science Fiction... But __this is possible today!__

(Except for the polite banter)

Read on to learn how __Machine Learning (TensorFlow Lite)__ makes this possible on the __BL602 RISC-V SoC__.

# TensorFlow Lite Library

Remember in our story...

1. Our Machine __learns to draw a wavy curve__

1. Our Machine __reproduces the wavy curve__ (to light up the LED)

To accomplish (1) and (2) on BL602, we shall use an open-source __Machine Learning__ library: [__TensorFlow Lite for Microcontrollers__](https://www.tensorflow.org/lite/microcontrollers)

_What's a Tensor?_

Remember these from our Math Textbook? __Scalar, Vector and Matrix__

![Scalar, Vector, Matrix](https://lupyuen.github.io/images/tflite-matrix.png)

[(From TensorFlow Guide)](https://www.tensorflow.org/guide/tensor)

When we extend a Matrix from 2D to 3D, we get a __Tensor With 3 Axes__...

![Tensor with 3 and 4 Axes](https://lupyuen.github.io/images/tflite-tensor.png)

And yes we can have a __Tensor With 4 or More Axes__!

__Tensors With Multiple Dimensions__ are really useful for crunching the numbers needed for Machine Learning.

That's how the TensorFlow library works: __Computing lots of Tensors__.

(Fortunately we won't need to compute any Tensors ourselves... The library does everything for us)

[More about Tensors](https://www.tensorflow.org/guide/tensor)

_Why is the library named TensorFlow?_

Because it doesn't drip, it flows 😂

But seriously... In Machine Learning we push lots of numbers __(Tensors)__ through various math functions over specific paths __(Dataflow Graphs)__.

That's why it's named __"TensorFlow"__

(Yes it sounds like the Neural Network in our brain)

[More about TensorFlow](https://en.m.wikipedia.org/wiki/TensorFlow)

_What's the "Lite" version of TensorFlow?_

TensorFlow normally runs on powerful servers to perform Machine Learning tasks. (Like Speech Recognition and Image Recognition)

We're using __TensorFlow Lite__, which is __optimised for microcontrollers__...

1.  Works on microcontrollers with __limited RAM__

    (Including Arduino, Arm and ESP32)

1.  Uses __Static Memory__ instead of Dynamic Memory (Heap)

1.  But it only supports __Basic Models__ of Machine Learning

Today we shall study the TensorFlow Lite library that has been ported to BL602...

-   [__`tflite-bl602` TensorFlow Lite Library for BL602__](https://github.com/lupyuen/tflite-bl602)

# TensorFlow Lite Firmware

Let's build, flash and run the TensorFlow Lite Firmware for BL602... And watch Machine Learning in action!

## Build the Firmware

Download the Firmware Binary File __`sdk_app_tflite.bin`__ from...

-  [__Binary Release of `sdk_app_tflite`__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v10.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_tflite.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/tflite/customer_app/sdk_app_tflite)...

```bash
# Download the tflite branch of lupyuen's bl_iot_sdk
git clone --recursive --branch tflite https://github.com/lupyuen/bl_iot_sdk

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$PWD/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

# Build the firmware
cd bl_iot_sdk/customer_app/sdk_app_tflite
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_tflite.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`tflite`__ branch, not the default __`master`__ branch)

## Flash the Firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_tflite.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `sdk_app_tflite.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_tflite.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_tflite.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_tflite.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the Firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

We're ready to enter the Machine Learning Commands into the BL602 Firmware!

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

# Machine Learning in Action

Remember this __wavy curve__?

![Wavy Curve](https://lupyuen.github.io/images/tflite-chart2.jpg)

We wanted to apply __Machine Learning on BL602__ to...

1.  __Learn__ the wavy curve

1.  __Reproduce__ values from the wavy curve

Watch what happens when we enter the __Machine Learning Commands__ into the BL602 Firmware.

## Load the Model

We enter this command to load BL602's "brain" with knowledge about the wavy curve...

```text
# init
```

(Wow wouldn't it be great if we could do this for our School Tests?)

Technically we call this __"Loading The TensorFlow Lite Model".__

The __TensorFlow Lite Model__ works like a "brain dump" or "knowledge snapshot" that tells BL602 everything about the wavy curve.

(How did we create the model? We'll learn in a while)

## Run an Inference

Now that BL602 has loaded the TensorFlow Lite Model (and knows everything about the wavy curve), let's test it!

This command asks BL602 to __infer the output value__ of the wavy curve, given the __input value `0.1`__...

```text
# infer 0.1
0.160969
```

BL602 responds with the __inferred output value `0.160969`__

![Infer Output Value](https://lupyuen.github.io/images/tflite-chart3.png)

Let's test it with two more __input values: `0.2` and `0.3`__...

```text
# infer 0.2
0.262633

# infer 0.3
0.372770
```

BL602 responds with the __inferred output values: `0.262633` and `0.372770`__

That's how we __load a TensorFlow Lite Model__ on BL602... And __run an inference__ with the TensorFlow Lite Model!

-   [__Watch the Demo Video on YouTube__](https://youtu.be/cCzUFIdUfio)

![Run TensorFlow Firmware](https://lupyuen.github.io/images/tflite-run.png)

# How Accurate Is It?

TODO

![Compare inferred vs actual values](https://lupyuen.github.io/images/tflite-compare.jpg)

TODO

# Load TensorFlow Model

TODO

["Get started with microcontrollers"](https://www.tensorflow.org/lite/microcontrollers/get_started_low_level)

["Understand the C++ library"](https://www.tensorflow.org/lite/microcontrollers/library)

# Run TensorFlow Inference

TODO

# Glow The LED

TODO

![Glowing the LED with TensorFlow Lite](https://lupyuen.github.io/images/tflite-glow.png)

TODO

# Train TensorFlow Model

TODO

["Build and convert models"](https://www.tensorflow.org/lite/microcontrollers/build_convert)

# What Can TensorFlow Do?

TODO

# Optimise TensorFlow

TODO

["Optimised Kernels"](https://www.tensorflow.org/lite/microcontrollers/library#optimized_kernels)

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/tflite.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tflite.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1402531760764641280)

![](https://lupyuen.github.io/images/tflite-build.png)

TODO

![](https://lupyuen.github.io/images/tflite-cmath.png)

TODO

![](https://lupyuen.github.io/images/tflite-commands.png)

TODO

![](https://lupyuen.github.io/images/tflite-cppflags.png)

TODO

![](https://lupyuen.github.io/images/tflite-cppflags2.png)

TODO

![](https://lupyuen.github.io/images/tflite-dsohandle.png)

TODO

![](https://lupyuen.github.io/images/tflite-gemmlowp.png)

TODO

![](https://lupyuen.github.io/images/tflite-gemmlowp2.png)

TODO

![](https://lupyuen.github.io/images/tflite-infer.png)

TODO

![](https://lupyuen.github.io/images/tflite-initstatic.png)

TODO

![](https://lupyuen.github.io/images/tflite-math.png)

TODO

![](https://lupyuen.github.io/images/tflite-flatbuffers.png)

TODO

![](https://lupyuen.github.io/images/tflite-ruy.png)

TODO

![](https://lupyuen.github.io/images/tflite-setup.png)

TODO

![](https://lupyuen.github.io/images/tflite-loop.png)

TODO

![](https://lupyuen.github.io/images/tflite-source.png)

TODO

![](https://lupyuen.github.io/images/tflite-static.png)

TODO

![](https://lupyuen.github.io/images/tflite-undefined.png)

TODO

![](https://lupyuen.github.io/images/tflite-undefined2.png)

TODO

![](https://lupyuen.github.io/images/tflite-undefined3.png)

TODO

![](https://lupyuen.github.io/images/tflite-undefined4.png)

TODO

