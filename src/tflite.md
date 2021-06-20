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

_The wavy curve looks familiar...?_

![Wavy Curve](https://lupyuen.github.io/images/tflite-chart2.jpg)

Yes it was the __Sine Function__ all along!

> __`y = sin( x )`__

(Input value `x` is in radians, not degrees)

_So we were using a TensorFlow Lite Model for the Sine Function?_

Right! The __"`init`"__ command from the previous chapter loads a TensorFlow Lite Model that's __trained with the Sine Function.__

_How accurate are the values inferred by the model?_

Sadly Machine Learning Models are __rarely 100% accurate.__

Here's a comparison of the __values inferred by the model (left)__ and the __actual values (right)__...

![Compare inferred vs actual values](https://lupyuen.github.io/images/tflite-compare.jpg)

_But we can train the model to be more accurate right?_

Training the Machine Learning Model on too much data may cause __Overfitting__...

When we vary the input value slightly, the __output value may fluctuate wildly__.

(We definitely don't want our LED to glow erratically!)

[More about Overfitting](https://en.wikipedia.org/wiki/Overfitting)

_Is the model accurate enough?_

Depends how we'll be using the model.

For glowing an LED it's probably OK to use a Machine Learning Model that's accurate to [__1 Significant Digit__](https://en.wikipedia.org/wiki/Significant_figures).

We'll watch the glowing LED in a while!

[(The TensorFlow Lite Model came from this sample code)](https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/hello_world)

# How It Works

Let's study the code inside the TensorFlow Lite Firmware for BL602... To understand how it __loads the TensorFlow Lite Model and runs inferences.__

Here are the __C++ Global Variables__ needed for TensorFlow Lite: [`main_functions.cc`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/main_functions.cc#L28-L39)

```c
// Globals for TensorFlow Lite
namespace {
  tflite::ErrorReporter* error_reporter = nullptr;
  const tflite::Model* model = nullptr;
  tflite::MicroInterpreter* interpreter = nullptr;
  TfLiteTensor* input = nullptr;
  TfLiteTensor* output = nullptr;

  constexpr int kTensorArenaSize = 2000;
  uint8_t tensor_arena[kTensorArenaSize];
}
```

-   __`error_reporter`__ will be used for __printing error messages__ to the console

-   __`model`__ is the __TensorFlow Lite Model__ that we shall load into memory

-   __`interpreter`__ provides the interface for __running inferences__ with the TensorFlow Lite Model

-   __`input`__ is the Tensor that we shall set to specify the __input values__ for running an inference

-   __`output`__ is the Tensor that will contain the __output values__ after running an inference

-   __`tensor_arena`__ is the __working memory__ that will be used by TensorFlow Lite to compute inferences

Now we study the code that populates the above Global Variables.

# Load TensorFlow Model

Here's the __"`init`" command__ for our BL602 Firmware: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/demo.c#L21-L24)

```c
/// Command to load the TensorFlow Lite Model (Sine Wave)
static void init(char *buf, int len, int argc, char **argv) {
  load_model();
}
```

The command calls __`load_model`__ to load the TensorFlow Lite Model: [`main_functions.cc`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/main_functions.cc#L41-L84)

```c
// Load the TensorFlow Lite Model into Static Memory
void load_model() {
  tflite::InitializeTarget();

  // Set up logging. Google style is to avoid globals or statics because of
  // lifetime uncertainty, but since this has a trivial destructor it's okay.
  static tflite::MicroErrorReporter micro_error_reporter;
  error_reporter = &micro_error_reporter;
```

Here we __initialise the TensorFlow Lite Library__.

Next we __load the TensorFlow Lite Model__...

```c
  // Map the model into a usable data structure. This doesn't involve any
  // copying or parsing, it's a very lightweight operation.
  model = tflite::GetModel(g_model);
  if (model->version() != TFLITE_SCHEMA_VERSION) {
    TF_LITE_REPORT_ERROR(error_reporter,
      "Model provided is schema version %d not equal "
      "to supported version %d.",
      model->version(), TFLITE_SCHEMA_VERSION);
    return;
  }
```

__`g_model`__ contains the __TensorFlow Lite Model Data__, as defined in [`model.cc`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/model.cc#L28-L238)

We create the __TensorFlow Lite Interpreter__ that will be called to run inferences...

```c
  // This pulls in all the operation implementations we need.
  static tflite::AllOpsResolver resolver;

  // Build an interpreter to run the model with.
  static tflite::MicroInterpreter static_interpreter(
      model, resolver, tensor_arena, kTensorArenaSize, error_reporter);
  interpreter = &static_interpreter;
```

Then we __allocate the working memory__ that will be used by the TensorFlow Lite Library to compute inferences...

```c
  // Allocate memory from the tensor_arena for the model's tensors.
  TfLiteStatus allocate_status = interpreter->AllocateTensors();
  if (allocate_status != kTfLiteOk) {
    TF_LITE_REPORT_ERROR(error_reporter, "AllocateTensors() failed");
    return;
  }
```

Finally we remember the __Input and Output Tensors__...

```c
  // Obtain pointers to the model's input and output tensors.
  input = interpreter->input(0);
  output = interpreter->output(0);
}
```

Which will be used in the next chapter to run inferences.

# Run TensorFlow Inference

Earlier we entered this command to __run an inference__ with the TensorFlow Lite Model...

```text
# infer 0.1
0.160969
```

Here's the __"`infer`" command__ in our BL602 Firmware: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/demo.c#L26-L37)

```c
/// Command to infer values with TensorFlow Lite Model (Sine Wave)
static void infer(char *buf, int len, int argc, char **argv) {
  //  Convert the argument to float
  if (argc != 2) { printf("Usage: infer <float>\r\n"); return; }
  float input = atof(argv[1]);
```

To run an inference, the "`infer`" command accepts __one input value__: a floating-point number.

We pass the floating-point number to the __`run_inference`__ function...

```c
  //  Run the inference
  float result = run_inference(input);

  //  Show the result
  printf("%f\r\n", result);
}
```

And we __print the result__ of the inference. (Another floating-point number)

__`run_inference`__ is defined in [`main_functions.cc`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/main_functions.cc#L86-L116) ...

```c
// Run an inference with the loaded TensorFlow Lite Model.
// Return the output value inferred by the model.
float run_inference(
  float x) {  //  Value to be fed into the model

  // Quantize the input from floating-point to integer
  int8_t x_quantized = x / input->params.scale 
    + input->params.zero_point;
```

Interesting Fact: Our TensorFlow Lite Model (for Sine Function) actually accepts an __integer input__ and produces an __integer output__! (8-bit integers)

(Integer models run more efficiently on microcontrollers)

The code above __converts the floating-point input__ to an 8-bit integer.

We pass the __8-bit integer input__ to the TensorFlow Lite Model through the __Input Tensor__...

```c
  // Place the quantized input in the model's input tensor
  input->data.int8[0] = x_quantized;
```

Then we __call the interpreter to run the inference__ on the TensorFlow Lite Model...

```c
  // Run inference, and report any error
  TfLiteStatus invoke_status = interpreter->Invoke();
  if (invoke_status != kTfLiteOk) {
    TF_LITE_REPORT_ERROR(error_reporter, "Invoke failed on x: %f\n",
      static_cast<double>(x));
    return 0;
  }
```

The 8-bit integer result is __returned through the Output Tensor__...

```c
  // Obtain the quantized output from model's output tensor
  int8_t y_quantized = output->data.int8[0];
```

We __convert the 8-bit integer result__ to floating-point...

```c
  // Dequantize the output from integer to floating-point
  float y = (y_quantized - output->params.zero_point) 
    * output->params.scale;

  // Output the results
  return y;
}
```

Finally we __return the floating-point result__.

The code we've seen is derived from the [TensorFlow Lite Hello World Sample](https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/hello_world), which is covered here...

-   ["TensorFlow Lite: Get started with microcontrollers"](https://www.tensorflow.org/lite/microcontrollers/get_started_low_level)

-   ["TensorFlow Lite: Understand the C++ library"](https://www.tensorflow.org/lite/microcontrollers/library)

# Glow The LED

As promised, now we __light up the BL602 LED with TensorFlow Lite__!

Here's the __"`glow`"__ command in our BL602 Firmware: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/demo.c#L39-L96)

```c
/// PineCone Blue LED is connected on BL602 GPIO 11
/// TODO: Change the LED GPIO Pin Number for your BL602 board
#define LED_GPIO 11

/// Use PWM Channel 1 to control the LED GPIO.
/// TODO: Select the PWM Channel that matches the LED GPIO
#define PWM_CHANNEL 1

/// Command to glow the LED with values generated by the TensorFlow Lite Model (Sine Wave).
/// We vary the LED brightness with Pulse Widge Modulation:
/// blinking the LED very rapidly with various Duty Cycle settings.
/// See https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm
static void glow(char *buf, int len, int argc, char **argv) {
  //  Configure the LED GPIO for PWM
  int rc = bl_pwm_init(
    PWM_CHANNEL,  //  PWM Channel (1) 
    LED_GPIO,     //  GPIO Pin Number (11)
    2000          //  PWM Frequency (2,000 Hz)
  );
  assert(rc == 0);
```

The "`glow`" command takes the __Output Values__ from the TensorFlow Lite Model (Sine Function) and sets the __brightness of the BL602 LED__...

![Wavy Curve](https://lupyuen.github.io/images/tflite-chart2.jpg)

The code above configures the __LED GPIO Pin for PWM Output__ at 2,000 cycles per second, by calling the [__BL602 PWM Hardware Abstraction Layer (HAL)__](https://lupyuen.github.io/articles/led#how-it-works-bl602-pwm).

(PWM or __Pulse Width Modulation__ means that we'll be pulsing the LED very rapidly at 2,000 times a second, to vary the perceived brightness. [See this](https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm))

To set the (perceived) LED Brightness, we set the __PWM Duty Cycle__ by calling the BL602 PWM HAL...

```c
  //  Dim the LED by setting the Duty Cycle to 100%
  rc = bl_pwm_set_duty(
    PWM_CHANNEL,  //  PWM Channel (1) 
    100           //  Duty Cycle (100%)
  );
  assert(rc == 0);
```

Here we set the __Duty Cycle to 100%__, which means that the LED GPIO will be __set to High for 100%__ of every PWM Cycle.

Our LED __switches off when the LED GPIO is set to High__. Thus the above code effectively sets the __LED Brightness to 0%__.

But PWM won't actually start until we do this...

```c
  //  Start the PWM, which will blink the LED very rapidly (2,000 times a second)
  rc = bl_pwm_start(PWM_CHANNEL);
  assert(rc == 0);
```

Now that __PWM is started__ for our LED GPIO, let's vary the LED Brightness...

1.  We do this __4 times__

    (Giving the glowing LED more time to mesmerise us)

1.  We step through the __Input Values from `0` to `6.283`__ (or `Pi * 2`) at intervals of `0.05`

    (Because the TensorFlow Lite Model has been trained on Input Values `0` to `Pi * 2`... One cycle of the Sine Wave)

```c
  //  Repeat 4 times...
  for (int i = 0; i < 4; i++) {

    //  With input values from 0 to 2 * Pi (stepping by 0.05)...
    for (float input = 0; input < kXrange; input += 0.05) {  //  kXrange is 2 * Pi: 6.283
```

Inside the loops, we __run the TensorFlow Lite inference__ with the Input Value (`0` to `6.283`)...

```c
      //  Infer the output value with the TensorFlow Model (Sine Wave)
      float output = run_inference(input);
```

(We've seen `run_inference` in the previous chapter)

The TensorFlow Lite Model (Sine Function) produces an __Output Value that ranges from `-1` to `1`.__

Negative values are not meaningful for setting the LED Brightness, hence we __multiply the Output Value by itself__...

```c
      //  Output value has range -1 to 1.
      //  We square the output value to produce range 0 to 1.
      float output_squared = output * output;
```

(Why compute __Output Squared__ instead of Output Absolute? Because Sine Squared produces a __smooth curve__, whereas Sine Absolute creates a sharp beak)

Next we set the __Duty Cycle to the Output Value Squared__, scaled to 100%...

```c
      //  Set the brightness (Duty Cycle) of the PWM LED to the 
      //  output value squared, scaled to 100%
      rc = bl_pwm_set_duty(
        PWM_CHANNEL,                //  PWM Channel (1) 
        (1 - output_squared) * 100  //  Duty Cycle (0% to 100%)
      );
      assert(rc == 0);
```

We __flip the LED Brightness__ (1 - Output Squared) because...

-  Duty Cycle = __0%__ means __100%__ brightness

-  Duty Cycle = __100%__ means __0%__ brightness

After setting the LED Brightness, we __sleep for 100 milliseconds__...

```c
      //  Sleep 100 milliseconds
      time_delay(                //  Sleep by number of ticks (from NimBLE Porting Layer)
        time_ms_to_ticks32(100)  //  Convert 100 milliseconds to ticks (from NimBLE Porting Layer)
      );
    }
  }
```

[(More about NimBLE Porting Layer)](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

And we repeat both loops.

At the end of the command, we __turn off the PWM__ for LED GPIO...

```c
  //  Stop the PWM, which will stop blinking the LED
  rc = bl_pwm_stop(PWM_CHANNEL);
  assert(rc == 0);
}
```

Let's run this!

![Glowing the LED with TensorFlow Lite](https://lupyuen.github.io/images/tflite-glow.png)

# Glowing Machine Learning in Action

1.  Start the __BL602 Firmware for TensorFlow Lite `sdk_app_tflite`__

    (As described earlier)

1.  Enter this command to __load the TensorFlow Lite Model__...

    ```text
    # init
    ```

    (We've seen the "`init`" command earlier)

1.  Then enter this command to __glow the LED with the TensorFlow Lite Model__...

    ```text
    # glow
    ```

    (Yep the "`glow`" command from the previous chapter)

1.  And the BL602 LED glows gently! Brighter and dimmer, brighter and dimmer, ...

    (Though the LED flips on abruptly at the end, because we turned off the PWM)

-   [__Watch the Demo Video on YouTube__](https://youtu.be/EFpYJ3qsmEY)

![Wavy Curve](https://lupyuen.github.io/images/tflite-chart2.jpg)

(Tip: The __Sine Function__ is a terrific way to do things __smoothly and continuously__! Because the derivative of `sin(x)` is `cos(x)`, another smooth curve! And the derivative of `cos(x)` is `-sin(x)`... Wow!)

# Train TensorFlow Model

![Creating a TensorFlow Lite Model won't be easy](https://lupyuen.github.io/images/tflite-meme.jpg)

Sorry Padme, it won't be easy to __create and train__ a TensorFlow Lite Model.

But let's quickly run through the steps...

_Where is the TensorFlow Lite Model defined?_

__`g_model`__ contains the __TensorFlow Lite Model Data__, as defined in [`model.cc`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/model.cc#L28-L238) ...

```c
// Automatically created from a TensorFlow Lite flatbuffer using the command:
//   xxd -i model.tflite > model.cc
// This is a standard TensorFlow Lite model file that has been converted into a
// C data array, so it can be easily compiled into a binary for devices that
// don't have a file system.
alignas(8) const unsigned char g_model[] = {
  0x1c, 0x00, 0x00, 0x00, 0x54, 0x46, 0x4c, 0x33, 0x14, 0x00, 0x20, 0x00,
  0x1c, 0x00, 0x18, 0x00, 0x14, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
  ...
  0x00, 0x00, 0x00, 0x09};
const int g_model_len = 2488;
```

The TensorFlow Lite Model (2,488 bytes) is stored in BL602's __XIP Flash ROM__.

This gives the TensorFlow Lite Library more __RAM to run Tensor Computations__ for inferencing.

(Remember __`tensor_arena`__?)

_Can we create and train this model on BL602?_

Sorry Padme nope.

Training a TensorFlow Lite Model requires __Python__. Thus we need a Linux, macOS or Windows computer.

Here's the __Python Jupyter Notebook__ for training the TensorFlow Lite Model that we have used...

-   ["Hello World: Jupyter Notebook on Google Colaboratory"](https://colab.research.google.com/github/tensorflow/tensorflow/blob/master/tensorflow/lite/micro/examples/hello_world/train/train_hello_world_model.ipynb?authuser=0)

Check out the docs on __training and converting TensorFlow Lite Models__...

-   ["TensorFlow Lite: Hello World Training"](https://github.com/tensorflow/tensorflow/blob/master/tensorflow/lite/micro/examples/hello_world/train/README.md)

-   ["TensorFlow Lite: Build and convert models"](https://www.tensorflow.org/lite/microcontrollers/build_convert)

# What Else Can TensorFlow Do?

Even though we've used TensorFlow Lite for a trivial task (glowing an LED)... There are __so many possible applications__!

1.  PineCone BL602 Board has a __3-in-1 LED: Red + Green + Blue__.

    We could control all 3 LEDs and glow them in a dazzling, multicolour way!

    (The TensorFlow Lite Model would probably produce an Output Tensor that contains 3 Output Values)

1.  Light up an LED when BL602 __detects my face__.

    We could stream the __2D Image Data from a Camera Module__ to the TensorFlow Lite Model.

    [Check out the sample code](https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/person_detection)

1.  Recognise __spoken words and phrases__.

    By streaming the __Audio Data from a Microphone__ to the TensorFlow Lite Model.

    [Check out the sample code](https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/micro_speech)

1.  Recognise __motion gestures__.

    By streaming the __Motion Data from an Accelerometer__ to the TensorFlow Lite Model.

    [Check out the sample code](https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/magic_wand)

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

# Appendix: Porting TensorFlow to BL602

In this chapter we discuss the changes we made when __porting TensorFlow Lite to BL602__.

## Source Repositories

TensorFlow Lite on BL602 is split across two repositories...

1.  __TensorFlow Lite Firmware:__

    TODO

    [github.com/lupyuen/bl_iot_sdk/tree/tflite](https://github.com/lupyuen/bl_iot_sdk/tree/tflite)

    [customer_app/sdk_app_tflite](https://github.com/lupyuen/bl_iot_sdk/tree/tflite/customer_app/sdk_app_tflite)

1.  __TensorFlow Lite Library:__

    TODO

    [github.com/lupyuen/tflite-bl602](https://github.com/lupyuen/tflite-bl602)

    `components/3rdparty/tflite-bl602`

    git submodule

## Makefiles

TODO

## Source Folders

TODO

From [`tflite-bl602/bouffalo.mk`](https://github.com/lupyuen/tflite-bl602/blob/main/bouffalo.mk) and [`tflite-bl602/component.mk`](https://github.com/lupyuen/tflite-bl602/blob/main/component.mk)

```text
# Include Folders
# TODO: Sync with bouffalo.mk and component.mk
COMPONENT_ADD_INCLUDEDIRS := \
    tensorflow/.. \
    tensorflow/lite/micro/tools/make/downloads/flatbuffers/include \
    tensorflow/lite/micro/tools/make/downloads/gemmlowp \
    tensorflow/lite/micro/tools/make/downloads/ruy

# Source Folders
# TODO: Sync with bouffalo.mk and component.mk
COMPONENT_SRCDIRS := \
    tensorflow/lite/c \
    tensorflow/lite/core/api \
    tensorflow/lite/kernels \
    tensorflow/lite/kernels/internal \
    tensorflow/lite/micro \
    tensorflow/lite/micro/kernels \
    tensorflow/lite/micro/memory_planner \
    tensorflow/lite/schema
```

TODO

![Source Folders](https://lupyuen.github.io/images/tflite-source.png)

TODO17

## Compiler Flags

TODO

From [`tflite-bl602/bouffalo.mk`](https://github.com/lupyuen/tflite-bl602/blob/main/bouffalo.mk#L28-L49)

```text
# Define the GCC compiler options:
# CFLAGS for C compiler, CPPFLAGS for C++ compiler

# Use global C math functions instead of std library.
# See tensorflow/lite/kernels/internal/cppmath.h
CFLAGS   += -DTF_LITE_USE_GLOBAL_CMATH_FUNCTIONS
CPPFLAGS += -DTF_LITE_USE_GLOBAL_CMATH_FUNCTIONS

# Use std::min instead of std::fmin
# See tensorflow/lite/kernels/internal/min.h
CFLAGS   += -DTF_LITE_USE_GLOBAL_MIN
CPPFLAGS += -DTF_LITE_USE_GLOBAL_MIN

# Use std::max instead of std::fmax
# See tensorflow/lite/kernels/internal/max.h
CFLAGS   += -DTF_LITE_USE_GLOBAL_MAX
CPPFLAGS += -DTF_LITE_USE_GLOBAL_MAX

# Use Static Memory instead of Heap Memory
# See tensorflow/lite/kernels/internal/types.h
CFLAGS   += -DTF_LITE_STATIC_MEMORY
CPPFLAGS += -DTF_LITE_STATIC_MEMORY
```

TODO

From [`sdk_app_tflite/bouffalo.mk`](https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/sdk_app_tflite/bouffalo.mk#L28-L41)

```text
# Define the GCC compiler options:
# CFLAGS for C compiler, CPPFLAGS for C++ compiler
# See additional options at components/3rdparty/tflite-bl602/bouffalo.mk

# Use Static Memory instead of Heap Memory
# See components/3rdparty/tflite-bl602/tensorflow/lite/kernels/internal/types.h
CFLAGS   += -DTF_LITE_STATIC_MEMORY
CPPFLAGS += -DTF_LITE_STATIC_MEMORY

# Don't use Thread-Safe Initialisation for C++ Static Variables.
# This fixes the missing symbols __cxa_guard_acquire and __cxa_guard_release.
# Note: This assumes that we will not init C++ static variables in multiple tasks.
# See https://alex-robenko.gitbook.io/bare_metal_cpp/compiler_output/static
CPPFLAGS += -fno-threadsafe-statics
```

TODO

![Compiler Flags](https://lupyuen.github.io/images/tflite-cppflags.png)

TODO5

![Compiler Flags](https://lupyuen.github.io/images/tflite-cppflags2.png)

TODO6

## Download Libraries

TODO

From [`tflite-bl602/bouffalo.mk`](https://github.com/lupyuen/tflite-bl602/blob/main/bouffalo.mk#L51-L112)

```text
# TensorFlow Makefile
# Based on https://github.com/lupyuen/bl_iot_sdk/blob/tflite/customer_app/sdk_app_tflite/Makefile

# root directory of tensorflow
TENSORFLOW_ROOT := 
MAKEFILE_DIR := $(BL60X_SDK_PATH)/components/3rdparty/tflite-bl602/tensorflow/lite/micro/tools/make

# For some invocations of the makefile, it is useful to avoid downloads. This
# can be achieved by explicitly passing in DISABLE_DOWNLOADS=true on the command
# line. Note that for target-specific downloads (e.g. CMSIS) there will need to
# be corresponding checking in the respecitve included makefiles (e.g.
# ext_libs/cmsis_nn.inc)
DISABLE_DOWNLOADS :=

ifneq ($(DISABLE_DOWNLOADS), true)
  # The download scripts require that the downloads directory already exist for
  # improved error checking. To accomodate that, we first create a downloads
  # directory.
  $(shell mkdir -p ${MAKEFILE_DIR}/downloads)

  # Directly download the flatbuffers library.
  DOWNLOAD_RESULT := $(shell $(MAKEFILE_DIR)/flatbuffers_download.sh ${MAKEFILE_DIR}/downloads)
  ifneq ($(DOWNLOAD_RESULT), SUCCESS)
    $(error Something went wrong with the flatbuffers download: $(DOWNLOAD_RESULT))
  endif

  DOWNLOAD_RESULT := $(shell $(MAKEFILE_DIR)/pigweed_download.sh ${MAKEFILE_DIR}/downloads)
  ifneq ($(DOWNLOAD_RESULT), SUCCESS)
    $(error Something went wrong with the pigweed download: $(DOWNLOAD_RESULT))
  endif

  #### TODO: Fix third-party downloads
  include $(MAKEFILE_DIR)/third_party_downloads.inc
  THIRD_PARTY_DOWNLOADS :=
  $(eval $(call add_third_party_download,$(GEMMLOWP_URL),$(GEMMLOWP_MD5),gemmlowp,))
  $(eval $(call add_third_party_download,$(RUY_URL),$(RUY_MD5),ruy,))
  $(eval $(call add_third_party_download,$(PERSON_MODEL_URL),$(PERSON_MODEL_MD5),person_model_grayscale,))
  RESULT := $(shell $(MAKEFILE_DIR)/person_detection_int8_download.sh ${MAKEFILE_DIR}/downloads $(CO_PROCESSOR))
  ifneq ($(RESULT), SUCCESS)
    $(error Something went wrong with the person detection int8 model download: $(RESULT))
  endif

  #### Added GEMMLOWP, RUY downloads
  #### TODO: Use the download rules in helper_functions.inc
  RESULT := $(shell $(MAKEFILE_DIR)/download_and_extract.sh $(GEMMLOWP_URL) $(GEMMLOWP_MD5) ${MAKEFILE_DIR}/downloads/gemmlowp)
  #### TODO: Check results of download
  # ifneq ($(RESULT), SUCCESS)
  #   $(error Something went wrong with the GEMMLOWP download: $(RESULT))
  # endif
  RESULT := $(shell $(MAKEFILE_DIR)/download_and_extract.sh $(RUY_URL) $(RUY_MD5) ${MAKEFILE_DIR}/downloads/ruy)
  #### TODO: Check results of download
  # ifneq ($(RESULT), SUCCESS)
  #   $(error Something went wrong with the RUY download: $(RESULT))
  # endif

endif

#### TODO: Fix third-party downloads
# Create rules for downloading third-party dependencies.
THIRD_PARTY_TARGETS :=
$(foreach DOWNLOAD,$(THIRD_PARTY_DOWNLOADS),$(eval $(call create_download_rule,$(DOWNLOAD))))
third_party_downloads: $(THIRD_PARTY_TARGETS)
```

TODO

![Download gemmlowp](https://lupyuen.github.io/images/tflite-gemmlowp.png)

TODO8

![Download gemmlowp](https://lupyuen.github.io/images/tflite-gemmlowp2.png)

TODO9

![Download ruy](https://lupyuen.github.io/images/tflite-ruy.png)

TODO14

## Optimise TensorFlow

TODO

-   ["TensorFlow Lite: Optimised Kernels"](https://www.tensorflow.org/lite/microcontrollers/library#optimized_kernels)

## TODO

![](https://lupyuen.github.io/images/tflite-cmath.png)

TODO3

![](https://lupyuen.github.io/images/tflite-commands.png)

TODO4

![](https://lupyuen.github.io/images/tflite-dsohandle.png)

TODO7

![](https://lupyuen.github.io/images/tflite-infer.png)

TODO10

![](https://lupyuen.github.io/images/tflite-initstatic.png)

TODO11

![](https://lupyuen.github.io/images/tflite-math.png)

TODO12

![](https://lupyuen.github.io/images/tflite-flatbuffers.png)

TODO13

![](https://lupyuen.github.io/images/tflite-setup.png)

TODO15

![](https://lupyuen.github.io/images/tflite-loop.png)

TODO16

![](https://lupyuen.github.io/images/tflite-static.png)

TODO18

![](https://lupyuen.github.io/images/tflite-undefined.png)

TODO19

![](https://lupyuen.github.io/images/tflite-undefined2.png)

TODO20

![](https://lupyuen.github.io/images/tflite-undefined3.png)

TODO21

![](https://lupyuen.github.io/images/tflite-undefined4.png)

TODO22

![](https://lupyuen.github.io/images/tflite-build.png)

TODO2

