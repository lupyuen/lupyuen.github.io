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

TODO

[(From TensorFlow Guide)](https://www.tensorflow.org/guide/tensor)

When we extend a Matrix from 2D to 3D, it becomes a __Tensor With 3 Axes__...

TODO

And yes we can have a __Tensor With 4 or More Axes__!

TODO

__Tensors With Multiple Dimensions__ are really useful for crunching the numbers needed for Machine Learning.

That's how the TensorFlow library works: Computing lots of Tensors.

(Fortunately we won't need to compute any Tensors ourselves... The library does everything for us)

[More about Tensors](https://www.tensorflow.org/guide/tensor)

_Why is the library named TensorFlow?_

Because it doesn't drip, it flows 😂

But seriously... In Machine Learning we push lots of numbers __(Tensors)__ through various math functions over specific paths __(Dataflow Graphs)__.

That's why it's named __"TensorFlow"__

(Yes it sounds like the Neural Network in our brain)

[More about TensorFlow](https://en.m.wikipedia.org/wiki/TensorFlow)

_What's the "Lite" version of TensorFlow?_

TODO

["Get started with microcontrollers"](https://www.tensorflow.org/lite/microcontrollers/get_started_low_level)

["Understand the C++ library"](https://www.tensorflow.org/lite/microcontrollers/library)

TODO

# TensorFlow Lite Firmware

TODO

# Load TensorFlow Model

TODO

# Run TensorFlow Inference

TODO

# Glow The LED

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
