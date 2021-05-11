# uLisp and Blockly on PineCone BL602 RISC-V Board

📝 _16 May 2021_

What if we could run __Lisp programs__ on the [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone)?

```text
( loop
  ( pinmode 11 :output )
  ( digitalwrite 11 :high )
  ( delay 1000 )
  ( pinmode 11 :output )
  ( digitalwrite 11 :low )
  ( delay 1000 )
)
```

And create these programs with a __drag-and-drop Web Editor__... Without typing a single Lisp parenthesis / bracket?

![Blockly for uLisp](https://lupyuen.github.io/images/lisp-web.png)

Today we shall explore __uLisp and Blockly__ as an interesting new way to create embedded programs for the __BL602 RISC-V + WiFi SoC__.

(And someday this could become really helpful for __IoT Education__)

The uLisp Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo on YouTube__](https://youtu.be/LNkmUIv7ZZc)

![uLisp and Blockly on PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/lisp-cover.jpg)

_uLisp and Blockly on PineCone BL602 RISC-V Board_

# Start with uLisp

TODO

http://www.ulisp.com/show?21T5

# Build the BL602 uLisp Firmware

TODO

https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp

https://github.com/lupyuen/ulisp-bl602

# Run the BL602 uLisp Firmware

TODO

We need a space before the first `(` because `(` is parsed as a command keyword...

List Commands from http://www.ulisp.com/show?1AC5

```text
# Create a list (1 2 3)
( list 1 2 3 )

# Returns 1
( car ( list 1 2 3 ) )

# Returns (2 3)
( cdr ( list 1 2 3 ) )
```

GPIO Commands from http://www.ulisp.com/show?1AEK

```text
# Configure GPIO Pin 11 (Blue LED) for output (instead of input) 
( pinmode 11 :output )

# Set GPIO Pin 11 to High (LED Off)
( digitalwrite 11 :high )

# Set GPIO Pin 11 to Low (LED On)
( digitalwrite 11 :low )

# Sleep 1,000 milliseconds (1 second)
( delay 1000 )
```

![](https://lupyuen.github.io/images/lisp-led.png)

TODO

Blinky Commands from http://www.ulisp.com/show?1AEK

```text
# Define the blinky function
( defun blinky ()             \
  ( pinmode 11 :output )      \
  ( loop                      \
   ( digitalwrite 11 :high )  \
   ( delay 1000 )             \
   ( digitalwrite 11 :low  )  \
   ( delay 1000 )))

# Run the blinky function
( blinky )
```

Watch the demo on YouTube...

- [__LED Demo__](https://youtu.be/RRhzW4j8BtI)

- [__Blinky Demo__](https://youtu.be/LNkmUIv7ZZc)

TODO

![](https://lupyuen.github.io/images/lisp-interpreter.png)

TODO

![](https://lupyuen.github.io/images/lisp-blinky.png)

TODO

![](https://lupyuen.github.io/images/lisp-blinky2.png)

# Now add Blockly

TODO

![](https://lupyuen.github.io/images/lisp-blockly.png)

TODO

![](https://lupyuen.github.io/images/lisp-blockly2.png)

TODO

# Run the Blockly Web Editor

TODO

https://appkaki.github.io/blockly-ulisp/demos/code/

https://github.com/AppKaki/blockly-ulisp

![](https://lupyuen.github.io/images/lisp-mobile.png)

TODO

# Porting uLisp to BL602

TODO

# Lisp Code Generator for Blockly

The following have been added into the existing [`generators`](generators) folder to generate Lisp code and to add blocks specific to uLisp...

-   [`generators/lisp.js`](generators/lisp.js): Main interface for Lisp Code Generator

-   [`generators/lisp`](generators/lisp): Lisp Code Generator for various blocks

-   [`generators/lisp/lisp_library.xml`](generators/lisp/lisp_library.xml): Blocks XML file used by Block Exporter to generate the custom blocks

The Lisp Code Generator is __incomplete__. The only blocks supported are...

1.  Forever

1.  On Start

1.  Wait

1.  GPIO Digital Write

The Lisp Code Generator is based on Visual Embedded Rust...

https://lupyuen.github.io/articles/advanced-topics-for-visual-embedded-rust-programming

![](https://lupyuen.github.io/images/lisp-dart.png)

TODO

![](https://lupyuen.github.io/images/lisp-generate.png)

TODO

![](https://lupyuen.github.io/images/lisp-rust.png)

TODO

# Blockly Web Editor for uLisp

Watch the demo on YouTube...

- [__LED Demo__](https://youtu.be/RRhzW4j8BtI)

- [__Blinky Demo__](https://youtu.be/LNkmUIv7ZZc)

Try it here...

https://appkaki.github.io/blockly-ulisp/demos/code/

The Blockly demo at [`demos/code`](demos/code) has been customised to include the Lisp Code Generator...

-   [`demos/code/index.html`](demos/code/index.html): Customised to load the Lisp Code Generator and Lisp Blocks

-   [`demos/code/code.js`](demos/code/code.js): Customised to load the Lisp Code Generator and Lisp Blocks

The Blockly demo calls the [__Web Serial API__](https://web.dev/serial/) to transfer the generated uLisp Script to BL602...

https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js#L641-L738

We assume that BL602 is running the uLisp Firmware and connected to our computer via USB...

https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp

Inspired by MakeCode for BBC micro:bit...

https://makecode.microbit.org/

# Web Serial API

TODO

![](https://lupyuen.github.io/images/lisp-terminal.png)

TODO

![](https://lupyuen.github.io/images/lisp-reboot.jpg)

TODO

![](https://lupyuen.github.io/images/lisp-reboot2.png)

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lisp.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lisp.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1389783215347429382)

TODO

![](https://lupyuen.github.io/images/lisp-build.png)

TODO

![](https://lupyuen.github.io/images/lisp-build2.png)

TODO
