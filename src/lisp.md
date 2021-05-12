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

And create the programs with a __drag-and-drop Web Editor__... Without typing a single Lisp parenthesis / bracket?

![Blockly for uLisp](https://lupyuen.github.io/images/lisp-web.png)

Today we shall explore __uLisp and Blockly__ as an interesting new way to create embedded programs for the __BL602 RISC-V + WiFi SoC__.

(And someday this could become really helpful for __IoT Education__)

The uLisp Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo on YouTube__](https://youtu.be/LNkmUIv7ZZc)

![uLisp and Blockly on PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/lisp-cover.jpg)

_uLisp and Blockly on PineCone BL602 RISC-V Board_

# Start with uLisp

_What is uLisp?_

From the [uLisp Website](http://www.ulisp.com)...

> uLisp® is a version of the Lisp programming language specifically designed to run on __microcontrollers with a limited amount of RAM__, from the Arduino Uno based on the ATmega328 up to the Teensy 4.0/4.1. You can use exactly the same uLisp program, irrespective of the platform.

> Because __uLisp is an interpreter__ you can type commands in, and see the effect immediately, without having to compile and upload your program. This makes it an ideal environment for __learning to program__, or for setting up simple electronic devices.

_Why is uLisp special?_

Compared with other embedded programming languages, uLisp looks particularly interesting because it has __built-in Arduino-like functions__ for GPIO, I2C, SPI, ADC, DAC, ... Even WiFi!

So this Blinky program runs perfectly fine on uLisp...

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

Because `pinmode` (set the GPIO pin mode) and `digitalwrite` (set the GPIO pin output) are Arduino-like GPIO functions predefined in uLisp.

(`delay` is another Arduino-like Timer function predefined in uLisp. It waits for the specified number of milliseconds.)

uLisp makes it possible to write __high-level scripts__ with GPIO, I2C, SPI, ADC, DAC and WiFi functions.

And for learners familiar with Arduino, this might be a helpful way to __adapt to modern microcontrollers__ like BL602.

_Why port uLisp to BL602?_

uLisp is a natural fit for the BL602 RISC-V + WiFi SoC because...

1.  BL602 has a __Command-Line Interface__ (and so does uLisp)

    Unlike most 32-bit microcontrollers, BL602 was designed to be accessed by embedded developers via a simple Command-Line Interface (over the USB Serial Port).

    BL602 doesn't have a fancy shell like `bash`. But uLisp on BL602 could offer some helpful __scripting capability__  for GPIO, I2C, SPI, WiFi, ...

1.  uLisp already works on __ESP32__ [(See this)](https://github.com/technoblogy/ulisp-esp)

    Since BL602 is a WiFi + Bluetooth LE SoC like ESP32, it might be easy to port the ESP32 version of uLisp to BL602. Including the WiFi functions.

_I'm new to Lisp... Too many brackets, no?_

In a while we'll talk about __Blockly for uLisp__... Drag-and-drop a uLisp program, without typing a single bracket / parenthesis!

(Works just like Scratch, the graphical programming tool)

And we may even upload and run a uLisp program on BL602 through a __Web Browser__... Thanks to the __Web Serial API__!

_Porting uLisp from ESP32 to BL602 sounds difficult?_

Not at all! [uLisp for ESP32](https://github.com/technoblogy/ulisp-esp) lives in a single C source file: [`ulisp-esp.ino`](https://github.com/technoblogy/ulisp-esp/blob/master/ulisp-esp.ino) ...

![uLisp for ESP32](https://lupyuen.github.io/images/lisp-source.jpg)

(With a few Arduino bits in C++)

Porting uLisp to BL602 (as a C library [`ulisp-bl602`](https://github.com/lupyuen/ulisp-bl602)) was quick and easy.

(More about this in a while.)

_What about porting the Arduino functions like `pinmode` and `digitalwrite`?_

The [__BL602 IoT SDK__](https://github.com/lupyuen/bl_iot_sdk/tree/ulisp) doesn't have these GPIO functions. 

So in BL602 uLisp we reimplemented these functions with the __BL602 Hardware Abstraction Layer for GPIO__.

(While exposing the same old names to uLisp programs: `pinmode` and `digitalwrite`)

_Anything else we should know about uLisp?_

uLisp is still [actively maintained](https://github.com/technoblogy?tab=repositories). It has an [active online community](http://forum.ulisp.com/).

# Build the BL602 uLisp Firmware

Download and build the [uLisp Firmware for BL602](https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp)...

```bash
# Download the ulisp branch of lupyuen's bl_iot_sdk
git clone --recursive --branch ulisp https://github.com/lupyuen/bl_iot_sdk

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

# Build the sdk_app_ulisp firmware
cd bl_iot_sdk/customer_app/sdk_app_ulisp
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_ulisp.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`ulisp`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_ulisp.bin` has been copied to the `blflash` folder.

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

Enter these commands to flash `sdk_app_ulisp.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_ulisp.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_ulisp.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_ulisp.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

# Run the BL602 uLisp Firmware

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

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter uLisp commands

Let's enter some uLisp commands and test the __BL602 uLisp Interpreter__!

__Please Note:__ For each uLisp command line we __insert a space " " after the first bracket "`(`"__.

That's because we programmed the BL602 Command Line to recognise "`(`" as a __Command Keyword__ that will call the uLisp Interpreter.

1.  Enter this to create a __list of numbers__...

    ```text
    ( list 1 2 3 )
    ```

    This returns __`(1 2 3)`__

1.  In Lisp, to __`car`__ a list is to take the __head of the list__...

    ```text
    ( car ( list 1 2 3 ) )
    ```

    This returns __`1`__

    (It's like deshelling a prawn)

1.  And to __`cdr`__ a list is to take the __tail of the list__...

    ```text
    ( cdr ( list 1 2 3 ) )
    ```

    This returns __`(2 3)`__

    [(Everything except the head... like Ebifurai No Shippo)](https://sumikko-gurashi.fandom.com/wiki/Ebifurai_No_Shippo)

![uLisp Interpreter](https://lupyuen.github.io/images/lisp-interpreter.png)

[(Based on the List Commands from uLisp)](http://www.ulisp.com/show?1AC5)

## Flip the LED

Now let's __flip the BL602 LED on and off__!

On PineCone BL602 the Blue LED is connected to __GPIO Pin 11__.

(If you're using a different BL602 board, please change the GPIO Pin Number accordingly)

1.  We configure __GPIO Pin 11 (Blue LED) for output__ (instead of input)...

    ```text
    ( pinmode 11 :output )
    ```

1.  Set __GPIO Pin 11 to High__...

    ```text
    ( digitalwrite 11 :high )
    ```

    The Blue LED switches off.

1.  Set __GPIO Pin 11 to Low__...

    ```text
    ( digitalwrite 11 :low )
    ```

    The Blue LED switches on.

1.  And we __sleep 1,000 milliseconds__ (1 second)...

    ```text
    ( delay 1000 )
    ```

    [__Watch the demo on YouTube__](https://youtu.be/9oLheWjzPcA)

![Flip the LED with uLisp](https://lupyuen.github.io/images/lisp-led.png)

[(Based on the GPIO Commands from uLisp)](http://www.ulisp.com/show?1AEK)

## Blinky Function

Now the show gets exciting: With uLisp we can define __functions and loops__ at the command line... Just like `bash`!

```text
( defun blinky ()             \
  ( pinmode 11 :output )      \
  ( loop                      \
   ( digitalwrite 11 :high )  \
   ( delay 1000 )             \
   ( digitalwrite 11 :low  )  \
   ( delay 1000 )))
```

Here's what it means...

![Blinky Function](https://lupyuen.github.io/images/lisp-blinky.png)

Enter the lines above into the BL602 command line. Note that...

1.  Each line __starts with a bracket "`(`" followed by a space " "__

    (Because "`(`" is a Command Keyword that will select the uLisp Interpreter)

1.  Each line (except the last line) __ends with backslash "`\`"__

    (Because each line is a continuation of the previous line)

1.  Alternatively, we may merge the lines into a single loooong line, remove the backslashes "`\`", and paste the loooong line into the BL602 command line.

We run the `blinky` function like so...

```text
( blinky )
```

And the __LED blinks every second!__ 

(Restart the board to stop it, sorry)

[__Watch the demo on YouTube__](https://youtu.be/TN4OaZNGjOA)

[(Based on the Blinky function from uLisp)](http://www.ulisp.com/show?1AEK)

# Now add Blockly

According to the [Blockly Overview](https://developers.google.com/blockly/guides/overview)...

> Blockly is a library that adds a __visual code editor__ to web and mobile apps. 

> The Blockly editor uses __interlocking, graphical blocks__ to represent code concepts like variables, logical expressions, loops, and more. 

> It allows users to apply programming principles __without having to worry about syntax__ or the intimidation of a blinking cursor on the command line.

In short, Blockly will let us __create uLisp programs through a Web Browser__ (with some customisation)...

![Blockly Web Editor](https://lupyuen.github.io/images/lisp-blockly2.png)

[(Yep it looks a lot like Scratch)](https://scratch.mit.edu/developers)

_Does Blockly require any server-side code?_

Nope, everything is done in __plain old HTML and JavaScript__, without any server-side code. It runs locally on our computer too.

(Which is great for developers)

_So we copy and paste the generated uLisp code from Blockly to BL602?_

Nope we're in 2021, everything can be automated!

See the __Run Button [ ▶ ]__ at top right?

Pressing it will __automatically transfer the uLisp Code from Blockly to BL602__... Thanks to the [__Web Serial API__](https://web.dev/serial/)!

Let's try it now.

# Run the Blockly Web Editor

We shall do two things with Blockly and uLisp on BL602...

1.  __Flip the BL602 LED__ on and off

1.  __Blink the BL602 LED__ every second

Just by dragging-and-dropping in a Web Browser!

## Flip the LED

1.  __Close the BL602 serial connection__ in `screen` / CoolTerm / `putty` / Web Serial Terminal (close the web browser)

1.  __Disconnect BL602__ from our computer, and __reconnect__ it to the USB Port.

1.  Click this link to run the __Blockly Web Editor for uLisp__...

    -  [__`blockly-ulisp` Web Editor__](https://appkaki.github.io/blockly-ulisp/demos/code/)

    (This website contains plain HTML and JavaScript, no server-side code. See [`blockly-ulisp`](https://github.com/AppKaki/blockly-ulisp))

1.  Click __`GPIO`__ in the left bar.

    Drag the __`digital write`__ block to the empty space.

    We should see this...

    ![Blockly Web Editor: Digital Write](https://lupyuen.github.io/images/lisp-edit1.png)

1.  In the __`digital write`__ block, change __`11`__ to the GPIO Pin Number for the LED.

    For PineCone BL602 Blue LED: Set it to __`11`__

1.  Click the __`Lisp`__ tab at the top.

    We should see this __uLisp code generated by Blockly__...

    ![Blockly Web Editor: uLisp code for Digital Write](https://lupyuen.github.io/images/lisp-edit2.png)

1.  Click the __Run Button [ ▶ ]__ at top right.

    When prompted, select the USB port for BL602.

    (It works on macOS, Windows and probably Linux too)

    The __LED switches on!__

1.  In the __`digital write`__ block, change __`LOW`__ to __`HIGH`__

    Click the __Run Button [ ▶ ]__ at top right.

    The __LED switches off!__

    [__Watch the demo on YouTube__](https://youtu.be/RRhzW4j8BtI)

## Blinky

Now we do the __Blinky Program__ the drag-and-drop way with Blockly...

1.  Erase the __`digital write`__ block from the last section

1.  Drag-and-drop this Blockly Program...

    ![Blockly Web Editor: Blinky](https://lupyuen.github.io/images/lisp-edit3.png)

    By snapping these blocks together...

    -   __`forever`__ from __`Loops`__ (left bar)

    -   __`digital write`__ from __`GPIO`__ (left bar)

    -   __`wait`__ from __`Loops`__ (left bar)

    Make sure they fit snugly. (Not floaty)

    [(Stuck? Check the video)](https://youtu.be/LNkmUIv7ZZc)

1.  Set the values for the __`digital write`__ and __`wait`__ blocks as shown above.

    In the __`digital write`__ block, change __`11`__ to the GPIO Pin Number for the LED.

    For PineCone BL602 Blue LED: Set it to __`11`__    

1.  Click the __`Lisp`__ tab at the top.

    We should see this __uLisp code generated by Blockly__...

    ![Blockly Web Editor: uLisp code for Blinky](https://lupyuen.github.io/images/lisp-edit4.png)

1.  Click the __Run Button [ ▶ ]__ at top right.

    The __LED blinks every second!__

    (Restart the board to stop it, sorry)

    [__Watch the demo on YouTube__](https://youtu.be/LNkmUIv7ZZc)

# Web Browser controls BL602 with Web Serial API

_What is this magic that transfers the uLisp code from Web Browser to BL602?_

The Blockly Web Editor calls the [__Web Serial API__](https://web.dev/serial/) to transfer the generated uLisp Script to BL602...

TODO

[`code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js#L641-L738)

We assume that BL602 is running the uLisp Firmware and connected to our computer via USB...

[`sdk_app_ulisp`](https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp)

![](https://lupyuen.github.io/images/lisp-terminal.png)

TODO

![](https://lupyuen.github.io/images/lisp-reboot.jpg)

TODO

![](https://lupyuen.github.io/images/lisp-reboot2.png)

TODO

# Porting uLisp to BL602

TODO

uLisp was ported to BL602 from ESP32 Arduino...

[`ulisp-esp`](https://github.com/technoblogy/ulisp-esp)

This firmware calls the BL602 uLisp Library `components/3rdparty/ulisp-bl602`...

[`ulisp-bl602`](https://github.com/lupyuen/ulisp-bl602)

This firmware works with `blockly-ulisp`, which allows embedded apps to be dragged-and-dropped from Web Browser to BL602...

[`blockly-ulisp`](https://github.com/AppKaki/blockly-ulisp)

![uLisp Blinky](https://lupyuen.github.io/images/lisp-blinky2.png)

# Customise Blockly for uLisp

The following have been added into the existing [`generators`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators) folder to generate Lisp code and to add blocks specific to uLisp...

-   [`generators/lisp.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp.js): Main interface for Lisp Code Generator

-   [`generators/lisp`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp): Lisp Code Generator for various blocks

-   [`generators/lisp/lisp_library.xml`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_library.xml): Blocks XML file used by Block Exporter to generate the custom blocks

The Lisp Code Generator is __incomplete__. The only blocks supported are...

1.  Forever

1.  On Start

1.  Wait

1.  GPIO Digital Write

The Lisp Code Generator is based on Visual Embedded Rust...

https://lupyuen.github.io/articles/advanced-topics-for-visual-embedded-rust-programming

![](https://lupyuen.github.io/images/lisp-blockly.png)

TODO

![](https://lupyuen.github.io/images/lisp-dart.png)

TODO

![](https://lupyuen.github.io/images/lisp-generate.png)

TODO

![](https://lupyuen.github.io/images/lisp-rust.png)

TODO

![](https://lupyuen.github.io/images/lisp-mobile.png)

# Blockly Web Editor for uLisp

Watch the demo on YouTube...


Try it here...

[`blockly-ulisp` Web Editor](https://appkaki.github.io/blockly-ulisp/demos/code/)

The Blockly demo at [`demos/code`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code) has been customised to include the Lisp Code Generator...

-   [`demos/code/index.html`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/index.html): Customised to load the Lisp Code Generator and Lisp Blocks

-   [`demos/code/code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js): Customised to load the Lisp Code Generator and Lisp Blocks

Inspired by MakeCode for BBC micro:bit...

[`MakeCode`](https://makecode.microbit.org/)

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
