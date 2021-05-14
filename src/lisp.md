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

_It's 2021... Why are we still learning Lisp?_

Lisp is __Not Dead Yet__! (Apologies to Monty Python)

We still see bits of Lisp today in __WebAssembly__... Like the __Stack Machine and S-Expressions__. [(See this)](https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format)

In fact the uLisp Interpreter looks a little like __Wasm3__, the WebAssembly Interpreter for Microcontrollers. [(See this)](https://github.com/wasm3/wasm3)

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

_What is this magic that teleports the uLisp code from Web Browser to BL602?_

The Blockly Web Editor calls the [__Web Serial API__](https://web.dev/serial/) (in JavaScript) to transfer the generated uLisp code to BL602 (via the USB Serial Port).

Web Serial API is supported on the newer web browsers. To check whether our web browser supports the Web Serial API, click this link...

-   [__Web Serial Terminal__](https://googlechromelabs.github.io/serial-terminal/)

We should be able to connect to BL602 via the USB Serial Port...

![Web Serial Terminal](https://lupyuen.github.io/images/lisp-terminal.png)

(Remember to set the __`Baud Rate`__ to __`Custom`__ with value __`2000000`__)

_So the Web Serial API lets us send commands to BL602?_

Yep it does! Here we send the __`reboot`__ command to BL602 via a Web Browser with the Web Serial API...

![Reboot with Web Serial API](https://lupyuen.github.io/images/lisp-reboot.jpg)

But there were two interesting challenges...

1.  __When do we stop?__

    Our JavaScript code might get stuck __waiting forever for a response__ from the BL602 command.

    For the `reboot` command we tweaked our JavaScript code to __stop when it detects the special keywords__...

    ```text
    Init CLI
    ```

    (Which means that BL602 has finished rebooting)

1.  __How do we clean up?__

    We use __Async Streams__ to transmit and receive BL602 serial data.

    Async Streams don't close immediately... We need to __`await` for them to close__.

    (Or our serial port will be locked from further access)

The proper way to send a `reboot` command to BL602 looks like this...

![Fixed reboot with Web Serial API](https://lupyuen.github.io/images/lisp-reboot2.png)

Let's look at the fixed code in Blockly (our bespoke version) that __sends uLisp Commands to BL602__.

## Sending a command to BL602

For convenience, we wrap the Web Serial API in a high-level JavaScript Async Function: __`runWebSerialCommand`__

Here's how we call `runWebSerialCommand` to send the __`reboot` Command__ to BL602 and wait for the response __"`Init CLI`"__...

```javascript
//  Send the reboot command
await runWebSerialCommand(
  "reboot",   //  Command
  "Init CLI"  //  Expected Response
);
```

(This also sends Enter / Carriage Return after the `reboot` Command)

We don't actually send the `reboot` Command in Blockly (because it's too disruptive).

Instead we send to BL602 an __Empty Command__ like so: [`code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js#L644-L673)

```javascript
//  Send an empty command and 
//  check that BL602 responds with "#"
await runWebSerialCommand(
  "",  //  Command
  "#"  //  Expected Response
);
```

This is equivalent to __hitting the Enter key__ and checking whether BL602 __responds with the Command Prompt "`#`"__

We do this __before sending each command to BL602__. (Just to be sure that BL602 is responsive)

Now to send an actual command like "`( pinmode 11 :output )`", we do this...

```javascript
//  Send the actual command but 
//  don't wait for response
await runWebSerialCommand(
  command,  //  Command
  null      //  Don't wait for response
);
```

__We don't wait for the response__ from BL602, because some uLisp commands don't return a response (`loop`) or they return a delayed response (`delay`).

That's why we send the Empty Command before the next command, to __check whether the previous command has completed.__

(In future we should make this more robust by adding a timeout)

## Calling the Web Serial API

Let's look inside the __`runWebSerialCommand`__ function and learn how it sends commands from Web Browser to BL602 via the Web Serial API.

__`runWebSerialCommand`__ accepts 2 parameters...

- __`command`__: The command that will be sent to from the Web Browser to BL602, like...

  ```text
  ( pinmode 11 :output )
  ```

  The function sends a Carriage Return after the command.

- __`expectedResponse`__: The expected response from BL602, like "`#`".

  The function will __wait for the expected response__ to be received from BL602 before returning.

  If the expected response is null, the function __returns without waiting__.

We start by checking whether the Web Serial API is supported by the web browser: [`code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js#L675-L738)

```javascript
//  Web Serial Port
var serialPort;

//  Run a command on BL602 via Web Serial API and wait for the expectedResponse (if not null)
//  Based on https://web.dev/serial/
async function runWebSerialCommand(command, expectedResponse) {
  //  Check if Web Serial API is supported
  if (!("serial" in navigator)) { alert("Web Serial API is not supported"); return; }
```

Next we prompt the user to __select the Serial Port__, and we remember the selection...

```javascript
  //  Prompt user to select any serial port
  if (!serialPort) { serialPort = await navigator.serial.requestPort(); }
  if (!serialPort) { return; }
```

We __open the Serial Port at 2 Mbps__, which is the standard Baud Rate for BL602 Firmware...

```javascript
  //  Wait for the serial port to open at 2 Mbps
  await serialPort.open({ baudRate: 2000000 });
```

In a while we shall set these to __defer the closing of the Read / Write Streams__ for the Serial Port...

```javascript
  //  Capture the events for closing the read and write streams
  var writableStreamClosed = null;
  var readableStreamClosed = null;
```

Now we're ready to send the Command String to the Serial Port...

1.  We __create a [TextEncoderStream](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoderStream)__ that will convert our Command String into UTF-8 Bytes

1.  We __pipe the `TextEncoderStream` to Serial Port Output__

1.  We __fetch the `writableStreamClosed` Promise__ that we'll call to close the Serial Port

1.  We __get the `writer` Stream__ for writing our Command String to the Serial Port Output

```javascript
  //  Send command to BL602
  {
    //  Open a write stream
    console.log("Writing to BL602: " + command + "...");
    const textEncoder = new TextEncoderStream();
    writableStreamClosed = textEncoder.readable.pipeTo(serialPort.writable);
    const writer = textEncoder.writable.getWriter();
```

We __write the Command String to the `writer` Stream__ (including the Carriage Return)...

```javascript
    //  Write the command
    await writer.write(command + "\r"); 

    //  Close the write stream
    writer.close();
  }
```

And we __close the `writer` Stream__ (Serial Port Output).

If we're expected to wait for the response from the Serial Port...

1.  We __create a [TextDecoderStream](https://developer.mozilla.org/en-US/docs/Web/API/TextDecoderStream)__ that will convert the Serial Port input from UTF-8 Bytes into Text Strings

1.  We __pipe the Serial Port Input to `TextDecoderStream`__

1.  We __fetch the `readableStreamClosed` Promise__ that we'll call to close the Serial Port

1.  We __get the `reader` Stream__ for reading response strings from the Serial Port Input

```javascript
  //  Read response from BL602
  if (expectedResponse) {
    //  Open a read stream
    console.log("Reading from BL602...");
    const textDecoder = new TextDecoderStream();
    readableStreamClosed = serialPort.readable.pipeTo(textDecoder.writable);
    const reader = textDecoder.readable.getReader();
```

We loop forever __reading strings from the `reader` Stream__ (Serial Port Input)...

```javascript    
    //  Listen to data coming from the serial device
    while (true) {
      const { value, done } = await reader.read();
      if (!done) { console.log(value); }
```

Until __we find the expected response__...

```javascript
      //  If the stream has ended, or the data contains expected response, we stop
      if (done || value.indexOf(expectedResponse) >= 0) { break; }
    }
```

And we __close the `reader` Stream__ (Serial Port Input)...

```javascript
    //  Close the read stream
    reader.cancel();
  }
```

Here's the catch (literally)... Our __`reader` and `writer` Streams are not actually closed yet!__

We need to __wait for the `reader` and `writer` Streams to close__...

```javascript
  //  Wait for read and write streams to be closed
  if (readableStreamClosed) { await readableStreamClosed.catch(() => { /* Ignore the error */ }); }
  if (writableStreamClosed) { await writableStreamClosed; }
```

Finally it's safe to __close the Serial Port__...

```javascript
  //  Close the port
  await serialPort.close();
  console.log("runWebSerial: OK");
}
```

And that's how Blockly sends a uLisp command to BL602 with the Web Serial API!

![uLisp Blinky](https://lupyuen.github.io/images/lisp-blinky2.png)

# Porting uLisp to BL602

Today we've seen uLisp on BL602, ported from the [ESP32 Arduino version of uLisp](https://github.com/technoblogy/ulisp-esp/blob/master/ulisp-esp.ino).

_Porting uLisp from ESP32 Arduino to BL602 sounds difficult?_

Not at all!

(Wait... We've said this before)

1.  __No Heap Memory, just Static Memory__

    uLisp needs only Static Memory, no Heap Memory. 
    
    This makes uLisp highly portable across microcontrollers: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L193-L194)

    ```c
    #define WORKSPACESIZE     8000  //  Cells (8*bytes)
    #define SYMBOLTABLESIZE   1024  //  Bytes

    object Workspace[WORKSPACESIZE];
    char SymbolTable[SYMBOLTABLESIZE];
    ```

1.  __Reading from BL602 Flash Memory is simpler__

    On Arduino we access Flash Memory by calling `PSTR`. 
    
    That's not necessary on BL602, so we stub out the Flash Memory functions: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L9-L11)

    ```c
    #define PGM_P     const char *
    #define PROGMEM
    #define PSTR(s)   s
    ```

1.  __`printf` works on BL602__

    No more `Serial.write`. (Nice!)

1.  __Compiles in C, no C++ needed__

    Because the Arduino C++ bits (like `Serial.write`) have been converted to C (like `printf`).

1.  __GPIO Functions__

    This GPIO code from the ESP32 Arduino version of uLisp: [`ulisp-esp.ino`](https://github.com/technoblogy/ulisp-esp/blob/master/ulisp-esp.ino#L3415-L3425)

    ```c
    /// Set the GPIO Output to High or Low
    object *fn_digitalwrite (object *args, object *env) {
        //  Omitted: Parse the GPIO pin number and High / Low
        ...

        //  Set the GPIO output (from Arduino)
        digitalWrite(pin, mode);
    ```

    Was ported to BL602 by calling the __BL602 GPIO Hardware Abstraction Layer__: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L3536-L3554)

    ```c
    /// Set the GPIO Output to High or Low
    object *fn_digitalwrite (object *args, object *env) {
        //  Omitted: Parse the GPIO pin number and High / Low
        //  (Same as before)
        ...

        //  Set the GPIO output (from BL602 GPIO HAL)
        int rc = bl_gpio_output_set(
            pin,  //  GPIO pin number
            mode  //  0 for low, 1 for high
        );
        assert(rc == 0);  //  Halt on error
    ```

    [(More about BL602 GPIO HAL)](https://lupyuen.github.io/articles/led#how-it-works-bl602-gpio)

1.  __Delay Function__

    BL602 runs on a __multitasking operating system (FreeRTOS)__.

    Thus we need to be respectful of other Background Tasks that may be running.

    Here's how we implement the __uLisp `delay` function__ on BL602: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L3593-L3605)

    ```c
    /// Delay for specified number of milliseconds
    object *fn_delay (object *args, object *env) {
        (void) env;
        object *arg1 = first(args);

        //  Convert milliseconds to ticks
        int millisec   = checkinteger(DELAY, arg1);
        uint32_t ticks = time_ms_to_ticks32(millisec);

        //  Sleep for the number of ticks
        time_delay(ticks);
        return arg1;
    }
    ```

    __`time_ms_to_ticks32` and `time_delay`__ are multitasking functions provided by the __NimBLE Porting Layer__, implemented with FreeRTOS.

    [(More about NimBLE Porting Layer)](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

1.  __Loop and Yield__

    The BL602 implementation of the __uLisp `loop` function__ is aware of multitasking too.

    We preempt the current task at every iteration of the loop: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L1691-L1705)

    ```c
    /// "loop" implementation in uLisp
    object *sp_loop (object *args, object *env) {
        object *start = args;
        for (;;) {
            //  Sleep 100 ticks in each iteration
            time_delay(100);  //  TODO: Tune this
    ```

    (This is probably no good for time-sensitive uLisp functions... We will have to rethink this)

1.  __BL602 cares about the Command Line__

    On Arduino we read and parse the Serial Input, byte by byte.

    Whereas on BL602, the __BL602 IoT SDK parses the Command Line__ for us.

    Here's how we __define "`(`" as a Command Keyword__ in BL602: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/ulisp/customer_app/sdk_app_ulisp/sdk_app_ulisp/demo.c#L45-L48)

    ```c
    /// List of commands. STATIC_CLI_CMD_ATTRIBUTE makes this(these) command(s) static
    const static struct cli_command cmds_user[] STATIC_CLI_CMD_ATTRIBUTE = {
        {
            "(",
            "Run the uLisp command",
            run_ulisp
        },
    };          
    ```

    When we enter a command like __"`( delay 1000 )`"__, the command-line interface calls our function `run_ulisp` defined in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/ulisp/customer_app/sdk_app_ulisp/sdk_app_ulisp/demo.c#L9-L40)

    ```c
    /// Command-Line Buffer that will be passed to uLisp
    static char cmd_buf[1024] = { 0 };

    /// Run a uLisp command
    void run_ulisp(char *buf, int len, int argc, char **argv) {
        //  If the last command line arg is `\`, we expect a continuation
        bool to_continue = false;
        if (strcmp(argv[argc - 1], "\\") == 0) {
            to_continue = true;
            argc--;   //  Skip the `\`
        }

        //  Concatenate the command line, separated by spaces
        for (int i = 0; i < argc; i++) {
            assert(argv[i] != NULL);
            strncat(cmd_buf, argv[i], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
            strncat(cmd_buf, " ",     sizeof(cmd_buf) - strlen(cmd_buf) - 1);
        }
        cmd_buf[sizeof(cmd_buf) - 1] = 0;

        //  If this the end of the command line...
        if (!to_continue) {
            //  Execute the command line
            execute_ulisp(cmd_buf);

            //  Erase the buffer
            cmd_buf[0] = 0;
        }
    }
    ```

    The command-line interface splits the command line into multiple arguments (delimited by space), so we need to __merge the arguments back into a single command line__.

    (Yeah, not so efficient)

    We support __continuation of command lines__ when the command line ends with __"`\`"__

    We pass the merged command line to __`execute_ulisp`__ defined in [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L5363-L5370)

    ```c
    /// Console input buffer, position and length
    const char *input_buf = NULL;
    int input_pos = 0;
    int input_len = 0;

    /// Execute the command line
    void execute_ulisp(const char *line) {
        //  Set the console input buffer
        input_buf = line;
        input_pos = 0;
        input_len = strlen(line);

        //  Start the uLisp Interpreter
        loop_ulisp();
    }
    ```

    Here we __save the merged command line into a buffer__ and start the uLisp Interpreter.

    Lastly we modified the __`gserial`__ function in uLisp to read the command line from the buffer (instead of Serial Input): [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/master/src/ulisp.c#L5085-L5124)

    ```c
    /// Return the next char from the console input buffer
    int gserial() {
        if (LastChar) {
            //  Return the previous char
            char temp = LastChar;
            LastChar = 0;
            return temp;
        }  
        if (input_pos >= input_len) {
            //  No more chars to read
            return '\n';
        }
        //  Return next char from the buffer
        return input_buf[input_pos++];
    }
    ```

![Porting uLisp to BL602](https://lupyuen.github.io/images/lisp-build.png)

## Missing uLisp Features

_What else needs to be ported to BL602?_

If the __Community could help__ to port the __missing uLisp Features__... That would be super awesome! 🙏 👍

TODO

setjmp

EEPROM

![uLisp builds OK on BL602](https://lupyuen.github.io/images/lisp-build2.png)

# Customise Blockly for uLisp

_How did we customise Blockly for uLisp and BL602?_

1.  We added __Custom Blocks__ like `forever`, `digital write` and `wait`

    All blocks under __GPIO, I2C and SPI__ are Custom Blocks. (See pic below)

1.  We created a __Code Generator__ that generates uLisp code.

    (More about this in the next section)

1.  We integrated Blockly with __Web Serial API__ to transfer the generated uLisp code to BL602

    (The Web Serial API code we saw earlier)

![Blockly Web Editor](https://lupyuen.github.io/images/lisp-blockly2.png)

_Which Blockly source files were modified?_

We modified these Blockly source files to load the Custom Blocks and generate uLisp code...

-   [`demos/code/index.html`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/index.html) 

    This is the __HTML source file__ for the Blockly Web Editor. (See pic above)

    [(See changes)](https://github.com/AppKaki/blockly-ulisp/pull/1/files#diff-dcf2ffe98d7d8b4a0dd7b9f769557dbe8c9e0e726236ef229def25c956a43d8f)

-   [`demos/code/code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js)

    This is the main __JavaScript source file__ for the Blockly Web Editor.

    This file contains the JavaScript function `runWebSerialCommand` that transfers the generated uLisp code to BL602 via Web Serial API.

    [(See changes)](https://github.com/AppKaki/blockly-ulisp/pull/1/files#diff-d72873b861dee958e5d443c919726dd856de594bd56b1e73d8948a7719163553)

-   [`core/workspace_svg.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/core/workspace_svg.js)

    This JavaScript file __renders the Blockly Workspace as SVG__, including the Toolbox Bar at left.

    [(See changes)](https://github.com/AppKaki/blockly-ulisp/pull/1/files#diff-068435ae2521855e9cdbfdf36bea7f06978c9401acede52042702667bb14d49c)

_How did we create the Custom Blocks?_

We used the __Block Exporter__ from Blockly to create the Custom Blocks...

-   [`generators/lisp/ lisp_library.xml`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_library.xml): XML for Custom Blocks

With Block Explorer and the Custom Blocks XML file, we generated this JavaScript file containing our Custom Blocks...

-   [`generators/lisp/ lisp_blocks.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_blocks.js): JavaScript for Custom Blocks

Block Exporter and Custom Blocks are explained here...

-   [__"Custom Blocks"__](https://developers.google.com/blockly/guides/create-custom-blocks/overview)

-   [__"Blockly Developer Tools"__](https://developers.google.com/blockly/guides/create-custom-blocks/blockly-developer-tools)

-   [__"Define Blocks"__](https://developers.google.com/blockly/guides/create-custom-blocks/define-blocks)

_Does Blockly work on Mobile Web Browsers?_

Yes but the Web Serial API won't work for transferring the generated uLisp code to BL602. (Because we can't connect BL602 as a USB Serial device)

In future we could use the [__Web Bluetooth API__](https://web.dev/bluetooth/) instead to transfer the uLisp code to BL602. (Since BL602 supports Bluetooth LE)

Here's how it looks on a Mobile Web Browser...

![Blockly on Mobile](https://lupyuen.github.io/images/lisp-mobile.png)

_What were we thinking when we designed the Custom Blocks: `forever`, `on_start`, `digital write`, `wait`, ..._

The custom blocks were inspired by __MakeCode for BBC micro:bit__...

-   [__MakeCode__](https://makecode.microbit.org/)

![uLisp Code Generator](https://lupyuen.github.io/images/lisp-generate.png)

# Code Generator for uLisp

_How did we generate uLisp code in Blockly?_

We created __Code Generators__ for uLisp. Our Code Generators are JavaScript Functions that emit uLisp code for each type of Block...

-   [__"Generating Code"__](https://developers.google.com/blockly/guides/create-custom-blocks/generating-code)

We started by __copying the Code Generators__ from Dart to Lisp into this Blockly folder...

-   [__`generators/lisp`__](https://github.com/AppKaki/blockly-ulisp/tree/master/generators/lisp): Code Generators for uLisp

![Copy code generators from Dart to Lisp](https://lupyuen.github.io/images/lisp-dart.png)

Then we added this __Code Generator Interface__ for uLisp...

-   [`generators/lisp.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp.js): Interface for uLisp Code Generator

_Which Blocks are supported by the uLisp Code Generator?_

The uLisp Code Generator is __incomplete__.

The only Blocks supported are...

1.  __`forever`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L40-L49)

1.  __`on_start`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/app_code.js#L3-L12)

1.  __`wait`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L51-L58)

1.  __`digital write`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L79-L89)

_How do we define a uLisp Code Generator?_

Here's how we define the __`forever` Code Generator__: [`lisp_functions.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L40-L49)

```c
//  Emit uLisp code for the "forever" block. 
//  Inspired by MakeCode "forever" and Arduino "loop".
Blockly.Lisp['forever'] = function(block) {
  //  Convert the code inside the "forever" block into uLisp
  var statements_stmts = Blockly.Lisp.statementToCode(block, 'STMTS');
  var code = statements_stmts;

  //  Wrap the converted uLisp code with "loop"
  code = [
    '( loop  ',
    code + ')',
  ].join('\n');

  //  Return the wrapped code
  return code;
};
```

This JavaScript function emits a __uLisp loop__ that wraps the code inside the `forever` block like so...

```text
( loop
    ...Code inside the loop block...
)
```

And here's the __`digital write` Code Generator__: [`lisp_functions.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L79-L89)

```c
//  Emit uLisp code for the "digtial write" block. 
Blockly.Lisp['digital_write_pin'] = function(block) {
  //  Fetch the GPIO Pin Number (e.g. 11)
  var dropdown_pin = block.getFieldValue('PIN');

  //  Fetch the GPIO Output: ":high" or "low"
  var dropdown_value = block.getFieldValue('VALUE');

  //  Compose the uLisp code to set the GPIO Pin mode and output.
  //  TODO: Call init_out only once,
  var code = [
    '( pinmode ' + dropdown_pin + ' :output )',
    '( digitalwrite ' + dropdown_pin + ' ' + dropdown_value + ' )',
    ''
  ].join('\n');  

  //  Return the uLisp code
  return code;
};
```

This JavaScript function emits uLisp code that __sets the GPIO Pin mode and output__ like so...

```text
( pinmode 11 :output )
( digitalwrite 11 :high )
```

## Missing Code Generators

_What about the missing uLisp Code Generators?_

If the __Community could help__ to fill in the __missing uLisp Code Generators__... That would be incredibly awesome! 🙏 👍 😀

1.  __Expressions__

    This [__Expression Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/math.js#L18-L485) should emit this uLisp Code...

    ```text
    ( / ( - 7 1 ) ( - 4 2 ) )
    ```

    [(From uLisp)](http://www.ulisp.com/show?1ACY)

1.  __Strings__

    This [__String Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/text.js#L18-L343) should emit this uLisp Code...

    ```text
    "This is a string"
    ```

    [(From uLisp)](http://www.ulisp.com/show?1LRV)

1.  __Lists__

    This [__List Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lists.js#L18-L447) should emit this uLisp Code...
    
    ```text
    ( first '( 1 2 3 ) )
    ```

    [(From uLisp)](http://www.ulisp.com/show?1AHT)

1.  __If__

    This [__If Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/logic.js#L18-L127) should emit this uLisp Code...    

    ```text
    ( if ( < ( analogread 0 ) 512 )
        ( digitalwrite 2 t )
        ( digitalwrite 3 t )
    )
    ```

    [(From uLisp)](http://www.ulisp.com/show?1AJM)

1.  __For Loops__

    This [__For Loop Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/loops.js#L62-L169) should emit this uLisp Code...    

    ```text
    ( dotimes ( pin 3 )
        ( digitalwrite pin :high ) 
    )
    ```

    [(From uLisp)](http://www.ulisp.com/show?2I01)

1.  __While Loops__

    This [__While Loop Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/loops.js#L18-L60) should emit this uLisp Code...    

    ```text
    ( loop
        ( unless ( digitalread 8 ) ( return ) )
    )
    ```

    [(From uLisp)](http://www.ulisp.com/show?2I01)

1.  __Variables__

    This [__Variable Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/variables.js#L18-L32) should emit this uLisp Code...   

    ```text
    ( defvar led 11 )

    ( setq led 11 )

    ( let* (
        ( led 11 )
        ...
        )
        body
    )
    ```

    [(From uLisp)](http://www.ulisp.com/show?1AEK)

1.  __Functions__

    This [__Function Code Generator__](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/procedures.js#L18-L111) should emit this uLisp Code...   

    ```text
    ( defun function_name ( ... ) ( ... ) )
    ```

    [(From uLisp)](http://www.ulisp.com/show?1AGL)

1.  __GPIO__

    The Code Generators for __[`digital read`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L71-L77)__ and __[`digital toggle`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L60-L69)__ should emit uLisp Code for...    

    -   [__`pinmode`__](http://www.ulisp.com/show?3L#pinmode)

    -   [__`digitalread`__](http://www.ulisp.com/show?3L#digitalread)

    -   [__`digitalwrite`__](http://www.ulisp.com/show?3L#digitalwrite)
    
1.  __I2C, SPI, ADC, DAC__

    We need to create __Custom Blocks and Code Generators for I2C, SPI, ADC and DAC__ that will emit uLisp Code for...

    -   [__`withi2c`__](http://www.ulisp.com/show?3L#withi2c)

    -   [__`restarti2c`__](http://www.ulisp.com/show?3L#restarti2c)

    -   [__`withspi`__](http://www.ulisp.com/show?3L#withspi)

    -   [__`analogread`__](http://www.ulisp.com/show?3L#analogread)

    -   [__`analogreference`__](http://www.ulisp.com/show?3L#analogreference)

    -   [__`analogreadresolution`__](http://www.ulisp.com/show?3L#analogreadresolution)

    -   [__`analogwrite`__](http://www.ulisp.com/show?3L#analogwrite)

1.  __WiFi__

    We need to create __WiFi Custom Blocks and Code Generators__ that will emit uLisp Code for...

    -   [__`available`__](http://www.ulisp.com/show?2B27#available)

    -   [__`connected`__](http://www.ulisp.com/show?2B27#connected)

    -   [__`wifilocalip`__](http://www.ulisp.com/show?2B27#wifilocalip)

    -   [__`wificonnect`__](http://www.ulisp.com/show?2B27#wificonnect)

    -   [__`wifiserver`__](http://www.ulisp.com/show?2B27#wifiserver)

    -   [__`wifisoftap`__](http://www.ulisp.com/show?2B27#wifisoftap)

    -   [__`withclient`__](http://www.ulisp.com/show?2B27#withclient)

1.  __Storage__

    Blockly __doesn't save our program__... Refresh the Web Browser and our program disappears.

    We could enhance Blockly to __save our program locally with JavaScript Local Storage__...

    -   [__`appengine/storage.js`__](https://github.com/AppKaki/blockly-ulisp/blob/master/appengine/storage.js)

    This script is not used in our version of Blockly. But it's referenced by our HTML code here: [`index.html`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/index.html#L11)

1.  __Copy and paste the XML Code__

    But in the meantime, we can manually save and restore the program by copying and pasting the contents of the __`XML`__ tab in Blockly.

_You sound strangely familiar with Blockly Code Generators?_

Yes the uLisp Code Generator is based on my earlier project on __Visual Embedded Rust__...

-   [__"Advanced Topics for Visual Embedded Rust"__](https://lupyuen.github.io/articles/advanced-topics-for-visual-embedded-rust-programming)

Generating Rust code in Blockly was highly challenging because we had to do __Type Inference with Procedural Macros__.

__uLisp is not Statically Typed__ like Rust, so generating uLisp code in Blockly looks a lot simpler.

(Blockly for Visual Embedded Rust is wrapped inside a [VSCode Extension](https://marketplace.visualstudio.com/items?itemName=LeeLupYuen.visual-embedded-rust) that allows __local, offline development__. We could do the same for Blockly and uLisp)

![Visual Embedded Rust](https://lupyuen.github.io/images/lisp-rust.png)

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
