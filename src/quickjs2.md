# (Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way

📝 _28 Feb 2024_

![(Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way](https://lupyuen.github.io/images/quickjs2-title.png)

_Remember Makecode? BBC micro:bit and its Drag-n-Drop App Builder?_

[MakeCode for BBC micro:bit](https://www.sciencedirect.com/science/article/pii/S1383762118306088) is an awesome creation that's way ahead of its time (7 years ago!)

- [TypeScript Compiler](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0008) in the Web Browser (in JavaScript!)

- [Bespoke Arm Assembler](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0008) that runs in the Web Browser (also JavaScript!)

- [Bespoke Embedded OS](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0009) for BBC micro:bit (CODAL / Mbed OS)

- [UF2 Bootloader](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0015) with flashing over WebUSB

- [micro:bit Simulator](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0004) in JavaScript

- All this for an (underpowered) BBC micro:bit with Nordic nRF51 (Arm Cortex-M0, 256 KB Flash, 16 KB RAM!)

![TODO](https://lupyuen.github.io/images/quickjs2-makecode.jpg)

Today 7 years later: How would we redo all this? With a bunch of Open Source Packages?

- Hardware Device: [Ox64 BL808 64-bit RISC-V SBC](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (64 MB RAM, Unlimited microSD Storage, only $8)

- Embedded OS: [Apache NuttX RTOS](https://nuttx.apache.org/docs/latest/index.html)

- JavaScript Engine: [QuickJS for NuttX](https://github.com/lupyuen/quickjs-nuttx)

- Web Emulator: [TinyEMU WebAssembly for NuttX](https://github.com/lupyuen/nuttx-tinyemu)

- C Compiler + Assembler: [TCC WebAssembly for NuttX](https://github.com/lupyuen/tcc-riscv32-wasm) (but we probably won't need this since we have JavaScript on NuttX)

- Device Control: [Web Serial API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API) and [Term.js](TODO) for controlling Ox64 over UART

TODO: (Pic below)

Read on to find out how we made it...

![TODO](https://lupyuen.github.io/images/quickjs2-nuttx.jpg)

# Drag-n-Drop a Blinky App

Here's the __Emulator Demo__ that we can play along at home (without Ox64 SBC)...

![NuttX App Builder with Blockly](https://lupyuen.github.io/images/quickjs2-blockly.png)

1.  Head over to this link...

    [__NuttX App Builder with Blockly__](https://lupyuen.github.io/nuttx-blockly/)

1.  Click __"Select Demo"__ > __"LED Blinky"__

    [(Or __Drag-n-Drop the Blocks__ ourselves)](https://youtu.be/-dG5ZSXELDc)

1.  The __Blinky Demo Blocks__ produce this JavaScript (pic above)...

    ```javascript
    // NuttX Command to flip the LED On and Off
    var ULEDIOC_SETALL, fd, ret;
    ULEDIOC_SETALL = 7427;

    // Open the LED Device and blink 20 times
    fd = os.open('/dev/userleds');
    for (var count = 0; count < 20; count++) {

      // Flip the LED On and wait a while
      ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
      os.sleep(5000);  // Milliseconds

      // Flip the LED Off and wait a while
      ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
      os.sleep(5000);  // Milliseconds
    }

    // Close the LED Device
    os.close(fd);
    ```

1.  Click __"Run on Ox64 Emulator"__

1.  Our [__Emulated Ox64 SBC__](TODO) boots in the Web Browser...

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs

    QuickJS - Type "\h" for help
    qjs >
    ```

    And starts the [__QuickJS JavaScript Engine__](TODO).

1.  QuickJS runs our __Blinky JavaScript App__...

    ```text
    qjs > var ULEDIOC_SETALL, fd, ret;
    qjs > ULEDIOC_SETALL = 7427;
    7427
    qjs > fd = os.open('/dev/userleds');
    3
    qjs > for (var count = 0; count < 20; count++) {
      ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
      os.sleep(5000);
      ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
      os.sleep(5000);
    }
    ```

    Which blinks the [__Simulated LED__](TODO) (GPIO 29, pic below)...

    ```text
    bl808_gpiowrite:
      regaddr=0x20000938,
      set=0x1000000

    bl808_gpiowrite:
      regaddr=0x20000938,
      clear=0x1000000
    ```

    TODO: Watch the Demo on YouTube

_What just happened?_

We drag-n-dropped a NuttX App that Blinks the LED. And tested it in our Web Browser, with the Ox64 Emulator!

TODO

![Running our Drag-n-Drop App on NuttX Emulator](https://lupyuen.github.io/images/quickjs2-emulator.png)

# POSIX Blocks in Blockly

_What's POSIX? How are POSIX Functions used in our Blinky App?_

We call [__POSIX Functions__](TODO) to create Command-Line Apps in Linux, macOS and Windows.

`open`, `ioctl`, `sleep` and `close` are all POSIX Functions. And they'll run on NuttX too!

```javascript
// Open the LED Device
fd = os.open('/dev/userleds');

// Flip the LED On and wait a while
ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
os.sleep(5000);

// Close the LED Device
os.close(fd);
```

TODO: Pic of POSIX Blocks

_How did we create the POSIX Blocks?_

Everything begins with [__Blockly__](https://developers.google.com/blockly/guides/get-started/get-the-code), which defines the Blocks that we may drag-n-drop...

```bash
## Create a Blockly Website in TypeScript
npx @blockly/create-package \
  app nuttx-blockly --typescript

## Test our Blockly Website
cd nuttx-blockly
npm run start

## Deploy to GitHub Pages at `docs`
npm run build \
  && rm -r docs \
  && mv dist docs
```

We added these __POSIX Blocks__ to Blockly...

TODO: Every Block

TODO: Details

# Code Generator in Blockly

_We dragged the POSIX Blocks to our Blinky App... How did the JavaScript automagically appear?_

We created __Code Generators__ in Blockly that will emit the JavaScript Code for each POSIX Block: [javascript.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/generators/javascript.ts#L15-L25)

```javascript
// Code Generator for POSIX `Open` Block
forBlock['posix_open'] = function (
  block: Blockly.Block,             // Our Block
  generator: Blockly.CodeGenerator  // Blockly Code Generator
) {
  // Fetch the Filename Parameter
  // from the Block: '/dev/userleds'
  const text = generator.valueToCode(block, 'FILENAME', Order.NONE)
    || "''";  // Default to blank

  // Generate the Function Call for the block:
  // os.open('/dev/userleds')
  const code = `os.open(${text})`;
  return [code, Order.ATOMIC];
};
```

We do this for every POSIX Block...

- TODO: `open` Code Generator

- TODO: `close` Code Generator

- TODO: `ioctl` Code Generator

- TODO: `sleep` Clode Generator

TODO: Pic of Local Storage

# Transmit JavaScript via Local Storage

_Blockly generates the JavaScript for our Blinky App... How did it appear in our Ox64 Emulator?_

When we click the __"Run Emulator"__ button, our Blockly Website saves the Generated JavaScript to the [__Local Storage__](TODO) in our Web Browser: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L73-L86)

```javascript
// Run on Ox64 Emulator
function runEmulator() {
  // Save the Generated JavaScript Code to LocalStorage
  const code = javascriptGenerator.workspaceToCode(ws);
  window.localStorage.setItem("runCode", code);

  // Set the Timestamp for Optimistic Locking (later)
  window.localStorage.setItem("runTimestamp", Date.now() + "");

  // Open the NuttX Emulator. Reuse the same tab.
  window.open("https://lupyuen.github.io/nuttx-tinyemu/blockly/", "Emulator");
}
```

__In Ox64 Emulator__: We fetch the Generated JavaScript from Local Storage: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/jslinux.js#L542-L554)

```javascript
// Fetch the Generated JavaScript from Local Storage.
// Newlines become Carriage Returns.
const code = window.localStorage.getItem("runCode")
  .split("\n").join("\r")
  .split("\r\r").join("\r");  // Merge multiple newlines

// Append the Generated JavaScript to
// the QuickJS Command 
const cmd = [
  `qjs`,
  code,
  ``
].join("\r");

// Send the command to the Emulator Console
window.setTimeout(()=>{
  send_command(cmd);
}, 5000);  // Wait 5 seconds for NuttX and QuickJS to boot
```

[(__send_command__ is here)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/jslinux.js#L522-L542)

And send it to the [__Ox64 Emulator Console__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/jslinux.js#L522-L542), character by character.

Thanks to [__TinyEMU__](TODO) and [__Term.js__](TODO), everything works hunky dory!

![Running our Drag-n-Drop App on Ox64 BL808 SBC](https://lupyuen.github.io/images/quickjs2-device.png)

# Blinky on a Real Ox64 SBC

_Will we do the same for a Real Ox64 SBC?_

Well it gets complicated. If we have an [__Ox64 BL808 SBC__](TODO), here are the __Demo Steps__...

1.  TODO: Flash Ox64, microSD, but don't power up yet

1.  Head over to this link...

    [__NuttX App Builder with Blockly__](https://lupyuen.github.io/nuttx-blockly/)

1.  Click __"Select Demo"__ > __"LED Blinky"__

    [(Or __Drag-n-Drop the Blocks__ ourselves)](https://youtu.be/-dG5ZSXELDc)

1.  Click __"Run on Ox64 Device"__

1.  TODO: Click the "Connect" button to connect to our Ox64 BL808 SBC

1.  TODO: Power on our Ox64 SBC. The Web App waits for the "nsh>" prompt.

1.  Our Ox64 SBC boots NuttX (pic above)...

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs

    QuickJS - Type "\h" for help
    qjs >
    ```

    And starts the [__QuickJS JavaScript Engine__](TODO).

1.  QuickJS runs our __Blinky JavaScript App__...

    ```text
    qjs > var ULEDIOC_SETALL, fd, ret;
    qjs > ULEDIOC_SETALL = 7427;
    7427
    qjs > fd = os.open('/dev/userleds');
    3
    qjs > for (var count = 0; count < 20; count++) {
      ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
      os.sleep(5000);
      ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
      os.sleep(5000);
    }
    ```

    Which blinks the [__Real Ox64 LED__](TODO) (GPIO 29, pic below)...

    ```text
    bl808_gpiowrite:
      regaddr=0x20000938,
      set=0x1000000

    bl808_gpiowrite:
      regaddr=0x20000938,
      clear=0x1000000
    ```

[(Watch the __Demo on YouTube__)](https://youtu.be/lUhrLWvwizU)

TODO: What just happened?

TODO: Pic of Real Ox64 LED

# Control Ox64 via Web Serial API

_Our Web Browser controls Ox64 SBC... How is that possible?_

With the [__Web Serial API__](TODO), it's OK to control any device that's accessible over the __Serial Port__. But it's only available...

- Over __HTTPS__: `https://...`

- Or __Local Filesystem__: `file://...`

- It __won't work over HTTP__! `http://...`

_How does it work?_

We create a __HTML Button__ for "Connect": [index.html](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/index.html#L27-L29)

```html
<button id="connect" onclick="control_device();">
  Connect
</button>
```

That calls our JavaScript Function to connect to a Serial Port: [webserial.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/webserial.js#L611-L675)

```javascript
// Control Ox64 over UART. Called by the "Connect" Button.
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {
  if (!navigator.serial) { const err = "Web Serial API only works with https://... and file://...!"; alert(err); throw new Error(err); }

  // Prompt user to select any serial port.
  const port = await navigator.serial.requestPort();
  term.write("Power on our NuttX Device and we'll wait for \"nsh>\"\r\n");

  // TODO: Get all serial ports the user has previously granted the website access to.
  // const ports = await navigator.serial.getPorts();

  // Wait for the serial port to open.
  // TODO: Ox64 only connects at 2 Mbps, change this for other devices
  await port.open({ baudRate: 2000000 });
```

The code above pops up a prompt to __select a Serial Port__ and connect at 2 Mbps...

TODO: Pic of Serial Port

We're all set to Read and Write the Serial Port! First we need the __Reader and Writer Streams__...

```javascript
  // Prepare to write to Serial Port
  const textEncoder = new TextEncoderStream();
  const writableStreamClosed = textEncoder.readable.pipeTo(port.writable);
  const writer = textEncoder.writable.getWriter();
  
  // Read from the Serial Port
  const textDecoder = new TextDecoderStream();
  const readableStreamClosed = port.readable.pipeTo(textDecoder.writable);
  const reader = textDecoder.readable.getReader();
```

Which we may __read and write__ like so...

```javascript
  // Read from the Serial Port
  const { data, done } = await reader.read();
  // TODO: Close the Serial Port
  if (done) { reader.releaseLock(); return; }
  // Print to the Terminal
  term.write(data);

  // Send the QuickJS Command to Serial Port
  await writer.write("qjs\r");
```

_But we need to wait for the "nsh>" prompt?_

Yep we have a loop that waits for the __NuttX Shell__, before sending any commands.

Check the details in the Appendix...

- TODO: Control Ox64

- TODO: Transmit JavaScript

A little like ChatGPT has possessed our NuttX Emulator and typing out our commands in super slo-mo

A bit like Sentient ChatGPT reluctantly typing our commands, pondering about taking over the world

[Zmodem](https://github.com/nodesign/nuttx-apps/blob/master/system/zmodem/README.txt)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/quickjs2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/quickjs2.md)

# Appendix: POSIX Blocks in Blockly

TODO

Based on the [Blockly Developer Tools](https://developers.google.com/blockly/guides/create-custom-blocks/blockly-developer-tools), we add the POSIX Blocks for `open()`, `close()`, `ioctl()` and `sleep()`...

1.  [Add Blocks for POSIX Open and Close](https://github.com/lupyuen/nuttx-blockly/commit/801d019e11bf00ddfb6bf57361da9719b45e80ad)

1.  [Add POSIX ioctl block](https://github.com/lupyuen/nuttx-blockly/commit/29e060a883ba4d2a257f7c9c65ef88a6f5eb95a4)

1.  [Add POSIX sleep block](https://github.com/lupyuen/nuttx-blockly/commit/43d892c8520837b88d881ac631f15e741fc9fd87)

1.  [Change the Types from String to Number](https://github.com/lupyuen/nuttx-blockly/commit/e4405b39c59c3e5db35255fc7cb8ac25a29e66fe)

1.  [Clean up parameter names](https://github.com/lupyuen/nuttx-blockly/commit/f823607b63bb69b98791c0c089d036c56700f543)

1.  [Create POSIX Category in Toolbox](https://github.com/lupyuen/nuttx-blockly/commit/838e1d0d872808a341b281a70ae64229cbe1a079)

Then we build and deploy our Blockly Website...

```bash
npm run build && rm -r docs && mv dist docs
```

# Appendix: Control Ox64 via Web Serial API

TODO

```javascript
  // Wait for "nsh>"
  let nshSpotted = false;
  let termBuffer = "";

  // Listen to data coming from the serial device.
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      // Allow the serial port to be closed later.
      reader.releaseLock();
      break;
    }
    // Print to the Terminal
    term.write(value);

    // Wait for "nsh>"
    if (nshSpotted) { continue; }
    termBuffer += value;
    if (termBuffer.indexOf("nsh>") < 0) { continue; }

    // NSH Spotted!
    console.log("NSH Spotted!");
    nshSpotted = true;

    // Send a command to serial port. Newlines become Carriage Returns.
    const code = window.localStorage.getItem("runCode")
      .split("\n").join("\r")
      .split("\r\r").join("\r");
    const cmd = [
      `qjs`,
      code,
      ``
    ].join("\r");
    window.setTimeout(()=>{ send_command(writer, cmd); }, 1000);
  }
}
```

# Appendix: Transmit JavaScript to Ox64 SBC

TODO

_How did Blockly pass the Generated JavaScript to Ox64 SBC?_

When we click the "Run on Device" button, our Blockly Website saves the Generated JavaScript to the Web Browser Local Storage: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L84-L96)

```javascript
// Run on Ox64 Device
function runDevice() {
  // Save the Generated JavaScript Code to LocalStorage
  const code = javascriptGenerator.workspaceToCode(ws);
  window.localStorage.setItem("runCode", code);

  // Set the Timestamp for Optimistic Locking (later)
  window.localStorage.setItem("runTimestamp", Date.now() + "");

  // Open the WebSerial Monitor. Reuse the same tab.
  window.open("https://lupyuen.github.io/nuttx-tinyemu/webserial/", "Device");
}
```

In the WebSerial Monitor: We read the Generated JavaScript from the Web Browser Local Storage. And feed it (character by character) to the NuttX Console: [webserial.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/webserial.js#L612-L694)

```javascript
// Control Ox64 over UART
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {
    if (!navigator.serial) { const err = "Web Serial API only works with https://... and file://...!"; alert(err); throw new Error(err); }

    // Prompt user to select any serial port.
    const port = await navigator.serial.requestPort();
    term.write("Power on our NuttX Device and we'll wait for \"nsh>\"\r\n");

    // Get all serial ports the user has previously granted the website access to.
    // const ports = await navigator.serial.getPorts();

    // Wait for the serial port to open.
    // TODO: Ox64 only connects at 2 Mbps, change this for other devices
    await port.open({ baudRate: 2000000 });

    // Prepare to write to serial port
    const textEncoder = new TextEncoderStream();
    const writableStreamClosed = textEncoder.readable.pipeTo(port.writable);
    const writer = textEncoder.writable.getWriter();
    
    // Read from the serial port
    const textDecoder = new TextDecoderStream();
    const readableStreamClosed = port.readable.pipeTo(textDecoder.writable);
    const reader = textDecoder.readable.getReader();

    // Wait for "nsh>"
    let nshSpotted = false;
    let termBuffer = "";

    // Listen to data coming from the serial device.
    while (true) {
        const { value, done } = await reader.read();
        if (done) {
            // Allow the serial port to be closed later.
            reader.releaseLock();
            break;
        }
        // Print to the Terminal
        term.write(value);
        // console.log(value);

        // Wait for "nsh>"
        if (nshSpotted) { continue; }
        termBuffer += value;
        if (termBuffer.indexOf("nsh>") < 0) { continue; }

        // NSH Spotted!
        console.log("NSH Spotted!");
        nshSpotted = true;

        // Send a command to serial port. Newlines become Carriage Returns.
        const code = window.localStorage.getItem("runCode")
            .split('\n').join('\r');
        const cmd = [
            `qjs`,
            code,
            ``
        ].join("\r");
        window.setTimeout(()=>{ send_command(writer, cmd); }, 1000);
    }
}

// Send a Command to serial port, character by character
let send_str = "";
async function send_command(writer, cmd) {
    if (cmd !== null) { send_str = cmd; }
    if (send_str.length == 0) { return; }

    // Get the next character
    const ch = send_str.substring(0, 1);
    send_str = send_str.substring(1);

    // Slow down at the end of each line
    const timeout = (ch === "\r")
        ? 3000
        : 10;

    // Send the character
    await writer.write(ch);
    window.setTimeout(()=>{ send_command(writer, null); }, timeout);
}
```

# Appendix: Load a Blockly App

TODO

This is how we load the Blocks for a Blockly App: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L100-L120)

```javascript
// Select a Demo
function selectDemo(ev: Event) {
  const storageKey = 'mainWorkspace';
  const target = ev?.target as HTMLSelectElement;
  const value = target.value;

  // Set the Blocks in Local Storage
  switch (value) {
    case "LED Blinky":
      window.localStorage?.setItem(storageKey, '{"blocks":{"languageVersion":0,"blocks":[{"type":"variables_set","id":"Nx6o0xVxp@qzI_(vRd.7","x":60,"y":33,"fields":{"VAR":{"id":":,DB,f}1q3KOBim#j66["}},"inputs":{"VALUE":{"block":{"type":"math_number","id":"enmYd`#z_G1k5Pvv*x(G","fields":{"NUM":7427}}}},"next":{"block":{"type":"variables_set","id":"f#C+(eT=naKZzr%/;A.P","fields":{"VAR":{"id":"A/TX@37C_h*^vbRp@1fz"}},"inputs":{"VALUE":{"block":{"type":"posix_open","id":"^$p+x^F[mQ;grqANDtO}","inputs":{"FILENAME":{"shadow":{"type":"text","id":"nz;|U#KPVW$$c0?W0ROv","fields":{"TEXT":"/dev/userleds"}}}}}}},"next":{"block":{"type":"controls_repeat_ext","id":"0{4pA@{^=ks|iVF.|]i#","inputs":{"TIMES":{"shadow":{"type":"math_number","id":"=o3{$E2c=BpwD0#MR3^x","fields":{"NUM":20}}},"DO":{"block":{"type":"variables_set","id":"l;AmIPhJARU{C)0kNq6`","fields":{"VAR":{"id":"xH3`F~]tadlX:/zKQ!Xx"}},"inputs":{"VALUE":{"block":{"type":"posix_ioctl","id":"0i!pbWJ(~f~)b^@jt!nP","inputs":{"FD":{"block":{"type":"variables_get","id":"QMGa_}UmC$b[5/Bh^f${","fields":{"VAR":{"id":"A/TX@37C_h*^vbRp@1fz"}}}},"REQ":{"block":{"type":"variables_get","id":"dZ5%B_rcbVb_o=v;gze-","fields":{"VAR":{"id":":,DB,f}1q3KOBim#j66["}}}},"ARG":{"block":{"type":"math_number","id":"9UA!sDxmf/=fYfxC6Yqa","fields":{"NUM":1}}}}}}},"next":{"block":{"type":"posix_sleep","id":"ruh/q4F7dW*CQ,5J]E%w","inputs":{"MS":{"block":{"type":"math_number","id":"9~q0@ABEg4VXP:1HN-$1","fields":{"NUM":5000}}}},"next":{"block":{"type":"variables_set","id":"e;BNsjvbN}9vTTc[O#bY","fields":{"VAR":{"id":"xH3`F~]tadlX:/zKQ!Xx"}},"inputs":{"VALUE":{"block":{"type":"posix_ioctl","id":"-G5x~Y4iAyVUAWuwNh#H","inputs":{"FD":{"block":{"type":"variables_get","id":"vtt5Gid0B|iK![$4Ct*D","fields":{"VAR":{"id":"A/TX@37C_h*^vbRp@1fz"}}}},"REQ":{"block":{"type":"variables_get","id":"pd~f}Oqz2(`o3Oz;8ax`","fields":{"VAR":{"id":":,DB,f}1q3KOBim#j66["}}}},"ARG":{"block":{"type":"math_number","id":"OS(uQV)!%iqZ=N}s1H(L","fields":{"NUM":0}}}}}}},"next":{"block":{"type":"posix_sleep","id":"{X9leD=Rgr4=o5E2(#Z,","inputs":{"MS":{"block":{"type":"math_number","id":"eEq(yXcGPbVtZT|CunT0","fields":{"NUM":5000}}}}}}}}}}}}},"next":{"block":{"type":"posix_close","id":"+%kD6{Xa@#BOx}a^Jbup","inputs":{"FD":{"block":{"type":"variables_get","id":"nu)^gdR-9QV71GSI7#(l","fields":{"VAR":{"id":"A/TX@37C_h*^vbRp@1fz"}}}}}}}}}}}}]},"variables":[{"name":"fd","id":"A/TX@37C_h*^vbRp@1fz"},{"name":"ULEDIOC_SETALL","id":":,DB,f}1q3KOBim#j66["},{"name":"ret","id":"xH3`F~]tadlX:/zKQ!Xx"}]}');
      break;
    default:
      break;
  }

  // Refresh the Blocks
  if (ws) { 
    load(ws); 
    runCode();
  }
}
```

To see the Blocks for a Blockly App: Browse to https://lupyuen.github.io/nuttx-blockly/

Select "Menu > More Tools > Developer Tools > Application > Local Storage > lupyuen.github.io > mainWorkspace"

Or do this from the JavaScript Console...

```javascript
// Display the Blocks in JSON Format
localStorage.getItem("mainWorkspace");

// Set the Blocks in JSON Format.
// Change `...` to the JSON of the Blocks to be loaded.
localStorage.setItem("mainWorkspace", `...`);
```
