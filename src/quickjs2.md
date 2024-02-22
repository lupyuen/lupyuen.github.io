# (Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way

📝 _28 Feb 2024_

![TODO](https://lupyuen.github.io/images/quickjs2-title.png)

TODO

A little like ChatGPT has possessed our NuttX Emulator and typing out our commands in super slo-mo

A bit like Sentient ChatGPT reluctantly typing our commands, pondering about taking over the world

[Zmodem](https://github.com/nodesign/nuttx-apps/blob/master/system/zmodem/README.txt)

![(Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way](https://lupyuen.github.io/images/quickjs2-blockly.png)

TODO

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

![TODO](https://lupyuen.github.io/images/quickjs2-nuttx.jpg)

TODO

![Running our Drag-n-Drop App on NuttX Emulator](https://lupyuen.github.io/images/quickjs2-emulator.png)

Read on to find out how we made it...

![NuttX App Builder with Blockly](https://lupyuen.github.io/images/quickjs2-blockly.png)

# Emulator Demo

Here's the __Emulator Demo__ that we can play along at home...

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
      os.sleep(20000);

      // Flip the LED Off and wait a while
      ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
      os.sleep(20000);
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
      os.sleep(20000);
      ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
      os.sleep(20000);
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

_What just happened?_

We drag-n-dropped a NuttX App that Blinks the LED. And tested it in our Web Browser, with the Ox64 Emulator!

TODO

![Running our Drag-n-Drop App on NuttX Emulator](https://lupyuen.github.io/images/quickjs2-emulator.png)

# POSIX Blocks in Blockly

TODO

# Blockly Code Generator

TODO

# Local Storage

TODO

# Device Demo

TODO

# Web Serial API

TODO

# Create the Blockly Project

TODO

MakeCode was created with Blockly, we'll stick with Blockly.

Based on the [Blockly Instructions](https://developers.google.com/blockly/guides/get-started/get-the-code)...

```bash
npx @blockly/create-package app nuttx-blockly --typescript
npm run build
```

Try the Blockly Demo: https://lupyuen.github.io/nuttx-blockly/

# Send a Command to NuttX Emulator

TODO

To send a command to NuttX Emulator: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/commit/f01727935818cd1685ee4a82943bb9f19b13d85c)

```javascript
let send_str = "";
function send_command(cmd) {
  if (cmd !== null) { send_str = cmd; }
  if (send_str.length == 0) { return; }
  console_write1(send_str.charCodeAt(0));
  send_str = send_str.substring(1);
  window.setTimeout(()=>{ send_command(null); }, 10);
}
const cmd = [
  `qjs`,
  `function main() { console.log(123); }`,
  `main()`,
  ``
].join("\r");
window.setTimeout(()=>{ send_command(cmd); }, 10000);
```

Which will start QuickJS and run a JavaScript Function:

https://lupyuen.github.io/nuttx-tinyemu/blockly/

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > function main() { console.log(123); }
undefined
qjs > main()
123
undefined
qjs >
```

# Add POSIX Blocks to Blockly

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

Let's test it...

# Drag-n-Drop a NuttX App for Ox64 BL808

TODO

Click this link: https://lupyuen.github.io/nuttx-blockly/

Then Drag-n-Drop this NuttX App...

[(Watch the Demo on YouTube)](https://youtu.be/-dG5ZSXELDc)

```javascript
var ULEDIOC_SETALL, fd, ret;
ULEDIOC_SETALL = 7427;
fd = os.open('/dev/userleds');
for (var count = 0; count < 20; count++) {
  ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
  os.sleep(20000);
  ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
  os.sleep(20000);
}
os.close(fd);
```

![(Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way](https://lupyuen.github.io/images/quickjs2-blockly.png)

Click the "Run on Ox64 Emulator" button.

Our Drag-n-Drop NuttX App runs automatically in the Emulator yay!

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > var ULEDIOC_SETALL, fd, ret;
undefined
qjs >
qjs >
qjs > ULEDIOC_SETALL = 7427;
7427
qjs > fd = os.open('/dev/userleds');
3
qjs > for (var count = 0; count < 20; count++) {
{  ...       ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
{  ...       os.sleep(20000);
{  ...       ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
{  ...       os.sleep(20000);
{  ...     }
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
```

![Running our Drag-n-Drop App on NuttX Emulator](https://lupyuen.github.io/images/quickjs2-emulator.png)

_How did Blockly pass the Generated JavaScript to NuttX Emulator?_

When we click the "Run on Emulator" button, our Blockly Website saves the Generated JavaScript to the Web Browser Local Storage: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L72-L78)

```javascript
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

In the NuttX Emulator: We read the Generated JavaScript from the Web Browser Local Storage. And feed it (character by character) to the NuttX Console: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/commit/85fb2b85ae85cd27b7623d937c4420a1d2bdd45c)

```javascript
// QuickJS Command to be sent
const cmd = [
  `qjs`,
  window.localStorage.getItem("runCode"),
  ``
].join("\r");

// Wait for NuttX to boot in 5 seconds. Then send the QuickJS Command.
window.setTimeout(()=>{ send_command(cmd); }, 5000);

// Send a Command to NuttX Console, character by character
let send_str = "";
function send_command(cmd) {
  if (cmd !== null) { send_str = cmd; }
  if (send_str.length == 0) { return; }
  console_write1(send_str.charCodeAt(0));
  send_str = send_str.substring(1);
  window.setTimeout(()=>{ send_command(null); }, 10);
}
```

# Drag-n-Drop a NuttX App to a Real Ox64 BL808 SBC

TODO

From NuttX Emulator to a Real NuttX Device! Click this link: https://lupyuen.github.io/nuttx-blockly/

Then Drag-n-Drop the same NuttX App (see the previous section)...

```javascript
var ULEDIOC_SETALL, fd, ret;
ULEDIOC_SETALL = 7427;
fd = os.open('/dev/userleds');
for (var count = 0; count < 20; count++) {
  ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
  os.sleep(20000);
  ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
  os.sleep(20000);
}
os.close(fd);
```

![(Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way](https://lupyuen.github.io/images/quickjs2-blockly.png)

1.  Click the "Run on Ox64 Device" button

1.  Click the "Connect" button to connect to our Ox64 BL808 SBC

1.  Power on our Ox64 SBC. The Web App waits for the "nsh>" prompt.

1.  Then our Drag-n-Drop NuttX App runs automatically on a Real Ox64 BL808 SBC yay!

[(Watch the Demo on YouTube)](https://youtu.be/lUhrLWvwizU)

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > var ULEDIOC_SETALL, fd, ret;
undefined
qjs >
qjs >
qjs > ULEDIOC_SETALL = 7427;
7427
qjs > fd = os.open('/dev/userleds');
3
qjs > for (var count = 0; count < 20; count++) {
{  ...       ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
{  ...       os.sleep(20000);
{  ...       ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
{  ...       os.sleep(20000);
{  ...     }
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
```

![Running our Drag-n-Drop App on Ox64 BL808 SBC](https://lupyuen.github.io/images/quickjs2-device.png)

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

More about the Web Serial API...

# Connect to Ox64 BL808 SBC via Web Serial API

TODO

Let's connect to Ox64 BL808 SBC in our Web Browser via the Web Serial API...

- [Web Serial API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API)

- [Read from and write to a serial port](https://developer.chrome.com/docs/capabilities/serial)

- [Getting started with the Web Serial API](https://codelabs.developers.google.com/codelabs/web-serial#0)

  (Very similar to what we're doing)

Beware, Web Serial API is only available...

- Over HTTPS: https://...

- Or Local Filesystem: file://...

- It won't work over HTTP! http://...

We create a button: [index.html](https://github.com/lupyuen/nuttx-tinyemu/commit/e5e74ac92d21d47c359dbabd4babcb0d59206408#diff-09992667561d80fbe8c76cc5e271739ba0bb8194b31341005f25d8aa3f6c2baf)

```html
<button id="connect" onclick="control_device();">
  Connect
</button>
```

Which connects to Ox64 over UART: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/commit/e5e74ac92d21d47c359dbabd4babcb0d59206408#diff-0600645ce087613109d3c3269c8fa545477739eff19b7d478672b715500bb9cc)

```javascript
// Control Ox64 over UART
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {
    if (!navigator.serial) { const err = "Web Serial API only works with https://... and file://...!"; alert(err); throw new Error(err); }

    // Prompt user to select any serial port.
    const port = await navigator.serial.requestPort();

    // Get all serial ports the user has previously granted the website access to.
    // const ports = await navigator.serial.getPorts();

    // Wait for the serial port to open.
    // TODO: Ox64 only connects at 2 Mbps, change this for other devices
    await port.open({ baudRate: 2000000 });

    // Read from the serial port
    const textDecoder = new TextDecoderStream();
    const readableStreamClosed = port.readable.pipeTo(textDecoder.writable);
    const reader = textDecoder.readable.getReader();

    // Listen to data coming from the serial device.
    while (true) {
        const { value, done } = await reader.read();
        if (done) {
            // Allow the serial port to be closed later.
            reader.releaseLock();
            break;
        }
        // value is a string.
        console.log(value);
    }
```

And Ox64 NuttX appears in our JavaScript Console yay!

```text
Starting kernel ...
ABC
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
NuttShell (NSH) NuttX-12.4.0-RC0
nsh>
```

# Send a Command to Ox64 BL808 SBC via Web Serial API

TODO

This is how we send a command to Ox64 BL808 SBC via Web Serial API: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/commit/1384db4edb398f6cb65718766af67dc1aa88bcb0)

```javascript
  // Wait for the serial port to open.
  // TODO: Ox64 only connects at 2 Mbps, change this for other devices
  await port.open({ baudRate: 2000000 });

  // Send a command to serial port
  const cmd = [
      `qjs`,
      `function main() { console.log(123); }`,
      `main()`,
      ``
  ].join("\r");
  const textEncoder = new TextEncoderStream();
  const writableStreamClosed = textEncoder.readable.pipeTo(port.writable);
  const writer = textEncoder.writable.getWriter();
  await writer.write(cmd);
  
  // Read from the serial port
  const textDecoder = new TextDecoderStream();
  const readableStreamClosed = port.readable.pipeTo(textDecoder.writable);
  const reader = textDecoder.readable.getReader();

  // Listen to data coming from the serial device.
  ...
```

And it works! Says the JavaScript Console...

```text
function main() { console.log(123); }
main()
123
undefined
qjs >
```

# Load the Blocks for a Blockly App

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

