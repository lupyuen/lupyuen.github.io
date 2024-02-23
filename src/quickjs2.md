# (Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way

📝 _28 Feb 2024_

![(Homage to MakeCode) Coding Ox64 BL808 SBC the Drag-n-Drop Way](https://lupyuen.github.io/images/quickjs2-title.png)

_Remember Makecode? BBC micro:bit and its Drag-n-Drop App Builder?_

[__MakeCode for BBC micro:bit__](https://www.sciencedirect.com/science/article/pii/S1383762118306088) is an awesome creation that's way ahead of its time (7 years ago!)

- [__TypeScript Compiler__](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0008) in the Web Browser (in JavaScript!)

- [__Bespoke Arm Assembler__](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0008) that runs in the Web Browser (also JavaScript)

- [__Custom Embedded OS__](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0009) for BBC micro:bit (CODAL + Mbed OS)

- [__UF2 Bootloader__](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0015) with flashing over Web USB

- [__micro:bit Simulator__](https://www.sciencedirect.com/science/article/pii/S1383762118306088#sec0004) in JavaScript

- All this for an underpowered [__BBC micro:bit__](https://en.wikipedia.org/wiki/Micro_Bit) with Nordic nRF51

  (Arm Cortex-M0, 256 KB Flash, 16 KB RAM!)

![MakeCode for BBC micro:bit](https://lupyuen.github.io/images/quickjs2-makecode.jpg)

__Today 7 years later:__ How would we redo all this? With a bunch of Open Source Packages?

- Hardware Device: [__Ox64 BL808 64-bit RISC-V SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358)

  (64 MB RAM, Unlimited microSD Storage, only $8)

- Embedded OS: [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)

- JavaScript Engine: [__QuickJS for NuttX__](https://lupyuen.github.io/articles/quickjs)

- Web Emulator: [__TinyEMU WebAssembly for NuttX__](https://lupyuen.github.io/articles/tinyemu2)

- C Compiler + Assembler: [__TCC WebAssembly for NuttX__](https://lupyuen.github.io/articles/tcc)

  (Won't need this since we have JavaScript)

- Device Control: [__Web Serial API__](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API) with [__Term.js__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/term.js)

  (Control Ox64 over UART)

This is how we gave MakeCode a wholesome wholesale makeover...

![Blockly App Builder for NuttX](https://lupyuen.github.io/images/quickjs2-nuttx.jpg)

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

1.  Our [__Emulated Ox64 SBC__](https://lupyuen.github.io/articles/tinyemu2) boots in the Web Browser...

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs

    QuickJS - Type "\h" for help
    qjs >
    ```

    And starts the [__QuickJS JavaScript Engine__](https://lupyuen.github.io/articles/quickjs).

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

    Which blinks the [__Simulated LED__](https://lupyuen.github.io/articles/quickjs#simulate-the-led-on-ox64-emulator) (GPIO 29, pic below)...

    ```text
    bl808_gpiowrite:
      regaddr=0x20000938,
      set=0x1000000

    bl808_gpiowrite:
      regaddr=0x20000938,
      clear=0x1000000
    ```

    [(Watch the __Demo on YouTube__)](https://youtu.be/-dG5ZSXELDc?si=pAkGdtvUHW9qpjoG&t=88)

_What just happened?_

We drag-n-dropped a NuttX App that Blinks the LED.

And our NuttX App runs automagically in our Web Browser, thanks to Ox64 Emulator!

We go behind the scenes...

![Running our Drag-n-Drop App on NuttX Emulator](https://lupyuen.github.io/images/quickjs2-emulator.png)

# POSIX Blocks in Blockly

_What's POSIX? How are POSIX Functions used in our Blinky App?_

We call [__POSIX Functions__](https://en.wikipedia.org/wiki/POSIX) to create Command-Line Apps in Linux, macOS and Windows.

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

![POSIX Blocks in Blockly](https://lupyuen.github.io/images/quickjs2-blocks.png)

_How did we create the POSIX Blocks? (Pic above)_

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

> ![POSIX Blocks in Blockly](https://lupyuen.github.io/images/quickjs2-posix.png)

Which are explained here...

- [__"POSIX Blocks in Blockly"__](https://lupyuen.github.io/articles/quickjs2#appendix-posix-blocks-in-blockly)

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

- [__`open` Code Generator__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/generators/javascript.ts#L15-L25)

- [__`close` Code Generator__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/generators/javascript.ts#L26-L38)

- [__`ioctl` Code Generator__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/generators/javascript.ts#L38-L52)

- [__`sleep` Clode Generator__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/generators/javascript.ts#L52-L64)

_POSIX Functions are supported by QuickJS?_

Yep the QuickJS JavaScript Engine supports [__these POSIX Functions__](https://bellard.org/quickjs/quickjs.html#os-module).

And we [__added `ioctl`__](https://lupyuen.github.io/articles/quickjs#add-ioctl-to-quickjs) to QuickJS.

![Running our NuttX App on Ox64 Emulator](https://lupyuen.github.io/images/quickjs2-nuttx2.jpg)

# Transmit JavaScript via Local Storage

_Blockly generates the JavaScript for our Blinky App... How did it appear in our Ox64 Emulator?_

When we click the __"Run Emulator"__ button, our Blockly Website saves the Generated JavaScript to the [__Local Storage__](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API) in our Web Browser: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L73-L86)

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

Thanks to [__TinyEMU__](https://lupyuen.github.io/articles/tinyemu2) and [__Term.js__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/term.js), everything works hunky dory!

_Hmmm it's so laggy? A bit like ChatGPT has possessed our Ox64 Emulator and typing out our commands in super slo-mo..._

Yeah we might inject our JavaScript File into the [__ROM FS Filesystem for Ox64 Emulator__](https://lupyuen.github.io/articles/romfs#from-tcc-to-nuttx-emulator).

This will make it much quicker to load our JavaScript File on Ox64 Emulator.

![Running our Drag-n-Drop App on Ox64 BL808 SBC](https://lupyuen.github.io/images/quickjs2-device.png)

# Blinky on a Real Ox64 SBC

_Will we do the same for a Real Ox64 SBC?_

Well it gets complicated. If we have an [__Ox64 BL808 SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358), here are the __Demo Steps__...

1.  Load our Ox64 SBC with __OpenSBI, U-Boot Bootloader, NuttX + QuickJS__ (on microSD). Don't power up yet...

    [__"QuickJS for NuttX Ox64"__](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

1.  Connect an LED to Ox64 at [__GPIO 29, Pin 21__](https://lupyuen.github.io/articles/quickjs#quickjs-blinks-the-led-on-ox64-sbc)

1.  Head over to this link...

    [__NuttX App Builder with Blockly__](https://lupyuen.github.io/nuttx-blockly/)

1.  Click __"Select Demo"__ > __"LED Blinky"__

    [(Or __Drag-n-Drop the Blocks__ ourselves)](https://youtu.be/-dG5ZSXELDc)

1.  Click __"Run on Ox64 Device"__

1.  Click the __"Connect"__ Button. Select the Serial Port for our Ox64 SBC...

    ![Selecting the Serial Port for Ox64 SBC](https://lupyuen.github.io/images/quickjs2-serial.png)

1.  Power on our Ox64 SBC. The Web Serial Monitor waits for the NuttX Shell __"nsh>"__ prompt...

    ![Wait for NuttX Shell](https://lupyuen.github.io/images/quickjs2-wait.png)

1.  Our Ox64 SBC boots NuttX...

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs

    QuickJS - Type "\h" for help
    qjs >
    ```

    And starts the [__QuickJS JavaScript Engine__](https://lupyuen.github.io/articles/quickjs).

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

    Which blinks the [__Real Ox64 LED__](https://lupyuen.github.io/articles/quickjs#quickjs-blinks-the-led-on-ox64-sbc) (GPIO 29, pic below)...

    ```text
    bl808_gpiowrite:
      regaddr=0x20000938,
      set=0x1000000

    bl808_gpiowrite:
      regaddr=0x20000938,
      clear=0x1000000
    ```

    [(Watch the __Demo on YouTube__)](https://youtu.be/lUhrLWvwizU)

What just happened? Let's break it down...

![Blinking a Real LED on Ox64 SBC](https://lupyuen.github.io/images/nim-blink2.webp)

# Control Ox64 via Web Serial API

_Our Web Browser controls Ox64 SBC... How is that possible?_

With the [__Web Serial API__](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API), it's OK to control any device that's accessible over the __Serial Port__. But it's only available...

- Over __HTTPS__: _https://..._

- Or __Local Filesystem__: _file://..._

- It __won't work over HTTP__! _http://..._

![Running our NuttX App on Ox64 SBC](https://lupyuen.github.io/images/quickjs2-nuttx3.jpg)

_How does it work?_

We create a __HTML Button__ for "Connect": [index.html](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/index.html#L27-L29)

```html
<!-- Connect Button in HTML -->
<button
  id="connect"
  onclick="control_device();">
  Connect
</button>
```

That calls our JavaScript Function to connect to a Serial Port: [webserial.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/webserial.js#L611-L675)

```javascript
// Control Ox64 over UART. Called by the "Connect" Button.
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {

  // Doesn't work in http://...
  if (!navigator.serial) { const err = "Web Serial API only works with https://... and file://...!"; alert(err); throw new Error(err); }

  // Prompt our Human to select a Serial Port
  const port = await navigator.serial.requestPort();
  term.write("Power on our NuttX Device and we'll wait for \"nsh>\"\r\n");

  // TODO: Get all Serial Ports our Human has previously granted access
  // const ports = await navigator.serial.getPorts();

  // Wait for the Serial Port to open.
  // TODO: Ox64 only connects at 2 Mbps, change this for other devices
  await port.open({ baudRate: 2000000 });
```

The code above pops up a prompt to __select a Serial Port__ and connect at 2 Mbps...

![Selecting the Serial Port](https://lupyuen.github.io/images/quickjs2-serial.png)

We're all set to Read and Write the Serial Port! First we need the __Reader and Writer Streams__...

```javascript
  // Prepare to Write to the Serial Port
  const textEncoder = new TextEncoderStream();
  const writableStreamClosed = textEncoder.readable.pipeTo(port.writable);
  const writer = textEncoder.writable.getWriter();
  
  // Prepare to Read from the Serial Port
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

- [__"Control Ox64 via Web Serial API"__](https://lupyuen.github.io/articles/quickjs2#appendix-control-ox64-via-web-serial-api)

- [__"Transmit JavaScript to Ox64 SBC"__](https://lupyuen.github.io/articles/quickjs2#appendix-transmit-javascript-to-ox64-sbc)

_Hmmm this is barely tolerable? Feels like ChatGPT becoming Sentient and reluctantly typing our commands, pondering about taking over the world..._

Yeah we might switch to [__Zmodem__](https://github.com/nodesign/nuttx-apps/blob/master/system/zmodem/README.txt) for quicker transfer of our JavaScript File over UART.

(Too bad we can't [__Inject the JavaScript__](https://lupyuen.github.io/articles/quickjs2#transmit-javascript-via-local-storage) into a Real microSD Filesystem)

_We created fun things with Web Serial API and Term.js. Anything else we can make?_

Thanks to Web Serial API (and Term.js), we can run [__PureScript__](https://www.purescript.org/) to parse the [__Real-Time Logs__](https://github.com/lupyuen/nuttx-purescript-parser) from a NuttX Device (or NuttX Emulator)...

All this in the Web Browser! Stay tuned for the next article.

![Blockly App Builder for NuttX](https://lupyuen.github.io/images/quickjs2-nuttx.jpg)

# What's Next

TODO: So much has changed over the past 7 years! We gave __MakeCode App Builder__ a wholesome wholesale makeover (pic above)...

- We swapped BBC micro:bit to a cheaper, $8 64-bit RISC-V Gadget...

  __Ox64 BL808 Single-Board Computer__

- We changed Mbed OS to __Apache NuttX RTOS__

  (Which runs well on Ox64 SBC and Ox64 Emulator)

- Huge Chunks of JavaScript became __WebAssembly__

  (Though we stuck with Blockly, like MakeCode)

- Made possible by these awesome Open Source Tools...

  __QuickJS__, __TinyEMU__ and __Term.js__

- We might optimise and switch to [__Zmodem__](https://lupyuen.github.io/articles/quickjs2#control-ox64-via-web-serial-api) with [__ROM FS Injection__](https://lupyuen.github.io/articles/quickjs2#transmit-javascript-via-local-storage)

  (Hope we won't fall back to Web USB)

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

Earlier we talked about adding __POSIX Blocks__ to our Blockly Website...

- [__POSIX Blocks in Blockly__](https://lupyuen.github.io/articles/quickjs2#posix-blocks-in-blockly)

- [__Code Generator in Blockly__](https://lupyuen.github.io/articles/quickjs2#code-generator-in-blockly)

With the [__Blockly Developer Tools__](https://developers.google.com/blockly/guides/create-custom-blocks/blockly-developer-tools), this is how we added our __POSIX Blocks__ to Blockly: [posix.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/blocks/posix.ts#L7-L26)

```javascript
// Define the POSIX Open Block in Blockly
const posixOpen = {

  // Name and Appearance of our Block
  'type': 'posix_open',
  'message0': 'Open Filename %1',

  // Our Block has one Parameter: Filename
  'args0': [
    {
      'type': 'input_value',
      'name': 'FILENAME',
      'check': 'String',
    },
  ],

  // How it looks
  'previousStatement': null,
  'nextStatement': null,
  'output': 'Number',
  'colour': 160,
  'tooltip': '',
  'helpUrl': '',
};
```

These are the __POSIX Blocks__ that we added...

- [__POSIX Open Block__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/blocks/posix.ts#L7-L26)

- [__POSIX Close Block__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/blocks/posix.ts#L26-L44)

- [__POSIX IOCtl Block__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/blocks/posix.ts#L44-L73)

- [__POSIX Sleep Block__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/blocks/posix.ts#L73-L97)

__In the Blockly Toolbox__ (Menu Bar of Blocks): We create a __POSIX Category__ that contains our POSIX Blocks: [toolbox.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/toolbox.ts#L6-L68)

```javascript
export const toolbox = {
  'kind': 'categoryToolbox',
  'contents': [
    {
      // Category for POSIX Blocks
      'kind': 'category',
      'name': 'POSIX',
      'categorystyle': 'text_category',
      'contents': [
        // POSIX Open Block
        {
          'kind': 'block',
          'type': 'posix_open',
          'inputs': {
            'FILENAME': {
              'shadow': {
                'type': 'text',
                'fields': {
                  'TEXT': '/dev/userleds',
                },
              },
            },
          },
        },
        // Followed by the other POSIX Blocks:
        // Close, IOCtl, Sleep
```

Then we __Build and Deploy__ our Blockly Website...

```bash
## Test our Blockly Website
cd nuttx-blockly
npm run start

## Deploy to GitHub Pages at `docs`
npm run build \
  && rm -r docs \
  && mv dist docs
```

Remember to [__Disable the JavaScript Eval__](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L35-L38).

Let's talk about loading a Blockly App...

# Appendix: Load a Blockly App

In our Blockly Website, we provide the feature to load the __Demo Blocks for a Blockly App__...

- [__"Drag-n-Drop a Blinky App"__](https://lupyuen.github.io/articles/quickjs2#drag-n-drop-a-blinky-app)

- [__"Blinky on a Real Ox64 SBC"__](https://lupyuen.github.io/articles/quickjs2#blinky-on-a-real-ox64-sbc)

This is how we __load the Blocks__ for a Blockly App: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L100-L120)

```javascript
// When we Select a Demo...
function selectDemo(ev: Event) {
  const storageKey = 'mainWorkspace';
  const target = ev?.target as HTMLSelectElement;
  const value = target.value;

  // Set the Blocks in our Local Storage
  switch (value) {
    case "LED Blinky":
      // Omitted: Super-long Blocks JSON
      window.localStorage?.setItem(storageKey, '{"blocks": ...}');
      break;

    default: break;
  }

  // Refresh the Workspace Blocks from Local Storage
  // And regenerate the JavaScript
  if (ws) { 
    load(ws); 
    runCode();
  }
}
```

To see the __Blocks JSON__ for a Blockly App...

1.  Browse to our [__Blockly Website__](https://lupyuen.github.io/nuttx-blockly/)

1.  Select _"Menu > More Tools > Developer Tools > Application > Local Storage > lupyuen.github.io > mainWorkspace"_

1.  We'll see the super-long __Blocks JSON__: _{"blocks": ...}_

Or do this from the __JavaScript Console__...

```javascript
// Display the Blocks in JSON Format
localStorage.getItem("mainWorkspace");

// Set the Blocks in JSON Format.
// Change `...` to the JSON of the Blocks to be loaded.
localStorage.setItem("mainWorkspace", `...`);
```

![Running our NuttX App on Ox64 SBC](https://lupyuen.github.io/images/quickjs2-nuttx3.jpg)

# Appendix: Control Ox64 via Web Serial API

Earlier we spoke about __controlling Ox64 SBC__ over the Web Serial API...

- [__"Control Ox64 via Web Serial API"__](https://lupyuen.github.io/articles/quickjs2#control-ox64-via-web-serial-api)

This is how we wait for the __NuttX Shell__ _("nsh>")_ before sending a JavaScript Command...

```javascript
// Control Ox64 over UART. Called by the "Connect" Button.
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {

  // Omitted: Prompt our Human to select a Serial Port
  // And wait for Serial Port to open
  const port = ...

  // Omitted: Prepare to Read and Write the Serial Port
  const writer = ...
  const reader = ...

  // Wait for "nsh>"
  let nshSpotted = false;
  let termBuffer = "";

  // Listen to data coming from the Serial Device
  while (true) {
    const { data, done } = await reader.read();
    if (done) {
      // Allow the serial port to be closed later.
      reader.releaseLock();
      break;
    }
    // Print to the Terminal
    term.write(data);

    // Wait for "nsh>"
    if (nshSpotted) { continue; }
    termBuffer += data;
    if (termBuffer.indexOf("nsh>") < 0) { continue; }

    // NSH Spotted! We read the Generated JavaScript
    // from the Web Browser's Local Storage.
    // Newlines become Carriage Returns.
    nshSpotted = true;
    const code = window.localStorage.getItem("runCode")
      .split("\n").join("\r")
      .split("\r\r").join("\r");

    // Append the Generated JavaScript to
    // the QuickJS Command 
    const cmd = [
      `qjs`,
      code,
      ``
    ].join("\r");

    // Send the command to the Serial Port
    window.setTimeout(()=>{
      send_command(writer, cmd); }, 
    1000);  // Wait a second
  }
}
```

Let's look inside __send_command__...

![Running our NuttX App on Ox64 SBC](https://lupyuen.github.io/images/quickjs2-nuttx3.jpg)

# Appendix: Transmit JavaScript to Ox64 SBC

_How did Blockly pass the Generated JavaScript to Ox64 SBC?_

When we click the __"Run on Device"__ button, our Blockly Website saves the Generated JavaScript to the Web Browser Local Storage: [index.ts](https://github.com/lupyuen/nuttx-blockly/blob/main/src/index.ts#L84-L96)

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

__In the WebSerial Monitor__: We read the Generated JavaScript from the Web Browser Local Storage. And feed it (character by character) to the NuttX Console: [webserial.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/webserial.js#L612-L694)

```javascript
// Control Ox64 over UART. Called by the "Connect" Button.
// https://developer.chrome.com/docs/capabilities/serial
async function control_device() {

  // Omitted: Prompt our Human to select a Serial Port
  // And wait for Serial Port to open
  const port = ...

  // Omitted: Prepare to Read and Write the Serial Port
  const writer = ...
  const reader = ...

  // Wait for "nsh>"
  let nshSpotted = false;
  let termBuffer = "";

  // Listen to data coming from the Serial Device
  while (true) {

    // Omitted: Wait for "nsh>"
    ...

    // NSH Spotted! We read the Generated JavaScript
    // from the Web Browser's Local Storage.
    // Newlines become Carriage Returns.
    nshSpotted = true;
    const code = window.localStorage.getItem("runCode")
      .split("\n").join("\r")
      .split("\r\r").join("\r");

    // Append the Generated JavaScript to
    // the QuickJS Command 
    const cmd = [
      `qjs`,
      code,
      ``
    ].join("\r");

    // Send the command to the Serial Port
    window.setTimeout(()=>{
      send_command(writer, cmd); }, 
    1000);  // Wait a second
  }
}
```

(We saw this in the previous section)

Here's the implementation of __send_command__: [webserial.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/webserial/webserial.js#L675-L695)

```javascript
// Command to be sent to Serial Port
let send_str = "";

// Send a Command to serial port, character by character
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
