# Nim on a Real-Time Operating System: Apache NuttX RTOS + Ox64 BL808 SBC

📝 _7 Jan 2024_

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Works great with Nim!](https://lupyuen.github.io/images/nim-ox64.png)

Happy New Year! 2024 is here and we're running [__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (Real-Time Operating System) on Single-Board Computers with __plenty of RAM__...

Like [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V SBC with __64 MB RAM!__ (Pic below)

_How will we use the Plentiful RAM?_

In this article, we create a __Blinky LED__ app with a Modern, Garbage-Collected Language: [__Nim Programming Language__](https://nim-lang.org).

[__Garbage-Collected__](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)) Languages (like Nim) require [__a bit more RAM__](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)#Disadvantages) than Low-Level Languages (like C). Perfect for our roomy (and vroomy) SBC!

[(Watch the __Demo on YouTube__)](https://youtube.com/shorts/KCkiXFxBgxQ)

_But we need a RISC-V SBC?_

No worries! We'll run Nim + NuttX on the __QEMU Emulator__ for 64-bit RISC-V. Which works great on Linux, macOS and Windows machines.

Everything that happens on Ox64 SBC, we'll see the __exact same thing__ in QEMU!

[(Except the __blinkenlight__)](https://lupyuen.github.io/images/nim-blink.jpg)

_Hmmm Garbage Collection... Won't it jitter: run-pause-run-pause?_

The fine folks at [__Wilderness Labs__](https://www.wildernesslabs.co/) are running [__.NET on NuttX__](https://www.wildernesslabs.co/developers) with Garbage Collection. Optimising for performance really helps!

[(See __TinyGo__ and __MicroPython__)](https://www.mdpi.com/2079-9292/12/1/143)

_How is Nim different from Rust and Zig?_

We've tested [__Rust on NuttX__](https://lupyuen.github.io/articles/rusti2c) and [__Zig on NuttX__](https://lupyuen.github.io/articles/lvgl4). __Nim is different__ because it...

- __Compiles to C__ (instead of Machine Code)

- Syntax is __Python-like__ (but Statically Compiled)

- Automatic __Garbage Collection__ (no Borrow Checker)

- And it's __Memory Safe__ (like Rust)

First we say hello to Nim...

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

# Basic Nim from scratch

_(3 languages in a title heh heh)_

This is the __simplest Nim Program__ that will run on NuttX: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L54-L63)

```nim
## Main Function in Nim.
## Will be called by NuttX, so we export to C.
proc hello_nim() {.exportc, cdecl.} =

  ## Print something
  echo "Hello Nim!"

  ## Force the Garbage Collection
  GC_runOrc()
```

Which looks a lot like Python!

_What's GC_runOrc?_

Our Nim Program will be __called by C__. (Remember NuttX?)

And Nim works with [__Garbage Collection__](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)). Thus we call [__GC_runOrc__](https://nim-lang.org/blog/2022/11/11/a-cost-model-for-nim.html) to...

- Force the Garbage Collection to complete

- Clean up all remaining Nim Objects

- Then return to C and NuttX

_What if we forget to call GC_runOrc?_

Erm don't! To make it unforgettable, we [__`defer`__](https://nim-lang.org/docs/manual.html#exception-handling-defer-statement) the Garbage Collection: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L54-L63)

```nim
## Main Function in Nim
proc hello_nim() {.exportc, cdecl.} =

  ## On Return: Force the Garbage Collection
  defer: GC_runOrc()

  ## Print something
  echo "Hello Nim!"
```

[__`defer`__](https://nim-lang.org/docs/manual.html#exception-handling-defer-statement) ensures that the Garbage Collection __will always happen__, as soon as we return from the Main Function.

Now we do something cool and enlightening...

([__hello_nim__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L54-L67) is called by our C Program [__hello_nim_main.c__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_main.c#L35-L42))

![Blink an LED with Nim](https://lupyuen.github.io/images/nim-code.jpg)

# Blink an LED

This is how we __blink an LED__ with Nim on NuttX: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L19-L50)

```nim
## Blink the LED
proc blink_led() =

  ## Open the LED Driver
  echo "Opening /dev/userleds"
  let fd = c_open("/dev/userleds", O_WRONLY)

  ## Check the File Descriptor for error
  if fd < 0:
    echo "Failed to open /dev/userleds"
    return
```

First we call the NuttX Function __`open`__ to access the __LED Driver__.

We might forget to __`close`__ the LED Driver (in case of error), so we [__`defer`__](https://nim-lang.org/docs/manual.html#exception-handling-defer-statement) the closing...

```nim
  ## On Return: Close the LED Driver
  defer: c_close(fd)
```

Next we call the NuttX Function __`ioctl`__ to flip __LED 0 to On__...

```nim
  ## Turn on LED
  echo "Set LED 0 to 1"
  var ret = c_ioctl(fd, ULEDIOC_SETALL, 1)
  if ret < 0:
    echo "ioctl(ULEDIOC_SETALL) failed"
    return
```

__ULEDIOC_SETALL__ accepts a Bit Mask of LED States. The value __`1`__ says that __LED 0__ (Bit 0) will be flipped On.

(Other LEDs will be flipped Off)

We __pause a while__...

```nim
  ## Wait a second (literally)
  ## Because 1 million microseconds = 1 second
  echo "Waiting..."
  c_usleep(1000_000)
```

Finally we flip __LED 0 to Off__...

```nim
  ## Turn off LED
  echo "Set LED 0 to 0"
  ret = c_ioctl(fd, ULEDIOC_SETALL, 0)
  if ret < 0:
    echo "ioctl(ULEDIOC_SETALL) failed"
    return

  ## Wait again
  echo "Waiting..."
  c_usleep(1000_000)
```

In our [__Main Function__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L54-L67): We call the above function __20 times__ to blink our LED (pic below)...

```nim
## Main Function in Nim
proc hello_nim() {.exportc, cdecl.} =

  ## On Return: Force the Garbage Collection
  defer: GC_runOrc()

  ## Blink the LED 20 times
  for loop in 0..19:
    blink_led()
```

[(Looks mighty similar to the __C Version__)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello/hello_main.c#L40-L85)

And we're almost done! Nim needs to discover our NuttX Functions...

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Nim blinks our LED](https://lupyuen.github.io/images/nim-blink2.jpg)

# Import NuttX Functions

_How will Nim know about open, close, ioctl, usleep?_

We __import the NuttX Functions__ from C into Nim: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L1-L19)

```nim
## Import NuttX Functions from C.
## Based on https://github.com/nim-lang/Nim/blob/devel/lib/std/syncio.nim

proc c_open(filename: cstring, mode: cint): cint {.
  importc: "open",
  header: "<fcntl.h>",
  nodecl.}

proc c_close(fd: cint): cint {.
  importc: "close",
  header: "<fcntl.h>",
  nodecl, discardable.}

proc c_ioctl(fd: cint, request: cint): cint {.
  importc: "ioctl",
  header: "<sys/ioctl.h>",
  nodecl, varargs.}

proc c_usleep(usec: cuint): cint {.
  importc: "usleep",
  header: "<unistd.h>",
  nodecl, discardable.}
```

[(__discardable__ tells Nim Compiler that the Return Value is Optional)](https://nim-lang.org/docs/manual.html#statements-and-expressions-discard-statement)

[(__nodecl__ means don't emit the C Declaration in the Generated Code)](https://nim-lang.org/docs/manual.html#implementation-specific-pragmas-nodecl-pragma)

We do the same for __NuttX Macros__...

```nim
## Import NuttX Macros from C.
## Based on https://github.com/nim-lang/Nim/blob/devel/lib/std/syncio.nim

var O_WRONLY {.
  importc: "O_WRONLY", 
  header: "<fcntl.h>".}: cint

var ULEDIOC_SETALL {.
  importc: "ULEDIOC_SETALL", 
  header: "<nuttx/leds/userled.h>".}: cint
```

We're ready to run this!

![Nim with Apache NuttX RTOS on QEMU RISC-V (64-bit)](https://lupyuen.github.io/images/nim-qemu.png)

# Run Nim on QEMU

_How to run Nim Blinky on QEMU Emulator?_

We begin by __booting NuttX RTOS__ on RISC-V QEMU Emulator (64-bit)...

1.  Install [__QEMU Emulator for RISC-V (64-bit)__](https://www.qemu.org/download/)...

    ```bash
    ## For macOS:
    brew install qemu

    ## For Debian and Ubuntu:
    sudo apt install qemu-system-riscv64
    ```

1.  Download __`nuttx`__ from the [__NuttX Release__](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)...

    [__nuttx: NuttX Image for 64-bit RISC-V QEMU__](https://github.com/lupyuen/nuttx-nim/releases/download/qemu-1/nuttx)

    If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/nim#appendix-build-nuttx-for-qemu)

1.  Start the __QEMU RISC-V Emulator__ (64-bit) with NuttX RTOS...

    ```bash
    qemu-system-riscv64 \
      -semihosting \
      -M virt,aclint=on \
      -cpu rv64 \
      -smp 8 \
      -bios none \
      -kernel nuttx \
      -nographic
    ```

1.  NuttX is now running in the __QEMU Emulator__! (Pic above)

    ```text
    NuttShell (NSH) NuttX-12.0.3
    nsh>
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L199-L208)

1.  At the NuttX Prompt, enter "__hello_nim__"...

    ```text
    nsh> hello_nim
    Hello Nim!
    Opening /dev/userleds
    ```

    [(Enter "__help__" to see the available commands)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L472-L497)

1.  Nim on NuttX blinks our __Simulated LED__...

    ```text
    Set LED 0 to 1
    board_userled_all: led=0, val=1
    Waiting...

    Set LED 0 to 0
    board_userled_all: led=0, val=0
    Waiting...

    Set LED 0 to 1
    board_userled_all: led=0, val=1
    Waiting...
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L210-L471)

1.  To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

Now we step out from the Virtual World into the Real World (like "The Matrix")...

![Connect an LED to Ox64 SBC at GPIO 29, Pin 21](https://lupyuen.github.io/images/nim-wiring.jpg)

# Nim Blinky on Ox64

_Will Nim Blinky run on a real RISC-V SBC?_

Yep! Connect an LED to Ox64 SBC at __GPIO 29, Pin 21__ (pic above)...

| Connect | To | Wire |
|:-----|:---|:-----|
| __Ox64 Pin 21__ <br>_(GPIO 29)_ | __Resistor__ <br>_(47 Ohm)_ | Red |
| __Resistor__ <br>_(47 Ohm)_ | __LED +__ <br>_(Curved Edge)_ | Breadboard
| __LED -__ <br>_(Flat Edge)_ | __Ox64 Pin 23__ <br>_(GND)_ | Black 

[(See the __Ox64 Pinout__)](https://wiki.pine64.org/wiki/File:Ox64_pinout.png)

(Resistor is __47 Ohm__, yellow-purple-black-gold, almost Karma Chameleon)

Follow these steps to __boot NuttX RTOS__ on our Ox64 BL808 SBC...

1.  Flash [__OpenSBI and U-Boot Bootloader__](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot) to Ox64

1.  Prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64)

1.  Download __`Image`__ from the [__NuttX Release__](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)...

    [__Image: NuttX Image for Ox64 BL808 SBC__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/Image)

    If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/nim#appendix-build-nuttx-for-ox64)

1.  Copy the __`Image`__ file and overwrite the __`Image`__ in the Linux microSD

1.  Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64

1.  NuttX is now running on our __Ox64 SBC__! (Pic below)

    ```text
    Starting kernel...
    NuttShell (NSH) NuttX-12.0.3
    nsh>
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96#file-ox64-nuttx-nim-blink-log-L112-L125)

1.  At the NuttX Prompt, enter "__hello_nim__"...

    ```text
    nsh> hello_nim
    Hello Nim!
    Opening /dev/userleds
    ```

    [(Enter "__help__" to see the available commands)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L472-L497)

1.  Nim on NuttX [__blinks our LED__](https://lupyuen.github.io/images/nim-blink.jpg)...

    ```text
    Set LED 0 to 1
    board_userled_all: led=0, val=1
    Waiting...

    Set LED 0 to 0
    board_userled_all: led=0, val=0
    Waiting...

    Set LED 0 to 1
    board_userled_all: led=0, val=1
    Waiting...
    ```

    [(Watch the __Demo on YouTube__)](https://youtube.com/shorts/KCkiXFxBgxQ)

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96#file-ox64-nuttx-nim-blink-log-L129-L395)

Nim blinks a real LED on a real RISC-V SBC! Let's figure out how it works...

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Works great with Nim!](https://lupyuen.github.io/images/nim-ox64.png)

# Inside Nim on NuttX

_Nim runs incredibly well on NuttX. How is that possible?_

That's because __Nim compiles to C__. As far as NuttX is concerned...

Nim looks like __any other C Program!__

_Whoa! How is Nim compiled to C?_

Our [__NuttX Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/Makefile#L37-L41) calls the Nim Compiler...

```bash
## Compile Nim to C
export TOPDIR=$PWD/nuttx
cd apps/examples/hello_nim
nim c --header hello_nim_async.nim 
```

Nim Compiler compiles our [__Nim Program__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L54-L63)...

```nim
## Nim Program that prints something
proc hello_nim() {.exportc, cdecl.} =
  echo "Hello Nim!"
```

Into this [__C Program__](https://gist.github.com/lupyuen/4d3f44b58fa88b17ca851decb0419b86#file-mhello_nim_async-nim-c-L198-L203)...

```c
// Main Function compiled from Nim to C:
// echo "Hello Nim!"
N_LIB_PRIVATE N_CDECL(void, hello_nim)(void) {
  ...
  // `echo` comes from the Nim System Library
  // https://github.com/nim-lang/Nim/blob/devel/lib/system.nim#L2849-L2902
  echoBinSafe(TM__1vqzGCGyH8jPEpAwiaNwvg_2, 1);
  ...
}

// String "Hello Nim!" compiled from Nim to C
static NIM_CONST tyArray__nHXaesL0DJZHyVS07ARPRA TM__1vqzGCGyH8jPEpAwiaNwvg_2 
  = {{10, (NimStrPayload*)&TM__1vqzGCGyH8jPEpAwiaNwvg_3}};

// Actual String for "Hello Nim!"
static const struct { NI cap; NIM_CHAR data[10+1]; } TM__1vqzGCGyH8jPEpAwiaNwvg_3 
  = { 10 | NIM_STRLIT_FLAG, "Hello Nim!" };
```

[(From .nimcache/@mhello_nim_async.nim.c)](https://gist.github.com/lupyuen/4d3f44b58fa88b17ca851decb0419b86#file-mhello_nim_async-nim-c-L198-L203)

[(See the __nimcache__)](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar)

Hence Nim Compiler has produced a __perfectly valid C Program__. That will compile with any C Compiler!

_How will NuttX compile this?_

Nim Compiler generates the code above into the [__`.nimcache`__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar) folder.

Our [__NuttX Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/Makefile#L31-L35) compiles everything inside [__`.nimcache`__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar) with the GCC Compiler...

```bash
## Compile everything in the .nimcache folder
NIMPATH = $(shell choosenim show path)
CFLAGS += -I $(NIMPATH)/lib -I ../../.nimcache
CSRCS  += $(wildcard ../../.nimcache/*.c)
```

And links the Nim Modules (compiled by GCC) into NuttX.

_So Nim Compiler is aware of NuttX?_

Yep! Nim Compiler is internally wired to __produce NuttX Code__ (that GCC will compile correctly)...

- [__Nim Support for NuttX__](https://github.com/nim-lang/Nim/pull/21372/files)

- [__Nim Configuration for NuttX: config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/config.nims)

Kudos to [__centurysys__](https://github.com/centurysys) and the Nim Community for making this possible!

_Everything is hunky dory with Nim on NuttX?_

We made some __Minor Fixes__, we'll upstream to NuttX shortly...

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

Here we see the Nim Compiler working perfectly, [__compiling our program__](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L55-L185) for NuttX (by parsing the [__NuttX Build Config__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nuttx.config))...

```bash
$ export TOPDIR=/workspaces/bookworm/nuttx
$ cd /workspaces/bookworm/apps/examples/hello_nim
$ nim c --header hello_nim_async.nim

read_config: /workspaces/bookworm/nuttx/.config
line=CONFIG_DEBUG_SYMBOLS=y
line=CONFIG_DEBUG_FULLOPT=y
line=CONFIG_ARCH="risc-v"
@["keyval=", "ARCH", "\"risc-v\""]
keyval[1]="risc-v"
line=CONFIG_RAM_SIZE=33554432
* arch:    riscv64
* opt:     oSize
* debug:   true
* ramSize: 33554432
* isSim:   false
Hint: used config file '/home/vscode/.choosenim/toolchains/nim-#devel/config/nim.cfg' [Conf]
Hint: used config file '/home/vscode/.choosenim/toolchains/nim-#devel/config/config.nims' [Conf]
Hint: used config file '/workspaces/bookworm/apps/config.nims' [Conf]
....................................................................................................................................
Hint: mm: orc; opt: size; options: -d:danger
92931 lines; 1.214s; 137.633MiB peakmem; proj: /workspaces/bookworm/apps/examples/hello_nim/hello_nim_async.nim; out: /workspaces/bookworm/apps/.nimcache/hello_nim_async.json [SuccessX]
```

_Isn't Nim supposed to be Memory Safe?_

Yeah so far we're doing Low-Level Coding with NuttX. And the __Nim Memory Safety__ doesn't shine through.

Later when we write __LVGL Graphical Apps__ in Nim, we'll appreciate the [__safety and simplicity__](https://github.com/mantielero/lvgl.nim/blob/main/examples/ex02_label.nim) of Nim...

- [__Nim Wrapper for LVGL Graphics Library__](https://github.com/mantielero/lvgl.nim)

  [(More about __Embedded Nim__)](https://nim-lang.org/docs/nimc.html#nim-for-embedded-systems)

  [(More about __Nim Compiler__)](https://nim-lang.org/docs/nimc.html)

![GPIO 29 in BL808 Reference Manual (Page 119)](https://lupyuen.github.io/images/nim-gpio.jpg)

[_GPIO 29 in BL808 Reference Manual (Page 119)_](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

# LED Driver for Ox64

_Nim Blinky needs an LED Driver for Ox64..._

_What's the Quickest Way to create a NuttX LED Driver?_

[__U-Boot Bootloader__](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96#file-ox64-nuttx-nim-blink-log-L79-L112) can help! Power up Ox64 and press Enter a few times to reveal the __U-Boot Command Prompt__.

We enter these __U-Boot Commands__...

```bash
## Dump the GPIO 29 Register at 0x20000938 (gpio_cfg29)
$ md 0x20000938 1
20000938: 00400803                             ..@.

## Set GPIO 29 Output to 1:
## (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24)
## = 0x1000b40
$ mw 0x20000938 0x1000b40 1

## Dump the GPIO 29 Register to verify
$ md 020000938 1
20000938: 01000b40                             @...

## Set GPIO 29 Output to 0:
## (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24)
## = 0xb40
$ mw 0x20000938 0xb40 1

## Dump the GPIO 29 Register to verify
$ md 0x20000938 1
20000938: 00000b40                             @...
```

And our LED (GPIO 29) will __flip On and Off__!

Thus we have verified the __Magic Bits__ for flipping our LED...

- Write to __GPIO 29 Register__ at __`0x2000` `0938`__ (gpio_cfg29)

- Register Value __`0x100` `0B40`__ will flip the LED On

- Register Value __`0xB40`__ will flip the LED Off

_How did we figure out the Magic Bits for GPIO 29?_

From [__BL808 Reference Manual__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) (Page 56), "Normal GPIO Output Mode"...

- Set __reg_gpio_29_oe__ (Bit 6) to __`1`__ to enable GPIO Output Mode <br>
  = (1 << 6)

- Set __reg_gpio_29_func_sel__ (Bits 8 to 12) to __`11`__ to enter SWGPIO Mode <br>
  = (11 << 8)

- Set __reg_gpio_29_mode__ (Bits 30 to 31) to __`0`__ to enable Normal Output Function of I/O <br>
  = (0 << 30)

- Set __reg_gpio_29_pu__ (Bit 4) and __reg_gpio_29_pd__ (Bit 5) to __`0`__ to disable Internal Pull-Up and Pull-Down functions <br>
  = (0 << 4)

- Set the Pin Level (__`0`__ or __`1`__) through __reg_gpio_29_o__ (Bit 24) <br>
  = Either (0 << 24) Or (1 << 24)

[(__GPIO Bits__ are listed in the pic above)](https://lupyuen.github.io/images/nim-gpio.jpg)

Which means...

- __Set GPIO Output to 0__ <br>
  = (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24) <br>
  = __`0xB40`__

- __Set GPIO Output to 1__ <br>
  = (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24) <br>
  = __`0x100` `0B40`__

And we write the above values to __GPIO 29 Register__ at __`0x2000` `0938`__ (gpio_cfg29)

_How to flip the GPIO in our LED Driver?_

We do this in our __NuttX LED Driver__: [bl808_userleds.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/boards/risc-v/bl808/ox64/src/bl808_userleds.c#L176-L209)

```c
// Flip the LEDs On and Off according to the LED Set
// (Bit 0 = LED 0)
void board_userled_all(uint32_t ledset) {

  // For LED 0 to 2...
  for (int i = 0; i < BOARD_LEDS; i++) {

    // Get the desired state of the LED
    const bool val = ((ledset & g_led_setmap[i]) != 0);

    // If this is LED 0...
    if (i == 0) {

      // Flip it On or Off?
      if (val) {

        // Flip LED 0 (GPIO 29) to On:
        // Set gpio_cfg29 to (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24)
        // mw 0x20000938 0x1000b40 1
        *(volatile uint32_t *) 0x20000938 = 0x1000b40;
      } else {

        // Flip LED 0 (GPIO 29) to Off:
        // Set gpio_cfg29 to (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24)
        // mw 0x20000938 0xb40 1
        *(volatile uint32_t *) 0x20000938 = 0xb40;
      }
    }
  }
}
```

That's how we created a barebones LED Driver for Ox64!

[(Remember to add the __Auto LED Driver__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/boards/risc-v/bl808/ox64/src/bl808_autoleds.c)

[(And update the __Board Kconfig__)](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-60cc096e3a9b22a769602cbbc3b0f5e7731e72db7b0338da04fcf665ed753b64)

[(And start our __LED Driver__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/boards/risc-v/bl808/ox64/src/bl808_appinit.c#L167-L179)

_Ahem it looks a little messy..._

No Worries! Later we'll replace the (awful) code above by the __BL808 GPIO Driver__. Which we'll copy from [__NuttX for BL602__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c)...

```c
// Get the desired state of LED[i]
const bool val = ((ledset & g_led_setmap[i]) != 0);

// Call the BL808 GPIO Driver to flip the LED On or Off
bl808_gpio_write(  // Write to the GPIO Output...
  g_led_map[i],    // GPIO Number for LED[i]
  val              // Flip it On or Off
);
```

_Anything else we patched?_

We fixed the __NuttX Timer__ for Ox64 (otherwise we can't blink)...

- [__"OpenSBI Timer for NuttX"__](https://lupyuen.github.io/articles/nim#appendix-opensbi-timer-for-nuttx)

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Nim blinks our LED](https://lupyuen.github.io/images/nim-blink.jpg)

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

[__lupyuen.github.io/src/nim.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nim.md)

![Nim with Apache NuttX RTOS on QEMU RISC-V (64-bit)](https://lupyuen.github.io/images/nim-qemu.png)

# Appendix: Build NuttX for QEMU

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for QEMU RISC-V (64-bit)__ that has Minor Fixes for Nim...

- [__nsh64/defconfig__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-dd54e0076f30825f912248f2424460e3126c2a8f4e2880709f5c68af9342ddcf): NuttX Config for QEMU

- [__qemu_rv_autoleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-5905dc63d5fd592e0a1e25ab25783ae99e54180a7b98fb59f56a73dee79104e6)
: Auto LED Driver for QEMU

- [__qemu_rv_userleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-a6fd389669ddef88302f00a34d401479886cb8983f7be58b32ba075699cb5bb8): User LED Driver for QEMU

- [__qemu_rv_appinit.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-beeaeb03fa5642002a542446c89251c9a7c5c1681cfe915387740ea0975e91b3): Start LED Driver

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

First we install [__Nim Compiler__](https://nim-lang.org/install_unix.html) (only the Latest Dev Version supports NuttX)...

```bash
## Install Nim Compiler: https://nim-lang.org/install_unix.html
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

## Add Nim to PATH
export PATH=$HOME/.nimble/bin:$PATH

## Select Latest Dev Version of Nim. Will take a while!
choosenim devel --latest
```

[(Nim won't install? Try a __Linux Container__)](https://github.com/lupyuen/nuttx-nim#build-nuttx-with-debian-container-in-vscode)

Then we download and build NuttX for __QEMU RISC-V (64-bit)__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for QEMU RISC-V (64-bit)
cd nuttx
tools/configure.sh rv-virt:nsh64

## Build NuttX
make

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

[(See the __Build Script__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

[(See the __Build Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa)

[(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

This produces the NuttX ELF Image __`nuttx`__ that we may boot on QEMU RISC-V Emulator...

```bash
## Start the QEMU RISC-V Emulator (64-bit) with NuttX RTOS
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

At the NuttX Prompt, enter "__hello_nim__"...

```text
nsh> hello_nim
Hello Nim!
Opening /dev/userleds
```

[(Enter "__help__" to see the available commands)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L472-L497)

Nim on NuttX blinks our __Simulated LED__...

```text
Set LED 0 to 1
board_userled_all: led=0, val=1
Waiting...

Set LED 0 to 0
board_userled_all: led=0, val=0
Waiting...

Set LED 0 to 1
board_userled_all: led=0, val=1
Waiting...
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L210-L471)

To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Works great with Nim!](https://lupyuen.github.io/images/nim-ox64.png)

# Appendix: Build NuttX for Ox64

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__ that has Minor Fixes for Nim...

- [__nsh/defconfig__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-fa4b30efe1c5e19ba2fdd2216528406d85fa89bf3d2d0e5161794191c1566078): NuttX Config for Ox64

- [__bl808_timerisr.c__](https://lupyuen.github.io/articles/nim#appendix-opensbi-timer-for-nuttx): RISC-V Timer for Ox64

- [__bl808_autoleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-efdf5ed87983905c7021de03a7add73932da529d4312b80f948eb199c256b170): Auto LED Driver for Ox64

- [__bl808_userleds.c__](https://lupyuen.github.io/articles/nim#led-driver-for-ox64): User LED Driver for Ox64

- [__bl808_appinit.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-902a3cb106dc7153d030370077938ef28c9412d8b3434888fca8bbf1a1cfbd54): Start LED Driver for Ox64

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

First we install [__Nim Compiler__](https://nim-lang.org/install_unix.html) (only the Latest Dev Version supports NuttX)...

```bash
## Install Nim Compiler: https://nim-lang.org/install_unix.html
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

## Add Nim to PATH
export PATH=$HOME/.nimble/bin:$PATH

## Select Latest Dev Version of Nim. Will take a while!
choosenim devel --latest
```

[(Nim won't install? Try a __Linux Container__)](https://github.com/lupyuen/nuttx-nim#build-nuttx-with-debian-container-in-vscode)

Then we download and build NuttX for __Ox64 BL808 SBC__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for Ox64 BL808 RISC-V SBC
cd nuttx
tools/configure.sh ox64:nsh

## Build NuttX
make

## Export the NuttX Kernel
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## Dump the hello_nim disassembly to hello_nim.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin/hello_nim \
  >hello_nim.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

Then we build the __Initial RAM Disk__ that contains NuttX Shell and NuttX Apps...

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.pad

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image
```

[(See the __Build Script__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)

[(See the __Build Log__)](https://gist.github.com/lupyuen/578a7eb2d4d827aa252fff37c172dd18)

[(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)

This produces the NuttX Image: __`Image`__

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

Then we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Copy the __`Image`__ file (from above) and overwrite the __`Image`__ in the Linux microSD...

```bash
## Overwrite the Linux Image
## on Ox64 microSD
cp Image \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH).

At the NuttX Prompt, enter "__hello_nim__"...

```text
nsh> hello_nim
Hello Nim!
Opening /dev/userleds

Set LED 0 to 1
board_userled_all: led=0, val=1
Waiting...

Set LED 0 to 0
board_userled_all: led=0, val=0
Waiting...
```

[(Enter "__help__" to see the available commands)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L472-L497)

Nim on NuttX [__blinks our LED__](https://lupyuen.github.io/images/nim-blink.jpg).

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96)

[(Watch the __Demo on YouTube__)](https://youtube.com/shorts/KCkiXFxBgxQ)

[(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)

![OpenSBI Supervisor Binary Interface](https://lupyuen.github.io/images/privilege-title.jpg)

# Appendix: OpenSBI Timer for NuttX

_The `sleep` command hangs in NuttX Shell. How to fix it?_

That's because we haven't implemented the __RISC-V Timer__ for Ox64! We should call [__OpenSBI Supervisor Binary Interface__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358#toc-bare-metal-experiments-8) to handle the Timer...

- [__Fix RISC-V Timer for Ox64__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/57ea5f000636f739ac3cb8ea1e60936798f6c3a9#diff-535879ffd6d9fc8e7d84b37a88bdeb1609c4a90e3777150939a96bed18696aee)

  (Ignore [riscv_mtimer.c](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/57ea5f000636f739ac3cb8ea1e60936798f6c3a9#diff-922834c58227800347b4486fa310c3570cd4014f200ac5ea0cd2e40764cefac4))

We only need to change the __Timer Initialisation__: [bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L116)

```c
// Timer Frequency
#define MTIMER_FREQ 1000000

// This function is called during start-up to initialize the timer interrupt.
void up_timer_initialize(void) {
  struct oneshot_lowerhalf_s *lower = riscv_mtimer_initialize(
    0, 0, RISCV_IRQ_STIMER, MTIMER_FREQ);
  DEBUGASSERT(lower);
  up_alarm_set_lowerhalf(lower);
}
```

How it works: At startup, [__up_timer_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L98-L116) (above) calls...

- [__riscv_mtimer_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/riscv_mtimer.c#L318-L332) which calls...

- [__riscv_mtimer_set_mtimecmp__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/riscv_mtimer.c#L136-L141) which calls...

- [__riscv_sbi_set_timer__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/supervisor/riscv_sbi.c#L94-L107) which calls...

- [__sbi_ecall__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/supervisor/riscv_sbi.c#L53-L76) which makes an ecall to OpenSBI

- Which accesses the __RISC-V System Timer__

Originally we set __MTIMER_FREQ__ to `10000000`: [bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L48)

```c
#define MTIMER_FREQ 10000000
```

But this causes the command __`sleep 1`__ to pause for 10 seconds. So we divide the frequency by 10: [bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L48)

```c
#define MTIMER_FREQ 1000000
```

Now the __`sleep`__ command works correctly in NuttX Shell! Here's the log (ignore the errors)...

- [__`sleep` works OK on Ox64__](https://gist.github.com/lupyuen/8aa66e7f88d1e31a5f198958c15e4393)
