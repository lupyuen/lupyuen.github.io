# Nim on a Real-Time Operating System: Apache NuttX RTOS + Ox64 BL808 SBC

📝 _7 Jan 2024_

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Works great with Nim!](https://lupyuen.github.io/images/nim-ox64.png)

Happy New Year! 2024 is here and we're running [__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (Real-Time Operating System) on Single-Board Computers with __plenty of RAM__...

Like [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V SBC with 64 MB RAM! (Pic below)

_How will we use the Plentiful RAM?_

In this article, we create a __Blinky LED__ app with a Modern, [__Garbage-Collected__](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)) Language: [__Nim Programming Language__](https://nim-lang.org).

Garbage-Collected Languages (like Nim) require __a bit more RAM__ than Low-Level Languages (like C). Perfect for our roomy SBC!

_But we need a RISC-V SBC?_

No worries! We'll run Nim + NuttX on the __QEMU Emulator__ for 64-bit RISC-V. Which works great on Linux, macOS and Windows machines.

Everything that happens on Ox64 SBC, we'll see the __exact same thing__ in QEMU! (Except the blinkenlight)

_Hmmm Garbage Collection... Won't it run-pause-run-pause?_

The fine folks at [__Wilderness Labs__](https://www.wildernesslabs.co/) are running [__.NET on NuttX__](https://www.wildernesslabs.co/developers) with Garbage Collection. Maybe it's not so bad!

(Also check out __TinyGo__ and __MicroPython__)

_How is Nim different from Rust and Zig?_

We've tested [__Rust__](https://lupyuen.github.io/articles/rusti2c) and [__Zig__](https://lupyuen.github.io/articles/lvgl4) with NuttX. __Nim is different__ because it...

- __Compiles to C__ (instead of Machine Code)

- Syntax is __Python-like__ (but Statically Compiled)

- Automatic __Garbage Collection__ (no Borrow Checker)

- And it's __Memory Safe__ (like Rust)

TODO

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

# Basic Nim from scratch

_(3 languages in a title heh heh)_

This is the __simplest Nim Program__ (that will run on NuttX): [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L56-L65)

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

And Nim works with [__Garbage Collection__](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)). Thus we call __GC_runOrc__ to force the Garbage Collection to complete, clean up all remaining Nim Objects, before returning to C and NuttX.

_What if we forget to call GC_runOrc?_

Erm don't! To make it unforgettable, we __`defer`__ the Garbage Collection: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L56-L65)

```nim
## Main Function in Nim
proc hello_nim() {.exportc, cdecl.} =

  ## On Return: Force the Garbage Collection
  defer: GC_runOrc()

  ## Print something
  echo "Hello Nim!"
```

__`defer`__ ensures that the Garbage Collection __will always happen__, as soon as we return from the Main Function.

Now we do something cool and enlightening...

![Blink an LED with Nim](https://lupyuen.github.io/images/nim-code.png)

# Blink an LED

This is how we __blink an LED__ with Nim on NuttX: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L21-L56)

```nim
## Blink the LED
proc blink_led() =

  ## Open the LED Driver
  echo "Opening /dev/userleds"
  let fd = c_open("/dev/userleds", O_WRONLY)

  ## Check the File Descriptor for errors
  if fd < 0:
    echo "Failed to open /dev/userleds"
    return
```

First we call the NuttX Function __`open`__ to access the __LED Driver__.

We might forget to __`close`__ the LED Driver (in case of errors), so we __`defer`__ the closing...

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

__ULEDIOC_SETALL__ accepts a Bit Mask of LED States. The value __`1`__ says LED 0 (Bit 0) will be flipped On. (Other LEDs will be flipped Off)

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

In our [__Main Function__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L56-L69): We call the above function __20 times__...

```nim
## Main Function in Nim
proc hello_nim() {.exportc, cdecl.} =

  ## On Return: Force the Garbage Collection
  defer: GC_runOrc()

  ## Blink the LED 20 times
  for loop in 0..19:
    blink_led()
```

TODO: Looks very similar to C

And we're almost done! Nim needs to discover our NuttX Functions...

# Import NuttX Functions

_How will Nim know about open / close / ioctl / usleep?_

We __import the NuttX Functions__ from C into Nim: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L1-L21)

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

(__discardable__ tells Nim Compiler that the Return Value is optional)

(__nodecl__ means don't emit the C Declaration in the Generated Code)

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

# Run Nim on QEMU

TODO: We begin by __booting NuttX RTOS__ on RISC-V QEMU Emulator (64-bit)...

1.  Install [__QEMU Emulator for RISC-V (64-bit)__](https://www.qemu.org/download/)...

    ```bash
    ## For macOS:
    brew install qemu

    ## For Debian and Ubuntu:
    sudo apt install qemu-system-riscv64
    ```

1.  TODO: Download __`nuttx`__ from the [__NuttX Release__](https://github.com/lupyuen/lupyuen.github.io/releases/tag/nuttx-riscv64)...

    TODO: [__nuttx: NuttX Image for 64-bit RISC-V QEMU__](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx)

    TODO: If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

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

1.  NuttX is now running in the QEMU Emulator! (Pic below)

    ```text
    uart_register: Registering /dev/console
    uart_register: Registering /dev/ttyS0
    nx_start_application: Starting init thread

    NuttShell (NSH) NuttX-12.1.0-RC0
    nsh> nx_start: CPU0: Beginning Idle Loop
    nsh>
    ```

    TODO: [(See the Complete Log)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

1.  TODO: hello_nim

1.  TODO: Enter "__help__" to see the available commands...

    ```text
    nsh> help
    help usage:  help [-v] [<cmd>]

        .         break     dd        exit      ls        ps        source    umount
        [         cat       df        false     mkdir     pwd       test      unset
        ?         cd        dmesg     free      mkrd      rm        time      uptime
        alias     cp        echo      help      mount     rmdir     true      usleep
        unalias   cmp       env       hexdump   mv        set       truncate  xd
        basename  dirname   exec      kill      printf    sleep     uname

    Builtin Apps:
        nsh     ostest  sh
    ```

1.  TODO: NuttX works like a tiny version of Linux, so the commands will look familiar...

    ```text
    nsh> uname -a
    NuttX 12.1.0-RC0 275db39 Jun 16 2023 20:22:08 risc-v rv-virt

    nsh> ls /dev
    /dev:
    console
    null
    ttyS0
    zero

    nsh> ps
      PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK           STACK   USED  FILLED COMMAND
        0     0   0 FIFO     Kthread N-- Ready              0000000000000000 002000 001224  61.2%  Idle Task
        1     1 100 RR       Task    --- Running            0000000000000000 002992 002024  67.6%  nsh_main
    ```

    [(See the Complete Log)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

1.  To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

TODO: Wiring pic

# Nim Blinky on Ox64

_Will Nim Blinky run on a real RISC-V SBC?_

Yep! Connect an LED to Ox64 at __GPIO 29, Pin 21__ (pic above)...

| Connect | To | Wire |
|:-----|:---|:-----|
| __Ox64 Pin 21__ | __LED +__ _(Curved)_ | Red |
| __LED -__ _(Flat)_ | __Resistor__ | Breadboard
| __Resistor__ | __Ox64 GND__ | Black 

[(See the __Ox64 Pinout__)](https://wiki.pine64.org/wiki/File:Ox64_pinout.png)

(Resistor is __47 Ohm__, yellow-purple-black-gold, almost Karma Chameleon)

TODO

# Inside Nim on NuttX

_Nim runs incredibly well on NuttX. How is that possible?_

That's because __Nim compiles to C__. As far as NuttX is concerned...

Nim looks like __another C Program!__

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

Into this [__C Program__](https://gist.github.com/lupyuen/4d3f44b58fa88b17ca851decb0419b86#file-mhello_nim_async-nim-c-L130-L146)...

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

[(From .nimcache/@mhello_nim_async.nim.c)](https://gist.github.com/lupyuen/4d3f44b58fa88b17ca851decb0419b86#file-mhello_nim_async-nim-c-L130-L146)

[(See the nimcache)](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar)

Yep Nim Compiler has produced a perfectly valid C Program. That will compile with any C Compiler!

_How will NuttX compile this?_

Nim Compiler generates the code above into the [__`.nimcache`__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar) folder.

Our [__NuttX Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/Makefile#L31-L35) compiles everything inside [__`.nimcache`__](https://github.com/lupyuen/nuttx-nim/releases/download/ox64-1/nimcache.tar) with the GCC Compiler...

```text
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

Here we see the Nim Compiler working perfectly, compiling our program for NuttX (by parsing the NuttX Build Config)...

```text
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

![GPIO 29 in BL808 Reference Manual (Page 119)](https://lupyuen.github.io/images/nim-gpio.jpg)

[_GPIO 29 in BL808 Reference Manual (Page 119)_](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

# LED Driver for Ox64

_Our Nim Experiment needs an LED Driver for Ox64..._

_What's the Quickest Way to create a NuttX LED Driver?_

__U-Boot Bootloader__ can help! Power up Ox64 and press Enter a few times to reveal the __U-Boot Command Prompt__.

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

From [__BL808 Reference Manual__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) Page 56, "Normal GPIO Output Mode"...

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
    bool val = ((ledset & g_led_setmap[i]) != 0);

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

TODO: How NuttX starts our __LED Driver__

TODO: Remember to add the __Auto-LED Driver__

_Ahem it looks a little messy..._

TODO: No Worries! Later we'll replace the (awful) code above by the __BL808 GPIO Driver__. Which we'll copy from __NuttX for BL602__.

```c
TODO: GPIO
```

_Anything else we patched?_

TODO: RISC-V Timer

![Nim App runs OK on Apache NuttX Real-Time Operating System and Ox64 BL808 RISC-V SBC](https://lupyuen.github.io/images/nim-ox64.png)

# Documentation

TODO

- [NuttX support for Nim](https://github.com/apache/nuttx-apps/pull/1597)

- [Nim support for NuttX](https://github.com/nim-lang/Nim/pull/21372/files)

- [For Nuttx, change ioselectors to use "select"](https://github.com/nim-lang/Nim/pull/21384)

- [Which implementation of NuttX select/poll/EPOLL is recommended in terms of performance and efficiency](https://github.com/apache/nuttx/issues/8604)

- [Nim on Arduino](https://disconnected.systems/blog/nim-on-adruino/)

- [Nim for Embedded Systems](https://github.com/nim-lang/Nim/blob/devel/doc/nimc.md#nim-for-embedded-systems)

- [Nim Compiler User Guide](https://nim-lang.org/docs/nimc.html)

- [Nim Wrapper for LVGL](https://github.com/mantielero/lvgl.nim)

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

# Appendix: RISC-V Timer with OpenSBI

TODO

_The `sleep` command hangs in NuttX Shell. How to fix it?_

That's because we haven't implemented the RISC-V Timer for Ox64! We should call OpenSBI to handle the Timer, [here's the fix](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/57ea5f000636f739ac3cb8ea1e60936798f6c3a9#diff-535879ffd6d9fc8e7d84b37a88bdeb1609c4a90e3777150939a96bed18696aee).

(Ignore riscv_mtimer.c, we were verifying that mtime and mtimecmp are unused in Kernel Mode)

We only need to change [arch/risc-v/src/bl808/bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L116)

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

How it works: At startup, `up_timer_initialize` (above) calls...

- [riscv_mtimer_initialize](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/riscv_mtimer.c#L318-L332) which calls...

- [riscv_mtimer_set_mtimecmp](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/riscv_mtimer.c#L136-L141) which calls...

- [riscv_sbi_set_timer](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/supervisor/riscv_sbi.c#L94-L107) which calls...

- [sbi_ecall](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/common/supervisor/riscv_sbi.c#L53-L76) which makes an ecall to OpenSBI

- Which accesses the System Timer

Originally we set MTIMER_FREQ to 10000000: [bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L48)

```c
#define MTIMER_FREQ 10000000
```

But this causes the command `sleep 1` to pause for 10 seconds. So we divide the frequency by 10: [bl808_timerisr.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/arch/risc-v/src/bl808/bl808_timerisr.c#L44-L48)

```c
#define MTIMER_FREQ 1000000
```

Now the `sleep` command works correctly in NuttX Shell!

[Here's the log (ignore the errors)](https://gist.github.com/lupyuen/8aa66e7f88d1e31a5f198958c15e4393)

# Appendix: Build NuttX for QEMU

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for QEMU RISC-V (64-bit)__ that has Minor Fixes for Nim...

- TODO: LED Driver for QEMU

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

This is how we download and build NuttX for __QEMU RISC-V (64-bit)__...

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

This produces the NuttX ELF Image __nuttx__ that we may boot on QEMU RISC-V Emulator...

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

TODO: [(See the __NuttX Log__)](https://gist.github.com/lupyuen/eda07e8fb1791e18451f0b4e99868324)

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/l7Y36nTkr8c)

# Appendix: Build NuttX for Ox64

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__ that has Minor Fixes for Nim...

- TODO: LED Driver for Ox64

- TODO: RISC-V Timer for Ox64

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

This is how we download and build NuttX for __Ox64 BL808 SBC__...

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
riscv-none-elf-objdump \
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

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

Then we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Overwrite the microSD Linux Image by the __NuttX Kernel__...

```bash
## Overwrite the Linux Image
## on Ox64 microSD
cp Image \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH).

TODO: [(See the __NuttX Log__)](https://gist.github.com/lupyuen/eda07e8fb1791e18451f0b4e99868324)

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/l7Y36nTkr8c)

[(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)
