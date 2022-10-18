# Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS

📝 _2 Jun 2022_

![Zig runs on BL602 with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-title.jpg)

[__Zig__](https://ziglang.org) is a general-purpose language for maintaining __robust, optimal, and reusable software__.

[__BL602__](https://lupyuen.github.io/articles/pinecone) is a __32-bit RISC-V SoC__ with WiFi and Bluetooth LE.

Let's run __Zig on BL602!__

_We're running Zig bare metal on BL602?_

Not quite. We'll need more work to get Zig talking to __BL602 Hardware__ and printing to the console.

Instead we'll run Zig on top of a __Real-Time Operating System__ (RTOS): [__Apache NuttX__](https://lupyuen.github.io/articles/nuttx).

_Zig on BL602 should be a piece of cake right?_

Well __Zig on RISC-V__ is kinda newish, and might present interesting new challenges.

In a while I'll explain the strange hack I did to run __Zig on BL602__...

-   [__lupyuen/zig-bl602-nuttx__](https://github.com/lupyuen/zig-bl602-nuttx)

_Why are we doing all this?_

Later below I'll share my thoughts about __Embedded Zig__ and how we might use Zig to maintain __Complex IoT Apps__. (Like for LoRa and LoRaWAN)

I'm totally new to Zig, please bear with me as I wade through the water and start swimming in Zig! 🙏

![Zig App bundled with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-code1a.png)

# Zig App

Below is the __barebones Zig App__ that's bundled with Apache NuttX RTOS. We'll run this on BL602: [hello_zig_main.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/hello_zig_main.zig)

```zig
//  Import the Zig Standard Library
const std = @import("std");

//  Import printf() from C
pub extern fn printf(
  _format: [*:0]const u8
) c_int;

//  Main Function
pub export fn hello_zig_main(
  _argc: c_int, 
  _argv: [*]const [*]const u8
) c_int {
  _ = _argc;
  _ = _argv;
  _ = printf("Hello, Zig!\n");
  return 0;
}
```

[(We tweaked the code slightly)](https://github.com/lupyuen/zig-bl602-nuttx#zig-app-for-nuttx)

The code above prints to the NuttX Console...

```text
Hello, Zig!
```

Let's dive into the Zig code.

![Zig on BL602](https://lupyuen.github.io/images/book-zig.jpg)

## Import Standard Library

We begin by importing the [__Zig Standard Library__](https://ziglang.org/documentation/master/#Zig-Standard-Library)...

```zig
//  Import the Zig Standard Library
const std = @import("std");
```

Which has all kinds of __Algos, Data Structures and Definitions__.

[(More about the Zig Standard Library)](https://ziglang.org/documentation/master/std/)

## Import printf

Next we cross into the grey zone between __Zig and C__...

```zig
//  Import printf() from C
pub extern fn printf(
  _format: [*:0]const u8
) c_int;
```

Here we import the __`printf()`__ function from the C Standard Library.

(Which is supported by NuttX because it's [__POSIX-Compliant__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance))

_What's `[*:0]const u8`?_

That's how we declare __C Strings__ in Zig...

|   |   |
|:--:|:--|
| __`[*:0]`__    | Pointer to a Null-Terminated Array... |
| __`const u8`__ | Of Constant Unsigned Bytes |
| &nbsp; | &nbsp; |

Which feels like "`const char *`" in C, but more expressive.

Zig calls this a [__Sentinel-Terminated Pointer__](https://ziglang.org/documentation/master/#Sentinel-Terminated-Pointers).

(That's because it's Terminated by the Null Sentinel, not because of "The Matrix")

_Why is the return type `c_int`?_

This says that __`printf()`__ returns an __`int`__ that's compatible with C. [(See this)](https://ziglang.org/documentation/master/#Primitive-Types)

## Main Function

NuttX expects our Zig App to export a __Main Function__ that follows the C Convention. So we so this in Zig...

```zig
//  Main Function
pub export fn hello_zig_main(
  _argc: c_int, 
  _argv: [*]const [*]const u8
) c_int {
```

__`argc`__ and __`argv`__ should look familiar, though __`argv`__ looks complicated...

-   "__`[*]const u8`__" is a Pointer to an Unknown Number of Constant Unsigned Bytes

    (Like "`const uint8_t *`" in C)

-   "__`[*]const [*]const u8`__" is a Pointer to an Unknown Number of the above Pointers

    (Like "`const uint8_t *[]`" in C)

    [(More about Zig Pointers)](https://ziglang.org/documentation/master/#Pointers)

Inside the Main Function, we call __`printf()`__ to print a string...

```zig
  _ = _argc;
  _ = _argv;
  _ = printf("Hello, Zig!\n");
  return 0;
```

_Why the "`_ = something`"?_

This tells the Zig Compiler that we're __not using the value__ of "`something`".

The Zig Compiler helpfully stops us if we forget to use a Variable (like `_argc`) or the Returned Value for a Function (like for `printf`).

_Doesn't Zig have its own printf?_

Yep we should call __`std.log.debug()`__ instead of __`printf()`__. See this...

-   [__"Zig Logging"__](https://github.com/lupyuen/zig-bl602-nuttx#logging)

_Did we forget something?_

For simplicity we excluded the __Variable Arguments__ for __`printf()`__.

Our declaration for __`printf()`__ specifies only one parameter: the __Format String__. So it's good for printing one unformatted string.

[(Here's the full declaration)](https://ziglang.org/documentation/master/#Sentinel-Terminated-Pointers)

![Enable Zig App in NuttX](https://lupyuen.github.io/images/zig-config1a.png)

# Enable Zig App

We're ready to __build our Zig App__ in NuttX! 

Follow these steps to __download and configure NuttX__ for BL602...

-   [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/nuttx#build-nuttx)

To __enable the Zig App__ in NuttX, we do this...

```bash
make menuconfig
```

And select __"Application Configuration"__ → __"Examples"__ → __"Hello Zig Example"__. (See pic above)

Save the configuration and exit menuconfig.

Something interesting happens when we build NuttX...

![Build fails on NuttX](https://lupyuen.github.io/images/zig-build1a.png)

# Build Fails on NuttX

When we __build NuttX__ with the Zig App...

```bash
make
```

We'll see this error (pic above)...

```text
LD: nuttx
riscv64-unknown-elf-ld: nuttx/staging/libapps.a(builtin_list.c.home.user.nuttx.apps.builtin.o):(.rodata.g_builtins+0xbc): 
undefined reference to `hello_zig_main'
```

[(Source)](https://gist.github.com/lupyuen/497c90b862aef48b57ff3124f2ea94d8)

Which is probably due to some __incomplete Build Rules__ in the NuttX Makefiles. [(See this)](https://github.com/apache/incubator-nuttx/issues/6219)

But no worries! Let's compile the Zig App ourselves and link it into the NuttX Firmware.

# Compile Zig App

Follow these steps to install the __Zig Compiler__...

-   [__"Zig: Getting Started"__](https://ziglang.org/learn/getting-started/)

This is how we __compile our Zig App__ for BL602 and link it with NuttX...

```bash
##  Download our modified Zig App for NuttX
git clone --recursive https://github.com/lupyuen/zig-bl602-nuttx
cd zig-bl602-nuttx

##  Compile the Zig App for BL602 
##  (RV32IMACF with Hardware Floating-Point)
zig build-obj \
  -target riscv32-freestanding-none \
  -mcpu sifive_e76 \
  hello_zig_main.zig

##  Copy the compiled app to NuttX and overwrite `hello_zig.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello_zig/*hello_zig.o

##  Build NuttX to link the Zig Object from `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

Note that we specify __"`build-obj`"__ when compiling our Zig App.

This generates a __RISC-V Object File__ `hello_zig_main.o` that will be linked into our NuttX Firmware.

Let's talk about the Zig Target, which looks especially interesting for RISC-V...

![Compile Zig App for BL602](https://lupyuen.github.io/images/zig-build3a.png)

# Zig Target

_Why is the Zig Target riscv32-freestanding-none?_

Zig Targets have the form "_(arch)(sub)_-_(os)_-_(abi)_"...

-   __`riscv32`__: Because BL602 is a 32-bit RISC-V processor

-   __`freestanding`__: Because Embedded Targets don't need an OS

-   __`none`__: Because Embedded Targets don't specify the ABI

[(More about Zig Targets)](https://ziglang.org/documentation/master/#Targets)

_Why is the Target CPU sifive_e76?_

BL602 is designated as __RV32IMACF__...

| Designation | Meaning |
|:---:|:---|
| __`RV32I`__ | 32-bit RISC-V with Base Integer Instructions
| __`M`__ | Integer Multiplication + Division
| __`A`__ | Atomic Instructions
| __`C`__ | Compressed Instructions
| __`F`__ | Single-Precision Floating-Point

[(Source)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

Among all Zig Targets, only __`sifive_e76`__ has the same designation...

```bash
$ zig targets
...
"sifive_e76": [ "a", "c", "f", "m" ],
```

[(Source)](https://gist.github.com/lupyuen/09d64c79e12b30e5eebc7d0a9c3b20a4)

Thus we use __`sifive_e76`__ as our Target CPU.

Or we may use __`baseline_rv32-d`__ as our Target CPU...

```bash
##  Compile the Zig App for BL602
##  (RV32IMACF with Hardware Floating-Point)
zig build-obj \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  hello_zig_main.zig
```

That's because...

-   "__`baseline_rv32`__" means __RV32IMACFD__

    ("D" for Double-Precision Floating-Point)

-   "__`-d`__" means remove the Double-Precision Floating-Point ("D")

    (But keep the Single-Precision Floating-Point)

    [(More about RISC-V Feature Flags for Zig. Thanks Matheus!)](https://github.com/lupyuen/zig-bl602-nuttx/issues/1)

Now comes another fun challenge, with a weird hack...

![Floating-Point ABI issue](https://lupyuen.github.io/images/zig-build2a.png)

# Floating-Point ABI

_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_

When we __link the Compiled Zig App__ with NuttX, we see this error (pic above)...

```bash
##  Build NuttX to link the Zig Object from `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
$ cd $HOME/nuttx/nuttx
$ make
...
riscv64-unknown-elf-ld: nuttx/staging/libapps.a(hello_main.c.home.user.nuttx.apps.examples.hello.o): 
can't link soft-float modules with single-float modules
```

_What is the meaning of this Soft-Float vs Single-Float? (Milk Shake?)_

Let's sniff the __NuttX Object Files__ produced by the NuttX Build...

```bash
##  Dump the ABI for the compiled NuttX code.
##  Do this BEFORE overwriting hello.o by hello_zig_main.o.
##  "*hello_zig.o" expands to something like "hello_main.c.home.user.nuttx.apps.examples.hello_zig.o"
$ riscv64-unknown-elf-readelf -h -A $HOME/nuttx/apps/examples/hello_zig/*hello_zig.o
ELF Header:
  Flags: 0x3, RVC, single-float ABI
  ...
File Attributes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

[(Source)](https://gist.github.com/lupyuen/5c090dead49eb50751578f28c15cecd5)

![NuttX was compiled for (Single-Precision) Hardware Floating-Point ABI](https://lupyuen.github.io/images/zig-abi1a.png)

The [__ELF Header__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header) says that the NuttX Object Files were compiled for the (Single-Precision) __Hardware Floating-Point__ ABI (Application Binary Interface).

[(NuttX compiles with the GCC Flags "`-march=rv32imafc -mabi=ilp32f`")](https://gist.github.com/lupyuen/288c980fdef75c334d32e669a921e623)

Whereas our __Zig Compiler__ produces an Object File with __Software Floating-Point__ ABI...

```bash
##  Dump the ABI for the compiled Zig app
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
ELF Header:
  Flags: 0x1, RVC, soft-float ABI
  ...
File Attributes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

[(Source)](https://gist.github.com/lupyuen/f04386a0b94ed1fb42a94d671edb1ba7)

![Zig Compiler produces an Object File with Software Floating-Point ABI](https://lupyuen.github.io/images/zig-abi2a.png)

GCC won't let us link Object Files with __different ABIs__: Software Floating-Point vs Hardware Floating-Point!

Let's fix this with a quick hack...

(Why did the Zig Compiler produce an Object File with Software Floating-Point ABI, when `sifive_e76` supports Hardware Floating-Point? [See this](https://www.reddit.com/r/Zig/comments/v2zgvh/comment/iavw5xp/?utm_source=share&utm_medium=web2x&context=3))

# Patch ELF Header

Earlier we discovered that the Zig Compiler generates an Object File with __Software Floating-Point__ ABI (Application Binary Interface)...

```bash
##  Dump the ABI for the compiled Zig app
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
...
Flags: 0x1, RVC, soft-float ABI
Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

But this won't link with NuttX because NuttX was compiled with __Hardware Floating-Point__ ABI.

We fix this by modifying the __ELF Header__...

-   Edit __`hello_zig_main.o`__ in a Hex Editor

    [(Like VSCode Hex Editor)](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor)

-   Change byte __`0x24`__ (Flags) from __`0x01`__ (Soft Float) to __`0x03`__ (Hard Float)

    [(See this)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header)

![Patch the ELF Header](https://lupyuen.github.io/images/zig-hex2a.png)

We verify that the Object File has been changed to __Hardware Floating-Point__ ABI...

```bash
##  Dump the ABI for the modified object file
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
...
Flags: 0x3, RVC, single-float ABI
Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

This is now __Hardware Floating-Point__ ABI and will link with NuttX.

_Is it really OK to change the ABI like this?_

Well technically the __ABI is correctly generated__ by the Zig Compiler...

```bash
##  Dump the ABI for the compiled Zig app
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
...
Flags: 0x1, RVC, soft-float ABI
Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

The last line translates to __RV32IMACF__, which means that the RISC-V Instruction Set is indeed targeted for __Hardware Floating-Point__. 

We're only editing the __ELF Header__, because it didn't seem to reflect the correct ABI for the Object File.

_Is there a proper fix for this?_

In future the Zig Compiler might allow us to specify the __Floating-Point ABI__ as the target...

```bash
##  Compile the Zig App for BL602
##  ("ilp32f" means Hardware Floating-Point ABI)
zig build-obj \
  -target riscv32-freestanding-ilp32f \
  ...
```

[(See this)](https://github.com/ziglang/zig/issues/9760#issuecomment-991738757)

_Can we patch the Object File via Command Line instead?_

Yep enter this at the Command Line to __patch the ELF Header__...

```bash
xxd -c 1 hello_zig_main.o \
  | sed 's/00000024: 01/00000024: 03/' \
  | xxd -r -c 1 - hello_zig_main2.o
cp hello_zig_main2.o hello_zig_main.o
```

This generates the Patched Object File at `hello_zig_main2.o`

[(More about `xxd`)](https://www.tutorialspoint.com/unix_commands/xxd.htm)

![Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

[_Pine64 PineCone BL602 RISC-V Board_](https://lupyuen.github.io/articles/pinecone)

# Zig Runs OK!

We're ready to link the __Patched Object File__ with NuttX...

```bash
##  Copy the modified object file to NuttX and overwrite `hello_zig.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello_zig/*hello_zig.o

##  Build NuttX to link the Zig Object from `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

Finally our NuttX Build succeeds!

Follow these steps to __flash and boot NuttX__ on BL602...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

In the NuttX Shell, enter __`hello_zig`__

```text
NuttShell (NSH) NuttX-10.3.0-RC2

nsh> hello_zig
Hello, Zig!
```

Yep Zig runs OK on BL602 with NuttX! 🎉

![Zig runs on BL602 with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-title.jpg)

And that's it for our (barebones) Zig Experiment today!

Let's talk about building real-world Embedded and IoT Apps with Zig...

![Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left) over SPI](https://lupyuen.github.io/images/spi2-title.jpg)

[_Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left) over SPI_](https://lupyuen.github.io/articles/spi2)

# Embedded Zig

_Will Zig run on Bare Metal? Without an RTOS like NuttX?_

Yep it can! Check out this project that runs __Bare Metal Zig__ on the HiFive1 RISC-V board...

-   [__nmeum/zig-riscv-embedded__](https://github.com/nmeum/zig-riscv-embedded)

_Can we build cross-platform Embedded Apps in Zig with GPIO, I2C, SPI, ...?_

We're not quite there yet, but the [__Zig Embedded Group__](https://microzig.tech) is creating a __Common Interface and Hardware Abstraction Layer__ for Embedded Platforms...

-   [__ZigEmbeddedGroup/microzig__](https://github.com/ZigEmbeddedGroup/microzig)

With the [__microzig Library__](https://github.com/ZigEmbeddedGroup/microzig), someday we might __blink the LED__ like so...

```zig
//  Import microzig library
const micro = @import("microzig");

//  Blink the LED
pub fn main() void {
  //  Open the LED GPIO at "/dev/gpio1"
  const led_pin = micro.Pin("/dev/gpio1");

  //  Configure the LED GPIO for Output
  const led = micro.Gpio(led_pin, .{
    .mode = .output,
    .initial_state = .low,
  });
  led.init();

  //  Loop forever blinking the LED
  while (true) {
    busyloop();
    led.toggle();
  }
}

//  Wait a short while
fn busyloop() void {
  const limit = 100_000;

  var i: u24 = 0;
  while (i < limit) : (i += 1) {
    @import("std").mem.doNotOptimizeAway(i);
  }
}
```

(Adapted from [blinky.zig](https://github.com/ZigEmbeddedGroup/microzig/blob/master/tests/blinky.zig))

_But our existing firmware is all in C. Do we rewrite everything in Zig?_

Aha! Here comes the really interesting thing about Zig, read on to find out...

![Pine64 PineDio Stack BL604 (left) talking LoRaWAN to RAKwireless WisGate (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

[_Pine64 PineDio Stack BL604 (left) talking LoRaWAN to RAKwireless WisGate (right)_](https://lupyuen.github.io/articles/lorawan3)

# Why Zig?

_Why are we doing all this with Zig instead of C?_

Here's why...

> "Zig has `zig cc` and `zig c++`, two commands that expose an interface flag-compatible with clang, allowing you to use the Zig compiler as a __drop-in replacement for your existing C/C++ compiler__."

> [(Source)](https://zig.news/kristoff/compile-a-c-c-project-with-zig-368j)

Because of this, Zig works great for __maintaining complex C projects__...

-   [__"Maintain it With Zig"__](https://kristoff.it/blog/maintain-it-with-zig)

-   [__"Compile a C/C++ Project with Zig"__](https://zig.news/kristoff/compile-a-c-c-project-with-zig-368j)

-   [__"Extend a C/C++ Project with Zig"__](https://zig.news/kristoff/extend-a-c-c-project-with-zig-55di)

-   [__"How serious (is) Zig about replacing C?"__](https://www.reddit.com/r/Zig/comments/urifjd/how_serious_zig_about_replacing_c/?utm_medium=android_app&utm_source=share)

Thus we might enjoy the benefits of Zig, without rewriting in Zig!

_How is this relevant to Embedded Apps and NuttX?_

Today we're running incredibly __complex C projects on NuttX__...

-   [__LoRa Wireless Comms__](https://lupyuen.github.io/articles/sx1262)

-   [__LoRaWAN Networking__](https://lupyuen.github.io/articles/lorawan3)

-   [__NimBLE Porting Layer__](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

Zig might be the best way to maintain and extend these __IoT Projects__ on NuttX.

_Why not rewrite in Zig? Or another modern language?_

That's because these C projects are still in [__Active Development__](https://github.com/Lora-net/LoRaMac-node/commits/master) and can __change at any moment.__

(Like when LoRaWAN introduces new [__Regional Frequencies__](https://github.com/Lora-net/LoRaMac-node/commit/379eef59fa95e22701230caa77476d9f55859f34) for wireless networking)

Any rewrites of these projects will need to __incorporate the updates__ very quickly. Which makes the maintenance of the rewritten projects horribly painful.

(Also LoRaWAN is [__Time Critical__](https://gist.github.com/lupyuen/1d96b24c6bf5164cba652d903eedb9d1), we can't change any code that might break compliance with the LoRaWAN Spec)

_So we'll have to keep the projects intact in C, but compile them with Zig Compiler instead?_

Yeah probably the best way to maintain and extend these Complex IoT Projects is to __compile them as-is with Zig__.

_But we can create new IoT Apps in Zig right?_

Yep totally! Since Zig interoperates well with C, we can create __IoT Apps in Zig__ that will call the C Libraries for LoRa / LoRaWAN / NimBLE...

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

I'm really impressed by this Wayland Compositor in Zig, how it imports a __huge bunch of C Header Files__, and calls them from Zig!

-   [__dreinharth/byway (Wayland Compositor in Zig)__](https://github.com/dreinharth/byway/blob/main/src/main.zig)

# What's Next

This has been a very quick experiment with Zig on RISC-V Microcontrollers... But it looks __super promising!__

In the coming weeks I'll test Zig as a __drop-in replacement for GCC.__ Let's find out whether Zig will cure our headaches in __maintaining Complex IoT Projects!__

Check out the updates here...

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

(Spoiler: It really works!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/Zig/comments/v2zgvh/zig_on_riscv_bl602_quick_peek_with_apache_nuttx/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/zig.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/zig.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1529261120124354560)

1.  This article was inspired by a question from my [__GitHub Sponsor__](https://github.com/sponsors/lupyuen): "Can we run Zig on BL602 with Apache NuttX RTOS?"

1.  For Embedded Platforms (like Apache NuttX RTOS), we need to implement our own __Panic Handler__...

    [__"Zig Panic Handler"__](https://github.com/lupyuen/zig-bl602-nuttx#panic-handler)

1.  [__Matheus Catarino França__](https://www.linkedin.com/feed/update/urn:li:activity:6935177950191341568/?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6935177950191341568%2C6935193220574285824%29) has a suggestion for fixing the NuttX Build for Zig Apps...

    _"make config is not running the compiler. I believe the problem must be in the application.mk in apps"_

    [(Source)](https://www.linkedin.com/feed/update/urn:li:activity:6935177950191341568/?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6935177950191341568%2C6935193220574285824%29)

1.  This __Revert Commit__ might tell us what's missing from the NuttX Makefiles...

    [__"Revert Zig Build"__](https://github.com/apache/incubator-nuttx/pull/5762/commits/ad17dfca52606671564636cdd773b09af8fb154e)

1.  We made two __Temporary Fixes to the NuttX Makefiles__ so that the Zig Object Files will be generated...

    [__nuttx/tools/Config.mk__](https://github.com/lupyuen/incubator-nuttx/commit/825531f3f571621754ba4c69f32406440dd0d9f3)

    [__apps/Application.mk__](https://github.com/lupyuen/incubator-nuttx-apps/commit/7fd9964b910add04f47780f519e3054f8e2692c9)
