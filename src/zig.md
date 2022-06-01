# Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS

📝 _7 Jun 2022_

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

Yep there's indeed a __`print()`__ function in Zig, and we ought to use it! [(See this)](https://ziglang.org/documentation/master/#Hello-World)

Eventually we'll update our Zig App to call the __`print()`__ function instead.

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

##  Copy the compiled app to NuttX and overwrite `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello/*hello.o

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
##  "*hello.o" expands to something like "hello_main.c.home.user.nuttx.apps.examples.hello.o"
$ riscv64-unknown-elf-readelf -h -A $HOME/nuttx/apps/examples/hello/*hello.o
ELF Header:
  Flags: 0x3, RVC, single-float ABI
  ...
File Attributes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

[(Source)](https://gist.github.com/lupyuen/5c090dead49eb50751578f28c15cecd5)

![NuttX was compiled for (Single-Precision) Hardware Floating-Point ABI](https://lupyuen.github.io/images/zig-abi1a.png)

The __ELF Header__ says that the NuttX Object Files were compiled for the (Single-Precision) __Hardware Floating-Point__ ABI (Application Binary Interface).

[(NuttX compiles with the GCC Flags `-march=rv32imafc -mabi=ilp32f`)](https://gist.github.com/lupyuen/288c980fdef75c334d32e669a921e623)

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

(__TODO:__ Why did the Zig Compiler produce an Object File with Software Floating-Point ABI, when `sifive_e76` supports Hardware Floating-Point?)

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

(__TODO:__ Find the right way to fix the ELF Header Floating-Point ABI in the Zig Compiler)

# Zig Runs OK!

We're ready to link the modified Object File with NuttX...

```bash
##  Copy the modified object file to NuttX and overwrite `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello/*hello.o

##  Build NuttX to link the Zig Object from `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

Finally our NuttX Build succeeds! 🎉

TODO

Zig runs OK on NuttX BL602!

```text
NuttShell (NSH) NuttX-10.3.0-RC2

nsh> hello_zig
Hello, Zig!
```

TODO

![Zig runs on BL602 with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-title.jpg)

# Embedded Zig

TODO: microzig

[__ZigEmbeddedGroup/microzig__](https://github.com/ZigEmbeddedGroup/microzig)

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

Adapted from [blinky.zig](https://github.com/ZigEmbeddedGroup/microzig/blob/master/tests/blinky.zig)

TODO: Bare metal Zig on RISC-V

-   [__nmeum/zig-riscv-embedded__](https://github.com/nmeum/zig-riscv-embedded)

# Why Zig?

TODO

[__"Maintain it With Zig"__](https://kristoff.it/blog/maintain-it-with-zig)

[__"Compile a C/C++ Project with Zig"__](https://zig.news/kristoff/compile-a-c-c-project-with-zig-368j)

[__"How serious Zig about replacing C?"__)](https://www.reddit.com/r/Zig/comments/urifjd/how_serious_zig_about_replacing_c/?utm_medium=android_app&utm_source=share)

[__dreinharth/byway (Wayland Compositor in Zig)__](https://github.com/dreinharth/byway/blob/main/src/main.zig)

Zig looks great for maintaining complex C projects

Today we're running incredibly complex C projects on NuttX: LoRaWAN Library, LoRa SX1262 Library, NimBLE Porting Layer

And we can't afford to make any code changes to the C code, in case the upstream code changes (e.g. new LoRaWAN Regions)

So best way to maintain and extend them is to compile with Zig

In future might be possible to build LoRaWAN IoT Apps in Zig

Why not rewrite in Zig (or another modern language)? Because we will have trouble syncing future updates to the C code

LoRaWAN is [__Time Critical__](https://gist.github.com/lupyuen/1d96b24c6bf5164cba652d903eedb9d1), we can't change any code that might break the compliance with the LoRaWAN Spec

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/zig.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/zig.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1529261120124354560)

# Appendix: Zig on RISC-V BL602 with Apache NuttX RTOS

TODO

To build the Zig App for NuttX on BL602...

```bash
##  Enable Zig App in NuttX menuconfig
make menuconfig

##  TODO: Select "Application Configuration > Examples > Hello Zig Example"
##  Save the configuration and exit menuconfig.

##  Build Nuttx
make

##  NuttX Build fails with Undefined Reference to `hello_zig_main`
##  That's OK, here's the fix...

##  Download our modified Zig App for NuttX
git clone --recursive https://github.com/lupyuen/zig-bl602-nuttx
cd zig-bl602-nuttx

##  Compile the Zig App for BL602 (RV32IMACF with Hardware Floating-Point)
zig build-obj \
    -target riscv32-freestanding-none \
    -mcpu sifive_e76 \
    hello_zig_main.zig

##  Dump the ABI for the compiled app
riscv64-unknown-elf-readelf -h -A hello_zig_main.o
##  Shows "Flags: 0x1, RVC, soft-float ABI"
##  Which is Software Floating-Point.
##  This won't link with NuttX because NuttX is compiled with Hardware Floating-Point

##  We change Software Floating-Point to Hardware Floating-Point...
##  Edit hello_zig_main.o in a Hex Editor, change byte 0x24 from 0x01 to 0x03
##  (See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header)

##  Dump the ABI for the compiled app
riscv64-unknown-elf-readelf -h -A hello_zig_main.o
##  Shows "Flags: 0x3, RVC, single-float ABI"
##  Which is Hardware Floating-Point and will link with NuttX

##  Copy the compiled app to NuttX and overwrite `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello/*hello.o

##  Build NuttX to link the Zig Object from `hello.o`
make

##  NuttX build should now succeed
```

Boot NuttX and enter this at the NuttX Shell...

```text
NuttShell (NSH) NuttX-10.3.0-RC2

nsh> hello_zig
Hello, Zig!

nsh> hello
Hello, Zig!
```

# Appendix: Hello App

TODO

Remember that we overwrote `hello.o` with our Zig Compiled Object File.

NuttX Build will fail unless we provide the `hello_main` function...

```text
riscv64-unknown-elf-ld: nuttx/staging/libapps.a(builtin_list.c.home.user.nuttx.apps.builtin.o):(.rodata.g_builtins+0xcc): 
undefined reference to `hello_main'
```

That's why we define `hello_main` in our Zig App...

```zig
pub export fn hello_main(
    _argc: c_int, 
    _argv: [*]const [*]const u8
) c_int {
    _ = _argc;
    _ = _argv;
    _ = printf("Hello, Zig!\n");
    return 0;
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/hello_zig_main.zig)


Which means that the `hello` app will call our Zig Code too...

```text
NuttShell (NSH) NuttX-10.3.0-RC2

nsh> hello
Hello, Zig!
```
