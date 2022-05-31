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

This tells the Zig Compiler that we're not using the value of "`something`".

The Zig Compiler helpfully stops us if we forget to use a Variable (like `_argc`) or the Returned Value for a Function (like for `printf`).

_Doesn't Zig have its own printf?_

Yep there's indeed a __`print()`__ function in Zig, and we ought to use it! [(See this)](https://ziglang.org/documentation/master/#Hello-World)

Eventually we'll fix our Zig App to call the __`print()`__ function instead.

_Did we forget something?_

For simplicity we excluded the __Variable Arguments__ for __`printf()`__.

Our declaration for __`printf()`__ specifies only one parameter: the __Format String__. So it's good for printing one unformatted string.

[(Here's the full declaration)](https://ziglang.org/documentation/master/#Sentinel-Terminated-Pointers)

# Enable Zig App

TODO

To enable the Zig App in NuttX...

```bash
make menuconfig
```

Select "Application Configuration > Examples > Hello Zig Example"

Save the configuration and exit menuconfig.

TODO

![](https://lupyuen.github.io/images/zig-config1a.png)

# Build Fails on NuttX

TODO

When we build NuttX...

```bash
make
```

We see this error...

```bash
LD: nuttx
riscv64-unknown-elf-ld: nuttx/staging/libapps.a(builtin_list.c.home.user.nuttx.apps.builtin.o):(.rodata.g_builtins+0xbc): 
undefined reference to `hello_zig_main'
```

[(Source)](https://gist.github.com/lupyuen/497c90b862aef48b57ff3124f2ea94d8)

Which looks similar to this issue...

https://github.com/apache/incubator-nuttx/issues/6219

This seems to be caused by the NuttX Build not calling the Zig Compiler.

But no worries! Let's compile the Zig App ourselves and link into NuttX.

TODO

![](https://lupyuen.github.io/images/zig-build1a.png)

# Compile Zig App

TODO

Here's how we compile our Zig App for RISC-V BL602 and link it with NuttX...

```bash
##  Download our modified Zig App for NuttX
git clone --recursive https://github.com/lupyuen/zig-bl602-nuttx
cd zig-bl602-nuttx

##  Compile the Zig App for BL602 (RV32IMACF with Hardware Floating-Point)
zig build-obj \
    -target riscv32-freestanding-none \
    -mcpu sifive_e76 \
    hello_zig_main.zig

##  Copy the compiled app to NuttX and overwrite `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello/*hello.o

##  Build NuttX to link the Zig Object from `hello.o`
make
```

TODO

![](https://lupyuen.github.io/images/zig-build3a.png)

# Zig Target

TODO

_Why is the target `riscv32-freestanding-none`?_

Zig Targets have the form `<arch><sub>-<os>-<abi>`...

`riscv32`: Because BL602 is a 32-bit RISC-V processor

`freestanding`: Because embedded targets don't need an OS

`none`: Because embedded targets don't specify the ABI

_Why is the target CPU `sifive_e76`?_

BL602 is designated as RV32IMACF...

| Designation | Meaning |
|:---:|:---|
| __`RV32I`__ | 32-bit RISC-V with Base Integer Instructions
| __`M`__ | Integer Multiplication + Division
| __`A`__ | Atomic Instructions
| __`C`__ | Compressed Instructions
| __`F`__ | Single-Precision Floating-Point

[(Source)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

Among all Zig Targets, only `sifive_e76` has the same designation...

```bash
$ zig targets
...
"sifive_e76": [ "a", "c", "f", "m" ],
```

[(Source)](https://gist.github.com/lupyuen/09d64c79e12b30e5eebc7d0a9c3b20a4)

Thus we use `sifive_e76` as our CPU Target.

Alternatively we may use `baseline_rv32-d` as our CPU Target...

```bash
##  Compile the Zig App for BL602 (RV32IMACF with Hardware Floating-Point)
zig build-obj \
    -target riscv32-freestanding-none \
    -mcpu=baseline_rv32-d \
    hello_zig_main.zig
```

Because...

-   `baseline_rv32` means RV32IMACFD 

    (D for Double-Precision Floating-Point)

-   `-d` means remove the Double-Precision Floating-Point (D)

    (But keep the Single-Precision Floating-Point)

[(More about RISC-V Feature Flags. Thanks Matheus!)](https://github.com/lupyuen/zig-bl602-nuttx/issues/1)

TODO

![](https://lupyuen.github.io/images/zig-build4a.jpg)

# Floating-Point ABI

TODO

When linking the Compiled Zig App with NuttX, we see this error...

```text
$ make
...
riscv64-unknown-elf-ld: nuttx/staging/libapps.a(hello_main.c.home.user.nuttx.apps.examples.hello.o): 
can't link soft-float modules with single-float modules
```

TODO

![](https://lupyuen.github.io/images/zig-build2a.png)

That's because NuttX was compiled for (Single-Precision) __Hardware Floating-Point__ ABI (Application Binary Interface)...

```bash
##  Do this BEFORE overwriting hello.o by hello_zig_main.o.
##  "*hello.o" expands to something like "hello_main.c.home.user.nuttx.apps.examples.hello.o"
$ riscv64-unknown-elf-readelf -h -A $HOME/nuttx/apps/examples/hello/*hello.o
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          4528 (bytes into file)
  Flags:                             0x3, RVC, single-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           40 (bytes)
  Number of section headers:         26
  Section header string table index: 25
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

[(Source)](https://gist.github.com/lupyuen/5c090dead49eb50751578f28c15cecd5)

[(NuttX was compiled with the GCC Flags `-march=rv32imafc -mabi=ilp32f`)](https://gist.github.com/lupyuen/288c980fdef75c334d32e669a921e623)

TODO

![](https://lupyuen.github.io/images/zig-abi1a.png)

Whereas Zig Compiler produces an Object File with __Software Floating-Point__ ABI...

```bash
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          11968 (bytes into file)
  Flags:                             0x1, RVC, soft-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           40 (bytes)
  Number of section headers:         24
  Section header string table index: 22
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_c2p0"
```

[(Source)](https://gist.github.com/lupyuen/f04386a0b94ed1fb42a94d671edb1ba7)

GCC won't allow us to link object files with Software Floating-Point and Hardware Floating-Point ABIs!

TODO: Why did the Zig Compiler produce an Object File with Software Floating-Point ABI, when `sifive_e76` supports Hardware Floating-Point?

TODO

![](https://lupyuen.github.io/images/zig-abi2a.png)

# Patch ELF Header

TODO

Zig Compiler generates an Object File with __Software Floating-Point__ ABI (Application Binary Interface)...

```bash
##  Dump the ABI for the compiled app
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
...
Flags: 0x1, RVC, soft-float ABI
```

This won't link with NuttX because NuttX is compiled with Hardware Floating-Point ABI.

We fix this by modifying the ELF Header...

-   Edit `hello_zig_main.o` in a Hex Editor

    [(Like VSCode Hex Editor)](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor)

-   Change byte `0x24` (Flags) from `0x01` (Soft Float) to `0x03` (Hard Float)

    [(See this)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header)

TODO

![](https://lupyuen.github.io/images/zig-hex2a.png)

We verify that the Object File has been changed to __Hardware Floating-Point__ ABI...

```bash
##  Dump the ABI for the compiled app
$ riscv64-unknown-elf-readelf -h -A hello_zig_main.o
...
Flags: 0x3, RVC, single-float ABI
```

This is now Hardware Floating-Point ABI and will link with NuttX.

Now we link the modified Object File with NuttX...

```bash
##  Copy the compiled app to NuttX and overwrite `hello.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp hello_zig_main.o $HOME/nuttx/apps/examples/hello/*hello.o

##  Build NuttX to link the Zig Object from `hello.o`
make
```

The NuttX Build should now succeed.

TODO: Find the right way to fix the Floating-Point ABI in the Zig Compiler

# Zig Runs OK!

TODO

The NuttX Build succeeds. Zig runs OK on NuttX BL602!

```text
NuttShell (NSH) NuttX-10.3.0-RC2

nsh> hello_zig
Hello, Zig!
```

TODO

![Zig runs on BL602 with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-title.jpg)

# Embedded Zig

TODO

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

# Why Zig?

TODO

[__"Maintain it With Zig"__](https://kristoff.it/blog/maintain-it-with-zig)

[__"Compile a C/C++ Project with Zig"__](https://zig.news/kristoff/compile-a-c-c-project-with-zig-368j)

[__"How serious Zig about replacing C?"__)](https://www.reddit.com/r/Zig/comments/urifjd/how_serious_zig_about_replacing_c/?utm_medium=android_app&utm_source=share)

Zig looks great for maintaining complex C projects

Today we're running incredibly complex C projects on NuttX: LoRaWAN Library, LoRa SX1262 Library, NimBLE Porting Layer

And we can't afford to make any code changes to the C code, in case the upstream code changes (e.g. new LoRaWAN Regions)

So best way to maintain and extend them is to compile with Zig

In future might be possible to build LoRaWAN IoT Apps in Zig

Why not rewrite in Zig (or another modern language)? Because we will have trouble syncing future updates to the C code

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
