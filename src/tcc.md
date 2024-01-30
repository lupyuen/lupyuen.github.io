# TCC RISC-V Compiler runs in the Web Browser (thanks to Zig Compiler)

📝 _7 Feb 2024_

![TODO](https://lupyuen.github.io/images/tcc-title.png)

[_(Try the __Online Demo__)_](https://lupyuen.github.io/tcc-riscv32-wasm/)

_TCC is a Tiny C Compiler for 64-bit RISC-V (and other platforms)..._

_Can we run TCC Compiler in a Web Browser?_

Let's do it! We'll compile [__TCC (Tiny C Compiler)__](https://github.com/sellicott/tcc-riscv32) from C to WebAssembly with [__Zig Compiler__](https://ziglang.org/).

In this article, we talk about the tricky bits of the TCC Port from __C to WebAssembly__...

TODO

[(Not to be confused with __TTC from the 80's__)](https://research.cs.queensu.ca/home/cordy/pub/downloads/tplus/Turing_Plus_Report.pdf)

_Why are we doing this?_

TODO: Somewhat working

Today we can run [__Apache NuttX RTOS in a Web Browser__](https://lupyuen.github.io/articles/tinyemu2). (With WebAssembly + Emscripten + 64-bit RISC-V)

(__Real-Time Operating System__ in Web Browser on General-Purpose Operating System!)

What if we could allow NuttX Apps to be compiled and tested in the Web Browser?

1.  We type a C Program into a HTML Textbox...

    ```c
    int main(int argc, char *argv[]) {
      printf("Hello, World!!\n");
      return 0;
    }
    ```

1.  Run TCC in the Web Browser to compile the C Program into an ELF Executable (64-bit RISC-V)

1.  Copy the ELF Executable to the NuttX Filesystem (via WebAssembly)

1.  NuttX runs our ELF Executable inside the Web Browser

![TCC RISC-V Compiler: Compiled to WebAssembly with Zig Compiler](https://lupyuen.github.io/images/tcc-web.png)

[_(Try the __Online Demo__)_](https://lupyuen.github.io/tcc-riscv32-wasm/)

# TCC in the Web Browser

Head over to this link to try __TCC Compiler in our Web Browser__ (pic above)...

- [__TCC RISC-V Compiler in WebAssembly__](https://lupyuen.github.io/tcc-riscv32-wasm/)

This __C Program__ appears...

```c
// Demo Program for TCC Compiler
int main(int argc, char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
```

Click the "__Compile__" button. Our Web Browser calls TCC to compile the above program...

```bash
## Compile to RISC-V ELF
tcc -c hello.c
```

And it downloads the compiled __RISC-V ELF `a.out`__. We inspect the Compiled Output...

```bash
## Dump the RISC-V Disassembly of TCC Output
$ riscv64-unknown-elf-objdump \
    --syms --source --reloc --demangle \
    --line-numbers --wide  --debugging \
    a.out

main():
   ## Prepare the Stack
   0: fe010113  addi   sp, sp, -32
   4: 00113c23  sd     ra, 24(sp)
   8: 00813823  sd     s0, 16(sp)
   c: 02010413  addi   s0, sp, 32
  10: 00000013  nop

   ## Load to Register A0: "Hello World"
  14: fea43423  sd     a0, -24(s0)
  18: feb43023  sd     a1, -32(s0)
  1c: 00000517  auipc  a0, 0x0
  1c: R_RISCV_PCREL_HI20 L.0
  20: 00050513  mv     a0, a0
  20: R_RISCV_PCREL_LO12_I .text

   ## Call printf()
  24: 00000097  auipc  ra, 0x0
  24: R_RISCV_CALL_PLT printf
  28: 000080e7  jalr   ra  ## 24 <main+0x24>

   ## Clean up the Stack and return 0 to Caller
  2c: 0000051b  sext.w a0, zero
  30: 01813083  ld     ra, 24(sp)
  34: 01013403  ld     s0, 16(sp)
  38: 02010113  addi   sp, sp, 32
  3c: 00008067  ret
```

[(About the __RISC-V Instructions__)](https://lupyuen.github.io/articles/app#inside-a-nuttx-app)

[(See the __Entire Dump__)](https://gist.github.com/lupyuen/ab8febefa9c649ad7c242ee3f7aaf974)

Yep the __64-bit RISC-V Code__ looks legit! Very similar to our [__NuttX App__](https://lupyuen.github.io/articles/app#inside-a-nuttx-app). (So it will probably run on NuttX)

# Zig compiles TCC to WebAssembly

_Zig Compiler will happily compile TCC to WebAssembly?_

Amazingly, yes!

```bash
## Zig Compiler compiles TCC Compiler from C to WebAssembly.
## Produces `tcc.o`
zig cc \
  -c \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -lc \
  tcc.c \
  -DTCC_TARGET_RISCV64 \
  -DCONFIG_TCC_CROSSPREFIX="\"riscv64-\""  \
  -DCONFIG_TCC_CRTPREFIX="\"/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_LIBPATHS="\"{B}:/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_SYSINCLUDEPATHS="\"{B}/include:/usr/riscv64-linux-gnu/include\""   \
  -DTCC_GITHASH="\"main:b3d10a35\"" \
  -Wall \
  -O2 \
  -Wdeclaration-after-statement \
  -fno-strict-aliasing \
  -Wno-pointer-sign \
  -Wno-sign-compare \
  -Wno-unused-result \
  -Wno-format-truncation \
  -Wno-stringop-truncation \
  -I.
```

[(See __tcc.c__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/tcc.c)

[(How we got the __Zig Compiler Options__)](TODO)

Then we link it with our __Zig Wrapper__ that exports the TCC Compiler to JavaScript...

```bash
## Compile our Zig Wrapper `tcc-wasm.zig` for WebAssembly
## and link it with TCC compiled for WebAssembly `tcc.o`
## Generates `tcc-wasm.wasm`
zig build-exe \
  --verbose-cimport \
  -target wasm32-freestanding \
  -rdynamic \
  -lc \
  -fno-entry \
  --export=compile_program \
  zig/tcc-wasm.zig \
  tcc.o

## Test everything with Web Browser or NodeJS
node zig/test.js
```

[(__tcc-wasm.zig__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig)

[(__test.js__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test.js)

_What's inside our Zig Wrapper?_

Our Zig Wrapper will...

1.  Receive the __C Program__ from JavaScript

1.  Receive the __TCC Compiler Options__ from JavaScript

1.  Call TCC Compiler to __compile our program__

1.  Return the compiled __RISC-V ELF__ to JavaScript

Like so: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L12-L77)

```zig
/// Call TCC Compiler to compile a C Program to RISC-V ELF
pub export fn compile_program(
  options_ptr: [*:0]const u8, // Options for TCC Compiler (Pointer to JSON Array:  ["-c", "hello.c"])
  code_ptr:    [*:0]const u8, // C Program to be compiled (Pointer to String)
) [*]const u8 { // Returns a pointer to the `a.out` Compiled Code (Size in first 4 bytes)

  // Receive the C Program from JavaScript and set our Read Buffer
  // https://blog.battlefy.com/zig-made-it-easy-to-pass-strings-back-and-forth-with-webassembly
  const code: []const u8 = std.mem.span(code_ptr);
  read_buf = code;

  // Omitted: Receive the TCC Compiler Options from JavaScript
  // (JSON containing String Array: ["-c", "hello.c"])
  ...

  // Call the TCC Compiler
  _ = main(@intCast(argc), &args_ptrs);

  // Return pointer of `a.out` to JavaScript.
  // First 4 bytes: Size of `a.out`. Followed by `a.out` data.
  const slice = std.heap.page_allocator.alloc(u8, write_buflen + 4)   
    catch @panic("Failed to allocate memory");
  slice[0] = @intCast((write_buflen >>  0) & 0xff);
  slice[1] = @intCast((write_buflen >>  8) & 0xff);
  slice[2] = @intCast((write_buflen >> 16) & 0xff);
  slice[3] = @intCast(write_buflen  >> 24);
  @memcpy(slice[4 .. write_buflen + 4], write_buf[0..write_buflen]);
  return slice.ptr; // TODO: Deallocate this memory
}
```

Plus a couple of Magical Bits that we'll explain in the next section.

[(How __JavaScript__ calls our Zig Wrapper)](TODO)

_Zig Compiler compiles TCC without any Code Changes?_

Inside TCC, we stubbed out the [__setjmp / longjmp__](https://github.com/lupyuen/tcc-riscv32-wasm/commit/e30454a0eb9916f820d58a7c3e104eeda67988d8) to make it compile with Zig Compiler.

(Everything else compiles OK!)

_Is that really OK?_

Well [__setjmp / longjmp__](https://en.wikipedia.org/wiki/Setjmp.h) are called to __Handle Errors__ during TCC Compilation.

We'll find a better way to express our outrage. Instead of jumping around!

Let's talk about Magical Bits inside our Zig Wrapper...

# POSIX for WebAssembly

_What's this POSIX?_

TCC Compiler was created as a __Command-Line App__. So it calls the typical [__POSIX Functions__](https://en.wikipedia.org/wiki/POSIX) like __fopen, fprintf, strncpy, malloc,__ ...

[(Similar to the __C Standard Library libc__)](https://en.wikipedia.org/wiki/C_standard_library)

_Is POSIX a problem for WebAssembly?_

WebAssembly running in a Web Browser ain't __No Command-Line__!

We counted [__72 POSIX Functions__](TODO) needed by TCC Compiler, but missing from WebAssembly.

Thus we'll fill in the [__Missing Functions__](TODO) ourselves.

_Surely other Zig Devs will have the same problem?_

Thankfully we can borrow the POSIX-like code from other __Zig Libraries__...

- [__ziglibc__](https://github.com/marler8997/ziglibc): Zig implementation of libc

- [__foundation-libc__](https://github.com/ZigEmbeddedGroup/foundation-libc): Freestanding implementation of libc

- [__PinePhone Simulator__](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation): For malloc

  [(See the __Borrowed Code__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L447-L774)

_72 POSIX Functions? Sounds like a lot of work..._

Actually we haven't implemented all 72 POSIX Functions. We __stubbed out most of the functions__ to figure out which ones are normally used: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L774-L853)

```zig
// Stub Out the Missing POSIX Functions.
// If TCC calls them, we'll see a Zig Panic.
// Then we implement them.
// The Types don't matter because we'll halt anyway.

pub export fn atoi(_: c_int) c_int {
  @panic("TODO: atoi");
}
pub export fn exit(_: c_int) c_int {
  @panic("TODO: exit");
}
pub export fn fopen(_: c_int) c_int {
  @panic("TODO: fopen");
}

// And many more functions...
```

Some of these functions are problematic in WebAssembly...

# File Input and Output

_Why no #include in TCC for WebAssembly? And no C Libraries?_

WebAssembly runs in a __Secure Sandbox__. No File Access allowed! (Like C Header and Library Files)

That's why our Zig Wrapper only __Emulates File Access__ for the bare minimum 2 files...

- Read the C Program: __hello.c__

- Write the RISC-V ELF: __a.out__

__Reading a Source File (hello.c)__ is extremely simplistic: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L107-L119)

```zig
/// Emulate the POSIX Function `read()`
/// We copy from One Single Read Buffer
/// that contains our C Program
export fn read(fd0: c_int, buf: [*:0]u8, nbyte: size_t) isize {

  // TODO: Support more than one file
  // TODO: Check overflow
  const len = read_buf.len;
  @memcpy(buf[0..len], read_buf[0..len]);
  buf[len] = 0;
  read_buf.len = 0;
  return @intCast(len);
}
```

__Writing the Compiled Output (a.out)__ is just as barebones: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L130-L142)

```zig
/// Emulate the POSIX Function `write()`
/// We write to One Single Memory Buffer
/// that will be returned to JavaScript as `a.out`
export fn fwrite(ptr: [*:0]const u8, size: usize, nmemb: usize, stream: *FILE) usize {

  // TODO: Support more than one `stream`
  const len = size * nmemb;
  @memcpy(write_buf[write_buflen .. write_buflen + len], ptr[0..]);
  write_buflen += len;
  return nmemb;
}
```

_Can we handle Multiple Files?_

We'll have to embed an __Emulated File System__ inside our Zig Wrapper. The File System will contain the C Header and Library Files needed by TCC.

[(Similar to the __Emscripten File System__)](https://emscripten.org/docs/porting/files/file_systems_overview.html)

[(Maybe we embed the simple __ROM FS File System__)](https://docs.kernel.org/filesystems/romfs.html)

TODO: Pic of Format Patterns

# Fearsome fprintf and Friends

_Why is fprintf particularly problematic?_

Here's the fearsome thing about __fprintf__ and friends: __sprintf, snprintf, vsnprintf__...

- __C Format Strings__: Difficult to parse

- __Variable Number of Untyped Arguments__: Might create Bad Pointers

Hence we hacked up an implementation of __String Formatting__ that's safer, simpler and so-barebones-you-can-make-_soup-tulang_.

_Soup tulang? Tell me more..._

Our Zig Wrapper uses __Pattern Matching__ to match the __C Formats__ and substitute the __Zig Equivalent__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L191-L209)

```zig
// Format a Single `%d`
// like `#define __TINYC__ %d`
FormatPattern{

  // If the C Format String contains this...
  .c_spec = "%d",
  
  // Then we apply this Zig Format...
  .zig_spec = "{}",
  
  // And extract these Argument Types
  // from the Varargs...
  .type0 = c_int,
  .type1 = null
}
```

This works OK (for now) because TCC Compiler only uses __5 Patterns for C Format Strings__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L191-L209)

```zig
/// Pattern Matching for C String Formatting:
/// We'll match these patterns when formatting strings
const format_patterns = [_]FormatPattern{

  // Format a Single `%d`, like `#define __TINYC__ %d`
  FormatPattern{
    .c_spec = "%d",  .zig_spec = "{}", 
    .type0  = c_int, .type1 = null
  },

  // Format a Single `%u`, like `L.%u`
  FormatPattern{ 
    .c_spec = "%u",  .zig_spec = "{}", 
    .type0  = c_int, .type1 = null 
  },

  // Format a Single `%s`, like `#define __BASE_FILE__ "%s"`
  // or `.rela%s`
  FormatPattern{
    .c_spec = "%s", .zig_spec = "{s}",
    .type0  = [*:0]const u8, .type1 = null
  },

  // Format Two `%s`, like `#define %s%s\n`
  FormatPattern{
    .c_spec = "%s%s", .zig_spec = "{s}{s}",
    .type0  = [*:0]const u8, .type1 = [*:0]const u8
  },

  // Format `%s:%d`, like `%s:%d: ` (File Name and Line Number)
  FormatPattern{
    .c_spec = "%s:%d", .zig_spec = "{s}:{}",
    .type0  = [*:0]const u8, .type1 = c_int
  },
};
```

And that's how we implement [__fprintf and friends__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L209-L447)!

[(How we do __Pattern Matching__)](TODO)

_So simple? Unbelievable!_

OK actually we'll hit more Format Patterns as TCC Compiler emits various Error and Warning Messages. But it's a good start!

Later our Zig Wrapper will have to parse meticulously all kinds of C Format Strings. Or we do the [__parsing in C__](https://github.com/marler8997/ziglibc/blob/main/src/printf.c#L32-L191), compiled to WebAssembly.

(Funny how __printf__ is the first thing we learn about C. Yet it's incredibly difficult to implement!)

TODO: Pic of missing printf

# Test with Apache NuttX RTOS

_TCC in WebAssembly has compiled our C Program to RISC-V ELF..._

_Will the RISC-V ELF run on Apache NuttX RTOS?_

We copy the __RISC-V ELF (a.out)__ to the __NuttX Apps__ File System...

```bash
## Copy RISC-V ELF `a.out`
## to NuttX Apps File System
cp a.out apps/bin/
chmod +x apps/bin/a.out
```

Then we boot __NuttX on QEMU__ (64-bit RISC-V) and run __a.out__ on NuttX...

```bash
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
load_absmodule: Loading /system/bin/a.out
elf_loadbinary: Loading file: /system/bin/a.out
...
elf_symvalue: SHN_UNDEF: Exported symbol "printf" not found
exec_internal: ERROR: Failed to load program 'a.out': -2
```

[(See the __Complete Log__)](https://github.com/lupyuen/tcc-riscv32-wasm#test-tcc-output-with-nuttx)

NuttX politely accepts the RISC-V ELF (produced by TCC). And says that __printf__ is missing.

Which makes sense: We haven't linked our C Program with the C Library!

[(NuttX should load a __RISC-V ELF__ like this)](https://gist.github.com/lupyuen/847f7adee50499cac5212f2b95d19cd3)

[(How we build and run __NuttX for QEMU__)](TODO)

_How else can we print something in NuttX?_

To print something, we can make a [__NuttX System Call (ECALL)__](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel) directly to NuttX Kernel...

```c
// NuttX System Call that prints something
// System Call Number is 61 (SYS_write)
// Works exactly like POSIX `write()`
ssize_t write(
  int fd,           // File Descriptor (1 for Standard Output)
  const char *buf,  // Buffer to be printed
  size_t buflen     // Buffer Length
);
```

That's the same NuttX System Call that __printf__ executes internally.

One last chance to say hello to NuttX...

[(__Warning:__ SYS_write 61 may change!)](https://lupyuen.github.io/articles/app#nuttx-kernel-handles-system-call)

TODO: Pic of ECALL

# Hello NuttX!

_We're making a System Call (ECALL) to NuttX Kernel to print something..._

_How will we write this in C?_

We code the [__ECALL in RISC-V Assembly__](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel) like this: [test-nuttx.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test-nuttx.js#L52-L105)

```c
int main(int argc, char *argv[]) {

  // Make NuttX System Call to write(fd, buf, buflen)
  const unsigned int nbr = 61; // SYS_write
  const void *parm1 = 1;       // File Descriptor (stdout)
  const void *parm2 = "Hello, World!!\n"; // Buffer
  const void *parm3 = 15; // Buffer Length

  // Load the Parameters into Registers A0 to A3
  // TODO: This doesn't work with TCC, so we load again below
  register long r0 asm("a0") = (long)(nbr);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);

  // Execute ECALL for System Call to NuttX Kernel
  // Again: Load the Parameters into Registers A0 to A3
  asm volatile (

    // Load 61 to Register A0 (SYS_write)
    // li a0, 61
    ".long 0x03d00513 \n"

    // Load 1 to Register A1 (File Descriptor)
    // li a1, 1
    ".long 0x00100593 \n"

    // Load 0xc0101000 to Register A2 (Buffer)
    // li a2, 0xc0101000
    ".long 0x000c0637 \n"
    ".long 0x1016061b \n"
    ".long 0x00c61613 \n"

    // Load 15 to Register A3 (Buffer Length)
    // li a3, 15
    ".long 0x00f00693 \n"

    // ECALL for System Call to NuttX Kernel
    "ecall \n"

    // NuttX needs NOP after ECALL
    ".word 0x0001 \n"
  );

  // Loop Forever
  for(;;) {}
  return 0;
}
```

We copy this into [__TCC WebAssembly__](https://lupyuen.github.io/tcc-riscv32-wasm/) and compile it.

[(Why so complicated? __Explained here__)](TODO)

_Does it work?_

TCC in WebAssembly compiles the code above to __RISC-V ELF (a.out)__. When we run it on NuttX...

```bash
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> a.out
...
## NuttX System Call for SYS_write (61)
riscv_swint:
  cmd: 61
  A0:  3d  ## SYS_write (61)
  A1:  01  ## File Descriptor (Standard Output)
  A2:  c0101000  ## Buffer
  A3:  0f        ## Buffer Length
...
## NuttX Kernel says hello
Hello, World!!
```

NuttX Kernel prints __"Hello World"__ yay!

Indeed we've created a C Compiler in a Web Browser, that __produces proper NuttX Apps__!

TODO: Pic of hello world

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX and Zig Communities) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tcc.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tcc.md)

# Appendix: Compile TCC with Zig Compiler

This is how we run __Zig Compiler to compile TCC Compiler__ from C to WebAssembly...

```bash
## Download the TCC Source Code.
## Configure the build for 64-bit RISC=V.

git clone https://github.com/lupyuen/tcc-riscv32-wasm
cd tcc-riscv32-wasm
./configure
make --trace cross-riscv64

## Call Zig Compiler to compile TCC Compiler
## from C to WebAssembly. Produces `tcc.o`

## Omitted: Run the `zig cc` command from earlier...
## TODO
```

_How did we figure out the `zig cc` options?_

Earlier we saw a long list of [__Zig Compiler Options__](TODO)...

```bash
zig cc \
  tcc.c \
  -DTCC_TARGET_RISCV64 \
  -DCONFIG_TCC_CROSSPREFIX="\"riscv64-\""  \
  -DCONFIG_TCC_CRTPREFIX="\"/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_LIBPATHS="\"{B}:/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_SYSINCLUDEPATHS="\"{B}/include:/usr/riscv64-linux-gnu/include\""   \
  ...
```

TODO

We compile TCC Compiler with the Zig Compiler. First we figure out the GCC Options...

```bash
## Show the GCC Options
$ make --trace cross-riscv64
gcc \
  -o riscv64-tcc.o \
  -c tcc.c \
  -DTCC_TARGET_RISCV64 \
  -DCONFIG_TCC_CROSSPREFIX="\"riscv64-\""  \
  -DCONFIG_TCC_CRTPREFIX="\"/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_LIBPATHS="\"{B}:/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_SYSINCLUDEPATHS="\"{B}/include:/usr/riscv64-linux-gnu/include\""   \
  -DTCC_GITHASH="\"main:b3d10a35\"" \
  -Wall \
  -O2 \
  -Wdeclaration-after-statement \
  -fno-strict-aliasing \
  -Wno-pointer-sign \
  -Wno-sign-compare \
  -Wno-unused-result \
  -Wno-format-truncation \
  -Wno-stringop-truncation \
  -I. 
```

We copy the above GCC Options and we compile TCC with Zig Compiler...


Yep it works OK!

# Appendix: JavaScript calls TCC Compiler

TODO: Earlier we saw

TODO

We test the TCC WebAssembly in a Web Browser with [docs/index.html](docs/index.html) and [docs/tcc.js](docs/tcc.js)...

```bash
## Start the Web Server
cargo install simple-http-server
simple-http-server ./docs &

## Copy the Linked TCC WebAssembly to the Web Server
cp tcc-wasm.wasm docs/
```

Browse to...

```text
http://localhost:8000/index.html
```

Open the JavaScript Console. Yep our TCC WebAssembly runs OK in a Web Browser!

```text
main: start
ret=123
main: end
```

Also published publicly here (see the JavaScript Console): https://lupyuen.github.io/tcc-riscv32-wasm/


We link our Compiled WebAssembly `tcc.o` with our Zig App: [zig/tcc-wasm.zig](zig/tcc-wasm.zig)

```bash
## Compile our Zig App `tcc-wasm.zig` for WebAssembly
## and link with TCC compiled for WebAssembly
zig build-exe \
  -target wasm32-freestanding \
  -rdynamic \
  -lc \
  -fno-entry \
  -freference-trace \
  --verbose-cimport \
  --export=compile_program \
  zig/tcc-wasm.zig \
  tcc.o

## Dump our Linked WebAssembly
wasm-objdump -h tcc-wasm.wasm
wasm-objdump -x tcc-wasm.wasm >/tmp/tcc-wasm.txt

## Run our Linked WebAssembly
## Shows: ret=123
node zig/test.js
```

Yep it runs OK and prints `123`, with our NodeJS Script: [zig/test.js](zig/test.js)

```javascript
const fs = require('fs');
const source = fs.readFileSync("./tcc-wasm.wasm");
const typedArray = new Uint8Array(source);

WebAssembly.instantiate(typedArray, {
  env: {
    print: (result) => { console.log(`The result is ${result}`); }
  }}).then(result => {
  const compile_program = result.instance.exports.compile_program;
  const ret = compile_program();
  console.log(`ret=${ret}`);
});
```

# Appendix: Pattern Matching for Format Strings

TODO: Earlier we saw

_TCC calls C Formatting Functions with Variable Arguments: fprintf, sprintf, ..._

_How will we implement them with Zig in WebAssembly?_

Parsing the C Format Strings in Zig will be tedious. Thankfully, TCC only uses 5 patterns of C Format Strings: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L191-L209)

```zig
/// Pattern Matching for String Formatting: We will match these patterns when formatting strings
const format_patterns = [_]FormatPattern{
    // Format a Single `%d`, like `#define __TINYC__ %d`
    FormatPattern{ .c_spec = "%d", .zig_spec = "{}", .type0 = c_int, .type1 = null },

    // Format a Single `%u`, like `L.%u`
    FormatPattern{ .c_spec = "%u", .zig_spec = "{}", .type0 = c_int, .type1 = null },

    // Format a Single `%s`, like `#define __BASE_FILE__ "%s"` or `.rela%s`
    FormatPattern{ .c_spec = "%s", .zig_spec = "{s}", .type0 = [*:0]const u8, .type1 = null },

    // Format Two `%s`, like `#define %s%s\n`
    FormatPattern{ .c_spec = "%s%s", .zig_spec = "{s}{s}", .type0 = [*:0]const u8, .type1 = [*:0]const u8 },

    // Format `%s:%d`, like `%s:%d: `
    FormatPattern{ .c_spec = "%s:%d", .zig_spec = "{s}:{}", .type0 = [*:0]const u8, .type1 = c_int },
};
```

We use `comptime` functions in Zig to implement the C String Formatting: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L276-L326)

```zig
/// CompTime Function to format a string by Pattern Matching.
/// Format a Single Specifier, like `#define __BASE_FILE__ "%s"`
/// If the Spec matches the Format: Return the number of bytes written to `str`, excluding terminating null.
/// Else return 0.
fn format_string1(
    ap: *std.builtin.VaList,
    str: [*]u8,
    size: size_t,
    format: []const u8, // Like `#define %s%s\n`
    comptime c_spec: []const u8, // Like `%s%s`
    comptime zig_spec: []const u8, // Like `{s}{s}`
    comptime T0: type, // Like `[*:0]const u8`
) usize {
    // Count the Format Specifiers: `%`
    const spec_cnt = std.mem.count(u8, c_spec, "%");
    const format_cnt = std.mem.count(u8, format, "%");

    // Check the Format Specifiers: `%`
    if (format_cnt != spec_cnt or // Quit if the number of specifiers are different
        !std.mem.containsAtLeast(u8, format, 1, c_spec)) // Or if the specifiers are not found
    {
        return 0;
    }

    // Fetch the args
    const a = @cVaArg(ap, T0);
    if (T0 == c_int) {
        debug("format_string1: size={}, format={s}, a={}", .{ size, format, a });
    } else {
        debug("format_string1: size={}, format={s}, a={s}", .{ size, format, a });
    }

    // Format the string. TODO: Check for overflow
    var buf: [100]u8 = undefined; // Limit to 100 chars
    const buf_slice = std.fmt.bufPrint(&buf, zig_spec, .{a}) catch {
        wasmlog.Console.log("*** format_string1 error: buf too small", .{});
        @panic("*** format_string1 error: buf too small");
    };

    // Replace the Format Specifier
    var buf2 = std.mem.zeroes([100]u8); // Limit to 100 chars
    _ = std.mem.replace(u8, format, c_spec, buf_slice, &buf2);

    // Return the string
    const len = std.mem.indexOfScalar(u8, &buf2, 0).?;
    @memcpy(str[0..len], buf2[0..len]);
    str[len] = 0;
    return len;
}
```

Previously without `comptime`, the implementation of C String Formatting gets very lengthy: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/8df0b4f64d188ff5936225dc545e8387ca512b8d/zig/tcc-wasm.zig#L188-L401)

```zig
export fn vsnprintf(str: [*:0]u8, size: size_t, format: [*:0]const u8, ...) c_int {
    // Count the Format Specifiers: `%`
    const format_slice = std.mem.span(format);
    const format_cnt = std.mem.count(u8, format_slice, "%");

    // TODO: Catch overflow
    if (format_cnt == 0) {
        // If no Format Specifiers: Return the Format, like `warning: `
        debug("vsnprintf: size={}, format={s}, format_cnt={}", .{ size, format, format_cnt });
        _ = memcpy(str, format, strlen(format));
        str[strlen(format)] = 0;
    } else if (format_cnt == 2 and std.mem.containsAtLeast(u8, format_slice, 1, "%s%s")) {
        // Format Two `%s`, like `#define %s%s\n`
        var ap = @cVaStart();
        defer @cVaEnd(&ap);
        const s0 = @cVaArg(&ap, [*:0]const u8);
        const s1 = @cVaArg(&ap, [*:0]const u8);
        debug("vsnprintf: size={}, format={s}, s0={s}, s1={s}", .{ size, format, s0, s1 });

        // Format the string
        const format2 = "{s}{s}"; // Equivalent to C: `%s%s`
        var buf: [100]u8 = undefined; // Limit to 100 chars
        const buf_slice = std.fmt.bufPrint(&buf, format2, .{ s0, s1 }) catch {
            wasmlog.Console.log("*** vsnprintf error: buf too small", .{});
            @panic("*** vsnprintf error: buf too small");
        };

        // Replace the Format Specifier
        var buf2 = std.mem.zeroes([100]u8); // Limit to 100 chars
        _ = std.mem.replace(u8, format_slice, "%s%s", buf_slice, &buf2);

        // Return the string
        const len = std.mem.indexOfScalar(u8, &buf2, 0).?;
        _ = memcpy(str, &buf2, @intCast(len));
        str[len] = 0;
    } else if (format_cnt == 2 and std.mem.containsAtLeast(u8, format_slice, 1, "%s:%d")) {
      // ...
```

Plus lots lots more of tedious coding! It's a lot simpler now with `comptime` Format Patterns.

Now we can handle all String Formatting correctly in TCC...

```text
+ node zig/test.js
compile_program: start
compile_program: options=["-c","hello.c"]
compile_program: code=
    int main(int argc, char *argv[]) {
      printf("Hello, World!!\n");
      return 0;
    }

compile_program: options[0]=-c
compile_program: options[1]=hello.c
open: path=hello.c, oflag=0, return fd=3
sem_init: sem=tcc-wasm.sem_t@10cfe8, pshared=0, value=1
sem_wait: sem=tcc-wasm.sem_t@10cfe8
TODO: setjmp
TODO: sscanf: str=0.9.27, format=%d.%d.%d
format_string1: size=128, format=#define __TINYC__ %d, a=1991381505
vsnprintf: return str=#define __TINYC__ 1991381505
format_string2: size=99, format=#define %s%s, a0=__riscv, a1= 1
vsnprintf: return str=#define __riscv 1
format_string2: size=81, format=#define %s%s, a0=__riscv_xlen 64, a1=
vsnprintf: return str=#define __riscv_xlen 64
format_string2: size=185, format=#define %s%s, a0=__riscv_flen 64, a1=
vsnprintf: return str=#define __riscv_flen 64
format_string2: size=161, format=#define %s%s, a0=__riscv_div, a1= 1
vsnprintf: return str=#define __riscv_div 1
format_string2: size=139, format=#define %s%s, a0=__riscv_mul, a1= 1
vsnprintf: return str=#define __riscv_mul 1
format_string2: size=117, format=#define %s%s, a0=__riscv_fdiv, a1= 1
vsnprintf: return str=#define __riscv_fdiv 1
format_string2: size=94, format=#define %s%s, a0=__riscv_fsqrt, a1= 1
vsnprintf: return str=#define __riscv_fsqrt 1
format_string2: size=326, format=#define %s%s, a0=__riscv_float_abi_double, a1= 1
vsnprintf: return str=#define __riscv_float_abi_double 1
format_string2: size=291, format=#define %s%s, a0=__linux__, a1= 1
vsnprintf: return str=#define __linux__ 1
format_string2: size=271, format=#define %s%s, a0=__linux, a1= 1
vsnprintf: return str=#define __linux 1
format_string2: size=253, format=#define %s%s, a0=__unix__, a1= 1
vsnprintf: return str=#define __unix__ 1
format_string2: size=234, format=#define %s%s, a0=__unix, a1= 1
vsnprintf: return str=#define __unix 1
format_string2: size=217, format=#define %s%s, a0=__CHAR_UNSIGNED__, a1= 1
vsnprintf: return str=#define __CHAR_UNSIGNED__ 1
format_string1: size=189, format=#define __SIZEOF_POINTER__ %d, a=8
vsnprintf: return str=#define __SIZEOF_POINTER__ 8
format_string1: size=160, format=#define __SIZEOF_LONG__ %d, a=8
vsnprintf: return str=#define __SIZEOF_LONG__ 8
format_string2: size=134, format=#define %s%s, a0=__STDC__, a1= 1
vsnprintf: return str=#define __STDC__ 1
format_string1: size=115, format=#define __STDC_VERSION__ %dL, a=199901
vsnprintf: return str=#define __STDC_VERSION__ 199901L
format_string1: size=356, format=#define __BASE_FILE__ "%s", a=hello.c
vsnprintf: return str=#define __BASE_FILE__ "hello.c"
read: fd=3, nbyte=8192
read: return buf=
    int main(int argc, char *argv[]) {
      printf("Hello, World!!\n");
      return 0;
    }
  
format_string2: size=128, format=%s:%d: , a0=hello.c, a1=3
vsnprintf: return str=hello.c:3: 
format_string0: size=117, format=warning: 
vsnprintf: return str=warning: 
format_string1: size=108, format=implicit declaration of function '%s', a=printf
vsnprintf: return str=implicit declaration of function 'printf'
format_string1: size=0, format=%s, a=hello.c:3: warning: implicit declaration of function 'printf'
fprintf: stream=tcc-wasm.FILE@2
hello.c:3: warning: implicit declaration of function 'printf'
format_string1: size=0, format=L.%u, a=0
sprintf: return str=L.0
format_string1: size=256, format=.rela%s, a=.text
snprintf: return str=.rela.text
read: fd=3, nbyte=8192
read: return buf=
close: fd=3
sem_post: sem=tcc-wasm.sem_t@10cfe8
format_string1: size=1024, format=%s, a=hello.c
snprintf: return str=hello.c
unlink: path=hello.o
open: path=hello.o, oflag=577, return fd=4
fdopen: fd=4, mode=wb, return FILE=5
...
close: stream=tcc-wasm.FILE@5
a.out: 1040 bytes
```

[(See the Complete Log)](https://gist.github.com/lupyuen/3e650bd6ad72b2e8ee8596858bc94f36)

TODO: Implement sscanf: `str=0.9.27, format=%d.%d.%d`

# Appendix: NuttX System Call

TODO: Earlier we saw

# Appendix: Build NuttX for QEMU RISC-V

TODO: Earlier we saw



_TCC fails to link our NuttX App because of Unknown Relocation Type for printf(). How else can we print something in our NuttX App?_

We can make a [NuttX System Call (ECALL)](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel) to `write(fd, buf, buflen)`.

Directly in our C Code! Like this: [test-nuttx.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test-nuttx.js#L55-L87)

```c
  int main(int argc, char *argv[])
  {
    // Make NuttX System Call to write(fd, buf, buflen)
    const unsigned int nbr = 61; // SYS_write
    const void *parm1 = 1;       // File Descriptor (stdout)
    const void *parm2 = "Hello, World!!\n"; // Buffer
    const void *parm3 = 15; // Buffer Length

    // Execute ECALL for System Call to NuttX Kernel
    register long r0 asm("a0") = (long)(nbr);
    register long r1 asm("a1") = (long)(parm1);
    register long r2 asm("a2") = (long)(parm2);
    register long r3 asm("a3") = (long)(parm3);
  
    asm volatile
    (
      // ECALL for System Call to NuttX Kernel
      "ecall \n"

      // We inserted NOP, because TCC says it's invalid (see below)
      ".word 0x0001 \n"
      :: "r"(r0), "r"(r1), "r"(r2), "r"(r3)
      : "memory"
    );
  
    // TODO: TCC says this is invalid
    // asm volatile("nop" : "=r"(r0));

    // Loop Forever
    for(;;) {}
    return 0;
  }
```

Why SysCall 61? Because that's the value of `SYS_write` System Call according to `nuttx.S` (the RISC-V Disassembly of NuttX Kernel).

_Does it work?_

Nope we don't see SysCall 61, but we see a SysCall 15 (what?)...

```yaml
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
riscv_swint: Entry: regs: 0x8020be10 cmd: 15
up_dump_register: EPC: 00000000c000006c
up_dump_register: A0: 000000000000000f A1: 00000000c0202010 A2: 0000000000000001 A3: 00000000c0202010
up_dump_register: A4: 00000000c0000000 A5: 0000000000000000 A6: 0000000000000000 A7: 0000000000000000
up_dump_register: T0: 0000000000000000 T1: 0000000000000000 T2: 0000000000000000 T3: 0000000000000000
up_dump_register: T4: 0000000000000000 T5: 0000000000000000 T6: 0000000000000000
up_dump_register: S0: 00000000c0202800 S1: 0000000000000000 S2: 0000000000000000 S3: 0000000000000000
up_dump_register: S4: 0000000000000000 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000000000000 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 00000000c02027a0 FP: 00000000c0202800 TP: 0000000000000000 RA: 000000008000adee
riscv_swint: SWInt Return: 7
```

_But the registers A0, A1, A2 and A3 don't look right!_

Let's hardcode Registers A0, A1, A2 and A3 in Machine Code (because TCC won't assemble the `li` instruction): [test-nuttx.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test-nuttx.js#L55-L87)

```c
// Load 61 to Register A0 (SYS_write)
// li a0, 61
".long 0x03d00513 \\n"

// Load 1 to Register A1 (File Descriptor)
// li a1, 1
".long 0x00100593 \\n"

// Load 0xc0101000 to Register A2 (Buffer)
// li a2, 0xc0101000
".long 0x000c0637 \\n"
".long 0x1016061b \\n"
".long 0x00c61613 \\n"

// Load 15 to Register A3 (Buffer Length)
// li a3, 15
".long 0x00f00693 \\n"

// ECALL for System Call to NuttX Kernel
"ecall \\n"

// We inserted NOP, because TCC says it's invalid (see below)
".word 0x0001 \\n"
```

(We used this [RISC-V Online Assembler](https://riscvasm.lucasteske.dev/#) to assemble the Machine Code)

When we run this, we see SysCall 61...

```yaml
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
riscv_swint: Entry: regs: 0x8020be10 cmd: 61
up_dump_register: EPC: 00000000c0000084
up_dump_register: A0: 000000000000003d A1: 0000000000000001 A2: 00000000c0101000 A3: 000000000000000f
up_dump_register: A4: 00000000c0000000 A5: 0000000000000000 A6: 0000000000000000 A7: 0000000000000000
up_dump_register: T0: 0000000000000000 T1: 0000000000000000 T2: 0000000000000000 T3: 0000000000000000
up_dump_register: T4: 0000000000000000 T5: 0000000000000000 T6: 0000000000000000
up_dump_register: S0: 00000000c0202800 S1: 0000000000000000 S2: 0000000000000000 S3: 0000000000000000
up_dump_register: S4: 0000000000000000 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000000000000 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 00000000c02027a0 FP: 00000000c0202800 TP: 0000000000000000 RA: 000000008000adee
riscv_swint: SWInt Return: 35
Hello, World!!
```

And "Hello, World!!" is printed yay!

_How did we figure out that the buffer is at 0xc0101000?_

We saw this in the NuttX Log...

```yaml
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
elf_read: Read 576 bytes from offset 512
elf_loadfile: Loaded sections:
elf_read: Read 154 bytes from offset 64
elf_loadfile: 1. 00000000->c0000000
elf_read: Read 0 bytes from offset 224
elf_loadfile: 2. 00000000->c0101000
elf_read: Read 16 bytes from offset 224
elf_loadfile: 3. 00000000->c0101000
elf_loadfile: 4. 00000000->c0101010
```

Which says that the NuttX ELF Loader copied 16 bytes from our NuttX App Data Section `.data.ro` to 0xc0101000. That's all 15 bytes of "Hello, World!!\n", including the terminating null!

_Something odd about the TCC-generated RISC-V Machine Code?_

The registers seem to be mushed up in the generated RISC-V Machine Code. That's why it was passing value 15 in Register A0. (Supposed to be Register A3)

```text
// register long a0 asm("a0") = 61; // SYS_write
// register long a1 asm("a1") = 1;  // File Descriptor (stdout)
// register long a2 asm("a2") = "Hello, World!!\\n"; // Buffer
// register long a3 asm("a3") = 15; // Buffer Length
// Execute ECALL for System Call to NuttX Kernel
// asm volatile (
// ECALL for System Call to NuttX Kernel
//   "ecall \\n"
//   ".word 0x0001 \\n"

main():
   0:   fc010113                add     sp,sp,-64
   4:   02113c23                sd      ra,56(sp)
   8:   02813823                sd      s0,48(sp)
   c:   04010413                add     s0,sp,64
  10:   00000013                nop
  14:   fea43423                sd      a0,-24(s0)
  18:   feb43023                sd      a1,-32(s0)

// Correct: Load Register A0 with 61 (SYS_write)
  1c:   03d0051b                addw    a0,zero,61
  20:   fca43c23                sd      a0,-40(s0)

// Nope: Load Register A0 with 1?
// Mixed up with Register A1! (Value 1)
  24:   0010051b                addw    a0,zero,1
  28:   fca43823                sd      a0,-48(s0)

// Nope: Load Register A0 with "Hello World"?
// Mixed up with Register A2!
  2c:   00000517                auipc   a0,0x0  2c: R_RISCV_PCREL_HI20  L.0
  30:   00050513                mv      a0,a0   30: R_RISCV_PCREL_LO12_I        .text
  34:   fca43423                sd      a0,-56(s0)

// Nope: Load Register A0 with 15?
// Mixed up with Register A3! (Value 15)
  38:   00f0051b                addw    a0,zero,15
  3c:   fca43023                sd      a0,-64(s0)

// Execute ECALL with Register A0 set to 15.
// Nope A0 should be 1!
  40:   00000073                ecall
  44:   0001                    nop

// Loop Forever
  46:   0000006f                j       46 <main+0x46>
  4a:   03813083                ld      ra,56(sp)
  4e:   03013403                ld      s0,48(sp)
  52:   04010113                add     sp,sp,64
  56:   00008067                ret
```

TODO: Is there a workaround? Do we paste the ECALL Machine Code ourselves?

TODO: Call the NuttX System Call `__exit` to terminate peacefully

# Appendix: Analysis of Missing Functions

TODO: Earlier we saw

TCC calls surprisingly few External Functions! We might get it running on WebAssembly. Here's our analysis of the Missing Functions: [zig/tcc-wasm.zig](zig/tcc-wasm.zig)

## Semaphore Functions

TODO

Not sure why TCC uses Semaphores? Maybe we'll understand when we support `#include` files.

TODO: Borrow Semaphore Functions from where?

- sem_init, sem_post, sem_wait

## Standard Library

TODO

qsort isn't used right now. Maybe for the Linker later?

TODO: Borrow qsort from where?

- exit, qsort

## Time Functions

TODO

Not used right now.

TODO: Borrow Time Functions from where?

- time, gettimeofday, localtime

## Math Functions

TODO

Also not used right now.

TODO: Borrow Math Functions from where?

- ldexp

## Varargs Functions

TODO

Varargs will be tricky to implement in Zig. Probably we should implement in C. Maybe MUSL?

Right now we're doing simple Pattern Matching. But it won't work for Real Programs.

- printf, snprintf, sprintf, vsnprintf
- sscanf

## Filesystem Functions

TODO

Will mock up these functions for WebAssembly. Maybe an Emulated Filesystem, similar to [Emscripten File System](https://emscripten.org/docs/porting/files/file_systems_overview.html)?

- getcwd
- remove, unlink

## File I/O Functions

TODO

Will mock up these functions for WebAssembly. Right now we read only 1 simple C Source File, and produce only 1 Object File. No header files, no libraries. And it works!

But later we might need an Emulated Filesystem, similar to [Emscripten File System](https://emscripten.org/docs/porting/files/file_systems_overview.html). And our File I/O code will support Multiple Files with proper Buffer Overflow Checks.

- open, fopen, fdopen, 
- close, fclose
- fprintf, fputc, fputs
- read, fread
- fwrite
- fflush
- fseek, ftell, lseek
- puts

## String Functions

TODO

Borrow from [foundation-libc](https://github.com/ZigEmbeddedGroup/foundation-libc) and [ziglibc](https://github.com/marler8997/ziglibc)

- atoi
- strcat, strchr, strcmp
- strncmp, strncpy, strrchr
- strstr, strtod, strtof
- strtol, strtold, strtoll
- strtoul, strtoull
- strerror
