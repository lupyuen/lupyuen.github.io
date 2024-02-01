# TCC RISC-V Compiler runs in the Web Browser (thanks to Zig Compiler)

📝 _7 Feb 2024_

![TCC RISC-V Compiler runs in the Web Browser (thanks to Zig Compiler)](https://lupyuen.github.io/images/tcc-title.png)

[(Try the __Online Demo__)](https://lupyuen.github.io/tcc-riscv32-wasm/)

[(Watch the __Demo on YouTube__)](https://youtu.be/DJMDYq52Iv8)

_TCC is a Tiny C Compiler for 64-bit RISC-V (and other platforms)..._

_Can we run TCC Compiler in a Web Browser?_

Let's do it! We'll compile [__TCC (Tiny C Compiler)__](https://github.com/sellicott/tcc-riscv32) from C to WebAssembly with [__Zig Compiler__](https://ziglang.org/).

In this article, we talk about the tricky bits of the TCC Port from __C to WebAssembly__...

- We compiled __TCC to WebAssembly__ with one tiny fix

- But we hit some __Missing POSIX Functions__

- So we cut down on __File Input and Output__ 

- We hacked a simple workaround for __fprintf and friends__

- And TCC produces a __RISC-V Binary__ that runs OK (Somewhat)

  [(Not to be confused with __TTC Compiler__)](https://research.cs.queensu.ca/home/cordy/pub/downloads/tplus/Turing_Plus_Report.pdf)

_Why are we doing this?_

Today we're running [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/tinyemu2) inside a Web Browser, with WebAssembly + Emscripten + 64-bit RISC-V.

(__Real-Time Operating System__ in Web Browser on General-Purpose Operating System!)

What if we could __compile and test NuttX Apps__ in the Web Browser...

1.  We type a __C Program__ into our Web Browser (pic below)

    ```c
    int main(int argc, char *argv[]) {
      printf("Hello, World!!\n");
      return 0;
    }
    ```

1.  Compile it into an __ELF Executable__ (64-bit RISC-V) with TCC

1.  Copy the ELF Executable to the __NuttX Filesystem__ (via WebAssembly)

1.  And __NuttX Emulator__ runs our ELF Executable inside the Web Browser

    [(Watch the __Demo on YouTube__)](https://youtu.be/DJMDYq52Iv8)

This is how we made it happen...

![Online Demo of TCC Compiler in WebAssembly](https://lupyuen.github.io/images/tcc-web.png)

[_Online Demo of TCC Compiler in WebAssembly_](https://lupyuen.github.io/tcc-riscv32-wasm/)

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

[(See the __Entire Disassembly__)](https://gist.github.com/lupyuen/ab8febefa9c649ad7c242ee3f7aaf974)

[(About the __RISC-V Instructions__)](https://lupyuen.github.io/articles/app#inside-a-nuttx-app)

Yep the __64-bit RISC-V Code__ looks legit! Very similar to our [__NuttX App__](https://lupyuen.github.io/articles/app#inside-a-nuttx-app). (So it will probably run on NuttX)

What's really happening? We go behind the scenes...

![Zig Compiler compiles TCC Compiler to WebAssembly](https://lupyuen.github.io/images/tcc-zig.jpg)

# Zig compiles TCC to WebAssembly

_Will Zig Compiler happily compile TCC to WebAssembly?_

Amazingly, yes! (Pic above)

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

[(See the __TCC Source Code__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/tcc.c)

[(About the __Zig Compiler Options__)](https://lupyuen.github.io/articles/tcc#appendix-compile-tcc-with-zig)

We link the TCC WebAssembly with our [__Zig Wrapper__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig) (that exports the TCC Compiler to JavaScript)...

```bash
## Compile our Zig Wrapper `tcc-wasm.zig` for WebAssembly
## and link it with TCC compiled for WebAssembly `tcc.o`
## Generates `tcc-wasm.wasm`
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

## Test everything with Web Browser or NodeJS
node zig/test.js
```

[(See the __Zig Wrapper tcc-wasm.zig__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig)

[(See the __Test JavaScript test.js__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test.js)

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

Plus a couple of Magical Bits that we'll cover in the next section.

[(How JavaScript calls our __Zig Wrapper__)](https://lupyuen.github.io/articles/tcc#appendix-javascript-calls-tcc)

_Zig Compiler compiles TCC without any code changes?_

Inside TCC, we stubbed out the [__setjmp / longjmp__](https://github.com/lupyuen/tcc-riscv32-wasm/commit/e30454a0eb9916f820d58a7c3e104eeda67988d8) to make it compile with Zig Compiler.

Everything else compiles OK!

_Is it really OK to stub them out?_

Well [__setjmp / longjmp__](https://en.wikipedia.org/wiki/Setjmp.h) are called to __Handle Errors__ during TCC Compilation.

We'll find a better way to express our outrage. (Instead of jumping around)

Let's study the Magical Bits inside our Zig Wrapper...

![TCC Compiler in WebAssembly needs POSIX Functions](https://lupyuen.github.io/images/tcc-posix.jpg)

# POSIX for WebAssembly

_What's this POSIX?_

TCC Compiler was created as a __Command Line App__. So it calls the typical [__POSIX Functions__](https://en.wikipedia.org/wiki/POSIX) like __fopen, fprintf, strncpy, malloc,__ ...

[(Similar to the __C Standard Library libc__)](https://en.wikipedia.org/wiki/C_standard_library)

_Is POSIX a problem for WebAssembly?_

WebAssembly running in a Web Browser ain't __No Command Line__! (Pic above)

We counted [__72 POSIX Functions__](https://lupyuen.github.io/articles/tcc#appendix-missing-functions) needed by TCC Compiler, but missing from WebAssembly.

Thus we fill in the [__Missing Functions__](https://lupyuen.github.io/articles/tcc#appendix-missing-functions) ourselves.

[(About the __Missing POSIX Functions__)](https://lupyuen.github.io/articles/tcc#appendix-missing-functions)

_Surely other Zig Devs will have the same problem?_

Thankfully we can borrow the POSIX Code from other __Zig Libraries__...

- [__ziglibc__](https://github.com/marler8997/ziglibc): Zig implementation of libc

- [__foundation-libc__](https://github.com/ZigEmbeddedGroup/foundation-libc): Freestanding implementation of libc

- [__PinePhone Simulator__](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation): For malloc

  [(See the __Borrowed Code__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L447-L774)

_72 POSIX Functions? Sounds like a lot of work..._

Actually we might not need all 72 POSIX Functions. We stubbed out __most of the functions__ to identify the ones that are called: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L774-L853)

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

Some of these functions are especially troubling for WebAssembly...

> ![File Input and Output are especially troubling for WebAssembly](https://lupyuen.github.io/images/tcc-posix2.jpg)

# File Input and Output

_Why no #include in TCC for WebAssembly? And no C Libraries?_

WebAssembly runs in a __Secure Sandbox__. No File Access allowed! (Like for C Header and Library Files)

That's why our Zig Wrapper only __Emulates File Access__ for the bare minimum 2 files...

- Read the __C Program `hello.c`__

- Write the __RISC-V ELF `a.out`__

__Reading a Source File `hello.c`__ is extremely simplistic: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L107-L119)

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

__Writing the Compiled Output `a.out`__ is just as barebones: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L130-L142)

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

We'll have to embed an __Emulated Filesystem__ inside our Zig Wrapper. The Filesystem will contain the C Header and Library Files needed by TCC.

[(Similar to the __Emscripten Filesystem__)](https://emscripten.org/docs/porting/files/file_systems_overview.html)

[(Maybe we embed the simple __ROM FS Filesystem__)](https://docs.kernel.org/filesystems/romfs.html)

![Our Zig Wrapper uses Pattern Matching to match the C Formats and substitute the Zig Equivalent](https://lupyuen.github.io/images/tcc-format.jpg)

# Fearsome fprintf and Friends

_Why is fprintf particularly problematic?_

Here's the fearsome thing about __fprintf__ and friends: __sprintf, snprintf, vsnprintf__...

- __C Format Strings__ are difficult to parse

- __Variable Number of Untyped Arguments__ might create Bad Pointers

Hence we hacked up an implementation of __String Formatting__ that's safer, simpler and so-barebones-you-can-make-_soup-tulang_.

_Soup tulang? Tell me more..._

Our Zig Wrapper uses __Pattern Matching__ to match the __C Formats__ and substitute the __Zig Equivalent__ (pic above): [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L191-L209)

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

[(How we do __Pattern Matching__)](https://lupyuen.github.io/articles/tcc#appendix-pattern-matching)

_So simple? Unbelievable!_

OK actually we'll hit more Format Patterns as TCC Compiler emits various __Error and Warning Messages__. But it's a good start!

Later our Zig Wrapper will have to parse meticulously all kinds of C Format Strings. Or we do the [__parsing in C__](https://github.com/marler8997/ziglibc/blob/main/src/printf.c#L32-L191), compiled to WebAssembly.

(Funny how __printf__ is the first thing we learn about C. Yet it's incredibly difficult to implement!)

![Compile and Run NuttX Apps in the Web Browser](https://lupyuen.github.io/images/tcc-nuttx.jpg)

# Test with Apache NuttX RTOS

_TCC in WebAssembly has compiled our C Program to RISC-V ELF..._

_Will the RISC-V ELF run on Apache NuttX RTOS?_

We copy the __RISC-V ELF `a.out`__ to the __NuttX Apps Filesystem__ (pic above)...

```bash
## Copy RISC-V ELF `a.out`
## to NuttX Apps Filesystem
cp a.out apps/bin/
chmod +x apps/bin/a.out
```

Then we boot __NuttX on QEMU__ (64-bit RISC-V) and run __`a.out`__ on NuttX...

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

[(How we build and run __NuttX for QEMU__)](https://lupyuen.github.io/articles/tcc#appendix-build-nuttx-for-qemu)

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

![TCC WebAssembly compiles a NuttX System Call](https://lupyuen.github.io/images/tcc-ecall.png)

# Hello NuttX!

_We're making a System Call (ECALL) to NuttX Kernel to print something..._

_How will we code this in C?_

We execute the [__ECALL in RISC-V Assembly__](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel) like this: [test-nuttx.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test-nuttx.js#L52-L105)

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

[(Why so complicated? __Explained here__)](https://lupyuen.github.io/articles/tcc#appendix-nuttx-system-call)

[(Warning: __SYS_write 61__ may change)](https://lupyuen.github.io/articles/app#nuttx-kernel-handles-system-call)

_Does it work?_

TCC in WebAssembly compiles the code above to __RISC-V ELF `a.out`__. When we run it on NuttX...

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

_OK so we can compile NuttX Apps in a Web Browser... But can we run them in a Web Browser?_

Yep, a NuttX App compiled in the Web Browser... Now runs OK with __NuttX Emulator in the Web Browser__! 🎉 (Pic below)

- [Watch the __Demo on YouTube__](https://youtu.be/DJMDYq52Iv8)

- [Find out __How It Works__](https://github.com/lupyuen/tcc-riscv32-wasm#nuttx-app-runs-in-a-web-browser)

![NuttX App compiled in a Web Browser... Runs inside the Web Browser!](https://lupyuen.github.io/images/tcc-emu2.png)

[_NuttX App compiled in a Web Browser... Runs inside the Web Browser!_](https://lupyuen.github.io/nuttx-tinyemu/tcc)

# What's Next

TODO

How would you use TCC in a Web Browser? Please lemme know 🙏

(Build and run RISC-V apps on iPhone?)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX and Zig Communities) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tcc.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tcc.md)

# Appendix: Compile TCC with Zig

This is how we run __Zig Compiler to compile TCC Compiler__ from C to WebAssembly (pic below)...

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
## https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly

## Compile our Zig Wrapper `tcc-wasm.zig` for WebAssembly
## and link it with TCC compiled for WebAssembly `tcc.o`
## Generates `tcc-wasm.wasm`

## Omitted: Run the `zig build-exe` command from earlier...
## https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly
```

_How did we figure out the `zig cc` options?_

Earlier we saw a long list of [__Zig Compiler Options__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly)...

```bash
## Zig Compiler Options for TCC Compiler
zig cc \
  tcc.c \
  -DTCC_TARGET_RISCV64 \
  -DCONFIG_TCC_CROSSPREFIX="\"riscv64-\""  \
  -DCONFIG_TCC_CRTPREFIX="\"/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_LIBPATHS="\"{B}:/usr/riscv64-linux-gnu/lib\"" \
  -DCONFIG_TCC_SYSINCLUDEPATHS="\"{B}/include:/usr/riscv64-linux-gnu/include\""   \
  ...
```

We got them from `make --trace`, which shows the __GCC Compiler Options__...

```bash
## Show the GCC Options for compiling TCC
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

And we copied above GCC Options to become the [__Zig Compiler Options__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly).

![TODO](https://lupyuen.github.io/images/tcc-zig.jpg)

# Appendix: JavaScript calls TCC

Previously we saw some __JavaScript (Web Browser and NodeJS)__ calling our TCC Compiler in WebAssembly (pic above)...

- [__TCC WebAssembly in Web Browser__](https://lupyuen.github.io/tcc-riscv32-wasm/)

- [__TCC WebAssembly in NodeJS__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly)

This is how we test the TCC WebAssembly in a Web Browser with a __Local Web Server__...

```bash
## Download the TCC Source Code.
git clone https://github.com/lupyuen/tcc-riscv32-wasm
cd tcc-riscv32-wasm

## Start the Web Server
cargo install simple-http-server
simple-http-server ./docs &

## Copy the Linked TCC WebAssembly to the Web Server
cp tcc-wasm.wasm docs/
```

Browse to this URL and our TCC WebAssembly will appear...

```bash
## Test TCC WebAssembly with Web Browser
http://localhost:8000/index.html
```

Check the __JavaScript Console__ for more messages.

_How does it work?_

On clicking the __Compile Button__, our JavaScript loads the TCC WebAssembly: [tcc.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L170-L187)

```javascript
// Load the WebAssembly Module and start the Main Function.
// Called by the Compile Button.
async function bootstrap() {
  // Load the WebAssembly Module
  // https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/instantiateStreaming
  const result = await WebAssembly.instantiateStreaming(
    fetch("tcc-wasm.wasm"),
    importObject
  );

  // Store references to WebAssembly Functions and Memory exported by Zig
  wasm.init(result);

  // Start the Main Function
  window.requestAnimationFrame(main);
}        
```

[(__importObject__ exports our __JavaScript Logger__ to Zig)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L25-L48)

[(__wasm__ is our __WebAssembly Helper__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L6-L25)

Which triggers the __Main Function__ and calls our Zig Function __compile_program__: [tcc.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L48-L86)

```javascript
// Main Function
function main() {
  // Allocate a String for passing the Compiler Options to Zig
  const options = read_options();
  const options_ptr = allocateString(JSON.stringify(options));
  
  // Allocate a String for passing the Program Code to Zig
  const code = document.getElementById("code").value;
  const code_ptr = allocateString(code);

  // Call TCC to compile a program
  const ptr = wasm.instance.exports
    .compile_program(options_ptr, code_ptr);
  console.log(`main: ptr=${ptr}`);

  // Get the `a.out` size from first 4 bytes returned
  const memory = wasm.instance.exports.memory;
  const data_len = new Uint8Array(memory.buffer, ptr, 4);
  const len = data_len[0] | data_len[1] << 8 | data_len[2] << 16 | data_len[3] << 24;
  console.log(`main: len=${len}`);
  if (len <= 0) { return; }

  // Encode the `a.out` data from the rest of the bytes returned
  const data = new Uint8Array(memory.buffer, ptr + 4, len);
  let encoded_data = "";
  for (const i in data) {
    const hex = Number(data[i]).toString(16).padStart(2, "0");
    encoded_data += `%${hex}`;
  }

  // Download the `a.out` data into the Web Browser
  download("a.out", encoded_data);
};
```

Our Main Function then downloads the __`a.out`__ file returned by our Zig Function.

[(__allocateString__ allocates a String from Zig Memory)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L86-L108)

[(__download__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/docs/tcc.js#L158-L170)

_What about NodeJS calling TCC WebAssembly?_

```bash
## Test TCC WebAssembly with NodeJS
node zig/test.js
```

__For Easier Testing__ (via Command-Line): We copied the JavaScript above into a NodeJS Script: [test.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test.js)

```javascript
// Allocate a String for passing the Compiler Options to Zig
const options = ["-c", "hello.c"];
const options_ptr = allocateString(JSON.stringify(options));

// Allocate a String for passing Program Code to Zig
const code_ptr = allocateString(`
  int main(int argc, char *argv[]) {
    printf("Hello, World!!\\n");
    return 0;
  }
`);

// Call TCC to compile a program
const ptr = wasm.instance.exports
  .compile_program(options_ptr, code_ptr);
```

![Our Zig Wrapper doing Pattern Matching for Formatting C Strings](https://lupyuen.github.io/images/tcc-format.jpg)

# Appendix: Pattern Matching

A while back we saw our Zig Wrapper doing __Pattern Matching__ for Formatting C Strings...

- [__"Fearsome fprintf and Friends"__](https://lupyuen.github.io/articles/tcc#fearsome-fprintf-and-friends)

We use __comptime Functions__ in Zig to implement the C String Formatting (pic above): [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L276-L326)

```zig
/// CompTime Function to format a string by Pattern Matching.
/// Format a Single Specifier, like `#define __BASE_FILE__ "%s"`
/// If the Spec matches the Format: Return the number of bytes written to `str`, excluding terminating null.
/// Else return 0.
fn format_string1(
  ap: *std.builtin.VaList,
  str: [*]u8,
  size: size_t,
  format: []const u8,  // Like `#define %s%s\n`
  comptime c_spec: []const u8,   // Like `%s%s`
  comptime zig_spec: []const u8, // Like `{s}{s}`
  comptime T0: type,  // Like `[*:0]const u8`
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

  // Format the string. TODO: Check for overflow
  var buf: [100]u8 = undefined; // Limit to 100 chars
  const buf_slice = std.fmt.bufPrint(&buf, zig_spec, .{a}) catch {
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

The function above is called by a __comptime Inline Loop__ that applies all the [__Format Patterns__](tcc-wasm.zig) that we saw earlier: [](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L209-L252)

```zig
/// Runtime Function to format a string by Pattern Matching.
/// Return the number of bytes written to `str`, excluding terminating null.
fn format_string(
  ap: *std.builtin.VaList,
  str: [*]u8,
  size: size_t,
  format: []const u8, // Like `#define %s%s\n`
) usize {
  // If no Format Specifiers: Return the Format, like `warning: `
  const len = format_string0(str, size, format);
  if (len > 0) { return len; }

  // For every Format Pattern...
  inline for (format_patterns) |pattern| {
    // Try formatting the string with the pattern...
    const len2 =
      if (pattern.type1) |t1|
      // Pattern has 2 parameters
      format_string2(ap, str, size, format, // Output String and Format String
        pattern.c_spec, pattern.zig_spec, // Format Specifiers for C and Zig
        pattern.type0, t1 // Types of the Parameters
      )
    else
      // Pattern has 1 parameter
      format_string1(ap, str, size, format, // Output String and Format String
        pattern.c_spec, pattern.zig_spec, // Format Specifiers for C and Zig
        pattern.type0 // Type of the Parameter
      );
    if (len2 > 0) { return len2; }
  }

  // Format String doesn't match any Format Pattern. We return the Format String.
  const len3 = format.len;
  @memcpy(str[0..len3], format[0..len3]);
  str[len3] = 0;
  return len3;
}
```

[(__format_string2__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L326-L380)

And the above function is called by __fprintf and friends__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L380-L431)

```zig
/// Implement the POSIX Function `fprintf`
export fn fprintf(stream: *FILE, format: [*:0]const u8, ...) c_int {
  // Prepare the varargs
  var ap = @cVaStart();
  defer @cVaEnd(&ap);

  // Format the string. TODO: Catch overflow
  var buf = std.mem.zeroes([100]u8); // Limit to 100 chars
  const format_slice = std.mem.span(format);
  const len = format_string(&ap, &buf, 0, format_slice);

  // TODO: Print to other File Streams. Right now we assume it's stderr (File Descriptor 2)
  return @intCast(len);
}

// Do the same for sprintf, snprintf, vsnprintf
```

[(See the __Formatting Log__)](https://gist.github.com/lupyuen/3e650bd6ad72b2e8ee8596858bc94f36)

![NuttX Apps make a System Call to print to the console](https://lupyuen.github.io/images/app-syscall.jpg)

# Appendix: NuttX System Call

Not long ago we saw a huge chunk of C Code that makes a __NuttX System Call__...

- [__"Hello NuttX!"__](https://lupyuen.github.io/articles/tcc#hello-nuttx)

_Why so complicated?_

Rightfully this __shorter version__ should work...

```c
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

asm volatile (
  // ECALL for System Call to NuttX Kernel
  "ecall \n"

  // NuttX needs NOP after ECALL
  ".word 0x0001 \n"
);
```

Sadly TCC generates __incorrect RISC-V Machine Code__ that mashes up the RISC-V Registers...

```yaml
main():
// Prepare the Stack
   0:  fc010113  add     sp,sp,-64
   4:  02113c23  sd      ra,56(sp)
   8:  02813823  sd      s0,48(sp)
   c:  04010413  add     s0,sp,64
  10:  00000013  nop
  14:  fea43423  sd      a0,-24(s0)
  18:  feb43023  sd      a1,-32(s0)

// Correct: Load Register A0 with 61 (SYS_write)
  1c:  03d0051b  addw    a0,zero,61
  20:  fca43c23  sd      a0,-40(s0)

// Nope: Load Register A0 with 1?
// Mixed up with Register A1! (Value 1)
  24:  0010051b  addw    a0,zero,1
  28:  fca43823  sd      a0,-48(s0)

// Nope: Load Register A0 with "Hello World"?
// Mixed up with Register A2!
  2c:  00000517  auipc   a0,0x0  2c: R_RISCV_PCREL_HI20  L.0
  30:  00050513  mv      a0,a0   30: R_RISCV_PCREL_LO12_I        .text
  34:  fca43423  sd      a0,-56(s0)

// Nope: Load Register A0 with 15?
// Mixed up with Register A3! (Value 15)
  38:  00f0051b  addw    a0,zero,15
  3c:  fca43023  sd      a0,-64(s0)

// Execute ECALL with Register A0 set to 15.
// Nope A0 should be 1!
  40:  00000073  ecall
  44:  0001      nop
```

Thus we __hardcode Registers A0, A1, A2 and A3__ in Machine Code: [test-nuttx.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test-nuttx.js#L55-L87)

```c
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

// We inserted NOP, because TCC says it's invalid (see below)
".word 0x0001 \n"
```

__TODO:__ Is there a workaround? Do we paste the ECALL Machine Code ourselves?

_What's with the `li` and `nop`?_

TCC won't assemble the __`li`__ and __`nop`__ instructions.

So we used this [__RISC-V Online Assembler__](https://riscvasm.lucasteske.dev/#) to assemble the Machine Code above.

_How did we figure out that the buffer is at 0xC010_1000?_

We saw this in the NuttX Log...

```yaml
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
Read 576 bytes from offset 512
Read 154 bytes from offset 64
1. 00000000->c0000000
Read 0 bytes from offset 224
2. 00000000->c0101000
Read 16 bytes from offset 224
3. 00000000->c0101000
4. 00000000->c0101010
```

Which says that the NuttX ELF Loader copied 16 bytes from our NuttX App Data Section __`.data.ro`__ to __`0xC010_1000`__. That's all 15 bytes of _"Hello, World!!\n"_, including the terminating null.

Thus our buffer is at buffer is at __`0xC010_1000`__.

_Why did we Loop Forever?_

```c
// Omitted: Execute ECALL for System Call to NuttX Kernel
asm volatile ( ... );

// Loop Forever
for(;;) {}
```

That's because NuttX Apps are not supposed to [__Return to NuttX Kernel__](https://github.com/lupyuen/tcc-riscv32-wasm#fix-missing-printf-in-nuttx-app).

We should call the NuttX System Call __`__exit`__ to terminate peacefully.

![Online Demo of Apache NuttX RTOS](https://lupyuen.github.io/images/tcc-demo.png)

[_Online Demo of Apache NuttX RTOS_](https://nuttx.apache.org/demo/)

# Appendix: Build NuttX for QEMU

Here are the steps to build and run __NuttX for QEMU 64-bit RISC-V__ (Kernel Mode)...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh rv-virt:knsh64
    make menuconfig
    ```

1.  (Optional) To enable __ELF Loader Logging__, select...

    - Build Setup > Debug Options > Binary Loader Debug Features > Enable "Binary Loader Error, Warnings and Info"

1.  (Optional) To enable __System Call Logging__, select...

    - Build Setup > Debug Options > SYSCALL  Debug Features > Enable "SYSCALL Error, Warnings and Info"

1.  Save and exit __menuconfig__.

1.  Build the __NuttX Kernel and NuttX Apps__...

    ```bash
    ## Build NuttX Kernel
    make -j 8

    ## Build NuttX Apps
    make -j 8 export
    pushd ../apps
    ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    make -j 8 import
    popd
    ```

This produces the NuttX ELF Image __nuttx__ that we may boot on QEMU RISC-V Emulator...

```bash
## For macOS: Install QEMU
brew install qemu

## For Debian and Ubuntu: Install QEMU
sudo apt install qemu-system-riscv64

## Boot NuttX on QEMU 64-bit RISC-V
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

NuttX Apps are located in __`apps/bin`__.

We may copy our __RISC-V ELF `a.out`__ to that folder.

![POSIX Functions aren't supported for TCC in WebAssembly](https://lupyuen.github.io/images/tcc-posix.jpg)

# Appendix: Missing Functions

Remember we said that POSIX Functions aren't supported in WebAssembly? (Pic above)

- [__"POSIX for WebAssembly"__](https://lupyuen.github.io/articles/tcc#posix-for-webassembly)

We dump the __Compiled WebAssembly__ of TCC Compiler, and we discover that it calls __72 POSIX Functions__...

```bash
## Dump the Compiled WebAssembly
## for TCC Compiler
$ sudo apt install wabt
$ wasm-objdump -x tcc.o

Import:
 - func[0] sig=1 <env.strcmp>  <- env.strcmp
 - func[1] sig=12 <env.memset> <- env.memset
 - func[2] sig=1 <env.getcwd>  <- env.getcwd
 ...
 - func[69] sig=2 <env.localtime> <- env.localtime
 - func[70] sig=13 <env.qsort>    <- env.qsort
 - func[71] sig=19 <env.strtoll>  <- env.strtoll
```

[(See the __Complete List__)](https://github.com/lupyuen/tcc-riscv32-wasm#missing-functions-in-tcc-webassembly)

Do we really need all 72 POSIX Functions? We run through the list...

__Filesystem Functions:__

We'll simulate these functions for WebAssembly. Maybe with an Emulated Filesystem, similar to [__Emscripten Filesystem__](https://emscripten.org/docs/porting/files/file_systems_overview.html). Or we embed [__ROM FS Filesystem__](https://docs.kernel.org/filesystems/romfs.html) into our Zig Wrapper.

- getcwd
- remove, unlink
- open, fopen, fdopen, 
- close, fclose
- fprintf, fputc, fputs
- read, fread
- fwrite
- fflush
- fseek, ftell, lseek
- puts

__Varargs Functions:__

As discussed earlier, Varargs will be tricky to implement in Zig. Probably we should do it in C. [(Like __ziglibc__)](https://github.com/marler8997/ziglibc/blob/main/src/printf.c#L32-L191)

Right now we're doing simple [__Pattern Matching__](TODO). But it might not be sufficient when TCC compiles Real Programs.

- printf, snprintf, sprintf, vsnprintf
- sscanf

__String Functions:__

We'll borrow from [__ziglibc__](https://github.com/marler8997/ziglibc) and [__foundation-libc__](https://github.com/ZigEmbeddedGroup/foundation-libc).

- atoi
- strcat, strchr, strcmp
- strncmp, strncpy, strrchr
- strstr, strtod, strtof
- strtol, strtold, strtoll
- strtoul, strtoull
- strerror

__Semaphore Functions:__

Not sure why TCC uses Semaphores? Maybe we'll understand when we support __`#include`__ files.

(Where can we borrow the Semaphore Functions?)

- sem_init, sem_post, sem_wait

__Standard Library:__

__qsort__ isn't used right now. Maybe for the Linker later?

(Borrow __qsort__ from where? We can probably implement __exit__)

- exit, qsort

__Time Functions:__

Not used right now, maybe later.

(How will we get the Time Functions? Call out to JavaScript to fetch the actual time?)

- time, gettimeofday, localtime

__Math Functions:__

Also not used right now.

(Anyone can lend us __ldexp__?)

- ldexp

__Outstanding Functions:__

We have implemented (fully or partially) many of the POSIX Functions above.

The ones that we haven't implemented? [__They will crash__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/tcc-wasm.zig#L774-L853) when TCC WebAssembly calls them...

TODO
