# TCC RISC-V Compiler runs in the Web Browser (thanks to Zig Compiler)

📝 _7 Feb 2024_

![TODO](https://lupyuen.github.io/images/tcc-title.png)

_TCC is a Tiny C Compiler for 64-bit RISC-V (and other platforms)..._

_Can we run TCC in a Web Browser?_

Let's do it! We'll compile [__TCC (Tiny C Compiler)__](https://github.com/sellicott/tcc-riscv32) from C to WebAssembly with [__Zig Compiler__](https://ziglang.org/).

In this article, we talk about the tricky bits of the TCC Porting from __C to WebAssembly__...

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

[(See the __Complete Output__)](https://gist.github.com/lupyuen/ab8febefa9c649ad7c242ee3f7aaf974)

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

One last chance to make NuttX say hello...

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

[(__Warning:__ SYS_write 61 may change!)](https://lupyuen.github.io/articles/app#nuttx-kernel-handles-system-call)

# TCC generates 64-bit RISC-V code

TODO

We build TCC to support 64-bit RISC-V Target...

```bash
## Build TCC for 64-bit RISC-V Target
git clone https://github.com/lupyuen/tcc-riscv32-wasm
cd tcc-riscv32-wasm
./configure
make help
make --trace cross-riscv64
./riscv64-tcc -v
```

We compile this C program...

```c
## Simple C Program
int main(int argc, char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
```

Like this...

```bash
## Compile C to 64-bit RISC-V
/workspaces/bookworm/tcc-riscv32/riscv64-tcc \
    -c \
    /workspaces/bookworm/apps/examples/hello/hello_main.c

## Dump the 64-bit RISC-V Disassembly
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  hello_main.o \
  >hello_main.S \
  2>&1
```

The RISC-V Disassembly looks valid, very similar to a [NuttX App](https://lupyuen.github.io/articles/app#inside-a-nuttx-app) (so it will probably run on NuttX): [hello_main.S](https://gist.github.com/lupyuen/46ffc9481c79e36274c0980f9d58f806)

```text
hello_main.o:     file format elf64-littleriscv
SYMBOL TABLE:
0000000000000000 l    df *ABS*  0000000000000000 /workspaces/bookworm/apps/examples/hello/hello_m
ain.c
0000000000000000 l     O .data.ro       0000000000000010 L.0
0000000000000000 g     F .text  0000000000000040 main
0000000000000000       F *UND*  0000000000000000 printf

Disassembly of section .text:
0000000000000000 <main>:
main():
   0:   fe010113                add     sp,sp,-32
   4:   00113c23                sd      ra,24(sp)
   8:   00813823                sd      s0,16(sp)
   c:   02010413                add     s0,sp,32
  10:   00000013                nop
  14:   fea43423                sd      a0,-24(s0)
  18:   feb43023                sd      a1,-32(s0)
  1c:   00000517                auipc   a0,0x0  1c: R_RISCV_PCREL_HI20  L.0
  20:   00050513                mv      a0,a0   20: R_RISCV_PCREL_LO12_I        .text
  24:   00000097                auipc   ra,0x0  24: R_RISCV_CALL_PLT    printf
  28:   000080e7                jalr    ra # 24 <main+0x24>
  2c:   0000051b                sext.w  a0,zero
  30:   01813083                ld      ra,24(sp)
  34:   01013403                ld      s0,16(sp)
  38:   02010113                add     sp,sp,32
  3c:   00008067                ret
```

See the Object File: [hello_main.o](https://gist.github.com/lupyuen/ac600d793a60b1e7f6ac95918580f266)

# Compile TCC with Zig Compiler

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

gcc \
  -o riscv64-tcc riscv64-tcc.o \
  -lm \
  -lpthread \
  -ldl \
  -s \

## Probably won't need this for now
../riscv64-tcc -c lib-arm64.c -o riscv64-lib-arm64.o -B.. -I..
../riscv64-tcc -c stdatomic.c -o riscv64-stdatomic.o -B.. -I..
../riscv64-tcc -c atomic.S -o riscv64-atomic.o -B.. -I..
../riscv64-tcc -c dsohandle.c -o riscv64-dsohandle.o -B.. -I..
../riscv64-tcc -ar rcs ../riscv64-libtcc1.a riscv64-lib-arm64.o riscv64-stdatomic.o riscv64-atomic.o riscv64-dsohandle.o
```

We copy the above GCC Options and we compile TCC with Zig Compiler...

```bash
## Compile TCC with Zig Compiler
export PATH=/workspaces/bookworm/zig-linux-x86_64-0.12.0-dev.2341+92211135f:$PATH
./configure
make --trace cross-riscv64
zig cc \
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

## Test our TCC compiled with Zig Compiler
/workspaces/bookworm/tcc-riscv32/a.out -v

/workspaces/bookworm/tcc-riscv32/a.out -c \
  /workspaces/bookworm/apps/examples/hello/hello_main.c

riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  hello_main.o \
  >hello_main.S \
  2>&1
```

Yep it works OK!

# Compile TCC to WebAssembly with Zig Compiler

TODO

Now we compile TCC to WebAssembly.

Zig Compiler doesn't like it, so we [Patch the longjmp / setjmp](https://github.com/lupyuen/tcc-riscv32-wasm/commit/e30454a0eb9916f820d58a7c3e104eeda67988d8). (We probably won't need it unless TCC hits Compiler Errors)

```bash
## Compile TCC from C to WebAssembly
./configure
make --trace cross-riscv64
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

## Dump our Compiled WebAssembly
sudo apt install wabt
wasm-objdump -h tcc.o
wasm-objdump -x tcc.o >/tmp/tcc.txt
```

Yep TCC compiles OK to WebAssembly with Zig Compiler!

# Missing Functions in TCC WebAssembly

TODO

We check the Compiled WebAssembly. These POSIX Functions are missing from the Compiled WebAssembly...

```text
$ wasm-objdump -x tcc.o >/tmp/tcc.txt
$ cat /tmp/tcc.txt

Import[75]:
 - memory[0] pages: initial=2 <- env.__linear_memory
 - global[0] i32 mutable=1 <- env.__stack_pointer
 - func[0] sig=1 <env.strcmp> <- env.strcmp
 - func[1] sig=12 <env.memset> <- env.memset
 - func[2] sig=1 <env.getcwd> <- env.getcwd
 - func[3] sig=1 <env.strcpy> <- env.strcpy
 - func[4] sig=2 <env.unlink> <- env.unlink
 - func[5] sig=0 <env.free> <- env.free
 - func[6] sig=6 <env.snprintf> <- env.snprintf
 - func[7] sig=2 <env.getenv> <- env.getenv
 - func[8] sig=2 <env.strlen> <- env.strlen
 - func[9] sig=12 <env.sem_init> <- env.sem_init
 - func[10] sig=2 <env.sem_wait> <- env.sem_wait
 - func[11] sig=1 <env.realloc> <- env.realloc
 - func[12] sig=12 <env.memmove> <- env.memmove
 - func[13] sig=2 <env.malloc> <- env.malloc
 - func[14] sig=12 <env.fprintf> <- env.fprintf
 - func[15] sig=2 <env.puts> <- env.puts
 - func[16] sig=0 <env.exit> <- env.exit
 - func[17] sig=2 <env.sem_post> <- env.sem_post
 - func[18] sig=1 <env.strchr> <- env.strchr
 - func[19] sig=1 <env.strrchr> <- env.strrchr
 - func[20] sig=6 <env.vsnprintf> <- env.vsnprintf
 - func[21] sig=1 <env.printf> <- env.printf
 - func[22] sig=2 <env.fflush> <- env.fflush
 - func[23] sig=12 <env.memcpy> <- env.memcpy
 - func[24] sig=12 <env.memcmp> <- env.memcmp
 - func[25] sig=12 <env.sscanf> <- env.sscanf
 - func[26] sig=1 <env.fputs> <- env.fputs
 - func[27] sig=2 <env.close> <- env.close
 - func[28] sig=12 <env.open> <- env.open
 - func[29] sig=18 <env.lseek> <- env.lseek
 - func[30] sig=12 <env.read> <- env.read
 - func[31] sig=12 <env.strtol> <- env.strtol
 - func[32] sig=2 <env.atoi> <- env.atoi
 - func[33] sig=19 <env.strtoull> <- env.strtoull
 - func[34] sig=12 <env.strtoul> <- env.strtoul
 - func[35] sig=1 <env.strstr> <- env.strstr
 - func[36] sig=1 <env.fopen> <- env.fopen
 - func[37] sig=12 <env.sprintf> <- env.sprintf
 - func[38] sig=2 <env.fclose> <- env.fclose
 - func[39] sig=12 <env.fseek> <- env.fseek
 - func[40] sig=2 <env.ftell> <- env.ftell
 - func[41] sig=6 <env.fread> <- env.fread
 - func[42] sig=6 <env.fwrite> <- env.fwrite
 - func[43] sig=2 <env.remove> <- env.remove
 - func[44] sig=1 <env.gettimeofday> <- env.gettimeofday
 - func[45] sig=1 <env.fdopen> <- env.fdopen
 - func[46] sig=12 <env.strncpy> <- env.strncpy
 - func[47] sig=24 <env.__extendsftf2> <- env.__extendsftf2
 - func[48] sig=25 <env.__extenddftf2> <- env.__extenddftf2
 - func[49] sig=9 <env.__floatunditf> <- env.__floatunditf
 - func[50] sig=3 <env.__floatunsitf> <- env.__floatunsitf
 - func[51] sig=26 <env.__trunctfsf2> <- env.__trunctfsf2
 - func[52] sig=27 <env.__trunctfdf2> <- env.__trunctfdf2
 - func[53] sig=28 <env.__netf2> <- env.__netf2
 - func[54] sig=29 <env.__fixunstfdi> <- env.__fixunstfdi
 - func[55] sig=30 <env.__subtf3> <- env.__subtf3
 - func[56] sig=30 <env.__multf3> <- env.__multf3
 - func[57] sig=28 <env.__eqtf2> <- env.__eqtf2
 - func[58] sig=30 <env.__divtf3> <- env.__divtf3
 - func[59] sig=30 <env.__addtf3> <- env.__addtf3
 - func[60] sig=2 <env.strerror> <- env.strerror
 - func[61] sig=1 <env.fputc> <- env.fputc
 - func[62] sig=1 <env.strcat> <- env.strcat
 - func[63] sig=12 <env.strncmp> <- env.strncmp
 - func[64] sig=31 <env.ldexp> <- env.ldexp
 - func[65] sig=32 <env.strtof> <- env.strtof
 - func[66] sig=8 <env.strtold> <- env.strtold
 - func[67] sig=33 <env.strtod> <- env.strtod
 - func[68] sig=2 <env.time> <- env.time
 - func[69] sig=2 <env.localtime> <- env.localtime
 - func[70] sig=13 <env.qsort> <- env.qsort
 - func[71] sig=19 <env.strtoll> <- env.strtoll
 - table[0] type=funcref initial=4 <- env.__indirect_function_table
```

TODO: How to fix these missing POSIX Functions for WebAssembly (Web Browser)

TODO: Do we need all of them? Maybe we run in a Web Browser and see what crashes? [Similar to this](https://lupyuen.github.io/articles/lvgl3)

# Test the TCC WebAssembly with NodeJS

TODO

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

# Test the TCC WebAssembly in a Web Browser

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

# Fix the Missing Functions

TODO

When we call `main()` in our Zig App: [zig/tcc-wasm.zig](zig/tcc-wasm.zig)

We see many many Undefined Symbols...

```text
+ zig build-exe --verbose-cimport -target wasm32-freestanding -rdynamic -lc -fno-entry --export=compile_program zig/tcc-wasm.zig tcc.o
error: wasm-ld: tcc.o: undefined symbol: realloc
error: wasm-ld: tcc.o: undefined symbol: free
error: wasm-ld: tcc.o: undefined symbol: snprintf
[...many many more...]
```

So we stubbed them in our Zig App: [zig/tcc-wasm.zig](zig/tcc-wasm.zig)

```zig
/// Fix the Missing Variables
pub export var errno: c_int = 0;
pub export var stdout: c_int = 1;
pub export var stderr: c_int = 2;

/// Fix the Missing Functions
pub export fn atoi(_: c_int) c_int {
    @panic("TODO: atoi");
}
pub export fn close(_: c_int) c_int {
    @panic("TODO: close");
}
[...many many more...]
```

Then we...

1.  Borrow from [foundation-libc](https://github.com/ZigEmbeddedGroup/foundation-libc) and [ziglibc](https://github.com/marler8997/ziglibc)

1.  [Fix malloc()](https://github.com/lupyuen/tcc-riscv32-wasm/commit/e7c76474deb52acadd3540dec0589ab98ae243a9#diff-5ecd8d41f5376644e9c3f17c9eac540841ff6f7c00bca34d7811b54e0b9bd7a0)

1.  [Add getenv()](https://github.com/lupyuen/tcc-riscv32-wasm/commit/c230681899503ea4fe37a3c7ff0031f7018e2e2d)

1.  [Add String Functions](https://github.com/lupyuen/tcc-riscv32-wasm/commit/4ea06f7602471a65539c65c746bfa65c6d1d4184)

1.  [Add open()](https://github.com/lupyuen/tcc-riscv32-wasm/commit/c0095568c3595c09345936b74616b528c99b364e)

1.  [Add sem_init, sem_wait, puts](https://github.com/lupyuen/tcc-riscv32-wasm/commit/99d1d4a19a2530d1972222d0cdea1c52771f537c)

1.  [Increase malloc buffer](https://github.com/lupyuen/tcc-riscv32-wasm/commit/765bc8b1313d579f9e8975ec57e949408385ae6e)

1.  [Add sscanf](https://github.com/lupyuen/tcc-riscv32-wasm/commit/abf18acd6053b852363afa9adefcc81501f334ed)

1.  [Add vsnprintf and fflush](https://github.com/lupyuen/tcc-riscv32-wasm/commit/c76b671e771d6ba4bb62230e1546aeb3e8637850)

1.  [Add fprintf](https://github.com/lupyuen/tcc-riscv32-wasm/commit/36d591ea197eb87eb5f14e9632512cfecc99cbaf)

1.  [Add read](https://github.com/lupyuen/tcc-riscv32-wasm/commit/7fe054b38cb52a289f1f512ba1e4ab07823b2ca4)

1.  [Add sprintf, snprintf](https://github.com/lupyuen/tcc-riscv32-wasm/commit/dd0161168815d570259e08d4bf0370a363e6e6e7)

1.  [Add close, sem_post, unlink](https://github.com/lupyuen/tcc-riscv32-wasm/commit/812eaa10d36bd29b6f4efcc35b09f4899f880d5b)

1.  [Add fdopen](https://github.com/lupyuen/tcc-riscv32-wasm/commit/7380fe18d6d109abb55b473b7b7e53749f92a32b)

1.  [Add fwrite](https://github.com/lupyuen/tcc-riscv32-wasm/commit/865eaa7970193cc1d3d3dbdfb2b1314971cc1d1c)

1.  [Add fputc](https://github.com/lupyuen/tcc-riscv32-wasm/commit/679d28b1020098d5e4e81f4646611f26270374a7)

1.  [Add fclose](https://github.com/lupyuen/tcc-riscv32-wasm/commit/455724992a92bcc2c6294a0a93612c5a616c1013)

1.  [Add fputs](https://github.com/lupyuen/tcc-riscv32-wasm/commit/547759dcf9b991c3b49737e24133b45c47dfd378)

1.  [Change `L.%u` to `L.0`, `.rela%s` to `.rela.text`](https://github.com/lupyuen/tcc-riscv32-wasm/commit/3c8e4337a66e77d06877f7b1606db71139560104)

1.  [Dump the `a.out` file](https://github.com/lupyuen/tcc-riscv32-wasm/commit/a6602a602293addfeb9ce548b9a3aacb62127c5f)

# TCC WebAssembly runs OK in a Web Browser!

TODO

When we run it in a [Web Browser](https://lupyuen.github.io/tcc-riscv32-wasm/): TCC compiles `hello.c` and writes to `a.out` yay!

```text
+ node zig/test.js
compile_program
open: path=hello.c, oflag=0, return fd=3
sem_init: sem=tcc-wasm.sem_t@107678, pshared=0, value=1
sem_wait: sem=tcc-wasm.sem_t@107678
TODO: setjmp
TODO: sscanf: str=0.9.27, format=%d.%d.%d
TODO: vsnprintf: size=128, format=#define __TINYC__ %d
TODO: vsnprintf: return str=#define __TINYC__ %d
TODO: vsnprintf: size=107, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=94, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=81, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=196, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=183, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=170, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=157, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=144, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=131, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=118, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=105, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=92, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=335, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=322, format=#define __SIZEOF_POINTER__ %d
TODO: vsnprintf: return str=#define __SIZEOF_POINTER__ %d
TODO: vsnprintf: size=292, format=#define __SIZEOF_LONG__ %d
TODO: vsnprintf: return str=#define __SIZEOF_LONG__ %d
TODO: vsnprintf: size=265, format=#define %s%s
TODO: vsnprintf: return str=#define FIX_vsnprintf
TODO: vsnprintf: size=252, format=#define __STDC_VERSION__ %dL
TODO: vsnprintf: return str=#define __STDC_VERSION__ %dL
TODO: vsnprintf: size=497, format=#define __BASE_FILE__ "%s"
TODO: vsnprintf: return str=#define __BASE_FILE__ "%s"
TODO: vsnprintf: size=128, format=In file included from %s:%d:
TODO: vsnprintf: return str=In file included from %s:%d:
TODO: vsnprintf: size=99, format=%s:%d: 
TODO: vsnprintf: return str=%s:%d: 
TODO: vsnprintf: size=92, format=warning: 
TODO: vsnprintf: return str=warning: 
TODO: vsnprintf: size=83, format=%s redefined
TODO: vsnprintf: return str=%s redefined
fprintf: stream=tcc-wasm.FILE@2, format=%s
read: fd=3, nbyte=8192
read: return buf=int main(int argc, char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
TODO: vsnprintf: size=128, format=%s:%d: 
TODO: vsnprintf: return str=%s:%d: 
TODO: vsnprintf: size=121, format=warning: 
TODO: vsnprintf: return str=warning: 
TODO: vsnprintf: size=112, format=implicit declaration of function '%s'
TODO: vsnprintf: return str=implicit declaration of function '%s'
fprintf: stream=tcc-wasm.FILE@2, format=%s
TODO: sprintf: format=L.%u
TODO: sprintf: return str=L.0
TODO: snprintf: size=256, format=.rela%s
TODO: snprintf: return str=.rela.text
read: fd=3, nbyte=8192
read: return 0
close: fd=3
sem_post: sem=tcc-wasm.sem_t@107678
TODO: snprintf: size=1024, format=%s
TODO: snprintf: return str=%s

unlink: path=a.out
open: path=a.out, oflag=577, return fd=4
fdopen: fd=4, mode=wb, return FILE=5
fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  7F 45 4C 46 02 01 01 00  00 00 00 00 00 00 00 00  .ELF............
  0016:  01 00 F3 00 01 00 00 00  00 00 00 00 00 00 00 00  ................
  0032:  00 00 00 00 00 00 00 00  D0 01 00 00 00 00 00 00  ................
  0048:  04 00 00 00 40 00 00 00  00 00 40 00 09 00 08 00  ....@.....@.....

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  13 01 01 FE 23 3C 11 00  23 38 81 00 13 04 01 02  ....#<..#8......
  0016:  13 00 00 00 23 34 A4 FE  23 30 B4 FE 17 05 00 00  ....#4..#0......
  0032:  13 05 05 00 97 00 00 00  E7 80 00 00 1B 05 00 00  ................
  0048:  83 30 81 01 03 34 01 01  13 01 01 02 67 80 00 00  .0...4......g...

fwrite: size=1, nmemb=16, stream=tcc-wasm.FILE@5
  0000:  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21 21 0A 00  Hello, World!!..

fwrite: size=1, nmemb=144, stream=tcc-wasm.FILE@5
  0000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  01 00 00 00 04 00 F1 FF  ................
  0032:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  0E 00 00 00 01 00 03 00  00 00 00 00 00 00 00 00  ................
  0064:  10 00 00 00 00 00 00 00  00 00 00 00 00 00 01 00  ................
  0080:  1C 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0096:  09 00 00 00 12 00 01 00  00 00 00 00 00 00 00 00  ................
  0112:  40 00 00 00 00 00 00 00  12 00 00 00 12 00 00 00  @...............
  0128:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=25, stream=tcc-wasm.FILE@5
  0000:  00 68 65 6C 6C 6F 2E 63  00 6D 61 69 6E 00 4C 2E  .hello.c.main.L.
  0016:  30 00 70 72 69 6E 74 66  00                       0.printf.

fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fwrite: size=1, nmemb=72, stream=tcc-wasm.FILE@5
  0000:  1C 00 00 00 00 00 00 00  17 00 00 00 02 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  20 00 00 00 00 00 00 00  ........ .......
  0032:  18 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  24 00 00 00 00 00 00 00  13 00 00 00 05 00 00 00  $...............
  0064:  00 00 00 00 00 00 00 00                           ........

fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fputc: c=0x00, stream=tcc-wasm.FILE@5
fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  00 2E 74 65 78 74 00 2E  64 61 74 61 00 2E 64 61  ..text..data..da
  0016:  74 61 2E 72 6F 00 2E 62  73 73 00 2E 73 79 6D 74  ta.ro..bss..symt
  0032:  61 62 00 2E 73 74 72 74  61 62 00 2E 72 65 6C 61  ab..strtab..rela
  0048:  2E 74 65 78 74 00 2E 73  68 73 74 72 74 61 62 00  .text..shstrtab.

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0032:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  01 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
  0032:  40 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  @...............
  0048:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  07 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  80 00 00 00 00 00 00 00  ................
  0032:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  0D 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  80 00 00 00 00 00 00 00  ................
  0032:  10 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  16 00 00 00 08 00 00 00  03 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00  ................
  0032:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  1B 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00  ................
  0016:  00 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00  ................
  0032:  90 00 00 00 00 00 00 00  06 00 00 00 04 00 00 00  ................
  0048:  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  23 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  #...............
  0016:  00 00 00 00 00 00 00 00  20 01 00 00 00 00 00 00  ........ .......
  0032:  19 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0048:  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  2B 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  +...............
  0016:  00 00 00 00 00 00 00 00  40 01 00 00 00 00 00 00  ........@.......
  0032:  48 00 00 00 00 00 00 00  05 00 00 00 01 00 00 00  H...............
  0048:  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  ................

fwrite: size=1, nmemb=64, stream=tcc-wasm.FILE@5
  0000:  36 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  6...............
  0016:  00 00 00 00 00 00 00 00  90 01 00 00 00 00 00 00  ................
  0032:  40 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  @...............
  0048:  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

close: stream=tcc-wasm.FILE@5
a.out: 1040 bytes
  0000:  7F 45 4C 46 02 01 01 00  00 00 00 00 00 00 00 00  .ELF............
  0016:  01 00 F3 00 01 00 00 00  00 00 00 00 00 00 00 00  ................
  0032:  00 00 00 00 00 00 00 00  D0 01 00 00 00 00 00 00  ................
  0048:  04 00 00 00 40 00 00 00  00 00 40 00 09 00 08 00  ....@.....@.....
  0064:  13 01 01 FE 23 3C 11 00  23 38 81 00 13 04 01 02  ....#<..#8......
  0080:  13 00 00 00 23 34 A4 FE  23 30 B4 FE 17 05 00 00  ....#4..#0......
  0096:  13 05 05 00 97 00 00 00  E7 80 00 00 1B 05 00 00  ................
  0112:  83 30 81 01 03 34 01 01  13 01 01 02 67 80 00 00  .0...4......g...
  0128:  48 65 6C 6C 6F 2C 20 57  6F 72 6C 64 21 21 0A 00  Hello, World!!..
  0144:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0160:  00 00 00 00 00 00 00 00  01 00 00 00 04 00 F1 FF  ................
  0176:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0192:  0E 00 00 00 01 00 03 00  00 00 00 00 00 00 00 00  ................
  0208:  10 00 00 00 00 00 00 00  00 00 00 00 00 00 01 00  ................
  0224:  1C 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0240:  09 00 00 00 12 00 01 00  00 00 00 00 00 00 00 00  ................
  0256:  40 00 00 00 00 00 00 00  12 00 00 00 12 00 00 00  @...............
  0272:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0288:  00 68 65 6C 6C 6F 2E 63  00 6D 61 69 6E 00 4C 2E  .hello.c.main.L.
  0304:  30 00 70 72 69 6E 74 66  00 00 00 00 00 00 00 00  0.printf........
  0320:  1C 00 00 00 00 00 00 00  17 00 00 00 02 00 00 00  ................
  0336:  00 00 00 00 00 00 00 00  20 00 00 00 00 00 00 00  ........ .......
  0352:  18 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  ................
  0368:  24 00 00 00 00 00 00 00  13 00 00 00 05 00 00 00  $...............
  0384:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0400:  00 2E 74 65 78 74 00 2E  64 61 74 61 00 2E 64 61  ..text..data..da
  0416:  74 61 2E 72 6F 00 2E 62  73 73 00 2E 73 79 6D 74  ta.ro..bss..symt
  0432:  61 62 00 2E 73 74 72 74  61 62 00 2E 72 65 6C 61  ab..strtab..rela
  0448:  2E 74 65 78 74 00 2E 73  68 73 74 72 74 61 62 00  .text..shstrtab.
  0464:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0480:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0496:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0512:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0528:  01 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  ................
  0544:  00 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
  0560:  40 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  @...............
  0576:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0592:  07 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  ................
  0608:  00 00 00 00 00 00 00 00  80 00 00 00 00 00 00 00  ................
  0624:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0640:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0656:  0D 00 00 00 01 00 00 00  03 00 00 00 00 00 00 00  ................
  0672:  00 00 00 00 00 00 00 00  80 00 00 00 00 00 00 00  ................
  0688:  10 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0704:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0720:  16 00 00 00 08 00 00 00  03 00 00 00 00 00 00 00  ................
  0736:  00 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00  ................
  0752:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0768:  08 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0784:  1B 00 00 00 02 00 00 00  00 00 00 00 00 00 00 00  ................
  0800:  00 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00  ................
  0816:  90 00 00 00 00 00 00 00  06 00 00 00 04 00 00 00  ................
  0832:  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  ................
  0848:  23 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  #...............
  0864:  00 00 00 00 00 00 00 00  20 01 00 00 00 00 00 00  ........ .......
  0880:  19 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0896:  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
  0912:  2B 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  +...............
  0928:  00 00 00 00 00 00 00 00  40 01 00 00 00 00 00 00  ........@.......
  0944:  48 00 00 00 00 00 00 00  05 00 00 00 01 00 00 00  H...............
  0960:  08 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  ................
  0976:  36 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  6...............
  0992:  00 00 00 00 00 00 00 00  90 01 00 00 00 00 00 00  ................
  1008:  40 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  @...............
  1024:  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

ret=1040
```

Also published publicly here (see the JavaScript Console): https://lupyuen.github.io/tcc-riscv32-wasm/

TODO: Check our WebAssembly with [Modsurfer](https://github.com/dylibso/modsurfer)

TODO: Need to implement vsnprintf() in C? Or we hardcode the patterns?

TODO: Didn't we pass the TCC Option `-c` to generate as Object File? Why is the output `a.out`?

Note: `invalid macro name` is caused by `#define %s%s`. We should mock up a valid name for `%s%s`

![TCC RISC-V Compiler: Compiled to WebAssembly with Zig Compiler](https://lupyuen.github.io/images/tcc-title.png)

[_(Try the __Online Demo__)_](https://lupyuen.github.io/tcc-riscv32-wasm/)

# Verify the TCC Output

TODO

Let's verify the generated `a.out`.

We copy the above `a.out` Hex Dump into a Text File: [a.txt](https://gist.github.com/lupyuen/fd78742847b146c6eea5dfcff0d932f7)

Then we decompile it...

```bash
## Convert a.txt to a.out
cat a.txt \
  | cut --bytes=10-58 \
  | xxd -revert -plain \
  >a.out

## Decompile the a.out to RISC-V Disassembly a.S
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  a.out \
  >a.S \
  2>&1
```

And the Decompiled RISC-V Disassembly looks correct! [a.S](https://gist.github.com/lupyuen/9a9fe3a7c061503f33752221dcb0992c)

```text
main():
   0: fe010113           add sp,sp,-32
   4: 00113c23           sd ra,24(sp)
   8: 00813823           sd s0,16(sp)
   c: 02010413           add s0,sp,32
  10: 00000013           nop
  14: fea43423           sd a0,-24(s0)
  18: feb43023           sd a1,-32(s0)
  1c: 00000517           auipc a0,0x0 1c: R_RISCV_PCREL_HI20 L.0
  20: 00050513           mv a0,a0 20: R_RISCV_PCREL_LO12_I .text
  24: 00000097           auipc ra,0x0 24: R_RISCV_CALL_PLT printf
  28: 000080e7           jalr ra # 24 <main+0x24>
  2c: 0000051b           sext.w a0,zero
  30: 01813083           ld ra,24(sp)
  34: 01013403           ld s0,16(sp)
  38: 02010113           add sp,sp,32
  3c: 00008067           ret
```

Very similar to [hello_main.S](https://gist.github.com/lupyuen/46ffc9481c79e36274c0980f9d58f806)

So yes TCC runs correctly in a Web Browser. With some limitations and lots of hacking! Yay!

![TCC RISC-V Compiler: Compiled to WebAssembly with Zig Compiler](https://lupyuen.github.io/images/tcc-web.png)

[_(Try the __Online Demo__)_](https://lupyuen.github.io/tcc-riscv32-wasm/)

TODO: Pic of Format Patterns

# Fearsome fprintf and Friends

TODO

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

# Test TCC Output with NuttX

TODO

_TCC in WebAssembly has compiled our C Program into the ELF Binary `a.out`. What happens when we run it on NuttX?_

Let's run the TCC Output `a.out` on NuttX! We copy `a.out` to NuttX Apps Filesystem...

```bash
mv ~/Downloads/a.out ~/riscv/apps/bin/
chmod +x ~/riscv/apps/bin/*
file  ~/riscv/apps/bin/a.out
ls -l ~/riscv/apps/bin
```

Which shows...

```text
$ file  ~/riscv/apps/bin/a.out
~/riscv/apps/bin/a.out: ELF 64-bit LSB relocatable, UCB RISC-V, version 1 (SYSV), not stripped

$ ls -l ~/riscv/apps/bin
total 4744
-rwxr-xr-x@ 1   1040 Jan 29 09:24 a.out
-rwxr-xr-x  1 200176 Jan 29 09:05 getprime
-rwxr-xr-x  1 119560 Jan 29 09:05 hello
-rwxr-xr-x  1 697368 Jan 29 09:05 init
-rwxr-xr-x  1 703840 Jan 29 09:05 ostest
-rwxr-xr-x  1 694648 Jan 29 09:05 sh
```

Then we boot NuttX on QEMU (64-bit RISC-V) and run `a.out` on NuttX...

```text
nsh> a.out
[   23.292000] load_absmodule: Loading /system/bin/a.out
[   23.293000] elf_loadbinary: Loading file: /system/bin/a.out
[   23.294000] elf_init: filename: /system/bin/a.out loadinfo: 0x8020afa8
[   23.295000] elf_read: Read 64 bytes from offset 0
[   23.297000] elf_dumploadinfo: LOAD_INFO:
[   23.298000] elf_dumploadinfo:   textalloc:    00000000
[   23.299000] elf_dumploadinfo:   dataalloc:    00000000
[   23.300000] elf_dumploadinfo:   textsize:     0
[   23.301000] elf_dumploadinfo:   datasize:     0
[   23.303000] elf_dumploadinfo:   textalign:    0
[   23.304000] elf_dumploadinfo:   dataalign:    0
[   23.305000] elf_dumploadinfo:   filelen:      1040
[   23.305000] elf_dumploadinfo:   symtabidx:    0
[   23.306000] elf_dumploadinfo:   strtabidx:    0
[   23.307000] elf_dumploadinfo: ELF Header:
[   23.308000] elf_dumploadinfo:   e_ident:      7f 45 4c 46
[   23.309000] elf_dumploadinfo:   e_type:       0001
[   23.310000] elf_dumploadinfo:   e_machine:    00f3
[   23.311000] elf_dumploadinfo:   e_version:    00000001
[   23.312000] elf_dumploadinfo:   e_entry:      00000000
[   23.313000] elf_dumploadinfo:   e_phoff:      0
[   23.314000] elf_dumploadinfo:   e_shoff:      464
[   23.315000] elf_dumploadinfo:   e_flags:      00000004
[   23.316000] elf_dumploadinfo:   e_ehsize:     64
[   23.317000] elf_dumploadinfo:   e_phentsize:  0
[   23.318000] elf_dumploadinfo:   e_phnum:      0
[   23.319000] elf_dumploadinfo:   e_shentsize:  64
[   23.320000] elf_dumploadinfo:   e_shnum:      9
[   23.321000] elf_dumploadinfo:   e_shstrndx:   8
[   23.323000] elf_load: loadinfo: 0x8020afa8
[   23.324000] elf_loadphdrs: No programs(?)
[   23.325000] elf_read: Read 576 bytes from offset 464
[   23.381000] elf_loadfile: Loaded sections:
[   23.382000] elf_read: Read 64 bytes from offset 64
[   23.382000] elf_loadfile: 1. 00000000->c0000000
[   23.383000] elf_read: Read 0 bytes from offset 128
[   23.383000] elf_loadfile: 2. 00000000->c0101000
[   23.383000] elf_read: Read 16 bytes from offset 128
[   23.385000] elf_loadfile: 3. 00000000->c0101000
[   23.387000] elf_loadfile: 4. 00000000->c0101010
[   23.388000] elf_dumploadinfo: LOAD_INFO:
[   23.390000] elf_dumploadinfo:   textalloc:    c0000000
[   23.390000] elf_dumploadinfo:   dataalloc:    c0101000
[   23.390000] elf_dumploadinfo:   textsize:     64
[   23.391000] elf_dumploadinfo:   datasize:     16
[   23.392000] elf_dumploadinfo:   textalign:    8
[   23.393000] elf_dumploadinfo:   dataalign:    8
[   23.393000] elf_dumploadinfo:   filelen:      1040
[   23.393000] elf_dumploadinfo:   symtabidx:    0
[   23.395000] elf_dumploadinfo:   strtabidx:    0
[   23.395000] elf_dumploadinfo: ELF Header:
[   23.395000] elf_dumploadinfo:   e_ident:      7f 45 4c 46
[   23.395000] elf_dumploadinfo:   e_type:       0001
[   23.396000] elf_dumploadinfo:   e_machine:    00f3
[   23.396000] elf_dumploadinfo:   e_version:    00000001
[   23.396000] elf_dumploadinfo:   e_entry:      00000000
[   23.397000] elf_dumploadinfo:   e_phoff:      0
[   23.397000] elf_dumploadinfo:   e_shoff:      464
[   23.397000] elf_dumploadinfo:   e_flags:      00000004
[   23.399000] elf_dumploadinfo:   e_ehsize:     64
[   23.400000] elf_dumploadinfo:   e_phentsize:  0
[   23.401000] elf_dumploadinfo:   e_phnum:      0
[   23.402000] elf_dumploadinfo:   e_shentsize:  64
[   23.403000] elf_dumploadinfo:   e_shnum:      9
[   23.403000] elf_dumploadinfo:   e_shstrndx:   8
[   23.403000] elf_dumploadinfo: Sections 0:
[   23.405000] elf_dumploadinfo:   sh_name:      00000000
[   23.406000] elf_dumploadinfo:   sh_type:      00000000
[   23.407000] elf_dumploadinfo:   sh_flags:     00000000
[   23.407000] elf_dumploadinfo:   sh_addr:      00000000
[   23.409000] elf_dumploadinfo:   sh_offset:    0
[   23.410000] elf_dumploadinfo:   sh_size:      0
[   23.412000] elf_dumploadinfo:   sh_link:      0
[   23.413000] elf_dumploadinfo:   sh_info:      0
[   23.414000] elf_dumploadinfo:   sh_addralign: 0
[   23.415000] elf_dumploadinfo:   sh_entsize:   0
[   23.416000] elf_dumploadinfo: Sections 1:
[   23.417000] elf_dumploadinfo:   sh_name:      00000001
[   23.419000] elf_dumploadinfo:   sh_type:      00000001
[   23.420000] elf_dumploadinfo:   sh_flags:     00000006
[   23.422000] elf_dumploadinfo:   sh_addr:      c0000000
[   23.423000] elf_dumploadinfo:   sh_offset:    64
[   23.426000] elf_dumploadinfo:   sh_size:      64
[   23.427000] elf_dumploadinfo:   sh_link:      0
[   23.428000] elf_dumploadinfo:   sh_info:      0
[   23.429000] elf_dumploadinfo:   sh_addralign: 8
[   23.430000] elf_dumploadinfo:   sh_entsize:   0
[   23.431000] elf_dumploadinfo: Sections 2:
[   23.432000] elf_dumploadinfo:   sh_name:      00000007
[   23.432000] elf_dumploadinfo:   sh_type:      00000001
[   23.433000] elf_dumploadinfo:   sh_flags:     00000003
[   23.433000] elf_dumploadinfo:   sh_addr:      c0101000
[   23.433000] elf_dumploadinfo:   sh_offset:    128
[   23.433000] elf_dumploadinfo:   sh_size:      0
[   23.433000] elf_dumploadinfo:   sh_link:      0
[   23.435000] elf_dumploadinfo:   sh_info:      0
[   23.435000] elf_dumploadinfo:   sh_addralign: 8
[   23.436000] elf_dumploadinfo:   sh_entsize:   0
[   23.437000] elf_dumploadinfo: Sections 3:
[   23.438000] elf_dumploadinfo:   sh_name:      0000000d
[   23.439000] elf_dumploadinfo:   sh_type:      00000001
[   23.442000] elf_dumploadinfo:   sh_flags:     00000003
[   23.443000] elf_dumploadinfo:   sh_addr:      c0101000
[   23.444000] elf_dumploadinfo:   sh_offset:    128
[   23.445000] elf_dumploadinfo:   sh_size:      16
[   23.446000] elf_dumploadinfo:   sh_link:      0
[   23.447000] elf_dumploadinfo:   sh_info:      0
[   23.447000] elf_dumploadinfo:   sh_addralign: 8
[   23.447000] elf_dumploadinfo:   sh_entsize:   0
[   23.447000] elf_dumploadinfo: Sections 4:
[   23.447000] elf_dumploadinfo:   sh_name:      00000016
[   23.448000] elf_dumploadinfo:   sh_type:      00000008
[   23.450000] elf_dumploadinfo:   sh_flags:     00000003
[   23.451000] elf_dumploadinfo:   sh_addr:      c0101010
[   23.453000] elf_dumploadinfo:   sh_offset:    144
[   23.454000] elf_dumploadinfo:   sh_size:      0
[   23.456000] elf_dumploadinfo:   sh_link:      0
[   23.457000] elf_dumploadinfo:   sh_info:      0
[   23.458000] elf_dumploadinfo:   sh_addralign: 8
[   23.460000] elf_dumploadinfo:   sh_entsize:   0
[   23.462000] elf_dumploadinfo: Sections 5:
[   23.463000] elf_dumploadinfo:   sh_name:      0000001b
[   23.464000] elf_dumploadinfo:   sh_type:      00000002
[   23.465000] elf_dumploadinfo:   sh_flags:     00000000
[   23.467000] elf_dumploadinfo:   sh_addr:      00000000
[   23.468000] elf_dumploadinfo:   sh_offset:    144
[   23.469000] elf_dumploadinfo:   sh_size:      144
[   23.471000] elf_dumploadinfo:   sh_link:      6
[   23.473000] elf_dumploadinfo:   sh_info:      4
[   23.474000] elf_dumploadinfo:   sh_addralign: 8
[   23.475000] elf_dumploadinfo:   sh_entsize:   24
[   23.477000] elf_dumploadinfo: Sections 6:
[   23.477000] elf_dumploadinfo:   sh_name:      00000023
[   23.479000] elf_dumploadinfo:   sh_type:      00000003
[   23.480000] elf_dumploadinfo:   sh_flags:     00000000
[   23.481000] elf_dumploadinfo:   sh_addr:      00000000
[   23.482000] elf_dumploadinfo:   sh_offset:    288
[   23.484000] elf_dumploadinfo:   sh_size:      25
[   23.485000] elf_dumploadinfo:   sh_link:      0
[   23.486000] elf_dumploadinfo:   sh_info:      0
[   23.487000] elf_dumploadinfo:   sh_addralign: 1
[   23.488000] elf_dumploadinfo:   sh_entsize:   0
[   23.489000] elf_dumploadinfo: Sections 7:
[   23.490000] elf_dumploadinfo:   sh_name:      0000002b
[   23.491000] elf_dumploadinfo:   sh_type:      00000004
[   23.493000] elf_dumploadinfo:   sh_flags:     00000000
[   23.494000] elf_dumploadinfo:   sh_addr:      00000000
[   23.495000] elf_dumploadinfo:   sh_offset:    320
[   23.496000] elf_dumploadinfo:   sh_size:      72
[   23.498000] elf_dumploadinfo:   sh_link:      5
[   23.499000] elf_dumploadinfo:   sh_info:      1
[   23.500000] elf_dumploadinfo:   sh_addralign: 8
[   23.501000] elf_dumploadinfo:   sh_entsize:   24
[   23.502000] elf_dumploadinfo: Sections 8:
[   23.504000] elf_dumploadinfo:   sh_name:      00000036
[   23.505000] elf_dumploadinfo:   sh_type:      00000003
[   23.507000] elf_dumploadinfo:   sh_flags:     00000000
[   23.508000] elf_dumploadinfo:   sh_addr:      00000000
[   23.509000] elf_dumploadinfo:   sh_offset:    400
[   23.510000] elf_dumploadinfo:   sh_size:      64
[   23.511000] elf_dumploadinfo:   sh_link:      0
[   23.512000] elf_dumploadinfo:   sh_info:      0
[   23.513000] elf_dumploadinfo:   sh_addralign: 1
[   23.514000] elf_dumploadinfo:   sh_entsize:   0
[   23.518000] elf_read: Read 72 bytes from offset 320
[   23.519000] elf_read: Read 24 bytes from offset 192
[   23.521000] elf_symvalue: Other: 00000000+c0101000=c0101000
[   23.523000] up_relocateadd: PCREL_HI20 at c000001c [00000517] to sym=0x80209030 st_value=c0101000
[   23.530000] _calc_imm: offset=1052644: hi=257 lo=-28
[   23.535000] elf_read: Read 24 bytes from offset 216
[   23.536000] elf_symvalue: Other: 0000001c+c0000000=c000001c
[   23.536000] up_relocateadd: PCREL_LO12_I at c0000020 [00050513] to sym=0x80209070 st_value=c000001c
[   23.537000] _calc_imm: offset=1052644: hi=257 lo=-28
[   23.539000] elf_read: Read 24 bytes from offset 264
[   23.541000] elf_read: Read 32 bytes from offset 306
[   23.542000] elf_symvalue: SHN_UNDEF: Exported symbol "printf" not found
[   23.549000] elf_relocateadd: Section 7 reloc 2: Failed to get value of symbol[5]: -2
[   23.556000] elf_loadbinary: Failed to bind symbols program binary: -2
[   23.562000] exec_internal: ERROR: Failed to load program 'a.out': -2
nsh: a.out: command not found
nsh> 
```

It says `printf` is missing. Let's fix it...

For Reference: Here's the log for an ELF that loads properly on NuttX: [NuttX ELF Loader Log](https://gist.github.com/lupyuen/847f7adee50499cac5212f2b95d19cd3)

# How NuttX Build links a NuttX App

TODO

_`printf` is missing from our TCC Output `a.out`. How does NuttX Build link a NuttX App?_

Let's find out...

```bash
cd apps
rm bin/hello
make --trace import
```

We see the Linker Command that produces the `hello` app...

```text
riscv-none-elf-ld \
  --oformat elf64-littleriscv \
  -e _start \
  -Bstatic \
  -Tapps/import/scripts/gnu-elf.ld \
  -Lapps/import/libs \
  -L "xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" apps/import/startup/crt0.o  hello_main.c.workspaces.bookworm.apps.examples.hello.o \
  --start-group \
  -lmm \
  -lc \
  -lproxies \
  -lgcc apps/libapps.a xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a \
  --end-group \
  -o  apps/bin/hello
```

This says that NuttX Build links NuttX Apps with these libraries...

- `crt0.o`: Start Code [`_start`](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/crt0.c#L144-L194)

- `-lmm`: Mmmmm?

- `-lc`: C Library

- `-lproxies`: [NuttX Proxy Functions](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel) for NuttX System Calls

- `-lgcc libgcc.a`: GCC Library

Which are located at `apps/import/libs`...

```text
$ ls -l apps/import/libs
total 18776
-rwxr-xr-x 1 3132730 Jan 29 02:12 libapps.a
-rw-r--r-- 1    1064 Jan 29 01:18 libarch.a
-rw-r--r-- 1 8946828 Jan 29 01:18 libc.a
-rw-r--r-- 1 1462710 Sep 24 08:10 libgcc.a
-rw-r--r-- 1 1276866 Jan 29 01:18 libm.a
-rw-r--r-- 1 1304366 Jan 29 01:18 libmm.a
-rw-r--r-- 1 3086312 Jan 29 01:18 libproxies.a
```

Let's run TCC to link `a.out` with the above libraries...

# Fix Missing `printf` in NuttX App

TODO

We run TCC to link `a.out` with the above libraries...

```bash
tcc-riscv32-wasm/riscv64-tcc \
  -nostdlib \
  apps/import/startup/crt0.o \
  apps/bin/a.out \
  apps/import/libs/libmm.a \
  apps/import/libs/libc.a \
  apps/import/libs/libproxies.a \
  apps/import/libs/libgcc.a
```

It says...

```text
tcc: error: Unknown relocation type for got: 60
```

When we remove `libproxies.a`, we don't see the Unknown Relocation Type...

```text
$ tcc-riscv32-wasm/riscv64-tcc \
  -nostdlib \
  apps/import/startup/crt0.o \
  apps/bin/a.out \
  apps/import/libs/libmm.a \
  apps/import/libs/libc.a \
  apps/import/libs/libgcc.a

tcc: error: undefined symbol '_exit'
tcc: error: undefined symbol '_assert'
tcc: error: undefined symbol 'nxsem_destroy'
tcc: error: undefined symbol 'gettid'
tcc: error: undefined symbol 'nxsem_wait'
tcc: error: undefined symbol 'nxsem_trywait'
tcc: error: undefined symbol 'clock_gettime'
tcc: error: undefined symbol 'nxsem_clockwait'
tcc: error: undefined symbol 'nxsem_post'
tcc: error: undefined symbol 'write'
tcc: error: undefined symbol 'lseek'
tcc: error: undefined symbol 'nx_pthread_exit'
```

Why is `libproxies.a` using Relocation Type 60? We dump the Proxy Object File...

```bash
riscv-none-elf-readelf --wide -all nuttx/syscall/PROXY_write.o
```

TODO: Check the [ELF Dump](https://gist.github.com/lupyuen/cb0484ec055a7a7dfa34b8a8a34244ee)

Let's link the Proxy Functions ourselves...

```bash
tcc-riscv32-wasm/riscv64-tcc \
  -nostdlib \
  apps/bin/a.out \
  nuttx/syscall/PROXY__exit.o \
  nuttx/syscall/PROXY__assert.o \
  nuttx/syscall/PROXY_nxsem_destroy.o \
  nuttx/syscall/PROXY_gettid.o \
  nuttx/syscall/PROXY_nxsem_wait.o \
  nuttx/syscall/PROXY_nxsem_trywait.o \
  nuttx/syscall/PROXY_clock_gettime.o \
  nuttx/syscall/PROXY_nxsem_clockwait.o \
  nuttx/syscall/PROXY_nxsem_post.o \
  nuttx/syscall/PROXY_write.o \
  nuttx/syscall/PROXY_lseek.o \
  nuttx/syscall/PROXY_nx_pthread_exit.o \
  apps/import/startup/crt0.o \
  apps/import/libs/libmm.a \
  apps/import/libs/libc.a \
  apps/import/libs/libgcc.a
```

_Does it work?_

Arg nope...

```text
tcc: error: Unknown relocation type for got: 60
```

Now Unknown Relocation Type is coming from `libc.a`. If we remove `libc.a`...

```text
$ tcc-riscv32-wasm/riscv64-tcc \
  -nostdlib \
  apps/import/startup/crt0.o \
  apps/bin/a.out \
  nuttx/syscall/PROXY__exit.o \
  nuttx/syscall/PROXY__assert.o \
  nuttx/syscall/PROXY_nxsem_destroy.o \
  nuttx/syscall/PROXY_gettid.o \
  nuttx/syscall/PROXY_nxsem_wait.o \
  nuttx/syscall/PROXY_nxsem_trywait.o \
  nuttx/syscall/PROXY_clock_gettime.o \
  nuttx/syscall/PROXY_nxsem_clockwait.o \
  nuttx/syscall/PROXY_nxsem_post.o \
  nuttx/syscall/PROXY_write.o \
  nuttx/syscall/PROXY_lseek.o \
  nuttx/syscall/PROXY_nx_pthread_exit.o \
  apps/import/libs/libmm.a

tcc: error: undefined symbol 'printf'
tcc: error: undefined symbol 'exit'
```

_What if we call `write` directly? (Since `write` is a Proxy to NuttX System Call) And stub out `exit`?_

```c
int write(int fildes, const void *buf, int nbyte);

int main(int argc, char *argv[]) {
  const char msg[] = "Hello, World!!\\n";
  write(1, msg, sizeof(msg));
  return 0;
}

void exit(int status) {
  const char msg[] = "TODO: exit\\n";
  write(1, msg, sizeof(msg));
}
```

Still the same sigh...

```text
tcc: error: Unknown relocation type for got: 60
```

Let's skip everything, we link only `a.out`. Since the other modules are causing the Unknown Relocation Type.

We discovered that `a.out` must be Relocatable Code, otherwise it crashes in NuttX. So we add `-r` to TCC Compiler Options in our modified [test.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/test.js#L48-L64)...

```javascript
  // Allocate a String for passing the Compiler Options to Zig
  const options = ["-c", "-r", "hello.c"];
  const options_ptr = allocateString(JSON.stringify(options));

  // Allocate a String for passing Program Code to Zig
  const code_ptr = allocateString(`
    int main(int argc, char *argv[]) {
      return 0;
    }
  `);

  // Call TCC to compile a program
  const ptr = wasm.instance.exports
    .compile_program(options_ptr, code_ptr);
  console.log(`ptr=${ptr}`);
```

And we run `a.out` on NuttX. Now we get an [Instruction Page Fault](https://gist.github.com/lupyuen/a715e4e77c011d610d0b418e97f8bf5d)...

```text
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
[    6.240000] binfmt_copyargv: args=2 argsize=23
[    6.240000] exec_module: Initialize the user heap (heapsize=528384)
[    6.242000] riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000008000ad8a, MTVAL: 000000008000ad8a
[    6.242000] riscv_exception: PANIC!!! Exception = 000000000000000c
[    6.242000] _assert: Current Version: NuttX  12.4.0 f8b0b06b978 Jan 29 2024 01:16:20 risc-v
[    6.242000] _assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: /system/bin/init process: /system/bin/init 0xc000001a
[    6.242000] up_dump_register: EPC: 000000008000ad8a
```

_Where is the Exception Program Counter 0x8000ad8a?_

0x8000ad8a is actually in NuttX Kernel...

```text
up_task_start():
nuttx/arch/risc-v/src/common/riscv_task_start.c:65
void up_task_start(main_t taskentry, int argc, char *argv[]) {
    8000ad7a: 1141                 add sp,sp,-16
    8000ad7c: 86b2                 mv a3,a2
nuttx/arch/risc-v/src/common/riscv_task_start.c:68
  /* Let sys_call3() do all of the work */

  sys_call3(SYS_task_start, (uintptr_t)taskentry, (uintptr_t)argc,
    8000ad7e: 862e                 mv a2,a1
    8000ad80: 85aa                 mv a1,a0
    8000ad82: 4511                 li a0,4
nuttx/arch/risc-v/src/common/riscv_task_start.c:65
    8000ad84: e406                 sd ra,8(sp)
nuttx/arch/risc-v/src/common/riscv_task_start.c:68
  sys_call3(SYS_task_start, (uintptr_t)taskentry, (uintptr_t)argc,
    8000ad86: 875f50ef           jal 800005fa <sys_call0>
nuttx/arch/risc-v/src/common/riscv_task_start.c:71
            (uintptr_t)argv);
  PANIC();
    8000ad8a: 0000e617           auipc a2,0xe
```

Maybe NuttX Kernel crashed because our NuttX App terminated without calling `exit()`?

We're guessing: NuttX Apps should NOT simply `ret` to the caller. They should call the NuttX System Call `__exit` to terminate peacefully.

[(As mentioned in `_start`)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/crt0.c#L144-L194)

_But is our NuttX App actually started?_

Let's tweak our code to loop forever, see whether our app actually gets started...

```javascript
  // Allocate a String for passing Program Code to Zig
  const code_ptr = allocateString(`
    int main(int argc, char *argv[]) {
      for (;;) {}
      return 0;
    }
  `);

  // Call TCC to compile a program
  const ptr = wasm.instance.exports
    .compile_program(options_ptr, code_ptr);
  console.log(`ptr=${ptr}`);
```

Yep NuttX hangs when starting our app! Which means our TCC Compiled App is actually started by NuttX yay!

```text
NuttShell (NSH) NuttX-12.4.0
nsh> a.out
...
load_absmodule: Successfully loaded module /system/bin/a.out
binfmt_dumpmodule: Module:
binfmt_dumpmodule:   entrypt:   0xc0000000
binfmt_dumpmodule:   mapped:    0 size=0
binfmt_dumpmodule:   alloc:     0 0 0
binfmt_dumpmodule:   addrenv:   0x80209b80
binfmt_dumpmodule:   stacksize: 2048
binfmt_dumpmodule:   unload:    0
exec_module: Executing a.out
binfmt_copyargv: args=1 argsize=6
binfmt_copyargv: args=2 argsize=23
exec_module: Initialize the user heap (heapsize=528384)
< ...NuttX Hangs... >
```

(NuttX seems to be starting the first thing that appears in `a.out`)

TODO: Unknown Relocation Type may be due to [Thread Local Storage](https://lists.gnu.org/archive/html/tinycc-devel/2020-06/msg00000.html) generated by GCC Compiler?

# ECALL for NuttX System Call

TODO

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

# Appendix: Analysis of Missing Functions

TODO

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
