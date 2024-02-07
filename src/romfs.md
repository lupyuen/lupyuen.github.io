# Zig runs ROM FS Filesystem in the Web Browser (thanks to Apache NuttX RTOS)

📝 _20 Feb 2024_

![TODO](https://lupyuen.github.io/images/romfs-title.png)

[(Try the __Online Demo__)](https://lupyuen.github.io/tcc-riscv32-wasm/romfs)

[(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

We're building a [__C Compiler for RISC-V__](https://lupyuen.github.io/articles/tcc) that runs in the __Web Browser__. (With [__Zig Compiler__](https://ziglang.org/) and WebAssembly)

But our C Compiler is kinda boring if it doesn't support __C Header Files__ and Library Files.

In this article we add a __Read-Only Filesystem__ to our Zig Webassembly...

- TODO: Hosting Include Files

- TODO: NuttX ROM FS Driver

- TODO: Integrate TCC Compiler

- TODO: Integrate NuttX Emulator

- TODO: NuttX System Calls

TODO: ![Online Demo of TCC Compiler in WebAssembly](https://lupyuen.github.io/images/tcc-web.png)

[_Online Demo of TCC Compiler in WebAssembly_](https://lupyuen.github.io/tcc-riscv32-wasm/romfs)

# C Compiler in the Web Browser

Head over here to open __TCC Compiler in our Web Browser__ (pic above)

- [__TCC RISC-V Compiler with ROM FS__](https://lupyuen.github.io/tcc-riscv32-wasm/romfs)

  [(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

This __C Program__ appears...

```c
// Demo Program for TCC Compiler
// with ROM FS
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]) {
  puts("Hello, World!!\n");
  exit(0);
}            
```

Click the "__Compile__" button. Our Web Browser calls TCC to compile the above program...

```bash
## Compile to RISC-V ELF
tcc -c hello.c
```

And it downloads the compiled [__RISC-V ELF `a.out`__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

To test the Compiled Output, we browse to the __NuttX Emulator__...

- [__NuttX Emulator for Ox64 RISC-V SBC__](https://lupyuen.github.io/nuttx-tinyemu/tcc/)

We run __`a.out`__ in the NuttX Emulator...

```bash
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> a.out
Hello, World!!
```

And it works: Our Web Browser generates a RISC-V Executable, that runs in a RISC-V Emulator!

[(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

_Surely it's a staged demo? Or something server-side?_

Everything runs entirely in our Web Browser. Try this...

1.  Browse to [__TCC RISC-V Compiler (ROM FS)__](https://lupyuen.github.io/tcc-riscv32-wasm/romfs)

1.  Change the _"Hello World"_ message

1.  Click "__Compile__"

1.  Reload the Web Browser for [__NuttX Emulator__](https://lupyuen.github.io/nuttx-tinyemu/tcc/)

1.  Run __`a.out`__

And the message changes! We discuss the internals...

![TCC Compiler in WebAssembly needs POSIX Functions](https://lupyuen.github.io/images/tcc-posix.jpg)

# File Access for WebAssembly

_Something oddly liberating about our demo..._

TCC Compiler was created as a __Command-Line App__ that calls the usual [__POSIX Functions__](https://lupyuen.github.io/articles/tcc#posix-for-webassembly) for File Access: __open, read, write,__ ...

But WebAssembly runs in a Secure Sandbox. [__No File Access__](https://lupyuen.github.io/articles/tcc#file-input-and-output) allowed, sorry! (Like for C Header Files)

_Huh! How did we get <stdio.h> and <stdlib.h>?_

```c
// Demo Program for TCC Compiler
// with ROM FS
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]) {
  puts("Hello, World!!\n");
  exit(0);
}            
```

_<stdio.h>_ and _<stdlib.h>_ come from the __ROM FS Filesystem__ that's bundled inside our TCC WebAssembly.

ROM FS works like a regular Filesystem (think FAT and EXT4). Just that it's tiny, __runs in memory__. And bundles easily with WebAssembly.

(Coming up in the next section)

_Hmmm sounds like a major makeover for TCC Compiler..._

Previously TCC Compiler could access Header Files __directly from the Local Filesystem__...

TODO: Pic of TCC Filesystem

Now TCC WebAssembly needs to hoop through our [__Zig Wrapper__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly) to read the ROM FS Filesystem...

TODO: Pic of TCC ROM FS

This is how we made it work...

# ROM FS Filesystem

_What's this ROM FS?_

[__ROM FS__](https://docs.kernel.org/filesystems/romfs.html) is a __Read-Only Filesystem__ that runs entirely in memory.

ROM FS is __a lot simpler__ than Read-Write Filesystems (like FAT and EXT4). That's why we run it inside TCC WebAssembly to host our C Include Files.

_How to bundle our C Header Files into ROM FS?_

__`genromfs`__ will pack our C Header Files into a ROM FS Filesystem: [build.sh](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh#L182-L190)

```bash
## For Ubuntu: Install `genromfs`
sudo apt install genromfs

## For macOS: Install `genromfs`
brew install genromfs

## Bundle the `romfs` folder into
## ROM FS Filesystem `romfs.bin`
## and label with this Volume Name
genromfs \
  -f romfs.bin \
  -d romfs \
  -V "ROMFS"
```

[(_<stdio.h>_ and _<stdlib.h>_ are in the __ROM FS Folder__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs)

[(Bundled into this __ROM FS Filesystem__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

We embed the [__ROM FS Filesystem `romfs.bin`__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin) into our [__Zig Wrapper__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly), so it will be accessible by TCC WebAssembly: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/c2146f65cc8f338b8a3aaa4c2e88e550e82514ec/zig/tcc-wasm.zig#L993-L997)

```zig
// Embed the ROM FS Filesystem
// into our Zig Wrapper
const ROMFS_DATA = @embedFile("romfs.bin");

// Later: Mount the ROM FS Filesystem
// from `ROMFS_DATA`
```

[(About __@embedFile__)](https://ziglang.org/documentation/master/#embedFile)

__For Easier Updates__: We should download [__`romfs.bin` from our Web Server__](TODO).

TODO: [(Works like the __Emscripten Filesystem__)](https://emscripten.org/docs/porting/files/file_systems_overview.html)

TODO: Pic of NuttX Driver

# NuttX Driver for ROM FS

_Is there a ROM FS Driver in Zig?_

We looked around [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) (Real-Time Operating System) and we found a [__ROM FS Driver__](https://github.com/apache/nuttx/blob/master/fs/romfs/fs_romfs.c) (in C). It works well with Zig!

Let's walk through the steps to call the __NuttX ROM FS Driver__ from Zig...

- __Mounting__ the ROM FS Filesystem

- __Opening__ a ROM FS File

- __Reading__ the ROM FS File

- And __Closing__ it

## Mount the Filesystem

This is how we __Mount our ROM FS Filesystem__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L11-L45)

```zig
/// Import the NuttX ROM FS Driver
const c = @cImport({
  @cInclude("zig_romfs.h");
});

/// Main Function of our Zig Wrapper
pub export fn compile_program(...) [*]const u8 {

  // Create the Memory Allocator for malloc
  memory_allocator = std.heap.FixedBufferAllocator
    .init(&memory_buffer);

  // Mount the ROM FS Filesystem
  const ret = c.romfs_bind(
    c.romfs_blkdriver, // Block Driver for ROM FS
    null,              // No Data needed
    &c.romfs_mountpt   // Returns the Mount Point
  );
  assert(ret >= 0);

  // Prepare the Mount Inode.
  // We'll use it for opening files.
  romfs_inode = c.create_mount_inode(
    c.romfs_mountpt  // Mount Point
  );

  // Omitted: Call the TCC Compiler
```

[(__romfs_inode__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L160-L163)

_What if the ROM FS Filesystem contains garbage?_

Our ROM FS Driver will __Fail the Mount Operation__.

That's because it searches for a [__Magic Number__](TODO) at the top of the filesystem.

[(See the __Mount Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L91-L98)

[(Not to be confused with __i-mode__)](https://en.wikipedia.org/wiki/I-mode)

## Open a ROM FS File

Next we __Open a ROM FS File__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L127-L138)

```zig
// Create the File Struct.
// Link to the Mount Inode.
var file = std.mem.zeroes(c.struct_file);
file.f_inode = romfs_inode;

// Open the ROM FS File
const ret2 = c.romfs_open(
  &file,       // File Struct
  "stdio.h",   // Pathname ("/" paths are accepted)
  c.O_RDONLY,  // Read-Only
  0            // Mode (Unused for Read-Only Files)
);
assert(ret2 >= 0);
```

[(See the __Open Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L99-L101)

## Read a ROM FS File

Finally we __Read and Close__ the ROM FS File: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L138-L157)

```zig
// Read the ROM FS File, first 4 bytes
var buf = std.mem.zeroes([4]u8);
const ret3 = c.romfs_read(
  &file,   // File Struct
  &buf,    // Buffer to be populated
  buf.len  // Buffer Size
);
assert(ret3 >= 0);

// Dump the 4 bytes
hexdump.hexdump(@ptrCast(&buf), @intCast(ret3));

// Close the ROM FS File
const ret4 = c.romfs_close(&file);
assert(ret4 >= 0);
```

[(__hexdump__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/main/zig/hexdump.zig#L9-L92)

We'll see this...

```yaml
romfs_read: Read 4 bytes from offset 0 
romfs_read: Read sector 17969028 
romfs_filecacheread: sector: 2 cached: 0 ncached: 1 sectorsize: 64 XIP base: anyopaque@1122f74 buffer: anyopaque@1122f74 
romfs_filecacheread: XIP buffer: anyopaque@1122ff4 
romfs_read: Return 4 bytes from sector offset 0 
  0000:  2F 2F 20 43  // C
romfs_close: Closing 
```

Which looks right because [_<stdio.h>_](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L1) begins with "[__`// C`__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L1)"

[(See the __Read Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L102-L113)

TODO: [(See the __Modified Source Files__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig)

TODO: [(See the __Build Script__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh)

![ROM FS Filesystem Header](https://lupyuen.github.io/images/romfs-format1.jpg)

# Inside a ROM FS Filesystem

TODO

__`genromfs`__ will pack our C Header Files into a ROM FS Filesystem: [build.sh](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh#L182-L190)

```bash
## For Ubuntu: Install `genromfs`
sudo apt install genromfs

## For macOS: Install `genromfs`
brew install genromfs

## Bundle the `romfs` folder into
## ROM FS Filesystem `romfs.bin`
## and label with this Volume Name
genromfs \
  -f romfs.bin \
  -d romfs \
  -V "ROMFS"
```

[(_<stdio.h>_ and _<stdlib.h>_ are in the __ROM FS Folder__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs)

[(Bundled into this __ROM FS Filesystem__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

![ROM FS File Header and Data](https://lupyuen.github.io/images/romfs-format2.jpg)

TODO

TODO: Pic of NuttX Driver

# TCC calls ROM FS Driver

_TCC Compiler expects POSIX Functions like open(), read(), close()..._

_How will we connect them to ROM FS?_

This is how we implement __POSIX `open()`__ to open a C Header File (from ROM FS): [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L166-L219)

```zig
/// Open the ROM FS File and return the POSIX File Descriptor.
/// Emulates POSIX `open()`
export fn open(path: [*:0]const u8, oflag: c_uint, ...) c_int {

  // Omitted: Open the C Program File `hello.c`
  // Or create the RISC-V ELF `hello.o`
  ...
  // Allocate the File Struct
  const files = std.heap.page_allocator.alloc(c.struct_file, 1) catch {
    @panic("open: Failed to allocate file");
  };
  const file = &files[0];
  file.* = std.mem.zeroes(c.struct_file);
  file.*.f_inode = romfs_inode;

  // Strip the System Include prefix
  const sys = "/usr/local/lib/tcc/include/";
  const strip_path =
    if (std.mem.startsWith(u8, std.mem.span(path), sys)) (path + sys.len)
    else path;

  // Open the ROM FS File
  const ret = c.romfs_open(
    file,       // File Struct
    strip_path, // Pathname
    c.O_RDONLY, // Read-Only
    0           // Mode (Unused for Read-Only Files)
  );
  if (ret < 0) { return ret; }

  // Remember the File Struct
  // for the POSIX File Descriptor
  const fd = next_fd;
  next_fd += 1;
  const f = fd - FIRST_FD - 1;
  assert(romfs_files.items.len == f);
  romfs_files.append(file) catch {
    @panic("Unable to allocate file");
  };
  return fd;
}
```

[(See the __Open Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L139-L141)

[(Caution: We might have __holes__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L166-L219)

[tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L27-L31)

```zig
// POSIX File Descriptors for TCC.
// This maps a File Descriptor to the File Struct.
// Index of romfs_files = File Descriptor Number - FIRST_FD - 1
var romfs_files: std.ArrayList(  // Array List of...
  *c.struct_file                 // Pointers to File Structs
) = undefined;

// At Startup: Allocate the POSIX
// File Descriptors for TCC
romfs_files = std.ArrayList(*c.struct_file)
  .init(std.heap.page_allocator);
```

(Why [__ArrayList__](https://ziglang.org/documentation/master/std/#A;std:ArrayList)? Because it grows easily as we add File Descriptors)

TODO: __POSIX `read()`__

When TCC WebAssembly calls `read` to read the Include File, we call ROM FS: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L226-L256)

```zig
/// Read the POSIX File Descriptor `fd`.
/// Emulates POSIX `read()`
export fn read(fd: c_int, buf: [*:0]u8, nbyte: size_t) isize {

  // Omitted: Read the C Program File `hello.c`
  ...
  // Fetch the File Struct by
  // POSIX File Descriptor
  const f = fd - FIRST_FD - 1;
  const file = romfs_files.items[
    @intCast(f)
  ];

  // Read from the ROM FS File
  const ret = c.romfs_read(
    file, // File Struct
    buf,  // Buffer to be populated
    nbyte // Buffer Size
  );
  assert(ret >= 0);
  return @intCast(ret);
}
```

[(See the __Read Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L142-L238)

TODO: __POSIX `close()`__

And finally we call ROM FS Driver to close the Include File: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L278-L298)

```zig
/// Close the POSIX File Descriptor
/// Emulates POSIX `close()`
export fn close(fd: c_int) c_int {

  // Omitted: Close the C Program File `hello.c`
  // Or close the RISC-V ELF `hello.o`
  ...
  // Fetch the File Struct by
  // POSIX File Descriptor
  const f = fd - FIRST_FD - 1;
  const file = romfs_files.items[
    @intCast(f)
  ];

  // Close the ROM FS File. TODO: Deallocate the file
  const ret = c.romfs_close(file);
  assert(ret >= 0);
  return 0;
}
```

[(See the __Close Log__)](https://gist.github.com/lupyuen/c05f606e4c25162136fd05c7a02d2191#file-tcc-wasm-nodejs-log-L238-L240)

_What if we need a Temporary Writeable Filesystem?_

Try the NuttX Tmp FS Driver: [nuttx/fs/tmpfs](https://github.com/apache/nuttx/tree/master/fs/tmpfs)

_Why not FAT?_

TODO: [__Immutable Filesystem__](https://blog.setale.me/2022/06/27/Steam-Deck-and-Overlay-FS/)

![TODO](https://lupyuen.github.io/images/romfs-title.png)

# From TCC to NuttX Emulator

_TCC compiles our C Program and sends it to NuttX Emulator... How does it work?_

Here's the Teleporting Magic Trick that we saw...

1.  Browse to [__TCC RISC-V Compiler (ROM FS)__](https://lupyuen.github.io/tcc-riscv32-wasm/romfs)

1.  Change the _"Hello World"_ message

1.  Click "__Compile__"

1.  Reload the Web Browser for [__NuttX Emulator__](https://lupyuen.github.io/nuttx-tinyemu/tcc/)

1.  Enter __`a.out`__ and the new message appears

    [(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

What just happened? In Chrome Web Browser, click to _Menu > Developer Tools > Application Tab > Local Storage > lupyuen.github.io_

We'll see that the __RISC-V ELF `a.out`__ is stored locally as __`elf_data`__ in the __JavaScript Local Storage__...

TODO: Pic of elf_data

That's why NuttX Emulator can pick up __`a.out`__ from our Web Browser!

_How did it get there?_

TODO

In our WebAssembly JavaScript: TCC Compiler saves __`a.out`__ to our __JavaScript Local Storage__: [tcc.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/docs/tcc.js#L60-L90)

```javascript
// Call TCC to compile a program
const ptr = wasm.instance.exports
  .compile_program(options_ptr, code_ptr);
...
// Encode the `a.out` data in text.
// Looks like: %7f%45%4c%46...
const data = new Uint8Array(memory.buffer, ptr + 4, len);
let encoded_data = "";
for (const i in data) {
  const hex = Number(data[i]).toString(16).padStart(2, "0");
  encoded_data += `%${hex}`;
}

// Save the ELF Data to JavaScript Local Storage.
// Will be loaded by NuttX Emulator
localStorage.setItem(
  "elf_data",   // Name for Local Storage
  encoded_data  // Encoded ELF Data
);
```

_But NuttX Emulator boots from a Fixed NuttX Image, loaded from our Static Web Server..._

_How did `a.out` magically appear inside the NuttX Image?_

We used a nifty illusion... __`a.out`__ was in the [__NuttX Image__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/tcc/Image) all along!

```bash
## Create a Fake `a.out` that
## contains a Distinct Pattern:
##   22 05 69 00
##   22 05 69 01
## For 1024 times
rm -f /tmp/pattern.txt
start=$((0x22056900))
for i in {0..1023}
do
  printf 0x%x\\n $(($start + $i)) >> /tmp/pattern.txt
done

## Copy the Fake `a.out`
## to our NuttX Apps Folder
cat /tmp/pattern.txt \
  | xxd -revert -plain \
  >apps/bin/a.out
hexdump -C apps/bin/a.out

## Fake `a.out` looks like...
## 0000  22 05 69 00 22 05 69 01  22 05 69 02 22 05 69 03  |".i.".i.".i.".i.|
## 0010  22 05 69 04 22 05 69 05  22 05 69 06 22 05 69 07  |".i.".i.".i.".i.|
## 0020  22 05 69 08 22 05 69 09  22 05 69 0a 22 05 69 0b  |".i.".i.".i.".i.|
```

During our NuttX Build, the __Fake `a.out`__ gets bundled into the [__Initial RAM Disk (initrd)__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/tcc/initrd)...

[__Which gets appended__](https://lupyuen.github.io/articles/app#initial-ram-disk) to the [__NuttX Image__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/tcc/Image).

_So we patched Fake `a.out` in the NuttX Image with the Real `a.out`?_

Exactly!

1.  In the JavaScript for __NuttX Emulator__: We read __`elf_data`__ from JavaScript Local Storage and pass it to TinyEMU WebAssembly

1.  Inside the __TinyEMU WebAssembly__: We receive the __`elf_data`__ and copy it locally

1.  Then we search for our __Magic Pattern `22 05 69 00`__ in our Fake __`a.out`__

1.  And we overwrite the Fake __`a.out`__ with the Real __`a.out`__ from __`elf_data`__

Everything is explained here...

TODO

That's how we compile a NuttX App in the Web Browser, and run it with NuttX Emulator in the Web Browser! 🎉

_Is there something special inside <stdio.h> and <stdlib.h>?_

```c
// Demo Program for TCC Compiler
// with ROM FS
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]) {
  puts("Hello, World!!\n");
  exit(0);
}            
```

They'll make __System Calls__ to NuttX Kernel, for printing and quitting...

TODO

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

[__lupyuen.github.io/src/romfs.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/romfs.md)

# Appendix: Build TCC WebAssembly

TODO

```bash
## Download the ROMFS Branch of TCC Source Code.
## Configure the build for 64-bit RISC-V.

git clone \
  --branch romfs \
  https://github.com/lupyuen/tcc-riscv32-wasm
cd tcc-riscv32-wasm
./configure
make cross-riscv64

## TODO
cd zig
./build.sh

## Call Zig Compiler to compile TCC Compiler
## from C to WebAssembly. Produces `tcc.o`

## Omitted: Run the `zig cc` command from earlier...
## https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly
TODO: zig cc ...

## Compile our Zig Wrapper `tcc-wasm.zig` for WebAssembly
## and link it with TCC compiled for WebAssembly `tcc.o`
## Generates `tcc-wasm.wasm`

## Omitted: Run the `zig build-exe` command from earlier...
## https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly
TODO: zig build-exe ...

## Start the Web Server
cargo install simple-http-server
simple-http-server ./docs &

## Whenever we rebuild TCC WebAssembly...
## Copy it to the Web Server
cp tcc-wasm.wasm docs/
```

[(See the __Build Script__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh)

Browse to this URL and our TCC WebAssembly will appear...

```bash
## Test ROM FS with TCC WebAssembly
http://localhost:8000/romfs/index.html
```

Check the __JavaScript Console__ for Debug Messages.

[(See the __JavaScript Log__)](TODO)

# Appendix: Download ROM FS

TODO

__For Easier Updates__: We should download __`romfs.bin` from our Web Server: [tcc.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/docs/romfs/tcc.js#L189-L212)

```javascript
// Load the WebAssembly Module and start the Main Function.
// Called by the Compile Button.
async function bootstrap() {
  // Omitted: Download the WebAssembly
  ...
  // Download the ROM FS Filesystem
  const response = await fetch("romfs.bin");
  wasm.romfs = await response.arrayBuffer();

  // Start the Main Function
  window.requestAnimationFrame(main);
}        
```

Our Main Function passes the __ROM FS Filesystem__ to our Zig Wrapper: [tcc.js](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/docs/romfs/tcc.js#L52-L81)

```javascript
// Main Function
function main() {
  // Omitted: Read the Compiler Options and Program Code
  ...
  // Copy `romfs.bin` into ROM FS Filesystem
  const romfs_data = new Uint8Array(wasm.romfs);
  const romfs_size = romfs_data.length;
  const memory = wasm.instance.exports.memory;
  const romfs_ptr = wasm.instance.exports
    .get_romfs(romfs_size);
  const romfs_slice = new Uint8Array(
    memory.buffer,
    romfs_ptr,
    romfs_size
  );
  romfs_slice.set(romfs_data);
    
  // Call TCC to compile the program
  const ptr = wasm.instance.exports
    .compile_program(options_ptr, code_ptr);
```

__`get_romfs`__ comes from our Zig Wrapper: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L112-L121)

```zig
/// Storage for ROM FS Filesystem
var ROMFS_DATA = std.mem.zeroes([8192]u8);

/// Return the pointer to ROM FS.
/// `size` is the expected filesystem size.
pub export fn get_romfs(size: u32) [*]const u8 {
  if (size > ROMFS_DATA.len) {
    @panic("get_romfs_ptr: Increase ROMFS_DATA size");
  }
  return &ROMFS_DATA;
}
```

Inside our Zig Wrapper, __`ROMFS_DATA`__ is passed to our NuttX ROM FS Driver via an __IOCTL Request__: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L963-L986)

```zig
/// ROM FS Driver makes this IOCTL Request
export fn mtd_ioctl(_: *mtd_dev_s, cmd: c_int, rm_xipbase: ?*c_int) c_int {

  // Request for Memory Address of ROM FS
  if (cmd == c.BIOC_XIPBASE) {

    // Note: We changed `ROMFS_DATA` to `&ROMFS_DATA`
    // because we're loading from Web Server
    rm_xipbase.?.* = @intCast(@intFromPtr(
      &ROMFS_DATA
    ));
```

# Appendix: NuttX ROM FS Driver

TODO

NuttX ROM FS Driver will call `mtd_ioctl` to map the ROM FS Data in memory: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L963-L986)

```zig
/// Embed the ROM FS Filesystem.
const ROMFS_DATA = @embedFile("romfs.bin");

/// ROM FS Driver makes this IOCTL Request
export fn mtd_ioctl(_: *mtd_dev_s, cmd: c_int, rm_xipbase: ?*c_int) c_int {

  // Request for Memory Address of ROM FS
  if (cmd == c.BIOC_XIPBASE) {
    // If we're loading `romfs.bin` from Web Server:
    // Change `ROMFS_DATA` to `&ROMFS_DATA`
    rm_xipbase.?.* = @intCast(@intFromPtr(
      ROMFS_DATA
    ));

  // Request for Storage Device Geometry
  } else if (cmd == c.MTDIOC_GEOMETRY) {
    const geo: *c.mtd_geometry_s = @ptrCast(rm_xipbase.?);
    geo.*.blocksize = 64;
    geo.*.erasesize = 64;
    geo.*.neraseblocks = 1024; // TODO: Is this needed?
    const name = "ZIG_ROMFS";
    @memcpy(geo.*.model[0..name.len], name);
    geo.*.model[name.len] = 0;

  // Unknown Request
  } else {
    debug("mtd_ioctl: Unknown command {}", .{cmd});
  }
  return 0;
}
```

TODO: [(See the __Build Script__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh)

TODO: C Integration

[zig_romfs.c](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/zig_romfs.c)

[zig_romfs.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/zig_romfs.h)

TODO: Because of extra logging: [__Iteratively handle printf formats__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L368-L411)

# Appendix: Print via NuttX System Call

TODO

In our Demo NuttX App, we implement __`puts`__ by calling __`write`__: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L18-L25)

```c
// Print the string to Standard Output
inline int puts(const char *s) {
  return
    write(1, s, strlen(s)) +
    write(1, "\n", 1);
}
```

Then we implement __`write`__ the exact same way as NuttX, making a System Call: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L25-L36)

```c
// Caution: NuttX System Call Number may change
#define SYS_write 61

// Write to the File Descriptor
// https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel
inline ssize_t write(int parm1, const void * parm2, size_t parm3) {
  return (ssize_t) sys_call3(
    (unsigned int) SYS_write,  // System Call Number
    (uintptr_t) parm1,         // File Descriptor (1 = Standard Output)
    (uintptr_t) parm2,         // Buffer to be written
    (uintptr_t) parm3          // Number of bytes to write
  );
}
```

__`sys_call3`__ is our hacked implementation of NuttX System Call: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L36-L84)

```c
// Make a System Call with 3 parameters
// https://github.com/apache/nuttx/blob/master/arch/risc-v/include/syscall.h#L240-L268
inline uintptr_t sys_call3(
  unsigned int nbr,  // System Call Number
  uintptr_t parm1,   // First Parameter
  uintptr_t parm2,   // Second Parameter
  uintptr_t parm3    // Third Parameter
) {
  // Pass the Function Number and Parameters in
  // Registers A0 to A3
  register long r3 asm("a0") = (long)(parm3);  // Will move to A3
  asm volatile ("slli a3, a0, 32");  // Shift 32 bits Left then Right
  asm volatile ("srli a3, a3, 32");  // To clear the top 32 bits

  register long r2 asm("a0") = (long)(parm2);  // Will move to A2
  asm volatile ("slli a2, a0, 32");  // Shift 32 bits Left then Right
  asm volatile ("srli a2, a2, 32");  // To clear the top 32 bits

  register long r1 asm("a0") = (long)(parm1);  // Will move to A1
  asm volatile ("slli a1, a0, 32");  // Shift 32 bits Left then Right
  asm volatile ("srli a1, a1, 32");  // To clear the top 32 bits

  register long r0 asm("a0") = (long)(nbr);  // Will stay in A0

  // `ecall` will jump from RISC-V User Mode
  // to RISC-V Supervisor Mode
  // to execute the System Call.
  asm volatile (

    // ECALL for System Call to NuttX Kernel
    "ecall \n"
    
    // NuttX needs NOP after ECALL
    ".word 0x0001 \n"

    // Input+Output Registers: None
    // Input-Only Registers: A0 to A3
    // Clobbers the Memory
    :
    : "r"(r0), "r"(r1), "r"(r2), "r"(r3)
    : "memory"
  );

  // Return the result from Register A0
  return r0;
} 
```

_Why so complicated?_

That's because TCC [__won't load the RISC-V Registers correctly__](https://lupyuen.github.io/articles/tcc#appendix-nuttx-system-call). Thus we load the registers ourselves.

_Why not simply copy A0 to A2 minus the hokey pokey?_

```c
// Load SysCall Parameter to Register A0
register long r2 asm("a0") = (long)(parm2);

// Copy Register A0 to A2
asm volatile ("addi a2, a0, 0");
```

When we do that, Register A2 __becomes negative__...

```yaml
riscv_swint: Entry: regs: 0x8020be10
cmd: 61
EPC: c0000160
A0: 3d 
A1: 01 
A2: ffffffffc0101000 
A3: 0f
[...Page Fault because A2 is an Invalid Address...]
```

So we Shift Away the __Negative Sign__ (_silly_ and _seriously_)...

```c
// Load SysCall Parameter to Register A0
register long r2 asm("a0") = (long)(parm2);

// Shift 32 bits Left and
// save to Register A2
asm volatile ("slli a2, a0, 32");

// Then shift 32 bits Right
// to clear the top 32 bits
asm volatile ("srli a2, a2, 32");
```

Then Register A2 becomes __Positively OK__...

```yaml
riscv_swint: Entry: regs: 0x8020be10
cmd: 61
EPC: c0000164
A0: 3d 
A1: 01
A2: c0101000
A3: 0f
Hello, World!!
```

BTW _Andy_ won't work either...

```c
// Load SysCall Parameter to Register A0
register long r2 asm("a0") = (long)(parm2);

// Logical AND with 0xffffffff
// then save to Register A2
asm volatile ("andi a2, a0, 0xffffffff");
```

Because __`0xFFFF_FFFF`__ gets assembled to __`-1`__.

# Appendix: Exit via NuttX System Call

TODO

In our Demo NuttX App, we implement __`exit`__ the same way as NuttX, by making a System Call: [stdlib.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdlib.h#L1-L10)

```c
// Caution: NuttX System Call Number may change
#define SYS__exit 8

// Terminate the NuttX Process.
// From nuttx/syscall/proxies/PROXY__exit.c
inline void exit(int parm1) {

  // Make a System Call to NuttX Kernel
  sys_call1(
    (unsigned int)SYS__exit,  // System Call Number
    (uintptr_t)parm1          // Exit Status
  );

  // Loop Forever
  while(1);
}
```

__`sys_call1`__ makes a NuttX System Call, with our hand-crafted RISC-V Assembly (as a workaround): [stdlib.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdlib.h#L10-L48)

```c
// Make a System Call with 1 parameter
// https://github.com/apache/nuttx/blob/master/arch/risc-v/include/syscall.h#L188-L213
inline uintptr_t sys_call1(
  unsigned int nbr,  // System Call Number
  uintptr_t parm1    // First Parameter
) {
  // Pass the Function Number and Parameters
  // Registers A0 to A1
  register long r1 asm("a0") = (long)(parm1);  // Will move to A1
  asm volatile ("slli a1, a0, 32");  // Shift 32 bits Left then Right
  asm volatile ("srli a1, a1, 32");  // To clear the top 32 bits

  register long r0 asm("a0") = (long)(nbr);  // Will stay in A0

  // `ecall` will jump from RISC-V User Mode
  // to RISC-V Supervisor Mode
  // to execute the System Call.
  asm volatile (

    // ECALL for System Call to NuttX Kernel
    "ecall \n"
    
    // NuttX needs NOP after ECALL
    ".word 0x0001 \n"

    // Input+Output Registers: None
    // Input-Only Registers: A0 to A1
    // Clobbers the Memory
    :
    : "r"(r0), "r"(r1)
    : "memory"
  );

  // Return the result from Register A0
  return r0;
} 
```

And everything works OK now!

_Wow this looks horribly painful... Are we doing any more of this?_

Nope sorry, we won't do any more of this! Hand-crafting the NuttX System Calls in RISC-V Assembly was [__positively painful__](TODO).

(We'll revisit this when the RISC-V Registers are hunky dory in TCC)

# Appendix: Patch the NuttX Emulator

TODO

_So we patched Fake `a.out` in the NuttX Image with the Real `a.out`?_

Exactly! In the NuttX Emulator JavaScript, we read `elf_data` from the Local Storage and pass it to TinyEMU WebAssembly: [jslinux.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/tcc/jslinux.js#L504-L545)

```javascript
// Receive the Encoded ELF Data for `a.out`
// from JavaScript Local Storage and decode it
// Encoded data looks like: %7f%45%4c%46...
const elf_data_encoded = localStorage.getItem("elf_data");
if (elf_data_encoded) {
  elf_data = new Uint8Array(
    elf_data_encoded
      .split("%")
      .slice(1)
      .map(hex=>Number("0x" + hex))
  );
  elf_len = elf_data.length;
}
...
// Pass the ELF Data to TinyEMU Emulator
Module.ccall(
  "vm_start",  // Call `vm_start` in TinyEMU WebAssembly
  null,
  [ ... ],     // Omitted: Parameter Types
  [ // Parameters for `vm_start`
    url, mem_size, cmdline, pwd, width, height, (net_state != null) | 0, drive_url, 
    // We added these for our ELF Data
    elf_data, elf_len
  ]
);
```

Inside the __TinyEMU WebAssembly__: We receive __`elf_data`__ and copy it locally, because it will be clobbered (why?): [jsemu.c](https://github.com/lupyuen/ox64-tinyemu/blob/tcc/jsemu.c#L182-L211)

```c
// Start the TinyEMU Emulator. Called by JavaScript.
void vm_start(...) {

  // Receive the ELF Data from JavaScript
  extern uint8_t elf_data[];  // From riscv_machine.c
  extern int elf_len;
  elf_len = elf_len0;

  // Copy ELF Data to Local Buffer because it will get clobbered
  if (elf_len > 4096) { puts("elf_len exceeds 4096, increase elf_data and a.out size"); }
  memcpy(elf_data, elf_data0, elf_len);
```

Then we search for our __Magic Pattern `22 05 69 00`__ in our Fake __`a.out`__: [riscv_machine.c](https://github.com/lupyuen/ox64-tinyemu/blob/tcc/riscv_machine.c#L1034-L1053)

```c
  // Patch the ELF Data to Fake `a.out` in Initial RAM Disk
  uint64_t elf_addr = 0;
  for (int i = 0; i < 0xD61680; i++) { // TODO: Fix the Image Size

    // Search for our Magic Pattern
    const uint8_t pattern[] = { 0x22, 0x05, 0x69, 0x00 };
    if (memcmp(&kernel_ptr[i], pattern, sizeof(pattern)) == 0) {

      // Overwrite our Magic Pattern with Real `a.out`. TODO: Catch overflow
      memcpy(&kernel_ptr[i], elf_data, elf_len);
      elf_addr = RAM_BASE_ADDR + i;
      break;
    }
  }
```

And we overwrite the Fake __`a.out`__ with the Real __`a.out`__ from __`elf_data`__.

That's how we compile a NuttX App in the Web Browser, and run it with NuttX Emulator in the Web Browser! 🎉

![ROM FS Filesystem Header](https://lupyuen.github.io/images/romfs-format1.jpg)

# Appendix: ROM FS Filesystem

TODO

__`genromfs`__ will pack our C Header Files into a ROM FS Filesystem: [build.sh](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh#L182-L190)

```bash
## For Ubuntu: Install `genromfs`
sudo apt install genromfs

## For macOS: Install `genromfs`
brew install genromfs

## Bundle the `romfs` folder into
## ROM FS Filesystem `romfs.bin`
## and label with this Volume Name
genromfs \
  -f romfs.bin \
  -d romfs \
  -V "ROMFS"
```

[(_<stdio.h>_ and _<stdlib.h>_ are in the __ROM FS Folder__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs)

[(Bundled into this __ROM FS Filesystem__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

Based on [__ROM FS Spec__](https://docs.kernel.org/filesystems/romfs.html)

And our [__ROM FS Filesystem `romfs.bin`__](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)...

```bash
hexdump -C tcc-riscv32-wasm/zig/romfs.bin 
```

We see the __ROM FS Filesystem Header__ (pic above)...

```text
      [ Magic Number        ]  [ FS Size ] [ Checksm ]
0000  2d 72 6f 6d 31 66 73 2d  00 00 0f 90 58 57 01 f8  |-rom1fs-....XW..|
      [ Volume Name: ROMFS                           ]
0010  52 4f 4d 46 53 00 00 00  00 00 00 00 00 00 00 00  |ROMFS...........|
```

Followed by File Header for "__`.`__"...

```text
----  File Header for `.`
      [ NextHdr ] [ Info    ]  [ Size    ] [ Checksm ]
0020  00 00 00 49 00 00 00 20  00 00 00 00 d1 ff ff 97  |...I... ........|
      [ File Name: `.`                               ]
0030  2e 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
      (NextHdr & 0xF = 9 means Executable Directory)
```

Followed by File Header for "__`..`__"...

```text
----  File Header for `..`
      [ NextHdr ] [ Info    ]  [ Size    ] [ Checksm ]
0040  00 00 00 60 00 00 00 20  00 00 00 00 d1 d1 ff 80  |...`... ........|
      [ File Name: `..`                              ]
0050  2e 2e 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
      (NextHdr & 0xF = 0 means Hard Link)
```

Followed by File Header and Data for "__`stdio.h`__" (pic below)...

```text
----  File Header for `stdio.h`
      [ NextHdr ] [ Info    ]  [ Size    ] [ Checksm ]
0060  00 00 0a 42 00 00 00 00  00 00 09 b7 1d 5d 1f 9e  |...B.........]..|
      [ File Name: `stdio.h`                         ]
0070  73 74 64 69 6f 2e 68 00  00 00 00 00 00 00 00 00  |stdio.h.........|
      (NextHdr & 0xF = 2 means Regular File)

----  File Data for `stdio.h`
0080  2f 2f 20 43 61 75 74 69  6f 6e 3a 20 54 68 69 73  |// Caution: This|
....
0a20  74 65 72 20 41 30 0a 20  20 72 65 74 75 72 6e 20  |ter A0.  return |
0a30  72 30 3b 0a 7d 20 0a 00  00 00 00 00 00 00 00 00  |r0;.} ..........|
```

Followed by File Header and Data for "__`stdlib.h`__"...

```text
----  File Header for `stdlib.h`
      [ NextHdr ] [ Info    ]  [ Size    ] [ Checksm ]
0a40  00 00 00 02 00 00 00 00  00 00 05 2e 23 29 67 fc  |............#)g.|
      [ File Name: `stdlib.h`                        ]
0a50  73 74 64 6c 69 62 2e 68  00 00 00 00 00 00 00 00  |stdlib.h........|
      (NextHdr & 0xF = 2 means Regular File)

----  File Data for `stdio.h`
0a60  2f 2f 20 43 61 75 74 69  6f 6e 3a 20 54 68 69 73  |// Caution: This|
....
0f80  72 65 74 75 72 6e 20 72  30 3b 0a 7d 20 0a 00 00  |return r0;.} ...|
0f90  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

![ROM FS File Header and Data](https://lupyuen.github.io/images/romfs-format2.jpg)
