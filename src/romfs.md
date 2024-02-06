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

We embed the __ROM FS Filesystem `romfs.bin`__ into our [__Zig Wrapper__](https://lupyuen.github.io/articles/tcc#zig-compiles-tcc-to-webassembly), so it will be accessible by TCC WebAssembly: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/c2146f65cc8f338b8a3aaa4c2e88e550e82514ec/zig/tcc-wasm.zig#L993-L997)

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

# NuttX Driver for ROM FS

_Is there a ROM FS Driver in Zig?_

We looked around [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) (Real-Time Operating System) and we found a [__ROM FS Driver__](https://github.com/apache/nuttx/blob/master/fs/romfs/fs_romfs.c) (in C). It works well in Zig!

Let's walk through the steps to call the __NuttX ROM FS Driver__ in Zig...

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

[(__romfs_files__ is defined here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L320-L324)

[(__romfs_inode__ is here)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L160-L163)

_What if the ROM FS Filesystem contains garbage?_

Our ROM FS Driver will __Fail the Mount Operation__.

That's because it searches for a Magic Number at the top of the filesystem: [fs_romfsutil.c](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfsutil.c#L765-L770)

```c
// Verify the Magic Number that identifies
// a ROM FS Filesystem
#define ROMFS_VHDR_MAGIC "-rom1fs-"
```

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

# Inside a ROM FS Filesystem

TODO

# TCC calls ROM FS Driver

TODO

_TCC WebAssembly needs a ROM FS Filesystem that will have C Header Files and C Library Files for building apps..._

_How will we integrate the NuttX ROM FS Driver in Zig?_

At Startup: We call the NuttX ROM FS Driver to mount the ROM FS Filesystem: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L24-L45)

```zig
/// Next File Descriptor Number.
/// First File Descriptor is reserved for C Program `hello.c`
var next_fd: c_int = FIRST_FD;
const FIRST_FD = 3;

/// Map a File Descriptor to the ROM FS File
/// Index of romfs_files = File Descriptor Number - FIRST_FD - 1
var romfs_files: std.ArrayList(*c.struct_file) = undefined;

/// Compile a C program to 64-bit RISC-V
pub export fn compile_program(...) [*]const u8 {

  // Create the Memory Allocator for malloc
  memory_allocator = std.heap.FixedBufferAllocator.init(&memory_buffer);

  // Map from File Descriptor to ROM FS File
  romfs_files = std.ArrayList(*c.struct_file).init(std.heap.page_allocator);
  defer romfs_files.deinit();

  // Mount the ROM FS Filesystem
  const ret = c.romfs_bind( // Bind the ROM FS Filesystem
    c.romfs_blkdriver, // blkdriver: ?*struct_inode_6
    null, // data: ?*const anyopaque
    &c.romfs_mountpt // handle: [*c]?*anyopaque
  );
  assert(ret >= 0);

  // Create the Mount Inode and test the ROM FS
  romfs_inode = c.create_mount_inode(c.romfs_mountpt);
  test_romfs();
```

NuttX ROM FS Driver will call `mtd_ioctl` to map the ROM FS Data in memory: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L974-L994)

```zig
/// Embed the ROM FS Filesystem.
/// Later our JavaScript shall fetch this over HTTP.
const ROMFS_DATA = @embedFile("romfs.bin");

export fn mtd_ioctl(_: *mtd_dev_s, cmd: c_int, rm_xipbase: ?*c_int) c_int {
  assert(rm_xipbase != null);
  if (cmd == c.BIOC_XIPBASE) {
    // Return the XIP Base Address
    rm_xipbase.?.* = @intCast(@intFromPtr(ROMFS_DATA));
  } else if (cmd == c.MTDIOC_GEOMETRY) {
    // Return the Storage Device Geometry
    const geo: *c.mtd_geometry_s = @ptrCast(rm_xipbase.?);
    geo.*.blocksize = 64;
    geo.*.erasesize = 64;
    geo.*.neraseblocks = 1024; // TODO: Is this needed?
    const name = "ZIG_ROMFS";
    @memcpy(geo.*.model[0..name.len], name);
    geo.*.model[name.len] = 0;
  } else {
    debug("mtd_ioctl: Unknown command {}", .{cmd});
  }
  return 0;
}
```

When TCC WebAssembly calls `open` to open an Include File, we call the NuttX ROM FS Driver to open the file in ROM FS: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L157-L207)

```zig
export fn open(path: [*:0]const u8, oflag: c_uint, ...) c_int {

  // If opening the C Program File `hello.c`
  // Or creating `hello.o`...
  // Just return the File Descriptor
  // TODO: This might create a hole in romfs_files if we open a file for reading after writing another file
  if (next_fd == FIRST_FD or oflag == 577) {
    const fd = next_fd;
    next_fd += 1;
    return fd;
  } else {
    // If opening an Include File or Library File...
    // Allocate the File Struct
    const files = std.heap.page_allocator.alloc(c.struct_file, 1) catch {
      debug("open: Failed to allocate file", .{});
      @panic("open: Failed to allocate file");
    };
    const file = &files[0];
    file.* = std.mem.zeroes(c.struct_file);
    file.*.f_inode = romfs_inode;

    // Strip the path from System Include
    const sys = "/usr/local/lib/tcc/include/";
    const strip_path = if (std.mem.startsWith(u8, std.mem.span(path), sys)) (path + sys.len) else path;

    // Open the ROM FS File
    const ret = c.romfs_open( // Open for Read-Only. `mode` is used only for creating files.
      file, // filep: [*c]struct_file
      strip_path, // relpath: [*c]const u8
      c.O_RDONLY, // oflags: c_int
      0 // mode: mode_t
    );
    if (ret < 0) { return ret; }

    // Remember the ROM FS File
    const fd = next_fd;
    next_fd += 1;
    const f = fd - FIRST_FD - 1;
    assert(romfs_files.items.len == f);
    romfs_files.append(file) catch {
      debug("Unable to allocate file", .{});
      @panic("Unable to allocate file");
    };
    return fd;
  }
}
```

When TCC WebAssembly calls `read` to read the Include File, we call ROM FS: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L214-L244)

```zig
export fn read(fd: c_int, buf: [*:0]u8, nbyte: size_t) isize {

  // If reading the C Program...
  if (fd == FIRST_FD) {
    // Copy from the Read Buffer
    const len = read_buf.len;
    assert(len < nbyte);
    @memcpy(buf[0..len], read_buf[0..len]);
    buf[len] = 0;
    read_buf.len = 0;
    return @intCast(len);
  } else {
    // Fetch the ROM FS File
    const f = fd - FIRST_FD - 1;
    const file = romfs_files.items[@intCast(f)];

    // Read from the ROM FS File
    const ret = c.romfs_read( // Read the file
      file, // filep: [*c]struct_file
      buf, // buffer: [*c]u8
      nbyte // buflen: usize
    );
    assert(ret >= 0);
    return @intCast(ret);
  }
}
```

And finally we call ROM FS Driver to close the Include File: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L266-L286)

```zig
export fn close(fd: c_int) c_int {

  // If closing an Include File or Library File...
  if (fd > FIRST_FD) {
    // Fetch the ROM FS File
    const f = fd - FIRST_FD - 1;
    if (f >= romfs_files.items.len) {
      // Skip the closing of `hello.o`
      return 0;
    }
    const file = romfs_files.items[@intCast(f)];

    // Close the ROM FS File. TODO: Deallocate the file
    const ret = c.romfs_close(file);
    assert(ret >= 0);
  }
  return 0;
}
```

We stage the Include Files `stdio.h` and `stdlib.h` here: [zig/romfs](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs)

```bash
$ ls -l zig/romfs
-rw-r--r-- 1 25 stdio.h
-rw-r--r-- 1 23 stdlib.h
```

And we bundle them into `romfs.bin`...

```bash
## Bundle the romfs folder into ROM FS Filesystem romfs.bin
## and label with this Volume Name
genromfs \
  -f zig/romfs.bin \
  -d zig/romfs \
  -V "ROMFS"
```

[(See the ROM FS Binary `zig/romfs.bin`)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

At last we have a proper POSIX (Read-Only) Filesystem for TCC WebAssembly yay!

```text
open: path=/usr/local/lib/tcc/include/stdio.h, oflag=0, return fd=4
Open 'stdio.h'
read: fd=4, nbyte=8192
XIP buffer: anyopaque@10b672
read: return buf=
  int puts(const char *s);

read: fd=4, nbyte=8192
read: return buf=
close: fd=4
Closing

open: path=/usr/local/lib/tcc/include/stdlib.h, oflag=0, return fd=5
Open 'stdlib.h'
read: fd=5, nbyte=8192
XIP buffer: anyopaque@10b6b2
read: return buf=
  void exit(int status);

read: fd=5, nbyte=8192
read: return buf=
close: fd=5
Closing
```

_What if we need a Temporary Writeable Filesystem?_

Try the NuttX Tmp FS Driver: [nuttx/fs/tmpfs](https://github.com/apache/nuttx/tree/master/fs/tmpfs)

_Why not FAT?_

TODO: [__Immutable Filesystem__](https://blog.setale.me/2022/06/27/Steam-Deck-and-Overlay-FS/)

Time to wrap up and run everything in a Web Browser...

# From TCC to NuttX Emulator

TODO

[(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

Remember we're doing a Decent Demo of Building and Testing a #NuttX App in the Web Browser... `puts` and `exit` finally work OK yay! 🎉

1.  TCC Compiler in WebAssembly compiles `puts` and `exit` to proper NuttX System Calls

1.  By loading `<stdio.h>` and `<stdlib.h>` from the ROM FS Filesystem (thanks to the NuttX Driver)

1.  TCC Compiler generates the 64-bit RISC-V ELF `a.out`

1.  Which gets automagically copied to NuttX Emulator in WebAssembly

1.  And NuttX Emulator executes `puts` and `exit` correctly as NuttX System Calls!

Try the new ROM FS Demo here: https://lupyuen.github.io/tcc-riscv32-wasm/romfs/

```c
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]) {
  puts("Hello, World!!\n");
  exit(0);
}
```

Click "Compile". Then run the `a.out` here: https://lupyuen.github.io/nuttx-tinyemu/tcc/

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> a.out
Hello, World!!
 
nsh> a.out
Hello, World!!
 
nsh> a.out
Hello, World!!
 
nsh>
```

Try changing "Hello World" to something else. Recompile and Reload the [NuttX Emulator](https://lupyuen.github.io/nuttx-tinyemu/tcc/). It works!

Impressive, no? 3 things we fixed...

[(Watch the __Demo on YouTube__)](https://youtu.be/sU69bUyrgN8)

# ROM FS Filesystem for TCC

TODO

_How did we get <stdio.h> and <stdlib.h> in TCC WebAssembly?_

We create a Staging Folder [zig/romfs](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs) that contains our C Header Files for TCC Compiler...

- [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h)

- [stdlib.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdlib.h)

Then we bundle the Staging Folder into a ROM FS Filesystem...

```bash
## Bundle the romfs folder into ROM FS Filesystem romfs.bin
## and label with this Volume Name
genromfs \
  -f zig/romfs.bin \
  -d zig/romfs \
  -V "ROMFS"
```

Which becomes the ROM FS Data File [zig/romfs.bin](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

Inside our TCC WebAssembly: We mounted the ROM FS Filesystem by calling the NuttX ROM FS Driver. (Which has been integrated into our Zig WebAssembly)

See the earlier sections to find out how we modded the POSIX Filesystem Calls (from TCC WebAssembly) to access the NuttX ROM FS Driver.

# Print with NuttX System Call

TODO

In our Demo NuttX App, we implement `puts` by calling `write`: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L18-L25)

```c
// Print the string to Standard Output
inline int puts(const char *s) {
  return
    write(1, s, strlen(s)) +
    write(1, "\n", 1);
}
```

Then we implement `write` the exact same way as NuttX, making a System Call: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L25-L36)

```c
// Caution: This may change
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

`sys_call3` is our hacked implementation of NuttX System Call: [stdio.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdio.h#L36-L84)

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
  // Input + Output Registers: A0 to A3
  // Clobbers the Memory
  asm volatile
  (
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

That's because TCC [won't load the RISC-V Registers correctly](https://lupyuen.github.io/articles/tcc#appendix-nuttx-system-call). Thus we load the registers ourselves.

_Why not simply copy A0 to A2?_

```c
register long r2 asm("a0") = (long)(parm2);  // Will move to A2
asm volatile ("addi a2, a0, 0");  // Copy A0 to A2
```

Because then Register A2 becomes negative...

```text
riscv_swint: Entry: regs: 0x8020be10
cmd: 61
EPC: 00000000c0000160
A0: 000000000000003d 
A1: 0000000000000001 
A2: ffffffffc0101000 
A3: 000000000000000f
[...Page Fault because A2 is Invalid Address...]
```

So we Shift away the Negative Sign...

```c
register long r2 asm("a0") = (long)(parm2);  // Will move to A2
asm volatile ("slli a2, a0, 32");  // Shift 32 bits Left then Right
asm volatile ("srli a2, a2, 32");  // To clear the top 32 bits
```

Then Register A2 becomes Positively OK...

```text
riscv_swint: Entry: regs: 0x8020be10
cmd: 61
EPC: 00000000c0000164
A0: 000000000000003d 
A1: 0000000000000001
A2: 00000000c0101000
A3: 000000000000000f
Hello, World!!
```

BTW `andi` doesn't work...

```c
register long r2 asm("a0") = (long)(parm2);  // Will move to A2
asm volatile ("andi a2, a0, 0xffffffff");
```

Because 0xffffffff gets assembled to -1. (Bug?)

# Exit with NuttX System Call

TODO

In our Demo NuttX App, we implement `exit` the same way as NuttX, by making a System Call: [stdlib.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdlib.h#L1-L10)

```c
// Caution: This may change
#define SYS__exit 8

// Terminate the NuttX Process
// From nuttx/syscall/proxies/PROXY__exit.c
inline void exit(int parm1) {
  sys_call1((unsigned int)SYS__exit, (uintptr_t)parm1);
  while(1);
}
```

`sys_call1` makes a NuttX System Call, with our hand-crafted RISC-V Assembly (as a workaround): [stdlib.h](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs/stdlib.h#L10-L48)

```c
// Make a System Call with 1 parameters
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
  // Input + Output Registers: A0 to A1
  // Clobbers the Memory
  asm volatile
  (
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

Nope we won't do any more of this! Hand-crafting the NuttX System Calls in RISC-V Assembly was extremely painful.

(Maybe we'll revisit this when the RISC-V Registers are working OK in TCC)

TODO: Define the printf formats %jd, %zu

TODO: Iteratively handle printf formats

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
