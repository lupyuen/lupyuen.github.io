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
// Demo Program for TCC Compiler with ROM FS
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

1.  Reload the [__NuttX Emulator__](https://lupyuen.github.io/nuttx-tinyemu/tcc/)

1.  Run __`a.out`__

And the message changes! We discuss the internals...

![TCC Compiler in WebAssembly needs POSIX Functions](https://lupyuen.github.io/images/tcc-posix.jpg)

# File Access for WebAssembly

_Something oddly liberating about our demo..._

TCC Compiler was created as a __Command-Line App__ that calls the usual [__POSIX Functions__](https://lupyuen.github.io/articles/tcc#posix-for-webassembly) like __open, read, write,__ ...

But WebAssembly runs in a Secure Sandbox. [__No File Access__](https://lupyuen.github.io/articles/tcc#file-input-and-output) allowed, sorry! (Like for C Header Files)

_Huh! How did we get <stdio.h> and <stdlib.h>?_

```c
// Demo Program for TCC Compiler with ROM FS
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]) {
  puts("Hello, World!!\n");
  exit(0);
}            
```

TODO

# ROM FS Filesystem

_What's this ROM FS?_

[__ROM FS__](https://docs.kernel.org/filesystems/romfs.html) is a __Read-Only Filesystem__ that runs entirely in memory.

ROM FS is __a lot simpler__ than Read-Write Filesystems (like FAT and EXT4). That's why we run it inside TCC WebAssembly to host our C Include Files.

TODO

_TCC WebAssembly needs an Embedded Filesystem that will have C Header Files and C Library Files for building apps..._

_How will we implement this Embedded Filesystem in Zig?_

Let's embed the simple [__ROM FS Filesystem__](https://docs.kernel.org/filesystems/romfs.html) inside our Zig Wrapper...

1.  Our TCC JavaScript will fetch the Bundled ROM FS Filesystem over HTTP: [romfs.bin](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/docs/romfs/romfs.bin)

1.  Then copy the Bundled ROM FS into Zig Wrapper's WebAssembly Memory

1.  Our Zig Wrapper will mount the ROM FS in memory

1.  And expose POSIX Functions to TCC that will access the Emulated Filesystem

[(Works like the __Emscripten Filesystem__)](https://emscripten.org/docs/porting/files/file_systems_overview.html)

_How to bundle our C Header Files and C Library Files into the ROM FS Filesystem?_

Like this...

```bash
## Bundle the romfs folder into ROM FS Filesystem romfs.bin
## and label with this Volume Name
genromfs \
  -f zig/romfs.bin \
  -d zig/romfs \
  -V "ROMFS"
```

[(See the ROM FS Binary `zig/romfs.bin`)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs.bin)

[(See the ROM FS Files `zig/romfs`)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/romfs)

_How to implement the ROM FS in our Zig Wrapper?_

We'll borrow the ROM FS Driver from Apache NuttX RTOS. And compile it from C to WebAssembly with Zig Compiler...

- [fs_romfs.c](https://github.com/apache/nuttx/blob/master/fs/romfs/fs_romfs.c)

- [fs_romfs.h](https://github.com/apache/nuttx/blob/master/fs/romfs/fs_romfs.h)

- [fs_romfsutil.c](https://github.com/apache/nuttx/blob/master/fs/romfs/fs_romfsutil.c)

- [inode.h](https://github.com/apache/nuttx/blob/master/fs/inode/inode.h)

- [fs.h](https://github.com/apache/nuttx/blob/master/include/nuttx/fs/fs.h)

[(See the __Modified Source Files__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig)

[(See the __Build Script__)](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/build.sh)

This compiles OK with Zig Compiler with a few tweaks, let's test it in Zig...

# Mount the ROM FS Filesystem in Zig

TODO

_We borrowed the ROM FS Driver from Apache NuttX RTOS. Zig Compiler compiles it to WebAssembly with a few tweaks..._

_How do we call the ROM FS Driver to Mount the ROM FS Filesystem?_

This is how we mount the ROM FS Filesystem in Zig: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L12-L34)

```zig
/// Import the ROM FS
const c = @cImport({
  @cInclude("zig_romfs.h");
});

/// Compile a C program to 64-bit RISC-V
pub export fn compile_program(...) [*]const u8 {

  // Create the Memory Allocator for malloc
  memory_allocator = std.heap.FixedBufferAllocator.init(&memory_buffer);

  // Mount the ROM FS Filesystem
  const ret = c.romfs_bind( // Bind the ROM FS Filesystem
    c.romfs_blkdriver, // blkdriver: ?*struct_inode_6
    null, // data: ?*const anyopaque
    &c.romfs_mountpt // handle: [*c]?*anyopaque
  );
  assert(ret >= 0);
```

Zig won't let us create objects for `romfs_blkdriver` and `romfs_mountpt`, so we create them in C: [fs_romfs.c](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfs.c#L48-L50)

```c
struct inode romfs_blkdriver_inode;
struct inode *romfs_blkdriver = &romfs_blkdriver_inode;
void *romfs_mountpt = NULL;
```

This crashes inside [romfs_fsconfigure](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfsutil.c#L738-L796)...

```bash
$ node zig/test.js
compile_program: start
Entry

wasm://wasm/0085e9b2:1
RuntimeError: unreachable
    at signature_mismatch:mtd_bread (wasm://wasm/0085e9b2:wasm-function[10]:0x842)
    at romfs_fsconfigure (wasm://wasm/0085e9b2:wasm-function[22]:0xab3)
    at romfs_bind (wasm://wasm/0085e9b2:wasm-function[20]:0x954)
    at compile_program (wasm://wasm/0085e9b2:wasm-function[251]:0x4e683)
    at /workspaces/bookworm/tcc-riscv32-wasm/zig/test.js:63:6
```

We need to return the XIP Address so that [romfs_fsconfigure](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfsutil.c#L738-L796) will read the RAM directly. (Instead of reading from the device)

From [fs_romfsutil.c](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfsutil.c#L704-L705):

```c
// Implement mid_ioctl() so that BIOC_XIPBASE
// sets the XIP Address in rm_xipbase
ret = MTD_IOCTL(inode->u.i_mtd, BIOC_XIPBASE,
  (unsigned long)&rm->rm_xipbase);
```

We implement `mid_ioctl` for `BIOC_XIPBASE`: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L819-L826)

```zig
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

/// Embed the ROM FS Filesystem.
/// Later our JavaScript shall fetch this over HTTP.
const ROMFS_DATA = @embedFile("romfs.bin");
```

Also we embed the ROM FS Data inside our Zig Wrapper for now. Later our JavaScript shall fetch `romfs.bin` over HTTP.

And the mounting succeeds yay! 

```bash
$ node zig/test.js
compile_program: start
compile_program: Mounting ROM FS...
Entry
compile_program: ROM FS mounted OK!
```

The ROM FS Driver verifies the Magic Number when mounting. So we know it's correct: [fs_romfsutil.c](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/fs_romfsutil.c#L765-L770)

```c
int romfs_fsconfigure(FAR struct romfs_mountpt_s *rm) {
  ...
  /* Verify the magic number at that identifies this as a ROMFS filesystem */
  #define ROMFS_VHDR_MAGIC   "-rom1fs-"
  if (memcmp(rm->rm_buffer, ROMFS_VHDR_MAGIC, 8) != 0)
    { return -EINVAL; }
```

_We're sure it's correct?_

If we don't embed a proper ROM FS Filesystem, the Magic Number will fail...

```bash
## Let's embed some junk:
## const ROMFS_DATA = @embedFile("build.sh");

## The ROM FS Mounting fails...
$ node zig/test.js
compile_program: start
Entry
ERROR: romfs_fsconfigure failed: -22
```

So yeah we're correct.

Let's open a file from ROM FS...

# Open a ROM FS File in Zig

TODO

This is how we open a file from ROM FS in Zig: [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L39-L46)

```c
// Create the Mount Inode
const mount_inode = c.create_mount_inode(c.romfs_mountpt);

// Create the File Struct
var filep = std.mem.zeroes(c.struct_file);
filep.f_inode = mount_inode;

// Open the file
const ret2 = c.romfs_open( // Open "hello" for Read-Only. `mode` is used only for creating files.
  &filep, // filep: [*c]struct_file
  "hello", // relpath: [*c]const u8
  c.O_RDONLY, // oflags: c_int
  0 // mode: mode_t
);
assert(ret2 >= 0);
```

Our file has been opened successfully yay!

```text
$ node zig/test-nuttx.js
compile_program: start
compile_program: Mounting ROM FS...
Entry
compile_program: ROM FS mounted OK!

compile_program: Opening ROM FS File `hello`...
Open 'hello'
compile_program: ROM FS File `hello` opened OK!
```

"/hello" works OK too...

```zig
// Open "/hello"
romfs_open(..., "/hello", ...);
```

_What if the file doesn't exist?_

ROM FS Driver says that the file doesn't exist...

```text
## Let's try a file that doesn't exist:
## romfs_open(..., "hello2", ...)

compile_program: Opening ROM FS File
Open 'hello2'
ERROR: Failed to find directory directory entry for '%s': %d
```

So yep our ROM FS Driver is reading the ROM FS Directory correctly!

_How did we figure out the Mount Inode?_

See the NuttX Code: [Create a Mount Inode](https://github.com/apache/nuttx/blob/master/fs/mount/fs_mount.c#L379-L409) with [inode_reserve](https://github.com/apache/nuttx/blob/master/fs/inode/fs_inodereserve.c#L146-L260)

Finally we read a ROM FS file...

# Read a ROM FS File in Zig

TODO

This is how we read a ROM FS File in Zig (and close it): [tcc-wasm.zig](https://github.com/lupyuen/tcc-riscv32-wasm/blob/romfs/zig/tcc-wasm.zig#L57-L73)

```zig
// Read the file
var buf = std.mem.zeroes([4]u8);
const ret3 = c.romfs_read( // Read the file
  &filep, // filep: [*c]struct_file
  &buf, // buffer: [*c]u8
  buf.len // buflen: usize
);
assert(ret3 >= 0);
hexdump.hexdump(@ptrCast(&buf), @intCast(ret3));

// Close the file
const ret4 = c.romfs_close(&filep);
assert(ret4 >= 0);
```

And it works yay!

```text
$ node zig/test.js
compile_program: start
compile_program: Mounting ROM FS...
Entry
compile_program: ROM FS mounted OK!

compile_program: Opening ROM FS File `hello`...
Open 'hello'
compile_program: ROM FS File `hello` opened OK!

compile_program: Reading ROM FS File `hello`...
Read %zu bytes from offset %jd
Read sector %jd
sector: %d cached: %d ncached: %d sectorsize: %d XIP base: %p buffer: %p
XIP buffer: %p
Return %d bytes from sector offset %d
compile_program: ROM FS File `hello` read OK!
  0000:  7F 45 4C 46                                       .ELF

compile_program: Closing ROM FS File `hello`...
Closing
compile_program: ROM FS File `hello` closed OK!
```

This works OK in the Web Browser too!

Let's integrate the ROM FS Driver with TCC...

# Integrate NuttX ROM FS Driver with TCC

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

TODO: Immutable Filesystem

Time to wrap up and run everything in a Web Browser...

# TCC WebAssembly with NuttX Emulator

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

## ROM FS Filesystem for Include Files

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

## Implement `puts` with NuttX System Call

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

## Implement `exit` with NuttX System Call

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
