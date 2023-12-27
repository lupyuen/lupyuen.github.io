# Nim on a Real-Time Operating System: Apache NuttX RTOS + Ox64 BL808

📝 _7 Jan 2024_

![TODO](https://lupyuen.github.io/images/nim-ox64.png)

TODO

2024 is (nearly) here. Apache NuttX RTOS (Real-Time Operating System) now runs on Single-Board Computers with plenty of RAM

Like Ox64 BL808 RISC-V SBC with 64 MB RAM!

_How do we use the Plentiful RAM?_

Let's consume the extra RAM meaningfully... We'll create NuttX Apps the simpler safer way with a Garbage-Collected Language: Nim Programming Language!

how different from Zig and Rust?

Memory Safe (like Rust)
Garbage Collected
Compiles to C (instead of LLVM)
Syntax is Python like but static compiled 

_But Garbage Collection? Won't it run-pause-run-pause?_

Awesome folks Wilderness Labs are running .NET on NuttX with Garbage Collection. Maybe it's not so bad!

Also TinyGo

[__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) 64-bit RISC-V Single-Board Computer (pic below)...

[__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (Real-Time Operating System)

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

__ULEDIOC_SETALL__ accepts a Bit Mask of LED States. We pass the value __`1`__ because Bit 0 refers to LED 0.

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

TODO: At the top of our Nim Program

[hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim#L1-L21)

```nim
## Import NuttX Functions from C.
## Based on https://github.com/nim-lang/Nim/blob/devel/lib/std/syncio.nim

proc c_open(filename: cstring, mode: cint): cint {.
  importc: "open", header: "<fcntl.h>",
  nodecl.}

proc c_close(fd: cint): cint {.
  importc: "close", header: "<fcntl.h>",
  nodecl, discardable.}

proc c_ioctl(fd: cint, request: cint): cint {.
  importc: "ioctl", header: "<sys/ioctl.h>",
  nodecl, varargs.}

proc c_usleep(usec: cuint): cint {.
  importc: "usleep", header: "<unistd.h>",
  nodecl, discardable.}
```

TODO

```nim
## Import NuttX Macros from C.
## Based on https://github.com/nim-lang/Nim/blob/devel/lib/std/syncio.nim

var O_WRONLY {.
  importc: "O_WRONLY", header: "<fcntl.h>".}: cint

var ULEDIOC_SETALL {.
  importc: "ULEDIOC_SETALL", header: "<nuttx/leds/userled.h>".}: cint
```

# Experiments with Nim on Apache NuttX Real-Time Operating System

TODO

![Nim App runs OK on Apache NuttX Real-Time Operating System](https://lupyuen.github.io/images/nim-title.png)

Today Apache NuttX RTOS runs on SBCs that have plenty of RAM: Ox64 with 64 MB RAM!

Now that we have plentiful RAM: Maybe we should build NuttX Apps with a Memory-Safe, Garbage-Collected language... Like Nim!

This Nim App: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim)

```nim
import std/asyncdispatch
import std/strformat

proc hello_nim() {.exportc, cdecl.} =
  echo "Hello Nim!"
  GC_runOrc()
```

Runs OK on NuttX for QEMU RISC-V 64-bit!

```text
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
NuttX  12.0.3 45150e164c5 Dec 23 2023 07:24:20 risc-v rv-virt

nsh> hello_nim
Hello Nim!
```

This is how we build NuttX with the Nim App inside...

```bash
## Install choosenim, add to PATH, select latest Dev Version of Nim Compiler
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
export PATH=/home/vscode/.nimble/bin:$PATH
choosenim devel --latest

## Download WIP NuttX and Apps
git clone --branch nim https://github.com/lupyuen2/wip-pinephone-nuttx nuttx
git clone --branch nim https://github.com/lupyuen2/wip-pinephone-nuttx-apps apps

## Configure NuttX for QEMU RISC-V (64-bit)
cd nuttx
tools/configure.sh rv-virt:nsh64

## Build NuttX
make

## Start NuttX with QEMU RISC-V (64-bit)
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

We made some minor tweaks in NuttX...

# Fix NuttX for Nim

TODO

_How did we fix NuttX to compile Nim Apps correctly?_

We moved .nimcache 2 levels up: [apps/examples/hello_nim/Makefile](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/Makefile)

```text
## Move .nimcache 2 levels up
CFLAGS += -I $(NIMPATH)/lib -I ../../.nimcache
CSRCS += $(wildcard ../../.nimcache/*.c)

## Previously:
## CFLAGS += -I $(NIMPATH)/lib -I ./.nimcache
## CSRCS += $(wildcard .nimcache/*.c)
```

And we switched the Nim Target Architecture from RISC-V 32-bit to 64-bit: [apps/config.nims](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/config.nims)

```nim
## Assume we are compiling with `riscv-none-elf-gcc` instead of `riscv64-unknown-elf-gcc`
switch "riscv32.nuttx.gcc.exe", "riscv-none-elf-gcc" ## TODO: Check for riscv64-unknown-elf-gcc
switch "riscv64.nuttx.gcc.exe", "riscv-none-elf-gcc" ## TODO: Check for riscv64-unknown-elf-gcc
## Previously: switch "riscv32.nuttx.gcc.exe", "riscv64-unknown-elf-gcc"
...
      case arch
      ...
      of "risc-v":
        ## TODO: Check for riscv32 or riscv3
        ## CONFIG_ARCH_RV32=y or CONFIG_ARCH_RV64=y
        result.arch = "riscv64"
        ## Previously: result.arch = "riscv32"
```

See the modified files...

- [Changes to NuttX Apps](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files)

- [Changes to NuttX Kernel](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files)

# Nim on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC

TODO

Nim also runs OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!

This Nim App: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim)

```nim
import std/asyncdispatch
import std/strformat

proc hello_nim() {.exportc, cdecl.} =
  echo "Hello Nim!"
  GC_runOrc()
```

Produces this output...

```text
Starting kernel ...
ABC
NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
NuttX  12.0.3 d27d0fd4be1-dirty Dec 24 2023 12:32:23 risc-v ox64

nsh> hello_nim
Hello Nim!
```

[(Source)](https://gist.github.com/lupyuen/adef0acd97669cd3570a0614e32166fc)

To build NuttX + Nim for Ox64 BL808 SBC...

```bash
## Install choosenim, add to PATH, select latest Dev Version of Nim Compiler
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
export PATH=/home/vscode/.nimble/bin:$PATH
choosenim devel --latest

## Download WIP NuttX and Apps
git clone --branch nim https://github.com/lupyuen2/wip-pinephone-nuttx nuttx
git clone --branch nim https://github.com/lupyuen2/wip-pinephone-nuttx-apps apps

## Configure NuttX for Ox64 BL808 RISC-V SBC
cd nuttx
tools/configure.sh ox64:nsh

## Build NuttX Kernel
make

## Build Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Export the Binary Image to `nuttx.bin`
riscv-none-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.pad

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image

## Copy NuttX Image to Ox64 Linux microSD
cp Image "/Volumes/NO NAME/"
diskutil unmountDisk /dev/disk2

## TODO: Boot Ox64 with the microSD
```

See the modified files...

- [Changes to NuttX Apps](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files)

- [Changes to NuttX Kernel](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files)

![Nim App runs OK on Apache NuttX Real-Time Operating System and Ox64 BL808 RISC-V SBC](https://lupyuen.github.io/images/nim-ox64.png)

# Blink an LED with Nim

TODO

This is how we Blink an LED with Nim on NuttX: [hello_nim_async.nim](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello_nim/hello_nim_async.nim)

```nim
import std/strformat  ## String Formatting

## Import NuttX Functions and Macros from C.
## Based on https://github.com/nim-lang/Nim/blob/devel/lib/std/syncio.nim
proc c_open(filename: cstring, mode: cint): cint {.
  importc: "open", header: "<fcntl.h>",
  nodecl.}
proc c_close(fd: cint): cint {.
  importc: "close", header: "<fcntl.h>",
  nodecl, discardable.}
proc c_ioctl(fd: cint, request: cint): cint {.
  importc: "ioctl", header: "<sys/ioctl.h>",
  nodecl, varargs.}
proc c_usleep(usec: cuint): cint {.
  importc: "usleep", header: "<unistd.h>",
  nodecl, discardable.}
var O_WRONLY {.
  importc: "O_WRONLY", header: "<fcntl.h>".}: cint
var ULEDIOC_SETALL {.
  importc: "ULEDIOC_SETALL", header: "<nuttx/leds/userled.h>".}: cint

## Blink the LED
proc blink_led() =

  ## Open the LED Driver
  echo "Opening /dev/userleds"
  let fd = c_open("/dev/userleds", O_WRONLY)
  if fd < 0:
    echo "Failed to open /dev/userleds"
    return

  ## On Return: Close the LED Driver
  defer: c_close(fd)

  ## Turn on LED
  echo "Set LED 0 to 1"
  var ret = c_ioctl(fd, ULEDIOC_SETALL, 1)
  if ret < 0:
    echo "ioctl(ULEDIOC_SETALL) failed"
    return

  ## Wait a second (literally)
  echo "Waiting..."
  c_usleep(1000_000)

  ## Turn off LED
  echo "Set LED 0 to 0"
  ret = c_ioctl(fd, ULEDIOC_SETALL, 0)
  if ret < 0:
    echo "ioctl(ULEDIOC_SETALL) failed"
    return

  ## Wait again
  echo "Waiting..."
  c_usleep(1000_000)

## Main Function in Nim
proc hello_nim() {.exportc, cdecl.} =

  ## On Return: Force the Garbage Collection
  defer: GC_runOrc()

  ## Print something
  echo "Hello Nim!"

  ## Blink the LED 20 times
  for loop in 0..19:
    blink_led()
```

Which calls our barebones NuttX LED Driver for Ox64 BL808...

- ["LED Driver for Ox64 BL808"](https://github.com/lupyuen/nuttx-ox64#led-driver-for-ox64-bl808)

And Nim blinks our LED on Ox64 BL808 SBC!

- [Watch the Demo on YouTube](https://youtube.com/shorts/KCkiXFxBgxQ)

- [See the Log](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96)

_How did we figure out the Nim Code?_

The code above is equivalent to this in C: [hello_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/nim/examples/hello/hello_main.c#L25-L85)

```c
#include <nuttx/config.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <nuttx/leds/userled.h>

int main(int argc, FAR char *argv[])
{
  printf("Hello, World!!\n");

  // Open the LED driver
  printf("Opening /dev/userleds\n");
  int fd = open("/dev/userleds", O_WRONLY);
  if (fd < 0)
    {
      int errcode = errno;
      printf("ERROR: Failed to open /dev/userleds: %d\n",
             errcode);
      return EXIT_FAILURE;
    }

  // Turn on LED
  puts("Set LED 0 to 1");
  int ret = ioctl(fd, ULEDIOC_SETALL, 1);
  if (ret < 0)
    {
      int errcode = errno;
      printf("ERROR: ioctl(ULEDIOC_SUPPORTED) failed: %d\n",
              errcode);
      return EXIT_FAILURE;
    }

  // Sleep a while
  puts("Waiting...");
  usleep(500 * 1000L);

  // Turn off LED
  puts("Set LED 0 to 0");
  ret = ioctl(fd, ULEDIOC_SETALL, 0);
  if (ret < 0)
    {
      int errcode = errno;
      printf("ERROR: ioctl(ULEDIOC_SUPPORTED) failed: %d\n",
              errcode);
      return EXIT_FAILURE;
    }

  // Close the LED Driver
  close(fd);

  return 0;
}
```

# Inside a Nim App for NuttX

TODO: What happens inside a NuttX App for NuttX?

https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c714a317e531aa8ab2de7b9a8e4c4b0f89f66626/config.nims

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

# Build NuttX with Debian Container in VSCode

TODO

Nim Compiler won't install on some machines (like a 10-year-old Mac). So we create a Debian Bookworm Container in VSCode that will compile Nim and NuttX...

1.  Install [Rancher Desktop](https://rancherdesktop.io/)

1.  In Rancher Desktop, click "Settings"...

    Set "Container Engine" to "dockerd (moby)"

    Under "Kubernetes", uncheck "Enable Kubernetes"

    (To reduce CPU Utilisation)

1.  Restart VSCode to use the new PATH

    Install the [VSCode Dev Containers Extension](https://code.visualstudio.com/docs/devcontainers/containers)

1.  In VSCode, click the "Remote Explorer" icon in the Left Bar

1.  Under "Dev Container", click "+" (New Dev Container)

1.  Select "New Dev Container"

1.  Select "Debian"

1.  Select "Additional Options" > "Bookworm"

    (With other versions of Debian, "apt install" will install outdated packages)

Inside the Debian Bookworm Container:

Install NuttX Prerequisites...

```bash
## From https://lupyuen.github.io/articles/nuttx#install-prerequisites
sudo apt update && sudo apt upgrade
sudo apt install \
  bison flex gettext texinfo libncurses5-dev libncursesw5-dev \
  gperf automake libtool pkg-config build-essential gperf genromfs \
  libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev \
  libexpat-dev gcc-multilib g++-multilib picocom u-boot-tools util-linux \
  kconfig-frontends

## Extra Tools for RISCV QEMU
sudo apt install xxd
sudo apt install qemu-system-riscv64
```

Install RISC-V Toolchain...

```bash
## Download xPack GNU RISC-V Embedded GCC Toolchain for 64-bit RISC-V
wget https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v13.2.0-2/xpack-riscv-none-elf-gcc-13.2.0-2-linux-x64.tar.gz
tar xf xpack-riscv-none-elf-gcc-13.2.0-2-linux-x64.tar.gz

## Add to PATH
export PATH=$PWD/xpack-riscv-none-elf-gcc-13.2.0-2/bin:$PATH

## Test gcc:
## gcc version 13.2.0 (xPack GNU RISC-V Embedded GCC x86_64) 
riscv-none-elf-gcc -v
```

[(Why we use xPack Toolchain)](https://lupyuen.github.io/articles/riscv#appendix-xpack-gnu-risc-v-embedded-gcc-toolchain-for-64-bit-risc-v)

Assuming that we need [Nim Compiler](https://nim-lang.org/install_unix.html)...

1.  Install [Nim Compiler](https://nim-lang.org/install_unix.html)...

    ```bash
    curl https://nim-lang.org/choosenim/init.sh -sSf | sh
    ```

1.  Add to PATH...

    ```bash
    export PATH=/home/vscode/.nimble/bin:$PATH
    ```

1.  Select Latest Dev Version of Nim...

    ```bash
    ## Will take a while!
    choosenim devel --latest
    ```

1.  Create a file named `a.nim`...

    ```text
    echo "Hello World"
    ```

1.  Test Nim...

    ```bash
    $ nim c a.nim
    Hint: used config file '/home/vscode/.choosenim/toolchains/nim-#devel/config/nim.cfg' [Conf]
    Hint: used config file '/home/vscode/.choosenim/toolchains/nim-#devel/config/config.nims' [Conf]
    .....................................................................
    Hint:  [Link]
    Hint: mm: orc; threads: on; opt: none (DEBUG BUILD, `-d:release` generates faster code)
    27941 lines; 0.342s; 30.445MiB peakmem; proj: /workspaces/debian/a.nim; out: /workspaces/debian/a [SuccessX]

    $ ls -l a
    -rwxr-xr-x 1 vscode vscode 96480 Dec 22 12:19 a

    $ ./a
    Hello World
    ```

Git Clone the `nuttx` and `apps` folders. Then configure NuttX...

```bash
## TODO: git clone ... nuttx
## TODO: git clone ... apps

## Configure NuttX for QEMU RISC-V (64-bit)
cd nuttx
tools/configure.sh rv-virt:nsh64
make menuconfig
```

Enable the settings...

- "Device Drivers > LED Support > LED Driver"

- "Device Drivers > LED Support > Generic Lower Half LED Driver"

- "Application Configuration > Examples > Hello World Example (Nim)"

- "Application Configuration > Examples > LED Driver Example"

If we need NuttX Networking: Select...

```text
Networking support: Enable "Networking support"
Networking Support → SocketCAN Support:
  Enable "SocketCAN Support"
  Enable "sockopt support"
RTOS Features → Tasks and Scheduling:
  Enable "Support parent/child task relationships"
  Enable "Retain child exit status"
```

Save and exit menuconfig, then build and run NuttX...

```bash
## Build NuttX
make

## Start NuttX with QEMU RISC-V (64-bit)
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

# usleep

TODO

usleep calls clock_nanosleep...

```text
00000000000007e8 <usleep>:
usleep():
/workspaces/bookworm/nuttx/libs/libc/unistd/lib_usleep.c:100
{
  struct timespec rqtp;
  time_t sec;
  int ret = 0;

  if (usec)
     7e8:	cd15                	beqz	a0,824 <.L3>	7e8: R_RISCV_RVC_BRANCH	.L3

00000000000007ea <.LVL1>:
/workspaces/bookworm/nuttx/libs/libc/unistd/lib_usleep.c:104
    {
      /* Let clock_nanosleep() do all of the work. */

      sec          = usec / 1000000;
     7ea:	000f47b7          	lui	a5,0xf4
     7ee:	2407879b          	addw	a5,a5,576 # f4240 <.LASF110+0xe2ec1>
     7f2:	02f5573b          	divuw	a4,a0,a5
/workspaces/bookworm/nuttx/libs/libc/unistd/lib_usleep.c:95
{
     7f6:	1101                	add	sp,sp,-32
/workspaces/bookworm/nuttx/libs/libc/unistd/lib_usleep.c:108
      rqtp.tv_sec  = sec;
      rqtp.tv_nsec = (usec - (sec * 1000000)) * 1000;

      ret = clock_nanosleep(CLOCK_REALTIME, 0, &rqtp, NULL);
     7f8:	860a                	mv	a2,sp
     7fa:	4681                	li	a3,0
     7fc:	4581                	li	a1,0
```

clock_nanosleep makes ecall to Kernel clock_nanosleep...

```text
0000000000001dee <clock_nanosleep>:
clock_nanosleep():
/workspaces/bookworm/nuttx/syscall/proxies/PROXY_clock_nanosleep.c:8
#include <nuttx/config.h>
#include <time.h>
#include <syscall.h>

int clock_nanosleep(clockid_t parm1, int parm2, FAR const struct timespec * parm3, FAR struct timespec * parm4)
{
    1dee:	88aa                	mv	a7,a0

0000000000001df0 <.LVL1>:
    1df0:	882e                	mv	a6,a1

0000000000001df2 <.LVL2>:
    1df2:	87b2                	mv	a5,a2

0000000000001df4 <.LVL3>:
    1df4:	8736                	mv	a4,a3

0000000000001df6 <.LBB4>:
sys_call4():
/workspaces/bookworm/nuttx/include/arch/syscall.h:281
  register long r0 asm("a0") = (long)(nbr);
    1df6:	03100513          	li	a0,49

0000000000001dfa <.LVL5>:
/workspaces/bookworm/nuttx/include/arch/syscall.h:282
  register long r1 asm("a1") = (long)(parm1);
    1dfa:	85c6                	mv	a1,a7

0000000000001dfc <.LVL6>:
/workspaces/bookworm/nuttx/include/arch/syscall.h:283
  register long r2 asm("a2") = (long)(parm2);
    1dfc:	8642                	mv	a2,a6

0000000000001dfe <.LVL7>:
/workspaces/bookworm/nuttx/include/arch/syscall.h:284
  register long r3 asm("a3") = (long)(parm3);
    1dfe:	86be                	mv	a3,a5

0000000000001e00 <.LVL8>:
/workspaces/bookworm/nuttx/include/arch/syscall.h:287
  asm volatile
    1e00:	00000073          	ecall
/workspaces/bookworm/nuttx/include/arch/syscall.h:294
  asm volatile("nop" : "=r"(r0));
    1e04:	0001                	nop

0000000000001e06 <.LBE4>:
clock_nanosleep():
/workspaces/bookworm/nuttx/syscall/proxies/PROXY_clock_nanosleep.c:10
  return (int)sys_call4((unsigned int)SYS_clock_nanosleep, (uintptr_t)parm1, (uintptr_t)parm2, (uintptr_t)parm3, (uintptr_t)parm4);
}
    1e06:	2501                	sext.w	a0,a0
    1e08:	8082                	ret
```

System Call Number for clock_nanosleep is 49...

```text
 <2><b5b0>: Abbrev Number: 1 (DW_TAG_enumerator)
    <b5b1>   DW_AT_name        : (strp) (offset: 0x8ca9): SYS_clock_nanosleep
    <b5b5>   DW_AT_const_value : (data1) 49
```

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

# Fix the RISC-V Timer with OpenSBI

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

# LED Driver for Ox64 BL808

TODO

We wish to blink an LED with Nim on Ox64...

- ["Blink an LED with Nim"](https://github.com/lupyuen/nuttx-nim#blink-an-led-with-nim)

But first we need a barebones NuttX LED Driver for Ox64.

_How to create the NuttX LED Driver?_

We assume LED is connected to GPIO 29, Pin 21. [(See the Pinout)](https://wiki.pine64.org/wiki/File:Ox64_pinout.png)

(With a 47 Ohm Resistor, yellow-purple-black-gold)

_How do we flip a BL808 GPIO High and Low?_

From BL808 Reference Manual Page 56, "Normal GPIO Output Mode"...

- Set reg_gpio_xx_oe (Bit 6) to 1 to enable the GPIO output mode <br>
  = (1 << 6)

- Set reg_gpio_xx_func_sel (Bits 8 to 12) to 11 to enter the SWGPIO mode <br>
  = (11 << 8)

- Set reg_gpio_xx_mode (Bits 30 to 31) to 0 to enable the normal output function of I/O <br>
  = (0 << 30)

- Set reg_gpio_xx_pu (Bit 4) and reg_gpio_xx_pd (Bit 5) to 0 to disable the internal pull-up and pull-down functions <br>
  = (0 << 4)

- Set the level of I/O pin through reg_gpio_xx_o (Bit 24) <br>
  = Either (0 << 24) Or (1 << 24)

(GPIO Bit Definitions are below)

Which means...

- Set GPIO Output to 0 <br>
  = (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24) <br>
  = 0xb40

- Set GPIO Output to 1 <br>
  = (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24) <br>
  = 0x1000b40

_How to test this?_

GPIO 29 Base Address `gpio_cfg29` is 0x20000938.

For testing, we run U-Boot Bootloader Commands to set GPIO 29 to High and Low...

```bash
## Dump gpio_cfg29 at 0x20000938
$ md 0x20000938 1
20000938: 00400803                             ..@.

## Set GPIO Output to 0: (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24)
## = 0xb40
$ mw 0x20000938 0xb40 1
$ md 0x20000938 1
20000938: 00000b40                             @...

## Set GPIO Output to 1: (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24)
## = 0x1000b40
$ mw 0x20000938 0x1000b40 1
$ md 020000938 1
20000938: 01000b40                             @...
```

And U-Boot switches the LED On and Off correctly yay!

_How to flip the GPIO in our NuttX LED Driver?_

This is how we flip the GPIO in our NuttX LED Driver: [bl808_userleds.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/nim/boards/risc-v/bl808/ox64/src/bl808_userleds.c#L176-L209)

```c
// Switch the LEDs On and Off according to the LED Set
// (Bit 0 = LED 0)
void board_userled_all(uint32_t ledset)
{
  _info("ledset=0x%x\n", ledset);////
  int i;

  // For LED 0 to 2...
  for (i = 0; i < BOARD_LEDS; i++)
    {
      // Get the desired state of the LED
      bool val = ((ledset & g_led_setmap[i]) != 0);
      _info("led=%d, val=%d\n", i, val);////

      // If this is LED 0...
      if (i == 0)
        {
          // Switch it On or Off?
          if (val)
            {
              // Switch LED 0 (GPIO 29) to On:
              // Set gpio_cfg29 to (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (1 << 24)
              // mw 0x20000938 0x1000b40 1
              *(volatile uint32_t *) 0x20000938 = 0x1000b40;
            }
          else
            {
              // Switch LED 0 (GPIO 29) to Off:
              // Set gpio_cfg29 to (1 << 6) | (11 << 8) | (0 << 30) | (0 << 4) | (0 << 24)
              // mw 0x20000938 0xb40 1
              *(volatile uint32_t *) 0x20000938 = 0xb40;
            }
        }
      ////TODO: a64_pio_write(g_led_map[i], (ledset & g_led_setmap[i]) != 0);
    }
}
```

And our LED Driver works OK with Nim: It blinks our LED on Ox64 BL808 SBC!

- [Watch the Demo on YouTube](https://youtube.com/shorts/KCkiXFxBgxQ)

- [See the Log](https://gist.github.com/lupyuen/553c2da4ad5d119468d223e162573e96)

- ["Blink an LED with Nim"](https://github.com/lupyuen/nuttx-nim#blink-an-led-with-nim)

Later we'll replace the (awful) code above by the BL808 GPIO Driver. Which we'll copy from NuttX for BL602.

_How did we get the GPIO Bit Definitions?_

From BL808 Reference Manual Page 119...

```text
4.8.30 gpio_cfg29
Base Address：0x20000938

Bits Name Type Reset Description

31:30 reg_gpio_29_mode r/w 0 When GPIO Function Selected to SWGPIO
00 (Output Value Mode): GPIO Output by reg_gpio_x_o
Value
01 (Set/Celar Mode ) :GPIO Output set by reg_gpio_x_set
and clear by reg_gpio_x_clr
10 : SWGPIO Source comes from GPIO DMA (GPIO DMA
Mode), GPIO Output value by gpio_dma_o
11: SWGPIO Source comes from GPIO DMA (GPIO DMA
Mode), GPIO Outout value by gpio_dma_set/gpio_dma_clr

29 RSVD

28 reg_gpio_29_i r 0

27 RSVD

26 reg_gpio_29_clr w1p 0 When SWGPIO @ Set/Clear Mode
Set this bit will clear GPIO output value to 0,when set/clr at
the same time, only set take effect

25 reg_gpio_29_set w1p 0 When SWGPIO @ Set/Clear Mode
Set this bit will set GPIO output value to 1,when set/clr at
the same time, only set take effect

24 reg_gpio_29_o r/w 0 When SWGPIO @ Output Value Mode
00 : GPIO Value changes according to this value
01 : GPIO Value Set by this register and clr by clr_reg

23 RSVD

22 reg_gpio_29_int_mask r/w 1 mask interrupt (1)

21 gpio_29_int_stat r 0 interrupt status

20 reg_gpio_29_int_clr r/w 0 clear interrupt

19:16 reg_gpio_29_int_mode_set r/w 0 0000 : sync falling edge trigger
0001 : sync rising edge trigger
0010 : sync low level trigger
0011 : sync high level trigger
01xx : sync rising & falling edge trigger
1000 : async falling edge trigger
1001 : async rising edge trigger
1010 : async low level trigger
1011 : async high level trigger

15:13 RSVD

12:8 reg_gpio_29_func_sel r/w 5’hB GPIO Function Select (Default : SW-GPIO)

7 RSVD

6 reg_gpio_29_oe r/w 0 Register Controlled GPIO Output Enable (Used when GPIO
Function select to Register Control GPIO)

5 reg_gpio_29_pd r/w 0 GPIO Pull Down Control

4 reg_gpio_29_pu r/w 0 GPIO Pull Up Control

3:2 reg_gpio_29_drv r/w 0 GPIO Driving Control

1 reg_gpio_29_smt r/w 1 GPIO SMT Control

0 reg_gpio_29_ie r/w 0 GPIO Input Enable
```

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
