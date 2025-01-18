# Fixing a uname bug (Apache NuttX RTOS)

📝 _19 Jan 2025_

![Fixing a uname bug (Apache NuttX RTOS)](https://lupyuen.github.io/images/uname-title.jpg)

Earlier This Week: [__uname__](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-13) became unusually quieter on [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)...

```bash
## Hmmm something is missing
NuttShell (NSH) NuttX-12.8.0
nsh> uname -a
NuttX 12.8.0  risc-v rv-virt
```

See the subtle bug? The [__Commit Hash__](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-nsh64-2025-01-13) is missing!

```bash
## Commit Hash should always appear
nsh> uname -a
NuttX 12.8.0 5f4a15b690 Jan 13 2025 00:34:30 risc-v rv-virt
```

![Commit Hash identifies the Exact Commit of NuttX that was used to produce the NuttX Build](https://lupyuen.github.io/images/uname-commit.png)

_Can we ignore it? Maybe nobody will notice?_

Noooooo! Commit Hash identifies the __Exact Commit of NuttX__ that was used to produce the NuttX Build. (Pic above)

Watch as we stomp the seemingly simple bug... That turns out to be __something seriously sinister__! _(Spoiler: Static Vars are broken)_

# Inside uname

_uname on NuttX: How does it work?_

Use the Source, Luke! First we peek inside the __uname__ command.

Our bug happens in __NuttX Shell__. Thus we search [__NuttX Apps Repo__](https://github.com/apache/nuttx-apps) for __uname__...

![Search NuttX Apps Repo for uname](https://lupyuen.github.io/images/uname-search1.png)

[__Searching for uname__](https://github.com/search?q=repo%3Aapache%2Fnuttx-apps%20uname&type=code) returns this code in NuttX Shell: [nsh_syscmds.c](https://github.com/apache/nuttx-apps/blob/master/nshlib/nsh_syscmds.c#L765-L863)

```c
// Declare the uname() function
#include <sys/utsname.h>

// NuttX Shell: To execute the uname command...
// We call the uname() function
int cmd_uname(...) { ...
  struct utsname info;
  ret = uname(&info);
```

We see that __uname command__ calls the __uname function__.

So we search the [__NuttX Kernel Repo__](https://github.com/apache/nuttx) for __uname__...

![Search the NuttX Kernel Repo for uname](https://lupyuen.github.io/images/uname-search2.png)

[__NuttX Kernel Search__](https://github.com/search?q=repo%3Aapache%2Fnuttx%20uname&type=code) says that __uname__ is defined here: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

```c
// CONFIG_VERSION_BUILD goes inside Static Var g_version
static char g_version[] = CONFIG_VERSION_BUILD;  // Omitted: Date and Time

// g_version goes into the uname output
int uname(FAR struct utsname *output) { ...
  strlcpy(
    output->version,         // Copy into the Output Version
    g_version,               // From our Static Var (CONFIG_VERSION_BUILD a.k.a Commit Hash)
    sizeof(output->version)  // Making sure we don't overflow
  );
```

(Is __uname__ a __Kernel Function__? We'll see soon)

![CONFIG_VERSION_BUILD inside uname](https://lupyuen.github.io/images/uname-title2.jpg)

# CONFIG_VERSION_BUILD

_What's this CONFIG_VERSION_BUILD?_

Earlier we saw that __uname__ function returns _CONFIG_VERSION_BUILD_: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

```c
// CONFIG_VERSION_BUILD goes inside Static Var g_version
static char g_version[] = CONFIG_VERSION_BUILD;  // Omitted: Date and Time

// g_version goes into the uname output
int uname(FAR struct utsname *output) { ...
  strlcpy(
    output->version,         // Copy into the Output Version
    g_version,               // From our Static Var (CONFIG_VERSION_BUILD a.k.a Commit Hash)
    sizeof(output->version)  // Making sure we don't overflow
  );
```

Let's track the origin of _CONFIG_VERSION_BUILD_. We build NuttX for [__QEMU RISC-V 64-bit__](https://nuttx.apache.org/docs/latest/platforms/risc-v/qemu-rv/boards/rv-virt/index.html) (Kernel Mode)

```bash
## Download the NuttX Kernel and NuttX Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps

## Configure NuttX for QEMU RISC-V 64-bit (Kernel Mode)
cd nuttx
tools/configure.sh rv-virt:knsh64

## Build the NuttX Kernel
make -j

## Build the NuttX Apps
make export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make import
popd
```

[(See the __Build Log__)](https://gist.github.com/lupyuen/db850282e6f84673b2fd07900f574f4d#file-special-qemu-riscv-knsh64-log-L47-L1251)

Maybe _CONFIG_VERSION_BUILD_ is in the NuttX Config File?

```bash
$ grep CONFIG_VERSION_BUILD .config
[ Nothing ]
## Nope it's not!
```

We head back to NuttX Kernel Repo and [__search for _CONFIG_VERSION_BUILD___](https://github.com/apache/nuttx/blob/master/Documentation/guides/versioning_and_task_names.rst#L57)...

> _The Version Number you are looking at comes from the Header File __nuttx/include/nuttx/version.h__._ 

> _That Header File was created at build time from a Hidden File that you can find in the top-level nuttx directory called __.version__._

Aha! _CONFIG_VERSION_BUILD_ a.k.a. Commit Hash comes from __version.h__

```bash
$ cat include/nuttx/version.h 
#define CONFIG_VERSION_BUILD "a2d4d74af7"
```

[(Thanks to __Ludovic Vanasse__ for porting the docs)](https://github.com/apache/nuttx/pull/14239)

![Static Variable g_version inside uname](https://lupyuen.github.io/images/uname-title2.jpg)

# Static Variable g_version

_Is CONFIG_VERSION_BUILD compiled correctly into our NuttX Image?_

We snoop the __NuttX Kernel Image__ to verify that _CONFIG_VERSION_BUILD_ is correct.

Recall that _CONFIG_VERSION_BUILD_ is stored in Static Variable __g_version__: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

```c
// CONFIG_VERSION_BUILD goes inside Static Var g_version
static char g_version[] = CONFIG_VERSION_BUILD;  // Omitted: Date and Time

// g_version goes into the uname output
int uname(FAR struct utsname *output) { ...
  strlcpy(
    output->version,         // Copy into the Output Version
    g_version,               // From our Static Var (CONFIG_VERSION_BUILD a.k.a Commit Hash)
    sizeof(output->version)  // Making sure we don't overflow
  );
```

According to __NuttX Linker Map__: Address of __g_version__ is __`0x8040` `03B8`__

```bash
## Search for g_version in Linker Map, show 1 line after
$ grep \
  --after-context=1 \
  g_version \
  nuttx.map

.data.g_version
  0x804003b8  0x21  staging/libkc.a(lib_utsname.o)
```

What's the value inside __g_version__? We dump the __Binary Image__ from NuttX Kernel ELF...

```bash
## Export the NuttX Binary Image to nuttx.bin
riscv-none-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin
```

Earlier we said __g_version__ is at __`0x8040` `03B8`__.

We open __nuttx.bin__ in [__VSCode Hex Editor__](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor), press __Ctrl-G__ and jump to __`0x2003B8`__...

[(Because NuttX Kernel loads at __`0x8020` `0000`__)](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel.script#L24-L26)

![nuttx.bin in VSCode Hex Viewer](https://lupyuen.github.io/images/uname-hex1.png)

And that's our _CONFIG_VERSION_BUILD_ with Commit Hash! Looks hunky dory, why wasn't it returned correctly to __uname__ and NuttX Shell?

![Call uname in NuttX Kernel](https://lupyuen.github.io/images/uname-title3.jpg)

# Call uname in NuttX Kernel

_Maybe NuttX Kernel got corrupted? Returning bad data for uname?_

We tweak the NuttX Kernel and call __uname__ at Kernel Startup: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-nuttx/blob/uname/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L118-L125)

```c
// Declare the uname() function
#include <sys/utsname.h>

// When Kernel Boots:
// Call the uname() function
int board_app_initialize(uintptr_t arg) { ...
  struct utsname info;
  int ret2 = uname(&info);

  // If uname() returns OK:
  // Print the Commit Hash a.k.a. g_version
  if (ret2 == 0) {
    _info("version=%s\n", info.version);
  }
```

Then inside the __uname__ function, we dump the value of __g_version__: [lib_utsname.c](https://github.com/lupyuen2/wip-nuttx/blob/uname/libs/libc/misc/lib_utsname.c#L108-L113)

```c
// Inside the uname() function:
// Print g_version with _info() and printf()
int uname(FAR struct utsname *name) { ...
  _info("From _info: g_version=%s\n",   g_version);  // Kernel Only
  printf("From printf: g_version=%s\n", g_version);  // Kernel and Apps
  printf("Address of g_version=%p\n",   g_version);  // Kernel and Apps
```

(Why print twice? We'll see soon)

We boot NuttX on [__QEMU RISC-V 64-bit__](https://nuttx.apache.org/docs/latest/platforms/risc-v/qemu-rv/boards/rv-virt/index.html)...

```bash
## Start QEMU with NuttX
$ qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -kernel nuttx \
  -nographic

## NuttX Kernel shows Commit Hash
From _info:
  g_version=bd6e5995ef Jan 16 2025 15:29:02
From printf:
  g_version=bd6e5995ef Jan 16 2025 15:29:02
  Address of g_version=0x804003b8
board_app_initialize:
  version=bd6e5995ef Jan 16 2025 15:29:02
NuttShell (NSH) NuttX-12.4.0
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/db850282e6f84673b2fd07900f574f4d#file-special-qemu-riscv-knsh64-log-L1391-L1395)

Yep NuttX Kernel correctly prints __g_version__ a.k.a. _CONFIG_VERSION_BUILD_ a.k.a. Commit Hash. No Kernel Corruption! _(Phew)_

![Call uname in NuttX App](https://lupyuen.github.io/images/uname-title4.jpg)

# Call uname in NuttX App

_Maybe something got corrupted in our NuttX App?_

Wow that's so diabolical, sure hope not. We mod the __NuttX Hello App__ and call __uname__: [hello_main.c](https://github.com/lupyuen2/wip-nuttx-apps/blob/uname/examples/hello/hello_main.c#L42-L57)

```c
// Declare the uname() function
#include <sys/utsname.h>

// In Hello App: Call the uname() function
int main(int argc, FAR char *argv[]) {
  struct utsname info;
  int ret = uname(&info);

  // If uname() returns OK:
  // Print the Commit Hash a.k.a. g_version
  if (ret >= 0) {
    printf("version=%s\n", info.version);
  }
```

Indeed something is messed up with __g_version__ a.k.a. _CONFIG_VERSION_BUILD_ a.k.a. Commit Hash...

```bash
## Why is Commit Hash empty?
NuttShell (NSH) NuttX-12.8.0
nsh> hello
version=
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/db850282e6f84673b2fd07900f574f4d#file-special-qemu-riscv-knsh64-log-L1416-L1431)

Inside our NuttX App: Why is __g_version__ empty? Wasn't it OK in NuttX Kernel?

# Dump the NuttX App Disassembly

_Why did uname work differently: NuttX Kernel vs NuttX Apps?_

Now we chase the __uname raving rabbid__ inside our __NuttX App__. Normally we'd dump the __RISC-V Disassembly__ for our Hello App ELF...

```bash
## Dump the RISC-V Disassembly for apps/bin/hello
$ riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin/hello \
  >hello.S \
  2>&1

## Impossible to read, without Debug Symbols
$ more hello.S
SYMBOL TABLE: no symbols
00000000c0000000 <.text>:
  c0000000: 1141  add sp, sp, -16
  c0000002: e006  sd  ra, 0(sp)
  c0000004: 82aa  mv  t0, a0
```

But ugh NuttX Build has unhelpfully __Discarded the Debug Symbols__ from our Hello App ELF, making it hard to digest.

_How to recover the Debug Symbols?_

We sniff the __NuttX Build__...

```bash
## Update our Hello App
$ cd ../apps
$ touch examples/hello/hello_main.c

## Trace the NuttX Build for Hello App
$ make import V=1
LD:  apps/bin/hello 
riscv-none-elf-ld -e main --oformat elf64-littleriscv -T nuttx/libs/libc/modlib/gnu-elf.ld -e __start -Bstatic -Tapps/import/scripts/gnu-elf.ld  -Lapps/import/libs -L "xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" apps/import/startup/crt0.o  hello_main.c...apps.examples.hello.o --start-group -lmm -lc -lproxies -lgcc apps/libapps.a xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a --end-group -o  apps/bin/hello
cp apps/bin/hello apps/bin_debug
riscv-none-elf-strip --strip-unneeded apps/bin/hello

## apps/bin/hello is missing the Debug Symbols
## apps/bin_debug/hello retains the Debug Symbols!
```

Ah NuttX Build has squirrelled away the __Debug Version__ of Hello App into __apps/bin_debug__. We dump its __RISC-V Disassembly__...

```bash
## Dump the RISC-V Disassembly for apps/bin_debug/hello
cd ../nuttx
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin_debug/hello \
  >hello.S \
  2>&1
```

[(See the __RISC-V Disassembly hello.S__)](https://gist.github.com/lupyuen/f713ff54d8aa5f8f482f7b03e34a9f06)

# Snoop uname in NuttX App

_Once Again: How is uname different in NuttX Kernel vs NuttX App?_

Earlier we dumped the __RISC-V Disassembly__ for our modded Hello App: [__hello.S__](https://gist.github.com/lupyuen/f713ff54d8aa5f8f482f7b03e34a9f06)

We browse the disassembly and search for __uname__. This appears: [hello.S](https://gist.github.com/lupyuen/f713ff54d8aa5f8f482f7b03e34a9f06#file-hello-s-L397-L496)

```c
// Inside Hello App: The RISC-V Disassembly of uname() function
int uname(FAR struct utsname *name) { ...

// Call _info() to print g_version
_info("From _info: g_version=%s\n", g_version);
  auipc a3, 0x100
  add   a3, a3, 170  // Arg #3: g_version
  auipc a2, 0x2
  add   a2, a2, -270 // Arg #2: Format String
  auipc a1, 0x2
  add   a1, a1, -814 // Arg #1: VarArgs Size (I think)
  li    a0, 6        // Arg #0: Info Logging Priority
  jal   c00007c8     // Call syslog()

// Call printf() to print g_version
printf("From printf: g_version=%s\n", g_version);
  auipc a1, 0x100
  add   a1, a1, 140  // Arg #1: g_version
  auipc a0, 0x2
  add   a0, a0, -804 // Arg #0: Format String
  jal   c00001e6     // Call printf()

// Call printf() to print Address of g_version
printf("Address of g_version=%p\n", g_version);
  auipc a1, 0x100
  add   a1, a1, 120  // Arg #1: g_version
  auipc a0, 0x2
  add   a0, a0, -792 // Arg #0: Format String
  jal   c00001e6     // Call printf()

// Copy g_version into the uname() output
strlcpy(name->version,  g_version, sizeof(name->version));
  li    a2, 51       // Arg #2: Size of name->version
  auipc a1, 0x100
  add   a1, a1, 96   // Arg #1: g_version
  add   a0, s0, 74   // Arg #0: name->version
  jal   c0000748     // Call strlcpy()
```

Which does 4 things...

1.  Call __\_info__ (a.k.a. __syslog__) to print __g_version__

1.  Call __printf__ to print __g_version__

1.  Followed by __Address of g_version__

1.  Copy __g_version__ into the __uname__ output

# uname is Not a Kernel Call

_Huh? Isn't this the exact same Kernel Code we saw earlier?_

Precisely! We expected __uname__ to be a [__System Call to NuttX Kernel__](https://lupyuen.github.io/articles/app#nuttx-app-calls-nuttx-kernel)...

![NuttX App calls NuttX Kernel](https://lupyuen.github.io/images/app-syscall.jpg)

But nope, __uname__ is a __Local Function__. _(Not a System Call)_

![uname is a Local Function, not a System Call](https://lupyuen.github.io/images/uname-title5.jpg)

Every NuttX App has a __Local Copy of g_version__ and Commit Hash. _(That's potentially corruptible hmmm...)_

Which explains why __printf__ appears in the [__Hello Output__](https://gist.github.com/lupyuen/db850282e6f84673b2fd07900f574f4d#file-special-qemu-riscv-knsh64-log-L1391-L1431) but not __\_info__...

```bash
## NuttX Kernel: Shows _info() and printf()
From _info:
  g_version=bd6e5995ef Jan 16 2025 15:29:02
From printf:
  g_version=bd6e5995ef Jan 16 2025 15:29:02
  Address of g_version=0x804003b8

## NuttX Apps: Won't show _info()
NuttShell (NSH) NuttX-12.4.0
nsh> hello
From printf:
  g_version=
  Address of g_version=0xc0100218
```

(Because __\_info__ and __syslog__ won't work in NuttX Apps)

The Full Path of __uname__ is a dead giveaway: It's a __Library Function__. _(Not a Kernel Function)_

```text
libs/libc/misc/lib_utsname.c
```

[(uname is a __System Call in Linux__)](https://man7.org/linux/man-pages/man2/syscalls.2.html)

# Static Variables are Broken

_Gasp! What if g_version a.k.a. Commit Hash got corrupted inside our app?_

Earlier we saw that __g_version__ is a __Static Variable__ that contains our Commit Hash: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

```c
// CONFIG_VERSION_BUILD goes inside Static Var g_version
static char g_version[] = CONFIG_VERSION_BUILD;  // Omitted: Date and Time

// g_version goes into the uname output
int uname(FAR struct utsname *output) { ...
  strlcpy(
    output->version,         // Copy into the Output Version
    g_version,               // From our Static Var (CONFIG_VERSION_BUILD a.k.a Commit Hash)
    sizeof(output->version)  // Making sure we don't overflow
  );
```

We have a hefty hunch that __Static Variables__ might be broken 😱. We test our hypothesis in __Hello App__: [hello_main.c](https://github.com/lupyuen2/wip-nuttx-apps/blob/uname/examples/hello/hello_main.c#L30-L65)

```c
// Define our Static Var
static char test_static[] =
  "Testing Static Var";

// In Hello App: Print our Static Var
// "test_static=Testing Static Var"
int main(int argc, FAR char *argv[]) {
  printf("test_static=%s\n", test_static);
  printf("Address of test_static=%p\n", test_static);
```

Our hunch is 100% correct: __Static Variables are Broken!__

```bash
## Why is Static Var `test_static` empty???
NuttShell (NSH) NuttX-12.4.0
nsh> hello
test_static=
Address of test_static=0xc0100200
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/db850282e6f84673b2fd07900f574f4d#file-special-qemu-riscv-knsh64-log-L1416-L1431)

![Static Variables are Broken!](https://lupyuen.github.io/images/uname-title6.jpg)

OK this goes waaaaay beyond our debugging capability. _(NuttX App Data Section got mapped incorrectly into the Memory Space?)_

We call in the __NuttX Experts__ for help. And it's awesomely fixed by [__anjiahao__](https://github.com/anjiahao1) yay! 🎉

- [__Static Char Arrays are Empty for NuttX Apps__](https://github.com/apache/nuttx/issues/15526)

- [__modlib: Data Section mismatch__](https://github.com/apache/nuttx/pull/15527)

__Lesson Learnt:__ Please pay attention to the slightest disturbance, like the __uname__ output...

It might be a sign of __something seriously sinister simmering__ under the surface!

![Fixing a uname bug (Apache NuttX RTOS)](https://lupyuen.github.io/images/uname-title.jpg)

# What's Next

Next Article: Why __Sync-Build-Ingest__ is super important for NuttX Continuous Integration. And how we monitor it with our __Magic Disco Light__.

After That: Since we can __Rewind NuttX Builds__ and automatically __Git Bisect__... Can we create a Bot that will fetch the __Failed Builds from NuttX Dashboard__, identify the Breaking PR, and escalate to the right folks?

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.github.io/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.github.io)

- [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/uname.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/uname.md)
