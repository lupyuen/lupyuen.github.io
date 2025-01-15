# Fixing a uname bug (Apache NuttX RTOS)

📝 _30 Jan 2025_

![TODO](https://lupyuen.github.io/images/uname-title.png)

Earlier This Week: [__`uname`__](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-13) became unusually quieter on [__Apache NuttX RTOS__](TODO)...

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

![TODO](https://lupyuen.github.io/images/uname-commit.png)

_Can we ignore it? Maybe nobody will notice?_

Noooooo! Commit Hash identifies the __Exact Commit of NuttX__ (pic above) that was used to produce the NuttX Build.

Watch as we stomp the seemingly simple bug... That turns out to be __something seriously sinister__! _(Spoiler: Static Vars are broken)_

# Inside uname

_uname on NuttX: How does it work?_

Use the Source, Luke! First we peek inside the __`uname`__ command.

Our bug happens in __NuttX Shell__. Thus we search the [__NuttX Apps Repo__](TODO) for __`uname`__...

TODO: Pic of uname search

[__Our search for `uname`__](https://github.com/search?q=repo%3Aapache%2Fnuttx-apps%20uname&type=code) returns this code in NuttX Shell: [nsh_syscmds.c](https://github.com/apache/nuttx-apps/blob/master/nshlib/nsh_syscmds.c#L771)

```c
TODO
```

We see that __`uname` command__ calls the __`uname` function__.

We search the [__NuttX Kernel Repo__](TODO) for __`uname`__...

TODO: Pic of uname search

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

(Is __`uname`__ a __Kernel Function__? We'll find out in a bit)

# CONFIG_VERSION_BUILD

_What's this CONFIG_VERSION_BUILD?_

Earlier we saw that __`uname`__ function returns __CONFIG_VERSION_BUILD__: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

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

Let's track the origin of __CONFIG_VERSION_BUILD__. We build NuttX for [__QEMU RISC-V 64-bit__](TODO) (Kernel Mode)

```bash
TODO
```

Maybe __CONFIG_VERSION_BUILD__ is in the NuttX Config File?

```bash
$ grep CONFIG_VERSION_BUILD .config
[ Nothing ]
## Nope it's not!
```

We head back to NuttX Kernel Repo and [__search for CONFIG_VERSION_BUILD__](https://github.com/apache/nuttx/blob/master/Documentation/guides/versioning_and_task_names.rst#L57)...

> _The Version Number you are looking at comes from the Header File __nuttx/include/nuttx/version.h__._ 

> _That Header File was created at build time from a Hidden File that you can find in the top-level nuttx directory called __.version__._

Aha! __CONFIG_VERSION_BUILD__ a.k.a. Commit Hash comes from __version.h__

```bash
$ cat include/nuttx/version.h 
#define CONFIG_VERSION_BUILD "a2d4d74af7"
```

[(Thanks to __Ludovic Vanasse__ for porting the docs)](https://github.com/apache/nuttx/pull/14239)

# Static Variable g_version

_Is CONFIG_VERSION_BUILD compiled correctly into our NuttX Image?_

We snoop the __NuttX Kernel Image__ to verify that __CONFIG_VERSION_BUILD__ is correct.

Recall that __CONFIG_VERSION_BUILD__ is stored in Static Variable __g_version__: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

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

What's the value inside __g_version__? We dump the __Binary Image__ of NuttX Kernel...

```bash
## Export the NuttX Binary Image to nuttx.bin
riscv-none-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin
```

Remember __g_version__ is at __`0x8040` `03B8`__?

We open __nuttx.bin__ in [__VSCode Hex Viewer__](TODO), press __Ctrl-G__ and jump to __`0x2003B8`__...

[(Because NuttX Kernel loads at __`0x8020` `0000`__)](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel.script#L24-L26)

![TODO](https://lupyuen.github.io/images/uname-hex1.png)

And that's our __CONFIG_VERSION_BUILD__ with Commit Hash! Looks hunky dory, why wasn't it returned correctly to __uname__ and NuttX Shell?

# Call uname in NuttX Kernel

_Maybe NuttX Kernel got corrupted? Returning bad data for uname?_

We tweak the NuttX Kernel and call __`uname`__ at Kernel Startup: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-nuttx/blob/uname/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L121)

```c
TODO
```

Inside the __`uname`__ function, we dump the value of __g_version__: [lib_utsname.c](https://github.com/lupyuen2/wip-nuttx/blob/uname/libs/libc/misc/lib_utsname.c#L109)

```c
TODO
```

(Why twice? We'll see in a while)

We boot NuttX on [__QEMU RISC-V 64-bit__](TODO)...

```bash
TODO: qemu
ABC
From _info:
  g_version=c3330b17c7e-dirty Jan 13 2025 11:49:41
From printf:
  g_version=c3330b17c7e-dirty Jan 13 2025 11:49:41
board_app_initialize:
  version=c3330b17c7e-dirty Jan 13 2025 11:49:41
```

[(See the __Complete Log__)](TODO)

Yep NuttX Kernel correctly prints __g_version__ a.k.a. __CONFIG_VERSION_BUILD__ a.k.a. Commit Hash. No Kernel Corruption! _(Phew)_

# Call uname in NuttX App

_Maybe something got corrupted in our NuttX App?_

Wow that's so diabolical, sure hope not. We mod the __NuttX Hello App__ and call __uname__: [hello_main.c](https://github.com/lupyuen2/wip-nuttx-apps/blob/uname/examples/hello/hello_main.c#L43-L53)

```c
TODO
```

Indeed something is messed up with __g_version__ a.k.a. __CONFIG_VERSION_BUILD__ a.k.a. Commit Hash...

```bash
## Why is Commit Hash empty?
NuttShell (NSH) NuttX-12.8.0
nsh> hello
version=
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ee3eee9752165bee8f3e60d57c224372#file-special-qemu-riscv-knsh64-log-L1410)

Inside our NuttX App: Why is __g_version__ empty? Wasn't it OK in NuttX Kernel?

# Dump the NuttX App Disassembly

_Why did uname work differently: NuttX Kernel vs NuttX Apps?_

Now we chase the __`uname` raving rabbid__ inside our __NuttX App__. Normally we'd dump the __RISC-V Disassembly__ for our NuttX App...

```bash
## Dump the RISC-V Disassembly for apps/bin/hello
$ riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin/hello \
  >hello.S \
  2>&1

TODO: grep
```

But ugh NuttX Build has unhelpfully __Discarded the Debug Symbols__ from our NuttX App, making it hard to digest.

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

Ah NuttX Build has squirrelled away the __Debug Version__ of our app into __apps/bin_debug__. We dump the __RISC-V Disassembly__...

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

We browse [__hello.S__](https://gist.github.com/lupyuen/f713ff54d8aa5f8f482f7b03e34a9f06) and search for __`uname`__. This appears: [hello.S](https://gist.github.com/lupyuen/f713ff54d8aa5f8f482f7b03e34a9f06#file-hello-s-L397-L496)

```text
int uname(FAR struct utsname *name) { ...

_info("From _info: g_version=%s\n", g_version);
  c000016e: 00100697           auipc a3,0x100
  c0000172: 0aa68693           add a3,a3,170 # c0100218 <g_version>
  c0000176: 00002617           auipc a2,0x2
  c000017a: ef260613           add a2,a2,-270 # c0002068 <__FUNCTION__.0>
  c000017e: 00002597           auipc a1,0x2
  c0000182: cd258593           add a1,a1,-814 # c0001e50 <_einit+0x120>
  c0000186: 4519               li a0,6
  c0000188: 640000ef           jal c00007c8 <syslog>

printf("From printf: g_version=%s\n", g_version);
  c000018c: 00100597           auipc a1,0x100
  c0000190: 08c58593           add a1,a1,140 # c0100218 <g_version>
  c0000194: 00002517           auipc a0,0x2
  c0000198: cdc50513           add a0,a0,-804 # c0001e70 <_einit+0x140>
  c000019c: 04a000ef           jal c00001e6 <printf>

printf("Address of g_version=%p\n", g_version);
  c00001a0: 00100597           auipc a1,0x100
  c00001a4: 07858593           add a1,a1,120 # c0100218 <g_version>
  c00001a8: 00002517           auipc a0,0x2
  c00001ac: ce850513           add a0,a0,-792 # c0001e90 <_einit+0x160>
  c00001b0: 036000ef           jal c00001e6 <printf>

strlcpy(name->version,  g_version, sizeof(name->version));
  c00001b4: 03300613           li a2,51
  c00001b8: 00100597           auipc a1,0x100
  c00001bc: 06058593           add a1,a1,96 # c0100218 <g_version>
  c00001c0: 04a40513           add a0,s0,74
  c00001c4: 584000ef           jal c0000748 <strlcpy>
```

Which does 4 things...

1.  Call __\_info__ (a.k.a. __syslog__) to print __g_version__

1.  TODO

# uname is Not a Kernel Call

_Huh? Isn't this the exact same Kernel Code we saw earlier?_

Precisely! We expected __`uname`__ to be a [__NuttX Kernel Call__](TODO)...

TODO: Pic of kernel call

But nope, __`uname`__ is a __Local Function__.

Every NuttX App has a __Local Copy of g_version__ and Commit Hash. _(That's potentially corruptible hmmm...)_

That's why __printf__ appears in the Hello Output but not __\_info__...

```bash
TODO
## _info doesn't appear
```

(Because __\_info__ and __syslog__ won't work in NuttX Apps)

The full path of __`uname`__ is a dead giveaway: It's a __Library Function__, not a Kernel Function...

```text
libs/libc/misc/lib_utsname.c
```

[(`uname` is a __System Call in Linux__)](https://man7.org/linux/man-pages/man2/syscalls.2.html)

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

We have a hefty hunch that __Static Variables__ might be broken _(gasp)_. We test our hypothesis in __Hello App__: [hello_main.c](TODO)

```c
TODO
```

Our hunch is 100% correct: __Static Variables are Broken!__

```bash
TODO
```

[(See the __Complete Log__)](TODO)

OK this gets waaaaay beyond our debugging capability. _(NuttX App Data Section got mapped incorrectly into the Memory Space?)_

We call in the __NuttX Experts__ for help. And it's awesomely fixed by [__anjiahao__](https://github.com/anjiahao1) yay! 🎉

- [__Static Char Arrays are empty for NuttX Apps__](https://github.com/apache/nuttx/issues/15526)

- [__modlib: gnu-elf.ld.in load exe elf data section mismatch__](https://github.com/apache/nuttx/pull/15527)

__Lesson Learnt:__ Please pay attention to the slightest disturbance, like the __`uname`__ output. It might be a sign of something seriously sinister simmering under the surface!

# What's Next

Next Article: Why __Sync-Build-Ingest__ is super important for NuttX CI. And how we monitor it with our __Magic Disco Light__.

After That: Since we can __Rewind NuttX Builds__ and automatically __Git Bisect__... Can we create a Bot that will fetch the __Failed Builds from NuttX Dashboard__, identify the Breaking PR, and escalate to the right folks?

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.github.io/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.github.io)

- [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/uname.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/uname.md)
