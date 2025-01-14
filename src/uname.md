# Fixing a uname bug (Apache NuttX RTOS)

📝 _30 Jan 2025_

![TODO](https://lupyuen.github.io/images/uname-title.png)

[__`uname`__](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-13) became unusually quieter on [__Apache NuttX RTOS__](TODO)...

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

Noooooo! Commit Hash identifies the __Exact Commit of NuttX__ (pic above) that was used to produce the NuttX Build. _(Apps Hash would be helpful too)_

Watch as we stomp this seemingly simple bug... That turns out to be __something seriously sinister__! _(Spoiler: Static Vars are broken)_

# Inside uname

_uname command: How does it work?_

To solve our mystery: First we understand what's inside the __`uname`__ command.

Our bug happens in __NuttX Shell__. Thus we search the [__NuttX Apps Repo__](TODO) for __`uname`__...

TODO: Pic of uname search

[__Our search for `uname`__](https://github.com/search?q=repo%3Aapache%2Fnuttx-apps%20uname&type=code) returns this code in NuttX Shell: [nsh_syscmds.c](https://github.com/apache/nuttx-apps/blob/master/nshlib/nsh_syscmds.c#L771)

```c
TODO
```

We see that __`uname` command__ calls the __`uname` function__.

We search the [__NuttX Kernel Repo__](TODO) for __`uname`__...

TODO: Pic of uname search

[__NuttX Kernel Search__](https://github.com/search?q=repo%3Aapache%2Fnuttx%20uname&type=code) says that __uname__ is defined here: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L93)

```c
TODO
```

But is __uname__ a __Kernel Function__? We'll find out in a bit!

# CONFIG_VERSION_BUILD

_What's this CONFIG_VERSION_BUILD?_

We saw earlier that __`uname`__ function returns __CONFIG_VERSION_BUILD__: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L93)

```c
TODO
```

Let's track the origin of __CONFIG_VERSION_BUILD__. We build NuttX for [__QEMU RISC-V 64-bit__](TODO)...

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

Aha! __CONFIG_VERSION_BUILD__ comes from __version.h__...

```bash
$ cat include/nuttx/version.h 
#define CONFIG_VERSION_BUILD "a2d4d74af7"
...
```

[(Thanks to TODO for porting the docs!)](TODO)

# Static Variable g_version

_CONFIG_VERSION_BUILD looks OK. But is it compiled correctly into the NuttX Image?_

Let's snoop the __NuttX Kernel Image__ to be sure that __CONFIG_VERSION_BUILD__ is correct.

We see that __CONFIG_VERSION_BUILD__ is stored in a Static Variable __g_version__: [lib_utsname.c](https://github.com/apache/nuttx/blob/master/libs/libc/misc/lib_utsname.c#L53-L113)

```c
// CONFIG_VERSION_BUILD goes inside Static Var g_version
static char g_version[] = CONFIG_VERSION_BUILD;

// g_version goes into uname output
int uname(FAR struct utsname *name) { ...
  strlcpy(name->version, g_version, sizeof(name->version));
```

According to __NuttX Linker Map__: The address of __g_version__ is __`0x8040` `03B8`__...

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

(Because NuttX Kernel loads at [__`0x8020` `0000`__](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel.script#L24-L26))

![TODO](https://lupyuen.github.io/images/uname-hex1.png)

And that's our __CONFIG_VERSION_BUILD__! Looks hunky dory, why wasn't it returned correctly to __uname__ and NuttX Shell?

# TODO

```text
Call uname like https://github.com/apache/nuttx-apps/blob/master/nshlib/nsh_syscmds.c#L771
#include <sys/utsname.h>
  struct utsname info;
  ret = uname(&info);

Call uname
https://github.com/lupyuen2/wip-nuttx-apps/blob/uname/examples/hello/hello_main.c#L43-L53

knsh64:
https://gist.github.com/lupyuen/ee3eee9752165bee8f3e60d57c224372#file-special-qemu-riscv-knsh64-log-L1410
NuttShell (NSH) NuttX-12.8.0
nsh> hello
Hello, World!!
ret=0
sysname=NuttX
nodename=
release=12.8.0
version=
machine=risc-v

print in kernel:
https://github.com/lupyuen2/wip-nuttx/blob/uname/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L121
https://github.com/lupyuen2/wip-nuttx/blob/uname/libs/libc/misc/lib_utsname.c#L109

ABC
uname: From _info: g_version=c3330b17c7e-dirty Jan 13 2025 11:49:41
From printf: g_version=c3330b17c7e-dirty Jan 13 2025 11:49:41
board_app_initialize: version=c3330b17c7e-dirty Jan 13 2025 11:49:41

NuttShell (NSH) NuttX-12.7.0
nsh> hello
Hello, World!!
From printf: g_version=
ret=0
sysname=NuttX
nodename=
release=12.7.0
version=
machine=risc-v
nsh> 

nuttx/hello.S

➜  apps git:(uname) $ touch examples/hello/hello_main.c
➜  apps git:(uname) $ make import V=1
LD:  /Users/luppy/riscv/apps/bin/hello 
riscv-none-elf-ld -e main --oformat elf64-littleriscv -T /Users/luppy/riscv/nuttx/libs/libc/modlib/gnu-elf.ld -e __start -Bstatic -T/Users/luppy/riscv/apps/import/scripts/gnu-elf.ld  -L/Users/luppy/riscv/apps/import/libs -L "/Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" /Users/luppy/riscv/apps/import/startup/crt0.o  hello_main.c.Users.luppy.riscv.apps.examples.hello.o --start-group -lmm -lc -lproxies -lgcc /Users/luppy/riscv/apps/libapps.a /Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a --end-group -o  /Users/luppy/riscv/apps/bin/hello

chmod +x /Users/luppy/riscv/apps/bin/hello
mkdir -p /Users/luppy/riscv/apps/bin_debug
cp /Users/luppy/riscv/apps/bin/hello /Users/luppy/riscv/apps/bin_debug
riscv-none-elf-strip --strip-unneeded /Users/luppy/riscv/apps/bin/hello

LD:  /Users/luppy/riscv/apps/bin/hello 
riscv-none-elf-ld \
  -e main \
  --oformat elf64-littleriscv \
  -T /Users/luppy/riscv/nuttx/libs/libc/modlib/gnu-elf.ld \
  -e __start \
  -Bstatic \
  -T/Users/luppy/riscv/apps/import/scripts/gnu-elf.ld  \
  -L/Users/luppy/riscv/apps/import/libs \
  -L "/Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" /Users/luppy/riscv/apps/import/startup/crt0.o  hello_main.c.Users.luppy.riscv.apps.examples.hello.o \
  --start-group \
  -lmm \
  -lc \
  -lproxies \
  -lgcc /Users/luppy/riscv/apps/libapps.a /Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a \
  --end-group \
  -o  /Users/luppy/riscv/apps/bin/hello

➜  apps git:(uname) $ ls -l /Users/luppy/riscv/apps/bin/hello
-rwxr-xr-x  1 luppy  staff  14048 Jan 13 11:32 /Users/luppy/riscv/apps/bin/hello
➜  apps git:(uname) $ 
cd examples/hello
 hello git:(uname) $ riscv-none-elf-ld \
  -e main \
  --oformat elf64-littleriscv \
  -T /Users/luppy/riscv/nuttx/libs/libc/modlib/gnu-elf.ld \
  -e __start \
  -Bstatic \
  -T/Users/luppy/riscv/apps/import/scripts/gnu-elf.ld  \
  -L/Users/luppy/riscv/apps/import/libs \
  -L "/Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" /Users/luppy/riscv/apps/import/startup/crt0.o  hello_main.c.Users.luppy.riscv.apps.examples.hello.o \
  --start-group \
  -lmm \
  -lc \
  -lproxies \
  -lgcc /Users/luppy/riscv/apps/libapps.a /Users/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a \
  --end-group \
  -o  /Users/luppy/riscv/apps/bin/hello
➜  hello git:(uname) $ ls -l /Users/luppy/riscv/apps/bin/hello
-rwxr-xr-x  1 luppy  staff  170928 Jan 13 11:35 /Users/luppy/riscv/apps/bin/hello
➜  hello git:(uname) $ 
cd nuttx
  riscv-none-elf-objdump \
    --syms --source --reloc --demangle --line-numbers --wide \
    --debugging \
    ../apps/bin/hello \
    >hello.S \
    2>&1

/Users/luppy/riscv/nuttx/hello.S
https://gist.github.com/lupyuen/f65565ba2fd825ae4226d2aee8a63c94

https://gist.github.com/lupyuen/877498cf437618b3b70ba57e59860cfe#file-hello-s-L356-L430

00000000c00000ba <uname>:
uname():
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:95
 *   Otherwise, -1 will be returned and errno set to indicate the error.
 *
 ****************************************************************************/

int uname(FAR struct utsname *name)
{
    c00000ba:	1101                	add	sp,sp,-32
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:100
  int ret = 0;

  /* Copy the strings.  Assure that each is NUL terminated. */

  strlcpy(name->sysname, "NuttX", sizeof(name->sysname));
    c00000bc:	4655                	li	a2,21
    c00000be:	00002597          	auipc	a1,0x2
    c00000c2:	c5a58593          	add	a1,a1,-934 # c0001d18 <_einit+0x74>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:95
{
    c00000c6:	ec06                	sd	ra,24(sp)
    c00000c8:	e822                	sd	s0,16(sp)
    c00000ca:	e426                	sd	s1,8(sp)
    c00000cc:	842a                	mv	s0,a0
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:100
  strlcpy(name->sysname, "NuttX", sizeof(name->sysname));
    c00000ce:	5ee000ef          	jal	c00006bc <strlcpy>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:104

  /* Get the hostname */

  ret = gethostname(name->nodename, HOST_NAME_MAX);
    c00000d2:	02000593          	li	a1,32
    c00000d6:	01540513          	add	a0,s0,21
    c00000da:	30b010ef          	jal	c0001be4 <gethostname>
    c00000de:	84aa                	mv	s1,a0
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:105
  name->nodename[HOST_NAME_MAX - 1] = '\0';
    c00000e0:	02040a23          	sb	zero,52(s0)
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:107

  strlcpy(name->release,  CONFIG_VERSION_STRING, sizeof(name->release));
    c00000e4:	4655                	li	a2,21
    c00000e6:	00002597          	auipc	a1,0x2
    c00000ea:	c3a58593          	add	a1,a1,-966 # c0001d20 <_einit+0x7c>
    c00000ee:	03540513          	add	a0,s0,53
    c00000f2:	5ca000ef          	jal	c00006bc <strlcpy>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:109

  _info("From _info: g_version=%s\n", g_version); //// TODO
    c00000f6:	00100697          	auipc	a3,0x100
    c00000fa:	10a68693          	add	a3,a3,266 # c0100200 <g_version>
    c00000fe:	00002617          	auipc	a2,0x2
    c0000102:	e0260613          	add	a2,a2,-510 # c0001f00 <__FUNCTION__.0>
    c0000106:	00002597          	auipc	a1,0x2
    c000010a:	c2258593          	add	a1,a1,-990 # c0001d28 <_einit+0x84>
    c000010e:	4519                	li	a0,6
    c0000110:	62c000ef          	jal	c000073c <syslog>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:110
  printf("From printf: g_version=%s\n", g_version); //// TODO
    c0000114:	00100597          	auipc	a1,0x100
    c0000118:	0ec58593          	add	a1,a1,236 # c0100200 <g_version>
    c000011c:	00002517          	auipc	a0,0x2
    c0000120:	c2c50513          	add	a0,a0,-980 # c0001d48 <_einit+0xa4>
    c0000124:	036000ef          	jal	c000015a <printf>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:111
  strlcpy(name->version,  g_version, sizeof(name->version));
    c0000128:	03300613          	li	a2,51
    c000012c:	00100597          	auipc	a1,0x100
    c0000130:	0d458593          	add	a1,a1,212 # c0100200 <g_version>
    c0000134:	04a40513          	add	a0,s0,74
    c0000138:	584000ef          	jal	c00006bc <strlcpy>
/Users/luppy/riscv/nuttx/libs/libc/misc/lib_utsname.c:113


  nuttx git:(uname) ✗ $ make distclean
➜  nuttx git:(uname) ✗ $ tools/configure.sh milkv_duos:nsh
make
relink hello
  riscv-none-elf-objdump \
    --syms --source --reloc --demangle --line-numbers --wide \
    --debugging \
    ../apps/bin/hello \
    >hello.S \
    2>&1

hello-sg2000.S:
https://gist.github.com/lupyuen/910061a54afeddc875ae3b227ab18f0f

Static Variables don't seem to work correctly for rv-virt:knsh64, wonder if there's a problem with the Linking of Static Vars?
https://github.com/apache/nuttx/pull/15444#issuecomment-2586160111

Why this PR?
Because uname was working before:
https://gist.github.com/lupyuen/489af50d987c94e2cda54d927a8ea4f3#file-special-qemu-riscv-knsh64-log-L1398-L1399

Call in The Experts for help. And fixed by anjiahao!
https://github.com/anjiahao1

[BUG] Static Char Arrays are empty for NuttX Apps compiled for rv-virt:knsh and knsh64 #15526
https://github.com/apache/nuttx/issues/15526

modlib:gnu-elf.ld.in load exe elf data section mismatch #15527
https://github.com/apache/nuttx/pull/15527

Lesson Learnt: Please pay attention to the slightest disturbances, like the `uname` output. It might be hiding something seriously sinister!

https://github.com/apache/nuttx/pull/15501
riscv/Toolchain.defs: guard -r use #15501

https://github.com/apache/nuttx/pull/15444
modlib: preprocess gnu-elf.ld for executable ELF #15444


But not sg2000
https://github.com/lupyuen/nuttx-sg2000/releases/tag/nuttx-sg2000-2025-01-13
nsh> uname -a
NuttX 12.8.0 5f4a15b690 Jan 13 2025 00:17:37 risc-v milkv_duos
```


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
