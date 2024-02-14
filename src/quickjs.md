# QuickJS JavaScript Engine on a Real-Time Operating System (Apache NuttX RTOS)

📝 _20 Feb 2024_

![QuickJS JavaScript Engine on a Real-Time Operating System (Apache NuttX RTOS)](https://lupyuen.github.io/images/quickjs-title.png)

[(Try the __Online Demo__)](https://lupyuen.github.io/nuttx-tinyemu/quickjs/)

[(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

[__QuickJS__](https://github.com/bellard/quickjs) is a small __JavaScript Engine__ that supports [__POSIX Functions__](https://bellard.org/quickjs/quickjs.html#os-module).

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) is a tiny __Real-Time Operating System__ (for all kinds of devices) that's compatible with POSIX.

_Can we run QuickJS on NuttX? And Blink the LED in 4 lines of JavaScript?_

```javascript
// Blink the NuttX LED, on then off
const ULEDIOC_SETALL = 0x1d03;
const fd = os.open("/dev/userleds", os.O_WRONLY);
os.ioctl(fd, ULEDIOC_SETALL, 1);
os.ioctl(fd, ULEDIOC_SETALL, 0);
```

Let's do it! In this article we...

TODO

We go hands-on (fingers too)...

# QuickJS on NuttX Emulator

Click here to try __QuickJS JavaScript Engine__ in NuttX Emulator...

- [__QuickJS on Ox64 NuttX Emulator__](https://lupyuen.github.io/nuttx-tinyemu/quickjs)

  [(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

Now we do some Finger Exercises (sorry __copy-pasta won't work__ in the Emulator)

1.  To start QuickJS: Enter this at the __NSH Prompt__...

    ```bash
    qjs
    ```

1.  At the QuickJS Prompt: We define the __NuttX LED Command__...

    ```javascript
    ULEDIOC_SETALL = 0x1d03
    ```

1.  Next we open the __NuttX LED Device__ (write-only)...

    ```javascript
    fd = os.open("/dev/userleds", os.O_WRONLY)
    ```

1.  Watch what happens when we __Flip On the LED__...

    ```javascript    
    os.ioctl(fd, ULEDIOC_SETALL, 1)
    ```

    __GPIO 29__ (lower right) turns Green!

1.  Then we __Flip Off the LED__...

    ```javascript
    os.ioctl(fd, ULEDIOC_SETALL, 0)
    ```

    __GPIO 29__ goes back to normal!

1.  Our Demo goes like this...

    ```bash
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs
    QuickJS - Type "\h" for help

    ## Define the NuttX LED Command
    qjs > ULEDIOC_SETALL = 0x1d03
    7427

    ## Open the NuttX LED Device (write-only)
    qjs > fd = os.open("/dev/userleds", os.O_WRONLY)
    3

    ## Flip LED On: GPIO 29 turns Green...
    qjs > os.ioctl(fd, ULEDIOC_SETALL, 1)
    bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
    0

    ## Flip LED Off: GPIO 29 goes back to normal...
    qjs > os.ioctl(fd, ULEDIOC_SETALL, 0)
    bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
    0
    ```

    [(See the __Complete Log__)](https://github.com/lupyuen/quickjs-nuttx#quickjs-blinks-the-led-on-ox64-emulator)

    [(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

_Help! Our fingers are hurting..._

Try this instead...

```bash
nsh> qjs --std /system/bin/blink.js
```

[(See the __Blinky JavaScript__)](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/blink.js)

[(Option "__`--std`__" will import the __`os`__ functions)](https://bellard.org/quickjs/quickjs.html#qjs-interpreter)

_Wow... A Blinky in JavaScript?_

Yep we flipped this [__NuttX Blinky App__](TODO) from C to __Interactive JavaScript__!

_Does it work on Real Hardware?_

The exact same NuttX Image blinks a Real LED on [__Ox64 BL808 SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (64-bit RISC-V). Though it's a little sluggish, we'll come back to this.

How did we make this happen? Read on to find out...

TODO: Pic of Real LED

# Build QuickJS for NuttX

_QuickJS compiles OK for NuttX?_

Mostly. QuickJS compiles for NuttX __with no code changes__...

- [__"Build QuickJS for NuttX"__](TODO)

Then we hit some __Missing Functions__...

1.  __POSIX Functions:__ Special ones like popen, pclose, pipe2, symlink, ...

1.  __Dynamic Linking:__ dlopen, dlsym, dlclose

1.  __Math Functions:__ pow, floor, trunc, ...

1.  __Atomic Functions:__ atomic_fetch_add_2, ...

    [(See the __Missing Functions__)](https://github.com/lupyuen/quickjs-nuttx#fix-the-missing-functions)

_How did we fix the missing functions?_

1.  __POSIX Functions:__ The typical POSIX Functions are OK. The special ones are probably available if we tweak the __Build Options__ for NuttX. For now, we [__stubbed them out__](TODO).

1.  __Dynamic Linking:__ We won't support Dynamic Linking for NuttX. We [__stubbed them out__](TODO).

1.  __Math Functions:__ We linked them with GCC Option __`-lm`__. The last few stragglers: We [__stubbed them out__](TODO).

1.  __Atomic Functions:__ We patched in the [__Missing Atomic Functions__](TODO).

    [(About __NuttX Atomic Functions__)](https://github.com/apache/nuttx/issues/10642)

    [(We might __disable QuickJS Atomic Functions__)](TODO)

After these fixes, QuickJS builds OK for NuttX! We run it...

# NuttX Stack is Full of QuickJS

_We fixed the QuickJS Build for NuttX... Does it run?_

Sorry nope! QuickJS ran into [__Mysterious Crashes__](https://github.com/lupyuen/quickjs-nuttx#quickjs-crashes-on-nuttx) on NuttX (with looping Stack Traces)...

- [__Strange Pointers__](https://github.com/lupyuen/quickjs-nuttx#atom-sentinel-becomes-0xffff_ffff) (`0xFFFF_FFFF`) while reading the JavaScript Atoms

- [__Unexpected Characters__](https://github.com/lupyuen/quickjs-nuttx#unexpected-character-in-quickjs) (`0xFF`) appeared in our JavaScript Strings

- [__Malloc was Erasing__](https://github.com/lupyuen/quickjs-nuttx#malloc-problems-in-nuttx) our JavaScript Strings

- [__Heap Memory__](https://github.com/lupyuen/quickjs-nuttx#heap-errors-and-stdio-weirdness) got weirdly corrupted (even __printf()__ failed)

After plenty of headscratching troubleshooting, this [__Vital Clue__](https://github.com/lupyuen/quickjs-nuttx#nuttx-stack-is-full-of-quickjs) suddenly pops up...

```yaml
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0006d52, MTVAL: ffffffffffffffff
...
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x802002b0      2048      2040    99.6%!   irq
dump_task:       0     0   0 FIFO     Kthread - Ready              0000000000000000 0x80206010      3056      1856    60.7%    Idle_Task
dump_task:       1     1 100 RR       Kthread - Waiting Semaphore  0000000000000000 0x8020a050      1968       704    35.7%    lpwork 0x802015f0 0x80201618
dump_task:       2     2 100 RR       Task    - Waiting Semaphore  0000000000000000 0xc0202040      3008       744    24.7%    /system/bin/init
dump_task:       3     3 100 RR       Task    - Running            0000000000000000 0xc0202050      1968      1968   100.0%!   qjs }¼uq¦ü®઄²äÅ
```

The last line shows that the __QuickJS Stack__ (2 KB) was __100% Full__! (And the Command Line was badly messed up)

We follow these steps to [__increase the App Stack Size__](https://github.com/lupyuen/nuttx-star64#increase-stack-size)...

1.  Enter "__`make menuconfig`__"

1.  Select _"Library Routines > Program Execution Options"_

1.  Set _"Default task_spawn Stack Size"_ to __65536__

    (That's 64 KB)

1.  Select _"Library Routines > Thread Local Storage (TLS)"_

    [(Why we set __Thread Local Storage__)](https://github.com/lupyuen/quickjs-nuttx#fix-quickjs-interactive-mode-on-nuttx)

1.  Set _"Maximum stack size (log2)"_ to __16__

    (Because 2^16 = 64 KB)

Which becomes this in our __NuttX Build Config__: [ox64/nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/904b95534298378d64b99c1f9e649f8bc27a8048#diff-fa4b30efe1c5e19ba2fdd2216528406d85fa89bf3d2d0e5161794191c1566078)

```bash
CONFIG_POSIX_SPAWN_DEFAULT_STACKSIZE=65536
CONFIG_TLS_LOG2_MAXSTACK=16
```

(Lesson Learnt: If the NuttX Stack Dump loops forever, we're probably __Out Of Stack Space__)

# Add ioctl() to QuickJS

_ioctl() doesn't appear in the QuickJS Docs?_

```javascript
// Flip On the NuttX LED
const ULEDIOC_SETALL = 0x1d03;
const fd = os.open("/dev/userleds", os.O_WRONLY);
os.ioctl(fd, ULEDIOC_SETALL, 1);
```

That's because we added __ioctl()__ to QuickJS: [quickjs-libc.c](https://github.com/lupyuen/quickjs-nuttx/commit/91aaf4257992c08b01590f0d61fa37a386933a4b#diff-95fe784bea3e0fbdf30ba834b1a74b538090f4d70f4f8770ef397ef68ec37aa3)

```c
// List of JavaScript Functions in `os` Module
static const JSCFunctionListEntry js_os_funcs[] = {
  ...
  // Declare our ioctl() function...
  JS_CFUNC_DEF(
    "ioctl",     // Function Name
    3,           // Parameters
    js_os_ioctl  // Implemented here
  ),
};

// Define our ioctl() function
static JSValue js_os_ioctl(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
  int fd, req;       // ioctl() File Descriptor and Request Number
  int64_t arg, ret;  // ioctl() Parameter and Return Value
  BOOL is_bigint;    // True if we're using BigInt for 64-bit Integers
  
  // First Arg is ioctl() File Descriptor (int32)
  if (JS_ToInt32(ctx, &fd, argv[0]))
    return JS_EXCEPTION;
  
  // Second Arg is ioctl() Request Number (int32)
  if (JS_ToInt32(ctx, &req, argv[1]))
    return JS_EXCEPTION;

  // Third Arg is ioctl() Parameter (int64)
  // TODO: What if it's int32? How to pass a Pointer to Struct?
  is_bigint = JS_IsBigInt(ctx, argv[2]);
  if (JS_ToInt64Ext(ctx, &arg, argv[2]))
    return JS_EXCEPTION;

  // Call NuttX ioctl()
  ret = ioctl(fd, req, arg);
  if (ret == -1)
    ret = -errno;

  // Return the Result as 64-bit or 32-bit Integers
  if (is_bigint)
    return JS_NewBigInt64(ctx, ret);
  else
    return JS_NewInt64(ctx, ret);
}
```

Yep __ioctl()__ is alive...

```bash
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help

qjs > os.ioctl
function ioctl()

qjs > os.ioctl(1,2,3)
-25

qjs > os.ioctl(100,2,3)
-9
```

![Connect an LED to Ox64 SBC at GPIO 29, Pin 21](https://lupyuen.github.io/images/nim-wiring.jpg)

# QuickJS Blinks the LED on Ox64 SBC

_We added ioctl() to QuickJS... Does it work?_

We test __ioctl()__ on a Real Device with a Real LED: __Ox64 BL808 RISC-V SBC__. Right after these fixes...

- [__Add the GPIO Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/8f75f3744f3964bd3ed0596421a93e59fb39cdd8)  for Ox64 BL808

- [__Add the LED Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/4f3996959132ca0d35874b7be3eef89d6bf7f351) for Ox64 BL808

- [__Increase the App Stack Size__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/904b95534298378d64b99c1f9e649f8bc27a8048)  from 2 KB to 64 KB

  (Otherwise QuickJS will crash mysteriously)

- [__Increase the RAM Disk Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/28453790d06c0282b85e5df98624f8fa1c0b2226) from 16 MB to 40 MB

  [(Why we enlarge the __RAM Disk Region__)](https://github.com/lupyuen/quickjs-nuttx#add-led-driver-to-nuttx-ox64-bl808-sbc)

- [__Fix the `leds` app__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/66f1389c8d17eecdc5ef7baa62d13435bd053ee3) for testing LED Driver
 
  (Because __task_create()__ is missing from Kernel Mode)

Connect an LED to Ox64 SBC at __GPIO 29, Pin 21__ (pic above)...

| Connect | To | Wire |
|:-----|:---|:-----|
| __Ox64 Pin 21__ <br>_(GPIO 29)_ | __Resistor__ <br>_(47 Ohm)_ | Red |
| __Resistor__ <br>_(47 Ohm)_ | __LED +__ <br>_(Curved Edge)_ | Breadboard
| __LED -__ <br>_(Flat Edge)_ | __Ox64 Pin 23__ <br>_(GND)_ | Black 

[(See the __Ox64 Pinout__)](https://wiki.pine64.org/wiki/File:Ox64_pinout.png)

(Resistor is __47 Ohm__, yellow-purple-black-gold, almost Karma Chameleon)

Boot NuttX on Ox64. Enter these commands...

```bash
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help

## Define the NuttX LED Command
qjs > ULEDIOC_SETALL = 0x1d03
7427

## Open the NuttX LED Device (write-only)
qjs > fd = os.open("/dev/userleds", os.O_WRONLY)
3

## Flip LED to On
qjs > os.ioctl(fd, ULEDIOC_SETALL, 1)
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
0

## Flip LED to Off
qjs > os.ioctl(fd, ULEDIOC_SETALL, 0)
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
0
```

Yep __ioctl()__ works great on a Real Device, with a Real LED!

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: QuickJS blinks our LED](https://lupyuen.github.io/images/nim-blink2.jpg)

_If we don't have an Ox64 SBC?_

No worries, the exact same steps will work for __QEMU Emulator__ (64-bit RISC-V)...

- [__Add the LED Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/1037eda906f11aef44f7670f8cc5a1c1d2141911) for QEMU

- [__Fix the `leds` app__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/45dbe5ce07239e7ca7dcb50cb0e55da151052429) for testing LED Driver

- [__Build QuickJS__](TODO) for NuttX QEMU

TODO: QEMU Log

![QuickJS Code Size](https://lupyuen.github.io/images/quickjs-text.jpg)

# How Small is QuickJS

_Will QuickJS runs on all kinds of NuttX Devices?_

```bash
$ riscv64-unknown-elf-size apps/bin/qjs
   text    data     bss     dec     hex filename
 554847     260      94  555201   878c1 apps/bin/qjs
```

Probably not? JavaScript needs quite a bit of RAM to run efficiently.

We ran [linkermapviz](https://github.com/PromyLOPh/linkermapviz) on the Linker Map: [nuttx/qjs-riscv.map](nuttx/qjs-riscv.map)

To produce this [Visualised Linker Map](https://lupyuen.github.io/nuttx-tinyemu/quickjs/linkermap)

| Size of Code + Data (Read-Only) | |
|:--------------------|:---:
| QuickJS with All The Toppings | __554 KB__ |
| Without REPL | __538 KB__ |
| Without BigInt | __522 KB__ |
| Without BigInt, REPL | __506 KB__ |

![QuickJS Data Size](https://lupyuen.github.io/images/quickjs-data.jpg)

_What about the Heap Memory Size?_

Based on the NuttX Logs with Heap Logging Enabled...

- [Heap Log: Without REPL](https://github.com/lupyuen/quickjs-nuttx/blob/d2dbef1afef26ae4cc76719d7cac3740da5f3387/nuttx/qemu.log)

- [Heap Log: With REPL](https://github.com/lupyuen/quickjs-nuttx/blob/38e004e6eb643932f6957e03828ad25242cf803a/nuttx/qemu.log)

We compute the Heap Usage in a Spreadsheet...

- [Heap Usage: Without Repl](https://docs.google.com/spreadsheets/d/1EpdktueHxfAR4VR80d1XSZRwdO2UvNGf_sPetHHzAGQ/edit?usp=sharing)

  Max: 276 KB

- [Heap Usage: With Repl](https://docs.google.com/spreadsheets/d/1g0-O2qdgjwNfSIxfayNzpUN8mmMyWFmRf2dMyQ9a8JI/edit?usp=sharing)

  Max: 371 KB

  (__"Free Size"__ might not be accurate because it uses __VLOOKUP__ for Top-Down Lookup)

TODO: Static Linking

![QuickJS JavaScript Engine to Apache NuttX RTOS](https://lupyuen.github.io/images/quickjs-title2.png)

# Simulate the LED on Ox64 Emulator

_NuttX Emulator blinks a Simulated LED (pic above, lower right)..._

_How does it work?_

We modded NuttX Emulator (in WebAssembly) to...

1.  Watch for updates to __GPIO Registers__

    (Like `0x2000_0938` for GPIO 29)

1.  Notify the __Web Browser JavaScript__ of any updates

    (Like `{"nuttxemu":{"gpio29":1}}`)

1.  Web Browser JavaScript __Flips the Simulated LED__

    (On or Off)

![Simulate the LED on Ox64 Emulator](https://lupyuen.github.io/images/quickjs-led.jpg)

Here's our NuttX Emulator (WebAssembly) intercepting all __Writes to GPIO 29__: [riscv_cpu.c](https://github.com/lupyuen/ox64-tinyemu/blob/main/riscv_cpu.c#L486-L553)

```c
// WebAssembly called by TinyEmu to emulate
// Writes to RISC-V Addresses
int target_write_slow(...) {
  ...
  // Intercept Writes to Memory-Mapped I/O
  switch(paddr) {

    // If we're writing to BL808 GPIO 29 (0x2000_0938)...
    case 0x20000938: {
      // Send an Emulator Notification to the Console:
      // {"nuttxemu":{"gpio29":1}}

      // Check if the Output Bit is Off or On
      #define reg_gpio_xx_o 24
      #define reg_gpio_xx_i 28
      const char b =
        ((val & (1 << reg_gpio_xx_o)) == 0)
        ? '0' : '1';

      // Send the Notification to Console
      char notify[] = "{\"nuttxemu\":{\"gpio29\":0}}\r\n";
      notify[strlen(notify) - 5] = b;
      print_console(NULL, notify, strlen(notify));
    }
```

Which sends a Notification to the Web Browser (JavaScript), saying that the __GPIO Output has changed__...

```json
{"nuttxemu":
  {"gpio29": 1}
}
```

Our Web Browser (JavaScript) receives the Notification and __Flips the Simulated LED__: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/term.js#L487-L507)

```javascript
// JavaScript called by our WebAssembly
// to print something to Console
Term.prototype.write = function(str) {

  // If this is a Notification JSON from Emulator WebAssembly:
  // {"nuttxemu":{"gpio29":1}}
  if (str.indexOf(`{"nuttxemu":`) == 0) {
    
    // Get the GPIO Number and GPIO Value from JSON
    const notify = JSON.parse(str).nuttxemu;  // {gpio29:1}
    const gpio = Object.keys(notify)[0];  // "gpio29"
    const val = notify[gpio];  // 0 or 1

    // Render the GPIO in HTML:
    // <td id="gpio29" class="gpio_on">GPIO29</td>
    document.getElementById("status").style.width = document.getElementById("term_wrap").style.width;  // Spread out the GPIO Status
    const gpio_status = document.getElementById(gpio);
    gpio_status.style.display = "block";
    gpio_status.className = (val == 0)
      ? "gpio_off"  // Normal CSS Style
      : "gpio_on";  // Green CSS Style
    return;
  }
```

[(__status__ and __gpio29__ are in HTML)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/index.html#L21-L29)

[(__gpio_off__ and __gpio_on__ are in CSS)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/style.css#L106-L117)

TODO

[(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

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

[__lupyuen.github.io/src/quickjs.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/quickjs.md)

# Appendix: Build QuickJS for NuttX

TODO

From the [Makefile Log](nuttx/make.log)...

```bash
## Build qjs.o
gcc \
  -g \
  -Wall \
  -MMD \
  -MF .obj/qjs.o.d \
  -Wno-array-bounds \
  -Wno-format-truncation \
  -fwrapv  \
  -D_GNU_SOURCE \
  -DCONFIG_VERSION=\"2024-01-13\" \
  -DCONFIG_BIGNUM \
  -O2 \
  -c \
  -o .obj/qjs.o \
  qjs.c

## Omitted: Build a bunch of other binaries

## Link them together
gcc \
  -g \
  -rdynamic \
  -o qjs \
  .obj/qjs.o \
  .obj/repl.o \
  .obj/quickjs.o \
  .obj/libregexp.o \
  .obj/libunicode.o \
  .obj/cutils.o \
  .obj/quickjs-libc.o \
  .obj/libbf.o \
  .obj/qjscalc.o \
  -lm \
  -ldl \
  -lpthread
```

Let's do the same for NuttX. From [tcc-riscv32-wasm](https://github.com/lupyuen/tcc-riscv32-wasm) we know that NuttX builds NuttX Apps like this...

```bash
$ cd ../apps
$ make --trace import

## Compile hello app
## For riscv-none-elf-gcc: "-march=rv64imafdc_zicsr_zifencei"
## For riscv64-unknown-elf-gcc: "-march=rv64imafdc"
riscv-none-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Wno-attributes \
  -Wno-unknown-pragmas \
  -Wno-psabi \
  -fno-common \
  -pipe  \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mcmodel=medany \
  -march=rv64imafdc_zicsr_zifencei \
  -mabi=lp64d \
  -isystem apps/import/include \
  -isystem apps/import/include \
  -D__NuttX__  \
  -I "apps/include"   \
  hello_main.c \
  -o  hello_main.c.workspaces.bookworm.apps.examples.hello.o

## Link hello app
## For riscv-none-elf-ld: "rv64imafdc_zicsr/lp64d"
## For riscv64-unknown-elf-ld: "rv64imafdc/lp64d
riscv-none-elf-ld \
  --oformat elf64-littleriscv \
  -e _start \
  -Bstatic \
  -Tapps/import/scripts/gnu-elf.ld \
  -Lapps/import/libs \
  -L "xpack-riscv-none-elf-gcc-13.2.0-2/lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d" \
  apps/import/startup/crt0.o  \
  hello_main.c.workspaces.bookworm.apps.examples.hello.o \
  --start-group \
  -lmm \
  -lc \
  -lproxies \
  -lgcc apps/libapps.a xpack-riscv-none-elf-gcc-13.2.0-2/lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a \
  --end-group \
  -o  apps/bin/hello
```

We'll do the same for QuickJS (and worry about the Makefile later).

Here's our Build Script for QuickJS NuttX: [nuttx/build.sh](nuttx/build.sh)

But `repl.c` and `qjscalc.c` are missing! They are generated by the QuickJS Compiler! From [nuttx/make.log](nuttx/make.log)

```bash
./qjsc -c -o repl.c -m repl.js
./qjsc -fbignum -c -o qjscalc.c qjscalc.js
```

Let's borrow them from the QuickJS Build: [nuttx/repl.c](nuttx/repl.c) and [nuttx/qjscalc.c](nuttx/qjscalc.c)

_What's inside the files?_

Some JavaScript Bytecode. Brilliant! From [nuttx/repl.c](nuttx/repl.c)

```c
/* File generated automatically by the QuickJS compiler. */
#include <inttypes.h>
const uint32_t qjsc_repl_size = 16280;
const uint8_t qjsc_repl[16280] = {
 0x02, 0xa5, 0x03, 0x0e, 0x72, 0x65, 0x70, 0x6c,
 0x2e, 0x6a, 0x73, 0x06, 0x73, 0x74, 0x64, 0x04,
```

TODO: https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/qemuled-1

TODO: https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/gpio2-1

# Appendix: Build NuttX for QEMU

TODO

In this article, we compiled a Work-In-Progress Version of __Apache NuttX RTOS for QEMU RISC-V (64-bit)__ that has Minor Fixes for Nim...

- [__nsh64/defconfig__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-dd54e0076f30825f912248f2424460e3126c2a8f4e2880709f5c68af9342ddcf): NuttX Config for QEMU

- [__qemu_rv_autoleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-5905dc63d5fd592e0a1e25ab25783ae99e54180a7b98fb59f56a73dee79104e6)
: Auto LED Driver for QEMU

- [__qemu_rv_userleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-a6fd389669ddef88302f00a34d401479886cb8983f7be58b32ba075699cb5bb8): User LED Driver for QEMU

- [__qemu_rv_appinit.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-beeaeb03fa5642002a542446c89251c9a7c5c1681cfe915387740ea0975e91b3): Start LED Driver

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

First we install [__Nim Compiler__](https://nim-lang.org/install_unix.html) (only the Latest Dev Version supports NuttX)...

```bash
## Install Nim Compiler: https://nim-lang.org/install_unix.html
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

## Add Nim to PATH
export PATH=$HOME/.nimble/bin:$PATH

## Select Latest Dev Version of Nim. Will take a while!
choosenim devel --latest

## Version should be 2.1.1 or later:
## Nim Compiler Version 2.1.1 [Linux: amd64]
## Compiled at 2023-12-22
nim -v
```

[(Nim won't install? Try a __Linux Container__)](https://github.com/lupyuen/nuttx-nim#build-nuttx-with-debian-container-in-vscode)

Then we download and build NuttX for __QEMU RISC-V (64-bit)__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for QEMU RISC-V (64-bit)
cd nuttx
tools/configure.sh rv-virt:nsh64

## Build NuttX
make

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

TODO: [(See the __Build Script__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

TODO: [(See the __Build Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa)

TODO: [(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

This produces the NuttX ELF Image __`nuttx`__ that we may boot on QEMU RISC-V Emulator...

```bash
## Start the QEMU RISC-V Emulator (64-bit) with NuttX RTOS
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

At the NuttX Prompt, enter "__hello_nim__"...

```text
nsh> hello_nim
Hello Nim!
Opening /dev/userleds
```

[(Enter "__help__" to see the available commands)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L472-L497)

Nim on NuttX blinks our __Simulated LED__...

```text
Set LED 0 to 1
board_userled_all: led=0, val=1
Waiting...

Set LED 0 to 0
board_userled_all: led=0, val=0
Waiting...

Set LED 0 to 1
board_userled_all: led=0, val=1
Waiting...
```

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa#file-qemu-nuttx-nim-build-log-L210-L471)

To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

_How to run our own Nim Code on NuttX?_

Locate this __Nim Source File__ and replace by our own Nim Code...

```text
apps/examples/hello_nim/hello_nim_async.nim
```

Then rebuild and restart NuttX.

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: Works great with Nim!](https://lupyuen.github.io/images/nim-ox64.png)

# Appendix: Build NuttX for Ox64

TODO

In this article, we compiled a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__ that has Minor Fixes for Nim...

- [__nsh/defconfig__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-fa4b30efe1c5e19ba2fdd2216528406d85fa89bf3d2d0e5161794191c1566078): NuttX Config for Ox64

- [__bl808_timerisr.c__](https://lupyuen.github.io/articles/nim#appendix-opensbi-timer-for-nuttx): RISC-V Timer for Ox64

- [__bl808_autoleds.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-efdf5ed87983905c7021de03a7add73932da529d4312b80f948eb199c256b170): Auto LED Driver for Ox64

- [__bl808_userleds.c__](https://lupyuen.github.io/articles/nim#led-driver-for-ox64): User LED Driver for Ox64

- [__bl808_appinit.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/47/files#diff-902a3cb106dc7153d030370077938ef28c9412d8b3434888fca8bbf1a1cfbd54): Start LED Driver for Ox64

- [__Makefile__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-7fb4194c7b9e7b17a2a650d4182f39fb0e932cc9bb566e9b580d22fa8a7b4307): Nimcache has moved 2 folders up

- [__config.nims__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/pull/3/files#diff-be274e89063d9377278fad5fdcdd936e89d2f32efd7eb8eb8a6a83ac4c711879): Add support for 64-bit RISC-V

First we install [__Nim Compiler__](https://nim-lang.org/install_unix.html) (only the Latest Dev Version supports NuttX)...

```bash
## Install Nim Compiler: https://nim-lang.org/install_unix.html
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

## Add Nim to PATH
export PATH=$HOME/.nimble/bin:$PATH

## Select Latest Dev Version of Nim. Will take a while!
choosenim devel --latest

## Version should be 2.1.1 or later:
## Nim Compiler Version 2.1.1 [Linux: amd64]
## Compiled at 2023-12-22
nim -v
```

[(Nim won't install? Try a __Linux Container__)](https://github.com/lupyuen/nuttx-nim#build-nuttx-with-debian-container-in-vscode)

Then we download and build NuttX for __Ox64 BL808 SBC__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for Ox64 BL808 RISC-V SBC
cd nuttx
tools/configure.sh ox64:nsh

## Build NuttX
make

## Export the NuttX Kernel
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## Dump the hello_nim disassembly to hello_nim.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin/hello_nim \
  >hello_nim.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

We build the __Initial RAM Disk__ that contains NuttX Shell and NuttX Apps...

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.pad

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image
```

TODO: [(See the __Build Script__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)

TODO: [(See the __Build Log__)](https://gist.github.com/lupyuen/578a7eb2d4d827aa252fff37c172dd18)

TODO: [(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/ox64-1)

This produces the NuttX Image for Ox64: __`Image`__

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

And we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Copy the __`Image`__ file (from above) and overwrite the __`Image`__ in the Linux microSD...

```bash
## Overwrite the Linux Image
## on Ox64 microSD
cp Image \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH).
