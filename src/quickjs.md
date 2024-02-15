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

- Run QuickJS on __Ox64 BL808 RISC-V SBC__

- Blink the LED by adding the __ioctl() function__

- Reconfigure the __NuttX App Stack__ because it's too tiny

- Analyse the __Memory Footprint__ of QuickJS (Code + Data + Heap Size)

- Test QuickJS on __NuttX WebAssembly Emulator__ (with a Simulated LED)

QuickJS is perfect for Iterative, Interactive Experiments on NuttX! We go hands-on (fingers too)...

![QuickJS JavaScript Engine in Ox64 NuttX Emulator](https://lupyuen.github.io/images/quickjs-title2.png)

# QuickJS on NuttX Emulator

Click here to try __QuickJS JavaScript Engine__ in NuttX Emulator (pic above)...

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

    [(About __ULEDIOC_SETALL__)](https://lupyuen.github.io/articles/nim#blink-an-led)

1.  Next we open the __NuttX LED Device__ (write-only)...

    ```javascript
    fd = os.open("/dev/userleds", os.O_WRONLY)
    ```

1.  Watch what happens when we __Flip On the LED__...

    ```javascript    
    os.ioctl(fd, ULEDIOC_SETALL, 1)
    ```

    __GPIO 29__ (pic above, lower right) turns Green!

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

    ## Flip LED On: GPIO 29 turns Green
    qjs > os.ioctl(fd, ULEDIOC_SETALL, 1)
    bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
    0

    ## Flip LED Off: GPIO 29 goes back to normal
    qjs > os.ioctl(fd, ULEDIOC_SETALL, 0)
    bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
    0
    ```

    [(See the __Complete Log__)](https://github.com/lupyuen/quickjs-nuttx#quickjs-blinks-the-led-on-ox64-emulator)

    [(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

_Erm our fingers are hurting?_

Try this __Non-Interactive JavaScript__ with QuickJS...

```bash
nsh> qjs --std /system/bin/blink.js
```

[(See the __Blinky JavaScript__)](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/blink.js)

[(Option "__`--std`__" will import the __`os`__ functions)](https://bellard.org/quickjs/quickjs.html#qjs-interpreter)

_Wow... A Blinky in JavaScript?_

Yep we flipped this [__NuttX Blinky App__](https://github.com/lupyuen/quickjs-nuttx#quickjs-calls-nuttx-led-driver) from C to __Interactive JavaScript__!

_Does it work on Real Hardware?_

The exact same QuickJS blinks a Real LED on [__Ox64 BL808 SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (64-bit RISC-V). Though it's a little sluggish, we'll come back to this.

How did we make this happen? Read on to find out...

![Auto-Test QuickJS with Expect Scripting](https://lupyuen.github.io/images/quickjs-expect.png)

[_Auto-Test QuickJS with Expect Scripting_](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/qemu.exp)

# Build QuickJS for NuttX

_QuickJS compiles OK for NuttX?_

Mostly. QuickJS compiles for NuttX __with no code changes__...

- [__"Build QuickJS for NuttX"__](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

Then we hit some __Missing Functions__...

1.  __POSIX Functions:__ _popen, pclose, pipe2, symlink, ..._

1.  __Dynamic Linking:__ _dlopen, dlsym, dlclose_

1.  __Math Functions:__ _pow, floor, trunc, ..._

1.  __Atomic Functions:__ _atomic_fetch_add_2, atomic_fetch_or_1, ..._

    [(See the __Missing Functions__)](https://github.com/lupyuen/quickjs-nuttx#fix-the-missing-functions)

_How to fix the missing functions?_

1.  __POSIX Functions:__ The typical POSIX Functions are OK. The special ones are probably available if we tweak the __Build Options__ for NuttX.

    For now, we stick with the Basic NuttX Config and stub out the [__Advanced POSIX Functions__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/stub.c).

1.  __Dynamic Linking:__ We won't support Dynamic Linking for NuttX. We [__stubbed the missing functions__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/stub.c).

1.  __Math Functions:__ We linked them with GCC Option "__`-lm`__". The last few stragglers: We [__stubbed the functions__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/stub.c).

1.  __Atomic Functions:__ We patched in the [__Missing Atomic Functions__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/arch_atomic.c#L32-L743).

    [(About __NuttX Atomic Functions__)](https://github.com/apache/nuttx/issues/10642)

    [(We might __Disable Atomic Functions__)](https://github.com/lupyuen/quickjs-nuttx/blob/master/quickjs.c#L67-L73)

After these fixes, QuickJS builds OK for NuttX!

[(How to build __QuickJS for NuttX__)](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

_That's plenty of fixing. Will it break QuickJS?_

Thankfully we have __Automated Testing__ with an Expect Script (pic above): [qemu.exp](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/qemu.exp)

```bash
#!/usr/bin/expect
## Expect Script for Testing QuickJS with QEMU Emulator

## For every 1 character sent, wait 0.001 milliseconds
set send_slow {1 0.001}

## Start NuttX on QEMU Emulator
spawn qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic

## Wait for the prompt and enter this command
expect "nsh> "
send -s "qjs -e console.log(123) \r"

## Check the response...
expect {
  ## If we see this message, exit normally
  "nsh>" { exit 0 }

  ## If timeout, exit with an error
  timeout { exit 1 }
}
```

Before the Auto-Test, we fix the Auto-Crash...

![Loopy Stack Trace probably means Stack Full](https://lupyuen.github.io/images/quickjs-stack.png)

[_Loopy Stack Trace probably means Stack Full_](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5385-L5478)

# NuttX Stack is Full of QuickJS

_We fixed the QuickJS Build for NuttX... Does it run?_

Sorry nope! QuickJS ran into [__Bizarre Crashes__](https://github.com/lupyuen/quickjs-nuttx#quickjs-crashes-on-nuttx) on NuttX (with looping Stack Traces, pic above)...

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

__Lesson Learnt:__ If the NuttX Stack Dump loops forever, we're probably __Out Of Stack Space__.

![POSIX Functions in QuickJS](https://lupyuen.github.io/images/quickjs-posix.png)

[_POSIX Functions in QuickJS_](https://bellard.org/quickjs/quickjs.html#os-module)

# Add ioctl() to QuickJS

_ioctl() doesn't appear in the QuickJS Docs? (Pic above)_

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

After adding this code to QuickJS, __ioctl()__ comes to life...

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

Next we test __ioctl()__...

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

[(Or run the __Blinky JavaScript__)](https://gist.github.com/lupyuen/f879aa3378aa1b0170a1d3ea2b0b9d67)

Yep __ioctl()__ works great on a Real Device, with a Real LED!

![Apache NuttX RTOS on Ox64 BL808 RISC-V SBC: QuickJS blinks our LED](https://lupyuen.github.io/images/nim-blink2.jpg)

_If we don't have an Ox64 SBC?_

No worries, the exact same steps will work for __QEMU Emulator__ (64-bit RISC-V)...

- [__Add the LED Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/1037eda906f11aef44f7670f8cc5a1c1d2141911) for QEMU

- [__Increase the App Stack Size__](https://github.com/apache/nuttx/commit/3b662696aff4b89e2b873a6b75d0006860fc9f7b)  from 2 KB to 64 KB

- [__Fix the `leds` app__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/45dbe5ce07239e7ca7dcb50cb0e55da151052429) for testing LED Driver

Check out the instructions...

- [__"Build NuttX for QEMU"__](https://lupyuen.github.io/articles/quickjs#appendix-build-nuttx-for-qemu)

- [__"Build QuickJS for NuttX QEMU"__](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

QuickJS for NuttX QEMU blinks a __Simulated LED__...

```text
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs --std /system/bin/blink.js
led=0, val=1
led=0, val=0
led=0, val=1
```

To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

[(See the __Complete Log__)](https://gist.github.com/lupyuen/a3d2a491112eaf5810edc1fa355606db)

![QuickJS Code Size rendered with linkermapviz](https://lupyuen.github.io/images/quickjs-text.jpg)

[_QuickJS Code Size rendered with linkermapviz_](https://lupyuen.github.io/nuttx-tinyemu/quickjs/linkermap)

# How Small is QuickJS

_Will QuickJS run on all kinds of NuttX Devices?_

```bash
$ riscv64-unknown-elf-size apps/bin/qjs
   text    data     bss     dec     hex filename
 554847     260      94  555201   878c1 apps/bin/qjs
```

Probably not? JavaScript needs __quite a bit of RAM__ to run comfortably.

We ran [__linkermapviz__](https://github.com/PromyLOPh/linkermapviz) on the [__QuickJS Linker Map__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/qjs-riscv.map) for NuttX QEMU...

```bash
## Visualise the QuickJS Linker Map for NuttX QEMU.
## Produces linkermap.html: https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/linkermap.html

git clone https://github.com/PromyLOPh/linkermapviz
cd linkermapviz
pip3 install .
linkermapviz < quickjs-nuttx/nuttx/qjs-riscv.map
```

Which produces the [__Visualised Linker Map__](https://lupyuen.github.io/nuttx-tinyemu/quickjs/linkermap) for QuickJS. (Pics above and below)

Here are the sizes of QuickJS and its options...

| Size of Code + Data (Read-Only) | |
|:--------------------|:---:
| QuickJS with All The Toppings | __554 KB__ |
| Without REPL | __538 KB__ |
| Without BigInt | __522 KB__ |
| Without BigInt, REPL | __506 KB__ |

[(__REPL__ is for Interactive Commands)](https://bellard.org/quickjs/quickjs.html#Quick-start)

[(__BigInt__ is for 64-Bit Numbers)](https://bellard.org/quickjs/quickjs.html#BigInt_002c-BigFloat_002c-BigDecimal)

![QuickJS Data Size](https://lupyuen.github.io/images/quickjs-data.jpg)

_What about the Heap Memory Size?_

Based on the NuttX Logs with __Heap Logging Enabled__...

- [__Heap Log: Without REPL__](https://github.com/lupyuen/quickjs-nuttx/blob/d2dbef1afef26ae4cc76719d7cac3740da5f3387/nuttx/qemu.log)

- [__Heap Log: With REPL__](https://github.com/lupyuen/quickjs-nuttx/blob/38e004e6eb643932f6957e03828ad25242cf803a/nuttx/qemu.log)

  [(__REPL__ runs extra __JavaScript Bytecode__)](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

![Computing the QuickJS Heap Usage with a Spreadsheet](https://lupyuen.github.io/images/quickjs-sheet.jpg)

We compute the __Heap Usage__ with a Spreadsheet (pic above)...

- [__Heap Usage: Without Repl__ (Google Sheets)](https://docs.google.com/spreadsheets/d/1EpdktueHxfAR4VR80d1XSZRwdO2UvNGf_sPetHHzAGQ/edit?usp=sharing)

- [__Heap Usage: With Repl__ (Google Sheets)](https://docs.google.com/spreadsheets/d/1g0-O2qdgjwNfSIxfayNzpUN8mmMyWFmRf2dMyQ9a8JI/edit?usp=sharing)

  (__"Free Size"__ might be inaccurate because it uses __VLOOKUP__ for Top-Down Lookup, though we actually need Down-Top Lookup)

And deduce the __QuickJS Heap Usage__ (pic below)...

| Max Heap Usage | |
|:---------------|:---:
| QuickJS without REPL | __276 KB__ |
| QuickJS with REPL | __371 KB__ |

![QuickJS Heap Usage](https://lupyuen.github.io/images/quickjs-heap.jpg)

Which totals __782 KB__ for Barebones QuickJS. And a whopping __925 KB__ for Turducken QuickJS. (Nearly 1 MB for Code + Data + Heap!)

For newer __Upsized NuttX Gadgets__ that are __Extra Roomy__ (and Vroomy), there's a high chance that we can run QuickJS...

And experiment with all kinds of __NuttX Drivers__ via ioctl(). The Interactive JavaScript Way!

![QEMU vs Ox64 QuickJS: 4 MB vs 22 MB](https://lupyuen.github.io/images/quickjs-size.png)

_QEMU vs Ox64 QuickJS: Any diff? (Pic above)_

QuickJS for NuttX QEMU is more Memory-Efficient because it uses [__Static Linking__](https://github.com/apache/nuttx/pull/11524).

(Instead of ELF Loader fixing the [__Relocatable Symbols__](https://lupyuen.github.io/articles/app#inside-a-nuttx-app) at runtime)

Right now Ox64 QuickJS is slower and [__multi-deca-mega-chonky__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/qjs): 22 MB! We might downsize to 4 MB (like QEMU) when we switch to Static Linking.

![QuickJS JavaScript Engine to Apache NuttX RTOS](https://lupyuen.github.io/images/quickjs-title.png)

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

    // GPIO Off or On
    gpio_status.className = (val == 0)
      ? "gpio_off"  // Normal CSS Style
      : "gpio_on";  // Green CSS Style
    return;         // Don't show in Console Output
  }
```

While suppressing the Notification from the Console Output.

[(__status__ and __gpio29__ are in HTML)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/index.html#L21-L29)

[(__gpio_off__ and __gpio_on__ are in CSS)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/quickjs/style.css#L106-L117)

[(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

![QuickJS JavaScript Engine in Ox64 NuttX Emulator](https://lupyuen.github.io/images/quickjs-title2.png)

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

Before building QuickJS: Build NuttX for __QEMU or Ox64__...

- [__Build NuttX for QEMU__](https://lupyuen.github.io/articles/quickjs#appendix-build-nuttx-for-qemu)

- [__Build NuttX for Ox64__](https://lupyuen.github.io/articles/quickjs#appendix-build-nuttx-for-ox64)

Then follow these steps to build __QuickJS for NuttX__ (QEMU or Ox64)...

```bash
## Download and build QuickJS for NuttX
git clone https://github.com/lupyuen/quickjs-nuttx
cd quickjs-nutttx/nuttx
./build.sh
```

[(See the __Build Script__)](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh)

Remember to...

- Set the [__Toolchain Path__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh#L4-L8)

- Select [__QuickJS for NuttX QEMU__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh#L8-L14)

- Or [__QuickJS for NuttX Ox64__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh#L14-L25)

_How did we figure out the steps to build QuickJS for NuttX?_

We ran "__`make --trace`__" to observe the __QuickJS Build__: [make.log](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/make.log)

```bash
## Build QuickJS for Debian x64 and observe the build
$ make --trace

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
...
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

We know that NuttX builds [__NuttX Apps__](https://github.com/lupyuen/tcc-riscv32-wasm) like this...

```bash
## Build NuttX Apps for QEMU and observe the build
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
  -lgcc apps/libapps.a \
  xpack-riscv-none-elf-gcc-13.2.0-2/lib/gcc/riscv-none-elf/13.2.0/rv64imafdc_zicsr/lp64d/libgcc.a \
  --end-group \
  -o  apps/bin/hello
```

[(__Ox64 Build__ is a little different)](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh#L19-L25)

Then we combined everything above into our [__QuickJS Build Script__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/build.sh).

Everything builds OK without changing any code in QuickJS! Though we [__stubbed out some functions__](https://lupyuen.github.io/articles/quickjs#build-quickjs-for-nuttx) because NuttX works a little differently.

(Later we'll merge our Build Script into the NuttX Makefiles)

_repl.c and qjscalc.c are missing?_

They're generated by the [__QuickJS Compiler__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/make.log#L28-L32)!

```bash
## Compile the REPL from JavaScript to C
./qjsc -c -o repl.c -m repl.js

## Compile the BigNum Calculator from JavaScript to C
./qjsc -fbignum -c -o qjscalc.c qjscalc.js
```

So we __borrow the output__ from another QuickJS Build (Debian x64) and add to NuttX...

- [__nuttx/repl.c__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/repl.c): Interactive-Mode REPL for QuickJS

- [__nuttx/qjscalc.c__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/qjscalc.c): BigNum Calculator for QuickJS

_What's inside repl.c and qjscalc.c?_

They contain plenty of [__JavaScript Bytecode__](https://github.com/lupyuen/quickjs-nuttx/blob/master/nuttx/repl.c). Brilliant!

```c
/* File generated automatically by the QuickJS compiler. */
#include <inttypes.h>
const uint32_t qjsc_repl_size = 16280;
const uint8_t qjsc_repl[16280] = {
 0x02, 0xa5, 0x03, 0x0e, 0x72, 0x65, 0x70, 0x6c,
 0x2e, 0x6a, 0x73, 0x06, 0x73, 0x74, 0x64, 0x04,
```

That's why REPL and BigNum will require more Heap Memory, to process the extra JavaScript Bytecode.

![QuickJS on NuttX QEMU](https://lupyuen.github.io/images/quickjs-qemu.png)

[_QuickJS on NuttX QEMU_](https://gist.github.com/lupyuen/a3d2a491112eaf5810edc1fa355606db)

# Appendix: Build NuttX for QEMU

In this article, we compiled a Work-In-Progress Version of __Apache NuttX RTOS for QEMU RISC-V (64-bit Kernel Mode)__ that has these updates...

- [__Add the LED Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/1037eda906f11aef44f7670f8cc5a1c1d2141911) for QEMU

- [__Increase the App Stack Size__](https://github.com/apache/nuttx/commit/3b662696aff4b89e2b873a6b75d0006860fc9f7b)  from 2 KB to 64 KB

- [__Fix the `leds` app__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/45dbe5ce07239e7ca7dcb50cb0e55da151052429) for testing LED Driver

We may download the [__NuttX Binaries for QEMU__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/qemuled-1)...

1.  Download the NuttX Kernel: [__`nuttx`__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/qemuled-1/nuttx)

    Copy to __`$HOME/nuttx/`__

1.  Download the NuttX Apps: [__`apps-bin.zip`__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/qemuled-1/apps-bin.zip)

    Unzip and copy the files inside (not the folder) into __`$HOME/apps/bin/`__

    (We should see __`$HOME/apps/bin/qjs`__ and __`blink.js`__)
 
1.  Then run...

    ```bash
    $ cd $HOME/nuttx/
    $ qemu-system-riscv64 \
        -semihosting \
        -M virt,aclint=on \
        -cpu rv64 \
        -smp 8 \
        -bios none \
        -kernel nuttx \
        -nographic
    ```

    [(See the __NuttX Log__)](https://gist.github.com/lupyuen/a3d2a491112eaf5810edc1fa355606db)

Or if we prefer to __build NuttX ourselves__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch qemuled \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch qemuled \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for QEMU RISC-V (64-bit Kernel Mode)
cd nuttx
tools/configure.sh rv-virt:knsh64

## Build NuttX
make

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

[(See the __Build Script__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/qemuled-1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/qemuled-1)

This produces the NuttX ELF Image __`nuttx`__ that we'll boot on QEMU RISC-V Emulator in a while.

But first: We build __QuickJS for Ox64__, which will produce `qjs` and `blink.sh` in the `apps/bin` folder...

- [__"Build QuickJS for NuttX QEMU"__](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

Now we boot __`nuttx`__ on QEMU RISC-V Emulator...

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

At the NuttX Prompt, enter...

```bash
qjs --std /system/bin/blink.js
```

QuickJS for NuttX QEMU blinks a __Simulated LED__...

```text
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs --std /system/bin/blink.js
led=0, val=1
led=0, val=0
led=0, val=1
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/a3d2a491112eaf5810edc1fa355606db)

To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

![QuickJS JavaScript Engine in Ox64 NuttX Emulator](https://lupyuen.github.io/images/quickjs-title2.png)

# Appendix: Build NuttX for Ox64

In this article, we compiled a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__ that has these updates...

- [__Add the GPIO Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/8f75f3744f3964bd3ed0596421a93e59fb39cdd8)  for Ox64 BL808

- [__Add the LED Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/4f3996959132ca0d35874b7be3eef89d6bf7f351) for Ox64 BL808

- [__Increase the App Stack Size__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/904b95534298378d64b99c1f9e649f8bc27a8048)  from 2 KB to 64 KB

- [__Increase the RAM Disk Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/28453790d06c0282b85e5df98624f8fa1c0b2226) from 16 MB to 40 MB

- [__Fix the `leds` app__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/66f1389c8d17eecdc5ef7baa62d13435bd053ee3) for testing LED Driver

We may download the [__NuttX Binaries for Ox64__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/gpio2-1)...

1.  Download the NuttX Image: [__`Image`__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/gpio2-1/Image)

1.  Prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

    [(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

1.  Copy the __`Image`__ file (from above) and overwrite the __`Image`__ in the Linux microSD...

    ```bash
    ## Overwrite the Linux Image
    ## on Ox64 microSD
    cp Image \
      "/Volumes/NO NAME/Image"
    diskutil unmountDisk /dev/disk2
    ```

1.  Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

1.  Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH).

1.  At the NuttX Prompt, enter...

    ```bash
    qjs --std /system/bin/blink.js
    ```

    QuickJS on NuttX blinks our __LED on GPIO 29__...

    ```yaml
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh> qjs --std /system/bin/blink.js

    bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
    bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
    bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
    bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/f879aa3378aa1b0170a1d3ea2b0b9d67)

Or if we prefer to __build NuttX ourselves__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch gpio2 \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch gpio2 \
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

We build the __NuttX Apps Filesystem__ that contains NuttX Shell and NuttX Apps...

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd
```

Next we build __QuickJS for Ox64__, which will produce `qjs` and `blink.sh` in the `apps/bin` folder...

- [__"Build QuickJS for NuttX Ox64"__](https://lupyuen.github.io/articles/quickjs#appendix-build-quickjs-for-nuttx)

We bundle QuickJS into the __Initial RAM Disk__ and append it to the NuttX Image...

```bash
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

[(See the __Build Script__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/gpio2-1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/gpio2-1)

This produces the NuttX Image for Ox64: __`Image`__

Follow the [__earlier instructions__](https://lupyuen.github.io/articles/quickjs#appendix-build-nuttx-for-ox64) to copy __`Image`__ to a Linux microSD and boot it on Ox64.

_The same files were used for NuttX Emulator? (Pic above)_

Yep we copied the Build Outputs above to the [__NuttX Emulator for Ox64__](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs/quickjs).
