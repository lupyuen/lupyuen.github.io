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

TODO: How Small? Heap Size?

TODO: Static Linking

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

After plenty of headscratching troubleshooting, this [__Vital Clue__](https://github.com/lupyuen/quickjs-nuttx#nuttx-stack-is-full-of-quickjs) suddenly popped up...

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

(Lesson Learnt: If the NuttX Stack Dump loops forever, we're probably __Out Of Stack Space__)

We follow these steps to [__increase the Stack Size__](https://github.com/lupyuen/nuttx-star64#increase-stack-size)...

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
    int fd, req;
    int64_t arg, ret;
    BOOL is_bigint;
    
    // First Arg is ioctl() File Descriptor (int32)
    if (JS_ToInt32(ctx, &fd, argv[0]))
        return JS_EXCEPTION;
    
    // Second Arg is ioctl() Request (int32)
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

    // Return the result as int64 or int32
    if (is_bigint)
        return JS_NewBigInt64(ctx, ret);
    else
        return JS_NewInt64(ctx, ret);
}
```

Yep it seems to work...

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

# Add LED Driver to NuttX QEMU RISC-V

TODO

We add the [LED Driver to NuttX QEMU RISC-V (knsh64)](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/1037eda906f11aef44f7670f8cc5a1c1d2141911).

We fix the `leds` app because [task_create is missing from QEMU knsh64](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/45dbe5ce07239e7ca7dcb50cb0e55da151052429).

The `leds` app works great with the LED Driver...

```text
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic
ABC[    0.015000] board_userled_all: ledset=0x0
[    0.016000] board_userled_all: led=0, val=0
[    0.016000] board_userled_all: led=1, val=0
[    0.017000] board_userled_all: led=2, val=0

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> leds
leds_main: Starting the led_daemon

led_daemon (pid# 3): Running
led_daemon: Opening /dev/userleds
led_daemon: Supported LEDs 0x07
led_daemon: LED set 0x01
[   29.652000] board_userled_all: ledset=0x1
[   29.652000] board_userled_all: led=0, val=1
[   29.652000] board_userled_all: led=1, val=0
[   29.653000] board_userled_all: led=2, val=0
led_daemon: LED set 0x02
[   30.154000] board_userled_all: ledset=0x2
[   30.154000] board_userled_all: led=0, val=0
[   30.155000] board_userled_all: led=1, val=1
[   30.155000] board_userled_all: led=2, val=0
led_daemon: LED set 0x03
[   30.656000] board_userled_all: ledset=0x3
[   30.656000] board_userled_all: led=0, val=1
[   30.656000] board_userled_all: led=1, val=1
[   30.657000] board_userled_all: led=2, val=0
```

Now we test with QuickJS...

# QuickJS calls NuttX LED Driver

TODO

This is how we blink an LED in C: [leds_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/qemuled/examples/leds/leds_main.c)

```c
#define _ULEDBASE       (0x1d00) /* User LED ioctl commands */
#define _IOC(type,nr)   ((type)|(nr))
#define _ULEDIOC(nr)      _IOC(_ULEDBASE,nr)
#define ULEDIOC_SETALL     _ULEDIOC(0x0003)

// Open the LED Device
int fd = open("/dev/userleds", os.O_WRONLY);
assert(fd > 0);

// Flip LED 0 to On
int ret = ioctl(fd, ULEDIOC_SETALL, 1);
assert(ret >= 0);

// Flip LED 0 to Off
int ret = ioctl(fd, ULEDIOC_SETALL, 0);
assert(ret >= 0);

close(fd);
```

Which becomes this in QuickJS...

```text
ULEDIOC_SETALL = 0x1d03
fd = os.open("/dev/userleds", os.O_WRONLY)
os.ioctl(fd, ULEDIOC_SETALL, 1)
os.ioctl(fd, ULEDIOC_SETALL, 0)
```

And it works yay!

```text
→ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > ULEDIOC_SETALL = 0x1d03
7427
qjs > fd = os.open("/dev/userleds", os.O_WRONLY)
3
qjs > ret = os.ioctl(fd, ULEDIOC_SETALL, 1);
[   24.851000] board_userled_all: ledset=0x1
[   24.852000] board_userled_all: led=0, val=1
[   24.852000] board_userled_all: led=1, val=0
[   24.852000] board_userled_all: led=2, val=0
0
qjs > ret = os.ioctl(fd, ULEDIOC_SETALL, 0);
[   29.617000] board_userled_all: ledset=0x0
[   29.617000] board_userled_all: led=0, val=0
[   29.617000] board_userled_all: led=1, val=0
[   29.618000] board_userled_all: led=2, val=0
0
qjs > 
```

# Add LED Driver to NuttX Ox64 BL808 SBC

TODO

Now we test on a Real Device with a Real LED: Ox64 BL808 SBC...

- We add the [GPIO Driver for Ox64 BL808](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/8f75f3744f3964bd3ed0596421a93e59fb39cdd8)

- We add the [LED Driver for Ox64 BL808](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/4f3996959132ca0d35874b7be3eef89d6bf7f351)

- We increase [Ox64 BL808 Stack Size to 64 KB](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/904b95534298378d64b99c1f9e649f8bc27a8048) for QuickJS

- We fix the `leds` app because [task_create is missing from QEMU knsh64](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/66f1389c8d17eecdc5ef7baa62d13435bd053ee3)

But our RAM Disk Region is too small (16 MB)...

```text
Starting kernel ...
bl808_copy_ramdisk: RAM Disk Region too small. Increase by 586288l bytes.
```

Initial RAM Disk (initrd) is now 17 MB...

```text
→ ls -l $HOME/ox64/nuttx/initrd
-rw-r--r--  1 17363968 Feb 12 13:06 /Users/Luppy/ox64/nuttx/initrd
```

We [increase the RAM Disk Region from](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/28453790d06c0282b85e5df98624f8fa1c0b2226) 16 MB to 40 MB.

But QuickJS crashes on Ox64...

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 0000000000007028, MTVAL: 0000000000007028
riscv_exception: PANIC!!! Exception = 000000000000000c
_assert: Current Version: NuttX  12.4.0-RC0 904b955-dirty Feb 12 2024 14:32:16 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: /system/bin/init process: /system/bin/init 0x8000004a
up_dump_register: EPC: 0000000000007028
up_dump_register: A0: 0000000000000001 A1: 0000000080210010 A2: 0000000000000001 A3: 0000000080210010
up_dump_register: A4: 0000000000000000 A5: 0000000000007028 A6: 0000000000000101 A7: 0000000000000000
up_dump_register: T0: 0000000000000000 T1: 0000000000000000 T2: 0000000000000000 T3: 0000000000000000
up_dump_register: T4: 0000000000000000 T5: 0000000000000000 T6: 0000000000000000
up_dump_register: S0: 0000000000000000 S1: 0000000000000000 S2: 0000000000000000 S3: 0000000000000000
up_dump_register: S4: 0000000000000000 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000000000000 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 0000000080220000 FP: 0000000000000000 TP: 0000000000000000 RA: 000000005020b28e
dump_stacks: ERROR: Stack pointer is not within the stack
dump_stack: IRQ Stack:
dump_stack:   base: 0x50400290
dump_stack:   size: 00002048
stack_dump: 0x50400708: 5021986a 00000000 5021a6d8 00000000 0000000a 00000000 50400828 00000000
stack_dump: 0x50400728: 00000008 00000000 0000005f 00000000 5020825e 00000000 504008d0 00000000
stack_dump: 0x50400748: 00000008 00000000 ffff9fef ffffffff 00004010 00000000 504008b0 00000000
stack_dump: 0x50400768: 30386230 35303430 ffff9fef ffffffff 00004010 00000000 00000039 00000000
stack_dump: 0x50400788: 00000000 00000000 5040b440 00000000 80210c00 00000000 00000bc0 00000000
stack_dump: 0x504007a8: 50401b30 00000000 00042020 00000002 80210040 00000000 50400290 00000000
stack_dump: 0x504007c8: 5021a3d0 00000000 5021a6c8 00000000 50400a90 00000000 50400848 00000000
stack_dump: 0x504007e8: 502175bc 00000000 50400290 00000000 5021a3d0 00000000 50400868 00000000
stack_dump: 0x50400808: 00000060 00000000 50218706 00000000 502186a0 00000000 50209008 00000000
stack_dump: 0x50400828: 0000000a 00000000 50400808 00000000 5020923c 00000000 50209008 00000000
stack_dump: 0x50400848: 50400880 00000000 00000800 00000000 5020925c 00000000 50218706 00000000
stack_dump: 0x50400868: 50400880 00000000 50209008 00000000 50201dd0 00000000 5021a6c8 00000000
stack_dump: 0x50400888: 50400868 00000000 50400880 00000000 00000000 00000000 50209008 00000000
stack_dump: 0x504008a8: 00000000 00000000 00000000 00000000 00000000 00000000 50209008 00000000
stack_dump: 0x504008c8: 00000000 00000000 5021a6e8 00000000 00000001 00000000 00000001 00000000
stack_dump: 0x504008e8: 5040a630 00000000 00000000 00000000 5020216a 00000000 8000004a 00000000
stack_dump: 0x50400908: deadbeef deadbeef deadbeef deadbeef 00000000 00000000 5040a630 00000000
stack_dump: 0x50400928: 5040ca40 00000000 50219b20 00000000 50219df8 00000000 00000055 00000000
stack_dump: 0x50400948: 7474754e 00000058 00000000 00000000 00000000 00000000 0000000c 00000000
stack_dump: 0x50400968: 5040ca40 00000000 504009d8 00000000 502175bc 2e323100 2d302e34 00304352
stack_dump: 0x50400988: 50219dd0 00000000 3039beef 35396234 69642d35 20797472 20626546 32203231
stack_dump: 0x504009a8: 20343230 333a3431 36313a32 00000000 0000000a 00000000 0000000c 73697200
stack_dump: 0x504009c8: 00762d63 00000000 50400028 00000000 50400a10 00000000 00000000 00000000
stack_dump: 0x504009e8: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x50400a08: 00000000 00000000 00000000 00000000 00000000 00000000 0000000c 00000000
stack_dump: 0x50400a28: 5040ca40 00000000 0000000c 00000000 502012e8 00000000 00000008 00000000
stack_dump: 0x50400a48: 50401b30 00000000 5040ca40 00000000 50200d66 00000000 00000000 00000000
stack_dump: 0x50400a68: 00000000 00000000 0000000c 00000000 50200894 00000000 00007028 00000000
stack_dump: 0x50400a88: 50200180 00000000 00000000 00000000 00000000 00000000 00000000 00000000
dump_stack: Kernel Stack:
dump_stack:   base: 0x5040b440
dump_stack:   size: 00003072
stack_dump: 0x5040c040: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
dump_stack: User Stack:
dump_stack:   base: 0x80210040
dump_stack:   size: 00003008
stack_dump:0x80210918: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210938: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210958: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210978: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210998: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x802109b8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x802109d8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x802109f8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210a18: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210a38: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210a58: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210a78: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210a98: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210ab8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210ad8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210af8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210b18: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210b38: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210b58: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210b78: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbee deadbeef
stack_dump: 0x80210b98: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210bb8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210bd8: deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef deadbeef
stack_dump: 0x80210bf8: deadbeef deadbeef 00000000 00000000 00000000 00000000 00000000 00000000
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x50400290      2048       968    47.2%    irq
dump_task:       0     0   0 FIFO     Kthread - Ready              0000000000000000 0x50407010      3056      1136    37.1%    Idle_Task
dump_task:       1     1 100 RR       Kthread - Waiting Semaphore  0000000000000000 0x50410050      1968       704    35.7%    lpwork 0x50401a90 0x50401ab8
dump_task:       6     6 100 RR       Task    - Running            0000000000000000 0x80210030     65488         0     0.0%    qjs
dump_task:       3     3 100 RR       Task    - Waiting Semaphore  0000000000000000 0x80210040      3008       744    24.7%    /system/bin/init
```

That's because [Ox64 Build is different](https://github.com/lupyuen/quickjs-nuttx/commit/221f80518f175a080888f2824408d81c734b9877#diff-a1427809210c3d4b0e73ca2c8712d61eaa10652316dfdcb7ac0cec8a8a81e27d)

We fix it, now it has doubled in size...

```text
→ ls -l $HOME/ox64/nuttx/initrd
-rw-r--r--  1 Luppy  staff  35765248 Feb 12 14:57 /Users/Luppy/ox64/nuttx/initrd
```

And QuickJS blinks the LED on Ox64 yay!

# QuickJS blinks the LED on Ox64 Emulator

TODO

_Will QuickJS run on Ox64 Emulator?_

Yep it works! https://lupyuen.github.io/nuttx-tinyemu/quickjs/

```text
Loading...
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > console.log(123)
123
undefined

qjs > ULEDIOC_SETALL = 0x1d03
7427

qjs > fd = os.open("/dev/userleds", os.O_WRONLY)
3

qjs > os.ioctl(fd, ULEDIOC_SETALL, 1)
bl808_gpiowrite: regaddr=0x20000938, set=0x1000000
0

qjs > os.ioctl(fd, ULEDIOC_SETALL, 0)
bl808_gpiowrite: regaddr=0x20000938, clear=0x1000000
0
```

[(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

![QuickJS JavaScript Engine to Apache NuttX RTOS](https://lupyuen.github.io/images/quickjs-title.png)

# Simulate the LED on Ox64 Emulator

TODO

Let's simulate the LED on Ox64 Emulator...

- When writing to BL808 GPIO Output: [Send an Emulator Notification](https://github.com/lupyuen/ox64-tinyemu/commit/622ba840fd40ac627de2bdb6a73354ce291754b9) to the Console: `{"nuttxemu":{"gpio29":1}}`

- In our Web Browser JavaScript: [Handle Emulator Notification](https://github.com/lupyuen/nuttx-tinyemu/commit/2cadf80b7a95e182d9ad0aef2edfd08e0948affa#diff-0935fa7cc51b2920653500625c6e64acb1c8b81b85a6042c716b049205c75a63)

And it works! https://lupyuen.github.io/nuttx-tinyemu/quickjs/

[(Watch the __Demo on YouTube__)](https://youtu.be/AFDVceqQNRs)

![QuickJS JavaScript Engine to Apache NuttX RTOS](https://lupyuen.github.io/images/quickjs-title2.png)

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
