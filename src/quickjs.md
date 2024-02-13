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

1.  __POSIX Functions:__ popen, pclose, pipe2, symlink, ...

1.  __Dynamic Linking:__ dlopen, dlsym, dlclose

1.  __Math Functions:__ pow, floor, trunc, ...

1.  __Atomic Functions:__ atomic_fetch_add_2, ...

_How did we fix the missing functions?_

1.  __POSIX Functions:__ They're probably available if we tweak the __Build Options__ for NuttX. For now, we [__stubbed them out__](TODO).

1.  __Dynamic Linking:__ We won't support Dynamic Linking for NuttX. We [__stubbed them out__](TODO).

1.  __Math Functions:__ We linked them with GCC Option __`-lm`__. The last few stragglers: We [__stubbed them out__](TODO).

1.  __Atomic Functions:__ We patched in the [__Missing Atomic Functions__](TODO).

    [(About __NuttX Atomic Functions__)](https://github.com/apache/nuttx/issues/10642)

    [(We might __disable QuickJS Atomic Functions__)](TODO)

TODO: Mostly

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

# Fix the Missing Functions

TODO

The NuttX Linking fails. The missing functions...

- POSIX Functions (popen, pclose, pipe2, symlink, ...): We'll stub them out: [nuttx/stub.c](nuttx/stub.c)

- Dynamic Linking (dlopen, dlsym, dlclose): Don't need Dynamic Linking for fib.so, point.so

- Atomic Functions (__atomic_fetch_add_2, ...): We patched them: [nuttx/arch_atomic.c](nuttx/arch_atomic.c) [(Why are they missing)](https://github.com/apache/nuttx/issues/10642)

- Math Functions (pow, floor, trunc, ...): Link with `-lm`

```text
+ riscv64-unknown-elf-ld --oformat elf64-littleriscv -e _start -Bstatic -T../apps/import/scripts/gnu-elf.ld -L../apps/import/libs -L riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-apple-darwin/lib/gcc/riscv64-unknown-elf/10.2.0/rv64imafdc/lp64d ../apps/import/startup/crt0.o .obj/qjs.o .obj/repl.o .obj/quickjs.o .obj/libregexp.o .obj/libunicode.o .obj/cutils.o .obj/quickjs-libc.o .obj/libbf.o .obj/qjscalc.o --start-group -lmm -lc -lproxies -lgcc ../apps/libapps.a riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-apple-darwin/lib/gcc/riscv64-unknown-elf/10.2.0/rv64imafdc/lp64d/libgcc.a --end-group -o ../apps/bin/qjs

riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_pow':
quickjs-nuttx/quickjs.c:12026: undefined reference to `pow'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `is_safe_integer':
quickjs-nuttx/quickjs.c:11108: undefined reference to `floor'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `time_clip':
quickjs-nuttx/quickjs.c:49422: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_fcvt1':
quickjs-nuttx/quickjs.c:11430: undefined reference to `fesetround'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:11432: undefined reference to `fesetround'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_ecvt1':
quickjs-nuttx/quickjs.c:11346: undefined reference to `fesetround'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:11348: undefined reference to `fesetround'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `set_date_fields':
quickjs-nuttx/quickjs.c:49435: undefined reference to `fmod'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:49438: undefined reference to `floor'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `JS_ComputeMemoryUsage':
quickjs-nuttx/quickjs.c:6209: undefined reference to `round'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:6213: undefined reference to `round'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:6215: undefined reference to `round'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:6218: undefined reference to `round'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_strtod':
quickjs-nuttx/quickjs.c:10071: undefined reference to `pow'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `JS_ToUint8ClampFree':
quickjs-nuttx/quickjs.c:10991: undefined reference to `lrint'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `JS_NumberIsInteger':
quickjs-nuttx/quickjs.c:11144: undefined reference to `floor'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_Date_UTC':
quickjs-nuttx/quickjs.c:49722: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `set_date_field':
quickjs-nuttx/quickjs.c:49499: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_date_setYear':
quickjs-nuttx/quickjs.c:50109: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_math_hypot':
quickjs-nuttx/quickjs.c:43061: undefined reference to `hypot'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_fmax':
quickjs-nuttx/quickjs.c:42949: undefined reference to `fmax'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_fmin':
quickjs-nuttx/quickjs.c:42935: undefined reference to `fmin'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `JS_ToBigIntFree':
quickjs-nuttx/quickjs.c:12143: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_atomics_op':
quickjs-nuttx/quickjs.c:55149: undefined reference to `__atomic_fetch_add_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55218: undefined reference to `__atomic_fetch_add_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55165: undefined reference to `__atomic_fetch_and_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55166: undefined reference to `__atomic_fetch_and_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55204: undefined reference to `__atomic_fetch_or_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55167: undefined reference to `__atomic_fetch_or_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55167: undefined reference to `__atomic_fetch_sub_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55168: undefined reference to `__atomic_fetch_sub_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55168: undefined reference to `__atomic_fetch_xor_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55169: undefined reference to `__atomic_fetch_xor_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55169: undefined reference to `__atomic_exchange_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55170: undefined reference to `__atomic_exchange_2'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55183: undefined reference to `__atomic_compare_exchange_1'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:55189: undefined reference to `__atomic_compare_exchange_2'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_atomics_store':
quickjs-nuttx/quickjs.c:55287: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_date_constructor':
quickjs-nuttx/quickjs.c:49674: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_function_bind':
quickjs-nuttx/quickjs.c:38439: undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o: in function `js_binary_arith_slow':
quickjs-nuttx/quickjs.c:13543: undefined reference to `fmod'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:13497: undefined reference to `fmod'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs.c:13526: undefined reference to `fmod'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x58): undefined reference to `fabs'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x78): undefined reference to `floor'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x98): undefined reference to `ceil'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0xd8): undefined reference to `sqrt'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0xf8): undefined reference to `acos'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x118): undefined reference to `asin'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x138): undefined reference to `atan'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x158): undefined reference to `atan2'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x178): undefined reference to `cos'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x198): undefined reference to `exp'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x1b8): undefined reference to `log'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x1f8): undefined reference to `sin'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x218): undefined reference to `tan'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x238): undefined reference to `trunc'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x278): undefined reference to `cosh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x298): undefined reference to `sinh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x2b8): undefined reference to `tanh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x2d8): undefined reference to `acosh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x2f8): undefined reference to `asinh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x318): undefined reference to `atanh'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x338): undefined reference to `expm1'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x358): undefined reference to `log1p'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x378): undefined reference to `log2'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x398): undefined reference to `log10'
riscv64-unknown-elf-ld: .obj/quickjs.o:(.rodata.js_math_funcs+0x3b8): undefined reference to `cbrt'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_std_popen':
quickjs-nuttx/quickjs-libc.c:942: undefined reference to `popen'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_std_file_finalizer':
quickjs-nuttx/quickjs-libc.c:807: undefined reference to `pclose'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_os_pipe':
quickjs-nuttx/quickjs-libc.c:3113: undefined reference to `pipe2'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_os_readlink':
quickjs-nuttx/quickjs-libc.c:2746: undefined reference to `readlink'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_new_message_pipe':
quickjs-nuttx/quickjs-libc.c:1635: undefined reference to `pipe2'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_std_file_close':
quickjs-nuttx/quickjs-libc.c:1050: undefined reference to `pclose'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_os_symlink':
quickjs-nuttx/quickjs-libc.c:2725: undefined reference to `symlink'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_std_urlGet':
quickjs-nuttx/quickjs-libc.c:1361: undefined reference to `popen'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `http_get_header_line':
quickjs-nuttx/quickjs-libc.c:1299: undefined reference to `pclose'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_std_urlGet':
quickjs-nuttx/quickjs-libc.c:1442: undefined reference to `pclose'
riscv64-unknown-elf-ld: .obj/quickjs-libc.o: in function `js_module_loader_so':
quickjs-nuttx/quickjs-libc.c:479: undefined reference to `dlopen'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs-libc.c:490: undefined reference to `dlsym'
riscv64-unknown-elf-ld: quickjs-nuttx/quickjs-libc.c:495: undefined reference to `dlclose'
```

After fixing the missing functions, QuickJS compiles OK for NuttX yay!

# QuickJS Crashes on NuttX

TODO

_Does QuickJS run on NuttX?_

We tested with our Expect Script: [nuttx/qemu.exp](nuttx/qemu.exp). The latest NuttX Log is always at [qemu.log](nuttx/qemu.log)

Nope NuttX crashes...

```text
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
load_absmodule: Successfully loaded module /system/bin/qjs
exec_module: Executing qjs
exec_module: Initialize the user heap (heapsize=528384)
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0006484, MTVAL: 00000008c0203b88
riscv_exception: PANIC!!! Exception = 000000000000000d
_assert: Current Version: NuttX  12.4.0-RC0 f8b0b06 Feb  9 2024 14:19:24 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: /system/bin/init process: /system/bin/init 0xc000004a
up_dump_register: EPC: 00000000c0006484
up_dump_register: A0: 00000000c02005d0 A1: 00000000c006b4e0 A2: 0000000000000074 A3: ffffffff00000000
up_dump_register: A4: 00000007fffffff8 A5: 00000008c0203b88 A6: ffffffffae012bc6 A7: 0000000000000000
up_dump_register: T0: 0000000080007474 T1: fffffffffc000000 T2: 00000000000001ff T3: 00000000c0207c40
up_dump_register: T4: 00000000c0207c38 T5: 0000000000000009 T6: 000000000000002a
up_dump_register: S0: 00000000c0201fc0 S1: ffffffffffffffff S2: 0000000003472fe9 S3: 00000000c02005d0
up_dump_register: S4: 0000000000000005 S5: 00000000c006b4e0 S6: 000000003fffffff S7: 000000007fffffff
up_dump_register: S8: 0000000040000000 S9: ffffffffc0000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 00000000c0202220 FP: 00000000c0201fc0 TP: 0000000000000000 RA: 00000000c001b32c
```

We look up the disassembly: [nuttx/qjs.S](nuttx/qjs.S)

EPC c0006484 is here...

```text
quickjs-nuttx/quickjs.c:2876
static JSAtom __JS_FindAtom(JSRuntime *rt, const char *str, size_t len,
                            int atom_type) { ...
        p = rt->atom_array[i];
    c0006476:	0609b783          	ld	a5,96(s3)
    c000647a:	02049693          	slli	a3,s1,0x20
    c000647e:	01d6d713          	srli	a4,a3,0x1d
    c0006482:	97ba                	add	a5,a5,a4
    c0006484:	6380                	ld	s0,0(a5)
```

_Why is it accessing MTVAL 8_c020_3b88? Maybe the `8` prefix shouldn't be there?_

Seems to be crashing while searching for the JavaScript Atom for a String.

Maybe we shouldn't borrow the bytecode [nuttx/repl.c](nuttx/repl.c) and [nuttx/qjscalc.c](nuttx/qjscalc.c) from another platform? (Debian x64)

Let's [disable BIGNUM and qjscalc.c](https://github.com/lupyuen/quickjs-nuttx/commit/fe3b62c84c66f7a50daa548d4f74adfcdbbee3cd).

To disable [nuttx/repl.c](nuttx/repl.c), we run QuickJS Non-Interactively, without REPL: [nuttx/qemu.exp](nuttx/qemu.exp)

```bash
qjs -e console.log(123)
```

It still crashes...

```text
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0006232, MTVAL: 00000008c0209718
riscv_exception: PANIC!!! Exception = 000000000000000d
_assert: Current Version: NuttX  12.4.0-RC0 f8b0b06 Feb  9 2024 14:19:24 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: /system/bin/init process: /system/bin/init 0xc000004a
up_dump_register: EPC: 00000000c0006232
up_dump_register: A0: 00000000c02005d0 A1: 00000000c0062868 A2: 0000000000000067 A3: ffffffff00000000
up_dump_register: A4: 00000007fffffff8 A5: 00000008c0209718 A6: 0000000000000003 A7: 0000000000000000
up_dump_register: T0: 0000000080007474 T1: fffffffffc000000 T2: 00000000000001ff T3: 00000000c020b8a0
up_dump_register: T4: 00000000c020b898 T5: 0000000000000009 T6: 000000000000002a
up_dump_register: S0: 00000000c0201f90 S1: ffffffffffffffff S2: 00000000398dc555 S3: 00000000c02005d0
up_dump_register: S4: 0000000000000012 S5: 00000000c0062868 S6: 000000003fffffff S7: 000000007fffffff
up_dump_register: S8: 0000000040000000 S9: ffffffffc0000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 00000000c0202440 FP: 00000000c0201f90 TP: 0000000000000000 RA: 00000000c0019fa4
```

EPC c0006232 in [qjs.S](nuttx/qjs.S) says...

```text
quickjs-nuttx/quickjs.c:2876
static JSAtom __JS_FindAtom(JSRuntime *rt, const char *str, size_t len,
                            int atom_type) { ...
        p = rt->atom_array[i];
    c0006224:	0609b783          	ld	a5,96(s3)
    c0006228:	02049693          	slli	a3,s1,0x20
    c000622c:	01d6d713          	srli	a4,a3,0x1d
    c0006230:	97ba                	add	a5,a5,a4
    c0006232:	6380                	ld	s0,0(a5)
```

Same old place! Similar MTVAL! 8_c020_9718

Might be a problem with the JavaScript Atom Tagging? The `8` prefix might be a tag? [quickjs.h](quickjs.h)

TODO: Is QuickJS built correctly for 64-bit pointers?

_Where exactly in main() are we crashing?_

JS_NewCFunction3 seems to crash the second time we call it.

TODO: Are we running low on App Text / Data / Heap? According to Linker Map [nuttx/qjs.map](nuttx/qjs.map), we're using 486 KB of App Text (Code).

```text
$ riscv64-unknown-elf-size ../apps/bin/qjs
   text    data     bss     dec     hex filename
 486371     260      94  486725   76d45 ../apps/bin/qjs
```

[NuttX Config](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L39-L40) says we have 128 pages of App Text. Assuming 8 KB per page, that's 1 MB of App Text.

TODO: Why does hash_string8 hang? Stack problems?

TODO: Memory Corruption? Now `printf` seems to crash with Mutex problems

# Atom Sentinel becomes 0xFFFF_FFFF

TODO

We discover that the Atom Sentinel has become 0xFFFF_FFFF (instead of 0), causing crashes while searching the Atom List for an Atom...

```text
__JS_FindAtom: e
00000000C0203DE0
__JS_FindAtom: f
00000000C0201F60
__JS_FindAtom: h
00000000C0201F6C
__JS_FindAtom: i
00000000FFFFFFFF
```

So we stop the Atom Search when we see Sentinel 0xFFFF_FFFF...

- [__JS_FindAtom](https://github.com/lupyuen/quickjs-nuttx/commit/b9a53eca9a177ddeb7a4972c3ccf1388db606feb#diff-45f1ae674139f993bf8a99c382c1ba4863272a6fec2f492d76d7ff1b2cfcfbe2)

- [__JS_NewAtom](https://github.com/lupyuen/quickjs-nuttx/commit/42eb9be1547dd42bf4eebf1e21b1be6732f95f7d#diff-45f1ae674139f993bf8a99c382c1ba4863272a6fec2f492d76d7ff1b2cfcfbe2)

# Heap Errors and STDIO Weirdness

TODO

Now it halts inside the NuttX Mutex for printf...

```text
__JS_FindAtom: 0
asIntN
__JS_FindAtom: a
__JS_FindAtom: b
__JS_FindAtom: c
__JS_FindAtom: d
mm_malloc: Allocated 0xc0211b70, size 32
mm_malloc: Allocated 0xc0212030, size 112
mm_free: Freeing 0xc0211b20
mm_malloc: Allocated 0xc0209790, size 160
mm_free: Freeing 0xc0209710
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c005321c, MTVAL: 0000000000000168
```

From here...

```text
bool nxmutex_is_hold(FAR mutex_t *mutex)
{
    c0053216:	1141                	addi	sp,sp,-16
    c0053218:	e406                	sd	ra,8(sp)
    c005321a:	e022                	sd	s0,0(sp)
/Users/Luppy/riscv/nuttx/libs/libc/misc/lib_mutex.c:149
  return mutex->holder == _SCHED_GETTID();
    c005321c:	4d00                	lw	s0,24(a0)
    c005321e:	3b1030ef          	jal	ra,c0056dce <gettid>
```

TODO: Why is the Mutex corrupted?

We [change all puts() to write()](https://github.com/lupyuen/quickjs-nuttx/commit/b8df93e209abd594dc6e843bbb1941ddae91350d#diff-93a38cdf6b6645fff66fa78773011a5330ea9ed48cc1f70f4c65a6f6b707e246), which doesn't use Mutex.

Now we see Heap Free Error...

```text
mm_free: Freeing 0xc0214e10
JS_CreateProperty: e
JS_CreateProperty: f
JS_CreateProperty: g
mm_free: Freeing 0xc0214c80
mm_free: Freeing 0xc0214e80
mm_free: Freeing 0xc0214c50
mm_free: Freeing 0xc0215080
mm_free: Freeing 0xc0200da0
mm_free: Freeing 0xc0201920
_assert: Current Version: NuttX  12.4.0-RC0 f8b0b06 Feb 10 2024 12:50:34 risc-v
_assert: Assertion failed : at file: mm_heap/mm_free.c:112 task: qjs process: qjs 0xc000339e
up_dump_register: EPC: 0000000080001faa
up_dump_register: A0:+ true
```

TODO: What is this Heap Free Error? [Sanity check against double-frees](https://github.com/apache/nuttx/blob/master/mm/mm_heap/mm_free.c#L109-L112)

After cleaning up the logs: We get another corrupted printf Mutex....

```text
__JS_FindAtom: 0
toString
JS_DefineProperty: a
JS_CreateProperty: a
JS_DefineProperty: a
JS_CreateProperty: a
mm_free: Freeing 0xc0214c90
mm_malloc: Allocated 0xc0215250, size 48
mm_malloc: Allocated 0xc0214c90, size 64
mm_free: Freeing 0xc0215250
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0055e9c, MTVAL: 0000000000000223
```

From here...

```text
/Users/Luppy/riscv/nuttx/libs/libc/stream/lib_stdoutstream.c:157
   * opened in binary mode.  In binary mode, the newline has no special
   * meaning.
   */

#ifndef CONFIG_STDIO_DISABLE_BUFFERING
  if (handle->fs_bufstart != NULL && (handle->fs_oflags & O_TEXT) != 0)
    c0055e9c:	6db8                	ld	a4,88(a1)
/Users/Luppy/riscv/nuttx/libs/libc/stream/lib_stdoutstream.c:164
      stream->common.flush = stdoutstream_flush;
    }
  else
#endif
```

STDIO Buffer is corrupted! We disable STDIO Buffering for now: `make menuconfig` > Library Routines > Standard C I/O > Disable STDIO Buffering

Now we are back to STDIO Mutex problem...

```text
__JS_FindAtom: 0
toString
JS_DefineProperty: a
JS_CreateProperty: a
JS_DefineProperty: a
JS_CreateProperty: a
mm_free: Freeing 0xc0214bc0
mm_malloc: Allocated 0xc0215180, size 48
mm_malloc: Allocated 0xc0214bc0, size 64
mm_free: Freeing 0xc0215180
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0053044, MTVAL: 000000000000012b
```

From here...

```text
/Users/Luppy/riscv/nuttx/libs/libc/misc/lib_mutex.c:148
bool nxmutex_is_hold(FAR mutex_t *mutex) {
    c005303e:	1141                	addi	sp,sp,-16
    c0053040:	e406                	sd	ra,8(sp)
    c0053042:	e022                	sd	s0,0(sp)
/Users/Luppy/riscv/nuttx/libs/libc/misc/lib_mutex.c:149
  return mutex->holder == _SCHED_GETTID();
    c0053044:	4d00                	lw	s0,24(a0)
    c0053046:	047030ef          	jal	ra,c005688c <gettid>
```

Which comes from fprintf(). So we [change fprintf() to write()](https://github.com/lupyuen/quickjs-nuttx/commit/28b001034e18e23b58825e942b8a70e18a98fa84#diff-95fe784bea3e0fbdf30ba834b1a74b538090f4d70f4f8770ef397ef68ec37aa3) because it doesn't use Mutex.

# Unexpected Character in QuickJS

TODO

Now we see...

```text
js_dump_obj: SyntaxError: unexpected character
__JS_FindAtom: 0
stack
js_dump_obj:     at <cmdline>:1
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c000697c, MTVAL: 00000008c0212088
```

_What is this unexpected character?_

We [log the unexpected character](https://github.com/lupyuen/quickjs-nuttx/commit/6435e45d09016a8b9fbc29fdae707c59d876e20e#diff-45f1ae674139f993bf8a99c382c1ba4863272a6fec2f492d76d7ff1b2cfcfbe2). And we see our old friend FF...

```text
__JS_FindAtom: __loadScript
mm_malloc: Allocated 0xc0214d80, size 560
__JS_FindAtom: <cmdline>
mm_malloc: Allocated 0xc0214bc0, size 48
mm_malloc: Allocated 0xc0214bf0, size 32
next_token: c0=00000000000000FF
next_token: c=00000000000000FF
next_token: c2=FFFFFFFFFFFFFFFF
```

# Malloc Problems in NuttX

TODO

We [logged the calls to malloc](https://github.com/lupyuen/quickjs-nuttx/commit/571b0487ed86d00cfaa15e0a3e5ff1e370844c55#diff-45f1ae674139f993bf8a99c382c1ba4863272a6fec2f492d76d7ff1b2cfcfbe2)...

```c
void *js_malloc(JSContext *ctx, size_t size)
{
    void *ptr;
_d("js_malloc: a="); _d(debug_expr); _d("\n"); ////
    ptr = js_malloc_rt(ctx->rt, size);
_d("js_malloc: b="); _d(debug_expr); _d("\n"); ////
    if (unlikely(!ptr)) {
_d("js_malloc: b="); _d(debug_expr); _d("\n"); ////
        JS_ThrowOutOfMemory(ctx);
        return NULL;
    }
_d("js_malloc: d="); _d(debug_expr); _d("\n"); ////
    return ptr;
}
```

Something strange happens...

```text
js_malloc: a=console.log(123)
js_def_malloc: a=console.log(123)
js_def_malloc: b=console.log(123)
mm_malloc: Allocated 0xc0205580, size 112
js_def_malloc: c=
js_def_malloc: d=
```

NuttX malloc() erased our JavaScript from the Command-Line Arg!

Why? We [switched to our own barebones malloc](https://github.com/lupyuen/quickjs-nuttx/commit/3283e9f16631f6d9f1babbe2e0cd5cba635f34e0) for testing.

But nope doesn't work.

We [copied the Command-Line Arg to Local Buffer](https://github.com/lupyuen/quickjs-nuttx/commit/a4e0b308089c69ce08439a7812fbe1a8836dfc6e#diff-93a38cdf6b6645fff66fa78773011a5330ea9ed48cc1f70f4c65a6f6b707e246). Works much better!

# NuttX Stack is Full of QuickJS

TODO

Let's increase the Stack Size, it's 100% full...

```text
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0006d52, MTVAL: ffffffffffffffff
...
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x802002b0      2048      2040    99.6%!   irq
dump_task:       0     0   0 FIFO     Kthread - Ready              0000000000000000 0x80206010      3056      1856    60.7%    Idle_Task
dump_task:       1     1 100 RR       Kthread - Waiting Semaphore  0000000000000000 0x8020a050      1968       704    35.7%    lpwork 0x802015f0 0x80201618
dump_task:       2     2 100 RR       Task    - Waiting Semaphore  0000000000000000 0xc0202040      3008       744    24.7%    /system/bin/init
dump_task:       3     3 100 RR       Task    - Running            0000000000000000 0xc0202050      1968      1968   100.0%!   qjs }¼uq¦ü®઄²äÅ
```

We follow these steps to [increase Stack Size](https://github.com/lupyuen/nuttx-star64#increase-stack-size): `make menuconfig` > Library Routines > Program Execution Options > Default task_spawn Stack Size. Set to 8192

Here are all the settings we changed so far...

```bash
CONFIG_POSIX_SPAWN_DEFAULT_STACKSIZE=8192
## Remove CONFIG_SYSLOG_TIMESTAMP=y
```

QuickJS on NuttX QEMU prints 123 correctly yay! [nuttx/qemu.log](nuttx/qemu.log)

```text
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs -e console.log(123) 
123
nsh>
```

# Fix QuickJS Interactive Mode on NuttX

TODO

But QuickJS nteractive Mode REPL fails. Need to increase stack some more. We see our old friend 8_c021_8308, which appears when we run out of stack

```text
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c0006484, MTVAL: 00000008c0218308
```

We increase Stack from 8 KB to 16 KB (looks too little?)...

```bash
CONFIG_POSIX_SPAWN_DEFAULT_STACKSIZE=16384
```

Oops too much (I think)...

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs -e console.log(123) 
_assert: Current Version: NuttX  12.4.0-RC0 f8b0b06-dirty Feb 11 2024 08:30:16 risc-v
_assert: Assertion failed : at file: common/riscv_createstack.c:89 task: /system/bin/init process: /system/bin/init 0xc000004a
```

Which comes from [riscv_createstack.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_createstack.c#L82-L89)

```c
int up_create_stack(struct tcb_s *tcb, size_t stack_size, uint8_t ttype) {
#ifdef CONFIG_TLS_ALIGNED
  /* The allocated stack size must not exceed the maximum possible for the
   * TLS feature.
   */
  DEBUGASSERT(stack_size <= TLS_MAXSTACK);
```

We increase CONFIG_TLS_LOG2_MAXSTACK from 13 to 14:
- Library Routines > Thread Local Storage (TLS) > Maximum stack size (log2)
- Set to 14

Stack is still full. Increase Stack some more...

```text
→ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic
ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 00000000c005cc8c, MTVAL: 0000000000040129
...
SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x802002b0      2048      2040    99.6%!   irq
dump_task:       0     0   0 FIFO     Kthread - Ready              0000000000000000 0x80206010      3056      1440    47.1%    Idle_Task
dump_task:       1     1 100 RR       Kthread - Waiting Semaphore  0000000000000000 0x8020c050      1968       704    35.7%    lpwork 0x802015f0 0x80201618
dump_task:       2     2 100 RR       Task    - Waiting Semaphore  0000000000000000 0xc0204040      3008       744    24.7%    /system/bin/init
dump_task:       3     3 100 RR       Task    - Running            0000000000000000 0xc0204030     16336     16320    99.9%!   qjs
```

We increase the Stack to 64 KB...

```bash
CONFIG_POSIX_SPAWN_DEFAULT_STACKSIZE=65536
CONFIG_TLS_LOG2_MAXSTACK=16
```

QuickJS Interactive Mode REPL finally works OK on NuttX QEMU (64-bit RISC-V) yay!

```text
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic

ABC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > console.log(123)
123
undefined
qjs > 
```

# QuickJS calls POSIX `open()` on NuttX

TODO

[POSIX `open()`](https://bellard.org/quickjs/quickjs.html#os-module) works OK too!

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> ls /system/bin/init
 /system/bin/init
nsh> qjs
QuickJS - Type "\h" for help
qjs > os.open("/system/bin/init", os.O_RDONLY)
3
qjs > os.open("/system/bin/init", os.O_RDONLY)
4
qjs > os.open("/system/bin/init", os.O_RDONLY)
5
```

We update our Expect Script for Automated Testing of QuickJS Interactive Mode REPL: [nuttx/qemu.exp](nuttx/qemu.exp)

```bash
## Wait for the prompt and enter this command
expect "nsh> "
send -s "qjs \r"

expect "qjs > "
send -s "console.log(123) \r"

expect "qjs > "
send -s "os.open('/system/bin/init', os.O_RDONLY) \r"

## Wait at most 30 seconds
set timeout 30

## Check the response...
expect {
  ## If we see this message, exit normally
  "qjs >" { exit 0 }

  ## If timeout, exit with an error
  timeout { exit 1 }
}
```

Current size of QuickJS....

```text
$ riscv64-unknown-elf-size ../apps/bin/qjs
   text    data     bss     dec     hex filename
 554847     260      94  555201   878c1 ../apps/bin/qjs
```

Mostly Text (Code), very little Data and BSS. Most of the Dynamic Data comes from the Heap. Stack is currently under 64 KB, but above 16 KB.

# Add ioctl() to QuickJS for NuttX

TODO

Let's add ioctl() so we can control the NuttX LED Driver (and other devices)!

We copied os.seek() from QuickJS and modded it [to become os.ioctl()](https://github.com/lupyuen/quickjs-nuttx/commit/91aaf4257992c08b01590f0d61fa37a386933a4b#diff-95fe784bea3e0fbdf30ba834b1a74b538090f4d70f4f8770ef397ef68ec37aa3)...

```c
static const JSCFunctionListEntry js_os_funcs[] = {
    ...
    JS_CFUNC_DEF("ioctl", 3, js_os_ioctl ),
    ...
};

static JSValue js_os_ioctl(JSContext *ctx, JSValueConst this_val,
                           int argc, JSValueConst *argv)
{
    int fd, req;
    int64_t arg, ret;
    BOOL is_bigint;
    
    if (JS_ToInt32(ctx, &fd, argv[0]))
        return JS_EXCEPTION;
    if (JS_ToInt32(ctx, &req, argv[1]))
        return JS_EXCEPTION;
    is_bigint = JS_IsBigInt(ctx, argv[2]);
    if (JS_ToInt64Ext(ctx, &arg, argv[2]))
        return JS_EXCEPTION;
    ret = ioctl(fd, req, arg);
    if (ret == -1)
        ret = -errno;
    if (is_bigint)
        return JS_NewBigInt64(ctx, ret);
    else
        return JS_NewInt64(ctx, ret);
}
```

TODO: Is arg int32 or int64?

Yep it seems to work...

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> qjs
QuickJS - Type "\h" for help
qjs > os.ioctl
function ioctl()
qjs > os.ioctl(1,2,3)
-25
qjs > os.ioctl(100,2,3)
-9
qjs > 
```

Let's test QuickJS ioctl() with NuttX LED Driver...

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
