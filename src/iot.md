# Build an IoT App with Zig and LoRaWAN

📝 _16 Jun 2022_

![Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/iot-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)_

In our last article we learnt to run barebones __Zig on a Microcontroller__ (RISC-V BL602) with a __Real-Time Operating System__ (Apache NuttX RTOS)...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

_But can we do something way more sophisticated with Zig?_

Yes we can! Today we shall run a complex __IoT Application__ with __Zig and LoRaWAN__...

-   Join a [__LoRaWAN Wireless Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

-   Transmit a __Data Packet__ to the LoRaWAN Network at regular intervals

Which is the typical firmware we would run on __IoT Sensors__.

_Will this run on any device?_

We'll do this on Pine64's [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board.

But the steps should be similar for BL602, ESP32-C3, Arm Cortex-M and other 32-bit microcontrollers supported by Zig.

_Why are we doing this?_

I always dreaded maintaining and extending complex __IoT Apps in C__. [(Like this one)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c)

Will Zig make this a little less painful? Let's find out!

This is the Zig source code that we'll study today...

-   [__lupyuen/zig-bl602-nuttx__](https://github.com/lupyuen/zig-bl602-nuttx)

![Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left). This works too!](https://lupyuen.github.io/images/spi2-title.jpg)

[_Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left). This works too!_](https://lupyuen.github.io/articles/spi2)

# LoRaWAN Network Stack

_What's a LoRaWAN Network Stack?_

To talk to a LoRaWAN Wireless Network, our IoT Gadget needs 3 things...

-   __LoRa Radio Transceiver__

    [(Like PineDio Stack's onboard Semtech SX1262 Transceiver)](https://www.semtech.com/products/wireless-rf/lora-core/sx1262)

-   __LoRa Driver__ that will transmit and receive raw LoRa Packets

    (By controlling the LoRa Transceiver over SPI)

-   __LoRaWAN Driver__ that will join a LoRaWAN Network and transmit LoRaWAN Data Packets

    (By calling the LoRa Driver)

Together, the LoRa Driver and LoRaWAN Driver make up the __LoRaWAN Network Stack__.

_Which LoRaWAN Stack will we use?_

We'll use __Semtech's Reference Implementation__ of the LoRaWAN Stack...

-   [__Lora-net/LoRaMac-node__](https://github.com/Lora-net/LoRaMac-node)

That we've ported to PineDio Stack BL604 with __Apache NuttX RTOS__...

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

The same LoRaWAN Stack is available on many other platforms, including [__Zephyr OS__](https://docs.zephyrproject.org/latest/connectivity/lora_lorawan/index.html) and [__Arduino__](beegee-tokyo/SX126x-Arduino).

[(My good friend JF has ported the stack to Linux)](https://codeberg.org/JF002/loramac-node)

_But the LoRaWAN Stack is in C! Will it work with Zig?_

Yep no worries! Zig will happily __import the LoRaWAN Stack from C__ without any wrappers or modifications.

And we'll call the LoRaWAN Stack as though it were a Zig Library!

_So we're not rewriting the LoRaWAN Stack in Zig?_

Rewriting the LoRaWAN Stack in Zig (or another language) sounds risky because the LoRaWAN Stack is still under [__Active Development__](https://github.com/Lora-net/LoRaMac-node/commits/master). It can change at any moment!

We'll stick with the __C Implementation__ of the LoRaWAN Stack so that our Zig IoT App will enjoy the latest LoRaWAN updates and features.

[(More about this)](https://lupyuen.github.io/articles/zig#why-zig)

![Import LoRaWAN Library](https://lupyuen.github.io/images/iot-code2a.png)

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L5-L48)

# Import LoRaWAN Library

Let's dive into our Zig IoT App! We import the [__Zig Standard Library__](https://lupyuen.github.io/articles/zig#import-standard-library) at the top of our app: [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L5-L48)

```zig
/// Import the Zig Standard Library
const std = @import("std");
```

Next we call [__@cImport__](https://ziglang.org/documentation/master/#cImport) to import the __C Macros and C Hander Files__...

```zig
/// Import the LoRaWAN Library from C
const c = @cImport({
  // Define C Macros for NuttX on RISC-V, equivalent to...
  // #define __NuttX__
  // #define NDEBUG
  // #define ARCH_RISCV

  @cDefine("__NuttX__",  "");
  @cDefine("NDEBUG",     "");
  @cDefine("ARCH_RISCV", "");
```

The code above defines the __C Macros__ that will be called by the C Header Files coming up.

Next comes a workaround for a __C Macro Error__ that appears on Zig with Apache NuttX RTOS...

```zig
  // Workaround for "Unable to translate macro: undefined identifier `LL`"
  @cDefine("LL", "");
  @cDefine("__int_c_join(a, b)", "a");  //  Bypass zig/lib/include/stdint.h
```

[(More about this)](https://lupyuen.github.io/articles/iot#appendix-macro-error)

We import the __C Header Files__ for Apache NuttX RTOS...

```zig
  // Import the NuttX Header Files from C, equivalent to...
  // #include <arch/types.h>
  // #include <../../nuttx/include/limits.h>
  // #include <stdio.h>

  @cInclude("arch/types.h");
  @cInclude("../../nuttx/include/limits.h");
  @cInclude("stdio.h");
```

Followed by the C Header Files for our __LoRaWAN Library__...

```zig
  // Import LoRaWAN Header Files from C, based on
  // https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c#L24-L40
  @cInclude("firmwareVersion.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/githubVersion.h");
  @cInclude("../libs/liblorawan/src/boards/utilities.h");
  @cInclude("../libs/liblorawan/src/mac/region/RegionCommon.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/Commissioning.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandler/LmHandler.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandler/packages/LmhpCompliance.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandler/packages/LmhpClockSync.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandler/packages/LmhpRemoteMcastSetup.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandler/packages/LmhpFragmentation.h");
  @cInclude("../libs/liblorawan/src/apps/LoRaMac/common/LmHandlerMsgDisplay.h");
});
```

[(Based on this C code)](https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c#L24-L40)

The LoRaWAN Library is now ready to be called by our Zig App!

This is how we reference the LoRaWAN Library to define our [__LoRaWAN Region__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country/)...

```zig
/// LoRaWAN Region
const ACTIVE_REGION = c.LORAMAC_REGION_AS923;
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L44-L86)

_Why the "__`c.`__" in `c.LORAMAC_REGION_AS923`?_

Remember that we imported the LoRaWAN Library under the __Namespace "`c`"__...

```zig
/// Import the LoRaWAN Library under Namespace "c"
const c = @cImport({ ... });
```

Hence we use "`c.something`" to refer to the Constants and Functions defined in the LoRaWAN Library.

_Why did we define the C Macros like `__NuttX__`?_

These C Macros are needed by the __NuttX Header Files__.

Without the macros, the NuttX Header Files won't be imported correctly into Zig. [(See this)](https://lupyuen.github.io/articles/iot#appendix-zig-compiler-as-drop-in-replacement-for-gcc)

_Why did we import "arch/types.h"?_

This fixes a problem with the __NuttX Types__. [(See this)](https://lupyuen.github.io/articles/iot#appendix-zig-compiler-as-drop-in-replacement-for-gcc)

Let's head over to the Main Function...

# Main Function

This is the [__Main Function__](https://lupyuen.github.io/articles/zig#main-function) for our Zig App: [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L90-L158)

```zig
/// Main Function that will be called by NuttX.
/// We call the LoRaWAN Library to join a 
/// LoRaWAN Network and send a Data Packet.
pub export fn lorawan_test_main(
  _argc: c_int, 
  _argv: [*]const [*]const u8
) c_int {
  _ = _argc;
  _ = _argv;

  // Init the Timer Struct at startup
  TxTimer = std.mem.zeroes(c.TimerEvent_t);
```

[(We init __TxTimer__ here because of this)](https://lupyuen.github.io/articles/iot#appendix-struct-initialisation-error)

We begin by computing the randomised __interval between transmissions__ of LoRaWAN Data Packets...

```zig
  // Compute the interval between transmissions based on Duty Cycle
  TxPeriodicity = @bitCast(u32,  // Cast to u32 because randr() can be negative
    APP_TX_DUTYCYCLE +
    c.randr(
      -APP_TX_DUTYCYCLE_RND,
      APP_TX_DUTYCYCLE_RND
    )
  );
```

(We'll talk about __@bitCast__ in a while)

Next we show the __App Version__...

```zig
  // Show the Firmware and GitHub Versions
  const appVersion = c.Version_t {
    .Value = c.FIRMWARE_VERSION,
  };
  const gitHubVersion = c.Version_t {
    .Value = c.GITHUB_VERSION,
  };
  c.DisplayAppInfo("Zig LoRaWAN Test", &appVersion, &gitHubVersion);
```

We __initialise the LoRaWAN Library__...

```zig
  // Init LoRaWAN
  if (LmHandlerInit(&LmHandlerCallbacks, &LmHandlerParams)
    != c.LORAMAC_HANDLER_SUCCESS) {
    std.log.err("LoRaMac wasn't properly initialized", .{});

    // Fatal error, endless loop.
    while (true) {}
  }
```

We set the __Max Tolerated Receive Error__...

```zig
  // Set system maximum tolerated rx error in milliseconds
  _ = c.LmHandlerSetSystemMaxRxError(20);
```

And we load some packages for __LoRaWAN Compliance__...

```zig
  // The LoRa-Alliance Compliance protocol package should always be initialized and activated.
  _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_COMPLIANCE,         &LmhpComplianceParams);
  _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_CLOCK_SYNC,         null);
  _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_REMOTE_MCAST_SETUP, null);
  _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_FRAGMENTATION,      &FragmentationParams);
```

Everything is hunky dory! We can now transmit a LoRaWAN Request to __join the LoRaWAN Network__...

```zig
  // Init the Clock Sync and File Transfer status
  IsClockSynched     = false;
  IsFileTransferDone = false;

  // Join the LoRaWAN Network
  c.LmHandlerJoin();
```

[(LoRaWAN Keys and EUIs are defined here)](https://github.com/Lora-net/LoRaMac-node/blob/master/src/peripherals/soft-se/se-identity.h)

We start the __Transmit Timer__ that will send a LoRaWAN Data Packet at periodic intervals (right after we join the LoRaWAN Network)...

```zig
  // Set the Transmit Timer
  StartTxProcess(LmHandlerTxEvents_t.LORAMAC_HANDLER_TX_ON_TIMER);
```

Finally we loop forever handling __LoRaWAN Events__...

```zig
  // Handle LoRaWAN Events
  handle_event_queue();  //  Never returns
  return 0;
}
```

(We'll talk about __handle_event_queue__ in a while)

That's all for the Main Function of our Zig App!

_Wait... Our Zig Code looks familiar?_

Yep our Zig Code is largely identical to the __C Code in the Demo App__ for the LoRaWAN Stack...

-   [__LoRaMac/fuota-test-01/main.c__](https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c#L314-L390)

    (Pic below)

__Converting C Code to Zig__ looks rather straightforward! In a while we'll talk about the tricky parts we encountered during the conversion.

![Demo App for the LoRaWAN Stack](https://lupyuen.github.io/images/iot-code1a.png)

[(Source)](https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c#L314-L390)

# Cast To Unsigned Integer

TODO

[lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L106-L113)

```zig
// In Zig: This is an unsigned integer (32-bit)
var TxPeriodicity: u32 = 0;

// Compute the interval between transmissions based on Duty Cycle.
// Cast to u32 because randr() can be negative.
TxPeriodicity = @bitCast(u32,
  APP_TX_DUTYCYCLE +
  c.randr(
    -APP_TX_DUTYCYCLE_RND,
    APP_TX_DUTYCYCLE_RND
  )
);
```

TODO

```c
// In C: This is an unsigned integer (32-bit)
uint32_t TxPeriodicity = 0;

// Compute the interval between transmissions based on Duty Cycle.
// Remember that randr() can be negative.
TxPeriodicity = 
  APP_TX_DUTYCYCLE + 
  randr( 
    -APP_TX_DUTYCYCLE_RND, 
    APP_TX_DUTYCYCLE_RND 
  );
```

[(Source)](https://github.com/Lora-net/LoRaMac-node/blob/master/src/apps/LoRaMac/fuota-test-01/B-L072Z-LRWAN1/main.c#L330-L333)

TODO

```text
unsigned 32-bit int cannot represent 
all possible signed 32-bit values
```

TODO

# Transmit Data Packet

TODO

[lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L163-L203)

```zig
/// Prepare the payload of a Data Packet transmit it
fn PrepareTxFrame() void {
  // If we haven't joined the LoRaWAN Network, try again later
  if (c.LmHandlerIsBusy()) {
    debug("PrepareTxFrame: Busy", .{});
    return;
  }

  // Send a message to LoRaWAN
  const msg: []const u8 = "Hi NuttX\x00";  // 9 bytes including null
  debug("PrepareTxFrame: Transmit to LoRaWAN ({} bytes): {s}", .{ 
    msg.len, msg 
  });

  // Compose the transmit request
  std.mem.copy(
    u8, 
    AppDataBuffer[0..msg.len], 
    msg[0..msg.len]
  );
  var appData = c.LmHandlerAppData_t {
    .Buffer     = @ptrCast([*c]u8, &AppDataBuffer),
    .BufferSize = msg.len,
    .Port       = 1,
  };

  // Validate the message size and check if it can be transmitted
  var txInfo: c.LoRaMacTxInfo_t = undefined;
  const status = c.LoRaMacQueryTxPossible(appData.BufferSize, &txInfo);
  debug("PrepareTxFrame: status={}, maxSize={}, currentSize={}", .{
    status, 
    txInfo.MaxPossibleApplicationDataSize, 
    txInfo.CurrentPossiblePayloadSize
  });
  assert(status == c.LORAMAC_STATUS_OK);

  // Transmit the message
  const sendStatus = c.LmHandlerSend(&appData, LmHandlerParams.IsTxConfirmed);
  assert(sendStatus == c.LORAMAC_HANDLER_SUCCESS);
  debug("PrepareTxFrame: Transmit OK", .{});
}
```

TODO: 9 bytes or shorter

# Convert LoRaWAN App to Zig

TODO

Finally we convert the LoRaWAN App [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c) from C to Zig, to show that we can build Complex IoT Apps in Zig.

The LoRaWAN App runs on PineDio Stack BL604 (RISC-V). The app connects to a LoRaWAN Gateway (like ChirpStack or The Things Network) and sends a Data Packet at regular intervals.

Here's the original C code: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c)

(700 lines of C code)

And our converted LoRaWAN Zig App: [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)

(673 lines of Zig code)

To compile the LoRaWAN Zig App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)...

```bash
##  Download our LoRaWAN Zig App for NuttX
git clone --recursive https://github.com/lupyuen/zig-bl602-nuttx
cd zig-bl602-nuttx

##  Compile the Zig App for BL602 (RV32IMACF with Hardware Floating-Point)
zig build-obj \
  --verbose-cimport \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -isystem "$HOME/nuttx/nuttx/include" \
  -I "$HOME/nuttx/apps/examples/lorawan_test" \
  lorawan_test.zig

##  Patch the ELF Header of `lorawan_test.o` from Soft-Float ABI to Hard-Float ABI
xxd -c 1 lorawan_test.o \
  | sed 's/00000024: 01/00000024: 03/' \
  | xxd -r -c 1 - lorawan_test2.o
cp lorawan_test2.o lorawan_test.o

##  Copy the compiled app to NuttX and overwrite `lorawan_test.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp lorawan_test.o $HOME/nuttx/apps/examples/lorawan_test/*lorawan_test.o

##  Build NuttX to link the Zig Object from `lorawan_test.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

![](https://lupyuen.github.io/images/iot-code3a.png)

TODO

```text
+ pushd ../zig-bl602-nuttx
~/nuttx/zig-bl602-nuttx ~/nuttx/nuttx
+ zig build-obj --verbose-cimport -target riscv32-freestanding-none -mcpu=baseline_rv32-d -isystem /home/user/nuttx/nuttx/include -I /home/user/nuttx/apps/examples/lorawan_test lorawan_test.zig
info(compilation): C import source: zig-cache/o/08fa8a0a89d15e88ae63a9f8e0af6c91/cimport.h
info(compilation): C import .d file: zig-cache/o/08fa8a0a89d15e88ae63a9f8e0af6c91/cimport.h.d
info(compilation): C import output: zig-cache/o/adbf03c74d351db638f34bb5535a8c3b/cimport.zig
+ xxd -c 1 lorawan_test.o
+ sed 's/00000024: 01/00000024: 03/'
+ xxd -r -c 1 - lorawan_test2.o
+ cp lorawan_test2.o lorawan_test.o
+ cp lorawan_test.o /home/user/nuttx/apps/examples/lorawan_test/lorawan_test_main.c.home.user.nuttx.apps.examples.lorawan_test.o
+ ls -l lorawan_test.o /home/user/nuttx/apps/examples/lorawan_test/lorawan_test_main.c.home.user.nuttx.apps.examples.lorawan_test.o
-rw-r--r-- 1 user user 467724 Jun 10 16:44 /home/user/nuttx/apps/examples/lorawan_test/lorawan_test_main.c.home.user.nuttx.apps.examples.lorawan_test.o
-rw-r--r-- 1 user user 467724 Jun 10 16:44 lorawan_test.o
+ popd
~/nuttx/nuttx
```

# Refer to Auto-Translated Zig Code

TODO

Some parts of the LoRaWAN Zig App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig) can get tricky to convert from C to Zig, like this C code...

```c
//  Original C code...
#define APP_TX_DUTYCYCLE     40000
#define APP_TX_DUTYCYCLE_RND  5000

uint32_t TxPeriodicity = 
    APP_TX_DUTYCYCLE +
    randr( 
        -APP_TX_DUTYCYCLE_RND, 
        APP_TX_DUTYCYCLE_RND
    );
```

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L283-L286)

Which has conflicting signed (`randr`) and unsigned (`APP_TX_DUTYCYCLE`) types.

We get help by referring to the auto-translated Zig Code: [translated/lorawan_test_main.zig](translated/lorawan_test_main.zig)

```zig
//  Converted from C to Zig...
const APP_TX_DUTYCYCLE:     c_int = 40000;
const APP_TX_DUTYCYCLE_RND: c_int = 5000;

//  Cast to u32 because randr() can be negative
var TxPeriodicity: u32 = @bitCast(u32,
    APP_TX_DUTYCYCLE +
    c.randr(
        -APP_TX_DUTYCYCLE_RND,
        APP_TX_DUTYCYCLE_RND
    )
);
```

Which resolves the conflicting types by casting the signed result to become unsigned.

# LoRaWAN Zig App Runs OK!

TODO

After fixing the above issues, we test the LoRaWAN Zig App on NuttX: [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)

```text
nsh> lorawan_test
Application name   : Zig LoRaWAN Test
...
###### =========== MLME-Confirm ============ ######
STATUS      : OK
###### ===========   JOINED     ============ ######
OTAA
DevAddr     :  00D803AB
DATA RATE   : DR_2
...
PrepareTxFrame: Transmit to LoRaWAN (9 bytes): Hi NuttX
###### =========== MCPS-Confirm ============ ######
STATUS      : OK
###### =====   UPLINK FRAME        1   ===== ######
CLASS       : A
TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00
DATA RATE   : DR_3
U/L FREQ    : 923200000
TX POWER    : 0
CHANNEL MASK: 0003
```

[(See the complete log)](https://gist.github.com/lupyuen/0871ac515b18d9d68d3aacf831fd0f5b)

LoRaWAN Zig App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig) successfully joins the LoRaWAN Network (ChirpStack on RAKwireless WisGate) and sends a Data Packet to the LoRaWAN Gateway yay!

# Safety Checks

TODO

The Zig Compiler reveals interesting insights when auto-translating our C code to Zig.

This C code copies an array, byte by byte...

```c
static int8_t FragDecoderWrite( uint32_t addr, uint8_t *data, uint32_t size ) {
    ...
    for(uint32_t i = 0; i < size; i++ ) {
        UnfragmentedData[addr + i] = data[i];
    }
    return 0; // Success
}
```

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L539-L550)

Here's the auto-translated Zig code...

```zig
pub fn FragDecoderWrite(arg_addr: u32, arg_data: [*c]u8, arg_size: u32) callconv(.C) i8 {
    ...
    var size = arg_size;
    var i: u32 = 0;
    while (i < size) : (i +%= 1) {
        UnfragmentedData[addr +% i] = data[i];
    }
    return 0;
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/translated/lorawan_test_main.zig#L4335-L4349)

Note that the Array Indexing in C...

```c
//  Array Indexing in C...
UnfragmentedData[addr + i]
```

Gets translated to this in Zig...

```zig
//  Array Indexing in Zig...
UnfragmentedData[addr +% i]
```

`+` in C becomes `+%` in Zig!

_What's `+%` in Zig?_

That's the Zig Operator for [__Wraparound Addition__](https://ziglang.org/documentation/master/#Wrapping-Operations).

Which means that the result wraps back to 0 (and beyond) if the addition overflows the integer.

But this isn't what we intended, since we don't expect the addition to overflow. That's why in our final converted Zig code, we revert `+%` back to `+`...

```zig
export fn FragDecoderWrite(addr: u32, data: [*c]u8, size: u32) i8 {
    ...
    var i: u32 = 0;
    while (i < size) : (i += 1) {
        UnfragmentedData[addr + i] = data[i];
    }
    return 0; // Success
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L407-L416)

_What happens if the addition overflows?_

We'll see a Runtime Error...

```text
panic: integer overflow
```

[(Source)](https://ziglang.org/documentation/master/#Integer-Overflow)

Which is probably a good thing, to ensure that our values are sensible.

_What if our Array Index goes out of bounds?_

We'll get this Runtime Error...

```text
panic: index out of bounds
```

[(Source)](https://ziglang.org/documentation/master/#Index-out-of-Bounds)

Here's the list of __Safety Checks__ done by Zig at runtime...

-   ["Undefined Behavior"](https://ziglang.org/documentation/master/#Undefined-Behavior)

If we prefer to live recklessly, this is how we disable the Safety Checks...

-   ["@setRuntimeSafety"](https://ziglang.org/documentation/master/#setRuntimeSafety)

# Panic Handler

TODO

_Some debug features don't seem to be working? Like `unreachable`, `std.debug.assert` and `std.debug.panic`?_

That's because for Embedded Platforms we need to implement our own Panic Handler...

-   ["Using Zig to Provide Stack Traces on Kernel Panic for a Bare Bones Operating System"](https://andrewkelley.me/post/zig-stack-traces-kernel-panic-bare-bones-os.html)

-   [Default Panic Handler: `std.debug.default_panic`](https://github.com/ziglang/zig/blob/master/lib/std/builtin.zig#L763-L847)

With our own Panic Handler, this Assertion Failure...

```zig
//  Create a short alias named `assert`
const assert = std.debug.assert;

//  Assertion Failure
assert(TxPeriodicity != 0);
```

Will show this Stack Trace...

```text
!ZIG PANIC!
reached unreachable code
Stack Trace:
0x23016394
0x23016ce0
```

According to our RISC-V Disassembly, the first address `23016394` doesn't look interesting, because it's inside the `assert` function...

```text
/home/user/zig-linux-x86_64-0.10.0-dev.2351+b64a1d5ab/lib/std/debug.zig:259
pub fn assert(ok: bool) void {
2301637c:	00b51c63          	bne	a0,a1,23016394 <std.debug.assert+0x2c>
23016380:	a009                j	23016382 <std.debug.assert+0x1a>
23016382:	2307e537          	lui	a0,0x2307e
23016386:	f9850513          	addi	a0,a0,-104 # 2307df98 <__unnamed_4>
2301638a:	4581                li	a1,0
2301638c:	00000097          	auipc	ra,0x0
23016390:	f3c080e7          	jalr	-196(ra) # 230162c8 <panic>
    if (!ok) unreachable; // assertion failure
23016394:	a009                j	23016396 <std.debug.assert+0x2e>
```

But the second address `23016ce0` reveals the assertion that failed...

```text
/home/user/nuttx/zig-bl602-nuttx/lorawan_test.zig:95
    assert(TxPeriodicity != 0);
23016ccc:	42013537          	lui	a0,0x42013
23016cd0:	fbc52503          	lw	a0,-68(a0) # 42012fbc <TxPeriodicity>
23016cd4:	00a03533          	snez	a0,a0
23016cd8:	fffff097          	auipc	ra,0xfffff
23016cdc:	690080e7          	jalr	1680(ra) # 23016368 <std.debug.assert>
/home/user/nuttx/zig-bl602-nuttx/lorawan_test.zig:100
    TxTimer = std.mem.zeroes(c.TimerEvent_t);
23016ce0:	42016537          	lui	a0,0x42016
```

This is our implementation of the Zig Panic Handler...

```zig
/// Called by Zig when it hits a Panic. We print the Panic Message, Stack Trace and halt. See 
/// https://andrewkelley.me/post/zig-stack-traces-kernel-panic-bare-bones-os.html
/// https://github.com/ziglang/zig/blob/master/lib/std/builtin.zig#L763-L847
pub fn panic(
    message: []const u8, 
    _stack_trace: ?*std.builtin.StackTrace
) noreturn {
    // Print the Panic Message
    _ = _stack_trace;
    _ = puts("\n!ZIG PANIC!");
    _ = puts(@ptrCast([*c]const u8, message));

    // Print the Stack Trace
    _ = puts("Stack Trace:");
    var it = std.debug.StackIterator.init(@returnAddress(), null);
    while (it.next()) |return_address| {
        _ = printf("%p\n", return_address);
    }

    // Halt
    while(true) {}
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L501-L522)

# Logging

TODO

We have implemented Debug Logging `std.log.debug` that's described here...

-   ["A simple overview of Zig's std.log"](https://gist.github.com/leecannon/d6f5d7e5af5881c466161270347ce84d)

Here's how we call `std.log.debug` to print a log message...

```zig
//  Create a short alias named `debug`
const debug  = std.log.debug;

//  Message with 8 bytes
const msg: []const u8 = "Hi NuttX";

//  Print the message
debug("Transmit to LoRaWAN ({} bytes): {s}", .{ 
    msg.len, msg 
});

// Prints: Transmit to LoRaWAN (8 bytes): Hi NuttX
```

`.{ ... }` creates an [__Anonymous Struct__](https://ziglearn.org/chapter-1/#anonymous-structs) with a variable number of arguments that will be passed to `std.log.debug` for printing.

Below is our implementation of `std.log.debug`...

```zig
/// Called by Zig for `std.log.debug`, `std.log.info`, `std.log.err`, ...
/// https://gist.github.com/leecannon/d6f5d7e5af5881c466161270347ce84d
pub fn log(
    comptime _message_level: std.log.Level,
    comptime _scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = _message_level;
    _ = _scope;

    // Format the message
    var buf: [100]u8 = undefined;  // Limit to 100 chars
    var slice = std.fmt.bufPrint(&buf, format, args)
        catch { _ = puts("*** log error: buf too small"); return; };
    
    // Terminate the formatted message with a null
    var buf2: [buf.len + 1 : 0]u8 = undefined;
    std.mem.copy(
        u8, 
        buf2[0..slice.len], 
        slice[0..slice.len]
    );
    buf2[slice.len] = 0;

    // Print the formatted message
    _ = puts(&buf2);
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L519-L546)

This implementation calls `puts()`, which is supported by Apache NuttX RTOS since it's [__POSIX-Compliant__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance).

![](https://lupyuen.github.io/images/iot-code4a.png)

# Compare C and Zig

TODO

The Original C Code and the Converted Zig Code for our LoRaWAN App look highly similar.

Here's the Main Function from our Original C Code...

```c
/// Main Function that will be called by NuttX. We call the LoRaWAN Library 
/// to Join a LoRaWAN Network and send a Data Packet.
int main(int argc, FAR char *argv[]) {
    //  If we are using Entropy Pool and the BL602 ADC is available,
    //  add the Internal Temperature Sensor data to the Entropy Pool
    init_entropy_pool();

    //  Compute the interval between transmissions based on Duty Cycle
    TxPeriodicity = APP_TX_DUTYCYCLE + randr( -APP_TX_DUTYCYCLE_RND, APP_TX_DUTYCYCLE_RND );

    const Version_t appVersion    = { .Value = FIRMWARE_VERSION };
    const Version_t gitHubVersion = { .Value = GITHUB_VERSION };
    DisplayAppInfo( "lorawan_test", 
                    &appVersion,
                    &gitHubVersion );

    //  Init LoRaWAN
    if ( LmHandlerInit( &LmHandlerCallbacks, &LmHandlerParams ) != LORAMAC_HANDLER_SUCCESS )
    {
        printf( "LoRaMac wasn't properly initialized\n" );
        //  Fatal error, endless loop.
        while ( 1 ) {}
    }

    // Set system maximum tolerated rx error in milliseconds
    LmHandlerSetSystemMaxRxError( 20 );

    // The LoRa-Alliance Compliance protocol package should always be initialized and activated.
    LmHandlerPackageRegister( PACKAGE_ID_COMPLIANCE, &LmhpComplianceParams );
    LmHandlerPackageRegister( PACKAGE_ID_CLOCK_SYNC, NULL );
    LmHandlerPackageRegister( PACKAGE_ID_REMOTE_MCAST_SETUP, NULL );
    LmHandlerPackageRegister( PACKAGE_ID_FRAGMENTATION, &FragmentationParams );

    IsClockSynched     = false;
    IsFileTransferDone = false;

    //  Join the LoRaWAN Network
    LmHandlerJoin( );

    //  Set the Transmit Timer
    StartTxProcess( LORAMAC_HANDLER_TX_ON_TIMER );

    //  Handle LoRaWAN Events
    handle_event_queue(NULL);  //  Never returns

    return 0;
}
```

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L271-L323)

And the Main Function from our Converted Zig Code (after some scrubbing)...

```zig
/// Main Function that will be called by NuttX. We call the LoRaWAN Library 
/// to Join a LoRaWAN Network and send a Data Packet.
pub export fn lorawan_test_main(
    _argc: c_int, 
    _argv: [*]const [*]const u8
) c_int {
    _ = _argc;
    _ = _argv;

    // Init the Timer Struct at startup
    TxTimer = std.mem.zeroes(c.TimerEvent_t);

    // If we are using Entropy Pool and the BL602 ADC is available,
    // add the Internal Temperature Sensor data to the Entropy Pool
    // TODO: init_entropy_pool();

    // Compute the interval between transmissions based on Duty Cycle
    TxPeriodicity = @bitCast(u32,  // Cast to u32 because randr() can be negative
        APP_TX_DUTYCYCLE +
        c.randr(
            -APP_TX_DUTYCYCLE_RND,
            APP_TX_DUTYCYCLE_RND
        )
    );

    // Show the Firmware and GitHub Versions
    const appVersion = c.Version_t {
        .Value = c.FIRMWARE_VERSION,
    };
    const gitHubVersion = c.Version_t {
        .Value = c.GITHUB_VERSION,
    };
    c.DisplayAppInfo("Zig LoRaWAN Test", &appVersion, &gitHubVersion);

    // Init LoRaWAN
    if (LmHandlerInit(&LmHandlerCallbacks, &LmHandlerParams)
        != c.LORAMAC_HANDLER_SUCCESS) {
        std.log.err("LoRaMac wasn't properly initialized", .{});
        // Fatal error, endless loop.
        while (true) {}
    }

    // Set system maximum tolerated rx error in milliseconds
    _ = c.LmHandlerSetSystemMaxRxError(20);

    // The LoRa-Alliance Compliance protocol package should always be initialized and activated.
    _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_COMPLIANCE,         &LmhpComplianceParams);
    _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_CLOCK_SYNC,         null);
    _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_REMOTE_MCAST_SETUP, null);
    _ = c.LmHandlerPackageRegister(c.PACKAGE_ID_FRAGMENTATION,      &FragmentationParams);

    // Init the Clock Sync and File Transfer status
    IsClockSynched     = false;
    IsFileTransferDone = false;

    // Join the LoRaWAN Network
    c.LmHandlerJoin();

    // Set the Transmit Timer
    StartTxProcess(LmHandlerTxEvents_t.LORAMAC_HANDLER_TX_ON_TIMER);

    // Handle LoRaWAN Events
    handle_event_queue();  //  Never returns

    return 0;
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L90-L158)

# What's Next

TODO: Clean up names of Types, Functions and Variables

TODO: Read the Internal Temperature Sensor

TODO: Encode the Temperature Sensor Data with TinyCBOR and transmit to The Things Network

https://lupyuen.github.io/articles/cbor2

TODO: Monitor sensor data with Prometheus and Grafana

https://lupyuen.github.io/articles/prometheus

TODO: Add new code with `@import()`

https://zig.news/mattnite/import-and-packages-23mb

TODO: Do we need to align buffers to 32 bits when exporting to C?

```zig
/// User application data
/// (Aligned to 32-bit because it's exported to C)
var AppDataBuffer: [LORAWAN_APP_DATA_BUFFER_MAX_SIZE]u8 align(4) = 
    std.mem.zeroes([LORAWAN_APP_DATA_BUFFER_MAX_SIZE]u8);
```

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/iot.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/iot.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1533595486577258496)

1.  This article was inspired by a question from my [__GitHub Sponsor__](https://github.com/sponsors/lupyuen): "Can we run Zig on BL602 with Apache NuttX RTOS?"

# Appendix: Zig Compiler as Drop-In Replacement for GCC

TODO

_Will Zig Compiler work as [Drop-In Replacement for GCC](https://lupyuen.github.io/articles/zig#why-zig) for compiling NuttX Libraries?_

Let's test it on the [LoRa SX1262 Library](https://lupyuen.github.io/articles/sx1262) for Apache NuttX RTOS!

Here's how NuttX compiles the [LoRa SX1262 Library](https://lupyuen.github.io/articles/sx1262) with GCC...

```bash
##  LoRa SX1262 Source Directory
cd $HOME/nuttx/nuttx/libs/libsx1262

##  Compile radio.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/radio.c \
  -o  src/radio.o

##  Compile sx126x.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/sx126x.c \
  -o  src/sx126x.o

##  Compile sx126x-nuttx.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/sx126x-nuttx.c \
  -o  src/sx126x-nuttx.o
```

(We observed this with `make --trace` while building NuttX)

We make these changes...

-   Change `riscv64-unknown-elf-gcc` to `zig cc`

-   Add the target `-target riscv32-freestanding-none -mcpu=baseline_rv32-d`

-   Remove `-march=rv32imafc`

And we run this...

```bash
##  LoRa SX1262 Source Directory
cd $HOME/nuttx/nuttx/libs/libsx1262

##  Compile radio.c with zig cc
zig cc \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/radio.c \
  -o  src/radio.o

##  Compile sx126x.c with zig cc
zig cc \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/sx126x.c \
  -o  src/sx126x.o

##  Compile sx126x-nuttx.c with zig cc
zig cc \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/sx126x-nuttx.c \
  -o  src/sx126x-nuttx.o

##  Link Zig Object Files with NuttX after compiling with `zig cc`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

Zig Compiler shows these errors...

```text
In file included from src/sx126x-nuttx.c:3:
In file included from nuttx/include/debug.h:39:
In file included from nuttx/include/sys/uio.h:45:
nuttx/include/sys/types.h:119:9: error: unknown type name '_size_t'
typedef _size_t      size_t;
        ^
nuttx/include/sys/types.h:120:9: error: unknown type name '_ssize_t'
typedef _ssize_t     ssize_t;
        ^
nuttx/include/sys/types.h:121:9: error: unknown type name '_size_t'
typedef _size_t      rsize_t;
        ^
nuttx/include/sys/types.h:174:9: error: unknown type name '_wchar_t'
typedef _wchar_t     wchar_t;
        ^
In file included from src/sx126x-nuttx.c:4:
In file included from nuttx/include/stdio.h:34:
nuttx/include/nuttx/fs/fs.h:238:20: error: use of undeclared identifier 'NAME_MAX'
  char      parent[NAME_MAX + 1];
                   ^
```

We fix this by including the right header files...

```c
#if defined(__NuttX__) && defined(__clang__)  //  Workaround for NuttX with zig cc
#include <arch/types.h>
#include "../../nuttx/include/limits.h"
#endif  //  defined(__NuttX__) && defined(__clang__)
```

Into these source files...

-   [radio.c](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/radio.c#L23-L26)
-   [sx126x-nuttx.c](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L4-L7)
-   [sx126x.c](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x.c#L23-L26)

[(See the changes)](https://github.com/lupyuen/lora-sx1262/commit/8da7e4d7cc8f1455d750bc51d75c640eea221f41)

We insert this code to tell us (at runtime) whether it was compiled with Zig Compiler or GCC...

```c
void SX126xIoInit( void ) {
#ifdef __clang__
#warning Compiled with zig cc
    puts("SX126xIoInit: Compiled with zig cc");
#else
#warning Compiled with gcc
    puts("SX126xIoInit: Compiled with gcc");
#endif  //  __clang__
```

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L119-L127)

Compiled with `zig cc`, the LoRa SX1262 Library runs OK on NuttX yay!

```text
nsh> lorawan_test
SX126xIoInit: Compiled with zig cc
...
###### =========== MLME-Confirm ============ ######
STATUS      : OK
###### ===========   JOINED     ============ ######
OTAA
DevAddr     :  000E268C
DATA RATE   : DR_2
...
###### =========== MCPS-Confirm ============ ######
STATUS      : OK
###### =====   UPLINK FRAME        1   ===== ######
CLASS       : A
TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00
DATA RATE   : DR_3
U/L FREQ    : 923400000
TX POWER    : 0
CHANNEL MASK: 0003
```

[(See the complete log)](https://gist.github.com/lupyuen/ada7f83a96eb36ad1b9fe09da4527003)

# Appendix: LoRaWAN Library for NuttX

TODO

Let's compile the huge [LoRaWAN Library](https://lupyuen.github.io/articles/lorawan3) with Zig Compiler.

NuttX compiles the LoRaWAN Library like this...

```bash
##  LoRaWAN Source Directory
cd $HOME/nuttx/nuttx/libs/liblorawan

##  Compile mac/LoRaMac.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/mac/LoRaMac.c \
  -o  src/mac/LoRaMac.o
```

We switch to the Zig Compiler...

```bash
##  LoRaWAN Source Directory
cd $HOME/nuttx/nuttx/libs/liblorawan

##  Compile mac/LoRaMac.c with zig cc
zig cc \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe   src/mac/LoRaMac.c \
  -o  src/mac/LoRaMac.o

##  Link Zig Object Files with NuttX after compiling with `zig cc`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

We include the right header files into [LoRaMac.c](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMac.c#L33-L36)...

```c
#if defined(__NuttX__) && defined(__clang__)  //  Workaround for NuttX with zig cc
#include <arch/types.h>
#include "../../nuttx/include/limits.h"
#endif  //  defined(__NuttX__) && defined(__clang__)
```

[(See the changes)](https://github.com/lupyuen/LoRaMac-node-nuttx/commit/e36b54ea3351fc80f03d13a131527bf6733410ab)

[LoRaMac.c](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMac.c) compiles OK with Zig Compiler.

TODO: Compile the other files in the LoRaWAN Library with `build.zig`

https://ziglang.org/documentation/master/#Zig-Build-System

TODO: Test the LoRaWAN Library

# Appendix: LoRaWAN App for NuttX

TODO

Now we compile the LoRaWAN App [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c) with Zig Compiler.

NuttX compiles the LoRaWAN App [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c) like this...

```bash
##  App Source Directory
cd $HOME/nuttx/apps/examples/lorawan_test/lorawan_test_main.c

##  Compile lorawan_test_main.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -Dmain=lorawan_test_main  lorawan_test_main.c \
  -o  lorawan_test_main.c.home.user.nuttx.apps.examples.lorawan_test.o
```

We switch to Zig Compiler...

```bash
##  App Source Directory
cd $HOME/nuttx/apps/examples/lorawan_test

##  Compile lorawan_test_main.c with zig cc
zig cc \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -Dmain=lorawan_test_main  lorawan_test_main.c \
  -o  *lorawan_test.o

##  Link Zig Object Files with NuttX after compiling with `zig cc`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

We include the right header files into [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L20-L23)...

```c
#if defined(__NuttX__) && defined(__clang__)  //  Workaround for NuttX with zig cc
#include <arch/types.h>
#include "../../nuttx/include/limits.h"
#endif  //  defined(__NuttX__) && defined(__clang__)
```

[(See the changes)](https://github.com/lupyuen/lorawan_test/commit/3d4a451d44cf36b19ef8d900281a2f8f9590de62)

Compiled with `zig cc`, the LoRaWAN App runs OK on NuttX yay!

```text
nsh> lorawan_test
lorawan_test_main: Compiled with zig cc
...
###### =========== MLME-Confirm ============ ######
STATUS      : OK
###### ===========   JOINED     ============ ######
OTAA
DevAddr     :  00DC5ED5
DATA RATE   : DR_2
...
###### =========== MCPS-Confirm ============ ######
STATUS      : OK
###### =====   UPLINK FRAME        1   ===== ######
CLASS       : A
TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00
DATA RATE   : DR_3
U/L FREQ    : 923400000
TX POWER    : 0
CHANNEL MASK: 0003
```

[(See the complete log)](https://gist.github.com/lupyuen/477982242d897771d7a5780c8a9b0910)

![](https://lupyuen.github.io/images/iot-code5a.png)

# Appendix: Auto-Translate LoRaWAN App to Zig

TODO

The Zig Compiler can auto-translate C code to Zig. [(See this)](https://ziglang.org/documentation/master/#C-Translation-CLI)

Here's how we auto-translate our LoRaWAN App [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c) from C to Zig...

-   Change `zig cc` to `zig translate-c`

-   Surround the C Flags by `-cflags` ... `--`

Like this...

```bash
##  App Source Directory
cd $HOME/nuttx/apps/examples/lorawan_test

##  Auto-translate lorawan_test_main.c from C to Zig
zig translate-c \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -cflags \
    -fno-common \
    -Wall \
    -Wstrict-prototypes \
    -Wshadow \
    -Wundef \
    -Os \
    -fno-strict-aliasing \
    -fomit-frame-pointer \
    -fstack-protector-all \
    -ffunction-sections \
    -fdata-sections \
    -g \
    -mabi=ilp32f \
    -mno-relax \
  -- \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -Dmain=lorawan_test_main  \
  lorawan_test_main.c \
  >lorawan_test_main.zig
```

Here's the original C code: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c)

And the auto-translation from C to Zig: [translated/lorawan_test_main.zig](translated/lorawan_test_main.zig)

Here's a snippet from the original C code...

```c
int main(int argc, FAR char *argv[]) {
#ifdef __clang__
    puts("lorawan_test_main: Compiled with zig cc");
#else
    puts("lorawan_test_main: Compiled with gcc");
#endif  //  __clang__

    //  If we are using Entropy Pool and the BL602 ADC is available,
    //  add the Internal Temperature Sensor data to the Entropy Pool
    init_entropy_pool();

    //  Compute the interval between transmissions based on Duty Cycle
    TxPeriodicity = APP_TX_DUTYCYCLE + randr( -APP_TX_DUTYCYCLE_RND, APP_TX_DUTYCYCLE_RND );

    const Version_t appVersion    = { .Value = FIRMWARE_VERSION };
    const Version_t gitHubVersion = { .Value = GITHUB_VERSION };
    DisplayAppInfo( "lorawan_test", 
                    &appVersion,
                    &gitHubVersion );

    //  Init LoRaWAN
    if ( LmHandlerInit( &LmHandlerCallbacks, &LmHandlerParams ) != LORAMAC_HANDLER_SUCCESS )
    {
        printf( "LoRaMac wasn't properly initialized\n" );
        //  Fatal error, endless loop.
        while ( 1 ) {}
    }

    // Set system maximum tolerated rx error in milliseconds
    LmHandlerSetSystemMaxRxError( 20 );

    // The LoRa-Alliance Compliance protocol package should always be initialized and activated.
    LmHandlerPackageRegister( PACKAGE_ID_COMPLIANCE, &LmhpComplianceParams );
    LmHandlerPackageRegister( PACKAGE_ID_CLOCK_SYNC, NULL );
    LmHandlerPackageRegister( PACKAGE_ID_REMOTE_MCAST_SETUP, NULL );
    LmHandlerPackageRegister( PACKAGE_ID_FRAGMENTATION, &FragmentationParams );

    IsClockSynched     = false;
    IsFileTransferDone = false;

    //  Join the LoRaWAN Network
    LmHandlerJoin( );

    //  Set the Transmit Timer
    StartTxProcess( LORAMAC_HANDLER_TX_ON_TIMER );

    //  Handle LoRaWAN Events
    handle_event_queue(NULL);  //  Never returns

    return 0;
}
```

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L271-L323)

And the auto-translated Zig code...

```zig
pub export fn lorawan_test_main(arg_argc: c_int, arg_argv: [*c][*c]u8) c_int {
    var argc = arg_argc;
    _ = argc;
    var argv = arg_argv;
    _ = argv;
    _ = puts("lorawan_test_main: Compiled with zig cc");
    init_entropy_pool();
    TxPeriodicity = @bitCast(u32, @as(c_int, 40000) + randr(-@as(c_int, 5000), @as(c_int, 5000)));
    const appVersion: Version_t = Version_t{
        .Value = @bitCast(u32, @as(c_int, 16908288)),
    };
    const gitHubVersion: Version_t = Version_t{
        .Value = @bitCast(u32, @as(c_int, 83886080)),
    };
    DisplayAppInfo("lorawan_test", &appVersion, &gitHubVersion);
    if (LmHandlerInit(&LmHandlerCallbacks, &LmHandlerParams) != LORAMAC_HANDLER_SUCCESS) {
        _ = printf("LoRaMac wasn't properly initialized\n");
        while (true) {}
    }
    _ = LmHandlerSetSystemMaxRxError(@bitCast(u32, @as(c_int, 20)));
    _ = LmHandlerPackageRegister(@bitCast(u8, @truncate(i8, @as(c_int, 0))), @ptrCast(?*anyopaque, &LmhpComplianceParams));
    _ = LmHandlerPackageRegister(@bitCast(u8, @truncate(i8, @as(c_int, 1))), @intToPtr(?*anyopaque, @as(c_int, 0)));
    _ = LmHandlerPackageRegister(@bitCast(u8, @truncate(i8, @as(c_int, 2))), @intToPtr(?*anyopaque, @as(c_int, 0)));
    _ = LmHandlerPackageRegister(@bitCast(u8, @truncate(i8, @as(c_int, 3))), @ptrCast(?*anyopaque, &FragmentationParams));
    IsClockSynched = @as(c_int, 0) != 0;
    IsFileTransferDone = @as(c_int, 0) != 0;
    LmHandlerJoin();
    StartTxProcess(@bitCast(c_uint, LORAMAC_HANDLER_TX_ON_TIMER));
    handle_event_queue(@intToPtr(?*anyopaque, @as(c_int, 0)));
    return 0;
}
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/translated/lorawan_test_main.zig#L4535-L4565)

We'll refer to this auto-translated Zig Code when we manually convert our LoRaWAN App [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c) from C to Zig.

# Appendix: Opaque Type Error

TODO

When we reference `LmHandlerCallbacks` in our LoRaWAN Zig App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)...

```zig
    _ = &LmHandlerCallbacks;
```

Zig Compiler will show this Opaque Type Error...

```text
zig-cache/o/d4d456612514c342a153a8d34fbf5970/cimport.zig:1353:5: error: opaque types have unknown size and therefore cannot be directly embedded in unions
    Fields: struct_sInfoFields,
    ^
zig-cache/o/d4d456612514c342a153a8d34fbf5970/cimport.zig:1563:5: note: while checking this field
    PingSlot: PingSlotInfo_t,
    ^
zig-cache/o/d4d456612514c342a153a8d34fbf5970/cimport.zig:1579:5: note: while checking this field
    PingSlotInfo: MlmeReqPingSlotInfo_t,
    ^
zig-cache/o/d4d456612514c342a153a8d34fbf5970/cimport.zig:1585:5: note: while checking this field
    Req: union_uMlmeParam,
    ^
zig-cache/o/d4d456612514c342a153a8d34fbf5970/cimport.zig:2277:5: note: while checking this field
    OnMacMlmeRequest: ?fn (LoRaMacStatus_t, [*c]MlmeReq_t, TimerTime_t) callconv(.C) void,
    ^
```

Opaque Type Error is explained here...

-   ["Extend a C/C++ Project with Zig"](https://zig.news/kristoff/extend-a-c-c-project-with-zig-55di)

-   ["Translation failures"](https://ziglang.org/documentation/master/#Translation-failures)

Let's trace through our Opaque Type Error...

```zig
export fn OnMacMlmeRequest(
    status: c.LoRaMacStatus_t,
    mlmeReq: [*c]c.MlmeReq_t, 
    nextTxIn: c.TimerTime_t
) void {
    c.DisplayMacMlmeRequestUpdate(status, mlmeReq, nextTxIn);
}
```

Our function `OnMacMlmeRequest` has a parameter of type `MlmeReq_t`, auto-imported by Zig Compiler as...

```zig
pub const MlmeReq_t = struct_sMlmeReq;

pub const struct_sMlmeReq = extern struct {
    Type: Mlme_t,
    Req: union_uMlmeParam,
    ReqReturn: RequestReturnParam_t,
};
```

Which contains another auto-imported type `union_uMlmeParam`...

```zig
pub const union_uMlmeParam = extern union {
    Join: MlmeReqJoin_t,
    TxCw: MlmeReqTxCw_t,
    PingSlotInfo: MlmeReqPingSlotInfo_t,
    DeriveMcKEKey: MlmeReqDeriveMcKEKey_t,
    DeriveMcSessionKeyPair: MlmeReqDeriveMcSessionKeyPair_t,
};
```

Which contains an `MlmeReqPingSlotInfo_t`...

```zig
pub const MlmeReqPingSlotInfo_t = struct_sMlmeReqPingSlotInfo;

pub const struct_sMlmeReqPingSlotInfo = extern struct {
    PingSlot: PingSlotInfo_t,
};
```

Which contains a `PingSlotInfo_t`...

```zig
pub const PingSlotInfo_t = union_uPingSlotInfo;

pub const union_uPingSlotInfo = extern union {
    Value: u8,
    Fields: struct_sInfoFields,
};
```

Which contains a `struct_sInfoFields`...

```zig
pub const struct_sInfoFields = opaque {};
```

But the fields of `struct_sInfoFields` are not known by the Zig Compiler!

If we refer to the original C code...

```c
typedef union uPingSlotInfo
{
    /*!
     * Parameter for byte access
     */
    uint8_t Value;
    /*!
     * Structure containing the parameters for the PingSlotInfoReq
     */
    struct sInfoFields
    {
        /*!
         * Periodicity = 0: ping slot every second
         * Periodicity = 7: ping slot every 128 seconds
         */
        uint8_t Periodicity     : 3;
        /*!
         * RFU
         */
        uint8_t RFU             : 5;
    }Fields;
}PingSlotInfo_t;
```

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMac.h#L312-L333)

We see that `sInfoFields` contains Bit Fields, that the Zig Compiler is unable to translate.

# Appendix: Fix Opaque Type

TODO

Earlier we saw that this fails to compile in our LoRaWAN Zig App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)...

```zig
    _ = &LmHandlerCallbacks;
```

That's because `LmHandlerCallbacks` references the auto-imported type `MlmeReq_t`, which contains Bit Fields and can't be translated by the Zig Compiler.

Let's convert `MlmeReq_t` to an Opaque Type, since we won't be accessing the fields anyway...

```zig
/// We use an Opaque Type to represent MLME Request, because it contains Bit Fields that can't be converted by Zig
const MlmeReq_t = opaque {};
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L695-L696)

We convert `LmHandlerCallbacks` to use our Opaque Type `MlmeReq_t`...

```zig
/// Handler Callbacks. Adapted from 
/// https://github.com/lupyuen/zig-bl602-nuttx/blob/main/translated/lorawan_test_main.zig#L2818-L2833
pub const LmHandlerCallbacks_t = extern struct {
    GetBatteryLevel: ?fn () callconv(.C) u8,
    GetTemperature: ?fn () callconv(.C) f32,
    GetRandomSeed: ?fn () callconv(.C) u32,
    OnMacProcess: ?fn () callconv(.C) void,
    OnNvmDataChange: ?fn (c.LmHandlerNvmContextStates_t, u16) callconv(.C) void,
    OnNetworkParametersChange: ?fn ([*c]c.CommissioningParams_t) callconv(.C) void,
    OnMacMcpsRequest: ?fn (c.LoRaMacStatus_t, [*c]c.McpsReq_t, c.TimerTime_t) callconv(.C) void,
    /// Changed `[*c]c.MlmeReq_t` to `*MlmeReq_t`
    OnMacMlmeRequest: ?fn (c.LoRaMacStatus_t, *MlmeReq_t, c.TimerTime_t) callconv(.C) void,
    OnJoinRequest: ?fn ([*c]c.LmHandlerJoinParams_t) callconv(.C) void,
    OnTxData: ?fn ([*c]c.LmHandlerTxParams_t) callconv(.C) void,
    OnRxData: ?fn ([*c]c.LmHandlerAppData_t, [*c]c.LmHandlerRxParams_t) callconv(.C) void,
    OnClassChange: ?fn (c.DeviceClass_t) callconv(.C) void,
    OnBeaconStatusChange: ?fn ([*c]c.LoRaMacHandlerBeaconParams_t) callconv(.C) void,
    OnSysTimeUpdate: ?fn (bool, i32) callconv(.C) void,
};
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L675-L693)

We change all auto-imported `MlmeReq_t` references from...

```zig
[*c]c.MlmeReq_t
```

To our Opaque Type...

```zig
*MlmeReq_t
```

We also change all auto-imported `LmHandlerCallbacks_t` references from...

```zig
[*c]c.LmHandlerCallbacks_t
```

To our converted `LmHandlerCallbacks_t`...

```zig
*LmHandlerCallbacks_t
```

Which means we need to import the affected LoRaWAN Functions ourselves...

```zig
/// Changed `[*c]c.MlmeReq_t` to `*MlmeReq_t`. Adapted from
/// https://github.com/lupyuen/zig-bl602-nuttx/blob/main/translated/lorawan_test_main.zig#L2905
extern fn DisplayMacMlmeRequestUpdate(
    status: c.LoRaMacStatus_t, 
    mlmeReq: *MlmeReq_t, 
    nextTxIn: c.TimerTime_t
) void;

/// Changed `[*c]c.LmHandlerCallbacks_t` to `*LmHandlerCallbacks_t`. Adapted from
/// https://github.com/lupyuen/zig-bl602-nuttx/blob/main/translated/lorawan_test_main.zig#L2835
extern fn LmHandlerInit(
    callbacks: *LmHandlerCallbacks_t, 
    handlerParams: [*c]c.LmHandlerParams_t
) c.LmHandlerErrorStatus_t;
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L707-L720)

After fixing the Opaque Type, Zig Compiler successfully compiles our LoRaWAN Test App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig) yay!

# Appendix: Macro Error

TODO

While compiling our LoRaWAN Test App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig), we see this Macro Error...

```text
zig-cache/o/23409ceec9a6e6769c416fde1695882f/cimport.zig:2904:32: 
error: unable to translate macro: undefined identifier `LL`
pub const __INT64_C_SUFFIX__ = @compileError("unable to translate macro: undefined identifier `LL`"); 
// (no file):178:9
```

According to the Zig Docs, this means that the Zig Compiler failed to translate a C Macro...

-   ["C Macros"](https://ziglang.org/documentation/master/#C-Macros)

So we define `LL` ourselves...

```zig
/// Import the LoRaWAN Library from C
const c = @cImport({
    // Workaround for "Unable to translate macro: undefined identifier `LL`"
    @cDefine("LL", "");
```

(`LL` is the "long long" suffix for C Constants, which is probably not needed when we import C Types and Functions into Zig)

Then Zig Compiler emits this error...

```text
zig-cache/o/83fc6cf7a78f5781f258f156f891554b/cimport.zig:2940:26: 
error: unable to translate C expr: unexpected token '##'
pub const __int_c_join = @compileError("unable to translate C expr: unexpected token '##'"); 
// /home/user/zig-linux-x86_64-0.10.0-dev.2351+b64a1d5ab/lib/include/stdint.h:282:9
```

Which refers to this line in `stdint.h`...

```c
#define __int_c_join(a, b) a ## b
```

The `__int_c_join` Macro fails because the `LL` suffix is now blank and the `##` Concatenation Operator fails.

We redefine the `__int_c_join` Macro without the `##` Concatenation Operator...

```zig
/// Import the LoRaWAN Library from C
const c = @cImport({
    // Workaround for "Unable to translate macro: undefined identifier `LL`"
    @cDefine("LL", "");
    @cDefine("__int_c_join(a, b)", "a");  //  Bypass zig/lib/include/stdint.h
```

Now Zig Compiler successfully compiles our LoRaWAN Test App [lorawan_test.zig](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig)

# Appendix: Struct Initialisation Error

TODO

Zig Compiler crashes when it tries to initialise the Timer Struct at startup...

```zig
/// Timer to handle the application data transmission duty cycle
var TxTimer: c.TimerEvent_t = 
    std.mem.zeroes(c.TimerEvent_t);

// Zig Compiler crashes with...
// TODO buf_write_value_bytes maybe typethread 11512 panic:
// Unable to dump stack trace: debug info stripped
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L679-L684)

So we initialise the Timer Struct in the Main Function instead...

```zig
/// Timer to handle the application data transmission duty cycle.
/// Init the timer in Main Function.
var TxTimer: c.TimerEvent_t = undefined;

/// Main Function
pub export fn lorawan_test_main(
    _argc: c_int, 
    _argv: [*]const [*]const u8
) c_int {
    // Init the Timer Struct at startup
    TxTimer = std.mem.zeroes(c.TimerEvent_t);
```

[(Source)](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/lorawan_test.zig#L90-L101)
