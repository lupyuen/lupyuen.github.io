# Early Days of Rust Apps on Apache NuttX RTOS

📝 _19 Aug 2024_

![Blinking the NuttX LED in Rust](https://lupyuen.github.io/images/rust6-title.jpg)

[(__Update:__ Rust Standard Library is now supported on NuttX!)](https://lupyuen.org/articles/rust7.html)

My student [__Rushabh Gala__](https://github.com/rushabhvg) has just completed his project for [__Google Summer of Code__](https://summerofcode.withgoogle.com/). Rushabh has created __Safer Rust Apps__ for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/)...

- [__GSoC Final Report__](https://rushabhvg.github.io/articles/end_report)

- [__GSoC Midterm Report__](https://rushabhvg.github.io/articles/mid_term_blog_post)

- [__NuttX Workshop Presentation__](https://youtu.be/dFOodFieo4M?si=r4-MZWQwKnvqVv3h)

In this article we walk through Rushabh's contributions. And understand how we're evolving __Rust Apps for NuttX__...

1.  __Blinking the LED__ in Rust

1.  __Handling Errors__ returned by NuttX

1.  Testing on __QEMU RISC-V Emulator__

1.  And maybe __Linux / macOS / Windows__

1.  But __No Crates Allowed__ in NuttX!

1.  Be wary of the __Main Function__ and __Panic Handler__

1.  We created __LED Drivers__ for QEMU and Ox64 BL808 SBC

1.  And we're running __Daily Build and Test__ of our Rust App

1.  Thanks to our __Updated Docker Image__ for Continuous Integration

![Blinking the NuttX LED in Rust](https://lupyuen.github.io/images/rust6-flow2.jpg)

# Blink The LED

This is how we __Blink the LED__ in a NuttX Rust App: [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L59-L91)

```rust
// Main Program Logic. Called by `leds_rust_main`
fn rust_main(_argc: i32, _argv: *const *const u8)  // Args from NuttX Shell
  -> Result<i32, i32> {  // Return a Result Code (int) or Error Code (int)

  // Open the LED Device
  safe_puts("Hello, Rust!!");
  let fd = safe_open("/dev/userleds", O_WRONLY) ?;  // Quit on error

  // Flip LED 1 to On
  safe_ioctl(fd, ULEDIOC_SETALL, 1) ?;  // Quit on error
  unsafe { usleep(500_000); }

  // Flip LED 1 to Off
  safe_ioctl(fd, ULEDIOC_SETALL, 0) ?;  // Quit on error
  unsafe { close(fd); }

  // Return successfully with result 0
  Ok(0)
}
```

[(__Mirrored here:__ nuttx-rust-app/app/src/main.rs)](https://github.com/lupyuen/nuttx-rust-app/blob/main/app/src/main.rs)

Our Rust Blinky App looks mighty similar to the [__C Version__](https://github.com/lupyuen2/wip-nuttx-apps/blob/nim/examples/hello/hello_main.c#L40-L85)! But with simpler Error Handling than C. (We'll talk more)

_What are safe_open and safe_ioctl?_

They are safer versions of __open__ and __ioctl__, from our [__NuttX Module__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs). Inside the NuttX Module we...

- Define the Safe Wrappers: [__`safe_*`__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L69-L119)

- Import [__usleep__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L28-L41) and [__close__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L28-L41) from C

- Plus the NuttX Constants: [__O_WRONLY__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L41-L51) and [__ULEDIOC_SETALL__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L41-L51)

We import the __NuttX Module__ into our Rust App like so: [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L20-L45)

```rust
// Comment out these lines for testing on Linux / macOS / Windows
#![no_main]  // For NuttX Only: No Main Function
#![no_std]   // For NuttX Only: Use Rust Core Library (instead of Rust Standard Library)

// Import the NuttX Module
mod nuttx;
use nuttx::*;
```

And yes this code runs on Linux, macOS and Windows! We'll come back to this, first we test on QEMU...

![Testing Rust Blinky on QEMU Emulator](https://lupyuen.github.io/images/rust6-qemu.jpg)

# Test on QEMU Emulator

To test Rust Blinky on __QEMU RISC-V Emulator__, follow these steps...

```bash
## TODO: Install the NuttX Build Prerequisites, skip the RISC-V Toolchain
## https://lupyuen.github.io/articles/nuttx#install-prerequisites

## TODO: Download the xPack Toolchain for RISC-V
## https://lupyuen.github.io/articles/riscv#appendix-xpack-gnu-risc-v-embedded-gcc-toolchain-for-64-bit-risc-v

## Install the Rust Target for QEMU RISC-V 64-bit
rustup target add riscv64gc-unknown-none-elf

## Install QEMU Emulator for RISC-V
sudo apt install qemu-system-riscv64  ## For Linux
brew install qemu  ## For macOS

## Download the Source Code for NuttX Kernel and Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

## Configure the NuttX Build: QEMU RISC-V 64-bit with LED Driver and Rust
tools/configure.sh rv-virt:leds64_rust

## Build the NuttX Kernel. Ignore the warning: `nuttx has a LOAD segment with RWX permissions`
make

## Boot the NuttX Kernel in QEMU RISC-V 64-bit
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic
```

[(See the __Build Script__)](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-leds64-rust.yml)


At the NSH Prompt: Enter "__`leds_rust`__" (pic above)

```text
NuttShell (NSH) NuttX-12.6.0-RC1
nsh> leds_rust
Hello, Rust!!
Opening /dev/userleds

Set LED 1 to 1
board_userled: LED 1 set to 1
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
Sleeping...

Set LED 1 to 0
board_userled: LED 1 set to 0
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
```

Rust blinks our Simulated LED on NuttX QEMU! Let's head back inside the code...

[(See the __NuttX Log__)](https://github.com/lupyuen/nuttx-riscv64/actions/runs/10396419763/job/28790386663)

[(QEMU RISC-V 32-bit needs a __Custom Rust Target__)](https://lupyuen.github.io/articles/rust4#custom-target-for-rust)

![Blinking the NuttX LED in Rust](https://lupyuen.github.io/images/rust6-title.jpg)

# Handle Errors Safely

_Why the funny question mark? (Pic above)_

```rust
let fd = safe_open(  // Open the LED Device...
  "/dev/userleds",   // Device Path
  O_WRONLY           // Open for Write-Only
) ?;                 // Quit on error
```

Remember in C we check the [__Result Value__](https://github.com/lupyuen2/wip-nuttx-apps/blob/nim/examples/hello/hello_main.c#L46-L64) at every call to __open__ and __ioctl__... Now with __safe_open__ and __safe_ioctl__, Rust does the checking for us!

If something goes wrong, the code above will exit the function with an __Error Value__. (Like if _"/dev/userleds"_ doesn't exist)

Our NuttX App becomes a little safer with the [__Question Mark Operator__](https://doc.rust-lang.org/rust-by-example/std/result/question_mark.html), by auto-checking the results of System Calls.

(Rust Compiler __will warn us__ if we forget the Question Mark)

_But usleep and close are still unsafe?_

```rust
// Wait a while
unsafe { usleep(500_000); }
...
// Close the LED Device
unsafe { close(fd); }
```

Yeah there's not much point in wrapping __usleep__ and __close__? Since we don't check the Return Values.

(__safe_puts__ has a limited [__Buffer Size__](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/nuttx.rs#L104-L119))

_Can we auto-close the File Descriptor when it goes out of scope?_

Probably, if we do [__Managed File Descriptors__](https://docs.rs/rustix/latest/rustix/fd/struct.OwnedFd.html). But that's way beyond the size, scope and scale of GSoC.

![Run Rust Blinky on Linux / macOS / Windows](https://lupyuen.github.io/images/rust6-cargo.jpg)

# Runs on Linux / macOS / Windows

_Will our NuttX App actually run on Linux, macOS and Windows?_

```rust
// Comment out these lines for testing on Linux / macOS / Windows
#![no_main]  // For NuttX Only: No Main Function
#![no_std]   // For NuttX Only: Use Rust Core Library (instead of Rust Standard Library)
```

Yep indeed! Just comment out the above lines and our Rust Blinky App will run on __Linux / macOS / Windows__ (WSL)...

```bash
$ git clone https://github.com/lupyuen/nuttx-rust-app
$ cd nuttx-rust-app
$ cd app
$ cargo run
Hello, Rust!!
Opening /dev/userleds
ERROR: rust_main() failed with error -1
```

Though it fails (as expected) because _"/dev/userleds"_ doesn't exist on Linux / macOS / Windows. (Pic above)

This greatly simplifies our NuttX App Development: We could (potentially) compile and run our NuttX App on our __Local Computer__, before testing on NuttX!

(__Rust Analyzer__ won't work inside NuttX Projects sigh)

![Blinking the NuttX LED in Rust](https://lupyuen.github.io/images/rust6-flow.jpg)

# Main Function for Rust

_We saw the LED Blinky code in rust_main. Who calls rust_main?_

Remember that __rust_main__ returns a [__Result Type__](https://doc.rust-lang.org/rust-by-example/error/result.html): [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L59-L91)

```rust
// `rust_main` accepts the args from NuttX Shell
// And returns a Result Code (int) or Error Code (int)
fn rust_main(_argc: i32, _argv: *const *const u8)
  -> Result<i32, i32> { ... }
```

But NuttX expects us to provide a Main Function named __leds_rust_main__. And it shall return an __Integer Result__. (Not a Result Type)

Thus we create an __leds_rust_main__ function that calls __rust_main__ (pic above) and returns the right result: [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L91-L120)

```rust
// For NuttX: This will be called by NuttX Shell
// For Linux / macOS / Windows: This wil be called by `main`
#[no_mangle]
pub extern "C" fn leds_rust_main(argc: i32, argv: *const *const u8)  // Args from NuttX Shell
  -> i32 {  // Return a Result Code (0) or Error Code (negative)

  // Call the program logic in Rust Main
  let res = rust_main(argc, argv);

  // If Rust Main returns an error, print it.
  // We won't wrap `printf`, because it needs VarArgs.
  if let Err(e) = res {
    unsafe { printf(b"ERROR: rust_main() failed with error %d\n\0" as *const u8, e); }
    e  // Return the Error Code
  } else {
    0  // Or return the Result Code 0
  }
}
```

_What about Linux / macOS / Windows?_

They expect us to provide a __main__ function...

![Main Function for Rust Blinky](https://lupyuen.github.io/images/rust6-flow3.jpg)

Thus we do this: [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L120-L128)

```rust
// For Linux / macOS / Windows: Define the Main Function
#[cfg(not(target_os = "none"))]
fn main() {
  // Call Rust Main without args
  leds_rust_main(
    0,                 // argc: Zero Args
    core::ptr::null()  // argv: Null Pointer
  );
}
```

![Panic Handler for Rust Blinky App](https://lupyuen.github.io/images/rust6-flow4.jpg)

# Panic Handler for Rust

_Anything else specific to NuttX?_

Yep NuttX Apps run on the [__Rust Core Library__](https://doc.rust-lang.org/core/) (no_std) and require a [__Panic Handler__](https://doc.rust-lang.org/nomicon/panic-handler.html).

That's why we need this: [leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs#L29-L59)

```rust
// For NuttX Only: Import the Panic Type
#[cfg(target_os = "none")]
use core::{
  panic::PanicInfo,
  result::Result::{self, Err, Ok},
};

// For NuttX Only: Define the Panic Handler for `no_std`
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  loop {}
}
```

(Sorry __cfg__ won't work for __no_main__ and __no_std__)

![No Crates allowed in NuttX](https://lupyuen.github.io/images/rust6-flow5.jpg)

# No Crates in NuttX

[(__Update:__ NuttX now supports __Cargo__ and __Tokio__!)](https://github.com/apache/nuttx-apps/pull/2487)

_We're coding Rust in a strange way. Why not use crates and cargo?_

Ah that's because NuttX [__doesn't support Rust Crates__](https://github.com/apache/nuttx/pull/5566#issuecomment-1046963430)! We can't use __cargo__ either, NuttX Build will call __rustc__ directly...

```bash
## Configure the NuttX Project
## for QEMU RISC-V 64-bit including Rust
$ tools/configure.sh rv-virt:leds64_rust

## Build the NuttX Project
## Which calls `rustc`
$ make
```

Which complicates our coding of NuttX Rust Apps. That's why we hope to test them first on [__Linux / macOS / Windows__](https://lupyuen.github.io/articles/rust6#runs-on-linux--macos--windows).

(__NuttX Module nuttx.rs__ should probably live in a Common Source Folder)

(Maybe NuttX will allow some crates, similar to [__Rust for Linux Kernel__](https://rust-for-linux.com/third-party-crates))

![Rust Blinky on Ox64 BL808 SBC](https://lupyuen.github.io/images/rust6-ox64.jpg)

[_Rust Blinky on Ox64 BL808 SBC_](https://youtube.com/shorts/t6nxVZWS0Js?feature=share)

# LED Drivers for NuttX

_12 weeks of GSoC: What else have we implemented?_

Remember our Blinky NuttX App in Rust? Well a NuttX App ain't really a NuttX App... Unless it runs __on Real Hardware__!

We tested our Rust Blinky App on [__Ox64 BL808 RISC-V SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (pic above). Which needs us to create the __GPIO and LED Drivers__ for Ox64 SBC...

- [__"Add GPIO Driver for BL808"__](https://github.com/apache/nuttx/pull/12571)

- [__"Add LED Driver for Ox64"__](https://github.com/apache/nuttx/pull/12614)

  [(NuttX Ox64 needs __leds_rust_main__ to be renamed as __main__)](https://lupyuen.github.io/articles/rust5#appendix-main-function-is-missing)

![NuttX LED Drivers for QEMU RISC-V Emulator and Ox64 BL808 SBC](https://lupyuen.github.io/images/rust6-flow6.jpg)

_What about folks without Ox64 SBC?_

We created the LED Driver for __QEMU RISC-V Emulator__, which will blink a Simulated LED on NuttX. (Pic above)

Everyone can run the __Rust Blinky App__ (from above) and reproduce the exact same results, thanks to the QEMU LED Driver...

- [__"Add LED Driver for QEMU RISC-V"__](https://github.com/apache/nuttx/pull/12762)

![Daily Build and Test of Rust Blinky App at GitHub Actions](https://lupyuen.github.io/images/rust6-daily.png)

# Daily Build and Test

_Our Rust Blinky App: Will it break someday?_

Yeah it's possible that our Rust App will someday __fail to build or execute__ correctly...

1.  __Rust Compiler__ might change and break our app

    (Since we're not calling it the __cargo__ way)

1.  __NuttX Makefiles__ might cause problems for Rust Apps

    (Because NuttX is mostly in C, not Rust)

That's why we extended the __Continuous Integration__ workflow for NuttX...

Every NuttX Pull Request will now trigger a rebuild of our [__Rust Blinky App__](https://lupyuen.github.io/articles/rust6#blink-the-led). If anything breaks, we'll find out right away!

- [__"Fix the Rust and D Builds for QEMU RISC-V"__](https://github.com/apache/nuttx/pull/12854)

- [__"Add Rust Target for QEMU RISC-V 64-bit"__](https://github.com/apache/nuttx/pull/12858)

- [__"Add Build Config for leds64_rust"__](https://github.com/apache/nuttx/pull/12862)

_Why so complicated?_

That's because the NuttX Continuous Integration (CI) runs inside a __Docker Container__. Which requires delicate modding...

- [__"Building the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)

- [__"Downloading the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-downloading-the-docker-image-for-nuttx-ci)

NuttX CI also compiles __hello_rust__ for [__NuttX Simulator__](https://github.com/apache/nuttx/blob/master/boards/sim/sim/sim/configs/rust/defconfig#L27). Though it's simpler and doesn't need a Special Rust Target for the Docker Image.

_Will we know if the Rust Blinky App fails to execute correctly?_

Every day through __GitHub Actions__: We're testing the Rust Blinky App on QEMU RISC-V Emulator. (Pic above)

If Rust Blinky fails to execute (or produces the wrong output), GitHub Actions will notify us...

- [__"Daily Test of Rust Blinky"__](https://lupyuen.github.io/articles/rust6#appendix-daily-test-of-rust-blinky)

_Anything else we're testing daily?_

If something goes wrong: We need to be clear whether it's our Rust App Failing vs __NuttX QEMU Failing__. That's why we also test NuttX QEMU every day at GitHub Actions...

- [__"Daily Test of NuttX QEMU RISC-V"__](https://lupyuen.github.io/articles/rust6#appendix-daily-test-of-nuttx-qemu-risc-v)

- [__"NuttX QEMU RISC-V fails on GitHub Actions"__](https://lupyuen.github.io/articles/rust6#appendix-nuttx-qemu-risc-v-fails-on-github-actions)

![Adding NuttX as Tier 3 Target to Rust](https://lupyuen.github.io/images/rust6-target.jpg)

# All Things Considered 

_Wow that's plenty of coding for 12 weeks of GSoC!_

Indeed, we tracked all Coding Tasks in our [__GSoC Task Spreadsheet__](https://docs.google.com/spreadsheets/d/1NzaS7gp2eYhegSA1DsH5Zw-o0tShqL-ewvVhoSSR0UQ/edit?usp=drive_link). And we recorded Daily Updates in the [__NuttX Discord Channel__](https://discord.gg/eAz5QudKSQ).

_Will Rust officially support NuttX?_

The NuttX Community is now prepping NuttX as [__Tier 3 Target__](https://lists.apache.org/thread/oqx7p3vb4dcgko4mm2f0vqgqnkorn49p) to Rust. [(First step is __approved__! Pic above)](https://github.com/rust-lang/rust/pull/127755)

_Everything in this article... Becomes redundant?_

Soon we'll have lots of [__Coding and Testing__](https://github.com/apache/nuttx-apps/pull/2487) to implement NuttX as Tier 3 Target, that works with the [__Rust Standard Library__](https://doc.rust-lang.org/std/index.html).

Meanwhile, we can call [__NuttX Safe Wrappers__](https://lupyuen.github.io/articles/rust6#handle-errors-safely) (prescribed in this article) to build Rust Apps for NuttX, the Interim Way.

![Blinking the NuttX LED in Rust](https://lupyuen.github.io/images/rust6-flow.jpg)

# What's Next

These are the __Early Days of Rust Apps__ on Apache NuttX RTOS. We talked about...

- __Blinking the LED__ in Rust

  __Handling Errors__ returned by NuttX

- Testing on __QEMU RISC-V Emulator__

  And possibly __Linux / macOS / Windows__

- But NuttX __Won't Allow Any Crates__!

  (Someday it might? Similar to [__Rust for Linux Kernel__](https://rust-for-linux.com/third-party-crates))

- Be wary of the __Main Function__ and __Panic Handler__!

  (NuttX works differently from Linux / macOS / Windows)

- Check out the __LED Drivers__ we created

  (For testing QEMU Emulator and Ox64 BL808 SBC)

- We're running __Daily Build and Test__ of our Rust App

  (With our __Updated Docker Image__ for Continuous Integration)

Check out the next article...

- [__"Rust Standard Library on Apache NuttX RTOS"__](https://lupyuen.org/articles/rust7.html)

Many Thanks to my [__GitHub Sponsors__](https://lupyuen.github.io/articles/sponsor) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

Special Thanks to __Mr Rushabh Gala__: Sorry it’s my first GSoC, I could have done better, I'm grateful for your patience and understanding 🙏

-   [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=41289120)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/rust6.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust6.md)

# Appendix: NuttX vs Rust Embedded HAL

[(__Update:__ NuttX now supports __Cargo__ and __Tokio__!)](https://lupyuen.org/articles/rust7.html)

_Shall we implement Rust Embedded HAL on NuttX?_

Actually I'm not too clear if we should stick to the Official Rust Embedded HAL for NuttX. Here's why...

To blink an LED in __Rust Embedded HAL__: We fetch the GPIO, then switch it off and on...

- [__Rust Embedded HAL: Blink the LED__](https://docs.rust-embedded.org/discovery/microbit/05-led-roulette/light-it-up.html)

But there's no need to do this in NuttX! We simply open the LED Device __/dev/userleds__. And control it via __ioctl__...

- [__Blink the LED (NuttX)__](https://lupyuen.github.io/articles/rust6#blink-the-led)

Rust Embedded HAL feels strange when we force-fit it into NuttX. I2C will have similar issues...

- [__NuttX Embedded HAL (I2C)__](https://lupyuen.github.io/articles/rusti2c#nuttx-embedded-hal)

If we look at __Rust on Zephyr__: They propose to call a Native Zephyr API to [__blink the LED__](https://github.com/zephyrproject-rtos/zephyr/issues/65837)...

```rust
// Proposed Rust on Zephyr
#![no_std]
#![no_main]

#[zephyr::entry]
fn main() {
  let dt = zephyr::devicetree::take().unwrap();
  let led = dt.chosen.led0;
  loop {
    led.toggle().unwrap();
    zephyr::sys::sleep(1000);
  }
}
```

My gut feel is that we should do it the Zephyr way. But make it POSIX-like. Thus we should drop __nuttx-embedded-hal__ altogether :-)

_What about Rustix?_

Rustix is kinda heavy I think? It does Owned File Descriptors that will auto-close when they go out of scope. There might be a lot of dependencies inside?

Earlier I [wrote this](https://lupyuen.github.io/articles/rust6#handle-errors-safely)...

> _Can we auto-close the File Descriptor when it goes out of scope?_
> Probably, if we do [__Managed File Descriptors__](https://docs.rs/rustix/latest/rustix/fd/struct.OwnedFd.html). But that's way beyond the size, scope and scale of GSoC.

[(More discussion here)](https://github.com/apache/nuttx-apps/pull/2487)

__Update:__ We're reassessing Rustix for NuttX. Simpler is swell but we'll run into problems with I/O Safety sigh. Check out the new article...

- [__"Rust Standard Library on Apache NuttX RTOS"__](https://lupyuen.org/articles/rust7.html)

![Testing Rust Blinky on QEMU Emulator](https://lupyuen.github.io/images/rust6-qemu.jpg)

# Appendix: Daily Test of Rust Blinky

Earlier we said that our Rust Blinky App might someday [__fail to build or execute__](https://lupyuen.github.io/articles/rust6#daily-build-and-test) correctly. That's why we...

- [__Trigger a Rebuild__](https://lupyuen.github.io/articles/rust6#daily-build-and-test) of our Rust Blinky App on every NuttX Pull Request

- __Run and Test__ our Rust Blinky App every day at GitHub Actions

If anything breaks, we'll find out right away!

_How to test our app with GitHub Actions?_

__Every day at GitHub Actions:__ We boot NuttX on QEMU RISC-V (64-bit) and verify the output of "__`leds_rust`__" (pic above)

```bash
## Start the QEMU Emulator for 64-bit RISC-V
$ spawn qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic

## Run `leds_rust` and verify the output
NuttShell (NSH) NuttX-12.6.0-RC1
nsh> leds_rust
Hello, Rust!!
Opening /dev/userleds

Set LED 1 to 1
board_userled: LED 1 set to 1
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
Sleeping...

Set LED 1 to 0
board_userled: LED 1 set to 0
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
```

[(See the __GitHub Actions Log__)](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-leds64-rust.yml)

Here's the __GitHub Actions Workflow__ (pic below) to build and run Rust Blinky: [qemu-riscv-leds64-rust.yml](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-leds64-rust.yml)

```bash
## Download the Source Code for NuttX Kernel and Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

## Install the Rust Target for QEMU RISC-V 64-bit
rustup target add riscv64gc-unknown-none-elf

## Configure the NuttX Build: QEMU RISC-V 64-bit with LED Driver and Rust
tools/configure.sh rv-virt:leds64_rust

## Build the NuttX Kernel. Ignore the warning: `nuttx has a LOAD segment with RWX permissions`
make

## Install QEMU Emulator for RISC-V
sudo apt install qemu-system-riscv64

## Test NuttX and Rust Blinky with our Expect Script
wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-leds64-rust.exp
chmod +x qemu-riscv-leds64-rust.exp
./qemu-riscv-leds64-rust.exp
```

Which calls our __Expect Script__ to test Rust Blinky: [qemu-riscv-leds64-rust.exp](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-leds64-rust.exp)

```bash
#!/usr/bin/expect
## Expect Script for Testing NuttX Rust Blinky with QEMU Emulator

## Wait at most 10 seconds
set timeout 10

## For every 1 character sent, wait 0.01 milliseconds
set send_slow {1 0.01}

## Start the QEMU Emulator for 64-bit RISC-V
spawn qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic

## Wait for the prompt and enter `leds_rust`
expect "nsh> "
send -s "leds_rust\r"

## Check the response: LEDs 1, 2 and 3 should be Off
expect "board_userled: LED 1 set to 0"
expect "board_userled: LED 2 set to 0"
expect {
  ## If we see this message, continue normally
  "board_userled: LED 3 set to 0" {}

  ## If timeout, exit with an error
  ## And rerminate the session: Ctrl-A x
  timeout { 
    send "\x01x"
    puts "\n===== Error: Test Failed\n"
    exit 1 
  }
}

## Terminate the session: Ctrl-A x
send "\x01x"
puts "\n===== Test OK\n"
exit 0 
```

But our test is incomplete: We need to know if NuttX on QEMU is really OK...

![Daily Build and Test of Rust Blinky App at GitHub Actions](https://lupyuen.github.io/images/rust6-daily.png)

# Appendix: Daily Test of NuttX QEMU RISC-V

If something goes wrong with __Rust Blinky__: We need to be clear whether it's our Rust App Failing vs __NuttX QEMU Failing__. That's why we also test NuttX QEMU every day at GitHub Actions. (Pic above)

__NuttX for QEMU RISC-V__ comes in Multiple Flavours, we test four of the popular flavours every day...

- __32-bit RISC-V, Flat Build: <br> `rv-virt:nsh`__

  [GitHub Actions Workflow](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-nsh.yml) / [Test Log](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-nsh.yml)

- __32-bit RISC-V, Kernel Build: <br> `rv-virt:knsh`__

  [GitHub Actions Workflow](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-knsh.yml) / [Test Log](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-knsh.yml)

- __64-bit RISC-V, Flat Build: <br> `rv-virt:nsh64`__

  [GitHub Actions Workflow](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-nsh64.yml) / [Test Log](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-nsh64.yml)

- __64-bit RISC-V, Kernel Build: <br> `rv-virt:knsh64`__

  [GitHub Actions Workflow](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-knsh64.yml) / [Test Log](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-knsh64.yml)

  [(About __Flat Build__ vs __Kernel Build__)](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode)

_What's inside the GitHub Actions Workflow?_

__Every day at GitHub Actions:__ We boot NuttX on QEMU RISC-V and verify the output of [__OSTest__](https://lupyuen.github.io/articles/tinyemu3#daily-automated-testing)...

```bash
## Start the QEMU Emulator for 32-bit RISC-V
$ spawn qemu-system-riscv32 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv32 \
  -bios none \
  -kernel nuttx \
  -nographic

## Run `ostest` and verify the output
NuttShell (NSH) NuttX-12.6.0-RC1
nsh> ostest
...
ostest_main: Exiting with status 0
```

[(See the __GitHub Actions Log__)](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-nsh.yml)

Here's the __GitHub Actions Workflow__ to build and run NuttX QEMU RISC-V (32-bit): [qemu-riscv-nsh.yml](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-nsh.yml)

```bash
## Download the Source Code for NuttX Kernel and Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

## Configure the NuttX Build: QEMU RISC-V 32-bit (Flat Build)
tools/configure.sh rv-virt:nsh

## Build the NuttX Kernel. Ignore the warning: `nuttx has a LOAD segment with RWX permissions`
make

## Install QEMU Emulator for RISC-V (32-bit)
sudo apt install qemu-system-riscv32

## Test NuttX and OSTest with our Expect Script
wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-nsh.exp
chmod +x qemu-riscv-nsh.exp
./qemu-riscv-nsh.exp
```

Which calls our __Expect Script__ to boot NuttX and run [__OSTest__](https://lupyuen.github.io/articles/tinyemu3#daily-automated-testing): [qemu-riscv-nsh.exp](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-nsh.exp)

```bash
#!/usr/bin/expect
## Expect Script for Testing NuttX with QEMU Emulator

## Wait at most 300 seconds
set timeout 300

## For every 1 character sent, wait 0.01 milliseconds
set send_slow {1 0.01}

## Start the QEMU Emulator for 32-bit RISC-V
spawn qemu-system-riscv32 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv32 \
  -bios none \
  -kernel nuttx \
  -nographic

## Wait for the prompt and enter `ostest`
expect "nsh> "
send -s "ostest\r"

## Check the response...
expect {
  ## If we see this message, exit normally
  "ostest_main: Exiting with status 0" { 
    ## Terminate the session: Ctrl-A x
    send "\x01x"
    puts "\n===== Test OK\n"
    exit 0 
  }

  ## If timeout, exit with an error
  timeout { 
    ## Terminate the session: Ctrl-A x
    send "\x01x"
    puts "\n===== Error: Test Failed\n"
    exit 1 
  }
}
```

But there's a problem: OSTest for __64-bit QEMU RISC-V__ fails on GitHub Actions...

![Running a script on my Home Computer to download the 64-bit Daily Builds and run OSTest locally](https://lupyuen.github.io/images/rust6-task.jpg)

# Appendix: NuttX QEMU RISC-V fails on GitHub Actions

__Every day at GitHub Actions:__ We boot NuttX on __QEMU RISC-V Emulator__ (32-bit and 64-bit) and test it with [__OSTest__](https://lupyuen.github.io/articles/tinyemu3#daily-automated-testing)...

- [__"Daily Test of NuttX QEMU RISC-V"__](https://lupyuen.github.io/articles/rust6#appendix-daily-test-of-nuttx-qemu-risc-v)

_But we have problems?_

Yeah OSTest for __64-bit QEMU RISC-V__ fails on GitHub Actions, wonder why...

- __64-bit RISC-V Flat Build <br> `rv-virt:nsh64`__ crashes with...

  _"fpu_test: Started task FPU#1  / riscv_exception: Illegal instruction"_

  [(GitHub Actions Workflow)](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-nsh64.yml#L2)

- __64-bit RISC-V Kernel Build <br> `rv-virt:knsh64`__ hangs at...

  _"ostest_main: Started user_main"_

  [(__Update:__ It's a Docker Problem, not GitHub Actions)](https://gist.github.com/lupyuen/9d9fe108e8aaf387fcc390c57717cf81)

  [(GitHub Actions Workflow)](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-knsh64.yml#L2)

  [(About __Flat Build__ vs __Kernel Build__)](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode)

That's why I run a script on my Home Computer to download the 64-bit Daily Builds and __run OSTest locally__ (pic above)

- __64-bit RISC-V Flat Build <br> `rv-virt:nsh64`__

  [Task Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/task-nsh64.sh) / [Test Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/test-nsh64.sh)

  [Upload Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/upload-nsh64.sh) / [Sample Log](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-nsh64-2024-08-08)

- __64-bit RISC-V Kernel Build <br> `rv-virt:knsh64`__

  [Task Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/task-knsh64.sh) / [Test Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/test-knsh64.sh)

  [Upload Script](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/upload-knsh64.sh) / [Sample Log](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2024-08-08)

_What's inside the scripts?_

Inside our __Task Script__: We wait for the 64-bit __NuttX Daily Build__ to be published as a GitHub Release: [task-nsh64.sh](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/task-nsh64.sh)

```bash
## Background Task: Automated Testing of Apache NuttX RTOS for QEMU RISC-V 64-bit Flat Build
export BUILD_PREFIX=qemu-riscv-nsh64

## Wait for GitHub Release, then test NuttX
for (( ; ; ))
do
  ## Build Date is today (YYYY-MM-DD)
  BUILD_DATE=$(date +'%Y-%m-%d')
  test_nuttx $BUILD_DATE

  ## Wait a while
  sleep 600
done

## Wait for GitHub Release, then test NuttX on SBC
function test_nuttx {
  ...
  ## Download the NuttX Build
  local date=$1
  NUTTX_ZIP=/tmp/$BUILD_PREFIX-$date-nuttx.zip
  wget -q \
    https://github.com/lupyuen/nuttx-riscv64/releases/download/$BUILD_PREFIX-$date/nuttx.zip \
    -O $NUTTX_ZIP
  ...
  ## Run the NuttX Test
  test-nsh64.sh \
    >/tmp/release-$BUILD_PREFIX.log \
    2>&1
  ...
  ## Upload the Test Log
  upload-nsh64.sh \
    /tmp/release-$BUILD_PREFIX.tag \
    /tmp/release-$BUILD_PREFIX.log
}
```

Then we call our __Test Script__ to boot NuttX on QEMU and verify the output of [__OSTest__](https://lupyuen.github.io/articles/tinyemu3#daily-automated-testing): [test-nsh64.sh](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/test-nsh64.sh)

```bash
## Test Script: Apache NuttX RTOS for QEMU RISC-V 64-bit Flat Build
BUILD_PREFIX=qemu-riscv-nsh64

## Build Date is today (YYYY-MM-DD)
BUILD_DATE=$(date +'%Y-%m-%d')

## Download the latest NuttX build
wget -q https://github.com/lupyuen/nuttx-riscv64/releases/download/$BUILD_PREFIX-$BUILD_DATE/nuttx.zip
unzip -o nuttx.zip

## Write the Release Tag for populating the GitHub Release Notes later
echo "$BUILD_PREFIX-$BUILD_DATE" >/tmp/release-$BUILD_PREFIX.tag

## Boot NuttX on QEMU and run OSTest
wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-nsh64.exp
chmod +x qemu-riscv-nsh64.exp
./qemu-riscv-nsh64.exp
```

[(__qemu-riscv-nsh64.exp__ is here)](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-nsh64.exp)

Finally our Task Script calls our __Upload Script__, to upload the Test Log into the __GitHub Release Notes__: [upload-nsh64.sh](https://github.com/lupyuen/nuttx-riscv64/blob/main/task/upload-nsh64.sh)

```bash
## Upload Test Log to GitHub Release Notes of Apache NuttX RTOS for QEMU RISC-V 64-bit Flat Build
## Parameters: Release Tag, Test Log
repo=lupyuen/nuttx-riscv64
tag=$1
log=$2

## Preserve the Auto-Generated GitHub Release Notes.
## Fetch the current GitHub Release Notes and extract the body text.
gh release view \
  `cat $tag` \
  --json body \
  --jq '.body' \
  --repo $repo \
  >/tmp/upload-nsh64.old

## Find the position of the Previous Test Log, starting with "```"
cat /tmp/upload-nsh64.old \
  | grep '```' --max-count=1 --byte-offset \
  | sed 's/:.*//g' \
  >/tmp/upload-nsh64-previous-log.txt
prev=`cat /tmp/upload-nsh64-previous-log.txt`

## If Previous Test Log exists, discard it
if [ "$prev" != '' ]; then
  cat /tmp/upload-nsh64.old \
    | head --bytes=$prev \
    >>/tmp/upload-nsh64.log
else
  ## Else copy the entire Release Notes
  cat /tmp/upload-nsh64.old \
    >>/tmp/upload-nsh64.log
  echo "" >>/tmp/upload-nsh64.log
fi

## Show the Test Status
grep "^===== " $log \
  | colrm 1 6 \
  >>/tmp/upload-nsh64.log

## Enquote the Test Log without Carriage Return and Terminal Control Characters.
## The long pattern for sed doesn't work on macOS.
echo '```text' >>/tmp/upload-nsh64.log
cat $log \
  | tr -d '\r' \
  | tr -d '\r' \
  | sed 's/\x08/ /g' \
  | sed 's/\x1B(B//g' \
  | sed 's/\x1B\[K//g' \
  | sed 's/\x1B[<=>]//g' \
  | sed 's/\x1B\[[0-9:;<=>?]*[!]*[A-Za-z]//g' \
  | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g' \
  >>/tmp/upload-nsh64.log
echo '```' >>/tmp/upload-nsh64.log

## Upload the Test Log to the GitHub Release Notes
gh release edit \
  `cat $tag` \
  --notes-file /tmp/upload-nsh64.log \
  --repo $repo
```
