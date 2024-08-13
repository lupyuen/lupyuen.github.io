# Early Days of Rust Apps on Apache NuttX RTOS

📝 _19 Aug 2024_

![TODO](https://lupyuen.github.io/images/rust6-title.jpg)

My student [__Rushabh Gala__](TODO) has successfully completed his project for [__Google Summer of Code__](TODO)

TODO

Final Report

Midterm Report

NuttX Workshop Presentation 

In this article we look at the challenges and (partial) solutions 

We have fixed the Rust Target for QEMU 64-bit RISC-V...

- [__"Fix the Rust and D Builds for QEMU RISC-V"__](https://github.com/apache/nuttx/pull/12854)

- [__"Add Rust Target for QEMU RISC-V 64-bit"__](https://github.com/apache/nuttx/pull/12858)

- [__"Add Build Config for leds64_rust"__](https://github.com/apache/nuttx/pull/12862)

1. Super interesting new development: Some folks in the NuttX Community are working with the Rust Project, adding NuttX as an official platform for Rust Standard Library! [(See this)](https://lists.apache.org/thread/oqx7p3vb4dcgko4mm2f0vqgqnkorn49p)

   This might take some time to complete, because supporting NuttX in the Rust Standard Library will require lots of coding and testing. So our Project Report is still relevant, it will be the "Interim Way" to build Rust Apps for NuttX. And we have to demonstrate how Rust Apps can be built and tested with Rust Core Library, without `cargo`. (Exactly what we're doing now)

1. __[Updated 11 Aug]__ "What's left to do": Here are the outstanding items for the project, which I have just completed. We fixed the Rust Build for QEMU 64-bit RISC-V, and added it to the NuttX Continuous Integration (at GitHub Actions)...

   - [__"Fix the Rust and D Builds for QEMU RISC-V"__](https://github.com/apache/nuttx/pull/12854)

   - [__"Add Rust Target for QEMU RISC-V 64-bit"__](https://github.com/apache/nuttx/pull/12858)

   - [__"Add Build Config for leds64_rust"__](https://github.com/apache/nuttx/pull/12862)

1. __[Updated 12 Aug]__ We're now building and testing `leds_rust` every daily at GitHub Actions. We will be notified if the Rust Build breaks or if the Rust Execution fails in future.

   [Test Log](https://github.com/lupyuen/nuttx-riscv64/actions/workflows/qemu-riscv-leds64-rust.yml)
   
   [GitHub Actions Workflow](https://github.com/lupyuen/nuttx-riscv64/blob/main/.github/workflows/qemu-riscv-leds64-rust.yml)


# Blink The LED

TODO

This is how we __Blink the LED__ in a NuttX Rust App: [examples/leds_rust/leds_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/leds_rust/leds_rust_main.rs)

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

Looks mighty similar to the [__C Version__](TODO)!

(But with simpler Error Handling than C, we'll talk more)

_What are safe_open and safe_ioctl?_

They are safer versions of __open__ and __ioctl__ from our [__NuttX Module__](TODO), which...

- Defines the Safe Wrappers: __`safe_*`__

- Imports __usleep__ and __close__ from C

- Plus the NuttX Constants: __O_WRONLY__ and __ULEDIOC_SETALL__

We import the __NuttX Module__ like so...

```rust
// Comment out these lines for testing on Linux / macOS / Windows
#![no_main]  // For NuttX Only: No Main Function
#![no_std]   // For NuttX Only: Use Rust Core Library (instead of Rust Standard Library)

// Import the NuttX Module
mod nuttx;
use nuttx::*;
```

And yes this code runs on Linux, macOS and Windows! We'll come back to this.

# Handle Errors

_Why the funny question mark?_

```rust
let fd = safe_open(  // Open the LED Device...
  "/dev/userleds",   // Device Path
  O_WRONLY           // Open for Write-Only
) ?;                 // Quit on error
```

Remember in C we check the [__Result Value__](TODO) at every call to __open__ and __ioctl__... Now with __safe_open__ and __safe_ioctl__, Rust does the checking for us!

If something goes wrong, the code above will exit the function with an __Error Value__. (Like if _"/dev/userleds"_ doesn't exist)

Our NuttX App becomes a little safer with the [__Question Mark Operator__](https://doc.rust-lang.org/rust-by-example/std/result/question_mark.html), by auto-checking the results of System Calls.

(Rust Compiler will warn us if we forget the Question Mark)

TODO: safe_puts buffer size

TODO: Managed File Descriptors

_But usleep and close are still unsafe?_

```rust
// Wait a while
unsafe { usleep(500_000); }
...
// Close the LED Device
unsafe { close(fd); }
```

Yeah there's not much point in wrapping __usleep__ and __close__? Since we don't check the Return Values.

# Runs on Linux / macOS / Windows

_Will our NuttX App actually run on Linux, macOS and Windows?_

```rust
// Comment out these lines for testing on Linux / macOS / Windows
#![no_main]  // For NuttX Only: No Main Function
#![no_std]   // For NuttX Only: Use Rust Core Library (instead of Rust Standard Library)
```

Yep indeed! Just comment out the above lines and run on __Linux / macOS / Windows (WSL)__:

```bash
$ git clone https://github.com/lupyuen/nuttx-rust-app
$ cd nuttx-rust-app
$ cd app
$ cargo run
Hello, Rust!!
Opening /dev/userleds
ERROR: rust_main() failed with error -1
```

Which fails (as expected) because _"/dev/userleds"_ doesn't exist on Linux / macOS / Windows.

This greatly simplifies our NuttX App Development: We could (potentially) compile and run our NuttX App on our __Local Computer__, before testing on NuttX!

(__Rust Analyzer__ won't work inside NuttX Projects)

# Main Function

_We saw the LED Blinky code in rust_main. Who calls rust_main?_

Remember that __rust_main__ returns a __Result Type__...

```rust
// `rust_main` accepts the args from NuttX Shell
// And returns a Result Code (int) or Error Code (int)
fn rust_main(_argc: i32, _argv: *const *const u8)
  -> Result<i32, i32> { ... }
```

But NuttX expects us to provide a Main Function named __leds_rust_main__. And it shall return an __Integer Result__. (Not a Result Type)

Thus we create an __leds_rust_main__ function that calls __rust_main__ and returns the right result...

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

They expect us to provide a __main__ function. Thus we do this...

```rust
// For Linux / macOS / Windows: Define the Main Function
#[cfg(not(target_os = "none"))]
fn main() {

  // Call Rust Main without args
  leds_rust_main(0, core::ptr::null());
}
```

# Panic Handler

_Anything else specific to NuttX?_

Yep NuttX Apps run on the [__Rust Core Library__](TODO) (no_std) and require a __Panic Handler__...

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

# No Crates in NuttX

_We're coding Rust in a strange way. Why not use crates and cargo?_

Ah that's because NuttX [__doesn't support Rust Crates__](TODO)! We can't use __cargo__ either, NuttX Build calls __rustc__ directly...

```bash
## Configure the NuttX Project
## for QEMU RISC-V 64-bit including Rust
$ tools/configure.sh rv-virt:leds64_rust

## Build the NuttX Project
## Which calls `rustc`
$ make
```

Which complicates our coding of NuttX Rust Apps. That's why we hope to test them on [__Linux / macOS / Windows__](TODO).

TODO: No Crates! Need to embed NuttX Module in every Rust App (common folder?)

# LED Drivers for NuttX

_12 weeks of GSoC: What else have we implemented?_

Remember we're blinking the LED? We tested it on Real Hardware: [__Ox64 BL808 SBC__](TODO). Which required us to create the GPIO and LED Drivers for Ox64 SBC...

- TODO: GPIO Driver for Ox64 SBC

- TODO: LED Driver for Ox64 SBC

TODO: Ox64, Kernel Mode

_What about folks without Ox64 SBC?_

We created the LED Driver for __QEMU RISC-V Emulator__, which will blink a Simulated LED on NuttX...

- TODO: QEMU LED Driver

Everyone can run the __Rust Blinky App__ (from above) and reproduce the exact same results.

TODO: QEMU 32-bit

# Daily Build and Test

_Our Rust Blinky App: Will it break someday?_

Yeah it's possible that our Rust App will someday __fail to build or execute__ correctly...

1.  __Rust Compiler__ might change and break our app

    (Since we're not calling it the __cargo__ way)

1.  __NuttX Makefiles__ might cause problems for Rust Apps

    (Because NuttX is mostly in C, not Rust)

That's why we extended the __Continuous Integration__ workflow for NuttX...

Every NuttX Pull Request will now trigger a rebuild of our [__Rust Blinky App__](TODO). If anything breaks, we'll find out right away!

TODO: Docker Container

_What if the Rust Blinky App fails to execute correctly?_

TODO: Auto test at GitHub Actions

TODO: leds_rust daily test

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/rust6.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust6.md)
