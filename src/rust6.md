# Early Days of Rust Apps on Apache NuttX RTOS

📝 _19 Aug 2024_

![TODO](https://lupyuen.github.io/images/rust6-title.jpg)

TODO

My student Rushabh Gala has successfully completed 

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

# Error Handling

_Why the funny question mark?_

```rust
let fd = safe_open(  // Open the LED Device...
  "/dev/userleds",   // Device Path
  O_WRONLY           // Open for Write-Only
) ?;                 // Quit on error
```

Normally in C we check the [__Result Value__](TODO) at every call to __open__ and __ioctl__... Now with __safe_open__ and __safe_ioctl__, Rust does the checking for us!

If something goes wrong, the code above will exit the function with an __Error Value__. (Like if _"/dev/userleds"_ doesn't exist)

Our NuttX App becomes a little safer with the [__Question Mark Operator__](https://doc.rust-lang.org/rust-by-example/std/result/question_mark.html), by auto-checking the results of System Calls.

(Rust Compiler will warn us if we forget the Question Mark)

# Runs on Linux / macOS / Windows

TODO

```bash
$ git clone https://github.com/lupyuen/nuttx-rust-app
$ cd nuttx-rust-app/
$ cd app
$ cargo run
Hello, Rust!!
Opening /dev/userleds
ERROR: rust_main() failed with error -1
```

# Main Function

TODO: Main Function

```rust
// For NuttX: This will be called by NuttX Shell
// For Linux / macOS / Windows: This wil be called by `main`
#[no_mangle]
pub extern "C" fn leds_rust_main(argc: i32, argv: *const *const u8)  // Args from NuttX Shell
  -> i32 {  // Return a Result Code (0) or Error Code (negative)

  // Call the program logic in Rust Main
  let res = rust_main(argc, argv);

  // If Rust Main returns an error, print it
  if let Err(e) = res {
    unsafe { printf(b"ERROR: rust_main() failed with error %d\n\0" as *const u8, e); }
    e
  } else {
    0
  }
}
```

TODO: Main Function for Linux / macOS / Windows

```rust
// For Linux / macOS / Windows: Define the Main Function
#[cfg(not(target_os = "none"))]
fn main() {

  // Call Rust Main without args
  leds_rust_main(0, core::ptr::null());
}
```

TODO: Panic Handler

```rust
// For NuttX Only: Import the Panic Type
#[cfg(target_os = "none")]
use core::{
  panic::PanicInfo,
  result::Result::{self, Err, Ok},
};

// For NuttX Only: Define the Panic Handler for `no_std`
#[cfg(target_os = "none")]  // For NuttX
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
  loop {}
}
```

TODO: Run locally

TODO: Test locally

TODO: No Crates! Need to embed NuttX Module in every Rust App (common folder?)

TODO: Safe Wrapper

TODO: safe_puts buffer size

TODO: Error Handling

TODO: QEMU LED Driver

TODO: Ox64, Kernel Mode

TODO: QEMU 32-bit

TODO: Auto test at GitHub Actions

TODO: leds_rust daily test

TODO: Docker Container

TODO: Hard to test on local computer, Rust Analyser won't work

TODO: Unsafe printf, usleep, close

TODO: Managed File Descriptors

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
