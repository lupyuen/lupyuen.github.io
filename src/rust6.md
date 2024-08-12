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

# TODO

TODO

[app/src/main.rs](https://github.com/lupyuen/nuttx-rust-app/blob/main/app/src/main.rs)

```rust
/* Comment out these lines for testing with Rust Standard Library */

// #![no_main]
// #![no_std]

/****************************************************************************
 * Modules
 ****************************************************************************/

mod nuttx;

/****************************************************************************
 * Uses
 ****************************************************************************/

#[cfg(target_os = "none")]
use core::{
    panic::PanicInfo,
    result::Result::{self, Err, Ok},
};
use nuttx::*;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Panic Handler (needed for [no_std] compilation)
 ****************************************************************************/

#[cfg(target_os = "none")] /* For NuttX */
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

/****************************************************************************
 * rust_main
 ****************************************************************************/

fn rust_main(_argc: i32, _argv: *const *const u8) -> Result<i32, i32> {
    /* "Hello, Rust!!" using puts() from libc */

    safe_puts("Hello, Rust!!");

    /* Blink LED 1 using ioctl() from NuttX */

    safe_puts("Opening /dev/userleds");
    let fd = safe_open("/dev/userleds", O_WRONLY)?;
    safe_puts("Set LED 1 to 1");

    safe_ioctl(fd, ULEDIOC_SETALL, 1)?;
    safe_puts("Sleeping...");
    unsafe {
        usleep(500_000);
    }

    safe_puts("Set LED 1 to 0");
    safe_ioctl(fd, ULEDIOC_SETALL, 0)?;
    unsafe {
        close(fd);
    }

    /* Exit with status 0 */

    Ok(0)
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * hello_rust_main
 ****************************************************************************/

#[no_mangle]
pub extern "C" fn hello_rust_main(_argc: i32, _argv: *const *const u8) -> i32 {
    /* Call the program logic in Rust Main */

    let res = rust_main(0, core::ptr::null());

    /* If Rust Main returns an error, print it */

    if let Err(e) = res {
        unsafe {
            printf(
                b"ERROR: rust_main() failed with error %d\n\0" as *const u8,
                e,
            );
        }
        e
    } else {
        0
    }
}

/****************************************************************************
 * main
 ****************************************************************************/

#[cfg(not(target_os = "none"))] /* For Testing Locally */
fn main() {
    hello_rust_main(0, core::ptr::null());
}
```

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
