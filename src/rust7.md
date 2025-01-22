# Rust Standard Library on Apache NuttX RTOS

📝 _30 Jan 2025_

![TODO](https://lupyuen.github.io/images/rust7-title.jpg)

__Freshly Baked:__ Here's how we [__Blink the LED__](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust-std/examples/rust/hello/src/lib.rs) with __Rust Standard Library__ on [__Apache NuttX RTOS__](TODO)...

```rust
// Open the LED Device for NuttX
let fd = open(      // Equivalent to NuttX open()
  "/dev/userleds",  // LED Device
  OFlag::O_WRONLY,  // Write Only
  Mode::empty()     // No Modes
).unwrap();         // Halt on Error

// Define the ioctl() function for Flipping LEDs
const ULEDIOC_SETALL: i32 = 0x1d03;  // ioctl() Command
ioctl_write_int_bad!(  // ioctl() will write One Int Value (LED Bit State)
  led_set_all,         // Name of our New Function
  ULEDIOC_SETALL       // ioctl() Command to send
);

// Flip LED 1 to On
unsafe {             // Be careful of ioctl()
  led_set_all(       // Set the LEDs for...
    fd.as_raw_fd(),  // LED Device
    1                // LED 1 (Bit 0) turns On
  ).unwrap();        // Halt on Error
}  // Equivalent to ioctl(fd, ULEDIOC_SETALL, 1)

// Flip LED 1 to Off: ioctl(fd, ULEDIOC_SETALL, 0)
unsafe { led_set_all(fd.as_raw_fd(), 0).unwrap(); }
```

Which requires the __`nix` Rust Crate__ / Library...

```bash
## Add the `nix` Rust Crate
## To our NuttX Rust App
$ cd apps/examples/rust/hello
$ cargo add nix --features fs,ioctl

Updating crates.io index
Adding nix v0.29.0 to dependencies
Features: + fs + ioctl
```
_(OK it's more complicated. Stay tuned)_

All this is now possible thanks to the awesome work by [__Huang Qi__](https://github.com/apache/nuttx-apps/pull/2487)! 🎉

# Compile our Rust Hello App

TODO: Instructions

TODO: Run our Rust Hello App

Some bits are a little wonky

- [examples: New app to build Rust with Cargo](https://github.com/apache/nuttx-apps/pull/2487)

- [Add NuttX based targets for RISC-V and ARM](https://github.com/rust-lang/rust/pull/127755)

# JSON with Serde

_What's this Serde?_

Think _"Serialize-Deserialize"_. [__Serde__](https://crates.io/crates/serde) is a Rust Crate / Library for Serializing and Deserializing our Data Structures. Works with [__JSON, CBOR, MessagePack, ...__](https://serde.rs/#data-formats)

This is how we __Serialize to JSON__ in our NuttX App: [nuttx-apps/lib.rs](https://github.com/apache/nuttx-apps/blob/master/examples/rust/hello/src/lib.rs)

```rust
// Allow Serde to Serialize and Deserialize a Person Struct
#[derive(Serialize, Deserialize)]
struct Person {
  name: String,  // Containing a Name (string)
  age:  u8,      // And Age (uint8_t)
}  // Note: Rust Strings live in Heap Memory!

// Main Function of our Hello Rust App
#[no_mangle]
pub extern "C" fn hello_rust_cargo_main() {

  // Create a Person Struct
  let john = Person {
    name: "John".to_string(),
    age:  30,
  };

  // Serialize our Person Struct
  let json_str = serde_json  // Rust Struct
    ::to_string(&john)  // Becomes a String
    .unwrap();          // Halt on Error
  println!("{}", json_str);
```

This prints...

```bash
NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo
{"name":"John","age":30}
```

Now we __Deserialize from JSON__: [nuttx-apps/lib.rs](https://github.com/apache/nuttx-apps/blob/master/examples/rust/hello/src/lib.rs)

```rust
  // Declare a String with JSON inside
  let json_data = r#"
    {
      "name": "Alice",
      "age": 28
    }"#;

  // Deserialize our JSON String
  // Into a Person Struct
  let alice: Person = serde_json
    ::from_str(json_data)
    .unwrap();
  println!("Deserialized: {} is {} years old",
    alice.name, alice.age);
```

Which prints...

```bash
Deserialized: Alice is 28 years old
```

Serde will also handle __JSON Formatting__: [nuttx-apps/lib.rs](https://github.com/apache/nuttx-apps/blob/master/examples/rust/hello/src/lib.rs)

```rust
  // Serialize our Person Struct
  // But neatly please
  let pretty_json_str = serde_json
    ::to_string_pretty(&alice)
    .unwrap();
  println!("Pretty JSON:\n{}", pretty_json_str);
```

Looks much neater!

```bash
Pretty JSON:
{
  "name": "Alice",
  "age": 28
}
```

[(Serde also runs on __Rust Core Library__, but super messy)](https://bitboom.github.io/2020-10-22/serde-no-std)

# Async Functions with Tokio

_What's this Tokio? Sounds like a city?_

Indeed! "Tokio" is inspired by Tokyo (and [__Metal I/O__](https://crates.io/crates/mio))

> [__Tokio__](https://en.wikipedia.org/wiki/Tokio_(software)) ... provides a runtime and functions that enable the use of Asynchronous I/O, allowing for Concurrency in regards to Task Completion

Inside our __Rust Hello App__, this is how we we run __Async Functions__ with Tokio: [nuttx-apps/lib.rs](https://github.com/apache/nuttx-apps/blob/master/examples/rust/hello/src/lib.rs)

```rust
// Use One Single Thread (Current NuttX Thread)
// To schedule Async Functions
tokio::runtime::Builder
  ::new_current_thread()  // Current Thread is the Single-Threaded Scheduler
  .enable_all()  // Enable the I/O and Time Functions
  .build()   // Create the Single-Threaded Scheduler
  .unwrap()  // Halt on Error
  .block_on( // Start the Scheduler
    async {  // With this Async Function
      println!("Hello world from tokio!");
  });

// Is it really async? Let's block and find out!
println!("Looping Forever...");
loop {}
```

[(Derived from __`#[tokio::main]`__)](https://tokio.rs/tokio/topics/bridging)

Which prints...

```bash
nsh> hello_rust_cargo
Hello world from tokio!
Looping Forever...
```

_Yawn. Tokio looks underwhelming?_

Ah we haven't seen the full power of __Tokio Multi-Threaded Async Functions__ on NuttX!

```bash
nsh> hello_rust_cargo
pthread_create
nx_pthread_create
Task 0 sleeping for 1000 ms
Task 1 sleeping for  950 ms
Task 2 sleeping for  900 ms
Task 3 sleeping for  850 ms
Finished time-consuming task
Task 3 stopping
Task 2 stopping
Task 1 stopping
Task 0 stopping
```

Check the Appendix for the __Tokio Async Demo__. That works beautifully on NuttX!

- TODO: test_async

_But NuttX has POSIX Threads. Why use Async Functions?_

TODO: Threads vs Tasks vs Processes

TODO: NodeJS

(We're not calling it _"Async Task"_. Because a Task in NuttX is more like a NuttX Process)

_How would we use Tokio?_

> [__Tokio__](https://tokio.rs/tokio/tutorial) is designed for __I/O-Bound Applications__ where each individual task spends most of its time waiting for I/O.

Which means it's great for [__Network Servers__](https://tokio.rs/tokio/tutorial/io). Instead of spawning many many __NuttX Threads__... We spawn a few threads and call __Async Functions__.

# LED Blinky with Nix

_We're running nix on NuttX?_

Oh that's [__`nix` Crate__](https://crates.io/crates/nix) that provides __Safer Rust Bindings__ for POSIX / Unix / Linux. (Nope, not NixOS)

This is how we add the library to our __Rust Hello App__...

```bash
$ cd ../apps/examples/rust/hello
$ cargo add nix \
  --features fs,ioctl \
  --git https://github.com/lupyuen/nix.git \
  --branch nuttx

Updating git repository `https://github.com/lupyuen/nix.git`
Adding nix (git) to dependencies
Features: + fs + ioctl
34 deactivated features
```

_The URL looks a little sus?_

Yep it's our Bespoke `nix` Crate. That's because the Official `nix` Crate doesn't support NuttX yet. We made [__a few tweaks__](https://github.com/lupyuen/nix/pull/1/files) to compile on NuttX. [(Details in the __Appendix__)](TODO)

_Why are we calling nix?_

We're __Blinking the LED__ on NuttX. We could call the [__POSIX API__](https://crates.io/crates/libc) direcly from Rust...

```rust
let fd = unsafe { libc::open("/dev/userleds", ...) };
unsafe { libc::ioctl(fd, ULEDIOC_SETALL, 1); }
unsafe { close(fd); }
```

But it doesn't look very... Safe. That's why we call the __Safer POSIX Bindings__ provided by `nix` (tweaked for NuttX). Like so: [wip-nuttx-apps/lib.rs](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust-std/examples/rust/hello/src/lib.rs)

```rust
// Open the LED Device for NuttX
let fd = open(      // Equivalent to NuttX open()
  "/dev/userleds",  // LED Device
  OFlag::O_WRONLY,  // Write Only
  Mode::empty()     // No Modes
).unwrap();         // Halt on Error

// Define the ioctl() function for Flipping LEDs
const ULEDIOC_SETALL: i32 = 0x1d03;  // ioctl() Command
ioctl_write_int_bad!(  // ioctl() will write One Int Value (LED Bit State)
  led_set_all,         // Name of our New Function
  ULEDIOC_SETALL       // ioctl() Command to send
);

// Flip LED 1 to On
unsafe {             // Be careful of ioctl()
  led_set_all(       // Set the LEDs for...
    fd.as_raw_fd(),  // LED Device
    1                // LED 1 (Bit 0) turns On
  ).unwrap();        // Halt on Error
}  // Equivalent to ioctl(fd, ULEDIOC_SETALL, 1)

// Flip LED 1 to Off: ioctl(fd, ULEDIOC_SETALL, 0)
unsafe { led_set_all(fd.as_raw_fd(), 0).unwrap(); }
```

_ULEDIOC_SETALL looks familiar?_

We spoke about _ULEDIOC_SETALL_ in [__an earlier article__](https://lupyuen.github.io/articles/rust6#blink-the-led). And the Rust Code above mirrors the [__C Version__](https://github.com/lupyuen2/wip-nuttx-apps/blob/nim/examples/hello/hello_main.c#L40-L85) of our Blinky App.

_How to run the Rust Blinky App?_

1.  Copy the files from TODO...

1.  Overwrite our __Rust Hello App__: _apps/examples/rust/hello_

1.  [Rebuild our __NuttX Project__](TODO)

1.  Then run it with __QEMU RISC-V Emulator__

```bash
TODO
```

QEMU Emulator shows the __Emulated LED__ on NuttX.

[(What about __Rust Embedded HAL__?)](TODO)

# Owned File Descriptors

__Safety Quiz:__ Why will this run OK...

```rust
// Copied from above: Open the LED Device
let owned_fd = open("/dev/userleds", OFlag::O_WRONLY, Mode::empty())
  .unwrap();  // Returns an Owned File Descriptor
...
// Copied from above: Set the LEDs via ioctl()
led_set_all(
  owned_fd.as_raw_fd(),  // Borrow the Raw File Descriptor
  1                      // Flip LED 1 to On
).unwrap();              // Yep runs OK
```

But not this?

```rust
// Fetch earlier the Raw File Descriptor (from the LED Device)
let raw_fd = open("/dev/userleds", OFlag::O_WRONLY, Mode::empty())
  .unwrap()      // Returns an Owned File Descriptor
  .as_raw_fd();  // Which becomes a Raw File Descriptor
...
// Set the LEDs via ioctl()
led_set_all(
  raw_fd,    // Use the earlier Raw File Descriptor
  1          // Flip LED 1 to On
).unwrap();  // Oops will fail!
```

The second snippet will fail with this __EBADF Error__...

```bash
nsh> hello_rust_cargo
thread '<unnamed>' panicked at src/lib.rs:32:33:
called `Result::unwrap()` on an `Err` value: EBADF
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

There's something odd about __Raw File Descriptors__ vs __Owned File Descriptors__... Fetching the raw one too early might cause __EBADF Errors__. Here's why...

_What's a Raw File Descriptor?_

In NuttX and POSIX: [__Raw File Descriptor__](https://github.com/apache/nuttx/blob/master/include/stdio.h#L65-L71) is a __Plain Integer__ that specifies an I/O Stream...

|File Descriptor|Purpose|
|:---:|:----|
| 0 | Standard Input
| 1 | Standard Output
| 2 | Standard Error
| 3 | /dev/userleds <br> _(assuming we opened it)_

_What about Owned File Descriptor?_

In Rust: [__Owned File Descriptor__](https://doc.rust-lang.org/std/os/fd/struct.OwnedFd.html) is a __Rust Object__, wrapped around a Raw File Descriptor.

And Rust Objects can be __Automatically Dropped__, when they go out of scope. (Unlike Integers)

_Which causes the Second Snippet to fail?_

Exactly! _open()_ returns an __Owned File Descriptor__...

```rust
// Open the LED Device
let raw_fd = open("/dev/userleds", OFlag::O_WRONLY, Mode::empty())
  .unwrap()      // Returns an Owned File Descriptor
  .as_raw_fd();  // Which becomes a Raw File Descriptor
```

But we turned it into __Raw File Descriptor__. (The Plain Integer, not the Rust Object)

Oops! Our Owned File Descriptor goes __out of scope__ and gets dropped by Rust.

Which means Rust will helpfully close _/dev/userleds_. Since it's closed, the Raw File Descriptor __becomes invalid__...

```rust
// Set the LEDs via ioctl()
led_set_all(
  raw_fd,    // Use the earlier Raw File Descriptor
  1          // Flip LED 1 to On
).unwrap();  // Oops will fail with EBADF Error!
```

Resulting in the [__EBADF Error__](https://man.freebsd.org/cgi/man.cgi?errno(2)). _ioctl()_ failed because _/dev/userleds_ is already closed!

__Lesson Learnt:__ Be careful with Owned File Descriptors. They are super helpful for auto-closing our files. But might have strange consequences.

# Nix vs Rustix

_Is there a safer way to call ioctl()?_

Calling _ioctl()_ from Rust will surely get messy: It's an __Unsafe Call__ that might cause bad writes into the NuttX Kernel! (If we're not careful)

At the top of the article, we saw __`nix`__ crate calling _ioctl()_. Now we look at [__Rustix__](TODO) calling _ioctl()_: [rustix/fs/ioctl.rs](https://github.com/bytecodealliance/rustix/blob/main/src/fs/ioctl.rs#L16-L32)

```rust
// In Rustix: ioctl() is also unsafe
unsafe {
  // Create an "Ioctl Getter"
  // That will read data thru ioctl()
  let ctl = ioctl::Getter::<  // Ioctl Getter has 2 attributes...
    ioctl::BadOpcode<  // Attribute #1: Ioctl Command Code
      { c::BLKSSZGET } // Which is "Fetch the Logical Block Size of a Block Device"
    >,
    c::c_uint  // Attribute #2: Ioctl Getter will read a uint32_t thru ioctl()
  >::new();    // Create the Ioctl Getter

  // Now that we have the Ioctl Getter
  // We call ioctl() on the File Descriptor
  // Equivalent to: ioctl(fd, BLKSSZGET, &output) ; return output
  ioctl::ioctl(
    fd,  // File Descriptor
    ctl  // Ioctl Getter
  ) // Returns the Value Read (Or Error)
}
```

[(Based on the __Rustix Docs__)](https://docs.rs/rustix/latest/rustix/ioctl/index.html)

TODO: Nix vs Rustix

Updated nix

```text
Implement I/O Safety #1750
https://github.com/nix-rust/nix/issues/1750

Feature Name: io_safety
https://github.com/rust-lang/rfcs/blob/master/text/3128-io-safety.md
```

# What's Next

_Which platforms are supported for NuttX + Rust Standard Library?_

Arm and RISC-V (32-bit and 64-bit). [__Check this article__](https://nuttx.apache.org/docs/latest/guides/rust.html) for updates.

_Will it run on a RISC-V SBC?_

Sorry 64-bit __RISC-V Kernel Mode__ is [__not supported yet__](https://github.com/apache/nuttx-apps/pull/2487#issuecomment-2601488835).

_How to test?_

TODO: Build Farm? Docker? How to bisect

Next Article: Why __Sync-Build-Ingest__ is super important for NuttX Continuous Integration. And how we monitor it with our __Magic Disco Light__.

After That: Since we can __Rewind NuttX Builds__ and automatically __Git Bisect__... Can we create a Bot that will fetch the __Failed Builds from NuttX Dashboard__, identify the Breaking PR, and escalate to the right folks?

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.org/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/rust7.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/rust7.md)

# Appendix: Build NuttX for Rust Standard Library

TODO: Prerequisite

```text
hello_rust_cargo on Apache NuttX RTOS rv-virt:leds64
https://gist.github.com/lupyuen/6985933271f140db0dc6172ebba9bff5

hello_rust_cargo on macOS
https://gist.github.com/lupyuen/a2b91b5cc15824a31c287fbb6cda5fa2

hello_rust_cargo on Apache NuttX RTOS rv-virt:leds
https://gist.github.com/lupyuen/ccfae733657b864f2f9a24ce41808144

rm -rf .cargo .rustup rust rust2
https://rustup.rs/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Standard Installation 
. "$HOME/.cargo/env"

## error: the `-Z` flag is only accepted on the nightly channel of Cargo, but this is the `stable` channel
rustup update
rustup toolchain install nightly
rustup default nightly
rustc --version

## error: "/home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/Cargo.lock" does not exist, unable to build with the standard library, try: rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

mkdir rust
cd rust
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

git status && hash1=`git rev-parse HEAD`
pushd ../apps
git status && hash2=`git rev-parse HEAD`
popd
echo NuttX Source: https://github.com/apache/nuttx/tree/$hash1 >nuttx.hash
echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$hash2 >>nuttx.hash
cat nuttx.hash

make distclean
## tools/configure.sh rv-virt:nsh64
## tools/configure.sh rv-virt:knsh64
## tools/configure.sh rv-virt:leds
tools/configure.sh rv-virt:leds64

grep STACK .config

## error: Error loading target specification: Could not find specification for target "riscv64imafdc-unknown-nuttx-elf". Run `rustc --print target-list` for a list of built-in targets
## Disable CONFIG_ARCH_FPU
kconfig-tweak --disable CONFIG_ARCH_FPU

## Enable CONFIG_SYSTEM_TIME64 / CONFIG_FS_LARGEFILE / CONFIG_DEV_URANDOM / CONFIG_TLS_NELEM = 16
kconfig-tweak --enable CONFIG_SYSTEM_TIME64
kconfig-tweak --enable CONFIG_FS_LARGEFILE
kconfig-tweak --enable CONFIG_DEV_URANDOM
kconfig-tweak --set-val CONFIG_TLS_NELEM 16

## Enable Hello Rust Cargo App
kconfig-tweak --enable CONFIG_EXAMPLES_HELLO_RUST_CARGO

## For knsh64
kconfig-tweak --set-val CONFIG_EXAMPLES_HELLO_RUST_CARGO_STACKSIZE 16384

## Update the Kconfig Dependencies
make olddefconfig

grep STACK .config

dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x8006bbc0      2048      1016    49.6%    irq
dump_task:       0     0   0 FIFO     Kthread -   Ready              0000000000000000 0x8006e7f0      1904       888    46.6%    Idle_Task
dump_task:       1     1 100 RR       Task    -   Waiting Semaphore  0000000000000000 0x8006fd38      2888      1944    67.3%    nsh_main
dump_task:       3     3 100 RR       Task    -   Running            0000000000000000 0x80071420      1856      1856   100.0%!   hello_rust_cargo
QEMU: Terminated

   Compiling std v0.0.0 (/home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std)
error[E0308]: mismatched types
    --> /home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/pal/unix/fs.rs:1037:33
     |
1037 |         unsafe { CStr::from_ptr(self.entry.d_name.as_ptr()) }
     |                  -------------- ^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `*const u8`, found `*const i8`
     |                  |
     |                  arguments to this function are incorrect
     |
     = note: expected raw pointer `*const u8`
                found raw pointer `*const i8`
note: associated function defined here
    --> /home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ffi/c_str.rs:264:25
     |
264  |     pub const unsafe fn from_ptr<'a>(ptr: *const c_char) -> &'a CStr {
     |                         ^^^^^^^^

macOS:
error[E0308]: mismatched types
    --> .rustup/toolchains/nightly-aarch64-apple-darwin/lib/rustlib/src/rust/library/std/src/sys/pal/unix/fs.rs:1037:33
     |
1037 |         unsafe { CStr::from_ptr(self.entry.d_name.as_ptr()) }
     |                  -------------- ^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `*const u8`, found `*const i8`
     |                  |
     |                  arguments to this function are incorrect
     |
     = note: expected raw pointer `*const u8`
                found raw pointer `*const i8`

## Remember to patch fs.rs
vi $HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/pal/unix/fs.rs
head -n 1049 $HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/pal/unix/fs.rs | tail -n 17

    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "fuchsia",
        target_os = "redox",
        target_os = "aix",
        target_os = "nto",
        target_os = "vita",
        target_os = "hurd",
    )))]
    fn name_cstr(&self) -> &CStr {
        // Previously: unsafe { CStr::from_ptr(self.entry.d_name.as_ptr()) }
        unsafe { CStr::from_ptr(self.entry.d_name.as_ptr() as *const u8) }
    }

make -j

qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -bios none \
  -kernel nuttx \
  -nographic

uname -a
hello
hello_rust_cargo

## Dump the disassembly to nuttx.S
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

riscv/leds64-nuttx.S
```

TODO: Override nightly

```bash
## Set Rust to Nightly Build
## Apply this to the Parent Folder
## So it will work for `nuttx` and `apps`
pushd ..
rustup override list
rustup override set nightly
rustup override list
popd
```

Sometimes we might need to clean up the __Rust Compiled Files__, if the compilation goes wonky...

```bash
## Erase the Rust Build
pushd ../apps/examples/rust/hello
cargo clean
popd
```

# Appendix: Tokio Async Threading

Earlier we saw Tokio's __Single-Threaded Scheduler__, running on the __Current NuttX Thread__...

- TODO

```rust
// Use One Single Thread (Current NuttX Thread)
// To schedule Async Functions
tokio::runtime::Builder
  ::new_current_thread()  // Current Thread is the Single-Threaded Scheduler
  .enable_all()  // Enable the I/O and Time Functions
  .build()   // Create the Single-Threaded Scheduler
  .unwrap()  // Halt on Error
  .block_on( // Start the Scheduler
    async {  // With this Async Function
      println!("Hello world from tokio!");
  });

// Is it really async? Let's block and find out!
println!("Looping Forever...");
loop {}
```

Which isn't terribly exciting...

```bash
nsh> hello_rust_cargo
Hello world from tokio!
Looping Forever...
```

Now we try Tokio's __Multi-Threaded Scheduler__. And we create __One New NuttX Thread__ for the Scheduler: [wip-nuttx-apps/lib.rs](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust-std/examples/rust/hello/src/lib.rs)

```rust
// Run 4 Async Functions in the Background
// By creating One New NuttX Thread
// Based on https://tokio.rs/tokio/topics/bridging
fn test_async() {

  // Create a Multi-Threaded Scheduler
  // Containing One New NuttX Thread
  let runtime = tokio::runtime::Builder
    ::new_multi_thread() // Multi-Threaded Scheduler
    .worker_threads(1)   // With One New NuttX Thread for our Scheduler
    .enable_all() // Enable the I/O and Time Functions
    .build()      // Create the Multi-Threaded Scheduler
    .unwrap();    // Halt on Error

  // Create 4 Async Functions
  // Remember their Async Handles
  let mut handles = Vec::with_capacity(4);
  for i in 0..4 {
    handles.push(        // Remember the Async Handles
      runtime.spawn(     // Start in the Background
        my_bg_task(i))); // Our Async Function
  }

  // Pretend to be busy while Async Functions execute (in the background)
  // We wait 750 milliseconds
  std::thread::sleep(
    tokio::time::Duration::from_millis(750));
  println!("Finished time-consuming task.");

  // Wait for All Async Functions to complete
  for handle in handles {
    runtime
      .block_on(handle)  // Wait for One Async Function to complete
      .unwrap();
  }
}

// Our Async Function that runs in the background...
// If i=0: Sleep for 1000 ms
// If i=1: Sleep for  950 ms
// If i=2: Sleep for  900 ms
// If i=3: Sleep for  850 ms
async fn my_bg_task(i: u64) {
  let millis = 1000 - 50 * i;
  println!("Task {} sleeping for {} ms.", i, millis);
  tokio::time::sleep(
    tokio::time::Duration::from_millis(millis)
  ).await;  // Wait for sleep to complete
  println!("Task {} stopping.", i);
}

// Needed by Tokio Multi-Threaded Scheduler
#[no_mangle]
pub extern "C" fn pthread_set_name_np() {}
```

Which shows 

```bash
nsh> hello_rust_cargo
pthread_create
nx_pthread_create
Task 0 sleeping for 1000 ms
Task 1 sleeping for  950 ms
Task 2 sleeping for  900 ms
Task 3 sleeping for  850 ms
Finished time-consuming task
Task 3 stopping
Task 2 stopping
Task 1 stopping
Task 0 stopping
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/46db6d1baee0e589774cc43dd690da07)

TODO: [Bridging with sync code](https://tokio.rs/tokio/topics/bridging)

_What if we increase the Worker Threads? From 1 to 2?_

```rust
// Two Worker Threads instead of One
let runtime = tokio::runtime::Builder
  ::new_multi_thread() // New Multi-Threaded Scheduler
  .worker_threads(2)   // With Two New NuttX Threads for our Scheduler
```

TODO: Not much difference?

```text
pthread_create: pthread_entry=0x80048f10, arg=0x800873e8
nx_pthread_create: entry=0x80048f10, arg=0x800873e8
pthread_create: pthread_entry=0x80048f10, arg=0x80287830
nx_pthread_create: entry=0x80048f10, arg=0x80287830
Task 0 sleeping for 1000 ms.
Task 1 sleeping for 950 ms.
Task 2 sleeping for 900 ms.
Task 3 sleeping for 850 ms.
Finished time-consuming task.
Task 3 stopping.
Task 2 stopping.
Task 1 stopping.
Task 0 stopping.
nsh> 
```

TODO: pthread_create

```text
https://github.com/lupyuen2/wip-nuttx/blob/master/fs/vfs/fs_ioctl.c#L263-L264

#include <debug.h>////
int ioctl(int fd, int req, ...)
{
  // _info("fd=0x%x, req=0x%x", fd, req);////


https://github.com/lupyuen2/wip-nuttx/blob/master/libs/libc/pthread/pthread_create.c#L93

#include <debug.h>////
int pthread_create(FAR pthread_t *thread, FAR const pthread_attr_t *attr,
                   pthread_startroutine_t pthread_entry, pthread_addr_t arg)
{
  _info("pthread_entry=%p, arg=%p", pthread_entry, arg);////

https://github.com/lupyuen2/wip-nuttx/blob/master/sched/pthread/pthread_create.c#L34

#include <debug.h>////
int nx_pthread_create(pthread_trampoline_t trampoline, FAR pthread_t *thread,
                      FAR const pthread_attr_t *attr,
                      pthread_startroutine_t entry, pthread_addr_t arg)
{
  _info("entry=%p, arg=%p", entry, arg);////

```

# Appendix: Porting Nix to NuttX

TODO: Redox, BSD not Linux, PR

_What happens when we call nix crate as-is on NuttX?_

TODO

```bash
$ pushd ../apps/examples/rust/hello
$ cargo add nix --features fs,ioctl
Adding nix v0.29.0 to dependencies
Features: + fs + ioctl
33 deactivated features

$ popd
$ make -j

error[E0432]: unresolved import `self::const](TODO)

  -->   [errno.rs:19:15
   |
19 | pub use self::consts::*;
   |               ^^^^^^ could not find `consts` in `self`

error[E0432]: unresolved import `self::Errn](TODO)

   -->  [errno.rs:198:15
    |
198 |     use self::Errno::*;
    |               ^^^^^ could not find `Errno` in `self`

error[E0432]: unresolved import `crate::errno::Errn](TODO)

 -->  [fcntl.rs:2:5
  |
2 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `crate::errno::Errn](TODO)

 -->  [sys/signal.rs:6:5
  |
6 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `crate::errno::Errn](TODO)

 -->  [unistd.rs:3:5
  |
3 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `errno::Errn](TODO)

   -->  [lib.rs:194:5
    |
194 | use errno::Errno;
    |     ^^^^^^^-----
    |     |      |
    |     |      help: a similar name exists in the module: `errno`
    |     no `Errno` in `errno`
```

TODO: Fix nix

1.  We modified [src/errno.rs](TODO), copying FreeBSD `#[cfg(target_os = "freebsd")]` to NuttX `#[cfg(target_os = "nuttx")]`

1.  NuttX seems to have a similar POSIX Profile to __Redox OS__? That's why a lot of the modded code looks like this: [src/sys/time.rs](TODO)

    ```rust
    #[cfg(not(any(target_os = "redox", target_os="nuttx")))]
    pub const UTIME_OMIT: TimeSpec = ...

    #[cfg(not(any(target_os = "redox", target_os = "nuttx")))]
    pub const UTIME_NOW: TimeSpec = ...
    ```

1.  __For NuttX ioctl():__ It works more like BSD (parameter is `int`) than Linux (parameter is `long`): [sys/ioctl/mod.rs](TODO)

    TODO

1.  Here are all the files we modified:

    [All Modified Files](https://github.com/lupyuen/nix/pull/1/files)

    [errno.rs](TODO)

    [sys/time.rs](TODO)

    [fcntl.rs](TODO)

    [unistd.rs](TODO)

    [sys/stat.rs](TODO)

    [sys/statvfs.rs](TODO)

    [sys/mod.rs](TODO)

    [sys/ioctl/mod.rs](TODO)

    [sys/ioctl/bsd.rs](TODO)

<hr>

__Troubleshooting NuttX ioctl()__

To figure out if nix was passing parameters correctly to NuttX: We inserted Debug Code into NuttX Kernel...

```c
TODO
riscv/nuttx/fs/vfs/fs_ioctl.c
#include <debug.h>
int ioctl(int fd, int req, ...) {
  _info("fd=0x%x, req=0x%x", fd, req);////
```

Which [__Ioctl Macro__](https://docs.rs/nix/latest/nix/sys/ioctl/) shall we use in nix? We tried __ioctl_none!__...

```rust
const ULEDIOC_SETALL: i32 = 0x1d03;
ioctl_none!(led_on, ULEDIOC_SETALL, 1);
unsafe { led_on(fd).unwrap(); }
```

But the __ioctl() Command Code__ got mangled up (`0x201d0301` should be `0x1d03`)

```bash
NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo
fd=3
ioctl: fd=0x3, req=0x201d0301

thread '<unnamed>' panicked at src/lib.rs:31:25:
called `Result::unwrap()` on an `Err` value: ENOTTY
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Then we tried __ioctl_write_int!__...

```rust
const ULEDIOC_SETALL: i32 = 0x1d03;
ioctl_write_int!(led_on, ULEDIOC_SETALL, 1);
unsafe { led_on(fd, 1).unwrap(); }
```

Nope the __ioctl() Command Code__ is still mangled (`0x801d0301` should be `0x1d03`)

```bash
nsh> hello_rust_cargo
ioctl: fd=0x3, req=0x801d0301
thread '<unnamed>' panicked at src/lib.rs:30:28:
called `Result::unwrap()` on an `Err` value: ENOTTY
```

Finally this works: __ioctl_write_int_bad!__...

```rust
const ULEDIOC_SETALL: i32 = 0x1d03;
ioctl_write_int_bad!(led_set_all, ULEDIOC_SETALL);

// Equivalent to ioctl(fd, ULEDIOC_SETALL, 1)
unsafe { led_set_all(fd, 1).unwrap(); }

// Equivalent to ioctl(fd, ULEDIOC_SETALL, 0)
unsafe { led_set_all(fd, 0).unwrap(); }
```

__ioctl() Command Code__ `0x1d03` is hunky dory yay!

```bash
NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo
fd=3
ioctl: fd=0x3, req=0x1d03
board_userled: LED 1 set to 1
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
ioctl: fd=0x3, req=0x1d03
board_userled: LED 1 set to 0
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
```

# Appendix: Snooping Tokio on NuttX

TODO make V=1

```text
`make V=1` for `rv-virt:leds64`
https://gist.github.com/lupyuen/b8f051c25e872fb8a444559c3dbf6374

 1018  make distclean
 1019  tools/configure.sh rv-virt:leds64
 1020  ## Disable CONFIG_ARCH_FPU
 1021  kconfig-tweak --disable CONFIG_ARCH_FPU
 1022  ## Enable CONFIG_SYSTEM_TIME64 / CONFIG_FS_LARGEFILE / CONFIG_DEV_URANDOM / CONFIG_TLS_NELEM = 16
 1023  kconfig-tweak --enable CONFIG_SYSTEM_TIME64
 1024  kconfig-tweak --enable CONFIG_FS_LARGEFILE
 1025  kconfig-tweak --enable CONFIG_DEV_URANDOM
 1026  kconfig-tweak --set-val CONFIG_TLS_NELEM 16
 1027  ## Enable Hello Rust Cargo App
 1028  kconfig-tweak --enable CONFIG_EXAMPLES_HELLO_RUST_CARGO
 1029  ## For knsh64
 1030  kconfig-tweak --set-val CONFIG_EXAMPLES_HELLO_RUST_CARGO_STACKSIZE 16384
 1031  ## Update the Kconfig Dependencies
 1032  make olddefconfig
 1033  make V=1
```

TODO dump disassembly

```text
cd /home/luppy/rust/apps/examples/rust/hello
cargo build --release -Zbuild-std=std,panic_abort --manifest-path /home/luppy/rust/apps/examples/rust/hello/Cargo.toml --target riscv64imac-unknown-nuttx-elf

riscv-none-elf-gcc -E -P -x c -isystem /home/luppy/rust/nuttx/include -D__NuttX__ -DNDEBUG -D__KERNEL__  -I /home/luppy/rust/nuttx/arch/risc-v/src/chip -I /home/luppy/rust/nuttx/arch/risc-v/src/common -I /home/luppy/rust/nuttx/sched   /home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script -o  /home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script.tmp

riscv-none-elf-ld --entry=__start -melf64lriscv --gc-sections -nostdlib --cref -Map=/home/luppy/rust/nuttx/nuttx.map --print-memory-usage -T/home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script.tmp  -L /home/luppy/rust/nuttx/staging -L /home/luppy/rust/nuttx/arch/risc-v/src/board  \
        -o /home/luppy/rust/nuttx/nuttx   \
        --start-group -lsched -ldrivers -lboards -lc -lmm -larch -lm -lapps -lfs -lbinfmt -lboard /home/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imac/lp64/libgcc.a /home/luppy/rust/apps/examples/rust/hello/target/riscv64imac-unknown-nuttx-elf/release/libhello.a --end-group

Remove release, change to debug
pushd ../apps/examples/rust/hello
cargo build -Zbuild-std=std,panic_abort --manifest-path /home/luppy/rust/apps/examples/rust/hello/Cargo.toml --target riscv64imac-unknown-nuttx-elf
popd

riscv-none-elf-gcc -E -P -x c -isystem /home/luppy/rust/nuttx/include -D__NuttX__ -DNDEBUG -D__KERNEL__  -I /home/luppy/rust/nuttx/arch/risc-v/src/chip -I /home/luppy/rust/nuttx/arch/risc-v/src/common -I /home/luppy/rust/nuttx/sched   /home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script -o  /home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script.tmp

riscv-none-elf-ld --entry=__start -melf64lriscv --gc-sections -nostdlib --cref -Map=/home/luppy/rust/nuttx/nuttx.map --print-memory-usage -T/home/luppy/rust/nuttx/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script.tmp  -L /home/luppy/rust/nuttx/staging -L /home/luppy/rust/nuttx/arch/risc-v/src/board  \
        -o /home/luppy/rust/nuttx/nuttx   \
        --start-group -lsched -ldrivers -lboards -lc -lmm -larch -lm -lapps -lfs -lbinfmt -lboard /home/luppy/xpack-riscv-none-elf-gcc-13.2.0-2/bin/../lib/gcc/riscv-none-elf/13.2.0/rv64imac/lp64/libgcc.a /home/luppy/rust/apps/examples/rust/hello/target/riscv64imac-unknown-nuttx-elf/debug/libhello.a --end-group

## Dump the disassembly to nuttx.S
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

Cargo build debug
https://gist.github.com/lupyuen/7b52d54725aaa831cb3dddc0b68bb41f
riscv/leds64-debug-nuttx.S
```

TODO dump libhello

```text
## Dump the libhello.a disassembly to libhello.S
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  /home/luppy/rust/apps/examples/rust/hello/target/riscv64imac-unknown-nuttx-elf/debug/libhello.a \
  >libhello.S \
  2>&1

riscv/libhello.S
```

Search for pthread_create

```text
/home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/pal/unix/thread.rs:85
                    assert_eq!(libc::pthread_attr_setstacksize(&mut attr, stack_size), 0);
                }
            };
        }

        let ret = libc::pthread_create(&mut native, &attr, thread_start, p as *mut _);
 122:	00000517          	auipc	a0,0x0	122: R_RISCV_PCREL_HI20	std::sys::pal::unix::thread::Thread::new::thread_start
 126:	00050613          	mv	a2,a0	126: R_RISCV_PCREL_LO12_I	.Lpcrel_hi254
 12a:	0148                	add	a0,sp,132
 12c:	012c                	add	a1,sp,136
 12e:	f82e                	sd	a1,48(sp)
 130:	00000097          	auipc	ra,0x0	130: R_RISCV_CALL_PLT	pthread_create
 134:	000080e7          	jalr	ra # 130 <.Lpcrel_hi254+0xe>
 138:	85aa                	mv	a1,a0
 13a:	7542                	ld	a0,48(sp)
 13c:	862e                	mv	a2,a1
 13e:	fc32                	sd	a2,56(sp)
 140:	1eb12e23          	sw	a1,508(sp)

https://doc.rust-lang.org/src/std/sys/pal/unix/thread.rs.html#84

https://github.com/rust-lang/rust/blob/master/library/std/src/thread/mod.rs#L502
    unsafe fn spawn_unchecked_<'scope, F, T>(
        let my_thread = Thread::new(id, name);

Disassembly of section .text._ZN4core3ptr164drop_in_place$LT$std..thread..Builder..spawn_unchecked_..MaybeDangling$LT$tokio..runtime..blocking..pool..Spawner..spawn_thread..$u7b$$u7b$closure$u7d$$u7d$$GT$$GT$17hdb2d2ae6bc31ecdfE:

0000000000000000 <core::ptr::drop_in_place<std::thread::Builder::spawn_unchecked_::MaybeDangling<tokio::runtime::blocking::pool::Spawner::spawn_thread::{{closure}}>>>:
core::ptr::drop_in_place<std::thread::Builder::spawn_unchecked_::MaybeDangling<tokio::runtime::blocking::pool::Spawner::spawn_thread::{{closure}}>>:
/home/luppy/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/ptr/mod.rs:523
   0:	1141                	add	sp,sp,-16
   2:	e406                	sd	ra,8(sp)
   4:	e02a                	sd	a0,0(sp)
   6:	00000097          	auipc	ra,0x0	6: R_RISCV_CALL_PLT	<std::thread::Builder::spawn_unchecked_::MaybeDangling<T> as core::ops::drop::Drop>::drop
   a:	000080e7          	jalr	ra # 6 <core::ptr::drop_in_place<std::thread::Builder::spawn_unchecked_::MaybeDangling<tokio::runtime::blocking::pool::Spawner::spawn_thread::{{closure}}>>+0x6>
   e:	60a2                	ld	ra,8(sp)
  10:	0141                	add	sp,sp,16
  12:	8082                	ret
```

TODO NuttX Thread not Task

```text
hello_rust_cargo &
https://gist.github.com/lupyuen/0377d9e015fee1d6a833c22e1b118961
nsh> hello_rust_cargo &
hello_rust_cargo [4:100]
nsh> {"name":"John","age":30}
{"name":"Jane","age":25}
Deserialized: Alice is 28 years old
Pretty JSON:
{
  "name": "Alice",
  "age": 28
}
Hello world from tokio!

nsh> ps
  PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK            STACK    USED FILLED COMMAND
    0     0   0 FIFO     Kthread   - Ready              0000000000000000 0001904 0000712  37.3%  Idle_Task
    2     2 100 RR       Task      - Running            0000000000000000 0002888 0002472  85.5%! nsh_main
    4     4 100 RR       Task      - Ready              0000000000000000 0007992 0006904  86.3%! hello_rust_cargo
```
