# Rust Standard Library on Apache NuttX RTOS

📝 _30 Jan 2025_

![TODO](https://lupyuen.github.io/images/rust7-title.jpg)

__Freshly Baked:__ Here's how we [__Blink the LED__](TODO) with __Rust Standard Library__ on [__Apache NuttX RTOS__](TODO)...

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
_(OK it's more complicated. Stay tuned!)_

All this is now possible thanks to the awesome work by [__Huang Qi__](https://github.com/apache/nuttx-apps/pull/2487)! 🎉

# JSON with Serde

TODO

# Async Functions with Tokio

TODO

# LED Blinky with Nix

TODO: Not NixOS

# Owned File Descriptors

__Safety Quiz:__ Why will this work...

```rust
let owned_fd = open("/dev/userleds", OFlag::O_WRONLY, Mode::empty())
  .unwrap();  // Returns an Owned File Descriptor
...
led_set_all(
  owned_fd.as_raw_fd(),  // Borrow the Raw File Descriptor
  1
).unwrap();  // Yep runs OK
```

But not this?

```rust
let raw_fd = open("/dev/userleds", OFlag::O_WRONLY, Mode::empty())
  .unwrap()      // Returns an Owned File Descriptor
  .as_raw_fd();  // Which turns into a Raw File Descriptor
...
led_set_all(
  raw_fd,    // Use the Raw File Descriptor
  1
).unwrap();  // Oops will fail!
```

The second snippet will fail with this error...

```bash
NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo
thread '<unnamed>' panicked at src/lib.rs:32:33:
called `Result::unwrap()` on an `Err` value: EBADF
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```


# Nix vs Rustix

TODO: Are Nix ioctl safe?

# Appendix: Porting Nix to NuttX

TODO: Redox, BSD not Linux, PR

# TODO

```text
https://github.com/apache/nuttx-apps/blob/master/examples/rust/hello/src/lib.rs

examples: New app to build Rust with Cargo
https://github.com/apache/nuttx-apps/pull/2487

Add NuttX based targets for RISC-V and ARM
https://github.com/rust-lang/rust/pull/127755

The serde with no_std
https://bitboom.github.io/2020-10-22/serde-no-std

Hal?
demo app
why tokio for json
disassemble
Loop print something 
Strings
Patch 
Which platforms 
How to test
Build Farm? Docker?
How to bisect
Blinky
How to add crate
RISC-V SBC? No knsh64 yet
```

# TODO

```text
Rust in NuttX
https://nuttx.apache.org/docs/latest/guides/rust.html

examples: New app to build Rust with Cargo
https://github.com/apache/nuttx-apps/pull/2487

rust/hello: Optimize the build flags #2955
https://github.com/apache/nuttx-apps/pull/2955

https://github.com/apache/nuttx-apps/pull/2487#pullrequestreview-2538724037
Tested OK with make and rv-virt:nsh. Thank you so much! :-)
https://gist.github.com/lupyuen/37a28cc3ae0443aa29800d252e4345cf

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
kconfig-tweak --set-val CONFIG_EXAMPLES_HELLO_RUST_CARGO_STACKSIZE 8192

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
    --> /Users/luppy/.rustup/toolchains/nightly-aarch64-apple-darwin/lib/rustlib/src/rust/library/std/src/sys/pal/unix/fs.rs:1037:33
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

/Users/luppy/riscv/leds64-nuttx.S
```

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
 1030  kconfig-tweak --set-val CONFIG_EXAMPLES_HELLO_RUST_CARGO_STACKSIZE 8192
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
/Users/luppy/riscv/leds64-debug-nuttx.S
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

/Users/luppy/riscv/libhello.S
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

Override nightly

```bash
## Set Rust to nightly
pushd ..
rustup override list
rustup override set nightly
rustup override list
popd
```

TODO: nix

```text
https://crates.io/crates/nix
https://docs.rs/nix/0.29.0/nix/

➜  hello git:(master) ✗ $ cargo add nix --no-default-features
    Updating crates.io index
      Adding nix v0.29.0 to dependencies
             Features:
             35 deactivated features

➜  hello git:(master) ✗ $ cargo add nix --features fs,ioctl
    Updating crates.io index
      Adding nix v0.29.0 to dependencies
             Features:
             + fs
             + ioctl
             33 deactivated features

➜  hello git:(rust-std) ✗ $ cargo add nix --features fs,ioctl --git https://github.com/lupyuen/nix.git --branch nuttx
    Updating git repository `https://github.com/lupyuen/nix.git`
      Adding nix (git) to dependencies
             Features:
             + fs
             + ioctl
             34 deactivated features
    Updating git repository `https://github.com/lupyuen/nix.git`
     Locking 1 package to latest compatible version
      Adding nix v0.29.0 (https://github.com/lupyuen/nix.git?branch=nuttx#bcbcb50f)

➜  hello git:(master) ✗ $ pwd
/Users/luppy/riscv/apps/examples/rust/hello

   Compiling tokio v1.43.0
error[E0432]: unresolved import `self::consts`
  --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/errno.rs:19:15
   |
19 | pub use self::consts::*;
   |               ^^^^^^ could not find `consts` in `self`

error[E0432]: unresolved import `self::Errno`
   --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/errno.rs:198:15
    |
198 |     use self::Errno::*;
    |               ^^^^^ could not find `Errno` in `self`

error[E0432]: unresolved import `crate::errno::Errno`
 --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/fcntl.rs:2:5
  |
2 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `crate::errno::Errno`
 --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/signal.rs:6:5
  |
6 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `crate::errno::Errno`
 --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/unistd.rs:3:5
  |
3 | use crate::errno::Errno;
  |     ^^^^^^^^^^^^^^-----
  |     |             |
  |     |             help: a similar name exists in the module: `errno`
  |     no `Errno` in `errno`

error[E0432]: unresolved import `errno::Errno`
   --> /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/lib.rs:194:5
    |
194 | use errno::Errno;
    |     ^^^^^^^-----
    |     |      |
    |     |      help: a similar name exists in the module: `errno`
    |     no `Errno` in `errno`
```

TODO: Fix nix

```text
/Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/errno.rs
Copy #[cfg(target_os = "freebsd")]
to #[cfg(target_os = "nuttx")]

/Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/time.rs
    /// Leave the timestamp unchanged.
    #[cfg(not(any(target_os = "redox", target_os="nuttx")))]////
    // At the time of writing this PR, redox does not support this feature
    pub const UTIME_OMIT: TimeSpec =
        TimeSpec::new(0, libc::UTIME_OMIT as timespec_tv_nsec_t);
    /// Update the timestamp to `Now`
    // At the time of writing this PR, redox does not support this feature
    #[cfg(not(any(target_os = "redox", target_os = "nuttx")))]////
    pub const UTIME_NOW: TimeSpec =
        TimeSpec::new(0, libc::UTIME_NOW as timespec_tv_nsec_t);

cp \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/errno.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/time.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/fcntl.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/unistd.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/stat.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/statvfs.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/ioctl/mod.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/mod.rs \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0/src/sys/ioctl/bsd.rs \
  .
cp -r \
  /Users/luppy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/nix-0.29.0 \
  .
```

TODO: panic

```text
NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo
fd=3
{"name":"John","age":30}
{"name":"Jane","age":25}
Deserialized: Alice is 28 years old
Pretty JSON:
{
  "name": "Alice",
  "age": 28
}
Hello world from tokio!

NuttShell (NSH) NuttX-12.7.0
nsh> hello_rust_cargo

thread '<unnamed>' panicked at src/lib.rs:18:71:
called `Result::unwrap()` on an `Err` value: ENOENT
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
nsh> 
```

TODO: ioctl

```text
https://docs.rs/nix/latest/nix/sys/ioctl/

/Users/luppy/riscv/nuttx/fs/vfs/fs_ioctl.c
int ioctl(int fd, int req, ...) {
  _info("fd=0x%x, req=0x%x", fd, req);////

    const ULEDIOC_SETALL: i32 = 0x1d03;
    ioctl_none!(led_on, ULEDIOC_SETALL, 1);
    unsafe { led_on(fd).unwrap(); }

NuttShell (NSH) NuttX-12.7.0
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102

ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
hello_rust_cargo
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
ioctl: fd=0x1, req=0x118
fd=3
ioctl: fd=0x3, req=0x201d0301

thread '<unnamed>' panicked at src/lib.rs:31:25:
called `Result::unwrap()` on an `Err` value: ENOTTY
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102

    const ULEDIOC_SETALL: i32 = 0x1d03;
    // ioctl_none!(led_on, ULEDIOC_SETALL, 1);
    ioctl_write_int!(led_on, ULEDIOC_SETALL, 1);
    unsafe { led_on(fd, 1).unwrap(); }
    unsafe { led_on(fd, 0).unwrap(); }

NuttShell (NSH) NuttX-12.7.0
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102

ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
hello_rust_cargo
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
ioctl: fd=0x1, req=0x118
fd=3
ioctl: fd=0x3, req=0x801d0301

thread '<unnamed>' panicked at src/lib.rs:30:28:
called `Result::unwrap()` on an `Err` value: ENOTTY
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
```

ioctl OK yay!

```text
    const ULEDIOC_SETALL: i32 = 0x1d03;
    ioctl_write_int_bad!(led_set_all, ULEDIOC_SETALL);

    // Equivalent to ioctl(fd, ULEDIOC_SETALL, 1)
    unsafe { led_set_all(fd, 1).unwrap(); }

    // Equivalent to ioctl(fd, ULEDIOC_SETALL, 0)
    unsafe { led_set_all(fd, 0).unwrap(); }

NuttShell (NSH) NuttX-12.7.0
nsh> ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
hello_rust_cargo
ioctl: fd=0x0, req=0x101
ioctl: fd=0x0, req=0x102
ioctl: fd=0x1, req=0x118
fd=3
ioctl: fd=0x3, req=0x1d03
board_userled: LED 1 set to 1
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
ioctl: fd=0x3, req=0x1d03
board_userled: LED 1 set to 0
board_userled: LED 2 set to 0
board_userled: LED 3 set to 0
{"name":"John","age":30}
{"name":"Jane","age":25}
Deserialized: Alice is 28 years old
Pretty JSON:
{
  "name": "Alice",
  "age": 28
}
Hello world from tokio!
```

Updated nix

```text
Add support for NuttX #1
https://github.com/lupyuen/nix/pull/1/files

Implement I/O Safety #1750
https://github.com/nix-rust/nix/issues/1750

Feature Name: io_safety
https://github.com/rust-lang/rfcs/blob/master/text/3128-io-safety.md
```

[Rustix Ioctl](https://docs.rs/rustix/latest/rustix/ioctl/index.html)

NOTUSED

```text
## Build Apps Filesystem
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
./tools/mkromfsimg.sh ../nuttx/arch/risc-v/src/board/romfs_boot.c
popd
make -j

qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -kernel nuttx \
  -nographic

qemu-system-riscv32 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv32 \
  -smp 8 \
  -bios nuttx \
  -nographic

$ qemu-system-riscv32 -semihosting -M virt,aclint=on -cpu rv32 -smp 8 -bios nuttx -nographic
ABC
NuttShell (NSH) NuttX-10.0.1
nsh> uname -a
NuttX 10.0.1 8205548707 Jan  9 2025 12:25:16 risc-v rv-virt

nsh> hello_rust_cargo
{"name":"John","age":30}
{"name":"Jane","age":25}
Deserialized: Alice is 28 years old
Pretty JSON:
{
  "name": "Alice",
  "age": 28
}
Hello world from tokio!
```

# What's Next

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
