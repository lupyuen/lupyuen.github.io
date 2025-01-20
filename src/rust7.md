# Rust Standard Library on Apache NuttX RTOS

📝 _30 Jan 2025_

![TODO](https://lupyuen.github.io/images/rust7-title.jpg)

TODO

# TODO

```text
https://github.com/apache/nuttx-apps/pull/2487#pullrequestreview-2538724037
Tested OK with make and rv-virt:nsh. Thank you so much! :-)
https://gist.github.com/lupyuen/37a28cc3ae0443aa29800d252e4345cf

hello_rust_cargo on Apache NuttX RTOS rv-virt:leds64
https://gist.github.com/lupyuen/6985933271f140db0dc6172ebba9bff5

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
```

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

TODO

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
