# Rust Custom Target for QEMU RISC-V on Apache NuttX RTOS

📝 _22 Apr 2024_

![Rust Apps on Apache NuttX RTOS and QEMU RISC-V](https://lupyuen.github.io/images/rust4-title.jpg)

<div style="text-align: center">

[_Thanks to cool-retro-term!_](https://github.com/Swordfish90/cool-retro-term)

</div>

Last article we were compiling [__Rust Apps__](TODO) for [__Apache NuttX RTOS__](TODO) (QEMU RISC-V 32-bit). And we hit a __baffling error__...

```bash
$ make
riscv64-unknown-elf-ld: libapps.a
  hello_rust_1.o:
  can't link soft-float modules with double-float modules
```

Let's solve the problem! We dive inside the internals of __C-to-Rust Interop__...

- Rust compiles for __Soft-Float__, but NuttX expects __Double-Float__

  (Software vs Hardware Floating-Point)

- But Rust __doesn't support Double-Float__ (by default)

- So we create a __Rust Custom Target__ for Double-Float

- Rebuild the __Rust Core Library__ for Double-Float

- And our Rust App __builds OK with NuttX__!

TODO: Pic of double float vs soft float 

# Software vs Hardware Floating-Point

TODO

Compile nuttx

Hello.c

Target

Rustc

Oops we have a problem 

Never the twain shall meet!

Elf header

Change rust to double float 

# Rust Build for 64-bit RISC-V

TODO

__Exercise for the Reader:__ Last article we TODO

```bash
$ tools/configure.sh rv-virt:nsh64
$ make menuconfig
## TODO: Enable "Hello Rust Example"
$ make

RUSTC:  hello_rust_main.rs error: Error loading target specification: 
  Could not find specification for target "riscv64i-unknown-none-elf". 
  Run `rustc --print target-list` for a list of built-in targets

make[2]: *** [nuttx/apps/Application.mk:275: hello_rust.o] Error 1
make[1]: *** [Makefile:51: nuttx/apps/examples/hello_rust_all] Error 2
make: *** [tools/LibTargets.mk:232: nuttx/apps/libapps.a] Error 2
```

Which says that _riscv64i-unknown-none-elf_ isn't a valid Rust Target.

(Should be _riscv64gc-unknown-none-elf_ instead)

Fix the build?
Custom Target?
(10 points)

# Rust Custom Target for QEMU RISC-V on Apache NuttX RTOS

TODO

We have a problem compiling [Rust Apps for QEMU RISC-V 32-bit](https://lupyuen.github.io/articles/rust3#software-vs-hardware-floating-point)...

```bash
$ make
LD: nuttx
riscv64-unknown-elf-ld: nuttx/nuttx/staging/libapps.a
  (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o):
  can't link soft-float modules with double-float modules

riscv64-unknown-elf-ld: failed to merge target specific data of file
  nuttx/staging/libapps.a
  (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o)
```

That's because [NuttX builds Rust Apps](https://lupyuen.github.io/articles/rust3#how-nuttx-compiles-rust-apps) for `riscv32i-unknown-none-elf` (Software Floating-Point)...

```bash
## Compile `hello_rust_main.rs` to `hello_rust.o`
## for Rust Target: RISC-V 32-bit (Soft-Float)
rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv32i-unknown-none-elf \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs...apps.examples.hello_rust.o
```

But the rest of NuttX is Double-Precision Hardware Floating-Point!

(`-march=rv32imafdc -mabi=ilp32d`)

```bash
$ make --trace
...
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Wno-attributes \
  -Wno-unknown-pragmas \
  -Wno-psabi \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafdc \
  -mabi=ilp32d \
  -isystem nuttx/include \
  -D__NuttX__ \
  -DNDEBUG  \
  -pipe \
  -I "apps/include" \
  -Dmain=hello_main \
  hello_main.c \
  -o  hello_main.c...apps.examples.hello.o \
```

_Does Rust support Double-Precision Hardware Floating-Point?_

We're looking for a Rust Target like `riscv32gc-unknown-none-elf`...

```bash
$ rustup target list | grep riscv
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
riscv64gc-unknown-linux-gnu
riscv64gc-unknown-none-elf
riscv64imac-unknown-none-elf
```

But nope it's not supported! So we create a Rust Custom Target for `riscv32gc-unknown-none-elf`...

- [Custom Target for Rust](https://docs.rust-embedded.org/embedonomicon/custom-target.html)

Let's dump the Rust Targets `riscv32i` and `riscv64gc` to compare...

```bash
$ rustc \
  +nightly \
  -Z unstable-options \
  --print target-spec-json \
  --target riscv32i-unknown-none-elf

{
  "arch": "riscv32",
  "atomic-cas": false,
  "cpu": "generic-rv32",
  "data-layout": "e-m:e-p:32:32-i64:64-n32-S128",
  "eh-frame-header": false,
  "emit-debug-gdb-scripts": false,
  "is-builtin": true,
  "linker": "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-target": "riscv32",
  "max-atomic-width": 0,
  "panic-strategy": "abort",
  "relocation-model": "static",
  "target-pointer-width": "32"
}

$ rustc \
  +nightly \
  -Z unstable-options \
  --print target-spec-json \
  --target riscv64gc-unknown-none-elf  

{
  "arch": "riscv64",
  "code-model": "medium",
  "cpu": "generic-rv64",
  "data-layout": "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128",
  "eh-frame-header": false,
  "emit-debug-gdb-scripts": false,
  "features": "+m,+a,+f,+d,+c",
  "is-builtin": true,
  "linker": "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname": "lp64d",
  "llvm-target": "riscv64",
  "max-atomic-width": 64,
  "panic-strategy": "abort",
  "relocation-model": "static",
  "supported-sanitizers": [
    "kernel-address"
  ],
  "target-pointer-width": "64"
}
```

Based on the above, we create our Rust Custom Target: [riscv32gc-unknown-none-elf.json](riscv32gc-unknown-none-elf.json)

```json
{
  "arch": "riscv32",
  "cpu": "generic-rv32",
  "data-layout": "e-m:e-p:32:32-i64:64-n32-S128",
  "eh-frame-header": false,
  "emit-debug-gdb-scripts": false,
  "features": "+m,+a,+f,+d,+c",
  "linker": "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname": "ilp32d",
  "llvm-target": "riscv32",
  "max-atomic-width": 0,
  "panic-strategy": "abort",
  "relocation-model": "static",
  "target-pointer-width": "32"
}
```

Which is based on `riscv32i` with these changes...

- Removed `"atomic-cas": false`

- Added `"features": "+m,+a,+f,+d,+c"`

- Removed `"is-builtin": true`

- Added `"llvm-abiname": "ilp32d"`

  (`ilp32d` comes from `make --trace` above)

  [(More about `llvm-abiname`)](https://lupyuen.github.io/articles/rust#custom-rust-target-for-bl602)

Now we build the Rust Core Library for `riscv32gc`...

```bash
## Verify our Custom Target
rustc \
  --print cfg \
  --target riscv32gc-unknown-none-elf.json

## Build the Rust Core Library for `riscv32gc`
## Ignore the error: `app already exists`
cargo new app
pushd app
cargo clean
## Ignore the error: `can't find crate for std`
cargo build \
  -Zbuild-std=core,alloc \
  --target ../riscv32gc-unknown-none-elf.json
popd
```

We rebuild our Rust App with the new Rust Custom Target (linked to our Rust Core Library)...

```bash
## Compile our Rust App.
## Changed the target to riscv32gc-unknown-none-elf.json
rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv32gc-unknown-none-elf.json \
  -C panic=abort \
  -O \
  ../apps/examples/hello_rust/hello_rust_main.rs \
  -o ../apps/examples/hello_rust/*hello_rust.o \
  \
  -C incremental=app/target/riscv32gc-unknown-none-elf/debug/incremental \
  -L dependency=app/target/riscv32gc-unknown-none-elf/debug/deps \
  -L dependency=app/target/debug/deps \
  --extern noprelude:alloc=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-*.rlib` \
  --extern noprelude:compiler_builtins=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-*.rlib` \
  --extern noprelude:core=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-*.rlib` \
  -Z unstable-options

## Dump the ELF Header. Should show:
## Flags: 0x5, RVC, double-float ABI
riscv64-unknown-elf-readelf \
  -h -A \
  ../apps/examples/hello_rust/*hello_rust.o

## NuttX should link and execute correctly now
cp \
  ../apps/examples/hello_rust/*hello_rust.o \
  ../apps/examples/hello_rust/*hello_rust_1.o

pushd ../nuttx
make
qemu-system-riscv32 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv32 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
popd
```

And it works!

_Our Rust App links OK! Has the ELF Header changed?_

Yep the ELF Header has changed from Soft-Float to Double-Float...

```bash
## Before Custom Target
$ riscv64-unknown-elf-readelf \
  -h -A \
  ../apps/examples/hello_rust/*hello_rust_1.o

ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          10240 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           40 (bytes)
  Number of section headers:         29
  Section header string table index: 1
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv32i2p1"

## After Custom Target
$ riscv64-unknown-elf-readelf \
  -h -A \
  ../apps/examples/hello_rust/*hello_rust.o

ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          10352 (bytes into file)
  Flags:                             0x5, RVC, double-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           40 (bytes)
  Number of section headers:         29
  Section header string table index: 1
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv32i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0"

## Which looks similar to other C Binaries
$ riscv64-unknown-elf-readelf \
  -h -A \
  ../apps/examples/hello/*hello.o                 

ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           RISC-V
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          3776 (bytes into file)
  Flags:                             0x5, RVC, double-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           40 (bytes)
  Number of section headers:         26
  Section header string table index: 25
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv32i2p0_m2p0_a2p0_f2p0_d2p0_c2p0"
```

_How did we figure out the rustc options?_

`cargo build` will call `rustc` with a whole bunch of options.

We ran `cargo build -v` to dump the `rustc` options that were used to compile a Rust App with our Custom Rust Core Library for `riscv32gc`...

```bash
$ cargo build -v \
  -Zbuild-std=core,alloc \
  --target ../riscv32gc-unknown-none-elf.json

   Compiling compiler_builtins v0.1.101
   Compiling core v0.0.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/core)
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name build_script_build --edition=2018 $HOME/.cargo/registry/src/index.crates.io-6f17d22bba15001f/compiler_builtins-0.1.101/build.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type bin --emit=dep-info,link -C embed-bitcode=no -C debuginfo=2 -C split-debuginfo=unpacked --cfg 'feature="compiler-builtins"' --cfg 'feature="core"' --cfg 'feature="default"' --cfg 'feature="rustc-dep-of-std"' -C metadata=9bd0bac7535b33a8 -C extra-filename=-9bd0bac7535b33a8 --out-dir $HOME/riscv/nuttx-rust-app/app/target/debug/build/compiler_builtins-9bd0bac7535b33a8 -Z force-unstable-if-unmarked -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --cap-lints allow`
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name core --edition=2021 $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/core/src/lib.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type lib --emit=dep-info,metadata,link -C embed-bitcode=no -C debuginfo=2 -C metadata=d271c6ebb87f9b41 -C extra-filename=-d271c6ebb87f9b41 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -Z force-unstable-if-unmarked -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --cap-lints allow`
     Running `$HOME/riscv/nuttx-rust-app/app/target/debug/build/compiler_builtins-9bd0bac7535b33a8/build-script-build`
   Compiling rustc-std-workspace-core v1.99.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/rustc-std-workspace-core)
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name rustc_std_workspace_core --edition=2021 $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/rustc-std-workspace-core/lib.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type lib --emit=dep-info,metadata,link -C embed-bitcode=no -C debuginfo=2 -C metadata=52e0df2b2cc19b6e -C extra-filename=-52e0df2b2cc19b6e --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -Z force-unstable-if-unmarked -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rmeta --cap-lints allow`
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name compiler_builtins --edition=2018 $HOME/.cargo/registry/src/index.crates.io-6f17d22bba15001f/compiler_builtins-0.1.101/src/lib.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type lib --emit=dep-info,metadata,link -C embed-bitcode=no -C debuginfo=2 --cfg 'feature="compiler-builtins"' --cfg 'feature="core"' --cfg 'feature="default"' --cfg 'feature="rustc-dep-of-std"' -C metadata=cd0d33c2bd30ca51 -C extra-filename=-cd0d33c2bd30ca51 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -Z force-unstable-if-unmarked -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/librustc_std_workspace_core-52e0df2b2cc19b6e.rmeta --cap-lints allow --cfg 'feature="unstable"' --cfg 'feature="mem"'`
   Compiling alloc v0.0.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/alloc)
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name alloc --edition=2021 $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/lib.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type lib --emit=dep-info,metadata,link -C embed-bitcode=no -C debuginfo=2 -C metadata=5d7bc2e4f3c29e08 -C extra-filename=-5d7bc2e4f3c29e08 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -Z force-unstable-if-unmarked -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rmeta --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rmeta --cap-lints allow`
   Compiling app v0.1.0 ($HOME/riscv/nuttx-rust-app/app)
     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name app --edition=2021 src/main.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type bin --emit=dep-info,link -C embed-bitcode=no -C debuginfo=2 -C metadata=1ff442e6481e1397 -C extra-filename=-1ff442e6481e1397 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -C incremental=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/incremental -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern 'noprelude:alloc=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-5d7bc2e4f3c29e08.rlib' --extern 'noprelude:compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rlib' --extern 'noprelude:core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rlib' -Z unstable-options`
error[E0463]: can't find crate for `std`
  |
  = note: the `riscv32gc-unknown-none-elf` target may not support the standard library
  = note: `std` is required by `app` because it does not declare `#![no_std]`
  = help: consider building the standard library from source with `cargo build -Zbuild-std`

error: cannot find macro `println` in this scope
 --> src/main.rs:2:5
  |
2 |     println!("Hello, world!");
  |     ^^^^^^^

error: `#[panic_handler]` function required, but not found

For more information about this error, try `rustc --explain E0463`.
error: could not compile `app` (bin "app") due to 3 previous errors

Caused by:
  process didn't exit successfully: `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name app --edition=2021 src/main.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type bin --emit=dep-info,link -C embed-bitcode=no -C debuginfo=2 -C metadata=1ff442e6481e1397 -C extra-filename=-1ff442e6481e1397 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -C incremental=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/incremental -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern 'noprelude:alloc=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-5d7bc2e4f3c29e08.rlib' --extern 'noprelude:compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rlib' --extern 'noprelude:core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rlib' -Z unstable-options` (exit status: 1)
```

This Rust Compiler Issue might be relevant...

- [Allow building for hard-float targets in RISC-V](https://github.com/rust-lang/rust/issues/65024)

_How to see the Targets supported by GCC?_

Like this...

```bash
$ riscv64-unknown-elf-gcc --target-help

  Supported ABIs (for use with the -mabi= option):
    ilp32 ilp32d ilp32e ilp32f lp64 lp64d lp64f
```

[(As explained here)](https://gcc.gnu.org/onlinedocs/gcc/RISC-V-Options.html#index-mabi-5)

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

[__lupyuen.github.io/src/rust4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust4.md)
