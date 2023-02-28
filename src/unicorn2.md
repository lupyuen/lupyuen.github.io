# (Clickable) Call Graph for Apache NuttX Real-Time Operating System

📝 _10 Mar 2023_

![Call Graph for Apache NuttX Real-Time Operating System](https://lupyuen.github.io/images/unicorn2-title.jpg)

[_Clickable Call Graph for Apache NuttX RTOS_](https://github.com/lupyuen/pinephone-emulator#call-graph-for-apache-nuttx-rtos)

Last week we ran [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/what) (RTOS) on [__Unicorn Emulator__](https://www.unicorn-engine.org/)...

-   [__"(Possibly) Emulate PinePhone with Unicorn Emulator"__](https://lupyuen.github.io/articles/unicorn)

And we hit a baffling [__Arm64 Exception__](https://lupyuen.github.io/articles/unicorn#emulator-halts-with-mmu-fault) in the (Emulated) __Memory Management Unit__.

In this article we'll create some tools  to __troubleshoot the Arm64 Exception__ in NuttX...

-   Render the [__Dynamic Call Graph__](https://en.wikipedia.org/wiki/Call_graph) for Apache NuttX RTOS, to understand how it boots (pic above)

-   [__Make it Clickable__](https://github.com/lupyuen/pinephone-emulator#call-graph-for-apache-nuttx-rtos), so we can browse the __NuttX Source Code__ as we explore the Call Graph

-   We'll use a __Block Execution Hook__ in Unicorn Emulator to generate the Call Graph with Rust

-   And call the Rust Libraries [__addr2line__](https://crates.io/crates/addr2line) and [__gimli__](https://crates.io/crates/gimli) to map the Code Addresses to NuttX Kernel Functions

-   Thanks to the (Clickable) Call Graph, we'll describe the complete __Boot Process__ of NuttX RTOS on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)

-   And explain how we might do __Automated Daily Build and Test__ for NuttX on PinePhone

CPU Emulators (like Unicorn) can be super helpful for understanding the internals of __complex embedded programs__... Like Apache NuttX RTOS!

Let's dive in and learn how...

![Running Apache NuttX RTOS in Unicorn](https://lupyuen.github.io/images/unicorn-code4.png)

[_Running Apache NuttX RTOS in Unicorn_](https://lupyuen.github.io/articles/unicorn#apache-nuttx-rtos-in-unicorn)

# Intercept Code Execution in Unicorn

_What's Unicorn? How does it work with Apache NuttX RTOS?_

[__Unicorn__](https://www.unicorn-engine.org/) is a lightweight __CPU Emulator Framework__ based on [__QEMU__](http://www.qemu.org/).

In the [__last article__](https://lupyuen.github.io/articles/unicorn) we called Unicorn (in Rust) to run the __Arm64 Machine Code__ for Apache NuttX RTOS...

```rust
// Arm64 Machine Code for Apache NuttX RTOS
let arm64_code = include_bytes!("../nuttx/nuttx.bin");

// Init Unicorn Emulator in Arm64 mode
let mut unicorn = Unicorn::new(
  Arch::ARM64,
  Mode::LITTLE_ENDIAN
).expect("failed to init Unicorn");

// Magical horse mutates to bird
let emu = &mut unicorn;

// Omitted: Map Executable Memory and I/O Memory in Unicorn
...

// Boot NuttX RTOS in Unicorn Emulator
let err = emu.emu_start(
  0x4008_0000,  // Begin Address
  0x4008_0000 + arm64_code.len() as u64,  // End Address
  0,  // No Timeout
  0   // Unlimited number of instructions
);
```

[(Source)](https://lupyuen.github.io/articles/unicorn#apache-nuttx-rtos-in-unicorn)

And NuttX starts booting in the Unicorn Emulator!

_So Unicorn works like QEMU?_

Yes but with a fun new twist: Unicorn lets us __intercept the Execution__ of Emulated Code by attaching a __Hook Function__...

```rust
// Add Unicorn Hook that will intercept
// every Block of Arm64 Instructions
let _ = emu.add_block_hook(hook_block)
  .expect("failed to add block hook");
```

So we can __trace the flow__ of the Emulated Code.

Here's the __Hook Function__ that will be called whenever Unicorn emulates a Block of Arm64 Instructions...

```rust
// Hook Function for Block Emulation.
// Called once for each Block of Arm64 Instructions.
fn hook_block(
  _: &mut Unicorn<()>,  // Emulator
  address: u64,  // Block Address
  size: u32      // Block Size
) {
  // TODO: Trace the flow of emulated code
  println!("hook_block: address={:#x}, size={:?}", address, size);
}
```

[(Source)](https://lupyuen.github.io/articles/unicorn#block-execution-hook)

TODO

# Map Address to Function with ELF File

TODO

Our __Block Execution Hook__ now prints the __Function Name__ and the __Filename__...

```text
hook_block:  
  address=0x40080eb0, 
  size=12, 
  setup_page_tables, 
  arch/arm64/src/common/arm64_mmu.c:516:25

hook_block:  
  address=0x40080eec, 
  size=16, 
  enable_mmu_el1, 
  arch/arm64/src/common/arm64_mmu.c:543:11

err=Err(EXCEPTION)
```

[(Source)](https://gist.github.com/lupyuen/f2e883b2b8054d75fbac7de661f0ee5a)

Our Hook Function looks up the Address in the [__DWARF Debug Symbols__](https://crates.io/crates/gimli) of the [__NuttX ELF File__](https://github.com/lupyuen/pinephone-emulator/blob/main/nuttx/nuttx).

This is explained here...

-   ["Map Address to Function with ELF File"](https://lupyuen.github.io/articles/unicorn#appendix-map-address-to-function-with-elf-file)

# Call Graph for Apache NuttX RTOS

TODO

To troubleshoot the Apache NuttX MMU Fault on Unicorn Emulator, we auto-generated this Call Graph...

(To see the NuttX Source Code: Right-click the Node and select "Open Link")

-   [__"Call Graph for Apache NuttX RTOS"__](https://github.com/lupyuen/pinephone-emulator#call-graph-for-apache-nuttx-rtos)

We generated the Call Graph with this command...

```bash
cargo run | grep call_graph | cut -c 12-
```

(`cut` command removes columns 1 to 11)

Which produces this [Mermaid Flowchart](https://mermaid.js.org/syntax/flowchart.html)...

```text
→ cargo run | grep call_graph | cut -c 12- 

  flowchart TD

  arm64_boot_el1_init --> arm64_isb
  click arm64_boot_el1_init href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L137" "arch/arm64/src/common/arm64_boot.c "

  arm64_isb --> arm64_boot_el1_init
  click arm64_isb href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/barriers.h#L57" "arch/arm64/src/common/barriers.h "
  ...

  setup_page_tables --> enable_mmu_el1
  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L515" "arch/arm64/src/common/arm64_mmu.c "

  enable_mmu_el1 --> ***_HALT_***
  click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L542" "arch/arm64/src/common/arm64_mmu.c "
```

[(Source)](https://gist.github.com/lupyuen/b0e4019801aaf9860bcb234c8a9c8584)

The Call Graph is generated by our Block Execution Hook like so...

[main.rs](https://github.com/lupyuen/pinephone-emulator/blob/b23c1d251a7fb244f2e396419d12ab532deb3e6b/src/main.rs#L130-L159)

```rust
/// Hook Function for Block Emulation.
/// Called once for each Basic Block of Arm64 Instructions.
fn hook_block(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Block Address
    size: u32      // Block Size
) {
    // Ignore the memset() loop. TODO: Read the ELF Symbol Table to get address of memset().
    if address >= 0x4008_9328 && address <= 0x4008_933c { return; }
    print!("hook_block:  address={:#010x}, size={:02}", address, size);

    // Print the Function Name
    let function = map_address_to_function(address);
    if let Some(ref name) = function {
        print!(", {}", name);
    }

    // Print the Source Filename
    let loc = map_address_to_location(address);
    if let Some((ref file, line, col)) = loc {
        let file = file.clone().unwrap_or("".to_string());
        let line = line.unwrap_or(0);
        let col = col.unwrap_or(0);
        print!(", {}:{}:{}", file, line, col);
    }
    println!();

    // Print the Call Graph
    call_graph(address, size, function, loc);
}
```

`call_graph` prints the Call Graph by looking up the Block Address in the ELF Context...

[main.rs](https://github.com/lupyuen/pinephone-emulator/blob/b23c1d251a7fb244f2e396419d12ab532deb3e6b/src/main.rs#L224-L265)

```rust
/// Print the Mermaid Call Graph for this Function Call:
/// cargo run | grep call_graph | cut -c 12-
fn call_graph(
    _address: u64,  // Code Address
    _size: u32,     // Size of Code Block
    function: Option<String>,  // Function Name
    loc: Option<(        // Source Location
        Option<String>,  // Filename
        Option<u32>,     // Line
        Option<u32>      // Column
    )>
) {
    // Get the Function Name
    let Some(fname) = function
        else { return; };

    // Unsafe because `LAST_FNAME` is a Static Mutable
    unsafe {
        // Skip if we are still in the same Function
        static mut LAST_FNAME: String = String::new();
        static mut LAST_LOC: Option<(Option<String>, Option<u32>, Option<u32>)> = None;
        if fname.eq(&LAST_FNAME) { return; }

        // If this function has not been shown too often...
        if can_show_function(&fname) {
            // Print the Call Flow
            if LAST_FNAME.is_empty() {            
                println!("call_graph:  flowchart TD");  // Top-Down Flowchart
            } else {
                // URL looks like https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L541
                let (file, line, _) = LAST_LOC.clone().unwrap_or((Some("".to_string()), None, None));
                let file = file.unwrap_or("".to_string());
                let line = line.unwrap_or(1) - 1;
                let url = format!("https://github.com/apache/nuttx/blob/master/{file}#L{line}");
                println!("call_graph:  {LAST_FNAME} --> {fname}");
                println!("call_graph:  click {LAST_FNAME} href \"{url}\" \"{file} \"");
            }
        }
        LAST_FNAME = fname;
        LAST_LOC = loc;
    }
}
```

We map the Block Address to Function Name and Source File in `map_address_to_function` and `map_address_to_location`...

[main.rs](https://github.com/lupyuen/pinephone-emulator/blob/b23c1d251a7fb244f2e396419d12ab532deb3e6b/src/main.rs#L175-L222)

```rust
/// Map the Arm64 Code Address to the Function Name by looking up the ELF Context
fn map_address_to_function(
    address: u64       // Code Address
) -> Option<String> {  // Function Name
    // Lookup the Arm64 Code Address in the ELF Context
    let context = ELF_CONTEXT.context.borrow();
    let mut frames = context.find_frames(address)
        .expect("failed to find frames");

    // Return the Function Name
    if let Some(frame) = frames.next().unwrap() {
        if let Some(func) = frame.function {
            if let Ok(name) = func.raw_name() {
                let s = String::from(name);
                return Some(s);
            }
        }    
    }
    None
}

/// Map the Arm64 Code Address to the Source Filename, Line and Column
fn map_address_to_location(
    address: u64     // Code Address
) -> Option<(        // Returns...
    Option<String>,  // Filename
    Option<u32>,     // Line
    Option<u32>      // Column
)> {
    // Lookup the Arm64 Code Address in the ELF Context
    let context = ELF_CONTEXT.context.borrow();
    let loc = context.find_location(address)
        .expect("failed to find location");

    // Return the Filename, Line and Column
    if let Some(loc) = loc {
        if let Some(file) = loc.file {
            let s = String::from(file)
                .replace("/private/tmp/nuttx/nuttx/", "")
                .replace("arch/arm64/src/chip", "arch/arm64/src/a64");  // TODO: Handle other chips
            Some((Some(s), loc.line, loc.column))
        } else {
            Some((None, loc.line, loc.column))
        }
    } else {
        None
    }
}
```

`ELF_CONTEXT` is explained here...

-   ["Map Address to Function with ELF File"](https://lupyuen.github.io/articles/unicorn#appendix-map-address-to-function-with-elf-file)

# How NuttX Boots on PinePhone

TODO

-   [__"Call Graph for Apache NuttX RTOS"__](https://github.com/lupyuen/pinephone-emulator#call-graph-for-apache-nuttx-rtos)

## Arm64 Header

TODO

[arm64_head](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_head.S#L78-L227)

-   Calls [arm64_boot_el1_init](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L132-L162)

-   And [arm64_boot_primary_c_routine](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L181)

## Init EL1

TODO

[arm64_boot_el1_init](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L132-L162)

-   Sets the EL1 Vector Table [vbar_el1](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L135-L140)

-   Sets [cpacr_el1](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L140-L147)

-   Sets [sctlr_el1](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L147-L153)

-   Sets [cntv_cval_el0](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L153-L155)

## Primary Routine

TODO

[arm64_boot_primary_c_routine](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L179-L184)

-   Calls [boot_early_memset](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L164-L177)

    And [arm64_chip_boot](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_boot.c#L73-L105)

## Boot Chip

TODO

[arm64_chip_boot](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_boot.c#L73-L105)

-   Calls [arm64_mmu_init](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L577-L628)

-   Which calls [setup_page_tables](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L485-L524)

-   Which calls [enable_mmu_el1](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L526-L552)

-   Which fails with MMU Fault

# After MMU Fault

TODO: After fault

## After Boot Chip

[arm64_chip_boot](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_boot.c#L73-L105)

-   Calls [a64_board_initialize](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_boardinit.c#L59-L85)

-   And [a64_earlyserialinit](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L590-L619)

## After Primary Routine

[arm64_boot_primary_c_routine](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_boot.c#L179-L184)

-   Calls nx_start

# Automated Daily Build and Test

TODO

# What's Next

TODO

This has been a fun educational exercise. Now we have a way to run __Automated Daily Tests__ for Apache NuttX RTOS on PinePhone... Kudos to the __Maintainers of Unicorn Emulator__!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/unicorn2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/unicorn2.md)
