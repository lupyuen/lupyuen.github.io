# Rust on RISC-V BL602: Simulated with WebAssembly

📝 _16 Aug 2021_

_Can we run Rust Firmware for BL602 RISC-V SoC in a Web Browser... Simulated with WebAssembly?_

![Fornite vs Embedded Programming](https://lupyuen.github.io/images/cloud-title.jpg)

__Try it here__...

-   [__BL602 / BL604 Simulator in WebAssembly__](https://github.com/lupyuen/bl602-simulator)

![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

Let's __Simulate BL602 / BL604 Rust Firmware__ in a Web Browser with __WebAssembly__...

1.  We take this BL602 / BL604 __Blinky Firmware in Rust__...

    - [__Rust Blinky Firmware for BL602__](https://github.com/lupyuen/bl602-simulator/blob/main/sdk_app_rust_gpio/rust/src/lib.rs)

1.  Which calls the __Rust Wrapper for BL602 IoT SDK__...

    - [__Rust Wrapper for BL602 IoT SDK__](https://crates.io/crates/bl602-sdk)

1.  We __compile to WebAssembly__ the Rust Firmware and Rust Wrapper

1.  In WebAssembly we __intercept calls to BL602 IoT SDK__ with __Stub Functions__

    (Like for the BL602 GPIO HAL)

    - [__Rust Stub Functions for BL602 Simulator__](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs)

1.  Add a __Simulator UI (HTML + JavaScript)__ to simulate a __PineCone BL602__ or __PineDio Stack BL604__...

    - [__“Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly”__](https://lupyuen.github.io/articles/wasm)
    
    (Without the Blockly part, since we can't compile Rust in a Web Browser)
    
    ![Handling BL602 Simulator Events](https://lupyuen.github.io/images/rust-simulator.png)

Why do this in __Rust__?

- Because we have already __parsed the BL602 IoT SDK interfaces__ with `bindgen`

  (While creating the BL602 Rust Wrapper) 

- Which lets us __manipulate the BL602 SDK interfaces__ with Rust in interesting ways

  (Like our `safe_wrap` Procedural Macro in Rust)
    
- More about __BL602 Rust Wrapper__...

  - [__"Rust on RISC-V BL602: Is It Sunny?"__](https://lupyuen.github.io/articles/adc)

Why are we doing this? What __problem are we solving__?

1.  Shorten the __Code - Build - Flash - Test Cycle__ for BL602 and BL604

    (Because flashing BL602 via UART is kinda cumbersome)
    
1.  We could potentially catch __BL602 SDK Calling Errors__ for new devs and __explain the errors in a friendly way__

    (Invalid parameters or usage, like reading a GPIO Pin configured for output)

1.  Make it easier to __Learn Embedded Programming__

    (Even without any Embedded Hardware)

1.  __Automated Testing__ of BL602 Firmware

1.  __Trace Calls to BL602 IoT SDK__ for debugging

We might be able to __Simulate C Firmware__ too, if we...
    
- Tweak the BL602 C Firmware to __build with Emscripten__

- And call the __Stub Functions__

# Rust Firmware for BL602

TODO

# Build BL602 Firmware for WebAssembly

TODO

# JSON Stream of Simulation Events

TODO

# Intercept Calls to BL602 IoT SDK

TODO

# Check for API Errors

TODO

# HTML + JavaScript UI

TODO

# What's Next

TODO

Soon we shall test the Rust Firmware on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/07/15/july-update/)... As we explore whether it's feasible to teach __Rust as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rustsim.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rustsim.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1423169766080933891)
