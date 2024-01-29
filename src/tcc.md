# TCC RISC-V Compiler runs in the Web Browser (thanks to Zig Compiler)

📝 _7 Feb 2024_

![TODO](https://lupyuen.github.io/images/tcc-title.png)

TODO

_TCC is a Tiny C Compiler for 64-bit RISC-V... Can we run TCC in a Web Browser?_

Let's find out! We'll compile TCC to WebAssembly with Zig Compiler.

TODO: Interesting challenges

_Why are we doing this?_

Today we can run [__Apache NuttX RTOS in a Web Browser__](https://lupyuen.github.io/articles/tinyemu2) (with WebAssembly + Emscripten + 64-bit RISC-V).

What if we could allow NuttX Apps to be compiled and tested in the Web Browser?

1.  We type a C Program into a HTML Textbox...

    ```c
    int main(int argc, char *argv[]) {
      printf("Hello, World!!\n");
      return 0;
    }
    ```

1.  Run TCC in the Web Browser to compile the C Program into an ELF Executable (64-bit RISC-V)

1.  Copy the ELF Executable to the NuttX Filesystem (via WebAssembly)

1.  NuttX runs our ELF Executable inside the Web Browser

![TCC RISC-V Compiler: Compiled to WebAssembly with Zig Compiler](https://lupyuen.github.io/images/tcc-web.png)

[_(Try the __Online Demo__)_](https://lupyuen.github.io/tcc-riscv32-wasm/)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX and Zig Communities) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tcc.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tcc.md)
