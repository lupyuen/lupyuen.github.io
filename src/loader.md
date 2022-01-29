# BL602 EFlash Loader: Reverse Engineered with Ghidra

📝 _5 Feb 2022_

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/loader-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board_

Something interesting happens when we __flash firmware to BL602 and BL604__ RISC-V boards (above: PineDio Stack BL604, below: PineCone BL602)...

It starts a tiny program __inside the board__ to make flashing possible: The __EFlash Loader__.

Step by step we shall __uncover what's inside__ EFlash Loader, thanks to [__Ghidra__](https://ghidra-sre.org/) the popular tool for Software Reverse Engineering.

_Why are we doing this?_

1.  EFlash Loader is a critical part of the __Flashing Process__

    (Good to understand how it works)

1.  __No Source Code__ is available for EFlash Loader

    [(According to GitHub Code Search)](https://github.com/search?q=bflb_eflash_loader_cmd_write_flash&type=code)

1.  EFlash Loader is a __small__ (37 KB) and __self-contained__ program

    [(32-bit RISC-V, specifically RV32IMACF)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

1.  EFlash Loader gets __updated occasionally__, so it's good for us to understand what's changed

This is my first time using Ghidra so this might be a fun and educational exercise!

(But please bear with my ignorance 🙏)

![Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

_Pine64 PineCone BL602 RISC-V Board_

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/loader.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/loader.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1486187004232867842)
