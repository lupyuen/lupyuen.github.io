# Preparing a Pull Request for Apache NuttX RTOS

📝 _30 Nov 2022_

![TODO](https://lupyuen.github.io/images/pr-title.jpg)

TODO

This article explains how I prepared my Pull Requests for submission to Apache NuttX RTOS. So if we're contributing code to NuttX, just follow these steps and things will (probably) go hunky dory!

[Development Workflow](https://nuttx.apache.org/docs/latest/contributing/workflow.html)

# NuttX Repositories

TODO

- master branch always in sync with mainline
- Enable github actions
- Why lupyuen2

- create a PR in a branch
- testable (QEMU)
- small modular self-contained feature

# Build and Test

TODO

- test locally
- capture the log
- don't wait too long because upstream may change
- regression testing
- (optional) logs, super helpful for debugging

Docs: https://nuttx.apache.org/docs/latest/contributing/documentation.html

run.sh QEMU: https://gist.github.com/lupyuen/5e2fba642a33bf64d3378df3795042d7
- QEMU good for regression testing
- Since we might not have the actual hw
- How to support PinePhone UART in QEMU?
- Zig Extension?

# Check Coding Style

TODO

[NuttX C Coding Standard](https://nuttx.apache.org/docs/latest/contributing/coding_style.html)

nxstyle:

```bash
gcc -o $HOME/nxstyle $HOME/PinePhone/wip-nuttx/nuttx/tools/nxstyle.c

$HOME/nxstyle $HOME/PinePhone/wip-nuttx/nuttx/arch/arm64/Kconfig
../nxstyle arch/arm64/include/qemu/chip.h
../nxstyle arch/arm64/src/common/Make.defs
../nxstyle arch/arm64/src/common/arm64_gic.h
../nxstyle arch/arm64/src/common/arm64_gicv2.c
$HOME/nxstyle $HOME/PinePhone/wip-nuttx/nuttx/arch/arm64/src/common/arm64_gicv3.c
../nxstyle boards/arm64/qemu/qemu-armv8a/README.txt
../nxstyle boards/arm64/qemu/qemu-armv8a/configs/nsh_gicv2/defconfig

/* */ not balanced
```

$HOME/nxstyle $HOME/PinePhone/wip-nuttx/nuttx/arch/arm/src/armv7-a/arm_gicv2.c

- VSCode Extension?
- Linux checkpatch? https://marketplace.visualstudio.com/items?itemName=idanp.checkpatch
- Best if can convert to NuttX style 
- Check one last time

# Sqash the Commits

TODO

- Why squash commits 
- Force push

# Write the Pull Request

TODO

- Markdown PR: https://gist.github.com/lupyuen/4dbe011143dfc5404e1791ba74a79deb
- Update Doc
- (optional) commands used for testing
- (optional) logs, super helpful for debugging
- regression testing

# Meditate

TODO

- We're about to make NuttX History...
- Our PR will be recorded for posterity!
- Breathe. Take a long walk and ponder who might benefit from the PR, how we might help them
- I walked 12 km (3 hours) while meditating on the PR
- Submit the PR
- (Touch up the PR and resquashif we get an epiphany during the long walk)

# Submit the Pull Request

TODO

- Grab a coffee and standby!
- let the CI run and fix errors
- wait for others to review and comment
- Standby to fix the PR (have a strong cup of coffee)

# Fix the Pull Request

TODO

# Update Our Repositories

TODO

- After merge: pull updates
- create a new branch for the next feature

Command Line: [Flight rules for Git](https://github.com/k88hudson/git-flight-rules)

[arch/arm64: Add support for Generic Interrupt Controller Version 2](https://github.com/apache/nuttx/pull/7630)

[arch/arm64: Add support for PINE64 PinePhone](https://github.com/apache/nuttx/pull/7692)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pr.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pr.md)
