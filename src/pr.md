# Preparing a Pull Request for Apache NuttX RTOS

📝 _30 Nov 2022_

![TODO](https://lupyuen.github.io/images/pr-title.jpg)

This article explains how I prepared my Pull Requests for submission to [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html). So if we're contributing code to NuttX, just follow these steps and things will (probably) go Hunky Dory!

(Like the fish)

Before we begin, please swim over to the official __Development Workflow__ for NuttX...

-   [__"NuttX Development Workflow"__](https://nuttx.apache.org/docs/latest/contributing/workflow.html)

OK let's dive in! (Like the fish)

![Create Fork](https://lupyuen.github.io/images/pr-fork.png)

# NuttX Repositories

We begin by __creating our forks__ for the __`nuttx`__ and __`apps`__ repositories...

1.  Browse to __NuttX Repository__...

    [__github.com/apache/nuttx__](https://github.com/apache/nuttx)

    Click "__Fork__" to create our fork. (Pic above)

    Click "__Actions__" and enable workflows...

    ![Enable Workflows](https://lupyuen.github.io/images/pr-actions.png)

    (This will check that our code compiles OK at every commit)

1.  Do the same for the __NuttX Apps Repository__...

    [__github.com/apache/nuttx-apps__](https://github.com/apache/nuttx-apps)

    Click "__Fork__" to create our fork.

    Click "__Actions__" and enable workflows.

1.  As a principle, let's keep our __`master`__ branch __always in sync__ with the NuttX Mainline __`master`__ branch.

    (This seems cleaner for syncing upstream updates into our repo)

    Let's __create a branch__ to make our changes...

1.  In our NuttX Repository, click __`master`__.

    Enter the name of our new branch.
    
    Click "__Create Branch__"

    ![Create Branch](https://lupyuen.github.io/images/pr-branch.png)

    [(I named my branch __`gic`__ for Generic Interrupt Controller)](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/gic)

1.  Do the same for our __NuttX Apps Repository__

    (Because we should sync __`nuttx`__ and __`apps`__ too)

1.  Download the new branches of our __`nuttx`__ and __`apps`__ repositories...

    ```bash
    ## Download the "gic" branch of "lupyuen2/wip-pinephone-nuttx"
    ## TODO: Change the branch name and repo URLs
    mkdir nuttx
    cd nuttx
    git clone \
      --branch gic \
      https://github.com/lupyuen2/wip-pinephone-nuttx \
      nuttx
    git clone \
      --branch gic \
      https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
      apps
    ```

    We're ready to code!

# Build and Test


TODO

- test locally
- capture the log
- don't wait too long because upstream may change

- create a PR in a branch
- testable (QEMU)
- small modular self-contained feature

- sometimes GitHub Actions will fail. Just re-run the failed jobs [(Like this)](https://lupyuen.github.io/images/pr-rerun.png)

```text
Error response from daemon:
login attempt to https://ghcr.io/v2/
failed with status: 503 Service Unavailable"
```

## Regression Testing

_Will our modified code break other parts of NuttX?_

That's why it's good to run a [__Regression Test__](https://en.wikipedia.org/wiki/Regression_testing) (if feasible) to be sure that other parts of NuttX aren't affected by our modified code.

TODO

- regression testing
- (optional) logs, super helpful for debugging

For our Pull Request...

[arch/arm64: Add support for Generic Interrupt Controller Version 2](https://github.com/apache/nuttx/pull/7630)

[run.sh QEMU](https://gist.github.com/lupyuen/5e2fba642a33bf64d3378df3795042d7)
- QEMU good for regression testing
- Since we might not have the actual hw
- How to support PinePhone UART in QEMU?
- Zig Extension?

(Yeah it will be hard to run a Regression Test if it requires hardware that we don't have)

## Documentation

TODO

[NuttX Documentation](https://nuttx.apache.org/docs/latest/contributing/documentation.html)

![Check Coding Style with nxstyle](https://lupyuen.github.io/images/pr-nxstyle.png)

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

$HOME/nxstyle $HOME/PinePhone/wip-nuttx/nuttx/arch/arm/src/armv7-a/arm_gicv2.c
```

- VSCode Extension?
- [Linux checkpatch?](https://marketplace.visualstudio.com/items?itemName=idanp.checkpatch)
- Best if can convert to NuttX style 
- Check one last time

# Write the Pull Request

TODO

- [Markdown PR](https://gist.github.com/lupyuen/4dbe011143dfc5404e1791ba74a79deb)
- Update Doc
- (optional) commands used for testing
- (optional) logs, super helpful for debugging
- regression testing

[arch/arm64: Add support for Generic Interrupt Controller Version 2](https://github.com/apache/nuttx/pull/7630)

[arch/arm64: Add support for PINE64 PinePhone](https://github.com/apache/nuttx/pull/7692)

## Summary

TODO

## Impact

TODO

## Testing

TODO

![Squash Commits with GitHub Desktop](https://lupyuen.github.io/images/pr-squash1.png)

# Squash the Commits

_What's this "squashing"?_

"Squashing" means we're __combining Multiple Commits__ into One Single Commit.

Our __Commit History__ can get awfully messy during development...

```text
- Initial Commit
- Fixing Build
- Build OK!
- Oops fixing bug
- Tested OK yay!
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/commits/pinephone/arch/arm64/src/qemu/qemu_serial.c)

So we always __Squash the Commits__ into One Single Commit (to help future maintainers)...

```text
- arch/arm64: Add support for Generic Interrupt Controller Version 2
```

[(Source)](https://github.com/apache/nuttx/pull/7630/commits)

_How do we squash the commits?_

We'll use [__GitHub Desktop__](https://desktop.github.com/) (because I'm terrible with the Git Command Line)...

1.  Install [__GitHub Desktop__](https://desktop.github.com/) and launch it

1.  Click "__File → Add Local Repository__"

    Select our downloaded __`nuttx`__ folder.

    Click "__Add Repository__"

1.  Click the "__History__" tab to reveal the Commit History

    [(Pic above)](https://lupyuen.github.io/images/pr-squash1.png)

1.  Select the Commits to be Squashed.

    Right-click the Commits.

    Select "__Squash Commits__"

    [(Pic above)](https://lupyuen.github.io/images/pr-squash1.png)

1.  Copy the __Title__ of our Pull Request and paste into the __Title Box__...

    ```text
    arch/arm64: Add support for Generic Interrupt Controller Version 2
    ```

    Copy the __Summary__ of our Pull Request and paste into the __Description Box__...

    ```text
    This PR adds support for GIC Version 2.
    - `boards/arm64/qemu/qemu-armv8a/configs/nsh_gicv2/defconfig`: Added the Board Configuration
    ```

    Click "__Squash Commits__"

    ![Squash Commits with GitHub Desktop](https://lupyuen.github.io/images/pr-squash2.png)

1.  Click "__Begin Squash__"

    ![Squash Commits with GitHub Desktop](https://lupyuen.github.io/images/pr-squash3.png)

1.  Click "__Force Push Origin__"

    ![Squash Commits with GitHub Desktop](https://lupyuen.github.io/images/pr-squash4.png)

1.  Click "__I'm Sure__"

    ![Squash Commits with GitHub Desktop](https://lupyuen.github.io/images/pr-squash5.png)

    And we're ready to merge upstream! (Like the salmon)

_What if we prefer the Git Command Line?_

Here are the steps to Squash Commits with the __Git Command Line__...

-   [__"Flight rules for Git: I need to combine commits"__](https://github.com/k88hudson/git-flight-rules#i-need-to-combine-commits)

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
