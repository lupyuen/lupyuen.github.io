# Preparing a Pull Request for Apache NuttX RTOS

📝 _30 Nov 2022_

![Typical Pull Request for Apache NuttX RTOS](https://lupyuen.github.io/images/pr-title.jpg)

This article explains how I prepared my Pull Requests for submission to [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html). So if we're contributing code to NuttX, just follow these steps and things will (probably) go Hunky Dory!

(Like the fish)

Before we begin, please swim over to the official __Development Workflow__ for NuttX...

-   [__"NuttX Development Workflow"__](https://nuttx.apache.org/docs/latest/contributing/workflow.html)

Ready? Let's dive in! (Like the fish)

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

# Build and Test

We're ready to code!

1.  Consider breaking our Pull Request into __Smaller Pull Requests__.

    This Pull Request implements __One Single Feature__ (Generic Interrupt Controller)...

    [__"arch/arm64: Add support for Generic Interrupt Controller Version 2"__](https://github.com/apache/nuttx/pull/7630)

    That's called by another Pull Request...

    [__"arch/arm64: Add support for PINE64 PinePhone"__](https://github.com/apache/nuttx/pull/7692)

1.  __Modify the code__ in __`nuttx`__ and __`apps`__ to implement our awesome new feature.

1.  __Build and test__ the modified code.

    [(I configured `F1` in VSCode to run this __Build Script__)](https://gist.github.com/lupyuen/5e2fba642a33bf64d3378df3795042d7)

1.  Capture the __Output Log__ and save it as a [__GitHub Gist__](https://gist.github.com/lupyuen/7537da777d728a22ab379b1ef234a2d1)...

    -   [__"NuttX QEMU Log for Generic Interrupt Controller"__](https://gist.github.com/lupyuen/7537da777d728a22ab379b1ef234a2d1)

    We'll add this to our Pull Request. __Test Logs are super helpful__ for NuttX Maintainers!

    (Because we can't tell which way the train went... Unless we have the Test Logs!)

1.  __Commit the modified code__ to our repositories.

    Sometimes the __GitHub Actions Workflow__ will fail with a strange error (like below). Just re-run the failed jobs. [(Like this)](https://lupyuen.github.io/images/pr-rerun.png)

    ```text
    Error response from daemon:
    login attempt to https://ghcr.io/v2/
    failed with status: 503 Service Unavailable"
    ```

## Regression Test

_Will our modified code break other parts of NuttX?_

That's why it's good to run a [__Regression Test__](https://en.wikipedia.org/wiki/Regression_testing) (if feasible) to be sure that other parts of NuttX aren't affected by our modified code.

For our Pull Request...

-   [__"arch/arm64: Add support for Generic Interrupt Controller Version 2"__](https://github.com/apache/nuttx/pull/7630)

We tested with QEMU Emulator our __new implementation__ of Generic Interrupt Controller v2...

```bash
tools/configure.sh qemu-armv8a:nsh_gicv2 ; make ; qemu-system-aarch64 ...
```

[(See the NuttX QEMU Log)](https://gist.github.com/lupyuen/7537da777d728a22ab379b1ef234a2d1)

And for Regression Testing we tested the __existing implementation__ of Generic Interrupt Controller v3...

```bash
tools/configure.sh qemu-armv8a:nsh ; make ; qemu-system-aarch64 ...
```

[(See the NuttX QEMU Log)](https://gist.github.com/lupyuen/dec66bc348092a998772b32993e5ed65)

Remember to capture the __Output Log__, we'll add it to our Pull Request.

(Yeah it will be hard to run a Regression Test if it requires hardware that we don't have)

## Documentation

Please update the __Documentation__. The Documentation might be in a __Text File__...

-   [__nuttx/.../README.txt__](https://github.com/apache/nuttx/blob/master/boards/arm64/qemu/qemu-armv8a/README.txt)

Or in the __Official NuttX Docs__...

-   [__nuttx/Documentation/.../index.rst__](https://github.com/apache/nuttx/blob/master/Documentation/platforms/arm/a64/boards/pinephone/index.rst)

To update the Official NuttX Docs, follow the instructions here...

-   [__"NuttX Documentation"__](https://nuttx.apache.org/docs/latest/contributing/documentation.html)

    [(See the Log)](https://gist.github.com/lupyuen/c061ac688f430ef11a1c60e0b284a1fe)

![Check Coding Style with nxstyle](https://lupyuen.github.io/images/pr-nxstyle.jpg)

# Check Coding Style

Our NuttX Code will follow this Coding Standard...

-   [__"NuttX C Coding Standard"__](https://nuttx.apache.org/docs/latest/contributing/coding_style.html)

NuttX provides a tool __`nxstyle`__ that will check the Coding Style of our source files...

```bash
## Compile nxstyle
## TODO: Change "$HOME/nuttx" to our NuttX Project Folder
gcc -o $HOME/nxstyle $HOME/nuttx/nuttx/tools/nxstyle.c

## Check coding style for our modified source files
## TODO: Change the file paths
$HOME/nxstyle $HOME/nuttx/nuttx/arch/arm64/Kconfig
$HOME/nxstyle $HOME/nuttx/nuttx/arch/arm64/src/common/Make.defs
$HOME/nxstyle $HOME/nuttx/nuttx/arch/arm64/src/common/arm64_gic.h
$HOME/nxstyle $HOME/nuttx/nuttx/arch/arm64/src/common/arm64_gicv2.c
```

[(`nxstyle.c` is here)](https://github.com/apache/nuttx/blob/master/tools/nxstyle.c)

[(How I run `nxstyle` in my __Build Script__)](https://gist.github.com/lupyuen/5e2fba642a33bf64d3378df3795042d7)

_Will `nxstyle` check Kconfig and Makefiles?_

Not yet, but maybe someday? That's why we passed all the modified files to `nxstyle` for checking.

_How do we fix our code?_

The pic above shows the output from __`nxstyle`__. We'll see messages like...

```text
- C++ style comment
- Long line found
- Mixed case identifier found
- Operator/assignment must be followed/preceded with whitespace
- Upper case hex constant found
- #include outside of 'Included Files' section
```

We modify our code so that this...

```c
// Initialize GIC. Called by CPU0 only.
int arm64_gic_initialize(void) {
  // Verify that GIC Version is 2
  int err = gic_validate_dist_version();
  if (err) { sinfo("no distributor detected, giving up ret=%d\n", err); return err; }

  // CPU0-specific initialization for GIC
  arm_gic0_initialize();

  // CPU-generic initialization for GIC
  arm_gic_initialize();
  return 0;
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/common/arm64_gicv3.c#L717-L743)

Becomes this...

```c
/****************************************************************************
 * Name: arm64_gic_initialize
 *
 * Description:
 *   Initialize GIC. Called by CPU0 only.
 *
 * Input Parameters
 *   None
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value is returned on any failure.
 *
 ****************************************************************************/

int arm64_gic_initialize(void)
{
  int err;

  /* Verify that GIC Version is 2 */

  err = gic_validate_dist_version();
  if (err)
    {
      sinfo("no distributor detected, giving up ret=%d\n", err);
      return err;
    }

  /* CPU0-specific initialization for GIC */

  arm_gic0_initialize();

  /* CPU-generic initialization for GIC */

  arm_gic_initialize();

  return 0;
}
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_gicv2.c#L1325-L1363)

If we see this...

```text
/* */ not balanced
```

Check that our stars "__`*`__" are aligned (heh)...

```text
/******************************
 * Name: missing_asterisk_below
 *
 *****************************/
```

After fixing, __test our code__ one last time.

# Write the Pull Request

Our Pull Request will have...

1.  __Title__: NuttX Subsystem and One-Line Summary

1.  __Summary__: What's the purpose of the Pull Request? What files are changed?

1.  __Impact__: Which parts of NuttX are affected by the Pull Request? Which parts _won't_ be affected?

1.  __Testing__: Provide evidence that our Pull Request does what it's supposed to do.

    (And that it won't do what it's _not supposed_ to do)

To write the above items, let's walk through these Pull Requests...

-   [__"arch/arm64: Add support for Generic Interrupt Controller Version 2"__](https://github.com/apache/nuttx/pull/7630)

-   [__"arch/arm64: Add support for PINE64 PinePhone"__](https://github.com/apache/nuttx/pull/7692)

## Title

Inside our Title is the __NuttX Subsystem__ and __One-Line Summary__...

>   _"arch/arm64: Add support for Generic Interrupt Controller Version 2"_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

Let's write this into a __Markdown File__ for easier copying...

-   [__Sample Pull Request__](https://gist.github.com/lupyuen/4dbe011143dfc5404e1791ba74a79deb)

    [(See the Markdown Code)](https://gist.githubusercontent.com/lupyuen/4dbe011143dfc5404e1791ba74a79deb/raw/b8731c9132c428050e6146c0d2097e7bb7c6eb03/sample-nuttx-pull-request.md)

We'll add the following sections to the Markdown File...

## Summary

In the Summary we write the __purpose of the Pull Request__...

>   _"This PR adds support for GIC Version 2, which is needed by Pine64 PinePhone."_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

And we list the __files that we changed__...

>   _"`arch/arm64/Kconfig`: Under "ARM64 Options", we added an integer option ARM_GIC_VERSION ("GIC version") that selects the GIC Version. Valid values are 2, 3 and 4, default is 3."_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

If it's a long list, we might break into subsections like this...

-   [__arch/arm64: Add support for PINE64 PinePhone__](https://github.com/apache/nuttx/pull/7692)

## Impact

Under "Impact", we write __which parts of NuttX are affected__ by the Pull Request. 

(And which parts _won't_ be affected)

>   _"With this PR, NuttX now supports GIC v2 on Arm64._

>   _There is no impact on the existing implementation of GIC v3, as tested below."_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

## Testing

Under "Testing", we provide evidence that our Pull Request __does what it's supposed to do.__ We fill in the...

- __Commands__ used for testing

- __Output Logs__ captured from our testing

Like this...

>   _"We tested with QEMU our implementation of GIC v2:_

>   _`tools/configure.sh qemu-armv8a:nsh_gicv2 ; make ; qemu-system-aarch64 ...`_

>   _[(See the NuttX QEMU Log)](https://gist.github.com/lupyuen/7537da777d728a22ab379b1ef234a2d1)_

>   _The log shows that GIC v2 has correctly handled interrupts"_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

If we have done a [__Regression Test__](https://lupyuen.github.io/articles/pr#regression-test), provide the details too...

>   _"For Regression Testing: We tested the existing implementation of GIC v3..."_

>   _`tools/configure.sh qemu-armv8a:nsh ; make ; qemu-system-aarch64 ...`_

>   _[(See the NuttX QEMU Log)](https://gist.github.com/lupyuen/dec66bc348092a998772b32993e5ed65)_

>   [(Source)](https://github.com/apache/nuttx/pull/7630)

__Test Logs are super helpful__ for NuttX Maintainers!

(Because we can't tell which way the train went... By staring at the track!)

Now we tidy up our commits...

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

![Taking a long walk](https://lupyuen.github.io/images/pr-walk.jpg)

# Meditate

__Breathe. Take a break.__

We're about to make __NuttX History__... Our changes will be recorded for posterity!

Take a long walk and ponder...

-   __Who might benefit__ from our Pull Request

-   How we might __best help them__

(I walked 12 km for 3 hours while meditating on my Pull Request)

If we get an inspiration or epiphany, touch up the Pull Request.

(And resquash the commits)

_What's your epiphany?_

TODO

![Submit the Pull Request](https://lupyuen.github.io/images/pr-pullrequest1.png)

# Submit the Pull Request

Finally it's time to submit our Pull Request!

1.  Create the __Pull Request__ (pic above)

1.  Verify that it has only __One Single Commit__ (pic above)

    [(Squash the Commits)](https://lupyuen.github.io/articles/pr#squash-the-commits)

1.  Copy these into the Pull Request...

    [__Title__](https://lupyuen.github.io/articles/pr#title)

    [__Summary__](https://lupyuen.github.io/articles/pr#summary)

    [__Impact__](https://lupyuen.github.io/articles/pr#impact)

    [__Testing__](https://lupyuen.github.io/articles/pr#testing)

    [(Like this)](https://github.com/apache/nuttx/pull/7630)

1.  Submit the Pull Request

1.  Wait for the __Automated Checks__ to be completed (might take an hour)...

    ![Automated Checks for Pull Request](https://lupyuen.github.io/images/pr-pullrequest2.png)

1.  __Fix any errors__ in the Automated Checks

1.  Wait for the NuttX Team to __review and comment__ on our Pull Request.

    This might take a while (due to the time zones)... Grab a coffee and standby for fixes!

    If all goes Hunky Dory, our Pull Request will be __approved and merged!__ 🎉

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

# Notes

TODO

- QEMU good for regression testing
- Since we might not have the actual hw
- How to support PinePhone UART in QEMU?
- Zig Extension?

- VSCode Extension?
- [Linux checkpatch?](https://marketplace.visualstudio.com/items?itemName=idanp.checkpatch)
- Best if can convert to NuttX style 
