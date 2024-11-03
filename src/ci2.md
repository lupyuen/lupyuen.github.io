# Your very own Build Farm for Apache NuttX RTOS

📝 _27 Oct 2024_

![Refurbished Ubuntu PC becomes Build Farm for Apache NuttX RTOS](https://lupyuen.github.io/images/ci2-title.jpg)

[__Refurbished Ubuntu PCs__](https://qoto.org/@lupyuen/113328181160576977) have become quite affordable ($370 pic above). Can we turn them into a __(Low-Cost) Build Farm__ for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)?

In this article we...

- __Compile NuttX__ for a group of Arm32 Boards

- Then scale up and compile NuttX for __All Arm32 Boards__

- Thanks to the __Docker Image__ provided by NuttX

_Why not do all this in GitHub Actions? It's free ain't it?_

GitHub Actions taught us a Painful Lesson: [__Freebies Won't Last Forever!__](https://github.com/apache/nuttx/issues/14376)

It's probably a bad idea to be locked-in and over-dependent on a __Single Provider for Continuous Integration__. That's why we're exploring alternatives...

[__"[URGENT] Reducing our usage of GitHub Runners"__](https://github.com/apache/nuttx/issues/14376)

![Build Logs for All Boards](https://lupyuen.github.io/images/ci2-log.jpg)

# Target Groups in NuttX

We're creating a Build Farm that will compile __All Boards__ in __All Configurations__ (pic above)

- [__Build Logs for All Boards__](https://gist.github.com/nuttxpr)

To do that, we count every single thing that we're compiling: Targets and Target Groups.

_What's a Target Group?_

```bash
## Select the NuttX Target and compile it
tools/configure.sh rv-virt:nsh
make
```

Remember this __configure.sh__ thingy? Let's call __rv-virt:nsh__ a NuttX Target. Thanks to the awesome NuttX Contributors, we have created [__1,594 NuttX Targets__](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0).

To compile all 1,594 Targets, we lump them into 30 [__Target Groups__](https://github.com/apache/nuttx/tree/master/tools/ci/testlist) (so they're easier to track)

- [_arm-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-01.dat) ... [_arm-14_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-14.dat)

- [_risc-v-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/risc-v-01.dat) ... [_risc-v-06_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/risc-v-06.dat)

- [_sim-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/sim-01.dat) ... [_sim-03_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/sim-03.dat)

- [_xtensa-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/xtensa-01.dat), [_xtensa-02_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/xtensa-02.dat)

- [_arm64-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm64-01.dat), [_x86\_64-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/x86_64-01.dat), [_other_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/other.dat)

Looks familiar? Yep we see these when we [ __Submit a Pull Request__](https://lupyuen.github.io/articles/pr#submit-the-pull-request).

[(See the __Complete List__)](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

_What's inside the Target Groups?_

[_arm-01_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-01.dat) has BeagleBone Black and Sony Spresense...

![Target Group arm-01](https://lupyuen.github.io/images/ci2-group1.png)

[_arm-06_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-06.dat) has RP2040 Boards...

![Target Group arm-06](https://lupyuen.github.io/images/ci2-group2.png)

[_risc-v-03_](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/risc-v-03.dat) has ESP32-C6 and ESP32-H2 Boards...

![Target Group risc-v-03](https://lupyuen.github.io/images/ci2-group3.png)

[(And __So Many More__)](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

_How are Target Groups defined?_

Every NuttX Target has its own __defconfig__...

```bash
$ cd nuttx ; find . -name defconfig
./boards/arm/am335x/beaglebone-black/configs/nsh/defconfig
./boards/arm/cxd56xx/spresense/configs/usbmsc/defconfig
./boards/arm/cxd56xx/spresense/configs/lte/defconfig
./boards/arm/cxd56xx/spresense/configs/wifi/defconfig
...
```

Thus NuttX uses a __Wildcard Pattern__ to select the __defconfig__ (which becomes a NuttX Target): [tools/ci/testlist/arm-05.dat](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-05.dat)

```text
## Target Group arm-05 contains:
## boards/arm/[m-q]*/*/configs/*/defconfig
/arm/[m-q]*,CONFIG_ARM_TOOLCHAIN_GNU_EABI

## Compile the above Targets
## with `make` and GCC Toolchain

## Except for these:
## Compile with CMake instead
CMake,arduino-nano-33ble:nsh

## Exclude this Target from the build
-moxa:nsh
```

We're ready to build the Target Groups...

![Build NuttX for One Target Group](https://lupyuen.github.io/images/ci2-flow2.jpg)

# Build NuttX for One Target Group

Suppose we wish to compile the NuttX Targets inside __Target Group _arm-01___...

![Target Group arm-01](https://lupyuen.github.io/images/ci2-group1.png)

Here are the steps for Ubuntu x64...

1.  Install __Docker Engine__

    [__"Install Docker Engine on Ubuntu"__](https://docs.docker.com/engine/install/ubuntu/)

1.  Download the __Docker Image__ for NuttX

    ```bash
    sudo docker pull \
      ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest
    ```

    [(Won't work for __Arm64__)](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)

1.  Start the __Docker Container__

    ```bash
    sudo docker run -it \
      ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
      /bin/bash -c "..."
    ```

1.  Check out the __master__ branch of __nuttx__ repo

    ```bash
    git clone \
      https://github.com/apache/nuttx
    ```

1.  Do the same for __nuttx-apps__ repo

    ```bash
    git clone \
      https://github.com/apache/nuttx-apps \
      apps
    ```

1.  Inside the Docker Container: __Build the Targets__ for _arm-01_

    ```bash
    cd nuttx/tools/ci
    ./cibuild.sh \
      -c -A -N -R \
      testlist/arm-01.dat
    ```

    [(__cibuild.sh__ compiles a Target Group)](https://github.com/apache/nuttx/blob/master/tools/ci/cibuild.sh)

    [(__arm-01.dat__ selects the Arm32 Targets)](https://github.com/apache/nuttx/blob/master/tools/ci/testlist/arm-01.dat)

1.  Wait for _arm-01_ to complete, then clean up

    (About 1.5 hours. That's 15 mins slower than GitHub Actions)

    ```bash
    ## Optional: Free up the Docker disk space
    sudo docker system prune --force
    ```

Put everything together: [run-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-job.sh)

```bash
## Build a NuttX Target Group with Docker
## Parameter is the Target Group, like "arm-01"
job=$1

## TODO: Install Docker Engine
## https://docs.docker.com/engine/install/ubuntu/

## Download the Docker Image for NuttX
sudo docker pull \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest

## Inside the Docker Container:
## Build the Target Group 
sudo docker run -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash -c "
  cd ;
  pwd ;
  git clone https://github.com/apache/nuttx ;
  git clone https://github.com/apache/nuttx-apps apps ;
  pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/\$(git rev-parse HEAD) ; popd ;
  pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/\$(git rev-parse HEAD) ; popd ;
  cd nuttx/tools/ci ;
  (./cibuild.sh -c -A -N -R testlist/$job.dat || echo '***** BUILD FAILED') ;
"
```

We run it like this (will take 1.5 hours)...

```bash
$ sudo ./run-job.sh arm-01
NuttX Source: https://github.com/apache/nuttx/tree/9c1e0d3d640a297cab9f2bfeedff02f6ce7a8162
NuttX Apps: https://github.com/apache/nuttx-apps/tree/52a50ea72a2d88ff5b7f3308e1d132d0333982e8
====================================================================================
Configuration/Tool: pcduino-a10/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-10-20 17:38:10
------------------------------------------------------------------------------------
  Cleaning...
  Configuring...
  Disabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Enabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Building NuttX...
arm-none-eabi-ld: warning: /root/nuttx/nuttx has a LOAD segment with RWX permissions
  Normalize pcduino-a10/nsh
====================================================================================
Configuration/Tool: beaglebone-black/lcd,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-10-20 17:39:09
```

[(See the __Complete Log__)](https://gist.github.com/nuttxpr/15b86be9e100cace466b99bb790f3a75)

[(Ignore "arm-nuttx-eabi-gcc: command not found")](https://github.com/apache/nuttx/issues/14374)

_What about building a Single Target?_

Suppose we wish to build __ox64:nsh__. Just change this...

```bash
cd nuttx/tools/ci ;
./cibuild.sh -c -A -N -R testlist/$job.dat ;
```

To this...

```bash
cd nuttx ;
tools/configure.sh ox64:nsh ;
make ;
```

_What if we're testing our own repo?_

Suppose we're preparing a Pull Request at _github.com/USER/nuttx/tree/BRANCH_. Just change this...

```bash
git clone https://github.com/apache/nuttx ;
```

To this...

```bash
git clone https://github.com/USER/nuttx --branch BRANCH ;
```

[(More about this)](https://github.com/apache/nuttx/issues/14601#issuecomment-2452875114)

_How to copy the Compiled Files out of the Docker Container?_

This will copy out the __Compiled NuttX Binary__ from Docker...

```bash
## Get the Container ID
sudo docker ps

## Fill in the Container ID below
## Works only when the container is still running so, hmmm...
sudo docker cp \
  CONTAINER_ID:/root/nuttx/nuttx \
  .
```

Now we scale up...

![Build NuttX for All Target Groups](https://lupyuen.github.io/images/ci2-flow.jpg)

# Build NuttX for All Target Groups

_What about compiling NuttX for All Target Groups? From _arm-01_ to _arm-14_?_

We loop through __All Target Groups__ and compile them...

- For Each __Target Group__:

  _arm-01_ ... _arm-14_

- __Compile NuttX__ for the Target Group

- Check for __Errors and Warnings__

- Upload the __Build Log__

Our script becomes more sophisticated: [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L71-L97)

```bash
## Repeat Forever for All Target Groups
for (( ; ; )); do
  for job in \
    arm-01 arm-02 arm-03 arm-04 \
    arm-05 arm-06 arm-07 arm-08 \
    arm-09 arm-10 arm-11 arm-12 \
    arm-13 arm-14
  do
    ## Build the Target Group
    ## and find Errors / Warnings
    run_job $job
    clean_log
    find_messages

    ## Get the hashes for NuttX and Apps
    nuttx_hash=$(grep --only-matching -E "nuttx/tree/[0-9a-z]+" $log_file | grep --only-matching -E "[0-9a-z]+$")
    apps_hash=$(grep --only-matching -E "nuttx-apps/tree/[0-9a-z]+" $log_file | grep --only-matching -E "[0-9a-z]+$")

    ## Upload the log
    ## https://gist.github.com/nuttxpr
    upload_log $job $nuttx_hash $apps_hash
    sleep 10
  done

  ## Free up the Docker disk space
  sudo docker system prune --force
done
```

[(__clean_log__ is here)](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L30-L47)

We run our Build Farm like this...

```bash
## Download the scripts
git clone https://github.com/lupyuen/nuttx-release
cd nuttx-release

## Login to GitHub in Headless Mode
sudo apt install gh
sudo gh auth login

## (1) What Account: "GitHub.com"
## (2) Preferred Protocol: "HTTPS"
## (3) Authenticate GitHub CLI: "Login with a web browser"
## (4) Copy the One-Time Code, press Enter
## (5) Press "q" to quit the Text Browser that appears
## (6) Switch to Firefox Browser and load https://github.com/login/device
## (7) Enter the One-Time Code. GitHub Login will proceed.
## See https://stackoverflow.com/questions/78890002/how-to-do-gh-auth-login-when-run-in-headless-mode

## Run the Build Job forever: arm-01 ... arm-14
sudo ./run-ci.sh
```

[(__For Safety:__ Create a __New GitHub Account__ for posting the gists)](https://lists.apache.org/thread/dntkkb954oss4flcckqjgghzycplrdnf)

_How does it work?_

Inside our script, __run_job__ will compile a single Target Group: [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L20-L30)

```bash
## Build the Target Group, like "arm-01"
function run_job {
  local job=$1
  pushd /tmp
  script $log_file \
    $script_option \
    "$script_dir/run-job.sh $job"
  popd
}
```

Which calls the script we've seen earlier: [__run-job.sh__](https://lupyuen.github.io/articles/ci2#build-nuttx-for-one-target-group)

__upload_log__ will upload the log (to GitHub Gist) for further processing (and alerting): [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L59-L71)

[(Now we have a __NuttX Dashboard__!)](https://github.com/apache/nuttx/issues/14558)

```bash
## Upload to GitHub Gist.
## For Safety: We should create a New GitHub Account for publishing Gists.
## https://gist.github.com/nuttxpr
function upload_log {
  local job=$1
  local nuttx_hash=$2
  local apps_hash=$3

  ## TODO: Change this to use GitHub Token for our new GitHub Account
  cat $log_file | \
    gh gist create \
    --public \
    --desc "[$job] CI Log for nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash" \
    --filename "ci-$job.log"
}
```

[(See the __Uploaded Logs__)](https://gist.github.com/nuttxpr)

[(How to __Delete Gists__)](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L97-L104)

![Build Server is constrained by CPU, not RAM or I/O](https://lupyuen.github.io/images/ci2-load.png)

The whole thing _(arm-01 ... arm-14)_ will take __17.5 Hours__ to complete on our [__Refurbished Intel i5 PC__](https://qoto.org/@lupyuen/113328181160576977).

(Constrained by CPU, not RAM or I/O. Pic above)

Something quirky about about Errors and Warnings...

![Find Errors and Warnings](https://lupyuen.github.io/images/ci2-flow3.jpg)

# Find Errors and Warnings

In the script above, we call __find_messages__ to search for Errors and Warnings: [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh#L47-L61)

```bash
## Search for Errors and Warnings
function find_messages {
  local tmp_file=/tmp/release-tmp.log
  local msg_file=/tmp/release-msg.log
  local pattern='^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$'
  grep '^\*\*\*\*\*' $log_file \
    > $msg_file
  grep -P "$pattern" $log_file \
    | uniq \
    >> $msg_file
  cat $msg_file $log_file >$tmp_file
  mv $tmp_file $log_file
}
```

Which will insert the Errors and Warnings into the top of the Log File.

_Why the funny Regex Pattern?_

The __Regex Pattern__ above is the same one that NuttX uses to detect errors in our [__Continuous Integration__](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L180) builds: [.github/gcc.json](https://github.com/apache/nuttx/blob/master/.github/gcc.json)

```bash
## Filename : Line : Col : warning/error : Message
^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$
```

Which will match and detect [__GCC Compiler Errors__](https://gist.github.com/nuttxpr/62d5cc0da1686174446b3614ea208af0#file-ci-arm-12-log-L1) like...

```bash
chip/stm32_gpio.c:41:11: warning: CONFIG_STM32_USE_LEGACY_PINMAP will be deprecated
```

But it won't match [__CMake Errors__](https://gist.github.com/nuttxpr/353f4c035473cdf67afe0d76496ca950#file-ci-arm-11-log-L421-L451) like this!

```text
CMake Warning at cmake/nuttx_kconfig.cmake:171 (message):
  Kconfig Configuration Error: warning: STM32_HAVE_HRTIM1_PLLCLK (defined at
  arch/arm/src/stm32/Kconfig:8109) has direct dependencies STM32_HRTIM &&
  ARCH_CHIP_STM32 && ARCH_ARM with value n, but is currently being y-selected
```

And [__Linker Errors__](https://gist.github.com/nuttxpr/74e46f5eca2a0cd5a234e5389d40457a#file-ci-arm-04-log-L157)...

```text
arm-none-eabi-ld: /root/nuttx/staging//libc.a(lib_arc4random.o): in function `arc4random_buf':
/root/nuttx/libs/libc/stdlib/lib_arc4random.c:111:(.text.arc4random_buf+0x26): undefined reference to `clock_systime_ticks'
```

Also __Network and Timeout Errors__...

```text
curl: (6) Could not resolve host: github.com
make[1]: *** [open-amp.defs:59: open-amp.zip] Error 6
```

We might need to tweak the Regex Pattern and catch more errors.

![NuttX GitHub Runners: Live Update](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png)

# What's Next

_Huh? Aren't we making a Build Farm, not a Build Server?_

Just add a second Ubuntu PC, partition the Target Groups across the PCs. And we'll have a Build Farm!

_What about macOS?_

macOS compiles NuttX a little differently from Linux. [(See __sim/rpserver_virtio__)](https://github.com/NuttX/nuttx/actions/runs/11470464140/job/31924857916#step:7:1448)

BUT... GitHub charges a [__10x Premium for macOS Runners__](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers). That's why [__we shut them down__](https://github.com/apache/nuttx/issues/14376) to cut costs. [(Pic above)](https://github.com/apache/nuttx/issues/14376#issuecomment-2428086912)

Probably cheaper to buy our own Refurbished Mac Mini (Intel only), running NuttX Jobs all day?

[(Seeking help to port NuttX Jobs to __M1 Mac__)](https://github.com/apache/nuttx/issues/14526)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=41958051)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci2.md)
