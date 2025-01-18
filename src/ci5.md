# macOS Build Farm for Apache NuttX RTOS (Apple Silicon)

📝 _8 Dec 2024_

![macOS Build Farm for Apache NuttX RTOS (Apple Silicon)](https://lupyuen.github.io/images/ci5-title.png)

__Folks on macOS:__ Compiling [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) used to be so tiresome. Not any more! [run-build-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh)

```bash
## Build Anything on Apple Silicon macOS:
## Arm32, RISC-V and Xtensa!
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm
./run-build-macos.sh raspberrypi-pico:nsh
./run-build-macos.sh ox64:nsh
./run-build-macos.sh esp32s3-devkit:nsh

## NuttX Executable will be at
## /tmp/run-build-macos/nuttx
```

In this article, we explain...

- How we __Build Anything__ on macOS Arm64

- By patching the __NuttX CI Script__ for macOS

- Which also becomes our __macOS Build Farm__

- Thanks to the awesome work by [__Simbit18__](https://github.com/simbit18)!

- __Can macOS replace a PC?__ Not quite yet

- Because some NuttX Targets __won't build__ correctly

> ![GNU Coreutils and Binutils on PATH are also known to break build in MacOS](https://lupyuen.github.io/images/ci5-path.png)

> <span style="font-size:80%"> [_"GNU Coreutils and Binutils on PATH are also known to break build in MacOS"_](https://github.com/pyenv/pyenv/issues/2862#issuecomment-1849198741) </span>

# Fix the PATH!

__Super Important!__ NuttX won't build correctly on macOS unless we remove __Homebrew `ar`__ from __PATH__: [run-job-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-job-macos.sh#L32-L46)

```bash
## Remove Homebrew `ar` from PATH
## Instead: We use `/usr/bin/ar`
## https://github.com/pyenv/pyenv/issues/2862#issuecomment-1849198741
export PATH=$(
  echo $PATH \
    | tr ':' '\n' \
    | grep -v "/opt/homebrew/opt/make/libexec/gnubin" \
    | grep -v "/opt/homebrew/opt/coreutils/libexec/gnubin" \
    | grep -v "/opt/homebrew/opt/binutils/bin" \
    | tr '\n' ':'
)
if [[ $(which ar) != "/usr/bin/ar" ]]; then
  echo "ERROR: Expected 'which ar' to return /usr/bin/ar, not $(which ar)"
  exit 1
fi
```

Thus we should always do the above before compiling NuttX. Otherwise we'll see a conflict between the [__Homebrew and Clang Linkers__](https://github.com/apache/nuttx/pull/14691#issuecomment-2462583245)...

```text
ld: archive member '/' not a mach-o file in 'libgp.a'
clang++: error: linker command failed with exit code 1 (use -v to see invocation)
```

![Building raspberrypi-pico:nsh on macOS](https://lupyuen.github.io/images/ci5-build.png)

# Build Anything on macOS

Earlier we talked about compiling __Any NuttX Target__ on macOS: [run-build-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh)

```bash
## Build Anything on Apple Silicon macOS:
## Arm32, RISC-V and Xtensa!
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm
./run-build-macos.sh raspberrypi-pico:nsh
./run-build-macos.sh ox64:nsh
./run-build-macos.sh esp32s3-devkit:nsh

## NuttX Executable will be at
## /tmp/run-build-macos/nuttx

## To re-download the GCC Toolchains
## rm -rf /tmp/run-build-macos
```

And it works on __Apple Silicon__! M1, M2, M3, M4, ...

```text
$ ./run-build-macos.sh raspberrypi-pico:nsh

Configuration/Tool: raspberrypi-pico/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Cleaning...
  Configuring...
  Disabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Enabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Building NuttX...
  Normalize raspberrypi-pico/nsh
```

- [__Build Log for Arm32__](https://gist.github.com/lupyuen/5feabeb03f07da716745f9edde73babb) _(raspberrypi-pico:nsh)_

- [__Build Log for RISC-V__](https://gist.github.com/lupyuen/0274fa1ed737d3c82a6b11883a4ad761) _(ox64:nsh)_

- [__Build Log for Xtensa__](https://gist.github.com/lupyuen/2e9934d78440551f10771b7afcbb33be) _(esp32s3-devkit:nsh)_

- With __Some Exceptions__, see below

_Huh what about the GCC Toolchains? Arm32, RISC-V, Xtensa..._

__Toolchains are Auto-Downloaded__. Thanks to the brilliant Continuous Integration Script by [__Simbit18__](https://github.com/simbit18)!

- [__NuttX CI for macOS Arm64__](https://github.com/apache/nuttx/pull/14723) _(darwin_arm64.sh)_

- [__Add Xtensa Toolchain__](https://github.com/apache/nuttx/pull/14934)

- [__Plus more updates__](https://github.com/apache/nuttx/commits/master/tools/ci/platforms/darwin_arm64.sh)

- [__How it started__](https://github.com/apache/nuttx/pull/14691)

Just make sure we've installed [__brew__](https://brew.sh), [__neofetch__](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh#L1-L11) and [__Xcode Command-Line Tools__](https://www.makeuseof.com/install-xcode-command-line-tools/).

[(Yep the same script drives our __GitHub Daily Builds__)](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L239-L251)

> ![Toolchains are downloaded in __10 mins__, subsequent builds are quicker](https://lupyuen.github.io/images/ci5-toolchains.png)

> <span style="font-size:80%"> [_Toolchains are downloaded in __10 mins__, subsequent builds are quicker_](https://gist.github.com/lupyuen/0274fa1ed737d3c82a6b11883a4ad761#file-gistfile1-txt-L4236) </span>

# Patch the CI Script

_We're running the NuttX CI Script on our computer. How does it work?_

This is how we call [_tools/ci/cibuild.sh_](https://github.com/apache/nuttx/blob/master/tools/ci/cibuild.sh) to Download the Toolchains and __Compile our NuttX Target__: [run-build-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh)

```bash
## Let's download the NuttX Toolchains and Run a NuttX Build on macOS
## First we checkout the NuttX Repo and NuttX Apps...
tmp_dir=/tmp/run-build-macos
cd $tmp_dir
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps

## Then we patch the NuttX CI Script for Apple Silicon: darwin_arm64.sh
## Which will trigger an "uncommitted files" warning later
pushd nuttx
$script_dir/patch-ci-macos.sh  ## https://github.com/lupyuen/nuttx-build-farm/blob/main/patch-ci-macos.sh
popd

## Omitted: Suppress the uncommitted darwin_arm64.sh warning:
## We copy the patched "nuttx" folder to "nuttx-patched"
## Then restore the original "nuttx" folder
...

## NuttX CI Build expects this Target Format:
## /arm/rp2040/raspberrypi-pico/configs/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
## /risc-v/bl808/ox64/configs/nsh
## /xtensa/esp32s3/esp32s3-devkit/configs/nsh
target_file=$tmp_dir/target.dat
rm -f $target_file
echo "/arm/*/$board/configs/$config,CONFIG_ARM_TOOLCHAIN_GNU_EABI" >>$target_file
echo "/arm64/*/$board/configs/$config"  >>$target_file
echo "/risc-v/*/$board/configs/$config" >>$target_file
echo "/sim/*/$board/configs/$config"    >>$target_file
echo "/x86_64/*/$board/configs/$config" >>$target_file
echo "/xtensa/*/$board/configs/$config" >>$target_file

## Run the NuttX CI Build in "nuttx-patched"
pushd nuttx-patched/tools/ci
(
  ./cibuild.sh -i -c -A -R $target_file \
    || echo '***** BUILD FAILED'
)
popd
```

_What is patch-ci-macos.sh?_

__To run NuttX CI Locally:__ We made Minor Tweaks. Somehow this Python Environment runs OK at __GitHub Actions__: [darwin_arm64.sh](https://github.com/apache/nuttx/blob/master/tools/ci/platforms/darwin_arm64.sh#L209-L250)

```bash
## Original Python Environment:
## Works OK for GitHub Actions
python_tools() { ...
  python3 \
    -m venv \
    --system-site-packages /opt/homebrew ...
```

But it doesn't work locally. Hence we patch [_darwin_arm64.sh_](https://github.com/apache/nuttx/blob/master/tools/ci/platforms/darwin_arm64.sh) to __Run Locally__: [patch-ci-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/patch-ci-macos.sh#L52-L75)

```bash
## Modified Python Environment:
## For Local macOS
python_tools() {
  python3 -m venv .venv
  source .venv/bin/activate
```

_Why the "uncommitted darwin_arm64.sh warning"?_

Remember we just patched _darwin_arm64.sh_? NuttX CI is super picky about __Modified Files__, it will warn us because we changed _darwin_arm64.sh_.

__Our Workaround:__ We copy the modified _nuttx_ folder to _nuttx-patched_. Then we run NuttX CI from _nuttx-patched_ folder: [run-build-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh#L89-L134)

```bash
## Suppress the uncommitted darwin_arm64.sh warning:
## We copy the patched "nuttx" folder to "nuttx-patched"
## Then restore the original "nuttx" folder
cp -r nuttx nuttx-patched
pushd nuttx
git restore tools/ci
popd

## Patch the CI Job cibuild.sh to point to "nuttx-patched"
## Change: CIPLAT=${CIWORKSPACE}/nuttx/tools/ci/platforms
## To:     CIPLAT=${CIWORKSPACE}/nuttx-patched/tools/ci/platforms
file=nuttx-patched/tools/ci/cibuild.sh
tmp_file=$tmp_dir/cibuild.sh
search='\/nuttx\/tools\/'
replace='\/nuttx-patched\/tools\/'
cat $file \
  | sed "s/$search/$replace/g" \
  >$tmp_file
mv $tmp_file $file
chmod +x $file

## Run the NuttX CI Build in "nuttx-patched"
pushd nuttx-patched/tools/ci
./cibuild.sh -i -c -A -R $target_file
...
```

![macOS won't compile sim:nsh](https://lupyuen.github.io/images/ci5-simnsh.png)

# Except These Targets

_Awesome! We can compile Everything NuttX on macOS Arm64?_

Erm sorry not quite. These NuttX Targets __won't compile on macOS__...

<span style="font-size:90%">

| Group | Target | Troubles |
|:------|:-------|:---------|
| __arm-05__ | [_nrf5340-dk : <br> rpmsghci_nimble_cpuapp_](https://gist.github.com/lupyuen/1ce979b38c32943545fdde6da144998d) | _ble_svc_gatt.c: rc set but not used_
| __arm-07__ | [_ucans32k146 : <br> se05x_](https://gist.github.com/lupyuen/e2129ba7aa707372be5c13d733b14044) | _mv: illegal option T_
| __arm64-01__ | [_imx93-evk : <br> bootloader_](https://gist.github.com/lupyuen/90d5825725c5abfe89805f104bfa8696) | _ld: library not found for -lcrt0.o_
| __other__ | [_micropendous3 : <br> hello_](https://gist.github.com/lupyuen/966ba9c1bafdfb4cc11625c68a66709b) | _avr-objcopy: Bad CPU type in executable_
| __sim-01 to 03__ | [_sim : <br> nsh_](https://gist.github.com/lupyuen/41955b62a7620cd65e49c6202dc73e6d) | _clang: invalid argument 'medium' to -mcmodel=_
| __x86_64-01__ | [_qemu-intel64 : <br> jumbo_](https://gist.github.com/lupyuen/2771ee11a07f0a33bf0c5d8ef2e5db5f) | _arg_rex.c: setjmp.h: No such file or directory_
| __xtensa-02__ | [_esp32s3-devkit : <br> qemu\_debug_](https://gist.github.com/lupyuen/d3a45a1cb247649e83c0c240eb233fd3) | _xtensa_hostfs.c: SIMCALL_O_NONBLOCK undeclared_
| __xtensa-02__ | [_esp32s3-devkit : <br> knsh_](https://gist.github.com/lupyuen/122a9d572e486b43d3eb60edb44f2189) | _sed: invalid command code ._
| __Clang Groups__ | [_Clang Targets_](https://github.com/apache/nuttx/pull/14691#issuecomment-2466518544) | _clang++: configuration file cannot be found_
| &nbsp;

</span>

We'll come back to this. First we talk about NuttX Build Farm...

![macOS Build Farm](https://lupyuen.github.io/images/ci5-farm.jpg)

# macOS Build Farm

_What's this macOS Build Farm?_

Earlier we compiled NuttX for One Single Target. Now we scale up and __Compile All NuttX Targets__... Non-Stop 24 by 7!

This becomes our Community-Hosted __macOS Build Farm__ for NuttX.

[(Why? So we can __Catch Build Errors__ without depending on GitHub Actions)](https://lupyuen.github.io/articles/ci4)

If Your Mac has Spare CPU Cycles: Please join our __macOS Build Farm__! 🙏 Like so: [run.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run.sh)

```bash
## Run the NuttX Build Farm for macOS.
## Set the GitHub Token: (Should have Gist Permission)
## export GITHUB_TOKEN=...
. $HOME/github-token.sh
brew install neofetch gh glab

## Run All NuttX CI Jobs on macOS
## Will repeat forever
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm
./run-ci-macos.sh

## To re-download the GCC Toolchains:
## rm -rf /tmp/run-job-macos

## For Testing:
## Run One Single NuttX CI Job on macOS
## ./run-job-macos.sh risc-v-01
```

And please tell me your __Gist User ID__. (Also works for [__GitLab Snippets__](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh#L1-L20))

The Build Outcomes will appear in [__NuttX Dashboard__](https://lupyuen.github.io/articles/ci4)...

![macOS Build Farm for Apache NuttX RTOS (Apple Silicon)](https://lupyuen.github.io/images/ci5-dashboard.png)

_How does it work?_

macOS Build Farm shall run (nearly) __All NuttX CI Jobs__, forever and ever: [run-ci-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh#L85-L139)

```bash
## Run All NuttX CI Jobs on macOS, forever and ever.
## Arm32 Jobs run hotter (80 deg C) than RISC-V Jobs (70 deg C).
## So we stagger the jobs.
## risc-v-05: CI Test may hang, we move to the end
for (( ; ; )); do
  for job in \
    arm-08 risc-v-06 \
    arm-09 xtensa-01 \
    arm-10 arm-11 arm-12 arm-13 arm-14 \
    arm-01 risc-v-01 \
    arm-02 risc-v-02 \
    arm-03 risc-v-03 \
    arm-04 risc-v-04 \
    arm-06 risc-v-05
  do
    ## Run the CI Job and find Errors / Warnings
    run_job $job
    clean_log
    find_messages

    ## Upload the log to GitLab Snippet or GitHub Gist
    upload_log $job $nuttx_hash $apps_hash
  done
done

## Run the NuttX CI Job (e.g. risc-v-01)
## Capture the output
function run_job {
  local job=$1
  pushd /tmp
  script $log_file \
    $script_option \
    $script_dir/run-job-macos.sh $job
  popd
}
```

<span style="font-size:90%">

[(__Some Target Groups__ won't compile)](https://lupyuen.github.io/articles/ci5#except-these-targets)

[(__clean_log__ removes Control Chars)](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh#L37-L55)

[(__find_messages__ searches for Errors)](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh#L55-L69)

[(__upload_log__ uploads to GitLab Snippet or GitHub Gist)](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh#L69-L81)

</span>

_What's inside run-job-macos.sh?_

It will run one single __NuttX CI Job__. Similar to the [__NuttX Build Script__](https://lupyuen.github.io/articles/ci5#patch-the-ci-script) we saw earlier: [run-job-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-job-macos.sh)

```bash
## Run one single NuttX CI Job on macOS (e.g. risc-v-01)
## Checkout the NuttX Repo and NuttX Apps
tmp_dir=/tmp/run-job-macos
cd $tmp_dir
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps

## Patch the macOS CI Job for Apple Silicon: darwin_arm64.sh
## Which will trigger an "uncommitted files" warning later
pushd nuttx
$script_dir/patch-ci-macos.sh  ## https://github.com/lupyuen/nuttx-build-farm/blob/main/patch-ci-macos.sh
popd

## Omitted: Suppress the uncommitted darwin_arm64.sh warning:
## We copy the patched "nuttx" folder to "nuttx-patched"
## Then restore the original "nuttx" folder
...

## Exclude clang Targets from macOS Build
## Because they will fail due to unknown arch
## "/arm/lpc54xx,CONFIG_ARM_TOOLCHAIN_CLANG"
## https://github.com/apache/nuttx/pull/14691#issuecomment-2466518544
tmp_file=$tmp_dir/rewrite-testlist.dat
for file in nuttx-patched/tools/ci/testlist/*.dat; do
  grep -v "CLANG" \
    $file \
    >$tmp_file
  mv $tmp_file $file
done

## If CI Test Hangs: Kill it after 1 hour
( sleep 3600 ; echo Killing pytest after timeout... ; pkill -f pytest )&

## Run the CI Job in "nuttx-patched"
## ./cibuild.sh -i -c -A -R testlist/risc-v-01.dat
pushd nuttx-patched/tools/ci
(
  ./cibuild.sh -i -c -A -R testlist/$job.dat \
    || echo '***** BUILD FAILED'
)
popd
```

Now we can cook some NuttX on macOS...

![Mac Mini will get (nearly) Boiling Hot (90 deg C) when running the NuttX Build Farm](https://lupyuen.github.io/images/ci5-title.png)

# Mac Gets Smokin' Hot

_Anything we should worry about?_

Yeah Mac Mini will get (nearly) __Boiling Hot__ (90°C) when running the NuttX Build Farm! All CPU Cores will be __100% Maxed Out__. (M2 Pro, pic above)

I recommend [__TG Pro__](https://www.tunabellysoftware.com/tgpro/) for Fan Control. Set the __Fan Speed to Auto-Max__. (Pic below)

Which will trigger the fans at __70°C__ (red bar below), keeping things cooler. (Compare the green bars with above)

Do you have a __Mac Pro__ or __M4 Pro__? Please test the [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci5#macos-build-farm)! 🙏

([__Xcode Benchmark__](https://github.com/devMEremenko/XcodeBenchmark) suggests Your Mac might be twice as fast as my M2 Pro)

![TG Pro will trigger the fans at 70 deg C](https://lupyuen.github.io/images/ci5-fan.png)

_Is macOS Arm64 faster than Intel PC? For compiling NuttX Arm32?_

Not really, Compiling Arm on Arm isn't much faster. I still prefer Ubuntu PC for compiling NuttX, lemme explain...

![Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!](https://lupyuen.github.io/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!_](https://qoto.org/@lupyuen/113517788288458811)

</span>

# macOS Reconsidered

_Is macOS good enough for NuttX Development?_

If we're Compiling NuttX for __One Single Target__: Arm32 / RISC-V / Xtensa... Yep sure!

But as NuttX Maintainer: I find it tough to reproduce __All Possible NuttX Builds__ on macOS...

- [__Some NuttX Targets__](https://lupyuen.github.io/articles/ci5#except-these-targets) won't compile for macOS

- We have __Limited Skills__ (and machines) for maintaining NuttX CI on macOS

- My Favourite Setup: [__VSCode on macOS__](https://youtu.be/gPNURDLBu70) controlling a [__Refurbished Xeon Workstation__](https://qoto.org/@lupyuen/113517788288458811) for [__Ubuntu Docker Builds__](https://lupyuen.github.io/articles/ci2#build-nuttx-for-one-target-group) (which will faithfully compile everything)

- Shall we use [__Docker for macOS Arm64__](https://discord.com/channels/716091708336504884/1280436444141453313)?

- By [__Modding the NuttX Dockerfile__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)?

![VSCode on macOS controlling a Refurbished Xeon Workstation for Ubuntu Docker Builds](https://lupyuen.github.io/images/ci5-remote.jpg)

[(Watch the __Video on YouTube__)](https://youtu.be/gPNURDLBu70)

Hopefully we'll find a reliable way to compile _sim:nsh_ on macOS...

```bash
## macOS Arm64 won't compile sim:nsh
$ git clone https://github.com/lupyuen/nuttx-build-farm
$ cd nuttx-build-farm
$ ./run-build-macos.sh sim:nsh
clang: error: invalid argument 'medium' to -mcmodel=
```
<span style="font-size:90%">

[(See the __Complete Log__)](https://gist.github.com/lupyuen/41955b62a7620cd65e49c6202dc73e6d)

[(It was __Previously Working!__)](https://github.com/apache/nuttx/pull/14606#pullrequestreview-2425925903)

</span>

![Build Farm for Apache NuttX RTOS](https://lupyuen.github.io/images/ci4-flow.jpg)

# What's Next

Next Article: We chat about a new tool to __"Rewind The Build"__ when something breaks the Daily Build...

- [__"Rewinding a Build for Apache NuttX RTOS (Docker)"__](https://lupyuen.github.io/articles/ci6)

Then we study the internals of a [__Mystifying Bug__](https://github.com/apache/nuttx/issues/14808) that concerns __PyTest, QEMU RISC-V and `expect`__.

- [__"Failing a Continuous Integration Test for Apache NuttX RTOS (QEMU RISC-V)"__](https://lupyuen.github.io/articles/ci7)

- [__"(Experimental) Mastodon Server for Apache NuttX Continuous Integration (macOS Rancher Desktop)"__](https://lupyuen.github.io/articles/mastodon)

- [__"Git Bisecting a Bug (Apache NuttX RTOS)"__](https://lupyuen.org/articles/bisect.html)

- [__"Forgejo Git Forge for Apache NuttX RTOS (Experimental)"__](https://lupyuen.org/articles/forgejo.html)

- [__"Fixing a uname bug (Apache NuttX RTOS)"__](https://lupyuen.org/articles/uname.html)

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://lupyuen.github.io/articles/sponsor), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=42353273)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci5.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci5.md)
