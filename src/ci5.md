# macOS Build Farm for Apache NuttX RTOS (Apple Silicon)

📝 _24 Dec 2024_

![TODO](https://lupyuen.github.io/images/ci5-title.jpg)

__Folks on macOS:__ Compiling [__Apache NuttX RTOS__](TODO) used to be so tiresome. Not any more! [run-build-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-build-macos.sh)

```bash
## Build Anything on Apple Silicon macOS:
## Arm32, RISC-V and Xtensa!
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm
./run-build-macos.sh raspberrypi-pico:nsh
./run-build-macos.sh ox64:nsh
./run-build-macos.sh esp32s3-devkit:nsh
```

TODO

- TODO: Thanks to the awesome work by [__Simbit18__](TODO)!

# Fix the PATH!

__Super Important!__ NuttX won't build correctly on macOS unless we remove __Homebrew ar__ from __PATH__: [run-job-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/run-job-macos.sh)

```bash
## Remove Homebrew ar from PATH
## Instead: We use /usr/bin/ar
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

## To re-download the GCC Toolchains:
## rm -rf /tmp/run-build-macos
```

And it works on __Apple Silicon__! M1, M2, M3, M4, ...

- [__Build Log for Arm32__](https://gist.github.com/lupyuen/5feabeb03f07da716745f9edde73babb) _(raspberrypi-pico:nsh)_

- [__Build Log for RISC-V__](https://gist.github.com/lupyuen/0274fa1ed737d3c82a6b11883a4ad761) _(ox64:nsh)_

- [__Build Log for Xtensa__](https://gist.github.com/lupyuen/2e9934d78440551f10771b7afcbb33be) _(esp32s3-devkit:nsh)_

- With __Some Exceptions__, see below

_Huh what about the GCC Toolchains? Arm32, RISC-V, Xtensa..._

__Toolchains are Auto-Downloaded__, thanks to the brilliant Continuous Integration Script by [__Simbit18__](TODO)!

- [__NuttX CI for macOS Arm64__](https://github.com/apache/nuttx/pull/14723) _(darwin_arm64.sh)_

- [__Add Xtensa Toolchain__](https://github.com/apache/nuttx/pull/14934)

- [__Plus more updates__](https://github.com/apache/nuttx/commits/master/tools/ci/platforms/darwin_arm64.sh)

Just make sure we've installed [__brew__](TODO), [__neofetch__](TODO) and [__Xcode Command-Line Tools__](TODO).

[(Yep the same script drives our __GitHub Daily Builds__)](TODO)

[(Toolchains are downloaded in __10 mins__, subsequent builds are quicker)](https://gist.github.com/lupyuen/0274fa1ed737d3c82a6b11883a4ad761#file-gistfile1-txt-L4236)

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
$script_dir/patch-ci-macos.sh
popd

## Omitted: Suppress the uncommitted darwin_arm64.sh warning:
## We copy the patched "nuttx" folder to "nuttx-patched"
## Then restore the original "nuttx" folder
...

## NuttX CI Build expects this Target Format:
## /arm/rp2040/raspberrypi-pico/configs/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
## /risc-v/bl808/ox64/configs/nsh
## /xtensa/esp32s3/esp32s3-devkit/configs/nsh
## TODO: Add arm64, sim, x86_64, ...
target_file=$tmp_dir/target.dat
rm -f $target_file
echo "/arm/*/$board/configs/$config,CONFIG_ARM_TOOLCHAIN_GNU_EABI" >>$target_file
echo "/risc-v/*/$board/configs/$config" >>$target_file
echo "/xtensa/*/$board/configs/$config" >>$target_file

## Run the NuttX CI Build in "nuttx-patched"
pushd nuttx-patched/tools/ci
(
  ./cibuild.sh -i -c -A -R $target_file \
    || echo '***** BUILD FAILED'
)
popd
```

_What's this patch-ci-macos.sh?_

__To run NuttX CI Locally:__ We made Minor Tweaks. Somehow this Python Environment runs OK at __GitHub Actions__: [TODO](TODO)

```bash
## Original Python Environment:
## Works OK for GitHub Actions
python_tools() { ...
  python3 -m venv \
    --system-site-packages /opt/homebrew ...
```

But it doesn't work locally. Hence we patch _darwin_arm64.sh_ to __Run Locally__: [patch-ci-macos.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/patch-ci-macos.sh#L52-L75)

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

_How does it compare with Docker?_

TODO: Compare with Docker

# Except These Targets

TODO

# macOS Build Farm

_What about the macOS Build Farm?_

Earlier we compiled NuttX for One Single Target. Now we scale up and __Compile All NuttX Targets__... Non-Stop 24 by 7!

TODO: Why? So

# TODO

Build Farm

Compile arm on arm? Not really so fast
compile riscv is faster than compile arm
Mac pro
M4 ultra

https://github.com/devMEremenko/XcodeBenchmark

Refurbished Xeon Workstation is still faster
And more predictable
Use macOS as Front End
VSCode Remote
As a Maintainer, quite tough to depend solely on macOS

brew install gh neofetch

x64 vs arm64 toolchains

TG Pro
Set Fan Speed to "Auto-Max"

Doesn't work:

```bash
tools/configure.sh sim/nsh
make
./nuttx
```


https://github.com/lupyuen/nuttx-build-farm/blob/main/run.sh

```bash
#!/usr/bin/env bash
#  Run NuttX Build Farm for macOS

## Set the GitHub Token
## export GITHUB_TOKEN=...
. $HOME/github-token-macos.sh

set -e  #  Exit when any command fails
set -x  #  Echo commands

## Run All NuttX CI Jobs on macOS
./run-ci-macos.sh

## Run One Single NuttX CI Job on macOS
# ./run-job-macos.sh risc-v-05
```

https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh

```bash
#!/usr/bin/env bash
## Run All NuttX CI Jobs on macOS
## Read the article: https://lupyuen.codeberg.page/articles/ci2.html

echo Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh
device=ci

set -x  ## Echo commands

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"
log_file=/tmp/release-$device.log

## Get the `script` option
if [ "`uname`" == "Linux" ]; then
  script_option=-c
else
  script_option=
fi

## Run the job
function run_job {
  local job=$1
  pushd /tmp
  script $log_file \
    $script_option \
    $script_dir/run-job-macos.sh $job
  popd
}

## Strip the control chars
function clean_log {
  local tmp_file=/tmp/release-tmp.log
  cat $log_file \
    | tr -d '\r' \
    | tr -d '\r' \
    | sed 's/\x08/ /g' \
    | sed 's/\x1B(B//g' \
    | sed 's/\x1B\[K//g' \
    | sed 's/\x1B[<=>]//g' \
    | sed 's/\x1B\[[0-9:;<=>?]*[!]*[A-Za-z]//g' \
    | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g' \
    | cat -v \
    >$tmp_file
  mv $tmp_file $log_file
  echo ----- "Done! $log_file"
}

## Search for Errors and Warnings
function find_messages {
  local tmp_file=/tmp/release-tmp.log
  local msg_file=/tmp/release-msg.log
  local pattern='^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$'
  grep '^\*\*\*\*\*' $log_file \
    > $msg_file
  grep -E "$pattern" $log_file \
    | uniq \
    >> $msg_file
  cat $msg_file $log_file >$tmp_file
  mv $tmp_file $log_file
}

## Upload to GitHub Gist
function upload_log {
  local job=$1
  local nuttx_hash=$2
  local apps_hash=$3
  cat $log_file | \
    gh gist create \
    --public \
    --desc "[$job] CI Log for nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash" \
    --filename "ci-$job.log"
}

## Skip to a Random CI Job. Assume max 32 CI Jobs.
let "skip = $RANDOM % 32"
echo Skipping $skip CI Jobs...

## Repeat forever for All CI Jobs, excluding:
## arm-05: "nrf5340-dk/rpmsghci_nimble_cpuapp: apps/wireless/bluetooth/nimble/mynewt-nimble/nimble/host/services/gatt/src/ble_svc_gatt.c:174:9: error: variable 'rc' set but not used"
## arm-07: "ucans32k146/se05x: mv: illegal option -- T"
## xtensa-02: "esp32s3-devkit/qemu_debug: common/xtensa_hostfs.c:102:24: error: 'SIMCALL_O_NONBLOCK' undeclared"
## xtensa-02: "esp32s3-devkit/knsh: sed: 1: invalid command code ."
## arm64-01: "imx93-evk/bootloader: ld: library not found for -lcrt0.o"
## sim-01, 02, 03: "clang: error: invalid argument 'medium' to -mcmodel="
## other: "micropendous3/hello: make: avr-objcopy: Bad CPU type in executable"
## x86_64-01: "argtable3/src/arg_rex.c:295:10: fatal error: setjmp.h: No such file or directory"
## risc-v-05: CI Test may hang, we move to the end
## Arm32 Jobs run hotter (80 deg C) than RISC-V Jobs (70 deg C). So we stagger the jobs.
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
    ## Skip to a Random CI Job
    if [[ $skip -gt 0 ]]; then
      let skip--
      continue
    fi

    ## Run the CI Job and find errors / warnings
    run_job $job
    clean_log
    find_messages

    ## Get the hashes for NuttX and Apps
    nuttx_hash=$(
      cat $log_file \
      | grep --only-matching -E 'nuttx/tree/[0-9a-z]+' \
      | grep --only-matching -E '[0-9a-z]+$' --max-count=1
    )
    apps_hash=$(
      cat $log_file \
      | grep --only-matching -E 'nuttx-apps/tree/[0-9a-z]+' \
      | grep --only-matching -E '[0-9a-z]+$' --max-count=1
    )

    ## Upload the log
    upload_log $job $nuttx_hash $apps_hash
    date ; sleep 20
  done

  ## Re-download the toolchain, in case the files got messed up
  rm -rf /tmp/run-job-macos
done

## Here's how we delete the 20 latest gists
function delete_gists {
  local gist_ids=($(gh gist list --limit 20 | cut -f 1 | xargs))
  for gist_id in "${gist_ids[@]}"; do
    gh gist delete $gist_id
  done
}
```

https://github.com/lupyuen/nuttx-build-farm/blob/main/run-job-macos.sh

```bash
#!/usr/bin/env bash
## Run a NuttX CI Job on macOS
## To re-download the toolchain: rm -rf /tmp/run-job-macos
## Read the article: https://lupyuen.codeberg.page/articles/ci2.html

echo Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/run-job-macos.sh
echo Called by https://github.com/lupyuen/nuttx-build-farm/blob/main/run-ci-macos.sh
echo utc_time=$(date -u +'%Y-%m-%dT%H:%M:%S')
echo local_time=$(date +'%Y-%m-%dT%H:%M:%S')

set -e  #  Exit when any command fails
set -x  #  Echo commands

# Parameter is CI Job, like "arm-01"
job=$1
if [[ "$job" == "" ]]; then
  echo "ERROR: Job Parameter is missing (e.g. arm-01)"
  exit 1
fi

## Show the System Info
set | grep TMUX || true
neofetch
uname -a

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"

## Remove Homebrew ar from PATH. It shall become /usr/bin/ar
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

## Preserve the Tools Folder
tmp_dir=/tmp/run-job-macos
tools_dir=$tmp_dir/tools
if [[ -d $tools_dir ]]; then
  rm -rf /tmp/tools
  mv $tools_dir /tmp
fi

## Create the Temp Folder and restore the Tools Folder
rm -rf $tmp_dir
mkdir $tmp_dir
cd $tmp_dir
if [[ -d /tmp/tools ]]; then
  mv /tmp/tools .
fi

## Somehow wasi-sdk always fails. We re-download.
rm -rf $tmp_dir/tools/wasi-sdk*

## Checkout NuttX Repo and NuttX Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd

## Patch the macOS CI Job for Apple Silicon: darwin_arm64.sh
## Which will trigger an "uncommitted files" warning later
pushd nuttx
$script_dir/patch-ci-macos.sh
git status
popd

## Suppress the uncommitted darwin_arm64.sh warning:
## We copy the patched "nuttx" folder to "nuttx-patched"
## Then restore the original "nuttx" folder
cp -r nuttx nuttx-patched
pushd nuttx
git restore tools/ci
git status
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

## Exclude clang Targets from macOS Build, because they will fail due to unknown arch
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
## ./cibuild.sh -i -c -A -R testlist/macos.dat
## ./cibuild.sh -i -c -A -R testlist/arm-01.dat
pushd nuttx-patched/tools/ci
(
  ./cibuild.sh -i -c -A -R testlist/$job.dat \
    || echo '***** BUILD FAILED'
)
popd

## Monitor the Disk Space
df -H
```



Docker for Arm64?

Mod the Dockerfile?

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci5.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci5.md)
