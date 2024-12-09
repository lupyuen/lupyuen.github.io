# "Rewinding a Build" for Apache NuttX RTOS (Docker)

📝 _24 Dec 2024_

![TODO](https://lupyuen.github.io/images/ci6-title.jpg)

TODO: [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) 

__2 Dec 2024:__ Chirstmas ain't here yet, but [__NuttX Dashboard__](TODO) is already __Decked in Red__...

TODO: Pic

Which say that ??? is failing to build. (We'll chat about CI Test next article)

TODO: We chat about a new tool to [__"Rewind The Build"__](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh) when something breaks the Daily Build.

# TODO

https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3

```bash
$ sudo sh -c '. ../github-token.sh && ./rewind-build.sh esp32c6-devkitc:gpio cc96289e2d88a9cdd5a9bedf0be2d72bf5b0e509'
```

TODO: Summary

```text
$ git reset --hard cc96289e2d88a9cdd5a9bedf0be2d72bf5b0e509
$ git log
```

| 2024-12-02 |    |     |
|:-----------|:---|:----|
| __12:05__ | _cc96289e_ | _xtensa: syscall SYS_switch_context and SYS_restore_context use 0 para_
| __11:59__ | _dc8bde8d_ | _cmake(enhance): Enhance romfs so that RAWS files can be added in any location_
| __11:49__ | _208f31c2_ | _boards/qemu64: Due to dependency changes, the test program of kasantest is deleted_
| __11:47__ | _9fbb81e8_ | _samv7: fix bytes to words calculation in user signature read_
| __11:14__ | _140b3080_ | _drivers/audio/wm8994.c: Include nuttx/arch.h to fix compilation (up_mdelay prototype)_
| __09:41__ | _40023987_ | _risc-v: remove g_running_tasks[this_cpu()] = NULL_
| __09:23__ | _19e42a89_ | _arch/tricore: migrate to SPDX identifier_

Normally we do this...

```text
## Build the Latest Commit: "xtensa syscall"
git reset --hard cc96289e
tools/configure.sh esp32c6-devkitc:gpio
make

## If Build Fails: Try the Previous Commit "Enhance romfs"
make distclean
git reset --hard dc8bde8d
tools/configure.sh esp32c6-devkitc:gpio
make

## Repeat until the Build Succeeds
## Record everything we've done as evidence
```

__But for Nuttx Maintainers:__ Compiling NuttX Locally might not always work, we might miss out some toolchains.

Thus we run __Docker to Compile NuttX__...

```text
## Build the Latest Commit: "xtensa syscall"
sudo docker run -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx
git reset --hard cc96289e
tools/configure.sh esp32c6-devkitc:gpio
make -j
exit

## If Build Fails: Try the Previous Commit "Enhance romfs"
sudo docker run ...
git reset --hard dc8bde8d ...
tools/configure.sh esp32c6-devkitc:gpio
make -j ...

## Repeat until the Build Succeeds
## Record everything we've done as evidence
```

Yep this gets tedious, we __repeat all this 20 times__ to catch the Breaking Commit!

That's why we run a script to __"Rewind the Build"__, Step Back in Time 20 times (says Kylie), to discover the Breaking Commit.

https://gist.github.com/lupyuen/588086e525e91db6ab20fdcfe818af5a#file-ci-unknown-log-L427

```text
***** BUILD FAILED FOR THIS COMMIT: nuttx @ 400239877d55b3f63f72c96ca27d44220ae35a89 / nuttx-apps @ ce217b874437b2bd60ad2a2343442506cd8b50b8
(Build OK for Previous Commit 19e42a8978179d23a49c9090c9a713206e6575d0)
***** BUILD FAILED FOR NEXT COMMIT: nuttx @ 140b3080c5f6921e0f9cec0a56ebdb72ca51d1d8 / nuttx-apps @ ce217b874437b2bd60ad2a2343442506cd8b50b8
```

TODO: Manually

TODO: ci6-dashboard1.png

![TODO](https://lupyuen.github.io/images/ci6-dashboard1.png)

TODO: ci6-dashboard2.png

![TODO](https://lupyuen.github.io/images/ci6-dashboard2.png)

TODO: ci6-history1.png

![TODO](https://lupyuen.github.io/images/ci6-history1.png)

TODO: ci6-history2.png

![TODO](https://lupyuen.github.io/images/ci6-history2.png)

TODO: ci6-history3.png

![TODO](https://lupyuen.github.io/images/ci6-history3.png)

TODO: ci6-history4.png

![TODO](https://lupyuen.github.io/images/ci6-history4.png)

TODO: ci6-log1.png

![TODO](https://lupyuen.github.io/images/ci6-log1.png)

TODO: ci6-log2.png

![TODO](https://lupyuen.github.io/images/ci6-log2.png)

https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh

```bash
#!/usr/bin/env bash
## Rewind the NuttX Build for a bunch of Commits.
## Results will appear in the NuttX Dashboard > NuttX Build History:
##   brew install neofetch gh
##   sudo sh -c '. ../github-token.sh && ./rewind-build.sh ox64:nsh'
##   sudo sh -c '. ../github-token.sh && ./rewind-build.sh rv-virt:citest 656883fec5561ca91502a26bf018473ca0229aa4 3c4ddd2802a189fccc802230ab946d50a97cb93c'

## Given a NuttX Target (ox64:nsh):
##   Build the Target for the Latest Commit
##   If it fails: Rebuild with Previous Commit and Next Commit
##   Repeat with Previous 20 Commits
##   Upload Every Build Log to GitHub Gist

## github-token.sh contains `export GITHUB_TOKEN=...`
## GitHub Token needs to have Gist Permission

echo Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh $1

set -e  ## Exit when any command fails
set -x  ## Echo commands

# First Parameter is Target, like "ox64:nsh"
target=$1
if [[ "$target" == "" ]]; then
  echo "ERROR: Target Parameter is missing (e.g. ox64:nsh)"
  exit 1
fi

## (Optional) Second Parameter is the Starting Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
nuttx_commit=$2

## (Optional) Third Parameter is the Commit Hash of NuttX Apps Repo, like "d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288"
apps_commit=$3

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"

## Get the `script` option
if [ "`uname`" == "Linux" ]; then
  script_option=-c
else
  script_option=
fi

## Build the NuttX Commit for the Target
function build_commit {
  local log=$1
  local timestamp=$2
  local apps_hash=$3
  local nuttx_hash=$4
  local prev_hash=$5
  local next_hash=$6

  ## Run the Build Job and find errors / warnings
  run_job \
    $log \
    $timestamp \
    $apps_hash \
    $nuttx_hash \
    $prev_hash \
    $next_hash
  clean_log $log
  find_messages $log

  ## Upload the log
  local job=unknown
  upload_log \
    $log \
    $job \
    $nuttx_hash \
    $apps_hash \
    $timestamp
}

## Run the Build Job
function run_job {
  local log_file=$1
  local timestamp=$2
  local apps_hash=$3
  local nuttx_hash=$4
  local prev_hash=$5
  local next_hash=$6
  pushd /tmp
  script $log_file \
    $script_option \
    " \
      $script_dir/rewind-commit.sh \
        $target \
        $nuttx_hash \
        $apps_hash \
        $timestamp \
        $prev_hash \
        $next_hash \
    "
  popd
}

## Strip the control chars
function clean_log {
  local log_file=$1
  local tmp_file=$log_file.tmp
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
  local log_file=$1
  local tmp_file=$log_file.tmp
  local msg_file=$log_file.msg
  local pattern='^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$'
  grep '^\*\*\*\*\*' $log_file \
    > $msg_file || true
  grep -P "$pattern" $log_file \
    | uniq \
    >> $msg_file || true
  cat $msg_file $log_file >$tmp_file
  mv $tmp_file $log_file
}

## Upload to GitHub Gist
function upload_log {
  local log_file=$1
  local job=$2
  local nuttx_hash=$3
  local apps_hash=$4
  local timestamp=$5
  cat $log_file | \
    gh gist create \
    --public \
    --desc "[$job] CI Log for $target @ $timestamp / nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash" \
    --filename "ci-$job.log"
}

## Create the Temp Folder
tmp_dir=/tmp/rewind-build/$target
rm -rf $tmp_dir
mkdir -p $tmp_dir
cd $tmp_dir

## Get the Latest NuttX Apps Commit (if not provided)
if [[ "$apps_commit" != "" ]]; then
  apps_hash=$apps_commit
else
  git clone https://github.com/apache/nuttx-apps apps
  pushd apps
  apps_hash=$(git rev-parse HEAD)
  popd
fi

## If NuttX Commit is provided: Rewind to the commit
git clone https://github.com/apache/nuttx
cd nuttx
if [[ "$nuttx_commit" != "" ]]; then
  git reset --hard $nuttx_commit
fi

## Build the Latest 20 Commits
num_commits=20
count=1
for commit in $(
  TZ=UTC0 \
  git log \
  -$(( $num_commits + 1 )) \
  --date='format-local:%Y-%m-%dT%H:%M:%S' \
  --format="%cd,%H"
); do
  ## Commit looks like 2024-11-24T09:52:42,9f9cc7ecebd97c1a6b511a1863b1528295f68cd7
  prev_timestamp=$(echo $commit | cut -d ',' -f 1)  ## 2024-11-24T09:52:42
  prev_hash=$(echo $commit | cut -d ',' -f 2)  ## 9f9cc7ecebd97c1a6b511a1863b1528295f68cd7
  if [[ "$next_hash" == "" ]]; then
    next_hash=$prev_hash
  fi;
  if [[ "$nuttx_hash" == "" ]]; then
    nuttx_hash=$prev_hash
  fi;
  if [[ "$timestamp" == "" ]]; then
    timestamp=$prev_timestamp
    continue  ## Shift the Previous into Present
  fi;

  set +x ; echo "***** #$count of $num_commits: Building nuttx @ $nuttx_hash / nuttx_apps @ $apps_hash" ; set -x ; sleep 10
  build_commit \
    $tmp_dir/$nuttx_hash.log \
    $timestamp \
    $apps_hash \
    $nuttx_hash \
    $prev_hash \
    $next_hash

  ## Shift the Commits
  next_hash=$nuttx_hash
  nuttx_hash=$prev_hash
  timestamp=$prev_timestamp
  ((count++))
  date
done

## Wait for Background Tasks to complete
fg || true

## Free up the Docker disk space
sudo docker system prune --force
set +x ; echo "***** Done!" ; set -x
```

https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh

```bash
#!/usr/bin/env bash
## Rewind the NuttX Build for One Single Commit.
## sudo ./rewind-commit.sh ox64:nsh 7f84a64109f94787d92c2f44465e43fde6f3d28f d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288 2024-11-24T00:00:00 7f84a64109f94787d92c2f44465e43fde6f3d28f 7f84a64109f94787d92c2f44465e43fde6f3d28f
## sudo ./rewind-commit.sh rv-virt:citest 656883fec5561ca91502a26bf018473ca0229aa4 3c4ddd2802a189fccc802230ab946d50a97cb93c

## Given a NuttX Target (ox64:nsh):
## Build the Target for the Commit
## If it fails: Rebuild with Previous Commit and Next Commit

echo Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh $1 $2 $3 $4 $5 $6
echo Called by https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh

set -e  ## Exit when any command fails
set -x  ## Echo commands

## First Parameter is Target, like "ox64:nsh"
target=$1
if [[ "$target" == "" ]]; then
  echo "ERROR: Target is missing (e.g. ox64:nsh)"
  exit 1
fi

## Second Parameter is the Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
nuttx_hash=$2
if [[ "$nuttx_hash" == "" ]]; then
  echo "ERROR: NuttX Hash is missing (e.g. 7f84a64109f94787d92c2f44465e43fde6f3d28f)"
  exit 1
fi

## Third Parameter is the Commit Hash of NuttX Apps Repo, like "d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288"
apps_hash=$3
if [[ "$apps_hash" == "" ]]; then
  echo "ERROR: NuttX Apps Hash is missing (e.g. d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288)"
  exit 1
fi

## (Optional) Fourth Parameter is the Timestamp of the NuttX Commit, like "2024-11-24T00:00:00"
timestamp=$4
if [[ "$timestamp" == "" ]]; then
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S")
fi

## (Optional) Fifth Parameter is the Previous Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
prev_hash=$5
if [[ "$prev_hash" == "" ]]; then
  prev_hash=$nuttx_hash
fi

## (Optional) Sixth Parameter is the Next Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
next_hash=$6
if [[ "$next_hash" == "" ]]; then
  next_hash=$nuttx_hash
fi

## Show the System Info
set | grep TMUX || true
neofetch

## Download the Docker Image
sudo docker pull \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest

## Build NuttX in Docker Container
## If CI Test Hangs: Kill it after 1 hour
## We follow the CI Log Format, so that ingest-nuttx-builds will
## ingest our log into NuttX Dashboard and appear in NuttX Build History
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs
## ====================================================================================
## Configuration/Tool: adafruit-kb2040/nshsram,
## 2024-11-25 03:25:20
## ------------------------------------------------------------------------------------
function build_nuttx {
  local nuttx_commit=$1
  local apps_commit=$2
  local target_slash=$(echo $target | tr ':' '/')
  local timestamp_space=$(echo $timestamp | tr 'T' ' ')

  set +x  ## Disable Echo
  echo "===================================================================================="
  echo "Configuration/Tool: $target_slash,"
  echo "$timestamp_space"
  echo "------------------------------------------------------------------------------------"
  set -x  ## Enable Echo

  set +e  ## Ignore errors
  sudo docker run -it \
    ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
    /bin/bash -c "
    set -e ;
    set -x ;
    uname -a ;
    cd ;
    pwd ;
    git clone https://github.com/apache/nuttx ;
    git clone https://github.com/apache/nuttx-apps apps ;
    echo Building nuttx @ $nuttx_commit / nuttx-apps @ $apps_commit ;
    pushd nuttx ; git reset --hard $nuttx_commit ; popd ;
    pushd apps  ; git reset --hard $apps_commit  ; popd ;
    pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/\$(git rev-parse HEAD)    ; popd ;
    pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/\$(git rev-parse HEAD) ; popd ;
    cd nuttx ;
    ( sleep 3600 ; echo Killing pytest after timeout... ; pkill -f pytest )&
    (
      (./tools/configure.sh $target && make -j) || (res=\$? ; echo '***** BUILD FAILED' ; exit \$res)
    )
  "
  res=$?
  set -e  ## Exit when any command fails
  set +x  ## Disable Echo
  echo res=$res
  echo "===================================================================================="
  set -x  ## Enable Echo
}

## Build the Target for the Commit
echo "Building This Commit: nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash"
build_nuttx $nuttx_hash $apps_hash
echo res=$res

## If it fails: Rebuild with Previous Commit and Next Commit
if [[ "$res" != "0" ]]; then
  echo "***** BUILD FAILED FOR THIS COMMIT: nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash"

  if [[ "$prev_hash" != "$nuttx_hash" ]]; then
    echo "Building Previous Commit: nuttx @ $prev_hash / nuttx-apps @ $apps_hash"
    res=
    build_nuttx $prev_hash $apps_hash
    echo res=$res
    if [[ "$res" != "0" ]]; then
      echo "***** BUILD FAILED FOR PREVIOUS COMMIT: nuttx @ $prev_hash / nuttx-apps @ $apps_hash"
    fi
  fi

  if [[ "$next_hash" != "$nuttx_hash" ]]; then
    echo "Building Next Commit: nuttx @ $next_hash / nuttx-apps @ $apps_hash"
    res=
    build_nuttx $next_hash $apps_hash
    echo res=$res
    if [[ "$res" != "0" ]]; then
      echo "***** BUILD FAILED FOR NEXT COMMIT: nuttx @ $next_hash / nuttx-apps @ $apps_hash"
    fi
  fi
fi

## Monitor the Disk Space (in case Docker takes too much)
df -H
```

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

[__lupyuen.github.io/src/ci6.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci6.md)
