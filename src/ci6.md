# "Rewinding a Build" for Apache NuttX RTOS (Docker)

📝 _15 Dec 2024_

!["Rewinding a Build" for Apache NuttX RTOS (Docker)](https://lupyuen.github.io/images/ci6-title.jpg)

__2 Dec 2024:__ Christmas ain't here yet, but our [__Dashboard for Apache NuttX RTOS__](https://lupyuen.github.io/articles/ci4) is already __Decked in Red__...

![Dashboard for Apache NuttX RTOS is already Decked in Red](https://lupyuen.github.io/images/ci6-dashboard2.png)

Which says that NuttX Build is __failing for ESP32-C6__, as reported by [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci2). (More about CI Test next article)

<span style="font-size:90%">

> [_"riscv_exit.c: error: 'tcb' undeclared: <br> g_running_tasks[this_cpu()] = tcb"_](https://gist.github.com/lupyuen/588086e525e91db6ab20fdcfe818af5a#file-ci-unknown-log-L217)

</span>

Normally our NuttX Maintainers will scramble to identify the __Breaking Commit__. (Before it gets piled on by More Breaking Commits)

Not any more! Now we can go back in time and __"Rewind The Build"__, when something breaks the Daily Build...

```bash
## Rewind The Build for
## NuttX Target esp32c6-devkitc:gpio
$ sudo sh -c '
    . ../github-token.sh &&
    ./rewind-build.sh
      esp32c6-devkitc:gpio
  '
Build Failed for This Commit:
  nuttx @ 400239877d55b3f63f72c96ca27d44220ae35a89

[Build OK for Previous Commit:
  nuttx @ 19e42a8978179d23a49c9090c9a713206e6575d0]

Build Failed for Next Commit:
  nuttx @ 140b3080c5f6921e0f9cec0a56ebdb72ca51d1d8

## A-ha! 40023987 is the Breaking Commit!
```

In this article, we look inside our new tool to __Rewind The NuttX Build__...

- How we run the __Rewind Build Script__

- How the Breaking Commit appears in __NuttX Build History__ (pic below)

- What's __inside our Rewind Script__

- How we used to __Rewind Builds Manually__

- Why we build __NuttX in Docker__

![NuttX Build History](https://lupyuen.github.io/images/ci6-history4a.png)

# Rewind The Build

_How does it work?_

```bash
## Rewind The Build for NuttX Target esp32c6-devkitc:gpio
## TODO: Install Docker Engine
## https://docs.docker.com/engine/install/ubuntu/

## TODO: For WSL, we may need to install Docker on Native Windows
## https://github.com/apache/nuttx/issues/14601#issuecomment-2453595402

$ sudo apt install neofetch glab gh
$ git clone https://github.com/lupyuen/nuttx-build-farm
$ cd nuttx-build-farm

## github-token.sh contains a GitHub Token with Gist Permission:
## export GITHUB_TOKEN=...
$ sudo sh -c '
    . ../github-token.sh &&
    ./rewind-build.sh
      esp32c6-devkitc:gpio
  '
Build Failed for This Commit:
  nuttx @ 400239877d55b3f63f72c96ca27d44220ae35a89

[Build OK for Previous Commit:
  nuttx @ 19e42a8978179d23a49c9090c9a713206e6575d0]

Build Failed for Next Commit:
  nuttx @ 140b3080c5f6921e0f9cec0a56ebdb72ca51d1d8

## A-ha! 40023987 is the Breaking Commit!
```

<span style="font-size:90%">

[(Works also for __GitLab Snippets__)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L1-L31)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3)

</span>

We fly our DeLorean back to 2 Dec 2024. And inspect the __NuttX Commits__ that might have broken our build...

```text
## Show the NuttX Commits on 2 Dec 2024
git clone https://github.com/apache/nuttx
cd nuttx
git reset --hard cc96289e2d88a9cdd5a9bedf0be2d72bf5b0e509
git log
```

| 2 Dec | Commit | Title |
|:-----------|:---|:----|
| __12:05__ | [_cc96289e_](https://github.com/apache/nuttx/pull/15010) | _xtensa: syscall SYS_switch_context and SYS_restore_context use 0 para_
| __11:59__ | [_dc8bde8d_](https://github.com/apache/nuttx/pull/15009) | _cmake(enhance): Enhance romfs so that RAWS files can be added in any location_
| __11:49__ | [_208f31c2_](https://github.com/apache/nuttx/pull/15012) | _boards/qemu64: Due to dependency changes, the test program of kasantest is deleted_
| __11:47__ | [_9fbb81e8_](https://github.com/apache/nuttx/pull/15013) | _samv7: fix bytes to words calculation in user signature read_
| __11:14__ | [_140b3080_](https://github.com/apache/nuttx/pull/15011) | _drivers/audio/wm8994.c: Include nuttx/arch.h to fix compilation (up_mdelay prototype)_
| __09:41__ | [_40023987_](https://github.com/apache/nuttx/pull/14984) | _risc-v: remove g_running_tasks[this_cpu()] = NULL_
| __09:23__ | [_19e42a89_](https://github.com/apache/nuttx/pull/14996) | _arch/tricore: migrate to SPDX identifier_
| | | _(Many more commits!)_

One of these is the __Breaking Commit__. Which one?

> ![Rewinding a Build the Manual Way](https://lupyuen.github.io/images/ci6-title2.jpg)

# The Manual Way

This is the __Manual Way__ to find the Breaking Commit (pic above)...

```bash
## Build the Latest Commit: "xtensa syscall"
make distclean
git reset --hard cc96289e
tools/configure.sh esp32c6-devkitc:gpio
make

## If Build Fails: Try the Previous Commit "Enhance romfs"
make distclean
git reset --hard dc8bde8d
tools/configure.sh esp32c6-devkitc:gpio
make

## If Build Fails: Try the Previous Commit "Test program of kasantest"
make distclean
git reset --hard 208f31c2
tools/configure.sh esp32c6-devkitc:gpio
make

## Repeat until the Build Succeeds
## Record everything we've done as evidence
```

__But for Nuttx Maintainers:__ Compiling NuttX Locally might not always work!

We might miss out some toolchains and fail the build: __Arm, RISC-V, Xtensa, x86_64, ...__

> ![Rewinding a Build with Docker](https://lupyuen.github.io/images/ci6-title3.jpg)

# The Docker Way

Thus we run __Docker to Compile NuttX__. Which has __All Toolchains__ bundled inside (pic above)...

```bash
## Build the Latest Commit: "xtensa syscall"
## With the NuttX Docker Image
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

[(More about __NuttX Docker Build__)](https://lupyuen.codeberg.page/articles/ci2.html#build-nuttx-for-one-target-group)

Yep this gets tedious, we __repeat all this 20 times__ (or more) to catch the Breaking Commit!

That's why we run a script to __"Rewind the Build"__, Step Back in Time 20 times (says Kylie), to discover the Breaking Commit...

```bash
## Rewind The Build for NuttX Target esp32c6-devkitc:gpio
## TODO: Install Docker Engine on Ubuntu x64
## https://docs.docker.com/engine/install/ubuntu/
$ sudo apt install neofetch glab gh
$ git clone https://github.com/lupyuen/nuttx-build-farm
$ cd nuttx-build-farm

## github-token.sh contains a GitHub Token with Gist Permission:
## export GITHUB_TOKEN=...
$ sudo sh -c '
    . ../github-token.sh &&
    ./rewind-build.sh
      esp32c6-devkitc:gpio
  '
Build Failed for This Commit:
  nuttx @ 400239877d55b3f63f72c96ca27d44220ae35a89

[Build OK for Previous Commit:
  nuttx @ 19e42a8978179d23a49c9090c9a713206e6575d0]

Build Failed for Next Commit:
  nuttx @ 140b3080c5f6921e0f9cec0a56ebdb72ca51d1d8

## A-ha! 40023987 is the Breaking Commit!
```

<span style="font-size:90%">

[(Works also for __GitLab Snippets__)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L1-L31)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3)

</span>

The [__Rewind Build Log__](https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3) looks kinda messy. We have a better way to record the rewinding, and reveal the Breaking Commit...

# NuttX Build History

Head over to [__NuttX Dashboard__](https://nuttx-dashboard.org) and click __"NuttX Build History"__. (At the top)

Set the __Board__ and __Config__ to _esp32c6-devkitc_ and _gpio_...

![NuttX Build History before fixing](https://lupyuen.github.io/images/ci6-history4a.png)

In reverse chronological order, __NuttX Build History__ says that...

- NuttX Build is __currently failing__ (reported by NuttX Build Farm)

- __Commit 40023987 Onwards:__ All Builds Failed

- __Before Commit 40023987:__ NuttX Builds were Successful

- Which means: Commit 40023987 is our [__Breaking Commit!__](https://gist.github.com/lupyuen/588086e525e91db6ab20fdcfe818af5a#file-ci-unknown-log-L1-L7)

- See the _"sudo docker"_ entries above? They were helpfully inserted by our [__Rewind Build Script__](https://lupyuen.github.io/articles/ci6#rewind-build-script)

- Much neater than the [__Rewind Build Log__](https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3)!

After fixing the Breaking Commit, NuttX Build History shows that everything is [__hunky dory again__](https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?from=now-7d&to=now&timezone=browser&var-arch=$__all&var-subarch=$__all&var-board=esp32c6-devkitc&var-config=gpio&var-group=$__all&var-Filters=) (top row)

![NuttX Build History after fixing](https://lupyuen.github.io/images/ci6-history4.png)

_How did our Rewind Build Script update the Build History?_

Our __Rewind Build Script__ exports the Build Logs to [__GitLab Snippets__](https://gist.github.com/lupyuen/588086e525e91db6ab20fdcfe818af5a#file-ci-unknown-log-L217). (Or GitHub Gists, pic below)

The Build Logs are then ingested into our __NuttX Build History__ by a Scheduled Task. So when you run the Rewind Build Script, please tell me your __GitLab or GitHub User ID__.

![Our Rewind Build Script exports the Build Logs to GitLab Snippets or GitHub Gists](https://lupyuen.github.io/images/ci6-log2.png)

# Rewind Build Script

_What's inside the Rewind Build Script?_

We fetch the __Latest 20 Commits__ from NuttX Repo and Build Each Commit, latest one first: [rewind-build.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L180-L248)

```bash
## First Parameter is Target, like "ox64:nsh"
## Checkout the NuttX Repo and NuttX Apps
target=$1
tmp_dir=/tmp/rewind-build/$target
rm -rf $tmp_dir && mkdir -p $tmp_dir && cd $tmp_dir
git clone https://github.com/apache/nuttx-apps apps
git clone https://github.com/apache/nuttx
cd nuttx

## Fetch the Latest 20 Commits
## In Reverse Chronological Order
for commit in $(
  TZ=UTC0 \
  git log \
  -21 \
  --date='format-local:%Y-%m-%dT%H:%M:%S' \
  --format="%cd,%H"
); do
  ## Commit looks like 2024-11-24T09:52:42,9f9cc7ecebd97c1a6b511a1863b1528295f68cd7
  prev_timestamp=$(echo $commit | cut -d ',' -f 1)  ## 2024-11-24T09:52:42
  prev_hash=$(echo $commit | cut -d ',' -f 2)  ## 9f9cc7ecebd97c1a6b511a1863b1528295f68cd7

  ## For First Commit: Shift the Commits, don't build yet
  if [[ "$next_hash" == "" ]]; then
    next_hash=$prev_hash
  fi;
  if [[ "$nuttx_hash" == "" ]]; then
    nuttx_hash=$prev_hash
  fi;
  if [[ "$timestamp" == "" ]]; then
    timestamp=$prev_timestamp
    continue
  fi;

  ## Compile NuttX for this Commit
  build_commit \
    $tmp_dir/$nuttx_hash.log \
    $timestamp $apps_hash \
    $nuttx_hash $prev_hash $next_hash

  ## Shift the Commits
  next_hash=$nuttx_hash
  nuttx_hash=$prev_hash
  timestamp=$prev_timestamp
done
```

__build_commit__ will compile a NuttX Commit (pic below) and upload the __Build Log__: [rewind-build.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L60-L113)

```bash
## Build the NuttX Commit for the Target
function build_commit {
  ...
  ## Run the Build Job and find errors / warnings
  run_job \
    $log $timestamp $apps_hash \
    $nuttx_hash $prev_hash $next_hash
  clean_log $log
  find_messages $log

  ## Upload the log
  upload_log \
    $log "unknown" \
    $nuttx_hash $apps_hash $timestamp
}

## Run the Build Job for the NuttX Commit and Target.
## Record the Build Log into a file.
function run_job {
  ...
  pushd /tmp
  script $log_file \
    $script_option \
    " \
      $script_dir/rewind-commit.sh \
        $target $nuttx_hash $apps_hash \
        $timestamp $prev_hash $next_hash \
    "
  popd
}
```

Which will call _rewind_commit.sh_ to compile One Single Commit...

<span style="font-size:90%">

[(__clean_log__ removes Control Chars)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L113-L132)

[(__find_messages__ searches for Errors)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L132-L147)

[(__upload_log__ uploads to GitLab Snippet or GitHub Gist)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L147-L180)

[(__Simon Filgis__ suggests that we could use _"git bisect"_ to replace the loop that walks through all commits, making it even faster!)](https://lists.apache.org/thread/n882xpo087gdxwfbbszh8lod5mrm1ttr)

</span>

![Rewind Build Script](https://lupyuen.github.io/images/ci6-title4.jpg)

# Rewind One Commit

Earlier we saw our [__Rewind Build Script__](https://lupyuen.github.io/articles/ci6#rewind-build-script) compiling the Latest 20 Commits. (Pic above)

This is how we compile __One Single Commit__ for NuttX: [rewind-commit.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh#L114-L146)

```bash
target=$1      ## NuttX Target, like "ox64:nsh"
nuttx_hash=$2  ## Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
apps_hash=$3   ## Commit Hash of NuttX Apps Repo, like "d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288"
timestamp=$4   ## Timestamp of the NuttX Commit, like "2024-11-24T00:00:00"
prev_hash=$5   ## Previous Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"
next_hash=$6   ## Next Commit Hash of NuttX Repo, like "7f84a64109f94787d92c2f44465e43fde6f3d28f"

## Download the Docker Image
sudo docker pull \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest

## Build the Target for This Commit
build_nuttx $nuttx_hash $apps_hash

## If it fails: Rebuild with Previous Commit and Next Commit
if [[ "$res" != "0" ]]; then
  build_nuttx $prev_hash $apps_hash
  build_nuttx $next_hash $apps_hash
fi
```

Which calls __build_nuttx__ to compile the commit with the __NuttX Docker Image__: [rewind-commit.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh#L62-L114)

```bash
## Build NuttX in Docker Container
## If CI Test Hangs: Kill it after 1 hour
## We follow the CI Log Format, so that ingest-nuttx-builds will
## ingest our log into NuttX Dashboard and appear in NuttX Build History
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs
function build_nuttx {
  ...
  sudo docker run -it \
    ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
    /bin/bash -c "
    set -e ;
    set -x ;
    cd ;
    git clone https://github.com/apache/nuttx ;
    git clone https://github.com/apache/nuttx-apps apps ;
    pushd nuttx ; git reset --hard $nuttx_commit ; popd ;
    pushd apps  ; git reset --hard $apps_commit  ; popd ;
    cd nuttx ;
    ( sleep 3600 ; echo Killing pytest after timeout... ; pkill -f pytest )&
    (
      (./tools/configure.sh $target && make -j) || (res=\$? ; echo '***** BUILD FAILED' ; exit \$res)
    )
  "
  res=$?
}
```

Finally we see the whole picture, closing the loop with NuttX Repo, NuttX Build Farm, NuttX Dashboard and NuttX Build History!

[(How we __Ingest Build Logs__)](https://lupyuen.github.io/articles/ci4#ingest-the-build-logs)

!["Rewinding a Build" for Apache NuttX RTOS (Docker)](https://lupyuen.github.io/images/ci6-title.jpg)

# What's Next

_Phew that was quick for finding the Breaking Commit?_

Yeah our Rewind Build Script took [__only one hour__](https://gist.github.com/lupyuen/0fe795089736c0ab33be2c965d0f4cf3#file-gistfile1-txt-L540-L8070) to rewind 20 commits and isolate the Breaking Commit! Though fixing it took longer...

- QEMU RISC-V crashed with an [__Instruction Page Fault__](https://github.com/apache/nuttx/pull/15014#issuecomment-2513466731)

- Which we tracked down by [__Rewinding the Past 50 Commits__](https://github.com/lupyuen/nuttx-riscv64/blob/main/special-qemu-riscv-knsh.sh#L43-L59)

- And auto-testing [__Each Commit in QEMU RISC-V__](https://gist.github.com/lupyuen/74c74050683721f1bbbedb21e026ac6f#file-special-qemu-riscv-knsh-log-L1414)

- Yep it's the same idea as Rewinding a Build! Just that we're (slowly) locating a __Runtime Fault__ instead of a (quicker) Compile Error

_Happy Holidays! Will we have more stories about NuttX CI?_

Next Article: We study the internals of a [__Mystifying Bug__](https://github.com/apache/nuttx/issues/14808) that concerns __PyTest, QEMU RISC-V and `expect`__.

Then we'll chat about an __Experimental Mastodon Server__ for NuttX Continuous Integration.

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=42419654)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci6.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci6.md)
