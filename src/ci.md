# Continuous Integration for Apache NuttX RTOS

📝 _11 Sep 2024_

![Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/nuttx-ci.jpg)

_Why do we need Continuous Integration?_

Suppose we [__Submit a Pull Request__](https://lupyuen.github.io/articles/pr) for NuttX. We need to be sure that our Modified Code won't break the Existing Builds in NuttX.

That's why our Pull Request will trigger the __Continuous Integration Workflow__, to recompile NuttX for __All Hardware Platforms__.

That's [__1,594 Build Targets__](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0) across Arm, RISC-V, Xtensa, AVR, i486, Simulator and more!

_What happens inside the Continuous Integration?_

Head over to the [__NuttX Repository__](https://github.com/apache/nuttx)...

- Click [__GitHub Actions > Workflows > Build__](https://github.com/apache/nuttx/actions/workflows/build.yml)

- Click [__any one of the jobs__](https://github.com/apache/nuttx/actions/runs/10552464655)

- Click [__Linux (arm-01) > Run Builds__](https://github.com/apache/nuttx/actions/runs/10552464655/job/29231352816)

We'll see this __NuttX Build for Arm32__...

```text
====================================================================================
Configuration/Tool: pcduino-a10/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-08-26 02:30:55
------------------------------------------------------------------------------------
Cleaning...
Configuring...
Enabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
Building NuttX...
arm-none-eabi-ld: warning: /github/workspace/sources/nuttx/nuttx has a LOAD segment with RWX permissions
Normalize pcduino-a10/nsh
```

Followed by __Many More Arm32 Builds__...

```text
Config: beaglebone-black/nsh
Config: at32f437-mini/eth
Config: at32f437-mini/sdcard
Config: at32f437-mini/systemview
Config: at32f437-mini/rtc
...
```

_What's in a NuttX Build?_

Each __NuttX Build__ will be a...

- Regular __NuttX Make__ for a NuttX Target

- Or a __NuttX CMake__ for Newer Targets

- Or a __Python Test__ for POSIX Validation

_What about other NuttX Targets? Arm64, RISC-V, Xtensa, ..._

Every Pull Request will trigger __24 Jobs for Continuous Integration__, all compiling concurrently...

- __Arm32 Targets:__ arm-01, arm-02, arm-03, ...

- __RISC-V Targets:__ riscv-01, ...

- __Xtensa Targets:__ xtensa-01, ...

- __Simulator Targets:__ sim-01, ...

- __Other Targets__ (Arm64, AVR, i486, ...)

- __macOS and Windows__ (msys2)

Each of the above 24 jobs will run for __30 minutes to 2 hours__. After 2 hours, we'll know for sure whether our Modified Code will break any NuttX Build!

# One Thousand Build Targets

_Each of the 24 jobs above will run up to 2 hours. Why?_

That's because the 24 Build Jobs will __recompile 1,594 NuttX Targets__ from scratch!

Here's the [__complete list of Build Targets__](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)...

- __Arm32:__ 932 targets

  _(arm-01 to arm-13)_

- __RISC-V:__ 212 targets

  _(riscv-01, riscv-02)_

- __Xtensa:__ 195 targets

  _(xtensa-01, xtensa-02)_

- __Simulator:__ 86 targets

  _(sim-01, sim-02)_

- __Others:__ 72 targets

  _(other)_

- __macOS and Windows:__ 97 targets

  _(macos, sim-01, sim-02, msys2)_

_Is this a problem?_

Every single Pull Request will execute 24 Build Jobs in parallel. 

Which needs __24 GitHub Runners__ per Pull Request. And [__they ain't cheap__](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions#per-minute-rates-for-standard-runners)!

![GitHub Runners for Apache NuttX RTOS](https://lupyuen.github.io/images/nuttx-ci2.png)

# Self-Hosted Runners

We experiment with [__Self-Hosted Runners__](https://docs.github.com/en/actions/hosting-your-own-runners) to understand what happens inside NuttX Continous Integration. We run them on two computers...

- __Older PC__ on Ubuntu x64 (Intel i7, 3.7 GHz)

- __Newer Mac Mini__ on macOS Arm64 (M2 Pro)

- With plenty of __Internet Bandwidth__

Look for this code in our __GitHub Actions Worklow__: [.github/workflows/build.yml](https://github.com/lupyuen3/runner-nuttx/pull/1/files#diff-5c3fa597431eda03ac3339ae6bf7f05e1a50d6fc7333679ec38e21b337cb6721)

```yaml
## Linux Build runs on GitHub Runners
Linux:
  needs:   Fetch-Source
  runs-on: ubuntu-latest
```

Change __`runs-on`__ to...

```yaml
  ## Linux Build now runs on Self-Hosted Runners (Linux x64)
  runs-on: [self-hosted, Linux, X64]
```

Install __Self-Hosted Runners__ for Linux x64 and macOS Arm64...

- [__Follow these Instructions__](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners) from GitHub

- Apply the [__Fixes for Linux Runners__](https://lupyuen.github.io/articles/ci#appendix-fixes-for-ubuntu-x64)

- And the [__Fixes for macOS Runners__](https://lupyuen.github.io/articles/ci#appendix-fixes-for-macos-arm64)

They will run like this...

```bash
## Configure our Self-Hosted Runner for Linux x64
$ cd actions-runner
$ ./config.sh --url YOUR_REPO --token YOUR_TOKEN
Enter the name of the runner group: <Press Enter>
Enter the name of runner: <Press Enter>
This runner will have the following labels:
  'self-hosted', 'Linux', 'X64'
Enter any additional labels: <Press Enter>
Enter name of work folder: <Press Enter>

## For macOS on Arm64: Runner Labels will be
## 'self-hosted', 'macOS', 'ARM64'

## Start our Self-Hosted Runner
$ ./run.sh
Current runner version: '2.319.1'
Listening for Jobs
Running job: Linux (arm-01)
```

Beware of [__Security Concerns__](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)!

- Ensure that Self-Hosted Runners will run only __Approved Scripts and Commands__

- Remember to __Disable External Users__ from triggering GitHub Actions on our repo

- __Shut Down the Runners__ when we're done with testing

# Running the Runners

_Our Self-Hosted Runners: Do they work for NuttX Builds?_

According to [__the result here__](https://github.com/lupyuen3/runner-nuttx/actions), yep [__they work yay__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349060343)!

That's __2 hours__ on a 10-year-old MacBook Pro with Intel i7 on Ubuntu.

(Compare that with __GitHub Runners__, which will take __30 mins__ per job)

![linux-build](https://github.com/user-attachments/assets/2e2861bc-6af0-48f4-b3a1-d0083cd23155)

_Do we need a faster PC?_

Not necessarily. We see some __Network Throttling__ for our Self-Hosted Runners (in spite of our super-fast internet)...

- __Docker Hub__ will throttle our downloading of the NuttX Docker Image. Which is required for [__building the NuttX Targets__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci).

  If it gets too slow, cancel the GitHub Workflow and restart. Throttling will magically disappear.

- __Downloading the NuttX Source Code__ (700 MB) from GitHub takes 25 minutes.

  (For GitHub Runners: Under 10 seconds!)

  ![Screenshot 2024-08-29 at 2 09 11 PM](https://github.com/user-attachments/assets/585bc261-bc39-4be4-8515-85894254aace)

_Can we guesstimate the time to run a Build Job?_

Just browse the __GitHub Actions Log__ for the Build Job. See the __Line Numbers__?

Every Build Job will have roughly __1,000 Lines of Log__ (by sheer coincidence). We can use this to guess the Job Duration.

_What about macOS on Arm64?_

Sadly the [__Linux Builds__](https://github.com/lupyuen3/runner-nuttx/actions/workflows/build.yml) won't run on macOS Arm64 because they need __Docker on Linux x64__...

- [__"Building the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)

- [__"Downloading the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-downloading-the-docker-image-for-nuttx-ci)

We'll talk about Emulating x64 on macOS Arm64. But first we run Fetch Source on macOS...

![Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/nuttx-ci.jpg)

# Fetch Source on macOS Arm64

_We haven't invoked the Runners for macOS Arm64?_

[__Fetch Source__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29343582486) works OK on macOS Arm64. Let's try it now.

Head over to our NuttX Repo and update the __GitHub Actions Workflow__: [.github/workflows/build.yml](https://github.com/lupyuen3/runner-nuttx/pull/1/files#diff-5c3fa597431eda03ac3339ae6bf7f05e1a50d6fc7333679ec38e21b337cb6721)

```yaml
## Fetch-Source runs on GitHub Runners
jobs:
  Fetch-Source:
    runs-on: ubuntu-latest
```

Change __`runs-on`__ to...

```yaml
    ## Fetch-Source now runs on Self-Hosted Runners (macOS Arm64)
    runs-on: [self-hosted, macOS, ARM64]
```

[__According to our log__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29343582486), Fetch Source runs OK on macOS Arm64.

(Completes in about a minute, 700 MB GitHub Uploads are surprisingly quick)

_How is Fetch Source used?_

__Fetch Source__ happens before any NuttX Build. It checks out the Source Code from the NuttX Kernel Repo and NuttX Apps Repo.

Then it zips up the Source Code and passes the Zipped Source Code to the NuttX Builds.

(__700 MB__ of zipped source code)

_Anything else we can run on macOS Arm64?_

Unfortunately not, we need some more fixes...

- [__"NuttX CI for macOS"__](https://lupyuen.github.io/articles/ci#appendix-nuttx-ci-for-macos)

- [__"Documentation Build for NuttX"__](https://lupyuen.github.io/articles/ci#appendix-documentation-build-for-nuttx)

# UTM Emulator for macOS Arm64

_So NuttX Builds run better with a huge x64 Ubuntu PC. Can we make macOS on Arm64 more useful?_

Let's test [__UTM Emulator for macOS Arm64__](https://mac.getutm.app/), to emulate Ubuntu x64. (Spoiler: It's really slow!)

On a super-duper Mac Mini (M2 Pro, 32 GB RAM): We can emulate an Intel i7 PC with __32 CPUs and 4 GB RAM__ (because we don't need much RAM)

![Screenshot 2024-08-29 at 10 08 07 PM](https://github.com/user-attachments/assets/5ff0d94e-4a04-4cf4-8f0a-8e0ee9d1cd59)

Remember to __Force Multicore__ and bump up the __JIT Cache__...

![Screenshot 2024-08-29 at 10 08 25 PM](https://github.com/user-attachments/assets/3a162236-9c14-4615-b9c7-c3a90ef7293c)

__Ubuntu Disk Space__ in the UTM Virtual Machine needs to be big enough for NuttX Docker Image...

```bash
$ neofetch
OS:     Ubuntu 24.04.1 LTS x86_64
Host:   KVM/QEMU (Standard PC (Q35 + ICH9, 2009) pc-q35-7.2)
Kernel: 6.8.0-41-generic
CPU:    Intel i7 9xx (Nehalem i7, IBRS update) (16) @ 1.000GHz
GPU:    00:02.0 Red Hat, Inc. Virtio 1.0 GPU
Memory: 1153MiB / 3907MiB

$ df -H
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           410M  1.7M  409M   1% /run
/dev/sda2        67G   31G   33G  49% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M  8.2k  5.3M   1% /run/lock
efivarfs        263k   57k  201k  23% /sys/firmware/efi/efivars
/dev/sda1       1.2G  6.5M  1.2G   1% /boot/efi
tmpfs           410M  115k  410M   1% /run/user/1000

$ cd actions-runner
$ ./run.sh 

Connected to GitHub
Current runner version: '2.319.1'
02:33:17Z: Listening for Jobs
02:33:23Z: Running job: Linux (arm-04)
06:47:38Z: Job Linux (arm-04) completed with result: Succeeded
06:47:43Z: Running job: Linux (arm-01)
```

During __Run Builds__: CPU hits 100%...

![Screenshot 2024-08-29 at 4 56 06 PM](https://github.com/user-attachments/assets/60d4d3eb-d075-49c9-b3ac-bcfa74150668)

(Don't leave System Monitor running, it consumes quite a bit of CPU!)

If the CI Job doesn't complete in __6 hours__: GitHub will cancel it! So we should give it as much CPU as possible.

__Why emulate 32 CPUs?__ That's because we want to max out the macOS Arm64 CPU Utilisation. Our chance to watch Mac Mini run smokin' hot!

![Screenshot 2024-08-30 at 4 14 20 PM](https://github.com/user-attachments/assets/a9dab4fd-a59f-4348-a3f7-397973797288)

![Screenshot 2024-08-30 at 4 14 05 PM](https://github.com/user-attachments/assets/bfd51e51-1bee-49c2-88a3-01698d51d8a4)

![Screenshot 2024-08-29 at 10 43 39 PM](https://github.com/user-attachments/assets/0ea9f33e-1e6f-412a-8f56-6f40dee7f699)

Results of macOS Arm64 __emulating Ubuntu x64__ (24.04.1 LTS) with 4GB RAM...

- [__Build for arm-01__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29503152279)

  _(Incomplete. Timeout after 6 hours sigh)_

- [__Build for arm-02__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29508376208)

  _(Completed in 1.7 hours, vs 1 hour for GitHub Runners)_

- [__Build for arm-03__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29428211466)

  _(Completed in 4 hours, vs 0.5 hours for GitHub Runners)_

- [__Build for arm-04__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29456380032)

  _(Completed in 4 hours, vs 0.5 hours for GitHub Runners)_

Does __UTM Emulator__ work for NuttX Builds? Yeah kinda...

But how long to build? __4 hours!__

(Instead of __33 mins__ for GitHub Runners)

_What if we run a Self-Hosted Runner inside a Docker Container on macOS Arm64? (Rancher Desktop)_

But it becomes a __Linux Arm64 Runner__, not a Linux x64 Runner. Which won't work with our current NuttX Docker Image, which is x64 only...

- [__"Building the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)

- [__"Downloading the Docker Image for NuttX CI"__](https://lupyuen.github.io/articles/pr#appendix-downloading-the-docker-image-for-nuttx-ci)

Unless we create a Linux Arm64 Docker Image? Like for [__Compiling RISC-V Platforms__](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci).

We'll chat about this in [__NuttX Discord Channel__](https://discord.com/channels/716091708336504884/1280436444141453313).

![Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/nuttx-ci.jpg)

# What's Next

According to [__ASF Policy__](https://infra.apache.org/github-actions-policy.html): We should reduce to __15 Concurrent GitHub Runners__  (we're now at 24 concurrent runners). How?

1.  We could review the [__1,594 Build Targets__](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0) and decide which targets should be excluded. Or reprioritised to run earlier / later.

1.  We could run [__All 1,594 Builds__](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0) only when the PR is Approved. So we can save on Build Times for the Submission / Resubmission of the PR.

1.  We need a quicker way to __"Fail Fast"__ and (in case of failure) prevent other Build Jobs from running. Which will reduce the number of Runners.

1. What if we could __Start Earlier the Build Jobs__ that are impacted by the Modified Code in the PR?

   So if I modify something for Ox64 BL808 SBC, it should start the CI Job for __`ox64:nsh`__. If it fails, then don't bother with the rest of the Arm / RISC-V / Simulator jobs.

   (Maybe we dump the __NuttX ELF Disassembly__ and figure out which Source Files are used for which NuttX Targets?)

Let's discuss!

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci.md)

# Appendix: Phase 1 of CI Upgrade

We're modifying NuttX CI (Continuous Integration) and GitHub Actions, to comply with ASF Policy. Unfortunately, these changes will extend the Build Duration for a NuttX Pull Request by roughly 15 mins, from 2 hours to 2.25 hours.

Right now, every NuttX Pull Request will trigger 24 Concurrent Jobs (GitHub Runners), [__executing them in parallel__](https://lupyuen.github.io/articles/ci).

According to [__ASF Policy__](https://infra.apache.org/github-actions-policy.html): We should run at most 15 Concurrent Jobs.

Thus we'll cut down the Concurrent Jobs from 24 down to 15. That's 12 Linux Jobs, 2 macOS, 1 Windows. (Each job takes 30 mins to 2 hours)

(1) Right now our "Linux > Strategy" is a flat list of 20 Linux Jobs, all executed in parallel...

```yaml
  Linux:
    needs: Fetch-Source
    runs-on: ubuntu-latest
    env:
      DOCKER_BUILDKIT: 1

    strategy:
      matrix:
        boards: [arm-01, arm-02, arm-03, arm-04, arm-05, arm-06, arm-07, arm-08, arm-09, arm-10, arm-11, arm-12, arm-13, other, risc-v-01, risc-v-02, sim-01, sim-02, xtensa-01, xtensa-02]
```

(2) We change "Linux > Strategy" to prioritise by Target Architecture, and limit to 12 concurrent jobs...

```yaml
  Linux:
    needs: Fetch-Source
    runs-on: ubuntu-latest
    env:
      DOCKER_BUILDKIT: 1

    strategy:
      max-parallel: 12
      matrix:
        boards: [
          arm-01, other, risc-v-01, sim-01, xtensa-01,
          arm-02, risc-v-02, sim-02, xtensa-02,
          arm-03, arm-04, arm-05, arm-06, arm-07, arm-08, arm-09, arm-10, arm-11, arm-12, arm-13
        ]
```

(3) So NuttX CI will initially execute 12 Build Jobs across Arm32, Arm64, RISC-V, Simulator and Xtensa. As they complete, NuttX CI will execute the remaining 8 Build Jobs (for Arm32).

(4) This will extend the Overall Build Duration from [__2 hours__](https://github.com/apache/nuttx/actions/runs/10817443237) to [__2.25 hours__](https://github.com/lupyuen4/ci-nuttx/actions/runs/10828246630)

(5) We'll also limit macOS Jobs to 2, Windows Jobs to 1. Here's the [__Draft PR__](https://github.com/apache/nuttx/pull/13412).

```yaml
  macOS:
    permissions:
      contents: none
    runs-on: macos-13
    needs: Fetch-Source
    strategy:
      max-parallel: 2
      matrix:
        boards: [macos, sim-01, sim-02]
  ...
  msys2:
    needs: Fetch-Source
    runs-on: windows-latest
    strategy:
      fail-fast: false
      max-parallel: 1
      matrix:
        boards: [msys2]
```

Read on for Phase 2...

# Appendix: Phase 2 of CI Upgrade

For Phase 2: We should "rebalance" the Build Targets. Move the Newer or Higher Priority or Riskier Targets to arm-01, risc-v-01, sim-01, xtensa-01.

Hopefully this will allow NuttX CI to Fail Faster (for breaking changes), and prevent unnecessary builds (also reduce waiting time).

We should probably balance arm-01, risc-v-01, sim-01, xtensa-01 so they run in about 30 mins consistently.

Read on for Phase 3...

# Appendix: Phase 3 of CI Upgrade

For Phase 3: We should migrate most of the NuttX Targets to a Daily Job for Build and Test.

Check out the [__discussion here__](https://lists.apache.org/thread/3k6y28y8z6gklnws1pdg48gb6j28zmxp).

# Appendix: Fixes for Ubuntu x64

To run the Self-Hosted Runners on Ubuntu x64, we need these fixes...

```bash
## TODO: Install Docker Engine: https://docs.docker.com/engine/install/ubuntu/
## TODO: Apply this fix: https://stackoverflow.com/questions/48957195/how-to-fix-docker-got-permission-denied-issue
## Note: podman won't work

## NuttX CI needs to save files in `/github`, so we create it
## TODO: How to give each runner its own `/github` folder? Do we mount in Docker?
mkdir -p $HOME/github/home
mkdir -p $HOME/github/workspace
sudo ln -s $HOME/github /github
ls -l /github/home

## TODO: Clean up after every job, then restart the runner
sudo rm -rf $HOME/actions-runner/_work/runner-nuttx
cd $HOME/actions-runner
./run.sh

## TODO: In case of timeout after 6 hours:
## Restart the Ubuntu Machine, because the tasks are still running in background!
```

_Why Docker Engine? Not Podman Docker?_

Podman Docker on Linux x64 [fails with this error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677). Might be a [problem with Podman](https://github.com/containers/podman/discussions/14238)...

```text
Writing manifest to image destination
Error: statfs /var/run/docker.sock: permission denied
```

Docker Engine [fails with a similar error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29344966455)...

```text
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.47/images/create?fromImage=ghcr.io%2Fapache%2Fnuttx%2Fapache-nuttx-ci-linux&tag=latest": dial unix /var/run/docker.sock: connect: permission denied
```

That's why we apply [this Docker Fix](https://stackoverflow.com/questions/48957195/how-to-fix-docker-got-permission-denied-issue). 

# Appendix: Fixes for macOS Arm64

To run the Self-Hosted Runners on macOS Arm64, we need these fixes...

```bash
sudo mkdir /Users/runner
sudo chown $USER /Users/runner
sudo chgrp staff /Users/runner
ls -ld /Users/runner
```

# Appendix: NuttX CI for macOS

We have challenges running NuttX CI on macOS Arm64...

[`Build macOS (macos / sim-01 / sim-02)`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/build.yml) on macOS Arm64: `setup-python` will [hang because it's prompting for password](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29343630883). So we comment out `setup-python`.

```text
Run actions/setup-python@v5
Installed versions
Version 3.[8](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:9) was not found in the local cache
Version 3.8 is available for downloading
Download from "https://github.com/actions/python-versions/releases/download/3.8.10-887[9](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:10)978422/python-3.8.10-darwin-arm64.tar.gz"
Extract downloaded archive
/usr/bin/tar xz -C /Users/luppy/actions-runner2/_work/_temp/2e[13](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:14)8b05-b7c9-4759-956a-7283af148721 -f /Users/luppy/actions-runner2/_work/_temp/792ffa3a-a28f-4443-91c8-0d81f55e422f
Execute installation script
Check if Python hostedtoolcache folder exist...
Install Python binaries from prebuilt package
```

Then it fails while [downloading the toolchain](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349061179):

```text
+ wget --quiet https://developer.arm.com/-/media/Files/downloads/gnu/13.2.rel1/binrel/arm-gnu-toolchain-13.2.rel1-darwin-x86_64-arm-none-eabi.tar.xz
+ xz -d arm-gnu-toolchain-13.2.rel1-darwin-x86_64-arm-none-eabi.tar.xz
xz: arm-gnu-toolchain-13.2.rel1-darwin-x86_64-arm-none-eabi.tar.xz: Unexpected end of input
```

Retry and it [fails at objcopy sigh](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29359739769):

```text
+ rm -f /Users/luppy/actions-runner3/_work/runner-nuttx/runner-nuttx/sources/tools/bintools/bin/objcopy
+ ln -s /usr/local/opt/binutils/bin/objcopy /Users/luppy/actions-runner3/_work/runner-nuttx/runner-nuttx/sources/tools/bintools/bin/objcopy
+ command objcopy --version
+ objcopy --version
/Users/luppy/actions-runner3/_work/runner-nuttx/runner-nuttx/sources/nuttx/tools/ci/platforms/darwin.sh: line 93: objcopy: command not found
```

__TODO:__ Do we change the toolchain from x64 to Arm64?

# Appendix: Documentation Build for NuttX

_Our Self-Hosted Runners: Do they work for Documentation Build?_

- [`Documentation`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/doc.yml) on macOS Arm64: [Hangs at setup-python](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677) because it prompts for password:
  ```text
  Run actions/setup-python@v5
  Installed versions
  Version 3.[8](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:9) was not found in the local cache
  Version 3.8 is available for downloading
  Download from "https://github.com/actions/python-versions/releases/download/3.8.10-887[9](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:10)978422/python-3.8.10-darwin-arm64.tar.gz"
  Extract downloaded archive
  /usr/bin/tar xz -C /Users/luppy/actions-runner2/_work/_temp/2e[13](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677#step:3:14)8b05-b7c9-4759-956a-7283af148721 -f /Users/luppy/actions-runner2/_work/_temp/792ffa3a-a28f-4443-91c8-0d81f55e422f
  Execute installation script
  Check if Python hostedtoolcache folder exist...
  Install Python binaries from prebuilt package
  ```
  And it won't work on macOS because it needs `apt`: [workflows/doc.yml](https://github.com/lupyuen3/runner-nuttx/blob/master/.github/workflows/doc.yml#L34-L40)
  ```yaml
      - name: Install LaTeX packages
        run: |
          sudo apt-get update -y
          sudo apt-get install -y \
            texlive-latex-recommended texlive-fonts-recommended \
            texlive-latex-base texlive-latex-extra latexmk texlive-luatex \
            fonts-freefont-otf xindy
  ```

- [`Documentation`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/doc.yml) on Linux Arm64:  [Fails at setup-python](https://github.com/lupyuen3/runner-nuttx/actions/runs/10590973119/job/29347607289)
  ```text
  Run actions/setup-python@v5
  Installed versions
  Version 3.[8](https://github.com/lupyuen3/runner-nuttx/actions/runs/10590973119/job/29347607289#step:3:9) was not found in the local cache
  Error: The version '3.8' with architecture 'arm64' was not found for Debian 12.
  The list of all available versions can be found here: https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json
  ```
  So we comment out `setup-python`. Then it fails with [pip3 not found](https://github.com/lupyuen3/runner-nuttx/actions/runs/10593895809/job/29356477035):
  ```text
  pip3: command not found
  ```
  __TODO:__ Switch to pipenv

- [`Documentation`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/doc.yml) on Linux x64: [Fails with rmdir error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125174/job/29348045745)
  ```text
  Copying '/home/luppy/.gitconfig' to '/home/luppy/actions-runner/_work/_temp/8c370e2f-3f8f-4e01-b8f2-1ccb301640a1/.gitconfig'
  Temporarily overriding HOME='/home/luppy/actions-runner/_work/_temp/8c370e2f-3f8f-4e01-b8f2-1ccb301640a1' before making global git config changes
  Adding repository directory to the temporary git global config as a safe directory
  /usr/bin/git config --global --add safe.directory /home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx
  Deleting the contents of '/home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx'
  Error: File was unable to be removed Error: EACCES: permission denied, rmdir '/home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx/buildartifacts/at32f437-mini'
  ```
  __TODO:__ Check the rmdir directory

# Appendix: Ubuntu x64 Runner In Action

Let's watch the Ubuntu x64 Runner in action...

- On an Intel PC

- On macOS Arm64 with UTM Emulator

## Intel PC with Ubuntu x64

Our 10-year-old MacBook Pro (Intel i7) hits 100% when running the Linux Build for NuttX CI. But it works!

- [__Build for arm-02__](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349060343)

![linux-build](https://github.com/user-attachments/assets/2e2861bc-6af0-48f4-b3a1-d0083cd23155)

## macOS Arm64 with UTM Emulator

On a super-duper Mac Mini (M2 Pro, 32 GB RAM): We can emulate an Intel i7 PC with __32 CPUs and 4 GB RAM__ (because we don't need much RAM)

![Screenshot 2024-08-29 at 10 08 07 PM](https://github.com/user-attachments/assets/5ff0d94e-4a04-4cf4-8f0a-8e0ee9d1cd59)

Remember to __Force Multicore__ and bump up the __JIT Cache__...

![Screenshot 2024-08-29 at 10 08 25 PM](https://github.com/user-attachments/assets/3a162236-9c14-4615-b9c7-c3a90ef7293c)

__Ubuntu Disk Space__ in the UTM Virtual Machine needs to be big enough for NuttX Docker Image...

```text
$ neofetch
            .-/+oossssoo+/-.               user@ubuntu-emu-arm64
        `:+ssssssssssssssssss+:`           ---------------------
      -+ssssssssssssssssssyyssss+-         OS: Ubuntu 24.04.1 LTS x86_64
    .ossssssssssssssssssdMMMNysssso.       Host: KVM/QEMU (Standard PC (Q35 + ICH9, 2009) pc-q35-7.2)
   /ssssssssssshdmmNNmmyNMMMMhssssss/      Kernel: 6.8.0-41-generic
  +ssssssssshmydMMMMMMMNddddyssssssss+     Uptime: 1 min
 /sssssssshNMMMyhhyyyyhmNMMMNhssssssss/    Packages: 1546 (dpkg), 10 (snap)
.ssssssssdMMMNhsssssssssshNMMMdssssssss.   Shell: bash 5.2.21
+sssshhhyNMMNyssssssssssssyNMMMysssssss+   Resolution: 1280x800
ossyNMMMNyMMhsssssssssssssshmmmhssssssso   Terminal: /dev/pts/1
ossyNMMMNyMMhsssssssssssssshmmmhssssssso   CPU: Intel i7 9xx (Nehalem i7, IBRS update) (16) @ 1.000GHz
+sssshhhyNMMNyssssssssssssyNMMMysssssss+   GPU: 00:02.0 Red Hat, Inc. Virtio 1.0 GPU
.ssssssssdMMMNhsssssssssshNMMMdssssssss.   Memory: 1153MiB / 3907MiB
 /sssssssshNMMMyhhyyyyhdNMMMNhssssssss/
  +sssssssssdmydMMMMMMMMddddyssssssss+
   /ssssssssssshdmNNNNmyNMMMMhssssss/
    .ossssssssssssssssssdMMMNysssso.
      -+sssssssssssssssssyyyssss+-
        `:+ssssssssssssssssss+:`
            .-/+oossssoo+/-.

$ df -H
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           410M  1.7M  409M   1% /run
/dev/sda2        67G   31G   33G  49% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M  8.2k  5.3M   1% /run/lock
efivarfs        263k   57k  201k  23% /sys/firmware/efi/efivars
/dev/sda1       1.2G  6.5M  1.2G   1% /boot/efi
tmpfs           410M  115k  410M   1% /run/user/1000
```

During `Download Source Artifact`: GitHub seems to be throttling the download (total 700 MB over 25 mins)

![Screenshot 2024-08-29 at 2 09 11 PM](https://github.com/user-attachments/assets/585bc261-bc39-4be4-8515-85894254aace)

During `Run Builds`: CPU hits 100%

![Screenshot 2024-08-29 at 4 56 06 PM](https://github.com/user-attachments/assets/60d4d3eb-d075-49c9-b3ac-bcfa74150668)

Note: Don't leave System Monitor running, it consumes quite a bit of CPU!

If the CI Job doesn't complete in __6 hours__: GitHub will cancel it! So we should give it as much CPU as possible.

Why emulate 32 CPUs? That's because we want to max out the macOS Arm64 CPU Utilisation. Here's our chance to watch Mac Mini run smokin' hot!

![Screenshot 2024-08-30 at 4 14 05 PM](https://github.com/user-attachments/assets/bfd51e51-1bee-49c2-88a3-01698d51d8a4)

![Screenshot 2024-08-30 at 4 14 20 PM](https://github.com/user-attachments/assets/a9dab4fd-a59f-4348-a3f7-397973797288)

![Screenshot 2024-08-29 at 10 43 39 PM](https://github.com/user-attachments/assets/0ea9f33e-1e6f-412a-8f56-6f40dee7f699)

Here's how it runs:

```text
$ cd actions-runner/
$ sudo rm -rf _work/runner-nuttx
$ df -H
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           410M  1.7M  408M   1% /run
/dev/sda2        67G   28G   35G  45% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M  8.2k  5.3M   1% /run/lock
efivarfs        263k  130k  128k  51% /sys/firmware/efi/efivars
/dev/sda1       1.2G  6.5M  1.2G   1% /boot/efi
tmpfs           410M  119k  410M   1% /run/user/1000

$ ./run.sh 
Connected to GitHub
Current runner version: '2.319.1'
2024-08-30 02:33:17Z: Listening for Jobs
2024-08-30 02:33:23Z: Running job: Linux (arm-04)
2024-08-30 06:47:38Z: Job Linux (arm-04) completed with result: Succeeded
2024-08-30 06:47:43Z: Running job: Linux (arm-01)
```

Here are the Runner Options:

```text
$ ./run.sh --help
Commands:
 ./config.sh         Configures the runner
 ./config.sh remove  Unconfigures the runner
 ./run.sh            Runs the runner interactively. Does not require any options.

Options:
 --help     Prints the help for each command
 --version  Prints the runner version
 --commit   Prints the runner commit
 --check    Check the runner's network connectivity with GitHub server

Config Options:
 --unattended           Disable interactive prompts for missing arguments. Defaults will be used for missing options
 --url string           Repository to add the runner to. Required if unattended
 --token string         Registration token. Required if unattended
 --name string          Name of the runner to configure (default ubuntu-emu-arm64)
 --runnergroup string   Name of the runner group to add this runner to (defaults to the default runner group)
 --labels string        Custom labels that will be added to the runner. This option is mandatory if --no-default-labels is used.
 --no-default-labels    Disables adding the default labels: 'self-hosted,Linux,X64'
 --local                Removes the runner config files from your local machine. Used as an option to the remove command
 --work string          Relative runner work directory (default _work)
 --replace              Replace any existing runner with the same name (default false)
 --pat                  GitHub personal access token with repo scope. Used for checking network connectivity when executing `./run.sh --check`
 --disableupdate        Disable self-hosted runner automatic update to the latest released version`
 --ephemeral            Configure the runner to only take one job and then let the service un-configure the runner after the job finishes (default false)

Examples:
 Check GitHub server network connectivity:
  ./run.sh --check --url <url> --pat <pat>
 Configure a runner non-interactively:
  ./config.sh --unattended --url <url> --token <token>
 Configure a runner non-interactively, replacing any existing runner with the same name:
  ./config.sh --unattended --url <url> --token <token> --replace [--name <name>]
 Configure a runner non-interactively with three extra labels:
  ./config.sh --unattended --url <url> --token <token> --labels L1,L2,L3
Runner listener exit with 0 return code, stop the service, no retry needed.
Exiting runner...
```
