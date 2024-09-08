# Self-Hosted Runners for Continuous Integration (Apache NuttX RTOS)

📝 _19 Sep 2024_

![TODO](https://lupyuen.github.io/images/ci-title.jpg)

TODO

Why are we doing this?

- In case we need to reduce [GitHub Hosting Costs](https://docs.google.com/spreadsheets/d/1gY0VrSJvouXwDIclspQCFoBcoHhNCbGicNoVJRhJ-h4/edit?gid=0#gid=0). Or if we need to run the NuttX CI privately.

- It's a great way to understand the Internals of NuttX CI!

- Why is NuttX CI so heavy? That's because for every PR, it compiles every single NuttX Build Config: Arm, RISC-V, Simulator. (Hosting charges won't be cheap)

TODO: We might need a quicker way to "fail fast" and prevent other CI Jobs from running? Which will reduce the number of Runners?

TODO: What if we could start earlier the CI Jobs that are impacted by the Modified Code in the PR? So if I modify something for Ox64 BL808 SBC, it should start the CI Job for `ox64:nsh`. If it fails, then don't bother with the rest of the Arm / RISC-V / Simulator jobs.

TODO: Suppose we need to throttle our GitHub Runners from 36 Runners down to 25 Runners (and cut costs). What would be the impact on NuttX CI Duration? Are there any tools for modeling the queueing duration? 

TODO: Pic of GitHub Actions > Workflows > Build

# Continuous Integration for NuttX

_Why do we need Continuous Integration?_

Suppose we [__Submit a Pull Request__](https://lupyuen.github.io/articles/pr) for NuttX. We need to be sure that our Modified Code won't break the Existing Builds in NuttX.

That's why our Pull Request will trigger the __Continuous Integration Workflow__, to recompile NuttX for __All Hardware Platforms__.

(__1,594 Builds__ across Arm, RISC-V, Xtensa, AVR, i486, Simulator and more!)

TODO: Isn't this a little excessive? But we don't know which platforms are impacted!

_What happens inside the Continuous Integration?_

Head over to the [__NuttX Repository__](TODO) and click [__GitHub Actions > Workflows > Build__](https://github.com/apache/nuttx/actions/workflows/build.yml)

TODO: Pic above

Click one of the jobs: https://github.com/apache/nuttx/actions/runs/10552464655

Click __Linux (arm-01) > Run Builds__: https://github.com/apache/nuttx/actions/runs/10552464655/job/29231352816

TODO: Pic

We'll see this __NuttX Build for Arm32__...

```text
 ====================================================================================
Configuration/Tool: pcduino-a10/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-08-26 02:30:55
------------------------------------------------------------------------------------
  Cleaning...
  Configuring...
  Disabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Enabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Building NuttX...
arm-none-eabi-ld: warning: /github/workspace/sources/nuttx/nuttx has a LOAD segment with RWX permissions
  Normalize pcduino-a10/nsh
====================================================================================
Configuration/Tool: beaglebone-black/lcd,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-08-26 02:31:40
------------------------------------------------------------------------------------
```

Followed by __More Builds for Arm32__...

```text
Configuration/Tool: beaglebone-black/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
Configuration/Tool: at32f437-mini/eth,CONFIG_ARM_TOOLCHAIN_GNU_EABI
Configuration/Tool: at32f437-mini/sdcard,CONFIG_ARM_TOOLCHAIN_GNU_EABI
Configuration/Tool: at32f437-mini/systemview,CONFIG_ARM_TOOLCHAIN_GNU_EABI
Configuration/Tool: at32f437-mini/rtc,CONFIG_ARM_TOOLCHAIN_GNU_EABI
...
```

Each __NuttX Build__ will be a...

- Regular [__NuttX Make__](TODO)

- Or a [__NuttX CMake__](TODO)

- Or a [__Python Test__](TODO)

_What about other NuttX Targets? Arm64, RISC-V, Xtensa, ..._

Every Pull Request will trigger __24 Jobs for Continuous Integration__, all executing concurrently...

- __Arm32 Targets:__ arm-01, arm-02, arm-03, ...

- __RISC-V Targets:__ riscv-01, ...

- __Xtensa Targets:__ xtensa-01, ...

- __Simulator Targets:__ sim-01, ...

- __Other Targets__ (Arm64, AVR, i486, ...)

- __macOS and Windows__ (msys2)

TODO: each with its own Runner, lasting 30-90 mins per job

TODO: On some days we're hitting a max of ??? Full-Time Runners. And [__they ain't cheap__](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions#per-minute-rates-for-standard-runners)!

TODO: Switch to Self-Hosted Runners

# One Thousand Build Targets


TODO: The 24 CI Jobs above will recompile 1,594 Build Targets from scratch. Here's the [complete list of Build Targets](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

TODO: Reduce to 15 concurrent

TODO: We could review the Build Targets above and decide which targets should be excluded? Or reprioritised to run earlier / later?

TODO: Or we could run all 1,594 builds only when the PR is Approved? So we can save on Build Times for the Submission / Resubmission of the PR? Thanks!

TODO: Fetch-Source then Download Source Artifact

TODO: Docker Pull

# Self-Hosted Runners

Let's experiment with __Self-Hosted Runners__ to cut costs. We run them on two computers...

- __Older PC__ on Ubuntu x64 (Intel i7)

- __Newer Mac Mini__ on macOS Arm64 (Apple Silicon M2 Pro)

- With plenty of __Internet Bandwidth__ (Downlink 650 Mbps, Uplink 560 Mbps)
- TODO: [Fibre To The Home](http://speedtestsg.speedtestcustom.com/result/ca95c5c0-64eb-11ef-982f-dfa9296e96b3)

TODO: Throttled by GitHub and Docker Hub

- [Follow these instructions](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners) to install Self-Hosted Runners for Linux x64 and macOS Arm64

- See below for the fixes for Linux x64 and macOS Arm64

- Security Concerns: How to be sure that Self-Hosted Runners will run only approved scripts and commands?
  (Right now I have disabled external users from triggering GitHub Actions on my repo)

- Shut down the runners when we're done with testing

Look for this code in the GitHub Actions Worklow: [.github/workflows/build.yml](https://github.com/lupyuen3/runner-nuttx/pull/1/files#diff-5c3fa597431eda03ac3339ae6bf7f05e1a50d6fc7333679ec38e21b337cb6721)

```yaml
## Linux Build runs on GitHub Runners
Linux:
  needs:   Fetch-Source
  runs-on: ubuntu-latest
```

Change `runs-on` to...

```yaml
  ## Linux Build now runs on Self-Hosted Runners (Linux x64)
  runs-on: [self-hosted, Linux, X64]
```

TODO

```bash
## Configure our Self-Hosted Runner for Linux x64
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
Running job: TODO
```

# Running the Runners

TODO

_Our Self-Hosted Runners: Do they work for NuttX CI Builds?_

Here's the result: https://github.com/lupyuen3/runner-nuttx/actions

And [it works yay](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349060343)! (2 hours on a 10-year-old MacBook Pro with Intel i7)

TODO: Pic of Ubuntu Runner

__Docker Hub__ will throttle our downloading of Docker Images. If it gets too slow, cancel the GitHub Workflow and restart. Throttling will magically disappear.

_Can we guesstimate the time to run a CI Build?_

Just browse the GitHub Actions Log for the CI Build. See the Line Numbers? Every NuttX CI Build will have roughly 1,000 lines of log (by sheer coincidence). We can use this to guess the CI Build Duration.

TODO: Podman Docker on Linux x64 [fails with this error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440489/job/29343575677). Might be a [problem with Podman](https://github.com/containers/podman/discussions/14238).

```text
Writing manifest to image destination
Error: statfs /var/run/docker.sock: permission denied
```

_What about macOS on Arm64?_

TODO: Most of the [Linux Builds](https://github.com/lupyuen3/runner-nuttx/actions/workflows/build.yml) won't work on macOS Arm64 because they need Docker on Linux x64 

We'll talk about Emulating x64 on macOS Arm64. But first we run Fetch Source on macOS...

# Fetch Source on macOS Arm64

_We haven't invoked the Runners for macOS Arm64?_

TODO: Fetch Source will work fine on Linux x64

TODO: [`Fetch-Source`](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29343582486) works OK on macOS Arm64

[.github/workflows/build.yml](https://github.com/lupyuen3/runner-nuttx/pull/1/files#diff-5c3fa597431eda03ac3339ae6bf7f05e1a50d6fc7333679ec38e21b337cb6721)

```yaml
## Fetch-Source runs on GitHub Runners
jobs:
  Fetch-Source:
    runs-on: ubuntu-latest
```

Change `runs-on` to...

```yaml
    ## Fetch-Source now runs on Self-Hosted Runners (macOS Arm64)
    runs-on: [self-hosted, macOS, ARM64]
```

# UTM Emulator for macOS Arm64

TODO

_So NuttX CI works better with a huge x64 Ubuntu PC. Can we make macOS on Arm64 more useful?_

- Now testing [UTM Emulator for macOS Arm64](https://mac.getutm.app/), to emulate Ubuntu x64 (because my MacBook Pro x64 is running too hot and slow). 

  Here's our Emulated Ubuntu x64 24.04.1 LTS with 4GB RAM: [Build for arm-01](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29503152279), [Build for arm-02](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29508376208), [Build for arm-03](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29428211466), [Build for arm-04](https://github.com/lupyuen3/runner-nuttx/actions/runs/10594022857/job/29456380032)

  Does it work? Yes! How many hours? 4 hours! (Instead of 33 mins when hosted at GitHub)

  TODO: Do we run multiple Virtual Machines in macOS UTM?

- Alternatively: Running a Self-Hosted Runner inside a Docker Container (Rancher Desktop) on macOS Arm64

  But Then: It becomes a Linux Arm64 Runner, not a Linux x64 Runner. Which won't work with our current NuttX CI Docker Image, which is x64 only.

  Unless: We create a Linux Arm64 Docker Image for NuttX CI? Like for [Compiling RISC-V Platforms](https://lupyuen.github.io/articles/pr#appendix-building-the-docker-image-for-nuttx-ci)?


# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci.md)

# Appendix: Fixes for Ubuntu x64

TODO

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

TODO: Docker Engine [fails with this error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29344966455):

```text
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.47/images/create?fromImage=ghcr.io%2Fapache%2Fnuttx%2Fapache-nuttx-ci-linux&tag=latest": dial unix /var/run/docker.sock: connect: permission denied
  ```

We apply [this Docker Fix](https://stackoverflow.com/questions/48957195/how-to-fix-docker-got-permission-denied-issue). 

# Appendix: Fixes for macOS Arm64

TODO

```bash
sudo mkdir /Users/runner
sudo chown $USER /Users/runner
sudo chgrp staff /Users/runner
ls -ld /Users/runner

## Maybe need pip?
brew install python
```

# Appendix: Documentation Build for NuttX

TODO

_Does it work for Documentation Build?_

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
  TODO: Switch to pipenv

- [`Documentation`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/doc.yml) on Linux x64: [Fails with rmdir error](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125174/job/29348045745)
  ```text
  Copying '/home/luppy/.gitconfig' to '/home/luppy/actions-runner/_work/_temp/8c370e2f-3f8f-4e01-b8f2-1ccb301640a1/.gitconfig'
  Temporarily overriding HOME='/home/luppy/actions-runner/_work/_temp/8c370e2f-3f8f-4e01-b8f2-1ccb301640a1' before making global git config changes
  Adding repository directory to the temporary git global config as a safe directory
  /usr/bin/git config --global --add safe.directory /home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx
  Deleting the contents of '/home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx'
  Error: File was unable to be removed Error: EACCES: permission denied, rmdir '/home/luppy/actions-runner/_work/runner-nuttx/runner-nuttx/buildartifacts/at32f437-mini'
  ```
  TODO: Check the rmdir directory

# Appendix: NuttX CI for macOS

TODO

- [`Build macOS (macos / sim-01 / sim-02)`](https://github.com/lupyuen3/runner-nuttx/actions/workflows/build.yml) on macOS Arm64: `setup-python` will [hang because it's prompting for password](https://github.com/lupyuen3/runner-nuttx/actions/runs/10589440434/job/29343630883). So we comment out `setup-python`.

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
  Then it fails while [downloading the toolchain](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349061179)
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
  TODO: Do we change the toolchain from x64 to Arm64?

# Appendix: Ubuntu x64 Runner In Action

TODO

## Intel PC with Ubuntu x64

TODO

Our 10-year-old MacBook Pro (Intel i7) hits 100% when running the Linux Build for NuttX CI: [Build for arm-02](https://github.com/lupyuen3/runner-nuttx/actions/runs/10591125185/job/29349060343)

![linux-build](https://github.com/user-attachments/assets/2e2861bc-6af0-48f4-b3a1-d0083cd23155)

## macOS Arm64 with UTM Emulator

TODO

On a powerful Mac Mini (M2 Pro, 32 GB RAM): We can emulate an Intel i7 PC with 32 CPUs and 4 GB RAM (we don't need much RAM)

![Screenshot 2024-08-29 at 10 08 07 PM](https://github.com/user-attachments/assets/5ff0d94e-4a04-4cf4-8f0a-8e0ee9d1cd59)

![Screenshot 2024-08-29 at 10 08 25 PM](https://github.com/user-attachments/assets/3a162236-9c14-4615-b9c7-c3a90ef7293c)

Ubuntu Disk Space in UTM VM needs to be big enough for NuttX Docker Image:

```text
user@ubuntu-emu-arm64:~$ neofetch
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

user@ubuntu-emu-arm64:~$ df -H
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

Why emulate 32 CPUs? That's because we want to max out the macOS Arm64 CPU Utilisation. Here's our chance to watch Mac Mini run smokin' hot!

![Screenshot 2024-08-30 at 4 14 05 PM](https://github.com/user-attachments/assets/bfd51e51-1bee-49c2-88a3-01698d51d8a4)

![Screenshot 2024-08-30 at 4 14 20 PM](https://github.com/user-attachments/assets/a9dab4fd-a59f-4348-a3f7-397973797288)

![Screenshot 2024-08-29 at 10 43 39 PM](https://github.com/user-attachments/assets/0ea9f33e-1e6f-412a-8f56-6f40dee7f699)

Here's how it runs:

```text
user@ubuntu-emu-arm64:~$ cd actions-runner/
user@ubuntu-emu-arm64:~/actions-runner$ sudo rm -rf _work/runner-nuttx
[sudo] password for user: 
user@ubuntu-emu-arm64:~/actions-runner$ df -H
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           410M  1.7M  408M   1% /run
/dev/sda2        67G   28G   35G  45% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M  8.2k  5.3M   1% /run/lock
efivarfs        263k  130k  128k  51% /sys/firmware/efi/efivars
/dev/sda1       1.2G  6.5M  1.2G   1% /boot/efi
tmpfs           410M  119k  410M   1% /run/user/1000
user@ubuntu-emu-arm64:~/actions-runner$ ./run.sh 

\u221a Connected to GitHub
Current runner version: '2.319.1'
2024-08-30 02:33:17Z: Listening for Jobs
2024-08-30 02:33:23Z: Running job: Linux (arm-04)
2024-08-30 06:47:38Z: Job Linux (arm-04) completed with result: Succeeded
2024-08-30 06:47:43Z: Running job: Linux (arm-01)
```

Runner Options:

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
