# Optimising the Continuous Integration for Apache NuttX RTOS

📝 _23 Nov 2024_

![TODO](https://lupyuen.github.io/images/ci3-title.jpg)

TODO: Continuous Integration (CI)

Dev build time dropped from ??? to ???

GitHub Usage dropped from ??? to ???

```bash
cp "$HOME/Desktop/Screenshot 2024-10-17 at 5.01.11 PM.png" ~/Desktop/before-30days.png
```

TODO: Pic of last 7 days

# Rescue Plan

We had [__an ultimatum__](https://lists.apache.org/thread/2yzv1fdf9y6pdkg11j9b4b93grb2bn0q) to reduce (drastically) our usage of GitHub Actions. Or our Continuous Integration would __Halt Totally in Two Weeks__!

After an [__overnight deliberation__](TODO), we swiftly activated [__our rescue plan__](TODO)...

1.  When we submit or update a __Complex PR__ that affects __All Architectures__ (Arm, RISC-V, Xtensa, etc)...

    CI Workflow shall run only __Half the Jobs__ for CI Checks.

    (Will reduce GitHub Cost by 32%)

1.  When the __Complex PR is Merged:__ CI Workflow will still run all jobs `arm-01` to `arm-14`

    (Simple PRs with One Single Arch / Board will build the same way as before. Thus Arm32 PRs shall build only `arm-01` to `arm-14`)

1.  When we __Merge a PR:__ our [__Merge Jobs will run at NuttX/nuttx__](https://github.com/NuttX/nuttx/actions/workflows/build.yml) repo. (Instead of _apache/nuttx_ repo)

    We shall have only __Two Scheduled Merge Jobs__ per day: 00:00 UTC and 12:00 UTC.

1.  How? I shall quickly [__Cancel any Merge Jobs__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) that appear in `nuttx` and `nuttx-apps` repos.

    Then at 00:00 UTC and 12:00 UTC: I shall start the Latest Merge Job at `NuttX/nuttx` repo.

    (Eventually we disabled the [__Merge Jobs for NuttX Repo__](https://github.com/apache/nuttx/pull/14618). Also for [__NuttX Apps__](https://github.com/apache/nuttx-apps/pull/2817))

1.  __macOS and Windows Jobs__ (msys2 / msvc): They shall be totally disabled until we find a way to manage their costs.

    (GitHub charges [__10x Premium for macOS Runners__](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers), 2x Premium for Windows Runners!)

We have reasons for doing these, backed by real data...

# Present Pains

We studied the CI Jobs for the previous day...

- [__Analysis of CI Jobs over 24 Hours__](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=0#gid=0)

Many CI Jobs were __Incomplete__: We wasted GitHub Runners on jobs that were eventually __superseded and cancelled__...

![Screenshot 2024-10-17 at 1 18 14 PM](https://github.com/user-attachments/assets/953e2ac7-aee5-45c6-986c-3bcdd97d0b5e)

When we __Halve the CI Jobs:__ We reduce the wastage of GitHub Runners...

![Screenshot 2024-10-17 at 1 15 30 PM](https://github.com/user-attachments/assets/bda5c8c3-862a-41b6-bab3-20352ba9976a)

__Scheduled Merge Jobs__ will also reduce wastage of GitHub Runners, since most Merge Jobs didn't complete. Only One Merge Job completed on that day...

![Screenshot 2024-10-17 at 1 16 16 PM](https://github.com/user-attachments/assets/1452067f-a151-4641-8d1e-3c84c0f45796)

All these fixes were super helpful for complying with the [__ASF Policy for GitHub Actions__](https://infra.apache.org/github-actions-policy.html)!

# Disable macOS and Windows Builds

_Quitting the macOS Builds? That's horribly drastic!_

Yeah sorry we can't enable __macOS Builds__ in NuttX Repo right now...

- macOS Runners [__cost 10 times__](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers) as much as Linux Runners.

  To enable One macOS Job: We need to disable 10 Linux Jobs! Which is not feasible.

- Our macOS Jobs are in an __untidy state__ right now, showing too many warnings.

  We need someone familiar with Intel Macs to clean up the macOS Jobs.

  (See this [__macOS Log__](https://github.com/NuttX/nuttx/actions/runs/11630100298/job/32388421934) and [__Another Log__](https://github.com/NuttX/nuttx/actions/runs/11630100298/job/32388422211))

- That's why we moved the macOS Builds to the __NuttX Mirror Repo__, which won't be charged to NuttX Project.

  [(Discussion here)](https://github.com/apache/nuttx/issues/14598)

_But can we still prevent breakage of ALL Builds? Linux / macOS / msvc / msys2?_

Nope this is __simply impossible__...

- In the good old days: We were using __far too many__ GitHub Runners.

  This is not sustainable, we don't have the budget to run all the CI Checks we used to.

- Hence we should expect __some breakage__.

  We should be prepared to backtrack and figure out which PR broke the build.

- That's why we have tools like the [__NuttX Dashboard__](https://github.com/apache/nuttx/issues/14558), to detect breakage earlier.

  (Without depending on GitHub CI)

- Also we should show some __love and respect__ for NuttX Devs!

  Previously we waited [__2.5 hours__](TODO) for All CI Checks. Now we wait at most [__1.5 hours__](https://github.com/apache/nuttx/actions/runs/11582139779), let's stick to this.

  [(We re-enabled the __Windows Jobs__)](https://github.com/apache/nuttx/issues/14598)

  [(Seeking help to port NuttX Jobs to __M1 Mac__)](https://github.com/apache/nuttx/issues/14526)

# Move the Merge Jobs

_What are Merge Jobs? Why move them?_

Suppose our NuttX Admin __Merges a PR__.

Normally our CI Workflow will trigger a __Merge Job__, to verify that everything compiles OK after Merging the PR.

Which means running [__34 Build Sub-Jobs__](TODO) (2.5 elapsed hours) across all architectures: Arm32, Arm64, RISC-V, Xtensa, macOS, Windows, ...

This is extremely costly, so we decided to run them as __Scheduled Merge Jobs__. I trigger them __Twice Daily__: 00:00 UTC and 12:00 UTC.

![Screenshot 2024-10-19 at 11 33 46 AM](https://github.com/user-attachments/assets/617cc2fe-38ac-474f-8cd8-141d19d5b1f0)

_Is there a problem?_

We spent __One-Third__ of our GitHub Runner Minutes on Scheduled Merge Jobs! (Pic above)

[__Our CI Data__](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=650325940#gid=650325940) shows that the Scheduled Merge Job keeps getting disrupted by Newer Merged PRs.

And when we restart a Scheduled Merge Job, we waste precious GitHub Minutes.

(__101 GitHub Hours__ for one single Scheduled Merge Job!)

_Thus we moved them?_

Yep this is clearly not sustainable. So we moved the Scheduled Merge Jobs to a new [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx/actions/workflows/build.yml).

Where the Merge Jobs can run free __without disruption__!

(In an Unpaid GitHub Org Account that won't be charged to NuttX Project)

_What about the Old Merge Jobs?_

Initially I ran a script that will quickly [__Cancel any Merge Jobs__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) that appear in `nuttx` and `nuttx-apps` repos.

Eventually we disabled the [__Merge Jobs for NuttX Repo__](https://github.com/apache/nuttx/pull/14618). 

(Also for [__NuttX Apps__](https://github.com/apache/nuttx-apps/pull/2817))

_How to trigger the Scheduled Merge Job?_

Every Day at __00:00 UTC__ and __12:00 UTC__: I do this...

1.  Browse to the [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx)

1.  Click "__Sync Fork > Discard Commits__"

1.  Which will __Sync our Mirror Repo__ with the Upstream NuttX Repo

1.  Run this script to enable the __macOS Builds__: [enable-macos-windows.sh](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows.sh)

1.  Which will also [__Disable Fail-Fast__](TODO) so that it runs all builds. (Regardless of error)

1.  And [__Remove Max Parallel__](TODO) so that it will use unlimited concurrent runners. (Because it's free!)

1.  If the Merge Job fails with a [__Mystifying Network Error__](TODO): I restart the Failed Sub-Jobs

1.  Wait for the Merge Job to complete. Then [__Ingest the GitHub Logs__](https://github.com/lupyuen/ingest-nuttx-builds) into our [__NuttX Dashboard__](https://github.com/apache/nuttx/issues/14558). (Next article)

_Isn't this cheating? Offloading to a Free GitHub Account?_

Yeah that's why we need a [__NuttX Build Farm__](TODO). (Details below)

![Halve the CI Checks for a Complex PR](https://lupyuen.github.io/images/ci3-checks.png)

# Halve the CI Checks

_One-Thirds of our GitHub Runner Minutes were spent on Merge Jobs. What about the rest?_

[__Two-Thirds__](TODO) of our GitHub Runner Minutes were spent on Submitting and Updating PRs.

That's why we decided to skip __Half the CI Checks__ for Complex PRs.

(A __Complex PR__ affects __All Architectures__: Arm, RISC-V, Xtensa, etc)

_Which CI Checks did we select?_

Today we run these __CI Checks__ when submitting or updating a Complex PR (pic above)...

TODO: CI Checks

TODO: [(See the __Pull Request__)](TODO)

TODO: [(Also synced to __NuttX Apps__)](TODO)

TODO: Halve the Jobs for [__RISC-V, Xtensa and Simulator__](https://github.com/apache/nuttx/pull/14400) for Complex PRs
  
TODO: Do the same for [`nuttx-apps` repo](https://github.com/apache/nuttx-apps/pull/2758)  

TODO: Build Rules

TODO: Why were these jobs chosen?

TODO: Rotate?

TODO: Simple PR

# Live Metric for Full-Time Runners

_Hitting the Target Metrics in 2 weeks... Everyone needs to help out right?_

Our quota is __25 Full-Time GitHub Runners__ per day.

We published our own __Live Metric for Full-Time Runners__, for everyone to track...

![Live Metric for Full-Time Runners](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png)

- __Date:__ We compute the Full-Time Runners only for Today's Date (UTC)

- __Elapsed Hours:__ Number of hours elapsed since 00:00 UTC

- __GitHub Job Hours:__ Elapsed Duration of all `nuttx` and `nuttx-apps` GitHub Jobs. (Cancelled / Completed / Failed)

  This data is available only AFTER the job has been Cancelled / Completed / Failed. (Might have lagged by 1.5 hours)
  
  But this is the _Elapsed Job Duration_. It doesn't say that we're running 8 Sub-Jobs in parallel. That's why we need...

- __GitHub Runner Hours:__ Number of GitHub Runners * Job Duration. Effectively the _Chargeable Minutes_ by GitHub.

  We compute this as 8 * GitHub Job Hours. This is [__averaged from past data__](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=1163309346#gid=1163309346).
  
  (Remember: One GitHub Runner will run One Single Sub-Job, like _arm-01_)

- __Full-Time GitHub Runners:__ Equals GitHub Runner Hours / Elapsed Hours.

  It means _"How many GitHub Runners, running Full-Time, in order to consume the GitHub Runner Hours"_.
  
  (We should keep this below 25 per day, per week, per month)

We publish the data every __15 minutes__...

1.  [__compute-github-runners.sh__](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners.sh) calls GitHub API to add up the __Elapsed Duration__ of All Completed GitHub Jobs for today.

    Then it extrapolates the Number of __Full-Time GitHub Runners__.
  
    (1 GitHub Job Hour roughly equals 8 GitHub Runner Hours, which equals 8 Full-Time Runners Per Hour)

1.  [__run.sh__](https://github.com/lupyuen/nuttx-metrics/blob/main/run.sh) calls the script above and render the Full-Time GitHub Runners as a PNG.

    (Thanks to ImageMagick)

1.  [__compute-github-runners2.sh__](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners2.sh): Is the Linux Version of the above macOS Script.

    (But less accurate, due to BC Rounding)

Next comes the Watchmen...

![PXL_20241020_114213194](https://github.com/user-attachments/assets/e25badb4-112b-4392-8605-7427aee47b89)

# Monitor our CI Servers 24 x 7

_Doesn't sound right that an Unpaid Volunteer is monitoring our CI Servers 24 x 7 ... But someone's gotta do it!_ 👍

This runs on a 4K TV (Xiaomi 65-inch) all day, all night...

![Screenshot 2024-10-28 at 1 53 26 PM](https://github.com/user-attachments/assets/3f862ed6-8890-4d00-99e1-f5b8352ddcd1)

When I'm out on [__Overnight Hikes__](https://www.strava.com/activities/12737067287): I check my phone at every water break...

![GridArt_20241028_150938083](https://github.com/user-attachments/assets/88232734-aecc-4af8-bc0e-641db1cfdf9e)

_If something goes wrong?_

I have GitHub Scripts that will run on __Termux Android__. Remember to `pkg install gh` and set `GITHUB_TOKEN`...

- [__enable-macos-windows2.sh__](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows2.sh): Enable the macOS Builds in the NuttX Mirror Repo

- [__compute-github-runners2.sh__](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners2.sh): Compute the number of Full-Time GitHub Runners for the day (less accurately than macOS version)

- [__kill-push-master.sh__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh): Cancel all Merge Jobs in NuttX Repo and NuttX Apps

# Final Verdict

TODO

Past 7 Days: We consumed __12 Full-Time Runners__, which is half the ASF Quota of 25 Full-Time Runners yay!

![Screenshot 2024-10-30 at 6 06 21 AM](https://github.com/user-attachments/assets/baa0734e-3875-4b58-bd51-9cb69f264f26)

FYI: Our "Monthly Bill" for GitHub Actions used to be __$18K__...

![before-30days](https://github.com/user-attachments/assets/f05c8da2-4930-4b0e-ba4d-a4c1f1ffae36)

Right now our __Monthly Bill is $14K__. And still dropping!

![after-30days](https://github.com/user-attachments/assets/db9def46-e386-43a2-9e10-79475e34547b)

Let's wait for the good news from ASF, thank you everyone! 🙏

![](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png)

[(Live Image)](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png) [(Live Log)](https://github.com/lupyuen/nuttx-metrics/blob/main/compute-github-runners.log)

# TODO

TODO

[NuttX Dashboard for Build Farm](https://github.com/apache/nuttx/issues/14558)

[Running CI Checks before submitting PR](https://github.com/apache/nuttx/issues/14601#issuecomment-2452875114)

[Verify a PR after merging](https://github.com/apache/nuttx/issues/14407)

sync CI Workflow from nuttx to nuttx apps

????script to start jobs

nuttx website docs: [nuttx-website main.yml](https://github.com/apache/nuttx-website/blob/master/.github/workflows/main.yml)
30 github minutes

- Excellent Initiative by @raiden00pl: We [__Merge Multiple Targets__](https://github.com/apache/nuttx/pull/14410) into One Target, and reduce the build time

# Our Wishlist

It's past Diwali and Halloween... Our CI Servers are still running. __We made it yay!__ 🎉

We got plenty to do...

- Become more resilient and self-sufficient with [__Our Own Build Farm__](https://lupyuen.codeberg.page/articles/ci2.html)

  (Away from GitHub)

- Analyse our Build Logs with [__Our Own Tools__](https://github.com/apache/nuttx/issues/14558) 

  (Instead of GitHub)

Thank you everyone for making this happen! 🙏

[(Please join __Your Ubuntu PC__ to our Build Farm)](TODO)

_But our Merge Jobs are still running in a Free Account?_

We learnt a Painful Lesson today: __Freebies Won't Last Forever!__

We should probably maintain an official __Paid GitHub Org Account__ to run our Merge Jobs...

1.  New GitHub Org shall be sponsored by our generous __Stakeholder Companies__

    (Espressif, Sony, Xiaomi, ...)

1.  New GitHub Org shall be maintained by a __Paid Employee__ of our Stakeholder Companies

    (Instead of an Unpaid Volunteer)

1.  Which means clicking Twice Per Day to trigger the [__Scheduled Merge Jobs__](TODO)

    (My fingers are getting tired)

1.  And __Restarting the Merge Jobs__ 

    [(Which might fail due to __Mysterious Network Errors__)](TODO)

1.  New GitHub Org shall host the Official Downloads of __NuttX Compiled Binaries__

    (For our upcoming __Board Testing Farm__)

1.  New GitHub Org will eventually __Offload CI Checks__ from our NuttX Repos

    (Maybe macOS CI Checks for New PRs)

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

[__lupyuen.github.io/src/ci3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci3.md)

# Appendix: Merge Jobs are Costly

TODO

Hi All: Our [__Merge Jobs are now at github.com/NuttX/nuttx__](https://github.com/NuttX/nuttx/actions/workflows/build.yml)

Yesterday we spent __One-Third__ of our GitHub Runner Minutes on Merge Jobs. This is not sustainable, so I moved them to `nuttxpr` repo. (Which won't be charged)

![Screenshot 2024-10-19 at 11 33 46 AM](https://github.com/user-attachments/assets/617cc2fe-38ac-474f-8cd8-141d19d5b1f0)

[The data from yesterday](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=650325940#gid=650325940) shows that our Scheduled Merge Job keeps getting disrupted by newer Merged PRs. And when we restart a Scheduled Merge Job, we waste GitHub Minutes. (__101 GitHub Hours__ for one single Scheduled Merge Job!)

__Two-Thirds__ of our GitHub Runner Minutes were spent on Creating and Updating PRs. That's why we're skipping half the jobs today.

# Appendix: Verify our PR Merge

TODO

_When NuttX merges our PR, the Merge Job won't run until 00:00 UTC and 12:00 UTC. How can we be really sure that our PR was merged correctly?_

Let's create a __GitHub Org__ (at no cost), fork the NuttX Repo and trigger the __CI Workflow__. (Which won't charge any extra GitHub Runner Minutes to NuttX Project!)

["How to Verify a PR Merge"](https://github.com/apache/nuttx/issues/14407)

(I think this might also work if ASF shuts down our CI Servers. We can create many many orgs actually)

# Appendix: Timeout Errors

TODO

Something That Bugs Me: __Timeout Errors__ will cost us precious GitHub Minutes. The remaining jobs get killed, and restarting these remaining jobs from scratch will consume extra GitHub Minutes. (The restart below costs us 6 extra GitHub Runner Hours)

(1) How do we retry these Timeout Errors?

(2) Can we have Restartable Builds? Doesn't quite make sense to build everything from scratch (arm6, arm7, riscv7) just because one job failed (xtensa2)

(3) Or xtensa2 should wait for others to finish, before it declares a timeout and dies? Hmmm...

```text
Configuration/Tool: esp32s2-kaluga-1/lvgl_st7789
curl: (28) Failed to connect to github.com port 443 after 133994 ms: Connection timed out
```
[(See the __Complete Log__)](https://github.com/apache/nuttx/actions/runs/11395811301/attempts/1)

Something strange about __Network Timeouts__ in our Docker Workflows: First Run fails while [downloading something from GitHub](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111488205#step:7:626):
```text
Configuration/Tool: imxrt1050-evk/libcxxtest,CONFIG_ARM_TOOLCHAIN_GNU_EABI
curl: (28) Failed to connect to github.com port 443 after 134188 ms: Connection timed out
make[1]: *** [libcxx.defs:28: libcxx-17.0.6.src.tar.xz] Error 28
```

Second Run fails again, while [downloading NimBLE from GitHub](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32112716849#step:7:536):
```text
Configuration/Tool: nucleo-wb55rg/nimble,CONFIG_ARM_TOOLCHAIN_GNU_EABI
curl: (28) Failed to connect to github.com port [443](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32112716849#step:7:444) after 134619 ms: Connection timed out
make[2]: *** [Makefile:55: /github/workspace/sources/apps/wireless/bluetooth/nimble_context] Error 2
```

[Third Run succeeds.](https://github.com/nuttxpr/nuttx/actions/runs/11535899222) Why do we keep seeing these errors: GitHub Actions with Docker, can't connect to GitHub itself?

Is something misconfigured in our Docker Image? But the exact same Docker Image runs fine on [my own Build Farm](https://lupyuen.codeberg.page/articles/ci2.html). It [doesn't show any errors](https://lupyuen.codeberg.page/articles/ci2.html).

Is GitHub Actions starting our Docker Container with the wrong MTU (Network Packet Size)? 🤔
- [GitHub Actions with Smaller MTU Size](https://github.com/actions/actions-runner-controller/issues/393)
- [Docker MTU issues and solutions](https://mlohr.com/docker-mtu/)

Meanwhile I'm running a script to Restart Failed Jobs on our NuttX Mirror Repos: [restart-failed-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/restart-failed-job.sh)

# Appendix: Build Rules for CI Workflow

TODO

[Enhance the CI Workflow to skip the Unmodified Architectures](https://github.com/apache/nuttx/issues/13775)

- NuttX Devs need to wait (2 hours) for the CI Build to complete across all Architectures (Arm32, Arm64, RISC-V, Xtensa), even though they're modifying a Single Architecture

- We're using too many GitHub Runners and Build Minutes, exceeding the [ASF Policy for GitHub Actions](https://infra.apache.org/github-actions-policy.html)

- Our usage of GitHub Runners is going up ($12K per month), we need to stay within the [ASF Budget for GitHub Runners](https://infra.apache.org/github-actions-policy.html) ($8.2K per month)

- What if CI could build only the Modified Architecture?

- Right now most of our CI Builds are taking 2 hours 15 mins. Can we complete the build within 1 hour, when we Create / Modify a Simple PR?

## Overall Solution

- We propose a Partial Solution, based on the Arch and Board Labels (recently added to CI)

- We target only the Simple PRs: One Arch Label + One Board Label + One Size Label, like "Arch: risc-v, Board: risc-v, Size: XS"

- If "Arch: arm" is the only non-size label, then we build only `arm-01`, `arm-02`, ...

- Same for "Board: arm"

- If Arch and Board Labels are both present: They must be the same

- Similar rules for RISC-V, Simulator, x86_64 and Xtensa

- Simple PR + Docs is still considered a Simple PR (so devs won't be penalised for adding docs)

## Fetch the Arch Labels

This is how we fetch the Arch Labels, and identify as Arm, Arm64, RISC-V, Xtensa: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L32-L104)

```yaml
# Get the Arch for the PR: arm, arm64, risc-v, xtensa, ...
- name: Get arch
  id: get-arch
  run: |        

    # If PR is Not Created or Modified: Build all targets
    pr=${{github.event.pull_request.number}}
    if [[ "$pr" == "" ]]; then
      echo "Not a Created or Modified PR, will build all targets"
      exit
    fi

    # Ignore the Label "Area: Documentation", because it won't affect the Build Targets
    query='.labels | map(select(.name != "Area: Documentation")) | '
    select_name='.[].name'
    select_length='length'

    # Get the Labels for the PR: "Arch: risc-v \n Board: risc-v \n Size: XS"
    # If GitHub CLI Fails: Build all targets
    labels=$(gh pr view $pr --repo $GITHUB_REPOSITORY --json labels --jq $query$select_name || echo "")
    numlabels=$(gh pr view $pr --repo $GITHUB_REPOSITORY --json labels --jq $query$select_length || echo "")
    echo "numlabels=$numlabels" | tee -a $GITHUB_OUTPUT

    # Identify the Size, Arch and Board Labels
    if [[ "$labels" == *"Size: "* ]]; then
      echo 'labels_contain_size=1' | tee -a $GITHUB_OUTPUT
    fi
    if [[ "$labels" == *"Arch: "* ]]; then
      echo 'labels_contain_arch=1' | tee -a $GITHUB_OUTPUT
    fi
    if [[ "$labels" == *"Board: "* ]]; then
      echo 'labels_contain_board=1' | tee -a $GITHUB_OUTPUT
    fi

    # Get the Arch Label
    if [[ "$labels" == *"Arch: arm64"* ]]; then
      echo 'arch_contains_arm64=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Arch: arm"* ]]; then
      echo 'arch_contains_arm=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Arch: risc-v"* ]]; then
      echo 'arch_contains_riscv=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Arch: simulator"* ]]; then
      echo 'arch_contains_sim=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Arch: x86_64"* ]]; then
      echo 'arch_contains_x86_64=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Arch: xtensa"* ]]; then
      echo 'arch_contains_xtensa=1' | tee -a $GITHUB_OUTPUT
    fi

    # Get the Board Label
    if [[ "$labels" == *"Board: arm64"* ]]; then
      echo 'board_contains_arm64=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Board: arm"* ]]; then
      echo 'board_contains_arm=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Board: risc-v"* ]]; then
      echo 'board_contains_riscv=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Board: simulator"* ]]; then
      echo 'board_contains_sim=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Board: x86_64"* ]]; then
      echo 'board_contains_x86_64=1' | tee -a $GITHUB_OUTPUT
    elif [[ "$labels" == *"Board: xtensa"* ]]; then
      echo 'board_contains_xtensa=1' | tee -a $GITHUB_OUTPUT
    fi

  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Why ` || echo ""`? That's because if the GitHub CLI `gh` fails for any reason, we will build all targets. This ensures that our CI Workflow won't get disrupted due to errors in GitHub CLI.

## Handle Only Simple PRs

We handle only Simple PRs: One Arch Label + One Board Label + One Size Label, like "Arch: risc-v, Board: risc-v, Size: XS". If it's not a Simple PR: We build everything.

[arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L127-L169)

```yaml
# inputs.boards is a JSON Array: ["arm-01", "risc-v-01", "xtensa-01", ...]
# We compact and remove the newlines
boards=$( echo '${{ inputs.boards }}' | jq --compact-output ".")
numboards=$( echo "$boards" | jq "length" )

# We consider only Simple PRs with:
# Arch + Size Labels Only
# Board + Size Labels Only
# Arch + Board + Size Labels Only
if [[ "$labels_contain_size" != "1" ]]; then
  echo "Size Label Missing, will build all targets"
  quit=1
elif [[ "$numlabels" == "2" && "$labels_contain_arch" == "1" ]]; then
  echo "Arch + Size Labels Only"
elif [[ "$numlabels" == "2" && "$labels_contain_board" == "1" ]]; then
  echo "Board + Size Labels Only"
elif [[ "$numlabels" == "3" && "$labels_contain_arch" == "1"  && "$labels_contain_board" == "1" ]]; then
  # Arch and Board must be the same
  if [[
    "$arch_contains_arm" != "$board_contains_arm" ||
    "$arch_contains_arm64" != "$board_contains_arm64" ||
    "$arch_contains_riscv" != "$board_contains_riscv" ||
    "$arch_contains_sim" != "$board_contains_sim" ||
    "$arch_contains_x86_64" != "$board_contains_x86_64" ||
    "$arch_contains_xtensa" != "$board_contains_xtensa"
  ]]; then
    echo "Arch and Board are not the same, will build all targets"
    quit=1
  else
    echo "Arch + Board + Size Labels Only"
  fi
else
  echo "Not a Simple PR, will build all targets"
  quit=1
fi

# If Not a Simple PR: Build all targets
if [[ "$quit" == "1" ]]; then
  echo "selected_builds=$boards" | tee -a $GITHUB_OUTPUT
  exit
fi
```

## For Arm Arch: Identify the Non-Arm Builds

Suppose the PR says "Arch: arm" or "Board: arm". We filter out the builds that should be skipped (RISC-V, Xtensa, etc):

[arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L169-L234)

```yaml
# For every board
for (( i=0; i<numboards; i++ ))
do
  # Fetch the board
  board=$( echo "$boards" | jq ".[$i]" )
  skip_build=0
  
  # For "Arch / Board: arm": Build arm-01, arm-02, ...
  if [[ "$arch_contains_arm" == "1" || "$board_contains_arm" == "1" ]]; then
    if [[ "$board" != *"arm"* ]]; then
      skip_build=1
    fi
  # Omitted: Arm64, RISC-V, Simulator x86_64, Xtensa
  ...
  # For Other Arch: Allow the build
  else
    echo Build by default: $board
  fi

  # Add the board to the selected builds
  if [[ "$skip_build" == "0" ]]; then
    echo Add $board to selected_builds
    if [[ "$selected_builds" == "" ]]; then
      selected_builds=$board
    else
      selected_builds=$selected_builds,$board
    fi
  fi
done

# Return the selected builds as JSON Array
# If Selected Builds is empty: Skip all builds
echo "selected_builds=[$selected_builds]" | tee -a $GITHUB_OUTPUT
if [[ "$selected_builds" == "" ]]; then
  echo "skip_all_builds=1" | tee -a $GITHUB_OUTPUT
fi
```

## Skip The Non-Arm Builds

Earlier we saw the code in `arch.yml` [(Reusable Workflow)](https://docs.github.com/en/actions/sharing-automations/reusing-workflows) that identifies the builds to be skipped. The code above is called by `build.yml` (Build Workflow) which will actually skip the builds:

[build.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L119-L148)

```yaml
# Select the Linux Builds based on PR Arch Label
Linux-Arch:
uses: apache/nuttx/.github/workflows/arch.yml@master
needs: Fetch-Source
with:
  os: Linux
  boards: |
    [
      "arm-01", "other", "risc-v-01", "sim-01", "xtensa-01",
      "arm-02", "risc-v-02", "sim-02", "xtensa-02",
      "arm-03", "arm-04", "arm-05", "arm-06", "arm-07", "arm-08", "arm-09", "arm-10", "arm-11", "arm-12", "arm-13"
    ]

# Run the selected Linux Builds
Linux:
needs: Linux-Arch
if: ${{ needs.Linux-Arch.outputs.skip_all_builds != '1' }}
runs-on: ubuntu-latest
env:
  DOCKER_BUILDKIT: 1

strategy:
  max-parallel: 12
  matrix:
    boards: ${{ fromJSON(needs.Linux-Arch.outputs.selected_builds) }}

steps:
  ## Omitted: Run cibuild.sh on Linux
```

Why `needs: Fetch-Source`? That's because the PR Labeler runs concurrently in the background. When we add `Fetch-Source` as a Job Dependency, we give the PR Labeler sufficient time to run (1 min), before we read the PR Label in `arch.yml`.

## Same for RISC-V, Simulator, x86_64 and Xtensa Builds

We do the same for RISC-V, Simulator, x86_64 and Xtensa:

[arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L105-L129)

```yaml
# For "Arch / Board: arm64": Build other
elif [[ "$arch_contains_arm64" == "1" || "$board_contains_arm64" == "1" ]]; then
  if [[ "$board" != *"other"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: risc-v": Build risc-v-01, risc-v-02
elif [[ "$arch_contains_riscv" == "1" || "$board_contains_riscv" == "1" ]]; then
  if [[ "$board" != *"risc-v"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: simulator": Build sim-01, sim-02
elif [[ "$arch_contains_sim" == "1" || "$board_contains_sim" == "1" ]]; then
  if [[ "$board" != *"sim"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: x86_64": Build other
elif [[ "$arch_contains_x86_64" == "1" || "$board_contains_x86_64" == "1" ]]; then
  if [[ "$board" != *"other"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: xtensa": Build xtensa-01, xtensa-02
elif [[ "$arch_contains_xtensa" == "1" || "$board_contains_xtensa" == "1" ]]; then
  if [[ "$board" != *"xtensa"* ]]; then
    skip_build=1
  fi
```

## Skip the macOS and Windows Builds

For these Simple PRs (One Arch Label + One Size Label), we skip the macOS and Windows builds (`macos`, `macos/sim-*`, `msys2`) since these builds are costly:

(`macos` and `macos/sim-*` builds will take 2 hours to complete due to the queueing for macOS Runners)

[build.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L194-L281)

```yaml
# Select the macOS Builds based on PR Arch Label
macOS-Arch:
  uses: apache/nuttx/.github/workflows/arch.yml@master
  needs: Fetch-Source
  with:
    os: Linux
    boards: |
      ["macos", "sim-01", "sim-02"]

# Run the selected macOS Builds
macOS:
  permissions:
    contents: none
  runs-on: macos-13
  needs: macOS-Arch
  if: ${{ needs.macOS-Arch.outputs.skip_all_builds != '1' }}
  strategy:
    max-parallel: 2
    matrix:
      boards: ${{ fromJSON(needs.macOS-Arch.outputs.selected_builds) }}
  steps:
    ## Omitted: Run cibuild.sh on macOS
    ...
# Select the msys2 Builds based on PR Arch Label
msys2-Arch:
  uses: apache/nuttx/.github/workflows/arch.yml@master
  needs: Fetch-Source
  with:
    os: Linux
    boards: |
      ["msys2"]

# Run the selected msys2 Builds
msys2:
  needs: msys2-Arch
  if: ${{ needs.msys2-Arch.outputs.skip_all_builds != '1' }}
  runs-on: windows-latest
  strategy:
    fail-fast: false
    max-parallel: 1
    matrix:
      boards: ${{ fromJSON(needs.msys2-Arch.outputs.selected_builds) }}

  defaults:
    run:
      shell: msys2 {0}
  steps:
    ## Omitted: Run cibuild.sh on msys2
```

`skip_all_builds` will be set to `1` for Simple PRs on macOS and msys2.

(Except for "Arch: Simulator", which will enable the macOS Builds for sim-01 and sim-02)

## Ignore the Documentation

NuttX Devs shouldn't be penalised for adding docs! That's why we ignore the label "Area: Documentation", so that Simple PR + Docs is still a Simple PR (which will skip the unnecessary builds).

[arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L44-L55)

```yaml
# Ignore the Label "Area: Documentation", because it won't affect the Build Targets
query='.labels | map(select(.name != "Area: Documentation")) | '
select_name='.[].name'
select_length='length'

# Get the Labels for the PR: "Arch: risc-v \n Board: risc-v \n Size: XS"
# If GitHub CLI Fails: Build all targets
labels=$(gh pr view $pr --repo $GITHUB_REPOSITORY --json labels --jq $query$select_name || echo "")
numlabels=$(gh pr view $pr --repo $GITHUB_REPOSITORY --json labels --jq $query$select_length || echo "")
echo "numlabels=$numlabels" | tee -a $GITHUB_OUTPUT
```

## Sync the CI Workflow from nuttx repo to nuttx-apps

Remember to sync `build.yml` and `arch.yml` from `nuttx` repo to `nuttx-apps`! https://github.com/apache/nuttx-apps/pull/2676

`build.yml` refers to `arch.yml` (for the build rules). So when we sync `build.yml` from `nuttx` to `nuttx-apps`, we won't need to remove the references to `arch.yml`.

We could make `nuttx-apps/build.yml` point to the `nuttx/arch.yml`. But that would make the CI fragile: Changes to `nuttx/arch.yml` might cause `nuttx-apps/build.yml` to break.

Yep `arch.yml` is totally not needed in `nuttx-apps`. I have difficulty keeping `nuttx/build.yml` and `nuttx-apps/build.yml` in sync, that's why I simply copied over `arch.yml` as-is. In future we could extend `arch.yml` with Build Rules that are specific to `nuttx-apps`?

If we decide to remove `nuttx-apps/arch.yml`: This means that we need to rewrite the `build.yml` logic from this:

```yaml
# Select the Linux Builds based on PR Arch Label
Linux-Arch:
  uses: apache/nuttx-apps/.github/workflows/arch.yml@master
  needs: Fetch-Source
  with:
    boards: |
      [
        "arm-01", "other", "risc-v-01", "sim-01", "xtensa-01", ...
      ]

# Run the selected Linux Builds
Linux:
  needs: Linux-Arch
  if: ${{ needs.Linux-Arch.outputs.skip_all_builds != '1' }}
  strategy:
    matrix:
      boards: ${{ fromJSON(needs.Linux-Arch.outputs.selected_builds) }}
```

Back to this:

```yaml
Linux:
  needs: Fetch-Source
  strategy:
    matrix:
      boards: [arm-01, arm-02, arm-03, arm-04, arm-05, arm-06, arm-07, arm-08, arm-09, arm-10, arm-11, arm-12, arm-13, other, risc-v-01, risc-v-02, sim-01, sim-02, xtensa-01, xtensa-02]
```

## Testing

(Note: The timings here are obsolete)

When we test our updated CI Workflow, we see that the irrelevant builds are skipped in seconds. Click "Show All Jobs" to reveal the timings:

- [CI Build for Arm32 PR](https://github.com/lupyuen5/label-nuttx/actions/runs/11208805090)

  (Completed in 2 hours, roughly 15 mins faster than before. Bottleneck is `arm-05`, which takes 2 hours, we should split into smaller jobs)

- [CI Build for Arm64 PR](https://github.com/lupyuen5/label-nuttx/actions/runs/11210569865)

  (Completed in 51 mins yay!)

- [CI Build for RISC-V PR](https://github.com/lupyuen5/label-nuttx/actions/runs/11197522570)

  (Completed in 1 hour 50 mins. Bottleneck is `riscv-01` and `riscv-02`, at 1 hour 47 mins each, we should split into smaller jobs)

- [CI Build for Xtensa PR](https://github.com/lupyuen5/label-nuttx/actions/runs/11200284084)

  (Completed in 1 hour 17 mins. Bottleneck is `xtensa-01` and `xtensa-02`, at 1 hour 15 mins each)

- [CI Build for Other PRs and Non-PR (All Targets)](https://github.com/lupyuen5/label-nuttx/actions/runs/11199194493)

  (Same as the present CI)

- When PRs are Merged: All Targets are recompiled (2 hours 13 mins), no changes from the Present CI. [Merge Arm32 PR](https://github.com/lupyuen5/label-nuttx/actions/runs/11200309934)

- Previously the irrelevant builds were skipped in seconds. Now the irrelevant builds (e.g. `arm-01`) are totally omitted for Simple PRs [(e.g. "Arch: risc-v")](https://github.com/lupyuen5/label-nuttx/actions/runs/11197522570)

  ![Screenshot 2024-10-06 at 11 39 43 AM](https://github.com/user-attachments/assets/8fb091b9-2ba0-4c3a-a533-af5c6609dab7)

## Actual Performance

We recorded the CI Build Performance based on Real-World PRs:

- **For Arm32:** Simple PRs will build in [**2 hours**](https://github.com/apache/nuttx/actions/runs/11217886131) (previously [**also 2 hours**](https://github.com/apache/nuttx/actions/runs/11210724531))

- **For Arm64:** Simple PRs will build in [**49 mins**](https://github.com/apache/nuttx/actions/runs/11232103862) (previously [**2 hours 11 mins**](https://github.com/apache/nuttx/actions/runs/11140028404))

- **For RISC-V:** Simple PRs will build in **1 hour 45 mins** (previously [**also 1 hour 45 mins**](https://github.com/apache/nuttx/actions/runs/11163805578))

- **For Xtensa:** Simple PRs will build in **1 hour 17 mins** (previously [**2 hours 11 mins**](https://github.com/apache/nuttx/actions/runs/11105657530))

- **For x86_64:** Simple PRs will build in [**48 mins**](https://github.com/apache/nuttx/actions/runs/11228070770) (previously [**2 hours 13 mins**](https://github.com/apache/nuttx/actions/runs/11158309196))

- **For Simulator:** Simple PRs will build in [**1 hour 32 mins**](https://github.com/apache/nuttx/actions/runs/11216774654) (previously [**2 hours 12 mins**](https://github.com/apache/nuttx/actions/runs/11146942454))

- OK no big wow yet. We need to break `arm-05`, `riscv-01` and `riscv-02` into multiple smaller jobs. Then things will really zoom! [(See the Build Job Details)](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

  Move the RP2040 jobs from `arm-05` to `arm-06`, then add `arm-14`. Add jobs `riscv-03` to `riscv-06`.

   (__Update:__ All Done! Check the PRs below)

- We already see a __27% Reduction in GitHub Runner Hours__! From [**15 Runner Hours**](https://github.com/apache/nuttx/actions/runs/11210724531/usage) down to [**11 Runner Hours**](https://github.com/apache/nuttx/actions/runs/11217886131/usage) per Arm32 Build.

- Split the Board Labels according to Arch, like "Board: arm". So "Board: arm" should build the exact same way as "Arch: arm". Same for "Board: arm, Arch: arm". Update the Build Rules to use the Board Labels

   (__Update:__ All Done! Check the PRs below)

- Split the `others` job into `arm64` and `x86_64`

   (__Update:__ All Done! Check the PRs below)

__TODO:__ Reorg and rename the CI Build Jobs, for better performance and easier maintenance. But how?

- I have a hunch that CI works better when we pack the jobs into One-Hour Time Slices

- Kinda like packing yummy goodies into Bento Boxes, making sure they don't overflow the Time Boxes  :-)

- We should probably shift the Riskiest / Most Failure Prone builds into the First Build Job. So we can Fail Faster (in case of problems), and skip the rest of the jobs

- Recently we see many builds for [Arm32 Goldfish](https://github.com/apache/nuttx/pulls?q=is%3Apr+is%3Aclosed+goldfish+). Can we limit the builds to the Goldfish Boards only? To identify Goldfish PRs, we can label the PRs like this: "Arch: arm, SubArch: goldfish" and/or "Board: arm, SubBoard: goldfish"

- How will we filter out the Build Jobs (e.g. `arm-01`) that should be built for a SubBoard (e.g. `stm32`)? [Maybe like this](https://gist.github.com/lupyuen/bccd1ac260603a2e3cd7440b8b4ee86c)
