# Optimising the Continuous Integration for Apache NuttX RTOS

📝 _10 Nov 2024_

![Optimising the Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/ci3-title.jpg)

__Within Two Weeks:__ We squashed our GitHub Actions spending from __$4,900__ (weekly) down to __$890__...

![Within Two Weeks: We squashed our GitHub Actions spending from $4,900 (weekly) down to $890](https://lupyuen.github.io/images/ci3-beforeafter7days.jpg)

__Previously:__ Our developers waited __2.5 Hours__ for a Pull Request to be checked. Now we wait at most __1.5 Hours__! (Pic below)

This article explains everything we did in the (Semi-Chaotic) Two Weeks for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)...

- Shut down the __macOS and Windows Builds__, revive them in a different form

- __Merge Jobs__ are super costly, we moved them to the NuttX Mirror Repo

- We __Halved the CI Checks__ for Complex PRs. (Continuous Integration)

- __Simple PRs__ are already quite fast. (Sometimes 12 Mins!)

- Coding the __Build Rules__ for our CI Workflow, monitoring our CI Servers 24 x 7

- We can't run __All CI Checks__, but NuttX Devs can help ourselves!

![Previously: Our developers waited 2.5 Hours for a Pull Request to be checked. Now we wait at most 1.5 Hours](https://lupyuen.github.io/images/ci3-beforeafter.jpg)

# Rescue Plan

We had [__an ultimatum__](https://lists.apache.org/thread/2yzv1fdf9y6pdkg11j9b4b93grb2bn0q) to reduce (drastically) our usage of GitHub Actions. Or our Continuous Integration would __Halt Totally in Two Weeks__!

After [__deliberating overnight:__](https://www.strava.com/activities/12673094079) We swiftly activated [__our rescue plan__](https://github.com/apache/nuttx/issues/14376)...

- __Submit / Update a Complex PR:__

  CI Workflow shall trigger only __Half the Jobs__ for CI Checks.

  _(A __Complex PR__ affects __All Architectures__: Arm32, Arm64, RISC-V, Xtensa, etc. Will reduce GitHub Cost by 32%)_

- __Merge a Complex PR:__

  CI Workflow shall __Run All Jobs__ like before.
  
  _(arm-01 ... arm-14, risc-v, xtensa, etc)_

- __Simple PRs:__

  No change. Thus Simple Arm32 PRs shall build only _arm-01 ... arm-14._

  _(A __Simple PR__ concerns only __One Single Architecture__: Arm32 OR Arm64 OR RISC-V etc)_

- __After Merging Any PR:__

  Merge Jobs shall run at [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx/actions/workflows/build.yml).
  
  _(Instead of OG Repo _apache/nuttx_)_

- __Two Scheduled Merge Jobs:__

  Daily at __00:00 UTC__ and __12:00 UTC__.

  _(No more On-Demand Merge Jobs)_

- __macOS and Windows Jobs:__

  Shall be __Totally Disabled__.
  
  _(Until we find a way to manage their costs)_

We have reasons for doing these, backed by solid data...

![We wasted GitHub Runners on Merge Jobs that were eventually superseded and cancelled](https://lupyuen.github.io/images/ci3-cancel.jpg)

# Present Pains

We studied the CI Jobs for the previous day...

- [__Analysis of CI Jobs over 24 Hours__](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=0#gid=0)

Many CI Jobs were __Incomplete__: We wasted GitHub Runners on Merge Jobs that were eventually __superseded and cancelled__ (pic above, we'll come back to this)

![Screenshot 2024-10-17 at 1 18 14 PM](https://github.com/user-attachments/assets/953e2ac7-aee5-45c6-986c-3bcdd97d0b5e)

__Scheduled Merge Jobs__ will reduce wastage of GitHub Runners, since most Merge Jobs didn't complete. Only One Merge Job completed on that day...

![Screenshot 2024-10-17 at 1 16 16 PM](https://github.com/user-attachments/assets/1452067f-a151-4641-8d1e-3c84c0f45796)

When we __Halve the CI Jobs:__ We reduce the wastage of GitHub Runners...

![Screenshot 2024-10-17 at 1 15 30 PM](https://github.com/user-attachments/assets/bda5c8c3-862a-41b6-bab3-20352ba9976a)

This analysis was super helpful for complying with the [__ASF Policy for GitHub Actions__](https://infra.apache.org/github-actions-policy.html)! Next we follow through...

![Disable macOS Builds](https://lupyuen.github.io/images/ci3-macos.jpg)

# Disable macOS and Windows Builds

_Quitting the macOS Builds? That's horribly drastic!_

Yeah sorry we can't enable __macOS Builds__ in NuttX Repo right now...

- macOS Runners [__cost 10 times__](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers) as much as Linux Runners.

  To enable One macOS Job: We need to disable 10 Linux Jobs! Which is not feasible.

- Our macOS Jobs are in an __untidy state__ right now, showing many many warnings.

  We need someone familiar with Intel Macs to clean up the macOS Jobs.

  (See the [__macOS Log__](https://github.com/NuttX/nuttx/actions/runs/11728929385/job/32673549658#step:7:4236))

- That's why we moved the macOS Builds to the [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx/actions/workflows/build.yml), which won't be charged to NuttX Project.

  [(Discussion here)](https://github.com/apache/nuttx/issues/14598)

  [(__macOS Build Farm__ coming soon!)](https://github.com/apache/nuttx/issues/14526)

![NuttX Dashboard](https://lupyuen.github.io/images/ci3-dashboard.png)

_Can we still prevent breakage of ALL Builds? Linux, macOS AND Windows?_

Nope this is __simply impossible__...

- In the good old days: We were using __far too many__ GitHub Runners.

  This is not sustainable, we don't have the budget to do all the CI Checks we used to.

- Hence we should expect __some breakage__.

  We should be prepared to backtrack and figure out which PR broke the build.

- That's why we have tools like [__NuttX Dashboard__](https://github.com/apache/nuttx/issues/14558) (pic above), to detect breakage earlier.

  (Without depending on GitHub CI)

- Remember to show __Love and Respect__ for NuttX Devs!

  Previously we waited [__2.5 Hours__](https://github.com/apache/nuttx/actions/runs/11308145630) for All CI Checks. Now we wait at most [__1.5 Hours__](https://github.com/apache/nuttx/actions/runs/11582139779), let's stick to this.

_What about the Windows Builds?_

Recently we [__re-enabled the Windows Builds__](https://github.com/apache/nuttx/issues/14598), because they're not as costly as macOS Builds.

We'll continue to monitor our GitHub Costs. And shut down the Windows Builds if necessary.

[(Windows Runners are __twice the cost__ of Linux Runners)](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers)

![Normally our CI Workflow will trigger a Merge Job, to verify that everything compiles OK after Merging the PR](https://lupyuen.github.io/images/ci3-merge.jpg)

# Move the Merge Jobs

_What are Merge Jobs? Why move them?_

Suppose our NuttX Admin __Merges a PR__. (Pic above)

Normally our CI Workflow will trigger a __Merge Job__, to verify that everything compiles OK after Merging the PR.

Which means ploughing through [__34 Sub-Jobs__](https://lupyuen.github.io/articles/ci#one-thousand-build-targets) (2.5 elapsed hours) across __All Architectures__: _Arm32, Arm64, RISC-V, Xtensa, macOS, Windows, ..._

This is extremely costly, hence we decided to trigger them as __Scheduled Merge Jobs__. I trigger them __Twice Daily__: 00:00 UTC and 12:00 UTC.

![Screenshot 2024-10-19 at 11 33 46 AM](https://github.com/user-attachments/assets/617cc2fe-38ac-474f-8cd8-141d19d5b1f0)

_Is there a problem?_

We spent [__One-Third__](https://github.com/apache/nuttx/issues/14376#issuecomment-2423563132) of our GitHub Runner Minutes on Scheduled Merge Jobs! (Pic above)

[__Our CI Data__](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=650325940#gid=650325940) shows that the Scheduled Merge Job kept getting disrupted by Newer Merged PRs. (Pic below)

And when we restart a Scheduled Merge Job, we waste precious GitHub Minutes.

[(__101 GitHub Hours__ for one single Scheduled Merge Job!)](https://github.com/apache/nuttx/issues/14376#issuecomment-2423563132)

![Merge Job kept getting disrupted by Newer Merged PRs](https://lupyuen.github.io/images/ci3-before.jpg)

_Our Merge Jobs are overwhelming!_

Yep this is clearly not sustainable. We moved the Scheduled Merge Jobs to a new [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx/actions/workflows/build.yml). (Pic below)

Where the Merge Jobs can run free __without disruption__.

[(In an __Unpaid GitHub Org Account__, not charged to NuttX Project)](https://github.com/NuttX)

![Optimising the Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/ci3-title.jpg)

_What about the Old Merge Jobs?_

Initially I ran a script that will quickly [__Cancel any Merge Jobs__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) that appear in NuttX Repo and NuttX Apps.

Eventually we disabled the [__Merge Jobs for NuttX Repo__](https://github.com/apache/nuttx/pull/14618). 

[(And for __NuttX Apps__)](https://github.com/apache/nuttx-apps/pull/2817)

[(Restoring __Auto-Build on Sync__)](https://github.com/apache/nuttx/issues/14407)

_How to trigger the Scheduled Merge Job?_

Every Day at __00:00 UTC__ and __12:00 UTC__: I do this...

1.  Browse to the [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx)

1.  Click "__Sync Fork > Discard Commits__"

1.  Which will __Sync our Mirror Repo__ based on the Upstream NuttX Repo

1.  Run this script to enable the __macOS Builds__: [enable-macos-windows.sh](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows.sh)

1.  Which will also [__Disable Fail-Fast__](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows.sh#L35-L55) and grind through all builds. [(Regardless of error, pic below)](https://github.com/NuttX/nuttx/commit/31aea70d52d1eb6138912619f835693008596eca)

1.  And [__Remove Max Parallel__](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows.sh#L35-L55) to use unlimited concurrent runners. [(Because it's free! Pic below)](https://github.com/NuttX/nuttx/commit/31aea70d52d1eb6138912619f835693008596eca)

1.  If the Merge Job fails with a [__Mystifying Network Timeout__](https://lupyuen.github.io/articles/ci3#appendix-network-timeout-at-github): I restart the Failed Sub-Jobs. [(__CI Test__ might overrun)](https://github.com/apache/nuttx/issues/14680)

1.  Wait for the Merge Job to complete. Then [__Ingest the GitHub Logs__](https://github.com/lupyuen/ingest-nuttx-builds) into our [__NuttX Dashboard__](https://github.com/apache/nuttx/issues/14558). (Next article)

![Disable Fail-Fast and Remove Max Parallel](https://lupyuen.github.io/images/ci3-workflow.png)

_Is it really OK to Disable the Merge Jobs? What about Docs and Docker Builds?_

- __Docker Builds:__ When [__Dockerfile__](https://github.com/apache/nuttx/blob/master/tools/ci/docker/linux/Dockerfile) is updated, it will trigger the CI Workflow [__docker_linux.yml__](https://github.com/apache/nuttx/blob/master/.github/workflows/docker_linux.yml). Which is not affected by this new setup, and will continue to execute. (Exactly like before)

- __Documentation:__ When the docs are updated, they are published to NuttX Website via the CI Workflow [__main.yml__](https://github.com/apache/nuttx-website/blob/master/.github/workflows/main.yml) from the NuttX Website repo (scheduled daily). Which is not affected by our grand plan.

- __Release Branch:__ Merging a PR to the Release Branch will still run the PR Merge Job (exactly like before). [__Release Branch__](https://github.com/apache/nuttx/issues/14062#issuecomment-2406373748) shall always be verified through [__Complete CI Checks__](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L14-L26).

  [(More about this)](https://github.com/apache/nuttx/pull/14618)

_Isn't this cheating? Offloading to a Free GitHub Account?_

Yeah that's why we need a [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci3#our-wishlist). (Details below)

![Halve the CI Checks for a Complex PR](https://lupyuen.github.io/images/ci3-checks.png)

# Halve the CI Checks

_One-Thirds of our GitHub Runner Minutes were spent on Merge Jobs. What about the rest?_

[__Two-Thirds__](https://github.com/apache/nuttx/issues/14376#issuecomment-2423563132) of our GitHub Runner Minutes were spent on validating __New and Updated PRs__.

Hence we're skipping __Half the CI Checks__ for Complex PRs.

(A __Complex PR__ affects __All Architectures__: _Arm32, Arm64 RISC-V, Xtensa, etc_)

_Which CI Checks did we select?_

Today we start only these __CI Checks__ when submitting or updating a Complex PR (pic above)

- _arm-03, 05, 06, 07, 08, 10, 13_
- _risc-v-01, 02, 03_
- _sim-01, 02_
- _xtensa-01, arm64-01, x86\_64-01, other_

[(See the __Pull Request__)](https://github.com/apache/nuttx/pull/14602)

[(Synced to __NuttX Apps__)](https://github.com/apache/nuttx-apps/pull/2813)

_Why did we choose these CI Checks?_

We selected the CI Checks above because they validate NuttX Builds on __Popular Boards__ (and for special tests)

| Target Group | Board / Test |
|:----------|:----------------------|
| _arm-01_ | Sony Spresense (TODO) |
| _arm-05_ | Nordic nRF52 |
| _arm-06_ | Raspberry Pi RP2040 |
| _arm-07_ | Microchip SAMD |
| _arm-08, 10, 13_ | STM32 |
| _risc-v-02, 03_ | ESP32-C3, C6, H2 |
| _sim-01, 02_ | CI Test, Matter |

We might [__rotate the list__](https://github.com/apache/nuttx/pull/14602) above to get better CI Coverage.

[(See the Complete List of __CI Builds__)](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

![Complex PR vs Simple PR](https://lupyuen.github.io/images/ci3-pr.jpg)

_What about Simple PRs?_

A __Simple PR__ concerns only __One Single Architecture__: _Arm32 OR Arm64 OR RISC-V OR Xtensa etc._

When we create a Simple PR for Arm32: It will trigger only the CI Checks for _arm-01_ ... _arm-14_.

Which will [__complete earlier__](https://lupyuen.codeberg.page/articles/ci3.html#actual-performance) than a Complex PR.

[(__x86_64 Devs__ are the happiest. Their PRs complete in __10 Mins__!)](https://lupyuen.codeberg.page/articles/ci3.html#actual-performance)

_Sounds awfully complicated. How did we code the rules?_

Indeed! The Build Rules are explained here...

- ["__Build Rules for CI Workflow__"](https://lupyuen.github.io/articles/ci3#appendix-build-rules-for-ci-workflow)

# Live Metric for Full-Time Runners

_Hitting the Target Metrics in 2 weeks... Everyone needs to help out right?_

Our quota is [__25 Full-Time GitHub Runners__](https://infra.apache.org/github-actions-policy.html) per day.

We published our own __Live Metric for Full-Time Runners__, for everyone to track...

![Live Metric for Full-Time Runners](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png)

- __Date:__ We compute the Full-Time Runners only for Today's Date (UTC)

- __Elapsed Hours:__ Number of hours elapsed since 00:00 UTC

- __GitHub Job Hours:__ Elapsed Duration of all GitHub Jobs at NuttX Repo and NuttX Apps. _(Cancelled / Completed / Failed)_

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

[__On Overnight Hikes__](https://www.strava.com/activities/12737067287): I check my phone at every water break...

![GridArt_20241028_150938083](https://github.com/user-attachments/assets/88232734-aecc-4af8-bc0e-641db1cfdf9e)

_If something goes wrong?_

We have GitHub Scripts for __Termux Android__. Remember to _"pkg install gh"_ and set _GITHUB_TOKEN_...

- [__enable-macos-windows2.sh__](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows2.sh): Enable the macOS Builds in the NuttX Mirror Repo

- [__compute-github-runners2.sh__](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners2.sh): Compute the number of Full-Time GitHub Runners for the day (less accurately than macOS version)

- [__kill-push-master.sh__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh): Cancel all Merge Jobs in NuttX Repo and NuttX Apps

# Final Verdict

It's past Diwali and Halloween and Elections... Our CI Servers are still alive. __We made it yay!__ 🎉

__Within Two Weeks:__ We squashed our GitHub Actions spending from __$4,900__ (weekly) down to __$890__...

![Within Two Weeks: We squashed our GitHub Actions spending from $4,900 (weekly) down to $890](https://lupyuen.github.io/images/ci3-beforeafter7days.jpg)

__"Monthly Bill"__ for GitHub Actions used to be __$18K__...

![Monthly Bill for GitHub Actions used to be $18K](https://lupyuen.github.io/images/ci3-before30days.png)

Presently our __Monthly Bill is $9.8K__. Slashed by half (almost) and still dropping! Thank you everyone for making this happen! 🙏

![Right now our Monthly Bill is $9.8K](https://lupyuen.github.io/images/ci3-after30days.png)

__Bonus Love & Respect:__ Previously our devs waited __2.5 Hours__ for a Pull Request to be checked. Now we wait at most __1.5 Hours__!

![Tired Fingers syncing the NuttX Repo to NuttX Mirror Repo](https://lupyuen.github.io/images/ci3-sync.jpg)

# Our Wishlist

_Everything is hunky dory?_

Trusting a __Single Provider for Continuous Integration__ is a terrible thing. We got plenty more to do...

- Become more resilient and self-sufficient with [__Our Own Build Farm__](https://lupyuen.codeberg.page/articles/ci2.html)

  (Away from GitHub)

- Analyse our Build Logs with [__Our Own Tools__](https://github.com/apache/nuttx/issues/14558) 

  (Instead of GitHub)

- Excellent Initiative by [__Mateusz Szafoni__](https://github.com/raiden00pl): We [__Merge Multiple Targets__](https://github.com/apache/nuttx/pull/14410) into One Target

  (And cut the Build Time)

[🙏🙏🙏 Please join __Your Ubuntu PC__ to our Build Farm! 🙏🙏🙏](https://github.com/apache/nuttx/issues/14558)

_But our Merge Jobs are still running in a Free Account?_

We learnt a Painful Lesson today: __Freebies Won't Last Forever!__

We should probably maintain an official __Paid GitHub Org Account__ to execute our Merge Jobs...

1.  New GitHub Org shall be sponsored by our generous __Stakeholder Companies__

    (Espressif, Sony, Xiaomi, ...)

1.  New GitHub Org shall be maintained by a __Paid Employee__ of our Stakeholder Companies

    (Instead of an Unpaid Volunteer)

1.  Which means clicking Twice Per Day to trigger the [__Scheduled Merge Jobs__](https://lupyuen.codeberg.page/articles/ci3.html#move-the-merge-jobs)

    (My fingers are tired, pic above)

1.  And restarting the __Failed Merge Jobs__ 

    [(Because of __Mysterious Network Timeouts__)](https://lupyuen.github.io/articles/ci3#appendix-network-timeout-at-github)

    [(__CI Test__ might overrun)](https://github.com/apache/nuttx/issues/14680)

1.  New GitHub Org shall host the Official Downloads of __NuttX Compiled Binaries__

    (For upcoming __Board Testing Farm__)

1.  New GitHub Org will eventually __Offload CI Checks__ from our NuttX Repos

    (Maybe do macOS CI Checks for PRs)

![Optimising the Continuous Integration for Apache NuttX RTOS](https://lupyuen.github.io/images/ci3-title.jpg)

# What's Next

Next Article: We'll chat about __NuttX Dashboard__. And how we made it with Grafana and Prometheus.

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! I couldn't have survived the two choatic and stressful weeks without your help. And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=42097212)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci3.md)

# Appendix: Self-Hosted GitHub Runners

_Have we tried Self-Hosted GitHub Runners?_

Yep I tested Self-Hosted GitHub Runners, I wrote about my experience here: [__"Continuous Integration for Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ci)

- GitHub Runners are actually quite complex to setup. And the machine needs to be __properly secured__, in case any unauthorised code is pushed down from GitHub.

- We don't have budget to set up __Professionally-Secured VMs__ for GitHub Runners anyway

- NuttX Project might be a little __too dependent on GitHub__. Even if we had the funds, the ASF contract with GitHub won't allow us to pay more for extra usage. So we're trying alternatives.

- Right now we're testing a __Community-Hosted Build Farm__ based on Ubuntu PCs and macOS: [__"Your very own Build Farm for Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ci2)

![CI Checks for a Complex PR](https://lupyuen.github.io/images/ci3-checks.png)

# Appendix: Check our PR Submission

_Before submitting a PR to NuttX: How to check our PR thoroughly?_

Yep it's super important to __thoroughly test our PRs__ before submitting to NuttX.

But NuttX Project [__doesn't have the budget__](https://lupyuen.codeberg.page/articles/ci3.html#disable-macos-and-windows-builds) to run all CI Checks for New PRs. The onus is on us to test our PRs (without depending on the CI Workflow)

1. Run the CI Builds ourselves with __Docker Engine__

2. Or run the CI Builds with __GitHub Actions__

(1) might be slower, depending on our PC. With (2) we don't need to worry about Wasting GitHub Runners, so long as the CI Workflow runs entirely in our own personal repo, before submitting to NuttX Repo.

Here are the instructions...

- [__CI Check: Docker vs GitHub Actions__](https://github.com/apache/nuttx/issues/14601#issuecomment-2452875114)

- [__CI Check: Enable for PR Branch__](https://github.com/apache/nuttx/pull/14590#issuecomment-2459178845)

![NuttX Dashboard](https://lupyuen.github.io/images/ci3-dashboard.png)

_What if our PR fails the check, caused by Another PR?_

We wait for the __Other PR to be patched__...

1.  Set our PR to __Draft Mode__

1.  Keep checking the __NuttX Dashboard__ (above)

1.  Wait patiently for the __Red Error Boxes__ to disappear

1.  [__Rebase our PR__](https://lupyuen.github.io/articles/pr#submit-the-pull-request) with the Master Branch

1.  Our PR should pass the CI Check. Set our PR to __Ready for Review__.

Otherwise we might miss a [__Serious Bug__](https://github.com/apache/nuttx/actions/runs/11700129839).

![Screenshot 2024-10-19 at 8 11 22 AM](https://github.com/user-attachments/assets/ca08db63-ecca-4b18-984e-46ba3a9716c2)

# Appendix: Verify our PR Merge

_When NuttX merges our PR, the Merge Job won't run until 00:00 UTC and 12:00 UTC. How can we be really sure that our PR was merged correctly?_

Let's create a __GitHub Org__ (at no cost), fork the NuttX Repo and trigger the __CI Workflow__. (Which won't charge any extra GitHub Runner Minutes to NuttX Project!)

- [__"How to Verify a PR Merge"__](https://github.com/apache/nuttx/issues/14407)

This will probably work if our CI Servers ever go dark.

![Network Timeout at GitHub](https://lupyuen.github.io/images/ci3-timeout.png)

# Appendix: Network Timeout at GitHub

[(See the __NuttX Issue__)](https://github.com/apache/nuttx/issues/14682)

Something super strange about __Network Timeouts__ (pic above) in our CI Docker Workflows at GitHub Actions. Here's an example...

- First Run fails while [__downloading something from GitHub__](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111488205#step:7:626)...

  ```text
  Configuration/Tool: imxrt1050-evk/libcxxtest,CONFIG_ARM_TOOLCHAIN_GNU_EABI
  curl: (28) Failed to connect to github.com port 443 after 134188 ms: Connection timed out
  make[1]: *** [libcxx.defs:28: libcxx-17.0.6.src.tar.xz] Error 28
  ```

- Second Run fails again, while [__downloading NimBLE from GitHub__](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32112716849#step:7:536)...

  ```text
  Configuration/Tool: nucleo-wb55rg/nimble,CONFIG_ARM_TOOLCHAIN_GNU_EABI
  curl: (28) Failed to connect to github.com port [443](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32112716849#step:7:444) after 134619 ms: Connection timed out
  make[2]: *** [Makefile:55: /github/workspace/sources/apps/wireless/bluetooth/nimble_context] Error 2
  ```

- [__Third Run succeeds.__](https://github.com/nuttxpr/nuttx/actions/runs/11535899222) Why do we keep seeing these errors: GitHub Actions with Docker, can't connect to GitHub itself?

- Is there a __Concurrent Connection Limit__ for GitHub HTTPS Connections?

  We see __4 Concurrent Connections__ to GitHub HTTPS...

  - [__risc-v-05__ at 00:41:06](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111489166#step:7:84)

  - [__xtensa-02__ at 00:41:17](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111488582#step:7:510)

  - [__xtensa-01__ at 00:41:34](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111487874#step:7:586)

  - [__risc-v-02__ at 00:41:58](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111488301#step:7:532)

  The __Fifth Connection__ failed: [__arm-02__ at 00:42:52](https://github.com/nuttxpr/nuttx/actions/runs/11535899222/job/32111488205#step:7:619)

- Should we use a [__Caching Proxy Server__](https://ubuntu.com/server/docs/how-to-install-a-squid-server) for curl?

  ```bash
  $ export https_proxy=https://1.2.3.4:1234
  $ curl https://github.com/...
  ```

- Is something misconfigured in our __Docker Image__?

  But the exact same Docker Image runs fine on [__our own Build Farm__](https://lupyuen.github.io/articles/ci2). It [__doesn't show any errors__](https://lupyuen.codeberg.page/articles/ci2.html).

- Is GitHub Actions starting our Docker Container with the wrong MTU (Network Packet Size)? 🤔

  - [__GitHub Actions with Smaller MTU Size__](https://github.com/actions/actions-runner-controller/issues/393)

  - [__Docker MTU issues and solutions__](https://mlohr.com/docker-mtu/)

- Meanwhile I'm running a script to Restart Failed Jobs on our NuttX Mirror Repo: [restart-failed-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/restart-failed-job.sh)

These __Timeout Errors__ will cost us precious GitHub Minutes. The remaining jobs get killed, and restarting these killed jobs from scratch will consume extra GitHub Minutes. (The restart below costs us 6 extra GitHub Runner Hours)

1.  How do we __Retry these Timeout Errors__?

1.  Can we have __Restartable Builds__?

    Doesn't quite make sense to kill everything and rebuild from scratch _(arm6, arm7, riscv7)_ just because one job failed _(xtensa2)_

1.  Or _xtensa2_ should __wait for others__ to finish, before it declares a timeout and croaks?

```text
Configuration/Tool: esp32s2-kaluga-1/lvgl_st7789
curl: Failed to connect to github.com port 443 after 133994 ms:
Connection timed out
```
[(See the __Complete Log__)](https://github.com/apache/nuttx/actions/runs/11395811301/job/31708665147#step:7:348)

![Previously: Our developers waited 2.5 Hours for a Pull Request to be checked. Now we wait at most 1.5 Hours](https://lupyuen.github.io/images/ci3-beforeafter.jpg)

# Appendix: Build Rules for CI Workflow

Initially we created the __Build Rules__ for CI Workflow to solve these problems that we observed in Sep 2024...

- NuttX Devs need to wait (2.5 hours) for the CI Build to complete __Across all Architectures__ _(Arm32, Arm64, RISC-V, Xtensa)_...

  Even though we're modifying a __Single Architecture__.

- We're using __too many GitHub Runners__ and Build Minutes, exceeding the [__ASF Policy for GitHub Actions__](https://infra.apache.org/github-actions-policy.html)

- Our usage of GitHub Runners is going up ($12K per month)

  We need to stay within the [__ASF Budget for GitHub Runners__](https://infra.apache.org/github-actions-policy.html) ($8.2K per month)

- What if CI could build only the __Modified Architecture__?

- Right now most of our CI Builds are taking 2.5 mins.

  Can we __complete the build within 1 hour__, when we Create / Modify a Simple PR?

This section explains how we coded the Build Rules. Which were mighty helpful for cutting costs in Nov 2024.

[(Discussion here)](https://github.com/apache/nuttx/issues/13775)

## Overall Solution

We propose a Partial Solution, based on the [__Arch and Board Labels__](https://github.com/apache/nuttx/pull/13545) (recently added to CI)...

- We target only the __Simple PRs__: One Arch Label + One Board Label + One Size Label.

  Like _"Arch: risc-v, Board: risc-v, Size: XS"_

- If _"Arch: arm"_ is the only non-size label, then we build only _arm-01, arm-02, ..._

- Same for _"Board: arm"_

- If __Arch and Board Labels__ are both present: They must be the same

- Similar rules for RISC-V, Simulator, x86_64 and Xtensa

- __Simple PR + Docs__ is still considered a Simple PR (so devs won't be penalised for adding docs)

## Fetch the Arch Labels

__In our Build Rules:__ This is how we fetch the Arch Labels from a PR. And identify the PR as Arm, Arm64, RISC-V or Xtensa: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L32-L104)

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

Why "` || echo ""`"? That's because if the __GitHub CLI gh__ fails for any reason, we shall build all targets.

This ensures that our CI Workflow won't get disrupted due to errors in GitHub CLI.

## Limit to Simple PRs

We handle only __Simple PRs__: One Arch Label + One Board Label + One Size Label.

Like _"Arch: risc-v, Board: risc-v, Size: XS"_.

If it's __Not a Simple PR__: We build everything. Like so: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L130-L189)

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
  # If PR was Created or Modified: Exclude some boards
  pr=${{github.event.pull_request.number}}
  if [[ "$pr" != "" ]]; then
    echo "Excluding arm-0[1249], arm-1[124-9], risc-v-04..06, sim-03, xtensa-02"
    boards=$(
      echo '${{ inputs.boards }}' |
      jq --compact-output \
      'map(
        select(
          test("arm-0[1249]") == false and test("arm-1[124-9]") == false and
          test("risc-v-0[4-9]") == false and
          test("sim-0[3-9]") == false and
          test("xtensa-0[2-9]") == false
        )
      )'
    )
  fi
  echo "selected_builds=$boards" | tee -a $GITHUB_OUTPUT
  exit
fi
```

## Identify the Non-Arm Builds

Suppose the PR says _"Arch: arm"_ or _"Board: arm"_.

We filter out the builds that should be skipped (RISC-V, Xtensa, etc): [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L189-L254)

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

Earlier we saw the code in _arch.yml_ [__Reusable Workflow__](https://docs.github.com/en/actions/sharing-automations/reusing-workflows) that identifies the builds to be skipped.

The code above is called by _build.yml_ (Build Workflow). Which will actually skip the builds: [build.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L119-L148)

```yaml
# Select the Linux Builds based on PR Arch Label
Linux-Arch:
uses: apache/nuttx/.github/workflows/arch.yml@master
needs: Fetch-Source
with:
  os: Linux
  boards: |
    [
      "arm-01", "risc-v-01", "sim-01", "xtensa-01", "arm64-01", "x86_64-01", "other",
      "arm-02", "risc-v-02", "sim-02", "xtensa-02",
      "arm-03", "risc-v-03", "sim-03",
      "arm-04", "risc-v-04",
      "arm-05", "risc-v-05",
      "arm-06", "risc-v-06",
      "arm-07", "arm-08", "arm-09", "arm-10", "arm-11", "arm-12", "arm-13", "arm-14"
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

Why _"needs: Fetch-Source"_? That's because the PR Labeler runs __concurrently in the background__.

When we add _Fetch-Source_ as a __Job Dependency__: We give the PR Labeler sufficient time to run (1 min), before we read the PR Label in _arch.yml_.

## Same for Other Builds

We do the same for Arm64, RISC-V, Simulator, x86_64 and Xtensa: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L202-L232)

```yaml
# For "Arch / Board: arm64": Build arm64-01
elif [[ "$arch_contains_arm64" == "1" || "$board_contains_arm64" == "1" ]]; then
  if [[ "$board" != *"arm64-"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: risc-v": Build risc-v-01, risc-v-02, ...
elif [[ "$arch_contains_riscv" == "1" || "$board_contains_riscv" == "1" ]]; then
  if [[ "$board" != *"risc-v-"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: simulator": Build sim-01, sim-02
elif [[ "$arch_contains_sim" == "1" || "$board_contains_sim" == "1" ]]; then
  if [[ "$board" != *"sim-"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: x86_64": Build x86_64-01
elif [[ "$arch_contains_x86_64" == "1" || "$board_contains_x86_64" == "1" ]]; then
  if [[ "$board" != *"x86_64-"* ]]; then
    skip_build=1
  fi

# For "Arch / Board: xtensa": Build xtensa-01, xtensa-02
elif [[ "$arch_contains_xtensa" == "1" || "$board_contains_xtensa" == "1" ]]; then
  if [[ "$board" != *"xtensa-"* ]]; then
    skip_build=1
  fi
```

![Disable macOS Builds](https://lupyuen.github.io/images/ci3-macos.jpg)

## Skip the macOS Builds

__For Simple PRs and Complex PRs:__ We skip the macOS builds _(macos, macos/sim-*)_ since these builds are costly: [build.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L196-L256)

(macOS builds will take __2 hours to complete__ due to the queueing for macOS Runners)

```yaml
# Select the macOS Builds based on PR Arch Label
macOS-Arch:
  uses: apache/nuttx/.github/workflows/arch.yml@master
  needs: Fetch-Source
  with:
    os: macOS
    boards: |
      ["macos", "sim-01", "sim-02", "sim-03"]

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
```

_skip_all_builds_ for macOS will be set to `1`: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L100-L112)

```yaml
# Select the Builds for the PR: arm-01, risc-v-01, xtensa-01, ...
- name: Select builds
  id: select-builds
  run: |

    # Skip all macOS Builds
    if [[ "${{ inputs.os }}" == "macOS" ]]; then
      echo "Skipping all macOS Builds"
      echo "skip_all_builds=1" | tee -a $GITHUB_OUTPUT
      exit
    fi
```

## Ignore the Docs Label

NuttX Devs shouldn't be __penalised for adding docs__!

That's why we ignore the label _"Area: Documentation"_. Which means that __Simple PR + Docs__ is still a Simple PR.

And will skip the unnecessary builds: [arch.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/arch.yml#L44-L55)

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

## Sync to NuttX Apps

Remember to sync _build.yml_ and _arch.yml_ from __NuttX Repo to NuttX Apps__!

[(See the __Pull Request__)](https://github.com/apache/nuttx-apps/pull/2676)

_How are they connected?_

- _build.yml_ points to _arch.yml_ for the __Build Rules__.

  When we sync _build.yml_ from NuttX Repo to NuttX Apps, we won't need to remove the references to _arch.yml_.

- We could make _nuttx-apps/build.yml_ point to _nuttx/arch.yml_.

  But that would make the __CI Fragile__: Changes to _nuttx/arch.yml_ might cause _nuttx-apps/build.yml_ to break.

- That's why we point _nuttx-apps/build.yml_ to  _nuttx-apps/arch.yml_ instead.

_But NuttX Apps don't need Build Rules?_

- _arch.yml_ is kinda redundant in NuttX Apps. Everything is a __Complex PR__!

- I have difficulty keeping _nuttx/build.yml_ and _nuttx-apps/build.yml_ in sync. That's why I simply copied over _arch.yml_ as-is. 

- In future we could extend _arch.yml_ with __App-Specific__ Build Ruiles

_CI Build Workflow looks very different now?_

Yeah our __CI Build Workflow__ used to be simpler: [build.yml](https://github.com/apache/nuttx/blob/6a0c0722e23f5fc294a4574111742765e8c0dd04/.github/workflows/build.yml#L117-L179)

```yaml
Linux:
  needs: Fetch-Source
  strategy:
    matrix:
      boards: [arm-01, arm-02, arm-03, arm-04, arm-05, arm-06, arm-07, arm-08, arm-09, arm-10, arm-11, arm-12, arm-13, other, risc-v-01, risc-v-02, sim-01, sim-02, xtensa-01, xtensa-02]
```

Now with __Build Rules__, it becomes more complicated: [build.yml](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L118-L196)

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

One thing remains the same: We configure the __Target Groups__ in _build.yml_. (Instead of _arch.yml_)

## Actual Performance

For our Initial Implementation of Build Rules: We recorded the __CI Build Performance__ for Simple PRs.

Then we made the Simple PRs faster...

| Build Time | Before | After |
|:------------------|:------:|:-----:|
| Arm32 | [**2 hours**](https://github.com/apache/nuttx/actions/runs/11210724531) | [**1.5 hours**](https://github.com/apache/nuttx/actions/runs/11707495067)
| Arm64 | [**2.2 hours**](https://github.com/apache/nuttx/actions/runs/11140028404) | [**30 mins**](https://github.com/apache/nuttx/actions/runs/11704164434)
| RISC-V | [**1.8 hours**](https://github.com/apache/nuttx/actions/runs/11163805578) | [**50 mins**](https://github.com/apache/nuttx/actions/runs/11669727849)
| Xtensa | [**2.2 hours**](https://github.com/apache/nuttx/actions/runs/11105657530) | [**1.5 hours**](https://github.com/apache/nuttx/actions/runs/11699279596)
| x86_64 | [**2.2 hours**](https://github.com/apache/nuttx/actions/runs/11158309196) | [**10 mins**](https://github.com/apache/nuttx/actions/runs/11661703226)
| Simulator | [**2.2 hours**](https://github.com/apache/nuttx/actions/runs/11146942454) | [**1 hour**](https://github.com/apache/nuttx/actions/runs/11499427672)

_How did we make the Simple PRs faster?_

- We broke up __Big Jobs__ _(arm-05, riscv-01, riscv-02)_ into Multiple Smaller Jobs.

  __Small Jobs__ will really fly! [(See the Build Job Details)](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

  (We moved the RP2040 jobs from _arm-05_ to _arm-06_, then added _arm-14_. Followed by jobs _riscv-03 ... riscv-06_)

- We saw a __27% Reduction in GitHub Runner Hours__! From [**15 Runner Hours**](https://github.com/apache/nuttx/actions/runs/11210724531/usage) down to [**11 Runner Hours**](https://github.com/apache/nuttx/actions/runs/11217886131/usage) per Arm32 Build.

- We split the __Board Labels__ according to Arch, like _"Board: arm"_.

  Thus _"Board: arm"_ should build the exact same way as _"Arch: arm"_.
  
  Same for _"Board: arm, Arch: arm"_. We updated the Build Rules to use the Board Labels.

- We split the _others_ job into _arm64_ and _x86_64_

__Up Next:__ Reorg and rename the CI Build Jobs, for better performance and easier maintenance. But how?

- I have a hunch that CI works better when we pack the jobs into __One-Hour Time Slices__

- Kinda like packing yummy goodies into __Bento Boxes__, making sure they don't overflow the Time Boxes  :-)

- We should probably shift the __Riskiest / Most Failure Prone__ builds into the First Build Job _(arm-00, risc-v-00, sim-00)_.

  And we shall __Fail Faster__ (in case of problems), skipping the rest of the jobs.

- Recently we see many builds for [__Arm32 Goldfish__](https://github.com/apache/nuttx/pulls?q=is%3Apr+is%3Aclosed+goldfish+).

  Can we limit the builds to the __Goldfish Boards__ only? 
  
  To identify __Goldfish PRs__, we can label the PRs like this: _"Arch: arm, SubArch: goldfish"_ and _"Board: arm, SubBoard: goldfish"_

- Instead of Building an __Entire Arch__ _(arm-01)_...

  Can we build __One Single SubArch__ _(stm32)_?

  How will we __Filter the Build Jobs__ (e.g. _arm-01_) that should be built for a SubArch (e.g. _stm32_)? [(Maybe like this)](https://gist.github.com/lupyuen/bccd1ac260603a2e3cd7440b8b4ee86c)

  [(Discussion here)](https://github.com/apache/nuttx/issues/13775)

![Spot the exact knotty moment that we were told about the CI Shutdown](https://lupyuen.github.io/images/ci3-hike.jpg)

[_Spot the exact knotty moment that we were told about the CI Shutdown_](https://www.strava.com/activities/12673094079)
