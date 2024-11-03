# Optimising the Continuous Integration for Apache NuttX RTOS

📝 _23 Nov 2024_

![TODO](https://lupyuen.github.io/images/ci3-title.jpg)

TODO: Dev build time dropped from ??? to ???
GitHub Usage dropped from ??? to ???
cp "$HOME/Desktop/Screenshot 2024-10-17 at 5.01.11 PM.png" ~/Desktop/before-30days.png

# Ultimatum

TODO

Hi All: We have [an ultimatum](https://lists.apache.org/thread/2yzv1fdf9y6pdkg11j9b4b93grb2bn0q) to reduce (drastically) our usage of GitHub Actions. Or our Continuous Integration will halt totally in Two Weeks. Here's what I'll implement within 24 hours for `nuttx` and `nuttx-apps` repos:

1. When we submit or update a __Complex PR__ that affects __All Architectures__ (Arm, RISC-V, Xtensa, etc): CI Workflow shall run only half the jobs. Previously CI Workflow will run `arm-01` to `arm-14`, now we will run only `arm-01` to `arm-07`. (This will reduce GitHub Cost by 32%)

1. When the __Complex PR is Merged:__ CI Workflow will still run all jobs `arm-01` to `arm-14`

   (Simple PRs with One Single Arch / Board will build the same way as before: `arm-01` to `arm-14`)

1. __For NuttX Admins:__ Our [__Merge Jobs are now at github.com/NuttX/nuttx__](https://github.com/NuttX/nuttx/actions/workflows/build.yml). We shall have only __Two Scheduled Merge Jobs__ per day 

   I shall quickly [Cancel any Merge Jobs](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) that appear in `nuttx` and `nuttx-apps` repos. Then at 00:00 UTC and 12:00 UTC: I shall start the Latest Merge Job at `nuttxpr`. ~~(This will reduce GitHub Cost by 17%)~~

1. __macOS and Windows Jobs__ (msys2 / msvc): They shall be totally disabled until we find a way to manage their costs. (GitHub charges [10x premium for macOS runners](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers), 2x premium for Windows runners!)

   Let's monitor the GitHub Cost after disabling macOS and Windows Jobs. It's possible that macOS and Windows Jobs are contributing a huge part of the cost. We could re-enable and simplify them after monitoring.

   (This must be done for BOTH `nuttx` and `nuttx-apps` repos. Sadly the ASF Report for GitHub Runners doesn't break down the usage by repo, so we'll never know how much macOS and Windows Jobs are contributing to the cost. That's why we need https://github.com/apache/nuttx/pull/14377)

   (Wish I could run NuttX CI Jobs on my M2 Mac Mini. But the CI Script only supports Intel Macs sigh. Buy a Refurbished Intel Mac Mini?)

We have done an Analysis of CI Jobs over the past 24 hours:

https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=0#gid=0

Many CI Jobs are __Incomplete__: We waste GitHub Runners on jobs that eventually get superseded and cancelled

![Screenshot 2024-10-17 at 1 18 14 PM](https://github.com/user-attachments/assets/953e2ac7-aee5-45c6-986c-3bcdd97d0b5e)

When we __Half the CI Jobs:__ We reduce the wastage of GitHub Runners

![Screenshot 2024-10-17 at 1 15 30 PM](https://github.com/user-attachments/assets/bda5c8c3-862a-41b6-bab3-20352ba9976a)

__Scheduled Merge Jobs__ will also reduce wastage of GitHub Runners, since most Merge Jobs don't complete (only 1 completed yesterday)

![Screenshot 2024-10-17 at 1 16 16 PM](https://github.com/user-attachments/assets/1452067f-a151-4641-8d1e-3c84c0f45796)

[See the ASF Policy for GitHub Actions](https://infra.apache.org/github-actions-policy.html)

# Move the Merge Jobs

TODO: Isn't this cheating? Yeah that's why we need a Build Farm

Stats for the past 24 hours: We consumed __61 Full-Time Runners__, still got a long way away from our target of 25 Full-Time Runners (otherwise ASF will halt our servers in 12 days)
- Our [__Merge Jobs are now at github.com/NuttX/nuttx__](https://github.com/NuttX/nuttx/actions/workflows/build.yml)
- ~~We have switched to [Four Scheduled Merge Jobs](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) per day. New Merge Jobs will now run for a few seconds before getting auto-killed [by our script](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh), via the GitHub CLI. [(See the Merge Jobs)](https://github.com/apache/nuttx/actions/workflows/build.yml?query=branch%3Amaster+event%3Apush)~~
- `nuttx-apps` has stopped macOS and Windows Jobs. But not much impact, since we don't compile `nuttx-apps` often <br> https://github.com/apache/nuttx-apps/pull/2750
- Still waiting for `nuttx` repo to stop macOS and Windows Jobs (Update: merged!) <br> https://github.com/apache/nuttx/pull/14377
- Also waiting for `nuttx` repo to Halve The Jobs (Update: merged!) <br> https://github.com/apache/nuttx/pull/14386
- And for `nuttx-apps` to Halve The Jobs (probably not much impact, since we don't compile `nuttx-apps` often)  (Update: merged!) <br> https://github.com/apache/nuttx-apps/pull/2753
- Will wait for the above to be merged, then we monitor some more (Update: All merged! Thanks Tomek :-)
- If our Full-Time Runners don't reduce significantly after 24 hours: We shall [further reduce our jobs](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=1936368893#gid=1936368893), halving the jobs for RISC-V / Xtensa / Simulator when we Create / Modify a Complex PR. Also: Reduce the Daily Merge Jobs from 4 to 2.
- We shall close this issue only when we reach our target of __25 Full-Time Runners__ per day. (And ASF won't shut us down)

![Screenshot 2024-10-18 at 6 14 48 AM](https://github.com/user-attachments/assets/8c3d193f-c836-4bd5-8a3c-37c5a073fe32)

# Half the CI Checks

TODO

__11 Days To Doomsday:__ But we're doing much better already! In the past 24 hours, we consumed __36 Full-Time GitHub Runners__. We're getting closer to the ASF Target of __25 Full-Time Runners__! Today we shall:

- Halve the Jobs for __RISC-V, Xtensa and Simulator__ for Complex PRs <br>
  https://github.com/apache/nuttx/pull/14400

- Do the same for `nuttx-apps` repo <br>
  https://github.com/apache/nuttx-apps/pull/2758

- Our [__Merge Jobs are now at github.com/nuttxpr/nuttx__](https://github.com/nuttxpr/nuttx/actions)

  ~~Reduce the Scheduled Merge Jobs to [__Two Per Day__](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh) at 00:00 / 12:00 UTC (down from Four Per Day)~~

Hopefully we'll reach the ASF Target tomorrow, and ASF won't kill our servers no more! Thanks!

![Screenshot 2024-10-19 at 7 15 11 AM](https://github.com/user-attachments/assets/b5bbc42b-df0c-4004-89dd-164293ae6749)

# Disable macOS and Windows Builds

TODO: Re-enable Windows Builds, monitor closely

[CI Jobs for macOS, msvc and msys2](https://github.com/apache/nuttx/issues/14598)

Sorry I can't enable macOS Builds right now:
- macOS Runners [cost 10 times](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers) as much as Linux Runners. To enable One macOS Job, we need to disable 10 Linux Jobs! Which is not feasible.
- Our macOS Jobs are in a bad state right now, showing too many warnings. We need someone familiar with Intel Macs to clean up the macOS Jobs.
https://github.com/NuttX/nuttx/actions/runs/11630100298/job/32388421934
https://github.com/NuttX/nuttx/actions/runs/11630100298/job/32388422211

[CI Jobs for macOS, msvc and msys2](https://github.com/apache/nuttx/issues/14598)

But can we still prevent breakage of Linux / macOS / msvc / msys2 Builds?
- Nope this is simply impossible. In the good old days: We were using far too many GitHub Runners. This is not sustainable, we don't have the budget to run all the CI Checks we used to.
- So we should expect some breakage to happen. We have to be prepared to backtrack and figure out which PR broke the build.
- That's why we have tools like the [NuttX Dashboard](https://github.com/apache/nuttx/issues/14558), to detect breakage earlier without depending on GitHub CI.
- Also we should show some love and respect to NuttX Devs: Previously they waited 2.5 hours for All CI Checks. Now they wait at most 1.5 hours, I think we should stick to this.

# Live Metric for Full-Time Runners

TODO

ASF Infra Reports are still down. But now we have our own __Live Metrics for Full-Time GitHub Runners!__ (reload for updates)

![](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png)

[(Live Image)](https://lupyuen.github.io/nuttx-metrics/github-fulltime-runners.png) [(Live Log)](https://github.com/lupyuen/nuttx-metrics/blob/main/compute-github-runners.log)

This shows the number of __Full-Time Runners for the Day__, computed since 00:00 UTC. (Remember: We should keep this below 25)
- __Date:__ We compute the Full-Time Runners for today's date only (UTC)
- __Elapsed Hours:__ Number of hours elapsed since 00:00 UTC
- __GitHub Job Hours:__ Duration of all `nuttx` and `nuttx-apps` GitHub Jobs (cancelled / completed / failed). This data is available only AFTER the job has been cancelled / completed / failed (might be a lag of 1.5 hours). This is the Elapsed Job Duration, it doesn't say that we're running 8 smaller jobs in parallel, that's why we need...
- __GitHub Runner Hours:__ Number of GitHub Runners * Job Duration, which is effectively the Chargeable Minutes by GitHub. We compute this as 8 * GitHub Job Hours. This is [averaged from past data](https://docs.google.com/spreadsheets/d/1ujGKmUyy-cGY-l1pDBfle_Y6LKMsNp7o3rbfT1UkiZE/edit?gid=1163309346#gid=1163309346). (Remember: One GitHub Runner will run One Single Sub-Job, like arm-01)
- __Full-Time GitHub Runners:__ Equals GitHub Runner Hours / Elapsed Hours. It means "How many GitHub Runners, running Full-Time, in order to consume the GitHub Runner Hours". (We should keep this below 25 per day, per week, per month, etc)

How it works:
- [compute-github-runners.sh](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners.sh) calls GitHub API to add up the Duration of All Completed GitHub Jobs for today. Then it extrapolates the Number of Full-Time GitHub Runners. (1 GitHub Job Hour roughly equals 8 GitHub Runner Hours, which equals 8 Full-Time Runners Per Hour)
- [run.sh](https://github.com/lupyuen/nuttx-metrics/blob/main/run.sh) calls the script above to render the Full-Time GitHub Runners as a PNG (with ImageMagick)

# Monitoring our CI Servers 24 x 7

TODO

This runs on my 4K TV (Xiaomi 65-inch) all day, all night:

![Screenshot 2024-10-28 at 1 53 26 PM](https://github.com/user-attachments/assets/3f862ed6-8890-4d00-99e1-f5b8352ddcd1)

When I'm out on [Overnight Hikes](https://www.strava.com/activities/12737067287): I check my phone at every water break:
![GridArt_20241028_150938083](https://github.com/user-attachments/assets/88232734-aecc-4af8-bc0e-641db1cfdf9e)

I have GitHub Scripts that will run on Termux Android (remember to `pkg install gh` and set `GITHUB_TOKEN`):
- [enable-macos-windows2.sh](https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows2.sh): Enable the macOS and Windows Builds
- [compute-github-runners2.sh](https://github.com/lupyuen/nuttx-release/blob/main/compute-github-runners2.sh): Compute the number of Full-Time GitHub Runners for the day
- [kill-push-master.sh](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh): Cancel all Merge Jobs

# Final Verdict

TODO

__0 Days to Final Audit:__ ASF Infra Team will be checking on us one last time today! Yesterday was a super busy Tuesday, we consumed __15 Full-Time GitHub Runners__ (peaked briefly at 31)

![Screenshot 2024-10-30 at 6 02 25 AM](https://github.com/user-attachments/assets/538b9903-51d0-43e4-9537-fbd6e4d8d742)

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

[Running CI Checks before submitting PR](https://github.com/apache/nuttx/issues/14601#issuecomment-2452875114)

[Verify a PR after merging](https://github.com/apache/nuttx/issues/14407)

macos

merge jobs
auto kill merge jobs
restart merge jobs
why network error?

mirror repo
enable windows and macos
that's cheating ain't it? moving from one freebie to another freebit?
yeah we might run our own build farm

simple vs complex pr

build rules

runner live updates widget

termux anywhere
gh and token
`pkg install gh`
24x7 monitoring

after 1 whole night of deliberation
we put our plan into action
google sheet analyse github runner minutes vs elapsed runtime

script to start jobs

nuttx website docs
https://github.com/apache/nuttx-website/blob/master/.github/workflows/main.yml
30 github minutes

It's Oct 31 and our CI Servers are still running. We made it yay! 🎉

We got plenty to do:

1. We made lots of fixes to the CI Workflow. I'll document everything in an article.

2. Become more resilient and self-sufficient with [Our Own Build Farm](https://lupyuen.codeberg.page/articles/ci2.html) (away from GitHub)

3. Analyse our Build Logs with [Our Own Tools](https://github.com/apache/nuttx/issues/14558) (instead of GitHub)

Thank you everyone for making this happen! 🙏

- Excellent Initiative by @raiden00pl: We __Merge Multiple Targets__ into One Target, and reduce the build time

  https://github.com/apache/nuttx/pull/14410

Yeah it doesn't sound right that an Unpaid Volunteer is monitoring our CI Servers 24 x 7 🤔
![PXL_20241020_114213194](https://github.com/user-attachments/assets/e25badb4-112b-4392-8605-7427aee47b89)

# Our Wishlist

TODO

> We have the https://github.com/nuttx organization too maybe we can make use of it too? :-)

I think we learnt a Painful Lesson today: Freebies Won't Last Forever! The new GitHub Org for NuttX should probably be a __Paid GitHub Org__:
- New GitHub Org shall be sponsored by our generous Stakeholder Companies (Espressif, Sony, Xiaomi, ...)
- New GitHub Org shall be maintained by a Paid Employee of our Stakeholder Companies
- Which means clicking Twice Per Day to trigger the [Scheduled Merge Jobs](https://github.com/nuttxpr/nuttx/actions) (I'm getting tired of this)
- And restarting the Scheduled Merge Job (if it fails). Also: [Killing the Old Merge Jobs](https://github.com/lupyuen/nuttx-release/blob/main/kill-push-master.sh)
- New GitHub Org shall host the Official Downloads of NuttX Compiled Binaries (for our upcoming Board Testing Farm)
- New GitHub Org will eventually offload more CI Jobs from our GitHub Repos (e.g. macOS and Windows Builds)

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

Hi @xiaoxiang781216 @GUIDINGLI @cederom @raiden00pl @acassis @jerpelea: With immediate effect, please see [__github.com/nuttxpr/nuttx__](https://github.com/nuttxpr/nuttx/actions) for our Merge Jobs. I will trigger the jobs daily at 00:00 UTC and 12:00 UTC. I have given you Admin Access to `nuttxpr` in case you need to restart the jobs. Thanks!

# Appendix: Verify our PR Merge

TODO

_When NuttX merges our PR, the Merge Job won't run until 00:00 UTC and 12:00 UTC. How can we be really sure that our PR was merged correctly?_

Let's create a __GitHub Org__ (at no cost), fork the NuttX Repo and trigger the __CI Workflow__. (Which won't charge any extra GitHub Runner Minutes to NuttX Project!)

- https://github.com/apache/nuttx/issues/14407

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
https://github.com/apache/nuttx/actions/runs/11395811301/attempts/1

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
- https://github.com/actions/actions-runner-controller/issues/393
- [Docker MTU issues and solutions](https://mlohr.com/docker-mtu/)

Meanwhile I'm running a script to Restart Failed Jobs on our NuttX Mirror Repos: [restart-failed-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/restart-failed-job.sh)
