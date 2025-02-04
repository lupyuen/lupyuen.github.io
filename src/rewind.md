# Auto-Rewind for Daily Test (Apache NuttX RTOS)

📝 _26 Feb 2025_

![Auto-Rewind for Daily Test (Apache NuttX RTOS)](https://lupyuen.org/images/rewind-title.jpg)

If the __Daily Test__ fails for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) ... Can we __Auto-Rewind__ and discover the __Breaking Commit__? Let's try this (pic above)

1.  Every Day at 00:00 UTC: __Ubuntu Cron__ shall trigger a __Daily Build and Test__ of NuttX for __QEMU RISC-V__ _(knsh64 / 64-bit Kernel Build)_

1.  __If The Test Fails:__ Our Machine will __Backtrack The Commits__, rebuilding and retesting each commit _(on QEMU Emulator)_

1.  When it discovers the __Breaking Commit__: Our Machine shall post a [__Mastodon Alert__](https://nuttx-feed.org/@nuttx_build/113922504467871604), that includes the _(suspicious)_ __Pull Request__

1.  __Bonus:__ The Machine will draft a [__Polite Note__](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4801057) for our NuttX Colleague to investigate the Pull Request, please

    ![Auto-Rewind for Daily Test (Apache NuttX RTOS)](https://lupyuen.org/images/rewind-mastodon3.png)

_Why are we doing this?_

If NuttX Fails on __QEMU RISC-V__: High chance that NuttX will also fail on __RISC-V SBCs__ like Ox64 BL808 and Oz64 SG2000.

Thus it's important to Nip the Bud and Fix the Bug early, before it hurts our RISC-V Devs. _(Be Kind, Rewind!)_

![Find the Breaking Commit](https://lupyuen.org/images/rewind-title2.jpg)

# Find the Breaking Commit

We wrote a script that will __Rewind the NuttX Build__ and discover the Breaking Commit...

```bash
## Set the GitLab Token, check that it's OK
## export GITLAB_TOKEN=...
. $HOME/gitlab-token.sh
glab auth status

## Set the GitLab User and Repo for posting GitLab Snippets
export GITLAB_USER=lupyuen
export GITLAB_REPO=nuttx-build-log

## Download the NuttX Rewind Script
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm

## Find the Breaking Commit for QEMU RISC-V (64-bit Kernel Build)
nuttx_hash=  ## Optional: Begin with this NuttX Hash
apps_hash=   ## Optional: Begin with this Apps Hash
./rewind-build.sh \
  rv-virt:knsh64_test \
  $nuttx_hash \
  $apps_hash
```

Our Rewind Script runs __20 Iterations of Build + Test__...

```bash
## Build and Test: Latest NuttX Commit
git reset --hard HEAD
tools/configure.sh rv-virt:knsh64
make -j
qemu-system-riscv64 -kernel nuttx

## Build and Test: Previous NuttX Commit
git reset --hard HEAD~1
tools/configure.sh rv-virt:knsh64
make -j
qemu-system-riscv64 -kernel nuttx
...
## Build and Test: 20th NuttX Commit
git reset --hard HEAD~19
tools/configure.sh rv-virt:knsh64
make -j
qemu-system-riscv64 -kernel nuttx

## Roughly One Hour for 20 Rewinds of Build + Test
```

(What about Git Bisect? We'll come back to this)

_Build and Test 20 times! Won't it look mighty messy?_

Ah that's why we present neatly the __20 Outcomes__ (Build + Test) as the [__NuttX Build History__](https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?from=now-7d&to=now&timezone=browser&var-arch=$__all&var-subarch=$__all&var-board=rv-virt&var-config=knsh64_test6&var-group=$__all&var-Filters=), inside our [__NuttX Dashboard__](https://lupyuen.github.io/articles/ci4)...

![NuttX Build History](https://lupyuen.org/images/rewind-history.png)

What's inside our script? We dive in...

[(Which __Apps Hash__ to use? NuttX Build History can help)](https://lists.apache.org/thread/4oqjrwnzoq41tm0r6bl8bsgwbqokc4kp)

> ![Testing One Commit](https://lupyuen.org/images/rewind-title3.jpg)

# Testing One Commit

_How to find the Breaking Commit?_

We zoom out and explain slowly, from Micro to Macro. This script will __Build and Test NuttX__ for __One Single Commit__ on QEMU: [build-test-knsh64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-knsh64.sh)

```bash
## Build and Test NuttX for QEMU RISC-V 64-bit (Kernel Build)
## Download NuttX and Apps
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps

## Switch to this NuttX Commit and Apps Commit
pushd nuttx ; git reset --hard $nuttx_hash ; popd
pushd apps  ; git reset --hard $apps_hash  ; popd

## Configure the NuttX Build
cd nuttx
tools/configure.sh rv-virt:knsh64

## Build the NuttX Kernel
make -j

## Build the NuttX Apps
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Boot NuttX on QEMU RISC-V 64-bit
## Run OSTest with our Expect Script
wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-knsh64.exp
expect qemu-riscv-knsh64.exp
```

[(__Expect Script__ shall validate the QEMU Output)](https://github.com/lupyuen/nuttx-riscv64/blob/main/qemu-riscv-knsh64.exp)

The script above is called by __build_nuttx__ below. Which will wrap the output in the Log Format that __NuttX Dashboard__ expects: [rewind-commit.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh)

```bash
## Build and Test One Commit
function build_nuttx { ...

  ## NuttX Dashboard expects this Log Format
  echo "===================================================================================="
  echo "Configuration/Tool: rv-virt/knsh64_test,"
  echo "$timestamp"
  echo "------------------------------------------------------------------------------------"

  ## Build and Test Locally: QEMU RISC-V 64-bit Kernel Build
  $script_dir/build-test-knsh64.sh \
    $nuttx_commit \
    $apps_commit
  res=$?

  ## Omitted: Build and Test Other Targets
  echo "===================================================================================="
}
```

Our [__Test Log__](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85) looks like this...

TODO: Sample Build / Test Log

For Every Commit, we bundle __Three Commits__ into a single Log File: _This Commit, Previous Commit, Next Commit_: [rewind-commit.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-commit.sh#L133-L169)

```bash
## Build and Test This Commit
build_nuttx $nuttx_hash $apps_hash

## If Build / Test Fails...
if [[ "$res" != "0" ]]; then
  echo "BUILD / TEST FAILED FOR THIS COMMIT: nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash"

  ## Rebuild / Retest with the Previous Commit
  build_nuttx $prev_hash $apps_hash
  if [[ "$res" != "0" ]]; then
    echo "BUILD / TEST FAILED FOR PREVIOUS COMMIT: nuttx @ $prev_hash / nuttx-apps @ $apps_hash"
  fi

  ## Rebuild / Retest with the Next Commit
  build_nuttx $next_hash $apps_hash
  if [[ "$res" != "0" ]]; then
    echo "BUILD / TEST FAILED FOR NEXT COMMIT: nuttx @ $next_hash / nuttx-apps @ $apps_hash"
  fi
fi

## Why the Long Echoes? We'll ingest them later
```

Our Three-In-One Log becomes a little easier to read, less flipping back and forth. Let's zoom out...

![Testing 20 Commits](https://lupyuen.org/images/rewind-title4.jpg)

# Testing 20 Commits

_Who calls the script above: rewind-commit.sh?_

The script above is called by __run_job__ below: [rewind-build.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L105-L128)

```bash
## Build and Test This Commit
## And capture the Build / Test Output
function run_job { ...
  script $log_file \
    $script_option \
    " \
      $script_dir/rewind-commit.sh \
        $target \
        $nuttx_hash $apps_hash \
        $timestamp \
        $prev_hash $next_hash \
    "
}
```

Which captures the __Build / Test Output__ into a Log File.

What happens to the __Log File__? We upload and publish it as a __GitLab Snippet__: [rewind-build.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L75-L105)

```bash
## Build and Test One Commit for the NuttX Target
function build_commit { ...

  ## Build and Test This Commit
  ## And capture the Build / Test Output into a Log File
  run_job \
    $log $timestamp \
    $apps_hash $nuttx_hash \
    $prev_hash $next_hash
  clean_log $log
  find_messages $log

  ## Upload the Build / Test Log File
  ## As GitLab Snippet
  upload_log \
    $log unknown \
    $nuttx_hash $apps_hash \
    $timestamp
}
```

[(__upload_log__ creates the GitLab Snippet)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L172-L205)

[(__GitHub Gists__ are supported too)](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L172-L205)

Remember we need to Build and Test __20 Commits__? We call the script above 20 times: [rewind-build.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh#L205-L275)

```bash
## Build and Test the Latest 20 Commits
num_commits=20
num_success=0
count=1
for commit in $(
  TZ=UTC0 \
  git log \
  -$(( $num_commits + 1 )) \
  --date='format-local:%Y-%m-%dT%H:%M:%S' \
  --format="%cd,%H"
); do
  ## Extract the Commit Timestamp and Commit Hash
  ## Commit looks like 2024-11-24T09:52:42,9f9cc7ecebd97c1a6b511a1863b1528295f68cd7
  prev_timestamp=$(echo $commit | cut -d ',' -f 1)  ## 2024-11-24T09:52:42
  prev_hash=$(echo $commit | cut -d ',' -f 2)       ## 9f9cc7ecebd97c1a6b511a1863b1528295f68cd7

  ## Build and Test the NuttX Hash + Apps Hash
  ## If It Fails: Build and Test the Previous NuttX Hash + Previous Apps Hash
  build_commit \
    $tmp_dir/$nuttx_hash.log \
    $timestamp \
    $apps_hash $nuttx_hash \
    $prev_hash $next_hash

  ## Shift the Commits
  ## Omitted: Skip the First Commit (because we need a Previous Commit)
  next_hash=$nuttx_hash
  nuttx_hash=$prev_hash
  timestamp=$prev_timestamp
  ((count++)) || true

  ## Stop when we have reached the
  ## Minimum Number of Successful Commits
  if [[ "$num_success" == "$min_commits" ]]; then
    break
  fi
done
```

TODO: Breaking Commit

![Ingest the Test Log](https://lupyuen.org/images/rewind-title5.jpg)

# Ingest the Test Log

_Why publish the Test Log as a GitLab Snippet?_

That's because we'll Ingest the Test Log into our __NuttX Dashboard__. (So we can present the logs neatly as __NuttX Build History__)

This is how we __Ingest a Test Log__ into our [__Prometheus Time-Series Database__](https://lupyuen.github.io/articles/ci4#prometheus-metrics) (that powers our NuttX Dashboard)...

```bash
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{ 

  ## These fields shall be rendered in Grafana (NuttX Dashboard and Build History)
  timestamp="2025-01-11T10:54:36",
  user="rewind",
  board="rv-virt",
  config="knsh64_test",
  target="rv-virt:knsh64_test",
  url="https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85",

  ## Here's the NuttX Hash and Apps Hash for This Commit
  nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5",
  apps_hash="a6b9e718460a56722205c2a84a9b07b94ca664aa",

  ## Previous Commit is OK (Score=1)
  nuttx_hash_prev="be40c01ddd6f43a527abeae31042ba7978aabb58",
  apps_hash_prev="a6b9e718460a56722205c2a84a9b07b94ca664aa",
  build_score_prev="1",

  ## Next Commit is Not OK (Score=0)
  nuttx_hash_next="48846954d8506e1c95089a8654787fdc42cc098c",
  apps_hash_next="a6b9e718460a56722205c2a84a9b07b94ca664aa",
  build_score_next="0"

} 0  ## Means This Commit Failed (Score=0)
```

__Hello Prometheus:__ We're sending you this __Test Log__ at the Specified URL...

- __NuttX Target__ is QEMU RISC-V _(rv-virt:knsh64)_

- __Previous Commit__ is OK _(Previous Score = 1)_

- __Next Commit__ is NOT OK _(Next Score = 0)_

- __This Commit__ is NOT OK _(This Score = 0)_

  [(See the __Complete Log__)](https://gist.github.com/lupyuen/e5f9d4d3e113b3ed3bc1726c7ebb9897#file-gistfile1-txt-L553-L578)

Which is transformed and transmitted by our __Rust App__, from GitLab Snippet to Prometheus: [ingest-nuttx-builds/main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L589-L703)

```rust
// Post the Test Log to Prometheus Pushgateway
async fn post_to_pushgateway( ... ) -> ... { ...

  // Compose the Pushgateway Metric
  let body = format!(
r##"
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score ... version="{version}" ... {build_score}
"##);

  // Send the Metric to Pushgateway via HTTP POST
  let client = reqwest::Client::new();
  let pushgateway = format!("http://localhost:9091/metrics/job/{user}/instance/{target_rewind}");
  let res = client
    .post(pushgateway)
    .body(body)
    .send()
    .await?;
}
```

[(How we fetch __GitLab Snippets__)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L171-L263)

[(And __Extract the Fields__ from Test Logs)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L704-L760)

[(See the __Rust App Log__)](https://gist.github.com/lupyuen/e5f9d4d3e113b3ed3bc1726c7ebb9897)

TODO: Breaking Commit

![Query Prometheus for Breaking Commit](https://lupyuen.org/images/rewind-title6.jpg)

# Query Prometheus for Breaking Commit

_Test Logs are now inside Prometheus Database. How will Prometheus tell us the Breaking Commit?_

Recall that our __Prometheus Database__ contains...

- __20 Test Logs__ and their Outcomes:

  _Commit is OK or Failed_

- Each Test Log contains __Three Outcomes__:

  _This Commit vs Previous Commit vs Next Commit_

The __Test Logs__ in Prometheus will look like this...

<span style="font-size:80%">

| | |
|:---:|:---|
| _Test Log #1_ | This Commit _FAILED_ <br> Previous Commit _FAILED_
| _Test Log #2_ | This Commit _FAILED_ <br> Previous Commit _FAILED_
| ...
| _Test Log #6_ | This Commit _FAILED_ <br> Previous Commit is __OK__
| _Test Log #7_ | This Commit is __OK__
| _Test Log #8_ | This Commit is __OK__
| _Test Log #9_ | This Commit is __OK__
| &nbsp;

</span>

Ding ding: __Test Log #6__ will reveal the [__Breaking Commit__](https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?from=now-7d&to=now&timezone=browser&var-arch=$__all&var-subarch=$__all&var-board=rv-virt&var-config=knsh64_test6&var-group=$__all&var-Filters=)!

![NuttX Build History](https://lupyuen.org/images/rewind-history.png)

_Inside Prometheus: How to find Test Log #6?_

We fetch the Breaking Commit with this __Prometheus Query__...

```bash
build_score{
  target="rv-virt:knsh64_test",
  build_score_prev="1"
} == 0
```

__Dear Prometheus:__ Please find the __Test Log__ that matches...

- __NuttX Target__ is QEMU RISC-V _(rv-virt:knsh64)_

- __Previous Commit__ is OK _(Previous Score = 1)_

- __This Commit__ is NOT OK _(This Score = 0)_

Prometheus returns the __Breaking Commit__ that we seek...

TODO: Screenshot of Prometheus

Coded in our __Rust App__ like so: [nuttx-rewind-notify/main.rs](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L44-L73)

```rust
// Query Prometheus for the Breaking Commit
let query = format!(r##"
  build_score{ ...
    target="{TARGET}",
    build_score_prev="1"
  ... } == 0
"##);

// Send query to Prometheus via HTTP Form Post
let params = [("query", query)];
let client = reqwest::Client::new();
let prometheus = format!("http://{prometheus_server}/api/v1/query");
let res = client
  .post(prometheus)
  .form(&params)
  .send()
  .await?;

// Process the Query Results (Breaking Commit)
let body = res.text().await?;
let data: Value = serde_json::from_str(&body).unwrap();
let builds = &data["data"]["result"];
```

![Write a Polite Note](https://lupyuen.org/images/rewind-title7.jpg)

# Write a Polite Note

_Great! Our Machine has auto-discovered the Breaking Commit. But Our Machine can't fix it right?_

Here comes the Human-Computer Interface: Our Machine (kinda) __Escalates the Breaking Commit__ to a Human Expert for fixing, politely please...

<span style="font-size:80%">

> Sorry @USERNAME: The above PR is failing for rv-virt:knsh64_test. Could you please take a look? Thanks! [_nuttx-build-log/snippets/4800059_](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85)

```text
$ git clone https://github.com/apache/nuttx
$ git clone https://github.com/apache/nuttx-apps apps
$ pushd nuttx
$ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
$ popd
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
$ cd nuttx
$ tools/configure.sh rv-virt:knsh64
$ make -j
...
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
riscv_exception: Segmentation fault in PID 2: /system/bin/init
```
> [(Earlier Commit is OK)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800063#L80)
[(See the Build History)](https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board=rv-virt&var-config=knsh64_test6)

</span>

This goes to our [__Mastodon Server__](https://lupyuen.github.io/articles/mastodon) for NuttX Continuous Integration. I'll copy this and paste it as a PR Comment, after my vetting.

_Our Machine writes this based on the Breaking Commit? From the Previous Section?_

Exactly! We won't explain the [__Dull Bits__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L81-L251), involving...

1.  Extracting the [__Test Log__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L140-L157)

    _(Only the [__Important Parts__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L251-L331))_

1.  Fetching the [__Breaking PR from GitHub__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L109-L138)

    _(Based on the Breaking Commit)_

1.  Composing the [__Mastodon Post__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L157-L178)

    _(And [__Posting to Mastodon__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L178-L220))_

1.  __Without__ any AI or LLM

    _(Because they ain't cheap)_

_But Mastodon Posts are limited to 500 chars?_

Bummer. That's why we [__Create a GitLab Snippet__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L364-L410) for our Polite Note. And embed the Hyperlink in our Mastodon Post.

_How to get the Breaking PR from GitHub?_

We call the [__GitHub API__](https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#list-pull-requests-associated-with-a-commit)...

```bash
## Fetch the Pull Request for this Commit
$ commit=be40c01ddd6f43a527abeae31042ba7978aabb58
$ curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/apache/nuttx/commits/$commit/pulls

[{ html_url: "https://github.com/apache/nuttx/pull/15444",
   title:    "modlib: preprocess gnu-elf.ld for executable ELF",
   user: { login: "GITHUB_USERID", ...
```

Which [__becomes this function__](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L109-L138) in our Rust App.

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ba6a33c4c021f0437a95117784e5190b)

[(Searching for __NuttX Commit__ in Prometheus)](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/src/main.rs#L331-L364)

> ![Cron Job for Daily Test and Rewind](https://lupyuen.org/images/rewind-title8.jpg)

# Cron Everything

_We coded plenty of goodies over the Lunar New Year. How will they be triggered?_

Via [__Ubuntu Cron__](https://help.ubuntu.com/community/CronHowto). Every Day it shall trigger the __Daily Test and Rewind__ (pic above)

```bash
## Add a Cron Job
$ crontab -e

## Then insert this...
## Test and Rewind: Every Day at 00:00 UTC
0 0 * * * /home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build

## Or For Testing...
## Test and Rewind: Every Hour at 00:16, 01:16, 12:16, ...
16 * * * * /home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build

## Exit and Monitor our Cron Job
$ tail -f /var/log/syslog
```

[(__cron.sh__ will start _rewind-build.sh_)](https://github.com/lupyuen/nuttx-build-farm/blob/main/cron.sh)

We'll see the __Test and Rewind__ in action...

<span style="font-size:80%">

```bash
(luppy) CMD (/home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build)
+ ./rewind-build.sh rv-virt:knsh64_test HEAD HEAD 1 20
  /tmp/rewind-build-rv-virt:knsh64_test/apps /tmp/rewind-build-rv-virt:knsh64_test
  #1 of 20: Building nuttx @ 8995e5a66e14819e2bfda467d4f9fb8719fd9134 / nuttx_apps @ 43439a6b16a435bce7d9ac85f05c3a6013f91348
+ build_commit /tmp/rewind-build-rv-virt:knsh64_test/8995e5a66e14819e2bfda467d4f9fb8719fd9134.log 2025-02-03T08:21:26 43439a6b16a435bce7d9ac85f05c3a6013f91348 8995e5a66e14819e2bfda467d4f9fb8719fd9134 dc5251f9c8db878ac9706586eb85ad7e201286b6 8995e5a66e14819e2bfda467d4f9fb8719fd9134
+ run_job /tmp/rewind-build-rv-virt:knsh64_test/8995e5a66e14819e2bfda467d4f9fb8719fd9134.log 2025-02-03T08:21:26 43439a6b16a435bce7d9ac85f05c3a6013f91348 8995e5a66e14819e2bfda467d4f9fb8719fd9134 dc5251f9c8db878ac9706586eb85ad7e201286b6 8995e5a66e14819e2bfda467d4f9fb8719fd9134
+ script /tmp/rewind-build-rv-virt:knsh64_test/8995e5a66e14819e2bfda467d4f9fb8719fd9134.log -c '       /home/luppy/nuttx-build-farm/rewind-commit.sh         rv-virt:knsh64_test         8995e5a66e14819e2bfda467d4f9fb8719fd9134         43439a6b16a435bce7d9ac85f05c3a6013f91348         2025-02-03T08:21:26         dc5251f9c8db878ac9706586eb85ad7e201286b6         8995e5a66e14819e2bfda467d4f9fb8719fd9134     '
+ /home/luppy/nuttx-build-farm/build-test-knsh64.sh 8995e5a66e14819e2bfda467d4f9fb8719fd9134 43439a6b16a435bce7d9ac85f05c3a6013f91348#015
...
+ glab snippet new --repo lupyuen/nuttx-build-log --visibility public --title '[unknown] CI Log for rv-virt:knsh64_test @ 2025-02-03T08:21:26 / nuttx @ 8995e5a66e14819e2bfda467d4f9fb8719fd9134 / nuttx-apps @ 43439a6b16a435bce7d9ac85f05c3a6013f91348' --filename ci-unknown.log
  Creating snippet in https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4802191
  Done!
```

</span>

[(See the __Complete Log__)](https://gist.github.com/lupyuen/0fadc12338b5f9a0275c0682b2f72456)

[(See the __GitLab Snippets__)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets)

> ![Cron Jab for Mastodon Notification](https://lupyuen.org/images/rewind-title9.jpg)

_And the Polite Note? That goes to our Mastodon Server?_

Every 15 Minutes: Ubuntu Cron shall trigger the __Mastodon Notification__ (pic above)

```bash
## Add a Cron Job
$ crontab -e

## Then insert this...
## Notify Mastodon: Every 15 minutes
*/15 * * * * /home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify

## Or For Testing...
## Notify Mastodon: Every Hour at 00:16, 01:16, 12:16, ...
16 * * * * /home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify

## Exit and Monitor our Cron Job
$ tail -f /var/log/syslog
```

[(__cron.sh__ will start our Rust App)](https://github.com/lupyuen/nuttx-rewind-notify/blob/main/cron.sh)

The __Mastodon Notification__ appears like so...

<span style="font-size:80%">

```bash
(luppy) CMD (/home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify)
+ cargo run
build_score{
  target="rv-virt:knsh64_test",
  build_score_prev="1"
} == 0
rv-virt : KNSH64_TEST - Build Failed (rewind)
  Breaking PR: https://github.com/apache/nuttx/pull/15444
  Build History: https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board=rv-virt&var-config=knsh64_test6
  Sorry @USERNAME: The above PR is failing for rv-virt:knsh64_test. Could you please take a look? Thanks!
```

</span>

[(See the __Complete Log__)](https://gist.github.com/lupyuen/65c58383ffc53f616990995d97667ddf)

![Auto-Rewind for Daily Test (Apache NuttX RTOS)](https://lupyuen.org/images/rewind-title.jpg)

# Be Kind, Rewind!

1.  _Wow this looks super complicated. Does it work?_

    Dunno, we're still testing? Hopefully the New System will make my __Daily Routine__ a little less painful...

    - Every Morning: I check the [__NuttX Daily Test__](https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-12)

    - Oops Daily Test failed! I run a script to [__Rewind or Bisect__](https://github.com/lupyuen/nuttx-riscv64/blob/main/special-qemu-riscv-knsh64.sh#L45-L61) the Daily Build

    - I write a [__Polite Note__](https://github.com/apache/nuttx/pull/15444#issuecomment-2585595498) _(depending on my mood)_

    - And post it to the __Breaking Pull Request__

    That's why we're __Fast Tracking__ the complicated new system: Right now it runs __Every Hour__. (Instead of every day)

1.  _What if it's a smashing success?_

    We might extend the __Daily Rewind__ to a Real Board: [__Oz64 SG2000 RISC-V SBC__](https://lupyuen.github.io/articles/sg2000a).

    Or maybe [__SG2000 Emulator__](https://lupyuen.github.io/articles/sg2000b) and [__Ox64 Emulator__](https://lupyuen.github.io/articles/tinyemu3), since they're quicker and more consistent than Real Hardware. (Though less accurate)

    Plus other __QEMU Targets__: _rv-virt:nsh / nsh64 / knsh_

1.  _Suppose we wish to add Our Own Boards to the System?_

    Let's assume we have __Automated Board Testing__. Then we could upload the __NuttX Test Logs__ _(in the prescribed format)_ to GitLab Snippets or GitHub Gists. They'll appear in NuttX Dashboard and Build History.

    (Rewinding the Build on Our Own Boards? Needs more work)

1.  _Why Rewind every commit? Isn't Git Bisect quicker?_

    Ah remember that we're fixing Runtime Bugs, not Compile Errors. Git Bisect won't work if the Runtime Bug is [__Not Reliably Reproducible__](https://lupyuen.github.io/articles/bisect#good-commit-goes-bad).

    When we Rewind 20 Commits, we'll know if the bug is Reliably Reproducible.

1.  _Why aren't we using Docker?_

    Docker doesn't run OSTest correctly on [__QEMU RISC-V 64-bit__](https://lupyuen.github.io/articles/rust6#appendix-nuttx-qemu-risc-v-fails-on-github-actions).

1.  _Any more Grand Plans?_

    We might allow a __PR Comment__ to trigger a Build + Test on QEMU. For example, this PR Comment...

    ```bash
    @nuttxpr test rv-virt:knsh64
    ```

    Will trigger our __Test Bot__ to download the PR Code, and run Build + Test on QEMU RISC-V. Or on __Real Hardware__...

    ```bash
    @nuttxpr test milkv_duos:nsh
    ```
    
    Super helpful for __Testing Pull Requests__ before Merging. But might have [__Security Implications__](https://github.com/apache/nuttx/issues/15731#issuecomment-2628647886) 🤔

![Daily Test + Rewind is hosted on this hefty Ubuntu Xeon Workstation](https://lupyuen.org/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_Daily Test + Rewind is hosted on this hefty Ubuntu Xeon Workstation_](https://qoto.org/@lupyuen/113517788288458811)

</span>

# What's Next

Special Thanks to __Mr Gregory Nutt__ for your guidance and kindness. I'm also grateful to [__My Sponsors__](https://lupyuen.org/articles/sponsor), for supporting my writing. 

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/rewind.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/rewind.md)
