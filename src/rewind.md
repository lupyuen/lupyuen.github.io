# Auto-Rewind for Daily Test (Apache NuttX RTOS)

📝 _26 Feb 2025_

![TODO](https://lupyuen.github.io/images/rewind-title.jpg)

If the __Daily Test__ fails for [__Apache NuttX RTOS__](TODO)... Can we __Auto-Rewind__ and discover the __Breaking Commit__? Let's find out!

1.  Every Day at 00:00 UTC: [__Ubuntu Cron__](TODO) shall trigger a __Daily Buld and Test__ of NuttX for __QEMU RISC-V__ _(knsh64 / 64-bit Kernel Build)_

1.  __If The Test Fails:__ Our Machine will [__Backtrack The Commits__](TODO), rebuilding and retesting each commit _(on QEMU Emulator)_

1.  When it discovers the __Breaking Commit__: Our Machine shall post a [__Mastodon Alert__](TODO), that includes the _(suspicious)_ __Pull Request__

1.  __Bonus:__ The Machine will draft a [__Polite Note__](TODO) for our NuttX Colleague to investigate the Pull Request, please

_Why are we doing this?_

__If NuttX Fails on QEMU RISC-V:__ High chance that NuttX will also fail on __RISC-V SBCs__ like Ox64 BL808 and Oz64 SG2000.

Thus it's important to Nip the Bud and Fix the Bug, before it hurts our RISC-V Devs. _(Be Kind, Rewind!)_

# Find the Breaking Commit

Our script will __Rewind the NuttX Build__ and discover the Breaking Commit...

```bash
## Download the NuttX Rewind Scripts
git clone https://github.com/lupyuen/nuttx-build-farm
cd nuttx-build-farm

## Set the GitLab Token, check that it's OK
. ../gitlab-token.sh
glab auth status

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

_Build and Test 20 times? Won't the log be awfully messy?_

Ah that's why we neatly present the __20 Outcomes__ (Build + Test) as the __NuttX Build History__ (part of [__NuttX Dashboard__](TODO))

TODO: Pic of Build History

What's inside our script? We dive in...

[(Which __Apps Hash__ to use? NuttX Build History can help)](TODO)

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

[(__Expect Script__ shall validate the QEMU Output)](TODO)

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

# Ingest the Test Log

_Why publish the Test Log as a GitLab Snippet?_

That's because we'll Ingest the Test Log into our __NuttX Dashboard__. (So we can present the logs neatly as __NuttX Build History__)

This is how we __Ingest a Test Log__ into our [__Prometheus Time-Series Database__](TODO) (that powers our NuttX Dashboard)...

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

[(See the __Complete Log__)](https://gist.github.com/lupyuen/e5f9d4d3e113b3ed3bc1726c7ebb9897#file-gistfile1-txt-L553-L578)

Which is transmitted by our __Rust App__: [ingest-nuttx-builds/main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L589-L703)

```rust
// Post the Test Log to Prometheus Pushgateway
async fn post_to_pushgateway( ... ) -> ... { ...

  // Compose the Pushgateway Metric
  let body = format!(
r##"
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{{ version="{version}", timestamp="{timestamp}", timestamp_log="{timestamp_log}", user="{user}", arch="{arch}", subarch="{subarch}", group="{group}", board="{board}", config="{config}", target="{target}", url="{url}", url_display="{url_display}"{msg_opt}{nuttx_hash_opt}{apps_hash_opt}{prev_opt}{next_opt} }} {build_score}
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

[(How we fetch the __GitLab Snippets__)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L171-L263)

[(And __Extract the Fields__ from Test Logs)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L704-L760)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/e5f9d4d3e113b3ed3bc1726c7ebb9897)

TODO: Screenshot of Prometheus

TODO: Breaking Commit

# Query Prometheus for Breaking Commit

TODO

# Get Log

TODO

```text
Get Log

build_score{
target="rv-virt:knsh64_test5",
build_score_prev="1"
} == 0

Breaking Commit:
nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5"

build_score{
target="rv-virt:knsh64_test5",
nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5"
}

url="https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L85"

Starting at Line 85: Search for lines starting with "+ " or "spawn"

wget https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962/raw/main/ci-unknown.log
grep "^+ " ci-unknown.log

<<
+ /home/luppy/nuttx-build-farm/build-test-knsh64.sh 657247bda89d60112d79bb9b8d223eca5f9641b5 a6b9e718460a56722205c2a84a9b07b94ca664aa
+ nuttx_hash=657247bda89d60112d79bb9b8d223eca5f9641b5
+ apps_hash=a6b9e718460a56722205c2a84a9b07b94ca664aa
+ neofetch
+ tmp_path=/tmp/build-test-knsh64
+ rm -rf /tmp/build-test-knsh64
+ mkdir /tmp/build-test-knsh64
+ cd /tmp/build-test-knsh64
+ git clone https://github.com/apache/nuttx
+ git clone https://github.com/apache/nuttx-apps apps
+ [[ 657247bda89d60112d79bb9b8d223eca5f9641b5 != '' ]]
+ pushd nuttx
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
+ popd
+ [[ a6b9e718460a56722205c2a84a9b07b94ca664aa != '' ]]
+ pushd apps
+ git reset --hard a6b9e718460a56722205c2a84a9b07b94ca664aa
+ popd
+ set +x
+ riscv-none-elf-gcc -v
+ rustup --version
+ rustc --version
+ cd nuttx
+ tools/configure.sh rv-virt:knsh64
+ make -j
+ riscv-none-elf-size nuttx
+ make -j export
+ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
+ make -j import
+ popd
+ qemu-system-riscv64 --version
+ script=qemu-riscv-knsh64
+ wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-knsh64.exp
spawn qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
+ expect ./qemu-riscv-knsh64.exp
>>

Include Commit Info
<<
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
>>

Include QEMU and OpenSBI version
<<
+ qemu-system-riscv64 --version
QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.4)

+ expect ./qemu-riscv-knsh64.exp
spawn qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic

OpenSBI v1.3
>>

Extract Log from Line Number till "===== "
Extract 5 lines:
"+ git reset "
"NuttX Source: "
"NuttX Apps: "
"+ qemu"
"+ expect ./qemu"

Search for lines starting with "===== Error: Test Failed" or "===== Test OK"
Backtrack last 10 lines
```


# Get Hashes from Prometheus 

```text
TODO: Get hashes from Prometheus 

https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-12
NuttX Source: https://github.com/apache/nuttx/tree/aa0aecbd80a2ce69ee33ced41b7677f8521acd43
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa

https://github.com/apache/nuttx/pull/15444#issuecomment-2585595498
Sorry @yf13: This PR is causing "Instruction page fault" for rv-virt:knsh64. Wonder if there's something I missed in my testing steps? Thanks!

https://gist.github.com/lupyuen/60d54514ce9a8589b56ed6207c356d95#file-special-qemu-riscv-knsh64-log-L1396
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
+ tools/configure.sh rv-virt:knsh64
+ make -j
+ make export
+ pushd ../apps
+ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
+ make import
+ popd
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
QEMU emulator version 9.2.0
OpenSBI v1.5.1
ABC
riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
riscv_exception: Segmentation fault in PID 2: /system/bin/init
(Earlier Commit is OK)
```

# Query Prometheus

TODO

```text
Query prometheus for today's builds by rewind
Sort by timestamp_log

Search for
***** BUILD / TEST FAILED FOR THIS COMMIT: nuttx @ 657247bda89d60112d79bb9b8d223eca5f9641b5 / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
***** Build / Test OK for Previous Commit: nuttx @ be40c01ddd6f43a527abeae31042ba7978aabb58 / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
***** BUILD / TEST FAILED FOR NEXT COMMIT: nuttx @ 48846954d8506e1c95089a8654787fdc42cc098c / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799243#L1629

Sort by Log Timestamp
```

# Get Breaking PR

TODO

```text
Get Breaking PR

List pull requests associated with a commit
https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#list-pull-requests-associated-with-a-commit

commit=be40c01ddd6f43a527abeae31042ba7978aabb58
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/apache/nuttx/commits/$commit/pulls

[
  {
    "url": "https://api.github.com/repos/apache/nuttx/pulls/15444",
    "id": 2263146908,
    "node_id": "PR_kwDODZiUac6G5OGc",
    "html_url": "https://github.com/apache/nuttx/pull/15444",
    "diff_url": "https://github.com/apache/nuttx/pull/15444.diff",
    "patch_url": "https://github.com/apache/nuttx/pull/15444.patch",
    "issue_url": "https://api.github.com/repos/apache/nuttx/issues/15444",
    "number": 15444,
    "state": "closed",
    "locked": false,
    "title": "modlib: preprocess gnu-elf.ld for executable ELF",
    "user": {
      "login": "yf13",
      "id": 5899566,
      "node_id": "MDQ6VXNlcjU4OTk1NjY=",
      "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
      "gravatar_id": "",
      "url": "https://api.github.com/users/yf13",
      "html_url": "https://github.com/yf13",
      "followers_url": "https://api.github.com/users/yf13/followers",
      "following_url": "https://api.github.com/users/yf13/following{/other_user}",
      "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
      "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
      "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
      "organizations_url": "https://api.github.com/users/yf13/orgs",
      "repos_url": "https://api.github.com/users/yf13/repos",
      "events_url": "https://api.github.com/users/yf13/events{/privacy}",
      "received_events_url": "https://api.github.com/users/yf13/received_events",
      "type": "User",
      "user_view_type": "public",
      "site_admin": false
    },
    "body": "# Summary\r\n\r\nThis allows apps for kernel mode NuttX (e.g. on arm/qemu-armv7a) can be built as executable type ELF files. Benefits of executable programs are smaller in size and easier GDB debugging.\r\n\r\nInitial scope was only for qemu-armv7a but it used an almost duplicated `gnu-elf.ld` which differs only at `.text` and `.data` addresses from the `gnu-elf.ld` in modlib.  \r\n\r\nTo avoid such duplications, a preprocessed `gnu-elf.ld` in modlib is added  so that to adapt to target config. This requires minor tweaks for `addrenv.h` so that some macros can be included in `gnu-elf.ld.in`.\r\n\r\n# Impacts\r\n\r\nHardware: qemu-armv7a or using kernel build.\r\n\r\n# Testing\r\n\r\n- local checks with QEMU v6.2 on Ubuntu 22.04: `qemu-armv7a:knsh`, `bl602evb:elf`.\r\n- CI checks\r\n\r\n",
    "created_at": "2025-01-07T06:30:43Z",
    "updated_at": "2025-01-14T04:41:41Z",
    "closed_at": "2025-01-11T10:54:36Z",
    "merged_at": "2025-01-11T10:54:36Z",
    "merge_commit_sha": "ff488133c9348901fc6abd3890299a9f9d81dec6",
    "assignee": null,
    "assignees": [

    ],
    "requested_reviewers": [

    ],
    "requested_teams": [

    ],
    "labels": [
      {
        "id": 7292036618,
        "node_id": "LA_kwDODZiUac8AAAABsqOmCg",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Arch:%20all",
        "name": "Arch: all",
        "color": "DC5544",
        "default": false,
        "description": "Issues that apply to all architectures"
      },
      {
        "id": 7292038640,
        "node_id": "LA_kwDODZiUac8AAAABsqOt8A",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Arch:%20arm",
        "name": "Arch: arm",
        "color": "DC5544",
        "default": false,
        "description": "Issues related to ARM (32-bit) architecture"
      },
      {
        "id": 7292097170,
        "node_id": "LA_kwDODZiUac8AAAABsqSSkg",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Area:%20OS%20Components",
        "name": "Area: OS Components",
        "color": "0075ca",
        "default": false,
        "description": "OS Components issues"
      },
      {
        "id": 7486822345,
        "node_id": "LA_kwDODZiUac8AAAABvj_XyQ",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Size:%20S",
        "name": "Size: S",
        "color": "FEF2C0",
        "default": false,
        "description": "The size of the change in this PR is small"
      }
    ],
    "milestone": null,
    "draft": false,
    "commits_url": "https://api.github.com/repos/apache/nuttx/pulls/15444/commits",
    "review_comments_url": "https://api.github.com/repos/apache/nuttx/pulls/15444/comments",
    "review_comment_url": "https://api.github.com/repos/apache/nuttx/pulls/comments{/number}",
    "comments_url": "https://api.github.com/repos/apache/nuttx/issues/15444/comments",
    "statuses_url": "https://api.github.com/repos/apache/nuttx/statuses/1be695191cd77b426ac53914cf0ebc0e60617c8c",
    "head": {
      "label": "yf13:a7mi",
      "ref": "a7mi",
      "sha": "1be695191cd77b426ac53914cf0ebc0e60617c8c",
      "user": {
        "login": "yf13",
        "id": 5899566,
        "node_id": "MDQ6VXNlcjU4OTk1NjY=",
        "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/yf13",
        "html_url": "https://github.com/yf13",
        "followers_url": "https://api.github.com/users/yf13/followers",
        "following_url": "https://api.github.com/users/yf13/following{/other_user}",
        "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
        "organizations_url": "https://api.github.com/users/yf13/orgs",
        "repos_url": "https://api.github.com/users/yf13/repos",
        "events_url": "https://api.github.com/users/yf13/events{/privacy}",
        "received_events_url": "https://api.github.com/users/yf13/received_events",
        "type": "User",
        "user_view_type": "public",
        "site_admin": false
      },
      "repo": {
        "id": 730975045,
        "node_id": "R_kgDOK5HLRQ",
        "name": "nuttx",
        "full_name": "yf13/nuttx",
        "private": false,
        "owner": {
          "login": "yf13",
          "id": 5899566,
          "node_id": "MDQ6VXNlcjU4OTk1NjY=",
          "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
          "gravatar_id": "",
          "url": "https://api.github.com/users/yf13",
          "html_url": "https://github.com/yf13",
          "followers_url": "https://api.github.com/users/yf13/followers",
          "following_url": "https://api.github.com/users/yf13/following{/other_user}",
          "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
          "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
          "organizations_url": "https://api.github.com/users/yf13/orgs",
          "repos_url": "https://api.github.com/users/yf13/repos",
          "events_url": "https://api.github.com/users/yf13/events{/privacy}",
          "received_events_url": "https://api.github.com/users/yf13/received_events",
          "type": "User",
          "user_view_type": "public",
          "site_admin": false
        },
        "html_url": "https://github.com/yf13/nuttx",
        "description": "Apache NuttX is a mature, real-time embedded operating system (RTOS)",
        "fork": true,
        "url": "https://api.github.com/repos/yf13/nuttx",
        "forks_url": "https://api.github.com/repos/yf13/nuttx/forks",
        "keys_url": "https://api.github.com/repos/yf13/nuttx/keys{/key_id}",
        "collaborators_url": "https://api.github.com/repos/yf13/nuttx/collaborators{/collaborator}",
        "teams_url": "https://api.github.com/repos/yf13/nuttx/teams",
        "hooks_url": "https://api.github.com/repos/yf13/nuttx/hooks",
        "issue_events_url": "https://api.github.com/repos/yf13/nuttx/issues/events{/number}",
        "events_url": "https://api.github.com/repos/yf13/nuttx/events",
        "assignees_url": "https://api.github.com/repos/yf13/nuttx/assignees{/user}",
        "branches_url": "https://api.github.com/repos/yf13/nuttx/branches{/branch}",
        "tags_url": "https://api.github.com/repos/yf13/nuttx/tags",
        "blobs_url": "https://api.github.com/repos/yf13/nuttx/git/blobs{/sha}",
        "git_tags_url": "https://api.github.com/repos/yf13/nuttx/git/tags{/sha}",
        "git_refs_url": "https://api.github.com/repos/yf13/nuttx/git/refs{/sha}",
        "trees_url": "https://api.github.com/repos/yf13/nuttx/git/trees{/sha}",
        "statuses_url": "https://api.github.com/repos/yf13/nuttx/statuses/{sha}",
        "languages_url": "https://api.github.com/repos/yf13/nuttx/languages",
        "stargazers_url": "https://api.github.com/repos/yf13/nuttx/stargazers",
        "contributors_url": "https://api.github.com/repos/yf13/nuttx/contributors",
        "subscribers_url": "https://api.github.com/repos/yf13/nuttx/subscribers",
        "subscription_url": "https://api.github.com/repos/yf13/nuttx/subscription",
        "commits_url": "https://api.github.com/repos/yf13/nuttx/commits{/sha}",
        "git_commits_url": "https://api.github.com/repos/yf13/nuttx/git/commits{/sha}",
        "comments_url": "https://api.github.com/repos/yf13/nuttx/comments{/number}",
        "issue_comment_url": "https://api.github.com/repos/yf13/nuttx/issues/comments{/number}",
        "contents_url": "https://api.github.com/repos/yf13/nuttx/contents/{+path}",
        "compare_url": "https://api.github.com/repos/yf13/nuttx/compare/{base}...{head}",
        "merges_url": "https://api.github.com/repos/yf13/nuttx/merges",
        "archive_url": "https://api.github.com/repos/yf13/nuttx/{archive_format}{/ref}",
        "downloads_url": "https://api.github.com/repos/yf13/nuttx/downloads",
        "issues_url": "https://api.github.com/repos/yf13/nuttx/issues{/number}",
        "pulls_url": "https://api.github.com/repos/yf13/nuttx/pulls{/number}",
        "milestones_url": "https://api.github.com/repos/yf13/nuttx/milestones{/number}",
        "notifications_url": "https://api.github.com/repos/yf13/nuttx/notifications{?since,all,participating}",
        "labels_url": "https://api.github.com/repos/yf13/nuttx/labels{/name}",
        "releases_url": "https://api.github.com/repos/yf13/nuttx/releases{/id}",
        "deployments_url": "https://api.github.com/repos/yf13/nuttx/deployments",
        "created_at": "2023-12-13T04:50:13Z",
        "updated_at": "2025-01-22T05:52:32Z",
        "pushed_at": "2025-01-27T01:39:23Z",
        "git_url": "git://github.com/yf13/nuttx.git",
        "ssh_url": "git@github.com:yf13/nuttx.git",
        "clone_url": "https://github.com/yf13/nuttx.git",
        "svn_url": "https://github.com/yf13/nuttx",
        "homepage": "https://nuttx.apache.org/",
        "size": 315415,
        "stargazers_count": 2,
        "watchers_count": 2,
        "language": "C",
        "has_issues": false,
        "has_projects": true,
        "has_downloads": true,
        "has_wiki": false,
        "has_pages": true,
        "has_discussions": false,
        "forks_count": 0,
        "mirror_url": null,
        "archived": false,
        "disabled": false,
        "open_issues_count": 0,
        "license": {
          "key": "apache-2.0",
          "name": "Apache License 2.0",
          "spdx_id": "Apache-2.0",
          "url": "https://api.github.com/licenses/apache-2.0",
          "node_id": "MDc6TGljZW5zZTI="
        },
        "allow_forking": true,
        "is_template": false,
        "web_commit_signoff_required": false,
        "topics": [

        ],
        "visibility": "public",
        "forks": 0,
        "open_issues": 0,
        "watchers": 2,
        "default_branch": "master"
      }
    },
    "base": {
      "label": "apache:master",
      "ref": "master",
      "sha": "91c71ed00a61ca4ba46000be9e814074e6a70e49",
      "user": {
        "login": "apache",
        "id": 47359,
        "node_id": "MDEyOk9yZ2FuaXphdGlvbjQ3MzU5",
        "avatar_url": "https://avatars.githubusercontent.com/u/47359?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/apache",
        "html_url": "https://github.com/apache",
        "followers_url": "https://api.github.com/users/apache/followers",
        "following_url": "https://api.github.com/users/apache/following{/other_user}",
        "gists_url": "https://api.github.com/users/apache/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/apache/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/apache/subscriptions",
        "organizations_url": "https://api.github.com/users/apache/orgs",
        "repos_url": "https://api.github.com/users/apache/repos",
        "events_url": "https://api.github.com/users/apache/events{/privacy}",
        "received_events_url": "https://api.github.com/users/apache/received_events",
        "type": "Organization",
        "user_view_type": "public",
        "site_admin": false
      },
      "repo": {
        "id": 228103273,
        "node_id": "MDEwOlJlcG9zaXRvcnkyMjgxMDMyNzM=",
        "name": "nuttx",
        "full_name": "apache/nuttx",
        "private": false,
        "owner": {
          "login": "apache",
          "id": 47359,
          "node_id": "MDEyOk9yZ2FuaXphdGlvbjQ3MzU5",
          "avatar_url": "https://avatars.githubusercontent.com/u/47359?v=4",
          "gravatar_id": "",
          "url": "https://api.github.com/users/apache",
          "html_url": "https://github.com/apache",
          "followers_url": "https://api.github.com/users/apache/followers",
          "following_url": "https://api.github.com/users/apache/following{/other_user}",
          "gists_url": "https://api.github.com/users/apache/gists{/gist_id}",
          "starred_url": "https://api.github.com/users/apache/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/apache/subscriptions",
          "organizations_url": "https://api.github.com/users/apache/orgs",
          "repos_url": "https://api.github.com/users/apache/repos",
          "events_url": "https://api.github.com/users/apache/events{/privacy}",
          "received_events_url": "https://api.github.com/users/apache/received_events",
          "type": "Organization",
          "user_view_type": "public",
          "site_admin": false
        },
        "html_url": "https://github.com/apache/nuttx",
        "description": "Apache NuttX is a mature, real-time embedded operating system (RTOS)",
        "fork": false,
        "url": "https://api.github.com/repos/apache/nuttx",
        "forks_url": "https://api.github.com/repos/apache/nuttx/forks",
        "keys_url": "https://api.github.com/repos/apache/nuttx/keys{/key_id}",
        "collaborators_url": "https://api.github.com/repos/apache/nuttx/collaborators{/collaborator}",
        "teams_url": "https://api.github.com/repos/apache/nuttx/teams",
        "hooks_url": "https://api.github.com/repos/apache/nuttx/hooks",
        "issue_events_url": "https://api.github.com/repos/apache/nuttx/issues/events{/number}",
        "events_url": "https://api.github.com/repos/apache/nuttx/events",
        "assignees_url": "https://api.github.com/repos/apache/nuttx/assignees{/user}",
        "branches_url": "https://api.github.com/repos/apache/nuttx/branches{/branch}",
        "tags_url": "https://api.github.com/repos/apache/nuttx/tags",
        "blobs_url": "https://api.github.com/repos/apache/nuttx/git/blobs{/sha}",
        "git_tags_url": "https://api.github.com/repos/apache/nuttx/git/tags{/sha}",
        "git_refs_url": "https://api.github.com/repos/apache/nuttx/git/refs{/sha}",
        "trees_url": "https://api.github.com/repos/apache/nuttx/git/trees{/sha}",
        "statuses_url": "https://api.github.com/repos/apache/nuttx/statuses/{sha}",
        "languages_url": "https://api.github.com/repos/apache/nuttx/languages",
        "stargazers_url": "https://api.github.com/repos/apache/nuttx/stargazers",
        "contributors_url": "https://api.github.com/repos/apache/nuttx/contributors",
        "subscribers_url": "https://api.github.com/repos/apache/nuttx/subscribers",
        "subscription_url": "https://api.github.com/repos/apache/nuttx/subscription",
        "commits_url": "https://api.github.com/repos/apache/nuttx/commits{/sha}",
        "git_commits_url": "https://api.github.com/repos/apache/nuttx/git/commits{/sha}",
        "comments_url": "https://api.github.com/repos/apache/nuttx/comments{/number}",
        "issue_comment_url": "https://api.github.com/repos/apache/nuttx/issues/comments{/number}",
        "contents_url": "https://api.github.com/repos/apache/nuttx/contents/{+path}",
        "compare_url": "https://api.github.com/repos/apache/nuttx/compare/{base}...{head}",
        "merges_url": "https://api.github.com/repos/apache/nuttx/merges",
        "archive_url": "https://api.github.com/repos/apache/nuttx/{archive_format}{/ref}",
        "downloads_url": "https://api.github.com/repos/apache/nuttx/downloads",
        "issues_url": "https://api.github.com/repos/apache/nuttx/issues{/number}",
        "pulls_url": "https://api.github.com/repos/apache/nuttx/pulls{/number}",
        "milestones_url": "https://api.github.com/repos/apache/nuttx/milestones{/number}",
        "notifications_url": "https://api.github.com/repos/apache/nuttx/notifications{?since,all,participating}",
        "labels_url": "https://api.github.com/repos/apache/nuttx/labels{/name}",
        "releases_url": "https://api.github.com/repos/apache/nuttx/releases{/id}",
        "deployments_url": "https://api.github.com/repos/apache/nuttx/deployments",
        "created_at": "2019-12-14T23:27:55Z",
        "updated_at": "2025-01-29T04:43:44Z",
        "pushed_at": "2025-01-29T04:43:39Z",
        "git_url": "git://github.com/apache/nuttx.git",
        "ssh_url": "git@github.com:apache/nuttx.git",
        "clone_url": "https://github.com/apache/nuttx.git",
        "svn_url": "https://github.com/apache/nuttx",
        "homepage": "https://nuttx.apache.org/",
        "size": 316389,
        "stargazers_count": 3066,
        "watchers_count": 3066,
        "language": "C",
        "has_issues": true,
        "has_projects": true,
        "has_downloads": true,
        "has_wiki": false,
        "has_pages": false,
        "has_discussions": false,
        "forks_count": 1232,
        "mirror_url": null,
        "archived": false,
        "disabled": false,
        "open_issues_count": 572,
        "license": {
          "key": "apache-2.0",
          "name": "Apache License 2.0",
          "spdx_id": "Apache-2.0",
          "url": "https://api.github.com/licenses/apache-2.0",
          "node_id": "MDc6TGljZW5zZTI="
        },
        "allow_forking": true,
        "is_template": false,
        "web_commit_signoff_required": false,
        "topics": [
          "embedded",
          "mcu",
          "microcontroller",
          "nuttx",
          "real-time",
          "rtos"
        ],
        "visibility": "public",
        "forks": 1232,
        "open_issues": 572,
        "watchers": 3066,
        "default_branch": "master"
      }
    },
    "_links": {
      "self": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444"
      },
      "html": {
        "href": "https://github.com/apache/nuttx/pull/15444"
      },
      "issue": {
        "href": "https://api.github.com/repos/apache/nuttx/issues/15444"
      },
      "comments": {
        "href": "https://api.github.com/repos/apache/nuttx/issues/15444/comments"
      },
      "review_comments": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444/comments"
      },
      "review_comment": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/comments{/number}"
      },
      "commits": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444/commits"
      },
      "statuses": {
        "href": "https://api.github.com/repos/apache/nuttx/statuses/1be695191cd77b426ac53914cf0ebc0e60617c8c"
      }
    },
    "author_association": "CONTRIBUTOR",
    "auto_merge": null,
    "active_lock_reason": null
  }
]
```

# Get Breaking Commit

TODO

```text
Get Breaking Commit

build_score{
target="rv-virt:knsh64_test5",
build_score_prev="1"
} == 0

Get nuttx_hash_prev
"be40c01ddd6f43a527abeae31042ba7978aabb58"

build_score{apps_hash="a6b9e718460a56722205c2a84a9b07b94ca664aa", apps_hash_next="a6b9e718460a56722205c2a84a9b07b94ca664aa", apps_hash_prev="a6b9e718460a56722205c2a84a9b07b94ca664aa", arch="unknown", board="rv-virt", build_score_next="0", build_score_prev="1", config="knsh64_test5", exported_instance="rv-virt:knsh64_test5@657247bda89d60112d79bb9b8d223eca5f9641b5@a6b9e718460a56722205c2a84a9b07b94ca664aa", exported_job="rewind", group="unknown", instance="localhost:9091", job="pushgateway", msg="+ /home/luppy/nuttx-build-farm/build-test-knsh64.sh 48846954d8506e1c95089a8654787fdc42cc098c a6b9e718460a56722205c2a84a9b07b94ca664aa Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-knsh64.sh 48846954d8506e1c95089a8654787fdc42cc098c a6b9e718460a56722205c2a84a9b07b94ca664aa + nuttx_hash=48846954d8506e1c95089a8654787fdc42cc098c + apps_hash=a6b9e718460a56722205c2a84a9b07b94ca664aa + neofetch .-/+oossssoo+/-. `:+ssssssssssssssssss+:` -+ssssssssssssssssssyyssss+-", nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5", nuttx_hash_next="48846954d8506e1c95089a8654787fdc42cc098c", nuttx_hash_prev="be40c01ddd6f43a527abeae31042ba7978aabb58", subarch="unknown", target="rv-virt:knsh64_test5", timestamp="2025-01-11T10:54:36", timestamp_log="2025-01-29T04:59:10.699Z", url="https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L1629", url_display="gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L1629", user="rewind", version="3"}
```

# nuttx-rewind-notify

```text
nuttx-rewind-notify

export PROMETHEUS_SERVER=luppys-mac-mini.local:9090
./run.sh",

const ALL_BUILDS_FILENAME: &str = "/tmp/nuttx-rewind-notify.json";

cron:

crontab -e

## Run every 15 minutes
*/15 * * * * /home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify

## Run every hour at 00:16, 01:16, 12:16, ...
16 * * * * /home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify

tail -f /var/log/syslog
<<
2025-01-31T18:29:21.853366+08:00 thinkstation crontab[3946431]: (luppy) BEGIN EDIT (luppy)
2025-01-31T18:29:29.480578+08:00 thinkstation crontab[3946431]: (luppy) REPLACE (luppy)
2025-01-31T18:29:29.480737+08:00 thinkstation crontab[3946431]: (luppy) END EDIT (luppy)
2025-01-31T18:30:01.179722+08:00 thinkstation systemd[1]: Starting sysstat-collect.service - system activity accounting tool...
2025-01-31T18:30:01.197467+08:00 thinkstation systemd[1]: sysstat-collect.service: Deactivated successfully.
2025-01-31T18:30:01.197644+08:00 thinkstation systemd[1]: Finished sysstat-collect.service - system activity accounting tool.
2025-01-31T18:30:01.542271+08:00 thinkstation cron[1248]: (luppy) RELOAD (crontabs/luppy)
2025-01-31T18:30:01.548522+08:00 thinkstation CRON[4011165]: (root) CMD ([ -x /etc/init.d/anacron ] && if [ ! -d /run/systemd/system ]; then /usr/sbin/invoke-rc.d anacron start >/dev/null; fi)
2025-01-31T18:30:01.554147+08:00 thinkstation CRON[4011172]: (luppy) CMD (/home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify)
2025-01-31T18:30:01.561773+08:00 thinkstation nuttx-rewind-notify: + export PROMETHEUS_SERVER=luppys-mac-mini.local:9090
2025-01-31T18:30:01.562012+08:00 thinkstation nuttx-rewind-notify: + PROMETHEUS_SERVER=luppys-mac-mini.local:9090
2025-01-31T18:30:01.562086+08:00 thinkstation nuttx-rewind-notify: + script_path=/home/luppy/nuttx-rewind-notify/cron.sh
2025-01-31T18:30:01.565423+08:00 thinkstation nuttx-rewind-notify: +++ dirname -- /home/luppy/nuttx-rewind-notify/cron.sh
2025-01-31T18:30:01.565529+08:00 thinkstation nuttx-rewind-notify: ++ cd -P /home/luppy/nuttx-rewind-notify
2025-01-31T18:30:01.565598+08:00 thinkstation nuttx-rewind-notify: ++ pwd
2025-01-31T18:30:01.565670+08:00 thinkstation nuttx-rewind-notify: + script_dir=/home/luppy/nuttx-rewind-notify
2025-01-31T18:30:01.565742+08:00 thinkstation nuttx-rewind-notify: + cd /home/luppy/nuttx-rewind-notify
2025-01-31T18:30:01.565801+08:00 thinkstation nuttx-rewind-notify: + cargo run
2025-01-31T18:30:01.878649+08:00 thinkstation nuttx-rewind-notify:     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.21s
2025-01-31T18:30:01.893883+08:00 thinkstation nuttx-rewind-notify:      Running `target/debug/nuttx-rewind-notify`
2025-01-31T18:30:01.920672+08:00 thinkstation nuttx-rewind-notify: query=
2025-01-31T18:30:01.923383+08:00 thinkstation nuttx-rewind-notify:         build_score{
2025-01-31T18:30:01.923533+08:00 thinkstation nuttx-rewind-notify:             target="rv-virt:knsh64_test8",
2025-01-31T18:30:01.923643+08:00 thinkstation nuttx-rewind-notify:             build_score_prev="1"
2025-01-31T18:30:01.923739+08:00 thinkstation nuttx-rewind-notify:         } == 0
2025-01-31T18:30:01.924934+08:00 thinkstation nuttx-rewind-notify:     
2025-01-31T18:30:02.130675+08:00 thinkstation nuttx-rewind-notify: res=Response { url: "http://luppys-mac-mini.local:9090/api/v1/query", status: 200, headers: {"content-type": "application/json", "date": "Fri, 31 Jan 2025 10:30:02 GMT", "content-length": "63"} }
2025-01-31T18:30:27.330670+08:00 thinkstation crontab[4054090]: (luppy) BEGIN EDIT (luppy)
2025-01-31T18:30:30.928696+08:00 thinkstation crontab[4054090]: (luppy) REPLACE (luppy)
2025-01-31T18:30:30.928960+08:00 thinkstation crontab[4054090]: (luppy) END EDIT (luppy)
2025-01-31T18:31:01.144675+08:00 thinkstation cron[1248]: (luppy) RELOAD (crontabs/luppy)
2025-01-31T18:31:01.603569+08:00 thinkstation CRON[4119911]: (luppy) CMD (/home/luppy/nuttx-rewind-notify/cron.sh 2>&1 | logger -t nuttx-rewind-notify)
2025-01-31T18:31:01.608441+08:00 thinkstation nuttx-rewind-notify: + export PROMETHEUS_SERVER=luppys-mac-mini.local:9090
2025-01-31T18:31:01.608661+08:00 thinkstation nuttx-rewind-notify: + PROMETHEUS_SERVER=luppys-mac-mini.local:9090
2025-01-31T18:31:01.608738+08:00 thinkstation nuttx-rewind-notify: + script_path=/home/luppy/nuttx-rewind-notify/cron.sh
2025-01-31T18:31:01.608876+08:00 thinkstation nuttx-rewind-notify: +++ dirname -- /home/luppy/nuttx-rewind-notify/cron.sh
2025-01-31T18:31:01.609689+08:00 thinkstation nuttx-rewind-notify: ++ cd -P /home/luppy/nuttx-rewind-notify
2025-01-31T18:31:01.609776+08:00 thinkstation nuttx-rewind-notify: ++ pwd
2025-01-31T18:31:01.609959+08:00 thinkstation nuttx-rewind-notify: + script_dir=/home/luppy/nuttx-rewind-notify
2025-01-31T18:31:01.610021+08:00 thinkstation nuttx-rewind-notify: + cd /home/luppy/nuttx-rewind-notify
2025-01-31T18:31:01.610077+08:00 thinkstation nuttx-rewind-notify: + cargo run
2025-01-31T18:31:02.081532+08:00 thinkstation nuttx-rewind-notify:    Compiling nuttx-rewind-notify v1.0.0 (/home/luppy/nuttx-rewind-notify)
2025-01-31T18:31:04.336844+08:00 thinkstation nuttx-rewind-notify:     Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.67s
2025-01-31T18:31:04.615750+08:00 thinkstation nuttx-rewind-notify:      Running `target/debug/nuttx-rewind-notify`
2025-01-31T18:31:04.638879+08:00 thinkstation nuttx-rewind-notify: query=
2025-01-31T18:31:04.639035+08:00 thinkstation nuttx-rewind-notify:         build_score{
2025-01-31T18:31:04.639126+08:00 thinkstation nuttx-rewind-notify:             target="rv-virt:knsh64_test6",
2025-01-31T18:31:04.639213+08:00 thinkstation nuttx-rewind-notify:             build_score_prev="1"
2025-01-31T18:31:04.639304+08:00 thinkstation nuttx-rewind-notify:         } == 0
2025-01-31T18:31:04.642417+08:00 thinkstation nuttx-rewind-notify:     
2025-01-31T18:31:04.845860+08:00 thinkstation nuttx-rewind-notify: res=Response { url: "http://luppys-mac-mini.local:9090/api/v1/query", status: 200, headers: {"content-type": "application/json", "date": "Fri, 31 Jan 2025 10:31:04 GMT", "content-length": "1630"} }
2025-01-31T18:31:04.846089+08:00 thinkstation nuttx-rewind-notify: nuttx_hash_prev=be40c01ddd6f43a527abeae31042ba7978aabb58
2025-01-31T18:31:04.846164+08:00 thinkstation nuttx-rewind-notify: url=https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85
2025-01-31T18:31:04.846233+08:00 thinkstation nuttx-rewind-notify: board=rv-virt
2025-01-31T18:31:04.846299+08:00 thinkstation nuttx-rewind-notify: config=knsh64_test6
2025-01-31T18:31:04.846384+08:00 thinkstation nuttx-rewind-notify: user=rewind
2025-01-31T18:31:04.846460+08:00 thinkstation nuttx-rewind-notify: query=
2025-01-31T18:31:04.846516+08:00 thinkstation nuttx-rewind-notify:         build_score{
2025-01-31T18:31:04.846614+08:00 thinkstation nuttx-rewind-notify:             target="rv-virt:knsh64_test6",
2025-01-31T18:31:04.846706+08:00 thinkstation nuttx-rewind-notify:             nuttx_hash="be40c01ddd6f43a527abeae31042ba7978aabb58"
2025-01-31T18:31:04.846791+08:00 thinkstation nuttx-rewind-notify:         }
2025-01-31T18:31:04.846878+08:00 thinkstation nuttx-rewind-notify:     
2025-01-31T18:31:04.967500+08:00 thinkstation nuttx-rewind-notify: res=Response { url: "http://luppys-mac-mini.local:9090/api/v1/query", status: 200, headers: {"content-type": "application/json", "date": "Fri, 31 Jan 2025 10:31:04 GMT", "content-length": "1344"} }
2025-01-31T18:31:04.967635+08:00 thinkstation nuttx-rewind-notify: previous_url=https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800063#L80
2025-01-31T18:31:05.506663+08:00 thinkstation nuttx-rewind-notify: pr_url=https://github.com/apache/nuttx/pull/15444
2025-01-31T18:31:05.506806+08:00 thinkstation nuttx-rewind-notify: pr_user=yf13
2025-01-31T18:31:05.506893+08:00 thinkstation nuttx-rewind-notify: raw_url=https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059/raw/
2025-01-31T18:31:06.178706+08:00 thinkstation nuttx-rewind-notify: 138: $ git clone https://github.com/apache/nuttx
2025-01-31T18:31:06.178905+08:00 thinkstation nuttx-rewind-notify: 147: $ git clone https://github.com/apache/nuttx-apps apps
2025-01-31T18:31:06.179012+08:00 thinkstation nuttx-rewind-notify: 156: $ pushd nuttx
2025-01-31T18:31:06.179112+08:00 thinkstation nuttx-rewind-notify: 158: $ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
2025-01-31T18:31:06.179256+08:00 thinkstation nuttx-rewind-notify: 159: HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
2025-01-31T18:31:06.179451+08:00 thinkstation nuttx-rewind-notify: 160: $ popd
2025-01-31T18:31:06.179558+08:00 thinkstation nuttx-rewind-notify: 163: $ pushd apps
2025-01-31T18:31:06.179626+08:00 thinkstation nuttx-rewind-notify: 165: $ git reset --hard a6b9e718460a56722205c2a84a9b07b94ca664aa
2025-01-31T18:31:06.179694+08:00 thinkstation nuttx-rewind-notify: 166: HEAD is now at a6b9e7184 testing/nettest: Add utils directory and two tcp testcases to the testing framework
2025-01-31T18:31:06.179761+08:00 thinkstation nuttx-rewind-notify: 167: $ popd
2025-01-31T18:31:06.179827+08:00 thinkstation nuttx-rewind-notify: 171: NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
2025-01-31T18:31:06.179894+08:00 thinkstation nuttx-rewind-notify: 174: NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
2025-01-31T18:31:06.179958+08:00 thinkstation nuttx-rewind-notify: 191: $ cd nuttx
2025-01-31T18:31:06.180025+08:00 thinkstation nuttx-rewind-notify: 192: $ tools/configure.sh rv-virt:knsh64
2025-01-31T18:31:06.180088+08:00 thinkstation nuttx-rewind-notify: 239: $ make -j
2025-01-31T18:31:06.180160+08:00 thinkstation nuttx-rewind-notify: 255: $ make -j export
2025-01-31T18:31:06.180225+08:00 thinkstation nuttx-rewind-notify: 256: $ pushd ../apps
2025-01-31T18:31:06.180291+08:00 thinkstation nuttx-rewind-notify: 258: $ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
2025-01-31T18:31:06.180372+08:00 thinkstation nuttx-rewind-notify: 259: $ make -j import
2025-01-31T18:31:06.180443+08:00 thinkstation nuttx-rewind-notify: 363: $ popd
2025-01-31T18:31:06.180503+08:00 thinkstation nuttx-rewind-notify: 365: $ qemu-system-riscv64 --version
2025-01-31T18:31:06.180569+08:00 thinkstation nuttx-rewind-notify: 366: QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.4)
2025-01-31T18:31:06.181138+08:00 thinkstation nuttx-rewind-notify: 382: $ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
2025-01-31T18:31:06.181212+08:00 thinkstation nuttx-rewind-notify: 384: OpenSBI v1.3
2025-01-31T18:31:06.181285+08:00 thinkstation nuttx-rewind-notify: 432: Boot HART ISA Extensions  : time,sstc
2025-01-31T18:31:06.181373+08:00 thinkstation nuttx-rewind-notify: 433: Boot HART PMP Count       : 16
2025-01-31T18:31:06.181436+08:00 thinkstation nuttx-rewind-notify: 434: Boot HART PMP Granularity : 4
2025-01-31T18:31:06.181511+08:00 thinkstation nuttx-rewind-notify: 435: Boot HART PMP Address Bits: 54
2025-01-31T18:31:06.181575+08:00 thinkstation nuttx-rewind-notify: 436: Boot HART MHPM Count      : 16
2025-01-31T18:31:06.181640+08:00 thinkstation nuttx-rewind-notify: 437: Boot HART MIDELEG         : 0x0000000000001666
2025-01-31T18:31:06.181704+08:00 thinkstation nuttx-rewind-notify: 438: Boot HART MEDELEG         : 0x0000000000f0b509
2025-01-31T18:31:06.181769+08:00 thinkstation nuttx-rewind-notify: 439: ABC[    0.238338] riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
2025-01-31T18:31:06.181835+08:00 thinkstation nuttx-rewind-notify: 440: [    0.242809] riscv_exception: Segmentation fault in PID 2: /system/bin/init
2025-01-31T18:31:06.181912+08:00 thinkstation nuttx-rewind-notify: 441: 
2025-01-31T18:31:06.181989+08:00 thinkstation nuttx-rewind-notify: status=
2025-01-31T18:31:06.182054+08:00 thinkstation nuttx-rewind-notify: 
2025-01-31T18:31:06.182122+08:00 thinkstation nuttx-rewind-notify: rv-virt : KNSH64_TEST6 - Build Failed (rewind)
2025-01-31T18:31:06.182186+08:00 thinkstation nuttx-rewind-notify: Breaking PR: https://github.com/apache/nuttx/pull/15444
2025-01-31T18:31:06.182251+08:00 thinkstation nuttx-rewind-notify: NuttX Dashboard: https://nuttx-dashboard.org
2025-01-31T18:31:06.182316+08:00 thinkstation nuttx-rewind-notify: Build History: https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board=rv-virt&var-config=knsh64_test6
2025-01-31T18:31:06.182404+08:00 thinkstation nuttx-rewind-notify: 
2025-01-31T18:31:06.182470+08:00 thinkstation nuttx-rewind-notify: Sorry @yf13: The above PR is failing for rv-virt:knsh64_test6. Could you please take a look? Thanks!
2025-01-31T18:31:06.182531+08:00 thinkstation nuttx-rewind-notify: https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85
2025-01-31T18:31:06.182596+08:00 thinkstation nuttx-rewind-notify: ```text
2025-01-31T18:31:06.182660+08:00 thinkstation nuttx-rewind-notify: $ git clone https://github.com/apache/nuttx
2025-01-31T18:31:06.182725+08:00 thinkstation nuttx-rewind-notify: $ git clone https://github.com/apache/nuttx-apps apps
2025-01-31T18:31:06.182786+08:00 thinkstation nuttx-rewind-notify: $ pushd nuttx
2025-01-31T18:31:06.182846+08:00 thinkstation nuttx-rewind-notify: $ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
2025-01-31T18:31:06.182910+08:00 thinkstation nuttx-rewind-notify: HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
2025-01-31T18:31:06.182977+08:00 thinkstation nuttx-rewind-notify: $ popd
2025-01-31T18:31:06.183042+08:00 thinkstation nuttx-rewind-notify: $ pushd apps
2025-01-31T18:31:06.183102+08:00 thinkstation nuttx-rewind-notify: $ git reset --hard a6b9e718460a56722205c2a84a9b07b94ca664aa
2025-01-31T18:31:06.183162+08:00 thinkstation nuttx-rewind-notify: HEAD is now at a6b9e7184 testing/nettest: Add utils directory and two tcp testcases to the testing framework
2025-01-31T18:31:06.183227+08:00 thinkstation nuttx-rewind-notify: $ popd
2025-01-31T18:31:06.183288+08:00 thinkstation nuttx-rewind-notify: NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
2025-01-31T18:31:06.183361+08:00 thinkstation nuttx-rewind-notify: NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
2025-01-31T18:31:06.183431+08:00 thinkstation nuttx-rewind-notify: $ cd nuttx
2025-01-31T18:31:06.183496+08:00 thinkstation nuttx-rewind-notify: $ tools/configure.sh rv-virt:knsh64
2025-01-31T18:31:06.183557+08:00 thinkstation nuttx-rewind-notify: $ make -j
2025-01-31T18:31:06.183627+08:00 thinkstation nuttx-rewind-notify: $ make -j export
2025-01-31T18:31:06.183692+08:00 thinkstation nuttx-rewind-notify: $ pushd ../apps
2025-01-31T18:31:06.183762+08:00 thinkstation nuttx-rewind-notify: $ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
2025-01-31T18:31:06.183822+08:00 thinkstation nuttx-rewind-notify: $ make -j import
2025-01-31T18:31:06.183885+08:00 thinkstation nuttx-rewind-notify: $ popd
2025-01-31T18:31:06.183939+08:00 thinkstation nuttx-rewind-notify: $ qemu-system-riscv64 --version
2025-01-31T18:31:06.184003+08:00 thinkstation nuttx-rewind-notify: QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.4)
2025-01-31T18:31:06.184072+08:00 thinkstation nuttx-rewind-notify: $ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
2025-01-31T18:31:06.184143+08:00 thinkstation nuttx-rewind-notify: OpenSBI v1.3
2025-01-31T18:31:06.184211+08:00 thinkstation nuttx-rewind-notify: Boot HART ISA Extensions  : time,sstc
2025-01-31T18:31:06.184279+08:00 thinkstation nuttx-rewind-notify: Boot HART PMP Count       : 16
2025-01-31T18:31:06.184364+08:00 thinkstation nuttx-rewind-notify: Boot HART PMP Granularity : 4
2025-01-31T18:31:06.184427+08:00 thinkstation nuttx-rewind-notify: Boot HART PMP Address Bits: 54
2025-01-31T18:31:06.184487+08:00 thinkstation nuttx-rewind-notify: Boot HART MHPM Count      : 16
2025-01-31T18:31:06.184541+08:00 thinkstation nuttx-rewind-notify: Boot HART MIDELEG         : 0x0000000000001666
2025-01-31T18:31:06.184600+08:00 thinkstation nuttx-rewind-notify: Boot HART MEDELEG         : 0x0000000000f0b509
2025-01-31T18:31:06.184654+08:00 thinkstation nuttx-rewind-notify: ABC[    0.238338] riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
2025-01-31T18:31:06.184715+08:00 thinkstation nuttx-rewind-notify: [    0.242809] riscv_exception: Segmentation fault in PID 2: /system/bin/init
2025-01-31T18:31:06.184779+08:00 thinkstation nuttx-rewind-notify: 
2025-01-31T18:31:06.184841+08:00 thinkstation nuttx-rewind-notify: ```
2025-01-31T18:31:06.184904+08:00 thinkstation nuttx-rewind-notify: [(Earlier Commit is OK)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800063#L80)
2025-01-31T18:31:06.184969+08:00 thinkstation nuttx-rewind-notify: [(See the Build History)](https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board=rv-virt&var-config=knsh64_test6)
2025-01-31T18:31:06.185042+08:00 thinkstation nuttx-rewind-notify:             
2025-01-31T18:31:07.364053+08:00 thinkstation nuttx-rewind-notify: snippet_url=
2025-01-31T18:31:07.364225+08:00 thinkstation nuttx-rewind-notify: https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4801057
2025-01-31T18:31:07.781755+08:00 thinkstation nuttx-rewind-notify: res=Response { url: "https://nuttx-feed.org/api/v1/statuses", status: 200, headers: {"date": "Fri, 31 Jan 2025 10:31:07 GMT", "content-type": "application/json; charset=utf-8", "content-length": "3763", "connection": "keep-alive", "cache-control": "private, no-store", "content-security-policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'", "etag": "W/\"9a52e8b22f4bb37b96bfdd8b737c9ae9\"", "referrer-policy": "same-origin", "strict-transport-security": "max-age=63072000; includeSubDomains", "vary": "Authorization, Origin", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "x-ratelimit-limit": "300", "x-ratelimit-remaining": "297", "x-ratelimit-reset": "2025-01-31T12:00:00.180196Z", "x-request-id": "4e920371-0b4f-4a27-9ed0-2f6efee59eec", "x-runtime": "0.051579", "x-xss-protection": "0", "cf-cache-status": "DYNAMIC", "report-to": "{\"endpoints\":[{\"url\":\"https:\/\/a.nel.cloudflare.com\/report\/v4?s=V2keLESz1ucPXJh%2BkCWpkuJb4jdGM2BEHwg2wVQfX1KTdo0qK1BKt7u5t%2BIZBtAW6hz468oucrG
2025-01-31T18:31:07.784412+08:00 thinkstation nuttx-rewind-notify: 8lw6hMtBflMCo3iRwhA3QkkiXuy1oEN7rlzCRWEzCVnt%2F1JxM4Jc3kQ%3D%3D\"}],\"group\":\"cf-nel\",\"max_age\":604800}", "nel": "{\"success_fraction\":0,\"report_to\":\"cf-nel\",\"max_age\":604800}", "server": "cloudflare", "cf-ray": "90a907c148f46045-SIN", "alt-svc": "h3=\":443\"; ma=86400", "server-timing": "cfL4;desc=\"?proto=TCP&rtt=2820&min_rtt=2083&rtt_var=1243&sent=4&recv=7&lost=0&retrans=0&sent_bytes=2833&recv_bytes=1464&delivery_rate=1382999&cwnd=196&unsent_bytes=0&cid=7928dd566ec28f03&ts=94&x=0\""} }
2025-01-31T18:31:07.784581+08:00 thinkstation nuttx-rewind-notify: Body: {"id":"113922504467871604","created_at":"2025-01-31T10:31:05.147Z","in_reply_to_id":null,"in_reply_to_account_id":null,"sensitive":false,"spoiler_text":"","visibility":"public","language":"en","uri":"https://nuttx-feed.org/users/nuttx_build/statuses/113922504467871604","url":"https://nuttx-feed.org/@nuttx_build/113922504467871604","replies_count":0,"reblogs_count":0,"favourites_count":0,"edited_at":null,"favourited":false,"reblogged":false,"muted":false,"bookmarked":false,"pinned":false,"content":"\u003cp\u003eDetails: \u003ca href=\"https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4801057\" target=\"_blank\" rel=\"nofollow noopener noreferrer\" translate=\"no\"\u003e\u003cspan class=\"invisible\"\u003ehttps://\u003c/span\u003e\u003cspan class=\"ellipsis\"\u003egitlab.com/lupyuen/nuttx-build\u003c/span\u003e\u003cspan class=\"invisible\"\u003e-log/-/snippets/4801057\u003c/span\u003e\u003c/a\u003e\u003c/p\u003e\u003cp\u003erv-virt : KNSH64_TEST6 - Build Failed (rewind)\u003cbr /\u003eBreaking PR: \u
2025-01-31T18:31:07.784717+08:00 thinkstation nuttx-rewind-notify: 003ca href=\"https://github.com/apache/nuttx/pull/15444\" target=\"_blank\" rel=\"nofollow noopener noreferrer\" translate=\"no\"\u003e\u003cspan class=\"invisible\"\u003ehttps://\u003c/span\u003e\u003cspan class=\"ellipsis\"\u003egithub.com/apache/nuttx/pull/1\u003c/span\u003e\u003cspan class=\"invisible\"\u003e5444\u003c/span\u003e\u003c/a\u003e\u003cbr /\u003eNuttX Dashboard: \u003ca href=\"https://nuttx-dashboard.org\" target=\"_blank\" rel=\"nofollow noopener noreferrer\" translate=\"no\"\u003e\u003cspan class=\"invisible\"\u003ehttps://\u003c/span\u003e\u003cspan class=\"\"\u003enuttx-dashboard.org\u003c/span\u003e\u003cspan class=\"invisible\"\u003e\u003c/span\u003e\u003c/a\u003e\u003cbr /\u003eBuild History: \u003ca href=\"https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board=rv-virt\u0026amp;var-config=knsh64_test6\" target=\"_blank\" rel=\"nofollow noopener noreferrer\" translate=\"no\"\u003e\u003cspan class=\"invisible\"\u003ehttps://\u003c/span\u003e\u003cspan class=\"ellipsis
2025-01-31T18:31:07.784854+08:00 thinkstation nuttx-rewind-notify: \"\u003enuttx-dashboard.org/d/fe2q876w\u003c/span\u003e\u003cspan class=\"invisible\"\u003eubc3kc/nuttx-build-history?var-board=rv-virt\u0026amp;var-config=knsh64_test6\u003c/span\u003e\u003c/a\u003e\u003c/p\u003e\u003cp\u003eSorry @yf13: The above PR is failing for rv-virt:knsh64_test6. Could you please take a look? Thanks!\u003cbr /\u003e\u003ca href=\"https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800059#L85\" target=\"_blank\" rel=\"nofollow noopener noreferrer\" translate=\"no\"\u003e\u003cspan class=\"invisible\"\u003ehttps://\u003c/span\u003e\u003cspan class=\"ellipsis\"\u003egitlab.com/lupyuen/nuttx-build\u003c/span\u003e\u003cspan class=\"invisible\"\u003e-log/-/snippets/4800059#L85\u003c/span\u003e\u003c/a\u003e\u003cbr /\u003e``\u003c/p\u003e","filtered":[],"reblog":null,"application":{"name":"NuttX Dashboard","website":"https://nuttx-dashboard.org"},"account":{"id":"113642720924513889","username":"nuttx_build","acct":"nuttx_build","display_name":"","locked":false,"bot":false,"discoverable"
2025-01-31T18:31:07.784992+08:00 thinkstation nuttx-rewind-notify: :null,"indexable":false,"group":false,"created_at":"2024-12-13T00:00:00.000Z","note":"","url":"https://nuttx-feed.org/@nuttx_build","uri":"https://nuttx-feed.org/users/nuttx_build","avatar":"https://nuttx-feed.org/avatars/original/missing.png","avatar_static":"https://nuttx-feed.org/avatars/original/missing.png","header":"https://nuttx-feed.org/headers/original/missing.png","header_static":"https://nuttx-feed.org/headers/original/missing.png","followers_count":1,"following_count":0,"statuses_count":781,"last_status_at":"2025-01-31","hide_collections":null,"noindex":false,"emojis":[],"roles":[],"fields":[]},"media_attachments":[],"mentions":[],"tags":[],"emojis":[],"card":null,"poll":null}
2025-01-31T18:31:07.785121+08:00 thinkstation nuttx-rewind-notify: status_id=113922504467871604
2025-01-31T18:31:07.785208+08:00 thinkstation nuttx-rewind-notify: 
2025-01-31T18:31:07.785296+08:00 thinkstation nuttx-rewind-notify: all_builds=
2025-01-31T18:31:07.785407+08:00 thinkstation nuttx-rewind-notify: {
2025-01-31T18:31:07.785494+08:00 thinkstation nuttx-rewind-notify:   "rv-virt:knsh64_test6": {
2025-01-31T18:31:07.785583+08:00 thinkstation nuttx-rewind-notify:     "status_id": "113922504467871604",
2025-01-31T18:31:07.785670+08:00 thinkstation nuttx-rewind-notify:     "users": [
2025-01-31T18:31:07.785753+08:00 thinkstation nuttx-rewind-notify:       "rewind"
2025-01-31T18:31:07.785843+08:00 thinkstation nuttx-rewind-notify:     ]
2025-01-31T18:31:07.785932+08:00 thinkstation nuttx-rewind-notify:   }
2025-01-31T18:31:07.786033+08:00 thinkstation nuttx-rewind-notify: }
2025-01-31T18:31:07.786127+08:00 thinkstation nuttx-rewind-notify: 
>>
```

# Cron Job

TODO

```text
https://help.ubuntu.com/community/CronHowto
. $HOME/gitlab-token.sh && glab auth status && cd $HOME/nuttx-build-farm && ./rewind-build.sh rv-virt:knsh64_test8 HEAD HEAD 1 20

crontab -e

## Run every day at 00:00 UTC
0 0 * * * /home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build

## Run every hour at 00:16, 01:16, 12:16, ...
16 * * * * /home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build

tail -f /var/log/syslog
<<
2025-01-31T15:15:33.725765+08:00 thinkstation crontab[2982952]: (luppy) BEGIN EDIT (luppy)
2025-01-31T15:15:53.889440+08:00 thinkstation crontab[2982952]: (luppy) REPLACE (luppy)
2025-01-31T15:15:53.889656+08:00 thinkstation crontab[2982952]: (luppy) END EDIT (luppy)

2025-01-31T17:13:01.834380+08:00 thinkstation CRON[1234832]: (luppy) CMD (/home/luppy/nuttx-build-farm/cron.sh 2>&1 | logger -t nuttx-rewind-build)
2025-01-31T17:13:01.834657+08:00 thinkstation nuttx-rewind-build: + target=rv-virt:knsh64_test8
2025-01-31T17:13:01.834800+08:00 thinkstation nuttx-rewind-build: + nuttx_hash=HEAD
2025-01-31T17:13:01.834869+08:00 thinkstation nuttx-rewind-build: + apps_hash=HEAD
2025-01-31T17:13:01.834924+08:00 thinkstation nuttx-rewind-build: + min_commits=1
2025-01-31T17:13:01.834982+08:00 thinkstation nuttx-rewind-build: + max_commits=20
2025-01-31T17:13:01.835036+08:00 thinkstation nuttx-rewind-build: + script_path=/home/luppy/nuttx-build-farm/cron.sh
2025-01-31T17:13:01.835093+08:00 thinkstation nuttx-rewind-build: +++ dirname -- /home/luppy/nuttx-build-farm/cron.sh
2025-01-31T17:13:01.835145+08:00 thinkstation nuttx-rewind-build: ++ cd -P /home/luppy/nuttx-build-farm
2025-01-31T17:13:01.835197+08:00 thinkstation nuttx-rewind-build: ++ pwd
2025-01-31T17:13:01.835249+08:00 thinkstation nuttx-rewind-build: + script_dir=/home/luppy/nuttx-build-farm
2025-01-31T17:13:01.835301+08:00 thinkstation nuttx-rewind-build: + cd /home/luppy/nuttx-build-farm
2025-01-31T17:13:01.835359+08:00 thinkstation nuttx-rewind-build: + ./rewind-build.sh rv-virt:knsh64_test8 HEAD HEAD 1 20
2025-01-31T17:13:01.835415+08:00 thinkstation nuttx-rewind-build: Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/rewind-build.sh rv-virt:knsh64_test8 HEAD HEAD 1 20
...
2025-01-31T17:17:56.123175+08:00 thinkstation nuttx-rewind-build: - Creating snippet in lupyuen/nuttx-build-log
2025-01-31T17:17:57.586891+08:00 thinkstation nuttx-rewind-build: https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4801032
2025-01-31T17:17:57.591633+08:00 thinkstation nuttx-rewind-build: + next_hash=4606f1f9e1e897ce508f9dcadcc57dea979041b5
2025-01-31T17:17:57.591815+08:00 thinkstation nuttx-rewind-build: + nuttx_hash=11a47a4b0c3b4c371578bc3e578b2088dffbb678
2025-01-31T17:17:57.591922+08:00 thinkstation nuttx-rewind-build: + timestamp=2025-01-31T04:53:36
2025-01-31T17:17:57.592019+08:00 thinkstation nuttx-rewind-build: + (( count++ ))
2025-01-31T17:17:57.592118+08:00 thinkstation nuttx-rewind-build: + [[ 1 == \1 ]]
2025-01-31T17:17:57.592208+08:00 thinkstation nuttx-rewind-build: + break
2025-01-31T17:17:57.592298+08:00 thinkstation nuttx-rewind-build: + set +x
2025-01-31T17:17:57.592406+08:00 thinkstation nuttx-rewind-build: ***** Done!
>>

Without logger:
<<
2025-01-31T15:40:47.812335+08:00 thinkstation CRON[280259]: (CRON) info (No MTA installed, discarding output)
>>

ls -l /tmp
drwxrwxr-x  4 luppy luppy    4096 Jan 31 15:17 rewind-build-rv-virt:knsh64_test8
drwxrwxr-x  3 luppy luppy    4096 Jan 31 15:17 build-test-knsh64

tail -f /tmp/rewind-build-rv-virt:knsh64_test8/*.log
<<
Final memory usage:
VARIABLE  BEFORE   AFTER
======== ======== ========
arena       81000    81000
ordblks         2        3
mxordblk    7cff8    78ff8
uordblks     2660     4570
fordblks    7e9a0    7ca90
user_main: Exiting
ostest_main: Exiting with status 0

===== Test OK

+ res=0
+ set -e
+ set +x
res=0
====================================================================================
+ echo res=0
res=0
+ [[ 0 != \0 ]]
+ echo '***** Build / Test OK for Previous Commit: nuttx @ 11a47a4b0c3b4c371578bc3e578b2088dffbb678 / nuttx-apps @ e1e28eb88ad153711223cab612f5d5bd019f8dd4'
***** Build / Test OK for Previous Commit: nuttx @ 11a47a4b0c3b4c371578bc3e578b2088dffbb678 / nuttx-apps @ e1e28eb88ad153711223cab612f5d5bd019f8dd4
+ [[ 4606f1f9e1e897ce508f9dcadcc57dea979041b5 != \4\6\0\6\f\1\f\9\e\1\e\8\9\7\c\e\5\0\8\f\9\d\c\a\d\c\c\5\7\d\e\a\9\7\9\0\4\1\b\5 ]]
+ df -H
>>

Check the snippets
https://gitlab.com/lupyuen/nuttx-build-log/-/snippets
```

# Convert to Commit ID

TODO

```text
If Hash=HEAD:
Convert to Commit ID

build_score{
    config!="leds64_zig",
    user!="nuttxlinux",
    user!="nuttxmacos",
    user!="jerpelea"
} < 0.5

```

# Delete Snippet

TODO

```text
Delete Snippet
https://docs.gitlab.com/ee/api/snippets.html#delete-snippet

curl --request DELETE \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/snippets/1"
```

# Create Snippet

TODO

```text
Create Snippet
https://docs.gitlab.com/ee/api/snippets.html#create-new-snippet

snippet.json
<<
{
  "title": "This is a snippet",
  "description": "Hello World snippet",
  "visibility": "public",
  "files": [
    {
      "content": "Hello world",
      "file_path": "test.txt"
    }
  ]
}
>>

. $HOME/gitlab-token.sh
user=lupyuen
repo=nuttx-build-log
curl --url https://gitlab.com/api/v4/projects/$user%2F$repo/snippets \
  --header 'Content-Type: application/json' \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \

curl --request POST "https://gitlab.com/api/v4/projects/$user%2F$repo/snippets" \
  --header 'Content-Type: application/json' \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  -d @snippet.json

https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800488
```


# Test Failed vs Test OK

TODO

```text
nuttx_hash_next
nuttx_hash_prev

apps_hash_next
apps_prev_next

build_score_next
build_score_prev

if group == "unknown"
Search for
"build / test failed" vs "build / test ok"
"this commit" vs "previous commit" vs "next commit"

extract nuttx hash
extract apps hash

if failed: build_score=0
if successful: build_score=1
```


# What's Next

TODO: Git Bisect? Assume < 20 commits. If necessary: Test and rewind more often

TODO: nsh, nsh64, knsh, knsh64, ox64 emulator, sg2000 emulator, sg2000 board?

TODO: @nuttxpr test rv-virt:knsh64. Security?

TODO: I might try a scaled-down simpler implementation that has less security risk. For example, when I post a PR Comment `@nuttxpr please test`, then our Test Bot will download the PR and run Build + Test on QEMU RISC-V 🤔

TODO: Why not Docker

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
