# Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)

📝 _28 Feb 2025_

![Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-title.jpg)

We're [__Making Things Better__](https://lists.apache.org/thread/mn4l1tmr6fj46o2y9vvrmfcrgyo48s5d) (and making better things) with [__Apache NuttX RTOS__](TODO).

Our new __Test Bot for Pull Requests__ will allow a [__Pull Request Comment__](https://github.com/apache/nuttx/pull/15756#issuecomment-2641277894) to trigger a __NuttX Build + Test__ on Real Hardware. For example, this PR Comment...

```bash
@nuttxpr test oz64:nsh
```

Will trigger our PR Test Bot to download the PR Code and test it on [__Oz64 SG2000 RISC-V SBC__](TODO). (Pic above)

Super helpful for __Testing Pull Requests__ before Merging. But might have [__Security Implications__](https://github.com/apache/nuttx/issues/15731#issuecomment-2628647886). (We'll come back to this)

![NuttX Bot for Building and Testing Pull Requests](https://lupyuen.org/images/rewind-bot3.jpg)

_(Thanks to PINE64 for sponsoring the Oz64 SBC)_

# Expect Script

https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp

```bash
#!/usr/bin/expect
## Expect Script for Testing NuttX on Oz64 SG2000, over SSH to SBC
puts "Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp"

## For every 1 character sent, wait 0.001 milliseconds
set send_slow {1 0.001}

## Wait at most 60 seconds
set timeout 60

## Connect to SBC over SSH
spawn ssh $::env(OZ64_SERVER)

## Wake up SBC
send -s "\r"

## Connect to SBC over USB Serial Port
expect "$"
send -s "screen -x\r"

## Wait a while
sleep 5

## Terminate the session: Ctrl-A k y
send -s "\x01ky"
send -s "\r"
sleep 5

## Connect to USB Serial Terminal
expect "$"
send -s "screen /dev/ttyUSB0 115200\r"

## Power Off Oz64
puts "Power Off Oz64..."
system "./oz64-power.sh off"
sleep 5

## Power On Oz64
puts "Power On Oz64..."
system "./oz64-power.sh on"

## Wait for the prompt and enter `uname -a`
expect {
  "nsh> " {}

  ## If timeout, exit with an error
  timeout { 
    ## Terminate the session: Ctrl-A k y
    send -s "\x01ky"
    send -s "exit\r"
    system "./oz64-power.sh off"
    puts "\n===== Error: Test Failed\n"
    exit 1 
  }
}
send -s "uname -a\r"

## Wait at most 300 seconds for other commands
set timeout 300

## Wait for the prompt and enter `free`
expect "nsh> "
send -s "free\r"

## Wait for the prompt and enter `ps`
expect "nsh> "
send -s "ps\r"

## Wait for the prompt and enter `ls -l /dev`
expect "nsh> "
send -s "ls -l /dev\r"

## Wait for the prompt and enter `hello`
expect "nsh> "
send -s "hello\r"

## Wait for the prompt and enter `getprime`
expect "nsh> "
send -s "getprime\r"

## Wait for the prompt and enter `hello`
expect "nsh> "
send -s "hello\r"

## Wait for the prompt and enter `getprime`
expect "nsh> "
send -s "getprime\r"

## Wait for the prompt and enter `ostest`
expect "nsh> "
send -s "ostest\r"

## Check the response...
expect {
  ## If we see this message, exit normally
  "ostest_main: Exiting with status 0" { 
    ## Terminate the session: Ctrl-A k y
    send -s "\x01ky"
    send -s "exit\r"
    system "./oz64-power.sh off"
    puts "\n===== Test OK\n"
    exit 0 
  }

  ## If timeout, exit with an error
  timeout { 
    ## Terminate the session: Ctrl-A k y
    send -s "\x01ky"
    send -s "exit\r"
    system "./oz64-power.sh off"
    puts "\n===== Error: Test Failed\n"
    exit 1 
  }
}
```

# NuttX Test Bot

https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs

```rust
//! Fetch the Latest 20 Unread Notifications:
//!   If Mention = "@nuttxpr test rv-virt:knsh64"
//!   - Build and Test NuttX
//!   - Capture the Output Log
//!   - Extract the Log Output and Result
//!   - Post as PR Comment
//!   - Post to Mastodon
//!   - Allow only Specific People
```

Fetch all Notifications:

https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L43-L111

```rust
    // Fetch all Notifications
    // TODO: Unread only
    let notifications = octocrab
        .activity()
        .notifications()
        .list()
        .all(true)
        .send()
        .await?;

    // For Every Notification...
    for n in notifications {
        // Handle only Mentions
        let reason = &n.reason;  // "mention"
        // println!("reason={reason}", );
        if reason != "mention" { continue; }
        // TODO: Mark Notification as Read

        // Fetch the PR from the Notification
        let owner = n.repository.owner.clone().unwrap().login;
        let repo = n.repository.name.clone();
        let pr_title = &n.subject.title;  // "Testing our bot"
        let pr_url = n.subject.url.clone().unwrap();  // https://api.github.com/repos/lupyuen2/wip-nuttx/pulls/88
        let thread_url = &n.url;  // https://api.github.com/notifications/threads/14630615157
        println!("owner={owner}");
        println!("repo={repo}");
        println!("pr_title={pr_title}");
        println!("pr_url={pr_url}");
        println!("thread_url={thread_url}");
        if !pr_url.as_str().contains("/pulls/") { error!("Not a PR: {pr_url}"); continue; }
        // println!("n={n:#?}");

        // Extract the PR Number
        let regex = Regex::new(".*/([0-9]+)$").unwrap();
        let caps = regex.captures(pr_url.as_str()).unwrap();
        let pr_id_str = caps.get(1).unwrap().as_str();
        let pr_id: u64 = pr_id_str.parse().unwrap();
        println!("pr_id={pr_id}");

        // Allow only Specific Repos: apache/nuttx, apache/nuttx-apps
        if owner != "apache" ||
            !["nuttx", "nuttx-apps"].contains(&repo.as_str()) {
            error!("Disallowed owner/repo: {owner}/{repo}");
            continue;
        }

        // Get the Handlers for GitHub Pull Requests and Issues
        let pulls = octocrab.pulls(&owner, &repo);
        let issues = octocrab.issues(&owner, &repo);

        // Post the Result and Log Output as PR Comment
        process_pr(&pulls, &issues, pr_id).await?;

        // Wait 1 minute
        sleep(Duration::from_secs(60));

        // TODO: Mark Notification as Read
        // TODO: Continue to Next Notification
        break;

        // TODO: Allow only Specific People
        // TODO: Post to Mastodon
    }
```

Build and Test the PR. Then post the results as a PR Comment

https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L111-L175

```rust
/// Build and Test the PR. Then post the results as a PR Comment
async fn process_pr(pulls: &PullRequestHandler<'_>, issues: &IssueHandler<'_>, pr_id: u64) -> Result<(), Box<dyn std::error::Error>> {
    // Get the Command and Args: ["test", "milkv_duos:nsh"]
    let args = get_command(issues, pr_id).await?;
    if args.is_none() { warn!("Missing command"); return Ok(()); }
    let args = args.unwrap();
    let cmd = &args[0];
    let target = &args[1];
    if cmd != "test" { error!("Unknown command: {cmd}"); return Ok(()); }
    let (script, target) = match target.as_str() {
        "milkv_duos:nsh" => ("oz64", target),
        "oz64:nsh"       => ("oz64", &"milkv_duos:nsh".into()),
        "rv-virt:knsh64" => ("knsh64", target),
        _ => { error!("Unknown target: {target}"); return Ok(()); }
    };
    println!("target={target}");
    println!("script={script}");

    // Fetch the PR
    let pr = pulls
        .get(pr_id)
        .await?;
    info!("{:#?}", pr.url);

    // Skip if PR State is Not Open
    if pr.state.clone().unwrap() != IssueState::Open {
        info!("Skipping Closed PR: {}", pr_id);
        return Ok(());
    }

    // Fetch the PR Reactions. Quit if Both Reactions are set.
    let reactions = get_reactions(issues, pr_id).await?;
    if reactions.0.is_some() && reactions.1.is_some() {
        info!("Skipping PR after 3 retries: {}", pr_id);
        return Ok(());
    }

    // Bump up the PR Reactions: 00 > 01 > 10 > 11
    bump_reactions(issues, pr_id, reactions).await?;

    // Build and Test the PR
    let response_text = build_test(&pr, target, script).await?;

    // Header for PR Comment
    let header = "[**\\[Experimental Bot, please feedback here\\]**](https://github.com/search?q=repo%3Aapache%2Fnuttx+15779&type=issues)";

    // Compose the PR Comment
    let comment_text =
        header.to_string() + "\n\n" +
        &response_text;

    // Post the PR Comment
    issues.create_comment(pr_id, comment_text).await?;

    // If successful, delete the PR Reactions
    delete_reactions(issues, pr_id).await?;
    info!("{:#?}", pr.url);

    // Wait 1 minute
    sleep(Duration::from_secs(60));

    // Return OK
    Ok(())
}
```

https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L203-L278

```rust
/// Build and Test the PR. Return the Build-Test Result.
async fn build_test(pr: &PullRequest, target: &str, script: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Get the Head Ref and Head URL from PR
    // let pr: Value = serde_json::from_str(&body).unwrap();
    // let pr_id = pr["number"].as_u64().unwrap();
    let head = &pr.head;
    let head_ref = &head.ref_field;  // "test-bot"
    let head_url = head.repo.clone().unwrap().html_url.unwrap();  // https://github.com/lupyuen2/wip-nuttx
    // println!("head_ref={head_ref}");
    // println!("head_url={head_url}");

    // True if URL is an Apps Repo
    let is_apps =
        if head_url.as_str().contains("apps") { true }
        else { false };

    // Set the URLs and Refs for NuttX and Apps
    let nuttx_hash = "HEAD";
    let nuttx_url =
        if is_apps { "https://github.com/apache/nuttx" }
        else { head_url.as_str() };
    let nuttx_ref =
        if is_apps { "master" }
        else { head_ref };
    let apps_hash = "HEAD";
    let apps_url = 
        if is_apps { head_url.as_str() }
        else { "https://github.com/apache/nuttx-apps" };
    let apps_ref =
        if is_apps { head_ref }
        else { "master" };

    // Build and Test NuttX: ./build-test.sh knsh64 /tmp/build-test.log HEAD HEAD https://github.com/apache/nuttx master https://github.com/apache/nuttx-apps master
    // Which calls: ./build-test-knsh64.sh HEAD HEAD https://github.com/apache/nuttx master https://github.com/apache/nuttx-apps master
    let cmd = format!("./build-test-{script}.sh \n  {nuttx_hash} {apps_hash} \n  {nuttx_url} {nuttx_ref} \n  {apps_url} {apps_ref}");
    println!("{cmd}");
    // std::process::exit(0); ////
    println!("PLEASE VERIFY");
    sleep(Duration::from_secs(30));

    // Start the Build and Test Script
    let log = "/tmp/nuttx-test-bot.log";
    let mut child = Command
        ::new("../nuttx-build-farm/build-test.sh")
        .arg(script).arg(log)
        .arg(nuttx_hash).arg(apps_hash)
        .arg(nuttx_url).arg(nuttx_ref)
        .arg(apps_url).arg(apps_ref)
        .spawn().unwrap();
    // println!("child={child:?}");

    // Wait for Build and Test to complete
    let status = child.wait().unwrap();  // 0 if successful
    println!("status={status:?}");

    // Upload the log as GitLab Snippet
    let log_content = fs::read_to_string(log).unwrap();
    let snippet_url = create_snippet(&log_content).await?;

    // Extract the Log Output
    let log_extract = extract_log(&snippet_url).await?;
    let log_content = log_extract.join("\n");
    println!("log_content=\n{log_content}");
    let mut result = 
        if status.success() { format!("Build and Test Successful ({target})\n") }
        else { format!("Build and Test **FAILED** ({target})\n") };
    result.push_str(&snippet_url);
    result.push_str("\n```text\n");
    result.push_str(&log_content);
    result.push_str("\n```\n");
    println!("result={result}");

    // Return the Result
    Ok(result)
}
```

# Build Script

Build and Test NuttX. Called by nuttx-test-bot

https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh

```bash
#!/usr/bin/env bash
## Build and Test NuttX. Called by nuttx-test-bot.
## ./build-test.sh knsh64 /tmp/build-test.log
## ./build-test.sh knsh64 /tmp/build-test.log HEAD HEAD
## ./build-test.sh knsh64 /tmp/build-test.log HEAD HEAD https://github.com/apache/nuttx master https://github.com/apache/nuttx-apps master
echo "Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh $1 $2 $3 $4 $5 $6 $7 $8"

set -e  ## Exit when any command fails
set -x  ## Echo commands

## First Parameter is the Build Test Script, like "knsh64"
script=$1
if [[ "$script" == "" ]]; then
  echo "ERROR: Script is missing (e.g. knsh64)"
  exit 1
fi

## Second Parameter is the Log File, like "/tmp/build-test.log"
log=$2
if [[ "$log" == "" ]]; then
  echo "ERROR: Log File is missing (e.g. /tmp/build-test.log)"
  exit 1
fi

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"

## Get the `script` option
if [ "`uname`" == "Linux" ]; then
  script_option=-c
else
  script_option=
fi

## Build and Test NuttX
function build_test {
  local script=$1
  local log=$2

  ## Propagate the Return Status from Script
  pushd /tmp
  set +e  ## Ignore errors
  script $log \
    --return \
    $script_option \
    "$script_dir/build-test-$script.sh $3 $4 $5 $6 $7 $8"
  res=$?
  set -e  ## Exit when any command fails
  popd

  ## Find errors and warnings
  clean_log $log
  find_messages $log
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

## Build and Test NuttX
build_test \
  $script \
  $log \
  $3 $4 $5 $6 $7 $8

set +x ; echo "***** Done! res=$res" ; set -x
exit $res
```

Build and Test NuttX for Oz64 SG2000 RISC-V SBC

https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-oz64.sh

```bash
#!/usr/bin/env bash
## Build and Test NuttX for Oz64 SG2000 RISC-V SBC
## ./build-test-oz64.sh
## ./build-test-oz64.sh HEAD HEAD
## ./build-test-oz64.sh HEAD HEAD https://github.com/apache/nuttx master https://github.com/apache/nuttx-apps master
echo "Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-oz64.sh $1 $2 $3 $4 $5 $6"

set -e  #  Exit when any command fails
set -x  #  Echo commands

## Server that controls Oz64
export OZ64_SERVER=tftpserver

nuttx_hash=$1  ## Optional NuttX Hash (HEAD)
apps_hash=$2   ## Optional Apps Hash (HEAD)
nuttx_url=$3   ## Optional NuttX URL (https://github.com/apache/nuttx)
nuttx_ref=$4   ## Optional NuttX Ref (master)
apps_url=$5    ## Optional Apps URL (https://github.com/apache/nuttx-apps
apps_ref=$6    ## Optional Apps Ref (master)
neofetch

## Set the defaults
if [[ "$nuttx_hash" == "" ]]; then
  nuttx_hash=HEAD
fi
if [[ "$apps_hash" == "" ]]; then
  apps_hash=HEAD
fi
if [[ "$nuttx_url" == "" ]]; then
  nuttx_url=https://github.com/apache/nuttx
fi
if [[ "$nuttx_ref" == "" ]]; then
  nuttx_ref=master
fi
if [[ "$apps_url" == "" ]]; then
  apps_url=https://github.com/apache/nuttx-apps
fi
if [[ "$apps_ref" == "" ]]; then
  apps_ref=master
fi

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"

## Run in a Temp Folder
nuttx_ref2=$(echo $nuttx_ref | tr '/' '_')
apps_ref2=$(echo $apps_ref | tr '/' '_')
tmp_path=/tmp/build-test-oz64-$nuttx_ref2-$apps_ref2
rm -rf $tmp_path
mkdir $tmp_path
cd $tmp_path

## Download NuttX and Apps
git clone $nuttx_url nuttx --branch $nuttx_ref
git clone $apps_url  apps  --branch $apps_ref

## Switch to this NuttX Commit
if [[ "$nuttx_hash" != "" ]]; then
  pushd nuttx
  git reset --hard $nuttx_hash
  popd
fi

## Switch to this Apps Commit
if [[ "$apps_hash" != "" ]]; then
  pushd apps
  git reset --hard $apps_hash
  popd
fi

## Dump the NuttX and Apps Hash
set +x  ## Disable Echo
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd
set -x  ## Enable Echo

## Show the GCC and Rust versions
riscv-none-elf-gcc -v
rustup --version || true
rustc  --version || true

## Configure the NuttX Build
cd nuttx
tools/configure.sh milkv_duos:nsh

## Build the NuttX Kernel
make -j
riscv-none-elf-size nuttx

## Build the NuttX Apps
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Generate Initial RAM Disk
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.pad

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.pad initrd \
  >Image

## Copy the NuttX Image to TFTP Server
scp Image $OZ64_SERVER:/tftpboot/Image-sg2000
ssh $OZ64_SERVER ls -l /tftpboot/Image-sg2000

## Run the NuttX Test
cd $script_dir
expect ./oz64.exp
```

# Power On SBC

https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64-power.sh

```bash
#!/usr/bin/env bash
## Power Oz64 On or Off
## ./oz64-power on
## ./oz64-power off
echo "Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64-power.sh $1"

set -e  ## Exit when any command fails

## First Parameter is on or off
state=$1
if [[ "$state" == "" ]]; then
  echo "ERROR: Specify 'on' or 'off'"
  exit 1
fi

## Get the Home Assistant Token, copied from http://localhost:8123/profile/security
## export HOME_ASSISTANT_TOKEN=xxxx
. $HOME/home-assistant-token.sh

## Set the Home Assistant Server
export HOME_ASSISTANT_SERVER=luppys-mac-mini.local:8123

echo "----- Power $state Oz64"
curl \
    -X POST \
    -H "Authorization: Bearer $HOME_ASSISTANT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"entity_id\": \"automation.oz64_power_$state\"}" \
    http://$HOME_ASSISTANT_SERVER/api/services/automation/trigger
```

power3

![TODO](https://lupyuen.org/images/testbot-power3.png)

power4

![TODO](https://lupyuen.org/images/testbot-power4.png)

power1

![TODO](https://lupyuen.org/images/testbot-power1.png)

power2

![TODO](https://lupyuen.org/images/testbot-power2.png)

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

[__lupyuen.org/src/testbot.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot.md)

![PR Test Bot is hosted on this hefty Ubuntu Xeon Workstation](https://lupyuen.org/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_PR Test Bot is hosted on this hefty Ubuntu Xeon Workstation_](https://qoto.org/@lupyuen/113517788288458811)

</span>
