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

TODO: Pic of Test Controller + Oz64

# Connect our Oz64 SBC

Oz64 won't boot over USB or Serial. We'll connect these to control Oz64 (pic above)

- __Wired Ethernet__: For booting NuttX over TFTP

- __UART0 Port__: For receiving NuttX Shell Commands (Pins TODO)

- Which connects to our __Test Controller__ (Linux SBC) via a USB Serial Dongle

- Test Controller is also our __TFTP Server__ for booting NuttX on Oz64

  [(What about __Simpler Boards__: STM32 and nRF52? Use __OpenOCD + ST-Link__)](https://nuttx.apache.org/docs/latest/quickstart/running.html)

_How shall we test Oz64?_

Test Controller sends these __NuttX Commands__ to Oz64: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp)

```bash
## Record the NuttX Commit Hash
nsh> uname -a
TODO

## Check for corrupted Heap Memory
nsh> free
TODO

## Show what's running
nsh> ps
TODO

## List the Device Drivers
nsh> ls -l /dev
TODO

## Simple App
nsh> hello
TODO

## App with Threading and Timers
nsh> getprime
TODO

## Omitted: Test `hello` and `getprime` again
## To verify the swapping of Address Spaces

## Exercise everything in NuttX
nsh> ostest
TODO
```

[(Why we test __hello__ and __getprime__ twice)](TODO)

The responses to the above commands are validated by another machine...

TODO: Pic of Build & Test Server, Test Controller, Ox64

# Control our Oz64 SBC

_Who controls our Test Controller?_

Our Test Controller (Linux SBC) accepts commands from the __Build & Test Server__ (Ubuntu PC).

Remember the NuttX Commands from Previous Section? Our Build & Test Server runs this __Expect Script__ to send the commands to Oz64, passing through the Test Controller: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp)

```bash
## Wait at most 300 seconds for each command
set timeout 300

## Expect Script for Testing NuttX on Oz64 SG2000, over SSH to SBC
send -s "uname -a\r"

## Wait for the prompt and enter `free`
expect "nsh> "
send -s "free\r"

## Wait for the prompt and enter `ps`
expect "nsh> "
send -s "ps\r"

## Omitted: Send the other commands
...

## Wait for the prompt and enter `ostest`
expect "nsh> "
send -s "ostest\r"
```

The same script shall __Validate the Responses__ from Oz64: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp)

```bash
## Check the response from `ostest`...
expect {
  ## If we see this message...
  "ostest_main: Exiting with status 0" { 

    ## Terminate the `screen` session: Ctrl-A k y
    ## Exit the SSH Session
    send -s "\x01ky"
    send -s "exit\r"

    ## Power off Oz64 and Exit normally
    system "./oz64-power.sh off"
    exit 0 
  }

  ## If we don't see the message, exit with an error
  ## Omitted: Power off Oz64. Terminate the `screen` session and SSH Session
  timeout { ...
    exit 1 
  }
}
```

But these commands will only work when we tell __Test Controller__ (Linux SBC) to pass them through to Oz64. That's why our __Expect Script__ does this at the top: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp)

```bash
## For every 1 character sent, wait 1 millisecond
## Wait at most 60 seconds for every command
set send_slow {1 0.001}
set timeout 60

## Connect from Build & Test Server (Ubuntu PC)
## to Test Controller (Linux SBC) over SSH
## Will execute `ssh test-controller`
## Then wake up the SBC
spawn ssh test-controller
send -s "\r"

## Terminate the Previous Session for the `screen` command: Ctrl-A k y
expect "$"
send -s "screen -x\r"
sleep 5
send -s "\x01ky\r"
sleep 5

## Connect to USB Serial Terminal via the `screen` command
## Test Controller (Linux SBC) now becomes a passthrough
expect "$"
send -s "screen /dev/ttyUSB0 115200\r"

## Power Oz64 Off and On
system "./oz64-power.sh off"
sleep 5
system "./oz64-power.sh on"

## Wait for the NuttX Prompt
expect {
  "nsh> " {}

  ## If timeout, exit with an error
  ## Omitted: Power off Oz64. Terminate the `screen` session and SSH Session
  timeout { ...
    exit 1 
  }
}

## Omitted: Enter the NuttX Commands and validate the responses
send -s "uname -a\r"
```

Turning our Test Controller into a __Passthrough for NuttX Commands__...

```bash
## Build & Test Server: Launches a shell on Test Controller...
$ ssh test-controller

## Test Controller: Executes these Linux Commands...
$ screen -x
$ screen /dev/ttyUSB0 115200

## Test Controller: Passes through the NuttX Commands...
nsh> uname -a
TODO

## Build & Test Server: Validates the responses
```

(Can we combine the Linux SBC and Ubuntu PC? We'll come back to this)

# Build and Test Script

_Who runs the above Expect Script?_

The Expect Script above is called by our __Build & Test Script__ that will...

- Compile the NuttX Kernel and Apps

- Copy them to our Test Controller (Linux SBC)

- Start the Expect Script (from Previous Section)

- So that Test Controller will boot Oz64 (over TFTP) and send the NuttX Test Commands

Like so: [build-test-oz64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-oz64.sh)

```bash
## TODO: nuttx_url / apps_url

## Build and Test NuttX for Oz64 SG2000 RISC-V SBC
## Download NuttX and Apps
git clone $nuttx_url nuttx --branch $nuttx_ref
git clone $apps_url  apps  --branch $apps_ref

## Configure the NuttX Build
cd nuttx
tools/configure.sh milkv_duos:nsh

## Build the NuttX Kernel
## And the NuttX Apps
make -j
make -j export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j import
popd

## Generate the NuttX Image:
## NuttX Kernel + Padding + NuttX Apps
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"
head -c 65536 /dev/zero >/tmp/nuttx.pad
cat nuttx.bin /tmp/nuttx.pad initrd >Image

## Copy the NuttX Image to TFTP Server (Test Controller)
scp Image test-controller:/tftpboot/Image-sg2000
ssh test-controller ls -l /tftpboot/Image-sg2000

## Start the Expect Script
## That runs the NuttX Test on Oz64
expect ./oz64.exp
```

Build and Test NuttX. Called by nuttx-test-bot

[nuttx-build-farm/build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh)

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

# Test Bot for Pull Requests

_How will a Pull Request trigger the script above?_

[nuttx-test-bot/main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs)

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

[main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L43-L111)

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

[main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L111-L175)

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

[main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L203-L278)

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

# Power Up our Oz64 SBC

One Final Step: How we flip the Power, On and Off for our Oz64 SBC.

[nuttx-build-farm/oz64-power.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64-power.sh)

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

# Security Implications

TODO

Reminder to myself: Be careful when running Unmerged Code on our Home Computers. In case the PR contains any Scripts or Apps that may cause problems on our Home Computer or Home Network.

Basically we only operate on NuttX repos, so there should be no malware... but anyone can send PR with anything true!!!

How to prevent problems? Network separation? One time use containers / jails / vm with restricted network access?

I might try a scaled-down simpler implementation that has less security risk. For example, when I post a PR Comment @nuttxpr please test, then our Test Bot will download the PR and run Build + Test on QEMU RISC-V 🤔

5 Years Ago: We had Security Issues with a PineTime Smartwatch that we opened up for Remote Testing :-)

Notify via Mastodon. Click "Like" on the PR to approve?

[Remote PineTime Bot: Security Issues](https://github.com/lupyuen/remote-pinetime-bot?tab=readme-ov-file#security-issues)

1.  NuttX Scripts

1.  Network Access (DMZ / Guest Network)

1.  Semihosting: Breaking out from Semihosting Guest to Semihosting Host

_If we had to do it all again with NuttX on PineTime?_

Same: SBC with OpenOCD + Semihosting. Send Screenshot in PR Comment

# TODO

Combine Build & Test Server with Test Controller

Multiple Test Controllers

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
