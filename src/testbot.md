# Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)

📝 _28 Feb 2025_

![Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-title.jpg)

We're [__Making Things Better__](https://lists.apache.org/thread/mn4l1tmr6fj46o2y9vvrmfcrgyo48s5d) _(and making better things)_ with [__Apache NuttX RTOS__](TODO).

Our new __Test Bot for Pull Requests__ will allow a [__Pull Request Comment__](https://github.com/apache/nuttx/pull/15756#issuecomment-2641277894) to trigger a __NuttX Build + Test__ on Real Hardware. This PR Comment...

```bash
@nuttxpr test oz64:nsh
```

Will trigger our PR Test Bot to download the PR Code and test it on [__Oz64 SG2000 RISC-V SBC__](TODO). (Pic above)

This is super helpful for __Testing Pull Requests__ before Merging.

TODO: In this article

TODO: But might have [__Security Implications__](https://github.com/apache/nuttx/issues/15731#issuecomment-2628647886). (We'll come back to this)

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

TODO: Pic of Build & Test Server, Test Controller, Oz64

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
## Check the response from OSTest`...
expect {

  ## If OSTest completes successfully...
  "ostest_main: Exiting with status 0" { 

    ## Terminate the `screen` session: Ctrl-A k y
    ## Exit the SSH Session
    send -s "\x01ky"
    send -s "exit\r"

    ## Power off Oz64 and Exit normally
    system "./oz64-power.sh off"
    exit 0 
  }

  ## If OSTest Fails: Exit with an error
  ## Omitted: Power off Oz64. Terminate the `screen` session and SSH Session
  timeout { ...
    exit 1 
  }
}
```

# Pass Through to Oz64

_Erm this Expect Script runs on Build & Test Server? Not Test Controller?_

Ah the __NuttX Commands__ above will work, no worries! Build & Test Server _(Ubuntu PC)_ will ask Test Controller _(Linux SBC)_ to __pass them through__ to Oz64.

That's why our __Expect Script__ does this on Build & Test Server: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp)

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
send -s "screen -x\r" ; sleep 5
send -s "\x01ky\r"    ; sleep 5

## Connect to USB Serial Terminal via the `screen` command
## Test Controller (Linux SBC) now becomes a passthrough
expect "$"
send -s "screen /dev/ttyUSB0 115200\r"

## Power Oz64 Off and On
system "./oz64-power.sh off" ; sleep 5
system "./oz64-power.sh on"

## Wait for the NuttX Prompt
expect {
  "nsh> " {}

  ## If NuttX Crashes: Exit with an error
  ## Omitted: Power off Oz64. Terminate the `screen` session and SSH Session
  timeout { ...
    exit 1 
  }
}

## Omitted: Enter the NuttX Commands and validate the responses
## send -s "uname -a\r"
```

(How to power up Oz64? See below)

Turning our Test Controller into a __Passthrough for NuttX Commands__...

```bash
## Watch How It Works...
## Build & Test Server: Launches a shell on Test Controller...
$ ssh test-controller

## Test Controller: Connects to Oz64 Serial Terminal...
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

- Compile the __NuttX Kernel__ _(plus NuttX Apps)_

- Copy them to __Test Controller__ _(Linux SBC)_

- Start the __Expect Script__ _(from above)_

- So Test Controller will __Boot Oz64__ _(over TFTP)_

- And send __Test Commands__ _(to NuttX Shell)_

Like so: [build-test-oz64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-oz64.sh)

```bash
## TODO: nuttx_url / apps_url

## Build and Test NuttX for Oz64 SG2000 RISC-V SBC
## Download NuttX and Apps
git clone https://github.com/USERNAME/nuttx    nuttx --branch BRANCH
git clone https://github.com/apache/nuttx-apps apps  --branch master

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

## Copy the NuttX Image to our Test Controller (TFTP Server)
scp Image test-controller:/tftpboot/Image-sg2000
ssh test-controller ls -l /tftpboot/Image-sg2000

## Start the Expect Script
## That runs the NuttX Test on Oz64
expect ./oz64.exp
```

# Test Bot for Pull Requests

_How will a Pull Request trigger the script above?_

With a little help from [__GitHub API__](TODO). Our Test Bot shall...

- Fetch the __Newest Notifications__ for _@nuttxpr_

- Find a __Mentioned Comment__: _"@nuttxpr test oz64:nsh"_

- __Build and Test__ NuttX on Oz64 _(script above)_

- Capture the __Test Log__ _(and extract the essential bits)_

- Post the Test Log as a __PR Comment__

This is how we __Fetch Notifications__ for _@nuttxpr_: [main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L43-L111)

```rust
// Fetch all Notifications for @nuttxpr
let notifications = octocrab
  .activity()       // Get User Activity from GitHub
  .notifications()  // Notifications specifically
  .list()           // Return as a list
  .all(true)        // Read and Unread Notifications
  .send()           // Fetch from GitHub
  .await?;          // Block until completed

// For Every Notification...
for n in notifications {

  // Handle only Mentions
  let reason = &n.reason;
  if reason != "mention" { continue; }

  // Fetch the PR from the Notification
  // Handle only PR Notifications
  let pr_url = n.subject.url.clone().unwrap();  // https://api.github.com/repos/lupyuen2/wip-nuttx/pulls/88
  if !pr_url.as_str().contains("/pulls/") { continue; }

  // Omitted: Extract the PR Number from PR URL
  // Allow only Specific Repos: apache/nuttx, apache/nuttx-apps
  ...

  // Execute the Build & Test for Oz64
  // Post the Test Log as a PR Comment
  process_pr(&pulls, &issues, pr_id).await?;
}
```

This is how we execute the __Build & Test__ for Oz64. Then post the __Test Log__ as a PR Comment: [main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L111-L175)

```rust
/// Execute the Build & Test for Oz64. Post the Test Log as a PR Comment.
async fn process_pr(...) -> Result<...> {

  // Fetch the PR from GitHub
  let pr = pulls.get(pr_id).await?;

  // Get the Command and Args: ["test", "oz64:nsh"]
  // Omitted: Set target="milkv_duos:nsh", script="oz64"
  let args = get_command(issues, pr_id).await?;

  // Build and Test the PR on Oz64
  let response_text = build_test(&pr, target, script).await?;

  // Post the PR Comment. Return OK.
  let comment_text =
    header.to_string() + "\n\n" +
    &response_text;
  issues.create_comment(pr_id, comment_text).await?;
  Ok(())
}
```

# Bot calls Test Script

_What's inside build_test?_

It will call a script to execute the __Oz64 Build & Test__. And record the Test Log as a __GitLab Snippet__: [main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L203-L278)

```rust
/// Build and Test the PR. Return the Build-Test Result.
/// target="milkv_duos:nsh", script="oz64"
async fn build_test(pr: &PullRequest, target: &str, script: &str) -> Result<String, ...> {

  // Get the PR URL and PR Branch
  // Omitted: Set apps_url="https://github.com/apache/nuttx-apps", apps_ref="master"
  let head = &pr.head;
  let nuttx_ref = &head.ref_field;
  let nuttx_url = head.repo.clone().unwrap().html_url.unwrap();

  // Start the Build and Test Script
  // Record the Test Log
  let log = "/tmp/nuttx-test-bot.log";
  let mut child = Command
    ::new("../nuttx-build-farm/build-test.sh")
    .arg(script).arg(log)
    .arg("HEAD").arg("HEAD")
    .arg(nuttx_url).arg(nuttx_ref)
    .arg(apps_url).arg(apps_ref)
    .spawn().unwrap();

  // Wait for Build and Test to complete (0 if successful)
  let status = child.wait().unwrap();

  // Upload the Test Log as GitLab Snippet
  let log_content = fs::read_to_string(log).unwrap();
  let snippet_url = create_snippet(&log_content).await?;

  // Extract the essential bits from Test Log
  // Return the Extracted Test Log and Snippet URL
  let log_extract = extract_log(&snippet_url).await?;
  let log_content = log_extract.join("\n");
  let mut result = 
    if status.success() { format!("Build and Test Successful ({target})\n") }
    else { format!("Build and Test **FAILED** ({target})\n") };
  result.push_str(&snippet_url);
  result.push_str(&log_content);
  Ok(result)
}
```

[(__create_snippet__ publishes the GitLab Snippet)](TODO)

Which will call our __Generic Build & Test Script__ like so: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh#L1-L7)

```bash
## Set the NuttX PR URL, branch and commit hash
nuttx_url=https://github.com/USERNAME/nuttx
nuttx_ref=BRANCH
nuttx_hash=HEAD

## Set the Apps PR URL, branch and commit hash
apps_url=https://github.com/apache/nuttx-apps
apps_ref=master
apps_hash=HEAD

## Start the Oz64 Build and Test
## Record the Test Log
build-test.sh \
  oz64 nuttx-test-bot.log \
  $nuttx_hash $apps_hash \
  $nuttx_url  $nuttx_ref \
  $apps_url   $apps_ref
```

[(__build-test.sh__ is explained here)](TODO)

[(Which calls the __Build & Test Script__ we saw earlier)](TODO)

[(How to run our __Test Bot__)](TODO)

[(See the __Bot Log__)](TODO)

# Power Up our Oz64 SBC

_We need to power up Oz64 so it will boot NuttX over TFTP. How to control the power?_

With an [__IKEA Smart Power Plug__](TODO) and [__IKEA Zigbee Hub__](TODO). Here's our script that __Flips the Oz64 Power__, On and Off: [oz64-power.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64-power.sh)

```bash
## This script will power Oz64 on or off...
## ./oz64-power on
## ./oz64-power off

## First Parameter is on or off
state=$1

## Set the Home Assistant Server
export HOME_ASSISTANT_SERVER=luppys-mac-mini.local:8123

## Get the Home Assistant Token, copied from http://localhost:8123/profile/security
## export HOME_ASSISTANT_TOKEN=xxxx
. $HOME/home-assistant-token.sh

## Call Home Assistant API: Power Oz64 On or Off
curl \
  -X POST \
  -H "Authorization: Bearer $HOME_ASSISTANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"entity_id\": \"automation.oz64_power_$state\"}" \
  http://$HOME_ASSISTANT_SERVER/api/services/automation/trigger
```

This script assumes that we have...

- Installed a [__Home Assistant Server__](TODO)

- Added the Smart Power Plug (and Zigbee Hub) to [__Google Home__](TODO)

- Installed the [__Google Home Integration__](TODO) for Home Assistant

- Created the [__Power Automation__](TODO) in Home Assistant: _"Oz64 Power On"_ and _"Oz64 Power Off"_...

power3

![TODO](https://lupyuen.org/images/testbot-power3.png)

power4

![TODO](https://lupyuen.org/images/testbot-power4.png)

power1

![TODO](https://lupyuen.org/images/testbot-power1.png)

power2

![TODO](https://lupyuen.org/images/testbot-power2.png)

# Securing Our Bot

1.  _A Bot that will auto-build and auto-test any Pull Request. What could possibly go wrong?_

    Plenty! The Pull Requests is awaiting __Manual Review__. It might contain __Unauthorised Code__ that will be executed by our Bot. _(Think: Makefiles with Malicious Scripts inside)_

    Or the Runtime Code might disrupt the __Local Network__ hosting our Bot. Also it might break out of the [__Semihosting Environment__](TODO) and mess up our Host Machine.

1.  _Has something happened before?_

    Five Years Ago: I connected a [__PineTime Smartwatch__](https://github.com/lupyuen/remote-pinetime-bot) to the net for anyone to test their firmware. Some folks discovered that they could break out of the [__Semihosting Environment__](https://github.com/lupyuen/remote-pinetime-bot?tab=readme-ov-file#security-issues) and access my computer.

1.  _Speaking of PineTime: How shall we allow auto-testing of firmware?_

    Let's assume NuttX has been ported to PineTime Smartwatch _(Nordic nRF52832)_. On our Test Controller _(Linux SBC)_, we'll run [__OpenOCD + ST-Link + Semihosting__](TODO) for flashing and testing.

    Watch Faces on PineTime will render on the __LVGL Display__. Our Test Controller shall have a __MIPI CSI Camera__, that will snap a pic of the LVGL Display. And attach the pic to the Test Log, for Manual Validation.

    We'll start our Test Bot manually, after reviewing the code in the PR. Or maybe our Bot shall push a notification to my phone (via __Mastodon Alert__). I'll review the PR, click "Like" on the PR Comment, to activate the test.

1.  _Can we combine the Test Controller with the Build & Test Server?_

    Yeah we could combine the __Test Controller__ _(Linux SBC)_ with the __Build & Test Server__ _(Ubuntu PC)_. Though the Current Design will scale better with __Multiple Test Controllers__...

    TODO: Pic of Multiple Test Controllers

    (Too bad we don't have a solution for Swapping SD Cards)

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

# Appendix: Build and Test NuttX

TODO

Called by nuttx-test-bot

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
