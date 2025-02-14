# Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)

📝 _16 Feb 2025_

![PINE64 Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-title.jpg)

We're always [__Making Things Better__](https://lists.apache.org/thread/pob88z6pnbg0pzt4syhhfwjyq3067h3b) _(and making better things)_ with [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html). Today we talk about our new __Test Bot for Pull Requests__.

Test Bot shall watch for [__Comments on Pull Requests__](https://github.com/apache/nuttx/pull/15756#issuecomment-2641277894) and start a __NuttX Build and Test__ on Real Hardware. This PR Comment...

```bash
@nuttxpr test oz64:nsh
```

Will trigger our PR Test Bot to __Download, Build and Test__ the PR Code on [__Oz64 SG2000 RISC-V SBC__](https://lupyuen.github.io/articles/sg2000) (pic above). Which is mighty helpful for __Validating Pull Requests__ (pic below) before Merging.

[(Watch the __Demo on YouTube__)](https://youtu.be/qiBhC5VTkIo)

_Why are we doing this?_

Testing a Pull Request on Real Hardware is a __Compulsory, Cumbersome Chore__. Executed by our Unpaid Volunteers who care about Code Quality. Let's make it a little less painful! 👍

(Be Mindful: Pull Requests might have [__Security Concerns__](https://lupyuen.github.io/articles/testbot#securing-our-bot))

![NuttX Bot for Building and Testing Pull Requests](https://lupyuen.org/images/rewind-bot3.jpg)

_(Thanks to PINE64 for sponsoring the Oz64 SBC)_

# Connect our Oz64 SBC

_Our Test Bot shall control Oz64. How?_

With an _(inexpensive)_ Arm64 Linux SBC, called the __Test Controller__. Oz64 won't boot over USB or Serial, we'll connect these instead...

- __Wired Ethernet__: For booting NuttX over TFTP _(Trivial File Transfer Protocol)_

- __UART0 Port__: For receiving NuttX Shell Commands _(TX: Pin 8, RX: Pin 10)_

- Which connects to our __Test Controller__ _(Linux SBC)_ via a USB Serial Dongle

- Test Controller is also our [__TFTP Server__](https://lupyuen.github.io/articles/sg2000#boot-nuttx-over-tftp) for booting NuttX on Oz64

![Connect our Oz64 SBC to Test Controller](https://lupyuen.org/images/testbot-flow2.jpg)

[(__Arm32 Boards__: STM32 and nRF52? Use __OpenOCD + ST-Link__)](https://nuttx.apache.org/docs/latest/quickstart/running.html)

[(__GPIO Wiring__ might be needed for RISC-V Boards)](https://lupyuen.github.io/articles/auto#connect-bl602-to-single-board-computer)

_How shall we test Oz64?_

Test Controller will send these __NuttX Commands__ to Oz64: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp#L56-L114)

```bash
## Record the NuttX Commit Hash
nsh> uname -a
NuttX 10.3.0 d33f654011 ...

## Check the Heap Memory
nsh> free
total: 2061312 / used: 11624 / free: 2049688 ...

## Show what's running
nsh> ps
/system/bin/init ...

## List the Device Drivers
nsh> ls -l /dev
console ...

## Simple App
nsh> hello
Hello, World!!

## App with Threading and Timers
nsh> getprime
getprime took 279 msec

## Omitted: Test `hello` and `getprime` again
## To verify the swapping of Address Spaces

## Exercise everything in NuttX
nsh> ostest
ostest_main: Exiting with status 0
```

[(See the __Test Log__)](https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4803688#L456)

[(Why we test __hello__ and __getprime__ twice)](https://lupyuen.github.io/articles/mmu#appendix-flush-the-mmu-cache-for-t-head-c906)

Responses to the above commands are validated by another machine...

![Test Controller (Linux SBC) accepts commands from the Build & Test Server (Ubuntu PC)](https://lupyuen.org/images/testbot-flow3.jpg)

# Control our Oz64 SBC

_Who controls our Test Controller?_

Our Test Controller _(Linux SBC)_ will accept commands from the __Build & Test Server__ _(Ubuntu PC, pic above)_.

Remember the NuttX Commands from Previous Section? Our Build & Test Server will run this [__Expect Script__](https://core.tcl-lang.org/expect/index) to send the commands to Oz64, passing through the Test Controller: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp#L56-L114)

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

The same script shall __Validate the Responses__ from Oz64: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp#L92-L114)

```bash
## Check the response from OSTest...
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

Even though it's NOT running on Test Controller...

![Pass Through to Oz64](https://lupyuen.org/images/testbot-flow4.jpg)

# Pass Through to Oz64

_Erm this Expect Script will run on Build & Test Server? Not Test Controller?_

Ah the __NuttX Commands__ above will work, no worries! Build & Test Server _(Ubuntu PC)_ will ask Test Controller _(Linux SBC)_ to __pass them through__ to Oz64.

That's why our __Expect Script__ does this on Build & Test Server: [oz64.exp](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64.exp#L1-L57)

```bash
## For every 1 character sent, wait 1 millisecond
## Wait at most 60 seconds for every command
set send_slow {1 0.001}
set timeout 60

## Connect from Build & Test Server (Ubuntu PC)
## to Test Controller (Linux SBC) over SSH
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

[(See the __Bot Log__)](https://gist.github.com/lupyuen/ef1bf2b899e6f1b7f036e34500dd9a97#file-gistfile1-txt-L376-L1491)

[(How to __Power up Oz64__)](https://lupyuen.github.io/articles/testbot#power-up-our-oz64-sbc)

The Expect Script will turn our Test Controller into a __Passthrough for NuttX Commands__...

```bash
## Watch How It Works...
## Build & Test Server: Launches a shell on Test Controller...
$ ssh test-controller

## Test Controller: Connects to Oz64 Serial Terminal...
$ screen -x
$ screen /dev/ttyUSB0 115200

## Test Controller: Passes through the NuttX Commands...
nsh> uname -a
NuttX 10.3.0 d33f654011 ...

## Build & Test Server: Validates the responses
```

Before the testing, we need to build NuttX...

[(Combining the __Linux SBC__ and __Ubuntu PC__)](https://lupyuen.github.io/articles/testbot#securing-our-bot)

![Build and Test Script](https://lupyuen.org/images/testbot-flow5.jpg)

# Build and Test Script

_Who runs the above Expect Script?_

The Expect Script above is called by our __Build & Test Script__ that will...

- Download the __NuttX Code__ _(from the Pull Request)_

- Compile the __NuttX Kernel__ _(plus NuttX Apps)_

- Copy them to __Test Controller__ _(Linux SBC)_

- Start the __Expect Script__ _(from above)_

- So Test Controller will __Boot Oz64__ _(over TFTP)_

- And send __Test Commands__ _(to NuttX Shell)_

Like so: [build-test-oz64.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-oz64.sh)

```bash
## Build and Test NuttX for Oz64 SG2000 RISC-V SBC
## Download NuttX and Apps based on the Pull Request
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

[(Explained here)](https://lupyuen.github.io/articles/sg2000#appendix-build-nuttx-for-sg2000)

Who calls this script? We find out...

![Test Bot for Pull Requests](https://lupyuen.org/images/testbot-flow6.jpg)

# Test Bot for Pull Requests

_How will a Pull Request trigger the script above?_

With a little help from [__GitHub API__](https://docs.github.com/en/rest/activity/notifications?apiVersion=2022-11-28#list-notifications-for-the-authenticated-user). Our Test Bot shall...

- Fetch the __Newest Notifications__ for _@nuttxpr_

- Find a __Mentioned Comment__: _"@nuttxpr test oz64:nsh"_

- __Download NuttX__ Source Code _(from the Pull Request)_

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
  .all(true)        // All Notifications: Read and Unread
  .send()           // Send the Request to GitHub
  .await?;          // Wait until completed

// For Every Notification...
for n in notifications {

  // We handle only Mentions
  let reason = &n.reason;
  if reason != "mention" { continue; }

  // We handle only PR Notifications
  // Fetch the PR from the Notification
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

__process_pr__ will execute the __Build & Test__ for Oz64. Then post the __Test Log__ as a PR Comment: [main.rs](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L111-L175)

```rust
/// Execute the Build & Test for Oz64.
/// Post the Test Log as a PR Comment.
async fn process_pr(...) -> Result<...> {

  // Fetch the PR from GitHub
  let pr = pulls.get(pr_id).await?;

  // Get the Command and Args: ["test", "oz64:nsh"]
  // Omitted: Set target="milkv_duos:nsh", script="oz64"
  let args = get_command(issues, pr_id).await?;

  // Build and Test the PR on Oz64
  let response_text = build_test(
    &pr,     // Pull Request fetched from GitHub
    target,  // "milkv_duos:nsh"
    script   // "oz64"
  ).await?;

  // Post the PR Comment
  let comment_text =
    header.to_string() + "\n\n" +
    &response_text;
  issues.create_comment(pr_id, comment_text).await?;
  Ok(())
}
```

Finally we're ready for the Big Picture...

[(How to run __Test Bot__)](https://github.com/lupyuen/nuttx-test-bot/blob/main/run.sh)

[(See the __Bot Log__)](https://gist.github.com/lupyuen/ef1bf2b899e6f1b7f036e34500dd9a97)

![Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-flow.jpg)

# Bot calls Test Script

_Test Bot calls build_test. What's inside build_test?_

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
  let log_extract = extract_log(&snippet_url).await?;
  let log_content = log_extract.join("\n");
  let mut result = 
    if status.success() { format!("Build and Test Successful ({target})\n") }
    else { format!("Build and Test **FAILED** ({target})\n") };

  // Return the Extracted Test Log and Snippet URL
  result.push_str(&snippet_url);
  result.push_str(&log_content);
  Ok(result)
}
```

[(__create_snippet__ publishes the GitLab Snippet)](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L370-L417)

Which will call our __Generic Build & Test Script__ like so: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh#L1-L7)

```bash
## Download this NuttX PR: URL, branch and commit hash
nuttx_url=https://github.com/USERNAME/nuttx
nuttx_ref=BRANCH
nuttx_hash=HEAD

## Download this Apps PR: URL, branch and commit hash
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

[(__build-test.sh__ is explained here)](https://lupyuen.github.io/articles/testbot#appendix-build-and-test-nuttx)

[(Calling the __Build & Test Script__ we saw earlier)](https://lupyuen.github.io/articles/testbot#build-and-test-script)

![Evidence of a Successful Testing](https://lupyuen.org/images/rewind-bot3.jpg)

_What about the essential bits?_

[__extract_log__](https://github.com/lupyuen/nuttx-test-bot/blob/main/src/main.rs#L279-L370) will pick out the evidence of a __Successful Test__: _Commit Hash, Build Steps, OSTest Result (or Crash Dump)_

```bash
## Extracted Test Log will look like this...
## Build and Test Successful (milkv_duos:nsh)
$ git clone https://github.com/USERNAME/nuttx    nuttx --branch BRANCH
$ git clone https://github.com/apache/nuttx-apps apps  --branch master

$ pushd nuttx ; git reset --hard HEAD ; popd
HEAD is now at d33f654011 include/stdlib.h: define system() prototype for the flat build
$ pushd apps  ; git reset --hard HEAD ; popd
HEAD is now at f139e56cd testing/libc/wcstombs: Add testing application for wcstombs

NuttX Source: https://github.com/apache/nuttx/tree/d33f6540113b8a5a4392f8a69b1a8b6258669f64
NuttX Apps:   https://github.com/apache/nuttx-apps/tree/f139e56cd62a30d6edcd7207c7e4cbc6e9b8b7d1

$ cd nuttx
$ tools/configure.sh milkv_duos:nsh
$ make -j
...
$ ssh test-controller
OpenSBI v0.9
nsh> uname -a
NuttX 10.3.0 d33f654011 Feb  7 2025 06:49:26 risc-v milkv_duos
nsh> ostest
ostest_main: Exiting with status 0
```

The __Test Evidence__ becomes a [__PR Comment__](https://github.com/apache/nuttx/pull/15756#issuecomment-2641300672) (pic above). With this evidence, we can safely Merge the Pull Request into NuttX!

[(See the __Extracted Log__)](https://github.com/apache/nuttx/pull/15756#issuecomment-2641300672)

[(Watch the __Demo on YouTube__)](https://youtu.be/qiBhC5VTkIo)

![IKEA Smart Power Plug and IKEA Zigbee Hub](https://lupyuen.org/images/testbot-ikea.png)

# Power Up our Oz64 SBC

_We need to power up Oz64 so it will boot NuttX over TFTP. How to control the power?_

With an [__IKEA Smart Power Plug__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug) and [__IKEA Zigbee Hub__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug). Here's our script that __Flips the Oz64 Power__, On and Off: [oz64-power.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/oz64-power.sh)

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

## Call the Home Assistant API:
## Power Oz64 On or Off
curl \
  -X POST \
  -H "Authorization: Bearer $HOME_ASSISTANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"entity_id\": \"automation.oz64_power_$state\"}" \
  http://$HOME_ASSISTANT_SERVER/api/services/automation/trigger
```

This script assumes that we have...

- Installed a [__Home Assistant Server__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _(Works fine with Docker)_

- Added the Smart Power Plug to [__Google Assistant__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug)

  _"Oz64 Power" (pic above)_

- Installed the [__Google Assistant SDK__](https://lupyuen.github.io/articles/sg2000a#ikea-smart-power-plug) for Home Assistant

  _(So we don't need Zigbee programming)_

- Created the [__Power Automation__](https://lupyuen.github.io/articles/sg2000a#call-the-home-assistant-api) in Home Assistant

  _"Oz64 Power On"_ and _"Oz64 Power Off" (pic below)_

And our Test Bot is complete! Except for these security issues...

![Automations in Home Assistant: Oz64 Power On and Oz64 Power Off](https://lupyuen.org/images/testbot-power.png)

# Securing Our Bot

1.  _Our Bot shall Auto-Build and Auto-Test any Pull Request. What could possibly go wrong?_

    Plenty! The Pull Request is awaiting __Manual Review__. It might contain __Unauthorised Code__ that will be executed by our Bot. _(Think: Makefiles with Malicious Scripts inside)_

    Or the Runtime Code might disrupt the __Local Network__ hosting our Bot. Also it might break out of the [__Semihosting Environment__](https://lupyuen.github.io/articles/semihost#nuttx-calls-semihosting) and mess up our Host Machine.

1.  _Has something happened before?_

    Five Years Ago: I connected a [__PineTime Smartwatch__](https://github.com/lupyuen/remote-pinetime-bot) _(Apache Mynewt)_ to the internet, for anyone to test their firmware. Some kind folks disclosed that they could break out of the [__Semihosting Environment__](https://github.com/lupyuen/remote-pinetime-bot?tab=readme-ov-file#security-issues) and access my computer.

1.  _Thus we're doing it the wiser, safer way?_

    Indeed. Today we [__Start Manually__](https://github.com/lupyuen/nuttx-test-bot/blob/main/run.sh) our Test Bot, after reviewing the code in the PR. We do this for all Pull Requests involving __RISC-V Architecture__.
    
    It gets better! Soon: Test Bot will run non-stop and push a [__Mastodon Alert__](https://lupyuen.github.io/articles/mastodon) to our phones, when it's triggered. To activate the PR Test, we review the PR and click _"Like"_ on the PR Comment.

    ![Remote PineTime Live Stream](https://lupyuen.org/images/remote-pinetime-youtube.png)

1.  _Speaking of PineTime: How shall we allow auto-testing of firmware?_

    Let's assume NuttX has been ported to PineTime Smartwatch _(Nordic nRF52832)_. On our Test Controller _(Linux SBC)_, we'll run [__OpenOCD + ST-Link + Semihosting__](https://nuttx.apache.org/docs/latest/quickstart/running.html) for flashing and testing.

    Watch Faces on PineTime will render on the __LVGL Display__ (pic above). Our Test Controller shall have a __MIPI CSI Camera__, that will snap a pic of the LVGL Display. And attach the pic to the Test Log, for Manual Validation.

1.  _Can we combine the Test Controller with the Build & Test Server?_

    Yeah we could combine the __Test Controller__ _(Linux SBC)_ with the __Build & Test Server__ _(Ubuntu PC)_. Though the Current Design will scale better with __Multiple Test Controllers__ and a [__MicroSD Multiplexer__](https://www.tindie.com/products/3mdeb/sd-wire-sd-card-reader-sd-card-mux/)...

![Multiple Test Controllers](https://lupyuen.org/images/testbot-multi.jpg)

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

![Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-flow.jpg)

# Appendix: Build and Test NuttX

Earlier we spoke about our Test Bot calling the __Generic Build & Test Script__...

- [__"Bot calls Test Script"__](https://lupyuen.github.io/articles/testbot#bot-calls-test-script)

```bash
## Download this NuttX PR: URL, branch and commit hash
nuttx_url=https://github.com/USERNAME/nuttx
nuttx_ref=BRANCH
nuttx_hash=HEAD

## Download this Apps PR: URL, branch and commit hash
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

This section explains what's inside [__build-test.sh__](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh).

Here are the parameters for our script: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh)

```bash
## First Parameter is the Build & Test Script, like "oz64"
## Second Parameter is the Log File, like "/tmp/build-test.log"
## Other Parameters shall be passed through to the Build & Test Script:
##   nuttx_hash apps_hash
##   nuttx_url  nuttx_ref
##   apps_url   apps_ref
script=$1  ## oz64
log=$2     ## /tmp/build-test.log

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
build_test \
  $script \
  $log \
  $3 $4 $5 $6 $7 $8

## Return the Result Code to the caller
exit $res
```

__build_test__ will call the __Platform-Specific__ Build & Test Script, like for Oz64. The Test Log will be recorded into the Log File: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh#L35-L56)

```bash
## Build and Test NuttX
function build_test {
  local script=$1  ## oz64
  local log=$2     ## /tmp/build-test.log

  ## Call the Platform-Specific Build & Test Script: build-test-oz64.sh
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
```

[(__Oz64 Build & Test Script__ is explained here)](https://lupyuen.github.io/articles/testbot#build-and-test-script)

The code above calls __clean_log__ and __find_messages__.

__clean_log__ will remove Special Characters from the Log File: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh#L56-L75)

```bash
## Strip the Control Characters from the Log File
function clean_log {
  local log_file=$1  ## /tmp/build-test.log
  local tmp_file=$log_file.tmp  ## /tmp/build-test.log.tmp
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
}
```

__find_messages__ will search for Warning and Errors, and insert them into the top of the Log File: [build-test.sh](https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test.sh#L75-L90)

```bash
## Search for Errors and Warnings
function find_messages {
  local log_file=$1  ## /tmp/build-test.log
  local tmp_file=$log_file.tmp  ## /tmp/build-test.log.tmp
  local msg_file=$log_file.msg  ## /tmp/build-test.log.msg
  local pattern='^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$'
  grep '^\*\*\*\*\*' $log_file \
    > $msg_file || true
  grep -P "$pattern" $log_file \
    | uniq \
    >> $msg_file || true
  cat $msg_file $log_file >$tmp_file
  mv $tmp_file $log_file
}
```

_Why the funny Regex Pattern?_

The __Regex Pattern__ above is the same one that NuttX uses to detect errors in our [__Continuous Integration__](https://github.com/apache/nuttx/blob/master/.github/workflows/build.yml#L172-L180) builds: [.github/gcc.json](https://github.com/apache/nuttx/blob/master/.github/gcc.json)

```bash
## Filename : Line : Col : warning/error : Message
^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$
```

Which will match and detect [__GCC Compiler Errors__](https://gist.github.com/nuttxpr/62d5cc0da1686174446b3614ea208af0#file-ci-arm-12-log-L1) like...

```bash
chip/stm32_gpio.c:41:11: warning: CONFIG_STM32_USE_LEGACY_PINMAP will be deprecated
```

But it won't match [__CMake Errors__](https://gist.github.com/nuttxpr/353f4c035473cdf67afe0d76496ca950#file-ci-arm-11-log-L421-L451) like this!

```text
CMake Warning at cmake/nuttx_kconfig.cmake:171 (message):
  Kconfig Configuration Error: warning: STM32_HAVE_HRTIM1_PLLCLK (defined at
  arch/arm/src/stm32/Kconfig:8109) has direct dependencies STM32_HRTIM &&
  ARCH_CHIP_STM32 && ARCH_ARM with value n, but is currently being y-selected
```

And [__Linker Errors__](https://gist.github.com/nuttxpr/74e46f5eca2a0cd5a234e5389d40457a#file-ci-arm-04-log-L157)...

```text
arm-none-eabi-ld: /root/nuttx/staging//libc.a(lib_arc4random.o): in function `arc4random_buf':
/root/nuttx/libs/libc/stdlib/lib_arc4random.c:111:(.text.arc4random_buf+0x26): undefined reference to `clock_systime_ticks'
```

Also __Network and Timeout Errors__...

```text
curl: (6) Could not resolve host: github.com
make[1]: *** [open-amp.defs:59: open-amp.zip] Error 6
```

We might need to tweak the Regex Pattern and catch more errors.

![PR Test Bot is hosted on this hefty Ubuntu Xeon Workstation](https://lupyuen.org/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_PR Test Bot is hosted on this hefty Ubuntu Xeon Workstation_](https://qoto.org/@lupyuen/113517788288458811)

</span>
