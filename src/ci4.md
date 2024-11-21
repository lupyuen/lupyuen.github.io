# Continuous Integration Dashboard for Apache NuttX RTOS  (Prometheus and Grafana)

📝 _24 Nov 2024_

![Continuous Integration Dashboard for Apache NuttX RTOS](https://lupyuen.github.io/images/ci4-dashboard.png)

Last article we spoke about the __(Twice) Daily Builds__ for [__Apache NuttX RTOS__](TODO)...

- [__"Optimising the Continuous Integration for Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ci3)

Today we'll talk about __Monitoring the Daily Builds__ (also the [__NuttX Build Farm__](TODO)) with our __NuttX Dashboard__...

- TODO

- TODO

- TODO

_What will NuttX Dashboard tell us?_

NuttX Dashboard shows a __Snapshot of Failed Builds__ for the present moment. (Pic above)

We may __Filter the Builds__ by Architecture, Board and Config...

![TODO](https://lupyuen.github.io/images/ci4-filter.png)

The snapshot includes builds from the (community-hosted) [__NuttX Build Farm__](TODO) as well as __GitHub Actions__ (twice-daily builds).

To see __GitHub Actions Only__: Click __`[+]`__ and set __`User`__ to __`NuttX`__...

![TODO](https://lupyuen.github.io/images/ci4-user.png)

To see the __History of Builds__: Click the link for _"NuttX Build History"_. Remember to select the Board and Config. (Pic below)

_Sounds Great! What's the URL?_

Sorry can't print it here, our dashboard is under attack by WordPress Malware Bots (!). Please head over to NuttX Repo and seek NuttX-Dashboard. (Dog Tea? Organic!)

![Build History Dashboard](https://lupyuen.github.io/images/ci4-history.png)

# Build Score

_What's this Build Score?_

Our NuttX Dashboard needs to know the __"Goodiness"__ of Every NuttX Build (pic above). Whether it's a...

- __Total Fail__: _"undefined reference to atomic\_fetch\_add\_2"_

- __Warning__: _"nuttx has a LOAD segment with RWX permission"_

- __Success__: NuttX compiles and links OK

That's why we assign a __Build Score__ for every build...

| Score | Status | Example |
|:-----:|:-------|:--------|
| 0.0 | Error | _undefined reference to atomic\_fetch\_add\_2_
| 0.5 | Warning | _nuttx has a LOAD segment with RWX permission_
| 0.8 | Unknown | _STM32_USE_LEGACY_PINMAP will be deprecated_
| 1.0 | Success | _(No Errors and Warnings)_

Which makes it simpler to __Colour-Code__ our Dashboard: Green _(Success)_ / Yellow _(Warning)_ / Red _(Error)_.

TODO: Pic of build score

Sounds easy? But we'll catch __Multiple Kinds of Errors__...

- __Compile Errors:__ TODO

- __Linker Errors:__ _"undefined reference to atomic\_fetch\_add\_2"_

- __CI Test Failures:__ _"test\_pipe FAILED"_

_Doesn't the Build Score vary over time?_

Yep the Build Score is actually a [__Time Series Metric__](https://prometheus.io/docs/concepts/data_model/)! It will have the following dimensions...

- __Timestamp:__ When the NuttX Build was executed _(2024-11-24T00:00:00)_

- __User:__ Whose PC executed the NuttX Build _(nuttxpr)_

- __Target:__ NuttX Target that we're building _(milkv\_duos:nsh)_

Which folds neatly into this URL, as we'll soon see...

```text
localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
```

_Where do we store the Build Scores?_

Inside a special __Time Series Database__ called [__Prometheus__](TODO).

We'll come back to Prometheus, first we study the Dashboard...

TODO: Pic of Grafana

# Grafana Dashboard

TODO

Create a simple dashboard

Assume Build Score already set up

```bash
brew install grafana
brew services start grafana
http://localhost:3000
admin for username and password
```

TODO: ci4-grafana1.png

![TODO](https://lupyuen.github.io/images/ci4-grafana1.png)

TODO: ci4-grafana2.png

![TODO](https://lupyuen.github.io/images/ci4-grafana2.png)

TODO: ci4-grafana3.png

![TODO](https://lupyuen.github.io/images/ci4-grafana3.png)

TODO: ci4-grafana4.png

![TODO](https://lupyuen.github.io/images/ci4-grafana4.png)

TODO: ci4-grafana5.png

![TODO](https://lupyuen.github.io/images/ci4-grafana5.png)

TODO: ci4-grafana6.png

![TODO](https://lupyuen.github.io/images/ci4-grafana6.png)

TODO: ci4-grafana7.png

![TODO](https://lupyuen.github.io/images/ci4-grafana7.png)

TODO: ci4-grafana8.png

![TODO](https://lupyuen.github.io/images/ci4-grafana8.png)

TODO: ci4-grafana9.png

![TODO](https://lupyuen.github.io/images/ci4-grafana9.png)

TODO: ci4-grafana10.png

![TODO](https://lupyuen.github.io/images/ci4-grafana10.png)

TODO: View JSON

TODO: Grafana Config

TODO: Watch for usage

Update the Grafana and Prometheus Configuration...

- [/opt/homebrew/etc/grafana/grafana.ini](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/grafana.ini)

- [/opt/homebrew/etc/prometheus.yml](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml)

Add the Grafana Dashboard and Panels...

[dashboard.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard.json)
- [links.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/links.json)
- [highlights.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/highlights.json)
- [error-builds.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/error-builds.json)
- [success-builds.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/success-builds.json)

[dashboard-history.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard-history.json)
- [history.json](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/history.json)

TODO: Pic of Prometheus and Pushgateway

# Prometheus Metrics

_We've seen the Grafana Dashboard Setup. What about the Prometheus Metrics?_

Remember that our Build Scores are stored inside a special (open-source) __Time Series Database__ called [__Prometheus__](TODO).

This is how we install Prometheus...

```bash
## For macOS:
brew install prometheus
brew services start prometheus

## For Ubuntu:
TODO

## TODO: Check that Prometheus is up
## http://localhost:9090

## TODO: Update the Prometheus Config
## Edit /opt/homebrew/etc/prometheus.yml (macOS)
## Or TODO (Ubuntu)
## Replace by contents of:
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml

## Restart Prometheus
brew services restart prometheus ## macOS
TODO ## Ubuntu
```

Prometheus looks like this...

![TODO](https://lupyuen.github.io/images/ci4-prometheus.png)

Recall that we assign a __Build Score__ for every build...

| Score | Status | Example |
|:-----:|:-------|:--------|
| 0.0 | Error | _undefined reference to atomic\_fetch\_add\_2_
| 0.5 | Warning | _nuttx has a LOAD segment with RWX permission_
| 0.8 | Unknown | _STM32_USE_LEGACY_PINMAP will be deprecated_
| 1.0 | Success | _(No Errors and Warnings)_

This is how we __Load a Build Score__ into Prometheus...

```bash
## For macOS:
brew install go

## For Ubuntu:
TODO

## Install and start Pushgateway
git clone https://github.com/prometheus/pushgateway
cd pushgateway
go run main.go

## TODO: Check that Pushgateway is up
## http://localhost:9091

## Load a Build Score into Pushgateway
## Build Score is 0 for User nuttxpr, Target milkv_duos:nsh
cat <<EOF | curl --data-binary @- http://localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{ timestamp="2024-11-24T00:00:00", url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
EOF
```

Pushgateway looks like this...

![TODO](https://lupyuen.github.io/images/ci4-pushgateway.png)

_What's this Pushgateway?_

Prometheus works by [__Scraping Metrics__](https://prometheus.io/docs/prometheus/latest/getting_started/) over HTTP.

That's why we install [__Pushgateway__](TODO) as a HTTP Endpoint that will serve the Metrics (Build Score) to Prometheus.

(Which means that we load the Build Scores into Pushgateway, like above)

_How does it work?_

We post the Build Score over HTTP to Pushgateway at...

```text
localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
```

- _nuttxpr_ is the name of our Ubuntu Build PC

- _milkv\_duos:nsh_ is the NuttX Target that we're building

The body of the HTTP POST says...

```text
build_score{ timestamp="2024-11-24T00:00:00", url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
```

- _gist.github.com_ points to the Build Log for the NuttX Target (GitHub Gist)

- _"test\_pipe FAILED"_ says why the NuttX Build failed (due to CI Test)

- _0.0_ is the Build Score (0 means Error)

Remember that this __Build Score__ _(0.0)_ is specific to our __Build PC__ _(nuttxpr)_ and __NuttX Target__ _(milkv\_duos:nsh)_.

(It will vary over time, hence it's a Time Series)

_What about the other fields?_

Oh yes we have a long list of fields describing every Build Score...

- __version__: TODO
- __user__:  TODO
- __arch__:  TODO
- __subarch__:  TODO
- __group__:  TODO
- __board__:  TODO
- __config__:  TODO
- __target__:  TODO
- __url_display__:  TODO
- __nuttx_hash__: TODO
- __apps_hash__: TODO
- Plus timestamp, url, msg (from above)

[(See the __Complete Fields__)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L466-L490)

TODO: [prometheus.yml](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml)

Multple Values

Remove Duplicates

HTTP Request

OK to push latest data twice

OK to push from multiple PCs, they are distinct

TODO: Pic of ingesting

# Ingest the Build Logs

Now we be like an Amoeba and ingest all kinds of Build Logs!

- Build Logs from [__NuttX Build Farm__](TODO)

- Build Logs from [__GitHub Actions__](TODO)

We ingest the [__GitHub Gists__](TODO) from our Build Farm: [run.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/run.sh#L34-L41)

```bash
## Find all defconfig pathnames in NuttX Repo
git clone https://github.com/apache/nuttx
find nuttx \
  -name defconfig \
  >/tmp/defconfig.txt

## Ingest logs from nuttxpr GitHub Gist.
## Remove special characters so they don't mess up the terminal.
git clone https://github.com/lupyuen/ingest-nuttx-builds
cd ingest-nuttx-builds
cargo run -- \
  --user nuttxpr \
  --defconfig /tmp/defconfig.txt \
  | tr -d '\033\007'
```

Which will __Identify Errors and Warnings__ in the logs: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L311-L353)

<span style="font-size:90%">

```rust
// To Identify Errors and Warnings:
// We skip the known lines
if
  line.starts_with("----------") ||
  line.starts_with("-- ") ||  // "-- Build type:"
  line.starts_with("Cleaning") ||
  line.starts_with("Configuring") ||
  line.starts_with("Select") ||
  line.starts_with("Disabling") ||
  line.starts_with("Enabling") ||
  line.starts_with("Building") ||
  line.starts_with("Normalize") ||
  line.starts_with("% Total") ||
  line.starts_with("Dload") ||
  line.starts_with("~/apps") ||
  line.starts_with("~/nuttx") ||
  line.starts_with("find: 'boards/") ||  // "find: 'boards/risc-v/q[0-d]*': No such file or directory"
  line.starts_with("|        ^~~~~~~") ||  // `warning "FPU test not built; Only available in the flat build (CONFIG_BUILD_FLAT)"`
  line.contains("FPU test not built") ||
  line.starts_with("a nuttx-export-") ||  // "a nuttx-export-12.7.0/tools/incdir.c"
  line.contains(" PASSED") ||  // CI Test: "test_hello PASSED"
  line.contains(" SKIPPED") ||  // CI Test: "test_mm SKIPPED"
  line.contains("On branch master") ||  // "On branch master"
  line.contains("Your branch is up to date") ||  // "Your branch is up to date with 'origin/master'"
  line.contains("Changes not staged for commit") ||  // "Changes not staged for commit:"
  line.contains("git add <file>") ||  // "(use "git add <file>..." to update what will be committed)"
  line.contains("git restore <file>")  // "(use "git restore <file>..." to discard changes in working directory)"
{ continue; }

// Skip Downloads: "100  533k    0  533k    0     0   541k      0 --:--:-- --:--:-- --:--:--  541k100 1646k    0 1646k    0     0  1573k      0 --:--:--  0:00:01 --:--:-- 17.8M"
let re = Regex::new(r#"^[0-9]+\s+[0-9]+"#).unwrap();
let caps = re.captures(line);
if caps.is_some() { continue; }
```

</span>

Then we compute the __Build Score__: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L353-L395)

<span style="font-size:90%">

```rust
// Not an error:
// "test_ltp_interfaces_aio_error_1_1 PASSED"
// "lua-5.4.0/testes/errors.lua"
// "nuttx-export-12.7.0/include/libcxx/__system_error"
let msg_join = msg.join(" ");
let contains_error = msg_join
  .replace("aio_error", "aio_e_r_r_o_r")
  .replace("errors.lua", "e_r_r_o_r_s.lua")
  .replace("_error", "_e_r_r_o_r")
  .replace("error_", "e_r_r_o_r_")
  .to_lowercase()
  .contains("error");

// Identify CI Test as Error: "test_helloxx FAILED"
let contains_error = contains_error ||
  msg_join.contains(" FAILED");

// Given Board=sim, Config=rtptools
// Identify defconfig as Error: "modified:...boards/sim/sim/sim/configs/rtptools/defconfig"
let target_split = target.split(":").collect::<Vec<_>>();
let board = target_split[0];
let config = target_split[1];
let board_config = format!("/{board}/configs/{config}/defconfig");
let contains_error = contains_error ||
(
  msg_join.contains(&"modified:") &&
  msg_join.contains(&"boards/") &&
  msg_join.contains(&board_config.as_str())
);

// Search for Warnings
let contains_warning = msg_join
  .to_lowercase()
  .contains("warning");

// Compute the Build Score based on Error vs Warning
let build_score =
  if msg.is_empty() { 1.0 }
  else if contains_error { 0.0 }
  else if contains_warning { 0.5 }
  else { 0.8 };
```

</span>

And we post the __Build Scores to Pushgateway__: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L466-L490)

<span style="font-size:90%">

```rust
// Compose the Pushgateway Metric
let body = format!(
r##"
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score ... version= ...
"##);

// Post to Pushgateway over HTTP
let client = reqwest::Client::new();
let pushgateway = format!("http://localhost:9091/metrics/job/{user}/instance/{target}");
let res = client
  .post(pushgateway)
  .body(body)
  .send()
  .await?;
```

</span>

_Why do we need the defconfigs?_

```bash
## Find all defconfig pathnames in NuttX Repo
git clone https://github.com/apache/nuttx
find nuttx \
  -name defconfig \
  >/tmp/defconfig.txt

## defconfig.txt contains:
## boards/xtensa/esp32/esp32-devkitc/configs/knsh/defconfig
## boards/z80/ez80/ez80f910200kitg/configs/ostest/defconfig
## boards/risc-v/sg2000/milkv_duos/configs/nsh/defconfig
## boards/arm/rp2040/seeed-xiao-rp2040/configs/ws2812/defconfig
```

Suppose we're ingesting a NuttX Target _milkv_duos:nsh_. To identify the Target's __Sub-Architecture__ _(sg2000)_, we search the _defconfig_ pathnames: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L490-L513)

<span style="font-size:90%">

```rust
// Given a list of all defconfig pathnames:
// Search for a Target ("milkv_duos:nsh")
// Return the Sub-Architecture ("sg2000")
async fn get_sub_arch(defconfig: &str, target: &str) -> Result<String, Box<dyn std::error::Error>> {
  let target_split = target.split(":").collect::<Vec<_>>();
  let board = target_split[0];
  let config = target_split[1];

  // defconfig contains ".../boards/risc-v/sg2000/milkv_duos/configs/nsh/defconfig"
  // Search for "/{board}/configs/{config}/defconfig"
  let search = format!("/{board}/configs/{config}/defconfig");
  let input = File::open(defconfig).unwrap();
  let buffered = BufReader::new(input);
  for line in buffered.lines() {
    let line = line.unwrap();
    if let Some(pos) = line.find(&search) {
      let s = &line[0..pos];
      let slash = s.rfind("/").unwrap();
      let subarch = s[slash + 1..].to_string();
      return Ok(subarch);
    }
  }
  Ok("unknown".into())
}
```

</span>

_Phew the Errors and Warnings look so complicated!_

Yeah our Build Logs appear in all shapes and sizes. We might need to standardise the way we present the logs.

![Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!](https://lupyuen.github.io/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!_](https://qoto.org/@lupyuen/113517788288458811)

</span>

# Ingest from GitHub Actions

_What about the Build Logs from GitHub Actions?_

It gets a little more complicated, we need to download the __Build Logs from GitHub Actions__.

But before that, we need the __GitHub Run ID__: [github.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L17-L39)

```bash
## Fetch the Jobs for the Run ID. Get the Job ID for the Job Name.
local os=$1    ## "Linux" or "msys2"
local step=$2  ## "7" or "9"
local group=$3 ## "arm-01"
local job_name="$os ($group)"
local job_id=$(
  curl -L \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/$user/$repo/actions/runs/$run_id/jobs?per_page=100 \
    | jq ".jobs | map(select(.name == \"$job_name\")) | .[].id"
)
```

Now we can __Download the Run Logs__: [github.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L144-L153)

```bash
## Download the Run Logs from GitHub
## https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28#download-workflow-run-logs
curl -L \
  --output /tmp/run-log.zip \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/$user/$repo/actions/runs/$run_id/logs
```

__For Each Target Group:__ We ingest the Log File: [github.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L161-L185)

```bash
## For All Target Groups
## TODO: Handle macOS when the warnings have been cleaned up
for group in \
  arm-01 arm-02 arm-03 arm-04 \
  arm-05 arm-06 arm-07 arm-08 \
  arm-09 arm-10 arm-11 arm-12 \
  arm-13 arm-14 \
  risc-v-01 risc-v-02 risc-v-03 risc-v-04 \
  risc-v-05 risc-v-06 \
  sim-01 sim-02 sim-03 \
  xtensa-01 xtensa-02 \
  arm64-01 x86_64-01 other msys2
do
  ## Ingest the Log File
  if [[ "$group" == "msys2" ]]; then
    ingest_log "msys2" $msys2_step $group
  else
    ingest_log "Linux" $linux_step $group
  fi
done
```

[(__ingest_log__ is here)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L15-L73)

Which will be ingested like this: [github.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L59-L73)

```bash
## Ingest the Log File
cargo run -- \
  --user $user \
  --repo $repo \
  --defconfig $defconfig \
  --file $pathname \
  --nuttx-hash $nuttx_hash \
  --apps-hash $apps_hash \
  --group $group \
  --run-id $run_id \
  --job-id $job_id \
  --step $step

## TODO: Example
```

_How do we run all this?_

We ingest the GitHub Logs right after the [__Twice-Daily Build__](TODO) of NuttX. (00:00 UTC and 12:00 UTC)

Thus it makes sense to bundle the Build and Ingest into one single script: [build-github-and-ingest.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/build-github-and-ingest.sh)

```bash
## Build NuttX Mirror Repo and Ingest NuttX Build Logs
## from GitHub Actions into Prometheus Pushgateway

## TODO: Twice Daily at 00:00 UTC and 12:00 UTC
## Go to NuttX Mirror Repo: github.com/NuttX/nuttx
## Click Sync Fork > Discard Commits

## Start the Linux, macOS and Windows Builds for NuttX
## https://github.com/lupyuen/nuttx-release/blob/main/enable-macos-windows.sh
~/nuttx-release/enable-macos-windows.sh

## Wait for the NuttX Build to start
sleep 300

## Wait for the NuttX Build to complete
## Then ingest the GitHub Logs
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh
./github.sh
```

![TODO](https://lupyuen.github.io/images/ci4-flow.jpg)

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci4.md)

![Continuous Integration Dashboard for Apache NuttX RTOS](https://lupyuen.github.io/images/ci4-dashboard.png)

# Appendix: All Builds Dashboard

TODO: error1

![TODO](https://lupyuen.github.io/images/ci4-error1.png)

TODO: error2

![TODO](https://lupyuen.github.io/images/ci4-error2.png)

TODO: error3

![TODO](https://lupyuen.github.io/images/ci4-error3.png)

TODO: error4

![TODO](https://lupyuen.github.io/images/ci4-error4.png)

TODO: error5

![TODO](https://lupyuen.github.io/images/ci4-error5.png)

TODO: error6

![TODO](https://lupyuen.github.io/images/ci4-error6.png)

TODO: highlight1

![TODO](https://lupyuen.github.io/images/ci4-highlight1.png)

TODO: highlight2

![TODO](https://lupyuen.github.io/images/ci4-highlight2.png)

TODO

![Build History Dashboard](https://lupyuen.github.io/images/ci4-history.png)

# Appendix: Build History Dashboard

TODO: history1

![TODO](https://lupyuen.github.io/images/ci4-history1.png)

TODO: history2

![TODO](https://lupyuen.github.io/images/ci4-history2.png)

TODO: history3

![TODO](https://lupyuen.github.io/images/ci4-history3.png)
