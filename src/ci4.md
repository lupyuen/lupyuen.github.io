# Continuous Integration Dashboard for Apache NuttX RTOS  (Prometheus and Grafana)

📝 _24 Nov 2024_

![Continuous Integration Dashboard for Apache NuttX RTOS  (Prometheus and Grafana)](https://lupyuen.github.io/images/ci4-dashboard.png)

Last article we spoke about the __(Twice) Daily Builds__ for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)...

- [__"Optimising the Continuous Integration for Apache NuttX RTOS (GitHub Actions)"__](https://lupyuen.github.io/articles/ci3)

Today we talk about __Monitoring the Daily Builds__ (also the [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci2)) with our new __NuttX Dashboard__...

- We created our Dashboard with __Grafana__ (open-source)

- Pulling the Build Data from __Prometheus__ (also open-source)

- Which is populated by __Pushgateway__ (staging database)

- Integrated with our __Build Farm__ and __GitHub Actions__

- Why do all this? Because [__we can't afford__](https://lupyuen.github.io/articles/ci3#disable-macos-and-windows-builds) to run Complete CI Checks on Every Pull Request!

- We expect __some breakage__, and NuttX Dashboard will help with the fixing

_What will NuttX Dashboard tell us?_

NuttX Dashboard shows a __Snapshot of Failed Builds__ for the present moment. (Pic above)

We may __Filter the Builds__ by Architecture, Board and Config...

![Filter the Builds by Architecture, Board and Config](https://lupyuen.github.io/images/ci4-filter.png)

The snapshot includes builds from the (community-hosted) [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci2) as well as [__GitHub Actions__](https://lupyuen.github.io/articles/ci3#move-the-merge-jobs) (twice-daily builds).

To see __GitHub Actions Only__: Click __`[+]`__ and set __`User`__ to __`NuttX`__...

![Show GitHub Actions Only](https://lupyuen.github.io/images/ci4-user.png)

To see the __History of Builds__: Click the link for _"NuttX Build History"_. Remember to select the Board and Config. (Pic below)

_Sounds Great! What's the URL?_

Sorry can't print it here, our dashboard is under attack by WordPress Malware Bots (!). Please head over to NuttX Repo and seek __NuttX-Dashboard__. (Dog Tea? Organic!)

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
| __`0.0`__ | Error | _undefined reference to atomic\_fetch\_add\_2_
| __`0.5`__ | Warning | _nuttx has a LOAD segment with RWX permission_
| __`0.8`__ | Unknown | _STM32_USE_LEGACY_PINMAP will be deprecated_
| __`1.0`__ | Success | _(No Errors and Warnings)_

Which makes it simpler to __Colour-Code__ our Dashboard: Green _(Success)_ / Yellow _(Warning)_ / Red _(Error)_.

![Build Scores for NuttX Dashboard](https://lupyuen.github.io/images/ci4-flow2.jpg)

Sounds easy? But we'll catch __Multiple Kinds of Errors__ (in various formats)

- __Compile Errors:__ _"return with no value"_

- __Linker Errors:__ _"undefined reference to atomic\_fetch\_add\_2"_

- __Config Errors:__ _"modified: sim/configs/rtptools/defconfig"_

- __Network Errors:__ _"curl 92 HTTP/2 stream 0 was not closed cleanly"_

- __CI Test Failures:__ _"test\_pipe FAILED"_

_Doesn't the Build Score vary over time?_

Yep the Build Score is actually a [__Time Series Metric__](https://prometheus.io/docs/concepts/data_model/)! It will have the following dimensions...

- __Timestamp:__ When the NuttX Build was executed _(2024-11-24T00:00:00)_

- __User:__ Whose PC executed the NuttX Build _(nuttxpr)_

- __Target:__ NuttX Target that we're building _(milkv\_duos:nsh)_

Which will fold neatly into this URL, as we'll soon see...

```text
localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
```

_Where do we store the Build Scores?_

Inside a special open-source __Time Series Database__ called [__Prometheus__](https://prometheus.io/).

We'll come back to Prometheus, first we study the Dashboard...

![Grafana Dashboard](https://lupyuen.github.io/images/ci4-flow3.jpg)

# Grafana Dashboard

_What's this Grafana?_

[__Grafana__](https://grafana.com/oss/grafana/) is an open-source toolkit for creating __Monitoring Dashboards__.

Sadly there isn't a "programming language" for coding Grafana. Thus we walk through the steps to create our __NuttX Dashboard with Grafana__...

```bash
## Install Grafana on Ubuntu
## See https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/
sudo apt install grafana
sudo systemctl start grafana-server

## Or macOS
brew install grafana
brew services start grafana

## Browse to http://localhost:3000
## Login as `admin` for username and password
```

1.  Inside Grafana: We create a __New Dashboard__...

    ![Create a New Dashboard](https://lupyuen.github.io/images/ci4-grafana3.png)

1.  Add a __Visualisation__...

    ![Add a Visualisation](https://lupyuen.github.io/images/ci4-grafana4.png)

1.  Select the __Prometheus Data Source__ (we'll explain why)

    ![Select the Prometheus Data Source](https://lupyuen.github.io/images/ci4-grafana5.png)

1.  Change the Visualisation to __"Table"__ (top right)

    Choose __Build Score__ as the Metric. Click __"Run Queries"__...

    ![Change to Table Visualisation](https://lupyuen.github.io/images/ci4-grafana1.png)

1.  We see a list of Build Scores in the Data Table above.

    But where's the Timestamp, Board and Config?

    That's why we do __Transformations__ > __Add Transformation__ > __Labels To Fields__

    ![Transform Label To Fields](https://lupyuen.github.io/images/ci4-grafana2.png)

1.  And the data appears! Timestamp, Board, Config, ...

    ![Build Scores with Timestamp, Board, Config](https://lupyuen.github.io/images/ci4-grafana6.png)

1.  Hmmm it's the same Board and Config... Just different Timestamps.

    We click __Queries__ > __Format: Table__ > __Type: Instant__ > __Refresh__

    ![Change to Instant Query](https://lupyuen.github.io/images/ci4-grafana7.png)

1.  Much better! We see the __Build Score__ at the End of Each Row (to be colourised)

    ![Build Scores](https://lupyuen.github.io/images/ci4-grafana8.png)

1.  Our NuttX Deashboard is nearly ready. To check our progress: Click __Inspect__ > __Panel JSON__

    ![Inspect Panel JSON](https://lupyuen.github.io/images/ci4-grafana9.png)

1.  And compare with our __Completed Panel JSON__...

    [__Panel: Builds with Errors and Warnings__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/error-builds.json)

    [__Panel: Successful Builds__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/success-builds.json)

1.  How to get there? Watch the steps...

    [__"All Builds Dashboard"__](https://lupyuen.github.io/articles/ci4#appendix-all-builds-dashboard)

    [__"Build History Dashboard"__](https://lupyuen.github.io/articles/ci4#appendix-build-history-dashboard)

![Prometheus Metrics](https://lupyuen.github.io/images/ci4-flow4.jpg)

# Prometheus Metrics

_We saw the setup for Grafana Dashboard. What about the Prometheus Metrics?_

Remember that our Build Scores are stored inside a special (open-source) __Time Series Database__ called [__Prometheus__](https://prometheus.io/).

This is how we install Prometheus...

```bash
## Install Prometheus on Ubuntu
sudp apt install prometheus
sudo systemctl start prometheus

## Or macOS
brew install prometheus
brew services start prometheus

## TODO: Update the Prometheus Config
## Edit /etc/prometheus/prometheus.yml (Ubuntu)
## Or /opt/homebrew/etc/prometheus.yml (macOS)

## Replace by contents of
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml

## Restart Prometheus
sudo systemctl restart prometheus ## Ubuntu
brew services restart prometheus  ## macOS

## Check that Prometheus is up
## http://localhost:9090
```

__Prometheus__ looks like this...

![Prometheus User Interface](https://lupyuen.github.io/images/ci4-prometheus.png)

Recall that we assign a __Build Score__ for every build...

| Score | Status | Example |
|:-----:|:-------|:--------|
| __`0.0`__ | Error | _undefined reference to atomic\_fetch\_add\_2_
| __`0.5`__ | Warning | _nuttx has a LOAD segment with RWX permission_
| __`0.8`__ | Unknown | _STM32_USE_LEGACY_PINMAP will be deprecated_
| __`1.0`__ | Success | _(No Errors and Warnings)_

This is how we __Load a Build Score__ into Prometheus...

```bash
## Install GoLang
sudo apt install golang-go ## For Ubuntu
brew install go  ## For macOS

## Install Pushgateway
git clone https://github.com/prometheus/pushgateway
cd pushgateway
go run main.go

## Check that Pushgateway is up
## http://localhost:9091

## Load a Build Score into Pushgateway
## Build Score is 0 for User nuttxpr, Target milkv_duos:nsh
cat <<EOF | curl --data-binary @- http://localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{ timestamp="2024-11-24T00:00:00", url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
EOF
```

__Pushgateway__ looks like this...

![Pushgateway User Interface](https://lupyuen.github.io/images/ci4-pushgateway.png)

_What's this Pushgateway?_

Prometheus works by [__Scraping Metrics__](https://prometheus.io/docs/prometheus/latest/getting_started/) over HTTP.

That's why we install [__Pushgateway__](https://prometheus.io/docs/practices/pushing/) as a HTTP Endpoint (Staging Area) that will serve the Build Score (Metrics) to Prometheus.

(Which means that we load the Build Scores into Pushgateway, like above)

![Pushgateway and Prometheus for Build Scores](https://lupyuen.github.io/images/ci4-flow2.jpg)

_How does it work?_

We post the Build Score over __HTTP to Pushgateway__ at...

```text
localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
```

- _nuttxpr_ is the name of our Ubuntu Build PC

- _milkv\_duos:nsh_ is the NuttX Target that we're building

The Body of the __HTTP POST__ says...

```text
build_score{ timestamp="2024-11-24T00:00:00", url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
```

- _gist.github.com_ points to the Build Log for the NuttX Target (GitHub Gist)

- _"test\_pipe FAILED"_ says why the NuttX Build failed (due to CI Test)

- _0.0_ is the Build Score (0 means Error)

Remember that this __Build Score__ _(0.0)_ is specific to our __Build PC__ _(nuttxpr)_ and __NuttX Target__ _(milkv\_duos:nsh)_.

(It will vary over time, hence it's a Time Series)

_What about the other fields?_

Oh yes we have a long list of fields describing __Every Build Score__...

<span style="font-size:90%">

| Field | Value |
|:------|:------|
| __version__ | Always 3
| __user__ | Which Build PC _(nuttxmacos)_
| __arch__ | Architecture _(risc-v)_
| __group__ | Target Group _(risc-v-01)_
| __board__ | Board _(ox64)_
| __config__ | Config _(nsh)_
| __target__ | Board:Config _(ox64:nsh)_
| __subarch__ | Sub-Architecture _(bl808)_
| __url_display__ | Short URL of Build Log
| __nuttx_hash__ | Commit Hash of NuttX Repo _(7f84a64109f94787d92c2f44465e43fde6f3d28f)_
| __apps_hash__ | Commit Hash of NuttX Apps _(d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288)_

</span>

Plus the earlier fields: __timestamp, url, msg__. Commit Hash is super helpful for tracking a Breaking Commit!

[(See the __Complete Fields__)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L426-L515)

_Anything else we should know about Prometheus?_

We configured Prometheus to scrape the __Build Scores from Pushgateway__, every 15 seconds: [prometheus.yml](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml)

```yaml
## Prometheus Configuration
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
    - targets: ["localhost:9090"]

  ## Prometheus will scrape the Metrics
  ## from Pushgateway every 15 seconds
  - job_name: "pushgateway"
    static_configs:
    - targets: ["localhost:9091"]
```

And it's perfectly OK to post the __Same Build Log__ twice to Pushgateway. (Because the Timestamp will differentiate the logs)

[(Ask your Local Library for __"Mastering Prometheus"__)](https://share.libbyapp.com/title/10565151)

![Ingest the Build Logs](https://lupyuen.github.io/images/ci4-flow5.jpg)

# Ingest the Build Logs

Now we be like an Amoeba and ingest all kinds of Build Logs!

- Build Logs from [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci2)

- Build Logs from [__GitHub Actions__](https://lupyuen.github.io/articles/ci3)

For NuttX Build Farm, we ingest the [__GitHub Gists__](https://lupyuen.github.io/articles/ci2#build-nuttx-for-all-target-groups) that contain the Build Logs: [run.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/run.sh#L34-L41)

```bash
## Find all defconfig pathnames in NuttX Repo
git clone https://github.com/apache/nuttx
find nuttx \
  -name defconfig \
  >/tmp/defconfig.txt

## Ingest the Build Logs from GitHub Gists: `nuttxpr`
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
  line.starts_with("-- ") ||  // "-- Build type:"
  line.starts_with("----------")  ||
  line.starts_with("Cleaning")    ||
  line.starts_with("Configuring") ||
  line.starts_with("Select")      ||
  line.starts_with("Disabling")   ||
  line.starts_with("Enabling")    ||
  line.starts_with("Building")    ||
  line.starts_with("Normalize")   ||
  line.starts_with("% Total")     ||
  line.starts_with("Dload")       ||
  line.starts_with("~/apps")      ||
  line.starts_with("~/nuttx")     ||
  line.starts_with("find: 'boards/")   ||  // "find: 'boards/risc-v/q[0-d]*': No such file or directory"
  line.starts_with("|        ^~~~~~~") ||  // `warning "FPU test not built; Only available in the flat build (CONFIG_BUILD_FLAT)"`
  line.contains("FPU test not built")  ||
  line.starts_with("a nuttx-export-")  ||  // "a nuttx-export-12.7.0/tools/incdir.c"
  line.contains(" PASSED")  ||  // CI Test: "test_hello PASSED"
  line.contains(" SKIPPED") ||  // CI Test: "test_mm SKIPPED"
  line.contains("On branch master") ||  // "On branch master"
  line.contains("Your branch is up to date")     ||  // "Your branch is up to date with 'origin/master'"
  line.contains("Changes not staged for commit") ||  // "Changes not staged for commit:"
  line.contains("git add <file>")  ||  // "(use "git add <file>..." to update what will be committed)"
  line.contains("git restore <file>")  // "(use "git restore <file>..." to discard changes in working directory)"
{ continue; }

// Skip Downloads: "100  533k    0  533k    0     0   541k      0 --:--:-- --:--:-- --:--:--  541k100 1646k    0 1646k    0     0  1573k      0 --:--:--  0:00:01 --:--:-- 17.8M"
let re = Regex::new(r#"^[0-9]+\s+[0-9]+"#).unwrap();
let caps = re.captures(line);
if caps.is_some() { continue; }
```

</span>

Then compute the __Build Score__: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L353-L395)

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

And post the __Build Scores to Pushgateway__: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L474-L515)

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
## boards/risc-v/sg2000/milkv_duos/configs/nsh/defconfig
## boards/arm/rp2040/seeed-xiao-rp2040/configs/ws2812/defconfig
## boards/xtensa/esp32/esp32-devkitc/configs/knsh/defconfig
```

Suppose we're ingesting a NuttX Target _milkv\_duos:nsh_.

To identify the Target's __Sub-Architecture__ _(sg2000)_, we search for _milkv\_duos/.../nsh_ in the _defconfig_ pathnames: [main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L515-L538)

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

    // Sub-Architecture appears before "/{board}"
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

_Phew the Errors and Warnings are so complicated!_

Yeah our Build Logs appear in all shapes and sizes. We might need to standardise the way we present the logs.

![Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!](https://lupyuen.github.io/images/ci4-thinkstation.jpg)

<span style="font-size:80%">

[_Refurbished 12-Core Xeon ThinkStation ($400 / 24 kg!) becomes (hefty) Ubuntu Build Farm for Apache NuttX RTOS. 4 times the throughput of a PC!_](https://qoto.org/@lupyuen/113517788288458811)

</span>

# Ingest from GitHub Actions

_What about the Build Logs from GitHub Actions?_

It gets a little more complicated, we need to download the [__Build Logs from GitHub Actions__](https://lupyuen.github.io/articles/ci3#move-the-merge-jobs).

But before that, we need the __GitHub Run ID__ to identify the Build Job: [github.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh#L17-L39)

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
## Ingest the Log Files from GitHub Actions
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

## user=NuttX
## repo=nuttx
## defconfig=/tmp/defconfig.txt (from earlier)
## pathname=/tmp/ingest-nuttx-builds/ci-arm-01.log
## nuttx_hash=7f84a64109f94787d92c2f44465e43fde6f3d28f
## apps_hash=d6edbd0cec72cb44ceb9d0f5b932cbd7a2b96288
## group=arm-01
## run_id=11603561928
## job_id=32310817851
## step=7
```

_How to run all this?_

We ingest the GitHub Logs right after the [__Twice-Daily Build__](https://lupyuen.github.io/articles/ci3#move-the-merge-jobs) of NuttX. (00:00 UTC and 12:00 UTC)

Thus it makes sense to bundle the __Build and Ingest__ into One Single Script: [build-github-and-ingest.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/build-github-and-ingest.sh)

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

And that's how we created our Continuous Integration Dashboard for NuttX!

[(Please join our __Build Farm__ 🙏)](https://github.com/apache/nuttx/issues/14558)

![Continuous Integration Dashboard for Apache NuttX RTOS  (Prometheus and Grafana)](https://lupyuen.github.io/images/ci4-flow.jpg)

# What's Next

_Why are we doing all this?_

That's because [__we can't afford__](https://lupyuen.github.io/articles/ci3#disable-macos-and-windows-builds) to run Complete CI Checks on Every Pull Request!

We expect __some breakage__, and NuttX Dashboard will help with the fixing.

_What happens when NuttX Dashboard reports a Broken Build?_

Right now we scramble to identify the [__Breaking Commit__](https://github.com/apache/nuttx/issues/14808). And prevent more Broken Commits from piling on.

Yes NuttX Dashboard will tell us the [__Commit Hashes__](https://lupyuen.github.io/articles/ci4#build-score) for the [__Build History__](https://lupyuen.github.io/articles/ci4#appendix-build-history-dashboard). But the Batched Commits aren't __Temporally Precise__, and we race against time to inspect and recompile each Past Commit.

_Can we automate this?_

Yeah someday our NuttX Build Farm shall __"Rewind The Build"__ when something breaks...

Automatically __Backtrack the Commits__, Compile each Commit and discover the Breaking Commit. [(Like this)](https://github.com/lupyuen/nuttx-riscv64/blob/main/special-qemu-riscv-knsh64.sh#L42-L69)

_Any more stories of NuttX CI?_

Next Article: We chat about the updated __NuttX Build Farm__ that runs on __macOS for Apple Silicon__. (Great news for NuttX Devs on macOS)

Then we study the internals of a [__Mystifying Bug__](https://github.com/apache/nuttx/issues/14808) that concerns __PyTest, QEMU RISC-V and `expect`__. (So it will disappear sooner from NuttX Dashboard)

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=42224186)

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

Earlier we spoke about creating the __NuttX Dashboard__ (pic above). And we created a __Rudimentary Dashboard__ with Grafana...

- [__"Grafana Dashboard"__](https://lupyuen.github.io/articles/ci4#grafana-dashboard)

We nearly completed the __Panel JSON__...

- [__Panel: Builds with Errors and Warnings__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/error-builds.json)

- [__Panel: Successful Builds__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/success-builds.json)

Let's flesh out the remaining bits of our creation.

Before we begin: Check that our __Prometheus Data Source__ is configured to fetch the Build Scores from Prometheus and Pushgateway...

![Configure our Prometheus Data Source](https://lupyuen.github.io/images/ci4-datasource.png)

[(Remember to set __prometheus.yml__)](https://lupyuen.github.io/articles/ci4#prometheus-metrics)

Head back to our upcoming dashboard...

1.  This is how we __Filter by Arch, Sub-Arch, Board, Config__, which we defined as [__Dashboard Variables__](https://grafana.com/docs/grafana/latest/dashboards/variables/) (see below)

    ![Filter by Arch, Sub-Arch, Board, Config](https://lupyuen.github.io/images/ci4-error1.png)

1.  Why match the __Funny Timestamps__? Well mistakes were make. We exclude these Timestamps so they won't appear in the dashboard...

    ![We exclude these Timestamps](https://lupyuen.github.io/images/ci4-error2.png)

1.  For Builds with Errors and Warnings: We select __Values (Build Scores) <= 0.5__...

    ![select Values (Build Scores) <= 0.5](https://lupyuen.github.io/images/ci4-error3.png)

1.  We __Rename and Reorder the Fields__...

    ![Rename the Fields](https://lupyuen.github.io/images/ci4-error6.png)

1.  Set the __Timestamp__ to Lower Case, __Config__ to Upper Case...

    ![Set the Timestamp to Lower Case, Config to Upper Case](https://lupyuen.github.io/images/ci4-error4.png)

1.  Set the __Color Scheme__ to __From Thresholds By Value__

    Set the __Data Links__: Title becomes "`Show the Build Log`", URL becomes "`${__data.fields.url}`"

    Colour the Values (Build Scores) with the __Value Mappings__ below

    ![Set the Color Scheme and Data Links](https://lupyuen.github.io/images/ci4-error5.png)

1.  And we'll achieve this __Completed Panel JSON__...

    [__Panel: Builds with Errors and Warnings__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/error-builds.json)

_What about the Successful Builds?_

1.  Copy the Panel for __"Builds with Errors and Warnings"__

    Paste into a New Panel: __"Successful Builds"__

1.  Select __Values (Build Scores) > 0.5__

    ![Select Values (Build Scores) > 0.5](https://lupyuen.github.io/images/ci4-history1.png)

1.  And we'll accomplish this __Completed Panel JSON__

    [__Panel: Successful Builds__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/success-builds.json)

_And the Highlights Panel at the top?_

1.  Copy the Panel for __"Builds with Errors and Warnings"__

    Paste into a New Panel: __"Highlights of Errors / Warnings"__

1.  Change the Visualisation from __"Table" to "Stat"__  (top right)

    ![Change the Visualisation from "Table" to "Stat"](https://lupyuen.github.io/images/ci4-highlight1.png)

1.  Select __Sort by Value__ (Build Score) and __Limit to 8 Items__...

    ![Sort by Value and Limit to 8 Items](https://lupyuen.github.io/images/ci4-highlight2.png)

1.  And we'll get this __Completed Panel JSON__

    [__Panel: Highlights of Errors / Warnings__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/highlights.json)

1.  Also check out the __Dashboard JSON__ and __Links Panel__ _("See the NuttX Build History")_

    [__Links Panel__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/links.json)

    [__Dashboard JSON__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard.json)

    Which will define the __Dashboard Variables__...

    ![Dashboard Variables](https://lupyuen.github.io/images/ci4-variables.png)

Up Next: The NuttX Dashboard for Build History...

![Build History Dashboard](https://lupyuen.github.io/images/ci4-history.png)

# Appendix: Build History Dashboard

In the previous section: We created the NuttX Dashboard for Errors, Warnings and Successful Builds.

Now we do the same for __Build History Dashboard__ (pic above)...

1.  Copy the Dashboard from the previous section.

    Delete all Panels, except __"Builds with Errors and Warnings"__.

    Edit the Panel.

1.  Under Queries: Set __Options > Type__ to __Range__

    ![Set Type to Range](https://lupyuen.github.io/images/ci4-history2.png)

1.  Under Transformations: Set __Group By__ to First Severity, First Board, First Config, First Build Log, First Apps Hash, First NuttX Hash

    In __Organise Fields By Name__: Rename and Reorder the fields as shown below

    Set the __Value Mappings__ below

    ![Organise Fields By Name and Value Mappings](https://lupyuen.github.io/images/ci4-history3.png)

1.  Here are the __Panel and Dashboard JSON__...

    [__Panel: Build History__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/history.json)

    [__Dashboard: NuttX Build History__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard-history.json)

_Is Grafana really safe for web hosting?_

Use this (safer) __Grafana Configuration__: [grafana.ini](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/grafana.ini)

- Modified Entries are tagged by "__TODO__"

- __For Ubuntu:__ Copy to _/etc/grafana/grafana.ini_

- __For macOS:__ Copy to _/opt/homebrew/etc/grafana/grafana.ini_

Watch out for the pesky __WordPress Malware Bots__! This might help: [show-log.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/show-log.sh)

```bash
## Show Logs from Grafana
log_file=/var/log/grafana/grafana.log ## For Ubuntu
log_file=/opt/homebrew/var/log/grafana/grafana.log ## For macOS

## Watch for any suspicious activity
for (( ; ; )); do
  clear
  tail -f $log_file \
    | grep --line-buffered 'logger=context ' \
    | grep --line-buffered -v ' path=/api/frontend-metrics ' \
    | grep --line-buffered -v ' path=/api/live/ws ' \
    | grep --line-buffered -v ' path=/api/plugins/grafana-lokiexplore-app/settings ' \
    | grep --line-buffered -v ' path=/api/user/auth-tokens/rotate ' \
    | grep --line-buffered -v ' path=/favicon.ico ' \
    | grep --line-buffered -v ' remote_addr=\[::1\] ' \
    | cut -d ' ' -f 9-15 \
    &

  ## Restart the log display every 12 hours, due to Log Rotation
  sleep $(( 12 * 60 * 60 ))
  kill %1
done
```
