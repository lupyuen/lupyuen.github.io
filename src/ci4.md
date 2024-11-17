# Continuous Integration Dashboard for Apache NuttX RTOS

📝 _30 Nov 2024_

![Continuous Integration Dashboard for Apache NuttX RTOS](https://lupyuen.github.io/images/ci4-title.jpg)

TODO: dashboard

![TODO](https://lupyuen.github.io/images/ci4-dashboard.png)

TODO: history

![TODO](https://lupyuen.github.io/images/ci4-history.png)

# Build Score

TODO

| Score | Status | Example |
|:-----:|:-------|:--------|
| 0.0 | Error | TODO
| 0.5 | Warning | TODO
| 0.8 | Unknown | TODO
| 1.0 | Success | TODO

Examples

Metric per Target and Source

Why Pull not Push?

Multple Values

Remove Duplicates

# Grafana Dashboard

TODO

Create a simple dashboard

Assume Build Score already set up

```bash
brew install grafana
brew services start grafana
http://localhost:3000
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

# Prometheus Setup

_We've seen the Grafana Dashboard Setup. What about the Prometheus Metrics?_

TODO

HTTP Request

Nowhere to pull

So pull from Pushgateway

We push to Pushgateway

OK to push latest data twice

OK to push from multiple PCs, they are distinct

TODO: prometheus

![TODO](https://lupyuen.github.io/images/ci4-prometheus.png)

TODO: pushgateway

![TODO](https://lupyuen.github.io/images/ci4-pushgateway.png)

```bash
## For macOS:
brew install prometheus
brew services start prometheus

## For Ubuntu:
TODO

http://localhost:9090
admin for username and password

## For macOS:
brew install go

## For Ubuntu:
TODO

git clone https://github.com/prometheus/pushgateway
cd pushgateway
go run main.go
http://localhost:9091

cat <<EOF | curl --data-binary @- http://localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{ url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
EOF
```

Note the URL...

```text
localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
```

- _nuttxpr_ is the name of our Ubuntu Build PC

- _milkv\_duos:nsh_ is the NuttX Target that we're building

The body of the HTTP POST says...

```text
build_score{ url="http://gist.github.com/...", msg="test_pipe FAILED" } 0.0
```

- _gist.github.com_ points to the Build Log for the NuttX Target (GitHub Gist)

- _"test\_pipe FAILED"_ says why the NuttX Build failed (due to CI Test)

- _0.0_ is the Build Score (0 means Error)

Remember that this __Build Score__ _(0.0)_ is specific to our __Build PC__ _(nuttxpr)_ and __NuttX Target__ _(milkv\_duos:nsh)_.

TODO: Will change

_What about the other fields?_

Oh yes we have a long list of fields detailing every Build Score (beyond the above)...

- __version__: TODO
- __timestamp__:  TODO
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

[(See the __Complete Fields__)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L466-L490)

TODO: Incomplete Fields

# Ingest the Build Logs

TODO: Ingest logs from nuttxpr GitHub Gist

[run.sh](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/run.sh#L34-L41)

```bash
## Ingest logs from nuttxpr GitHub Gist. Remove special characters.
cargo run -- \
  --user nuttxpr \
  --defconfig /tmp/defconfig.txt \
  | tr -d '\033\007'
```

TODO: Skip the known lines

[main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L311-L342)

```rust

    // To Identify Errors / Warnings: Skip the known lines
    let mut msg: Vec<&str> = vec![];
    let lines = &lines[l..];
    for line in lines {
        let line = line.trim();
        if line.starts_with("----------") ||
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
            line.contains(" SKIPPED")  // CI Test: "test_mm SKIPPED"
        { continue; }

        // Skip Downloads: "100  533k    0  533k    0     0   541k      0 --:--:-- --:--:-- --:--:--  541k100 1646k    0 1646k    0     0  1573k      0 --:--:--  0:00:01 --:--:-- 17.8M"
        let re = Regex::new(r#"^[0-9]+\s+[0-9]+"#).unwrap();
        let caps = re.captures(line);
        if caps.is_some() { continue; }
```

TODO: Compute the Build Score

[main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L347-L370)

```rust
    // Compute the Build Score based on Error vs Warning. Not an error:
    // "test_ltp_interfaces_aio_error_1_1 PASSED"
    // "lua-5.4.0/testes/errors.lua"
    // "nuttx-export-12.7.0/include/libcxx/__system_error"
    let contains_error = msg.join(" ")
        .replace("aio_error", "aio_e_r_r_o_r")
        .replace("errors.lua", "e_r_r_o_r_s.lua")
        .replace("_error", "_e_r_r_o_r")
        .replace("error_", "e_r_r_o_r_")
        .to_lowercase()
        .contains("error");
    let contains_error = contains_error ||
        msg.join(" ")
        .contains(" FAILED");  // CI Test: "test_helloxx FAILED"
    let contains_warning = msg.join(" ")
        .to_lowercase()
        .contains("warning");
    let build_score =
        if msg.is_empty() { 1.0 }
        else if contains_error { 0.0 }
        else if contains_warning { 0.5 }
        else { 0.8 };
```

TODO: Post to Pushgateway

[main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L466-L490)

```rust
    // Compose the Pushgateway Metric
    let body = format!(
r##"
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score ... version= ...
"##);
    println!("body={body}");
    let client = reqwest::Client::new();
    let pushgateway = format!("http://localhost:9091/metrics/job/{user}/instance/{target}");
    let res = client
        .post(pushgateway)
        .body(body)
        .send()
        .await?;
    println!("res={res:?}");
    if !res.status().is_success() {
        println!("*** Pushgateway Failed");
        sleep(Duration::from_secs(1));
    }
```

TODO: Given a list of all defconfig pathnames, search for a target (like "ox64:nsh") and return the Sub-Architecture (like "bl808")

[main.rs](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/src/main.rs#L490-L513)

```rust
// Given a list of all defconfig pathnames, search for a target (like "ox64:nsh")
// and return the Sub-Architecture (like "bl808")
async fn get_sub_arch(defconfig: &str, target: &str) -> Result<String, Box<dyn std::error::Error>> {
    let target_split = target.split(":").collect::<Vec<_>>();
    let board = target_split[0];
    let config = target_split[1];

    // defconfig contains "/.../nuttx/boards/risc-v/bl808/ox64/configs/nsh/defconfig"
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

# Ingest the Logs from GitHub Actions

TODO

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
