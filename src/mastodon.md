# (Experimental) Mastodon Server for Apache NuttX Continuous Integration (macOS Rancher Desktop)

📝 _30 Dec 2024_

![TODO](https://lupyuen.github.io/images/mastodon-title.jpg)

TODO

We're out for an [__overnight hike__](TODO), city to airport. Our [__Build Farm for Apache NuttX RTOS__](TODO) runs non-stop all day, all night. Continuously compiling over [__1,000 NuttX Targets__](TODO). 

Can we be 100% sure that __NuttX is OK?__ Without getting spammed by __alert emails__ all night? (Sorry we got zero budget for _"paging duty"_ services)

TODO: Pic of mobile 

TODO: mastodon-mobile3.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile3.png)

TODO: mastodon-mobile4.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile4.png)

in this article we talk about Mastodon 

# Mastodon for NuttX CI

TODO

TODO: mastodon-mobile1.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile1.png)

TODO: mastodon-mobile2.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile2.png)

TODO: mastodon-mobile3.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile3.png)

TODO: mastodon-mobile4.png

![TODO](https://lupyuen.github.io/images/mastodon-mobile4.png)

# Install our Mastodon Server

TODO: Straightforwrd, thanks to the excellent Mastodon Docs

TODO: SSL / Hosting Provider

We use port 3001 because 3000 is already used by Grafana

# Test our Mastodon Server

TODO: Working without email

Monitor the logs

```text
Public Timeline: https://docs.joinmastodon.org/client/public/#timelines
curl https://nuttx-feed.org/api/v1/timelines/public | jq
```

TODO: Federation

# Post NuttX Builds to Mastodon

TODO: Prometheus to Mastodon

TODO: [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)

TODO: Suppose I'm interested in only rv-virt:python. Can I subscribe to the alerts via Mastodon / Fediverse / ActivityPub?

# TODO

Need moderation?

discussion only

fediverse

Register on qoto home

NuttX Load: Running Jobs and Cost of GitHub Actions

Alert for long-running jobs

Monitor sync-build-ingest

Mastodon could link Failed Builds / Failed Tests to NuttX Issue?

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

[__lupyuen.github.io/src/mastodon.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mastodon.md)

# Appendix: Query Prometheus for Failed Builds

TODO

TODO: mastodon-grafana.png

![TODO](https://lupyuen.github.io/images/mastodon-grafana.png)

TODO: mastodon-prometheus.png

![TODO](https://lupyuen.github.io/images/mastodon-prometheus.png)

```text
Query Prometheus for Build Failures
http://localhost:9090
build_score{user!="rewind", user!="nuttxlinux", user!="nuttxmacos", user!="jerpelea"} < 0.5

curl -X POST \
        -F 'query=build_score{config!="leds64_zig", user!="rewind", user!="nuttxlinux", user!="nuttxmacos", user!="jerpelea"} < 0.5' \
        http://localhost:9090/api/v1/query

{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"build_score","apps_hash":"b08c29617bbf1f2c6227f74e23ffdd7706997e0c","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"nuttxpr","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"virtio/virtio-mmio.c: In function 'virtio_mmio_config_virtqueue': \n virtio/virtio-mmio.c:346:14: error: cast from pointer to integer of different size [-Werror=pointer-to-int-cast] \n 346 |       addr = (uint64_t)kasan_reset_tag((FAR void *)vq->vq_ring.desc); \n |              ^ \n virtio/virtio-mmio.c:350:14: error: cast from pointer to integer of different size [-Werror=pointer-to-int-cast] \n 350 |       addr = (uint64_t)kasan_reset_tag((FAR void *)vq->vq_ring.avail); \n |              ^ \n virtio/virti","nuttx_hash":"04815338334e63cd82c38ee12244e54829766e88","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-06T06:14:54","url":"https://gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L169","url_display":"gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L169","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"b08c29617bbf1f2c6227f74e23ffdd7706997e0c","arch":"risc-v","board":"rv-virt","config":"citest64","exported_instance":"rv-virt:citest64","exported_job":"nuttxpr","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_popen FAILED                                  [ 30%] \n test_example/test_example.py::test_usrsocktest FAILED                            [ 38%] \n test_os/test_os.py::test_ostest FAILED                                           [ 46%]","nuttx_hash":"04815338334e63cd82c38ee12244e54829766e88","subarch":"qemu-rv","target":"rv-virt:citest64","timestamp":"2024-12-06T06:19:39","url":"https://gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L236","url_display":"gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L236","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"37acd5e6712bc91e6c5fd3b9cdde06ff9a3cada3","arch":"xtensa","board":"esp32-devkitc","config":"nxdiag","exported_instance":"esp32-devkitc:nxdiag","exported_job":"nuttxmacos2","group":"xtensa-01","instance":"localhost:9091","job":"pushgateway","msg":"./nxdiag.c:34:10: fatal error: sysinfo.h: No such file or directory \n 34 | #include \"sysinfo.h\" \n |          ^~~~~~~~~~~ \n compilation terminated. \n ERROR: xtensa-esp32-elf-gcc failed: 1 \n command: xtensa-esp32-elf-gcc -MT ./nxdiag.c.private.tmp.run-job-macos.apps.system.nxdiag.o  -M '-fno-common' '-Wall' '-Wstrict-prototypes' '-Wshadow' '-Wundef' '-Wno-attributes' '-Wno-unknown-pragmas' '-Wno-psabi' '-Os' '-fno-strict-aliasing' '-fomit-frame-pointer' '-ffunction-sections' '-fdata-sections' '-mlongca","nuttx_hash":"fd20684a7b65b45a8e1e4e52ea8a4bd4b47cb11a","subarch":"esp32","target":"esp32-devkitc:nxdiag","timestamp":"2024-12-09T23:07:00","url":"https://gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4778616#L1075","url_display":"gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4778616#L1075","user":"nuttxmacos2","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"1f8b9aa74c38460fe8fe47646f70e85e79bcc21f","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"nuttxmacos2","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_helloxx FAILED                                            [  0%] \n test_example/test_example.py::test_pipe FAILED                                               [  0%] \n test_example/test_example.py::test_popen FAILED                                              [  0%] \n test_example/test_example.py::test_usrsocktest FAILED                                        [  0%] \n test_open_posix/test_openposix_.py::test_ltp_interfaces_mq_send_4_2 FAILED                   [  0%] ","nuttx_hash":"5607eece841346ae807f1474ea36e422d6dfc97d","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-10T19:48:36","url":"https://gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4779209#L824","url_display":"gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4779209#L824","user":"nuttxmacos2","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"1f8b9aa74c38460fe8fe47646f70e85e79bcc21f","arch":"xtensa","board":"esp32s3-devkit","config":"timer","exported_instance":"esp32s3-devkit:timer","exported_job":"nuttxpr","group":"xtensa-02","instance":"localhost:9091","job":"pushgateway","msg":"In file included from chip/esp32s3_libc_stubs.c:25: \n chip/esp32s3_libc_stubs.c: In function 'esp_setup_syscall_table': \n chip/esp32s3_libc_stubs.c:418:3: error: static assertion failed: \"Invalid size of struct __lock\" \n 418 |   static_assert(sizeof(struct __lock) >= sizeof(mutex_t), \n |   ^~~~~~~~~~~~~ \n make[1]: *** [Makefile:146: esp32s3_libc_stubs.o] Error 1 \n make[1]: Target 'libarch.a' not remade because of errors. \n make: *** [tools/LibTargets.mk:170: arch/xtensa/src/libarch.a] Error 2 \n ma","nuttx_hash":"5607eece841346ae807f1474ea36e422d6dfc97d","subarch":"esp32s3","target":"esp32s3-devkit:timer","timestamp":"2024-12-10T23:09:05","url":"https://gist.github.com/nuttxpr/108ce53648bac75a85e8be288351b939#file-ci-xtensa-02-log-L769","url_display":"gist.github.com/nuttxpr/108ce53648bac75a85e8be288351b939#file-ci-xtensa-02-log-L769","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"e861ea8b53e6c86b28274e3651036761d17d88ea","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"NuttX","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_hello FAILED                          [  0%] \n test_example/test_example.py::test_helloxx FAILED                        [  0%] \n test_example/test_example.py::test_pipe FAILED                           [  0%] \n test_example/test_example.py::test_popen FAILED                          [  0%] \n test_example/test_example.py::test_usrsocktest FAILED                    [  0%] \n test_open_posix/test_openposix_.py::test_ltp_interfaces_mq_send_4_2 FAILED [  0%] \n test_open_po","nuttx_hash":"b99e7617aa2fa70f8724a2a7db4b08e723a09bb4","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-11T22:09:43","url":"https://github.com/NuttX/nuttx/actions/runs/12285244144/job/34282901789#step:7:88","url_display":"github.com/NuttX/nuttx/actions/runs/12285244144/job/34282901789#step:7:88","user":"NuttX","version":"3"},"value":[1733974316.308,"0"]}]}}
```

# Appendix: Post NuttX Builds to Mastodon

TODO: [run.sh](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/run.sh)

```bash
#!/usr/bin/env bash
## Post the Failed Jobs from Prometheus to Mastodon

set -e  ## Exit when any command fails
set -x  ## Echo commands

## Set the Access Token for Mastodon
## https://docs.joinmastodon.org/client/authorized/#token
## export MASTODON_TOKEN=...
set +x  ## Disable Echo
. ../mastodon-token.sh
set -x  ## Echo commands

set +e  ## Ignore errors
for (( ; ; )); do
    ## Post the Failed Jobs from Prometheus to Mastodon
    cargo run

    ## Wait a while
    date ; sleep 900
done
```

TODO: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
//! (1) Fetch the Failed NuttX Builds from Prometheus
//! (2) Post to Mastodon

use std::{
    fs::File,
    io::{BufReader, Write},
    thread::sleep,
    time::Duration,
};
use clap::Parser;
use serde_json::{
    json,
    to_string_pretty,
    Value,
};

// Remembers the Mastodon Posts for All Builds:
// {
//   "rv-virt:citest" : {
//     status_id: "12345",
//     users: ["nuttxpr", "NuttX", "lupyuen"]
//   }
//   "rv-virt:citest64" : ...
// }
const ALL_BUILDS_FILENAME: &str = "/tmp/nuttx-prometheus-to-mastodon.json";

/// Command-Line Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init the Logger and Command-Line Args
    env_logger::init();
    // let args = Args::parse();

    // Fetch the Failed Builds from Prometheus
    let query = r##"
        build_score{
            config!="leds64_zig",
            user!="rewind",
            user!="nuttxlinux",
            user!="nuttxmacos",
            user!="jerpelea"
        } < 0.5
    "##;
    println!("query={query}");
    let params = [("query", query)];
    let client = reqwest::Client::new();
    let prometheus = "http://localhost:9090/api/v1/query";
    let res = client
        .post(prometheus)
        .form(&params)
        .send()
        .await?;
    println!("res={res:?}");
    if !res.status().is_success() {
        println!("*** Prometheus Failed");
        sleep(Duration::from_secs(1));
    }
    println!("Status: {}", res.status());
    println!("Headers:\n{:#?}", res.headers());
    let body = res.text().await?;
    println!("Body: {body}");
    let data: Value = serde_json::from_str(&body).unwrap();
    let builds = &data["data"]["result"];
    println!("\n\nbuilds={builds:?}");

    // Load the Mastodon Posts for All Builds
    let mut all_builds = json!({});
    if let Ok(file) = File::open(ALL_BUILDS_FILENAME) {
        let reader = BufReader::new(file);
        all_builds = serde_json::from_reader(reader).unwrap();    
    }

    // For Each Failed Build...
    for build in builds.as_array().unwrap() {
        println!("\n\nbuild={build:?}");
        let metric = &build["metric"];
        println!("\n\nmetric={metric:?}");
        let board = metric["board"].as_str().unwrap();
        let config = metric["config"].as_str().unwrap();
        let user = metric["user"].as_str().unwrap();
        let msg = metric["msg"].as_str().unwrap_or("");
        let config_upper = config.to_uppercase();
        let target = format!("{board}:{config}");
        println!("\n\nboard={board}");
        println!("config={config}");
        println!("user={user}");
        println!("msg={msg}");

        // Compose the Mastodon Post as...
        // rv-virt : CITEST - Build Failed (NuttX)
        // NuttX Dashboard: ...
        // Build History: ...
        // [Error Message]
        let mut status = format!(
            r##"
{board} : {config_upper} - Build Failed ({user})
NuttX Dashboard: https://nuttx-dashboard.org
Build History: https://nuttx-dashboard.org/d/fe2q876wubc3kc/nuttx-build-history?var-board={board}&var-config={config}

{msg}
            "##);
        status.truncate(512);  // Mastodon allows only 500 chars
        let mut params = Vec::new();
        params.push(("status", status));

        // If the Mastodon Post already exists for Board and Config:
        // Reply to the Mastodon Post
        if let Some(status_id) = all_builds[&target]["status_id"].as_str() {
            params.push(("in_reply_to_id", status_id.to_string()));

            // If the User already exists for the Board and Config:
            // Skip the Mastodon Post
            if let Some(users) = all_builds[&target]["users"].as_array() {
                if users.contains(&json!(user)) {
                    println!("Skipping {user} @ {target}, already exists");
                    continue;
                }
            }
        }

        // Post to Mastodon
        let token = std::env::var("MASTODON_TOKEN")
            .expect("MASTODON_TOKEN env variable is required");
        let client = reqwest::Client::new();
        let mastodon = "https://nuttx-feed.org/api/v1/statuses";
        let res = client
            .post(mastodon)
            .header("Authorization", format!("Bearer {token}"))
            .form(&params)
            .send()
            .await?;
        println!("res={res:?}");
        if !res.status().is_success() {
            println!("*** Mastodon Failed: {user} @ {target}");
            sleep(Duration::from_secs(30));
            continue;
        }
        println!("Status: {}", res.status());
        println!("Headers:\n{:#?}", res.headers());
        let body = res.text().await?;
        println!("Body: {body}");

        // Remember the Mastodon Post ID (Status ID)
        let status: Value = serde_json::from_str(&body).unwrap();
        let status_id = status["id"].as_str().unwrap();
        println!("status_id={status_id}");
        all_builds[&target]["status_id"] = status_id.into();

        // Append the User to All Builds
        if let Some(users) = all_builds[&target]["users"].as_array() {
            if !users.contains(&json!(user)) {
                let mut users = users.clone();
                users.push(json!(user));
                all_builds[&target]["users"] = json!(users);
            }
        } else {
            all_builds[&target]["users"] = json!([user]);
        }

        // Save the Mastodon Posts for All Builds
        let json = to_string_pretty(&all_builds).unwrap();
        let mut file = File::create(ALL_BUILDS_FILENAME).unwrap();
        file.write_all(json.as_bytes()).unwrap();
        println!("\n\nall_builds=\n{json}");

        // Wait a while
        sleep(Duration::from_secs(30));
    }

    // Return OK
    Ok(())
}
```

# Appendix: Install our Mastodon Server

TODO: Rancher Desktop on macOS, probably work on Docker Desktop for Linux / macOS / Windows

TODO: Explain each section of compose.yml

1.  Download the __Mastodon Source Code__ and init the Environment Config

    ```bash
    git clone \
      https://github.com/mastodon/mastodon \
      --branch v4.3.2
    cd mastodon
    echo >.env.production
    ```

1.  Replace __docker-compose.yml__ with our slightly-tweaked version

    ```bash
    rm docker-compose.yml
    wget https://raw.githubusercontent.com/lupyuen/mastodon/refs/heads/main/docker-compose.yml
    ```

    [(See the __Minor Tweaks__)](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

1.  Purge the __Docker Volumes__, if they already exist (see below)

    ```bash
    docker volume rm postgres-data
    docker volume rm redis-data
    docker volume rm es-data
    docker volume rm lt-data
    ```

1.  Edit [__docker-compose.yml__](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml#L58-L67). Set "__web > command__" to "__sleep infinity__"

    ```yaml
    web:
      command: sleep infinity
    ```

    (Why? Because we'll start the Web Container to Configure Mastodon)

1.  Start the __Docker Containers for Mastodon__: Database, Web, Redis (Memory Cache), Streaming (WebSocket), Sidekiq (Batch Jobs), Elasticsearch (Search Engine)

    ```bash
    ## TODO: Is `sudo` needed?
    sudo docker compose up

    ## Ignore the Redis, Streaming, Elasticsearch errors
    ## redis-1: Memory overcommit must be enabled
    ## streaming-1: connect ECONNREFUSED 127.0.0.1:6379
    ## es-1: max virtual memory areas vm.max_map_count is too low

    ## Press Ctrl-C to quit the log
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/fb086d6f5fe84044c6c8dae1093b0328#file-gistfile1-txt-L226-L789)

1.  __Init the Postgres Database:__ We create the Mastodon User

    ```bash
    ## From https://docs.joinmastodon.org/admin/install/#creating-a-user
    docker exec \
      -it \
      mastodon-db-1 \
      /bin/bash
    exec su-exec \
      postgres \
      psql
    CREATE USER mastodon CREATEDB;
    \q
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b#file-gistfile1-txt-L1-L11)

1.  __Generate the Mastodon Config:__ We connect to Web Container and prep the Mastodon Config

    ```bash
    ## From https://docs.joinmastodon.org/admin/install/#generating-a-configuration
    docker exec \
      -it \
      mastodon-web-1 \
      /bin/bash
    RAILS_ENV=production \
      bin/rails \
      mastodon:setup
    exit
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b#file-gistfile1-txt-L11-L95)

1.  Mastodon has __Many Questions__, we answer them

    (Change _nuttx-feed.org_ to Your Domain Name)

    ```yaml
    Domain name: nuttx-feed.org
    Enable single user mode?      No
    Using Docker to run Mastodon? Yes

    PostgreSQL host:     db
    PostgreSQL port:     5432
    PostgreSQL database: mastodon_production
    PostgreSQL user:     mastodon
    Password of user:    [ blank ]

    Redis host:     redis
    Redis port:     6379
    Redis password: [ blank ]

    Store uploaded files on the cloud? No
    Send e-mails from localhost?       Yes
    E-mail address: Mastodon <notifications@nuttx-feed.org>
    Send a test e-mail? No

    Check for important updates? Yes
    Save configuration?          Yes
    Save it to .env.production outside Docker:
    # Generated with mastodon:setup on 2024-12-08 23:40:38 UTC
    [ TODO: Please Save Mastodon Config! ]

    Prepare the database now?           Yes
    Create an admin user straight away? Yes
    Username: [ Your Admin Username ]
    E-mail:   [ Your Email Address ]
    Login with the password:
    [ TODO: Please Save Admin Password! ]
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b#file-gistfile1-txt-L11-L95)

    (No Email Server? Read on for our workaround)

1.  Copy the Mastodon Config from above to __`.env.production`__

    ```text
    # Generated with mastodon:setup on 2024-12-08 23:40:38 UTC
    LOCAL_DOMAIN=nuttx-feed.org
    SINGLE_USER_MODE=false
    SECRET_KEY_BASE=...
    OTP_SECRET=...
    ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY=...
    ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT=...
    ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY=...
    VAPID_PRIVATE_KEY=...
    VAPID_PUBLIC_KEY=...
    DB_HOST=db
    DB_PORT=5432
    DB_NAME=mastodon_production
    DB_USER=mastodon
    DB_PASS=
    REDIS_HOST=redis
    REDIS_PORT=6379
    REDIS_PASSWORD=
    SMTP_SERVER=localhost
    SMTP_PORT=25
    SMTP_AUTH_METHOD=none
    SMTP_OPENSSL_VERIFY_MODE=none
    SMTP_ENABLE_STARTTLS=auto
    SMTP_FROM_ADDRESS=Mastodon <notifications@nuttx-feed.org>
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b#file-gistfile1-txt-L46-L75)

1.  Edit [__docker-compose.yml__](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml#L58-L67). Set "__web > command__" to this...

    ```yaml
    web:
      command: bundle exec puma -C config/puma.rb
    ```

    (Why? Because we're done Configuring Mastodon!)

1.  Restart the __Docker Containers__ for Mastodon

    ```bash
    ## TODO: Is `sudo` needed?
    sudo docker compose down
    sudo docker compose up
    ```

1.  And __Mastodon is Up__!

    ```bash
    redis-1:     Ready to accept connections tcp
    db-1:        database system is ready to accept connections
    streaming-1: request completed
    web-1:       GET /health
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/420540f9157f2702c14944fc47743742)

    (Sidekiq will have errors, we'll explain why)

_Why the tweaks to docker-compose.yml?_

Somehow Rancher Desktop doesn't like to __Mount the Local Filesystem__, failing with a permission error...

```yaml
## Local Filesystem will fail on macOS Rancher Desktop
services:
  db:
    volumes:
      - ./postgres14:/var/lib/postgresql/data
```

Thus we __Mount the Docker Volumes__ instead: [docker-compose.yml](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

```yaml
## Docker Volumes will mount OK on macOS Rancher Desktop
services:
  db:
    volumes:
      - postgres-data:/var/lib/postgresql/data

  redis:
    volumes:
      - redis-data:/data

  sidekiq:
    volumes:
      - lt-data:/mastodon/public/system

## Declare the Docker Volumes
volumes:
  postgres-data:
  redis-data:
  es-data:
  lt-data:
```

Note that Mastodon will appear at __HTTP Port 3001__, because Port 3000 is already taken by Grafana: [docker-compose.yml](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

```yaml
web:
  ports:
    - '127.0.0.1:3001:3000'
```

# Appendix: Test our Mastodon Server

We're ready to __Test Mastodon__!

1.  Talk to our __Web Hosting Provider__ (or Tunnel Provider).

    Channel all Incoming Requests for _https://nuttx-feed.org_
    
    To _http://YOUR\_DOCKER\_MACHINE:3001_

    (__HTTPS Port 443__ connects to __HTTP Port 3001__ via Reverse Proxy)

    (For CloudFlare Tunnel: Set __Security > Settings > High__)

    (Change _nuttx-feed.org_ to Your Domain Name)

1.  Browse to _https://nuttx-feed.org_. __Mastodon is Up!__

    ![TODO](https://lupyuen.github.io/images/mastodon-web5.png)

1.  Log in with the __Admin User and Password__

    (From previous section)

1.  Browse to __Administration > Settings__ and fill in...
    - __Branding__
    - __About__
    - __Registrations > Who Can Sign Up <br> > Approval Required > Require A Reason__

1.  Normally we'll approve New Accounts at __Moderation > Accounts > Approve__

    But we don't have an __Outgoing Mail Server__ to validate the email address!
    
    Let's work around this...

# Appendix: Create our Mastodon Account

Remember that we'll pretend to be a Regular User _(nuttx_build)_ and post Mastodon Updates? This is how we create the Mastodon User...

1.  Browse to _https://YOUR_DOMAIN_NAME.org_. Click __"Create Account"__ and fill in the info

    TODO: Pics of Register

1.  Normally we'll approve New Accounts at __Moderation > Accounts > Approve__

    TODO: Pic of Approve

    But we don't have an __Outgoing Mail Server__ to validate the email address!

1.  Instead we do this...

    ```bash
    ## Approve and Confirm the Email Address
    ## From https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
    docker exec -it \
      mastodon-web-1 \
      /bin/bash
    bin/tootctl accounts \
      approve nuttx_build
    bin/tootctl accounts \
      modify nuttx_build \
      --confirm
    exit
    ```

    (Change _nuttx_build_ to the new username)

1.  FYI for a new __Owner Account__, do this...

    ```bash
    ## From https://docs.joinmastodon.org/admin/setup/#admin-cli
    docker exec -it mastodon-web-1 /bin/bash
    bin/tootctl accounts \
      create YOUR_OWNER_USERNAME \
      --email YOUR_OWNER_EMAIL \
      --confirmed \
      --role Owner
    bin/tootctl accounts \
      approve YOUR_OWNER_NAME
    exit
    ```

1.  That's why it's OK to ignore the __Sidekiq Errors__ for sending email...

    ```text
    TODO
    sidekiq-1    | 2024-12-09T00:04:55.035Z pid=6 tid=2ppy class=ActionMailer::MailDeliveryJob jid=8b52310d0afc7d27b0af3d4b elapsed=0.043 INFO: fail
    sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: {"context":"Job raised exception","job":{"retry":true,"queue":"mailers","wrapped":"ActionMailer::MailDeliveryJob","args":[{"job_class":"ActionMailer::MailDeliveryJob","job_id":"a7c8ac28-83bd-42b8-a4de-554f533a01f8","provider_job_id":null,"queue_name":"mailers","priority":null,"arguments":["UserMailer","password_change","deliver_now",{"args":[{"_aj_globalid":"gid://mastodon/User/1"}],"_aj_ruby2_keywords":["args"]}],"executions":0,"exception_executions":{},"locale":"en","timezone":"UTC","enqueued_at":"2024-12-09T00:00:54.250576360Z","scheduled_at":null}],"class":"ActiveJob::QueueAdapters::SidekiqAdapter::JobWrapper","jid":"8b52310d0afc7d27b0af3d4b","created_at":1733702454.2507422,"enqueued_at":1733702694.9922712,"error_message":"Connection refused - connect(2) for \"localhost\" port 25","error_class":"Errno::ECONNREFUSED","failed_at":1733702454.3886917,"retry_count":3,"retried_at":1733702562.7745714}}
    sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: Errno::ECONNREFUSED: Connection refused - connect(2) for "localhost" port 25
    sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: /usr/local/bundle/gems/net-smtp-0.5.0/lib/net/smtp.rb:663:in `initialize'
    ```

TODO: mastodon-register1.png

![TODO](https://lupyuen.github.io/images/mastodon-register1.png)

TODO: mastodon-register2.png

![TODO](https://lupyuen.github.io/images/mastodon-register2.png)

TODO: mastodon-register3.png

![TODO](https://lupyuen.github.io/images/mastodon-register3.png)

TODO: mastodon-register4.png

![TODO](https://lupyuen.github.io/images/mastodon-register4.png)

# Appendix: Create our Mastodon App

TODO

1.  This is how we create a __Mastodon App__...

    ```text
    ## Create Our App: https://docs.joinmastodon.org/client/token/#app
    curl -X POST \
      -F 'client_name=NuttX Dashboard' \
      -F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob' \
      -F 'scopes=read write push' \
      -F 'website=https://nuttx-dashboard.org' \
      https://YOUR_DOMAIN_NAME.org/api/v1/apps
    ```

1.  We'll see the __Client ID__ and __Client Secret__. Please save them and keep them secret! (Change _nuttx-dashboard_ to your App Name)

    ```json
    {"id":"3",
    "name":"NuttX Dashboard",
    "website":"https://nuttx-dashboard.org",
    "scopes":["read","write","push"],
    "redirect_uris":["urn:ietf:wg:oauth:2.0:oob"],
    "vapid_key":"...",
    "redirect_uri":"urn:ietf:wg:oauth:2.0:oob",
    "client_id":"...",
    "client_secret":"...",
    "client_secret_expires_at":0}
    ```

1.  Open a Web Browser. Browse to _https://YOUR_DOMAIN_NAME.org_

    Log in as Your New User _(nuttx_build)_

1.  Paste this URL into the Same Web Browser

    ```text
    https://YOUR_DOMAIN_NAME.org/oauth/authorize
      ?client_id=YOUR_CLIENT_ID
      &scope=read+write+push
      &redirect_uri=urn:ietf:wg:oauth:2.0:oob
      &response_type=code
    ```

    [(Explained here)](https://docs.joinmastodon.org/client/authorized/)

1.  Copy the __Authorization Code__. (It will expire soon!)

1.  We transform the Authorization Code into an __Access Token__ 

    ```bash
    ## From https://docs.joinmastodon.org/client/authorized/#token
    export CLIENT_ID=...     ## From Above
    export CLIENT_SECRET=... ## From Above
    export AUTH_CODE=...     ## From Above
    curl -X POST \
      -F "client_id=$CLIENT_ID" \
      -F "client_secret=$CLIENT_SECRET" \
      -F "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
      -F "grant_type=authorization_code" \
      -F "code=$AUTH_CODE" \
      -F "scope=read write push" \
      https://YOUR_DOMAIN_NAME.org/oauth/token
    ```

1.  We'll see the __Access Token__. Please save it and keep secret!

    ```json
    {"access_token":"...",
    "token_type":"Bearer",
    "scope":"read write push",
    "created_at":1733966892}
    ```

1.  To test our Access Token...

    ```bash
    export ACCESS_TOKEN=...  ## From Above
    curl \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      https://YOUR_DOMAIN_NAME.org/api/v1/accounts/verify_credentials
    ```

1.  We'll see...

    ```json
    {"username": "nuttx_build",
    "acct": "nuttx_build",
    "display_name": "NuttX Build",
    "locked": false,
    "bot": false,
    "discoverable": null,
    "indexable": false,
    ...
    ```

    Yep looks hunky dory!

TODO: mastodon-register5.png

![TODO](https://lupyuen.github.io/images/mastodon-register5.png)

TODO: mastodon-register6.png

![TODO](https://lupyuen.github.io/images/mastodon-register6.png)

# Appendix: Create a Mastodon Post

Our Regular Mastondon User is up! Let's post something as the user...

```bash
## Create Status: https://docs.joinmastodon.org/methods/statuses/#create
export ACCESS_TOKEN=...  ## From Above
curl -X POST \
	-H "Authorization: Bearer $ACCESS_TOKEN" \
	-F "status=Posting a status from curl" \
	https://YOUR_DOMAIN_NAME.org/api/v1/statuses
```

And our __Mastodon Post__ appears!

![TODO](https://lupyuen.github.io/images/mastodon-web4.png)

__ActivityPub__ is the Main API for Mastodon and Fediverse. Let's make sure that it works on our server...

```bash
## Install `jq` for Browsing JSON
$ brew install jq      ## For macOS
$ sudo apt install jq  ## For Ubuntu

## Fetch the TODO Activity Feed for nuttx_build at nuttx-feed.org
$ curl \
  -H 'Accept: application/activity+json' \
  https://nuttx-feed.org/@nuttx_build \
  | jq

{ ... TODO ... }

## Fetch the above Activity (Post)
$ curl -H \
  'Accept: application/activity+json' \
  https://nuttx-feed.org/@nuttx_build/TODO \
  | jq

{ ... TODO ... }

## Fetch the User nuttx_build at nuttx-feed.org
$ curl \
  https://nuttx-feed.org/.well-known/webfinger\?resource\=acct:nuttx_build@nuttx-feed.org \
  | jq

{ ... ""acct:nuttx_build@nuttx-feed.org" ... }
```

__WebFinger__ is particularly important, it locates Users within the Fediverse. It should always work!

TODO

```text
TODO
https://github.com/h3poteto/megalodon-rs

Post With Status: https://github.com/h3poteto/megalodon-rs/blob/master/examples/mastodon_post_with_schedule.rs
```

TODO: mastodon-register7.png

![TODO](https://lupyuen.github.io/images/mastodon-register7.png)

TODO: mastodon-log.png

![TODO](https://lupyuen.github.io/images/mastodon-log.png)

```text
Docker Logs:
https://gist.github.com/lupyuen/fb086d6f5fe84044c6c8dae1093b0328
https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b
https://gist.github.com/lupyuen/edbf045433189bebd4ad843608772ce8
https://gist.github.com/lupyuen/420540f9157f2702c14944fc47743742
https://gist.github.com/lupyuen/89eb8fc76ac9342209bb9c0553298d4c
https://gist.github.com/lupyuen/21ad4e38fa00796d132e63d41e4a339f
```

# Appendix: Backup our Mastodon Server

TODO

```bash
## From https://docs.joinmastodon.org/admin/backups/
## Backup Postgres Database (and check for sensible data)
docker exec \
  -it \
  mastodon-db-1 \
  /bin/bash -c \
  "exec su-exec postgres pg_dumpall" \
  >mastodon.sql
head -50 mastodon.sql

## Backup Redis (and check for sensible data)
docker cp \
  mastodon-redis-1:/data/dump.rdb \
  .
strings dump.rdb \
  | tail -50

## Backup User-Uploaded Files
tar cvf \
  mastodon-public-system.tar \
  mastodon/public/system
```

TODO: Is it safe to run Mastodon as Docker? Docker Isolation vs VM

Might be a little different for macOS Rancher Desktop

# Appendix: Enable Elasticsearch for Mastodon

TODO: Administration > Dashboard

"Could not connect to Elasticsearch. Please check that it is running, or disable full-text search"

Enable Elasticsearch:

https://github.com/lupyuen/mastodon/commit/b7d147d1e4928013ae789d783cf96b5b2628e347

.env.production

```bash
ES_ENABLED=true
ES_HOST=es
ES_PORT=9200
```

docker-compose.yml: Uncomment section for es

```yaml
  es:
    volumes:
       - es-data:/usr/share/elasticsearch/data
  web:
    depends_on:
      - db
      - redis
      - es
```

TODO

```bash
docker compose down
docker compose up
```

"es-1         | bootstrap check failure [1] of [1]: max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]"

Increase max_map_count:

https://docs.rancherdesktop.io/how-to-guides/increasing-open-file-limit/

Restart Docker Desktop

```bash
## Print the Max Virtual Memory Areas
$ docker exec \
  -it \
  mastodon-es-1 \
  /bin/bash -c \
  "sysctl vm.max_map_count"

vm.max_map_count = 262144
```

TODO: Administration > Dashboard

"Elasticsearch index mappings are outdated"

```bash
docker exec \
  -it \
  mastodon-web-1 \
  /bin/bash
bin/tootctl search \
  deploy --only=instances \
  accounts tags statuses public_statuses
exit
```

# Appendix: Docker Compose for Mastodon

_What's this Docker Compose? Why use it for Mastodon?_

TODO: Minor Tweaks

[(See the __Minor Tweaks__)](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

## Database Server

[__PostgreSQL__](TODO) is our Database Server for Mastodon: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
services:
  db:
    restart: always
    image: postgres:14-alpine
    shm_size: 256mb

    ## Map the Docker Volume "postgres-data"
    ## because macOS Rancher Desktop won't work correctly with a Local Filesystem
    volumes:
      -  postgres-data:/var/lib/postgresql/data
    
    ## Allow auto-login by all connections from localhost
    environment:
      - 'POSTGRES_HOST_AUTH_METHOD=trust'

    ## Database Server is not exposed outside Docker
    networks:
      - internal_network
    healthcheck:
      test: ['CMD', 'pg_isready', '-U', 'postgres']
```

Note the last line for _POSTGRES_HOST_AUTH_METHOD_. It says that our Database Server will allow auto-login by __all connections from localhost__. Even without PostgreSQL Password!

This is probably OK for us, since our Database Server runs in its own Docker Container.

We map the __Docker Volume__ _postgres-data_, because macOS Rancher Desktop won't work correctly with a Local Filesystem like _./postgres14_.

## Web Server 

Powered by Ruby-on-Rails, __Puma__ is our Web Server: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
  web:
    ## You can uncomment the following line if you want to not use the prebuilt image, for example if you have local code changes
    ## build: .
    image: ghcr.io/mastodon/mastodon:v4.3.2
    restart: always

    ## Read the Mastondon Config from Docker Host
    env_file: .env.production

    ## Start the Puma Web Server
    command: bundle exec puma -C config/puma.rb
    ## When Configuring Mastodon: Change to...
    ## command: sleep infinity

    ## HTTP Port 3000 should always return OK
    healthcheck:
      # prettier-ignore
      test: ['CMD-SHELL',"curl -s --noproxy localhost localhost:3000/health | grep -q 'OK' || exit 1"]

    ## Mastodon will appear outside Docker at HTTP Port 3001
    ## because Port 3000 is already taken by Grafana
    ports:
      - '127.0.0.1:3001:3000'
    networks:
      - external_network
      - internal_network
    depends_on:
      - db
      - redis
      - es
    volumes:
      - ./public/system:/mastodon/public/system
```

Note that Mastodon will appear at __HTTP Port 3001__, because Port 3000 is already taken by Grafana: [docker-compose.yml](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

## Redis Server

Web Server fetching data directly from Database Server will be awfully slow. That's why we use Redis as an __In-Memory Caching Database__: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
  redis:
    restart: always
    image: redis:7-alpine

    ## Map the Docker Volume "redis-data"
    ## because macOS Rancher Desktop won't work correctly with a Local Filesystem
    volumes:
      - redis-data:/data

    ## Redis Server is not exposed outside Docker
    networks:
      - internal_network
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
```

## Sidekiq Server

Remember that Emails that Mastodon will send upon User Registration? Mastodon does this with __Sidekiq__ for running Background Batch Jobs, so it won't hold up the Web Server: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
  sidekiq:
    build: .
    image: ghcr.io/mastodon/mastodon:v4.3.2
    restart: always

    ## Read the Mastondon Config from Docker Host
    env_file: .env.production

    ## Start the Sidekiq Batch Job Server
    command: bundle exec sidekiq
    depends_on:
      - db
      - redis
    volumes:
      - ./public/system:/mastodon/public/system

    ## Sidekiq Server is exposed outside Docker
    ## for Outgoing Connections, to deliver emails
    networks:
      - external_network
      - internal_network
    healthcheck:
      test: ['CMD-SHELL', "ps aux | grep '[s]idekiq\ 6' || false"]
```

## Streaming Server

__Optional:__ Mastodon (and Fediverse) uses [__ActivityPub__](TODO) for exchanging lots of info about Users and Posts. Our Web Server supports the __HTTP Rest API__, but there's a more efficient way: __WebSocket API__.

WebSocket is __totally optional__, Mastodon works fine without it, probably a little less efficient: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
  streaming:
    ## You can uncomment the following lines if you want to not use the prebuilt image, for example if you have local code changes
    ## build:
    ##   dockerfile: ./streaming/Dockerfile
    ##   context: .
    image: ghcr.io/mastodon/mastodon-streaming:v4.3.2
    restart: always

    ## Read the Mastondon Config from Docker Host
    env_file: .env.production

    ## Start the Streaming Server (Node.js!)
    command: node ./streaming/index.js
    depends_on:
      - db
      - redis

    ## WebSocket will listen on HTTP Port 4000
    ## for Incoming Connections (totally optional!)
    ports:
      - '127.0.0.1:4000:4000'
    networks:
      - external_network
      - internal_network
    healthcheck:
      # prettier-ignore
      test: ['CMD-SHELL', "curl -s --noproxy localhost localhost:4000/api/v1/streaming/health | grep -q 'OK' || exit 1"]
```

## Elasticsearch Server

__Optional:__ Elasticsearch is for __Full-Text Search__. Also totally optional, unless we require Full-Text Search for Users and Posts: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
  es:
    restart: always
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.4
    environment:
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m -Des.enforce.bootstrap.checks=true"
      - "xpack.license.self_generated.type=basic"
      - "xpack.security.enabled=false"
      - "xpack.watcher.enabled=false"
      - "xpack.graph.enabled=false"
      - "xpack.ml.enabled=false"
      - "bootstrap.memory_lock=true"
      - "cluster.name=es-mastodon"
      - "discovery.type=single-node"
      - "thread_pool.write.queue_size=1000"

    ## Elasticsearch is exposed externally at HTTP Port 9200. (Why?)
    ports:
      - '127.0.0.1:9200:9200'
    networks:
       - external_network
       - internal_network
    healthcheck:
       test: ["CMD-SHELL", "curl --silent --fail localhost:9200/_cluster/health || exit 1"]

    ## Map the Docker Volume "es-data"
    ## because macOS Rancher Desktop won't work correctly with a Local Filesystem
    volumes:
       - es-data:/usr/share/elasticsearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
```

## Volumes and Networks

Finally we declare the __Volumes and Networks__ used by our Docker Containers: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

```yaml
volumes:
  postgres-data:
  redis-data:
  es-data:
  lt-data:

networks:
  external_network:
  internal_network:
    internal: true
```

## Simplest Server for Mastodon

_Phew that looks might complicated!_

There's a simpler way

TODO: Not recommended for internet hosting!

```text
Previously:
git clone https://github.com/mastodon/mastodon --branch v4.3.2
code mastodon

.devcontainer/compose.yaml:
<<
    ports:
      - '127.0.0.1:3001:3000'
>>

.env.development
<<
LOCAL_DOMAIN=nuttx-feed.org
>>

cd mastodon
docker compose -f .devcontainer/compose.yaml up -d
docker compose -f .devcontainer/compose.yaml exec app bin/setup
docker compose -f .devcontainer/compose.yaml exec app bin/dev
http://localhost:3001/home
docker compose -f .devcontainer/compose.yaml down

https://docs.joinmastodon.org/admin/setup/#admin-cli
docker exec -it devcontainer-app-1 /bin/bash
bin/tootctl accounts create \
  lupyuen \
  --email luppy@appkaki.com \
  --confirmed \
  --role Owner

https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
bin/tootctl accounts approve lupyuen

docker exec -it devcontainer-app-1 /bin/bash
bin/tootctl search deploy --only=tags
```
