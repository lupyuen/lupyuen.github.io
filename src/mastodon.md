# (Experimental) Mastodon Server for Apache NuttX Continuous Integration (macOS Rancher Desktop)

📝 _30 Dec 2024_

![TODO](https://lupyuen.github.io/images/mastodon-title.jpg)

We're out for an [__overnight hike__](https://www.strava.com/activities/13055019749), city to airport. Our [__Build Farm for Apache NuttX RTOS__](https://lupyuen.github.io/articles/ci4) runs non-stop all day, all night. Continuously compiling over [__1,000 NuttX Targets__](https://lupyuen.github.io/articles/ci#one-thousand-build-targets). 

Can we be 100% sure that __NuttX is OK?__ Without getting spammed by __alert emails__ all night? (Sorry we got zero budget for _"paging duty"_ services)

![TODO](https://lupyuen.github.io/images/mastodon-mobile3.png)

TODO: In this article we talk about Mastodon 

- TODO

![Following the NuttX Feed on Mastodon](https://lupyuen.github.io/images/mastodon-mobile1.png)

# Mastodon for NuttX CI

1.  Register for a [__Mastodon Account__](https://joinmastodon.org) on any Fediverse Server (I got mine at [__`qoto.org`__](qoto.org))

1.  __On Our Mobile Device:__ Install a Mastodon App (like [__Tusky__](https://tusky.app/)) and log in

1.  Tap the __Search__ button. Enter...

    ```text
    @nuttx_build@nuttx-feed.org
    ```

    Tap the __Accounts__ tab, then tap the account that appears. (Pic above)

1.  Tap the __Follow__ button. And the __Notify__ button beside it. (Pic above)

1.  That's all! When a NuttX Build Fails, we'll see a __Notification in the Mastodon App__ (linking to NuttX Build History)

![Notification in the Mastodon App links to NuttX Build History](https://lupyuen.github.io/images/mastodon-mobile3.png)

_How did we get the Failed NuttX Builds?_

Thanks to the NuttX Community: We have a (self-hosted) [__NuttX Build Farm__](https://lupyuen.github.io/articles/ci4) that continously compiles All NuttX Targets. _(1,600 Targets!)_

Failed Builds are auto-escalated to the [__NuttX Dashboard__](https://lupyuen.github.io/articles/ci4). (Grafana + Prometheus)

In a while, we'll explain how the Failed Builds are channeled from NuttX Dashboard into __Mastodon Posts__.

First we talk about Mastodon...

# Our Mastodon Server

_What kind of animal is Mastodon?_

Think Twitter... But __Open-Source__ and __Self-Hosted__! _(Ruby-on-Rails + PostgreSQL + Redis + Elasticsearch)_ Mastodon is mostly used for Global Social Networking on [__The Fediverse__](https://en.wikipedia.org/wiki/Fediverse).

Though today we're making something unexpected, unconventional with Mastodon: Pushing Notifications of __Failed NuttX Builds__.

_(Think "Social Network for NuttX Maintainers")_

TODO: Pic of Mastodon

_OK weird flex. How to get started?_

We begin by installing our __Mastodon Server with Docker__ (pic above)...

- [__"Install our Mastodon Server"__](https://lupyuen.github.io/articles/mastodon#appendix-install-our-mastodon-server)

- [__"Test our Mastodon Server"__](https://lupyuen.github.io/articles/mastodon#appendix-test-our-mastodon-server)

- [__"Enable Elasticsearch for Mastodon"__](https://lupyuen.github.io/articles/mastodon#appendix-enable-elasticsearch-for-mastodon)

- [__"Docker Compose for Mastodon"__](https://lupyuen.github.io/articles/mastodon#appendix-docker-compose-for-mastodon)

- Based on the excellent [__Mastodon Docs__](https://docs.joinmastodon.org/admin/prerequisites/)

Right now we're testing on (open-source) [__macOS Rancher Desktop__](https://rancherdesktop.io/), thus we tweaked the steps a bit.

# Bot User for Mastodon

_Will we have Users in our Mastodon Server?_

Surprisingly, Nope! Our Mastodon Server shall be a tad __Anti-Social__...

- We'll make __One Bot User__ _(nuttx_build)_ for posting NuttX Builds

- __No Other Users__ on our server, since we're not really a Social Network

- But __Users on Other Servers__ _(like qoto.org)_ can Follow our Bot User!

- And receive __Notifications of Failed Builds__ through their accounts

- That's the power of [__Federated ActivityPub__](https://docs.joinmastodon.org/spec/activitypub/)!

This is how we create our __Bot User for Mastodon__...

![Create our Mastodon Account](https://lupyuen.github.io/images/mastodon-register1.png)

Details in the Appendix...

- [__"Test our Mastodon Server"__](https://lupyuen.github.io/articles/mastodon#appendix-test-our-mastodon-server)

- [__"Create our Mastodon Account"__](https://lupyuen.github.io/articles/mastodon#appendix-create-our-mastodon-account)

We have a slight hiccup...

# Email-Less Mastodon

_How to verify the Email Address of our Bot User?_

Remember our Mastodon Server has __Zero Budget__? This means we won't have an __Outgoing Email Server__. (SMTP)

That's perfectly OK! Mastodon provides __Command-Line Tools__ to manage our users...

```bash
## Connect to Mastodon Web (Docker Container)
sudo docker exec \
  -it \
  mastodon-web-1 \
  /bin/bash

## Approve and Confirm the Email Address
## https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
bin/tootctl accounts \
  approve nuttx_build
bin/tootctl accounts \
  modify nuttx_build \
  --confirm
```

The detailed steps are here...

- [__"Create our Mastodon Account"__](https://lupyuen.github.io/articles/mastodon#appendix-create-our-mastodon-account)

# Post to Mastodon

_How will our Bot post a message to Mastodon?_

__With curl:__ This is how we post a __Status Update__ to Mastodon...

```bash
## Post a message to Mastodon (Status Update)
export ACCESS_TOKEN=...  ## Coming up
curl -X POST \
	-H "Authorization: Bearer $ACCESS_TOKEN" \
	-F "status=Posting a status from curl" \
	https://YOUR_DOMAIN_NAME.org/api/v1/statuses

```

It appears like this...

![Post a message to Mastodon (Status Update)](https://lupyuen.github.io/images/mastodon-web4.png)

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-create-a-mastodon-post)

_What's this Access Token?_

We pass an __Access Token__ to Authenticate our Bot User with Mastodon. This is how we create the Access Token...

```bash
## Create an Access Token
export CLIENT_ID=...     ## Coming up
export CLIENT_SECRET=... ## Coming up
export AUTH_CODE=...     ## Coming up
curl -X POST \
  -F "client_id=$CLIENT_ID" \
  -F "client_secret=$CLIENT_SECRET" \
  -F "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
  -F "grant_type=authorization_code" \
  -F "code=$AUTH_CODE" \
  -F "scope=read write push" \
  https://YOUR_DOMAIN_NAME.org/oauth/token
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-create-our-mastodon-app)

_What about the Client ID, Secret and Authorization Code?_

__Client ID and Secret__ will select the Mastodon App for our Bot User...

```bash
## Create Our Mastodon App
curl -X POST \
  -F 'client_name=NuttX Dashboard' \
  -F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob' \
  -F 'scopes=read write push' \
  -F 'website=https://nuttx-dashboard.org' \
  https://YOUR_DOMAIN_NAME.org/api/v1/apps

## Returns { "client_id" : "...", "client_secret" : "..." }
## We save the Client ID and Secret
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-create-our-mastodon-app)

Which we use to create the __Authorization Code__...

```bash
## Open a Web Browser. Browse to https://YOUR_DOMAIN_NAME.org
## Log in as Your New User (nuttx_build)
## Paste this URL into the Same Web Browser
https://YOUR_DOMAIN_NAME.org/oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &scope=read+write+push
  &redirect_uri=urn:ietf:wg:oauth:2.0:oob
  &response_type=code

## Copy the Authorization Code. It will expire soon!
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-create-our-mastodon-app)

# Prometheus to Mastodon

Now comes the tricky bit. How to transmogrify __NuttX Dashboard__...

TODO: Pic of NuttX Dashboard

Into __Mastodon Posts__?

TODO: Pic of posts

This is our grand plan...

1.  __Outcomes of NuttX Builds__ are already recorded...

1.  Inside our __Prometheus Time-Series Database__ (open-source)

1.  Thus we __Query the Failed Builds__ from Prometheus Database

1.  Reformat them as __Mastodon Posts__

1.  Submit to Mastodon via __ActivityPub API__

TODO: Pic of flow

__Prometheus Time-Series Database:__ This is how we fetch the Failed Builds from Prometheus...

```bash
## Find all Build Scores < 0.5
build_score < 0.5
```

Prometheus returns a huge bunch of fields...

TODO: Pic of Prometheus

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-query-prometheus-for-nuttx-builds)

__Query the Failed Builds:__ We query Prometheus and extract the fields in Rust...

```rust
// Fetch the Failed Builds from Prometheus
let query = r##"
  build_score < 0.5
"##;
let params = [("query", query)];
let client = reqwest::Client::new();
let prometheus = "http://localhost:9090/api/v1/query";
let res = client
  .post(prometheus)
  .form(&params)
  .send()
  .await?;
let body = res.text().await?;
let data: Value = serde_json::from_str(&body).unwrap();
let builds = &data["data"]["result"];
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-query-prometheus-for-nuttx-builds)

__Reformat as Mastodon Posts:__ From JSON into Plain Text...

```rust
// For Each Failed Build...
for build in builds.as_array().unwrap() {
  ...
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
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-post-nuttx-builds-to-mastodon)

__Submit to Mastodon via ActivityPub:__ By posting over HTTPS...

```rust
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
  if !res.status().is_success() { continue; }
  // Omitted: Remember the Mastodon Posts for All Builds
}
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-post-nuttx-builds-to-mastodon)

__Skip Duplicates:__ Remember everything in a JSON File, so we won't notify the same thing twice...

```rust
// This JSON File remembers the Mastodon Posts for All Builds:
// {
//   "rv-virt:citest" : {
//     status_id: "12345",
//     users: ["nuttxpr", "NuttX", "lupyuen"]
//   }
//   "rv-virt:citest64" : ...
// }
const ALL_BUILDS_FILENAME: &str =
  "/tmp/nuttx-prometheus-to-mastodon.json"; ...
let mut all_builds = serde_json::from_reader(reader).unwrap();    
...
// If the User already exists for the Board and Config:
// Skip the Mastodon Post
if let Some(users) = all_builds[&target]["users"].as_array() {
  if users.contains(&json!(user)) { continue; }
}
```

[(Explained here)](https://lupyuen.github.io/articles/mastodon#appendix-post-nuttx-builds-to-mastodon)

[__The Appendix__](https://lupyuen.github.io/articles/mastodon#appendix-post-nuttx-builds-to-mastodon) explains how we thread the Mastodon Posts neatly by __NuttX Target__. (Board + Config)

![NuttX Builds threaded neatly](https://lupyuen.github.io/images/mastodon-register7.png)

# All Toots Considered

1.  _Will we accept Regular Users on our Mastodon Server?_

    Probably not? We have __Zero Budget for User Moderation__. We'll ask folks to register for an account on any Fediverse Server. The Push Notifications for Failed Builds will work fine with any server.

1.  _But any Fediverse User can reply to our Mastodon Posts?_

    Yeah this could be useful! We could discuss a specific Failed Build. Or hyperlink to the [__NuttX Issue__](https://github.com/apache/nuttx/issues) that someone has created for the Failed Build.

1.  _How will we know when a Failed Build recovers?_

    This gets tricky. Should we pester folks with an __Extra Push Notification__ whenever a Failed Build recovers?

    For Complex Notifications: We might need to integrate [__Prometheus Alertmanager__](https://prometheus.io/docs/alerting/latest/alertmanager/) with Mastodon.

1.  _Suppose I'm interested only in rv-virt:python. Can I subscribe to the Specific Alert via Mastodon / Fediverse / ActivityPub?_

    Good question! We're still trying to figure out.

1.  _Anything else we should monitor with Mastodon?_

    [__Sync-Build-Ingest__](https://lupyuen.github.io/articles/ci3#move-the-merge-jobs) is a Critical NuttX Job that needs to run non-stop, without fail. We should post a Mastodon Notification if something fails to run.

    [__Cost of GitHub Runners__](https://lupyuen.github.io/articles/ci3#live-metric-for-full-time-runners) shall be continuously monitored. We should push a Mastodon Alert if it exceeds our budget. (Before ASF comes after us)

    [__Over-Running GitHub Jobs__](https://lupyuen.github.io/articles/ci3#present-pains) shall also be monitored, so our (beloved and respected) NuttX Devs won't wait forever for our CI Jobs to complete. Mastodon sounds mightly helpful for watching over Everything NuttX! 👍

TODO

```text
Public Timeline: https://docs.joinmastodon.org/client/public/#timelines
curl https://nuttx-feed.org/api/v1/timelines/public | jq
```

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

# Appendix: Query Prometheus for NuttX Builds

We're fetching the __Failed NuttX Builds__ from Prometheus. We browse to Prometheus at _http://localhost:9090_ and enter this __Prometheus Query__...

```bash
## Find all Build Scores < 0.5
## But skip these users...
build_score{
  user != "rewind",     ## Used for Build Rewind only
  user != "nuttxlinux", ## Retired (Blocked by GitHub)
  user != "nuttxmacos"  ## Retired (Blocked by GitHub)
} < 0.5
```

![Fetching the Failed NuttX Builds from Prometheus](https://lupyuen.github.io/images/mastodon-prometheus.png)

_Why 0.5?_

Build Score is 1.0 for Successful Builds, 0.5 for Warnings, 0.0 for Errors. Thus we search for Build Scores < 0.5.

TODO: Table of Build Scores

_What's returned by Prometheus?_

Plenty of fields, describing every Failed Build in detail...

TODO: Table of Fields

We can do the same with curl and __HTTP POST__...

TODO: nuttx_hash

```bash
$ curl -X POST \
  -F 'query=
    build_score{
      user != "rewind",
      user != "nuttxlinux",
      user != "nuttxmacos"
    } < 0.5
  ' \
  http://localhost:9090/api/v1/query

{"status" : "success", "data" : {"resultType" : "vector", "result" : [{"metric"{
  "__name__"  : "build_score",
  "timestamp" : "2024-12-06T06:14:54",
  "user"      : "nuttxpr",
  "nuttx_hash": "04815338334e63cd82c38ee12244e54829766e88",
  "apps_hash" : "b08c29617bbf1f2c6227f74e23ffdd7706997e0c",
  "arch"      : "risc-v",
  "subarch"   : "qemu-rv",
  "board"     : "rv-virt",
  "config"    : "citest",
  "msg"       : "virtio/virtio-mmio.c: In function
    'virtio_mmio_config_virtqueue': \n virtio/virtio-mmio.c:346:14:
    error: cast from pointer to integer of different size ...
```

In the next section: We'll replicate this with Rust.

_How did we get the above Prometheus Query?_

We copied and pasted from our [__NuttX Dashboard in Grafana__](https://lupyuen.github.io/articles/ci4#grafana-dashboard)...

![Prometheus Query from our NuttX Dashboard in Grafana](https://lupyuen.github.io/images/mastodon-grafana.png)

# Appendix: Post NuttX Builds to Mastodon

In the previous section: We fetched the __Failed NuttX Builds__ from Prometheus. Now we post them to __Mastodon__: [run.sh](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/run.sh)

```bash
## Set the Access Token for Mastodon
## https://docs.joinmastodon.org/client/authorized/#token
## export MASTODON_TOKEN=...
. ../mastodon-token.sh

## Do this forever...
for (( ; ; )); do

  ## Post the Failed Jobs from Prometheus to Mastodon
  cargo run

  ## Wait a while
  date ; sleep 900
done
```

Inside our Rust App, this is how we fetch the __Failed Builds from Prometheus__: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
// Fetch the Failed Builds from Prometheus
let query = r##"
  build_score{
    user!="rewind",
    user!="nuttxlinux",
    user!="nuttxmacos"
  } < 0.5
"##;
let params = [("query", query)];
let client = reqwest::Client::new();
let prometheus = "http://localhost:9090/api/v1/query";
let res = client
  .post(prometheus)
  .form(&params)
  .send()
  .await?;
let body = res.text().await?;
let data: Value = serde_json::from_str(&body).unwrap();
let builds = &data["data"]["result"];
```

__For Every Failed Build:__ We compose the __Mastodon Post__: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
// For Each Failed Build...
for build in builds.as_array().unwrap() {
  ...
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
```

And we __post to Mastodon__: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
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
  if !res.status().is_success() { continue; }
  // Omitted: Remember the Mastodon Posts for All Builds
}
```

_Won't we see repeated Mastodon Posts?_

That's why we __Remember the Mastodon Posts__ for All Builds, in a JSON File: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
// Remembers the Mastodon Posts for All Builds:
// {
//   "rv-virt:citest" : {
//     status_id: "12345",
//     users: ["nuttxpr", "NuttX", "lupyuen"]
//   }
//   "rv-virt:citest64" : ...
// }
const ALL_BUILDS_FILENAME: &str =
  "/tmp/nuttx-prometheus-to-mastodon.json";
...
// Load the Mastodon Posts for All Builds
let mut all_builds = json!({});
if let Ok(file) = File::open(ALL_BUILDS_FILENAME) {
  let reader = BufReader::new(file);
  all_builds = serde_json::from_reader(reader).unwrap();    
}
```

If the User already exists for the Board and Config: We __Skip the Mastodon Post__: [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
// If the Mastodon Post already exists for Board and Config:
// Reply to the Mastodon Post
if let Some(status_id) = all_builds[&target]["status_id"].as_str() {
  params.push(("in_reply_to_id", status_id.to_string()));

  // If the User already exists for the Board and Config:
  // Skip the Mastodon Post
  if let Some(users) = all_builds[&target]["users"].as_array() {
    if users.contains(&json!(user)) { continue; }
  }
}
```

And if the Mastodon Post already exists for the Board and Config: We __Reply to the Mastodon Post__. (To keep the Failed Builds threaded neatly, pic below)

This is how we __Remember the Mastodon Post ID__ (Status ID): [main.rs](https://github.com/lupyuen/nuttx-prometheus-to-mastodon/blob/main/src/main.rs)

```rust
// Remember the Mastodon Post ID (Status ID)
let body = res.text().await?;
let status: Value = serde_json::from_str(&body).unwrap();
let status_id = status["id"].as_str().unwrap();
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
```

Which gets saved into a __JSON File__.

![NuttX Builds threaded neatly](https://lupyuen.github.io/images/mastodon-register7.png)

# Appendix: Install our Mastodon Server

Here are the steps to install Mastodon Server with Docker Compose. We tested with [__Rancher Desktop on macOS__](https://rancherdesktop.io/), the same steps will probably work on [__Docker Desktop__](https://docs.docker.com/engine/install/ubuntu/) for Linux / macOS / Windows.

[(__docker-compose.yml__ is explained here)](https://lupyuen.github.io/articles/mastodon#appendix-docker-compose-for-mastodon)

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

    ## If It Quits To Command-Line:
    ## Run a second time to get it up
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
    sudo docker exec \
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
    sudo docker exec \
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

    [(See __Another Log__)](https://gist.github.com/lupyuen/edbf045433189bebd4ad843608772ce8)

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

    ![Mastodon Web UI](https://lupyuen.github.io/images/mastodon-web5.png)

1.  Log in with the __Admin User and Password__

    (From previous section)

1.  Browse to __Administration > Settings__ and fill in...
    - __Branding__
    - __About__
    - __Registrations > Who Can Sign Up <br> > Approval Required > Require A Reason__

1.  Normally we'll approve New Accounts at __Moderation > Accounts > Approve__

    But we don't have an __Outgoing Mail Server__ to validate the email address!
    
    Let's work around this...

![Create our Mastodon Account](https://lupyuen.github.io/images/mastodon-register1.png)

# Appendix: Create our Mastodon Account

Remember that we'll pretend to be a Regular User _(nuttx_build)_ and post Mastodon Updates? This is how we create the Mastodon User...

1.  Browse to _https://YOUR_DOMAIN_NAME.org_. Click __"Create Account"__ and fill in the info (pic above)

1.  Normally we'll approve New Accounts at __Moderation > Accounts > Approve__

    ![Approving New Accounts at Moderation > Accounts > Approve](https://lupyuen.github.io/images/mastodon-register3.png)

    But we don't have an __Outgoing Mail Server__ to validate the Email Address!

    ![We don't have an Outgoing Mail Server to validate the email address](https://lupyuen.github.io/images/mastodon-register4.png)

1.  Instead we do this...

    ```bash
    ## Approve and Confirm the Email Address
    ## From https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
    sudo docker exec \
      -it \
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
    sudo docker exec \
      -it \
      mastodon-web-1 \
      /bin/bash
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

1.  Click __Authorize__. (Pic below)

1.  Copy the __Authorization Code__. (Pic below. It will expire soon!)

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

![Getting a Mastodon Authorization Code](https://lupyuen.github.io/images/mastodon-register5.png)

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

![Creating a Mastodon Post](https://lupyuen.github.io/images/mastodon-web4.png)

[__ActivityPub__](https://docs.joinmastodon.org/spec/activitypub/) is the Main API for Mastodon and Fediverse. Let's make sure that it works on our server...

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

```text
TODO
➜  ~ $ curl -H 'Accept: application/activity+json' https://nuttx-feed.org/@lupyuen | jq
https://gist.github.com/lupyuen/89eb8fc76ac9342209bb9c0553298d4c
```

# Appendix: Backup our Mastodon Server

TODO

```bash
## From https://docs.joinmastodon.org/admin/backups/
## Backup Postgres Database (and check for sensible data)
sudo docker exec \
  -it \
  mastodon-db-1 \
  /bin/bash -c \
  "exec su-exec postgres pg_dumpall" \
  >mastodon.sql
head -50 mastodon.sql

## Backup Redis (and check for sensible data)
sudo docker cp \
  mastodon-redis-1:/data/dump.rdb \
  .
strings dump.rdb \
  | tail -50

## Backup User-Uploaded Files
tar cvf \
  mastodon-public-system.tar \
  mastodon/public/system
```

Remember to watch our Mastodon Server for __Dubious Web Requests__! Like these pesky WordPress Malware Bots...

![WordPress Malware Bots](https://lupyuen.github.io/images/mastodon-log.png)

TODO: Is it safe to run Mastodon as Docker? Docker Isolation vs VM

TODO: Might be a little different for macOS Rancher Desktop

# Appendix: Enable Elasticsearch for Mastodon

Enabling __Elasticsearch__ for macOS Rancher Desktop is a little tricky. That's why we saved it for last.

1.  In Mastodon Web: Head over to __Administration > Dashboard__. It should say...

    _"Could not connect to Elasticsearch. Please check that it is running, or disable full-text search"_

1.  To Enable Elasticsearch: Edit __`.env.production`__ and add these lines...

    ```bash
    ES_ENABLED=true
    ES_HOST=es
    ES_PORT=9200
    ```

1.  Edit [__docker-compose.yml__](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml).

    Uncomment the Section for __"`es`"__

    Map the Docker Volume __es-data__ for Elasticsearch
    
    Web Container should depend on __"`es`"__

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

1.  Restart the Docker Containers

    ```bash
    sudo docker compose down
    sudo docker compose up
    ```

1.  We'll see...

    _"es-1: bootstrap check failure: max virtual memory areas vm.max_map_count 65530 is too low, increase to at least 262144"_

1.  Here comes the tricky part: __max_map_count__ is configured here!

    ```text
    ~/Library/Application\ Support/rancher-desktop/lima/_config/override.yaml
    ```

    [__Follow the Instructions__](https://docs.rancherdesktop.io/how-to-guides/increasing-open-file-limit/) and set...

    ```bash
    sysctl -w vm.max_map_count=262144
    ```

1.  Restart Docker Desktop

1.  Verify that __max_map_count__ has increased

    ```bash
    ## Print the Max Virtual Memory Areas
    $ sudo docker exec \
      -it \
      mastodon-es-1 \
      /bin/bash -c \
      "sysctl vm.max_map_count"

    vm.max_map_count = 262144
    ```

1.  Head back to Mastodon Web. Click __Administration > Dashboard__. We should see...

    _"Elasticsearch index mappings are outdated"_

1.  Finally we __Reindex Elasticsearch__

    ```bash
    sudo docker exec \
      -it \
      mastodon-web-1 \
      /bin/bash
    bin/tootctl search \
      deploy --only=instances \
      accounts tags statuses public_statuses
    exit
    ```

1.  At __Administration > Dashboard__: Mastodon complains no more!

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/21ad4e38fa00796d132e63d41e4a339f)

# Appendix: Docker Compose for Mastodon

_What's this Docker Compose? Why use it for Mastodon?_

TODO: Minor Tweaks

[(See the __Minor Tweaks__)](https://github.com/lupyuen/mastodon/compare/upstream...lupyuen:mastodon:main)

## Database Server

[__PostgreSQL__](https://www.postgresql.org/) is our Database Server for Mastodon: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

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

_(Streaming Server is Optional)_

Mastodon (and Fediverse) uses [__ActivityPub__](https://docs.joinmastodon.org/spec/activitypub/) for exchanging lots of info about Users and Posts. Our Web Server supports the __HTTP Rest API__, but there's a more efficient way: __WebSocket API__.

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

_(Elasticsearch is optional)_

Elasticsearch is for __Full-Text Search__. Also totally optional, unless we require Full-Text Search for Users and Posts: [docker-compose.yml](https://github.com/lupyuen/mastodon/blob/main/docker-compose.yml)

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

```bash
git clone https://github.com/mastodon/mastodon --branch v4.3.2
cd mastodon
sudo docker compose -f .devcontainer/compose.yaml up -d
sudo docker compose -f .devcontainer/compose.yaml exec app bin/setup
sudo docker compose -f .devcontainer/compose.yaml exec app bin/dev

## Browse to Mastodon Web at http://localhost:3000

## TODO: Default Admin ID

## From https://docs.joinmastodon.org/admin/setup/#admin-cli
## And https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
sudo docker exec \
  -it \
  devcontainer-app-1 \
  /bin/bash
bin/tootctl accounts create \
  YOUR_OWNER_USERNAME \
  --email YOUR_OWNER_EMAIL \
  --confirmed \
  --role Owner
bin/tootctl accounts \
  approve YOUR_OWNER_USERNAME
exit

## Reindex Elasticsearch
sudo docker exec \
  -it \
  devcontainer-app-1 \
  /bin/bash
bin/tootctl search \
  deploy --only=tags
exit
```

TODO: Optional: 

.devcontainer/compose.yaml:

```yaml
    ports:
      - '127.0.0.1:3001:3000'
```

.env.development:

```bash
LOCAL_DOMAIN=nuttx-feed.org
```
