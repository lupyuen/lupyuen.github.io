# Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS

📝 _20 Feb 2025_

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

12 Months Ago: We created a __Grafana Dashboard__ (pic above) that monitors the successful / failed __Daily Builds__ of [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html), across all 339 microcontroller boards. So we'll be alerted if NuttX fails to build for (say) RP2040...

- [__"Continuous Integration Dashboard for Apache NuttX RTOS"__](https://lupyuen.org/articles/ci4)

_Was everything hunky dory?_

Nope! Grafana Dashboard was running on a (macOS) __Home Computer__. Thus if we're overseas for [__Marathon Races__](https://lupyuen.org/articles/marathon#whats-next) and there's a Home Power Outage... NuttX Dashboard goes down and never recovers!

Today, let's migrate NuttX Dashboard from our Home Computer to __Google Cloud VM__. It will cost more, and we don't have the Hosting Budget. But at least NuttX Dashboard will continue running when the lights go poof.

_What if we prefer another cloud? Or our own machine?_

The steps below will work for any __Debian Bookworm__ machine. Hopefully someday we'll budget for the machine. (And secure it too)

_Will it be cheaper on an Asian Cloud? Like AliCloud?_

Hmmm interesting... We should [__try it sometime__](https://web.archive.org/web/20191204194108/https://medium.com/@ly.lee/first-impressions-of-alibaba-cloud-aliyun-688dc46fa9b8?source=friends_link&sk=0685f5028f4ce9575dfae9cc9515143d)!

![NuttX Dashboard](https://lupyuen.org/images/dashboard-flow.jpg)

# Create Our Virtual Machine

We begin by creating a __Google Cloud Project__ that will operate our VM (pic above). We named it _nuttx-dashboard_...

- [__Create a Google Cloud Project__](https://console.cloud.google.com/projectcreate) _(console.cloud.google.com)_

![Create a Google Cloud Project](https://lupyuen.org/images/dashboard-vm1.png)

Then we create our __Virtual Machine__...

1.  Click __"Select Project"__

    ![Select Project](https://lupyuen.org/images/dashboard-vm2.png)

1.  Click __"Create a VM"__

    ![Create a VM](https://lupyuen.org/images/dashboard-vm3.png)

1.  Click __"Compute Engine API > Enable"__ and wait a while

    ![Compute Engine API > Enable](https://lupyuen.org/images/dashboard-vm4.png)

1.  Fill in the __Instance Name__ _"nuttx-dashboard-vm"_. Our VM shall be __General Purpose / Debian Bookworm__

    Click __"Create"__

    ![Create VM](https://lupyuen.org/images/dashboard-vm5.png)

1.  Click __"Connect > SSH"__

    ![Connect > SSH](https://lupyuen.org/images/dashboard-vm6.png)

1.  And SSH Console appears! Remember to __Update and Upgrade__ the VM...

    ```bash
    sudo apt update
    sudo apt upgrade
    ```

![SSH Console](https://lupyuen.org/images/dashboard-vm7.png)

Let's populate our new VM...

![Grafana OSS Server](https://lupyuen.org/images/dashboard-flow1.jpg)

# Install Grafana OSS Server

We're ready to install __Grafana OSS Server__! Yep the thingy (pic above) that renders our NuttX Dashboard...

- [__Install Grafana OSS on Debian__](https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/#install-from-apt-repository)

```bash
## Grafana OSS from https://apt.grafana.com (stable)
## Install the prerequisite packages
sudo apt-get install -y apt-transport-https wget

## Import the GPG key
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null

## Add a repository for stable releases
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

## Update the list of available packages
sudo apt-get update

## Install the latest OSS release
sudo apt-get install grafana

## Configure grafana to start automatically using systemd
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable grafana-server

## Start grafana-server
sudo /bin/systemctl start grafana-server

## Grafana Server is listening on http://localhost:3000
## "tcp6 0 0 :::3000 :::* LISTEN"
netstat -an | grep LISTEN
```

_How to access Grafana Server?_

Grafana is listening at __TCP Port 3000__. We create a __Firewall Rule__ to allow incoming packets for Port 3000...

1.  Grab the __External IP Address__ for our VM...

    __VM Instance > External IP__

    ![VM Instance > External IP](https://lupyuen.org/images/dashboard-grafana1.png)

1.  Allow Incoming Packets for TCP Port 3000...

    Click __VM Instance > Set Up Firewall Rules__

    ![VM Instance > Set Up Firewall Rules](https://lupyuen.org/images/dashboard-grafana2.png)

    Click __Firewall Policies > Create Firewall Rule__

    ![Firewall Policies > Create Firewall Rule](https://lupyuen.org/images/dashboard-grafana3.png)

    __Name:__ allow-tcp-3000

    __Targets:__ All instances in the network

    __IPv4 Ranges:__ 0.0.0.0/0

    __Protocol and Ports:__ TCP 3000

    Click __"Create"__

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-grafana4.png)

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-grafana5.png)

    Verify our Firewall Rule...

    ![Verify our Firewall Rule](https://lupyuen.org/images/dashboard-grafana6.png)

1.  Browse to port 3000 of our External IP Address...

    ```bash
    http://x.x.x.x:3000
    ```

    __Username:__ admin

    __Password:__ admin

    ![Grafana Login](https://lupyuen.org/images/dashboard-grafana7.png)

1.  Set the new password

    ![Set the Grafana Password](https://lupyuen.org/images/dashboard-grafana8.png)

1.  And we're in Grafana!

    ![Grafana Home](https://lupyuen.org/images/dashboard-grafana9.png)

Our Grafana Dashboard needs data...

![Prometheus Server](https://lupyuen.org/images/dashboard-flow2.jpg)

# Install Prometheus Server

_Where's the data store for Grafana?_

We'll install [__Prometheus Time-Series Database__](https://lupyuen.org/articles/ci4#prometheus-metrics) (pic above), to record the successful and failed builds of NuttX across all 339 microcontroller boards...

```bash
## From https://ecintelligence.ma/en/blog/complete-guide-to-prometheus-and-grafana-monitorin/
## Install Prometheus Server
sudo apt install prometheus

## Start Prometheus Server on boot
sudo systemctl enable prometheus

## Start Prometheus Server right now
sudo systemctl start prometheus

## Check the status of Prometheus Server
sudo systemctl status prometheus

## We should see...
## ● prometheus.service - Monitoring system and time series database
## Loaded: loaded (/lib/systemd/system/prometheus.service; enabled; preset: enabled)
## Active: active (running)

## Verify that Prometheus is listening on TCP Port 9090
sudo ss -tlnp | grep -E '9090|9100'

## We should see...
## LISTEN 0 4096 *:9090 *:* users:(("prometheus",pid=93392,fd=7))     
## LISTEN 0 4096 *:9100 *:* users:(("prometheus-node",pid=93237,fd=3))

## Later we'll configure Prometheus...
## /etc/prometheus/prometheus.yml
```

To see Prometheus: We create a __Firewall Rule__ to allow incoming access to __TCP Port 9090__...

1.  Click __"VM Instance > Set Up Firewall Rules"__

1.  Click __"Firewall Policies > Create Firewall Rule"__

    __Name:__ allow-tcp-9090

    __Targets:__ All instances in the network

    __IPv4 Ranges:__ 0.0.0.0/0

    __Protocol and Ports:__ TCP 9090

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-prometheus1.png)

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-prometheus2.png)

1.  Click __"Create"__. Verify that Port 9090 is open...

    ![Verify Port 9090](https://lupyuen.org/images/dashboard-prometheus3.png)

1.  Prometheus appears when we browse to Port 9090 of our __External IP Address__...

    ```bash
    http://x.x.x.x:9090
    ```

![Prometheus Web UI](https://lupyuen.org/images/dashboard-prometheus4.png)

_Why Prometheus? Why not SQL Database?_

Remember we got Zero Budget for hosting NuttX Dashboard? Prometheus seems to be the Cheapest Way of hosting Time-Series Data.

![Prometheus Pushgateway](https://lupyuen.org/images/dashboard-flow3.jpg)

# Install Prometheus Pushgateway

_What's this Prometheus Pushgateway?_

Funny Thing about Prometheus: We can't push Time-Series Data to Prometheus Server, and expect it to be stored. Instead we do this...

1.  We install [__Prometheus Pushgateway__](https://lupyuen.org/articles/ci4#prometheus-metrics) (as the in-memory Staging Area for Time-Series Data)

1.  We push our __Time-Series Data__ to Prometheus Pushgateway (over HTTP, pic above)

1.  __Prometheus Server__ shall scrape our Time-Series Data from Pushgateway (and store the data)

Here's how we install __Prometheus Pushgateway__...

```bash
## From https://devopscube.com/setup-prometheus-pushgateway-vm/
wget https://github.com/prometheus/pushgateway/releases/download/v1.11.2/pushgateway-1.11.2.linux-amd64.tar.gz
tar xvf pushgateway-1.11.2.linux-amd64.tar.gz
mv pushgateway-1.11.2.linux-amd64 pushgateway
cd pushgateway/
sudo useradd -rs /bin/false pushgateway
sudo cp pushgateway /usr/local/bin/
sudo chown pushgateway:pushgateway /usr/local/bin/pushgateway

sudo --shell
cat <<EOT > /etc/systemd/system/pushgateway.service
[Unit]
Description=Prometheus Pushgateway
Wants=network-online.target
After=network-online.target

[Service]
User=pushgateway
Group=pushgateway
Type=simple
ExecStart=/usr/local/bin/pushgateway

[Install]
WantedBy=multi-user.target
EOT
exit

sudo systemctl enable pushgateway
sudo systemctl start pushgateway
sudo systemctl status pushgateway

## We should see...
## pushgateway.service - Prometheus Pushgateway
## Loaded: loaded (/etc/systemd/system/pushgateway.service; enabled; preset: enabled)
## Active: active (running) since Mon 2026-01-05 08:46:49 UTC; 4s ago

curl localhost:9091/metrics

## We should see...
## HELP go_gc_duration_seconds A summary of the wall-time pause (stop-the-world) duration in garbage collection cycles.
## TYPE go_gc_duration_seconds summary
```

Prometheus Pushgateway has an Admin UI at __TCP Port 9091__. We grant access...

1.  Click __"VM Instance > Set Up Firewall Rules"__

1.  Click __"Firewall Policies > Create Firewall Rule"__

    __Name:__ allow-tcp-9091

    __Targets:__ All instances in the network

    __IPv4 Ranges:__ 0.0.0.0/0

    __Protocol and Ports:__ TCP 9091

    Click __"Create"__

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-prometheus5.png)

    ![Create Firewall Rule](https://lupyuen.org/images/dashboard-prometheus6.png)

    ![Verify Firewall Rule](https://lupyuen.org/images/dashboard-prometheus7.png)

1.  Prometheus Pushgateway appears on our External IP Address at...

    ```bash
    http://x.x.x.x:9091
    ```

![Prometheus Pushgateway Web UI](https://lupyuen.org/images/dashboard-pushgateway1.png)

# Ingest a Sample NuttX Log

We're all done with installation! Now we ingest some __NuttX Build Logs__ to verify that Prometheus Server and Pushgateway are talking...

```bash
## Download the Sample NuttX Build Log
pushd /tmp
wget https://github.com/lupyuen/ingest-nuttx-builds/releases/download/v1.0.0/defconfig.txt
wget https://github.com/lupyuen/ingest-nuttx-builds/releases/download/v1.0.0/ci-xtensa-02.log
popd

## Install Rust: https://rustup.rs/
## Press Enter for default option
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
sudo apt install gcc pkg-config libssl-dev

## Ingest the Sample NuttX Build Log into Prometheus Pushgateway
sudo apt install git
git clone https://github.com/lupyuen/ingest-nuttx-builds
cd ingest-nuttx-builds
cargo run \
  -- \
  --user NuttX \
  --repo nuttx \
  --defconfig /tmp/defconfig.txt \
  --file /tmp/ci-xtensa-02.log \
  --nuttx-hash 59f200ac4fe6c940dc0eab2155bb3cb566724082 \
  --apps-hash 4f93ec0a4335d574eeecfd295584fbfb17056e5b \
  --group xtensa-02 \
  --run-id 20706016275 \
  --job-id 59436813170 \
  --step 10

## We should see...
## lines[0]=Configuration/Tool: esp32s3-devkit/spi
## lines.last=  [1/1] Normalize esp32s3-devkit/spi
## target=esp32s3-devkit:spi
## timestamp=2026-01-05T08:39:57
## body=
## # TYPE build_score gauge
## # HELP build_score 1.0 for successful build, 0.0 for failed build
## build_score{ version="3", timestamp="2026-01-05T08:39:57", timestamp_log="2026-01-05T08:39:57", user="NuttX", arch="xtensa", subarch="esp32s3", group="xtensa-02", board="esp32s3-devkit", config="spi", target="esp32s3-devkit:spi", url="https://github.com/NuttX/nuttx/actions/runs/20706016275/job/59436813170#step:10:2455", url_display="", nuttx_hash="59f200ac4fe6c940dc0eab2155bb3cb566724082", apps_hash="4f93ec0a4335d574eeecfd295584fbfb17056e5b" } 1
## res=Response { url: "http://localhost:9091/metrics/job/NuttX/instance/esp32s3-devkit:spi", status: 200, headers: {"date": "Mon, 05 Jan 2026 10:10:52 GMT", "content-length": "0"} }
```

Browse to Prometheus Pushgateway at our __External IP Address__, port 9091. We'll see the __NuttX Build Logs__ that we have ingested...

```bash
http://x.x.x.x:9091
```

![Prometheus Pushgateway shows NuttX Build Logs](https://lupyuen.org/images/dashboard-pushgateway2.png)

We configure __Prometheus Server__ to talk to Pushgateway...

```bash
## Edit the Prometheus Server Config
sudo nano /etc/prometheus/prometheus.yml

## Erase everything in the file. Replace by contents of
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml

## Restart our Prometheus Server
sudo systemctl restart prometheus

## Which will scrape the Metrics from Prometheus Pushgateway every 15 seconds...
## global:
##   scrape_interval: 15s
## scrape_configs:
##   - job_name: "prometheus"
##     static_configs:
##     - targets: ["localhost:9090"]
##   - job_name: "pushgateway"
##     static_configs:
##     - targets: ["localhost:9091"]
```

__Wait One Minute:__ Prometheus Server shall scrape and store the Ingested Build Logs from Pushgateway.

Browse to Prometheus Server at our __External IP Address__, port 9090...

```bash
http://x.x.x.x:9090
```

Enter this Prometheus Query...

```bash
build_score
```

And click __"Execute"__. Yep Prometheus Server has successfully scraped and stored the __NuttX Build Logs__ from Pushgateway yay!

![Prometheus Server has successfully scraped and stored the NuttX Build Logs from Pushgateway](https://lupyuen.org/images/dashboard-pushgateway3.png)

# Connect Grafana to Prometheus

_How will Grafana Dashboard talk to our Prometheus Database?_

1.  Inside Grafana: Click __"Menu > Data Sources > Prometheus"__.

1.  Set the __Prometheus Server URL__ to...

    ```bash
    http://localhost:9090
    ```

    ![Prometheus Data Source](https://lupyuen.org/images/ci4-datasource.png)

1.  Click __"Dashboards > New > New Dashboard"__

    ![Dashboards > New > New Dashboard](https://lupyuen.org/images/ci4-grafana3.png)

1.  Click __"Settings > JSON Model"__

    Copy and overwrite the Dashboard JSON from here: [__dashboard.json__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard.json)

    ![Settings > JSON Model](https://lupyuen.org/images/dashboard-json1.png)

1.  But change ALL references to __Prometheus UID__...

    ```json
    ...
    "datasource": {
      "type": "prometheus",
      "uid": "df998a9io0yrkb"
    }
    ...
    ```

    (Get the UID from the Dashboard JSON before overwriting it)

1.  Allow everyone to view: Click __"Settings > Add Permission > Role > Viewer > View"__

    ![Settings > Add Permission > Role > Viewer > View](https://lupyuen.org/images/dashboard-json5.png)

1.  Save the dashboard. That's our First Dashboard: __"Build Logs Dashboard"__

    ![Build Logs Dashboard](https://lupyuen.org/images/dashboard-json2.png)

1.  Once Again: Click __"Dashboards > New > New Dashboard"__

    ![Dashboards > New > New Dashboard](https://lupyuen.org/images/ci4-grafana3.png)

1.  Click __"Settings > JSON Model"__

    Copy and overwite the Dashboard History JSON from here: [__dashboard-history.json__](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard-history.json)

    ![TSettings > JSON ModelODO](https://lupyuen.org/images/dashboard-json3.png)

1.  But change ALL references to __Prometheus UID__...

    ```json
    ...
    "datasource": {
      "type": "prometheus",
      "uid": "df998a9io0yrkb"
    }
    ...
    ```

    (Get the UID from the Dashboard JSON before overwriting it)

1.  Allow everyone to view: Click __"Settings > Add Permission > Role > Viewer > View"__

    ![Settings > Add Permission > Role > Viewer > View](https://lupyuen.org/images/dashboard-json6.png)

1.  Save the dashboard. That's our Second and Final Dashboard: __"NuttX Build History Dashboard"__

    ![NuttX Build History Dashboard](https://lupyuen.org/images/dashboard-json4.png)

Let's integrate our dashboard with GitHub Actions...

![Ingest the GitHub Actions Logs](https://lupyuen.org/images/dashboard-flow4.jpg)

# Set the GitHub Token

_What's this GitHub Token?_

Our VM shall download and ingest the __GitHub Actions Logs__. This requires a GitHub Token to access the GitHub Actions Logs.

Inside our VM: Create _$HOME/github-token.sh_ and fill in the __GitHub Token__. Any Plain GitHub Account will do (like _nuttxpr_). Don't use an Admin Account!

```bash
## GitHub Settings > Developer Settings > Tokens (Classic) > Generate New Token (Classic)
## Check the following:
## repo (Full control of private repositories)
## repo:status (Access commit status)
## repo_deployment (Access deployment status)
## public_repo (Access public repositories)
## repo:invite (Access repository invitations)
## security_events (Read and write security events)
export GITHUB_TOKEN=...

## Enable Rust Logging
export RUST_LOG=info 
export RUST_BACKTRACE=1
```

If we're ingesting [__GitLab Snippets__](https://lupyuen.org/articles/ci2#build-nuttx-for-all-target-groups): Create _$HOME/gitlab-token.sh_ and fill in the __GitLab Token__...

```bash
## User Settings > Access tokens
## Select scopes:
## api: Grants complete read/write access to the API, including all groups and projects, the container registry, the dependency proxy, and the package registry.
export GITLAB_TOKEN=...
export GITLAB_USER=lupyuen
export GITLAB_REPO=nuttx-build-log
```

Make sure that _nuttxpr_ has __Push Permission__ for NuttX Mirror Repo...

- [__"NuttX Mirror Repo"__](https://lupyuen.org/articles/dashboard#appendix-nuttx-mirror-repo)

![Ingest the GitHub Actions Logs](https://lupyuen.org/images/dashboard-flow4.jpg)

# Ingest the GitHub Actions Logs

We have a [__NuttX Mirror Repo__](https://github.com/NuttX/nuttx) _(github.com/NuttX/nuttx)_ that will run [__Daily Builds of NuttX__](https://lupyuen.org/articles/ci3#move-the-merge-jobs) across all 339 microcontroller boards.

Let's ingest the __GitHub Actions Logs__ (pic above) from the Mirror Repo Builds. Inside our VM: Do this...

```bash
## Install GitHub CLI: https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian
(type -p wget >/dev/null || (sudo apt update && sudo apt install wget -y)) \
  && sudo mkdir -p -m 755 /etc/apt/keyrings \
  && out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  && cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
  && sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
  && sudo mkdir -p -m 755 /etc/apt/sources.list.d \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
  && sudo apt update \
  && sudo apt install gh -y
. $HOME/github-token.sh
gh auth status

## We should see...
## ✓ Logged in to github.com account nuttxpr (GITHUB_TOKEN)
## - Active account: true
## - Git operations protocol: https
## - Token: ghp_************************************
## - Token scopes: 'read:org', 'repo'

## github.sh needs the NuttX defconfigs here (yeah we should fix the hardcoded "riscv")
mkdir $HOME/riscv
pushd $HOME/riscv
git clone https://github.com/apache/nuttx
popd

## Ingest the GitHub Actions Logs
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh
sudo apt install unzip
cd
git clone https://github.com/lupyuen/ingest-nuttx-builds
cd ingest-nuttx-builds
./github.sh
```

[(See the log for github.sh)](https://gist.github.com/lupyuen/8cf82eab994c2bca77f129ffa118acf0)

1.  Check __Prometheus Pushgateway__ at our External IP Address, port 9091. We should see the logs ingested from GitHub Actions...

    ```bash
    http://x.x.x.x:9091
    ```

    ![Prometheus Pushgateway shows the logs ingested from GitHub Actions](https://lupyuen.org/images/dashboard-ingest1.png)

1.  Check __Prometheus Server__ at our External IP Address, port 9090. Enter the Prometheus Query __"build_score"__, click __Execute__. We'll see the same logs...

    ```bash
    http://x.x.x.x:9090
    ```

    ![Prometheus Server shows the logs ingested from GitHub Actions](https://lupyuen.org/images/dashboard-ingest2.png)

    __Bonus:__ This query will reveal that NuttX has 339 microcontroller boards: __"count by (board) (build_score)"__

    TODO: Pic of 339 boards

1.  Check __Grafana Dashboard__ at our External IP Address, port 3000. We'll see the GitHub Actions Logs...

    ```bash
    http://x.x.x.x:3000/d/fe2bqg6uk7nr4a
    ```

    ![Grafana Dashboard shows the logs ingested from GitHub Actions](https://lupyuen.org/images/dashboard-ingest3.png)

1.  Finally check the __Build History__

    ```bash
    http://x.x.x.x:3000/d/fe2q876wubc3kc
    ```

    ![Build History Dashboard](https://lupyuen.org/images/dashboard-ingest4.png)

# Start the NuttX Mirror Build

_What triggers the Daily Build at NuttX Mirror Repo?_

Our script _sync-build-ingest.sh_ will trigger the __Daily Build__, followed by the ingestion of the GitHub Actions Logs.

Only one instance of _sync-build-ingest.sh_ should ever be running! Make sure _lupyuen_ isn't running it on his Home Computer.

Inside our VM: Do this...

```bash
## Set the GitHub Token
. $HOME/github-token.sh
gh auth status

## We should see...
## ✓ Logged in to github.com account nuttxpr (GITHUB_TOKEN)
## - Active account: true
## - Git operations protocol: https
## - Token: ghp_************************************
## - Token scopes: 'read:org', 'repo'

## Configure the Git User
git config --global user.email "nuttxpr@gmail.com"
git config --global user.name "nuttxpr (nuttx-dashboard-vm)"

## Start the NuttX Mirror Build and ingest the logs from GitHub Actions
## https://github.com/lupyuen/nuttx-release/blob/main/sync-build-ingest.sh
cd
git clone https://github.com/lupyuen/nuttx-release
cd $HOME/nuttx-release
./sync-build-ingest.sh

## If we see: "**** ERROR: Expected Downstream Commit to be 'Enable macOS Builds' but found: ..."
## Then run this instead:
## ./enable-macos-windows.sh
## ./sync-build-ingest.sh
```

[(Log for sync-build-ingest.sh)](https://gist.github.com/lupyuen/c9dd83842ab9b845eadedb968bd63bc1)

[(Log for enable-macos-windows.sh)](https://gist.github.com/lupyuen/3d21869dae705d6c9d3acc1e8d94ffd1)

We'll see the __"Enable macOS Patch"__ that starts the NuttX Build...

```bash
https://github.com/NuttX/nuttx/commits/master/
```

![Enable macOS Patch](https://lupyuen.org/images/dashboard-github15.png)

And the __NuttX Build__ should be running...

```bash
https://github.com/NuttX/nuttx/actions/workflows/build.yml
```

![NuttX Build should be running](https://lupyuen.org/images/dashboard-github16.png)

In case of sync problems: Go to [github.com/NuttX/nuttx](https://github.com/NuttX/nuttx/tree/master), click __"Sync Fork > Update Branch (or Discard Commit)"__ (pic below). Then run _enable-macos-windows.sh_ followed by _sync-build-ingest.sh_.

![Sync Fork > Update Branch (or Discard Commit)](https://lupyuen.org/images/dashboard-github7.png)

If we see this error...

```bash
fatal: cannot create directory at 'arch/arm/src/kinetis': No space left on device
warning: Clone succeeded, but checkout failed.
```

Then increase the Disk Space, we need 5 GB for _/tmp_...

- [__"Expand the VM Disk"__](https://lupyuen.org/articles/dashboard#appendix-expand-the-vm-disk)

# Forever Build and Ingest

Everything We've Done for NuttX Build and Ingest: Needs to be looped forever. Edit _$HOME/sync.sh_ and fill this in...

```bash
#!/usr/bin/env bash
## Sync NuttX Mirror, Build NuttX Mirror and Ingest GitHub Actions Logs

set -x  #  Echo commands
. $HOME/github-token.sh
gh auth status

for (( ; ; )); do
  cd $HOME/nuttx-release
  ./sync-build-ingest.sh

  set +x ; echo "**** sync.sh: Waiting" ; set -x
  date ; sleep 900
done
```

Whenever our VM Boots: Run _$HOME/sync.sh_...

```bash
## Don't use cron, need to monitor manually so that
## we don't overuse the GitHub Runners of the Mirror Repo
sudo apt install tmux
tmux
chmod +x $HOME/sync.sh
$HOME/sync.sh

## If the SSH Session Disconnects:
## Do this to reconnect the sync.sh session...
## tmux a
```

[(Log for NuttX Build and Ingest)](https://github.com/lupyuen/nuttx-release/releases/download/v1.0.0/sync.log)

__One More Step:__ We need to ingest the GitHub Gists and GitLab Snippets...

- [__"Ingest the GitHub Gists"__](https://lupyuen.org/articles/dashboard#appendix-ingest-the-github-gists)

__In Case of Sync Problems:__ Go to [_github.com/NuttX/nuttx_](https://github.com/NuttX/nuttx), click __"Sync Fork > Discard Commit"__. Then run _enable-macos-windows.sh_ followed by _sync.sh_. _(Hmmm this seems to happen often in our VM. Why?)_

# Secure Our Grafana Server

We're ready to Go Live! We tweak some Grafana Settings to make NuttX Dashboard more secure.

Inside our VM: Edit _/etc/grafana/grafana.ini_. Look for these settings and change them (don't add them)

```bash
# Default UI theme ("dark", "light" or "system")
# Default: default_theme = dark
default_theme = light

# Path to a custom home page. Users are only redirected to this if the default home dashboard is used. It should match a frontend route and contain a leading slash.
# Default: home_page =
home_page = /d/fe2bqg6uk7nr4a

# Disable usage of Grafana build-in login solution.
# Default: disable_login = false
disable_login = true

# Set to true to disable (hide) the login form, useful if you use OAuth, defaults to false
disable_login_form = true

# enable anonymous access
# Default: enabled = false
enabled = true

# specify organization name that should be used for unauthenticated users
org_name = Main Org.

# specify role for unauthenticated users
org_role = Viewer

# mask the Grafana version number for unauthenticated users
# Default: hide_version = false
hide_version = true
```

[(See the modified grafana.ini)](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/grafana2.ini)

Restart Grafana...

```bash
sudo systemctl restart grafana-server
```

Publish online our NuttX Dashboard with Cloudflare Tunnel or another CDN...

- [__"Publish Online with Cloudflare"__](https://lupyuen.org/articles/dashboard#appendix-publish-online-with-cloudflare)


![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

NuttX Dashboard is ready to serve. Yay!

![Cost of Google Cloud VM](https://lupyuen.org/images/dashboard-cost1.png)

# Cost of Google Cloud

_Hosting our dashboard on Google Cloud: Is it expensive?_

NuttX Dashboard on __Google Cloud VM__ (pic above) is costing us...

- __USD 1.24__ per day

- __USD 38__ per month

- __USD 453__ per year

Since we have __Zero Budget__ for NuttX Dashboard: We'll pay this out of our own pocket.

![Google recommends that we bump up the VM Capacity, increasing 16 SGD per month. Yikes!](https://lupyuen.org/images/dashboard-cost2.png)

_How's our VM Utilisation?_

Our VM runs continuously at __50% CPU__ (pic above), forever busy ingesting the NuttX Build Logs.

Google recommends that we bump up the VM Capacity, __increasing USD 16__ per month. Yikes!

_Will it be cheaper on an Asian Cloud? Like AliCloud?_

Hmmm interesting... We should [__try it sometime__](https://web.archive.org/web/20191204194108/https://medium.com/@ly.lee/first-impressions-of-alibaba-cloud-aliyun-688dc46fa9b8?source=friends_link&sk=0685f5028f4ce9575dfae9cc9515143d)!

# What's Next

Now that NuttX Dashboard is running in the Cloud (and not at Home)... We're going overseas for [__Twincity Marathon__](https://lupyuen.org/articles/marathon#whats-next)!

_Anything else we're running on our Home Computer?_

TODO: Yeah sadly these home-based __NuttX Monitoring Jobs__ will probably stop running while we're overseas for Marathon Races...

nuttx-metrics

riscv64

avaota-a1, starpro64, oz64

mastodon, forgejo

_Running the Build Farm on Google Cloud?_

TODO: Noooo.... Too expensive! We'll run a Second-Hand Ubuntu Xeon Server.

![NuttX Mirror Repo](https://lupyuen.org/images/dashboard-flow4.jpg)

# Appendix: NuttX Mirror Repo

_What triggers the Daily Build at NuttX Mirror Repo?_

Our script _sync-build-ingest.sh_ will trigger the __Daily Build__, followed by the ingestion of the GitHub Actions Logs.

Inside the script: Our Regular GitHub Account _nuttxpr_ will start the build by pushing a patch to the NuttX Mirror Repo (pic above). This is how we grant the __Push Permission__ to _nuttxpr_...

1.  Browse to the Collaborators for NuttX Mirror Repo

    ```bash
    https://github.com/NuttX/nuttx/settings/access
    ```

1.  Click __"Add People"__

    Enter __nuttxpr__

    ![Add People](https://lupyuen.org/images/dashboard-github8.png)

1.  Set the Role to __"Write"__

    ![Set the Role to "Write"](https://lupyuen.org/images/dashboard-github9.png)

    ![Set the Role to "Write"](https://lupyuen.org/images/dashboard-github10.png)

1.  Log in as _nuttxpr_ to accept the invitation

    ![Accept the invitation](https://lupyuen.org/images/dashboard-github11.png)

    ![Accept the invitation](https://lupyuen.org/images/dashboard-github12.png)

    ![Accept the invitation](https://lupyuen.org/images/dashboard-github13.png)

1.  Check that _nuttxpr_ has become a collaborator

    ```bash
    https://github.com/NuttX/nuttx/settings/access
    ```

    ![Check collaborators](https://lupyuen.org/images/dashboard-github14.png)

![Ingest the GitHub Gists](https://lupyuen.org/images/dashboard-flow5.jpg)

# Appendix: Ingest the GitHub Gists

_What's with the GitHub Gists and GitLab Snippets?_

We have a [__NuttX Build Farm__](https://lupyuen.org/articles/ci2) hosted at home (pic above). Our Build Farm will build NuttX all day, and record the __Build Logs__ into GitHub Gists or GitLab Snippets. We run the script below to ingest the Build Logs into NuttX Dashboard. [(Remember to set GitLab Token)](https://lupyuen.org/articles/dashboard#set-the-github-token)

Whenever our VM Boots: Do this...

```bash
## Ingest the GitHub Gists and GitLab Snippets
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/run.sh
tmux
cd $HOME/ingest-nuttx-builds
./run.sh

## If the SSH Session Disconnects:
## Do this to reconnect the run.sh session...
## tmux a

## Don't use cron, need to monitor manually so that we don't 
## overuse the GitHub API and GitLab API
```

[(Log for ingest-nuttx-builds/run.sh)](https://gist.github.com/lupyuen/d29be01f9e5ad256c6bb6df1e1ddea6d)

![SSH Key for GitHub](https://lupyuen.org/images/dashboard-flow4.jpg)

# Appendix: SSH Key for GitHub

_What triggers the Daily Build at NuttX Mirror Repo?_

Our script _sync-build-ingest.sh_ will trigger the __Daily Build__, followed by the ingestion of the GitHub Actions Logs.

Inside the script: Our Regular GitHub Account _nuttxpr_ will start the build by pushing a patch to the NuttX Mirror Repo (pic above). This is how we create an SSH Key for GitHub that will allow _nuttxpr_ to push the patch...

(_nuttxpr_ is an Ordinary GitHub Account with Read Access. Don't use a GitHub Admin Account!)

1.  Inside our VM: Create the __GitHub SSH Key__

    ```bash
    ## From https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent
    ssh-keygen \
      -t ed25519 \
      -f $HOME/.ssh/nuttxpr@github \
      -C "nuttxpr@github"
    ```

1.  Add the SSH Key to GitHub Account

    [__Follow the steps here__](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)

    Copy from our Public Key at _$HOME/.ssh/nuttxpr@github.pub_, paste into to GitHub

1.  Test the SSH Key

    ```bash
    ssh -T \
      -i $HOME/.ssh/nuttxpr@github \
      git@github.com

    ## We should see...
    ## Hi nuttxpr! You've successfully authenticated, but GitHub does not provide shell access.
    ```

1.  Add the SSH Key to our SSH Config. Edit _$HOME/.ssh/config_

    ```bash
    nano $HOME/.ssh/config
    ```

    Add this...

    ```bash
    Host github.com
      IdentityFile ~/.ssh/nuttxpr@github
    ```

1.  Test our updated SSH Config

    ```bash
    ## Should now work without stating Private Key
    ssh -T \
      git@github.com

    ## We should see...
    ## Hi nuttxpr! You've successfully authenticated, but GitHub does not provide shell access.
    ```

# Appendix: SSH Key for VM Login

Connecting to our VM gets tedious. Let's create an __SSH Key for VM Login__...

1.  Create the SSH Key on __Our Computer__ (NOT the VM)

    ```bash
    ## From https://docs.cloud.google.com/compute/docs/connect/create-ssh-keys
    ## Do this on our computer, NOT the VM!
    ## Change "luppy" to your VM Username
    ssh-keygen \
      -t rsa \
      -f $HOME/.ssh/nuttx-dashboard-vm \
      -C luppy

    ## Check the output
    ls $HOME/.ssh/nuttx-dashboard-vm*

    ## We should see...
    ## nuttx-dashboard-vm
    ## nuttx-dashboard-vm.pub
    ```

1.  Add the SSH Public Key to our VM...

    [__Follow the steps here__](https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys?cloudshell=false#metadata)

    Browse to __"Google Cloud Console > Metadata"__
    
    ```bash
    https://console.cloud.google.com/compute/metadata
    ```

    ![Google Cloud Console > Metadata](https://lupyuen.org/images/dashboard-ssh1.png)

    Click __"SSH Keys > Add SSH Key"__

    ![SSH Keys > Add SSH Key](https://lupyuen.org/images/dashboard-ssh2.png)

    Copy and paste the contents of our Public Key: _$HOME/.ssh/nuttx-dashboard-vm.pub_

    ![Copy and paste the Public Key](https://lupyuen.org/images/dashboard-ssh3.png)

    Click __"Save"__

    ![Save the SSH Key](https://lupyuen.org/images/dashboard-ssh4.png)

1.  Test the SSH Key with VM Login

    ```bash
    ## From https://docs.cloud.google.com/compute/docs/connect/standard-ssh#openssh-client
    ## Change "luppy" to your VM Username
    ssh \
      -i $HOME/.ssh/nuttx-dashboard-vm \
      luppy@x.x.x.x
    ```

# Appendix: Remote Connect in VSCode

_Is there an easier way to work with our VM?_

Yep use a __SSH Remote Connection in VSCode__!

1.  Assume that we have added an SSH Key for VM Login...

    [__"SSH Key for VM Login"__](https://lupyuen.org/articles/dashboard#appendix-ssh-key-for-vm-login)

1.  In VSCode: Click __"Remote Explorer > SSH > +"__

    ![Remote Explorer > SSH > +](https://lupyuen.org/images/dashboard-ssh5.png)

1.  Enter the SSH Command

    ```bash
    ssh -i ~/.ssh/nuttx-dashboard-vm luppy@x.x.x.x 
    ```

    ![SSH Command](https://lupyuen.org/images/dashboard-ssh6.png)

1.  Select the SSH Config file _$HOME/.ssh/config_

    Click __"Connect"__

    To open a Remote File or Remote Folder: Click __"File > Open File / Folder"__

    ![File > Open File / Folder](https://lupyuen.org/images/dashboard-ssh7.png)

_$HOME/.ssh/config_ will look like:

```bash
Host x.x.x.x
  HostName x.x.x.x
  IdentityFile ~/.ssh/nuttx-dashboard-vm
  User luppy
```

Probably better to rename the "Host", in case the IP Address changes...

```bash
Host nuttx-dashboard-vm
  HostName x.x.x.x
  IdentityFile ~/.ssh/nuttx-dashboard-vm
  User luppy
```

![Should rename the Host](https://lupyuen.org/images/dashboard-ssh8.png)

TODO: Port forward pic

# Appendix: Expand the VM Disk

By Default: Google Cloud allocates __10 GB of Disk Space__...

```bash
$ df -H
Filesystem      Size  Used Avail Use% Mounted on
udev            2.1G     0  2.1G   0% /dev
tmpfs           412M  574k  411M   1% /run
/dev/sda1        11G  8.5G  1.4G  87% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M     0  5.3M   0% /run/lock
/dev/sda15      130M   13M  118M  10% /boot/efi
tmpfs           412M     0  412M   0% /run/user/1000
```

But _/tmp_ and _/dev/sda1_ will __Run Out of Disk Space__ while ingesting NuttX Build Logs...

```bash
## Out of space in /tmp
$ df -H
Filesystem      Size  Used Avail Use% Mounted on
udev            2.1G     0  2.1G   0% /dev
tmpfs           412M  574k  411M   1% /run
/dev/sda1        11G  9.8G     0 100% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M     0  5.3M   0% /run/lock
/dev/sda15      130M   13M  118M  10% /boot/efi
tmpfs           412M     0  412M   0% /run/user/1000

## Most of the disk space used by /tmp
$ rm -rf /tmp/sync-build-ingest/
```

This is how we [__Expand the VM Disk__](https://dev.to/lovestaco/expanding-disk-size-in-google-cloud-5gkh), from 10 GB to 20 GB...

1.  Click __"VM > Details > Storage > Boot Disk"__

    ![VM > Details > Storage > Boot Disk](https://lupyuen.org/images/dashboard-disk1.png)

1.  Click __"Menu > Edit"__ (Top Right)

    ![Menu > Edit](https://lupyuen.org/images/dashboard-disk2.png)

1.  Increase the size from 10 GB to 20 GB. Click __Save__

    ![Increase the size from 10 GB to 20 GB](https://lupyuen.org/images/dashboard-disk3.png)

1.  Inside our VM: Do this...

    ```bash
    sudo apt install fdisk
    sudo fdisk -l

    ## We should see
    ## Device      Start      End  Sectors  Size Type
    ## /dev/sda1  262144 20969471 20707328  9.9G Linux root (x86-64)
    ## /dev/sda14   2048     8191     6144    3M BIOS boot
    ## /dev/sda15   8192   262143   253952  124M EFI System

    ## Let's expand /dev/sda to 20 GB
    sudo fdisk /dev/sda

    ## Ignore the warning
    ## Enter: w

    ## Resize partition 1 (/dev/sda1), which maps to /
    sudo apt install cloud-guest-utils
    sudo growpart /dev/sda 1

    ## We should see...
    ## CHANGED: partition=1 start=262144 old: size=20707328 end=20969471 new: size=41680863 end=41943006

    ## Resize the Filesystem
    sudo resize2fs /dev/sda1

    ## We should see...
    ## Filesystem at /dev/sda1 is mounted on /; on-line resizing required
    ## old_desc_blocks = 2, new_desc_blocks = 3
    ## The filesystem on /dev/sda1 is now 5210107 (4k) blocks long.

    ## sda1 is bigger now
    $ sudo fdisk -l
    Device      Start      End  Sectors  Size Type
    /dev/sda1  262144 41943006 41680863 19.9G Linux root (x86-64)
    /dev/sda14   2048     8191     6144    3M BIOS boot
    /dev/sda15   8192   262143   253952  124M EFI System

    ## More space in /tmp yay!
    $ df -H
    Filesystem      Size  Used Avail Use% Mounted on
    udev            2.1G     0  2.1G   0% /dev
    tmpfs           412M  574k  411M   1% /run
    /dev/sda1        21G  8.5G   12G  43% /
    tmpfs           2.1G     0  2.1G   0% /dev/shm
    tmpfs           5.3M     0  5.3M   0% /run/lock
    /dev/sda15      130M   13M  118M  10% /boot/efi
    tmpfs           412M     0  412M   0% /run/user/1000
    ```

# Appendix: Publish Online with Cloudflare

_Our VM is running. How do we actually publish it at a Web URL?_

Here are two ways...

- Option One: We publish it with a __Cloudflare Tunnel__

- Option Two: We publish to __Any CDN__

__Option One: Cloudflare Tunnel__

1.  We create a Cloudflare Tunnel, pointing to...

    ```bash
    http://localhost:3000
    ```

    ![Cloudflare Tunnel](https://lupyuen.org/images/dashboard-cloudflare2.png)

    ![Cloudflare Tunnel](https://lupyuen.org/images/dashboard-cloudflare1.png)

    ![Cloudflare Tunnel](https://lupyuen.org/images/dashboard-cloudflare3.png)

1.  Remember to set the cache...

    Set __"Cache URI Path > Wildcard > Value"__ to...

    ```bash
    /public/*
    ```

    ![Cloudflare Cache](https://lupyuen.org/images/dashboard-cloudflare12.png)

    ![Cloudflare Cache](https://lupyuen.org/images/dashboard-cloudflare13.png)

__Option Two: Cloudflare CDN__

1.  Remember that Grafana listens at __Port 3000__? We configure __iptables__ to route incoming packets from __Port 80 to Port 3000__...

    ```bash
    ## https://askubuntu.com/questions/444729/redirect-port-80-to-8080-and-make-it-work-on-local-machine

    $ sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3000

    $ sudo iptables -t nat -L -n -v

    Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination         
        0     0 REDIRECT   6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 redir ports 3000

    ## To delete the rule:
    ## sudo iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3000
    ```

1.  Configure our __VM Firewall__ to allow HTTP traffic...

    Click __"VM > Edit > Dynamic Network Interfaces > Allow HTTP traffic"__

    ![VM > Edit > Dynamic Network Interfaces > Allow HTTP traffic](https://lupyuen.org/images/dashboard-cloudflare8.png)

    ![VM > Edit > Dynamic Network Interfaces > Allow HTTP traffic](https://lupyuen.org/images/dashboard-cloudflare9.png)

    ![VM > Edit > Dynamic Network Interfaces > Allow HTTP traffic](https://lupyuen.org/images/dashboard-cloudflare10.png)

1.  Why does this work? That's because there's a Default Firewall Rule __"default-allow-http"__ that wil allow incoming TCP Port 80, whenever the Target Tag matches __"http_server"__...

    ![Default Firewall Rule "default-allow-http" allows incoming TCP Port 80, whenever the Target Tag matches "http_server"](https://lupyuen.org/images/dashboard-cloudflare11.png)

1.  Check that our __External IP Address__ is now accessible via HTTP Port 80:

    ```bash    
    http://x.x.x.x
    ```

1.  Under Cloudflare DNS: Create an __"A Record"__ that points to our External IP Address.

    Remember to __Enable the HTTP Proxy__.

    (Actually we should get a __Static IP Address__ for our VM)

    ![Create the "A Record" for DNS](https://lupyuen.org/images/dashboard-cloudflare4.png)

1.  And our NuttX Dashboard is live on the web!

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)
