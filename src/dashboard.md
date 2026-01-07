# Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS

📝 _20 Feb 2025_

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

TODO

# Create Our Virtual Machine

Create Project: nuttx-dashboard

https://console.cloud.google.com/projectcreate

Click "Select Project"

Click "Create a VM". General Purpose / Debian Bookworm is OK.

Click "Compute Engine API > Enable" and wait a while

Fill in the Instance Name "nuttx-dashboard-vm". Click "Create"

Click "Connect > SSH"

And SSH Console appears!

```bash
Linux nuttx-dashboard-vm 6.1.0-41-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.158-1 (2025-11-09) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
luppy@nuttx-dashboard-vm:~$ uname -a
Linux nuttx-dashboard-vm 6.1.0-41-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.158-1 (2025-11-09) x86_64 GNU/Linux
luppy@nuttx-dashboard-vm:~$ 

sudo apt update
sudo apt upgrade
```

# Install Grafana

Install the latest version of Grafana OSS

https://grafana.com/grafana/download/12.3.0?pg=oss-graf&plcmt=hero-btn-1&edition=oss

https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/#install-from-apt-repository

```bash
## Grafana OSS	grafana	https://apt.grafana.com stable main
## Install the prerequisite packages
sudo apt-get install -y apt-transport-https wget

## Import the GPG key
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null

## Add a repository for stable releases
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

## Updates the list of available packages
sudo apt-get update

## Installs the latest OSS release
sudo apt-get install grafana

## Configure grafana to start automatically using systemd
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable grafana-server

## Start grafana-server
sudo /bin/systemctl start grafana-server

## Grafana Server is listening on http://localhost:3000
$ netstat -an | grep LISTEN
tcp6       0      0 :::3000                 :::*                    LISTEN     
```

VM Instances > External IP
35.198.238.211

VM Instances > Set Up Firewall Rules

Firewall Policies > Create Firewall Rule

allow-tcp-3000

Targets: All instances in the network

IPv4 Ranges: 0.0.0.0/0

Protocol and Ports: TCP 3000

Click "Create"

http://35.198.238.211:3000

Username: admin
Password: admin
Set the new password

# Install Prometheus

```bash
## From https://ecintelligence.ma/en/blog/complete-guide-to-prometheus-and-grafana-monitorin/
## Install Prometheus server
sudo apt install prometheus

## Enable services to start on boot
sudo systemctl enable prometheus

## Start services
sudo systemctl start prometheus

## Check service status
sudo systemctl status prometheus

## We should see...
## ● prometheus.service - Monitoring system and time series database
## Loaded: loaded (/lib/systemd/system/prometheus.service; enabled; preset: enabled)
## Active: active (running)

## Check listening ports
sudo ss -tlnp | grep -E '9090|9100'

## We should see...
## LISTEN 0      4096               *:9090             *:*    users:(("prometheus",pid=93392,fd=7))     
## LISTEN 0      4096               *:9100             *:*    users:(("prometheus-node",pid=93237,fd=3))
```

VM Instances > Set Up Firewall Rules

Firewall Policies > Create Firewall Rule

allow-tcp-9090

Targets: All instances in the network

IPv4 Ranges: 0.0.0.0/0

Protocol and Ports: TCP 9090

Click "Create"

http://35.198.238.211:9090

The main configuration file is located at /etc/prometheus/prometheus.yml

# Install Pushgateway

https://devopscube.com/setup-prometheus-pushgateway-vm/

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

VM Instances > Set Up Firewall Rules

Firewall Policies > Create Firewall Rule

allow-tcp-9091

Targets: All instances in the network

IPv4 Ranges: 0.0.0.0/0

Protocol and Ports: TCP 9091

Click "Create"

http://35.198.238.211:9091

# Ingest a Sample NuttX Log

```bash
pushd /tmp
wget https://github.com/lupyuen/ingest-nuttx-builds/releases/download/v1.0.0/defconfig.txt
wget https://github.com/lupyuen/ingest-nuttx-builds/releases/download/v1.0.0/ci-xtensa-02.log
popd

## Install rust: https://rustup.rs/
## Press Enter for default option
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
sudo apt install gcc pkg-config libssl-dev

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

Check http://35.198.238.211:9091

TODO: Connect prometheus to pushgateway

```bash
sudo nano /etc/prometheus/prometheus.yml
## Erase everything in the file. Replace by contents of
## https://github.com/lupyuen/ingest-nuttx-builds/blob/main/prometheus.yml
sudo systemctl restart prometheus
```

Check http://35.198.238.211:9090

Enter the query "build_score"

Press Execute

# Connect Grafana to Prometheus

Follow these steps to create the dashboard (skip the `apt install`):

[Grafana Dashboard](https://lupyuen.org/articles/ci4#grafana-dashboard)

Add Data Source: https://lupyuen.org/articles/ci4#appendix-all-builds-dashboard

Copy and overwrite the Dashboard JSON: https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard.json

But change ALL references to Prometheus UID:

```json
...
"datasource": {
  "type": "prometheus",
  "uid": "df998a9io0yrkb"
}
...
```

(Get the UID from the Dashboard JSON before overwriting it)

Copy and overwite the Dashboard History JSON: https://github.com/lupyuen/ingest-nuttx-builds/blob/main/dashboard-history.json

Remember to change ALL references to Prometheus UID. (See above)

# SSH Key for VM Login

Create SSH Key: https://docs.cloud.google.com/compute/docs/connect/create-ssh-keys

```bash
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

Install the GCloud CLI: https://docs.cloud.google.com/sdk/docs/install-sdk

```bash
## For macOS:
brew install gcloud-cli
export PATH=/opt/homebrew/share/google-cloud-sdk/bin:"$PATH"
gcloud version
## We should see: Google Cloud SDK 550.0.0
```

Add SSH keys to VMs that use metadata-based SSH keys: https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys?cloudshell=false#metadata

Google Cloud Console: Metadata: https://console.cloud.google.com/compute/metadata

Click "SSH Keys"

Click "Add SSH Key"

Copy and paste the contents of $HOME/.ssh/nuttx-dashboard-vm.pub

Click "Save"

```bash
## From https://docs.cloud.google.com/compute/docs/connect/standard-ssh#openssh-client
## Change "luppy" to your VM Username
ssh \
  -i $HOME/.ssh/nuttx-dashboard-vm \
  luppy@35.198.238.211
```

In VSCode: Click "Remote Explorer > SSH > +"

```bash
ssh -i ~/.ssh/nuttx-dashboard-vm luppy@35.198.238.211 
```

Select the SSH Config file $HOME/.ssh/config

Click "Connect"

Click "File > Open File / Folder"

$HOME/.ssh/config will look like:

```bash
Host 35.198.238.211
  HostName 35.198.238.211
  IdentityFile ~/.ssh/nuttx-dashboard-vm
  User luppy
```

Probably better to rename the "Host", in case the IP Address changes...

```bash
Host nuttx-dashboard-vm
  HostName 35.198.238.211
  IdentityFile ~/.ssh/nuttx-dashboard-vm
  User luppy
```

# SSH Key for GitHub

Create the GitHub SSH Key on VM: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent

```bash
ssh-keygen \
  -t ed25519 \
  -f $HOME/.ssh/nuttxpr@github \
  -C "nuttxpr@github"
```

Add SSH Key to GitHub Account: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account

Copy from Public Key $HOME/.ssh/nuttxpr@github.pub to GitHub

Test it:

```bash
ssh -T \
  -i $HOME/.ssh/nuttxpr@github \
  git@github.com

## We should see...
## Hi nuttxpr! You've successfully authenticated, but GitHub does not provide shell access.
```

Edit $HOME/.ssh/config

```bash
nano $HOME/.ssh/config
```

Add this...

```bash
Host github.com
  IdentityFile ~/.ssh/nuttxpr@github
```

Test it:

```bash
## Should now work without stating Private Key
ssh -T \
  git@github.com

## We should see...
## Hi nuttxpr! You've successfully authenticated, but GitHub does not provide shell access.
```

# Set the GitHub Token

Create $HOME/github-token.sh

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

If we're ingesting GitLab Snippets: Create $HOME/gitlab-token.sh

```bash
## User Settings > Access tokens
## Select scopes:
## api: Grants complete read/write access to the API, including all groups and projects, the container registry, the dependency proxy, and the package registry.
export GITLAB_TOKEN=...
export GITLAB_USER=lupyuen
export GITLAB_REPO=nuttx-build-log
```

# Nuttx Mirror Repo

`nuttxpr` will start the build by pushing a patch to the NuttX Mirror Repo. We grant permission to `nuttxpr`

NuttX Organisation Members: https://github.com/orgs/NuttX/people

Click "Invite Member"

Enter `nuttxpr`

Role In Organisation: Member

Log in as `nuttxpr` to accept the invitation

Check the people: https://github.com/orgs/NuttX/people

# Ingest GitHub Logs

Inside the VM: Run https://github.com/lupyuen/ingest-nuttx-builds/blob/main/github.sh

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

## Run github.sh
sudo apt install unzip
git clone https://github.com/lupyuen/ingest-nuttx-builds
cd ingest-nuttx-builds
./github.sh
```

Log for Ingest NuttX Builds: https://gist.github.com/lupyuen/8cf82eab994c2bca77f129ffa118acf0

Check Pushgateway http://35.198.238.211:9091

Check Prometheus: Enter "build_score", click Execute. http://35.198.238.211:9090

Check Grafana http://35.198.238.211:3000/d/fe2bqg6uk7nr4a

And Build History: http://35.198.238.211:3000/d/fe2q876wubc3kc

TODO: Fix step:10 to ??? for Linux

# Start the Build for NuttX Mirror Repo

Inside the VM:

```bash

```

?gh CLI

?Permission

TODO

# Ingest GitLab Logs

TODO

# Cost of Google Cloud

TODO
