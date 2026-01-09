# Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS

📝 _20 Feb 2025_

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

TODO

_What if we prefer another cloud? Or our own machine?_

The steps below will work for any Debian Bookworm machine.

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

Set permission: 
- Settings > Permission > Role Viewer > View
- Same for Build History Dashboard

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

nuttxpr is an Ordinary GitHub Account with Read Access. Don't use a GitHub Admin Account!

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

# NuttX Mirror Repo

`nuttxpr` will start the build by pushing a patch to the NuttX Mirror Repo. We grant permission to `nuttxpr`

NuttX Mirror Collaborators: https://github.com/NuttX/nuttx/settings/access

Click "Add People"

Enter `nuttxpr`

Role: Write

Log in as `nuttxpr` to accept the invitation

Check the collaborators: https://github.com/NuttX/nuttx/settings/access

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
cd
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

Only one instance of sync-build-ingest.sh should ever be running! Make sure `lupyuen` isn't running it on his Home Computer.

Inside the VM: Run https://github.com/lupyuen/nuttx-release/blob/main/sync-build-ingest.sh

```bash
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

## Run sync-build-ingest.sh
cd
git clone https://github.com/lupyuen/nuttx-release
cd $HOME/nuttx-release
./sync-build-ingest.sh

## If we see: "**** ERROR: Expected Downstream Commit to be 'Enable macOS Builds' but found: ..."
## Then run this instead:
## ./enable-macos-windows.sh
## ./sync-build-ingest.sh
```

[sync-build-ingest.sh Log](https://gist.github.com/lupyuen/c9dd83842ab9b845eadedb968bd63bc1)

[enable-macos-windows.sh Log](https://gist.github.com/lupyuen/3d21869dae705d6c9d3acc1e8d94ffd1)

We should see the patch that starts the NuttX Build:

https://github.com/NuttX/nuttx/commits/master/

And the NuttX Build should be running:

https://github.com/NuttX/nuttx/actions/workflows/build.yml

In case of sync problems: Go to https://github.com/NuttX/nuttx/tree/master, click "Sync Fork > Discard Commit". Then run enable-macos-windows.sh followed by sync-build-ingest.sh.

If we see

```bash
fatal: cannot create directory at 'arch/arm/src/kinetis': No space left on device
warning: Clone succeeded, but checkout failed.
```

Increase the disk space. Need 5 GB for /tmp. See the section below.

# Forever Build and Ingest

nano $HOME/sync.sh

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

Run $HOME/sync.sh

```bash
sudo apt install tmux
tmux
chmod +x $HOME/sync.sh
$HOME/sync.sh

## If the SSH Session Disconnects:
## Do this to reconnect the sync.sh session...
## tmux a
```

(Don't use cron, need to monitor manually so that we don't run into overuse of the GitHub Runners of the Mirror Repo)

[Log for NuttX Build and Ingest](https://github.com/lupyuen/nuttx-release/releases/download/v1.0.0/sync.log)

In case of sync problems: Go to https://github.com/NuttX/nuttx/tree/master, click "Sync Fork > Discard Commit". Then run enable-macos-windows.sh followed by sync.sh.

# Ingest the GitHub Gists and GitLab Snippets

Remember to set GitLab Token

```bash
tmux
cd $HOME/ingest-nuttx-builds
./run.sh

## If the SSH Session Disconnects:
## Do this to reconnect the run.sh session...
## tmux a
```

(Don't use cron, need to monitor manually so that we don't run into overuse of the GitHub API and GitLab API)

[Log for Ingest GitHub Gists and GitLab Snippets](https://gist.github.com/lupyuen/d29be01f9e5ad256c6bb6df1e1ddea6d)

# Expand the VM Disk

```bash
## TODO: Out of space in /tmp
$ df -H
Filesystem      Size  Used Avail Use% Mounted on
udev            2.1G     0  2.1G   0% /dev
tmpfs           412M  574k  411M   1% /run
/dev/sda1        11G  9.8G     0 100% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M     0  5.3M   0% /run/lock
/dev/sda15      130M   13M  118M  10% /boot/efi
tmpfs           412M     0  412M   0% /run/user/1000

## Before:
$ df -H
Filesystem      Size  Used Avail Use% Mounted on
udev            2.1G     0  2.1G   0% /dev
tmpfs           412M  574k  411M   1% /run
/dev/sda1        11G  8.5G  1.4G  87% /
tmpfs           2.1G     0  2.1G   0% /dev/shm
tmpfs           5.3M     0  5.3M   0% /run/lock
/dev/sda15      130M   13M  118M  10% /boot/efi
tmpfs           412M     0  412M   0% /run/user/1000

## Most of the disk space used by /tmp
$ rm -rf /tmp/sync-build-ingest/
```

Resize the disk: https://dev.to/lovestaco/expanding-disk-size-in-google-cloud-5gkh

Click VM > Details > Storage > Boot Disk

Click Menu > Edit at Top Right

Increase the size from 10 GB to 20 GB. Click Save

Inside the VM:

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

# Configure Our Grafana Server

Edit /etc/grafana/grafana.ini

Look for these settings and edit them (don't add them)...

```bash
# Log web requests
# Default: router_logging = false
router_logging = true

# enable gzip
# Default: enable_gzip = false
enable_gzip = true

# This enables data proxy logging, default is false
logging = true

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

[grafana.ini](https://github.com/lupyuen/ingest-nuttx-builds/blob/main/grafana2.ini)

Restart grafana

```bash
sudo systemctl restart grafana-server
```

# Publish Online with Cloudflare Tunnel

TODO

Create a Cloudflare Tunnel, pointing to http://localhost:3000

Or use Cloudflare CDN.

# Cost of Google Cloud

TODO

_Will it be cheaper to run on an Asian Cloud? Like AliCloud? _

Hmmm interesting... We should try out! 

# What's Next

Now that NuttX Dashboard is running in the Cloud (and not at Home)... We're going overseas for Twincity Marathon!

TODO
