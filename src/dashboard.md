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

# Push Metrics to Prometheus

```bash
+ cargo run -- --user NuttX --repo nuttx --defconfig /tmp/defconfig-github.txt --file /tmp/ci-xtensa-01.log --nuttx-hash 59f200ac4fe6c940dc0eab2155bb3cb566724082 --apps-hash 4f93ec0a4335d574eeecfd295584fbfb17056e5b --group xtensa-01 --run-id 20706016275 --job-id 59436813143 --step 10
```

# Connect Grafana to Prometheus

# Sync.sh

