# Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS

📝 _20 Feb 2025_

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

TODO

# Create Virtual Machine

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

### Configure grafana to start automatically using systemd
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable grafana-server

### Start grafana-server
sudo /bin/systemctl start grafana-server

$ netstat -an | grep LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:5355            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:20202           0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::3000                 :::*                    LISTEN     
tcp6       0      0 ::1:25                  :::*                    LISTEN     
tcp6       0      0 :::5355                 :::*                    LISTEN     
tcp6       0      0 :::20201                :::*                    LISTEN 
```

# Install Prometheus

# Connect Grafana to Prometheus

