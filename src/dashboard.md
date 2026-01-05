# Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS

📝 _20 Feb 2025_

![Grafana Dashboard on Google Cloud VM for Apache NuttX RTOS](https://lupyuen.org/images/dashboard-title.jpg)

TODO

# Create Virtual Machine

Create Project: nuttx-dashboard

https://console.cloud.google.com/projectcreate

Click "Select Project"

Click "Create a VM"

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

# Install Prometheus

# Connect Grafana to Prometheus

