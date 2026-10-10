# ACDS Cybersecurity Lab Setup

This document describes the local virtual lab used to validate the
Adaptive Cyber Defense System (ACDS) asset-discovery,
service-identification, vulnerability-assessment, and
defense-verification workflows.

> **Scope and safety:** Use these procedures only on virtual machines
> and subnets you own or are explicitly authorized to test. Keep
> discovery limited to the dedicated VMware lab subnet. Do not scan the
> physical Wi-Fi network, enable VMware port forwarding, or expose
> database services just to create test ports.

## 1. Lab architecture

The lab uses a Windows host running ACDS and two Linux virtual machines
managed by VMware Workstation 17 Player.

  ---------------------------------------------------------------------------
  Component         Role                Network           Known address
  ----------------- ------------------- ----------------- -------------------
  Windows 11 host   Runs the ACDS       VMware VMnet8 NAT `192.168.93.1` on
                    Streamlit                             VMnet8
                    application and                       
                    initiates discovery                   

  Kali Linux VM     Linux               VMware VMnet8 NAT Previously
                    discovery/service                     `192.168.93.129`;
                    test target                           verify after
                                                          changing adapters

  Ubuntu Server     Linux web/SSH test  VMware VMnet8 NAT `192.168.93.130` at
  24.04.5 LTS VM    target                                last verification
  (`acdsserver`)                                          

  VMware NAT        NAT gateway for     VMnet8            `192.168.93.2`
  gateway           VMnet8                                

  Lab subnet        Authorized          VMnet8            `192.168.93.0/24`
                    discovery range                       
  ---------------------------------------------------------------------------

VM IP addresses can change if VMware DHCP leases change. Always verify
current addresses before scanning. The Windows host's physical Wi-Fi
network is separate and is **not** part of this lab.

### Network mode

Configure both Kali and Ubuntu VM network adapters as **NAT (VMnet8)**
in VMware Workstation:

1.  Shut down the VM cleanly.
2.  Open **Virtual Machine Settings → Network Adapter**.
3.  Select **NAT: Used to share the host's IP address**.
4.  Enable **Connected** and **Connect at power on**.
5.  Start the VM and verify its IP address.

NAT allows the VMs to use the host's network connection for outbound
internet access. It does not guarantee every traffic pattern between
VMs, so test connectivity after configuration. Do not configure port
forwarding for this lab.

## 2. Current known services

### Ubuntu Server

Ubuntu is configured with OpenSSH and Apache HTTP Server.

  -----------------------------------------------------------------------
  Service                 Port/protocol           Expected purpose
  ----------------------- ----------------------- -----------------------
  OpenSSH                 TCP 22                  Remote administration
                                                  from the Windows host

  Apache HTTP Server      TCP 80                  HTTP service used for
                                                  discovery and
                                                  controlled on/off
                                                  testing

  `systemd-resolved` stub TCP/UDP 53 on loopback  Local DNS stub; not a
                                                  LAN-facing DNS service
  -----------------------------------------------------------------------

Last observed Ubuntu details:

-   Hostname: `acdsserver`
-   OS: Ubuntu Server 24.04.5 LTS
-   NAT address at last check: `192.168.93.130`
-   Apache package: `2.4.58-1ubuntu8.16`
-   Apache banner: `Apache/2.4.58 (Ubuntu)`
-   SSH and Apache services were running.
-   UFW reported `inactive` at the last check. Do not assume a host
    firewall is enforcing rules.

Package versions and service states change over time. Re-check them
during each experiment.

### Kali Linux

Kali was previously observed at `192.168.93.129`, with SSH on TCP 22 and
Apache/HTTP on TCP 80. Verify its current IP and listening services
after switching the VM adapter to NAT.

## 3. Connect to Ubuntu from Windows PowerShell

Find the current Ubuntu address in the Ubuntu console:

``` bash
hostname -I
```

From Windows PowerShell, connect using the actual current address:

``` powershell
ssh ubuntu_user@192.168.93.130
```

Replace the example IP if it has changed. On first connection, verify
the host fingerprint if practical before accepting it. The SSH password
is not displayed while typing; this is normal.

If SSH fails, check the Ubuntu console:

``` bash
sudo systemctl status ssh --no-pager
sudo ss -lntp
```

From Windows, test TCP 22:

``` powershell
Test-NetConnection 192.168.93.130 -Port 22
```

## 4. Verify network and internet connectivity

Run inside each Linux VM:

``` bash
ip -4 addr
ip route
```

For Ubuntu, the expected NAT subnet is `192.168.93.0/24`, with the NAT
gateway usually `192.168.93.2`.

Test the gateway:

``` bash
ping -c 4 192.168.93.2
```

Test DNS and outbound HTTPS from Ubuntu:

``` bash
getent hosts archive.ubuntu.com
curl -I --max-time 10 https://archive.ubuntu.com/
```

If a test fails, capture the output before changing network settings. Do
not disable security controls or change VMware subnets as a first
troubleshooting step.

## 5. Inspect listening services

Run on Ubuntu:

``` bash
sudo ss -lntup
systemctl --type=service --state=running
sudo ufw status verbose
```

These commands are read-only. They show listening TCP/UDP sockets,
running services, and UFW status.

From Windows PowerShell, test the expected Ubuntu services:

``` powershell
Test-NetConnection 192.168.93.130 -Port 22
Test-NetConnection 192.168.93.130 -Port 80
```

Replace the IP if Ubuntu's current address differs.

## 6. Discover the lab subnet

Run discovery only against the authorized VMnet8 lab subnet. If Nmap is
installed on the Windows host:

``` powershell
nmap -sn 192.168.93.0/24
```

This performs host discovery without a port scan. Some hosts may not
respond to discovery probes, so a missing result does not conclusively
prove a host is offline.

To inspect service versions on the two known lab VMs:

``` powershell
nmap -sV 192.168.93.129 192.168.93.130
```

Replace the example addresses with verified current IPs. Do not broaden
this command to the physical Wi-Fi subnet.

In ACDS, enter the subnet in CIDR notation:

``` text
192.168.93.0/24
```

Confirm that the asset inventory contains the expected hosts and that
discovered ports match independent checks. A port being open means a
service is reachable; it does not, by itself, prove a vulnerability.

## 7. Controlled HTTP service on/off experiment

Use this experiment to test whether ACDS detects a service disappearing
and returning. Keep SSH running so the management session remains
available.

Create a simple Apache control script on Ubuntu:

``` bash
cat > ~/acds-service-control.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-status}" in
  start)
    sudo systemctl start apache2
    ;;
  stop)
    sudo systemctl stop apache2
    ;;
  restart)
    sudo systemctl restart apache2
    ;;
  status)
    systemctl --no-pager --full status apache2 || true
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

echo
sudo ss -lntp
EOF

chmod +x ~/acds-service-control.sh
```

Check the initial state:

``` bash
~/acds-service-control.sh status
```

Stop Apache temporarily:

``` bash
~/acds-service-control.sh stop
```

From a **second** Windows PowerShell window, check TCP 80:

``` powershell
Test-NetConnection 192.168.93.130 -Port 80
```

Run an ACDS rescan and record whether port 80 is shown as closed,
filtered, or not detected. Restore Apache from the SSH session:

``` bash
~/acds-service-control.sh start
```

Repeat the Windows connectivity check and ACDS scan. Confirm that HTTP
becomes reachable again.

**Do not stop SSH (TCP 22) during a remote session.** Stopping Apache
reduces HTTP exposure but does not patch Apache or establish that the
software has no vulnerabilities.

## 8. Patch verification

Collect package evidence before applying updates:

``` bash
apache2 -v
apt-cache policy apache2
apt list --upgradable
apt changelog apache2 | head -80
```

Refresh package metadata when needed:

``` bash
sudo apt update
```

`apt update` refreshes repository metadata; it does not upgrade
installed packages. Apply package updates only when appropriate for the
lab and after recording the pre-change state. Re-check the installed
package revision and service status after any update.

For CVE assessment, do not rely only on the upstream banner (for
example, `Apache/2.4.58 (Ubuntu)`). Ubuntu may backport security fixes
while retaining the upstream version. Use distribution-specific security
status and package revision evidence where available. Treat uncertain
matches as potential/unverified rather than confirmed.

## 9. ACDS validation checklist

-   [ ] Both Linux VMs use VMnet8 NAT.
-   [ ] Current IP addresses are recorded.
-   [ ] Both VMs can reach the intended network and internet endpoints.
-   [ ] Windows can reach Ubuntu and Kali on expected service ports.
-   [ ] ACDS scans only `192.168.93.0/24` for this lab.
-   [ ] Asset inventory matches independently observed hosts.
-   [ ] Service/port observations are reproducible.
-   [ ] Service version and CVE claims include supporting evidence.
-   [ ] A controlled Apache stop causes HTTP reachability to change.
-   [ ] Restarting Apache restores HTTP reachability.
-   [ ] Risk changes are explained by evidence, not merely by an open
    port.
-   [ ] Before/after results and timestamps are recorded.
-   [ ] No credentials, secrets, private keys, or personal network
    details are committed.

## 10. Troubleshooting notes

### Ubuntu IP changed

Run `hostname -I` in Ubuntu and update the target address used by
PowerShell and ACDS.

### SSH is unreachable

Check `sudo systemctl status ssh --no-pager` in the VM, confirm the
adapter is NAT, and run `Test-NetConnection <UBUNTU_IP> -Port 22` from
Windows.

### Apache is not reachable

Check `sudo systemctl status apache2 --no-pager`, then `sudo ss -lntp`.
Verify that the IP in the test matches Ubuntu's current address.

### `apt update` cannot reach repositories

Check `ip route`, `getent hosts archive.ubuntu.com`, and
`curl -I --max-time 10 https://archive.ubuntu.com/`. Diagnose gateway,
DNS, and connectivity separately.

### ACDS misses a host

A host-discovery probe can be blocked or ignored. Compare ACDS results
with VM IPs and direct connectivity tests; record discovery limitations
instead of assuming the host is absent.

## 11. Reproducibility record

For each lab run, record:

-   Date/time
-   Subnet scanned
-   Current IP of each VM
-   Discovered assets and ports
-   Service/version evidence
-   CVE source and applicability status
-   Defensive action performed
-   Before/after connectivity and ACDS results
-   Any limitations or errors

Keep results separated into **observed**, **inferred**, **calculated**,
and **simulated** evidence. Analytical attack-path simulation is not
proof that an exploit was executed.

------------------------------------------------------------------------

**Maintainer note:** Update this document when the topology, service
inventory, or ACDS scan workflow changes. Never commit passwords, SSH
private keys, tokens, or unredacted sensitive scan results.
