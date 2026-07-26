#!/bin/bash
# =============================================================================
# ACDS Vulnerable Lab Target — Ubuntu 22.04/24.04 (VMware NAT)
# Run INSIDE the guest VM with: sudo bash setup-vulnerable-ubuntu.sh
#
# Exposes ports the ACDS app scans: 21, 22, 80, 3306 (and optional 23)
# Educational lab only — isolate on VMware NAT, never expose to the internet.
# =============================================================================
set -e

TARGET_IP="${TARGET_IP:-192.168.93.128}"
HOSTNAME="${HOSTNAME:-acds-vuln-target}"
IFACE="${IFACE:-}"

echo "=== ACDS Vulnerable Lab Target Setup ==="
echo "Target IP: $TARGET_IP"
echo "Hostname:  $HOSTNAME"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server apache2 vsftpd mysql-server inetutils-telnetd telnetd ufw net-tools

hostnamectl set-hostname "$HOSTNAME"

# --- Static IP (netplan) ---
if [ -z "$IFACE" ]; then
  IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
fi
echo "Using interface: $IFACE"

GATEWAY="192.168.93.2"
DNS="192.168.93.2"

cat > /etc/netplan/01-acds-lab.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${IFACE}:
      dhcp4: no
      addresses:
        - ${TARGET_IP}/24
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses: [${DNS}]
EOF

chmod 600 /etc/netplan/01-acds-lab.yaml
netplan apply || true

# --- SSH (port 22) — banner visible to scanner ---
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl enable --now ssh

# --- Apache (port 80) ---
echo "<html><body><h1>ACDS Vulnerable Lab Server</h1><p>Port 80 open for scanning demo.</p></body></html>" \
  > /var/www/html/index.html
systemctl enable --now apache2

# --- FTP (port 21) — anonymous read (lab only) ---
cat > /etc/vsftpd.conf <<'EOF'
listen=YES
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/var/ftp
no_anon_password=YES
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
EOF
mkdir -p /var/ftp/pub
echo "ACDS lab FTP share" > /var/ftp/pub/readme.txt
systemctl enable --now vsftpd

# --- MySQL (port 3306) — bound to all interfaces (intentionally weak lab config) ---
mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld
systemctl enable --now mysql || systemctl enable --now mariadb || true

# Allow remote connections on 3306 (lab only)
MYSQL_CNF="/etc/mysql/mysql.conf.d/mysqld.cnf"
if [ -f "$MYSQL_CNF" ]; then
  sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' "$MYSQL_CNF" || echo "bind-address = 0.0.0.0" >> "$MYSQL_CNF"
  systemctl restart mysql || systemctl restart mariadb || true
fi

# --- Telnet (port 23) — high-risk service for demo (optional but useful) ---
systemctl enable --now inetd 2>/dev/null || systemctl enable --now openbsd-inetd 2>/dev/null || true

# --- Firewall: allow scanned ports on LAN ---
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 21/tcp
ufw allow 23/tcp
ufw allow 3306/tcp
ufw --force enable

echo ""
echo "=== Setup complete ==="
echo "Hostname: $(hostname)"
echo "IP:       $(hostname -I | awk '{print $1}')"
echo ""
echo "Open ports the ACDS app should detect:"
ss -tlnp | grep -E ':21|:22|:23|:80|:3306' || netstat -tlnp | grep -E ':21|:22|:23|:80|:3306'
echo ""
echo "From your Windows host, verify:"
echo "  ping ${TARGET_IP}"
echo "  Test-NetConnection ${TARGET_IP} -Port 22"
echo "  Test-NetConnection ${TARGET_IP} -Port 80"
echo ""
echo "Then in ACDS: Real Network Scan → uncheck Auto-detect → prefix 192.168.93. → scan range 200"
