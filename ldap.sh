#!/bin/bash

# === CONFIGURABLE PARAMETERS ===
DOMAIN_NAME="example.com"
AD_ADMIN="suresh"
AD_PASSWORD="ctrls@1234\$#\$"  # Escape special characters properly
OU_PATH="OU=LinuxServers,DC=example,DC=com"
AD_SUDO_GROUP="LinuxAdmins"
AD_SERVER_IP="10.3.0.4"
NET_IFACE="eth0"
LINUX_HOSTNAME=$(hostname -s)

# === AUTO DNS + HOSTNAME ===
echo "🖥️  Setting hostname and DNS..."
hostnamectl set-hostname "${LINUX_HOSTNAME}.${DOMAIN_NAME}"
echo "nameserver $AD_SERVER_IP" > /etc/resolv.conf

# === DETECT OS ===
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "❌ Cannot detect OS."
    exit 1
fi
echo "📦 Detected OS: $OS"

# === CONFIGURE NETWORK ===
if [[ "$OS" =~ ^(centos|rhel|rocky|almalinux)$ ]]; then
    cat > /etc/sysconfig/network-scripts/ifcfg-${NET_IFACE} <<EOF
DEVICE=${NET_IFACE}
BOOTPROTO=dhcp
ONBOOT=yes
PEERDNS=no
DHCP_HOSTNAME=${LINUX_HOSTNAME}.${DOMAIN_NAME}
DNS1=${AD_SERVER_IP}
DOMAIN="${DOMAIN_NAME}"
EOF

elif [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    cat > /etc/netplan/99-ad-config.yaml <<EOF
network:
  version: 2
  ethernets:
    ${NET_IFACE}:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
      nameservers:
        addresses: [${AD_SERVER_IP}]
        search: [${DOMAIN_NAME}]
      dhcp-identifier: mac
EOF
    netplan apply

elif [[ "$OS" == "sles" || "$OS" == "opensuse" ]]; then
    cat > /etc/sysconfig/network/ifcfg-${NET_IFACE} <<EOF
BOOTPROTO='dhcp'
STARTMODE='auto'
DHCLIENT_SET_HOSTNAME='yes'
DHCLIENT_HOSTNAME='${LINUX_HOSTNAME}.${DOMAIN_NAME}'
NETCONFIG_DNS_POLICY=''
DNS1='${AD_SERVER_IP}'
DOMAIN='${DOMAIN_NAME}'
EOF

    # Add krb5.conf if not present
cat > /etc/krb5.conf <<EOF
[libdefaults]
  default_realm = ${DOMAIN_NAME^^}
  dns_lookup_realm = true
  dns_lookup_kdc = true
EOF
fi

# === INSTALL REQUIRED PACKAGES ===
echo "📥 Installing required packages..."
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    apt update
    apt install -y realmd sssd sssd-tools adcli samba-common-bin samba-libs oddjob oddjob-mkhomedir packagekit sudo krb5-user 

elif [[ "$OS" =~ ^(centos|rhel|rocky|almalinux)$ ]]; then
    yum install -y realmd sssd adcli samba-common samba-common-tools oddjob oddjob-mkhomedir sssd-tools krb5-workstation sudo

elif [[ "$OS" == "sles" || "$OS" == "opensuse" ]]; then
    zypper refresh
    zypper install -y realmd sssd adcli samba samba-client oddjob oddjob-mkhomedir krb5-client sudo
fi

# === VERIFY SSSD CONFIGURATION ===
SSSD_CONF="/etc/sssd/sssd.conf"

if [ ! -f "$SSSD_CONF" ]; then
    echo "⚠️  sssd.conf missing, generating basic config..."
    cat > "$SSSD_CONF" <<EOF
[sssd]
domains = ${DOMAIN_NAME}
config_file_version = 2
services = nss, pam

[domain/${DOMAIN_NAME}]
ad_domain = ${DOMAIN_NAME}
krb5_realm = ${DOMAIN_NAME^^}
realmd_tags = manages-system joined-with-adcli
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = False
fallback_homedir = /home/%u
access_provider = ad
EOF
fi

chmod 600 "$SSSD_CONF"
chown root:root "$SSSD_CONF"
echo "✅ Validated sssd.conf and permissions"

# === REALM DISCOVERY ===
echo "🔍 Discovering domain using adcli..."
realm discover "$DOMAIN_NAME" || {
    echo "❌ Domain discovery failed."
    exit 1
}

# === KINIT FOR CACHED CREDENTIALS ===
echo "🎫 Getting Kerberos ticket for $AD_ADMIN..."
printf '%s' "$AD_PASSWORD" | kinit "${AD_ADMIN}@${DOMAIN_NAME^^}" || {
    echo "❌ kinit failed: Wrong credentials or clock skew?"
    exit 1
}

# === DOMAIN JOIN WITH adcli ===
echo "🔐 Attempting to join domain using adcli..."
if adcli join --domain="$DOMAIN_NAME" --login-user="$AD_ADMIN" --stdin-password <<< "$AD_PASSWORD" --domain-ou="$OU_PATH"; then
    echo "✅ Joined domain with OU using adcli."
else
    echo "⚠️  Failed with OU, retrying without OU..."
    if adcli join --domain="$DOMAIN_NAME" --login-user="$AD_ADMIN" --stdin-password <<< "$AD_PASSWORD"; then
        echo "✅ Joined domain without OU using adcli."
    else
        echo "❌ Domain join failed via adcli. Trying realm as fallback..."
        echo "$AD_PASSWORD" | realm join --user="$AD_ADMIN" "$DOMAIN_NAME" || {
            echo "❌ Realm join failed too. Check credentials or permissions."
            exit 1
        }
    fi
fi

# === ENABLE HOME DIR CREATION ===
authconfig --enablemkhomedir --update 2>/dev/null || pam-auth-update --enable mkhomedir || true

# === SSSD CONFIG TWEAK ===
if [ -f /etc/sssd/sssd.conf ]; then
    sed -i 's/use_fully_qualified_names = True/use_fully_qualified_names = False/' /etc/sssd/sssd.conf
    chmod 600 /etc/sssd/sssd.conf
    echo "🔧 Updated sssd.conf"
fi

systemctl restart sssd

# === SUDOERS FOR AD GROUP ===
SUDOERS_FILE="/etc/sudoers.d/ad_sudo_group"
echo "%$AD_SUDO_GROUP ALL=(ALL) NOPASSWD: ALL" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
echo "🛡️  Sudo access granted to AD group: @$AD_SUDO_GROUP"

echo "✅ AD Join Complete on $OS"
