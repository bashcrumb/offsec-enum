#!/bin/bash
# ──────────────────────────────────────────────────────────
# offsec-enum-ng setup — installs all tool dependencies on Kali
# ──────────────────────────────────────────────────────────

set -e

if [[ $EUID -ne 0 ]]; then
    echo "[!] Root recommended — some packages need elevated privileges."
    read -rp "    Continue anyway? (y/n) " reply
    echo
    if [[ ! $reply =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "[*] Updating package index..."
apt update || true

# ── Core scanning & web enumeration ──────────────────────
echo "[*] Installing core tools..."
apt install -y \
    nmap nikto gobuster whatweb \
    python3 python3-pip curl wget

# ── SMB / NetBIOS ────────────────────────────────────────
echo "[*] Installing SMB tools..."
apt install -y \
    enum4linux smbmap smbclient nbtscan

# ── SNMP ─────────────────────────────────────────────────
echo "[*] Installing SNMP tools..."
apt install -y \
    snmp onesixtyone

# ── DNS ──────────────────────────────────────────────────
echo "[*] Installing DNS tools..."
apt install -y \
    dnsutils dnsrecon dnsenum

# ── LDAP ─────────────────────────────────────────────────
echo "[*] Installing LDAP tools..."
apt install -y \
    ldap-utils

# ── NFS / RPC ────────────────────────────────────────────
echo "[*] Installing NFS/RPC tools..."
apt install -y \
    nfs-common rpcbind

# ── SMTP ─────────────────────────────────────────────────
echo "[*] Installing SMTP tools..."
apt install -y \
    smtp-user-enum 2>/dev/null || echo "    smtp-user-enum not in repos — install manually if needed"

# ── Wordlists ────────────────────────────────────────────
echo "[*] Installing wordlists..."
apt install -y wordlists seclists

if [ -d "/usr/share/wordlists/dirb" ]; then
    gunzip /usr/share/wordlists/dirb/*.gz 2>/dev/null || true
fi
if [ -d "/usr/share/wordlists/dirbuster" ]; then
    gunzip /usr/share/wordlists/dirbuster/*.gz 2>/dev/null || true
fi

# ── Verify installations ────────────────────────────────
echo ""
echo "[*] Verifying tool installations..."

tools=(
    nmap nikto gobuster whatweb
    enum4linux smbmap smbclient nbtscan
    onesixtyone snmpwalk
    dig dnsrecon dnsenum
    ldapsearch
    rpcinfo showmount
    smtp-user-enum
    python3
)

missing=()
for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "    [+] $tool"
    else
        echo "    [-] $tool  (MISSING)"
        missing+=("$tool")
    fi
done

echo ""
if [ ${#missing[@]} -eq 0 ]; then
    echo "[+] All tools installed successfully."
else
    echo "[!] Missing tools (${#missing[@]}): ${missing[*]}"
    echo "    Install manually or check package names for your distro."
fi

# ── Make script executable ───────────────────────────────
if [ -f "offsec-enum-ng.py" ]; then
    chmod +x offsec-enum-ng.py
    echo "[+] offsec-enum-ng.py marked executable."
fi

echo ""
echo "[+] Setup complete."
