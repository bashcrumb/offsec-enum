#!/bin/bash

# Run this on kali linux to install all dependencies

if [[ $EUID -ne 0 ]]; then
    echo "This must be run as root!"
    read -p "Continue anyway? (y/n) "
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
	exit 1
    fi
fi

apt update

apt install -y nmap nikto gobuster enum4linux smbmap smbclient whatweb python3 python3-pip

apt install -y nbtscan onesixtyone snmpwalk ldapsearch curl wget

apt install -y wordlists seclists

if [ -d "/usr/share/wordlists/dirb" ]; then
    gunzip /usr/share/wordlists/dirb/*.gz 2>/dev/null
fi

if [ -d "/usr/share/wordlists/dirbuster" ]; then
    gunzip /usr/share/wordlists/dirbuster/*.gz 2>/dev/null
fi

tools=("nmap" "nikto" "gobuster" "enum4linux" "smbmap" "smbclient" "whatweb" "python3")
missing=()

for tool in "${tools}[@]}"; do
    if command -v $tool &> /dev/null; then
	echo "$tool: installed"
    else
	missing+=($tool)
    fi
done

if [ ${#missing[@]} -eq 0 ]; then
    echo "all tools installed"
else
    echo "missing tools: ${missing[*]}"
fi

chmod +x offsec_enum.py
