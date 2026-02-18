# offsec-enum-ng

Automated enumeration for OSCP exam efficiency. Handles the tedious scanning and enumeration so you can focus on exploitation.

## What It Does

Runs a full enumeration pipeline against a target: port discovery → service detection → service-specific enumeration → actionable findings report. Everything runs concurrently where possible, checkpoints progress so you can resume if interrupted, and produces a report that tells you exactly what to try next.

## Features

- **Port Scanning**: Full TCP (`-p-`), configurable port ranges, independent UDP top-100
- **14 Service Enumerators**:
  - HTTP/HTTPS — nikto, gobuster (medium wordlist + extensions), whatweb
  - SMB — enum4linux-ng (JSON + text), smbmap, smbclient, NSE scripts
  - FTP — anonymous access detection
  - SSH — auth methods, host keys
  - MySQL — info, databases, empty password check
  - MSSQL — info, empty password, config
  - SNMP — community string brute force (onesixtyone), snmpwalk (full + processes + TCP ports)
  - DNS — zone transfers (dig axfr), dnsrecon, dnsenum
  - LDAP — base DN discovery, anonymous bind enumeration, NSE scripts
  - NFS/RPC — rpcinfo, showmount, NSE scripts
  - SMTP — user enumeration (VRFY), commands, open relay check
  - RDP — encryption enum, NTLM info
  - WinRM — NTLM info leak (domain/hostname/OS), auth methods (skips useless nikto/gobuster on HTTPAPI ports)
  - Windows RPC — rpcclient null session (users, groups, domain info, shares), impacket-rpcdump endpoint mapping
- **Vulnerability Scanning**: NSE vuln scripts on all discovered ports
- **Concurrent Enumeration**: Parallel service scans via thread pool (configurable)
- **Checkpoint/Resume**: Atomic state saves after each phase — `Ctrl+C` and pick up where you left off
- **Actionable Reports**: Findings sorted by severity with copy-paste next-step commands
- **JSON Export**: Machine-readable `REPORT.json` for custom tooling or dashboards
- **Security Hardened**: No `shell=True`, input validation on targets and ports

## Prerequisites

### Quick Setup

```bash
sudo ./setup.sh
```

This installs all dependencies and verifies them. Run it on a fresh Kali box and you're good to go.

### Manual Install

If you prefer to install manually:

```bash
# Core
sudo apt install -y nmap nikto gobuster whatweb python3

# SMB
sudo apt install -y enum4linux-ng smbmap smbclient nbtscan

# Windows RPC
sudo apt install -y samba-common-bin python3-impacket

# WinRM
sudo apt install -y evil-winrm  # or: gem install evil-winrm

# SNMP
sudo apt install -y snmp onesixtyone

# DNS
sudo apt install -y dnsutils dnsrecon dnsenum

# LDAP
sudo apt install -y ldap-utils

# NFS/RPC
sudo apt install -y nfs-common rpcbind

# SMTP
sudo apt install -y smtp-user-enum

# Wordlists
sudo apt install -y wordlists seclists
```

## Installation

```bash
git clone <repo-url> && cd offsec-enum-ng
sudo ./setup.sh
```

## Usage

### Basic

```bash
# Standard full enumeration
sudo python3 offsec-enum-ng.py 10.10.10.10

# Custom output directory
sudo python3 offsec-enum-ng.py 10.10.10.10 -o /root/offsec/target1
```

### Common Patterns

```bash
# Quick scan (top 10000 TCP, skip UDP)
sudo python3 offsec-enum-ng.py 10.10.10.10 -q

# Specific ports only
sudo python3 offsec-enum-ng.py 10.10.10.10 -p 80,443,8080

# Port range
sudo python3 offsec-enum-ng.py 10.10.10.10 -p 1-1000

# DNS zone transfers (requires domain name)
sudo python3 offsec-enum-ng.py 10.10.10.10 -d megacorp.local

# More threads for faster enumeration
sudo python3 offsec-enum-ng.py 10.10.10.10 -t 5

# Slow target — double all tool timeouts
sudo python3 offsec-enum-ng.py 10.10.10.10 --timeout-multiplier 2.0

# Resume after interruption
sudo python3 offsec-enum-ng.py 10.10.10.10 -o ./enum_results_10.10.10.10_20250217 --resume

# Verbose logging (DEBUG level)
sudo python3 offsec-enum-ng.py 10.10.10.10 -v
```

### Full Command Reference

```
usage: offsec-enum-ng.py [-h] [-o OUTPUT] [-p PORTS] [-q] [-v] [-t THREADS]
                      [-d DOMAIN] [--timeout-multiplier FLOAT] [--resume]
                      target

Arguments:
  target                    Target IP address or hostname

Options:
  -h, --help                Show help message
  -o, --output OUTPUT       Output directory (default: ./enum_results)
  -p, --ports PORTS         Port specification (e.g., 1-1000 or 80,443,8080)
  -q, --quick               Quick mode (top 10000 TCP ports, skip UDP)
  -v, --verbose             Verbose output (DEBUG log level)
  -t, --threads THREADS     Concurrent enumeration threads (default: 3)
  -d, --domain DOMAIN       Domain name for DNS zone transfer attempts
  --timeout-multiplier N    Scale all tool timeouts (default: 1.0)
  --resume                  Resume from checkpoint (requires existing output dir)
```

## Output Structure

```
enum_results_10.10.10.10_20250217_143052/
├── REPORT.md              # Actionable findings report
├── REPORT.json            # Machine-readable structured data
├── state.json             # Checkpoint file (for --resume)
├── enum_20250217_143052.log
├── nmap/
│   ├── initial_scan.xml
│   ├── initial_scan.nmap
│   ├── vuln_scan.xml
│   └── udp_scan.xml
├── web/
│   ├── nikto_80.txt
│   ├── gobuster_80.txt
│   ├── whatweb_80.txt
│   ├── nikto_443.txt
│   ├── gobuster_443.txt
│   └── whatweb_443.txt
├── smb/
│   ├── enum4linux-ng.json
│   ├── enum4linux-ng.txt
│   ├── smbmap.txt
│   ├── smbclient.txt
│   └── nmap_smb_445.txt
├── msrpc/
│   ├── rpcclient_null.txt
│   └── rpcdump.txt
├── winrm/
│   ├── winrm_ntlm_5985.txt
│   └── winrm_auth_5985.txt
├── ftp/
│   └── ftp_enum_21.txt
├── snmp/
│   ├── onesixtyone.txt
│   ├── snmpwalk_full.txt
│   ├── snmpwalk_processes.txt
│   └── snmpwalk_tcp_ports.txt
├── dns/
│   ├── dig_axfr.txt
│   ├── dnsrecon.txt
│   └── dnsenum.txt
├── ldap/
│   ├── ldapsearch_base.txt
│   ├── ldapsearch_full.txt
│   └── nmap_ldap.txt
├── nfs/
│   ├── rpcinfo.txt
│   ├── showmount.txt
│   └── nmap_nfs.txt
├── smtp/
│   ├── nmap_smtp.txt
│   └── smtp_user_enum.txt
└── misc/
    ├── ssh_enum_22.txt
    ├── mysql_enum_3306.txt
    ├── mssql_enum_1433.txt
    └── rdp_enum_3389.txt
```

## Report

The generated `REPORT.md` includes:

1. **Executive Summary** — target, duration, port count, findings by severity
2. **Critical & High Findings** — each with evidence and an exact next-step command
3. **Service Details** — port table with product/version info
4. **Web Discovery** — gobuster interesting hits + nikto findings
5. **Other Findings** — medium/low/info items
6. **Enumeration Coverage** — completed tasks, failed/timed-out commands
7. **Raw Data Index** — every output file with sizes

Findings the engine detects automatically:

| Severity | Finding | Example Next Step |
|----------|---------|-------------------|
| CRITICAL | FTP anonymous login | `ftp 10.10.10.10` — download all files |
| CRITICAL | MySQL root empty password | `mysql -h 10.10.10.10 -u root` |
| HIGH | SMB writable share | `smbclient //10.10.10.10/SHARE -N` — upload shell |
| HIGH | SMB null session | `enum4linux-ng -A 10.10.10.10` |
| HIGH | SNMP default community | `snmpwalk -v2c -c public 10.10.10.10` |
| HIGH | RPC null session (users enumerated) | `rpcclient -U "" -N 10.10.10.10 -c "enumdomusers"` |
| MEDIUM | Interesting web paths | `curl -v http://10.10.10.10/admin` |
| MEDIUM | Nikto vulnerabilities | Investigate manually |
| MEDIUM | Enumerated SMB users | Use for password attacks |
| INFO | WinRM available | `evil-winrm -i 10.10.10.10 -u USER -p PASS` |

`REPORT.json` contains the same data in structured form for piping into other tools.

## OSCP Exam Workflow

### Before the Exam

1. Run `setup.sh` on your Kali VM
2. Test on HTB/Proving Grounds boxes
3. Practice the resume workflow — start a scan, `Ctrl+C`, `--resume`
4. Get familiar with the report format so you know where to look

### During the Exam

```bash
# Fire off all targets immediately
sudo python3 offsec-enum-ng.py 192.168.x.10 -o target1 &
sudo python3 offsec-enum-ng.py 192.168.x.11 -o target2 &
sudo python3 offsec-enum-ng.py 192.168.x.12 -o target3 &

# If a scan is too slow, kill and restart with quick mode
sudo python3 offsec-enum-ng.py 192.168.x.10 -o target1_quick -q

# If you need DNS zone transfers
sudo python3 offsec-enum-ng.py 192.168.x.10 -o target1 -d megacorp.local

# Interrupted? Resume without re-running completed phases
sudo python3 offsec-enum-ng.py 192.168.x.10 -o target1_10.10.10.10_20250217 --resume
```

**Priority review order**: Check `REPORT.md` critical findings first → web/ and smb/ directories → winrm/ if 5985 is open → msrpc/ for null session results → snmp/ if port 161 is open → everything else.

### Time-Saving Tips

- Run all targets in parallel from the start
- Open `REPORT.md` as soon as enumeration finishes — critical findings are at the top
- Use `-q` for a fast first pass, then full scan if you need more coverage
- The `--resume` flag means `Ctrl+C` is never wasted work
- `REPORT.json` can be parsed with `jq` for quick filtering:
  ```bash
  jq '.findings[] | select(.severity == "CRITICAL")' REPORT.json
  ```

## Customization

### Add a Custom Enumerator

Add a method to `EnumerationEngine` and register it in `_classify_port()`:

```python
def enumerate_redis(self, port):
    """Enumerate Redis."""
    self.logger.info("Enumerating Redis on port %d...", port)
    redis_dir = self._ensure_output_dir("redis")

    result = self.run_command(
        ["nmap", "-p", str(port),
         "--script=redis-info,redis-brute",
         self.target],
        output_file=redis_dir / f"nmap_redis_{port}.txt",
        timeout=self._timeout('nmap_nse'),
    )
    if result.success:
        self.logger.success("Redis enumeration complete (%.1fs)", result.duration)
```

Then add a match clause to `_classify_port()`:

```python
if 'redis' in service or port == 6379:
    tasks.append((self.enumerate_redis, port))
```

### Change Wordlists

Edit the `wordlist` variable in `enumerate_http()`:

```python
wordlist = "/usr/share/wordlists/your-custom-list.txt"
```

### Adjust Timeouts

Use the CLI multiplier for global scaling, or edit `TIMEOUT_DEFAULTS` for per-tool control:

```python
TIMEOUT_DEFAULTS = {
    'gobuster': 3600,   # increase for huge wordlists
    'nikto': 900,       # more time for thorough scans
    ...
}
```

## Troubleshooting

**Permission errors** — most scans need root for raw sockets:
```bash
sudo python3 offsec-enum-ng.py <target>
```

**Missing tools** — re-run setup or install individually:
```bash
sudo ./setup.sh
# or
sudo apt install -y <tool-name>
```

**Slow scans** — use quick mode or scale timeouts:
```bash
sudo python3 offsec-enum-ng.py 10.10.10.10 -q
sudo python3 offsec-enum-ng.py 10.10.10.10 --timeout-multiplier 0.5
```

**Resume not working** — `--resume` needs the exact output directory path (the timestamped one):
```bash
sudo python3 offsec-enum-ng.py 10.10.10.10 -o enum_results_10.10.10.10_20250217_143052 --resume
```

## Exam Compliance

- Enumeration only — no automated exploitation
- No Metasploit auto-exploit modules
- Manual verification still required
- Screenshots and notes are your responsibility

## Legal

Authorized penetration testing and education only. Never run against systems you don't have explicit permission to test.

## License

Free to use for OSCP preparation and ethical hacking education.
