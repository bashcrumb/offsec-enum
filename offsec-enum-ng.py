#!/usr/bin/env python3
"""
offsec-enum-ng — Automated Enumeration for OSCP
Comprehensive network and service enumeration for penetration testing
"""

import subprocess
import os
import sys
import argparse
import ipaddress
import re
import json
import logging
import time
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Custom log level — SUCCESS sits between INFO (20) and WARNING (30)
# ---------------------------------------------------------------------------

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


def _log_success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)


logging.Logger.success = _log_success


# ---------------------------------------------------------------------------
# ANSI colors + colored console formatter
# ---------------------------------------------------------------------------

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ColoredFormatter(logging.Formatter):
    """Console formatter that reproduces the original [*]/[+]/[!]/[-] prefixes."""

    LEVEL_MAP = {
        logging.DEBUG:    (Colors.OKCYAN,  '[~]'),
        logging.INFO:     (Colors.OKBLUE,  '[*]'),
        SUCCESS:          (Colors.OKGREEN, '[+]'),
        logging.WARNING:  (Colors.WARNING, '[!]'),
        logging.ERROR:    (Colors.FAIL,    '[-]'),
        logging.CRITICAL: (Colors.FAIL,    '[!!]'),
    }

    def format(self, record):
        color, prefix = self.LEVEL_MAP.get(
            record.levelno, (Colors.ENDC, '[?]')
        )
        return f"{color}{prefix}{Colors.ENDC} {record.getMessage()}"


def setup_logging(log_file_path, verbosity=logging.INFO):
    """Configure the ``oscp_enum`` logger with console + file handlers."""
    logger = logging.getLogger('oscp_enum')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(verbosity)
    console.setFormatter(ColoredFormatter())
    logger.addHandler(console)

    file_handler = logging.FileHandler(str(log_file_path), mode='a')
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    """Structured result from a single command execution."""
    command: List[str]
    success: bool
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


@dataclass
class PortInfo:
    """Structured information about a discovered open port."""
    port: int
    protocol: str       # "tcp" or "udp"
    service: str        # nmap service name
    product: str        # e.g., "Apache httpd", "OpenSSH"
    version: str        # e.g., "2.4.49", "8.9p1"
    tunnel: str         # e.g., "ssl" — key for HTTPS detection
    nse_scripts: Dict[str, str]

    @property
    def version_string(self):
        """Human-readable product/version string for reports."""
        parts = [p for p in (self.product, self.version) if p]
        return ' '.join(parts) if parts else self.service

    def to_dict(self):
        """Serialize for JSON checkpoint."""
        return {
            'port': self.port,
            'protocol': self.protocol,
            'service': self.service,
            'product': self.product,
            'version': self.version,
            'tunnel': self.tunnel,
            'nse_scripts': self.nse_scripts,
        }

    @classmethod
    def from_dict(cls, d):
        """Deserialize from JSON checkpoint."""
        return cls(
            port=d['port'],
            protocol=d['protocol'],
            service=d['service'],
            product=d.get('product', ''),
            version=d.get('version', ''),
            tunnel=d.get('tunnel', ''),
            nse_scripts=d.get('nse_scripts', {}),
        )


@dataclass
class Finding:
    """An actionable finding extracted from tool output."""
    severity: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str       # e.g., "anonymous_access", "default_creds"
    port: int
    service: str
    description: str
    evidence: str       # relevant output snippet
    next_step: str      # actionable recommendation

    # Sort order: CRITICAL first
    _SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

    def __lt__(self, other):
        return self._SEV_ORDER.get(self.severity, 5) < self._SEV_ORDER.get(other.severity, 5)


# ---------------------------------------------------------------------------
# Output file parsers (Phase 7.1) — all fault-tolerant
# ---------------------------------------------------------------------------

INTERESTING_PATHS = {
    '/admin', '/administrator', '/backup', '/backups', '/upload', '/uploads',
    '/config', '/configuration', '/phpmyadmin', '/manager', '/console',
    '/debug', '/server-status', '/server-info', '/.env', '/.git',
    '/wp-admin', '/wp-login', '/api', '/swagger', '/graphql',
}

INTERESTING_EXTENSIONS = {'.bak', '.old', '.conf', '.config', '.sql', '.zip',
                          '.tar', '.gz', '.log', '.env', '.key', '.pem'}


def parse_gobuster_results(filepath):
    """Parse gobuster output → list of dicts with path, status, size."""
    results = []
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return results

    try:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Format (gobuster <3.6): /path (Status: 200) [Size: 1234]
                # Format (gobuster 3.6+): /path  [Status=200, Size=1234, ...]
                m = re.match(
                    r'^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]',
                    line,
                )
                if not m:
                    m = re.match(
                        r'^(/\S*)\s+\[Status=(\d+),\s*Size=(\d+)',
                        line,
                    )
                if m:
                    entry = {
                        'path': m.group(1),
                        'status': int(m.group(2)),
                        'size': int(m.group(3)),
                    }
                    entry['interesting'] = (
                        entry['status'] in (200, 301, 302, 403)
                        and (
                            entry['path'].lower() in INTERESTING_PATHS
                            or any(entry['path'].lower().endswith(ext) for ext in INTERESTING_EXTENSIONS)
                        )
                    )
                    results.append(entry)
    except Exception:
        pass
    return results


def parse_nikto_results(filepath):
    """Parse nikto output → list of vulnerability lines."""
    findings = []
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return findings

    try:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('+') and 'OSVDB' in line:
                    findings.append(line)
                elif line.startswith('+') and any(kw in line.lower() for kw in
                        ['vulnerability', 'vulnerable', 'default', 'backdoor',
                         'disclosure', 'misconfiguration', 'outdated']):
                    findings.append(line)
    except Exception:
        pass
    return findings


def parse_enum4linux_results(filepath):
    """Parse enum4linux output → dict with users, shares, os_info, password_policy."""
    result = {'users': [], 'shares': [], 'os_info': '', 'password_policy': '',
              'null_session': False}
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return result

    try:
        content = path.read_text(errors='replace')
        for line in content.split('\n'):
            if 'user:' in line.lower() and '[' in line:
                result['users'].append(line.strip())
            if 'Disk' in line or 'IPC' in line or 'Print' in line:
                if '\\\\' in line or '//' in line:
                    result['shares'].append(line.strip())
            if 'OS=' in line or 'os info' in line.lower():
                result['os_info'] = line.strip()
            if 'password' in line.lower() and 'policy' in line.lower():
                result['password_policy'] = line.strip()
            if 'null session' in line.lower() and 'success' in line.lower():
                result['null_session'] = True
    except Exception:
        pass
    return result


def parse_smbmap_results(filepath):
    """Parse smbmap output → list of dicts with share, permissions."""
    shares = []
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return shares

    try:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('-') or line.startswith('['):
                    continue
                parts = line.split()
                if len(parts) >= 3 and any(
                    perm in line.upper() for perm in ['READ', 'WRITE', 'NO ACCESS']
                ):
                    share_name = parts[0]
                    perms = ' '.join(parts[1:])
                    readable = 'READ' in perms.upper()
                    writable = 'WRITE' in perms.upper()
                    shares.append({
                        'name': share_name,
                        'permissions': perms,
                        'readable': readable,
                        'writable': writable,
                    })
    except Exception:
        pass
    return shares


def parse_ftp_nmap(filepath):
    """Parse nmap FTP script output → dict with anon_access flag."""
    result = {'anonymous_access': False, 'details': ''}
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return result

    try:
        content = path.read_text(errors='replace')
        if 'Anonymous FTP login allowed' in content or 'ftp-anon: Anonymous' in content:
            result['anonymous_access'] = True
        result['details'] = content.strip()[:500]
    except Exception:
        pass
    return result


def parse_snmpwalk_results(filepath):
    """Parse snmpwalk output → dict with system_info, entries list."""
    result = {'system_info': '', 'entries': [], 'has_data': False}
    path = Path(filepath)
    if not path.exists() or path.stat().st_size == 0:
        return result

    try:
        with open(path, errors='replace') as f:
            lines = f.readlines()
        if lines:
            result['has_data'] = True
            result['entries'] = [l.strip() for l in lines[:50]]
            for line in lines:
                if 'sysDescr' in line or 'SNMPv2-MIB::sysDescr' in line:
                    result['system_info'] = line.strip()
                    break
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Timeout configuration (Phase 6.3)
# ---------------------------------------------------------------------------

TIMEOUT_DEFAULTS = {
    'nmap_initial':  3600,
    'nmap_vuln':     1800,
    'nmap_udp':      1800,
    'nikto':          600,
    'gobuster':      2400,
    'whatweb':        300,
    'enum4linux':     600,
    'smbmap':         300,
    'smbclient':      300,
    'nmap_nse':       300,
    'onesixtyone':    300,
    'snmpwalk':       600,
    'dig':            300,
    'dnsrecon':       600,
    'dnsenum':        600,
    'ldapsearch':     300,
    'rpcinfo':        300,
    'showmount':      300,
    'smtp_user_enum': 600,
    'rdp':            300,
    'default':        600,
}


# ---------------------------------------------------------------------------
# State manager (Phase 6.1 + 6.2)
# ---------------------------------------------------------------------------

class StateManager:
    """Checkpoint / resume manager.

    Persists scan progress to ``state.json`` inside the output directory
    so the tool can resume after a Ctrl-C or crash.
    """

    STATE_FILE = 'state.json'

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.state_path = self.output_dir / self.STATE_FILE
        self.target: str = ''
        self.start_time: str = ''
        self.open_ports: Dict[int, dict] = {}
        self.completed_phases: List[str] = []
        self.completed_enumerations: Set[str] = set()  # "func_name:port"
        self.failed_commands: List[dict] = []

    # ---- persistence ----

    def save(self):
        """Write current state to disk."""
        data = {
            'target': self.target,
            'start_time': self.start_time,
            'open_ports': self.open_ports,
            'completed_phases': self.completed_phases,
            'completed_enumerations': sorted(self.completed_enumerations),
            'failed_commands': self.failed_commands,
        }
        tmp_path = self.state_path.with_suffix('.tmp')
        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=2)
        tmp_path.replace(self.state_path)

    def load(self):
        """Load state from disk. Returns True on success."""
        if not self.state_path.exists():
            return False
        with open(self.state_path) as f:
            data = json.load(f)
        self.target = data.get('target', '')
        self.start_time = data.get('start_time', '')
        self.open_ports = data.get('open_ports', {})
        self.completed_phases = data.get('completed_phases', [])
        self.completed_enumerations = set(data.get('completed_enumerations', []))
        self.failed_commands = data.get('failed_commands', [])
        return True

    # ---- convenience ----

    def phase_done(self, phase_name):
        """Record a phase as complete and checkpoint."""
        if phase_name not in self.completed_phases:
            self.completed_phases.append(phase_name)
        self.save()

    def is_phase_done(self, phase_name):
        return phase_name in self.completed_phases

    def enumeration_done(self, func_name, port):
        """Record an individual enumeration task as complete and checkpoint."""
        key = f"{func_name}:{port}"
        self.completed_enumerations.add(key)
        self.save()

    def is_enumeration_done(self, func_name, port):
        return f"{func_name}:{port}" in self.completed_enumerations

    def sync_open_ports(self, open_ports_dict):
        """Snapshot current open_ports to state (serialized)."""
        self.open_ports = {
            str(port): pi.to_dict()
            for port, pi in open_ports_dict.items()
        }

    def sync_failed_commands(self, failed_list):
        """Snapshot engine's failed_commands (List[CommandResult]) into state."""
        self.failed_commands = [
            {
                'command': ' '.join(cr.command),
                'duration': round(cr.duration, 1),
                'timed_out': cr.timed_out,
                'stderr': cr.stderr[:500],
            }
            for cr in failed_list
        ]

    def restore_open_ports(self):
        """Deserialize open_ports back to Dict[int, PortInfo]."""
        return {
            int(port_str): PortInfo.from_dict(d)
            for port_str, d in self.open_ports.items()
        }

    @property
    def exists(self):
        return self.state_path.exists()


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def validate_target(target):
    """Validate that *target* is a legal IPv4/IPv6 address or RFC-1123 hostname."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if len(target) > 253:
        raise ValueError(
            f"Invalid target '{target}': hostname exceeds 253 characters"
        )

    labels = target.rstrip('.').split('.')
    if not labels or any(label == '' for label in labels):
        raise ValueError(
            f"Invalid target '{target}': contains empty labels (consecutive dots)"
        )

    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValueError(
                f"Invalid target '{target}': label '{label}' violates RFC 1123 "
                f"(alphanumeric and hyphens only, 1-63 chars, no leading/trailing hyphen)"
            )

    return target


def validate_ports(port_string):
    """Validate a user-supplied port specification."""
    segments = port_string.split(',')
    for segment in segments:
        segment = segment.strip()
        if not segment:
            raise ValueError(
                f"Invalid port specification '{port_string}': empty segment"
            )

        if '-' in segment:
            parts = segment.split('-', 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise ValueError(
                    f"Invalid port range '{segment}': expected START-END"
                )
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(
                    f"Invalid port range '{segment}': non-numeric values"
                )
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise ValueError(
                    f"Invalid port range '{segment}': ports must be 1-65535"
                )
            if start > end:
                raise ValueError(
                    f"Invalid port range '{segment}': start ({start}) > end ({end})"
                )
        else:
            try:
                port = int(segment)
            except ValueError:
                raise ValueError(
                    f"Invalid port '{segment}': non-numeric value"
                )
            if not 1 <= port <= 65535:
                raise ValueError(
                    f"Invalid port '{segment}': must be 1-65535"
                )

    return port_string


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class EnumerationEngine:
    def __init__(self, target, output_dir, ports=None, quick=False,
                 verbosity=logging.INFO, threads=3, domain=None,
                 timeout_multiplier=1.0, resume=False):
        self.target = target
        self.output_dir = Path(output_dir)
        self.ports = ports
        self.quick = quick
        self.threads = max(1, threads)
        self.domain: Optional[str] = domain
        self.timeout_multiplier = max(0.1, timeout_multiplier)
        self.open_ports: Dict[int, PortInfo] = {}
        self.failed_commands: List[CommandResult] = []
        self._lock = threading.Lock()

        # Create base output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up structured logging
        log_file = self.output_dir / f"enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.logger = setup_logging(log_file, verbosity=verbosity)

        # State manager
        self.state = StateManager(self.output_dir)
        self._resume_mode = resume

        if resume:
            if self.state.load():
                self.logger.info("Resuming from checkpoint: %s", self.state.state_path)
                self.open_ports = self.state.restore_open_ports()
                # Restore previous run's failures so reports are cumulative
                for fc in self.state.failed_commands:
                    self.failed_commands.append(CommandResult(
                        command=fc.get('command', '').split(),
                        success=False,
                        stdout='',
                        stderr=fc.get('stderr', ''),
                        duration=fc.get('duration', 0.0),
                        timed_out=fc.get('timed_out', False),
                    ))
                self.logger.info(
                    "Restored %d open port(s), %d completed phase(s), "
                    "%d completed enumeration(s), %d failed command(s)",
                    len(self.open_ports),
                    len(self.state.completed_phases),
                    len(self.state.completed_enumerations),
                    len(self.failed_commands),
                )
            else:
                self.logger.error(
                    "No state.json found in %s — cannot resume. "
                    "Run without --resume first.", self.output_dir,
                )
                raise FileNotFoundError(
                    f"state.json not found in {self.output_dir}"
                )
        else:
            # Fresh run — initialize state
            self.state.target = target
            self.state.start_time = datetime.now().isoformat()

    # ------------------------------------------------------------------
    # Timeout helper (Phase 6.3)
    # ------------------------------------------------------------------

    def _timeout(self, tool_key):
        """Return the timeout (seconds) for *tool_key*, scaled by the multiplier."""
        base = TIMEOUT_DEFAULTS.get(tool_key, TIMEOUT_DEFAULTS['default'])
        return int(base * self.timeout_multiplier)

    # ------------------------------------------------------------------
    # Dynamic output directory helper
    # ------------------------------------------------------------------

    def _ensure_output_dir(self, subdir):
        """Create and return ``output_dir / subdir``, creating parents as needed."""
        path = self.output_dir / subdir
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ------------------------------------------------------------------
    # Command execution (thread-safe)
    # ------------------------------------------------------------------

    def run_command(self, command, output_file=None, timeout=None):
        """Execute a command given as a *list* of arguments.

        Thread-safe: failed results are appended under a lock.
        Returns a :class:`CommandResult` with structured output.
        """
        display_cmd = ' '.join(command)
        start = time.monotonic()

        try:
            self.logger.info("Running: %s", display_cmd)
            result = subprocess.run(
                command,
                capture_output=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
            )
            elapsed = time.monotonic() - start

            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n=== STDERR ===\n")
                        f.write(result.stderr)

            cmd_result = CommandResult(
                command=command,
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                duration=elapsed,
            )

            if not cmd_result.success:
                self.logger.warning(
                    "Command exited %d (%.1fs): %s",
                    result.returncode, elapsed, display_cmd,
                )
                with self._lock:
                    self.failed_commands.append(cmd_result)

            return cmd_result

        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            self.logger.warning("Command timed out after %.1fs: %s", elapsed, display_cmd)
            cmd_result = CommandResult(
                command=command,
                success=False,
                stdout="",
                stderr="Timeout",
                duration=elapsed,
                timed_out=True,
            )
            with self._lock:
                self.failed_commands.append(cmd_result)
            return cmd_result

        except Exception as e:
            elapsed = time.monotonic() - start
            self.logger.error("Error running command: %s", e)
            cmd_result = CommandResult(
                command=command,
                success=False,
                stdout="",
                stderr=str(e),
                duration=elapsed,
            )
            with self._lock:
                self.failed_commands.append(cmd_result)
            return cmd_result

    # ------------------------------------------------------------------
    # Port-arg helper
    # ------------------------------------------------------------------

    def _port_args(self):
        """Return the nmap port-flag arguments as a list."""
        if self.ports:
            return ["-p", self.ports]
        if self.quick:
            return ["-p", "1-10000"]
        return ["-p-"]

    # ------------------------------------------------------------------
    # Nmap scanning & parsing
    # ------------------------------------------------------------------

    def initial_nmap_scan(self):
        """Quick initial port scan to identify open ports."""
        self.logger.info("Starting initial port discovery...")

        nmap_dir = self._ensure_output_dir("nmap")
        output_base = str(nmap_dir / "initial_scan")

        command = [
            "nmap", "-sV", "-sC",
            *self._port_args(),
            "-oA", output_base,
            "--open", "-T4",
            self.target,
        ]

        cmd_result = self.run_command(command, timeout=self._timeout('nmap_initial'))

        if cmd_result.success:
            self.logger.success("Initial scan complete (%.1fs)", cmd_result.duration)
            xml_path = Path(output_base + ".xml")
            if xml_path.exists():
                self.parse_nmap_xml(xml_path)
            else:
                self.logger.warning(
                    "XML output not found at %s, falling back to stdout parsing",
                    xml_path,
                )
                self.parse_nmap_output(cmd_result.stdout)
        else:
            self.logger.error("Initial scan failed")

    def parse_nmap_xml(self, xml_path):
        """Parse nmap XML output for structured port/service data."""
        try:
            tree = ET.parse(str(xml_path))
            root = tree.getroot()
        except ET.ParseError as e:
            self.logger.error("Failed to parse nmap XML: %s", e)
            return

        for host in root.findall('.//host'):
            ports_elem = host.find('ports')
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall('port'):
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue

                port_id = int(port_elem.get('portid', '0'))
                protocol = port_elem.get('protocol', 'tcp')

                svc = port_elem.find('service')
                if svc is not None:
                    service = svc.get('name', 'unknown')
                    product = svc.get('product', '')
                    version = svc.get('version', '')
                    tunnel = svc.get('tunnel', '')
                else:
                    service = 'unknown'
                    product = ''
                    version = ''
                    tunnel = ''

                nse_scripts = {}
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id', '')
                    script_output = script_elem.get('output', '')
                    if script_id:
                        nse_scripts[script_id] = script_output

                port_info = PortInfo(
                    port=port_id, protocol=protocol, service=service,
                    product=product, version=version, tunnel=tunnel,
                    nse_scripts=nse_scripts,
                )
                self.open_ports[port_id] = port_info
                self.logger.success(
                    "Found open port: %d/%s (%s)",
                    port_id, protocol, port_info.version_string,
                )

    def parse_nmap_output(self, nmap_output):
        """Fallback: parse nmap stdout to extract open ports and services."""
        for line in nmap_output.split('\n'):
            if 'open' in line and ('/tcp' in line or '/udp' in line):
                parts = line.split()
                try:
                    port_proto = parts[0].split('/')
                    port = int(port_proto[0])
                    protocol = port_proto[1] if len(port_proto) > 1 else 'tcp'
                    service = parts[2] if len(parts) > 2 else "unknown"
                    self.open_ports[port] = PortInfo(
                        port=port, protocol=protocol, service=service,
                        product='', version='', tunnel='', nse_scripts={},
                    )
                    self.logger.success("Found open port: %d/%s (%s)", port, protocol, service)
                except (ValueError, IndexError):
                    continue

    # ------------------------------------------------------------------
    # UDP scan (independent of TCP results)
    # ------------------------------------------------------------------

    def udp_scan(self):
        """Run a UDP top-ports scan and merge results into open_ports."""
        if self.quick:
            self.logger.info("Skipping UDP scan (quick mode)")
            return

        self.logger.info("Running UDP scan (top 100 ports)...")
        nmap_dir = self._ensure_output_dir("nmap")
        udp_output_base = str(nmap_dir / "udp_scan")

        udp_cmd = [
            "nmap", "-sU", "-sV",
            "--top-ports", "100",
            "-oA", udp_output_base,
            self.target,
        ]
        result = self.run_command(udp_cmd, timeout=self._timeout('nmap_udp'))

        if result.success:
            self.logger.success("UDP scan complete (%.1fs)", result.duration)
            xml_path = Path(udp_output_base + ".xml")
            if xml_path.exists():
                self.parse_nmap_xml(xml_path)
            else:
                self.logger.debug("UDP XML not found; UDP results not merged")

    def detailed_nmap_scans(self):
        """Run detailed nmap scans on discovered TCP ports."""
        if not self.open_ports:
            self.logger.warning("No open ports found, skipping detailed scans")
            return

        tcp_ports = [
            str(p) for p, pi in self.open_ports.items()
            if pi.protocol == 'tcp'
        ]
        if not tcp_ports:
            self.logger.info("No TCP ports for detailed scans")
            return

        ports_str = ','.join(tcp_ports)

        self.logger.info("Running NSE vulnerability scripts...")
        nmap_dir = self._ensure_output_dir("nmap")
        vuln_output_base = str(nmap_dir / "vuln_scan")
        vuln_cmd = [
            "nmap", "-sV", "--script=vuln",
            "-p", ports_str,
            "-oA", vuln_output_base,
            self.target,
        ]
        result = self.run_command(vuln_cmd, timeout=self._timeout('nmap_vuln'))
        if result.success:
            self.logger.success("Vulnerability scan complete (%.1fs)", result.duration)

    # ------------------------------------------------------------------
    # Service enumeration — original services
    # ------------------------------------------------------------------

    def _is_https(self, port_info):
        """Determine if a port is serving HTTPS based on all available signals."""
        return (
            port_info.tunnel == 'ssl'
            or 'https' in port_info.service.lower()
            or 'ssl' in port_info.service.lower()
            or port_info.port in (443, 8443)
        )

    def enumerate_http(self, port):
        """Enumerate HTTP/HTTPS services."""
        self.logger.info("Enumerating HTTP on port %d...", port)

        port_info = self.open_ports[port]
        protocol = "https" if self._is_https(port_info) else "http"
        url = f"{protocol}://{self.target}:{port}"

        web_dir = self._ensure_output_dir("web")

        # Nikto
        nikto_output = str(web_dir / f"nikto_{port}.txt")
        nikto_cmd = ["nikto", "-h", url, "-output", nikto_output]
        result = self.run_command(nikto_cmd, timeout=self._timeout('nikto'))
        if result.success:
            self.logger.success("Nikto scan complete for port %d (%.1fs)", port, result.duration)
        elif result.stderr:
            Path(web_dir / f"nikto_{port}.stderr").write_text(
                result.stderr, errors='replace')

        # Gobuster
        gobuster_output = str(web_dir / f"gobuster_{port}.txt")
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

        if os.path.exists(wordlist):
            gobuster_cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-o", gobuster_output,
                "-t", "50",
                "-x", "php,txt,html,jsp,asp,aspx",
            ]
            result = self.run_command(gobuster_cmd, timeout=self._timeout('gobuster'))
            if result.success:
                self.logger.success("Gobuster complete for port %d (%.1fs)", port, result.duration)
            elif result.stderr:
                Path(web_dir / f"gobuster_{port}.stderr").write_text(
                    result.stderr, errors='replace')
        else:
            self.logger.warning("Wordlist not found: %s", wordlist)

        # WhatWeb
        whatweb_output = str(web_dir / f"whatweb_{port}.txt")
        whatweb_cmd = [
            "whatweb", url,
            "-a", "3",
            f"--log-verbose={whatweb_output}",
        ]
        result = self.run_command(whatweb_cmd, timeout=self._timeout('whatweb'))
        if result.success:
            self.logger.success("WhatWeb complete for port %d (%.1fs)", port, result.duration)
        elif result.stderr:
            Path(web_dir / f"whatweb_{port}.stderr").write_text(
                result.stderr, errors='replace')

    def enumerate_smb(self, port):
        """Enumerate SMB services."""
        self.logger.info("Enumerating SMB on port %d...", port)

        smb_dir = self._ensure_output_dir("smb")

        enum4linux_output = smb_dir / "enum4linux.txt"
        enum4linux_cmd = ["enum4linux", "-a", self.target]
        result = self.run_command(enum4linux_cmd, output_file=enum4linux_output,
                                  timeout=self._timeout('enum4linux'))
        if result.success:
            self.logger.success("enum4linux complete (%.1fs)", result.duration)

        smbmap_output = smb_dir / "smbmap.txt"
        smbmap_cmd = ["smbmap", "-H", self.target]
        result = self.run_command(smbmap_cmd, output_file=smbmap_output,
                                  timeout=self._timeout('smbmap'))
        if result.success:
            self.logger.success("smbmap complete (%.1fs)", result.duration)

        smbclient_output = smb_dir / "smbclient.txt"
        smbclient_cmd = ["smbclient", "-L", f"//{self.target}", "-N"]
        result = self.run_command(smbclient_cmd, output_file=smbclient_output,
                                  timeout=self._timeout('smbclient'))
        if result.success:
            self.logger.success("smbclient complete (%.1fs)", result.duration)

        nmap_smb_output = smb_dir / f"nmap_smb_{port}.txt"
        nmap_smb_cmd = [
            "nmap", "-p", str(port),
            "--script=smb-enum-shares,smb-enum-users,smb-os-discovery",
            self.target,
        ]
        result = self.run_command(nmap_smb_cmd, output_file=nmap_smb_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("NSE SMB scripts complete (%.1fs)", result.duration)

    def enumerate_ftp(self, port):
        """Enumerate FTP services."""
        self.logger.info("Enumerating FTP on port %d...", port)

        ftp_dir = self._ensure_output_dir("ftp")

        ftp_output = ftp_dir / f"ftp_enum_{port}.txt"
        nmap_ftp_cmd = [
            "nmap", "-p", str(port),
            "--script=ftp-anon,ftp-bounce,ftp-syst",
            self.target,
        ]
        result = self.run_command(nmap_ftp_cmd, output_file=ftp_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("FTP enumeration complete (%.1fs)", result.duration)

    def enumerate_ssh(self, port):
        """Enumerate SSH services."""
        self.logger.info("Enumerating SSH on port %d...", port)

        misc_dir = self._ensure_output_dir("misc")

        ssh_output = misc_dir / f"ssh_enum_{port}.txt"
        nmap_ssh_cmd = [
            "nmap", "-p", str(port),
            "--script=ssh-auth-methods,ssh-hostkey",
            self.target,
        ]
        result = self.run_command(nmap_ssh_cmd, output_file=ssh_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("SSH enumeration complete (%.1fs)", result.duration)

    def enumerate_mysql(self, port):
        """Enumerate MySQL services."""
        self.logger.info("Enumerating MySQL on port %d...", port)

        misc_dir = self._ensure_output_dir("misc")

        mysql_output = misc_dir / f"mysql_enum_{port}.txt"
        nmap_mysql_cmd = [
            "nmap", "-p", str(port),
            "--script=mysql-info,mysql-databases,mysql-empty-password",
            self.target,
        ]
        result = self.run_command(nmap_mysql_cmd, output_file=mysql_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("MySQL enumeration complete (%.1fs)", result.duration)

    def enumerate_mssql(self, port):
        """Enumerate MSSQL services."""
        self.logger.info("Enumerating MSSQL on port %d...", port)

        misc_dir = self._ensure_output_dir("misc")

        mssql_output = misc_dir / f"mssql_enum_{port}.txt"
        nmap_mssql_cmd = [
            "nmap", "-p", str(port),
            "--script=ms-sql-info,ms-sql-empty-password,ms-sql-config",
            self.target,
        ]
        result = self.run_command(nmap_mssql_cmd, output_file=mssql_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("MSSQL enumeration complete (%.1fs)", result.duration)

    # ------------------------------------------------------------------
    # Service enumeration — Phase 5 new services
    # ------------------------------------------------------------------

    def enumerate_snmp(self, port):
        """Enumerate SNMP services."""
        self.logger.info("Enumerating SNMP on port %d...", port)

        snmp_dir = self._ensure_output_dir("snmp")

        community_list = "/usr/share/seclists/Discovery/SNMP/snmp.txt"
        if os.path.exists(community_list):
            onesixty_output = snmp_dir / "onesixtyone.txt"
            onesixty_cmd = ["onesixtyone", "-c", community_list, self.target]
            result = self.run_command(onesixty_cmd, output_file=onesixty_output,
                                      timeout=self._timeout('onesixtyone'))
            if result.success:
                self.logger.success("onesixtyone complete (%.1fs)", result.duration)
        else:
            self.logger.warning("SNMP community list not found: %s", community_list)

        snmpwalk_output = snmp_dir / "snmpwalk_full.txt"
        snmpwalk_cmd = ["snmpwalk", "-v2c", "-c", "public", self.target]
        result = self.run_command(snmpwalk_cmd, output_file=snmpwalk_output,
                                  timeout=self._timeout('snmpwalk'))
        if result.success:
            self.logger.success("snmpwalk (full) complete (%.1fs)", result.duration)

        procs_output = snmp_dir / "snmpwalk_processes.txt"
        procs_cmd = [
            "snmpwalk", "-v2c", "-c", "public",
            self.target, "1.3.6.1.2.1.25.4.2.1.2",
        ]
        result = self.run_command(procs_cmd, output_file=procs_output,
                                  timeout=self._timeout('snmpwalk'))
        if result.success:
            self.logger.success("snmpwalk (processes) complete (%.1fs)", result.duration)

        tcpports_output = snmp_dir / "snmpwalk_tcpports.txt"
        tcpports_cmd = [
            "snmpwalk", "-v2c", "-c", "public",
            self.target, "1.3.6.1.2.1.6.13.1.3",
        ]
        result = self.run_command(tcpports_cmd, output_file=tcpports_output,
                                  timeout=self._timeout('snmpwalk'))
        if result.success:
            self.logger.success("snmpwalk (TCP ports) complete (%.1fs)", result.duration)

    def enumerate_dns(self, port):
        """Enumerate DNS services."""
        self.logger.info("Enumerating DNS on port %d...", port)

        dns_dir = self._ensure_output_dir("dns")

        if self.domain:
            axfr_output = dns_dir / "dig_axfr.txt"
            axfr_cmd = ["dig", "axfr", f"@{self.target}", self.domain]
            result = self.run_command(axfr_cmd, output_file=axfr_output,
                                      timeout=self._timeout('dig'))
            if result.success:
                self.logger.success("dig axfr complete (%.1fs)", result.duration)
        else:
            self.logger.info("Skipping zone transfer (no --domain specified)")

        dnsrecon_output = dns_dir / "dnsrecon.txt"
        dnsrecon_target = self.domain if self.domain else self.target
        dnsrecon_cmd = ["dnsrecon", "-d", dnsrecon_target, "-t", "std"]
        result = self.run_command(dnsrecon_cmd, output_file=dnsrecon_output,
                                  timeout=self._timeout('dnsrecon'))
        if result.success:
            self.logger.success("dnsrecon complete (%.1fs)", result.duration)

        dnsenum_output = dns_dir / "dnsenum.txt"
        dnsenum_target = self.domain if self.domain else self.target
        dnsenum_cmd = ["dnsenum", dnsenum_target]
        result = self.run_command(dnsenum_cmd, output_file=dnsenum_output,
                                  timeout=self._timeout('dnsenum'))
        if result.success:
            self.logger.success("dnsenum complete (%.1fs)", result.duration)

    def enumerate_ldap(self, port):
        """Enumerate LDAP services."""
        self.logger.info("Enumerating LDAP on port %d...", port)

        ldap_dir = self._ensure_output_dir("ldap")

        ldap_scheme = "ldaps" if port == 636 else "ldap"

        basedn_output = ldap_dir / "ldap_basedn.txt"
        basedn_cmd = [
            "ldapsearch", "-x",
            "-H", f"{ldap_scheme}://{self.target}:{port}",
            "-b", "", "-s", "base", "namingContexts",
        ]
        result = self.run_command(basedn_cmd, output_file=basedn_output,
                                  timeout=self._timeout('ldapsearch'))
        if result.success:
            self.logger.success("LDAP base DN discovery complete (%.1fs)", result.duration)

        anon_output = ldap_dir / "ldap_anonymous.txt"
        anon_cmd = [
            "ldapsearch", "-x",
            "-H", f"{ldap_scheme}://{self.target}:{port}",
            "-b", "", "(objectClass=*)",
        ]
        result = self.run_command(anon_cmd, output_file=anon_output,
                                  timeout=self._timeout('ldapsearch'))
        if result.success:
            self.logger.success("LDAP anonymous bind complete (%.1fs)", result.duration)

        nse_output = ldap_dir / "nmap_ldap.txt"
        nse_cmd = [
            "nmap", "-p", str(port),
            "--script=ldap-rootdse,ldap-search",
            self.target,
        ]
        result = self.run_command(nse_cmd, output_file=nse_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("NSE LDAP scripts complete (%.1fs)", result.duration)

    def enumerate_nfs(self, port):
        """Enumerate NFS / RPC services."""
        self.logger.info("Enumerating NFS/RPC on port %d...", port)

        nfs_dir = self._ensure_output_dir("nfs")

        rpcinfo_output = nfs_dir / "rpcinfo.txt"
        rpcinfo_cmd = ["rpcinfo", "-p", self.target]
        result = self.run_command(rpcinfo_cmd, output_file=rpcinfo_output,
                                  timeout=self._timeout('rpcinfo'))
        if result.success:
            self.logger.success("rpcinfo complete (%.1fs)", result.duration)

        showmount_output = nfs_dir / "showmount.txt"
        showmount_cmd = ["showmount", "-e", self.target]
        result = self.run_command(showmount_cmd, output_file=showmount_output,
                                  timeout=self._timeout('showmount'))
        if result.success:
            self.logger.success("showmount complete (%.1fs)", result.duration)

        nse_output = nfs_dir / "nmap_nfs.txt"
        nse_cmd = [
            "nmap", "-p", str(port),
            "--script=nfs-ls,nfs-showmount,nfs-statfs",
            self.target,
        ]
        result = self.run_command(nse_cmd, output_file=nse_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("NSE NFS scripts complete (%.1fs)", result.duration)

    def enumerate_smtp(self, port):
        """Enumerate SMTP services."""
        self.logger.info("Enumerating SMTP on port %d...", port)

        smtp_dir = self._ensure_output_dir("smtp")

        nse_output = smtp_dir / "nmap_smtp.txt"
        nse_cmd = [
            "nmap", "-p", str(port),
            "--script=smtp-enum-users,smtp-commands,smtp-open-relay",
            self.target,
        ]
        result = self.run_command(nse_cmd, output_file=nse_output,
                                  timeout=self._timeout('nmap_nse'))
        if result.success:
            self.logger.success("NSE SMTP scripts complete (%.1fs)", result.duration)

        userlist = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        if os.path.exists(userlist):
            userenum_output = smtp_dir / "smtp_user_enum.txt"
            userenum_cmd = [
                "smtp-user-enum", "-M", "VRFY",
                "-U", userlist, "-t", self.target, "-p", str(port),
            ]
            result = self.run_command(userenum_cmd, output_file=userenum_output,
                                      timeout=self._timeout('smtp_user_enum'))
            if result.success:
                self.logger.success("smtp-user-enum complete (%.1fs)", result.duration)
        else:
            self.logger.warning("SMTP user list not found: %s", userlist)

    def enumerate_rdp(self, port):
        """Enumerate RDP services."""
        self.logger.info("Enumerating RDP on port %d...", port)

        misc_dir = self._ensure_output_dir("misc")

        rdp_output = misc_dir / f"rdp_enum_{port}.txt"
        rdp_cmd = [
            "nmap", "-p", str(port),
            "--script=rdp-enum-encryption,rdp-ntlm-info",
            self.target,
        ]
        result = self.run_command(rdp_cmd, output_file=rdp_output,
                                  timeout=self._timeout('rdp'))
        if result.success:
            self.logger.success("RDP enumeration complete (%.1fs)", result.duration)

    # ------------------------------------------------------------------
    # Service classification & dispatch
    # ------------------------------------------------------------------

    SERVICE_PORT_MAP = {
        'http':  [80, 8080, 8000, 8888, 3000],
        'https': [443, 8443],
        'smb':   [139, 445],
        'ftp':   [21],
        'ssh':   [22],
        'mysql': [3306],
        'mssql': [1433],
        'snmp':  [161, 162],
        'dns':   [53],
        'ldap':  [389, 636],
        'nfs':   [111, 2049],
        'smtp':  [25, 587],
        'rdp':   [3389],
    }

    def _classify_port(self, port, port_info):
        """Return a list of ``(enumerator_func, port)`` tasks for *port*."""
        tasks: List[Tuple[Callable, int]] = []
        service_lower = port_info.service.lower()

        if ('http' in service_lower
                or port in self.SERVICE_PORT_MAP['http']
                + self.SERVICE_PORT_MAP['https']):
            tasks.append((self.enumerate_http, port))

        if ('smb' in service_lower
                or 'microsoft-ds' in service_lower
                or 'netbios' in service_lower
                or port in self.SERVICE_PORT_MAP['smb']):
            tasks.append((self.enumerate_smb, port))

        if 'ftp' in service_lower or port in self.SERVICE_PORT_MAP['ftp']:
            tasks.append((self.enumerate_ftp, port))

        if 'ssh' in service_lower or port in self.SERVICE_PORT_MAP['ssh']:
            tasks.append((self.enumerate_ssh, port))

        if 'mysql' in service_lower or port in self.SERVICE_PORT_MAP['mysql']:
            tasks.append((self.enumerate_mysql, port))

        if ('mssql' in service_lower
                or 'ms-sql' in service_lower
                or port in self.SERVICE_PORT_MAP['mssql']):
            tasks.append((self.enumerate_mssql, port))

        if 'snmp' in service_lower or port in self.SERVICE_PORT_MAP['snmp']:
            tasks.append((self.enumerate_snmp, port))

        if ('dns' in service_lower
                or 'domain' in service_lower
                or port in self.SERVICE_PORT_MAP['dns']):
            tasks.append((self.enumerate_dns, port))

        if 'ldap' in service_lower or port in self.SERVICE_PORT_MAP['ldap']:
            tasks.append((self.enumerate_ldap, port))

        if ('nfs' in service_lower
                or 'rpcbind' in service_lower
                or 'portmapper' in service_lower
                or port in self.SERVICE_PORT_MAP['nfs']):
            tasks.append((self.enumerate_nfs, port))

        if 'smtp' in service_lower or port in self.SERVICE_PORT_MAP['smtp']:
            tasks.append((self.enumerate_smtp, port))

        if ('rdp' in service_lower
                or 'ms-wbt-server' in service_lower
                or port in self.SERVICE_PORT_MAP['rdp']):
            tasks.append((self.enumerate_rdp, port))

        return tasks

    # Host-level enumerators that scan the target, not a specific port.
    # Only dispatch once regardless of how many matching ports are open.
    _HOST_LEVEL_ENUMERATORS = frozenset({
        'enumerate_smb', 'enumerate_snmp', 'enumerate_nfs',
    })

    def enumerate_services(self):
        """Classify ports then run all enumeration tasks concurrently.

        In resume mode, completed enumerations are skipped.
        Each successful task is checkpointed via :class:`StateManager`.
        """
        tasks: List[Tuple[Callable, int]] = []
        dispatched_host_level: Set[str] = set()

        for port, port_info in self.open_ports.items():
            for func, p in self._classify_port(port, port_info):
                name = func.__name__
                if name in self._HOST_LEVEL_ENUMERATORS:
                    if name in dispatched_host_level:
                        continue
                    dispatched_host_level.add(name)
                tasks.append((func, p))

        # Filter out already-completed tasks in resume mode
        if self._resume_mode:
            original_count = len(tasks)
            tasks = [
                (func, port)
                for func, port in tasks
                if not self.state.is_enumeration_done(func.__name__, port)
            ]
            skipped = original_count - len(tasks)
            if skipped > 0:
                self.logger.info(
                    "Resuming — skipping %d already-completed enumeration(s)",
                    skipped,
                )

        if not tasks:
            self.logger.info("No remaining enumeration tasks")
            return

        self.logger.info(
            "Dispatching %d enumeration task(s) across %d thread(s)",
            len(tasks), self.threads,
        )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(func, port): (func.__name__, port)
                for func, port in tasks
            }
            for future in as_completed(futures):
                name, port = futures[future]
                try:
                    future.result()
                    # Checkpoint on success
                    self.state.enumeration_done(name, port)
                except Exception as exc:
                    self.logger.error(
                        "Unhandled exception in %s (port %d): %s",
                        name, port, exc,
                    )

    # ------------------------------------------------------------------
    # Findings aggregation (Phase 7.2)
    # ------------------------------------------------------------------

    def _aggregate_findings(self):
        """Scan tool output files and generate actionable findings."""
        findings: List[Finding] = []

        # --- FTP anonymous access ---
        for port, pi in self.open_ports.items():
            if 'ftp' in pi.service.lower() or port == 21:
                ftp_file = self.output_dir / "ftp" / f"ftp_enum_{port}.txt"
                ftp_data = parse_ftp_nmap(ftp_file)
                if ftp_data['anonymous_access']:
                    findings.append(Finding(
                        severity='CRITICAL', category='anonymous_access',
                        port=port, service='FTP',
                        description='FTP anonymous login enabled.',
                        evidence='Anonymous FTP login allowed',
                        next_step=f'ftp {self.target} — login as anonymous, download all files',
                    ))

        # --- SMB null session / readable shares ---
        smbmap_file = self.output_dir / "smb" / "smbmap.txt"
        smb_shares = parse_smbmap_results(smbmap_file)
        for share in smb_shares:
            if share.get('writable'):
                findings.append(Finding(
                    severity='HIGH', category='writable_share',
                    port=445, service='SMB',
                    description=f"SMB share '{share['name']}' is WRITABLE without credentials.",
                    evidence=share['permissions'],
                    next_step=f"smbclient //{self.target}/{share['name']} -N — upload a shell",
                ))
            elif share.get('readable'):
                findings.append(Finding(
                    severity='HIGH', category='readable_share',
                    port=445, service='SMB',
                    description=f"SMB share '{share['name']}' is READABLE without credentials.",
                    evidence=share['permissions'],
                    next_step=f"smbclient //{self.target}/{share['name']} -N — enumerate contents",
                ))

        e4l_file = self.output_dir / "smb" / "enum4linux.txt"
        e4l_data = parse_enum4linux_results(e4l_file)
        if e4l_data['null_session']:
            findings.append(Finding(
                severity='HIGH', category='null_session',
                port=445, service='SMB',
                description='SMB null session authentication succeeded.',
                evidence='Null session established',
                next_step=f'enum4linux -a {self.target} — extract users, groups, policies',
            ))
        if e4l_data['users']:
            findings.append(Finding(
                severity='MEDIUM', category='user_enumeration',
                port=445, service='SMB',
                description=f"Enumerated {len(e4l_data['users'])} user(s) via SMB.",
                evidence='; '.join(e4l_data['users'][:5]),
                next_step='Use discovered usernames for password attacks',
            ))

        # --- SNMP default community ---
        snmp_file = self.output_dir / "snmp" / "snmpwalk_full.txt"
        snmp_data = parse_snmpwalk_results(snmp_file)
        if snmp_data['has_data']:
            findings.append(Finding(
                severity='HIGH', category='default_community',
                port=161, service='SNMP',
                description='SNMP default community string "public" returned data.',
                evidence=snmp_data.get('system_info', 'Data retrieved via public community'),
                next_step=f'snmpwalk -v2c -c public {self.target} — extract system info, processes, network',
            ))

        # --- MySQL empty password ---
        for port, pi in self.open_ports.items():
            if 'mysql' in pi.service.lower() or port == 3306:
                mysql_file = self.output_dir / "misc" / f"mysql_enum_{port}.txt"
                if mysql_file.exists():
                    try:
                        content = mysql_file.read_text(errors='replace')
                        if 'empty password' in content.lower() and 'root' in content.lower():
                            findings.append(Finding(
                                severity='CRITICAL', category='default_creds',
                                port=port, service='MySQL',
                                description='MySQL root has no password.',
                                evidence='mysql-empty-password: root has empty password',
                                next_step=f'mysql -h {self.target} -u root -P {port}',
                            ))
                    except Exception:
                        pass

        # --- Web: gobuster interesting paths ---
        web_dir = self.output_dir / "web"
        if web_dir.is_dir():
            for port, pi in self.open_ports.items():
                gobuster_file = web_dir / f"gobuster_{port}.txt"
                hits = parse_gobuster_results(gobuster_file)
                interesting = [h for h in hits if h.get('interesting')]
                proto = "https" if self._is_https(pi) else "http"
                for hit in interesting[:10]:
                    findings.append(Finding(
                        severity='MEDIUM', category='web_discovery',
                        port=port, service='HTTP',
                        description=f"Interesting path discovered: {hit['path']} (Status {hit['status']})",
                        evidence=f"Status {hit['status']}, Size {hit['size']}",
                        next_step=f"curl -v {proto}://{self.target}:{port}{hit['path']}",
                    ))

                # Nikto findings
                nikto_file = web_dir / f"nikto_{port}.txt"
                nikto_vulns = parse_nikto_results(nikto_file)
                for vuln_line in nikto_vulns[:10]:
                    findings.append(Finding(
                        severity='MEDIUM', category='nikto_finding',
                        port=port, service='HTTP',
                        description=vuln_line[:200],
                        evidence=vuln_line[:300],
                        next_step='Investigate and verify manually',
                    ))

        return sorted(findings)

    # ------------------------------------------------------------------
    # Reporting (Phase 7.3 + 7.4)
    # ------------------------------------------------------------------

    def generate_report(self):
        """Generate an enhanced Markdown report with findings and coverage."""
        self.logger.info("Generating enumeration report...")

        findings = self._aggregate_findings()
        report_file = self.output_dir / "REPORT.md"

        # Compute scan duration
        try:
            start_dt = datetime.fromisoformat(self.state.start_time)
            duration_secs = (datetime.now() - start_dt).total_seconds()
            duration_str = f"{int(duration_secs // 3600)}h {int((duration_secs % 3600) // 60)}m {int(duration_secs % 60)}s"
        except Exception:
            duration_str = "unknown"

        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        with open(report_file, 'w') as f:
            # --- Section 1: Executive Summary ---
            f.write(f"# Enumeration Report for {self.target}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
            f.write(f"**Scan Duration:** {duration_str}  \n")
            f.write(f"**Open Ports:** {len(self.open_ports)}  \n")
            f.write(f"**Findings:** {len(findings)}")
            if sev_counts:
                parts = []
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    if sev in sev_counts:
                        parts.append(f"{sev_counts[sev]} {sev}")
                f.write(f" ({', '.join(parts)})")
            f.write("  \n")
            f.write(f"**Failed Commands:** {len(self.failed_commands)}  \n\n")

            # --- Section 2: Critical/High Findings ---
            crit_high = [x for x in findings if x.severity in ('CRITICAL', 'HIGH')]
            if crit_high:
                f.write("---\n\n## Critical & High Findings\n\n")
                for finding in crit_high:
                    f.write(f"### [{finding.severity}] {finding.description}\n\n")
                    f.write(f"- **Port:** {finding.port}/{finding.service}\n")
                    f.write(f"- **Category:** {finding.category}\n")
                    f.write(f"- **Evidence:** `{finding.evidence[:200]}`\n")
                    f.write(f"- **Next Step:** `{finding.next_step}`\n\n")

            # --- Section 3: Service Details ---
            f.write("---\n\n## Service Details\n\n")
            if self.open_ports:
                f.write("| Port | Proto | Service | Version |\n")
                f.write("|------|-------|---------|--------|\n")
                for port in sorted(self.open_ports.keys()):
                    pi = self.open_ports[port]
                    f.write(
                        f"| {pi.port} | {pi.protocol} "
                        f"| {pi.service} | {pi.version_string} |\n"
                    )
                f.write("\n")
            else:
                f.write("No open ports discovered.\n\n")

            # --- Section 4: Web Discovery ---
            web_dir = self.output_dir / "web"
            web_findings = [x for x in findings
                            if x.category in ('web_discovery', 'nikto_finding')]
            if web_findings:
                f.write("---\n\n## Web Discovery\n\n")
                gobuster_findings = [x for x in web_findings if x.category == 'web_discovery']
                if gobuster_findings:
                    f.write("### Gobuster Hits\n\n")
                    f.write("| Port | Path | Status | Next Step |\n")
                    f.write("|------|------|--------|----------|\n")
                    for gf in gobuster_findings:
                        path_val = gf.description.split(': ', 1)[-1].split(' (')[0] if ': ' in gf.description else gf.description
                        status_val = gf.evidence.split(',')[0] if gf.evidence else ''
                        f.write(f"| {gf.port} | {path_val} | {status_val} | `{gf.next_step}` |\n")
                    f.write("\n")

                nikto_findings = [x for x in web_findings if x.category == 'nikto_finding']
                if nikto_findings:
                    f.write("### Nikto Findings\n\n")
                    for nf in nikto_findings:
                        f.write(f"- {nf.description}\n")
                    f.write("\n")

            # --- Section 5: All Findings (Medium/Low/Info) ---
            other_findings = [x for x in findings if x.severity not in ('CRITICAL', 'HIGH')]
            if other_findings:
                f.write("---\n\n## Other Findings\n\n")
                for finding in other_findings:
                    f.write(f"- **[{finding.severity}]** {finding.description} "
                            f"(port {finding.port}) → `{finding.next_step}`\n")
                f.write("\n")

            # --- Section 5b: Enumeration Coverage ---
            f.write("---\n\n## Enumeration Coverage\n\n")

            completed = sorted(self.state.completed_enumerations)
            if completed:
                f.write("### Completed Tasks\n\n")
                for entry in completed:
                    f.write(f"- `{entry}`\n")
                f.write("\n")

            if self.failed_commands:
                f.write("### Failed / Timed-out Commands\n\n")
                for cr in self.failed_commands:
                    display = ' '.join(cr.command)
                    status = "TIMEOUT" if cr.timed_out else "FAILED"
                    f.write(f"- [{status}] `{display}` ({cr.duration:.1f}s)\n")
                f.write("\n")

            # --- Section 6: Raw Data Index ---
            f.write("---\n\n## Raw Data Index\n\n")
            for subdir in sorted(d.name for d in self.output_dir.iterdir() if d.is_dir()):
                dir_path = self.output_dir / subdir
                files = sorted(dir_path.iterdir())
                if files:
                    f.write(f"### `{subdir}/`\n\n")
                    for fp in files:
                        if fp.is_file():
                            size = fp.stat().st_size
                            if size < 1024:
                                size_str = f"{size} B"
                            elif size < 1048576:
                                size_str = f"{size / 1024:.1f} KB"
                            else:
                                size_str = f"{size / 1048576:.1f} MB"
                            f.write(f"- `{fp.name}` ({size_str})\n")
                    f.write("\n")

        self.logger.success("Report saved to %s", report_file)
        return findings

    def generate_json_report(self, findings):
        """Write REPORT.json with full structured data."""
        self.logger.info("Generating JSON report...")

        # Compute duration
        try:
            start_dt = datetime.fromisoformat(self.state.start_time)
            duration_secs = (datetime.now() - start_dt).total_seconds()
        except Exception:
            duration_secs = 0.0

        data = {
            'target': self.target,
            'generated': datetime.now().isoformat(),
            'start_time': self.state.start_time,
            'duration_seconds': round(duration_secs, 1),
            'open_ports': {
                str(port): pi.to_dict()
                for port, pi in self.open_ports.items()
            },
            'findings': [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'port': f.port,
                    'service': f.service,
                    'description': f.description,
                    'evidence': f.evidence,
                    'next_step': f.next_step,
                }
                for f in findings
            ],
            'failed_commands': [
                {
                    'command': ' '.join(cr.command),
                    'duration': round(cr.duration, 1),
                    'timed_out': cr.timed_out,
                    'stderr': cr.stderr[:500],
                }
                for cr in self.failed_commands
            ],
            'completed_phases': self.state.completed_phases,
            'completed_enumerations': sorted(self.state.completed_enumerations),
        }

        json_file = self.output_dir / "REPORT.json"
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

        self.logger.success("JSON report saved to %s", json_file)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self):
        """Execute full enumeration workflow with checkpoint/resume support."""
        self.logger.info("Starting enumeration of %s", self.target)
        self.logger.info("Output directory: %s", self.output_dir)
        if self.timeout_multiplier != 1.0:
            self.logger.info("Timeout multiplier: %.1fx", self.timeout_multiplier)

        # --- Phase: initial_nmap_scan ---
        if not self.state.is_phase_done('initial_nmap_scan'):
            self.initial_nmap_scan()
            self.state.sync_open_ports(self.open_ports)
            self.state.sync_failed_commands(self.failed_commands)
            self.state.phase_done('initial_nmap_scan')
        else:
            self.logger.info("Resuming — skipping initial_nmap_scan (already complete)")

        # --- Phase: udp_scan ---
        if not self.state.is_phase_done('udp_scan'):
            self.udp_scan()
            self.state.sync_open_ports(self.open_ports)
            self.state.sync_failed_commands(self.failed_commands)
            self.state.phase_done('udp_scan')
        else:
            self.logger.info("Resuming — skipping udp_scan (already complete)")

        if self.open_ports:
            # --- Phase: detailed_nmap_scans ---
            if not self.state.is_phase_done('detailed_nmap_scans'):
                self.detailed_nmap_scans()
                self.state.sync_failed_commands(self.failed_commands)
                self.state.phase_done('detailed_nmap_scans')
            else:
                self.logger.info("Resuming — skipping detailed_nmap_scans (already complete)")

            # --- Phase: enumerate_services ---
            self.enumerate_services()
            self.state.sync_failed_commands(self.failed_commands)
            self.state.phase_done('enumerate_services')

        findings = self.generate_report()
        self.generate_json_report(findings)

        self.logger.success("Enumeration complete!")
        self.logger.info("Check %s for all results", self.output_dir)

        if self.failed_commands:
            self.logger.warning(
                "%d command(s) failed or timed out — see REPORT.md",
                len(self.failed_commands),
            )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    banner = f"""
{Colors.OKGREEN}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║                    offsec-enum-ng v1.7                    ║
║        Comprehensive Network & Service Enumeration        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="offsec-enum-ng — automated enumeration for OSCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-o', '--output', default='./enum_results',
                        help='Output directory (default: ./enum_results)')
    parser.add_argument('-p', '--ports',
                        help='Port specification (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-q', '--quick', action='store_true',
                        help='Quick mode (scan top 10000 ports only, skip UDP)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (show DEBUG messages)')
    parser.add_argument('-t', '--threads', type=int, default=3,
                        help='Number of concurrent enumeration threads (default: 3)')
    parser.add_argument('-d', '--domain',
                        help='Domain name for DNS zone transfer attempts')
    parser.add_argument('--timeout-multiplier', type=float, default=1.0,
                        help='Scale all tool timeouts (e.g., 2.0 for slow targets)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume a previous scan from checkpoint (requires existing output dir)')

    args = parser.parse_args()

    # --- Validate target ---
    try:
        validated_target = validate_target(args.target)
    except ValueError as e:
        print(f"{Colors.FAIL}[-] {e}{Colors.ENDC}")
        sys.exit(1)

    # --- Validate ports (if supplied) ---
    validated_ports = None
    if args.ports:
        try:
            validated_ports = validate_ports(args.ports)
        except ValueError as e:
            print(f"{Colors.FAIL}[-] {e}{Colors.ENDC}")
            sys.exit(1)

    # --- Determine output directory ---
    if args.resume:
        # Resume mode: use existing directory (--output is treated as the dir)
        output_dir = args.output
        if not Path(output_dir).is_dir():
            print(f"{Colors.FAIL}[-] Output directory not found: {output_dir}{Colors.ENDC}")
            sys.exit(1)
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = f"{args.output}_{validated_target}_{timestamp}"

    # Map verbosity flag to log level
    verbosity = logging.DEBUG if args.verbose else logging.INFO

    # Initialize and run
    try:
        engine = EnumerationEngine(
            target=validated_target,
            output_dir=output_dir,
            ports=validated_ports,
            quick=args.quick,
            verbosity=verbosity,
            threads=args.threads,
            domain=args.domain,
            timeout_multiplier=args.timeout_multiplier,
            resume=args.resume,
        )
    except FileNotFoundError as e:
        print(f"{Colors.FAIL}[-] {e}{Colors.ENDC}")
        sys.exit(1)

    try:
        engine.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Enumeration interrupted by user{Colors.ENDC}")
        # Checkpoint is already saved per-phase/per-enumeration
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
