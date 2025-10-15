#!/usr/bin/env python3
"""
Enhanced Cybersecurity Assistant for Kali Linux Tools
Author: Assistant
Version: 2.0
License: Educational Use Only
"""

import subprocess
import json
import re
import sys
import os
import signal
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path


class CyberSecAssistant:
    """Enhanced cybersecurity assistant with improved functionality and error handling"""
    
    def __init__(self):
        # Initialize data structures
        self.kali_tools = self.load_tools_data()
        self.session_history = []
        self.config = self.load_config()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Display startup messages
        self._display_startup()
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print("\n\n🔒 Shutting down safely...")
        self._safe_exit()
    
    def _safe_exit(self):
        """Safe exit with optional history export"""
        try:
            if self.session_history:
                export = input("📝 Export command history? (y/N): ").strip().lower()
                if export == 'y':
                    filename = input("Enter filename (or press Enter for default): ").strip()
                    if not filename:
                        filename = f"cybersec_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    print(self.export_history(filename))
        except:
            pass
        print("🔒 Stay safe and ethical! Goodbye!")
        sys.exit(0)
    
    def _display_startup(self):
        """Display enhanced startup information"""
        print("=" * 60)
        print("🔒 CYBERSECURITY ASSISTANT v2.0")
        print("=" * 60)
        print("⚠️  For EDUCATIONAL and AUTHORIZED testing purposes ONLY!")
        print(f"📊 Database: {len(self.kali_tools)} tools loaded")
        print("📋 Type 'help' for commands or 'ethical' for usage guidelines")
        print("=" * 60)
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration settings"""
        config_file = Path("cybersec_config.json")
        default_config = {
            "max_history": 100,
            "timeout_seconds": 15,
            "verbose_mode": False,
            "auto_save_history": False,
            "preferred_output_format": "text"
        }
        
        try:
            if config_file.exists():
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            else:
                # Create default config file
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
        
        return default_config
    
    def load_tools_data(self) -> Dict[str, Dict[str, Any]]:
        """Load tools data from JSON file with enhanced error handling"""
        tools_file = Path("kali_tools.json")
        
        # Enhanced default tools database
        default_tools = {
    'nmap': {
        'description': 'Network discovery and security auditing tool',
        'basic_usage': 'nmap [options] [target]',
        'common_commands': [
            'nmap -sS target_ip  # SYN scan (stealth scan)',
            'nmap -sU target_ip  # UDP scan',
            'nmap -A target_ip   # Aggressive scan (OS & version detection)',
            'nmap -sV target_ip  # Version detection',
            'nmap -O target_ip   # OS detection',
            'nmap -p 1-1000 target_ip  # Scan specific port range',
            'nmap -sC target_ip  # Default script scan',
            'nmap --script vuln target_ip  # Run vulnerability scripts'
        ],
        'categories': ['reconnaissance', 'enumeration', 'network']
    },

    'netcat': {
        'description': 'Swiss-army tool for reading/writing raw network connections (TCP/UDP)',
        'basic_usage': 'nc [options] host port',
        'common_commands': [
            'nc -lvp 4444  # Listen on TCP port 4444 (verbose)',
            'nc target_ip 80  # Connect to target on port 80',
            'nc -u target_ip 53  # UDP connection to port 53',
            'nc -zv target_ip 1-1000  # Port scan (zero-I/O)',
            'echo "hello" | nc target_ip 1234  # Send data to remote port'
        ],
        'categories': ['network', 'post-exploitation', 'debugging']
    },

    'wireshark': {
        'description': 'Graphical network protocol analyzer for packet inspection',
        'basic_usage': 'wireshark (use tshark for CLI: tshark [options])',
        'common_commands': [
            'wireshark  # Launch GUI to capture/analyze packets',
            'tshark -i eth0 -w capture.pcap  # Capture to file using CLI',
            'tshark -r capture.pcap -Y "http"  # Filter read for HTTP packets',
            'wireshark -k -i eth0  # Start capturing immediately in GUI'
        ],
        'categories': ['network', 'forensics', 'analysis']
    },

    'tcpdump': {
        'description': 'Command-line packet analyzer and capture tool',
        'basic_usage': 'tcpdump [options] [expression]',
        'common_commands': [
            'tcpdump -i eth0  # Capture on interface eth0',
            'tcpdump -i eth0 -w out.pcap  # Write capture to file',
            'tcpdump -r out.pcap  # Read capture file',
            'tcpdump -nn -s 0 -v port 80  # Verbose capture for HTTP traffic',
            'tcpdump -i any "tcp and port 22"  # Filter by expression'
        ],
        'categories': ['network', 'forensics', 'analysis']
    },

    'aircrack-ng': {
        'description': 'Suite for wireless network auditing (capture, crack WPA/WEP)',
        'basic_usage': 'aircrack-ng [options] <capturefile>',
        'common_commands': [
            'airmon-ng start wlan0  # Put card into monitor mode',
            'airodump-ng wlan0mon  # Capture wireless traffic',
            'aireplay-ng --deauth 10 -a AP_MAC wlan0mon  # Send deauths (testing)',
            'aircrack-ng -w wordlist.txt capture.cap  # Crack captured handshake',
            'airmon-ng stop wlan0mon  # Stop monitor mode'
        ],
        'categories': ['wireless', 'reconnaissance', 'password-recovery']
    },

    'metasploit-framework': {
        'description': 'Modular penetration testing framework (exploitation & post-exploitation)',
        'basic_usage': 'msfconsole  # Launch Metasploit console',
        'common_commands': [
            'msfconsole  # Start interactive Metasploit',
            'search type:exploit name  # Search for modules',
            'use exploit/windows/smb/ms17_010_eternalblue  # Select a module',
            'set RHOST target_ip  # Set target host',
            'run / exploit  # Execute exploit (when configured)'
        ],
        'categories': ['exploitation', 'post-exploitation', 'framework']
    },

    'burpsuite': {
        'description': 'Web application security testing proxy and toolkit',
        'basic_usage': 'burpsuite (use in conjunction with browser proxy settings)',
        'common_commands': [
            'Start Burp and configure browser proxy to 127.0.0.1:8080',
            'Use Proxy -> Intercept to view/modify requests',
            'Scanner (Professional) to automatically identify web vulnerabilities',
            'Repeater to manually modify and re-send requests for testing'
        ],
        'categories': ['web-apps', 'proxy', 'analysis']
    },

    'sqlmap': {
        'description': 'Automated tool for detecting and exploiting SQL injection flaws',
        'basic_usage': 'sqlmap -u "http://target/page.php?id=1" [options]',
        'common_commands': [
            'sqlmap -u "http://target/vuln.php?id=1" --dbs  # Enumerate databases',
            'sqlmap -u "URL" -p id --dump  # Dump table contents',
            'sqlmap -u "URL" --risk=3 --level=5  # Increase test intensity',
            'sqlmap -u "URL" --os-shell  # Attempt to get an OS shell (requires vuln)'
        ],
        'categories': ['web-apps', 'exploitation', 'database']
    },

    'nikto': {
        'description': 'Web server scanner that checks for dangerous files, outdated software, and misconfigurations',
        'basic_usage': 'nikto -h target_host',
        'common_commands': [
            'nikto -h http://target  # Basic scan',
            'nikto -h target -output nikto_results.txt  # Save results',
            'nikto -h target -Plugins "all"  # Run all plugins',
            'nikto -h target -Tuning x  # Tune tests (e.g., 1=files, 2=serv headers)'
        ],
        'categories': ['web-apps', 'vulnerability-scanning', 'enumeration']
    },

    'john': {
        'description': 'John the Ripper — password cracking tool for offline hashes',
        'basic_usage': 'john [options] <hashfile>',
        'common_commands': [
            'john --wordlist=wordlist.txt hashes.txt  # Wordlist attack',
            'john --show hashes.txt  # Show cracked passwords',
            'john --format=md5 hashes.txt  # Specify hash format',
            'john --incremental hashes.txt  # Brute-force mode'
        ],
        'categories': ['password-cracking', 'forensics', 'offline-analysis']
    },

    'hashcat': {
        'description': 'High-performance password recovery tool that leverages GPU acceleration',
        'basic_usage': 'hashcat -m <hash_type> -a <attack_mode> hashfile wordlist',
        'common_commands': [
            'hashcat -m 0 -a 0 hash.txt rockyou.txt  # MD5 straight wordlist',
            'hashcat -m 1000 -a 3 hash.txt ?a?a?a?a?a  # NTLM brute-force',
            'hashcat --show hash.txt  # Show cracked hashes',
            'hashcat -b  # Benchmark modes'
        ],
        'categories': ['password-cracking', 'gpu-acceleration', 'forensics']
    },

    'hydra': {
        'description': 'Online password cracking tool for attacking network authentication services (ssh, ftp, http, etc.)',
        'basic_usage': 'hydra -L users.txt -P passwords.txt target service',
        'common_commands': [
            'hydra -l admin -P rockyou.txt target ssh  # Single user SSH attack',
            'hydra -L users.txt -P pass.txt ftp://target  # FTP attack with lists',
            'hydra -s 2222 -t 4 target ssh  # Specify port and threads',
            'hydra -S -V target https-get /login  # HTTPS form example'
        ],
        'categories': ['credential-stuffing', 'brute-force', 'network']
    },

    'gobuster': {
        'description': 'Directory and DNS busting tool to discover hidden web paths and virtual hosts',
        'basic_usage': 'gobuster dir -u <url> -w <wordlist>',
        'common_commands': [
            'gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt',
            'gobuster dns -d example.com -w subdomains.txt  # DNS subdomain enumeration',
            'gobuster dir -u https://target -w wordlist.txt -x php,html,txt  # Extensions',
            'gobuster vhost -u http://target -w vhosts.txt  # Virtual host discovery'
        ],
        'categories': ['reconnaissance', 'web-apps', 'enumeration']
    },

    'dirb': {
        'description': 'Simple web content scanner that brute-forces directories and files',
        'basic_usage': 'dirb <url> [wordlist]',
        'common_commands': [
            'dirb http://target /usr/share/wordlists/common.txt  # Basic directory scan',
            'dirb https://target -S  # Silent mode, less verbose',
            'dirb http://target -X .php,.html  # Check specific extensions'
        ],
        'categories': ['web-apps', 'reconnaissance', 'enumeration']
    },

    'masscan': {
        'description': 'Extremely fast network port scanner (can scan the Internet in minutes)',
        'basic_usage': 'masscan [target] -p [port-range] --rate [rate]',
        'common_commands': [
            'masscan 10.0.0.0/8 -p80,443 --rate=1000  # Fast scan of ports 80/443',
            'masscan target -p1-65535 --rate=10000  # Full port range (high rate)',
            'masscan -oX results.xml target  # Output results as XML'
        ],
        'categories': ['reconnaissance', 'network', 'scanning']
    },

    'openvas': {
        'description': 'Open-source vulnerability scanning and management (now Greenbone Vulnerability Manager - GVM)',
        'basic_usage': 'gvm-launch / gvm-manage-certs and use web UI (gvm) for scans',
        'common_commands': [
            'gvm-setup  # Initial setup (varies by distro)',
            'gvm-start  # Start services',
            'Use GVM web UI to create targets, tasks and run vulnerability scans',
            'gvm-check-setup  # Verify installation status'
        ],
        'categories': ['vulnerability-management', 'scanning', 'compliance']
    },

    'smbclient': {
        'description': 'FTP-like client to access SMB/CIFS resources on Windows/Samba servers',
        'basic_usage': 'smbclient //[host]/[share] -U username',
        'common_commands': [
            'smbclient -L //target -U ""  # List shares (anonymous)',
            'smbclient //target/share -U user  # Connect to share interactively',
            'smbclient -N //target/share  # Connect without password (if allowed)',
            'smbclient --option=clientNTLMv2=0 //target  # Tweak options for legacy shares'
        ],
        'categories': ['network', 'file-sharing', 'enumeration']
    },

    'enum4linux': {
        'description': 'Tool for enumerating Windows and Samba information (users, groups, shares)',
        'basic_usage': 'enum4linux [options] target',
        'common_commands': [
            'enum4linux -a target  # Full enumeration (shares, users, OS info)',
            'enum4linux -U target  # Enumerate users',
            'enum4linux -S target  # Enumerate shares'
        ],
        'categories': ['enumeration', 'windows', 'reconnaissance']
    },

    'snort': {
        'description': 'Network intrusion detection and prevention system (packet inspection with rules)',
        'basic_usage': 'snort -c /etc/snort/snort.conf -i eth0',
        'common_commands': [
            'snort -A console -q -c /etc/snort/snort.conf -i eth0  # Run in console mode',
            'snort -c /etc/snort/snort.conf -T  # Test configuration',
            'snort -l /var/log/snort -c /etc/snort/snort.conf  # Logging directory'
        ],
        'categories': ['intrusion-detection', 'network', 'monitoring']
    },

    'ettercap': {
        'description': 'Comprehensive suite for man-in-the-middle attacks on LAN (ARP spoofing, sniffing, filtering)',
        'basic_usage': 'ettercap -T -q -i interface  # Text mode; use GUI for GUI mode',
        'common_commands': [
            'ettercap -T -i eth0 -M arp:remote /target1/ /target2/  # ARP MITM between two hosts',
            'ettercap -G  # Launch GUI version for interactive use',
            'ettercap -T -i eth0 -r capture.pcap  # Read from capture file'
        ],
        'categories': ['man-in-the-middle', 'network', 'sniffing']
    },

    'proxychains': {
        'description': 'Forces any TCP connection made by any application to follow through proxy (SOCKS/HTTP)',
        'basic_usage': 'proxychains <application> [args]',
        'common_commands': [
            'proxychains firefox  # Launch Firefox through proxy chain',
            'proxychains nmap -sT target  # Use proxy chains with nmap TCP connect scan',
            'Edit /etc/proxychains.conf to configure proxies (socks4/socks5/http)'
        ],
        'categories': ['anonymity', 'proxying', 'operational-security']
            }
        }
        
        try:
            if tools_file.exists():
                with open(tools_file, 'r') as f:
                    loaded_tools = json.load(f)
                    # Validate loaded data
                    if self._validate_tools_data(loaded_tools):
                        return loaded_tools
                    else:
                        print("Warning: Invalid tools data format, using defaults")
            
            # Create/update the file with default data
            with open(tools_file, 'w') as f:
                json.dump(default_tools, f, indent=2)
            return default_tools
            
        except Exception as e:
            print(f"Warning: Could not load tools data: {e}")
            return default_tools
    
    def _validate_tools_data(self, tools_data: Dict) -> bool:
        """Validate the structure of tools data"""
        required_fields = ['description', 'basic_usage', 'common_commands']
        
        for tool_name, tool_info in tools_data.items():
            if not isinstance(tool_info, dict):
                return False
            for field in required_fields:
                if field not in tool_info:
                    return False
        return True
    
    def save_tools_data(self):
        """Save tools data to JSON file with error handling"""
        try:
            with open("kali_tools.json", 'w') as f:
                json.dump(self.kali_tools, f, indent=2)
            return "✅ Tools database saved successfully"
        except Exception as e:
            return f"❌ Error saving tools data: {e}"
    
    def add_to_history(self, command: str, result: str):
        """Add command to session history with size management"""
        self.session_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'result': result[:500] + '...' if len(result) > 500 else result
        })
        
        # Keep only last N commands based on config
        max_history = self.config.get('max_history', 100)
        if len(self.session_history) > max_history:
            self.session_history = self.session_history[-max_history:]
        
        # Auto-save if enabled
        if self.config.get('auto_save_history', False):
            self.export_history("auto_save_history.json")
    
    def export_history(self, filename: str = "") -> str:
        """Export session history to file with enhanced formatting"""
        if not filename:
            filename = f"cybersec_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'tool_count': len(self.kali_tools),
                    'command_count': len(self.session_history),
                    'version': '2.0'
                },
                'history': self.session_history
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            return f"📝 History exported to {filename} ({len(self.session_history)} commands)"
        except Exception as e:
            return f"❌ Error exporting history: {e}"
    
    def get_system_info(self, tool_name: str) -> Dict[str, Any]:
        """Get comprehensive system information about a tool"""
        info = {
            'installed': False,
            'path': None,
            'man_available': False,
            'help_available': False,
            'version': None
        }
        
        # Check if tool is installed
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                info['installed'] = True
                info['path'] = result.stdout.strip()
        except:
            pass
        
        if not info['installed']:
            return info
        
        # Check man page availability
        try:
            result = subprocess.run(['man', '-w', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            info['man_available'] = result.returncode == 0
        except:
            pass
        
        # Check help availability and get
