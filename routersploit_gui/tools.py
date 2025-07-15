"""Security tools management for RouterSploit GUI."""

import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import socket
import threading
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import nmap
import requests
import structlog

from . import config

logger = structlog.get_logger(__name__)


class NetcatEnumerator:
    """Netcat-based service enumeration for manual banner grabbing."""
    
    def __init__(self) -> None:
        """Initialize the netcat enumerator."""
        self.timeout = 10
        self.common_service_patterns = {
            21: {"name": "ftp", "commands": ["HELP\r\n", "USER anonymous\r\n"]},
            22: {"name": "ssh", "commands": ["\r\n"]},
            23: {"name": "telnet", "commands": ["\r\n"]},
            25: {"name": "smtp", "commands": ["EHLO test\r\n", "HELP\r\n"]},
            53: {"name": "dns", "commands": []},  # DNS requires special handling
            80: {"name": "http", "commands": ["GET / HTTP/1.1\r\nHost: %TARGET%\r\n\r\n"]},
            110: {"name": "pop3", "commands": ["USER test\r\n", "HELP\r\n"]},
            143: {"name": "imap", "commands": ["a001 CAPABILITY\r\n"]},
            443: {"name": "https", "commands": ["GET / HTTP/1.1\r\nHost: %TARGET%\r\n\r\n"]},
            993: {"name": "imaps", "commands": ["a001 CAPABILITY\r\n"]},
            995: {"name": "pop3s", "commands": ["USER test\r\n"]},
            3306: {"name": "mysql", "commands": []},
            5432: {"name": "postgresql", "commands": []},
            1433: {"name": "mssql", "commands": []},
            3389: {"name": "rdp", "commands": []},
            5900: {"name": "vnc", "commands": []},
            6379: {"name": "redis", "commands": ["INFO\r\n"]},
            27017: {"name": "mongodb", "commands": []},
        }
    
    def enumerate_service(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Enumerate a service using netcat-style banner grabbing.
        
        Args:
            target: Target IP address or hostname
            port: Port number to enumerate
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary containing service information
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-NC] {line}", "warning" if level == "info" else level)
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Enumerating service on {target}:{port} using netcat", "info")
            if debug:
                debug_emit(f"NetcatEnumerator.enumerate_service called for {target}:{port}")
                
            result = {
                "target": target,
                "port": port,
                "service": "unknown",
                "version": "",
                "banner": "",
                "method": "netcat",
                "timestamp": time.time()
            }
            
            # Try to connect and grab banner
            banner = self._grab_banner(target, port, verbose=verbose, debug=debug, on_output=on_output)
            if banner:
                result["banner"] = banner
                
                # Try to identify service from banner
                service_info = self._identify_service_from_banner(banner, port, verbose=verbose, debug=debug, on_output=on_output)
                result.update(service_info)
            
            # Try service-specific enumeration
            if result["service"] == "unknown" and port in self.common_service_patterns:
                service_info = self._enumerate_specific_service(target, port, verbose=verbose, debug=debug, on_output=on_output)
                result.update(service_info)
            
            if verbose and on_output:
                on_output(f"[Verbose] Service enumeration completed for {target}:{port} - {result['service']}", "info")
            
            return result
            
        except Exception as e:
            error_msg = f"Netcat enumeration failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, target=target, port=port, error=str(e))
            return {"error": error_msg}
    
    def _grab_banner(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> str:
        """Grab banner from a service using raw socket connection.
        
        Args:
            target: Target IP address or hostname
            port: Port number
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Banner string if successful, empty string otherwise
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-BANNER] {line}", "warning" if level == "info" else level)
                
        try:
            if debug:
                debug_emit(f"Attempting to grab banner from {target}:{port}")
                
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect
            if debug:
                debug_emit(f"Connecting to {target}:{port}")
            sock.connect((target, port))
            
            # Wait for banner (some services send it immediately)
            banner = ""
            try:
                sock.settimeout(5)  # Shorter timeout for banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if debug:
                    debug_emit(f"Received banner: {banner[:100]}...")
            except socket.timeout:
                if debug:
                    debug_emit("No immediate banner received")
                pass
            
            # If no banner, try sending common commands
            if not banner and port in self.common_service_patterns:
                commands = self.common_service_patterns[port]["commands"]
                for cmd in commands:
                    try:
                        # Replace placeholder with actual target
                        actual_cmd = cmd.replace("%TARGET%", target)
                        if debug:
                            debug_emit(f"Sending command: {repr(actual_cmd)}")
                        sock.send(actual_cmd.encode('utf-8'))
                        
                        # Wait for response
                        sock.settimeout(3)
                        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if response:
                            banner = response
                            if debug:
                                debug_emit(f"Received response: {response[:100]}...")
                            break
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if debug:
                            debug_emit(f"Command failed: {e}")
                        continue
            
            sock.close()
            
            if verbose and on_output and banner:
                on_output(f"[netcat] Banner grabbed from {target}:{port}: {banner[:100]}{'...' if len(banner) > 100 else ''}", "info")
            
            return banner
            
        except Exception as e:
            if debug:
                debug_emit(f"Banner grab failed: {e}")
            return ""
    
    def _identify_service_from_banner(self, banner: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Identify service and version from banner string.
        
        Args:
            banner: Banner string
            port: Port number
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary with service and version information
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-IDENT] {line}", "warning" if level == "info" else level)
                
        banner_lower = banner.lower()
        service_info = {"service": "unknown", "version": "", "product": ""}
        
        # Service identification patterns
        service_patterns = {
            "ssh": [r"ssh-(\d+\.\d+)-(.+)", r"openssh[_\s]+(\d+\.\d+)", r"libssh[_\s]+(\d+\.\d+)"],
            "ftp": [r"(\d+\.\d+\.\d+)", r"vsftpd\s+(\d+\.\d+)", r"proftpd\s+(\d+\.\d+)"],
            "smtp": [r"postfix", r"sendmail", r"exim\s+(\d+\.\d+)", r"microsoft\s+smtp"],
            "http": [r"server:\s*(.+)", r"apache[/\s]+(\d+\.\d+)", r"nginx[/\s]+(\d+\.\d+)", r"iis[/\s]+(\d+\.\d+)"],
            "mysql": [r"mysql\s+(\d+\.\d+)", r"mariadb\s+(\d+\.\d+)"],
            "postgresql": [r"postgresql\s+(\d+\.\d+)"],
            "redis": [r"redis_version:(\d+\.\d+)"],
            "mongodb": [r"mongodb\s+(\d+\.\d+)"],
            "telnet": [r"telnet", r"login:", r"username:"],
            "pop3": [r"\+ok.*pop3", r"dovecot"],
            "imap": [r"imap4.*ok", r"dovecot"],
            "vnc": [r"rfb\s+(\d+\.\d+)", r"vnc"],
            "rdp": [r"rdp", r"terminal\s+services"],
        }
        
        # Check banner against patterns
        for service, patterns in service_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, banner_lower)
                if match:
                    service_info["service"] = service
                    if match.groups():
                        service_info["version"] = match.group(1)
                    if debug:
                        debug_emit(f"Identified service: {service} version: {service_info['version']}")
                    break
            if service_info["service"] != "unknown":
                break
        
        # If no specific service found, try generic patterns
        if service_info["service"] == "unknown":
            # Check for common server headers
            if "server:" in banner_lower:
                server_match = re.search(r"server:\s*(.+?)(?:\r|\n|$)", banner_lower)
                if server_match:
                    service_info["product"] = server_match.group(1).strip()
                    if debug:
                        debug_emit(f"Found server header: {service_info['product']}")
            
            # Check for version numbers
            version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
            if version_match:
                service_info["version"] = version_match.group(1)
                if debug:
                    debug_emit(f"Found version: {service_info['version']}")
        
        # Use port-based fallback if still unknown
        if service_info["service"] == "unknown" and port in self.common_service_patterns:
            service_info["service"] = self.common_service_patterns[port]["name"]
            if debug:
                debug_emit(f"Using port-based fallback: {service_info['service']}")
        
        if verbose and on_output:
            on_output(f"[netcat] Identified service: {service_info['service']} {service_info['version']}", "info")
        
        return service_info
    
    def _enumerate_specific_service(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Perform service-specific enumeration.
        
        Args:
            target: Target IP address or hostname
            port: Port number
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary with additional service information
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-ENUM] {line}", "warning" if level == "info" else level)
                
        service_info = {"service": "unknown", "version": "", "details": ""}
        
        try:
            if port == 80 or port == 443:
                # HTTP/HTTPS enumeration
                service_info.update(self._enumerate_http(target, port, verbose=verbose, debug=debug, on_output=on_output))
            elif port == 21:
                # FTP enumeration
                service_info.update(self._enumerate_ftp(target, port, verbose=verbose, debug=debug, on_output=on_output))
            elif port == 22:
                # SSH enumeration
                service_info.update(self._enumerate_ssh(target, port, verbose=verbose, debug=debug, on_output=on_output))
            elif port == 25:
                # SMTP enumeration
                service_info.update(self._enumerate_smtp(target, port, verbose=verbose, debug=debug, on_output=on_output))
            
            if verbose and on_output and service_info["service"] != "unknown":
                on_output(f"[netcat] Service-specific enumeration completed for {service_info['service']}", "info")
            
        except Exception as e:
            if debug:
                debug_emit(f"Service-specific enumeration failed: {e}")
        
        return service_info
    
    def _enumerate_http(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Enumerate HTTP service."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-HTTP] {line}", "warning" if level == "info" else level)
                
        try:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{target}:{port}/"
            
            if debug:
                debug_emit(f"Making HTTP request to {url}")
            
            response = requests.get(url, timeout=10, verify=False)
            
            service_info = {
                "service": "http" if port == 80 else "https",
                "version": "",
                "product": ""
            }
            
            # Extract server information
            server_header = response.headers.get('Server', '')
            if server_header:
                service_info["product"] = server_header
                
                # Extract version from server header
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", server_header)
                if version_match:
                    service_info["version"] = version_match.group(1)
            
            if debug:
                debug_emit(f"HTTP enumeration result: {service_info}")
            
            return service_info
            
        except Exception as e:
            if debug:
                debug_emit(f"HTTP enumeration failed: {e}")
            return {"service": "http" if port == 80 else "https"}
    
    def _enumerate_ftp(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Enumerate FTP service."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-FTP] {line}", "warning" if level == "info" else level)
                
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            # Read welcome banner
            welcome = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            service_info = {
                "service": "ftp",
                "version": "",
                "product": ""
            }
            
            # Parse FTP banner
            if "ftp" in welcome.lower():
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", welcome)
                if version_match:
                    service_info["version"] = version_match.group(1)
                
                if "vsftpd" in welcome.lower():
                    service_info["product"] = "vsftpd"
                elif "proftpd" in welcome.lower():
                    service_info["product"] = "proftpd"
                elif "filezilla" in welcome.lower():
                    service_info["product"] = "filezilla"
            
            sock.close()
            
            if debug:
                debug_emit(f"FTP enumeration result: {service_info}")
            
            return service_info
            
        except Exception as e:
            if debug:
                debug_emit(f"FTP enumeration failed: {e}")
            return {"service": "ftp"}
    
    def _enumerate_ssh(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Enumerate SSH service."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-SSH] {line}", "warning" if level == "info" else level)
                
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            # Read SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            service_info = {
                "service": "ssh",
                "version": "",
                "product": ""
            }
            
            # Parse SSH banner (format: SSH-2.0-OpenSSH_7.4)
            ssh_match = re.search(r"SSH-(\d+\.\d+)-(.+)", banner)
            if ssh_match:
                protocol_version = ssh_match.group(1)
                server_version = ssh_match.group(2)
                
                service_info["version"] = protocol_version
                service_info["product"] = server_version
                
                # Extract OpenSSH version
                openssh_match = re.search(r"OpenSSH_(\d+\.\d+)", server_version)
                if openssh_match:
                    service_info["version"] = openssh_match.group(1)
                    service_info["product"] = "OpenSSH"
            
            sock.close()
            
            if debug:
                debug_emit(f"SSH enumeration result: {service_info}")
            
            return service_info
            
        except Exception as e:
            if debug:
                debug_emit(f"SSH enumeration failed: {e}")
            return {"service": "ssh"}
    
    def _enumerate_smtp(self, target: str, port: int, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, str]:
        """Enumerate SMTP service."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-SMTP] {line}", "warning" if level == "info" else level)
                
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            # Read SMTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Send EHLO command
            sock.send(b"EHLO test\r\n")
            ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            service_info = {
                "service": "smtp",
                "version": "",
                "product": ""
            }
            
            # Parse SMTP responses
            full_response = banner + " " + ehlo_response
            
            if "postfix" in full_response.lower():
                service_info["product"] = "Postfix"
            elif "sendmail" in full_response.lower():
                service_info["product"] = "Sendmail"
            elif "exim" in full_response.lower():
                service_info["product"] = "Exim"
            elif "microsoft" in full_response.lower():
                service_info["product"] = "Microsoft SMTP"
            
            # Extract version
            version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", full_response)
            if version_match:
                service_info["version"] = version_match.group(1)
            
            sock.close()
            
            if debug:
                debug_emit(f"SMTP enumeration result: {service_info}")
            
            return service_info
            
        except Exception as e:
            if debug:
                debug_emit(f"SMTP enumeration failed: {e}")
            return {"service": "smtp"}
    
    def enumerate_multiple_ports(self, target: str, ports: List[int], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[int, Dict[str, Any]]:
        """Enumerate multiple ports in parallel for better performance.
        
        Args:
            target: Target IP address or hostname
            ports: List of port numbers to enumerate
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary mapping port numbers to service information
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-MULTI] {line}", "warning" if level == "info" else level)
                
        results = {}
        
        if verbose and on_output:
            on_output(f"[Verbose] Enumerating {len(ports)} ports on {target} in parallel", "info")
        if debug:
            debug_emit(f"Starting parallel enumeration of {len(ports)} ports")
        
        # Use threading for parallel enumeration
        threads = []
        lock = threading.Lock()
        
        def enumerate_port(port):
            try:
                result = self.enumerate_service(target, port, verbose=verbose, debug=debug, on_output=on_output)
                with lock:
                    results[port] = result
            except Exception as e:
                if debug:
                    debug_emit(f"Thread for port {port} failed: {e}")
                with lock:
                    results[port] = {"error": str(e)}
        
        # Start threads (limit to 10 concurrent threads)
        for i in range(0, len(ports), 10):
            batch = ports[i:i+10]
            batch_threads = []
            
            for port in batch:
                thread = threading.Thread(target=enumerate_port, args=(port,))
                thread.start()
                batch_threads.append(thread)
            
            # Wait for batch to complete
            for thread in batch_threads:
                thread.join()
            
            if verbose and on_output:
                on_output(f"[Verbose] Completed enumeration batch {i//10 + 1}/{(len(ports) + 9)//10}", "info")
        
        if debug:
            debug_emit(f"Parallel enumeration completed, {len(results)} results")
        
        return results


class NmapScanner:
    """Wrapper for nmap scanning functionality."""

    def __init__(self) -> None:
        """Initialize the nmap scanner."""
        # This is kept for potential future use or other nmap utilities.
        self.scanner = nmap.PortScanner()
        self.netcat_enumerator = NetcatEnumerator()

    def scan_target(self, target: str, ports: str = "common", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """
        Scan a target for open ports and services using nmap with netcat fallback.
        
        Args:
            target: IP address or hostname to scan.
            ports: Port range to scan (default: 'common' for common ports, or specific range like '1-65535').
            verbose: If True, provides detailed output to the callback.
            debug: If True, provides comprehensive debug information.
            on_output: Callback function to send real-time output to.

        Returns:
            Dictionary containing scan results with enhanced service detection.
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-NMAP] {line}", "warning" if level == "info" else level)
                
        if verbose and on_output:
            on_output(f"[Verbose] Starting enhanced nmap scan on {target}:{ports}", "info")
        if debug:
            debug_emit(f"Enhanced NmapScanner.scan_target called")
            debug_emit(f"Target: {target}, Ports: {ports}")
            debug_emit(f"Verbose: {verbose}, Debug: {debug}")
            
        logger.info("Starting enhanced nmap scan", target=target, ports=ports)

        scan_start_time = time.time()
        try:
            # Handle common ports selection
            if ports == "common":
                # Comprehensive list of common ports for vulnerability assessment
                common_ports_raw = [
                    # Very common ports
                    "21", "22", "23", "25", "53", "80", "110", "111", "135", "139", "143", "443", "445", "993", "995",
                    # Database ports
                    "1433", "1521", "3306", "3389", "5432", "5984", "6379", "7000", "7001", "8086", "9042", "9200", "9300", "11211", "27017", "27018", "27019", "28017",
                    # Web services
                    "81", "591", "593", "832", "981", "1010", "1311", "2082", "2083", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5104", "5108", "5800", "6543", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9443", "9800", "9943", "9980", "9981", "12443", "16080", "18091", "18092", "20720",
                    # Remote access  
                    "179", "389", "636", "989", "990", "992", "1723", "1755", "1761", "2000", "2001", "2049", "2121", "2717", "4899", "5060", "5061", "5357", "5500", "5631", "5666", "5900", "5901", "5902", "5903", "6000", "6001", "6646", "7070", "8200", "8300", "8800", "8843", "9100", "9999", "10000", "32768", "49152", "49153", "49154", "49155", "49156", "49157",
                    # Additional common high ports
                    "4000", "6463", "7687", "8461", "10001", "10002", "10003", "10004", "10009", "10010", "10012", "10024", "10025", "10082", "10180", "10215", "10443", "10566", "10616", "10617", "10621", "10626", "10628", "10629", "10778", "11110", "11111", "11434", "11967", "12000", "12001", "12174", "12265", "12345", "13456", "13722", "13782", "13783", "14000", "14238", "14441", "14442", "15000", "15002", "15003", "15004", "15660", "15742", "16000", "16001", "16012", "16016", "16018", "16113", "16992", "16993", "17877", "17988", "18040", "18101", "18988", "19101", "19283", "19315", "19350", "19780", "19801", "19842", "20000", "20005", "20031", "20221", "20222", "20828", "21571", "22939", "23502", "24438", "24439", "24444", "24800", "25001", "25734", "25735", "26214", "27000", "27352", "27353", "27355", "27356", "27715", "28201", "30000", "30718", "30951", "31038", "31337", "32769", "32770", "32771", "32772", "32773", "32774", "32775", "32776", "32777", "32778", "32779", "32780", "32781", "32782", "32783", "32784", "32785", "33354", "33899", "34571", "34572", "34573", "35500", "35727", "38292", "40193", "40911", "41511", "42510", "44176", "44442", "44443", "44501", "45100", "48080", "49158", "49159", "49160", "49161", "49163", "49165", "49167", "49175", "49176", "65000", "65129", "65389"
                ]
                # Remove duplicates by converting to set and back to list, then sort
                common_ports = sorted(set(common_ports_raw), key=int)
                ports_arg = ",".join(common_ports)
                if verbose and on_output:
                    on_output(f"[Verbose] Using comprehensive common ports scan ({len(common_ports)} ports)", "info")
            else:
                ports_arg = ports
                if verbose and on_output:
                    on_output(f"[Verbose] Using custom port range: {ports}", "info")
            
            # Use more reasonable nmap command for faster scanning
            cmd = ["nmap", target, "-sV", "-sC", "-T4", "-v", f"-p{ports_arg}", "-oX", "-"]
            
            # If scanning localhost, exclude port 5000 to avoid interfering with the web server
            if target in ["127.0.0.1", "localhost"]:
                cmd.extend(["--exclude-ports", "5000"])
                if verbose and on_output:
                    on_output(f"[Verbose] Excluding port 5000 to avoid interfering with web server", "info")
            
            # Add reasonable timeouts (reduced from previous version)
            cmd.extend(["--host-timeout", "300s", "--max-rtt-timeout", "2s", "--max-retries", "3"])

            if verbose and on_output:
                on_output(f"[Verbose] Running command: {' '.join(cmd)}", "info")
                on_output(f"[Verbose] Using T4 timing and scanning ports {ports}", "info")
            if debug:
                debug_emit(f"Constructed nmap command: {' '.join(cmd)}")

            # Run nmap scan
            result = self._run_nmap_scan(cmd, target, scan_start_time, verbose=verbose, debug=debug, on_output=on_output)
            
            if "error" in result:
                return result
            
            # Enhance results with netcat enumeration for unknown services
            result = self._enhance_with_netcat(result, verbose=verbose, debug=debug, on_output=on_output)
            
            return result

        except FileNotFoundError:
            error_message = "nmap command not found. Please ensure nmap is installed and in your PATH."
            if on_output:
                on_output(error_message, "error")
            logger.error(error_message)
            return {"error": error_message}

        except Exception as e:
            error_message = f"An unexpected error occurred during nmap scan: {e}"
            if on_output:
                on_output(error_message, "error")
            logger.exception("Unexpected error during nmap scan", target=target)
            return {"error": error_message}

    def _run_nmap_scan(self, cmd: List[str], target: str, scan_start_time: float, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Run the nmap scan command and handle output."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-NMAP] {line}", "warning" if level == "info" else level)
                
        # Use Popen for real-time output - combine stdout and stderr for nmap verbose output
        if debug:
            debug_emit("Starting subprocess.Popen")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout to capture all nmap output
            text=True,
            bufsize=0,  # Unbuffered for real-time output
            universal_newlines=True
        )
        if debug:
            debug_emit(f"Process started, PID: {process.pid}")

        xml_output = []

        # Read output in real-time
        if debug:
            debug_emit("Starting real-time output reading loop")
        try:
            line_count = 0
            
            last_output_time = time.time()
            # Reduced timeout for faster scanning
            max_silence_time = 120  # 2 minutes without output
            
            while True:
                # Check if process is still running and hasn't been silent too long
                current_time = time.time()
                silence_duration = current_time - last_output_time
                
                if silence_duration > max_silence_time:
                    if verbose and on_output:
                        on_output(f"[Verbose] No output for {max_silence_time}s, checking if nmap is hung...", "warning")
                    
                    # Check if process is still alive
                    if process.poll() is None:
                        if verbose and on_output:
                            on_output("[Verbose] Nmap appears to be hung, terminating...", "warning")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        break
                
                # Check for overall timeout (reduced to 10 minutes)
                if current_time - scan_start_time > 600:
                    if verbose and on_output:
                        on_output("[Verbose] Scan exceeded 10 minute limit, terminating...", "warning")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    break
                
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    if debug:
                        debug_emit(f"End of output reached, total lines: {line_count}")
                    break
                
                if output:
                    last_output_time = current_time  # Reset the silence timer
                    line = output.strip()
                    xml_output.append(line)
                    line_count += 1
                    
                    # Show nmap output in real-time
                    if verbose and on_output and line.strip() and not line.startswith('<'):
                        if 'Starting Nmap' in line:
                            on_output(f"[nmap] 🚀 {line}", "info")
                        elif 'Initiating' in line:
                            on_output(f"[nmap] 🔍 {line}", "info")
                        elif 'Completed' in line:
                            on_output(f"[nmap] ✅ {line}", "success")
                        elif 'Discovered open port' in line:
                            on_output(f"[nmap] 🎯 {line}", "success")
                        elif 'Stats:' in line:
                            on_output(f"[nmap] 📊 {line}", "info")
                        else:
                            on_output(f"[nmap] {line}", "info")
                            
        except Exception as read_error:
            if verbose and on_output:
                on_output(f"[Verbose] Error reading nmap output: {read_error}", "warning")
            logger.warning("Error reading nmap output", error=str(read_error))

        # Wait for process to complete
        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            if verbose and on_output:
                on_output("[Verbose] Nmap process timeout, terminating...", "warning")
            process.terminate()
            try:
                return_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait()
        
        full_xml = '\n'.join(xml_output)

        if return_code != 0:
            error_message = f"Nmap scan failed with return code {return_code}."
            if on_output:
                on_output(error_message, "warning" if return_code == 1 else "error")
            logger.error("Nmap scan failed", target=target, return_code=return_code)
            
            # Continue processing if we have some XML output
            if return_code == 1 and full_xml.strip():
                if verbose and on_output:
                    on_output("[Verbose] Continuing despite warnings", "info")
            else:
                return {"error": error_message}

        if not full_xml.strip():
            if on_output:
                on_output(f"Nmap scan on {target} produced no output.", "warning")
            logger.warning("Nmap scan returned no output", target=target)
            return {"error": "Nmap returned no output."}

        # Extract XML content from mixed output
        xml_content = self._extract_xml_content(full_xml, verbose=verbose, debug=debug, on_output=on_output)
        if not xml_content:
            error_message = "No valid XML content found in nmap output."
            if on_output:
                on_output(error_message, "error")
            logger.error(error_message, target=target)
            return {"error": error_message}

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            error_message = f"Failed to parse nmap XML output: {e}"
            if on_output:
                on_output(error_message, "error")
            logger.error(error_message, target=target)
            return {"error": "Failed to parse nmap XML output."}

        result = self._parse_nmap_xml(root, target)
        
        # Calculate timing
        total_scan_time = time.time() - scan_start_time
        if on_output:
            on_output(f"[Verbose] ✅ Nmap scan completed for {target} in {total_scan_time:.1f}s", "success")
        
        return result

    def _extract_xml_content(self, mixed_output: str, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> str:
        """Extract clean XML content from mixed nmap output.
        
        Args:
            mixed_output: Raw output from nmap containing both XML and text
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Clean XML content or empty string if no valid XML found
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-XML] {line}", "warning" if level == "info" else level)
                
        if debug:
            debug_emit("Starting XML extraction from mixed output")
            debug_emit(f"Mixed output length: {len(mixed_output)} characters")
            
        # Find XML start and end markers
        xml_start_marker = "<?xml"
        xml_end_marker = "</nmaprun>"
        
        lines = mixed_output.split('\n')
        xml_lines = []
        in_xml = False
        
        for line in lines:
            # Check if we're starting XML content
            if xml_start_marker in line:
                in_xml = True
                # Include the line that starts the XML
                xml_lines.append(line)
                if debug:
                    debug_emit("Found XML start marker")
                continue
                
            # Check if we're ending XML content  
            if xml_end_marker in line:
                xml_lines.append(line)
                if debug:
                    debug_emit("Found XML end marker")
                break
                
            # Include XML lines
            if in_xml:
                xml_lines.append(line)
                
        xml_content = '\n'.join(xml_lines)
        
        if debug:
            debug_emit(f"Extracted XML content length: {len(xml_content)} characters")
            if xml_content.strip():
                debug_emit("XML extraction successful")
            else:
                debug_emit("XML extraction failed - no content found")
                
        return xml_content.strip()

    def _enhance_with_netcat(self, nmap_result: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Enhance nmap results with netcat enumeration for unknown services.
        
        Args:
            nmap_result: Results from nmap scan
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Enhanced results with netcat enumeration data
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-ENHANCE] {line}", "warning" if level == "info" else level)
                
        if "error" in nmap_result:
            return nmap_result
        
        try:
            target = nmap_result.get("target", "")
            ports_to_enumerate = []
            
            # Find ports that need better service identification
            for port_info in nmap_result.get("ports", []):
                if port_info.get("state") == "open":
                    service = port_info.get("service", "")
                    version = port_info.get("version", "")
                    
                    # Enumerate if service is unknown or no version detected
                    if (service in ["unknown", "tcpwrapped", ""] or 
                        version == "" or 
                        service == "http" and not version):
                        ports_to_enumerate.append(int(port_info["port"]))
            
            if ports_to_enumerate:
                if verbose and on_output:
                    on_output(f"[Verbose] Enhancing {len(ports_to_enumerate)} ports with netcat enumeration", "info")
                if debug:
                    debug_emit(f"Ports to enumerate: {ports_to_enumerate}")
                
                # Enumerate ports with netcat
                netcat_results = self.netcat_enumerator.enumerate_multiple_ports(
                    target, ports_to_enumerate, verbose=verbose, debug=debug, on_output=on_output
                )
                
                # Merge results
                for port_info in nmap_result["ports"]:
                    port_num = int(port_info["port"])
                    if port_num in netcat_results:
                        netcat_info = netcat_results[port_num]
                        if "error" not in netcat_info:
                            # Update service information if netcat found something better
                            if netcat_info.get("service", "unknown") != "unknown":
                                port_info["service"] = netcat_info["service"]
                                port_info["netcat_service"] = netcat_info["service"]
                            
                            if netcat_info.get("version", ""):
                                port_info["version"] = netcat_info["version"]
                                port_info["netcat_version"] = netcat_info["version"]
                            
                            if netcat_info.get("product", ""):
                                port_info["product"] = netcat_info["product"]
                                port_info["netcat_product"] = netcat_info["product"]
                            
                            if netcat_info.get("banner", ""):
                                port_info["banner"] = netcat_info["banner"]
                            
                            port_info["enhanced_by_netcat"] = True
                            
                            if verbose and on_output:
                                on_output(f"[netcat] Enhanced port {port_num}: {netcat_info['service']} {netcat_info.get('version', '')}", "success")
            
            if verbose and on_output:
                enhanced_count = len([p for p in nmap_result["ports"] if p.get("enhanced_by_netcat")])
                on_output(f"[Verbose] Netcat enhancement completed. Enhanced {enhanced_count} ports.", "info")
            
            return nmap_result
            
        except Exception as e:
            error_msg = f"Netcat enhancement failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            # Return original results if enhancement fails
            return nmap_result

    def _parse_nmap_xml(self, root: ET.Element, target: str) -> Dict[str, Any]:
        """Parse the XML output from nmap into a dictionary."""
        
        result: Dict[str, Any] = {
            "target": target,
            "status": "unknown",
            "ports": [],
            "os_info": [],
            "vulnerabilities": []
        }

        host_element = root.find("host")
        if not host_element:
            return result

        status_element = host_element.find("status")
        if status_element is not None:
            result["status"] = status_element.get("state", "unknown")

        ports_element = host_element.find("ports")
        if ports_element is not None:
            for port_element in ports_element.findall("port"):
                port_id = port_element.get("portid")
                state_element = port_element.find("state")
                service_element = port_element.find("service")
                
                port_info = {
                    "port": port_id,
                    "state": state_element.get("state") if state_element is not None else "unknown",
                    "service": service_element.get("name") if service_element is not None else "unknown",
                    "version": service_element.get("version") if service_element is not None else "",
                    "product": service_element.get("product") if service_element is not None else "",
                    "script_output": {}
                }
                
                for script_element in port_element.findall("script"):
                    script_id = script_element.get("id")
                    script_output = script_element.get("output")
                    if script_id and script_output:
                        port_info["script_output"][script_id] = script_output
                        if "vuln" in script_id.lower():
                            result["vulnerabilities"].append({
                                "port": port_id,
                                "script": script_id,
                                "output": script_output
                            })
                result["ports"].append(port_info)
        
        os_element = host_element.find("os")
        if os_element is not None:
            for osmatch in os_element.findall("osmatch"):
                result["os_info"].append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                })

        return result


class MetasploitWrapper:
    """Wrapper for Metasploit Framework functionality."""
    
    def __init__(self) -> None:
        """Initialize the Metasploit wrapper."""
        self.msf_path = config.METASPLOIT_PATH
        self.search_cache = {}  # Cache search results
        
    def search_exploits(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Search for exploits matching a service and version with caching.
        
        Args:
            service: Service name (e.g., "apache", "ssh")
            version: Version string (optional)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            
        Returns:
            List of matching exploits
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-MSF] {line}", "warning" if level == "info" else level)
                
        # Check cache first
        cache_key = f"{service}:{version}"
        if cache_key in self.search_cache:
            if debug:
                debug_emit(f"Using cached Metasploit results for {cache_key}")
            return self.search_cache[cache_key]
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Searching Metasploit exploits for {service} {version}", "info")
            if debug:
                debug_emit(f"MetasploitWrapper.search_exploits called")
                debug_emit(f"Service: {service}, Version: {version}")
                debug_emit(f"MSF Path: {self.msf_path}")
            logger.info("Searching Metasploit exploits", service=service, version=version)
            
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                # Improved search query
                search_query = f"search type:exploit name:{service}"
                if version:
                    search_query += f" {version}"
                
                script_content = f"""
{search_query}
exit
"""
                f.write(script_content)
                script_path = f.name
            
            # Run msfconsole with script
            cmd = [self.msf_path, "-r", script_path, "-q", "-x", f"'{search_query}; exit'"]
            if verbose and on_output:
                on_output(f"[Verbose] Running Metasploit command: {' '.join(cmd)}", "info")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if verbose and on_output:
                if result.stdout.strip():
                    on_output(f"[msfconsole] Metasploit search completed", "info")
                if result.stderr.strip():
                    on_output(f"[msfconsole] Warnings: {result.stderr[:200]}", "warning")
            
            # Parse results
            exploits = []
            for line in result.stdout.split('\n'):
                if 'exploit/' in line and service.lower() in line.lower():
                    # Parse exploit line format
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        exploit_path = parts[0]
                        rank = parts[1] if len(parts) > 1 else "unknown"
                        description = " ".join(parts[2:]) if len(parts) > 2 else ""
                        
                        exploits.append({
                            "name": exploit_path,
                            "rank": rank,
                            "description": description,
                            "service": service,
                            "source": "metasploit"
                        })
            
            # Cache results
            self.search_cache[cache_key] = exploits
            
            # Clean up
            Path(script_path).unlink(missing_ok=True)
            
            if verbose and on_output:
                on_output(f"[Verbose] Metasploit search completed. Found {len(exploits)} exploits.", "info")
            logger.info("Metasploit search completed", service=service, exploits_found=len(exploits))
            return exploits
            
        except subprocess.TimeoutExpired:
            error_msg = "Metasploit search timed out"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "warning")
            logger.warning(error_msg, service=service)
            return []
        except Exception as e:
            error_msg = f"Metasploit search failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, service=service, error=str(e))
            return []


class ExploitDBWrapper:
    """Wrapper for Exploit-DB API functionality with retry logic."""
    
    def __init__(self) -> None:
        """Initialize the Exploit-DB wrapper."""
        self.api_key = config.EXPLOIT_DB_API_KEY
        self.base_url = "https://exploit-db.com/api/v1"
        self.search_cache = {}  # Cache search results
        self.retry_count = 3
        self.retry_delay = 2
        
    def search_exploits(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Search Exploit-DB for exploits with retry logic and caching.
        
        Args:
            service: Service name (e.g., "apache", "ssh")
            version: Version string (optional)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            
        Returns:
            List of matching exploits
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-EDB] {line}", "warning" if level == "info" else level)
                
        # Check cache first
        cache_key = f"{service}:{version}"
        if cache_key in self.search_cache:
            if debug:
                debug_emit(f"Using cached Exploit-DB results for {cache_key}")
            return self.search_cache[cache_key]
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Searching Exploit-DB for {service} {version}", "info")
            logger.info("Searching Exploit-DB", service=service, version=version)
            
            # Build search query
            query = service
            if version:
                query += f" {version}"
            
            # Try multiple search approaches
            search_params_list = [
                {"q": query, "type": "exploits"},
                {"q": service, "type": "exploits"},  # Fallback without version
                {"search": query},  # Alternative parameter name
            ]
            
            for attempt, params in enumerate(search_params_list):
                if debug:
                    debug_emit(f"Search attempt {attempt + 1} with params: {params}")
                    
                for retry in range(self.retry_count):
                    try:
                        headers = {
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                        }
                        if self.api_key:
                            headers["Authorization"] = f"Bearer {self.api_key}"
                        
                        if verbose and on_output:
                            on_output(f"[Verbose] Exploit-DB API request attempt {retry + 1}/{self.retry_count}", "info")
                        
                        response = requests.get(
                            f"{self.base_url}/search",
                            headers=headers,
                            params=params,
                            timeout=15
                        )
                        
                        if debug:
                            debug_emit(f"API response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            data = response.json()
                            
                            exploits = []
                            results = data.get("data", [])
                            
                            if not results and "results" in data:
                                results = data["results"]
                            
                            for item in results:
                                exploit = {
                                    "id": item.get("id"),
                                    "title": item.get("title", ""),
                                    "description": item.get("description", ""),
                                    "author": item.get("author", {}).get("name", "") if isinstance(item.get("author"), dict) else str(item.get("author", "")),
                                    "date": item.get("date_published", ""),
                                    "platform": item.get("platform", ""),
                                    "type": item.get("type", ""),
                                    "verified": item.get("verified", False),
                                    "source": "exploit-db"
                                }
                                exploits.append(exploit)
                            
                            # Cache results
                            self.search_cache[cache_key] = exploits
                            
                            if verbose and on_output:
                                on_output(f"[Verbose] Exploit-DB search completed. Found {len(exploits)} exploits.", "info")
                            logger.info("Exploit-DB search completed", service=service, exploits_found=len(exploits))
                            return exploits
                            
                        elif response.status_code == 403:
                            if verbose and on_output:
                                on_output(f"[Verbose] Exploit-DB API blocked (403). Trying alternative approach...", "warning")
                            # Try alternative search method
                            alternative_result = self._search_alternative(service, version, verbose=verbose, debug=debug, on_output=on_output)
                            if alternative_result:
                                return alternative_result
                            continue
                            
                        elif response.status_code == 429:
                            if verbose and on_output:
                                on_output(f"[Verbose] Exploit-DB rate limit hit. Retrying in {self.retry_delay}s...", "warning")
                            time.sleep(self.retry_delay)
                            continue
                        else:
                            if debug:
                                debug_emit(f"API request failed with status {response.status_code}")
                            break
                            
                    except requests.exceptions.RequestException as e:
                        if debug:
                            debug_emit(f"Request exception: {e}")
                        if retry < self.retry_count - 1:
                            time.sleep(self.retry_delay)
                        continue
                
                # If we got here, this search approach failed, try the next one
                if debug:
                    debug_emit(f"Search approach {attempt + 1} failed, trying next approach")
            
            if verbose and on_output:
                on_output(f"[Verbose] All Exploit-DB search attempts failed", "warning")
            logger.warning("All Exploit-DB search attempts failed", service=service)
            return []
                
        except Exception as e:
            error_msg = f"Exploit-DB search failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, service=service, error=str(e))
            return []
    
    def _search_alternative(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Alternative search method when API is blocked."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-ALT] {line}", "warning" if level == "info" else level)
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Trying alternative Exploit-DB search method", "info")
            
            # Try using searchsploit if available
            try:
                cmd = ["searchsploit", service]
                if version:
                    cmd.append(version)
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    exploits = []
                    for line in result.stdout.split('\n'):
                        if '|' in line and service.lower() in line.lower():
                            parts = line.split('|')
                            if len(parts) >= 2:
                                title = parts[0].strip()
                                path = parts[1].strip() if len(parts) > 1 else ""
                                
                                exploits.append({
                                    "title": title,
                                    "path": path,
                                    "source": "searchsploit",
                                    "service": service
                                })
                    
                    if verbose and on_output:
                        on_output(f"[Verbose] Alternative search found {len(exploits)} exploits", "info")
                    return exploits
                    
            except (FileNotFoundError, subprocess.TimeoutExpired):
                if debug:
                    debug_emit("searchsploit not available or timed out")
                pass
            
            # If searchsploit fails, return empty list
            return []
            
        except Exception as e:
            if debug:
                debug_emit(f"Alternative search failed: {e}")
            return []


class VulnerabilityAnalyzer:
    """Analyzes scan results to identify potential vulnerabilities."""
    
    def __init__(self) -> None:
        """Initialize the vulnerability analyzer."""
        self.msf_wrapper = MetasploitWrapper()
        self.exploit_db_wrapper = ExploitDBWrapper()
        
    def analyze_scan_results(self, scan_results: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Analyze nmap scan results to identify vulnerabilities.
        
        Args:
            scan_results: Results from nmap scan
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary containing vulnerability analysis
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-VULN] {line}", "warning" if level == "info" else level)
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Analyzing scan results for vulnerabilities", "info")
            logger.info("Analyzing scan results for vulnerabilities")
            
            analysis = {
                "target": scan_results.get("target"),
                "vulnerabilities": [],
                "recommendations": [],
                "exploits_found": [],
                "enhanced_services": []
            }
            
            # Analyze each open port
            for port_info in scan_results.get("ports", []):
                if port_info.get("state") == "open":
                    service = port_info.get("service", "")
                    version = port_info.get("version", "")
                    product = port_info.get("product", "")
                    
                    if verbose and on_output:
                        enhanced_text = " (enhanced by netcat)" if port_info.get("enhanced_by_netcat") else ""
                        on_output(f"[Verbose] Analyzing port {port_info['port']}: {service} {version} {product}{enhanced_text}", "info")
                    
                    # Track netcat-enhanced services
                    if port_info.get("enhanced_by_netcat"):
                        analysis["enhanced_services"].append({
                            "port": port_info["port"],
                            "service": service,
                            "version": version,
                            "banner": port_info.get("banner", "")
                        })
                    
                    # Search for exploits only for known services
                    if service and service != "unknown":
                        if verbose and on_output:
                            on_output(f"[Verbose] Searching for exploits for service: {service}", "info")
                            
                        # Search Metasploit (with timeout protection)
                        try:
                            msf_exploits = self.msf_wrapper.search_exploits(service, version, verbose=verbose, debug=debug, on_output=on_output)
                            for exploit in msf_exploits:
                                analysis["exploits_found"].append({
                                    "source": "metasploit",
                                    "port": port_info["port"],
                                    "service": service,
                                    "exploit": exploit
                                })
                        except Exception as e:
                            if debug:
                                debug_emit(f"Metasploit search failed: {e}")
                        
                        # Search Exploit-DB (with timeout protection)
                        try:
                            edb_exploits = self.exploit_db_wrapper.search_exploits(service, version, verbose=verbose, debug=debug, on_output=on_output)
                            for exploit in edb_exploits:
                                analysis["exploits_found"].append({
                                    "source": "exploit-db",
                                    "port": port_info["port"],
                                    "service": service,
                                    "exploit": exploit
                                })
                        except Exception as e:
                            if debug:
                                debug_emit(f"Exploit-DB search failed: {e}")
                    
                    # Enhanced vulnerability detection
                    vulnerabilities = self._detect_vulnerabilities(port_info, verbose=verbose, debug=debug, on_output=on_output)
                    analysis["vulnerabilities"].extend(vulnerabilities)
            
            # Generate recommendations
            self._generate_recommendations(analysis, verbose=verbose, debug=debug, on_output=on_output)
            
            if verbose and on_output:
                on_output(f"[Verbose] Vulnerability analysis completed. Found {len(analysis['exploits_found'])} exploits, {len(analysis['vulnerabilities'])} vulnerabilities.", "info")
                if analysis["enhanced_services"]:
                    on_output(f"[Verbose] Netcat enhanced {len(analysis['enhanced_services'])} services with better detection.", "info")
            
            logger.info("Vulnerability analysis completed", 
                       exploits_found=len(analysis["exploits_found"]),
                       vulnerabilities_found=len(analysis["vulnerabilities"]),
                       enhanced_services=len(analysis["enhanced_services"]))
            
            return analysis
            
        except Exception as e:
            error_msg = f"Vulnerability analysis failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def _detect_vulnerabilities(self, port_info: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Detect vulnerabilities for a specific port."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-DETECT] {line}", "warning" if level == "info" else level)
                
        vulnerabilities = []
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "")
        port = port_info.get("port", "")
        
        # Enhanced vulnerability detection patterns
        vuln_patterns = {
            "ssh": {
                "versions": ["2.0", "1.99", "1.9"],
                "vuln_type": "weak_protocol",
                "description": "Old SSH protocol version detected",
                "severity": "medium"
            },
            "ftp": {
                "always_vulnerable": True,
                "vuln_type": "cleartext_auth",
                "description": "FTP transmits credentials in cleartext",
                "severity": "medium"
            },
            "telnet": {
                "always_vulnerable": True,
                "vuln_type": "cleartext_auth",
                "description": "Telnet transmits all data in cleartext",
                "severity": "high"
            },
            "http": {
                "check_version": True,
                "vuln_type": "web_service",
                "description": "Web service detected - potential for web-based attacks",
                "severity": "low"
            },
            "mysql": {
                "default_ports": ["3306"],
                "vuln_type": "database_exposure",
                "description": "Database service exposed to network",
                "severity": "high"
            },
            "postgresql": {
                "default_ports": ["5432"],
                "vuln_type": "database_exposure",
                "description": "Database service exposed to network",
                "severity": "high"
            },
            "rdp": {
                "default_ports": ["3389"],
                "vuln_type": "remote_desktop",
                "description": "Remote Desktop Protocol exposed",
                "severity": "high"
            },
            "vnc": {
                "default_ports": ["5900"],
                "vuln_type": "remote_desktop",
                "description": "VNC remote desktop exposed",
                "severity": "high"
            }
        }
        
        if service in vuln_patterns:
            pattern = vuln_patterns[service]
            
            if pattern.get("always_vulnerable"):
                vulnerabilities.append({
                    "type": pattern["vuln_type"],
                    "port": port,
                    "service": service,
                    "description": pattern["description"],
                    "severity": pattern["severity"],
                    "version": version
                })
                if debug:
                    debug_emit(f"Always vulnerable service detected: {service}")
            
            elif pattern.get("versions") and version:
                for vuln_version in pattern["versions"]:
                    if vuln_version in version:
                        vulnerabilities.append({
                            "type": pattern["vuln_type"],
                            "port": port,
                            "service": service,
                            "description": f"{pattern['description']} (version {version})",
                            "severity": pattern["severity"],
                            "version": version
                        })
                        if debug:
                            debug_emit(f"Vulnerable version detected: {service} {version}")
            
            elif pattern.get("check_version") or pattern.get("default_ports"):
                vulnerabilities.append({
                    "type": pattern["vuln_type"],
                    "port": port,
                    "service": service,
                    "description": pattern["description"],
                    "severity": pattern["severity"],
                    "version": version
                })
                if debug:
                    debug_emit(f"Service vulnerability detected: {service}")
        
        # Check for common weak authentication scenarios
        if service in ["ssh", "ftp", "telnet", "mysql", "postgresql"]:
            vulnerabilities.append({
                "type": "weak_auth_potential",
                "port": port,
                "service": service,
                "description": f"Service {service} may have weak authentication",
                "severity": "medium",
                "version": version
            })
        
        # Check banner for specific vulnerability indicators
        banner = port_info.get("banner", "")
        if banner:
            if "default" in banner.lower() or "admin" in banner.lower():
                vulnerabilities.append({
                    "type": "default_credentials",
                    "port": port,
                    "service": service,
                    "description": "Service banner suggests default credentials",
                    "severity": "high",
                    "banner": banner[:100]
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self, analysis: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> None:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        if analysis["exploits_found"]:
            recommendations.append({
                "priority": "critical",
                "action": "exploit_available",
                "description": f"Found {len(analysis['exploits_found'])} potential exploits - immediate testing recommended",
                "count": len(analysis["exploits_found"])
            })
        
        if analysis["vulnerabilities"]:
            high_severity = len([v for v in analysis["vulnerabilities"] if v.get("severity") == "high"])
            if high_severity > 0:
                recommendations.append({
                    "priority": "high",
                    "action": "high_severity_vulns",
                    "description": f"Found {high_severity} high-severity vulnerabilities requiring immediate attention",
                    "count": high_severity
                })
        
        if analysis["enhanced_services"]:
            recommendations.append({
                "priority": "medium",
                "action": "netcat_enhanced",
                "description": f"Netcat enumeration enhanced {len(analysis['enhanced_services'])} services - manual verification recommended",
                "count": len(analysis["enhanced_services"])
            })
        
        # Add general recommendations
        open_ports = len([p for p in analysis.get("ports", []) if p.get("state") == "open"])
        if open_ports > 10:
            recommendations.append({
                "priority": "medium",
                "action": "port_reduction",
                "description": f"{open_ports} open ports detected - consider reducing attack surface",
                "count": open_ports
            })
        
        analysis["recommendations"] = recommendations


class ToolManager:
    """Manages all security tools for the LLM agent."""
    
    def __init__(self) -> None:
        """Initialize the tool manager."""
        self.nmap_scanner = NmapScanner()
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.netcat_enumerator = NetcatEnumerator()
        
    def scan_and_analyze(self, target: str, ports: str = "common", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Perform complete scan and vulnerability analysis with netcat enhancement.
        
        Args:
            target: Target IP address or hostname
            ports: Port range to scan (default: 'common' for common ports, or specific range like '1-65535')
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Complete analysis results
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-TOOLMGR] {line}", "warning" if level == "info" else level)
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Starting enhanced scan and analysis for {target}:{ports}", "info")
            if debug:
                debug_emit(f"Enhanced ToolManager.scan_and_analyze called for target: {target}")
                debug_emit(f"Port range: {ports}")
                debug_emit(f"Scanner initialized: {self.nmap_scanner is not None}")
                debug_emit(f"Analyzer initialized: {self.vuln_analyzer is not None}")
                debug_emit(f"Netcat enumerator initialized: {self.netcat_enumerator is not None}")
                
            logger.info("Starting enhanced scan and analysis", target=target, ports=ports)
            
            # Step 1: Enhanced Nmap scan with netcat fallback
            if debug:
                debug_emit("Step 1: Starting enhanced nmap scan")
            scan_results = self.nmap_scanner.scan_target(target, ports, verbose=verbose, debug=debug, on_output=on_output)
            if "error" in scan_results:
                if debug:
                    debug_emit(f"Nmap scan failed: {scan_results['error']}", "error")
                return scan_results
            if debug:
                debug_emit(f"Enhanced nmap scan completed, found {len(scan_results.get('ports', []))} ports")
                enhanced_ports = len([p for p in scan_results.get('ports', []) if p.get('enhanced_by_netcat')])
                if enhanced_ports > 0:
                    debug_emit(f"Netcat enhanced {enhanced_ports} ports")
            
            # Step 2: Enhanced vulnerability analysis
            if debug:
                debug_emit("Step 2: Starting enhanced vulnerability analysis")
            analysis = self.vuln_analyzer.analyze_scan_results(scan_results, verbose=verbose, debug=debug, on_output=on_output)
            if debug:
                debug_emit(f"Enhanced vulnerability analysis completed")
            
            # Step 3: Combine results
            if debug:
                debug_emit("Step 3: Combining enhanced results")
            complete_results = {
                "target": target,
                "ports_scanned": ports,
                "scan_results": scan_results,
                "vulnerability_analysis": analysis,
                "netcat_enhanced": len([p for p in scan_results.get('ports', []) if p.get('enhanced_by_netcat')]) > 0,
                "timestamp": time.time()
            }
            
            if verbose and on_output:
                total_ports = len(scan_results.get('ports', []))
                enhanced_ports = len([p for p in scan_results.get('ports', []) if p.get('enhanced_by_netcat')])
                exploits_found = len(analysis.get('exploits_found', []))
                vulnerabilities_found = len(analysis.get('vulnerabilities', []))
                
                on_output(f"[Verbose] ✅ Enhanced scan and analysis completed for {target}", "success")
                on_output(f"[Verbose] 📊 Results: {total_ports} ports, {enhanced_ports} netcat-enhanced, {exploits_found} exploits, {vulnerabilities_found} vulnerabilities", "info")
                
            if debug:
                debug_emit(f"Enhanced analysis finished, result keys: {list(complete_results.keys())}")
                
            logger.info("Enhanced scan and analysis finished", target=target, 
                       ports_found=len(scan_results.get('ports', [])),
                       netcat_enhanced=complete_results["netcat_enhanced"],
                       exploits_found=len(analysis.get('exploits_found', [])),
                       vulnerabilities_found=len(analysis.get('vulnerabilities', [])))
            return complete_results
            
        except Exception as e:
            error_msg = f"Enhanced scan and analysis failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, target=target, error=str(e))
            return {"error": error_msg}
    
    def search_exploits(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Search for exploits using multiple sources.
        
        Args:
            service: Service name
            version: Service version
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Combined exploit search results
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-SEARCH] {line}", "warning" if level == "info" else level)
                
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Searching exploits for {service} {version}", "info")
            
            results = {
                "service": service,
                "version": version,
                "metasploit_exploits": [],
                "exploitdb_exploits": [],
                "total_exploits": 0
            }
            
            # Search Metasploit
            try:
                msf_exploits = self.vuln_analyzer.msf_wrapper.search_exploits(service, version, verbose=verbose, debug=debug, on_output=on_output)
                results["metasploit_exploits"] = msf_exploits
            except Exception as e:
                if debug:
                    debug_emit(f"Metasploit search failed: {e}")
            
            # Search Exploit-DB
            try:
                edb_exploits = self.vuln_analyzer.exploit_db_wrapper.search_exploits(service, version, verbose=verbose, debug=debug, on_output=on_output)
                results["exploitdb_exploits"] = edb_exploits
            except Exception as e:
                if debug:
                    debug_emit(f"Exploit-DB search failed: {e}")
            
            results["total_exploits"] = len(results["metasploit_exploits"]) + len(results["exploitdb_exploits"])
            
            if verbose and on_output:
                on_output(f"[Verbose] Exploit search completed. Found {results['total_exploits']} total exploits.", "info")
            
            return results
            
        except Exception as e:
            error_msg = f"Exploit search failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, service=service, error=str(e))
            return {"error": error_msg}
    
    def generate_exploit(self, vulnerability: Dict[str, Any], target_info: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Generate a custom exploit for a vulnerability.
        
        Args:
            vulnerability: Vulnerability details
            target_info: Target information
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Generated exploit information
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Generating custom exploit for {vulnerability.get('type', 'unknown')} vulnerability", "info")
            
            # This is a placeholder for exploit generation
            # In a real implementation, this would use AI or predefined templates
            exploit_template = {
                "vulnerability": vulnerability,
                "target": target_info,
                "exploit_type": "custom",
                "language": "python",
                "code": "# Custom exploit generation not implemented in this version",
                "description": "Custom exploit generation requires advanced AI capabilities",
                "status": "template_only"
            }
            
            if verbose and on_output:
                on_output(f"[Verbose] Custom exploit template generated", "info")
            
            return exploit_template
            
        except Exception as e:
            error_msg = f"Exploit generation failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def test_exploit(self, exploit_code: str, target: str, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Test an exploit against a target.
        
        Args:
            exploit_code: Exploit code to test
            target: Target to test against
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Test results
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Testing exploit against {target}", "info")
            
            # This is a placeholder for exploit testing
            # In a real implementation, this would safely execute the exploit
            test_result = {
                "target": target,
                "exploit_code": exploit_code[:200] + "...",  # Truncate for display
                "test_status": "not_implemented",
                "description": "Exploit testing requires safe execution environment",
                "recommendation": "Manual testing in controlled environment recommended"
            }
            
            if verbose and on_output:
                on_output(f"[Verbose] Exploit testing completed (simulation)", "info")
            
            return test_result
            
        except Exception as e:
            error_msg = f"Exploit testing failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg} 