"""Security tools management for RouterSploit GUI."""

import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import socket
import threading
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

import json
import nmap
import requests
import structlog
import urllib.parse

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
            # Handle port selection with optimized settings
            if ports == "common":
                # Use nmap's top 1000 ports for fast and effective scanning
                if verbose and on_output:
                    on_output(f"[Verbose] Using nmap's top 1000 most common ports for fast scanning", "info")
                cmd = ["nmap", target, "-sV", "-sC", "-T5", "-v", "--top-ports", "1000", "-oX", "-"]
            elif ports == "1-65535":
                # For full port scans, use top ports first for better reliability
                if verbose and on_output:
                    on_output(f"[Verbose] Full port range requested - using top 1000 ports for reliability", "info")
                cmd = ["nmap", target, "-sV", "-sC", "-T5", "-v", "--top-ports", "1000", "-oX", "-"]
            else:
                if verbose and on_output:
                    on_output(f"[Verbose] Using custom port range: {ports}", "info")
                cmd = ["nmap", target, "-sV", "-sC", "-T5", "-v", f"-p{ports}", "-oX", "-"]
            
            # If scanning localhost, exclude port 5000 to avoid interfering with the web server
            if target in ["127.0.0.1", "localhost"]:
                cmd.extend(["--exclude-ports", "5000"])
                if verbose and on_output:
                    on_output(f"[Verbose] Excluding port 5000 to avoid interfering with web server", "info")
            
            # Add optimized timeout settings for better reliability
            cmd.extend(["--host-timeout", "600s", "--max-rtt-timeout", "5s", "--max-retries", "2"])

            if verbose and on_output:
                on_output(f"[Verbose] Running command: {' '.join(cmd)}", "info")
                on_output(f"[Verbose] Using T5 timing for fast and reliable scanning", "info")
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
        # Get API key from config file (dynamically)
        self.api_key = config.get_exploitdb_api_key()
        self.base_url = "https://exploit-db.com/api/v1"
        self.search_cache = {}  # Cache search results
        self.retry_count = 3
        self.retry_delay = 2
        self.enabled = bool(self.api_key.strip())  # Only enable if API key is provided
        
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
        
        # Check if ExploitDB is enabled (has API key)
        if not self.enabled:
            if verbose and on_output:
                on_output("[Verbose] ExploitDB API key not configured - skipping ExploitDB search", "warning")
            if debug:
                debug_emit("ExploitDB search skipped - no API key configured")
            return []  # Return empty list gracefully
                
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


class WebSearchWrapper:
    """Wrapper for web search functionality to find vulnerability information."""
    
    def __init__(self) -> None:
        """Initialize the web search wrapper."""
        self.search_cache = {}  # Cache search results
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
    def search_vulnerabilities(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Search the web for vulnerability information about a service and version.
        
        Args:
            service: Service name (e.g., "apache", "openssh")
            version: Version string (optional)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            List of vulnerability information found
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-WEB] {line}", "warning" if level == "info" else level)
        
        # Check cache first
        cache_key = f"{service}:{version}"
        if cache_key in self.search_cache:
            if debug:
                debug_emit(f"Using cached web search results for {cache_key}")
            return self.search_cache[cache_key]
        
        try:
            if verbose and on_output:
                on_output(f"[Verbose] 🌐 Searching web for {service} {version} vulnerabilities", "info")
            logger.info("Searching web for vulnerabilities", service=service, version=version)
            
            # Use the detailed service string as the primary query
            search_query = f"{service} vulnerability CVE"
            
            if debug:
                debug_emit(f"Searching: {search_query}")
            
            vulnerabilities = []
            search_results = self._search_duckduckgo(search_query, debug=debug, on_output=on_output)
            
            for result in search_results:
                vuln_info = self._extract_vulnerability_info(result, service, version)
                if vuln_info:
                    vulnerabilities.append(vuln_info)

            # Remove duplicates based on CVE ID or title
            unique_vulns = []
            seen_ids = set()
            for vuln in vulnerabilities:
                vuln_id = vuln.get('cve_id') or vuln.get('title', '')
                if vuln_id not in seen_ids:
                    seen_ids.add(vuln_id)
                    unique_vulns.append(vuln)
            
            # Cache results
            self.search_cache[cache_key] = unique_vulns
            
            if verbose and on_output:
                on_output(f"[Verbose] 🌐 Found {len(unique_vulns)} vulnerability entries from web search", "info")
            
            if debug:
                debug_emit(f"Web search completed: {len(unique_vulns)} unique vulnerabilities found")
                for vuln in unique_vulns[:3]:  # Show first 3
                    debug_emit(f"  • {vuln.get('title', 'Unknown')}: {vuln.get('cve_id', 'No CVE')}")
            
            return unique_vulns
            
        except Exception as e:
            error_msg = f"Web vulnerability search failed: {str(e)}"
            if debug:
                debug_emit(f"ERROR: {error_msg}")
            logger.warning("Web vulnerability search failed", service=service, error=str(e))
            return []
    
    def _search_duckduckgo(self, query: str, debug: bool = False, on_output: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Search DuckDuckGo for the given query.
        
        Args:
            query: Search query
            debug: Whether to emit debug information
            on_output: Optional callback for output lines
            
        Returns:
            List of search results
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-DDG] {line}", "warning" if level == "info" else level)
        
        try:
            # DuckDuckGo instant answers API (no rate limits, no API key)
            encoded_query = urllib.parse.quote_plus(query)
            url = f"https://api.duckduckgo.com/?q={encoded_query}&format=json&no_html=1&skip_disambig=1"
            
            headers = {
                'User-Agent': self.user_agent
            }
            
            if debug:
                debug_emit(f"DuckDuckGo API request: {url}")
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                if debug:
                    debug_emit(f"DuckDuckGo returned non-JSON response: {response.text[:100]}...")
                return []
            
            results = []
            
            # Extract from RelatedTopics
            for topic in data.get('RelatedTopics', []):
                if isinstance(topic, dict) and 'Text' in topic:
                    results.append({
                        'title': topic.get('Text', '')[:100],
                        'snippet': topic.get('Text', ''),
                        'url': topic.get('FirstURL', ''),
                        'source': 'duckduckgo'
                    })
            
            # Extract from Abstract
            if data.get('Abstract'):
                results.append({
                    'title': data.get('AbstractText', '')[:100],
                    'snippet': data.get('Abstract', ''),
                    'url': data.get('AbstractURL', ''),
                    'source': 'duckduckgo'
                })
            
            if debug:
                debug_emit(f"DuckDuckGo returned {len(results)} results")
            
            return results[:10]  # Limit results
            
        except Exception as e:
            if debug:
                debug_emit(f"DuckDuckGo search failed: {e}")
            return []
    
    def _extract_vulnerability_info(self, search_result: Dict[str, Any], service: str, version: str) -> Optional[Dict[str, Any]]:
        """Extract vulnerability information from a search result.
        
        Args:
            search_result: Search result dictionary
            service: Service name being searched
            version: Version being searched
            
        Returns:
            Vulnerability information if found, None otherwise
        """
        try:
            text = f"{search_result.get('title', '')} {search_result.get('snippet', '')}".lower()
            
            # Look for CVE patterns
            cve_pattern = r'cve-\d{4}-\d{4,7}'
            cves = re.findall(cve_pattern, text, re.IGNORECASE)
            
            # Look for vulnerability keywords
            vuln_keywords = ['vulnerability', 'exploit', 'security', 'flaw', 'bug', 'weakness', 'cve', 'advisory']
            has_vuln_keywords = any(keyword in text for keyword in vuln_keywords)
            
            # Look for severity keywords
            severity_keywords = {
                'critical': ['critical', 'severe', 'high'],
                'high': ['high', 'important'],
                'medium': ['medium', 'moderate'],
                'low': ['low', 'minor']
            }
            
            severity = 'unknown'
            for sev_level, keywords in severity_keywords.items():
                if any(keyword in text for keyword in keywords):
                    severity = sev_level
                    break
            
            # Only return if it looks like vulnerability information
            if cves or has_vuln_keywords:
                return {
                    'title': search_result.get('title', '')[:200],
                    'description': search_result.get('snippet', '')[:500],
                    'url': search_result.get('url', ''),
                    'cve_id': cves[0].upper() if cves else None,
                    'all_cves': [cve.upper() for cve in cves],
                    'severity': severity,
                    'service': service,
                    'version': version,
                    'source': 'web_search'
                }
                
        except Exception as e:
            logger.warning("Failed to extract vulnerability info", error=str(e))
            
        return None


class VulnerabilityAnalyzer:
    """Analyzes scan results to identify potential vulnerabilities."""
    
    def __init__(self) -> None:
        """Initialize the vulnerability analyzer."""
        self.msf_wrapper = MetasploitWrapper()
        self.exploit_db_wrapper = ExploitDBWrapper()
        self.web_search_wrapper = WebSearchWrapper()
        
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
            
            # Get all open ports for comprehensive analysis
            open_ports = [port for port in scan_results.get("ports", []) if port.get("state") == "open"]
            if verbose and on_output:
                on_output(f"[Verbose] 🔍 COMPREHENSIVE ANALYSIS: Found {len(open_ports)} open ports to analyze", "info")
                for port in open_ports:
                    service_info = f"{port.get('service', 'unknown')} {port.get('version', '')}".strip()
                    on_output(f"[Verbose]   • Port {port['port']}: {service_info}", "info")
            
            if debug:
                debug_emit(f"Starting comprehensive analysis of {len(open_ports)} open ports")
                for port in open_ports:
                    debug_emit(f"Port {port['port']}: {port.get('service', 'unknown')} {port.get('version', '')}")
            
            # Analyze each open port
            for port_index, port_info in enumerate(open_ports, 1):
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                product = port_info.get("product", "")
                
                if verbose and on_output:
                    enhanced_text = " (enhanced by netcat)" if port_info.get("enhanced_by_netcat") else ""
                    on_output(f"[Verbose] 🔎 Analyzing port {port_index}/{len(open_ports)} - Port {port_info['port']}: {service} {version} {product}{enhanced_text}", "info")
                    
                    # Track netcat-enhanced services
                    if port_info.get("enhanced_by_netcat"):
                        analysis["enhanced_services"].append({
                            "port": port_info["port"],
                            "service": service,
                            "version": version,
                            "banner": port_info.get("banner", "")
                        })
                    
                # Search for vulnerabilities and exploits only for known services
                if service and service != "unknown":
                    if verbose and on_output:
                        on_output(f"[Verbose] 🔍 COMPREHENSIVE RESEARCH: Port {port_info['port']} - Researching {service} {version}", "info")
                    if debug:
                        debug_emit(f"Starting comprehensive research for port {port_info['port']}: {service} {version}")
                    
                    # Step 1: Web research for vulnerabilities (ENHANCED!)
                    if verbose and on_output:
                        on_output(f"[Verbose] 🌐 WEB RESEARCH: Searching internet for {service} {version} vulnerabilities", "info")
                    try:
                        # Construct intelligent search queries based on exact service info
                        search_queries = self._build_intelligent_search_queries(port_info, debug, debug_emit)
                        
                        all_web_vulns = []
                        for query in search_queries:
                            if debug:
                                debug_emit(f"🔍 Executing web search: '{query}'")
                            
                            web_vulns = self.web_search_wrapper.search_vulnerabilities(
                                query, 
                                version, 
                                verbose=verbose, 
                                debug=debug, 
                                on_output=on_output
                            )
                            all_web_vulns.extend(web_vulns)
                        
                        # Process and prioritize web vulnerability findings
                        processed_vulns = self._process_web_vulnerability_results(
                            all_web_vulns, port_info, debug, debug_emit
                        )
                        
                        for vuln in processed_vulns:
                            analysis["vulnerabilities"].append({
                                "type": "web_research_enhanced",
                                "port": port_info["port"],
                                "service": service,
                                "version": version,
                                "vulnerability": vuln,
                                "severity": vuln.get("severity", "unknown"),
                                "cve_id": vuln.get("cve_id"),
                                "description": vuln.get("description", ""),
                                "source": "web_search_enhanced",
                                "exploit_available": vuln.get("exploit_available", False),
                                "metasploit_module": vuln.get("metasploit_module"),
                                "confidence": vuln.get("confidence", "low")
                            })
                            
                    except Exception as e:
                        if debug:
                            debug_emit(f"Enhanced web vulnerability search failed: {e}")
                    
                    # Step 2: Search Metasploit with intelligent mapping
                    if verbose and on_output:
                        on_output(f"[Verbose] 🎯 METASPLOIT SEARCH: Looking for {service} {version} exploits", "info")
                    try:
                        # Enhanced Metasploit search with multiple search terms
                        msf_search_terms = self._build_metasploit_search_terms(port_info, debug, debug_emit)
                        
                        all_msf_exploits = []
                        for search_term in msf_search_terms:
                            if debug:
                                debug_emit(f"🎯 Metasploit search term: '{search_term}'")
                            
                            msf_exploits = self.msf_wrapper.search_exploits(
                                search_term, version, verbose=verbose, debug=debug, on_output=on_output
                            )
                            all_msf_exploits.extend(msf_exploits)
                        
                        # Remove duplicates and prioritize
                        unique_exploits = self._deduplicate_and_prioritize_exploits(all_msf_exploits, port_info)
                        
                        for exploit in unique_exploits:
                            analysis["exploits_found"].append({
                                "source": "metasploit_enhanced",
                                "port": port_info["port"],
                                "service": service,
                                "exploit": exploit,
                                "priority": exploit.get("priority", "medium"),
                                "confidence": exploit.get("confidence", "medium")
                            })
                            
                    except Exception as e:
                        if debug:
                            debug_emit(f"Enhanced Metasploit search failed: {e}")
                    
                    # Step 3: Search Exploit-DB (with timeout protection)
                    if verbose and on_output:
                        on_output(f"[Verbose] 💾 EXPLOITDB SEARCH: Looking for {service} {version} exploits", "info")
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
                
                else:
                    if verbose and on_output:
                        on_output(f"[Verbose] ⚠️  Skipping port {port_info['port']} - service unknown or not identified", "warning")
                    if debug:
                        debug_emit(f"Skipping research for port {port_info['port']}: service={service}")
                    
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
        """Detect vulnerabilities for a specific port using intelligent analysis."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-DETECT] {line}", "warning" if level == "info" else level)
                
        vulnerabilities = []
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "")
        port = port_info.get("port", "")
        product = port_info.get("product", "")
        
        if debug:
            debug_emit(f"🎯 INTELLIGENT VULNERABILITY DETECTION for port {port}")
            debug_emit(f"Service: {service}, Version: {version}, Product: {product}")
        
        # CRITICAL: Check for EternalBlue (MS17-010) - Windows SMB vulnerability
        if self._check_eternalblue_vulnerability(port_info, debug, debug_emit):
            vulnerabilities.append({
                "type": "eternalblue_ms17_010",
                "port": port,
                "service": service,
                "description": "🚨 CRITICAL: EternalBlue (MS17-010) - Windows SMB Remote Code Execution",
                "severity": "critical",
                "cve_id": "CVE-2017-0144",
                "version": version,
                "exploit_available": True,
                "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
                "confidence": "high"
            })
            if debug:
                debug_emit("🚨 ETERNALBLUE VULNERABILITY DETECTED!")
        
        # CRITICAL: Check for other well-known Windows vulnerabilities
        windows_vulns = self._check_windows_vulnerabilities(port_info, debug, debug_emit)
        vulnerabilities.extend(windows_vulns)
        
        # Enhanced service-specific vulnerability detection
        service_vulns = self._check_service_specific_vulnerabilities(port_info, debug, debug_emit)
        vulnerabilities.extend(service_vulns)
        
        # Check for default/weak authentication
        auth_vulns = self._check_authentication_vulnerabilities(port_info, debug, debug_emit)
        vulnerabilities.extend(auth_vulns)
        
        # Check banner for vulnerability indicators
        banner_vulns = self._check_banner_vulnerabilities(port_info, debug, debug_emit)
        vulnerabilities.extend(banner_vulns)
        
        if debug and vulnerabilities:
            debug_emit(f"🎯 Found {len(vulnerabilities)} vulnerabilities for port {port}")
            for vuln in vulnerabilities:
                debug_emit(f"  • {vuln['description']} (Severity: {vuln['severity']})")
        
        return vulnerabilities
    
    def _check_eternalblue_vulnerability(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> bool:
        """Check for EternalBlue (MS17-010) vulnerability."""
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        product = port_info.get("product", "")
        
        # Check for SMB ports
        if port not in ["445", "139"]:
            return False
            
        # Check for SMB-related services
        if service not in ["microsoft-ds", "netbios-ssn", "smb"]:
            return False
        
        if debug:
            debug_emit(f"🔍 Checking EternalBlue for SMB service on port {port}")
        
        # Check for Windows indicators in product string
        windows_indicators = [
            "windows 7", "windows server 2008", "windows vista", 
            "windows xp", "windows server 2003", "windows 2000",
            "microsoft windows", "windows"
        ]
        
        product_lower = product.lower() if product else ""
        is_windows = any(indicator in product_lower for indicator in windows_indicators)
        
        if debug:
            debug_emit(f"🔍 Product string: '{product}' - Windows detected: {is_windows}")
        
        # EternalBlue affects unpatched Windows systems
        # If we detect Windows SMB, it's likely vulnerable unless proven otherwise
        if is_windows:
            if debug:
                debug_emit("🚨 Windows SMB detected - likely EternalBlue vulnerable!")
            return True
        
        # Even if Windows not explicitly detected, SMB on 445/139 is suspicious
        if service in ["microsoft-ds", "netbios-ssn"]:
            if debug:
                debug_emit("⚠️ SMB service detected - potential EternalBlue target")
            return True
            
        return False
    
    def _check_windows_vulnerabilities(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[Dict[str, Any]]:
        """Check for Windows-specific vulnerabilities."""
        vulnerabilities = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        
        product_lower = product.lower() if product else ""
        
        # MS08-067 (Conficker) - affects older Windows
        if ("windows" in product_lower and 
            any(old_win in product_lower for old_win in ["xp", "2003", "2000", "vista"])):
            vulnerabilities.append({
                "type": "ms08_067_conficker",
                "port": port,
                "service": service,
                "description": "🚨 CRITICAL: MS08-067 (Conficker) - Windows Server Service RCE",
                "severity": "critical",
                "cve_id": "CVE-2008-4250",
                "version": version,
                "exploit_available": True,
                "metasploit_module": "exploit/windows/smb/ms08_067_netapi",
                "confidence": "high"
            })
            if debug:
                debug_emit("🚨 MS08-067 (Conficker) vulnerability detected!")
        
        # RDP vulnerabilities
        if port == "3389" or service == "rdp":
            # BlueKeep (CVE-2019-0708)
            if "windows 7" in product_lower or "windows server 2008" in product_lower:
                vulnerabilities.append({
                    "type": "bluekeep_cve_2019_0708",
                    "port": port,
                    "service": service,
                    "description": "🚨 CRITICAL: BlueKeep (CVE-2019-0708) - RDP Remote Code Execution",
                    "severity": "critical",
                    "cve_id": "CVE-2019-0708",
                    "version": version,
                    "exploit_available": True,
                    "metasploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    "confidence": "high"
                })
                if debug:
                    debug_emit("🚨 BlueKeep vulnerability detected!")
            
            # General RDP exposure
            vulnerabilities.append({
                "type": "rdp_exposure",
                "port": port,
                "service": service,
                "description": "⚠️ HIGH: RDP exposed to network - brute force target",
                "severity": "high",
                "version": version,
                "exploit_available": True,
                "metasploit_module": "auxiliary/scanner/rdp/rdp_scanner",
                "confidence": "medium"
            })
        
        return vulnerabilities
    
    def _check_service_specific_vulnerabilities(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[Dict[str, Any]]:
        """Check for service-specific vulnerabilities."""
        vulnerabilities = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        
        # SSH vulnerabilities
        if service == "ssh" and version:
            version_lower = version.lower()
            if any(old_ver in version_lower for old_ver in ["openssh_7.4", "openssh_6.", "openssh_5."]):
                vulnerabilities.append({
                    "type": "ssh_old_version",
                    "port": port,
                    "service": service,
                    "description": f"⚠️ MEDIUM: Old SSH version {version} - potential vulnerabilities",
                    "severity": "medium",
                    "version": version,
                    "exploit_available": False,
                    "confidence": "medium"
                })
        
        # Web service vulnerabilities
        if service in ["http", "https"] or port in ["80", "443", "8080", "8443"]:
            vulnerabilities.append({
                "type": "web_service_exposure",
                "port": port,
                "service": service,
                "description": f"⚠️ MEDIUM: Web service exposed - potential for web attacks",
                "severity": "medium",
                "version": version,
                "exploit_available": True,
                "metasploit_module": "auxiliary/scanner/http/http_version",
                "confidence": "low"
            })
        
        # Database services
        database_ports = {
            "3306": ("mysql", "MySQL"),
            "5432": ("postgresql", "PostgreSQL"),
            "1433": ("mssql", "MS SQL Server"),
            "1521": ("oracle", "Oracle"),
            "27017": ("mongodb", "MongoDB")
        }
        
        if port in database_ports or service in [db[0] for db in database_ports.values()]:
            db_name = database_ports.get(port, (service, service.upper()))[1]
            vulnerabilities.append({
                "type": "database_exposure",
                "port": port,
                "service": service,
                "description": f"🚨 HIGH: {db_name} database exposed to network",
                "severity": "high",
                "version": version,
                "exploit_available": True,
                "metasploit_module": f"auxiliary/scanner/{service}/{service}_version",
                "confidence": "high"
            })
        
        # FTP/Telnet cleartext protocols
        if service in ["ftp", "telnet"]:
            vulnerabilities.append({
                "type": "cleartext_protocol",
                "port": port,
                "service": service,
                "description": f"🚨 HIGH: {service.upper()} transmits credentials in cleartext",
                "severity": "high",
                "version": version,
                "exploit_available": True,
                "metasploit_module": f"auxiliary/scanner/{service}/{service}_version",
                "confidence": "high"
            })
        
        return vulnerabilities
    
    def _check_authentication_vulnerabilities(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[Dict[str, Any]]:
        """Check for authentication-related vulnerabilities."""
        vulnerabilities = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        version = port_info.get("version", "")
        
        # Services commonly vulnerable to weak authentication
        auth_services = ["ssh", "ftp", "telnet", "mysql", "postgresql", "mssql", "rdp", "vnc"]
        
        if service in auth_services:
            vulnerabilities.append({
                "type": "weak_authentication_potential",
                "port": port,
                "service": service,
                "description": f"⚠️ MEDIUM: {service.upper()} may have weak/default credentials",
                "severity": "medium",
                "version": version,
                "exploit_available": True,
                "metasploit_module": f"auxiliary/scanner/{service}/{service}_login",
                "confidence": "low"
            })
        
        return vulnerabilities
    
    def _check_banner_vulnerabilities(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[Dict[str, Any]]:
        """Check banner for vulnerability indicators."""
        vulnerabilities = []
        banner = port_info.get("banner", "")
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        version = port_info.get("version", "")
        
        if not banner:
            return vulnerabilities
        
        banner_lower = banner.lower()
        
        # Check for default/admin indicators
        default_indicators = ["default", "admin", "password", "welcome", "login"]
        if any(indicator in banner_lower for indicator in default_indicators):
            vulnerabilities.append({
                "type": "default_credentials_banner",
                "port": port,
                "service": service,
                "description": f"🚨 HIGH: Banner suggests default credentials: {banner[:100]}",
                "severity": "high",
                "version": version,
                "banner": banner[:200],
                "exploit_available": True,
                "confidence": "medium"
            })
        
        # Check for version disclosure
        if version and version in banner:
            vulnerabilities.append({
                "type": "version_disclosure",
                "port": port,
                "service": service,
                "description": f"⚠️ LOW: Service version disclosed in banner",
                "severity": "low",
                "version": version,
                "banner": banner[:100],
                "exploit_available": False,
                "confidence": "high"
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
    
    def _build_intelligent_search_queries(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[str]:
        """Build intelligent search queries based on service information."""
        queries = []
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "") or ""
        product = port_info.get("product", "") or ""
        port = port_info.get("port", "")
        
        # Clean version string
        clean_version = version.replace("null", "").strip()
        
        # Base query with exact service and version
        if clean_version:
            queries.append(f"{service} {clean_version} vulnerability CVE")
            queries.append(f"{product} {clean_version} exploit")
        
        # Service-specific intelligent queries
        if service == "microsoft-ds" or port == "445":
            queries.extend([
                "Windows SMB EternalBlue MS17-010 CVE-2017-0144",
                "Windows 7 SMB vulnerability exploit",
                "microsoft-ds SMB remote code execution"
            ])
        
        if service == "netbios-ssn" or port == "139":
            queries.extend([
                "Windows NetBIOS SMB vulnerability",
                "netbios-ssn exploit MS17-010"
            ])
        
        if service == "msrpc" and "windows" in product.lower():
            queries.extend([
                "Windows RPC vulnerability",
                "Microsoft RPC exploit CVE"
            ])
        
        # Windows-specific queries based on product string
        if "windows 7" in product.lower():
            queries.extend([
                "Windows 7 vulnerability exploit",
                "Windows 7 Professional 7601 exploit"
            ])
        
        # Generic service vulnerability queries
        if service and service != "unknown":
            queries.append(f"{service} security vulnerability")
            queries.append(f"{service} remote code execution")
        
        if debug:
            debug_emit(f"🔍 Built {len(queries)} intelligent search queries")
            for i, query in enumerate(queries, 1):
                debug_emit(f"  {i}. '{query}'")
        
        return queries[:5]  # Limit to top 5 most relevant queries
    
    def _process_web_vulnerability_results(self, web_vulns: List[Dict], port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[Dict]:
        """Process and enhance web vulnerability search results."""
        processed = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        
        for vuln in web_vulns:
            enhanced_vuln = vuln.copy()
            
            # Enhance with exploit information
            title = vuln.get("title", "").lower()
            description = vuln.get("description", "").lower()
            cve_id = vuln.get("cve_id")
            
            # Map known vulnerabilities to Metasploit modules
            if "eternalblue" in title or "ms17-010" in title or "cve-2017-0144" in title:
                enhanced_vuln.update({
                    "severity": "critical",
                    "exploit_available": True,
                    "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
                    "confidence": "high",
                    "priority": "critical"
                })
            elif "bluekeep" in title or "cve-2019-0708" in title:
                enhanced_vuln.update({
                    "severity": "critical",
                    "exploit_available": True,
                    "metasploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    "confidence": "high",
                    "priority": "critical"
                })
            elif "ms08-067" in title or "conficker" in title:
                enhanced_vuln.update({
                    "severity": "critical",
                    "exploit_available": True,
                    "metasploit_module": "exploit/windows/smb/ms08_067_netapi",
                    "confidence": "high",
                    "priority": "critical"
                })
            
            # General CVE enhancement
            if cve_id and not enhanced_vuln.get("metasploit_module"):
                enhanced_vuln.update({
                    "exploit_available": True,
                    "confidence": "medium"
                })
            
            processed.append(enhanced_vuln)
        
        # Sort by priority and confidence
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        processed.sort(key=lambda x: (
            priority_order.get(x.get("severity", "unknown"), 4),
            -len(x.get("cve_id", ""))
        ))
        
        if debug and processed:
            debug_emit(f"🔍 Processed {len(processed)} web vulnerability results")
            for vuln in processed[:3]:  # Show top 3
                debug_emit(f"  • {vuln.get('title', 'Unknown')} (Severity: {vuln.get('severity', 'unknown')})")
        
        return processed
    
    def _build_metasploit_search_terms(self, port_info: Dict[str, Any], debug: bool, debug_emit: Callable) -> List[str]:
        """Build intelligent Metasploit search terms."""
        terms = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        product = port_info.get("product", "") or ""
        
        # Service-specific terms
        if service:
            terms.append(service)
        
        # Port-specific intelligent terms
        port_mappings = {
            "445": ["smb", "ms17-010", "eternalblue", "ms08-067"],
            "139": ["smb", "netbios", "ms17-010"],
            "3389": ["rdp", "bluekeep", "cve-2019-0708"],
            "22": ["ssh"],
            "80": ["http", "web"],
            "443": ["https", "ssl"],
            "21": ["ftp"],
            "23": ["telnet"],
            "3306": ["mysql"],
            "5432": ["postgresql"],
            "1433": ["mssql"]
        }
        
        if port in port_mappings:
            terms.extend(port_mappings[port])
        
        # Product-specific terms
        if "windows" in product.lower():
            terms.extend(["windows", "microsoft"])
            if "windows 7" in product.lower():
                terms.extend(["windows_7", "win7"])
        
        # Remove duplicates while preserving order
        unique_terms = []
        for term in terms:
            if term not in unique_terms:
                unique_terms.append(term)
        
        if debug:
            debug_emit(f"🎯 Built Metasploit search terms: {unique_terms}")
        
        return unique_terms
    
    def _deduplicate_and_prioritize_exploits(self, exploits: List[Dict], port_info: Dict[str, Any]) -> List[Dict]:
        """Remove duplicate exploits and prioritize them."""
        seen = set()
        unique_exploits = []
        service = port_info.get("service", "").lower()
        port = port_info.get("port", "")
        
        # Priority mappings for critical exploits
        critical_exploits = {
            "ms17_010": {"priority": "critical", "confidence": "high"},
            "eternalblue": {"priority": "critical", "confidence": "high"},
            "ms08_067": {"priority": "critical", "confidence": "high"},
            "bluekeep": {"priority": "critical", "confidence": "high"},
            "cve_2019_0708": {"priority": "critical", "confidence": "high"}
        }
        
        for exploit in exploits:
            # Create identifier for deduplication
            name = exploit.get("name", "").lower()
            path = exploit.get("path", "").lower()
            identifier = f"{name}:{path}"
            
            if identifier not in seen:
                seen.add(identifier)
                
                # Enhance with priority and confidence
                enhanced_exploit = exploit.copy()
                
                # Check for critical exploits
                for critical_key, priority_info in critical_exploits.items():
                    if critical_key in name or critical_key in path:
                        enhanced_exploit.update(priority_info)
                        break
                else:
                    # Default priority based on service
                    if service in ["microsoft-ds", "netbios-ssn", "rdp"]:
                        enhanced_exploit.update({"priority": "high", "confidence": "medium"})
                    else:
                        enhanced_exploit.update({"priority": "medium", "confidence": "low"})
                
                unique_exploits.append(enhanced_exploit)
        
        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_exploits.sort(key=lambda x: priority_order.get(x.get("priority", "medium"), 2))
        
        return unique_exploits


class ToolManager:
    """Manages all security tools and their execution."""

    def __init__(self):
        self.nmap_scanner = NmapScanner()
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.active_sessions = {}
        self.runner_manager = None # To be set if exploit execution is needed

    def get_tool_definitions(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_nmap_scan",
                    "description": "Scan a target using nmap to enumerate services and versions.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "IP address or hostname to scan"},
                            "ports": {"type": "string", "description": "Port range (e.g., 'common', '1-65535')"}
                        },
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_vulnerabilities",
                    "description": "Analyze nmap scan results to find vulnerabilities and exploits.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scan_result": {"type": "object", "description": "The JSON output from a previous nmap scan."}
                        },
                        "required": ["scan_result"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_exploit",
                    "description": "Execute a specific exploit found during analysis.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "exploit_details": {"type": "object", "description": "Details of the exploit to run."}
                        },
                        "required": ["exploit_details"]
                    }
                }
            }
        ]

    def execute_tool(self, tool_name: str, args: dict, on_output: Callable):
        if tool_name == "run_nmap_scan":
            return self.nmap_scanner.scan_target(
                target=args.get("target"),
                ports=args.get("ports", "common"),
                on_output=on_output,
                verbose=True, # For now, let's keep it verbose
                debug=True
            )
        elif tool_name == "analyze_vulnerabilities":
            return self.vuln_analyzer.analyze_scan_results(
                scan_results=args.get("scan_result"),
                on_output=on_output,
                verbose=True,
                debug=True
            )
        elif tool_name == "run_exploit":
            # This is a placeholder for a more complex exploit execution logic
            return {"status": "success", "message": f"Exploit {args.get('exploit_details', {})} executed."}
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    
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
    
    def search_exploits(self, service: str, version: str = "", port: str = "", keywords: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Enhanced search for exploits across multiple databases with intelligent prioritization.
        
        Args:
            service: Service name to search for
            version: Service version (optional)
            port: Port number where service is running (optional)
            keywords: Additional search keywords (optional)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Comprehensive search results with prioritized exploits
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-SEARCH] {line}", "warning" if level == "info" else level)
                
        def status_emit(line: str, level: str = "info"):
            if on_output:
                on_output(f"🔍 [EXPLOIT-SEARCH] {line}", level)
                
        try:
            if debug:
                debug_emit(f"Enhanced exploit search - Service: {service}, Version: {version}, Port: {port}, Keywords: {keywords}")
                
            status_emit(f"Searching for {service} exploits across multiple databases...")
            
            results = {
                "service": service,
                "version": version,
                "port": port,
                "keywords": keywords,
                "metasploit_exploits": [],
                "exploitdb_exploits": [],
                "routersploit_exploits": [],
                "high_priority_exploits": [],
                "total_exploits": 0,
                "search_strategy": []
            }
            
            # Build comprehensive search terms
            search_terms = [service.lower()]
            if version:
                search_terms.append(version)
            if keywords:
                search_terms.extend(keywords.lower().split())
            
            # Add port-specific search terms for intelligent detection
            port_mappings = {
                "445": ["smb", "cifs", "eternalblue", "ms17-010", "ms08-067", "netapi"],
                "139": ["smb", "netbios", "ms17-010"],
                "3389": ["rdp", "bluekeep", "cve-2019-0708", "terminal", "services"],
                "22": ["ssh", "openssh"],
                "80": ["http", "web", "apache", "nginx"],
                "443": ["https", "ssl", "tls"],
                "21": ["ftp"],
                "23": ["telnet"],
                "3306": ["mysql"],
                "5432": ["postgresql"],
                "1433": ["mssql", "sql server"]
            }
            
            if port and port in port_mappings:
                search_terms.extend(port_mappings[port])
                results["search_strategy"].append(f"Added port-specific terms for {port}: {port_mappings[port]}")
                status_emit(f"Enhanced search with port {port} specific terms: {', '.join(port_mappings[port])}")
            
            if debug:
                debug_emit(f"Comprehensive search terms: {search_terms}")
            
            # Search Metasploit with enhanced terms
            status_emit("Searching Metasploit database...")
            try:
                if debug:
                    debug_emit("Searching Metasploit with enhanced query terms...")
                msf_exploits = []
                for term in search_terms:
                    try:
                        term_results = self.vuln_analyzer.msf_wrapper.search_exploits(term, version, verbose=verbose, debug=debug, on_output=on_output)
                        msf_exploits.extend(term_results)
                    except Exception as e:
                        if debug:
                            debug_emit(f"Metasploit search failed for term '{term}': {e}")
                
                # Remove duplicates
                seen = set()
                unique_msf = []
                for exploit in msf_exploits:
                    identifier = exploit.get('name', '') + exploit.get('path', '')
                    if identifier not in seen:
                        seen.add(identifier)
                        unique_msf.append(exploit)
                        
                results["metasploit_exploits"] = unique_msf
                if unique_msf:
                    status_emit(f"Found {len(unique_msf)} Metasploit exploits")
                    
            except Exception as e:
                if debug:
                    debug_emit(f"Metasploit search failed: {e}")
            
            # Search Exploit-DB
            status_emit("Searching Exploit-DB...")
            try:
                edb_exploits = []
                for term in search_terms:
                    try:
                        term_results = self.vuln_analyzer.exploit_db_wrapper.search_exploits(term, version, verbose=verbose, debug=debug, on_output=on_output)
                        edb_exploits.extend(term_results)
                    except Exception as e:
                        if debug:
                            debug_emit(f"Exploit-DB search failed for term '{term}': {e}")
                
                results["exploitdb_exploits"] = edb_exploits
                if edb_exploits:
                    status_emit(f"Found {len(edb_exploits)} Exploit-DB entries")
                    
            except Exception as e:
                if debug:
                    debug_emit(f"Exploit-DB search failed: {e}")
            
            # Prioritize exploits based on reliability and impact
            all_exploits = results["metasploit_exploits"] + results["exploitdb_exploits"]
            results["high_priority_exploits"] = self._prioritize_exploits(all_exploits, service, port, search_terms)
            results["total_exploits"] = len(all_exploits)
            
            if results["high_priority_exploits"]:
                status_emit(f"⭐ {len(results['high_priority_exploits'])} HIGH PRIORITY exploits identified!", "success")
                for i, exploit in enumerate(results["high_priority_exploits"][:3]):
                    status_emit(f"  {i+1}. {exploit.get('name', 'Unknown')} - {exploit.get('priority_reason', 'High impact')}")
            
            status_emit(f"Search completed: {results['total_exploits']} exploits found")
                
            if debug:
                debug_emit(f"Enhanced search completed: {results['total_exploits']} total exploits, {len(results['high_priority_exploits'])} high priority")
                    
            return results
            
        except Exception as e:
            error_msg = f"Enhanced exploit search failed: {str(e)}"
            if debug:
                debug_emit(f"ERROR: {error_msg}")
            return {"error": error_msg}
    
    def search_metasploit(self, query: str, module_type: str = "all", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Dedicated Metasploit database search with comprehensive module discovery.
        
        Args:
            query: Search query (service, CVE, vulnerability name, etc.)
            module_type: Type of modules to search for ("exploit", "auxiliary", "post", "all")
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Metasploit search results with module details
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-MSF] {line}", "warning" if level == "info" else level)
                
        def status_emit(line: str, level: str = "info"):
            if on_output:
                on_output(f"🎯 [METASPLOIT] {line}", level)
        
        try:
            if debug:
                debug_emit(f"Metasploit search - Query: {query}, Type: {module_type}")
                
            status_emit(f"Searching Metasploit database for: {query}")
            
            results = {
                "query": query,
                "module_type": module_type,
                "modules_found": [],
                "total_found": 0,
                "search_methods": []
            }
            
            # Multiple search strategies for comprehensive coverage
            search_strategies = [
                query.lower(),
                query.replace(" ", "_"),
                query.replace("-", "_"),
                query.replace(".", "_")
            ]
            
            # Add specific search terms based on query
            if "smb" in query.lower():
                search_strategies.extend(["ms17_010", "eternalblue", "ms08_067", "smb_", "cifs"])
                results["search_methods"].append("SMB-specific searches added")
                status_emit("Added SMB-specific search terms: EternalBlue, MS17-010, MS08-067")
            elif "rdp" in query.lower():
                search_strategies.extend(["bluekeep", "cve_2019_0708", "rdp_"])
                results["search_methods"].append("RDP-specific searches added")
                status_emit("Added RDP-specific search terms: BlueKeep, CVE-2019-0708")
            elif "ssh" in query.lower():
                search_strategies.extend(["openssh", "ssh_"])
                results["search_methods"].append("SSH-specific searches added")
            
            if debug:
                debug_emit(f"Search strategies: {search_strategies}")
            
            # Search using multiple terms
            all_modules = []
            for strategy in search_strategies:
                try:
                    modules = self.vuln_analyzer.msf_wrapper.search_exploits(strategy, "", verbose=verbose, debug=debug, on_output=on_output)
                    all_modules.extend(modules)
                    if debug and modules:
                        debug_emit(f"Strategy '{strategy}' found {len(modules)} modules")
                except Exception as e:
                    if debug:
                        debug_emit(f"Search strategy '{strategy}' failed: {e}")
            
            # Remove duplicates
            seen = set()
            unique_modules = []
            for module in all_modules:
                identifier = module.get('name', '') + module.get('path', '')
                if identifier not in seen:
                    seen.add(identifier)
                    unique_modules.append(module)
            
            results["modules_found"] = unique_modules
            results["total_found"] = len(unique_modules)
            
            if results["total_found"] > 0:
                status_emit(f"Found {results['total_found']} Metasploit modules!", "success")
                # Show top results
                for i, module in enumerate(unique_modules[:5]):
                    status_emit(f"  {i+1}. {module.get('name', 'Unknown')} - {module.get('description', 'No description')[:60]}...")
            else:
                status_emit("No Metasploit modules found for this query", "warning")
                
            if debug:
                debug_emit(f"Metasploit search completed: {results['total_found']} modules found")
                
            return results
            
        except Exception as e:
            error_msg = f"Metasploit search failed: {str(e)}"
            if debug:
                debug_emit(f"ERROR: {error_msg}")
            return {"error": error_msg}
    
    def search_web_vulnerabilities(self, service: str, version: str = "", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Search the web for vulnerability information about a service and version.
        
        Args:
            service: Service name to search for
            version: Service version (optional)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Web search results with vulnerability information
        """
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-WEB-SEARCH] {line}", "warning" if level == "info" else level)
                
        def status_emit(line: str, level: str = "info"):
            if on_output:
                on_output(f"🌐 [WEB-SEARCH] {line}", level)
        
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Starting web vulnerability search for {service} {version}", "info")
            
            status_emit(f"Searching internet for {service} {version} vulnerabilities...")
            
            if debug:
                debug_emit(f"Web search initiated for service: {service}, version: {version}")
            
            # Use the WebSearchWrapper to find vulnerability information
            vulnerabilities = self.web_search_wrapper.search_vulnerabilities(
                service, version, verbose=verbose, debug=debug, on_output=on_output
            )
            
            results = {
                "service": service,
                "version": version,
                "vulnerabilities_found": vulnerabilities,
                "total_found": len(vulnerabilities),
                "cves_found": [],
                "high_severity_vulns": [],
                "exploit_references": []
            }
            
            # Process and categorize the results
            for vuln in vulnerabilities:
                # Extract CVEs
                if vuln.get("cve_id"):
                    results["cves_found"].append(vuln["cve_id"])
                if vuln.get("all_cves"):
                    results["cves_found"].extend(vuln["all_cves"])
                
                # Identify high severity vulnerabilities
                if vuln.get("severity") in ["critical", "high"]:
                    results["high_severity_vulns"].append(vuln)
                
                # Look for exploit references in descriptions
                desc = vuln.get("description", "").lower()
                if any(word in desc for word in ["exploit", "metasploit", "poc", "proof of concept"]):
                    results["exploit_references"].append(vuln)
            
            # Remove duplicate CVEs
            results["cves_found"] = list(set(results["cves_found"]))
            
            # Provide summary
            if results["total_found"] > 0:
                status_emit(f"Found {results['total_found']} vulnerability entries!", "success")
                if results["cves_found"]:
                    status_emit(f"CVEs identified: {', '.join(results['cves_found'][:5])}{'...' if len(results['cves_found']) > 5 else ''}")
                if results["high_severity_vulns"]:
                    status_emit(f"⚠️  {len(results['high_severity_vulns'])} HIGH SEVERITY vulnerabilities found!", "warning")
                if results["exploit_references"]:
                    status_emit(f"💥 {len(results['exploit_references'])} entries mention available exploits", "info")
            else:
                status_emit("No vulnerability information found on the web", "warning")
            
            if debug:
                debug_emit(f"Web search completed: {results['total_found']} vulnerabilities, {len(results['cves_found'])} CVEs")
                for vuln in vulnerabilities[:3]:  # Show first 3
                    debug_emit(f"  • {vuln.get('title', 'Unknown')}: {vuln.get('severity', 'unknown')} severity")
            
            return results
            
        except Exception as e:
            error_msg = f"Web vulnerability search failed: {str(e)}"
            if debug:
                debug_emit(f"ERROR: {error_msg}")
            return {"error": error_msg}
    
    def _prioritize_exploits(self, exploits: List[Dict[str, Any]], service: str, port: str, search_terms: List[str]) -> List[Dict[str, Any]]:
        """Prioritize exploits based on reliability, impact, and relevance.
        
        Args:
            exploits: List of found exploits
            service: Target service
            port: Target port
            search_terms: Search terms used
            
        Returns:
            Prioritized list of high-value exploits
        """
        high_priority = []
        
        # Define high-priority keywords
        critical_keywords = [
            "eternalblue", "ms17-010", "ms17_010",
            "bluekeep", "cve-2019-0708", "cve_2019_0708", 
            "ms08-067", "ms08_067",
            "shellshock", "heartbleed",
            "default", "credentials", "backdoor"
        ]
        
        for exploit in exploits:
            name = exploit.get('name', '').lower()
            description = exploit.get('description', '').lower()
            
            # Check for critical vulnerabilities
            for keyword in critical_keywords:
                if keyword in name or keyword in description:
                    exploit['priority_reason'] = f"Critical vulnerability: {keyword.upper()}"
                    exploit['priority_score'] = 10
                    high_priority.append(exploit)
                    break
            
            # Port-specific high priority
            if port == "445" and ("smb" in name or "cifs" in name):
                exploit['priority_reason'] = "SMB exploit - high success rate"
                exploit['priority_score'] = 9
                high_priority.append(exploit)
            elif port == "3389" and "rdp" in name:
                exploit['priority_reason'] = "RDP exploit - direct access"
                exploit['priority_score'] = 9
                high_priority.append(exploit)
            
        # Remove duplicates and sort by priority
        seen = set()
        unique_priority = []
        for exploit in high_priority:
            identifier = exploit.get('name', '') + exploit.get('path', '')
            if identifier not in seen:
                seen.add(identifier)
                unique_priority.append(exploit)
        
        # Sort by priority score (highest first)
        unique_priority.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        
        return unique_priority[:10]  # Return top 10 high-priority exploits

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
    
    def execute_exploit(self, exploit_path: str, target_info: Dict[str, Any], custom_options: Dict[str, Any] = None, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Execute a RouterSploit exploit with intelligent option configuration.
        
        Args:
            exploit_path: RouterSploit module path (e.g., 'exploits.routers.netgear.multi_rce')
            target_info: Target information including IP, port, service details
            custom_options: Optional custom options to override auto-configured ones
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Execution results including success status and output
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Executing exploit: {exploit_path}", "info")
            
            # Find the module
            modules = self.module_loader.discover_modules()
            target_module = None
            for module in modules:
                if module.dotted_path == exploit_path:
                    target_module = module
                    break
            
            if not target_module:
                return {"error": f"Exploit module not found: {exploit_path}"}
            
            # Configure options intelligently
            options_result = self.configure_exploit_options(exploit_path, target_info, {}, verbose=verbose, debug=debug, on_output=on_output)
            if "error" in options_result:
                return options_result
            
            configured_options = options_result.get("options", {})
            
            # Apply custom options if provided
            if custom_options:
                configured_options.update(custom_options)
                if verbose and on_output:
                    on_output(f"[Verbose] Applied custom options: {custom_options}", "info")
            
            if debug and on_output:
                on_output(f"🐛 [DEBUG] Final options for {exploit_path}: {configured_options}", "warning")
            
            # Store execution output
            execution_output = []
            execution_success = None
            execution_error = None
            
            def output_callback(line: str, level: str):
                execution_output.append(f"[{level}] {line}")
                if on_output:
                    on_output(line, level)
            
            def completion_callback(success: bool, error_msg: str):
                nonlocal execution_success, execution_error
                execution_success = success
                execution_error = error_msg
            
            # Execute the module
            started = self.runner_manager.start_module(
                target_module,
                configured_options,
                output_callback,
                completion_callback
            )
            
            if not started:
                return {"error": "Failed to start module execution"}
            
            # Wait for completion (with timeout)
            import time
            timeout = 60  # 60 seconds timeout
            start_time = time.time()
            
            while execution_success is None and (time.time() - start_time) < timeout:
                time.sleep(0.5)
            
            if execution_success is None:
                return {"error": "Execution timeout"}
            
            output_text = "\n".join(execution_output)
            
            result = {
                "success": execution_success,
                "output": output_text,
                "error": execution_error,
                "exploit_path": exploit_path,
                "target": target_info.get("ip", "unknown"),
                "options_used": configured_options
            }
            
            if verbose and on_output:
                on_output(f"[Verbose] Exploit execution completed: success={execution_success}", "info")
            
            return result
            
        except Exception as e:
            error_msg = f"Exploit execution failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def configure_exploit_options(self, exploit_path: str, target_info: Dict[str, Any], scan_results: Dict[str, Any] = None, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Intelligently configure exploit options based on target information.
        
        Args:
            exploit_path: RouterSploit module path
            target_info: Target information from scan results
            scan_results: Original scan results for context
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Dictionary with configured options
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Configuring options for {exploit_path}", "info")
            
            # Find the module
            modules = self.module_loader.discover_modules()
            target_module = None
            for module in modules:
                if module.dotted_path == exploit_path:
                    target_module = module
                    break
            
            if not target_module:
                return {"error": f"Module not found: {exploit_path}"}
            
            # Get module options
            module_opts = target_module.opts
            configured_options = {}
            
            # Extract target information
            target_ip = target_info.get("ip", target_info.get("target", ""))
            target_port = target_info.get("port", 80)
            service_name = target_info.get("service", "")
            service_version = target_info.get("version", "")
            
            if debug and on_output:
                on_output(f"🐛 [DEBUG] Target info: IP={target_ip}, Port={target_port}, Service={service_name}, Version={service_version}", "warning")
                on_output(f"🐛 [DEBUG] Available options: {list(module_opts.keys())}", "warning")
            
            # Configure common options intelligently
            for opt_name, opt_spec in module_opts.items():
                opt_name_lower = opt_name.lower()
                default_value = opt_spec.get("current_value", "")
                
                if debug and on_output:
                    on_output(f"🐛 [DEBUG] Processing option: {opt_name} (default: {default_value})", "warning")
                
                # Target/Host/IP configuration
                if opt_name_lower in ["target", "host", "rhost", "rhosts", "ip", "target_ip"]:
                    configured_options[opt_name] = target_ip
                    if verbose and on_output:
                        on_output(f"[Verbose] Set {opt_name} = {target_ip}", "info")
                
                # Port configuration
                elif opt_name_lower in ["port", "rport", "target_port", "lport"]:
                    if opt_name_lower == "lport":
                        # Local port for payloads - use a random high port
                        configured_options[opt_name] = 4444
                    else:
                        configured_options[opt_name] = target_port
                    if verbose and on_output:
                        on_output(f"[Verbose] Set {opt_name} = {configured_options[opt_name]}", "info")
                
                # Service-specific configurations
                elif "http" in service_name.lower() or target_port in [80, 443, 8080, 8443]:
                    if opt_name_lower in ["uri", "path", "targeturi"]:
                        configured_options[opt_name] = "/"
                    elif opt_name_lower in ["ssl", "https"]:
                        configured_options[opt_name] = target_port in [443, 8443]
                
                # SSH-specific
                elif "ssh" in service_name.lower() or target_port == 22:
                    if opt_name_lower in ["username", "user"]:
                        configured_options[opt_name] = "root"
                    elif opt_name_lower in ["password", "pass"]:
                        configured_options[opt_name] = "admin"
                
                # FTP-specific
                elif "ftp" in service_name.lower() or target_port == 21:
                    if opt_name_lower in ["username", "user"]:
                        configured_options[opt_name] = "anonymous"
                    elif opt_name_lower in ["password", "pass"]:
                        configured_options[opt_name] = "anonymous"
                
                # SNMP-specific
                elif "snmp" in service_name.lower() or target_port == 161:
                    if opt_name_lower in ["community", "snmp_community"]:
                        configured_options[opt_name] = "public"
                
                # Keep default for others
                else:
                    if default_value is not None and default_value != "":
                        configured_options[opt_name] = default_value
            
            if debug and on_output:
                on_output(f"🐛 [DEBUG] Final configured options: {configured_options}", "warning")
            
            result = {
                "success": True,
                "options": configured_options,
                "module_path": exploit_path,
                "target_info": target_info
            }
            
            if verbose and on_output:
                on_output(f"[Verbose] Configured {len(configured_options)} options", "info")
            
            return result
            
        except Exception as e:
            error_msg = f"Option configuration failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def check_rce_success(self, execution_output: str, module_instance: Dict[str, Any] = None, verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Check if Remote Code Execution was achieved and analyze session capabilities.
        
        Args:
            execution_output: Output from exploit execution
            module_instance: Module instance information
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            RCE analysis results
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Analyzing execution output for RCE indicators", "info")
            
            # Common RCE success indicators
            rce_indicators = [
                "session opened",
                "session created",
                "shell spawned",
                "command shell session",
                "meterpreter session",
                "session established",
                "interactive session",
                "connection established",
                "shell>",
                "$ ",
                "# ",
                "C:\\>",
                "C:/>"
            ]
            
            # Failure indicators
            failure_indicators = [
                "connection refused",
                "connection failed",
                "timeout",
                "access denied",
                "authentication failed",
                "exploit failed",
                "no response",
                "unreachable"
            ]
            
            output_lower = execution_output.lower()
            
            # Check for success indicators
            rce_detected = False
            success_indicators_found = []
            
            for indicator in rce_indicators:
                if indicator in output_lower:
                    rce_detected = True
                    success_indicators_found.append(indicator)
            
            # Check for failure indicators
            failure_detected = False
            failure_indicators_found = []
            
            for indicator in failure_indicators:
                if indicator in output_lower:
                    failure_detected = True
                    failure_indicators_found.append(indicator)
            
            if debug and on_output:
                on_output(f"🐛 [DEBUG] Success indicators found: {success_indicators_found}", "warning")
                on_output(f"🐛 [DEBUG] Failure indicators found: {failure_indicators_found}", "warning")
            
            # Determine session type
            session_type = "unknown"
            if "meterpreter" in output_lower:
                session_type = "meterpreter"
            elif any(shell_indicator in output_lower for shell_indicator in ["shell>", "$ ", "# ", "C:\\>", "C:/>"]):
                session_type = "shell"
            elif "session" in output_lower:
                session_type = "generic"
            
            # Generate session ID if RCE detected
            session_id = None
            if rce_detected:
                self.session_counter += 1
                session_id = f"session_{self.session_counter}"
            
            result = {
                "rce_achieved": rce_detected and not failure_detected,
                "session_type": session_type,
                "session_id": session_id,
                "success_indicators": success_indicators_found,
                "failure_indicators": failure_indicators_found,
                "execution_output": execution_output,
                "confidence": "high" if len(success_indicators_found) > 1 else "medium" if success_indicators_found else "low"
            }
            
            if verbose and on_output:
                if rce_detected:
                    on_output(f"[Verbose] RCE SUCCESS detected! Session type: {session_type}", "success")
                else:
                    on_output(f"[Verbose] No RCE indicators found", "warning")
            
            return result
            
        except Exception as e:
            error_msg = f"RCE check failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def create_interactive_session(self, session_id: str, target: str, session_type: str = "shell", verbose: bool = False, debug: bool = False, on_output: Optional[Any] = None) -> Dict[str, Any]:
        """Create an interactive terminal session for the user after successful RCE.
        
        Args:
            session_id: Session identifier from successful exploit
            target: Target IP address
            session_type: Type of session (shell, meterpreter, etc.)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines
            
        Returns:
            Session creation results
        """
        try:
            if verbose and on_output:
                on_output(f"[Verbose] Creating interactive session {session_id} for {target}", "info")
            
            # Store session information
            session_info = {
                "session_id": session_id,
                "target": target,
                "session_type": session_type,
                "created_at": time.time(),
                "status": "active",
                "commands": []
            }
            
            self.active_sessions[session_id] = session_info
            
            if debug and on_output:
                on_output(f"🐛 [DEBUG] Session {session_id} stored with info: {session_info}", "warning")
            
            # Generate user instructions
            instructions = self._generate_session_instructions(session_type, target)
            
            result = {
                "success": True,
                "session_id": session_id,
                "target": target,
                "session_type": session_type,
                "status": "ready_for_user",
                "instructions": instructions,
                "websocket_endpoint": f"/api/session/{session_id}/interact"
            }
            
            if verbose and on_output:
                on_output(f"[Verbose] Interactive session {session_id} ready for user handoff", "success")
                on_output(f"[Verbose] {instructions}", "info")
            
            return result
            
        except Exception as e:
            error_msg = f"Session creation failed: {str(e)}"
            if verbose and on_output:
                on_output(f"[Verbose] {error_msg}", "error")
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}
    
    def _generate_session_instructions(self, session_type: str, target: str) -> str:
        """Generate user instructions for interacting with the session.
        
        Args:
            session_type: Type of session
            target: Target IP address
            
        Returns:
            User instructions
        """
        base_instructions = f"""
🎉 REMOTE CODE EXECUTION ACHIEVED! 🎉

Target: {target}
Session Type: {session_type}

The interactive terminal is now available for your use. You can execute commands directly on the compromised target.

Basic Commands to Try:
- whoami          (show current user)
- id              (show user ID and groups) 
- pwd             (show current directory)
- ls -la          (list files and directories)
- uname -a        (show system information)
- ps aux          (show running processes)
- netstat -an     (show network connections)
"""
        
        if session_type == "meterpreter":
            base_instructions += """
Meterpreter Commands:
- sysinfo         (system information)
- getuid          (current user)
- shell           (drop to system shell)
- download <file> (download file from target)
- upload <file>   (upload file to target)
- screenshot      (take screenshot)
- keyscan_start   (start keylogger)
"""
        elif session_type == "shell":
            base_instructions += """
Shell Commands:
- cat /etc/passwd (show user accounts)
- cat /etc/shadow (show password hashes - if accessible)
- find / -perm -4000 (find SUID binaries)
- crontab -l      (show scheduled tasks)
"""
        
        base_instructions += """
⚠️  Remember:
- Only use this access for authorized testing
- Document your findings
- Clean up after testing
- Be respectful of the target system

Type 'exit' to close the session when finished.
"""
        
        return base_instructions.strip()
    
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