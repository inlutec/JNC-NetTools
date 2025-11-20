import nmap
import subprocess
import shlex
import tempfile
import os
from PyQt6.QtCore import QThread, pyqtSignal

import re

class ScannerThread(QThread):
    scan_finished = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    scan_progress = pyqtSignal(str)
    port_found = pyqtSignal(int, str, str, str) # port, proto, state, service

    def __init__(self, target, arguments):
        super().__init__()
        self.target = target
        self.arguments = arguments
        self.process = None
        self.temp_xml = None

    def run(self):
        try:
            # Create temp file for XML output
            fd, self.temp_xml = tempfile.mkstemp(suffix='.xml')
            os.close(fd)
            
            # Construct command: nmap -oX <temp_file> -v <arguments> <target>
            # -v is important to get progress output on stdout
            cmd = ["nmap", "-oX", self.temp_xml, "-v"] + shlex.split(self.arguments) + [self.target]
            
            self.scan_progress.emit(f"Executing: {' '.join(cmd)}\n")
            
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            
            # Regex for discovered ports: "Discovered open port 80/tcp on 192.168.1.1"
            port_regex = re.compile(r"Discovered open port (\d+)/(\w+) on")
            
            # Read stdout line by line for progress
            while True:
                line = self.process.stdout.readline()
                if not line and self.process.poll() is not None:
                    break
                if line:
                    self.scan_progress.emit(line.strip())
                    # Check for discovered port
                    match = port_regex.search(line)
                    if match:
                        port = int(match.group(1))
                        proto = match.group(2).upper()
                        self.port_found.emit(port, proto, "open", "")
            
            stdout, stderr = self.process.communicate()
            
            if self.process.returncode == 0:
                # Parse XML output from file
                nm = nmap.PortScanner()
                try:
                    with open(self.temp_xml, 'r') as f:
                        xml_content = f.read()
                        
                    if not xml_content:
                        self.scan_error.emit("Scan produced no output.")
                        return

                    result = nm.analyse_nmap_xml_scan(xml_content)
                    if result is None:
                        result = nm.scan_result
                    self.scan_finished.emit(result)
                except Exception as e:
                    self.scan_error.emit(f"Error parsing scan results: {str(e)}")
            else:
                # If killed or failed
                if self.process.returncode == -9: # SIGKILL
                     self.scan_progress.emit("\nScan stopped by user.")
                     self.scan_error.emit("Scan stopped by user.")
                else:
                     self.scan_error.emit(f"Scan failed: {stderr}")
                
        except Exception as e:
            self.scan_error.emit(str(e))
        finally:
            # Cleanup temp file
            if self.temp_xml and os.path.exists(self.temp_xml):
                try:
                    os.remove(self.temp_xml)
                except:
                    pass

    def stop(self):
        if self.process:
            self.process.kill()
        self.wait()

class NetworkScanner:
    def __init__(self):
        pass

    def scan(self, target, ports=None, scan_type="TCP", skip_discovery=False):
        """
        Initiates a scan. Returns the thread object.
        target: IP or range (e.g., '192.168.1.1' or '192.168.1.0/24')
        ports: String of ports (e.g., '80,443' or '1-1000')
        scan_type: 'TCP' or 'UDP'
        skip_discovery: If True, adds -Pn (treat all as online). If False, performs host discovery (ARP/Ping).
        """
        # -T4: Aggressive timing
        # --stats-every 5s: Print progress line every 5 seconds
        # --min-rate 1000: Send packets at least 1000 per second (Speed up)
        arguments = "-T4 --stats-every 5s --min-rate 1000"
        
        if skip_discovery:
            arguments += " -Pn"
            
        if scan_type == "UDP":
            arguments += " -sU"
        else:
            arguments += " -sT" # Connect scan (safer for non-root)
            
        if ports:
            arguments += f" -p {ports}"
        else:
            arguments += " -F" # Fast scan if no ports specified
            
        thread = ScannerThread(target, arguments)
        thread.start()
        return thread
