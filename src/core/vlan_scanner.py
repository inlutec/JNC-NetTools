from PyQt6.QtCore import QThread, pyqtSignal
import subprocess
import re
import time

class VLANScannerThread(QThread):
    vlan_detected = pyqtSignal(int, int) # vlan_id, count
    untagged_detected = pyqtSignal(int) # count
    scan_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, timeout=10):
        super().__init__()
        self.interface = interface
        self.timeout = timeout
        self.running = True
        self.process = None
        self.detected_vlans = {} # vlan_id -> count
        self.untagged_count = 0

    def run(self):
        try:
            # Use tcpdump to capture ALL packets to detect untagged vs tagged
            # -i: interface
            # -e: print link-level header (to see vlan)
            # -n: don't resolve names
            # -l: buffered output
            # not arp and not stp: filter out some noise if desired, but let's keep it simple
            cmd = ["tcpdump", "-i", self.interface, "-e", "-n", "-l"]
            
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            
            start_time = time.time()
            
            while self.running:
                # Check timeout
                if time.time() - start_time > self.timeout:
                    break
                    
                # Non-blocking read line
                line = self.process.stdout.readline()
                if not line and self.process.poll() is not None:
                    break
                    
                if line:
                    self.parse_line(line)
                    
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            if self.process:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except:
                    self.process.kill()
            self.scan_finished.emit()

    def parse_line(self, line):
        # Example Tagged: ... ethertype 802.1Q (0x8100), length 100: vlan 35, p 0, ethertype IPv4 ...
        # Example Untagged: ... ethertype IPv4 (0x0800), length 100: ...
        
        # Regex to find "vlan <id>"
        match = re.search(r"vlan (\d+)", line)
        if match:
            vlan_id = int(match.group(1))
            if vlan_id not in self.detected_vlans:
                self.detected_vlans[vlan_id] = 0
            
            self.detected_vlans[vlan_id] += 1
            self.vlan_detected.emit(vlan_id, self.detected_vlans[vlan_id])
        else:
            # It's an untagged packet (or at least not 802.1Q)
            # Filter out empty lines or weird output
            if "ethertype" in line:
                self.untagged_count += 1
                self.untagged_detected.emit(self.untagged_count)

    def stop(self):
        self.running = False
        if self.process:
            self.process.kill() # Force kill to break readline()
        self.wait()

class VLANScanner:
    def __init__(self):
        pass

    def scan(self, interface, timeout=10):
        thread = VLANScannerThread(interface, timeout)
        thread.start()
        return thread
