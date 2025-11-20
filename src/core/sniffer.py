from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
from PyQt6.QtCore import QThread, pyqtSignal
import datetime

class SnifferThread(QThread):
    packet_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, filter_str=""):
        super().__init__()
        self.interface = interface
        self.filter_str = filter_str
        self.running = True

    def run(self):
        try:
            # Check if interface is up
            if not self.is_interface_up(self.interface):
                raise Exception(f"Interface {self.interface} is DOWN. Please enable it first.")

            sniff(iface=self.interface, 
                  prn=self.process_packet, 
                  filter=self.filter_str, 
                  store=0, 
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def is_interface_up(self, interface):
        try:
            import psutil
            stats = psutil.net_if_stats()
            if interface in stats:
                return stats[interface].isup
            return False
        except:
            return True # Assume up if check fails to avoid blocking

    def process_packet(self, packet):
        if not self.running:
            return

        try:
            pkt_info = {
                'time': datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src': 'Unknown',
                'dst': 'Unknown',
                'proto': 'Unknown',
                'info': packet.summary()
            }

            if IP in packet:
                pkt_info['src'] = packet[IP].src
                pkt_info['dst'] = packet[IP].dst
                pkt_info['proto'] = packet[IP].proto
                
                # Printer Ports
                printer_ports = [631, 515, 9100]
                
                if TCP in packet:
                    pkt_info['proto'] = 'TCP'
                    flags = packet[TCP].flags
                    flag_str = str(flags)
                    
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    
                    info = f"{sport} -> {dport} [{flag_str}]"
                    
                    # Check for Printer Traffic
                    if sport in printer_ports or dport in printer_ports:
                        info = f"[PRINTER] {info}"
                        
                    # Check for potential issues (simple heuristics)
                    if 'R' in flag_str: # RST
                        info += " [RESET]"
                        pkt_info['status'] = 'Error'
                    elif 'S' in flag_str and 'A' not in flag_str: # SYN only
                        info += " [SYN]"
                        pkt_info['status'] = 'Connecting'
                    else:
                        pkt_info['status'] = 'OK'
                        
                    pkt_info['info'] = info
                    
                elif UDP in packet:
                    pkt_info['proto'] = 'UDP'
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"{sport} -> {dport}"
                    
                    if sport in printer_ports or dport in printer_ports:
                        info = f"[PRINTER] {info}"
                        
                    pkt_info['info'] = info
                    pkt_info['status'] = 'OK'
                    
                elif ICMP in packet:
                    pkt_info['proto'] = 'ICMP'
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    
                    if icmp_type == 3: # Destination Unreachable
                        pkt_info['info'] = f"Dest Unreachable (Code: {icmp_code})"
                        pkt_info['status'] = 'Error'
                    else:
                        pkt_info['info'] = f"Type: {icmp_type} Code: {icmp_code}"
                        pkt_info['status'] = 'OK'
                        
            elif ARP in packet:
                pkt_info['proto'] = 'ARP'
                pkt_info['src'] = packet[ARP].psrc
                pkt_info['dst'] = packet[ARP].pdst
                pkt_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
                pkt_info['status'] = 'OK'

            self.packet_received.emit(pkt_info)
            
        except Exception:
            pass

    def stop(self):
        self.running = False

class NetworkSniffer:
    def __init__(self):
        self.thread = None

    def start_sniffing(self, interface, filter_str=""):
        self.thread = SnifferThread(interface, filter_str)
        self.thread.start()
        return self.thread

    def stop_sniffing(self):
        if self.thread:
            self.thread.stop()
            self.thread.wait()
            self.thread = None
