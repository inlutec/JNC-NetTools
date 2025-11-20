import socket
import fcntl
import struct
import psutil
import subprocess
import json
from pyroute2 import IPRoute

class NetworkManager:
    def __init__(self):
        self.ipr = IPRoute()

    def list_interfaces(self):
        """
        Returns a list of dictionaries containing interface details.
        """
        interfaces = []
        
        # Get basic stats using psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        # Get more detailed info using pyroute2
        links = self.ipr.get_links()
        
        for link in links:
            if_name = link.get_attr('IFLA_IFNAME')
            if if_name == 'lo':
                continue
                
            if_index = link['index']
            mac_address = link.get_attr('IFLA_ADDRESS')
            operstate = link.get_attr('IFLA_OPERSTATE')
            
            # Get IP addresses for this interface
            ip_addrs = self.ipr.get_addr(index=if_index)
            ipv4 = []
            ipv6 = []
            
            for addr in ip_addrs:
                family = addr['family']
                ip = addr.get_attr('IFA_ADDRESS')
                prefixlen = addr['prefixlen']
                
                if family == socket.AF_INET:
                    ipv4.append(f"{ip}/{prefixlen}")
                elif family == socket.AF_INET6:
                    ipv6.append(f"{ip}/{prefixlen}")

            # Determine type (Wired/Wireless) - heuristic
            # In a real scenario, we might check /sys/class/net/<iface>/wireless or use iw
            is_wireless = False
            try:
                # Simple check if wireless extension exists
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    fcntl.ioctl(s.fileno(), 0x8B01, struct.pack('256s', if_name.encode()[:15]))
                is_wireless = True
            except OSError:
                pass

            interfaces.append({
                'name': if_name,
                'mac': mac_address,
                'status': operstate,
                'ipv4': ipv4,
                'ipv6': ipv6,
                'type': 'Wireless' if is_wireless else 'Wired',
                'is_up': operstate == 'UP',
                'config': self.get_interface_config(if_name) # Add config details
            })
            
        return interfaces

    def get_interface_config(self, iface_name):
        """
        Uses nmcli to get the current configuration of the interface.
        Returns a dict with mode (auto/manual), ip, gateway, dns.
        """
        config = {
            'method': 'unknown',
            'ip': '',
            'prefix': '',
            'gateway': '',
            'dns': ''
        }
        
        try:
            # 1. Get Connection Method (from connection profile)
            cmd_conn = ["nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", iface_name]
            res_conn = subprocess.run(cmd_conn, capture_output=True, text=True)
            conn_name = res_conn.stdout.strip().split(':')[1] if ':' in res_conn.stdout else res_conn.stdout.strip()
            
            if conn_name:
                cmd_method = ["nmcli", "-t", "-f", "ipv4.method", "connection", "show", conn_name]
                res_method = subprocess.run(cmd_method, capture_output=True, text=True)
                config['method'] = res_method.stdout.strip().split(':')[1] if ':' in res_method.stdout else res_method.stdout.strip()

            # 2. Get Dynamic/Applied Config (from device show)
            # Fields: IP4.ADDRESS[1], IP4.GATEWAY, IP4.DNS[1]
            cmd_dev = ["nmcli", "-t", "-f", "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS", "device", "show", iface_name]
            result = subprocess.run(cmd_dev, capture_output=True, text=True)
            
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ':' not in line: continue
                key, value = line.split(':', 1)
                value = value.strip()
                
                if key.startswith("IP4.ADDRESS"):
                    if '/' in value:
                        config['ip'], config['prefix'] = value.split('/')
                    else:
                        config['ip'] = value
                elif key == "IP4.GATEWAY":
                    config['gateway'] = value
                elif key.startswith("IP4.DNS"):
                    # Append multiple DNS if needed, for now just take the first or comma separate
                    if config['dns']:
                        config['dns'] += ", " + value
                    else:
                        config['dns'] = value
            
        except Exception:
            pass
            
        return config

    def apply_interface_config(self, iface_name, method, ip=None, prefix=None, gateway=None, dns=None):
        """
        Uses nmcli to apply configuration.
        method: 'auto' (DHCP) or 'manual' (Static)
        """
        try:
            # Get connection name
            cmd = ["nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", iface_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            conn_name = result.stdout.strip().split(':')[1] if ':' in result.stdout else result.stdout.strip()
            
            if not conn_name:
                # Try to create a new connection if none exists? 
                # For now, assume one exists or fail.
                return False, "No NetworkManager connection found for this interface."

            cmds = ["nmcli", "connection", "modify", conn_name, "ipv4.method", method]
            
            if method == 'manual':
                if not ip or not prefix:
                    return False, "IP and Prefix required for manual mode."
                cmds.extend(["ipv4.addresses", f"{ip}/{prefix}"])
                if gateway:
                    cmds.extend(["ipv4.gateway", gateway])
                if dns:
                    cmds.extend(["ipv4.dns", dns])
            else:
                # Clear static settings when switching to auto
                cmds.extend(["ipv4.addresses", "", "ipv4.gateway", "", "ipv4.dns", ""])

            # Apply changes
            subprocess.run(cmds, check=True)
            
            # Bring up the connection to apply
            subprocess.run(["nmcli", "connection", "up", conn_name], check=True)
            
            return True, f"Configuration applied to {iface_name}"
            
        except subprocess.CalledProcessError as e:
            return False, f"Failed to apply config: {str(e)}"
        except Exception as e:
            return False, str(e)

    def set_ip_config(self, iface_name, ip_address, prefix_len, gateway=None):
        # Legacy method wrapper
        return self.apply_interface_config(iface_name, 'manual', ip_address, prefix_len, gateway)

    def set_dhcp(self, iface_name):
        # Legacy method wrapper
        return self.apply_interface_config(iface_name, 'auto')

    def create_vlan_bridge(self, trunk_iface, vlan_id, access_iface):
        """
        Creates a bridge between a VLAN on the trunk interface and an access interface.
        1. Create VLAN interface (e.g., eth0.35)
        2. Create Bridge (e.g., br35)
        3. Add VLAN interface and Access interface to Bridge
        4. Bring everything UP
        """
        vlan_iface_name = f"{trunk_iface}.{vlan_id}"
        bridge_name = f"br{vlan_id}"
        
        try:
            # 1. Create VLAN interface
            trunk_idx = self.ipr.link_lookup(ifname=trunk_iface)[0]
            self.ipr.link('add', ifname=vlan_iface_name, kind='vlan', 
                          link=trunk_idx, vlan_id=int(vlan_id))
            
            # 2. Create Bridge
            self.ipr.link('add', ifname=bridge_name, kind='bridge')
            
            # 3. Add ports to bridge
            vlan_idx = self.ipr.link_lookup(ifname=vlan_iface_name)[0]
            access_idx = self.ipr.link_lookup(ifname=access_iface)[0]
            bridge_idx = self.ipr.link_lookup(ifname=bridge_name)[0]
            
            self.ipr.link('set', index=vlan_idx, master=bridge_idx)
            self.ipr.link('set', index=access_idx, master=bridge_idx)
            
            # 4. Bring up interfaces
            self.ipr.link('set', index=vlan_idx, state='up')
            self.ipr.link('set', index=access_idx, state='up')
            self.ipr.link('set', index=bridge_idx, state='up')
            
            return True, f"Bridge {bridge_name} created successfully."
            
        except Exception as e:
            return False, str(e)

    def create_simple_bridge(self, iface1, iface2):
        """
        Creates a simple bridge between two interfaces (Passthrough).
        """
        bridge_name = "br_pass"
        try:
            # Check if bridge exists
            if self.ipr.link_lookup(ifname=bridge_name):
                return False, f"Bridge {bridge_name} already exists."

            # Create bridge
            self.ipr.link('add', ifname=bridge_name, kind='bridge')
            br_idx = self.ipr.link_lookup(ifname=bridge_name)[0]
            
            # Get indices
            idx1 = self.ipr.link_lookup(ifname=iface1)[0]
            idx2 = self.ipr.link_lookup(ifname=iface2)[0]
            
            # Helper to prepare interface
            def prepare_interface(iface_name):
                # Check if wireless
                is_wireless = False
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        fcntl.ioctl(s.fileno(), 0x8B01, struct.pack('256s', iface_name.encode()[:15]))
                    is_wireless = True
                except OSError:
                    pass
                
                if is_wireless:
                    # Try to enable 4addr mode (WDS) for bridging
                    try:
                        subprocess.run(["iw", "dev", iface_name, "set", "4addr", "on"], check=True, capture_output=True)
                    except subprocess.CalledProcessError:
                        # If 4addr fails, we proceed but warn/expect failure
                        pass
                    except FileNotFoundError:
                        # iw command not installed
                        pass

            prepare_interface(iface1)
            prepare_interface(iface2)
            
            # Add ports to bridge
            try:
                self.ipr.link('set', index=idx1, master=br_idx)
                self.ipr.link('set', index=idx2, master=br_idx)
            except Exception as e:
                if "95" in str(e) or "Operation not supported" in str(e):
                    # Cleanup
                    self.ipr.link('del', index=br_idx)
                    return False, (f"Bridging failed (Error 95). Wi-Fi interfaces in Client mode cannot be bridged "
                                   f"unless they support '4addr' (WDS) mode. Your card/driver may not support this.")
                raise e
            
            # Bring everything up
            self.ipr.link('set', index=br_idx, state='up')
            self.ipr.link('set', index=idx1, state='up')
            self.ipr.link('set', index=idx2, state='up')
            
            return True, f"Bridge {bridge_name} created between {iface1} and {iface2}"
            
        except Exception as e:
            # Cleanup if failed
            try:
                br_idx = self.ipr.link_lookup(ifname=bridge_name)
                if br_idx:
                    self.ipr.link('del', index=br_idx[0])
            except:
                pass
            return False, str(e)

    def start_dhcp_server(self, interface, ip, range_start, range_end):
        """
        Starts a dnsmasq DHCP server on the specified interface.
        """
        try:
            # 1. Configure IP on the interface
            self.apply_interface_config(interface, 'manual', ip, '24') # Assuming /24 for simplicity
            
            # 2. Kill existing dnsmasq for this interface (simple cleanup)
            subprocess.run(["pkill", "-f", f"dnsmasq.*{interface}"], check=False)
            
            # 3. Start dnsmasq
            # --interface=br_pass --dhcp-range=192.168.x.x,192.168.x.y,12h --bind-interfaces
            cmd = [
                "dnsmasq",
                "--no-daemon",
                f"--interface={interface}",
                f"--dhcp-range={range_start},{range_end},12h",
                f"--listen-address={ip}",
                "--bind-interfaces"
            ]
            
            # Run in background
            subprocess.Popen(cmd)
            
            return True, f"DHCP Server started on {interface}"
            
        except Exception as e:
            return False, str(e)

    def delete_bridge(self, bridge_name):
        try:
            # Cleanup DHCP if running
            subprocess.run(["pkill", "-f", f"dnsmasq.*{bridge_name}"], check=False)
            
            idx = self.ipr.link_lookup(ifname=bridge_name)
            if not idx:
                return False, "Bridge not found"
            
            self.ipr.link('del', index=idx[0])
            return True, "Bridge deleted"
        except Exception as e:
            return False, str(e)

    def setup_wifi_ap(self, wifi_iface, ssid, password, bridge_name):
        """
        Sets up a Wi-Fi Access Point bridged to the specified bridge.
        Uses hostapd.
        """
        import subprocess
        import os
        
        # 1. Create hostapd config
        hostapd_conf = f"""
interface={wifi_iface}
bridge={bridge_name}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        conf_path = f"/tmp/hostapd_{wifi_iface}.conf"
        with open(conf_path, "w") as f:
            f.write(hostapd_conf)
            
        # 2. Kill existing hostapd on this interface
        subprocess.run(["pkill", "-f", f"hostapd_{wifi_iface}.conf"], check=False)
        
        # 3. Start hostapd
        try:
            subprocess.Popen(["hostapd", conf_path])
            return True, "Wi-Fi AP started."
        except Exception as e:
            return False, str(e)

    def close(self):
        self.ipr.close()
