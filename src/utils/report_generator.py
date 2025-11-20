import datetime
import os

class ReportGenerator:
    def __init__(self):
        pass

    def generate_html_report(self, interfaces, scan_results, sniff_all, sniff_failed, filename="report.html"):
        """
        Generates an HTML report with the provided data.
        """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>JNC-NetTools Report</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; }}
                h1 {{ color: #0078d7; border-bottom: 3px solid #0078d7; padding-bottom: 10px; margin-bottom: 30px; }}
                h2 {{ color: #444; margin-top: 40px; border-left: 5px solid #0078d7; padding-left: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }}
                th, td {{ border: 1px solid #e0e0e0; padding: 10px; text-align: left; }}
                th {{ background-color: #f8f9fa; color: #333; font-weight: 600; }}
                tr:nth-child(even) {{ background-color: #fcfcfc; }}
                .timestamp {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
                .status-up {{ color: green; font-weight: bold; }}
                .status-down {{ color: red; font-weight: bold; }}
                .error-row {{ background-color: #fff0f0 !important; }}
                .error-text {{ color: #d32f2f; font-weight: bold; }}
                .badge {{ padding: 3px 8px; border-radius: 12px; font-size: 0.85em; color: white; }}
                .badge-tcp {{ background-color: #0078d7; }}
                .badge-udp {{ background-color: #e65100; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>JNC-NetTools Diagnostic Report</h1>
                <p class="timestamp">Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                
                <h2>Network Interfaces</h2>
                <table>
                    <tr><th>Name</th><th>Type</th><th>Status</th><th>IP Address</th><th>MAC Address</th></tr>
        """
        
        for iface in interfaces:
            ip = iface['ipv4'][0] if iface['ipv4'] else "N/A"
            status_class = "status-up" if iface['is_up'] else "status-down"
            html += f"<tr><td><b>{iface['name']}</b></td><td>{iface['type']}</td><td class='{status_class}'>{iface['status']}</td><td>{ip}</td><td>{iface['mac']}</td></tr>"
            
        html += """
                </table>
                
                <h2>Port Scan Results</h2>
                <table>
                    <tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Status</th></tr>
        """
        
        if not scan_results:
             html += "<tr><td colspan='4' style='text-align:center; color:#888;'>No scan results available.</td></tr>"
        else:
            for item in scan_results:
                html += f"<tr><td>{item['ip']}</td><td>{item['mac']}</td><td>{item['vendor']}</td><td>{item['status']}</td></tr>"
            
        html += """
                </table>
                
                <h2>Anomalies / Failed Traffic (Errors & Retransmissions)</h2>
                <table>
                    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th><th>Status</th></tr>
        """
        
        if not sniff_failed:
            html += "<tr><td colspan='6' style='text-align:center; color:#888;'>No anomalies detected.</td></tr>"
        else:
            for pkt in sniff_failed:
                html += f"<tr class='error-row'><td>{pkt['time']}</td><td>{pkt['src']}</td><td>{pkt['dst']}</td><td>{pkt['proto']}</td><td>{pkt['info']}</td><td class='error-text'>{pkt['status']}</td></tr>"

        html += """
                </table>

                <h2>Traffic Log (Last 100 Packets)</h2>
                <table>
                    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th><th>Status</th></tr>
        """
        
        # Limit to last 100 for readability
        for pkt in sniff_all[-100:]:
            html += f"<tr><td>{pkt['time']}</td><td>{pkt['src']}</td><td>{pkt['dst']}</td><td>{pkt['proto']}</td><td>{pkt['info']}</td><td>{pkt['status']}</td></tr>"
            
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        try:
            with open(filename, "w") as f:
                f.write(html)
            return True, os.path.abspath(filename)
        except Exception as e:
            return False, str(e)
