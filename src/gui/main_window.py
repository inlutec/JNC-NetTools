from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, 
                             QLabel, QHBoxLayout, QStatusBar)
from PyQt6.QtCore import Qt
from src.core.network_manager import NetworkManager
from src.gui.widgets.interface_list import InterfaceListWidget
from src.gui.widgets.ip_config import IPConfigWidget
from src.gui.widgets.vlan_bridge import VLANBridgeWidget
from src.gui.widgets.scanner_view import ScannerWidget
from src.gui.widgets.sniffer_view import SnifferWidget
from src.gui.widgets.diagnostics_view import DiagnosticsWidget
from src.gui.widgets.port_scanner import PortScannerWidget
from src.utils.report_generator import ReportGenerator
from PyQt6.QtWidgets import QFileDialog

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("JNC-NetTools // ADA version")
        self.setMinimumSize(1000, 700) # Allow resizing, set minimum size
        
        self.nm = NetworkManager()
        
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Sidebar (Interface List)
        self.interface_list = InterfaceListWidget(self.nm)
        self.interface_list.setFixedWidth(300)
        self.interface_list.interface_selected.connect(self.on_interface_selected)
        main_layout.addWidget(self.interface_list)
        
        # Main Content Area (Tabs)
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # IP Configuration Tab
        self.ip_config_widget = IPConfigWidget(self.nm)
        self.tabs.addTab(self.ip_config_widget, "IP Configuration")
        
        # VLAN & Bridge Tab
        self.vlan_bridge_widget = VLANBridgeWidget(self.nm)
        self.tabs.addTab(self.vlan_bridge_widget, "VLAN / Bridge")
        
        # Scanner Tab (Network Discovery)
        self.scanner_widget = ScannerWidget()
        self.tabs.addTab(self.scanner_widget, "Net Scanner")
        
        # Port Scanner Tab (Dedicated)
        self.port_scanner_widget = PortScannerWidget()
        self.tabs.addTab(self.port_scanner_widget, "Port Scanner")
        
        # Sniffer Tab
        self.sniffer_widget = SnifferWidget(self.nm)
        self.tabs.addTab(self.sniffer_widget, "Sniffer")

        # Diagnostics Tab
        self.diagnostics_widget = DiagnosticsWidget()
        self.tabs.addTab(self.diagnostics_widget, "Diagnostics")
        
        # Report Button (Top Right or Bottom)
        # Let's add a toolbar for global actions
        toolbar = self.addToolBar("Main")
        toolbar.addAction("Generate Report", self.generate_report)
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def on_interface_selected(self, iface_data):
        self.status_bar.showMessage(f"Selected Interface: {iface_data['name']}")
        self.ip_config_widget.set_interface(iface_data)

    def closeEvent(self, event):
        self.nm.close()
        self.scanner_widget.close()
        self.port_scanner_widget.close()
        self.vlan_bridge_widget.close()
        event.accept()

    def generate_report(self):
        # Gather data
        interfaces = self.nm.list_interfaces()
        
        # Get scan results from scanner widget
        scan_results = []
        for row in range(self.scanner_widget.table.rowCount()):
            scan_results.append({
                'ip': self.scanner_widget.table.item(row, 0).text(),
                'mac': self.scanner_widget.table.item(row, 1).text(),
                'vendor': self.scanner_widget.table.item(row, 2).text(),
                'status': self.scanner_widget.table.item(row, 3).text()
            })
            
        # Get sniffer results (All Traffic)
        sniff_all = []
        for row in range(self.sniffer_widget.table_all.rowCount()):
            sniff_all.append({
                'time': self.sniffer_widget.table_all.item(row, 0).text(),
                'src': self.sniffer_widget.table_all.item(row, 1).text(),
                'dst': self.sniffer_widget.table_all.item(row, 2).text(),
                'proto': self.sniffer_widget.table_all.item(row, 3).text(),
                'info': self.sniffer_widget.table_all.item(row, 4).text(),
                'status': self.sniffer_widget.table_all.item(row, 5).text()
            })

        # Get sniffer results (Failed/Anomalies)
        sniff_failed = []
        for row in range(self.sniffer_widget.table_failed.rowCount()):
            sniff_failed.append({
                'time': self.sniffer_widget.table_failed.item(row, 0).text(),
                'src': self.sniffer_widget.table_failed.item(row, 1).text(),
                'dst': self.sniffer_widget.table_failed.item(row, 2).text(),
                'proto': self.sniffer_widget.table_failed.item(row, 3).text(),
                'info': self.sniffer_widget.table_failed.item(row, 4).text(),
                'status': self.sniffer_widget.table_failed.item(row, 5).text()
            })
            
        generator = ReportGenerator()
        filename, _ = QFileDialog.getSaveFileName(self, "Save Report", "report.html", "HTML Files (*.html)")
        
        if filename:
            success, msg = generator.generate_html_report(interfaces, scan_results, sniff_all, sniff_failed, filename)
            if success:
                self.status_bar.showMessage(f"Report saved to {msg}")
            else:
                self.status_bar.showMessage(f"Error saving report: {msg}")
