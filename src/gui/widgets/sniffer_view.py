from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QLineEdit, QMessageBox, QCheckBox, QSplitter, QGroupBox)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from src.core.sniffer import NetworkSniffer

class SnifferWidget(QWidget):
    def __init__(self, network_manager):
        super().__init__()
        self.nm = network_manager
        self.sniffer = NetworkSniffer()
        self.is_sniffing = False
        
        self.layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.iface_combo = QComboBox()
        self.refresh_interfaces()
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF Filter (e.g. tcp port 80)")
        
        self.ip_filter_input = QLineEdit()
        self.ip_filter_input.setPlaceholderText("Filter IP (Src/Dst)")
        self.ip_filter_input.textChanged.connect(self.apply_ip_filter)
        
        self.start_btn = QPushButton("Start Sniffing")
        self.start_btn.clicked.connect(self.toggle_sniffing)
        
        controls_layout.addWidget(QLabel("Interface:"))
        controls_layout.addWidget(self.iface_combo)
        controls_layout.addWidget(QLabel("BPF:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addWidget(QLabel("IP Filter:"))
        controls_layout.addWidget(self.ip_filter_input)
        controls_layout.addWidget(self.start_btn)
        
        self.layout.addLayout(controls_layout)
        
        # Splitter for Dual Consoles
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.layout.addWidget(self.splitter)
        
        # Top Console: All Traffic
        self.all_traffic_group = QGroupBox("All Traffic")
        self.all_traffic_layout = QVBoxLayout(self.all_traffic_group)
        self.table_all = self.create_table()
        self.all_traffic_layout.addWidget(self.table_all)
        self.splitter.addWidget(self.all_traffic_group)
        
        # Bottom Console: Failed / Slow / Anomalies
        self.failed_traffic_group = QGroupBox("Failed / Slow / Anomalies")
        self.failed_traffic_layout = QVBoxLayout(self.failed_traffic_group)
        self.table_failed = self.create_table()
        self.failed_traffic_layout.addWidget(self.table_failed)
        self.splitter.addWidget(self.failed_traffic_group)
        
        # Set initial sizes
        self.splitter.setSizes([400, 200])

    def create_table(self):
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Info", "Status"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        return table

    def refresh_interfaces(self):
        self.iface_combo.clear()
        interfaces = self.nm.list_interfaces()
        for iface in interfaces:
            self.iface_combo.addItem(iface['name'])

    def toggle_sniffing(self):
        if self.is_sniffing:
            self.sniffer.stop_sniffing()
            self.start_btn.setText("Start Sniffing")
            self.start_btn.setStyleSheet("background-color: #007acc;")
            self.is_sniffing = False
        else:
            iface = self.iface_combo.currentText()
            filter_str = self.filter_input.text()
            
            self.table_all.setRowCount(0)
            self.table_failed.setRowCount(0)
            
            self.sniffer_thread = self.sniffer.start_sniffing(iface, filter_str)
            self.sniffer_thread.packet_received.connect(self.add_packet)
            self.sniffer_thread.error_occurred.connect(self.on_error)
            
            self.start_btn.setText("Stop Sniffing")
            self.start_btn.setStyleSheet("background-color: #d32f2f;")
            self.is_sniffing = True

    def add_packet(self, pkt):
        # Add to All Traffic
        self.insert_packet_row(self.table_all, pkt)
        
        # Check if failed/slow/anomaly
        status = pkt.get('status', '')
        if status in ['Error', 'Connecting']:
            self.insert_packet_row(self.table_failed, pkt)

    def insert_packet_row(self, table, pkt):
        row = table.rowCount()
        table.insertRow(row)
        table.setItem(row, 0, QTableWidgetItem(pkt['time']))
        table.setItem(row, 1, QTableWidgetItem(pkt['src']))
        table.setItem(row, 2, QTableWidgetItem(pkt['dst']))
        table.setItem(row, 3, QTableWidgetItem(str(pkt['proto'])))
        table.setItem(row, 4, QTableWidgetItem(pkt['info']))
        
        status_item = QTableWidgetItem(pkt.get('status', ''))
        if pkt.get('status') == 'Error':
            status_item.setForeground(QColor('#ff5252')) # Red
        elif pkt.get('status') == 'Connecting':
            status_item.setForeground(QColor('#ffab40')) # Orange
        elif pkt.get('status') == 'OK':
             status_item.setForeground(QColor('#69f0ae')) # Green
            
        table.setItem(row, 5, status_item)
        
        # Check filter immediately
        self.check_filter_for_row(table, row, pkt['src'], pkt['dst'])
        
        if not table.isRowHidden(row):
            table.scrollToBottom()

    def apply_ip_filter(self):
        filter_ip = self.ip_filter_input.text().strip()
        
        for table in [self.table_all, self.table_failed]:
            for row in range(table.rowCount()):
                src = table.item(row, 1).text()
                dst = table.item(row, 2).text()
                
                if not filter_ip:
                    table.setRowHidden(row, False)
                elif filter_ip in src or filter_ip in dst:
                    table.setRowHidden(row, False)
                else:
                    table.setRowHidden(row, True)

    def check_filter_for_row(self, table, row, src, dst):
        filter_ip = self.ip_filter_input.text().strip()
        if not filter_ip:
            table.setRowHidden(row, False)
            return
            
        if filter_ip in src or filter_ip in dst:
            table.setRowHidden(row, False)
        else:
            table.setRowHidden(row, True)

    def on_error(self, msg):
        self.toggle_sniffing()
        QMessageBox.critical(self, "Sniffer Error", msg)
