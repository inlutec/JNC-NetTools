from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QProgressBar, QComboBox, QTextEdit, QGroupBox)
from src.core.scanner import NetworkScanner

class ScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = NetworkScanner()
        self.scan_thread = None
        
        self.layout = QVBoxLayout(self)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target Network (e.g. 192.168.1.0/24)")
        
        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Up", "Down"])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)
        
        controls_layout.addWidget(QLabel("Target:"))
        controls_layout.addWidget(self.target_input)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_combo)
        controls_layout.addWidget(self.scan_btn)
        
        self.layout.addLayout(controls_layout)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 0) # Indeterminate
        self.progress.hide()
        self.layout.addWidget(self.progress)
        
        # Results Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor", "Status", "Open Ports"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table)
        
        # Progress Log
        log_group = QGroupBox("Scan Progress")
        log_layout = QVBoxLayout(log_group)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: monospace;")
        log_layout.addWidget(self.log_output)
        self.layout.addWidget(log_group)

    def start_scan(self):
        if self.scan_btn.text() == "Stop Scan":
            if self.scan_thread:
                self.scan_thread.stop()
                self.scan_btn.setEnabled(False)
                self.scan_btn.setText("Stopping...")
            return

        target = self.target_input.text()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP range.")
            return
            
        self.scan_btn.setText("Stop Scan")
        self.scan_btn.setStyleSheet("background-color: #800000; color: white;")
        self.progress.show()
        self.table.setRowCount(0)
        self.log_output.clear()
        
        # Use default scan (TCP, Fast ports) for discovery
        # skip_discovery=False ensures we ONLY scan hosts that are UP (ARP/Ping response)
        self.scan_thread = self.scanner.scan(target, ports=None, scan_type="TCP", skip_discovery=False)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)

    def on_scan_progress(self, msg):
        self.log_output.append(msg)
        sb = self.log_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_scan_finished(self, result):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Network")
        self.scan_btn.setStyleSheet("")
        self.progress.hide()
        
        scan_data = result.get('scan', {})
        self.table.setRowCount(len(scan_data))
        
        for i, (ip, data) in enumerate(scan_data.items()):
            mac = "Unknown"
            vendor = "Unknown"
            status = data['status']['state']
            
            if 'addresses' in data and 'mac' in data['addresses']:
                mac = data['addresses']['mac']
                if 'vendor' in data and mac in data['vendor']:
                    vendor = data['vendor'][mac]
            
            # Collect Open Ports
            open_ports = []
            if 'tcp' in data:
                for port, info in data['tcp'].items():
                    if info['state'] == 'open':
                        open_ports.append(f"{port}/tcp")
            if 'udp' in data:
                for port, info in data['udp'].items():
                    if info['state'] == 'open':
                        open_ports.append(f"{port}/udp")
            
            ports_str = ", ".join(open_ports) if open_ports else ""
            
            self.table.setItem(i, 0, QTableWidgetItem(ip))
            self.table.setItem(i, 1, QTableWidgetItem(mac))
            self.table.setItem(i, 2, QTableWidgetItem(vendor))
            self.table.setItem(i, 3, QTableWidgetItem(status))
            self.table.setItem(i, 4, QTableWidgetItem(ports_str))
            
        self.apply_filters()

    def apply_filters(self):
        filter_text = self.filter_combo.currentText().lower()
        
        for row in range(self.table.rowCount()):
            status_item = self.table.item(row, 3)
            if not status_item:
                continue
                
            status = status_item.text().lower()
            
            if filter_text == "all":
                self.table.setRowHidden(row, False)
            elif filter_text == "up" and status == "up":
                self.table.setRowHidden(row, False)
            elif filter_text == "down" and status == "down":
                self.table.setRowHidden(row, False)
            else:
                self.table.setRowHidden(row, True)

    def on_scan_error(self, error):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Network")
        self.scan_btn.setStyleSheet("")
        self.progress.hide()
        
        if "stopped by user" in str(error):
            return
            
        QMessageBox.critical(self, "Scan Error", error)

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        event.accept()
