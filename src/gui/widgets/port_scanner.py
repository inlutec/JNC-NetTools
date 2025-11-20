from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QMessageBox, QGroupBox, QTextEdit)
from PyQt6.QtCore import Qt
from src.core.scanner import NetworkScanner

class PortScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = NetworkScanner()
        self.scan_thread = None
        
        self.layout = QVBoxLayout(self)
        
        # Controls Group
        controls_group = QGroupBox("Target Configuration")
        controls_layout = QVBoxLayout(controls_group)
        
        # Target IP
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target IP:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.50")
        target_layout.addWidget(self.target_input)
        controls_layout.addLayout(target_layout)
        
        # Ports
        ports_layout = QHBoxLayout()
        ports_layout.addWidget(QLabel("Ports:"))
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("e.g., 80, 443, 1000-2000")
        ports_layout.addWidget(self.ports_input)
        controls_layout.addLayout(ports_layout)
        
        # Protocol & Button
        action_layout = QHBoxLayout()
        action_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "Both"])
        action_layout.addWidget(self.protocol_combo)
        
        self.scan_btn = QPushButton("Start Port Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_btn)
        
        controls_layout.addLayout(action_layout)
        
        self.layout.addWidget(controls_group)
        
        # Filter & Search Group
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Open", "Closed"])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.filter_combo)
        
        filter_layout.addWidget(QLabel("Search Port:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search port number...")
        self.search_input.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.search_input)
        
        self.layout.addLayout(filter_layout)
        
        # Results Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service"])
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
            self.stop_scan()
            return

        target = self.target_input.text().strip()
        ports = self.ports_input.text().strip()
        protocol = self.protocol_combo.currentText()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP.")
            return
            
        if not ports:
            QMessageBox.warning(self, "Error", "Please enter ports to scan.")
            return
            
        self.scan_btn.setText("Stop Scan")
        self.scan_btn.setStyleSheet("background-color: #800000; color: white;") # Red for stop
        self.table.setRowCount(0)
        self.log_output.clear()
        
        self.current_target = target
        self.current_ports = ports
        self.chain_udp = False
        
        if protocol == "Both":
            self.chain_udp = True
            self.run_scan(target, ports, "TCP")
        else:
            self.run_scan(target, ports, protocol)

    def run_scan(self, target, ports, protocol):
        self.log_output.append(f"--- Starting {protocol} Scan ---\n")
        # Port Scanner should use skip_discovery=True (-Pn) to ensure it scans even if ping blocked
        self.scan_thread = self.scanner.scan(target, ports, protocol, skip_discovery=True)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.scan_error.connect(self.on_scan_error)
        self.scan_thread.scan_progress.connect(self.on_scan_progress)
        self.scan_thread.port_found.connect(self.on_port_found)

    def stop_scan(self):
        self.chain_udp = False # Cancel chain
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_btn.setEnabled(False)
            self.scan_btn.setText("Stopping...")

    def on_scan_progress(self, msg):
        self.log_output.append(msg)
        sb = self.log_output.verticalScrollBar()
        sb.setValue(sb.maximum())
        
    def on_port_found(self, port, proto, state, service):
        # Check if already exists
        items = self.table.findItems(str(port), Qt.MatchFlag.MatchExactly)
        for item in items:
            if item.column() == 0:
                row = item.row()
                if self.table.item(row, 1).text() == proto:
                    return 
        
        self.add_result_row(port, proto, state, service)

    def on_scan_finished(self, result):
        # 1. Process XML results
        found_ports = set() 
        if result and 'scan' in result:
            for ip, data in result['scan'].items():
                if 'tcp' in data:
                    for port, info in data['tcp'].items():
                        self.update_or_add_row(port, "TCP", info['state'], info.get('name', ''))
                        found_ports.add((int(port), "TCP"))
                if 'udp' in data:
                    for port, info in data['udp'].items():
                        self.update_or_add_row(port, "UDP", info['state'], info.get('name', ''))
                        found_ports.add((int(port), "UDP"))

        # 2. Chain UDP if needed
        if self.chain_udp:
            self.chain_udp = False
            self.run_scan(self.current_target, self.current_ports, "UDP")
            return

        # 3. Finalize (only after all scans done)
        self.finalize_scan(found_ports)

    def finalize_scan(self, found_ports_unused):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Port Scan")
        self.scan_btn.setStyleSheet("") 
        
        # Disable updates to prevent freeze
        self.table.setUpdatesEnabled(False)
        
        try:
            # 1. Build set of ALREADY FOUND ports from the table
            existing_ports = set()
            for row in range(self.table.rowCount()):
                port_item = self.table.item(row, 0)
                proto_item = self.table.item(row, 1)
                if port_item and proto_item:
                    existing_ports.add((int(port_item.text()), proto_item.text()))

            # 2. Parse requested ports
            requested_ports_str = self.ports_input.text().strip()
            requested_proto = self.protocol_combo.currentText()
            
            target_ports = set()
            try:
                parts = requested_ports_str.split(',')
                for part in parts:
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        target_ports.update(range(start, end + 1))
                    else:
                        target_ports.add(int(part))
            except:
                pass 
                
            # Determine protocols
            protos = []
            if requested_proto == "TCP" or requested_proto == "Both":
                protos.append("TCP")
            if requested_proto == "UDP" or requested_proto == "Both":
                protos.append("UDP")
                
            # 3. Add closed rows for missing ports
            # Only show closed ports if the total number of ports is reasonable (< 500)
            # to prevent UI freezing and overwhelming the user.
            if len(target_ports) > 500:
                self.log_output.append(f"\n[INFO] Large range ({len(target_ports)} ports). Hiding closed ports.")
            else:
                self.table.setSortingEnabled(False)
                
                for port in target_ports:
                    for proto in protos:
                        if (port, proto) not in existing_ports:
                            # Pass update_filter=False for bulk addition
                            self.add_result_row(port, proto, "closed", "", update_filter=False)
                            
                self.table.setSortingEnabled(True)
            
            self.apply_filters() # Apply once at the end
            
        finally:
            self.table.setUpdatesEnabled(True)

    def row_exists(self, port, proto):
        # Deprecated / Unused in optimized version but kept for safety if needed elsewhere
        items = self.table.findItems(str(port), Qt.MatchFlag.MatchExactly)
        for item in items:
            if item.column() == 0:
                if self.table.item(item.row(), 1).text() == proto:
                    return True
        return False

    def update_or_add_row(self, port, proto, state, service):
        # Find row
        items = self.table.findItems(str(port), Qt.MatchFlag.MatchExactly)
        found_row = -1
        for item in items:
            if item.column() == 0:
                if self.table.item(item.row(), 1).text() == proto:
                    found_row = item.row()
                    break
        
        if found_row >= 0:
            # Update
            self.update_row_style(found_row, state)
            self.table.setItem(found_row, 3, QTableWidgetItem(service))
        else:
            # Add
            self.add_result_row(port, proto, state, service)

    def add_result_row(self, port, proto, state, service, update_filter=True):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.table.setItem(row, 1, QTableWidgetItem(proto))
        
        state_item = QTableWidgetItem(state)
        self.table.setItem(row, 2, state_item)
        self.table.setItem(row, 3, QTableWidgetItem(service))
        
        self.update_row_style(row, state)
        
        if update_filter:
            self.apply_filters() # Re-apply filters to new row

    def update_row_style(self, row, state):
        state_item = self.table.item(row, 2)
        if state == 'open':
            state_item.setForeground(Qt.GlobalColor.green)
            state_item.setText("open")
        elif state == 'closed':
            state_item.setForeground(Qt.GlobalColor.red)
            state_item.setText("closed")
        else:
            state_item.setForeground(Qt.GlobalColor.yellow)
            state_item.setText(state)

    def apply_filters(self):
        filter_state = self.filter_combo.currentText().lower()
        search_text = self.search_input.text().strip()
        
        for i in range(self.table.rowCount()):
            show = True
            
            # State Filter
            state_item = self.table.item(i, 2)
            state = state_item.text()
            if filter_state != "all":
                if filter_state == "open" and state != "open":
                    show = False
                elif filter_state == "closed" and state != "closed":
                    show = False
            
            # Search Filter
            if show and search_text:
                port_item = self.table.item(i, 0)
                if search_text not in port_item.text():
                    show = False
            
            self.table.setRowHidden(i, not show)

    def on_scan_error(self, msg):
        self.chain_udp = False # Stop chain on error
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Port Scan")
        self.scan_btn.setStyleSheet("") 
        
        if "kill" in str(msg) or "None" in str(msg) or "stopped by user" in str(msg):
             return
             
        QMessageBox.critical(self, "Error", f"Scan failed: {msg}")

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        event.accept()
