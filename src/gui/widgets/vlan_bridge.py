from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QComboBox, QSpinBox, QPushButton, QGroupBox, 
                             QMessageBox, QFormLayout, QLineEdit, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QCheckBox, QSplitter)
from PyQt6.QtCore import Qt, QTimer
from src.core.vlan_scanner import VLANScanner

class VLANBridgeWidget(QWidget):
    def __init__(self, network_manager):
        super().__init__()
        self.nm = network_manager
        self.vlan_scanner = VLANScanner()
        self.scan_thread = None
        
        self.layout = QVBoxLayout(self)
        
        # Create a horizontal layout for the top part (Bridge + Wifi)
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.layout.addWidget(self.splitter)
        
        # Top Container Widget
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # Left Column: Wired Bridging
        left_col = QVBoxLayout()
        
        # Wired Bridging Group
        wired_group = QGroupBox("Wired Bridging")
        wired_layout = QVBoxLayout(wired_group)
        wired_layout.setSpacing(5)
        wired_layout.setContentsMargins(10, 15, 10, 10)
        
        # Mode Selection
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["VLAN Trunk (Trunk -> Access)", "Passthrough (Untagged -> Untagged)"])
        self.mode_combo.currentIndexChanged.connect(self.toggle_mode_inputs)
        mode_layout.addWidget(self.mode_combo)
        wired_layout.addLayout(mode_layout)
        
        # Interface Selection
        form_layout = QFormLayout()
        form_layout.setSpacing(5)
        self.trunk_combo = QComboBox() # Input
        self.trunk_combo.currentIndexChanged.connect(self.on_trunk_combo_changed)
        self.access_combo = QComboBox() # Output
        
        self.lbl_input = QLabel("Input Interface (Trunk):")
        self.lbl_output = QLabel("Output Interface (Access):")
        
        form_layout.addRow(self.lbl_input, self.trunk_combo)
        form_layout.addRow(self.lbl_output, self.access_combo)
        
        # VLAN ID Input
        self.vlan_input = QSpinBox()
        self.vlan_input.setRange(1, 4094)
        self.lbl_vlan = QLabel("VLAN ID:")
        form_layout.addRow(self.lbl_vlan, self.vlan_input)
        
        wired_layout.addLayout(form_layout)
        
        # IP / DHCP Configuration
        ip_group = QGroupBox("Bridge IP & DHCP Server")
        ip_layout = QFormLayout(ip_group)
        ip_layout.setSpacing(5)
        
        self.enable_dhcp_cb = QCheckBox("Enable DHCP Server & Static IP")
        self.enable_dhcp_cb.toggled.connect(self.toggle_dhcp_inputs)
        ip_layout.addRow(self.enable_dhcp_cb)
        
        self.bridge_ip = QLineEdit("192.168.50.1")
        self.dhcp_start = QLineEdit("192.168.50.10")
        self.dhcp_end = QLineEdit("192.168.50.100")
        
        ip_layout.addRow("Bridge IP (Gateway):", self.bridge_ip)
        ip_layout.addRow("DHCP Start:", self.dhcp_start)
        ip_layout.addRow("DHCP End:", self.dhcp_end)
        
        wired_layout.addWidget(ip_group)
        self.ip_group = ip_group
        
        # Initialize inputs state
        self.toggle_dhcp_inputs(False)
        
        self.bridge_btn = QPushButton("Create Bridge")
        self.bridge_btn.clicked.connect(self.create_bridge)
        wired_layout.addWidget(self.bridge_btn)
        
        # Bridge Management Group
        manage_group = QGroupBox("Manage Bridges")
        manage_layout = QHBoxLayout(manage_group)
        manage_layout.setContentsMargins(5, 15, 5, 5)
        
        self.active_bridges_combo = QComboBox()
        self.delete_bridge_btn = QPushButton("Delete Bridge")
        self.delete_bridge_btn.setStyleSheet("background-color: #800000; color: white;")
        self.delete_bridge_btn.clicked.connect(self.delete_bridge)
        
        manage_layout.addWidget(QLabel("Active Bridges:"))
        manage_layout.addWidget(self.active_bridges_combo)
        manage_layout.addWidget(self.delete_bridge_btn)
        
        wired_layout.addWidget(manage_group)
        
        left_col.addWidget(wired_group)
        top_layout.addLayout(left_col)
        
        # Right Column: Wi-Fi Bridging
        right_col = QVBoxLayout()
        wifi_group = QGroupBox("Wi-Fi AP Bridging")
        wifi_layout = QVBoxLayout(wifi_group)
        wifi_layout.setSpacing(5)
        wifi_layout.setContentsMargins(10, 15, 10, 10)
        
        wifi_form = QFormLayout()
        wifi_form.setSpacing(5)
        self.wifi_iface_combo = QComboBox()
        self.wifi_iface_combo.currentIndexChanged.connect(self.on_wifi_iface_changed)
        self.ssid_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.bridge_select_combo = QComboBox() # Select which bridge to attach to
        
        wifi_form.addRow("Wi-Fi Interface:", self.wifi_iface_combo)
        wifi_form.addRow("SSID:", self.ssid_input)
        wifi_form.addRow("Password:", self.password_input)
        wifi_form.addRow("Attach to Bridge:", self.bridge_select_combo)
        
        wifi_layout.addLayout(wifi_form)
        
        # Wi-Fi DHCP Configuration
        wifi_dhcp_group = QGroupBox("Wi-Fi DHCP Server")
        wifi_dhcp_layout = QFormLayout(wifi_dhcp_group)
        wifi_dhcp_layout.setSpacing(5)
        
        self.wifi_enable_dhcp_cb = QCheckBox("Enable DHCP on Bridge")
        self.wifi_enable_dhcp_cb.toggled.connect(self.toggle_wifi_dhcp_inputs)
        wifi_dhcp_layout.addRow(self.wifi_enable_dhcp_cb)
        
        self.wifi_bridge_ip = QLineEdit("192.168.60.1")
        self.wifi_dhcp_start = QLineEdit("192.168.60.10")
        self.wifi_dhcp_end = QLineEdit("192.168.60.100")
        
        wifi_dhcp_layout.addRow("Bridge IP:", self.wifi_bridge_ip)
        wifi_dhcp_layout.addRow("DHCP Start:", self.wifi_dhcp_start)
        wifi_dhcp_layout.addRow("DHCP End:", self.wifi_dhcp_end)
        
        wifi_layout.addWidget(wifi_dhcp_group)
        self.wifi_dhcp_group = wifi_dhcp_group
        
        # Initialize Wi-Fi DHCP inputs state
        self.toggle_wifi_dhcp_inputs(False)
        
        wifi_btns_layout = QHBoxLayout()
        self.wifi_btn = QPushButton("Start Wi-Fi AP")
        self.wifi_btn.clicked.connect(self.start_wifi)
        wifi_btns_layout.addWidget(self.wifi_btn)
        
        self.stop_wifi_btn = QPushButton("Stop Wi-Fi AP")
        self.stop_wifi_btn.clicked.connect(self.stop_wifi)
        self.stop_wifi_btn.setEnabled(False)
        wifi_btns_layout.addWidget(self.stop_wifi_btn)
        
        wifi_layout.addLayout(wifi_btns_layout)
        
        # Connected Clients
        self.clients_group = QGroupBox("Connected Clients")
        clients_layout = QVBoxLayout(self.clients_group)
        clients_layout.setContentsMargins(5, 15, 5, 5)
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(3)
        self.clients_table.setHorizontalHeaderLabels(["MAC", "IP", "Hostname"])
        self.clients_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.clients_table.setMaximumHeight(150)
        clients_layout.addWidget(self.clients_table)
        wifi_layout.addWidget(self.clients_group)
        
        right_col.addWidget(wifi_group)
        top_layout.addLayout(right_col)
        
        # Client Refresh Timer
        self.client_timer = QTimer()
        self.client_timer.timeout.connect(self.refresh_clients)
        self.client_timer.setInterval(5000) # 5 seconds
        
        self.splitter.addWidget(top_widget)
        
        # Bottom Part: VLAN Scanner
        scanner_group = QGroupBox("Passive VLAN Scanner")
        scanner_layout = QVBoxLayout(scanner_group)
        scanner_layout.setContentsMargins(10, 15, 10, 10)
        
        scan_controls = QHBoxLayout()
        self.scan_iface_combo = QComboBox()
        self.scan_btn = QPushButton("Start Scan (10s)")
        self.scan_btn.clicked.connect(self.start_scan)
        
        scan_controls.addWidget(QLabel("Interface:"))
        scan_controls.addWidget(self.scan_iface_combo)
        scan_controls.addWidget(self.scan_btn)
        
        scanner_layout.addLayout(scan_controls)
        
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(2)
        self.scan_table.setHorizontalHeaderLabels(["VLAN ID", "Packets Detected"])
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.scan_table.setMinimumHeight(200) # Ensure it has space
        scanner_layout.addWidget(self.scan_table)
        
        self.port_type_label = QLabel("Port Type: Unknown")
        self.port_type_label.setStyleSheet("font-weight: bold; color: #aaaaaa;")
        scanner_layout.addWidget(self.port_type_label)
        
        self.splitter.addWidget(scanner_group)
        
        # Set initial sizes for splitter (Top, Bottom)
        self.splitter.setSizes([400, 300])
        
        self.refresh_interfaces()
        self.toggle_mode_inputs() # Initialize UI based on default mode

    def refresh_interfaces(self):
        interfaces = self.nm.list_interfaces()
        self.trunk_combo.clear()
        self.access_combo.clear()
        self.scan_iface_combo.clear()
        self.wifi_iface_combo.clear()
        
        for iface in interfaces:
            name = iface['name']
            self.trunk_combo.addItem(name)
            self.access_combo.addItem(name)
            self.scan_iface_combo.addItem(name)
            if iface['type'] == 'Wireless':
                self.wifi_iface_combo.addItem(name)
                
        # Populate bridges
        self.bridge_select_combo.clear()
        self.active_bridges_combo.clear()
        
        bridges = [iface['name'] for iface in interfaces if iface['name'].startswith('br')]
        
        for br in bridges:
            self.bridge_select_combo.addItem(br)
            self.active_bridges_combo.addItem(br)
            
        # Add manual entry option for Wi-Fi bridge selection if needed
        self.bridge_select_combo.setEditable(True)

    def toggle_mode_inputs(self):
        mode = self.mode_combo.currentText()
        if "Passthrough" in mode:
            self.lbl_input.setText("Interface 1:")
            self.lbl_output.setText("Interface 2:")
            self.lbl_vlan.setVisible(False)
            self.vlan_input.setVisible(False)
        else:
            self.lbl_input.setText("Input Interface (Trunk):")
            self.lbl_output.setText("Output Interface (Access):")
            self.lbl_vlan.setVisible(True)
            self.lbl_vlan.setVisible(True)
            self.vlan_input.setVisible(True)

    def toggle_dhcp_inputs(self, checked):
        self.bridge_ip.setEnabled(checked)
        self.dhcp_start.setEnabled(checked)
        self.dhcp_end.setEnabled(checked)

    def toggle_wifi_dhcp_inputs(self, checked):
        self.wifi_bridge_ip.setEnabled(checked)
        self.wifi_dhcp_start.setEnabled(checked)
        self.wifi_dhcp_end.setEnabled(checked)

    def on_trunk_combo_changed(self, index):
        iface_name = self.trunk_combo.currentText()
        self.autofill_dhcp(iface_name, self.bridge_ip, self.dhcp_start, self.dhcp_end)

    def on_wifi_iface_changed(self, index):
        iface_name = self.wifi_iface_combo.currentText()
        self.autofill_dhcp(iface_name, self.wifi_bridge_ip, self.wifi_dhcp_start, self.wifi_dhcp_end)

    def autofill_dhcp(self, iface_name, ip_field, start_field, end_field):
        if not iface_name:
            return
            
        # Get config to auto-fill DHCP
        config = self.nm.get_interface_config(iface_name)
        ip = config.get('ip', '')
        
        if ip:
            # Suggest a subnet based on this IP
            parts = ip.split('.')
            if len(parts) == 4:
                base = ".".join(parts[:3])
                ip_field.setText(ip)
                start_field.setText(f"{base}.100")
                end_field.setText(f"{base}.200")

    def create_bridge(self):
        mode = self.mode_combo.currentText()
        iface1 = self.trunk_combo.currentText()
        iface2 = self.access_combo.currentText()
        
        if iface1 == iface2:
            QMessageBox.warning(self, "Error", "Interfaces must be different")
            return

        success = False
        msg = ""
        bridge_name = ""
        
        if "Passthrough" in mode:
            success, msg = self.nm.create_simple_bridge(iface1, iface2)
            bridge_name = "br_pass"
        else:
            vlan_id = self.vlan_input.value()
            success, msg = self.nm.create_vlan_bridge(iface1, vlan_id, iface2)
            bridge_name = f"br{vlan_id}"
            
        if success:
            # Handle IP/DHCP
            if self.enable_dhcp_cb.isChecked():
                ip = self.bridge_ip.text()
                start = self.dhcp_start.text()
                end = self.dhcp_end.text()
                
                # Start DHCP
                d_success, d_msg = self.nm.start_dhcp_server(bridge_name, ip, start, end)
                if d_success:
                    msg += f"\nDHCP Server running on {ip}"
                else:
                    msg += f"\nDHCP Error: {d_msg}"
            
            QMessageBox.information(self, "Success", msg)
            self.bridge_select_combo.addItem(bridge_name)
        else:
            QMessageBox.critical(self, "Error", msg)

    def start_wifi(self):
        wifi_iface = self.wifi_iface_combo.currentText()
        ssid = self.ssid_input.text()
        password = self.password_input.text()
        bridge = self.bridge_select_combo.currentText()
        
        if not wifi_iface or not ssid or not password or not bridge:
            QMessageBox.warning(self, "Error", "Please fill all Wi-Fi fields.")
            return
            
        success, msg = self.nm.setup_wifi_ap(wifi_iface, ssid, password, bridge)
        
        if success:
            # Handle DHCP for Wi-Fi
            if self.wifi_enable_dhcp_cb.isChecked():
                ip = self.wifi_bridge_ip.text()
                start = self.wifi_dhcp_start.text()
                end = self.wifi_dhcp_end.text()
                
                # Start DHCP on the bridge
                d_success, d_msg = self.nm.start_dhcp_server(bridge, ip, start, end)
                if d_success:
                    msg += f"\nDHCP Server running on {ip}"
                else:
                    msg += f"\nDHCP Error: {d_msg}"
            
            self.wifi_btn.setEnabled(False)
            self.stop_wifi_btn.setEnabled(True)
            self.client_timer.start()
            QMessageBox.information(self, "Success", msg)
        else:
            QMessageBox.critical(self, "Error", f"Failed to start Wi-Fi AP: {msg}")

    def delete_bridge(self):
        bridge = self.active_bridges_combo.currentText()
        if not bridge:
            return
            
        confirm = QMessageBox.question(self, "Confirm Deletion", 
                                     f"Are you sure you want to delete bridge '{bridge}'?\nThis will stop any associated DHCP servers.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                     
        if confirm == QMessageBox.StandardButton.Yes:
            success, msg = self.nm.delete_bridge(bridge)
            if success:
                QMessageBox.information(self, "Success", msg)
                self.refresh_interfaces()
            else:
                QMessageBox.critical(self, "Error", msg)

    def stop_wifi(self):
        iface = self.wifi_iface_combo.currentText()
        success, msg = self.nm.stop_wifi_ap(iface)
        
        if success:
            self.wifi_btn.setEnabled(True)
            self.stop_wifi_btn.setEnabled(False)
            self.client_timer.stop()
            self.clients_table.setRowCount(0)
            QMessageBox.information(self, "Success", msg)
        else:
            QMessageBox.critical(self, "Error", msg)

    def refresh_clients(self):
        iface = self.wifi_iface_combo.currentText()
        clients = self.nm.get_wifi_clients(iface)
        
        self.clients_table.setRowCount(len(clients))
        for i, client in enumerate(clients):
            self.clients_table.setItem(i, 0, QTableWidgetItem(client['mac']))
            self.clients_table.setItem(i, 1, QTableWidgetItem(client['ip']))
            self.clients_table.setItem(i, 2, QTableWidgetItem(client['hostname']))

    def start_scan(self):
        if self.scan_btn.text() == "Stop Scan":
            if self.scan_thread:
                self.scan_thread.stop()
                self.scan_btn.setEnabled(False)
                self.scan_btn.setText("Stopping...")
            return

        iface = self.scan_iface_combo.currentText()
        self.scan_table.setRowCount(0)
        self.port_type_label.setText("Port Type: Scanning...")
        self.port_type_label.setStyleSheet("font-weight: bold; color: #e0e000;")
        
        self.scan_btn.setText("Stop Scan")
        self.scan_btn.setStyleSheet("background-color: #800000; color: white;")
        
        self.scan_thread = self.vlan_scanner.scan(iface)
        self.scan_thread.vlan_detected.connect(self.on_vlan_detected)
        self.scan_thread.untagged_detected.connect(self.on_untagged_detected)
        self.scan_thread.scan_finished.connect(self.on_scan_finished)
        self.scan_thread.error_occurred.connect(self.on_scan_error)

    def on_untagged_detected(self, count):
        self.update_table_row("Untagged (Native)", count)
        self.update_port_analysis()

    def on_vlan_detected(self, vlan_id, count):
        self.update_table_row(str(vlan_id), count)
        self.update_port_analysis()
        
    def update_table_row(self, label, count):
        # Check if row exists
        found = False
        for row in range(self.scan_table.rowCount()):
            if self.scan_table.item(row, 0).text() == label:
                self.scan_table.setItem(row, 1, QTableWidgetItem(str(count)))
                found = True
                break
        
        if not found:
            row = self.scan_table.rowCount()
            self.scan_table.insertRow(row)
            self.scan_table.setItem(row, 0, QTableWidgetItem(label))
            self.scan_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def update_port_analysis(self):
        # Analyze table content to guess port type
        has_untagged = False
        vlan_count = 0
        
        for row in range(self.scan_table.rowCount()):
            label = self.scan_table.item(row, 0).text()
            if label == "Untagged (Native)":
                has_untagged = True
            else:
                vlan_count += 1
        
        if vlan_count > 1:
            msg = f"Trunk Port (Detected {vlan_count} VLANs)"
            color = "#00e000" # Green
        elif vlan_count == 1 and has_untagged:
            msg = "Hybrid Port (Tagged + Untagged)"
            color = "#e0e000" # Yellow
        elif vlan_count == 1:
            msg = "Trunk Port (Single VLAN)"
            color = "#00e000"
        elif has_untagged:
            msg = "Access Port (Untagged Traffic Only)"
            color = "#00e0e0" # Cyan
        else:
            msg = "Unknown / No Traffic"
            color = "#aaaaaa"
            
        self.port_type_label.setText(f"Port Type: {msg}")
        self.port_type_label.setStyleSheet(f"font-weight: bold; color: {color};")

    def on_scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Scan (10s)")
        self.scan_btn.setStyleSheet("")
        # Don't show popup if just stopped, but hard to distinguish here without flag. 
        # Let's just show it, or maybe check if it was manual stop?
        # For now, simple message is fine.
        # QMessageBox.information(self, "Scan Finished", "VLAN Scan completed.") 

    def on_scan_error(self, msg):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Scan (10s)")
        self.scan_btn.setStyleSheet("")
        QMessageBox.critical(self, "Error", msg)

    def closeEvent(self, event):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
        event.accept()
