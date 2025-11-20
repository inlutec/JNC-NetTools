from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QRadioButton, QButtonGroup,
                             QGroupBox, QFormLayout, QMessageBox)
from PyQt6.QtCore import Qt
import ipaddress

class IPConfigWidget(QWidget):
    def __init__(self, network_manager):
        super().__init__()
        self.nm = network_manager
        self.current_iface = None
        
        self.layout = QVBoxLayout(self)
        
        # IP Configuration Group
        config_group = QGroupBox("IP Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Mode Selection
        mode_layout = QHBoxLayout()
        self.dhcp_radio = QRadioButton("DHCP")
        self.static_radio = QRadioButton("Static")
        self.static_radio.setChecked(True)
        
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.dhcp_radio)
        self.mode_group.addButton(self.static_radio)
        
        mode_layout.addWidget(self.dhcp_radio)
        mode_layout.addWidget(self.static_radio)
        mode_layout.addStretch()
        config_layout.addLayout(mode_layout)
        
        # Static IP Fields
        self.form_layout = QFormLayout()
        self.ip_input = QLineEdit()
        self.cidr_input = QLineEdit()
        self.cidr_input.setPlaceholderText("24")
        self.gateway_input = QLineEdit()
        
        self.form_layout.addRow("IP Address:", self.ip_input)
        self.form_layout.addRow("CIDR Prefix:", self.cidr_input)
        self.form_layout.addRow("Gateway:", self.gateway_input)
        
        # DNS Field
        self.dns_input = QLineEdit()
        self.form_layout.addRow("DNS:", self.dns_input)
        
        config_layout.addLayout(self.form_layout)
        
        # Apply Button
        self.apply_btn = QPushButton("Apply Configuration")
        self.apply_btn.clicked.connect(self.apply_config)
        config_layout.addWidget(self.apply_btn)
        
        self.layout.addWidget(config_group)
        
        # Subnet Calculator Group
        calc_group = QGroupBox("Subnet Calculator")
        calc_layout = QVBoxLayout(calc_group)
        
        calc_form = QFormLayout()
        self.calc_ip = QLineEdit()
        self.calc_cidr = QLineEdit()
        self.calc_cidr.setPlaceholderText("24")
        self.calc_netmask = QLineEdit()
        self.calc_netmask.setReadOnly(True)
        self.calc_network = QLineEdit()
        self.calc_network.setReadOnly(True)
        self.calc_broadcast = QLineEdit()
        self.calc_broadcast.setReadOnly(True)
        
        calc_form.addRow("IP Address:", self.calc_ip)
        calc_form.addRow("CIDR:", self.calc_cidr)
        calc_form.addRow("Netmask:", self.calc_netmask)
        calc_form.addRow("Network:", self.calc_network)
        calc_form.addRow("Broadcast:", self.calc_broadcast)
        
        calc_layout.addLayout(calc_form)
        
        # Calculate Button (or auto-calc)
        self.calc_btn = QPushButton("Calculate")
        self.calc_btn.clicked.connect(self.calculate_subnet)
        calc_layout.addWidget(self.calc_btn)
        
        self.layout.addWidget(calc_group)
        self.layout.addStretch()
        
        # Connect signals
        self.dhcp_radio.toggled.connect(self.toggle_inputs)
        self.static_radio.toggled.connect(self.toggle_inputs)

    def set_interface(self, iface_data):
        self.current_iface = iface_data
        
        # Get real config from NM
        config = iface_data.get('config', {})
        method = config.get('method', 'auto')
        
        if method == 'manual':
            self.static_radio.setChecked(True)
            self.ip_input.setText(config.get('ip', ''))
            self.cidr_input.setText(config.get('prefix', ''))
            self.gateway_input.setText(config.get('gateway', ''))
            self.dns_input.setText(config.get('dns', ''))
        else:
            self.dhcp_radio.setChecked(True)
            # Clear fields or show current lease?
            # For now, let's show current IP even if DHCP
            if iface_data['ipv4']:
                ip, prefix = iface_data['ipv4'][0].split('/')
                self.ip_input.setText(ip)
                self.cidr_input.setText(prefix)
        
        # Update calculator
        self.calc_ip.setText(self.ip_input.text())
        self.calc_cidr.setText(self.cidr_input.text())
        self.calculate_subnet()

    def toggle_inputs(self):
        enabled = self.static_radio.isChecked()
        self.ip_input.setEnabled(enabled)
        self.cidr_input.setEnabled(enabled)
        self.gateway_input.setEnabled(enabled)
        self.dns_input.setEnabled(enabled)

    def calculate_subnet(self):
        ip = self.calc_ip.text()
        cidr = self.calc_cidr.text()
        
        if not ip or not cidr:
            return
            
        try:
            network = ipaddress.IPv4Interface(f"{ip}/{cidr}")
            self.calc_netmask.setText(str(network.netmask))
            self.calc_network.setText(str(network.network))
            self.calc_broadcast.setText(str(network.network.broadcast_address))
        except ValueError as e:
            self.calc_netmask.setText("Invalid IP/CIDR")

    def apply_config(self):
        if not self.current_iface:
            QMessageBox.warning(self, "Error", "No interface selected")
            return
            
        iface_name = self.current_iface['name']
        
        try:
            if self.dhcp_radio.isChecked():
                success, msg = self.nm.apply_interface_config(iface_name, 'auto')
            else:
                ip = self.ip_input.text()
                cidr = self.cidr_input.text()
                gateway = self.gateway_input.text()
                dns = self.dns_input.text()
                success, msg = self.nm.apply_interface_config(iface_name, 'manual', ip, cidr, gateway, dns)
            
            if success:
                QMessageBox.information(self, "Success", msg)
            else:
                QMessageBox.critical(self, "Error", msg)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
