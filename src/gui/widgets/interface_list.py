from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QListWidget, QListWidgetItem, 
                             QLabel, QHBoxLayout, QFrame, QPushButton, QStyle)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QFont

class InterfaceListWidget(QWidget):
    interface_selected = pyqtSignal(dict)

    def __init__(self, network_manager):
        super().__init__()
        self.nm = network_manager
        self.layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Network Interfaces")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        # Refresh Button
        self.refresh_btn = QPushButton()
        self.refresh_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.refresh_btn.setToolTip("Refresh Interfaces")
        self.refresh_btn.setFixedSize(30, 30)
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        header_layout.addWidget(self.refresh_btn)
        
        self.layout.addLayout(header_layout)
        
        # List
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.layout.addWidget(self.list_widget)
        
        self.refresh_interfaces()

    def refresh_interfaces(self):
        self.list_widget.clear()
        interfaces = self.nm.list_interfaces()
        
        for iface in interfaces:
            item = QListWidgetItem()
            
            # Create custom widget for the item
            item_widget = QWidget()
            item_layout = QVBoxLayout(item_widget)
            item_layout.setContentsMargins(5, 5, 5, 5)
            
            # Top row: Name + Type + Status
            top_row = QHBoxLayout()
            name_label = QLabel(iface['name'])
            name_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            
            type_label = QLabel(iface['type'])
            type_label.setStyleSheet("color: #aaaaaa; font-size: 10px;")
            
            status_color = "#4caf50" if iface['is_up'] else "#f44336"
            status_label = QLabel("● " + iface['status'])
            status_label.setStyleSheet(f"color: {status_color}; font-weight: bold;")
            
            # Config Method Badge (DHCP/Static)
            config_method = iface.get('config', {}).get('method', 'unknown')
            method_text = "DHCP" if config_method == 'auto' else "Static" if config_method == 'manual' else config_method.upper()
            method_label = QLabel(f"[{method_text}]")
            method_label.setStyleSheet("color: #e0e0e0; font-size: 10px; background-color: #3e3e3e; padding: 2px 4px; border-radius: 3px;")
            
            top_row.addWidget(name_label)
            top_row.addWidget(type_label)
            top_row.addWidget(method_label)
            top_row.addStretch()
            top_row.addWidget(status_label)
            
            # Bottom row: IP + MAC
            bottom_row = QHBoxLayout()
            
            ip_text = iface['ipv4'][0] if iface['ipv4'] else "No IP"
            ip_label = QLabel(f"IP: {ip_text}")
            ip_label.setStyleSheet("color: #0078d7;")
            
            mac_label = QLabel(f"MAC: {iface['mac']}")
            mac_label.setStyleSheet("color: #888888;")
            
            bottom_row.addWidget(ip_label)
            bottom_row.addStretch()
            bottom_row.addWidget(mac_label)
            
            item_layout.addLayout(top_row)
            item_layout.addLayout(bottom_row)
            
            item.setSizeHint(item_widget.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, item_widget)
            
            # Store data in item
            item.setData(Qt.ItemDataRole.UserRole, iface)

    def on_item_clicked(self, item):
        iface_data = item.data(Qt.ItemDataRole.UserRole)
        self.interface_selected.emit(iface_data)
