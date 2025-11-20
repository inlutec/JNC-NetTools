from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QComboBox, 
                             QTabWidget, QSpinBox, QGroupBox)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from src.core.diagnostics import DiagnosticsManager

class DiagnosticsWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args
        self.is_running = True

    def run(self):
        try:
            for line in self.func(*self.args):
                if not self.is_running:
                    break
                self.output_signal.emit(line)
        except Exception as e:
            self.output_signal.emit(f"Error: {str(e)}")
        finally:
            self.finished_signal.emit()

    def stop(self):
        self.is_running = False

class DiagnosticsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.dm = DiagnosticsManager()
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Tabs for different tools
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Ping Tab
        self.ping_tab = QWidget()
        self.init_ping_tab()
        self.tabs.addTab(self.ping_tab, "Ping")

        # Traceroute Tab
        self.traceroute_tab = QWidget()
        self.init_traceroute_tab()
        self.tabs.addTab(self.traceroute_tab, "Traceroute")

        # DNS Tab
        self.dns_tab = QWidget()
        self.init_dns_tab()
        self.tabs.addTab(self.dns_tab, "DNS Lookup")

    def init_ping_tab(self):
        layout = QVBoxLayout(self.ping_tab)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Host:"))
        self.ping_host_input = QLineEdit()
        self.ping_host_input.setPlaceholderText("e.g., google.com or 8.8.8.8")
        controls_layout.addWidget(self.ping_host_input)
        
        controls_layout.addWidget(QLabel("Count:"))
        self.ping_count_input = QSpinBox()
        self.ping_count_input.setRange(1, 100)
        self.ping_count_input.setValue(4)
        controls_layout.addWidget(self.ping_count_input)
        
        self.ping_btn = QPushButton("Ping")
        self.ping_btn.clicked.connect(self.start_ping)
        controls_layout.addWidget(self.ping_btn)
        
        layout.addLayout(controls_layout)
        
        # Output
        self.ping_output = QTextEdit()
        self.ping_output.setReadOnly(True)
        layout.addWidget(self.ping_output)

    def init_traceroute_tab(self):
        layout = QVBoxLayout(self.traceroute_tab)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Host:"))
        self.trace_host_input = QLineEdit()
        self.trace_host_input.setPlaceholderText("e.g., google.com")
        controls_layout.addWidget(self.trace_host_input)
        
        self.trace_btn = QPushButton("Trace")
        self.trace_btn.clicked.connect(self.start_traceroute)
        controls_layout.addWidget(self.trace_btn)
        
        layout.addLayout(controls_layout)
        
        # Output
        self.trace_output = QTextEdit()
        self.trace_output.setReadOnly(True)
        layout.addWidget(self.trace_output)

    def init_dns_tab(self):
        layout = QVBoxLayout(self.dns_tab)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Host:"))
        self.dns_host_input = QLineEdit()
        self.dns_host_input.setPlaceholderText("e.g., google.com")
        controls_layout.addWidget(self.dns_host_input)
        
        controls_layout.addWidget(QLabel("Type:"))
        self.dns_type_input = QComboBox()
        self.dns_type_input.addItems(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
        controls_layout.addWidget(self.dns_type_input)
        
        self.dns_btn = QPushButton("Lookup")
        self.dns_btn.clicked.connect(self.start_dns)
        controls_layout.addWidget(self.dns_btn)
        
        layout.addLayout(controls_layout)
        
        # Output
        self.dns_output = QTextEdit()
        self.dns_output.setReadOnly(True)
        layout.addWidget(self.dns_output)

    def start_ping(self):
        host = self.ping_host_input.text().strip()
        if not host:
            self.ping_output.append("Please enter a host.")
            return
            
        count = self.ping_count_input.value()
        self.ping_output.clear()
        self.ping_output.append(f"Pinging {host}...")
        self.ping_btn.setEnabled(False)
        
        self.worker = DiagnosticsWorker(self.dm.run_ping, host, count)
        self.worker.output_signal.connect(self.ping_output.append)
        self.worker.finished_signal.connect(lambda: self.ping_btn.setEnabled(True))
        self.worker.start()

    def start_traceroute(self):
        host = self.trace_host_input.text().strip()
        if not host:
            self.trace_output.append("Please enter a host.")
            return
            
        self.trace_output.clear()
        self.trace_output.append(f"Tracing route to {host}...")
        self.trace_btn.setEnabled(False)
        
        self.worker = DiagnosticsWorker(self.dm.run_traceroute, host)
        self.worker.output_signal.connect(self.trace_output.append)
        self.worker.finished_signal.connect(lambda: self.trace_btn.setEnabled(True))
        self.worker.start()

    def start_dns(self):
        host = self.dns_host_input.text().strip()
        if not host:
            self.dns_output.append("Please enter a host.")
            return
            
        query_type = self.dns_type_input.currentText()
        self.dns_output.clear()
        self.dns_output.append(f"Looking up {query_type} records for {host}...")
        self.dns_btn.setEnabled(False)
        
        self.worker = DiagnosticsWorker(self.dm.run_dns_lookup, host, query_type)
        self.worker.output_signal.connect(self.dns_output.append)
        self.worker.finished_signal.connect(lambda: self.dns_btn.setEnabled(True))
        self.worker.start()
