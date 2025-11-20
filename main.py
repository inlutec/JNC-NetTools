import sys
import os
from PyQt6.QtWidgets import QApplication
from src.gui.main_window import MainWindow
from src.gui.styles import apply_styles

def main():
    # Check for root privileges
    if os.geteuid() != 0:
        print("This application requires root privileges to manage network interfaces.")
        print("Please run with sudo.")
        sys.exit(1)

    app = QApplication(sys.argv)
    
    # Apply premium styles
    apply_styles(app)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
