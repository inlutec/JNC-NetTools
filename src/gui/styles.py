from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor

def apply_styles(app: QApplication):
    """Applies a premium dark theme to the application."""
    app.setStyle("Fusion")
    
    palette = QPalette()
    
    # Colors
    dark_bg = QColor(30, 30, 30)
    darker_bg = QColor(20, 20, 20)
    text_color = QColor(230, 230, 230)
    accent_color = QColor(0, 120, 215) # A nice blue
    accent_hover = QColor(0, 140, 240)
    disabled_text = QColor(127, 127, 127)
    
    palette.setColor(QPalette.ColorRole.Window, dark_bg)
    palette.setColor(QPalette.ColorRole.WindowText, text_color)
    palette.setColor(QPalette.ColorRole.Base, darker_bg)
    palette.setColor(QPalette.ColorRole.AlternateBase, dark_bg)
    palette.setColor(QPalette.ColorRole.ToolTipBase, text_color)
    palette.setColor(QPalette.ColorRole.ToolTipText, text_color)
    palette.setColor(QPalette.ColorRole.Text, text_color)
    palette.setColor(QPalette.ColorRole.Button, dark_bg)
    palette.setColor(QPalette.ColorRole.ButtonText, text_color)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, accent_color)
    palette.setColor(QPalette.ColorRole.Highlight, accent_color)
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    
    app.setPalette(palette)
    
    # Stylesheet for specific widgets to add that "premium" feel
    # Stylesheet for specific widgets to add that "premium" feel
    app.setStyleSheet("""
        QMainWindow {
            background-color: #181818;
        }
        QWidget {
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            font-size: 13px;
            color: #e0e0e0;
        }
        QTabWidget::pane {
            border: 1px solid #333333;
            background: #252526;
            border-radius: 4px;
            top: -1px; 
        }
        QTabBar::tab {
            background: #1e1e1e;
            color: #999999;
            padding: 10px 20px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
            font-weight: 600;
            border: 1px solid transparent;
        }
        QTabBar::tab:selected {
            background: #252526;
            color: #ffffff;
            border-top: 2px solid #007acc;
            border-bottom: 1px solid #252526; 
        }
        QTabBar::tab:hover {
            background: #2d2d2d;
            color: #ffffff;
        }
        QPushButton {
            background-color: #007acc;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #0062a3;
        }
        QPushButton:pressed {
            background-color: #004c80;
        }
        QPushButton:disabled {
            background-color: #333333;
            color: #666666;
        }
        QLineEdit, QComboBox, QSpinBox {
            background-color: #333333;
            border: 1px solid #444444;
            color: #f0f0f0;
            padding: 6px;
            border-radius: 3px;
        }
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
            border: 1px solid #007acc;
            background-color: #3c3c3c;
        }
        QTableWidget {
            background-color: #1e1e1e;
            border: 1px solid #333333;
            border-radius: 4px;
            gridline-color: #333333;
            selection-background-color: #264f78;
            selection-color: white;
            alternate-background-color: #252526;
        }
        QHeaderView::section {
            background-color: #252526;
            color: #cccccc;
            padding: 6px;
            border: none;
            border-right: 1px solid #333333;
            border-bottom: 1px solid #333333;
            font-weight: 600;
        }
        QListWidget {
            background-color: #1e1e1e;
            border: 1px solid #333333;
            border-radius: 4px;
        }
        QListWidget::item {
            padding: 8px;
            border-bottom: 1px solid #252526;
        }
        QListWidget::item:selected {
            background-color: #37373d;
            color: white;
            border-left: 2px solid #007acc;
        }
        QGroupBox {
            border: 1px solid #444444;
            border-radius: 6px;
            margin-top: 20px;
            padding-top: 15px;
            font-weight: 600;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 5px;
            color: #007acc;
            left: 10px;
        }
        QStatusBar {
            background-color: #007acc;
            color: white;
        }
        QProgressBar {
            border: 1px solid #444444;
            border-radius: 4px;
            text-align: center;
            background-color: #333333;
        }
        QProgressBar::chunk {
            background-color: #007acc;
            width: 10px;
        }
        QSplitter::handle {
            background-color: #333333;
        }
    """)

from PyQt6.QtCore import Qt
