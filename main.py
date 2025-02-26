import os
import sys
from PyQt5.QtWidgets import (QApplication,QLineEdit, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QListWidget, QPushButton, QFileDialog, QMessageBox, QComboBox,
                             QCheckBox, QProgressBar, QStatusBar, QGroupBox, QSpacerItem, QSizePolicy,
                             QAbstractItemView, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMimeData
from PyQt5.QtGui import QFont, QIcon, QDragEnterEvent, QDropEvent
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

APP_STYLE = """
/* ... (keep existing style sheet unchanged) ... */
"""

class FileListWidget(QListWidget):
    def __init__(self, mode='encrypt', parent=None):
        super().__init__(parent)
        self.mode = mode
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)
        self.setSelectionMode(QListWidget.ExtendedSelection)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        valid_extensions = ['.png', '.jpg', '.jpeg', '.bmp'] if self.mode == 'encrypt' else ['.enc']
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path) and os.path.splitext(file_path)[1].lower() in valid_extensions:
                self.addItem(file_path)
        event.acceptProposedAction()

class CryptoThread(QThread):
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(bool, list)

    def __init__(self, operation, file_paths, password, algorithm, key_size=256, 
                 delete_original=False, delete_encrypted=False):
        super().__init__()
        self.operation = operation
        self.file_paths = file_paths
        self.password = password
        self.algorithm = algorithm
        self.key_size = key_size
        self.delete_original = delete_original
        self.delete_encrypted = delete_encrypted
        self._is_running = True

    def stop(self):
        self._is_running = False

    def derive_key(self, salt):
        return PBKDF2(self.password, salt, dkLen=self.key_size//8, count=1000000)

    def run(self):
        errors = []
        total_files = len(self.file_paths)
        for idx, file_path in enumerate(self.file_paths):
            if not self._is_running:
                break
            try:
                if self.operation == 'encrypt':
                    self.encrypt_file(file_path)
                    if self.delete_original:
                        os.remove(file_path)
                else:
                    self.decrypt_file(file_path)
                    if self.delete_encrypted:
                        os.remove(file_path)
                self.progress_updated.emit(int((idx+1)/total_files*100))
            except Exception as e:
                errors.append(f"{file_path}: {str(e)}")
        self.operation_completed.emit(len(errors) == 0, errors)

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        salt = get_random_bytes(32)
        iv = get_random_bytes(16)
        key = self.derive_key(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        output_path = file_path + '.enc'
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(encrypted_data)

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            salt = f.read(32)
            iv = f.read(16)
            encrypted_data = f.read()

        key = self.derive_key(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        output_path = os.path.splitext(file_path)[0]
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

class ImageCryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureImage Cryptography Suite")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet(APP_STYLE)
        self.setup_ui()
        self.setup_menu()
        self.crypto_thread = None
        self.setWindowIcon(QIcon("icon.png"))

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("SecureImage Cryptography Suite")
        header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.encrypt_tab = self.create_encrypt_tab()
        self.decrypt_tab = self.create_decrypt_tab()
        self.tabs.addTab(self.encrypt_tab, "🔒 Encrypt")
        self.tabs.addTab(self.decrypt_tab, "🔓 Decrypt")
        layout.addWidget(self.tabs)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)

        # File Selection Group
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        self.encrypt_file_list = FileListWidget(mode='encrypt')
        self.encrypt_file_count = QLabel("0 files selected")
        
        btn_layout = QHBoxLayout()
        self.btn_add_encrypt = QPushButton("Add Files")
        self.btn_add_encrypt.clicked.connect(lambda: self.add_files(self.encrypt_file_list, True))
        self.btn_remove_encrypt = QPushButton("Remove Selected")
        self.btn_remove_encrypt.clicked.connect(lambda: self.remove_selected_files(self.encrypt_file_list))
        self.btn_clear_encrypt = QPushButton("Clear All")
        self.btn_clear_encrypt.clicked.connect(self.encrypt_file_list.clear)
        
        btn_layout.addWidget(self.btn_add_encrypt)
        btn_layout.addWidget(self.btn_remove_encrypt)
        btn_layout.addWidget(self.btn_clear_encrypt)
        
        file_layout.addWidget(self.encrypt_file_count)
        file_layout.addWidget(self.encrypt_file_list)
        file_layout.addLayout(btn_layout)
        self.encrypt_file_list.model().rowsInserted.connect(lambda: self.update_file_count(self.encrypt_file_list, self.encrypt_file_count))
        self.encrypt_file_list.model().rowsRemoved.connect(lambda: self.update_file_count(self.encrypt_file_list, self.encrypt_file_count))

        # Security Settings
        security_group = QGroupBox("Security Settings")
        security_layout = QVBoxLayout(security_group)
        
        # Password
        pass_layout = QHBoxLayout()
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setPlaceholderText("Encryption password...")
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        self.show_pass_check = QCheckBox("Show")
        self.show_pass_check.stateChanged.connect(self.toggle_password_visibility)
        pass_layout.addWidget(self.encrypt_password)
        pass_layout.addWidget(self.show_pass_check)

        # Algorithm
        algo_layout = QHBoxLayout()
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["AES-128", "AES-192", "AES-256"])
        algo_layout.addWidget(QLabel("Algorithm:"))
        algo_layout.addWidget(self.algorithm_combo)

        # Options
        self.delete_original_check = QCheckBox("Delete original files after encryption")
        
        security_layout.addLayout(pass_layout)
        security_layout.addLayout(algo_layout)
        security_layout.addWidget(self.delete_original_check)

        # Encrypt Button
        self.btn_encrypt = QPushButton("🔒 Start Encryption")
        self.btn_encrypt.clicked.connect(self.start_encryption)
        self.btn_encrypt.setStyleSheet("background-color: #4CAF50; color: white;")

        layout.addWidget(file_group)
        layout.addWidget(security_group)
        layout.addStretch()
        layout.addWidget(self.btn_encrypt)
        return tab

    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)

        # File Selection Group
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        self.decrypt_file_list = FileListWidget(mode='decrypt')
        self.decrypt_file_count = QLabel("0 files selected")
        
        btn_layout = QHBoxLayout()
        self.btn_add_decrypt = QPushButton("Add Files")
        self.btn_add_decrypt.clicked.connect(lambda: self.add_files(self.decrypt_file_list, False))
        self.btn_remove_decrypt = QPushButton("Remove Selected")
        self.btn_remove_decrypt.clicked.connect(lambda: self.remove_selected_files(self.decrypt_file_list))
        self.btn_clear_decrypt = QPushButton("Clear All")
        self.btn_clear_decrypt.clicked.connect(self.decrypt_file_list.clear)
        
        btn_layout.addWidget(self.btn_add_decrypt)
        btn_layout.addWidget(self.btn_remove_decrypt)
        btn_layout.addWidget(self.btn_clear_decrypt)
        
        file_layout.addWidget(self.decrypt_file_count)
        file_layout.addWidget(self.decrypt_file_list)
        file_layout.addLayout(btn_layout)
        self.decrypt_file_list.model().rowsInserted.connect(lambda: self.update_file_count(self.decrypt_file_list, self.decrypt_file_count))
        self.decrypt_file_list.model().rowsRemoved.connect(lambda: self.update_file_count(self.decrypt_file_list, self.decrypt_file_count))

        # Security Settings
        pass_group = QGroupBox("Security Settings")
        pass_layout = QVBoxLayout(pass_group)
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setPlaceholderText("Decryption password...")
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        self.delete_encrypted_check = QCheckBox("Delete encrypted files after decryption")
        pass_layout.addWidget(self.decrypt_password)
        pass_layout.addWidget(self.delete_encrypted_check)

        # Decrypt Button
        self.btn_decrypt = QPushButton("🔓 Start Decryption")
        self.btn_decrypt.clicked.connect(self.start_decryption)
        self.btn_decrypt.setStyleSheet("background-color: #2196F3; color: white;")

        layout.addWidget(file_group)
        layout.addWidget(pass_group)
        layout.addStretch()
        layout.addWidget(self.btn_decrypt)
        return tab

    def setup_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("📁 File")
        exit_action = file_menu.addAction("🚪 Exit")
        exit_action.triggered.connect(self.close)

        help_menu = menu.addMenu("❓ Help")
        about_action = help_menu.addAction("ℹ️ About")
        about_action.triggered.connect(self.show_about)

    def add_files(self, list_widget, is_encrypt):
        filter = "Images (*.png *.jpg *.jpeg *.bmp)" if is_encrypt else "Encrypted Files (*.enc)"
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", filter)
        if files:
            for f in files:
                if not list_widget.findItems(f, Qt.MatchExactly):
                    list_widget.addItem(f)

    def remove_selected_files(self, list_widget):
        for item in list_widget.selectedItems():
            list_widget.takeItem(list_widget.row(item))

    def update_file_count(self, list_widget, label):
        label.setText(f"{list_widget.count()} files selected")

    def toggle_password_visibility(self, state):
        mode = QLineEdit.Normal if state else QLineEdit.Password
        self.encrypt_password.setEchoMode(mode)
        self.decrypt_password.setEchoMode(mode)

    def validate_inputs(self, file_count, password):
        if file_count == 0:
            self.show_error("No files selected!", "Please select at least one file.")
            return False
        if not password:
            self.show_error("Password required!", "Please enter a valid password.")
            return False
        return True

    def start_encryption(self):
        file_paths = [self.encrypt_file_list.item(i).text() for i in range(self.encrypt_file_list.count())]
        password = self.encrypt_password.text()
        
        if not self.validate_inputs(len(file_paths), password):
            return

        algorithm = self.algorithm_combo.currentText()
        key_size = int(algorithm.split('-')[1])
        delete_original = self.delete_original_check.isChecked()

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.tabs.setEnabled(False)
        self.status_bar.showMessage(f"Encrypting {len(file_paths)} files...")

        self.crypto_thread = CryptoThread(
            'encrypt', file_paths, password.encode(), algorithm, key_size, delete_original)
        self.crypto_thread.progress_updated.connect(self.progress_bar.setValue)
        self.crypto_thread.operation_completed.connect(self.on_operation_complete)
        self.crypto_thread.start()

    def start_decryption(self):
        file_paths = [self.decrypt_file_list.item(i).text() for i in range(self.decrypt_file_list.count())]
        password = self.decrypt_password.text()
        
        if not self.validate_inputs(len(file_paths), password):
            return

        delete_encrypted = self.delete_encrypted_check.isChecked()

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.tabs.setEnabled(False)
        self.status_bar.showMessage(f"Decrypting {len(file_paths)} files...")

        self.crypto_thread = CryptoThread(
            'decrypt', file_paths, password.encode(), 'AES', delete_encrypted=delete_encrypted)
        self.crypto_thread.progress_updated.connect(self.progress_bar.setValue)
        self.crypto_thread.operation_completed.connect(self.on_operation_complete)
        self.crypto_thread.start()

    def on_operation_complete(self, success, errors):
        self.progress_bar.hide()
        self.tabs.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Success", "All files processed successfully!")
            self.status_bar.showMessage("Ready")
        else:
            error_msg = "\n".join([self.translate_error(e) for e in errors])
            self.show_error("Operation Failed", f"Encountered errors:\n{error_msg}")

    def translate_error(self, error):
        if "Padding" in error:
            return "Incorrect password or corrupted file detected"
        return error.split(':')[-1].strip()

    def show_error(self, title, message):
        QMessageBox.critical(self, title, message)

    def show_about(self):
        about_text = """<b>SecureImage Cryptography Suite v2.0</b><br><br>
        Enhanced features:<br>
        - Multi-file encryption/decryption<br>
        - Drag-and-drop support<br>
        - Progress tracking<br>
        - File management options<br><br>
        © 2025 SecureImage. All rights reserved."""
        QMessageBox.about(self, "About", about_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ImageCryptoApp()
    window.show()
    sys.exit(app.exec_())