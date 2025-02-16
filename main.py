import os
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, QComboBox,
                             QCheckBox, QProgressBar, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

class CryptoThread(QThread):
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(bool, str)

    def __init__(self, operation, file_path, password, algorithm, key_size=256):
        super().__init__()
        self.operation = operation
        self.file_path = file_path
        self.password = password
        self.algorithm = algorithm
        self.key_size = key_size
        self.salt = get_random_bytes(32)
        self.iv = get_random_bytes(16)

    def derive_key(self, salt):
        return PBKDF2(self.password, salt, dkLen=self.key_size//8, count=1000000)

    def run(self):
        try:
            if self.operation == 'encrypt':
                self.encrypt_file()
            else:
                self.decrypt_file()
            self.operation_completed.emit(True, "")
        except Exception as e:
            self.operation_completed.emit(False, str(e))

    def encrypt_file(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()

        key = self.derive_key(self.salt)
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        output_path = self.file_path + '.enc'
        with open(output_path, 'wb') as f:
            f.write(self.salt)
            f.write(self.iv)
            f.write(encrypted_data)

    def decrypt_file(self):
        with open(self.file_path, 'rb') as f:
            salt = f.read(32)
            iv = f.read(16)
            encrypted_data = f.read()

        key = self.derive_key(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        output_path = os.path.splitext(self.file_path)[0]
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

class ImageCryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Image Cryptography Suite")
        self.setGeometry(100, 100, 600, 400)
        self.setup_ui()
        self.setup_menu()
        self.crypto_thread = None

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        self.tabs = QTabWidget()
        self.encrypt_tab = self.create_encrypt_tab()
        self.decrypt_tab = self.create_decrypt_tab()

        self.tabs.addTab(self.encrypt_tab, "Encrypt")
        self.tabs.addTab(self.decrypt_tab, "Decrypt")

        self.progress_bar = QProgressBar()
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        layout.addWidget(self.tabs)
        layout.addWidget(self.progress_bar)

    def create_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # File Selection
        file_layout = QHBoxLayout()
        self.encrypt_file_entry = QLineEdit()
        file_layout.addWidget(self.encrypt_file_entry)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(lambda: self.select_file(self.encrypt_file_entry))
        file_layout.addWidget(btn_browse)

        # Password Input
        pass_layout = QHBoxLayout()
        self.encrypt_password_entry = QLineEdit()
        self.encrypt_password_entry.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(self.encrypt_password_entry)
        self.show_password_check = QCheckBox("Show Password")
        self.show_password_check.stateChanged.connect(self.toggle_password_visibility)
        pass_layout.addWidget(self.show_password_check)

        # Algorithm Selection
        algo_layout = QHBoxLayout()
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["AES-128", "AES-192", "AES-256"])
        algo_layout.addWidget(QLabel("Algorithm:"))
        algo_layout.addWidget(self.algorithm_combo)

        # Encrypt Button
        btn_encrypt = QPushButton("Encrypt Image")
        btn_encrypt.clicked.connect(self.start_encryption)

        layout.addLayout(file_layout)
        layout.addLayout(pass_layout)
        layout.addLayout(algo_layout)
        layout.addWidget(btn_encrypt)
        return tab

    def create_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # File Selection
        file_layout = QHBoxLayout()
        self.decrypt_file_entry = QLineEdit()
        file_layout.addWidget(self.decrypt_file_entry)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(lambda: self.select_file(self.decrypt_file_entry))
        file_layout.addWidget(btn_browse)

        # Password Input
        pass_layout = QHBoxLayout()
        self.decrypt_password_entry = QLineEdit()
        self.decrypt_password_entry.setEchoMode(QLineEdit.Password)
        pass_layout.addWidget(self.decrypt_password_entry)

        # Decrypt Button
        btn_decrypt = QPushButton("Decrypt Image")
        btn_decrypt.clicked.connect(self.start_decryption)

        layout.addLayout(file_layout)
        layout.addLayout(pass_layout)
        layout.addWidget(btn_decrypt)
        return tab

    def setup_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        help_menu = menu.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)

    def select_file(self, entry_widget):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image File", "", 
                                                  "Image Files (*.png *.jpg *.jpeg *.bmp *.enc)")
        if file_path:
            entry_widget.setText(file_path)

    def toggle_password_visibility(self, state):
        if state == Qt.Checked:
            self.encrypt_password_entry.setEchoMode(QLineEdit.Normal)
            self.decrypt_password_entry.setEchoMode(QLineEdit.Normal)
        else:
            self.encrypt_password_entry.setEchoMode(QLineEdit.Password)
            self.decrypt_password_entry.setEchoMode(QLineEdit.Password)

    def validate_inputs(self, file_path, password):
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file!")
            return False
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password!")
            return False
        return True

    def start_encryption(self):
        file_path = self.encrypt_file_entry.text()
        password = self.encrypt_password_entry.text()
        algorithm = self.algorithm_combo.currentText()

        if not self.validate_inputs(file_path, password):
            return

        key_size = int(algorithm.split('-')[1])
        self.crypto_thread = CryptoThread('encrypt', file_path, password.encode(), algorithm, key_size)
        self.crypto_thread.operation_completed.connect(self.on_operation_complete)
        self.crypto_thread.start()

    def start_decryption(self):
        file_path = self.decrypt_file_entry.text()
        password = self.decrypt_password_entry.text()

        if not self.validate_inputs(file_path, password):
            return

        self.crypto_thread = CryptoThread('decrypt', file_path, password.encode(), 'AES')
        self.crypto_thread.operation_completed.connect(self.on_operation_complete)
        self.crypto_thread.start()

    def on_operation_complete(self, success, message):
        if success:
            QMessageBox.information(self, "Success", "Operation completed successfully!")
            self.status_bar.showMessage("Operation completed successfully!")
        else:
            QMessageBox.critical(self, "Error", f"Operation failed: {message}")
            self.status_bar.showMessage("Operation failed!")

    def show_about(self):
        QMessageBox.about(self, "About Image Cryptography Suite",
                         "Secure Image Encryption Tool\n\n"
                         "Features:\n"
                         "- AES Encryption (128/192/256-bit)\n"
                         "- PBKDF2 key derivation\n"
                         "- Secure password handling\n"
                         "- Cross-platform support")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ImageCryptoApp()
    window.show()
    sys.exit(app.exec_())
