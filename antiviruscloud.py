import os
import sys
import hashlib
import mimetypes
import requests
import time
import re
import logging

# Windows API for monitoring
import win32file
import win32con

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QListWidget, QLabel, QMessageBox, QHBoxLayout, QProgressBar, QGroupBox, QGridLayout
)
from PySide6.QtCore import QThread, Signal, Qt, QMutex, QWaitCondition
from PySide6.QtGui import QMovie

# For desktop notifications
from notifypy import Notify

# ----------------- Antivirus Style Sheet -----------------
antivirus_style = """
QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
    font-family: Arial, sans-serif;
    font-size: 14px;
}

QPushButton {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #007bff, stop:0.8 #0056b3);
    color: white;
    border: 2px solid #007bff;
    padding: 4px 10px;
    border-radius: 8px;
    min-width: 70px;
    font-weight: bold;
    text-align: center;
    qproperty-iconSize: 16px;
}

QPushButton:hover {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #0056b3, stop:0.8 #004380);
    border-color: #0056b3;
}

QPushButton:pressed {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #004380, stop:0.8 #003d75);
    border-color: #004380;
}

QLabel {
    color: #e0e0e0;
}

QFileDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}

QListWidget {
    background-color: #3c3c3c;
    color: #e0e0e0;
    border: 1px solid #5a5a5a;
}

QListWidget::item {
    padding: 4px;
}

QListWidget::item:selected {
    background-color: #007bff;
    color: white;
}

QProgressBar {
    background-color: #3c3c3c;
    border: 1px solid #5a5a5a;
    text-align: center;
}

QDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}

QDialogButtonBox {
    background-color: #2b2b2b;
}
"""

# ----------------- Helper Functions -----------------
def calculate_file_hash(file_path):
    """
    Returns the MD5 hash (as a hex string) and the file content.
    If the file is empty, returns None for the hash.
    """
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            if len(file_data) == 0:
                return None, file_data
            return hashlib.md5(file_data).hexdigest(), file_data
    except Exception:
        return None, None

def query_md5_online_sync(md5_hash):
    """
    Queries an online database using the file's MD5 hash.
    Risk Level (%)    Description
        0             file is clean
        10            file is clean (auto verdict)
        70            malware suspicion
        100           malware
    Reference: https://api.nictasoft.com/api-file-20.php
    """
    try:
        md5_hash_upper = md5_hash.upper()
        url = f"https://www.nictasoft.com/ace/md5/{md5_hash_upper}"
        response = requests.get(url)

        if response.status_code == 200:
            result = response.text.strip().lower()

            # Malware Check (exact match)
            if "[100% risk] malware" in result:
                return "Malware"

            # Safe Check (exact match)
            if "[0% risk] safe" in result:
                return "Benign"

            # Safe Check (auto verdict)
            if "[0% risk] safe" in result:
                return "Benign (auto verdict)"

            # Suspicious Check
            if "[70% risk] safe" in result:
                return "Suspicious"

            # Unknown Check
            if "this file is not yet rated" in result:
                return "Unknown"

            # Default Case
            return "Unknown (Result)"
        else:
            return "Unknown (API error)"

    except Exception as ex:
        return f"Error: {ex}"

def local_analysis(file_path, file_data):
    """
    Performs a local analysis of the file.
    Returns a string with the file name and type.
    """
    try:
        file_name = os.path.basename(file_path)
        file_type, _ = mimetypes.guess_type(file_path)
        return f"Name: {file_name} | Type: {file_type if file_type else 'Unknown'}"
    except Exception as e:
        return f"Local analysis error: {e}"

def notify_user(file_path, virus_name=""):
    """
    Sends a desktop notification for a malware detection.
    If virus_name is empty, it is not included in the message.
    """
    notification = Notify()
    notification.title = "Malware Alert"
    if virus_name:
        notification.message = f"Malicious file detected:\n{file_path}\nVirus: {virus_name}"
    else:
        notification.message = f"Malicious file detected:\n{file_path}"
    notification.send()

def scan_and_remove_warn(file_path):
    """
    Scans the file and auto-removes it if malware is detected.
    Returns a tuple (is_malware, virus_name).
    For demonstration, any file with '.mal' in its name is considered malicious.
    """
    if ".mal" in file_path.lower():
        try:
            os.remove(file_path)
            logging.info(f"Malicious file removed: {file_path}")
        except Exception as e:
            logging.error(f"Failed to remove {file_path}: {e}")
        return (True, "ExampleVirus")
    return (False, "")

# ----------------- Worker Thread for Scanning -----------------
class ScanWorker(QThread):
    # Signals for each file category:
    file_malicious = Signal(str)
    file_clean = Signal(str)
    file_unknown = Signal(str)
    file_suspicious = Signal(str)
    progress_update = Signal(int)
    current_file = Signal(str)
    scanned_count = Signal(int, int)
    scan_complete_counts = Signal(int, int, int, int)
    scan_finished = Signal()

    def __init__(self, folder_path):
        super().__init__()
        self.folder_path = folder_path
        self._is_stopped = False
        self._paused = False
        self.mutex = QMutex()
        self.pause_condition = QWaitCondition()

    def run(self):
        total_files = 0
        for root, _, files in os.walk(self.folder_path):
            total_files += len(files)
        if total_files == 0:
            self.scan_complete_counts.emit(0, 0, 0, 0)
            self.scanned_count.emit(0, 0)
            self.scan_finished.emit()
            return

        clean_count = 0
        malicious_count = 0
        unknown_count = 0
        suspicious_count = 0
        scanned_files = 0

        for root, _, files in os.walk(self.folder_path):
            for file in files:
                # Check for pause
                self.mutex.lock()
                while self._paused:
                    self.pause_condition.wait(self.mutex)
                self.mutex.unlock()

                if self._is_stopped:
                    break

                file_path = os.path.join(root, file)
                file_hash, file_data = calculate_file_hash(file_path)
                if file_hash is None:
                    clean_count += 1
                    message = f"Clean File (Empty): {file_path}"
                    self.file_clean.emit(message)
                    scanned_files += 1
                    self.scanned_count.emit(scanned_files, total_files)
                    self.progress_update.emit(int((scanned_files / total_files) * 100))
                    continue

                risk_result = query_md5_online_sync(file_hash)
                self.current_file.emit(f"{file_path} -> {risk_result}")

                local_info = local_analysis(file_path, file_data)
                if risk_result.startswith("Benign"):
                    clean_count += 1
                    message = (
                        f"Clean File Detected:\n"
                        f"Path: {file_path}\n"
                        f"MD5: {file_hash}\n"
                        f"{local_info}\n"
                        f"Status: {risk_result}\n"
                        f"{'-'*50}"
                    )
                    self.file_clean.emit(message)
                elif risk_result.startswith("Malware"):
                    malicious_count += 1
                    message = (
                        f"Malicious File Detected:\n"
                        f"Path: {file_path}\n"
                        f"MD5: {file_hash}\n"
                        f"{local_info}\n"
                        f"Status: {risk_result}\n"
                        f"{'-'*50}"
                    )
                    self.file_malicious.emit(message)
                elif risk_result.startswith("Suspicious"):
                    suspicious_count += 1
                    message = (
                        f"Suspicious File Detected:\n"
                        f"Path: {file_path}\n"
                        f"MD5: {file_hash}\n"
                        f"{local_info}\n"
                        f"Status: {risk_result}\n"
                        f"{'-'*50}"
                    )
                    self.file_suspicious.emit(message)
                else:
                    unknown_count += 1
                    message = (
                        f"Unknown File Detected:\n"
                        f"Path: {file_path}\n"
                        f"MD5: {file_hash}\n"
                        f"{local_info}\n"
                        f"Status: {risk_result}\n"
                        f"{'-'*50}"
                    )
                    self.file_unknown.emit(message)

                scanned_files += 1
                self.scanned_count.emit(scanned_files, total_files)
                self.progress_update.emit(int((scanned_files / total_files) * 100))
            if self._is_stopped:
                break

        self.scan_complete_counts.emit(unknown_count, malicious_count, clean_count, suspicious_count)
        self.scan_finished.emit()

    def stop(self):
        self._is_stopped = True
        self.resume()  # In case it is paused

    def pause(self):
        self.mutex.lock()
        self._paused = True
        self.mutex.unlock()

    def resume(self):
        self.mutex.lock()
        self._paused = False
        self.pause_condition.wakeAll()
        self.mutex.unlock()

# ----------------- Real-Time Monitoring Thread -----------------
class MonitorThread(QThread):
    """
    Monitors a directory for changes using Windows API.
    When a file is modified or created, it scans the file.
    If malware is detected (and auto-removed), it emits a signal.
    """
    malware_detected = Signal(str, str)  # file_path, virus_name

    def __init__(self, monitor_folder):
        super().__init__()
        self.monitor_folder = monitor_folder
        self._stopped = False

    def run(self):
        if not os.path.exists(self.monitor_folder):
            logging.error(f"The monitor folder path does not exist: {self.monitor_folder}")
            return

        hDir = win32file.CreateFile(
            self.monitor_folder,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        try:
            while not self._stopped:
                results = win32file.ReadDirectoryChangesW(
                    hDir,
                    1024,
                    True,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )
                for action, file in results:
                    pathToScan = os.path.join(self.monitor_folder, file)
                    if os.path.exists(pathToScan):
                        logging.info(f"Real-time detected change: {pathToScan}")
                        is_malware, virus_name = scan_and_remove_warn(pathToScan)
                        if is_malware:
                            self.malware_detected.emit(pathToScan, virus_name)
                    else:
                        logging.warning(f"File or folder not found: {pathToScan}")
        except Exception as ex:
            logging.error(f"An error occurred in MonitorThread: {ex}")
        finally:
            win32file.CloseHandle(hDir)

    def stop(self):
        self._stopped = True

# ----------------- Main Application Window -----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional Antivirus Cloud Scanner")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Top control buttons.
        top_button_layout = QHBoxLayout()
        self.select_folder_button = QPushButton("Select Folder")
        self.select_folder_button.clicked.connect(self.select_folder)
        top_button_layout.addWidget(self.select_folder_button)

        self.start_scan_button = QPushButton("Start Scan")
        self.start_scan_button.clicked.connect(self.start_scan)
        self.start_scan_button.setEnabled(False)
        top_button_layout.addWidget(self.start_scan_button)

        self.pause_scan_button = QPushButton("Pause Scan")
        self.pause_scan_button.clicked.connect(self.pause_scan)
        self.pause_scan_button.setEnabled(False)
        top_button_layout.addWidget(self.pause_scan_button)

        self.resume_scan_button = QPushButton("Resume Scan")
        self.resume_scan_button.clicked.connect(self.resume_scan)
        self.resume_scan_button.setEnabled(False)
        top_button_layout.addWidget(self.resume_scan_button)

        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.stop_scan_button.setEnabled(False)
        top_button_layout.addWidget(self.stop_scan_button)
        
        self.remove_virus_button = QPushButton("Remove Viruses")
        self.remove_virus_button.clicked.connect(self.remove_virus_files)
        self.remove_virus_button.setEnabled(False)
        top_button_layout.addWidget(self.remove_virus_button)
        
        # New toggle button for real-time monitoring.
        self.monitor_button = QPushButton("Start Monitoring")
        self.monitor_button.setCheckable(True)
        self.monitor_button.clicked.connect(self.toggle_monitoring)
        top_button_layout.addWidget(self.monitor_button)

        self.main_layout.addLayout(top_button_layout)

        # Folder label.
        self.folder_label = QLabel("Selected Folder: None")
        self.main_layout.addWidget(self.folder_label)

        # Current file label.
        self.current_file_label = QLabel("Current File: N/A")
        self.main_layout.addWidget(self.current_file_label)

        # Scanned file count label.
        self.scanned_count_label = QLabel("Scanned: 0 / 0")
        self.main_layout.addWidget(self.scanned_count_label)

        # Scanning animation.
        self.animation_label = QLabel(alignment=Qt.AlignCenter)
        try:
            self.movie = QMovie("assets\\spinner.gif")
            if self.movie.isValid():
                self.animation_label.setMovie(self.movie)
            else:
                self.animation_label.setText("Scanning...")
        except Exception:
            self.animation_label.setText("Scanning...")
        self.animation_label.hide()
        self.main_layout.addWidget(self.animation_label)

        # Progress bar.
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.main_layout.addWidget(self.progress_bar)

        # Group box with four lists: Malicious, Clean, Suspicious, Unknown.
        self.result_group = QGroupBox("Scan Results")
        self.result_layout = QGridLayout()
        self.result_group.setLayout(self.result_layout)
        self.main_layout.addWidget(self.result_group)

        self.malicious_list = QListWidget()
        self.result_layout.addWidget(QLabel("Malicious Files"), 0, 0)
        self.result_layout.addWidget(self.malicious_list, 1, 0)

        self.clean_list = QListWidget()
        self.result_layout.addWidget(QLabel("Clean Files"), 0, 1)
        self.result_layout.addWidget(self.clean_list, 1, 1)

        self.suspicious_list = QListWidget()
        self.result_layout.addWidget(QLabel("Suspicious Files"), 0, 2)
        self.result_layout.addWidget(self.suspicious_list, 1, 2)

        self.unknown_list = QListWidget()
        self.result_layout.addWidget(QLabel("Unknown Files"), 0, 3)
        self.result_layout.addWidget(self.unknown_list, 1, 3)

        # Live summary label.
        self.summary_label = QLabel("")
        self.main_layout.addWidget(self.summary_label)

        # Totals group.
        self.totals_group = QGroupBox("Totals")
        totals_layout = QHBoxLayout()
        self.label_total_scanned = QLabel("Total Scanned: 0")
        self.label_total_malicious = QLabel("Malicious: 0")
        self.label_total_clean = QLabel("Clean: 0")
        self.label_total_suspicious = QLabel("Suspicious: 0")
        self.label_total_unknown = QLabel("Unknown: 0")
        totals_layout.addWidget(self.label_total_scanned)
        totals_layout.addWidget(self.label_total_malicious)
        totals_layout.addWidget(self.label_total_clean)
        totals_layout.addWidget(self.label_total_suspicious)
        totals_layout.addWidget(self.label_total_unknown)
        self.totals_group.setLayout(totals_layout)
        self.main_layout.addWidget(self.totals_group)

        # Initialize counters.
        self.count_malicious = 0
        self.count_clean = 0
        self.count_unknown = 0
        self.count_suspicious = 0
        self.total_scanned = 0

        # List to store malicious file paths.
        self.malicious_files = []

        self.scan_worker = None
        self.monitor_thread = None
        self.selected_folder = None

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.selected_folder = folder
            self.folder_label.setText(f"Selected Folder: {folder}")
            self.start_scan_button.setEnabled(True)
            self.malicious_list.clear()
            self.clean_list.clear()
            self.suspicious_list.clear()
            self.unknown_list.clear()
            self.progress_bar.setValue(0)
            self.current_file_label.setText("Current File: N/A")
            self.scanned_count_label.setText("Scanned: 0 / 0")
            self.summary_label.setText("")
            self.count_malicious = 0
            self.count_clean = 0
            self.count_unknown = 0
            self.count_suspicious = 0
            self.total_scanned = 0
            self.malicious_files = []
            self.update_totals()
            self.remove_virus_button.setEnabled(False)
            self.log("Folder selected: " + folder)

    def start_scan(self):
        if not self.selected_folder:
            QMessageBox.warning(self, "No Folder Selected", "Please select a folder first.")
            return

        self.malicious_list.clear()
        self.clean_list.clear()
        self.suspicious_list.clear()
        self.unknown_list.clear()
        self.progress_bar.setValue(0)
        self.current_file_label.setText("Current File: N/A")
        self.scanned_count_label.setText("Scanned: 0 / 0")
        self.summary_label.setText("")
        self.animation_label.show()
        if hasattr(self, "movie") and self.movie.isValid():
            self.movie.start()

        self.scan_worker = ScanWorker(self.selected_folder)
        self.scan_worker.file_malicious.connect(self.update_malicious)
        self.scan_worker.file_clean.connect(self.update_clean)
        self.scan_worker.file_unknown.connect(self.update_unknown)
        self.scan_worker.file_suspicious.connect(self.update_suspicious)
        self.scan_worker.progress_update.connect(self.progress_bar.setValue)
        self.scan_worker.current_file.connect(self.update_current_file)
        self.scan_worker.scanned_count.connect(self.update_scanned_count)
        self.scan_worker.scan_complete_counts.connect(self.update_summary)
        self.scan_worker.scan_finished.connect(self.scan_complete)

        self.start_scan_button.setEnabled(False)
        self.select_folder_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        self.pause_scan_button.setEnabled(True)
        self.resume_scan_button.setEnabled(False)
        self.remove_virus_button.setEnabled(False)

        self.scan_worker.start()
        self.log("Scan started...")

    def pause_scan(self):
        if self.scan_worker:
            self.scan_worker.pause()
            self.current_file_label.setText("Current File: Paused...")
            self.pause_scan_button.setEnabled(False)
            self.resume_scan_button.setEnabled(True)
            self.log("Scan paused.")

    def resume_scan(self):
        if self.scan_worker:
            self.scan_worker.resume()
            self.current_file_label.setText("Current File: Resumed")
            self.pause_scan_button.setEnabled(True)
            self.resume_scan_button.setEnabled(False)
            self.log("Scan resumed.")

    def stop_scan(self):
        if self.scan_worker is not None:
            self.scan_worker.stop()
            self.stop_scan_button.setEnabled(False)
            self.pause_scan_button.setEnabled(False)
            self.resume_scan_button.setEnabled(False)
            self.current_file_label.setText("Current File: Stopping...")
            self.log("Scan stopping...")

    def update_malicious(self, message):
        self.count_malicious += 1
        self.malicious_list.addItem(message)
        self.malicious_list.scrollToBottom()
        self.update_live_summary()
        # Extract file path from the message.
        for line in message.splitlines():
            if line.startswith("Path: "):
                file_path = line.replace("Path: ", "").strip()
                self.malicious_files.append(file_path)
                break

    def update_clean(self, message):
        self.count_clean += 1
        self.clean_list.addItem(message)
        self.clean_list.scrollToBottom()
        self.update_live_summary()

    def update_unknown(self, message):
        self.count_unknown += 1
        self.unknown_list.addItem(message)
        self.unknown_list.scrollToBottom()
        self.update_live_summary()

    def update_suspicious(self, message):
        self.count_suspicious += 1
        self.suspicious_list.addItem(message)
        self.suspicious_list.scrollToBottom()
        self.update_live_summary()

    def update_live_summary(self):
        live_summary = (
            f"Live Scan Summary: Malicious: {self.count_malicious}, "
            f"Clean: {self.count_clean}, Suspicious: {self.count_suspicious}, "
            f"Unknown: {self.count_unknown}"
        )
        self.summary_label.setText(live_summary)
        self.update_totals()

    def update_totals(self):
        self.label_total_malicious.setText(f"Malicious: {self.count_malicious}")
        self.label_total_clean.setText(f"Clean: {self.count_clean}")
        self.label_total_suspicious.setText(f"Suspicious: {self.count_suspicious}")
        self.label_total_unknown.setText(f"Unknown: {self.count_unknown}")
        self.label_total_scanned.setText(f"Total Scanned: {self.total_scanned}")

    def update_current_file(self, status):
        self.current_file_label.setText(f"Current File: {status}")

    def update_scanned_count(self, scanned, total):
        self.total_scanned = scanned
        self.scanned_count_label.setText(f"Scanned: {scanned} / {total}")
        self.update_totals()

    def update_summary(self, unknown_count, malicious_count, clean_count, suspicious_count):
        final_summary = (
            f"Final Scan Summary: Malicious: {malicious_count}, Clean: {clean_count}, "
            f"Suspicious: {suspicious_count}, Unknown: {unknown_count}"
        )
        self.summary_label.setText(final_summary)
        self.count_malicious = malicious_count
        self.count_clean = clean_count
        self.count_unknown = unknown_count
        self.count_suspicious = suspicious_count
        self.update_totals()

    def scan_complete(self):
        self.current_file_label.setText("Current File: N/A")
        self.progress_bar.setValue(100)
        self.animation_label.hide()
        if hasattr(self, "movie") and self.movie.isValid():
            self.movie.stop()
        if self.malicious_files:
            self.remove_virus_button.setEnabled(True)
        self.start_scan_button.setEnabled(True)
        self.select_folder_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)
        self.pause_scan_button.setEnabled(False)
        self.resume_scan_button.setEnabled(False)
        if self.scan_worker._is_stopped:
            self.summary_label.setText(self.summary_label.text() + " (Scan Aborted)")
        self.malicious_list.addItem("Scan complete!")
        self.clean_list.addItem("Scan complete!")
        self.suspicious_list.addItem("Scan complete!")
        self.unknown_list.addItem("Scan complete!")
        self.log("Scan complete.")

    def remove_virus_files(self):
        if not self.malicious_files:
            QMessageBox.information(self, "No Viruses Found", "No malicious files to remove.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to permanently remove {len(self.malicious_files)} malicious file(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            errors = []
            for file_path in self.malicious_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        errors.append(f"File not found: {file_path}")
                except Exception as e:
                    errors.append(f"Error removing {file_path}: {e}")

            if errors:
                QMessageBox.warning(self, "Removal Errors", "\n".join(errors))
            else:
                QMessageBox.information(self, "Removal Successful", "All malicious files have been removed.")
            self.malicious_list.addItem("Removal process complete.")
            self.remove_virus_button.setEnabled(False)
            self.malicious_files = []
            self.log("Virus removal executed.")

    def toggle_monitoring(self):
        if self.monitor_button.isChecked():
            if not self.selected_folder:
                QMessageBox.warning(self, "No Folder Selected", "Please select a folder first.")
                self.monitor_button.setChecked(False)
                return
            self.log("Starting real-time monitoring...")
            self.monitor_thread = MonitorThread(self.selected_folder)
            self.monitor_thread.malware_detected.connect(self.on_malware_detected)
            self.monitor_thread.start()
            self.monitor_button.setText("Stop Monitoring")
        else:
            if self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread.wait()
                self.monitor_thread = None
            self.log("Real-time monitoring stopped.")
            self.monitor_button.setText("Start Monitoring")

    def on_malware_detected(self, file_path, virus_name):
        message = f"Malicious file auto-removed: {file_path}"
        if virus_name:
            message += f" (Virus: {virus_name})"
        self.malicious_list.addItem(message)
        self.malicious_list.scrollToBottom()
        notify_user(file_path, virus_name)
        self.log("Real-time malware detection: " + message)

    def log(self, message):
        # Helper function to log messages (could be extended to a dedicated log widget)
        print(message)
        logging.info(message)

# ----------------- Main Execution -----------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    window = MainWindow()
    window.resize(1200, 750)
    window.show()
    sys.exit(app.exec())
