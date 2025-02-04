import os
import sys
import hashlib
import mimetypes
import requests
import time
import re

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QListWidget, QLabel, QMessageBox, QHBoxLayout, QProgressBar, QGroupBox, QGridLayout
)
from PySide6.QtCore import QThread, Signal, Qt, QMutex, QWaitCondition
from PySide6.QtGui import QMovie

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

    Risk Level (%)	Description
        0	file is clean
        10	file is clean (auto verdict)
        70	malware suspicion
        100	malware
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

# ----------------- Worker Thread -----------------
class ScanWorker(QThread):
    # Signals for each file category:
    file_malicious = Signal(str)
    file_clean = Signal(str)
    file_unknown = Signal(str)
    file_suspicious = Signal(str)
    # Updates for progress bar (0-100)
    progress_update = Signal(int)
    # Emits the current file path with its risk status.
    current_file = Signal(str)
    # Emits scanned file count: (scanned, total)
    scanned_count = Signal(int, int)
    # Emits final counts when scan is complete: unknown, malicious, clean, suspicious.
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

        # Emit final counts: unknown, malicious, clean, suspicious.
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

# ----------------- Main Application Window -----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional Antivirus Cloud Scanner")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Top layout: Folder selection and scan control buttons.
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

        self.main_layout.addLayout(top_button_layout)

        # Label to show selected folder.
        self.folder_label = QLabel("Selected Folder: None")
        self.main_layout.addWidget(self.folder_label)

        # Label to show the current file being scanned.
        self.current_file_label = QLabel("Current File: N/A")
        self.main_layout.addWidget(self.current_file_label)

        # Label to show scanned file count.
        self.scanned_count_label = QLabel("Scanned: 0 / 0")
        self.main_layout.addWidget(self.scanned_count_label)

        # Scanning animation (spinner).
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

        # Group box to hold four lists: Malicious, Clean, Suspicious, Unknown.
        self.result_group = QGroupBox("Scan Results")
        self.result_layout = QGridLayout()
        self.result_group.setLayout(self.result_layout)
        self.main_layout.addWidget(self.result_group)

        # Malicious Files List.
        self.malicious_list = QListWidget()
        self.result_layout.addWidget(QLabel("Malicious Files"), 0, 0)
        self.result_layout.addWidget(self.malicious_list, 1, 0)

        # Clean Files List.
        self.clean_list = QListWidget()
        self.result_layout.addWidget(QLabel("Clean Files"), 0, 1)
        self.result_layout.addWidget(self.clean_list, 1, 1)

        # Suspicious Files List.
        self.suspicious_list = QListWidget()
        self.result_layout.addWidget(QLabel("Suspicious Files"), 0, 2)
        self.result_layout.addWidget(self.suspicious_list, 1, 2)

        # Unknown Files List.
        self.unknown_list = QListWidget()
        self.result_layout.addWidget(QLabel("Unknown Files"), 0, 3)
        self.result_layout.addWidget(self.unknown_list, 1, 3)

        # Label to display the live scan summary.
        self.summary_label = QLabel("")
        self.main_layout.addWidget(self.summary_label)

        # Totals Group: to show live total numbers in separate labels.
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

        # Initialize live counters.
        self.count_malicious = 0
        self.count_clean = 0
        self.count_unknown = 0
        self.count_suspicious = 0
        self.total_scanned = 0

        self.scan_worker = None
        self.selected_folder = None

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.selected_folder = folder
            self.folder_label.setText(f"Selected Folder: {folder}")
            self.start_scan_button.setEnabled(True)
            # Clear previous results.
            self.malicious_list.clear()
            self.clean_list.clear()
            self.suspicious_list.clear()
            self.unknown_list.clear()
            self.progress_bar.setValue(0)
            self.current_file_label.setText("Current File: N/A")
            self.scanned_count_label.setText("Scanned: 0 / 0")
            self.summary_label.setText("")
            # Reset live counters.
            self.count_malicious = 0
            self.count_clean = 0
            self.count_unknown = 0
            self.count_suspicious = 0
            self.total_scanned = 0
            self.update_totals()

    def start_scan(self):
        if not self.selected_folder:
            QMessageBox.warning(self, "No Folder Selected", "Please select a folder first.")
            return

        # Clear previous results and start the animation.
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

        # Create and connect the worker.
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

        # Adjust button states.
        self.start_scan_button.setEnabled(False)
        self.select_folder_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        self.pause_scan_button.setEnabled(True)
        self.resume_scan_button.setEnabled(False)

        self.scan_worker.start()

    def pause_scan(self):
        if self.scan_worker:
            self.scan_worker.pause()
            self.current_file_label.setText("Current File: Paused...")
            self.pause_scan_button.setEnabled(False)
            self.resume_scan_button.setEnabled(True)

    def resume_scan(self):
        if self.scan_worker:
            self.scan_worker.resume()
            self.current_file_label.setText("Current File: Resumed")
            self.pause_scan_button.setEnabled(True)
            self.resume_scan_button.setEnabled(False)

    def stop_scan(self):
        if self.scan_worker is not None:
            self.scan_worker.stop()
            self.stop_scan_button.setEnabled(False)
            self.pause_scan_button.setEnabled(False)
            self.resume_scan_button.setEnabled(False)
            self.current_file_label.setText("Current File: Stopping...")

    def update_malicious(self, message):
        self.count_malicious += 1
        self.malicious_list.addItem(message)
        self.malicious_list.scrollToBottom()
        self.update_live_summary()

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
        # Update totals one last time.
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

        # Reset button states.
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

# ----------------- Main Execution -----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    window = MainWindow()
    window.resize(1200, 750)
    window.show()
    sys.exit(app.exec())
