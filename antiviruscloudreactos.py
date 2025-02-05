#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import hashlib
import mimetypes
import requests
import time
import re
import logging
import threading
import queue

import win32file
import win32con

# Use win10toast for notifications (compatible with Python 3.5)
from win10toast import ToastNotifier

# Tkinter imports for Python 3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

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
    Queries the online API and returns a risk string.
    The returned risk string is based on the online results.
    """
    try:
        md5_hash_upper = md5_hash.upper()
        url = "https://www.nictasoft.com/ace/md5/{}".format(md5_hash_upper)
        response = requests.get(url)

        if response.status_code == 200:
            result = response.text.strip()
            lower_result = result.lower()

            # Check for high-risk (malware) indication.
            if "[100% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return "Malware ({})".format(virus_name)
                else:
                    return "Malware"
            
            # Check for 70% risk which we treat as suspicious.
            if "[70% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return "Suspicious ({})".format(virus_name)
                else:
                    return "Suspicious"
            
            # Check safe statuses.
            if "[0% risk]" in lower_result:
                return "Benign"
            if "[10% risk]" in lower_result:
                return "Benign (auto verdict)"
            
            # Unknown status.
            if "this file is not yet rated" in lower_result:
                return "Unknown"
            
            # Default case.
            return "Unknown (Result)"
        else:
            return "Unknown (API error)"
    except Exception as ex:
        return "Error: {}".format(ex)

def local_analysis(file_path, file_data):
    """
    Performs a local analysis of the file.
    Returns a string with the file name and type.
    """
    try:
        file_name = os.path.basename(file_path)
        file_type, _ = mimetypes.guess_type(file_path)
        return "Name: {} | Type: {}".format(file_name, file_type if file_type else 'Unknown')
    except Exception as e:
        return "Local analysis error: {}".format(e)

def notify_user(file_path, virus_name=""):
    """
    Sends a desktop notification for a malware detection using win10toast.
    """
    toaster = ToastNotifier()
    title = "Malware Alert"
    if virus_name:
        message = "Malicious file quarantined:\n{}\nVirus: {}".format(file_path, virus_name)
    else:
        message = "Malicious file quarantined:\n{}".format(file_path)
    # duration is in seconds; adjust as needed.
    toaster.show_toast(title, message, duration=10)

# Quarantine folder path.
QUARANTINE_FOLDER = os.path.join(os.getcwd(), "quarantine")

def scan_and_quarantine(file_path):
    """
    Scans the file by calculating its MD5 hash and querying the cloud.
    If the risk level is Malware, the file is quarantined.
    Returns a tuple: (is_malware, status)
    """
    file_hash, file_data = calculate_file_hash(file_path)
    if not file_hash:
        return (False, "Clean (Empty file)")
    
    risk_result = query_md5_online_sync(file_hash)
    if risk_result.startswith("Benign") or risk_result.startswith("Suspicious") or risk_result.startswith("Unknown") or risk_result.startswith("Error"):
        return (False, risk_result)
    
    # If risk_result indicates Malware, then proceed with quarantine.
    if "Malware" in risk_result:
        if not os.path.exists(QUARANTINE_FOLDER):
            os.makedirs(QUARANTINE_FOLDER)
        base_name = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_FOLDER, base_name)
        try:
            shutil.move(file_path, quarantine_path)
            logging.info("Malicious file quarantined: {} -> {}".format(file_path, quarantine_path))
        except Exception as e:
            logging.error("Failed to quarantine {}: {}".format(file_path, e))
        return (True, risk_result)
    
    return (False, risk_result)

# ----------------- Worker Thread for Scanning -----------------
class ScanWorker(threading.Thread):
    """
    Worker thread to scan a folder.
    Communicates with the main thread via a thread-safe queue.
    """
    def __init__(self, folder_path, queue):
        threading.Thread.__init__(self)
        self.folder_path = folder_path
        self.queue = queue
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()  # When set, scanning is paused.

    def run(self):
        total_files = 0
        for root, _, files in os.walk(self.folder_path):
            total_files += len(files)
        if total_files == 0:
            self.queue.put({'type': 'scan_complete', 'data': (0, 0, 0, 0)})
            return

        clean_count = 0
        malicious_count = 0
        unknown_count = 0
        suspicious_count = 0
        scanned_files = 0

        for root, _, files in os.walk(self.folder_path):
            for file in files:
                if self.stop_event.is_set():
                    self.queue.put({'type': 'scan_aborted'})
                    return

                # Pause handling:
                while self.pause_event.is_set():
                    time.sleep(0.1)
                    if self.stop_event.is_set():
                        self.queue.put({'type': 'scan_aborted'})
                        return

                file_path = os.path.join(root, file)
                file_hash, file_data = calculate_file_hash(file_path)
                if file_hash is None:
                    clean_count += 1
                    message = "Clean File (Empty): {}".format(file_path)
                    self.queue.put({'type': 'update_clean', 'data': message})
                    scanned_files += 1
                    self.queue.put({'type': 'update_progress', 'data': (scanned_files, total_files)})
                    continue

                risk_result = query_md5_online_sync(file_hash)
                current_status = "{} -> {}".format(file_path, risk_result)
                self.queue.put({'type': 'current_file', 'data': current_status})
                local_info = local_analysis(file_path, file_data)

                if risk_result.startswith("Benign"):
                    clean_count += 1
                    message = ("Clean File Detected:\n"
                               "Path: {}\n"
                               "MD5: {}\n"
                               "{}\n"
                               "Status: {}\n"
                               "{}").format(file_path, file_hash, local_info, risk_result, "-" * 50)
                    self.queue.put({'type': 'update_clean', 'data': message})
                elif risk_result.startswith("Malware"):
                    malicious_count += 1
                    message = ("Malicious File Detected:\n"
                               "Path: {}\n"
                               "MD5: {}\n"
                               "{}\n"
                               "Status: {}\n"
                               "{}").format(file_path, file_hash, local_info, risk_result, "-" * 50)
                    self.queue.put({'type': 'update_malicious', 'data': message})
                elif risk_result.startswith("Suspicious"):
                    suspicious_count += 1
                    message = ("Suspicious File Detected:\n"
                               "Path: {}\n"
                               "MD5: {}\n"
                               "{}\n"
                               "Status: {}\n"
                               "{}").format(file_path, file_hash, local_info, risk_result, "-" * 50)
                    self.queue.put({'type': 'update_suspicious', 'data': message})
                else:
                    unknown_count += 1
                    message = ("Unknown File Detected:\n"
                               "Path: {}\n"
                               "MD5: {}\n"
                               "{}\n"
                               "Status: {}\n"
                               "{}").format(file_path, file_hash, local_info, risk_result, "-" * 50)
                    self.queue.put({'type': 'update_unknown', 'data': message})

                scanned_files += 1
                self.queue.put({'type': 'update_progress', 'data': (scanned_files, total_files)})
        # Send final counts.
        self.queue.put({'type': 'scan_complete', 'data': (unknown_count, malicious_count, clean_count, suspicious_count)})

    def pause(self):
        self.pause_event.set()

    def resume(self):
        self.pause_event.clear()

    def stop(self):
        self.stop_event.set()
        self.resume()  # In case we are paused, let the thread exit.

# ----------------- Real-Time Monitoring Thread -----------------
class MonitorThread(threading.Thread):
    """
    Monitors a directory for changes using Windows API.
    When a file is modified or created, it scans the file.
    """
    def __init__(self, monitor_folder, queue):
        threading.Thread.__init__(self)
        self.monitor_folder = monitor_folder
        self.queue = queue
        self.stop_event = threading.Event()

    def run(self):
        if not os.path.exists(self.monitor_folder):
            logging.error("The monitor folder path does not exist: {}".format(self.monitor_folder))
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
            while not self.stop_event.is_set():
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
                        logging.info("Real-time detected change: {}".format(pathToScan))
                        is_malware, risk_result = scan_and_quarantine(pathToScan)
                        if is_malware:
                            # Send a message to update the malicious list.
                            self.queue.put({'type': 'monitor_malware', 'data': (pathToScan, risk_result)})
                    else:
                        logging.warning("File or folder not found: {}".format(pathToScan))
        except Exception as ex:
            logging.error("An error occurred in MonitorThread: {}".format(ex))
        finally:
            win32file.CloseHandle(hDir)

    def stop(self):
        self.stop_event.set()

# ----------------- Main Application Window -----------------
class MainApplication(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Haci Murad Antivirus Cloud Scanner")
        self.geometry("1200x750")

        # Setup logging.
        logging.basicConfig(level=logging.INFO)

        # Create a thread-safe queue for inter-thread communication.
        self.queue = queue.Queue()

        # Initialize thread variables.
        self.scan_thread = None
        self.monitor_thread = None

        # Initialize counters.
        self.count_malicious = 0
        self.count_clean = 0
        self.count_unknown = 0
        self.count_suspicious = 0
        self.total_scanned = 0

        # List to store quarantined file paths.
        self.malicious_files = []

        self.selected_folder = None

        # --- Top Controls ---
        top_frame = tk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.select_folder_button = tk.Button(top_frame, text="Select Folder", command=self.select_folder)
        self.select_folder_button.pack(side=tk.LEFT, padx=2)

        self.start_scan_button = tk.Button(top_frame, text="Start Scan", command=self.start_scan, state=tk.DISABLED)
        self.start_scan_button.pack(side=tk.LEFT, padx=2)

        self.pause_scan_button = tk.Button(top_frame, text="Pause Scan", command=self.pause_scan, state=tk.DISABLED)
        self.pause_scan_button.pack(side=tk.LEFT, padx=2)

        self.resume_scan_button = tk.Button(top_frame, text="Resume Scan", command=self.resume_scan, state=tk.DISABLED)
        self.resume_scan_button.pack(side=tk.LEFT, padx=2)

        self.stop_scan_button = tk.Button(top_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_button.pack(side=tk.LEFT, padx=2)

        self.open_quarantine_button = tk.Button(top_frame, text="Open Quarantine", command=self.open_quarantine, state=tk.DISABLED)
        self.open_quarantine_button.pack(side=tk.LEFT, padx=2)

        self.monitoring = False
        self.monitor_button = tk.Button(top_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=2)

        # --- Folder and Status Labels ---
        status_frame = tk.Frame(self)
        status_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.folder_label = tk.Label(status_frame, text="Selected Folder: None")
        self.folder_label.pack(side=tk.TOP, anchor="w")

        self.current_file_label = tk.Label(status_frame, text="Current File: N/A")
        self.current_file_label.pack(side=tk.TOP, anchor="w")

        self.scanned_count_label = tk.Label(status_frame, text="Scanned: 0 / 0")
        self.scanned_count_label.pack(side=tk.TOP, anchor="w")

        # --- Progress Bar ---
        progress_frame = tk.Frame(self)
        progress_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=5)

        # --- Results Lists ---
        results_frame = tk.Frame(self)
        results_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create four listboxes for Malicious, Clean, Suspicious, Unknown.
        self.malicious_list = tk.Listbox(results_frame)
        self.clean_list = tk.Listbox(results_frame)
        self.suspicious_list = tk.Listbox(results_frame)
        self.unknown_list = tk.Listbox(results_frame)

        # Arrange them in a grid.
        tk.Label(results_frame, text="Malicious Files").grid(row=0, column=0)
        tk.Label(results_frame, text="Clean Files").grid(row=0, column=1)
        tk.Label(results_frame, text="Suspicious Files").grid(row=0, column=2)
        tk.Label(results_frame, text="Unknown Files").grid(row=0, column=3)

        self.malicious_list.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self.clean_list.grid(row=1, column=1, sticky="nsew", padx=2, pady=2)
        self.suspicious_list.grid(row=1, column=2, sticky="nsew", padx=2, pady=2)
        self.unknown_list.grid(row=1, column=3, sticky="nsew", padx=2, pady=2)

        # Make columns expand equally.
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_columnconfigure(1, weight=1)
        results_frame.grid_columnconfigure(2, weight=1)
        results_frame.grid_columnconfigure(3, weight=1)

        # --- Totals Summary ---
        totals_frame = tk.Frame(self)
        totals_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.total_scanned_label = tk.Label(totals_frame, text="Total Scanned: 0")
        self.total_scanned_label.pack(side=tk.LEFT, padx=2)
        self.total_malicious_label = tk.Label(totals_frame, text="Malicious: 0")
        self.total_malicious_label.pack(side=tk.LEFT, padx=2)
        self.total_clean_label = tk.Label(totals_frame, text="Clean: 0")
        self.total_clean_label.pack(side=tk.LEFT, padx=2)
        self.total_suspicious_label = tk.Label(totals_frame, text="Suspicious: 0")
        self.total_suspicious_label.pack(side=tk.LEFT, padx=2)
        self.total_unknown_label = tk.Label(totals_frame, text="Unknown: 0")
        self.total_unknown_label.pack(side=tk.LEFT, padx=2)

        # --- Start the periodic check for queue messages ---
        self.after(100, self.process_queue)

    # --- Button Callback Methods ---
    def select_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self.selected_folder = folder
            self.folder_label.config(text="Selected Folder: {}".format(folder))
            self.start_scan_button.config(state=tk.NORMAL)
            self.malicious_list.delete(0, tk.END)
            self.clean_list.delete(0, tk.END)
            self.suspicious_list.delete(0, tk.END)
            self.unknown_list.delete(0, tk.END)
            self.progress_var.set(0)
            self.current_file_label.config(text="Current File: N/A")
            self.scanned_count_label.config(text="Scanned: 0 / 0")
            self.reset_counts()
            self.open_quarantine_button.config(state=tk.DISABLED)
            logging.info("Folder selected: " + folder)

    def start_scan(self):
        if not self.selected_folder:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            return

        # Clear previous lists and counters.
        self.malicious_list.delete(0, tk.END)
        self.clean_list.delete(0, tk.END)
        self.suspicious_list.delete(0, tk.END)
        self.unknown_list.delete(0, tk.END)
        self.progress_var.set(0)
        self.current_file_label.config(text="Current File: N/A")
        self.scanned_count_label.config(text="Scanned: 0 / 0")
        self.reset_counts()

        # Disable buttons during scan.
        self.start_scan_button.config(state=tk.DISABLED)
        self.select_folder_button.config(state=tk.DISABLED)
        self.stop_scan_button.config(state=tk.NORMAL)
        self.pause_scan_button.config(state=tk.NORMAL)
        self.resume_scan_button.config(state=tk.DISABLED)
        self.open_quarantine_button.config(state=tk.DISABLED)

        # Start the scan worker thread.
        self.scan_thread = ScanWorker(self.selected_folder, self.queue)
        self.scan_thread.start()
        logging.info("Scan started...")

    def pause_scan(self):
        if self.scan_thread:
            self.scan_thread.pause()
            self.current_file_label.config(text="Current File: Paused...")
            self.pause_scan_button.config(state=tk.DISABLED)
            self.resume_scan_button.config(state=tk.NORMAL)
            logging.info("Scan paused.")

    def resume_scan(self):
        if self.scan_thread:
            self.scan_thread.resume()
            self.current_file_label.config(text="Current File: Resumed")
            self.pause_scan_button.config(state=tk.NORMAL)
            self.resume_scan_button.config(state=tk.DISABLED)
            logging.info("Scan resumed.")

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.stop_scan_button.config(state=tk.DISABLED)
            self.pause_scan_button.config(state=tk.DISABLED)
            self.resume_scan_button.config(state=tk.DISABLED)
            self.current_file_label.config(text="Current File: Stopping...")
            logging.info("Scan stopping...")

    def open_quarantine(self):
        quarantine_folder = QUARANTINE_FOLDER
        if not os.path.exists(quarantine_folder):
            messagebox.showinfo("Quarantine", "No quarantine folder exists.")
            return
        try:
            os.startfile(quarantine_folder)
            logging.info("Opened quarantine folder.")
        except Exception as e:
            logging.error("Failed to open quarantine folder: {}".format(e))

    def toggle_monitoring(self):
        if not self.selected_folder:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            return

        if not self.monitoring:
            # Start monitoring.
            self.monitor_thread = MonitorThread(self.selected_folder, self.queue)
            self.monitor_thread.start()
            self.monitor_button.config(text="Stop Monitoring")
            self.monitoring = True
            logging.info("Real-time monitoring started.")
        else:
            # Stop monitoring.
            if self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread.join()
                self.monitor_thread = None
            self.monitor_button.config(text="Start Monitoring")
            self.monitoring = False
            logging.info("Real-time monitoring stopped.")

    def reset_counts(self):
        self.count_malicious = 0
        self.count_clean = 0
        self.count_unknown = 0
        self.count_suspicious = 0
        self.total_scanned = 0
        self.malicious_files = []
        self.update_totals()

    def update_totals(self):
        self.total_scanned_label.config(text="Total Scanned: {}".format(self.total_scanned))
        self.total_malicious_label.config(text="Malicious: {}".format(self.count_malicious))
        self.total_clean_label.config(text="Clean: {}".format(self.count_clean))
        self.total_suspicious_label.config(text="Suspicious: {}".format(self.count_suspicious))
        self.total_unknown_label.config(text="Unknown: {}".format(self.count_unknown))

    # --- Queue Processing ---
    def process_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                mtype = msg.get('type')
                data = msg.get('data')
                if mtype == 'update_malicious':
                    self.count_malicious += 1
                    self.malicious_list.insert(tk.END, data)
                    # Attempt to extract the file path from the message.
                    for line in data.splitlines():
                        if line.startswith("Path: "):
                            file_path = line.replace("Path: ", "").strip()
                            self.malicious_files.append(file_path)
                            break
                elif mtype == 'update_clean':
                    self.count_clean += 1
                    self.clean_list.insert(tk.END, data)
                elif mtype == 'update_suspicious':
                    self.count_suspicious += 1
                    self.suspicious_list.insert(tk.END, data)
                elif mtype == 'update_unknown':
                    self.count_unknown += 1
                    self.unknown_list.insert(tk.END, data)
                elif mtype == 'update_progress':
                    scanned, total = data
                    self.total_scanned = scanned
                    self.scanned_count_label.config(text="Scanned: {} / {}".format(scanned, total))
                    percent = int((scanned / float(total)) * 100)
                    self.progress_var.set(percent)
                    self.update_totals()
                elif mtype == 'current_file':
                    self.current_file_label.config(text="Current File: {}".format(data))
                elif mtype == 'scan_complete':
                    # data = (unknown_count, malicious_count, clean_count, suspicious_count)
                    unknown_count, malicious_count, clean_count, suspicious_count = data
                    summary = ("Final Scan Summary: Malicious: {}, Clean: {}, Suspicious: {}, Unknown: {}"
                               .format(malicious_count, clean_count, suspicious_count, unknown_count))
                    self.current_file_label.config(text="Scan complete!")
                    self.malicious_list.insert(tk.END, "Scan complete!")
                    self.clean_list.insert(tk.END, "Scan complete!")
                    self.suspicious_list.insert(tk.END, "Scan complete!")
                    self.unknown_list.insert(tk.END, "Scan complete!")
                    logging.info(summary)
                    # Enable buttons after scan.
                    self.start_scan_button.config(state=tk.NORMAL)
                    self.select_folder_button.config(state=tk.NORMAL)
                    self.stop_scan_button.config(state=tk.DISABLED)
                    self.pause_scan_button.config(state=tk.DISABLED)
                    self.resume_scan_button.config(state=tk.DISABLED)
                    if self.malicious_files:
                        self.open_quarantine_button.config(state=tk.NORMAL)
                elif mtype == 'scan_aborted':
                    self.current_file_label.config(text="Scan Aborted")
                    self.start_scan_button.config(state=tk.NORMAL)
                    self.select_folder_button.config(state=tk.NORMAL)
                    self.stop_scan_button.config(state=tk.DISABLED)
                    self.pause_scan_button.config(state=tk.DISABLED)
                    self.resume_scan_button.config(state=tk.DISABLED)
                    logging.info("Scan aborted.")
                elif mtype == 'monitor_malware':
                    # data = (file_path, virus_info)
                    file_path, virus_info = data
                    message = "Malicious file auto-quarantined: {} ({})".format(file_path, virus_info)
                    self.malicious_list.insert(tk.END, message)
                    notify_user(file_path, virus_info)
                    logging.info("Real-time malware detection: " + message)
                self.queue.task_done()
        except queue.Empty:
            pass
        # Check the queue again after 100 ms.
        self.after(100, self.process_queue)

    def on_close(self):
        # Stop any running threads.
        if self.scan_thread:
            self.scan_thread.stop()
        if self.monitor_thread:
            self.monitor_thread.stop()
        self.destroy()

# ----------------- Main Execution -----------------
if __name__ == "__main__":
    app = MainApplication()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
