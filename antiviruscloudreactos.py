#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil
import hashlib
import mimetypes
import requests
import logging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil

import win32file
import win32con

# Use win10toast for notifications (compatible with Python 3.5+)
from win10toast import ToastNotifier

# Tkinter imports for Python 3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

application_log_file = os.path.join(log_directory, "antivirus.log")
logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Custom directory change flags
FILE_NOTIFY_CHANGE_LAST_ACCESS    = 0x00000020
FILE_NOTIFY_CHANGE_CREATION       = 0x00000040
FILE_NOTIFY_CHANGE_EA             = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME    = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE    = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE   = 0x00000800

# ----------------- Helper Functions -----------------
def calculate_file_hash(file_path):
    """Returns the MD5 hash (as a hex string) and file content. If the file is empty, returns None for the hash."""
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            if len(file_data) == 0:
                return None, file_data
            return hashlib.md5(file_data).hexdigest(), file_data
    except Exception:
        return None, None

def query_md5_online_sync(md5_hash):
    """Queries the online API and returns a risk string."""
    try:
        md5_hash_upper = md5_hash.upper()
        url = "https://www.nictasoft.com/ace/md5/{}".format(md5_hash_upper)
        response = requests.get(url)
        if response.status_code == 200:
            result = response.text.strip()
            lower_result = result.lower()
            if "[100% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return "Malware ({})".format(virus_name)
                else:
                    return "Malware"
            if "[70% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return "Suspicious ({})".format(virus_name)
                else:
                    return "Suspicious"
            if "[0% risk]" in lower_result:
                return "Benign"
            if "[10% risk]" in lower_result:
                return "Benign (auto verdict)"
            if "this file is not yet rated" in lower_result:
                return "Unknown"
            return "Unknown (Result)"
        else:
            return "Unknown (API error)"
    except Exception as ex:
        return "Error: {}".format(ex)

def local_analysis(file_path, file_data):
    """Performs a local analysis of the file. Returns a string with the file name and type."""
    try:
        file_name = os.path.basename(file_path)
        file_type, _ = mimetypes.guess_type(file_path)
        return "Name: {} | Type: {}".format(file_name, file_type if file_type else "Unknown")
    except Exception as e:
        return "Local analysis error: {}".format(e)

def notify_user(file_path, virus_name=""):
    """Sends a desktop notification for a malware detection using win10toast."""
    toaster = ToastNotifier()
    title = "Malware Alert"
    if virus_name:
        message = "Malicious file quarantined:\n{}\nVirus: {}".format(file_path, virus_name)
    else:
        message = "Malicious file quarantined:\n{}".format(file_path)
    # Display notification (ensure your system supports Toast notifications)
    toaster.show_toast(title, message, duration=10)

# Define the quarantine folder and JSON file to store quarantine records.
QUARANTINE_FOLDER = os.path.join(os.getcwd(), "quarantine")
QUARANTINE_DATA_FILE = os.path.join(QUARANTINE_FOLDER, "quarantine_data.json")

def ensure_quarantine_folder():
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)
    # Ensure the JSON file exists.
    if not os.path.exists(QUARANTINE_DATA_FILE):
        with open(QUARANTINE_DATA_FILE, 'w') as f:
            json.dump([], f)

def add_quarantine_record(original_path, virus_name, quarantine_path):
    """
    Append a record to the quarantine JSON file.
    Each record contains:
      - original_path: the original file location
      - quarantine_path: where the file is now located
      - virus_name: the virus identifier (if any)
      - date: timestamp of quarantine
    """
    ensure_quarantine_folder()
    record = {
        "original_path": original_path,
        "quarantine_path": quarantine_path,
        "virus_name": virus_name,
        "date": datetime.datetime.now().isoformat()
    }
    try:
        with open(QUARANTINE_DATA_FILE, 'r') as f:
            data = json.load(f)
    except Exception:
        data = []
    data.append(record)
    with open(QUARANTINE_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def open_quarantine_manager():
    """
    This function can be invoked by your quarantine manager GUI.
    It reads the JSON file with quarantine records and returns the list.
    """
    ensure_quarantine_folder()
    try:
        with open(QUARANTINE_DATA_FILE, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error("Failed to load quarantine data: {}".format(e))
        data = []
    return data

def delete_all_quarantined_files():
    """
    Deletes all files recorded in the quarantine JSON and clears the JSON file.
    Returns a list of any error messages encountered.
    """
    ensure_quarantine_folder()
    try:
        with open(QUARANTINE_DATA_FILE, 'r') as f:
            records = json.load(f)
    except Exception as e:
        logging.error("Failed to load quarantine data: {}".format(e))
        records = []
    errors = []
    for record in records:
        quarantine_path = record.get("quarantine_path")
        if quarantine_path and os.path.exists(quarantine_path):
            try:
                os.remove(quarantine_path)
                logging.info("Deleted quarantined file: {}".format(quarantine_path))
            except Exception as e:
                errors.append("Failed to delete {}: {}".format(quarantine_path, e))
    # Clear the quarantine JSON file
    with open(QUARANTINE_DATA_FILE, 'w') as f:
        json.dump([], f, indent=4)
    return errors

def restore_all_quarantined_files():
    """
    Restores all quarantined files to their original locations as recorded in the JSON file.
    If a file already exists at the original location, that file is skipped.
    Returns a list of any error messages encountered.
    """
    ensure_quarantine_folder()
    try:
        with open(QUARANTINE_DATA_FILE, 'r') as f:
            records = json.load(f)
    except Exception as e:
        logging.error("Failed to load quarantine data: {}".format(e))
        records = []
    errors = []
    restored_records = []
    for record in records:
        quarantine_path = record.get("quarantine_path")
        original_path = record.get("original_path")
        if quarantine_path and os.path.exists(quarantine_path):
            # If a file already exists at the original location, skip restoration.
            if os.path.exists(original_path):
                errors.append("File already exists at original location: {}".format(original_path))
                continue
            try:
                # Ensure the original directory exists
                original_dir = os.path.dirname(original_path)
                if not os.path.exists(original_dir):
                    os.makedirs(original_dir)
                shutil.move(quarantine_path, original_path)
                logging.info("Restored file: {} -> {}".format(quarantine_path, original_path))
                restored_records.append(record)
            except Exception as e:
                errors.append("Failed to restore {}: {}".format(quarantine_path, e))
    # Remove restored records from the JSON file.
    remaining_records = [rec for rec in records if rec not in restored_records]
    with open(QUARANTINE_DATA_FILE, 'w') as f:
        json.dump(remaining_records, f, indent=4)
    return errors

def scan_and_quarantine(file_path):
    """Scans the file, and if it is determined to be malware, moves it to the quarantine folder."""
    file_hash, file_data = calculate_file_hash(file_path)
    if not file_hash:
        return (False, "Clean (Empty file)")
    
    risk_result = query_md5_online_sync(file_hash)
    if risk_result.startswith("Benign") or risk_result.startswith("Suspicious") or \
       risk_result.startswith("Unknown") or risk_result.startswith("Error"):
        return (False, risk_result)
    
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

# ----------------- Multi-threaded Scan Worker -----------------
class ScanWorker(threading.Thread):
    """
    Multi-threaded scan worker that uses a ThreadPoolExecutor to process files concurrently.
    Now uses a hash cache to avoid re-scanning files whose results have already been determined.
    """
    def __init__(self, folder_path, queue, max_workers=200):
        threading.Thread.__init__(self)
        self.folder_path = folder_path
        self.queue = queue
        self.stop_event = threading.Event()
        self.pause_cond = threading.Condition()
        self.paused = False
        self.max_workers = max_workers
        self.hash_cache = {}         # Cache: { file_hash: result_dict }
        self.cache_lock = threading.Lock()  # Protects access to hash_cache

        logging.info("ScanWorker initialized for folder: %s with max_workers=%s", self.folder_path, self.max_workers)

    def run(self):
        logging.info("ScanWorker started scanning folder: %s", self.folder_path)
        # Gather all file paths from the folder (and subfolders)
        file_paths = []
        for root, dirs, files in os.walk(self.folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                file_paths.append(full_path)

        total_files = len(file_paths)
        logging.info("Total files found: %d", total_files)
        if total_files == 0:
            logging.info("No files to scan in folder: %s", self.folder_path)
            self.queue.put({'type': 'scan_complete', 'data': (0, 0, 0, 0)})
            return

        scanned_files = 0
        # Counters for final summary
        clean_count = 0
        malicious_count = 0
        suspicious_count = 0
        unknown_count = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {executor.submit(self.process_file, fp): fp for fp in file_paths}
            logging.info("Submitted all file scanning tasks to the executor.")

            for future in as_completed(future_to_path):
                if self.stop_event.is_set():
                    logging.info("Stop event set. Aborting scan.")
                    self.queue.put({'type': 'scan_aborted'})
                    executor.shutdown(wait=False)
                    return

                try:
                    result = future.result()  # result is a dict with keys: 'type' and 'data'
                except Exception as e:
                    logging.error("Error processing file: %s", e)
                    continue

                update_type = result.get("type")
                data = result.get("data")

                if update_type == "update_clean":
                    clean_count += 1
                elif update_type == "update_malicious":
                    malicious_count += 1
                elif update_type == "update_suspicious":
                    suspicious_count += 1
                elif update_type == "update_unknown":
                    unknown_count += 1

                logging.debug("Scan result for a file: %s", data)
                self.queue.put(result)
                scanned_files += 1
                self.queue.put({'type': 'update_progress', 'data': (scanned_files, total_files)})
                logging.info("Progress update: %d/%d files scanned.", scanned_files, total_files)

        logging.info("Scan complete. Summary: Unknown: %d, Malicious: %d, Clean: %d, Suspicious: %d",
                     unknown_count, malicious_count, clean_count, suspicious_count)
        self.queue.put({'type': 'scan_complete', 'data': (unknown_count, malicious_count, clean_count, suspicious_count)})

    def process_file(self, file_path):
        logging.debug("Processing file: %s", file_path)
        # Pause support
        with self.pause_cond:
            while self.paused:
                logging.info("ScanWorker paused. Waiting...")
                self.pause_cond.wait()
            if self.stop_event.is_set():
                logging.info("Stop event set while processing file: %s", file_path)
                return {'type': 'skipped', 'data': "Scan aborted: {}".format(file_path)}

        # Calculate file hash and file data
        try:
            file_hash, file_data = calculate_file_hash(file_path)
            logging.debug("Calculated hash for %s: %s", file_path, file_hash)
        except Exception as e:
            logging.error("Error calculating hash for %s: %s", file_path, e)
            return {'type': 'skipped', 'data': "Error calculating hash for {}".format(file_path)}

        if not file_hash:
            msg = "Clean File (Empty): {}".format(file_path)
            logging.info("Empty file detected: %s", file_path)
            result = {'type': 'update_clean', 'data': msg}
            return result

        # Check if this file hash is already in our cache
        with self.cache_lock:
            if file_hash in self.hash_cache:
                cached_result = self.hash_cache[file_hash]
                logging.info("Cache hit for file %s with hash %s", file_path, file_hash)
                self.queue.put({'type': 'current_file', 'data': "{} -> Cached Result".format(file_path)})
                return cached_result

        # Not in cache: perform the scan
        try:
            risk_result = query_md5_online_sync(file_hash)
        except Exception as e:
            risk_result = "Unknown"

        try:
            local_info = local_analysis(file_path, file_data)
            logging.debug("Local analysis for %s: %s", file_path, local_info)
        except Exception as e:
            logging.error("Error performing local analysis for %s: %s", file_path, e)
            local_info = "No local analysis available."

        self.queue.put({'type': 'current_file', 'data': "{} -> {}".format(file_path, risk_result)})

        # Build the result message based on the scan outcome.
        if risk_result.startswith("Benign"):
            msg = ("Clean File Detected:\nPath: {}\nMD5: {}\n{}\nStatus: {}\n{}"
                   .format(file_path, file_hash, local_info, risk_result, "-" * 50))
            result = {'type': 'update_clean', 'data': msg}
            logging.info("File marked as clean: %s", file_path)

        elif risk_result.startswith("Malware"):
            logging.warning("Malicious file detected: %s", file_path)
            try:
                ensure_quarantine_folder()
                quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
                shutil.move(file_path, quarantine_path)
                logging.info("Malicious file quarantined: %s -> %s", file_path, quarantine_path)
                add_quarantine_record(file_path, risk_result, quarantine_path)
                notify_user(file_path, risk_result)
            except Exception as e:
                logging.error("Failed to quarantine %s: %s", file_path, e)
            msg = ("Malicious File Detected:\nPath: {}\nMD5: {}\n{}\nStatus: {}\n{}"
                   .format(file_path, file_hash, local_info, risk_result, "-" * 50))
            result = {'type': 'update_malicious', 'data': msg}

        elif risk_result.startswith("Suspicious"):
            msg = ("Suspicious File Detected:\nPath: {}\nMD5: {}\n{}\nStatus: {}\n{}"
                   .format(file_path, file_hash, local_info, risk_result, "-" * 50))
            result = {'type': 'update_suspicious', 'data': msg}
            logging.info("File marked as suspicious: %s", file_path)

        else:
            msg = ("Unknown File Detected:\nPath: {}\nMD5: {}\n{}\nStatus: {}\n{}"
                   .format(file_path, file_hash, local_info, risk_result, "-" * 50))
            result = {'type': 'update_unknown', 'data': msg}
            logging.info("File marked as unknown: %s", file_path)

        # Save the result in the cache for future reuse.
        with self.cache_lock:
            self.hash_cache[file_hash] = result
            logging.debug("Cached result for file %s with hash %s", file_path, file_hash)

        return result

    def pause(self):
        with self.pause_cond:
            self.paused = True
            logging.info("ScanWorker paused.")

    def resume(self):
        with self.pause_cond:
            self.paused = False
            self.pause_cond.notify_all()
            logging.info("ScanWorker resumed.")

    def stop(self):
        logging.info("Stop signal received for ScanWorker.")
        self.stop_event.set()
        self.resume()

# ----------------- Real-Time Monitoring Thread -----------------
# Custom flags for directory changes
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

class MonitorThread(threading.Thread):
    """
    Monitors a directory for changes and processes changed files concurrently.
    Also scans all running processes using psutil, skipping files already scanned.
    """
    def __init__(self, monitor_folder, queue, max_workers=200, process_scan_interval=30):
        threading.Thread.__init__(self)
        self.monitor_folder = monitor_folder
        self.queue = queue
        self.stop_event = threading.Event()
        self.max_workers = max_workers
        self.process_scan_interval = process_scan_interval  # seconds between process scans

        # Initialize a hash cache and a lock for thread-safety.
        self.hash_cache = {}  # Format: { file_hash: risk_result, exe_path: risk_result }
        self.cache_lock = threading.Lock()

        # Timestamp for scheduling process scans.
        self.last_process_scan_time = 0

        logging.info("MonitorThread initialized for folder: %s", self.monitor_folder)

    def run(self):
        logging.info("MonitorThread started.")
        if not os.path.exists(self.monitor_folder):
            logging.error("Monitor folder not found: %s", self.monitor_folder)
            return

        try:
            hDir = win32file.CreateFile(
                self.monitor_folder,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            logging.info("Successfully opened directory handle for %s", self.monitor_folder)
        except Exception as e:
            logging.error("Failed to open directory handle for %s: %s", self.monitor_folder, e)
            return

        change_flags = (
            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
            win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
            win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
            win32con.FILE_NOTIFY_CHANGE_SIZE |
            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
            win32con.FILE_NOTIFY_CHANGE_SECURITY |
            FILE_NOTIFY_CHANGE_LAST_ACCESS |
            FILE_NOTIFY_CHANGE_CREATION |
            FILE_NOTIFY_CHANGE_EA |
            FILE_NOTIFY_CHANGE_STREAM_NAME |
            FILE_NOTIFY_CHANGE_STREAM_SIZE |
            FILE_NOTIFY_CHANGE_STREAM_WRITE
        )

        # Use a ThreadPoolExecutor for processing file changes and process scans.
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            try:
                while not self.stop_event.is_set():
                    logging.debug("Waiting for file system changes in %s", self.monitor_folder)
                    results = win32file.ReadDirectoryChangesW(
                        hDir,
                        1024,
                        True,
                        change_flags,
                        None,
                        None
                    )
                    logging.info("Detected %d change(s) in %s", len(results), self.monitor_folder)
                    for action, file in results:
                        path_to_scan = os.path.join(self.monitor_folder, file)
                        logging.debug("Change detected: Action %s on file %s", action, path_to_scan)
                        if os.path.exists(path_to_scan):
                            logging.info("Submitting file scan for: %s", path_to_scan)
                            executor.submit(self.process_changed_file, path_to_scan)
                        else:
                            logging.warning("File not found: %s", path_to_scan)

                    # Always scan running processes.
                    logging.info("Submitting process scan.")
                    executor.submit(self.scan_processes)
            except Exception as ex:
                logging.error("Error in MonitorThread run loop: %s", ex)
            finally:
                try:
                    win32file.CloseHandle(hDir)
                    logging.info("Closed directory handle for %s", self.monitor_folder)
                except Exception as e:
                    logging.error("Error closing directory handle: %s", e)

        logging.info("MonitorThread exiting.")

    def process_changed_file(self, file_path):
        """
        Processes a file system change: compute its hash and query its risk status.
        If malware is detected, quarantine the file.
        """
        logging.debug("Processing changed file: %s", file_path)
        try:
            file_hash, file_data = calculate_file_hash(file_path)
        except Exception as e:
            logging.error("Error calculating hash for %s: %s", file_path, e)
            return

        if not file_hash:
            logging.warning("No hash computed for file: %s", file_path)
            return

        # Check the hash cache.
        with self.cache_lock:
            if file_hash in self.hash_cache:
                risk_result = self.hash_cache[file_hash]
                logging.info("Cache hit for %s: %s", file_path, risk_result)
                self.queue.put({'type': 'current_file', 'data': "{} -> Cached Result".format(file_path)})
            else:
                logging.info("Cache miss for %s; querying risk online.", file_path)
                try:
                    risk_result = query_md5_online_sync(file_hash)
                except Exception as e:
                    logging.error("Error querying online for %s: %s", file_path, e)
                    return
                self.hash_cache[file_hash] = risk_result
                self.queue.put({'type': 'current_file', 'data': "{} -> {}".format(file_path, risk_result)})

        # If malware is detected, quarantine the file.
        if risk_result.startswith("Malware"):
            logging.warning("Malware detected in file: %s", file_path)
            try:
                ensure_quarantine_folder()
                quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
                shutil.move(file_path, quarantine_path)
                logging.info("Real-time: Malicious file quarantined: %s -> %s", file_path, quarantine_path)
                add_quarantine_record(file_path, risk_result, quarantine_path)
                notify_user(file_path, risk_result)
            except Exception as e:
                logging.error("Real-time: Failed to quarantine %s: %s", file_path, e)
            self.queue.put({'type': 'monitor_malware', 'data': (file_path, risk_result)})
        else:
            logging.debug("File %s is clean: %s", file_path, risk_result)

    def scan_processes(self):
        """
        Always scan all running processes using psutil, but skip scanning
        files (executables) that have already been scanned.
        """
        logging.info("Starting scan of running processes.")
        try:
            processes = list(psutil.process_iter())
        except Exception as e:
            logging.error("Failed to retrieve processes: %s", e)
            return

        # Use a ThreadPoolExecutor for process scanning.
        with ThreadPoolExecutor(max_workers=200) as executor:
            for proc in processes:
                try:
                    proc_info = proc.as_dict(attrs=['pid', 'name', 'exe'])
                    logging.debug("Submitting scan for process: %s (PID: %s)", 
                                  proc_info.get('name'), proc_info.get('pid'))
                    executor.submit(self.scan_process, proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logging.debug("Skipping process due to error: %s", e)
                except Exception as e:
                    logging.error("Error retrieving process info: %s", e)
        logging.info("Completed submission of process scan tasks.")

    def scan_process(self, proc_info):
        """
        Scans a single process by computing its executable's hash and checking the risk.
        Skips scanning files that have already been processed (using a hash cache).
        The parameter proc_info is a dictionary containing process details.
        """
        try:
            exe_path = proc_info.get('exe')
            if not exe_path:
                logging.debug("Process %s (PID: %s) has no executable path; skipping.",
                              proc_info.get('name'), proc_info.get('pid'))
                return

            if not os.path.exists(exe_path):
                logging.debug("Executable path does not exist for process %s (PID: %s): %s",
                              proc_info.get('name'), proc_info.get('pid'), exe_path)
                return

            # Check if the file path is already in the cache.
            with self.cache_lock:
                if exe_path in self.hash_cache:
                    risk_result = self.hash_cache[exe_path]
                    logging.info("Cache hit for process executable %s: %s", exe_path, risk_result)
                    self.queue.put({'type': 'process_scan', 'data': "Cached: {} -> {}".format(exe_path, risk_result)})
                    return

            logging.debug("Computing hash for process executable: %s", exe_path)
            file_hash, file_data = calculate_file_hash(exe_path)
            if not file_hash:
                msg = ("Process {} (PID: {}): Unable to compute hash for {}"
                       .format(proc_info.get('name'), proc_info.get('pid'), exe_path))
                logging.warning(msg)
                self.queue.put({'type': 'process_scan', 'data': msg})
                return

            # Check the hash cache.
            with self.cache_lock:
                if file_hash in self.hash_cache:
                    risk_result = self.hash_cache[file_hash]
                    logging.info("Cache hit for hash %s of executable %s", file_hash, exe_path)
                else:
                    logging.info("Cache miss for hash %s of executable %s; querying risk.", file_hash, exe_path)
                    try:
                        risk_result = query_md5_online_sync(file_hash)
                    except Exception as e:
                        logging.error("Error querying online for process %s: %s", exe_path, e)
                        return
                    # Cache both the hash and the file path.
                    self.hash_cache[file_hash] = risk_result
                    self.hash_cache[exe_path] = risk_result

            msg = ("Process: {} (PID: {}), Executable: {}\nRisk: {}"
                   .format(proc_info.get('name'), proc_info.get('pid'), exe_path, risk_result))
            logging.info("Process scan result: %s", msg)
            self.queue.put({'type': 'process_scan', 'data': msg})

            # Notify user for malware or suspicious processes.
            if risk_result.startswith("Malware"):
                logging.warning("Malware detected in process executable: %s", exe_path)
                notify_user(exe_path, risk_result)
                self.queue.put({'type': 'process_malware', 'data': msg})
            elif risk_result.startswith("Suspicious"):
                logging.warning("Suspicious result detected in process executable: %s", exe_path)
                notify_user(exe_path, risk_result)
                self.queue.put({'type': 'process_suspicious', 'data': msg})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as specific_ex:
            logging.debug("Process scanning skipped due to process exception: %s", specific_ex)
            return
        except Exception as e:
            logging.error("Error scanning process %s: %s", proc_info, e)

    def stop(self):
        logging.info("Stop signal received for MonitorThread.")
        self.stop_event.set()

# ----------------- Quarantine Manager Function -----------------
def open_quarantine_manager():
    """
    This function can be invoked by your quarantine manager GUI.
    It reads the JSON file with quarantine records and returns the list.
    """
    ensure_quarantine_folder()
    try:
        with open(QUARANTINE_DATA_FILE, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error("Failed to load quarantine data: {}".format(e))
        data = []
    return data

# ----------------- Main Application Window -----------------
class MainApplication(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Haci Murad Antivirus Cloud Scanner")
        self.geometry("700x370")
        logging.info("Application started with title 'Haci Murad Antivirus Cloud Scanner'.")

        self.queue = queue.Queue()
        self.scan_thread = None
        self.monitor_thread = None

        self.count_malicious = 0
        self.count_clean = 0
        self.count_unknown = 0
        self.count_suspicious = 0
        self.total_scanned = 0
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

        # --- Status Labels ---
        status_frame = tk.Frame(self)
        status_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.folder_label = tk.Label(status_frame, text="Selected Folder: None")
        self.folder_label.pack(anchor="w")
        self.current_file_label = tk.Label(status_frame, text="Current File: N/A")
        self.current_file_label.pack(anchor="w")
        self.scanned_count_label = tk.Label(status_frame, text="Scanned: 0 / 0")
        self.scanned_count_label.pack(anchor="w")

        # --- Progress Bar ---
        progress_frame = tk.Frame(self)
        progress_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=5)

        # --- Results Lists ---
        results_frame = tk.Frame(self)
        results_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.malicious_list = tk.Listbox(results_frame)
        self.clean_list = tk.Listbox(results_frame)
        self.suspicious_list = tk.Listbox(results_frame)
        self.unknown_list = tk.Listbox(results_frame)

        tk.Label(results_frame, text="Malicious Files").grid(row=0, column=0)
        tk.Label(results_frame, text="Clean Files").grid(row=0, column=1)
        tk.Label(results_frame, text="Suspicious Files").grid(row=0, column=2)
        tk.Label(results_frame, text="Unknown Files").grid(row=0, column=3)

        self.malicious_list.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self.clean_list.grid(row=1, column=1, sticky="nsew", padx=2, pady=2)
        self.suspicious_list.grid(row=1, column=2, sticky="nsew", padx=2, pady=2)
        self.unknown_list.grid(row=1, column=3, sticky="nsew", padx=2, pady=2)

        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_columnconfigure(1, weight=1)
        results_frame.grid_columnconfigure(2, weight=1)
        results_frame.grid_columnconfigure(3, weight=1)

        # Bind right-click on each list to show a context menu.
        self.malicious_list.bind("<Button-3>", self.on_list_right_click)
        self.clean_list.bind("<Button-3>", self.on_list_right_click)
        self.suspicious_list.bind("<Button-3>", self.on_list_right_click)
        self.unknown_list.bind("<Button-3>", self.on_list_right_click)

        # --- Manual Actions Frame ---
        actions_frame = tk.Frame(self)
        actions_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        tk.Label(actions_frame, text="Manual Actions:").pack(side=tk.LEFT, padx=5)
        self.delete_button = tk.Button(actions_frame, text="Delete Selected File", command=self.delete_selected)
        self.delete_button.pack(side=tk.LEFT, padx=2)
        self.quarantine_button = tk.Button(actions_frame, text="Quarantine Selected File", command=self.quarantine_selected)
        self.quarantine_button.pack(side=tk.LEFT, padx=2)
        self.delete_all_button = tk.Button(actions_frame, text="Delete All", command=self.delete_all)
        self.delete_all_button.pack(side=tk.LEFT, padx=2)
        self.quarantine_all_button = tk.Button(actions_frame, text="Quarantine All", command=self.quarantine_all)
        self.quarantine_all_button.pack(side=tk.LEFT, padx=2)

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

        self.after(100, self.process_queue)
        logging.info("UI initialized successfully.")

    def extract_filepath(self, text):
        """
        Tries to extract a file path from a given text by looking for a line that starts with "Path: ".
        Returns the file path if found, or the text stripped.
        """
        logging.debug("Extracting file path from text.")
        for line in text.splitlines():
            if line.startswith("Path: "):
                file_path = line.replace("Path: ", "").strip()
                logging.debug("Extracted file path: %s", file_path)
                return file_path
        logging.debug("No specific file path found, returning stripped text.")
        return text.strip()

    def on_list_right_click(self, event):
        """Show a context menu with actions for the selected list item."""
        widget = event.widget
        try:
            index = widget.nearest(event.y)
            widget.selection_clear(0, tk.END)
            widget.selection_set(index)
            entry = widget.get(index)
            logging.debug("Right-click on list item: %s", entry)
        except Exception as e:
            logging.error("Error handling right-click event: %s", e)
            return
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Delete", command=lambda: self.delete_selected_item(widget, index))
        menu.add_command(label="Quarantine", command=lambda: self.quarantine_selected_item(widget, index))
        menu.add_command(label="Skip", command=lambda: self.skip_selected_item(widget, index))
        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()
        logging.debug("Context menu displayed for list item.")

    def delete_selected_item(self, lst, index):
        """Deletes the file corresponding to the selected item in the given list."""
        entry = lst.get(index)
        file_path = self.extract_filepath(entry)
        logging.info("Attempting to delete file: %s", file_path)
        if file_path and os.path.exists(file_path):
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete:\n{}".format(file_path)):
                try:
                    os.remove(file_path)
                    messagebox.showinfo("Delete", "Deleted file:\n{}".format(file_path))
                    logging.info("Deleted file: %s", file_path)
                    lst.delete(index)
                except Exception as e:
                    logging.error("Failed to delete file %s: %s", file_path, e)
                    messagebox.showerror("Error", "Failed to delete file:\n{}\nError: {}".format(file_path, e))
        else:
            logging.warning("File not found for deletion: %s", file_path)
            messagebox.showwarning("Not Found", "File does not exist:\n{}".format(file_path))

    def quarantine_selected_item(self, lst, index):
        """Moves the selected file into the quarantine folder."""
        entry = lst.get(index)
        file_path = self.extract_filepath(entry)
        logging.info("Attempting to quarantine file: %s", file_path)
        if file_path and os.path.exists(file_path):
            if not os.path.exists(QUARANTINE_FOLDER):
                os.makedirs(QUARANTINE_FOLDER)
                logging.debug("Created quarantine folder: %s", QUARANTINE_FOLDER)
            quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
            if messagebox.askyesno("Confirm Quarantine", "Are you sure you want to quarantine:\n{}".format(file_path)):
                try:
                    shutil.move(file_path, quarantine_path)
                    messagebox.showinfo("Quarantine", "File quarantined to:\n{}".format(quarantine_path))
                    logging.info("File quarantined: %s -> %s", file_path, quarantine_path)
                    lst.delete(index)
                except Exception as e:
                    logging.error("Failed to quarantine file %s: %s", file_path, e)
                    messagebox.showerror("Error", "Failed to quarantine file:\n{}\nError: {}".format(file_path, e))
        else:
            logging.warning("File not found for quarantine: %s", file_path)
            messagebox.showwarning("Not Found", "File does not exist:\n{}".format(file_path))

    def skip_selected_item(self, lst, index):
        """Simply notifies the user that the file was skipped."""
        entry = lst.get(index)
        file_path = self.extract_filepath(entry)
        logging.info("File skipped: %s", file_path)
        messagebox.showinfo("Skip", "File skipped:\n{}".format(file_path))

    def delete_selected(self):
        """Deletes the file corresponding to the selected entry from any list."""
        logging.info("Delete selected file triggered.")
        for lst in [self.malicious_list, self.clean_list, self.suspicious_list, self.unknown_list]:
            try:
                index = lst.curselection()[0]
                self.delete_selected_item(lst, index)
                return
            except IndexError:
                continue
        logging.warning("No file selected for deletion.")
        messagebox.showwarning("No Selection", "Please select a file from one of the lists first.")

    def quarantine_selected(self):
        """Manually moves the selected file into the quarantine folder."""
        logging.info("Quarantine selected file triggered.")
        for lst in [self.malicious_list, self.clean_list, self.suspicious_list, self.unknown_list]:
            try:
                index = lst.curselection()[0]
                self.quarantine_selected_item(lst, index)
                return
            except IndexError:
                continue
        logging.warning("No file selected for quarantine.")
        messagebox.showwarning("No Selection", "Please select a file from one of the lists first.")

    def delete_all(self):
        """Deletes all files listed in all lists after confirmation."""
        logging.info("Delete all files triggered.")
        all_files = []
        for lst in [self.malicious_list, self.clean_list, self.suspicious_list, self.unknown_list]:
            for i in range(lst.size()):
                entry = lst.get(i)
                file_path = self.extract_filepath(entry)
                if file_path and file_path not in all_files:
                    all_files.append(file_path)
        if not all_files:
            logging.info("No files available to delete.")
            messagebox.showwarning("No Files", "No files to delete.")
            return
        if messagebox.askyesno("Confirm Delete All", "Are you sure you want to delete all files listed?"):
            errors = []
            for file_path in all_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        logging.info("Deleted file: %s", file_path)
                    except Exception as e:
                        errors.append("Failed to delete {}: {}".format(file_path, e))
                        logging.error("Failed to delete file %s: %s", file_path, e)
            if errors:
                messagebox.showerror("Delete All Errors", "\n".join(errors))
            else:
                messagebox.showinfo("Delete All", "All files deleted.")
            self.malicious_list.delete(0, tk.END)
            self.clean_list.delete(0, tk.END)
            self.suspicious_list.delete(0, tk.END)
            self.unknown_list.delete(0, tk.END)

    def quarantine_all(self):
        """Moves all files listed in all lists to the quarantine folder after confirmation."""
        logging.info("Quarantine all files triggered.")
        all_files = []
        for lst in [self.malicious_list, self.clean_list, self.suspicious_list, self.unknown_list]:
            for i in range(lst.size()):
                entry = lst.get(i)
                file_path = self.extract_filepath(entry)
                if file_path and file_path not in all_files:
                    all_files.append(file_path)
        if not all_files:
            logging.info("No files available to quarantine.")
            messagebox.showwarning("No Files", "No files to quarantine.")
            return
        if messagebox.askyesno("Confirm Quarantine All", "Are you sure you want to quarantine all files listed?"):
            if not os.path.exists(QUARANTINE_FOLDER):
                os.makedirs(QUARANTINE_FOLDER)
                logging.debug("Created quarantine folder: %s", QUARANTINE_FOLDER)
            errors = []
            for file_path in all_files:
                if os.path.exists(file_path):
                    quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
                    try:
                        shutil.move(file_path, quarantine_path)
                        logging.info("File quarantined: %s -> %s", file_path, quarantine_path)
                    except Exception as e:
                        errors.append("Failed to quarantine {}: {}".format(file_path, e))
                        logging.error("Failed to quarantine file %s: %s", file_path, e)
            if errors:
                messagebox.showerror("Quarantine All Errors", "\n".join(errors))
            else:
                messagebox.showinfo("Quarantine All", "All files quarantined.")
            self.malicious_list.delete(0, tk.END)
            self.clean_list.delete(0, tk.END)
            self.suspicious_list.delete(0, tk.END)
            self.unknown_list.delete(0, tk.END)

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
            logging.info("Folder selected: %s", folder)
        else:
            logging.info("No folder was selected.")

    def start_scan(self):
        if not self.selected_folder:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            logging.warning("Start scan attempted with no folder selected.")
            return

        # Clear previous results
        logging.info("Starting scan for folder: %s", self.selected_folder)
        self.malicious_list.delete(0, tk.END)
        self.clean_list.delete(0, tk.END)
        self.suspicious_list.delete(0, tk.END)
        self.unknown_list.delete(0, tk.END)
        self.progress_var.set(0)
        self.current_file_label.config(text="Current File: N/A")
        self.scanned_count_label.config(text="Scanned: 0 / 0")
        self.reset_counts()

        self.start_scan_button.config(state=tk.DISABLED)
        self.select_folder_button.config(state=tk.DISABLED)
        self.stop_scan_button.config(state=tk.NORMAL)
        self.pause_scan_button.config(state=tk.NORMAL)
        self.resume_scan_button.config(state=tk.DISABLED)
        self.open_quarantine_button.config(state=tk.DISABLED)

        # If your ScanWorker accepts a hash cache parameter, adjust as needed.
        self.scan_thread = ScanWorker(self.selected_folder, self.queue, max_workers=200)
        self.scan_thread.start()
        logging.info("Scan thread started for folder: %s", self.selected_folder)

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
        logging.info("Open quarantine triggered.")
        if not os.path.exists(QUARANTINE_FOLDER):
            messagebox.showinfo("Quarantine", "No quarantine folder exists.")
            logging.info("No quarantine folder exists.")
            return
        try:
            os.startfile(QUARANTINE_FOLDER)
            logging.info("Opened quarantine folder: %s", QUARANTINE_FOLDER)
        except Exception as e:
            logging.error("Failed to open quarantine folder: %s", e)

    def toggle_monitoring(self):
        if not self.selected_folder:
            messagebox.showwarning("No Folder Selected", "Please select a folder first.")
            logging.warning("Monitoring toggle attempted with no folder selected.")
            return
        if not self.monitoring:
            self.monitor_thread = MonitorThread(self.selected_folder, self.queue)
            self.monitor_thread.start()
            self.monitor_button.config(text="Stop Monitoring")
            self.monitoring = True
            logging.info("Real-time monitoring started for folder: %s", self.selected_folder)
        else:
            if self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread.join()
                self.monitor_thread = None
                logging.info("Real-time monitoring thread stopped.")
            self.monitor_button.config(text="Start Monitoring")
            self.monitoring = False
            logging.info("Real-time monitoring toggled off.")

    def reset_counts(self):
        logging.debug("Resetting counts.")
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
        logging.debug("Totals updated: Scanned=%d, Malicious=%d, Clean=%d, Suspicious=%d, Unknown=%d",
                      self.total_scanned, self.count_malicious, self.count_clean, self.count_suspicious, self.count_unknown)

    def process_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                mtype = msg.get("type")
                data = msg.get("data")
                logging.debug("Processing queue message: %s with data: %s", mtype, data)
                if mtype == "update_malicious":
                    self.count_malicious += 1
                    self.malicious_list.insert(tk.END, data)
                    for line in data.splitlines():
                        if line.startswith("Path: "):
                            file_path = line.replace("Path: ", "").strip()
                            if file_path not in self.malicious_files:
                                self.malicious_files.append(file_path)
                            break
                elif mtype == "update_clean":
                    self.count_clean += 1
                    self.clean_list.insert(tk.END, data)
                elif mtype == "update_suspicious":
                    self.count_suspicious += 1
                    self.suspicious_list.insert(tk.END, data)
                elif mtype == "update_unknown":
                    self.count_unknown += 1
                    self.unknown_list.insert(tk.END, data)
                elif mtype == "update_progress":
                    scanned, total = data
                    self.total_scanned = scanned
                    self.scanned_count_label.config(text="Scanned: {} / {}".format(scanned, total))
                    percent = int((scanned / float(total)) * 100)
                    self.progress_var.set(percent)
                    self.update_totals()
                elif mtype == "current_file":
                    self.current_file_label.config(text="Current File: {}".format(data))
                elif mtype == "scan_complete":
                    unknown_count, malicious_count, clean_count, suspicious_count = data
                    summary = ("Final Scan Summary:\nMalicious: {}, Clean: {}, Suspicious: {}, Unknown: {}"
                               .format(malicious_count, clean_count, suspicious_count, unknown_count))
                    self.current_file_label.config(text="Scan complete!")
                    self.malicious_list.insert(tk.END, "Scan complete!")
                    self.clean_list.insert(tk.END, "Scan complete!")
                    self.suspicious_list.insert(tk.END, "Scan complete!")
                    self.unknown_list.insert(tk.END, "Scan complete!")
                    logging.info("Scan complete. " + summary)
                    messagebox.showinfo("Scan Finished", summary)
                    self.start_scan_button.config(state=tk.NORMAL)
                    self.select_folder_button.config(state=tk.NORMAL)
                    self.stop_scan_button.config(state=tk.DISABLED)
                    self.pause_scan_button.config(state=tk.DISABLED)
                    self.resume_scan_button.config(state=tk.DISABLED)
                    if self.malicious_files:
                        self.open_quarantine_button.config(state=tk.NORMAL)
                elif mtype == "scan_aborted":
                    self.current_file_label.config(text="Scan Aborted")
                    self.start_scan_button.config(state=tk.NORMAL)
                    self.select_folder_button.config(state=tk.NORMAL)
                    self.stop_scan_button.config(state=tk.DISABLED)
                    self.pause_scan_button.config(state=tk.DISABLED)
                    self.resume_scan_button.config(state=tk.DISABLED)
                    logging.info("Scan aborted.")
                elif mtype == "monitor_malware":
                    file_path, virus_info = data
                    message = "Malicious file auto-quarantined:\n{} ({})".format(file_path, virus_info)
                    self.malicious_list.insert(tk.END, message)
                    notify_user(file_path, virus_info)
                    logging.info("Real-time malware detection: " + message)
                    messagebox.showinfo("Monitor Event", message)
                self.queue.task_done()
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def on_close(self):
        logging.info("Application closing.")
        if self.scan_thread:
            self.scan_thread.stop()
            logging.info("Scan thread stopped.")
        if self.monitor_thread:
            self.monitor_thread.stop()
            logging.info("Monitor thread stopped.")
        self.destroy()

if __name__ == "__main__":
    app = MainApplication()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
