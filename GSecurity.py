import os
import time
import psutil
import ctypes
import shutil
import logging
import threading
import hashlib
import aiohttp
import asyncio
from win32com.client import Dispatch
import win32api
import win32con
import win32security
import win32process
from pathlib import Path
from psutil import AccessDenied, NoSuchProcess, ZombieProcess

# Constants
VIRUSTOTAL_API_KEY = 'your_api_key_here'
LOG_FILE = "antivirus_dll_monitor.log"
QUARANTINE_DIR = "C:\\Quarantine"
WHITELIST_PATHS = ["C:\\Windows\\System32", "C:\\Program Files"]
SUSPICIOUS_PATHS = ["\\Temp", "\\AppData"]
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5
BLOCKED_URLS_FILE = "blocked_urls.txt"
SUSPICIOUS_APIS = ["SetWindowsHookExW", "CreateRemoteThread"]
OVERLAY_KEYWORDS = ["overlay", "hook", "dll"]
PROTECTED_DRIVERS = ["intel", "amd", "nvidia", "realtek"]
CACHE_FILE = "vt_cache.json"
CACHE_EXPIRY = 3600  # in seconds

# Setup Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger('CombinedAntivirus')

# Load and Save Cache
def load_cache():
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading cache: {e}")
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        logger.error(f"Error saving cache: {e}")

# DLL Monitoring Functions
def get_loaded_dlls(pid):
    dlls = []
    try:
        h_process = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid)
        if not h_process:
            return dlls
        
        modules = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        
        if ctypes.windll.psapi.EnumProcessModules(h_process, ctypes.byref(modules), ctypes.sizeof(modules), ctypes.byref(needed)):
            count = needed.value // ctypes.sizeof(ctypes.c_void_p)
            for i in range(count):
                module_name = ctypes.create_unicode_buffer(260)
                ctypes.windll.psapi.GetModuleFileNameExW(h_process, modules[i], module_name, 260)
                dlls.append(module_name.value)
        
        ctypes.windll.kernel32.CloseHandle(h_process)
    except Exception as e:
        logger.error(f"Error retrieving DLLs for PID {pid}: {e}")
    return dlls

def analyze_dll(dll_path):
    if any(dll_path.startswith(path) for path in WHITELIST_PATHS):
        return False
    if any(path in dll_path for path in SUSPICIOUS_PATHS):
        return True
    if any(driver in dll_path.lower() for driver in PROTECTED_DRIVERS):
        return False
    try:
        signer = Dispatch("Scripting.Signer")
        return not signer.Verify(dll_path)
    except Exception as e:
        logger.warning(f"Could not verify signature for {dll_path}: {e}")
        return True

def quarantine_item(item_path):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(item_path))
        shutil.move(item_path, quarantine_path)
        logger.info(f"Quarantined: {item_path}")
    except Exception as e:
        logger.error(f"Failed to quarantine {item_path}: {e}")

# Advanced Keylogger Detection
def detect_keylogger():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
            if handle:
                modules = win32process.EnumProcessModules(handle)
                for module in modules:
                    module_name = os.path.basename(win32process.GetModuleFileNameEx(handle, module)).lower()
                    if "keyboard" in module_name or "keylog" in module_name:
                        logger.warning(f"Detected potential keylogger: {module_name} in process {proc.info['name']} (PID: {pid})")
                        terminate_process(pid, proc.info['name'])
                        quarantine_item(module_name)
                win32api.CloseHandle(handle)
        except Exception as e:
            logger.error(f"Error checking for keylogger in process {proc.info.get('name', '')}: {e}")

# Overlay Detection and Termination
def detect_overlays():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in OVERLAY_KEYWORDS):
                logger.warning(f"Detected overlay: {name} (PID: {pid})")
                terminate_process(pid, name)
                quarantine_item(name)
        except (AccessDenied, NoSuchProcess, ZombieProcess) as e:
            logger.error(f"Error accessing process {proc.info.get('name', '')}: {e}")

# Antivirus and DLL Scanning Async Task
async def scan_file(session, file_path, cache):
    try:
        file_hash = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()
        current_time = time.time()

        if file_hash in cache and current_time - cache[file_hash]['timestamp'] < CACHE_EXPIRY:
            logger.info(f"File {file_path} found in cache. Skipping upload.")
            return

        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                logger.info(f"File {file_path} already scanned by others.")
                cache[file_hash] = {'timestamp': current_time, 'status': 'scanned'}
            else:
                async with session.post('https://www.virustotal.com/api/v3/files', headers=headers, files={'file': open(file_path, 'rb')}) as upload_response:
                    if upload_response.status == 200:
                        logger.info(f"File {file_path} uploaded for scanning.")
                        cache[file_hash] = {'timestamp': current_time, 'status': 'uploaded'}
    except PermissionError:
        logger.warning(f"Permission denied for file {file_path}. Skipping.")
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {e}")

async def antivirus_scan():
    cache = load_cache()
    async with aiohttp.ClientSession() as session:
        for root, _, files in os.walk("C:\\"):
            for file in files:
                await scan_file(session, os.path.join(root, file), cache)
    save_cache(cache)

# Process Termination
def terminate_process(pid, name):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
        if handle:
            logger.info(f"Terminating process {name} (PID: {pid})")
            win32api.TerminateProcess(handle, 0)
            win32api.CloseHandle(handle)
        if any(driver in name.lower() for driver in PROTECTED_DRIVERS):
            logger.info(f"Protected driver skipped: {name} (PID: {pid})")
            return
        quarantine_item(name)
    except Exception as e:
        logger.error(f"Failed to terminate process {name} (PID: {pid}): {e}")

# Main Execution
def main():
    dll_monitor_thread = threading.Thread(target=dll_monitor, daemon=True)
    dll_monitor_thread.start()

    keylogger_thread = threading.Thread(target=detect_keylogger, daemon=True)
    keylogger_thread.start()

    overlay_thread = threading.Thread(target=detect_overlays, daemon=True)
    overlay_thread.start()

    asyncio.run(antivirus_scan())

def dll_monitor():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                dlls = get_loaded_dlls(proc.info['pid'])
                for dll in dlls:
                    if analyze_dll(dll):
                        logger.warning(f"Suspicious DLL detected: {dll}")
                        quarantine_item(dll)
            except Exception as e:
                logger.error(f"Error monitoring process {proc.info.get('name', '')}: {e}")
        time.sleep(10)

if __name__ == "__main__":
    main()
