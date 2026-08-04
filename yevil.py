#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (Flawless Overwrite Engine)
"""

import os
import sys
import subprocess
import time
import signal
import csv
import select
import shutil
import math
import re
from collections import defaultdict

# ============================================
# ANSI COLORS
# ============================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
STOP_SCANNING = False
CSV_PREFIX = '/tmp/yevil_scan'

# ============================================
# CLEANUP
# ============================================

def cleanup():
    global MONITOR_INTERFACE, SCANNER_PROCESS
    print("\n[+] Cleaning up...")
    if SCANNER_PROCESS:
        try:
            SCANNER_PROCESS.terminate()
            time.sleep(0.5)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
        except:
            pass
        SCANNER_PROCESS = None

    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    if MONITOR_INTERFACE:
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', MONITOR_INTERFACE, 'down'],
                           capture_output=True, check=False)
            subprocess.run(['sudo', 'iw', 'dev', MONITOR_INTERFACE, 'set', 'type', 'managed'],
                           capture_output=True, check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', MONITOR_INTERFACE, 'up'],
                           capture_output=True, check=False)
            print(f"[+] {MONITOR_INTERFACE} reset to managed mode")
        except:
            pass
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                           capture_output=True, check=False)
            print("[+] NetworkManager restarted")
        except:
            pass
    print("[+] Cleanup complete!")

def signal_handler(sig, frame):
    global STOP_SCANNING
    STOP_SCANNING = True

# ============================================
# ADAPTER FUNCTIONS
# ============================================

def detect_adapters():
    print("\n[+] Detecting wireless adapters...")
    adapters = []
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                adapter = line.split()[0]
                if adapter not in adapters and 'mon' not in adapter:
                    adapters.append(adapter)
    except:
        pass
    return adapters

def set_monitor_mode(adapter):
    global MONITOR_INTERFACE
    print(f"\n[+] Setting {adapter} to monitor mode...")
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True, text=True)
        time.sleep(1)
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'],
                       check=True, capture_output=True)
        subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'],
                       check=True, capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'],
                       check=True, capture_output=True)
        MONITOR_INTERFACE = adapter
        result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            print(f"[+] ✅ {adapter} is now in MONITOR MODE!")
            return True
        else:
            print("[!] Monitor mode not verified!")
            return False
    except Exception as e:
        print(f"[-] Failed: {e}")
        return False

# ============================================
# CSV PARSER
# ============================================

def parse_networks(csv_file):
    networks = []
    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 14:
                    continue
                if row[0] == 'BSSID':
                    continue
                bssid = row[0].strip()
                if not bssid:
                    continue
                networks.append({
                    'bssid': bssid,
                    'channel': row[3],
                    'privacy': row[5],
                    'cipher': row[6],
                    'authentication': row[7],
                    'power': row[8],
                    'ssid': row[13].strip() if len(row) > 13 and row[13].strip() else '<Hidden>'
                })
    except:
        pass
    return networks

def parse_stations(csv_file):
    clients = defaultdict(int)
    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 6:
                    continue
                if row[0] == 'Station MAC':
                    continue
                bssid = row[5].strip()
                if bssid:
                    clients[bssid.upper()] += 1
    except:
        pass
    return clients

# ============================================
# BULLETPROOF TABLE BUILDER (No terminal wrapping)
# ============================================

def safe_truncate(text, max_len):
    """Truncates text to ensure it stays under max_len, avoiding terminal wraps."""
    clean_text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    if len(clean_text) <= max_len:
        return text
    # Since ESSID is plain text (unless Hidden), this safe slice works beautifully
    return text[:max_len-3] + "..."

def build_table(networks, clients, term_width):
    # Sort by signal strength
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    # Fixed character column widths (including spaces)
    FIXED_WIDTH = 4 + 1 + 17 + 1 + 4 + 1 + 6 + 1 + 8 + 1 + 8 + 1 + 10 + 1 + 6 # 71 chars
    essid_width = max(5, term_width - FIXED_WIDTH - 3) # Adjust for breathing room

    lines = []
    
    # 1. Title
    title = f"{CYAN}YEVIL - Real-Time WiFi Scanner (Networks found: {len(networks)}){RESET}"
    lines.append(title)

    # 2. Headers (Using a manual space calculation so columns align perfectly)
    header = f"{BOLD}{YELLOW}{'#':<4} {'ESSID':<{essid_width}} {'BSSID':<17} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}{RESET}"
    lines.append(header)

    # 3. Rows
    for idx, net in enumerate(networks_sorted, 1):
        pwr_val = net['power']
        try:
            pwr = int(pwr_val)
            pwr_color = GREEN if pwr > -50 else YELLOW if pwr > -65 else RED
        except:
            pwr_color = WHITE

        ssid = net['ssid']
        if ssid == '<Hidden>':
            ssid_display = f"{RED}{ssid}{RESET}"
        else:
            ssid_display = ssid
        
        # Safe truncation prevents terminal wrapping at ANY terminal width
        ssid_display = safe_truncate(ssid_display, essid_width)

        client_count = clients.get(net['bssid'].upper(), 0)

        row = (f"{GREEN}{idx:<4}{RESET} "
               f"{ssid_display:<{essid_width}} "
               f"{MAGENTA}{net['bssid']:<17}{RESET} "
               f"{CYAN}{net['channel']:<4}{RESET} "
               f"{pwr_color}{pwr_val:<6}{RESET} "
               f"{WHITE}{net['privacy']:<8}{RESET} "
               f"{WHITE}{net['cipher']:<8}{RESET} "
               f"{WHITE}{net['authentication']:<10}{RESET} "
               f"{GREEN}{client_count:<6}{RESET}")
        
        lines.append(row)

    # 4. Footer
    footer = f"{BOLD}{YELLOW}Press 'q' to stop scanning and show results{RESET}"
    lines.append(footer)

    return lines

# ============================================
# FLAWLESS OVERWRITE LOGIC (No Clear Screen)
# ============================================

def update_display(old_lines, new_lines):
    """Replaces old lines with new lines in-place, leaving zero artifacts."""
    if not old_lines:
        sys.stdout.write('\n'.join(new_lines) + '\n')
        sys.stdout.flush()
        return

    # Move cursor up the exact number of lines printed previously
    sys.stdout.write(f'\033[{len(old_lines)}A')

    # Write new lines and clear trailing old lines
    max_len = max(len(old_lines), len(new_lines))
    for i in range(max_len):
        sys.stdout.write('\033[2K')  # Erase entire current line
        
        if i < len(new_lines):
            sys.stdout.write(new_lines[i])
        else:
            sys.stdout.write('') # Write blank to clear the old line completely

        if i < max_len - 1:
            sys.stdout.write('\n')
    
    sys.stdout.flush()

# ============================================
# SCANNER LOOP
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg',
           '--output-format', 'csv',
           '--write', CSV_PREFIX,
           '--write-interval', '1']
    
    print(f"\n[+] Running: {' '.join(cmd)}")
    print("[+] Starting real-time UI (Preserves previous command history)...")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return

    time.sleep(2) # Wait for first CSV

    last_networks = []
    last_clients = defaultdict(int)
    old_lines = []
    last_width = 0

    # Set stdin to non-blocking for 'q' detection
    import fcntl, termios
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    while not STOP_SCANNING:
        # Detect 'q' input
        try:
            ch = sys.stdin.read(1)
            if ch.lower() == 'q':
                STOP_SCANNING = True
                break
        except (BlockingIOError, ValueError):
            pass

        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            time.sleep(0.2)
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)
        current_width = shutil.get_terminal_size().columns

        if networks != last_networks or clients != last_clients or current_width != last_width:
            new_lines = build_table(networks, clients, current_width)
            
            if new_lines != old_lines or current_width != last_width:
                update_display(old_lines, new_lines)
                old_lines = new_lines
                last_width = current_width
                last_networks = networks
                last_clients = clients
        
        time.sleep(0.3)

    # Kill process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(0.5)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██╗   ██╗███████╗██╗   ██╗██╗██╗                          ║
║    ╚██╗ ██╔╝██╔════╝██║   ██║██║██║                          ║
║     ╚████╔╝ █████╗  ██║   ██║██║██║                          ║
║      ╚██╔╝  ██╔══╝  ╚██╗ ██╔╝██║██║                          ║
║       ██║   ███████╗ ╚████╔╝ ██║███████╗                     ║
║       ╚═╝   ╚══════╝  ╚═══╝  ╚═╝╚══════╝                     ║
║                                                               ║
║           WiFi Security Testing Tool                          ║
║           ⚠️  For Educational Purposes Only!                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
""")
    print("[+] Yevil - WiFi Security Testing Tool")
    print("[+] For Educational Purposes Only!")
    print("="*50)

    if os.geteuid() != 0:
        print("[!] This tool requires root privileges!")
        print("[!] Please run with: sudo python3 yevil.py")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        print("\n[!] No wireless adapters detected!")
        sys.exit(1)

    print("\n[+] Detected Adapters:")
    for i, adapter in enumerate(adapters, 1):
        print(f"   {i}. {adapter}")

    print()
    while True:
        try:
            choice = input("[?] Select adapter (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
        except:
            pass
        print("[-] Invalid selection!")

    print(f"\n[+] Selected: {selected}")

    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
    if 'Mode:Monitor' in result.stdout:
        print("[+] Already in monitor mode")
        monitor_adapter = selected
    else:
        print("[!] Adapter is not in monitor mode!")
        set_mon = input("\n[?] Set monitor mode now? (y/n): ")
        if set_mon.lower() == 'y':
            if set_monitor_mode(selected):
                monitor_adapter = selected
            else:
                print("[!] Failed to set monitor mode!")
                sys.exit(1)
        else:
            print("[+] Exiting...")
            sys.exit(0)

    # Start scan
    start_scanner(monitor_adapter)

    # The table is already beautifully printed on the screen, so we just ask below it!
    print() # Move cursor down to a fresh line
    print("="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup()
    else:
        print("[+] Adapter remains in monitor mode")
        print(f"[+] Manual cleanup: sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up")

    print("\n[+] Done!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[+] Ctrl+C detected. Cleaning up...")
        cleanup()
        print("[+] Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        cleanup()
        sys.exit(1)
