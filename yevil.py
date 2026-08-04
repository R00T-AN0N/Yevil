#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (ANSI TUI - Preserves scrollback)
"""

import os
import sys
import subprocess
import time
import signal
import csv
import select
import shutil
from collections import defaultdict

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
STOP_SCANNING = False
CSV_PREFIX = '/tmp/yevil_scan'

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
                    clients[bssid] += 1
    except:
        pass
    return clients

# ============================================
# ANSI TABLE DRAWING ENGINE (Preserves terminal scrollback)
# ============================================

def draw_table(networks, clients, width):
    # Sort networks by signal strength
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    # Uppercase BSSIDs for client matching
    clients_upper = {k.upper(): v for k, v in clients.items()}

    # Calculate dynamic ESSID width to prevent line wrapping
    essid_width = 30
    base_width = 4 + essid_width + 17 + 4 + 6 + 8 + 8 + 10 + 6 # 93 total
    if width < base_width:
        essid_width = max(10, essid_width - (base_width - width))

    lines = []

    # 1. Empty state
    if not networks_sorted:
        lines.append(f"{CYAN}YEVIL - Real-Time WiFi Scanner (Scanning...){RESET}")
        lines.append("")
        lines.append(f"{WHITE}Waiting for access points...{RESET}")
        lines.append("")
        lines.append(f"{BOLD}{YELLOW}Press 'q' to stop scanning and show results{RESET}")
        return lines

    # 2. Title
    title = f"YEVIL - Real-Time WiFi Scanner (Networks found: {len(networks)})"
    lines.append(f"{CYAN}{title}{RESET}")

    # 3. Headers
    header = f"{'#':<4} {'ESSID':<{essid_width}} {'BSSID':<17} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
    lines.append(f"{BOLD}{YELLOW}{header}{RESET}")

    # 4. Data
    for idx, net in enumerate(networks_sorted, 1):
        pwr_val = net['power']
        try:
            pwr = int(pwr_val)
            if pwr > -50: pwr_color = GREEN
            elif pwr > -65: pwr_color = YELLOW
            else: pwr_color = RED
        except:
            pwr_color = WHITE

        ssid = net['ssid']
        if ssid == '<Hidden>':
            ssid_display = f"{RED}{ssid}{RESET}"
        else:
            ssid_display = ssid

        # Truncate ESSID strictly
        if len(ssid_display) > essid_width:
            ssid_display = ssid_display[:essid_width-3] + "..."

        client_count = clients_upper.get(net['bssid'].upper(), 0)

        row = (f"{idx:<4} "
               f"{ssid_display:<{essid_width}} "
               f"{MAGENTA}{net['bssid']:<17}{RESET} "
               f"{CYAN}{net['channel']:<4}{RESET} "
               f"{pwr_color}{pwr_val:<6}{RESET} "
               f"{WHITE}{net['privacy']:<8}{RESET} "
               f"{WHITE}{net['cipher']:<8}{RESET} "
               f"{WHITE}{net['authentication']:<10}{RESET} "
               f"{GREEN}{client_count:<6}{RESET}")
        
        # Prevent entire row from wrapping
        lines.append(row[:width])

    # 5. Footer
    footer = f"Press 'q' to stop scanning and show results"
    lines.append(f"{BOLD}{YELLOW}{footer}{RESET}")

    return lines

# ============================================
# SCANNER LOOP (Pure ANSI - No curses)
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    # Clean old CSVs
    for f in [f'{CSV_PREFIX}-01.csv', f'{CSV_PREFIX}-01.kismet.csv']:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg',
           '--output-format', 'csv',
           '--write', CSV_PREFIX,
           '--write-interval', '1']
    
    print(f"\n[+] Running: {' '.join(cmd)}")
    print("[+] Starting real-time UI (Scrollback preserved)...")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return

    time.sleep(2)

    last_networks = []
    last_clients = defaultdict(int)
    last_lines = []

    while not STOP_SCANNING:
        # Non-blocking check for 'q' input
        rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
        if rlist:
            ch = sys.stdin.read(1)
            if ch.lower() == 'q':
                STOP_SCANNING = True
                break

        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            time.sleep(0.1)
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)

        if networks != last_networks or clients != last_clients:
            width = shutil.get_terminal_size().columns
            new_lines = draw_table(networks, clients, width)

            if not last_lines:
                # First time printing: Just print normally
                sys.stdout.write('\n'.join(new_lines) + '\n')
            else:
                # Guaranteed overwrite engine (handles growing/shrinking tables without artifacts)
                max_len = max(len(last_lines), len(new_lines))
                
                # Pad both lists to the exact same length
                last_padded = last_lines + [''] * (max_len - len(last_lines))
                new_padded = new_lines + [''] * (max_len - len(new_lines))

                # Move up exactly max_len lines
                sys.stdout.write(f"\033[{max_len}A")
                # Overwrite the entire block, clearing each line to the end
                for i, line in enumerate(new_padded):
                    sys.stdout.write(line + "\033[K")
                    if i < max_len - 1:
                        sys.stdout.write("\n")

            sys.stdout.flush()
            last_networks = networks
            last_clients = clients
            last_lines = new_lines

    # Kill scanner process
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
║           WiFi Security Testing Tool (ANSI TUI)               ║
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

    # Start the scanner
    start_scanner(monitor_adapter)

    # Because we did NOT clear the screen, the final table is already there!
    # We just print the cleanup prompt directly underneath it.
    print("\n" + "="*50)
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
