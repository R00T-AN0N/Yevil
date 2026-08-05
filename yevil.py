#!/usr/bin/env python3
"""
Yevil - Static WiFi Scanner (new networks = new rows, no flicker)
"""

import os
import sys
import subprocess
import time
import signal
import csv
from collections import defaultdict

# ============================================
# COLOURS
# ============================================

class Colors:
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    cyan = '\033[96m'
    white = '\033[97m'
    reset = '\033[0m'
    bold = '\033[1m'
    clear = '\033[2J\033[H'

    @staticmethod
    def print_colored(text, color='white', bold=False):
        style = Colors.bold if bold else ''
        print(f"{style}{getattr(Colors, color, '')}{text}{Colors.reset}")

# ============================================
# BANNER
# ============================================

BANNER = f"""
{Colors.cyan}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██╗   ██╗███████╗██╗   ██╗██╗██╗                          ║
║    ╚██╗ ██╔╝██╔════╝██║   ██║██║██║                          ║
║     ╚████╔╝ █████╗  ██║   ██║██║██║                          ║
║      ╚██╔╝  ██╔══╝  ╚██╗ ██╔╝██║██║                          ║
║       ██║   ███████╗ ╚████╔╝ ██║███████╗                     ║
║       ╚═╝   ╚══════╝  ╚═══╝  ╚═╝╚══════╝                     ║
║                                                               ║
║           WiFi Security Testing Tool v2.0.0                   ║
║           ⚠️  For Educational Purposes Only!                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.reset}
"""

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
    print("\n[!] Ctrl+C detected")
    STOP_SCANNING = True
    cleanup()
    print("\n[+] Goodbye!")
    sys.exit(0)

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
# CSV PARSERS
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
                    'beacons': row[9],
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
                if len(row) < 8:
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
# STATIC TABLE DISPLAY
# ============================================

def draw_static_table(networks, clients):
    """Draw a single static table (clears screen once, then prints everything)."""
    sys.stdout.write(Colors.clear)
    sys.stdout.flush()

    print(f"{Colors.cyan}{'='*120}")
    print(f"  YEVIL - Static WiFi Scanner".center(120))
    print(f"  Networks found: {len(networks)}".center(120))
    print(f"{'='*120}{Colors.reset}")

    header = f"{Colors.bold}{Colors.yellow}"
    header += f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
    header += f"{Colors.reset}"
    print(header)
    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")

    # Sort by signal strength (optional)
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    for idx, net in enumerate(networks_sorted, 1):
        try:
            pwr = int(net['power'])
            color = 'green' if pwr > -50 else 'yellow' if pwr > -65 else 'red'
        except:
            color = 'white'

        ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
        if ssid == '':
            ssid = '<Hidden>'
        client_count = clients.get(net['bssid'], 0)

        row = f"{idx:<4} {ssid:<30} {net['bssid']:<18} {net['channel']:<4} "
        row += f"{net['power']:<6} {net['privacy']:<8} {net['cipher']:<8} {net['authentication']:<10} {client_count:<6}"
        Colors.print_colored(row, color)

    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
    print(f"{Colors.white}Press Ctrl+C to stop scanning (new networks will appear below){Colors.reset}")
    print(f"{Colors.cyan}{'='*120}{Colors.reset}")

# ============================================
# SCANNER LOOP (only add new rows when new BSSID appears)
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
    print("[+] Scanning... Press Ctrl+C to stop.")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return

    # Wait for first CSV
    time.sleep(2)

    seen_bssids = set()
    all_networks = []
    all_clients = defaultdict(int)

    while not STOP_SCANNING:
        time.sleep(0.5)  # check frequently
        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)

        # Look for new BSSIDs
        new_bssids = set(net['bssid'] for net in networks) - seen_bssids
        if new_bssids:
            seen_bssids.update(new_bssids)
            # Add all networks (in case of update)
            # We'll rebuild the full list from the new CSV
            all_networks = networks  # replace with latest
            all_clients = clients
            # Redraw the whole table
            draw_static_table(all_networks, all_clients)

    # Cleanup process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(1)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    Colors.print_colored("[+] Yevil - WiFi Security Testing Tool", 'cyan', True)
    Colors.print_colored("[+] For Educational Purposes Only!", 'yellow')
    print("="*50)

    if os.geteuid() != 0:
        Colors.print_colored("[!] This tool requires root privileges!", 'red')
        Colors.print_colored("[!] Please run with: sudo python3 yevil.py", 'yellow')
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        Colors.print_colored("\n[!] No wireless adapters detected!", 'red')
        sys.exit(1)

    Colors.print_colored("\n📋 Detected Adapters:", 'cyan', True)
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
        Colors.print_colored("[-] Invalid selection!", 'red')

    Colors.print_colored(f"\n[+] Selected: {selected}", 'green')

    # Check mode
    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
    if 'Mode:Monitor' in result.stdout:
        Colors.print_colored("[+] Already in monitor mode", 'green')
        monitor_adapter = selected
    else:
        Colors.print_colored("[!] Adapter is not in monitor mode!", 'yellow')
        set_mon = input("\n[?] Set monitor mode now? (y/n): ")
        if set_mon.lower() == 'y':
            if set_monitor_mode(selected):
                monitor_adapter = selected
            else:
                Colors.print_colored("[!] Failed to set monitor mode!", 'red')
                sys.exit(1)
        else:
            Colors.print_colored("[+] Exiting...", 'yellow')
            sys.exit(0)

    start_scanner(monitor_adapter)

    print("\n" + "="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup()
    else:
        Colors.print_colored("[+] Adapter remains in monitor mode", 'yellow')
        Colors.print_colored(f"[+] Manual cleanup: sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up", 'yellow')

    Colors.print_colored("\n[+] Done!", 'green', True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Ctrl+C detected. Cleaning up...", 'yellow')
        cleanup()
        Colors.print_colored("[+] Goodbye!", 'cyan', True)
        sys.exit(0)
    except Exception as e:
        Colors.print_colored(f"\n[-] Error: {e}", 'red')
        cleanup()
        sys.exit(1)
