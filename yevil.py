#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (curses TUI with final result printing)
"""

import os
import sys
import subprocess
import time
import signal
import csv
import curses
from collections import defaultdict

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
                    clients[bssid] += 1
    except:
        pass
    return clients

# ============================================
# CURSES UI DRAWING ENGINE (Resilient to resizing)
# ============================================

def write(stdscr, y, x, text, color):
    """Safely writes text to a specific coordinate without crashing on overflow."""
    h, w = stdscr.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    max_len = w - x
    if max_len <= 0:
        return
    try:
        stdscr.addstr(y, x, text[:max_len], color)
    except curses.error:
        pass

def draw_ui(stdscr, networks, clients):
    # Get terminal dimensions
    height, width = stdscr.getmaxyx()
    stdscr.clear()

    # Define colors
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Strong signal
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Medium signal
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Weak signal / Hidden
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Titles
    curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # BSSID
    curses.init_pair(6, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Headers
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Normal text

    # 1. Title
    title = f"YEVIL - Real-Time WiFi Scanner (Networks found: {len(networks)})"
    write(stdscr, 0, max(0, (width - len(title)) // 2), title, curses.color_pair(4) | curses.A_BOLD)

    # 2. Headers
    header = f"{'#':<4} {'ESSID':<30} {'BSSID':<17} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
    write(stdscr, 1, 0, header, curses.color_pair(6) | curses.A_BOLD)

    # 3. Data Sorting
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    # Create uppercase mapping for BSSIDs to avoid case mismatch
    clients_bssid_upper = {k.upper(): v for k, v in clients.items()}

    row_y = 2
    for idx, net in enumerate(networks_sorted, 1):
        if row_y >= height - 1:
            break

        pwr_val = net['power']
        try:
            pwr = int(pwr_val)
            pwr_color = 1 if pwr > -50 else (2 if pwr > -65 else 3)
        except:
            pwr_color = 7

        ssid = net['ssid']
        ssid_color = 3 if ssid == '<Hidden>' else 4

        # Safely write each column respecting terminal width
        x = 0
        write(stdscr, row_y, x, f"{idx:<4}", curses.color_pair(1))
        x += 4
        write(stdscr, row_y, x, f"{ssid:<30}", curses.color_pair(ssid_color))
        x += 30
        write(stdscr, row_y, x, f"{net['bssid']:<17}", curses.color_pair(5))
        x += 17
        write(stdscr, row_y, x, f"{net['channel']:<4}", curses.color_pair(4))
        x += 4
        write(stdscr, row_y, x, f"{pwr_val:<6}", curses.color_pair(pwr_color))
        x += 6
        write(stdscr, row_y, x, f"{net['privacy']:<8}", curses.color_pair(7))
        x += 8
        write(stdscr, row_y, x, f"{net['cipher']:<8}", curses.color_pair(7))
        x += 8
        write(stdscr, row_y, x, f"{net['authentication']:<10}", curses.color_pair(7))
        x += 10
        write(stdscr, row_y, x, f"{clients_bssid_upper.get(net['bssid'].upper(), 0):<6}", curses.color_pair(1))

        row_y += 1

    # 4. Footer
    footer = "Press Ctrl+C or 'q' to stop scanning"
    write(stdscr, height-1, max(0, (width - len(footer)) // 2), footer, curses.color_pair(6) | curses.A_BLINK)
    stdscr.refresh()

# ============================================
# SCANNER LOOP (returns data for final print)
# ============================================

def start_scanner(stdscr, adapter):
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
    print("[+] Starting real-time UI...")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return [], {}

    time.sleep(2)

    last_networks = []
    last_clients = defaultdict(int)

    stdscr.nodelay(1)
    stdscr.timeout(500)

    while not STOP_SCANNING:
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q'):
            STOP_SCANNING = True
            break

        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            time.sleep(0.1)
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)

        if networks != last_networks or clients != last_clients:
            draw_ui(stdscr, networks, clients)
            last_networks = networks
            last_clients = clients

    # Kill the airodump process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(0.5)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

    # PAUSE SO THE USER CAN READ THE FINAL TABLE
    height, width = stdscr.getmaxyx()
    stdscr.nodelay(0)
    msg = "Scan complete. Press ANY KEY to return to the terminal with results..."
    write(stdscr, height-1, max(0, (width - len(msg)) // 2), msg, curses.color_pair(6) | curses.A_BLINK)
    stdscr.refresh()
    stdscr.getch()

    return last_networks, last_clients

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
║           WiFi Security Testing Tool (curses TUI)             ║
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

    # Check mode
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

    # Start curses
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.start_color()

    # Run the engine
    networks, clients = start_scanner(stdscr, monitor_adapter)

    # Clean up curses (this wipes the screen, but we save the data)
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()

    # ==========================================
    # PRINT FINAL RESULTS TO TERMINAL
    # ==========================================
    print("\n" + "="*50)
    if networks:
        print("\n[+] Final Scan Results:")
        print("-" * 84)
        print(f"{'#':<4} {'ESSID':<30} {'BSSID':<17} {'CH':<4} {'PWR':<6} {'CLIENTS':<6}")
        print("-" * 84)
        try:
            networks_sorted = sorted(networks,
                                     key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                     reverse=True)
        except:
            networks_sorted = networks

        for idx, net in enumerate(networks_sorted, 1):
            client_count = clients.get(net['bssid'], 0)
            print(f"{idx:<4} {net['ssid'][:30]:<30} {net['bssid']:<17} {net['channel']:<4} {net['power']:<6} {client_count:<6}")
    else:
        print("\n[!] No networks were found during the scan.")

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
