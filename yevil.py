#!/usr/bin/env python3
"""
Yevil - Live WiFi Scanner (curses TUI engine - Wifite style)
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
    # We only set the flag here. The main curses loop will break cleanly and restore the terminal.
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
# CURSES UI DRAWING ENGINE (Wifite-style Responsive)
# ============================================

def draw_ui(stdscr, networks, clients):
    # Get current terminal dimensions
    height, width = stdscr.getmaxyx()
    stdscr.clear()

    # Define color pairs for curses
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Strong signal
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Medium signal
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Weak signal / Hidden
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Titles / Channels
    curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # BSSID
    curses.init_pair(6, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Headers / Footers
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Standard text

    # --- 1. Title ---
    title = f"YEVIL - Real-Time WiFi Scanner (Networks found: {len(networks)})"
    try:
        stdscr.addstr(0, max(0, (width - len(title)) // 2), title, curses.color_pair(4) | curses.A_BOLD)
    except:
        pass

    # --- 2. Headers (Automatically truncated by curses/width to prevent wrapping) ---
    header = f"{'#':<4} {'ESSID':<30} {'BSSID':<17} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
    try:
        stdscr.addstr(1, 0, header[:width-1], curses.color_pair(6) | curses.A_BOLD)
    except:
        pass

    # --- 3. Data Rows ---
    try:
        networks_sorted = sorted(networks,
                                 key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                 reverse=True)
    except:
        networks_sorted = networks

    row_y = 2
    for idx, net in enumerate(networks_sorted, 1):
        if row_y >= height - 1:
            break

        # Determine power color
        pwr_val = net['power']
        try:
            pwr = int(pwr_val)
            if pwr > -50: pwr_color = 1
            elif pwr > -65: pwr_color = 2
            else: pwr_color = 3
        except:
            pwr_color = 7

        # Determine SSID color
        ssid = net['ssid']
        is_hidden = ssid == '<Hidden>'
        ssid_color = 3 if is_hidden else 4

        # Write each column individually, strictly truncating to prevent screen overflow
        x = 0
        try: stdscr.addstr(row_y, x, f"{idx:<4}", curses.color_pair(1))
        except: pass
        x += 4

        try: stdscr.addstr(row_y, x, f"{ssid[:30]:<30}"[:width - x - 1], curses.color_pair(ssid_color))
        except: pass
        x += 30

        try: stdscr.addstr(row_y, x, f"{net['bssid']:<17}"[:width - x - 1], curses.color_pair(5))
        except: pass
        x += 17

        try: stdscr.addstr(row_y, x, f"{net['channel']:<4}", curses.color_pair(4))
        except: pass
        x += 4

        try: stdscr.addstr(row_y, x, f"{pwr_val:<6}", curses.color_pair(pwr_color))
        except: pass
        x += 6

        try: stdscr.addstr(row_y, x, f"{net['privacy']:<8}", curses.color_pair(7))
        except: pass
        x += 8

        try: stdscr.addstr(row_y, x, f"{net['cipher']:<8}", curses.color_pair(7))
        except: pass
        x += 8

        try: stdscr.addstr(row_y, x, f"{net['authentication']:<10}", curses.color_pair(7))
        except: pass
        x += 10

        try: stdscr.addstr(row_y, x, f"{clients.get(net['bssid'], 0):<6}", curses.color_pair(1))
        except: pass

        row_y += 1

    # --- 4. Footer ---
    footer = "Press Ctrl+C to stop scanning"
    try:
        stdscr.addstr(height-1, max(0, (width - len(footer)) // 2), footer, curses.color_pair(6) | curses.A_BLINK)
    except:
        pass
    
    stdscr.refresh()

# ============================================
# SCANNER LOOP (curses wrapper engine)
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
        return

    # Wait for first CSV
    time.sleep(2)

    last_networks = []
    last_clients = {}

    # Set terminal to non-blocking getch
    stdscr.nodelay(1)
    stdscr.timeout(500) # Check every 500ms for keyboard input
    
    while not STOP_SCANNING:
        # Check for explicit 'q' quit, but keep Ctrl+C as the primary exit
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q'):
            STOP_SCANNING = True
            break

        csv_file = f'{CSV_PREFIX}-01.csv'
        if not os.path.exists(csv_file):
            # Briefly wait until airodump writes the file
            time.sleep(0.1)
            continue

        networks = parse_networks(csv_file)
        clients = parse_stations(csv_file)

        if networks != last_networks or clients != last_clients:
            draw_ui(stdscr, networks, clients)
            last_networks = networks
            last_clients = clients

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

    # Run the curses engine inside a wrapper (guarantees 100% clean reset on exit)
    try:
        curses.wrapper(start_scanner, monitor_adapter)
    except KeyboardInterrupt:
        # If user presses Ctrl+C aggressively outside the loop, pass to our cleanup
        pass

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
    except Exception as e:
        print(f"\n[-] Error: {e}")
        cleanup()
        sys.exit(1)
