#!/usr/bin/env python3
"""
Yevil - Clean Real‑time WiFi Scanner (Curses-based TUI)
Single clean table, color-coded, no scrolling or overlapping headers.
"""

import os
import sys
import subprocess
import re
import time
import signal
import glob
import curses
from collections import defaultdict

# ============================================
# GLOBALS
# ============================================

MONITOR_INTERFACE = None
SCANNER_PROCESS = None
CSV_PREFIX = "/tmp/yevil_scan"

networks = {}               # bssid -> {ssid, bssid, power, channel, encryption}
clients = defaultdict(set)  # bssid -> set of station MACs

# ============================================
# CLEANUP & UTILITIES
# ============================================

def cleanup_files():
    for f in glob.glob(f"{CSV_PREFIX}*"):
        try:
            os.remove(f)
        except:
            pass

def cleanup():
    global MONITOR_INTERFACE, SCANNER_PROCESS
    if SCANNER_PROCESS:
        try:
            SCANNER_PROCESS.terminate()
            time.sleep(0.3)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
        except:
            pass
        SCANNER_PROCESS = None

    cleanup_files()

    if MONITOR_INTERFACE:
        try:
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'down'], capture_output=True)
            subprocess.run(['iw', 'dev', MONITOR_INTERFACE, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['ip', 'link', 'set', MONITOR_INTERFACE, 'up'], capture_output=True)
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
        except:
            pass

def detect_adapters():
    adapters = []
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                adapter = line.split()[0]
                if adapter not in adapters:
                    adapters.append(adapter)
    except:
        pass
    return adapters

def set_monitor_mode(adapter):
    global MONITOR_INTERFACE
    try:
        subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
        subprocess.run(['ip', 'link', 'set', adapter, 'down'], check=True, capture_output=True)
        subprocess.run(['iw', 'dev', adapter, 'set', 'type', 'monitor'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', adapter, 'up'], check=True, capture_output=True)
        MONITOR_INTERFACE = adapter
        return True
    except Exception:
        return False

# ============================================
# CSV PARSER
# ============================================

def parse_csv_file(csv_file):
    global networks, clients
    if not os.path.exists(csv_file):
        return

    temp_nets = {}
    temp_clients = defaultdict(set)

    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        parsing_stations = False

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("Station MAC"):
                parsing_stations = True
                continue

            parts = [p.strip() for p in line.split(',')]

            if not parsing_stations:
                if len(parts) >= 14 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
                    bssid = parts[0]
                    power = parts[8]
                    channel = parts[3]
                    privacy = parts[5]
                    ssid = parts[13]

                    if not ssid or ssid == "":
                        ssid = "<Hidden>"

                    temp_nets[bssid] = {
                        'bssid': bssid,
                        'power': power,
                        'channel': channel,
                        'encryption': privacy,
                        'ssid': ssid
                    }
            else:
                if len(parts) >= 6 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
                    client_mac = parts[0]
                    associated_bssid = parts[5]
                    if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', associated_bssid):
                        temp_clients[associated_bssid].add(client_mac)

        networks = temp_nets
        clients = temp_clients
    except Exception:
        pass

# ============================================
# CURSES REAL-TIME DISPLAY
# ============================================

def curses_display(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(500)  # Refresh loop every 500ms

    # Setup Colors
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # Strong Signal
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Medium Signal
    curses.init_pair(3, curses.COLOR_RED, -1)     # Weak Signal
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # Headers & Borders

    target_csv = f"{CSV_PREFIX}-01.csv"

    while True:
        # Check if user pressed Ctrl+C or 'q'
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q') or key == 3:  # 3 is Ctrl+C
            break

        parse_csv_file(target_csv)
        stdscr.erase()

        max_y, max_x = stdscr.getmaxyx()

        # Header Title
        title = "=== YEVIL - REAL-TIME WI-FI SCANNER ==="
        stdscr.addstr(0, max(0, (max_x - len(title)) // 2), title, curses.color_pair(4) | curses.A_BOLD)

        # Table Headers
        header = f"{'NUM':<4} {'ESSID':<28} {'CH':<4} {'ENCR':<8} {'POWER':<8} {'CLIENTS':<7} {'BSSID'}"
        stdscr.addstr(2, 0, header[:max_x-1], curses.color_pair(4) | curses.A_BOLD)
        stdscr.addstr(3, 0, "-" * min(max_x - 1, 80), curses.color_pair(4))

        # Sort Networks by Power
        def get_power(net):
            try:
                return int(net['power'])
            except:
                return -100

        sorted_nets = sorted(networks.values(), key=get_power, reverse=True)

        row_idx = 4
        for idx, net in enumerate(sorted_nets, 1):
            if row_idx >= max_y - 2:
                break  # Stop drawing if terminal screen is full

            try:
                pwr = int(net['power'])
                if pwr > -60:
                    color = curses.color_pair(1)  # Green
                elif pwr > -75:
                    color = curses.color_pair(2)  # Yellow
                else:
                    color = curses.color_pair(3)  # Red
            except:
                color = curses.color_pair(0)

            ssid = net['ssid'][:26]
            client_count = len(clients.get(net['bssid'], set()))
            pwr_str = f"{net['power']} dB" if net['power'].lstrip('-').isdigit() else net['power']

            line = f"{idx:<4} {ssid:<28} {net['channel']:<4} {net['encryption']:<8} {pwr_str:<8} {client_count:<7} {net['bssid']}"
            stdscr.addstr(row_idx, 0, line[:max_x-1], color)
            row_idx += 1

        # Footer
        footer = "Press 'q' or Ctrl+C to stop scanning."
        stdscr.addstr(max_y - 1, 0, footer[:max_x-1], curses.color_pair(4) | curses.A_REVERSE)

        stdscr.refresh()

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    if os.geteuid() != 0:
        print("[-] This tool requires root privileges! Run with: sudo python3 yevil_clean.py")
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        print("[-] No wireless adapters detected!")
        sys.exit(1)

    print("\n📋 Available Wireless Adapters:")
    for i, adapter in enumerate(adapters, 1):
        print(f"  {i}. {adapter}")

    while True:
        try:
            choice = input("\n[?] Select adapter number: ")
            selected = adapters[int(choice) - 1]
            break
        except (IndexError, ValueError):
            print("[-] Invalid selection!")

    print(f"[*] Setting {selected} into monitor mode...")
    if not set_monitor_mode(selected):
        print("[-] Failed to set monitor mode.")
        sys.exit(1)

    cleanup_files()

    # Launch background airodump scanner
    cmd = [
        'airodump-ng', selected,
        '--band', 'abg',
        '--write', CSV_PREFIX,
        '--output-format', 'csv'
    ]

    global SCANNER_PROCESS
    SCANNER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Launching Interface...")
    time.sleep(1)

    # Hand over control to curses TUI engine
    try:
        curses.wrapper(curses_display)
    except Exception as e:
        pass
    finally:
        cleanup()
        print("\n[+] Scan finished and interface cleaned up.")

if __name__ == "__main__":
    main()
