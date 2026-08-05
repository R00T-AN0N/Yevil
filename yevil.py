#!/usr/bin/env python3
"""
Yevil - Real‑time WiFi Scanner (Clean UI with CSV-backed parsing)
ESSID first, colour‑coded, accurate client counts, single persistent table.
"""

import os
import sys
import subprocess
import re
import time
import signal
import csv
import glob
from collections import defaultdict

# ============================================
# COLOURS
# ============================================

class Colors:
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    cyan = '\033[96m'
    white = '\033[97m'
    reset = '\033[0m'
    bold = '\033[1m'

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
║           WiFi Security Testing Tool v2.1.0                   ║
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
CSV_PREFIX = "/tmp/yevil_scan"

networks = {}               # bssid -> {ssid, bssid, power, channel, encryption}
clients = defaultdict(set)  # bssid -> set of station MACs

# ============================================
# CLEANUP
# ============================================

def cleanup_files():
    """Removes temporary CSV scan files."""
    for f in glob.glob(f"{CSV_PREFIX}*"):
        try:
            os.remove(f)
        except:
            pass

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

    cleanup_files()

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
    cleanup()
    print("\n[+] Goodbye!")
    sys.exit(0)

# ============================================
# ADAPTER FUNCTIONS
# ============================================

def detect_adapters():
    print("[+] Detecting wireless adapters...")
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
# PARSING & DRAWING
# ============================================

def parse_csv_file(csv_file):
    """Parses airodump CSV output for clean BSSID and Client data."""
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
                # Access Point section
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
                # Station/Client section
                if len(parts) >= 6 and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[0]):
                    client_mac = parts[0]
                    associated_bssid = parts[5]
                    if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', associated_bssid):
                        temp_clients[associated_bssid].add(client_mac)

        networks = temp_nets
        clients = temp_clients
    except Exception:
        pass

def redraw_table():
    """Clears the screen and draws one clean persistent table."""
    # Move cursor to top-left corner instead of creating endless scroll
    sys.stdout.write('\033[H\033[2J')
    sys.stdout.flush()

    print(f"{Colors.cyan}{'='*110}")
    print(f"  YEVIL - Real-time WiFi Scanner".center(110))
    print(f"  Networks Discovered: {len(networks)}".center(110))
    print(f"{'='*110}{Colors.reset}")

    header = f"{Colors.bold}{Colors.yellow}"
    header += f"{'#':<4} {'ESSID':<32} {'BSSID':<20} {'CH':<5} {'PWR':<7} {'ENC':<10} {'CLIENTS':<6}"
    header += f"{Colors.reset}"
    print(header)
    print(f"{Colors.cyan}{'-'*110}{Colors.reset}")

    # Sort networks by signal strength (PWR)
    def get_power(net):
        try:
            return int(net['power'])
        except:
            return -100

    sorted_nets = sorted(networks.values(), key=get_power, reverse=True)

    for idx, net in enumerate(sorted_nets, 1):
        try:
            pwr = int(net['power'])
            color = 'green' if pwr > -60 else 'yellow' if pwr > -75 else 'red'
        except:
            color = 'white'

        ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
        client_count = len(clients.get(net['bssid'], set()))

        row = f"{idx:<4} {ssid:<32} {net['bssid']:<20} {net['channel']:<5} "
        row += f"{net['power']:<7} {net['encryption']:<10} {client_count:<6}"
        Colors.print_colored(row, color)

    print(f"{Colors.cyan}{'-'*110}{Colors.reset}")
    print(f"{Colors.white}Press Ctrl+C to stop scanning and lock target.{Colors.reset}")
    print(f"{Colors.cyan}{'='*110}{Colors.reset}")

# ============================================
# SCANNER EXECUTION
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    cleanup_files()

    cmd = [
        'sudo', 'airodump-ng', adapter,
        '--band', 'abg',
        '--write', CSV_PREFIX,
        '--output-format', 'csv'
    ]

    try:
        SCANNER_PROCESS = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return

    target_csv = f"{CSV_PREFIX}-01.csv"

    try:
        while not STOP_SCANNING:
            parse_csv_file(target_csv)
            redraw_table()
            time.sleep(0.5)
    except KeyboardInterrupt:
        STOP_SCANNING = True

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    Colors.print_colored("[+] Yevil - Real‑time WiFi Scanner", 'cyan', True)
    print("="*55)

    if os.geteuid() != 0:
        Colors.print_colored("[!] This tool requires root privileges!", 'red')
        Colors.print_colored("[!] Run with: sudo python3 yevil.py", 'yellow')
        sys.exit(1)

    adapters = detect_adapters()
    if not adapters:
        Colors.print_colored("\n[!] No wireless adapters detected!", 'red')
        sys.exit(1)

    Colors.print_colored("\n📋 Detected Adapters:", 'cyan', True)
    for i, adapter in enumerate(adapters, 1):
        print(f"   {i}. {adapter}")

    while True:
        try:
            choice = input("\n[?] Select adapter (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
        except:
            pass
        Colors.print_colored("[-] Invalid selection!", 'red')

    # Monitor Mode Verification
    result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
    if 'Mode:Monitor' in result.stdout:
        Colors.print_colored("[+] Already in monitor mode", 'green')
        monitor_adapter = selected
    else:
        if set_monitor_mode(selected):
            monitor_adapter = selected
        else:
            sys.exit(1)

    start_scanner(monitor_adapter)

    cleanup()

if __name__ == "__main__":
    main()
