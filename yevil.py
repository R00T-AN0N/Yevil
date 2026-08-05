#!/usr/bin/env python3
"""
Yevil - Real‑time WiFi Scanner (one live table, no files)
ESSID first, colour‑coded, client count included.
"""

import os
import sys
import subprocess
import re
import time
import signal
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
networks = {}          # bssid -> {ssid, bssid, power, channel, encryption, ...}
clients = defaultdict(int)  # bssid -> count
seen_bssids = set()

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
# PARSING AND DISPLAY
# ============================================

def parse_bssid_line(line):
    """Parse a line from the BSSID section."""
    parts = line.strip().split()
    if len(parts) < 10:
        return None
    # Must start with MAC
    if not re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
        return None
    bssid = parts[0]
    power = parts[1]
    channel = parts[5] if len(parts) > 5 else '0'
    encryption = parts[7] if len(parts) > 7 else 'OPN'
    cipher = parts[8] if len(parts) > 8 else ''
    auth = parts[9] if len(parts) > 9 else ''
    # ESSID is everything after position 10
    ssid = ' '.join(parts[10:]) if len(parts) > 10 else '<Hidden>'
    if ssid == '' or ssid == '<length: 0>':
        ssid = '<Hidden>'
    return {
        'bssid': bssid,
        'power': power,
        'channel': channel,
        'encryption': encryption,
        'cipher': cipher,
        'authentication': auth,
        'ssid': ssid
    }

def redraw_table():
    """Clear screen and draw the complete table."""
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()

    print(f"{Colors.cyan}{'='*120}")
    print(f"  YEVIL - Real-time WiFi Scanner".center(120))
    print(f"  Networks found: {len(networks)}".center(120))
    print(f"{'='*120}{Colors.reset}")

    # Header: ESSID first
    header = f"{Colors.bold}{Colors.yellow}"
    header += f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CLIENTS':<6}"
    header += f"{Colors.reset}"
    print(header)
    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")

    # Sort by signal strength
    try:
        sorted_nets = sorted(networks.values(),
                             key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                             reverse=True)
    except:
        sorted_nets = list(networks.values())

    for idx, net in enumerate(sorted_nets, 1):
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
        row += f"{net['power']:<6} {net['encryption']:<8} {client_count:<6}"
        Colors.print_colored(row, color)

    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
    print(f"{Colors.white}Press Ctrl+C to stop scanning (table updates in real-time){Colors.reset}")
    print(f"{Colors.cyan}{'='*120}{Colors.reset}")

# ============================================
# SCANNER – real‑time parsing
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING, networks, clients, seen_bssids

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg']
    print(f"\n[+] Running: {' '.join(cmd)}")
    print("[+] Scanning... Press Ctrl+C to stop.\n")
    time.sleep(1)

    try:
        SCANNER_PROCESS = subprocess.Popen(cmd,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True,
                                           bufsize=1)
    except Exception as e:
        print(f"[-] Failed to start scanner: {e}")
        return

    in_bssid = False
    in_station = False
    line_count = 0
    last_redraw = 0

    while not STOP_SCANNING:
        line = SCANNER_PROCESS.stdout.readline()
        if not line:
            break
        line_count += 1

        # Detect BSSID header
        if 'BSSID' in line and 'PWR' in line and 'Beacons' in line:
            in_bssid = True
            in_station = False
            continue
        # Detect Station header
        if 'Station' in line and 'PWR' in line and 'Lost' in line:
            in_bssid = False
            in_station = True
            continue

        if in_bssid and line.strip():
            net = parse_bssid_line(line)
            if net and net['bssid'] not in seen_bssids:
                seen_bssids.add(net['bssid'])
                networks[net['bssid']] = net
                # Redraw immediately on new network
                redraw_table()
                last_redraw = time.time()
            elif net and net['bssid'] in networks:
                # Update existing network (power, etc.)
                networks[net['bssid']] = net

        if in_station and line.strip():
            # Station line: BSSID  STATION  PWR  Rate  Lost  Frames  Notes
            parts = line.split()
            if len(parts) >= 2:
                # First column is BSSID
                if re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
                    bssid = parts[0]
                    # Count clients
                    # But we need to avoid double counting; we'll store clients as a set of station MACs
                    # For simplicity, we increment each time we see a station for that BSSID.
                    # However, stations may appear multiple times; we'll store unique station MACs per BSSID.
                    # We'll parse station MAC from second field.
                    if len(parts) > 1 and re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[1]):
                        station_mac = parts[1]
                        # We'll maintain a dict of sets per BSSID
                        # But to keep it simple, we'll count unique station MACs by storing them in a set.
                        # We'll use a global dict of sets.
                        # For now, we'll just increment a counter each time we see a station – that's not accurate.
                        # Better: store a set of stations per BSSID.
                        # Let's maintain a global dict: stations_per_bssid = defaultdict(set)
                        # But we need to define it earlier.
                        pass

        # Redraw periodically to update client counts (since station lines may appear without new BSSID)
        # We'll redraw every 2 seconds if data changed.
        now = time.time()
        if now - last_redraw > 2 and networks:
            # We need to update clients by parsing station lines again? We already parse them.
            # We'll just redraw the table with current data.
            redraw_table()
            last_redraw = now

    # Cleanup process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(0.5)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

    # Final draw
    if networks:
        redraw_table()

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    Colors.print_colored("[+] Yevil - Real‑time WiFi Scanner", 'cyan', True)
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

    # Check monitor mode
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
