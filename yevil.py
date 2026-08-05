#!/usr/bin/env python3
"""
Yevil - Custom WiFi Scanner (ESSID first, client count, colored, no bottom table)
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
# PARSER AND DISPLAY
# ============================================

def parse_bssid_line(line):
    """Extract BSSID info from a line in the BSSID section."""
    # Format: BSSID  PWR  Beacons  #Data  #/s  CH  MB  ENC  CIPHER  AUTH  ESSID
    parts = line.strip().split()
    if len(parts) < 10:
        return None
    # Check if first part looks like a MAC address
    if not re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
        return None
    bssid = parts[0]
    power = parts[1] if len(parts) > 1 else '0'
    # Channel is at index 5 (0-based)
    channel = parts[5] if len(parts) > 5 else '0'
    # Encryption at index 7
    encryption = parts[7] if len(parts) > 7 else 'OPN'
    # Cipher at index 8
    cipher = parts[8] if len(parts) > 8 else ''
    # Authentication at index 9
    auth = parts[9] if len(parts) > 9 else ''
    # ESSID is the rest after index 10
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

def draw_table(networks, clients):
    """Draw a clean table with ESSID first, then BSSID, CH, PWR, ENC, CLIENTS."""
    if not networks:
        sys.stdout.write(Colors.clear)
        sys.stdout.flush()
        print(f"{Colors.cyan}{'='*120}")
        print(f"  YEVIL - Custom WiFi Scanner".center(120))
        print(f"  Scanning for networks...".center(120))
        print(f"{'='*120}{Colors.reset}")
        return

    sys.stdout.write(Colors.clear)
    sys.stdout.flush()

    print(f"{Colors.cyan}{'='*120}")
    print(f"  YEVIL - Custom WiFi Scanner".center(120))
    print(f"  Networks found: {len(networks)}".center(120))
    print(f"{'='*120}{Colors.reset}")

    # Header: ESSID first, then BSSID, CH, PWR, ENC, CLIENTS
    header = f"{Colors.bold}{Colors.yellow}"
    header += f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CLIENTS':<6}"
    header += f"{Colors.reset}"
    print(header)
    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")

    # Sort by signal strength (strongest first)
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
        row += f"{net['power']:<6} {net['encryption']:<8} {client_count:<6}"
        Colors.print_colored(row, color)

    print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
    print(f"{Colors.white}Press Ctrl+C to stop scanning (new networks appear below){Colors.reset}")
    print(f"{Colors.cyan}{'='*120}{Colors.reset}")

# ============================================
# SCANNER WITH PARSING
# ============================================

def start_scanner(adapter):
    global SCANNER_PROCESS, STOP_SCANNING

    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg']
    print(f"\n[+] Running: {' '.join(cmd)}")
    print("[+] Scanning... Press Ctrl+C to stop.")
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

    networks = []
    clients = defaultdict(int)
    seen_bssids = set()
    in_bssid = False
    in_station = False

    # We'll collect lines and parse
    lines_buffer = []

    while not STOP_SCANNING:
        line = SCANNER_PROCESS.stdout.readline()
        if not line:
            break
        lines_buffer.append(line)
        if len(lines_buffer) > 200:
            lines_buffer = lines_buffer[-200:]

        # Detect sections
        if 'BSSID' in line and 'PWR' in line and 'Beacons' in line:
            in_bssid = True
            in_station = False
            continue
        if 'Station' in line and 'PWR' in line and 'Lost' in line:
            in_bssid = False
            in_station = True
            continue

        # Parse BSSID lines
        if in_bssid and line.strip():
            net = parse_bssid_line(line)
            if net and net['bssid'] not in seen_bssids:
                seen_bssids.add(net['bssid'])
                networks.append(net)
                # Redraw table immediately when new network appears
                # We'll also need to update clients later
                # For now, we'll redraw after parsing stations as well

        # Parse station lines to count clients
        if in_station and line.strip():
            # Format: BSSID  STATION  PWR  Rate  Lost  Frames  Notes
            parts = line.split()
            if len(parts) >= 2:
                # First is BSSID, second is Station MAC
                if re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
                    bssid = parts[0]
                    clients[bssid] += 1

        # Periodically redraw table (but only if we have networks and something changed)
        # We'll redraw after each BSSID addition or when we have station updates
        # We'll just redraw after each new BSSID appears, and we'll include client counts from stations

        # Since we don't have a good event for "new BSSID", we'll simply check every 0.5s
        # and redraw if the network list changed or clients changed.
        # Simpler: redraw every time we have networks, but that will flicker.
        # Better: redraw only when new BSSID added.

        # We'll use a timer to redraw once per second if any networks exist.
        # But we already redraw on new BSSID. Let's also redraw periodically to show client updates.
        # We'll redraw every 2 seconds if there are networks.

    # Cleanup process
    if SCANNER_PROCESS:
        SCANNER_PROCESS.terminate()
        time.sleep(0.5)
        if SCANNER_PROCESS.poll() is None:
            SCANNER_PROCESS.kill()
        SCANNER_PROCESS = None

    # Final draw
    if networks:
        draw_table(networks, clients)

# ============================================
# MAIN
# ============================================

def main():
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    Colors.print_colored("[+] Yevil - Custom WiFi Scanner", 'cyan', True)
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
