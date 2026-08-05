#!/usr/bin/env python3
"""
Yevil - Real‑Time WiFi Scanner (No Files, Pure Parsing)
Colourful table with client counts, updated live.
"""

import os
import sys
import subprocess
import time
import signal
import re
import threading
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
    magenta = '\033[95m'
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
# REAL-TIME PARSER & DISPLAY
# ============================================

class RealtimeScanner:
    def __init__(self, adapter):
        self.adapter = adapter
        self.networks = {}          # bssid -> dict
        self.clients = defaultdict(list)   # bssid -> list of station MACs
        self.process = None
        self.running = True
        self.lock = threading.Lock()
        self.last_display = 0
        self.in_bssid = False
        self.in_station = False

    def parse_line(self, line):
        """Parse a line from airodump-ng output."""
        line = line.strip()
        if not line:
            return

        # Detect headers
        if 'BSSID' in line and 'PWR' in line and 'Beacons' in line:
            self.in_bssid = True
            self.in_station = False
            return
        if 'Station' in line and 'PWR' in line and 'Lost' in line:
            self.in_bssid = False
            self.in_station = True
            return

        # BSSID line: BSSID  PWR  Beacons  #Data  #/s  CH  MB  ENC  CIPHER  AUTH  ESSID
        if self.in_bssid:
            parts = line.split()
            if len(parts) >= 10:
                # Check if first part is MAC
                if re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
                    bssid = parts[0]
                    power = parts[1] if len(parts) > 1 else '0'
                    beacons = parts[2] if len(parts) > 2 else '0'
                    channel = parts[5] if len(parts) > 5 else '0'
                    encryption = parts[7] if len(parts) > 7 else 'OPN'
                    cipher = parts[8] if len(parts) > 8 else ''
                    auth = parts[9] if len(parts) > 9 else ''
                    ssid = ' '.join(parts[10:]) if len(parts) > 10 else '<Hidden>'
                    if ssid == '' or ssid == '<length: 0>':
                        ssid = '<Hidden>'
                    with self.lock:
                        self.networks[bssid] = {
                            'bssid': bssid,
                            'power': power,
                            'beacons': beacons,
                            'channel': channel,
                            'encryption': encryption,
                            'cipher': cipher,
                            'authentication': auth,
                            'ssid': ssid
                        }

        # Station line: BSSID  STATION  PWR  Rate  Lost  Frames  Notes  Probes
        if self.in_station:
            parts = line.split()
            if len(parts) >= 8:
                # First part is BSSID, second is station MAC
                if re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
                    bssid = parts[0]
                    station = parts[1]
                    with self.lock:
                        if station not in self.clients[bssid]:
                            self.clients[bssid].append(station)

    def display_table(self):
        """Print a colourful table with client counts."""
        with self.lock:
            if not self.networks:
                # Show scanning message
                sys.stdout.write(Colors.clear)
                sys.stdout.flush()
                print(f"{Colors.cyan}{'='*120}")
                print(f"  YEVIL - Real-Time WiFi Scanner".center(120))
                print(f"  Adapter: {self.adapter} (Monitor Mode)".center(120))
                print(f"{'='*120}{Colors.reset}")
                print("\n" + " "*50 + "🔍 Scanning for networks...")
                print(f"{Colors.cyan}{'='*120}{Colors.reset}")
                return

            # Sort by signal strength
            try:
                sorted_networks = sorted(self.networks.values(),
                                         key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else -100,
                                         reverse=True)
            except:
                sorted_networks = list(self.networks.values())

            sys.stdout.write(Colors.clear)
            sys.stdout.flush()

            print(f"{Colors.cyan}{'='*120}")
            print(f"  YEVIL - Real-Time WiFi Scanner".center(120))
            print(f"  Adapter: {self.adapter} (Monitor Mode)".center(120))
            print(f"  Networks Found: {len(self.networks)}".center(120))
            print(f"{'='*120}{Colors.reset}")

            # Header
            header = f"{Colors.bold}{Colors.yellow}"
            header += f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
            header += f"{Colors.reset}"
            print(header)
            print(f"{Colors.cyan}{'-'*120}{Colors.reset}")

            for idx, net in enumerate(sorted_networks, 1):
                # Colour by signal
                try:
                    pwr = int(net['power'])
                    if pwr > -50:
                        color = 'green'
                    elif pwr > -65:
                        color = 'yellow'
                    else:
                        color = 'red'
                except:
                    color = 'white'

                ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
                if ssid == '':
                    ssid = '<Hidden>'

                client_count = len(self.clients.get(net['bssid'], []))

                row = f"{idx:<4} {ssid:<30} {net['bssid']:<18} {net['channel']:<4} "
                row += f"{net['power']:<6} {net['encryption']:<8} {net['cipher']:<8} {net['authentication']:<10} {client_count:<6}"
                Colors.print_colored(row, color)

            print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
            print(f"{Colors.white}Press Ctrl+C to stop scanning{Colors.reset}")
            print(f"{Colors.cyan}{'='*120}{Colors.reset}")

    def scan(self):
        """Start airodump-ng and parse output in real-time."""
        global SCANNER_PROCESS, STOP_SCANNING

        cmd = ['sudo', 'airodump-ng', self.adapter, '--band', 'abg']
        print(f"\n[+] Running: {' '.join(cmd)}")
        print("[+] Parsing output in real-time...\n")
        time.sleep(1)

        try:
            self.process = subprocess.Popen(cmd,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            text=True,
                                            bufsize=1)
            SCANNER_PROCESS = self.process

            # Read line by line
            while self.running and not STOP_SCANNING:
                line = self.process.stdout.readline()
                if not line:
                    break
                self.parse_line(line)

                # Update display every 0.5 seconds
                now = time.time()
                if now - self.last_display >= 0.5:
                    self.display_table()
                    self.last_display = now

            # Final display
            self.display_table()

        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            if self.process:
                self.process.terminate()
                time.sleep(0.5)
                if self.process.poll() is None:
                    self.process.kill()
                self.process = None
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

    # Start scanner
    scanner = RealtimeScanner(monitor_adapter)
    scanner.scan()

    # After scan finishes, cleanup
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
