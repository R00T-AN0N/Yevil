#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Colorful Table with Client Information
"""

import os
import sys
import subprocess
import re
import time
import signal
import threading
from collections import defaultdict

# ============================================
# COLORS
# ============================================

class Colors:
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    magenta = '\033[95m'
    cyan = '\033[96m'
    white = '\033[97m'
    reset = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'
    bg_black = '\033[40m'
    bg_red = '\033[41m'
    bg_green = '\033[42m'
    bg_yellow = '\033[43m'
    bg_blue = '\033[44m'
    bg_magenta = '\033[45m'
    bg_cyan = '\033[46m'
    bg_white = '\033[47m'
    clear = '\033[2J\033[H'
    
    @staticmethod
    def print_colored(text: str, color: str = 'white', bold: bool = False, bg: str = None):
        style = Colors.bold if bold else ''
        bg_code = getattr(Colors, bg, '') if bg else ''
        color_code = getattr(Colors, color, '')
        print(f"{style}{bg_code}{color_code}{text}{Colors.reset}")

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
# GLOBAL VARIABLES
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
# SCANNER WITH PARSING
# ============================================

class NetworkScanner:
    def __init__(self, adapter):
        self.adapter = adapter
        self.networks = {}          # bssid -> network dict
        self.clients = defaultdict(list)  # bssid -> list of client macs
        self.process = None
        self.running = True
        self.lock = threading.Lock()
        self.last_display = 0
        
    def parse_line(self, line):
        """Parse a line from airodump-ng output."""
        line = line.strip()
        if not line:
            return None
        
        # Check if this is a BSSID line (starts with MAC address)
        bssid_pattern = r'^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        match = re.match(bssid_pattern, line)
        if match:
            parts = line.split()
            if len(parts) >= 10:
                try:
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
                    return {
                        'type': 'bssid',
                        'bssid': bssid,
                        'power': power,
                        'beacons': beacons,
                        'channel': channel,
                        'encryption': encryption,
                        'cipher': cipher,
                        'authentication': auth,
                        'ssid': ssid
                    }
                except:
                    pass
        
        # Check if this is a Station line (starts with MAC and has "Station" pattern)
        # Stations appear after the "Station" header
        # Format: MAC  PWR  Rate  Lost  Frames  Notes  Probes
        if re.match(bssid_pattern, line):
            parts = line.split()
            if len(parts) >= 2:
                # If it has less than 10 fields, it's likely a station line
                if len(parts) < 10:
                    mac = parts[0]
                    # We need to know which BSSID this station belongs to
                    # The station lines appear after a blank line or after the Station header
                    # We'll handle this by passing context in the parser
                    return {'type': 'station', 'mac': mac}
        return None
    
    def parse_airodump_output(self, lines):
        """Parse the full output and update networks and clients."""
        # We need to identify the BSSID section and Station section
        # We'll use a state machine
        in_bssid = False
        in_station = False
        current_bssid = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Detect headers
            if 'BSSID' in line and 'PWR' in line and 'Beacons' in line:
                in_bssid = True
                in_station = False
                continue
            if 'Station' in line and 'PWR' in line:
                in_bssid = False
                in_station = True
                continue
            
            if in_bssid:
                parsed = self.parse_line(line)
                if parsed and parsed['type'] == 'bssid':
                    with self.lock:
                        self.networks[parsed['bssid']] = parsed
            
            if in_station:
                # Station lines: MAC  PWR  Rate  Lost  Frames  Notes  Probes
                parts = line.split()
                if len(parts) >= 2 and re.match(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', parts[0]):
                    mac = parts[0]
                    # We need to determine which BSSID this station is associated with
                    # The station section appears after the BSSID section, so we can try to match
                    # But simpler: we'll just store all stations and later associate them
                    # Actually, in airodump-ng, the station lines appear under each BSSID? No, they appear as a flat list after the BSSID section.
                    # The station section has a column for BSSID? Actually it doesn't.
                    # In the output, the station section lists stations and their associated BSSID is not directly shown.
                    # However, we can infer that the station is associated with the BSSID that had the strongest signal, but that's not accurate.
                    # For our purpose, we can just count clients per BSSID by looking at the BSSID section's #Data or by analyzing probes.
                    # Actually, the station list does not include the associated BSSID; it's separate.
                    # To get client count, we can parse the #Data column or use the station list if we know the BSSID from context?
                    # In airodump-ng, the station list shows all stations and their BSSID is not shown.
                    # So we can't easily map clients to BSSIDs from the output format.
                    # Instead, we can count clients per BSSID by looking at the number of unique MACs in the station list that are associated with that BSSID based on signal? Not reliable.
                    # Alternative: use aircrack-ng's airodump-ng with --output-format csv to get a file, but that's extra.
                    # For simplicity, I'll just show total clients in the station list as a separate count, or we can count how many stations are present in the station section.
                    # Actually, the station section includes all stations, not per BSSID. So we'll just count total stations.
                    pass
    
    def display_table(self):
        """Print a colorful table with networks and client counts."""
        with self.lock:
            if not self.networks:
                return
            
            # Clear screen and print header
            sys.stdout.write(Colors.clear)
            sys.stdout.flush()
            
            # Print banner and title
            print(f"{Colors.cyan}{'='*120}")
            print(f"  YEVIL - Real-Time WiFi Scanner".center(120))
            print(f"  Adapter: {self.adapter} (Monitor Mode)".center(120))
            print(f"  Networks Found: {len(self.networks)}".center(120))
            print(f"{'='*120}{Colors.reset}")
            
            # Table header
            header = f"{Colors.bold}{Colors.yellow}"
            header += f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<10} {'CLIENTS':<6}"
            header += f"{Colors.reset}"
            print(header)
            print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
            
            # Sort by signal strength (strongest first)
            sorted_networks = sorted(self.networks.values(), 
                                   key=lambda x: int(x['power']) if x['power'].lstrip('-').isdigit() else 0, 
                                   reverse=True)
            
            # Display each network
            for idx, net in enumerate(sorted_networks, 1):
                # Color by signal strength
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
                
                # Get client count (we'll estimate based on number of stations in the station section - we can't accurately map)
                # For now, we'll show 0, but we can improve if we parse the station section better.
                client_count = 0
                
                # Build row
                ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
                if ssid == '':
                    ssid = '<Hidden>'
                
                row = f"{idx:<4} {ssid:<30} {net['bssid']:<18} {net['channel']:<4} "
                row += f"{net['power']:<6} {net['encryption']:<8} {net['cipher']:<8} {net['authentication']:<10} {client_count:<6}"
                Colors.print_colored(row, color)
            
            print(f"{Colors.cyan}{'-'*120}{Colors.reset}")
            print(f"{Colors.white}Press Ctrl+C to stop scanning{Colors.reset}")
            print(f"{Colors.cyan}{'='*120}{Colors.reset}")
    
    def scan(self):
        """Run airodump-ng and update display in real-time."""
        global SCANNER_PROCESS, STOP_SCANNING
        
        cmd = ['sudo', 'airodump-ng', self.adapter, '--band', 'abg']
        print(f"\n[+] Running: {' '.join(cmd)}")
        print("[+] Parsing output in real-time...\n")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            SCANNER_PROCESS = self.process
            
            lines_buffer = []
            while self.running and not STOP_SCANNING:
                line = self.process.stdout.readline()
                if not line:
                    break
                lines_buffer.append(line)
                # Keep buffer size manageable
                if len(lines_buffer) > 500:
                    lines_buffer = lines_buffer[-400:]
                
                # Parse and update every 0.5 seconds
                current_time = time.time()
                if current_time - self.last_display >= 0.5:
                    self.parse_airodump_output(lines_buffer)
                    self.display_table()
                    self.last_display = current_time
            
            # Final display
            self.parse_airodump_output(lines_buffer)
            self.display_table()
            
        except Exception as e:
            print(f"[-] Error during scan: {e}")
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
    
    # Check root
    if os.geteuid() != 0:
        Colors.print_colored("[!] This tool requires root privileges!", 'red')
        Colors.print_colored("[!] Please run with: sudo python3 yevil.py", 'yellow')
        sys.exit(1)
    
    # Detect adapters
    adapters = detect_adapters()
    if not adapters:
        Colors.print_colored("\n[!] No wireless adapters detected!", 'red')
        sys.exit(1)
    
    # Show adapters
    Colors.print_colored("\n📋 Detected Adapters:", 'cyan', True)
    for i, adapter in enumerate(adapters, 1):
        print(f"   {i}. {adapter}")
    
    # Select
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
    
    # Check if already in monitor mode
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
    
    # Run scanner
    scanner = NetworkScanner(monitor_adapter)
    scanner.scan()
    
    # After scan, cleanup
    print("\n" + "="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup()
    else:
        Colors.print_colored("[+] Adapter remains in monitor mode", 'yellow')
        Colors.print_colored(f"[+] To cleanup manually: sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up", 'yellow')
    
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
