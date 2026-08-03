#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Real-Time Network Scanner - Working Version
"""

import os
import sys
import subprocess
import re
import time
import signal
import threading
from datetime import datetime

# ============================================
# COLORS
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
    def print_colored(text: str, color: str = 'white', bold: bool = False):
        style = Colors.bold if bold else ''
        print(f"{style}{getattr(Colors, color, '')}{text}{Colors.reset}")

# ============================================
# BANNER
# ============================================

BANNER = """
\033[96m
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
\033[0m
"""

# ============================================
# GLOBAL VARIABLES
# ============================================

MONITOR_INTERFACE = None
ORIGINAL_INTERFACE = None
SCANNER_PROCESS = None

# ============================================
# CLEANUP FUNCTIONS
# ============================================

def cleanup_monitor_mode():
    """Clean up monitor mode"""
    global MONITOR_INTERFACE, ORIGINAL_INTERFACE, SCANNER_PROCESS
    
    print("\n" + "="*60)
    print("[+] Cleaning up...")
    print("="*60)
    
    if SCANNER_PROCESS:
        try:
            SCANNER_PROCESS.terminate()
            time.sleep(0.5)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
        except:
            pass
    
    try:
        subprocess.run(['sudo', 'pkill', '-f', 'airodump-ng'], capture_output=True, check=False)
        subprocess.run(['sudo', 'pkill', '-f', 'aireplay-ng'], capture_output=True, check=False)
    except:
        pass
    
    if MONITOR_INTERFACE:
        try:
            print(f"[+] Stopping monitor mode on {MONITOR_INTERFACE}")
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
    except:
        pass
    
    print("[+] Cleanup complete!")
    print("="*60)

def signal_handler(signum, frame):
    """Handle Ctrl+C"""
    print(f"\n\n[!] Ctrl+C detected")
    cleanup_monitor_mode()
    print("\n[+] Goodbye!")
    sys.exit(0)

# ============================================
# ADAPTER HANDLER
# ============================================

class AdapterHandler:
    def __init__(self):
        self.adapters = []
        self.monitor_interface = None
        
    def detect_adapters(self) -> list:
        print("\n[+] Detecting wireless adapters...")
        
        adapters = []
        try:
            # Check iwconfig for wireless interfaces
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    adapter = line.split()[0]
                    if adapter not in adapters:
                        adapters.append(adapter)
            
            # Also check ip link
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
                    match = re.search(r':\s*(\w+)', line)
                    if match:
                        adapter = match.group(1)
                        if adapter not in adapters:
                            adapters.append(adapter)
        except:
            pass
        
        # Remove monitor interfaces from the list (we want the original)
        adapters = [a for a in adapters if 'mon' not in a]
        
        self.adapters = adapters
        return adapters
    
    def get_adapter_info(self, adapter: str) -> dict:
        info = {'name': adapter, 'mode': 'Unknown', 'driver': 'Unknown'}
        
        try:
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                info['mode'] = 'Monitor'
            elif 'Mode:Managed' in result.stdout:
                info['mode'] = 'Managed'
            else:
                match = re.search(r'Mode:(\w+)', result.stdout)
                if match:
                    info['mode'] = match.group(1)
        except:
            pass
        
        return info
    
    def set_monitor_mode(self, adapter: str) -> bool:
        global MONITOR_INTERFACE, ORIGINAL_INTERFACE
        
        print(f"\n[+] Setting {adapter} to monitor mode...")
        ORIGINAL_INTERFACE = adapter
        
        try:
            # Kill interfering processes
            print("[+] Killing interfering processes...")
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            time.sleep(1)
            
            # Use the manual method that works
            print("[+] Setting monitor mode using iw...")
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], 
                         check=True, capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], 
                         check=True, capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], 
                         check=True, capture_output=True)
            
            # Set TX power
            try:
                subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'txpower', 'fixed', '30'], 
                             capture_output=True, check=False)
            except:
                pass
            
            MONITOR_INTERFACE = adapter
            self.monitor_interface = MONITOR_INTERFACE
            
            # Verify monitor mode
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                print(f"[+] ✅ {adapter} is now in MONITOR MODE!")
                return True
            else:
                print(f"[!] Monitor mode not verified!")
                return False
                
        except Exception as e:
            print(f"[-] Failed to set monitor mode: {e}")
            return False


# ============================================
# REAL-TIME SCANNER
# ============================================

class RealTimeScanner:
    def __init__(self, adapter: str):
        self.adapter = adapter
        self.process = None
        self.running = True
        
    def parse_line(self, line: str) -> dict:
        """Parse airodump-ng output line"""
        parts = line.strip().split()
        
        # Need at least 10 parts for a valid BSSID line
        if len(parts) < 10:
            return None
        
        # Check if first part looks like BSSID
        bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        if not re.match(bssid_pattern, parts[0]):
            return None
        
        try:
            # Extract SSID - it's everything after the 10th column
            ssid = ' '.join(parts[10:]) if len(parts) > 10 else '<Hidden>'
            if ssid == '' or ssid == '<length: 0>':
                ssid = '<Hidden>'
            
            return {
                'bssid': parts[0],
                'power': parts[1] if len(parts) > 1 else '0',
                'beacons': parts[2] if len(parts) > 2 else '0',
                'data': parts[3] if len(parts) > 3 else '0',
                'channel': parts[5] if len(parts) > 5 else '0',
                'mb': parts[6] if len(parts) > 6 else '0',
                'encryption': parts[7] if len(parts) > 7 else 'OPN',
                'cipher': parts[8] if len(parts) > 8 else '',
                'authentication': parts[9] if len(parts) > 9 else '',
                'ssid': ssid
            }
        except:
            return None
    
    def print_header(self):
        """Print table header"""
        print(Colors.clear)
        print("="*120)
        print(f"🔍 YEVIL - Real-Time WiFi Scanner".center(120))
        print("="*120)
        print(f"📡 Adapter: {self.adapter} (Monitor Mode)".center(120))
        print("="*120)
        print()
        print(f"{'#':<4} {'ESSID':<32} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<12} {'BEACONS':<8}")
        print("-"*120)
    
    def print_network(self, num: int, net: dict):
        """Print a network row"""
        ssid = net['ssid'][:32] if len(net['ssid']) > 32 else net['ssid']
        if ssid == '':
            ssid = '<Hidden>'
        
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
        
        Colors.print_colored(
            f"{num:<4} {ssid[:32]:<32} {net['bssid']:<18} {net['channel']:<4} "
            f"{net['power']:<6} {net['encryption']:<8} {net['cipher']:<8} "
            f"{net['authentication']:<12} {net['beacons']:<8}",
            color
        )
    
    def scan_realtime(self):
        """Scan in real-time mode"""
        global SCANNER_PROCESS
        
        print(f"\n[+] Starting real-time scan on {self.adapter}")
        print("[+] Press Ctrl+C to stop")
        print("[+] Scanning for access points...\n")
        time.sleep(1)
        
        self.print_header()
        
        networks = []
        in_bssid_section = False
        last_update = time.time()
        found_any = False
        
        try:
            # Run airodump-ng on the adapter
            self.process = subprocess.Popen(
                ['sudo', 'airodump-ng', self.adapter, '--band', 'abg'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            SCANNER_PROCESS = self.process
            
            while self.running:
                try:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    # Check for BSSID header
                    if 'BSSID' in line and 'PWR' in line:
                        in_bssid_section = True
                        continue
                    
                    # Check for Station section (end of BSSID list)
                    if in_bssid_section and 'Station' in line:
                        in_bssid_section = False
                        continue
                    
                    # Parse BSSID lines
                    if in_bssid_section and line.strip():
                        net = self.parse_line(line)
                        if net:
                            found_any = True
                            # Check if this is a new network (unique BSSID)
                            exists = False
                            for existing in networks:
                                if existing['bssid'] == net['bssid']:
                                    # Update with latest data
                                    existing.update(net)
                                    exists = True
                                    break
                            if not exists:
                                networks.append(net)
                    
                    # Update display every 0.5 seconds
                    current_time = time.time()
                    if current_time - last_update >= 0.5:
                        self.print_header()
                        if networks:
                            for i, net in enumerate(networks, 1):
                                self.print_network(i, net)
                        else:
                            print("\n" + " "*50 + "🔍 Scanning for networks...")
                            print(" "*50 + "No networks found yet")
                        
                        print("-"*120)
                        print(f"Networks found: {len(networks)} | Adapter: {self.adapter}")
                        print("[Press Ctrl+C to stop scanning]")
                        print("="*120)
                        last_update = current_time
                        
                except:
                    break
            
        except Exception as e:
            print(f"[-] Error during scan: {e}")
        
        finally:
            if self.process:
                self.process.terminate()
                time.sleep(1)
                if self.process.poll() is None:
                    self.process.kill()
                self.process = None
                SCANNER_PROCESS = None
        
        return networks


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main function"""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(BANNER)
    
    Colors.print_colored("[+] Yevil - Real-Time WiFi Scanner", 'cyan', True)
    Colors.print_colored("[+] For Educational Purposes Only!", 'yellow')
    Colors.print_colored("[+] Press Ctrl+C to stop scanning and exit", 'yellow')
    print("="*50)
    
    # Check root
    if os.geteuid() != 0:
        Colors.print_colored("[!] This tool requires root privileges!", 'red')
        Colors.print_colored("[!] Please run with: sudo python3 yevil.py", 'yellow')
        sys.exit(1)
    
    # Create adapter handler
    handler = AdapterHandler()
    
    # Detect adapters
    adapters = handler.detect_adapters()
    
    if not adapters:
        Colors.print_colored("\n[!] No wireless adapters detected!", 'red')
        Colors.print_colored("[!] Please connect a USB WiFi adapter", 'yellow')
        sys.exit(1)
    
    # Display adapters
    Colors.print_colored("\n📋 Detected Adapters:", 'cyan', True)
    for i, adapter in enumerate(adapters, 1):
        info = handler.get_adapter_info(adapter)
        Colors.print_colored(f"   {i}. {adapter} ({info['mode']})", 'white')
    
    # Select adapter
    print()
    while True:
        try:
            choice = input("[?] Select adapter (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
            else:
                Colors.print_colored("[-] Invalid selection!", 'red')
        except ValueError:
            Colors.print_colored("[-] Enter a valid number!", 'red')
    
    Colors.print_colored(f"\n[+] Selected: {selected}", 'green')
    
    # Check mode
    info = handler.get_adapter_info(selected)
    
    if info['mode'] != 'Monitor':
        Colors.print_colored("[!] Adapter is not in monitor mode!", 'yellow')
        set_mon = input("\n[?] Set monitor mode now? (y/n): ")
        if set_mon.lower() == 'y':
            if handler.set_monitor_mode(selected):
                monitor_adapter = handler.monitor_interface
                Colors.print_colored(f"[+] Using: {monitor_adapter}", 'green')
            else:
                Colors.print_colored("[!] Failed to set monitor mode!", 'red')
                sys.exit(1)
        else:
            Colors.print_colored("[+] Exiting...", 'yellow')
            sys.exit(0)
    else:
        monitor_adapter = selected
        global MONITOR_INTERFACE
        MONITOR_INTERFACE = selected
        Colors.print_colored(f"[+] Already in monitor mode: {monitor_adapter}", 'green')
    
    # Start scanner
    scanner = RealTimeScanner(monitor_adapter)
    networks = scanner.scan_realtime()
    
    if networks:
        Colors.print_colored(f"\n[+] Found {len(networks)} networks", 'green', True)
    else:
        Colors.print_colored("\n[-] No networks found!", 'red')
        Colors.print_colored("[!] Make sure you're near a WiFi router", 'yellow')
    
    # Cleanup
    print("\n" + "="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup_monitor_mode()
    else:
        Colors.print_colored("[+] Adapter remains in monitor mode", 'yellow')
        Colors.print_colored(f"[+] To cleanup: sudo ip link set {monitor_adapter} down && sudo iw dev {monitor_adapter} set type managed && sudo ip link set {monitor_adapter} up", 'yellow')
    
    Colors.print_colored("\n[+] Done!", 'green', True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Ctrl+C detected. Cleaning up...", 'yellow')
        cleanup_monitor_mode()
        Colors.print_colored("[+] Goodbye!", 'cyan', True)
        sys.exit(0)
    except Exception as e:
        Colors.print_colored(f"\n[-] Error: {e}", 'red')
        cleanup_monitor_mode()
        sys.exit(1)
