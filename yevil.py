#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Real-Time Network Scanner
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
SCANNER_RUNNING = False

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
    
    if MONITOR_INTERFACE and 'mon' in MONITOR_INTERFACE:
        try:
            print(f"[+] Stopping monitor interface: {MONITOR_INTERFACE}")
            subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_INTERFACE], 
                         capture_output=True, text=True, check=False)
            time.sleep(1)
        except:
            pass
    
    if ORIGINAL_INTERFACE and ORIGINAL_INTERFACE != MONITOR_INTERFACE:
        try:
            print(f"[+] Resetting {ORIGINAL_INTERFACE} to managed mode...")
            subprocess.run(['sudo', 'ip', 'link', 'set', ORIGINAL_INTERFACE, 'down'], 
                         capture_output=True, check=False)
            subprocess.run(['sudo', 'iw', 'dev', ORIGINAL_INTERFACE, 'set', 'type', 'managed'], 
                         capture_output=True, check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', ORIGINAL_INTERFACE, 'up'], 
                         capture_output=True, check=False)
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
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    adapter = line.split()[0]
                    if adapter not in adapters:
                        adapters.append(adapter)
            
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
            print("[+] Killing interfering processes...")
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            time.sleep(1)
            
            print("[+] Running: sudo airmon-ng start " + adapter)
            result = subprocess.run(['sudo', 'airmon-ng', 'start', adapter], 
                                  capture_output=True, text=True)
            
            # Find monitor interface
            for line in result.stdout.split('\n'):
                if 'mon' in line and adapter in line:
                    match = re.search(r'(\w+mon\d*)', line)
                    if match:
                        MONITOR_INTERFACE = match.group(1)
                        self.monitor_interface = MONITOR_INTERFACE
                        print(f"[+] Monitor mode enabled on {MONITOR_INTERFACE}")
                        return True
            
            # If not found, try manual
            print("[+] Manual monitor mode setup...")
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], check=True)
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], check=True)
            
            MONITOR_INTERFACE = adapter
            self.monitor_interface = MONITOR_INTERFACE
            print(f"[+] Monitor mode enabled on {MONITOR_INTERFACE}")
            return True
                
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
        
        if len(parts) < 10:
            return None
        
        bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        if not re.match(bssid_pattern, parts[0]):
            return None
        
        try:
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
                'ssid': ' '.join(parts[10:]) if len(parts) > 10 else '<Hidden>'
            }
        except:
            return None
    
    def print_header(self):
        """Print table header"""
        print("\033[2J\033[H")  # Clear screen
        print("="*120)
        print(f"🔍 YEVIL - Real-Time WiFi Scanner on {self.adapter}".center(120))
        print("="*120)
        print()
        print(f"{'#':<4} {'ESSID':<30} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'CIPHER':<8} {'AUTH':<12} {'BEACONS':<8}")
        print("-"*120)
    
    def print_network(self, num: int, net: dict):
        """Print a network row"""
        ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
        if ssid == '' or ssid == '<length: 0>':
            ssid = '<Hidden>'
        
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
            f"{num:<4} {ssid[:30]:<30} {net['bssid']:<18} {net['channel']:<4} "
            f"{net['power']:<6} {net['encryption']:<8} {net['cipher']:<8} "
            f"{net['authentication']:<12} {net['beacons']:<8}",
            color
        )
    
    def scan_realtime(self):
        """Scan in real-time mode"""
        global SCANNER_PROCESS, SCANNER_RUNNING
        
        print(f"\n[+] Starting real-time scan on {self.adapter}")
        print("[+] Press Ctrl+C to stop")
        print("[+] Waiting for networks...\n")
        time.sleep(1)
        
        self.print_header()
        
        networks = []
        in_bssid_section = False
        last_update = time.time()
        
        try:
            self.process = subprocess.Popen(
                ['sudo', 'airodump-ng', self.adapter, '--band', 'abg'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            SCANNER_PROCESS = self.process
            SCANNER_RUNNING = True
            
            while self.running:
                try:
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    if 'BSSID' in line and 'PWR' in line:
                        in_bssid_section = True
                        continue
                    
                    if in_bssid_section and 'Station' in line:
                        in_bssid_section = False
                        continue
                    
                    if in_bssid_section and line.strip():
                        net = self.parse_line(line)
                        if net:
                            # Check if new network (unique BSSID)
                            exists = False
                            for existing in networks:
                                if existing['bssid'] == net['bssid']:
                                    exists = True
                                    break
                            if not exists:
                                networks.append(net)
                    
                    # Update display every 0.3 seconds
                    if time.time() - last_update >= 0.3:
                        self.print_header()
                        for i, net in enumerate(networks, 1):
                            self.print_network(i, net)
                        
                        print("-"*120)
                        print(f"Networks found: {len(networks)} | Adapter: {self.adapter} (Monitor Mode)")
                        print("[Press Ctrl+C to stop scanning]")
                        print("="*120)
                        last_update = time.time()
                        
                except:
                    break
            
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
            SCANNER_RUNNING = False
        
        return networks


# ============================================
# MAIN
# ============================================

def main():
    """Main function"""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(BANNER)
    
    Colors.print_colored("[+] Yevil - Real-Time WiFi Scanner", 'cyan', True)
    Colors.print_colored("[+] For Educational Purposes Only!", 'yellow')
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
    
    # Start real-time scanner
    scanner = RealTimeScanner(monitor_adapter)
    
    Colors.print_colored("\n[+] Starting real-time scan...", 'cyan', True)
    Colors.print_colored("[+] Press Ctrl+C to stop\n", 'yellow')
    time.sleep(1)
    
    networks = scanner.scan_realtime()
    
    if networks:
        Colors.print_colored(f"\n[+] Found {len(networks)} networks during scan", 'green', True)
    else:
        Colors.print_colored("\n[-] No networks found!", 'red')
    
    # Cleanup
    print("\n" + "="*50)
    cleanup_choice = input("\n[?] Cleanup monitor mode? (y/n): ")
    if cleanup_choice.lower() == 'y':
        cleanup_monitor_mode()
    else:
        Colors.print_colored("[+] Adapter remains in monitor mode", 'yellow')
        Colors.print_colored("[+] To cleanup: sudo airmon-ng stop " + (monitor_adapter or ''), 'yellow')
    
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
