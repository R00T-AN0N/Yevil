#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Step 2: Live Network Scanning with Interactive Selection & Cleanup
"""

import os
import sys
import subprocess
import re
import time
import signal
import threading
import atexit
from datetime import datetime

# ============================================
# GLOBAL VARIABLES FOR CLEANUP
# ============================================

CLEANUP_DONE = False
MONITOR_INTERFACE = None
ORIGINAL_INTERFACE = None
SCANNER_PROCESS = None

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
# CLEANUP FUNCTIONS
# ============================================

def cleanup_monitor_mode():
    """Clean up monitor mode and restore normal mode"""
    global CLEANUP_DONE, MONITOR_INTERFACE, ORIGINAL_INTERFACE
    
    if CLEANUP_DONE:
        return
    
    CLEANUP_DONE = True
    
    print("\n\n" + "="*60)
    print("[+] Cleaning up monitor mode...")
    print("="*60)
    
    try:
        print("[+] Killing interfering processes...")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                     capture_output=True, text=True)
        time.sleep(1)
    except:
        pass
    
    if MONITOR_INTERFACE:
        try:
            print(f"[+] Stopping monitor interface: {MONITOR_INTERFACE}")
            subprocess.run(['sudo', 'airmon-ng', 'stop', MONITOR_INTERFACE], 
                         capture_output=True, text=True)
            time.sleep(1)
        except:
            pass
    
    if ORIGINAL_INTERFACE:
        try:
            print(f"[+] Resetting {ORIGINAL_INTERFACE} to managed mode...")
            subprocess.run(['sudo', 'ip', 'link', 'set', ORIGINAL_INTERFACE, 'down'], 
                         capture_output=True, check=False)
            subprocess.run(['sudo', 'iw', 'dev', ORIGINAL_INTERFACE, 'set', 'type', 'managed'], 
                         capture_output=True, check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', ORIGINAL_INTERFACE, 'up'], 
                         capture_output=True, check=False)
            print(f"[+] {ORIGINAL_INTERFACE} reset to managed mode")
            time.sleep(1)
        except:
            pass
    
    try:
        print("[+] Restarting NetworkManager...")
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                     capture_output=True, check=False)
        print("[+] NetworkManager restarted")
    except:
        pass
    
    try:
        subprocess.run(['sudo', 'pkill', '-f', 'airodump-ng'], capture_output=True, check=False)
        subprocess.run(['sudo', 'pkill', '-f', 'aireplay-ng'], capture_output=True, check=False)
    except:
        pass
    
    print("="*60)
    print("[+] Cleanup complete!")
    print("="*60)

def signal_handler(signum, frame):
    """Handle Ctrl+C and other signals"""
    print(f"\n\n[!] Signal {signum} received (Ctrl+C)")
    cleanup_monitor_mode()
    print("\n[+] Yevil exited safely. Goodbye!")
    sys.exit(0)

def register_cleanup():
    """Register cleanup handlers"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    atexit.register(cleanup_monitor_mode)

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
║           WiFi Security Testing Tool v1.0.0                   ║
║           ⚠️  For Educational Purposes Only!                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
\033[0m
"""

# ============================================
# ADAPTER HANDLER CLASS
# ============================================

class AdapterHandler:
    """Handle WiFi adapter detection and monitor mode setup"""
    
    def __init__(self):
        self.adapters = []
        self.selected_adapter = None
        self.monitor_interface = None
        
    def detect_adapters(self) -> list:
        """Detect all wireless adapters"""
        print("\n[+] Scanning for wireless adapters...")
        
        adapters = []
        
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    adapter = line.split()[0]
                    if adapter not in adapters and 'mon' not in adapter:
                        adapters.append(adapter)
            
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
                    match = re.search(r':\s*(\w+)', line)
                    if match:
                        adapter = match.group(1)
                        if adapter not in adapters and 'mon' not in adapter:
                            adapters.append(adapter)
            
            if os.path.exists('/sys/class/net/'):
                for device in os.listdir('/sys/class/net/'):
                    if (device.startswith('wlan') or device.startswith('wlp')) and 'mon' not in device:
                        if device not in adapters:
                            adapters.append(device)
        
        except Exception as e:
            print(f"[-] Error detecting adapters: {e}")
        
        self.adapters = list(set(adapters))
        
        if adapters:
            print(f"[+] Found {len(adapters)} adapter(s)")
        else:
            print("[!] No wireless adapters found!")
        
        return adapters
    
    def get_adapter_info(self, adapter: str) -> dict:
        """Get detailed information about an adapter"""
        info = {
            'name': adapter,
            'driver': 'Unknown',
            'chipset': 'Unknown',
            'tx_power': 'Unknown',
            'mode': 'Unknown',
            'channel': 'Unknown',
            'frequency': 'Unknown'
        }
        
        try:
            result = subprocess.run(['ethtool', '-i', adapter], 
                                  capture_output=True, text=True)
            if 'driver' in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'driver:' in line:
                        info['driver'] = line.split('driver:')[1].strip()
                        break
        except:
            pass
        
        try:
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            
            if 'Mode:Monitor' in result.stdout:
                info['mode'] = 'Monitor'
            elif 'Mode:Managed' in result.stdout:
                info['mode'] = 'Managed'
            elif 'Mode:Master' in result.stdout:
                info['mode'] = 'Master'
            else:
                match = re.search(r'Mode:(\w+)', result.stdout)
                if match:
                    info['mode'] = match.group(1)
            
            match = re.search(r'Channel:(\d+)', result.stdout)
            if match:
                info['channel'] = match.group(1)
            
            match = re.search(r'Frequency:([\d.]+)', result.stdout)
            if match:
                info['frequency'] = match.group(1)
            
            match = re.search(r'Tx-Power:([\d.]+)\s*dBm', result.stdout)
            if match:
                info['tx_power'] = match.group(1)
            
        except:
            pass
        
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            usb_chipsets = {
                'RTL8812': 'Realtek RTL8812AU',
                'RTL8188': 'Realtek RTL8188',
                'AR9271': 'Atheros AR9271',
                'MT7601': 'MediaTek MT7601',
                'Ralink': 'Ralink',
                'TP-Link': 'TP-Link'
            }
            
            for chipset in usb_chipsets:
                if chipset.lower() in result.stdout.lower():
                    info['chipset'] = usb_chipsets[chipset]
                    break
        except:
            pass
        
        return info
    
    def set_monitor_mode(self, adapter: str) -> bool:
        """Set adapter to monitor mode with TX power 30"""
        global MONITOR_INTERFACE, ORIGINAL_INTERFACE
        
        print(f"\n[+] Setting {adapter} to monitor mode with TX Power 30...")
        
        ORIGINAL_INTERFACE = adapter
        
        try:
            print("[+] Killing interfering processes...")
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            time.sleep(1)
            
            try:
                print("[+] Using airmon-ng...")
                result = subprocess.run(['sudo', 'airmon-ng', 'start', adapter], 
                                      capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if 'mon' in line and adapter in line:
                        match = re.search(r'(\w+mon\d*)', line)
                        if match:
                            MONITOR_INTERFACE = match.group(1)
                            self.monitor_interface = MONITOR_INTERFACE
                            print(f"[+] Monitor mode enabled on {MONITOR_INTERFACE}")
                            return True
            except Exception as e:
                print(f"   airmon-ng failed: {e}")
            
            print("[+] Using manual monitor mode setup...")
            
            commands = [
                f'sudo ip link set {adapter} down',
                f'sudo iw dev {adapter} set type monitor',
                f'sudo ip link set {adapter} up'
            ]
            for cmd in commands:
                subprocess.run(cmd.split(), check=True, capture_output=True)
            
            MONITOR_INTERFACE = adapter
            self.monitor_interface = MONITOR_INTERFACE
            
            try:
                subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'txpower', 'fixed', '30'], 
                             check=True, capture_output=True)
            except:
                pass
            
            print(f"[+] Monitor mode enabled on {MONITOR_INTERFACE}")
            return True
                
        except Exception as e:
            print(f"[-] Failed to set monitor mode: {e}")
            return False


# ============================================
# NETWORK SCANNER CLASS
# ============================================

class NetworkScanner:
    """Handle WiFi network scanning with live display"""
    
    def __init__(self, adapter: str):
        self.adapter = adapter
        self.networks = []
        self.running = True
        self.process = None
        self.scanning = False
        self.first_display = True
        
    def parse_airodump_output(self, lines: list) -> list:
        """Parse airodump-ng output lines"""
        networks = []
        bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        
        in_bssid_section = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'BSSID' in line and 'PWR' in line:
                in_bssid_section = True
                continue
            
            if in_bssid_section:
                if 'Station' in line:
                    break
                
                parts = line.split()
                if len(parts) >= 8:
                    if re.match(bssid_pattern, parts[0]):
                        bssid = parts[0]
                        power = parts[1] if len(parts) > 1 else '0'
                        channel = parts[2] if len(parts) > 2 else '0'
                        encryption = parts[5] if len(parts) > 5 else 'OPN'
                        
                        # Get SSID - it's usually at the end
                        ssid = '<Hidden>'
                        if len(parts) > 6:
                            # Try to find SSID
                            for i, part in enumerate(parts):
                                if part in ['WPA2', 'WPA', 'WEP', 'OPN', 'WPA3', 'WPA2-CCMP'] and i < len(parts) - 1:
                                    ssid = ' '.join(parts[i+1:])
                                    break
                            else:
                                ssid = ' '.join(parts[6:])
                        
                        network = {
                            'bssid': bssid,
                            'power': power,
                            'channel': channel,
                            'encryption': encryption,
                            'ssid': ssid if ssid else '<Hidden>'
                        }
                        networks.append(network)
        
        return networks
    
    def clear_screen(self):
        """Clear the screen and move cursor to top"""
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    
    def print_scan_header(self):
        """Print the scan header"""
        print("="*110)
        print(f"🔍 YEVIL - Scanning Networks on {self.adapter}".center(110))
        print("="*110)
        print()
        print(f"{'NUM':<5} {'ESSID':<35} {'BSSID':<20} {'CH':<5} {'ENCR':<10} {'POWER':<8} {'WPS?':<6} {'CLIENTS':<8}")
        print("-"*110)
    
    def print_network_row(self, num: int, network: dict):
        """Print a single network row"""
        ssid = network['ssid'][:35] if len(network['ssid']) > 35 else network['ssid']
        power = network['power']
        channel = network['channel']
        encryption = network['encryption']
        wps = "WPS" if "WPS" in ssid else ""
        
        # Color by signal strength
        try:
            power_val = int(power) if power.lstrip('-').isdigit() else 0
            if power_val > -50:
                color = 'green'
            elif power_val > -65:
                color = 'yellow'
            else:
                color = 'red'
        except:
            color = 'white'
        
        # Keep track of unique BSSIDs to avoid duplicates
        Colors.print_colored(
            f"{num:<5} {ssid[:35]:<35} {network['bssid']:<20} {channel:<5} {encryption:<10} {power:<8} {wps:<6} {'---':<8}",
            color
        )
    
    def display_networks(self, networks: list):
        """Display networks in a live table"""
        if not networks:
            return
        
        # Clear screen and print header
        self.clear_screen()
        self.print_scan_header()
        
        # Print each network (limit to 30)
        unique_bssids = {}
        for net in networks:
            if net['bssid'] not in unique_bssids:
                unique_bssids[net['bssid']] = net
        
        display_networks = list(unique_bssids.values())[:30]
        
        for i, net in enumerate(display_networks, 1):
            self.print_network_row(i, net)
        
        # Print footer
        print("-"*110)
        print(f"Networks found: {len(display_networks)} | Adapter: {self.adapter} (Monitor Mode)")
        print("\n[Press SPACE or ENTER to stop scanning and select target]")
        print("="*110)
    
    def check_key_pressed(self):
        """Check if a key was pressed (non-blocking)"""
        import termios
        import fcntl
        
        try:
            fd = sys.stdin.fileno()
            oldterm = termios.tcgetattr(fd)
            newattr = termios.tcgetattr(fd)
            newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSANOW, newattr)
            oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
            
            try:
                ch = sys.stdin.read(1)
                if ch and (ch == ' ' or ch == '\n' or ch == '\r' or ch == 'q'):
                    return True
            except:
                pass
            finally:
                termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
                fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
            
            return False
        except:
            return False
    
    def scan_networks_live(self) -> list:
        """Scan networks with live updating display"""
        global SCANNER_PROCESS
        
        print(f"\n[+] Starting live scan on {self.adapter}...")
        print("[+] Press SPACE, ENTER, or 'q' to stop scanning and select target")
        print("[+] Scanning for access points...")
        
        self.networks = []
        self.running = True
        self.scanning = True
        
        try:
            # Start airodump-ng with faster update
            self.process = subprocess.Popen(
                ['sudo', 'airodump-ng', self.adapter, '--band', 'abg'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            SCANNER_PROCESS = self.process
            
            # Show initial screen
            self.clear_screen()
            self.print_scan_header()
            print("\n" + " "*50 + "Scanning for networks...")
            print("-"*110)
            
            lines_buffer = []
            last_update = time.time()
            
            while self.running:
                try:
                    # Read line with timeout
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    lines_buffer.append(line)
                    if len(lines_buffer) > 200:
                        lines_buffer = lines_buffer[-200:]
                    
                    # Update display every 0.5 seconds
                    current_time = time.time()
                    if current_time - last_update >= 0.5:
                        networks = self.parse_airodump_output(lines_buffer)
                        if networks:
                            self.networks = networks
                            self.display_networks(networks)
                        last_update = current_time
                    
                    # Check if user pressed a key
                    if self.check_key_pressed():
                        self.running = False
                        break
                        
                except:
                    break
            
            # Final display
            if self.networks:
                self.display_networks(self.networks)
            
            if self.process:
                self.process.terminate()
                time.sleep(0.5)
                if self.process.poll() is None:
                    self.process.kill()
                self.process = None
                SCANNER_PROCESS = None
            
            self.scanning = False
            return self.networks
            
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            return []
    
    def select_target(self, networks: list) -> dict:
        """Let user select a target network"""
        if not networks:
            print("\n[-] No networks found to select!")
            return None
        
        # Clear duplicates
        unique_bssids = {}
        for net in networks:
            if net['bssid'] not in unique_bssids:
                unique_bssids[net['bssid']] = net
        
        unique_networks = list(unique_bssids.values())
        
        print("\n" + "="*70)
        print("🎯 SELECT TARGET NETWORK".center(70))
        print("="*70)
        
        print(f"\n{'#':<5} {'ESSID':<35} {'BSSID':<20} {'CH':<5} {'PWR':<8}")
        print("-"*70)
        
        for i, net in enumerate(unique_networks[:20], 1):
            ssid = net['ssid'][:35] if len(net['ssid']) > 35 else net['ssid']
            bssid = net['bssid']
            channel = net['channel']
            power = net['power']
            print(f"{i:<5} {ssid[:35]:<35} {bssid:<20} {channel:<5} {power:<8}")
        
        print("-"*70)
        
        while True:
            try:
                choice = input(f"\n[?] Enter network number (1-{len(unique_networks)}) or 0 to cancel: ")
                idx = int(choice) - 1
                
                if idx == -1:
                    return None
                
                if 0 <= idx < len(unique_networks):
                    selected = unique_networks[idx]
                    print(f"\n[+] Selected Network:")
                    print(f"   SSID    : {selected['ssid']}")
                    print(f"   BSSID   : {selected['bssid']}")
                    print(f"   Channel : {selected['channel']}")
                    print(f"   Power   : {selected['power']} dBm")
                    print(f"   Encrypt : {selected['encryption']}")
                    return selected
                else:
                    print("[-] Invalid selection!")
            except ValueError:
                print("[-] Please enter a valid number!")


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main function"""
    # Register cleanup handlers FIRST
    register_cleanup()
    
    print(BANNER)
    
    print("[+] Yevil - WiFi Security Testing Tool")
    print("[+] For Educational Purposes Only!")
    print("[+] Press Ctrl+C at any time to exit safely")
    print("="*50)
    
    # Check root
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges!")
        print("[!] Please run with: sudo python3 yevil.py")
        sys.exit(1)
    
    # Create adapter handler
    handler = AdapterHandler()
    
    # Detect adapters
    adapters = handler.detect_adapters()
    
    if not adapters:
        print("\n[!] No wireless adapters detected!")
        print("[!] Please connect a compatible USB WiFi adapter.")
        cleanup_monitor_mode()
        sys.exit(1)
    
    # Display detected adapters
    print("\n📋 Detected Adapters:")
    for i, adapter in enumerate(adapters, 1):
        info = handler.get_adapter_info(adapter)
        print(f"   {i}. {adapter} ({info['mode']})")
    
    # Select adapter
    print()
    while True:
        try:
            choice = input("[?] Select adapter number (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
            else:
                print("[-] Invalid selection!")
        except ValueError:
            print("[-] Please enter a valid number!")
    
    # Get and display info
    info = handler.get_adapter_info(selected)
    print(f"\n[+] Selected: {selected}")
    
    # Check if in monitor mode
    if info['mode'] != 'Monitor':
        print("[!] Adapter is not in monitor mode!")
        set_monitor = input("\n[?] Set monitor mode now? (y/n): ")
        if set_monitor.lower() == 'y':
            if handler.set_monitor_mode(selected):
                monitor_adapter = handler.monitor_interface
                print(f"[+] Using monitor interface: {monitor_adapter}")
            else:
                print("[!] Failed to set monitor mode!")
                cleanup_monitor_mode()
                sys.exit(1)
        else:
            print("[+] Exiting...")
            cleanup_monitor_mode()
            sys.exit(0)
    else:
        monitor_adapter = selected
        global MONITOR_INTERFACE
        MONITOR_INTERFACE = selected
        ORIGINAL_INTERFACE = selected
    
    # Create scanner
    scanner = NetworkScanner(monitor_adapter)
    
    # Start live scan
    print("\n[+] Starting live network scan...")
    print("[+] Press SPACE, ENTER, or 'q' to stop scanning and select target")
    time.sleep(2)
    
    networks = scanner.scan_networks_live()
    
    if networks:
        # Select target
        target = scanner.select_target(networks)
        if target:
            print("\n[+] Target selected successfully!")
            print(f"[+] Ready to capture packets from {target['ssid']}")
            
            # Save target info for next steps
            with open('/tmp/yevil_target.txt', 'w') as f:
                f.write(f"{target['bssid']}\n")
                f.write(f"{target['channel']}\n")
                f.write(f"{target['ssid']}\n")
        else:
            print("\n[+] No target selected. Exiting...")
    else:
        print("\n[-] No networks found!")
    
    print("\n" + "="*50)
    print("[+] Done!")
    
    # Cleanup before exit
    cleanup_monitor_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[+] Ctrl+C detected. Cleaning up...")
        cleanup_monitor_mode()
        print("[+] Exiting Yevil. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        cleanup_monitor_mode()
        sys.exit(1)
