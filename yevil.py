#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Step 2: Live Network Scanning with Interactive Selection
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
        Colors.print_colored("\n[+] Scanning for wireless adapters...", 'cyan', True)
        
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
            
            if os.path.exists('/sys/class/net/'):
                for device in os.listdir('/sys/class/net/'):
                    if device.startswith('wlan') or device.startswith('wlp') or 'mon' in device:
                        if device not in adapters:
                            adapters.append(device)
        
        except Exception as e:
            Colors.print_colored(f"[-] Error detecting adapters: {e}", 'red')
        
        self.adapters = adapters
        
        if adapters:
            Colors.print_colored(f"[+] Found {len(adapters)} adapter(s)", 'green')
        else:
            Colors.print_colored("[!] No wireless adapters found!", 'yellow')
        
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
        Colors.print_colored(f"\n[+] Setting {adapter} to monitor mode with TX Power 30...", 'cyan', True)
        
        try:
            Colors.print_colored("[+] Killing interfering processes...", 'blue')
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            time.sleep(1)
            
            Colors.print_colored("[+] Bringing interface down...", 'blue')
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], 
                         check=True, capture_output=True)
            
            Colors.print_colored("[+] Setting monitor mode...", 'blue')
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], 
                         check=True, capture_output=True)
            
            Colors.print_colored("[+] Bringing interface up...", 'blue')
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], 
                         check=True, capture_output=True)
            
            Colors.print_colored("[+] Setting TX power to 30 dBm...", 'blue')
            try:
                subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'txpower', 'fixed', '30'], 
                             check=True, capture_output=True)
            except:
                Colors.print_colored("[!] Could not set TX power to 30. Trying 20...", 'yellow')
                try:
                    subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'txpower', 'fixed', '20'], 
                                 check=True, capture_output=True)
                except:
                    Colors.print_colored("[!] Could not set TX power. Using default.", 'yellow')
            
            self.monitor_interface = adapter
            Colors.print_colored(f"\n[+] ✅ {adapter} is now in MONITOR MODE!", 'green', True)
            
            return True
            
        except Exception as e:
            Colors.print_colored(f"[-] Failed to set monitor mode: {e}", 'red')
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
        
    def parse_airodump_output(self, lines: list) -> list:
        """Parse airodump-ng output lines"""
        networks = []
        # Regular expression for BSSID
        bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        
        # Find the BSSID section in airodump output
        in_bssid_section = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Look for BSSID header
            if 'BSSID' in line and 'PWR' in line:
                in_bssid_section = True
                continue
            
            if in_bssid_section:
                # Check if we reached the Station section
                if 'Station' in line:
                    break
                
                # Try to parse BSSID line
                parts = line.split()
                if len(parts) >= 8:
                    # Check if first part looks like BSSID
                    if re.match(bssid_pattern, parts[0]):
                        bssid = parts[0]
                        power = parts[1] if len(parts) > 1 else '0'
                        channel = parts[2] if len(parts) > 2 else '0'
                        encryption = parts[5] if len(parts) > 5 else 'OPN'
                        
                        # Find SSID (usually at the end)
                        ssid = ' '.join(parts[6:]) if len(parts) > 6 else '<Hidden>'
                        # Sometimes SSID is after encryption
                        if len(parts) > 10:
                            # Try to find SSID
                            for i, part in enumerate(parts):
                                if part in ['WPA2', 'WPA', 'WEP', 'OPN', 'WPA3'] and i < len(parts) - 1:
                                    ssid = ' '.join(parts[i+1:])
                                    break
                        
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
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_scan_header(self, num_networks: int):
        """Print the scan header"""
        print(Colors.clear)
        print("="*100)
        Colors.print_colored(f"🔍 YEVIL - Scanning Networks on {self.adapter}", 'cyan', True)
        Colors.print_colored("="*100, 'cyan')
        print()
        print(f"{'NUM':<5} {'ESSID':<30} {'CH':<5} {'ENCR':<8} {'POWER':<8} {'WPS?':<6} {'CLIENTS':<10}")
        print("-"*100)
    
    def print_network_row(self, num: int, network: dict):
        """Print a single network row"""
        ssid = network['ssid'][:30] if len(network['ssid']) > 30 else network['ssid']
        power = network['power']
        channel = network['channel']
        encryption = network['encryption']
        
        # Check for WPS (we'll assume WPS for now, can be enhanced)
        wps = "WPS" if "WPS" in ssid or len(ssid) > 0 else ""
        
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
        
        Colors.print_colored(
            f"{num:<5} {ssid:<30} {channel:<5} {encryption:<8} {power:<8} {wps:<6} {'---':<10}",
            color
        )
    
    def display_networks(self, networks: list):
        """Display networks in a live table"""
        if not networks:
            return
        
        # Clear screen and print header
        self.clear_screen()
        self.print_scan_header(len(networks))
        
        # Print each network
        for i, net in enumerate(networks, 1):
            self.print_network_row(i, net)
        
        # Print footer
        print("-"*100)
        Colors.print_colored(f"Networks found: {len(networks)}", 'cyan', True)
        Colors.print_colored(f"Adapter: {self.adapter} (Monitor Mode)", 'green')
        Colors.print_colored("\n[Press any key to stop scanning and select target]", 'yellow', True)
        print("="*100)
    
    def scan_networks_live(self) -> list:
        """Scan networks with live updating display"""
        Colors.print_colored(f"\n[+] Starting live scan on {self.adapter}...", 'green', True)
        Colors.print_colored("[+] Press any key to stop scanning and select target", 'yellow')
        
        self.networks = []
        self.running = True
        self.scanning = True
        
        # Start airodump-ng in background
        try:
            self.process = subprocess.Popen(
                ['sudo', 'airodump-ng', self.adapter, '--band', 'abg'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Clear screen
            self.clear_screen()
            
            # Read output in real-time
            lines_buffer = []
            
            while self.running:
                try:
                    # Read line with timeout
                    line = self.process.stdout.readline()
                    if not line:
                        break
                    
                    lines_buffer.append(line)
                    
                    # Keep only last 200 lines for parsing
                    if len(lines_buffer) > 200:
                        lines_buffer = lines_buffer[-200:]
                    
                    # Parse networks from buffer
                    networks = self.parse_airodump_output(lines_buffer)
                    
                    if networks:
                        self.networks = networks
                        self.display_networks(networks)
                    
                    # Check if user pressed a key
                    if self.check_key_pressed():
                        self.running = False
                        break
                        
                except:
                    break
            
            # Cleanup
            if self.process:
                self.process.terminate()
                time.sleep(1)
                if self.process.poll() is None:
                    self.process.kill()
            
            self.scanning = False
            return self.networks
            
        except Exception as e:
            Colors.print_colored(f"[-] Error during scan: {e}", 'red')
            return []
    
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
                if ch:
                    return True
            except:
                pass
            finally:
                termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
                fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
            
            return False
        except:
            # Fallback: check every second
            return False
    
    def select_target(self, networks: list) -> dict:
        """Let user select a target network"""
        if not networks:
            Colors.print_colored("\n[-] No networks found to select!", 'red')
            return None
        
        print("\n" + "="*60)
        Colors.print_colored("🎯 SELECT TARGET NETWORK", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        # Display summary table
        print(f"\n{'#':<5} {'ESSID':<30} {'BSSID':<20} {'CH':<5} {'PWR':<8}")
        print("-"*70)
        
        for i, net in enumerate(networks[:20], 1):  # Show max 20
            ssid = net['ssid'][:30] if len(net['ssid']) > 30 else net['ssid']
            bssid = net['bssid']
            channel = net['channel']
            power = net['power']
            Colors.print_colored(
                f"{i:<5} {ssid:<30} {bssid:<20} {channel:<5} {power:<8}",
                'white'
            )
        
        print("-"*70)
        
        while True:
            try:
                choice = input(f"\n[?] Enter network number (1-{len(networks)}) or 0 to cancel: ")
                idx = int(choice) - 1
                
                if idx == -1:
                    return None
                
                if 0 <= idx < len(networks):
                    selected = networks[idx]
                    Colors.print_colored(f"\n[+] Selected Network:", 'green', True)
                    Colors.print_colored(f"   SSID    : {selected['ssid']}", 'green')
                    Colors.print_colored(f"   BSSID   : {selected['bssid']}", 'green')
                    Colors.print_colored(f"   Channel : {selected['channel']}", 'green')
                    Colors.print_colored(f"   Power   : {selected['power']} dBm", 'green')
                    Colors.print_colored(f"   Encrypt : {selected['encryption']}", 'green')
                    return selected
                else:
                    Colors.print_colored("[-] Invalid selection!", 'red')
            except ValueError:
                Colors.print_colored("[-] Please enter a valid number!", 'red')

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main function"""
    print(BANNER)
    
    Colors.print_colored("[+] Yevil - WiFi Security Testing Tool", 'cyan', True)
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
        Colors.print_colored("[!] Please connect a compatible USB WiFi adapter.", 'yellow')
        sys.exit(1)
    
    # Display detected adapters
    Colors.print_colored("\n📋 Detected Adapters:", 'cyan', True)
    for i, adapter in enumerate(adapters, 1):
        info = handler.get_adapter_info(adapter)
        Colors.print_colored(f"   {i}. {adapter} ({info['mode']})", 'white')
    
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
                Colors.print_colored("[-] Invalid selection!", 'red')
        except ValueError:
            Colors.print_colored("[-] Please enter a valid number!", 'red')
    
    # Get and display info
    info = handler.get_adapter_info(selected)
    Colors.print_colored(f"\n[+] Selected: {selected}", 'green', True)
    
    # Check if in monitor mode
    if info['mode'] != 'Monitor':
        Colors.print_colored("[!] Adapter is not in monitor mode!", 'yellow')
        set_monitor = input("\n[?] Set monitor mode now? (y/n): ")
        if set_monitor.lower() == 'y':
            if handler.set_monitor_mode(selected):
                monitor_adapter = selected
            else:
                Colors.print_colored("[!] Failed to set monitor mode!", 'red')
                sys.exit(1)
        else:
            Colors.print_colored("[+] Exiting...", 'yellow')
            sys.exit(0)
    else:
        monitor_adapter = selected
    
    # Create scanner
    scanner = NetworkScanner(monitor_adapter)
    
    # Start live scan
    Colors.print_colored("\n[+] Starting live network scan...", 'cyan', True)
    Colors.print_colored("[+] Press any key to stop scanning and select target", 'yellow')
    time.sleep(2)
    
    networks = scanner.scan_networks_live()
    
    if networks:
        # Select target
        target = scanner.select_target(networks)
        if target:
            Colors.print_colored("\n[+] Target selected successfully!", 'green', True)
            Colors.print_colored(f"[+] Ready to capture packets from {target['ssid']}", 'green')
            
            # Save target info for next steps
            with open('/tmp/yevil_target.txt', 'w') as f:
                f.write(f"{target['bssid']}\n")
                f.write(f"{target['channel']}\n")
                f.write(f"{target['ssid']}\n")
        else:
            Colors.print_colored("\n[+] No target selected. Exiting...", 'yellow')
    else:
        Colors.print_colored("\n[-] No networks found!", 'red')
    
    print("\n" + "="*50)
    Colors.print_colored("[+] Done!", 'green', True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Stopped by user", 'yellow')
        sys.exit(0)
    except Exception as e:
        Colors.print_colored(f"\n[-] Error: {e}", 'red')
        sys.exit(1)
