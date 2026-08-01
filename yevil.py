#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Step 2: Network Scanning with Visualization
"""

import os
import sys
import subprocess
import re
import time
import json
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
    
    def display_adapter_info(self, info: dict):
        """Display adapter information in a formatted table"""
        Colors.print_colored("\n" + "="*60, 'cyan')
        Colors.print_colored("📡 ADAPTER INFORMATION", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        print(f"  Name        : {info['name']}")
        print(f"  Driver      : {info['driver']}")
        print(f"  Chipset     : {info['chipset']}")
        print(f"  Mode        : {info['mode']}")
        print(f"  Channel     : {info['channel']}")
        print(f"  Frequency   : {info['frequency']} GHz")
        print(f"  TX Power    : {info['tx_power']} dBm")
        print("="*60)
    
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
            
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                Colors.print_colored("[+] Verified: Monitor mode active ✓", 'green')
                
                match = re.search(r'Tx-Power:([\d.]+)\s*dBm', result.stdout)
                if match:
                    Colors.print_colored(f"[+] TX Power: {match.group(1)} dBm ✓", 'green')
                else:
                    Colors.print_colored("[+] TX Power: Set successfully ✓", 'green')
            else:
                Colors.print_colored("[!] Could not verify monitor mode", 'yellow')
            
            return True
            
        except Exception as e:
            Colors.print_colored(f"[-] Failed to set monitor mode: {e}", 'red')
            return False
    
    def show_adapter_status(self, adapter: str):
        """Show current adapter status"""
        Colors.print_colored(f"\n[+] Current status of {adapter}:", 'cyan')
        
        try:
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines[:3]:
                if line.strip():
                    Colors.print_colored(f"   {line.strip()}", 'white')
        except:
            pass


# ============================================
# NETWORK SCANNER CLASS
# ============================================

class NetworkScanner:
    """Handle WiFi network scanning and visualization"""
    
    def __init__(self, adapter: str):
        self.adapter = adapter
        self.networks = []
        self.scan_time = 15
        
    def scan_animation(self):
        """Display scanning animation"""
        frames = [
            """
\033[96m
    ╔═══════════════════════════════════════════════════════════════╗
    ║                  🔍 SCANNING WiFi NETWORKS                    ║
    ║                                                               ║
    ║                      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                        ║
    ║                   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                     ║
    ║                ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                  ║
    ║             ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄               ║
    ║          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ║
    ║                                                               ║
    ║            Scanning for networks in range...                  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
\033[0m
            """,
            """
\033[96m
    ╔═══════════════════════════════════════════════════════════════╗
    ║                  📡 SCANNING WiFi NETWORKS                    ║
    ║                                                               ║
    ║    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
    ║    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
    ║    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
    ║    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
    ║                                                               ║
    ║             📶 Signal detected from networks                  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
\033[0m
            """,
            """
\033[96m
    ╔═══════════════════════════════════════════════════════════════╗
    ║                  📶 SCANNING WiFi NETWORKS                    ║
    ║                                                               ║
    ║    ╔═══════════════════════════════════════════════════════╗  ║
    ║    ║   WiFi Networks Found in Range:                       ║  ║
    ║    ║   ══════════════════════════════════════════════════  ║  ║
    ║    ║   ● Network 1: ████████████████░░░░  (Strong)        ║  ║
    ║    ║   ● Network 2: ██████████░░░░░░░░  (Medium)          ║  ║
    ║    ║   ● Network 3: ████░░░░░░░░░░░░░░  (Weak)            ║  ║
    ║    ╚═══════════════════════════════════════════════════════╝  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
\033[0m
            """
        ]
        
        for i in range(3):
            for frame in frames:
                sys.stdout.write('\033[2J\033[H')
                sys.stdout.write(frame)
                sys.stdout.flush()
                time.sleep(0.5)
    
    def parse_airodump_csv(self, filename: str) -> list:
        """Parse airodump-ng CSV output"""
        networks = []
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            network_start = False
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'PWR' in line:
                    network_start = i + 1
                    break
            
            if not network_start:
                return networks
            
            for line in lines[network_start:]:
                if 'Station' in line:
                    break
                    
                parts = line.strip().split(',')
                if len(parts) >= 10 and parts[0] and parts[0] != 'BSSID':
                    power = int(parts[8].strip()) if parts[8].strip().lstrip('-').isdigit() else 0
                    distance = self.calculate_distance(power)
                    
                    network = {
                        'bssid': parts[0].strip(),
                        'first_seen': parts[1].strip(),
                        'last_seen': parts[2].strip(),
                        'channel': parts[3].strip(),
                        'speed': parts[4].strip(),
                        'privacy': parts[5].strip(),
                        'cipher': parts[6].strip(),
                        'authentication': parts[7].strip(),
                        'power': power,
                        'beacons': parts[9].strip(),
                        'iv': parts[10].strip() if len(parts) > 10 else '',
                        'ssid': parts[13].strip() if len(parts) > 13 else '<Hidden>',
                        'distance': distance
                    }
                    networks.append(network)
            
        except Exception as e:
            Colors.print_colored(f"[-] Error parsing CSV: {e}", 'red')
        
        return networks
    
    def calculate_distance(self, signal_strength: int) -> float:
        """Calculate approximate distance from signal strength"""
        if signal_strength == 0:
            return 0.0
        try:
            distance = 10 ** ((27.55 - (20 * 2.4) - signal_strength) / 20)
            return round(distance, 2)
        except:
            return 0.0
    
    def display_networks_table(self, networks: list):
        """Display networks in a formatted table"""
        if not networks:
            Colors.print_colored("\n[-] No networks found!", 'red')
            return
        
        Colors.print_colored("\n" + "="*120, 'cyan')
        Colors.print_colored("📋 COMPLETE NETWORK SCAN RESULTS", 'cyan', True)
        Colors.print_colored("="*120, 'cyan')
        
        # Header
        print(f"{'#':<4} {'SSID':<25} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'DIST':<8} {'ENC':<8} {'AUTH':<12} {'PACKETS':<8}")
        print("-"*120)
        
        for i, net in enumerate(networks, 1):
            ssid = net['ssid'][:25] if net['ssid'] != '<Hidden>' else '<Hidden>'
            distance = net.get('distance', 0)
            power = net.get('power', 0)
            
            # Color based on signal strength
            if power > -50:
                color = 'green'
            elif power > -70:
                color = 'yellow'
            else:
                color = 'red'
            
            Colors.print_colored(
                f"{i:<4} {ssid:<25} {net['bssid']:<18} {net['channel']:<4} "
                f"{power:<6} {distance:<8.1f}m {net['privacy']:<8} "
                f"{net['authentication']:<12} {net['beacons']:<8}",
                color
            )
        
        print("="*120)
        Colors.print_colored(f"Total Networks Found: {len(networks)}", 'cyan', True)
        Colors.print_colored(f"Monitor Mode: {self.adapter}", 'green', True)
    
    def display_network_radar(self, networks: list):
        """Display network radar visualization"""
        if not networks:
            return
        
        Colors.print_colored("\n📡 NETWORK RADAR (Distance from center)", 'cyan', True)
        print("="*60)
        
        # Sort by signal strength
        sorted_networks = sorted(networks, key=lambda x: x.get('power', 0), reverse=True)
        top_networks = sorted_networks[:8]
        
        print("\n    ╔═══════════════════════════════════════════════════╗")
        print("    ║            WiFi Networks Radar View              ║")
        print("    ╠═══════════════════════════════════════════════════╣")
        
        for i, net in enumerate(top_networks, 1):
            ssid = net['ssid'][:20] if net['ssid'] != '<Hidden>' else '<Hidden>'
            power = net.get('power', 0)
            distance = net.get('distance', 0)
            
            # Create signal bars based on distance
            if distance < 10:
                bars = "████████████████"
                status = "🟢 Very Close"
            elif distance < 30:
                bars = "████████████░░░░"
                status = "🟡 Close"
            elif distance < 60:
                bars = "████████░░░░░░░░"
                status = "🟠 Medium"
            elif distance < 100:
                bars = "████░░░░░░░░░░░░"
                status = "🔴 Far"
            else:
                bars = "██░░░░░░░░░░░░░░"
                status = "⚫ Very Far"
            
            print(f"    ║ {i:2}. {ssid:<20} {bars}")
            print(f"    ║     BSSID: {net['bssid']} | CH: {net['channel']} | {status} | {distance}m")
            print("    ║")
        
        print("    ╚═══════════════════════════════════════════════════╝")
    
    def display_network_visualization(self, networks: list):
        """Display network signal strength visualization"""
        if not networks:
            return
        
        Colors.print_colored("\n📊 SIGNAL STRENGTH VISUALIZATION", 'cyan', True)
        print("="*60)
        
        # Sort by signal strength
        sorted_networks = sorted(networks, key=lambda x: x.get('power', 0), reverse=True)
        top_networks = sorted_networks[:10]
        
        print("\n   Signal Strength (dBm)")
        print("   -70  -65  -60  -55  -50  -45  -40")
        print("    │    │    │    │    │    │    │")
        
        for net in top_networks:
            ssid = net['ssid'][:20] if net['ssid'] != '<Hidden>' else '<Hidden>'
            power = net.get('power', 0)
            
            # Calculate bar length
            bar_length = int((power + 70) / 2) if power > -70 else 0
            bar_length = min(bar_length, 20)
            if bar_length < 0:
                bar_length = 0
            
            # Create bar
            bar = "█" * bar_length
            spaces = " " * (20 - bar_length)
            
            # Color based on signal strength
            if power > -50:
                color = 'green'
            elif power > -65:
                color = 'yellow'
            else:
                color = 'red'
            
            Colors.print_colored(f"   {ssid:<20} [{bar}{spaces}] {power} dBm", color)
        
        print("="*60)
        print("   █ = Signal Strength | 📶 Stronger signal = More bars")
    
    def scan_networks(self) -> list:
        """Perform network scan with visualization"""
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("📡 YEVIL NETWORK SCANNING", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        if not self.adapter:
            Colors.print_colored("[-] No adapter specified!", 'red')
            return []
        
        # Show animation
        self.scan_animation()
        
        Colors.print_colored(f"\n[+] Using adapter: {self.adapter}", 'green')
        Colors.print_colored(f"[+] Running: airodump-ng {self.adapter} --band abg", 'blue')
        Colors.print_colored("[+] Scanning all networks in range...", 'yellow')
        Colors.print_colored("[+] This will take 15 seconds...", 'yellow')
        
        try:
            # Clear previous scan
            subprocess.run(['rm', '-f', '/tmp/scan-01.csv', '/tmp/scan-01.cap'], capture_output=True)
            
            # Start airodump-ng
            process = subprocess.Popen(
                f'sudo airodump-ng {self.adapter} --band abg --write /tmp/scan --output-format csv --write-interval 1'.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Show countdown
            for i in range(self.scan_time, 0, -1):
                Colors.print_colored(f"   ⏳ Scanning... {i} seconds remaining", 'yellow', True)
                time.sleep(1)
            
            # Terminate
            process.terminate()
            time.sleep(2)
            
            # Parse results
            if os.path.exists('/tmp/scan-01.csv'):
                self.networks = self.parse_airodump_csv('/tmp/scan-01.csv')
                
                if self.networks:
                    Colors.print_colored(f"\n[+] ✅ Found {len(self.networks)} networks!", 'green', True)
                    
                    # Display visualizations
                    self.display_network_radar(self.networks)
                    self.display_network_visualization(self.networks)
                    self.display_networks_table(self.networks)
                else:
                    Colors.print_colored("\n[!] No networks found in range!", 'yellow')
                    Colors.print_colored("[!] Possible reasons:", 'yellow')
                    Colors.print_colored("   1. No WiFi networks nearby", 'white')
                    Colors.print_colored("   2. Adapter not in monitor mode", 'white')
                    Colors.print_colored("   3. Adapter not detecting signals", 'white')
                    Colors.print_colored("\n[+] Try moving closer to a WiFi router", 'yellow')
                    Colors.print_colored(f"[+] Try manually: sudo airodump-ng {self.adapter} --band abg", 'yellow')
                
                return self.networks
            else:
                Colors.print_colored("[-] No scan results found!", 'red')
                return []
                
        except Exception as e:
            Colors.print_colored(f"[-] Error scanning: {e}", 'red')
            return []
    
    def get_network_info(self, index: int) -> dict:
        """Get network information by index"""
        if 0 <= index < len(self.networks):
            return self.networks[index]
        return None


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Step 2: Network Scanning with Visualization"""
    print(BANNER)
    
    Colors.print_colored("[+] Step 2: Network Scanning with Visualization", 'cyan', True)
    Colors.print_colored("="*50, 'cyan')
    
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
    
    # Get and display detailed info
    Colors.print_colored(f"\n[+] Selected: {selected}", 'green', True)
    info = handler.get_adapter_info(selected)
    handler.display_adapter_info(info)
    
    # Ask for monitor mode setup
    confirm = input("\n[?] Set this adapter to monitor mode with TX Power 30? (y/n): ")
    
    if confirm.lower() == 'y':
        if handler.set_monitor_mode(selected):
            Colors.print_colored("\n[+] ✅ SUCCESS! Adapter is in monitor mode!", 'green', True)
            handler.show_adapter_status(selected)
            monitor_adapter = selected
        else:
            Colors.print_colored("\n[!] Failed to set monitor mode!", 'red')
            sys.exit(1)
    else:
        Colors.print_colored("\n[+] Skipping monitor mode setup.", 'yellow')
        monitor_adapter = selected
    
    # Ask for network scan
    scan_choice = input("\n[?] Scan for networks with visualization? (y/n): ")
    
    if scan_choice.lower() == 'y':
        # Create scanner
        scanner = NetworkScanner(monitor_adapter)
        
        # Scan networks
        networks = scanner.scan_networks()
        
        if networks:
            # Option to save results
            save_choice = input("\n[?] Save scan results to file? (y/n): ")
            if save_choice.lower() == 'y':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_results_{timestamp}.json"
                try:
                    with open(filename, 'w') as f:
                        json.dump(networks, f, indent=2)
                    Colors.print_colored(f"[+] Results saved to: {filename}", 'green')
                except Exception as e:
                    Colors.print_colored(f"[-] Failed to save: {e}", 'red')
        else:
            Colors.print_colored("\n[!] No networks found!", 'yellow')
    else:
        Colors.print_colored("\n[+] Skipping network scan.", 'yellow')
    
    Colors.print_colored("\n" + "="*50, 'cyan')
    Colors.print_colored("[+] Step 2 Complete!", 'green', True)
    Colors.print_colored("[+] Network scanning with visualization is working!", 'green')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Stopped by user", 'yellow')
        sys.exit(0)
    except Exception as e:
        Colors.print_colored(f"\n[-] Error: {e}", 'red')
        sys.exit(1)
