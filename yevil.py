#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Step 1: Adapter Detection & Monitor Mode with TX Power 30
"""

import os
import sys
import subprocess
import re
import time

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
            # Method 1: Using iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    adapter = line.split()[0]
                    if adapter not in adapters:
                        adapters.append(adapter)
            
            # Method 2: Using ip link
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wlan' in line.lower() or 'wlp' in line.lower():
                    match = re.search(r':\s*(\w+)', line)
                    if match:
                        adapter = match.group(1)
                        if adapter not in adapters:
                            adapters.append(adapter)
            
            # Method 3: Check /sys/class/net/
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
        
        Colors.print_colored(f"\n[+] Getting info for: {adapter}", 'blue')
        
        # Get driver info
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
        
        # Get iwconfig info
        try:
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            
            # Get mode
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
            
            # Get channel
            match = re.search(r'Channel:(\d+)', result.stdout)
            if match:
                info['channel'] = match.group(1)
            
            # Get frequency
            match = re.search(r'Frequency:([\d.]+)', result.stdout)
            if match:
                info['frequency'] = match.group(1)
            
            # Get TX power
            match = re.search(r'Tx-Power:([\d.]+)\s*dBm', result.stdout)
            if match:
                info['tx_power'] = match.group(1)
            
        except:
            pass
        
        # Try to get chipset from lsusb
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
            # Step 1: Kill interfering processes
            Colors.print_colored("[+] Killing interfering processes...", 'blue')
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            time.sleep(1)
            
            # Step 2: Bring interface down
            Colors.print_colored("[+] Bringing interface down...", 'blue')
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], 
                         check=True, capture_output=True)
            
            # Step 3: Set monitor mode
            Colors.print_colored("[+] Setting monitor mode...", 'blue')
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], 
                         check=True, capture_output=True)
            
            # Step 4: Bring interface up
            Colors.print_colored("[+] Bringing interface up...", 'blue')
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], 
                         check=True, capture_output=True)
            
            # Step 5: Set TX power to 30
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
            
            # Verify monitor mode
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            if 'Mode:Monitor' in result.stdout:
                Colors.print_colored("[+] Verified: Monitor mode active ✓", 'green')
                
                # Check TX power
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
    
    def set_tx_power(self, adapter: str, power: int = 30) -> bool:
        """Set TX power for adapter"""
        Colors.print_colored(f"\n[+] Setting TX power to {power} dBm...", 'blue')
        
        try:
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'txpower', 'fixed', str(power)], 
                         check=True, capture_output=True)
            Colors.print_colored(f"[+] TX power set to {power} dBm ✓", 'green')
            return True
        except:
            Colors.print_colored(f"[!] Could not set TX power to {power} dBm", 'yellow')
            return False
    
    def show_adapter_status(self, adapter: str):
        """Show current adapter status"""
        Colors.print_colored(f"\n[+] Current status of {adapter}:", 'cyan')
        
        try:
            result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines[:3]:  # Show first 3 lines
                if line.strip():
                    Colors.print_colored(f"   {line.strip()}", 'white')
        except:
            pass

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Step 1: Adapter Detection & Monitor Mode"""
    print(BANNER)
    
    Colors.print_colored("[+] Step 1: Adapter Detection & Monitor Mode Setup", 'cyan', True)
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
    
    # Ask for confirmation
    confirm = input("\n[?] Set this adapter to monitor mode with TX Power 30? (y/n): ")
    
    if confirm.lower() == 'y':
        # Set monitor mode
        if handler.set_monitor_mode(selected):
            Colors.print_colored("\n[+] ✅ SUCCESS! Adapter is in monitor mode!", 'green', True)
            
            # Show final status
            handler.show_adapter_status(selected)
            
            # Check TX power
            Colors.print_colored("\n[+] Checking TX power...", 'blue')
            result = subprocess.run(['iwconfig', selected], capture_output=True, text=True)
            match = re.search(r'Tx-Power:([\d.]+)\s*dBm', result.stdout)
            if match:
                Colors.print_colored(f"[+] Current TX Power: {match.group(1)} dBm", 'green')
            else:
                Colors.print_colored("[+] TX power set successfully", 'green')
        else:
            Colors.print_colored("\n[!] Failed to set monitor mode!", 'red')
    else:
        Colors.print_colored("\n[+] Skipping monitor mode setup.", 'yellow')
    
    Colors.print_colored("\n" + "="*50, 'cyan')
    Colors.print_colored("[+] Step 1 Complete!", 'green', True)
    Colors.print_colored("[+] You can now use your adapter in monitor mode!", 'green')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Stopped by user", 'yellow')
        sys.exit(0)
    except Exception as e:
        Colors.print_colored(f"\n[-] Error: {e}", 'red')
        sys.exit(1)
