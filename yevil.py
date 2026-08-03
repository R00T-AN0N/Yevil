#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Direct Command Approach - Uses the exact command that works
"""

import os
import sys
import subprocess
import re
import time
import signal
import threading
import pty
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
            time.sleep(1)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
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
        except Exception as e:
            print(f"[-] Cleanup error: {e}")
    
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                     capture_output=True, check=False)
        print("[+] NetworkManager restarted")
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
        except:
            pass
        
        self.adapters = adapters
        return adapters
    
    def get_adapter_info(self, adapter: str) -> dict:
        info = {'name': adapter, 'mode': 'Unknown'}
        
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
            
            print("[+] Setting monitor mode using iw...")
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], 
                         check=True, capture_output=True)
            subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], 
                         check=True, capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], 
                         check=True, capture_output=True)
            
            MONITOR_INTERFACE = adapter
            self.monitor_interface = MONITOR_INTERFACE
            
            # Verify
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
# SCANNER - DIRECT APPROACH
# ============================================

def scan_networks_direct(adapter):
    """Scan networks using the exact command that works"""
    global SCANNER_PROCESS
    
    print(f"\n[+] Starting scan on {adapter}")
    print("[+] Press Ctrl+C to stop")
    print("[+] Scanning for access points...\n")
    print("="*120)
    
    # The exact command that works
    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg']
    print(f"[+] Running: {' '.join(cmd)}\n")
    print("="*120)
    
    try:
        # Use pty to handle the output properly
        master_fd, slave_fd = pty.openpty()
        
        process = subprocess.Popen(
            cmd,
            stdout=slave_fd,
            stderr=slave_fd,
            stdin=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        SCANNER_PROCESS = process
        
        # Close slave fd in parent
        os.close(slave_fd)
        
        # Read from master fd
        output_buffer = []
        
        while True:
            try:
                # Read a chunk of data
                data = os.read(master_fd, 1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                # Print directly to stdout
                sys.stdout.write(data)
                sys.stdout.flush()
                
                # Store in buffer
                output_buffer.append(data)
                
            except Exception as e:
                break
        
        process.wait()
        SCANNER_PROCESS = None
        os.close(master_fd)
        
        return output_buffer
        
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        return []


# ============================================
# SIMPLE SCANNER - JUST PASS THROUGH
# ============================================

def scan_networks_simple(adapter):
    """Simply pass through the airodump-ng output"""
    global SCANNER_PROCESS
    
    print(f"\n[+] Starting scan on {adapter}")
    print("[+] Press Ctrl+C to stop")
    print("[+] Scanning for access points...\n")
    print("="*120)
    
    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg']
    print(f"[+] Running: {' '.join(cmd)}\n")
    print("="*120)
    
    try:
        # Use subprocess with PIPE and read line by line
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        SCANNER_PROCESS = process
        
        # Read and print output in real-time
        while True:
            line = process.stdout.readline()
            if not line:
                break
            sys.stdout.write(line)
            sys.stdout.flush()
        
        process.wait()
        SCANNER_PROCESS = None
        
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        
    finally:
        if SCANNER_PROCESS:
            SCANNER_PROCESS.terminate()
            time.sleep(1)
            if SCANNER_PROCESS.poll() is None:
                SCANNER_PROCESS.kill()
            SCANNER_PROCESS = None


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main function"""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print(BANNER)
    
    Colors.print_colored("[+] Yevil - WiFi Security Testing Tool", 'cyan', True)
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
    
    # Ask which scan method to use
    print("\n[+] Choose scanning method:")
    print("   1. Simple (recommended) - Direct pass-through")
    print("   2. Alternative - PTY method")
    choice = input("\n[?] Select method (1-2, default=1): ")
    
    if choice == '2':
        scan_networks_direct(monitor_adapter)
    else:
        scan_networks_simple(monitor_adapter)
    
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
