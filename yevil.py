#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Ultimate Simple Version - Direct Command Execution
"""

import os
import sys
import subprocess
import re
import time
import signal

# ============================================
# COLORS
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

# ============================================
# CLEANUP
# ============================================

def cleanup():
    global MONITOR_INTERFACE
    print("\n[+] Cleaning up...")
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
    print("\n[!] Ctrl+C detected")
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
        # Kill interfering processes
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                     capture_output=True, text=True)
        time.sleep(1)
        
        # Set monitor mode
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'down'], 
                     check=True, capture_output=True)
        subprocess.run(['sudo', 'iw', 'dev', adapter, 'set', 'type', 'monitor'], 
                     check=True, capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', adapter, 'up'], 
                     check=True, capture_output=True)
        
        MONITOR_INTERFACE = adapter
        
        # Verify
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
# MAIN SCANNER - DIRECT EXECUTION
# ============================================

def run_scan(adapter):
    """Run airodump-ng directly - this will show output in real-time"""
    cmd = ['sudo', 'airodump-ng', adapter, '--band', 'abg']
    print(f"\n[+] Running: {' '.join(cmd)}")
    print("[+] Press Ctrl+C to stop\n")
    print("="*120)
    
    # Execute the command - stdout will go directly to terminal
    # This is the same as running it manually
    try:
        subprocess.run(cmd, stdout=None, stderr=None, check=False)
    except KeyboardInterrupt:
        # Will be caught by main handler
        raise
    except Exception as e:
        print(f"[-] Error: {e}")

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
    
    # Run the scan
    run_scan(monitor_adapter)
    
    # After scan finishes (or user Ctrl+C), ask for cleanup
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
