#!/usr/bin/env python3
"""
Debug Script - Test WiFi Scanning Step by Step
"""

import os
import sys
import subprocess
import re
import time

class Colors:
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    cyan = '\033[96m'
    white = '\033[97m'
    reset = '\033[0m'
    bold = '\033[1m'

def print_colored(text, color='white', bold=False):
    style = Colors.bold if bold else ''
    print(f"{style}{getattr(Colors, color, '')}{text}{Colors.reset}")

def run_command(cmd):
    """Run a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def main():
    print("\n" + "="*60)
    print_colored("🔍 YEVIL - Network Scanning Debug Tool", 'cyan', True)
    print("="*60)
    
    # Check root
    if os.geteuid() != 0:
        print_colored("[!] This script requires root privileges!", 'red')
        print_colored("[!] Please run with: sudo python3 debug_scan.py", 'yellow')
        sys.exit(1)
    
    # Step 1: List all interfaces
    print_colored("\n[Step 1] Checking all network interfaces...", 'cyan', True)
    stdout, stderr = run_command("ip link show")
    print(stdout)
    
    # Step 2: Find wireless adapters
    print_colored("\n[Step 2] Finding wireless adapters...", 'cyan', True)
    stdout, stderr = run_command("iwconfig")
    print(stdout)
    
    # Step 3: Parse adapters
    adapters = []
    for line in stdout.split('\n'):
        if 'IEEE 802.11' in line:
            adapter = line.split()[0]
            adapters.append(adapter)
            print_colored(f"   Found: {adapter}", 'green')
    
    if not adapters:
        print_colored("[!] No wireless adapters found!", 'red')
        sys.exit(1)
    
    # Step 4: Select adapter
    print_colored("\n[Step 3] Select adapter:", 'cyan', True)
    for i, adapter in enumerate(adapters, 1):
        status = "Monitor" if 'mon' in adapter else "Managed"
        print(f"   {i}. {adapter} ({status})")
    
    choice = input("\n[?] Enter adapter number: ")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(adapters):
            adapter = adapters[idx]
        else:
            print_colored("[-] Invalid selection!", 'red')
            sys.exit(1)
    except:
        print_colored("[-] Invalid input!", 'red')
        sys.exit(1)
    
    print_colored(f"\n[+] Selected: {adapter}", 'green')
    
    # Step 5: Check current mode
    print_colored(f"\n[Step 4] Checking mode for {adapter}...", 'cyan', True)
    stdout, stderr = run_command(f"iwconfig {adapter}")
    print(stdout)
    
    # Step 6: Set monitor mode if needed
    if 'Mode:Monitor' not in stdout:
        print_colored(f"\n[Step 5] Setting {adapter} to monitor mode...", 'cyan', True)
        
        # Kill interfering processes
        run_command("sudo airmon-ng check kill")
        time.sleep(1)
        
        # Try airmon-ng
        print_colored("[+] Running: sudo airmon-ng start " + adapter, 'blue')
        stdout, stderr = run_command(f"sudo airmon-ng start {adapter}")
        print(stdout)
        
        # Find new monitor interface
        monitor_interface = None
        for line in stdout.split('\n'):
            if 'mon' in line and adapter in line:
                match = re.search(r'(\w+mon\d*)', line)
                if match:
                    monitor_interface = match.group(1)
                    break
        
        if not monitor_interface:
            # Check if adapter itself is in monitor mode
            stdout2, stderr = run_command(f"iwconfig {adapter}")
            if 'Mode:Monitor' in stdout2:
                monitor_interface = adapter
        
        if monitor_interface:
            print_colored(f"[+] Monitor interface: {monitor_interface}", 'green')
            adapter = monitor_interface
        else:
            print_colored("[!] Could not find monitor interface!", 'red')
            print_colored("[+] Trying manual method...", 'yellow')
            
            # Manual method
            run_command(f"sudo ip link set {adapter} down")
            run_command(f"sudo iw dev {adapter} set type monitor")
            run_command(f"sudo ip link set {adapter} up")
            
            stdout, stderr = run_command(f"iwconfig {adapter}")
            if 'Mode:Monitor' in stdout:
                print_colored(f"[+] {adapter} is now in monitor mode", 'green')
                monitor_interface = adapter
            else:
                print_colored("[!] Manual method also failed!", 'red')
                sys.exit(1)
    else:
        monitor_interface = adapter
        print_colored(f"[+] {adapter} is already in monitor mode", 'green')
    
    # Step 7: Test scanning
    print_colored(f"\n[Step 6] Testing scanning on {monitor_interface}...", 'cyan', True)
    print_colored("[+] Running: sudo timeout 10 airodump-ng " + monitor_interface + " --band abg", 'blue')
    print_colored("[+] This will run for 10 seconds...", 'yellow')
    print_colored("[+] Press Ctrl+C to stop early\n", 'yellow')
    
    # Run airodump-ng with timeout
    try:
        process = subprocess.Popen(
            ['sudo', 'timeout', '10', 'airodump-ng', monitor_interface, '--band', 'abg'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Read output for 10 seconds
        lines = []
        start_time = time.time()
        found_networks = False
        
        print_colored("\n" + "="*80, 'cyan')
        print_colored("📡 SCANNING OUTPUT:", 'cyan', True)
        print_colored("="*80, 'cyan')
        
        while time.time() - start_time < 10:
            try:
                line = process.stdout.readline()
                if line:
                    lines.append(line)
                    # Check if this line has a BSSID
                    if re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line):
                        found_networks = True
                        print_colored(f"   {line.strip()}", 'green')
                    elif 'BSSID' in line:
                        print_colored(f"   {line.strip()}", 'yellow')
            except:
                break
        
        process.terminate()
        time.sleep(1)
        
        print_colored("="*80, 'cyan')
        
        if found_networks:
            print_colored("\n[+] ✅ SUCCESS! Networks detected!", 'green', True)
        else:
            print_colored("\n[!] ❌ No networks detected!", 'red', True)
            print_colored("\n[!] Possible reasons:", 'yellow')
            print_colored("   1. No WiFi networks in range", 'white')
            print_colored("   2. Adapter not in monitor mode properly", 'white')
            print_colored("   3. Adapter doesn't support monitor mode", 'white')
            print_colored("   4. aircrack-ng not installed correctly", 'white')
            print_colored("\n[+] Try manually:", 'yellow')
            print_colored(f"   sudo airodump-ng {monitor_interface} --band abg", 'white')
            
    except Exception as e:
        print_colored(f"[-] Error: {e}", 'red')
    
    # Step 8: Cleanup
    print_colored(f"\n[Step 7] Cleaning up...", 'cyan', True)
    cleanup = input("\n[?] Stop monitor mode and cleanup? (y/n): ")
    if cleanup.lower() == 'y':
        if monitor_interface:
            run_command(f"sudo airmon-ng stop {monitor_interface}")
            print_colored("[+] Monitor mode stopped", 'green')
        
        run_command("sudo systemctl restart NetworkManager")
        print_colored("[+] NetworkManager restarted", 'green')
    
    print("\n" + "="*60)
    print_colored("[+] Debug complete!", 'green', True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\n[+] Stopped by user", 'yellow')
        sys.exit(0)
