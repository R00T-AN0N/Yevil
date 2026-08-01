#!/usr/bin/env python3
"""
Test Script: Debug Network Scanning
Run this to test if scanning works
"""

import os
import sys
import subprocess
import time
import re

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

def check_adapter_status(adapter):
    """Check if adapter is in monitor mode"""
    Colors.print_colored(f"\n[+] Checking {adapter} status...", 'cyan')
    try:
        result = subprocess.run(['iwconfig', adapter], capture_output=True, text=True)
        print(result.stdout)
        
        if 'Mode:Monitor' in result.stdout:
            Colors.print_colored("✅ Adapter is in MONITOR MODE", 'green')
            return True
        else:
            Colors.print_colored("❌ Adapter is NOT in monitor mode", 'red')
            return False
    except Exception as e:
        Colors.print_colored(f"[-] Error: {e}", 'red')
        return False

def test_airodump_direct(adapter):
    """Test airodump-ng directly with timeout"""
    Colors.print_colored(f"\n[+] Testing airodump-ng on {adapter}...", 'cyan')
    
    # Simple command to test
    cmd = f'sudo timeout 10 airodump-ng {adapter} --band abg'
    Colors.print_colored(f"[+] Running: {cmd}", 'yellow')
    
    try:
        # Run with timeout
        process = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for 12 seconds
        time.sleep(12)
        process.terminate()
        
        # Get output
        stdout, stderr = process.communicate(timeout=5)
        
        if stdout:
            Colors.print_colored(f"[+] Output length: {len(stdout)} characters", 'green')
            # Show first 500 characters
            Colors.print_colored("\n[+] Sample output:", 'cyan')
            print(stdout[:500])
            return True
        else:
            Colors.print_colored("[-] No output received", 'red')
            if stderr:
                Colors.print_colored(f"[-] Error: {stderr}", 'red')
            return False
            
    except subprocess.TimeoutExpired:
        Colors.print_colored("[-] Command timed out", 'red')
        return False
    except Exception as e:
        Colors.print_colored(f"[-] Error: {e}", 'red')
        return False

def test_airodump_csv(adapter):
    """Test airodump-ng with CSV output"""
    Colors.print_colored(f"\n[+] Testing airodump-ng with CSV output on {adapter}...", 'cyan')
    
    # Clear old files
    subprocess.run(['rm', '-f', '/tmp/test_scan-01.csv'], capture_output=True)
    
    cmd = f'sudo airodump-ng {adapter} --band abg --write /tmp/test_scan --output-format csv --write-interval 1'
    Colors.print_colored(f"[+] Running: {cmd}", 'yellow')
    
    try:
        process = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for 15 seconds
        for i in range(15, 0, -1):
            Colors.print_colored(f"   Scanning... {i} seconds remaining", 'yellow', True)
            time.sleep(1)
        
        process.terminate()
        time.sleep(2)
        
        # Check if CSV was created
        if os.path.exists('/tmp/test_scan-01.csv'):
            Colors.print_colored("[+] CSV file created successfully!", 'green')
            
            # Read and parse CSV
            with open('/tmp/test_scan-01.csv', 'r') as f:
                content = f.read()
                Colors.print_colored(f"[+] File size: {len(content)} bytes", 'green')
                
                # Show first 10 lines
                lines = content.split('\n')
                Colors.print_colored("\n[+] First 10 lines of CSV:", 'cyan')
                for i, line in enumerate(lines[:10]):
                    if line.strip():
                        print(f"   {i+1}: {line[:100]}...")
                
                # Check if BSSID lines exist
                bssid_lines = [line for line in lines if ',' in line and 'BSSID' not in line]
                if bssid_lines:
                    Colors.print_colored(f"\n[+] Found {len(bssid_lines)} network(s) in CSV!", 'green')
                    for line in bssid_lines[:5]:
                        parts = line.split(',')
                        if len(parts) >= 14:
                            bssid = parts[0].strip()
                            ssid = parts[13].strip() if parts[13] else '<Hidden>'
                            power = parts[8].strip()
                            Colors.print_colored(f"   • {ssid} | {bssid} | Power: {power} dBm", 'green')
                else:
                    Colors.print_colored("[-] No BSSID lines found in CSV", 'red')
                    Colors.print_colored("[!] No networks detected or format issue", 'yellow')
                
                return len(bssid_lines) > 0
        else:
            Colors.print_colored("[-] CSV file was not created!", 'red')
            Colors.print_colored("[!] airodump-ng may not be working properly", 'yellow')
            return False
            
    except Exception as e:
        Colors.print_colored(f"[-] Error: {e}", 'red')
        return False

def test_airodump_standard(adapter):
    """Test standard airodump-ng output"""
    Colors.print_colored(f"\n[+] Testing standard airodump-ng output on {adapter}...", 'cyan')
    
    try:
        # Run airodump-ng and capture output
        process = subprocess.Popen(
            ['sudo', 'airodump-ng', adapter, '--band', 'abg'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        Colors.print_colored("[+] Running for 10 seconds...", 'yellow')
        time.sleep(10)
        process.terminate()
        
        stdout, stderr = process.communicate(timeout=5)
        
        if stdout:
            Colors.print_colored(f"[+] Output length: {len(stdout)} characters", 'green')
            
            # Check for BSSID pattern
            bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
            matches = re.findall(bssid_pattern, stdout)
            
            if matches:
                Colors.print_colored(f"[+] Found {len(matches)} unique BSSIDs!", 'green')
                for bssid in set(matches):
                    Colors.print_colored(f"   • {bssid}", 'green')
                return True
            else:
                Colors.print_colored("[-] No BSSIDs found in output", 'red')
                Colors.print_colored("[!] No networks detected", 'yellow')
                return False
        else:
            Colors.print_colored("[-] No output received", 'red')
            return False
            
    except Exception as e:
        Colors.print_colored(f"[-] Error: {e}", 'red')
        return False

def test_manual_scan(adapter):
    """Test manual scan with simple approach"""
    Colors.print_colored(f"\n[+] Testing manual scan on {adapter}...", 'cyan')
    
    Colors.print_colored("[+] Trying: sudo airodump-ng --band abg " + adapter, 'blue')
    Colors.print_colored("[+] This will run for 10 seconds...", 'yellow')
    
    try:
        # Use subprocess with pipe to capture output
        process = subprocess.Popen(
            ['sudo', 'airodump-ng', '--band', 'abg', adapter],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Collect output for 10 seconds
        output_lines = []
        start_time = time.time()
        
        while time.time() - start_time < 10:
            try:
                line = process.stdout.readline()
                if line:
                    output_lines.append(line)
                    # Print network lines in real-time
                    if 'BSSID' not in line and 'Station' not in line and len(line.strip()) > 10:
                        Colors.print_colored(f"   {line.strip()[:80]}", 'cyan')
            except:
                break
        
        process.terminate()
        time.sleep(1)
        
        # Analyze output
        full_output = ''.join(output_lines)
        
        # Look for BSSIDs
        bssid_pattern = r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})'
        matches = re.findall(bssid_pattern, full_output)
        
        if matches:
            Colors.print_colored(f"\n[+] ✅ Found {len(set(matches))} network(s)!", 'green', True)
            for bssid in set(matches):
                # Try to find SSID
                ssid = "Unknown"
                lines = full_output.split('\n')
                for line in lines:
                    if bssid in line:
                        parts = line.split()
                        if len(parts) >= 13:
                            # SSID is usually at the end
                            ssid = ' '.join(parts[13:]) if len(parts) > 13 else parts[-1]
                        break
                Colors.print_colored(f"   • {ssid} - {bssid}", 'green')
            return True
        else:
            Colors.print_colored("\n[-] No BSSIDs found!", 'red')
            Colors.print_colored("[!] Make sure you're near a WiFi router", 'yellow')
            return False
            
    except Exception as e:
        Colors.print_colored(f"[-] Error: {e}", 'red')
        return False

def main():
    """Main test function"""
    print("\n" + "="*60)
    Colors.print_colored("🔍 YEVIL - Network Scanning Debug Tool", 'cyan', True)
    print("="*60)
    
    # Check root
    if os.geteuid() != 0:
        Colors.print_colored("[!] This script requires root privileges!", 'red')
        Colors.print_colored("[!] Please run with: sudo python3 test_scan.py", 'yellow')
        sys.exit(1)
    
    # Detect adapters
    Colors.print_colored("\n[+] Detecting wireless adapters...", 'cyan')
    adapters = []
    
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                adapter = line.split()[0]
                adapters.append(adapter)
    except:
        pass
    
    if not adapters:
        Colors.print_colored("[!] No wireless adapters found!", 'red')
        sys.exit(1)
    
    Colors.print_colored(f"[+] Found adapters: {', '.join(adapters)}", 'green')
    
    # Select adapter
    print()
    for i, adapter in enumerate(adapters, 1):
        Colors.print_colored(f"   {i}. {adapter}", 'white')
    
    while True:
        try:
            choice = input("\n[?] Select adapter number (1-{}): ".format(len(adapters)))
            idx = int(choice) - 1
            if 0 <= idx < len(adapters):
                selected = adapters[idx]
                break
        except:
            pass
    
    Colors.print_colored(f"\n[+] Selected: {selected}", 'green')
    
    # Check adapter status
    in_monitor = check_adapter_status(selected)
    
    if not in_monitor:
        Colors.print_colored("\n[!] Adapter is not in monitor mode!", 'red')
        set_monitor = input("\n[?] Set monitor mode now? (y/n): ")
        if set_monitor.lower() == 'y':
            try:
                subprocess.run(['sudo', 'airmon-ng', 'start', selected], check=True)
                Colors.print_colored("[+] Monitor mode enabled!", 'green')
                # Check for new monitor interface
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Mode:Monitor' in line:
                        mon_adapter = line.split()[0]
                        Colors.print_colored(f"[+] Using: {mon_adapter}", 'green')
                        selected = mon_adapter
                        break
            except:
                Colors.print_colored("[!] Failed to set monitor mode", 'red')
                sys.exit(1)
    
    # Now test scanning methods
    Colors.print_colored("\n" + "="*60, 'cyan')
    Colors.print_colored("📡 TESTING SCANNING METHODS", 'cyan', True)
    Colors.print_colored("="*60, 'cyan')
    
    # Method 1: CSV output
    success1 = test_airodump_csv(selected)
    
    # Method 2: Standard output
    success2 = test_airodump_standard(selected)
    
    # Method 3: Manual scan
    success3 = test_manual_scan(selected)
    
    # Summary
    Colors.print_colored("\n" + "="*60, 'cyan')
    Colors.print_colored("📊 TEST SUMMARY", 'cyan', True)
    Colors.print_colored("="*60, 'cyan')
    
    Colors.print_colored(f"   CSV Method     : {'✅' if success1 else '❌'}", 'green' if success1 else 'red')
    Colors.print_colored(f"   Standard Method: {'✅' if success2 else '❌'}", 'green' if success2 else 'red')
    Colors.print_colored(f"   Manual Scan    : {'✅' if success3 else '❌'}", 'green' if success3 else 'red')
    
    if success1 or success2 or success3:
        Colors.print_colored("\n[+] ✅ Scanning is working!", 'green', True)
    else:
        Colors.print_colored("\n[!] ❌ Scanning is NOT working!", 'red', True)
        Colors.print_colored("\n[!] Possible issues:", 'yellow')
        Colors.print_colored("   1. Adapter not properly in monitor mode", 'white')
        Colors.print_colored("   2. No WiFi networks in range", 'white')
        Colors.print_colored("   3. Adapter doesn't support monitor mode", 'white')
        Colors.print_colored("   4. aircrack-ng not properly installed", 'white')
        Colors.print_colored("\n[+] Try these commands manually:", 'yellow')
        Colors.print_colored(f"   sudo airmon-ng start {selected}", 'white')
        Colors.print_colored(f"   sudo airodump-ng {selected}mon --band abg", 'white')
    
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print_colored("\n\n[+] Stopped by user", 'yellow')
        sys.exit(0)
