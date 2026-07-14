import os
import re
import sys
import platform

def detect_default_auth_log():
    """Detects standard auth log paths based on the operating system."""
    system_os = platform.system().lower()
    
    if "linux" in system_os:
        # Check Ubuntu/Debian vs CentOS/RedHat paths
        if os.path.exists("/var/log/auth.log"):
            return "/var/log/auth.log"
        elif os.path.exists("/var/log/secure"):
            return "/var/log/secure"
    elif "darwin" in system_os:  # macOS
        if os.path.exists("/var/log/system.log"):
            return "/var/log/system.log"
            
    return None

def analyze_system_logs(log_path, filter_ip=None):
    """Parses a real system log file to audit login attempts."""
    print(f"\n[*] Scanning log file: {log_path}")
    if filter_ip:
        print(f"[*] Filtering results for IP address: {filter_ip}")
        
    failed_attempts = {}
    successful_attempts = []
    
    # Regex patterns for SSH logins
    failed_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh2')
    accepted_pattern = re.compile(r'Accepted password for (\S+) from (\S+) port \d+ ssh2')

    try:
        with open(log_path, "r", errors='ignore') as f:
            for line in f:
                # 1. Check for Failed Logins
                failed_match = failed_pattern.search(line)
                if failed_match:
                    user, ip = failed_match.groups()
                    if filter_ip and ip != filter_ip:
                        continue
                    
                    if ip not in failed_attempts:
                        failed_attempts[ip] = {"count": 0, "users": set()}
                    failed_attempts[ip]["count"] += 1
                    failed_attempts[ip]["users"].add(user)
                    
                # 2. Check for Successful Logins
                accepted_match = accepted_pattern.search(line)
                if accepted_match:
                    user, ip = accepted_match.groups()
                    if filter_ip and ip != filter_ip:
                        continue
                    successful_attempts.append({"ip": ip, "user": user, "line": line.strip()})
                    
    except PermissionError:
        print(f"\n[-] Permission Denied: Cannot read {log_path}.")
        print("[!] Tip: System logs are protected. Please run this command with administrative/sudo privileges:")
        if platform.system().lower() == "windows":
            print("    Run your terminal/PowerShell as Administrator.")
        else:
            print(f"    sudo {sys.executable} run.py --live")
        return
    except FileNotFoundError:
        print(f"\n[-] Error: Log file not found at {log_path}")
        return

    # Print Summary Results
    print("\n==================================================")
    print("🛡️  LIVE SYSTEM AUTH AUDIT RESULTS")
    print("==================================================")
    
    # Print Failures (Potential Brute Forces)
    print("\n[!] Failed Login Attempts by IP:")
    if not failed_attempts:
        print("  No failed login attempts detected.")
    else:
        for ip, info in failed_attempts.items():
            users_str = ", ".join(list(info["users"]))
            alert = " 🚨 (POTENTIAL BRUTE FORCE)" if info["count"] > 5 else ""
            print(f"  - IP: {ip:15} | Failed Attempts: {info['count']:3} | Targeted Users: [{users_str}]{alert}")
            
    # Print Successes
    print("\n[+] Successful Logins:")
    if not successful_attempts:
        print("  No successful logins detected.")
    else:
        for attempt in successful_attempts:
            print(f"  - IP: {attempt['ip']:15} | User: {attempt['user']}")

if __name__ == "__main__":
    print("==================================================")
    print("🔎 Live System Security Audit Configuration")
    print("==================================================")
    
    # 1. Ask for Target Log File
    default_path = detect_default_auth_log()
    path_prompt = f"Enter path to auth log file [{default_path}]: " if default_path else "Enter path to auth log file: "
    user_path = input(path_prompt).strip()
    
    log_path = user_path if user_path else default_path
    
    if not log_path:
        print("[-] Error: No log path provided, and could not auto-detect standard logs on this OS.")
        print("[*] On Windows, copy an OpenSSH auth log file to a folder and provide its path.")
        sys.exit(1)
        
    # 2. Ask for IP Filter (Optional)
    target_ip = input("Enter an IP to filter for (or press Enter to search all): ").strip()
    filter_ip = target_ip if target_ip else None
    
    analyze_system_logs(log_path, filter_ip)
