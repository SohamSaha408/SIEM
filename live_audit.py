import os
import re
import sys
import platform
import csv

# Path to the whitelist CSV in the same directory
DIR_PATH = os.path.dirname(os.path.abspath(__file__))
WHITELIST_PATH = os.path.join(DIR_PATH, "employee_directory.csv")

def load_employee_whitelist():
    """Loads whitelisted usernames and their approved IPs from CSV."""
    whitelist = {}
    if not os.path.exists(WHITELIST_PATH):
        print(f"[!] Warning: Whitelist file not found at {WHITELIST_PATH}")
        print("    Running audit without false-positive filtering.")
        return whitelist
        
    try:
        with open(WHITELIST_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                user = row['username'].strip()
                whitelist[user] = {
                    "ip": row['approved_ip'].strip(),
                    "name": row['employee_name'].strip(),
                    "dept": row['department'].strip()
                }
        print(f"[+] Loaded {len(whitelist)} employees into false-positive whitelist filter.")
    except Exception as e:
        print(f"[-] Error loading whitelist: {e}")
    return whitelist

def detect_default_auth_log():
    """Detects standard auth log paths based on the operating system."""
    system_os = platform.system().lower()
    if "linux" in system_os:
        if os.path.exists("/var/log/auth.log"):
            return "/var/log/auth.log"
        elif os.path.exists("/var/log/secure"):
            return "/var/log/secure"
    elif "darwin" in system_os:
        if os.path.exists("/var/log/system.log"):
            return "/var/log/system.log"
    return None

def analyze_system_logs(log_path, whitelist, filter_ip=None):
    """Parses a system log file and compares events against the whitelist."""
    print(f"\n[*] Scanning log file: {log_path}")
    if filter_ip:
        print(f"[*] Filtering results for IP: {filter_ip}")
        
    failed_attempts = {}
    successful_attempts = []
    
    failed_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh2')
    accepted_pattern = re.compile(r'Accepted password for (\S+) from (\S+) port \d+ ssh2')

    try:
        with open(log_path, "r", errors='ignore') as f:
            for line in f:
                # 1. Parse Failed Logins
                failed_match = failed_pattern.search(line)
                if failed_match:
                    user, ip = failed_match.groups()
                    if filter_ip and ip != filter_ip:
                        continue
                    
                    if ip not in failed_attempts:
                        failed_attempts[ip] = {"count": 0, "users": set()}
                    failed_attempts[ip]["count"] += 1
                    failed_attempts[ip]["users"].add(user)
                    
                # 2. Parse Successful Logins
                accepted_match = accepted_pattern.search(line)
                if accepted_match:
                    user, ip = accepted_match.groups()
                    if filter_ip and ip != filter_ip:
                        continue
                    successful_attempts.append({"ip": ip, "user": user, "line": line.strip()})
                    
    except PermissionError:
        print(f"\n[-] Permission Denied: Cannot read {log_path}.")
        print("[!] Tip: System logs require admin privileges. Run command with sudo:")
        print(f"    sudo {sys.executable} run.py --live")
        return
    except FileNotFoundError:
        print(f"\n[-] Error: Log file not found at {log_path}")
        return

    # Print Summary Results
    print("\n==================================================")
    print("🛡️  LIVE SYSTEM AUTH AUDIT RESULTS")
    print("==================================================")
    
    # 1. Print Failed Logins & Whitelist Classification
    print("\n[!] Failed Login Attempts by IP:")
    if not failed_attempts:
        print("  No failed login attempts detected.")
    else:
        for ip, info in failed_attempts.items():
            users_str = ", ".join(list(info["users"]))
            
            # Whitelist/False Positive logic
            classification = "🚨 (HIGH RISK - UNKNOWN SOURCE)"
            is_whitelisted = False
            
            # Check if any targeted username is an employee and if they are on their approved IP
            for u in info["users"]:
                if u in whitelist:
                    if whitelist[u]["ip"] == ip:
                        classification = "⚠️ (LOW RISK - EMPLOYEE FAT-FINGER TYPO)"
                        is_whitelisted = True
                        break
                    else:
                        classification = "🔥 (CRITICAL - ANOMALOUS IP TARGETING EMPLOYEE ACCOUNT)"
                        break
            
            # Brute force warning overlay
            bf_alert = " [BRUTE FORCE DETECTED]" if info["count"] > 5 and not is_whitelisted else ""
            print(f"  - IP: {ip:15} | Failed: {info['count']:3} | Users: [{users_str:20}] | Status: {classification}{bf_alert}")
            
    # 2. Print Successful Logins & Whitelist Classification
    print("\n[+] Successful Logins:")
    if not successful_attempts:
        print("  No successful logins detected.")
    else:
        for attempt in successful_attempts:
            ip = attempt['ip']
            user = attempt['user']
            
            # Check successful logins against whitelist
            if user in whitelist:
                if whitelist[user]["ip"] == ip:
                    classification = f"✅ Approved (Employee: {whitelist[user]['name']} - {whitelist[user]['dept']})"
                else:
                    classification = f"🚨 ALERT! (IP MISMATCH - Account accessed from unapproved IP: {ip})"
            else:
                classification = "❓ Alert: Successful login by unknown/un-whitelisted username"
                
            print(f"  - User: {user:12} | IP: {ip:15} | Status: {classification}")

if __name__ == "__main__":
    print("==================================================")
    print("🔎 Live System Security Audit Configuration")
    print("==================================================")
    
    # Load Whitelist
    whitelist = load_employee_whitelist()
    
    # 1. Ask for Target Log File
    default_path = detect_default_auth_log()
    path_prompt = f"Enter path to auth log file [{default_path}]: " if default_path else "Enter path to auth log file: "
    user_path = input(path_prompt).strip()
    
    log_path = user_path if user_path else default_path
    
    if not log_path:
        print("[-] Error: No log path provided, and could not auto-detect standard logs on this OS.")
        sys.exit(1)
        
    # 2. Ask for IP Filter (Optional)
    target_ip = input("Enter an IP to filter for (or press Enter to search all): ").strip()
    filter_ip = target_ip if target_ip else None
    
    analyze_system_logs(log_path, whitelist, filter_ip)
