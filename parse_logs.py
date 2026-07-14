import os
import re
import pandas as pd
from datetime import datetime

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_LOG_PATH = os.path.join(LOG_DIR, "auth.log")
NGINX_LOG_PATH = os.path.join(LOG_DIR, "nginx_access.log")

CLEANED_AUTH_CSV = os.path.join(LOG_DIR, "cleaned_auth_logs.csv")
CLEANED_NGINX_CSV = os.path.join(LOG_DIR, "cleaned_nginx_logs.csv")

def parse_nginx_line(line):
    """
    Parses a single line of Nginx access log.
    Combined Format: IP - - [Timestamp] "Method Path Protocol" Status Bytes "-" "UserAgent"
    """
    # Regex to extract key fields
    nginx_regex = r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]+" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    match = re.match(nginx_regex, line)
    if match:
        data = match.groupdict()
        # Parse timestamp: 14/Jul/2026:14:14:48 +0000
        try:
            dt = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
            data['timestamp'] = dt.isoformat()
        except ValueError:
            pass
        return data
    return None

def parse_auth_line(line):
    """
    Parses a single line of auth.log.
    Example: Jul 14 12:34:56 ubuntu-server sshd[12345]: Failed password for invalid user root from 203.0.113.200 port 54321 ssh2
    """
    # Base pattern to extract basic syslog header and message
    # Format: Month Day Time Hostname Process[PID]: Message
    syslog_regex = r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<process>sshd)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$'
    match = re.match(syslog_regex, line)
    
    if not match:
        return None
        
    gd = match.groupdict()
    msg = gd['message']
    
    # We will reconstruct a timestamp assuming current year 2026 (matching our generator)
    timestamp_str = f"2026 {gd['month']} {gd['day']} {gd['time']}"
    try:
        dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        timestamp = dt.isoformat()
    except ValueError:
        timestamp = None

    # Default values
    source_ip = None
    action = None
    target_user = None
    
    # Sub-parsing based on SSH message type
    # 1. Failed Password
    failed_match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)', msg)
    if failed_match:
        action = "Failed Login"
        target_user = failed_match.group(1)
        source_ip = failed_match.group(2)
        
    # 2. Accepted Password
    accepted_match = re.search(r'Accepted password for (\S+) from (\S+) port (\d+)', msg)
    if accepted_match:
        action = "Successful Login"
        target_user = accepted_match.group(1)
        source_ip = accepted_match.group(2)
        
    # 3. Session Opened
    opened_match = re.search(r'pam_unix\(sshd:session\): session opened for user (\S+)', msg)
    if opened_match:
        action = "Session Opened"
        target_user = opened_match.group(1)
        
    # 4. Session Closed
    closed_match = re.search(r'pam_unix\(sshd:session\): session closed for user (\S+)', msg)
    if closed_match:
        action = "Session Closed"
        target_user = closed_match.group(1)
        
    # If it doesn't match any target actions, we skip or mark as generic event
    if not action:
        return None
        
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "action": action,
        "target_user": target_user,
        "message": msg
    }

def process_nginx_logs():
    print("[*] Processing Nginx logs...")
    parsed_records = []
    
    if not os.path.exists(NGINX_LOG_PATH):
        print(f"[-] Error: Nginx log file not found at {NGINX_LOG_PATH}")
        return
        
    with open(NGINX_LOG_PATH, "r") as f:
        for line in f:
            record = parse_nginx_line(line.strip())
            if record:
                parsed_records.append(record)
                
    df = pd.DataFrame(parsed_records)
    
    # Data Cleaning and Standardization
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['status'] = df['status'].astype(int)
    # If bytes is '-', convert to 0
    df['bytes'] = df['bytes'].replace('-', 0).astype(int)
    
    # Save cleaned data
    df.to_csv(CLEANED_NGINX_CSV, index=False)
    print(f"[+] Nginx logs processed. Shape: {df.shape}. Saved to {CLEANED_NGINX_CSV}")
    return df

def process_auth_logs():
    print("[*] Processing Auth logs...")
    parsed_records = []
    
    if not os.path.exists(AUTH_LOG_PATH):
        print(f"[-] Error: Auth log file not found at {AUTH_LOG_PATH}")
        return
        
    with open(AUTH_LOG_PATH, "r") as f:
        for line in f:
            record = parse_auth_line(line.strip())
            if record:
                parsed_records.append(record)
                
    df = pd.DataFrame(parsed_records)
    
    # Data Cleaning and Standardization
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Fill missing IPs with 'local' (e.g. pam session openings don't have IP inside the message)
    df['source_ip'] = df['source_ip'].fillna('127.0.0.1')
    
    # Save cleaned data
    df.to_csv(CLEANED_AUTH_CSV, index=False)
    print(f"[+] Auth logs processed. Shape: {df.shape}. Saved to {CLEANED_AUTH_CSV}")
    return df

if __name__ == "__main__":
    nginx_df = process_nginx_logs()
    auth_df = process_auth_logs()
    
    print("\n--- Nginx Log Sample ---")
    if nginx_df is not None:
        print(nginx_df.head(3))
        
    print("\n--- Auth Log Sample ---")
    if auth_df is not None:
        print(auth_df.head(3))
