import os
import sys
import random
import datetime
import csv

# Define output directory
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_LOG_PATH = os.path.join(LOG_DIR, "auth.log")
NGINX_LOG_PATH = os.path.join(LOG_DIR, "nginx_access.log")
WHITELIST_PATH = os.path.join(LOG_DIR, "employee_directory.csv")

# Configuration
TOTAL_NORMAL_EVENTS = 1000
START_TIME = datetime.datetime.now() - datetime.timedelta(days=1)

# Default Fallbacks if whitelist is empty or missing
DEFAULT_NORMAL_IPS = ["192.168.1.15", "192.168.1.22", "10.0.0.12", "172.16.0.5"]
DEFAULT_SYSTEM_USERS = ["john", "alice", "bob", "devops_guy"]

EXTERNAL_IPS = ["198.51.100.4", "203.0.113.88", "192.0.2.14"]
COMMON_HTTP_PATHS = [
    "/", "/index.html", "/about", "/contact", "/portfolio",
    "/static/css/main.css", "/static/js/bundle.js", "/api/v1/status",
    "/blog", "/blog/post-1", "/login"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
]

def load_employee_directory():
    """Loads whitelisted usernames and IPs to use for normal log generation."""
    users = []
    ips = []
    
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    u = row['username'].strip()
                    ip = row['approved_ip'].strip()
                    if u: users.append(u)
                    if ip: ips.append(ip)
            if users and ips:
                return users, ips
        except Exception as e:
            pass
            
    return DEFAULT_SYSTEM_USERS, DEFAULT_NORMAL_IPS

def generate_auth_log(system_users, normal_ips, ssh_attacker_ip):
    """Generates a synthetic auth.log with normal logins and a brute-force SSH attack."""
    events = []
    current_time = START_TIME
    
    # 1. Generate Normal SSH traffic using the user-defined Whitelist
    for i in range(TOTAL_NORMAL_EVENTS // 2):
        current_time += datetime.timedelta(seconds=random.randint(10, 300))
        ip = random.choice(normal_ips)
        user = random.choice(system_users)
        port = random.randint(49152, 65535)
        
        if random.random() > 0.95:
            events.append((current_time, f"sshd[{random.randint(1000, 30000)}]: Failed password for {user} from {ip} port {port} ssh2"))
        else:
            events.append((current_time, f"sshd[{random.randint(1000, 30000)}]: Accepted password for {user} from {ip} port {port} ssh2"))
            events.append((current_time + datetime.timedelta(seconds=1), f"sshd[{random.randint(1000, 30000)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"))
            close_time = current_time + datetime.timedelta(minutes=random.randint(5, 60))
            events.append((close_time, f"sshd[{random.randint(1000, 30000)}]: pam_unix(sshd:session): session closed for user {user}"))

    # 2. Inject Brute-Force SSH Attack using custom Attacker IP
    attack_start_time = START_TIME + datetime.timedelta(hours=6)
    attack_time = attack_start_time
    invalid_usernames = ["root", "admin", "ubnt", "support", "test", "ftpuser", "oracle", "postgres"]
    
    for _ in range(80):
        attack_time += datetime.timedelta(seconds=random.uniform(0.5, 2.5))
        target_user = random.choice(invalid_usernames)
        port = random.randint(49152, 65535)
        events.append((attack_time, f"sshd[{random.randint(1000, 30000)}]: Failed password for invalid user {target_user} from {ssh_attacker_ip} port {port} ssh2"))
    
    # Successful login after brute-force (simulating compromise of a whitelisted user)
    compromised_user = random.choice(system_users)
    attack_time += datetime.timedelta(seconds=5)
    port = random.randint(49152, 65535)
    events.append((attack_time, f"sshd[{random.randint(1000, 30000)}]: Accepted password for {compromised_user} from {ssh_attacker_ip} port {port} ssh2"))
    events.append((attack_time + datetime.timedelta(seconds=1), f"sshd[{random.randint(1000, 30000)}]: pam_unix(sshd:session): session opened for user {compromised_user} by (uid=0)"))
    
    events.sort(key=lambda x: x[0])
    
    with open(AUTH_LOG_PATH, "w") as f:
        for timestamp, msg in events:
            time_str = timestamp.strftime("%b %d %H:%M:%S")
            f.write(f"{time_str} ubuntu-server {msg}\n")

def generate_nginx_log(normal_ips, web_attacker_ip):
    """Generates a synthetic Nginx access log with normal requests and a directory traversal attack."""
    events = []
    current_time = START_TIME
    
    # 1. Generate Normal HTTP traffic using whitelist IPs
    for i in range(TOTAL_NORMAL_EVENTS):
        current_time += datetime.timedelta(seconds=random.randint(5, 120))
        ip = random.choice(normal_ips + EXTERNAL_IPS)
        path = random.choice(COMMON_HTTP_PATHS)
        method = "POST" if path == "/login" else "GET"
        status = 200
        
        if path == "/login":
            status = random.choice([200, 302, 401])
        elif random.random() > 0.98:
            status = 404
            path = "/not-exist"
            
        bytes_sent = random.randint(150, 4500)
        ua = random.choice(USER_AGENTS)
        events.append((current_time, ip, method, path, status, bytes_sent, ua))
        
    # 2. Inject Directory Traversal Attack using custom Attacker IP
    attack_start_time = START_TIME + datetime.timedelta(hours=14)
    attack_time = attack_start_time
    traversal_payloads = [
        "/../../../../etc/passwd",
        "/../../../../etc/shadow",
        "/etc/passwd",
        "/static/../../../../etc/passwd",
        "/static/..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/boot.ini",
        "/windows/win.ini",
        "/var/log/auth.log",
        "/../../../var/log/nginx/access.log"
    ]
    ua_attacker = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    
    for payload in traversal_payloads:
        attack_time += datetime.timedelta(seconds=random.randint(1, 10))
        status = random.choice([400, 404, 403])
        bytes_sent = random.randint(100, 300)
        events.append((attack_time, web_attacker_ip, "GET", payload, status, bytes_sent, ua_attacker))
        
    events.sort(key=lambda x: x[0])
    
    with open(NGINX_LOG_PATH, "w") as f:
        for t, ip, method, path, status, bytes_sent, ua in events:
            time_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
            f.write(f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"\n')

if __name__ == "__main__":
    ssh_attacker = "203.0.113.200"
    web_attacker = "198.51.100.250"
    
    # Load Whitelist users and IPs to generate normal events
    system_users, normal_ips = load_employee_directory()
    
    # Generate logs automatically without prompt interfaces
    generate_auth_log(system_users, normal_ips, ssh_attacker)
    generate_nginx_log(normal_ips, web_attacker)
    
    print("[+] Synthetic log generation complete (using employee directory whitelists).")
