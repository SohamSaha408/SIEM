import os
import sqlite3
import pandas as pd

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(LOG_DIR, "siem_pipeline.db")

def export_to_csv(query, output_filename):
    conn = sqlite3.connect(DB_PATH)
    output_path = os.path.join(LOG_DIR, output_filename)
    try:
        df = pd.read_sql_query(query, conn)
        df.to_csv(output_path, index=False)
        print(f"[+] Exported dashboard data to {output_path} (Rows: {len(df)})")
    except Exception as e:
        print(f"[-] Error exporting {output_filename}: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    print("[*] Starting export of curated datasets for Tableau dashboard...")

    # Dataset 1: Web Traffic Timeline (For Time-Series Area/Line charts of requests & error spikes)
    query_traffic_timeline = """
    SELECT 
        strftime('%Y-%m-%d %H:00:00', timestamp) as timestamp_hour,
        COUNT(*) as total_requests,
        COUNT(DISTINCT ip) as active_ips,
        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_responses
    FROM web_logs
    GROUP BY timestamp_hour
    ORDER BY timestamp_hour ASC;
    """

    # Dataset 2: Auth Attempt Statistics (For Bar Charts identifying top SSH attackers)
    query_auth_stats = """
    SELECT 
        source_ip,
        action as auth_result,
        COUNT(*) as event_count,
        MIN(timestamp) as first_attempt,
        MAX(timestamp) as last_attempt
    FROM auth_logs
    GROUP BY source_ip, action
    ORDER BY event_count DESC;
    """

    # Dataset 3: Isolated Web Attacks (For Security Event tables detailing directory traversal activity)
    query_web_attacks = """
    SELECT 
        ip as attacker_ip,
        timestamp,
        method,
        url as requested_path,
        status as http_status
    FROM web_logs
    WHERE url LIKE '%..%' 
       OR url LIKE '%/etc/%'
       OR url LIKE '%/win.ini%'
       OR url LIKE '%boot.ini%'
    ORDER BY timestamp ASC;
    """

    export_to_csv(query_traffic_timeline, "tableau_traffic_timeline.csv")
    export_to_csv(query_auth_stats, "tableau_ssh_attacks.csv")
    export_to_csv(query_web_attacks, "tableau_web_attacks.csv")
    print("[*] Export complete. Ready to load into Tableau.")
