import os
import sqlite3
import pandas as pd

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(LOG_DIR, "siem_pipeline.db")

def run_query(title, query):
    conn = sqlite3.connect(DB_PATH)
    print(f"\n========================================\n[HUNTING] {title}\n========================================")
    try:
        df = pd.read_sql_query(query, conn)
        if df.empty:
            print("No threats matching this query were found.")
        else:
            print(df.to_string(index=False))
    except Exception as e:
        print(f"Error running query: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Query 1: Detect SSH Brute Force Attacks (Volume-based thresholding)
    query_ssh_brute = """
    SELECT 
        source_ip,
        COUNT(*) as failed_attempts,
        MIN(timestamp) as attack_start,
        MAX(timestamp) as attack_end,
        GROUP_CONCAT(DISTINCT target_user) as targeted_users
    FROM auth_logs
    WHERE action = 'Failed Login'
    GROUP BY source_ip
    HAVING failed_attempts > 5
    ORDER BY failed_attempts DESC;
    """
    
    # Query 2: Correlate Brute Force with Successful Compromise
    query_ssh_compromise = """
    WITH failures AS (
        SELECT 
            source_ip, 
            COUNT(*) as failed_count, 
            MIN(timestamp) as first_fail, 
            MAX(timestamp) as last_fail
        FROM auth_logs
        WHERE action = 'Failed Login'
        GROUP BY source_ip
        HAVING failed_count > 5
    ),
    successes AS (
        SELECT 
            source_ip, 
            timestamp as success_time, 
            target_user
        FROM auth_logs
        WHERE action = 'Successful Login'
    )
    SELECT 
        f.source_ip,
        f.failed_count,
        f.first_fail,
        f.last_fail,
        s.success_time,
        s.target_user
    FROM failures f
    JOIN successes s ON f.source_ip = s.source_ip
    WHERE s.success_time >= f.first_fail
    ORDER BY f.failed_count DESC;
    """
    
    # Query 3: Detect Directory Traversal Attacks (Pattern matching)
    query_directory_traversal = """
    SELECT 
        ip,
        timestamp,
        method,
        url,
        status,
        bytes
    FROM web_logs
    WHERE url LIKE '%..%' 
       OR url LIKE '%/etc/%'
       OR url LIKE '%/win.ini%'
       OR url LIKE '%boot.ini%'
    ORDER BY timestamp ASC;
    """
    
    # Query 4: Traffic Spike Detection (Hourly grouping)
    query_traffic_spikes = """
    SELECT 
        strftime('%Y-%m-%d %H:00:00', timestamp) as hour_bucket,
        COUNT(*) as request_count,
        COUNT(DISTINCT ip) as unique_ips,
        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as error_count
    FROM web_logs
    GROUP BY hour_bucket
    ORDER BY request_count DESC
    LIMIT 5;
    """
    
    run_query("Detect SSH Brute Force Attacks", query_ssh_brute)
    run_query("Correlate Brute Force with Successful Compromise", query_ssh_compromise)
    run_query("Detect Directory Traversal Attacks", query_directory_traversal)
    run_query("Hourly Web Traffic Spike Detection", query_traffic_spikes)
