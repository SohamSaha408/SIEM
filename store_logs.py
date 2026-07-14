import os
import sqlite3
import pandas as pd

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(LOG_DIR, "siem_pipeline.db")
CLEANED_AUTH_CSV = os.path.join(LOG_DIR, "cleaned_auth_logs.csv")
CLEANED_NGINX_CSV = os.path.join(LOG_DIR, "cleaned_nginx_logs.csv")

def create_database_schema(conn):
    """Creates the database schema with proper indexes for fast security analysis."""
    cursor = conn.cursor()
    
    print("[*] Creating database schema and tables...")
    
    # 1. Create Nginx Web Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS web_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        status INTEGER NOT NULL,
        bytes INTEGER NOT NULL
    );
    """)
    
    # 2. Create Auth Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        target_user TEXT,
        message TEXT
    );
    """)
    
    # 3. Create Security Indexes for fast threat hunting queries
    # Indexes on IP and timestamp are critical in SIEM environments for timeline correlation
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_web_ip ON web_logs(ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_web_time ON web_logs(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_web_status ON web_logs(status);")
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_logs(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_time ON auth_logs(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_action ON auth_logs(action);")
    
    conn.commit()
    print("[+] Tables and security indexes created successfully.")

def populate_database(conn):
    """Loads cleaned CSV files into Pandas and inserts them into the SQLite database."""
    print("[*] Ingesting CSV files into database...")
    
    # Load Web Logs
    if os.path.exists(CLEANED_NGINX_CSV):
        web_df = pd.read_csv(CLEANED_NGINX_CSV)
        # Ensure timestamp is formatted as string ISO format for SQLite compatibility
        web_df['timestamp'] = pd.to_datetime(web_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        # Insert using Pandas to_sql mapping (index=False ignores Pandas default row index and lets SQLite handle PK Auto-Increment)
        web_df.to_sql('web_logs', conn, if_exists='append', index=False)
        print(f"[+] Loaded {len(web_df)} web logs into 'web_logs' table.")
    else:
        print(f"[-] Warning: Cleaned Nginx CSV not found at {CLEANED_NGINX_CSV}")
        
    # Load Auth Logs
    if os.path.exists(CLEANED_AUTH_CSV):
        auth_df = pd.read_csv(CLEANED_AUTH_CSV)
        auth_df['timestamp'] = pd.to_datetime(auth_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        # Fill missing values for SQL safety
        auth_df['target_user'] = auth_df['target_user'].fillna('Unknown')
        auth_df.to_sql('auth_logs', conn, if_exists='append', index=False)
        print(f"[+] Loaded {len(auth_df)} auth logs into 'auth_logs' table.")
    else:
        print(f"[-] Warning: Cleaned Auth CSV not found at {CLEANED_AUTH_CSV}")

def verify_data(conn):
    """Quick validation query to verify tables are populated."""
    cursor = conn.cursor()
    print("\n--- Database Verification ---")
    
    cursor.execute("SELECT COUNT(*) FROM web_logs;")
    web_count = cursor.fetchone()[0]
    print(f"Total web_logs records: {web_count}")
    
    cursor.execute("SELECT COUNT(*) FROM auth_logs;")
    auth_count = cursor.fetchone()[0]
    print(f"Total auth_logs records: {auth_count}")

if __name__ == "__main__":
    # Connect to local SQLite database (will be created if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    
    try:
        create_database_schema(conn)
        populate_database(conn)
        verify_data(conn)
    finally:
        conn.close()
        print("[*] Database connection closed.")
