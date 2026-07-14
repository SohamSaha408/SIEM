import os
import sys
import argparse
import subprocess
import csv

BANNER = """
 ██████╗██╗███████╗███╗   ███╗
██╔════╝██║██╔════╝████╗  ████║
╚█████╗ ██║█████╗  ██╔████╔██║
 ╚═══██╗██║██╔═══╝  ██║╚██╔╝██║
██████╔╝██║███████╗██║ ╚═╝ ██║
╚═════╝ ╚═╝╚══════╝╚═╝     ╚═╝
   Custom SIEM Log Analysis & Threat Hunting Pipeline
"""

def clear_screen():
    """Clears the terminal screen for a clean menu experience."""
    os.system("cls" if os.name == "nt" else "clear")

def run_step(script_name, description, extra_args=None):
    """Helper function to run a python script and output its status."""
    print(f"\n==================================================")
    print(f"[*] Starting: {description} ({script_name})")
    print(f"==================================================")
    
    cmd = [sys.executable, script_name]
    if extra_args:
        cmd.extend(extra_args)
        
    try:
        # Run script using current Python interpreter
        subprocess.run(cmd, check=True)
        print(f"[+] Finished: {description} successfully.")
        input("\n[Press Enter to continue...]")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Error: {description} failed.")
        input("\n[Press Enter to continue...]")
        return False

def show_whitelist():
    """Displays the current whitelisted employees."""
    clear_screen()
    print("==================================================")
    print("👥 CURRENT WHITELISTED EMPLOYEES")
    print("==================================================")
    whitelist_path = "employee_directory.csv"
    if not os.path.exists(whitelist_path):
        print("[-] Whitelist file (employee_directory.csv) not found.")
    else:
        try:
            with open(whitelist_path, "r", encoding="utf-8") as f:
                print(f.read())
        except Exception as e:
            print(f"[-] Error reading whitelist: {e}")
    input("\n[Press Enter to return to menu...]")

def add_employee_to_whitelist():
    """Prompts the user to add a new employee and approved IP to the whitelist CSV."""
    clear_screen()
    print("==================================================")
    print("➕ ADD EMPLOYEE TO SECURITY WHITELIST")
    print("==================================================")
    
    username = input("Enter system username (e.g. bob): ").strip()
    approved_ip = input("Enter approved IP address (e.g. 192.168.1.15): ").strip()
    employee_name = input("Enter employee full name: ").strip()
    department = input("Enter department name: ").strip()
    
    if not (username and approved_ip and employee_name and department):
        print("\n[-] Error: All fields are required. Aborting.")
        input("\n[Press Enter to return to menu...]")
        return
        
    whitelist_path = "employee_directory.csv"
    file_exists = os.path.exists(whitelist_path)
    
    try:
        with open(whitelist_path, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["username", "approved_ip", "employee_name", "department"])
            writer.writerow([username, approved_ip, employee_name, department])
        print(f"\n[+] Successfully added {employee_name} ({username} - {approved_ip}) to whitelist.")
    except Exception as e:
        print(f"\n[-] Error saving to whitelist: {e}")
        
    input("\n[Press Enter to return to menu...]")

def interactive_menu():
    """Renders the Social Engineering Toolkit (SET) style interactive menu."""
    while True:
        clear_screen()
        print(BANNER)
        print("==================================================")
        print("SIEM PIPELINE MAIN INTERACTIVE MENU")
        print("==================================================")
        print("1) Generate Synthetic Logs (Phase 1)")
        print("2) Run Parser Unit Tests (Test Phase)")
        print("3) Parse and Clean Raw Logs (Phase 2)")
        print("4) Ingest Logs into SQL Database (Phase 3)")
        print("5) Execute Threat Hunting Queries (Phase 4)")
        print("6) Export CSV Datasets for Tableau (Phase 5)")
        print("7) Run Interactive Live System Audit (Real Logs)")
        print("8) Run Complete Pipeline End-to-End")
        print("9) View Employee Whitelist (employee_directory.csv)")
        print("10) Add Employee to Whitelist")
        print("0) Exit")
        print("==================================================")
        
        choice = input("siem> ").strip()
        
        if choice == "1":
            run_step("generate_logs.py", "Generating synthetic logs")
        elif choice == "2":
            run_step("test_parser.py", "Running parser unit tests")
        elif choice == "3":
            run_step("parse_logs.py", "Parsing raw log files")
        elif choice == "4":
            run_step("store_logs.py", "Ingesting data into SQLite database")
        elif choice == "5":
            run_step("hunt_threats.py", "Executing threat hunting queries")
        elif choice == "6":
            run_step("export_for_tableau.py", "Exporting datasets for Tableau")
        elif choice == "7":
            print("\n")
            subprocess.run([sys.executable, "live_audit.py"])
            input("\n[Press Enter to return to menu...]")
        elif choice == "8":
            clear_screen()
            print("[*] Running complete pipeline end-to-end...")
            if (run_step("generate_logs.py", "Generating synthetic logs") and
                run_step("test_parser.py", "Running parser unit tests") and
                run_step("parse_logs.py", "Parsing raw log files") and
                run_step("store_logs.py", "Ingesting data into SQLite database") and
                run_step("hunt_threats.py", "Executing threat hunting queries") and
                run_step("export_for_tableau.py", "Exporting datasets for Tableau")):
                print("\n[+] End-to-end pipeline completed successfully!")
            else:
                print("\n[-] Pipeline aborted due to failure.")
            input("\n[Press Enter to return to menu...]")
        elif choice == "9":
            show_whitelist()
        elif choice == "10":
            add_employee_to_whitelist()
        elif choice == "0" or choice.lower() == "exit" or choice.lower() == "quit":
            print("\n[*] Exiting SIEM Pipeline Tool. Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid choice. Please enter a number between 0 and 10.")
            input("\n[Press Enter to continue...]")

def main():
    parser = argparse.ArgumentParser(
        description="SIEM Log Analysis & Threat Hunting Pipeline CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                # Launch Interactive SET-style Menu
  python run.py --all          # Run the complete pipeline in sequence
  python run.py --hunt         # Run threat hunting queries directly
        """
    )
    
    parser.add_argument("-g", "--generate", action="store_true", help="Phase 1: Generate synthetic raw logs")
    parser.add_argument("-t", "--test", action="store_true", help="Test Phase: Run parsing unit tests")
    parser.add_argument("-p", "--parse", action="store_true", help="Phase 2: Extract & clean logs using Pandas")
    parser.add_argument("-s", "--store", action="store_true", help="Phase 3: Load cleaned logs into SQLite DB")
    parser.add_argument("-d", "--hunt", action="store_true", help="Phase 4: Run threat hunting detection queries")
    parser.add_argument("-e", "--export", action="store_true", help="Phase 5: Export CSV datasets for Tableau")
    parser.add_argument("-l", "--live", action="store_true", help="Interactive Phase: Run live security log audit")
    parser.add_argument("-a", "--all", action="store_true", help="Run the entire pipeline end-to-end")

    # If args are passed, run in non-interactive CLI mode
    if len(sys.argv) > 1:
        args = parser.parse_args()
        
        if args.live:
            subprocess.run([sys.executable, "live_audit.py"])
            sys.exit(0)
            
        steps = []
        if args.all or args.generate:
            steps.append((["generate_logs.py"], "Generating synthetic raw logs"))
        if args.all or args.test:
            steps.append((["test_parser.py"], "Running log parsing unit tests"))
        if args.all or args.parse:
            steps.append((["parse_logs.py"], "Parsing and cleaning logs using Pandas"))
        if args.all or args.store:
            steps.append((["store_logs.py"], "Ingesting cleaned logs into SQLite DB"))
        if args.all or args.hunt:
            steps.append((["hunt_threats.py"], "Executing SQL threat hunting queries"))
        if args.all or args.export:
            steps.append((["export_for_tableau.py"], "Exporting CSV datasets for Tableau"))
            
        for cmd_list, desc in steps:
            try:
                subprocess.run([sys.executable] + cmd_list, check=True)
            except subprocess.CalledProcessError:
                print(f"[-] Error: {desc} failed. Aborting pipeline.")
                sys.exit(1)
        print("\n[+] Selected pipeline stages completed successfully!")
    else:
        # Launch the beautiful interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
