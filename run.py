import argparse
import sys
import subprocess

def run_step(script_name, description):
    """Helper function to run a python script and output its status."""
    print(f"\n==================================================")
    print(f"[*] Starting: {description} ({script_name})")
    print(f"==================================================")
    
    try:
        # Run script using current Python interpreter to ensure virtual environments are respected
        result = subprocess.run([sys.executable, script_name], check=True)
        print(f"[+] Finished: {description} successfully.")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] Error: {description} failed.")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="SIEM Log Analysis & Threat Hunting Pipeline CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --all          # Run the complete pipeline in sequence (Default)
  python run.py -g -p          # Generate logs and parse them only
  python run.py --hunt         # Run threat hunting queries against the database
        """
    )
    
    parser.add_argument("-g", "--generate", action="store_true", help="Phase 1: Generate synthetic raw logs")
    parser.add_argument("-t", "--test", action="store_true", help="Test Phase: Run parsing unit tests")
    parser.add_argument("-p", "--parse", action="store_true", help="Phase 2: Extract & clean logs using Pandas")
    parser.add_argument("-s", "--store", action="store_true", help="Phase 3: Load cleaned logs into SQLite DB")
    parser.add_argument("-d", "--hunt", action="store_true", help="Phase 4: Run threat hunting detection queries")
    parser.add_argument("-e", "--export", action="store_true", help="Phase 5: Export CSV datasets for Tableau")
    parser.add_argument("-a", "--all", action="store_true", help="Run the entire pipeline end-to-end")

    args = parser.parse_args()

    # If no flags are provided, run all phases by default
    run_all = args.all or not (args.generate or args.test or args.parse or args.store or args.hunt or args.export)

    steps = []
    
    if run_all or args.generate:
        steps.append(("generate_logs.py", "Generating synthetic raw logs"))
        
    if run_all or args.test:
        steps.append(("test_parser.py", "Running log parsing unit tests"))
        
    if run_all or args.parse:
        steps.append(("parse_logs.py", "Parsing and cleaning logs using Pandas"))
        
    if run_all or args.store:
        steps.append(("store_logs.py", "Ingesting cleaned logs into SQLite DB"))
        
    if run_all or args.hunt:
        steps.append(("hunt_threats.py", "Executing SQL threat hunting queries"))
        
    if run_all or args.export:
        steps.append(("export_for_tableau.py", "Exporting CSV datasets for Tableau"))

    # Execute selected steps in sequence
    for script, desc in steps:
        success = run_step(script, desc)
        if not success:
            print("\n[-] Pipeline aborted due to failure in step.")
            sys.exit(1)
            
    print("\n[+] All pipeline stages completed successfully!")

if __name__ == "__main__":
    main()
