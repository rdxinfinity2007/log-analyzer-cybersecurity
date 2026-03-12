"""
Main Execution Module

This is the main entry point for the Automated Log Analysis System.
It orchestrates all components in the correct order:

1. Parse logs from logs.txt
2. Store logs in SQLite database
3. Detect suspicious activity
4. Run AI anomaly detection
5. Display results

Usage:
    python main.py
"""

import os
import sys
from datetime import datetime
import pandas as pd

# Import all modules
from parser import parse_logs, get_log_summary
from database import LogDatabase, init_database
from detector import ThreatDetector
from ai_model import AnomalyDetector


def print_header(title):
    """
    Print a formatted header.
    
    Args:
        title (str): Header title
    """
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def main():
    """
    Main execution function that runs the complete log analysis pipeline.
    """
    print_header("AUTOMATED LOG ANALYSIS SYSTEM FOR CYBERSECURITY")
    print(f"Analysis Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Check if logs.txt exists
    if not os.path.exists('logs.txt'):
        print("[ERROR] logs.txt not found!")
        print("Please ensure logs.txt exists in the current directory.")
        sys.exit(1)
    
    # ========================================
    # STEP 1: Parse Logs
    # ========================================
    print_header("STEP 1: LOG PARSING")
    print("Reading and parsing logs from logs.txt...\n")
    
    df = parse_logs('logs.txt')
    
    if df.empty:
        print("[ERROR] No logs could be parsed!")
        sys.exit(1)
    
    # Display log summary
    summary = get_log_summary(df)
    print("\n[LOG SUMMARY]")
    print(f"  Total Logs: {summary['total_logs']}")
    print(f"  Unique Users: {summary['unique_users']}")
    print(f"  Unique IPs: {summary['unique_ips']}")
    print(f"  Successful Logins: {summary['success_count']}")
    print(f"  Failed Logins: {summary['failed_count']}")
    print(f"  Time Range: {summary['time_range']}")
    
    # ========================================
    # STEP 2: Store in Database
    # ========================================
    print_header("STEP 2: DATABASE STORAGE")
    print("Initializing SQLite database...\n")
    
    db = init_database('logs.db')
    
    # Clear existing logs (optional - for fresh analysis)
    print("Clearing existing logs from database...")
    db.clear_logs()
    
    # Insert parsed logs
    print("Inserting parsed logs into database...\n")
    db.insert_logs_bulk(df)
    
    print(f"[SUCCESS] {db.get_log_count()} logs stored in database")
    
    # ========================================
    # STEP 3: Threat Detection
    # ========================================
    print_header("STEP 3: THREAT DETECTION ENGINE")
    print("Analyzing logs for suspicious patterns...\n")
    
    detector = ThreatDetector(
        df,
        failed_login_threshold=3,
        time_window_minutes=10
    )
    
    threat_results = detector.detect_all_threats()
    
    # Display threat detection results
    print("\n[THREAT DETECTION RESULTS]")
    print(f"  Suspicious IPs Detected: {len(threat_results['suspicious_ips'])}")
    print(f"  Multiple Failed Logins: {len(threat_results['multiple_failed_logins'])}")
    print(f"  Brute Force Attacks: {len(threat_results['brute_force_attacks'])}")
    print(f"  Abnormal Frequency: {len(threat_results['abnormal_frequency'])}")
    print(f"  Suspicious Usernames: {len(threat_results['suspicious_usernames'])}")
    
    if threat_results['suspicious_ips']:
        print("\n[SUSPICIOUS IP ADDRESSES]")
        for ip in threat_results['suspicious_ips'][:10]:  # Show first 10
            print(f"  - {ip}")
    
    # ========================================
    # STEP 4: AI Anomaly Detection
    # ========================================
    print_header("STEP 4: AI ANOMALY DETECTION")
    print("Running Isolation Forest anomaly detection...\n")
    
    ai_detector = AnomalyDetector(
        df,
        contamination=0.15,
        random_state=42
    )
    
    anomaly_results = ai_detector.detect_anomalies()
    
    # Display AI results
    print("\n[AI ANOMALY DETECTION RESULTS]")
    print(f"  Total IPs Analyzed: {len(anomaly_results['anomaly_results'])}")
    print(f"  Anomalies Detected: {len(anomaly_results['anomalous_ips'])}")
    
    if anomaly_results['anomalous_ips']:
        print("\n[TOP 5 ANOMALOUS IPs]")
        top_anomalies = ai_detector.get_top_anomalies(5)
        for idx, row in top_anomalies.iterrows():
            print(f"\n  IP: {row['ip']}")
            print(f"    Anomaly Score: {row['anomaly_score']:.4f}")
            print(f"    Login Frequency: {row['login_frequency']}")
            print(f"    Failed Logins: {row['failed_login_count']}")
            print(f"    Failed Ratio: {row['failed_ratio']:.2%}")
    
    # ========================================
    # STEP 5: Generate Reports
    # ========================================
    print_header("STEP 5: GENERATING REPORTS")
    
    # Save threat report
    threat_report = detector.generate_threat_report()
    with open('threat_report.txt', 'w') as f:
        f.write(threat_report)
    print("[SUCCESS] Threat report saved to: threat_report.txt")
    
    # Save AI anomaly report
    ai_report = ai_detector.generate_anomaly_report()
    with open('anomaly_report.txt', 'w') as f:
        f.write(ai_report)
    print("[SUCCESS] Anomaly report saved to: anomaly_report.txt")
    
    # Save results to CSV for dashboard
    anomaly_results['anomaly_results'].to_csv('anomaly_results.csv', index=False)
    print("[SUCCESS] Anomaly results saved to: anomaly_results.csv")
    
    # ========================================
    # Summary
    # ========================================
    print_header("ANALYSIS COMPLETE")
    
    print("[SUMMARY]")
    print(f"  Total Logs Analyzed: {len(df)}")
    print(f"  Suspicious IPs (Rule-Based): {len(threat_results['suspicious_ips'])}")
    print(f"  Anomalous IPs (AI-Based): {len(anomaly_results['anomalous_ips'])}")
    print(f"  Critical Threats: {len([t for t in threat_results['threat_details'] if t['severity'] == 'CRITICAL'])}")
    print(f"  High Severity Threats: {len([t for t in threat_results['threat_details'] if t['severity'] == 'HIGH'])}")
    
    print("\n[NEXT STEPS]")
    print("  1. Review threat_report.txt for detailed threat analysis")
    print("  2. Review anomaly_report.txt for AI-based anomaly detection")
    print("  3. Launch dashboard: streamlit run dashboard.py")
    print("  4. Start real-time monitoring: python realtime_monitor.py")
    
    print("\n" + "="*70)
    print(f"Analysis Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")
    
    # Close database connection
    db.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Analysis stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)