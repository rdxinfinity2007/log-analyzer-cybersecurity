"""
Real-Time Log Monitoring Module

This module continuously monitors the logs.txt file for new entries.
When new logs appear, it automatically analyzes them for suspicious activity.

Usage:
    from realtime_monitor import LogMonitor
    monitor = LogMonitor('logs.txt')
    monitor.start_monitoring()
"""

import time
import os
from datetime import datetime
import pandas as pd
from parser import parse_log_line
from detector import ThreatDetector
from ai_model import AnomalyDetector
from database import LogDatabase


class LogMonitor:
    """
    Class to monitor log files in real-time and detect threats.
    """
    
    def __init__(self, log_file_path, db_path='logs.db', check_interval=2):
        """
        Initialize the log monitor.
        
        Args:
            log_file_path (str): Path to the log file to monitor
            db_path (str): Path to the database
            check_interval (int): Seconds between checks for new logs
        """
        self.log_file_path = log_file_path
        self.db_path = db_path
        self.check_interval = check_interval
        self.last_position = 0
        self.monitoring = False
        self.alert_threshold = -0.5  # Anomaly score threshold for alerts
        
        # Initialize database
        self.db = LogDatabase(db_path)
        self.db.connect()
        
        # Track file size
        if os.path.exists(log_file_path):
            self.last_position = os.path.getsize(log_file_path)
    
    def read_new_logs(self):
        """
        Read new log entries since last check.
        
        Returns:
            list: List of new log entries (parsed)
        """
        new_logs = []
        
        try:
            if not os.path.exists(self.log_file_path):
                return new_logs
            
            current_size = os.path.getsize(self.log_file_path)
            
            # Check if file has grown
            if current_size > self.last_position:
                with open(self.log_file_path, 'r') as file:
                    # Seek to last read position
                    file.seek(self.last_position)
                    
                    # Read new lines
                    for line in file:
                        line = line.strip()
                        if line:
                            parsed = parse_log_line(line)
                            if parsed:
                                new_logs.append(parsed)
                
                # Update last position
                self.last_position = current_size
        
        except Exception as e:
            print(f"Error reading new logs: {e}")
        
        return new_logs
    
    def analyze_new_logs(self, new_logs):
        """
        Analyze new logs for threats and anomalies.
        
        Args:
            new_logs (list): List of new log entries
        """
        if not new_logs:
            return
        
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Analyzing {len(new_logs)} new log entries...")
        
        # Convert to DataFrame
        df_new = pd.DataFrame(new_logs)
        
        # Insert into database
        self.db.insert_logs_bulk(df_new)
        
        # Get all recent logs for analysis (last 100 entries)
        all_logs = self.db.get_all_logs()
        if len(all_logs) > 100:
            recent_logs = all_logs.tail(100)
        else:
            recent_logs = all_logs
        
        # Run threat detection on recent logs
        detector = ThreatDetector(recent_logs, failed_login_threshold=3, time_window_minutes=10)
        threat_results = detector.detect_all_threats()
        
        # Check for new suspicious IPs
        if threat_results['suspicious_ips']:
            print(f"\n[ALERT] {len(threat_results['suspicious_ips'])} suspicious IP(s) detected!")
            
            for threat in threat_results['threat_details']:
                if threat['severity'] in ['HIGH', 'CRITICAL']:
                    self.trigger_alert(threat)
        
        # Run AI anomaly detection if enough data
        if len(recent_logs) >= 10:
            try:
                ai_detector = AnomalyDetector(recent_logs, contamination=0.15)
                anomaly_results = ai_detector.detect_anomalies()
                
                # Check for critical anomalies
                critical_anomalies = anomaly_results['anomaly_results'][
                    (anomaly_results['anomaly_results']['is_anomaly']) & 
                    (anomaly_results['anomaly_results']['anomaly_score'] < self.alert_threshold)
                ]
                
                if not critical_anomalies.empty:
                    print(f"\n[AI ALERT] {len(critical_anomalies)} critical anomalies detected!")
                    
                    for _, row in critical_anomalies.iterrows():
                        self.trigger_ai_alert(row)
            
            except Exception as e:
                print(f"AI anomaly detection error: {e}")
    
    def trigger_alert(self, threat):
        """
        Trigger a security alert for detected threat.
        
        Args:
            threat (dict): Threat details
        """
        alert_message = f"""
{'='*60}
SECURITY ALERT - {threat['severity']}
{'='*60}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {threat['ip']}
Threat Type: {threat['threat_type']}
Details: {threat['details']}
{'='*60}
        """
        
        print(alert_message)
        
        # Log alert to file
        with open('security_alerts.log', 'a') as f:
            f.write(alert_message + '\n')
    
    def trigger_ai_alert(self, anomaly_row):
        """
        Trigger an AI-based anomaly alert.
        
        Args:
            anomaly_row (pandas.Series): Anomaly details
        """
        alert_message = f"""
{'='*60}
AI ANOMALY ALERT
{'='*60}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {anomaly_row['ip']}
Anomaly Score: {anomaly_row['anomaly_score']:.4f}
Login Frequency: {anomaly_row['login_frequency']}
Failed Logins: {anomaly_row['failed_login_count']}
Failed Ratio: {anomaly_row['failed_ratio']:.2%}
{'='*60}
        """
        
        print(alert_message)
        
        # Log alert to file
        with open('security_alerts.log', 'a') as f:
            f.write(alert_message + '\n')
    
    def start_monitoring(self):
        """
        Start continuous monitoring of the log file.
        """
        print("\n" + "="*60)
        print("REAL-TIME LOG MONITORING STARTED")
        print("="*60)
        print(f"Monitoring file: {self.log_file_path}")
        print(f"Check interval: {self.check_interval} seconds")
        print(f"Database: {self.db_path}")
        print("Press Ctrl+C to stop monitoring\n")
        
        self.monitoring = True
        
        try:
            while self.monitoring:
                # Read new logs
                new_logs = self.read_new_logs()
                
                # Analyze if new logs found
                if new_logs:
                    self.analyze_new_logs(new_logs)
                
                # Wait before next check
                time.sleep(self.check_interval)
        
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
            self.stop_monitoring()
        
        except Exception as e:
            print(f"\nMonitoring error: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """
        Stop monitoring and cleanup.
        """
        self.monitoring = False
        self.db.close()
        print("\n" + "="*60)
        print("MONITORING STOPPED")
        print("="*60)


def start_realtime_monitoring(log_file='logs.txt', db_path='logs.db', check_interval=2):
    """
    Convenience function to start real-time monitoring.
    
    Args:
        log_file (str): Path to log file
        db_path (str): Path to database
        check_interval (int): Seconds between checks
    """
    monitor = LogMonitor(log_file, db_path, check_interval)
    monitor.start_monitoring()


if __name__ == "__main__":
    # Start monitoring
    print("Starting Real-Time Log Monitor...\n")
    start_realtime_monitoring('logs.txt', 'logs.db', check_interval=2)