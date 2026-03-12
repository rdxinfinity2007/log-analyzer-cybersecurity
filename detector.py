"""
Threat Detection Engine

This module analyzes parsed logs to detect suspicious patterns and potential cyber threats.
It identifies:
- Multiple failed login attempts from the same IP
- Brute force attacks
- Abnormal login frequency
- Suspicious user behavior

Usage:
    from detector import ThreatDetector
    detector = ThreatDetector(df)
    suspicious_ips = detector.detect_threats()
"""

import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict


class ThreatDetector:
    """
    Class to detect various cybersecurity threats from log data.
    """
    
    def __init__(self, df, failed_login_threshold=3, time_window_minutes=10):
        """
        Initialize the threat detector.
        
        Args:
            df (pandas.DataFrame): Parsed log DataFrame
            failed_login_threshold (int): Number of failed logins to trigger alert
            time_window_minutes (int): Time window for detecting rapid attempts
        """
        self.df = df
        self.failed_login_threshold = failed_login_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.suspicious_ips = set()
        self.threat_details = []
    
    def detect_multiple_failed_logins(self):
        """
        Detect IPs with multiple failed login attempts.
        
        Returns:
            list: List of suspicious IPs with failed login counts
        """
        print("\n[*] Detecting multiple failed login attempts...")
        
        # Filter failed logins
        failed_logins = self.df[self.df['action'] == 'LOGIN FAILED']
        
        # Count failed logins per IP
        failed_counts = failed_logins.groupby('ip').size().reset_index(name='failed_count')
        
        # Filter IPs exceeding threshold
        suspicious = failed_counts[failed_counts['failed_count'] >= self.failed_login_threshold]
        
        for _, row in suspicious.iterrows():
            ip = row['ip']
            count = row['failed_count']
            self.suspicious_ips.add(ip)
            self.threat_details.append({
                'ip': ip,
                'threat_type': 'Multiple Failed Logins',
                'severity': 'HIGH' if count >= 5 else 'MEDIUM',
                'details': f"{count} failed login attempts detected",
                'count': count
            })
            print(f"  [!] Suspicious IP: {ip} - {count} failed login attempts")
        
        return suspicious.to_dict('records')
    
    def detect_brute_force_attacks(self):
        """
        Detect brute force attacks (rapid failed login attempts within time window).
        
        Returns:
            list: List of IPs performing brute force attacks
        """
        print("\n[*] Detecting brute force attacks...")
        
        failed_logins = self.df[self.df['action'] == 'LOGIN FAILED'].copy()
        failed_logins = failed_logins.sort_values('timestamp')
        
        brute_force_ips = []
        
        # Group by IP
        for ip, group in failed_logins.groupby('ip'):
            timestamps = group['timestamp'].tolist()
            
            # Check for rapid attempts within time window
            for i in range(len(timestamps)):
                rapid_attempts = 0
                start_time = timestamps[i]
                
                for j in range(i, len(timestamps)):
                    if timestamps[j] - start_time <= self.time_window:
                        rapid_attempts += 1
                    else:
                        break
                
                # If rapid attempts exceed threshold, it's a brute force attack
                if rapid_attempts >= self.failed_login_threshold:
                    self.suspicious_ips.add(ip)
                    
                    # Check if already added
                    if not any(d['ip'] == ip and d['threat_type'] == 'Brute Force Attack' for d in self.threat_details):
                        self.threat_details.append({
                            'ip': ip,
                            'threat_type': 'Brute Force Attack',
                            'severity': 'CRITICAL',
                            'details': f"{rapid_attempts} failed attempts in {self.time_window.seconds // 60} minutes",
                            'count': rapid_attempts
                        })
                        brute_force_ips.append({
                            'ip': ip,
                            'rapid_attempts': rapid_attempts,
                            'time_window': f"{self.time_window.seconds // 60} minutes"
                        })
                        print(f"  [!] BRUTE FORCE DETECTED: {ip} - {rapid_attempts} attempts in {self.time_window.seconds // 60} minutes")
                    break
        
        return brute_force_ips
    
    def detect_abnormal_login_frequency(self):
        """
        Detect IPs with abnormally high login frequency.
        
        Returns:
            list: List of IPs with abnormal activity
        """
        print("\n[*] Detecting abnormal login frequency...")
        
        # Count total login attempts per IP
        login_counts = self.df.groupby('ip').size().reset_index(name='total_attempts')
        
        # Calculate mean and standard deviation
        mean_attempts = login_counts['total_attempts'].mean()
        std_attempts = login_counts['total_attempts'].std()
        
        # Define abnormal as > mean + 2*std
        threshold = mean_attempts + (2 * std_attempts)
        
        abnormal = login_counts[login_counts['total_attempts'] > threshold]
        
        for _, row in abnormal.iterrows():
            ip = row['ip']
            count = row['total_attempts']
            self.suspicious_ips.add(ip)
            
            # Check if not already added
            if not any(d['ip'] == ip and d['threat_type'] == 'Abnormal Login Frequency' for d in self.threat_details):
                self.threat_details.append({
                    'ip': ip,
                    'threat_type': 'Abnormal Login Frequency',
                    'severity': 'MEDIUM',
                    'details': f"{count} total attempts (threshold: {threshold:.1f})",
                    'count': count
                })
                print(f"  [!] Abnormal activity: {ip} - {count} total attempts (threshold: {threshold:.1f})")
        
        return abnormal.to_dict('records')
    
    def detect_suspicious_usernames(self):
        """
        Detect attempts to login with common administrative usernames.
        
        Returns:
            list: List of IPs attempting suspicious usernames
        """
        print("\n[*] Detecting suspicious username attempts...")
        
        # Common administrative usernames that attackers try
        suspicious_usernames = ['admin', 'root', 'administrator', 'superuser', 'sa']
        
        suspicious_attempts = self.df[
            (self.df['user'].isin(suspicious_usernames)) & 
            (self.df['action'] == 'LOGIN FAILED')
        ]
        
        username_attacks = suspicious_attempts.groupby('ip').size().reset_index(name='suspicious_username_attempts')
        
        for _, row in username_attacks.iterrows():
            ip = row['ip']
            count = row['suspicious_username_attempts']
            self.suspicious_ips.add(ip)
            
            # Check if not already added
            if not any(d['ip'] == ip and d['threat_type'] == 'Suspicious Username Attempts' for d in self.threat_details):
                self.threat_details.append({
                    'ip': ip,
                    'threat_type': 'Suspicious Username Attempts',
                    'severity': 'HIGH',
                    'details': f"{count} attempts with admin usernames",
                    'count': count
                })
                print(f"  [!] Suspicious usernames: {ip} - {count} attempts with admin usernames")
        
        return username_attacks.to_dict('records')
    
    def detect_all_threats(self):
        """
        Run all threat detection methods.
        
        Returns:
            dict: Dictionary containing all detection results
        """
        print("\n" + "="*60)
        print("THREAT DETECTION ENGINE - ANALYSIS STARTED")
        print("="*60)
        
        results = {
            'multiple_failed_logins': self.detect_multiple_failed_logins(),
            'brute_force_attacks': self.detect_brute_force_attacks(),
            'abnormal_frequency': self.detect_abnormal_login_frequency(),
            'suspicious_usernames': self.detect_suspicious_usernames(),
            'suspicious_ips': list(self.suspicious_ips),
            'threat_details': self.threat_details
        }
        
        print("\n" + "="*60)
        print(f"ANALYSIS COMPLETE - {len(self.suspicious_ips)} SUSPICIOUS IPs DETECTED")
        print("="*60)
        
        return results
    
    def get_ip_summary(self, ip):
        """
        Get detailed summary for a specific IP address.
        
        Args:
            ip (str): IP address to analyze
            
        Returns:
            dict: Summary of activity for the IP
        """
        ip_logs = self.df[self.df['ip'] == ip]
        
        if ip_logs.empty:
            return None
        
        summary = {
            'ip': ip,
            'total_attempts': len(ip_logs),
            'failed_attempts': len(ip_logs[ip_logs['action'] == 'LOGIN FAILED']),
            'successful_attempts': len(ip_logs[ip_logs['action'] == 'LOGIN SUCCESS']),
            'unique_users_targeted': ip_logs['user'].nunique(),
            'first_seen': ip_logs['timestamp'].min(),
            'last_seen': ip_logs['timestamp'].max(),
            'users_attempted': ip_logs['user'].unique().tolist()
        }
        
        return summary
    
    def generate_threat_report(self):
        """
        Generate a comprehensive threat report.
        
        Returns:
            str: Formatted threat report
        """
        report = "\n" + "="*60 + "\n"
        report += "CYBERSECURITY THREAT DETECTION REPORT\n"
        report += "="*60 + "\n\n"
        
        report += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Logs Analyzed: {len(self.df)}\n"
        report += f"Suspicious IPs Detected: {len(self.suspicious_ips)}\n\n"
        
        if self.threat_details:
            report += "DETECTED THREATS:\n"
            report += "-" * 60 + "\n"
            
            for threat in self.threat_details:
                report += f"\nIP Address: {threat['ip']}\n"
                report += f"Threat Type: {threat['threat_type']}\n"
                report += f"Severity: {threat['severity']}\n"
                report += f"Details: {threat['details']}\n"
                report += "-" * 60 + "\n"
        else:
            report += "No threats detected.\n"
        
        return report


def detect_threats(df, failed_login_threshold=3, time_window_minutes=10):
    """
    Convenience function to detect threats from a DataFrame.
    
    Args:
        df (pandas.DataFrame): Parsed log DataFrame
        failed_login_threshold (int): Threshold for failed login alerts
        time_window_minutes (int): Time window for brute force detection
        
    Returns:
        dict: Detection results
    """
    detector = ThreatDetector(df, failed_login_threshold, time_window_minutes)
    return detector.detect_all_threats()


if __name__ == "__main__":
    # Test the detector
    print("Testing Threat Detection Engine...\n")
    
    # Import parser to get sample data
    from parser import parse_logs
    
    # Parse logs
    df = parse_logs('logs.txt')
    
    if not df.empty:
        # Create detector instance
        detector = ThreatDetector(df, failed_login_threshold=3, time_window_minutes=10)
        
        # Run all detections
        results = detector.detect_all_threats()
        
        # Print threat report
        print(detector.generate_threat_report())
        
        # Print IP summaries for suspicious IPs
        if results['suspicious_ips']:
            print("\n" + "="*60)
            print("DETAILED IP ANALYSIS")
            print("="*60)
            
            for ip in results['suspicious_ips'][:5]:  # Show first 5
                summary = detector.get_ip_summary(ip)
                print(f"\nIP: {summary['ip']}")
                print(f"  Total Attempts: {summary['total_attempts']}")
                print(f"  Failed: {summary['failed_attempts']}")
                print(f"  Successful: {summary['successful_attempts']}")
                print(f"  Users Targeted: {summary['unique_users_targeted']}")
                print(f"  First Seen: {summary['first_seen']}")
                print(f"  Last Seen: {summary['last_seen']}")
    else:
        print("No logs to analyze")