"""
AI Anomaly Detection Module

This module uses machine learning (Isolation Forest) to detect anomalies in login behavior.
It analyzes login frequency, failed login counts, and time intervals to identify suspicious IPs.

Usage:
    from ai_model import AnomalyDetector
    detector = AnomalyDetector(df)
    results = detector.detect_anomalies()
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')


class AnomalyDetector:
    """
    Class to detect anomalies in login behavior using Isolation Forest.
    """
    
    def __init__(self, df, contamination=0.1, random_state=42):
        """
        Initialize the anomaly detector.
        
        Args:
            df (pandas.DataFrame): Parsed log DataFrame
            contamination (float): Expected proportion of outliers (0.1 = 10%)
            random_state (int): Random seed for reproducibility
        """
        self.df = df
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        self.features_df = None
        self.anomaly_results = None
    
    def extract_features(self):
        """
        Extract features from logs for each IP address.
        
        Features:
        - login_frequency: Total number of login attempts
        - failed_login_count: Number of failed login attempts
        - success_login_count: Number of successful logins
        - failed_ratio: Ratio of failed to total logins
        - avg_time_interval: Average time between login attempts (seconds)
        - unique_users: Number of unique usernames attempted
        - login_duration: Time span between first and last login (seconds)
        
        Returns:
            pandas.DataFrame: Feature matrix for each IP
        """
        print("\n[*] Extracting features for anomaly detection...")
        
        features = []
        
        for ip, group in self.df.groupby('ip'):
            # Sort by timestamp
            group = group.sort_values('timestamp')
            
            # Basic counts
            total_attempts = len(group)
            failed_count = len(group[group['action'] == 'LOGIN FAILED'])
            success_count = len(group[group['action'] == 'LOGIN SUCCESS'])
            
            # Failed ratio
            failed_ratio = failed_count / total_attempts if total_attempts > 0 else 0
            
            # Time intervals between attempts
            timestamps = group['timestamp'].tolist()
            time_intervals = []
            
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                time_intervals.append(interval)
            
            avg_time_interval = np.mean(time_intervals) if time_intervals else 0
            min_time_interval = np.min(time_intervals) if time_intervals else 0
            
            # Unique users targeted
            unique_users = group['user'].nunique()
            
            # Login duration (time span)
            if len(timestamps) > 1:
                login_duration = (timestamps[-1] - timestamps[0]).total_seconds()
            else:
                login_duration = 0
            
            # Attempts per minute
            attempts_per_minute = (total_attempts / (login_duration / 60)) if login_duration > 0 else total_attempts
            
            features.append({
                'ip': ip,
                'login_frequency': total_attempts,
                'failed_login_count': failed_count,
                'success_login_count': success_count,
                'failed_ratio': failed_ratio,
                'avg_time_interval': avg_time_interval,
                'min_time_interval': min_time_interval,
                'unique_users': unique_users,
                'login_duration': login_duration,
                'attempts_per_minute': attempts_per_minute
            })
        
        self.features_df = pd.DataFrame(features)
        print(f"  [+] Extracted features for {len(self.features_df)} IP addresses")
        
        return self.features_df
    
    def train_model(self):
        """
        Train the Isolation Forest model on extracted features.
        """
        print("\n[*] Training Isolation Forest model...")
        
        if self.features_df is None:
            self.extract_features()
        
        # Select features for training (exclude IP address)
        feature_columns = [
            'login_frequency',
            'failed_login_count',
            'failed_ratio',
            'avg_time_interval',
            'min_time_interval',
            'unique_users',
            'attempts_per_minute'
        ]
        
        X = self.features_df[feature_columns].values
        
        # Standardize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        
        self.model.fit(X_scaled)
        print("  [+] Model training complete")
    
    def predict_anomalies(self):
        """
        Predict anomalies using the trained model.
        
        Returns:
            pandas.DataFrame: Results with anomaly scores and predictions
        """
        print("\n[*] Detecting anomalies...")
        
        if self.model is None:
            self.train_model()
        
        # Select features
        feature_columns = [
            'login_frequency',
            'failed_login_count',
            'failed_ratio',
            'avg_time_interval',
            'min_time_interval',
            'unique_users',
            'attempts_per_minute'
        ]
        
        X = self.features_df[feature_columns].values
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies
        # -1 for anomalies, 1 for normal
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (lower scores = more anomalous)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Add results to features dataframe
        self.features_df['anomaly_score'] = anomaly_scores
        self.features_df['is_anomaly'] = predictions == -1
        
        # Sort by anomaly score (most anomalous first)
        self.anomaly_results = self.features_df.sort_values('anomaly_score')
        
        anomaly_count = (predictions == -1).sum()
        print(f"  [+] Detected {anomaly_count} anomalous IP addresses")
        
        return self.anomaly_results
    
    def get_anomalous_ips(self, threshold=None):
        """
        Get list of anomalous IP addresses.
        
        Args:
            threshold (float): Custom anomaly score threshold (optional)
            
        Returns:
            list: List of anomalous IP addresses
        """
        if self.anomaly_results is None:
            self.predict_anomalies()
        
        if threshold is not None:
            # Use custom threshold
            anomalous = self.anomaly_results[self.anomaly_results['anomaly_score'] < threshold]
        else:
            # Use model's prediction
            anomalous = self.anomaly_results[self.anomaly_results['is_anomaly']]
        
        return anomalous['ip'].tolist()
    
    def get_top_anomalies(self, n=10):
        """
        Get top N most anomalous IPs.
        
        Args:
            n (int): Number of top anomalies to return
            
        Returns:
            pandas.DataFrame: Top N anomalous IPs with details
        """
        if self.anomaly_results is None:
            self.predict_anomalies()
        
        return self.anomaly_results.head(n)
    
    def generate_anomaly_report(self):
        """
        Generate a detailed anomaly detection report.
        
        Returns:
            str: Formatted report
        """
        if self.anomaly_results is None:
            self.predict_anomalies()
        
        report = "\n" + "="*60 + "\n"
        report += "AI ANOMALY DETECTION REPORT\n"
        report += "="*60 + "\n\n"
        
        report += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total IPs Analyzed: {len(self.anomaly_results)}\n"
        report += f"Anomalies Detected: {self.anomaly_results['is_anomaly'].sum()}\n"
        report += f"Contamination Rate: {self.contamination * 100}%\n\n"
        
        # Top anomalies
        top_anomalies = self.get_top_anomalies(5)
        
        report += "TOP 5 MOST ANOMALOUS IPs:\n"
        report += "-" * 60 + "\n"
        
        for idx, row in top_anomalies.iterrows():
            report += f"\nIP: {row['ip']}\n"
            report += f"  Anomaly Score: {row['anomaly_score']:.4f}\n"
            report += f"  Is Anomaly: {'YES' if row['is_anomaly'] else 'NO'}\n"
            report += f"  Login Frequency: {row['login_frequency']}\n"
            report += f"  Failed Logins: {row['failed_login_count']}\n"
            report += f"  Failed Ratio: {row['failed_ratio']:.2%}\n"
            report += f"  Avg Time Interval: {row['avg_time_interval']:.2f}s\n"
            report += f"  Unique Users: {row['unique_users']}\n"
            report += "-" * 60 + "\n"
        
        return report
    
    def detect_anomalies(self):
        """
        Complete anomaly detection pipeline.
        
        Returns:
            dict: Detection results
        """
        print("\n" + "="*60)
        print("AI ANOMALY DETECTION - ANALYSIS STARTED")
        print("="*60)
        
        # Extract features
        self.extract_features()
        
        # Train model
        self.train_model()
        
        # Predict anomalies
        results = self.predict_anomalies()
        
        # Get anomalous IPs
        anomalous_ips = self.get_anomalous_ips()
        
        print("\n" + "="*60)
        print(f"ANALYSIS COMPLETE - {len(anomalous_ips)} ANOMALIES DETECTED")
        print("="*60)
        
        return {
            'anomaly_results': results,
            'anomalous_ips': anomalous_ips,
            'features': self.features_df,
            'model': self.model
        }


def detect_anomalies(df, contamination=0.1):
    """
    Convenience function to detect anomalies from a DataFrame.
    
    Args:
        df (pandas.DataFrame): Parsed log DataFrame
        contamination (float): Expected proportion of outliers
        
    Returns:
        dict: Detection results
    """
    detector = AnomalyDetector(df, contamination=contamination)
    return detector.detect_anomalies()


if __name__ == "__main__":
    # Test the anomaly detector
    print("Testing AI Anomaly Detection Module...\n")
    
    # Import parser to get sample data
    from parser import parse_logs
    
    # Parse logs
    df = parse_logs('logs.txt')
    
    if not df.empty:
        # Create detector instance
        detector = AnomalyDetector(df, contamination=0.15)
        
        # Run anomaly detection
        results = detector.detect_anomalies()
        
        # Print report
        print(detector.generate_anomaly_report())
        
        # Show feature importance
        print("\n" + "="*60)
        print("FEATURE STATISTICS")
        print("="*60)
        print(detector.features_df.describe())
    else:
        print("No logs to analyze")