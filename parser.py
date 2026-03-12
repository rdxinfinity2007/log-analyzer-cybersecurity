"""\nLog Parser Module\n\nThis module reads raw log files and converts them into structured data.\nIt extracts timestamp, action, user, and IP address from each log entry.\n\nUsage:\n    from parser import parse_logs\n    df = parse_logs('logs.txt')\n"""

import pandas as pd
import re
from datetime import datetime


def parse_log_line(line):
    """
    Parse a single log line and extract structured data.\n    \n    Args:\n        line (str): Raw log line\n        \n    Returns:\n        dict: Parsed log data with keys: timestamp, action, user, ip\n        None: If line cannot be parsed\n    """
    try:
        # Regular expression pattern to match log format
        # Format: YYYY-MM-DD HH:MM:SS ACTION user:USERNAME ip:IP_ADDRESS
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (LOGIN (?:SUCCESS|FAILED)) user:(\S+) ip:(\d+\.\d+\.\d+\.\d+)'
        
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, action, user, ip = match.groups()
            
            # Convert timestamp string to datetime object
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            
            return {
                'timestamp': timestamp,
                'action': action,
                'user': user,
                'ip': ip
            }
        else:
            return None
            
    except Exception as e:
        print(f"Error parsing line: {line}")
        print(f"Error: {e}")
        return None


def parse_logs(log_file_path):
    """
    Parse entire log file and return structured DataFrame.\n    \n    Args:\n        log_file_path (str): Path to the log file\n        \n    Returns:\n        pandas.DataFrame: Parsed logs with columns: timestamp, action, user, ip\n    """
    parsed_logs = []
    
    try:
        # Read log file line by line
        with open(log_file_path, 'r') as file:
            for line in file:
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Parse the log line
                parsed_data = parse_log_line(line)
                
                if parsed_data:
                    parsed_logs.append(parsed_data)
        
        # Convert list of dictionaries to pandas DataFrame
        df = pd.DataFrame(parsed_logs)
        
        print(f"Successfully parsed {len(df)} log entries")
        return df
        
    except FileNotFoundError:
        print(f"Error: Log file '{log_file_path}' not found")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading log file: {e}")
        return pd.DataFrame()


def get_log_summary(df):
    """
    Generate summary statistics from parsed logs.\n    \n    Args:\n        df (pandas.DataFrame): Parsed log DataFrame\n        \n    Returns:\n        dict: Summary statistics\n    """
    if df.empty:
        return {}
    
    summary = {
        'total_logs': len(df),
        'unique_users': df['user'].nunique(),
        'unique_ips': df['ip'].nunique(),
        'success_count': len(df[df['action'] == 'LOGIN SUCCESS']),
        'failed_count': len(df[df['action'] == 'LOGIN FAILED']),
        'time_range': f"{df['timestamp'].min()} to {df['timestamp'].max()}"
    }
    
    return summary


if __name__ == "__main__":
    # Test the parser
    print("Testing Log Parser...\n")
    
    # Parse logs
    df = parse_logs('logs.txt')
    
    if not df.empty:
        print("\n=== Parsed Logs (First 10 entries) ===")
        print(df.head(10))
        
        print("\n=== Log Summary ===")
        summary = get_log_summary(df)
        for key, value in summary.items():
            print(f"{key}: {value}")
        
        print("\n=== Data Types ===")
        print(df.dtypes)
    else:
        print("No logs parsed")