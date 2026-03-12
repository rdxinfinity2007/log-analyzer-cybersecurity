"""
Database Module

This module handles all database operations for the log analysis system.
It creates and manages an SQLite database to store parsed logs.

Usage:
    from database import init_database, insert_logs, get_all_logs
    init_database()
    insert_logs(df)
"""

import sqlite3
import pandas as pd
from datetime import datetime


class LogDatabase:
    """
    Class to manage log database operations.
    """
    
    def __init__(self, db_path='logs.db'):
        """
        Initialize database connection.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def connect(self):
        """
        Establish connection to the database.
        """
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            print(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")
    
    def close(self):
        """
        Close database connection.
        """
        if self.conn:
            self.conn.close()
            print("Database connection closed")
    
    def create_table(self):
        """
        Create logs table if it doesn't exist.
        
        Table structure:
        - id: Primary key (auto-increment)
        - timestamp: Log timestamp
        - action: Login action (SUCCESS/FAILED)
        - user: Username
        - ip: IP address
        """
        try:
            create_table_query = '''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                user TEXT NOT NULL,
                ip TEXT NOT NULL
            )
            '''
            
            self.cursor.execute(create_table_query)
            self.conn.commit()
            print("Logs table created successfully")
            
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")
    
    def insert_log(self, timestamp, action, user, ip):
        """
        Insert a single log entry into the database.
        
        Args:
            timestamp (datetime): Log timestamp
            action (str): Login action
            user (str): Username
            ip (str): IP address
        """
        try:
            insert_query = '''
            INSERT INTO logs (timestamp, action, user, ip)
            VALUES (?, ?, ?, ?)
            '''
            
            # Convert datetime to string for storage
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            self.cursor.execute(insert_query, (timestamp_str, action, user, ip))
            self.conn.commit()
            
        except sqlite3.Error as e:
            print(f"Error inserting log: {e}")
    
    def insert_logs_bulk(self, df):
        """
        Insert multiple log entries from a DataFrame.
        
        Args:
            df (pandas.DataFrame): DataFrame with columns: timestamp, action, user, ip
        """
        try:
            # Convert DataFrame to list of tuples
            # Convert datetime objects to strings
            df_copy = df.copy()
            df_copy['timestamp'] = df_copy['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            logs_data = df_copy[['timestamp', 'action', 'user', 'ip']].values.tolist()
            
            insert_query = '''
            INSERT INTO logs (timestamp, action, user, ip)
            VALUES (?, ?, ?, ?)
            '''
            
            self.cursor.executemany(insert_query, logs_data)
            self.conn.commit()
            
            print(f"Successfully inserted {len(logs_data)} log entries")
            
        except sqlite3.Error as e:
            print(f"Error inserting logs in bulk: {e}")
    
    def get_all_logs(self):
        """
        Retrieve all logs from the database.
        
        Returns:
            pandas.DataFrame: All logs as a DataFrame
        """
        try:
            query = 'SELECT * FROM logs'
            df = pd.read_sql_query(query, self.conn)
            
            # Convert timestamp strings back to datetime objects
            if not df.empty:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            return df
            
        except sqlite3.Error as e:
            print(f"Error retrieving logs: {e}")
            return pd.DataFrame()
    
    def get_logs_by_ip(self, ip):
        """
        Retrieve all logs for a specific IP address.
        
        Args:
            ip (str): IP address to filter by
            
        Returns:
            pandas.DataFrame: Filtered logs
        """
        try:
            query = 'SELECT * FROM logs WHERE ip = ?'
            df = pd.read_sql_query(query, self.conn, params=(ip,))
            
            if not df.empty:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            return df
            
        except sqlite3.Error as e:
            print(f"Error retrieving logs by IP: {e}")
            return pd.DataFrame()
    
    def get_failed_logins(self):
        """
        Retrieve all failed login attempts.
        
        Returns:
            pandas.DataFrame: Failed login logs
        """
        try:
            query = "SELECT * FROM logs WHERE action = 'LOGIN FAILED'"
            df = pd.read_sql_query(query, self.conn)
            
            if not df.empty:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            return df
            
        except sqlite3.Error as e:
            print(f"Error retrieving failed logins: {e}")
            return pd.DataFrame()
    
    def get_log_count(self):
        """
        Get total number of logs in the database.
        
        Returns:
            int: Total log count
        """
        try:
            query = 'SELECT COUNT(*) FROM logs'
            self.cursor.execute(query)
            count = self.cursor.fetchone()[0]
            return count
            
        except sqlite3.Error as e:
            print(f"Error getting log count: {e}")
            return 0
    
    def clear_logs(self):
        """
        Delete all logs from the database.
        WARNING: This operation cannot be undone.
        """
        try:
            query = 'DELETE FROM logs'
            self.cursor.execute(query)
            self.conn.commit()
            print("All logs cleared from database")
            
        except sqlite3.Error as e:
            print(f"Error clearing logs: {e}")


def init_database(db_path='logs.db'):
    """
    Initialize the database and create the logs table.
    
    Args:
        db_path (str): Path to database file
        
    Returns:
        LogDatabase: Database instance
    """
    db = LogDatabase(db_path)
    db.connect()
    db.create_table()
    return db


def insert_logs(df, db_path='logs.db'):
    """
    Convenience function to insert logs from a DataFrame.
    
    Args:
        df (pandas.DataFrame): Logs DataFrame
        db_path (str): Path to database file
    """
    db = LogDatabase(db_path)
    db.connect()
    db.insert_logs_bulk(df)
    db.close()


def get_all_logs(db_path='logs.db'):
    """
    Convenience function to retrieve all logs.
    
    Args:
        db_path (str): Path to database file
        
    Returns:
        pandas.DataFrame: All logs
    """
    db = LogDatabase(db_path)
    db.connect()
    df = db.get_all_logs()
    db.close()
    return df


if __name__ == "__main__":
    # Test the database module
    print("Testing Database Module...\n")
    
    # Initialize database
    db = init_database()
    
    # Test with sample data
    sample_data = pd.DataFrame([
        {
            'timestamp': datetime.now(),
            'action': 'LOGIN SUCCESS',
            'user': 'test_user',
            'ip': '192.168.1.100'
        }
    ])
    
    print("\nInserting sample log...")
    db.insert_logs_bulk(sample_data)
    
    print("\nRetrieving all logs...")
    all_logs = db.get_all_logs()
    print(all_logs)
    
    print(f"\nTotal logs in database: {db.get_log_count()}")
    
    db.close()