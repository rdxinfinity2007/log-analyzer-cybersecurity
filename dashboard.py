"""
Security Dashboard Module

This module creates an interactive Streamlit dashboard for visualizing
log analysis results, threat detection, and anomaly detection.

Usage:
    streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# Import our modules
from parser import parse_logs, get_log_summary
from database import LogDatabase, init_database
from detector import ThreatDetector
from ai_model import AnomalyDetector

# Page configuration
st.set_page_config(
    page_title="Cybersecurity Log Analysis Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .alert-critical {
        background-color: #ff4444;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .alert-high {
        background-color: #ff8800;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .alert-medium {
        background-color: #ffbb33;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Cache data loading
@st.cache_data(ttl=60)
def load_data():
    """
    Load and process all data for the dashboard.
    """
    # Check if logs.txt exists
    if not os.path.exists('logs.txt'):
        return None, None, None, None
    
    # Parse logs
    df = parse_logs('logs.txt')
    
    if df.empty:
        return None, None, None, None
    
    # Get log summary
    summary = get_log_summary(df)
    
    # Run threat detection
    detector = ThreatDetector(df, failed_login_threshold=3, time_window_minutes=10)
    threat_results = detector.detect_all_threats()
    
    # Run AI anomaly detection
    ai_detector = AnomalyDetector(df, contamination=0.15)
    anomaly_results = ai_detector.detect_anomalies()
    
    return df, summary, threat_results, anomaly_results

def main():
    """
    Main dashboard function.
    """
    # Header
    st.markdown('<div class="main-header">🔒 Cybersecurity Log Analysis Dashboard</div>', unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("⚙️ Dashboard Controls")
    st.sidebar.markdown("---")
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.info("""
    **Dashboard Features:**
    - Real-time log analysis
    - Threat detection
    - AI anomaly detection
    - Interactive visualizations
    """)
    
    # Load data
    with st.spinner("Loading and analyzing logs..."):
        df, summary, threat_results, anomaly_results = load_data()
    
    # Check if data loaded successfully
    if df is None:
        st.error("❌ No logs found! Please ensure logs.txt exists and contains valid log entries.")
        st.info("Run `python main.py` first to generate analysis results.")
        return
    
    # Overview Metrics
    st.header("📊 Overview Metrics")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Logs",
            value=summary['total_logs'],
            delta=None
        )
    
    with col2:
        st.metric(
            label="Failed Logins",
            value=summary['failed_count'],
            delta=f"{(summary['failed_count']/summary['total_logs']*100):.1f}%"
        )
    
    with col3:
        st.metric(
            label="Suspicious IPs",
            value=len(threat_results['suspicious_ips']),
            delta="Threats Detected" if len(threat_results['suspicious_ips']) > 0 else "No Threats"
        )
    
    with col4:
        st.metric(
            label="AI Anomalies",
            value=len(anomaly_results['anomalous_ips']),
            delta="AI Detected" if len(anomaly_results['anomalous_ips']) > 0 else "Normal"
        )
    
    with col5:
        st.metric(
            label="Unique IPs",
            value=summary['unique_ips'],
            delta=None
        )
    
    st.markdown("---")
    
    # Threat Alerts Section
    st.header("🚨 Security Alerts")
    
    if threat_results['threat_details']:
        # Filter by severity
        critical_threats = [t for t in threat_results['threat_details'] if t['severity'] == 'CRITICAL']
        high_threats = [t for t in threat_results['threat_details'] if t['severity'] == 'HIGH']
        medium_threats = [t for t in threat_results['threat_details'] if t['severity'] == 'MEDIUM']
        
        # Display critical threats
        if critical_threats:
            st.subheader("🔴 Critical Threats")
            for threat in critical_threats:
                st.markdown(f"""
                <div class="alert-critical">
                    <strong>IP:</strong> {threat['ip']}<br>
                    <strong>Type:</strong> {threat['threat_type']}<br>
                    <strong>Details:</strong> {threat['details']}
                </div>
                """, unsafe_allow_html=True)
        
        # Display high threats
        if high_threats:
            st.subheader("🟠 High Severity Threats")
            for threat in high_threats:
                st.markdown(f"""
                <div class="alert-high">
                    <strong>IP:</strong> {threat['ip']}<br>
                    <strong>Type:</strong> {threat['threat_type']}<br>
                    <strong>Details:</strong> {threat['details']}
                </div>
                """, unsafe_allow_html=True)
        
        # Display medium threats
        if medium_threats:
            with st.expander("🟡 Medium Severity Threats"):
                for threat in medium_threats:
                    st.markdown(f"""
                    <div class="alert-medium">
                        <strong>IP:</strong> {threat['ip']}<br>
                        <strong>Type:</strong> {threat['threat_type']}<br>
                        <strong>Details:</strong> {threat['details']}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.success("✅ No security threats detected!")
    
    st.markdown("---")
    
    # Visualizations
    st.header("📈 Analytics & Visualizations")
    
    # Create tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["Login Activity", "Threat Analysis", "AI Anomalies", "IP Analysis"])
    
    with tab1:
        st.subheader("Login Activity Over Time")
        
        # Time series plot
        df_time = df.copy()
        df_time['hour'] = df_time['timestamp'].dt.floor('H')
        time_counts = df_time.groupby(['hour', 'action']).size().reset_index(name='count')
        
        fig_time = px.line(
            time_counts,
            x='hour',
            y='count',
            color='action',
            title='Login Attempts Over Time',
            labels={'hour': 'Time', 'count': 'Number of Attempts'},
            color_discrete_map={'LOGIN SUCCESS': 'green', 'LOGIN FAILED': 'red'}
        )
        st.plotly_chart(fig_time, use_container_width=True)
        
        # Success vs Failed pie chart
        col1, col2 = st.columns(2)
        
        with col1:
            action_counts = df['action'].value_counts()
            fig_pie = px.pie(
                values=action_counts.values,
                names=action_counts.index,
                title='Login Success vs Failed',
                color_discrete_map={'LOGIN SUCCESS': 'green', 'LOGIN FAILED': 'red'}
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Top users
            top_users = df['user'].value_counts().head(10)
            fig_users = px.bar(
                x=top_users.values,
                y=top_users.index,
                orientation='h',
                title='Top 10 Users by Login Attempts',
                labels={'x': 'Attempts', 'y': 'User'}
            )
            st.plotly_chart(fig_users, use_container_width=True)
    
    with tab2:
        st.subheader("Threat Detection Analysis")
        
        if threat_results['suspicious_ips']:
            # Threat type distribution
            threat_types = pd.DataFrame(threat_results['threat_details'])
            threat_type_counts = threat_types['threat_type'].value_counts()
            
            col1, col2 = st.columns(2)
            
            with col1:
                fig_threat_types = px.bar(
                    x=threat_type_counts.values,
                    y=threat_type_counts.index,
                    orientation='h',
                    title='Threat Types Distribution',
                    labels={'x': 'Count', 'y': 'Threat Type'},
                    color=threat_type_counts.values,
                    color_continuous_scale='Reds'
                )
                st.plotly_chart(fig_threat_types, use_container_width=True)
            
            with col2:
                # Severity distribution
                severity_counts = threat_types['severity'].value_counts()
                fig_severity = px.pie(
                    values=severity_counts.values,
                    names=severity_counts.index,
                    title='Threat Severity Distribution',
                    color_discrete_map={'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow'}
                )
                st.plotly_chart(fig_severity, use_container_width=True)
            
            # Suspicious IPs table
            st.subheader("Suspicious IP Addresses")
            st.dataframe(
                threat_types[['ip', 'threat_type', 'severity', 'details']],
                use_container_width=True
            )
        else:
            st.info("No threats detected in the current logs.")
    
    with tab3:
        st.subheader("AI Anomaly Detection Results")
        
        if not anomaly_results['anomaly_results'].empty:
            # Anomaly score distribution
            fig_anomaly_dist = px.histogram(
                anomaly_results['anomaly_results'],
                x='anomaly_score',
                nbins=30,
                title='Anomaly Score Distribution',
                labels={'anomaly_score': 'Anomaly Score', 'count': 'Frequency'},
                color_discrete_sequence=['#636EFA']
            )
            fig_anomaly_dist.add_vline(x=-0.5, line_dash="dash", line_color="red", annotation_text="Threshold")
            st.plotly_chart(fig_anomaly_dist, use_container_width=True)
            
            # Top anomalies
            st.subheader("Top 10 Anomalous IPs")
            top_anomalies = anomaly_results['anomaly_results'].nsmallest(10, 'anomaly_score')
            
            fig_top_anomalies = px.bar(
                top_anomalies,
                x='anomaly_score',
                y='ip',
                orientation='h',
                title='Most Anomalous IP Addresses',
                labels={'anomaly_score': 'Anomaly Score', 'ip': 'IP Address'},
                color='anomaly_score',
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig_top_anomalies, use_container_width=True)
            
            # Anomaly details table
            st.subheader("Anomaly Details")
            display_cols = ['ip', 'anomaly_score', 'login_frequency', 'failed_login_count', 'failed_ratio', 'is_anomaly']
            st.dataframe(
                anomaly_results['anomaly_results'][display_cols].sort_values('anomaly_score'),
                use_container_width=True
            )
        else:
            st.info("No anomaly data available.")
    
    with tab4:
        st.subheader("IP Address Analysis")
        
        # Top IPs by activity
        ip_counts = df['ip'].value_counts().head(15)
        
        fig_top_ips = px.bar(
            x=ip_counts.values,
            y=ip_counts.index,
            orientation='h',
            title='Top 15 Most Active IP Addresses',
            labels={'x': 'Login Attempts', 'y': 'IP Address'},
            color=ip_counts.values,
            color_continuous_scale='Blues'
        )
        st.plotly_chart(fig_top_ips, use_container_width=True)
        
        # IP details selector
        st.subheader("Detailed IP Analysis")
        selected_ip = st.selectbox("Select IP Address", df['ip'].unique())
        
        if selected_ip:
            ip_data = df[df['ip'] == selected_ip]
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Attempts", len(ip_data))
            with col2:
                st.metric("Failed Logins", len(ip_data[ip_data['action'] == 'LOGIN FAILED']))
            with col3:
                st.metric("Unique Users", ip_data['user'].nunique())
            
            # IP activity timeline
            ip_timeline = ip_data.groupby([ip_data['timestamp'].dt.floor('H'), 'action']).size().reset_index(name='count')
            fig_ip_timeline = px.line(
                ip_timeline,
                x='timestamp',
                y='count',
                color='action',
                title=f'Activity Timeline for {selected_ip}',
                color_discrete_map={'LOGIN SUCCESS': 'green', 'LOGIN FAILED': 'red'}
            )
            st.plotly_chart(fig_ip_timeline, use_container_width=True)
            
            # Users targeted by this IP
            st.subheader("Users Targeted")
            user_attempts = ip_data['user'].value_counts()
            st.dataframe(user_attempts, use_container_width=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <p>Automated Log Analysis System for Cybersecurity | Last Updated: {}</p>
    </div>
    """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), unsafe_allow_html=True)

if __name__ == "__main__":
    main()