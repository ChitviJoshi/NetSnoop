#!/usr/bin/env python3
"""
System Monitor Dashboard
A Python-based dashboard for visualizing system monitoring data
Run with: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import csv
import os
from datetime import datetime, timedelta
import time
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="System Monitor Dashboard",
    page_icon="🖥️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff6b6b;
    }
    .critical-alert {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(244, 67, 54, 0.2);
    }
    .high-alert {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(255, 152, 0, 0.2);
    }
    .medium-alert {
        background-color: #fff9c4;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(255, 193, 7, 0.2);
    }
    .extreme-alert {
        background-color: #f3e5f5;
        border-left: 4px solid #9c27b0;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(156, 39, 176, 0.3);
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { background-color: #f3e5f5; }
        50% { background-color: #fce4ec; }
        100% { background-color: #f3e5f5; }
    }
    .alert-header {
        font-weight: bold;
        font-size: 1.1em;
        margin-bottom: 0.5rem;
    }
    .alert-details {
        font-size: 0.9em;
        color: #666;
    }
</style>
""", unsafe_allow_html=True)

def load_anomaly_data(csv_file="anomalies.csv"):
    """Load anomaly data from CSV file"""
    try:
        if not os.path.exists(csv_file):
            return pd.DataFrame()
        
        df = pd.read_csv(csv_file)
        if not df.empty:
            # Handle IST timestamp format - remove " IST" suffix and parse
            if 'timestamp' in df.columns:
                # Remove " IST" suffix if present
                df['timestamp'] = df['timestamp'].astype(str).str.replace(' IST', '', regex=False)
                # Convert to datetime
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S', errors='coerce')
                # Drop any rows where timestamp parsing failed
                df = df.dropna(subset=['timestamp'])
            
            # Fix swapped columns: severity and pid are swapped in CSV
            if 'severity' in df.columns and 'pid' in df.columns:
                # Check if severity column contains numbers (indicating it's actually PID)
                if df['severity'].dtype in ['int64', 'float64'] or df['severity'].astype(str).str.isdigit().any():
                    # Swap the columns
                    df['severity'], df['pid'] = df['pid'], df['severity']
            
            df = df.sort_values('timestamp', ascending=False)
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

def load_log_data(log_file="netsnoop_persistent.txt"):
    """Load system log data"""
    try:
        if not os.path.exists(log_file):
            return []
        
        logs = []
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Get last 100 lines for recent activity
            for line in lines[-100:]:
                line = line.strip()
                if line and not line.startswith('='):
                    logs.append(line)
        
        return logs
    except Exception as e:
        st.error(f"Error loading log data: {e}")
        return []

def create_severity_color_map():
    """Create color mapping for severity levels"""
    return {
        'CRITICAL': '#f44336',
        'HIGH': '#ff9800', 
        'MEDIUM': '#ffc107',
        'LOW': '#4caf50',
        'EXTREME': '#9c27b0',
        'EMERGENCY': '#d32f2f'
    }

def display_metrics(df):
    """Display key metrics"""
    if df.empty:
        st.warning("No anomaly data available")
        return
    
    # Calculate metrics
    total_anomalies = len(df)
    
    # Recent activity (last hour)
    current_time = datetime.now()
    one_hour_ago = current_time - timedelta(hours=1)
    recent_anomalies = len(df[df['timestamp'] > one_hour_ago])
    
    # Critical anomalies
    critical_count = len(df[df['severity'] == 'CRITICAL'])
    
    # Most active process
    most_active_process = df['process_name'].value_counts().index[0] if not df.empty else "N/A"
    
    # Display metrics in columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🚨 Total Anomalies",
            value=total_anomalies,
            delta=f"+{recent_anomalies} (last hour)"
        )
    
    with col2:
        st.metric(
            label="🔴 Critical Alerts",
            value=critical_count,
            delta=f"{(critical_count/total_anomalies*100):.1f}%" if total_anomalies > 0 else "0%"
        )
    
    with col3:
        st.metric(
            label="⚡ Recent Activity",
            value=recent_anomalies,
            delta="Last 60 minutes"
        )
    
    with col4:
        st.metric(
            label="🎯 Most Active",
            value=most_active_process[:15] + "..." if len(most_active_process) > 15 else most_active_process
        )

def create_timeline_chart(df):
    """Create timeline chart of anomalies"""
    if df.empty:
        return None
    
    # Group by hour for timeline
    df_hourly = df.copy()
    df_hourly['hour'] = df_hourly['timestamp'].dt.floor('H')
    hourly_counts = df_hourly.groupby(['hour', 'severity']).size().reset_index(name='count')
    
    color_map = create_severity_color_map()
    
    fig = px.bar(
        hourly_counts,
        x='hour',
        y='count',
        color='severity',
        color_discrete_map=color_map,
        title="Anomaly Timeline (by Hour)",
        labels={'hour': 'Time', 'count': 'Number of Anomalies'}
    )
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Number of Anomalies",
        showlegend=True,
        height=400
    )
    
    return fig

def create_anomaly_type_chart(df):
    """Create pie chart of anomaly types"""
    if df.empty:
        return None
    
    # Extract anomaly type from reason column since we don't have anomaly_type column
    if 'reason' in df.columns:
        # Extract type from reason (e.g., "HIGH CPU: 95.0% CPU usage" -> "HIGH CPU")
        df['anomaly_type'] = df['reason'].str.extract(r'^([^:]+)')[0]
        type_counts = df['anomaly_type'].value_counts()
    else:
        # Fallback to severity if no reason column
        type_counts = df['severity'].value_counts()
    
    fig = px.pie(
        values=type_counts.values,
        names=type_counts.index,
        title="Anomaly Types Distribution"
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    
    return fig

def create_process_activity_chart(df):
    """Create bar chart of most active processes"""
    if df.empty:
        return None
    
    # Get top 10 most active processes
    process_counts = df['process_name'].value_counts().head(10)
    
    fig = px.bar(
        x=process_counts.values,
        y=process_counts.index,
        orientation='h',
        title="Top 10 Most Active Processes",
        labels={'x': 'Number of Anomalies', 'y': 'Process Name'}
    )
    
    fig.update_layout(height=400)
    
    return fig

def create_severity_timeline(df):
    """Create timeline showing severity distribution"""
    if df.empty:
        return None
    
    # Group by time and severity
    df_timeline = df.copy()
    df_timeline['hour'] = df_timeline['timestamp'].dt.floor('H')
    severity_timeline = df_timeline.groupby(['hour', 'severity']).size().unstack(fill_value=0)
    
    fig = go.Figure()
    color_map = create_severity_color_map()
    
    for severity in severity_timeline.columns:
        fig.add_trace(go.Scatter(
            x=severity_timeline.index,
            y=severity_timeline[severity],
            mode='lines+markers',
            name=severity,
            line=dict(color=color_map.get(severity, '#999999')),
            stackgroup='one'
        ))
    
    fig.update_layout(
        title="Severity Distribution Over Time",
        xaxis_title="Time",
        yaxis_title="Number of Anomalies",
        height=400
    )
    
    return fig

def display_recent_alerts(df, limit=10):
    """Display recent alerts table"""
    if df.empty:
        st.info("No recent alerts")
        return
    
    st.subheader("🚨 Recent Alerts")
    
    # Get recent alerts - adjust column names to match CSV structure
    columns_to_show = ['timestamp', 'severity', 'process_name', 'reason', 'pid']
    available_columns = [col for col in columns_to_show if col in df.columns]
    
    if not available_columns:
        st.warning("No compatible data columns found")
        return
    
    recent_df = df.head(limit)[available_columns]
    
    # Format the dataframe for display
    for idx, row in recent_df.iterrows():
        severity = str(row.get('severity', 'UNKNOWN')).upper()
        timestamp_str = row['timestamp'].strftime('%H:%M:%S') if pd.notna(row['timestamp']) else 'Unknown'
        process_name = str(row.get('process_name', 'Unknown'))
        reason = str(row.get('reason', 'No description available'))
        pid = str(row.get('pid', 'N/A'))
        
        # Enhanced alert styling with more visual impact
        if severity == 'CRITICAL':
            st.markdown(f"""
            <div class="critical-alert">
                <div class="alert-header">
                    🚨 <span style="color: #d32f2f; font-weight: bold;">CRITICAL ALERT</span> | {timestamp_str} | PID: {pid}
                </div>
                <div style="font-weight: bold; margin: 0.5rem 0;">Process: {process_name}</div>
                <div class="alert-details">{reason}</div>
            </div>
            """, unsafe_allow_html=True)
        elif severity == 'EXTREME':
            st.markdown(f"""
            <div class="extreme-alert">
                <div class="alert-header">
                    💥 <span style="color: #9c27b0; font-weight: bold;">EXTREME ALERT</span> | {timestamp_str} | PID: {pid}
                </div>
                <div style="font-weight: bold; margin: 0.5rem 0;">Process: {process_name}</div>
                <div class="alert-details">{reason}</div>
            </div>
            """, unsafe_allow_html=True)
        elif severity == 'HIGH':
            st.markdown(f"""
            <div class="high-alert">
                <div class="alert-header">
                    🔥 <span style="color: #f57c00; font-weight: bold;">HIGH ALERT</span> | {timestamp_str} | PID: {pid}
                </div>
                <div style="font-weight: bold; margin: 0.5rem 0;">Process: {process_name}</div>
                <div class="alert-details">{reason}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="medium-alert">
                <div class="alert-header">
                    ⚠️ <span style="color: #f9a825; font-weight: bold;">{severity} ALERT</span> | {timestamp_str} | PID: {pid}
                </div>
                <div style="font-weight: bold; margin: 0.5rem 0;">Process: {process_name}</div>
                <div class="alert-details">{reason}</div>
            </div>
            """, unsafe_allow_html=True)

def main():
    """Main dashboard application"""
    
    # Header
    st.title("🖥️ NetSnoop")
    st.markdown("             'Born to Track'")
    st.markdown("Real-time monitoring of system anomalies and process activities")
    
    # Sidebar
    st.sidebar.title("⚙️ Dashboard Controls")
    
    # Auto-refresh option
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=True)
    
    # File selection
    csv_file = st.sidebar.text_input("Anomalies CSV File", value="anomalies.csv")
    log_file = st.sidebar.text_input("Log File", value="netsnoop_persistent.txt")
    
    # Time range filter
    time_range = st.sidebar.selectbox(
        "Time Range",
        options=["Last Hour", "Last 6 Hours", "Last 24 Hours", "All Time"]
    )
    
    # Load data
    df = load_anomaly_data(csv_file)
    
    # Apply time filter
    if not df.empty and time_range != "All Time":
        current_time = datetime.now()
        if time_range == "Last Hour":
            cutoff_time = current_time - timedelta(hours=1)
        elif time_range == "Last 6 Hours":
            cutoff_time = current_time - timedelta(hours=6)
        elif time_range == "Last 24 Hours":
            cutoff_time = current_time - timedelta(hours=24)
        
        df = df[df['timestamp'] > cutoff_time]
    
    # Status indicator
    if df.empty:
        st.info("🟡 No data available - Make sure your monitoring script is running")
    else:
        last_update = df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        st.success(f"🟢 Live Data | Last Update: {last_update}")
    
    # Display metrics
    display_metrics(df)
    
    # Main content area
    if not df.empty:
        # Charts section
        st.header("📊 Analytics")
        
        # First row of charts
        col1, col2 = st.columns(2)
        
        with col1:
            timeline_fig = create_timeline_chart(df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
        
        with col2:
            type_fig = create_anomaly_type_chart(df)
            if type_fig:
                st.plotly_chart(type_fig, use_container_width=True)
        
        # Second row of charts
        col3, col4 = st.columns(2)
        
        with col3:
            process_fig = create_process_activity_chart(df)
            if process_fig:
                st.plotly_chart(process_fig, use_container_width=True)
        
        with col4:
            severity_fig = create_severity_timeline(df)
            if severity_fig:
                st.plotly_chart(severity_fig, use_container_width=True)
    
    # Recent alerts
    display_recent_alerts(df)
    
    # Detailed data table
    if not df.empty:
        with st.expander("📋 Detailed Anomaly Data"):
            st.dataframe(df, use_container_width=True)
    
    # System logs
    with st.expander("📜 Recent System Logs"):
        logs = load_log_data(log_file)
        if logs:
            for log in logs[-20:]:  # Show last 20 log entries
                st.text(log)
        else:
            st.info("No log data available")
    
    # Auto refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()

if __name__ == "__main__":
    main()