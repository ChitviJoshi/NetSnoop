#!/usr/bin/env python3
"""
NetSnoop Enhanced Dashboard - Simplified Version
Uses CSV files instead of database (easier!)
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from pathlib import Path
import csv
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


# ============================================================================
# DATA ACCESS LAYER (Repository Pattern)
# ============================================================================

class Repository(ABC):
    """Abstract repository for data access"""
    
    @abstractmethod
    def get_all_alerts(self, limit: int = 100) -> List[Dict]:
        pass
    
    @abstractmethod
    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        pass
    
    @abstractmethod
    def get_alert_statistics(self) -> Dict[str, Any]:
        pass


class CSVRepository(Repository):
    """CSV implementation of repository - EASIER THAN DATABASE!"""
    
    def __init__(self, csv_path: str = "alerts.csv"):
        self._csv_path = Path(csv_path)
        self._ensure_csv_exists()
    
    def _ensure_csv_exists(self):
        """Ensure CSV file exists"""
        if not self._csv_path.exists():
            st.warning(f"CSV file not found: {self._csv_path}")
            st.info("Make sure the monitor is running to generate alerts!")
    
    def get_all_alerts(self, limit: int = 100) -> List[Dict]:
        """Get all alerts from CSV"""
        try:
            if not self._csv_path.exists():
                return []
            
            # Read CSV file
            with open(self._csv_path, 'r') as f:
                reader = csv.DictReader(f)
                alerts = list(reader)
            
            # Return most recent alerts
            return alerts[-limit:] if len(alerts) > limit else alerts
        
        except Exception as e:
            st.error(f"Error reading CSV: {e}")
            return []
    
    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        """Get alerts by severity from CSV"""
        try:
            all_alerts = self.get_all_alerts(limit=10000)
            return [a for a in all_alerts if a.get('severity') == severity]
        except Exception as e:
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics from CSV"""
        try:
            if not self._csv_path.exists():
                return {
                    'total': 0,
                    'by_severity': {},
                    'by_type': {},
                    'recent_count': 0
                }
            
            # Read all alerts
            all_alerts = self.get_all_alerts(limit=10000)
            
            total = len(all_alerts)
            
            # Count by severity
            by_severity = {}
            for alert in all_alerts:
                severity = alert.get('severity', 'UNKNOWN')
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by monitor type
            by_type = {}
            for alert in all_alerts:
                mtype = alert.get('monitor_type', 'UNKNOWN')
                by_type[mtype] = by_type.get(mtype, 0) + 1
            
            # Count recent (last hour)
            recent_count = 0
            one_hour_ago = datetime.now() - timedelta(hours=1)
            
            for alert in all_alerts:
                try:
                    alert_time = datetime.fromisoformat(alert['timestamp'])
                    if alert_time > one_hour_ago:
                        recent_count += 1
                except:
                    pass
            
            return {
                'total': total,
                'by_severity': by_severity,
                'by_type': by_type,
                'recent_count': recent_count
            }
        
        except Exception as e:
            st.error(f"Error getting statistics: {e}")
            return {
                'total': 0,
                'by_severity': {},
                'by_type': {},
                'recent_count': 0
            }


# ============================================================================
# PRESENTATION LAYER (View Models)
# ============================================================================

class ViewModel(ABC):
    """Abstract view model"""
    
    @abstractmethod
    def prepare_data(self) -> Any:
        pass


class AlertViewModel(ViewModel):
    """View model for alerts"""
    
    def __init__(self, alerts: List[Dict]):
        self._alerts = alerts
    
    def prepare_data(self) -> pd.DataFrame:
        """Prepare alert data for display"""
        if not self._alerts:
            return pd.DataFrame()
        
        df = pd.DataFrame(self._alerts)
        
        # Convert timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp', ascending=False)
        
        return df
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count by severity"""
        if not self._alerts:
            return {}
        
        df = self.prepare_data()
        return df['severity'].value_counts().to_dict()
    
    def get_top_processes(self, limit: int = 10) -> Dict[str, int]:
        """Get top processes by alert count"""
        if not self._alerts:
            return {}
        
        df = self.prepare_data()
        return df['process_name'].value_counts().head(limit).to_dict()


class StatisticsViewModel(ViewModel):
    """View model for statistics"""
    
    def __init__(self, stats: Dict[str, Any]):
        self._stats = stats
    
    def prepare_data(self) -> Dict[str, Any]:
        """Prepare statistics data"""
        return {
            'total_alerts': self._stats.get('total', 0),
            'recent_alerts': self._stats.get('recent_count', 0),
            'critical_count': self._stats.get('by_severity', {}).get('CRITICAL', 0),
            'extreme_count': self._stats.get('by_severity', {}).get('EXTREME', 0),
            'severity_distribution': self._stats.get('by_severity', {}),
            'type_distribution': self._stats.get('by_type', {})
        }


# ============================================================================
# CHART FACTORY (Factory Pattern)
# ============================================================================

class ChartFactory:
    """Factory for creating different chart types"""
    
    @staticmethod
    def create_severity_timeline(df: pd.DataFrame) -> go.Figure:
        """Create severity timeline chart"""
        if df.empty:
            return None
        
        # Group by time bins
        df = df.copy()
        df['time_bin'] = df['timestamp'].dt.floor('5min')
        timeline = df.groupby(['time_bin', 'severity']).size().reset_index(name='count')
        
        fig = px.bar(
            timeline,
            x='time_bin',
            y='count',
            color='severity',
            title='Alert Timeline (5-minute intervals)',
            color_discrete_map={
                'HIGH': '#FFA500',
                'CRITICAL': '#FF0000',
                'EXTREME': '#8B008B',
                'MEDIUM': '#FFFF00',
                'LOW': '#90EE90'
            }
        )
        
        fig.update_layout(
            xaxis_title='Time',
            yaxis_title='Alert Count',
            height=400,
            showlegend=True
        )
        
        return fig
    
    @staticmethod
    def create_severity_pie(severity_counts: Dict[str, int]) -> go.Figure:
        """Create severity distribution pie chart"""
        if not severity_counts:
            return None
        
        fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title='Alerts by Severity Level',
            color=list(severity_counts.keys()),
            color_discrete_map={
                'HIGH': '#FFA500',
                'CRITICAL': '#FF0000',
                'EXTREME': '#8B008B',
                'MEDIUM': '#FFFF00',
                'LOW': '#90EE90'
            }
        )
        
        fig.update_traces(textposition='inside', textinfo='percent+label')
        fig.update_layout(height=400)
        
        return fig
    
    @staticmethod
    def create_process_bar(process_counts: Dict[str, int]) -> go.Figure:
        """Create top processes bar chart"""
        if not process_counts:
            return None
        
        fig = px.bar(
            x=list(process_counts.values()),
            y=list(process_counts.keys()),
            orientation='h',
            title='Top 10 Processes by Alert Count',
            labels={'x': 'Alert Count', 'y': 'Process Name'}
        )
        
        fig.update_layout(height=500)
        fig.update_traces(marker_color='#4CAF50')
        
        return fig
    
    @staticmethod
    def create_monitor_type_bar(type_counts: Dict[str, int]) -> go.Figure:
        """Create monitor type distribution"""
        if not type_counts:
            return None
        
        fig = px.bar(
            x=list(type_counts.keys()),
            y=list(type_counts.values()),
            title='Alerts by Monitor Type',
            labels={'x': 'Monitor Type', 'y': 'Alert Count'}
        )
        
        fig.update_layout(height=400)
        fig.update_traces(marker_color='#2196F3')
        
        return fig


# ============================================================================
# UI COMPONENTS (Component Pattern)
# ============================================================================

class UIComponent(ABC):
    """Abstract UI component"""
    
    @abstractmethod
    def render(self):
        pass


class HeaderComponent(UIComponent):
    """Header component"""
    
    def __init__(self, title: str, subtitle: str):
        self._title = title
        self._subtitle = subtitle
    
    def render(self):
        """Render header"""
        st.title(self._title)
        st.markdown(f"**{self._subtitle}**")
        st.markdown("---")


class MetricsComponent(UIComponent):
    """Metrics display component"""
    
    def __init__(self, stats_vm: StatisticsViewModel):
        self._stats_vm = stats_vm
    
    def render(self):
        """Render metrics"""
        stats = self._stats_vm.prepare_data()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="📊 Total Alerts",
                value=stats['total_alerts']
            )
        
        with col2:
            st.metric(
                label="🕐 Recent (1h)",
                value=stats['recent_alerts'],
                delta="Active" if stats['recent_alerts'] > 0 else "Quiet"
            )
        
        with col3:
            st.metric(
                label="🔴 Critical",
                value=stats['critical_count'],
                delta="⚠️" if stats['critical_count'] > 0 else "✅"
            )
        
        with col4:
            st.metric(
                label="💀 Extreme",
                value=stats['extreme_count'],
                delta="🚨" if stats['extreme_count'] > 0 else "✅"
            )


class ChartGridComponent(UIComponent):
    """Chart grid component"""
    
    def __init__(self, alert_vm: AlertViewModel, stats_vm: StatisticsViewModel):
        self._alert_vm = alert_vm
        self._stats_vm = stats_vm
    
    def render(self):
        """Render chart grid"""
        st.markdown("### 📊 Visual Analytics")
        
        df = self._alert_vm.prepare_data()
        stats = self._stats_vm.prepare_data()
        
        # Row 1: Timeline and Severity Pie
        col1, col2 = st.columns(2)
        
        with col1:
            timeline_fig = ChartFactory.create_severity_timeline(df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
        
        with col2:
            severity_counts = self._alert_vm.get_severity_counts()
            pie_fig = ChartFactory.create_severity_pie(severity_counts)
            if pie_fig:
                st.plotly_chart(pie_fig, use_container_width=True)
        
        # Row 2: Process Bar and Monitor Type Bar
        col3, col4 = st.columns(2)
        
        with col3:
            process_counts = self._alert_vm.get_top_processes()
            process_fig = ChartFactory.create_process_bar(process_counts)
            if process_fig:
                st.plotly_chart(process_fig, use_container_width=True)
        
        with col4:
            type_fig = ChartFactory.create_monitor_type_bar(stats['type_distribution'])
            if type_fig:
                st.plotly_chart(type_fig, use_container_width=True)


class AlertTableComponent(UIComponent):
    """Alert table component"""
    
    def __init__(self, alert_vm: AlertViewModel, limit: int = 50):
        self._alert_vm = alert_vm
        self._limit = limit
    
    def render(self):
        """Render alert table"""
        st.markdown("### 🚨 Recent Alerts")
        
        df = self._alert_vm.prepare_data()
        
        if df.empty:
            st.info("No alerts found. Monitor may not be running.")
            return
        
        # Display columns
        display_df = df[['timestamp', 'severity', 'monitor_type', 
                        'process_name', 'pid', 'value', 'unit']].head(self._limit)
        
        # Style by severity
        def style_severity(row):
            colors = {
                'EXTREME': 'background-color: #8B008B; color: white',
                'CRITICAL': 'background-color: #FF0000; color: white',
                'HIGH': 'background-color: #FFA500; color: black',
                'MEDIUM': 'background-color: #FFFF00; color: black',
                'LOW': 'background-color: #90EE90; color: black'
            }
            return [colors.get(row['severity'], '')] * len(row)
        
        styled_df = display_df.style.apply(style_severity, axis=1)
        
        st.dataframe(styled_df, use_container_width=True, height=500)


class SidebarComponent(UIComponent):
    """Sidebar component"""
    
    def __init__(self, repository: Repository):
        self._repository = repository
    
    def render(self):
        """Render sidebar"""
        with st.sidebar:
            st.header("⚙️ Dashboard Controls")
            
            # Refresh button
            if st.button("🔄 Refresh Data", use_container_width=True, type="primary"):
                st.rerun()
            
            st.markdown("---")
            
            # Auto-refresh
            auto_refresh = st.checkbox("🔁 Auto-refresh", value=False)
            if auto_refresh:
                refresh_interval = st.slider("Refresh interval (seconds)", 10, 60, 30)
                time.sleep(refresh_interval)
                st.rerun()
            
            st.markdown("---")
            
            # Filter options
            st.subheader("🔍 Filters")
            
            severity_filter = st.multiselect(
                "Severity Level",
                options=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'EXTREME'],
                default=['HIGH', 'CRITICAL', 'EXTREME']
            )
            
            st.markdown("---")
            
            # Statistics
            st.subheader("📈 Quick Stats")
            stats = self._repository.get_alert_statistics()
            
            st.write(f"**Total Alerts:** {stats['total']}")
            
            if stats['by_severity']:
                st.write("**By Severity:**")
                for severity, count in sorted(stats['by_severity'].items()):
                    st.write(f"  • {severity}: {count}")
            
            st.markdown("---")
            
            # About
            st.subheader("ℹ️ About")
            st.write("**NetSnoop Monitor**")
            st.write("Version: 3.0 Enhanced")
            st.write("Architecture: Advanced OOP")
            st.write("Classes: 20+")
            st.write("Patterns: 10+")


# ============================================================================
# DASHBOARD CONTROLLER (MVC Pattern)
# ============================================================================

class DashboardController:
    """Controller for dashboard (MVC pattern)"""
    
    def __init__(self, repository: Repository):
        self._repository = repository
        self._setup_page()
    
    def _setup_page(self):
        """Setup Streamlit page configuration"""
        st.set_page_config(
            page_title="NetSnoop Enhanced Dashboard",
            page_icon="🖥️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
    
    def run(self):
        """Run dashboard"""
        try:
            # Fetch data
            alerts = self._repository.get_all_alerts(limit=500)
            stats = self._repository.get_alert_statistics()
            
            # Create view models
            alert_vm = AlertViewModel(alerts)
            stats_vm = StatisticsViewModel(stats)
            
            # Render components
            HeaderComponent(
                "🖥️ NetSnoop Enhanced System Monitor",
                "Real-Time Process Monitoring & Anomaly Detection Dashboard"
            ).render()
            
            SidebarComponent(self._repository).render()
            
            MetricsComponent(stats_vm).render()
            
            st.markdown("---")
            
            ChartGridComponent(alert_vm, stats_vm).render()
            
            st.markdown("---")
            
            AlertTableComponent(alert_vm, limit=50).render()
        
        except Exception as e:
            st.error(f"Dashboard Error: {e}")
            st.exception(e)


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

class DashboardApplication:
    """Main dashboard application"""
    
    def __init__(self, csv_path: str = "alerts.csv"):
        self._repository = CSVRepository(csv_path)  # CSV instead of database!
        self._controller = DashboardController(self._repository)
    
    def run(self):
        """Run application"""
        self._controller.run()


def main():
    """Main entry point"""
    st.markdown("""
    <style>
    .info-box {
        background-color: #e7f3ff;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 20px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Show helpful info
    if not Path("alerts.csv").exists():
        st.info("📝 No alerts.csv file found. Make sure to run simple_monitor.py first!")
    
    app = DashboardApplication(csv_path="alerts.csv")
    app.run()


if __name__ == "__main__":
    main()