"""
Data Visualization Module
Creates visualizations for network traffic analysis and anomaly detection
"""

import logging
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
from typing import Dict, List, Optional, Tuple
import matplotlib.dates as mdates
from matplotlib.backends.backend_agg import FigureCanvasAgg
import io
import base64

class TrafficVisualizer:
    """Network traffic visualization and analysis"""
    
    def __init__(self, output_dir='visualizations'):
        """
        Initialize traffic visualizer
        
        Args:
            output_dir: Directory to save visualizations
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        self.figures = {}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Set matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        self.logger.info("Traffic visualizer initialized")
    
    def create_traffic_overview(self, packets_df, save_path=None):
        """
        Create comprehensive traffic overview visualization
        
        Args:
            packets_df: DataFrame with packet data
            save_path: Optional path to save the figure
            
        Returns:
            matplotlib.figure.Figure: Created figure
        """
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Network Traffic Overview', fontsize=16, fontweight='bold')
            
            # 1. Protocol distribution
            self._plot_protocol_distribution(packets_df, axes[0, 0])
            
            # 2. Traffic over time
            self._plot_traffic_over_time(packets_df, axes[0, 1])
            
            # 3. Top source IPs
            self._plot_top_ips(packets_df, axes[1, 0], 'src_ip', 'Top Source IPs')
            
            # 4. Top destination IPs
            self._plot_top_ips(packets_df, axes[1, 1], 'dst_ip', 'Top Destination IPs')
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"Traffic overview saved to {save_path}")
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating traffic overview: {str(e)}")
            return None
    
    def create_anomaly_visualization(self, features_df, anomaly_results, save_path=None):
        """
        Create anomaly detection visualization
        
        Args:
            features_df: DataFrame with features
            anomaly_results: Anomaly detection results
            save_path: Optional path to save the figure
            
        Returns:
            matplotlib.figure.Figure: Created figure
        """
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Anomaly Detection Analysis', fontsize=16, fontweight='bold')
            
            # 1. Anomaly distribution
            self._plot_anomaly_distribution(anomaly_results, axes[0, 0])
            
            # 2. Anomaly scores distribution
            self._plot_anomaly_scores(anomaly_results, axes[0, 1])
            
            # 3. Feature correlation with anomalies
            self._plot_feature_correlation(features_df, anomaly_results, axes[1, 0])
            
            # 4. Anomaly timeline
            self._plot_anomaly_timeline(features_df, anomaly_results, axes[1, 1])
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"Anomaly visualization saved to {save_path}")
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating anomaly visualization: {str(e)}")
            return None
    
    def create_port_analysis(self, packets_df, save_path=None):
        """
        Create port analysis visualization
        
        Args:
            packets_df: DataFrame with packet data
            save_path: Optional path to save the figure
            
        Returns:
            matplotlib.figure.Figure: Created figure
        """
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Port Analysis', fontsize=16, fontweight='bold')
            
            # 1. Source ports distribution
            self._plot_port_distribution(packets_df, axes[0, 0], 'src_port', 'Source Ports')
            
            # 2. Destination ports distribution
            self._plot_port_distribution(packets_df, axes[0, 1], 'dst_port', 'Destination Ports')
            
            # 3. Port usage heatmap
            self._plot_port_heatmap(packets_df, axes[1, 0])
            
            # 4. Well-known ports analysis
            self._plot_well_known_ports(packets_df, axes[1, 1])
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"Port analysis saved to {save_path}")
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating port analysis: {str(e)}")
            return None
    
    def create_security_dashboard(self, packets_df, alerts_df, save_path=None):
        """
        Create security dashboard visualization
        
        Args:
            packets_df: DataFrame with packet data
            alerts_df: DataFrame with alert data
            save_path: Optional path to save the figure
            
        Returns:
            matplotlib.figure.Figure: Created figure
        """
        try:
            fig, axes = plt.subplots(2, 3, figsize=(18, 12))
            fig.suptitle('Security Dashboard', fontsize=16, fontweight='bold')
            
            # 1. Alert severity distribution
            self._plot_alert_severity(alerts_df, axes[0, 0])
            
            # 2. Alert timeline
            self._plot_alert_timeline(alerts_df, axes[0, 1])
            
            # 3. Top attacking IPs
            self._plot_attacking_ips(alerts_df, axes[0, 2])
            
            # 4. Protocol vs Alert type
            self._plot_protocol_alerts(alerts_df, axes[1, 0])
            
            # 5. Geographic distribution (if IP geolocation available)
            self._plot_geographic_distribution(packets_df, axes[1, 1])
            
            # 6. Traffic vs Alerts correlation
            self._plot_traffic_alerts_correlation(packets_df, alerts_df, axes[1, 2])
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"Security dashboard saved to {save_path}")
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating security dashboard: {str(e)}")
            return None
    
    def _plot_protocol_distribution(self, packets_df, ax):
        """Plot protocol distribution"""
        if 'protocol' not in packets_df.columns:
            ax.text(0.5, 0.5, 'No protocol data', ha='center', va='center')
            return
        
        protocol_counts = packets_df['protocol'].value_counts()
        
        if not protocol_counts.empty:
            protocol_counts.plot(kind='pie', ax=ax, autopct='%1.1f%%')
            ax.set_title('Protocol Distribution')
            ax.set_ylabel('')
        else:
            ax.text(0.5, 0.5, 'No protocol data', ha='center', va='center')
    
    def _plot_traffic_over_time(self, packets_df, ax):
        """Plot traffic over time"""
        if 'timestamp' not in packets_df.columns:
            ax.text(0.5, 0.5, 'No timestamp data', ha='center', va='center')
            return
        
        try:
            # Convert timestamp to datetime if needed
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
            
            # Resample by minute
            traffic_over_time = packets_df.set_index('timestamp').resample('1T').size()
            
            if not traffic_over_time.empty:
                traffic_over_time.plot(ax=ax, marker='o', markersize=3)
                ax.set_title('Traffic Over Time')
                ax.set_xlabel('Time')
                ax.set_ylabel('Packet Count')
                ax.tick_params(axis='x', rotation=45)
            else:
                ax.text(0.5, 0.5, 'No traffic data', ha='center', va='center')
                
        except Exception as e:
            self.logger.warning(f"Error plotting traffic over time: {str(e)}")
            ax.text(0.5, 0.5, 'Error plotting data', ha='center', va='center')
    
    def _plot_top_ips(self, packets_df, ax, ip_column, title):
        """Plot top IPs"""
        if ip_column not in packets_df.columns:
            ax.text(0.5, 0.5, f'No {ip_column} data', ha='center', va='center')
            return
        
        top_ips = packets_df[ip_column].value_counts().head(10)
        
        if not top_ips.empty:
            top_ips.plot(kind='barh', ax=ax)
            ax.set_title(title)
            ax.set_xlabel('Packet Count')
        else:
            ax.text(0.5, 0.5, 'No IP data', ha='center', va='center')
    
    def _plot_anomaly_distribution(self, anomaly_results, ax):
        """Plot anomaly distribution"""
        if 'predictions' not in anomaly_results:
            ax.text(0.5, 0.5, 'No anomaly data', ha='center', va='center')
            return
        
        predictions = anomaly_results['predictions']
        normal_count = np.sum(predictions == 0)
        anomaly_count = np.sum(predictions == 1)
        
        labels = ['Normal', 'Anomaly']
        sizes = [normal_count, anomaly_count]
        colors = ['lightgreen', 'lightcoral']
        
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
        ax.set_title('Anomaly Distribution')
    
    def _plot_anomaly_scores(self, anomaly_results, ax):
        """Plot anomaly scores distribution"""
        if 'scores' not in anomaly_results:
            ax.text(0.5, 0.5, 'No score data', ha='center', va='center')
            return
        
        scores = anomaly_results['scores']
        
        ax.hist(scores, bins=30, alpha=0.7, color='skyblue', edgecolor='black')
        ax.set_title('Anomaly Scores Distribution')
        ax.set_xlabel('Anomaly Score')
        ax.set_ylabel('Frequency')
        ax.axvline(x=np.mean(scores), color='red', linestyle='--', label='Mean')
        ax.legend()
    
    def _plot_feature_correlation(self, features_df, anomaly_results, ax):
        """Plot feature correlation with anomalies"""
        if features_df.empty or 'predictions' not in anomaly_results:
            ax.text(0.5, 0.5, 'No correlation data', ha='center', va='center')
            return
        
        # Select numeric features
        numeric_features = features_df.select_dtypes(include=[np.number])
        
        if numeric_features.empty:
            ax.text(0.5, 0.5, 'No numeric features', ha='center', va='center')
            return
        
        # Limit to top 10 features
        if len(numeric_features.columns) > 10:
            numeric_features = numeric_features.iloc[:, :10]
        
        # Add anomaly predictions
        numeric_features['anomaly'] = anomaly_results['predictions']
        
        # Calculate correlation matrix
        corr_matrix = numeric_features.corr()
        
        # Plot heatmap
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0, ax=ax, fmt='.2f')
        ax.set_title('Feature Correlation with Anomalies')
    
    def _plot_anomaly_timeline(self, features_df, anomaly_results, ax):
        """Plot anomaly timeline"""
        if features_df.empty or 'predictions' not in anomaly_results:
            ax.text(0.5, 0.5, 'No timeline data', ha='center', va='center')
            return
        
        # Create timeline data
        timeline_data = pd.DataFrame({
            'index': range(len(anomaly_results['predictions'])),
            'anomaly': anomaly_results['predictions']
        })
        
        # Plot anomalies over time
        anomalies = timeline_data[timeline_data['anomaly'] == 1]
        normal = timeline_data[timeline_data['anomaly'] == 0]
        
        ax.scatter(normal['index'], [0]*len(normal), color='green', alpha=0.6, s=20, label='Normal')
        ax.scatter(anomalies['index'], [1]*len(anomalies), color='red', alpha=0.8, s=30, label='Anomaly')
        
        ax.set_title('Anomaly Timeline')
        ax.set_xlabel('Packet Index')
        ax.set_ylabel('Classification')
        ax.set_yticks([0, 1])
        ax.set_yticklabels(['Normal', 'Anomaly'])
        ax.legend()
    
    def _plot_port_distribution(self, packets_df, ax, port_column, title):
        """Plot port distribution"""
        if port_column not in packets_df.columns:
            ax.text(0.5, 0.5, f'No {port_column} data', ha='center', va='center')
            return
        
        # Filter out zero ports and get top 20
        ports = packets_df[packets_df[port_column] > 0][port_column].value_counts().head(20)
        
        if not ports.empty:
            ports.plot(kind='bar', ax=ax)
            ax.set_title(title)
            ax.set_xlabel('Port')
            ax.set_ylabel('Count')
            ax.tick_params(axis='x', rotation=45)
        else:
            ax.text(0.5, 0.5, 'No port data', ha='center', va='center')
    
    def _plot_port_heatmap(self, packets_df, ax):
        """Plot port usage heatmap"""
        if 'src_port' not in packets_df.columns or 'dst_port' not in packets_df.columns:
            ax.text(0.5, 0.5, 'No port data', ha='center', va='center')
            return
        
        # Create port pair matrix
        port_pairs = packets_df.groupby(['src_port', 'dst_port']).size().reset_index(name='count')
        port_pairs = port_pairs[port_pairs['count'] > 1]  # Filter low-frequency pairs
        
        if not port_pairs.empty:
            # Limit to top ports for visualization
            top_src_ports = port_pairs['src_port'].value_counts().head(10).index
            top_dst_ports = port_pairs['dst_port'].value_counts().head(10).index
            
            filtered_pairs = port_pairs[
                (port_pairs['src_port'].isin(top_src_ports)) & 
                (port_pairs['dst_port'].isin(top_dst_ports))
            ]
            
            if not filtered_pairs.empty:
                pivot_data = filtered_pairs.pivot(index='src_port', columns='dst_port', values='count').fillna(0)
                sns.heatmap(pivot_data, annot=True, fmt='g', cmap='YlOrRd', ax=ax)
                ax.set_title('Port Usage Heatmap (Src vs Dst)')
            else:
                ax.text(0.5, 0.5, 'No significant port pairs', ha='center', va='center')
        else:
            ax.text(0.5, 0.5, 'No port pairs found', ha='center', va='center')
    
    def _plot_well_known_ports(self, packets_df, ax):
        """Plot well-known ports analysis"""
        if 'dst_port' not in packets_df.columns:
            ax.text(0.5, 0.5, 'No port data', ha='center', va='center')
            return
        
        # Define well-known ports
        well_known_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3389: 'RDP'
        }
        
        # Count connections to well-known ports
        port_counts = {}
        for port, service in well_known_ports.items():
            count = len(packets_df[packets_df['dst_port'] == port])
            if count > 0:
                port_counts[f'{port} ({service})'] = count
        
        if port_counts:
            ports_df = pd.DataFrame(list(port_counts.items()), columns=['Port_Service', 'Count'])
            ports_df.plot(x='Port_Service', y='Count', kind='bar', ax=ax, legend=False)
            ax.set_title('Well-Known Ports Usage')
            ax.set_xlabel('Port (Service)')
            ax.set_ylabel('Connection Count')
            ax.tick_params(axis='x', rotation=45)
        else:
            ax.text(0.5, 0.5, 'No well-known port usage', ha='center', va='center')
    
    def _plot_alert_severity(self, alerts_df, ax):
        """Plot alert severity distribution"""
        if alerts_df.empty or 'severity' not in alerts_df.columns:
            ax.text(0.5, 0.5, 'No alert data', ha='center', va='center')
            return
        
        severity_counts = alerts_df['severity'].value_counts()
        
        if not severity_counts.empty:
            colors = {'low': 'yellow', 'medium': 'orange', 'high': 'red'}
            severity_counts.plot(kind='pie', ax=ax, autopct='%1.1f%%', 
                               colors=[colors.get(sev, 'gray') for sev in severity_counts.index])
            ax.set_title('Alert Severity Distribution')
            ax.set_ylabel('')
        else:
            ax.text(0.5, 0.5, 'No severity data', ha='center', va='center')
    
    def _plot_alert_timeline(self, alerts_df, ax):
        """Plot alert timeline"""
        if alerts_df.empty or 'timestamp' not in alerts_df.columns:
            ax.text(0.5, 0.5, 'No alert timeline data', ha='center', va='center')
            return
        
        try:
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
            timeline = alerts_df.set_index('timestamp').resample('1T').size()
            
            if not timeline.empty:
                timeline.plot(ax=ax, marker='o', color='red', alpha=0.7)
                ax.set_title('Alert Timeline')
                ax.set_xlabel('Time')
                ax.set_ylabel('Alert Count')
                ax.tick_params(axis='x', rotation=45)
            else:
                ax.text(0.5, 0.5, 'No timeline data', ha='center', va='center')
                
        except Exception as e:
            self.logger.warning(f"Error plotting alert timeline: {str(e)}")
            ax.text(0.5, 0.5, 'Error plotting timeline', ha='center', va='center')
    
    def _plot_attacking_ips(self, alerts_df, ax):
        """Plot top attacking IPs"""
        if alerts_df.empty:
            ax.text(0.5, 0.5, 'No alert data', ha='center', va='center')
            return
        
        # Extract source IPs from packet_info if available
        src_ips = []
        for _, alert in alerts_df.iterrows():
            packet_info = alert.get('packet_info', {})
            if isinstance(packet_info, dict) and 'src_ip' in packet_info:
                src_ips.append(packet_info['src_ip'])
        
        if src_ips:
            ip_counts = pd.Series(src_ips).value_counts().head(10)
            ip_counts.plot(kind='barh', ax=ax)
            ax.set_title('Top Attacking IPs')
            ax.set_xlabel('Alert Count')
        else:
            ax.text(0.5, 0.5, 'No IP data in alerts', ha='center', va='center')
    
    def _plot_protocol_alerts(self, alerts_df, ax):
        """Plot protocol vs alert type"""
        if alerts_df.empty:
            ax.text(0.5, 0.5, 'No alert data', ax.text(0.5, 0.5, 'No alert data', ha='center', va='center')
            return
        
        # Extract protocol information
        protocols = []
        alert_types = []
        
        for _, alert in alerts_df.iterrows():
            packet_info = alert.get('packet_info', {})
            if isinstance(packet_info, dict):
                protocol = packet_info.get('protocol', 'unknown')
                alert_type = alert.get('anomaly_type', 'unknown')
                protocols.append(protocol)
                alert_types.append(alert_type)
        
        if protocols and alert_types:
            protocol_alert_df = pd.DataFrame({
                'Protocol': protocols,
                'Alert_Type': alert_types
            })
            
            cross_tab = pd.crosstab(protocol_alert_df['Protocol'], protocol_alert_df['Alert_Type'])
            sns.heatmap(cross_tab, annot=True, fmt='d', cmap='Reds', ax=ax)
            ax.set_title('Protocol vs Alert Type')
        else:
            ax.text(0.5, 0.5, 'No protocol data', ha='center', va='center')
    
    def _plot_geographic_distribution(self, packets_df, ax):
        """Plot geographic distribution (placeholder)"""
        ax.text(0.5, 0.5, 'Geographic visualization\nrequires IP geolocation data', 
                ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Geographic Distribution')
    
    def _plot_traffic_alerts_correlation(self, packets_df, alerts_df, ax):
        """Plot traffic vs alerts correlation"""
        if packets_df.empty or alerts_df.empty:
            ax.text(0.5, 0.5, 'Insufficient data for correlation', ha='center', va='center')
            return
        
        # This would require time-based correlation
        # For now, show a placeholder
        ax.text(0.5, 0.5, 'Traffic vs Alerts\nCorrelation Analysis', 
                ha='center', va='center', transform=ax.transAxes)
        ax.set_title('Traffic vs Alerts Correlation')
    
    def save_figure_as_base64(self, fig):
        """Convert matplotlib figure to base64 string"""
        try:
            canvas = FigureCanvasAgg(fig)
            buffer = io.BytesIO()
            canvas.print_figure(buffer, format='png', dpi=100)
            buffer.seek(0)
            
            image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
            buffer.close()
            
            return image_base64
            
        except Exception as e:
            self.logger.error(f"Error converting figure to base64: {str(e)}")
            return None
    
    def create_real_time_chart(self, data, chart_type='line'):
        """
        Create a real-time chart
        
        Args:
            data: Data for the chart
            chart_type: Type of chart ('line', 'bar', 'pie')
            
        Returns:
            matplotlib.figure.Figure: Created figure
        """
        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            if chart_type == 'line':
                if isinstance(data, pd.Series):
                    data.plot(ax=ax, marker='o')
                else:
                    ax.plot(data)
                ax.set_title('Real-time Traffic Monitor')
                ax.set_xlabel('Time')
                ax.set_ylabel('Value')
                
            elif chart_type == 'bar':
                if isinstance(data, pd.Series):
                    data.plot(kind='bar', ax=ax)
                else:
                    ax.bar(range(len(data)), data)
                ax.set_title('Traffic Statistics')
                ax.set_xlabel('Category')
                ax.set_ylabel('Count')
                
            elif chart_type == 'pie':
                if isinstance(data, pd.Series):
                    data.plot(kind='pie', ax=ax, autopct='%1.1f%%')
                else:
                    ax.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
                ax.set_title('Distribution')
                ax.set_ylabel('')
            
            plt.tight_layout()
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating real-time chart: {str(e)}")
            return None
    
    def close_all_figures(self):
        """Close all matplotlib figures to free memory"""
        plt.close('all')
        self.logger.info("All figures closed")
    
    def get_available_visualizations(self):
        """Get list of available visualization types"""
        return [
            'traffic_overview',
            'anomaly_analysis',
            'port_analysis',
            'security_dashboard',
            'real_time_charts'
        ]