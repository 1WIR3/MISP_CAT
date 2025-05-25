import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
import numpy as np
from datetime import datetime, timedelta
import json
from typing import Dict, List, Tuple, Set
import warnings
warnings.filterwarnings('ignore')

class MISPCorrelationAnalyzer:
    def __init__(self, correlation_data=None):
        """
        Initialize the MISP Correlation Analyzer
        
        Args:
            correlation_data: List of correlation objects or pandas DataFrame
        """
        self.correlations = []
        self.graph = nx.Graph()
        self.df = None
        
        if correlation_data:
            self.load_data(correlation_data)
    
    def load_data(self, data):
        """Load correlation data from various formats"""
        if isinstance(data, pd.DataFrame):
            self.df = data
        elif isinstance(data, list):
            # Assume list of correlation dictionaries
            self.df = pd.DataFrame(data)
        else:
            raise ValueError("Data must be pandas DataFrame or list of dictionaries")
        
        self._build_graph()
    
    def load_from_misp_export(self, json_file):
        """Load data from MISP JSON export"""
        with open(json_file, 'r') as f:
            misp_data = json.load(f)
        
        correlations = []
        
        # Handle different MISP JSON export formats
        events_data = []
        if isinstance(misp_data, dict):
            if 'response' in misp_data:
                events_data = misp_data['response']
            elif 'Event' in misp_data:
                events_data = [misp_data]  # Single event
            else:
                events_data = [misp_data]
        elif isinstance(misp_data, list):
            events_data = misp_data
        
        for event_data in events_data:
            event = event_data.get('Event', event_data)
            event_id = event.get('id')
            event_info = event.get('info', '')
            event_date = event.get('date', '')
            
            # Process attributes and their correlations
            attributes = event.get('Attribute', [])
            for attr in attributes:
                attr_id = attr.get('id')
                attr_value = attr.get('value')
                attr_type = attr.get('type')
                attr_category = attr.get('category')
                attr_timestamp = attr.get('timestamp')
                
                # Check for related attributes (correlations)
                if 'RelatedAttribute' in attr:
                    for related in attr['RelatedAttribute']:
                        for rel_attr in related.get('Attribute', []):
                            correlations.append({
                                'source_event_id': event_id,
                                'source_event_info': event_info,
                                'source_event_date': event_date,
                                'source_attribute_id': attr_id,
                                'source_value': attr_value,
                                'source_type': attr_type,
                                'source_category': attr_category,
                                'source_timestamp': attr_timestamp,
                                'target_event_id': rel_attr.get('event_id'),
                                'target_attribute_id': rel_attr.get('id'),
                                'target_value': rel_attr.get('value'),
                                'target_type': rel_attr.get('type'),
                                'target_category': rel_attr.get('category'),
                                'correlation_type': 'related_attribute',
                                'timestamp': attr_timestamp
                            })
                
                # Check for shadow attributes (proposals)
                if 'ShadowAttribute' in attr:
                    for shadow in attr['ShadowAttribute']:
                        correlations.append({
                            'source_event_id': event_id,
                            'source_event_info': event_info,
                            'source_event_date': event_date,
                            'source_attribute_id': attr_id,
                            'source_value': attr_value,
                            'source_type': attr_type,
                            'source_category': attr_category,
                            'source_timestamp': attr_timestamp,
                            'target_event_id': shadow.get('event_id'),
                            'target_value': shadow.get('value'),
                            'target_type': shadow.get('type'),
                            'target_category': shadow.get('category'),
                            'correlation_type': 'shadow_attribute',
                            'timestamp': attr_timestamp
                        })
        
        # Also extract object-level correlations
        for event_data in events_data:
            event = event_data.get('Event', event_data)
            event_id = event.get('id')
            
            # Process objects
            for obj in event.get('Object', []):
                obj_name = obj.get('name')
                for attr in obj.get('Attribute', []):
                    attr_value = attr.get('value')
                    attr_type = attr.get('type')
                    
                    if 'RelatedAttribute' in attr:
                        for related in attr['RelatedAttribute']:
                            for rel_attr in related.get('Attribute', []):
                                correlations.append({
                                    'source_event_id': event_id,
                                    'source_value': attr_value,
                                    'source_type': attr_type,
                                    'source_object': obj_name,
                                    'target_event_id': rel_attr.get('event_id'),
                                    'target_value': rel_attr.get('value'),
                                    'target_type': rel_attr.get('type'),
                                    'correlation_type': 'object_attribute',
                                    'timestamp': attr.get('timestamp')
                                })
        
        if not correlations:
            print("Warning: No correlations found in MISP export. This could mean:")
            print("1. No correlations exist in the exported data")
            print("2. Export doesn't include correlation data")
            print("3. Different MISP export format than expected")
            
            # Create basic correlations from co-occurrence in same events
            correlations = self._create_cooccurrence_correlations(events_data)
        
        self.df = pd.DataFrame(correlations)
        if not self.df.empty:
            print(f"Loaded {len(self.df)} correlations from MISP export")
        self._build_graph()
    
    def _create_cooccurrence_correlations(self, events_data):
        """Create correlations based on co-occurrence of attributes in same events"""
        correlations = []
        
        for event_data in events_data:
            event = event_data.get('Event', event_data)
            event_id = event.get('id')
            
            # Get all attributes from this event
            attributes = []
            for attr in event.get('Attribute', []):
                if attr.get('value') and attr.get('type'):
                    attributes.append({
                        'id': attr.get('id'),
                        'value': attr.get('value'),
                        'type': attr.get('type'),
                        'category': attr.get('category'),
                        'timestamp': attr.get('timestamp')
                    })
            
            # Create correlations between all pairs of attributes in the same event
            for i, attr1 in enumerate(attributes):
                for attr2 in attributes[i+1:]:
                    correlations.append({
                        'source_event_id': event_id,
                        'source_attribute_id': attr1['id'],
                        'source_value': attr1['value'],
                        'source_type': attr1['type'],
                        'source_category': attr1['category'],
                        'target_event_id': event_id,
                        'target_attribute_id': attr2['id'],
                        'target_value': attr2['value'],
                        'target_type': attr2['type'],
                        'target_category': attr2['category'],
                        'correlation_type': 'co_occurrence',
                        'timestamp': attr1['timestamp']
                    })
        
        return correlations
    
    def _build_graph(self):
        """Build NetworkX graph from correlation data"""
        self.graph = nx.Graph()
        
        for _, row in self.df.iterrows():
            source = f"{row.get('source_type', 'unknown')}:{row.get('source_value', 'unknown')}"
            target = f"{row.get('target_type', 'unknown')}:{row.get('target_value', 'unknown')}"
            
            self.graph.add_edge(source, target, 
                              weight=1,
                              correlation_type=row.get('correlation_type', 'unknown'),
                              source_event=row.get('source_event'),
                              target_event=row.get('target_event'))
    
    def analyze_correlation_patterns(self):
        """Analyze correlation patterns and return insights"""
        if self.df is None or self.df.empty:
            return "No data loaded"
        
        patterns = {
            'total_correlations': len(self.df),
            'unique_sources': self.df['source_value'].nunique() if 'source_value' in self.df else 0,
            'unique_targets': self.df['target_value'].nunique() if 'target_value' in self.df else 0,
            'correlation_types': self.df['correlation_type'].value_counts().to_dict() if 'correlation_type' in self.df else {},
            'source_types': self.df['source_type'].value_counts().to_dict() if 'source_type' in self.df else {},
            'target_types': self.df['target_type'].value_counts().to_dict() if 'target_type' in self.df else {}
        }
        
        return patterns
    
    def find_correlation_clusters(self, min_cluster_size=3):
        """Find clusters of highly correlated IOCs"""
        if self.graph.number_of_nodes() == 0:
            return []
        
        # Find connected components
        components = list(nx.connected_components(self.graph))
        clusters = [comp for comp in components if len(comp) >= min_cluster_size]
        
        cluster_info = []
        for i, cluster in enumerate(clusters):
            subgraph = self.graph.subgraph(cluster)
            cluster_info.append({
                'cluster_id': i,
                'size': len(cluster),
                'nodes': list(cluster),
                'edges': len(subgraph.edges()),
                'density': nx.density(subgraph),
                'avg_clustering': nx.average_clustering(subgraph)
            })
        
        return sorted(cluster_info, key=lambda x: x['size'], reverse=True)
    
    def identify_pivot_points(self, top_n=10):
        """Identify IOCs that serve as pivot points (high centrality)"""
        if self.graph.number_of_nodes() == 0:
            return []
        
        # Calculate various centrality measures
        degree_centrality = nx.degree_centrality(self.graph)
        betweenness_centrality = nx.betweenness_centrality(self.graph)
        eigenvector_centrality = nx.eigenvector_centrality(self.graph, max_iter=1000)
        
        pivot_points = []
        for node in self.graph.nodes():
            pivot_points.append({
                'ioc': node,
                'degree': self.graph.degree(node),
                'degree_centrality': degree_centrality[node],
                'betweenness_centrality': betweenness_centrality[node],
                'eigenvector_centrality': eigenvector_centrality[node],
                'combined_score': (degree_centrality[node] + 
                                 betweenness_centrality[node] + 
                                 eigenvector_centrality[node]) / 3
            })
        
        return sorted(pivot_points, key=lambda x: x['combined_score'], reverse=True)[:top_n]
    
    def analyze_temporal_correlations(self, timestamp_column='timestamp'):
        """Analyze how correlations evolve over time"""
        if timestamp_column not in self.df.columns:
            return "No timestamp data available"
        
        # Convert timestamps
        self.df['date'] = pd.to_datetime(self.df[timestamp_column])
        
        # Group by time periods
        daily_correlations = self.df.groupby(self.df['date'].dt.date).size()
        weekly_correlations = self.df.groupby(self.df['date'].dt.to_period('W')).size()
        
        return {
            'daily_trend': daily_correlations.to_dict(),
            'weekly_trend': weekly_correlations.to_dict(),
            'peak_day': daily_correlations.idxmax(),
            'peak_count': daily_correlations.max()
        }
    
    def generate_correlation_report(self):
        """Generate comprehensive correlation analysis report"""
        report = []
        report.append("=== MISP Correlation Analysis Report ===\n")
        
        # Basic statistics
        patterns = self.analyze_correlation_patterns()
        report.append("## Basic Statistics")
        report.append(f"Total Correlations: {patterns['total_correlations']}")
        report.append(f"Unique Source IOCs: {patterns['unique_sources']}")
        report.append(f"Unique Target IOCs: {patterns['unique_targets']}")
        report.append("")
        
        # Correlation types
        if patterns['correlation_types']:
            report.append("## Correlation Types")
            for corr_type, count in patterns['correlation_types'].items():
                report.append(f"  {corr_type}: {count}")
            report.append("")
        
        # Top pivot points
        pivots = self.identify_pivot_points(5)
        if pivots:
            report.append("## Top Pivot Points (Most Connected IOCs)")
            for i, pivot in enumerate(pivots[:5]):
                report.append(f"{i+1}. {pivot['ioc']}")
                report.append(f"   Connections: {pivot['degree']}")
                report.append(f"   Combined Centrality Score: {pivot['combined_score']:.3f}")
            report.append("")
        
        # Correlation clusters
        clusters = self.find_correlation_clusters()
        if clusters:
            report.append("## Major Correlation Clusters")
            for cluster in clusters[:3]:
                report.append(f"Cluster {cluster['cluster_id']}: {cluster['size']} IOCs")
                report.append(f"  Density: {cluster['density']:.3f}")
                report.append(f"  Sample IOCs: {', '.join(list(cluster['nodes'])[:3])}")
            report.append("")
        
        return "\n".join(report)
    
    def visualize_correlation_network(self, max_nodes=100, figsize=(15, 10)):
        """Visualize correlation network"""
        if self.graph.number_of_nodes() == 0:
            print("No graph data to visualize")
            return
        
        # Sample nodes if too many
        if self.graph.number_of_nodes() > max_nodes:
            # Get most connected nodes
            degrees = dict(self.graph.degree())
            top_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
            subgraph = self.graph.subgraph([node for node, _ in top_nodes])
        else:
            subgraph = self.graph
        
        plt.figure(figsize=figsize)
        
        # Calculate layout
        pos = nx.spring_layout(subgraph, k=1, iterations=50)
        
        # Draw network
        nx.draw_networkx_nodes(subgraph, pos, 
                              node_size=[v * 50 for v in dict(subgraph.degree()).values()],
                              node_color='lightblue', alpha=0.7)
        
        nx.draw_networkx_edges(subgraph, pos, alpha=0.5, width=0.5)
        
        # Add labels for high-degree nodes
        high_degree_nodes = {node: degree for node, degree in subgraph.degree() if degree > 2}
        labels = {node: node.split(':')[1][:10] + '...' if ':' in node else node[:10] + '...' 
                 for node in high_degree_nodes.keys()}
        
        nx.draw_networkx_labels(subgraph, pos, labels, font_size=8)
        
        plt.title("MISP Correlation Network")
        plt.axis('off')
        plt.tight_layout()
        plt.show()
    
    def export_high_priority_iocs(self, top_n=20):
        """Export high-priority IOCs based on correlation analysis"""
        pivots = self.identify_pivot_points(top_n)
        
        priority_iocs = []
        for pivot in pivots:
            ioc_parts = pivot['ioc'].split(':', 1)
            priority_iocs.append({
                'ioc_type': ioc_parts[0] if len(ioc_parts) > 1 else 'unknown',
                'ioc_value': ioc_parts[1] if len(ioc_parts) > 1 else pivot['ioc'],
                'connection_count': pivot['degree'],
                'centrality_score': pivot['combined_score'],
                'priority_rank': pivots.index(pivot) + 1
            })
        
        return pd.DataFrame(priority_iocs)

# Example usage and helper functions
def demo_analysis():
    """Demonstrate analysis with sample data"""
    # Sample correlation data
    sample_data = [
        {'source_type': 'ip-src', 'source_value': '192.168.1.100', 
         'target_type': 'domain', 'target_value': 'malicious.com', 'correlation_type': 'network'},
        {'source_type': 'domain', 'source_value': 'malicious.com', 
         'target_type': 'sha256', 'target_value': 'abc123...', 'correlation_type': 'payload'},
        {'source_type': 'ip-src', 'source_value': '192.168.1.100', 
         'target_type': 'url', 'target_value': 'http://evil.com/payload', 'correlation_type': 'network'},
        # Add more sample correlations...
    ]
    
    analyzer = MISPCorrelationAnalyzer(sample_data)
    
    print("=== Sample Analysis ===")
    print(analyzer.generate_correlation_report())
    
    # Show pivot points
    pivots = analyzer.identify_pivot_points(5)
    print("\nTop Pivot Points:")
    for pivot in pivots:
        print(f"  {pivot['ioc']}: {pivot['degree']} connections")
    
    return analyzer

# MISP Export Helper Functions
def load_misp_csv_export(csv_file):
    """Load MISP CSV export and convert to correlation format"""
    df = pd.read_csv(csv_file)
    
    # Group by event to find co-occurring attributes
    correlations = []
    for event_id, group in df.groupby('event_id'):
        attrs = group.to_dict('records')
        
        # Create correlations between attributes in same event
        for i, attr1 in enumerate(attrs):
            for attr2 in attrs[i+1:]:
                correlations.append({
                    'source_event_id': event_id,
                    'source_value': attr1.get('value'),
                    'source_type': attr1.get('type'),
                    'source_category': attr1.get('category'),
                    'target_event_id': event_id,
                    'target_value': attr2.get('value'),
                    'target_type': attr2.get('type'),
                    'target_category': attr2.get('category'),
                    'correlation_type': 'co_occurrence',
                    'timestamp': attr1.get('timestamp')
                })
    
    return MISPCorrelationAnalyzer(correlations)

def quick_misp_analysis(file_path):
    """Quick analysis function for MISP exports"""
    if file_path.endswith('.json'):
        analyzer = MISPCorrelationAnalyzer()
        analyzer.load_from_misp_export(file_path)
    elif file_path.endswith('.csv'):
        analyzer = load_misp_csv_export(file_path)
    else:
        raise ValueError("Unsupported file format. Use .json or .csv")
    
    print(analyzer.generate_correlation_report())
    return analyzer

# Example usage for different MISP export formats
def demo_misp_formats():
    """Show how to use different MISP export formats"""
    print("=== MISP Export Format Examples ===\n")
    
    print("1. For JSON exports:")
    print("   analyzer = MISPCorrelationAnalyzer()")
    print("   analyzer.load_from_misp_export('misp_export.json')")
    print("   print(analyzer.generate_correlation_report())")
    print()
    
    print("2. For CSV exports:")
    print("   analyzer = load_misp_csv_export('misp_export.csv')")
    print("   print(analyzer.generate_correlation_report())")
    print()
    
    print("3. Quick analysis:")
    print("   analyzer = quick_misp_analysis('your_misp_file.json')")
    print()
    
    print("MISP Export Instructions:")
    print("- JSON: Events → List Events → Select → Download → JSON")
    print("- CSV: Events → List Events → Download → CSV")
    print("- API: curl -H 'Authorization: YOUR_API_KEY' https://your-misp/events/restSearch.json")
    
    return True

if __name__ == "__main__":
    # Run demo
    analyzer = demo_analysis()
    
    # Uncomment to visualize (requires matplotlib)
    # analyzer.visualize_correlation_network()
