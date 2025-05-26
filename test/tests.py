import unittest
import pandas as pd
import networkx as nx
from misp_correlation_analysis import MISPCorrelationAnalyzer

class TestMISPCorrelationAnalyzer(unittest.TestCase):
    def setUp(self):
        """Set up test data and initialize the analyzer."""
        self.sample_data = [
            {'source_type': 'ip-src', 'source_value': '192.168.1.100', 
             'target_type': 'domain', 'target_value': 'malicious.com', 'correlation_type': 'network'},
            {'source_type': 'domain', 'source_value': 'malicious.com', 
             'target_type': 'sha256', 'target_value': 'abc123...', 'correlation_type': 'payload'},
            {'source_type': 'ip-src', 'source_value': '192.168.1.100', 
             'target_type': 'url', 'target_value': 'http://evil.com/payload', 'correlation_type': 'network'},
        ]
        self.analyzer = MISPCorrelationAnalyzer(self.sample_data)

    def test_load_data(self):
        """Test loading data into the analyzer."""
        self.assertIsInstance(self.analyzer.df, pd.DataFrame)
        self.assertEqual(len(self.analyzer.df), len(self.sample_data))

    def test_load_from_misp_export(self):
        """Test loading data from a MISP JSON export."""
        # Create a mock JSON file
        mock_json = {
            "Event": {
                "id": "1",
                "info": "Test Event",
                "date": "2025-05-26",
                "Attribute": [
                    {"id": "1", "value": "192.168.1.100", "type": "ip-src", "category": "Network activity"},
                    {"id": "2", "value": "malicious.com", "type": "domain", "category": "Network activity"}
                ]
            }
        }
        with open("mock_misp.json", "w") as f:
            import json
            json.dump(mock_json, f)

        self.analyzer.load_from_misp_export("mock_misp.json")
        self.assertGreater(len(self.analyzer.df), 0)

    def test_analyze_correlation_patterns(self):
        """Test analyzing correlation patterns."""
        patterns = self.analyzer.analyze_correlation_patterns()
        self.assertIn('total_correlations', patterns)
        self.assertEqual(patterns['total_correlations'], len(self.sample_data))

    def test_find_correlation_clusters(self):
        """Test finding correlation clusters."""
        clusters = self.analyzer.find_correlation_clusters()
        self.assertIsInstance(clusters, list)

    def test_identify_pivot_points(self):
        """Test identifying pivot points."""
        pivots = self.analyzer.identify_pivot_points()
        self.assertIsInstance(pivots, list)
        self.assertLessEqual(len(pivots), 10)

    def test_analyze_temporal_correlations(self):
        """Test analyzing temporal correlations."""
        self.analyzer.df['timestamp'] = pd.to_datetime('2025-05-26')
        trends = self.analyzer.analyze_temporal_correlations()
        self.assertIn('daily_trend', trends)

    def test_generate_correlation_report(self):
        """Test generating a correlation report."""
        report = self.analyzer.generate_correlation_report()
        self.assertIsInstance(report, str)
        self.assertIn("=== MISP Correlation Analysis Report ===", report)

    def test_visualize_correlation_network(self):
        """Test visualizing the correlation network."""
        # Visualization is hard to test programmatically, but we can ensure no exceptions are raised
        try:
            self.analyzer.visualize_correlation_network(max_nodes=10)
        except Exception as e:
            self.fail(f"Visualization raised an exception: {e}")

    def test_export_high_priority_iocs(self):
        """Test exporting high-priority IOCs."""
        iocs = self.analyzer.export_high_priority_iocs()
        self.assertIsInstance(iocs, pd.DataFrame)
        self.assertLessEqual(len(iocs), 20)

if __name__ == '__main__':
    unittest.main()
