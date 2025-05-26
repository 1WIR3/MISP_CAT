#!/usr/bin/env python3
"""
basic_analysis.py - Basic MISP Correlation Analysis Example

This script demonstrates the fundamental features of the MISP Correlation Analysis Toolkit.
Perfect for getting started and understanding your correlation data.

Usage:
    python basic_analysis.py misp_export.json
    python basic_analysis.py misp_export.csv

Author: MISP Correlation Analysis Toolkit
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
import pandas as pd

# Import the main analyzer (assumes misp_analyzer.py is in same directory)
from misp_analyzer import MISPCorrelationAnalyzer, quick_misp_analysis, load_misp_csv_export

def main():
    parser = argparse.ArgumentParser(
        description="Basic MISP Correlation Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python basic_analysis.py data/misp_export.json
    python basic_analysis.py data/misp_export.csv --output-dir results/
    python basic_analysis.py data/misp_export.json --top-iocs 20 --min-cluster-size 5
        """
    )
    
    parser.add_argument('input_file', help='MISP export file (JSON or CSV)')
    parser.add_argument('--output-dir', '-o', default='output', 
                       help='Output directory for results (default: output)')
    parser.add_argument('--top-iocs', '-t', type=int, default=15,
                       help='Number of top IOCs to identify (default: 15)')
    parser.add_argument('--min-cluster-size', '-c', type=int, default=3,
                       help='Minimum cluster size for analysis (default: 3)')
    parser.add_argument('--visualize', '-v', action='store_true',
                       help='Generate network visualization')
    
    args = parser.parse_args()
    
    # Validate input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file '{args.input_file}' not found")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    print("="*60)
    print("MISP CORRELATION ANALYSIS - BASIC EXAMPLE")
    print("="*60)
    print(f"Input file: {input_path}")
    print(f"Output directory: {output_dir}")
    print(f"Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Load and analyze data
        print("📊 Loading MISP data...")
        if input_path.suffix.lower() == '.json':
            analyzer = MISPCorrelationAnalyzer()
            analyzer.load_from_misp_export(str(input_path))
        elif input_path.suffix.lower() == '.csv':
            analyzer = load_misp_csv_export(str(input_path))
        else:
            print("Error: Unsupported file format. Use .json or .csv")
            sys.exit(1)
        
        if analyzer.df.empty:
            print("⚠️  No correlation data found in the export")
            print("This might mean:")
            print("  - No correlations exist in the data")
            print("  - Export settings didn't include correlations")
            print("  - Different MISP export format")
            sys.exit(1)
        
        print(f"✅ Loaded {len(analyzer.df)} correlations successfully")
        print(f"   Graph: {analyzer.graph.number_of_nodes()} nodes, {analyzer.graph.number_of_edges()} edges")
        print()
        
        # 1. Generate comprehensive report
        print("📋 Generating analysis report...")
        report = analyzer.generate_correlation_report()
        
        # Save report to file
        report_file = output_dir / 'correlation_analysis_report.txt'
        with open(report_file, 'w') as f:
            f.write(f"MISP Correlation Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source file: {input_path}\n")
            f.write("="*60 + "\n\n")
            f.write(report)
        
        print(f"✅ Report saved to: {report_file}")
        
        # Print key insights to console
        patterns = analyzer.analyze_correlation_patterns()
        print(f"   📈 Total correlations: {patterns['total_correlations']}")
        print(f"   🎯 Unique IOCs: {patterns['unique_sources'] + patterns['unique_targets']}")
        print()
        
        # 2. Identify priority IOCs (pivot points)
        print(f"🔍 Identifying top {args.top_iocs} priority IOCs...")
        priority_iocs = analyzer.export_high_priority_iocs(args.top_iocs)
        
        if not priority_iocs.empty:
            priority_file = output_dir / 'priority_iocs.csv'
            priority_iocs.to_csv(priority_file, index=False)
            print(f"✅ Priority IOCs saved to: {priority_file}")
            
            # Show top 5 in console
            print("   Top 5 Priority IOCs:")
            for i, row in priority_iocs.head().iterrows():
                print(f"   {i+1}. {row['ioc_type']}:{row['ioc_value'][:50]}...")
                print(f"      Connections: {row['connection_count']}, Score: {row['centrality_score']:.3f}")
        else:
            print("⚠️  No priority IOCs identified")
        print()
        
        # 3. Analyze threat clusters
        print(f"🔗 Finding correlation clusters (min size: {args.min_cluster_size})...")
        clusters = analyzer.find_correlation_clusters(args.min_cluster_size)
        
        if clusters:
            # Save cluster analysis
            cluster_data = []
            for cluster in clusters:
                cluster_data.append({
                    'cluster_id': cluster['cluster_id'],
                    'size': cluster['size'],
                    'density': f"{cluster['density']:.3f}",
                    'edges': cluster['edges'],
                    'sample_iocs': ' | '.join(list(cluster['nodes'])[:3])
                })
            
            cluster_df = pd.DataFrame(cluster_data)
            cluster_file = output_dir / 'threat_clusters.csv'
            cluster_df.to_csv(cluster_file, index=False)
            print(f"✅ Found {len(clusters)} clusters, saved to: {cluster_file}")
            
            # Show top 3 clusters
            print("   Top 3 Clusters:")
            for i, cluster in enumerate(clusters[:3]):
                print(f"   {i+1}. Cluster {cluster['cluster_id']}: {cluster['size']} IOCs")
                print(f"      Density: {cluster['density']:.3f}")
        else:
            print("⚠️  No significant clusters found")
        print()
        
        # 4. Generate network visualization (optional)
        if args.visualize:
            print("🎨 Generating network visualization...")
            try:
                import matplotlib.pyplot as plt
                analyzer.visualize_correlation_network(max_nodes=100, figsize=(15, 10))
                
                viz_file = output_dir / 'correlation_network.png'
                plt.savefig(viz_file, dpi=300, bbox_inches='tight')
                plt.close()
                print(f"✅ Visualization saved to: {viz_file}")
            except Exception as e:
                print(f"⚠️  Visualization failed: {e}")
        
        # 5. Summary statistics
        print("="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"📁 Output files created in: {output_dir}")
        print(f"📊 Total correlations analyzed: {len(analyzer.df)}")
        print(f"🎯 Priority IOCs identified: {len(priority_iocs) if not priority_iocs.empty else 0}")
        print(f"🔗 Threat clusters found: {len(clusters)}")
        print(f"⏱️  Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Actionable recommendations
        print("\n💡 RECOMMENDATIONS:")
        if not priority_iocs.empty:
            top_ioc = priority_iocs.iloc[0]
            print(f"   1. Investigate top IOC: {top_ioc['ioc_type']}:{top_ioc['ioc_value']}")
            print(f"      (Connected to {top_ioc['connection_count']} other indicators)")
        
        if clusters:
            largest_cluster = max(clusters, key=lambda x: x['size'])
            print(f"   2. Analyze largest cluster: {largest_cluster['size']} related IOCs")
            print(f"      (May represent single campaign or threat actor)")
        
        print(f"   3. Review detailed report: {report_file}")
        print(f"   4. Share priority IOCs with hunting teams: {output_dir / 'priority_iocs.csv'}")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        print("\nTroubleshooting tips:")
        print("  - Ensure MISP export includes correlations")
        print("  - Check file format (JSON/CSV)")
        print("  - Verify file is not corrupted")
        sys.exit(1)

if __name__ == "__main__":
    main()
