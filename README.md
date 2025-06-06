# MISP Correlation Analysis Toolkit -  Guide

## Table of Contents
1. [Installation & Setup](#installation--setup)
2. [MISP Data Export](#misp-data-export)
3. [Tool Usage](#tool-usage)
4. [Analysis Examples](#analysis-examples)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

## Installation & Setup

### Prerequisites
- Python 3.7 or higher
- MISP instance access (for data export)

### Step 1: Install Required Libraries

Create a new directory and set up your environment:

```bash
mkdir misp-correlation-analysis
cd misp-correlation-analysis

# Create virtual environment (recommended)
python -m venv misp-env
source misp-env/bin/activate  # On Windows: misp-env\Scripts\activate

# Install required packages
pip install pandas networkx matplotlib seaborn numpy pymisp
```
Alternitatively, requirements.txt can be used to install all packages:

``` pip install -r requirements.txt ```

  
### Step 2: Save the Analysis Code

1. Copy the MISP Correlation Analysis Toolkit code into a file named `misp_analyzer.py`
2. Make sure all dependencies are installed
3. Test the installation by running:

```bash
python -c "import pandas, networkx, matplotlib; print('All dependencies installed successfully!')"
```

## MISP Data Export

### Method 1: Web Interface Export (Recommended)

#### JSON Export (Best Option)
1. **Login to your MISP instance**
2. **Navigate to Events**:
   - Go to `Events` → `List Events`
   - Use filters to select relevant events (date range, tags, etc.)
3. **Select Events**:
   - Check boxes next to events you want to analyze
   - Or use "Select All" for comprehensive analysis
4. **Export Data**:
   - Click `Download` button
   - Select `JSON` format
   - **Important**: Ensure "Include correlations" is checked
   - **Important**: Check "Include related events" if available
5. **Save File**: Save as `misp_export.json`

#### CSV Export (Alternative)
1. Follow steps 1-3 above
2. **Export Data**:
   - Click `Download` button
   - Select `CSV` format
   - Save as `misp_export.csv`

### Method 2: API Export

```bash
# Replace with your MISP details
MISP_URL="https://your-misp-instance.com"
API_KEY="your-api-key-here"

# Export events with correlations
curl -H "Authorization: $API_KEY" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     "$MISP_URL/events/restSearch.json" \
     -d '{
       "includeCorrelations": true,
       "includeRelatedTags": true,
       "published": true,
       "limit": 1000
     }' > misp_export.json
```

### Method 3: PyMISP Script

```python
from pymisp import PyMISP

# Configure MISP connection
misp = PyMISP('https://your-misp-instance.com', 'your-api-key', ssl=False)

# Search for events with correlations
events = misp.search(
    controller='events',
    published=True,
    include_correlations=True,
    include_context=True,
    limit=1000
)

# Save to file
import json
with open('misp_export.json', 'w') as f:
    json.dump(events, f, indent=2)
```

## Tool Usage

### Basic Usage

```python
from misp_analyzer import MISPCorrelationAnalyzer, quick_misp_analysis

# Method 1: Quick analysis (auto-detects format)
analyzer = quick_misp_analysis('misp_export.json')

# Method 2: Manual loading
analyzer = MISPCorrelationAnalyzer()
analyzer.load_from_misp_export('misp_export.json')

# Generate comprehensive report
print(analyzer.generate_correlation_report())
```

### Step-by-Step Analysis Process

#### Step 1: Load and Validate Data
```python
from misp_analyzer import MISPCorrelationAnalyzer

# Initialize analyzer
analyzer = MISPCorrelationAnalyzer()

# Load MISP export
analyzer.load_from_misp_export('misp_export.json')

# Check data quality
print(f"Loaded {len(analyzer.df)} correlations")
print(f"Graph has {analyzer.graph.number_of_nodes()} nodes and {analyzer.graph.number_of_edges()} edges")
```

#### Step 2: Basic Pattern Analysis
```python
# Get overview of correlation patterns
patterns = analyzer.analyze_correlation_patterns()
print("=== Correlation Overview ===")
for key, value in patterns.items():
    print(f"{key}: {value}")
```

#### Step 3: Identify Key IOCs (Pivot Points)
```python
# Find most connected IOCs
pivots = analyzer.identify_pivot_points(top_n=10)
print("\n=== Top Pivot Points ===")
for i, pivot in enumerate(pivots):
    print(f"{i+1}. {pivot['ioc']}")
    print(f"   Connections: {pivot['degree']}")
    print(f"   Centrality Score: {pivot['combined_score']:.3f}")
```

#### Step 4: Find Threat Clusters
```python
# Identify correlation clusters
clusters = analyzer.find_correlation_clusters(min_cluster_size=3)
print("\n=== Major Threat Clusters ===")
for cluster in clusters[:5]:  # Top 5 clusters
    print(f"Cluster {cluster['cluster_id']}: {cluster['size']} IOCs")
    print(f"  Density: {cluster['density']:.3f}")
    print(f"  Sample IOCs: {', '.join(list(cluster['nodes'])[:3])}")
```

#### Step 5: Export Priority IOCs
```python
# Get prioritized IOC list
priority_iocs = analyzer.export_high_priority_iocs(top_n=20)
priority_iocs.to_csv('high_priority_iocs.csv', index=False)
print("High priority IOCs saved to 'high_priority_iocs.csv'")
```

#### Step 6: Visualize Network (Optional)
```python
# Create network visualization
analyzer.visualize_correlation_network(max_nodes=50, figsize=(15, 10))
```

## Analysis Examples

### Example 1: APT Campaign Analysis

```python
# Load APT-related events
analyzer = MISPCorrelationAnalyzer()
analyzer.load_from_misp_export('apt_events.json')

# Generate full report
report = analyzer.generate_correlation_report()
print(report)

# Focus on infrastructure pivots
pivots = analyzer.identify_pivot_points(20)
infrastructure_pivots = [p for p in pivots if 'ip-' in p['ioc'] or 'domain' in p['ioc']]

print("=== Infrastructure Pivot Points ===")
for pivot in infrastructure_pivots[:10]:
    print(f"IOC: {pivot['ioc']}")
    print(f"Connections: {pivot['degree']}")
    print(f"Type: Infrastructure")
    print()
```

### Example 2: Malware Family Analysis

```python
# Analyze malware correlations
analyzer = MISPCorrelationAnalyzer()
analyzer.load_from_misp_export('malware_events.json')

# Find malware clusters
clusters = analyzer.find_correlation_clusters(min_cluster_size=5)

print("=== Malware Family Clusters ===")
for cluster in clusters:
    # Filter for malware-related IOCs
    malware_iocs = [ioc for ioc in cluster['nodes'] if any(x in ioc.lower() for x in ['sha', 'md5', 'filename'])]
    
    if malware_iocs:
        print(f"Cluster {cluster['cluster_id']} - Potential Malware Family")
        print(f"  Size: {len(malware_iocs)} malware samples")
        print(f"  Samples: {malware_iocs[:3]}")
        print()
```

### Example 3: Temporal Campaign Tracking

```python
# Analyze campaign evolution over time
analyzer = MISPCorrelationAnalyzer()
analyzer.load_from_misp_export('campaign_events.json')

# Temporal analysis (if timestamp data available)
if 'timestamp' in analyzer.df.columns:
    temporal_data = analyzer.analyze_temporal_correlations()
    
    print("=== Campaign Timeline ===")
    print(f"Peak Activity Day: {temporal_data['peak_day']}")
    print(f"Peak Correlations: {temporal_data['peak_count']}")
    
    # Plot daily activity
    import matplotlib.pyplot as plt
    daily_data = temporal_data['daily_trend']
    
    plt.figure(figsize=(12, 6))
    plt.plot(list(daily_data.keys()), list(daily_data.values()))
    plt.title('Campaign Activity Over Time')
    plt.xlabel('Date')
    plt.ylabel('Number of Correlations')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
```

### Example 4: Cross-Event IOC Hunting

```python
# Find IOCs that appear across multiple events
analyzer = MISPCorrelationAnalyzer()
analyzer.load_from_misp_export('hunting_events.json')

# Get pivot points and check event distribution
pivots = analyzer.identify_pivot_points(50)

print("=== Cross-Event IOCs (Potential Hunting Leads) ===")
for pivot in pivots:
    # Count unique events this IOC appears in
    related_events = set()
    
    # Check source events
    mask = analyzer.df['source_value'] == pivot['ioc'].split(':', 1)[1]
    source_events = analyzer.df[mask]['source_event_id'].unique()
    
    # Check target events  
    mask = analyzer.df['target_value'] == pivot['ioc'].split(':', 1)[1]
    target_events = analyzer.df[mask]['target_event_id'].unique()
    
    all_events = set(list(source_events) + list(target_events))
    
    if len(all_events) > 2:  # IOC appears in multiple events
        print(f"IOC: {pivot['ioc']}")
        print(f"  Appears in {len(all_events)} events")
        print(f"  Total connections: {pivot['degree']}")
        print(f"  Centrality score: {pivot['combined_score']:.3f}")
        print()
```

## Advanced Features

### Custom Correlation Analysis

```python
# Create custom correlation rules
def analyze_custom_correlations(analyzer):
    """Custom analysis for specific use cases"""
    
    # Find C2 infrastructure patterns
    c2_indicators = []
    for _, row in analyzer.df.iterrows():
        if (row['source_type'] in ['ip-src', 'domain'] and 
            row['target_type'] in ['url', 'uri']):
            c2_indicators.append(row)
    
    print(f"Found {len(c2_indicators)} potential C2 correlations")
    
    # Find file-to-network correlations
    file_net_correlations = []
    for _, row in analyzer.df.iterrows():
        if (any(x in row['source_type'] for x in ['sha', 'md5', 'filename']) and
            any(x in row['target_type'] for x in ['ip-', 'domain', 'url'])):
            file_net_correlations.append(row)
    
    print(f"Found {len(file_net_correlations)} file-to-network correlations")
    
    return c2_indicators, file_net_correlations

# Usage
c2_data, file_net_data = analyze_custom_correlations(analyzer)
```

### Integration with Other Tools

```python
# Export for YARA rule creation
def export_for_yara(analyzer, output_file='yara_candidates.txt'):
    """Export string/hex values for YARA rule creation"""
    
    pivots = analyzer.identify_pivot_points(20)
    
    with open(output_file, 'w') as f:
        f.write("// High-priority IOCs for YARA rules\n")
        f.write("// Generated from MISP correlation analysis\n\n")
        
        for pivot in pivots:
            ioc_type, ioc_value = pivot['ioc'].split(':', 1)
            if ioc_type in ['filename', 'pattern-in-file']:
                f.write(f'// {ioc_type}: {ioc_value} (connections: {pivot["degree"]})\n')
                f.write(f'$string{pivots.index(pivot)} = "{ioc_value}"\n\n')

# Export for Splunk searches
def export_for_splunk(analyzer, output_file='splunk_searches.txt'):
    """Export IOCs formatted for Splunk searches"""
    
    pivots = analyzer.identify_pivot_points(30)
    
    with open(output_file, 'w') as f:
        f.write("# High-priority IOCs for Splunk hunting\n")
        f.write("# Generated from MISP correlation analysis\n\n")
        
        # Group by IOC type
        by_type = {}
        for pivot in pivots:
            ioc_type, ioc_value = pivot['ioc'].split(':', 1)
            if ioc_type not in by_type:
                by_type[ioc_type] = []
            by_type[ioc_type].append(ioc_value)
        
        for ioc_type, values in by_type.items():
            f.write(f"# {ioc_type.upper()} searches\n")
            if ioc_type == 'ip-src':
                f.write(f'src_ip IN ({", ".join([f\'"{v}"\' for v in values[:10]])})\n')
            elif ioc_type == 'domain':
                f.write(f'query IN ({", ".join([f\'"{v}"\' for v in values[:10]])})\n')
            f.write("\n")

# Usage
export_for_yara(analyzer)
export_for_splunk(analyzer)
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: "No correlations found in MISP export"
**Cause**: MISP export doesn't include correlation data
**Solutions**:
1. Re-export with "Include correlations" checked
2. Use co-occurrence analysis (automatically done by tool)
3. Check MISP correlation settings

#### Issue 2: "Graph has no nodes"
**Cause**: Data format not recognized
**Solutions**:
```python
# Debug data structure
print("Data columns:", analyzer.df.columns.tolist())
print("Sample data:", analyzer.df.head())

# Manual data inspection
with open('misp_export.json', 'r') as f:
    data = json.load(f)
    print("JSON structure:", list(data.keys()))
```

#### Issue 3: Memory issues with large datasets
**Solution**: Process data in chunks
```python
# For large datasets
def process_large_misp_export(file_path, chunk_size=1000):
    """Process large MISP exports in chunks"""
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    events = data.get('response', data)
    
    for i in range(0, len(events), chunk_size):
        chunk = events[i:i+chunk_size]
        analyzer = MISPCorrelationAnalyzer()
        
        # Process chunk
        temp_data = {'response': chunk}
        with open('temp_chunk.json', 'w') as temp_f:
            json.dump(temp_data, temp_f)
        
        analyzer.load_from_misp_export('temp_chunk.json')
        
        # Analyze chunk
        print(f"Chunk {i//chunk_size + 1}: {len(analyzer.df)} correlations")
        pivots = analyzer.identify_pivot_points(10)
        
        # Save chunk results
        pd.DataFrame(pivots).to_csv(f'chunk_{i//chunk_size}_pivots.csv')
```

#### Issue 4: Visualization not showing
**Solution**: Check matplotlib backend
```python
import matplotlib
matplotlib.use('Agg')  # For headless environments
# or
matplotlib.use('TkAgg')  # For interactive environments

# Alternative: save plots instead of showing
analyzer.visualize_correlation_network()
plt.savefig('correlation_network.png', dpi=300, bbox_inches='tight')
```

## Best Practices

### 1. Data Quality
- **Export recent data**: Focus on events from last 6-12 months for active threats
- **Include context**: Always export with correlations and related events
- **Filter appropriately**: Use MISP tags and categories to focus analysis

### 2. Analysis Strategy
- **Start broad**: Begin with general correlation analysis
- **Focus iteratively**: Drill down into specific clusters or pivot points
- **Cross-reference**: Validate findings against external intelligence

### 3. Operational Integration
- **Regular analysis**: Run correlation analysis weekly/monthly
- **Automated alerts**: Set up monitoring for new high-centrality IOCs
- **Team sharing**: Share priority IOC lists with hunting teams

### 4. Performance Optimization
- **Limit node count**: Use max_nodes parameter for large networks
- **Cache results**: Save analysis results for future reference
- **Incremental analysis**: Process new events incrementally

### 5. Security Considerations
- **Data handling**: Ensure MISP exports are properly secured
- **Access control**: Limit access to correlation analysis results
- **Attribution**: Be careful about threat actor attribution based solely on correlations

## Complete Workflow Example

Here's a complete end-to-end workflow:

```python
#!/usr/bin/env python3
"""
Complete MISP Correlation Analysis Workflow
"""

from misp_analyzer import MISPCorrelationAnalyzer
import pandas as pd
import json
from datetime import datetime

def main():
    """Complete analysis workflow"""
    
    print("=== MISP Correlation Analysis Workflow ===")
    print(f"Analysis started at: {datetime.now()}\n")
    
    # Step 1: Load data
    print("Step 1: Loading MISP export...")
    analyzer = MISPCorrelationAnalyzer()
    analyzer.load_from_misp_export('misp_export.json')
    print(f"Loaded {len(analyzer.df)} correlations\n")
    
    # Step 2: Generate comprehensive report
    print("Step 2: Generating analysis report...")
    report = analyzer.generate_correlation_report()
    
    # Save report
    with open('correlation_analysis_report.txt', 'w') as f:
        f.write(f"MISP Correlation Analysis Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("=" * 50 + "\n\n")
        f.write(report)
    
    print("Report saved to 'correlation_analysis_report.txt'\n")
    
    # Step 3: Identify and export priority IOCs
    print("Step 3: Identifying priority IOCs...")
    priority_iocs = analyzer.export_high_priority_iocs(50)
    priority_iocs.to_csv('priority_iocs.csv', index=False)
    print(f"Exported {len(priority_iocs)} priority IOCs to 'priority_iocs.csv'\n")
    
    # Step 4: Find threat clusters
    print("Step 4: Analyzing threat clusters...")
    clusters = analyzer.find_correlation_clusters(min_cluster_size=3)
    
    cluster_summary = []
    for cluster in clusters[:10]:  # Top 10 clusters
        cluster_summary.append({
            'cluster_id': cluster['cluster_id'],
            'size': cluster['size'],
            'density': cluster['density'],
            'sample_iocs': ', '.join(list(cluster['nodes'])[:3])
        })
    
    pd.DataFrame(cluster_summary).to_csv('threat_clusters.csv', index=False)
    print(f"Analyzed {len(clusters)} clusters, saved top 10 to 'threat_clusters.csv'\n")
    
    # Step 5: Create visualizations
    print("Step 5: Creating network visualization...")
    try:
        analyzer.visualize_correlation_network(max_nodes=100)
        plt.savefig('correlation_network.png', dpi=300, bbox_inches='tight')
        print("Network visualization saved to 'correlation_network.png'\n")
    except Exception as e:
        print(f"Visualization failed: {e}\n")
    
    # Step 6: Summary
    print("=== Analysis Complete ===")
    print("Generated files:")
    print("- correlation_analysis_report.txt")
    print("- priority_iocs.csv")
    print("- threat_clusters.csv")
    print("- correlation_network.png")
    print(f"\nAnalysis completed at: {datetime.now()}")

if __name__ == "__main__":
    main()
```

Save this as `run_analysis.py` and execute with:
```bash
python run_analysis.py
```

# Running Unit Tests for `MISPCorrelationAnalyzer`

This guide explains how to run the unit tests for the `MISPCorrelationAnalyzer` class.

## Prerequisites
1. **Python Environment**: Ensure you have Python 3.7 or later installed.
2. **Dependencies**: Install the required libraries by running:
pip install pandas networkx matplotlib seaborn

## Setting Up the Test Suite
1. Save the test suite provided earlier in a file named `test_misp_correlation_analyzer.py` in the same directory as `misp_correlation_analysis.py`.
2. Ensure the directory structure looks like this:
. ├── misp_correlation_analysis.py ├── test_misp_correlation_analyzer.py

## Running the Tests

### Using `unittest`
Run the tests using Python's built-in `unittest` module:
python -m unittest test_misp_correlation_analyzer.py

### Using `pytest` (Optional)
If you prefer `pytest`, install it first:
pip install pytest

Then, run the tests with:
pytest test_misp_correlation_analyzer.py

## Expected Output
If all tests pass, you should see output similar to the following:

### `unittest` Output
Ran 9 tests in 0.123s
OK
============================= test session starts ============================== collected 9 items
test_misp_correlation_analyzer.py .........                             [100%]
============================== 9 passed in 0.12s ===============================


## Notes
- If any test fails, the output will include details about the failed test(s), including the error message and traceback.
- Ensure that the `misp_correlation_analysis.py` file is free of syntax errors before running the tests.

## Additional Information
- For more details on the `MISPCorrelationAnalyzer` class, refer to the comments and docstrings in the `misp_correlation_analysis.py` file.
- If you encounter issues, ensure that all dependencies are installed and that the test file is in the correct directory.
