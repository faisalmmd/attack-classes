#!/bin/bash
# Fresh Start Script for HTML Violations Analyzer
# This script ensures clean database and proper timestamp extraction

echo "🚀 Starting Fresh HTML Violations Analysis..."

# Step 1: Backup existing results (optional)
if [ -f "results.db" ]; then
    echo "📦 Backing up existing results.db..."
    mv results.db results_backup_$(date +%Y%m%d_%H%M%S).db
fi

# Step 2: Clean up any existing log files
echo "🧹 Cleaning up old log files..."
rm -rf log_output/
mkdir -p log_output/

# Step 3: Verify input directory exists
INPUT_DIR="../regional-longitudinal-study/subset_collected_data/snapshot_data"
if [ ! -d "$INPUT_DIR" ]; then
    echo "❌ ERROR: Input directory not found: $INPUT_DIR"
    echo "Please check the path in config.yml"
    exit 1
fi

echo "✅ Input directory found: $INPUT_DIR"

# Step 4: Count HTML files
HTML_COUNT=$(find "$INPUT_DIR" -name "*.html" | wc -l)
echo "📊 Found $HTML_COUNT HTML files to process"

# Step 5: Show sample file structure
echo "📁 Sample file structure:"
find "$INPUT_DIR" -name "*.html" | head -5

# Step 6: Test timestamp extraction on sample files
echo "🔍 Testing timestamp extraction on sample files..."
python3 -c "
import os
import re
from datetime import datetime

def extract_timestamp_from_filename(file_path):
    filename = os.path.basename(file_path)
    timestamp_match = re.search(r'_(\d{14})\.html$', filename)
    if timestamp_match:
        timestamp_str = timestamp_match.group(1)
        try:
            year = int(timestamp_str[:4])
            month = int(timestamp_str[4:6])
            day = int(timestamp_str[6:8])
            hour = int(timestamp_str[8:10])
            minute = int(timestamp_str[10:12])
            second = int(timestamp_str[12:14])
            if 2000 <= year <= 2030 and 1 <= month <= 12 and 1 <= day <= 31:
                return datetime(year, month, day, hour, minute, second)
        except ValueError:
            pass
    return None

# Test on sample files
import glob
sample_files = glob.glob('$INPUT_DIR/**/*.html', recursive=True)[:5]
for file_path in sample_files:
    filename = os.path.basename(file_path)
    extracted = extract_timestamp_from_filename(file_path)
    if extracted:
        print(f'✅ {filename} -> {extracted} (Year: {extracted.year})')
    else:
        print(f'❌ {filename} -> Failed to extract timestamp')
"

# Step 7: Check Python environment
echo "🐍 Checking Python environment..."
python3 -c "
import sys
print(f'Python version: {sys.version}')

required_modules = ['yaml', 'sqlalchemy', 'bs4', 'pandas', 'matplotlib', 'seaborn']
missing = []

for module in required_modules:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError:
        missing.append(module)
        print(f'❌ {module} - MISSING')

if missing:
    print(f'\n⚠️  Install missing modules: pip install {\" \".join(missing)}')
    exit(1)
else:
    print('✅ All required modules available')
"

if [ $? -ne 0 ]; then
    echo "❌ Python environment check failed"
    exit 1
fi

# Step 8: Validate config.yml
echo "📋 Validating config.yml..."
python3 -c "
import yaml
import os

try:
    with open('config.yml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Check required sections
    required_sections = ['general', 'database', 'crawler', 'checker']
    for section in required_sections:
        if section not in config:
            print(f'❌ Missing section: {section}')
            exit(1)
        else:
            print(f'✅ Section {section} found')
    
    # Check input directory
    input_dir = config.get('input_dir', '')
    if not os.path.exists(input_dir):
        print(f'❌ Input directory not found: {input_dir}')
        exit(1)
    else:
        print(f'✅ Input directory exists: {input_dir}')
    
    # Check database config
    db_config = config.get('database', {})
    if db_config.get('type') == 'sqlite':
        print(f'✅ Database: SQLite ({db_config.get(\"name\", \"results.db\")})')
    
    # Check rules
    rules = config.get('checker', {}).get('rules', [])
    print(f'✅ Rules to check: {rules}')
    
    print('✅ Config validation passed')
    
except Exception as e:
    print(f'❌ Config validation failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ Config validation failed"
    exit 1
fi

# Step 9: Ready to run
echo ""
echo "🎯 READY TO START FRESH ANALYSIS!"
echo ""
echo "Next steps:"
echo "1. Replace your current basicChecker.py with the fixed version"
echo "2. Run: python3 main.py --module local_files"
echo "3. Wait for processing to complete"
echo "4. Run: python3 fixed_analysis.py results.db"
echo ""
echo "Expected processing time: ~$(echo "scale=0; $HTML_COUNT / 100" | bc) minutes for $HTML_COUNT files"
echo ""

# Ask user if they want to start
read -p "Do you want to start the analysis now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 Starting analysis..."
    echo "⏰ Started at: $(date)"
    
    # Run the main analysis
    python3 main.py --module local_files
    
    if [ $? -eq 0 ]; then
        echo "✅ Analysis completed successfully!"
        echo "📊 Creating visualizations..."
        python3 fixed_analysis.py results.db
        echo "🎉 All done! Check the plots/ directory for visualizations."
    else
        echo "❌ Analysis failed. Check the logs in log_output/ directory."
    fi
else
    echo "👍 Ready when you are! Run: python3 main.py --module local_files"
fi