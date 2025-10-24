#!/bin/bash
# Quick Repository Setup for HTML Violation Analyzer

echo "🚀 HTML Violation Analyzer - Enhanced Version Setup"
echo "=================================================="
echo "Building upon Florian Hantke's IMC 2022 research"

# Create directory structure
echo "📁 Creating directories..."
mkdir -p crawler checker/rules config data/{input,output/{plots,reports,logs},sample}
mkdir -p tests/fixtures docs scripts .github/workflows

# Create __init__.py files
echo "🐍 Creating Python packages..."
touch crawler/__init__.py checker/__init__.py checker/rules/__init__.py tests/__init__.py

# Move existing files
echo "📦 Moving files to proper locations..."

# Backup config
if [ -f "config.yml" ]; then
    cp config.yml config/example.yml
    echo "✓ Config backed up to config/example.yml"
fi

# Move sample data
if [ -f "country_summary.csv" ]; then
    mv country_summary.csv data/sample/
    echo "✓ Moved sample data"
fi

echo ""
echo "📋 FILES TO CREATE FROM ARTIFACTS:"
echo "=================================="
echo "1. README.md (with proper attribution)"
echo "2. requirements.txt" 
echo "3. .gitignore"
echo "4. LICENSE (with dual copyright)"
echo "5. CITATION.cff (for academic citation)"
echo "6. scripts/setup_database.py"
echo "7. docs/acknowledgments.md"
echo ""
echo "📦 FILES TO MOVE:"
echo "================"
echo "8. Move all your Python files to correct directories"
echo "9. Create rule files using provided templates"
echo "10. Update __init__.py files with correct imports"
echo ""
echo "Ready to proceed? (Press Enter to continue)"
read