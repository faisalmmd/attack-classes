# Quick Start Guide 🚀

Get up and running with RetireJS Analyzer in 2 minutes!

## Step 1: Install Prerequisites

```bash
# Install Node.js if not already installed
# Visit https://nodejs.org/ or use your package manager

# Verify installation
node --version
npm --version
```

## Step 2: Install RetireJS

```bash
# Install RetireJS globally
npm install -g retire

# Verify installation
retire --version
```

## Step 3: Download RetireJS Analyzer

```bash
# Clone or download the files to your local machine
# You need these files:
# - retire-analyzer.js
# - package.json
# - README.md (optional)

# Make the script executable (Linux/Mac)
chmod +x retire-analyzer.js
```

## Step 4: Run Your First Analysis

```bash
# Basic analysis of current directory
node retire-analyzer.js

# Or analyze a specific directory (replace with your path)
node retire-analyzer.js /path/to/your/js/files
```

## Step 5: View Results

After running, check the `retire-analysis` directory:

```
retire-analysis/
├── vulnerability-report.json    # Machine-readable data
├── vulnerability-report.csv     # Spreadsheet format  
└── vulnerability-report.html    # Visual report (open in browser)
```

## Your Use Case - Regional Study Data

Based on your original output, here's how to analyze your dataset:

```bash
# Navigate to your project directory
cd ~/regional-longitudinal-study/subset_collected_data

# Analyze the entire snapshot_js_data directory
node /path/to/retire-analyzer.js ./snapshot_js_data --output ./security-analysis

# Generate country-specific reports
for country_dir in ./snapshot_js_data/*/; do
    country=$(basename "$country_dir")
    echo "Analyzing $country..."
    node /path/to/retire-analyzer.js "$country_dir" --output "./security-analysis/$country"
done
```

## Common Commands for Your Workflow

```bash
# High-severity issues only (for urgent fixes)
node retire-analyzer.js ./snapshot_js_data --severity high --format html

# CSV format for research analysis
node retire-analyzer.js ./snapshot_js_data --format csv

# JSON for programmatic processing
node retire-analyzer.js ./snapshot_js_data --format json
```

## Example Output You'll See

Instead of the cluttered output you showed:
```
/home/faisal/regional-longitudinal-study/subset_collected_data/snapshot_js_data/AE/chatengineweb_mohap_gov_ae/2023_20230404113856_script_3.js
 ↳ bootstrap 4.3.1
bootstrap 4.3.1 has known vulnerabilities: severity: medium; summary: Bootstrap Cross-Site Scripting (XSS) vulnerability...
```

You'll get organized output like:
```
🔍 Starting RetireJS vulnerability analysis...
📁 Analyzing: ./snapshot_js_data
✅ Analysis complete!

📊 ANALYSIS SUMMARY
==================
Total files scanned: 2,847
Vulnerable files: 143
Total vulnerabilities: 201
Severity breakdown:
  🔴 High: 12
  🟡 Medium: 156
  🟢 Low: 33

Most vulnerable libraries:
  📦 bootstrap: 67 vulnerabilities
  📦 jquery: 45 vulnerabilities
  📦 lodash: 23 vulnerabilities

Reports saved to: ./retire-analysis
```

## Next Steps

1. **Review the HTML report** - Open `retire-analysis/vulnerability-report.html` in your browser
2. **Analyze trends** - Use the CSV file to identify patterns across countries/regions
3. **Prioritize fixes** - Focus on high-severity vulnerabilities first
4. **Set up automation** - Run periodic scans on new data

## Need Help?

- Check `README.md` for detailed documentation
- Run `node retire-analyzer.js --help` for all options
- See `examples.md` for advanced usage patterns

**You're ready to go! **