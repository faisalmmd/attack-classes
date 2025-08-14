# RetireJS Analyzer - Usage Examples

## Real-World Scenarios

### 1. Security Audit for Web Application

**Scenario**: You need to audit all JavaScript files in a web application before deployment.

```bash
# Analyze the entire web assets directory
node retire-analyzer.js /var/www/myapp/assets/js --output ./security-audit-2024

# Focus on critical vulnerabilities only
node retire-analyzer.js /var/www/myapp/assets/js --severity high --format html
```

**What you get**:
- Complete vulnerability inventory
- Risk assessment by severity
- Actionable remediation guidance
- Executive-friendly HTML report

### 2. Research Dataset Analysis

**Scenario**: Analyzing a large collection of JavaScript files from multiple websites (like your use case).

```bash
# Process your entire dataset with comprehensive reporting
node retire-analyzer.js ~/regional-longitudinal-study/subset_collected_data/snapshot_js_data

# Generate CSV for spreadsheet analysis
node retire-analyzer.js ~/regional-longitudinal-study/subset_collected_data/snapshot_js_data --format csv

# Create reports organized by country/region
for country_dir in ~/regional-longitudinal-study/subset_collected_data/snapshot_js_data/*/; do
    country_code=$(basename "$country_dir")
    echo "Analyzing $country_code..."
    node retire-analyzer.js "$country_dir" --output "./reports/$country_code"
done
```

**What you get**:
- Country-by-country vulnerability breakdown
- Trend analysis across regions
- Research-ready data formats
- Comparative security posture insights

### 3. CI/CD Pipeline Integration

**Scenario**: Integrate security scanning into your build pipeline.

```bash
# In your CI script (.github/workflows, Jenkins, etc.)
node retire-analyzer.js ./src --severity high --format json

# Exit with error code if high-severity vulnerabilities found
if [ $(jq '.summary.severityBreakdown.high' ./retire-analysis/vulnerability-report.json) -gt 0 ]; then
    echo "❌ High severity vulnerabilities found. Build failed."
    exit 1
fi
```

**What you get**:
- Automated security gates
- JSON output for pipeline processing
- Build failure on critical issues
- Security metrics tracking

### 4. Library Risk Assessment

**Scenario**: Evaluating third-party JavaScript libraries before adoption.

```bash
# Analyze a specific library or vendor directory
node retire-analyzer.js ./node_modules/bootstrap --format all

# Compare multiple library versions
mkdir library-comparison
for version in 4.3.1 4.5.0 5.0.0; do
    node retire-analyzer.js "./libs/bootstrap-$version" --output "./library-comparison/bootstrap-$version"
done
```

**What you get**:
- Library-specific vulnerability profiles
- Version comparison data
- Risk-informed adoption decisions
- Vendor security assessment

### 5. Periodic Security Monitoring

**Scenario**: Regular monitoring of production applications.

```bash
#!/bin/bash
# weekly-security-scan.sh

DATE=$(date +%Y-%m-%d)
REPORT_DIR="./security-reports/$DATE"

# Scan production assets
node retire-analyzer.js /var/www/production/assets --output "$REPORT_DIR"

# Archive previous reports
tar -czf "security-reports-$DATE.tar.gz" "$REPORT_DIR"

# Send alert if high-severity issues found
HIGH_COUNT=$(jq '.summary.severityBreakdown.high' "$REPORT_DIR/vulnerability-report.json")
if [ "$HIGH_COUNT" -gt 0 ]; then
    # Send notification (email, Slack, etc.)
    echo "🚨 Security Alert: $HIGH_COUNT high-severity vulnerabilities found"
fi
```

**What you get**:
- Historical vulnerability tracking
- Automated alerting
- Trend analysis over time
- Proactive security monitoring

## Advanced Usage Patterns

### Batch Processing Multiple Directories

```bash
#!/bin/bash
# Process multiple project directories

PROJECTS=(
    "/home/user/project1/js"
    "/home/user/project2/assets" 
    "/home/user/project3/static/js"
)

for project in "${PROJECTS[@]}"; do
    project_name=$(basename "$(dirname "$project")")
    echo "🔍 Analyzing $project_name..."
    
    node retire-analyzer.js "$project" \
        --output "./reports/$project_name" \
        --format all \
        --severity all
        
    echo "✅ $project_name analysis complete"
done

# Generate combined summary
echo "📊 Generating combined report..."
# Custom script to merge multiple JSON reports
```

### Filtering and Custom Analysis

```bash
# Only analyze specific file patterns
find ./js-files -name "*.min.js" -exec dirname {} \; | sort -u | while read dir; do
    node retire-analyzer.js "$dir" --output "./minified-analysis/$(basename "$dir")"
done

# Focus on specific libraries
node retire-analyzer.js ./vendor-libs --format csv | grep -E "(bootstrap|jquery|lodash)"

# Time-based analysis (files modified in last 30 days)
find ./src -name "*.js" -mtime -30 -exec dirname {} \; | sort -u | while read recent_dir; do
    node retire-analyzer.js "$recent_dir" --output "./recent-changes-analysis"
done
```

### Integration with Other Tools

```bash
# Combine with npm audit for comprehensive analysis
npm audit --json > npm-audit.json
node retire-analyzer.js ./src --format json

# Merge with OWASP Dependency Check
# Custom script to correlate findings across tools

# Integration with security dashboards
curl -X POST "https://security-dashboard.company.com/api/vulnerabilities" \
     -H "Content-Type: application/json" \
     -d @./retire-analysis/vulnerability-report.json
```

## Output Analysis Examples

### JSON Report Processing

```bash
# Extract high-severity vulnerabilities
jq '.vulnerabilities[] | select(.severity == "high")' vulnerability-report.json

# Count vulnerabilities by library
jq '.summary.libraryBreakdown' vulnerability-report.json

# Find files with most vulnerabilities
jq -r '.vulnerabilities | group_by(.file) | map({file: .[0].file, count: length}) | sort_by(.count) | reverse | .[0:5]' vulnerability-report.json

# Generate trending report
jq -r '.vulnerabilities[] | [.library, .version, .severity, .cve] | @csv' vulnerability-report.json
```

### CSV Report Analysis

```bash
# Sort by severity in spreadsheet applications
# Filter by specific time periods
# Create pivot tables for vulnerability trends
# Generate charts for executive reporting

# Command-line CSV processing
csvstat vulnerability-report.csv --freq Severity
csvgrep -c Library -m "bootstrap" vulnerability-report.csv
```

### HTML Report Customization

The HTML reports are self-contained and can be:
- Hosted on internal wikis or portals
- Shared with stakeholders via email
- Archived for compliance purposes
- Customized with company branding

## Performance Optimization

### Large Dataset Processing

```bash
# Process in parallel (GNU parallel required)
find ./large-dataset -type d -name "*js*" | parallel -j4 node retire-analyzer.js {} --output ./results/{/.}

# Memory-efficient processing for huge datasets
ulimit -v 2097152  # Limit memory usage
node --max-old-space-size=4096 retire-analyzer.js ./huge-dataset
```

### Incremental Analysis

```bash
# Only analyze changed files
git diff --name-only --diff-filter=AM HEAD~1 | grep "\.js$" | xargs -I {} dirname {} | sort -u | while read changed_dir; do
    node retire-analyzer.js "$changed_dir" --output "./incremental-reports/$(date +%Y%m%d)"
done
```

## Troubleshooting Examples

### Common Issues and Solutions

```bash
# Issue: Too many files, analysis takes forever
# Solution: Exclude unnecessary directories
node retire-analyzer.js ./src --format json 2>/dev/null | grep -v "node_modules\|vendor\|dist"

# Issue: Permission denied on output directory  
# Solution: Use home directory or create writable location
mkdir -p ~/security-reports
node retire-analyzer.js ./src --output ~/security-reports

# Issue: RetireJS not finding vulnerabilities in minified files
# Solution: Include source maps or analyze pre-build files
node retire-analyzer.js ./src-unminified --output ./detailed-analysis

# Issue: Need to exclude false positives
# Solution: Post-process the JSON output
jq 'del(.vulnerabilities[] | select(.cve == "CVE-2021-23337"))' vulnerability-report.json > filtered-report.json
```

### Validation and Quality Checks

```bash
# Verify reports were generated correctly
ls -la ./retire-analysis/
file ./retire-analysis/*

# Check JSON validity
jq . ./retire-analysis/vulnerability-report.json >/dev/null && echo "Valid JSON" || echo "Invalid JSON"

# Validate CSV format
csvclean ./retire-analysis/vulnerability-report.csv

# Test HTML rendering
python3 -m http.server 8000 --directory ./retire-analysis
# Visit http://localhost:8000/vulnerability-report.html
```

## Best Practices

1. **Regular Scanning**: Set up automated weekly or monthly scans
2. **Version Control**: Track security reports alongside code changes
3. **Prioritization**: Focus on high-severity vulnerabilities first
4. **Documentation**: Maintain remediation logs and decision records
5. **Integration**: Combine with other security tools for comprehensive coverage
6. **Archiving**: Keep historical reports for trend analysis and compliance