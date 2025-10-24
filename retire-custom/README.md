# RetireJS Analyzer 

An enhanced wrapper around the [RetireJS](https://retirejs.github.io/retire.js/) vulnerability scanner that provides organized, detailed reporting for large-scale JavaScript security analysis.

> **Built on top of RetireJS by [Erlend Oftedal](https://github.com/eoftedal)**

## Quick Start

```bash
# Install dependencies
npm install

# Run analysis on current directory
node path/to/js/analyzer/retire-analyzer.js

# Analyze specific directory
node retire-analyzer.js /path/to/your/js/files

# Generate only HTML report with high severity vulnerabilities
node retire-analyzer.js --format html --severity high
```

## Prerequisites

- Node.js (v12 or higher)
- **RetireJS** installed globally: `npm install -g retire`
  - *Credit: RetireJS is created and maintained by [Erlend Oftedal](https://github.com/erlend-oftedal)*

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Make sure RetireJS is installed globally:
   ```bash
   npm install -g retire
   ```

## Usage

### Basic Usage

```bash
# Analyze current directory
node retire-analyzer.js

# Analyze specific path
node retire-analyzer.js /path/to/javascript/files
```

### Advanced Options

```bash
# Specify output directory
node retire-analyzer.js --output ./security-reports

# Generate specific report format
node retire-analyzer.js --format json
node retire-analyzer.js --format csv  
node retire-analyzer.js --format html
node retire-analyzer.js --format all  # default

# Filter by severity level
node retire-analyzer.js --severity high
node retire-analyzer.js --severity medium
node retire-analyzer.js --severity low
node retire-analyzer.js --severity all  # default

# Combined options
node retire-analyzer.js /path/to/files --output ./reports --format html --severity high
```

### Command Line Options

| Option | Short | Description | Default |
|--------|--------|-------------|---------|
| `--output` | `-o` | Output directory for reports | `./retire-analysis` |
| `--format` | `-f` | Report format: `json`, `csv`, `html`, `all` | `all` |
| `--severity` | `-s` | Filter by severity: `low`, `medium`, `high`, `all` | `all` |
| `--help` | `-h` | Show help message | - |

## Output Reports

The tool generates three types of reports in your specified output directory:

### 1. JSON Report (`vulnerability-report.json`)
- Machine-readable structured data
- Complete vulnerability details
- Summary statistics
- Perfect for further processing or integration

### 2. CSV Report (`vulnerability-report.csv`)
- Spreadsheet-compatible format
- Easy to filter and sort in Excel/Google Sheets
- Columns: File, Library, Version, Severity, CVE, Summary, URLs

### 3. HTML Report (`vulnerability-report.html`)
- Beautiful, interactive web report
- Visual severity indicators
- Clickable CVE links
- Summary dashboard with statistics
- Mobile-responsive design

## What You Get

### Summary Statistics
- Total files scanned
- Number of vulnerable files
- Total vulnerabilities found
- Breakdown by severity (High/Medium/Low)
- Most vulnerable libraries identified

### Detailed Vulnerability Information
- **File Path**: Exact location of vulnerable JavaScript
- **Library & Version**: Identified vulnerable dependency
- **Severity Level**: Risk assessment (High/Medium/Low)
- **CVE References**: Direct links to vulnerability databases
- **Description**: Human-readable vulnerability summary
- **Reference URLs**: Additional security resources

## Use Cases

### Security Auditing
```bash
# Generate comprehensive security report
node retire-analyzer.js /path/to/web/assets --output ./security-audit-2024
```

### CI/CD Integration
```bash
# Focus on high-severity issues for build pipeline
node retire-analyzer.js --severity high --format json
```

### Research & Analysis
```bash
# Analyze large dataset with detailed reporting
node retire-analyzer.js /research/js-dataset --format all
```

### Quick Triage
```bash
# Get HTML report for easy review
node retire-analyzer.js --format html
```

## Example Output

### Console Summary
```
Starting RetireJS vulnerability analysis...
Analyzing: /home/user/js-files
Analysis complete!

ANALYSIS SUMMARY
==================
Total files scanned: 1,247
Vulnerable files: 23
Total vulnerabilities: 31
Severity breakdown:
  🔴 High: 5
  🟡 Medium: 18
  🟢 Low: 8

Most vulnerable libraries:
  📦 bootstrap: 12 vulnerabilities
  📦 jquery: 8 vulnerabilities
  📦 lodash: 6 vulnerabilities

Reports saved to: /home/user/retire-analysis
```

### File Structure After Analysis
```
retire-analysis/
├── vulnerability-report.json    # Structured data
├── vulnerability-report.csv     # Spreadsheet format
└── vulnerability-report.html    # Interactive report
```

## Customization

You can modify the `RetireAnalyzer` class to add:

- **Custom filtering logic**: Filter by specific libraries or CVE patterns
- **Additional output formats**: XML, SARIF, or custom formats
- **Integration hooks**: Webhook notifications, database storage
- **Enhanced parsing**: Support for different RetireJS output formats

### Programmatic Usage

```javascript
const RetireAnalyzer = require('./retire-analyzer');

const analyzer = new RetireAnalyzer({
    outputDir: './custom-reports',
    format: 'json',
    severity: 'high'
});

analyzer.run('/path/to/analyze');
```

## Troubleshooting

### Common Issues

**"retire: command not found"**
```bash
npm install -g retire
```

**Permission denied on output directory**
```bash
chmod +w ./retire-analysis
# or use a different output directory
node retire-analyzer.js --output ~/reports
```

**Large dataset timeouts**
- The tool includes a 10MB buffer for large outputs
- For extremely large datasets, consider analyzing in smaller batches

**Empty reports generated**
- Ensure RetireJS is properly installed
- Verify the target path contains JavaScript files
- Check that retire.js can access the files

### Debug Mode

Add debug logging by modifying the script or check RetireJS directly:
```bash
retire --path /your/path --outputformat text
```

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **Built on top of [RetireJS](https://retirejs.github.io/retire.js/)** - The excellent vulnerability scanner that powers this tool
- **Created and maintained by [Erlend Oftedal](https://github.com/erlend-oftedal)** - Thank you for building and maintaining RetireJS
- **RetireJS Community** - For maintaining the comprehensive vulnerability database
- Inspired by the need for better security tooling in large-scale JavaScript analysis
- Special thanks to the OWASP community for recognizing "Using Components with Known Vulnerabilities" as a critical security risk

## Related Tools

- **[RetireJS](https://retirejs.github.io/retire.js/)** - The underlying vulnerability scanner (⭐ **Give them a star!**)
- **[RetireJS Repository](https://github.com/RetireJS/retire.js)** - Source code and issues
- **[RetireJS Vulnerability Database](https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository.json)** - The comprehensive vulnerability data
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Node.js package vulnerability checker
- [Snyk](https://snyk.io/) - Commercial security platform
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) - Multi-language dependency scanner

---
