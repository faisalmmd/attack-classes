#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class RetireAnalyzer {
    constructor(options = {}) {
        this.options = {
            outputDir: options.outputDir || './retire-analysis',
            format: options.format || 'all', // 'json', 'csv', 'html', 'all'
            severity: options.severity || 'all', // 'low', 'medium', 'high', 'all'
            includeDetails: options.includeDetails !== false,
            ...options
        };
        
        this.results = {
            summary: {
                totalFiles: 0,
                vulnerableFiles: 0,
                totalVulnerabilities: 0,
                severityBreakdown: { low: 0, medium: 0, high: 0 },
                libraryBreakdown: {}
            },
            vulnerabilities: []
        };
    }

    run(targetPath = '.') {
        console.log('🔍 Starting RetireJS vulnerability analysis...');
        
        try {
            // Ensure output directory exists
            if (!fs.existsSync(this.options.outputDir)) {
                fs.mkdirSync(this.options.outputDir, { recursive: true });
            }

            // Run retire.js and capture output
            console.log(`📁 Analyzing: ${path.resolve(targetPath)}`);
            const retireOutput = this.runRetire(targetPath);
            
            // Parse the output
            this.parseRetireOutput(retireOutput);
            
            // Generate reports
            this.generateReports();
            
            console.log('✅ Analysis complete!');
            this.printSummary();
            
        } catch (error) {
            console.error('❌ Error during analysis:', error.message);
            process.exit(1);
        }
    }

    runRetire(targetPath) {
        try {
            const command = `retire --path "${targetPath}" --outputformat text`;
            return execSync(command, { 
                encoding: 'utf8',
                maxBuffer: 1024 * 1024 * 10 // 10MB buffer
            });
        } catch (error) {
            // retire.js exits with code 13 when vulnerabilities are found
            if (error.status === 13) {
                return error.stdout || '';
            }
            throw new Error(`Failed to run retire.js: ${error.message}`);
        }
    }

    parseRetireOutput(output) {
        const lines = output.split('\n').filter(line => line.trim());
        let currentFile = null;
        
        for (const line of lines) {
            // Skip header lines
            if (line.includes('retire.js v') || line.includes('Downloading')) {
                continue;
            }
            
            // File path line (doesn't start with space or arrow)
            if (!line.startsWith(' ') && !line.startsWith('↳') && line.includes('.js')) {
                currentFile = line.trim();
                this.results.summary.totalFiles++;
                continue;
            }
            
            // Library detection line (starts with ↳)
            if (line.startsWith(' ↳')) {
                const libraryInfo = line.replace(' ↳ ', '').trim();
                continue;
            }
            
            // Vulnerability details line
            if (line.includes('has known vulnerabilities:') && currentFile) {
                this.parseVulnerabilityLine(line, currentFile);
            }
        }
    }

    parseVulnerabilityLine(line, filePath) {
        try {
            // Extract library and version
            const libMatch = line.match(/^(.+?)\s+has known vulnerabilities:/);
            if (!libMatch) return;
            
            const [libraryName, version] = libMatch[1].split(' ');
            
            // Extract vulnerability details
            const details = line.split('has known vulnerabilities: ')[1];
            const severity = this.extractSeverity(details);
            const summary = this.extractSummary(details);
            const cve = this.extractCVE(details);
            const urls = this.extractUrls(details);
            
            const vulnerability = {
                file: filePath,
                library: libraryName,
                version: version,
                severity: severity,
                summary: summary,
                cve: cve,
                urls: urls,
                timestamp: new Date().toISOString()
            };
            
            // Filter by severity if specified
            if (this.options.severity !== 'all' && severity !== this.options.severity) {
                return;
            }
            
            this.results.vulnerabilities.push(vulnerability);
            this.updateSummaryStats(vulnerability);
            
        } catch (error) {
            console.warn(`⚠️  Failed to parse vulnerability line: ${line.substring(0, 100)}...`);
        }
    }

    extractSeverity(details) {
        const match = details.match(/severity:\s*(\w+)/);
        return match ? match[1] : 'unknown';
    }

    extractSummary(details) {
        const match = details.match(/summary:\s*([^,;]+)/);
        return match ? match[1].trim() : 'No summary available';
    }

    extractCVE(details) {
        const match = details.match(/CVE:\s*(CVE-\d{4}-\d+)/);
        return match ? match[1] : null;
    }

    extractUrls(details) {
        const urlRegex = /https?:\/\/[^\s]+/g;
        return details.match(urlRegex) || [];
    }

    updateSummaryStats(vulnerability) {
        this.results.summary.totalVulnerabilities++;
        this.results.summary.severityBreakdown[vulnerability.severity]++;
        
        if (!this.results.summary.libraryBreakdown[vulnerability.library]) {
            this.results.summary.libraryBreakdown[vulnerability.library] = 0;
        }
        this.results.summary.libraryBreakdown[vulnerability.library]++;
        
        // Count unique vulnerable files
        const vulnerableFiles = new Set(this.results.vulnerabilities.map(v => v.file));
        this.results.summary.vulnerableFiles = vulnerableFiles.size;
    }

    generateReports() {
        if (this.options.format === 'all' || this.options.format === 'json') {
            this.generateJSONReport();
        }
        
        if (this.options.format === 'all' || this.options.format === 'csv') {
            this.generateCSVReport();
        }
        
        if (this.options.format === 'all' || this.options.format === 'html') {
            this.generateHTMLReport();
        }
    }

    generateJSONReport() {
        const reportPath = path.join(this.options.outputDir, 'vulnerability-report.json');
        fs.writeFileSync(reportPath, JSON.stringify(this.results, null, 2));
        console.log(`📄 JSON report saved: ${reportPath}`);
    }

    generateCSVReport() {
        const reportPath = path.join(this.options.outputDir, 'vulnerability-report.csv');
        const headers = ['File', 'Library', 'Version', 'Severity', 'CVE', 'Summary', 'URLs'];
        
        const csvContent = [
            headers.join(','),
            ...this.results.vulnerabilities.map(v => [
                `"${v.file}"`,
                v.library,
                v.version,
                v.severity,
                v.cve || '',
                `"${v.summary}"`,
                `"${v.urls.join('; ')}"`
            ].join(','))
        ].join('\n');
        
        fs.writeFileSync(reportPath, csvContent);
        console.log(`📊 CSV report saved: ${reportPath}`);
    }

    generateHTMLReport() {
        const reportPath = path.join(this.options.outputDir, 'vulnerability-report.html');
        const html = this.createHTMLReport();
        fs.writeFileSync(reportPath, html);
        console.log(`🌐 HTML report saved: ${reportPath}`);
    }

    createHTMLReport() {
        const { summary, vulnerabilities } = this.results;
        
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RetireJS Vulnerability Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2em; font-weight: bold; color: #333; }
        .stat-label { color: #666; margin-top: 5px; }
        .severity-high { border-left-color: #dc3545; }
        .severity-medium { border-left-color: #ffc107; }
        .severity-low { border-left-color: #28a745; }
        .vulnerabilities-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .vulnerabilities-table th, .vulnerabilities-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .vulnerabilities-table th { background: #f8f9fa; font-weight: 600; }
        .severity-badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.85em; font-weight: 500; }
        .severity-badge.high { background: #dc3545; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #28a745; }
        .file-path { font-family: monospace; font-size: 0.9em; color: #666; }
        .library-name { font-weight: 500; color: #333; }
        .cve-link { color: #007bff; text-decoration: none; }
        .cve-link:hover { text-decoration: underline; }
        .section-title { font-size: 1.5em; margin: 30px 0 15px 0; color: #333; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 RetireJS Security Analysis Report</h1>
            <p>Generated on ${new Date().toLocaleString()}</p>
        </div>
        
        <div class="content">
            <h2 class="section-title">📊 Summary</h2>
            <div class="summary">
                <div class="stat-card">
                    <div class="stat-number">${summary.totalFiles}</div>
                    <div class="stat-label">Total Files Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${summary.vulnerableFiles}</div>
                    <div class="stat-label">Vulnerable Files</div>
                </div>
                <div class="stat-card severity-high">
                    <div class="stat-number">${summary.severityBreakdown.high}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card severity-medium">
                    <div class="stat-number">${summary.severityBreakdown.medium}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-card severity-low">
                    <div class="stat-number">${summary.severityBreakdown.low}</div>
                    <div class="stat-label">Low Severity</div>
                </div>
            </div>

            <h2 class="section-title">🚨 Vulnerabilities</h2>
            ${vulnerabilities.length === 0 ? '<p>🎉 No vulnerabilities found matching your criteria!</p>' : `
            <table class="vulnerabilities-table">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Library</th>
                        <th>Version</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilities.map(v => `
                    <tr>
                        <td><div class="file-path">${v.file}</div></td>
                        <td><div class="library-name">${v.library}</div></td>
                        <td>${v.version}</td>
                        <td><span class="severity-badge ${v.severity}">${v.severity.toUpperCase()}</span></td>
                        <td>${v.cve ? `<a href="https://nvd.nist.gov/vuln/detail/${v.cve}" class="cve-link" target="_blank">${v.cve}</a>` : '-'}</td>
                        <td>${v.summary}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
            `}
        </div>
    </div>
</body>
</html>`;
    }

    printSummary() {
        const { summary } = this.results;
        console.log('\n📊 ANALYSIS SUMMARY');
        console.log('==================');
        console.log(`Total files scanned: ${summary.totalFiles}`);
        console.log(`Vulnerable files: ${summary.vulnerableFiles}`);
        console.log(`Total vulnerabilities: ${summary.totalVulnerabilities}`);
        console.log(`Severity breakdown:`);
        console.log(`  🔴 High: ${summary.severityBreakdown.high}`);
        console.log(`  🟡 Medium: ${summary.severityBreakdown.medium}`);
        console.log(`  🟢 Low: ${summary.severityBreakdown.low}`);
        
        if (Object.keys(summary.libraryBreakdown).length > 0) {
            console.log(`\nMost vulnerable libraries:`);
            const sortedLibraries = Object.entries(summary.libraryBreakdown)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 5);
            
            sortedLibraries.forEach(([lib, count]) => {
                console.log(`  📦 ${lib}: ${count} vulnerabilities`);
            });
        }
        
        console.log(`\n📁 Reports saved to: ${path.resolve(this.options.outputDir)}`);
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const options = {};
    let targetPath = '.';
    
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const nextArg = args[i + 1];
        
        switch (arg) {
            case '--output':
            case '-o':
                options.outputDir = nextArg;
                i++;
                break;
            case '--format':
            case '-f':
                options.format = nextArg;
                i++;
                break;
            case '--severity':
            case '-s':
                options.severity = nextArg;
                i++;
                break;
            case '--help':
            case '-h':
                console.log(`
RetireJS Analyzer - Enhanced vulnerability scanning and reporting

USAGE:
    node retire-analyzer.js [PATH] [OPTIONS]

OPTIONS:
    -o, --output DIR     Output directory for reports (default: ./retire-analysis)
    -f, --format FORMAT  Report format: json, csv, html, all (default: all)
    -s, --severity LEVEL Filter by severity: low, medium, high, all (default: all)
    -h, --help          Show this help message

EXAMPLES:
    node retire-analyzer.js                           # Analyze current directory
    node retire-analyzer.js /path/to/js/files         # Analyze specific path
    node retire-analyzer.js --format html             # Generate only HTML report
    node retire-analyzer.js --severity high           # Show only high severity
`);
                process.exit(0);
                break;
            default:
                if (!arg.startsWith('-')) {
                    targetPath = arg;
                }
        }
    }
    
    const analyzer = new RetireAnalyzer(options);
    analyzer.run(targetPath);
}

module.exports = RetireAnalyzer;
