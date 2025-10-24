# HTML Violation Analyzer

A comprehensive web compliance analysis system that crawls websites and checks them against various validation rules. Built upon the foundational work from the [IMC 2022 paper](https://swag.cispa.saarland/papers/hantke2022violations.pdf) "HTML Violations and Where to Find Them: A Longitudinal Analysis of Specification Violations in HTML" by Florian Hantke.

This enhanced version extends the original [HTML Violations Analyzer](https://github.com/cispa/html-violations-analyzer) with advanced analytics, visualization capabilities, and expanded data source support including local HTML files with country-based filtering.

## Features

- **Multi-Source Crawling**: Support for Common Crawl, live websites, and local HTML files
- **Country-Based Filtering**: Analyze websites by country codes
- **Rule-Based Validation**: Extensible rule system for various compliance checks
- **Advanced Analytics**: Comprehensive violation trend analysis with visualizations
- **Multi-Processing**: Parallel processing for efficient large-scale analysis
- **Database Integration**: SQLite and PostgreSQL support
- **Rich Reporting**: Automated generation of plots, reports, and executive summaries

## Supported Validation Rules

- **FB2**: Facebook integration compliance
- **DM3**: Data management standards
- **DE3_1**: Data extraction validation
- **HF1**: HTML form structure validation
- **HF4**: HTML form accessibility compliance
- add others as required

## Installation

### Prerequisites

- Python 3.8 or higher
- SQLite or PostgreSQL database
- Git

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/html-violation-analyzer.git
   cd html-violation-analyzer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system**
   ```bash
   cp config/example.yml config.yml
   # Edit config.yml with your settings
   ```

4. **Initialize the database**
   ```bash
   python scripts/setup_database.py
   ```

## Usage

### Basic Analysis

Analyze local HTML files for a specific country:

```bash
python main.py --module local_files --country UA
```

### Live Website Crawling

Crawl live websites from a URL list:

```bash
python main.py --module dynamic --urls urls.txt
```

### Common Crawl Analysis

Analyze data from Common Crawl archives:

```bash
python main.py --module common_crawl --files crawl_data.txt
```

### Generate Comprehensive Reports

After running analysis, generate detailed visualizations:

```bash
python analyze_db.py results.db
```

## Output

The system generates several types of output:

### Visualizations (in `data/output/plots/`)
- **Executive Summary**: High-level overview dashboard
- **Country Trends**: Country-specific violation trends over time
- **Rule Analysis**: Performance analysis for each validation rule
- **Correlation Matrix**: How different rules correlate with each other
- **Temporal Patterns**: Time-based violation patterns

### Reports (in `data/output/reports/`)
- **Country-Year Trends**: CSV with violation rates by country and year
- **Rule Performance**: Detailed rule-by-rule analysis
- **Domain Violations**: Website-specific violation reports
- **Yearly Progression**: Year-over-year changes

### Database
- All results stored in SQLite/PostgreSQL for further analysis
- Structured data with proper relationships between websites, rules, and results

## Configuration

Edit `config.yml` to customize:

```yaml
general:
  log_level: DEBUG
  output: ./data/output/
  mode: PROD
  number_crawler_processes: 4
  number_checker_processes: 2

database:
  type: sqlite
  name: results.db

checker:
  rules:
    - FB2
    - DM3
    - DE3_1
    - HF1
    - HF4
```

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Crawlers  │───▶│  Checkers   │───▶│  Database   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Local Files  │    │Rule Engine │    │ Analytics   │
│Common Crawl │    │Multi-rules │    │Visualizations│
│Live Sites   │    │Parallel    │    │   Reports   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Components

- **Crawlers**: Extract HTML content from various sources
- **Checkers**: Apply validation rules to crawled content
- **Database**: Store results with proper relationships
- **Analytics**: Generate insights and visualizations

## Testing

Run the test suite:

```bash
python -m pytest tests/
```

Run specific test categories:

```bash
# Test crawlers
python -m pytest tests/test_crawler.py

# Test checkers
python -m pytest tests/test_checker.py

# Test database operations
python -m pytest tests/test_database.py
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Usage Examples](docs/usage.md)
- [Configuration Reference](docs/configuration.md)
- [Rule Documentation](docs/rules.md)
- [API Reference](docs/api.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License, maintaining compatibility with the original work.

**Original Copyright**: Copyright 2022 Florian Hantke  
**Enhanced Version**: [Your copyright notice]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgments

### Original Work
This project builds upon the excellent foundation laid by **Florian Hantke** and the CISPA Helmholtz Center for Information Security. The original HTML violations analyzer was developed as part of groundbreaking research published in:

**"HTML Violations and Where to Find Them: A Longitudinal Analysis of Specification Violations in HTML"**  
*IMC 2022 - Internet Measurement Conference*  
[Paper](https://swag.cispa.saarland/papers/hantke2022violations.pdf) | [💻 Original Repository](https://github.com/cispa/html-violations-analyzer)

### Key Contributions from Original Work
- **Common Crawl Integration**: Innovative use of Common Crawl archives for large-scale web analysis
- **Modular Architecture**: Extensible crawler and checker system design
- **Rule-Based Validation**: Framework for defining and applying HTML validation rules
- **Database Integration**: Structured storage and retrieval of violation data
- **Research Methodology**: Scientific approach to longitudinal web compliance analysis

### Enhancements in This Version
Building on the solid foundation, this version adds:
- **Advanced Analytics**: Comprehensive violation trend analysis with statistical insights
- **Rich Visualizations**: Executive dashboards, heatmaps, correlation matrices, and temporal analysis
- **Local File Support**: Enhanced local HTML file processing with country-based filtering
- **Improved Database**: Enhanced database models with better relationship handling
- **Modern Tooling**: Updated dependencies, GitHub Actions CI/CD, and comprehensive documentation
- **Extended Reporting**: CSV exports, detailed reports, and publication-ready visualizations

### Research Impact
The original work has been instrumental in understanding HTML specification compliance across the web. This enhanced version aims to make these powerful analysis tools more accessible to researchers, developers, and compliance teams.

### Credits
- **Original Author**: Florian Hantke (CISPA Helmholtz Center for Information Security)
- **Original License**: MIT License (maintained in this derivative work)
- **Enhancement Development**: [Your name/organization]
- **Common Crawl Project**: For providing web archive data
- **Open Source Community**: For the excellent libraries and tools that make this work possible

## Support & Citations

### Academic Citations
If you use this tool in academic research, please cite the original work:

```bibtex
@inproceedings{hantke2022violations,
  title={HTML Violations and Where to Find Them: A Longitudinal Analysis of Specification Violations in HTML},
  author={Hantke, Florian},
  booktitle={Proceedings of the 22nd ACM Internet Measurement Conference},
  year={2022},
  organization={ACM}
}
```

### Support Channels
- **Issues**: [GitHub Issues](https://github.com/skymasterfm/html-violation-analyzer/issues)
- **Documentation**: [Project Wiki](https://github.com/skymasterfm/html-violation-analyzer/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/skymasterfm/html-violation-analyzer/discussions)
- **Original Research**: [IMC 2022 Paper](https://swag.cispa.saarland/papers/hantke2022violations.pdf)

---

**Note**: This tool is designed for research and compliance analysis purposes. Please ensure you have proper permissions before crawling live websites and respect robots.txt files.