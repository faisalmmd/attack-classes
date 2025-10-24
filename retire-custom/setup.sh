#!/bin/bash

echo "🔧 Setting up RetireJS Analyzer..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    echo "   Visit: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js found: $(node --version)"

# Check if npm is available
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not available. Please install npm first."
    exit 1
fi

echo "✅ npm found: $(npm --version)"

# Install retire globally if not already installed
if ! command -v retire &> /dev/null; then
    echo "📦 Installing RetireJS globally..."
    npm install -g retire
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install RetireJS. Please check your permissions."
        echo "   You might need to run: sudo npm install -g retire"
        exit 1
    fi
else
    echo "✅ RetireJS already installed: $(retire --version 2>&1 | head -1)"
fi

# Make the analyzer executable
chmod +x retire-analyzer.js

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📚 Quick start:"
echo "   ./retire-analyzer.js --help"
echo "   ./retire-analyzer.js /path/to/js/files"
echo ""
echo "📊 Example commands:"
echo "   # Analyze current directory with all reports"
echo "   ./retire-analyzer.js"
echo ""
echo "   # High severity only, HTML report"
echo "   ./retire-analyzer.js --severity high --format html"
echo ""
echo "   # Analyze specific directory"
echo "   ./retire-analyzer.js /path/to/your/js/dataset"
echo ""