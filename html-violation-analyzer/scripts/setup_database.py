#!/usr/bin/env python3
"""
Database Setup Script for HTML Violation Analyzer

This script initializes the database and creates necessary tables.
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database import create_my_engine, create_database, get_session
from database import CheckerRule
from checker import rules
import yaml

def load_config(config_path="config.yml"):
    """Load configuration from YAML file"""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Config file not found: {config_path}")
        print("Please copy config/example.yml to config.yml and customize it.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing config file: {e}")
        sys.exit(1)

def setup_database():
    """Initialize database and create tables"""
    print("Setting up database...")
    
    try:
        # Create engine and tables
        create_my_engine()
        create_database()
        print("✓ Database tables created successfully")
        
        # Test connection
        session = get_session()
        session.close()
        print("✓ Database connection test passed")
        
    except Exception as e:
        print(f"✗ Database setup failed: {e}")
        sys.exit(1)

def setup_rules(config):
    """Initialize validation rules in the database"""
    print("Setting up validation rules...")
    
    try:
        session = get_session()
        applied_rules = config.get("checker", {}).get("rules", [])
        
        for rule_name in applied_rules:
            # Check if rule exists in code
            rule_class = getattr(rules, rule_name, None)
            if not rule_class:
                print(f"Warning: Rule {rule_name} not found in rules module")
                continue
            
            # Check if rule already exists in database
            existing_rule = session.query(CheckerRule).filter(
                CheckerRule.name == rule_name
            ).first()
            
            if existing_rule:
                print(f"  - Rule {rule_name} already exists")
                continue
            
            # Create new rule
            checker_rule = CheckerRule(
                name=rule_name,
                name_informal=getattr(rule_class, 'name_informal', rule_name),
                description=getattr(rule_class, 'description', f"Rule {rule_name}")
            )
            session.add(checker_rule)
            print(f"  + Added rule {rule_name}")
        
        session.commit()
        session.close()
        print(f"✓ Rules setup completed ({len(applied_rules)} rules configured)")
        
    except Exception as e:
        print(f"✗ Rules setup failed: {e}")
        if 'session' in locals():
            session.rollback()
            session.close()
        sys.exit(1)

def create_output_directories():
    """Create necessary output directories"""
    print("Creating output directories...")
    
    directories = [
        "data/output/plots",
        "data/output/reports", 
        "data/output/logs",
        "data/input",
        "data/sample"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Created {directory}")

def main():
    """Main setup function"""
    print("HTML Violation Analyzer - Database Setup")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    
    # Setup steps
    setup_database()
    setup_rules(config)
    create_output_directories()
    
    print("\n" + "=" * 50)
    print("✓ Setup completed successfully!")
    print("\nNext steps:")
    print("1. Place your HTML files in data/input/")
    print("2. Run: python main.py --module local_files --country [COUNTRY_CODE]")
    print("3. Generate reports: python analyze_db.py results.db")
    print("\nFor more information, see docs/usage.md")

if __name__ == "__main__":
    main()
