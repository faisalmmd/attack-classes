import yaml
import os
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, create_engine
from sqlalchemy.orm import relationship, declarative_base, sessionmaker, scoped_session

Base = declarative_base()
engine = None
SessionFactory = None

def create_my_engine():
    """Initialize the database engine from config"""
    global engine, SessionFactory
    
    config_path = os.environ.get("CONFIG_YML", "config.yml")
    
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        raise Exception(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise Exception(f"Error parsing config file: {e}")

    db_cfg = config.get("database", {})
    db_type = db_cfg.get("type", "sqlite")

    if db_type == "sqlite":
        db_path = db_cfg.get("name", "results.db")
        # Use absolute path to avoid issues with relative paths
        if not os.path.isabs(db_path):
            db_path = os.path.abspath(db_path)
        
        engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
            connect_args={'check_same_thread': False}
        )
        print(f"SQLite database engine created: {db_path}")
        
    elif db_type == "postgres":
        required_fields = ["user", "password", "host", "port", "dbname"]
        for field in required_fields:
            if field not in db_cfg:
                raise ValueError(f"Missing required PostgreSQL config: {field}")
                
        user = db_cfg["user"]
        password = db_cfg["password"]
        host = db_cfg["host"]
        port = db_cfg["port"]
        dbname = db_cfg["dbname"]
        
        engine = create_engine(
            f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{dbname}",
            echo=False,
            pool_pre_ping=True
        )
        print(f"PostgreSQL database engine created: {host}:{port}/{dbname}")
        
    else:
        raise ValueError(f"Unsupported database type: {db_type}")
    
    # Create session factory
    SessionFactory = sessionmaker(bind=engine)
    
    return engine

def get_session():
    """Get a database session with proper error handling"""
    global engine, SessionFactory
    
    # Ensure engine is initialized
    if engine is None or SessionFactory is None:
        print("Engine not initialized, creating...")
        create_my_engine()
    
    if engine is None:
        raise Exception("Failed to create database engine")
    
    try:
        # Create scoped session for thread safety
        database_session = scoped_session(SessionFactory)
        return database_session
    except Exception as e:
        print(f"Error creating database session: {e}")
        raise Exception(f"Database session creation failed: {e}")

def create_database():
    """Create database tables with proper error handling"""
    global engine
    
    if engine is None:
        create_my_engine()
    
    if engine is None:
        raise Exception("Cannot create database: engine is None")
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully")
        
        # Test session creation
        session = get_session()
        session.commit()
        session.close()
        print("Database initialization completed")
        
    except Exception as e:
        print(f"Error creating database: {e}")
        raise Exception(f"Database creation failed: {e}")

def close_engine():
    """Properly close the database engine"""
    global engine
    if engine:
        engine.dispose()
        print("Database engine disposed")

class CheckerResult(Base):
    __tablename__ = 'checker_results'

    rule_id = Column(Integer, ForeignKey('checker_rule.id'), primary_key=True)
    website_id = Column(Integer, ForeignKey('website.id'), primary_key=True)
    result = Column(Boolean)
    
    # Add relationships for easier querying
    rule = relationship('CheckerRule', back_populates='results')
    website = relationship('Website', back_populates='results')

class CheckerRule(Base):
    __tablename__ = 'checker_rule'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)  # Rule codes like FB2, DM3
    name_informal = Column(String)
    description = Column(String)
    
    # Relationship to results
    results = relationship('CheckerResult', back_populates='rule')

class Website(Base):
    __tablename__ = 'website'

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    domain = Column(String)
    path = Column(String)
    loaded = Column(Boolean)
    content = Column(String)
    content_hash = Column(String)
    timestamp = Column(DateTime)
    category = Column(String)
    country = Column(String)
    size = Column(Integer)
    error = Column(String)
    extra_info = Column(String)
    tranco_rank = Column(String)
    crawl = Column(String)
    
    # Relationship to results
    results = relationship('CheckerResult', back_populates='website')

# Utility functions for common database operations
def get_or_create_rule(session, rule_name, name_informal=None, description=None):
    """Get existing rule or create new one"""
    rule = session.query(CheckerRule).filter(CheckerRule.name == rule_name).first()
    if not rule:
        rule = CheckerRule(
            name=rule_name,
            name_informal=name_informal or rule_name,
            description=description or f"Rule {rule_name}"
        )
        session.add(rule)
        session.flush()  # Get the ID without committing
    return rule

def get_or_create_website(session, **website_data):
    """Get existing website or create new one"""
    # You might want to use a combination of hostname + path as unique identifier
    website = session.query(Website).filter(
        Website.hostname == website_data.get('hostname'),
        Website.path == website_data.get('path')
    ).first()
    
    if not website:
        website = Website(**website_data)
        session.add(website)
        session.flush()  # Get the ID without committing
    return website

def add_checker_result(session, rule_name, website_data, result):
    """Add a checker result with proper relationship handling"""
    try:
        # Get or create rule
        rule = get_or_create_rule(session, rule_name)
        
        # Get or create website
        website = get_or_create_website(session, **website_data)
        
        # Check if result already exists
        existing = session.query(CheckerResult).filter(
            CheckerResult.rule_id == rule.id,
            CheckerResult.website_id == website.id
        ).first()
        
        if existing:
            # Update existing result
            existing.result = result
        else:
            # Create new result
            checker_result = CheckerResult(
                rule_id=rule.id,
                website_id=website.id,
                result=result
            )
            session.add(checker_result)
        
        session.commit()
        return True
        
    except Exception as e:
        session.rollback()
        print(f"Error adding checker result: {e}")
        return False