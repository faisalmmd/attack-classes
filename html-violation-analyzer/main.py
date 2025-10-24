from crawler import CommonCrawlCrawlerFromSQL, CommonCrawlCrawler, DynamicCrawler, FileCrawler, local_files
from checker import BasicChecker
from log import Logger, LogEvent
from datetime import datetime
import argparse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import multiprocessing
from os import path, mkdir
import yaml
import signal
import sys
import time
from crawler.fileCrawler import FileCrawler
from crawler import local_files  # Ensure local_files is imported

from database import get_session, create_database, create_my_engine
from database import CheckerResult, CheckerRule 
from checker import rules

CONFIG_FILE = "./config.yml"
DEAD_PILL = "DEADPILL"

def get_country_input(config):
    """Prompt user for country code and validate input"""
    # First, check what countries are available
    available_countries = local_files.get_available_countries(config)
    
    if available_countries:
        print("\nAvailable countries in the dataset:")
        for country in sorted(available_countries):
            print(f"  - {country}")
        print()
    
    while True:
        country_code = input("Enter country code (e.g., UA for Ukraine, US for United States): ").strip().upper()
        
        # Basic validation - should be 2 uppercase letters
        if len(country_code) == 2 and country_code.isalpha():
            # Check if country exists in dataset
            if available_countries and country_code not in available_countries:
                print(f"\nWarning: '{country_code}' was not found in the available countries.")
                print("Available countries are:", ", ".join(sorted(available_countries)))
                proceed = input("Do you want to proceed anyway? (y/n): ").strip().lower()
                if proceed != 'y':
                    continue
            
            confirm = input(f"You selected '{country_code}'. Is this correct? (y/n): ").strip().lower()
            if confirm == 'y':
                return country_code
            elif confirm == 'n':
                continue
            else:
                print("Please enter 'y' for yes or 'n' for no.")
        else:
            print("Invalid country code. Please enter a 2-letter country code.")

def main():
    parser = argparse.ArgumentParser(description='Crawl websites and check some rules.')
    parser.add_argument('--module', help='Crawling module [common_crawl, common_crawl_sql, file, dynamic, local_files]')
    parser.add_argument('--urls', help='Path to a list of URL you want to crawl')
    parser.add_argument('--config', help='Path to the config file')
    parser.add_argument('--files', help='Path to a file containing commonCrawl information')
    parser.add_argument('--crawl', help='The crawl id if the CC data are selected from a database')
    parser.add_argument('--country', help='Country code to filter files (e.g., UA, US)')
    args = parser.parse_args()

    start_time = time.time()
    global CONFIG_FILE
    if args.config:
        CONFIG_FILE = args.config

    print(CONFIG_FILE)

    with open(CONFIG_FILE, "r") as ymlfile:
        config = yaml.load(ymlfile, Loader=yaml.FullLoader)

    if not config:
        print(f"No such config: {CONFIG_FILE}")
        return 1

    output_dir = config["general"]["output"]
    if not path.exists(output_dir):
        mkdir(output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    log_level = config["general"]["log_level"]
    log_queue = multiprocessing.Manager().Queue()
    log_file = path.join(output_dir, f"{timestamp}.log")
    logger = Logger(log_queue, log_level, log_file, DEAD_PILL)
    log_process = multiprocessing.Process(target=logger.run)
    log_process.start()

    applied_rules = config["checker"]["rules"] or []  
    create_my_engine()
    create_database()
    database_session = get_session() 

    for rule_name in applied_rules:
        rule = getattr(rules, rule_name, None)
        if not rule: 
            raise Exception(f"No such rule {rule_name}")

        rule_exists = database_session.query(CheckerRule).filter(CheckerRule.name == rule_name).first()
        if rule_exists:
            continue
        
        checker_rule = CheckerRule(
            name=rule_name,
            name_informal=rule.name_informal.strip(),
            description=rule.description.strip()
        )
        database_session.add(checker_rule)

    database_session.commit()
    database_session.close()

    number_crawler_processes = int(config["general"]["number_crawler_processes"])
    number_checker_processes = int(config["general"]["number_checker_processes"])
    mode = config["general"]["mode"] 

    urls = args.urls if args.urls else config["crawler"].get("urls", [])
    files = args.files if args.files else config["crawler"].get("files", [])
    db_file = config["crawler"].get("db_path", [])
    crawl = args.crawl if args.crawl else ""
    module = args.module if args.module else ""

    # Get country filter for local_files module
    country_filter = None
    if module == "local_files":
        # Check if country was provided via command line
        if args.country:
            country_filter = args.country.upper()
            print(f"Using country filter from command line: {country_filter}")
        else:
            # Ask user for country input
            country_filter = get_country_input(config)
        
        log_queue.put(LogEvent("INFO", __name__, f"Filtering files for country: {country_filter}"))

    result_queue = multiprocessing.Queue()
    currentCrawler = None

    if module == "common_crawl_sql":
        currentCrawler = CommonCrawlCrawlerFromSQL(
            number_crawler_processes, result_queue, log_queue, DEAD_PILL, db_file, crawl, mode
        )
    elif module == "common_crawl":
        currentCrawler = CommonCrawlCrawler(
            number_crawler_processes, result_queue, log_queue, DEAD_PILL, urls, files, mode
        )
    elif module == "dynamic":
        currentCrawler = DynamicCrawler(
            number_crawler_processes, result_queue, log_queue, DEAD_PILL, urls, mode
        )
    elif module == "file":
        currentCrawler = FileCrawler(
            number_crawler_processes, result_queue, log_queue, DEAD_PILL, files[0], mode
        )
    elif module == "local_files":
        # Pass country filter to collect_files function
        html_paths = local_files.collect_files(config, country_filter=country_filter)
        
        # Log statistics about filtered files
        log_queue.put(LogEvent("INFO", __name__, f"Found {len(html_paths)} HTML files for country {country_filter}"))
        
        if len(html_paths) == 0:
            log_queue.put(LogEvent("WARNING", __name__, f"No HTML files found for country {country_filter}"))
            log_queue.put(DEAD_PILL)
            log_process.join()
            print(f"\nNo HTML files found for country '{country_filter}' in the specified directory.")
            print("Please check that the country code is correct and that files exist for this country.")
            sys.exit(1)
        
        currentCrawler = FileCrawler(number_crawler_processes, result_queue, log_queue, DEAD_PILL, html_paths, mode)


    if not currentCrawler:
        log_queue.put(LogEvent("CRITICAL", __name__, f"No valid module selected: '{module}'"))
        log_queue.put(DEAD_PILL)
        log_process.join()
        sys.exit(1)

    basicChecker = BasicChecker(
        number_checker_processes, result_queue, log_queue, DEAD_PILL, applied_rules, mode
    )

    checker_process = multiprocessing.Process(target=basicChecker.run)
    checker_process.start()

    def exit_handler(sig, frame):
        log_queue.put(LogEvent("INFO", __name__, "You pressed Ctrl+C"))
        checker_process.terminate()
        checker_process.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    currentCrawler.run()
    checker_process.join()

    delta_time = round(time.time() - start_time)
    log_queue.put(LogEvent("INFO", __name__, f"Execution Time: {delta_time} seconds"))

    log_queue.put(DEAD_PILL)
    log_process.join()

if __name__ == '__main__':
    multiprocessing.set_start_method('spawn')
    main()