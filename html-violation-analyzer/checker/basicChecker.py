from multiprocessing import Pool, get_context
from log import LogEvent
from checker import rules
import signal
from datetime import datetime
from urllib.parse import urlparse
from hashlib import md5
import os
import re

from database import CheckerResult, Website, CheckerRule, get_session, create_my_engine

class BasicChecker:
    """ Takes results from the result queue and checks the specified rules.
        If the result queue outputs the dead pill, the checker shuts down.

        :param number_processes: The maximum number of checker processes
        :type number_processes: int
        :param result_queue: The queue that outputs the crawler results
        :type result_queue: multiprocessing.Queue
        :param log_queue: The queue that takes log events
        :type log_queue: multiprocessing.Manager().Queue
        :param dead_pill: The dead pill to shutdown the checker
        :type dead_pill: string
        :param rules: The name of rules to apply
        :type rules: list
        :param mode: The current running mode, debug or prod
        :type mode: string
        :param database_engine: The path to the sqlite database TODO
        :type database_file: string
    """

    def __init__(self, number_processes, result_queue, log_queue, dead_pill,
                 rules, mode):
        """ Constructor method
        """
        self.number_processes = number_processes
        self.result_queue = result_queue
        self.log_queue = log_queue
        self.dead_pill = dead_pill
        self.rules = rules
        self.mode = mode
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def _handle_error(self, e):
        """ Error handler
        """
        self.log_queue.put(LogEvent("ERROR", __name__, e))

    def run(self):
        """ The function 'run' is started in a new process to handle log events
            from the log queue
        """
        pool = get_context("spawn").Pool(self.number_processes)

        while 1:
            self.log_queue.put(LogEvent("INFO", __name__, f"SIZE: {self.result_queue.qsize()}"))

            self.log_queue.put(LogEvent("DEBUG", __name__, "Checker is running"))
            requestResult = self.result_queue.get()
            if requestResult == self.dead_pill: 
                self.log_queue.put(LogEvent("DEBUG", __name__, "Shutdown Checker"))
                # pool.terminate()
                break

            try:
                pool.starmap_async(
                    check,
                    [(self.rules, requestResult, self.log_queue)],
                    error_callback=self._handle_error
                )
            except Exception as e:
                self.log_queue.put(LogEvent("ERROR", __name__, f"Checker failed to put job in queue: {e}"))
                # break ?

        pool.close()
        pool.join()

def extract_domain_from_path(file_path):
    """Extract domain from file path like 'snapshot_data/UA/www_president_gov_ua/2022_index...'"""
    try:
        # Get the directory name which should be the domain
        path_parts = file_path.replace('\\', '/').split('/')
        for part in path_parts:
            if part.startswith('www_') or '_gov_' in part or '_org_' in part:
                # Convert underscore format back to domain format
                domain = part.replace('_', '.')
                return domain
        # If no clear domain pattern, use the parent directory name
        return path_parts[-2] if len(path_parts) > 1 else "unknown"
    except:
        return "unknown"

def extract_country_from_path(file_path):
    """Extract country code from file path like 'snapshot_data/UA/www_president...'"""
    try:
        path_parts = file_path.replace('\\', '/').split('/')
        for part in path_parts:
            if len(part) == 2 and part.isupper():
                return part
        return "unknown"
    except:
        return "unknown"

def extract_year_and_timestamp_from_filename(file_path):
    """Extract year and timestamp from filename like '2022_index_www_president_gov_ua_20220404234046.html'
    
    Returns: (year, timestamp)
    """
    try:
        filename = os.path.basename(file_path)
        
        # Extract year from the beginning of filename (e.g., "2022_index_...")
        year = None
        if filename[:4].isdigit() and filename.startswith(('19', '20')):
            year = int(filename[:4])
            if not (1990 <= year <= 2030):
                year = None
        
        # Look for timestamp pattern: YYYYMMDDHHMMSS (usually at the end)
        timestamp_pattern = re.compile(r'(\d{14})')
        matches = timestamp_pattern.findall(filename)
        
        for match in matches:
            # Validate it's a reasonable timestamp
            try:
                ts_year = int(match[:4])
                ts_month = int(match[4:6])
                ts_day = int(match[6:8])
                ts_hour = int(match[8:10])
                ts_minute = int(match[10:12])
                ts_second = int(match[12:14])
                
                # Validate date components
                if (1990 <= ts_year <= 2030 and 
                    1 <= ts_month <= 12 and 
                    1 <= ts_day <= 31 and 
                    0 <= ts_hour <= 23 and 
                    0 <= ts_minute <= 59 and 
                    0 <= ts_second <= 59):
                    
                    dt = datetime(ts_year, ts_month, ts_day, ts_hour, ts_minute, ts_second)
                    
                    # If we didn't find a year at the beginning, use the timestamp year
                    if year is None:
                        year = ts_year
                    
                    return year, int(dt.timestamp())
            except:
                continue
        
        # If we found a year but no valid timestamp, create one for January 1st of that year
        if year:
            dt = datetime(year, 1, 1, 0, 0, 0)
            return year, int(dt.timestamp())
        
        # Fallback: return current time (this should rarely happen)
        return None, int(datetime.now().timestamp())
        
    except Exception as e:
        return None, int(datetime.now().timestamp())

def check(rule_names, result, log_queue):
    """ The function 'check' is called by the BasicChecker.
        It checks all defined rules for one crawler result.
        :param rule_names: A list of rules that are applied
        :type rule_names: list
        :param result: The request result that is checked
        :type result: dict 
        :param log_queue: The queue that takes log events
        :type log_queue: multiprocessing.Manager().Queue
    """
    
    database_session = None
    website = None
    
    try:
        database_session = get_session()
        
        # Handle file path vs URL
        if result.get('url', '').startswith('http'):
            url = urlparse(result['url'])
            hostname = url.hostname
            domain = hostname
            path = url.path
            country = hostname.split('.')[-1] if hostname else "unknown"
            timestamp = result.get("timestamp", int(datetime.now().timestamp()))
            year = datetime.fromtimestamp(timestamp).year
        else:
            # Local file processing
            file_path = result.get('url', result.get('file_path', ''))
            hostname = extract_domain_from_path(file_path)
            domain = hostname
            path = file_path
            country = extract_country_from_path(file_path)
            
            # Extract year and timestamp from filename
            year, timestamp = extract_year_and_timestamp_from_filename(file_path)
            
            # Log the extracted year for debugging
            log_queue.put(LogEvent("DEBUG", __name__, f"File: {os.path.basename(file_path)} -> Year: {year}"))

        content_hash = md5(result["content"].encode()).hexdigest()
        crawl_id = result.get("crawl_id", "local_files")
        tranco_rank = result.get("tranco_rank", -1)

        # Logging an error case
        if result.get("status") == "error":            
            website = Website(
                hostname=hostname,
                domain=domain,
                path=path,
                country=country,
                content="",
                content_hash=content_hash,
                size=len(result.get('content', '')),
                category="TBD",
                extra_info=crawl_id,
                crawl=crawl_id,
                tranco_rank=tranco_rank,
                error=result.get("content", "Unknown error"),
                timestamp=datetime.fromtimestamp(timestamp)
            )
            database_session.add(website)
            database_session.commit()
            return

        checker_results = []

        # Starting to check
        worked = 0
        for rule_name in rule_names:
            try:
                rule = getattr(rules, rule_name)
            except AttributeError:
                log_queue.put(LogEvent(
                    "ERROR", __name__, f"Skip {rule_name}. No such rule exists."
                ))
                continue

            try:
                res = rule.run_rule(result["content"])
            except Exception as e:
                log_queue.put(LogEvent(
                    "ERROR", __name__, f"Rule {rule_name} failed: {e}"
                ))
                continue

            if res == True:
                worked += 1

            checker_results.append((rule_name, res))

        log_queue.put(LogEvent("DEBUG", __name__, f"{path} worked {worked}/{len(rule_names)}"))

        # Storing website infos - IMPORTANT: Use the correct timestamp
        website = Website(
            hostname=hostname,
            domain=domain,
            path=path,
            country=country,
            content="",  # Will be filled if there are violations
            content_hash=content_hash,
            size=len(result['content']),
            category="TBD",
            extra_info=crawl_id,
            crawl=crawl_id,
            tranco_rank=tranco_rank,
            timestamp=datetime.fromtimestamp(timestamp)  # This will store the correct date
        )
        database_session.add(website)
        database_session.flush()  # Get the website ID

        # Store checker results
        for rule_name, res in checker_results:
            rule_object = database_session.query(CheckerRule) \
                .filter(CheckerRule.name == rule_name).first()

            if rule_object is None:
                log_queue.put(LogEvent(
                    "ERROR", __name__, f"Rule {rule_name} not found in database"
                ))
                continue

            # Store content only for violations to save space
            if res == False and website.content == "":
                website.content = result["content"]

            database_session.add(CheckerResult(
                rule_id=rule_object.id,
                website_id=website.id,
                result=res
            ))

        database_session.commit()
        log_queue.put(LogEvent("DEBUG", __name__, f"Successfully saved results for {path}"))

    except Exception as e:
        log_queue.put(LogEvent("ERROR", __name__, f"ERROR in checker: {e}"))
        if database_session:
            try:
                database_session.rollback()
            except:
                pass
    finally:
        if database_session:
            try:
                database_session.close()
            except:
                pass