from log import LogEvent
from .basicCrawler import BasicCrawler, BasicCrawlerTask
from datetime import datetime
import io
import requests
import gzip
import json
import sqlite3
import psycopg2

class CommonCrawlTask(BasicCrawlerTask):
    """ Represents a task that the crawler can run.
        The task extracts HTML content from CommonCrawl.
        :param url: The url the crawler should work with
        :type url: string
        :param filename: Path to the gzip file that holds the content
        :type filename: string
        :param offset: Offset in the gzip file
        :type offset: string
        :param length: Length of the content
        :type length: string
        :param log_queue: The queue that takes log events
        :type log_queue: multiprocessing.Manager().Queue
        :param last_task: Defines if the task is the last task.
        :type last_task: bool, optional
    """

    def __init__(self, url, domain, filename, offset, length, timestmap, crawl_id, tranco_rank, log_queue, last_task=False):
        """ Constructor method
        """
        super().__init__(url, last_task=last_task)
        if url:
            self.filename = filename
            self.domain = domain
            self.offset = offset
            self.offset_end = int(offset) + int(length) - 1
            self.timestamp = timestmap
            self.crawl_id = crawl_id
            self.tranco_rank = tranco_rank
            self.log_queue = log_queue

    def run(self):
        """ Runs one crawling job. It takes the result from the CommonCrawl API
            and extracts the HTML content.
        """
        # TODO mby add timeouts
        self.log_queue.put(LogEvent("INFO", __name__, f"Crawling in task {self.url}"))

        # data_url = "https://commoncrawl.s3.amazonaws.com"
        data_url = "https://data.commoncrawl.org"
        url = f"{data_url}/{self.filename}"
        headers={"Range": f"bytes={self.offset}-{self.offset_end}"}

        resp = requests.get(url, headers=headers)
        l = f"Resp Length for {self.url}: {len(resp.text)}"
        self.log_queue.put(LogEvent("INFO", __name__, l))

        status = "data"
        data = ""
        
        try:
            zipped_file = io.BytesIO(resp.content)
            unzipped_file = gzip.GzipFile(fileobj=zipped_file)
            raw_data: bytes = unzipped_file.read()
        except Exception as e:
            em = f"ERROR for {self.url}\n{url}\n{self.offset} - {self.offset_end}\n{resp.content}\n{e}"
            self.log_queue.put(LogEvent("ERROR", __name__, em))
            status = "error"
            output = em
            raw_data = b""

        try:
            data: str = raw_data.decode("utf-8")
        except UnicodeDecodeError:
            em = f"Warning: Could not extract file downloaded from {url}"
            self.log_queue.put(LogEvent("ERROR", __name__, em)) 
            status = "error"
            output = em

        html = ""

        if len(data) > 0:
            data_parts = data.strip().split("\r\n\r\n", 2)
            html = data_parts[2] if len(data_parts) == 3 else ""

        if status == "data":
            output = html

        ts = datetime.strptime(self.timestamp, "%Y%m%d%H%M%S")
        out = {
                "status": status,
                "url": self.url,
                "domain": self.domain,
                "content": output,
                "crawl_id": self.crawl_id,
                "tranco_rank": self.tranco_rank,
                "timestamp": ts.strftime("%s")
        }
        return out


class CommonCrawlCrawlerFromSQL(BasicCrawler):
    """ CommonCrawlCrawler is an BasicCrawler implementation based on CommonCrawl.
        Thus, is is only takes static HTMl files and ignores the JS.
        What it basically does is, it uses the CommonCrawl API to request URLs 
        and uses the output to receive the HTML content from the CommonCrawl database.

        :param number_processes: The maximum number of crawler processes
        :type number_processes: int
        :param result_queue: The queue to append the crawler results
        :type result_queue: multiprocessing.Queue
        :param log_queue: The queue that takes log events
        :type log_queue: multiprocessing.Manager().Queue
        :param dead_pill: The dead pill to shutdown the checker
        :type dead_pill: string
        :param urls: The urls that are requested
        :type urls: list
        :param files: If CommonCrawl API response are stored offline,
                      the user can use them via files.
        :type files: list
        :param mode: The current running mode, debug or prod
        :type mode: string
    """

    
    def __init__(self, number_processes, result_queue, log_queue, dead_pill,
                 db_file, crawl, mode):
        """ Constructor method
        """
        super().__init__(number_processes, result_queue, log_queue, dead_pill, mode)  
        self.tasks = 0
        self.crawl_id = crawl
        self._fill_crawling_tasks(db_file)

    def _add_crawling_task(self, entry):
        """ Takes the response from CommonCrawl API and adds the entries as crawler task
            :param resp: Response from the CommonCrawl API
            :type resp: string
        """
        crawler_task = CommonCrawlTask(entry["url"], entry["domain"], entry["filename"], entry["offset"],
                                       entry["length"], "20210612120221", self.crawl_id, entry["tranco_rank"], self.log_queue)
        self.crawling_tasks.put(crawler_task)
        self.tasks += 1

    def _fill_crawling_tasks(self, db_file):
        """ Requests the position of content in CommonCrawls database via the API.
            Every response is put in the crawling tasks queue.
            :param db_file: CommonCrawl indexes that are stored in a DB
            :type db_file: string
        """
        # TODO Run this parallel to the run function. Filling takes a while... 
        self.log_queue.put(LogEvent("INFO", __name__, "Fill Common Crawler with tasks"))

        # takes tasks from the db
        con = psycopg2.connect(db_file)
        cur = con.cursor()
        cur.execute("""SELECT domain, d.reg_domain, path, warc_filename, warc_record_offset, warc_record_length, tranco_rank
                            FROM entry as e JOIN (SELECT DISTINCT reg_domain, tranco_rank FROM domain_table) as d on e.reg_domain = d.reg_domain
                            WHERE e.crawl=%s""", [self.crawl_id])
        rows = cur.fetchall()
        rows_list = list(rows)
        con.close()
        print(f"Analyze {len(rows_list)} urls")
        for r in rows_list:
            entry = {
                "url": "http://" + r[0] + r[2],
                "domain": r[1],
                "filename": r[3],
                "offset": r[4],
                "length": r[5],
                "tranco_rank": r[6]
            }
            self._add_crawling_task(entry)
        
        # add last task
        crawler_task = CommonCrawlTask("", "", "", "", "", "", "", "", self.log_queue, last_task=True)
        self.crawling_tasks.put(crawler_task)
