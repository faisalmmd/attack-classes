from log import LogEvent
from .basicCrawler import BasicCrawler, BasicCrawlerTask
from datetime import datetime
import io
import requests
import gzip
import json

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

    def __init__(self, url, filename, offset, length, timestmap, log_queue, last_task=False):
        """ Constructor method
        """
        super().__init__(url, last_task=last_task)
        if url:
            self.filename = filename
            self.offset = offset
            self.offset_end = int(offset) + int(length) - 1
            self.timestamp = timestmap
            self.log_queue = log_queue

    def run(self):
        """ Runs one crawling job. It takes the result from the CommonCrawl API
            and extracts the HTML content.
        """

        self.log_queue.put(LogEvent("INFO", __name__, f"Crawling in task {self.url}"))

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
            raw_data = ""

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
        return {"status": status, "url": self.url, "content": output, "timestamp": ts.strftime("%s")}


class CommonCrawlCrawler(BasicCrawler):
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
                 urls, files, mode):
        """ Constructor method
        """
        super().__init__(number_processes, result_queue, log_queue, dead_pill, mode)  
        self.tasks = 0
        self._fill_crawling_tasks(urls, files)

    def _add_crawling_task(self, resp):
        """ Takes the response from CommonCrawl API and adds the entries as crawler task
            :param resp: Response from the CommonCrawl API
            :type resp: string
        """
        for entry in resp.splitlines():
            if self.mode == "DEBUG" and self.tasks > 15: break 
            j = json.loads(entry)
            crawler_task = CommonCrawlTask(j["url"], j["filename"], j["offset"],
                                           j["length"], j["timestamp"], self.log_queue)
            # crawler_task = CommonCrawlTask(j["url"], j["filename"], j["offset"],
                                           # j["length"], "20210612120221", self.log_queue)
            self.crawling_tasks.put(crawler_task)
            self.tasks += 1

    def _fill_crawling_tasks(self, urls, files):
        """ Requests the position of content in CommonCrawls database via the API.
            Every response is put in the crawling tasks queue.
            :param urls: The urls that are requested
            :type urls: list
            :param files: If CommonCrawl API response are stored offline,
                          the user can use them via files.
            :type files: list
        """
        # TODO Run this parallel to the run function. Filling takes a while... 
        self.log_queue.put(LogEvent("INFO", __name__, "Fill Common Crawler with tasks"))

        # get the current search id 
        index_url = "https://index.commoncrawl.org"
        collcetion_info = requests.get(f"{index_url}/collinfo.json").json()
        collection_id = collcetion_info[0]["id"]

        # takes tasks from the online collection
        for u in urls:
            url = f"{index_url}/{collection_id}-index?url={u}&output=json"
            resp = requests.get(url).text
            self._add_crawling_task(resp)

        # takes tasks from a collection stored offline
        for file in files:
            with open(file, "r") as f:
                resp = f.read()
                self._add_crawling_task(resp)

        # add last task
        crawler_task = CommonCrawlTask("", "", "", "", "", self.log_queue, last_task=True)
        self.crawling_tasks.put(crawler_task)
