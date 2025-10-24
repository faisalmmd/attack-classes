import os
from log import LogEvent
from .basicCrawler import BasicCrawler, BasicCrawlerTask
import time

class FileCrawlTask(BasicCrawlerTask):
    def __init__(self, url, log_queue, last_task=False):
        super().__init__(url, last_task=last_task)
        if url:
            self.log_queue = log_queue

    def run(self):
        self.log_queue.put(LogEvent("INFO", __name__, f"Gonna start to crawl {self.url}"))

        content = ""
        status = "data"
        
        try:
            with open(self.url, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            em = f"ERROR for {self.url}\n{e}"
            self.log_queue.put(LogEvent("ERROR", __name__, em))
            status = "error"
            content = em

        return {
            "status": status,
            "url": self.url,
            "content": content,
            "timestamp": str(time.time()).split('.')[0]
        }

class FileCrawler(BasicCrawler):
    def __init__(self, number_processes, result_queue, log_queue, dead_pill,
                 directory_or_filelist, mode):
        super().__init__(number_processes, result_queue, log_queue, dead_pill, mode)
        self.tasks = 0
        self._fill_crawling_tasks(directory_or_filelist)

    def _fill_crawling_tasks(self, directory_or_filelist):
        self.log_queue.put(LogEvent("INFO", __name__, "Fill File Crawler with tasks"))

        if isinstance(directory_or_filelist, list):
            file_list = directory_or_filelist
        else:
            file_list = [
                os.path.join(directory_or_filelist, fname)
                for fname in os.listdir(directory_or_filelist)
            ]

        for file_path in file_list:
            if self.mode == "DEBUG" and self.tasks > 15:
                break
            crawler_task = FileCrawlTask(file_path, self.log_queue)
            self.crawling_tasks.put(crawler_task)
            self.tasks += 1

        # Final task marks completion
        final_task = FileCrawlTask("", self.log_queue, last_task=True)
        self.crawling_tasks.put(final_task)
