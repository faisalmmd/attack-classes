from log import LogEvent
from .basicCrawler import BasicCrawler, BasicCrawlerTask

import asyncio
from pyppeteer import launch
import json

class DynamicCrawlTask(BasicCrawlerTask):

    def __init__(self, url, log_queue, last_task=False):
        """ Constructor method
        """
        super().__init__(url, last_task=last_task)
        if url:
            self.log_queue = log_queue
            

    async def run_pyppeteer(self):
        
        browser = await launch()
        page = await browser.newPage()
        
        # Hook JS function
        # await page.evaluateOnNewDocument('alert = (i) => "hello" + i')

        res = await page.goto(self.url)
        # dont do this, because it already gives the rendered html
        # content = await page.evaluate('document.documentElement.outerHTML')
        content = await res.text()
        await browser.close()
        self.log_queue.put(LogEvent("INFO", __name__, "got content: %s" % content[:10]))
        return {"url": self.url, "content": content}

    def run(self):
        self.log_queue.put(LogEvent("INFO", __name__, "Gonna start to crawl %s" % self.url))
        return asyncio.get_event_loop().run_until_complete(self.run_pyppeteer())


class DynamicCrawler(BasicCrawler):
    
    def __init__(self, number_processes, result_queue, log_queue, dead_pill,
                 urls, mode):
        """ Constructor method
        """
        super().__init__(number_processes, result_queue, log_queue, dead_pill, mode)  
        self.tasks = 0
        self._fill_crawling_tasks(urls)

    def _fill_crawling_tasks(self, urls):

        self.log_queue.put(LogEvent("INFO", __name__, "Fill Dynamic Crawler with tasks"))
        for url in urls:
            if self.mode == "DEBUG" and self.tasks > 15: break 
            crawler_task = DynamicCrawlTask(url, self.log_queue)
            self.crawling_tasks.put(crawler_task)
            self.tasks += 1

        crawler_task = DynamicCrawlTask("", self.log_queue, last_task=True)
        self.crawling_tasks.put(crawler_task)
