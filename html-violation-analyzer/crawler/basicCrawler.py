from multiprocessing import Queue, Pool, get_context
from log import LogEvent
import time
import signal

""" basicCrawler
    The BasicCrawler and BasicTask are the superclasses for various crawlers.
"""

class BasicCrawlerTask:
    """ Represents a task that the crawler can run.
        :param url: The url the crawler should work with
        :type url: string
        :param last_task: Defines if the task is the last task.
        :type last_task: bool, optional
    """

    def __init__(self, url, last_task=False):
        """ Constructor method
        """
        self.url = url
        self.last_task = last_task

    def run(self):
        """ The run function is implemented for each task individally.
        """
        pass


class BasicCrawler:
    """ BasicCrawler is the superclass for various crawlers.
        The implemented crawler fills tasks in the crawling_tasks queue.
        The function 'run' takes these tasks and calls the function 'run'
        in each task.
        If the last task appears, the crawler shuts down and puts a
        dead pill in the result queue to signal the checker to shut down.

        :param number_processes: The maximum number of crawler processes
        :type number_processes: int
        :param result_queue: The queue to append the crawler results
        :type result_queue: multiprocessing.Queue
        :param log_queue: The queue that takes log events
        :type log_queue: multiprocessing.Manager().Queue
        :param dead_pill: The dead pill to shutdown the checker
        :type dead_pill: string
        :param mode: The current running mode, debug or prod
        :type mode: string
    """

    def __init__(self, number_processes, result_queue, log_queue, dead_pill, mode):
        """ Constructor method
        """
        self.number_processes = number_processes
        self.result_queue = result_queue
        self.log_queue = log_queue
        self.dead_pill = dead_pill
        self.crawling_tasks = Queue()
        self.mode = mode
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def raise_error(self, e):
        """ Error handler
        """
        self.log_queue.put(LogEvent("ERROR", __name__, e))
        
    def run(self):
        """ The function 'run' is started in a new process to handle the crawling tasks.
            Every crawling task from the crawler_task queue starts the function crawl.
        """
        self.log_queue.put(LogEvent("INFO", __name__, "Initializing Crawler Thread Pool"))
        pool = get_context("spawn").Pool(self.number_processes, proc_init,
                                         [self.result_queue])

        self.log_queue.put(LogEvent("DEBUG", __name__, "Start Crawler"))
        while 1:
            # self.log_queue.put(LogEvent("DEBUG", __name__, "Working"))
            task = self.crawling_tasks.get()
            if task == self.dead_pill:
                t = "Shutdown Crawler because of dead pill"
                self.log_queue.put(LogEvent("INFO", __name__, t))
                break
            if task.last_task:
                t = "Shutdown Crawler because of last task"
                self.log_queue.put(LogEvent("INFO", __name__,t ))
                break

            try:
                pool.map_async(crawl, [task], error_callback=self.raise_error)
            except Exception as e:
                self.log_queue.put(LogEvent("ERROR", __name__, f"Crawler failed to put job in queue: {e}"))
                # break ?

        pool.close()
        pool.join()
        self.result_queue.put(self.dead_pill)


def crawl(task: BasicCrawlerTask):
    """ This function runs a crawler tasks and puts the output
        into the result queue.
        :param task: The crawler task that is used processed.
        :type task: BasicCrawlerTask
    """
    result = task.run()
    time.sleep(0.05)
    crawl.result_queue.put(result)
    del task

def proc_init(result_queue):
    """ This function is a workaround to make the result queue accessible in crawl. 
        :param result_queue: The queue to append the crawler results
        :type result_queue: multiprocessing.Queue
    """
    crawl.result_queue = result_queue
