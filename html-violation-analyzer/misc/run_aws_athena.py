import requests
import boto3
import time
import sqlite3
import json
from urllib.parse import urlparse
from multiprocessing import Pool, Queue, Process
import signal
from config import aws_access_key_id, aws_secret_access_key, api_token, chat_id

# all january crawls
crawls_list = [
    'CC-MAIN-2015-14', # Jan
    'CC-MAIN-2016-07', # Feb
    'CC-MAIN-2017-04', # Jan
    'CC-MAIN-2018-05', # Jan
    'CC-MAIN-2019-04', # Jan
    'CC-MAIN-2020-05', # Jan
    'CC-MAIN-2021-04', # Jan
    'CC-MAIN-2022-05', # Jan
]

domain_list = [
    # "google.com",
    # "facebook.com",
    # "youtube.com",
    # "microsoft.com",
    # "twitter.com",
    # "instagram.com",
    "netflix.com",
    "linkedin.com",
    "tmall.com",
    "qq.com" 
]

database = "athena.20000_24915.db"
result_queue = Queue()

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

BOTO_SESSION = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name = "us-east-1"
)

class AthenaQuery:

    def __init__(self, domain, crawls, limit=10):
        self._output = {}
        for crawl in crawls:
            self._output[crawl] = []
        
        self._database = "ccindex"
        self._result_bucket = "s3://my-cc-bcket/"
        self._client = BOTO_SESSION.client('athena', region_name="us-east-1")
        self._limit = limit
        self._next_token = None
        self._domain = domain
        
        self._query = """
            SELECT url_host_name, url_host_registered_domain, url_path, crawl,
                MAX(CONCAT(warc_filename, '___', CAST(warc_record_offset AS varchar(50)), '___', CAST(warc_record_length AS varchar(50)), '___', warc_segment))
            FROM "ccindex"."ccindex"
            WHERE crawl IN (%s)
            AND subset = 'warc'
            AND url_host_tld = '%s'
            AND content_mime_type = 'text/html'
            AND url_host_registered_domain = '%s'
            GROUP BY url_host_name, url_host_registered_domain, url_path, crawl
            ORDER BY url_path, crawl
            """ % (
                    "'" + "','".join(crawls) + "'",
                    domain.split('.')[-1], # I checked that they always take the last part
                    domain
            )
    
    def request_query(self):
        response = self._client.start_query_execution(
            QueryString=self._query,
            QueryExecutionContext={
                'Database': self._database
            },
            ResultConfiguration={
                'OutputLocation': self._result_bucket
            }
        )

        print("started...")
        print(response["QueryExecutionId"])
        self._query_execution_id = response["QueryExecutionId"]

    def wait_for_result(self):
        while 1:
            status = self._client.get_query_execution(QueryExecutionId=self._query_execution_id)
            if status["QueryExecution"]["Status"]["State"] == "SUCCEEDED":
                break
            if status["QueryExecution"]["Status"]["State"] == "FAILED":
                print("ERROR [%s - %s]: %s" % (self._domain, self._query_execution_id, status["QueryExecution"]["Status"]["StateChangeReason"]))
                import sys
                sys.exit(1)
            print("[%s - %s] Waiting..." % (self._domain, self._query_execution_id))
            time.sleep(2)

    def request_result(self):
        if self._next_token:
            self._response = self._client.get_query_results(
                QueryExecutionId=self._query_execution_id,
                NextToken=self._next_token
            )
        else:
            self._response = self._client.get_query_results(
                QueryExecutionId=self._query_execution_id
            )

        if "NextToken" in self._response:
            self._next_token = self._response["NextToken"]
            return True
        else:
            self._next_token = None
            return False

    def parse_response(self):
        # return True if full else False
            
        for row in self._response["ResultSet"]["Rows"][1:]:
            d = row["Data"]
            url_host_name   = d[0]["VarCharValue"]
            url_host_reg_d  = d[1]["VarCharValue"]
            url_path        = d[2]["VarCharValue"]
            crawl_name      = d[3]["VarCharValue"]
            warc_info       = d[4]["VarCharValue"]

            if len(self._output[crawl_name]) != self._limit:
                warc_split = warc_info.split("___")
                o = {
                        "domain": url_host_name,
                        "reg_domain": url_host_reg_d,
                        "path": url_path,
                        "crawl": crawl_name,
                        "warc_filename": warc_split[0],
                        "warc_record_offset": warc_split[1],
                        "warc_record_length": warc_split[2],
                        "warc_segment": warc_split[3],
                    }
                self._output[crawl_name].append(o)

        # Check if output is already full
        data_is_full = True
        for crawl in self._output.keys():
            if len(self._output[crawl]) != self._limit:
                print(f"[{self._domain} - {self._query_execution_id}] {crawl} not yet full: {len(self._output[crawl])}")
                data_is_full = False
                break

        return data_is_full

    def run_old_query(self, query_execution_id):
        self._query_execution_id = query_execution_id

        while 1:
            next = self.request_result()
            full = self.parse_response()
            print(f"next: {next} -> {self._next_token}")
            print(f"full: {full}")
            if full or not next:
                break
        print("FINISHED %s" % self._domain)
        return self._output

    def run(self):
        self.request_query()
        self.wait_for_result()
        
        while 1:
            next = self.request_result()
            full = self.parse_response()
            print(f"next: {next}")
            print(f"full: {full}")
            if full or not next:
                break
        print("FINISHED")
        result_queue.put({"event": "ENTRY", "res": self._output})
        return self._output

def database_process():

    while 1:
        entry = result_queue.get()
        if  entry["event"] == "DEADPILL":
            break

        con = sqlite3.connect(database)
        cur = con.cursor()

        if  entry["event"] == "ENTRY":
            res = entry["res"]
            for crawl in res:
                for e in res[crawl]:
                    cur.execute("INSERT INTO entry values (?, ?, ?, ?, ?, ?, ?, ?)",
                        (e["domain"], e["reg_domain"], e["path"], e["crawl"], 
                        e["warc_filename"], e["warc_record_offset"],
                        e["warc_record_length"], e["warc_segment"] ))
        
        con.commit()
        con.close()
        
def work(domain):
    print("Work on %s" % domain)
    send_log("Work on %s" % domain)
    aq = AthenaQuery(domain, crawls_list)
    res = aq.run()


def send_log(text):
    res = requests.get("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s" % (api_token, chat_id, text))

def main():

    con = sqlite3.connect(database)
    cur = con.cursor()

    cur.execute("""CREATE TABLE entry (
            domain text,
            reg_domain text,
            path text,
            crawl text,
            warc_filename text,
            warc_record_offset text,
            warc_record_length text,
            warc_segment text
    )""")
    con.commit()
    con.close()


    db_process = Process(target=database_process)
    db_process.start()

    list_file = open("./top_50k_appearing_every_day.json", "r").read()
    list_file = list_file.splitlines()
    domain_list = []
    for line in list_file[20000:]:
        j = json.loads(line)
        domain_list.append(j["domain"])

    p1 = Pool(10, init_worker)
    try:
        p1.map(work, domain_list)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating workers")
        p1.terminate()
        p1.join()
    
    result_queue.put({"event": "DEADPILL"})
    db_process.join()
    send_log("DONE")

if __name__ == "__main__":
    main()
