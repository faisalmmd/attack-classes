import requests
import boto3
import psycopg2
import json
from urllib.parse import urlparse
from multiprocessing import Pool, Queue, Process
import signal
from config import aws_access_key_id, aws_secret_access_key, api_token, chat_id


result_queue = Queue()

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

BOTO_SESSION = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name = "us-east-1"
)

class AthenaQuery:

    def __init__(self, max_entries):
        self._client = BOTO_SESSION.client('athena', region_name="us-east-1")
        self._next_token = None
        self._output = []
        self._number_of_entries = {
                "CC-MAIN-2015-14": 0,
                "CC-MAIN-2016-07": 0,
                "CC-MAIN-2017-04": 0,
                "CC-MAIN-2018-05": 0,
                "CC-MAIN-2019-04": 0,
                "CC-MAIN-2020-05": 0,
                "CC-MAIN-2021-04": 0,
                "CC-MAIN-2022-05": 0
        }
        self._max_entries = max_entries
        self._reg_domain = None
       
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
        output = []
        url_host_reg_d = None
        for row in self._response["ResultSet"]["Rows"][1:]:

            d = row["Data"]
            url_host_name   = d[0]["VarCharValue"]
            url_host_reg_d  = d[1]["VarCharValue"]
            url_path        = d[2]["VarCharValue"]
            crawl_name      = d[3]["VarCharValue"]
            warc_info       = d[4]["VarCharValue"]

            if self._number_of_entries[crawl_name] >= self._max_entries:
                continue

            warc_split = warc_info.split("___")
            o = {
                    "type": "entry",
                    "domain": url_host_name,
                    "reg_domain": url_host_reg_d,
                    "path": url_path,
                    "crawl": crawl_name,
                    "warc_filename": warc_split[0],
                    "warc_record_offset": warc_split[1],
                    "warc_record_length": warc_split[2],
                    "warc_segment": warc_split[3],
                }
            output.append(o)
            self._number_of_entries[crawl_name] += 1

        if self._reg_domain is None and url_host_reg_d is not None:
            self._reg_domain = url_host_reg_d

        if len(output) > 0:
            self.do_database(output)

    def do_database(self, output):
        con = psycopg2.connect("dbname='cc_index_database_200_2' user='athena' host='localhost' password='f1h89f90u1'")
        cur = con.cursor()

        for e in output:
            if e["type"] == "domain":
                print("work on domain")
                cur.execute("INSERT INTO domain_table values (%s, %s, %s, %s)",
                    (e["reg_domain"], e["crawl"], self._query_execution_id, e["number_pages"])) 

            elif e["type"] == "entry":
                cur.execute("INSERT INTO entry values (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (e["domain"], e["reg_domain"], e["path"], e["crawl"], 
                    e["warc_filename"], e["warc_record_offset"],
                    e["warc_record_length"], e["warc_segment"] ))
            else:
                print(e)
        
        con.commit()
        con.close()


    def run(self, query_execution_id):
        self._query_execution_id = query_execution_id

        print("DO")
        while 1:
            try:
                next = self.request_result()
                self.parse_response()
            except Exception as e:
                return

            if not next:
                break
            
            # check if all crawls are full
            cont = False
            for crawl in self._number_of_entries.keys():
                if self._number_of_entries[crawl] < 200:
                    cont = True
            if not cont:
                break
            print(f"Try again {self._reg_domain}: {self._next_token}")

        domains = []
        for crawl in self._number_of_entries.keys():
            d = {
                "type": "domain",
                "reg_domain": self._reg_domain if self._reg_domain is not None else "not existend",
                "crawl": crawl,
                "number_pages": self._number_of_entries[crawl]
            }
            domains.append(d)
        self.do_database(domains)

def get_query_execution_ids(next_token=None):
    client = BOTO_SESSION.client('athena', region_name="us-east-1")
    if next_token:
        executions = client.list_query_executions(NextToken=next_token)
    else:
        executions = client.list_query_executions(NextToken=next_token)
    query_execution_ids = executions.get("QueryExecutionIds")
    next_token = executions.get("NextToken")

    return ()


def work(query_execution_id):
    print("Work on %s" % query_execution_id)
    aq = AthenaQuery(200)
    res = aq.run(query_execution_id)


def send_log(text):
    res = requests.get("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s" % (api_token, chat_id, text))

def main():
    
    con = psycopg2.connect("dbname='cc_index_database_200_2' user='athena' host='localhost' password='f1h89f90u1'")
    cur = con.cursor()
    if False:
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

        cur.execute("""CREATE TABLE domain_table (
                reg_domain text,
                crawl text,
                query_execution_id text,
                number_pages integer
        )""")

    cur.execute("SELECT DISTINCT query_execution_id FROM domain_table;")
    old_exec_ids = [i[0] for i in cur.fetchall()]
    con.commit()
    con.close()

    all_ids = []
    client = BOTO_SESSION.client('athena', region_name="us-east-1")
    executions = client.list_query_executions()
    next_token = executions.get("NextToken")

    f = open("./execution_ids.txt", "r")
    all_ids = [l for l in f.read().splitlines()]
    f.close()

    """
    while next_token:
        cur_ids = list(executions.get("QueryExecutionIds"))
        if "4afdd144-fa88-4424-8f0c-5a719c093e1f" in cur_ids:
            cont = True

        if cont:
            all_ids += cur_ids 
        print(f"I have found {len(all_ids)} execution ids so far")

        '''
        if len(all_ids) > 10:
            break
        '''

        executions = client.list_query_executions(NextToken=next_token)
        next_token = executions.get("NextToken", None)
    """

    print(f"I have found {len(all_ids)} execution ids")
    all_ids = [i for i in all_ids if i not in old_exec_ids]
    print(f"Dedup: {len(all_ids)} execution ids")

    return

    p1 = Pool(12, init_worker)
    try:
        p1.map(work, all_ids)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating workers")
        p1.terminate()
        p1.join()
    
    print("DONE")

if __name__ == "__main__":
    main()
