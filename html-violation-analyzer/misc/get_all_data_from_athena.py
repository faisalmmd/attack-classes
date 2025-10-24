import requests
import boto3
import sys
import time
import psycopg2
import json
from urllib.parse import urlparse
from multiprocessing import Pool, Queue, Process
import signal
from config import aws_access_key_id, aws_secret_access_key, api_token, chat_id


database = "athena.max.db"
result_queue = Queue()

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

BOTO_SESSION = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name = "us-east-1"
)

class AthenaQuery:

    def __init__(self):
        self._client = BOTO_SESSION.client('athena', region_name="us-east-1")
        self._next_token = None
        self._output = []
       
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
        for row in self._response["ResultSet"]["Rows"][1:]:
            d = row["Data"]
            url_host_name   = d[0]["VarCharValue"]
            url_host_reg_d  = d[1]["VarCharValue"]
            url_path        = d[2]["VarCharValue"]
            crawl_name      = d[3]["VarCharValue"]
            warc_info       = d[4]["VarCharValue"]

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
            output.append(o)

        if len(output) > 0:
            self.do_database(output)

    def do_database(self, output):
        con = psycopg2.connect("dbname='cc_index_database' user='athena' host='localhost' password='f1h89f90u1'")
        cur = con.cursor()

        for e in output:
            cur.execute("INSERT INTO entry values (%s, %s, %s, %s, %s, %s, %s, %s)",
                (e["domain"], e["reg_domain"], e["path"], e["crawl"], 
                e["warc_filename"], e["warc_record_offset"],
                e["warc_record_length"], e["warc_segment"] ))
        
        con.commit()
        con.close()


    def run(self, query_execution_id):
        self._query_execution_id = query_execution_id

        print("DO")
        while 1:
            next = self.request_result()
            self.parse_response()
            if not next:
                break

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
    aq = AthenaQuery()
    res = aq.run(query_execution_id)


def send_log(text):
    res = requests.get("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s" % (api_token, chat_id, text))

def main():

    '''
    con = psycopg2.connect("dbname='cc_index_database' user='athena' host='localhost' password='f1h89f90u1'")
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
    '''

    all_ids = []
    client = BOTO_SESSION.client('athena', region_name="us-east-1")
    executions = client.list_query_executions()
    next_token = executions.get("NextToken")

    while next_token:
        all_ids += executions.get("QueryExecutionIds")
        print(f"I have found {len(all_ids)} execution ids so far")
        executions = client.list_query_executions(NextToken=next_token)
        next_token = executions.get("NextToken", None)

    print(f"I have found {len(all_ids)} execution ids")

    p1 = Pool(10, init_worker)
    try:
        p1.map(work, all_ids)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating workers")
        p1.terminate()
        p1.join()
    
    print("DONE")

if __name__ == "__main__":
    main()
