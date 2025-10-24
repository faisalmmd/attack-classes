import requests
import json
from multiprocessing import Pool, Queue, Process
from base64 import urlsafe_b64encode
from hashlib import md5
from urllib.parse import urlparse
import sqlite3
import signal
import time

""" Get Archive Sites
    The purpose of this script is to download websites for a search domain from archive org
"""

result_queue = Queue()
database = "example.db"

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def get_urls(domain, limit=10):
    """ Get Urls
        Use the archive CDX API to request existing entries
    """

    url = "http://web.archive.org/cdx/search/cdx"
    params = {
            "url": "%s/*" % domain,
            "output": "json",
            "from": 20220101000000,
            "to": 20220115000000,
            "limit": 1000,
            "filter": ["mimetype:text/html", "statuscode:200"]
            }

    try:
        res = requests.get(url, params=params)
    except Exception as e:
        print("CDX ERROR: %s - %s" % (domain, e))

        output = {
            "event": "DOMAIN",
            "domain": domain,
            "date": "",
            "error": e,
            "entires": ""
        }
        result_queue.put(output)
        return

    if res.status_code != 200:
        print("CDX ERROR: %s" % (domain))

        output = {
            "event": "DOMAIN",
            "domain": domain,
            "date": "",
            "error": res.text,
            "entires": ""
        }
        result_queue.put(output)
        return

    # Too many requests
    retry_cnt = 0
    while "The best solution is to wait a few seconds and reload the existing page." in res.text:
        print("SLEEP: %s: I need to wait 1 minute! (%d)" % (domain, retry_cnt))
        retry_cnt += 1
        time.sleep(60)

        try:
            res = requests.get(url, params=params)
        except Exception as e:
            print("CDX ERROR: %s - %s" % (domain, e))

            output = {
                "event": "DOMAIN",
                "domain": domain,
                "date": "",
                "error": e,
                "entires": ""
            }
            result_queue.put(output)
            return

    num_entries = 0 if len(res.json()) == 0 else len(res.json()) - 1
    urls = []
    output = []
    print("%s: %d" % (domain, num_entries))

    output = {
        "event": "DOMAIN",
        "domain": domain,
        "date": "",
        "error": "",
        "entires": num_entries
    }
    result_queue.put(output)

    for entry in res.json()[1:]:
        url = entry[2]
        date = entry[1]

        if url in urls:
            continue
        urls.append(url)

        if len(output) == limit:
            break

        output = {
            "event": "PATH",
            "domain": domain,
            "path": url,
            "date": date
        }
        result_queue.put(output)

def get_content(date, path):
    url = "https://web.archive.org/web/%sid_/%s"
    url = url % (date, path)

    res = requests.get(url)

    if res.status_code != 200:
        print(f"ERROR {res.status_code}: {url}")
        return

    # p = urlsafe_b64encode(path.encode()).decode()

    d = urlparse(path).hostname
    m = md5(path.encode()).hexdigest()

    file_path = f"archive_output/{d}_{m}_{date}.txt"
    f = open(file_path, "w")
    f.write(res.text)
    f.close()

def work(line):
    j = json.loads(line)
    domain = j["domain"]
    data = get_urls(domain, limit=10)

    # TODO: dedup path
    """
    urls = []
    for d in data:
        date = d[1]
        path = d[2]
        get_content(date, path)
    """

def database_process():

    while 1:
        entry = result_queue.get()
        if  entry["event"] == "DEADPILL":
            break

        con = sqlite3.connect(database)
        cur = con.cursor()

        if  entry["event"] == "PATH":
            cur.execute("INSERT INTO path values (?, ?, ?)", (entry["domain"], entry["path"], entry["date"]))
        
        if  entry["event"] == "DOMAIN":
            cur.execute("INSERT INTO domain values (?, ?, ?, ?)", (entry["domain"], entry["date"], entry["entires"], entry["error"]))

        con.commit()
        con.close()
        


def main():
    top_list = "./top_50k_appearing_every_day.json" 
    
    con = sqlite3.connect(database)
    cur = con.cursor()
    cur.execute("CREATE TABLE domain (domain text, date text, entries int, error text)")
    cur.execute("CREATE TABLE path (domain text, path text, timestamp text)")
    con.commit()
    con.close()

    db_process = Process(target=database_process)
    db_process.start()
    lines =  open(top_list).read()
    lines = lines.split('\n')

    p1 = Pool(10, init_worker)
    try:
        p1.map(work, lines)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating workers")
        p1.terminate()
        p1.join()
    
    result_queue.put({"event": "DEADPILL"})
    db_process.join()

if __name__ == '__main__':
    main()
