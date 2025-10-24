import csv
import json
import time
import sys
import random
import requests
from os import path
from urllib.parse import urlparse
from multiprocessing import Pool, Value

""" Work Top List
    The purpose of this tool is to download commonCrawl entries for top alexa lists
"""

N = 10
PROCESSES = 100
CRAWL_ID = "CC-MAIN-2020-29"
OUTPUT = "./output/"

def get_n_entries_for_domain(domain):
    print(f"Working on {domain}")
    search = f"{domain}/*"
    url = f"https://index.commoncrawl.org/{CRAWL_ID}-index?url={search}&output=json"

    for i in range(10):
        search_result = requests.get(url)
        if search_result.status_code == 200:
            break

        if i == 9:
            print(f"Failed to load {domain}")
            return []
        time.sleep(10)
        print(f"Try again: {domain}")

    search_result = search_result.text.splitlines()

    print(f"{CRAWL_ID} {domain}: {len(search_result)} results")

    output = []

    if len(search_result) < N:
        output = search_result
    else:
        # Take first plus n-1 random entries
        for i in [0] + random.sample(range(1, len(search_result)), N-1):
            output.append(search_result[i])
    
    print(f"Writing to file {domain}")
    output_path = path.join(OUTPUT, f"output-{domain}.txt")
    output_file = open(output_path, "w")
    for line in output:
        output_file.write(line + "\n")
    output_file.close()
    print(f"Finished {domain}")

def main():
    global CRAWL_ID 
    global OUTPUT

    if (len(sys.argv) != 4):
        print(f"Usage: {__file__} <crawl_id> <top_list> <output>")

    CRAWL_ID = sys.argv[1]
    top_list = sys.argv[2]
    OUTPUT = sys.argv[3]
        
    list_file = open(top_list, "r")
    top_x_list = []
    for line in list_file:
        j = json.loads(line)
        top_x_list.append(j["domain"])
    list_file.close()
    
    top_1k_list = [d for d in top_x_list[1000:]]

    pool = Pool(processes=PROCESSES)
    pool.map(get_n_entries_for_domain, top_1k_list)

    pool.close()
    pool.join()

main()
