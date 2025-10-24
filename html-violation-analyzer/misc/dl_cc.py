from fileinput import filename
import requests
import io 
import gzip
import datetime

data_url = "https://data.commoncrawl.org"
filename = "crawl-data/CC-MAIN-2015-14/segments/1427132827069.83/warc/CC-MAIN-20150323174707-00272-ip-10-168-14-71.ec2.internal.warc.gz"
offset = 570495589
length = 5785
offset_end = offset + length - 1
url = f"{data_url}/{filename}"
headers={"Range": f"bytes={offset}-{offset_end}"}

resp = requests.get(url, headers=headers)
l = f"Resp Length for {url}: {len(resp.text)}"

status = "data"
data = ""

try:
    zipped_file = io.BytesIO(resp.content)
    unzipped_file = gzip.GzipFile(fileobj=zipped_file)
    raw_data: bytes = unzipped_file.read()
except Exception as e:
    em = f"ERROR for {url}\n{url}\n{offset} - {offset_end}\n{resp.content}\n{e}"
    print("ERROR", __name__, em)
    status = "error"
    output = em
    raw_data = ""

try:
    data: str = raw_data.decode("utf-8")
except UnicodeDecodeError:
    em = f"Warning: Could not extract file downloaded from {url}"
    print("ERROR", __name__, em)
    status = "error"
    output = em

html = ""

if len(data) > 0:
    data_parts = data.strip().split("\r\n\r\n", 2)
    html = data_parts[2] if len(data_parts) == 3 else ""

if status == "data":
    output = html

print(output)