import re
from html.parser import HTMLParser

# with regex, because http parser already return all lower case.

name_informal = """ Mixed Case Rule """
description = """ Check whether an element uses mixed case in attribute name. """

# TODO 
# Collect all tags with the parser
# -> count whether all tags are used in lower

class WAF1(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True):
        super().__init__(convert_charrefs=convert_charrefs)
        self._data = []
        self._tags = []
        self._attrs = []

    def handle_starttag(self, tag, attrs):
        self._tags.append(tag)
        for k, v in attrs:
            self._attrs.append(k)

    def handle_data(self, data):
        if len(data) > 2:
            self._data.append(data)

    def handle_comment(self, data):
        if len(data) > 2:
            self._data.append(data)

    def get_all_data(self):
        return self._data

    def get_all_tags(self):
        return set(self._tags)

    def get_all_attrs(self):
        return set(self._attrs)

def run_rule(html, debug=False):
    # clean html first
    waf1 = WAF1()
    waf1.feed(html)
    tags = waf1.get_all_tags()
    attrs = waf1.get_all_attrs()
    data = "\n".join(waf1.get_all_data())

    for t in tags:
        elements = re.findall(r"<" + re.escape(t) + ".*", data)
        for element in elements:
            element = element.strip()
            html = html.replace(element, "")

    # print(attrs)
    # find all starting tags
    for t in tags:
        elements = re.findall(r"<" + re.escape(t) + ".*?>", html, flags=re.DOTALL | re.IGNORECASE)
        for element in elements:
            for attr in attrs:
                regexp = re.compile(r'[\/\s]' + re.escape(attr) + '[\s=]')
                if (regexp.search(element.lower()) and attr not in element):
                    if debug:
                        print(element)
                        print(attr)
                    return False
    return True
