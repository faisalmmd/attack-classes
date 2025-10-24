import re
import string
from html.parser import HTMLParser

name_informal = """ Multiple spaces, newline, etc between attributes """
description = """ Check whether an element uses tabs, newlines or multiple spaces instead of one space between an attribute and its value. """

def check_tag(inp, debug=False):
    state = "tag_open"

    for c in inp[1:]:
        # print(f"{c} ({ord(c)}) is in {state}")
        if state == "tag_open":
            if c in string.ascii_letters:
                state = "tag_name"
                continue
            else:
                # Anything else is not allowed.
                # ! and ? are filtered by re
                return False 
            
        if state == "tag_name":
            if c in string.ascii_letters:
                continue
            elif c in ["\t", "\n", "\r", "\f", " ", "/"]:
                state = "before_attribute"
                continue
            elif c == ">":
                return True
                
        if state == "before_attribute":
            if c in ["\t", "\n", "\r", "\f", " ", "/"]:
                continue
            elif c == ">":
                return True
            else:
                state = "attribute_name"
                continue

        if state == "attribute_name":
            if c in string.ascii_letters + "\"'<":
                continue
            elif c in ["\t", "\n", "\r", "\f", " "]:
                state = "after_attribute_name"
                continue
            elif c in ["/"]:
                state = "before_attribute"
                continue
            elif c == ">":
                return True
            elif c == "=":
                state = "before_attribute_value"
                continue            
            
        if state == "after_attribute_name":
            if c == "=":
                # we had spaces and stuff before that
                if debug:
                    print("error 1")
                return False
            elif c in ["\t", "\n", "\r", "\f", " "]:
                continue
            elif c == ">":
                return True
            else:
                state = "attribute_name"
                continue

        if state == "before_attribute_value":
            if c in ["\t", "\n", "\r", "\f"," "]:
                if debug:
                    print("error 2")
                return False
            elif c == "\"":
                state = "attribute_value_double_quote"
                continue
            elif c == "\'":
                state = "attribute_value_single_quote"
                continue
            elif c == ">":
                return True
            else:
                state = "attribute_value_unquoted"
                continue

        if state == "attribute_value_double_quote":
            if c == "\"":
                # skipping after state, because we dont need it
                state = "before_attribute"
                continue
            else:
                continue

        if state == "attribute_value_single_quote":
            if c == "\'":
                # skipping after state, because we dont need it
                state = "before_attribute"
                continue
            else:
                continue

        if state == "attribute_value_unquoted":
            if c in ["\t", "\n", "\r", "\f", " "]:
                # skipping after state, because we dont need it
                state = "before_attribute"
                continue
            elif c == ">":
                return True
            else:
                continue

class WAF4(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True):
        super().__init__(convert_charrefs=convert_charrefs)
        self._data = []
        self._tags = []

    def handle_starttag(self, tag, attrs):
        self._tags.append(tag)

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

def run_rule(html, debug=False):    
    # clean html first
    waf4 = WAF4()
    waf4.feed(html)
    tags = waf4.get_all_tags()
    data = "\n".join(waf4.get_all_data())

    for t in tags:
        elements = re.findall(r"<" + re.escape(t) + ".*", data)
        for element in elements:
            element = element.strip()
            html = html.replace(element, "")

    # find all starting tags
    for t in tags:
        elements = re.findall(r"<" + re.escape(t) + ".*?>", html, flags=re.DOTALL)
        for element in elements:
            res = check_tag(element, debug=debug)
            if res == False:
                if debug:
                    print(element)
                return False
    return True

