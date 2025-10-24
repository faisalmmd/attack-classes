from html.parser import HTMLParser

name_informal = """ Move element from head to body """
description = """ Checks the head section of the document. The rule checks if the head is standard complient. """

class HF1_1(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._cur_ele = None
        # https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inhead
        # I dont allow html
        self._allow_list = ["base", "basefont", "bgsound",
            "link", "meta", "title", "noscript", "script",
            "noframes", "style"]
        self._not_self_closing = ["title", "script", "noframes", "style", "noscript"]
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        # We only check for one level of element, since nested is not allowed in head
        if tag == "head":
            self._state = "in_head"
        elif (self._state == "in_head" 
                and tag in self._allow_list
                and tag in self._not_self_closing):
            self._state = "in_head_ele"
            self._cur_ele = tag
        elif self._state == "in_head" and tag not in self._allow_list:
            if self._debug:
                print(f"NOT ALLOWED: {tag}")
            self._state = "error"
         # nested not allowed, but skip noscript, because it can be nested
        elif self._state == "in_head_ele" and self._cur_ele != "noscript": 
            if self._debug:
                print(f"NESTED: {tag}")
            self._state = "error"

    def handle_endtag(self, tag):
        if self._state == "in_head" and tag == "head":
            self._state = "close"    
        elif self._state == "in_head_ele" and tag == self._cur_ele:
            self._state = "in_head"            
            self._cur_ele = None

    def handle_data(self, data):
        if self._state == "in_head" and data.strip() != "":
            if self._debug:
                print(f"DATA: {data} ({[ord(c) for c in data]})")
            self._state = "error"

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    hf1_1 = HF1_1(debug=debug)
    hf1_1.feed(html)
    res = hf1_1.is_valid()
    del hf1_1
    return res