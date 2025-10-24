from html.parser import HTMLParser

name_informal = """ Wipe body element """
description = """ Checks whether content exists between head and body. """

class HF2(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if  self._state != "error" and tag == "body": # state can be init or after head
            self._state = "in_body"
        elif self._state == "after_head": # we want an open body tag
            self._state = "error"

    def handle_endtag(self, tag):
        if self._state == "after_head":  # we want an open body tag
            self._state = "error"
        elif self._state == "init" and tag == "head":
            self._state = "after_head"  

    def handle_data(self, data):
        if self._state == "after_head" and data.strip() != "":
            self._state = "error"

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    hf2 = HF2(debug=debug)
    hf2.feed(html)
    res = hf2.is_valid()
    del hf2
    return res
